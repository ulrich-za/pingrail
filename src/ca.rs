//! pingrail's own certificate authority.
//!
//! On first start pingrail makes a certificate authority for this machine
//! and issues the web UI's certificate from it. Trust the authority once on
//! a phone or computer (the web UI's "Set up a phone" screen, or `pingrail
//! trust`) and every certificate it issues is trusted, including the yearly
//! renewals pingrail makes by itself.
//!
//! The authority can only vouch for this machine. Its name constraints allow
//! names nobody can register publicly (localhost, *.local, *.home.arpa,
//! *.internal, *.lan, *.home), this machine's own names and private
//! addresses, so even a stolen key couldn't impersonate a public website.
//!
//! A certificate you configure (`[tls]` in pingrail.toml) is used as it is
//! instead, and re-read when its file changes.

use anyhow::{bail, Context, Result};
use chrono::{Datelike, Utc};
use rcgen::{
    BasicConstraints, CertificateParams, CidrSubnet, DistinguishedName, DnType, ExtendedKeyUsagePurpose, GeneralSubtree,
    IsCa, Issuer, KeyPair, KeyUsagePurpose, NameConstraints, PublicKeyData, SanType, SerialNumber,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use serde::Serialize;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;
use x509_parser::extensions::GeneralName;

use crate::config::TlsConfig;
use crate::tls::{fingerprint, fmt_fingerprint, provider, write_private, Fingerprint};

const CA_YEARS: i32 = 10;
/// Make a new authority when the current one has less than this left.
const CA_RENEW_DAYS: i64 = 365;
/// Apple's limit for certificates from an authority you install is 825
/// days; 397 matches public certificates.
const LEAF_DAYS: u64 = 397;
const LEAF_RENEW_DAYS: i64 = 30;

/// Name suffixes nobody can register publicly.
const PRIVATE_SUFFIXES: &[&str] = &["localhost", "local", "home.arpa", "internal", "lan", "home"];

/// Loopback, private, shared (CGNAT, e.g. Tailscale), link-local and
/// unique-local ranges.
fn private_nets() -> Vec<(IpAddr, u8)> {
    [
        ("127.0.0.0", 8),
        ("10.0.0.0", 8),
        ("172.16.0.0", 12),
        ("192.168.0.0", 16),
        ("100.64.0.0", 10),
        ("169.254.0.0", 16),
        ("::1", 128),
        ("fc00::", 7),
        ("fe80::", 10),
    ]
    .iter()
    .map(|(a, p)| (a.parse().expect("valid range"), *p))
    .collect()
}

fn ip_is_private(ip: IpAddr) -> bool {
    crate::http::in_nets(ip, &private_nets())
}

struct Files {
    ca: PathBuf,
    ca_key: PathBuf,
    cert: PathBuf,
    key: PathBuf,
}

fn files(dir: &Path) -> Files {
    Files { ca: dir.join("ca.pem"), ca_key: dir.join("ca-key.pem"), cert: dir.join("cert.pem"), key: dir.join("key.pem") }
}

/// The certificate every new connection gets; swapped when renewed.
#[derive(Debug)]
struct Resolver(RwLock<Arc<CertifiedKey>>);

impl ResolvesServerCert for Resolver {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.read().unwrap().clone())
    }
}

struct Ca {
    der: CertificateDer<'static>,
    key_pem: String,
    /// The DNS names it may vouch for (each with its subdomains).
    dns: Vec<String>,
    expires: i64,
}

impl Ca {
    fn covers(&self, name: &str) -> bool {
        self.dns.iter().any(|c| name == c || name.strip_suffix(c.as_str()).is_some_and(|rest| rest.ends_with('.')))
    }
}

struct Inner {
    ca: Option<Ca>,
    leaf: CertificateDer<'static>,
    /// For a configured certificate: the files' modification times.
    stamp: Option<(SystemTime, SystemTime)>,
}

/// What a refresh changed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Refreshed {
    pub leaf: bool,
    pub ca: bool,
}

/// The web UI's certificate, as shown in the web UI.
#[derive(Debug, Clone, Serialize)]
pub struct CertInfo {
    /// A certificate configured in pingrail.toml.
    pub custom: bool,
    pub ca_sha256: Option<String>,
    pub ca_expires_ms: Option<i64>,
    pub names: Vec<String>,
    pub addresses: Vec<String>,
    pub expires_ms: i64,
}

pub struct Certs {
    dir: PathBuf,
    system: bool,
    custom: Option<(PathBuf, PathBuf)>,
    resolver: Arc<Resolver>,
    inner: Mutex<Inner>,
}

impl Certs {
    /// The configured certificate, or pingrail's own (making the authority
    /// and certificate as needed). `system` = the service's shared data
    /// folder, whose keys get locked down to the service. `extra` = names
    /// added in the web UI.
    pub fn load(dir: &Path, cfg: &TlsConfig, system: bool, extra: &[String]) -> Result<(Certs, Refreshed)> {
        let custom = !cfg.cert_file.trim().is_empty();
        if custom {
            if cfg.key_file.trim().is_empty() {
                bail!("tls.cert_file is set in pingrail.toml but tls.key_file isn't");
            }
            let (cert, key) = (PathBuf::from(cfg.cert_file.trim()), PathBuf::from(cfg.key_file.trim()));
            let (ck, stamp) = load_custom(&cert, &key)?;
            let leaf = ck.cert[0].clone();
            return Ok((
                Certs {
                    dir: dir.to_path_buf(),
                    system,
                    custom: Some((cert, key)),
                    resolver: Arc::new(Resolver(RwLock::new(Arc::new(ck)))),
                    inner: Mutex::new(Inner { ca: None, leaf, stamp: Some(stamp) }),
                },
                Refreshed::default(),
            ));
        }
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        let f = files(dir);
        let mut changed = Refreshed::default();
        let had_old = f.cert.exists() && !f.ca.exists();
        guard_ca_files(&f)?;
        let ca = match load_ca(&f) {
            Some(ca) if ca_fits(&ca, extra) => ca,
            _ => {
                changed.ca = true;
                create_ca(&f, system, extra)?
            }
        };
        let (ck, leaf_new) = ensure_leaf(&f, &ca, system, extra, changed.ca)?;
        changed.leaf = leaf_new;
        if had_old {
            tracing::info!(
                "replaced the old self-signed certificate with one from pingrail's own certificate authority \
                 (SHA-256 {}); computers that trusted the old one need `pingrail trust` again",
                fmt_fingerprint(&fingerprint(&ca.der))
            );
        }
        let leaf = ck.cert[0].clone();
        Ok((
            Certs {
                dir: dir.to_path_buf(),
                system,
                custom: None,
                resolver: Arc::new(Resolver(RwLock::new(Arc::new(ck)))),
                inner: Mutex::new(Inner { ca: Some(ca), leaf, stamp: None }),
            },
            changed,
        ))
    }

    pub fn server_config(&self) -> Result<Arc<rustls::ServerConfig>> {
        let mut c = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_cert_resolver(self.resolver.clone());
        c.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(c))
    }

    /// What clients pin: the authority, or a configured certificate itself.
    pub fn pin(&self) -> Fingerprint {
        let inner = self.inner.lock().unwrap();
        fingerprint(inner.ca.as_ref().map_or(&inner.leaf, |ca| &ca.der))
    }

    /// The authority's certificate (DER), for phones and computers to trust.
    pub fn ca_der(&self) -> Option<CertificateDer<'static>> {
        self.inner.lock().unwrap().ca.as_ref().map(|ca| ca.der.clone())
    }

    /// Can the authority vouch for `name` without being replaced?
    pub fn covers(&self, name: &str) -> bool {
        self.inner.lock().unwrap().ca.as_ref().is_some_and(|ca| ca.covers(name))
    }

    /// The certificate's DNS names.
    pub fn dns_names(&self) -> Vec<String> {
        sans(&self.inner.lock().unwrap().leaf).0
    }

    pub fn info(&self) -> CertInfo {
        let inner = self.inner.lock().unwrap();
        let (names, ips) = sans(&inner.leaf);
        CertInfo {
            custom: self.custom.is_some(),
            ca_sha256: inner.ca.as_ref().map(|ca| fmt_fingerprint(&fingerprint(&ca.der))),
            ca_expires_ms: inner.ca.as_ref().map(|ca| ca.expires * 1000),
            names,
            addresses: ips.iter().map(IpAddr::to_string).collect(),
            expires_ms: not_after(&inner.leaf).unwrap_or(0) * 1000,
        }
    }

    /// Renew what needs renewing: the certificate when it nears expiry or
    /// this machine's names or addresses changed, the authority when a name
    /// added in the web UI is outside it (or it nears expiry). A configured
    /// certificate is re-read when its files change.
    pub fn refresh(&self, extra: &[String]) -> Result<Refreshed> {
        let mut inner = self.inner.lock().unwrap();
        let mut changed = Refreshed::default();
        if let Some((cert, key)) = &self.custom {
            let now = (mtime(cert), mtime(key));
            if inner.stamp != Some(now) {
                let (ck, stamp) = load_custom(cert, key)?;
                if ck.cert[0] != inner.leaf {
                    changed.leaf = true;
                    tracing::info!("reloaded the certificate {}", cert.display());
                }
                inner.leaf = ck.cert[0].clone();
                inner.stamp = Some(stamp);
                *self.resolver.0.write().unwrap() = Arc::new(ck);
            }
            return Ok(changed);
        }
        let f = files(&self.dir);
        guard_ca_files(&f)?;
        let fits = inner.ca.as_ref().is_some_and(|ca| ca_fits(ca, extra));
        if !fits {
            inner.ca = Some(create_ca(&f, self.system, extra)?);
            changed.ca = true;
            tracing::warn!(
                "made a new certificate authority (SHA-256 {}); devices that trusted the old one must trust this one",
                fmt_fingerprint(&self.pin_of(&inner))
            );
        }
        let ca = inner.ca.as_ref().expect("own certificate has an authority");
        let (ck, leaf_new) = ensure_leaf(&f, ca, self.system, extra, changed.ca)?;
        if leaf_new {
            changed.leaf = true;
            inner.leaf = ck.cert[0].clone();
            *self.resolver.0.write().unwrap() = Arc::new(ck);
        }
        Ok(changed)
    }

    fn pin_of(&self, inner: &Inner) -> Fingerprint {
        fingerprint(inner.ca.as_ref().map_or(&inner.leaf, |ca| &ca.der))
    }
}

fn mtime(p: &Path) -> SystemTime {
    std::fs::metadata(p).and_then(|m| m.modified()).unwrap_or(SystemTime::UNIX_EPOCH)
}

fn load_custom(cert: &Path, key: &Path) -> Result<(CertifiedKey, (SystemTime, SystemTime))> {
    let stamp = (mtime(cert), mtime(key));
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert)
        .with_context(|| format!("reading {}", cert.display()))?
        .collect::<std::result::Result<_, _>>()
        .with_context(|| format!("reading {}", cert.display()))?;
    if chain.is_empty() {
        bail!("no certificate in {}", cert.display());
    }
    let key = PrivateKeyDer::from_pem_file(key).with_context(|| format!("reading the private key {}", key.display()))?;
    let ck = CertifiedKey::from_der(chain, key, &provider()).context("the certificate and private key don't match")?;
    Ok((ck, stamp))
}

// ----- names added in the web UI ----------------------------------------------

const NAMES_KEY: &str = "cert_names";

/// Names added in the web UI (the addresses you browse to this machine by).
pub fn saved_names(store: &crate::store::Store) -> Vec<String> {
    parse_names(store.meta_get(NAMES_KEY).ok().flatten())
}

/// The same, read from the database file directly (for the installer).
pub fn saved_names_in(db: &Path) -> Vec<String> {
    parse_names(crate::store::peek_meta(db, NAMES_KEY))
}

fn parse_names(json: Option<String>) -> Vec<String> {
    json.and_then(|j| serde_json::from_str::<Vec<String>>(&j).ok())
        .unwrap_or_default()
        .into_iter()
        .filter(|n| crate::util::valid_dns_name(n))
        .collect()
}

/// Add a name; returns the full list.
pub fn add_name(store: &crate::store::Store, name: &str) -> Result<Vec<String>> {
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if !crate::util::valid_dns_name(&name) {
        bail!("not a host name: {name}");
    }
    let mut names = saved_names(store);
    if !names.contains(&name) {
        if names.len() >= 16 {
            bail!("at most 16 names can be added");
        }
        names.push(name);
        store.meta_set(NAMES_KEY, &serde_json::to_string(&names)?)?;
    }
    Ok(names)
}

// ----- the authority ----------------------------------------------------------

fn now_secs() -> i64 {
    Utc::now().timestamp()
}

/// Refuse to go on when the authority's files exist but can't be read (a
/// permissions problem): replacing the authority would make every phone and
/// computer that trusts it stop trusting this server.
fn guard_ca_files(f: &Files) -> Result<()> {
    for p in [&f.ca, &f.ca_key] {
        if let Err(e) = std::fs::File::open(p)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            bail!(
                "can't read {} ({e}); fix its permissions (run `pingrail service init` as root or Administrator) \
                 rather than letting pingrail replace its certificate authority",
                p.display()
            );
        }
    }
    Ok(())
}

fn load_ca(f: &Files) -> Option<Ca> {
    let der = CertificateDer::from_pem_file(&f.ca).ok()?;
    let key_pem = std::fs::read_to_string(&f.ca_key).ok()?;
    let key = KeyPair::from_pem(&key_pem).ok()?;
    let (_, x) = x509_parser::parse_x509_certificate(&der).ok()?;
    // The key must belong to the certificate.
    if x.public_key().raw != key.subject_public_key_info().as_slice() {
        tracing::warn!("{} doesn't match {}; making a new authority", f.ca_key.display(), f.ca.display());
        return None;
    }
    let dns = x
        .name_constraints()
        .ok()
        .flatten()
        .and_then(|nc| nc.value.permitted_subtrees.clone())
        .unwrap_or_default()
        .iter()
        .filter_map(|s| match s.base {
            GeneralName::DNSName(d) => Some(d.to_ascii_lowercase()),
            _ => None,
        })
        .collect();
    let expires = x.validity().not_after.timestamp();
    Some(Ca { der: der.into_owned(), key_pem, dns, expires })
}

/// Still valid for a while, and covers every name added in the web UI?
fn ca_fits(ca: &Ca, extra: &[String]) -> bool {
    ca.expires - now_secs() > CA_RENEW_DAYS * 86_400 && extra.iter().all(|n| ca.covers(n))
}

/// This machine's names: localhost, its host name on its own, with .local
/// and with each DNS search domain, then names added in the web UI.
fn machine_dns(extra: &[String]) -> Vec<String> {
    let mut names = vec!["localhost".to_string()];
    if let Some(h) = crate::util::hostname() {
        names.push(h.clone());
        names.push(format!("{h}.local"));
        for s in crate::util::dns_suffixes() {
            names.push(format!("{h}.{s}"));
        }
    }
    names.extend(extra.iter().cloned());
    let mut out: Vec<String> = Vec::new();
    for n in names {
        let n = n.to_ascii_lowercase();
        if crate::util::valid_dns_name(&n) && !out.contains(&n) {
            out.push(n);
        }
    }
    out
}

fn create_ca(f: &Files, system: bool, extra: &[String]) -> Result<Ca> {
    let host = crate::util::hostname();
    // Private suffixes, then this machine's names not already under one.
    let mut dns: Vec<String> = PRIVATE_SUFFIXES.iter().map(|s| s.to_string()).collect();
    for n in machine_dns(extra) {
        let covered = dns.iter().any(|c| n == *c || n.ends_with(&format!(".{c}")));
        if !covered {
            dns.push(n);
        }
    }
    let mut p = CertificateParams::default();
    p.distinguished_name = DistinguishedName::new();
    p.distinguished_name.push(DnType::CommonName, format!("pingrail CA for {}", host.as_deref().unwrap_or("this machine")));
    p.distinguished_name.push(DnType::OrganizationName, "pingrail");
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    p.name_constraints = Some(NameConstraints {
        permitted_subtrees: dns
            .iter()
            .map(|d| GeneralSubtree::DnsName(d.clone()))
            .chain(private_nets().into_iter().map(|(ip, len)| GeneralSubtree::IpAddress(CidrSubnet::from_addr_prefix(ip, len))))
            .collect(),
        excluded_subtrees: vec![],
    });
    let today = Utc::now().date_naive();
    let start = today - chrono::Days::new(1);
    p.not_before = rcgen::date_time_ymd(start.year(), start.month() as u8, start.day() as u8);
    p.not_after = rcgen::date_time_ymd(start.year() + CA_YEARS, start.month() as u8, start.day().min(28) as u8);
    p.serial_number = Some(random_serial()?);
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let cert = p.self_signed(&key)?;
    let key_pem = key.serialize_pem();
    write_private(&f.ca_key, key_pem.as_bytes(), system)?;
    write_public(&f.ca, cert.pem().as_bytes())?;
    tracing::info!("created pingrail's certificate authority: {}", f.ca.display());
    load_ca(f).context("reading back the new certificate authority")
}

fn random_serial() -> Result<SerialNumber> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| anyhow::anyhow!("random: {e}"))?;
    b[0] &= 0x7f;
    b[0] |= 0x01;
    Ok(SerialNumber::from_slice(&b))
}

fn write_public(path: &Path, data: &[u8]) -> Result<()> {
    std::fs::write(path, data).with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Public: the TUI reads it to pin the service.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))?;
    }
    Ok(())
}

// ----- the web UI's certificate ---------------------------------------------------

/// The names and addresses the certificate should carry: this machine's,
/// as far as the authority may vouch for them.
fn wanted(ca: &Ca, extra: &[String]) -> (Vec<String>, Vec<IpAddr>) {
    let dns: Vec<String> = machine_dns(extra).into_iter().filter(|n| ca.covers(n)).collect();
    let mut ips: Vec<IpAddr> = vec!["127.0.0.1".parse().unwrap(), "::1".parse().unwrap()];
    if let Some(ip) = crate::util::lan_ip()
        && ip_is_private(ip)
        && !ips.contains(&ip)
    {
        ips.push(ip);
    }
    (dns, ips)
}

/// The certificate in use, or a new one when it's missing, from another
/// authority, near expiry or for other names.
fn ensure_leaf(f: &Files, ca: &Ca, system: bool, extra: &[String], force: bool) -> Result<(CertifiedKey, bool)> {
    let (dns, ips) = wanted(ca, extra);
    if !force && let Some(ck) = current_leaf(f, ca, &dns, &ips) {
        return Ok((ck, false));
    }
    let ck = issue_leaf(f, ca, system, &dns, &ips)?;
    tracing::info!("issued the web UI certificate for {}", dns.iter().cloned().chain(ips.iter().map(|i| i.to_string())).collect::<Vec<_>>().join(", "));
    Ok((ck, true))
}

fn current_leaf(f: &Files, ca: &Ca, dns: &[String], ips: &[IpAddr]) -> Option<CertifiedKey> {
    let chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(&f.cert).ok()?.collect::<std::result::Result<_, _>>().ok()?;
    let leaf = chain.first()?.clone();
    if !signed_by(&leaf, &ca.der) || not_after(&leaf)? - now_secs() < LEAF_RENEW_DAYS * 86_400 {
        return None;
    }
    let (have_dns, have_ips) = sans(&leaf);
    let same = |a: &[String], b: &[String]| a.len() == b.len() && a.iter().all(|x| b.contains(x));
    let ip_strings = |v: &[IpAddr]| v.iter().map(IpAddr::to_string).collect::<Vec<_>>();
    if !same(&have_dns, dns) || !same(&ip_strings(&have_ips), &ip_strings(ips)) {
        return None;
    }
    let key = PrivateKeyDer::from_pem_file(&f.key).ok()?;
    CertifiedKey::from_der(vec![leaf, ca.der.clone()], key, &provider()).ok()
}

fn issue_leaf(f: &Files, ca: &Ca, system: bool, dns: &[String], ips: &[IpAddr]) -> Result<CertifiedKey> {
    let mut p = CertificateParams::default();
    p.subject_alt_names = dns
        .iter()
        .map(|d| Ok(SanType::DnsName(d.clone().try_into()?)))
        .chain(ips.iter().map(|ip| Ok(SanType::IpAddress(*ip))))
        .collect::<Result<_, rcgen::Error>>()?;
    p.distinguished_name = DistinguishedName::new();
    p.distinguished_name.push(DnType::CommonName, dns.get(1).or(dns.first()).cloned().unwrap_or_else(|| "pingrail".into()));
    p.distinguished_name.push(DnType::OrganizationName, "pingrail");
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    p.use_authority_key_identifier_extension = true;
    let start = Utc::now().date_naive() - chrono::Days::new(1);
    let end = start + chrono::Days::new(LEAF_DAYS);
    p.not_before = rcgen::date_time_ymd(start.year(), start.month() as u8, start.day() as u8);
    p.not_after = rcgen::date_time_ymd(end.year(), end.month() as u8, end.day() as u8);
    p.serial_number = Some(random_serial()?);
    let ca_key = KeyPair::from_pem(&ca.key_pem).context("reading the authority's key")?;
    let issuer = Issuer::from_ca_cert_der(&ca.der, &ca_key).context("reading the authority's certificate")?;
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let cert = p.signed_by(&key, &issuer)?;
    let ca_pem = String::from_utf8(std::fs::read(&f.ca)?).context("reading the authority's certificate")?;
    write_private(&f.key, key.serialize_pem().as_bytes(), system)?;
    write_public(&f.cert, format!("{}{}", cert.pem(), ca_pem).as_bytes())?;
    let der = PrivateKeyDer::from_pem_slice(key.serialize_pem().as_bytes())?;
    Ok(CertifiedKey::from_der(vec![cert.der().clone(), ca.der.clone()], der, &provider())?)
}

// ----- reading certificates -----------------------------------------------------

/// DNS names and IP addresses in a certificate.
pub fn sans(der: &CertificateDer<'_>) -> (Vec<String>, Vec<IpAddr>) {
    let mut dns = Vec::new();
    let mut ips = Vec::new();
    if let Ok((_, x)) = x509_parser::parse_x509_certificate(der)
        && let Ok(Some(san)) = x.subject_alternative_name()
    {
        for n in &san.value.general_names {
            match n {
                GeneralName::DNSName(d) => dns.push(d.to_ascii_lowercase()),
                GeneralName::IPAddress(b) => match b.len() {
                    4 => ips.push(IpAddr::from(<[u8; 4]>::try_from(*b).unwrap())),
                    16 => ips.push(IpAddr::from(<[u8; 16]>::try_from(*b).unwrap())),
                    _ => {}
                },
                _ => {}
            }
        }
    }
    (dns, ips)
}

fn not_after(der: &CertificateDer<'_>) -> Option<i64> {
    let (_, x) = x509_parser::parse_x509_certificate(der).ok()?;
    Some(x.validity().not_after.timestamp())
}

/// Does `leaf` chain to `ca` as a server certificate, now? Names aren't
/// checked: `ca` belongs to one machine.
pub fn signed_by(leaf: &CertificateDer<'_>, ca: &CertificateDer<'_>) -> bool {
    let Ok(anchor) = webpki::anchor_from_trusted_cert(ca) else { return false };
    let Ok(ee) = webpki::EndEntityCert::try_from(leaf) else { return false };
    ee.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &[anchor],
        &[],
        UnixTime::now(),
        webpki::KeyUsage::server_auth(),
        None,
        None,
    )
    .is_ok()
}

/// A pingrail authority: self-issued, a CA, and limited by name
/// constraints. (Public authorities are never name-constrained, so pinning
/// one of these can't end up trusting a public CA.)
pub fn is_pingrail_ca(der: &CertificateDer<'_>) -> bool {
    let Ok((_, x)) = x509_parser::parse_x509_certificate(der) else { return false };
    x.tbs_certificate.subject.as_raw() == x.tbs_certificate.issuer.as_raw()
        && x.is_ca()
        && x.name_constraints().ok().flatten().is_some_and(|nc| nc.value.permitted_subtrees.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!("pingrail-ca-{}", crate::config::random_hex(4)));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn authority_issues_a_constrained_renewable_certificate() {
        crate::tls::install_default_provider();
        let dir = tmp();
        let (certs, changed) = Certs::load(&dir, &TlsConfig::default(), false, &[]).unwrap();
        assert!(changed.ca && changed.leaf);
        let ca = certs.ca_der().unwrap();
        assert!(is_pingrail_ca(&ca));
        let info = certs.info();
        assert!(info.names.contains(&"localhost".to_string()), "{info:?}");
        assert!(info.addresses.contains(&"127.0.0.1".to_string()));
        let days = (info.expires_ms / 1000 - now_secs()) / 86_400;
        assert!((390..=397).contains(&days), "{days} days");
        // The chain served is the certificate then the authority.
        let chain: Vec<CertificateDer> =
            CertificateDer::pem_file_iter(dir.join("cert.pem")).unwrap().map(|c| c.unwrap()).collect();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[1], ca);
        assert!(signed_by(&chain[0], &ca));
        // Loading again changes nothing; the pin is the authority.
        let (again, changed) = Certs::load(&dir, &TlsConfig::default(), false, &[]).unwrap();
        assert_eq!(changed, Refreshed::default());
        assert_eq!(again.pin(), fingerprint(&ca));
        assert_eq!(certs.refresh(&[]).unwrap(), Refreshed::default());
        // A name under a private suffix: new certificate, same authority.
        let r = certs.refresh(&["mypc.home.arpa".into()]).unwrap();
        assert_eq!(r, Refreshed { leaf: true, ca: false });
        assert!(certs.dns_names().contains(&"mypc.home.arpa".to_string()));
        assert_eq!(certs.pin(), fingerprint(&ca));
        // A name outside it: a new authority that covers it.
        assert!(!certs.covers("mypc.corp"));
        let r = certs.refresh(&["mypc.corp".into()]).unwrap();
        assert_eq!(r, Refreshed { leaf: true, ca: true });
        assert!(certs.covers("mypc.corp") && certs.covers("x.mypc.corp"));
        assert!(!certs.covers("example.com") && !certs.covers("evil-mypc.corp"));
        assert_ne!(certs.pin(), fingerprint(&ca));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for k in ["ca-key.pem", "key.pem"] {
                let mode = std::fs::metadata(dir.join(k)).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o600, "{k} is owner-only");
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_authority_cannot_vouch_for_public_names() {
        // Issue a certificate for a public name with the authority's key, by
        // hand: a verifier enforcing the constraints must refuse it.
        crate::tls::install_default_provider();
        let dir = tmp();
        let (certs, _) = Certs::load(&dir, &TlsConfig::default(), false, &[]).unwrap();
        let ca_der = certs.ca_der().unwrap();
        let ca_key = KeyPair::from_pem(&std::fs::read_to_string(dir.join("ca-key.pem")).unwrap()).unwrap();
        let issuer = Issuer::from_ca_cert_der(&ca_der, &ca_key).unwrap();
        let mut p = CertificateParams::new(vec!["www.example.com".to_string()]).unwrap();
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let k = KeyPair::generate().unwrap();
        let evil = p.signed_by(&k, &issuer).unwrap();
        assert!(!signed_by(evil.der(), &ca_der), "name constraints must reject www.example.com");
        let mut p = CertificateParams::new(vec!["8.8.8.8".to_string()]).unwrap();
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let evil = p.signed_by(&k, &issuer).unwrap();
        assert!(!signed_by(evil.der(), &ca_der), "name constraints must reject public addresses");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_old_self_signed_certificate_is_replaced() {
        crate::tls::install_default_provider();
        let dir = tmp();
        let p = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let k = KeyPair::generate().unwrap();
        let old = p.self_signed(&k).unwrap();
        std::fs::write(dir.join("cert.pem"), old.pem()).unwrap();
        std::fs::write(dir.join("key.pem"), k.serialize_pem()).unwrap();
        let (certs, changed) = Certs::load(&dir, &TlsConfig::default(), false, &[]).unwrap();
        assert!(changed.ca && changed.leaf);
        assert!(certs.ca_der().is_some());
        assert_ne!(certs.info().names.len(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
