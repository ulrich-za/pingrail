//! HTTPS. pingrail only speaks HTTPS, on both ports and between the TUI/CLI
//! and the service.
//!
//! The service uses your certificate (`[tls]` in pingrail.toml) or, by
//! default, one from its own certificate authority (see `ca`). A client
//! trusts a service when
//! - a SHA-256 fingerprint it pinned matches the certificate, or the
//!   pingrail authority sent with it (which must have issued it): the local
//!   service's (read from its data folder), a local TUI session's, or one you
//!   approved with `pingrail trust <url>`; or
//! - the system's certificate store vouches for it.
//!
//! Crypto is rustls with the ring backend.

use anyhow::{anyhow, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::config::{Config, Paths, TlsConfig};

pub type Fingerprint = [u8; 32];

pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Make ring the process-wide default provider (anything that builds a
/// rustls config without naming one then uses it).
pub fn install_default_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub fn fingerprint(der: &[u8]) -> Fingerprint {
    let d = ring::digest::digest(&ring::digest::SHA256, der);
    let mut f = [0u8; 32];
    f.copy_from_slice(d.as_ref());
    f
}

/// "AB:CD:…" (32 pairs).
pub fn fmt_fingerprint(f: &Fingerprint) -> String {
    f.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

/// Accepts "AB:CD:…", "abcd…" or with spaces.
pub fn parse_fingerprint(s: &str) -> Option<Fingerprint> {
    let hex: Vec<u8> = s.bytes().filter(|c| !matches!(c, b':' | b' ' | b'-')).collect();
    if hex.len() != 64 || !hex.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut f = [0u8; 32];
    for (i, pair) in hex.chunks(2).enumerate() {
        f[i] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(f)
}

// ----- the service's certificate ------------------------------------------------
// See `ca` for pingrail's own certificate authority and the web UI's
// certificate.

/// Where the configured certificate lives, or pingrail's own.
pub fn cert_paths(data_dir: &Path, cfg: &TlsConfig) -> (PathBuf, PathBuf) {
    if cfg.cert_file.trim().is_empty() {
        (data_dir.join("cert.pem"), data_dir.join("key.pem"))
    } else {
        (PathBuf::from(cfg.cert_file.trim()), PathBuf::from(cfg.key_file.trim()))
    }
}

/// Write a private key readable only by its owner (Unix) or by the service,
/// SYSTEM and Administrators (the shared Windows data folder).
pub fn write_private(path: &Path, data: &[u8], system: bool) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let _ = system;
        let _ = std::fs::remove_file(path);
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
        f.write_all(data)?;
    }
    #[cfg(windows)]
    {
        std::fs::write(path, data)?;
        if system {
            restrict_windows_key(path);
        }
    }
    Ok(())
}

/// Remove inherited access (local users can read ProgramData) from the key.
#[cfg(windows)]
pub fn restrict_windows_key(path: &Path) {
    let p = path.to_string_lossy().to_string();
    // SYSTEM, Administrators, LocalService (the service account, which
    // replaces its certificate's key when renewing it).
    let r = std::process::Command::new("icacls")
        .args([&p, "/inheritance:r", "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F", "*S-1-5-19:F"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    if !matches!(r, Ok(s) if s.success()) {
        tracing::warn!("could not restrict access to {p}");
    }
}

// ----- clients ---------------------------------------------------------------

/// What the local service presents, as seen from this machine, if this user
/// can read it (Linux: the user who installed pingrail; Windows: any local
/// user): its certificate authority and its current certificate.
pub fn local_pins(paths: &Paths) -> Vec<Fingerprint> {
    let cfg = Config::load_quiet(&paths.config_file);
    let (cert, _) = cert_paths(&paths.data_dir, &cfg.tls);
    let mut pins = Vec::new();
    if cfg.tls.cert_file.trim().is_empty()
        && let Ok(ca) = CertificateDer::from_pem_file(paths.data_dir.join("ca.pem"))
    {
        pins.push(fingerprint(&ca));
    }
    if let Some(leaf) = CertificateDer::pem_file_iter(&cert).ok().and_then(|mut it| it.next()).and_then(|r| r.ok()) {
        pins.push(fingerprint(&leaf));
    }
    pins
}

/// The certificate a client was shown but couldn't trust.
#[derive(Debug, thiserror::Error)]
#[error(
    "{url} presented a certificate this computer doesn't trust yet.\n\
     SHA-256 fingerprint: {fingerprint}\n\
     If it matches the fingerprint shown on that machine (pingrail status, or the TUI's w screen), run:\n  \
     pingrail trust {url}"
)]
pub struct Untrusted {
    pub url: String,
    pub fingerprint: String,
}

pub fn is_untrusted(e: &anyhow::Error) -> bool {
    e.chain().any(|c| c.downcast_ref::<Untrusted>().is_some())
}

#[derive(Debug)]
struct PinVerifier {
    pins: Vec<Fingerprint>,
    system: Option<Arc<dyn ServerCertVerifier>>,
    provider: Arc<CryptoProvider>,
    /// The last certificate rejected, for a helpful error message.
    rejected: Arc<Mutex<Option<Fingerprint>>>,
    /// Accept anything (only used to read a certificate for `pingrail trust`).
    accept_any: bool,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let fp = fingerprint(end_entity);
        if self.accept_any || self.pins.contains(&fp) {
            return Ok(ServerCertVerified::assertion());
        }
        // A pinned pingrail authority sent along with a certificate it issued.
        if intermediates
            .iter()
            .any(|ca| self.pins.contains(&fingerprint(ca)) && crate::ca::signed_by(end_entity, ca))
        {
            return Ok(ServerCertVerified::assertion());
        }
        let r = match &self.system {
            Some(v) => v.verify_server_cert(end_entity, intermediates, server_name, ocsp, now),
            None => Err(rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)),
        };
        if r.is_err() {
            *self.rejected.lock().unwrap() = Some(fp);
        }
        r
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// Client TLS settings trusting `pins` or the system store, plus the slot
/// that records a rejected certificate.
pub fn client_config(pins: Vec<Fingerprint>) -> (rustls::ClientConfig, Arc<Mutex<Option<Fingerprint>>>) {
    let provider = provider();
    let system = rustls_platform_verifier::Verifier::new(provider.clone())
        .ok()
        .map(|v| Arc::new(v) as Arc<dyn ServerCertVerifier>);
    let rejected = Arc::new(Mutex::new(None));
    let verifier = PinVerifier { pins, system, provider: provider.clone(), rejected: rejected.clone(), accept_any: false };
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring supports the default TLS versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    (cfg, rejected)
}

/// Connect to `url` and read what to pin without trusting it (for `pingrail
/// trust`): the pingrail authority it sends, or else its certificate.
/// Nothing is sent over the connection.
pub async fn peer_fingerprint(url: &str) -> Result<(Fingerprint, bool)> {
    let u = reqwest::Url::parse(url).with_context(|| format!("not a URL: {url}"))?;
    let host = u.host_str().ok_or_else(|| anyhow!("no host in {url}"))?.trim_matches(['[', ']']).to_string();
    let port = u.port_or_known_default().unwrap_or(443);
    let provider = provider();
    let verifier = PinVerifier {
        pins: vec![],
        system: None,
        provider: provider.clone(),
        rejected: Arc::new(Mutex::new(None)),
        accept_any: true,
    };
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    let name = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => ServerName::IpAddress(ip.into()),
        Err(_) => ServerName::try_from(host.clone()).map_err(|_| anyhow!("bad host name {host}"))?,
    };
    let tcp = tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect((host.as_str(), port)))
        .await
        .map_err(|_| anyhow!("{host}:{port} did not answer"))?
        .with_context(|| format!("cannot reach {host}:{port}"))?;
    let tls = tokio::time::timeout(
        Duration::from_secs(5),
        tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(name, tcp),
    )
    .await
    .map_err(|_| anyhow!("{host}:{port} did not complete a TLS handshake (is it a pingrail service?)"))?
    .with_context(|| format!("TLS handshake with {host}:{port} failed"))?;
    let (_, conn) = tls.get_ref();
    let chain = conn.peer_certificates().unwrap_or_default();
    let leaf = chain.first().ok_or_else(|| anyhow!("{host}:{port} sent no certificate"))?;
    Ok(match chain.last() {
        Some(ca) if chain.len() > 1 && crate::ca::is_pingrail_ca(ca) && crate::ca::signed_by(leaf, ca) => (fingerprint(ca), true),
        _ => (fingerprint(leaf), false),
    })
}

// ----- servers you've approved -------------------------------------------------

fn known_file() -> PathBuf {
    let user = Paths::user();
    user.config_file.parent().map(Path::to_path_buf).unwrap_or(user.data_dir).join("known-servers.toml")
}

/// "host:port", lower-case, for a service URL.
pub fn server_key(url: &str) -> Option<String> {
    let u = reqwest::Url::parse(url).ok()?;
    Some(format!("{}:{}", u.host_str()?.to_ascii_lowercase(), u.port_or_known_default()?))
}

fn load_known() -> BTreeMap<String, String> {
    std::fs::read_to_string(known_file())
        .ok()
        .and_then(|s| toml::from_str::<BTreeMap<String, BTreeMap<String, String>>>(&s).ok())
        .and_then(|mut m| m.remove("servers"))
        .unwrap_or_default()
}

pub fn known_pins(url: &str) -> Vec<Fingerprint> {
    let Some(key) = server_key(url) else { return vec![] };
    load_known().get(&key).and_then(|f| parse_fingerprint(f)).into_iter().collect()
}

/// Trust `fp` for `url` from now on (replacing any earlier one).
pub fn remember(url: &str, fp: &Fingerprint) -> Result<PathBuf> {
    let key = server_key(url).ok_or_else(|| anyhow!("not a service URL: {url}"))?;
    let mut known = load_known();
    known.insert(key, fmt_fingerprint(fp));
    let mut doc = BTreeMap::new();
    doc.insert("servers".to_string(), known);
    let path = known_file();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let text = format!(
        "# pingrail services you've chosen to trust (host:port = SHA-256 certificate fingerprint).\n{}",
        toml::to_string(&doc)?
    );
    std::fs::write(&path, text)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_round_trip() {
        let f = fingerprint(b"hello");
        let s = fmt_fingerprint(&f);
        assert_eq!(s.len(), 32 * 3 - 1);
        assert_eq!(parse_fingerprint(&s), Some(f));
        assert_eq!(parse_fingerprint(&s.replace(':', "").to_lowercase()), Some(f));
        assert_eq!(parse_fingerprint("AB:CD"), None);
        assert_eq!(server_key("https://Pi.Lan:8040/x"), Some("pi.lan:8040".into()));
        assert_eq!(server_key("https://[fd00::7]:8040"), Some("[fd00::7]:8040".into()));
    }

    #[test]
    fn local_pins_are_the_authority_and_certificate() {
        install_default_provider();
        let dir = std::env::temp_dir().join(format!("pingrail-tls-{}", crate::config::random_hex(4)));
        let (certs, _) = crate::ca::Certs::load(&dir, &TlsConfig::default(), false, &[]).unwrap();
        let pins = local_pins(&Paths::in_dir(&dir));
        assert_eq!(pins.len(), 2);
        assert_eq!(pins[0], certs.pin());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn clients_trust_a_pinned_authority_and_nothing_else() {
        install_default_provider();
        let dir = std::env::temp_dir().join(format!("pingrail-tls-{}", crate::config::random_hex(4)));
        let (certs, _) = crate::ca::Certs::load(&dir, &TlsConfig::default(), false, &[]).unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(certs.server_config().unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let a = acceptor.clone();
                tokio::spawn(async move {
                    let _ = a.accept(tcp).await;
                });
            }
        });
        let url = format!("https://127.0.0.1:{port}");
        // `pingrail trust` pins the authority.
        assert_eq!(peer_fingerprint(&url).await.unwrap(), (certs.pin(), true));
        let connect = |pins: Vec<Fingerprint>| async move {
            let (cfg, _) = client_config(pins);
            let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            tokio_rustls::TlsConnector::from(Arc::new(cfg))
                .connect(ServerName::try_from("127.0.0.1").unwrap(), tcp)
                .await
                .is_ok()
        };
        assert!(connect(vec![certs.pin()]).await, "pinned authority is trusted");
        assert!(!connect(vec![fingerprint(b"something else")]).await, "unpinned is refused");
        // Another machine's authority doesn't vouch for this one.
        let other = std::env::temp_dir().join(format!("pingrail-tls-{}", crate::config::random_hex(4)));
        let (o, _) = crate::ca::Certs::load(&other, &TlsConfig::default(), false, &[]).unwrap();
        assert!(!connect(vec![o.pin()]).await);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&other);
    }
}
