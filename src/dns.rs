//! "Your DNS": which DNS servers this machine is set to use and, since that
//! is usually just the router, who really does the looking up.
//!
//! The second part works by asking, through the machine's own DNS, for a
//! name whose answer is the address of whichever resolver came asking
//! (Akamai and Google each run one). That address is then matched to the
//! network it belongs to with Team Cymru's public IP-to-network lookup, and
//! compared with this machine's own public address:
//!
//! - the same address: the lookups are done on this connection (your own
//!   resolver, such as Unbound on the router);
//! - the same network: your internet provider's DNS;
//! - otherwise a public service (Cloudflare, Google…) or another network.
//!
//! Everything here is a handful of ordinary DNS questions every half hour.
//! Nothing about your targets is sent. `probe.identify_dns = false` turns it
//! off, leaving only the list of configured servers.
//!
//! Answers come from the network, so they are treated as untrusted: sizes
//! are bounded, names are cut down to plain printable text, and a reply is
//! only accepted from the server that was asked, for the question asked.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::net::UdpSocket;

/// Who does the looking up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsKind {
    /// A resolver on this connection (same public address).
    Own,
    /// The internet provider's (same network as this connection).
    Isp,
    /// A well-known public service.
    Public,
    /// Some other network.
    Other,
}

/// What the web UI, the terminal app and reports show.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DnsView {
    /// The servers this machine is set to use (often the router). Never
    /// sent to share-link visitors.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub servers: Vec<String>,
    /// The address the resolver shows to the internet. Never sent to
    /// share-link visitors: with your own resolver it is your address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolver: Option<String>,
    /// Whose network that resolver is on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<DnsKind>,
    /// The above in one line of plain words, for whoever is reading.
    #[serde(default)]
    pub text: String,
}

impl DnsView {
    /// What a share-link visitor may see: whose DNS it is, and nothing that
    /// points at the network (no local servers, no addresses).
    pub fn public(&self) -> Option<DnsView> {
        self.kind?;
        let mut v = DnsView { owner: self.owner.clone(), asn: self.asn, kind: self.kind, ..Default::default() };
        v.text = v.describe(false);
        Some(v)
    }

    /// One line of plain words. `yours` is false on a share link, where the
    /// reader is someone else: "your" would be wrong there.
    pub fn describe(&self, yours: bool) -> String {
        let named = match (&self.owner, self.asn) {
            (Some(o), Some(n)) => format!("{o} (AS{n})"),
            (Some(o), None) => o.clone(),
            (None, Some(n)) => format!("AS{n}"),
            (None, None) => String::new(),
        };
        let mut s = match self.kind {
            Some(DnsKind::Own) => {
                if yours { "your own resolver, on this connection".to_string() } else { "its own resolver, on the same connection".to_string() }
            }
            Some(DnsKind::Isp) => {
                let whose = if yours { "your internet provider" } else { "the internet provider" };
                if named.is_empty() { whose.to_string() } else { format!("{named}, {whose}") }
            }
            Some(DnsKind::Public) | Some(DnsKind::Other) if !named.is_empty() => named,
            _ => self.resolver.clone().unwrap_or_default(),
        };
        if !self.servers.is_empty() {
            let via = self.servers.iter().take(2).cloned().collect::<Vec<_>>().join(", ");
            if s.is_empty() {
                s = via;
            } else if self.servers.iter().all(|x| Some(x) != self.resolver.as_ref()) {
                s.push_str(&format!(", via {via}"));
            }
        }
        s
    }
}

/// Public resolvers people commonly set, by network number.
const WELL_KNOWN: &[(u32, &str)] = &[
    (13335, "Cloudflare"),
    (15169, "Google"),
    (19281, "Quad9"),
    (36692, "OpenDNS"),
    (34939, "NextDNS"),
    (212772, "AdGuard"),
];

/// Kept up to date in the background; see [`DnsWatch::start`].
#[derive(Default)]
pub struct DnsWatch {
    view: RwLock<Option<DnsView>>,
}

impl DnsWatch {
    /// For the owner (signed in, or the terminal app).
    pub fn view(&self) -> Option<DnsView> {
        let mut v = self.view.read().unwrap_or_else(|e| e.into_inner()).clone()?;
        v.text = v.describe(true);
        Some(v)
    }

    /// Work it out shortly after start and every half hour after (sooner
    /// after a failure: the connection may have been down).
    pub fn start(identify: bool) -> Arc<DnsWatch> {
        let w = Arc::new(DnsWatch::default());
        let me = w.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(2)).await;
            loop {
                let v = detect(identify).await;
                let settled = !identify || v.kind.is_some();
                let seen = !v.servers.is_empty() || v.kind.is_some();
                *me.view.write().unwrap_or_else(|e| e.into_inner()) = seen.then_some(v);
                tokio::time::sleep(Duration::from_secs(if settled { 1800 } else { 300 })).await;
            }
        });
        w
    }
}

async fn detect(identify: bool) -> DnsView {
    let servers = tokio::task::spawn_blocking(system_servers).await.unwrap_or_default();
    let mut v = DnsView { servers: shown_servers(&servers), ..Default::default() };
    if !identify {
        return v;
    }
    // Ask through the first configured server that answers.
    let mut resolver = None;
    let mut via = None;
    for s in servers.iter().take(3) {
        let at = SocketAddr::new(*s, 53);
        if let Some(ip) = resolver_seen_by_the_internet(at).await {
            resolver = Some(ip);
            via = Some(at);
            break;
        }
    }
    let (Some(resolver), Some(via)) = (resolver, via) else { return v };
    v.resolver = Some(resolver.to_string());
    let mine = public_address(via).await;
    let asn = origin_asn(via, resolver).await;
    v.asn = asn;
    if let Some(n) = asn {
        v.owner = match WELL_KNOWN.iter().find(|(a, _)| *a == n) {
            Some((_, name)) => Some(name.to_string()),
            None => as_name(via, n).await,
        };
    }
    v.kind = Some(if mine == Some(resolver) {
        DnsKind::Own
    } else {
        let my_asn = match mine {
            Some(ip) => origin_asn(via, ip).await,
            None => None,
        };
        if asn.is_some() && asn == my_asn {
            DnsKind::Isp
        } else if asn.is_some_and(|n| WELL_KNOWN.iter().any(|(a, _)| *a == n)) {
            DnsKind::Public
        } else {
            DnsKind::Other
        }
    });
    v
}

/// The address our resolver shows to authoritative servers. The first name
/// makes the resolver ask over IPv4, so it can be compared with our own
/// IPv4 address.
async fn resolver_seen_by_the_internet(via: SocketAddr) -> Option<IpAddr> {
    for name in ["whoami.ipv4.akahelp.net", "whoami.ds.akahelp.net", "o-o.myaddr.l.google.com"] {
        if let Ok(ans) = query(via, name, TYPE_TXT).await
            && let Some(ip) = ans.iter().find_map(whoami_ip)
            && is_public(ip)
        {
            return Some(ip);
        }
    }
    let ans = query(via, "whoami.akamai.net", TYPE_A).await.ok()?;
    ans.iter().find_map(|a| if let Answer::Addr(ip) = a { Some(*ip) } else { None }).filter(|ip| is_public(*ip))
}

/// Our own public address: the same question put straight to Google's name
/// server, which then sees us instead of a resolver.
async fn public_address(via: SocketAddr) -> Option<IpAddr> {
    let ns = query(via, "ns1.google.com", TYPE_A).await.ok()?;
    let ns = ns.iter().find_map(|a| if let Answer::Addr(ip) = a { Some(*ip) } else { None }).filter(|ip| is_public(*ip))?;
    let ans = query(SocketAddr::new(ns, 53), "o-o.myaddr.l.google.com", TYPE_TXT).await.ok()?;
    ans.iter().find_map(whoami_ip).filter(|ip| is_public(*ip))
}

/// The address in a "who asked?" TXT answer: Akamai's `"ns" "192.0.2.1"`
/// or Google's `"192.0.2.1"`.
fn whoami_ip(a: &Answer) -> Option<IpAddr> {
    let Answer::Txt(parts) = a else { return None };
    match parts.as_slice() {
        [label, ip] if label == "ns" => ip.parse().ok(),
        [ip] => ip.parse().ok(),
        _ => None,
    }
}

/// The network (AS number) an address is announced from, per Team Cymru.
async fn origin_asn(via: SocketAddr, ip: IpAddr) -> Option<u32> {
    let name = match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.origin.asn.cymru.com", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let nibbles: Vec<String> = v6.octets().iter().rev().flat_map(|b| [format!("{:x}", b & 15), format!("{:x}", b >> 4)]).collect();
            format!("{}.origin6.asn.cymru.com", nibbles.join("."))
        }
    };
    let ans = query(via, &name, TYPE_TXT).await.ok()?;
    ans.iter().find_map(|a| if let Answer::Txt(p) = a { parse_origin(&p.concat()) } else { None })
}

/// "13335 | 1.1.1.0/24 | US | arin | 2010-07-14" (several numbers when an
/// address is announced by more than one network: the first).
fn parse_origin(txt: &str) -> Option<u32> {
    txt.split('|').next()?.split_whitespace().next()?.parse().ok().filter(|n| *n != 0)
}

async fn as_name(via: SocketAddr, asn: u32) -> Option<String> {
    let ans = query(via, &format!("AS{asn}.asn.cymru.com"), TYPE_TXT).await.ok()?;
    ans.iter().find_map(|a| if let Answer::Txt(p) = a { parse_as_name(&p.concat()) } else { None })
}

/// "37680 | ZA | afrinic | 2013-01-22 | COOL-IDEAS, ZA" gives "COOL-IDEAS".
/// The name is someone else's text: keep plain printable characters only.
fn parse_as_name(txt: &str) -> Option<String> {
    let last = txt.rsplit('|').next()?.trim();
    // Drop the ", ZA" country suffix.
    let name = match last.rsplit_once(',') {
        Some((n, cc)) if cc.trim().len() == 2 => n.trim(),
        _ => last,
    };
    let clean: String =
        name.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.' | '&' | '+' | '/')).take(48).collect();
    let clean = clean.trim().to_string();
    (!clean.is_empty()).then_some(clean)
}

fn is_public(ip: IpAddr) -> bool {
    !crate::netpolicy::is_private(ip)
}

/// The configured servers as shown: a local stub (systemd-resolved's
/// 127.0.0.53) says nothing, so it is left out when there is anything else.
fn shown_servers(servers: &[IpAddr]) -> Vec<String> {
    let real: Vec<String> = servers.iter().filter(|ip| !ip.is_loopback()).take(4).map(|ip| ip.to_string()).collect();
    if real.is_empty() { servers.iter().take(1).map(|ip| ip.to_string()).collect() } else { real }
}

// ----- the servers this machine is set to use ------------------------------

/// `nameserver` lines of a resolv.conf.
fn parse_resolv_conf(text: &str) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = Vec::new();
    for line in text.lines() {
        let mut it = line.split_whitespace();
        if it.next() != Some("nameserver") {
            continue;
        }
        // An IPv6 server may carry a zone ("fe80::1%eth0").
        if let Some(ip) = it.next().and_then(|a| a.split('%').next()).and_then(|a| a.parse::<IpAddr>().ok())
            && !out.contains(&ip)
        {
            out.push(ip);
        }
    }
    out
}

#[cfg(unix)]
fn system_servers() -> Vec<IpAddr> {
    let read = |p: &str| std::fs::read_to_string(p).map(|t| parse_resolv_conf(&t)).unwrap_or_default();
    let mut servers = read("/etc/resolv.conf");
    // systemd-resolved puts a local stub there; the servers behind it are
    // listed in its own file. Questions still go to the stub first.
    if servers.iter().all(|ip| ip.is_loopback()) {
        for ip in read("/run/systemd/resolve/resolv.conf") {
            if !servers.contains(&ip) {
                servers.push(ip);
            }
        }
    }
    servers
}

#[cfg(windows)]
fn system_servers() -> Vec<IpAddr> {
    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_FRIENDLY_NAME, GAA_FLAG_SKIP_MULTICAST, GAA_FLAG_SKIP_UNICAST,
        IF_TYPE_SOFTWARE_LOOPBACK, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC};

    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_FRIENDLY_NAME;
    // u64 storage keeps the buffer aligned for the structures Windows writes.
    let mut len: u32 = 16 * 1024;
    let mut buf: Vec<u64> = Vec::new();
    let mut ok = false;
    for _ in 0..4 {
        buf = vec![0u64; (len as usize).div_ceil(8)];
        // SAFETY: buf is writable for `len` bytes; Windows fills it with a
        // linked list that stays inside it, or reports the size it needs.
        let rc = unsafe {
            GetAdaptersAddresses(AF_UNSPEC as u32, flags, std::ptr::null(), buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>(), &mut len)
        };
        if rc == ERROR_SUCCESS {
            ok = true;
            break;
        }
        if rc != ERROR_BUFFER_OVERFLOW {
            break;
        }
    }
    if !ok {
        return Vec::new();
    }
    // (has a gateway, metric, address): connected adapters that lead
    // somewhere come first, then the order Windows prefers them in.
    let mut found: Vec<(bool, u32, IpAddr)> = Vec::new();
    // SAFETY: on success the buffer holds a valid list of adapters; every
    // pointer followed below was written by Windows and points into buf,
    // which outlives the loop. Addresses are read by length-checked bytes.
    unsafe {
        let mut a = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        while !a.is_null() {
            let ad = &*a;
            if ad.OperStatus == IfOperStatusUp && ad.IfType != IF_TYPE_SOFTWARE_LOOPBACK {
                let routed = !ad.FirstGatewayAddress.is_null();
                let mut d = ad.FirstDnsServerAddress;
                while !d.is_null() {
                    let sa = (*d).Address;
                    let p = sa.lpSockaddr.cast::<u8>();
                    if !p.is_null() && sa.iSockaddrLength >= 8 {
                        let family = u16::from_ne_bytes([*p, *p.add(1)]);
                        let ip = if family == AF_INET {
                            Some(IpAddr::V4(Ipv4Addr::new(*p.add(4), *p.add(5), *p.add(6), *p.add(7))))
                        } else if family == AF_INET6 && sa.iSockaddrLength >= 24 {
                            let mut o = [0u8; 16];
                            std::ptr::copy_nonoverlapping(p.add(8), o.as_mut_ptr(), 16);
                            Some(IpAddr::V6(Ipv6Addr::from(o)))
                        } else {
                            None
                        };
                        // fec0::/10 are placeholders Windows lists when no
                        // IPv6 DNS server is set.
                        let placeholder = matches!(ip, Some(IpAddr::V6(v6)) if v6.segments()[0] & 0xffc0 == 0xfec0);
                        if let Some(ip) = ip
                            && !placeholder
                        {
                            found.push((routed, if ip.is_ipv4() { ad.Ipv4Metric } else { ad.Ipv6Metric }, ip));
                        }
                    }
                    d = (*d).Next;
                }
            }
            a = ad.Next;
        }
    }
    found.sort_by_key(|(routed, metric, ip)| (!routed, *metric, ip.is_ipv6()));
    let mut out: Vec<IpAddr> = Vec::new();
    for (_, _, ip) in found {
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    out
}

// ----- a small DNS client ---------------------------------------------------

const TYPE_A: u16 = 1;
const TYPE_TXT: u16 = 16;
const TYPE_AAAA: u16 = 28;

#[derive(Debug, Clone, PartialEq)]
enum Answer {
    Addr(IpAddr),
    /// The character strings of one TXT record.
    Txt(Vec<String>),
}

/// One question to one server over UDP, with one retry. The socket is
/// connected, so only that server's replies are received.
async fn query(server: SocketAddr, name: &str, qtype: u16) -> anyhow::Result<Vec<Answer>> {
    let mut id = [0u8; 2];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut id).map_err(|_| anyhow::anyhow!("no randomness"))?;
    let id = u16::from_be_bytes(id);
    let packet = build_query(id, name, qtype)?;
    let bind: SocketAddr = if server.is_ipv4() { (Ipv4Addr::UNSPECIFIED, 0).into() } else { (Ipv6Addr::UNSPECIFIED, 0).into() };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(server).await?;
    let mut buf = [0u8; 2048];
    for _ in 0..2 {
        sock.send(&packet).await?;
        let deadline = tokio::time::Instant::now() + Duration::from_millis(2500);
        // Keep reading until our answer or the deadline: anything else on
        // the socket is not for this question.
        while let Ok(Ok(n)) = tokio::time::timeout_at(deadline, sock.recv(&mut buf)).await {
            if let Some(r) = parse_reply(&buf[..n], id, name, qtype) {
                return r;
            }
        }
    }
    anyhow::bail!("no answer from {server}")
}

fn build_query(id: u16, name: &str, qtype: u16) -> anyhow::Result<Vec<u8>> {
    let mut p = Vec::with_capacity(32 + name.len());
    p.extend_from_slice(&id.to_be_bytes());
    // Recursion desired, one question.
    p.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.trim_end_matches('.').split('.') {
        anyhow::ensure!(!label.is_empty() && label.len() <= 63 && label.is_ascii(), "bad name");
        p.push(label.len() as u8);
        p.extend_from_slice(label.as_bytes());
    }
    anyhow::ensure!(p.len() <= 12 + 254, "name too long");
    p.push(0);
    p.extend_from_slice(&qtype.to_be_bytes());
    p.extend_from_slice(&[0, 1]);
    Ok(p)
}

/// None = not a reply to this question (ignore it); Some(Err) = the server
/// said no; Some(Ok) = the answers of the type asked for.
fn parse_reply(b: &[u8], id: u16, name: &str, qtype: u16) -> Option<anyhow::Result<Vec<Answer>>> {
    let sent = build_query(id, name, qtype).ok()?;
    if b.len() < sent.len() || b[..2] != sent[..2] || b[2] & 0x80 == 0 {
        return None;
    }
    // The question must come back as asked (names compare without case).
    if u16::from_be_bytes([b[4], b[5]]) != 1 || !b[12..sent.len()].eq_ignore_ascii_case(&sent[12..]) {
        return None;
    }
    let rcode = b[3] & 0x0f;
    if rcode != 0 {
        return Some(Err(anyhow::anyhow!("the DNS server answered with error {rcode}")));
    }
    if b[2] & 0x02 != 0 {
        return Some(Err(anyhow::anyhow!("the answer was cut short")));
    }
    let count = u16::from_be_bytes([b[6], b[7]]).min(32);
    let mut at = sent.len();
    let mut out = Vec::new();
    for _ in 0..count {
        let Some(next) = skip_name(b, at) else { break };
        let Some(h) = b.get(next..next + 10) else { break };
        let rtype = u16::from_be_bytes([h[0], h[1]]);
        let rdlen = u16::from_be_bytes([h[8], h[9]]) as usize;
        let Some(rd) = b.get(next + 10..next + 10 + rdlen) else { break };
        at = next + 10 + rdlen;
        if rtype != qtype {
            continue;
        }
        match rtype {
            TYPE_A if rd.len() == 4 => out.push(Answer::Addr(IpAddr::V4(Ipv4Addr::new(rd[0], rd[1], rd[2], rd[3])))),
            TYPE_AAAA if rd.len() == 16 => {
                let mut o = [0u8; 16];
                o.copy_from_slice(rd);
                out.push(Answer::Addr(IpAddr::V6(Ipv6Addr::from(o))));
            }
            TYPE_TXT => {
                let mut parts = Vec::new();
                let mut i = 0;
                while i < rd.len() {
                    let n = rd[i] as usize;
                    let Some(s) = rd.get(i + 1..i + 1 + n) else { break };
                    parts.push(String::from_utf8_lossy(s).into_owned());
                    i += 1 + n;
                }
                out.push(Answer::Txt(parts));
            }
            _ => {}
        }
    }
    Some(Ok(out))
}

/// The offset just past a (possibly compressed) name starting at `at`.
fn skip_name(b: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let len = *b.get(at)? as usize;
        if len & 0xc0 == 0xc0 {
            // A pointer ends the name; what it points at needn't be read.
            return (at + 2 <= b.len()).then_some(at + 2);
        }
        if len & 0xc0 != 0 {
            return None;
        }
        at += 1 + len;
        if len == 0 {
            return Some(at);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reply to `build_query(id, name, qtype)` carrying `records`
    /// (type, rdata), each named by a pointer to the question.
    fn reply(id: u16, name: &str, qtype: u16, records: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut p = build_query(id, name, qtype).unwrap();
        p[2] = 0x81;
        p[3] = 0x80;
        p[7] = records.len() as u8;
        for (t, rd) in records {
            p.extend_from_slice(&[0xc0, 0x0c]);
            p.extend_from_slice(&t.to_be_bytes());
            p.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
            p.extend_from_slice(&(rd.len() as u16).to_be_bytes());
            p.extend_from_slice(rd);
        }
        p
    }

    fn txt(parts: &[&str]) -> Vec<u8> {
        parts.iter().flat_map(|s| std::iter::once(s.len() as u8).chain(s.bytes())).collect()
    }

    #[test]
    fn reads_who_asked_answers() {
        let name = "whoami.ds.akahelp.net";
        let r = reply(7, name, TYPE_TXT, &[(TYPE_TXT, txt(&["ecs", "203.0.113.0/24/0"])), (TYPE_TXT, txt(&["ns", "2001:db8::abcd"]))]);
        let ans = parse_reply(&r, 7, name, TYPE_TXT).unwrap().unwrap();
        assert_eq!(ans.iter().find_map(whoami_ip), Some("2001:db8::abcd".parse().unwrap()));

        let name = "o-o.myaddr.l.google.com";
        let r = reply(9, name, TYPE_TXT, &[(TYPE_TXT, txt(&["edns0-client-subnet 198.51.100.0/24"])), (TYPE_TXT, txt(&["198.51.100.7"]))]);
        let ans = parse_reply(&r, 9, name, TYPE_TXT).unwrap().unwrap();
        assert_eq!(ans.iter().find_map(whoami_ip), Some("198.51.100.7".parse().unwrap()));

        // A CNAME in front of the address is skipped.
        let r = reply(3, "whoami.akamai.net", TYPE_A, &[(5, vec![1, b'x', 0]), (TYPE_A, vec![192, 0, 2, 9])]);
        assert_eq!(parse_reply(&r, 3, "whoami.akamai.net", TYPE_A).unwrap().unwrap(), vec![Answer::Addr("192.0.2.9".parse().unwrap())]);
    }

    #[test]
    fn only_a_reply_to_the_question_asked_counts() {
        let name = "example.com";
        let good = reply(5, name, TYPE_A, &[(TYPE_A, vec![192, 0, 2, 1])]);
        assert!(parse_reply(&good, 5, name, TYPE_A).is_some());
        // Another id, another name, another type, or a query rather than a reply.
        assert!(parse_reply(&good, 6, name, TYPE_A).is_none());
        assert!(parse_reply(&good, 5, "example.org", TYPE_A).is_none());
        assert!(parse_reply(&good, 5, name, TYPE_TXT).is_none());
        assert!(parse_reply(&build_query(5, name, TYPE_A).unwrap(), 5, name, TYPE_A).is_none());
        // Servers may answer in another letter case.
        assert!(parse_reply(&reply(5, "EXAMPLE.com", TYPE_A, &[]), 5, name, TYPE_A).is_some());
        // An error from the server is an answer, of the unhappy kind.
        let mut refused = reply(5, name, TYPE_A, &[]);
        refused[3] = 0x85;
        assert!(parse_reply(&refused, 5, name, TYPE_A).unwrap().is_err());
    }

    #[test]
    fn broken_replies_do_no_harm() {
        let name = "example.com";
        let good = reply(5, name, TYPE_TXT, &[(TYPE_TXT, txt(&["ns", "192.0.2.1"])), (TYPE_TXT, txt(&["x"]))]);
        // Every truncation parses without panicking, to whatever is whole.
        for n in 0..good.len() {
            let _ = parse_reply(&good[..n], 5, name, TYPE_TXT);
        }
        // Lengths that point past the end.
        let mut bad = reply(5, name, TYPE_TXT, &[(TYPE_TXT, txt(&["abc"]))]);
        let n = bad.len();
        bad[n - 4] = 200;
        assert_eq!(parse_reply(&bad, 5, name, TYPE_TXT).unwrap().unwrap(), vec![Answer::Txt(vec![])]);
        let mut bad = reply(5, name, TYPE_TXT, &[(TYPE_TXT, txt(&["abc"]))]);
        let n = bad.len();
        bad[n - 5] = 0xff;
        assert!(parse_reply(&bad, 5, name, TYPE_TXT).unwrap().unwrap().is_empty());
        // A claimed 65535 answers with none present.
        let mut bad = reply(5, name, TYPE_TXT, &[]);
        bad[6] = 0xff;
        bad[7] = 0xff;
        assert!(parse_reply(&bad, 5, name, TYPE_TXT).unwrap().unwrap().is_empty());
        assert!(build_query(1, "a..b", TYPE_A).is_err());
        assert!(build_query(1, &"a".repeat(64), TYPE_A).is_err());
    }

    #[test]
    fn network_names_are_read_and_cleaned() {
        assert_eq!(parse_origin("13335 | 1.1.1.0/24 | US | arin | 2010-07-14"), Some(13335));
        assert_eq!(parse_origin("37680 3741 | 102.132.0.0/16 | ZA | afrinic |"), Some(37680));
        assert_eq!(parse_origin("NA | x"), None);
        assert_eq!(parse_as_name("37680 | ZA | afrinic | 2013-01-22 | COOL-IDEAS, ZA").as_deref(), Some("COOL-IDEAS"));
        assert_eq!(parse_as_name("1 | US | arin | 2001 | LVLT-1 - Level 3 Parent, LLC, US").as_deref(), Some("LVLT-1 - Level 3 Parent LLC"));
        // Markup or control characters in someone else's text never get through.
        assert_eq!(parse_as_name("1 | <script>alert(1)</script>\u{7}, ZA").as_deref(), Some("scriptalert1/script"));
        assert_eq!(parse_as_name("1 | , ZA"), None);
        assert_eq!(parse_as_name(&format!("1 | {}", "A".repeat(200))).map(|s| s.len()), Some(48));
    }

    #[test]
    fn configured_servers_are_found() {
        let conf = "# made by NetworkManager\nsearch arda\nnameserver 192.168.1.1\nnameserver fe80::1%eth0\nnameserver 192.168.1.1\noptions edns0\nnameserver nonsense\n";
        assert_eq!(parse_resolv_conf(conf), vec!["192.168.1.1".parse::<IpAddr>().unwrap(), "fe80::1".parse().unwrap()]);
        let stub: IpAddr = "127.0.0.53".parse().unwrap();
        let router: IpAddr = "192.168.1.1".parse().unwrap();
        assert_eq!(shown_servers(&[stub, router]), vec!["192.168.1.1"]);
        assert_eq!(shown_servers(&[stub]), vec!["127.0.0.53"]);
    }

    #[test]
    fn described_in_plain_words_and_safely_for_visitors() {
        let v = DnsView {
            servers: vec!["192.168.1.1".into()],
            resolver: Some("102.132.1.1".into()),
            owner: Some("COOL-IDEAS".into()),
            asn: Some(37680),
            kind: Some(DnsKind::Isp),
            ..Default::default()
        };
        assert_eq!(v.describe(true), "COOL-IDEAS (AS37680), your internet provider, via 192.168.1.1");
        let p = v.public().unwrap();
        assert!(p.servers.is_empty() && p.resolver.is_none());
        assert_eq!(p.text, "COOL-IDEAS (AS37680), the internet provider");
        let json = serde_json::to_string(&p).unwrap();
        assert!(!json.contains("192.168") && !json.contains("102.132") && !json.contains("servers"), "{json}");

        let own = DnsView { kind: Some(DnsKind::Own), resolver: Some("102.132.1.9".into()), servers: vec!["192.168.1.1".into()], ..Default::default() };
        assert_eq!(own.describe(true), "your own resolver, on this connection, via 192.168.1.1");
        assert_eq!(own.public().unwrap().describe(false), "its own resolver, on the same connection");
        assert!(!serde_json::to_string(&own.public().unwrap()).unwrap().contains("102.132"));

        let cf = DnsView {
            kind: Some(DnsKind::Public),
            owner: Some("Cloudflare".into()),
            asn: Some(13335),
            servers: vec!["1.1.1.1".into()],
            resolver: Some("172.68.1.1".into()),
            ..Default::default()
        };
        assert_eq!(cf.describe(true), "Cloudflare (AS13335), via 1.1.1.1");
        // Only the configured servers known: those, and nothing for visitors.
        let bare = DnsView { servers: vec!["192.168.1.1".into()], ..Default::default() };
        assert_eq!(bare.describe(true), "192.168.1.1");
        assert!(bare.public().is_none());
    }
}
