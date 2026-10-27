//! Raw-socket ICMP prober for Linux and other Unix systems.

use super::{checksum, payload_bytes, ProbeReply, ProbeSpec, ReplyKind};
use anyhow::{anyhow, Result};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::collections::HashMap;
use std::io;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::sync::oneshot;

struct Pending {
    tx: oneshot::Sender<ProbeReply>,
    sent: Instant,
}

/// Outstanding probes keyed by (is_v6, sequence number).
type PendingMap = Arc<Mutex<HashMap<(bool, u16), Pending>>>;

struct Sock {
    fd: AsyncFd<Socket>,
    /// Setting the TTL and sending must happen together.
    send_lock: Mutex<()>,
}

pub struct Prober {
    v4: Option<Arc<Sock>>,
    v6: Option<Arc<Sock>>,
    v4_err: Option<String>,
    v6_err: Option<String>,
    ident: u16,
    seq: AtomicU16,
    pending: PendingMap,
}

pub const PERMISSION_HINT: &str = "raw ICMP sockets need the CAP_NET_RAW capability. \
The pingrail package grants it automatically; for a manual install run \
`sudo setcap cap_net_raw+ep $(command -v pingrail)` or run as root.";

fn open(domain: Domain, proto: Protocol) -> io::Result<Socket> {
    let s = Socket::new(domain, Type::RAW, Some(proto))?;
    s.set_nonblocking(true)?;
    // Large receive buffer: many targets × many hops can reply at once.
    let _ = s.set_recv_buffer_size(1 << 20);
    Ok(s)
}

fn register(s: Socket) -> io::Result<AsyncFd<Socket>> {
    // SAFETY: the Socket owns its file descriptor for as long as the AsyncFd lives.
    unsafe { AsyncFd::register_with_interest(s, Interest::READABLE) }.map_err(io::Error::from)
}

fn describe(e: &io::Error) -> String {
    if e.kind() == io::ErrorKind::PermissionDenied {
        format!("permission denied: {PERMISSION_HINT}")
    } else {
        e.to_string()
    }
}

impl Prober {
    /// Open the sockets and start the receive loops. Must be called inside a
    /// Tokio runtime.
    pub fn new() -> Result<Prober> {
        let mut rnd = [0u8; 2];
        let _ = getrandom::fill(&mut rnd);
        let ident = (std::process::id() as u16) ^ u16::from_ne_bytes(rnd);
        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));

        let (v4, v4_err) = match open(Domain::IPV4, Protocol::ICMPV4).and_then(register) {
            Ok(fd) => (Some(Arc::new(Sock { fd, send_lock: Mutex::new(()) })), None),
            Err(e) => (None, Some(describe(&e))),
        };
        let (v6, v6_err) = match open(Domain::IPV6, Protocol::ICMPV6).and_then(register) {
            Ok(fd) => (Some(Arc::new(Sock { fd, send_lock: Mutex::new(()) })), None),
            Err(e) => (None, Some(describe(&e))),
        };
        if v4.is_none() && v6.is_none() {
            return Err(anyhow!(
                "cannot open ICMP socket: {}",
                v4_err.clone().unwrap_or_default()
            ));
        }
        if let Some(s) = &v4 {
            tokio::spawn(recv_loop(s.clone(), false, ident, pending.clone()));
        }
        if let Some(s) = &v6 {
            tokio::spawn(recv_loop(s.clone(), true, ident, pending.clone()));
        }
        Ok(Prober { v4, v6, v4_err, v6_err, ident, seq: AtomicU16::new(1), pending })
    }

    /// Send one echo request and wait for whatever answers it.
    /// `Ok(None)` means no reply within the timeout.
    pub async fn probe(&self, spec: ProbeSpec) -> Result<Option<ProbeReply>> {
        let v6 = spec.dst.is_ipv6();
        let sock = if v6 {
            self.v6.as_ref().ok_or_else(|| {
                anyhow!("IPv6 unavailable: {}", self.v6_err.clone().unwrap_or_default())
            })?
        } else {
            self.v4.as_ref().ok_or_else(|| {
                anyhow!("IPv4 unavailable: {}", self.v4_err.clone().unwrap_or_default())
            })?
        };

        let (tx, rx) = oneshot::channel();
        let seq = {
            let map = self.pending.lock().unwrap();
            let mut s;
            loop {
                s = self.seq.fetch_add(1, Ordering::Relaxed);
                if !map.contains_key(&(v6, s)) {
                    break;
                }
            }
            s
        };
        let key = (v6, seq);

        let mut pkt = Vec::with_capacity(8 + spec.payload);
        pkt.push(if v6 { 128 } else { 8 });
        pkt.push(0);
        pkt.extend_from_slice(&[0, 0]);
        pkt.extend_from_slice(&self.ident.to_be_bytes());
        pkt.extend_from_slice(&seq.to_be_bytes());
        pkt.extend_from_slice(&payload_bytes(spec.payload));
        if !v6 {
            // The kernel fills in the ICMPv6 checksum itself.
            let c = checksum(&pkt);
            pkt[2..4].copy_from_slice(&c.to_be_bytes());
        }
        let addr = SockAddr::from(SocketAddr::new(spec.dst, 0));

        {
            let _guard = sock.send_lock.lock().unwrap();
            let s = sock.fd.get_ref();
            if v6 {
                s.set_unicast_hops_v6(spec.ttl as u32)?;
            } else {
                s.set_ttl_v4(spec.ttl as u32)?;
            }
            self.pending.lock().unwrap().insert(key, Pending { tx, sent: Instant::now() });
            if let Err(e) = s.send_to(&pkt, &addr) {
                self.pending.lock().unwrap().remove(&key);
                return Err(e.into());
            }
        }

        match tokio::time::timeout(spec.timeout, rx).await {
            Ok(Ok(reply)) => Ok(Some(reply)),
            _ => {
                self.pending.lock().unwrap().remove(&key);
                Ok(None)
            }
        }
    }
}

async fn recv_loop(sock: Arc<Sock>, v6: bool, ident: u16, pending: PendingMap) {
    let mut buf = vec![MaybeUninit::<u8>::uninit(); 4096];
    loop {
        let mut guard = match sock.fd.readable().await {
            Ok(g) => g,
            Err(e) => {
                tracing::error!("ICMP receive loop stopped: {e}");
                return;
            }
        };
        loop {
            match guard.try_io(|inner| inner.get_ref().recv_from(&mut buf)) {
                Ok(Ok((n, from))) => {
                    let now = Instant::now();
                    // SAFETY: recv_from initialised the first `n` bytes.
                    let data = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
                    let src = from.as_socket().map(|a| a.ip());
                    let parsed = if v6 { parse_v6(data, src) } else { parse_v4(data) };
                    if let Some(p) = parsed {
                        if p.ident != ident {
                            continue;
                        }
                        let entry = pending.lock().unwrap().remove(&(v6, p.seq));
                        if let Some(entry) = entry {
                            let _ = entry.tx.send(ProbeReply {
                                from: p.from,
                                rtt: now.saturating_duration_since(entry.sent),
                                kind: p.kind,
                            });
                        }
                    }
                }
                Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => continue,
                Ok(Err(e)) => {
                    tracing::debug!("ICMP recv error: {e}");
                    break;
                }
                Err(_would_block) => break,
            }
        }
    }
}

#[derive(Debug, PartialEq)]
pub(crate) struct Parsed {
    pub from: IpAddr,
    pub ident: u16,
    pub seq: u16,
    pub kind: ReplyKind,
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

/// Parse an IPv4 packet (with IP header) received on a raw ICMP socket.
pub(crate) fn parse_v4(data: &[u8]) -> Option<Parsed> {
    if data.len() < 20 || data[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((data[0] & 0x0f) as usize) * 4;
    let from = IpAddr::V4(Ipv4Addr::new(data[12], data[13], data[14], data[15]));
    let icmp = data.get(ihl..)?;
    let ty = *icmp.first()?;
    match ty {
        0 => Some(Parsed { from, ident: be16(icmp, 4)?, seq: be16(icmp, 6)?, kind: ReplyKind::Echo }),
        3 | 11 => {
            let inner = icmp.get(8..)?;
            if inner.len() < 20 || inner[0] >> 4 != 4 || inner[9] != 1 {
                return None;
            }
            let inner_ihl = ((inner[0] & 0x0f) as usize) * 4;
            let orig = inner.get(inner_ihl..)?;
            if *orig.first()? != 8 {
                return None;
            }
            let kind = if ty == 11 { ReplyKind::TimeExceeded } else { ReplyKind::Unreachable };
            Some(Parsed { from, ident: be16(orig, 4)?, seq: be16(orig, 6)?, kind })
        }
        _ => None,
    }
}

/// Parse an ICMPv6 message (no IP header) received on a raw ICMPv6 socket.
pub(crate) fn parse_v6(icmp: &[u8], src: Option<IpAddr>) -> Option<Parsed> {
    let from = src?;
    let ty = *icmp.first()?;
    match ty {
        129 => Some(Parsed { from, ident: be16(icmp, 4)?, seq: be16(icmp, 6)?, kind: ReplyKind::Echo }),
        1 | 3 => {
            // 8-byte ICMPv6 header, then the original 40-byte IPv6 header.
            let inner = icmp.get(8..)?;
            if inner.len() < 48 || inner[0] >> 4 != 6 || inner[6] != 58 {
                return None;
            }
            let orig = &inner[40..];
            if orig[0] != 128 {
                return None;
            }
            let kind = if ty == 3 { ReplyKind::TimeExceeded } else { ReplyKind::Unreachable };
            Some(Parsed { from, ident: be16(orig, 4)?, seq: be16(orig, 6)?, kind })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_header(src: [u8; 4], proto: u8) -> Vec<u8> {
        let mut h = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, proto, 0, 0];
        h.extend_from_slice(&src);
        h.extend_from_slice(&[10, 0, 0, 1]);
        h
    }

    #[test]
    fn echo_reply_v4() {
        let mut pkt = ipv4_header([8, 8, 8, 8], 1);
        pkt.extend_from_slice(&[0, 0, 0, 0, 0xab, 0xcd, 0x00, 0x07, 1, 2, 3]);
        let p = parse_v4(&pkt).unwrap();
        assert_eq!(p.from, "8.8.8.8".parse::<IpAddr>().unwrap());
        assert_eq!((p.ident, p.seq, p.kind), (0xabcd, 7, ReplyKind::Echo));
    }

    #[test]
    fn time_exceeded_v4() {
        let mut pkt = ipv4_header([192, 168, 1, 1], 1);
        pkt.extend_from_slice(&[11, 0, 0, 0, 0, 0, 0, 0]);
        pkt.extend(ipv4_header([10, 0, 0, 1], 1));
        pkt.extend_from_slice(&[8, 0, 0, 0, 0x12, 0x34, 0x01, 0x00]);
        let p = parse_v4(&pkt).unwrap();
        assert_eq!(p.from, "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!((p.ident, p.seq, p.kind), (0x1234, 256, ReplyKind::TimeExceeded));
    }

    #[test]
    fn ignores_echo_requests() {
        let mut pkt = ipv4_header([127, 0, 0, 1], 1);
        pkt.extend_from_slice(&[8, 0, 0, 0, 0, 1, 0, 1]);
        assert!(parse_v4(&pkt).is_none());
    }

    #[test]
    fn time_exceeded_v6() {
        let mut pkt = vec![3, 0, 0, 0, 0, 0, 0, 0];
        let mut ip6 = vec![0x60, 0, 0, 0, 0, 16, 58, 1];
        ip6.extend_from_slice(&[0u8; 32]);
        pkt.extend(ip6);
        pkt.extend_from_slice(&[128, 0, 0, 0, 0xbe, 0xef, 0, 9]);
        let src: IpAddr = "2001:db8::1".parse().unwrap();
        let p = parse_v6(&pkt, Some(src)).unwrap();
        assert_eq!((p.ident, p.seq, p.kind), (0xbeef, 9, ReplyKind::TimeExceeded));
    }

    /// Anyone on the internet can send ICMP to this machine: malformed or
    /// random packets must be ignored, never crash the prober.
    #[test]
    fn random_packets_never_panic() {
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let src: Option<IpAddr> = Some("203.0.113.1".parse().unwrap());
        for _ in 0..200_000 {
            let len = (next() % 120) as usize;
            let mut pkt: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            // Make many of them look nearly valid so deeper code runs too.
            if len > 20 && next() % 2 == 0 {
                pkt[0] = 0x45 | ((next() % 16) as u8);
                pkt[20.min(len - 1)] = [0, 3, 11][(next() % 3) as usize];
            }
            let _ = parse_v4(&pkt);
            if !pkt.is_empty() && next() % 2 == 0 {
                pkt[0] = [129, 1, 3][(next() % 3) as usize];
            }
            let _ = parse_v6(&pkt, src);
        }
    }
}
