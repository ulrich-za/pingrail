//! ICMP echo probing with a configurable TTL.
//!
//! * Linux/Unix: raw ICMP sockets (needs CAP_NET_RAW, granted by the package
//!   via `setcap` and by the systemd unit).
//! * Windows: the IP Helper API (`IcmpSendEcho` / `Icmp6SendEcho2`), which
//!   needs no administrator rights and is what `tracert` uses.

use std::net::IpAddr;
use std::time::Duration;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::Prober;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::Prober;

/// What kind of ICMP message answered a probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyKind {
    /// Echo reply from the destination.
    Echo,
    /// TTL expired in transit (a router on the path).
    TimeExceeded,
    /// Destination unreachable (code is the ICMP code).
    Unreachable,
}

#[derive(Debug, Clone, Copy)]
pub struct ProbeReply {
    pub from: IpAddr,
    pub rtt: Duration,
    pub kind: ReplyKind,
}

/// Parameters for one probe.
#[derive(Debug, Clone, Copy)]
pub struct ProbeSpec {
    pub dst: IpAddr,
    pub ttl: u8,
    pub timeout: Duration,
    pub payload: usize,
}

/// Default TTL for endpoint pings.
pub const ENDPOINT_TTL: u8 = 64;

/// Build the ICMP echo payload (a recognisable pattern).
pub(crate) fn payload_bytes(len: usize) -> Vec<u8> {
    let pat = b"pingrail-probe-";
    (0..len).map(|i| pat[i % pat.len()]).collect()
}

/// Internet checksum (RFC 1071).
#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [b] = chunks.remainder() {
        sum += (*b as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_known_vector() {
        // Example from RFC 1071 section 3.
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(checksum(&data), !0xddf2u16);
    }

    #[test]
    fn checksum_verifies_to_zero() {
        let mut pkt = vec![8u8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01];
        pkt.extend(payload_bytes(13));
        let c = checksum(&pkt);
        pkt[2..4].copy_from_slice(&c.to_be_bytes());
        assert_eq!(checksum(&pkt), 0);
    }
}
