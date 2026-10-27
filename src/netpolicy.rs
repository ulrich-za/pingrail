//! Address classification for share links: which hop addresses count as
//! "private" when hiding them, and which destinations a visitor may add.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn v4_in(ip: Ipv4Addr, net: [u8; 4], bits: u8) -> bool {
    let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits as u32) };
    (u32::from(ip) & mask) == (u32::from(Ipv4Addr::from(net)) & mask)
}

fn v6_in(ip: Ipv6Addr, net: Ipv6Addr, bits: u8) -> bool {
    let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits as u32) };
    (u128::from(ip) & mask) == (u128::from(net) & mask)
}

/// Addresses that only make sense inside a site: RFC 1918, loopback,
/// link-local and IPv6 unique-local. These are what "hide private hops" masks.
pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_private() || a.is_loopback() || a.is_link_local() || a.is_unspecified(),
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return is_private(IpAddr::V4(v4));
            }
            a.is_loopback()
                || a.is_unspecified()
                || v6_in(a, "fe80::".parse().unwrap(), 10)
                || v6_in(a, "fc00::".parse().unwrap(), 7)
                // Deprecated site-local, still routed inside some networks.
                || v6_in(a, "fec0::".parse().unwrap(), 10)
        }
    }
}

/// IPv4 blocks visitors may not probe: every entry in IANA's IPv4
/// Special-Purpose Address Registry (as of 2025-10-09, including the few
/// marked globally reachable, which are anycast services rather than hosts),
/// plus multicast. Private-use, loopback and link-local are refused by
/// `is_private` first.
const V4_REFUSED: [([u8; 4], u8); 15] = [
    ([0, 0, 0, 0], 8),        // "this network"
    ([100, 64, 0, 0], 10),    // shared address space (carrier-grade NAT)
    ([192, 0, 0, 0], 24),     // IETF protocol assignments (incl. PCP/TURN anycast, NAT64 discovery)
    ([192, 0, 2, 0], 24),     // documentation (TEST-NET-1)
    ([192, 31, 196, 0], 24),  // AS112-v4
    ([192, 52, 193, 0], 24),  // AMT
    ([192, 88, 99, 0], 24),   // deprecated 6to4 relay anycast (incl. 6a44)
    ([192, 175, 48, 0], 24),  // direct delegation AS112
    ([198, 18, 0, 0], 15),    // benchmarking
    ([198, 51, 100, 0], 24),  // documentation (TEST-NET-2)
    ([203, 0, 113, 0], 24),   // documentation (TEST-NET-3)
    ([224, 0, 0, 0], 4),      // multicast
    ([240, 0, 0, 0], 4),      // reserved
    ([255, 255, 255, 255], 32), // limited broadcast (inside 240/4; listed for clarity)
    ([127, 0, 0, 0], 8),      // loopback (also caught by is_private)
];

/// IPv6: only global unicast (2000::/3) is allowed at all; inside it, these
/// IANA special-purpose blocks are refused (registry as of 2025-10-09).
/// Everything else in the registry (::1, ::, 64:ff9b:1::/48, 100::/64,
/// 100:0:0:1::/64, 5f00::/16, fc00::/7, fe80::/10) and multicast lies
/// outside 2000::/3 and is refused by the allow-list.
const V6_REFUSED: [(&str, u8); 5] = [
    ("2001::", 23),        // IETF protocol assignments: Teredo, benchmarking, AMT, AS112, ORCHID(v2), DETs, anycasts
    ("2001:db8::", 32),    // documentation
    ("2002::", 16),        // 6to4 (deprecated; embeds hidden IPv4 addresses)
    ("2620:4f:8000::", 48), // direct delegation AS112
    ("3fff::", 20),        // documentation
];

/// Globally routable unicast addresses a share-link visitor may add as a
/// destination without an explicit exception. IPv4-mapped (::ffff:a.b.c.d)
/// and NAT64 (64:ff9b::a.b.c.d) addresses are judged by the IPv4 address
/// they carry, since that's where the packets end up.
pub fn is_public(ip: IpAddr) -> bool {
    if is_private(ip) {
        return false;
    }
    match ip {
        IpAddr::V4(a) => !V4_REFUSED.iter().any(|(n, b)| v4_in(a, *n, *b)),
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            if v6_in(a, "64:ff9b::".parse().unwrap(), 96) {
                let o = a.octets();
                return is_public(IpAddr::V4(Ipv4Addr::new(o[12], o[13], o[14], o[15])));
            }
            v6_in(a, "2000::".parse().unwrap(), 3) && !V6_REFUSED.iter().any(|(n, b)| v6_in(a, n.parse().unwrap(), *b))
        }
    }
}

/// Parse "10.0.0.0/8", "192.168.1.1" or "fd00::/8".
pub fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let s = s.trim();
    let (addr, bits) = match s.split_once('/') {
        Some((a, b)) => (a.trim(), Some(b.trim().parse::<u8>().ok()?)),
        None => (s, None),
    };
    let ip: IpAddr = addr.parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let bits = bits.unwrap_or(max);
    (bits <= max).then_some((ip, bits))
}

pub fn in_cidr(ip: IpAddr, net: IpAddr, bits: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => v4_in(a, n.octets(), bits),
        (IpAddr::V6(a), IpAddr::V6(n)) => v6_in(a, n, bits),
        _ => false,
    }
}

/// May a restricted target probe `ip`?
pub fn destination_allowed(ip: IpAddr, exceptions: &[String]) -> bool {
    is_public(ip)
        || exceptions
            .iter()
            .filter_map(|e| parse_cidr(e))
            .any(|(net, bits)| in_cidr(ip, net, bits))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn classification() {
        for p in ["192.168.0.1", "10.1.2.3", "172.16.5.4", "127.0.0.1", "169.254.1.1", "fd12::1", "fe80::1", "::1"] {
            assert!(is_private(ip(p)), "{p} should be private");
            assert!(!is_public(ip(p)), "{p} should not be public");
        }
        assert!(is_private(ip("fec0::1")), "deprecated site-local counts as private when hiding hops");
        // CGNAT and documentation ranges: not private for display, not public for visitors.
        assert!(!is_private(ip("100.64.1.1")) && !is_public(ip("100.64.1.1")));
    }

    /// Real, routable destinations stay allowed, including next to the edges
    /// of refused blocks.
    #[test]
    fn public_destinations_are_allowed() {
        for p in [
            "1.1.1.1", "8.8.8.8", "9.9.9.9", "154.0.0.131", "197.234.240.37", "100.63.255.255", "100.128.0.0",
            "192.0.1.255", "192.0.3.0", "198.17.255.255", "198.20.0.0", "223.255.255.255",
            "2606:4700:4700::1111", "2001:4860:4860::8888", "2a00:1450:4001::200e", "2c0f:fb50:4002::1",
            "2001:200::1", "2003::1", "3fff:1000::1", "2620:4f:8001::1",
            "::ffff:8.8.8.8", "64:ff9b::808:808",
        ] {
            assert!(is_public(ip(p)), "{p} should be allowed");
        }
    }

    /// One address from every entry in IANA's IPv4 and IPv6 Special-Purpose
    /// Address Registries (2025-10-09), plus multicast and other non-global
    /// space. None may be added by a visitor.
    #[test]
    fn every_iana_special_purpose_block_is_refused() {
        let v4 = [
            ("0.0.0.0/8", "0.1.2.3"),
            ("0.0.0.0/32", "0.0.0.0"),
            ("10.0.0.0/8", "10.255.255.255"),
            ("100.64.0.0/10", "100.127.255.255"),
            ("127.0.0.0/8", "127.8.8.8"),
            ("169.254.0.0/16", "169.254.169.254"),
            ("172.16.0.0/12", "172.31.255.255"),
            ("192.0.0.0/24", "192.0.0.200"),
            ("192.0.0.0/29", "192.0.0.7"),
            ("192.0.0.8/32", "192.0.0.8"),
            ("192.0.0.9/32 (PCP anycast)", "192.0.0.9"),
            ("192.0.0.10/32 (TURN anycast)", "192.0.0.10"),
            ("192.0.0.170/32", "192.0.0.170"),
            ("192.0.0.171/32", "192.0.0.171"),
            ("192.0.2.0/24", "192.0.2.1"),
            ("192.31.196.0/24 (AS112)", "192.31.196.1"),
            ("192.52.193.0/24 (AMT)", "192.52.193.1"),
            ("192.88.99.0/24 (deprecated 6to4 relay)", "192.88.99.1"),
            ("192.88.99.2/32 (6a44 relay)", "192.88.99.2"),
            ("192.168.0.0/16", "192.168.255.254"),
            ("192.175.48.0/24 (AS112)", "192.175.48.1"),
            ("198.18.0.0/15", "198.19.255.255"),
            ("198.51.100.0/24", "198.51.100.7"),
            ("203.0.113.0/24", "203.0.113.200"),
            ("240.0.0.0/4", "250.1.1.1"),
            ("255.255.255.255/32", "255.255.255.255"),
            ("224.0.0.0/4 (multicast)", "239.255.255.250"),
        ];
        let v6 = [
            ("::1/128", "::1"),
            ("::/128", "::"),
            ("::ffff:0:0/96 (mapped private)", "::ffff:192.168.1.1"),
            ("::ffff:0:0/96 (mapped loopback)", "::ffff:127.0.0.1"),
            ("64:ff9b::/96 (NAT64 of private)", "64:ff9b::c0a8:101"),
            ("64:ff9b::/96 (NAT64 of CGNAT)", "64:ff9b::6440:1"),
            ("64:ff9b:1::/48", "64:ff9b:1::808:808"),
            ("100::/64", "100::1"),
            ("100:0:0:1::/64", "100:0:0:1::1"),
            ("2001::/23", "2001:1ff:ffff::1"),
            ("2001::/32 (Teredo)", "2001:0:4136:e378:8000:63bf:3fff:fdd2"),
            ("2001:1::1/128", "2001:1::1"),
            ("2001:1::2/128", "2001:1::2"),
            ("2001:1::3/128", "2001:1::3"),
            ("2001:2::/48", "2001:2::1"),
            ("2001:3::/32 (AMT)", "2001:3::1"),
            ("2001:4:112::/48 (AS112)", "2001:4:112::1"),
            ("2001:10::/28 (ORCHID)", "2001:10::1"),
            ("2001:20::/28 (ORCHIDv2)", "2001:20::1"),
            ("2001:30::/28 (DETs)", "2001:30::1"),
            ("2001:db8::/32", "2001:db8::1"),
            ("2002::/16 (6to4, even of a public address)", "2002:808:808::1"),
            ("2620:4f:8000::/48 (AS112)", "2620:4f:8000::1"),
            ("3fff::/20", "3fff:fff::1"),
            ("5f00::/16 (SRv6)", "5f00::1"),
            ("fc00::/7", "fd00::1"),
            ("fe80::/10", "fe80::1"),
            ("fec0::/10 (deprecated site-local)", "fec0::1"),
            ("ff00::/8 (multicast)", "ff02::1"),
            ("::/96 (IPv4-compatible, deprecated)", "::8.8.8.8"),
            ("outside 2000::/3", "4000::1"),
            ("outside 2000::/3", "1fff:ffff::1"),
        ];
        for (block, addr) in v4.iter().chain(v6.iter()) {
            assert!(!is_public(ip(addr)), "{addr} ({block}) must be refused");
        }
    }

    #[test]
    fn cidrs() {
        assert_eq!(parse_cidr("10.0.0.0/8"), Some((ip("10.0.0.0"), 8)));
        assert_eq!(parse_cidr("192.168.1.30"), Some((ip("192.168.1.30"), 32)));
        assert_eq!(parse_cidr("10.0.0.0/33"), None);
        assert_eq!(parse_cidr("nope"), None);
        let ex = vec!["192.168.1.0/24".to_string(), "100.64.0.1".to_string()];
        assert!(destination_allowed(ip("192.168.1.30"), &ex));
        assert!(destination_allowed(ip("100.64.0.1"), &ex));
        assert!(!destination_allowed(ip("192.168.8.1"), &ex));
        assert!(destination_allowed(ip("8.8.8.8"), &[]));
    }
}
