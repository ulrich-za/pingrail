//! ICMP prober for Windows using the IP Helper API.
//!
//! `IcmpSendEcho` / `Icmp6SendEcho2` work without administrator rights and are
//! not affected by the Windows Firewall rules that block raw sockets. Each
//! call blocks until a reply or the timeout, so probes run on Tokio's blocking
//! thread pool. Round-trip times are measured with a monotonic clock around
//! the call (the API itself only reports whole milliseconds).

use super::{payload_bytes, ProbeReply, ProbeSpec, ReplyKind};
use anyhow::{anyhow, Result};
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;
use windows_sys::Win32::Foundation::{GetLastError, INVALID_HANDLE_VALUE};
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::Networking::WinSock::{AF_INET6, SOCKADDR_IN6};

pub struct Prober;

impl Prober {
    pub fn new() -> Result<Prober> {
        // Sanity-check that the API is usable.
        unsafe {
            let h = IcmpCreateFile();
            if h == INVALID_HANDLE_VALUE {
                return Err(anyhow!("IcmpCreateFile failed (error {})", GetLastError()));
            }
            IcmpCloseHandle(h);
        }
        Ok(Prober)
    }

    pub async fn probe(&self, spec: ProbeSpec) -> Result<Option<ProbeReply>> {
        tokio::task::spawn_blocking(move || match spec.dst {
            IpAddr::V4(a) => probe_v4(a, spec),
            IpAddr::V6(a) => probe_v6(a, spec),
        })
        .await?
    }
}

fn status_kind(status: u32) -> Option<ReplyKind> {
    match status {
        IP_SUCCESS => Some(ReplyKind::Echo),
        IP_TTL_EXPIRED_TRANSIT | IP_TTL_EXPIRED_REASSEM => Some(ReplyKind::TimeExceeded),
        IP_DEST_HOST_UNREACHABLE | IP_DEST_NET_UNREACHABLE | IP_DEST_PORT_UNREACHABLE
        | IP_DEST_PROT_UNREACHABLE | IP_DEST_UNREACHABLE => Some(ReplyKind::Unreachable),
        _ => None,
    }
}

fn probe_v4(dst: Ipv4Addr, spec: ProbeSpec) -> Result<Option<ProbeReply>> {
    let payload = payload_bytes(spec.payload);
    // u64 backing store keeps the reply struct (which holds a pointer) aligned.
    let reply_len = size_of::<ICMP_ECHO_REPLY>() + payload.len().max(8) + 8 + 256;
    let mut buf = vec![0u64; reply_len.div_ceil(8)];
    unsafe {
        let h = IcmpCreateFile();
        if h == INVALID_HANDLE_VALUE {
            return Err(anyhow!("IcmpCreateFile failed (error {})", GetLastError()));
        }
        let mut opts: IP_OPTION_INFORMATION = zeroed();
        opts.Ttl = spec.ttl;
        let start = Instant::now();
        let n = IcmpSendEcho(
            h,
            u32::from_ne_bytes(dst.octets()),
            payload.as_ptr() as *const c_void,
            payload.len() as u16,
            &opts,
            buf.as_mut_ptr() as *mut c_void,
            (buf.len() * 8) as u32,
            spec.timeout.as_millis().min(u32::MAX as u128) as u32,
        );
        let rtt = start.elapsed();
        let err = if n == 0 { GetLastError() } else { 0 };
        IcmpCloseHandle(h);

        let reply = &*(buf.as_ptr() as *const ICMP_ECHO_REPLY);
        let status = if n > 0 { reply.Status } else { err };
        if status == IP_REQ_TIMED_OUT {
            return Ok(None);
        }
        let Some(kind) = status_kind(status) else {
            if n == 0 && err != 0 && err < 11000 {
                return Err(anyhow!("IcmpSendEcho failed (error {err})"));
            }
            return Ok(None);
        };
        if reply.Address == 0 {
            return Ok(None);
        }
        let from = IpAddr::V4(Ipv4Addr::from(reply.Address.to_ne_bytes()));
        Ok(Some(ProbeReply { from, rtt, kind }))
    }
}

fn probe_v6(dst: Ipv6Addr, spec: ProbeSpec) -> Result<Option<ProbeReply>> {
    let payload = payload_bytes(spec.payload);
    let reply_len = size_of::<ICMPV6_ECHO_REPLY_LH>() + payload.len().max(8) + 8 + 256;
    let mut buf = vec![0u64; reply_len.div_ceil(8)];
    unsafe {
        let h = Icmp6CreateFile();
        if h == INVALID_HANDLE_VALUE {
            return Err(anyhow!("Icmp6CreateFile failed (error {})", GetLastError()));
        }
        let mut src: SOCKADDR_IN6 = zeroed();
        src.sin6_family = AF_INET6;
        let mut dst_sa: SOCKADDR_IN6 = zeroed();
        dst_sa.sin6_family = AF_INET6;
        dst_sa.sin6_addr.u.Byte = dst.octets();
        let mut opts: IP_OPTION_INFORMATION = zeroed();
        opts.Ttl = spec.ttl;
        let start = Instant::now();
        let n = Icmp6SendEcho2(
            h,
            std::ptr::null_mut(),
            None,
            std::ptr::null(),
            &src,
            &dst_sa,
            payload.as_ptr() as *const c_void,
            payload.len() as u16,
            &opts,
            buf.as_mut_ptr() as *mut c_void,
            (buf.len() * 8) as u32,
            spec.timeout.as_millis().min(u32::MAX as u128) as u32,
        );
        let rtt = start.elapsed();
        let err = if n == 0 { GetLastError() } else { 0 };
        IcmpCloseHandle(h);

        let reply = &*(buf.as_ptr() as *const ICMPV6_ECHO_REPLY_LH);
        let status = if n > 0 { reply.Status } else { err };
        if status == IP_REQ_TIMED_OUT {
            return Ok(None);
        }
        let Some(kind) = status_kind(status) else {
            if n == 0 && err != 0 && err < 11000 {
                return Err(anyhow!("Icmp6SendEcho2 failed (error {err})"));
            }
            return Ok(None);
        };
        let mut octets = [0u8; 16];
        // IPV6_ADDRESS_EX is packed: copy the words out before iterating.
        let words: [u16; 8] = std::ptr::addr_of!(reply.Address.sin6_addr).read_unaligned();
        for (i, w) in words.iter().enumerate() {
            octets[i * 2..i * 2 + 2].copy_from_slice(&w.to_ne_bytes());
        }
        let from = Ipv6Addr::from(octets);
        if from.is_unspecified() {
            return Ok(None);
        }
        Ok(Some(ProbeReply { from: IpAddr::V6(from), rtt, kind }))
    }
}
