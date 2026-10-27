//! How much memory this machine (or the container or service slice pingrail
//! runs in) has, for sizing password hashing.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Memory {
    /// Physical memory pingrail may use at most, in bytes.
    pub total: u64,
    /// Memory free for use right now, in bytes.
    pub available: u64,
}

/// The machine's memory, narrowed by any cgroup limit (Linux), or `None`
/// when it can't be read.
pub fn detect() -> Option<Memory> {
    imp::detect()
}

#[cfg(target_os = "linux")]
mod imp {
    use super::Memory;
    use std::path::{Path, PathBuf};

    pub fn detect() -> Option<Memory> {
        let info = std::fs::read_to_string("/proc/meminfo").ok()?;
        let mut m = parse_meminfo(&info)?;
        if let Some((limit, used)) = cgroup_limit() {
            m.total = m.total.min(limit);
            m.available = m.available.min(limit.saturating_sub(used));
        }
        Some(m)
    }

    pub(super) fn parse_meminfo(s: &str) -> Option<Memory> {
        let field = |name: &str| -> Option<u64> {
            s.lines()
                .find_map(|l| l.strip_prefix(name)?.strip_prefix(':'))?
                .split_whitespace()
                .next()?
                .parse::<u64>()
                .ok()
                .map(|kib| kib * 1024)
        };
        let total = field("MemTotal")?;
        // Kernels before 3.14 lack MemAvailable; free + cache is close enough.
        let available = field("MemAvailable")
            .or_else(|| Some(field("MemFree")? + field("Cached").unwrap_or(0)))
            .unwrap_or(total / 2);
        Some(Memory { total, available: available.min(total) })
    }

    /// The tightest memory limit on this process's cgroup or any parent, and
    /// what that cgroup uses now.
    fn cgroup_limit() -> Option<(u64, u64)> {
        let own = std::fs::read_to_string("/proc/self/cgroup").ok()?;
        // cgroup v2: one line "0::/path".
        if let Some(rel) = own.lines().find_map(|l| l.strip_prefix("0::")) {
            let root = Path::new("/sys/fs/cgroup");
            let mut dir: PathBuf = root.join(rel.trim_start_matches('/'));
            let mut best: Option<(u64, u64)> = None;
            while dir.starts_with(root) {
                if let Some(limit) = read_u64(&dir.join("memory.max")) {
                    let used = read_u64(&dir.join("memory.current")).unwrap_or(0);
                    if best.is_none_or(|(b, _)| limit < b) {
                        best = Some((limit, used));
                    }
                }
                if !dir.pop() {
                    break;
                }
            }
            return best;
        }
        // cgroup v1.
        let dir = Path::new("/sys/fs/cgroup/memory");
        let limit = read_u64(&dir.join("memory.limit_in_bytes"))?;
        // "No limit" is reported as a huge number.
        if limit >= 1 << 60 {
            return None;
        }
        Some((limit, read_u64(&dir.join("memory.usage_in_bytes")).unwrap_or(0)))
    }

    /// A number from a cgroup file; "max" (no limit) reads as nothing.
    fn read_u64(p: &Path) -> Option<u64> {
        std::fs::read_to_string(p).ok()?.trim().parse().ok()
    }
}

#[cfg(windows)]
mod imp {
    use super::Memory;
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

    pub fn detect() -> Option<Memory> {
        // SAFETY: MEMORYSTATUSEX is plain data; dwLength must be set first.
        let mut s: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
        s.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        if unsafe { GlobalMemoryStatusEx(&mut s) } == 0 {
            return None;
        }
        Some(Memory { total: s.ullTotalPhys, available: s.ullAvailPhys.min(s.ullTotalPhys) })
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
mod imp {
    use super::Memory;

    pub fn detect() -> Option<Memory> {
        // SAFETY: sysconf only reads system values.
        let (pages, size) = unsafe { (libc::sysconf(libc::_SC_PHYS_PAGES), libc::sysconf(libc::_SC_PAGESIZE)) };
        if pages <= 0 || size <= 0 {
            return None;
        }
        let total = pages as u64 * size as u64;
        Some(Memory { total, available: total / 2 })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn this_machine_has_memory() {
        let m = super::detect().expect("memory readable");
        assert!(m.total > 64 << 20 && m.available <= m.total, "{m:?}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn meminfo_parses() {
        let m = super::imp::parse_meminfo("MemTotal:        8000000 kB\nMemFree:  1000 kB\nMemAvailable:    6000000 kB\n").unwrap();
        assert_eq!(m.total, 8_000_000 * 1024);
        assert_eq!(m.available, 6_000_000 * 1024);
        // Old kernels: free + cached.
        let m = super::imp::parse_meminfo("MemTotal: 1000 kB\nMemFree: 100 kB\nCached: 300 kB\n").unwrap();
        assert_eq!(m.available, 400 * 1024);
    }
}
