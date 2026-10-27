//! Small helpers shared by the CLI and TUI.

use anyhow::{anyhow, bail, Result};
use chrono::{Local, NaiveDateTime, TimeZone};
use std::io::Write;
use std::net::{IpAddr, UdpSocket};

/// The address other machines on the LAN would use to reach us (best guess,
/// no packets are sent).
pub fn lan_ip() -> Option<IpAddr> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("192.0.2.1:9").ok()?;
    let ip = s.local_addr().ok()?.ip();
    (!ip.is_unspecified()).then_some(ip)
}

/// Is `ip` one of this machine's own addresses? (Only those can be bound.)
pub fn is_this_machine(ip: IpAddr) -> bool {
    ip.is_loopback() || UdpSocket::bind((ip, 0)).is_ok()
}

/// This machine's host name as a DNS label ("CAFÉ-PC" becomes
/// "cafe-pc", as routers register it), if there is a usable one.
pub fn hostname() -> Option<String> {
    #[cfg(windows)]
    let name = std::env::var("COMPUTERNAME").ok();
    #[cfg(not(windows))]
    let name = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .or_else(|_| std::fs::read_to_string("/etc/hostname"))
        .ok();
    dns_label(&name?)
}

/// `s` folded to a lower-case DNS label, or `None` if nothing usable is left.
pub fn dns_label(s: &str) -> Option<String> {
    let name: String = s.trim().chars().map(fold_char).collect::<String>().to_ascii_lowercase();
    valid_dns_name(&name).then_some(name).filter(|n| !n.contains('.'))
}

/// Latin letters with accents to their plain letters (other characters are
/// left alone and then rejected as not ASCII).
fn fold_char(c: char) -> char {
    match c {
        'À'..='Å' | 'à'..='å' | 'Ā'..='ą' => 'a',
        'Ç' | 'ç' | 'Ć'..='č' => 'c',
        'Ð' | 'ð' | 'Ď'..='đ' => 'd',
        'È'..='Ë' | 'è'..='ë' | 'Ē'..='ě' => 'e',
        'Ĝ'..='ģ' => 'g',
        'Ĥ'..='ħ' => 'h',
        'Ì'..='Ï' | 'ì'..='ï' | 'Ĩ'..='ı' => 'i',
        'Ĵ' | 'ĵ' => 'j',
        'Ķ' | 'ķ' => 'k',
        'Ĺ'..='ł' => 'l',
        'Ñ' | 'ñ' | 'Ń'..='ň' => 'n',
        'Ò'..='Ö' | 'Ø' | 'ò'..='ö' | 'ø' | 'Ō'..='ő' => 'o',
        'Ŕ'..='ř' => 'r',
        'Ś'..='š' => 's',
        'Ţ'..='ŧ' => 't',
        'Ù'..='Ü' | 'ù'..='ü' | 'Ũ'..='ų' => 'u',
        'Ŵ' | 'ŵ' => 'w',
        'Ý' | 'ý' | 'ÿ' | 'Ŷ'..='Ÿ' => 'y',
        'Ź'..='ž' => 'z',
        c => c,
    }
}

/// An ASCII host name: dot-separated labels of letters, digits and inner
/// hyphens, not all digits at the end (that would be an IP address).
pub fn valid_dns_name(name: &str) -> bool {
    let labels: Vec<&str> = name.split('.').collect();
    !name.is_empty()
        && name.len() <= 253
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
        && !labels.last().is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()))
}

/// The DNS search domains this machine was given (by DHCP or by hand), so
/// "mypc" is also known as "mypc.lan".
pub fn dns_suffixes() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    #[cfg(not(windows))]
    if let Ok(conf) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in conf.lines() {
            let mut words = line.split_whitespace();
            if matches!(words.next(), Some("search" | "domain")) {
                out.extend(words.map(str::to_string));
            }
        }
    }
    #[cfg(windows)]
    out.extend(windows_dns_suffixes());
    let mut clean: Vec<String> = Vec::new();
    for s in out {
        let s = s.trim().trim_end_matches('.').to_ascii_lowercase();
        if valid_dns_name(&s) && !clean.contains(&s) {
            clean.push(s);
        }
    }
    clean
}

/// Primary and connection-specific DNS suffixes from the registry.
#[cfg(windows)]
fn windows_dns_suffixes() -> Vec<String> {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::*;
    let wide = |s: &str| s.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
    let read = |key: HKEY, name: &str| -> Option<String> {
        let name = wide(name);
        let mut buf = vec![0u16; 1024];
        let mut len = (buf.len() * 2) as u32;
        // SAFETY: buf is valid for len bytes; RRF_RT_REG_SZ null-terminates.
        let rc = unsafe {
            RegGetValueW(key, std::ptr::null(), name.as_ptr(), RRF_RT_REG_SZ, std::ptr::null_mut(), buf.as_mut_ptr().cast(), &mut len)
        };
        (rc == ERROR_SUCCESS).then(|| String::from_utf16_lossy(&buf[..(len as usize / 2)]).trim_end_matches('\0').to_string())
    };
    let mut out = Vec::new();
    let base = wide(r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters");
    // SAFETY: plain registry reads with handles closed afterwards.
    unsafe {
        let mut key: HKEY = std::ptr::null_mut();
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, base.as_ptr(), 0, KEY_READ, &mut key) != ERROR_SUCCESS {
            return out;
        }
        for v in ["Domain", "NV Domain", "DhcpDomain"] {
            out.extend(read(key, v));
        }
        if let Some(list) = read(key, "SearchList") {
            out.extend(list.split([',', ' ']).filter(|s| !s.is_empty()).map(str::to_string));
        }
        let ifs = wide("Interfaces");
        let mut ik: HKEY = std::ptr::null_mut();
        if RegOpenKeyExW(key, ifs.as_ptr(), 0, KEY_READ, &mut ik) == ERROR_SUCCESS {
            let mut i = 0u32;
            loop {
                let mut name = [0u16; 256];
                let mut n = name.len() as u32;
                let rc = RegEnumKeyExW(ik, i, name.as_mut_ptr(), &mut n, std::ptr::null(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut());
                if rc != ERROR_SUCCESS {
                    break;
                }
                i += 1;
                let mut sub: HKEY = std::ptr::null_mut();
                if RegOpenKeyExW(ik, name.as_ptr(), 0, KEY_READ, &mut sub) == ERROR_SUCCESS {
                    for v in ["Domain", "DhcpDomain"] {
                        out.extend(read(sub, v));
                    }
                    RegCloseKey(sub);
                }
            }
            RegCloseKey(ik);
        }
        RegCloseKey(key);
    }
    out
}

/// `text` as a QR code: an SVG of dark squares on white with the standard
/// quiet zone, one path, crisp at any size.
pub fn qr_svg(text: &str) -> Result<String> {
    let code = qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::M)
        .map_err(|e| anyhow!("{e}"))?;
    let w = code.width();
    let colors = code.to_colors();
    const QUIET: usize = 4;
    let size = w + 2 * QUIET;
    let mut d = String::new();
    for y in 0..w {
        let mut x = 0;
        while x < w {
            if colors[y * w + x] == qrcode::Color::Dark {
                let start = x;
                while x < w && colors[y * w + x] == qrcode::Color::Dark {
                    x += 1;
                }
                d.push_str(&format!("M{} {}h{}v1h-{}z", start + QUIET, y + QUIET, x - start, x - start));
            } else {
                x += 1;
            }
        }
    }
    Ok(format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {size} {size}\">\
         <rect width=\"{size}\" height=\"{size}\" fill=\"#fff\"/><path fill=\"#0b1320\" d=\"{d}\"/></svg>"
    ))
}

/// Minutes east of UTC for the local time zone.
pub fn local_offset_min() -> i32 {
    Local::now().offset().local_minus_utc() / 60
}

/// Parse "2026-10-22 08:00", "2026-10-22 08:00:30", "2026-10-22T08:00" or
/// "2026-10-22" (midnight) in local time; returns epoch milliseconds.
pub fn parse_local_time(s: &str) -> Result<i64> {
    let s = s.trim().replace('T', " ");
    let formats = ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"];
    for f in formats {
        if let Ok(n) = NaiveDateTime::parse_from_str(&s, f) {
            return local_to_ms(n);
        }
    }
    if let Ok(d) = chrono::NaiveDate::parse_from_str(&s, "%Y-%m-%d") {
        return local_to_ms(d.and_hms_opt(0, 0, 0).unwrap());
    }
    bail!("'{s}' is not a date/time like 2026-10-22 08:00")
}

fn local_to_ms(n: NaiveDateTime) -> Result<i64> {
    Local
        .from_local_datetime(&n)
        .earliest()
        .map(|d| d.timestamp_millis())
        .ok_or_else(|| anyhow!("that local time does not exist"))
}

/// Parse durations like "90s", "15m", "1h", "1.5h", "2d", "1w".
pub fn parse_duration_ms(s: &str) -> Result<i64> {
    let s = s.trim().to_lowercase();
    let split = s.find(|c: char| c.is_ascii_alphabetic()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: f64 = num.trim().parse().map_err(|_| anyhow!("'{s}' is not a duration like 1h or 30m"))?;
    let mult = match unit.trim() {
        "s" | "sec" | "secs" => 1_000.0,
        "" | "m" | "min" | "mins" => 60_000.0,
        "h" | "hr" | "hour" | "hours" => 3_600_000.0,
        "d" | "day" | "days" => 86_400_000.0,
        "w" | "week" | "weeks" => 604_800_000.0,
        u => bail!("unknown unit '{u}' (use s, m, h, d or w)"),
    };
    let ms = (n * mult) as i64;
    if ms <= 0 {
        bail!("duration must be positive");
    }
    Ok(ms)
}

pub fn fmt_local(ms: i64, fmt: &str) -> String {
    Local.timestamp_millis_opt(ms).single().map(|d| d.format(fmt).to_string()).unwrap_or_default()
}

/// Read a line from the terminal without echoing it.
pub fn prompt_password(prompt: &str) -> Result<String> {
    use crossterm::event::{read, Event, KeyCode, KeyEventKind, KeyModifiers};
    use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
    print!("{prompt}");
    std::io::stdout().flush()?;
    enable_raw_mode()?;
    let mut s = String::new();
    let result = loop {
        match read() {
            Ok(Event::Key(k)) if k.kind != KeyEventKind::Release => match k.code {
                KeyCode::Enter => break Ok(()),
                KeyCode::Backspace => {
                    s.pop();
                }
                KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                    break Err(anyhow!("cancelled"));
                }
                KeyCode::Esc => break Err(anyhow!("cancelled")),
                KeyCode::Char(c) => s.push(c),
                _ => {}
            },
            Ok(_) => {}
            Err(e) => break Err(e.into()),
        }
    };
    disable_raw_mode()?;
    println!();
    result.map(|_| s)
}

/// A random password from an unambiguous alphabet.
pub fn generate_password() -> String {
    const ALPHA: &[u8] = b"abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).expect("system RNG unavailable");
    buf.iter().map(|b| ALPHA[*b as usize % ALPHA.len()] as char).collect()
}

/// Try to open a URL in the default browser (best effort).
pub fn open_browser(url: &str) -> bool {
    #[cfg(windows)]
    let r = std::process::Command::new("cmd").args(["/C", "start", "", url]).spawn();
    #[cfg(target_os = "macos")]
    let r = std::process::Command::new("open").arg(url).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let r = std::process::Command::new("xdg-open")
        .arg(url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    r.is_ok()
}


/// The IPv4 default gateway, if one can be found (cached after first call).
pub fn default_gateway() -> Option<std::net::Ipv4Addr> {
    static GW: std::sync::OnceLock<Option<std::net::Ipv4Addr>> = std::sync::OnceLock::new();
    *GW.get_or_init(find_gateway)
}

#[cfg(target_os = "linux")]
fn find_gateway() -> Option<std::net::Ipv4Addr> {
    let text = std::fs::read_to_string("/proc/net/route").ok()?;
    text.lines().skip(1).find_map(|l| {
        let cols: Vec<&str> = l.split_whitespace().collect();
        if cols.len() > 2 && cols[1] == "00000000" {
            let gw = u32::from_str_radix(cols[2], 16).ok()?;
            (gw != 0).then(|| std::net::Ipv4Addr::from(gw.to_le_bytes()))
        } else {
            None
        }
    })
}

#[cfg(windows)]
fn find_gateway() -> Option<std::net::Ipv4Addr> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = std::process::Command::new("route")
        .args(["print", "-4", "0.0.0.0"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines().find_map(|l| {
        let cols: Vec<&str> = l.split_whitespace().collect();
        if cols.len() >= 3 && cols[0] == "0.0.0.0" && cols[1] == "0.0.0.0" {
            cols[2].parse().ok()
        } else {
            None
        }
    })
}

#[cfg(not(any(target_os = "linux", windows)))]
fn find_gateway() -> Option<std::net::Ipv4Addr> {
    None
}

/// Make text from outside (target names, link labels, reverse-DNS names)
/// safe to show anywhere: drops control characters (terminal escape codes,
/// characters XML can't carry), invisible formatting and bidirectional
/// overrides, folds runs of whitespace, trims, and keeps at most `max` chars.
pub fn clean_text(s: &str, max: usize) -> String {
    let invisible = |c: char| {
        matches!(c,
            '\u{00AD}' | '\u{061C}' | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{2069}'
            | '\u{FEFF}' | '\u{FFF9}'..='\u{FFFB}')
    };
    let mut out = String::with_capacity(s.len().min(max * 4));
    let mut space = false;
    for c in s.chars() {
        if c.is_whitespace() {
            space = !out.is_empty();
            continue;
        }
        if c.is_control() || invisible(c) {
            continue;
        }
        if space {
            out.push(' ');
            space = false;
        }
        out.push(c);
    }
    out.chars().take(max).collect()
}

/// Free space on the disk holding `path`, in bytes.
pub fn free_space(path: &std::path::Path) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        // SAFETY: valid NUL-terminated path and a zeroed out-parameter.
        if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
            return None;
        }
        Some(st.f_bavail as u64 * st.f_frsize as u64)
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        let mut avail = 0u64;
        // SAFETY: valid NUL-terminated wide path; other out-params may be null.
        let ok = unsafe { GetDiskFreeSpaceExW(wide.as_ptr(), &mut avail, std::ptr::null_mut(), std::ptr::null_mut()) };
        if ok == 0 {
            return None;
        }
        Some(avail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_addresses() {
        assert!(is_this_machine("127.0.0.1".parse().unwrap()));
        assert!(is_this_machine("::1".parse().unwrap()));
        assert!(!is_this_machine("8.8.8.8".parse().unwrap()));
        assert!(!is_this_machine("192.0.2.77".parse().unwrap()));
    }

    #[test]
    fn host_names_fold_to_dns_labels() {
        assert_eq!(dns_label("CAFÉ-PC").as_deref(), Some("cafe-pc"));
        assert_eq!(dns_label(" Pi\n").as_deref(), Some("pi"));
        assert_eq!(dns_label("Ørthanc-2").as_deref(), Some("orthanc-2"));
        assert_eq!(dns_label("東京"), None);
        assert_eq!(dns_label("-bad"), None);
        assert_eq!(dns_label("a.b"), None);
        assert!(valid_dns_name("mypc.lan"));
        assert!(valid_dns_name("localhost"));
        assert!(!valid_dns_name("192.168.1.20"));
        assert!(!valid_dns_name("mypc.lan."));
        assert!(!valid_dns_name("bad_name.lan"));
        assert!(!valid_dns_name(""));
    }

    #[test]
    fn cleans_untrusted_text() {
        assert_eq!(clean_text("  Office\t uplink \n", 64), "Office uplink");
        assert_eq!(clean_text("evil\u{1b}]52;c;aGk=\u{7}name", 64), "evil]52;c;aGk=name");
        assert_eq!(clean_text("abc\u{202E}gnp.exe", 64), "abcgnp.exe");
        assert_eq!(clean_text("zero\u{200B}width", 64), "zerowidth");
        assert_eq!(clean_text("bell\u{0}\u{7f}", 64), "bell");
        assert_eq!(clean_text("Ünïcödé ok", 64), "Ünïcödé ok");
        assert_eq!(clean_text("abcdef", 3), "abc");
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration_ms("90s").unwrap(), 90_000);
        assert_eq!(parse_duration_ms("1.5h").unwrap(), 5_400_000);
        assert_eq!(parse_duration_ms("2d").unwrap(), 172_800_000);
        assert_eq!(parse_duration_ms("15").unwrap(), 900_000);
        assert!(parse_duration_ms("abc").is_err());
    }

    #[test]
    fn times() {
        let a = parse_local_time("2026-10-22 08:00").unwrap();
        let b = parse_local_time("2026-10-22T08:00:30").unwrap();
        assert_eq!(b - a, 30_000);
        assert!(parse_local_time("yesterday").is_err());
    }
}
