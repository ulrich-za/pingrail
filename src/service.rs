//! Installing and controlling the background service (systemd on Linux,
//! the Service Control Manager on Windows).

use anyhow::{bail, Context, Result};
use std::process::Command;

use crate::config::{load_or_create_token, Config, Paths};

pub const SERVICE_NAME: &str = "pingrail";

fn run(cmd: &str, args: &[&str]) -> Result<std::process::Output> {
    Command::new(cmd).args(args).output().with_context(|| format!("running {cmd}"))
}

fn run_ok(cmd: &str, args: &[&str]) -> Result<()> {
    let o = run(cmd, args)?;
    if !o.status.success() {
        bail!(
            "{cmd} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&o.stderr).trim()
        );
    }
    Ok(())
}

/// Create the service's config, data directory and API token.
pub fn init_files() -> Result<Paths> {
    let paths = Paths::system();
    paths.ensure()?;
    #[cfg(windows)]
    windows::grant_service_access(&paths);
    crate::migrate::run(&paths);
    let cfg = Config::load_or_create(&paths.config_file)?;
    load_or_create_token(&paths.token_file())?;
    // The certificate authority and HTTPS certificate, made now so the
    // service never has to and the keys' permissions are set while we're an
    // administrator.
    let names = crate::ca::saved_names_in(&paths.db_file());
    match crate::ca::Certs::load(&paths.data_dir, &cfg.tls, true, &names) {
        Ok((certs, _)) => {
            #[cfg(windows)]
            if !certs.info().custom {
                for k in ["key.pem", "ca-key.pem"] {
                    crate::tls::restrict_windows_key(&paths.data_dir.join(k));
                }
            }
            println!("certificate authority SHA-256 {}", crate::tls::fmt_fingerprint(&certs.pin()));
        }
        Err(e) => eprintln!("pingrail: certificate: {e:#}"),
    }
    #[cfg(unix)]
    unix::fix_ownership(&paths)?;
    Ok(paths)
}

pub fn web_hint(paths: &Paths) -> String {
    let cfg = Config::load_quiet(&paths.config_file);
    let host = crate::util::lan_ip().map(|i| i.to_string()).unwrap_or_else(|| "localhost".into());
    format!("Web UI: https://{host}:{}/", cfg.port())
}

#[cfg(unix)]
pub use unix::*;
#[cfg(windows)]
pub use windows::*;

#[cfg(unix)]
mod unix {
    use super::*;
    use std::path::Path;

    const UNIT_PACKAGED: &str = "/lib/systemd/system/pingrail.service";
    const UNIT_LOCAL: &str = "/etc/systemd/system/pingrail.service";

    pub fn is_root() -> bool {
        unsafe { libc::geteuid() == 0 }
    }

    fn require_root(what: &str) -> Result<()> {
        if !is_root() {
            bail!("{what} needs root. Run: sudo pingrail service {what}");
        }
        Ok(())
    }

    fn user_exists(name: &str) -> bool {
        run("id", &["-u", name]).map(|o| o.status.success()).unwrap_or(false)
    }

    pub(super) fn fix_ownership(paths: &Paths) -> Result<()> {
        if !is_root() {
            return Ok(());
        }
        if !user_exists(SERVICE_NAME) {
            let _ = run_ok(
                "useradd",
                &["--system", "--home-dir", "/var/lib/pingrail", "--no-create-home", "--shell", "/usr/sbin/nologin", SERVICE_NAME],
            );
        }
        if user_exists(SERVICE_NAME) {
            let dir = paths.data_dir.to_string_lossy().to_string();
            let _ = run_ok("chown", &["-R", "pingrail:pingrail", &dir]);
            let _ = run_ok("chmod", &["0750", &dir]);
        }
        let token = paths.token_file().to_string_lossy().to_string();
        let _ = run_ok("chmod", &["0640", &token]);
        // Let the user who ran sudo read the token so their TUI connects
        // without a password. Falls back to the pingrail group.
        if let Ok(user) = std::env::var("SUDO_USER")
            && !user.is_empty() && user != "root" {
                let dir = paths.data_dir.to_string_lossy().to_string();
                let acl_ok = run_ok("setfacl", &["-m", &format!("u:{user}:x"), &dir]).is_ok()
                    && run_ok("setfacl", &["-m", &format!("u:{user}:r"), &token]).is_ok();
                if !acl_ok {
                    let _ = run_ok("usermod", &["-aG", SERVICE_NAME, &user]);
                }
            }
        Ok(())
    }

    fn unit_text(exe: &Path) -> String {
        format!(
            "[Unit]
Description=pingrail latency and route monitor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=pingrail
Group=pingrail
ExecStart={} service run
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
NoNewPrivileges=true
StateDirectory=pingrail
ConfigurationDirectory=pingrail
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
",
            exe.display()
        )
    }

    /// Give the binary CAP_NET_RAW so local (non-service) TUI sessions can
    /// open raw ICMP sockets without sudo.
    pub fn grant_capability(exe: &Path) {
        let _ = run_ok("setcap", &["cap_net_raw+ep", &exe.to_string_lossy()]);
    }

    pub fn install() -> Result<()> {
        require_root("install")?;
        let exe = std::env::current_exe()?.canonicalize()?;
        let paths = init_files()?;
        if !Path::new(UNIT_PACKAGED).exists() {
            std::fs::write(UNIT_LOCAL, unit_text(&exe)).context("writing systemd unit")?;
        }
        grant_capability(&exe);
        run_ok("systemctl", &["daemon-reload"])?;
        run_ok("systemctl", &["enable", "--now", SERVICE_NAME])?;
        println!("pingrail service installed and started.");
        println!("{}", web_hint(&paths));
        println!("Set the web UI password with: sudo pingrail passwd   (or from the TUI)");
        Ok(())
    }

    pub fn uninstall(purge: bool) -> Result<()> {
        require_root("uninstall")?;
        let _ = run_ok("systemctl", &["disable", "--now", SERVICE_NAME]);
        if Path::new(UNIT_LOCAL).exists() {
            std::fs::remove_file(UNIT_LOCAL)?;
            let _ = run_ok("systemctl", &["daemon-reload"]);
        }
        if purge {
            let p = Paths::system();
            let _ = std::fs::remove_dir_all(&p.data_dir);
            let _ = std::fs::remove_file(&p.config_file);
            println!("Removed service and data.");
        } else {
            println!("Service removed. Data kept in {}", Paths::system().data_dir.display());
        }
        Ok(())
    }

    pub fn start() -> Result<()> {
        require_root("start")?;
        run_ok("systemctl", &["start", SERVICE_NAME])
    }

    pub fn stop() -> Result<()> {
        require_root("stop")?;
        run_ok("systemctl", &["stop", SERVICE_NAME])
    }

    pub fn status() -> Result<String> {
        let o = run("systemctl", &["is-active", SERVICE_NAME])?;
        let state = String::from_utf8_lossy(&o.stdout).trim().to_string();
        let enabled = run("systemctl", &["is-enabled", SERVICE_NAME])
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();
        Ok(format!("service: {state} (start at boot: {enabled})"))
    }

    pub fn start_hint() -> &'static str {
        "Install and start the background service with: sudo pingrail service install"
    }

    pub fn firewall(_add: bool) -> Result<()> {
        println!(
            "Not needed on Linux; if you use a firewall, open TCP port 8040 for the web UI and 8041 for share links \
             (e.g. ufw allow 8040,8041/tcp)."
        );
        Ok(())
    }

    pub fn path_entry(_add: bool) -> Result<()> {
        println!("Not needed on Linux: the package installs pingrail to /usr/bin.");
        Ok(())
    }

    /// Add (or remove) pingrail's certificate authority to the system's
    /// trusted certificates (Debian/Ubuntu layout).
    pub fn trust_ca(add: bool) -> Result<()> {
        require_root("trust")?;
        let store = Path::new("/usr/local/share/ca-certificates");
        if !store.is_dir() {
            bail!("{} not found; add {} to your system's trusted certificates by hand", store.display(), ca_file().display());
        }
        for e in std::fs::read_dir(store)?.flatten() {
            if e.file_name().to_string_lossy().starts_with("pingrail-") {
                std::fs::remove_file(e.path())?;
            }
        }
        if add {
            let host = crate::util::hostname().unwrap_or_else(|| "local".into());
            std::fs::copy(ca_file(), store.join(format!("pingrail-{host}.crt"))).context("no certificate authority yet: run `sudo pingrail service init`")?;
        }
        run_ok("update-ca-certificates", &["--fresh"])?;
        Ok(())
    }
}

/// The service's certificate authority.
pub fn ca_file() -> std::path::PathBuf {
    Paths::system().data_dir.join("ca.pem")
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::ffi::OsString;
    use std::time::Duration;
    use windows_service::service::{
        ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState, ServiceType,
    };
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    const FIREWALL_RULE: &str = "pingrail web UI";

    /// The service runs as the built-in low-privilege LocalService account
    /// (not LocalSystem), so a bug can't take over the machine.
    pub const SERVICE_ACCOUNT: &str = r"NT AUTHORITY\LocalService";
    /// LocalService's well-known SID (language-independent).
    const LOCAL_SERVICE_SID: &str = "*S-1-5-19";

    /// Let LocalService write the data folder (database, token, log); the
    /// config file and everything else inherit from it.
    pub fn grant_service_access(paths: &Paths) {
        let dir = paths.data_dir.to_string_lossy().to_string();
        if let Err(e) = run_ok("icacls", &[&dir, "/grant", &format!("{LOCAL_SERVICE_SID}:(OI)(CI)M"), "/T", "/C", "/Q"]) {
            tracing::warn!("could not give the service access to {dir}: {e:#}");
        }
    }

    fn manager(access: ServiceManagerAccess) -> Result<ServiceManager> {
        ServiceManager::local_computer(None::<&str>, access).map_err(|e| {
            anyhow::anyhow!("cannot open the Service Control Manager ({e}). Run this from an elevated (Administrator) prompt.")
        })
    }

    pub fn install() -> Result<()> {
        let exe = std::env::current_exe()?;
        let paths = init_files()?;
        let mgr = manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
        let info = ServiceInfo {
            name: OsString::from(SERVICE_NAME),
            display_name: OsString::from("pingrail latency monitor"),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: exe.clone(),
            launch_arguments: vec![OsString::from("service"), OsString::from("run")],
            dependencies: vec![],
            account_name: Some(OsString::from(SERVICE_ACCOUNT)),
            account_password: None,
        };
        let svc = match mgr.create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS) {
            Ok(s) => s,
            Err(_) => {
                // Already installed: update its path in case it moved.
                let s = mgr.open_service(
                    SERVICE_NAME,
                    ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS,
                )?;
                s.change_config(&info)?;
                s
            }
        };
        let _ = svc.set_description("Pings and traces routes to monitored hosts; serves the pingrail web UI.");
        let _ = firewall(true);
        if svc.query_status()?.current_state != ServiceState::Running {
            svc.start::<&str>(&[]).context("starting service")?;
        }
        println!("pingrail service installed and started.");
        println!("{}", web_hint(&paths));
        Ok(())
    }

    /// Allow (or stop allowing) inbound connections to the web UI port on
    /// private and domain networks.
    pub fn firewall(add: bool) -> Result<()> {
        let _ = run("netsh", &["advfirewall", "firewall", "delete", "rule", &format!("name={FIREWALL_RULE}")]);
        if add {
            let paths = Paths::system();
            let cfg = Config::load_quiet(&paths.config_file);
            // The web UI port plus the share-link port, when that's enabled.
            let mut ports = vec![cfg.port()];
            if let Some(p) = cfg.share.port()
                && !ports.contains(&p)
            {
                ports.push(p);
            }
            let port = ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
            run_ok(
                "netsh",
                &[
                    "advfirewall", "firewall", "add", "rule",
                    &format!("name={FIREWALL_RULE}"),
                    "dir=in", "action=allow", "protocol=TCP",
                    &format!("localport={port}"),
                    "profile=private,domain",
                ],
            )?;
        }
        Ok(())
    }

    /// Add (or remove) pingrail's certificate authority to this computer's
    /// trusted root certificates, so browsers here trust the web UI. Removes
    /// any earlier pingrail authority for this machine first.
    pub fn trust_ca(add: bool) -> Result<()> {
        let cn = format!("pingrail CA for {}", crate::util::hostname().as_deref().unwrap_or("this machine"));
        for _ in 0..8 {
            if !run("certutil", &["-delstore", "Root", &cn]).map(|o| o.status.success()).unwrap_or(false) {
                break;
            }
        }
        if add {
            let ca = ca_file();
            if !ca.exists() {
                bail!("no certificate authority yet: run `pingrail service init` as Administrator");
            }
            run_ok("certutil", &["-addstore", "-f", "Root", &ca.to_string_lossy()])?;
        }
        Ok(())
    }

    /// Add (or remove) the folder holding pingrail.exe to the machine-wide
    /// PATH, leaving every other entry untouched.
    pub fn path_entry(add: bool) -> Result<()> {
        use windows_sys::Win32::Foundation::ERROR_SUCCESS;
        use windows_sys::Win32::System::Registry::*;
        use windows_sys::Win32::UI::WindowsAndMessaging::{SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE};

        let wide = |s: &str| s.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
        let exe = std::env::current_exe()?;
        let dir = exe.parent().context("no install folder")?.to_string_lossy().trim_end_matches('\\').to_string();
        let subkey = wide(r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment");
        let name = wide("Path");
        unsafe {
            let mut key: HKEY = std::ptr::null_mut();
            if RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.as_ptr(), 0, KEY_READ | KEY_WRITE, &mut key) != ERROR_SUCCESS {
                bail!("cannot open the system environment (run as Administrator)");
            }
            let mut ty: REG_VALUE_TYPE = 0;
            let mut len: u32 = 0;
            RegQueryValueExW(key, name.as_ptr(), std::ptr::null(), &mut ty, std::ptr::null_mut(), &mut len);
            let mut buf = vec![0u16; (len as usize / 2) + 1];
            let mut len2 = (buf.len() * 2) as u32;
            let current = if RegQueryValueExW(key, name.as_ptr(), std::ptr::null(), &mut ty, buf.as_mut_ptr() as *mut u8, &mut len2) == ERROR_SUCCESS {
                let n = (len2 as usize / 2).min(buf.len());
                String::from_utf16_lossy(&buf[..n]).trim_end_matches('\0').to_string()
            } else {
                String::new()
            };
            let mut parts: Vec<String> = current
                .split(';')
                .filter(|p| !p.is_empty())
                .filter(|p| !p.trim_end_matches('\\').eq_ignore_ascii_case(&dir))
                .map(String::from)
                .collect();
            if add {
                parts.push(dir.clone());
            }
            let value = wide(&parts.join(";"));
            let kind = if ty == REG_SZ { REG_SZ } else { REG_EXPAND_SZ };
            let rc = RegSetValueExW(key, name.as_ptr(), 0, kind, value.as_ptr() as *const u8, (value.len() * 2) as u32);
            RegCloseKey(key);
            if rc != ERROR_SUCCESS {
                bail!("updating PATH failed (error {rc})");
            }
            let env = wide("Environment");
            let mut result = 0usize;
            SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, env.as_ptr() as isize, SMTO_ABORTIFHUNG, 3000, &mut result);
        }
        Ok(())
    }

    pub fn uninstall(purge: bool) -> Result<()> {
        let mgr = manager(ServiceManagerAccess::CONNECT)?;
        if let Ok(svc) = mgr.open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        ) {
            if svc.query_status()?.current_state != ServiceState::Stopped {
                let _ = svc.stop();
                for _ in 0..20 {
                    std::thread::sleep(Duration::from_millis(250));
                    if svc.query_status()?.current_state == ServiceState::Stopped {
                        break;
                    }
                }
            }
            svc.delete()?;
        }
        let _ = firewall(false);
        if purge {
            let _ = std::fs::remove_dir_all(Paths::system().data_dir);
        }
        println!("pingrail service removed.");
        Ok(())
    }

    pub fn start() -> Result<()> {
        let mgr = manager(ServiceManagerAccess::CONNECT)?;
        let svc = mgr.open_service(SERVICE_NAME, ServiceAccess::START)?;
        svc.start::<&str>(&[])?;
        Ok(())
    }

    pub fn stop() -> Result<()> {
        let mgr = manager(ServiceManagerAccess::CONNECT)?;
        let svc = mgr.open_service(SERVICE_NAME, ServiceAccess::STOP)?;
        svc.stop()?;
        Ok(())
    }

    pub fn status() -> Result<String> {
        let mgr = manager(ServiceManagerAccess::CONNECT)?;
        match mgr.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
            Ok(svc) => Ok(format!("service: {:?}", svc.query_status()?.current_state)),
            Err(_) => Ok("service: not installed".into()),
        }
    }

    pub fn start_hint() -> &'static str {
        "Start the background service from an Administrator prompt with: pingrail service install"
    }

    // ----- running under the SCM ------------------------------------------

    use std::sync::OnceLock;
    use windows_service::service::{ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceStatus};
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::{define_windows_service, service_dispatcher};

    static PATHS: OnceLock<(Paths, Option<String>)> = OnceLock::new();

    define_windows_service!(ffi_service_main, service_main);

    /// Hand control to the SCM. Returns Ok(false) if we were not started by
    /// the SCM (i.e. run from a console), so the caller can run in the
    /// foreground instead.
    pub fn run_dispatcher(paths: Paths, listen: Option<String>) -> Result<bool> {
        let _ = PATHS.set((paths, listen));
        match service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
            Ok(()) => Ok(true),
            Err(windows_service::Error::Winapi(e)) if e.raw_os_error() == Some(1063) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    fn service_main(_args: Vec<OsString>) {
        if let Err(e) = run_service() {
            tracing::error!("service failed: {e:#}");
        }
    }

    fn run_service() -> Result<()> {
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let tx = std::sync::Mutex::new(Some(tx));
        let handle = service_control_handler::register(SERVICE_NAME, move |ev| match ev {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                if let Some(t) = tx.lock().unwrap().take() {
                    let _ = t.send(());
                }
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        })?;
        let status = |state, accept, code| ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(code),
            checkpoint: 0,
            wait_hint: Duration::from_secs(10),
            process_id: None,
        };
        handle.set_service_status(status(ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN, 0))?;
        let (paths, listen) = PATHS.get().cloned().unwrap_or((Paths::system(), None));
        let rt = tokio::runtime::Runtime::new()?;
        let result = rt.block_on(crate::daemon::run(paths, listen, async move {
            let _ = rx.await;
        }));
        let code = if result.is_ok() { 0 } else { 1 };
        handle.set_service_status(status(ServiceState::Stopped, ServiceControlAccept::empty(), code))?;
        result
    }
}
