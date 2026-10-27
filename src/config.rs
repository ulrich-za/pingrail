//! Configuration file and on-disk locations.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::model::Thresholds;

pub const DEFAULT_PORT: u16 = 8040;

pub const DEFAULT_SHARE_PORT: u16 = 8041;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    pub web: WebConfig,
    pub tls: TlsConfig,
    pub share: ShareConfig,
    pub probe: ProbeConfig,
    pub storage: StorageConfig,
    pub thresholds: Thresholds,
}

/// HTTPS for both listeners. pingrail only speaks HTTPS.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct TlsConfig {
    /// PEM certificate (with any intermediates) used on both ports. Empty =
    /// one from pingrail's own certificate authority (see `ca`).
    pub cert_file: String,
    /// PEM private key for `cert_file`.
    pub key_file: String,
}

/// Share links: a second listener that serves only share pages (no admin UI,
/// no sign-in), for a Cloudflare Tunnel or reverse proxy to point at.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ShareConfig {
    /// Address for share links only. Empty = don't open a separate port (share
    /// links still work on the main web UI port).
    pub listen: String,
    /// Address people use to open share links, e.g. "https://pingrail.example.com".
    /// Empty = https://<this machine>:<share port>.
    pub public_url: String,
    /// Proxies whose X-Forwarded-For / CF-Connecting-IP headers are believed
    /// (IPs or CIDRs). Requests from anywhere else are logged under their own
    /// address. Default: this machine only (e.g. cloudflared running here).
    pub trusted_proxies: Vec<String>,
}

impl Default for ShareConfig {
    fn default() -> Self {
        Self {
            listen: format!("0.0.0.0:{DEFAULT_SHARE_PORT}"),
            public_url: String::new(),
            trusted_proxies: vec!["127.0.0.1".into(), "::1".into()],
        }
    }
}

impl ShareConfig {
    pub fn port(&self) -> Option<u16> {
        if self.listen.trim().is_empty() {
            return None;
        }
        self.listen.rsplit(':').next().and_then(|p| p.parse().ok())
    }
}


#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WebConfig {
    /// Address the web UI / API listens on. Use 127.0.0.1:8040 to keep it local.
    pub listen: String,
    /// Web sessions expire after this many hours.
    pub session_hours: u32,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self { listen: format!("0.0.0.0:{DEFAULT_PORT}"), session_hours: 24 * 7 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProbeConfig {
    /// Default sample interval for new targets (ms).
    pub interval_ms: u32,
    /// How long to wait for each reply (ms).
    pub timeout_ms: u32,
    /// ICMP payload size in bytes.
    pub packet_size: usize,
    /// Highest TTL probed when tracing a route.
    pub max_hops: u8,
    /// Delay between hop probes within one sample, to avoid bursts (ms).
    pub hop_stagger_ms: u32,
    /// Look up hostnames for hop addresses.
    pub reverse_dns: bool,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            interval_ms: 2500,
            timeout_ms: 2000,
            packet_size: 56,
            max_hops: 30,
            hop_stagger_ms: 5,
            reverse_dns: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    /// Samples older than this are deleted.
    pub retention_days: u32,
    /// When free disk space drops below this, destinations added by share-link
    /// visitors are paused (your own targets keep running). 0 = never.
    pub min_free_mb: u64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self { retention_days: 30, min_free_mb: 1024 }
    }
}

impl Config {
    pub fn load_or_create(path: &Path) -> Result<Config> {
        if path.exists() {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?;
            let cfg: Config =
                toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
            Ok(cfg)
        } else {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir).ok();
            }
            // The commented template: same values as the defaults, plus
            // explanations of each setting.
            std::fs::write(path, CONFIG_TEMPLATE).ok();
            Ok(Config::default())
        }
    }

    /// Load without creating; falls back to defaults.
    pub fn load_quiet(path: &Path) -> Config {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|t| toml::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn port(&self) -> u16 {
        self.web
            .listen
            .rsplit(':')
            .next()
            .and_then(|p| p.parse().ok())
            .unwrap_or(DEFAULT_PORT)
    }
}

/// Where a pingrail instance keeps its files.
#[derive(Debug, Clone)]
pub struct Paths {
    pub config_file: PathBuf,
    pub data_dir: PathBuf,
}

impl Paths {
    /// Everything (config, database, token) in one directory.
    pub fn in_dir(dir: &Path) -> Paths {
        Paths { config_file: dir.join("pingrail.toml"), data_dir: dir.to_path_buf() }
    }

    /// Locations used by the background service.
    pub fn system() -> Paths {
        #[cfg(windows)]
        {
            let base = std::env::var_os("ProgramData")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
            Paths::in_dir(&base.join("pingrail"))
        }
        #[cfg(not(windows))]
        {
            Paths {
                config_file: PathBuf::from("/etc/pingrail/pingrail.toml"),
                data_dir: PathBuf::from("/var/lib/pingrail"),
            }
        }
    }

    /// Locations used by a local (non-service) TUI session.
    pub fn user() -> Paths {
        match directories::ProjectDirs::from("", "", "pingrail") {
            Some(d) => Paths {
                config_file: d.config_dir().join("pingrail.toml"),
                data_dir: d.data_dir().to_path_buf(),
            },
            None => Paths::in_dir(Path::new(".pingrail")),
        }
    }

    /// Where hopwatch (pingrail's earlier name) kept the service's files.
    pub fn legacy_system() -> Paths {
        #[cfg(windows)]
        {
            let base = std::env::var_os("ProgramData")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
            let dir = base.join("hopwatch");
            Paths { config_file: dir.join("hopwatch.toml"), data_dir: dir }
        }
        #[cfg(not(windows))]
        {
            Paths {
                config_file: PathBuf::from("/etc/hopwatch/hopwatch.toml"),
                data_dir: PathBuf::from("/var/lib/hopwatch"),
            }
        }
    }

    /// Where hopwatch kept a local (non-service) session's files.
    pub fn legacy_user() -> Option<Paths> {
        directories::ProjectDirs::from("", "", "hopwatch").map(|d| Paths {
            config_file: d.config_dir().join("hopwatch.toml"),
            data_dir: d.data_dir().to_path_buf(),
        })
    }

    pub fn db_file(&self) -> PathBuf {
        self.data_dir.join("pingrail.db")
    }

    pub fn token_file(&self) -> PathBuf {
        self.data_dir.join("api.token")
    }

    pub fn log_file(&self) -> PathBuf {
        self.data_dir.join("pingrail.log")
    }

    pub fn ensure(&self) -> Result<()> {
        std::fs::create_dir_all(&self.data_dir)
            .with_context(|| format!("creating {}", self.data_dir.display()))?;
        if let Some(dir) = self.config_file.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        Ok(())
    }
}

/// Generate a random hex string with `bytes` bytes of entropy.
pub fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).expect("system RNG unavailable");
    hex::encode(buf)
}

/// Read the API token, creating it if missing. On Unix the file is 0640.
/// The configuration file written on first start (also shipped as
/// pingrail.toml.example).
pub const CONFIG_TEMPLATE: &str = include_str!("../packaging/linux/pingrail.toml");

pub fn load_or_create_token(path: &Path) -> Result<String> {
    if let Ok(t) = std::fs::read_to_string(path) {
        let t = t.trim().to_string();
        if t.len() >= 32 {
            return Ok(t);
        }
    }
    let token = random_hex(32);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).ok();
    }
    std::fs::write(path, format!("{token}\n"))
        .with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640)).ok();
    }
    Ok(token)
}

pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_matches_defaults() {
        let parsed: Config = toml::from_str(CONFIG_TEMPLATE).expect("template parses");
        assert_eq!(
            toml::to_string(&parsed).unwrap(),
            toml::to_string(&Config::default()).unwrap(),
            "packaging/linux/pingrail.toml must hold the default values"
        );
    }
}
