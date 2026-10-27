//! Types shared by the engine, the HTTP API, the TUI and the report renderer.

use serde::{Deserialize, Serialize};

/// A monitored host.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Target {
    pub id: i64,
    /// Hostname or IP address as typed by the user.
    pub host: String,
    /// Display label (defaults to the host).
    pub name: String,
    /// Time between samples in milliseconds.
    pub interval_ms: u32,
    /// Trace the route (per-hop probing) as well as pinging the endpoint.
    pub trace: bool,
    /// false = paused.
    pub enabled: bool,
    /// Owning TUI session. `None` means the target runs in the background and
    /// keeps running when every TUI has closed.
    pub session: Option<String>,
    pub created_ms: i64,
    /// Share link whose visitor added this target (None = added by you).
    #[serde(default)]
    pub share_id: Option<i64>,
    /// Set on visitor-added targets: the host may only resolve to public
    /// addresses, plus these private IPs/CIDRs.
    #[serde(default)]
    pub restrict: Option<Vec<String>>,
}

impl Target {
    pub fn is_background(&self) -> bool {
        self.session.is_none()
    }
}

/// Body for creating a target.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NewTarget {
    pub host: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub interval_ms: Option<u32>,
    #[serde(default)]
    pub trace: Option<bool>,
    /// Owning TUI session; omit for a background target.
    #[serde(default)]
    pub session: Option<String>,
}

/// Body for updating a target. Absent fields are left unchanged.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TargetPatch {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub trace: Option<bool>,
    #[serde(default)]
    pub interval_ms: Option<u32>,
    /// `Some(None)` / JSON `null` turns the target into a background target;
    /// `Some(Some(id))` hands it to a TUI session.
    #[serde(default, with = "double_option")]
    pub session: Option<Option<String>>,
}

mod double_option {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<Option<String>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            None => s.serialize_none(),
            Some(inner) => inner.serialize(s),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Option<String>>, D::Error> {
        Ok(Some(Option::<String>::deserialize(d)?))
    }
}

/// Summary statistics over a window of samples.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Stats {
    pub sent: u32,
    pub received: u32,
    pub loss_pct: f64,
    /// Latency of the most recent sample (None if it was lost).
    pub cur_ms: Option<f64>,
    pub min_ms: Option<f64>,
    pub avg_ms: Option<f64>,
    pub max_ms: Option<f64>,
    pub stddev_ms: Option<f64>,
    /// Mean absolute difference between consecutive replies.
    pub jitter_ms: Option<f64>,
    pub p95_ms: Option<f64>,
    /// Estimated Mean Opinion Score (1.0–4.5) for a voice call over this path.
    pub mos: Option<f64>,
}

/// Live engine state for a target.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct LiveStatus {
    pub ip: Option<String>,
    pub error: Option<String>,
    /// Number of hops to the destination, once discovered.
    pub hop_count: Option<u8>,
    pub last_sample_ms: Option<i64>,
}

/// One row of the overview table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetOverview {
    pub target: Target,
    pub live: LiveStatus,
    pub stats: Stats,
    /// Average latency per bucket, oldest first (None = no replies).
    pub spark: Vec<Option<f64>>,
    /// Lost fraction per bucket (0.0–1.0, None = no samples).
    pub spark_loss: Vec<Option<f64>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Overview {
    pub now_ms: i64,
    pub window_ms: i64,
    pub targets: Vec<TargetOverview>,
    pub thresholds: Thresholds,
}

/// Statistics for one hop of the route.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HopStat {
    pub ttl: u8,
    /// Most common responder for this TTL.
    pub addr: Option<String>,
    /// Reverse DNS name of `addr`, when known.
    pub hostname: Option<String>,
    /// Number of distinct responders seen at this TTL (ECMP / route flaps).
    pub responders: u32,
    /// This hop is the destination.
    pub is_dest: bool,
    /// Set when the address is hidden from a share-link visitor
    /// ("private network" or "hidden").
    #[serde(default)]
    pub masked: Option<String>,
    pub stats: Stats,
    /// Loss that carries on from this hop to the furthest hop that answers
    /// (the lowest loss at this hop or any later one). None when this hop
    /// never answered.
    #[serde(default)]
    pub carried_pct: Option<f64>,
    /// What this hop's loss means once later hops are taken into account.
    #[serde(default)]
    pub reading: Option<HopReading>,
}

/// What a hop's packet loss means once the hops after it are taken into
/// account. A router that drops or rate-limits replies to itself shows loss
/// that the hops after it don't; real loss carries on to the destination.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HopReading {
    /// Loss that reaches the destination starts at this hop.
    LossStarts,
    /// Loss that started at an earlier hop passes through this one.
    LossCarried,
    /// This hop loses replies that later hops don't: it limits replies to
    /// itself, which is not loss on the path.
    LimitsReplies,
    /// This hop never answered, but later hops did.
    NoReply,
}

/// One time bucket of a latency timeline.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Bucket {
    pub t_ms: i64,
    pub sent: u32,
    pub lost: u32,
    pub min_ms: Option<f64>,
    pub avg_ms: Option<f64>,
    pub max_ms: Option<f64>,
}

/// How a timeline's points relate to the samples behind them.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum TimelineMode {
    /// One point per sample (there is room to draw every sample).
    #[default]
    Samples,
    /// One point per fixed-length slice of time, aligned to the clock.
    Slices,
}

/// One point of a latency timeline: a single sample, or a slice of samples.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Point {
    /// Sample time, or the start of the slice.
    pub t_ms: i64,
    pub sent: u32,
    pub lost: u32,
    pub min_ms: Option<f64>,
    pub avg_ms: Option<f64>,
    pub max_ms: Option<f64>,
    /// A real gap (no samples for longer than the interval allows) comes
    /// right before this point: don't join it to the previous one.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub gap: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Timeline {
    pub from_ms: i64,
    pub to_ms: i64,
    pub mode: TimelineMode,
    /// Slice length (slices mode) or the typical sample interval (samples mode).
    pub step_ms: i64,
    /// Typical (median) sample interval in the window.
    pub interval_ms: i64,
    /// Shortest and longest sample interval in the window (they differ when
    /// the interval was changed part-way).
    #[serde(default)]
    pub interval_min_ms: i64,
    #[serde(default)]
    pub interval_max_ms: i64,
    pub points: Vec<Point>,
    /// Stretches with no samples, as [start, end) pairs.
    pub gaps: Vec<[i64; 2]>,
}

/// Everything needed to draw one target's detail view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detail {
    pub target: Target,
    pub live: LiveStatus,
    /// Stats for the destination, or for `hop` when set.
    pub stats: Stats,
    pub hops: Vec<HopStat>,
    /// The hop (TTL) that `stats` and `timeline` describe; None = destination.
    #[serde(default)]
    pub hop: Option<u8>,
    pub timeline: Timeline,
}

/// Latency/loss thresholds used for colouring.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct Thresholds {
    pub warn_ms: f64,
    pub crit_ms: f64,
    pub loss_warn_pct: f64,
    pub loss_crit_pct: f64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self { warn_ms: 100.0, crit_ms: 200.0, loss_warn_pct: 1.0, loss_crit_pct: 10.0 }
    }
}

/// Severity used for colouring values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    None,
    Good,
    Warn,
    Crit,
}

impl Thresholds {
    pub fn latency(&self, ms: Option<f64>) -> Level {
        match ms {
            None => Level::None,
            Some(v) if v >= self.crit_ms => Level::Crit,
            Some(v) if v >= self.warn_ms => Level::Warn,
            Some(_) => Level::Good,
        }
    }

    pub fn loss(&self, pct: f64, sent: u32) -> Level {
        if sent == 0 {
            Level::None
        } else if pct >= self.loss_crit_pct {
            Level::Crit
        } else if pct >= self.loss_warn_pct {
            Level::Warn
        } else {
            Level::Good
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Health {
    pub name: String,
    pub version: String,
    pub has_password: bool,
    pub listen: String,
    /// SHA-256 fingerprint of what clients pin: the service's certificate
    /// authority, or a configured certificate ("AB:CD:…").
    #[serde(default)]
    pub cert_sha256: String,
    /// Passkeys can be used at the address this was asked on.
    #[serde(default)]
    pub passkeys: bool,
    /// Signing in needs a passkey (passwords are refused).
    #[serde(default)]
    pub passkey_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Me {
    pub user: String,
    pub via: String,
    pub has_password: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordRequest {
    #[serde(default)]
    pub username: Option<String>,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: String,
}

/// What to do with a TUI session's foreground targets when it ends.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SessionEnd {
    /// Hand them to the background service.
    Background,
    /// Pause them.
    Stop,
}

/// How much history a share-link visitor may see.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum HistoryMode {
    /// Everything that is stored.
    #[default]
    All,
    /// The last `history_days` days.
    Days,
    /// Only since the link was created.
    Since,
}

/// The settings of a share link (what you choose when creating it).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ShareSettings {
    pub label: String,
    /// Your targets included in the link.
    pub target_ids: Vec<i64>,
    /// Visitors may add their own destinations.
    pub can_add: bool,
    pub max_targets: u32,
    /// Visitors may download PDF/PNG reports.
    pub can_export: bool,
    pub history: HistoryMode,
    pub history_days: u32,
    /// Show private (RFC 1918, link-local, ULA) hop addresses as "private network".
    pub hide_private: bool,
    /// Hide the first N public hops (they reveal your ISP and area).
    pub hide_public_hops: u8,
    /// Hide reverse-DNS names of hops.
    pub hide_hostnames: bool,
    /// Private addresses or CIDRs visitors may add as destinations.
    pub allow_private: Vec<String>,
    /// Visitors' destinations sample no faster than this (ms).
    pub min_interval_ms: u32,
    /// Keep samples of visitors' destinations this many days (0 = as long
    /// as everything else, storage.retention_days).
    pub visitor_retention_days: u32,
    /// Most disk space visitors' destinations may use, in MB (0 = no limit).
    /// When reached they pause until data ages out or the limit is raised.
    pub visitor_storage_mb: u32,
    /// None = never expires.
    pub expires_ms: Option<i64>,
}

impl Default for ShareSettings {
    fn default() -> Self {
        ShareSettings {
            label: String::new(),
            target_ids: Vec::new(),
            can_add: false,
            max_targets: 5,
            can_export: false,
            history: HistoryMode::All,
            history_days: 7,
            hide_private: true,
            hide_public_hops: 0,
            hide_hostnames: false,
            allow_private: Vec::new(),
            min_interval_ms: 2500,
            visitor_retention_days: 0,
            visitor_storage_mb: 1024,
            expires_ms: None,
        }
    }
}

/// A share link as stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Share {
    pub id: i64,
    pub token: String,
    #[serde(flatten)]
    pub settings: ShareSettings,
    pub created_ms: i64,
    pub revoked: bool,
    pub last_seen_ms: Option<i64>,
    pub last_seen_ip: Option<String>,
    pub views: i64,
    /// Targets visitors added through this link.
    pub owned_ids: Vec<i64>,
}

impl Share {
    pub fn is_active(&self, now: i64) -> bool {
        !self.revoked && self.settings.expires_ms.is_none_or(|e| e > now)
    }

    pub fn status(&self, now: i64) -> &'static str {
        if self.revoked {
            "revoked"
        } else if !self.is_active(now) {
            "expired"
        } else {
            "active"
        }
    }

    /// Earliest sample a visitor may see.
    pub fn earliest_ms(&self, now: i64) -> Option<i64> {
        match self.settings.history {
            HistoryMode::All => None,
            HistoryMode::Days => Some(now - self.settings.history_days.max(1) as i64 * 86_400_000),
            HistoryMode::Since => Some(self.created_ms),
        }
    }

    /// Your targets plus the visitor's own.
    pub fn visible_ids(&self) -> Vec<i64> {
        let mut v = self.settings.target_ids.clone();
        v.extend(self.owned_ids.iter().copied());
        v.sort_unstable();
        v.dedup();
        v
    }
}

/// A share link as the admin UI sees it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareInfo {
    #[serde(flatten)]
    pub share: Share,
    pub status: String,
    pub url: String,
}

/// GET /api/shares
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharesResponse {
    pub shares: Vec<ShareInfo>,
    /// share.public_url from the config (empty = not set).
    pub public_url: String,
    /// The share-only port, if enabled.
    pub share_port: Option<u16>,
}

/// What a share-link visitor is told about the link.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareVisit {
    pub can_add: bool,
    pub max_targets: u32,
    /// Targets added through this link (the visitor may change these).
    pub owned_ids: Vec<i64>,
    pub can_export: bool,
    pub expires_ms: Option<i64>,
    pub earliest_ms: Option<i64>,
    pub hide_private: bool,
    pub hide_public_hops: u8,
    pub hide_hostnames: bool,
    pub min_interval_ms: u32,
    pub thresholds: Thresholds,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReportFormat {
    Pdf,
    Png,
}

impl ReportFormat {
    pub fn extension(self) -> &'static str {
        match self {
            ReportFormat::Pdf => "pdf",
            ReportFormat::Png => "png",
        }
    }

    pub fn mime(self) -> &'static str {
        match self {
            ReportFormat::Pdf => "application/pdf",
            ReportFormat::Png => "image/png",
        }
    }
}
