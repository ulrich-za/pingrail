//! SQLite storage for targets, samples, share links and settings. Accounts,
//! passkeys and sessions are doorward's, in its own `auth_` tables in the
//! same file (see `auth`).

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::config::now_ms;
use crate::model::{NewTarget, Share, ShareSettings, Target, TargetEvent, TargetPatch};

/// How a hop probe was answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HopKind {
    Timeout = 0,
    TimeExceeded = 1,
    Echo = 2,
    Unreachable = 3,
}

/// Result of probing one TTL in one sample.
#[derive(Debug, Clone, PartialEq)]
pub struct HopRecord {
    pub ttl: u8,
    pub addr: Option<IpAddr>,
    pub rtt_us: Option<u32>,
    pub kind: HopKind,
}

/// One sample of one target.
#[derive(Debug, Clone)]
pub struct RoundRecord {
    pub target_id: i64,
    pub ts_ms: i64,
    /// The target's sample interval when this sample was taken.
    pub interval_ms: u32,
    /// Endpoint round-trip time; None = lost.
    pub rtt_us: Option<u32>,
    /// Per-hop results when route tracing is on.
    pub hops: Option<Vec<HopRecord>>,
}

pub fn encode_hops(hops: &[HopRecord]) -> Vec<u8> {
    let mut out = Vec::with_capacity(hops.len() * 10);
    for h in hops {
        let mut flags = (h.kind as u8) << 4;
        if h.addr.is_some() {
            flags |= 1;
        }
        if matches!(h.addr, Some(IpAddr::V6(_))) {
            flags |= 2;
        }
        if h.rtt_us.is_some() {
            flags |= 4;
        }
        out.push(h.ttl);
        out.push(flags);
        if let Some(r) = h.rtt_us {
            out.extend_from_slice(&r.to_le_bytes());
        }
        match h.addr {
            Some(IpAddr::V4(a)) => out.extend_from_slice(&a.octets()),
            Some(IpAddr::V6(a)) => out.extend_from_slice(&a.octets()),
            None => {}
        }
    }
    out
}

pub fn decode_hops(mut b: &[u8]) -> Vec<HopRecord> {
    let mut out = Vec::new();
    while b.len() >= 2 {
        let ttl = b[0];
        let flags = b[1];
        b = &b[2..];
        let rtt_us = if flags & 4 != 0 {
            if b.len() < 4 {
                break;
            }
            let v = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
            b = &b[4..];
            Some(v)
        } else {
            None
        };
        let addr = if flags & 1 != 0 {
            if flags & 2 != 0 {
                if b.len() < 16 {
                    break;
                }
                let mut o = [0u8; 16];
                o.copy_from_slice(&b[..16]);
                b = &b[16..];
                Some(IpAddr::V6(Ipv6Addr::from(o)))
            } else {
                if b.len() < 4 {
                    break;
                }
                let a = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
                b = &b[4..];
                Some(IpAddr::V4(a))
            }
        } else {
            None
        };
        let kind = match flags >> 4 {
            1 => HopKind::TimeExceeded,
            2 => HopKind::Echo,
            3 => HopKind::Unreachable,
            _ => HopKind::Timeout,
        };
        out.push(HopRecord { ttl, addr, rtt_us, kind });
    }
    out
}

pub struct Store {
    write: Mutex<Connection>,
    read: Mutex<Connection>,
    /// Reads made for share-link visitors use their own connection, so busy
    /// visitors can never make your own web UI or terminal UI wait.
    share_read: Mutex<Connection>,
}

thread_local! {
    /// Set while a blocking task runs on behalf of a share-link visitor.
    static SHARE_READER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// One endpoint (or hop) sample: time, round-trip time (None = lost) and the
/// interval in force (None for samples recorded before that was stored).
pub type Sample = (i64, Option<f64>, Option<u32>);

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL,
    name TEXT NOT NULL,
    interval_ms INTEGER NOT NULL,
    trace INTEGER NOT NULL,
    enabled INTEGER NOT NULL,
    session TEXT,
    created_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS rounds (
    target_id INTEGER NOT NULL,
    ts_ms INTEGER NOT NULL,
    rtt_us INTEGER,
    PRIMARY KEY (target_id, ts_ms)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS hops (
    target_id INTEGER NOT NULL,
    ts_ms INTEGER NOT NULL,
    data BLOB NOT NULL,
    PRIMARY KEY (target_id, ts_ms)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS target_events (
    target_id INTEGER NOT NULL,
    ts_ms INTEGER NOT NULL,
    kind TEXT NOT NULL,
    old TEXT,
    new TEXT,
    PRIMARY KEY (target_id, ts_ms, kind)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS shares (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT NOT NULL UNIQUE,
    settings TEXT NOT NULL,
    created_ms INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    closed INTEGER NOT NULL DEFAULT 0,
    last_seen_ms INTEGER,
    last_seen_ip TEXT,
    views INTEGER NOT NULL DEFAULT 0
);
"#;

/// Columns added after the first release.
fn migrate(c: &Connection) -> Result<()> {
    let cols: Vec<String> = c
        .prepare("PRAGMA table_info(targets)")?
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<rusqlite::Result<_>>()?;
    if !cols.iter().any(|c| c == "share_id") {
        c.execute_batch("ALTER TABLE targets ADD COLUMN share_id INTEGER")?;
    }
    if !cols.iter().any(|c| c == "restrict_to") {
        c.execute_batch("ALTER TABLE targets ADD COLUMN restrict_to TEXT")?;
    }
    c.execute_batch("CREATE INDEX IF NOT EXISTS targets_share ON targets(share_id)")?;
    let rcols: Vec<String> = c
        .prepare("PRAGMA table_info(rounds)")?
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<rusqlite::Result<_>>()?;
    if !rcols.iter().any(|c| c == "interval_ms") {
        c.execute_batch("ALTER TABLE rounds ADD COLUMN interval_ms INTEGER")?;
    }
    if !cols.iter().any(|c| c == "last_ip") {
        // The address the target's name last resolved to, so a change is
        // noticed across restarts too.
        c.execute_batch("ALTER TABLE targets ADD COLUMN last_ip TEXT")?;
    }
    sanitize_names(c)?;
    Ok(())
}

fn table_exists(c: &Connection, name: &str) -> Result<bool> {
    Ok(c.query_row("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1", [name], |_| Ok(()))
        .optional()?
        .is_some())
}

fn columns(c: &Connection, table: &str) -> Result<Vec<String>> {
    Ok(c.prepare(&format!("PRAGMA table_info({table})"))?
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<rusqlite::Result<_>>()?)
}

/// A web UI account saved by pingrail 0.3 or earlier, before sign-in moved
/// to doorward.
#[derive(Debug, Clone)]
pub struct LegacyUser {
    pub username: String,
    /// Argon2id PHC string.
    pub phc: String,
    /// The passkey user handle (made the first time a passkey was added).
    pub uuid: Option<String>,
}

/// A passkey saved by pingrail 0.3.
#[derive(Debug, Clone)]
pub struct LegacyPasskey {
    pub username: String,
    pub rp_id: String,
    /// base64url.
    pub cred_id: String,
    /// webauthn-rs's Passkey as JSON.
    pub passkey: String,
    pub label: String,
    pub created_ms: i64,
    pub last_used_ms: Option<i64>,
}

/// Names typed before pingrail cleaned input (or imported from hopwatch) may
/// hold control characters; clean them once.
fn sanitize_names(c: &Connection) -> Result<()> {
    let targets: Vec<(i64, String)> = c
        .prepare("SELECT id, name FROM targets")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    for (id, name) in targets {
        let clean = crate::util::clean_text(&name, 64);
        if clean != name {
            c.execute("UPDATE targets SET name=?2 WHERE id=?1", params![id, if clean.is_empty() { "target".to_string() } else { clean }])?;
        }
    }
    let shares: Vec<(i64, String)> = c
        .prepare("SELECT id, settings FROM shares")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    for (id, json) in shares {
        if let Ok(mut st) = serde_json::from_str::<ShareSettings>(&json) {
            let clean = crate::util::clean_text(&st.label, 80);
            if clean != st.label {
                st.label = clean;
                c.execute("UPDATE shares SET settings=?2 WHERE id=?1", params![id, serde_json::to_string(&st)?])?;
            }
        }
    }
    Ok(())
}

fn row_to_share(r: &rusqlite::Row) -> rusqlite::Result<Share> {
    let settings: String = r.get(2)?;
    Ok(Share {
        id: r.get(0)?,
        token: r.get(1)?,
        settings: serde_json::from_str(&settings).unwrap_or_default(),
        created_ms: r.get(3)?,
        revoked: r.get::<_, i64>(4)? != 0,
        last_seen_ms: r.get(5)?,
        last_seen_ip: r.get(6)?,
        views: r.get(7)?,
        owned_ids: Vec::new(),
    })
}

const SHARE_COLS: &str = "id, token, settings, created_ms, revoked, last_seen_ms, last_seen_ip, views";

fn connect(path: &Path) -> Result<Connection> {
    let c = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
    c.busy_timeout(std::time::Duration::from_secs(10))?;
    c.pragma_update(None, "journal_mode", "WAL")?;
    c.pragma_update(None, "synchronous", "NORMAL")?;
    c.pragma_update(None, "foreign_keys", "ON")?;
    Ok(c)
}

fn row_to_target(r: &rusqlite::Row) -> rusqlite::Result<Target> {
    Ok(Target {
        id: r.get(0)?,
        host: r.get(1)?,
        name: r.get(2)?,
        interval_ms: r.get::<_, i64>(3)? as u32,
        trace: r.get::<_, i64>(4)? != 0,
        enabled: r.get::<_, i64>(5)? != 0,
        session: r.get(6)?,
        created_ms: r.get(7)?,
        share_id: r.get(8)?,
        restrict: r
            .get::<_, Option<String>>(9)?
            .and_then(|j| serde_json::from_str::<Vec<String>>(&j).ok()),
    })
}

const TARGET_COLS: &str = "id, host, name, interval_ms, trace, enabled, session, created_ms, share_id, restrict_to";

impl Store {
    pub fn open(path: &Path) -> Result<Arc<Store>> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).ok();
        }
        let w = connect(path)?;
        w.execute_batch(SCHEMA).context("creating schema")?;
        migrate(&w).context("upgrading database")?;
        let r = connect(path)?;
        let sr = connect(path)?;
        Ok(Arc::new(Store { write: Mutex::new(w), read: Mutex::new(r), share_read: Mutex::new(sr) }))
    }

    fn reader(&self) -> std::sync::MutexGuard<'_, Connection> {
        if SHARE_READER.with(|c| c.get()) { self.share_read.lock().unwrap() } else { self.read.lock().unwrap() }
    }

    // ----- targets -------------------------------------------------------

    pub fn list_targets(&self) -> Result<Vec<Target>> {
        let c = self.reader();
        let mut st = c.prepare(&format!("SELECT {TARGET_COLS} FROM targets ORDER BY id"))?;
        let rows = st.query_map([], row_to_target)?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn get_target(&self, id: i64) -> Result<Option<Target>> {
        let c = self.reader();
        Ok(c.query_row(
            &format!("SELECT {TARGET_COLS} FROM targets WHERE id = ?1"),
            [id],
            row_to_target,
        )
        .optional()?)
    }

    pub fn add_target(&self, t: &NewTarget, default_interval: u32) -> Result<Target> {
        self.add_target_owned(t, default_interval, None, None)
    }

    /// Add a target, optionally owned by a share link and restricted to
    /// public destinations (plus `restrict`'s private exceptions).
    pub fn add_target_owned(
        &self,
        t: &NewTarget,
        default_interval: u32,
        share_id: Option<i64>,
        restrict: Option<&[String]>,
    ) -> Result<Target> {
        let host = t.host.trim().to_string();
        let name = t
            .name
            .as_deref()
            .map(|n| crate::util::clean_text(n, 64))
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| host.clone());
        let interval = t.interval_ms.unwrap_or(default_interval).clamp(250, 3_600_000);
        let trace = t.trace.unwrap_or(true);
        let c = self.write.lock().unwrap();
        let restrict = restrict.map(|r| serde_json::to_string(r).unwrap_or_else(|_| "[]".into()));
        c.execute(
            "INSERT INTO targets (host, name, interval_ms, trace, enabled, session, created_ms, share_id, restrict_to)
             VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?7, ?8)",
            params![host, name, interval as i64, trace as i64, t.session, now_ms(), share_id, restrict],
        )?;
        let id = c.last_insert_rowid();
        drop(c);
        Ok(self.get_target(id)?.expect("just inserted"))
    }

    pub fn update_target(&self, id: i64, p: &TargetPatch) -> Result<Option<Target>> {
        let Some(mut t) = self.get_target(id)? else { return Ok(None) };
        if let Some(n) = &p.name {
            let n = crate::util::clean_text(n, 64);
            t.name = if n.is_empty() { t.host.clone() } else { n };
        }
        if let Some(e) = p.enabled {
            t.enabled = e;
        }
        if let Some(tr) = p.trace {
            t.trace = tr;
        }
        if let Some(i) = p.interval_ms {
            t.interval_ms = i.clamp(250, 3_600_000);
        }
        if let Some(s) = &p.session {
            t.session = s.clone();
        }
        let c = self.write.lock().unwrap();
        c.execute(
            "UPDATE targets SET name=?2, enabled=?3, trace=?4, interval_ms=?5, session=?6 WHERE id=?1",
            params![id, t.name, t.enabled as i64, t.trace as i64, t.interval_ms as i64, t.session],
        )?;
        Ok(Some(t))
    }

    pub fn delete_target(&self, id: i64) -> Result<bool> {
        let mut c = self.write.lock().unwrap();
        let tx = c.transaction()?;
        let n = tx.execute("DELETE FROM targets WHERE id=?1", [id])?;
        tx.execute("DELETE FROM rounds WHERE target_id=?1", [id])?;
        tx.execute("DELETE FROM hops WHERE target_id=?1", [id])?;
        tx.execute("DELETE FROM target_events WHERE target_id=?1", [id])?;
        tx.commit()?;
        Ok(n > 0)
    }

    /// Pause every target owned by `session` and hand it back to no-one.
    pub fn end_session(&self, session: &str, keep_running: bool) -> Result<usize> {
        let c = self.write.lock().unwrap();
        let n = if keep_running {
            c.execute("UPDATE targets SET session=NULL WHERE session=?1", [session])?
        } else {
            c.execute("UPDATE targets SET session=NULL, enabled=0 WHERE session=?1", [session])?
        };
        Ok(n)
    }

    /// Sessions do not survive a restart: pause anything a TUI owned.
    pub fn pause_all_sessions(&self) -> Result<usize> {
        let c = self.write.lock().unwrap();
        Ok(c.execute(
            "UPDATE targets SET session=NULL, enabled=0 WHERE session IS NOT NULL",
            [],
        )?)
    }

    /// Make a visitor-added target yours (no owner, no restriction).
    pub fn take_over_target(&self, id: i64) -> Result<()> {
        let c = self.write.lock().unwrap();
        c.execute("UPDATE targets SET share_id=NULL, restrict_to=NULL WHERE id=?1", [id])?;
        Ok(())
    }

    // ----- share links ----------------------------------------------------

    fn attach_owned(&self, shares: &mut [Share]) -> Result<()> {
        let c = self.reader();
        let mut st = c.prepare_cached("SELECT share_id, id FROM targets WHERE share_id IS NOT NULL ORDER BY id")?;
        let pairs = st
            .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for sh in shares.iter_mut() {
            sh.owned_ids = pairs.iter().filter(|(s, _)| *s == sh.id).map(|(_, t)| *t).collect();
        }
        Ok(())
    }

    pub fn create_share(&self, settings: &ShareSettings, token: &str) -> Result<Share> {
        let json = serde_json::to_string(settings)?;
        let id = {
            let c = self.write.lock().unwrap();
            c.execute(
                "INSERT INTO shares (token, settings, created_ms) VALUES (?1, ?2, ?3)",
                params![token, json, now_ms()],
            )?;
            c.last_insert_rowid()
        };
        Ok(self.get_share(id)?.expect("just inserted"))
    }

    pub fn list_shares(&self) -> Result<Vec<Share>> {
        let mut v = {
            let c = self.reader();
            let mut st = c.prepare(&format!("SELECT {SHARE_COLS} FROM shares ORDER BY id DESC"))?;
            st.query_map([], row_to_share)?.collect::<rusqlite::Result<Vec<_>>>()?
        };
        self.attach_owned(&mut v)?;
        Ok(v)
    }

    pub fn get_share(&self, id: i64) -> Result<Option<Share>> {
        let sh = {
            let c = self.reader();
            c.query_row(&format!("SELECT {SHARE_COLS} FROM shares WHERE id=?1"), [id], row_to_share)
                .optional()?
        };
        self.with_owned(sh)
    }

    #[cfg(test)]
    pub fn share_by_token(&self, token: &str) -> Result<Option<Share>> {
        let sh = {
            let c = self.reader();
            c.query_row(&format!("SELECT {SHARE_COLS} FROM shares WHERE token=?1"), [token], row_to_share)
                .optional()?
        };
        self.with_owned(sh)
    }

    fn with_owned(&self, sh: Option<Share>) -> Result<Option<Share>> {
        match sh {
            Some(s) => {
                let mut v = [s];
                self.attach_owned(&mut v)?;
                let [s] = v;
                Ok(Some(s))
            }
            None => Ok(None),
        }
    }

    /// Replace a share's settings. Extending the expiry of an expired (but not
    /// revoked) link reopens it; its visitors' targets stay paused.
    pub fn update_share(&self, id: i64, settings: &ShareSettings) -> Result<Option<Share>> {
        let json = serde_json::to_string(settings)?;
        {
            let c = self.write.lock().unwrap();
            let n = c.execute(
                "UPDATE shares SET settings=?2,
                     closed = CASE WHEN revoked=0 AND (?3 IS NULL OR ?3 > ?4) THEN 0 ELSE closed END
                 WHERE id=?1",
                params![id, json, settings.expires_ms, now_ms()],
            )?;
            if n == 0 {
                return Ok(None);
            }
            // Destinations visitors already added follow the link's current
            // private-address exceptions, not the ones it had back then.
            let allow = serde_json::to_string(&settings.allow_private)?;
            c.execute("UPDATE targets SET restrict_to=?2 WHERE share_id=?1 AND restrict_to IS NOT NULL", params![id, allow])?;
        }
        self.get_share(id)
    }

    /// New link for an existing share; also un-revokes it.
    pub fn regenerate_share(&self, id: i64, token: &str) -> Result<Option<Share>> {
        {
            let c = self.write.lock().unwrap();
            if c.execute("UPDATE shares SET token=?2, revoked=0, closed=0 WHERE id=?1", params![id, token])? == 0 {
                return Ok(None);
            }
        }
        self.get_share(id)
    }

    /// Revoke a link and pause what its visitors added.
    pub fn revoke_share(&self, id: i64) -> Result<bool> {
        let c = self.write.lock().unwrap();
        let n = c.execute("UPDATE shares SET revoked=1, closed=1 WHERE id=?1", [id])?;
        c.execute("UPDATE targets SET enabled=0 WHERE share_id=?1", [id])?;
        Ok(n > 0)
    }

    /// Delete a link. Targets its visitors added are paused and become yours.
    pub fn delete_share(&self, id: i64) -> Result<bool> {
        let mut c = self.write.lock().unwrap();
        let tx = c.transaction()?;
        tx.execute("UPDATE targets SET enabled=0, share_id=NULL, restrict_to=NULL WHERE share_id=?1", [id])?;
        let n = tx.execute("DELETE FROM shares WHERE id=?1", [id])?;
        tx.commit()?;
        Ok(n > 0)
    }

    /// Pause visitors' targets on links that have expired. Returns how many
    /// links were closed.
    pub fn close_inactive_shares(&self, now: i64) -> Result<usize> {
        let mut c = self.write.lock().unwrap();
        let tx = c.transaction()?;
        let ids: Vec<i64> = {
            let mut st = tx.prepare("SELECT id, settings, revoked FROM shares WHERE closed=0")?;
            st.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?)))?
                .filter_map(|r| r.ok())
                .filter(|(_, json, revoked)| {
                    *revoked != 0
                        || serde_json::from_str::<ShareSettings>(json)
                            .ok()
                            .and_then(|s| s.expires_ms)
                            .is_some_and(|e| e <= now)
                })
                .map(|(id, _, _)| id)
                .collect()
        };
        for id in &ids {
            tx.execute("UPDATE targets SET enabled=0 WHERE share_id=?1", [id])?;
            tx.execute("UPDATE shares SET closed=1 WHERE id=?1", [id])?;
        }
        tx.commit()?;
        Ok(ids.len())
    }

    /// Record a visit to a share link.
    pub fn touch_share(&self, id: i64, ip: Option<&str>, count_view: bool) -> Result<()> {
        let c = self.write.lock().unwrap();
        c.execute(
            "UPDATE shares SET last_seen_ms=?2, last_seen_ip=COALESCE(?3, last_seen_ip), views=views+?4 WHERE id=?1",
            params![id, now_ms(), ip, count_view as i64],
        )?;
        Ok(())
    }

    // ----- samples -------------------------------------------------------

    pub fn insert_rounds(&self, rounds: &[RoundRecord]) -> Result<()> {
        if rounds.is_empty() {
            return Ok(());
        }
        let mut c = self.write.lock().unwrap();
        let tx = c.transaction()?;
        {
            let mut r = tx.prepare_cached(
                "INSERT OR REPLACE INTO rounds (target_id, ts_ms, rtt_us, interval_ms) VALUES (?1, ?2, ?3, ?4)",
            )?;
            let mut h = tx.prepare_cached(
                "INSERT OR REPLACE INTO hops (target_id, ts_ms, data) VALUES (?1, ?2, ?3)",
            )?;
            for rd in rounds {
                r.execute(params![rd.target_id, rd.ts_ms, rd.rtt_us.map(|v| v as i64), rd.interval_ms as i64])?;
                if let Some(hops) = &rd.hops {
                    h.execute(params![rd.target_id, rd.ts_ms, encode_hops(hops)])?;
                }
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Endpoint samples in `[from, to)` as (ts_ms, rtt_ms).
    pub fn load_rounds(&self, target: i64, from: i64, to: i64) -> Result<Vec<(i64, Option<f64>)>> {
        let c = self.reader();
        let mut st = c.prepare_cached(
            "SELECT ts_ms, rtt_us FROM rounds WHERE target_id=?1 AND ts_ms>=?2 AND ts_ms<?3 ORDER BY ts_ms",
        )?;
        let rows = st
            .query_map(params![target, from, to], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, Option<i64>>(1)?.map(|us| us as f64 / 1000.0)))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Endpoint samples in `[from, to)` with the interval each was taken at.
    pub fn load_samples(&self, target: i64, from: i64, to: i64) -> Result<Vec<Sample>> {
        let c = self.reader();
        let mut st = c.prepare_cached(
            "SELECT ts_ms, rtt_us, interval_ms FROM rounds WHERE target_id=?1 AND ts_ms>=?2 AND ts_ms<?3 ORDER BY ts_ms",
        )?;
        let rows = st
            .query_map(params![target, from, to], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Option<i64>>(1)?.map(|us| us as f64 / 1000.0),
                    r.get::<_, Option<i64>>(2)?.map(|v| v.clamp(1, u32::MAX as i64) as u32),
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Visit per-hop samples in `[from, to)` in time order without keeping
    /// them: `f(ts_ms, hops, interval_ms)`.
    pub fn for_each_hops(
        &self,
        target: i64,
        from: i64,
        to: i64,
        mut f: impl FnMut(i64, &[HopRecord], Option<u32>),
    ) -> Result<()> {
        let c = self.reader();
        let mut st = c.prepare_cached(
            "SELECT h.ts_ms, h.data, r.interval_ms FROM hops h
             LEFT JOIN rounds r ON r.target_id = h.target_id AND r.ts_ms = h.ts_ms
             WHERE h.target_id=?1 AND h.ts_ms>=?2 AND h.ts_ms<?3 ORDER BY h.ts_ms",
        )?;
        let mut rows = st.query(params![target, from, to])?;
        while let Some(r) = rows.next()? {
            let ts: i64 = r.get(0)?;
            let blob = r.get_ref(1)?.as_blob()?;
            let iv = r.get::<_, Option<i64>>(2)?.map(|v| v.clamp(1, u32::MAX as i64) as u32);
            f(ts, &decode_hops(blob), iv);
        }
        Ok(())
    }

    /// Delete samples of `targets` older than `before_ms`.
    pub fn prune_targets(&self, targets: &[i64], before_ms: i64) -> Result<usize> {
        let c = self.write.lock().unwrap();
        let mut n = 0;
        for id in targets {
            n += c.execute("DELETE FROM rounds WHERE target_id=?1 AND ts_ms < ?2", params![id, before_ms])?;
            n += c.execute("DELETE FROM hops WHERE target_id=?1 AND ts_ms < ?2", params![id, before_ms])?;
            c.execute("DELETE FROM target_events WHERE target_id=?1 AND ts_ms < ?2", params![id, before_ms])?;
        }
        Ok(n)
    }

    /// Approximate disk space used by the samples of `targets`, in bytes
    /// (row payload plus typical per-row overhead).
    pub fn storage_used(&self, targets: &[i64]) -> Result<u64> {
        let c = self.reader();
        let mut total = 0u64;
        for id in targets {
            let rounds: i64 = c.query_row("SELECT COUNT(*) FROM rounds WHERE target_id=?1", [id], |r| r.get(0))?;
            let (hops, blob): (i64, Option<i64>) =
                c.query_row("SELECT COUNT(*), SUM(length(data)) FROM hops WHERE target_id=?1", [id], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?;
            total += rounds as u64 * 40 + hops as u64 * 30 + blob.unwrap_or(0) as u64;
        }
        Ok(total)
    }

    pub fn prune(&self, before_ms: i64) -> Result<usize> {
        let c = self.write.lock().unwrap();
        let a = c.execute("DELETE FROM rounds WHERE ts_ms < ?1", [before_ms])?;
        let b = c.execute("DELETE FROM hops WHERE ts_ms < ?1", [before_ms])?;
        c.execute("DELETE FROM target_events WHERE ts_ms < ?1", [before_ms])?;
        Ok(a + b)
    }

    // ----- settings kept in the database -----------------------------------

    pub fn meta_get(&self, key: &str) -> Result<Option<String>> {
        let c = self.reader();
        Ok(c.query_row("SELECT value FROM meta WHERE key=?1", [key], |r| r.get(0)).optional()?)
    }

    pub fn meta_set(&self, key: &str, value: &str) -> Result<()> {
        let c = self.write.lock().unwrap();
        c.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    // ----- what targets resolve to --------------------------------------

    /// The address a target's name last resolved to.
    pub fn target_last_ip(&self, id: i64) -> Result<Option<String>> {
        let c = self.reader();
        Ok(c.query_row("SELECT last_ip FROM targets WHERE id=?1", [id], |r| r.get(0)).optional()?.flatten())
    }

    /// A target's name now resolves to `new`; when it resolved to something
    /// else before (`old`), that is recorded as a change at `ts_ms`.
    pub fn record_address(&self, id: i64, ts_ms: i64, old: Option<&str>, new: &str) -> Result<()> {
        let mut c = self.write.lock().unwrap();
        let tx = c.transaction()?;
        let n = tx.execute("UPDATE targets SET last_ip=?2 WHERE id=?1", params![id, new])?;
        if n > 0
            && let Some(old) = old
            && old != new
        {
            tx.execute(
                "INSERT OR REPLACE INTO target_events (target_id, ts_ms, kind, old, new) VALUES (?1, ?2, 'address', ?3, ?4)",
                params![id, ts_ms, old, new],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// What happened to a target in `[from, to)`, oldest first (at most
    /// `limit`, the latest ones).
    pub fn target_events(&self, id: i64, from: i64, to: i64, limit: usize) -> Result<Vec<TargetEvent>> {
        let c = self.reader();
        let mut st = c.prepare(
            "SELECT ts_ms, kind, old, new FROM target_events WHERE target_id=?1 AND ts_ms >= ?2 AND ts_ms < ?3
             ORDER BY ts_ms DESC LIMIT ?4",
        )?;
        let mut v = st
            .query_map(params![id, from, to, limit as i64], |r| {
                Ok(TargetEvent { ts_ms: r.get(0)?, kind: r.get(1)?, from: r.get(2)?, to: r.get(3)?, ..Default::default() })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        v.reverse();
        Ok(v)
    }

    // ----- accounts saved by pingrail 0.3 ---------------------------------

    /// Web UI accounts and passkeys saved before sign-in moved to doorward,
    /// or `None` once they have been moved (see `auth`).
    pub fn legacy_accounts(&self) -> Result<Option<(Vec<LegacyUser>, Vec<LegacyPasskey>)>> {
        let c = self.write.lock().unwrap();
        if !table_exists(&c, "users")? {
            return Ok(None);
        }
        let with_uuid = columns(&c, "users")?.iter().any(|n| n == "uuid");
        let sql = if with_uuid { "SELECT username, phc, uuid FROM users" } else { "SELECT username, phc, NULL FROM users" };
        let users = c
            .prepare(sql)?
            .query_map([], |r| Ok(LegacyUser { username: r.get(0)?, phc: r.get(1)?, uuid: r.get(2)? }))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let passkeys = if table_exists(&c, "passkeys")? {
            c.prepare("SELECT username, rp_id, cred_id, passkey, label, created_ms, last_used_ms FROM passkeys ORDER BY id")?
                .query_map([], |r| {
                    Ok(LegacyPasskey {
                        username: r.get(0)?,
                        rp_id: r.get(1)?,
                        cred_id: r.get(2)?,
                        passkey: r.get(3)?,
                        label: r.get(4)?,
                        created_ms: r.get(5)?,
                        last_used_ms: r.get(6)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?
        } else {
            Vec::new()
        };
        Ok(Some((users, passkeys)))
    }

    /// Remove pingrail 0.3's account tables once doorward has their contents
    /// (their sessions are left behind: everyone signs in once).
    pub fn drop_legacy_accounts(&self) -> Result<()> {
        let mut c = self.write.lock().unwrap();
        let tx = c.transaction()?;
        tx.execute_batch(
            "DROP TABLE IF EXISTS web_sessions; DROP TABLE IF EXISTS passkeys; DROP TABLE IF EXISTS users;
             DELETE FROM meta WHERE key IN ('argon2_policy', 'web_sessions_hashed');",
        )?;
        tx.commit()?;
        Ok(())
    }
}

/// One setting from a database without opening it for writing or
/// upgrading it (for the installer, which may run beside the service).
pub fn peek_meta(db: &Path, key: &str) -> Option<String> {
    if !db.exists() {
        return None;
    }
    let c = Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).ok()?;
    c.query_row("SELECT value FROM meta WHERE key=?1", [key], |r| r.get(0)).ok()
}

/// Run a blocking store operation off the async runtime.
pub async fn blocking<T, F>(store: &Arc<Store>, f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(&Store) -> Result<T> + Send + 'static,
{
    let s = store.clone();
    tokio::task::spawn_blocking(move || f(&s)).await?
}

/// Like [`blocking`], on behalf of a share-link visitor: reads use the
/// separate share connection.
pub async fn blocking_share<T, F>(store: &Arc<Store>, f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(&Store) -> Result<T> + Send + 'static,
{
    let s = store.clone();
    tokio::task::spawn_blocking(move || {
        SHARE_READER.with(|c| c.set(true));
        let r = f(&s);
        SHARE_READER.with(|c| c.set(false));
        r
    })
    .await?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corrupt_hop_blobs_never_panic() {
        let mut x: u64 = 88172645463325252;
        for _ in 0..100_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let len = (x % 64) as usize;
            let blob: Vec<u8> = (0..len).map(|i| (x >> (i % 8 * 8)) as u8 ^ i as u8).collect();
            let _ = decode_hops(&blob);
        }
    }

    #[test]
    fn hop_blob_roundtrip() {
        let hops = vec![
            HopRecord { ttl: 1, addr: Some("192.168.1.1".parse().unwrap()), rtt_us: Some(812), kind: HopKind::TimeExceeded },
            HopRecord { ttl: 2, addr: None, rtt_us: None, kind: HopKind::Timeout },
            HopRecord { ttl: 3, addr: Some("2001:db8::9".parse().unwrap()), rtt_us: Some(15_000), kind: HopKind::Echo },
        ];
        assert_eq!(decode_hops(&encode_hops(&hops)), hops);
    }

    #[test]
    fn accounts_from_0_3_are_handed_over_then_dropped() {
        let dir = std::env::temp_dir().join(format!("pingrail-test-{}", crate::config::random_hex(4)));
        let db = dir.join("t.db");
        {
            std::fs::create_dir_all(&dir).unwrap();
            let c = Connection::open(&db).unwrap();
            c.execute_batch(
                "CREATE TABLE users (username TEXT PRIMARY KEY, phc TEXT NOT NULL, uuid TEXT);
                 CREATE TABLE web_sessions (token TEXT PRIMARY KEY, username TEXT NOT NULL, expires_ms INTEGER NOT NULL, auth_ms INTEGER);
                 CREATE TABLE passkeys (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, rp_id TEXT NOT NULL,
                     cred_id TEXT NOT NULL UNIQUE, passkey TEXT NOT NULL, label TEXT NOT NULL, created_ms INTEGER NOT NULL, last_used_ms INTEGER);
                 CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 INSERT INTO users VALUES ('admin', '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA', '0f8c2b1e-3c4d-4e5f-8a9b-0c1d2e3f4a5b');
                 INSERT INTO web_sessions VALUES ('abc', 'admin', 99999999999999, 0);
                 INSERT INTO passkeys (username, rp_id, cred_id, passkey, label, created_ms) VALUES ('admin', 'pc.lan', 'AAEC', '{}', 'Phone', 5);
                 INSERT INTO meta VALUES ('argon2_policy', '{}'), ('passkey_required', '1');",
            )
            .unwrap();
        }
        let s = Store::open(&db).unwrap();
        let (users, keys) = s.legacy_accounts().unwrap().expect("0.3 tables found");
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].uuid.as_deref(), Some("0f8c2b1e-3c4d-4e5f-8a9b-0c1d2e3f4a5b"));
        assert_eq!((keys[0].rp_id.as_str(), keys[0].cred_id.as_str(), keys[0].label.as_str()), ("pc.lan", "AAEC", "Phone"));
        s.drop_legacy_accounts().unwrap();
        assert!(s.legacy_accounts().unwrap().is_none(), "gone once handed over");
        assert_eq!(s.meta_get("argon2_policy").unwrap(), None);
        assert_eq!(s.meta_get("passkey_required").unwrap().as_deref(), Some("1"), "pingrail's own setting stays");
        drop(s);
        // Reopening doesn't bring the tables back.
        let s = Store::open(&db).unwrap();
        assert!(s.legacy_accounts().unwrap().is_none());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn address_changes_are_recorded_once() {
        let dir = std::env::temp_dir().join(format!("pingrail-test-{}", crate::config::random_hex(4)));
        let s = Store::open(&dir.join("t.db")).unwrap();
        let t = s.add_target(&NewTarget { host: "cdn.example.com".into(), ..Default::default() }, 1000).unwrap();
        assert_eq!(s.target_last_ip(t.id).unwrap(), None);
        s.record_address(t.id, 1_000, None, "192.0.2.7").unwrap();
        s.record_address(t.id, 2_000, Some("192.0.2.7"), "192.0.2.7").unwrap();
        assert!(s.target_events(t.id, 0, i64::MAX, 10).unwrap().is_empty(), "no change, no event");
        s.record_address(t.id, 3_000, Some("192.0.2.7"), "198.51.100.10").unwrap();
        s.record_address(t.id, 4_000, Some("198.51.100.10"), "192.0.2.7").unwrap();
        assert_eq!(s.target_last_ip(t.id).unwrap().as_deref(), Some("192.0.2.7"));
        let ev = s.target_events(t.id, 0, i64::MAX, 10).unwrap();
        assert_eq!(ev.len(), 2);
        assert_eq!((ev[0].ts_ms, ev[0].from.as_deref(), ev[0].to.as_deref()), (3_000, Some("192.0.2.7"), Some("198.51.100.10")));
        assert_eq!(ev[0].kind, "address");
        assert_eq!(s.target_events(t.id, 3_500, i64::MAX, 10).unwrap().len(), 1, "range");
        assert_eq!(s.target_events(t.id, 0, i64::MAX, 1).unwrap()[0].ts_ms, 4_000, "the latest when capped");
        s.prune(3_500).unwrap();
        assert_eq!(s.target_events(t.id, 0, i64::MAX, 10).unwrap().len(), 1, "pruned with the samples");
        s.delete_target(t.id).unwrap();
        assert!(s.target_events(t.id, 0, i64::MAX, 10).unwrap().is_empty());
        s.record_address(t.id, 5_000, Some("a"), "b").unwrap();
        assert!(s.target_events(t.id, 0, i64::MAX, 10).unwrap().is_empty(), "nothing for a deleted target");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn store_roundtrip() {
        let dir = std::env::temp_dir().join(format!("pingrail-test-{}", crate::config::random_hex(4)));
        let s = Store::open(&dir.join("t.db")).unwrap();
        let t = s.add_target(&NewTarget { host: "1.1.1.1".into(), ..Default::default() }, 1000).unwrap();
        assert_eq!(t.name, "1.1.1.1");
        assert!(t.is_background());
        s.insert_rounds(&[
            RoundRecord { target_id: t.id, ts_ms: 1000, interval_ms: 1000, rtt_us: Some(1500), hops: None },
            RoundRecord { target_id: t.id, ts_ms: 2000, interval_ms: 1000, rtt_us: None, hops: Some(vec![]) },
        ])
        .unwrap();
        let r = s.load_rounds(t.id, 0, 5000).unwrap();
        assert_eq!(r, vec![(1000, Some(1.5)), (2000, None)]);
        let p = TargetPatch { session: Some(Some("abc".into())), enabled: Some(false), ..Default::default() };
        let t2 = s.update_target(t.id, &p).unwrap().unwrap();
        assert_eq!(t2.session.as_deref(), Some("abc"));
        assert!(!t2.enabled);
        assert_eq!(s.end_session("abc", true).unwrap(), 1);
        assert!(s.get_target(t.id).unwrap().unwrap().is_background());
        assert!(s.delete_target(t.id).unwrap());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn share_lifecycle() {
        let dir = std::env::temp_dir().join(format!("pingrail-test-{}", crate::config::random_hex(4)));
        let s = Store::open(&dir.join("t.db")).unwrap();
        let mine = s.add_target(&NewTarget { host: "1.1.1.1".into(), ..Default::default() }, 1000).unwrap();
        let settings = ShareSettings { label: "ISP".into(), target_ids: vec![mine.id], can_add: true, ..Default::default() };
        let sh = s.create_share(&settings, "tok1").unwrap();
        let theirs = s
            .add_target_owned(&NewTarget { host: "9.9.9.9".into(), ..Default::default() }, 1000, Some(sh.id), Some(&["10.0.0.0/8".to_string()]))
            .unwrap();
        assert_eq!(theirs.share_id, Some(sh.id));
        assert_eq!(theirs.restrict.as_deref(), Some(&["10.0.0.0/8".to_string()][..]));
        let sh = s.share_by_token("tok1").unwrap().unwrap();
        assert_eq!(sh.owned_ids, vec![theirs.id]);
        assert_eq!(sh.visible_ids(), vec![mine.id, theirs.id]);

        // Expire it: the visitor's target is paused, mine is untouched.
        let mut expired = sh.settings.clone();
        expired.expires_ms = Some(now_ms() - 1);
        s.update_share(sh.id, &expired).unwrap();
        // Saving the link also re-applies its private exceptions (now none)
        // to destinations visitors added earlier; my own target has none.
        assert_eq!(s.get_target(theirs.id).unwrap().unwrap().restrict, Some(vec![]));
        assert_eq!(s.get_target(mine.id).unwrap().unwrap().restrict, None);
        let mut widened = expired.clone();
        widened.allow_private = vec!["192.168.1.0/24".into()];
        s.update_share(sh.id, &widened).unwrap();
        assert_eq!(s.get_target(theirs.id).unwrap().unwrap().restrict, Some(vec!["192.168.1.0/24".to_string()]));
        s.update_share(sh.id, &expired).unwrap();
        assert_eq!(s.close_inactive_shares(now_ms()).unwrap(), 1);
        assert!(!s.get_target(theirs.id).unwrap().unwrap().enabled);
        assert!(s.get_target(mine.id).unwrap().unwrap().enabled);
        assert_eq!(s.close_inactive_shares(now_ms()).unwrap(), 0);

        // Regenerate gives a new token and reactivates the link.
        let sh2 = s.regenerate_share(sh.id, "tok2").unwrap().unwrap();
        assert!(s.share_by_token("tok1").unwrap().is_none());
        assert_eq!(sh2.token, "tok2");

        // Deleting the link hands the visitor's target over to you, paused.
        assert!(s.delete_share(sh.id).unwrap());
        let t = s.get_target(theirs.id).unwrap().unwrap();
        assert_eq!((t.share_id, t.restrict.is_none(), t.enabled), (None, true, false));
        std::fs::remove_dir_all(dir).ok();
    }
}
