//! SQLite storage for targets, samples, users and web sessions.

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::config::now_ms;
use crate::model::{NewTarget, Share, ShareSettings, Target, TargetPatch};

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
CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, phc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS web_sessions (
    token TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    expires_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS passkeys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    rp_id TEXT NOT NULL,
    cred_id TEXT NOT NULL UNIQUE,
    passkey TEXT NOT NULL,
    label TEXT NOT NULL,
    created_ms INTEGER NOT NULL,
    last_used_ms INTEGER
);
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
    let ucols: Vec<String> = c
        .prepare("PRAGMA table_info(users)")?
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<rusqlite::Result<_>>()?;
    if !ucols.iter().any(|c| c == "uuid") {
        // The user handle passkeys carry (random, never shown).
        c.execute_batch("ALTER TABLE users ADD COLUMN uuid TEXT")?;
    }
    let scols: Vec<String> = c
        .prepare("PRAGMA table_info(web_sessions)")?
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<rusqlite::Result<_>>()?;
    if !scols.iter().any(|c| c == "auth_ms") {
        // When the session's user last proved who they are.
        c.execute_batch("ALTER TABLE web_sessions ADD COLUMN auth_ms INTEGER")?;
    }
    sanitize_names(c)?;
    hash_session_tokens(c)?;
    Ok(())
}

/// Web sessions are looked up by the SHA-256 of their cookie, so a copy of
/// the database can't be used to sign in. Sessions saved before that are
/// converted once, without signing anyone out.
fn hash_session_tokens(c: &Connection) -> Result<()> {
    let done: Option<String> =
        c.query_row("SELECT value FROM meta WHERE key='web_sessions_hashed'", [], |r| r.get(0)).optional()?;
    if done.is_some() {
        return Ok(());
    }
    let tokens: Vec<String> = c
        .prepare("SELECT token FROM web_sessions")?
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    for t in tokens {
        c.execute("UPDATE web_sessions SET token=?2 WHERE token=?1", params![t, session_key(&t)])?;
    }
    c.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('web_sessions_hashed', '1')", [])?;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct PasskeyRow {
    pub id: i64,
    pub username: String,
    pub rp_id: String,
    /// webauthn-rs's Passkey as JSON.
    pub passkey: String,
    pub label: String,
    pub created_ms: i64,
    pub last_used_ms: Option<i64>,
}

fn uuid_string(b: &[u8; 16]) -> String {
    let h = hex::encode(b);
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

/// What a session cookie is stored as.
fn session_key(token: &str) -> String {
    hex::encode(ring::digest::digest(&ring::digest::SHA256, token.as_bytes()))
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
        c.execute("DELETE FROM web_sessions WHERE expires_ms < ?1", [now_ms()])?;
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

    // ----- users & web sessions -----------------------------------------

    pub fn has_users(&self) -> Result<bool> {
        let c = self.reader();
        let n: i64 = c.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?;
        Ok(n > 0)
    }

    pub fn set_user(&self, username: &str, phc: &str) -> Result<()> {
        let c = self.write.lock().unwrap();
        c.execute(
            "INSERT INTO users (username, phc) VALUES (?1, ?2)
             ON CONFLICT(username) DO UPDATE SET phc=excluded.phc",
            params![username, phc],
        )?;
        // Changing a password signs that user out everywhere.
        c.execute("DELETE FROM web_sessions WHERE username=?1", [username])?;
        Ok(())
    }

    pub fn user_phc(&self, username: &str) -> Result<Option<String>> {
        let c = self.reader();
        Ok(c.query_row("SELECT phc FROM users WHERE username=?1", [username], |r| r.get(0))
            .optional()?)
    }

    /// Save a password hashed with newer settings, unless the password was
    /// changed meanwhile. Nobody is signed out.
    pub fn rehash_user(&self, username: &str, old_phc: &str, new_phc: &str) -> Result<()> {
        let c = self.write.lock().unwrap();
        c.execute("UPDATE users SET phc=?3 WHERE username=?1 AND phc=?2", params![username, old_phc, new_phc])?;
        Ok(())
    }

    pub fn create_web_session(&self, token: &str, username: &str, expires_ms: i64) -> Result<()> {
        let c = self.write.lock().unwrap();
        c.execute(
            "INSERT INTO web_sessions (token, username, expires_ms, auth_ms) VALUES (?1, ?2, ?3, ?4)",
            params![session_key(token), username, expires_ms, now_ms()],
        )?;
        Ok(())
    }

    /// A session's user and when they last signed in or confirmed it was them.
    pub fn web_session(&self, token: &str) -> Result<Option<(String, i64)>> {
        let c = self.reader();
        Ok(c.query_row(
            "SELECT username, COALESCE(auth_ms, 0) FROM web_sessions WHERE token=?1 AND expires_ms > ?2",
            params![session_key(token), now_ms()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?)
    }

    /// Sign `username` out everywhere except the session `keep`.
    pub fn end_other_sessions(&self, username: &str, keep: Option<&str>) -> Result<usize> {
        let c = self.write.lock().unwrap();
        Ok(c.execute(
            "DELETE FROM web_sessions WHERE username=?1 AND token<>?2",
            params![username, keep.map(session_key).unwrap_or_default()],
        )?)
    }

    // ----- passkeys --------------------------------------------------------

    /// The user's passkey handle, made on first use.
    pub fn user_uuid(&self, username: &str) -> Result<Option<String>> {
        let c = self.write.lock().unwrap();
        let row: Option<Option<String>> =
            c.query_row("SELECT uuid FROM users WHERE username=?1", [username], |r| r.get(0)).optional()?;
        match row {
            None => Ok(None),
            Some(Some(u)) => Ok(Some(u)),
            Some(None) => {
                let mut b = [0u8; 16];
                getrandom::fill(&mut b).map_err(|e| anyhow::anyhow!("random: {e}"))?;
                b[6] = (b[6] & 0x0f) | 0x40;
                b[8] = (b[8] & 0x3f) | 0x80;
                let u = uuid_string(&b);
                c.execute("UPDATE users SET uuid=?2 WHERE username=?1", params![username, u])?;
                Ok(Some(u))
            }
        }
    }

    pub fn user_by_uuid(&self, uuid: &str) -> Result<Option<String>> {
        let c = self.reader();
        Ok(c.query_row("SELECT username FROM users WHERE uuid=?1", [uuid], |r| r.get(0)).optional()?)
    }

    /// Passkeys, of one user or everyone's, for one relying party or all.
    pub fn passkeys(&self, username: Option<&str>, rp_id: Option<&str>) -> Result<Vec<PasskeyRow>> {
        let c = self.reader();
        let mut st = c.prepare(
            "SELECT id, username, rp_id, passkey, label, created_ms, last_used_ms FROM passkeys
             WHERE (?1 IS NULL OR username=?1) AND (?2 IS NULL OR rp_id=?2) ORDER BY id",
        )?;
        let rows = st
            .query_map(params![username, rp_id], |r| {
                Ok(PasskeyRow {
                    id: r.get(0)?,
                    username: r.get(1)?,
                    rp_id: r.get(2)?,
                    passkey: r.get(3)?,
                    label: r.get(4)?,
                    created_ms: r.get(5)?,
                    last_used_ms: r.get(6)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn add_passkey(&self, username: &str, rp_id: &str, cred_id: &str, passkey: &str, label: &str) -> Result<i64> {
        let c = self.write.lock().unwrap();
        c.execute(
            "INSERT INTO passkeys (username, rp_id, cred_id, passkey, label, created_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![username, rp_id, cred_id, passkey, label, now_ms()],
        )?;
        Ok(c.last_insert_rowid())
    }

    /// Record a sign-in with a passkey (and its updated counter, if any).
    pub fn passkey_used(&self, id: i64, passkey: Option<&str>) -> Result<()> {
        let c = self.write.lock().unwrap();
        c.execute(
            "UPDATE passkeys SET last_used_ms=?2, passkey=COALESCE(?3, passkey) WHERE id=?1",
            params![id, now_ms(), passkey],
        )?;
        Ok(())
    }

    /// Remove a passkey (only `username`'s, when given).
    pub fn delete_passkey(&self, id: i64, username: Option<&str>) -> Result<bool> {
        let c = self.write.lock().unwrap();
        Ok(c.execute("DELETE FROM passkeys WHERE id=?1 AND (?2 IS NULL OR username=?2)", params![id, username])? > 0)
    }

    pub fn delete_all_passkeys(&self) -> Result<usize> {
        let c = self.write.lock().unwrap();
        Ok(c.execute("DELETE FROM passkeys", [])?)
    }

    pub fn delete_web_session(&self, token: &str) -> Result<()> {
        let c = self.write.lock().unwrap();
        c.execute("DELETE FROM web_sessions WHERE token=?1", [session_key(token)])?;
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
    fn sessions_are_stored_hashed_and_old_ones_converted() {
        let dir = std::env::temp_dir().join(format!("pingrail-test-{}", crate::config::random_hex(4)));
        let db = dir.join("t.db");
        // A database from before hashing, with one plain-text session.
        {
            std::fs::create_dir_all(&dir).unwrap();
            let c = Connection::open(&db).unwrap();
            c.execute_batch(SCHEMA).unwrap();
            c.execute("INSERT INTO web_sessions VALUES ('oldcookie', 'admin', ?1)", [now_ms() + 60_000]).unwrap();
        }
        let s = Store::open(&db).unwrap();
        assert_eq!(s.web_session("oldcookie").unwrap().map(|x| x.0).as_deref(), Some("admin"));
        s.create_web_session("newcookie", "admin", now_ms() + 60_000).unwrap();
        let stored: Vec<String> = s
            .reader()
            .prepare("SELECT token FROM web_sessions")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert!(!stored.iter().any(|t| t.contains("cookie")), "{stored:?}");
        assert_eq!(s.web_session(&session_key("newcookie")).unwrap(), None);
        s.delete_web_session("newcookie").unwrap();
        assert_eq!(s.web_session("newcookie").unwrap(), None);
        // Converted once only.
        drop(s);
        let s = Store::open(&db).unwrap();
        assert_eq!(s.web_session("oldcookie").unwrap().map(|x| x.0).as_deref(), Some("admin"));
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
