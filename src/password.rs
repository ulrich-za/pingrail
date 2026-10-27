//! Password hashing: Argon2id, sized to the machine it runs on.
//!
//! Each password check uses a fixed slice of memory and real CPU time, which
//! is what makes guessing slow. The slice is chosen once from this machine's
//! memory (2 % of the total or 10 % of what's free, whichever is smaller,
//! split between two checks at a time), the number of passes is timed so a
//! check takes about a third of a second, and the result is saved. It is
//! never weaker than OWASP's minimum (19 MiB with 2 passes, or 46 MiB with
//! one) and never more than 256 MiB.

use anyhow::{Context, Result};
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use std::sync::RwLock;
use std::time::{Duration, Instant};

use crate::config::{now_ms, random_hex};
use crate::store::Store;
use crate::sysmem::{self, Memory};

const KIB_PER_MIB: u32 = 1024;
/// OWASP's minimum: 19 MiB with at least 2 passes…
const FLOOR_M: u32 = 19 * KIB_PER_MIB;
/// …or 46 MiB and more with at least 1.
const ONE_PASS_M: u32 = 46 * KIB_PER_MIB;
const CAP_M: u32 = 256 * KIB_PER_MIB;
/// Two checks at a time only when each still gets this much.
const SHARE_MIN_M: u32 = 32 * KIB_PER_MIB;
const MAX_T: u32 = 10;
/// How long one check should take.
const TARGET_MS: f64 = 350.0;
/// Shrink the memory if the fewest passes allowed would take longer.
const SLOW_MS: f64 = 1000.0;
/// Saved hashes asking for more than this are refused rather than tried.
const SANE_M: u32 = 1024 * KIB_PER_MIB;
/// Retune when the machine's memory changes by more than this fraction.
const RETUNE_CHANGE: f64 = 0.2;
const META_KEY: &str = "argon2_policy";

/// How passwords are hashed on this machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
    /// Checks allowed at once (1 or 2).
    pub concurrency: u32,
    /// The memory the policy was chosen for, in bytes (0 = unknown).
    pub ram_total: u64,
    /// About how long one check takes, in milliseconds.
    pub check_ms: u32,
    pub tuned_ms: i64,
}

impl Policy {
    /// The minimum, for machines whose memory can't be read.
    pub fn floor() -> Policy {
        Policy { m_kib: FLOOR_M, t: 2, p: 1, concurrency: 1, ram_total: 0, check_ms: 0, tuned_ms: 0 }
    }

    fn valid(&self) -> bool {
        (FLOOR_M..=CAP_M).contains(&self.m_kib)
            && (t_floor(self.m_kib)..=MAX_T).contains(&self.t)
            && self.p == 1
            && (1..=2).contains(&self.concurrency)
    }

    fn params(&self) -> Result<Params> {
        Params::new(self.m_kib, self.t, self.p, None).map_err(|e| anyhow::anyhow!("Argon2 settings: {e}"))
    }

    pub fn describe(&self) -> String {
        let ram = if self.ram_total > 0 {
            format!(", sized for {:.1} GiB of memory", self.ram_total as f64 / (1u64 << 30) as f64)
        } else {
            String::new()
        };
        format!(
            "Argon2id, {} MiB, {} pass{}, about {} ms per check, {} at a time{ram}",
            self.m_kib / KIB_PER_MIB,
            self.t,
            if self.t == 1 { "" } else { "es" },
            self.check_ms,
            self.concurrency
        )
    }
}

/// The fewest passes OWASP allows at this memory.
fn t_floor(m_kib: u32) -> u32 {
    if m_kib >= ONE_PASS_M { 1 } else { 2 }
}

/// Memory per check and checks at a time for this much memory.
pub fn plan_memory(mem: Option<Memory>) -> (u32, u32) {
    let Some(mem) = mem else { return (FLOOR_M, 1) };
    let budget_kib = ((mem.total / 50).min(mem.available / 10) / 1024).min(u32::MAX as u64) as u32;
    let (per, concurrency) = if budget_kib / 2 >= SHARE_MIN_M { (budget_kib / 2, 2) } else { (budget_kib, 1) };
    (per.clamp(FLOOR_M, CAP_M), concurrency)
}

/// Passes for a check of about `TARGET_MS`, given how long one pass takes.
pub fn pick_t(m_kib: u32, pass_ms: f64) -> u32 {
    let t = (TARGET_MS / pass_ms.max(0.1)).round() as u32;
    t.clamp(t_floor(m_kib), MAX_T)
}

/// How long one Argon2id pass over `m_kib` takes here (best of two), or
/// `None` when that memory can't be had.
fn time_pass(m_kib: u32) -> Result<Option<f64>> {
    let params = Params::new(m_kib, 1, 1, Some(32)).map_err(|e| anyhow::anyhow!("{e}"))?;
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|e| anyhow::anyhow!("random: {e}"))?;
    let mut out = [0u8; 32];
    let mut best = f64::MAX;
    for _ in 0..2 {
        let start = Instant::now();
        match a.hash_password_into(b"pingrail calibration", &salt, &mut out) {
            Ok(()) => best = best.min(start.elapsed().as_secs_f64() * 1000.0),
            Err(argon2::Error::OutOfMemory) => return Ok(None),
            Err(e) => anyhow::bail!("timing Argon2: {e}"),
        }
    }
    Ok(Some(best))
}

/// Choose a policy for this machine (takes a second or two).
pub fn tune(mem: Option<Memory>) -> Result<Policy> {
    let (mut m, concurrency) = plan_memory(mem);
    loop {
        match time_pass(m)? {
            Some(pass) if pass * t_floor(m) as f64 <= SLOW_MS || m == FLOOR_M => {
                let t = pick_t(m, pass);
                return Ok(Policy {
                    m_kib: m,
                    t,
                    p: 1,
                    concurrency,
                    ram_total: mem.map_or(0, |m| m.total),
                    check_ms: (pass * t as f64).round() as u32,
                    tuned_ms: now_ms(),
                });
            }
            None if m == FLOOR_M => anyhow::bail!("not enough memory for password hashing ({} MiB)", FLOOR_M / KIB_PER_MIB),
            // Too slow, or that much memory isn't free: try half.
            _ => m = (m / 2).max(FLOOR_M),
        }
    }
}

fn ram_changed(was: u64, now: Option<Memory>) -> bool {
    match now {
        Some(now) if was > 0 => (now.total as f64 - was as f64).abs() / was as f64 > RETUNE_CHANGE,
        Some(_) => true,
        None => false,
    }
}

/// The saved policy, or a newly tuned one when there is none, when the
/// machine's memory has changed a lot, or when `force` is set.
pub fn load_or_tune(store: &Store, force: bool) -> Result<Policy> {
    let mem = sysmem::detect();
    if !force
        && let Some(saved) = store.meta_get(META_KEY)?
        && let Ok(p) = serde_json::from_str::<Policy>(&saved)
        && p.valid()
        && !ram_changed(p.ram_total, mem)
    {
        return Ok(p);
    }
    let p = tune(mem)?;
    store.meta_set(META_KEY, &serde_json::to_string(&p)?)?;
    Ok(p)
}

/// The policy for a starting service (tuned on the first start).
pub async fn start(store: &std::sync::Arc<Store>) -> Result<Passwords> {
    let s = store.clone();
    tokio::task::spawn_blocking(move || {
        let p = load_or_tune(&s, false)?;
        tracing::info!("password hashing: {}", p.describe());
        Passwords::new(p)
    })
    .await?
}

/// What checking a password found.
#[derive(Debug, PartialEq, Eq)]
pub enum Check {
    /// Right, and `rehash` when it was saved with other settings.
    Good { rehash: bool },
    Wrong,
    /// Not enough free memory just now.
    Busy,
}

#[derive(Debug, thiserror::Error)]
pub enum HashError {
    #[error("not enough free memory to hash a password right now; try again shortly")]
    Busy,
    #[error("hashing password: {0}")]
    Failed(String),
}

/// The policy in force, with a stand-in hash that unknown usernames are
/// checked against so they take as long as real ones.
pub struct Passwords {
    active: RwLock<(Policy, String)>,
    /// Two permits; a check takes both when only one may run at a time.
    gate: tokio::sync::Semaphore,
}

impl Passwords {
    pub fn new(policy: Policy) -> Result<Passwords> {
        let dummy = hash_with(&random_hex(16), &policy)?;
        Ok(Passwords { active: RwLock::new((policy, dummy)), gate: tokio::sync::Semaphore::new(2) })
    }

    pub fn policy(&self) -> Policy {
        self.active.read().unwrap().0
    }

    /// Switch to a newly tuned policy.
    pub fn replace(&self, policy: Policy) -> Result<()> {
        let dummy = hash_with(&random_hex(16), &policy)?;
        *self.active.write().unwrap() = (policy, dummy);
        Ok(())
    }

    /// Wait (up to `wait`) for a turn to check or hash a password.
    pub async fn turn(&self, wait: Duration) -> Option<tokio::sync::SemaphorePermit<'_>> {
        let n = if self.policy().concurrency >= 2 { 1 } else { 2 };
        tokio::time::timeout(wait, self.gate.acquire_many(n)).await.ok()?.ok()
    }

    pub fn hash(&self, password: &str) -> std::result::Result<String, HashError> {
        hash_with(password, &self.policy()).map_err(|e| match e.downcast_ref::<HashError>() {
            Some(HashError::Busy) => HashError::Busy,
            _ => HashError::Failed(format!("{e:#}")),
        })
    }

    /// Check `password` against a saved hash; with no saved hash (unknown
    /// user) the stand-in is checked instead and the answer is `Wrong`.
    pub fn check(&self, password: &str, phc: Option<&str>) -> Check {
        let (policy, dummy) = self.active.read().unwrap().clone();
        match phc {
            Some(phc) => check_with(password, phc, &policy),
            None => match check_with(password, &dummy, &policy) {
                Check::Busy => Check::Busy,
                _ => Check::Wrong,
            },
        }
    }
}

fn hash_with(password: &str, policy: &Policy) -> Result<String> {
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, policy.params()?);
    match a.hash_password(password.as_bytes()) {
        Ok(h) => Ok(h.to_string()),
        Err(argon2::password_hash::Error::OutOfMemory) => Err(HashError::Busy.into()),
        Err(e) => Err(HashError::Failed(e.to_string())).context("hashing password"),
    }
}

fn check_with(password: &str, phc: &str, policy: &Policy) -> Check {
    let Ok(hash) = PasswordHash::new(phc) else {
        tracing::warn!("a saved password hash is unreadable");
        return Check::Wrong;
    };
    let Ok(saved) = Params::try_from(&hash) else { return Check::Wrong };
    if saved.m_cost() > SANE_M {
        tracing::warn!("a saved password hash asks for {} MiB; refusing it", saved.m_cost() / KIB_PER_MIB);
        return Check::Wrong;
    }
    match Argon2::default().verify_password(password.as_bytes(), &hash) {
        Ok(()) => Check::Good {
            rehash: hash.algorithm.as_str() != "argon2id"
                || hash.version != Some(Version::V0x13.into())
                || saved.m_cost() != policy.m_kib
                || saved.t_cost() != policy.t
                || saved.p_cost() != policy.p,
        },
        Err(argon2::password_hash::Error::OutOfMemory) => Check::Busy,
        Err(_) => Check::Wrong,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1 << 30;
    const MIB: u64 = 1 << 20;

    fn mem(total: u64, available: u64) -> Option<Memory> {
        Some(Memory { total, available })
    }

    #[test]
    fn memory_follows_the_machine() {
        // 16 GB, mostly free: 2 % = 327 MiB, two checks of 163 MiB.
        assert_eq!(plan_memory(mem(16 * GIB, 12 * GIB)), (163 * KIB_PER_MIB + 860, 2));
        // 64 GB: capped at 256 MiB each.
        assert_eq!(plan_memory(mem(64 * GIB, 60 * GIB)), (CAP_M, 2));
        // Busy 8 GB machine: 10 % of 1 GiB free = 102 MiB, two of 51 MiB.
        assert_eq!(plan_memory(mem(8 * GIB, GIB)).1, 2);
        assert_eq!(plan_memory(mem(8 * GIB, GIB)).0 / KIB_PER_MIB, 51);
        // 2 GB Pi: 41 MiB is too little to share, so one check at a time.
        assert_eq!(plan_memory(mem(2 * GIB, 1500 * MIB)), (40 * KIB_PER_MIB + 983, 1));
        // 512 MB: never below the floor.
        assert_eq!(plan_memory(mem(512 * MIB, 200 * MIB)), (FLOOR_M, 1));
        assert_eq!(plan_memory(None), (FLOOR_M, 1));
    }

    #[test]
    fn passes_meet_owasp_and_the_time_target() {
        assert_eq!(pick_t(FLOOR_M, 40.0), 9); // fast machine: more passes
        assert_eq!(pick_t(FLOOR_M, 300.0), 2); // never below 2 under 46 MiB
        assert_eq!(pick_t(CAP_M, 600.0), 1);
        assert_eq!(pick_t(CAP_M, 120.0), 3);
        assert_eq!(pick_t(CAP_M, 1.0), MAX_T);
    }

    #[test]
    fn retunes_only_on_a_real_memory_change() {
        assert!(!ram_changed(16 * GIB, mem(15 * GIB, GIB)));
        assert!(ram_changed(16 * GIB, mem(8 * GIB, GIB)));
        assert!(ram_changed(0, mem(8 * GIB, GIB)));
        assert!(!ram_changed(16 * GIB, None));
    }

    fn quick() -> Policy {
        Policy { m_kib: FLOOR_M, t: 2, p: 1, concurrency: 2, ram_total: 0, check_ms: 0, tuned_ms: 0 }
    }

    #[test]
    fn hash_check_and_rehash() {
        let pw = Passwords::new(quick()).unwrap();
        let phc = pw.hash("correct horse").unwrap();
        assert!(phc.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "{phc}");
        assert_eq!(pw.check("correct horse", Some(&phc)), Check::Good { rehash: false });
        assert_eq!(pw.check("wrong", Some(&phc)), Check::Wrong);
        // Unknown user: the stand-in is checked, never accepted.
        assert_eq!(pw.check("correct horse", None), Check::Wrong);
        // Settings changed since: the right password asks to be rehashed.
        pw.replace(Policy { t: 3, ..quick() }).unwrap();
        assert_eq!(pw.check("correct horse", Some(&phc)), Check::Good { rehash: true });
        // Old argon2 defaults (19 MiB, t=2) from before tuning still sign in.
        let old = Argon2::default().hash_password(b"legacy").unwrap().to_string();
        assert!(matches!(pw.check("legacy", Some(&old)), Check::Good { .. }));
    }

    #[test]
    fn absurd_saved_settings_are_refused() {
        let pw = Passwords::new(quick()).unwrap();
        let huge = "$argon2id$v=19$m=4194304,t=1,p=1$c29tZXNhbHRzb21lc2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g";
        assert_eq!(pw.check("x", Some(huge)), Check::Wrong);
        assert_eq!(pw.check("x", Some("not a hash")), Check::Wrong);
    }

    #[test]
    fn tuning_meets_the_floor() {
        let p = tune(mem(GIB, 512 * MIB)).unwrap();
        assert!(p.valid(), "{p:?}");
        assert_eq!(p.concurrency, 1);
    }
}
