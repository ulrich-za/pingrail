//! The monitoring engine: one task per enabled target, each taking a sample
//! every interval. A sample pings the endpoint and, when route tracing is on,
//! probes every hop by sending echo requests with increasing TTLs (the
//! technique PingPlotter, mtr and WinMTR use).

use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Notify, Semaphore};
use tokio::task::{JoinHandle, JoinSet};

use crate::config::{now_ms, Config, ProbeConfig};
use crate::model::{LiveStatus, Target};
use crate::probe::{ProbeReply, ProbeSpec, Prober, ReplyKind, ENDPOINT_TTL};
use crate::store::{blocking, HopKind, HopRecord, RoundRecord, Store};

/// Route discovery state for one target.
#[derive(Debug, Default)]
struct RouteState {
    /// TTL at which the destination answered most recently.
    dest_ttl: Option<u8>,
    /// Consecutive samples where the endpoint answered but no hop up to
    /// `dest_ttl` did (route probably got longer).
    misses: u8,
}

/// What a running target task was started with: a change to any of it
/// (including a visitor target's allowed private ranges) restarts the task.
type TaskKey = (String, u32, bool, Option<Vec<String>>);

struct Running {
    key: TaskKey,
    handle: JoinHandle<()>,
}

fn task_key(t: &Target) -> TaskKey {
    (t.host.clone(), t.interval_ms, t.trace, t.restrict.clone())
}

struct Ctx {
    prober: Arc<Prober>,
    cfg: ProbeConfig,
    live: Arc<RwLock<HashMap<i64, LiveStatus>>>,
    tx: mpsc::UnboundedSender<RoundRecord>,
    guard: Arc<VisitorGuard>,
}

/// Pauses destinations added by share-link visitors when the disk is
/// nearly full or their link has used its storage limit. Your own targets
/// are never paused.
#[derive(Default)]
pub struct VisitorGuard {
    low_disk: AtomicBool,
    /// Links whose visitors' destinations reached the storage limit (MB).
    full: RwLock<HashMap<i64, u32>>,
}

impl VisitorGuard {
    fn reason(&self, share_id: i64) -> Option<String> {
        if self.low_disk.load(Ordering::Relaxed) {
            return Some("Paused: the monitor is low on disk space. The owner needs to free some up.".into());
        }
        self.full.read().unwrap().get(&share_id).map(|mb| {
            format!(
                "Paused: destinations added through this link have used their {} storage limit. \
                 They resume when older samples age out, or when the owner raises the limit.",
                fmt_mb(*mb)
            )
        })
    }
}

fn fmt_mb(mb: u32) -> String {
    if mb >= 1024 && mb % 1024 == 0 { format!("{} GB", mb / 1024) } else { format!("{mb} MB") }
}

pub struct Engine {
    store: Arc<Store>,
    ctx: Arc<Ctx>,
    tasks: tokio::sync::Mutex<HashMap<i64, Running>>,
    writer: Mutex<Option<JoinHandle<()>>>,
    pub rdns: Arc<Rdns>,
    storage_check: Arc<Notify>,
}

impl Engine {
    /// Start the engine and launch every enabled target.
    pub async fn start(store: Arc<Store>, prober: Arc<Prober>, cfg: &Config, data_dir: Option<PathBuf>) -> Result<Arc<Engine>> {
        let (tx, rx) = mpsc::unbounded_channel();
        let writer = tokio::spawn(writer_loop(store.clone(), rx));
        let retention = cfg.storage.retention_days.max(1) as i64;
        let st = store.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_secs(3600));
            loop {
                iv.tick().await;
                let cutoff = now_ms() - retention * 86_400_000;
                match blocking(&st, move |s| s.prune(cutoff)).await {
                    Ok(n) if n > 0 => tracing::info!("pruned {n} old samples"),
                    Err(e) => tracing::warn!("prune failed: {e:#}"),
                    _ => {}
                }
            }
        });
        let guard = Arc::new(VisitorGuard::default());
        let storage_check = Arc::new(Notify::new());
        tokio::spawn(visitor_storage_loop(
            store.clone(),
            guard.clone(),
            storage_check.clone(),
            data_dir,
            cfg.storage.min_free_mb,
        ));
        let engine = Arc::new(Engine {
            store,
            ctx: Arc::new(Ctx {
                prober,
                cfg: cfg.probe.clone(),
                live: Arc::new(RwLock::new(HashMap::new())),
                tx,
                guard,
            }),
            tasks: tokio::sync::Mutex::new(HashMap::new()),
            writer: Mutex::new(Some(writer)),
            rdns: Arc::new(Rdns::new(cfg.probe.reverse_dns)),
            storage_check,
        });
        engine.sync().await?;
        Ok(engine)
    }

    /// Re-check visitors' storage limits now (after a link's settings change).
    pub fn recheck_visitor_storage(&self) {
        self.storage_check.notify_one();
    }

    /// Reconcile running tasks with the targets table.
    pub async fn sync(&self) -> Result<()> {
        let targets = blocking(&self.store, |s| s.list_targets()).await?;
        let mut tasks = self.tasks.lock().await;
        let wanted: HashMap<i64, &Target> =
            targets.iter().filter(|t| t.enabled).map(|t| (t.id, t)).collect();

        tasks.retain(|id, r| {
            let keep = wanted
                .get(id)
                .is_some_and(|t| r.key == task_key(t));
            if !keep {
                r.handle.abort();
            }
            keep
        });
        {
            let mut live = self.ctx.live.write().unwrap();
            live.retain(|id, _| wanted.contains_key(id));
        }
        for (id, t) in wanted {
            if tasks.contains_key(&id) {
                continue;
            }
            let handle = tokio::spawn(target_loop((*t).clone(), self.ctx.clone()));
            tasks.insert(id, Running { key: task_key(t), handle });
        }
        Ok(())
    }

    pub fn live(&self, id: i64) -> LiveStatus {
        self.ctx.live.read().unwrap().get(&id).cloned().unwrap_or_default()
    }

    /// Stop every target and flush pending samples to disk.
    pub async fn shutdown(&self) {
        for (_, r) in self.tasks.lock().await.drain() {
            r.handle.abort();
        }
        // Let in-flight samples finish and the writer flush its last batch.
        let wait = self.ctx.cfg.timeout_ms.min(1500) as u64 + 400;
        tokio::time::sleep(Duration::from_millis(wait)).await;
        let writer = self.writer.lock().unwrap().take();
        if let Some(w) = writer {
            w.abort();
        }
    }
}

/// Every minute: is the disk nearly full? Every five minutes (or when asked):
/// apply each link's retention to its visitors' destinations and check
/// their storage limit.
async fn visitor_storage_loop(
    store: Arc<Store>,
    guard: Arc<VisitorGuard>,
    wake: Arc<Notify>,
    data_dir: Option<PathBuf>,
    min_free_mb: u64,
) {
    let mut tick: u64 = 0;
    loop {
        let forced = tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(if tick == 0 { 5 } else { 60 })) => false,
            _ = wake.notified() => true,
        };
        if min_free_mb > 0
            && let Some(dir) = &data_dir
            && let Some(free) = crate::util::free_space(dir)
        {
            let low = free < min_free_mb * 1024 * 1024;
            if guard.low_disk.swap(low, Ordering::Relaxed) != low {
                if low {
                    tracing::warn!(
                        "only {} MB free (limit {min_free_mb} MB): pausing destinations added by share-link visitors",
                        free / 1024 / 1024
                    );
                } else {
                    tracing::info!("disk space recovered: share-link visitors' destinations resume");
                }
            }
        }
        if forced || tick % 5 == 0 {
            let now = now_ms();
            let r = blocking(&store, move |s| {
                let mut full = HashMap::new();
                for sh in s.list_shares()? {
                    if sh.owned_ids.is_empty() {
                        continue;
                    }
                    let days = sh.settings.visitor_retention_days;
                    if days > 0 {
                        s.prune_targets(&sh.owned_ids, now - days as i64 * 86_400_000)?;
                    }
                    let mb = sh.settings.visitor_storage_mb;
                    if mb > 0 && s.storage_used(&sh.owned_ids)? > mb as u64 * 1024 * 1024 {
                        full.insert(sh.id, mb);
                    }
                }
                Ok(full)
            })
            .await;
            match r {
                Ok(full) => {
                    let mut cur = guard.full.write().unwrap();
                    for (id, mb) in &full {
                        if !cur.contains_key(id) {
                            tracing::warn!("share link {id}: visitors' destinations reached the {} limit; pausing them", fmt_mb(*mb));
                        }
                    }
                    *cur = full;
                }
                Err(e) => tracing::warn!("checking visitors' storage failed: {e:#}"),
            }
        }
        tick += 1;
    }
}

async fn writer_loop(store: Arc<Store>, mut rx: mpsc::UnboundedReceiver<RoundRecord>) {
    let mut batch = Vec::new();
    loop {
        let Some(first) = rx.recv().await else { break };
        batch.push(first);
        let deadline = tokio::time::Instant::now() + Duration::from_millis(250);
        while batch.len() < 1000 {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(r)) => batch.push(r),
                _ => break,
            }
        }
        let rows = std::mem::take(&mut batch);
        if let Err(e) = blocking(&store, move |s| s.insert_rounds(&rows)).await {
            tracing::error!("writing samples failed: {e:#}");
        }
    }
}

/// Resolve a host, preferring IPv4 unless an IPv6 literal was given.
pub async fn resolve(host: &str) -> Result<IpAddr> {
    let h = host.trim().trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = h.parse::<IpAddr>() {
        return Ok(ip);
    }
    let addrs: Vec<IpAddr> = tokio::net::lookup_host((h, 0)).await?.map(|a| a.ip()).collect();
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .copied()
        .ok_or_else(|| anyhow::anyhow!("no addresses for {h}"))
}

async fn target_loop(t: Target, ctx: Arc<Ctx>) {
    let route = Arc::new(Mutex::new(RouteState::default()));
    let mut resolved: Option<(IpAddr, Instant)> = None;
    let mut ticker = tokio::time::interval(Duration::from_millis(t.interval_ms.max(250) as u64));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        let ts = now_ms();
        if let Some(sid) = t.share_id
            && let Some(why) = ctx.guard.reason(sid)
        {
            set_live(&ctx, t.id, |l| {
                l.error = Some(why);
                l.last_sample_ms = Some(ts);
            });
            continue;
        }
        let stale = resolved.is_none_or(|(_, at)| at.elapsed() > Duration::from_secs(300));
        if stale {
            match resolve(&t.host).await {
                Ok(ip) => {
                    if resolved.map(|r| r.0) != Some(ip) {
                        // New address: rediscover the route.
                        *route.lock().unwrap() = RouteState::default();
                    }
                    resolved = Some((ip, Instant::now()));
                }
                Err(e) => {
                    if resolved.is_none() {
                        set_live(&ctx, t.id, |l| {
                            l.error = Some(format!("cannot resolve {}: {e}", t.host));
                            l.last_sample_ms = Some(ts);
                        });
                        let _ = ctx.tx.send(RoundRecord { target_id: t.id, ts_ms: ts, interval_ms: t.interval_ms, rtt_us: None, hops: None });
                        continue;
                    }
                }
            }
        }
        let ip = resolved.expect("resolved").0;
        // Visitor-added targets may only probe public addresses (plus the
        // link's exceptions), checked on every resolution.
        if let Some(allow) = &t.restrict
            && !crate::netpolicy::destination_allowed(ip, allow)
        {
            set_live(&ctx, t.id, |l| {
                l.ip = Some(ip.to_string());
                l.error = Some(format!("{ip} is a private or reserved address, which this share link doesn't allow"));
                l.last_sample_ms = Some(ts);
            });
            continue;
        }
        tokio::spawn(sample(ctx.clone(), t.id, ip, ts, t.interval_ms, t.trace, route.clone()));
    }
}

fn set_live(ctx: &Ctx, id: i64, f: impl FnOnce(&mut LiveStatus)) {
    let mut live = ctx.live.write().unwrap();
    f(live.entry(id).or_default());
}

fn us(d: Duration) -> u32 {
    d.as_micros().min(u32::MAX as u128) as u32
}

async fn sample(ctx: Arc<Ctx>, id: i64, ip: IpAddr, ts: i64, interval_ms: u32, trace: bool, route: Arc<Mutex<RouteState>>) {
    let cfg = &ctx.cfg;
    let spec = |ttl: u8| ProbeSpec {
        dst: ip,
        ttl,
        timeout: Duration::from_millis(cfg.timeout_ms as u64),
        payload: cfg.packet_size,
    };

    let mut set: JoinSet<(u8, Result<Option<ProbeReply>>)> = JoinSet::new();
    let p = ctx.prober.clone();
    let endpoint_spec = spec(ENDPOINT_TTL);
    set.spawn(async move { (0, p.probe(endpoint_spec).await) });

    let max = if trace {
        let r = route.lock().unwrap();
        r.dest_ttl.unwrap_or(cfg.max_hops).min(cfg.max_hops).max(1)
    } else {
        0
    };
    for ttl in 1..=max {
        let p = ctx.prober.clone();
        let s = spec(ttl);
        let delay = Duration::from_millis(cfg.hop_stagger_ms as u64 * (ttl as u64 - 1));
        set.spawn(async move {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            (ttl, p.probe(s).await)
        });
    }

    let mut endpoint: Option<ProbeReply> = None;
    let mut error: Option<String> = None;
    let mut hops: Vec<HopRecord> = Vec::with_capacity(max as usize);
    while let Some(res) = set.join_next().await {
        let Ok((ttl, r)) = res else { continue };
        let reply = match r {
            Ok(v) => v,
            Err(e) => {
                if ttl == 0 || error.is_none() {
                    error = Some(e.to_string());
                }
                None
            }
        };
        if ttl == 0 {
            endpoint = reply.filter(|r| r.kind == ReplyKind::Echo);
        } else {
            hops.push(match reply {
                Some(r) => HopRecord {
                    ttl,
                    addr: Some(r.from),
                    rtt_us: Some(us(r.rtt)),
                    kind: match r.kind {
                        ReplyKind::Echo => HopKind::Echo,
                        ReplyKind::TimeExceeded => HopKind::TimeExceeded,
                        ReplyKind::Unreachable => HopKind::Unreachable,
                    },
                },
                None => HopRecord { ttl, addr: None, rtt_us: None, kind: HopKind::Timeout },
            });
        }
    }
    hops.sort_by_key(|h| h.ttl);

    let mut hop_count = None;
    if trace {
        let reached = hops
            .iter()
            .find(|h| h.kind == HopKind::Echo || (h.kind == HopKind::Unreachable && h.addr == Some(ip)))
            .map(|h| h.ttl);
        let mut r = route.lock().unwrap();
        match reached {
            Some(d) => {
                r.dest_ttl = Some(d);
                r.misses = 0;
                hops.truncate(d as usize);
            }
            None => {
                if r.dest_ttl.is_some() && endpoint.is_some() {
                    r.misses += 1;
                    if r.misses >= 3 {
                        r.dest_ttl = None;
                        r.misses = 0;
                    }
                }
                // Drop trailing silent hops beyond the last responder (+1).
                let last = hops.iter().rposition(|h| h.addr.is_some()).map_or(0, |i| i + 2);
                hops.truncate(last.max(1).min(hops.len()));
            }
        }
        hop_count = r.dest_ttl;
    }

    if endpoint.is_some() {
        error = None;
    }
    set_live(&ctx, id, |l| {
        l.ip = Some(ip.to_string());
        l.error = error;
        l.hop_count = hop_count;
        l.last_sample_ms = Some(ts);
    });
    let _ = ctx.tx.send(RoundRecord {
        target_id: id,
        ts_ms: ts,
        interval_ms,
        rtt_us: endpoint.map(|r| us(r.rtt)),
        hops: if trace { Some(hops) } else { None },
    });
}

/// Reverse-DNS names are chosen by whoever controls the address: keep only
/// clean, plausible host names.
fn clean_name(name: Option<String>) -> Option<String> {
    name.map(|n| crate::util::clean_text(&n, 253))
        .filter(|n| !n.is_empty() && n.parse::<IpAddr>().is_err())
}

/// Cached reverse-DNS lookups for hop addresses.
pub struct Rdns {
    enabled: bool,
    cache: Mutex<HashMap<IpAddr, (Option<String>, Instant)>>,
    inflight: Mutex<HashSet<IpAddr>>,
    sem: Arc<Semaphore>,
}

impl Rdns {
    pub fn new(enabled: bool) -> Rdns {
        Rdns {
            enabled,
            cache: Mutex::new(HashMap::new()),
            inflight: Mutex::new(HashSet::new()),
            sem: Arc::new(Semaphore::new(4)),
        }
    }

    fn remember(&self, ip: IpAddr, name: Option<String>) {
        let mut c = self.cache.lock().unwrap();
        // Visitors can add destinations whose routes cross many routers;
        // keep the cache bounded.
        if c.len() > 20_000 {
            c.retain(|_, (_, at)| at.elapsed() < Duration::from_secs(3600));
            if c.len() > 20_000 {
                c.clear();
            }
        }
        c.insert(ip, (name, Instant::now()));
    }

    /// Cached name for `ip`, looking it up synchronously on a miss
    /// (for use on blocking threads, e.g. while rendering a report).
    pub fn resolve_now(&self, ip: IpAddr) -> Option<String> {
        if !self.enabled {
            return None;
        }
        if let Some((name, at)) = self.cache.lock().unwrap().get(&ip)
            && at.elapsed() < Duration::from_secs(3600) {
                return name.clone();
            }
        let name = clean_name(dns_lookup::lookup_addr(&ip).ok());
        self.remember(ip, name.clone());
        name
    }

    /// Cached name for `ip`; starts a background lookup on a miss.
    pub fn get(self: &Arc<Self>, ip: IpAddr) -> Option<String> {
        if !self.enabled {
            return None;
        }
        if let Some((name, at)) = self.cache.lock().unwrap().get(&ip)
            && at.elapsed() < Duration::from_secs(3600) {
                return name.clone();
            }
        if !self.inflight.lock().unwrap().insert(ip) {
            return None;
        }
        let me = self.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _permit = me.sem.clone().acquire_owned().await;
                let name = clean_name(
                    tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip).ok()).await.ok().flatten(),
                );
                me.remember(ip, name);
                me.inflight.lock().unwrap().remove(&ip);
            });
        }
        None
    }
}
