//! Share links: read-only (optionally "can add destinations") access to a
//! chosen set of targets via an unguessable URL, without signing in.
//!
//! Visitors use `/s/<token>` (the normal web UI in share mode) and the
//! `/api/s/<token>/…` endpoints below.
//!
//! Protection against abuse, since anyone with a link (a public forum, say)
//! can call these endpoints:
//! - link codes are checked against an in-memory list first, so made-up codes
//!   never touch the database, and addresses that keep guessing are blocked;
//! - every visitor address and every link has its own request budget, and
//!   expensive requests (long time ranges) cost more of it;
//! - time ranges, end times and point counts are rounded to a few values, so
//!   visitors share cached answers and can't force endless distinct queries;
//! - visitors' reads use their own database connection, so the owner's web
//!   UI and terminal UI never wait for them.

use axum::body::Body;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch};
use axum::{Json, Router};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

use crate::analysis::{self, Privacy, Scope};
use crate::config::now_ms;
use crate::engine::resolve;
use crate::model::*;
use crate::netpolicy;
use crate::pages::Visitor;
use crate::report::{self, ReportRequest};
use crate::server::{client_ip, status_response, valid_host, ApiError, ApiResult, St};
use crate::store::{blocking, blocking_share, Store};

const LIVE_TTL: Duration = Duration::from_secs(2);
const HISTORY_TTL: Duration = Duration::from_secs(15);
/// Per link: burst and sustained budget for uncached work.
const LINK_BURST: f64 = 40.0;
const LINK_REFILL: f64 = 10.0;
/// Per visitor address: burst and sustained budget for all requests.
const ADDR_BURST: f64 = 60.0;
const ADDR_REFILL: f64 = 10.0;
/// Made-up link codes allowed per address in `MISS_WINDOW` before it is
/// blocked for `MISS_BLOCK`.
const MISS_LIMIT: u32 = 20;
const MISS_WINDOW: Duration = Duration::from_secs(600);
const MISS_BLOCK: Duration = Duration::from_secs(900);
const REPORT_COOLDOWN: Duration = Duration::from_secs(10);
/// Time windows visitors can ask for (the web UI's choices).
const WINDOWS: [i64; 9] = [300_000, 600_000, 1_800_000, 3_600_000, 10_800_000, 21_600_000, 86_400_000, 604_800_000, 2_592_000_000];
/// Point counts visitors can ask for.
const POINTS: [usize; 10] = [1600, 1200, 1000, 800, 600, 400, 300, 200, 120, 60];

/// A cached response body: stored at, time to live, bytes.
type CacheEntry = (Instant, Duration, Vec<u8>);

#[derive(Debug, Clone, Copy)]
struct Misses {
    count: u32,
    since: Instant,
    blocked_until: Option<Instant>,
}

/// Runtime state for share links, kept in the server's AppState.
pub struct ShareState {
    cache: Mutex<HashMap<String, CacheEntry>>,
    link_budget: Mutex<HashMap<i64, (f64, Instant)>>,
    addr_budget: Mutex<HashMap<IpAddr, (f64, Instant)>>,
    misses: Mutex<HashMap<IpAddr, Misses>>,
    /// Every link code that exists, with its link's id.
    tokens: RwLock<Option<HashMap<String, i64>>>,
    last_seen: Mutex<HashMap<i64, Instant>>,
    last_report: Mutex<HashMap<i64, Instant>>,
    /// Share computations never take more than this many blocking threads,
    /// so a busy link can't starve monitoring.
    work: Semaphore,
    reports: Semaphore,
}

impl Default for ShareState {
    fn default() -> Self {
        ShareState {
            cache: Mutex::new(HashMap::new()),
            link_budget: Mutex::new(HashMap::new()),
            addr_budget: Mutex::new(HashMap::new()),
            misses: Mutex::new(HashMap::new()),
            tokens: RwLock::new(None),
            last_seen: Mutex::new(HashMap::new()),
            last_report: Mutex::new(HashMap::new()),
            work: Semaphore::new(2),
            reports: Semaphore::new(1),
        }
    }
}

pub(crate) fn take<K: std::hash::Hash + Eq>(budget: &mut HashMap<K, (f64, Instant)>, key: K, burst: f64, refill: f64, cost: f64) -> bool {
    let (tokens, at) = budget.entry(key).or_insert((burst, Instant::now()));
    *tokens = (*tokens + at.elapsed().as_secs_f64() * refill).min(burst);
    *at = Instant::now();
    if *tokens >= cost {
        *tokens -= cost;
        true
    } else {
        false
    }
}

impl ShareState {
    fn cached(&self, key: &str) -> Option<Vec<u8>> {
        let c = self.cache.lock().unwrap();
        c.get(key).filter(|(at, ttl, _)| at.elapsed() < *ttl).map(|(_, _, b)| b.clone())
    }

    fn store(&self, key: String, ttl: Duration, body: Vec<u8>) {
        let mut c = self.cache.lock().unwrap();
        if c.len() > 2000 {
            c.retain(|_, (at, ttl, _)| at.elapsed() < *ttl);
            if c.len() > 2000 {
                c.clear();
            }
        }
        c.insert(key, (Instant::now(), ttl, body));
    }

    /// Drop cached responses for one link (after something about it changed).
    pub(crate) fn invalidate(&self, share_id: i64) {
        let prefix = format!("{share_id}|");
        self.cache.lock().unwrap().retain(|k, _| !k.starts_with(&prefix));
    }

    /// Spend `cost` from a link's budget for uncached work.
    fn allow(&self, share_id: i64, cost: f64) -> bool {
        take(&mut self.link_budget.lock().unwrap(), share_id, LINK_BURST, LINK_REFILL, cost)
    }

    /// Spend `cost` from a visitor address's budget.
    fn allow_addr(&self, ip: IpAddr, cost: f64) -> bool {
        let mut b = self.addr_budget.lock().unwrap();
        if b.len() > 50_000 {
            // Full budgets carry no information: forget them.
            b.retain(|_, (_, at)| at.elapsed() < Duration::from_secs(10));
        }
        take(&mut b, ip, ADDR_BURST, ADDR_REFILL, cost)
    }

    fn blocked(&self, ip: IpAddr) -> bool {
        self.misses
            .lock()
            .unwrap()
            .get(&ip)
            .and_then(|m| m.blocked_until)
            .is_some_and(|until| Instant::now() < until)
    }

    /// Note a made-up link code from `ip`.
    fn miss(&self, ip: IpAddr) {
        let mut m = self.misses.lock().unwrap();
        if m.len() > 50_000 {
            m.retain(|_, v| v.blocked_until.is_some_and(|u| Instant::now() < u) || v.since.elapsed() < MISS_WINDOW);
        }
        let e = m.entry(ip).or_insert(Misses { count: 0, since: Instant::now(), blocked_until: None });
        if e.since.elapsed() > MISS_WINDOW {
            *e = Misses { count: 0, since: Instant::now(), blocked_until: None };
        }
        e.count += 1;
        if e.count >= MISS_LIMIT {
            e.blocked_until = Some(Instant::now() + MISS_BLOCK);
            tracing::warn!("share links: blocking {ip} for {} min after {} unknown link codes", MISS_BLOCK.as_secs() / 60, e.count);
        }
    }

    /// Reload the list of link codes (after links are created or changed).
    pub async fn reload(&self, store: &std::sync::Arc<Store>) {
        match blocking(store, |s| s.list_shares()).await {
            Ok(list) => {
                let map = list.into_iter().map(|s| (s.token, s.id)).collect();
                *self.tokens.write().unwrap() = Some(map);
            }
            Err(e) => tracing::warn!("loading share links failed: {e:#}"),
        }
    }

    fn token_id(&self, token: &str) -> Option<Option<i64>> {
        self.tokens.read().unwrap().as_ref().map(|m| m.get(token).copied())
    }
}

pub fn routes() -> Router<St> {
    Router::new()
        .route("/s/{token}", get(page))
        .route("/api/s/{token}/info", get(info))
        .route("/api/s/{token}/overview", get(overview))
        .route("/api/s/{token}/targets", axum::routing::post(add_target))
        .route("/api/s/{token}/targets/{id}", patch(patch_target).delete(delete_target))
        .route("/api/s/{token}/targets/{id}/detail", get(detail))
        .route("/api/s/{token}/report", get(report_handler))
}

/// The router for the share-only listener: share pages and their assets,
/// nothing else.
pub fn public_router(state: St) -> Router {
    Router::new()
        .route("/", get(not_here))
        .merge(crate::server::static_routes())
        .merge(routes())
        .fallback(not_here)
        .with_state(state)
        .layer(axum::extract::DefaultBodyLimit::max(16 * 1024))
        .layer(axum::middleware::from_fn(crate::http::harden))
}

async fn not_here(uri: axum::http::Uri) -> Response {
    if uri.path().starts_with("/api/") {
        return ApiError::not_found().into_response();
    }
    status_response(
        StatusCode::NOT_FOUND,
        "Destination unreachable",
        "This address only opens pingrail share links. Check that you copied the whole link.",
        None,
    )
}

/// A share link's page. The link is checked first, so a made-up, switched-off
/// or expired link gets a page that says so (and made-up codes count towards
/// blocking an address that guesses), and a working link gets a page with
/// only the controls it allows.
async fn page(
    State(st): State<St>,
    Path(token): Path<String>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let refused = |e: ApiError| match e.0 {
        StatusCode::NOT_FOUND => status_response(e.0, "Destination unreachable", &e.1, None),
        StatusCode::GONE => status_response(e.0, "This link has ended", &e.1, None),
        StatusCode::TOO_MANY_REQUESTS => status_response(e.0, "Slow down", &e.1, None),
        _ => status_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "This monitor can't open the link right now",
            "Try again in a minute.",
            None,
        ),
    };
    let ip = match admit(&st, peer, &headers, 1.0) {
        Ok(ip) => ip,
        Err(e) => return refused(e),
    };
    let share = match load(&st, &token, ip).await {
        Ok(s) => s,
        Err(e) => return refused(e),
    };
    let v = Visitor { add: share.settings.can_add, export: share.settings.can_export };
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8"), (header::CACHE_CONTROL, "no-store")],
        crate::pages::pages().share_html(v),
    )
        .into_response()
}

fn json_bytes(body: Vec<u8>) -> Response {
    ([(header::CONTENT_TYPE, HeaderValue::from_static("application/json"))], body).into_response()
}

fn limited() -> ApiError {
    ApiError(StatusCode::TOO_MANY_REQUESTS, "Too many requests on this link. Wait a few seconds and try again.".into())
}

fn invalid() -> ApiError {
    ApiError(StatusCode::NOT_FOUND, "This link isn't valid. Check that you copied all of it, or ask for a new one.".into())
}

/// The visitor's address, after checking it isn't blocked or over budget.
fn admit(st: &St, peer: SocketAddr, headers: &HeaderMap, cost: f64) -> ApiResult<IpAddr> {
    let ip = client_ip(st, peer, headers);
    if st.share.blocked(ip) {
        return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "Too many invalid links from your address. Try again later.".into()));
    }
    if !st.share.allow_addr(ip, cost) {
        return Err(limited());
    }
    Ok(ip)
}

/// Look up a link and refuse it if it's unknown, revoked or expired.
async fn load(st: &St, token: &str, ip: IpAddr) -> ApiResult<Share> {
    if token.len() < 16 || token.len() > 128 || !token.chars().all(|c| c.is_ascii_alphanumeric()) {
        st.share.miss(ip);
        return Err(invalid());
    }
    if st.share.token_id(token).is_none() {
        st.share.reload(&st.store).await;
    }
    let Some(Some(id)) = st.share.token_id(token) else {
        st.share.miss(ip);
        return Err(invalid());
    };
    let share = blocking_share(&st.store, move |s| s.get_share(id)).await?;
    let share = match share {
        Some(s) if s.token == token => s,
        _ => {
            // Changed since the list was loaded (new link made, say).
            st.share.reload(&st.store).await;
            st.share.miss(ip);
            return Err(invalid());
        }
    };
    let now = now_ms();
    if share.revoked {
        return Err(ApiError(StatusCode::GONE, "This link has been switched off by the person who shared it.".into()));
    }
    if !share.is_active(now) {
        let when = share
            .settings
            .expires_ms
            .map(|e| crate::util::fmt_local(e, "%-d %b %Y %H:%M"))
            .unwrap_or_default();
        return Err(ApiError(StatusCode::GONE, format!("This link expired on {when}. Ask the person who shared it for a new one.")));
    }
    Ok(share)
}

fn scope(share: &Share, now: i64) -> Scope {
    Scope {
        ids: Some(share.visible_ids()),
        earliest_ms: share.earliest_ms(now),
        privacy: Privacy {
            hide_private: share.settings.hide_private,
            hide_public_hops: share.settings.hide_public_hops,
            hide_hostnames: share.settings.hide_hostnames,
        },
    }
}

/// Record that the link was used (a "view" for page loads; otherwise just
/// last-seen, written at most once a minute).
async fn touch(st: &St, share: &Share, ip: IpAddr, view: bool) {
    if !view {
        let mut seen = st.share.last_seen.lock().unwrap();
        if seen.get(&share.id).is_some_and(|at| at.elapsed() < Duration::from_secs(60)) {
            return;
        }
        seen.insert(share.id, Instant::now());
    }
    let id = share.id;
    let ip = ip.to_string();
    let _ = blocking(&st.store, move |s| s.touch_share(id, Some(&ip), view)).await;
}

/// The nearest window visitors may use.
fn norm_window(w: Option<i64>) -> i64 {
    let w = w.unwrap_or(600_000).max(1) as f64;
    *WINDOWS
        .iter()
        .min_by(|a, b| (w / **a as f64).ln().abs().total_cmp(&(w / **b as f64).ln().abs()))
        .expect("non-empty")
}

/// The largest allowed point count not above `n`.
fn norm_points(n: Option<usize>) -> usize {
    let n = n.unwrap_or(400);
    POINTS.into_iter().find(|p| n >= *p).unwrap_or(60)
}

/// End times snap to a hundredth of the window: panning looks the same,
/// but there are only so many distinct views to compute.
fn snap_end(end: i64, window: i64) -> i64 {
    let grid = (window / 100).max(1000);
    end.div_euclid(grid) * grid
}

/// Budget cost of computing a view: long ranges read much more data.
fn cost_of(window: i64) -> f64 {
    1.0 + (window / 86_400_000) as f64
}

#[derive(Deserialize)]
struct InfoQuery {
    /// Set by the page when it re-checks the link; doesn't count as a view.
    refresh: Option<u8>,
}

async fn info(
    State(st): State<St>,
    Path(token): Path<String>,
    Query(q): Query<InfoQuery>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> ApiResult<Json<ShareVisit>> {
    let ip = admit(&st, peer, &headers, 1.0)?;
    let share = load(&st, &token, ip).await?;
    if q.refresh.is_some() && !st.share.allow(share.id, 0.5) {
        return Err(limited());
    }
    touch(&st, &share, ip, q.refresh.is_none()).await;
    let now = now_ms();
    Ok(Json(ShareVisit {
        can_add: share.settings.can_add,
        max_targets: share.settings.max_targets,
        owned_ids: share.owned_ids.clone(),
        can_export: share.settings.can_export,
        expires_ms: share.settings.expires_ms,
        earliest_ms: share.earliest_ms(now),
        hide_private: share.settings.hide_private,
        hide_public_hops: share.settings.hide_public_hops,
        hide_hostnames: share.settings.hide_hostnames,
        min_interval_ms: share.settings.min_interval_ms,
        thresholds: st.cfg.thresholds,
    }))
}

#[derive(Deserialize)]
struct OverviewQuery {
    window_ms: Option<i64>,
}

async fn overview(
    State(st): State<St>,
    Path(token): Path<String>,
    Query(q): Query<OverviewQuery>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let ip = admit(&st, peer, &headers, 1.0)?;
    let share = load(&st, &token, ip).await?;
    touch(&st, &share, ip, false).await;
    let window = norm_window(q.window_ms);
    let key = format!("{}|ov|{window}", share.id);
    if let Some(b) = st.share.cached(&key) {
        return Ok(json_bytes(b));
    }
    let cost = cost_of(window);
    if !st.share.allow(share.id, cost) || !st.share.allow_addr(ip, cost - 1.0) {
        return Err(limited());
    }
    let _permit = st.share.work.acquire().await.map_err(|e| anyhow::anyhow!(e))?;
    let engine = st.engine.clone();
    let thresholds = st.cfg.thresholds;
    let now = now_ms();
    let sc = scope(&share, now);
    let ov = blocking_share(&st.store, move |s| {
        analysis::overview_scoped(s, &|id| engine.live(id), thresholds, now, window, 40, &sc)
    })
    .await?;
    let body = serde_json::to_vec(&ov).map_err(anyhow::Error::from)?;
    st.share.store(key, LIVE_TTL, body.clone());
    Ok(json_bytes(body))
}

#[derive(Deserialize)]
struct DetailQuery {
    window_ms: Option<i64>,
    /// End of the viewed range; omitted = live.
    end_ms: Option<i64>,
    #[serde(alias = "buckets")]
    points: Option<usize>,
    hop: Option<u8>,
}

async fn detail(
    State(st): State<St>,
    Path((token, id)): Path<(String, i64)>,
    Query(q): Query<DetailQuery>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let ip = admit(&st, peer, &headers, 1.0)?;
    let share = load(&st, &token, ip).await?;
    if !share.visible_ids().contains(&id) {
        return Err(ApiError::not_found());
    }
    let window = norm_window(q.window_ms);
    let points = norm_points(q.points);
    let now = now_ms();
    let end = q.end_ms.map(|e| snap_end(e.min(now), window));
    let key = format!("{}|d|{id}|{window}|{end:?}|{points}|{:?}", share.id, q.hop);
    if let Some(b) = st.share.cached(&key) {
        return Ok(json_bytes(b));
    }
    let cost = cost_of(window);
    if !st.share.allow(share.id, cost) || !st.share.allow_addr(ip, cost - 1.0) {
        return Err(limited());
    }
    let _permit = st.share.work.acquire().await.map_err(|e| anyhow::anyhow!(e))?;
    let to = end.unwrap_or(now + 1);
    let from = to - window;
    let sc = scope(&share, now);
    let live_status = st.engine.live(id);
    let rdns = st.engine.rdns.clone();
    let hop = q.hop;
    let thresholds = st.cfg.thresholds;
    let d = blocking_share(&st.store, move |s| {
        let Some(t) = s.get_target(id)? else { return Ok(None) };
        analysis::detail_scoped(s, t, live_status, Some(&rdns), from, to, points, hop, thresholds, &sc).map(Some)
    })
    .await?
    .ok_or_else(ApiError::not_found)?;
    let body = serde_json::to_vec(&d).map_err(anyhow::Error::from)?;
    st.share.store(key, if end.is_none() { LIVE_TTL } else { HISTORY_TTL }, body.clone());
    Ok(json_bytes(body))
}

#[derive(Deserialize)]
struct NewVisitorTarget {
    host: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    interval_ms: Option<u32>,
    #[serde(default)]
    trace: Option<bool>,
}

async fn add_target(
    State(st): State<St>,
    Path(token): Path<String>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<NewVisitorTarget>,
) -> ApiResult<Json<Target>> {
    let ip = admit(&st, peer, &headers, 5.0)?;
    let share = load(&st, &token, ip).await?;
    if !share.settings.can_add {
        return Err(ApiError(StatusCode::FORBIDDEN, "This link doesn't allow adding destinations.".into()));
    }
    if share.owned_ids.len() as u32 >= share.settings.max_targets {
        return Err(ApiError::bad(format!(
            "This link allows up to {} destinations. Remove one before adding another.",
            share.settings.max_targets
        )));
    }
    if !st.share.allow(share.id, 5.0) {
        return Err(limited());
    }
    let host = req.host.trim().to_string();
    if !valid_host(&host) {
        return Err(ApiError::bad("Enter a host name or IP address."));
    }
    let name = req.name.map(|n| crate::util::clean_text(&n, 64)).filter(|n| !n.is_empty());
    let ip_dest = match tokio::time::timeout(Duration::from_secs(5), resolve(&host)).await {
        Ok(Ok(ip)) => ip,
        Ok(Err(e)) => return Err(ApiError::bad(format!("Can't resolve {host}: {e}"))),
        Err(_) => return Err(ApiError::bad(format!("Timed out resolving {host}."))),
    };
    let allow = share.settings.allow_private.clone();
    if !netpolicy::destination_allowed(ip_dest, &allow) {
        let what = if host == ip_dest.to_string() { host.clone() } else { format!("{host} ({ip_dest})") };
        return Err(ApiError::bad(format!(
            "{what} is a private or reserved address. This link only allows public destinations."
        )));
    }
    let min = share.settings.min_interval_ms.max(250);
    let interval = req.interval_ms.unwrap_or(st.cfg.probe.interval_ms.max(min)).clamp(min, 3_600_000);
    let nt = NewTarget { host, name, interval_ms: Some(interval), trace: Some(req.trace.unwrap_or(true)), session: None };
    let share_id = share.id;
    let default_interval = st.cfg.probe.interval_ms;
    let t = blocking(&st.store, move |s| s.add_target_owned(&nt, default_interval, Some(share_id), Some(&allow))).await?;
    st.engine.sync().await?;
    st.share.invalidate(share.id);
    tracing::info!("share link {} ({}) added target {} ({}) from {ip}", share.id, share.settings.label, t.id, t.host);
    Ok(Json(analysis::public_target(t)))
}

#[derive(Deserialize)]
struct VisitorPatch {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    interval_ms: Option<u32>,
    #[serde(default)]
    trace: Option<bool>,
}

async fn patch_target(
    State(st): State<St>,
    Path((token, id)): Path<(String, i64)>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(p): Json<VisitorPatch>,
) -> ApiResult<Json<Target>> {
    let ip = admit(&st, peer, &headers, 2.0)?;
    let share = load(&st, &token, ip).await?;
    if !share.settings.can_add {
        return Err(ApiError(StatusCode::FORBIDDEN, "This link doesn't allow changing destinations.".into()));
    }
    if !share.owned_ids.contains(&id) {
        return Err(ApiError(StatusCode::FORBIDDEN, "You can only change destinations added through this link.".into()));
    }
    if !st.share.allow(share.id, 2.0) {
        return Err(limited());
    }
    let min = share.settings.min_interval_ms.max(250);
    let patch = TargetPatch {
        name: p.name.map(|n| crate::util::clean_text(&n, 64)),
        enabled: p.enabled,
        trace: p.trace,
        interval_ms: p.interval_ms.map(|i| i.clamp(min, 3_600_000)),
        session: None,
    };
    let t = blocking(&st.store, move |s| s.update_target(id, &patch)).await?.ok_or_else(ApiError::not_found)?;
    st.engine.sync().await?;
    st.share.invalidate(share.id);
    Ok(Json(analysis::public_target(t)))
}

async fn delete_target(
    State(st): State<St>,
    Path((token, id)): Path<(String, i64)>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    let ip = admit(&st, peer, &headers, 2.0)?;
    let share = load(&st, &token, ip).await?;
    if !share.settings.can_add {
        return Err(ApiError(StatusCode::FORBIDDEN, "This link doesn't allow removing destinations.".into()));
    }
    if !share.owned_ids.contains(&id) {
        return Err(ApiError(StatusCode::FORBIDDEN, "You can only remove destinations added through this link.".into()));
    }
    if !st.share.allow(share.id, 2.0) {
        return Err(limited());
    }
    blocking(&st.store, move |s| s.delete_target(id)).await?;
    st.engine.sync().await?;
    st.share.invalidate(share.id);
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct ReportQuery {
    targets: Option<String>,
    from: i64,
    to: i64,
    format: Option<String>,
    tz: Option<i32>,
}

async fn report_handler(
    State(st): State<St>,
    Path(token): Path<String>,
    Query(q): Query<ReportQuery>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let ip = admit(&st, peer, &headers, 10.0)?;
    let share = load(&st, &token, ip).await?;
    if !share.settings.can_export {
        return Err(ApiError(StatusCode::FORBIDDEN, "This link doesn't allow downloading reports.".into()));
    }
    {
        let mut last = st.share.last_report.lock().unwrap();
        if last.get(&share.id).is_some_and(|at| at.elapsed() < REPORT_COOLDOWN) {
            return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "A report was just made from this link. Try again in a few seconds.".into()));
        }
        last.insert(share.id, Instant::now());
    }
    let format = match q.format.as_deref().unwrap_or("pdf") {
        "pdf" => ReportFormat::Pdf,
        "png" => ReportFormat::Png,
        _ => return Err(ApiError::bad("format must be pdf or png")),
    };
    let now = now_ms();
    let sc = scope(&share, now);
    let to = q.to.min(now + 1);
    let from = sc.clamp_from(q.from).max(to - 90 * 86_400_000);
    if from >= to {
        return Err(ApiError::bad("There's no data this link can show in that time range."));
    }
    let visible = share.visible_ids();
    let ids: Vec<i64> = match q.targets.as_deref() {
        None | Some("") | Some("all") => visible.clone(),
        Some(list) => list.split(',').filter_map(|x| x.trim().parse().ok()).filter(|i| visible.contains(i)).collect(),
    };
    if ids.is_empty() {
        return Err(ApiError::bad("Choose at least one target."));
    }
    let _permit = st.share.reports.acquire().await.map_err(|e| anyhow::anyhow!(e))?;
    let req = ReportRequest { target_ids: ids, from_ms: from, to_ms: to, tz_offset_min: q.tz.unwrap_or(0).clamp(-840, 840), format };
    let fname = report::file_name(&req);
    let rdns = st.engine.rdns.clone();
    let thresholds = st.cfg.thresholds;
    let bytes = blocking_share(&st.store, move |s| report::render(s, Some(&rdns), thresholds, &req, &sc)).await?;
    Ok((
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(format.mime())),
            (
                header::CONTENT_DISPOSITION,
                HeaderValue::from_str(&format!("attachment; filename=\"{fname}\"")).unwrap_or(HeaderValue::from_static("attachment")),
            ),
        ],
        Body::from(bytes),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_are_normalised() {
        assert_eq!(norm_points(Some(5000)), 1600);
        assert_eq!(norm_points(Some(745)), 600);
        assert_eq!(norm_points(Some(10)), 60);
        assert_eq!(norm_window(Some(600_000)), 600_000);
        assert_eq!(norm_window(Some(700_000)), 600_000);
        assert_eq!(norm_window(Some(1)), 300_000);
        assert_eq!(norm_window(Some(i64::MAX)), 2_592_000_000);
        // End times on a grid of 1/100 of the window: 6 s for 10 minutes.
        assert_eq!(snap_end(1_000_005_999, 600_000), 1_000_002_000);
        assert_eq!(snap_end(1_000_008_000, 600_000), 1_000_008_000);
        assert_eq!(cost_of(600_000), 1.0);
        assert_eq!(cost_of(2_592_000_000), 31.0);
    }

    #[test]
    fn budgets() {
        let s = ShareState::default();
        let ok = (0..100).filter(|_| s.allow(1, 1.0)).count();
        assert!((40..=41).contains(&ok), "link burst allowed {ok}");
        assert!(s.allow(2, 1.0), "links have separate budgets");
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let ok = (0..200).filter(|_| s.allow_addr(ip, 1.0)).count();
        assert!((60..=61).contains(&ok), "address burst allowed {ok}");
        assert!(s.allow_addr("203.0.113.10".parse().unwrap(), 1.0));
    }

    #[test]
    fn guessing_codes_gets_an_address_blocked() {
        let s = ShareState::default();
        let ip: IpAddr = "198.51.100.7".parse().unwrap();
        for _ in 0..MISS_LIMIT - 1 {
            s.miss(ip);
        }
        assert!(!s.blocked(ip));
        s.miss(ip);
        assert!(s.blocked(ip));
        assert!(!s.blocked("198.51.100.8".parse().unwrap()));
    }

    #[test]
    fn cache_expires_and_invalidates() {
        let s = ShareState::default();
        s.store("7|ov|1".into(), Duration::from_secs(60), b"x".to_vec());
        assert_eq!(s.cached("7|ov|1").as_deref(), Some(&b"x"[..]));
        s.invalidate(7);
        assert!(s.cached("7|ov|1").is_none());
        s.store("8|ov|1".into(), Duration::from_millis(0), b"y".to_vec());
        assert!(s.cached("8|ov|1").is_none());
    }
}
