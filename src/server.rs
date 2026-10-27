//! HTTP API and web UI.
//!
//! Authentication: either `Authorization: Bearer <api token>` (used by the TUI
//! and CLI on the same machine; the token lives in the service's data
//! directory) or a session cookie obtained by logging in with the web
//! username/password.

use anyhow::Result;
use axum::body::Body;
use axum::extract::{ConnectInfo, Path, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::analysis;
use crate::config::{now_ms, random_hex, Config};
use crate::engine::{resolve, Engine};
use crate::model::*;
use crate::password::{Check, HashError, Passwords};
use crate::report::{self, ReportRequest};
use crate::store::{blocking, Store};

/// The __Host- prefix makes browsers insist on Secure, Path=/ and no Domain.
const COOKIE: &str = "__Host-pr_session";
/// Password checks are deliberately expensive (see `password`), so only one
/// or two run at once, and sign-in attempts from everyone together are
/// rate-limited (burst, then per second), on top of the per-address
/// slow-down and lockout.
const LOGIN_BURST: f64 = 20.0;
const LOGIN_REFILL_PER_SEC: f64 = 0.5;
/// Failed sign-ins from one address within 15 minutes before it is refused
/// for 15 minutes, and how many addresses are tracked at most.
const LOGIN_LOCKOUT_FAILURES: u32 = 20;
const LOGIN_LOCKOUT: Duration = Duration::from_secs(900);
const LOGIN_TRACKED_MAX: usize = 10_000;
/// A TUI session that has not sent a heartbeat for this long is ended and
/// its foreground targets are paused.
const SESSION_TIMEOUT: Duration = Duration::from_secs(30);

pub struct AppState {
    pub store: Arc<Store>,
    pub engine: Arc<Engine>,
    pub cfg: Config,
    pub token: String,
    pub listen: String,
    tui_sessions: Mutex<HashMap<String, Instant>>,
    login_failures: Mutex<HashMap<IpAddr, (u32, Instant)>>,
    pub passwords: Passwords,
    pub ceremonies: crate::passkeys::Ceremonies,
    login_budget: Mutex<HashMap<(), (f64, Instant)>>,
    /// The certificate this service presents, and its authority.
    pub certs: Arc<crate::ca::Certs>,
    /// SHA-256 fingerprint of what clients pin (the authority).
    pub cert_sha256: String,
    pub share: crate::share::ShareState,
    /// Proxies whose forwarded-for headers are believed.
    pub trusted: Vec<(IpAddr, u8)>,
}

impl AppState {
    pub fn new(
        store: Arc<Store>,
        engine: Arc<Engine>,
        cfg: Config,
        token: String,
        listen: String,
        certs: Arc<crate::ca::Certs>,
        passwords: Passwords,
    ) -> Arc<AppState> {
        let cfg_trusted = cfg.share.trusted_proxies.clone();
        Arc::new(AppState {
            store,
            engine,
            cfg,
            token,
            listen,
            tui_sessions: Mutex::new(HashMap::new()),
            login_failures: Mutex::new(HashMap::new()),
            passwords,
            ceremonies: Default::default(),
            login_budget: Mutex::new(HashMap::new()),
            cert_sha256: crate::tls::fmt_fingerprint(&certs.pin()),
            certs,
            share: crate::share::ShareState::default(),
            trusted: crate::http::parse_nets(&cfg_trusted),
        })
    }
}

pub type St = Arc<AppState>;

#[derive(Clone, Debug)]
pub struct Principal {
    pub user: String,
    pub via: &'static str,
    /// When this user last signed in or confirmed it was them (ms).
    pub auth_ms: i64,
}

/// Changes to how you sign in need a sign-in within this long.
pub const RECENT_MS: i64 = 10 * 60_000;

impl Principal {
    /// Signed in recently enough to change sign-in settings (the API token
    /// always is: it's this machine).
    pub fn recent(&self) -> bool {
        self.via == "token" || now_ms() - self.auth_ms < RECENT_MS
    }
}

/// Refuse unless `p` signed in within the last ten minutes.
pub fn need_recent(p: &Principal) -> ApiResult<()> {
    if p.recent() {
        Ok(())
    } else {
        Err(ApiError(StatusCode::FORBIDDEN, "confirm it's you first".into()))
    }
}

#[derive(Debug)]
pub struct ApiError(pub StatusCode, pub String);

impl ApiError {
    pub fn bad(msg: impl Into<String>) -> Self {
        ApiError(StatusCode::BAD_REQUEST, msg.into())
    }
    pub fn not_found() -> Self {
        ApiError(StatusCode::NOT_FOUND, "not found".into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({ "error": self.1 }))).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        tracing::error!("request failed: {e:#}");
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}"))
    }
}

pub type ApiResult<T> = std::result::Result<T, ApiError>;

pub fn router(state: St) -> Router {
    let api = Router::new()
        .route("/api/me", get(me))
        .route("/api/logout", post(logout))
        .route("/api/password", post(set_password))
        .route("/api/password/tune", post(tune_passwords))
        .route("/api/overview", get(overview))
        .route("/api/targets", get(list_targets).post(add_target))
        .route("/api/targets/{id}", axum::routing::patch(patch_target).delete(delete_target))
        .route("/api/targets/{id}/detail", get(detail))
        .route("/api/report", get(report_handler))
        .route("/api/sessions", post(open_session))
        .route("/api/sessions/{id}/heartbeat", post(heartbeat))
        .route("/api/sessions/{id}", axum::routing::delete(end_session))
        .route("/api/certificate", get(certificate_info))
        .route("/api/certificate/names", post(add_certificate_name))
        .route("/api/qr", get(qr))
        .merge(crate::passkeys::auth_routes())
        .route("/api/shares", get(list_shares).post(create_share))
        .route("/api/shares/{id}", axum::routing::put(update_share).delete(delete_share))
        .route("/api/shares/{id}/regenerate", post(regenerate_share))
        .route("/api/shares/{id}/revoke", post(revoke_share))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth));

    Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/ca.crt", get(ca_crt))
        .merge(static_routes())
        .route("/api/health", get(health))
        .route("/api/ping", get(ping))
        .route("/api/login", post(login))
        .merge(crate::passkeys::routes())
        .merge(api)
        .merge(crate::share::routes())
        .fallback(not_found)
        .with_state(state)
        .layer(axum::extract::DefaultBodyLimit::max(64 * 1024))
        .layer(middleware::from_fn(crate::http::harden))
}

/// Files served on both the web UI port and the share port.
pub fn static_routes() -> Router<St> {
    use crate::pages::Visitor;
    let mut r = Router::new()
        .route("/app.css", get(app_css))
        .route("/fonts/mona-sans.woff2", get(|| async { font(MONA_SANS) }))
        .route("/fonts/martian-mono.woff2", get(|| async { font(MARTIAN_MONO) }))
        .route("/favicon.svg", get(favicon))
        .route("/favicon.ico", get(favicon_ico))
        .route("/apple-touch-icon.png", get(touch_icon))
        .route("/about/license.txt", get(license_txt))
        .route("/about/third-party.txt", get(third_party_txt));
    // One script per kind of link, so each page carries only what it can use.
    for v in [
        Visitor { add: false, export: false },
        Visitor { add: true, export: false },
        Visitor { add: false, export: true },
        Visitor { add: true, export: true },
    ] {
        r = r.route(v.script_path(), get(move || async move { asset(crate::pages::pages().share_js(v), "text/javascript; charset=utf-8") }));
    }
    r
}

/// An HTML page for a status (404, 410, 429…); see `pages::status_page`.
pub fn status_response(code: StatusCode, title: &str, text: &str, back: Option<(&str, &str)>) -> Response {
    let body = crate::pages::status_page(code.as_u16(), title, text, back);
    (
        code,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8"), (header::CACHE_CONTROL, "no-store")],
        body,
    )
        .into_response()
}

/// Unknown addresses on the web UI port: JSON for the API, a page otherwise.
async fn not_found(req: Request) -> Response {
    if req.uri().path().starts_with("/api/") {
        return ApiError::not_found().into_response();
    }
    status_response(
        StatusCode::NOT_FOUND,
        "Destination unreachable",
        "There's no route to that address on this server.",
        Some(("/", "Back to pingrail")),
    )
}

/// Serve until `shutdown` resolves: the web UI/API on `listener` and, when
/// given, share pages only on `share_listener`. Also runs the TUI-session
/// reaper and closes expired share links.
pub async fn serve(
    state: St,
    listener: tokio::net::TcpListener,
    share_listener: Option<tokio::net::TcpListener>,
    tls: Arc<rustls::ServerConfig>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        shutdown.await;
        let _ = stop_tx.send(true);
    });

    // Renew the certificate when it nears expiry or this machine's names or
    // addresses change (checked hourly; new connections get the new one).
    let renew_state = state.clone();
    let renewer = tokio::spawn(async move {
        let mut iv = tokio::time::interval(Duration::from_secs(3600));
        iv.tick().await;
        loop {
            iv.tick().await;
            let st = renew_state.clone();
            let r = tokio::task::spawn_blocking(move || st.certs.refresh(&crate::ca::saved_names(&st.store))).await;
            if let Ok(Err(e)) = r {
                tracing::warn!("renewing the certificate failed: {e:#}");
            }
        }
    });
    let reaper_state = state.clone();
    let reaper = tokio::spawn(async move {
        let mut iv = tokio::time::interval(Duration::from_secs(5));
        let mut ticks = 0u32;
        loop {
            iv.tick().await;
            ticks += 1;
            if ticks % 6 == 1 {
                match blocking(&reaper_state.store, |s| s.close_inactive_shares(now_ms())).await {
                    Ok(n) if n > 0 => {
                        tracing::info!("{n} share link(s) expired; pausing destinations their visitors added");
                        let _ = reaper_state.engine.sync().await;
                    }
                    Err(e) => tracing::warn!("checking share links failed: {e:#}"),
                    _ => {}
                }
            }
            let expired: Vec<String> = {
                let mut s = reaper_state.tui_sessions.lock().unwrap();
                let dead: Vec<String> = s
                    .iter()
                    .filter(|(_, at)| at.elapsed() > SESSION_TIMEOUT)
                    .map(|(k, _)| k.clone())
                    .collect();
                for k in &dead {
                    s.remove(k);
                }
                dead
            };
            for id in expired {
                tracing::info!("TUI session {id} timed out; pausing its foreground targets");
                let i = id.clone();
                let _ = blocking(&reaper_state.store, move |s| s.end_session(&i, false)).await;
                let _ = reaper_state.engine.sync().await;
            }
        }
    });
    let exempt = {
        let trusted = state.trusted.clone();
        Arc::new(move |ip: IpAddr| crate::http::in_nets(ip, &trusted)) as Arc<dyn Fn(IpAddr) -> bool + Send + Sync>
    };
    let share_task = share_listener.map(|l| {
        let app = crate::share::public_router(state.clone());
        let rx = stop_rx.clone();
        let ex = exempt.clone();
        let tls = tls.clone();
        tokio::spawn(async move { crate::http::serve(l, app, crate::http::Limits::share(), ex, tls, rx).await })
    });
    let app = router(state);
    crate::http::serve(listener, app, crate::http::Limits::web(), exempt, tls, stop_rx).await;
    reaper.abort();
    renewer.abort();
    if let Some(t) = share_task {
        let _ = t.await;
    }
    Ok(())
}

/// The visitor's address. When the connection comes from a trusted proxy
/// (share.trusted_proxies, by default this machine, e.g. cloudflared), use
/// the address it reports in CF-Connecting-IP / X-Forwarded-For.
pub fn client_ip(st: &AppState, peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
    forwarded_ip(peer, headers, &st.trusted)
}

fn forwarded_ip(peer: SocketAddr, headers: &HeaderMap, trusted: &[(IpAddr, u8)]) -> IpAddr {
    let p = peer.ip();
    if crate::http::in_nets(p, trusted) {
        for name in ["cf-connecting-ip", "x-forwarded-for"] {
            if let Some(ip) = headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split(',').next())
                .and_then(|v| v.trim().parse::<IpAddr>().ok())
            {
                return ip;
            }
        }
    }
    p
}

// ----- auth ---------------------------------------------------------------

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| {
            let (k, v) = kv.trim().split_once('=')?;
            (k == name).then(|| v.to_string())
        })
        .next()
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn auth(State(st): State<St>, mut req: Request, next: Next) -> Response {
    let headers = req.headers();
    if let Some(bearer) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        if constant_eq(bearer.trim().as_bytes(), st.token.as_bytes()) {
            req.extensions_mut().insert(Principal { user: "local".into(), via: "token", auth_ms: now_ms() });
            return next.run(req).await;
        }
        return ApiError(StatusCode::UNAUTHORIZED, "invalid API token".into()).into_response();
    }
    if let Some(tok) = cookie_value(headers, COOKIE) {
        // Cross-site protection for cookie-authenticated writes.
        let via_proxy = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .is_some_and(|c| crate::http::in_nets(c.0.ip(), &st.trusted));
        if req.method() != Method::GET && !same_origin(headers, via_proxy) {
            return ApiError(StatusCode::FORBIDDEN, "cross-origin request refused".into()).into_response();
        }
        let s = st.store.clone();
        let user = tokio::task::spawn_blocking(move || s.web_session(&tok)).await;
        if let Ok(Ok(Some((user, auth_ms)))) = user {
            req.extensions_mut().insert(Principal { user, via: "session", auth_ms });
            return next.run(req).await;
        }
    }
    ApiError(StatusCode::UNAUTHORIZED, "login required".into()).into_response()
}

/// Does a browser request's Origin match the host it was sent to? Behind a
/// trusted reverse proxy (`via_proxy`) the Host header may be rewritten, so
/// the forwarded host is accepted too; from anyone else it's ignored. (The
/// SameSite=Strict cookie is the first line of defence; this is a second.)
fn same_origin(headers: &HeaderMap, via_proxy: bool) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        return true; // non-browser client or same-origin navigation
    };
    let Some(origin_host) = origin.strip_prefix("https://") else { return false };
    let names: &[&str] = if via_proxy { &["host", "x-forwarded-host"] } else { &["host"] };
    names.iter().any(|name| {
        headers
            .get(*name)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|h| h.split(',').next().map(str::trim) == Some(origin_host))
    })
}

// ----- static assets ------------------------------------------------------

const APP_CSS: &str = include_str!("web/app.css");
/// Mona Sans and Martian Mono (SIL Open Font License 1.1), the Latin files
/// exactly as Google Fonts publishes them; see THIRD-PARTY-NOTICES.txt.
const MONA_SANS: &[u8] = include_bytes!("../assets/fonts/web/mona-sans-latin.woff2");
const MARTIAN_MONO: &[u8] = include_bytes!("../assets/fonts/web/martian-mono-latin-400.woff2");
const FAVICON: &str = include_str!("web/favicon.svg");
const FAVICON_ICO: &[u8] = include_bytes!("../assets/brand/favicon.ico");
const TOUCH_ICON: &[u8] = include_bytes!("../assets/brand/apple-touch-icon.png");
pub const LICENSE_TEXT: &str = include_str!("../LICENSE");
pub const THIRD_PARTY_TEXT: &str = include_str!("../THIRD-PARTY-NOTICES.txt");

/// Who made pingrail and on what terms (shown in every About screen).
pub mod about {
    pub const NAME: &str = "pingrail";
    pub const VERSION: &str = env!("CARGO_PKG_VERSION");
    pub const PUBLISHER: &str = "Ulrich Holtzhausen";
    pub const COPYRIGHT: &str = "Copyright © 2026 Ulrich Holtzhausen";
    pub const LICENSE: &str = "Apache-2.0";
    pub const CONTACT: &str = "https://github.com/ulrich-za/pingrail/issues";
    pub const TRADEMARK: &str =
        "pingrail is a trademark of Ulrich Holtzhausen; the licence does not grant permission to use the name. The pingrail logo carries no such restriction.";
    pub const WARRANTY: &str = "pingrail is open source under the Apache License, Version 2.0. It is distributed on an \"AS IS\" basis, \
        WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. The source code is at \
        https://github.com/ulrich-za/pingrail.";
}

fn asset(body: &'static str, ctype: &'static str) -> Response {
    (
        [
            (header::CONTENT_TYPE, ctype),
            (header::CACHE_CONTROL, "no-cache"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        body,
    )
        .into_response()
}

fn font(body: &'static [u8]) -> Response {
    ([(header::CONTENT_TYPE, "font/woff2"), (header::CACHE_CONTROL, "max-age=604800")], body).into_response()
}

/// The admin UI.
pub async fn index() -> Response {
    asset(&crate::pages::pages().admin_html, "text/html; charset=utf-8")
}
pub async fn favicon_ico() -> Response {
    ([(header::CONTENT_TYPE, "image/x-icon"), (header::CACHE_CONTROL, "max-age=86400")], FAVICON_ICO).into_response()
}
pub async fn touch_icon() -> Response {
    ([(header::CONTENT_TYPE, "image/png"), (header::CACHE_CONTROL, "max-age=86400")], TOUCH_ICON).into_response()
}
pub async fn license_txt() -> Response {
    asset(LICENSE_TEXT, "text/plain; charset=utf-8")
}
pub async fn third_party_txt() -> Response {
    asset(THIRD_PARTY_TEXT, "text/plain; charset=utf-8")
}
pub async fn app_js() -> Response {
    asset(&crate::pages::pages().admin_js, "text/javascript; charset=utf-8")
}
pub async fn app_css() -> Response {
    asset(APP_CSS, "text/css; charset=utf-8")
}
pub async fn favicon() -> Response {
    asset(FAVICON, "image/svg+xml")
}

// ----- handlers -----------------------------------------------------------

async fn health(State(st): State<St>, headers: HeaderMap) -> ApiResult<Json<Health>> {
    let (has_password, passkey_required) =
        blocking(&st.store, |s| Ok((s.has_users()?, crate::passkeys::required(s)))).await?;
    Ok(Json(Health {
        name: "pingrail".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        has_password,
        listen: st.listen.clone(),
        cert_sha256: st.cert_sha256.clone(),
        passkeys: crate::passkeys::relying_party(&st, &headers).is_ok(),
        passkey_required,
    }))
}

/// pingrail's certificate authority, for phones and computers to trust
/// (web UI port only; it's public, being sent with every connection).
async fn ca_crt(State(st): State<St>) -> Response {
    let Some(der) = st.certs.ca_der() else {
        return status_response(StatusCode::NOT_FOUND, "No certificate authority", "This server uses a certificate configured in pingrail.toml.", Some(("/", "Back to pingrail")));
    };
    let host = crate::util::hostname().unwrap_or_else(|| "pingrail".into());
    (
        [
            (header::CONTENT_TYPE, HeaderValue::from_static("application/x-x509-ca-cert")),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            (
                header::CONTENT_DISPOSITION,
                HeaderValue::from_str(&format!("attachment; filename=\"pingrail-{host}.crt\"")).unwrap_or(HeaderValue::from_static("attachment")),
            ),
        ],
        der.to_vec(),
    )
        .into_response()
}

#[derive(serde::Serialize)]
struct CertificateView {
    #[serde(flatten)]
    info: crate::ca::CertInfo,
    /// The address you're using, when the certificate (or its authority)
    /// doesn't cover it yet.
    host: Option<String>,
    host_named: bool,
    host_covered: bool,
    host_in_ca: bool,
    port: u16,
}

/// The host name the browser used (from Host), when it's a name.
fn request_host(headers: &HeaderMap) -> Option<(String, Option<u16>)> {
    let h = headers.get(header::HOST)?.to_str().ok()?.trim().to_ascii_lowercase();
    if h.starts_with('[') {
        return None; // IPv6 literal
    }
    let (name, port) = match h.rsplit_once(':') {
        Some((n, p)) => (n.to_string(), p.parse().ok()),
        None => (h, None),
    };
    crate::util::valid_dns_name(&name).then_some((name, port))
}

async fn certificate_info(State(st): State<St>, headers: HeaderMap) -> Json<CertificateView> {
    let info = st.certs.info();
    let host = request_host(&headers);
    let port = host.as_ref().and_then(|h| h.1).unwrap_or_else(|| st.cfg.port());
    let name = host.map(|h| h.0);
    Json(CertificateView {
        host_covered: name.as_ref().is_some_and(|n| info.names.contains(n)),
        host_in_ca: name.as_ref().is_some_and(|n| st.certs.covers(n)),
        host_named: name.is_some(),
        host: name,
        port,
        info,
    })
}

#[derive(Deserialize)]
struct QrQuery {
    /// "ca" (the authority, to trust) or "app" (the web UI).
    #[serde(rename = "for")]
    what: String,
    host: String,
}

/// A QR code (SVG) for a phone to open this server's authority or web UI
/// at one of the certificate's own names or addresses.
async fn qr(State(st): State<St>, headers: HeaderMap, Query(q): Query<QrQuery>) -> ApiResult<Response> {
    let host = q.host.trim().to_ascii_lowercase();
    let info = st.certs.info();
    let known = info.names.contains(&host) || info.addresses.contains(&host);
    if !known {
        return Err(ApiError::bad("not one of this server's names"));
    }
    let port = request_host(&headers).and_then(|h| h.1).unwrap_or_else(|| st.cfg.port());
    let shown = if host.contains(':') { format!("[{host}]") } else { host };
    let path = match q.what.as_str() {
        "ca" => "/ca.crt",
        "app" => "/",
        _ => return Err(ApiError::bad("for must be ca or app")),
    };
    let url = format!("https://{shown}:{port}{path}");
    let svg = crate::util::qr_svg(&url).map_err(|e| ApiError::bad(format!("QR code: {e}")))?;
    Ok(([(header::CONTENT_TYPE, "image/svg+xml"), (header::CACHE_CONTROL, "no-store")], svg).into_response())
}

#[derive(Deserialize)]
struct NameRequest {
    name: String,
}

/// Put another name for this machine on its certificate (the web UI offers
/// the one you browsed to). A name the authority doesn't cover means a new
/// authority, which devices must trust again.
async fn add_certificate_name(
    State(st): State<St>,
    Extension(p): Extension<Principal>,
    Json(req): Json<NameRequest>,
) -> ApiResult<Json<crate::ca::Refreshed>> {
    if st.certs.info().custom {
        return Err(ApiError::bad("this server uses a certificate configured in pingrail.toml"));
    }
    // A new authority means every device must trust it again: only right
    // after signing in.
    if !st.certs.covers(req.name.trim()) && !p.recent() {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "This makes a new certificate authority, which needs a recent sign-in. Sign out and in again, then retry".into(),
        ));
    }
    // Only names that lead here: a name outside the authority's limits widens
    // what a new authority may vouch for, so it must resolve to this machine.
    let name = req.name.trim().trim_end_matches('.').to_ascii_lowercase();
    if crate::util::valid_dns_name(&name) && !st.certs.covers(&name) {
        let found = tokio::time::timeout(Duration::from_secs(4), tokio::net::lookup_host((name.as_str(), 0))).await;
        let ips: Vec<IpAddr> = match found {
            Ok(Ok(addrs)) => addrs.map(|a| a.ip()).collect(),
            _ => vec![],
        };
        if !ips.iter().any(|ip| crate::util::is_this_machine(*ip)) {
            let shown = if ips.is_empty() { "nothing".to_string() } else { ips.iter().map(IpAddr::to_string).collect::<Vec<_>>().join(", ") };
            return Err(ApiError::bad(format!("{name} doesn't lead to this machine (it resolves to {shown} here)")));
        }
    }
    let st2 = st.clone();
    let changed = tokio::task::spawn_blocking(move || -> Result<std::result::Result<crate::ca::Refreshed, String>> {
        let names = match crate::ca::add_name(&st2.store, &name) {
            Ok(n) => n,
            Err(e) => return Ok(Err(format!("{e:#}"))),
        };
        Ok(Ok(st2.certs.refresh(&names)?))
    })
    .await
    .map_err(anyhow::Error::from)??
    .map_err(ApiError::bad)?;
    Ok(Json(changed))
}

/// What the sign-in page measures its round trip with: nothing to read, and
/// cheap enough to answer every second.
async fn ping() -> StatusCode {
    StatusCode::NO_CONTENT
}

/// A refused sign-in, with when to try again (the sign-in page counts down).
fn too_many(retry_after_secs: u64, msg: &str) -> Response {
    let mut resp = ApiError(StatusCode::TOO_MANY_REQUESTS, msg.into()).into_response();
    resp.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from(retry_after_secs.max(1)));
    resp
}

/// Before any sign-in attempt (password or passkey): refuse an address
/// that failed too often, keep everyone together to a trickle, and slow down
/// an address that keeps failing.
pub async fn sign_in_gate(st: &AppState, ip: IpAddr) -> Option<Response> {
    let (failures, last_failure) = {
        let mut f = st.login_failures.lock().unwrap();
        f.retain(|_, (_, at)| at.elapsed() < LOGIN_LOCKOUT);
        f.get(&ip).map(|(n, at)| (*n, Some(*at))).unwrap_or((0, None))
    };
    if failures >= LOGIN_LOCKOUT_FAILURES {
        let left = last_failure.map_or(LOGIN_LOCKOUT, |at| LOGIN_LOCKOUT.saturating_sub(at.elapsed()));
        return Some(too_many(left.as_secs() + 1, "Too many failed sign-ins from your address. Try again in 15 minutes."));
    }
    if !crate::share::take(&mut st.login_budget.lock().unwrap(), (), LOGIN_BURST, LOGIN_REFILL_PER_SEC, 1.0) {
        return Some(too_many((1.0 / LOGIN_REFILL_PER_SEC).ceil() as u64, "Too many sign-in attempts right now. Wait a moment and try again."));
    }
    if failures > 3 {
        tokio::time::sleep(Duration::from_millis(500 * failures.min(10) as u64)).await;
    }
    None
}

/// Count a failed sign-in against `ip`.
pub async fn sign_in_failed(st: &AppState, ip: IpAddr) {
    {
        let mut f = st.login_failures.lock().unwrap();
        if f.len() >= LOGIN_TRACKED_MAX && !f.contains_key(&ip) {
            // Forget the addresses that failed longest ago.
            let mut by_age: Vec<(IpAddr, Instant)> = f.iter().map(|(k, (_, at))| (*k, *at)).collect();
            by_age.sort_by_key(|(_, at)| *at);
            for (k, _) in by_age.into_iter().take(LOGIN_TRACKED_MAX / 10) {
                f.remove(&k);
            }
        }
        let e = f.entry(ip).or_insert((0, Instant::now()));
        e.0 += 1;
        e.1 = Instant::now();
    }
    tokio::time::sleep(Duration::from_millis(400)).await;
}

/// Signed in: a new session (replacing the one this browser had, if any)
/// and its cookie.
pub async fn start_session(st: &AppState, ip: IpAddr, headers: &HeaderMap, username: String) -> ApiResult<Response> {
    st.login_failures.lock().unwrap().remove(&ip);
    let old = cookie_value(headers, COOKIE);
    let token = random_hex(32);
    let hours = st.cfg.web.session_hours.max(1) as i64;
    let expires = now_ms() + hours * 3_600_000;
    let (t, u) = (token.clone(), username.clone());
    blocking(&st.store, move |s| {
        if let Some(old) = old {
            s.delete_web_session(&old)?;
        }
        s.create_web_session(&t, &u, expires)
    })
    .await?;
    let cookie = format!("{COOKIE}={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={}", hours * 3600);
    let mut resp = Json(Me { user: username, via: "session".into(), has_password: true }).into_response();
    resp.headers_mut().insert(header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());
    Ok(resp)
}

/// The session cookie this request carries.
pub fn session_cookie(headers: &HeaderMap) -> Option<String> {
    cookie_value(headers, COOKIE)
}

async fn login(
    State(st): State<St>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> ApiResult<Response> {
    let ip = client_ip(&st, peer, &headers);
    if blocking(&st.store, |s| Ok(crate::passkeys::required(s))).await? {
        return Err(ApiError(StatusCode::FORBIDDEN, "This server needs a passkey to sign in".into()));
    }
    if let Some(refused) = sign_in_gate(&st, ip).await {
        return Ok(refused);
    }
    // Only one or two password checks run at once, so a flood can't eat
    // the machine's memory and CPU.
    let Some(permit) = st.passwords.turn(Duration::from_secs(10)).await else {
        return Err(busy());
    };
    let username = req.username.trim().to_string();
    let u = username.clone();
    let phc = blocking(&st.store, move |s| s.user_phc(&u)).await?;
    let password = req.password.clone();
    let st2 = st.clone();
    let (u, phc2) = (username.clone(), phc.clone());
    // Unknown usernames are checked against a stand-in, so they take as long.
    let check = tokio::task::spawn_blocking(move || {
        let check = st2.passwords.check(&password, phc2.as_deref());
        // Saved with older settings: save it again with today's.
        if check == (Check::Good { rehash: true })
            && let Some(old) = phc2
            && let Ok(new) = st2.passwords.hash(&password)
            && let Err(e) = st2.store.rehash_user(&u, &old, &new)
        {
            tracing::warn!("saving a rehashed password failed: {e:#}");
        }
        check
    })
    .await
    .unwrap_or(Check::Wrong);
    // The expensive part is done: let the next check start.
    drop(permit);
    if check == Check::Busy {
        return Err(busy());
    }
    if !matches!(check, Check::Good { .. }) {
        sign_in_failed(&st, ip).await;
        return Err(ApiError(StatusCode::UNAUTHORIZED, "wrong username or password".into()));
    }
    start_session(&st, ip, &headers, username).await
}

fn busy() -> ApiError {
    ApiError(StatusCode::SERVICE_UNAVAILABLE, "The service is busy. Try signing in again shortly.".into())
}

async fn logout(State(st): State<St>, headers: HeaderMap) -> ApiResult<Response> {
    if let Some(tok) = cookie_value(&headers, COOKIE) {
        blocking(&st.store, move |s| s.delete_web_session(&tok)).await?;
    }
    let mut resp = StatusCode::NO_CONTENT.into_response();
    resp.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static("__Host-pr_session=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0"),
    );
    Ok(resp)
}

async fn me(State(st): State<St>, Extension(p): Extension<Principal>) -> ApiResult<Json<Me>> {
    let has_password = blocking(&st.store, |s| s.has_users()).await?;
    Ok(Json(Me { user: p.user, via: p.via.into(), has_password }))
}

async fn set_password(
    State(st): State<St>,
    Extension(p): Extension<Principal>,
    Json(req): Json<PasswordRequest>,
) -> ApiResult<StatusCode> {
    if req.password.chars().count() < 8 {
        return Err(ApiError::bad("password must be at least 8 characters"));
    }
    let username = match (&req.username, p.via) {
        (Some(u), "token") if !u.trim().is_empty() => u.trim().to_string(),
        (_, "token") => "admin".to_string(),
        // A web user can only change their own password.
        _ => p.user.clone(),
    };
    let Some(permit) = st.passwords.turn(Duration::from_secs(10)).await else {
        return Err(busy());
    };
    let pw = req.password.clone();
    let st2 = st.clone();
    let phc = tokio::task::spawn_blocking(move || st2.passwords.hash(&pw)).await.map_err(anyhow::Error::from)?;
    drop(permit);
    let phc = match phc {
        Ok(phc) => phc,
        Err(HashError::Busy) => return Err(busy()),
        Err(e) => return Err(anyhow::Error::from(e).into()),
    };
    blocking(&st.store, move |s| s.set_user(&username, &phc)).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Re-time password hashing for this machine (`pingrail passwd --tune`).
/// Only the API token may ask: it takes a second or two of full CPU.
async fn tune_passwords(State(st): State<St>, Extension(p): Extension<Principal>) -> ApiResult<Json<crate::password::Policy>> {
    if p.via != "token" {
        return Err(ApiError(StatusCode::FORBIDDEN, "run `pingrail passwd --tune` on the server".into()));
    }
    let Some(_permit) = st.passwords.turn(Duration::from_secs(10)).await else {
        return Err(busy());
    };
    let st2 = st.clone();
    let policy = tokio::task::spawn_blocking(move || -> Result<crate::password::Policy> {
        let policy = crate::password::load_or_tune(&st2.store, true)?;
        st2.passwords.replace(policy)?;
        Ok(policy)
    })
    .await
    .map_err(anyhow::Error::from)??;
    Ok(Json(policy))
}

#[derive(Deserialize)]
struct OverviewQuery {
    window_ms: Option<i64>,
    spark: Option<usize>,
}

async fn overview(State(st): State<St>, Query(q): Query<OverviewQuery>) -> ApiResult<Json<Overview>> {
    let window = q.window_ms.unwrap_or(600_000).clamp(10_000, 90 * 86_400_000);
    let spark = q.spark.unwrap_or(30);
    let engine = st.engine.clone();
    let thresholds = st.cfg.thresholds;
    let ov = blocking(&st.store, move |s| {
        analysis::overview(s, &|id| engine.live(id), thresholds, now_ms(), window, spark)
    })
    .await?;
    Ok(Json(ov))
}

async fn list_targets(State(st): State<St>) -> ApiResult<Json<Vec<Target>>> {
    Ok(Json(blocking(&st.store, |s| s.list_targets()).await?))
}

pub fn valid_host(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_' | '[' | ']' | '%'))
}

async fn add_target(State(st): State<St>, Json(mut req): Json<NewTarget>) -> ApiResult<Json<Target>> {
    req.host = req.host.trim().to_string();
    if !valid_host(&req.host) {
        return Err(ApiError::bad("enter a hostname or IP address"));
    }
    match tokio::time::timeout(Duration::from_secs(5), resolve(&req.host)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(ApiError::bad(format!("cannot resolve {}: {e}", req.host))),
        Err(_) => return Err(ApiError::bad(format!("timed out resolving {}", req.host))),
    }
    let default_interval = st.cfg.probe.interval_ms;
    let t = blocking(&st.store, move |s| s.add_target(&req, default_interval)).await?;
    st.engine.sync().await?;
    Ok(Json(t))
}

async fn patch_target(
    State(st): State<St>,
    Path(id): Path<i64>,
    Json(p): Json<TargetPatch>,
) -> ApiResult<Json<Target>> {
    let resume = p.enabled == Some(true);
    let t = blocking(&st.store, move |s| {
        // Resuming a destination a share-link visitor added after their link
        // has ended makes it yours.
        if resume
            && let Some(t) = s.get_target(id)?
            && let Some(sid) = t.share_id
            && s.get_share(sid)?.is_none_or(|sh| !sh.is_active(now_ms()))
        {
            s.take_over_target(id)?;
        }
        s.update_target(id, &p)
    })
    .await?
    .ok_or_else(ApiError::not_found)?;
    st.engine.sync().await?;
    Ok(Json(t))
}

async fn delete_target(State(st): State<St>, Path(id): Path<i64>) -> ApiResult<StatusCode> {
    let ok = blocking(&st.store, move |s| s.delete_target(id)).await?;
    st.engine.sync().await?;
    if ok { Ok(StatusCode::NO_CONTENT) } else { Err(ApiError::not_found()) }
}

#[derive(Deserialize)]
struct RangeQuery {
    from: Option<i64>,
    to: Option<i64>,
    /// Most points the chart has room for (about one per 2 px).
    #[serde(alias = "buckets")]
    points: Option<usize>,
    /// Graph this hop (TTL) instead of the destination.
    hop: Option<u8>,
}

async fn detail(State(st): State<St>, Path(id): Path<i64>, Query(q): Query<RangeQuery>) -> ApiResult<Json<Detail>> {
    let to = q.to.unwrap_or_else(|| now_ms() + 1);
    let from = q.from.unwrap_or(to - 600_000);
    if from >= to {
        return Err(ApiError::bad("'from' must be before 'to'"));
    }
    let points = q.points.unwrap_or(400).clamp(10, 4000);
    let hop = q.hop;
    let live = st.engine.live(id);
    let rdns = st.engine.rdns.clone();
    let thresholds = st.cfg.thresholds;
    let d = blocking(&st.store, move |s| {
        let Some(t) = s.get_target(id)? else { return Ok(None) };
        analysis::detail(s, t, live, Some(&rdns), from, to, points, hop, thresholds).map(Some)
    })
    .await?
    .ok_or_else(ApiError::not_found)?;
    Ok(Json(d))
}

#[derive(Deserialize)]
struct ReportQuery {
    targets: Option<String>,
    from: i64,
    to: i64,
    format: Option<String>,
    tz: Option<i32>,
}

async fn report_handler(State(st): State<St>, Query(q): Query<ReportQuery>) -> ApiResult<Response> {
    let format = match q.format.as_deref().unwrap_or("pdf") {
        "pdf" => ReportFormat::Pdf,
        "png" => ReportFormat::Png,
        _ => return Err(ApiError::bad("format must be pdf or png")),
    };
    if q.from >= q.to {
        return Err(ApiError::bad("'from' must be before 'to'"));
    }
    let ids: Vec<i64> = match q.targets.as_deref() {
        None | Some("") | Some("all") => blocking(&st.store, |s| s.list_targets()).await?.iter().map(|t| t.id).collect(),
        Some(list) => list.split(',').filter_map(|x| x.trim().parse().ok()).collect(),
    };
    if ids.is_empty() {
        return Err(ApiError::bad("no targets to report on"));
    }
    let req = ReportRequest {
        target_ids: ids,
        from_ms: q.from,
        to_ms: q.to,
        tz_offset_min: q.tz.unwrap_or(0).clamp(-14 * 60, 14 * 60),
        format,
    };
    let rdns = st.engine.rdns.clone();
    let thresholds = st.cfg.thresholds;
    let fname = report::file_name(&req);
    let bytes = blocking(&st.store, move |s| report::render(s, Some(&rdns), thresholds, &req, &analysis::Scope::everything())).await?;
    Ok((
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(format.mime())),
            (
                header::CONTENT_DISPOSITION,
                HeaderValue::from_str(&format!("attachment; filename=\"{fname}\""))
                    .unwrap_or(HeaderValue::from_static("attachment")),
            ),
        ],
        Body::from(bytes),
    )
        .into_response())
}

async fn open_session(State(st): State<St>) -> ApiResult<Json<SessionInfo>> {
    let id = random_hex(8);
    st.tui_sessions.lock().unwrap().insert(id.clone(), Instant::now());
    Ok(Json(SessionInfo { id }))
}

async fn heartbeat(State(st): State<St>, Path(id): Path<String>) -> ApiResult<StatusCode> {
    let mut s = st.tui_sessions.lock().unwrap();
    match s.get_mut(&id) {
        Some(at) => {
            *at = Instant::now();
            Ok(StatusCode::NO_CONTENT)
        }
        None => Err(ApiError::not_found()),
    }
}

#[derive(Deserialize)]
struct EndQuery {
    end: Option<SessionEnd>,
}

async fn end_session(
    State(st): State<St>,
    Path(id): Path<String>,
    Query(q): Query<EndQuery>,
) -> ApiResult<StatusCode> {
    st.tui_sessions.lock().unwrap().remove(&id);
    let keep = q.end.unwrap_or(SessionEnd::Stop) == SessionEnd::Background;
    blocking(&st.store, move |s| s.end_session(&id, keep)).await?;
    st.engine.sync().await?;
    Ok(StatusCode::NO_CONTENT)
}

// ----- share links (admin) -------------------------------------------------

/// The link visitors open. Uses share.public_url when set; otherwise the
/// host the admin is browsing from, on the share-only port.
fn share_url(cfg: &Config, host_header: &str, token: &str) -> String {
    let public = cfg.share.public_url.trim().trim_end_matches('/');
    if !public.is_empty() {
        return format!("{public}/s/{token}");
    }
    let host_only = if let Some(rest) = host_header.strip_prefix('[') {
        format!("[{}]", rest.split(']').next().unwrap_or(""))
    } else {
        match host_header.rsplit_once(':') {
            Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => h.to_string(),
            _ => host_header.to_string(),
        }
    };
    let host_only = if host_only.is_empty() { "localhost".to_string() } else { host_only };
    match cfg.share.port() {
        Some(port) => format!("https://{host_only}:{port}/s/{token}"),
        None => format!("https://{host_header}/s/{token}"),
    }
}

/// The host a request was addressed to: the Host header, or the forwarded
/// host when (and only when) it came through a trusted proxy. Used to build
/// share-link addresses when share.public_url isn't set.
struct RequestHost(String);

impl axum::extract::FromRequestParts<St> for RequestHost {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut axum::http::request::Parts, st: &St) -> Result<Self, Self::Rejection> {
        let via_proxy = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .is_some_and(|c| crate::http::in_nets(c.0.ip(), &st.trusted));
        Ok(RequestHost(host_of(&parts.headers, via_proxy)))
    }
}

fn host_of(headers: &HeaderMap, via_proxy: bool) -> String {
    let names: &[&str] = if via_proxy { &["x-forwarded-host", "host"] } else { &["host"] };
    names
        .iter()
        .find_map(|n| headers.get(*n))
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .filter(|h| {
            !h.is_empty()
                && h.len() <= 255
                && h.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'))
        })
        .map(String::from)
        .unwrap_or_else(|| "localhost".into())
}

fn share_info(cfg: &Config, host: &str, share: Share) -> ShareInfo {
    let now = now_ms();
    ShareInfo { status: share.status(now).into(), url: share_url(cfg, host, &share.token), share }
}

/// Check and tidy settings from the admin UI.
fn clean_settings(mut s: ShareSettings, existing: &[i64], creating: bool) -> ApiResult<ShareSettings> {
    s.label = crate::util::clean_text(&s.label, 80);
    if s.label.is_empty() {
        s.label = "Shared link".into();
    }
    s.target_ids.retain(|id| existing.contains(id));
    s.target_ids.sort_unstable();
    s.target_ids.dedup();
    if s.target_ids.is_empty() && !s.can_add {
        return Err(ApiError::bad("Choose at least one target, or let visitors add their own."));
    }
    s.max_targets = s.max_targets.clamp(1, 20);
    s.history_days = s.history_days.clamp(1, 365);
    s.hide_public_hops = s.hide_public_hops.min(10);
    s.min_interval_ms = s.min_interval_ms.clamp(250, 3_600_000);
    s.visitor_retention_days = s.visitor_retention_days.min(3650);
    s.visitor_storage_mb = s.visitor_storage_mb.min(10_000_000);
    let mut allow = Vec::new();
    for a in s.allow_private.iter().flat_map(|a| a.split([',', ' ', '\n'])).map(str::trim).filter(|a| !a.is_empty()) {
        if crate::netpolicy::parse_cidr(a).is_none() {
            return Err(ApiError::bad(format!("'{a}' isn't an IP address or range like 192.168.1.0/24.")));
        }
        allow.push(a.to_string());
    }
    s.allow_private = allow;
    if creating && s.expires_ms.is_some_and(|e| e <= now_ms()) {
        return Err(ApiError::bad("The expiry has to be in the future."));
    }
    Ok(s)
}

async fn list_shares(State(st): State<St>, RequestHost(host): RequestHost) -> ApiResult<Json<SharesResponse>> {
    let shares = blocking(&st.store, |s| s.list_shares()).await?;
    Ok(Json(SharesResponse {
        shares: shares.into_iter().map(|sh| share_info(&st.cfg, &host, sh)).collect(),
        public_url: st.cfg.share.public_url.clone(),
        share_port: st.cfg.share.port(),
    }))
}

async fn create_share(
    State(st): State<St>,
    RequestHost(host): RequestHost,
    Json(settings): Json<ShareSettings>,
) -> ApiResult<Json<ShareInfo>> {
    let existing: Vec<i64> = blocking(&st.store, |s| s.list_targets()).await?.iter().map(|t| t.id).collect();
    let settings = clean_settings(settings, &existing, true)?;
    let token = random_hex(20);
    let sh = blocking(&st.store, move |s| s.create_share(&settings, &token)).await?;
    tracing::info!("created share link {} ({})", sh.id, sh.settings.label);
    shares_changed(&st, sh.id).await;
    Ok(Json(share_info(&st.cfg, &host, sh)))
}

async fn update_share(
    State(st): State<St>,
    Path(id): Path<i64>,
    RequestHost(host): RequestHost,
    Json(settings): Json<ShareSettings>,
) -> ApiResult<Json<ShareInfo>> {
    let existing: Vec<i64> = blocking(&st.store, |s| s.list_targets()).await?.iter().map(|t| t.id).collect();
    let settings = clean_settings(settings, &existing, false)?;
    let sh = blocking(&st.store, move |s| s.update_share(id, &settings)).await?.ok_or_else(ApiError::not_found)?;
    // Restart visitors' destinations whose allowed private ranges changed.
    st.engine.sync().await?;
    shares_changed(&st, id).await;
    Ok(Json(share_info(&st.cfg, &host, sh)))
}

async fn regenerate_share(
    State(st): State<St>,
    Path(id): Path<i64>,
    RequestHost(host): RequestHost,
) -> ApiResult<Json<ShareInfo>> {
    let token = random_hex(20);
    let sh = blocking(&st.store, move |s| s.regenerate_share(id, &token)).await?.ok_or_else(ApiError::not_found)?;
    shares_changed(&st, id).await;
    Ok(Json(share_info(&st.cfg, &host, sh)))
}

async fn revoke_share(
    State(st): State<St>,
    Path(id): Path<i64>,
    RequestHost(host): RequestHost,
) -> ApiResult<Json<ShareInfo>> {
    if !blocking(&st.store, move |s| s.revoke_share(id)).await? {
        return Err(ApiError::not_found());
    }
    st.engine.sync().await?;
    shares_changed(&st, id).await;
    let sh = blocking(&st.store, move |s| s.get_share(id)).await?.ok_or_else(ApiError::not_found)?;
    Ok(Json(share_info(&st.cfg, &host, sh)))
}

async fn delete_share(State(st): State<St>, Path(id): Path<i64>) -> ApiResult<StatusCode> {
    if !blocking(&st.store, move |s| s.delete_share(id)).await? {
        return Err(ApiError::not_found());
    }
    st.engine.sync().await?;
    shares_changed(&st, id).await;
    Ok(StatusCode::NO_CONTENT)
}

/// After a link is created or changed: refresh the list of valid codes,
/// drop cached answers and re-check its visitors' storage limits.
async fn shares_changed(st: &St, id: i64) {
    st.share.invalidate(id);
    st.share.reload(&st.store).await;
    st.engine.recheck_visitor_storage();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_urls() {
        let mut cfg = Config::default();
        assert_eq!(share_url(&cfg, "192.168.1.7:8040", "abc"), "https://192.168.1.7:8041/s/abc");
        assert_eq!(share_url(&cfg, "[fd00::7]:8040", "abc"), "https://[fd00::7]:8041/s/abc");
        cfg.share.listen = String::new();
        assert_eq!(share_url(&cfg, "pi.lan:8040", "abc"), "https://pi.lan:8040/s/abc");
        cfg.share.public_url = "https://pingrail.example.com/".into();
        assert_eq!(share_url(&cfg, "pi.lan:8040", "abc"), "https://pingrail.example.com/s/abc");
    }

    #[test]
    fn share_settings_validation() {
        let ok = clean_settings(ShareSettings { label: "  ISP  ".into(), target_ids: vec![1, 1, 99], ..Default::default() }, &[1, 2], true).unwrap();
        assert_eq!((ok.label.as_str(), ok.target_ids.clone()), ("ISP", vec![1]));
        assert!(clean_settings(ShareSettings::default(), &[1], true).is_err(), "no targets and no adding");
        let bad_cidr = ShareSettings { target_ids: vec![1], allow_private: vec!["10.0.0.0/99".into()], ..Default::default() };
        assert!(clean_settings(bad_cidr, &[1], true).is_err());
        let past = ShareSettings { target_ids: vec![1], expires_ms: Some(1), ..Default::default() };
        assert!(clean_settings(past.clone(), &[1], true).is_err());
        assert!(clean_settings(past, &[1], false).is_ok(), "editing an expired link is allowed");
    }

    #[test]
    fn proxy_client_ip() {
        let peer: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let m = h(&[("cf-connecting-ip", "41.13.2.9")]);
        let trusted = crate::http::parse_nets(&["127.0.0.1".into(), "::1".into()]);
        assert_eq!(forwarded_ip(peer, &m, &trusted).to_string(), "41.13.2.9");
        let lan: SocketAddr = "192.168.1.50:5000".parse().unwrap();
        assert_eq!(forwarded_ip(lan, &m, &trusted).to_string(), "192.168.1.50", "an untrusted LAN host can't fake its address");
        let outside: SocketAddr = "8.8.8.8:5000".parse().unwrap();
        assert_eq!(forwarded_ip(outside, &m, &trusted).to_string(), "8.8.8.8", "headers from the internet are ignored");
    }

    fn h(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in pairs {
            m.insert(*k, HeaderValue::from_static(v));
        }
        m
    }

    #[test]
    fn origin_checks() {
        assert!(same_origin(&h(&[("host", "pi:8040")]), false));
        assert!(same_origin(&h(&[("host", "pi:8040"), ("origin", "https://pi:8040")]), false));
        assert!(!same_origin(&h(&[("host", "pi:8040"), ("origin", "http://pi:8040")]), false), "https only");
        assert!(!same_origin(&h(&[("host", "pi:8040"), ("origin", "https://evil.example")]), false));
        let proxied = h(&[
            ("host", "127.0.0.1:8040"),
            ("x-forwarded-host", "pingrail.example.com"),
            ("origin", "https://pingrail.example.com"),
        ]);
        assert!(same_origin(&proxied, true));
        assert!(!same_origin(&proxied, false), "forwarded host only counts from a trusted proxy");
    }

    #[test]
    fn forwarded_host_only_from_trusted_proxies() {
        let m = h(&[("host", "pi.lan:8040"), ("x-forwarded-host", "evil.example")]);
        assert_eq!(host_of(&m, false), "pi.lan:8040");
        assert_eq!(host_of(&m, true), "evil.example");
        assert_eq!(host_of(&h(&[("host", "a b\"<x>")]), false), "localhost", "junk hosts aren't used");
    }

    #[test]
    fn cookies_and_tokens() {
        let m = h(&[("cookie", "a=1; __Host-pr_session=abc; b=2")]);
        assert_eq!(cookie_value(&m, COOKIE).as_deref(), Some("abc"));
        assert!(constant_eq(b"same", b"same"));
        assert!(!constant_eq(b"same", b"diff"));
        assert!(!constant_eq(b"short", b"longer"));
    }

    #[test]
    fn host_validation() {
        assert!(valid_host("8.8.8.8"));
        assert!(valid_host("vpn.example.com"));
        assert!(valid_host("2001:db8::1"));
        assert!(!valid_host("rm -rf /"));
        assert!(!valid_host(""));
    }
}
