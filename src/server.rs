//! HTTP API and web UI.
//!
//! Authentication: either `Authorization: Bearer <api token>` (used by the TUI
//! and CLI on the same machine; the token lives in the service's data
//! directory) or a doorward session, signed in with a password or a passkey
//! through `/auth/…` (see `auth`).

use anyhow::Result;
use axum::body::Body;
use axum::extract::{ConnectInfo, FromRef, FromRequestParts, Path, Query, Request, State};
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
use crate::report::{self, ReportRequest};
use crate::store::{blocking, Store};

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
    /// Signing in (doorward).
    pub auth: Arc<crate::auth::Auth>,
    /// The certificate this service presents, and its authority.
    pub certs: Arc<crate::ca::Certs>,
    /// SHA-256 fingerprint of what clients pin (the authority).
    pub cert_sha256: String,
    pub share: crate::share::ShareState,
    /// Proxies whose forwarded-for headers are believed.
    pub trusted: Vec<(IpAddr, u8)>,
}

impl St {
    pub fn new(
        store: Arc<Store>,
        engine: Arc<Engine>,
        cfg: Config,
        token: String,
        listen: String,
        certs: Arc<crate::ca::Certs>,
        auth: Arc<crate::auth::Auth>,
    ) -> St {
        let cfg_trusted = cfg.share.trusted_proxies.clone();
        St(Arc::new(AppState {
            store,
            engine,
            cfg,
            token,
            listen,
            tui_sessions: Mutex::new(HashMap::new()),
            auth,
            cert_sha256: crate::tls::fmt_fingerprint(&certs.pin()),
            certs,
            share: crate::share::ShareState::default(),
            trusted: crate::http::parse_nets(&cfg_trusted),
        }))
    }
}

/// The routers' state.
#[derive(Clone)]
pub struct St(pub Arc<AppState>);

impl std::ops::Deref for St {
    type Target = AppState;
    fn deref(&self) -> &AppState {
        &self.0
    }
}

/// doorward's extractors and endpoints find the doorkeeper this way: the one
/// the request started with.
impl FromRef<St> for doorward::Doorward {
    fn from_ref(st: &St) -> doorward::Doorward {
        crate::auth::dw(st)
    }
}

#[derive(Clone, Debug)]
pub struct Principal {
    pub user: String,
    pub via: &'static str,
    /// The doorward session, when signed in through the web UI.
    pub session: Option<doorward::axum::Authenticated>,
    /// Signed in (or confirmed it was them) in the last ten minutes.
    recent: bool,
}

impl Principal {
    /// Signed in recently enough to change sign-in settings (the API token
    /// always is: it's this machine).
    pub fn recent(&self) -> bool {
        self.via == "token" || self.recent
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
        .route("/api/password", post(set_password))
        .route("/api/password/tune", post(tune_passwords))
        .route("/api/overview", get(overview).layer(middleware::from_fn(crate::http::gzip_json)))
        .route("/api/targets", get(list_targets).post(add_target))
        .route("/api/targets/{id}", axum::routing::patch(patch_target).delete(delete_target))
        .route("/api/targets/{id}/detail", get(detail).layer(middleware::from_fn(crate::http::gzip_json)))
        .route("/api/report", get(report_handler))
        .route("/api/sessions", post(open_session))
        .route("/api/sessions/{id}/heartbeat", post(heartbeat))
        .route("/api/sessions/{id}", axum::routing::delete(end_session))
        .route("/api/certificate", get(certificate_info))
        .route("/api/certificate/names", post(add_certificate_name))
        .route("/api/qr", get(qr))
        .merge(crate::auth::routes())
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
        .nest("/auth", doorward::axum::routes())
        .merge(api)
        .merge(crate::share::routes())
        .fallback(not_found)
        .layer(middleware::from_fn_with_state(state.clone(), crate::auth::pin))
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
        r = r.route(v.script_path(), get(move |h: HeaderMap| async move { asset(&h, crate::pages::pages().share_js(v), "text/javascript; charset=utf-8") }));
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
            // Sign-in follows the certificate's names and addresses.
            if let Err(e) = renew_state.auth.refresh(&renew_state.store, &renew_state.certs).await {
                tracing::warn!("updating sign-in addresses failed: {e:#}");
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
            if ticks % 120 == 2 {
                // Every ten minutes: expired sessions, old log lines.
                if let Err(e) = reaper_state.auth.latest().upkeep().await {
                    tracing::warn!("sign-in upkeep failed: {e}");
                }
            }
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
/// the address it reports.
pub fn client_ip(st: &AppState, peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
    forwarded_ip(peer, headers, &st.trusted)
}

/// IPv4 addresses written as IPv6 (`::ffff:a.b.c.d`) as plain IPv4.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

/// From a trusted proxy: the right-most `X-Forwarded-For` entry that isn't
/// itself a trusted proxy (everything left of it could have been written by
/// the visitor), or `CF-Connecting-IP` when there's no `X-Forwarded-For`
/// (cloudflared sends both). From anyone else, the connection's address.
fn forwarded_ip(peer: SocketAddr, headers: &HeaderMap, trusted: &[(IpAddr, u8)]) -> IpAddr {
    let p = canonical(peer.ip());
    if !crate::http::in_nets(p, trusted) {
        return p;
    }
    let mut entries: Vec<&str> = Vec::new();
    for v in headers.get_all("x-forwarded-for") {
        let Ok(v) = v.to_str() else { return p };
        entries.extend(v.split(','));
    }
    for e in entries.iter().rev() {
        match e.trim().parse::<IpAddr>() {
            Ok(ip) if !crate::http::in_nets(canonical(ip), trusted) => return canonical(ip),
            Ok(_) => continue,
            Err(_) => return p,
        }
    }
    if entries.is_empty() {
        let mut cf = headers.get_all("cf-connecting-ip").iter();
        if let (Some(v), None) = (cf.next(), cf.next())
            && let Some(ip) = v.to_str().ok().and_then(|v| v.trim().parse::<IpAddr>().ok())
        {
            return canonical(ip);
        }
    }
    p
}

// ----- auth ---------------------------------------------------------------

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Who is asking: this machine (the API token in the service's data
/// folder) or someone signed in through doorward. doorward refuses requests
/// to addresses that aren't on its list, writes from other sites, and
/// expired or ended sessions.
async fn auth(State(st): State<St>, req: Request, next: Next) -> Response {
    if let Some(bearer) = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        if !constant_eq(bearer.trim().as_bytes(), st.token.as_bytes()) {
            return ApiError(StatusCode::UNAUTHORIZED, "invalid API token".into()).into_response();
        }
        let mut req = req;
        req.extensions_mut().insert(Principal { user: "local".into(), via: "token", session: None, recent: true });
        return next.run(req).await;
    }
    let (mut parts, body) = req.into_parts();
    match doorward::axum::Authenticated::from_request_parts(&mut parts, &st).await {
        Ok(a) => {
            let recent = crate::auth::dw(&st).is_recent(&a.session);
            let user = a.session.user.username.clone();
            parts.extensions.insert(Principal { user, via: "session", session: Some(a), recent });
            next.run(Request::from_parts(parts, body)).await
        }
        Err(e) => e.into_response(),
    }
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

fn asset(req: &HeaderMap, body: &'static str, ctype: &'static str) -> Response {
    crate::http::packed(body).response(req, ctype, true)
}

fn font(body: &'static [u8]) -> Response {
    ([(header::CONTENT_TYPE, "font/woff2"), (header::CACHE_CONTROL, "max-age=604800")], body).into_response()
}

/// The admin UI.
pub async fn index(h: HeaderMap) -> Response {
    asset(&h, &crate::pages::pages().admin_html, "text/html; charset=utf-8")
}
pub async fn favicon_ico() -> Response {
    ([(header::CONTENT_TYPE, "image/x-icon"), (header::CACHE_CONTROL, "max-age=86400")], FAVICON_ICO).into_response()
}
pub async fn touch_icon() -> Response {
    ([(header::CONTENT_TYPE, "image/png"), (header::CACHE_CONTROL, "max-age=86400")], TOUCH_ICON).into_response()
}
pub async fn license_txt(h: HeaderMap) -> Response {
    asset(&h, LICENSE_TEXT, "text/plain; charset=utf-8")
}
pub async fn third_party_txt(h: HeaderMap) -> Response {
    asset(&h, THIRD_PARTY_TEXT, "text/plain; charset=utf-8")
}
pub async fn app_js(h: HeaderMap) -> Response {
    asset(&h, &crate::pages::pages().admin_js, "text/javascript; charset=utf-8")
}
pub async fn app_css(h: HeaderMap) -> Response {
    asset(&h, APP_CSS, "text/css; charset=utf-8")
}
pub async fn favicon(h: HeaderMap) -> Response {
    asset(&h, FAVICON, "image/svg+xml")
}

// ----- handlers -----------------------------------------------------------

/// Whether anyone can sign in yet, and what the sign-in page should offer
/// at the address it was asked on (public: the sign-in page needs it).
async fn health(
    State(st): State<St>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
) -> ApiResult<Json<Health>> {
    let dw = crate::auth::dw(&st);
    let here = dw
        .visit(&doorward::RequestInfo { peer: peer.ip(), method: &method, host: None, headers: &headers })
        .ok()
        .map(|v| dw.address_info(&v));
    // Elsewhere: where sign-in works (the names first; they're on the
    // certificate every visitor is shown anyway).
    let open_at = if here.is_some() {
        Vec::new()
    } else {
        // Names before addresses, the most specific first, localhost last.
        let mut v: Vec<&doorward::Address> = dw.addresses().iter().collect();
        v.sort_by_key(|a| {
            let h = a.host();
            let ip = h.starts_with('[') || h.parse::<IpAddr>().is_ok();
            (ip, h == "localhost", usize::MAX - h.matches('.').count(), a.origin().to_string())
        });
        v.into_iter().map(|a| a.origin().to_string()).take(4).collect()
    };
    Ok(Json(Health {
        name: "pingrail".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        has_password: crate::auth::has_users(&dw).await,
        listen: st.listen.clone(),
        cert_sha256: st.cert_sha256.clone(),
        passkeys: here.as_ref().is_some_and(|a| a.passkeys),
        passkey_required: here.as_ref().is_some_and(|a| !a.passwords),
        here: here.is_some(),
        open_at,
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
    /// The name you're using, and whether the certificate has it.
    host: Option<String>,
    host_covered: bool,
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

/// Put another name for this machine on its certificate (from Set up a
/// phone). Signing in then works at that name too, so it must lead to this
/// machine and needs a recent sign-in. A name the authority doesn't cover
/// means a new authority, which devices must trust again.
async fn add_certificate_name(
    State(st): State<St>,
    Extension(p): Extension<Principal>,
    Json(req): Json<NameRequest>,
) -> ApiResult<Json<crate::ca::Refreshed>> {
    if st.certs.info().custom {
        return Err(ApiError::bad("this server uses a certificate configured in pingrail.toml"));
    }
    if !p.recent() {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "Adding a name needs a recent sign-in. Sign out and in again, then retry".into(),
        ));
    }
    let name = req.name.trim().trim_end_matches('.').to_ascii_lowercase();
    if !crate::util::valid_dns_name(&name) {
        return Err(ApiError::bad(format!("{name} isn't a name pingrail can use")));
    }
    // Only names that lead here: anything else would let sign-in (and a
    // new authority) vouch for somewhere that isn't this machine.
    if !st.certs.dns_names().contains(&name) {
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
    // Sign-in works at the new name too.
    st.auth.refresh(&st.store, &st.certs).await?;
    Ok(Json(changed))
}

/// What the sign-in page measures its round trip with: nothing to read, and
/// cheap enough to answer every second.
async fn ping() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn me(State(st): State<St>, Extension(p): Extension<Principal>) -> ApiResult<Json<Me>> {
    let has_password = crate::auth::has_users(&crate::auth::dw(&st)).await;
    Ok(Json(Me { user: p.user, via: p.via.into(), has_password }))
}

/// `pingrail passwd` and the terminal UI's P: set a password on this
/// machine (the API token), making the account if needed. Every session of
/// that user ends. (Signed-in users change their own through doorward's
/// `/auth/password`, which needs the current one.)
async fn set_password(
    State(st): State<St>,
    Extension(p): Extension<Principal>,
    Json(req): Json<PasswordRequest>,
) -> ApiResult<StatusCode> {
    if p.via != "token" {
        return Err(ApiError(StatusCode::FORBIDDEN, "change your password in the web UI's menu".into()));
    }
    let username = req.username.as_deref().map(str::trim).filter(|u| !u.is_empty()).unwrap_or("admin");
    crate::auth::set_password(&crate::auth::dw(&st), username, &req.password)
        .await
        .map_err(crate::auth::api_error)?;
    tracing::info!("password set for {username}");
    Ok(StatusCode::NO_CONTENT)
}

/// Re-time password hashing for this machine (`pingrail passwd --tune`).
/// Only the API token may ask: it takes a second or two of full CPU.
async fn tune_passwords(State(st): State<St>, Extension(p): Extension<Principal>) -> ApiResult<Json<serde_json::Value>> {
    if p.via != "token" {
        return Err(ApiError(StatusCode::FORBIDDEN, "run `pingrail passwd --tune` on the server".into()));
    }
    let policy = crate::auth::dw(&st).retune_hashing().await.map_err(crate::auth::api_error)?;
    Ok(Json(serde_json::json!({ "describe": policy.describe() })))
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
    let mut ov = blocking(&st.store, move |s| {
        analysis::overview(s, &|id| engine.live(id), thresholds, now_ms(), window, spark)
    })
    .await?;
    ov.dns = st.engine.dns.view();
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
    crate::store::purge_soon(&st.store);
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
        // X-Forwarded-For: the right-most entry the proxy added, not what the
        // visitor wrote in front of it.
        let spoofed = h(&[("x-forwarded-for", "10.0.0.1, 41.13.2.9"), ("cf-connecting-ip", "10.0.0.2")]);
        assert_eq!(forwarded_ip(peer, &spoofed, &trusted).to_string(), "41.13.2.9");
        let chained = h(&[("x-forwarded-for", "41.13.2.9, 127.0.0.1")]);
        assert_eq!(forwarded_ip(peer, &chained, &trusted).to_string(), "41.13.2.9", "our own proxies are skipped");
        let junk = h(&[("x-forwarded-for", "41.13.2.9, nonsense")]);
        assert_eq!(forwarded_ip(peer, &junk, &trusted).to_string(), "127.0.0.1", "unreadable: the proxy itself");
        let mapped = h(&[("x-forwarded-for", "::ffff:41.13.2.9")]);
        assert_eq!(forwarded_ip(peer, &mapped, &trusted).to_string(), "41.13.2.9");
    }

    fn h(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in pairs {
            m.insert(*k, HeaderValue::from_static(v));
        }
        m
    }

    #[test]
    fn forwarded_host_only_from_trusted_proxies() {
        let m = h(&[("host", "pi.lan:8040"), ("x-forwarded-host", "evil.example")]);
        assert_eq!(host_of(&m, false), "pi.lan:8040");
        assert_eq!(host_of(&m, true), "evil.example");
        assert_eq!(host_of(&h(&[("host", "a b\"<x>")]), false), "localhost", "junk hosts aren't used");
    }

    #[test]
    fn tokens() {
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
