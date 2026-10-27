//! Passkeys: signing in with a phone, a security key or this computer
//! instead of a password (WebAuthn, via webauthn-rs).
//!
//! A passkey belongs to the name you browse to (its "relying party"), such
//! as mypc.lan. That name must be on this server's certificate, and
//! the browser must trust the certificate: browsers refuse passkeys on IP
//! addresses and on certificate warnings.
//!
//! Only the web UI port offers passkeys; the share-link port has none of
//! these addresses. Ceremony state lives in memory for two minutes.

use axum::extract::{ConnectInfo, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::{delete, get, post};
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use webauthn_rs::prelude::*;

use crate::config::{now_ms, random_hex};
use crate::server::{need_recent, ApiError, ApiResult, Principal, St};
use crate::store::{blocking, PasskeyRow, Store};

const CEREMONY_TTL: Duration = Duration::from_secs(120);
const CEREMONY_MAX: usize = 256;
const REQUIRED_KEY: &str = "passkey_required";
const MAX_PER_USER: usize = 20;

/// Ceremonies by id, with when each began.
type Pending<V> = Mutex<HashMap<String, (Instant, V)>>;

/// Sign-ins and registrations in progress.
#[derive(Default)]
pub struct Ceremonies {
    /// Origin, state.
    sign_in: Pending<(String, DiscoverableAuthentication)>,
    /// User, origin, label, state.
    register: Pending<(String, String, String, PasskeyRegistration)>,
}

/// Keep a ceremony, dropping expired ones and, when full, the oldest.
fn keep<V>(map: &Pending<V>, id: String, v: V) {
    let mut m = map.lock().unwrap();
    m.retain(|_, (at, _)| at.elapsed() < CEREMONY_TTL);
    if m.len() >= CEREMONY_MAX
        && let Some(oldest) = m.iter().min_by_key(|(_, (at, _))| *at).map(|(k, _)| k.clone())
    {
        m.remove(&oldest);
    }
    m.insert(id, (Instant::now(), v));
}

fn take<V>(map: &Pending<V>, id: &str) -> Option<V> {
    let (at, v) = map.lock().unwrap().remove(id)?;
    (at.elapsed() < CEREMONY_TTL).then_some(v)
}

/// Is a passkey needed to sign in?
pub fn required(s: &Store) -> bool {
    s.meta_get(REQUIRED_KEY).ok().flatten().as_deref() == Some("1")
}

/// Why passkeys can't be used at this address.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case", tag = "reason", content = "name")]
pub enum Unavailable {
    /// Browsed to by IP address (browsers refuse passkeys there).
    Address,
    /// A name that isn't on the certificate (yet).
    NotOnCertificate(String),
    /// A certificate configured in pingrail.toml doesn't list it.
    Custom(String),
}

/// The relying party for this request: the host name browsed to, which
/// must be on the certificate, and the exact origin.
pub fn relying_party(st: &St, headers: &HeaderMap) -> Result<(String, Url), Unavailable> {
    let h = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_ascii_lowercase())
        .unwrap_or_default();
    if h.starts_with('[') {
        return Err(Unavailable::Address);
    }
    let (name, port) = match h.rsplit_once(':') {
        Some((n, p)) => (n.to_string(), p.parse::<u16>().ok()),
        None => (h.clone(), None),
    };
    if !crate::util::valid_dns_name(&name) {
        return Err(Unavailable::Address);
    }
    if !st.certs.dns_names().contains(&name) {
        return Err(if st.certs.info().custom { Unavailable::Custom(name) } else { Unavailable::NotOnCertificate(name) });
    }
    let origin = match port {
        Some(p) if p != 443 => format!("https://{name}:{p}"),
        _ => format!("https://{name}"),
    };
    let url = Url::parse(&origin).map_err(|_| Unavailable::Address)?;
    Ok((name, url))
}

fn webauthn(rp_id: &str, origin: &Url) -> ApiResult<Webauthn> {
    WebauthnBuilder::new(rp_id, origin)
        .and_then(|b| b.rp_name("pingrail").timeout(CEREMONY_TTL).build())
        .map_err(|e| ApiError::bad(format!("passkeys: {e}")))
}

fn here(st: &St, headers: &HeaderMap) -> ApiResult<(String, Url)> {
    relying_party(st, headers).map_err(|e| {
        ApiError::bad(match e {
            Unavailable::Address => "Passkeys need a name, not an IP address. Open pingrail by its name.".to_string(),
            Unavailable::NotOnCertificate(n) | Unavailable::Custom(n) => format!("{n} isn't on this server's certificate yet."),
        })
    })
}

fn cred_key(id: &CredentialID) -> String {
    serde_json::to_value(id).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default()
}

/// Ask the browser for a discoverable passkey where it can (the account
/// lives on the authenticator, so the sign-in page needs no username).
fn prefer_resident(ccr: &CreationChallengeResponse) -> ApiResult<serde_json::Value> {
    let mut v = serde_json::to_value(ccr).map_err(anyhow::Error::from)?;
    if let Some(sel) = v.pointer_mut("/publicKey/authenticatorSelection").and_then(|s| s.as_object_mut()) {
        sel.insert("residentKey".into(), "preferred".into());
    }
    Ok(v)
}

pub fn routes() -> Router<St> {
    Router::new()
        .route("/api/passkey/sign-in", post(sign_in_start))
        .route("/api/passkey/sign-in/finish", post(sign_in_finish))
}

pub fn auth_routes() -> Router<St> {
    Router::new()
        .route("/api/passkeys", get(list))
        .route("/api/passkeys/register", post(register_start))
        .route("/api/passkeys/register/finish", post(register_finish))
        .route("/api/passkeys/{id}", delete(remove))
        .route("/api/passkeys/required", post(set_required))
        .route("/api/passkeys/reset", post(reset))
}

// ----- signing in --------------------------------------------------------------

#[derive(Serialize)]
struct Ceremony<T> {
    ceremony: String,
    options: T,
}

async fn sign_in_start(
    State(st): State<St>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let ip = crate::server::client_ip(&st, peer, &headers);
    if let Some(refused) = crate::server::sign_in_gate(&st, ip).await {
        return Ok(refused);
    }
    let (rp_id, origin) = here(&st, &headers)?;
    let w = webauthn(&rp_id, &origin)?;
    let (options, state) = w.start_discoverable_authentication().map_err(|e| ApiError::bad(format!("passkeys: {e}")))?;
    let id = random_hex(16);
    keep(&st.ceremonies.sign_in, id.clone(), (origin.to_string(), state));
    use axum::response::IntoResponse;
    Ok(Json(Ceremony { ceremony: id, options }).into_response())
}

#[derive(Deserialize)]
struct SignInFinish {
    ceremony: String,
    credential: PublicKeyCredential,
}

async fn sign_in_finish(
    State(st): State<St>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<SignInFinish>,
) -> ApiResult<Response> {
    let ip = crate::server::client_ip(&st, peer, &headers);
    let (rp_id, origin) = here(&st, &headers)?;
    let refused = || ApiError(StatusCode::UNAUTHORIZED, "That passkey isn't one this server knows. Try another, or your password.".into());
    let Some((was_origin, state)) = take(&st.ceremonies.sign_in, &req.ceremony) else {
        return Err(ApiError::bad("The passkey request expired. Try again."));
    };
    if was_origin != origin.as_str() {
        return Err(refused());
    }
    let w = webauthn(&rp_id, &origin)?;
    let Ok((uuid, _)) = w.identify_discoverable_authentication(&req.credential) else {
        crate::server::sign_in_failed(&st, ip).await;
        return Err(refused());
    };
    let (u, rp) = (uuid.to_string(), rp_id.clone());
    let found = blocking(&st.store, move |s| {
        let Some(user) = s.user_by_uuid(&u)? else { return Ok(None) };
        let rows = s.passkeys(Some(&user), Some(&rp))?;
        Ok(Some((user, rows)))
    })
    .await?;
    let Some((user, rows)) = found else {
        crate::server::sign_in_failed(&st, ip).await;
        return Err(refused());
    };
    let keys: Vec<(PasskeyRow, Passkey)> =
        rows.into_iter().filter_map(|r| serde_json::from_str::<Passkey>(&r.passkey).ok().map(|p| (r, p))).collect();
    let discoverable: Vec<DiscoverableKey> = keys.iter().map(|(_, p)| p.into()).collect();
    let result = match w.finish_discoverable_authentication(&req.credential, state, &discoverable) {
        Ok(r) => r,
        Err(e) => {
            tracing::info!("passkey sign-in refused for {user}: {e}");
            crate::server::sign_in_failed(&st, ip).await;
            return Err(refused());
        }
    };
    if let Some((row, mut pk)) = keys.into_iter().find(|(_, p)| p.cred_id() == result.cred_id()) {
        let updated = pk.update_credential(&result) == Some(true);
        let json = updated.then(|| serde_json::to_string(&pk).ok()).flatten();
        blocking(&st.store, move |s| s.passkey_used(row.id, json.as_deref())).await?;
    }
    crate::server::start_session(&st, ip, &headers, user).await
}

// ----- managing passkeys -----------------------------------------------------------

#[derive(Serialize)]
struct PasskeyView {
    id: i64,
    label: String,
    rp_id: String,
    created_ms: i64,
    last_used_ms: Option<i64>,
    /// Works at the address you're on now.
    here: bool,
    /// Whose it is (only listed for the API token).
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<String>,
}

#[derive(Serialize)]
struct Overview {
    /// The name passkeys belong to here, or why there is none.
    rp_id: Option<String>,
    unavailable: Option<Unavailable>,
    required: bool,
    /// Signed in recently enough to make changes.
    recent: bool,
    /// Milliseconds of that left.
    recent_left_ms: i64,
    passkeys: Vec<PasskeyView>,
}

async fn overview(st: &St, p: &Principal, headers: &HeaderMap) -> ApiResult<Overview> {
    let rp = relying_party(st, headers);
    let rp_id = rp.as_ref().ok().map(|(id, _)| id.clone());
    let user = (p.via != "token").then(|| p.user.clone());
    let (rows, required) = blocking(&st.store, move |s| Ok((s.passkeys(user.as_deref(), None)?, required(s)))).await?;
    let token = p.via == "token";
    Ok(Overview {
        unavailable: rp.err(),
        required,
        recent: p.recent(),
        recent_left_ms: if token { i64::MAX } else { (crate::server::RECENT_MS - (now_ms() - p.auth_ms)).max(0) },
        passkeys: rows
            .into_iter()
            .map(|r| PasskeyView {
                here: rp_id.as_deref() == Some(r.rp_id.as_str()),
                id: r.id,
                label: r.label,
                rp_id: r.rp_id,
                created_ms: r.created_ms,
                last_used_ms: r.last_used_ms,
                user: token.then_some(r.username),
            })
            .collect(),
        rp_id,
    })
}

async fn list(State(st): State<St>, Extension(p): Extension<Principal>, headers: HeaderMap) -> ApiResult<Json<Overview>> {
    Ok(Json(overview(&st, &p, &headers).await?))
}

#[derive(Deserialize)]
struct RegisterStart {
    #[serde(default)]
    label: String,
}

async fn register_start(
    State(st): State<St>,
    Extension(p): Extension<Principal>,
    headers: HeaderMap,
    Json(req): Json<RegisterStart>,
) -> ApiResult<Json<Ceremony<serde_json::Value>>> {
    if p.via == "token" {
        return Err(ApiError::bad("add passkeys from the web UI"));
    }
    need_recent(&p)?;
    let (rp_id, origin) = here(&st, &headers)?;
    let label = match crate::util::clean_text(&req.label, 40) {
        l if l.is_empty() => "Passkey".to_string(),
        l => l,
    };
    let (user, rp) = (p.user.clone(), rp_id.clone());
    let (uuid, existing) = blocking(&st.store, move |s| {
        let uuid = s.user_uuid(&user)?;
        Ok((uuid, s.passkeys(Some(&user), Some(&rp))?))
    })
    .await?;
    let Some(uuid) = uuid.and_then(|u| Uuid::parse_str(&u).ok()) else {
        return Err(ApiError::bad("set a password for this user first"));
    };
    if existing.len() >= MAX_PER_USER {
        return Err(ApiError::bad(format!("at most {MAX_PER_USER} passkeys per user; remove one first")));
    }
    let exclude: Vec<CredentialID> = existing
        .iter()
        .filter_map(|r| serde_json::from_str::<Passkey>(&r.passkey).ok())
        .map(|pk| pk.cred_id().clone())
        .collect();
    let w = webauthn(&rp_id, &origin)?;
    let (options, state) = w
        .start_passkey_registration(uuid, &p.user, &p.user, Some(exclude))
        .map_err(|e| ApiError::bad(format!("passkeys: {e}")))?;
    let options = prefer_resident(&options)?;
    let id = random_hex(16);
    keep(&st.ceremonies.register, id.clone(), (p.user.clone(), origin.to_string(), label, state));
    Ok(Json(Ceremony { ceremony: id, options }))
}

#[derive(Deserialize)]
struct RegisterFinish {
    ceremony: String,
    credential: RegisterPublicKeyCredential,
}

async fn register_finish(
    State(st): State<St>,
    Extension(p): Extension<Principal>,
    headers: HeaderMap,
    Json(req): Json<RegisterFinish>,
) -> ApiResult<Json<Overview>> {
    need_recent(&p)?;
    let (rp_id, origin) = here(&st, &headers)?;
    let Some((user, was_origin, label, state)) = take(&st.ceremonies.register, &req.ceremony) else {
        return Err(ApiError::bad("The passkey request expired. Try again."));
    };
    if user != p.user || was_origin != origin.as_str() {
        return Err(ApiError::bad("That passkey request was for someone else."));
    }
    let w = webauthn(&rp_id, &origin)?;
    let pk = w
        .finish_passkey_registration(&req.credential, &state)
        .map_err(|e| ApiError::bad(format!("The passkey couldn't be added ({e}).")))?;
    let json = serde_json::to_string(&pk).map_err(anyhow::Error::from)?;
    let cred = cred_key(pk.cred_id());
    let keep_cookie = crate::server::session_cookie(&headers);
    let u = p.user.clone();
    blocking(&st.store, move |s| {
        s.add_passkey(&u, &rp_id, &cred, &json, &label)?;
        // A new way in: other sessions must sign in again.
        s.end_other_sessions(&u, keep_cookie.as_deref())?;
        Ok(())
    })
    .await
    .map_err(|e| if format!("{e:#}").contains("UNIQUE") { ApiError::bad("That passkey is already added.") } else { e.into() })?;
    tracing::info!("passkey added for {}", p.user);
    Ok(Json(overview(&st, &p, &headers).await?))
}

async fn remove(
    State(st): State<St>,
    Extension(p): Extension<Principal>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> ApiResult<Json<Overview>> {
    need_recent(&p)?;
    let user = (p.via != "token").then(|| p.user.clone());
    let keep_cookie = crate::server::session_cookie(&headers);
    let outcome = blocking(&st.store, move |s| {
        let mine = s.passkeys(user.as_deref(), None)?;
        let Some(row) = mine.iter().find(|r| r.id == id) else { return Ok(Err("not found")) };
        // Keep a way in: with passkeys required, the owner's last one stays.
        if required(s) && s.passkeys(Some(&row.username), None)?.len() <= 1 {
            return Ok(Err("last"));
        }
        s.delete_passkey(id, user.as_deref())?;
        s.end_other_sessions(&row.username, keep_cookie.as_deref())?;
        Ok(Ok(()))
    })
    .await?;
    match outcome {
        Ok(()) => Ok(Json(overview(&st, &p, &headers).await?)),
        Err("last") => Err(ApiError::bad("This is the last passkey. Turn off “Require a passkey” before removing it.")),
        Err(_) => Err(ApiError::not_found()),
    }
}

#[derive(Deserialize)]
struct Required {
    on: bool,
}

async fn set_required(
    State(st): State<St>,
    Extension(p): Extension<Principal>,
    headers: HeaderMap,
    Json(req): Json<Required>,
) -> ApiResult<Json<Overview>> {
    need_recent(&p)?;
    if req.on {
        // Only with a passkey that works where you are now, so you can't
        // lock yourself out from here.
        let (rp_id, _) = here(&st, &headers)?;
        let u = p.user.clone();
        let have = blocking(&st.store, move |s| Ok(s.passkeys(Some(&u), Some(&rp_id))?.len())).await?;
        if have == 0 {
            return Err(ApiError::bad("Add a passkey that works here first."));
        }
    }
    let on = req.on;
    let (u, keep_cookie) = (p.user.clone(), crate::server::session_cookie(&headers));
    blocking(&st.store, move |s| {
        s.meta_set(REQUIRED_KEY, if on { "1" } else { "0" })?;
        // Sessions that began with the password end; this one stays.
        if on {
            s.end_other_sessions(&u, keep_cookie.as_deref())?;
        }
        Ok(())
    })
    .await?;
    tracing::info!("passkeys {} to sign in", if on { "now required" } else { "no longer required" });
    Ok(Json(overview(&st, &p, &headers).await?))
}

/// `pingrail passkeys reset`: remove every passkey and let passwords sign
/// in again. Only the API token (this machine) may.
async fn reset(State(st): State<St>, Extension(p): Extension<Principal>) -> ApiResult<StatusCode> {
    if p.via != "token" {
        return Err(ApiError(StatusCode::FORBIDDEN, "run `pingrail passkeys reset` on the server".into()));
    }
    blocking(&st.store, reset_store).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Remove every passkey and turn off the requirement.
pub fn reset_store(s: &Store) -> anyhow::Result<()> {
    let n = s.delete_all_passkeys()?;
    s.meta_set(REQUIRED_KEY, "0")?;
    tracing::info!("removed {n} passkey(s); passwords can sign in again");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ceremonies_expire_and_are_single_use() {
        let m: Pending<u32> = Mutex::default();
        keep(&m, "a".into(), 1);
        assert_eq!(take(&m, "a"), Some(1));
        assert_eq!(take(&m, "a"), None);
        for i in 0..(CEREMONY_MAX as u32 + 10) {
            keep(&m, format!("k{i}"), i);
        }
        assert_eq!(m.lock().unwrap().len(), CEREMONY_MAX);
        assert_eq!(take(&m, "k0"), None, "oldest dropped when full");
        m.lock().unwrap().insert("old".into(), (Instant::now() - CEREMONY_TTL - Duration::from_secs(1), 9));
        assert_eq!(take(&m, "old"), None, "expired");
    }
}
