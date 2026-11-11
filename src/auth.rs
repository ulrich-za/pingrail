//! Signing in to the web UI, through doorward: passwords, passkeys,
//! sessions, rate limits and the security log.
//!
//! pingrail decides where and how people sign in; doorward enforces it:
//!
//! - **Addresses:** every name and IP address on this server's certificate,
//!   at the web UI port. A browser can't use the web UI at any other name
//!   without a certificate warning, and doorward refuses sign-ins there.
//! - **Passkeys** at every name (browsers refuse them on IP addresses).
//! - **"Require a passkey"** turns passwords off at every name and leaves
//!   the IP addresses out.
//!
//! The list follows the certificate (a name added in the web UI, a new
//! address from DHCP), so the doorkeeper is rebuilt when it changes.
//! Sessions live in the database and carry on. Each request keeps the
//! doorkeeper it started with (see [`pin`]).
//!
//! Accounts, passkeys and sessions are kept in doorward's own `auth_`
//! tables in pingrail's database. pingrail 0.3 kept accounts and passkeys
//! itself; they are moved across once, keeping their passwords and passkeys.

use anyhow::{anyhow, Context, Result};
use axum::extract::{Path as UrlPath, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use axum::routing::{delete, get, post};
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use doorward::store::{PasskeyRecord, Store as AuthStore, StoreError, UserRecord};
use doorward::{Address, Doorward, ErrorCode, IpNet, NewUser, SessionLengths, Username, Uuid};

use crate::ca::Certs;
use crate::config::{now_ms, Config};
use crate::server::{ApiError, ApiResult, Principal, St};
use crate::store::{blocking, Store};

/// pingrail's setting: passkeys needed to sign in ("1"), kept in its meta table.
pub const REQUIRED_KEY: &str = "passkey_required";
/// The same cookie name as pingrail 0.3, so its old cookies are replaced.
const SESSION_COOKIE: &str = "__Host-pr_session";
const DEVICE_COOKIE: &str = "__Host-pr_device";
/// Every pingrail account is the monitor's owner.
pub const ROLE: &str = "admin";

/// What pingrail tells doorward besides the addresses.
#[derive(Clone, Debug)]
pub struct Settings {
    /// The web UI's port.
    pub port: u16,
    /// How long a session lasts (the web UI keeps you signed in this long).
    pub session_hours: u32,
    /// Proxies whose forwarding headers are believed (share.trusted_proxies).
    pub trusted: Vec<IpNet>,
}

impl Settings {
    pub fn new(cfg: &Config, port: u16) -> Settings {
        let trusted = cfg
            .share
            .trusted_proxies
            .iter()
            .filter_map(|p| match IpNet::parse(p.trim()) {
                Ok(n) => Some(n),
                Err(_) => {
                    tracing::warn!("share.trusted_proxies: '{p}' isn't an address or range; ignored");
                    None
                }
            })
            .collect();
        Settings { port, session_hours: cfg.web.session_hours.clamp(1, 24 * 366), trusted }
    }
}

/// The doorkeeper in force, rebuilt when the addresses change.
pub struct Auth {
    store: Arc<dyn AuthStore>,
    settings: Settings,
    current: RwLock<Doorward>,
    /// The addresses `current` was built with.
    shape: Mutex<String>,
    rebuilding: tokio::sync::Mutex<()>,
}

tokio::task_local! {
    /// The doorkeeper this request started with.
    static PINNED: Doorward;
}

/// Middleware: the request keeps one doorkeeper from start to finish, even
/// if the addresses change meanwhile (a request's view of its address is an
/// index into the doorkeeper's list).
pub async fn pin(State(st): State<St>, req: Request, next: Next) -> Response {
    PINNED.scope(st.auth.latest(), next.run(req)).await
}

/// The doorkeeper for this request.
pub fn dw(st: &St) -> Doorward {
    PINNED.try_with(Clone::clone).unwrap_or_else(|_| st.auth.latest())
}

impl Auth {
    /// Open doorward's tables (moving pingrail 0.3's accounts across the
    /// first time) and build the doorkeeper for this certificate. Times
    /// password hashing on the very first start (a second or two).
    pub async fn start(db: &Path, store: &Arc<Store>, certs: &Certs, settings: Settings) -> Result<Arc<Auth>> {
        let auth_store = open_store(db, store).await?;
        let addrs = addresses(certs, &settings, required(store).await);
        let shape = shape_of(&addrs);
        let dw = build(auth_store.clone(), addrs, &settings).await?;
        tracing::info!("sign-in at {}", origins(&dw));
        Ok(Arc::new(Auth {
            store: auth_store,
            settings,
            current: RwLock::new(dw),
            shape: Mutex::new(shape),
            rebuilding: tokio::sync::Mutex::new(()),
        }))
    }

    /// The doorkeeper in force now.
    pub fn latest(&self) -> Doorward {
        self.current.read().unwrap().clone()
    }

    /// After the certificate or the passkey setting changed: rebuild the
    /// doorkeeper if its addresses differ.
    pub async fn refresh(&self, store: &Arc<Store>, certs: &Certs) -> Result<()> {
        let _one = self.rebuilding.lock().await;
        let addrs = addresses(certs, &self.settings, required(store).await);
        let shape = shape_of(&addrs);
        if *self.shape.lock().unwrap() == shape {
            return Ok(());
        }
        let dw = build(self.store.clone(), addrs, &self.settings).await?;
        tracing::info!("sign-in now at {}", origins(&dw));
        *self.current.write().unwrap() = dw;
        *self.shape.lock().unwrap() = shape;
        Ok(())
    }
}

/// The doorkeeper without the service, for `pingrail passwd` and
/// `pingrail passkeys` on the machine when the service isn't running.
pub async fn offline(db: &Path) -> Result<Doorward> {
    let store = Store::open(db)?;
    let auth_store = open_store(db, &store).await?;
    let settings = Settings { port: 443, session_hours: 1, trusted: Vec::new() };
    build(auth_store, vec![Address::new("https://localhost").map_err(|e| anyhow!("{e}"))?], &settings).await
}

/// doorward's tables, upgraded, with pingrail 0.3's accounts moved in.
async fn open_store(db: &Path, store: &Arc<Store>) -> Result<Arc<dyn AuthStore>> {
    let auth_store: Arc<dyn AuthStore> = Arc::new(
        doorward_sqlite::SqliteStore::open(db).map_err(|e| anyhow!("opening sign-in tables in {}: {e}", db.display()))?,
    );
    auth_store.migrate().await.map_err(|e| anyhow!("upgrading sign-in tables: {e}"))?;
    move_accounts(store, &auth_store).await.context("moving pingrail 0.3's accounts to doorward")?;
    Ok(auth_store)
}

async fn required(store: &Arc<Store>) -> bool {
    blocking(store, |s| s.meta_get(REQUIRED_KEY)).await.ok().flatten().as_deref() == Some("1")
}

fn origin(port: u16, host: &str) -> String {
    if port == 443 { format!("https://{host}") } else { format!("https://{host}:{port}") }
}

/// Where sign-in happens, and how, for this certificate.
fn addresses(certs: &Certs, s: &Settings, required: bool) -> Vec<Address> {
    let lengths = SessionLengths::new(None, Duration::from_secs(s.session_hours as u64 * 3600), true);
    let mut out: Vec<Address> = Vec::new();
    let add = |out: &mut Vec<Address>, a: Address| {
        if !out.iter().any(|b| b.origin() == a.origin()) {
            out.push(a);
        }
    };
    for name in certs.dns_names() {
        // Wildcards and names doorward can't check (such as with `_`) are
        // left out.
        if let Ok(a) = Address::new(&origin(s.port, &name)) {
            add(&mut out, a.passkeys(true).passwords(!required).sessions(lengths).remembered(None));
        }
    }
    if !required {
        for ip in certs.info().addresses {
            let host = if ip.contains(':') { format!("[{ip}]") } else { ip };
            if let Ok(a) = Address::new(&origin(s.port, &host)) {
                add(&mut out, a.sessions(lengths).remembered(None));
            }
        }
    }
    if out.is_empty()
        && let Ok(a) = Address::new(&origin(s.port, "localhost"))
    {
        add(&mut out, a.passkeys(true).passwords(!required).sessions(lengths).remembered(None));
    }
    out
}

fn shape_of(addrs: &[Address]) -> String {
    addrs
        .iter()
        .map(|a| format!("{} {} {}", a.origin(), a.allows_passwords(), a.allows_passkeys()))
        .collect::<Vec<_>>()
        .join("\n")
}

fn origins(dw: &Doorward) -> String {
    dw.addresses().iter().map(|a| a.origin()).collect::<Vec<_>>().join(", ")
}

async fn build(store: Arc<dyn AuthStore>, addrs: Vec<Address>, s: &Settings) -> Result<Doorward> {
    let mut b = Doorward::builder_shared(store)
        .trusted_proxies(s.trusted.iter().copied())
        .cookie_name(SESSION_COOKIE)
        .device_cookie_name(DEVICE_COOKIE)
        .app_name("pingrail")
        .refuse_password_words(["pingrail"]);
    for a in addrs {
        b = b.address(a);
    }
    b.build().await.map_err(|e| anyhow!("starting sign-in: {e}"))
}

/// A random (version 4) UUID.
fn random_uuid() -> Result<Uuid> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| anyhow!("random: {e}"))?;
    Ok(uuid::Builder::from_random_bytes(b).into_uuid())
}

/// Move pingrail 0.3's accounts and passkeys into doorward's tables, then
/// drop pingrail's. Passwords keep working (the same Argon2id hashes) and so
/// do passkeys (each account keeps its passkey user handle as its id).
/// Safe to run again after an interruption: what is already there is kept.
async fn move_accounts(store: &Arc<Store>, auth: &Arc<dyn AuthStore>) -> Result<()> {
    let Some((users, keys)) = blocking(store, |s| s.legacy_accounts()).await? else { return Ok(()) };
    let e = |e: StoreError| anyhow!("{e}");
    let now = now_ms();
    let mut ids: Vec<(String, Uuid)> = Vec::new();
    for u in &users {
        let name = match Username::parse(&u.username) {
            Ok(n) => n,
            Err(_) => {
                tracing::warn!("account '{}' can't be kept (its name isn't allowed now); set a new one with `pingrail passwd`", u.username);
                continue;
            }
        };
        if let Some(existing) = auth.user_by_key(name.key()).await.map_err(e)? {
            ids.push((u.username.clone(), existing.id));
            continue;
        }
        let id = match u.uuid.as_deref().map(Uuid::parse_str) {
            Some(Ok(id)) => id,
            _ => random_uuid()?,
        };
        let rec = UserRecord {
            id,
            username: name.as_str().to_string(),
            username_key: name.key().to_string(),
            username_skeleton: name.skeleton().to_string(),
            display_name: name.as_str().to_string(),
            active: true,
            created_ms: now,
            roles: vec![ROLE.to_string()],
        };
        auth.insert_user(&rec).await.map_err(e)?;
        auth.set_password(id, &u.phc, now).await.map_err(e)?;
        ids.push((u.username.clone(), id));
    }
    let mut moved = 0;
    for k in &keys {
        let Some((_, user_id)) = ids.iter().find(|(n, _)| *n == k.username) else { continue };
        let rec = PasskeyRecord {
            id: random_uuid()?,
            user_id: *user_id,
            rp_id: k.rp_id.clone(),
            cred_id: k.cred_id.clone(),
            passkey_json: k.passkey.clone(),
            label: k.label.clone(),
            created_ms: k.created_ms,
            last_used_ms: k.last_used_ms,
        };
        match auth.insert_passkey(&rec).await {
            Ok(()) => moved += 1,
            Err(StoreError::Conflict(_)) => {} // moved by an earlier, interrupted run
            Err(err) => return Err(e(err)),
        }
    }
    blocking(store, |s| s.drop_legacy_accounts()).await?;
    tracing::info!("moved {} account(s) and {moved} passkey(s) to doorward; everyone signs in once", ids.len());
    Ok(())
}

// ----- words -------------------------------------------------------------------

/// A doorward refusal in words, for the command line and pingrail's own
/// endpoints (the web UI words doorward's own endpoints itself).
pub fn words(e: &doorward::Error) -> &'static str {
    match e.code() {
        ErrorCode::Busy => "the service is busy; try again in a moment",
        ErrorCode::PasswordTooShort => "use at least 8 characters",
        ErrorCode::PasswordTooLong => "use at most 256 characters",
        ErrorCode::PasswordTooCommon => {
            "that password is too easy to guess (it's a common one, or contains the username or “pingrail”); choose another"
        }
        ErrorCode::InvalidCredentials => "wrong username or password",
        ErrorCode::PasskeyNotRecognised => "that passkey isn't one this server knows",
        ErrorCode::TooManyAttempts => "too many attempts; wait a moment and try again",
        ErrorCode::NotSignedIn => "sign in first",
        ErrorCode::NeedsRecentSignIn => "confirm it's you first",
        ErrorCode::CrossOrigin => "refused: the request came from another site",
        ErrorCode::AddressNotAllowed => "pingrail doesn't take sign-ins at this address",
        ErrorCode::PasswordsDisabledHere => "this server needs a passkey to sign in",
        ErrorCode::PasskeysUnavailableHere => "passkeys don't work at this address",
        ErrorCode::CeremonyExpired => "the passkey request expired; try again",
        ErrorCode::UsernameInvalid => "a username is 1 to 64 letters, digits and . _ - @ +",
        ErrorCode::UsernameTaken => "that username is taken",
        ErrorCode::AccountDisabled => "this account is switched off",
        ErrorCode::LastPasskey => "that's the last passkey that works there; turn off “Require a passkey” first",
        ErrorCode::TooManyPasskeys => "at most 20 passkeys; remove one first",
        ErrorCode::PasskeyAlreadyAdded => "that passkey is already added",
        ErrorCode::PasskeyRejected => "the passkey couldn't be used",
        ErrorCode::NotFound => "not found",
        ErrorCode::Forbidden => "not allowed",
        ErrorCode::Internal => "something went wrong; the service log has the details",
        _ => "the request was refused",
    }
}

/// A doorward refusal as a JSON error from pingrail's own endpoints.
pub fn api_error(e: doorward::Error) -> ApiError {
    let code = e.code();
    if code == ErrorCode::Internal {
        tracing::error!("sign-in: {e}");
    }
    let status = StatusCode::from_u16(code.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    ApiError(status, words(&e).into())
}

/// A doorward refusal for the command line.
pub fn cli_error(e: doorward::Error) -> anyhow::Error {
    if e.code() == ErrorCode::Internal { anyhow!("{e}") } else { anyhow!("{}", words(&e)) }
}

// ----- accounts (the command line and pingrail's own endpoints) -----------------

/// Set `username`'s password, making the account if there's none yet. Every
/// session of theirs ends.
pub async fn set_password(dw: &Doorward, username: &str, password: &str) -> Result<(), doorward::Error> {
    match dw.user_by_username(username).await? {
        Some(u) => dw.set_password(u.id, password).await,
        None => dw
            .create_user(NewUser {
                username: username.to_string(),
                password: Some(password.to_string().into()),
                roles: vec![ROLE.to_string()],
                ..Default::default()
            })
            .await
            .map(|_| ()),
    }
}

/// Is there an account at all?
pub async fn has_users(dw: &Doorward) -> bool {
    dw.users().await.is_ok_and(|u| !u.is_empty())
}

/// Everyone's passkeys, with whose each is.
pub async fn all_passkeys(dw: &Doorward) -> Result<Vec<PasskeyView>, doorward::Error> {
    let mut out = Vec::new();
    for u in dw.users().await? {
        for k in dw.user_passkeys(u.id).await? {
            out.push(PasskeyView::of(k, Some(u.username.clone())));
        }
    }
    out.sort_by_key(|k| k.created_ms);
    Ok(out)
}

/// Remove every passkey and let passwords sign in again (`pingrail passkeys
/// reset`). Returns how many were removed.
pub async fn reset_passkeys(dw: &Doorward, store: &Arc<Store>) -> Result<usize> {
    let mut n = 0;
    for u in dw.users().await.map_err(cli_error)? {
        n += dw.remove_all_passkeys(u.id).await.map_err(cli_error)?;
    }
    blocking(store, |s| s.meta_set(REQUIRED_KEY, "0")).await?;
    tracing::info!("removed {n} passkey(s); passwords can sign in again");
    Ok(n)
}

/// Remove the passkey whose id starts with `prefix` (at least 4 characters,
/// matching one passkey). With passkeys required, someone's last one stays.
pub async fn remove_passkey(dw: &Doorward, store: &Arc<Store>, prefix: &str) -> Result<PasskeyView> {
    let prefix = prefix.trim().to_ascii_lowercase();
    if prefix.len() < 4 {
        anyhow::bail!("give at least the first 4 characters of the passkey's id (see `pingrail passkeys list`)");
    }
    let all = all_passkeys(dw).await.map_err(cli_error)?;
    let found: Vec<&PasskeyView> = all.iter().filter(|k| k.id.starts_with(&prefix)).collect();
    let k = match found.as_slice() {
        [k] => (*k).clone(),
        [] => anyhow::bail!("no passkey {prefix}"),
        _ => anyhow::bail!("{prefix} matches more than one passkey; give more of its id"),
    };
    let user = dw.user_by_username(k.user.as_deref().unwrap_or("")).await.map_err(cli_error)?.ok_or_else(|| anyhow!("no passkey {prefix}"))?;
    if required(store).await && all.iter().filter(|p| p.user == k.user).count() <= 1 {
        anyhow::bail!("that's {}'s last passkey and passkeys are required; run `pingrail passkeys reset` instead", user.username);
    }
    let id = Uuid::parse_str(&k.id).map_err(|_| anyhow!("no passkey {prefix}"))?;
    if !dw.store().delete_passkey(id, user.id).await.map_err(|e| anyhow!("{e}"))? {
        anyhow::bail!("no passkey {prefix}");
    }
    tracing::info!("removed passkey {} ({}) of {}", k.label, k.rp_id, user.username);
    Ok(k)
}

// ----- the web UI's passkey settings (pingrail's part) --------------------------

/// Passkeys in the web UI's list.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasskeyView {
    pub id: String,
    pub label: String,
    /// The name it works at.
    pub rp_id: String,
    pub created_ms: i64,
    pub last_used_ms: Option<i64>,
    /// Works at the address you're on now.
    pub here: bool,
    /// Whose it is (listed for the command line only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

impl PasskeyView {
    fn of(k: doorward::passkey::PasskeyInfo, user: Option<String>) -> PasskeyView {
        PasskeyView {
            id: k.id.to_string(),
            label: k.label,
            rp_id: k.rp_id,
            created_ms: k.created_ms,
            last_used_ms: k.last_used_ms,
            here: k.here,
            user,
        }
    }
}

/// Why passkeys can't be used at this address.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case", tag = "reason")]
pub enum Unavailable {
    /// Browsed to by IP address (browsers refuse passkeys there).
    Address,
}

#[derive(Serialize)]
pub struct Overview {
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

pub fn routes() -> Router<St> {
    Router::new()
        .route("/api/passkeys", get(list))
        .route("/api/passkeys/required", post(set_required))
        .route("/api/passkeys/reset", post(reset))
        .route("/api/passkeys/{id}", delete(remove_by_token))
}

async fn overview(st: &St, p: &Principal) -> ApiResult<Overview> {
    let dw = dw(st);
    let required = required(&st.store).await;
    let Some(a) = &p.session else {
        // The API token (this machine): everyone's.
        return Ok(Overview {
            rp_id: None,
            unavailable: None,
            required,
            recent: true,
            recent_left_ms: i64::MAX,
            passkeys: all_passkeys(&dw).await.map_err(api_error)?,
        });
    };
    let here = dw.address_info(&a.visit);
    let host = here.origin.trim_start_matches("https://").rsplit_once(':').map_or(here.origin.trim_start_matches("https://"), |(h, _)| h).to_string();
    let passkeys = dw.passkeys(&a.visit, &a.session).await.map_err(api_error)?;
    Ok(Overview {
        unavailable: (!here.passkeys).then_some(Unavailable::Address),
        rp_id: here.passkeys.then_some(host),
        required,
        recent: dw.is_recent(&a.session),
        recent_left_ms: dw.recent_left(&a.session).as_millis().min(i64::MAX as u128) as i64,
        passkeys: passkeys.into_iter().map(|k| PasskeyView::of(k, None)).collect(),
    })
}

async fn list(State(st): State<St>, Extension(p): Extension<Principal>) -> ApiResult<Json<Overview>> {
    Ok(Json(overview(&st, &p).await?))
}

#[derive(Deserialize)]
struct Required {
    on: bool,
}

/// Turn "Require a passkey" on or off. On: only with a passkey that works
/// where you are, so you can't lock yourself out from here, and every other
/// session ends.
async fn set_required(
    State(st): State<St>,
    Extension(p): Extension<Principal>,
    Json(req): Json<Required>,
) -> ApiResult<Json<Overview>> {
    let Some(a) = &p.session else {
        return Err(ApiError::bad("change this in the web UI"));
    };
    let dw = dw(&st);
    dw.require_recent(&a.session).map_err(api_error)?;
    if req.on && !dw.passkeys(&a.visit, &a.session).await.map_err(api_error)?.iter().any(|k| k.here) {
        return Err(ApiError::bad("Add a passkey that works here first."));
    }
    let on = req.on;
    blocking(&st.store, move |s| s.meta_set(REQUIRED_KEY, if on { "1" } else { "0" })).await?;
    st.auth.refresh(&st.store, &st.certs).await?;
    if on {
        // Sessions that began with the password end; this one stays.
        dw.end_other_sessions(&a.visit, &a.session).await.map_err(api_error)?;
    }
    tracing::info!("passkeys {} to sign in", if on { "now required" } else { "no longer required" });
    Ok(Json(overview(&st, &p).await?))
}

/// `pingrail passkeys reset`: only the API token (this machine) may.
async fn reset(State(st): State<St>, Extension(p): Extension<Principal>) -> ApiResult<StatusCode> {
    if p.via != "token" {
        return Err(ApiError(StatusCode::FORBIDDEN, "run `pingrail passkeys reset` on the server".into()));
    }
    reset_passkeys(&dw(&st), &st.store).await?;
    st.auth.refresh(&st.store, &st.certs).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `pingrail passkeys remove`: only the API token. (The web UI removes its
/// own through doorward's `/auth/passkeys/{id}`.)
async fn remove_by_token(
    State(st): State<St>,
    Extension(p): Extension<Principal>,
    UrlPath(id): UrlPath<String>,
) -> ApiResult<Json<PasskeyView>> {
    if p.via != "token" {
        return Err(ApiError(StatusCode::FORBIDDEN, "remove passkeys in the web UI's Passkeys dialog".into()));
    }
    Ok(Json(remove_passkey(&dw(&st), &st.store, &id).await.map_err(|e| ApiError::bad(format!("{e:#}")))?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuids_are_random_version_4() {
        let a = random_uuid().unwrap();
        assert_eq!(a.get_version_num(), 4);
        assert_ne!(a, random_uuid().unwrap());
    }

    #[test]
    fn origins_leave_out_the_default_port() {
        assert_eq!(origin(443, "pc.lan"), "https://pc.lan");
        assert_eq!(origin(8040, "[fd00::7]"), "https://[fd00::7]:8040");
    }
}
