//! HTTPS client for the pingrail API (used by the TUI and CLI commands).

use anyhow::{anyhow, bail, Context, Result};
use reqwest::header::{AUTHORIZATION, COOKIE, SET_COOKIE};
use reqwest::{RequestBuilder, Response, StatusCode};
use serde::de::DeserializeOwned;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use crate::model::*;

/// Returned (inside anyhow) when the server wants credentials.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Unauthorized(pub String);

#[derive(Clone, Debug)]
enum Auth {
    None,
    Token(String),
    Cookie(String),
}

#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    base: String,
    auth: Arc<RwLock<Auth>>,
    /// A certificate the last connection rejected (for a helpful error).
    rejected: Arc<Mutex<Option<crate::tls::Fingerprint>>>,
}

/// "pi:8040" or "http://pi:8040" → "https://pi:8040": pingrail only speaks HTTPS.
pub fn https_url(url: &str) -> String {
    let u = url.trim().trim_end_matches('/');
    if let Some(rest) = u.strip_prefix("http://") {
        format!("https://{rest}")
    } else if u.starts_with("https://") {
        u.to_string()
    } else {
        format!("https://{u}")
    }
}

impl Client {
    /// A client for the service at `base`, trusting certificates in `pins`,
    /// ones you approved with `pingrail trust`, or ones the system trusts.
    pub fn new(base: &str, token: Option<String>, mut pins: Vec<crate::tls::Fingerprint>) -> Result<Client> {
        let base = https_url(base);
        pins.extend(crate::tls::known_pins(&base));
        let (tls, rejected) = crate::tls::client_config(pins);
        let http = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .https_only(true)
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(120))
            .no_proxy()
            .build()?;
        let auth = match token {
            Some(t) => Auth::Token(t),
            None => Auth::None,
        };
        Ok(Client { http, base, auth: Arc::new(RwLock::new(auth)), rejected })
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    /// Explain a failed request: an untrusted certificate, an unreachable
    /// service or a timeout.
    fn conn_err(&self, e: reqwest::Error) -> anyhow::Error {
        if let Some(fp) = self.rejected.lock().unwrap().take() {
            return crate::tls::Untrusted { url: self.base.clone(), fingerprint: crate::tls::fmt_fingerprint(&fp) }.into();
        }
        if e.is_connect() {
            anyhow!("cannot reach the pingrail service at {} ({e})", self.base)
        } else if e.is_timeout() {
            anyhow!("the pingrail service did not respond in time")
        } else {
            anyhow!(e)
        }
    }

    pub fn uses_token(&self) -> bool {
        matches!(*self.auth.read().unwrap(), Auth::Token(_))
    }

    fn req(&self, method: reqwest::Method, path: &str) -> RequestBuilder {
        let rb = self.http.request(method, format!("{}{}", self.base, path));
        match &*self.auth.read().unwrap() {
            Auth::Token(t) => rb.header(AUTHORIZATION, format!("Bearer {t}")),
            Auth::Cookie(c) => rb.header(COOKIE, c.clone()),
            Auth::None => rb,
        }
    }

    async fn check(resp: Response) -> Result<Response> {
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        let msg = resp
            .json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(String::from))
            .unwrap_or_else(|| status.to_string());
        if status == StatusCode::UNAUTHORIZED {
            return Err(Unauthorized(msg).into());
        }
        Err(anyhow!(msg))
    }

    async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let r = self.req(reqwest::Method::GET, path).send().await.map_err(|e| self.conn_err(e))?;
        Ok(Self::check(r).await?.json().await?)
    }

    pub async fn health(&self) -> Result<Health> {
        let r = self.http.get(format!("{}/api/health", self.base)).send().await.map_err(|e| self.conn_err(e))?;
        let h: Health = Self::check(r).await?.json().await.context("not a pingrail server")?;
        if h.name != "pingrail" {
            bail!("not a pingrail server");
        }
        Ok(h)
    }

    pub async fn me(&self) -> Result<Me> {
        self.get_json("/api/me").await
    }

    pub async fn login(&self, username: &str, password: &str) -> Result<()> {
        let r = self
            .http
            .post(format!("{}/api/login", self.base))
            .json(&LoginRequest { username: username.into(), password: password.into() })
            .send()
            .await
            .map_err(|e| self.conn_err(e))?;
        let r = Self::check(r).await?;
        let cookie = r
            .headers()
            .get(SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .map(String::from)
            .ok_or_else(|| anyhow!("server did not start a session"))?;
        *self.auth.write().unwrap() = Auth::Cookie(cookie);
        Ok(())
    }

    pub async fn set_password(&self, username: Option<&str>, password: &str) -> Result<()> {
        let r = self
            .req(reqwest::Method::POST, "/api/password")
            .json(&PasswordRequest { username: username.map(String::from), password: password.into() })
            .send()
            .await
            .map_err(|e| self.conn_err(e))?;
        Self::check(r).await?;
        Ok(())
    }

    pub async fn passkeys(&self) -> Result<serde_json::Value> {
        self.get_json("/api/passkeys").await
    }

    pub async fn remove_passkey(&self, id: i64) -> Result<()> {
        let r = self.req(reqwest::Method::DELETE, &format!("/api/passkeys/{id}")).send().await.map_err(|e| self.conn_err(e))?;
        Self::check(r).await?;
        Ok(())
    }

    pub async fn reset_passkeys(&self) -> Result<()> {
        let r = self.req(reqwest::Method::POST, "/api/passkeys/reset").send().await.map_err(|e| self.conn_err(e))?;
        Self::check(r).await?;
        Ok(())
    }

    pub async fn tune_passwords(&self) -> Result<crate::password::Policy> {
        let r = self.req(reqwest::Method::POST, "/api/password/tune").send().await.map_err(|e| self.conn_err(e))?;
        Ok(Self::check(r).await?.json().await?)
    }

    pub async fn overview(&self, window_ms: i64, spark: usize) -> Result<Overview> {
        self.get_json(&format!("/api/overview?window_ms={window_ms}&spark={spark}")).await
    }

    pub async fn add_target(&self, t: &NewTarget) -> Result<Target> {
        let r = self.req(reqwest::Method::POST, "/api/targets").json(t).send().await.map_err(|e| self.conn_err(e))?;
        Ok(Self::check(r).await?.json().await?)
    }

    pub async fn patch_target(&self, id: i64, p: &TargetPatch) -> Result<Target> {
        let r = self
            .req(reqwest::Method::PATCH, &format!("/api/targets/{id}"))
            .json(p)
            .send()
            .await
            .map_err(|e| self.conn_err(e))?;
        Ok(Self::check(r).await?.json().await?)
    }

    pub async fn delete_target(&self, id: i64) -> Result<()> {
        let r = self.req(reqwest::Method::DELETE, &format!("/api/targets/{id}")).send().await.map_err(|e| self.conn_err(e))?;
        Self::check(r).await?;
        Ok(())
    }

    pub async fn shares(&self) -> Result<SharesResponse> {
        self.get_json("/api/shares").await
    }

    pub async fn revoke_share(&self, id: i64) -> Result<ShareInfo> {
        let r = self
            .req(reqwest::Method::POST, &format!("/api/shares/{id}/revoke"))
            .json(&serde_json::json!({}))
            .send()
            .await
            .map_err(|e| self.conn_err(e))?;
        Ok(Self::check(r).await?.json().await?)
    }

    pub async fn targets(&self) -> Result<Vec<Target>> {
        self.get_json("/api/targets").await
    }

    pub async fn detail(&self, id: i64, from: i64, to: i64, points: usize, hop: Option<u8>) -> Result<Detail> {
        let hop = hop.map(|h| format!("&hop={h}")).unwrap_or_default();
        self.get_json(&format!("/api/targets/{id}/detail?from={from}&to={to}&points={points}{hop}")).await
    }

    pub async fn report(
        &self,
        ids: &[i64],
        from: i64,
        to: i64,
        tz_offset_min: i32,
        format: ReportFormat,
    ) -> Result<Vec<u8>> {
        let list: Vec<String> = ids.iter().map(|i| i.to_string()).collect();
        let path = format!(
            "/api/report?targets={}&from={from}&to={to}&tz={tz_offset_min}&format={}",
            list.join(","),
            format.extension()
        );
        let r = self.req(reqwest::Method::GET, &path).send().await.map_err(|e| self.conn_err(e))?;
        Ok(Self::check(r).await?.bytes().await?.to_vec())
    }

    pub async fn open_session(&self) -> Result<String> {
        let r = self.req(reqwest::Method::POST, "/api/sessions").send().await.map_err(|e| self.conn_err(e))?;
        let s: SessionInfo = Self::check(r).await?.json().await?;
        Ok(s.id)
    }

    /// Returns false if the server no longer knows the session.
    pub async fn heartbeat(&self, id: &str) -> Result<bool> {
        let r = self
            .req(reqwest::Method::POST, &format!("/api/sessions/{id}/heartbeat"))
            .send()
            .await
            .map_err(|e| self.conn_err(e))?;
        if r.status() == StatusCode::NOT_FOUND {
            return Ok(false);
        }
        Self::check(r).await?;
        Ok(true)
    }

    pub async fn end_session(&self, id: &str, end: SessionEnd) -> Result<()> {
        let e = match end {
            SessionEnd::Background => "background",
            SessionEnd::Stop => "stop",
        };
        let r = self
            .req(reqwest::Method::DELETE, &format!("/api/sessions/{id}?end={e}"))
            .send()
            .await
            .map_err(|e| self.conn_err(e))?;
        Self::check(r).await?;
        Ok(())
    }
}

pub fn is_unauthorized(e: &anyhow::Error) -> bool {
    e.downcast_ref::<Unauthorized>().is_some()
}
