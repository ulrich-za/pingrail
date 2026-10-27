//! Running the engine + web server, either as the background service or
//! embedded inside a TUI session.

use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::sync::oneshot;

use crate::ca::Certs;
use crate::config::{load_or_create_token, random_hex, Config, Paths};
use crate::engine::Engine;
use crate::probe::Prober;
use crate::server::{self, AppState};
use crate::store::Store;

/// Run the service until `shutdown` resolves.
pub async fn run(
    paths: Paths,
    listen_override: Option<String>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    paths.ensure()?;
    crate::migrate::run(&paths);
    let cfg = Config::load_or_create(&paths.config_file)?;
    let token = load_or_create_token(&paths.token_file())?;
    let store = Store::open(&paths.db_file())?;
    let paused = store.pause_all_sessions()?;
    if paused > 0 {
        tracing::info!("paused {paused} foreground target(s) left over from TUI sessions");
    }
    let system = paths.data_dir == Paths::system().data_dir;
    let (certs, _) = Certs::load(&paths.data_dir, &cfg.tls, system, &crate::ca::saved_names(&store))?;
    let certs = Arc::new(certs);
    let tls = certs.server_config()?;
    let fp = crate::tls::fmt_fingerprint(&certs.pin());
    let prober = Arc::new(Prober::new().context("starting ICMP prober")?);
    let engine = Engine::start(store.clone(), prober, &cfg, Some(paths.data_dir.clone())).await?;

    let listen = listen_override.unwrap_or_else(|| cfg.web.listen.clone());
    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .with_context(|| format!("cannot listen on {listen}"))?;
    tracing::info!(
        "pingrail {} running; web UI on https://{listen}/ (data: {})",
        env!("CARGO_PKG_VERSION"),
        paths.data_dir.display()
    );
    let share_listener = match cfg.share.listen.trim() {
        "" => None,
        addr => match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => {
                tracing::info!("share links on https://{addr}/s/<code>");
                Some(l)
            }
            Err(e) => {
                tracing::warn!("share links: cannot listen on {addr} ({e}); they still work on the web UI port");
                None
            }
        },
    };
    let info = certs.info();
    if info.custom {
        tracing::info!("certificate configured in pingrail.toml, SHA-256 {fp}");
    } else {
        tracing::info!("certificate for {} from pingrail's certificate authority, SHA-256 {fp}", info.names.join(", "));
    }
    let passwords = crate::password::start(&store).await?;
    let state = AppState::new(store.clone(), engine.clone(), cfg, token, listen, certs, passwords);
    server::serve(state, listener, share_listener, tls, shutdown).await?;
    tracing::info!("shutting down");
    engine.shutdown().await;
    Ok(())
}

/// An engine + API running inside the TUI process, on a loopback port with
/// a throwaway token. Monitoring stops when the TUI exits.
pub struct Embedded {
    pub url: String,
    pub token: String,
    /// The session's certificate, which its client pins.
    pub fingerprint: crate::tls::Fingerprint,
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<Result<()>>,
}

impl Embedded {
    pub async fn start(paths: Paths) -> Result<Embedded> {
        paths.ensure()?;
        crate::migrate::run(&paths);
        let cfg = Config::load_or_create(&paths.config_file)?;
        let store = Store::open(&paths.db_file())?;
        store.pause_all_sessions()?;
        let (certs, _) = Certs::load(&paths.data_dir, &cfg.tls, false, &crate::ca::saved_names(&store))?;
        let certs = Arc::new(certs);
        let tls = certs.server_config()?;
        let prober = Arc::new(Prober::new()?);
        let engine = Engine::start(store.clone(), prober, &cfg, Some(paths.data_dir.clone())).await?;
        // No separate share port in a local session: links use this one.
        let mut cfg = cfg;
        cfg.share.listen.clear();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let token = random_hex(32);
        let fingerprint = certs.pin();
        let passwords = crate::password::start(&store).await?;
        let state = AppState::new(store, engine.clone(), cfg, token.clone(), addr.to_string(), certs, passwords);
        let (tx, rx) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            server::serve(state, listener, None, tls, async move {
                let _ = rx.await;
            })
            .await?;
            engine.shutdown().await;
            Ok(())
        });
        Ok(Embedded { url: format!("https://{addr}"), token, fingerprint, stop: Some(tx), task })
    }

    pub async fn stop(mut self) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        let _ = tokio::time::timeout(std::time::Duration::from_secs(4), &mut self.task).await;
    }
}
