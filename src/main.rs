//! pingrail — multi-target ping and route monitor.

mod analysis;
mod ca;
mod client;
mod config;
mod daemon;
mod engine;
mod http;
mod migrate;
mod model;
mod netpolicy;
mod pages;
mod passkeys;
mod password;
mod probe;
mod report;
mod server;
mod service;
mod share;
mod stats;
mod store;
mod sysmem;
mod tls;
mod tui;
mod util;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use std::process::ExitCode;

use crate::client::Client;
use crate::config::{now_ms, Config, Paths};
use crate::model::{NewTarget, ReportFormat, TargetPatch};

#[derive(Parser)]
#[command(
    name = "pingrail",
    version,
    about = "Ping many hosts at once, trace their routes, and graph latency, jitter and loss.",
    after_help = "Run without a command to open the terminal UI.\n\
Examples:\n  pingrail                          open the TUI\n  pingrail --connect https://pi:8040 open the TUI against another machine's service\n  pingrail targets add 8.8.8.8      add a background target\n  pingrail export --last 24h -f pdf write a PDF report for the last day\n  sudo pingrail service install     install + start the background service (Linux)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
    #[command(flatten)]
    conn: ConnArgs,
}

#[derive(Args, Clone, Debug)]
pub struct ConnArgs {
    /// URL of a pingrail service to use, e.g. https://192.168.1.20:8040
    #[arg(long, global = true, env = "PINGRAIL_URL")]
    pub connect: Option<String>,
    /// Run a local session inside this process instead of using the background service
    #[arg(long, global = true)]
    pub local: bool,
    /// Keep config, database and token in this directory
    #[arg(long, global = true, env = "PINGRAIL_DATA_DIR", value_name = "DIR")]
    pub data_dir: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Open the terminal UI (the default)
    Tui,
    /// Install, control or run the background service
    Service {
        #[command(subcommand)]
        action: ServiceCmd,
    },
    /// Set the password for the web UI
    Passwd {
        /// Web username
        #[arg(long, default_value = "admin")]
        user: String,
        /// Generate a random password and print it
        #[arg(long)]
        generate: bool,
        /// Re-time password hashing for this machine's memory and CPU instead
        #[arg(long, conflicts_with_all = ["user", "generate"])]
        tune: bool,
    },
    /// List or remove passkeys, or remove them all so passwords sign in again
    #[command(alias = "passkey")]
    Passkeys {
        #[command(subcommand)]
        action: PasskeyCmd,
    },
    /// List, add, remove, pause or resume monitored targets
    #[command(alias = "target")]
    Targets {
        #[command(subcommand)]
        action: TargetCmd,
    },
    /// List share links or switch one off (create and edit them in the web UI)
    #[command(alias = "share")]
    Shares {
        #[command(subcommand)]
        action: ShareCmd,
    },
    /// Write a PDF or PNG report for a time range
    Export(ExportArgs),
    /// Show whether the service is running and summarise targets
    Status,
    /// Trust a pingrail service's certificate (for --connect to another machine)
    Trust {
        /// The service, e.g. https://192.168.1.20:8040
        url: String,
        /// The fingerprint you expect (as shown on that machine); skips the question
        #[arg(long)]
        fingerprint: Option<String>,
    },
    /// Version, copyright and licence
    About {
        /// Print the full Apache License 2.0 text
        #[arg(long)]
        license: bool,
        /// Print the third-party notices
        #[arg(long)]
        third_party: bool,
    },
}

#[derive(Subcommand)]
enum ServiceCmd {
    /// Run the service in the foreground (what the service manager runs)
    Run {
        /// Listen address for the web UI/API (overrides the config file)
        #[arg(long)]
        listen: Option<String>,
    },
    /// Install the service, start it now and at every boot (needs admin/root)
    Install,
    /// Stop and remove the service (needs admin/root)
    Uninstall {
        /// Also delete the database and configuration
        #[arg(long)]
        purge: bool,
    },
    /// Start the installed service
    Start,
    /// Stop the installed service
    Stop,
    /// Show the service state
    Status,
    /// Create config, data directory and token (used by packages)
    #[command(hide = true)]
    Init,
    /// Add or remove the Windows Firewall rule for the web UI (used by the installer)
    #[command(hide = true)]
    Firewall {
        #[arg(value_parser = ["add", "remove"])]
        action: String,
    },
    /// Add or remove pingrail's folder in the system PATH (Windows; used by the installer)
    #[command(hide = true)]
    Path {
        #[arg(value_parser = ["add", "remove"])]
        action: String,
    },
    /// Trust (or stop trusting) the service's certificate authority on this computer (needs admin/root)
    Trust {
        #[arg(value_parser = ["add", "remove"])]
        action: String,
    },
}

#[derive(Subcommand)]
enum PasskeyCmd {
    /// List everyone's passkeys
    List,
    /// Remove one passkey (by the number `list` shows)
    Remove { id: i64 },
    /// Remove every passkey and allow signing in with a password again
    Reset,
}

#[derive(Subcommand)]
enum TargetCmd {
    /// List targets
    List,
    /// Add a target that runs in the background
    Add {
        host: String,
        /// Display name
        #[arg(long)]
        name: Option<String>,
        /// Seconds between samples (default 2.5)
        #[arg(long)]
        interval: Option<f64>,
        /// Ping the endpoint only, without tracing the route
        #[arg(long)]
        no_trace: bool,
    },
    /// Remove a target and its history (by id, host or name)
    Remove { target: String },
    /// Pause a target
    Pause { target: String },
    /// Resume a paused target
    Resume { target: String },
}

#[derive(Subcommand)]
enum ShareCmd {
    /// List share links, what they allow and their addresses
    List,
    /// Switch a link off right away (by id or label)
    #[command(alias = "off")]
    Revoke { link: String },
}

#[derive(Clone, Copy, ValueEnum)]
enum Fmt {
    Pdf,
    Png,
}

#[derive(Args)]
struct ExportArgs {
    /// Output format
    #[arg(short, long, value_enum, default_value = "pdf")]
    format: Fmt,
    /// Report on the last period, e.g. 30m, 6h, 7d (default 1h)
    #[arg(long, conflicts_with_all = ["from"])]
    last: Option<String>,
    /// Start time, local, e.g. "2026-10-22 08:00"
    #[arg(long)]
    from: Option<String>,
    /// End time, local (default now)
    #[arg(long)]
    to: Option<String>,
    /// Target id, host or name (repeat for several; default all)
    #[arg(short = 't', long = "target")]
    targets: Vec<String>,
    /// Output file (default: a descriptive name in the current directory)
    #[arg(short, long)]
    output: Option<PathBuf>,
}

/// Where to find the service and how to authenticate to it.
#[derive(Clone, Debug)]
pub struct Conn {
    pub url: String,
    pub token: Option<String>,
    /// The user named a server explicitly (don't fall back to a local session).
    pub explicit: bool,
    pub paths: Paths,
    /// --data-dir (or PINGRAIL_DATA_DIR) was given.
    pub custom_dir: bool,
    /// This machine's service certificate, when readable (trusted as is).
    pub pins: Vec<tls::Fingerprint>,
}

impl Conn {
    /// Where a local session keeps its data: the directory you named, or
    /// your own user folder (never the service's).
    pub fn local_paths(&self) -> Paths {
        if self.custom_dir { self.paths.clone() } else { Paths::user() }
    }

    pub fn client(&self) -> Result<Client> {
        Client::new(&self.url, self.token.clone(), self.pins.clone())
    }
}

pub fn resolve_conn(c: &ConnArgs) -> Conn {
    let paths = c.data_dir.as_deref().map(Paths::in_dir).unwrap_or_else(Paths::system);
    let env_token = std::env::var("PINGRAIL_TOKEN").ok().filter(|t| !t.is_empty());
    let pins = tls::local_pins(&paths);
    if let Some(u) = &c.connect {
        let url = client::https_url(u);
        return Conn { url, token: env_token, explicit: true, paths, custom_dir: c.data_dir.is_some(), pins };
    }
    let cfg = Config::load_quiet(&paths.config_file);
    let token = env_token.or_else(|| {
        std::fs::read_to_string(paths.token_file()).ok().map(|t| t.trim().to_string()).filter(|t| !t.is_empty())
    });
    Conn {
        url: format!("https://127.0.0.1:{}", cfg.port()),
        token,
        explicit: false,
        paths,
        custom_dir: c.data_dir.is_some(),
        pins,
    }
}

fn init_logging(to_stderr: bool, file: Option<PathBuf>) {
    use tracing_subscriber::EnvFilter;
    // The system certificate check logs its own error for every untrusted
    // certificate; pingrail explains those itself.
    let filter = EnvFilter::try_from_env("PINGRAIL_LOG")
        .unwrap_or_else(|_| EnvFilter::new("info,rustls_platform_verifier=off,rustls=warn"));
    if let Some(path) = file
        && let Ok(f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_ansi(false)
                .with_writer(std::sync::Mutex::new(f))
                .try_init();
            return;
        }
    if to_stderr {
        let _ = tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr).try_init();
    }
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread().enable_all().build()?)
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("signal handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = term.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn main() -> ExitCode {
    tls::install_default_provider();
    let cli = Cli::parse();
    match real_main(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// Plain CLI commands exit quietly when their output is piped into `head`
/// and the like, instead of panicking on a closed pipe.
fn quiet_broken_pipe() {
    #[cfg(unix)]
    // SAFETY: restoring the default disposition of a signal before any
    // threads are started.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

fn real_main(cli: Cli) -> Result<()> {
    if matches!(cli.cmd, Some(Cmd::Targets { .. } | Cmd::Shares { .. } | Cmd::Status)) {
        quiet_broken_pipe();
    }
    let conn = resolve_conn(&cli.conn);
    match cli.cmd {
        None | Some(Cmd::Tui) => {
            init_logging(false, std::env::var_os("PINGRAIL_LOG").map(|_| Paths::user().data_dir.join("tui.log")));
            runtime()?.block_on(tui::run(conn, cli.conn.local))
        }
        Some(Cmd::Service { action }) => service_cmd(action, &cli.conn),
        Some(Cmd::Passkeys { action }) => {
            init_logging(true, None);
            runtime()?.block_on(passkeys_cmd(conn, cli.conn.local, action))
        }
        Some(Cmd::Passwd { tune: true, .. }) => {
            init_logging(true, None);
            runtime()?.block_on(tune_passwords(conn, cli.conn.local))
        }
        Some(Cmd::Passwd { user, generate, .. }) => {
            init_logging(true, None);
            runtime()?.block_on(passwd(conn, cli.conn.local, &user, generate))
        }
        Some(Cmd::Targets { action }) => {
            init_logging(true, None);
            runtime()?.block_on(with_client(conn, cli.conn.local, |c| Box::pin(targets_cmd(c, action))))
        }
        Some(Cmd::Shares { action }) => {
            init_logging(true, None);
            runtime()?.block_on(with_client(conn, cli.conn.local, |c| Box::pin(shares_cmd(c, action))))
        }
        Some(Cmd::Export(args)) => {
            init_logging(true, None);
            runtime()?.block_on(with_client(conn, cli.conn.local, |c| Box::pin(export_cmd(c, args))))
        }
        Some(Cmd::Trust { url, fingerprint }) => runtime()?.block_on(trust_cmd(&url, fingerprint.as_deref())),
        Some(Cmd::About { license, third_party }) => {
            use crate::server::about;
            use std::io::Write;
            let text = if license {
                server::LICENSE_TEXT.to_string()
            } else if third_party {
                server::THIRD_PARTY_TEXT.to_string()
            } else {
                format!(
                    "{} {}  ({})\n{}\nLicence: {} (Apache License, version 2.0)\nQuestions and bug reports: {}\n\n{}\n\n{}\n\n\
                     Full licence: pingrail about --license    Third-party notices: pingrail about --third-party\n",
                    about::NAME,
                    about::VERSION,
                    about::PUBLISHER,
                    about::COPYRIGHT,
                    about::LICENSE,
                    about::CONTACT,
                    about::WARRANTY,
                    about::TRADEMARK
                )
            };
            // Piped into `less` or `head`: a closed pipe isn't an error.
            let _ = std::io::stdout().lock().write_all(text.as_bytes());
            Ok(())
        }
        Some(Cmd::Status) => {
            init_logging(true, None);
            runtime()?.block_on(status_cmd(conn))
        }
    }
}

fn service_cmd(action: ServiceCmd, args: &ConnArgs) -> Result<()> {
    match action {
        ServiceCmd::Run { listen } => {
            let paths = args.data_dir.as_deref().map(Paths::in_dir).unwrap_or_else(Paths::system);
            #[cfg(windows)]
            {
                paths.ensure().ok();
                init_logging(true, Some(paths.log_file()));
                if service::run_dispatcher(paths.clone(), listen.clone())? {
                    return Ok(());
                }
            }
            init_logging(true, None);
            runtime()?.block_on(daemon::run(paths, listen, shutdown_signal()))
        }
        ServiceCmd::Install => service::install(),
        ServiceCmd::Uninstall { purge } => service::uninstall(purge),
        ServiceCmd::Start => service::start(),
        ServiceCmd::Stop => service::stop(),
        ServiceCmd::Status => {
            println!("{}", service::status()?);
            Ok(())
        }
        ServiceCmd::Firewall { action } => service::firewall(action == "add"),
        ServiceCmd::Path { action } => service::path_entry(action == "add"),
        ServiceCmd::Trust { action } => {
            service::trust_ca(action == "add")?;
            println!(
                "{} {}",
                if action == "add" { "This computer now trusts" } else { "This computer no longer trusts" },
                service::ca_file().display()
            );
            Ok(())
        }
        ServiceCmd::Init => {
            let p = service::init_files()?;
            #[cfg(unix)]
            if let Ok(exe) = std::env::current_exe() {
                service::grant_capability(&exe);
            }
            println!("initialised {}", p.data_dir.display());
            Ok(())
        }
    }
}

/// Run `f` with a client for the service, or for a temporary local engine
/// when `--local` was given.
async fn with_client<F>(conn: Conn, local: bool, f: F) -> Result<()>
where
    F: FnOnce(Client) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>>>>,
{
    if local {
        let paths = conn.paths.clone();
        let paths = if conn.explicit { paths } else { conn.local_paths() };
        let emb = daemon::Embedded::start(paths).await?;
        let client = Client::new(&emb.url, Some(emb.token.clone()), vec![emb.fingerprint])?;
        let r = f(client).await;
        emb.stop().await;
        return r;
    }
    let client = conn.client()?;
    if let Err(e) = client.health().await {
        if conn.explicit || tls::is_untrusted(&e) {
            return Err(e);
        }
        bail!("{e}\n{}\n(or add --local to use a local session)", service::start_hint());
    }
    if conn.token.is_none() || client.me().await.is_err() {
        let user = std::env::var("PINGRAIL_USER").unwrap_or_else(|_| "admin".into());
        let pw = match std::env::var("PINGRAIL_PASSWORD") {
            Ok(p) => p,
            Err(_) => {
                use std::io::IsTerminal;
                if !std::io::stdin().is_terminal() {
                    bail!(
                        "this user can't read the service's API token ({}). Run as the user who installed pingrail, \
                         or set PINGRAIL_USER and PINGRAIL_PASSWORD to the web UI login.",
                        conn.paths.token_file().display()
                    );
                }
                util::prompt_password(&format!("Password for {user} at {}: ", conn.url))?
            }
        };
        client.login(&user, &pw).await?;
    }
    f(client).await
}

/// `pingrail passkeys …`: through the running service when there is one,
/// otherwise straight in the database (so `reset` works even when the
/// service won't start or nobody can sign in).
async fn passkeys_cmd(conn: Conn, local: bool, action: PasskeyCmd) -> Result<()> {
    let client = if local {
        None
    } else {
        match conn.client() {
            Ok(c) if c.health().await.is_ok() => Some(c),
            _ => None,
        }
    };
    let open_db = || -> Result<std::sync::Arc<store::Store>> {
        let paths = if local { conn.local_paths() } else { conn.paths.clone() };
        let db = paths.db_file();
        if !db.exists() {
            bail!("the service isn't reachable and there's no database at {}", db.display());
        }
        store::Store::open(&db).with_context(|| format!("opening {}", db.display()))
    };
    match action {
        PasskeyCmd::List => {
            let rows: Vec<(i64, String, String, String, i64, Option<i64>)> = match &client {
                Some(c) => {
                    let v = c.passkeys().await?;
                    v["passkeys"]
                        .as_array()
                        .cloned()
                        .unwrap_or_default()
                        .iter()
                        .map(|p| {
                            (
                                p["id"].as_i64().unwrap_or(0),
                                p["user"].as_str().unwrap_or("").to_string(),
                                p["label"].as_str().unwrap_or("").to_string(),
                                p["rp_id"].as_str().unwrap_or("").to_string(),
                                p["created_ms"].as_i64().unwrap_or(0),
                                p["last_used_ms"].as_i64(),
                            )
                        })
                        .collect()
                }
                None => open_db()?
                    .passkeys(None, None)?
                    .into_iter()
                    .map(|r| (r.id, r.username, r.label, r.rp_id, r.created_ms, r.last_used_ms))
                    .collect(),
            };
            let required = match &client {
                Some(c) => c.passkeys().await?["required"].as_bool().unwrap_or(false),
                None => passkeys::required(&*open_db()?),
            };
            if rows.is_empty() {
                println!("No passkeys.");
            }
            for (id, user, label, rp, created, used) in rows {
                let when = |ms: i64| chrono::DateTime::from_timestamp_millis(ms).map(|d| d.with_timezone(&chrono::Local).format("%Y-%m-%d").to_string()).unwrap_or_default();
                println!(
                    "{id:>4}  {user:<12} {label:<24} {rp:<28} added {}{}",
                    when(created),
                    used.map(|u| format!(", last used {}", when(u))).unwrap_or_default()
                );
            }
            println!("Signing in {}.", if required { "needs a passkey" } else { "works with a passkey or the password" });
        }
        PasskeyCmd::Remove { id } => {
            match &client {
                Some(c) => c.remove_passkey(id).await?,
                None => {
                    if !open_db()?.delete_passkey(id, None)? {
                        bail!("no passkey {id}");
                    }
                }
            }
            println!("Removed passkey {id}.");
        }
        PasskeyCmd::Reset => {
            match &client {
                Some(c) => c.reset_passkeys().await?,
                None => passkeys::reset_store(&*open_db()?)?,
            }
            println!("Removed every passkey. Signing in works with the password again (set one with `pingrail passwd`).");
        }
    }
    Ok(())
}

/// `pingrail passwd --tune`: through the running service when there is
/// one (so it switches at once), otherwise straight in the database.
async fn tune_passwords(conn: Conn, local: bool) -> Result<()> {
    let via_api = async {
        let c = conn.client()?;
        c.health().await?;
        c.tune_passwords().await
    };
    let policy = match if local { Err(anyhow!("local")) } else { via_api.await } {
        Ok(p) => p,
        Err(e) => {
            let paths = if local { conn.local_paths() } else { conn.paths.clone() };
            let db = paths.db_file();
            if !local && !db.exists() {
                bail!("cannot reach the service ({e}) and no database at {}", db.display());
            }
            let store = store::Store::open(&db).with_context(|| format!("opening {}", db.display()))?;
            println!("Timing password hashing on this machine…");
            password::load_or_tune(&store, true)?
        }
    };
    println!("Password hashing: {}.", policy.describe());
    println!("Saved passwords switch to these settings the next time each one signs in.");
    Ok(())
}

async fn passwd(conn: Conn, local: bool, user: &str, generate: bool) -> Result<()> {
    let password = if generate {
        util::generate_password()
    } else {
        let a = util::prompt_password(&format!("New web password for '{user}': "))?;
        let b = util::prompt_password("Repeat: ")?;
        if a != b {
            bail!("passwords do not match");
        }
        a
    };
    if password.chars().count() < 8 {
        bail!("password must be at least 8 characters");
    }
    let user_owned = user.to_string();
    let pw = password.clone();
    // Prefer the running service; fall back to writing the database directly.
    let via_api = async {
        let c = conn.client()?;
        c.health().await?;
        c.set_password(Some(&user_owned), &pw).await
    };
    let api_result = if local { Err(anyhow!("local")) } else { via_api.await };
    if let Err(e) = api_result {
        let paths = if local { conn.local_paths() } else { conn.paths.clone() };
        let db = paths.db_file();
        if !local && !db.exists() && !paths.data_dir.exists() {
            bail!("cannot reach the service ({e}) and no database at {}", db.display());
        }
        let store = store::Store::open(&db).with_context(|| format!("opening {}", db.display()))?;
        let policy = password::load_or_tune(&store, false)?;
        let phc = password::Passwords::new(policy)?.hash(&password)?;
        store.set_user(user, &phc)?;
        drop(store);
        #[cfg(unix)]
        if service::is_root() && !local {
            for f in ["pingrail.db", "pingrail.db-wal", "pingrail.db-shm"] {
                let p = paths.data_dir.join(f);
                if p.exists() {
                    let _ = std::process::Command::new("chown").args(["pingrail:pingrail", &p.to_string_lossy()]).status();
                }
            }
        }
    }
    if generate {
        println!("Web UI user: {user}\nPassword:    {password}");
    } else {
        println!("Password updated for '{user}'.");
    }
    Ok(())
}

async fn find_target(c: &Client, key: &str) -> Result<model::Target> {
    let all = c.targets().await?;
    if let Ok(id) = key.parse::<i64>()
        && let Some(t) = all.iter().find(|t| t.id == id) {
            return Ok(t.clone());
        }
    let matches: Vec<_> = all
        .iter()
        .filter(|t| t.host.eq_ignore_ascii_case(key) || t.name.eq_ignore_ascii_case(key))
        .collect();
    match matches.as_slice() {
        [one] => Ok((*one).clone()),
        [] => bail!("no target matches '{key}'"),
        _ => bail!("'{key}' matches several targets; use the id from `pingrail targets list`"),
    }
}

async fn targets_cmd(c: Client, action: TargetCmd) -> Result<()> {
    match action {
        TargetCmd::List => {
            let ov = c.overview(600_000, 1).await?;
            if ov.targets.is_empty() {
                println!("No targets. Add one with: pingrail targets add <host>");
                return Ok(());
            }
            println!(
                "{:>4}  {:<24} {:<28} {:<10} {:>8} {:>8} {:>7} {:>6}",
                "ID", "NAME", "HOST", "STATE", "AVG ms", "JITTER", "LOSS %", "HOPS"
            );
            for t in ov.targets {
                let state = if !t.target.enabled {
                    "paused"
                } else if t.target.share_id.is_some() {
                    "link"
                } else if t.target.is_background() {
                    "running"
                } else {
                    "tui"
                };
                println!(
                    "{:>4}  {:<24} {:<28} {:<10} {:>8} {:>8} {:>7} {:>6}",
                    t.target.id,
                    clip(&t.target.name, 24),
                    clip(&t.target.host, 28),
                    state,
                    stats::fmt_ms(t.stats.avg_ms),
                    stats::fmt_ms(t.stats.jitter_ms),
                    if t.stats.sent > 0 { stats::fmt_pct(t.stats.loss_pct) } else { "—".into() },
                    t.live.hop_count.map(|h| h.to_string()).unwrap_or("—".into()),
                );
            }
        }
        TargetCmd::Add { host, name, interval, no_trace } => {
            let t = c
                .add_target(&NewTarget {
                    host,
                    name,
                    interval_ms: interval.map(|s| (s * 1000.0) as u32),
                    trace: Some(!no_trace),
                    session: None,
                })
                .await?;
            println!("Added #{} {} ({})", t.id, t.name, t.host);
        }
        TargetCmd::Remove { target } => {
            let t = find_target(&c, &target).await?;
            c.delete_target(t.id).await?;
            println!("Removed #{} {}", t.id, t.name);
        }
        TargetCmd::Pause { target } => {
            let t = find_target(&c, &target).await?;
            c.patch_target(t.id, &TargetPatch { enabled: Some(false), ..Default::default() }).await?;
            println!("Paused #{} {}", t.id, t.name);
        }
        TargetCmd::Resume { target } => {
            let t = find_target(&c, &target).await?;
            c.patch_target(t.id, &TargetPatch { enabled: Some(true), session: Some(None), ..Default::default() })
                .await?;
            println!("Resumed #{} {}", t.id, t.name);
        }
    }
    Ok(())
}

async fn shares_cmd(c: Client, action: ShareCmd) -> Result<()> {
    let list = c.shares().await?;
    match action {
        ShareCmd::List => {
            if list.shares.is_empty() {
                println!("No share links. Make one in the web UI: select a target and choose Share.");
                return Ok(());
            }
            let names: std::collections::HashMap<i64, String> =
                c.targets().await?.into_iter().map(|t| (t.id, t.name)).collect();
            let when = |ms: i64| util::fmt_local(ms, "%-d %b %Y %H:%M");
            for sh in &list.shares {
                let s = &sh.share.settings;
                let status = match sh.status.as_str() {
                    "revoked" => "switched off",
                    other => other,
                };
                println!("#{:<3} {}  [{status}]", sh.share.id, s.label);
                if !sh.share.revoked {
                    println!("     {}", sh.url);
                }
                let mut facts: Vec<String> = Vec::new();
                let shown: Vec<&str> = s.target_ids.iter().filter_map(|id| names.get(id).map(String::as_str)).collect();
                facts.push(if shown.is_empty() { "none of your targets".into() } else { shown.join(", ") });
                facts.push(if s.can_add {
                    format!("visitors can add up to {} ({} added)", s.max_targets, sh.share.owned_ids.len())
                } else {
                    "view only".into()
                });
                if s.can_export {
                    facts.push("reports allowed".into());
                }
                facts.push(if s.hide_private { "private hops hidden" } else { "private hops shown" }.into());
                if s.hide_public_hops > 0 {
                    facts.push(format!("first {} public hop(s) hidden", s.hide_public_hops));
                }
                if s.hide_hostnames {
                    facts.push("host names hidden".into());
                }
                match s.history {
                    model::HistoryMode::All => {}
                    model::HistoryMode::Days => facts.push(format!("last {} days of history", s.history_days)),
                    model::HistoryMode::Since => facts.push(format!("history from {}", when(sh.share.created_ms))),
                }
                match (sh.status.as_str(), s.expires_ms) {
                    ("active", Some(e)) => facts.push(format!("until {}", when(e))),
                    ("active", None) => facts.push("no time limit".into()),
                    ("expired", Some(e)) => facts.push(format!("expired {}", when(e))),
                    _ => {}
                }
                facts.push(match sh.share.last_seen_ms {
                    Some(at) if sh.share.views > 0 => format!(
                        "opened {}x, last {}{}",
                        sh.share.views,
                        when(at),
                        sh.share.last_seen_ip.as_deref().map(|ip| format!(" from {ip}")).unwrap_or_default()
                    ),
                    _ => "not opened yet".into(),
                });
                println!("     {}", facts.join(" · "));
            }
            if list.public_url.trim().is_empty() {
                println!(
                    "\nThese addresses only work on your network. To share links on the internet, point a\n\
                     Cloudflare Tunnel or reverse proxy at the share port ({}) and set public_url under\n\
                     [share] in pingrail.toml.",
                    list.share_port.map(|p| p.to_string()).unwrap_or_else(|| "the web UI port".into())
                );
            }
        }
        ShareCmd::Revoke { link } => {
            let found: Vec<&model::ShareInfo> = match link.trim_start_matches('#').parse::<i64>() {
                Ok(id) => list.shares.iter().filter(|s| s.share.id == id).collect(),
                Err(_) => list.shares.iter().filter(|s| s.share.settings.label.eq_ignore_ascii_case(link.trim())).collect(),
            };
            let sh = match found.as_slice() {
                [one] => *one,
                [] => bail!("no share link matches '{link}'; see `pingrail shares list`"),
                _ => bail!("'{link}' matches several links; use the id from `pingrail shares list`"),
            };
            if sh.share.revoked {
                println!("#{} {} is already switched off.", sh.share.id, sh.share.settings.label);
                return Ok(());
            }
            let done = c.revoke_share(sh.share.id).await?;
            println!("Switched off #{} {}. Anyone opening it now sees that it no longer works.", done.share.id, done.share.settings.label);
            if !done.share.owned_ids.is_empty() {
                println!("Destinations visitors added through it are paused (not deleted).");
            }
        }
    }
    Ok(())
}

fn clip(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut o: String = s.chars().take(n - 1).collect();
        o.push('…');
        o
    }
}

async fn export_cmd(c: Client, a: ExportArgs) -> Result<()> {
    let to = match &a.to {
        Some(t) => util::parse_local_time(t)?,
        None => now_ms(),
    };
    let from = match (&a.from, &a.last) {
        (Some(f), _) => util::parse_local_time(f)?,
        (None, Some(l)) => to - util::parse_duration_ms(l)?,
        (None, None) => to - 3_600_000,
    };
    if from >= to {
        bail!("the start time must be before the end time");
    }
    let ids: Vec<i64> = if a.targets.is_empty() {
        c.targets().await?.iter().map(|t| t.id).collect()
    } else {
        let mut v = Vec::new();
        for k in &a.targets {
            v.push(find_target(&c, k).await?.id);
        }
        v
    };
    if ids.is_empty() {
        bail!("there are no targets to report on");
    }
    let format = match a.format {
        Fmt::Pdf => ReportFormat::Pdf,
        Fmt::Png => ReportFormat::Png,
    };
    let tz = util::local_offset_min();
    let bytes = c.report(&ids, from, to, tz, format).await?;
    let out = a.output.unwrap_or_else(|| {
        PathBuf::from(report::file_name(&report::ReportRequest {
            target_ids: ids.clone(),
            from_ms: from,
            to_ms: to,
            tz_offset_min: tz,
            format,
        }))
    });
    std::fs::write(&out, bytes).with_context(|| format!("writing {}", out.display()))?;
    println!("Wrote {}", out.display());
    Ok(())
}

/// Show a service's certificate fingerprint and, once confirmed, trust it.
async fn trust_cmd(url: &str, expected: Option<&str>) -> Result<()> {
    let url = client::https_url(url);
    let (fp, authority) = tls::peer_fingerprint(&url).await?;
    let shown = tls::fmt_fingerprint(&fp);
    let what = if authority { "certificate authority" } else { "certificate" };
    println!("{url}'s {what} has the SHA-256 fingerprint\n  {shown}");
    match expected {
        Some(e) => {
            let want = tls::parse_fingerprint(e).ok_or_else(|| anyhow!("--fingerprint isn't a SHA-256 fingerprint"))?;
            if want != fp {
                bail!("that isn't the fingerprint you expected: not trusting it");
            }
        }
        None => {
            use std::io::{IsTerminal, Write};
            if !std::io::stdin().is_terminal() {
                bail!("compare it with the one shown on that machine, then run again with --fingerprint {shown}");
            }
            println!("Compare it with the one shown on that machine (`pingrail status` there, or the TUI's w screen).");
            print!("Trust it? [y/N] ");
            std::io::stdout().flush().ok();
            let mut answer = String::new();
            std::io::stdin().read_line(&mut answer)?;
            if !matches!(answer.trim(), "y" | "Y" | "yes" | "Yes") {
                bail!("not trusted");
            }
        }
    }
    let file = tls::remember(&url, &fp)?;
    println!("Trusted. (Saved in {})", file.display());
    Ok(())
}

async fn status_cmd(conn: Conn) -> Result<()> {
    #[cfg(any(unix, windows))]
    if !conn.explicit
        && let Ok(s) = service::status() {
            println!("{s}");
        }
    let c = conn.client()?;
    match c.health().await {
        Ok(h) => {
            println!("pingrail {} reachable at {}", h.version, conn.url);
            if !h.cert_sha256.is_empty() {
                println!("fingerprint to trust (SHA-256) {}", h.cert_sha256);
            }
            println!(
                "web UI listening on {} ({})",
                h.listen,
                if h.has_password { "password set" } else { "no password set yet: run `pingrail passwd`" }
            );
            if conn.token.is_some()
                && let Ok(ov) = c.overview(600_000, 1).await {
                    let running = ov.targets.iter().filter(|t| t.target.enabled).count();
                    println!("{} targets ({} running)", ov.targets.len(), running);
                }
        }
        Err(e) => println!("service not reachable at {}: {e}", conn.url),
    }
    Ok(())
}
