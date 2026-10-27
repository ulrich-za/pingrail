//! Terminal UI. Always talks to an engine over the HTTP API: either the
//! background service, or an engine embedded in this process when the
//! service isn't running ("local session").

mod input;
mod ui;
mod widgets;

use anyhow::{bail, Result};
use ratatui::crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers,
    MouseEventKind,
};
use ratatui::crossterm::execute;
use ratatui::layout::Rect;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

use crate::client::{is_unauthorized, Client};
use crate::config::{now_ms, Paths};
use crate::daemon::Embedded;
use crate::model::*;
use crate::report::{self, ReportRequest};
use crate::util;
use crate::Conn;
use input::Input;

/// Selectable view windows.
pub const WINDOWS: &[(i64, &str)] = &[
    (60_000, "1 min"),
    (300_000, "5 min"),
    (600_000, "10 min"),
    (1_800_000, "30 min"),
    (3_600_000, "1 h"),
    (10_800_000, "3 h"),
    (21_600_000, "6 h"),
    (43_200_000, "12 h"),
    (86_400_000, "24 h"),
    (172_800_000, "48 h"),
    (604_800_000, "7 days"),
    (2_592_000_000, "30 days"),
];
const DEFAULT_WINDOW: usize = 2;

#[derive(Debug, Clone, PartialEq)]
pub enum Mode {
    /// `cert`: the service's certificate fingerprint, shown on the w screen.
    Service { url: String, listen: String, cert: String },
    Local { url: String, reason: String, cert: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Targets,
    Hops,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToastLevel {
    Info,
    Warn,
    Error,
}

pub struct Toast {
    pub text: String,
    pub level: ToastLevel,
    pub at: Instant,
}

pub struct TargetForm {
    pub editing: Option<i64>,
    pub host: Input,
    pub name: Input,
    pub interval: Input,
    pub trace: bool,
    pub background: bool,
    pub field: usize,
    pub error: Option<String>,
    pub busy: bool,
}

pub const RANGE_CHOICES: &[&str] = &["Current view", "Last 1 h", "Last 24 h", "Last 7 days", "Custom"];
pub const FORMAT_CHOICES: &[&str] = &["PDF", "PNG", "PDF + PNG"];

pub struct ExportForm {
    pub range: usize,
    pub from: Input,
    pub to: Input,
    pub all: bool,
    pub format: usize,
    pub dir: Input,
    pub field: usize,
    pub error: Option<String>,
    pub busy: bool,
}

pub struct PasswordForm {
    pub p1: Input,
    pub p2: Input,
    pub field: usize,
    pub error: Option<String>,
    pub busy: bool,
    pub first_run: bool,
}

pub struct LoginForm {
    pub user: Input,
    pub pass: Input,
    pub field: usize,
    pub error: Option<String>,
    pub busy: bool,
}

pub enum Popup {
    Help,
    About,
    Target(TargetForm),
    ConfirmDelete { id: i64, name: String },
    Export(ExportForm),
    Password(PasswordForm),
    Login(LoginForm),
    Web,
    Quit { foreground: usize },
    Message { title: String, body: String, fatal: bool },
}

pub enum Msg {
    Overview(Result<Overview>),
    Detail(i64, u64, Result<Detail>),
    Me(Result<Me>),
    Session(Result<String>),
    Heartbeat(Result<bool>),
    TargetSaved(Result<Target>, bool),
    Action(Result<String>),
    Exported(Result<Vec<PathBuf>>),
    LoggedIn(Result<()>),
    PasswordSet(Result<()>),
    SessionEnded,
}

pub struct App {
    pub client: Client,
    pub mode: Mode,
    pub tx: mpsc::UnboundedSender<Msg>,
    pub session: Option<String>,
    pub ready: bool,
    pub has_password: bool,
    pub overview: Option<Overview>,
    pub overview_err: Option<String>,
    pub detail: Option<Detail>,
    pub selected: usize,
    pub selected_id: Option<i64>,
    pub hop_selected: usize,
    pub focus: Focus,
    pub window: usize,
    /// End of the viewed range; None = live.
    pub view_end: Option<i64>,
    pub popup: Option<Popup>,
    pub toast: Option<Toast>,
    pub timeline_buckets: usize,
    pub targets_area: Rect,
    pub targets_offset: usize,
    inflight_ov: bool,
    inflight_detail: bool,
    detail_gen: u64,
    last_ov: Option<Instant>,
    last_detail: Option<Instant>,
    last_heartbeat: Instant,
    pub quit: bool,
    quitting: bool,
}

impl App {
    fn new(client: Client, mode: Mode, tx: mpsc::UnboundedSender<Msg>) -> App {
        App {
            client,
            mode,
            tx,
            session: None,
            ready: false,
            has_password: true,
            overview: None,
            overview_err: None,
            detail: None,
            selected: 0,
            selected_id: None,
            hop_selected: 0,
            focus: Focus::Targets,
            window: DEFAULT_WINDOW,
            view_end: None,
            popup: None,
            toast: None,
            timeline_buckets: 120,
            targets_area: Rect::default(),
            targets_offset: 0,
            inflight_ov: false,
            inflight_detail: false,
            detail_gen: 0,
            last_ov: None,
            last_detail: None,
            last_heartbeat: Instant::now(),
            quit: false,
            quitting: false,
        }
    }

    pub fn is_local(&self) -> bool {
        matches!(self.mode, Mode::Local { .. })
    }

    pub fn window_ms(&self) -> i64 {
        WINDOWS[self.window].0
    }

    pub fn view_range(&self) -> (i64, i64) {
        let to = self.view_end.unwrap_or_else(|| now_ms() + 1);
        (to - self.window_ms(), to)
    }

    pub fn targets(&self) -> &[TargetOverview] {
        self.overview.as_ref().map(|o| o.targets.as_slice()).unwrap_or(&[])
    }

    pub fn selected_target(&self) -> Option<&TargetOverview> {
        self.targets().get(self.selected)
    }

    pub fn thresholds(&self) -> Thresholds {
        self.overview.as_ref().map(|o| o.thresholds).unwrap_or_default()
    }

    pub fn toast(&mut self, level: ToastLevel, text: impl Into<String>) {
        self.toast = Some(Toast { text: text.into(), level, at: Instant::now() });
    }

    /// The hop whose latency the timeline shows (when the route table has focus).
    pub fn graph_hop(&self) -> Option<u8> {
        if self.focus != Focus::Hops {
            return None;
        }
        self.detail.as_ref().and_then(|d| d.hops.get(self.hop_selected)).map(|h| h.ttl)
    }

    fn refresh_interval(&self) -> Duration {
        let w = self.window_ms();
        Duration::from_millis(match w {
            w if w <= 3_600_000 => 1000,
            w if w <= 21_600_000 => 3000,
            w if w <= 172_800_000 => 10_000,
            _ => 30_000,
        })
    }

    fn spawn<F>(&self, fut: F)
    where
        F: std::future::Future<Output = Msg> + Send + 'static,
    {
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let _ = tx.send(fut.await);
        });
    }

    fn mark_detail_dirty(&mut self) {
        self.last_detail = None;
        self.detail_gen += 1;
        self.inflight_detail = false;
    }

    fn tick(&mut self) {
        if let Some(t) = &self.toast
            && t.at.elapsed() > Duration::from_secs(6) {
                self.toast = None;
            }
        if !self.ready || self.quitting {
            return;
        }
        let iv = self.refresh_interval();
        if !self.inflight_ov && self.last_ov.is_none_or(|t| t.elapsed() >= iv) {
            self.inflight_ov = true;
            self.last_ov = Some(Instant::now());
            let c = self.client.clone();
            let w = self.window_ms();
            self.spawn(async move { Msg::Overview(c.overview(w, 60).await) });
        }
        if let Some(id) = self.selected_id {
            let due = self.last_detail.is_none_or(|t| t.elapsed() >= iv);
            if !self.inflight_detail && due {
                self.inflight_detail = true;
                self.last_detail = Some(Instant::now());
                let c = self.client.clone();
                let (from, to) = self.view_range();
                let buckets = self.timeline_buckets.max(10);
                let generation = self.detail_gen;
                let hop = self.graph_hop();
                self.spawn(async move { Msg::Detail(id, generation, c.detail(id, from, to, buckets, hop).await) });
            }
        }
        if let Some(s) = &self.session
            && self.last_heartbeat.elapsed() >= Duration::from_secs(10) {
                self.last_heartbeat = Instant::now();
                let c = self.client.clone();
                let s = s.clone();
                self.spawn(async move { Msg::Heartbeat(c.heartbeat(&s).await) });
            }
    }

    fn after_auth(&mut self) {
        self.ready = true;
        if !self.is_local() {
            let c = self.client.clone();
            self.spawn(async move { Msg::Session(c.open_session().await) });
        }
        if self.client.uses_token() {
            let c = self.client.clone();
            self.spawn(async move { Msg::Me(c.me().await) });
        }
    }

    fn on_msg(&mut self, msg: Msg) {
        match msg {
            Msg::Overview(r) => {
                self.inflight_ov = false;
                match r {
                    Ok(ov) => {
                        self.overview_err = None;
                        self.overview = Some(ov);
                        self.fix_selection();
                    }
                    Err(e) if is_unauthorized(&e) => self.need_login(),
                    Err(e) => self.overview_err = Some(format!("{e:#}")),
                }
            }
            Msg::Detail(id, generation, r) => {
                if generation != self.detail_gen {
                    return;
                }
                self.inflight_detail = false;
                match r {
                    Ok(d) if Some(id) == self.selected_id => {
                        let n = d.hops.len();
                        self.detail = Some(d);
                        if self.hop_selected >= n {
                            self.hop_selected = n.saturating_sub(1);
                        }
                    }
                    Ok(_) => {}
                    Err(e) if is_unauthorized(&e) => self.need_login(),
                    Err(_) => {}
                }
            }
            Msg::Me(r) => match r {
                Ok(me) => {
                    self.has_password = me.has_password;
                    if !me.has_password && self.popup.is_none() {
                        self.popup = Some(Popup::Password(PasswordForm {
                            p1: Input::masked(),
                            p2: Input::masked(),
                            field: 0,
                            error: None,
                            busy: false,
                            first_run: true,
                        }));
                    }
                }
                Err(e) if is_unauthorized(&e) => self.need_login(),
                Err(_) => {}
            },
            Msg::Session(r) => match r {
                Ok(id) => self.session = Some(id),
                Err(e) => self.toast(ToastLevel::Warn, format!("could not register this TUI session: {e:#}")),
            },
            Msg::Heartbeat(r) => {
                if let Ok(false) = r {
                    // The service forgot us (e.g. it restarted): our foreground
                    // targets were paused. Register again.
                    self.toast(ToastLevel::Warn, "Session expired on the service; foreground targets were paused.");
                    let c = self.client.clone();
                    self.spawn(async move { Msg::Session(c.open_session().await) });
                }
            }
            Msg::TargetSaved(r, added) => {
                match r {
                    Ok(t) => {
                        self.popup = None;
                        self.toast(ToastLevel::Info, if added { format!("Added {}", t.name) } else { format!("Saved {}", t.name) });
                        self.selected_id = Some(t.id);
                        self.mark_detail_dirty();
                        self.detail = None;
                        self.last_ov = None;
                    }
                    Err(e) => {
                        if let Some(Popup::Target(f)) = &mut self.popup {
                            f.busy = false;
                            f.error = Some(format!("{e:#}"));
                        } else {
                            self.toast(ToastLevel::Error, format!("{e:#}"));
                        }
                    }
                }
            }
            Msg::Action(r) => {
                match r {
                    Ok(t) => self.toast(ToastLevel::Info, t),
                    Err(e) => self.toast(ToastLevel::Error, format!("{e:#}")),
                }
                self.last_ov = None;
                self.mark_detail_dirty();
            }
            Msg::Exported(r) => match r {
                Ok(paths) => {
                    self.popup = Some(Popup::Message {
                        title: "Report saved".into(),
                        body: paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join("\n"),
                        fatal: false,
                    });
                }
                Err(e) => {
                    if let Some(Popup::Export(f)) = &mut self.popup {
                        f.busy = false;
                        f.error = Some(format!("{e:#}"));
                    }
                }
            },
            Msg::LoggedIn(r) => match r {
                Ok(()) => {
                    self.popup = None;
                    self.has_password = true;
                    self.after_auth();
                }
                Err(e) => {
                    if let Some(Popup::Login(f)) = &mut self.popup {
                        f.busy = false;
                        f.error = Some(format!("{e:#}"));
                    }
                }
            },
            Msg::PasswordSet(r) => match r {
                Ok(()) => {
                    self.popup = None;
                    self.has_password = true;
                    self.toast(ToastLevel::Info, "Web UI password set (username: admin).");
                }
                Err(e) => {
                    if let Some(Popup::Password(f)) = &mut self.popup {
                        f.busy = false;
                        f.error = Some(format!("{e:#}"));
                    }
                }
            },
            Msg::SessionEnded => self.quit = true,
        }
    }

    fn need_login(&mut self) {
        self.ready = false;
        if !matches!(self.popup, Some(Popup::Login(_))) {
            self.popup = Some(login_form(None));
        }
    }

    fn fix_selection(&mut self) {
        let n = self.targets().len();
        if n == 0 {
            self.selected = 0;
            if self.selected_id.take().is_some() {
                self.detail = None;
            }
            return;
        }
        if let Some(id) = self.selected_id
            && let Some(i) = self.targets().iter().position(|t| t.target.id == id) {
                self.selected = i;
                return;
            }
        self.selected = self.selected.min(n - 1);
        self.select(self.selected);
    }

    fn select(&mut self, idx: usize) {
        let n = self.targets().len();
        if n == 0 {
            return;
        }
        let idx = idx.min(n - 1);
        self.selected = idx;
        let id = self.targets()[idx].target.id;
        if self.selected_id != Some(id) {
            self.selected_id = Some(id);
            self.detail = None;
            self.hop_selected = 0;
            self.mark_detail_dirty();
        }
    }

    fn set_window(&mut self, w: usize) {
        if w != self.window {
            self.window = w;
            self.last_ov = None;
            self.mark_detail_dirty();
        }
    }

    fn pan(&mut self, dir: i64) {
        let step = self.window_ms() / 4;
        let now = now_ms();
        let end = self.view_end.unwrap_or(now) + dir * step;
        self.view_end = if end >= now { None } else { Some(end) };
        self.mark_detail_dirty();
    }

    // ----- actions ----------------------------------------------------------

    fn open_add(&mut self, host: &str) {
        let interval = 2.5;
        self.popup = Some(Popup::Target(TargetForm {
            editing: None,
            host: Input::new(host),
            name: Input::default(),
            interval: Input::new(&format!("{interval}")),
            trace: true,
            background: false,
            field: 0,
            error: None,
            busy: false,
        }));
    }

    fn open_edit(&mut self) {
        let Some(t) = self.selected_target().map(|t| t.target.clone()) else { return };
        self.popup = Some(Popup::Target(TargetForm {
            editing: Some(t.id),
            host: Input::new(&t.host),
            name: Input::new(if t.name == t.host { "" } else { &t.name }),
            interval: Input::new(&trim_float(t.interval_ms as f64 / 1000.0)),
            trace: t.trace,
            background: t.is_background(),
            field: 1,
            error: None,
            busy: false,
        }));
    }

    fn quick_add(&mut self, host: String, name: &str) {
        let c = self.client.clone();
        let session = if self.is_local() { None } else { self.session.clone() };
        let t = NewTarget { host, name: Some(name.into()), interval_ms: None, trace: Some(true), session };
        self.spawn(async move { Msg::TargetSaved(c.add_target(&t).await, true) });
    }

    fn submit_target(&mut self) {
        let local = self.is_local();
        let session = self.session.clone();
        let c = self.client.clone();
        let Some(Popup::Target(f)) = &mut self.popup else { return };
        let host = f.host.value.trim().to_string();
        if host.is_empty() {
            f.error = Some("Enter a hostname or IP address.".into());
            f.field = 0;
            return;
        }
        let interval: f64 = match f.interval.value.trim().parse() {
            Ok(v) if (0.25..=3600.0).contains(&v) => v,
            _ => {
                f.error = Some("Interval must be between 0.25 and 3600 seconds.".into());
                f.field = 2;
                return;
            }
        };
        f.busy = true;
        f.error = None;
        let name = f.name.value.trim().to_string();
        let owner = if local || f.background { None } else { session };
        let interval_ms = (interval * 1000.0).round() as u32;
        match f.editing {
            None => {
                let t = NewTarget {
                    host,
                    name: (!name.is_empty()).then_some(name),
                    interval_ms: Some(interval_ms),
                    trace: Some(f.trace),
                    session: owner,
                };
                self.spawn(async move { Msg::TargetSaved(c.add_target(&t).await, true) });
            }
            Some(id) => {
                let p = TargetPatch {
                    name: Some(name),
                    interval_ms: Some(interval_ms),
                    trace: Some(f.trace),
                    session: if local { None } else { Some(owner) },
                    enabled: None,
                };
                self.spawn(async move { Msg::TargetSaved(c.patch_target(id, &p).await, false) });
            }
        }
    }

    fn toggle_pause(&mut self) {
        let Some(t) = self.selected_target().map(|t| t.target.clone()) else { return };
        let c = self.client.clone();
        let p = TargetPatch { enabled: Some(!t.enabled), ..Default::default() };
        let msg = if t.enabled { format!("Paused {}", t.name) } else { format!("Resumed {}", t.name) };
        self.spawn(async move { Msg::Action(c.patch_target(t.id, &p).await.map(|_| msg)) });
    }

    fn toggle_background(&mut self) {
        if self.is_local() {
            self.popup = Some(Popup::Message {
                title: "Background monitoring".into(),
                body: format!(
                    "This is a local session: the background service isn't running, so monitoring stops when you quit.\n\n{}\n\nThen open pingrail again and press b on a target to keep it running after you quit.",
                    crate::service::start_hint()
                ),
                fatal: false,
            });
            return;
        }
        let Some(t) = self.selected_target().map(|t| t.target.clone()) else { return };
        let Some(sess) = self.session.clone() else {
            self.toast(ToastLevel::Warn, "Not registered with the service yet; try again in a moment.");
            return;
        };
        if t.share_id.is_some() {
            self.toast(ToastLevel::Warn, "A visitor added this through a share link. It runs in the background while the link works.");
            return;
        }
        let to_bg = !t.is_background();
        let p = TargetPatch {
            session: Some(if to_bg { None } else { Some(sess) }),
            enabled: Some(true),
            ..Default::default()
        };
        let msg = if to_bg {
            format!("{} will keep running in the background after you quit", t.name)
        } else {
            format!("{} now stops when you quit this TUI", t.name)
        };
        let c = self.client.clone();
        self.spawn(async move { Msg::Action(c.patch_target(t.id, &p).await.map(|_| msg)) });
    }

    fn all_to_background(&mut self) {
        if self.is_local() {
            self.toggle_background();
            return;
        }
        let Some(sess) = self.session.clone() else { return };
        let ids: Vec<i64> = self
            .targets()
            .iter()
            .filter(|t| t.target.session.as_deref() == Some(sess.as_str()))
            .map(|t| t.target.id)
            .collect();
        if ids.is_empty() {
            self.toast(ToastLevel::Info, "All targets already run in the background.");
            return;
        }
        let c = self.client.clone();
        self.spawn(async move {
            for id in &ids {
                if let Err(e) = c.patch_target(*id, &TargetPatch { session: Some(None), ..Default::default() }).await {
                    return Msg::Action(Err(e));
                }
            }
            Msg::Action(Ok(format!("{} target(s) moved to the background", ids.len())))
        });
    }

    fn open_export(&mut self) {
        let (from, to) = self.view_range();
        let dir = directories::UserDirs::new()
            .and_then(|d| d.document_dir().map(|p| p.to_path_buf()).or_else(|| Some(d.home_dir().to_path_buf())))
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("."));
        self.popup = Some(Popup::Export(ExportForm {
            range: 0,
            from: Input::new(&util::fmt_local(from, "%Y-%m-%d %H:%M")),
            to: Input::new(&util::fmt_local(to, "%Y-%m-%d %H:%M")),
            all: self.targets().len() > 1 && self.selected_target().is_none(),
            format: 0,
            dir: Input::new(&dir.display().to_string()),
            field: 0,
            error: None,
            busy: false,
        }));
    }

    fn submit_export(&mut self) {
        let (vf, vt) = self.view_range();
        let selected = self.selected_id;
        let all_ids: Vec<i64> = self.targets().iter().map(|t| t.target.id).collect();
        let c = self.client.clone();
        let Some(Popup::Export(f)) = &mut self.popup else { return };
        let now = now_ms();
        let range = match f.range {
            0 => Ok((vf, vt.min(now))),
            1 => Ok((now - 3_600_000, now)),
            2 => Ok((now - 86_400_000, now)),
            3 => Ok((now - 604_800_000, now)),
            _ => util::parse_local_time(&f.from.value).and_then(|a| util::parse_local_time(&f.to.value).map(|b| (a, b))),
        };
        let (from, to) = match range {
            Ok(r) if r.0 < r.1 => r,
            Ok(_) => {
                f.error = Some("The start must be before the end.".into());
                return;
            }
            Err(e) => {
                f.error = Some(format!("{e}"));
                return;
            }
        };
        let ids = if f.all { all_ids } else { selected.into_iter().collect() };
        if ids.is_empty() {
            f.error = Some("There are no targets to report on.".into());
            return;
        }
        let dir = PathBuf::from(f.dir.value.trim());
        if !dir.is_dir() {
            f.error = Some(format!("{} is not a folder.", dir.display()));
            f.field = 5;
            return;
        }
        let formats = match f.format {
            0 => vec![ReportFormat::Pdf],
            1 => vec![ReportFormat::Png],
            _ => vec![ReportFormat::Pdf, ReportFormat::Png],
        };
        f.busy = true;
        f.error = None;
        let tz = util::local_offset_min();
        self.spawn(async move {
            let mut out = Vec::new();
            for fmt in formats {
                let bytes = match c.report(&ids, from, to, tz, fmt).await {
                    Ok(b) => b,
                    Err(e) => return Msg::Exported(Err(e)),
                };
                let name = report::file_name(&ReportRequest {
                    target_ids: ids.clone(),
                    from_ms: from,
                    to_ms: to,
                    tz_offset_min: tz,
                    format: fmt,
                });
                let path = dir.join(name);
                if let Err(e) = std::fs::write(&path, bytes) {
                    return Msg::Exported(Err(anyhow::anyhow!("writing {}: {e}", path.display())));
                }
                out.push(path);
            }
            Msg::Exported(Ok(out))
        });
    }

    fn request_quit(&mut self) {
        if self.is_local() {
            let running = self.targets().iter().filter(|t| t.target.enabled).count();
            if running > 0 {
                self.popup = Some(Popup::Quit { foreground: running });
            } else {
                self.quit = true;
            }
            return;
        }
        let fg = match &self.session {
            Some(s) => self
                .targets()
                .iter()
                .filter(|t| t.target.enabled && t.target.session.as_deref() == Some(s.as_str()))
                .count(),
            None => 0,
        };
        if fg > 0 {
            self.popup = Some(Popup::Quit { foreground: fg });
        } else {
            self.end_session(SessionEnd::Stop);
        }
    }

    fn end_session(&mut self, end: SessionEnd) {
        self.quitting = true;
        match self.session.clone() {
            Some(s) => {
                let c = self.client.clone();
                self.spawn(async move {
                    let _ = tokio::time::timeout(Duration::from_secs(3), c.end_session(&s, end)).await;
                    Msg::SessionEnded
                });
            }
            None => self.quit = true,
        }
    }

    // ----- input ------------------------------------------------------------

    fn on_key(&mut self, k: KeyEvent) {
        if k.kind == KeyEventKind::Release {
            return;
        }
        if k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL) {
            if matches!(self.popup, Some(Popup::Login(_))) || !self.ready {
                self.quit = true;
            } else if self.popup.is_some() {
                self.popup = None;
            } else {
                self.request_quit();
            }
            return;
        }
        if self.popup.is_some() {
            self.on_popup_key(k);
            return;
        }
        let n = self.targets().len();
        match k.code {
            KeyCode::Char('q') => self.request_quit(),
            KeyCode::Char('?') | KeyCode::F(1) => self.popup = Some(Popup::Help),
            KeyCode::Tab | KeyCode::BackTab => {
                let has_hops = self.detail.as_ref().is_some_and(|d| !d.hops.is_empty());
                self.focus = if self.focus == Focus::Targets && has_hops { Focus::Hops } else { Focus::Targets };
                self.mark_detail_dirty();
            }
            KeyCode::Esc if self.focus == Focus::Hops => {
                self.focus = Focus::Targets;
                self.mark_detail_dirty();
            }
            KeyCode::Up | KeyCode::Char('k') => match self.focus {
                Focus::Targets => self.select(self.selected.saturating_sub(1)),
                Focus::Hops => {
                    self.hop_selected = self.hop_selected.saturating_sub(1);
                    self.mark_detail_dirty();
                }
            },
            KeyCode::Down | KeyCode::Char('j') => match self.focus {
                Focus::Targets => self.select(self.selected + 1),
                Focus::Hops => {
                    let max = self.detail.as_ref().map(|d| d.hops.len()).unwrap_or(0);
                    self.hop_selected = (self.hop_selected + 1).min(max.saturating_sub(1));
                    self.mark_detail_dirty();
                }
            },
            KeyCode::Home | KeyCode::Char('g') => self.select(0),
            KeyCode::Char('G') => self.select(n.saturating_sub(1)),
            KeyCode::Char('a') | KeyCode::Insert => self.open_add(""),
            KeyCode::Char('e') | KeyCode::Enter if n > 0 => self.open_edit(),
            KeyCode::Char('d') | KeyCode::Delete if n > 0 => {
                if let Some(t) = self.selected_target() {
                    self.popup = Some(Popup::ConfirmDelete { id: t.target.id, name: t.target.name.clone() });
                }
            }
            KeyCode::Char(' ') | KeyCode::Char('p') if n > 0 => self.toggle_pause(),
            KeyCode::Char('b') if n > 0 => self.toggle_background(),
            KeyCode::Char('B') if n > 0 => self.all_to_background(),
            KeyCode::Char('[') | KeyCode::Char('-') => self.set_window(self.window.saturating_sub(1)),
            KeyCode::Char(']') | KeyCode::Char('+') | KeyCode::Char('=') => {
                self.set_window((self.window + 1).min(WINDOWS.len() - 1))
            }
            KeyCode::Left | KeyCode::Char('h') => self.pan(-1),
            KeyCode::Right | KeyCode::Char('l') => self.pan(1),
            KeyCode::End | KeyCode::Char('L') => {
                self.view_end = None;
                self.mark_detail_dirty();
            }
            KeyCode::Char('x') | KeyCode::Char('s') => self.open_export(),
            KeyCode::Char('w') => self.popup = Some(Popup::Web),
            KeyCode::Char('i') => self.popup = Some(Popup::About),
            KeyCode::Char('P') => self.open_password(),
            KeyCode::Char('r') => {
                self.last_ov = None;
                self.mark_detail_dirty();
            }
            KeyCode::Char(c @ '1'..='3') if n == 0 => {
                match c {
                    '1' => self.quick_add("1.1.1.1".into(), "Cloudflare DNS"),
                    '2' => self.quick_add("8.8.8.8".into(), "Google DNS"),
                    _ => match util::default_gateway() {
                        Some(gw) => self.quick_add(gw.to_string(), "Default gateway"),
                        None => self.toast(ToastLevel::Warn, "Could not find your default gateway."),
                    },
                }
            }
            _ => {}
        }
    }

    fn open_password(&mut self) {
        if !self.client.uses_token() {
            self.toast(ToastLevel::Warn, "Change the password from the web UI, or run `pingrail passwd` on the service machine.");
            return;
        }
        self.popup = Some(Popup::Password(PasswordForm {
            p1: Input::masked(),
            p2: Input::masked(),
            field: 0,
            error: None,
            busy: false,
            first_run: false,
        }));
    }

    fn on_popup_key(&mut self, k: KeyEvent) {
        let Some(popup) = self.popup.as_mut() else { return };
        match popup {
            Popup::Help => {
                if matches!(k.code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') | KeyCode::Char('?')) {
                    self.popup = None;
                } else if k.code == KeyCode::Char('i') {
                    self.popup = Some(Popup::About);
                }
            }
            Popup::About => {
                if matches!(k.code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') | KeyCode::Char('i')) {
                    self.popup = None;
                }
            }
            Popup::Web => match k.code {
                KeyCode::Char('p') | KeyCode::Char('P') => self.open_password(),
                KeyCode::Char('o') => {
                    let url = ui::web_urls(self).first().cloned();
                    if let Some(u) = url
                        && !util::open_browser(&u) {
                            self.toast(ToastLevel::Warn, "Could not open a browser here.");
                        }
                }
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') | KeyCode::Char('w') => self.popup = None,
                _ => {}
            },
            Popup::Message { fatal, .. } => {
                if matches!(k.code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q')) {
                    if *fatal {
                        self.quit = true;
                    }
                    self.popup = None;
                }
            }
            Popup::ConfirmDelete { id, name } => match k.code {
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                    let (id, name) = (*id, name.clone());
                    let c = self.client.clone();
                    self.popup = None;
                    self.spawn(async move { Msg::Action(c.delete_target(id).await.map(|_| format!("Removed {name}"))) });
                }
                KeyCode::Char('n') | KeyCode::Esc => self.popup = None,
                _ => {}
            },
            Popup::Quit { .. } => match k.code {
                KeyCode::Char('k') | KeyCode::Char('K') if !self.is_local() => {
                    self.popup = None;
                    self.end_session(SessionEnd::Background);
                }
                KeyCode::Char('s') | KeyCode::Char('S') if !self.is_local() => {
                    self.popup = None;
                    self.end_session(SessionEnd::Stop);
                }
                KeyCode::Char('q') | KeyCode::Char('y') | KeyCode::Enter if self.is_local() => self.quit = true,
                KeyCode::Esc | KeyCode::Char('c') => self.popup = None,
                _ => {}
            },
            Popup::Target(f) => {
                if f.busy {
                    return;
                }
                let fields = 5;
                match k.code {
                    KeyCode::Esc => self.popup = None,
                    KeyCode::Enter => self.submit_target(),
                    KeyCode::Tab | KeyCode::Down => f.field = next_field(f.field, fields, f.editing.is_some()),
                    KeyCode::BackTab | KeyCode::Up => f.field = prev_field(f.field, fields, f.editing.is_some()),
                    KeyCode::Char(' ') if f.field == 3 => f.trace = !f.trace,
                    KeyCode::Char(' ') if f.field == 4 => f.background = !f.background,
                    _ => {
                        let input = match f.field {
                            0 if f.editing.is_none() => Some(&mut f.host),
                            1 => Some(&mut f.name),
                            2 => Some(&mut f.interval),
                            _ => None,
                        };
                        if let Some(i) = input {
                            i.handle(k);
                        }
                    }
                }
            }
            Popup::Export(f) => {
                if f.busy {
                    return;
                }
                let custom = f.range == RANGE_CHOICES.len() - 1;
                let skip = |i: usize| !custom && (i == 1 || i == 2);
                match k.code {
                    KeyCode::Esc => self.popup = None,
                    KeyCode::Enter => self.submit_export(),
                    KeyCode::Tab | KeyCode::Down => {
                        let mut n = (f.field + 1) % 6;
                        while skip(n) {
                            n = (n + 1) % 6;
                        }
                        f.field = n;
                    }
                    KeyCode::BackTab | KeyCode::Up => {
                        let mut n = (f.field + 5) % 6;
                        while skip(n) {
                            n = (n + 5) % 6;
                        }
                        f.field = n;
                    }
                    KeyCode::Left | KeyCode::Right | KeyCode::Char(' ') if matches!(f.field, 0 | 3 | 4) => {
                        let fwd = k.code != KeyCode::Left;
                        let cycle = |v: usize, n: usize| if fwd { (v + 1) % n } else { (v + n - 1) % n };
                        match f.field {
                            0 => f.range = cycle(f.range, RANGE_CHOICES.len()),
                            3 => f.all = !f.all,
                            _ => f.format = cycle(f.format, FORMAT_CHOICES.len()),
                        }
                    }
                    _ => {
                        let input = match f.field {
                            1 => Some(&mut f.from),
                            2 => Some(&mut f.to),
                            5 => Some(&mut f.dir),
                            _ => None,
                        };
                        if let Some(i) = input {
                            i.handle(k);
                        }
                    }
                }
            }
            Popup::Password(f) => {
                if f.busy {
                    return;
                }
                match k.code {
                    KeyCode::Esc => {
                        if f.first_run {
                            self.toast(ToastLevel::Info, "Skipped. Press P any time to set the web UI password.");
                        }
                        self.popup = None;
                    }
                    KeyCode::Tab | KeyCode::Down | KeyCode::BackTab | KeyCode::Up => f.field = 1 - f.field,
                    KeyCode::Enter => {
                        if f.field == 0 && f.p2.value.is_empty() {
                            f.field = 1;
                            return;
                        }
                        if f.p1.value.chars().count() < 8 {
                            f.error = Some("Use at least 8 characters.".into());
                            return;
                        }
                        if f.p1.value != f.p2.value {
                            f.error = Some("The two passwords don't match.".into());
                            return;
                        }
                        f.busy = true;
                        let pw = f.p1.value.clone();
                        let c = self.client.clone();
                        self.spawn(async move { Msg::PasswordSet(c.set_password(None, &pw).await) });
                    }
                    _ => {
                        if f.field == 0 {
                            f.p1.handle(k);
                        } else {
                            f.p2.handle(k);
                        }
                    }
                }
            }
            Popup::Login(f) => {
                if f.busy {
                    return;
                }
                match k.code {
                    KeyCode::Esc => self.quit = true,
                    KeyCode::Tab | KeyCode::Down | KeyCode::BackTab | KeyCode::Up => f.field = 1 - f.field,
                    KeyCode::Enter => {
                        if f.field == 0 {
                            f.field = 1;
                            return;
                        }
                        f.busy = true;
                        f.error = None;
                        let (u, p) = (f.user.value.trim().to_string(), f.pass.value.clone());
                        let c = self.client.clone();
                        self.spawn(async move { Msg::LoggedIn(c.login(&u, &p).await) });
                    }
                    _ => {
                        if f.field == 0 {
                            f.user.handle(k);
                        } else {
                            f.pass.handle(k);
                        }
                    }
                }
            }
        }
    }

    fn on_mouse(&mut self, kind: MouseEventKind, col: u16, row: u16) {
        if self.popup.is_some() {
            return;
        }
        match kind {
            MouseEventKind::ScrollUp => self.select(self.selected.saturating_sub(1)),
            MouseEventKind::ScrollDown => self.select(self.selected + 1),
            MouseEventKind::Down(_) => {
                let a = self.targets_area;
                // Border + header row, then one row per target.
                if col >= a.x && col < a.x + a.width && row >= a.y + 2 && row < a.y + a.height.saturating_sub(1) {
                    let idx = (row - a.y - 2) as usize + self.targets_offset;
                    if idx < self.targets().len() {
                        self.focus = Focus::Targets;
                        self.select(idx);
                    }
                }
            }
            _ => {}
        }
    }
}

fn next_field(f: usize, n: usize, editing: bool) -> usize {
    let mut x = (f + 1) % n;
    if editing && x == 0 {
        x = 1;
    }
    x
}

fn prev_field(f: usize, n: usize, editing: bool) -> usize {
    let mut x = (f + n - 1) % n;
    if editing && x == 0 {
        x = n - 1;
    }
    x
}

fn trim_float(v: f64) -> String {
    let s = format!("{v:.2}");
    s.trim_end_matches('0').trim_end_matches('.').to_string()
}

fn login_form(err: Option<String>) -> Popup {
    Popup::Login(LoginForm { user: Input::new("admin"), pass: Input::masked(), field: 1, error: err, busy: false })
}

/// Work out whether to talk to the service or start a local engine.
async fn connect(conn: &Conn, local: bool) -> Result<(Client, Mode, Option<Embedded>)> {
    if !local {
        let client = conn.client()?;
        match client.health().await {
            Ok(h) => {
                return Ok((client, Mode::Service { url: conn.url.clone(), listen: h.listen, cert: h.cert_sha256 }, None));
            }
            Err(e) if conn.explicit || crate::tls::is_untrusted(&e) => bail!("{e:#}"),
            Err(e) => {
                let paths = conn.local_paths();
                return start_local(paths, format!("{e:#}")).await;
            }
        }
    }
    let paths = conn.local_paths();
    start_local(paths, "started with --local".into()).await
}

async fn start_local(paths: Paths, reason: String) -> Result<(Client, Mode, Option<Embedded>)> {
    let emb = match Embedded::start(paths).await {
        Ok(e) => e,
        Err(e) => bail!(
            "the background service isn't running and a local session could not start:\n  {e:#}\n\n{}",
            crate::service::start_hint()
        ),
    };
    let client = Client::new(&emb.url, Some(emb.token.clone()), vec![emb.fingerprint])?;
    let cert = crate::tls::fmt_fingerprint(&emb.fingerprint);
    Ok((client, Mode::Local { url: emb.url.clone(), reason, cert }, Some(emb)))
}

pub async fn run(conn: Conn, local: bool) -> Result<()> {
    let (client, mode, embedded) = connect(&conn, local).await?;
    let mut terminal = ratatui::try_init()?;
    let _ = execute!(std::io::stdout(), EnableMouseCapture);
    let result = event_loop(&mut terminal, client, mode, conn.token.is_some() || local).await;
    let _ = execute!(std::io::stdout(), DisableMouseCapture);
    ratatui::restore();
    if let Some(e) = embedded {
        e.stop().await;
    }
    result
}

async fn event_loop(
    terminal: &mut ratatui::DefaultTerminal,
    client: Client,
    mode: Mode,
    have_token: bool,
) -> Result<()> {
    let (tx, mut rx) = mpsc::unbounded_channel::<Msg>();
    let (ev_tx, mut ev_rx) = mpsc::unbounded_channel::<Event>();
    std::thread::spawn(move || loop {
        match event::poll(Duration::from_millis(200)) {
            Ok(true) => match event::read() {
                Ok(ev) => {
                    if ev_tx.send(ev).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            },
            Ok(false) => {
                if ev_tx.is_closed() {
                    break;
                }
            }
            Err(_) => break,
        }
    });

    let mut app = App::new(client, mode, tx);
    if app.is_local() {
        app.toast(ToastLevel::Warn, "Local session: the background service isn't running, so monitoring stops when you quit. Press b for details.");
        app.after_auth();
    } else if have_token {
        app.after_auth();
    } else {
        app.popup = Some(login_form(None));
    }

    let mut ticker = tokio::time::interval(Duration::from_millis(250));
    loop {
        terminal.draw(|f| ui::draw(f, &mut app))?;
        tokio::select! {
            Some(ev) = ev_rx.recv() => match ev {
                Event::Key(k) => app.on_key(k),
                Event::Mouse(m) => app.on_mouse(m.kind, m.column, m.row),
                _ => {}
            },
            Some(msg) = rx.recv() => app.on_msg(msg),
            _ = ticker.tick() => {}
        }
        app.tick();
        if app.quit {
            break;
        }
    }
    Ok(())
}
