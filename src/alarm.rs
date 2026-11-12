//! Alarms: noticing that a target has stopped answering, is losing pings or
//! has turned slow, saying so by email, and saying so once more when it is
//! back to normal.
//!
//! Everything is worked out from the samples already saved, every few
//! seconds, so nothing is lost over a restart. An alarm is quiet by design:
//! one email when it starts and one when it ends, one "unstable" email for
//! a target that keeps dropping, and one email for the monitor's own
//! connection going down, instead of one for every target behind it.
//!
//! Alarms belong to the owner. Nothing here is reachable through a share
//! link, and destinations added through one never raise an alarm.

use anyhow::Result;
use chrono::{DateTime, FixedOffset, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::config::now_ms;
use crate::mail::MailServer;
use crate::model::Target;
use crate::stats::fmt_ms;
use crate::store::{blocking, AlarmRow, Store};

// ----- settings --------------------------------------------------------------

/// When to raise an alarm about a target.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Limits {
    /// No reply for `down_s` seconds.
    pub down: bool,
    pub down_s: u32,
    /// More than `loss_pct` % of pings lost over `loss_min` minutes.
    pub loss: bool,
    pub loss_pct: f64,
    pub loss_min: u32,
    /// An average above `slow_ms` over `slow_min` minutes.
    pub slow: bool,
    pub slow_ms: f64,
    pub slow_min: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { down: true, down_s: 30, loss: true, loss_pct: 2.0, loss_min: 5, slow: true, slow_ms: 150.0, slow_min: 5 }
    }
}

impl Limits {
    /// The same limits, with every number inside what makes sense.
    fn cleaned(mut self) -> Limits {
        let num = |v: f64, lo: f64, hi: f64, or: f64| if v.is_finite() { v.clamp(lo, hi) } else { or };
        self.down_s = self.down_s.clamp(5, 86_400);
        self.loss_pct = num(self.loss_pct, 0.01, 100.0, 2.0);
        self.loss_min = self.loss_min.clamp(1, 1440);
        self.slow_ms = num(self.slow_ms, 1.0, 60_000.0, 150.0);
        self.slow_min = self.slow_min.clamp(1, 1440);
        self
    }

    fn none() -> Limits {
        Limits { down: false, loss: false, slow: false, ..Limits::default() }
    }
}

/// How often to say an alarm is still going.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Remind {
    #[default]
    Never,
    Hour,
    Day,
}

/// Everything set under Menu › Alarms, bar the mail password.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Settings {
    /// Who gets the emails.
    pub to: Vec<String>,
    pub limits: Limits,
    /// More than `unstable_count` alarms from one target within
    /// `unstable_min` minutes make it "unstable".
    pub unstable_count: u32,
    pub unstable_min: u32,
    pub remind: Remind,
    pub mail: MailServer,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { to: Vec::new(), limits: Limits::default(), unstable_count: 3, unstable_min: 15, remind: Remind::Never, mail: MailServer::default() }
    }
}

/// Most addresses alarm emails can go to.
const MAX_RECIPIENTS: usize = 10;

impl Settings {
    /// Check what was typed and tidy it. The error is for the form.
    pub fn cleaned(mut self) -> std::result::Result<Settings, String> {
        self.limits = self.limits.cleaned();
        self.unstable_count = self.unstable_count.clamp(1, 100);
        self.unstable_min = self.unstable_min.clamp(1, 1440);
        let mut to: Vec<String> = Vec::new();
        for a in &self.to {
            let a = a.trim();
            if a.is_empty() {
                continue;
            }
            if !crate::mail::valid_address(a) {
                return Err(format!("“{}” is not an email address.", crate::util::clean_text(a, 80)));
            }
            if !to.iter().any(|x| x.eq_ignore_ascii_case(a)) {
                to.push(a.to_string());
            }
        }
        if to.len() > MAX_RECIPIENTS {
            return Err(format!("Alarm emails can go to at most {MAX_RECIPIENTS} addresses."));
        }
        self.to = to;
        let m = &mut self.mail;
        m.host = m.host.trim().to_string();
        m.username = m.username.trim().to_string();
        m.from = crate::util::clean_text(&m.from, 200);
        if !m.host.is_empty() && !crate::mail::valid_host(&m.host) {
            return Err("The mail server is not a host name or address.".into());
        }
        if !m.from.is_empty() && crate::mail::parse_from(&m.from).is_none() {
            return Err("From needs an email address, on its own or as “Name <address>”.".into());
        }
        if m.username.len() > 254 || m.username.chars().any(|c| c.is_control()) {
            return Err("The mail username is not one a mail server can take.".into());
        }
        Ok(self)
    }

    /// Emails can be sent: there is a server, a sender and someone to send to.
    pub fn mail_ready(&self) -> bool {
        self.mail.ready() && !self.to.is_empty()
    }
}

/// One target's say over its alarms.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum TargetAlarm {
    /// The limits under Menu › Alarms.
    #[default]
    General,
    /// Limits of its own.
    Own(Limits),
    /// Never raises an alarm.
    None,
}

const SETTINGS_KEY: &str = "alarms";

pub fn load_settings(store: &Store) -> Settings {
    store.meta_get(SETTINGS_KEY).ok().flatten().and_then(|j| serde_json::from_str(&j).ok()).unwrap_or_default()
}

// ----- alarms ----------------------------------------------------------------

/// What an alarm is about.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// A target is not answering.
    Down,
    /// A target is losing pings.
    Loss,
    /// A target is slow.
    Slow,
    /// No target answers: this machine is cut off.
    Cutoff,
    /// No target beyond the local network answers.
    Internet,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Down => "down",
            Kind::Loss => "loss",
            Kind::Slow => "slow",
            Kind::Cutoff => "cutoff",
            Kind::Internet => "internet",
        }
    }

    fn parse(s: &str) -> Option<Kind> {
        [Kind::Down, Kind::Loss, Kind::Slow, Kind::Cutoff, Kind::Internet].into_iter().find(|k| k.as_str() == s)
    }
}

/// The figures that go with an alarm.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
struct Detail {
    /// The limit that was crossed: seconds, percent or milliseconds.
    limit: f64,
    /// Minutes the limit is measured over (loss and slow).
    window_min: u32,
    /// The worst it got: percent lost, or average milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    worst: Option<f64>,
    /// Pings lost while it lasted.
    #[serde(skip_serializing_if = "Option::is_none")]
    lost: Option<u64>,
    /// Targets that went quiet together (cut-offs).
    #[serde(skip_serializing_if = "Option::is_none")]
    targets: Option<u32>,
    /// Pings sent and lost in the window when a loss alarm was raised.
    #[serde(skip_serializing_if = "Option::is_none")]
    counted: Option<(u64, u64)>,
}

#[derive(Debug, Clone, PartialEq)]
struct Alarm {
    row: AlarmRow,
    kind: Kind,
    detail: Detail,
}

impl Alarm {
    fn from_row(row: AlarmRow) -> Option<Alarm> {
        let kind = Kind::parse(&row.kind)?;
        let detail = serde_json::from_str(&row.detail).unwrap_or_default();
        Some(Alarm { row, kind, detail })
    }

    /// In a few words, what the alarm is: for lists.
    fn what(&self) -> String {
        let d = &self.detail;
        match self.kind {
            Kind::Down => format!("Not answering for {}", secs(d.limit as i64)),
            Kind::Loss => {
                let worst = d.worst.map(|w| format!(", {} at worst", pct(w))).unwrap_or_default();
                format!("Lost more than {} over {}{worst}", pct(d.limit), mins(d.window_min))
            }
            Kind::Slow => {
                let worst = d.worst.map(|w| format!(", {} ms at worst", fmt_ms(Some(w)))).unwrap_or_default();
                format!("Slower than {} ms over {}{worst}", fmt_ms(Some(d.limit)), mins(d.window_min))
            }
            Kind::Cutoff => "This machine was cut off: no target answered".into(),
            Kind::Internet => "Internet connection down: no target beyond this network answered".into(),
        }
    }
}

/// An alarm as the web UI and the terminal UI show it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AlarmView {
    pub id: i64,
    /// None for an alarm about the monitor's own connection.
    pub target_id: Option<i64>,
    /// The target's name, or this machine's.
    pub name: String,
    pub kind: Kind,
    /// When what it is about began, and when the alarm was raised.
    pub since_ms: i64,
    pub raised_ms: i64,
    pub ended_ms: Option<i64>,
    pub what: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lost: Option<u64>,
    /// Why no email went out, when none did: "off" (mail is not set up),
    /// "unstable" or "stopped".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mail_note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mail_start_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mail_end_ms: Option<i64>,
}

/// What every screen needs to know about alarms right now.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct AlarmsNow {
    /// Alarms that have not ended, oldest first.
    pub active: Vec<AlarmView>,
    /// Targets whose alarms are paused, with until when (ms).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub paused: HashMap<i64, i64>,
    /// Emails can be sent (a server and recipients are set).
    pub mail_ready: bool,
    /// How many addresses alarm emails go to.
    pub recipients: usize,
    /// Why the last email could not be sent, while one is still waiting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mail_error: Option<String>,
}

/// What is going on now and the latest alarms, as `/api/alarms` answers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlarmsList {
    pub now: AlarmsNow,
    /// The latest alarms of every target, newest first.
    pub recent: Vec<AlarmView>,
}

impl AlarmView {
    /// What has been wrong for a while, ready for "since 13:53":
    /// "Printer has not answered".
    pub fn ongoing(&self) -> String {
        match self.kind {
            Kind::Down => format!("{} has not answered", self.name),
            Kind::Loss => format!("{} has been losing pings", self.name),
            Kind::Slow => format!("{} has been slow", self.name),
            Kind::Cutoff => format!("{} has been cut off", self.name),
            Kind::Internet => "The internet connection has been down".to_string(),
        }
    }

    /// What is wrong, as a sentence starts: "Printer is not answering".
    pub fn short(&self) -> String {
        match self.kind {
            Kind::Down => format!("{} is not answering", self.name),
            Kind::Loss => format!("{} is losing pings", self.name),
            Kind::Slow => format!("{} is slow", self.name),
            Kind::Cutoff => format!("{} is cut off", self.name),
            Kind::Internet => "The internet connection is down".to_string(),
        }
    }
}

// ----- words -------------------------------------------------------------------

fn pct(v: f64) -> String {
    if v >= 99.995 {
        "100 %".into()
    } else if v < 10.0 {
        let s = format!("{v:.2}");
        format!("{} %", s.trim_end_matches('0').trim_end_matches('.'))
    } else {
        format!("{v:.1} %")
    }
}

fn secs(s: i64) -> String {
    if s >= 120 && s % 60 == 0 { format!("{} min", s / 60) } else { format!("{s} s") }
}

/// The same in full, for a sentence: "30 seconds", "2 minutes".
fn secs_long(s: i64) -> String {
    if s >= 120 && s % 60 == 0 { format!("{} minutes", s / 60) } else { format!("{s} seconds") }
}

fn mins(m: u32) -> String {
    if m >= 120 && m.is_multiple_of(60) { format!("{} h", m / 60) } else { format!("{m} min") }
}

/// A length of time: "40 s", "38 min 12 s", "2 h 5 min", "3 days 4 h".
pub fn dur(ms: i64) -> String {
    let s = (ms.max(0) + 500) / 1000;
    let (d, h, m, sec) = (s / 86_400, s % 86_400 / 3600, s % 3600 / 60, s % 60);
    if d > 0 {
        let days = if d == 1 { "1 day".to_string() } else { format!("{d} days") };
        if h > 0 { format!("{days} {h} h") } else { days }
    } else if h > 0 {
        if m > 0 { format!("{h} h {m} min") } else { format!("{h} h") }
    } else if m > 0 {
        if sec > 0 { format!("{m} min {sec} s") } else { format!("{m} min") }
    } else {
        format!("{sec} s")
    }
}

fn count(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn plural(n: u64, one: &str, many: &str) -> String {
    format!("{} {}", count(n), if n == 1 { one } else { many })
}

/// Where and when the monitor is, for the wording of emails.
#[derive(Debug, Clone)]
pub struct Env {
    /// This machine's name.
    pub host: String,
    /// Where the web UI is. None in a terminal session, whose address
    /// stops working when the terminal closes.
    pub url: Option<String>,
    /// How far behind the clock saved samples run: a lost ping is only
    /// known to be lost when its time is up, and is saved a little later.
    pub lag_ms: i64,
    /// The time zone emails are written in; None = this machine's.
    pub tz: Option<FixedOffset>,
}

impl Env {
    fn zone(&self) -> FixedOffset {
        self.tz.unwrap_or_else(|| *chrono::Local::now().offset())
    }

    fn local(&self, ms: i64) -> DateTime<FixedOffset> {
        Utc.timestamp_millis_opt(ms).single().unwrap_or_default().with_timezone(&self.zone())
    }

    /// "13:53:10".
    fn time(&self, ms: i64) -> String {
        self.local(ms).format("%H:%M:%S").to_string()
    }

    /// "13:53".
    fn hm(&self, ms: i64) -> String {
        self.local(ms).format("%H:%M").to_string()
    }

    /// "13:53:10 on 11 November".
    fn stamp(&self, ms: i64) -> String {
        self.local(ms).format("%H:%M:%S on %-d %B").to_string()
    }

    /// "13:53:10 to 14:31:22", with the dates when they differ.
    fn span(&self, a: i64, b: i64) -> String {
        if self.local(a).date_naive() == self.local(b).date_naive() {
            format!("{} to {}", self.time(a), self.time(b))
        } else {
            format!("{} to {}", self.stamp(a), self.stamp(b))
        }
    }

    /// The lines every email ends with.
    fn foot(&self) -> String {
        let s = self.zone().local_minus_utc();
        let zone = format!("UTC{}{:02}:{:02}", if s < 0 { '-' } else { '+' }, s.abs() / 3600, s.abs() % 3600 / 60);
        let open = self.url.as_ref().map(|u| format!("Open pingrail: {u}\n\n")).unwrap_or_default();
        format!("{open}Times are {zone}. To change or pause alarms, open pingrail and choose Menu, then Alarms.\n")
    }
}

/// A target as an email names it: "Printer (192.168.10.60)".
fn named(t: &Target) -> String {
    if t.name == t.host { t.name.clone() } else { format!("{} ({})", t.name, t.host) }
}

// ----- working it out ---------------------------------------------------------

/// What the saved samples say about one rule for one target.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Verdict {
    /// The limit is crossed; with the figure that crosses it.
    Yes(f64),
    /// It is not; with the figure.
    No(f64),
    /// Too few samples to say: leave things as they are.
    Unknown,
}

/// A target that is raising alarm after alarm.
#[derive(Debug, Clone, Copy)]
struct Unstable {
    since_ms: i64,
    last_raise_ms: i64,
    alarms: u32,
}

/// Works the alarms out, one pass at a time. What it keeps between passes
/// is only what the database does not: which targets are unstable, and
/// since when everything has been quiet.
#[derive(Default)]
pub struct Evaluator {
    unstable: HashMap<i64, Unstable>,
    /// A cut-off that has begun but not yet lasted long enough to record.
    cut_seen: Option<(Kind, i64)>,
    /// Since when a loss or slow alarm has been back under its limit.
    under: HashMap<(i64, Kind), i64>,
    passes: u64,
}

/// How long loss or slowness must stay under its limit before the alarm
/// ends: a quarter of the time it is measured over, between one minute and
/// fifteen. Without it, loss that comes and goes (a camera restarting on the
/// hour) would end and raise the alarm again each time.
fn settle_ms(window_min: u32) -> i64 {
    (window_min as i64 * 15_000).clamp(60_000, 900_000)
}

/// The newest samples of a target, for telling a cut-off from one target's trouble.
struct Quick {
    has: bool,
    silent: bool,
    public: bool,
}

const HOUR: i64 = 3_600_000;

impl Evaluator {
    /// One pass over every target at `now`.
    pub fn pass(&mut self, store: &Store, env: &Env, now: i64) -> Result<()> {
        let settings = load_settings(store);
        let mail = settings.mail_ready();
        let targets: Vec<Target> = store.list_targets()?.into_iter().filter(|t| t.share_id.is_none()).collect();
        let own = store.alarm_targets()?;
        let edge = now - env.lag_ms;
        // Loss and slowness move slowly: every third pass is plenty.
        let slow_pass = self.passes.is_multiple_of(3);
        self.passes += 1;

        let limits_of = |t: &Target| -> Limits {
            let (cfg, paused) = own.get(&t.id).map_or((None, None), |(c, p)| (Some(c.as_str()), *p));
            if !t.enabled || paused.is_some_and(|until| until > now) {
                return Limits::none();
            }
            match cfg.and_then(|c| serde_json::from_str::<TargetAlarm>(c).ok()).unwrap_or_default() {
                TargetAlarm::General => settings.limits,
                TargetAlarm::Own(l) => l.cleaned(),
                TargetAlarm::None => Limits::none(),
            }
        };
        let mut active: Vec<Alarm> = store.alarms_active()?.into_iter().filter_map(Alarm::from_row).collect();

        // An alarm whose target is gone, paused or no longer watched for it
        // ends without a word.
        active.retain(|a| {
            let Some(id) = a.row.target_id else { return true };
            let on = targets.iter().find(|t| t.id == id).map(&limits_of).is_some_and(|l| match a.kind {
                Kind::Down => l.down,
                Kind::Loss => l.loss,
                Kind::Slow => l.slow,
                _ => true,
            });
            if !on {
                let _ = store.alarm_update(a.row.id, Some(now), None, Some(Some("stopped")), None);
            }
            on
        });

        // ---- is it one target, or the monitor's own connection?
        let mut quick: HashMap<i64, Quick> = HashMap::new();
        for t in targets.iter().filter(|t| t.enabled) {
            let q = (t.interval_ms as i64 * 5 / 2).max(10_000);
            let (sent, answered, _, _) = store.round_totals(t.id, edge - q, edge + 1)?;
            let public = store
                .target_last_ip(t.id)?
                .or_else(|| Some(t.host.clone()))
                .and_then(|a| a.parse::<std::net::IpAddr>().ok())
                .is_some_and(crate::netpolicy::is_public);
            quick.insert(t.id, Quick { has: sent > 0, silent: sent > 0 && answered == 0, public });
        }
        let seen: Vec<&Quick> = quick.values().filter(|q| q.has).collect();
        let all_silent = seen.len() >= 2 && seen.iter().all(|q| q.silent);
        let public: Vec<&&Quick> = seen.iter().filter(|q| q.public).collect();
        let internet_silent = !all_silent && public.len() >= 2 && public.iter().all(|q| q.silent) && seen.iter().any(|q| !q.public && !q.silent);
        let cut = if all_silent {
            Some(Kind::Cutoff)
        } else if internet_silent {
            Some(Kind::Internet)
        } else {
            None
        };
        // Targets whose silence the cut-off explains.
        let held = |id: i64| match cut {
            Some(Kind::Cutoff) => true,
            Some(_) => quick.get(&id).is_some_and(|q| q.public),
            None => false,
        };
        let cut_alarm = active.iter().position(|a| a.row.target_id.is_none());
        match (cut, cut_alarm) {
            (Some(kind), None) => {
                let (seen_kind, first) = *self.cut_seen.get_or_insert((kind, now));
                // Everything going quiet after only the internet did is one event.
                let kind = if seen_kind == Kind::Cutoff { Kind::Cutoff } else { kind };
                self.cut_seen = Some((kind, first));
                if settings.limits.down && now - first >= settings.limits.down_s as i64 * 1000 {
                    let affected: Vec<&Target> = targets.iter().filter(|t| t.enabled && quick.get(&t.id).is_some_and(|q| q.has) && held(t.id)).collect();
                    // It began with the first ping lost after the last reply any of them gave.
                    let last = affected.iter().filter_map(|t| store.last_reply(t.id, edge - HOUR, edge + 1).ok().flatten()).max();
                    let lost = affected.iter().filter_map(|t| store.first_round(t.id, last.map_or(edge - HOUR, |ts| ts + 1), edge + 1).ok().flatten()).min();
                    let since = lost.unwrap_or(first).min(first);
                    let detail = Detail { limit: settings.limits.down_s as f64, targets: Some(affected.len() as u32), ..Default::default() };
                    let note = (!mail).then_some("off");
                    let id = store.alarm_insert(None, kind.as_str(), since, now, &serde_json::to_string(&detail)?, note)?;
                    // Said at once all the same: if the targets share a link
                    // somewhere else, this machine can still send mail. If it
                    // cannot, the email waits and the one at the end replaces it.
                    if mail {
                        let (subject, body) = self.mail_cut_start(env, kind, since, affected.len() as u64);
                        store.mail_queue(Some(id), "start", now, &subject, &body)?;
                    }
                    tracing::warn!("alarm: {}", if kind == Kind::Cutoff { "no target answers; this machine looks cut off" } else { "no target beyond this network answers" });
                }
            }
            (Some(_), Some(_)) => {}
            (None, Some(i)) => {
                let a = active.remove(i);
                self.cut_seen = None;
                store.alarm_update(a.row.id, Some(edge), None, None, None)?;
                tracing::info!("alarm over: targets answer again");
                if a.row.mail_note.is_none() {
                    let still: Vec<String> = targets.iter().filter(|t| quick.get(&t.id).is_some_and(|q| q.silent)).map(|t| t.name.clone()).collect();
                    // An email about its start that never left is dropped:
                    // the one about its end says it all.
                    store.mail_cancel(a.row.id, "start")?;
                    let (subject, body) = self.mail_cut(env, &a, edge, &still, a.row.mail_start_ms.is_some());
                    store.mail_queue(Some(a.row.id), "end", now, &subject, &body)?;
                }
            }
            (None, None) => self.cut_seen = None,
        }

        // Stretches left out when counting loss: a target's own outages
        // (they have their own alarm) and the monitor's cut-offs.
        let longest = targets.iter().map(|t| limits_of(t).loss_min).max().unwrap_or(5) as i64 * 60_000;
        let outages: Vec<Alarm> =
            store.alarms_since(edge - longest, &["down", "cutoff", "internet"])?.into_iter().filter_map(Alarm::from_row).collect();

        // ---- each target, each rule
        for t in targets.iter().filter(|t| t.enabled) {
            let l = limits_of(t);
            let iv = t.interval_ms.max(1) as i64;
            let down_active = active.iter().any(|a| a.row.target_id == Some(t.id) && a.kind == Kind::Down);
            for kind in [Kind::Down, Kind::Loss, Kind::Slow] {
                let on = match kind {
                    Kind::Down => l.down,
                    Kind::Loss => l.loss,
                    _ => l.slow,
                };
                if !on || (kind != Kind::Down && !slow_pass) {
                    continue;
                }
                let current = active.iter().find(|a| a.row.target_id == Some(t.id) && a.kind == kind).cloned();
                // Pings sent and lost behind a loss verdict.
                let mut counted: Option<(u64, u64)> = None;
                let verdict = match kind {
                    Kind::Down => {
                        let w = (l.down_s as i64 * 1000).max(iv * 5 / 2);
                        let (sent, answered, _, _) = store.round_totals(t.id, edge - w, edge + 1)?;
                        if answered > 0 {
                            Verdict::No(0.0)
                        } else if sent >= 2 {
                            Verdict::Yes(0.0)
                        } else {
                            Verdict::Unknown
                        }
                    }
                    Kind::Loss => {
                        let w = l.loss_min as i64 * 60_000;
                        // Silence that has not ended yet may be an outage in
                        // the making, which has its own alarm: it counts as
                        // loss once it is over, if it was too short for one.
                        let tail = if l.down { Some((store.last_reply(t.id, edge - w + 1, edge + 1)?.map_or(edge - w + 1, |ts| ts + 1), edge + 1)) } else { None };
                        let (sent, lost) = loss_in(store, t, &outages, quick.get(&t.id).is_some_and(|q| q.public), tail, edge - w + 1, edge + 1)?;
                        counted = Some((sent, lost));
                        if sent < enough(w, iv) {
                            Verdict::Unknown
                        } else {
                            let p = 100.0 * lost as f64 / sent as f64;
                            if p > l.loss_pct { Verdict::Yes(p) } else { Verdict::No(p) }
                        }
                    }
                    _ => {
                        let w = l.slow_min as i64 * 60_000;
                        let (_, answered, sum, _) = store.round_totals(t.id, edge - w + 1, edge + 1)?;
                        if answered < enough(w, iv) {
                            Verdict::Unknown
                        } else {
                            let avg = sum / answered as f64 / 1000.0;
                            if avg > l.slow_ms { Verdict::Yes(avg) } else { Verdict::No(avg) }
                        }
                    }
                };
                match (current, verdict) {
                    (None, Verdict::Yes(v)) => {
                        // A cut-off explains the silence, and an outage the loss.
                        if held(t.id) || (kind != Kind::Down && down_active) {
                            continue;
                        }
                        let a = self.raise(store, env, &settings, t, kind, &l, v, counted, edge, now)?;
                        active.push(a);
                    }
                    (Some(a), Verdict::No(v)) => {
                        if kind != Kind::Down {
                            let under = *self.under.entry((t.id, kind)).or_insert(now);
                            if now - under < settle_ms(a.detail.window_min) {
                                continue;
                            }
                            self.under.remove(&(t.id, kind));
                        }
                        self.end(store, env, t, a, v, edge, now)?;
                        active.retain(|a| !(a.row.target_id == Some(t.id) && a.kind == kind));
                    }
                    (Some(mut a), Verdict::Yes(v)) => {
                        self.under.remove(&(t.id, kind));
                        // Keep the worst it got, and say it is still going if asked to.
                        if kind != Kind::Down && a.detail.worst.is_none_or(|w| v > w * 1.02) {
                            a.detail.worst = Some(v);
                            store.alarm_update(a.row.id, None, Some(&serde_json::to_string(&a.detail)?), None, None)?;
                        }
                        let every = match settings.remind {
                            Remind::Never => None,
                            Remind::Hour => Some(HOUR),
                            Remind::Day => Some(24 * HOUR),
                        };
                        if let (Some(every), Some(last), None) = (every, a.row.last_mail_ms, a.row.mail_note.as_deref())
                            && now - last >= every
                            && mail
                        {
                            let (subject, body) = self.mail_still(env, t, &a, now);
                            store.mail_queue(Some(a.row.id), "note", now, &subject, &body)?;
                            store.alarm_update(a.row.id, None, None, None, Some(now))?;
                        }
                    }
                    _ => {}
                }
            }
        }

        // ---- targets that have settled
        let quiet = settings.unstable_min as i64 * 60_000;
        let settled: Vec<i64> = self.unstable.iter().filter(|(_, u)| now - u.last_raise_ms >= quiet).map(|(id, _)| *id).collect();
        for id in settled {
            let u = self.unstable.remove(&id).expect("listed above");
            let Some(t) = targets.iter().find(|t| t.id == id) else { continue };
            if !mail {
                continue;
            }
            // Still in alarm: that alarm's own email, held back until now.
            let going = active.iter().filter(|a| a.row.target_id == Some(id)).min_by_key(|a| a.kind as u8).cloned();
            match going {
                Some(a) => {
                    let (subject, body) = self.mail_start(store, env, t, &a, edge)?;
                    store.mail_queue(Some(a.row.id), "start", now, &subject, &body)?;
                    store.alarm_update(a.row.id, None, None, Some(None), Some(now))?;
                }
                None => {
                    let subject = format!("[pingrail] {} is steady again", t.name);
                    let body = format!(
                        "{} has raised no alarm for {}.\n\nWhile it was unstable it raised {}, between {}.\nMeasured from: {}\n\n{}",
                        named(t),
                        mins(settings.unstable_min),
                        plural(u.alarms as u64, "alarm", "alarms"),
                        env.span(u.since_ms, u.last_raise_ms),
                        env.host,
                        env.foot()
                    );
                    store.mail_queue(None, "note", now, &subject, &body)?;
                }
            }
        }
        Ok(())
    }

    /// A limit has just been crossed: record it and say so.
    #[allow(clippy::too_many_arguments)]
    fn raise(
        &mut self,
        store: &Store,
        env: &Env,
        settings: &Settings,
        t: &Target,
        kind: Kind,
        l: &Limits,
        value: f64,
        counted: Option<(u64, u64)>,
        edge: i64,
        now: i64,
    ) -> Result<Alarm> {
        let (since, detail) = match kind {
            Kind::Down => {
                // It began with the first ping after the last reply.
                let last = store.last_reply(t.id, edge - HOUR, edge + 1)?;
                let since = store.first_round(t.id, last.map_or(edge - HOUR, |ts| ts + 1), edge + 1)?.unwrap_or(edge);
                (since, Detail { limit: l.down_s as f64, ..Default::default() })
            }
            Kind::Loss => (now, Detail { limit: l.loss_pct, window_min: l.loss_min, worst: Some(value), counted, ..Default::default() }),
            _ => (now, Detail { limit: l.slow_ms, window_min: l.slow_min, worst: Some(value), ..Default::default() }),
        };
        let window = settings.unstable_min as i64 * 60_000;
        let recent = store.alarms_raised(t.id, now - window)? + 1;
        let mail = settings.mail_ready();
        let was_unstable = self.unstable.contains_key(&t.id);
        let becomes_unstable = !was_unstable && recent > settings.unstable_count;
        let note = if !mail {
            Some("off")
        } else if was_unstable || becomes_unstable {
            Some("unstable")
        } else {
            None
        };
        let id = store.alarm_insert(Some(t.id), kind.as_str(), since, now, &serde_json::to_string(&detail)?, note)?;
        let row = AlarmRow {
            id,
            target_id: Some(t.id),
            kind: kind.as_str().into(),
            since_ms: since,
            raised_ms: now,
            ended_ms: None,
            detail: String::new(),
            mail_note: note.map(str::to_string),
            mail_start_ms: None,
            mail_end_ms: None,
            last_mail_ms: None,
        };
        let a = Alarm { row, kind, detail };
        tracing::warn!("alarm: {} — {}", t.name, a.what());
        if let Some(u) = self.unstable.get_mut(&t.id) {
            u.last_raise_ms = now;
            u.alarms += 1;
        } else if becomes_unstable {
            let first = store.alarms_recent(Some(t.id), recent as usize)?.iter().map(|r| r.raised_ms).filter(|r| *r >= now - window).min().unwrap_or(now);
            self.unstable.insert(t.id, Unstable { since_ms: first, last_raise_ms: now, alarms: recent });
            if mail {
                let subject = format!("[pingrail] {} is unstable ({} alarms in {})", t.name, recent, mins(settings.unstable_min));
                let mut body = format!("{} has raised {} since {}:\n\n", named(t), plural(recent as u64, "alarm", "alarms"), env.time(first));
                let mut rows = store.alarms_recent(Some(t.id), recent as usize)?;
                rows.reverse();
                for r in rows.into_iter().filter(|r| r.raised_ms >= now - window).filter_map(Alarm::from_row) {
                    let lasted = r.row.ended_ms.map(|e| format!(", for {}", dur(e - r.row.since_ms))).unwrap_or_else(|| ", still going".into());
                    body.push_str(&format!("{}  {}{lasted}\n", env.time(r.row.raised_ms), r.what()));
                }
                body.push_str(&format!(
                    "\nMeasured from: {}\n\nYou will not get an email for each alarm while this goes on. The next one comes when {} has raised no alarm for {}.\n\n{}",
                    env.host,
                    t.name,
                    mins(settings.unstable_min),
                    env.foot()
                ));
                store.mail_queue(None, "note", now, &subject, &body)?;
            }
        } else if mail {
            let (subject, body) = self.mail_start(store, env, t, &a, edge)?;
            store.mail_queue(Some(id), "start", now, &subject, &body)?;
            store.alarm_update(id, None, None, None, Some(now))?;
        }
        Ok(a)
    }

    /// Things are back within the limit: close the alarm and say so.
    #[allow(clippy::too_many_arguments)]
    fn end(&mut self, store: &Store, env: &Env, t: &Target, mut a: Alarm, value: f64, edge: i64, now: i64) -> Result<()> {
        let ended = match a.kind {
            // It ended with the first reply.
            Kind::Down => store.first_reply(t.id, a.row.since_ms, edge + 1)?.unwrap_or(edge),
            _ => now,
        };
        let (sent, answered, _, _) = store.round_totals(t.id, a.row.since_ms, ended)?;
        a.detail.lost = Some(sent - answered);
        store.alarm_update(a.row.id, Some(ended), Some(&serde_json::to_string(&a.detail)?), None, None)?;
        tracing::info!("alarm over: {} — {}", t.name, a.what());
        // Only an alarm that announced itself announces its end.
        if a.row.mail_note.is_some() || self.unstable.contains_key(&t.id) {
            return Ok(());
        }
        let d = &a.detail;
        let lasted = dur(ended - a.row.since_ms);
        let (subject, body) = match a.kind {
            Kind::Down => {
                let (s2, a2, sum, _) = store.round_totals(t.id, ended, edge + 1)?;
                let since_back = if a2 > 0 {
                    format!("{} ms on average, {}", fmt_ms(Some(sum / a2 as f64 / 1000.0)), if s2 == a2 { "none lost".to_string() } else { format!("{} lost", count(s2 - a2)) })
                } else {
                    "no figures yet".into()
                };
                (
                    format!("[pingrail] {} is answering again (was down {})", t.name, lasted),
                    format!(
                        "{} answered again at {}.\n\nNot answering for: {}, from {}\nPings lost: {}\nSince it came back: {}\nMeasured from: {}\n\n{}",
                        named(t),
                        env.stamp(ended),
                        lasted,
                        env.span(a.row.since_ms, ended),
                        count(sent - answered),
                        since_back,
                        env.host,
                        env.foot()
                    ),
                )
            }
            Kind::Loss => (
                format!("[pingrail] {} has stopped losing pings", t.name),
                format!(
                    "{} lost {} of its pings over the last {}, back under its limit of {}.\n\nThe alarm lasted: {}, from {}\nAt worst: {} lost over {}\nMeasured from: {}\n\n{}",
                    named(t),
                    pct(value),
                    mins(d.window_min),
                    pct(d.limit),
                    lasted,
                    env.span(a.row.since_ms, ended),
                    pct(d.worst.unwrap_or(value)),
                    mins(d.window_min),
                    env.host,
                    env.foot()
                ),
            ),
            _ => (
                format!("[pingrail] {} is back to speed ({} ms on average)", t.name, fmt_ms(Some(value))),
                format!(
                    "{} has averaged {} ms over the last {}, back under its limit of {} ms.\n\nThe alarm lasted: {}, from {}\nAt worst: {} ms on average over {}\nMeasured from: {}\n\n{}",
                    named(t),
                    fmt_ms(Some(value)),
                    mins(d.window_min),
                    fmt_ms(Some(d.limit)),
                    lasted,
                    env.span(a.row.since_ms, ended),
                    fmt_ms(Some(d.worst.unwrap_or(value))),
                    mins(d.window_min),
                    env.host,
                    env.foot()
                ),
            ),
        };
        store.mail_queue(Some(a.row.id), "end", now, &subject, &body)?;
        Ok(())
    }

    /// The email that announces an alarm.
    fn mail_start(&self, store: &Store, env: &Env, t: &Target, a: &Alarm, edge: i64) -> Result<(String, String)> {
        let d = &a.detail;
        let iv = t.interval_ms.max(1) as i64;
        Ok(match a.kind {
            Kind::Down => {
                let last = store.last_reply(t.id, a.row.since_ms - HOUR, a.row.since_ms)?;
                let last = last.map(|ts| format!("Last reply: {}\n", env.time(ts))).unwrap_or_default();
                let quiet = edge - a.row.since_ms;
                // Just raised: the limit says it best. Held back: the real time does.
                let for_how_long = if quiet < d.limit as i64 * 2000 { secs_long(d.limit as i64) } else { dur(quiet) };
                (
                    format!("[pingrail] {} is not answering", t.name),
                    format!(
                        "{} has not answered a ping for {}.\n\nNo reply since: {}\n{}Measured from: {}\n\nYou will get one more email when {} answers again.\n\n{}",
                        named(t),
                        for_how_long,
                        env.stamp(a.row.since_ms),
                        last,
                        env.host,
                        t.name,
                        env.foot()
                    ),
                )
            }
            Kind::Loss => {
                let w = d.window_min as i64 * 60_000;
                let (sent, lost) = match d.counted {
                    Some(c) => c,
                    None => {
                        let (sent, answered, _, _) = store.round_totals(t.id, edge - w + 1, edge + 1)?;
                        (sent, sent - answered)
                    }
                };
                // The longest run of lost pings in the window.
                let (mut best, mut run): ((i64, i64), Option<(i64, i64)>) = ((0, 0), None);
                store.for_each_round(t.id, edge - w + 1, edge + 1, |ts, rtt| match (rtt, run) {
                    (None, Some((a, _))) => run = Some((a, ts)),
                    (None, None) => run = Some((ts, ts)),
                    (Some(_), Some((a, b))) => {
                        if b - a + iv > best.1 {
                            best = (a, b - a + iv);
                        }
                        run = None;
                    }
                    _ => {}
                })?;
                if let Some((a, b)) = run
                    && b - a + iv > best.1
                {
                    best = (a, b - a + iv);
                }
                let longest = if best.1 > 0 { format!("Longest stretch with no reply: {}, from {}\n", dur(best.1), env.time(best.0)) } else { String::new() };
                let (all, all_answered, _, _) = store.round_totals(t.id, i64::MIN, edge + 1)?;
                let first = store.round_bounds(t.id, i64::MIN, edge + 1)?.map_or(edge, |b| b.0);
                let worst = d.worst.unwrap_or(0.0);
                (
                    format!("[pingrail] {} is losing pings ({} over {})", t.name, pct(worst), mins(d.window_min)),
                    format!(
                        "{} lost {} of its last {}. That is {} over {}; its limit is {}.\n\n{}On record: {} of {} lost ({}) since {}\nMeasured from: {}\n\nYou will get one more email when its loss over {} has stayed under {} for {}.\n\n{}",
                        named(t),
                        count(lost),
                        plural(sent, "ping", "pings"),
                        pct(worst),
                        mins(d.window_min),
                        pct(d.limit),
                        longest,
                        count(all - all_answered),
                        count(all),
                        pct(100.0 * (all - all_answered) as f64 / all.max(1) as f64),
                        env.local(first).format("%-d %B"),
                        env.host,
                        mins(d.window_min),
                        pct(d.limit),
                        dur(settle_ms(d.window_min)),
                        env.foot()
                    ),
                )
            }
            _ => {
                let w = d.window_min as i64 * 60_000;
                let (sent, answered, _, max) = store.round_totals(t.id, edge - w + 1, edge + 1)?;
                let (_, before, sum, _) = store.round_totals(t.id, edge - w - 24 * HOUR, edge - w + 1)?;
                let usual = if before > 0 { format!("Its usual average: {} ms, over the 24 hours before\n", fmt_ms(Some(sum / before as f64 / 1000.0))) } else { String::new() };
                let worst = d.worst.unwrap_or(0.0);
                (
                    format!("[pingrail] {} is slow ({} ms on average)", t.name, fmt_ms(Some(worst))),
                    format!(
                        "{} has averaged {} ms over the last {}. Its limit is {} ms.\n\n{}Slowest reply: {} ms\nPings lost in the same {}: {}\nMeasured from: {}\n\nYou will get one more email when its average over {} has stayed under {} ms for {}.\n\n{}",
                        named(t),
                        fmt_ms(Some(worst)),
                        mins(d.window_min),
                        fmt_ms(Some(d.limit)),
                        usual,
                        fmt_ms(Some(max as f64 / 1000.0)),
                        mins(d.window_min),
                        if sent == answered { "none".to_string() } else { count(sent - answered) },
                        env.host,
                        mins(d.window_min),
                        fmt_ms(Some(d.limit)),
                        dur(settle_ms(d.window_min)),
                        env.foot()
                    ),
                )
            }
        })
    }

    /// The email that says an alarm is still going.
    fn mail_still(&self, env: &Env, t: &Target, a: &Alarm, now: i64) -> (String, String) {
        let state = match a.kind {
            Kind::Down => "not answering",
            Kind::Loss => "losing pings",
            _ => "slow",
        };
        let lasted = dur(now - a.row.since_ms);
        (
            format!("[pingrail] {} is still {state} ({lasted})", t.name),
            format!(
                "{} is still {state}.\n\nSince: {}\nAlarm: {}\nMeasured from: {}\n\n{}",
                named(t),
                env.stamp(a.row.since_ms),
                a.what(),
                env.host,
                env.foot()
            ),
        )
    }

    /// Every target, or every one beyond the local network, has gone quiet.
    fn mail_cut_start(&self, env: &Env, kind: Kind, since: i64, n: u64) -> (String, String) {
        let (subject, first, why, reach) = if kind == Kind::Cutoff {
            (
                format!("[pingrail] None of the {n} targets is answering"),
                format!("pingrail on {} has not had a reply from any of its {} since {}.", env.host, plural(n, "running target", "running targets"), env.stamp(since)),
                "When every target goes quiet at once, the fault is most likely something they share: this machine's own connection, or the link to where the targets are. So this is one alarm, not one for each target.",
                "If you are reading this while it is still going on, this machine can still send mail, so its own connection works and the fault is further along.",
            )
        } else {
            (
                "[pingrail] Nothing beyond the local network is answering".to_string(),
                format!(
                    "pingrail on {} has not had a reply from any of its {} beyond the local network since {}. Targets on the local network still answer.",
                    env.host,
                    plural(n, "target", "targets"),
                    env.stamp(since)
                ),
                "The fault is most likely the internet connection, so this is one alarm, not one for each target.",
                "If you are reading this while it is still going on, this machine can still send mail, so the internet connection works at least in part and the fault is further along.",
            )
        };
        (subject, format!("{first}\n\n{why}\n\n{reach}\n\nYou will get one more email when they answer again.\n\n{}", env.foot()))
    }

    /// The email about the monitor's own connection once it is back. `told`:
    /// the email about its start went out.
    fn mail_cut(&self, env: &Env, a: &Alarm, ended: i64, still: &[String], told: bool) -> (String, String) {
        let n = a.detail.targets.unwrap_or(0) as u64;
        let span = if env.local(a.row.since_ms).date_naive() == env.local(ended).date_naive() {
            format!("{} to {}", env.hm(a.row.since_ms), env.hm(ended))
        } else {
            env.span(a.row.since_ms, ended)
        };
        let lasted = dur(ended - a.row.since_ms);
        let (subject, first, why) = if a.kind == Kind::Cutoff {
            (
                format!("[pingrail] {} was cut off from {span}", env.host),
                format!("pingrail on {} could not reach any of its {} from {}. That is {lasted}.", env.host, plural(n, "running target", "running targets"), env.span(a.row.since_ms, ended)),
                "When every target goes quiet at once, the fault is most likely this machine's own connection, so no alarm was raised for each target.",
            )
        } else {
            (
                format!("[pingrail] The internet connection at {} was down from {span}", env.host),
                format!(
                    "pingrail on {} could not reach any of its {} beyond the local network from {}. That is {lasted}.",
                    env.host,
                    plural(n, "target", "targets"),
                    env.span(a.row.since_ms, ended)
                ),
                "Targets on the local network kept answering, so the fault is most likely the internet connection, and no alarm was raised for each target.",
            )
        };
        let still = if still.is_empty() {
            "Every target is answering again.".to_string()
        } else {
            format!("Still not answering now: {}. Each gets its own alarm.", still.join(", "))
        };
        let alone = if told { "" } else { " No email about it could be sent while it lasted." };
        (subject, format!("{first}\n\n{why}{alone}\n\n{still}\n\n{}", env.foot()))
    }
}

/// Pings needed in a window of `w` ms at one every `iv` ms before a share
/// of them means anything: half of what a full window holds, and ten.
fn enough(w: i64, iv: i64) -> u64 {
    ((w / iv.max(1)) / 2).max(10) as u64
}

/// Pings sent and lost in `[from, to)`, leaving out the target's outages and
/// the monitor's cut-offs: those have alarms of their own.
fn loss_in(store: &Store, t: &Target, outages: &[Alarm], public: bool, also: Option<(i64, i64)>, from: i64, to: i64) -> Result<(u64, u64)> {
    let (sent, answered, _, _) = store.round_totals(t.id, from, to)?;
    let (mut sent, mut lost) = (sent, sent - answered);
    let mut spans: Vec<(i64, i64)> = outages
        .iter()
        .filter(|a| match a.kind {
            Kind::Down => a.row.target_id == Some(t.id),
            Kind::Cutoff => true,
            Kind::Internet => public,
            _ => false,
        })
        .map(|a| (a.row.since_ms, a.row.ended_ms.unwrap_or(to)))
        .chain(also)
        .map(|(a, b)| (a.max(from), b.min(to)))
        .filter(|(a, b)| b > a)
        .collect();
    spans.sort_unstable();
    let mut merged: Vec<(i64, i64)> = Vec::new();
    for (a, b) in spans {
        match merged.last_mut() {
            Some(last) if a <= last.1 => last.1 = last.1.max(b),
            _ => merged.push((a, b)),
        }
    }
    for (a, b) in merged {
        let (s, ans, _, _) = store.round_totals(t.id, a, b)?;
        sent = sent.saturating_sub(s);
        lost = lost.saturating_sub(s - ans);
    }
    Ok((sent, lost))
}

// ----- the running service -----------------------------------------------------

/// How often the alarms are worked out, and how long an email that cannot
/// be sent is kept trying.
const PASS_EVERY: Duration = Duration::from_secs(5);
const GIVE_UP_AFTER: i64 = 72 * HOUR;

pub struct Alarms {
    store: Arc<Store>,
    env: Env,
    data_dir: PathBuf,
    system: bool,
    /// Wakes the outbox when there is something to send.
    post: tokio::sync::Notify,
    last_test: Mutex<Option<std::time::Instant>>,
}

impl Alarms {
    /// Start working out alarms and sending their emails. `url` is where
    /// the web UI is, for emails to point at.
    pub fn start(store: Arc<Store>, cfg: &crate::config::Config, data_dir: PathBuf, system: bool, url: Option<String>) -> Arc<Alarms> {
        let env = Env {
            host: crate::util::hostname().unwrap_or_else(|| "this machine".into()),
            url,
            lag_ms: cfg.probe.timeout_ms as i64 + cfg.storage.write_interval().as_millis() as i64 + 500,
            tz: None,
        };
        let alarms = Arc::new(Alarms { store, env, data_dir, system, post: tokio::sync::Notify::new(), last_test: Mutex::new(None) });
        let a = alarms.clone();
        tokio::spawn(async move {
            let mut ev = Evaluator::default();
            let mut iv = tokio::time::interval(PASS_EVERY);
            iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // Let the first samples after a start arrive before judging.
            tokio::time::sleep(Duration::from_secs(10)).await;
            loop {
                iv.tick().await;
                let (store, env) = (a.store.clone(), a.env.clone());
                let r = tokio::task::spawn_blocking(move || {
                    let r = ev.pass(&store, &env, now_ms());
                    (ev, r)
                })
                .await;
                match r {
                    Ok((back, r)) => {
                        ev = back;
                        if let Err(e) = r {
                            tracing::warn!("working out alarms failed: {e:#}");
                        }
                    }
                    Err(e) => {
                        tracing::error!("the alarm task stopped: {e}");
                        return;
                    }
                }
                a.post.notify_one();
            }
        });
        let a = alarms.clone();
        tokio::spawn(async move {
            loop {
                let _ = tokio::time::timeout(Duration::from_secs(15), a.post.notified()).await;
                if let Err(e) = a.flush().await {
                    tracing::warn!("sending alarm emails failed: {e:#}");
                }
            }
        });
        alarms
    }

    fn password_file(&self) -> PathBuf {
        self.data_dir.join("mail.key")
    }

    /// The mail password, if one is saved.
    fn password(&self) -> Option<String> {
        std::fs::read_to_string(self.password_file()).ok().map(|p| p.trim_end_matches(['\r', '\n']).to_string()).filter(|p| !p.is_empty())
    }

    pub fn password_set(&self) -> bool {
        self.password().is_some()
    }

    pub fn settings(&self) -> Settings {
        load_settings(&self.store)
    }

    /// Save the settings, and the mail password when a new one is given
    /// (`Some("")` forgets it).
    pub fn save(&self, s: Settings, password: Option<String>) -> std::result::Result<Settings, String> {
        let s = s.cleaned()?;
        if let Some(p) = password {
            if p.len() > 1024 || p.chars().any(|c| c.is_control()) {
                return Err("The mail password is not one a mail server can take.".into());
            }
            if p.is_empty() {
                let _ = std::fs::remove_file(self.password_file());
            } else {
                crate::tls::write_private(&self.password_file(), p.as_bytes(), self.system).map_err(|e| format!("Could not save the mail password: {e}."))?;
            }
        }
        // No username, no use for a password.
        if s.mail.username.is_empty() {
            let _ = std::fs::remove_file(self.password_file());
        }
        let json = serde_json::to_string(&s).map_err(|e| e.to_string())?;
        self.store.meta_set(SETTINGS_KEY, &json).map_err(|e| format!("Could not save the settings: {e}."))?;
        self.post.notify_one();
        Ok(s)
    }

    /// Send a test email with `s` (what is in the form, saved or not) and
    /// `password` (None = the saved one).
    pub async fn test(&self, s: Settings, password: Option<String>) -> std::result::Result<String, String> {
        let s = s.cleaned()?;
        if s.to.is_empty() {
            return Err("Enter at least one address to send alarm emails to.".into());
        }
        if !s.mail.ready() {
            return Err("Enter the mail server and a From address first.".into());
        }
        {
            let mut last = self.last_test.lock().unwrap();
            if last.is_some_and(|t| t.elapsed() < Duration::from_secs(5)) {
                return Err("A test email was sent a moment ago. Give it a few seconds.".into());
            }
            *last = Some(std::time::Instant::now());
        }
        let password = password.filter(|p| !p.is_empty()).or_else(|| self.password());
        let now = now_ms();
        let subject = format!("[pingrail] Test email from {}", self.env.host);
        let body = format!(
            "This is the test email you asked for at {}. Alarm emails from pingrail on {} will come from this address and go to: {}.\n\n{}",
            self.env.stamp(now),
            self.env.host,
            s.to.join(", "),
            self.env.foot()
        );
        crate::mail::send(&s.mail, password.as_deref(), &self.env.host, crate::mail::Email { to: &s.to, subject: &subject, body: &body })
            .await
            .map(|()| format!("Test email accepted by {} at {}.", s.mail.host, self.env.hm(now_ms())))
            .map_err(|e| e.text)
    }

    /// Send what is waiting in the outbox.
    async fn flush(&self) -> Result<()> {
        let now = now_ms();
        let pending = blocking(&self.store, move |s| {
            let dropped = s.mail_drop(now - GIVE_UP_AFTER)?;
            if dropped > 0 {
                tracing::warn!("gave up on {dropped} alarm email(s) that could not be sent for three days");
            }
            s.mail_pending()
        })
        .await?;
        if pending.is_empty() {
            return Ok(());
        }
        let settings = self.settings();
        if !settings.mail_ready() {
            return Ok(());
        }
        // One email that is due takes the rest along: they all wait on the
        // same mail server, and this keeps a held-up start and end together.
        if !pending.iter().any(|m| m.next_ms <= now) {
            return Ok(());
        }
        let password = self.password();
        // Emails held up for a while (the line was down, say) go out as one.
        let mut batches: Vec<(String, String, Vec<crate::store::MailRow>)> = if pending.len() >= 2 && pending[0].created_ms < now - 60_000 {
            let mut body = format!("{} from pingrail on {} could not be sent until now. Here they are, oldest first.\n", plural(pending.len() as u64, "email", "emails"), self.env.host);
            for m in &pending {
                body.push_str(&format!("\n----------------------------------------\n{}\nWritten at {}\n\n{}", m.subject, self.env.stamp(m.created_ms), m.body));
            }
            vec![(format!("[pingrail] {} alarm emails from {}", pending.len(), self.env.host), body, pending)]
        } else {
            pending.into_iter().map(|m| (m.subject.clone(), m.body.clone(), vec![m])).collect()
        };
        batches.reverse();
        while let Some((subject, body, rows)) = batches.pop() {
            let mail = crate::mail::Email { to: &settings.to, subject: &subject, body: &body };
            match crate::mail::send(&settings.mail, password.as_deref(), &self.env.host, mail).await {
                Ok(()) => {
                    tracing::info!("alarm email sent: {subject}");
                    let at = now_ms();
                    blocking(&self.store, move |s| s.mail_sent(&rows, at)).await?;
                }
                Err(e) => {
                    tracing::warn!("alarm email not sent: {e}");
                    // Sooner at first, then every five minutes; settings
                    // that are refused are not hammered. The rest would meet
                    // the same fate, so they wait the same time.
                    let attempts = rows.iter().map(|m| m.attempts).max().unwrap_or(0);
                    let wait = if e.temporary { (15_000i64 << attempts.min(5)).min(300_000) } else { 600_000 };
                    let (at, text) = (now_ms() + wait, e.text.clone());
                    let waiting: Vec<i64> = batches.iter().flat_map(|(_, _, rows)| rows.iter().map(|m| m.id)).collect();
                    blocking(&self.store, move |s| {
                        for m in &rows {
                            s.mail_failed(m.id, at, &text)?;
                        }
                        for id in waiting {
                            s.mail_wait(id, at)?;
                        }
                        Ok(())
                    })
                    .await?;
                    break;
                }
            }
        }
        Ok(())
    }

    fn view(&self, a: Alarm, targets: &[Target]) -> AlarmView {
        let name = match a.row.target_id {
            Some(id) => targets.iter().find(|t| t.id == id).map_or_else(|| "a removed target".to_string(), |t| t.name.clone()),
            None => self.env.host.clone(),
        };
        AlarmView {
            id: a.row.id,
            target_id: a.row.target_id,
            name,
            kind: a.kind,
            since_ms: a.row.since_ms,
            raised_ms: a.row.raised_ms,
            ended_ms: a.row.ended_ms,
            what: a.what(),
            lost: a.detail.lost,
            mail_note: a.row.mail_note.clone(),
            mail_start_ms: a.row.mail_start_ms,
            mail_end_ms: a.row.mail_end_ms,
        }
    }

    /// What is going on now, for the banner and the marks.
    pub fn now(&self, store: &Store) -> Result<AlarmsNow> {
        let targets = store.list_targets()?;
        let settings = load_settings(store);
        let now = now_ms();
        let active = store.alarms_active()?.into_iter().filter_map(Alarm::from_row).map(|a| self.view(a, &targets)).collect();
        let paused = store.alarm_targets()?.into_iter().filter_map(|(id, (_, p))| p.filter(|until| *until > now).map(|until| (id, until))).collect();
        Ok(AlarmsNow {
            active,
            paused,
            mail_ready: settings.mail_ready(),
            recipients: settings.to.len(),
            mail_error: store.mail_last_error()?,
        })
    }

    /// The latest alarms, newest first: one target's, or all.
    pub fn recent(&self, store: &Store, target: Option<i64>, limit: usize) -> Result<Vec<AlarmView>> {
        let targets = store.list_targets()?;
        Ok(store.alarms_recent(target, limit)?.into_iter().filter_map(Alarm::from_row).map(|a| self.view(a, &targets)).collect())
    }
}

/// A target's own alarm settings, and until when its alarms are paused.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct TargetAlarmView {
    #[serde(flatten)]
    pub alarm: TargetAlarm,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paused_until_ms: Option<i64>,
    /// The limits under Menu › Alarms, for the form to show.
    #[serde(default)]
    pub general: Limits,
}

pub fn target_alarm(store: &Store, id: i64) -> Result<TargetAlarmView> {
    let (cfg, paused) = store.alarm_targets()?.remove(&id).unwrap_or_default();
    let now = now_ms();
    Ok(TargetAlarmView {
        alarm: serde_json::from_str(&cfg).unwrap_or_default(),
        paused_until_ms: paused.filter(|p| *p > now),
        general: load_settings(store).limits,
    })
}

pub fn set_target_alarm(store: &Store, id: i64, alarm: TargetAlarm) -> Result<()> {
    let alarm = match alarm {
        TargetAlarm::Own(l) => TargetAlarm::Own(l.cleaned()),
        other => other,
    };
    store.alarm_target_set(id, Some(&serde_json::to_string(&alarm)?), None)
}

/// Pause a target's alarms for `minutes` (None = until resumed, 0 = resume).
pub fn pause_target(store: &Store, id: i64, minutes: Option<u32>) -> Result<()> {
    let until = match minutes {
        None => Some(i64::MAX),
        Some(0) => None,
        Some(m) => Some(now_ms() + m.min(525_600) as i64 * 60_000),
    };
    store.alarm_target_set(id, None, Some(until))
}

/// The address of the web UI for emails: this machine's name and the port
/// the service listens on.
pub fn web_url(listen: &str) -> Option<String> {
    let port = listen.rsplit_once(':')?.1.parse::<u16>().ok()?;
    let host = crate::util::hostname().or_else(|| crate::util::lan_ip().map(|ip| ip.to_string()))?;
    Some(if port == 443 { format!("https://{host}") } else { format!("https://{host}:{port}") })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::NewTarget;
    use crate::store::RoundRecord;

    struct Bench {
        dir: PathBuf,
        store: Arc<Store>,
        env: Env,
        ev: Evaluator,
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.dir).ok();
        }
    }

    fn bench(mail: bool) -> Bench {
        let dir = std::env::temp_dir().join(format!("pingrail-test-{}", crate::config::random_hex(4)));
        let store = Store::open(&dir.join("t.db")).unwrap();
        if mail {
            let s = Settings {
                to: vec!["ulrich@example.com".into(), "office@example.com".into()],
                mail: MailServer { host: "smtp.example.com".into(), from: "pingrail <alarms@example.com>".into(), ..Default::default() },
                ..Default::default()
            };
            store.meta_set(SETTINGS_KEY, &serde_json::to_string(&s).unwrap()).unwrap();
        }
        let env = Env { host: "office-pc".into(), url: Some("https://office-pc:8040".into()), lag_ms: 0, tz: FixedOffset::east_opt(7200) };
        Bench { dir, store, env, ev: Evaluator::default() }
    }

    impl Bench {
        fn target(&self, host: &str, name: &str, interval_ms: u32) -> Target {
            self.store.add_target(&NewTarget { host: host.into(), name: Some(name.into()), interval_ms: Some(interval_ms), trace: Some(false), ..Default::default() }, 1000).unwrap()
        }

        /// Pings from `from_s` to `to_s`, lost where `lost` says so.
        fn pings(&self, t: &Target, from_s: i64, to_s: i64, rtt_ms: f64, lost: impl Fn(i64) -> bool) {
            let iv = t.interval_ms as i64;
            let rows: Vec<RoundRecord> = (from_s * 1000 / iv..to_s * 1000 / iv)
                .map(|k| RoundRecord { target_id: t.id, ts_ms: k * iv, interval_ms: t.interval_ms, rtt_us: (!lost(k * iv / 1000)).then_some((rtt_ms * 1000.0) as u32), hops: None })
                .collect();
            self.store.insert_rounds(&rows).unwrap();
        }

        /// A pass every five seconds from `from_s` up to and including `to_s`.
        fn run(&mut self, from_s: i64, to_s: i64) {
            let mut s = from_s;
            while s <= to_s {
                self.ev.pass(&self.store, &self.env, s * 1000).unwrap();
                s += 5;
            }
        }

        fn subjects(&self) -> Vec<String> {
            self.store.mail_pending().unwrap().into_iter().map(|m| m.subject).collect()
        }

        fn body(&self, subject_has: &str) -> String {
            self.store.mail_pending().unwrap().into_iter().find(|m| m.subject.contains(subject_has)).map(|m| m.body).unwrap_or_default()
        }

        fn alarms(&self) -> Vec<(String, i64, Option<i64>, Option<String>)> {
            let mut rows = self.store.alarms_recent(None, 100).unwrap();
            rows.reverse();
            rows.into_iter().map(|a| (a.kind, a.since_ms / 1000, a.ended_ms.map(|e| e / 1000), a.mail_note)).collect()
        }
    }

    #[test]
    fn not_answering_is_one_alarm_and_two_emails() {
        let mut b = bench(true);
        let t = b.target("192.168.10.60", "Printer", 1000);
        // Answers for ten minutes, is silent for 100 seconds, answers again.
        b.pings(&t, 0, 1000, 0.6, |s| (600..700).contains(&s));
        b.run(500, 625);
        assert!(b.alarms().is_empty(), "25 seconds of silence is under the limit");
        b.run(630, 690);
        assert_eq!(b.alarms(), [("down".to_string(), 600, None, None)]);
        assert_eq!(b.subjects(), ["[pingrail] Printer is not answering"]);
        let body = b.body("not answering");
        assert!(body.starts_with("Printer (192.168.10.60) has not answered a ping for 30 seconds.\n\nNo reply since: 02:10:00 on 1 January\nLast reply: 02:09:59\nMeasured from: office-pc\n\n"), "{body}");
        assert!(body.contains("You will get one more email when Printer answers again.\n\nOpen pingrail: https://office-pc:8040\n\nTimes are UTC+02:00."));
        b.run(695, 800);
        assert_eq!(b.alarms(), [("down".to_string(), 600, Some(700), None)]);
        assert_eq!(b.subjects(), ["[pingrail] Printer is not answering", "[pingrail] Printer is answering again (was down 1 min 40 s)"]);
        let body = b.body("answering again");
        assert!(body.contains("Not answering for: 1 min 40 s, from 02:10:00 to 02:11:40\nPings lost: 100\nSince it came back: 0.60 ms on average, none lost\n"), "{body}");
        // The two minutes it was away are not then reported as packet loss.
        b.run(805, 995);
        assert_eq!(b.alarms().len(), 1);
        // What the screens are told.
        let alarms = Alarms { store: b.store.clone(), env: b.env.clone(), data_dir: b.dir.clone(), system: false, post: tokio::sync::Notify::new(), last_test: Mutex::new(None) };
        let recent = alarms.recent(&b.store, Some(t.id), 10).unwrap();
        assert_eq!((recent[0].name.as_str(), recent[0].what.as_str(), recent[0].lost), ("Printer", "Not answering for 30 s", Some(100)));
        assert!(alarms.now(&b.store).unwrap().active.is_empty());
    }

    #[test]
    fn a_camera_that_restarts_every_hour_is_caught_by_its_loss_limit() {
        let mut b = bench(true);
        let t = b.target("192.168.10.44", "Lobby camera", 2500);
        // Its own limits: a minute of silence, or more than 0.5 % lost in an hour.
        set_target_alarm(&b.store, t.id, TargetAlarm::Own(Limits { down_s: 60, loss_pct: 0.5, loss_min: 60, slow: false, ..Default::default() })).unwrap();
        // A clean hour, then 40 seconds of silence on the hour three times, then none.
        b.pings(&t, 0, 7 * 3600, 1.8, |s| (3600..4 * 3600).contains(&s) && s % 3600 < 40);
        b.run(3000, 3600 + 35);
        assert!(b.alarms().is_empty(), "silence that has not ended is not yet loss");
        b.run(3600 + 40, 3600 + 120);
        assert_eq!(b.alarms().iter().map(|a| a.0.as_str()).collect::<Vec<_>>(), ["loss"], "40 s is not an outage, but it is over 0.5 %");
        assert_eq!(b.subjects(), ["[pingrail] Lobby camera is losing pings (1.11 % over 60 min)"]);
        let body = b.body("losing pings");
        assert!(body.starts_with("Lobby camera (192.168.10.44) lost 16 of its last 1,440 pings. That is 1.11 % over 60 min; its limit is 0.5 %.\n\nLongest stretch with no reply: 40 s, from 03:00:00\nOn record: 16 of 1,"), "{body}");
        assert!(body.contains("You will get one more email when its loss over 60 min has stayed under 0.5 % for 15 min."));
        // It keeps restarting, and each restart pushes the last one out of
        // the hour for a moment: still one alarm.
        b.run(3600 + 125, 4 * 3600);
        assert_eq!(b.alarms(), [("loss".to_string(), 3645, None, None)]);
        // The last restart leaves the hour at 4 h 0 min 40 s; 15 minutes under the limit end it.
        b.run(4 * 3600 + 5, 4 * 3600 + 20 * 60);
        let a = b.alarms();
        assert!(a.len() == 1 && a[0].2.is_some_and(|e| (4 * 3600 + 15 * 60..4 * 3600 + 17 * 60).contains(&e)), "{a:?}");
        assert_eq!(b.subjects().last().unwrap(), "[pingrail] Lobby camera has stopped losing pings");
    }

    #[test]
    fn slow_is_an_average_over_the_limit() {
        let mut b = bench(true);
        let t = b.target("vpn.example.com", "Head office VPN", 1000);
        b.pings(&t, 0, 3600, 38.0, |_| false);
        b.pings(&t, 3600, 4200, 212.0, |_| false);
        b.pings(&t, 4200, 5400, 38.0, |_| false);
        b.run(3000, 3600);
        assert!(b.alarms().is_empty());
        b.run(3605, 4100);
        assert_eq!(b.alarms().iter().map(|a| a.0.as_str()).collect::<Vec<_>>(), ["slow"]);
        let subject = b.subjects().remove(0);
        assert!(subject.starts_with("[pingrail] Head office VPN is slow ("), "{subject}");
        let body = b.body("is slow");
        assert!(body.contains("Its limit is 150 ms.\n\nIts usual average: 38.0 ms, over the 24 hours before\nSlowest reply: 212 ms\nPings lost in the same 5 min: none\n"), "{body}");
        b.run(4105, 4700);
        assert!(b.alarms()[0].2.is_some());
        assert!(b.subjects()[1].starts_with("[pingrail] Head office VPN is back to speed ("));
    }

    #[test]
    fn a_dead_line_is_one_email_not_one_per_target() {
        let mut b = bench(true);
        let router = b.target("192.168.10.1", "Core router", 1000);
        let dns = b.target("8.8.8.8", "Google DNS", 1000);
        let cf = b.target("1.1.1.1", "Cloudflare DNS", 1000);
        let out = |s: i64| (1000..2000).contains(&s);
        // The internet line drops for 1000 s; the router keeps answering.
        b.pings(&router, 0, 4000, 0.5, |_| false);
        b.pings(&dns, 0, 4000, 16.0, out);
        // One of them stays down after the line is back.
        b.pings(&cf, 0, 4000, 14.0, |s| s >= 1000);
        b.run(900, 1990);
        assert_eq!(b.alarms(), [("internet".to_string(), 1000, None, None)]);
        // One email is tried at once: it leaves if the fault is further along.
        assert_eq!(b.subjects(), ["[pingrail] Nothing beyond the local network is answering"]);
        assert!(b.body("Nothing beyond").starts_with("pingrail on office-pc has not had a reply from any of its 2 targets beyond the local network since 02:16:40 on"));
        // It could not leave, so the one at the end takes its place.
        b.run(1995, 2100);
        let a = b.alarms();
        assert_eq!(a[0].0, "internet");
        assert!(a[0].2.is_some());
        // The target that did not come back gets its own alarm, from when it really went.
        assert_eq!((a[1].0.as_str(), a[1].1, a[1].2), ("down", 1000, None));
        let s = b.subjects();
        assert_eq!(s[0], "[pingrail] The internet connection at office-pc was down from 02:16 to 02:33");
        assert_eq!(s[1], "[pingrail] Cloudflare DNS is not answering");
        let body = b.body("internet connection");
        assert!(body.starts_with("pingrail on office-pc could not reach any of its 2 targets beyond the local network from 02:16:40 to 02:33:20. That is 16 min 40 s."), "{body}");
        assert!(body.contains("No email about it could be sent while it lasted."));
        assert!(body.contains("Still not answering now: Cloudflare DNS. Each gets its own alarm."));
        assert!(b.body("Cloudflare DNS is not").contains("has not answered a ping for 16 min"));
        // The outage is not counted as packet loss for the one that came back.
        b.run(2105, 2400);
        assert_eq!(b.alarms().len(), 2);
    }

    #[test]
    fn everything_quiet_is_this_machine_cut_off() {
        let mut b = bench(true);
        let router = b.target("192.168.10.1", "Core router", 1000);
        let dns = b.target("8.8.8.8", "Google DNS", 2500);
        for t in [&router, &dns] {
            b.pings(t, 0, 3000, 1.0, |s| (1000..1500).contains(&s));
        }
        b.run(900, 1600);
        let a = b.alarms();
        assert_eq!(a.len(), 1);
        assert_eq!((a[0].0.as_str(), a[0].1, a[0].2), ("cutoff", 1000, Some(1500)));
        assert_eq!(b.subjects(), ["[pingrail] office-pc was cut off from 02:16 to 02:25"]);
        assert!(b.body("cut off").contains("could not reach any of its 2 running targets from 02:16:40 to 02:25:00. That is 8 min 20 s.\n\nWhen every target goes quiet at once"));
        assert!(b.body("cut off").contains("Every target is answering again."));
        // Targets that share a link somewhere else: the first email does leave,
        // and the one at the end no longer says it could not.
        let mut b = bench(true);
        let cams = [b.target("10.20.0.11", "Gate camera", 1000), b.target("10.20.0.12", "Yard camera", 1000)];
        for t in &cams {
            b.pings(t, 0, 3000, 30.0, |s| (1000..1500).contains(&s));
        }
        b.run(900, 1200);
        let waiting = b.store.mail_pending().unwrap();
        assert_eq!(waiting.iter().map(|m| m.subject.as_str()).collect::<Vec<_>>(), ["[pingrail] None of the 2 targets is answering"]);
        assert!(waiting[0].body.contains("this machine can still send mail"));
        b.store.mail_sent(&waiting, 1_100_000).unwrap();
        b.run(1205, 1600);
        assert_eq!(b.subjects(), ["[pingrail] office-pc was cut off from 02:16 to 02:25"]);
        assert!(!b.body("cut off").contains("No email about it could be sent"));
        // One target alone is never a cut-off: it is just that target.
        let mut b = bench(true);
        let only = b.target("8.8.8.8", "Google DNS", 1000);
        b.pings(&only, 0, 2000, 16.0, |s| s >= 1000);
        b.run(900, 1100);
        assert_eq!(b.alarms(), [("down".to_string(), 1000, None, None)]);
    }

    #[test]
    fn a_target_that_keeps_dropping_is_called_unstable_once() {
        let mut b = bench(true);
        let t = b.target("192.168.10.44", "Lobby camera", 1000);
        // Five 40-second drops, three minutes apart, then steady.
        b.pings(&t, 0, 4000, 1.8, |s| (1000..1900).contains(&s) && (s - 1000) % 180 < 40);
        b.run(900, 1900);
        let a = b.alarms();
        assert_eq!(a.len(), 5);
        assert_eq!(a.iter().map(|x| x.3.as_deref()).collect::<Vec<_>>(), [None, None, None, Some("unstable"), Some("unstable")]);
        let s = b.subjects();
        // Three alarms announced and ended, then one email for the pattern.
        assert_eq!(s.len(), 7, "{s:#?}");
        assert_eq!(s[6], "[pingrail] Lobby camera is unstable (4 alarms in 15 min)");
        let body = b.body("unstable");
        assert!(body.starts_with("Lobby camera (192.168.10.44) has raised 4 alarms since 02:17:10:\n\n02:17:10  Not answering for 30 s, for 40 s\n"), "{body}");
        assert!(body.contains("The next one comes when Lobby camera has raised no alarm for 15 min."));
        // Fifteen minutes without a new alarm: one email to say so.
        b.run(1905, 2800);
        let s = b.subjects();
        assert_eq!(s.len(), 8, "{s:#?}");
        assert_eq!(s[7], "[pingrail] Lobby camera is steady again");
        assert!(b.body("steady again").contains("While it was unstable it raised 5 alarms, between 02:17:10 to 02:29:10."), "{}", b.body("steady again"));
    }

    #[test]
    fn paused_switched_off_and_visitors_destinations_stay_quiet() {
        let mut b = bench(true);
        let t = b.target("192.168.10.60", "Printer", 1000);
        let quiet = b.target("192.168.10.61", "Label printer", 1000);
        let router = b.target("192.168.10.1", "Core router", 1000);
        set_target_alarm(&b.store, quiet.id, TargetAlarm::None).unwrap();
        let theirs = b.store.add_target_owned(&NewTarget { host: "192.168.10.99".into(), ..Default::default() }, 1000, Some(7), None).unwrap();
        b.pings(&router, 0, 3000, 0.5, |_| false);
        for x in [&t, &quiet, &theirs] {
            b.pings(x, 0, 3000, 0.6, |s| s >= 1000);
        }
        b.run(900, 1100);
        assert_eq!(b.alarms(), [("down".to_string(), 1000, None, None)], "only the watched target raises one");
        assert_eq!(b.subjects().len(), 1);
        // Pausing its alarms ends the alarm without an email, and none is raised while paused.
        b.store.alarm_target_set(t.id, None, Some(Some(1500 * 1000))).unwrap();
        b.run(1105, 1400);
        assert_eq!(b.alarms(), [("down".to_string(), 1000, Some(1105), Some("stopped".into()))]);
        assert_eq!(b.subjects().len(), 1);
        // When the pause runs out it is still down: a new alarm.
        b.run(1405, 1600);
        assert_eq!(b.alarms().len(), 2);
        assert_eq!(b.subjects().len(), 2);
        // Pausing the target itself (no more pings) ends that one quietly too.
        b.store.update_target(t.id, &crate::model::TargetPatch { enabled: Some(false), ..Default::default() }).unwrap();
        b.run(1605, 1700);
        assert!(b.alarms().iter().all(|a| a.2.is_some()));
        assert_eq!(b.subjects().len(), 2);
        // Removing a target removes its alarms.
        b.store.delete_target(t.id).unwrap();
        assert!(b.alarms().is_empty());
    }

    #[test]
    fn without_mail_alarms_still_show() {
        let mut b = bench(false);
        let t = b.target("192.168.10.60", "Printer", 1000);
        b.pings(&t, 0, 2000, 0.6, |s| (1000..1200).contains(&s));
        b.run(900, 1300);
        assert_eq!(b.alarms(), [("down".to_string(), 1000, Some(1200), Some("off".into()))]);
        assert!(b.subjects().is_empty());
    }

    #[test]
    fn reminders_when_asked_for() {
        let mut b = bench(true);
        let mut s = load_settings(&b.store);
        s.remind = Remind::Hour;
        b.store.meta_set(SETTINGS_KEY, &serde_json::to_string(&s).unwrap()).unwrap();
        let t = b.target("192.168.10.60", "Printer", 2500);
        b.pings(&t, 0, 9000, 0.6, |s| s >= 1000);
        b.run(900, 1000 + 2 * 3600 + 100);
        assert_eq!(
            b.subjects(),
            ["[pingrail] Printer is not answering", "[pingrail] Printer is still not answering (1 h)", "[pingrail] Printer is still not answering (2 h)"]
        );
    }

    #[test]
    fn settings_are_checked() {
        let ok = Settings { to: vec![" ulrich@example.com ".into(), "ULRICH@example.com".into(), "".into()], ..Default::default() }.cleaned().unwrap();
        assert_eq!(ok.to, ["ulrich@example.com"]);
        assert!(!ok.mail_ready());
        let bad = Settings { to: vec!["someone@example.com\r\nBcc: x@y.z".into()], ..Default::default() }.cleaned();
        assert!(bad.unwrap_err().contains("is not an email address"));
        let wild = Settings {
            limits: Limits { down_s: 0, loss_pct: f64::NAN, loss_min: 99_999, slow_ms: -5.0, slow_min: 0, ..Default::default() },
            unstable_count: 0,
            ..Default::default()
        }
        .cleaned()
        .unwrap();
        assert_eq!((wild.limits.down_s, wild.limits.loss_pct, wild.limits.loss_min, wild.limits.slow_ms, wild.limits.slow_min, wild.unstable_count), (5, 2.0, 1440, 1.0, 1, 1));
        let m = |host: &str, from: &str| Settings { mail: MailServer { host: host.into(), from: from.into(), ..Default::default() }, ..Default::default() }.cleaned();
        assert!(m("smtp.example.com", "pingrail <alarms@example.com>").is_ok());
        assert!(m("smtp example", "a@b.com").unwrap_err().contains("mail server"));
        assert!(m("smtp.example.com", "nobody").unwrap_err().contains("From"));
        assert!(Settings { to: (0..11).map(|i| format!("a{i}@example.com")).collect(), ..Default::default() }.cleaned().unwrap_err().contains("at most 10"));
        // What a target's own settings look like on the wire.
        let own: TargetAlarm = serde_json::from_str(r#"{"mode":"own","down":true,"down_s":60,"loss":true,"loss_pct":0.5,"loss_min":60,"slow":false}"#).unwrap();
        assert_eq!(own, TargetAlarm::Own(Limits { down_s: 60, loss_pct: 0.5, loss_min: 60, slow: false, ..Default::default() }));
        assert_eq!(serde_json::from_str::<TargetAlarm>(r#"{"mode":"none"}"#).unwrap(), TargetAlarm::None);
        assert_eq!(serde_json::to_string(&TargetAlarm::General).unwrap(), r#"{"mode":"general"}"#);
        assert_eq!((dur(40_000), dur(2_292_000), dur(7_500_000), dur(273_600_000)), ("40 s".into(), "38 min 12 s".into(), "2 h 5 min".into(), "3 days 4 h".into()));
        assert_eq!((pct(1.1111), pct(2.0), pct(0.5), pct(12.34), pct(100.0)), ("1.11 %".into(), "2 %".into(), "0.5 %".into(), "12.3 %".into(), "100 %".into()));
    }
}
