//! PDF and PNG reports. Each page is laid out as SVG (A4 portrait, 1 unit =
//! 1 pt), then rasterised with resvg for PNG or converted to vector PDF pages
//! with svg2pdf. Fonts are embedded in the output so it looks identical
//! everywhere. The report's own typefaces, Source Sans 3 and Source Serif 4,
//! are built into the program; the DejaVu files installed beside it (see
//! `font_dirs`) stand in for characters those two lack.

use anyhow::{anyhow, Result};
use chrono::{DateTime, Datelike, FixedOffset, TimeZone, Utc};
use resvg::{tiny_skia, usvg};
use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use crate::analysis::{self, Privacy, Recorded, Scope};
use crate::config::now_ms;
use crate::engine::Rdns;
use crate::model::{Detail, HopReading, HopStat, LiveStatus, Point, ReportFormat, Stats, Thresholds, Timeline, TimelineMode};
use crate::stats::{axis_max, fmt_ms, nice_ceil, percentile};
use crate::store::Store;

/// Source Sans 3 and Source Serif 4 (SIL Open Font License 1.1), the files
/// exactly as Adobe publishes them.
const SANS: &[u8] = include_bytes!("../assets/fonts/report/SourceSans3-Regular.ttf");
const SANS_SEMI: &[u8] = include_bytes!("../assets/fonts/report/SourceSans3-Semibold.ttf");
const SANS_BOLD: &[u8] = include_bytes!("../assets/fonts/report/SourceSans3-Bold.ttf");
const SERIF_BOLD: &[u8] = include_bytes!("../assets/fonts/report/SourceSerif4-Bold.ttf");
const BODY_FAMILY: &str = "Source Sans 3";
const HEAD_FAMILY: &str = "Source Serif 4";
/// Looked for beside the program, for characters the built-in faces lack.
const FALLBACK_FILES: [&str; 2] = ["DejaVuSans.ttf", "DejaVuSans-Bold.ttf"];
const FALLBACK_FAMILY: &str = "DejaVu Sans";

const W: f64 = 595.0;
const H: f64 = 842.0;
const M: f64 = 36.0;
const PNG_SCALE: f32 = 2.0;
/// Most points a chart is drawn with: up to this many pings are each drawn
/// on their own, more are gathered into slices of time.
const CHART_BUCKETS: usize = 480;

// Palette (light surface; reports are made for paper and screens alike).
const SURFACE: &str = "#ffffff";
const INK: &str = "#0a2036";
const MUTED: &str = "#3a4f66";
const BLUE: &str = "#004e89";
const CREAM: &str = "#f6f5e6";
const RULE: &str = "#b9c6d3";
const TINT: &str = "#eef3f8";
const PLOT: &str = "#f4f8fb";
const TRACK: &str = "#dbe4ee";
const NO_DATA: &str = "#e3e9ef";
const TEAL: &str = "#0d737e";
const TEAL_LIGHT: &str = "#7fc4cb";
const BAND: &str = "#bfe6ea";
const RANGE: &str = "#7d92a8";
const GREEN: &str = "#11924f";
const AMBER: &str = "#eeac1a";
const RED: &str = "#d92d2a";

// Type sizes and the page's fixed lines.
const BODY: f64 = 10.5;
const SMALL: f64 = 9.75;
/// Height of a line of text, as a multiple of its size.
const LEAD: f64 = 1.45;
/// The rule above the footer; nothing else is drawn below it.
const FOOT_TOP: f64 = H - 45.6;
/// Lowest point the body of a page may reach.
const LIMIT: f64 = FOOT_TOP - 9.0;

pub struct ReportRequest {
    pub target_ids: Vec<i64>,
    pub from_ms: i64,
    pub to_ms: i64,
    /// Minutes east of UTC for timestamps in the report.
    pub tz_offset_min: i32,
    pub format: ReportFormat,
}

/// What a report says about the monitor that measured it.
#[derive(Debug, Clone, Default)]
pub struct Monitor {
    /// This machine's name, for "measured from". Left out on share links.
    pub host: Option<String>,
    /// Whose DNS the monitor uses, in plain words with no addresses.
    pub dns: Option<String>,
    /// How many days of history pingrail keeps.
    pub retention_days: u32,
}

fn tz(req: &ReportRequest) -> FixedOffset {
    FixedOffset::east_opt(req.tz_offset_min * 60).unwrap_or(FixedOffset::east_opt(0).unwrap())
}

fn local(ms: i64, tz: FixedOffset) -> DateTime<FixedOffset> {
    Utc.timestamp_millis_opt(ms).single().unwrap_or_default().with_timezone(&tz)
}

fn tz_label(tz: FixedOffset) -> String {
    let s = tz.local_minus_utc();
    let sign = if s < 0 { '-' } else { '+' };
    let s = s.abs();
    if s % 3600 == 0 {
        format!("UTC{sign}{:02}:00", s / 3600)
    } else {
        format!("UTC{sign}{:02}:{:02}", s / 3600, (s % 3600) / 60)
    }
}

pub fn file_name(req: &ReportRequest) -> String {
    let tz = tz(req);
    let a = local(req.from_ms, tz);
    let b = local(req.to_ms, tz);
    format!(
        "pingrail-report-{}-{}.{}",
        a.format("%Y%m%d-%H%M"),
        if a.date_naive() == b.date_naive() { b.format("%H%M").to_string() } else { b.format("%Y%m%d-%H%M").to_string() },
        req.format.extension()
    )
}

/// One target as the report shows it: the period asked for, and everything
/// on record.
struct Item {
    d: Detail,
    rec: Recorded,
}

/// Build the report.
pub fn render(
    store: &Store,
    rdns: Option<&Arc<Rdns>>,
    th: Thresholds,
    req: &ReportRequest,
    scope: &Scope,
    monitor: &Monitor,
) -> Result<Vec<u8>> {
    let mut items = Vec::new();
    let budget = Instant::now() + Duration::from_secs(4);
    let now = now_ms();
    // Look names up before masking, then mask.
    let unmasked = Scope { privacy: Privacy::default(), ..scope.clone() };
    for &id in &req.target_ids {
        if !scope.allows(id) {
            continue;
        }
        let Some(t) = store.get_target(id)? else { continue };
        let mut d = analysis::detail_scoped(
            store,
            t,
            LiveStatus::default(),
            rdns,
            req.from_ms,
            req.to_ms,
            CHART_BUCKETS,
            None,
            th,
            &unmasked,
        )?;
        if let Some(r) = rdns {
            for h in &mut d.hops {
                if h.hostname.is_none() && Instant::now() < budget
                    && let Some(ip) = h.addr.as_deref().and_then(|a| a.parse().ok()) {
                        h.hostname = r.resolve_now(ip);
                    }
            }
        }
        analysis::apply_privacy(&mut d.hops, scope.privacy);
        let rec = analysis::recorded(store, id, scope, now, req.tz_offset_min as i64 * 60_000)?;
        items.push(Item { d, rec });
    }
    if items.is_empty() {
        return Err(anyhow!("none of the selected targets exist"));
    }
    let pages = build_pages(&items, req, scope, monitor, now);
    match req.format {
        ReportFormat::Pdf => to_pdf(&pages),
        ReportFormat::Png => to_png(&pages),
    }
}

// ----- text ---------------------------------------------------------------

/// The faces the report is set in.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Font {
    Regular,
    Semi,
    Bold,
    /// Headings: Source Serif 4 Bold.
    Head,
}

impl Font {
    /// The SVG attributes that select this face (regular is the default).
    fn attrs(self) -> &'static str {
        match self {
            Font::Regular => "",
            Font::Semi => r#" font-weight="600""#,
            Font::Bold => r#" font-weight="700""#,
            Font::Head => r#" font-family="'Source Serif 4'" font-weight="700""#,
        }
    }
}

fn faces() -> &'static [Option<ttf_parser::Face<'static>>; 4] {
    static FACES: OnceLock<[Option<ttf_parser::Face<'static>>; 4]> = OnceLock::new();
    FACES.get_or_init(|| [SANS, SANS_SEMI, SANS_BOLD, SERIF_BOLD].map(|data| ttf_parser::Face::parse(data, 0).ok()))
}

/// DejaVu Sans, when it is installed beside the program: it sets (and here
/// measures) characters the report's own faces lack.
fn fallback_face() -> Option<&'static ttf_parser::Face<'static>> {
    static FACE: OnceLock<Option<ttf_parser::Face<'static>>> = OnceLock::new();
    FACE.get_or_init(|| {
        let path = font_dirs().into_iter().map(|d| d.join(FALLBACK_FILES[0])).find(|p| p.is_file())?;
        // Read once and kept for as long as the program runs.
        let data: &'static [u8] = Box::leak(std::fs::read(path).ok()?.into_boxed_slice());
        ttf_parser::Face::parse(data, 0).ok()
    })
    .as_ref()
}

/// Width, in ems, allowed for a character no face here can measure.
const FULL_WIDTH: f64 = 1.05;

fn advance(face: &ttf_parser::Face, ch: char) -> Option<f64> {
    let g = face.glyph_index(ch)?;
    Some(face.glyph_hor_advance(g)? as f64 / face.units_per_em() as f64)
}

/// Width of `s` set in `font` at `size`, from the face's own metrics.
fn text_w(s: &str, size: f64, font: Font) -> f64 {
    let Some(face) = &faces()[font as usize] else {
        return s.chars().count() as f64 * size * 0.5;
    };
    s.chars()
        .map(|ch| {
            advance(face, ch).unwrap_or_else(|| {
                // Set in another font: DejaVu's width if it has the
                // character, or a little over an em, as wide as such
                // characters get.
                let wider = if font == Font::Regular { 1.0 } else { 1.1 };
                fallback_face().and_then(|f| advance(f, ch)).map_or(FULL_WIDTH, |a| (a * wider).min(FULL_WIDTH))
            })
        })
        .sum::<f64>()
        * size
}

/// `s`, cut short with an ellipsis when it is wider than `max_w`.
fn truncate(s: &str, max_w: f64, size: f64, font: Font) -> String {
    if text_w(s, size, font) <= max_w {
        return s.to_string();
    }
    let mut out = String::new();
    let room = max_w - text_w("…", size, font);
    let mut w = 0.0;
    for ch in s.chars() {
        w += text_w(ch.encode_utf8(&mut [0; 4]), size, font);
        if w > room {
            break;
        }
        out.push(ch);
    }
    let mut out = out.trim_end().to_string();
    out.push('…');
    out
}

/// Greedy word wrap to lines no wider than `max_w`. Lines break at plain
/// spaces only, so a figure stays with its unit.
fn wrap(s: &str, max_w: f64, size: f64, font: Font) -> Vec<String> {
    let mut lines = Vec::new();
    let mut cur = String::new();
    for word in s.split(' ').filter(|w| !w.is_empty()) {
        let cand = if cur.is_empty() { word.to_string() } else { format!("{cur} {word}") };
        if text_w(&cand, size, font) > max_w && !cur.is_empty() {
            lines.push(std::mem::take(&mut cur));
            cur = word.to_string();
        } else {
            cur = cand;
        }
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    lines
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// Whether the report's own typeface can set `ch`.
fn own_glyph(ch: char) -> bool {
    ch.is_ascii() || ch.is_whitespace() || faces()[Font::Regular as usize].as_ref().is_some_and(|f| f.glyph_index(ch).is_some())
}

/// `s` cut where it changes between characters the report's typeface has
/// and ones it lacks (a name in Japanese, say): `(text, has)` for each
/// stretch. Spaces count as the report's own, so the gaps between
/// stretches are ones it can measure.
fn script_runs(s: &str) -> Vec<(String, bool)> {
    let mut out: Vec<(String, bool)> = Vec::new();
    for ch in s.chars() {
        let own = own_glyph(ch);
        match out.last_mut() {
            Some((run, o)) if *o == own => run.push(ch),
            _ => out.push((ch.to_string(), own)),
        }
    }
    out
}

/// Text with characters the report's typeface lacks, as spans that each
/// start at a place worked out here. The renderer sets a whole stretch of
/// text in another font as soon as one character needs it; placed apart,
/// only the stretch that needs another font gets one.
fn placed_spans(x: f64, y: f64, anchor: Anchor, runs: &[Run]) -> String {
    let total: f64 = runs.iter().map(|(s, size, _, font)| text_w(s, *size, *font)).sum();
    let mut x = match anchor {
        Anchor::Start => x,
        Anchor::Middle => x - total / 2.0,
        Anchor::End => x - total,
    };
    let mut out = String::new();
    for (s, size, fill, font) in runs {
        for (run, own) in script_runs(s) {
            // A heading names its own family: the other font takes its place.
            let face = match (own, font) {
                (true, _) => font.attrs().to_string(),
                (false, Font::Head) => format!(r#" font-weight="700" font-family="'{FALLBACK_FAMILY}'""#),
                (false, _) => format!(r#"{} font-family="'{FALLBACK_FAMILY}'""#, font.attrs()),
            };
            let _ = write!(out, r#"<tspan x="{x:.2}" y="{y:.2}" font-size="{size}" fill="{fill}"{face}>{}</tspan>"#, esc(&run));
            x += text_w(&run, *size, *font);
        }
    }
    out
}

/// Baseline of a line of text whose box starts at `top`.
fn base(top: f64, size: f64) -> f64 {
    top + size * 1.04
}

/// Baseline that centres a line of text on `mid`.
fn centred(mid: f64, size: f64) -> f64 {
    mid + size * 0.33
}

// ----- SVG helpers --------------------------------------------------------

#[derive(Clone, Copy)]
enum Anchor {
    Start,
    Middle,
    End,
}

impl Anchor {
    fn attr(self) -> &'static str {
        match self {
            Anchor::Start => "start",
            Anchor::Middle => "middle",
            Anchor::End => "end",
        }
    }
}

/// A stretch of text in one size, colour and face.
type Run<'a> = (&'a str, f64, &'a str, Font);

struct Svg {
    b: String,
}

impl Svg {
    fn new() -> Svg {
        let mut b = String::with_capacity(64 * 1024);
        let _ = write!(
            b,
            r#"<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" font-family="'{BODY_FAMILY}'"><rect width="{W}" height="{H}" fill="{SURFACE}"/>"#
        );
        Svg { b }
    }

    #[allow(clippy::too_many_arguments)]
    fn text(&mut self, x: f64, y: f64, size: f64, fill: &str, anchor: Anchor, font: Font, s: &str) {
        if !s.chars().all(own_glyph) {
            let _ = write!(self.b, r#"<text xml:space="preserve">{}</text>"#, placed_spans(x, y, anchor, &[(s, size, fill, font)]));
            return;
        }
        let _ = write!(
            self.b,
            r#"<text x="{x:.2}" y="{y:.2}" font-size="{size}" fill="{fill}" text-anchor="{}"{}>{}</text>"#,
            anchor.attr(),
            font.attrs(),
            esc(s)
        );
    }

    /// Several runs on one line, set one after the other.
    fn runs(&mut self, x: f64, y: f64, anchor: Anchor, runs: &[Run]) {
        if !runs.iter().all(|r| r.0.chars().all(own_glyph)) {
            let _ = write!(self.b, r#"<text xml:space="preserve">{}</text>"#, placed_spans(x, y, anchor, runs));
            return;
        }
        let _ = write!(self.b, r#"<text x="{x:.2}" y="{y:.2}" text-anchor="{}" xml:space="preserve">"#, anchor.attr());
        for (s, size, fill, font) in runs {
            let _ = write!(self.b, r#"<tspan font-size="{size}" fill="{fill}"{}>{}</tspan>"#, font.attrs(), esc(s));
        }
        self.b.push_str("</text>");
    }

    /// A paragraph starting at `top`; returns where it ends.
    #[allow(clippy::too_many_arguments)]
    fn para(&mut self, x: f64, top: f64, size: f64, fill: &str, max_w: f64, font: Font, s: &str) -> f64 {
        let mut y = top;
        for line in wrap(s, max_w, size, font) {
            self.text(x, base(y, size), size, fill, Anchor::Start, font, &line);
            y += size * LEAD;
        }
        y
    }

    fn rect(&mut self, x: f64, y: f64, w: f64, h: f64, fill: &str, rx: f64) {
        if w <= 0.0 || h <= 0.0 {
            return;
        }
        let _ = write!(self.b, r#"<rect x="{x:.2}" y="{y:.2}" width="{w:.2}" height="{h:.2}" rx="{rx}" fill="{fill}"/>"#);
    }

    /// A rectangle with an outline; the outline's middle runs along the edge given.
    #[allow(clippy::too_many_arguments)]
    fn frame(&mut self, x: f64, y: f64, w: f64, h: f64, fill: &str, stroke: &str, sw: f64, rx: f64) {
        let _ = write!(
            self.b,
            r#"<rect x="{x:.2}" y="{y:.2}" width="{w:.2}" height="{h:.2}" rx="{rx}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"/>"#
        );
    }

    fn line(&mut self, x1: f64, y1: f64, x2: f64, y2: f64, stroke: &str, w: f64) {
        let _ = write!(
            self.b,
            r#"<line x1="{x1:.2}" y1="{y1:.2}" x2="{x2:.2}" y2="{y2:.2}" stroke="{stroke}" stroke-width="{w}"/>"#
        );
    }

    fn circle(&mut self, cx: f64, cy: f64, r: f64, fill: &str) {
        let _ = write!(self.b, r#"<circle cx="{cx:.2}" cy="{cy:.2}" r="{r}" fill="{fill}"/>"#);
    }

    fn ring(&mut self, cx: f64, cy: f64, r: f64, stroke: &str, w: f64) {
        let _ = write!(self.b, r#"<circle cx="{cx:.2}" cy="{cy:.2}" r="{r}" fill="none" stroke="{stroke}" stroke-width="{w}"/>"#);
    }

    fn polyline(&mut self, pts: &[(f64, f64)], stroke: &str, w: f64) {
        if pts.len() < 2 {
            if let Some(&(x, y)) = pts.first() {
                self.circle(x, y, w.max(1.0), stroke);
            }
            return;
        }
        let mut d = String::new();
        for (i, (x, y)) in pts.iter().enumerate() {
            let _ = write!(d, "{}{x:.2},{y:.2}", if i == 0 { "M" } else { " L" });
        }
        let _ = write!(
            self.b,
            r#"<path d="{d}" fill="none" stroke="{stroke}" stroke-width="{w}" stroke-linejoin="round" stroke-linecap="round"/>"#
        );
    }

    fn area(&mut self, upper: &[(f64, f64)], lower: &[(f64, f64)], fill: &str) {
        if upper.is_empty() {
            return;
        }
        let mut d = String::new();
        for (i, (x, y)) in upper.iter().enumerate() {
            let _ = write!(d, "{}{x:.2},{y:.2}", if i == 0 { "M" } else { " L" });
        }
        for (x, y) in lower.iter().rev() {
            let _ = write!(d, " L{x:.2},{y:.2}");
        }
        d.push_str(" Z");
        let _ = write!(self.b, r#"<path d="{d}" fill="{fill}"/>"#);
    }

    fn finish(mut self) -> String {
        self.b.push_str("</svg>");
        self.b
    }
}

// ----- words and numbers --------------------------------------------------

fn fmt_count(n: u64) -> String {
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

/// "0 %", "0.67 %", "12.5 %", "100 %". The space before the sign is one a
/// line never breaks at.
fn pct(v: f64) -> String {
    if v <= 0.0 {
        "0\u{a0}%".into()
    } else if v >= 99.995 {
        "100\u{a0}%".into()
    } else if v < 0.005 {
        "under 0.01\u{a0}%".into()
    } else if v < 10.0 {
        format!("{v:.2}\u{a0}%")
    } else {
        format!("{v:.1}\u{a0}%")
    }
}

fn share(lost: u64, sent: u64) -> f64 {
    if sent == 0 { 0.0 } else { 100.0 * lost as f64 / sent as f64 }
}

/// "14.2 ms", or a dash when there is nothing to show.
fn ms(v: Option<f64>) -> String {
    match v {
        Some(_) => format!("{}\u{a0}ms", fmt_ms(v)),
        None => "—".into(),
    }
}

fn plural(n: u64, one: &str, many: &str) -> String {
    format!("{} {}", fmt_count(n), if n == 1 { one } else { many })
}

fn fmt_interval(ms: u32) -> String {
    if ms.is_multiple_of(1000) {
        format!("{} s", ms / 1000)
    } else {
        format!("{:.1} s", ms as f64 / 1000.0)
    }
}

/// A length of time in words: "5 minutes", "2 h 30 min", "12 days 3 h".
fn fmt_dur(ms: i64) -> String {
    let mut s = (ms.max(0) + 500) / 1000;
    if s >= 120 {
        s = (s + 30) / 60 * 60;
    }
    let (d, h, m) = (s / 86_400, s % 86_400 / 3600, s % 3600 / 60);
    if s < 60 {
        plural(s as u64, "second", "seconds")
    } else if d == 0 && h == 0 {
        plural(m as u64, "minute", "minutes")
    } else if d == 0 && m == 0 {
        plural(h as u64, "hour", "hours")
    } else if d == 0 {
        format!("{h} h {m} min")
    } else if h == 0 {
        plural(d as u64, "day", "days")
    } else {
        format!("{} {h} h", plural(d as u64, "day", "days"))
    }
}

// ----- time axis ----------------------------------------------------------

const STEPS: &[i64] = &[
    1_000, 2_000, 5_000, 10_000, 15_000, 30_000, 60_000, 120_000, 300_000, 600_000, 900_000, 1_800_000,
    3_600_000, 7_200_000, 10_800_000, 21_600_000, 43_200_000, 86_400_000, 172_800_000, 604_800_000,
];

/// Tick positions (ms) and labels for a time range, aligned to the local zone.
fn time_ticks(from: i64, to: i64, tz: FixedOffset, max_ticks: i64) -> Vec<(i64, String)> {
    let span = (to - from).max(1);
    let step = *STEPS.iter().find(|s| span / **s <= max_ticks).unwrap_or(&604_800_000);
    let off = tz.local_minus_utc() as i64 * 1000;
    let first = ((from + off + step - 1).div_euclid(step)) * step - off;
    let mut out = Vec::new();
    let mut t = first;
    while t <= to {
        let d = local(t, tz);
        let label = if step >= 86_400_000 {
            d.format("%d %b").to_string()
        } else if span > 86_400_000 {
            if d.format("%H:%M").to_string() == "00:00" { d.format("%d %b").to_string() } else { d.format("%H:%M").to_string() }
        } else if step < 60_000 {
            d.format("%H:%M:%S").to_string()
        } else {
            d.format("%H:%M").to_string()
        };
        out.push((t, label));
        t += step;
    }
    out
}

/// "11 November 2026, 07:34 to 07:39", for the top of the report.
fn period_title(from: i64, to: i64, tz: FixedOffset) -> String {
    let a = local(from, tz);
    let b = local(to, tz);
    if a.date_naive() == b.date_naive() {
        format!("{}, {} to {}", a.format("%-d %B %Y"), a.format("%H:%M"), b.format("%H:%M"))
    } else {
        format!("{} to {}", a.format("%-d %b %Y, %H:%M"), b.format("%-d %b %Y, %H:%M"))
    }
}

/// The same, shorter and with the time zone, for the top of later pages.
fn range_label(from: i64, to: i64, tz: FixedOffset) -> String {
    let a = local(from, tz);
    let b = local(to, tz);
    if a.date_naive() == b.date_naive() {
        format!("{}, {} to {} ({})", a.format("%-d %b %Y"), a.format("%H:%M"), b.format("%H:%M"), tz_label(tz))
    } else {
        format!("{} to {} ({})", a.format("%-d %b %Y, %H:%M"), b.format("%-d %b %Y, %H:%M"), tz_label(tz))
    }
}

/// "11 Nov, 02:03", with the year when it is not this year.
fn stamp(ms: i64, c: &Ctx) -> String {
    let d = local(ms, c.tz);
    if d.year() == local(c.now, c.tz).year() {
        d.format("%-d %b, %H:%M").to_string()
    } else {
        d.format("%-d %b %Y, %H:%M").to_string()
    }
}

// ----- marks --------------------------------------------------------------

/// What a mark says. Marks are about lost pings and nothing else: a target
/// that answers slowly but always is not marked down, and one that drops a
/// single ping never gets the green one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mark {
    /// Every ping was answered.
    Clean,
    /// At least one ping went unanswered.
    Loss,
    /// No ping was answered.
    Down,
    /// No pings were sent.
    Empty,
}

fn mark_of(sent: u64, lost: u64) -> Mark {
    if sent == 0 {
        Mark::Empty
    } else if lost == 0 {
        Mark::Clean
    } else if lost >= sent {
        Mark::Down
    } else {
        Mark::Loss
    }
}

fn lost_in(s: &Stats) -> u64 {
    s.sent.saturating_sub(s.received) as u64
}

fn period_mark(s: &Stats) -> Mark {
    mark_of(s.sent as u64, lost_in(s))
}

/// A mark `size` across, centred on (cx, cy). Each has its own shape, so it
/// reads without colour too.
fn mark(svg: &mut Svg, cx: f64, cy: f64, size: f64, m: Mark) {
    let r = size / 2.0;
    match m {
        Mark::Clean => svg.circle(cx, cy, r, GREEN),
        Mark::Loss => svg.frame(cx - r, cy - r, size, size, AMBER, INK, 0.75, 0.0),
        Mark::Down => {
            let _ = write!(
                svg.b,
                r#"<path d="M{:.2} {cy:.2} L{cx:.2} {:.2} L{:.2} {cy:.2} L{cx:.2} {:.2} Z" fill="{RED}"/>"#,
                cx - r * 1.3,
                cy - r * 1.3,
                cx + r * 1.3,
                cy + r * 1.3
            );
        }
        Mark::Empty => svg.ring(cx, cy, r - 0.5, MUTED, 1.0),
    }
}

/// The large mark in the summary box, 22.5 pt across with its top left at (x, y).
fn big_mark(svg: &mut Svg, x: f64, y: f64, m: Mark) {
    let (cx, cy) = (x + 11.25, y + 11.25);
    let bang = |svg: &mut Svg, color: &str| {
        let _ = write!(
            svg.b,
            r#"<path d="M{cx:.2} {:.2}V{:.2}M{cx:.2} {:.2}v0.4" fill="none" stroke="{color}" stroke-width="2.25" stroke-linecap="round"/>"#,
            cy - 4.5,
            cy + 1.5,
            cy + 4.5
        );
    };
    match m {
        Mark::Clean => {
            svg.circle(cx, cy, 10.0, GREEN);
            let _ = write!(
                svg.b,
                r#"<path d="M{:.2} {:.2} L{:.2} {:.2} L{:.2} {:.2}" fill="none" stroke="{SURFACE}" stroke-width="2.25" stroke-linecap="round" stroke-linejoin="round"/>"#,
                cx - 4.6,
                cy + 0.4,
                cx - 1.4,
                cy + 3.6,
                cx + 4.8,
                cy - 3.4
            );
        }
        Mark::Loss => {
            svg.frame(x + 2.25, y + 2.25, 18.0, 18.0, AMBER, INK, 1.5, 0.0);
            bang(svg, INK);
        }
        Mark::Down => {
            let _ = write!(
                svg.b,
                r#"<path d="M{:.2} {cy:.2} L{cx:.2} {:.2} L{:.2} {cy:.2} L{cx:.2} {:.2} Z" fill="{RED}"/>"#,
                cx - 11.25,
                cy - 11.25,
                cx + 11.25,
                cy + 11.25
            );
            bang(svg, SURFACE);
        }
        Mark::Empty => svg.ring(cx, cy, 9.0, MUTED, 1.5),
    }
}

// ----- pages --------------------------------------------------------------

struct Ctx<'a> {
    req: &'a ReportRequest,
    tz: FixedOffset,
    scope: &'a Scope,
    monitor: &'a Monitor,
    now: i64,
    generated: String,
}

/// The lettering of the pingrail lockup, as the brand file draws it.
fn wordmark() -> &'static str {
    static D: OnceLock<String> = OnceLock::new();
    D.get_or_init(|| {
        let svg = include_str!("../assets/brand/pingrail-lockup.svg");
        let d = svg.rfind("<path d=\"").map(|i| &svg[i + 9..]).and_then(|rest| rest.find('"').map(|j| &rest[..j]));
        // Path data only: nothing else from the file reaches the page.
        d.filter(|d| d.chars().all(|ch| ch.is_ascii_alphanumeric() || " .,-".contains(ch))).unwrap_or_default().to_string()
    })
}

/// The pingrail lockup (mark and name) `h` points tall, the rail's left
/// edge at `x`, centred on `cy`.
fn lockup(svg: &mut Svg, x: f64, cy: f64, h: f64, color: &str) {
    // The brand file is 48 units tall; its rail starts 13.875 units in.
    let s = h / 48.0;
    let tx = x - 13.875 * s;
    let ty = cy - 26.0 * s;
    let _ = write!(
        svg.b,
        r#"<g transform="translate({tx:.2} {ty:.2}) scale({s:.4})"><g transform="scale(0.75)"><path d="M22 31V56" fill="none" stroke="{color}" stroke-width="7" stroke-linecap="round"/><circle cx="34" cy="31" r="12" fill="none" stroke="{color}" stroke-width="6.5"/><circle cx="34" cy="31" r="4.2" fill="{color}"/></g><path d="{}" fill="{color}"/></g>"#,
        wordmark()
    );
}

/// The blue band that opens the report. Returns where it ends.
fn band(svg: &mut Svg, c: &Ctx, targets: usize) -> f64 {
    let title = period_title(c.req.from_ms, c.req.to_ms, c.tz);
    // The title is set as large as the page allows.
    let mut size = 25.5;
    while size > 15.0 && text_w(&title, size, Font::Head) > W - 2.0 * M {
        size -= 0.5;
    }
    let h = 48.0 + size * 1.1 + 4.5 + 11.25 * LEAD + 18.0;
    svg.rect(0.0, 0.0, W, h, BLUE, 0.0);
    lockup(svg, M, 28.5, 22.0, CREAM);
    let _ = write!(
        svg.b,
        r#"<text x="{:.2}" y="31.60" font-size="9" fill="{CREAM}" text-anchor="end" font-weight="600" letter-spacing="0.9">LATENCY AND ROUTE REPORT</text>"#,
        W - M
    );
    let top = 48.0;
    svg.text(M, top + size * 0.9, size, CREAM, Anchor::Start, Font::Head, &title);
    let mut sub = format!(
        "{}, {}",
        fmt_dur(c.req.to_ms - c.req.from_ms),
        if targets == 1 { "one target".to_string() } else { format!("{targets} targets") }
    );
    if let Some(host) = &c.monitor.host {
        sub.push_str(&format!(", measured from {host}"));
    }
    sub.push_str(&format!(". Times are {}.", tz_label(c.tz)));
    let y = top + size * 1.1 + 4.5;
    svg.text(M, base(y, 11.25), 11.25, CREAM, Anchor::Start, Font::Regular, &truncate(&sub, W - 2.0 * M, 11.25, Font::Regular));
    h
}

/// The line that tops every page after the first. Returns where the body starts.
fn running_head(svg: &mut Svg, c: &Ctx) -> f64 {
    lockup(svg, M, 29.5, 15.0, BLUE);
    svg.text(W - M, 33.0, SMALL, MUTED, Anchor::End, Font::Regular, &range_label(c.req.from_ms, c.req.to_ms, c.tz));
    svg.rect(M, 43.5, W - 2.0 * M, 2.25, BLUE, 0.0);
    59.25
}

fn page_footer(svg: &mut Svg, c: &Ctx, page: usize, total: usize) {
    svg.line(M, FOOT_TOP, W - M, FOOT_TOP, RULE, 0.75);
    let y = base(FOOT_TOP + 9.0, SMALL);
    svg.text(
        M,
        y,
        SMALL,
        MUTED,
        Anchor::Start,
        Font::Regular,
        &format!("Made by pingrail {} on {}", env!("CARGO_PKG_VERSION"), c.generated),
    );
    svg.text(W - M, y, SMALL, MUTED, Anchor::End, Font::Regular, &format!("Page {page} of {total}"));
}

fn build_pages(items: &[Item], req: &ReportRequest, scope: &Scope, monitor: &Monitor, now: i64) -> Vec<String> {
    let tz = tz(req);
    let c = Ctx { req, tz, scope, monitor, now, generated: local(now, tz).format("%-d %b %Y, %H:%M").to_string() };
    let mut pages = summary_pages(&c, items);
    for it in items {
        target_pages(&c, it, &mut pages);
    }
    let total = pages.len();
    pages
        .into_iter()
        .enumerate()
        .map(|(i, mut svg)| {
            page_footer(&mut svg, &c, i + 1, total);
            svg.finish()
        })
        .collect()
}

/// A section's heading and the line under it. Returns where the section's
/// content starts.
fn section_head(svg: &mut Svg, x: f64, top: f64, title: &str, sub: &str, max_w: f64) -> f64 {
    svg.text(x, top + 16.9, 15.75, BLUE, Anchor::Start, Font::Head, title);
    svg.text(x, base(top + 22.8, BODY), BODY, MUTED, Anchor::Start, Font::Regular, &truncate(sub, max_w, BODY, Font::Regular));
    top + 22.8 + BODY * LEAD
}

/// A smaller heading with a note beside it, as on a target's page.
fn minor_head(svg: &mut Svg, x: f64, top: f64, title: &str, note: &str) {
    svg.runs(x, top + 13.7, Anchor::Start, &[(title, 12.75, BLUE, Font::Head), ("  ", SMALL, MUTED, Font::Regular), (note, SMALL, MUTED, Font::Regular)]);
}

// ----- summary ------------------------------------------------------------

/// The headline of the report: its mark, a few words, and a sentence or two.
/// The green mark is only given when nothing was lost at all, in the period
/// or on record.
fn verdict(items: &[Item]) -> (Mark, String, String) {
    let n = items.len();
    let lost_now = |it: &Item| lost_in(&it.d.stats);
    let down = items.iter().filter(|it| period_mark(&it.d.stats) == Mark::Down).count();
    let any_now = items.iter().any(|it| lost_now(it) > 0);
    let any_rec = items.iter().any(|it| it.rec.lost > 0);
    let sent_now: u64 = items.iter().map(|it| it.d.stats.sent as u64).sum();
    let sent_rec: u64 = items.iter().map(|it| it.rec.sent).sum();

    let (m, head) = if down > 0 {
        let head = match (n, down) {
            (1, _) => "Not answering".to_string(),
            (_, 1) => "One target is not answering".to_string(),
            _ => format!("{down} targets are not answering"),
        };
        (Mark::Down, head)
    } else if any_now {
        (Mark::Loss, "Packet loss detected".to_string())
    } else if any_rec {
        (Mark::Loss, "Packet loss on record".to_string())
    } else if sent_now == 0 {
        (Mark::Empty, "No pings in this period".to_string())
    } else {
        (Mark::Clean, "No packet loss".to_string())
    };

    if m == Mark::Clean {
        let text = format!(
            "Every ping was answered: {} in this period and {} on record.",
            fmt_count(sent_now),
            fmt_count(sent_rec)
        );
        return (m, head, text);
    }
    if m == Mark::Empty {
        let text = if sent_rec == 0 {
            "Nothing is on record yet either.".to_string()
        } else {
            format!("On record, every one of {} was answered.", plural(sent_rec, "ping", "pings"))
        };
        return (m, head, text);
    }

    // The targets that lost anything, worst first; a few get a sentence each.
    let mut lossy: Vec<&Item> = items.iter().filter(|it| lost_now(it) > 0 || it.rec.lost > 0).collect();
    lossy.sort_by(|a, b| {
        let key = |it: &Item| (share(lost_now(it), it.d.stats.sent as u64), it.rec.loss_pct());
        key(b).partial_cmp(&key(a)).unwrap_or(std::cmp::Ordering::Equal)
    });
    const NAMED: usize = 3;
    let mut text = String::new();
    for it in lossy.iter().take(NAMED) {
        let s = &it.d.stats;
        let (sent, lost) = (s.sent as u64, lost_now(it));
        let name = &it.d.target.name;
        let now = if sent == 0 {
            format!("{name} has no pings in this period")
        } else if lost == 0 {
            format!("{name} lost none in this period")
        } else if lost >= sent {
            format!("{name} answered none of {} in this period", plural(sent, "ping", "pings"))
        } else {
            format!("{name} lost {} of {} in this period ({})", fmt_count(lost), plural(sent, "ping", "pings"), pct(share(lost, sent)))
        };
        let rec = if it.rec.sent == 0 {
            String::new()
        } else if it.rec.lost == 0 {
            " and none on record".to_string()
        } else {
            format!(" and {} of {} on record ({})", fmt_count(it.rec.lost), fmt_count(it.rec.sent), pct(it.rec.loss_pct()))
        };
        text.push_str(&format!("{now}{rec}. "));
    }
    let more = lossy.len().saturating_sub(NAMED);
    let clean = n - lossy.len();
    if more > 0 {
        text.push_str(&format!("{} lost pings too (see the tables below). ", plural(more as u64, "more target", "more targets")));
    }
    match clean {
        0 => {}
        1 if more == 0 => {
            let it = items.iter().find(|it| lost_now(it) == 0 && it.rec.lost == 0).expect("counted above");
            text.push_str(&format!("{} lost none, in this period or on record.", it.d.target.name));
        }
        _ => text.push_str(&format!("The other {} lost none, in this period or on record.", plural(clean as u64, "target", "targets"))),
    }
    (m, head, text.trim_end().to_string())
}

/// The box that holds the verdict. Returns where it ends.
fn verdict_box(svg: &mut Svg, items: &[Item], top: f64) -> f64 {
    let (m, head, text) = verdict(items);
    let tx = M + 13.5 + 22.5 + 10.5;
    let max_w = W - M - 13.5 - tx;
    let lines = wrap(&text, max_w, 11.25, Font::Regular);
    let h = 12.0 + 20.7 + 3.0 + lines.len() as f64 * 11.25 * LEAD + 12.0;
    svg.frame(M + 0.75, top + 0.75, W - 2.0 * M - 1.5, h - 1.5, "none", BLUE, 1.5, 7.5);
    big_mark(svg, M + 13.5, top + 12.0, m);
    svg.text(tx, top + 12.0 + 15.3, 14.25, INK, Anchor::Start, Font::Head, &head);
    let mut y = top + 12.0 + 20.7 + 3.0;
    for line in lines {
        svg.text(tx, base(y, 11.25), 11.25, INK, Anchor::Start, Font::Regular, &line);
        y += 11.25 * LEAD;
    }
    top + h
}

/// Columns set flush right, each as wide as its widest cell. Returns each
/// column's right edge, the last ending at `right`, and where the first starts.
fn right_cols(heads: &[&str], cells: &[Vec<(String, f64, Font)>], right: f64, gap: f64) -> (Vec<f64>, f64) {
    let mut edges = vec![0.0; heads.len()];
    let mut x = right;
    for k in (0..heads.len()).rev() {
        let w = cells
            .iter()
            .map(|row| text_w(&row[k].0, row[k].1, row[k].2))
            .fold(text_w(heads[k], SMALL, Font::Semi), f64::max);
        edges[k] = x;
        x -= w + gap;
    }
    (edges, x)
}

/// The heading row of a table. Returns where the rows start.
fn table_head(svg: &mut Svg, x0: f64, x1: f64, top: f64, heads: &[(&str, f64, Anchor)]) -> f64 {
    for (h, x, a) in heads {
        svg.text(*x, base(top + 4.5, SMALL), SMALL, MUTED, *a, Font::Semi, h);
    }
    let y = top + 4.5 + SMALL * LEAD + 4.5;
    svg.rect(x0, y, x1 - x0, 1.5, BLUE, 0.0);
    y + 1.5
}

fn summary_pages(c: &Ctx, items: &[Item]) -> Vec<Svg> {
    let mut pages = Vec::new();
    let mut svg = Svg::new();
    let mut y = band(&mut svg, c, items.len()) + 19.5;
    y = verdict_box(&mut svg, items, y) + 18.0;
    // A few targets get roomy rows; more than that, one line each.
    let roomy = items.len() <= 3;
    let dur = fmt_dur(c.req.to_ms - c.req.from_ms);

    // --- This report
    let cells: Vec<Vec<(String, f64, Font)>> = items
        .iter()
        .map(|it| {
            let s = &it.d.stats;
            let (sent, lost) = (s.sent as u64, lost_in(s));
            vec![
                (ms(s.avg_ms), BODY, Font::Regular),
                (ms(s.max_ms), BODY, Font::Regular),
                (ms(s.jitter_ms), BODY, Font::Regular),
                (if sent > 0 { format!("{} of {}", fmt_count(lost), fmt_count(sent)) } else { "—".into() }, BODY, Font::Regular),
                (if sent > 0 { pct(share(lost, sent)) } else { "—".into() }, BODY, Font::Bold),
                (s.mos.map(|m| format!("{m:.2}")).unwrap_or("—".into()), BODY, Font::Regular),
            ]
        })
        .collect();
    let heads = ["Average", "Slowest", "Jitter", "Pings lost", "Loss", "MOS"];
    let spark_w = 90.0;
    let spark_x = W - M - spark_w;
    let (edges, first) = right_cols(&heads, &cells, spark_x - 12.0, 12.0);
    let name_x = M + 13.5;
    let name_w = (first - name_x).max(40.0);
    let row_h = if roomy { 45.4 } else { 24.0 };
    let mut i = 0;
    while i < items.len() {
        let fits = ((LIMIT - y - (22.8 + BODY * LEAD + 7.5 + 24.6)) / row_h).floor().max(0.0) as usize;
        if fits < (items.len() - i).min(4) {
            pages.push(std::mem::replace(&mut svg, Svg::new()));
            y = running_head(&mut svg, c);
        }
        let title = if i == 0 { "This report" } else { "This report, continued" };
        y = section_head(&mut svg, M, y, title, &format!("{dur} of pings, shown on the graphs that follow."), W - 2.0 * M) + 7.5;
        let mut hs: Vec<(&str, f64, Anchor)> = vec![("Target", M, Anchor::Start)];
        hs.extend(heads.iter().zip(&edges).map(|(h, x)| (*h, *x, Anchor::End)));
        hs.push(("Latency", spark_x, Anchor::Start));
        y = table_head(&mut svg, M, W - M, y, &hs);
        while i < items.len() && y + row_h <= LIMIT {
            let it = &items[i];
            let mid = y + row_h / 2.0;
            let t = &it.d.target;
            if roomy {
                mark(&mut svg, M + 3.75, y + 7.5 + 8.2, 7.5, period_mark(&it.d.stats));
                svg.text(name_x, base(y + 7.5, 11.25), 11.25, INK, Anchor::Start, Font::Bold, &truncate(&t.name, name_w, 11.25, Font::Bold));
                if t.host != t.name {
                    svg.text(name_x, base(y + 7.5 + 16.3, SMALL), SMALL, MUTED, Anchor::Start, Font::Regular, &truncate(&t.host, name_w, SMALL, Font::Regular));
                }
            } else {
                mark(&mut svg, M + 3.75, mid, 7.5, period_mark(&it.d.stats));
                let name = truncate(&t.name, name_w, BODY, Font::Bold);
                let left = name_w - text_w(&name, BODY, Font::Bold) - 6.0;
                let host = if t.host != t.name && left > 30.0 { truncate(&t.host, left, SMALL, Font::Regular) } else { String::new() };
                svg.runs(name_x, centred(mid, BODY), Anchor::Start, &[(&name, BODY, INK, Font::Bold), ("  ", SMALL, MUTED, Font::Regular), (&host, SMALL, MUTED, Font::Regular)]);
            }
            for (k, (v, size, font)) in cells[i].iter().enumerate() {
                svg.text(edges[k], centred(mid, *size), *size, INK, Anchor::End, *font, v);
            }
            let sh = if roomy { 19.5 } else { 14.0 };
            sparkline(&mut svg, &it.d, spark_x, mid - sh / 2.0, spark_w, sh);
            y += row_h;
            svg.line(M, y, W - M, y, RULE, 0.75);
            i += 1;
        }
    }
    y += 18.0;

    // --- All recorded pings, on a tinted panel
    let (px0, px1) = (M + 15.0, W - M - 15.0);
    let cells: Vec<Vec<(String, f64, Font)>> = items
        .iter()
        .map(|it| {
            let r = &it.rec;
            if r.sent == 0 {
                return vec![("—".into(), BODY, Font::Regular), ("—".into(), 12.75, Font::Bold), ("—".into(), BODY, Font::Regular)];
            }
            vec![
                (format!("{} of {}", fmt_count(r.lost), fmt_count(r.sent)), BODY, Font::Regular),
                (pct(r.loss_pct()), 12.75, Font::Bold),
                (ms(r.avg_ms), BODY, Font::Regular),
            ]
        })
        .collect();
    let since: Vec<(String, String)> = items
        .iter()
        .map(|it| match (it.rec.first_ms, it.rec.last_ms) {
            (Some(a), Some(b)) => (stamp(a, c), fmt_dur(b - a)),
            _ => ("Nothing on record".to_string(), String::new()),
        })
        .collect();
    let heads = ["Pings lost", "Loss", "Average"];
    let bars_w = if roomy { 142.5 } else { 112.5 };
    let bars_x = px1 - bars_w;
    let (edges, first) = right_cols(&heads, &cells, bars_x - 12.0, 12.0);
    let since_w = since
        .iter()
        .map(|(a, b)| text_w(a, BODY, Font::Regular).max(text_w(b, SMALL, Font::Regular)))
        .fold(text_w("On record since", SMALL, Font::Semi), f64::max);
    let since_x = first - since_w;
    let name_w = (since_x - 12.0 - px0).max(40.0);
    // Both bars share one scale: 10 % unless something lost more.
    let worst = items
        .iter()
        .flat_map(|it| [share(lost_in(&it.d.stats), it.d.stats.sent as u64), it.rec.loss_pct()])
        .fold(0.0, f64::max);
    let scale = if worst > 10.0 { nice_ceil(worst).min(100.0) } else { 10.0 };
    let history = match c.scope.earliest_ms {
        Some(e) => format!("This link shows history from {} on; earlier pings are not counted.", stamp(e, c)),
        None => format!("History older than the {} pingrail keeps is not counted.", plural(c.monitor.retention_days.max(1) as u64, "day", "days")),
    };
    let note = format!("Bars run from 0 to {scale:.0} % loss. {history}");
    let note_lines = wrap(&note, px1 - px0, SMALL, Font::Regular).len() as f64;
    let row_h = if roomy { 47.0 } else { 32.0 };
    let fixed = 13.5 + 22.8 + BODY * LEAD + 9.0 + 24.6 + 7.5 + note_lines * SMALL * LEAD + 12.0;
    let mut i = 0;
    while i < items.len() {
        // Start on a new page sooner than leave a row or two behind.
        let left = items.len() - i;
        let fits = ((LIMIT - y - fixed) / row_h).floor().max(0.0) as usize;
        if fits < left.min(4) {
            pages.push(std::mem::replace(&mut svg, Svg::new()));
            y = running_head(&mut svg, c);
        }
        let n = (((LIMIT - y - fixed) / row_h).floor() as usize).clamp(1, left);
        svg.rect(M, y, W - 2.0 * M, fixed + n as f64 * row_h, TINT, 7.5);
        let title = if i == 0 { "All recorded pings" } else { "All recorded pings, continued" };
        y = section_head(
            &mut svg,
            px0,
            y + 13.5,
            title,
            if items.len() == 1 { "Everything pingrail has on record for this target, not only the period above." } else { "Everything pingrail has on record for each target, not only the period above." },
            px1 - px0,
        ) + 9.0;
        let mut hs: Vec<(&str, f64, Anchor)> = vec![("Target", px0, Anchor::Start), ("On record since", since_x, Anchor::Start)];
        hs.extend(heads.iter().zip(&edges).map(|(h, x)| (*h, *x, Anchor::End)));
        hs.push(("Loss, this report against all", bars_x, Anchor::Start));
        y = table_head(&mut svg, px0, px1, y, &hs);
        for (k, it) in items[i..i + n].iter().enumerate() {
            let idx = i + k;
            let mid = y + row_h / 2.0;
            svg.text(px0, centred(mid, 11.25), 11.25, INK, Anchor::Start, Font::Bold, &truncate(&it.d.target.name, name_w, 11.25, Font::Bold));
            let (a, b) = &since[idx];
            // The date, and under it how long ago that is.
            let lead = if roomy { 14.6 } else { 12.6 };
            svg.text(since_x, base(mid - lead, BODY), BODY, INK, Anchor::Start, Font::Regular, a);
            svg.text(since_x, base(mid + lead - 14.0, SMALL), SMALL, MUTED, Anchor::Start, Font::Regular, b);
            for (j, (v, size, font)) in cells[idx].iter().enumerate() {
                svg.text(edges[j], centred(mid, *size), *size, INK, Anchor::End, *font, v);
            }
            let s = &it.d.stats;
            let rows = [("now", share(lost_in(s), s.sent as u64), s.sent > 0, BLUE), ("all", it.rec.loss_pct(), it.rec.sent > 0, RED)];
            for (j, (label, v, has, color)) in rows.into_iter().enumerate() {
                let cy = mid - 6.5 + j as f64 * 13.0;
                svg.text(bars_x, centred(cy, SMALL), SMALL, INK, Anchor::Start, Font::Regular, label);
                let (bx, bw) = (bars_x + 30.0, bars_w - 30.0);
                svg.rect(bx, cy - 3.0, bw, 6.0, TRACK, 0.0);
                if has && v > 0.0 {
                    svg.rect(bx, cy - 3.0, ((v / scale).min(1.0) * bw).max(1.5), 6.0, color, 0.0);
                }
            }
            y += row_h;
            if k + 1 < n {
                svg.line(px0, y, px1, y, RULE, 0.75);
            }
        }
        i += n;
        y = svg.para(px0, y + 7.5, SMALL, MUTED, px1 - px0, Font::Regular, &note) + 12.0;
        y += 18.0;
    }

    // --- How to read this
    let col_w = (W - 2.0 * M - 27.0) / 3.0;
    let keys = [
        (Mark::Clean, "No loss", "Every ping in the period was answered."),
        (Mark::Loss, "Packet loss", "At least one ping went unanswered."),
        (Mark::Down, "Not answering", "No ping in the period was answered."),
    ];
    let closing = "The marks are about lost pings only, and the summary shows a tick only when nothing was lost, in this period or on record. Jitter is how much one reply time differs from the next. MOS estimates call quality from 1 (bad) to 4.5, the highest score possible. Anything from 4.3 up is excellent: calls sound clear.";
    let key_lines = keys.iter().map(|(_, _, t)| wrap(t, col_w, SMALL, Font::Regular).len()).max().unwrap_or(1) as f64;
    let closing_lines = wrap(closing, W - 2.0 * M, SMALL, Font::Regular).len() as f64;
    let key_h = 18.5 + 6.0 + (1.0 + key_lines + closing_lines) * SMALL * LEAD + 7.5;
    if y + key_h > LIMIT {
        pages.push(std::mem::replace(&mut svg, Svg::new()));
        y = running_head(&mut svg, c);
    }
    svg.text(M, y + 13.7, 12.75, BLUE, Anchor::Start, Font::Head, "How to read this");
    y += 18.5 + 6.0;
    for (k, (m, label, text)) in keys.into_iter().enumerate() {
        let x = M + k as f64 * (col_w + 13.5);
        mark(&mut svg, x + 3.75, y + 7.4, 7.5, m);
        svg.text(x + 12.0, base(y, SMALL), SMALL, INK, Anchor::Start, Font::Bold, label);
        svg.para(x, y + SMALL * LEAD, SMALL, INK, col_w, Font::Regular, text);
    }
    y += (1.0 + key_lines) * SMALL * LEAD + 7.5;
    svg.para(M, y, SMALL, MUTED, W - 2.0 * M, Font::Regular, closing);
    pages.push(svg);
    pages
}

/// A target's latency over the period, small enough for a table row, with a
/// red tick under it wherever pings were lost.
fn sparkline(svg: &mut Svg, d: &Detail, x: f64, y: f64, w: f64, h: f64) {
    let tl = &d.timeline;
    if tl.points.is_empty() {
        return;
    }
    let mut avgs: Vec<f64> = tl.points.iter().filter_map(|p| p.avg_ms).collect();
    let ymax = nice_ceil(percentile(&mut avgs, 98.0).unwrap_or(1.0) * 1.1);
    let span = (tl.to_ms - tl.from_ms).max(1) as f64;
    let xf = |t: i64| x + (t - tl.from_ms) as f64 / span * w;
    // Lost pings: a tick as tall as the share lost, against the worst point.
    let lost_share = |p: &Point| if p.sent == 0 { 0.0 } else { p.lost as f64 / p.sent as f64 };
    let worst = tl.points.iter().map(lost_share).fold(0.0, f64::max);
    let mut run: Vec<(f64, f64)> = Vec::new();
    for p in &tl.points {
        let px = xf(p.t_ms);
        if p.lost > 0 {
            let th = (lost_share(p) / worst * 4.5).max(1.2);
            svg.rect(px - 0.6, y + h - th, 1.2, th, RED, 0.0);
        }
        if p.gap {
            svg.polyline(&run, TEAL, 1.2);
            run.clear();
        }
        if let Some(v) = p.avg_ms {
            run.push((px, y + h - 6.0 - (v / ymax).min(1.0) * (h - 7.0)));
        }
    }
    svg.polyline(&run, TEAL, 1.2);
}

// ----- one target ---------------------------------------------------------

/// The target's name and the lines under it. Returns where they end.
fn target_header(svg: &mut Svg, c: &Ctx, d: &Detail, top: f64, continued: bool) -> f64 {
    let name = if continued { format!("{}, route continued", d.target.name) } else { d.target.name.clone() };
    // A long name is set smaller before it is cut short.
    let mut size = 22.5;
    while size > 15.0 && text_w(&name, size, Font::Head) > W - 2.0 * M {
        size -= 0.5;
    }
    svg.text(M, top + 20.25, size, INK, Anchor::Start, Font::Head, &truncate(&name, W - 2.0 * M, size, Font::Head));
    let mut y = top + 24.75 + 3.75;
    if continued {
        return y;
    }
    let mut parts = vec![d.target.host.clone()];
    if let Some(dest) = d.hops.iter().find(|h| h.is_dest) {
        if dest.masked.is_none()
            && let Some(a) = &dest.addr
            && *a != d.target.host {
                parts[0] = format!("{} ({a})", d.target.host);
            }
        parts.push(format!("{} away", plural(dest.ttl as u64, "hop", "hops")));
    }
    parts.push(if d.target.interval_ms == 1000 {
        "one ping a second".to_string()
    } else {
        format!("one ping every {}", fmt_interval(d.target.interval_ms))
    });
    let line = format!("{}.", parts.join(", "));
    svg.text(M, base(y, BODY), BODY, MUTED, Anchor::Start, Font::Regular, &truncate(&line, W - 2.0 * M, BODY, Font::Regular));
    y += BODY * LEAD;
    if let Some(dns) = c.monitor.dns.as_deref().filter(|s| !s.is_empty()) {
        let line = format!("This monitor’s DNS: {}.", dns.trim_end_matches('.'));
        svg.text(M, base(y + 1.5, BODY), BODY, MUTED, Anchor::Start, Font::Regular, &truncate(&line, W - 2.0 * M, BODY, Font::Regular));
        y += 1.5 + BODY * LEAD;
    }
    y
}

/// Height of the two blocks under a target's name.
const BLOCKS_H: f64 = 163.0;

/// "This report" beside "All recorded pings". Returns where they end.
fn stat_blocks(svg: &mut Svg, c: &Ctx, it: &Item, top: f64) -> f64 {
    let gap = 13.5;
    let w = (W - 2.0 * M - gap) / 2.0;
    let (pad_x, pad_y) = (12.0, 10.5);
    let s = &it.d.stats;
    let (sent, lost) = (s.sent as u64, lost_in(s));

    // --- This report
    let x = M;
    svg.frame(x + 0.375, top + 0.375, w - 0.75, BLOCKS_H - 0.75, "none", RULE, 0.75, 7.5);
    svg.text(x + pad_x, top + pad_y + 13.7, 12.75, BLUE, Anchor::Start, Font::Head, "This report");
    let sub = format!("{}, {}", fmt_dur(c.req.to_ms - c.req.from_ms), plural(sent, "ping", "pings"));
    svg.text(x + pad_x, base(top + pad_y + 18.5, SMALL), SMALL, MUTED, Anchor::Start, Font::Regular, &sub);
    let col_gap = 9.0;
    let col_w = (w - 2.0 * pad_x - 2.0 * col_gap) / 3.0;
    let grid = top + pad_y + 18.5 + SMALL * LEAD + 12.0;
    let figure = |v: Option<f64>| v.map(|_| fmt_ms(v));
    let cells: [(&str, Option<String>, &str); 6] = [
        ("Average", figure(s.avg_ms), " ms"),
        ("Slowest", figure(s.max_ms), " ms"),
        ("95th percentile", figure(s.p95_ms), " ms"),
        ("Jitter", figure(s.jitter_ms), " ms"),
        ("Pings lost", (sent > 0).then(|| fmt_count(lost)), ""),
        ("Call quality", s.mos.map(|m| format!("{m:.2}")), " MOS"),
    ];
    for (k, (label, value, unit)) in cells.into_iter().enumerate() {
        let cx = x + pad_x + (k % 3) as f64 * (col_w + col_gap);
        let cy = grid + (k / 3) as f64 * (SMALL * LEAD + 21.75 + 17.0);
        svg.text(cx, base(cy, SMALL), SMALL, MUTED, Anchor::Start, Font::Regular, label);
        let by = cy + SMALL * LEAD + 15.6;
        let Some(value) = value else {
            svg.text(cx, by, 15.0, MUTED, Anchor::Start, Font::Bold, "—");
            continue;
        };
        if label == "Pings lost" {
            // "2 of 300" on one line when it fits, the total underneath when not.
            let of = format!(" of {}", fmt_count(sent));
            let share = pct(share(lost, sent));
            let under = by + SMALL * LEAD;
            if text_w(&value, 15.0, Font::Bold) + text_w(&of, SMALL, Font::Regular) <= col_w {
                svg.runs(cx, by, Anchor::Start, &[(&value, 15.0, INK, Font::Bold), (&of, SMALL, INK, Font::Regular)]);
                svg.text(cx, under, SMALL, INK, Anchor::Start, Font::Regular, &share);
            } else {
                svg.text(cx, by, 15.0, INK, Anchor::Start, Font::Bold, &value);
                svg.text(cx, under, SMALL, INK, Anchor::Start, Font::Regular, &format!("{}, {share}", of.trim_start()));
            }
        } else {
            svg.runs(cx, by, Anchor::Start, &[(&value, 15.0, INK, Font::Bold), (unit, SMALL, INK, Font::Regular)]);
        }
    }

    // --- All recorded pings
    let x = M + w + gap;
    let r = &it.rec;
    let inner = w - 2.0 * pad_x;
    svg.rect(x, top, w, BLOCKS_H, TINT, 7.5);
    svg.text(x + pad_x, top + pad_y + 13.7, 12.75, BLUE, Anchor::Start, Font::Head, "All recorded pings");
    let (Some(first), Some(last)) = (r.first_ms, r.last_ms) else {
        svg.text(x + pad_x, base(top + pad_y + 18.5, SMALL), SMALL, MUTED, Anchor::Start, Font::Regular, "Nothing on record yet.");
        return top + BLOCKS_H;
    };
    let since = format!("Since {} ({})", stamp(first, c), fmt_dur(last - first));
    svg.text(x + pad_x, base(top + pad_y + 18.5, SMALL), SMALL, MUTED, Anchor::Start, Font::Regular, &since);
    let mut y = top + pad_y + 18.5 + SMALL * LEAD + 6.0;
    let big = fmt_count(r.lost);
    let of = format!(" of {} lost", fmt_count(r.sent));
    svg.runs(x + pad_x, y + 16.5, Anchor::Start, &[(&big, 19.5, INK, Font::Bold), (&of, 11.25, INK, Font::Regular)]);
    y += 22.4 + 1.5;
    mark(svg, x + pad_x + 3.75, y + 9.0, 7.5, mark_of(r.sent, r.lost));
    let latency = if r.avg_ms.is_some() {
        format!("average {}, slowest {}", ms(r.avg_ms), ms(r.max_ms))
    } else {
        "no replies on record".to_string()
    };
    let share = pct(r.loss_pct());
    let room = inner - 13.5 - text_w(&share, 12.75, Font::Bold) - 6.0;
    svg.runs(
        x + pad_x + 13.5,
        y + 13.5,
        Anchor::Start,
        &[(&share, 12.75, INK, Font::Bold), ("  ", SMALL, INK, Font::Regular), (&truncate(&latency, room, SMALL, Font::Regular), SMALL, INK, Font::Regular)],
    );
    y += 18.5 + 6.0;
    let (caption, outlined) = loss_bars(svg, c, r, x + pad_x, y, inner, 37.5);
    let cy = base(y + 37.5 + 1.5, SMALL);
    let mut room = inner;
    if outlined {
        let label = "this report";
        let lw = text_w(label, SMALL, Font::Regular);
        svg.text(x + pad_x + inner, cy, SMALL, MUTED, Anchor::End, Font::Regular, label);
        svg.frame(x + pad_x + inner - lw - 11.25, cy - 6.75, 6.75, 6.75, "none", BLUE, 1.5, 0.0);
        room -= lw + 21.0;
    }
    svg.text(x + pad_x, cy, SMALL, MUTED, Anchor::Start, Font::Regular, &truncate(&caption, room, SMALL, Font::Regular));
    top + BLOCKS_H
}

fn step_words(step: i64) -> String {
    match step {
        1 => "minute".into(),
        60 => "hour".into(),
        1440 => "day".into(),
        m if m < 60 => format!("{m} minutes"),
        m => format!("{} hours", m / 60),
    }
}

/// Everything on record as bars of loss over time, in a box `w` by `h` with
/// its top left at (x, y). The part the report covers is outlined, unless
/// that is all of it. Returns the caption that goes under it, and whether
/// anything was outlined.
fn loss_bars(svg: &mut Svg, c: &Ctx, r: &Recorded, x: f64, y: f64, w: f64, h: f64) -> (String, bool) {
    let (Some(first), step) = (r.bars.first().map(|b| b.0), r.step_min.max(1)) else {
        return (String::new(), false);
    };
    let n = r.bars.len();
    let bars: Vec<(u64, u64)> = r.bars.iter().map(|b| (b.1, b.2)).collect();
    let label_h = 9.0;
    let plot_h = h - label_h;
    let floor = y + plot_h;
    let pitch = w / n as f64;
    let bar_w = (pitch * 0.82).max(0.5);
    let tallest = bars.iter().map(|(s, l)| share(*l, *s)).fold(0.0, f64::max);
    let scale = nice_ceil(tallest.max(0.1));
    for (k, (sent, lost)) in bars.iter().enumerate() {
        if *lost > 0 {
            let bh = (share(*lost, *sent) / scale * (plot_h - 3.0)).max(1.5);
            svg.rect(x + k as f64 * pitch + (pitch - bar_w) / 2.0, floor - bh, bar_w, bh, RED, 0.0);
        }
    }
    svg.line(x, floor, x + w, floor, INK, 0.75);

    // Labels: as many as fit without touching.
    let off = c.tz.local_minus_utc() as i64 * 1000;
    let label = |k: usize| {
        // The bar's start, back on the clock.
        let d = local((first + k as i64) * step * 60_000 - off, c.tz);
        if step >= 1440 {
            d.format("%-d %b").to_string()
        } else if step >= 60 {
            if n as i64 * step > 1440 && d.format("%H").to_string() == "00" { d.format("%-d %b").to_string() } else { d.format("%H").to_string() }
        } else {
            d.format("%H:%M").to_string()
        }
    };
    let widest = (0..n).map(|k| text_w(&label(k), 7.5, Font::Regular)).fold(0.0, f64::max);
    let every = ((widest + 8.0) / pitch).ceil().max(1.0) as usize;
    for k in (0..n).step_by(every) {
        let cx = x + (k as f64 + 0.5) * pitch;
        let text = label(k);
        let half = text_w(&text, 7.5, Font::Regular) / 2.0;
        svg.text(cx.clamp(x + half, x + w - half), floor + 7.9, 7.5, INK, Anchor::Middle, Font::Regular, &text);
    }

    // The bars that hold the report's own period.
    let from = (c.req.from_ms + off).div_euclid(60_000).div_euclid(step) - first;
    let to = (c.req.to_ms - 1 + off).div_euclid(60_000).div_euclid(step) - first;
    let (lo, hi) = (from.max(0), to.min(n as i64 - 1));
    let outlined = lo <= hi && !(lo == 0 && hi == n as i64 - 1);
    if outlined {
        let ox = x + lo as f64 * pitch;
        let ow = (hi - lo + 1) as f64 * pitch;
        svg.frame(ox.max(x + 0.75), y + 0.75, ow.min(w - 1.5).max(3.0), plot_h - 0.75, "none", BLUE, 1.5, 0.0);
    }
    let caption = if r.lost == 0 {
        "No pings lost on record".to_string()
    } else {
        format!("Loss by {}, tallest bar {}", step_words(step), pct(tallest))
    };
    (caption, outlined)
}

/// What each point of a timeline stands for, for the caption under a chart.
fn timeline_caption(tl: &Timeline) -> String {
    match tl.mode {
        TimelineMode::Samples => format!(
            "Each point is one ping (every {}). The bold line is the average over {}.",
            interval_range(tl),
            fmt_dur(ma_window(tl))
        ),
        TimelineMode::Slices => {
            let per = |iv: i64| (tl.step_ms as f64 / iv.max(1) as f64).round().max(1.0) as i64;
            let (lo, hi) = (tl.interval_min_ms, tl.interval_max_ms);
            let n = if lo > 0 && hi > lo && per(hi) != per(lo) {
                format!("{} to {}", per(hi), per(lo))
            } else {
                format!("about {}", per(tl.interval_ms))
            };
            format!("Each point covers {} ({n} pings).", fmt_dur(tl.step_ms))
        }
    }
}

/// Everything in the latency chart that is not the plot itself: heading,
/// the strip of lost pings, the time labels and the caption.
const CHART_FIXED: f64 = 21.5 + 10.5 + 18.0 + 13.0 + 14.0;

/// The latency chart: the plot, and under it a strip that marks lost pings.
/// A red line runs through the plot too wherever no ping was answered.
/// Returns where the chart ends.
fn latency_chart(svg: &mut Svg, c: &Ctx, d: &Detail, top: f64, height: f64) -> f64 {
    let tl = &d.timeline;
    let pts = &tl.points;
    let x0 = M + 33.0;
    let x1 = W - M;
    let pw = x1 - x0;
    let (from, to) = (tl.from_ms, tl.to_ms);
    let span = (to - from).max(1) as f64;
    let xf = |t: i64| x0 + (t - from) as f64 / span * pw;
    let samples = tl.mode == TimelineMode::Samples;
    // Width of one point on the time axis.
    let pt_w = (tl.step_ms as f64 / span * pw).max(0.6);

    // Heading and key
    minor_head(svg, M, top, "Latency", "round trip, in ms");
    let ky = top + 13.7;
    let mut kx = W - M;
    let mut key = |svg: &mut Svg, label: &str, swatch: &dyn Fn(&mut Svg, f64, f64) -> f64| {
        svg.text(kx, ky, SMALL, INK, Anchor::End, Font::Regular, label);
        kx -= text_w(label, SMALL, Font::Regular) + 4.0;
        kx -= swatch(svg, kx, ky - 3.2) + 10.5;
    };
    let any_gap = tl.gaps.iter().any(|[a, b]| (*b).min(to) > (*a).max(from));
    if any_gap {
        key(svg, "not measured", &|svg, x, y| {
            svg.rect(x - 10.5, y - 3.0, 10.5, 6.0, NO_DATA, 0.0);
            10.5
        });
    }
    key(svg, if samples { "lost ping" } else { "pings lost" }, &|svg, x, y| {
        svg.rect(x - 1.5, y - 4.5, 1.5, 9.0, RED, 0.0);
        1.5
    });
    if samples {
        key(svg, "each ping", &|svg, x, y| {
            svg.line(x - 12.0, y, x, y, TEAL_LIGHT, 0.9);
            12.0
        });
    } else {
        key(svg, "fastest to slowest", &|svg, x, y| {
            svg.frame(x - 10.5, y - 3.0, 10.5, 6.0, BAND, TEAL, 0.75, 0.0);
            10.5
        });
    }
    key(svg, "average", &|svg, x, y| {
        svg.rect(x - 12.0, y - 1.1, 12.0, 2.2, TEAL, 0.0);
        12.0
    });

    let py0 = top + 21.5;
    let py1 = py0 + height;
    // The strip of lost pings under the plot.
    let sy0 = py1 + 10.5;
    let sy1 = sy0 + 18.0;
    // Scale: robust to a single spike.
    let mut maxes: Vec<f64> = pts.iter().filter_map(|x| x.max_ms).collect();
    let avg_max = pts.iter().filter_map(|x| x.avg_ms).fold(0.0, f64::max);
    let robust = percentile(&mut maxes, 98.0).unwrap_or(0.0);
    let ymax = axis_max((avg_max * 1.15).max(robust).max(1.0), 4);
    let yf = |v: f64| py1 - (v / ymax).min(1.0) * height;

    svg.rect(x0, py0, pw, height, PLOT, 0.0);
    svg.frame(x0, sy0, pw, sy1 - sy0, PLOT, RULE, 0.75, 0.0);
    // Stretches without samples
    for [a, b] in &tl.gaps {
        let (gx0, gx1) = (xf((*a).max(from)), xf((*b).min(to)));
        if gx1 > gx0 {
            svg.rect(gx0, py0, gx1 - gx0, height, NO_DATA, 0.0);
            svg.rect(gx0, sy0, gx1 - gx0, sy1 - sy0, NO_DATA, 0.0);
        }
    }
    // Grid and its labels
    for k in 0..=4 {
        let v = ymax * k as f64 / 4.0;
        let y = yf(v);
        svg.line(x0, y, x1, y, if k == 0 { INK } else { RULE }, 0.75);
        svg.text(x0 - 4.5, y + 2.9, 8.25, INK, Anchor::End, Font::Regular, &fmt_axis(v));
    }
    svg.text(x0 - 4.5, (sy0 + sy1) / 2.0 + 2.9, 8.25, INK, Anchor::End, Font::Regular, "lost");

    // Points are joined across lost samples; only real gaps break the line.
    // Each point sits in the middle of the time it covers.
    let mid = |p: &Point| xf(p.t_ms) + if samples { 0.0 } else { pt_w / 2.0 };
    let ma = if samples { moving_average(pts, ma_window(tl)) } else { pts.iter().map(|p| p.avg_ms).collect() };
    let mut upper = Vec::new();
    let mut lower = Vec::new();
    let mut detail = Vec::new();
    let mut line = Vec::new();
    for (i, p) in pts.iter().enumerate() {
        if p.gap {
            svg.area(&upper, &lower, BAND);
            svg.polyline(&detail, TEAL_LIGHT, 0.8);
            svg.polyline(&line, TEAL, 1.8);
            upper.clear();
            lower.clear();
            detail.clear();
            line.clear();
        }
        let x = mid(p);
        if let (Some(lo), Some(hi)) = (p.min_ms, p.max_ms) {
            if samples {
                detail.push((x, yf(hi)));
            } else {
                upper.push((x, yf(hi)));
                lower.push((x, yf(lo)));
            }
        }
        if let Some(a) = ma[i] {
            line.push((x, yf(a)));
        }
    }
    svg.area(&upper, &lower, BAND);
    svg.polyline(&detail, TEAL_LIGHT, 0.8);
    svg.polyline(&line, TEAL, 1.8);

    // Lost pings. One ping a point: a red line through the plot and the
    // strip. Many pings a point: a bar in the strip as tall as the share
    // lost, and the line through the plot only where none was answered.
    let tallest = pts.iter().filter(|p| p.sent > 0).map(|p| 100.0 * p.lost as f64 / p.sent as f64).fold(0.0, f64::max);
    let strip_max = if tallest > 0.0 { nice_ceil(tallest).min(100.0) } else { 100.0 };
    for p in pts.iter().filter(|p| p.sent > 0 && p.lost > 0) {
        if samples {
            svg.rect((xf(p.t_ms) - 0.75).clamp(x0, x1 - 1.5), py0, 1.5, sy1 - py0, RED, 0.0);
            continue;
        }
        let w = (pt_w - 0.3).max(1.5);
        let x = (xf(p.t_ms) + (pt_w - w) / 2.0).clamp(x0, x1 - w);
        if p.lost == p.sent {
            svg.rect(x, py0, w, sy1 - py0, RED, 0.0);
        } else {
            let bh = (100.0 * p.lost as f64 / p.sent as f64 / strip_max * (sy1 - sy0 - 1.5)).max(1.5);
            svg.rect(x, sy1 - bh, w, bh, RED, 0.0);
        }
    }
    if pts.iter().all(|x| x.avg_ms.is_none()) {
        let msg = if pts.is_empty() { "No pings in this period" } else { "No replies in this period" };
        let tw = text_w(msg, BODY, Font::Semi) + 12.0;
        svg.rect((x0 + x1 - tw) / 2.0, (py0 + py1) / 2.0 - 9.0, tw, 18.0, SURFACE, 3.0);
        svg.text((x0 + x1) / 2.0, (py0 + py1) / 2.0 + 3.5, BODY, INK, Anchor::Middle, Font::Semi, msg);
    }

    // Changes (such as a new address): a dotted line through the plot and
    // strip, and a numbered mark between them.
    let marks = event_marks(d, &xf);
    for (k, (x, _)) in marks.iter().enumerate() {
        let _ = write!(
            svg.b,
            r#"<line x1="{x:.2}" y1="{py0:.2}" x2="{x:.2}" y2="{sy1:.2}" stroke="{BLUE}" stroke-width="0.9" stroke-dasharray="2 2"/>"#
        );
        mark_glyph(svg, *x, py1 + 1.5);
        if d.events.len() > 1 {
            svg.text(*x + 5.0, py1 + 8.6, 7.5, BLUE, Anchor::Start, Font::Bold, &(k + 1).to_string());
        }
    }

    // Time labels
    let ticks = time_ticks(from, to, c.tz, 7);
    let mut last_x = f64::NEG_INFINITY;
    for (t, label) in &ticks {
        let x = xf(*t);
        let w = text_w(label, 8.25, Font::Regular);
        if x - w / 2.0 > last_x + 6.0 && x + w / 2.0 <= x1 + 10.0 && x - w / 2.0 >= x0 - 14.0 {
            svg.line(x, sy1, x, sy1 + 2.5, INK, 0.75);
            svg.text(x, sy1 + 11.0, 8.25, INK, Anchor::Middle, Font::Regular, label);
            last_x = x + w / 2.0;
        }
    }
    // What a point means
    let mut caption = timeline_caption(tl);
    if !samples && tallest > 0.0 {
        caption.push_str(&format!(" Red bars: the share of pings lost in each, tallest {}.", pct(tallest)));
    }
    let cy = sy1 + 13.0;
    svg.text(x0, base(cy, 9.0), 9.0, MUTED, Anchor::Start, Font::Regular, &truncate(&caption, pw, 9.0, Font::Regular));
    events_list(svg, c, d, &marks, x0, cy + 14.0)
}

/// Changes listed under a chart, at most this many.
const EVENTS_LISTED: usize = 3;
const EVENT_LINE_H: f64 = 12.5;

/// How much room the list of changes under the chart takes.
fn events_height(d: &Detail) -> f64 {
    let n = d.events.len();
    if n == 0 {
        return 0.0;
    }
    let lines = n.min(EVENTS_LISTED) + usize::from(n > EVENTS_LISTED);
    2.0 + lines as f64 * EVENT_LINE_H
}

/// The target's events grouped into marks: events within a few points of
/// each other share one, numbered from 1. Each is (x, numbers of its events).
fn event_marks(d: &Detail, xf: &dyn Fn(i64) -> f64) -> Vec<(f64, Vec<usize>)> {
    let mut marks: Vec<(f64, Vec<usize>)> = Vec::new();
    for (i, e) in d.events.iter().enumerate() {
        let x = xf(e.ts_ms);
        match marks.last_mut() {
            Some((lx, ids)) if x - *lx < 7.0 => ids.push(i),
            _ => marks.push((x, vec![i])),
        }
    }
    marks
}

/// A small triangle pointing up with its tip at (x, y).
fn mark_glyph(svg: &mut Svg, x: f64, y: f64) {
    let _ = write!(svg.b, r#"<path d="M{x:.2} {y:.2} L{:.2} {:.2} L{:.2} {:.2} Z" fill="{BLUE}"/>"#, x - 3.4, y + 6.0, x + 3.4, y + 6.0);
}

/// One line per change (the latest few) under the chart, each with the
/// number of its mark. Returns where the list ends.
fn events_list(svg: &mut Svg, c: &Ctx, d: &Detail, marks: &[(f64, Vec<usize>)], x0: f64, top: f64) -> f64 {
    let n = d.events.len();
    if n == 0 {
        return top;
    }
    let span = d.timeline.to_ms - d.timeline.from_ms;
    let fmt = if span <= 2 * 86_400_000 { "%H:%M:%S" } else { "%-d %b %H:%M" };
    let mut y = top + 2.0;
    if n > EVENTS_LISTED {
        let more = (n - EVENTS_LISTED) as u64;
        let line = format!("{} in this period {} marked above.", plural(more, "earlier change", "earlier changes"), if more == 1 { "is" } else { "are" });
        svg.text(x0, base(y, 9.0), 9.0, MUTED, Anchor::Start, Font::Regular, &line);
        y += EVENT_LINE_H;
    }
    for (i, e) in d.events.iter().enumerate().skip(n.saturating_sub(EVENTS_LISTED)) {
        let by = base(y, 9.0);
        mark_glyph(svg, x0 + 3.4, by - 6.2);
        let mut tx = x0 + 10.5;
        // Numbered like the marks on the chart when there's more than one.
        if n > 1 {
            let no = marks.iter().position(|(_, ids)| ids.contains(&i)).map_or(0, |m| m + 1).to_string();
            svg.text(tx, by, 9.0, BLUE, Anchor::Start, Font::Bold, &no);
            tx += text_w(&no, 9.0, Font::Bold) + 5.0;
        }
        let when = local(e.ts_ms, c.tz).format(fmt).to_string();
        let mut what = match e.kind.as_str() {
            "address" => format!(
                "Address changed from {} to {}",
                e.from.as_deref().unwrap_or("an unknown address"),
                e.to.as_deref().unwrap_or("an unknown address")
            ),
            k => k.to_string(),
        };
        if let (Some(b), Some(a)) = (e.before_ms, e.after_ms) {
            what.push_str(&format!(", average {} before and {} after", ms(Some(b)), ms(Some(a))));
        }
        svg.text(tx, by, 9.0, INK, Anchor::Start, Font::Semi, &when);
        tx += text_w(&when, 9.0, Font::Semi) + 6.0;
        svg.text(tx, by, 9.0, INK, Anchor::Start, Font::Regular, &truncate(&what, W - M - tx, 9.0, Font::Regular));
        y += EVENT_LINE_H;
    }
    y
}

fn fmt_axis(v: f64) -> String {
    if v == 0.0 {
        "0".into()
    } else if v < 1.0 {
        format!("{v:.2}")
    } else if v < 10.0 && v.fract() != 0.0 {
        format!("{v:.1}")
    } else {
        format!("{v:.0}")
    }
}

/// Lowest a row of the route table goes; rows take more when there is room.
const HOP_ROW: f64 = 15.5;
/// The route's heading and the table's own heading row.
const ROUTE_HEAD: f64 = 21.5 + 24.6;

/// The notes under the route table: what the figures are, and what the
/// marks beside a hop's loss mean when any hop has one.
fn route_notes(all: &[HopStat]) -> String {
    let mut notes = String::from("Each hop is probed on its own; only pings to the target itself are counted as lost on these pages.");
    if all.iter().any(|h| h.reading == Some(HopReading::LimitsReplies)) {
        notes.push_str(" A hop that limits replies answers fewer probes itself while later hops answer in full, so nothing is lost there.");
    }
    notes
}

fn route_notes_height(all: &[HopStat]) -> f64 {
    6.0 + wrap(&route_notes(all), W - 2.0 * M, 9.0, Font::Regular).len() as f64 * 9.0 * LEAD
}

/// The route table. `rows` are the hops on this page, `all` the whole route
/// (the bars share one scale). Returns where it ends.
fn hop_table(svg: &mut Svg, rows: &[&HopStat], all: &[HopStat], top: f64, title: bool, row_h: f64) -> f64 {
    let mut y = top;
    if title {
        minor_head(svg, M, y, "Route", "each hop on the way, in ms");
        y += 21.5;
    }
    let mut maxes: Vec<f64> = all.iter().filter_map(|h| h.stats.max_ms).collect();
    let gmax = nice_ceil(percentile(&mut maxes, 90.0).unwrap_or(1.0).max(1.0));
    let bar_head = format!("Fastest to slowest, 0 to {} ms", fmt_axis(gmax));
    // Columns
    let g1 = W - M;
    let g0 = g1 - text_w(&bar_head, SMALL, Font::Semi).max(120.0);
    let c_max = g0 - 12.0;
    let c_avg = c_max - 42.0;
    let c_loss = c_avg - 42.0;
    let c_hop = M + 18.0;
    let c_addr = M + 27.0;
    let c_name = M + 124.0;
    let name_w = c_loss - 46.0 - c_name;
    y = table_head(
        svg,
        M,
        W - M,
        y,
        &[
            ("Hop", c_hop, Anchor::End),
            ("Address", c_addr, Anchor::Start),
            ("Name", c_name, Anchor::Start),
            ("Loss", c_loss, Anchor::End),
            ("Average", c_avg, Anchor::End),
            ("Slowest", c_max, Anchor::End),
            (&bar_head, g0, Anchor::Start),
        ],
    );
    if rows.is_empty() {
        svg.text(M, base(y + 6.0, SMALL), SMALL, MUTED, Anchor::Start, Font::Regular, "No route on record for this period.");
        return y + 6.0 + SMALL * LEAD;
    }
    let gx = |v: f64| g0 + 3.75 + (v / gmax).min(1.0) * (g1 - g0 - 7.5);
    for h in rows {
        let mid = y + row_h / 2.0;
        let by = centred(mid, SMALL);
        let s = &h.stats;
        let font = if h.is_dest { Font::Bold } else { Font::Regular };
        let silent = h.addr.is_none() && h.masked.is_none();
        let ink = if silent { MUTED } else { INK };
        svg.text(c_hop, by, SMALL, ink, Anchor::End, font, &h.ttl.to_string());
        if silent {
            // Nothing answered at this hop. That is only loss when the hops
            // after it are silent too.
            let text = if h.reading == Some(HopReading::NoReply) {
                "No reply (later hops answer, so nothing is lost here)"
            } else {
                "No reply"
            };
            svg.text(c_addr, by, SMALL, MUTED, Anchor::Start, font, &truncate(text, c_loss - 26.0 - c_addr, SMALL, font));
            for x in [c_loss, c_avg, c_max] {
                svg.text(x, by, SMALL, MUTED, Anchor::End, font, "n/a");
            }
            let _ = write!(
                svg.b,
                r#"<rect x="{:.2}" y="{:.2}" width="{:.2}" height="6.75" fill="none" stroke="{RANGE}" stroke-width="0.75" stroke-dasharray="2.5 2"/>"#,
                g0 + 0.375,
                mid - 3.375,
                g1 - g0 - 0.75
            );
        } else {
            let addr = h.masked.clone().or_else(|| h.addr.clone()).unwrap_or_default();
            let addr = if h.responders > 1 { format!("{addr} +{}", h.responders - 1) } else { addr };
            svg.text(c_addr, by, SMALL, INK, Anchor::Start, font, &truncate(&addr, c_name - c_addr - 6.0, SMALL, font));
            // What the hop's loss means once later hops are taken into
            // account: only loss that carries on to the target is marked.
            let note = match h.reading {
                Some(HopReading::LossStarts) if h.is_dest => "loss only here",
                Some(HopReading::LossStarts) => "loss starts here",
                Some(HopReading::LimitsReplies) => "limits replies",
                _ => "",
            };
            let host = h.hostname.as_deref().unwrap_or_default();
            if note.is_empty() {
                svg.text(c_name, by, SMALL, INK, Anchor::Start, font, &truncate(host, name_w, SMALL, font));
            } else {
                let left = name_w - text_w(note, SMALL, Font::Semi) - 8.0;
                let host = if !host.is_empty() && left > 30.0 { truncate(host, left, SMALL, Font::Regular) } else { String::new() };
                svg.runs(c_name, by, Anchor::Start, &[(note, SMALL, INK, Font::Semi), ("  ", SMALL, INK, Font::Regular), (&host, SMALL, MUTED, Font::Regular)]);
            }
            let limited = h.reading == Some(HopReading::LimitsReplies);
            let loss = if s.sent > 0 { pct(s.loss_pct) } else { "—".into() };
            let lw = text_w(&loss, SMALL, font);
            if limited && s.loss_pct > 0.0 {
                svg.ring(c_loss - lw - 6.5, mid, 2.6, MUTED, 0.9);
            } else if matches!(h.reading, Some(HopReading::LossStarts | HopReading::LossCarried)) && s.loss_pct > 0.0 {
                mark(svg, c_loss - lw - 6.5, mid, 6.0, Mark::Loss);
            }
            svg.text(c_loss, by, SMALL, if limited { MUTED } else { INK }, Anchor::End, font, &loss);
            svg.text(c_avg, by, SMALL, INK, Anchor::End, font, &fmt_ms(s.avg_ms));
            svg.text(c_max, by, SMALL, INK, Anchor::End, font, &fmt_ms(s.max_ms));
            svg.rect(g0, mid - 3.75, g1 - g0, 7.5, TINT, 0.0);
            if let (Some(lo), Some(hi), Some(avg)) = (s.min_ms, s.max_ms, s.avg_ms) {
                svg.rect(gx(lo), mid - 1.5, (gx(hi) - gx(lo)).max(1.0), 3.0, RANGE, 0.0);
                svg.circle(gx(avg), mid, 3.75, BLUE);
            }
        }
        y += row_h;
        if h.is_dest {
            svg.rect(M, y - 0.75, W - 2.0 * M, 1.5, BLUE, 0.0);
        } else {
            svg.line(M, y, W - M, y, RULE, 0.75);
        }
    }
    svg.para(M, y + 6.0, 9.0, MUTED, W - 2.0 * M, Font::Regular, &route_notes(all))
}

/// A target's page, and more pages for the rest of a route too long for one.
fn target_pages(c: &Ctx, it: &Item, pages: &mut Vec<Svg>) {
    let d = &it.d;
    let mut svg = Svg::new();
    let mut y = running_head(&mut svg, c);
    y = target_header(&mut svg, c, d, y, false) + 13.5;
    y = stat_blocks(&mut svg, c, it, y) + 13.5;
    let chart_fixed = CHART_FIXED + events_height(d);
    if !d.target.trace {
        let plot = (LIMIT - y - chart_fixed - 13.5 - SMALL * LEAD).min(210.0);
        let end = latency_chart(&mut svg, c, d, y, plot);
        svg.text(M, base(end + 13.5, SMALL), SMALL, MUTED, Anchor::Start, Font::Regular, "Route tracing is off for this target.");
        pages.push(svg);
        return;
    }
    let route_fixed = ROUTE_HEAD + route_notes_height(&d.hops);
    let n = d.hops.len().max(1) as f64;
    // The plot gives up some height to keep a long route on one page.
    let room = |plot: f64| LIMIT - (y + chart_fixed + plot + 13.5 + route_fixed);
    let plot = [144.0, 124.0, 104.0].into_iter().find(|p| room(*p) >= n * HOP_ROW).unwrap_or(124.0);
    let top = latency_chart(&mut svg, c, d, y, plot) + 13.5;
    let room = LIMIT - top - route_fixed;
    let fit = (room / HOP_ROW).floor().max(1.0) as usize;
    let row_h = if d.hops.len() <= fit { (room / n).clamp(HOP_ROW, 21.0) } else { HOP_ROW };
    let first: Vec<&HopStat> = d.hops.iter().take(fit).collect();
    hop_table(&mut svg, &first, &d.hops, top, true, row_h);
    pages.push(svg);

    let rest: Vec<&HopStat> = d.hops.iter().skip(fit).collect();
    let mut i = 0;
    while i < rest.len() {
        let mut svg = Svg::new();
        let y = running_head(&mut svg, c);
        let top = target_header(&mut svg, c, d, y, true) + 9.0;
        let per = ((LIMIT - top - 24.6 - route_notes_height(&d.hops)) / HOP_ROW).floor().max(1.0) as usize;
        let end = (i + per).min(rest.len());
        hop_table(&mut svg, &rest[i..end], &d.hops, top, false, HOP_ROW);
        pages.push(svg);
        i = end;
    }
}

/// Centred moving average over `window_ms` of the points' averages (skipping
/// lost samples), restarting after each gap.
fn moving_average(points: &[Point], window_ms: i64) -> Vec<Option<f64>> {
    let half = window_ms / 2;
    let mut out = vec![None; points.len()];
    let mut seg_start = 0;
    for i in 0..=points.len() {
        if i == points.len() || (i > 0 && points[i].gap) {
            let seg = &points[seg_start..i];
            let (mut lo, mut hi) = (0usize, 0usize);
            let (mut sum, mut n) = (0.0, 0u32);
            for (k, p) in seg.iter().enumerate() {
                while hi < seg.len() && seg[hi].t_ms <= p.t_ms + half {
                    if let Some(v) = seg[hi].avg_ms {
                        sum += v;
                        n += 1;
                    }
                    hi += 1;
                }
                while seg[lo].t_ms < p.t_ms - half {
                    if let Some(v) = seg[lo].avg_ms {
                        sum -= v;
                        n -= 1;
                    }
                    lo += 1;
                }
                out[seg_start + k] = (n > 0).then(|| sum / n as f64);
            }
            seg_start = i;
        }
    }
    out
}

/// "2.5 s", or "1–2.5 s" when the interval changed within the window.
pub fn interval_range(tl: &Timeline) -> String {
    let (lo, hi) = (tl.interval_min_ms, tl.interval_max_ms);
    if lo > 0 && hi > lo {
        let a = fmt_interval(lo as u32);
        format!("{}–{}", a.trim_end_matches(" s"), fmt_interval(hi as u32))
    } else {
        fmt_interval(tl.interval_ms.max(1) as u32)
    }
}

/// Moving-average window for samples mode: about 30 s, at least 5 samples.
fn ma_window(tl: &Timeline) -> i64 {
    30_000.max(tl.interval_ms * 5)
}

pub fn fmt_span(ms: i64) -> String {
    if ms % 3_600_000 == 0 {
        let h = ms / 3_600_000;
        if h == 1 { "1-hour".into() } else { format!("{h}-hour") }
    } else if ms % 60_000 == 0 {
        format!("{}-minute", ms / 60_000)
    } else {
        let s = ms as f64 / 1000.0;
        if s.fract() == 0.0 { format!("{s:.0}-second") } else { format!("{s:.1}-second") }
    }
}

// ----- output -------------------------------------------------------------

/// Folders searched for the DejaVu font files, first match wins: an
/// override, `fonts` beside the program (Windows), the package's share
/// folder and the distribution's DejaVu package (Linux).
fn font_dirs() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = Vec::new();
    if let Some(d) = std::env::var_os("PINGRAIL_FONT_DIR").filter(|d| !d.is_empty()) {
        v.push(d.into());
    }
    if let Some(dir) = std::env::current_exe().ok().and_then(|e| e.parent().map(PathBuf::from)) {
        v.push(dir.join("fonts"));
        v.push(dir.join("../share/pingrail/fonts"));
    }
    #[cfg(unix)]
    for d in [
        "/usr/share/pingrail/fonts",
        "/usr/share/fonts/truetype/dejavu",
        "/usr/share/fonts/dejavu",
        "/usr/share/fonts/TTF",
        "/usr/share/fonts/dejavu-sans-fonts",
        "/usr/local/share/fonts",
    ] {
        v.push(d.into());
    }
    #[cfg(debug_assertions)]
    v.push(PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/fonts")));
    v
}

/// The fonts pages are set in. `wide` adds the system's fonts, for names in
/// scripts that neither the report's own faces nor DejaVu cover; looking
/// through them takes a moment, so it is only done for a page that needs it.
fn fontdb(wide: bool) -> Arc<usvg::fontdb::Database> {
    static OWN: OnceLock<Arc<usvg::fontdb::Database>> = OnceLock::new();
    static WIDE: OnceLock<Arc<usvg::fontdb::Database>> = OnceLock::new();
    let own = OWN.get_or_init(|| {
        let mut db = usvg::fontdb::Database::new();
        for data in [SANS, SANS_SEMI, SANS_BOLD, SERIF_BOLD] {
            db.load_font_source(usvg::fontdb::Source::Binary(Arc::new(data)));
        }
        if let Some(dir) = font_dirs().into_iter().find(|d| d.join(FALLBACK_FILES[0]).is_file()) {
            for f in FALLBACK_FILES {
                if let Err(e) = db.load_font_file(dir.join(f)) {
                    tracing::warn!("report font {}: {e}", dir.join(f).display());
                }
            }
        }
        db.set_sans_serif_family(BODY_FAMILY);
        db.set_serif_family(HEAD_FAMILY);
        db.set_monospace_family(BODY_FAMILY);
        Arc::new(db)
    });
    if !wide {
        return own.clone();
    }
    WIDE.get_or_init(|| {
        let mut db = (**own).clone();
        db.load_system_fonts();
        Arc::new(db)
    })
    .clone()
}

/// Whether `svg` has text the report's own typeface has no glyph for.
fn beyond_own_faces(svg: &str) -> bool {
    let Some(face) = &faces()[Font::Regular as usize] else { return true };
    svg.chars().any(|ch| !ch.is_ascii() && !ch.is_whitespace() && face.glyph_index(ch).is_none())
}

fn parse(svg: &str) -> Result<usvg::Tree> {
    let opt = usvg::Options { fontdb: fontdb(beyond_own_faces(svg)), font_family: BODY_FAMILY.into(), ..Default::default() };
    usvg::Tree::from_str(svg, &opt).map_err(|e| anyhow!("report layout error: {e}"))
}

fn to_png(pages: &[String]) -> Result<Vec<u8>> {
    let scale = PNG_SCALE;
    let pw = (W as f32 * scale).ceil() as u32;
    let ph = (H as f32 * scale).ceil() as u32;
    let sep = (12.0 * scale) as u32;
    let total_h = ph * pages.len() as u32 + sep * (pages.len() as u32).saturating_sub(1);
    let mut canvas = tiny_skia::Pixmap::new(pw, total_h).ok_or_else(|| anyhow!("report too large for PNG"))?;
    canvas.fill(tiny_skia::Color::from_rgba8(0xd9, 0xd8, 0xd3, 0xff));
    for (i, p) in pages.iter().enumerate() {
        let tree = parse(p)?;
        let mut page = tiny_skia::Pixmap::new(pw, ph).ok_or_else(|| anyhow!("pixmap"))?;
        resvg::render(&tree, tiny_skia::Transform::from_scale(scale, scale), &mut page.as_mut());
        canvas.draw_pixmap(
            0,
            (i as u32 * (ph + sep)) as i32,
            page.as_ref(),
            &tiny_skia::PixmapPaint::default(),
            tiny_skia::Transform::identity(),
            None,
        );
    }
    canvas.encode_png().map_err(|e| anyhow!("encoding PNG: {e}"))
}

fn to_pdf(pages: &[String]) -> Result<Vec<u8>> {
    use pdf_writer::{Content, Finish, Name, Pdf, Rect, Ref, TextStr};
    use std::collections::HashMap;

    let mut alloc = Ref::new(1);
    let catalog_id = alloc.bump();
    let tree_id = alloc.bump();
    let info_id = alloc.bump();
    let mut pdf = Pdf::new();
    let mut page_ids = Vec::new();
    let mut chunks = Vec::new();

    for p in pages {
        let tree = parse(p)?;
        let (chunk, svg_id) = svg2pdf::to_chunk(&tree, svg2pdf::ConversionOptions::default())
            .map_err(|e| anyhow!("PDF conversion failed: {e}"))?;
        let mut map = HashMap::new();
        let chunk = chunk.renumber(|old| *map.entry(old).or_insert_with(|| alloc.bump()));
        let svg_id = *map.get(&svg_id).ok_or_else(|| anyhow!("PDF conversion lost the page"))?;
        let page_id = alloc.bump();
        let content_id = alloc.bump();
        let name = Name(b"S1");
        let mut page = pdf.page(page_id);
        page.media_box(Rect::new(0.0, 0.0, W as f32, H as f32));
        page.parent(tree_id);
        page.contents(content_id);
        page.resources().x_objects().pair(name, svg_id);
        page.finish();
        let mut content = Content::new();
        content.transform([W as f32, 0.0, 0.0, H as f32, 0.0, 0.0]).x_object(name);
        pdf.stream(content_id, &content.finish());
        page_ids.push(page_id);
        chunks.push(chunk);
    }
    for c in &chunks {
        pdf.extend(c);
    }
    pdf.catalog(catalog_id).pages(tree_id);
    pdf.pages(tree_id).kids(page_ids.iter().copied()).count(page_ids.len() as i32);
    pdf.document_info(info_id)
        .title(TextStr("pingrail latency and route report"))
        .producer(TextStr(concat!("pingrail ", env!("CARGO_PKG_VERSION"))));
    Ok(pdf.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticks_are_aligned_to_local_time() {
        let tz = FixedOffset::east_opt(2 * 3600).unwrap();
        // 2026-10-22 08:07 SAST .. 09:03 SAST
        let from = Utc.with_ymd_and_hms(2026, 10, 22, 6, 7, 0).unwrap().timestamp_millis();
        let to = from + 56 * 60_000;
        let t = time_ticks(from, to, tz, 7);
        assert_eq!(t.first().unwrap().1, "08:10");
        assert!(t.len() <= 8);
    }

    #[test]
    fn tz_labels() {
        assert_eq!(tz_label(FixedOffset::east_opt(7200).unwrap()), "UTC+02:00");
        assert_eq!(tz_label(FixedOffset::east_opt(-(3 * 3600 + 1800)).unwrap()), "UTC-03:30");
    }

    #[test]
    fn the_built_in_faces_load_and_measure() {
        assert!(faces().iter().all(|f| f.is_some()));
        // Figures are all one width, so columns of numbers line up.
        for font in [Font::Regular, Font::Semi, Font::Bold, Font::Head] {
            let w = text_w("0", 10.0, font);
            assert!(w > 3.0 && "123456789".chars().all(|ch| (text_w(&ch.to_string(), 10.0, font) - w).abs() < 1e-9));
        }
        assert!(text_w("Packet loss detected", 10.0, Font::Bold) > text_w("Packet loss detected", 10.0, Font::Regular));
        let cut = truncate("a-very-long-host-name.example.net", 60.0, 10.0, Font::Regular);
        assert!(cut.ends_with('…') && text_w(&cut, 10.0, Font::Regular) <= 60.0);
        assert_eq!(truncate("short", 60.0, 10.0, Font::Regular), "short");
    }

    #[test]
    fn other_scripts_get_a_span_of_their_own() {
        // Cyrillic is in the report's typeface; Japanese is not.
        assert_eq!(script_runs("Офис Москва"), [("Офис Москва".to_string(), true)]);
        assert_eq!(
            script_runs("Tokyo 東京 オフィス lost 2"),
            [
                ("Tokyo ".to_string(), true),
                ("東京".to_string(), false),
                (" ".to_string(), true),
                ("オフィス".to_string(), false),
                (" lost 2".to_string(), true)
            ]
        );
        let mut svg = Svg::new();
        svg.text(100.0, 50.0, 10.0, INK, Anchor::Start, Font::Regular, "A <東京> & B");
        let page = svg.finish();
        // Each stretch is placed by its measured width, and only the one
        // that needs it asks for another font.
        let a = text_w("A <", 10.0, Font::Regular);
        assert!(page.contains(&format!(r#"<tspan x="100.00" y="50.00" font-size="10" fill="{INK}">A &lt;</tspan>"#)));
        assert!(page.contains(&format!(r#"<tspan x="{:.2}" y="50.00" font-size="10" fill="{INK}" font-family="'DejaVu Sans'">東京</tspan>"#, 100.0 + a)));
        assert!(page.contains(&format!(r#"<tspan x="{:.2}" y="50.00" font-size="10" fill="{INK}">&gt; &amp; B</tspan>"#, 100.0 + a + 21.0)));
        assert!(beyond_own_faces("<text>東京</text>") && !beyond_own_faces("<text>Офис — 4.79 % …</text>"));
        assert!(parse(&page).is_ok());
        // Headings and lines of several styles too.
        let mut svg = Svg::new();
        svg.text(100.0, 50.0, 20.0, INK, Anchor::End, Font::Head, "Офис 東京");
        svg.runs(100.0, 80.0, Anchor::Middle, &[("東京", 10.0, INK, Font::Bold), ("  host", 9.0, MUTED, Font::Regular)]);
        let page = svg.finish();
        assert!(page.contains(r#"font-weight="700" font-family="'DejaVu Sans'">東京</tspan>"#));
        assert!(parse(&page).is_ok());
    }

    #[test]
    fn the_wordmark_is_path_data() {
        let d = wordmark();
        assert!(d.starts_with('M') && d.len() > 1000 && !d.contains('<') && !d.contains('"'));
    }

    #[test]
    fn durations_and_shares_in_words() {
        assert_eq!(fmt_dur(300_000), "5 minutes");
        assert_eq!(fmt_dur(299_999), "5 minutes");
        assert_eq!(fmt_dur(45_000), "45 seconds");
        assert_eq!(fmt_dur(3_600_000), "1 hour");
        assert_eq!(fmt_dur(9 * 3_600_000 + 51 * 60_000), "9 h 51 min");
        assert_eq!(fmt_dur(30 * 86_400_000), "30 days");
        assert_eq!(fmt_dur(86_400_000 + 3 * 3_600_000), "1 day 3 h");
        let plain = |s: String| s.replace('\u{a0}', " ");
        assert_eq!(plain(pct(0.0)), "0 %");
        assert_eq!(plain(pct(share(2, 300))), "0.67 %");
        assert_eq!(plain(pct(share(1700, 35459))), "4.79 %");
        assert_eq!(plain(pct(12.34)), "12.3 %");
        assert_eq!(plain(pct(100.0)), "100 %");
        assert_eq!(plain(pct(share(1, 2_000_000))), "under 0.01 %");
        assert_eq!(plain(ms(Some(14.23))), "14.2 ms");
        // A figure is never parted from its unit at the end of a line.
        let lines = wrap(&format!("lost 2 of 300 pings in this period ({})", pct(0.67)), 150.0, 10.0, Font::Regular);
        assert!(lines.len() > 1 && lines.iter().all(|l| !l.starts_with('%')));
        assert_eq!(fmt_count(35459), "35,459");
    }

    fn item(name: &str, sent: u32, lost: u32, rec_sent: u64, rec_lost: u64) -> Item {
        let target = crate::model::Target {
            id: 1,
            host: name.to_lowercase(),
            name: name.into(),
            interval_ms: 1000,
            trace: false,
            enabled: true,
            session: None,
            created_ms: 0,
            share_id: None,
            restrict: None,
        };
        let stats = Stats { sent, received: sent - lost, loss_pct: share(lost as u64, sent as u64), ..Default::default() };
        Item {
            d: Detail { target, live: LiveStatus::default(), stats, hops: Vec::new(), hop: None, timeline: Timeline::default(), events: Vec::new() },
            rec: Recorded { sent: rec_sent, lost: rec_lost, ..Default::default() },
        }
    }

    #[test]
    fn the_tick_is_only_for_no_loss_at_all() {
        // Nothing lost, in the period or on record.
        let verdict = |items: &[Item]| {
            let (m, head, text) = verdict(items);
            (m, head, text.replace('\u{a0}', " "))
        };
        let (m, head, text) = verdict(&[item("Camera", 300, 0, 35_460, 0)]);
        assert_eq!((m, head.as_str()), (Mark::Clean, "No packet loss"));
        assert!(text.contains("300 in this period and 35,460 on record"));
        // A clean period does not earn it when pings were lost before.
        let (m, head, text) = verdict(&[item("Camera", 300, 0, 35_460, 41)]);
        assert_eq!((m, head.as_str()), (Mark::Loss, "Packet loss on record"));
        assert_eq!(text, "Camera lost none in this period and 41 of 35,460 on record (0.12 %).");
        // One lost ping is loss.
        let (m, head, text) = verdict(&[item("Cloudflare DNS", 300, 2, 35_459, 1_700), item("Google DNS", 300, 0, 35_460, 0)]);
        assert_eq!((m, head.as_str()), (Mark::Loss, "Packet loss detected"));
        assert_eq!(
            text,
            "Cloudflare DNS lost 2 of 300 pings in this period (0.67 %) and 1,700 of 35,459 on record (4.79 %). Google DNS lost none, in this period or on record."
        );
        // No reply at all.
        let (m, head, _) = verdict(&[item("Camera", 300, 300, 35_460, 900), item("Router", 300, 0, 35_460, 0)]);
        assert_eq!((m, head.as_str()), (Mark::Down, "One target is not answering"));
        assert_eq!(verdict(&[item("Camera", 0, 0, 0, 0)]).0, Mark::Empty);
        assert_eq!(period_mark(&item("x", 300, 1, 0, 0).d.stats), Mark::Loss);
    }

    #[test]
    fn a_report_renders_in_both_formats() {
        let dir = std::env::temp_dir().join(format!("pingrail-test-{}", crate::config::random_hex(4)));
        let s = Store::open(&dir.join("t.db")).unwrap();
        let mut ids = Vec::new();
        // Enough targets that the summary runs on to a second page.
        for k in 0..9u32 {
            let t = s
                .add_target(&crate::model::NewTarget { host: format!("host{k}.example.com"), trace: Some(false), ..Default::default() }, 1000)
                .unwrap();
            let rows: Vec<crate::store::RoundRecord> = (0..7200i64)
                .map(|i| crate::store::RoundRecord {
                    target_id: t.id,
                    ts_ms: i * 1000,
                    interval_ms: 1000,
                    rtt_us: (k == 0 || i % (40 * (k as i64 + 1)) != 7).then_some(14_000 + (i % 13) as u32 * 300),
                    hops: None,
                })
                .collect();
            s.insert_rounds(&rows).unwrap();
            ids.push(t.id);
        }
        let monitor = Monitor { host: Some("office-pc".into()), dns: Some("its own resolver, on the same connection".into()), retention_days: 30 };
        for (targets, from) in [(ids.clone(), 6_900_000), (ids[..2].to_vec(), 0)] {
            let mut req = ReportRequest { target_ids: targets.clone(), from_ms: from, to_ms: 7_200_000, tz_offset_min: 120, format: ReportFormat::Pdf };
            let scope = Scope::everything();
            let rec = analysis::recorded(&s, ids[1], &scope, 7_200_000, 7_200_000).unwrap();
            assert_eq!((rec.sent, rec.lost, rec.first_ms, rec.last_ms), (7200, 90, Some(0), Some(7_199_000)));
            // Two hours on record: a bar for every five minutes.
            assert_eq!((rec.step_min, rec.bars.len()), (5, 24));
            assert_eq!(rec.bars.iter().map(|b| (b.1, b.2)).fold((0, 0), |a, b| (a.0 + b.0, a.1 + b.1)), (rec.sent, rec.lost));
            assert_eq!((rec.avg_ms.map(|v| (v * 10.0).round()), rec.max_ms), (Some(158.0), Some(17.6)));
            let pdf = render(&s, None, Thresholds::default(), &req, &scope, &monitor).unwrap();
            assert!(pdf.starts_with(b"%PDF"));
            let pages = pdf.windows(11).filter(|w| w == b"/Type /Page").count() - 1;
            assert!(pages > targets.len(), "a summary and a page for each target, got {pages}");
            req.format = ReportFormat::Png;
            let png = render(&s, None, Thresholds::default(), &req, &scope, &monitor).unwrap();
            assert!(png.starts_with(b"\x89PNG"));
        }
        // A share link that starts later counts nothing from before.
        let scope = Scope { earliest_ms: Some(3_600_000), ..Default::default() };
        let rec = analysis::recorded(&s, ids[1], &scope, 7_200_000, 0).unwrap();
        assert_eq!((rec.sent, rec.first_ms), (3600, Some(3_600_000)));
        let other = Scope { ids: Some(vec![ids[0]]), ..Default::default() };
        assert_eq!(analysis::recorded(&s, ids[1], &other, 7_200_000, 0).unwrap().sent, 0);
        std::fs::remove_dir_all(dir).ok();
    }
}
