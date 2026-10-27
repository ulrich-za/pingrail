//! PDF and PNG reports. Each page is laid out as SVG (A4 portrait, 1 unit =
//! 1 pt), then rasterised with resvg for PNG or converted to vector PDF pages
//! with svg2pdf. Fonts are embedded in the output so it looks identical
//! everywhere. pingrail reads them from DejaVu font files installed beside it
//! (see `font_dirs`), falling back to the system's fonts.

use anyhow::{anyhow, Result};
use chrono::{DateTime, FixedOffset, TimeZone, Utc};
use resvg::{tiny_skia, usvg};
use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use crate::analysis::{self, Privacy, Scope};
use crate::config::now_ms;
use crate::engine::Rdns;
use crate::model::{Detail, HopReading, HopStat, Level, LiveStatus, ReportFormat, Stats, Thresholds};
use crate::stats::{axis_max, fmt_ms, fmt_pct, nice_ceil, percentile};
use crate::store::Store;

const FONT_FILES: [&str; 3] = ["DejaVuSans.ttf", "DejaVuSans-Bold.ttf", "DejaVuSansMono.ttf"];

const W: f64 = 595.0;
const H: f64 = 842.0;
const M: f64 = 36.0;
const PNG_SCALE: f32 = 2.0;
const CHART_BUCKETS: usize = 240;

// Palette (light surface; reports are made for paper and screens alike).
const SURFACE: &str = "#ffffff";
const TILE: &str = "#f5f5f3";
const ZEBRA: &str = "#f7f7f5";
const GAP: &str = "#efeeea";
const GRID: &str = "#e4e3df";
const AXIS: &str = "#c9c8c2";
const INK: &str = "#0b0b0b";
const ACCENT: &str = "#004e89";
const INK2: &str = "#52514e";
const INK3: &str = "#7d7c77";
const SERIES: &str = "#2a78d6";
const SERIES_LIGHT: &str = "#8fb9ea";
const RANGE: &str = "#b3b2ab";
const GOOD: &str = "#0ca30c";
const WARN: &str = "#fab219";
const CRIT: &str = "#d03b3b";

pub struct ReportRequest {
    pub target_ids: Vec<i64>,
    pub from_ms: i64,
    pub to_ms: i64,
    /// Minutes east of UTC for timestamps in the report.
    pub tz_offset_min: i32,
    pub format: ReportFormat,
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

/// Build the report.
pub fn render(
    store: &Store,
    rdns: Option<&Arc<Rdns>>,
    th: Thresholds,
    req: &ReportRequest,
    scope: &Scope,
) -> Result<Vec<u8>> {
    let mut details = Vec::new();
    let budget = Instant::now() + Duration::from_secs(4);
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
        details.push(d);
    }
    if details.is_empty() {
        return Err(anyhow!("none of the selected targets exist"));
    }
    let pages = build_pages(&details, req, th);
    match req.format {
        ReportFormat::Pdf => to_pdf(&pages),
        ReportFormat::Png => to_png(&pages),
    }
}

// ----- SVG helpers --------------------------------------------------------

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// Approximate rendered width of `s` (DejaVu metrics).
fn text_w(s: &str, size: f64, mono: bool, bold: bool) -> f64 {
    let per = if mono { 0.602 } else if bold { 0.70 } else { 0.57 };
    s.chars().count() as f64 * size * per
}

fn truncate(s: &str, max_w: f64, size: f64, mono: bool) -> String {
    if text_w(s, size, mono, false) <= max_w {
        return s.to_string();
    }
    let per = if mono { 0.602 } else { 0.57 } * size;
    let keep = ((max_w / per) as usize).saturating_sub(1).max(1);
    let mut out: String = s.chars().take(keep).collect();
    out.push('…');
    out
}

/// Greedy word wrap to lines no wider than `max_w`.
fn wrap(s: &str, max_w: f64, size: f64) -> Vec<String> {
    let mut lines = Vec::new();
    let mut cur = String::new();
    for word in s.split_whitespace() {
        let cand = if cur.is_empty() { word.to_string() } else { format!("{cur} {word}") };
        if text_w(&cand, size, false, false) > max_w && !cur.is_empty() {
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

#[derive(Clone, Copy)]
enum Anchor {
    Start,
    Middle,
    End,
}

struct Svg {
    b: String,
}

impl Svg {
    fn new() -> Svg {
        let mut b = String::with_capacity(64 * 1024);
        let _ = write!(
            b,
            r#"<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" font-family="sans-serif"><rect width="{W}" height="{H}" fill="{SURFACE}"/>"#
        );
        Svg { b }
    }

    #[allow(clippy::too_many_arguments)]
    fn text(&mut self, x: f64, y: f64, size: f64, fill: &str, anchor: Anchor, bold: bool, mono: bool, s: &str) {
        let a = match anchor {
            Anchor::Start => "start",
            Anchor::Middle => "middle",
            Anchor::End => "end",
        };
        let fam = if mono { r#" font-family="monospace""# } else { "" };
        let w = if bold { r#" font-weight="bold""# } else { "" };
        let _ = write!(
            self.b,
            r#"<text x="{x:.2}" y="{y:.2}" font-size="{size}" fill="{fill}" text-anchor="{a}"{fam}{w}>{}</text>"#,
            esc(s)
        );
    }

    fn para(&mut self, x: f64, y: f64, size: f64, fill: &str, max_w: f64, s: &str) -> f64 {
        let mut yy = y;
        for line in wrap(s, max_w, size) {
            self.text(x, yy, size, fill, Anchor::Start, false, false, &line);
            yy += size * 1.35;
        }
        yy
    }

    fn rect(&mut self, x: f64, y: f64, w: f64, h: f64, fill: &str, rx: f64) {
        if w <= 0.0 || h <= 0.0 {
            return;
        }
        let _ = write!(self.b, r#"<rect x="{x:.2}" y="{y:.2}" width="{w:.2}" height="{h:.2}" rx="{rx}" fill="{fill}"/>"#);
    }

    fn line(&mut self, x1: f64, y1: f64, x2: f64, y2: f64, stroke: &str, w: f64) {
        let _ = write!(
            self.b,
            r#"<line x1="{x1:.2}" y1="{y1:.2}" x2="{x2:.2}" y2="{y2:.2}" stroke="{stroke}" stroke-width="{w}" stroke-linecap="round"/>"#
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

    fn area(&mut self, upper: &[(f64, f64)], lower: &[(f64, f64)], fill: &str, opacity: f64) {
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
        let _ = write!(self.b, r#"<path d="{d}" fill="{fill}" fill-opacity="{opacity}"/>"#);
    }

    fn finish(mut self) -> String {
        self.b.push_str("</svg>");
        self.b
    }
}

fn level_color(l: Level) -> &'static str {
    match l {
        Level::Good => GOOD,
        Level::Warn => WARN,
        Level::Crit => CRIT,
        Level::None => INK3,
    }
}

fn mos_level(m: Option<f64>) -> (Level, &'static str) {
    match m {
        None => (Level::None, "No data"),
        Some(v) if v >= 4.0 => (Level::Good, "Good"),
        Some(v) if v >= 3.6 => (Level::Warn, "Fair"),
        Some(v) if v >= 3.1 => (Level::Crit, "Poor"),
        Some(_) => (Level::Crit, "Bad"),
    }
}

fn level_word(l: Level) -> &'static str {
    match l {
        Level::Good => "Good",
        Level::Warn => "Elevated",
        Level::Crit => "High",
        Level::None => "No data",
    }
}

fn fmt_count(n: u32) -> String {
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

fn fmt_interval(ms: u32) -> String {
    if ms.is_multiple_of(1000) {
        format!("{} s", ms / 1000)
    } else {
        format!("{:.1} s", ms as f64 / 1000.0)
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

fn range_label(from: i64, to: i64, tz: FixedOffset) -> String {
    let a = local(from, tz);
    let b = local(to, tz);
    if a.date_naive() == b.date_naive() {
        format!("{} {} – {} ({})", a.format("%-d %b %Y"), a.format("%H:%M"), b.format("%H:%M"), tz_label(tz))
    } else {
        format!("{} – {} ({})", a.format("%-d %b %Y %H:%M"), b.format("%-d %b %Y %H:%M"), tz_label(tz))
    }
}

// ----- pages --------------------------------------------------------------

struct Ctx<'a> {
    req: &'a ReportRequest,
    tz: FixedOffset,
    th: Thresholds,
    generated: String,
}

/// The pingrail mark (rail and ring), `h` points tall, its rail's left edge
/// at `x` and its ring centred on `cy`.
fn logo(svg: &mut Svg, x: f64, cy: f64, h: f64) {
    // The mark's drawing box in its own 64-unit space: x 18.5–49.3, y 15.75–59.5.
    let s = h / 43.75;
    let tx = x - 18.5 * s;
    let ty = cy - 31.0 * s;
    let _ = write!(
        svg.b,
        r#"<g transform="translate({tx:.2} {ty:.2}) scale({s:.4})"><path d="M22 31V56" fill="none" stroke="{ACCENT}" stroke-width="7" stroke-linecap="round"/><circle cx="34" cy="31" r="12" fill="none" stroke="{ACCENT}" stroke-width="6.5"/><circle cx="34" cy="31" r="4.2" fill="{ACCENT}"/></g>"#
    );
}

fn page_frame(svg: &mut Svg, c: &Ctx) {
    logo(svg, M, M - 0.6, 11.0);
    svg.text(M + 11.5, M + 2.0, 7.5, INK2, Anchor::Start, true, false, "PINGRAIL · LATENCY & ROUTE REPORT");
    svg.text(W - M, M + 2.0, 7.5, INK2, Anchor::End, false, false, &range_label(c.req.from_ms, c.req.to_ms, c.tz));
    svg.line(M, M + 9.0, W - M, M + 9.0, GRID, 0.75);
}

fn page_footer(svg: &mut Svg, c: &Ctx, page: usize, total: usize) {
    svg.line(M, H - M - 10.0, W - M, H - M - 10.0, GRID, 0.75);
    svg.text(
        M,
        H - M + 1.0,
        7.0,
        INK3,
        Anchor::Start,
        false,
        false,
        &format!("Generated by pingrail {} on {}", env!("CARGO_PKG_VERSION"), c.generated),
    );
    svg.text(W - M, H - M + 1.0, 7.0, INK3, Anchor::End, false, false, &format!("Page {page} of {total}"));
}

/// Pages are built as closures so the footer can know the total page count.
type PageFn<'a> = Box<dyn Fn(&mut Svg) + 'a>;

fn build_pages(details: &[Detail], req: &ReportRequest, th: Thresholds) -> Vec<String> {
    let tz = tz(req);
    let c = Ctx { req, tz, th, generated: local(now_ms(), tz).format("%-d %b %Y %H:%M").to_string() };
    let mut pages: Vec<PageFn> = Vec::new();

    if details.len() > 1 {
        const PER_PAGE: usize = 18;
        let chunks: Vec<&[Detail]> = details.chunks(PER_PAGE).collect();
        let n = chunks.len();
        for (i, chunk) in chunks.into_iter().enumerate() {
            let c = &c;
            pages.push(Box::new(move |svg| summary_page(svg, c, details.len(), chunk, i, n)));
        }
    }

    const FIRST_ROWS: usize = 20;
    const MORE_ROWS: usize = 46;
    for d in details {
        let c = &c;
        let first: Vec<&HopStat> = d.hops.iter().take(FIRST_ROWS).collect();
        pages.push(Box::new(move |svg| target_page(svg, c, d, &first)));
        let rest: Vec<&HopStat> = d.hops.iter().skip(FIRST_ROWS).collect();
        for chunk in rest.chunks(MORE_ROWS) {
            let rows = chunk.to_vec();
            pages.push(Box::new(move |svg| route_continued_page(svg, c, d, &rows)));
        }
    }

    let total = pages.len();
    pages
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let mut svg = Svg::new();
            page_frame(&mut svg, &c);
            f(&mut svg);
            page_footer(&mut svg, &c, i + 1, total);
            svg.finish()
        })
        .collect()
}

fn summary_page(svg: &mut Svg, c: &Ctx, total: usize, rows: &[Detail], idx: usize, pages: usize) {
    let mut y = M + 38.0;
    let title = if pages > 1 { format!("Summary ({} of {pages})", idx + 1) } else { "Summary".into() };
    svg.text(M, y, 18.0, INK, Anchor::Start, true, false, &title);
    y += 16.0;
    svg.text(M, y, 9.0, INK2, Anchor::Start, false, false, &format!("{total} targets · latency, jitter and loss to each endpoint"));
    y += 26.0;

    // Columns
    let cols: [(&str, f64, Anchor); 8] = [
        ("Target", M + 12.0, Anchor::Start),
        ("Average", M + 228.0, Anchor::End),
        ("Max", M + 268.0, Anchor::End),
        ("Jitter", M + 306.0, Anchor::End),
        ("Loss %", M + 346.0, Anchor::End),
        ("MOS", M + 380.0, Anchor::End),
        ("Latency over the period", M + 396.0, Anchor::Start),
        ("", 0.0, Anchor::Start),
    ];
    for (label, x, a) in cols.iter().take(7) {
        svg.text(*x, y, 7.5, INK2, *a, true, false, label);
    }
    y += 6.0;
    svg.line(M, y, W - M, y, AXIS, 0.75);
    let row_h = 34.0;
    for (i, d) in rows.iter().enumerate() {
        let top = y + i as f64 * row_h;
        if i % 2 == 1 {
            svg.rect(M, top, W - 2.0 * M, row_h, ZEBRA, 0.0);
        }
        let mid = top + row_h / 2.0;
        let s = &d.stats;
        let worst = c.th.latency(s.avg_ms).max(c.th.loss(s.loss_pct, s.sent));
        svg.circle(M + 5.0, mid - 3.0, 3.0, level_color(worst));
        svg.text(M + 12.0, mid - 1.0, 9.0, INK, Anchor::Start, true, false, &truncate(&d.target.name, 200.0, 9.0, false));
        svg.text(M + 12.0, mid + 10.0, 7.5, INK2, Anchor::Start, false, true, &truncate(&d.target.host, 200.0, 7.5, true));
        let vals = [
            (fmt_ms(s.avg_ms), M + 228.0),
            (fmt_ms(s.max_ms), M + 268.0),
            (fmt_ms(s.jitter_ms), M + 306.0),
            (if s.sent > 0 { fmt_pct(s.loss_pct) } else { "—".into() }, M + 346.0),
            (s.mos.map(|m| format!("{m:.1}")).unwrap_or("—".into()), M + 380.0),
        ];
        for (v, x) in vals {
            svg.text(x, mid + 3.0, 8.5, INK, Anchor::End, false, false, &v);
        }
        sparkline(svg, d, M + 396.0, top + 7.0, W - M - (M + 396.0) - 4.0, row_h - 14.0);
    }
    let bottom = y + rows.len() as f64 * row_h;
    svg.line(M, bottom, W - M, bottom, GRID, 0.75);
    svg.para(
        M,
        bottom + 16.0,
        7.5,
        INK3,
        W - 2.0 * M,
        &format!(
            "Latency in ms. Status dot: green below {} ms and {}% loss, amber below {} ms and {}% loss, red above. MOS estimates call quality (1–4.5).",
            c.th.warn_ms, c.th.loss_warn_pct, c.th.crit_ms, c.th.loss_crit_pct
        ),
    );
}

fn sparkline(svg: &mut Svg, d: &Detail, x: f64, y: f64, w: f64, h: f64) {
    let tl = &d.timeline;
    if tl.points.is_empty() {
        return;
    }
    let mut avgs: Vec<f64> = tl.points.iter().filter_map(|p| p.avg_ms).collect();
    let ymax = nice_ceil(percentile(&mut avgs, 98.0).unwrap_or(1.0) * 1.1);
    let span = (tl.to_ms - tl.from_ms).max(1) as f64;
    let xf = |t: i64| x + (t - tl.from_ms) as f64 / span * w;
    svg.line(x, y + h, x + w, y + h, GRID, 0.5);
    let mut run: Vec<(f64, f64)> = Vec::new();
    for p in &tl.points {
        let px = xf(p.t_ms);
        if p.lost > 0 {
            svg.rect(px - 0.4, y + h - 3.0, 0.8, 3.0, CRIT, 0.0);
        }
        if p.gap {
            svg.polyline(&run, SERIES, 1.1);
            run.clear();
        }
        if let Some(v) = p.avg_ms {
            run.push((px, y + h - 4.0 - (v / ymax).min(1.0) * (h - 5.0)));
        }
    }
    svg.polyline(&run, SERIES, 1.1);
}

/// Centred moving average over `window_ms` of the points' averages (skipping
/// lost samples), restarting after each gap.
pub fn moving_average(points: &[crate::model::Point], window_ms: i64) -> Vec<Option<f64>> {
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

/// What each point of a timeline stands for, for the caption under a chart.
pub fn timeline_caption(tl: &crate::model::Timeline) -> String {
    use crate::model::TimelineMode;
    match tl.mode {
        TimelineMode::Samples => format!(
            "Each point is one sample (every {}). Bold line: moving average over {}.",
            interval_range(tl),
            fmt_span(ma_window(tl))
        ),
        TimelineMode::Slices => {
            let per = |iv: i64| (tl.step_ms as f64 / iv.max(1) as f64).round().max(1.0) as i64;
            let (lo, hi) = (tl.interval_min_ms, tl.interval_max_ms);
            let n = if lo > 0 && hi > lo && per(hi) != per(lo) {
                format!("{}–{}", per(hi), per(lo))
            } else {
                format!("about {}", per(tl.interval_ms))
            };
            format!("Each point is a {} slice ({} samples). Bold line: average; band: lowest to highest.", fmt_span(tl.step_ms), n)
        }
    }
}

/// "2.5 s", or "1–2.5 s" when the interval changed within the window.
pub fn interval_range(tl: &crate::model::Timeline) -> String {
    let (lo, hi) = (tl.interval_min_ms, tl.interval_max_ms);
    if lo > 0 && hi > lo {
        let a = fmt_interval(lo as u32);
        format!("{}–{}", a.trim_end_matches(" s"), fmt_interval(hi as u32))
    } else {
        fmt_interval(tl.interval_ms.max(1) as u32)
    }
}

/// Moving-average window for samples mode: about 30 s, at least 5 samples.
pub fn ma_window(tl: &crate::model::Timeline) -> i64 {
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

fn target_header(svg: &mut Svg, d: &Detail, y: f64, continued: bool) -> f64 {
    let name = if continued { format!("{} (route, continued)", d.target.name) } else { d.target.name.clone() };
    svg.text(M, y, 18.0, INK, Anchor::Start, true, false, &truncate(&name, W - 2.0 * M, 18.0, false));
    let mut parts = vec![d.target.host.clone()];
    if let Some(dest) = d.hops.iter().find(|h| h.is_dest) {
        if let Some(a) = &dest.addr
            && *a != d.target.host {
                parts.push(a.clone());
            }
        if let Some(hn) = &dest.hostname
            && *hn != d.target.host {
                parts.push(hn.clone());
            }
        parts.push(format!("{} hops", dest.ttl));
    }
    parts.push(format!("sampled every {}", fmt_interval(d.target.interval_ms)));
    parts.push(format!("{} samples", fmt_count(d.stats.sent)));
    if let Some(p) = d.stats.p95_ms {
        parts.push(format!("95th percentile {} ms", fmt_ms(Some(p))));
    }
    svg.text(M, y + 15.0, 8.5, INK2, Anchor::Start, false, false, &truncate(&parts.join("  ·  "), W - 2.0 * M, 8.5, false));
    y + 15.0
}

fn tiles(svg: &mut Svg, c: &Ctx, s: &Stats, y: f64) -> f64 {
    let n = 6.0;
    let gap = 8.0;
    let w = (W - 2.0 * M - gap * (n - 1.0)) / n;
    let h = 50.0;
    let lat = |v: Option<f64>| (fmt_ms(v), "ms");
    let (ml, mw) = mos_level(s.mos);
    let loss_l = c.th.loss(s.loss_pct, s.sent);
    let avg_l = c.th.latency(s.avg_ms);
    let items: Vec<(&str, (String, &str), Option<(Level, &str)>)> = vec![
        ("Average", lat(s.avg_ms), Some((avg_l, level_word(avg_l)))),
        ("Minimum", lat(s.min_ms), None),
        ("Maximum", lat(s.max_ms), None),
        ("Jitter", lat(s.jitter_ms), None),
        (
            "Packet loss",
            (if s.sent > 0 { fmt_pct(s.loss_pct) } else { "—".into() }, "%"),
            Some((loss_l, level_word(loss_l))),
        ),
        ("MOS", (s.mos.map(|m| format!("{m:.2}")).unwrap_or("—".into()), ""), Some((ml, mw))),
    ];
    for (i, (label, (val, unit), status)) in items.into_iter().enumerate() {
        let x = M + i as f64 * (w + gap);
        svg.rect(x, y, w, h, TILE, 4.0);
        svg.text(x + 8.0, y + 13.0, 7.5, INK2, Anchor::Start, false, false, label);
        svg.text(x + 8.0, y + 31.0, 15.0, INK, Anchor::Start, true, false, &val);
        if !unit.is_empty() && val != "—" {
            let vw = text_w(&val, 15.0, false, true);
            svg.text(x + 10.0 + vw, y + 31.0, 8.0, INK2, Anchor::Start, false, false, unit);
        }
        if let Some((l, word)) = status {
            svg.circle(x + 11.0, y + 41.5, 2.6, level_color(l));
            svg.text(x + 17.0, y + 44.0, 7.0, INK2, Anchor::Start, false, false, word);
        }
    }
    y + h
}

fn latency_chart(svg: &mut Svg, c: &Ctx, d: &Detail, top: f64, height: f64, loss_h: f64) -> f64 {
    use crate::model::TimelineMode;
    let tl = &d.timeline;
    let pts = &tl.points;
    let x0 = M + 32.0;
    let x1 = W - M;
    let pw = x1 - x0;
    let (from, to) = (tl.from_ms, tl.to_ms);
    let span = (to - from).max(1) as f64;
    let xf = |t: i64| x0 + (t - from) as f64 / span * pw;
    let samples = tl.mode == TimelineMode::Samples;
    // Width of one point on the time axis.
    let pt_w = (tl.step_ms as f64 / span * pw).max(0.6);

    // Titles + key
    svg.text(M, top, 10.0, INK, Anchor::Start, true, false, "Latency");
    svg.text(M + 50.0, top, 8.0, INK2, Anchor::Start, false, false, "ms, endpoint round-trip time");
    let kx = W - M;
    let spread = if samples { "each sample" } else { "lowest to highest" };
    svg.text(kx, top, 7.5, INK2, Anchor::End, false, false, spread);
    let kw = text_w(spread, 7.5, false, false);
    if samples {
        svg.line(kx - kw - 16.0, top - 2.5, kx - kw - 4.0, top - 2.5, SERIES_LIGHT, 1.0);
    } else {
        svg.b.push_str(&format!(
            r#"<rect x="{:.2}" y="{:.2}" width="12" height="7" rx="1" fill="{SERIES}" fill-opacity="0.22"/>"#,
            kx - kw - 16.0,
            top - 6.0
        ));
    }
    let kx2 = kx - kw - 26.0;
    let avg_label = if samples { "moving average" } else { "average" };
    svg.text(kx2, top, 7.5, INK2, Anchor::End, false, false, avg_label);
    let kw2 = text_w(avg_label, 7.5, false, false);
    svg.line(kx2 - kw2 - 16.0, top - 2.5, kx2 - kw2 - 4.0, top - 2.5, SERIES, 2.0);

    let py0 = top + 10.0;
    let py1 = py0 + height;
    // Scale: robust to a single spike.
    let mut maxes: Vec<f64> = pts.iter().filter_map(|x| x.max_ms).collect();
    let avg_max = pts.iter().filter_map(|x| x.avg_ms).fold(0.0, f64::max);
    let robust = percentile(&mut maxes, 98.0).unwrap_or(0.0);
    let ymax = axis_max((avg_max * 1.15).max(robust).max(1.0), 4);
    let yf = |v: f64| py1 - (v / ymax).min(1.0) * height;
    let ly0 = py1 + 30.0;
    let ly1 = ly0 + loss_h;

    // Stretches without samples
    for [a, b] in &tl.gaps {
        let (gx0, gx1) = (xf((*a).max(from)), xf((*b).min(to)));
        if gx1 > gx0 {
            svg.rect(gx0, py0, gx1 - gx0, height, GAP, 0.0);
            svg.rect(gx0, ly0, gx1 - gx0, loss_h, GAP, 0.0);
        }
    }
    // Lost samples tint the latency area too
    for p in pts.iter().filter(|p| p.lost > 0 && p.lost == p.sent) {
        svg.b.push_str(&format!(
            r#"<rect x="{:.2}" y="{py0:.2}" width="{:.2}" height="{height:.2}" fill="{CRIT}" fill-opacity="0.10"/>"#,
            xf(p.t_ms),
            pt_w
        ));
    }

    // Grid + y labels
    for k in 0..=4 {
        let v = ymax * k as f64 / 4.0;
        let y = yf(v);
        svg.line(x0, y, x1, y, if k == 0 { AXIS } else { GRID }, if k == 0 { 0.75 } else { 0.5 });
        svg.text(x0 - 5.0, y + 2.5, 7.0, INK3, Anchor::End, false, false, &fmt_axis(v));
    }
    let ticks = time_ticks(from, to, c.tz, 7);
    for (t, _) in &ticks {
        let x = xf(*t);
        svg.line(x, py0, x, py1, GRID, 0.5);
    }

    // Threshold reference lines
    for (v, label) in [(c.th.warn_ms, "warn"), (c.th.crit_ms, "crit")] {
        if v < ymax {
            let y = yf(v);
            let color = if label == "warn" { WARN } else { CRIT };
            svg.b.push_str(&format!(
                r#"<line x1="{x0:.2}" y1="{y:.2}" x2="{x1:.2}" y2="{y:.2}" stroke="{color}" stroke-width="0.75" stroke-opacity="0.7"/>"#
            ));
            svg.text(x1 - 2.0, y - 2.5, 6.5, INK3, Anchor::End, false, false, &format!("{label} {} ms", fmt_axis(v)));
        }
    }

    // Points are joined across lost samples; only real gaps break the line.
    // Each point sits in the middle of the time it covers.
    let mid = |p: &crate::model::Point| xf(p.t_ms) + if samples { 0.0 } else { pt_w / 2.0 };
    let ma = if samples { moving_average(pts, ma_window(tl)) } else { pts.iter().map(|p| p.avg_ms).collect() };
    let mut upper = Vec::new();
    let mut lower = Vec::new();
    let mut detail = Vec::new();
    let mut line = Vec::new();
    for (i, p) in pts.iter().enumerate() {
        if p.gap {
            svg.area(&upper, &lower, SERIES, 0.20);
            svg.polyline(&detail, SERIES_LIGHT, 0.8);
            svg.polyline(&line, SERIES, 1.6);
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
    svg.area(&upper, &lower, SERIES, 0.20);
    svg.polyline(&detail, SERIES_LIGHT, 0.8);
    svg.polyline(&line, SERIES, 1.6);
    if pts.iter().all(|x| x.avg_ms.is_none()) {
        let msg = if pts.is_empty() { "No samples in this period" } else { "No replies in this period" };
        svg.text((x0 + x1) / 2.0, (py0 + py1) / 2.0, 9.0, INK3, Anchor::Middle, false, false, msg);
    }

    // Loss chart (separate scale, same time axis)
    svg.text(M, ly0 - 5.0, 10.0, INK, Anchor::Start, true, false, "Packet loss");
    svg.text(M + 66.0, ly0 - 5.0, 8.0, INK2, Anchor::Start, false, false, if samples { "lost samples" } else { "% of samples lost" });
    let max_loss = pts
        .iter()
        .filter(|x| x.sent > 0)
        .map(|x| 100.0 * x.lost as f64 / x.sent as f64)
        .fold(0.0, f64::max);
    let lmax = if samples { 100.0 } else if max_loss > 0.0 { nice_ceil(max_loss).min(100.0) } else { 10.0 };
    for (k, v) in [(0, 0.0), (1, lmax)] {
        let y = ly1 - v / lmax * loss_h;
        svg.line(x0, y, x1, y, if k == 0 { AXIS } else { GRID }, if k == 0 { 0.75 } else { 0.5 });
        svg.text(x0 - 5.0, y + 2.5, 7.0, INK3, Anchor::End, false, false, &fmt_axis(v));
    }
    for (t, _) in &ticks {
        let x = xf(*t);
        svg.line(x, ly0, x, ly1, GRID, 0.5);
    }
    for p in pts.iter().filter(|p| p.sent > 0 && p.lost > 0) {
        let pct = 100.0 * p.lost as f64 / p.sent as f64;
        let hgt = (pct / lmax * loss_h).max(1.0);
        let w = (pt_w - 0.3).max(0.8);
        let x = if samples { xf(p.t_ms) - w / 2.0 } else { xf(p.t_ms) + 0.15 };
        svg.rect(x, ly1 - hgt, w, hgt, CRIT, 0.0);
    }
    if max_loss == 0.0 && !pts.is_empty() {
        svg.text((x0 + x1) / 2.0, ly1 - loss_h / 2.0 + 3.0, 8.0, INK3, Anchor::Middle, false, false, "No packet loss");
    }
    // Time labels
    let mut last_x = f64::NEG_INFINITY;
    for (t, label) in &ticks {
        let x = xf(*t);
        let w = text_w(label, 7.0, false, false);
        if x - w / 2.0 > last_x + 6.0 && x + w / 2.0 <= x1 + 10.0 && x - w / 2.0 >= x0 - 14.0 {
            svg.text(x, ly1 + 11.0, 7.0, INK3, Anchor::Middle, false, false, label);
            last_x = x + w / 2.0;
        }
    }
    // What a point means
    svg.text(x0, ly1 + 24.0, 6.8, INK3, Anchor::Start, false, false, &timeline_caption(tl));
    ly1 + 24.0
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

fn hop_table(svg: &mut Svg, c: &Ctx, rows: &[&HopStat], all: &[HopStat], top: f64, title: bool) -> f64 {
    let mut y = top;
    if title {
        svg.text(M, y, 10.0, INK, Anchor::Start, true, false, "Route");
        svg.text(M + 38.0, y, 8.0, INK2, Anchor::Start, false, false, "per-hop statistics, ms");
        y += 14.0;
    }
    // x positions
    let c_hop = M + 16.0;
    let c_addr = M + 24.0;
    let c_name = M + 112.0;
    let c_loss = M + 286.0;
    let c_avg = M + 318.0;
    let c_min = M + 350.0;
    let c_max = M + 382.0;
    let c_jit = M + 414.0;
    let g0 = M + 426.0;
    let g1 = W - M - 4.0;
    let heads = [
        ("Hop", c_hop, Anchor::End),
        ("Address", c_addr, Anchor::Start),
        ("Hostname", c_name, Anchor::Start),
        ("Loss %", c_loss, Anchor::End),
        ("Avg", c_avg, Anchor::End),
        ("Min", c_min, Anchor::End),
        ("Max", c_max, Anchor::End),
        ("Jitter", c_jit, Anchor::End),
        ("Latency range", g0, Anchor::Start),
    ];
    for (h, x, a) in heads {
        svg.text(x, y, 7.5, INK2, a, true, false, h);
    }
    y += 5.0;
    svg.line(M, y, W - M, y, AXIS, 0.75);
    let row_h = 14.5;
    let mut maxes: Vec<f64> = all.iter().filter_map(|h| h.stats.max_ms).collect();
    let gmax = nice_ceil(percentile(&mut maxes, 90.0).unwrap_or(1.0).max(1.0));
    let gx = |v: f64| g0 + (v / gmax).min(1.0) * (g1 - g0);
    if rows.is_empty() {
        svg.text(M + 4.0, y + 14.0, 8.0, INK3, Anchor::Start, false, false, "No route data in this period.");
        return y + 20.0;
    }
    for (i, h) in rows.iter().enumerate() {
        let r0 = y + i as f64 * row_h;
        if i % 2 == 1 {
            svg.rect(M, r0, W - 2.0 * M, row_h, ZEBRA, 0.0);
        }
        let base = r0 + row_h / 2.0 + 2.7;
        let s = &h.stats;
        let bold = h.is_dest;
        svg.text(c_hop, base, 7.5, INK2, Anchor::End, bold, false, &h.ttl.to_string());
        let addr = h.masked.clone().or_else(|| h.addr.clone()).unwrap_or_else(|| "*".into());
        let addr = if h.responders > 1 { format!("{addr} +{}", h.responders - 1) } else { addr };
        svg.text(c_addr, base, 7.0, INK, Anchor::Start, bold, true, &truncate(&addr, 86.0, 7.0, true));
        // What the hop's loss means once later hops are taken into account:
        // only loss that carries on to the destination is marked as loss.
        let note = match h.reading {
            Some(HopReading::LossStarts) if h.is_dest => Some("loss only here"),
            Some(HopReading::LossStarts) => Some("loss starts here"),
            Some(HopReading::LimitsReplies) => Some("limits replies"),
            Some(HopReading::NoReply) => Some("no reply"),
            _ => None,
        };
        let name = match (note, h.hostname.as_deref()) {
            (Some(n), Some(host)) => format!("{n} · {host}"),
            (Some(n), None) => n.to_string(),
            (None, host) => host.unwrap_or_default().to_string(),
        };
        svg.text(c_name, base, 7.5, INK2, Anchor::Start, false, false, &truncate(&name, 136.0, 7.5, false));
        let loss_l = c.th.loss(s.loss_pct, s.sent);
        let limited = h.reading == Some(HopReading::LimitsReplies);
        let lw = text_w(&fmt_pct(s.loss_pct), 7.5, false, bold);
        if limited {
            svg.ring(c_loss - lw - 5.0, base - 2.6, 2.0, INK3, 0.8);
        } else if matches!(h.reading, Some(HopReading::LossStarts | HopReading::LossCarried))
            && matches!(loss_l, Level::Warn | Level::Crit)
        {
            svg.circle(c_loss - lw - 5.0, base - 2.6, 2.2, level_color(loss_l));
        }
        let vals = [
            (if s.sent > 0 { fmt_pct(s.loss_pct) } else { "—".into() }, c_loss),
            (fmt_ms(s.avg_ms), c_avg),
            (fmt_ms(s.min_ms), c_min),
            (fmt_ms(s.max_ms), c_max),
            (fmt_ms(s.jitter_ms), c_jit),
        ];
        for (i, (v, x)) in vals.into_iter().enumerate() {
            let ink = if i == 0 && limited { INK3 } else { INK };
            svg.text(x, base, 7.5, ink, Anchor::End, bold, false, &v);
        }
        if let (Some(lo), Some(hi), Some(avg)) = (s.min_ms, s.max_ms, s.avg_ms) {
            let cy = r0 + row_h / 2.0;
            svg.line(gx(lo), cy, gx(hi).max(gx(lo) + 0.5), cy, RANGE, 1.6);
            svg.circle(gx(avg), cy, 2.8, SURFACE);
            svg.circle(gx(avg), cy, 2.1, level_color(c.th.latency(Some(avg))));
        }
    }
    let end = y + rows.len() as f64 * row_h;
    svg.line(M, end, W - M, end, GRID, 0.75);
    svg.para(
        M,
        end + 11.0,
        6.8,
        INK3,
        W - 2.0 * M,
        &format!(
            "Range bar: min to max, dot = average (scale 0–{} ms). A filled loss mark is loss that carries on to the destination, from the hop where it starts. A hollow mark is a router limiting replies to itself: the hops after it answer normally, so it is not loss on the path.",
            fmt_axis(gmax)
        ),
    )
}

fn target_page(svg: &mut Svg, c: &Ctx, d: &Detail, hops: &[&HopStat]) {
    let mut y = target_header(svg, d, M + 38.0, false);
    y = tiles(svg, c, &d.stats, y + 12.0);
    let chart_h = if d.target.trace { 150.0 } else { 300.0 };
    let loss_h = if d.target.trace { 44.0 } else { 90.0 };
    y = latency_chart(svg, c, d, y + 26.0, chart_h, loss_h);
    if d.target.trace {
        hop_table(svg, c, hops, &d.hops, y + 26.0, true);
    } else {
        svg.text(M, y + 30.0, 8.0, INK3, Anchor::Start, false, false, "Route tracing is off for this target.");
    }
}

fn route_continued_page(svg: &mut Svg, c: &Ctx, d: &Detail, hops: &[&HopStat]) {
    let y = target_header(svg, d, M + 38.0, true);
    hop_table(svg, c, hops, &d.hops, y + 26.0, false);
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

fn fontdb() -> Arc<usvg::fontdb::Database> {
    static DB: OnceLock<Arc<usvg::fontdb::Database>> = OnceLock::new();
    DB.get_or_init(|| {
        let mut db = usvg::fontdb::Database::new();
        let found = font_dirs().into_iter().find(|d| d.join(FONT_FILES[0]).is_file());
        match &found {
            Some(dir) => {
                for f in FONT_FILES {
                    if let Err(e) = db.load_font_file(dir.join(f)) {
                        tracing::warn!("report font {}: {e}", dir.join(f).display());
                    }
                }
            }
            None => {
                tracing::info!("DejaVu fonts not found beside pingrail; reports use system fonts");
                db.load_system_fonts();
            }
        }
        let pick = |names: &[&str]| -> Option<String> {
            names.iter().find(|n| db.faces().any(|f| f.families.iter().any(|(fam, _)| fam == *n))).map(|n| n.to_string())
        };
        let sans = pick(&["DejaVu Sans", "Segoe UI", "Arial", "Liberation Sans", "Noto Sans", "Helvetica"])
            .or_else(|| db.faces().next().and_then(|f| f.families.first().map(|(n, _)| n.clone())));
        let mono = pick(&["DejaVu Sans Mono", "Consolas", "Liberation Mono", "Noto Sans Mono", "Courier New"]);
        match &sans {
            Some(s) => {
                // usvg falls back to the serif family when a face is missing.
                db.set_sans_serif_family(s.clone());
                db.set_serif_family(s.clone());
                db.set_monospace_family(mono.clone().unwrap_or_else(|| s.clone()));
            }
            None => tracing::warn!("no fonts found: report text will be missing (set PINGRAIL_FONT_DIR)"),
        }
        Arc::new(db)
    })
    .clone()
}

fn parse(svg: &str) -> Result<usvg::Tree> {
    let mut opt = usvg::Options::default();
    opt.fontdb = fontdb();
    opt.font_family = "sans-serif".into();
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
        .title(TextStr("pingrail latency & route report"))
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
}
