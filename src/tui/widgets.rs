//! Custom TUI graphics: the latency timeline, sparklines and hop range gauges.

use chrono::{Local, TimeZone};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Widget;

use crate::model::{Level, Thresholds, Timeline};
use crate::stats::{axis_max, nice_ceil, percentile};

pub const BLOCKS: [&str; 9] = [" ", "▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"];

pub fn level_color(l: Level) -> Color {
    match l {
        Level::Good => Color::Green,
        Level::Warn => Color::Yellow,
        Level::Crit => Color::Red,
        Level::None => Color::DarkGray,
    }
}

/// Bar-per-bucket latency timeline (PingPlotter's lower graph).
pub struct TimelineChart<'a> {
    pub timeline: &'a Timeline,
    pub th: Thresholds,
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

fn put(buf: &mut Buffer, x: u16, y: u16, sym: &str, style: Style) {
    if let Some(c) = buf.cell_mut((x, y)) {
        // Replace the cell outright: set_style alone would merge modifiers
        // (e.g. a gridline's DIM would bleed into a bar drawn over it).
        c.reset();
        c.set_symbol(sym).set_style(style);
    }
}

fn put_str(buf: &mut Buffer, x: u16, y: u16, s: &str, style: Style, max_x: u16) {
    for (i, ch) in s.chars().enumerate() {
        let xx = x + i as u16;
        if xx >= max_x {
            break;
        }
        let mut tmp = [0u8; 4];
        put(buf, xx, y, ch.encode_utf8(&mut tmp), style);
    }
}

impl Widget for TimelineChart<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.height < 3 || area.width < 16 {
            return;
        }
        let label_w: u16 = 6;
        let plot = Rect {
            x: area.x + label_w + 1,
            y: area.y,
            width: area.width - label_w - 1,
            height: area.height - 1,
        };
        let tl = self.timeline;
        let axis_style = Style::new().fg(Color::DarkGray);
        let cols = column_stats(tl, plot.width as usize);

        let mut maxes: Vec<f64> = cols.iter().flatten().filter_map(|c| c.max).collect();
        let avg_max = cols.iter().flatten().filter_map(|c| c.avg()).fold(0.0, f64::max);
        let robust = percentile(&mut maxes, 95.0).unwrap_or(0.0);
        let ymax = axis_max((avg_max * 1.15).max(robust).max(0.1), 2);

        // Axis labels and gridlines
        let rows = plot.height as f64;
        for (frac, row) in [(1.0, plot.y), (0.5, plot.y + plot.height / 2), (0.0, plot.y + plot.height - 1)] {
            let label = fmt_axis(ymax * frac);
            let lx = area.x + label_w.saturating_sub(label.chars().count() as u16);
            put_str(buf, lx, row, &label, axis_style, area.x + label_w);
            if frac > 0.0 {
                for x in plot.x..plot.x + plot.width {
                    put(buf, x, row, "┈", Style::new().fg(Color::DarkGray).add_modifier(Modifier::DIM));
                }
            }
        }
        for y in plot.y..plot.y + plot.height {
            put(buf, area.x + label_w, y, "│", axis_style);
        }
        put(buf, area.x + label_w, plot.y + plot.height, "└", axis_style);

        for (col, c) in cols.iter().enumerate() {
            let x = plot.x + col as u16;
            let Some(c) = c else { continue };
            match c.avg() {
                None => {
                    // Everything lost: a full-height red column.
                    for y in plot.y..plot.y + plot.height {
                        put(buf, x, y, "▐", Style::new().fg(Color::Red));
                    }
                }
                Some(avg) => {
                    let eighths = ((avg / ymax).min(1.0) * rows * 8.0).round().max(1.0) as u32;
                    let full = eighths / 8;
                    let rem = (eighths % 8) as usize;
                    let style = Style::new().fg(level_color(self.th.latency(Some(avg))));
                    for r in 0..full.min(plot.height as u32) {
                        put(buf, x, plot.y + plot.height - 1 - r as u16, "█", style);
                    }
                    if rem > 0 && full < plot.height as u32 {
                        put(buf, x, plot.y + plot.height - 1 - full as u16, BLOCKS[rem], style);
                    }
                    if c.max.is_some_and(|mx| mx > ymax) {
                        // A spike above the top of the scale.
                        put(buf, x, plot.y, "▴", Style::new().fg(level_color(self.th.latency(c.max))));
                    }
                    if c.lost > 0 {
                        // Colour by the loss thresholds, so one lost probe in
                        // a 15-minute column doesn't look like an outage.
                        let pct = c.lost as f64 * 100.0 / c.sent.max(1) as f64;
                        let (glyph, style) = match self.th.loss(pct, c.sent) {
                            Level::Crit => ("▼", Style::new().fg(Color::Red).add_modifier(Modifier::BOLD)),
                            Level::Warn => ("▼", Style::new().fg(Color::Yellow)),
                            _ => ("▾", Style::new().fg(Color::DarkGray)),
                        };
                        put(buf, x, plot.y, glyph, style);
                    }
                }
            }
        }

        // Time labels along the bottom row
        let y = plot.y + plot.height;
        let span = (self.timeline.to_ms - self.timeline.from_ms).max(1);
        let fmt = if span <= 600_000 {
            "%H:%M:%S"
        } else if span <= 2 * 86_400_000 {
            "%H:%M"
        } else {
            "%d %b %H:%M"
        };
        let ticks = 5u16;
        let mut last_end = 0u16;
        for i in 0..ticks {
            let col = (plot.width.saturating_sub(1)) * i / (ticks - 1);
            let t = self.timeline.from_ms + span * col as i64 / plot.width.max(1) as i64;
            let label = Local.timestamp_millis_opt(t).single().map(|d| d.format(fmt).to_string()).unwrap_or_default();
            let w = label.chars().count() as u16;
            let mut lx = (plot.x + col).saturating_sub(w / 2);
            if i == ticks - 1 {
                lx = (plot.x + plot.width).saturating_sub(w);
            }
            lx = lx.max(plot.x);
            if lx < last_end + 1 && i > 0 {
                continue;
            }
            put_str(buf, lx, y, &label, axis_style, area.x + area.width);
            last_end = lx + w;
        }
    }
}

/// What one terminal column of the timeline shows.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Column {
    pub sent: u32,
    pub lost: u32,
    sum: f64,
    got: u32,
    pub max: Option<f64>,
}

impl Column {
    pub fn avg(&self) -> Option<f64> {
        (self.got > 0).then(|| self.sum / self.got as f64)
    }
}

/// Spread the timeline's points over `width` columns. Each point covers the
/// time until the next point (unless a real gap follows), so a column
/// between two samples repeats the earlier one instead of showing a hole;
/// only real gaps stay empty.
pub fn column_stats(tl: &Timeline, width: usize) -> Vec<Option<Column>> {
    let mut cols: Vec<Option<Column>> = vec![None; width];
    if width == 0 || tl.points.is_empty() {
        return cols;
    }
    let span = (tl.to_ms - tl.from_ms).max(1) as f64;
    let colw = span / width as f64;
    let pts = &tl.points;
    for (i, p) in pts.iter().enumerate() {
        let own = p.t_ms + tl.step_ms.max(1);
        let end = match pts.get(i + 1) {
            Some(n) if !n.gap => n.t_ms,
            _ => own,
        };
        let c0 = (((p.t_ms - tl.from_ms) as f64) / colw).floor().max(0.0) as usize;
        let c1 = ((((end - tl.from_ms) as f64) / colw).ceil() as usize).max(c0 + 1).min(width);
        let got = p.sent - p.lost;
        for c in cols.iter_mut().take(c1).skip(c0.min(width)) {
            let e = c.get_or_insert_with(Column::default);
            e.sent += p.sent;
            e.lost += p.lost;
            if let Some(a) = p.avg_ms {
                e.sum += a * got as f64;
                e.got += got;
            }
            if let Some(m) = p.max_ms {
                e.max = Some(e.max.map_or(m, |x| x.max(m)));
            }
        }
    }
    cols
}

/// Compress `vals` to at most `width` points (average of averages, max of loss).
pub fn resample(spark: &[Option<f64>], loss: &[Option<f64>], width: usize) -> Vec<(Option<f64>, Option<f64>)> {
    let n = spark.len();
    if n == 0 || width == 0 {
        return Vec::new();
    }
    if n <= width {
        return spark.iter().copied().zip(loss.iter().copied().chain(std::iter::repeat(None))).collect();
    }
    (0..width)
        .map(|i| {
            let a = i * n / width;
            let b = ((i + 1) * n / width).max(a + 1);
            let vals: Vec<f64> = spark[a..b].iter().flatten().copied().collect();
            let avg = if vals.is_empty() { None } else { Some(vals.iter().sum::<f64>() / vals.len() as f64) };
            let l = loss.get(a..b).and_then(|s| s.iter().flatten().copied().fold(None, |m: Option<f64>, v| Some(m.map_or(v, |m| m.max(v)))));
            (avg, l)
        })
        .collect()
}

/// One-line sparkline of average latency per bucket, coloured by status,
/// with lost samples in red.
pub fn sparkline(spark: &[Option<f64>], loss: &[Option<f64>], width: usize, th: Thresholds) -> Line<'static> {
    let pts = resample(spark, loss, width);
    let mut vals: Vec<f64> = pts.iter().filter_map(|p| p.0).collect();
    let top = nice_ceil(percentile(&mut vals, 95.0).unwrap_or(1.0) * 1.2);
    let mut spans = Vec::with_capacity(width);
    let pad = width.saturating_sub(pts.len());
    if pad > 0 {
        spans.push(Span::raw(" ".repeat(pad)));
    }
    for (avg, l) in pts {
        let span = match (avg, l) {
            (None, Some(l)) if l > 0.0 => Span::styled("×", Style::new().fg(Color::Red)),
            (None, _) => Span::raw(" "),
            (Some(v), l) => {
                let idx = ((v / top).min(1.0) * 7.0).round() as usize + 1;
                let loss_pct = l.unwrap_or(0.0) * 100.0;
                let color = if loss_pct >= th.loss_crit_pct {
                    Color::Red
                } else if loss_pct >= th.loss_warn_pct {
                    Color::Yellow
                } else {
                    level_color(th.latency(Some(v)))
                };
                Span::styled(BLOCKS[idx.min(8)], Style::new().fg(color))
            }
        };
        spans.push(span);
    }
    Line::from(spans)
}

/// Horizontal min–avg–max gauge for a hop row.
pub fn range_gauge(min: Option<f64>, avg: Option<f64>, max: Option<f64>, scale: f64, width: usize, th: Thresholds) -> Line<'static> {
    let (Some(lo), Some(a), Some(hi)) = (min, avg, max) else {
        return Line::from(Span::styled("·".repeat(width.min(1)), Style::new().fg(Color::DarkGray)));
    };
    if width < 3 {
        return Line::default();
    }
    let pos = |v: f64| (((v / scale).min(1.0)) * (width - 1) as f64).round() as usize;
    let (pl, pa, ph) = (pos(lo), pos(a), pos(hi));
    let mut spans = Vec::new();
    spans.push(Span::raw(" ".repeat(pl)));
    for i in pl..=ph.max(pl) {
        if i == pa {
            spans.push(Span::styled("●", Style::new().fg(level_color(th.latency(Some(a))))));
        } else {
            spans.push(Span::styled("─", Style::new().fg(Color::DarkGray)));
        }
    }
    if hi > scale {
        spans.push(Span::styled("›", Style::new().fg(Color::DarkGray)));
    }
    Line::from(spans)
}
