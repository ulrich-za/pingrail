//! Drawing the TUI.

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, BorderType, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Wrap};
use ratatui::Frame;

use super::widgets::{level_color, range_gauge, sparkline, TimelineChart};
use super::*;
use crate::stats::{fmt_ms, fmt_pct, nice_ceil, percentile};
use crate::model::{HopReading, HopStat};

const ACCENT: Color = Color::Cyan;

pub fn draw(f: &mut Frame, app: &mut App) {
    let area = f.area();
    let [header, body, footer] =
        Layout::vertical([Constraint::Length(1), Constraint::Fill(1), Constraint::Length(1)]).areas(area);
    draw_header(f, header, app);
    draw_footer(f, footer, app);

    let n = app.targets().len();
    let trace = app.selected_target().is_some_and(|t| t.target.trace);
    let hop_rows = app.detail.as_ref().map(|d| d.hops.len()).unwrap_or(0);
    let max_targets = ((body.height as u32 * 35 / 100) as u16).max(7);
    let targets_h = ((n.max(if n == 0 { 6 } else { 1 }) + 3) as u16).min(max_targets);
    let remaining = body.height.saturating_sub(targets_h);
    let hops_h = if trace && remaining >= 18 {
        ((hop_rows.max(2) + 3) as u16).min(remaining * 45 / 100).max(5)
    } else {
        0
    };
    let [t_area, h_area, g_area] = Layout::vertical([
        Constraint::Length(targets_h),
        Constraint::Length(hops_h),
        Constraint::Fill(1),
    ])
    .areas(body);

    draw_targets(f, t_area, app);
    if hops_h > 0 {
        draw_hops(f, h_area, app);
    }
    draw_timeline(f, g_area, app);
    draw_popup(f, area, app);
}

fn block(title: Line<'static>, focused: bool) -> Block<'static> {
    Block::new()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(if focused { Style::new().fg(ACCENT) } else { Style::new().fg(Color::DarkGray) })
        .title(title)
}

fn draw_header(f: &mut Frame, area: Rect, app: &App) {
    let mut spans = vec![Span::styled(" pingrail ", Style::new().fg(Color::Black).bg(ACCENT).bold()), Span::raw(" ")];
    match &app.mode {
        Mode::Service { url, .. } => {
            let ok = app.overview_err.is_none();
            spans.push(Span::styled("● ", Style::new().fg(if ok { Color::Green } else { Color::Red })));
            spans.push(Span::raw(format!("service {}", url.trim_start_matches("https://"))));
        }
        Mode::Local { .. } => {
            spans.push(Span::styled("● ", Style::new().fg(Color::Yellow)));
            spans.push(Span::raw("local session"));
        }
    }
    spans.push(Span::styled("  │  ", Style::new().fg(Color::DarkGray)));
    let w = WINDOWS[app.window].1;
    match app.view_end {
        None => spans.push(Span::raw(format!("last {w}"))),
        Some(end) => {
            spans.push(Span::raw(format!("{w} ending {}", util::fmt_local(end, "%d %b %H:%M"))));
            spans.push(Span::styled("  (End = live)", Style::new().fg(Color::Yellow)));
        }
    }
    let clock = util::fmt_local(now_ms(), "%H:%M:%S ");
    let used: usize = spans.iter().map(|s| s.width()).sum();
    let pad = (area.width as usize).saturating_sub(used + clock.len());
    spans.push(Span::raw(" ".repeat(pad)));
    spans.push(Span::styled(clock, Style::new().fg(Color::Gray)));
    f.render_widget(Line::from(spans), area);
}

fn draw_footer(f: &mut Frame, area: Rect, app: &App) {
    if let Some(t) = &app.toast {
        let style = match t.level {
            ToastLevel::Info => Style::new().fg(Color::Black).bg(Color::Green),
            ToastLevel::Warn => Style::new().fg(Color::Black).bg(Color::Yellow),
            ToastLevel::Error => Style::new().fg(Color::White).bg(Color::Red),
        };
        f.render_widget(Line::from(Span::styled(format!(" {} ", t.text), style)), area);
        return;
    }
    if let Some(e) = &app.overview_err {
        f.render_widget(Line::from(Span::styled(format!(" {e} "), Style::new().fg(Color::White).bg(Color::Red))), area);
        return;
    }
    let keys: &[(&str, &str)] = &[
        ("a", "add"),
        ("e", "edit"),
        ("d", "delete"),
        ("space", "pause"),
        ("b", "background"),
        ("[ ]", "window"),
        ("← →", "scroll"),
        ("x", "export"),
        ("w", "web UI"),
        ("?", "help"),
        ("q", "quit"),
    ];
    let mut spans = Vec::new();
    let mut used = 0usize;
    for (k, label) in keys {
        let w = k.len() + label.len() + 3;
        if used + w > area.width as usize {
            break;
        }
        spans.push(Span::styled(format!(" {k}"), Style::new().fg(ACCENT).bold()));
        spans.push(Span::styled(format!(" {label} "), Style::new().fg(Color::Gray)));
        used += w;
    }
    f.render_widget(Line::from(spans), area);
}

fn right(s: String) -> Cell<'static> {
    Cell::from(Line::from(s).alignment(Alignment::Right))
}

fn latency_cell(v: Option<f64>, th: Thresholds, colored: bool) -> Cell<'static> {
    let style = if colored { Style::new().fg(level_color(th.latency(v))) } else { Style::new() };
    Cell::from(Line::from(Span::styled(fmt_ms(v), style)).alignment(Alignment::Right))
}

fn loss_cell(s: &Stats, th: Thresholds) -> Cell<'static> {
    if s.sent == 0 {
        return right("—".into());
    }
    let l = th.loss(s.loss_pct, s.sent);
    let style = match l {
        Level::Good => Style::new(),
        other => Style::new().fg(level_color(other)),
    };
    Cell::from(Line::from(Span::styled(fmt_pct(s.loss_pct), style)).alignment(Alignment::Right))
}

/// A hop's loss, coloured only when it carries on to the destination (see
/// `HopReading`): a router limiting its own replies shows dimmed.
fn hop_loss_cell(h: &HopStat, th: Thresholds) -> Cell<'static> {
    let s = &h.stats;
    if s.sent == 0 {
        return right("—".into());
    }
    let style = match (h.reading, th.loss(s.loss_pct, s.sent)) {
        (Some(HopReading::LimitsReplies), _) => Style::new().fg(Color::DarkGray),
        (Some(HopReading::LossStarts | HopReading::LossCarried), l) if l != Level::Good => Style::new().fg(level_color(l)),
        _ => Style::new(),
    };
    Cell::from(Line::from(Span::styled(fmt_pct(s.loss_pct), style)).alignment(Alignment::Right))
}

/// The hostname column, led by what the hop's loss means when that needs saying.
fn hop_name_cell(h: &HopStat) -> Cell<'static> {
    let note = match h.reading {
        Some(HopReading::LossStarts) if h.is_dest => Some(("loss only here ", Style::new().fg(Color::Yellow))),
        Some(HopReading::LossStarts) => Some(("loss starts here ", Style::new().fg(Color::Yellow))),
        Some(HopReading::LimitsReplies) => Some(("limits replies ", Style::new().fg(Color::DarkGray))),
        Some(HopReading::NoReply) => Some(("no reply ", Style::new().fg(Color::DarkGray))),
        _ => None,
    };
    let mut spans = Vec::new();
    if let Some((t, st)) = note {
        spans.push(Span::styled(t, st));
    }
    spans.push(Span::styled(h.hostname.clone().unwrap_or_default(), Style::new().fg(Color::Gray)));
    Cell::from(Line::from(spans))
}

fn draw_targets(f: &mut Frame, area: Rect, app: &mut App) {
    let focused = app.focus == Focus::Targets && app.popup.is_none();
    let n = app.targets().len();
    let title = Line::from(vec![
        Span::styled(" Targets ", Style::new().bold()),
        Span::styled(format!("({n}) "), Style::new().fg(Color::Gray)),
    ]);
    let b = block(title, focused);
    app.targets_area = area;
    if n == 0 {
        let inner = b.inner(area);
        f.render_widget(b, area);
        let gw = util::default_gateway().map(|g| format!(" ({g})")).unwrap_or_default();
        let lines = if app.overview.is_none() {
            vec![Line::from(Span::styled("Connecting…", Style::new().fg(Color::Gray)))]
        } else {
            vec![
                Line::from(Span::styled("No targets yet.", Style::new().bold())),
                Line::from(vec![
                    Span::raw("Press "),
                    Span::styled("a", Style::new().fg(ACCENT).bold()),
                    Span::raw(" to add any host or IP, or quick-add one:"),
                ]),
                Line::from(vec![Span::styled("  1 ", Style::new().fg(ACCENT).bold()), Span::raw("Cloudflare DNS (1.1.1.1)")]),
                Line::from(vec![Span::styled("  2 ", Style::new().fg(ACCENT).bold()), Span::raw("Google DNS (8.8.8.8)")]),
                Line::from(vec![Span::styled("  3 ", Style::new().fg(ACCENT).bold()), Span::raw(format!("Your default gateway{gw}"))]),
            ]
        };
        f.render_widget(Paragraph::new(lines), inner.inner(ratatui::layout::Margin::new(1, 0)));
        return;
    }

    let th = app.thresholds();
    let wide = area.width >= 118;
    let medium = area.width >= 92;
    let local = app.is_local();
    let my_session = app.session.clone();
    let spark_w = if wide { (area.width as usize).saturating_sub(118).clamp(10, 60) } else if medium { 10 } else { 0 };

    let mut header = vec!["", "Name", "Address", "Run", "Cur", "Avg"];
    let mut widths = vec![
        Constraint::Length(1),
        Constraint::Fill(2),
        Constraint::Fill(2),
        Constraint::Length(6),
        Constraint::Length(7),
        Constraint::Length(7),
    ];
    if wide {
        header.extend(["Min", "Max"]);
        widths.extend([Constraint::Length(7), Constraint::Length(7)]);
    }
    header.extend(["Jitter", "Loss%"]);
    widths.extend([Constraint::Length(7), Constraint::Length(6)]);
    if medium {
        header.push("MOS");
        widths.push(Constraint::Length(4));
    }
    if spark_w > 0 {
        header.push("Trend");
        widths.push(Constraint::Length(spark_w as u16));
    }

    let rows: Vec<Row> = app
        .targets()
        .iter()
        .map(|t| {
            let s = &t.stats;
            let paused = !t.target.enabled;
            let worst = th.latency(s.avg_ms).max(th.loss(s.loss_pct, s.sent));
            let dot = if paused {
                Span::styled("◦", Style::new().fg(Color::DarkGray))
            } else if t.live.error.is_some() && s.received == 0 {
                Span::styled("!", Style::new().fg(Color::Red).bold())
            } else {
                Span::styled("●", Style::new().fg(level_color(worst)))
            };
            let addr = match &t.live.ip {
                Some(ip) if ip != &t.target.host => format!("{} ({ip})", t.target.host),
                _ => t.target.host.clone(),
            };
            let (run, run_style) = if paused {
                ("paused", Style::new().fg(Color::DarkGray))
            } else if local {
                ("on", Style::new().fg(Color::Green))
            } else if t.target.share_id.is_some() {
                ("link", Style::new().fg(Color::Magenta))
            } else if t.target.is_background() {
                ("bg", Style::new().fg(ACCENT))
            } else if t.target.session == my_session {
                ("tui", Style::new().fg(Color::White))
            } else {
                ("other", Style::new().fg(Color::Gray))
            };
            let mut cells = vec![
                Cell::from(dot),
                Cell::from(t.target.name.clone()),
                Cell::from(Span::styled(addr, Style::new().fg(Color::Gray))),
                Cell::from(Span::styled(run, run_style)),
                latency_cell(s.cur_ms, th, true),
                latency_cell(s.avg_ms, th, true),
            ];
            if wide {
                cells.push(latency_cell(s.min_ms, th, false));
                cells.push(latency_cell(s.max_ms, th, false));
            }
            cells.push(latency_cell(s.jitter_ms, th, false));
            cells.push(loss_cell(s, th));
            if medium {
                cells.push(right(s.mos.map(|m| format!("{m:.1}")).unwrap_or("—".into())));
            }
            if spark_w > 0 {
                cells.push(Cell::from(sparkline(&t.spark, &t.spark_loss, spark_w, th)));
            }
            let row = Row::new(cells);
            if paused { row.style(Style::new().fg(Color::DarkGray)) } else { row }
        })
        .collect();

    let table = Table::new(rows, widths)
        .header(Row::new(header.into_iter().map(Cell::from)).style(Style::new().fg(Color::Gray).bold()))
        .block(b)
        .column_spacing(1)
        .row_highlight_style(if focused {
            Style::new().bg(Color::Rgb(40, 52, 70)).add_modifier(Modifier::BOLD)
        } else {
            Style::new().bg(Color::Rgb(36, 36, 40))
        });
    let mut state = TableState::default().with_selected(Some(app.selected)).with_offset(app.targets_offset);
    f.render_stateful_widget(table, area, &mut state);
    app.targets_offset = state.offset();
}

fn draw_hops(f: &mut Frame, area: Rect, app: &mut App) {
    let focused = app.focus == Focus::Hops && app.popup.is_none();
    let th = app.thresholds();
    let Some(d) = &app.detail else {
        f.render_widget(block(Line::from(" Route "), focused), area);
        return;
    };
    let dest = d.hops.iter().find(|h| h.is_dest);
    let mut title = vec![Span::styled(" Route ", Style::new().bold()), Span::raw(format!("to {} ", d.target.name))];
    match (dest, d.live.hop_count) {
        (Some(h), _) => title.push(Span::styled(format!("· {} hops ", h.ttl), Style::new().fg(Color::Gray))),
        (None, _) if !d.hops.is_empty() => {
            title.push(Span::styled("· destination not reached ", Style::new().fg(Color::Yellow)))
        }
        _ => {}
    }
    let b = block(Line::from(title), focused);
    if d.hops.is_empty() {
        let inner = b.inner(area);
        f.render_widget(b, area);
        f.render_widget(Paragraph::new(Span::styled(" Tracing route…", Style::new().fg(Color::Gray))), inner);
        return;
    }
    let wide = area.width >= 110;
    let mut maxes: Vec<f64> = d.hops.iter().filter_map(|h| h.stats.max_ms).collect();
    let scale = nice_ceil(percentile(&mut maxes, 90.0).unwrap_or(1.0).max(0.5));
    let gauge_w = (area.width as usize).saturating_sub(if wide { 108 } else { 70 }).clamp(8, 50);

    let mut header = vec!["#", "Address", "Hostname", "Loss%", "Sent", "Cur", "Avg"];
    let mut widths = vec![
        Constraint::Length(3),
        Constraint::Length(19),
        Constraint::Fill(1),
        Constraint::Length(6),
        Constraint::Length(6),
        Constraint::Length(7),
        Constraint::Length(7),
    ];
    if wide {
        header.extend(["Min", "Max", "Jitter"]);
        widths.extend([Constraint::Length(7), Constraint::Length(7), Constraint::Length(7)]);
    }
    header.push("Latency (0–");
    widths.push(Constraint::Length(gauge_w as u16));
    let gauge_header = format!("Latency 0–{} ms", if scale < 10.0 { format!("{scale}") } else { format!("{scale:.0}") });

    let rows: Vec<Row> = d
        .hops
        .iter()
        .map(|h| {
            let s = &h.stats;
            let mut addr = h.addr.clone().unwrap_or_else(|| "*".into());
            if h.responders > 1 {
                addr = format!("{addr} +{}", h.responders - 1);
            }
            let mut cells = vec![
                right(h.ttl.to_string()),
                Cell::from(addr),
                hop_name_cell(h),
                hop_loss_cell(h, th),
                right(s.sent.to_string()),
                latency_cell(s.cur_ms, th, true),
                latency_cell(s.avg_ms, th, true),
            ];
            if wide {
                cells.push(latency_cell(s.min_ms, th, false));
                cells.push(latency_cell(s.max_ms, th, false));
                cells.push(latency_cell(s.jitter_ms, th, false));
            }
            cells.push(Cell::from(range_gauge(s.min_ms, s.avg_ms, s.max_ms, scale, gauge_w, th)));
            let row = Row::new(cells);
            if h.is_dest { row.style(Style::new().bold()) } else { row }
        })
        .collect();
    let header_cells: Vec<Cell> = header
        .iter()
        .map(|h| if h.starts_with("Latency") { Cell::from(gauge_header.clone()) } else { Cell::from(*h) })
        .collect();
    let table = Table::new(rows, widths)
        .header(Row::new(header_cells).style(Style::new().fg(Color::Gray).bold()))
        .block(b)
        .column_spacing(1)
        .row_highlight_style(if focused { Style::new().bg(Color::Rgb(40, 52, 70)) } else { Style::new() });
    let mut state = TableState::default().with_selected(if focused { Some(app.hop_selected) } else { None });
    f.render_stateful_widget(table, area, &mut state);
}

fn draw_timeline(f: &mut Frame, area: Rect, app: &mut App) {
    let th = app.thresholds();
    let mut name = app.selected_target().map(|t| t.target.name.clone()).unwrap_or_default();
    let mut hop_hint = false;
    if let Some(d) = &app.detail {
        if let Some(ttl) = d.hop {
            let addr = d.hops.iter().find(|h| h.ttl == ttl).and_then(|h| h.addr.clone()).unwrap_or_else(|| "*".into());
            name = format!("hop {ttl} ({addr})");
            hop_hint = true;
        }
    }
    let mut title_spans = vec![
        Span::styled(" Latency ", Style::new().bold()),
        Span::raw(if name.is_empty() { String::new() } else { format!("to {name} ") }),
        Span::styled(format!("· {} ", WINDOWS[app.window].1), Style::new().fg(Color::Gray)),
    ];
    if let Some(d) = &app.detail {
        let what = match d.timeline.mode {
            crate::model::TimelineMode::Samples => format!("· every sample ({}) ", crate::report::interval_range(&d.timeline)),
            crate::model::TimelineMode::Slices => format!("· {} slices ", crate::report::fmt_span(d.timeline.step_ms)),
        };
        title_spans.push(Span::styled(what, Style::new().fg(Color::Gray)));
    }
    if hop_hint {
        title_spans.push(Span::styled("· Esc for destination ", Style::new().fg(Color::Yellow)));
    }
    let title = Line::from(title_spans);
    let legend = Line::from(vec![
        Span::styled(" █", Style::new().fg(Color::Green)),
        Span::styled(" avg ", Style::new().fg(Color::Gray)),
        Span::styled("▴", Style::new().fg(Color::Gray)),
        Span::styled(" spike off-scale ", Style::new().fg(Color::Gray)),
        Span::styled("▼", Style::new().fg(Color::Red)),
        Span::styled(" loss ", Style::new().fg(Color::Gray)),
    ])
    .alignment(Alignment::Right);
    let b = block(title, false).title(legend);
    let inner = b.inner(area);
    f.render_widget(b, area);
    if inner.height < 3 {
        return;
    }
    app.timeline_buckets = inner.width.saturating_sub(8).max(10) as usize;
    let Some(d) = &app.detail else {
        let msg = if app.targets().is_empty() { "" } else { " Loading…" };
        f.render_widget(Paragraph::new(Span::styled(msg, Style::new().fg(Color::Gray))), inner);
        return;
    };
    let [stats_area, chart_area] = Layout::vertical([Constraint::Length(1), Constraint::Fill(1)]).areas(inner);
    let s = &d.stats;
    let mut spans = vec![Span::raw(" ")];
    let mut stat = |label: &str, value: String, style: Style| {
        spans.push(Span::styled(format!("{label} "), Style::new().fg(Color::Gray)));
        spans.push(Span::styled(value, style));
        spans.push(Span::raw("   "));
    };
    if let Some(err) = &d.live.error {
        stat("error", err.clone(), Style::new().fg(Color::Red));
    }
    if s.sent == 0 {
        stat("", "no samples in this range".into(), Style::new().fg(Color::Gray));
    } else {
        stat("avg", format!("{} ms", fmt_ms(s.avg_ms)), Style::new().fg(level_color(th.latency(s.avg_ms))).bold());
        stat("min", fmt_ms(s.min_ms), Style::new());
        stat("max", fmt_ms(s.max_ms), Style::new());
        stat("p95", fmt_ms(s.p95_ms), Style::new());
        stat("jitter", fmt_ms(s.jitter_ms), Style::new());
        let ll = th.loss(s.loss_pct, s.sent);
        stat(
            "loss",
            format!("{}% of {}", fmt_pct(s.loss_pct), s.sent),
            if ll == Level::Good { Style::new() } else { Style::new().fg(level_color(ll)) },
        );
        if let Some(m) = s.mos {
            stat("MOS", format!("{m:.2}"), Style::new());
        }
    }
    f.render_widget(Line::from(spans), stats_area);
    f.render_widget(TimelineChart { timeline: &d.timeline, th }, chart_area);
}

// ----- popups ---------------------------------------------------------------

fn centered(w: u16, h: u16, area: Rect) -> Rect {
    let w = w.min(area.width.saturating_sub(2));
    let h = h.min(area.height.saturating_sub(2));
    Rect { x: area.x + (area.width - w) / 2, y: area.y + (area.height - h) / 2, width: w, height: h }
}

fn popup_block(title: &str) -> Block<'static> {
    Block::new()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(ACCENT))
        .title(Span::styled(format!(" {title} "), Style::new().bold()))
        .style(Style::new().bg(Color::Rgb(22, 24, 30)))
}

fn key(k: &str) -> Span<'static> {
    Span::styled(k.to_string(), Style::new().fg(ACCENT).bold())
}

/// Greedy word wrap for short fixed texts.
fn wrap_words(text: &str, width: usize) -> Vec<String> {
    let width = width.max(20);
    let mut out = Vec::new();
    let mut cur = String::new();
    for word in text.split_whitespace() {
        if !cur.is_empty() && cur.chars().count() + 1 + word.chars().count() > width {
            out.push(std::mem::take(&mut cur));
        }
        if !cur.is_empty() {
            cur.push(' ');
        }
        cur.push_str(word);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn hint(parts: &[(&str, &str)]) -> Line<'static> {
    let mut spans = Vec::new();
    for (k, l) in parts {
        spans.push(key(k));
        spans.push(Span::styled(format!(" {l}   "), Style::new().fg(Color::Gray)));
    }
    Line::from(spans)
}

fn field_label(label: &str, focused: bool) -> Span<'static> {
    let style = if focused { Style::new().fg(ACCENT).bold() } else { Style::new().fg(Color::Gray) };
    Span::styled(format!("{}{label:<14}", if focused { "› " } else { "  " }), style)
}

fn checkbox(label: &str, on: bool, focused: bool) -> Line<'static> {
    Line::from(vec![
        field_label("", focused),
        Span::styled(if on { "[x] " } else { "[ ] " }, if focused { Style::new().fg(ACCENT).bold() } else { Style::new() }),
        Span::raw(label.to_string()),
    ])
}

fn choices(opts: &[String], selected: usize, focused: bool) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    for (i, o) in opts.iter().enumerate() {
        let style = if i == selected {
            if focused { Style::new().fg(Color::Black).bg(ACCENT).bold() } else { Style::new().reversed() }
        } else {
            Style::new().fg(Color::Gray)
        };
        spans.push(Span::styled(format!(" {o} "), style));
        spans.push(Span::raw(" "));
    }
    spans
}

pub fn web_urls(app: &App) -> Vec<String> {
    match &app.mode {
        Mode::Local { url, .. } => vec![url.clone()],
        Mode::Service { url, listen, .. } => {
            let port = listen.rsplit(':').next().unwrap_or("8040");
            let host = listen.rsplit_once(':').map(|(h, _)| h).unwrap_or("0.0.0.0");
            let is_local_url = url.contains("127.0.0.1") || url.contains("localhost");
            if !is_local_url {
                vec![url.clone()]
            } else if host == "0.0.0.0" || host == "[::]" || host == "::" {
                let mut v = Vec::new();
                if let Some(ip) = util::lan_ip() {
                    v.push(format!("https://{ip}:{port}"));
                }
                v.push(format!("https://localhost:{port}"));
                v
            } else {
                vec![format!("https://{host}:{port}")]
            }
        }
    }
}

fn draw_popup(f: &mut Frame, area: Rect, app: &App) {
    let Some(p) = &app.popup else { return };
    match p {
        Popup::Help => {
            let r = centered(72, 27, area);
            f.render_widget(Clear, r);
            let rows: &[(&str, &str)] = &[
                ("↑ ↓  j k", "select a target (or a hop after Tab)"),
                ("Tab", "switch to the route; ↑ ↓ then graphs that hop"),
                ("a", "add a target"),
                ("e / Enter", "edit the selected target"),
                ("d / Del", "remove the target and its history"),
                ("space / p", "pause or resume"),
                ("b", "toggle background: keep running after you quit"),
                ("B", "move all of this TUI's targets to the background"),
                ("[  ]", "shorter / longer time window (1 min … 30 days)"),
                ("← →  h l", "scroll back / forward in time"),
                ("End", "jump back to live"),
                ("x", "export a PDF/PNG report"),
                ("w", "web UI address and password"),
                ("P", "set the web UI password"),
                ("i", "about pingrail (version, licence)"),
                ("r", "refresh now"),
                ("q", "quit"),
            ];
            let mut lines: Vec<Line> = rows
                .iter()
                .map(|(k, d)| Line::from(vec![Span::styled(format!("  {k:<12}"), Style::new().fg(ACCENT).bold()), Span::raw(d.to_string())]))
                .collect();
            lines.push(Line::default());
            let w = r.width.saturating_sub(6) as usize;
            for text in [
                "Colours: green / amber / red by latency and loss thresholds (edit them in pingrail.toml).",
                "Run: tui = stops when you quit · bg = runs in the background service · link = added through a share link.",
            ] {
                for l in wrap_words(text, w) {
                    lines.push(Line::from(Span::styled(format!("  {l}"), Style::new().fg(Color::Gray))));
                }
            }
            lines.push(Line::default());
            lines.push(hint(&[("Esc", "close")]));
            f.render_widget(Paragraph::new(lines).block(popup_block("Keys")), r);
        }
        Popup::Message { title, body, .. } => {
            let lines = body.lines().count() as u16;
            let r = centered(76, lines + 6, area);
            f.render_widget(Clear, r);
            let mut t = Text::from(body.clone());
            t.lines.push(Line::default());
            t.lines.push(hint(&[("Enter", "close")]));
            f.render_widget(Paragraph::new(t).wrap(Wrap { trim: false }).block(popup_block(title)), r.inner(ratatui::layout::Margin::new(0, 0)));
        }
        Popup::ConfirmDelete { name, .. } => {
            let r = centered(60, 7, area);
            f.render_widget(Clear, r);
            let lines = vec![
                Line::from(vec![Span::raw("Remove "), Span::styled(name.clone(), Style::new().bold()), Span::raw(" and all its history?")]),
                Line::default(),
                hint(&[("y", "remove"), ("n / Esc", "keep")]),
            ];
            f.render_widget(Paragraph::new(lines).block(popup_block("Remove target")), r);
        }
        Popup::Quit { foreground } => {
            let local = app.is_local();
            let r = centered(74, if local { 10 } else { 9 }, area);
            f.render_widget(Clear, r);
            let lines = if local {
                vec![
                    Line::from(format!("{foreground} target(s) are being monitored by this local session.")),
                    Line::from("Monitoring stops when you quit, because the background service isn't running."),
                    Line::default(),
                    Line::from(Span::styled(crate::service::start_hint(), Style::new().fg(Color::Gray))),
                    Line::default(),
                    hint(&[("q", "quit"), ("Esc", "cancel")]),
                ]
            } else {
                vec![
                    Line::from(format!("{foreground} target(s) run in the foreground of this TUI.")),
                    Line::default(),
                    Line::from(vec![key("k"), Span::raw("  keep them running in the background (see them in the web UI)")]),
                    Line::from(vec![key("s"), Span::raw("  stop them and quit")]),
                    Line::from(vec![key("Esc"), Span::raw(" cancel")]),
                ]
            };
            f.render_widget(Paragraph::new(lines).block(popup_block("Quit")), r);
        }
        Popup::About => {
            use crate::server::about;
            let r = centered(76, 20, area);
            f.render_widget(Clear, r);
            let w = r.width.saturating_sub(4) as usize;
            let gray = Style::new().fg(Color::Gray);
            let mut lines = vec![
                Line::from(vec![
                    Span::styled(format!("  {} ", about::NAME), Style::new().fg(ACCENT).bold()),
                    Span::raw(format!("{}  ·  {}", about::VERSION, about::PUBLISHER)),
                ]),
                Line::from(Span::raw(format!("  {}", about::COPYRIGHT))),
                Line::from(Span::raw(format!("  Licence: {} (Apache License, version 2.0)", about::LICENSE))),
                Line::from(Span::raw(format!("  Questions and bug reports: {}", about::CONTACT))),
                Line::default(),
            ];
            for l in wrap_words(about::WARRANTY, w.saturating_sub(2)) {
                lines.push(Line::from(Span::styled(format!("  {l}"), gray)));
            }
            lines.push(Line::default());
            for l in wrap_words(about::TRADEMARK, w.saturating_sub(2)) {
                lines.push(Line::from(Span::styled(format!("  {l}"), gray)));
            }
            lines.push(Line::default());
            for l in wrap_words(
                "Full licence and third-party notices: LICENSE and THIRD-PARTY-NOTICES.txt beside the program, \
                 `pingrail about --license`, or About in the web UI menu.",
                w.saturating_sub(2),
            ) {
                lines.push(Line::from(Span::styled(format!("  {l}"), gray)));
            }
            lines.push(Line::default());
            lines.push(hint(&[("Esc", "close")]));
            f.render_widget(Paragraph::new(lines).block(popup_block("About")), r);
        }
        Popup::Web => {
            let r = centered(78, 17, area);
            f.render_widget(Clear, r);
            let mut lines = vec![Line::from(if app.is_local() {
                "Web UI for this local session (this machine only, while the TUI is open):"
            } else {
                "Open the web UI from a browser:"
            })];
            for u in web_urls(app) {
                lines.push(Line::from(vec![Span::raw("   "), Span::styled(u, Style::new().fg(ACCENT).underlined())]));
            }
            if let Mode::Service { listen, .. } = &app.mode
                && listen.starts_with("127.") {
                    lines.push(Line::from(Span::styled(
                        "   (this machine only; for LAN access set web.listen = \"0.0.0.0:8040\")",
                        Style::new().fg(Color::Yellow),
                    )));
                }
            lines.push(Line::default());
            if app.has_password {
                lines.push(Line::from(vec![Span::raw("Password: "), Span::styled("set", Style::new().fg(Color::Green)), Span::raw("  (username: admin)")]));
            } else {
                lines.push(Line::from(vec![Span::raw("Password: "), Span::styled("not set yet", Style::new().fg(Color::Yellow)), Span::raw(" — set one to log in from a browser")]));
            }
            let cert = match &app.mode {
                Mode::Service { cert, .. } | Mode::Local { cert, .. } => cert.as_str(),
            };
            if !cert.is_empty() {
                lines.push(Line::default());
                lines.push(Line::from(Span::styled(
                    "Fingerprint to trust (SHA-256), for phones, browsers and `pingrail trust`:",
                    Style::new().fg(Color::Gray),
                )));
                // 32 pairs: two lines of 16.
                let half = cert.len().min(48);
                for part in [&cert[..half], &cert[half..]] {
                    let part = part.trim_matches(':');
                    if !part.is_empty() {
                        lines.push(Line::from(Span::raw(format!("   {part}"))));
                    }
                }
            }
            lines.push(Line::default());
            lines.push(hint(&[("p", "set password"), ("o", "open in browser"), ("Esc", "close")]));
            f.render_widget(Paragraph::new(lines).block(popup_block("Web UI")), r);
        }
        Popup::Target(form) => draw_target_form(f, area, app, form),
        Popup::Export(form) => draw_export_form(f, area, app, form),
        Popup::Password(form) => {
            let r = centered(74, if form.first_run { 11 } else { 10 }, area);
            f.render_widget(Clear, r);
            let iw = r.width.saturating_sub(22) as usize;
            let mut lines = vec![Line::from("Password for the web UI (username: admin)")];
            if form.first_run {
                lines.push(Line::from(Span::styled(
                    "Set it now so you can log in from a browser, or press Esc to skip.",
                    Style::new().fg(Color::Gray),
                )));
            }
            lines.push(Line::default());
            lines.push(Line::from(vec![field_label("New password", form.field == 0), Span::raw(" ")]).patch_input(form.p1.line(iw, form.field == 0, "at least 8 characters")));
            lines.push(Line::from(vec![field_label("Repeat", form.field == 1), Span::raw(" ")]).patch_input(form.p2.line(iw, form.field == 1, "")));
            lines.push(status_line(&form.error, form.busy, "Saving…"));
            lines.push(hint(&[("Enter", "save"), ("Tab", "next"), ("Esc", if form.first_run { "skip" } else { "cancel" })]));
            f.render_widget(Paragraph::new(lines).block(popup_block("Web UI password")), r);
        }
        Popup::Login(form) => {
            let r = centered(70, 11, area);
            f.render_widget(Clear, r);
            let iw = r.width.saturating_sub(22) as usize;
            let url = match &app.mode {
                Mode::Service { url, .. } => url.clone(),
                Mode::Local { url, .. } => url.clone(),
            };
            let lines = vec![
                Line::from(format!("Log in to the pingrail service at {url}")),
                Line::default(),
                Line::from(vec![field_label("Username", form.field == 0), Span::raw(" ")]).patch_input(form.user.line(iw, form.field == 0, "")),
                Line::from(vec![field_label("Password", form.field == 1), Span::raw(" ")]).patch_input(form.pass.line(iw, form.field == 1, "")),
                status_line(&form.error, form.busy, "Logging in…"),
                Line::from(Span::styled("No password yet? On the service machine run: sudo pingrail passwd", Style::new().fg(Color::Gray))),
                hint(&[("Enter", "log in"), ("Tab", "next"), ("Esc", "quit")]),
            ];
            f.render_widget(Paragraph::new(lines).block(popup_block("Log in")), r);
        }
    }
}

trait PatchInput {
    fn patch_input(self, input: Line<'static>) -> Line<'static>;
}

impl PatchInput for Line<'static> {
    fn patch_input(mut self, input: Line<'static>) -> Line<'static> {
        self.spans.extend(input.spans);
        self
    }
}

fn status_line(err: &Option<String>, busy: bool, busy_text: &str) -> Line<'static> {
    if busy {
        Line::from(Span::styled(format!("  {busy_text}"), Style::new().fg(Color::Yellow)))
    } else if let Some(e) = err {
        Line::from(Span::styled(format!("  {e}"), Style::new().fg(Color::Red)))
    } else {
        Line::default()
    }
}

fn draw_target_form(f: &mut Frame, area: Rect, app: &App, form: &TargetForm) {
    let r = centered(72, 13, area);
    f.render_widget(Clear, r);
    let iw = r.width.saturating_sub(22) as usize;
    let title = if form.editing.is_some() { "Edit target" } else { "Add target" };
    let host_line = if form.editing.is_some() {
        Line::from(vec![field_label("Host / IP", false), Span::raw(" "), Span::styled(form.host.value.clone(), Style::new().fg(Color::Gray))])
    } else {
        Line::from(vec![field_label("Host / IP", form.field == 0), Span::raw(" ")]).patch_input(form.host.line(iw, form.field == 0, "e.g. 8.8.8.8 or vpn.example.com"))
    };
    let bg_line = if app.is_local() {
        Line::from(vec![field_label("", form.field == 4), Span::styled("Local session: runs while this TUI is open", Style::new().fg(Color::DarkGray))])
    } else {
        checkbox("Keep running in the background after I quit", form.background, form.field == 4)
    };
    let lines = vec![
        Line::default(),
        host_line,
        Line::from(vec![field_label("Name", form.field == 1), Span::raw(" ")]).patch_input(form.name.line(iw, form.field == 1, "optional")),
        Line::from(vec![field_label("Interval (s)", form.field == 2), Span::raw(" ")]).patch_input(form.interval.line(10, form.field == 2, "2.5")),
        checkbox("Trace the route (per-hop statistics)", form.trace, form.field == 3),
        bg_line,
        Line::default(),
        status_line(&form.error, form.busy, if form.editing.is_some() { "Saving…" } else { "Checking host…" }),
        hint(&[("Enter", "save"), ("Tab", "next field"), ("Space", "toggle"), ("Esc", "cancel")]),
    ];
    f.render_widget(Paragraph::new(lines).block(popup_block(title)), r);
}

fn draw_export_form(f: &mut Frame, area: Rect, app: &App, form: &ExportForm) {
    let r = centered(84, 15, area);
    f.render_widget(Clear, r);
    let iw = r.width.saturating_sub(22) as usize;
    let custom = form.range == RANGE_CHOICES.len() - 1;
    let ranges: Vec<String> = RANGE_CHOICES
        .iter()
        .enumerate()
        .map(|(i, c)| if i == 0 { format!("{c} ({})", WINDOWS[app.window].1) } else { c.to_string() })
        .collect();
    let sel_name = app.selected_target().map(|t| t.target.name.clone()).unwrap_or_else(|| "none".into());
    let scope = vec![format!("Selected: {sel_name}"), format!("All {} targets", app.targets().len())];
    let formats: Vec<String> = FORMAT_CHOICES.iter().map(|s| s.to_string()).collect();
    let dim = Style::new().fg(Color::DarkGray);
    let time_line = |label: &str, idx: usize, input: &Input| {
        if custom {
            Line::from(vec![field_label(label, form.field == idx), Span::raw(" ")]).patch_input(input.line(20, form.field == idx, "YYYY-MM-DD HH:MM"))
        } else {
            Line::from(vec![Span::styled(format!("  {label:<14} "), dim), Span::styled(input.value.clone(), dim)])
        }
    };
    let mut range_line = vec![field_label("Time range", form.field == 0), Span::raw(" ")];
    range_line.extend(choices(&ranges, form.range, form.field == 0));
    let mut scope_line = vec![field_label("Targets", form.field == 3), Span::raw(" ")];
    scope_line.extend(choices(&scope, form.all as usize, form.field == 3));
    let mut fmt_line = vec![field_label("Format", form.field == 4), Span::raw(" ")];
    fmt_line.extend(choices(&formats, form.format, form.field == 4));
    let lines = vec![
        Line::default(),
        Line::from(range_line),
        time_line("From", 1, &form.from),
        time_line("To", 2, &form.to),
        Line::from(scope_line),
        Line::from(fmt_line),
        Line::from(vec![field_label("Save in", form.field == 5), Span::raw(" ")]).patch_input(form.dir.line(iw, form.field == 5, "")),
        Line::default(),
        status_line(&form.error, form.busy, "Generating report…"),
        Line::from(Span::styled("  Times are local. Choose Custom to type an exact range.", Style::new().fg(Color::Gray))),
        hint(&[("Enter", "export"), ("Tab", "next"), ("← →", "change option"), ("Esc", "cancel")]),
    ];
    f.render_widget(Paragraph::new(lines).block(popup_block("Export report")), r);
}
