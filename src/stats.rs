//! Latency statistics: loss, min/avg/max, jitter, percentiles and MOS.

use crate::model::{Bucket, Point, Stats, Timeline, TimelineMode};
use crate::store::Sample;

/// Compute statistics over samples in time order. `None` is a lost sample;
/// `Some(ms)` is a reply with that round-trip time.
pub fn compute<I: IntoIterator<Item = Option<f64>>>(samples: I) -> Stats {
    let mut c = Computing::default();
    for s in samples {
        c.push(s);
    }
    c.finish()
}

/// [`compute`], one sample at a time. Keeps 4 bytes per reply (for the 95th
/// percentile) and nothing else.
#[derive(Default)]
pub struct Computing {
    run: Running,
    /// Replies in whole microseconds, which is how they are measured.
    values: Vec<u32>,
}

impl Computing {
    pub fn push(&mut self, s: Option<f64>) {
        self.run.push(s);
        if let Some(v) = s {
            self.values.push((v * 1000.0).round().clamp(0.0, u32::MAX as f64) as u32);
        }
    }

    pub fn finish(mut self) -> Stats {
        let mut stats = self.run.finish();
        if !self.values.is_empty() {
            let rank = (0.95 * self.values.len() as f64).ceil() as usize;
            let idx = rank.clamp(1, self.values.len()) - 1;
            let (_, v, _) = self.values.select_nth_unstable(idx);
            stats.p95_ms = Some(*v as f64 / 1000.0);
        }
        stats
    }
}

/// Running statistics without keeping every value (no percentile): for
/// per-hop figures over long windows.
#[derive(Debug, Clone, Copy)]
pub struct Running {
    sent: u32,
    received: u32,
    min: f64,
    max: f64,
    sum: f64,
    sumsq: f64,
    prev: Option<f64>,
    jitter_sum: f64,
    jitter_n: u32,
    last: Option<f64>,
}

impl Default for Running {
    fn default() -> Self {
        Running {
            sent: 0,
            received: 0,
            min: f64::INFINITY,
            max: f64::NEG_INFINITY,
            sum: 0.0,
            sumsq: 0.0,
            prev: None,
            jitter_sum: 0.0,
            jitter_n: 0,
            last: None,
        }
    }
}

impl Running {
    pub fn push(&mut self, s: Option<f64>) {
        self.sent += 1;
        self.last = s;
        if let Some(v) = s {
            self.received += 1;
            self.min = self.min.min(v);
            self.max = self.max.max(v);
            self.sum += v;
            self.sumsq += v * v;
            if let Some(p) = self.prev {
                self.jitter_sum += (v - p).abs();
                self.jitter_n += 1;
            }
            self.prev = Some(v);
        }
    }

    pub fn finish(&self) -> Stats {
        if self.sent == 0 {
            return Stats::default();
        }
        let loss_pct = 100.0 * (self.sent - self.received) as f64 / self.sent as f64;
        if self.received == 0 {
            return Stats { sent: self.sent, received: 0, loss_pct, ..Stats::default() };
        }
        let n = self.received as f64;
        let avg = self.sum / n;
        let var = (self.sumsq / n - avg * avg).max(0.0);
        let jitter = if self.jitter_n > 0 { self.jitter_sum / self.jitter_n as f64 } else { 0.0 };
        Stats {
            sent: self.sent,
            received: self.received,
            loss_pct,
            cur_ms: self.last,
            min_ms: Some(self.min),
            avg_ms: Some(avg),
            max_ms: Some(self.max),
            stddev_ms: Some(var.sqrt()),
            jitter_ms: Some(jitter),
            p95_ms: None,
            mos: Some(mos(avg, jitter, loss_pct)),
        }
    }
}

/// Nearest-rank percentile; reorders `values`.
pub fn percentile(values: &mut [f64], pct: f64) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let rank = ((pct / 100.0) * values.len() as f64).ceil() as usize;
    let idx = rank.clamp(1, values.len()) - 1;
    let (_, v, _) = values.select_nth_unstable_by(idx, |a, b| a.total_cmp(b));
    Some(*v)
}

/// Estimate a Mean Opinion Score (1.0–4.5) from latency, jitter and loss using
/// the simplified ITU-T G.107 E-model commonly used by network monitoring tools.
pub fn mos(avg_ms: f64, jitter_ms: f64, loss_pct: f64) -> f64 {
    let effective = avg_ms + jitter_ms * 2.0 + 10.0;
    let mut r = if effective < 160.0 {
        93.2 - effective / 40.0
    } else {
        93.2 - (effective - 120.0) / 10.0
    };
    r -= loss_pct * 2.5;
    let r = r.clamp(0.0, 100.0);
    let m = 1.0 + 0.035 * r + 0.000007 * r * (r - 60.0) * (100.0 - r);
    m.clamp(1.0, 4.5)
}

/// Split `[from, to)` into `n` equal buckets and aggregate samples into them.
/// `rows` must be sorted by timestamp; each is `(ts_ms, rtt_ms)`.
#[cfg(test)]
pub fn bucketize(rows: &[(i64, Option<f64>)], from: i64, to: i64, n: usize) -> (i64, Vec<Bucket>) {
    let mut b = Buckets::new(from, to, n);
    for &(ts, rtt) in rows {
        b.push(ts, rtt);
    }
    b.finish()
}

/// `[from, to)` split into `n` equal buckets, filled one sample at a time.
pub struct Buckets {
    from: i64,
    to: i64,
    width: i64,
    buckets: Vec<Bucket>,
    sums: Vec<f64>,
}

impl Buckets {
    pub fn new(from: i64, to: i64, n: usize) -> Buckets {
        let n = n.max(1);
        let span = (to - from).max(1);
        let width = ((span as f64) / n as f64).ceil().max(1.0) as i64;
        let buckets = (0..n).map(|i| Bucket { t_ms: from + i as i64 * width, ..Bucket::default() }).collect();
        Buckets { from, to, width, buckets, sums: vec![0.0; n] }
    }

    pub fn push(&mut self, ts: i64, rtt: Option<f64>) {
        if ts < self.from || ts >= self.to {
            return;
        }
        let idx = (((ts - self.from) / self.width) as usize).min(self.buckets.len() - 1);
        let b = &mut self.buckets[idx];
        b.sent += 1;
        match rtt {
            None => b.lost += 1,
            Some(v) => {
                self.sums[idx] += v;
                b.min_ms = Some(b.min_ms.map_or(v, |m| m.min(v)));
                b.max_ms = Some(b.max_ms.map_or(v, |m| m.max(v)));
            }
        }
    }

    /// The bucket width and the buckets.
    pub fn finish(mut self) -> (i64, Vec<Bucket>) {
        for (b, s) in self.buckets.iter_mut().zip(self.sums) {
            let got = b.sent - b.lost;
            if got > 0 {
                b.avg_ms = Some(s / got as f64);
            }
        }
        (self.width, self.buckets)
    }
}

/// Slice lengths the timeline may use, so neighbouring views and visitors
/// share the same slices.
pub const SLICE_LADDER_MS: [i64; 18] = [
    1_000, 2_000, 5_000, 10_000, 15_000, 30_000, 60_000, 120_000, 300_000, 600_000, 900_000,
    1_800_000, 3_600_000, 7_200_000, 10_800_000, 21_600_000, 43_200_000, 86_400_000,
];

/// A gap is longer than this many intervals without a sample.
const GAP_INTERVALS: f64 = 2.5;
/// The newest sample can lag "now" by up to a probe timeout plus the
/// writer's batching; don't call that a gap.
const TAIL_SLACK_MS: i64 = 3_500;

/// Build the timeline for `[from, to)` from samples in time order.
///
/// When every sample fits (at most `max_points`), each sample is a point.
/// Otherwise samples are grouped into clock-aligned slices from
/// [`SLICE_LADDER_MS`], never shorter than two sample intervals, so every
/// slice holds samples and the same slices are produced on every refresh.
/// Gaps come from the interval each sample was taken at, so a change of
/// interval (or samples at 1 s next to samples at 60 s) never looks like
/// missing data.
pub fn timeline(samples: &[Sample], from: i64, to: i64, max_points: usize, default_iv: u32) -> Timeline {
    let max_points = max_points.clamp(10, 4000);
    let iv_of = |s: &Sample| s.interval_ms().unwrap_or(default_iv).max(1) as i64;
    let (typical, iv_min, iv_max) = {
        // The median interval, by counting how many samples used each (a
        // target has a handful of intervals over its life, not millions).
        let mut counts: std::collections::BTreeMap<i64, usize> = std::collections::BTreeMap::new();
        let mut run: Option<(i64, usize)> = None;
        for s in samples {
            let iv = iv_of(s);
            match &mut run {
                Some((last, n)) if *last == iv => *n += 1,
                run => {
                    if let Some((last, n)) = run.replace((iv, 1)) {
                        *counts.entry(last).or_default() += n;
                    }
                }
            }
        }
        if let Some((last, n)) = run {
            *counts.entry(last).or_default() += n;
        }
        match (counts.keys().next(), counts.keys().next_back()) {
            (Some(lo), Some(hi)) => {
                let mid = samples.len() / 2;
                let mut seen = 0;
                let median = counts.iter().find(|(_, n)| { seen += **n; seen > mid }).map_or(*hi, |(iv, _)| *iv);
                (median, *lo, *hi)
            }
            _ => {
                let d = default_iv.max(1) as i64;
                (d, d, d)
            }
        }
    };

    // Gaps, judged sample by sample.
    let mut gaps: Vec<[i64; 2]> = Vec::new();
    let mut gap_before = vec![false; samples.len()];
    match (samples.first(), samples.last()) {
        (Some(first), Some(last)) => {
            if (first.ts_ms - from) as f64 > GAP_INTERVALS * iv_of(first) as f64 {
                gaps.push([from, first.ts_ms]);
            }
            for i in 1..samples.len() {
                let (a, b) = (&samples[i - 1], &samples[i]);
                let allowed = GAP_INTERVALS * iv_of(a).max(iv_of(b)) as f64;
                if (b.ts_ms - a.ts_ms) as f64 > allowed {
                    gaps.push([a.ts_ms + iv_of(a), b.ts_ms]);
                    gap_before[i] = true;
                }
            }
            let iv = iv_of(last);
            if ((to - last.ts_ms) as f64) > GAP_INTERVALS * iv as f64 + TAIL_SLACK_MS as f64 {
                gaps.push([last.ts_ms + iv, to]);
            }
        }
        _ => gaps.push([from, to]),
    }

    let point = |s: &Sample, gap: bool| {
        let rtt = s.rtt_ms();
        Point { t_ms: s.ts_ms, sent: 1, lost: rtt.is_none() as u32, min_ms: rtt, avg_ms: rtt, max_ms: rtt, gap }
    };
    if samples.len() <= max_points {
        return Timeline {
            from_ms: from,
            to_ms: to,
            mode: TimelineMode::Samples,
            step_ms: typical,
            interval_ms: typical,
            interval_min_ms: iv_min,
            interval_max_ms: iv_max,
            points: samples.iter().zip(&gap_before).map(|(s, g)| point(s, *g)).collect(),
            gaps,
        };
    }

    let span = (to - from).max(1);
    let want = (span as f64 / max_points as f64).ceil() as i64;
    let floor = want.max(2 * typical);
    let step = SLICE_LADDER_MS
        .iter()
        .copied()
        .find(|s| *s >= floor)
        .unwrap_or_else(|| (floor + 3_599_999) / 3_600_000 * 3_600_000);

    let mut points: Vec<Point> = Vec::new();
    let mut sums: Vec<f64> = Vec::new();
    for (s, gap) in samples.iter().zip(&gap_before) {
        let start = s.ts_ms.div_euclid(step) * step;
        if points.last().is_none_or(|p| p.t_ms != start) {
            points.push(Point { t_ms: start, gap: *gap, ..Point::default() });
            sums.push(0.0);
        }
        let p = points.last_mut().expect("just pushed");
        let sum = sums.last_mut().expect("just pushed");
        p.sent += 1;
        match s.rtt_ms() {
            None => p.lost += 1,
            Some(v) => {
                *sum += v;
                p.min_ms = Some(p.min_ms.map_or(v, |m| m.min(v)));
                p.max_ms = Some(p.max_ms.map_or(v, |m| m.max(v)));
            }
        }
    }
    for (p, sum) in points.iter_mut().zip(sums) {
        let got = p.sent - p.lost;
        if got > 0 {
            p.avg_ms = Some(sum / got as f64);
        }
    }
    Timeline { from_ms: from, to_ms: to, mode: TimelineMode::Slices, step_ms: step, interval_ms: typical, interval_min_ms: iv_min, interval_max_ms: iv_max, points, gaps }
}

/// Round `v` up to a "nice" axis maximum (1, 2, 2.5, 5 × 10^k).
pub fn nice_ceil(v: f64) -> f64 {
    if !(v > 0.0) || !v.is_finite() {
        return 1.0;
    }
    let exp = v.log10().floor();
    let base = 10f64.powf(exp);
    let f = v / base;
    let nice = if f <= 1.0 {
        1.0
    } else if f <= 2.0 {
        2.0
    } else if f <= 2.5 {
        2.5
    } else if f <= 5.0 {
        5.0
    } else {
        10.0
    };
    nice * base
}

/// Axis maximum for `divisions` equal gridline steps, each a "nice" number
/// (1, 1.5, 2, 2.5, 3, 4, 5, 6, 8 × 10^k), at least `raw`.
pub fn axis_max(raw: f64, divisions: u32) -> f64 {
    if !(raw > 0.0) || !raw.is_finite() {
        return divisions as f64;
    }
    let step = raw / divisions as f64;
    let exp = step.log10().floor();
    let base = 10f64.powf(exp);
    let f = step / base;
    let nice = [1.0, 1.5, 2.0, 2.5, 3.0, 4.0, 5.0, 6.0, 8.0, 10.0]
        .into_iter()
        .find(|n| f <= *n + 1e-9)
        .unwrap_or(10.0);
    nice * base * divisions as f64
}

/// Format milliseconds compactly: "0.42", "12.3", "153".
pub fn fmt_ms(v: Option<f64>) -> String {
    match v {
        None => "—".into(),
        Some(v) if v < 1.0 => format!("{v:.2}"),
        Some(v) if v < 100.0 => format!("{v:.1}"),
        Some(v) => format!("{v:.0}"),
    }
}

pub fn fmt_pct(v: f64) -> String {
    if v == 0.0 {
        "0".into()
    } else if v < 10.0 {
        format!("{v:.1}")
    } else {
        format!("{v:.0}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streaming_statistics_match_keeping_every_sample() {
        // A spread of round trips with some lost, as (ms, in microsecond steps).
        let samples: Vec<Option<f64>> =
            (0..5000u32).map(|i| (i % 37 != 0).then(|| ((i * 7919) % 90_000) as f64 / 1000.0 + 0.25)).collect();
        let s = compute(samples.iter().copied());
        let mut kept: Vec<f64> = samples.iter().flatten().copied().collect();
        assert_eq!(s.p95_ms, percentile(&mut kept, 95.0), "the 95th percentile, exactly");
        assert_eq!(s.sent, 5000);
        assert_eq!(s.received as usize, kept.len());
        let avg = kept.iter().sum::<f64>() / kept.len() as f64;
        assert!((s.avg_ms.unwrap() - avg).abs() < 1e-9);
        assert_eq!(compute(std::iter::empty()), Stats::default());
        assert_eq!(compute([None, None]).p95_ms, None);
    }

    #[test]
    fn typical_interval_is_the_median_without_listing_them() {
        // 30 samples at 1 s, then 50 at 2.5 s, then 5 at 60 s.
        let mut s: Vec<Sample> = (0..30).map(|i| Sample::from_ms(i * 1000, Some(1.0), Some(1000))).collect();
        s.extend((0..50).map(|i| Sample::from_ms(30_000 + i * 2500, Some(1.0), Some(2500))));
        s.extend((0..5).map(|i| Sample::from_ms(155_000 + i * 60_000, Some(1.0), Some(60_000))));
        let tl = timeline(&s, 0, 460_000, 4000, 1000);
        assert_eq!((tl.interval_ms, tl.interval_min_ms, tl.interval_max_ms), (2500, 1000, 60_000));
        // Samples saved before intervals were use the target's own.
        let old: Vec<Sample> = (0..10).map(|i| Sample::from_ms(i * 5000, Some(1.0), None)).collect();
        assert_eq!(timeline(&old, 0, 50_000, 4000, 5000).interval_ms, 5000);
    }

    #[test]
    fn basic_stats() {
        let s = compute([Some(10.0), Some(20.0), None, Some(30.0)]);
        assert_eq!(s.sent, 4);
        assert_eq!(s.received, 3);
        assert!((s.loss_pct - 25.0).abs() < 1e-9);
        assert_eq!(s.min_ms, Some(10.0));
        assert_eq!(s.max_ms, Some(30.0));
        assert!((s.avg_ms.unwrap() - 20.0).abs() < 1e-9);
        // jitter: |20-10| + |30-20| over 2 pairs = 10
        assert!((s.jitter_ms.unwrap() - 10.0).abs() < 1e-9);
        assert_eq!(s.cur_ms, Some(30.0));
    }

    #[test]
    fn last_lost_means_no_current() {
        let s = compute([Some(10.0), None]);
        assert_eq!(s.cur_ms, None);
    }

    #[test]
    fn all_lost() {
        let s = compute([None, None]);
        assert_eq!(s.loss_pct, 100.0);
        assert_eq!(s.avg_ms, None);
        assert_eq!(s.mos, None);
    }

    #[test]
    fn mos_ranges() {
        assert!(mos(10.0, 1.0, 0.0) > 4.3);
        assert!(mos(300.0, 50.0, 5.0) < 3.0);
        assert_eq!(mos(2000.0, 500.0, 100.0), 1.0);
    }

    #[test]
    fn percentile_nearest_rank() {
        let mut v: Vec<f64> = (1..=100).map(|x| x as f64).collect();
        assert_eq!(percentile(&mut v, 95.0), Some(95.0));
    }

    #[test]
    fn buckets() {
        let rows = vec![(0, Some(10.0)), (500, None), (1000, Some(20.0)), (1500, Some(40.0))];
        let (w, b) = bucketize(&rows, 0, 2000, 2);
        assert_eq!(w, 1000);
        assert_eq!(b[0].sent, 2);
        assert_eq!(b[0].lost, 1);
        assert_eq!(b[1].avg_ms, Some(30.0));
        assert_eq!(b[1].max_ms, Some(40.0));
    }

    fn samples(n: usize, step: i64, iv: u32) -> Vec<Sample> {
        (0..n).map(|i| Sample::from_ms(i as i64 * step, Some(1.0 + (i % 7) as f64), Some(iv))).collect()
    }

    #[test]
    fn every_sample_when_it_fits() {
        // 10 minutes at 2.5 s = 240 samples on a chart with room for 700.
        let s = samples(240, 2500, 2500);
        let t = timeline(&s, 0, 600_000, 700, 2500);
        assert_eq!(t.mode, TimelineMode::Samples);
        assert_eq!(t.points.len(), 240);
        assert!(t.gaps.is_empty(), "{:?}", t.gaps);
        assert!(t.points.iter().all(|p| !p.gap));
        assert_eq!(t.interval_ms, 2500);
    }

    #[test]
    fn slices_never_shorter_than_two_intervals_and_never_empty() {
        // 1 hour at 2.5 s = 1440 samples, room for 750: 5 s slices of 2 samples.
        let s = samples(1440, 2500, 2500);
        let t = timeline(&s, 0, 3_600_000, 750, 2500);
        assert_eq!(t.mode, TimelineMode::Slices);
        assert_eq!(t.step_ms, 5_000);
        assert!(t.points.iter().all(|p| p.sent == 2), "every slice holds samples");
        assert!(t.gaps.is_empty());
    }

    #[test]
    fn slices_are_aligned_to_the_clock() {
        // The same samples viewed from slightly different windows give the
        // same slices: history doesn't shimmer on refresh.
        let s = samples(5000, 1000, 1000);
        let a = timeline(&s, 123, 5_000_123, 500, 1000);
        let b = timeline(&s, 1_877, 5_001_877, 500, 1000);
        assert_eq!(a.step_ms, 10_000);
        assert!(a.points.iter().all(|p| p.t_ms % 10_000 == 0));
        let common: Vec<_> = a.points.iter().filter(|p| p.t_ms >= 10_000 && p.t_ms < 4_990_000).collect();
        let other: Vec<_> = b.points.iter().filter(|p| p.t_ms >= 10_000 && p.t_ms < 4_990_000).collect();
        assert_eq!(common, other);
    }

    #[test]
    fn real_gaps_only() {
        // 2.5 s samples, then a 60 s pause, then more samples.
        let mut s = samples(40, 2500, 2500);
        let resume = 40 * 2500 + 60_000;
        s.extend((0..40).map(|i| Sample::from_ms(resume + i * 2500, Some(1.0), Some(2500))));
        let t = timeline(&s, 0, resume + 40 * 2500, 700, 2500);
        assert_eq!(t.gaps.len(), 1);
        assert_eq!(t.points.iter().filter(|p| p.gap).count(), 1);
        assert!(t.points[40].gap);
    }

    #[test]
    fn interval_change_is_not_a_gap() {
        // A visitor switches a destination from 1 s to 60 s.
        let mut s = samples(120, 1000, 1000);
        let start = 120 * 1000;
        s.extend((0..10).map(|i| Sample::from_ms(start + i * 60_000, Some(5.0), Some(60_000))));
        let t = timeline(&s, 0, start + 10 * 60_000, 700, 1000);
        assert!(t.gaps.is_empty(), "{:?}", t.gaps);
        assert!(t.points.iter().all(|p| !p.gap));
    }

    #[test]
    fn leading_and_trailing_gaps() {
        // Target added half way through the window, then paused.
        let s: Vec<Sample> = (0..20).map(|i| Sample::from_ms(300_000 + i * 2500, Some(2.0), Some(2500))).collect();
        let t = timeline(&s, 0, 600_000, 700, 2500);
        assert_eq!(t.gaps.first(), Some(&[0, 300_000]));
        assert_eq!(t.gaps.last().unwrap()[1], 600_000);
        // Fresh data is not a trailing gap even if the newest sample lags a bit.
        let t = timeline(&s, 0, 300_000 + 19 * 2500 + 4_000, 700, 2500);
        assert_eq!(t.gaps.len(), 1);
    }

    #[test]
    fn no_samples_is_one_gap() {
        let t = timeline(&[], 0, 600_000, 700, 2500);
        assert_eq!(t.gaps, vec![[0, 600_000]]);
        assert!(t.points.is_empty());
    }

    #[test]
    fn axis() {
        assert_eq!(axis_max(101.0, 4), 120.0);
        assert_eq!(axis_max(101.0, 2), 120.0);
        assert_eq!(axis_max(19.0, 4), 20.0);
        assert!((axis_max(0.3, 2) - 0.3).abs() < 1e-9);
    }

    #[test]
    fn nice() {
        assert_eq!(nice_ceil(0.7), 1.0);
        assert_eq!(nice_ceil(13.0), 20.0);
        assert_eq!(nice_ceil(230.0), 250.0);
        assert_eq!(nice_ceil(410.0), 500.0);
    }
}
