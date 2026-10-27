//! Turns stored samples into the views the TUI, web UI and reports show.

use anyhow::Result;
use std::collections::HashMap;
use std::net::IpAddr;

use std::sync::Arc;

use crate::engine::Rdns;
use crate::model::{Detail, HopReading, HopStat, LiveStatus, Overview, Target, TargetOverview, Thresholds};
use crate::stats::{bucketize, compute, timeline, Running};
use crate::store::{HopKind, HopRecord, Sample, Store};

/// What a share-link visitor is allowed to see.
#[derive(Debug, Clone, Default)]
pub struct Scope {
    /// Only these targets (None = all).
    pub ids: Option<Vec<i64>>,
    /// No samples before this time.
    pub earliest_ms: Option<i64>,
    pub privacy: Privacy,
}

impl Scope {
    pub fn everything() -> Scope {
        Scope::default()
    }

    pub fn allows(&self, id: i64) -> bool {
        self.ids.as_ref().is_none_or(|ids| ids.contains(&id))
    }

    pub fn clamp_from(&self, from: i64) -> i64 {
        self.earliest_ms.map_or(from, |e| from.max(e))
    }
}

/// Hop details hidden from share-link visitors.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Privacy {
    pub hide_private: bool,
    pub hide_public_hops: u8,
    pub hide_hostnames: bool,
}

impl Privacy {
    pub fn is_noop(&self) -> bool {
        !self.hide_private && self.hide_public_hops == 0 && !self.hide_hostnames
    }
}

/// Mask hop addresses and names according to `p`. The destination itself is
/// never masked (the visitor already knows it).
pub fn apply_privacy(hops: &mut [HopStat], p: Privacy) {
    if p.is_noop() {
        return;
    }
    let mut public_seen = 0u8;
    for h in hops.iter_mut() {
        let ip: Option<IpAddr> = h.addr.as_deref().and_then(|a| a.parse().ok());
        let mask = match ip {
            _ if h.is_dest => None,
            Some(ip) if p.hide_private && crate::netpolicy::is_private(ip) => Some("private network"),
            Some(ip) if !crate::netpolicy::is_private(ip) && public_seen < p.hide_public_hops => {
                public_seen += 1;
                Some("hidden")
            }
            _ => None,
        };
        if let Some(m) = mask {
            h.addr = None;
            h.hostname = None;
            h.responders = h.responders.min(1);
            h.masked = Some(m.to_string());
        }
        if p.hide_hostnames && !h.is_dest {
            h.hostname = None;
        }
    }
}

/// Strip owner details a visitor has no business seeing.
pub fn public_target(mut t: Target) -> Target {
    t.session = None;
    t.restrict = None;
    // Which link added it is the owner's business; visitors get owned_ids.
    t.share_id = None;
    t
}

pub fn overview(
    store: &Store,
    live: &dyn Fn(i64) -> LiveStatus,
    thresholds: Thresholds,
    now: i64,
    window_ms: i64,
    spark_n: usize,
) -> Result<Overview> {
    overview_scoped(store, live, thresholds, now, window_ms, spark_n, &Scope::everything())
}

#[allow(clippy::too_many_arguments)]
pub fn overview_scoped(
    store: &Store,
    live: &dyn Fn(i64) -> LiveStatus,
    thresholds: Thresholds,
    now: i64,
    window_ms: i64,
    spark_n: usize,
    scope: &Scope,
) -> Result<Overview> {
    let mut out = Vec::new();
    for t in store.list_targets()?.into_iter().filter(|t| scope.allows(t.id)) {
        let window_from = now - window_ms;
        let from = scope.clamp_from(window_from);
        let rows = store.load_rounds(t.id, from, now + 1)?;
        let stats = compute(rows.iter().map(|r| r.1));
        let (_, buckets) = bucketize(&rows, window_from, now + 1, spark_n.clamp(1, 600));
        let spark = buckets.iter().map(|b| b.avg_ms).collect();
        let spark_loss = buckets
            .iter()
            .map(|b| if b.sent == 0 { None } else { Some(b.lost as f64 / b.sent as f64) })
            .collect();
        let target = if scope.ids.is_some() { public_target(t) } else { t };
        out.push(TargetOverview { live: live(target.id), target, stats, spark, spark_loss });
    }
    Ok(Overview { now_ms: now, window_ms, targets: out, thresholds })
}

/// Detail for one target. With `hop`, the stats and timeline describe that
/// hop (TTL) instead of the destination.
#[allow(clippy::too_many_arguments)]
pub fn detail(
    store: &Store,
    target: Target,
    live: LiveStatus,
    rdns: Option<&Arc<Rdns>>,
    from: i64,
    to: i64,
    max_points: usize,
    hop: Option<u8>,
    th: Thresholds,
) -> Result<Detail> {
    detail_scoped(store, target, live, rdns, from, to, max_points, hop, th, &Scope::everything())
}

/// Like [`detail`], limited to what `scope` allows: no samples before
/// `scope.earliest_ms` (the timeline still spans `[from, to)`), and hop
/// addresses masked by `scope.privacy`.
#[allow(clippy::too_many_arguments)]
pub fn detail_scoped(
    store: &Store,
    target: Target,
    live: LiveStatus,
    rdns: Option<&Arc<Rdns>>,
    from: i64,
    to: i64,
    max_points: usize,
    hop: Option<u8>,
    th: Thresholds,
    scope: &Scope,
) -> Result<Detail> {
    let data_from = scope.clamp_from(from).min(to);
    // One pass over the hop samples: route statistics, plus the chosen
    // hop's own samples when a hop is being graphed.
    let mut acc = HopAcc::default();
    let mut hop_rows: Vec<Sample> = Vec::new();
    if target.trace {
        store.for_each_hops(target.id, data_from, to, |ts, hs, iv| {
            acc.push(hs);
            if let Some(ttl) = hop
                && let Some(h) = hs.iter().find(|h| h.ttl == ttl)
            {
                hop_rows.push((ts, h.rtt_us.map(|u| u as f64 / 1000.0), iv));
            }
        })?;
    }
    let mut hops = acc.finish(rdns);
    read_route(&mut hops, &th);
    let hop = hop.filter(|h| hops.iter().any(|x| x.ttl == *h));
    let rows: Vec<Sample> = match hop {
        Some(_) => hop_rows,
        None => store.load_samples(target.id, data_from, to)?,
    };
    let stats = compute(rows.iter().map(|r| r.1));
    let tl = timeline(&rows, from, to, max_points, target.interval_ms);
    apply_privacy(&mut hops, scope.privacy);
    let target = if scope.ids.is_some() { public_target(target) } else { target };
    Ok(Detail { target, live, stats, hops, hop, timeline: tl })
}

/// Work out what each hop's loss means (see [`HopReading`]).
///
/// Loss at a hop only matters if it carries on: every later hop, the
/// destination included, must lose at least as much. So the loss carried
/// from a hop is the lowest loss at it or any later hop that answers, and
/// the loss that reaches the destination starts at the first hop whose
/// carried loss reaches the warning level. Loss above what a hop carries on
/// is that router limiting replies to itself. Nothing is flagged unless the
/// destination itself loses packets.
///
/// What this can't tell apart: a router that drops ping traffic passing
/// through it (not just replies to itself) looks exactly like real loss.
pub fn read_route(hops: &mut [HopStat], th: &Thresholds) {
    let lossy = |pct: f64| pct >= th.loss_warn_pct;
    let mut floor: Option<f64> = None;
    let mut answered_later = false;
    let mut later: Vec<bool> = vec![false; hops.len()];
    for (i, h) in hops.iter_mut().enumerate().rev() {
        later[i] = answered_later;
        if h.stats.received > 0 {
            floor = Some(floor.map_or(h.stats.loss_pct, |f| f.min(h.stats.loss_pct)));
            h.carried_pct = floor;
            answered_later = true;
        } else {
            h.carried_pct = None;
        }
    }
    let dest = hops.iter().position(|h| h.is_dest && h.stats.received > 0);
    let start = dest
        .filter(|&d| lossy(hops[d].stats.loss_pct))
        .and_then(|d| (0..=d).find(|&i| hops[i].carried_pct.is_some_and(lossy)));
    for (i, h) in hops.iter_mut().enumerate() {
        let s = &h.stats;
        h.reading = if s.sent == 0 {
            None
        } else if s.received == 0 {
            later[i].then_some(HopReading::NoReply)
        } else if Some(i) == start {
            Some(HopReading::LossStarts)
        } else if !h.is_dest && lossy(s.loss_pct - h.carried_pct.unwrap_or(s.loss_pct)) {
            Some(HopReading::LimitsReplies)
        } else if start.is_some_and(|st| i > st) && dest.is_some_and(|d| i <= d) {
            Some(HopReading::LossCarried)
        } else {
            None
        };
    }
}

/// Aggregate per-hop statistics over a set of samples.
#[cfg(test)]
pub fn hop_stats(rows: &[(i64, Vec<HopRecord>)], rdns: Option<&Arc<Rdns>>) -> Vec<HopStat> {
    let mut acc = HopAcc::default();
    for (_, h) in rows {
        acc.push(h);
    }
    acc.finish(rdns)
}

/// Per-hop statistics built up one sample at a time, without keeping the
/// samples (a month of a traced target is millions of hop replies).
#[derive(Default)]
pub struct HopAcc {
    by_ttl: Vec<(Running, HashMap<IpAddr, u32>)>,
    /// Destination TTL of the last 20 samples (None = not reached).
    recent_dest: std::collections::VecDeque<Option<u8>>,
    max_probed: u8,
    furthest: u8,
    any: bool,
}

impl HopAcc {
    pub fn push(&mut self, hops: &[HopRecord]) {
        self.any = true;
        let dest = hops.iter().find(|h| h.kind == HopKind::Echo).map(|h| h.ttl);
        if self.recent_dest.len() == 20 {
            self.recent_dest.pop_front();
        }
        self.recent_dest.push_back(dest);
        if let Some(last) = hops.last() {
            self.max_probed = self.max_probed.max(last.ttl);
        }
        for h in hops {
            if h.ttl == 0 {
                continue;
            }
            let i = (h.ttl - 1) as usize;
            if self.by_ttl.len() <= i {
                self.by_ttl.resize_with(i + 1, Default::default);
            }
            let (run, addrs) = &mut self.by_ttl[i];
            run.push(h.rtt_us.map(|u| u as f64 / 1000.0));
            if let Some(ip) = h.addr {
                *addrs.entry(ip).or_default() += 1;
                self.furthest = self.furthest.max(h.ttl);
            }
        }
    }

    pub fn finish(self, rdns: Option<&Arc<Rdns>>) -> Vec<HopStat> {
        if !self.any {
            return Vec::new();
        }
        // Show the route as it was most recently seen: up to the destination
        // if the latest samples reached it, otherwise one hop past the
        // furthest responder.
        let latest_dest = self.recent_dest.iter().rev().find_map(|d| *d);
        let shown = match latest_dest {
            Some(d) => d,
            None => (self.furthest + 1).min(self.max_probed).max(1),
        } as usize;
        let mut by_ttl = self.by_ttl;
        by_ttl.resize_with(shown.max(by_ttl.len()), Default::default);
        by_ttl
            .into_iter()
            .take(shown)
            .enumerate()
            .map(|(i, (run, addrs))| {
                let ttl = (i + 1) as u8;
                let top = addrs.iter().max_by_key(|(_, n)| **n).map(|(ip, _)| *ip);
                HopStat {
                    ttl,
                    addr: top.map(|ip| ip.to_string()),
                    hostname: top.and_then(|ip| rdns.and_then(|r| r.get(ip))),
                    responders: addrs.len() as u32,
                    is_dest: latest_dest == Some(ttl),
                    masked: None,
                    stats: run.finish(),
                    carried_pct: None,
                    reading: None,
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Stats;

    fn hop(ttl: u8, addr: &str, us: u32, kind: HopKind) -> HopRecord {
        HopRecord { ttl, addr: Some(addr.parse().unwrap()), rtt_us: Some(us), kind }
    }

    #[test]
    fn route_trimmed_to_destination() {
        let rows = vec![
            (1, vec![
                hop(1, "10.0.0.1", 1000, HopKind::TimeExceeded),
                HopRecord { ttl: 2, addr: None, rtt_us: None, kind: HopKind::Timeout },
                hop(3, "8.8.8.8", 9000, HopKind::Echo),
            ]),
            (2, vec![
                hop(1, "10.0.0.1", 3000, HopKind::TimeExceeded),
                hop(2, "10.0.1.1", 5000, HopKind::TimeExceeded),
                hop(3, "8.8.8.8", 11000, HopKind::Echo),
            ]),
        ];
        let h = hop_stats(&rows, None);
        assert_eq!(h.len(), 3);
        assert_eq!(h[0].stats.avg_ms, Some(2.0));
        assert_eq!(h[1].stats.loss_pct, 50.0);
        assert!(h[2].is_dest);
        assert_eq!(h[2].addr.as_deref(), Some("8.8.8.8"));
    }

    #[test]
    fn privacy_masks_private_and_first_public_hops() {
        let mk = |ttl: u8, addr: &str, dest: bool| HopStat {
            ttl,
            addr: Some(addr.into()),
            hostname: Some(format!("h{ttl}.example")),
            responders: 2,
            is_dest: dest,
            ..HopStat::default()
        };
        let base = vec![mk(1, "192.168.0.1", false), mk(2, "154.0.0.131", false), mk(3, "154.0.0.75", false), mk(4, "1.1.1.1", true)];

        let mut h = base.clone();
        apply_privacy(&mut h, Privacy { hide_private: true, ..Default::default() });
        assert_eq!(h[0].masked.as_deref(), Some("private network"));
        assert_eq!((h[0].addr.clone(), h[0].hostname.clone()), (None, None));
        assert_eq!(h[1].addr.as_deref(), Some("154.0.0.131"));

        let mut h = base.clone();
        apply_privacy(&mut h, Privacy { hide_private: false, hide_public_hops: 1, hide_hostnames: true });
        assert_eq!(h[0].addr.as_deref(), Some("192.168.0.1"));
        assert_eq!(h[0].hostname, None);
        assert_eq!(h[1].masked.as_deref(), Some("hidden"));
        assert_eq!(h[2].addr.as_deref(), Some("154.0.0.75"));
        assert_eq!(h[3].addr.as_deref(), Some("1.1.1.1"));
        assert_eq!(h[3].hostname.as_deref(), Some("h4.example"), "destination keeps its name");

        let mut h = base.clone();
        apply_privacy(&mut h, Privacy::default());
        assert!(h.iter().all(|x| x.masked.is_none()));
    }

    /// A route with the given loss per hop (None = never answered); the
    /// last hop is the destination when `reached`.
    fn route(loss: &[Option<f64>], reached: bool) -> Vec<HopStat> {
        let n = loss.len();
        let mut hops: Vec<HopStat> = loss
            .iter()
            .enumerate()
            .map(|(i, l)| HopStat {
                ttl: i as u8 + 1,
                is_dest: reached && i + 1 == n,
                stats: Stats {
                    sent: 1000,
                    received: l.map_or(0, |p| (1000.0 * (1.0 - p / 100.0)).round() as u32),
                    loss_pct: l.unwrap_or(100.0),
                    ..Stats::default()
                },
                ..HopStat::default()
            })
            .collect();
        read_route(&mut hops, &Thresholds::default());
        hops
    }
    fn readings(h: &[HopStat]) -> Vec<Option<HopReading>> {
        h.iter().map(|x| x.reading).collect()
    }
    use HopReading::*;

    #[test]
    fn a_router_limiting_replies_is_not_loss() {
        // Hop 5 loses a third of its replies but everything after it answers:
        // a router limiting replies to itself. The destination is clean.
        let h = route(&[Some(0.2), Some(0.2), Some(0.3), Some(0.2), Some(35.0), Some(0.2), Some(0.1), Some(0.1)], true);
        assert_eq!(readings(&h), [None, None, None, None, Some(LimitsReplies), None, None, None]);
        assert_eq!(h[4].carried_pct, Some(0.1));
    }

    #[test]
    fn loss_that_carries_on_starts_where_it_first_appears() {
        let h = route(&[Some(0.0), Some(0.3), Some(5.2), Some(4.8), Some(6.0), Some(5.1)], true);
        assert_eq!(readings(&h), [None, None, Some(LossStarts), Some(LossCarried), Some(LossCarried), Some(LossCarried)]);
        assert_eq!(h[2].carried_pct, Some(4.8));
    }

    #[test]
    fn a_limiting_router_inside_real_loss_is_still_named() {
        // Real loss from hop 2; hop 3 also limits its own replies on top.
        let h = route(&[Some(0.0), Some(4.0), Some(30.0), Some(4.5), Some(4.2)], true);
        assert_eq!(readings(&h), [None, Some(LossStarts), Some(LimitsReplies), Some(LossCarried), Some(LossCarried)]);
    }

    #[test]
    fn loss_only_at_the_destination_starts_there() {
        let h = route(&[Some(0.0), Some(40.0), Some(0.1), Some(3.1)], true);
        assert_eq!(readings(&h), [None, Some(LimitsReplies), None, Some(LossStarts)]);
    }

    #[test]
    fn silent_hops_and_unreached_destinations() {
        // Hop 2 never answers but later hops do; nothing reaches the
        // destination yet, so nothing is called loss.
        let h = route(&[Some(0.0), None, Some(0.0), Some(12.0), None], false);
        assert_eq!(readings(&h), [None, Some(NoReply), None, None, None]);
        assert_eq!(h[1].carried_pct, None);
        // Small differences below the warning level are noise, not a finding.
        let h = route(&[Some(0.4), Some(0.9), Some(0.2), Some(0.6)], true);
        assert!(readings(&h).iter().all(Option::is_none));
    }

    #[test]
    fn unreachable_destination_shows_one_extra_hop() {
        let rows = vec![(1, vec![
            hop(1, "10.0.0.1", 1000, HopKind::TimeExceeded),
            hop(2, "10.0.1.1", 2000, HopKind::TimeExceeded),
            HopRecord { ttl: 3, addr: None, rtt_us: None, kind: HopKind::Timeout },
        ])];
        let h = hop_stats(&rows, None);
        assert_eq!(h.len(), 3);
        assert_eq!(h[2].stats.loss_pct, 100.0);
        assert!(!h[2].is_dest);
    }
}
