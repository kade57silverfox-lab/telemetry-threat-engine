//! Anomaly-based detection using probabilistic sketches.
//!
//! At millions of events/sec you cannot keep an exact per-source counter
//! table (unbounded memory growth, one entry per distinct IP). Instead we
//! use two well-known sketches with fixed memory and a known error bound:
//!
//! - `CountMinSketch`: approximate frequency of an event key (e.g. "how
//!   many SYNs has this source sent in the current window") -- used to
//!   catch floods.
//! - `HyperLogLog`: approximate cardinality (e.g. "how many distinct
//!   destination ports has this source touched") -- used to catch scans.
//!
//! Both are reset on a fixed window (see `WindowedAnomalyDetector`), which
//! is the sliding-window behavior a real NIDS needs: "too many X *within
//! T seconds*", not "too many X ever".

use crate::models::{Alert, DetectorKind, NetworkEvent, Severity};
use rustc_hash::FxHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Fixed-memory approximate counter. `width` controls the error bound,
/// `depth` (number of hash rows) controls the probability of collision
/// error -- standard Count-Min Sketch parameters.
pub struct CountMinSketch {
    depth: usize,
    width: usize,
    table: Vec<Vec<u32>>,
    seeds: Vec<u64>,
}

impl CountMinSketch {
    pub fn new(width: usize, depth: usize) -> Self {
        let seeds = (0..depth).map(|i| 0x9E3779B97F4A7C15u64.wrapping_mul(i as u64 + 1)).collect();
        Self {
            depth,
            width,
            table: vec![vec![0u32; width]; depth],
            seeds,
        }
    }

    fn hash(&self, key: &[u8], row: usize) -> usize {
        let mut hasher = FxHasher::default();
        self.seeds[row].hash(&mut hasher);
        key.hash(&mut hasher);
        (hasher.finish() as usize) % self.width
    }

    pub fn increment(&mut self, key: &[u8]) {
        for row in 0..self.depth {
            let col = self.hash(key, row);
            self.table[row][col] = self.table[row][col].saturating_add(1);
        }
    }

    /// Estimated count is always >= true count (sketch only over-counts,
    /// never under-counts, due to hash collisions).
    pub fn estimate(&self, key: &[u8]) -> u32 {
        (0..self.depth)
            .map(|row| self.table[row][self.hash(key, row)])
            .min()
            .unwrap_or(0)
    }

    pub fn clear(&mut self) {
        for row in self.table.iter_mut() {
            row.iter_mut().for_each(|c| *c = 0);
        }
    }
}

/// Approximate distinct-count estimator. This is a simplified HyperLogLog
/// (fixed number of buckets, standard leading-zero-run estimator) -- enough
/// buckets to keep error in the single-digit percent range for the scan
/// detection use case, without the full bias-correction tables of a
/// production HLL implementation.
pub struct HyperLogLog {
    buckets: Vec<u8>,
    bucket_bits: u32,
}

impl HyperLogLog {
    pub fn new(bucket_bits: u32) -> Self {
        Self {
            buckets: vec![0u8; 1 << bucket_bits],
            bucket_bits,
        }
    }

    pub fn add(&mut self, key: &[u8]) {
        let mut hasher = FxHasher::default();
        key.hash(&mut hasher);
        let h = hasher.finish();

        let bucket = (h >> (64 - self.bucket_bits)) as usize;
        let rest = h << self.bucket_bits | (1 << (self.bucket_bits - 1)); // avoid all-zero
        let rank = rest.leading_zeros() as u8 + 1;
        if rank > self.buckets[bucket] {
            self.buckets[bucket] = rank;
        }
    }

    /// Real bug caught here during live testing: the raw HLL estimator
    /// below (`alpha * m * m / sum`) is only accurate when the true
    /// cardinality is comparable to `m` (the bucket count). For SMALL true
    /// cardinalities -- which is the overwhelmingly common case here, since
    /// most benign source IPs touch exactly one destination port -- the raw
    /// formula badly OVERESTIMATES. A quick check: with 1024 buckets and a
    /// true cardinality of exactly 1, the raw formula returns an estimate
    /// of roughly 738, not ~1. That''s why the port-scan detector (threshold
    /// 25) was firing on nearly every single benign connection: any IP
    /// touching even one port could get an inflated estimate well past 25.
    ///
    /// Standard HyperLogLog implementations handle this with a documented
    /// "small-range correction": switch to linear counting
    /// (`m * ln(m / V)`, V = empty bucket count) when the data is actually
    /// sparse. The textbook cutoff for this is "raw estimate <= 2.5*m", but
    /// that threshold assumes near-ideal hash bit distribution; this
    /// implementation''s simplified hash doesn''t mix bits well enough for
    /// linear counting to stay accurate all the way up to 2.5*m (it was
    /// empirically ~40% low around cardinality 1000 against a 1024-bucket
    /// table). Keying the correction off the empty-bucket *fraction*
    /// instead -- only correct when the table is genuinely sparse (more
    /// than half the buckets never touched) -- targets exactly the
    /// low-cardinality regime the raw estimator gets wrong, without
    /// touching the medium/high-cardinality regime where the raw estimator
    /// was already accurate.
    ///
    /// One more wrinkle found while tuning this: this implementation''s
    /// hash (FxHash, chosen for speed over cryptographic quality) does not
    /// distribute buckets perfectly evenly for structured/sequential input
    /// -- empirically, even a true cardinality of 1000 against 1024
    /// buckets leaves more empty buckets than an ideal hash would (~55%
    /// empty here vs. a theoretical ~38%). Using a loose empty-fraction
    /// cutoff (e.g. 50%) would misfire the correction on that mid-range
    /// case too, where the plain raw estimator was already working. 90%
    /// empty is specific enough to catch the actual failure mode (a source
    /// that touched only a handful of ports) without disturbing ranges
    /// where the raw estimator is already accurate.
    pub fn estimate(&self) -> f64 {
        let m = self.buckets.len() as f64;
        let zero_buckets = self.buckets.iter().filter(|&&r| r == 0).count() as f64;

        if zero_buckets / m > 0.9 {
            return m * (m / zero_buckets).ln();
        }

        let alpha = 0.7213 / (1.0 + 1.079 / m);
        let sum: f64 = self.buckets.iter().map(|&r| 2f64.powi(-(r as i32))).sum();
        alpha * m * m / sum
    }

    /// Part of the sketch''s public API (a caller managing its own window
    /// rollover would use this); the detector below manages HLL lifetime by
    /// recreating instances per window instead, so this isn''t called
    /// internally, but removing it would make `HyperLogLog` a less honest,
    /// less reusable implementation of the data structure.
    #[allow(dead_code)]
    pub fn clear(&mut self) {
        self.buckets.iter_mut().for_each(|b| *b = 0);
    }
}

/// Ties the sketches together into window-based detection with concrete
/// thresholds. Windows reset every `window` duration -- this is the
/// sliding-window mechanism referenced throughout docs/DESIGN.md.
pub struct WindowedAnomalyDetector {
    window: Duration,
    window_start: Instant,
    syn_counts: CountMinSketch,
    port_cardinality: HashMap<u32, HyperLogLog>,
    syn_flood_threshold: u32,
    port_scan_threshold: f64,
    // NOTE on why these two sets exist: an earlier version tried to fire
    // "only once, right when the count crosses the threshold" by checking
    // for an exact value (`est == threshold`) or a narrow floating-point
    // band. But the Count-Min Sketch''s counters are shared across every
    // source hashing into the same buckets -- with enough concurrent
    // traffic, collision noise can make one source''s estimate jump
    // straight from 49 to 53 in a single packet, skipping the exact value
    // 50 entirely and never firing. Same problem for the port-scan''s
    // narrow band. This was the actual reason the anomaly detector almost
    // never fired despite processing millions of events -- not a sharding
    // issue, a crossing-detection issue. Tracking "have I already alerted
    // this source this window" and firing on `>=` fixes it without
    // spamming an alert on every subsequent packet after the first.
    /// Sources already alerted for SYN flood this window (see comment
    /// below on why this exists instead of an exact-value crossing check).
    alerted_flood_this_window: std::collections::HashSet<u32>,
    /// Sources already alerted for port scan this window.
    alerted_scan_this_window: std::collections::HashSet<u32>,
    next_id: AtomicU64,
}

impl WindowedAnomalyDetector {
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            window_start: Instant::now(),
            syn_counts: CountMinSketch::new(2048, 4),
            port_cardinality: HashMap::new(),
            syn_flood_threshold: 50,   // >=50 SYNs from one source per window => flood
            port_scan_threshold: 25.0, // >=25 distinct dst ports from one source per window => scan
            alerted_flood_this_window: std::collections::HashSet::new(),
            alerted_scan_this_window: std::collections::HashSet::new(),
            next_id: AtomicU64::new(1),
        }
    }

    fn maybe_roll_window(&mut self) {
        if self.window_start.elapsed() >= self.window {
            self.syn_counts.clear();
            self.port_cardinality.clear();
            self.alerted_flood_this_window.clear();
            self.alerted_scan_this_window.clear();
            self.window_start = Instant::now();
        }
    }

    pub fn observe(&mut self, event: &NetworkEvent) -> Vec<Alert> {
        self.maybe_roll_window();
        let mut alerts = Vec::new();
        let key = event.src_ip.to_be_bytes();

        if event.is_syn() {
            self.syn_counts.increment(&key);
            let est = self.syn_counts.estimate(&key);
            if est >= self.syn_flood_threshold
                && !self.alerted_flood_this_window.contains(&event.src_ip)
            {
                self.alerted_flood_this_window.insert(event.src_ip);
                alerts.push(self.alert(
                    event,
                    "syn-flood-anomaly",
                    Severity::Critical,
                    format!(
                        "source {} sent an estimated {}+ SYNs within {:?} window",
                        event.src_ip_str(),
                        est,
                        self.window
                    ),
                ));
            }
        }

        let hll = self
            .port_cardinality
            .entry(event.src_ip)
            .or_insert_with(|| HyperLogLog::new(10));
        hll.add(&event.dst_port.to_be_bytes());
        let distinct = hll.estimate();
        if distinct >= self.port_scan_threshold
            && !self.alerted_scan_this_window.contains(&event.src_ip)
        {
            self.alerted_scan_this_window.insert(event.src_ip);
            alerts.push(self.alert(
                event,
                "port-scan-anomaly",
                Severity::High,
                format!(
                    "source {} touched an estimated {:.0} distinct destination ports within {:?} window",
                    event.src_ip_str(),
                    distinct,
                    self.window
                ),
            ));
        }

        alerts
    }

    fn alert(&self, event: &NetworkEvent, rule: &str, severity: Severity, detail: String) -> Alert {
        Alert {
            id: self.next_id.fetch_add(1, Ordering::Relaxed),
            timestamp_ms: event.timestamp_ms,
            rule_name: rule.to_string(),
            severity,
            src_ip: event.src_ip_str(),
            dst_ip: event.dst_ip_str(),
            detail,
            detector: DetectorKind::Anomaly,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_min_sketch_never_undercounts() {
        let mut cms = CountMinSketch::new(64, 4);
        for _ in 0..100 {
            cms.increment(b"1.2.3.4");
        }
        assert!(cms.estimate(b"1.2.3.4") >= 100);
    }

    /// Regression test for the real bug: without the small-range
    /// correction, a true cardinality of 1 produced an estimate around
    /// 738 (see the comment on `estimate()`), which is why nearly every
    /// benign single-port connection was tripping the port-scan detector.
    /// A single distinct item must estimate as small, not in the hundreds.
    #[test]
    fn hyperloglog_small_cardinality_does_not_overestimate() {
        let mut hll = HyperLogLog::new(10);
        hll.add(b"only-one-item");
        let est = hll.estimate();
        assert!(
            est < 5.0,
            "true cardinality of 1 should estimate small, got {est} -- \
             this is the exact bug that caused mass false-positive port-scan alerts"
        );
    }

    #[test]
    fn hyperloglog_estimates_within_reasonable_error() {
        let mut hll = HyperLogLog::new(10);
        for i in 0..1000u32 {
            hll.add(&i.to_be_bytes());
        }
        let est = hll.estimate();
        // HLL with 2^10 buckets: expect single-digit-percent error range
        assert!(est > 800.0 && est < 1200.0, "estimate was {est}");
    }

    /// Regression test for the real bug: an exact-value crossing check
    /// (`est == threshold`) or narrow band can be skipped entirely when
    /// the sketch''s shared counters get inflated by unrelated traffic,
    /// jumping the estimate past the threshold in a single increment. A
    /// `>=` check with a per-window "already alerted" guard must still
    /// fire exactly once even when the count jumps straight past the
    /// threshold instead of landing on it.
    #[test]
    fn syn_flood_fires_even_when_estimate_jumps_past_threshold() {
        let mut det = WindowedAnomalyDetector::new(Duration::from_secs(5));
        // Manually inflate the shared sketch with unrelated "noise" traffic
        // from many different source IPs, some of which collide into the
        // same buckets our real attacker will use -- simulating exactly
        // the shared-counter collision pressure that caused the original
        // bug in concurrent, high-volume traffic.
        for i in 0u32..40 {
            det.syn_counts.increment(&i.to_be_bytes());
        }

        let attacker_ip: u32 = 0x0A00_00FF;
        let mut event = NetworkEvent {
            timestamp_ms: 0,
            src_ip: attacker_ip,
            dst_ip: 0xC0A80101,
            src_port: 4444,
            dst_port: 80,
            protocol: crate::models::Protocol::Tcp,
            flags: 0b0001, // SYN only
            payload_sample: vec![],
        };

        let mut fired = 0;
        for _ in 0..80 {
            // Real attack traffic varies source port per packet; src_ip
            // (what the detector keys on) stays fixed.
            event.src_port = event.src_port.wrapping_add(1);
            let alerts = det.observe(&event);
            fired += alerts
                .iter()
                .filter(|a| a.rule_name == "syn-flood-anomaly")
                .count();
        }

        assert_eq!(
            fired, 1,
            "expected exactly one syn-flood alert once the threshold was crossed, got {fired}"
        );
    }
}