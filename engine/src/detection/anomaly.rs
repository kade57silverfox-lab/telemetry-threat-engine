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

    pub fn estimate(&self) -> f64 {
        let m = self.buckets.len() as f64;
        let alpha = 0.7213 / (1.0 + 1.079 / m);
        let sum: f64 = self.buckets.iter().map(|&r| 2f64.powi(-(r as i32))).sum();
        alpha * m * m / sum
    }

    /// Part of the sketch's public API (a caller managing its own window
    /// rollover would use this); the detector below manages HLL lifetime by
    /// recreating instances per window instead, so this isn't called
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
    next_id: AtomicU64,
}

impl WindowedAnomalyDetector {
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            window_start: Instant::now(),
            syn_counts: CountMinSketch::new(2048, 4),
            port_cardinality: HashMap::new(),
            syn_flood_threshold: 50,   // >50 SYNs from one source per window => flood
            port_scan_threshold: 25.0, // >~25 distinct dst ports from one source per window => scan
            next_id: AtomicU64::new(1),
        }
    }

    fn maybe_roll_window(&mut self) {
        if self.window_start.elapsed() >= self.window {
            self.syn_counts.clear();
            self.port_cardinality.clear();
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
            if est == self.syn_flood_threshold {
                // fire once per window at the crossing point, not every event after
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
        if distinct >= self.port_scan_threshold && distinct < self.port_scan_threshold + 1.0 {
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
}
