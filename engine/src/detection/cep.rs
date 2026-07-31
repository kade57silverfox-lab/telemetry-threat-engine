//! Complex Event Processing (CEP) engine.
//!
//! Signature and anomaly detection (see `signature.rs`, `anomaly.rs`) both
//! judge a single event (or a single running count) in isolation. CEP is
//! different: it detects *sequences* of distinct event types, in order,
//! within a time window, correlated by a key (here: source IP) -- e.g.
//! "a reconnaissance probe followed by an exploit attempt from the same
//! source within 5 seconds" is a stronger, lower-false-positive signal
//! than either event alone.
//!
//! This is implemented as a small NFA: each rule is a sequence of
//! `Condition`s. For every tracked key we hold a set of "partial matches"
//! -- how far along the sequence that key has progressed, and when it
//! started. An incoming event may:
//!   1. start a new partial match at step 0 if it satisfies the rule's
//!      first condition,
//!   2. advance an existing partial match if it satisfies the *next*
//!      condition for that match,
//!   3. complete a partial match (all steps satisfied within the window),
//!      producing an alert.
//! Partial matches older than the rule's window are expired (treated as a
//! failed match, per the "reset" semantics of an NFA over a bounded
//! window) rather than kept forever, which bounds memory per key.

use crate::models::{Alert, DetectorKind, NetworkEvent, Severity};
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub enum Condition {
    IsSynOnly,
    HasSignaturePayload, // any non-empty payload sample containing suspicious markers
    /// Reserved for a future rule (e.g. "probe touches an unusually high
    /// port"); not wired into `with_default_rules` yet, kept here rather
    /// than deleted since it's part of the condition vocabulary the CEP
    /// engine already supports.
    #[allow(dead_code)]
    DistinctPortAbove(u16),
}

impl Condition {
    fn matches(&self, event: &NetworkEvent) -> bool {
        match self {
            Condition::IsSynOnly => event.is_syn(),
            Condition::HasSignaturePayload => !event.payload_sample.is_empty()
                && String::from_utf8_lossy(&event.payload_sample).contains("passwd"),
            Condition::DistinctPortAbove(p) => event.dst_port > *p,
        }
    }
}

pub struct CepRule {
    pub name: String,
    pub severity: Severity,
    pub steps: Vec<Condition>,
    pub window: Duration,
}

struct PartialMatch {
    step: usize,
    started_at: Instant,
}

pub struct CepEngine {
    rules: Vec<CepRule>,
    /// active[rule_idx][key] = partial matches in progress for that key
    active: Vec<HashMap<u32, Vec<PartialMatch>>>,
    next_id: std::sync::atomic::AtomicU64,
}

impl CepEngine {
    pub fn with_default_rules() -> Self {
        let rules = vec![CepRule {
            name: "probe-then-exploit-attempt".to_string(),
            severity: Severity::Critical,
            steps: vec![Condition::IsSynOnly, Condition::HasSignaturePayload],
            window: Duration::from_secs(5),
        }];
        let active = rules.iter().map(|_| HashMap::new()).collect();
        Self {
            rules,
            active,
            next_id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    pub fn process(&mut self, event: &NetworkEvent) -> Vec<Alert> {
        let mut alerts = Vec::new();
        let key = event.src_ip;
        let now = Instant::now();

        for (rule_idx, rule) in self.rules.iter().enumerate() {
            let partials = self.active[rule_idx].entry(key).or_default();

            // Expire stale partial matches (window elapsed => failed match).
            partials.retain(|p| now.duration_since(p.started_at) <= rule.window);

            // Try to advance existing partial matches, from furthest along
            // first so a completing match takes priority this tick.
            let mut completed = false;
            for p in partials.iter_mut().rev() {
                if p.step < rule.steps.len() && rule.steps[p.step].matches(event) {
                    p.step += 1;
                    if p.step == rule.steps.len() {
                        completed = true;
                        let id = self
                            .next_id
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        alerts.push(Alert {
                            id,
                            timestamp_ms: event.timestamp_ms,
                            rule_name: rule.name.clone(),
                            severity: rule.severity,
                            src_ip: event.src_ip_str(),
                            dst_ip: event.dst_ip_str(),
                            detail: format!(
                                "CEP rule '{}' completed: {} steps matched within {:?}",
                                rule.name,
                                rule.steps.len(),
                                rule.window
                            ),
                            detector: DetectorKind::Cep,
                        });
                        break; // only complete once per event
                    }
                }
            }

            // Drop completed matches so they don't fire again.
            if completed {
                partials.retain(|p| p.step < rule.steps.len());
            }

            // Start a new partial match if this event satisfies step 0.
            // (Independent of whether it also advanced another partial
            // match -- one event can both advance an older sequence and
            // begin a new one.)
            if !rule.steps.is_empty() && rule.steps[0].matches(event) {
                partials.push(PartialMatch {
                    step: 1,
                    started_at: now,
                });
            }
        }

        alerts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Protocol;

    fn syn_event(ip: u32) -> NetworkEvent {
        NetworkEvent {
            timestamp_ms: 0,
            src_ip: ip,
            dst_ip: 99,
            src_port: 1111,
            dst_port: 80,
            protocol: Protocol::Tcp,
            flags: 0b0001,
            payload_sample: vec![],
        }
    }

    fn payload_event(ip: u32) -> NetworkEvent {
        NetworkEvent {
            timestamp_ms: 0,
            src_ip: ip,
            dst_ip: 99,
            src_port: 1111,
            dst_port: 80,
            protocol: Protocol::Tcp,
            flags: 0b0011,
            payload_sample: b"GET /../../etc/passwd".to_vec(),
        }
    }

    #[test]
    fn sequence_within_window_fires_alert() {
        let mut cep = CepEngine::with_default_rules();
        assert!(cep.process(&syn_event(42)).is_empty());
        let alerts = cep.process(&payload_event(42));
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_name, "probe-then-exploit-attempt");
    }

    #[test]
    fn different_source_does_not_cross_contaminate() {
        let mut cep = CepEngine::with_default_rules();
        assert!(cep.process(&syn_event(1)).is_empty());
        // different source sends the second step -- should NOT complete
        // source 1's partial match.
        let alerts = cep.process(&payload_event(2));
        assert!(alerts.is_empty());
    }

    #[test]
    fn single_out_of_order_event_does_not_fire() {
        let mut cep = CepEngine::with_default_rules();
        // payload-only event never satisfies step 0 (IsSynOnly), so no
        // partial match starts, so a lone step-2 event never completes.
        let alerts = cep.process(&payload_event(7));
        assert!(alerts.is_empty());
    }
}
