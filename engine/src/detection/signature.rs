//! Signature-based detection using Aho-Corasick multi-pattern matching.
//!
//! The naive approach -- checking each packet payload against every known
//! signature one at a time -- is O(patterns) per packet. Aho-Corasick
//! builds a single automaton from *all* signatures up front, so matching
//! is O(payload length) per packet regardless of how many signatures exist.
//! This is the same technique Snort/Suricata use for content matching.

use crate::models::{Alert, DetectorKind, NetworkEvent, Severity};
use aho_corasick::AhoCorasick;

pub struct SignatureDetector {
    automaton: AhoCorasick,
    rule_names: Vec<String>,
    severities: Vec<Severity>,
    next_id: std::sync::atomic::AtomicU64,
}

impl SignatureDetector {
    /// Build the automaton from a fixed rule set. In a real deployment
    /// these rules would be loaded from the rules API (see api.rs) and the
    /// automaton rebuilt when the rule set changes.
    pub fn with_default_rules() -> Self {
        let patterns: Vec<&str> = vec![
            "/etc/passwd",
            "UNION SELECT",
            "<script>alert(",
            "cmd.exe",
            "../../",
        ];
        let names = vec![
            "path-traversal-passwd".to_string(),
            "sql-injection-union".to_string(),
            "xss-script-tag".to_string(),
            "windows-cmd-exec".to_string(),
            "path-traversal-generic".to_string(),
        ];
        let severities = vec![
            Severity::High,
            Severity::High,
            Severity::Medium,
            Severity::Critical,
            Severity::Medium,
        ];

        let automaton = AhoCorasick::new(&patterns).expect("valid pattern set");

        Self {
            automaton,
            rule_names: names,
            severities,
            next_id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    pub fn scan(&self, event: &NetworkEvent) -> Vec<Alert> {
        if event.payload_sample.is_empty() {
            return vec![];
        }
        let mut alerts = Vec::new();
        // Overlapping search, not `find_iter`'s non-overlapping leftmost-first
        // scan: a real payload can legitimately match two signatures whose
        // spans share bytes (e.g. "../../" and "/etc/passwd" overlap at the
        // slash in "../../etc/passwd"). Non-overlapping search would resume
        // scanning past the first match's end and silently miss the second,
        // which is exactly the kind of false negative a NIDS can't afford.
        for m in self.automaton.find_overlapping_iter(&event.payload_sample) {
            let idx = m.pattern().as_usize();
            let id = self.next_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            alerts.push(Alert {
                id,
                timestamp_ms: event.timestamp_ms,
                rule_name: self.rule_names[idx].clone(),
                severity: self.severities[idx],
                src_ip: event.src_ip_str(),
                dst_ip: event.dst_ip_str(),
                detail: format!(
                    "signature match for rule '{}' in payload sample",
                    self.rule_names[idx]
                ),
                detector: DetectorKind::Signature,
            });
        }
        alerts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Protocol;

    fn evt(payload: &str) -> NetworkEvent {
        NetworkEvent {
            timestamp_ms: 0,
            src_ip: 1,
            dst_ip: 2,
            src_port: 1234,
            dst_port: 80,
            protocol: Protocol::Tcp,
            flags: 0,
            payload_sample: payload.as_bytes().to_vec(),
        }
    }

    #[test]
    fn detects_path_traversal() {
        let d = SignatureDetector::with_default_rules();
        let alerts = d.scan(&evt("GET /../../etc/passwd HTTP/1.1"));
        assert!(alerts.iter().any(|a| a.rule_name == "path-traversal-passwd"));
    }

    #[test]
    fn benign_payload_produces_no_alerts() {
        let d = SignatureDetector::with_default_rules();
        let alerts = d.scan(&evt("GET /index.html HTTP/1.1"));
        assert!(alerts.is_empty());
    }
}
