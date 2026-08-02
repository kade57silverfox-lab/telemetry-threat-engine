//! Ingestion layer.
//!
//! In production this stage is an AF_XDP socket reading zero-copy frames
//! out of a UMEM ring that an eBPF/XDP program has already filtered
//! in-kernel (see `ebpf-reference/xdp_filter.c`). That requires root and a
//! real NIC/kernel, so this sandbox-friendly build swaps in a packet-event
//! generator that produces the same `NetworkEvent` struct at a configurable
//! rate, including injected attack patterns (SYN floods, port scans, a
//! known malicious payload signature) so the detection layer has real
//! signal to find.
//!
//! Everything downstream of this module (queue, detection, API) is
//! identical whether events come from here or from a real capture backend
//! -- that boundary is the whole point of the design.

use crate::models::{NetworkEvent, Protocol};
use rand::Rng;
use std::time::{SystemTime, UNIX_EPOCH};

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

pub struct Simulator {
    rng: rand::rngs::ThreadRng,
    tick: u64,
}

impl Simulator {
    pub fn new() -> Self {
        Self {
            rng: rand::thread_rng(),
            tick: 0,
        }
    }

    /// Produces a batch of events for one "tick". Roughly every 500 ticks
    /// we inject a burst that looks like a SYN flood, and occasionally a
    /// payload containing a known-bad byte signature, so the signature and
    /// anomaly detectors have real work to do end to end.
    pub fn next_batch(&mut self) -> Vec<NetworkEvent> {
        self.tick += 1;
        let mut events = Vec::new();
        let normal_count = self.rng.gen_range(20..60);

        for _ in 0..normal_count {
            events.push(self.benign_event());
        }

        // Inject a SYN flood burst periodically.
        if self.tick % 500 == 0 {
            let attacker_ip = self.rng.gen_range(0..255) as u32 | 0x0A00_0000; // 10.0.0.x
            for _ in 0..80 {
                events.push(NetworkEvent {
                    timestamp_ms: now_ms(),
                    src_ip: attacker_ip,
                    dst_ip: 0xC0A8_0101, // 192.168.1.1
                    src_port: self.rng.gen_range(1024..65535),
                    dst_port: 80,
                    protocol: Protocol::Tcp,
                    flags: 0b0001, // SYN only, no ACK
                    payload_sample: vec![],
                });
            }
        }

        // Inject a payload with a known-bad signature periodically.
        if self.tick % 733 == 0 {
            let mut evt = self.benign_event();
            evt.payload_sample = b"GET /../../etc/passwd HTTP/1.1".to_vec();
            events.push(evt);
        }

        // Inject a genuine probe-then-exploit sequence from ONE shared
        // source IP, so the CEP rule (SYN-only, then a signature payload,
        // from the same source, within 5s) is actually demonstrable.
        //
        // This was a real gap found during testing: the SYN-flood
        // injection above draws its attacker IP from a narrow 10.0.0.x
        // range, while the signature-payload injection draws from the
        // benign_event() helper''s full random u32 IP space -- so those two
        // event types could never share a source IP by construction. CEP
        // wasn''t "rarely" firing, it was structurally unable to fire at
        // all against this simulator''s traffic. This block fixes that by
        // explicitly modeling the two-step attack the rule is designed to
        // catch, using one shared IP for both steps.
        if self.tick % 900 == 0 {
            let prober_ip = self.rng.gen_range(0..255) as u32 | 0x0A00_0000;
            events.push(NetworkEvent {
                timestamp_ms: now_ms(),
                src_ip: prober_ip,
                dst_ip: 0xC0A8_0101,
                src_port: self.rng.gen_range(1024..65535),
                dst_port: 80,
                protocol: Protocol::Tcp,
                flags: 0b0001, // SYN only -- the "probe" step
                payload_sample: vec![],
            });
            events.push(NetworkEvent {
                timestamp_ms: now_ms(),
                src_ip: prober_ip, // SAME source as the probe above
                dst_ip: 0xC0A8_0101,
                src_port: self.rng.gen_range(1024..65535),
                dst_port: 80,
                protocol: Protocol::Tcp,
                flags: 0b0011,
                payload_sample: b"GET /../../etc/passwd HTTP/1.1".to_vec(), // the "exploit" step
            });
        }

        // Inject a port-scan pattern: one source hitting many destination
        // ports on the same target in quick succession.
        if self.tick % 611 == 0 {
            let scanner_ip = self.rng.gen_range(0..255) as u32 | 0x0A00_0000;
            for port in (1..40).map(|i| 1000 + i * 7) {
                events.push(NetworkEvent {
                    timestamp_ms: now_ms(),
                    src_ip: scanner_ip,
                    dst_ip: 0xC0A8_0101,
                    src_port: self.rng.gen_range(1024..65535),
                    dst_port: port,
                    protocol: Protocol::Tcp,
                    flags: 0b0001,
                    payload_sample: vec![],
                });
            }
        }

        events
    }

    fn benign_event(&mut self) -> NetworkEvent {
        NetworkEvent {
            timestamp_ms: now_ms(),
            src_ip: self.rng.gen_range(0..u32::MAX),
            dst_ip: 0xC0A8_0101,
            src_port: self.rng.gen_range(1024..65535),
            dst_port: *[80u16, 443, 22, 53].get(self.rng.gen_range(0..4)).unwrap(),
            protocol: Protocol::Tcp,
            flags: 0b0011, // SYN+ACK, normal handshake traffic
            payload_sample: b"GET /index.html HTTP/1.1".to_vec(),
        }
    }
}

impl Default for Simulator {
    fn default() -> Self {
        Self::new()
    }
}