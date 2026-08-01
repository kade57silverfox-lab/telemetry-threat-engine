//! Shared data types that flow through the engine.
//!
//! In production, `NetworkEvent` would be built from a real AF_XDP frame
//! (see `ebpf-reference/xdp_filter.c` for the kernel-side capture design).
//! Here it''s produced by the simulator in `ingestion.rs`, but every
//! downstream stage (queue, detection, API) is written against this same
//! struct, so swapping the simulator for a real capture backend does not
//! change anything past `ingestion.rs`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub timestamp_ms: i64,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
    /// TCP flags packed as bits: SYN=1, ACK=2, FIN=4, RST=8
    pub flags: u8,
    /// Truncated payload sample used for signature scanning (like a real
    /// NIDS, we only inspect the first N bytes for cost reasons).
    pub payload_sample: Vec<u8>,
}

impl NetworkEvent {
    pub fn is_syn(&self) -> bool {
        self.flags & 0b0001 != 0 && self.flags & 0b0010 == 0
    }

    pub fn src_ip_str(&self) -> String {
        ip_to_string(self.src_ip)
    }

    pub fn dst_ip_str(&self) -> String {
        ip_to_string(self.dst_ip)
    }

    /// Flow key: 5-tuple hash identifying a specific connection/session.
    /// Not used for worker sharding (see `shard_key` below for why) --
    /// kept as public API for a future per-connection feature (e.g.
    /// deduplicating alerts for the same exact connection), since it''s a
    /// meaningfully different concept from `shard_key` and removing it
    /// would make `NetworkEvent` less capable than it should be.
    #[allow(dead_code)]
    pub fn flow_key(&self) -> u64 {
        let mut h: u64 = 1469598103934665603; // FNV offset basis
        for b in [
            (self.src_ip >> 24) as u8,
            (self.src_ip >> 16) as u8,
            (self.src_ip >> 8) as u8,
            self.src_ip as u8,
            (self.dst_ip >> 24) as u8,
            (self.dst_ip >> 16) as u8,
            (self.dst_ip >> 8) as u8,
            self.dst_ip as u8,
            (self.src_port >> 8) as u8,
            self.src_port as u8,
            (self.dst_port >> 8) as u8,
            self.dst_port as u8,
        ] {
            h ^= b as u64;
            h = h.wrapping_mul(1099511628211); // FNV prime
        }
        h
    }

    /// Sharding key used to route events to worker queues: hashes
    /// `src_ip` ONLY, not the full 5-tuple.
    ///
    /// This matters concretely: a SYN flood or port scan from one source
    /// varies its source port on every packet (real attacks do this too --
    /// each connection attempt gets a fresh ephemeral port). If sharding
    /// used the full 5-tuple (`flow_key`), each packet from the same
    /// attacker would hash to a effectively random worker, scattering one
    /// source''s burst across every worker''s independent sketch/counter --
    /// so no single worker''s count would ever cross the anomaly threshold,
    /// even though the aggregate traffic clearly should. This was a real
    /// bug caught during testing: after switching to flow_key-based
    /// sharding for correctness, the SYN-flood and port-scan detectors
    /// stopped firing entirely, because their whole point is aggregating
    /// "how much has this source IP done", which requires every packet
    /// from that source to land on the same worker regardless of port.
    /// `shard_key` fixes this by hashing only `src_ip`.
    pub fn shard_key(&self) -> u64 {
        let mut h: u64 = 1469598103934665603; // FNV offset basis
        for b in [
            (self.src_ip >> 24) as u8,
            (self.src_ip >> 16) as u8,
            (self.src_ip >> 8) as u8,
            self.src_ip as u8,
        ] {
            h ^= b as u64;
            h = h.wrapping_mul(1099511628211); // FNV prime
        }
        h
    }
}

pub fn ip_to_string(ip: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 8) & 0xFF,
        ip & 0xFF
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: u64,
    pub timestamp_ms: i64,
    pub rule_name: String,
    pub severity: Severity,
    pub src_ip: String,
    pub dst_ip: String,
    pub detail: String,
    pub detector: DetectorKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectorKind {
    Signature,
    Anomaly,
    Cep,
}