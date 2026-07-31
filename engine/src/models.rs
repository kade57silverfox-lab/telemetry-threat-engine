//! Shared data types that flow through the engine.
//!
//! In production, `NetworkEvent` would be built from a real AF_XDP frame
//! (see `ebpf-reference/xdp_filter.c` for the kernel-side capture design).
//! Here it's produced by the simulator in `ingestion.rs`, but every
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

    /// Flow key used for sharding across workers: 5-tuple hash.
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
