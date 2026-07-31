# Threat Model

## Scope

This document covers what the engine is designed to detect, what's
explicitly out of scope, and the engine's own attack surface (a detection
system is itself a target).

## In scope: attacks the engine is designed to detect

| Attack | Detector | Mechanism | Confidence |
|---|---|---|---|
| SYN flood (volumetric DoS) | Anomaly | Count-Min Sketch estimated SYN count per source exceeds threshold in a 5s window | Medium — see limitations below |
| Port scan / reconnaissance | Anomaly | HyperLogLog estimated distinct destination ports per source exceeds threshold in a 5s window | Medium |
| Known exploit-attempt signatures (path traversal, SQLi, XSS markers, `cmd.exe`) | Signature | Aho-Corasick exact-match against a fixed pattern set on the payload sample | High for known patterns, zero for anything not in the pattern list |
| Probe-then-exploit sequence (recon followed by exploit attempt from the same source within a window) | CEP | NFA sequence matcher, correlates by source IP across a time window | Medium-High — correlation reduces false positives vs. either signal alone |

## Explicitly out of scope

- **Encrypted payload inspection.** The signature detector matches against
  `payload_sample`, a plaintext byte sample. TLS-encrypted exploit attempts
  are invisible to this detector entirely — a real deployment would need
  TLS termination/inspection (with its own separate privacy and legal
  considerations) or rely purely on metadata-based anomaly detection for
  encrypted traffic.
- **Novel/zero-day exploit patterns.** Signature detection only catches
  patterns already in the rule set (`signature.rs::with_default_rules`).
  This is a fundamental limitation of signature-based detection generally,
  not specific to this implementation — it's why the anomaly and CEP
  detectors exist alongside it.
- **Application-layer attacks that don't produce distinctive
  network-level signal** (e.g., business-logic abuse, credential stuffing
  at low-and-slow rates below the anomaly thresholds).
- **Attribution.** The engine reports the source IP the traffic claims to
  be from. It does not attempt to defeat IP spoofing or correlate against
  external threat intelligence to attribute an attack to a specific actor.

## The engine's own attack surface

A detection system is itself a target — an attacker who understands it can
try to blind, evade, or abuse it.

- **Threshold-aware evasion.** The SYN-flood threshold (50/window) and
  port-scan threshold (25 distinct ports/window) are fixed and, in this
  build, effectively public (they're in an open-source rule set). An
  attacker who knows the thresholds can stay just under them ("low and
  slow" scanning) and evade detection entirely. Mitigation for a real
  deployment: adaptive/statistical thresholds rather than fixed constants,
  and treating threshold values as sensitive configuration.
- **Resource-exhaustion against the detector itself.** The anomaly
  detector allocates a new `HyperLogLog` per distinct source IP
  (`port_cardinality: HashMap<u32, HyperLogLog>` in `anomaly.rs`). An
  attacker who spoofs a very large number of distinct source IPs, each
  sending only a few packets, could grow this map's memory use
  significantly within a single window before it resets. This is a real,
  currently-unmitigated limitation — a production version would cap the
  map's size (e.g., an LRU eviction policy) rather than let it grow
  unbounded per window.
- **API abuse.** The REST API (`api.rs`) is protected by a single shared
  bearer token (see `docs/DESIGN.md` §5 for why this is a demo-level
  choice, not production auth). A leaked token gives full read access to
  alert history and engine stats; there's no rate limiting on the API
  itself in this build.
- **The eBPF program's own correctness matters for security, not just
  performance.** `xdp_filter.c`'s bounds checks aren't just there to
  satisfy the verifier — a bug that under-checks and forwards a malformed
  packet the verifier didn't reject could crash or corrupt userspace state
  downstream. This is why every pointer dereference in that file is
  bounds-checked immediately before use, documented inline.

## Validation approach and its limits

`analysis/FINDINGS.md` covers this in detail: the current validation is
against the in-sandbox simulator's self-consistent injected patterns, which
produces a 0% observed false-positive rate that would be misleading to
present as validating detection accuracy against real traffic. A credible
validation pass needs a labeled dataset (CIC-IDS2017 or similar) with real
benign and malicious flows, replayed via `tcpreplay` through the actual
capture path, with thresholds tuned on a training split and evaluated on a
held-out split.
