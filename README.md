# High-Frequency Real-Time Telemetry & Threat Engine

A distributed stream-processing engine that ingests network events, runs
complex event processing (CEP) alongside signature and statistical anomaly
detection to identify ongoing attacks in real time, and exposes both an
authenticated API and a triage dashboard for operators.

This project is built and organized as one system passing through seven
distinct engineering disciplines — each with its own real, checkable
deliverable rather than a label attached to the same code three times. See
`docs/` for the write-ups; see below for where each role's evidence lives.

## Honest scope note

Kernel-level packet capture (eBPF/AF_XDP) needs root privileges, a real NIC,
and kernel headers — unavailable in a sandboxed dev container. The real
eBPF/XDP program is included and documented (`engine/ebpf-reference/`);
the running system uses an in-process event simulator
(`engine/src/ingestion.rs`) that produces identical `NetworkEvent` structs,
so every downstream stage — queue, detectors, API, dashboard — is exactly
what would run against real captured traffic. This tradeoff, and everything
else scoped out for time, is documented explicitly in `docs/DESIGN.md`
rather than glossed over.

## Quick start

```bash
cd engine
cargo build --release
API_TOKEN=your-secret-token ./target/release/threat-engine
```

The engine starts producing simulated traffic (including periodic injected
attacks: SYN floods, port scans, path-traversal/SQLi signature payloads, and
a probe-then-exploit sequence) and serves an API on `:8080`. Then open
`dashboard/index.html` in a browser, enter the API base URL and the token
printed in the engine's startup log, and watch alerts arrive live.

Or with Docker:
```bash
cd ops
API_TOKEN=your-secret-token docker compose up --build
```
Dashboard at `http://localhost:8081`, API at `http://localhost:8080`.

## Where each role's work lives

| Role | Deliverable |
|---|---|
| **Software Engineer** | `engine/src/queue.rs` (lock-free MPMC ring buffer, concurrency-stress-tested), `engine/src/detection/cep.rs` (NFA sequence matcher), `docs/DESIGN.md` (architecture, alternatives rejected, known limitations stated explicitly) |
| **Software Developer** | `engine/src/api.rs` (authenticated REST API), `ops/.github/workflows/ci.yml` (build/lint/test/package pipeline), `ops/Dockerfile` |
| **Data Analyst** | `analysis/analysis.ipynb` + `analysis/FINDINGS.md` — real captured telemetry (not synthetic), throughput/severity/detector charts, and an explicit discussion of what this analysis can't honestly claim about false-positive rate |
| **Cybersecurity** | `docs/THREAT_MODEL.md` (in/out of scope, the engine's own attack surface), `engine/src/detection/signature.rs` (Aho-Corasick) + `anomaly.rs` (Count-Min Sketch, HyperLogLog) |
| **IT Support** | `docs/RUNBOOK.md` — symptom-based troubleshooting, health-check semantics, log format |
| **Full-Stack** | `dashboard/index.html` — authenticated (bearer token via `/login`), wired live to the API, backed by the sharded engine |
| **UI/UX Research & Design** | `docs/UX_RESEARCH.md` — user/task framing, the v1→v2 design iteration, and the reasoning (pre-attentive color coding, progressive disclosure, canvas-vs-DOM performance) behind the triage layout |

## Repository layout

```
engine/               Rust workspace: core pipeline, detectors, API
  src/
    queue.rs           Lock-free MPMC ring buffer
    ingestion.rs        Event simulator (stand-in for AF_XDP capture)
    pipeline.rs         Wiring: producer -> sharded queues -> workers -> alerts
    models.rs           NetworkEvent, Alert, flow_key() hashing
    detection/
      signature.rs       Aho-Corasick signature matching
      anomaly.rs         Count-Min Sketch + HyperLogLog anomaly detection
      cep.rs             NFA-based complex event processing
    api.rs               Authenticated REST API (axum)
  ebpf-reference/
    xdp_filter.c         Real eBPF/XDP program (reference; doesn't run in-sandbox)
dashboard/
  index.html             Authenticated SOC triage console (single file)
analysis/
  capture_telemetry.py   Polls the live engine, writes real telemetry to CSV
  analyze_alerts.py       Throughput/severity/detector analysis + charts
  analysis.ipynb          Notebook deliverable
  FINDINGS.md             Written findings report
docs/
  DESIGN.md              Architecture, alternatives, known limitations
  THREAT_MODEL.md        What's detected, what isn't, the engine's own attack surface
  RUNBOOK.md             Operations: health checks, common failures, fixes
  UX_RESEARCH.md         User research and design rationale for the dashboard
ops/
  Dockerfile
  docker-compose.yml
  .github/workflows/ci.yml
```

## What's actually verified vs. what's a documented gap

Verified by running it: all 10 unit/stress tests pass; the engine runs live
and fires real alerts (SYN flood, path traversal, both signature patterns
correctly detected after fixing an overlapping-match bug); the dashboard's
exact API calls were tested against the live engine; the auth flow
(401 → login → 200) works; the analysis notebook runs on real captured data,
not synthetic data.

Documented as a known gap rather than hidden: no real load-test benchmark
establishing an actual throughput ceiling; no multi-node distribution;
single shared API token instead of per-user auth; detection thresholds are
illustrative, not validated against a labeled real-world dataset. All of
these are called out specifically in `docs/DESIGN.md` §5 and
`analysis/FINDINGS.md`, with what a real next step would look like for each.
