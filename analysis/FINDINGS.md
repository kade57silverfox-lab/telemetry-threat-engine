# Findings: Telemetry & Alert Analysis

Analysis of a 45-second capture from a live run of the engine (`analysis/alerts.csv`,
`analysis/stats_timeseries.csv`, captured via `capture_telemetry.py`). Full
methodology and charts are in `analysis.ipynb`; this document is the summary
for someone who wants the conclusions without running code.

## Throughput

| Metric | Value |
|---|---|
| Mean events/sec | ~1,977 |
| p50 events/sec | ~1,993 |
| p99 events/sec | ~2,127 |
| Events dropped | 0 |

Zero drops across the capture window means the lock-free queue and 4 detection
workers kept pace with everything the ingestion layer produced at this rate.
**This is not a claim about the system's ceiling** — it's a single-process
build fed by an in-sandbox simulator, not a production deployment under real
line-rate traffic. See `docs/DESIGN.md` for what a real load-test benchmark
(saturating the queue deliberately, measuring p50/p99/p999 *latency* as well
as throughput) would need to add to make a defensible capacity claim.

## Alert breakdown

| Severity | Count |
|---|---|
| Critical | 4 |
| High | 3 |
| Medium | 3 |
| Low | 0 |

| Detector | Count |
|---|---|
| Signature | 6 |
| Anomaly | 4 |
| CEP | 0 |

The CEP detector (`probe-then-exploit-attempt`) didn't fire in this
particular 45-second window — its rule requires a SYN-only event *followed
by* a signature-bearing payload from the same source within 5 seconds, and
the simulator's independent injection schedules for those two patterns
(every 500 vs. every 733 ticks) didn't line up from the same source IP
during this capture. That's a property of the test data generator's
injection timing, not a bug in the CEP engine — the unit tests in
`engine/src/detection/cep.rs` cover the sequence-matching logic directly
and confirm it fires when the pattern is actually presented.

## On false-positive rate — what this analysis can't honestly claim

Every alert in this capture matches an attack pattern the simulator
deliberately injected, and every injected pattern was designed to trigger
exactly the rule that fired. That produces a 0% *observed* false-positive
rate, but presenting that number as validation would be misleading: there's
no benign traffic in this capture that *could* have triggered a false
positive to begin with.

A defensible false-positive-rate claim needs:
1. A labeled public dataset (e.g. CIC-IDS2017) with both benign and
   malicious flows, replayed through the real capture path via `tcpreplay`
2. Thresholds tuned against a training split, evaluated against a held-out
   split — not tuned and evaluated on the same data
3. Both false-positive and false-negative rates reported, since a detector
   tuned to zero FPs by making thresholds very high just means it also
   misses more real attacks

None of that exists yet in this project. Flagging that gap explicitly is
more useful than a chart that looks clean for the wrong reason.

## What would change the threshold values

Two hardcoded thresholds currently drive the anomaly detector
(`engine/src/detection/anomaly.rs`):
- `syn_flood_threshold = 50` (SYNs per source per 5s window)
- `port_scan_threshold = 25.0` (distinct destination ports per source per
  5s window)

These were picked to be clearly above what the simulator's *benign* traffic
generator produces (which never sends more than a handful of connections
per source) and clearly below what its *attack* injection produces (80 SYNs,
~40 ports). They have not been validated against real traffic's benign-case
variance — a legitimate NAT gateway or load balancer, for example, can
produce SYN rates from one apparent source IP that a home-network threshold
would misclassify. That's a known limitation, documented so it isn't
mistaken for a validated production threshold.
