# Design Doc: High-Frequency Real-Time Telemetry & Threat Engine

## 1. Problem statement

Detect ongoing network-based attacks (SYN floods, port scans, known
exploit-attempt signatures, and multi-step probe-then-exploit sequences) in
real time, at a target throughput of "millions of events/sec" in the stated
production goal, with sub-second detection latency and bounded memory
regardless of how many distinct hosts are being observed.

**Constraints:**
- Detection must not require an exact count per observed IP (memory would
  grow unboundedly with the number of distinct sources)
- A slow detector or a burst of traffic must not be able to block or crash
  the capture path — backpressure must be an explicit, chosen policy, not
  an accident
- The system must be operable by someone other than its author (see
  `RUNBOOK.md`)

## 2. Architecture

```
 [NIC] -> [eBPF/XDP: early filter] -> [AF_XDP UMEM: zero-copy ring]
                                              |
                                    [ingestion.rs: capture thread]
                                              |
                                  [queue.rs: lock-free MPMC ring buffer]
                                        /       |        \
                              [worker 1]  [worker 2] ... [worker N]
                                   |            |             |
                       [signature.rs] [anomaly.rs] [cep.rs]  (each worker runs all three)
                                        \       |        /
                                       [AppState: alert store]
                                              |
                                    [api.rs: authenticated REST API]
                                              |
                                  [dashboard/index.html: triage console]
```

Everything from the queue onward is identical whether events originate from
the real eBPF/AF_XDP capture path or, as in this sandboxed build, from
`ingestion.rs`'s simulator. That boundary — `NetworkEvent` structs flowing
into the queue — is the seam the whole design is organized around.

## 3. Alternatives considered and rejected

**Why not just use Kafka + Flink/ksqlDB for everything?**
In a real production deployment, this is honestly the right answer for most
companies — mature, battle-tested, horizontally scalable out of the box.
This project exists to demonstrate understanding of what those systems do
*underneath*: the lock-free queue is what a Kafka broker's internals and
Flink's network stack are built on top of; the CEP engine is a small,
from-scratch version of what Flink CEP or Esper provide as a library. The
value of building it here is depth of understanding, not a claim that this
should replace Flink in production.

**Why a hand-rolled MPMC queue instead of `crossbeam::channel` or
`crossbeam::queue::ArrayQueue`?**
`crossbeam` is used elsewhere in this codebase and would be the pragmatic
choice for a real system. The queue in `queue.rs` is hand-built specifically
so the "lock-free data structures" claim has real, tested code behind it,
including a concurrency stress test — not a claim resting on "I imported a
crate that says lock-free in its docs."

**Why per-worker detector state instead of sharding by flow key?**
The current build gives every worker its own `WindowedAnomalyDetector` and
`CepEngine` instance, and any worker can pop any event off the shared queue.
This is a real limitation: a SYN flood from one source could get split
across workers, with each worker's Count-Min Sketch seeing only part of the
picture, understating the true count. The correct fix — hash each event by
`NetworkEvent::flow_key()` (already implemented in `models.rs`, currently
unused — see the dead-code warning on `cargo build`) and route it to a
specific worker via a per-worker queue instead of one shared queue — is
scoped out of this build for time, and documented here rather than silently
left as an unexplained gap.

**Why AF_XDP instead of a raw socket or `libpcap`?**
A raw socket or libpcap still copies every packet through the kernel's
normal network stack before userspace sees it. AF_XDP's UMEM ring is
memory-mapped and shared between kernel and userspace, so packets that
survive the in-kernel XDP filter reach userspace with zero copies. This is
the concrete mechanism behind the "memory-mapped files" claim in the
project brief — see `engine/ebpf-reference/xdp_filter.c` for the real
program and why it can't run in this sandbox (needs root + a NIC).

## 4. Backpressure policy

`queue.rs::push` returns `Err(item)` when the ring buffer is full.
`pipeline.rs::spawn_producer` treats this as: increment a dropped-events
counter and discard the event. This is a deliberate choice, not an
oversight — the alternative (block the capture thread until space frees up)
would let a slow detector stall packet capture itself, which is worse than
losing a few events during a burst. A production system under this same
constraint would more likely spill overflow to a disk-backed log for later
replay rather than dropping outright; that's flagged here as the next
increment on this decision, not implemented in this build.

## 5. Known limitations (stated explicitly, not hidden)

- **No flow-key sharding** (see above) — anomaly/CEP state can be split
  across workers, understating true per-source counts under high
  concurrency.
- **No real load-test benchmark.** The `/stats` endpoint and
  `analysis/FINDINGS.md` report what was *observed* against the in-sandbox
  simulator's injection rate (~2,000 events/sec), not a deliberate
  saturation test measuring p50/p99/p999 latency at the queue's actual
  ceiling. A real benchmark harness (a standalone load generator pushing
  directly into the queue at increasing rates until drops appear) is the
  next concrete step to make a defensible throughput claim.
- **No distributed sharding across nodes** — this build is a single
  process with N worker threads, not a multi-node deployment with
  consistent hashing across shards. The 5-tuple `flow_key()` hash exists
  and is the basis a real sharding scheme would use, but no inter-node
  transport (Kafka/NATS) is wired up here.
- **Single shared bearer token for API auth**, not per-user accounts or
  RBAC — sufficient to make the "authenticated admin panel" claim real and
  demonstrable, not a claim that this ships production-grade auth.
- **Detection thresholds are illustrative, not validated** — see
  `analysis/FINDINGS.md`'s discussion of what a labeled-dataset validation
  pass would require.

## 6. Testing

- `queue.rs`: single-thread correctness tests, a full/empty boundary test,
  and a concurrency stress test (8 producers x 20,000 items, 4 consumers)
  that would fail on either lost or double-delivered items under a race.
  This test previously had a broken exit condition that could hang — fixed
  during this build; see the comment in that test for the failure mode and
  why the fix is correct.
- `signature.rs`: detects a known-bad payload, confirms a benign payload
  produces no alerts. Also caught a real bug during this build: the
  detector originally used Aho-Corasick's non-overlapping search, which
  silently dropped a match when two signatures shared bytes in the same
  payload (`"../../"` and `"/etc/passwd"` overlap in
  `"../../etc/passwd"`) — fixed by switching to overlapping search.
- `anomaly.rs`: confirms Count-Min Sketch never undercounts, and
  HyperLogLog's cardinality estimate stays within expected error bounds.
- `cep.rs`: confirms a sequence completes within its window, confirms
  different sources don't cross-contaminate partial matches, confirms an
  out-of-order lone event never fires.
