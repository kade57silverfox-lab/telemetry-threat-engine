# Operations Runbook

Written for someone who did not build this system and is on call when
something goes wrong with it.

## Starting the engine

```bash
cd engine
cargo build --release
API_TOKEN=your-secret-token ./target/release/threat-engine
```

The engine binds `0.0.0.0:8080` and logs structured JSON to stdout. The
active `API_TOKEN` value is logged at startup — if you don't set the env
var, it falls back to `dev-token-change-me` (a dev-only default; **never
use the default in anything reachable outside your own machine**).

## Health checks

```bash
curl http://localhost:8080/health
```

Expected response:
```json
{"status":"ok","events_processed":123456,"events_dropped":0}
```

This endpoint is intentionally unauthenticated — a load balancer or
monitoring probe should never need a credential to check liveness. It's
also intentionally *not* just "is the process up": `events_processed`
increasing across repeated checks confirms the pipeline is making forward
progress, not just that the HTTP server is listening.

**A quick liveness check without extra tooling:**
```bash
watch -n 2 'curl -s http://localhost:8080/health'
```
If `events_processed` stops increasing between checks, the pipeline is
stalled even though the process is still running — see "Symptom: engine is
up but no events are being processed" below.

## Common failure symptoms and what to check

### Symptom: `events_dropped` is increasing

**Meaning:** the ingestion layer is producing events faster than the
detection workers can drain the queue — the queue is full and `push` is
failing (see `docs/DESIGN.md` §4 on the backpressure policy: events are
dropped, not blocked, when this happens).

**What to check:**
1. `curl http://localhost:8080/stats` — compare `events_processed` growth
   rate to `events_dropped` growth rate over a few seconds.
2. Check CPU usage of the process (`top`/`htop`) — if all worker threads
   are pegged at 100%, the detectors themselves are the bottleneck, not
   I/O.
3. Consider increasing `WORKER_COUNT` in `main.rs` if spare CPU cores are
   available, or increasing `QUEUE_CAPACITY` to absorb larger bursts
   (this buys time, not throughput — it doesn't fix a sustained overload).

### Symptom: engine is up but no events are being processed

**Meaning:** `events_processed` in `/stats` isn't increasing at all.

**What to check:**
1. Confirm the process is actually running: `ps aux | grep threat-engine`.
2. Check the logs for a panic (`RUST_BACKTRACE=1` when starting the engine
   gives a full trace if a worker thread panicked and died silently — a
   panicked thread in this build does not currently take down the whole
   process, which means the remaining workers keep running with reduced
   capacity, a real limitation worth flagging to engineering rather than
   silently living with).
3. Restart: kill the process and re-run the start command above.

### Symptom: dashboard shows "could not reach engine"

**What to check:**
1. Confirm the engine process is running and `/health` responds.
2. Confirm the API base URL entered in the dashboard's login screen
   matches where the engine is actually listening (default
   `http://localhost:8080`).
3. If the dashboard and engine are on different origins, confirm CORS
   isn't being blocked — the engine's API applies a permissive CORS layer
   by default (`api.rs`), so this is unlikely to be the issue in a default
   setup, but check browser devtools' network tab for a CORS error
   specifically if requests are failing silently.

### Symptom: dashboard login fails with a valid-looking token

**What to check:**
1. The token must match exactly what's logged at engine startup or set via
   `API_TOKEN` — copy-paste rather than retype to rule out a typo.
2. If the engine was restarted without `API_TOKEN` set, it falls back to
   the dev default, which may not match a token you'd previously set.

## Restarting a stalled worker

This build does not currently support restarting a single worker thread
independently — a stuck or panicked worker requires restarting the whole
process. `docs/DESIGN.md` §5 flags this as a known limitation; a production
version would supervise each worker thread and restart just the failed one
(e.g., via a supervisor pattern watching each thread's `JoinHandle`).

## Log format

All logs are structured JSON (via the `tracing` crate), one object per line,
suitable for shipping to any log aggregator that ingests JSON lines (e.g.
piping to `jq` locally, or a real log pipeline in production):

```bash
./target/release/threat-engine 2>&1 | jq .
```

Set `RUST_LOG=debug` for more verbose output if diagnosing an issue that
isn't visible at the default `info` level.
