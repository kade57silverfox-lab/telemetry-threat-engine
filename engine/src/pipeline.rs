//! Wires the stages together: ingestion -> per-worker lock-free queues ->
//! N detection workers -> shared alert store. This module is the concrete
//! answer to "how does backpressure work": a producer's `push` can fail if
//! a worker falls behind, and the policy for that (drop vs. block vs.
//! spill) is decided explicitly right here, not left implicit.
//!
//! Sharding: each worker owns its own queue and its own stateful detector
//! instances (`WindowedAnomalyDetector`, `CepEngine`). The producer routes
//! every event by `NetworkEvent::flow_key()` hashed down to a worker index,
//! so a given source IP's traffic always lands on the same worker -- this
//! is what makes the anomaly/CEP detectors' per-source counters accurate
//! under concurrency, instead of being split across workers and each
//! seeing only a fraction of one source's traffic (the earlier version of
//! this module had exactly that bug: one shared queue any worker could pop
//! from, so a SYN flood from one IP could be undercounted by being spread
//! across multiple workers' independent sketches).

use crate::detection::{anomaly::WindowedAnomalyDetector, cep::CepEngine, signature::SignatureDetector};
use crate::ingestion::Simulator;
use crate::models::{Alert, NetworkEvent};
use crate::queue::MpmcQueue;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct Stats {
    pub events_processed: AtomicU64,
    pub events_dropped: AtomicU64,
    pub alerts_fired: AtomicU64,
}

impl Default for Stats {
    fn default() -> Self {
        Self {
            events_processed: AtomicU64::new(0),
            events_dropped: AtomicU64::new(0),
            alerts_fired: AtomicU64::new(0),
        }
    }
}

const ALERT_HISTORY_CAP: usize = 5000;

pub struct AppState {
    /// One queue per worker (not one shared queue) -- see module docs for
    /// why sharding by flow key requires this instead of a single queue
    /// any worker could pop from.
    pub queues: Vec<Arc<MpmcQueue<NetworkEvent>>>,
    pub alerts: Mutex<VecDeque<Alert>>,
    pub stats: Stats,
}

impl AppState {
    pub fn new(worker_count: usize, queue_capacity: usize) -> Self {
        let queues = (0..worker_count)
            .map(|_| Arc::new(MpmcQueue::new(queue_capacity)))
            .collect();
        Self {
            queues,
            alerts: Mutex::new(VecDeque::new()),
            stats: Stats::default(),
        }
    }

    pub fn record_alert(&self, alert: Alert) {
        self.stats.alerts_fired.fetch_add(1, Ordering::Relaxed);
        let mut alerts = self.alerts.lock().expect("alert store poisoned");
        alerts.push_back(alert);
        if alerts.len() > ALERT_HISTORY_CAP {
            alerts.pop_front();
        }
    }
}

/// Spawns the producer (ingestion simulator) thread. In production this
/// thread is replaced by the AF_XDP reader loop; the per-worker queues it
/// routes into are unchanged.
pub fn spawn_producer(state: Arc<AppState>) {
    std::thread::spawn(move || {
        let mut sim = Simulator::new();
        let worker_count = state.queues.len();
        loop {
            for event in sim.next_batch() {
                let shard = (event.flow_key() as usize) % worker_count;
                match state.queues[shard].push(event) {
                    Ok(()) => {}
                    Err(_dropped) => {
                        // Explicit backpressure policy: drop under sustained
                        // overload rather than block the capture thread.
                        // A production system might instead spill to a
                        // disk-backed overflow log for later replay.
                        state.stats.events_dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    });
}

/// Spawns one detection worker thread per queue in `state.queues`. Each
/// worker owns its own `WindowedAnomalyDetector` and `CepEngine` instance,
/// which is now correct rather than approximate: because the producer
/// routes by flow_key, every event for a given source IP is guaranteed to
/// reach this same worker's queue, so its per-source sketches and partial
/// CEP matches see that source's complete traffic.
pub fn spawn_workers(state: Arc<AppState>) {
    for worker_idx in 0..state.queues.len() {
        let state = Arc::clone(&state);
        std::thread::spawn(move || {
            let queue = Arc::clone(&state.queues[worker_idx]);
            let sig = SignatureDetector::with_default_rules();
            let mut anomaly = WindowedAnomalyDetector::new(Duration::from_secs(5));
            let mut cep = CepEngine::with_default_rules();

            loop {
                match queue.pop() {
                    Some(event) => {
                        state.stats.events_processed.fetch_add(1, Ordering::Relaxed);

                        for alert in sig.scan(&event) {
                            state.record_alert(alert);
                        }
                        for alert in anomaly.observe(&event) {
                            state.record_alert(alert);
                        }
                        for alert in cep.process(&event) {
                            state.record_alert(alert);
                        }
                    }
                    None => std::thread::sleep(Duration::from_millis(5)),
                }
            }
        });
    }
}
