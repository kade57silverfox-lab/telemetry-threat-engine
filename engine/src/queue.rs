//! A bounded, lock-free multi-producer multi-consumer (MPMC) ring buffer.
//!
//! This is a from-scratch implementation of the algorithm described by
//! Dmitry Vyukov ("Bounded MPMC queue"): each slot carries its own
//! sequence number, so producers and consumers coordinate using per-slot
//! atomics instead of a single global lock. No thread ever blocks another
//! thread; a full/empty queue causes a caller to back off and retry
//! (see `push`/`pop` return values), which is the explicit backpressure
//! decision documented in docs/DESIGN.md.
//!
//! This exists specifically so the "lock-free data structures" claim in
//! the project has a real, tested implementation behind it rather than
//! being satisfied by pulling in crossbeam and never looking further.

use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Slot<T> {
    sequence: AtomicUsize,
    value: UnsafeCell<Option<T>>,
}

pub struct MpmcQueue<T> {
    buffer: Box<[Slot<T>]>,
    mask: usize,
    enqueue_pos: AtomicUsize,
    dequeue_pos: AtomicUsize,
}

// Safety: access to `value` is gated by the `sequence` atomic protocol below,
// which guarantees exclusive access at the point of read/write.
unsafe impl<T: Send> Sync for MpmcQueue<T> {}
unsafe impl<T: Send> Send for MpmcQueue<T> {}

impl<T> MpmcQueue<T> {
    /// `capacity` must be a power of two.
    pub fn new(capacity: usize) -> Self {
        assert!(capacity.is_power_of_two(), "capacity must be a power of two");
        let buffer: Vec<Slot<T>> = (0..capacity)
            .map(|i| Slot {
                sequence: AtomicUsize::new(i),
                value: UnsafeCell::new(None),
            })
            .collect();

        Self {
            buffer: buffer.into_boxed_slice(),
            mask: capacity - 1,
            enqueue_pos: AtomicUsize::new(0),
            dequeue_pos: AtomicUsize::new(0),
        }
    }

    /// Returns `Err(item)` if the queue is currently full (caller decides:
    /// drop, sample, spill to disk -- this is the backpressure policy).
    pub fn push(&self, item: T) -> Result<(), T> {
        let mut pos = self.enqueue_pos.load(Ordering::Relaxed);
        loop {
            let slot = &self.buffer[pos & self.mask];
            let seq = slot.sequence.load(Ordering::Acquire);
            let diff = seq as isize - pos as isize;

            if diff == 0 {
                match self.enqueue_pos.compare_exchange_weak(
                    pos,
                    pos + 1,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        unsafe { *slot.value.get() = Some(item) };
                        slot.sequence.store(pos + 1, Ordering::Release);
                        return Ok(());
                    }
                    Err(cur) => pos = cur,
                }
            } else if diff < 0 {
                return Err(item); // full
            } else {
                pos = self.enqueue_pos.load(Ordering::Relaxed);
            }
        }
    }

    /// Returns `None` if the queue is currently empty.
    pub fn pop(&self) -> Option<T> {
        let mut pos = self.dequeue_pos.load(Ordering::Relaxed);
        loop {
            let slot = &self.buffer[pos & self.mask];
            let seq = slot.sequence.load(Ordering::Acquire);
            let diff = seq as isize - (pos as isize + 1);

            if diff == 0 {
                match self.dequeue_pos.compare_exchange_weak(
                    pos,
                    pos + 1,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        let item = unsafe { (*slot.value.get()).take() };
                        slot.sequence.store(pos + self.mask + 1, Ordering::Release);
                        return item;
                    }
                    Err(cur) => pos = cur,
                }
            } else if diff < 0 {
                return None; // empty
            } else {
                pos = self.dequeue_pos.load(Ordering::Relaxed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn push_pop_single_thread() {
        let q: MpmcQueue<u32> = MpmcQueue::new(4);
        assert!(q.push(1).is_ok());
        assert!(q.push(2).is_ok());
        assert_eq!(q.pop(), Some(1));
        assert_eq!(q.pop(), Some(2));
        assert_eq!(q.pop(), None);
    }

    #[test]
    fn rejects_when_full() {
        let q: MpmcQueue<u32> = MpmcQueue::new(2);
        assert!(q.push(1).is_ok());
        assert!(q.push(2).is_ok());
        assert_eq!(q.push(3), Err(3));
    }

    /// Stress test: N producers push a known total count of unique items,
    /// M consumers drain them concurrently. If the algorithm has a race,
    /// this either loses items (final count mismatch) or double-delivers
    /// them (duplicate detection) -- run under `cargo test -- --nocapture`
    /// and, in CI, under `cargo test` built with ThreadSanitizer for a
    /// stronger guarantee than what a single run can prove.
    #[test]
    fn concurrent_stress_no_lost_or_duplicated_items() {
        const PRODUCERS: usize = 8;
        const PER_PRODUCER: usize = 20_000;
        const TOTAL: usize = PRODUCERS * PER_PRODUCER;

        let q = Arc::new(MpmcQueue::<usize>::new(1 << 16));
        let mut handles = vec![];

        for p in 0..PRODUCERS {
            let q = Arc::clone(&q);
            handles.push(thread::spawn(move || {
                for i in 0..PER_PRODUCER {
                    let item = p * PER_PRODUCER + i;
                    loop {
                        if q.push(item).is_ok() {
                            break;
                        }
                        thread::yield_now(); // backpressure: retry, don't block
                    }
                }
            }));
        }

        // NOTE: an earlier version of this test had each consumer exit once
        // *it individually* had popped roughly TOTAL/4 items. That assumes
        // consumers get an even share of the work, which the queue never
        // promises -- a slow thread can legitimately pop far fewer than its
        // "share" while a fast one pops far more. Under that assumption the
        // test would occasionally hang forever (a consumer waiting for
        // items that its siblings already drained). The correct termination
        // condition is global, not per-consumer: stop once every producer
        // has finished AND the shared total-popped count has reached TOTAL.
        let seen = Arc::new(std::sync::Mutex::new(vec![false; TOTAL]));
        let total_popped = Arc::new(AtomicUsize::new(0));
        let producers_done = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let mut consumer_handles = vec![];
        for _ in 0..4 {
            let q = Arc::clone(&q);
            let seen = Arc::clone(&seen);
            let total_popped = Arc::clone(&total_popped);
            let producers_done = Arc::clone(&producers_done);
            consumer_handles.push(thread::spawn(move || loop {
                match q.pop() {
                    Some(item) => {
                        let mut g = seen.lock().unwrap();
                        assert!(!g[item], "item {item} delivered twice");
                        g[item] = true;
                        drop(g);
                        total_popped.fetch_add(1, Ordering::Relaxed);
                    }
                    None => {
                        if producers_done.load(Ordering::Acquire)
                            && total_popped.load(Ordering::Acquire) >= TOTAL
                        {
                            break;
                        }
                        thread::yield_now();
                    }
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }
        producers_done.store(true, Ordering::Release);

        for h in consumer_handles {
            h.join().unwrap();
        }

        let g = seen.lock().unwrap();
        let total_seen = g.iter().filter(|b| **b).count();
        assert_eq!(total_seen, TOTAL, "lost or duplicated items under concurrency");
    }
}
