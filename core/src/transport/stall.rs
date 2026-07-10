//! Runtime stall detection for the multi-server pool (design:
//! `docs/superpowers/specs/2026-07-10-runtime-stall-detection-failover-design.md`). A `StallTracker`
//! records per-flow progress and reports outcomes (`record_stall` / `record_flow_ok`) to the pool via
//! `StallSink`. The stream + packet guards below wrap a member's I/O and drive the tracker.
#![cfg(feature = "multi-server")]

use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

/// The pool's per-member outcome recorder. Implemented by `SelectingTransport`.
pub(crate) trait StallSink: Send + Sync {
    /// A flow through `member` stalled (was active, then flatlined past the window).
    fn record_stall(&self, member: usize);
    /// A flow through `member` ended cleanly after being active (never stalled).
    fn record_flow_ok(&self, member: usize);
}

/// Per-flow progress state, shared (via `Arc`) by a flow's guard(s). Lock-free: a TCP flow has one
/// guard, a UDP flow has two (sink + source) that touch this concurrently.
pub(crate) struct StallTracker {
    sink: Arc<dyn StallSink>,
    member: usize,
    window: Duration,
    base: Instant,
    ever_active: AtomicBool,
    /// Millis since `base` of the last outbound byte/datagram (the UDP "still sending" gate).
    last_outbound_ms: AtomicU64,
    stalled: AtomicBool,
    done: AtomicBool,
}

impl StallTracker {
    pub(crate) fn new(sink: Arc<dyn StallSink>, member: usize, window: Duration) -> Arc<Self> {
        Arc::new(Self {
            sink,
            member,
            window,
            base: Instant::now(),
            ever_active: AtomicBool::new(false),
            last_outbound_ms: AtomicU64::new(0),
            stalled: AtomicBool::new(false),
            done: AtomicBool::new(false),
        })
    }

    fn elapsed_ms(&self) -> u64 {
        Instant::now().duration_since(self.base).as_millis() as u64
    }

    /// The flow has moved data and is now "active" (idle-from-start flows never set this).
    pub(crate) fn mark_active(&self) {
        self.ever_active.store(true, Ordering::Relaxed);
    }

    pub(crate) fn ever_active(&self) -> bool {
        self.ever_active.load(Ordering::Relaxed)
    }

    /// Record an outbound byte/datagram (updates the "recently sent" gate).
    pub(crate) fn mark_outbound(&self) {
        self.last_outbound_ms
            .store(self.elapsed_ms(), Ordering::Relaxed);
    }

    /// UDP gate: was there outbound activity within the last `window`? (i.e. the app is still trying,
    /// so inbound silence is a throttle rather than an idle flow).
    pub(crate) fn recently_sent(&self) -> bool {
        self.elapsed_ms()
            .saturating_sub(self.last_outbound_ms.load(Ordering::Relaxed))
            < self.window.as_millis() as u64
    }

    /// Report a stall to the pool exactly once, and return the error the guard surfaces to the pump.
    pub(crate) fn report_stall(&self) -> io::Error {
        if !self.stalled.swap(true, Ordering::Relaxed) {
            self.sink.record_stall(self.member);
        }
        io::Error::new(io::ErrorKind::TimedOut, "flow stalled")
    }
}

impl Drop for StallTracker {
    fn drop(&mut self) {
        // A flow that was active and never stalled ended cleanly — report it once.
        if self.ever_active.load(Ordering::Relaxed)
            && !self.stalled.load(Ordering::Relaxed)
            && !self.done.swap(true, Ordering::Relaxed)
        {
            self.sink.record_flow_ok(self.member);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    pub(super) struct RecordingSink {
        pub stalls: Mutex<Vec<usize>>,
        pub oks: Mutex<Vec<usize>>,
    }
    impl StallSink for RecordingSink {
        fn record_stall(&self, m: usize) {
            self.stalls.lock().unwrap().push(m);
        }
        fn record_flow_ok(&self, m: usize) {
            self.oks.lock().unwrap().push(m);
        }
    }

    #[tokio::test]
    async fn report_stall_is_once_and_suppresses_ok_on_drop() {
        let sink = Arc::new(RecordingSink::default());
        let t = StallTracker::new(sink.clone(), 2, Duration::from_secs(15));
        t.mark_active();
        let _ = t.report_stall();
        let _ = t.report_stall(); // second call is a no-op
        drop(t);
        assert_eq!(*sink.stalls.lock().unwrap(), vec![2]);
        assert!(
            sink.oks.lock().unwrap().is_empty(),
            "a stalled flow never reports ok"
        );
    }

    #[tokio::test]
    async fn clean_active_drop_reports_ok() {
        let sink = Arc::new(RecordingSink::default());
        let t = StallTracker::new(sink.clone(), 5, Duration::from_secs(15));
        t.mark_active();
        drop(t);
        assert_eq!(*sink.oks.lock().unwrap(), vec![5]);
    }

    #[tokio::test]
    async fn idle_from_start_drop_reports_nothing() {
        let sink = Arc::new(RecordingSink::default());
        let t = StallTracker::new(sink.clone(), 1, Duration::from_secs(15));
        drop(t); // never marked active
        assert!(sink.oks.lock().unwrap().is_empty());
        assert!(sink.stalls.lock().unwrap().is_empty());
    }
}
