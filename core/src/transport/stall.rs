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
#[allow(dead_code)] // wired in Task 5 (SelectingTransport)
pub(crate) trait StallSink: Send + Sync {
    /// A flow through `member` stalled (was active, then flatlined past the window).
    fn record_stall(&self, member: usize);
    /// A flow through `member` ended cleanly after being active (never stalled).
    fn record_flow_ok(&self, member: usize);
}

/// Per-flow progress state, shared (via `Arc`) by a flow's guard(s). Lock-free: a TCP flow has one
/// guard, a UDP flow has two (sink + source) that touch this concurrently.
#[allow(dead_code)] // wired in Task 5 (SelectingTransport)
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

#[allow(dead_code)] // wired in Task 5 (SelectingTransport)
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

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{sleep, Sleep};

/// Wraps a member's TCP stream. Any read/write is progress and resets a `Sleep(window)`; if the sleep
/// fires while the flow is `ever_active` (no progress in *either* direction for the window), it reports
/// a stall and errors so `copy_bidirectional` ends and the flow resets. `S: Unpin` (all `BoxedStream`s
/// are), so we project via `get_mut`.
#[allow(dead_code)] // wired in Task 5 (SelectingTransport)
pub(crate) struct StreamStallGuard<S> {
    inner: S,
    tracker: Arc<StallTracker>,
    window: Duration,
    deadline: Pin<Box<Sleep>>,
    armed: bool,
}

#[allow(dead_code)] // wired in Task 5 (SelectingTransport)
impl<S> StreamStallGuard<S> {
    pub(crate) fn new(inner: S, tracker: Arc<StallTracker>, window: Duration) -> Self {
        Self {
            inner,
            tracker,
            window,
            deadline: Box::pin(sleep(window)),
            armed: false,
        }
    }

    /// Note progress in either direction: mark active, and reset the idle deadline.
    fn on_progress(&mut self) {
        self.tracker.mark_active();
        self.armed = true;
        self.deadline.as_mut().reset(Instant::now() + self.window);
    }

    /// Poll the idle deadline when the inner I/O is Pending. Fires a stall once armed.
    fn poll_deadline<T>(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<T>> {
        if !self.armed {
            return Poll::Pending; // never fire before the flow was ever active
        }
        match self.deadline.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(Err(self.tracker.report_stall())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for StreamStallGuard<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                if buf.filled().len() > before {
                    this.on_progress();
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => this.poll_deadline(cx),
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for StreamStallGuard<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, data) {
            Poll::Ready(Ok(n)) => {
                if n > 0 {
                    this.on_progress();
                }
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => this.poll_deadline(cx),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
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

    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};

    #[tokio::test(start_paused = true)]
    async fn stream_guard_fires_after_active_then_silent() {
        let sink = Arc::new(RecordingSink::default());
        let tracker = StallTracker::new(sink.clone(), 7, Duration::from_secs(15));
        // `peer` feeds the guarded side; we send one byte (activity), then go silent.
        let (mut peer, inner): (DuplexStream, DuplexStream) = duplex(64);
        let mut guard = StreamStallGuard::new(inner, tracker, Duration::from_secs(15));
        peer.write_all(b"x").await.unwrap();
        let mut b = [0u8; 8];
        assert_eq!(guard.read(&mut b).await.unwrap(), 1); // progress → armed
                                                          // Now silent. Advance past the window; the next read must surface a stall error.
        tokio::time::advance(Duration::from_secs(16)).await;
        let err = guard.read(&mut b).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert_eq!(*sink.stalls.lock().unwrap(), vec![7]);
    }

    #[tokio::test(start_paused = true)]
    async fn stream_guard_idle_from_start_does_not_fire() {
        let sink = Arc::new(RecordingSink::default());
        let tracker = StallTracker::new(sink.clone(), 0, Duration::from_secs(15));
        let (_peer, inner): (DuplexStream, DuplexStream) = duplex(64);
        let mut guard = StreamStallGuard::new(inner, tracker, Duration::from_secs(15));
        let mut b = [0u8; 8];
        // Never any data. Advance well past the window; read stays pending (not a stall), so race it
        // against a timer and assert the read did NOT resolve to an error.
        tokio::time::advance(Duration::from_secs(60)).await;
        tokio::select! {
            r = guard.read(&mut b) => panic!("idle-from-start read resolved: {r:?}"),
            _ = tokio::time::sleep(Duration::from_millis(1)) => {}
        }
        assert!(sink.stalls.lock().unwrap().is_empty());
    }
}
