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

/// Aggregate byte accounting for one pool member, shared by every flow riding it.
///
/// This is the *starvation* signal: the evidence that a member still accepts writes but has stopped
/// returning anything. It is deliberately member-wide rather than per-flow. The v1 per-flow signal
/// above ("this flow saw no progress in EITHER direction for N seconds") cannot tell a throttled
/// tunnel from an idle HTTP/2 keep-alive, which is why it false-positived, quarantined healthy
/// members and shipped disabled. A byte *delta* can: an idle connection contributes zero outbound
/// bytes, so it never even enters the test.
///
/// Counters are monotonic and only ever incremented on the data path (one relaxed add per I/O);
/// the watchdog derives deltas by differencing successive samples.
pub(crate) struct MemberActivity {
    out: AtomicU64,
    inbound: AtomicU64,
}

impl MemberActivity {
    pub(crate) fn new() -> Self {
        Self {
            out: AtomicU64::new(0),
            inbound: AtomicU64::new(0),
        }
    }

    pub(crate) fn add_out(&self, n: u64) {
        self.out.fetch_add(n, Ordering::Relaxed);
    }

    pub(crate) fn add_in(&self, n: u64) {
        self.inbound.fetch_add(n, Ordering::Relaxed);
    }

    /// `(bytes_out, bytes_in)` so far. The two loads are independent, so a sample taken mid-write can
    /// straddle an update — harmless, since the watchdog needs a *sustained* imbalance across a whole
    /// window and one misattributed byte cannot manufacture one.
    pub(crate) fn sample(&self) -> (u64, u64) {
        (
            self.out.load(Ordering::Relaxed),
            self.inbound.load(Ordering::Relaxed),
        )
    }
}

/// Whether a member's traffic over one watchdog window looks starved: we pushed at least
/// `min_bytes` out and got **nothing** back.
///
/// The `in_delta == 0` test is deliberately absolute rather than a ratio. A blackholed or
/// DPI-dropped tunnel returns literally nothing, and requiring zero is what makes a false positive
/// essentially impossible — any reply traffic at all, on any flow, clears the member. The cost is
/// that a *throttled-but-trickling* member is not detected here; that case is left to the prober's
/// latency ranking.
///
/// `min_bytes` keeps a lone small request that is legitimately awaiting a slow reply (a long-poll,
/// a streaming subscribe) from tripping the detector on its own.
pub(crate) fn looks_starved(out_delta: u64, in_delta: u64, min_bytes: u64) -> bool {
    out_delta >= min_bytes && in_delta == 0
}

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
            last_outbound_ms: AtomicU64::new(u64::MAX), // u64::MAX = sentinel for "never sent"
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
    ///
    /// `last_outbound_ms` is initialised to `u64::MAX` as a sentinel for "never sent"; the
    /// saturating subtraction makes that case return 0, which is always ≤ any window — so we
    /// short-circuit on the sentinel first. Uses `<=` rather than `<` so a send recorded at t=0
    /// is still counted as recent when the timeout fires at exactly t=window (the common case
    /// with a paused clock or when send and timeout align in production).
    pub(crate) fn recently_sent(&self) -> bool {
        let last = self.last_outbound_ms.load(Ordering::Relaxed);
        if last == u64::MAX {
            return false; // never sent
        }
        self.elapsed_ms().saturating_sub(last) <= self.window.as_millis() as u64
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
pub(crate) struct StreamStallGuard<S> {
    inner: S,
    tracker: Arc<StallTracker>,
    window: Duration,
    deadline: Pin<Box<Sleep>>,
    armed: bool,
}

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

use crate::transport::{BoxedPacketSink, BoxedPacketSource, PacketSink, PacketSource};
use async_trait::async_trait;
use tokio::time::timeout;

/// Wraps a member's outbound datagram half: every send marks outbound activity (the "still sending"
/// gate the source uses to tell throttle from idle).
pub(crate) struct PacketSinkGuard {
    inner: BoxedPacketSink,
    tracker: Arc<StallTracker>,
}

impl PacketSinkGuard {
    pub(crate) fn new(inner: BoxedPacketSink, tracker: Arc<StallTracker>) -> Self {
        Self { inner, tracker }
    }
}

#[async_trait]
impl PacketSink for PacketSinkGuard {
    async fn send(&mut self, payload: &[u8]) -> io::Result<()> {
        self.tracker.mark_outbound();
        self.inner.send(payload).await
    }
}

/// Wraps a member's inbound datagram half. A received datagram marks the flow active and resets the
/// window; if `window` elapses with no datagram while the flow is active AND the app is still sending
/// (`recently_sent`), it reports a stall and errors so the reply pump ends and the association is
/// reclaimed. UDP `send` has no backpressure, so this "sending, nothing coming back" test is the
/// throttle signal — not bidirectional silence.
pub(crate) struct PacketSourceGuard {
    inner: BoxedPacketSource,
    tracker: Arc<StallTracker>,
    window: Duration,
}

impl PacketSourceGuard {
    pub(crate) fn new(
        inner: BoxedPacketSource,
        tracker: Arc<StallTracker>,
        window: Duration,
    ) -> Self {
        Self {
            inner,
            tracker,
            window,
        }
    }
}

#[async_trait]
impl PacketSource for PacketSourceGuard {
    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match timeout(self.window, self.inner.recv(buf)).await {
                Ok(Ok(n)) => {
                    self.tracker.mark_active();
                    return Ok(n);
                }
                Ok(Err(e)) => return Err(e),
                Err(_elapsed) => {
                    // No inbound datagram for `window`. Stall only if the flow was working and the app
                    // is still sending — otherwise it's idle/done; loop for a fresh window.
                    if self.tracker.ever_active() && self.tracker.recently_sent() {
                        return Err(self.tracker.report_stall());
                    }
                }
            }
        }
    }
}

/// Counts bytes through a member's TCP stream into its [`MemberActivity`]. Pure accounting — it
/// never errors, never times out, and imposes one relaxed atomic add per completed read/write, so
/// unlike [`StreamStallGuard`] it is cheap enough to install on every flow unconditionally.
pub(crate) struct MeteredStream<S> {
    inner: S,
    activity: Arc<MemberActivity>,
}

impl<S> MeteredStream<S> {
    pub(crate) fn new(inner: S, activity: Arc<MemberActivity>) -> Self {
        Self { inner, activity }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for MeteredStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let r = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &r {
            let n = buf.filled().len().saturating_sub(before);
            if n > 0 {
                this.activity.add_in(n as u64);
            }
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for MeteredStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let r = Pin::new(&mut this.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = &r {
            this.activity.add_out(*n as u64);
        }
        r
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// [`MeteredStream`]'s outbound-datagram counterpart.
pub(crate) struct MeteredSink {
    inner: BoxedPacketSink,
    activity: Arc<MemberActivity>,
}

impl MeteredSink {
    pub(crate) fn new(inner: BoxedPacketSink, activity: Arc<MemberActivity>) -> Self {
        Self { inner, activity }
    }
}

#[async_trait]
impl PacketSink for MeteredSink {
    async fn send(&mut self, payload: &[u8]) -> io::Result<()> {
        let r = self.inner.send(payload).await;
        if r.is_ok() {
            self.activity.add_out(payload.len() as u64);
        }
        r
    }
}

/// [`MeteredStream`]'s inbound-datagram counterpart.
pub(crate) struct MeteredSource {
    inner: BoxedPacketSource,
    activity: Arc<MemberActivity>,
}

impl MeteredSource {
    pub(crate) fn new(inner: BoxedPacketSource, activity: Arc<MemberActivity>) -> Self {
        Self { inner, activity }
    }
}

#[async_trait]
impl PacketSource for MeteredSource {
    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let r = self.inner.recv(buf).await;
        if let Ok(n) = &r {
            self.activity.add_in(*n as u64);
        }
        r
    }
}

#[cfg(test)]
mod starvation_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const MIN: u64 = 64 * 1024;

    /// The regression that took the v1 signal out of service. An idle HTTP/2 keep-alive is silent in
    /// both directions, and v1 read that as a stall — quarantining healthy members. The byte-delta
    /// signal cannot: with nothing written, the member never enters the test at all.
    #[test]
    fn an_idle_connection_is_not_starved() {
        assert!(!looks_starved(0, 0, MIN));
    }

    #[test]
    fn traffic_flowing_both_ways_is_not_starved() {
        assert!(!looks_starved(1_000_000, 500_000, MIN));
    }

    /// Any reply at all clears the member — the test is zero-inbound, not a ratio.
    #[test]
    fn a_single_byte_back_clears_a_heavily_writing_member() {
        assert!(!looks_starved(10_000_000, 1, MIN));
    }

    /// One small request awaiting a slow reply (long-poll, streaming subscribe) is below the floor,
    /// so it cannot trip the detector on its own.
    #[test]
    fn a_lone_small_request_awaiting_a_reply_is_not_starved() {
        assert!(!looks_starved(500, 0, MIN));
    }

    /// The case this whole detector exists for: real payload going out, nothing coming back.
    #[test]
    fn sustained_writes_with_no_reply_are_starved() {
        assert!(looks_starved(MIN, 0, MIN));
        assert!(looks_starved(MIN * 10, 0, MIN));
    }

    /// The counters must actually move, or the watchdog samples zeros forever and the whole detector
    /// is inert while looking wired up.
    #[tokio::test]
    async fn metered_stream_counts_both_directions() {
        let (mut peer, near) = tokio::io::duplex(1024);
        let activity = Arc::new(MemberActivity::new());
        let mut m = MeteredStream::new(near, Arc::clone(&activity));

        m.write_all(b"hello").await.expect("write");
        peer.write_all(b"worldly").await.expect("peer write");
        let mut buf = [0u8; 7];
        m.read_exact(&mut buf).await.expect("read");

        assert_eq!(activity.sample(), (5, 7), "(bytes_out, bytes_in)");
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

    // A source that yields `n` datagrams (1 byte each) then blocks forever.
    struct BurstThenSilent {
        remaining: usize,
    }
    #[async_trait]
    impl PacketSource for BurstThenSilent {
        async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.remaining > 0 {
                self.remaining -= 1;
                buf[0] = 1;
                Ok(1)
            } else {
                std::future::pending().await // silent forever
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn packet_source_fires_when_sending_but_silent() {
        let sink = Arc::new(RecordingSink::default());
        let tracker = StallTracker::new(sink.clone(), 9, Duration::from_secs(15));
        tracker.mark_outbound(); // app is sending
        let mut src = PacketSourceGuard::new(
            Box::new(BurstThenSilent { remaining: 1 }),
            tracker,
            Duration::from_secs(15),
        );
        let mut b = [0u8; 8];
        assert_eq!(src.recv(&mut b).await.unwrap(), 1); // one datagram → active
                                                        // Now the source is silent; the recv timeout should fire a stall (still recently_sent).
        let err = src.recv(&mut b).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert_eq!(*sink.stalls.lock().unwrap(), vec![9]);
    }

    #[tokio::test(start_paused = true)]
    async fn packet_source_idle_when_not_sending_does_not_fire() {
        let sink = Arc::new(RecordingSink::default());
        let tracker = StallTracker::new(sink.clone(), 3, Duration::from_secs(15));
        // Received once, but the app is NOT sending (no recent mark_outbound) → idle, not a stall.
        let mut src = PacketSourceGuard::new(
            Box::new(BurstThenSilent { remaining: 1 }),
            tracker,
            Duration::from_secs(15),
        );
        let mut b = [0u8; 8];
        assert_eq!(src.recv(&mut b).await.unwrap(), 1);
        tokio::select! {
            r = src.recv(&mut b) => panic!("idle recv resolved: {r:?}"),
            _ = tokio::time::sleep(Duration::from_secs(30)) => {}
        }
        assert!(sink.stalls.lock().unwrap().is_empty());
    }
}
