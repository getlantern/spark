# Runtime Stall Detection + Live Failover Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detect actively-stalled TCP *and* UDP flows through the multi-server pool, abort them (the app retries), quarantine a member after repeated stalls so new flows reroute to a healthy server, and restore a member only once real trial flows run without stalling.

**Architecture:** A shared `StallTracker` (lock-free atomics) records per-flow progress and reports outcomes to the pool via a `StallSink` trait. Two adapters wrap a member's I/O — `StreamStallGuard` (TCP, manual `AsyncRead`/`AsyncWrite` with a reset-on-progress `Sleep`) and `PacketStallGuard` (UDP, `timeout` on `recv` + a send-recency gate). `SelectingTransport` implements `StallSink`: it tallies stalls per member, quarantines after K stalls in a window (excluded from `members_and_order`), and recovers via passive trial flows.

**Tech Stack:** Rust, tokio (`time::Instant`, `time::Sleep`, `time::timeout`), `async_trait`, `std::sync::atomic`. All new code is `#[cfg(feature = "multi-server")]`. Design: `docs/superpowers/specs/2026-07-10-runtime-stall-detection-failover-design.md`.

## File structure

- **Create** `core/src/transport/stall.rs` — `StallSink` trait, `StallTracker` (atomics + predicates + outcome hooks), `StreamStallGuard`, `PacketStallGuard`, `PacketSink`/`PacketSource` guard wrappers, unit tests.
- **Modify** `core/src/transport/mod.rs` — `pub(crate) mod stall;` (gated); pass a `StallConfig` into `build_selecting`.
- **Modify** `core/src/transport/select.rs` — per-member `MemberHealth` state, `impl StallSink`, wrap the four dial paths, exclude quarantined from `members_and_order`/`snapshot`, cooldown→trial + trial routing, clear on `reload`.
- **Modify** `core/src/config/mod.rs` — new `TransportConfig` stall fields + defaults.
- **Modify** `core/src/config/lantern.rs` — map any server-provided stall knobs.

## Conventions

- Run all core tests with: `cargo test -p spark-core --features multi-server --lib`
- Everything new is gated `#[cfg(feature = "multi-server")]` (the base build must stay warning-clean; verified in the gate task).
- Timestamps use `tokio::time::Instant` so `tokio::time::pause()`/`advance()` drive tests deterministically.

---

## Phase 1 — detection + abort

### Task 1: TransportConfig stall knobs

**Files:**
- Modify: `core/src/config/mod.rs` (the `TransportConfig` struct ~line 377 and its `impl Default` ~line 385)

- [ ] **Step 1: Add the fields to `TransportConfig`** (immediately after the `probe_window` field)

```rust
    /// Runtime stall detection: a flow that was flowing and then flatlines for this many seconds is
    /// aborted and counted against its pool member. `0` disables stall detection entirely.
    #[serde(default = "default_stall_window_secs")]
    pub stall_window_secs: u64,
    /// Stalls a member may accrue within `stall_demote_window_secs` before it is quarantined.
    #[serde(default = "default_stall_demote_count")]
    pub stall_demote_count: u32,
    /// The sliding window (seconds) over which `stall_demote_count` is measured.
    #[serde(default = "default_stall_demote_window_secs")]
    pub stall_demote_window_secs: u64,
    /// Base cooldown (seconds) a quarantined member waits before going on trial. Doubles on each
    /// repeated quarantine, capped at `stall_quarantine_max_secs`.
    #[serde(default = "default_stall_quarantine_secs")]
    pub stall_quarantine_secs: u64,
    /// Cap (seconds) for the exponential quarantine backoff.
    #[serde(default = "default_stall_quarantine_max_secs")]
    pub stall_quarantine_max_secs: u64,
    /// Clean (non-stalling, ever-active) trial flows required to restore a quarantined member.
    #[serde(default = "default_stall_trial_flows")]
    pub stall_trial_flows: u32,
```

- [ ] **Step 2: Add the default fns** (just above `impl Default for TransportConfig`)

```rust
fn default_stall_window_secs() -> u64 { 15 }
fn default_stall_demote_count() -> u32 { 3 }
fn default_stall_demote_window_secs() -> u64 { 30 }
fn default_stall_quarantine_secs() -> u64 { 60 }
fn default_stall_quarantine_max_secs() -> u64 { 600 }
fn default_stall_trial_flows() -> u32 { 2 }
```

- [ ] **Step 3: Set them in `impl Default for TransportConfig`** (after `probe_window: 8,`)

```rust
            stall_window_secs: default_stall_window_secs(),
            stall_demote_count: default_stall_demote_count(),
            stall_demote_window_secs: default_stall_demote_window_secs(),
            stall_quarantine_secs: default_stall_quarantine_secs(),
            stall_quarantine_max_secs: default_stall_quarantine_max_secs(),
            stall_trial_flows: default_stall_trial_flows(),
        }
```

- [ ] **Step 4: Add a test** (in the `config` test module of `core/src/config/mod.rs`)

```rust
    #[test]
    fn transport_config_has_stall_defaults() {
        let c = TransportConfig::default();
        assert_eq!(c.stall_window_secs, 15);
        assert_eq!(c.stall_demote_count, 3);
        assert_eq!(c.stall_trial_flows, 2);
    }
```

- [ ] **Step 5: Run** `cargo test -p spark-core --features multi-server --lib config::tests::transport_config_has_stall_defaults` — Expected: PASS.
- [ ] **Step 6: Commit** `git add core/src/config/mod.rs && git commit -m "feat(config): stall-detection TransportConfig knobs"`

---

### Task 2: `StallSink` + `StallTracker`

**Files:**
- Create: `core/src/transport/stall.rs`
- Modify: `core/src/transport/mod.rs` (add the module)

- [ ] **Step 1: Register the module** — add to `core/src/transport/mod.rs` near the other `mod` lines:

```rust
#[cfg(feature = "multi-server")]
pub(crate) mod stall;
```

- [ ] **Step 2: Write the tracker + a failing test.** Create `core/src/transport/stall.rs`:

```rust
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
        self.last_outbound_ms.store(self.elapsed_ms(), Ordering::Relaxed);
    }

    /// UDP gate: was there outbound activity within the last `window`? (i.e. the app is still trying,
    /// so inbound silence is a throttle rather than an idle flow).
    pub(crate) fn recently_sent(&self) -> bool {
        self.elapsed_ms().saturating_sub(self.last_outbound_ms.load(Ordering::Relaxed))
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
        assert!(sink.oks.lock().unwrap().is_empty(), "a stalled flow never reports ok");
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
```

- [ ] **Step 3: Run** `cargo test -p spark-core --features multi-server --lib transport::stall` — Expected: 3 tests PASS.
- [ ] **Step 4: Commit** `git add core/src/transport/stall.rs core/src/transport/mod.rs && git commit -m "feat(transport): StallSink + StallTracker (lock-free flow outcome tracking)"`

---

### Task 3: `StreamStallGuard` (TCP adapter)

**Files:**
- Modify: `core/src/transport/stall.rs`

- [ ] **Step 1: Write the guard.** Append to `stall.rs` (above `#[cfg(test)] mod tests`):

```rust
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
```

- [ ] **Step 2: Write failing tests.** Add to `stall.rs` `mod tests`:

```rust
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
```

- [ ] **Step 3: Run** `cargo test -p spark-core --features multi-server --lib transport::stall::tests::stream_guard` — Expected: both PASS. (If `stream_guard_fires...` hangs, the deadline isn't being polled on Pending — re-check `poll_deadline` is reached from the `Poll::Pending` arm.)
- [ ] **Step 4: Commit** `git add core/src/transport/stall.rs && git commit -m "feat(transport): StreamStallGuard TCP stall adapter"`

---

### Task 4: `PacketStallGuard` (UDP adapters)

**Files:**
- Modify: `core/src/transport/stall.rs`

- [ ] **Step 1: Write the sink + source wrappers.** Append to `stall.rs` (above tests):

```rust
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
    pub(crate) fn new(inner: BoxedPacketSource, tracker: Arc<StallTracker>, window: Duration) -> Self {
        Self { inner, tracker, window }
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
```

- [ ] **Step 2: Write failing tests.** Add to `mod tests`:

```rust
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
```

- [ ] **Step 3: Run** `cargo test -p spark-core --features multi-server --lib transport::stall::tests::packet_source` — Expected: both PASS.
- [ ] **Step 4: Commit** `git add core/src/transport/stall.rs && git commit -m "feat(transport): PacketStallGuard UDP stall adapters"`

---

### Task 5: wire the guards into `SelectingTransport` (Phase-1 sink = log only)

**Files:**
- Modify: `core/src/transport/select.rs`
- Modify: `core/src/transport/mod.rs` (`build_selecting` passes the window)

- [ ] **Step 1: Add a `StallConfig` + carry it on `SelectingTransport`.** In `select.rs`, near the top:

```rust
use crate::transport::stall::{
    PacketSinkGuard, PacketSourceGuard, StallSink, StallTracker, StreamStallGuard,
};

/// Stall-detection tunables captured from `TransportConfig` at pool build.
#[derive(Clone, Copy)]
pub(crate) struct StallConfig {
    pub(crate) window: std::time::Duration,
    pub(crate) demote_count: u32,
    pub(crate) demote_window: std::time::Duration,
    pub(crate) quarantine: std::time::Duration,
    pub(crate) quarantine_max: std::time::Duration,
    pub(crate) trial_flows: u32,
}

impl StallConfig {
    pub(crate) fn enabled(&self) -> bool {
        !self.window.is_zero()
    }
}
```

Add a field to `struct SelectingTransport`:

```rust
    stall: StallConfig,
```

- [ ] **Step 2: Thread `StallConfig` through `new`.** Change `SelectingTransport::new` to accept `stall: StallConfig` (last param) and store it. Update `build_selecting` in `mod.rs` to build + pass it:

```rust
    let stall = crate::transport::select::StallConfig {
        window: std::time::Duration::from_secs(config.transport.stall_window_secs),
        demote_count: config.transport.stall_demote_count,
        demote_window: std::time::Duration::from_secs(config.transport.stall_demote_window_secs),
        quarantine: std::time::Duration::from_secs(config.transport.stall_quarantine_secs),
        quarantine_max: std::time::Duration::from_secs(config.transport.stall_quarantine_max_secs),
        trial_flows: config.transport.stall_trial_flows,
    };
    let st = Arc::new(SelectingTransport::new(
        members,
        std::time::Duration::from_secs(config.transport.probe_interval_secs),
        config.transport.probe_window,
        direct.clone() as Arc<dyn Transport>,
        direct as Arc<dyn UdpTransport>,
        stall,
    ));
```

Update the two test-only constructors (`SelectingTransport::new` callers in `select.rs` tests + the `selecting_with_direct` helper) to pass a disabled `StallConfig` where they don't care:

```rust
    // add to the `tests` module:
    fn test_stall_cfg() -> StallConfig {
        StallConfig {
            window: std::time::Duration::from_secs(15),
            demote_count: 3,
            demote_window: std::time::Duration::from_secs(30),
            quarantine: std::time::Duration::from_secs(60),
            quarantine_max: std::time::Duration::from_secs(600),
            trial_flows: 2,
        }
    }
```
and pass `test_stall_cfg()` into the `SelectingTransport::new(...)` test calls and add `stall: test_stall_cfg()` to the `selecting_with_direct` struct literal.

- [ ] **Step 3: Implement `StallSink` (Phase 1 = log only).** Add to `select.rs`:

```rust
impl StallSink for SelectingTransport {
    fn record_stall(&self, member: usize) {
        // Phase 1: detection + abort only. Member accounting lands in a later task.
        tracing::debug!(member, "flow stalled through pool member");
    }
    fn record_flow_ok(&self, _member: usize) {}
}
```

- [ ] **Step 4: Wrap the returned streams/datagrams.** In `SelectingTransport::dial`, after a member's `dial` succeeds (`Ok(s) => return Ok(s)`), wrap it before returning. Add a helper on `SelectingTransport`:

```rust
    /// Wrap a member's TCP stream in a stall guard (no-op when disabled).
    fn guard_stream(self: &Arc<Self>, member: usize, s: BoxedStream) -> BoxedStream {
        if !self.stall.enabled() {
            return s;
        }
        let sink: Arc<dyn StallSink> = self.clone();
        let tracker = StallTracker::new(sink, member, self.stall.window);
        Box::new(StreamStallGuard::new(s, tracker, self.stall.window))
    }

    /// Wrap a member's datagram halves in stall guards (no-op when disabled).
    fn guard_udp(
        self: &Arc<Self>,
        member: usize,
        sink_half: BoxedPacketSink,
        source_half: BoxedPacketSource,
    ) -> (BoxedPacketSink, BoxedPacketSource) {
        if !self.stall.enabled() {
            return (sink_half, source_half);
        }
        let sink: Arc<dyn StallSink> = self.clone();
        let tracker = StallTracker::new(sink, member, self.stall.window);
        (
            Box::new(PacketSinkGuard::new(sink_half, tracker.clone())),
            Box::new(PacketSourceGuard::new(source_half, tracker, self.stall.window)),
        )
    }
```

Then, in each of the four dial methods, wrap on success. **Note:** these methods take `&self` today but the guards need `Arc<Self>`. Change the four `Transport`/`UdpTransport` methods to obtain an `Arc` via a stored `Weak<Self>` set at construction:
- add `me: std::sync::OnceLock<std::sync::Weak<Self>>` to the struct;
- `build_selecting` calls `st.me.set(Arc::downgrade(&st)).ok();` right after `Arc::new(...)`;
- add `fn arc(&self) -> Option<Arc<Self>> { self.me.get().and_then(|w| w.upgrade()) }`;
- add `me: std::sync::OnceLock::new()` to the `selecting_with_direct` test struct literal (grep for every `SelectingTransport {` literal and add the field).

In each dial method's success arm:

```rust
    // dial: was `Ok(s) => return Ok(s),`
    Ok(s) => {
        return Ok(match self.arc() {
            Some(me) => me.guard_stream(i, s),
            None => s,
        });
    }
```
Apply the analogous change to `dial_addr` (both success arms), `dial_udp` (`Ok(p) => ...` → wrap via `guard_udp(i, p.0, p.1)`), and `dial_udp_addr`. Leave the fail-open-to-direct dials **unwrapped** (we only monitor pool members, not the direct floor).

- [ ] **Step 5: Run** `cargo test -p spark-core --features multi-server --lib transport::select` — Expected: all existing select tests still PASS (guards are transparent to correctness).
- [ ] **Step 6: Commit** `git add core/src/transport/select.rs core/src/transport/mod.rs && git commit -m "feat(transport): wrap pool member flows in stall guards (detect + abort)"`

---

## Phase 2 — member quarantine

### Task 6: per-member stall accounting → quarantine

**Files:**
- Modify: `core/src/transport/select.rs`

- [ ] **Step 1: Add member health state.** In `select.rs`, define:

```rust
/// Per-member liveness state driven by stall reports (separate from the latency `Selection`).
#[derive(Clone)]
enum MemberState {
    Healthy,
    /// Quarantined until this instant; `strikes` counts consecutive quarantines (backoff).
    Quarantined { until: tokio::time::Instant, strikes: u32 },
    /// On trial: re-admitted, needs `clean_needed` clean flows to fully recover; `strikes` retained
    /// so a failed trial backs off further.
    OnTrial { clean_needed: u32, strikes: u32 },
}

struct MemberHealth {
    state: MemberState,
    /// Millis-since-pool-start of recent stalls (for the K-in-window count).
    recent_stalls: std::collections::VecDeque<u64>,
}

impl MemberHealth {
    fn new() -> Self {
        Self { state: MemberState::Healthy, recent_stalls: std::collections::VecDeque::new() }
    }
}
```

Add to `SelectingTransport`: `health: Mutex<Vec<MemberHealth>>` and `health_base: tokio::time::Instant`. Initialize in `new`: `health: Mutex::new((0..len).map(|_| MemberHealth::new()).collect())`, `health_base: tokio::time::Instant::now()`. Also add both fields to the `selecting_with_direct` test struct literal (`health: Mutex::new((0..n).map(|_| MemberHealth::new()).collect())`, `health_base: tokio::time::Instant::now()`). Derive `Clone` on `MemberState` (needed by the `member_state` test accessor in Task 9).

- [ ] **Step 2: Write a failing test** (in `select.rs` tests):

```rust
    #[tokio::test(start_paused = true)]
    async fn member_quarantines_after_k_stalls() {
        let t = selecting(vec![member(true), member(true)], vec![0, 1]);
        // Below threshold: 2 stalls (default K=3) → still healthy.
        StallSink::record_stall(&t, 0);
        StallSink::record_stall(&t, 0);
        assert!(!t.is_quarantined(0));
        StallSink::record_stall(&t, 0); // 3rd within window → quarantined
        assert!(t.is_quarantined(0));
        assert!(!t.is_quarantined(1), "other member unaffected");
    }
```

(Add a test-only `pub(crate) fn is_quarantined(&self, i: usize) -> bool` that reads `matches!(self.health.lock()...[i].state, MemberState::Quarantined { .. })`.)

- [ ] **Step 3: Implement real `record_stall`.** Replace the Phase-1 log-only body:

```rust
    fn record_stall(&self, member: usize) {
        let now_ms = tokio::time::Instant::now().duration_since(self.health_base).as_millis() as u64;
        let window_ms = self.stall.demote_window.as_millis() as u64;
        let mut health = self.health.lock().unwrap_or_else(|e| e.into_inner());
        let Some(h) = health.get_mut(member) else { return };
        h.recent_stalls.push_back(now_ms);
        while let Some(&front) = h.recent_stalls.front() {
            if now_ms.saturating_sub(front) > window_ms {
                h.recent_stalls.pop_front();
            } else {
                break;
            }
        }
        let strikes = match h.state {
            MemberState::Quarantined { strikes, .. } | MemberState::OnTrial { strikes, .. } => strikes,
            MemberState::Healthy => 0,
        };
        let trial_stall = matches!(h.state, MemberState::OnTrial { .. });
        if trial_stall || h.recent_stalls.len() as u32 >= self.stall.demote_count {
            let n = strikes.saturating_add(1);
            let backoff = self.stall.quarantine.saturating_mul(1u32 << (n - 1).min(16));
            let backoff = backoff.min(self.stall.quarantine_max);
            h.state = MemberState::Quarantined {
                until: tokio::time::Instant::now() + backoff,
                strikes: n,
            };
            h.recent_stalls.clear();
            tracing::info!(member, strikes = n, "pool member quarantined (stalls)");
        }
    }
```

- [ ] **Step 4: Run** `cargo test -p spark-core --features multi-server --lib transport::select::tests::member_quarantines_after_k_stalls` — Expected: PASS.
- [ ] **Step 5: Commit** `git add core/src/transport/select.rs && git commit -m "feat(transport): quarantine a member after K stalls in a window"`

---

### Task 7: exclude quarantined members from selection + clear on reload

**Files:**
- Modify: `core/src/transport/select.rs`

- [ ] **Step 1: Write a failing test:**

```rust
    #[tokio::test(start_paused = true)]
    async fn quarantined_member_excluded_from_order() {
        let t = selecting(vec![member(true), member(true)], vec![0, 1]);
        for _ in 0..3 {
            StallSink::record_stall(&t, 0);
        }
        assert!(t.is_quarantined(0));
        let (_members, order) = t.members_and_order();
        assert!(!order.contains(&0), "quarantined member is not offered to new flows");
        assert!(order.contains(&1));
    }

    #[tokio::test(start_paused = true)]
    async fn reload_clears_quarantine() {
        let t = selecting(vec![member_with_meta(true, meta("a", "US"))], vec![0]);
        for _ in 0..3 {
            StallSink::record_stall(&t, 0);
        }
        assert!(t.is_quarantined(0));
        t.reload(vec![member_with_meta(true, meta("a2", "US"))]);
        assert!(!t.is_quarantined(0), "reload resets member health");
    }
```

- [ ] **Step 2: Filter quarantined in `members_and_order`.** **Lock-ordering rule (critical):** the `health` mutex and the `selection` mutex must never be held simultaneously — `record_stall`/`record_flow_ok` lock only `health`, so if `members_and_order` ever held `selection` while locking `health` you'd have a lock-order inversion. So compute `(members, order)` inside the existing `selection`-lock block, let that block **return/release**, and only *then* do the `health`-only filtering on the owned `order`. Never return empty *because of* quarantine is acceptable — an empty order fails open to the direct floor, which is the intended degradation. Add a helper (locks only `health`):

```rust
    /// Indices currently excluded from new flows: quarantined members whose cooldown hasn't elapsed.
    fn excluded(&self) -> std::collections::HashSet<usize> {
        let now = tokio::time::Instant::now();
        let health = self.health.lock().unwrap_or_else(|e| e.into_inner());
        health
            .iter()
            .enumerate()
            .filter_map(|(i, h)| match h.state {
                MemberState::Quarantined { until, .. } if until > now => Some(i),
                _ => None,
            })
            .collect()
    }
```

In `members_and_order`, **after the `selection`-lock block has returned `(members, order)`** (so no
`selection` lock is held), filter the owned `order`:

```rust
        let excluded = self.excluded(); // locks only `health`
        let order: Arc<[usize]> = if excluded.is_empty() {
            order
        } else {
            order.iter().copied().filter(|i| !excluded.contains(i)).collect()
        };
```

- [ ] **Step 3: Reflect quarantine in `snapshot`.** In `snapshot`, mark an excluded member unhealthy: after computing each `MemberStatus`, `if excluded.contains(&i) { healthy = false; }` (compute `let excluded = self.excluded();` once at the top of `snapshot`).

- [ ] **Step 4: Clear health on `reload`.** In `reload`, while holding `selection`, also reset health: `*self.health.lock().unwrap_or_else(|e| e.into_inner()) = (0..n).map(|_| MemberHealth::new()).collect();`.

- [ ] **Step 5: Run** `cargo test -p spark-core --features multi-server --lib transport::select` — Expected: the two new tests PASS + all existing PASS.
- [ ] **Step 6: Commit** `git add core/src/transport/select.rs && git commit -m "feat(transport): exclude quarantined members from selection; clear on reload"`

---

## Phase 3 — passive trial recovery

### Task 8: cooldown → trial transition + trial-flow routing

**Files:**
- Modify: `core/src/transport/select.rs`

- [ ] **Step 1: Write a failing test:**

```rust
    #[tokio::test(start_paused = true)]
    async fn quarantine_elapses_to_trial_and_offers_flows() {
        let t = selecting(vec![member(true), member(true)], vec![0, 1]);
        for _ in 0..3 {
            StallSink::record_stall(&t, 0);
        }
        // Before cooldown: excluded.
        assert!(!t.members_and_order().1.contains(&0));
        // After the 60s base cooldown: member 0 goes on trial and is offered the next flow first.
        tokio::time::advance(std::time::Duration::from_secs(61)).await;
        let (_m, order) = t.members_and_order();
        assert_eq!(order.first().copied(), Some(0), "trial member gets the next flow");
    }
```

- [ ] **Step 2: Flip cooldown→trial lazily + route trial flows.** Keep the lock-ordering rule from Task 7: all `health` access here is a separate lock scope that never overlaps the `selection` lock. Place this promotion block at the **very top of `members_and_order`, before the `selection`-lock block** (it needs `&mut` health):

```rust
        {
            let now = tokio::time::Instant::now();
            let mut health = self.health.lock().unwrap_or_else(|e| e.into_inner());
            for h in health.iter_mut() {
                if let MemberState::Quarantined { until, strikes } = h.state {
                    if until <= now {
                        h.state = MemberState::OnTrial {
                            clean_needed: self.stall.trial_flows,
                            strikes,
                        };
                    }
                }
            }
        }
```

Then, after filtering out `excluded`, if any member is `OnTrial`, put the first such member at the front of `order` (deliberately hand it the next flow) and decrement a *pending-offer* counter so we don't flood it — simplest correct v1: just lead with the trial member (its `StallGuard` will re-quarantine it fast if it's still bad):

```rust
        let trial = {
            let health = self.health.lock().unwrap_or_else(|e| e.into_inner());
            health.iter().position(|h| matches!(h.state, MemberState::OnTrial { .. }))
        };
        let order: Arc<[usize]> = match trial {
            Some(tm) if order.contains(&tm) => {
                let mut v = Vec::with_capacity(order.len());
                v.push(tm);
                v.extend(order.iter().copied().filter(|&i| i != tm));
                v.into()
            }
            _ => order,
        };
```

(Note: an `OnTrial` member is **not** in `excluded` — only `Quarantined { until > now }` is — so it appears in `order` and can be led.)

- [ ] **Step 3: Run** `cargo test -p spark-core --features multi-server --lib transport::select::tests::quarantine_elapses_to_trial_and_offers_flows` — Expected: PASS.
- [ ] **Step 4: Commit** `git add core/src/transport/select.rs && git commit -m "feat(transport): cooldown->trial transition + trial-flow routing"`

---

### Task 9: trial outcomes → restore / re-quarantine

**Files:**
- Modify: `core/src/transport/select.rs`

- [ ] **Step 1: Write failing tests:**

```rust
    #[tokio::test(start_paused = true)]
    async fn trial_restores_after_clean_flows() {
        let t = selecting(vec![member(true), member(true)], vec![0, 1]);
        for _ in 0..3 {
            StallSink::record_stall(&t, 0);
        }
        tokio::time::advance(std::time::Duration::from_secs(61)).await;
        let _ = t.members_and_order(); // promotes to OnTrial (clean_needed = 2)
        StallSink::record_flow_ok(&t, 0);
        StallSink::record_flow_ok(&t, 0); // 2 clean trial flows → restored
        assert!(matches!(t.member_state(0), MemberState::Healthy));
    }

    #[tokio::test(start_paused = true)]
    async fn trial_stall_requarantines_with_backoff() {
        let t = selecting(vec![member(true), member(true)], vec![0, 1]);
        for _ in 0..3 {
            StallSink::record_stall(&t, 0);
        }
        tokio::time::advance(std::time::Duration::from_secs(61)).await;
        let _ = t.members_and_order(); // OnTrial, strikes = 1
        StallSink::record_stall(&t, 0); // a trial-flow stall → re-quarantine (strikes = 2)
        assert!(t.is_quarantined(0));
        // Backoff doubled: still quarantined after the first 60s cooldown, cleared only after ~120s.
        tokio::time::advance(std::time::Duration::from_secs(61)).await;
        let _ = t.members_and_order();
        assert!(t.is_quarantined(0), "second-strike cooldown is ~120s, not 60s");
    }
```

(Add a test-only `pub(crate) fn member_state(&self, i: usize) -> MemberState` returning a clone.)

- [ ] **Step 2: Implement `record_flow_ok`** (real body, replacing the Phase-1 no-op):

```rust
    fn record_flow_ok(&self, member: usize) {
        let mut health = self.health.lock().unwrap_or_else(|e| e.into_inner());
        let Some(h) = health.get_mut(member) else { return };
        match &mut h.state {
            MemberState::OnTrial { clean_needed, .. } => {
                *clean_needed = clean_needed.saturating_sub(1);
                if *clean_needed == 0 {
                    h.state = MemberState::Healthy;
                    h.recent_stalls.clear();
                    tracing::info!(member, "pool member restored after clean trial flows");
                }
            }
            // Outside trial, a clean flow ages out transient stalls.
            MemberState::Healthy => h.recent_stalls.clear(),
            MemberState::Quarantined { .. } => {}
        }
    }
```

The re-quarantine-on-trial-stall path is already handled by Task 6's `record_stall` (`trial_stall` branch quarantines immediately with incremented strikes). Verify the backoff shift there uses `strikes` from the `OnTrial` arm — it does.

- [ ] **Step 3: Run** `cargo test -p spark-core --features multi-server --lib transport::select` — Expected: both new tests + all prior PASS.
- [ ] **Step 4: Commit** `git add core/src/transport/select.rs && git commit -m "feat(transport): trial recovery — restore on clean flows, re-quarantine with backoff"`

---

## Phase 4 — config plumbing + gate

### Task 10: lantern.rs mapping

**Files:**
- Modify: `core/src/config/lantern.rs`

- [ ] **Step 1: Write a failing test** (in `lantern.rs` tests) asserting defaults survive a parse with no stall keys, and that a server-provided value maps. First check what field the `config_raw.json` `options`/top-level exposes — if the wire has no stall block yet, map from a nested `options.stall` object when present, else keep defaults. Minimal, forward-compatible mapping:

```rust
    #[test]
    fn stall_defaults_preserved_when_absent() {
        let c = parse(); // existing helper: parses the sample config_raw fixture
        assert_eq!(c.transport.stall_window_secs, 15);
        assert_eq!(c.transport.stall_demote_count, 3);
    }
```

- [ ] **Step 2: Implement.** Since `Config::default()` already seeds the defaults (Task 1) and `lantern.rs` starts from `Config::default()`, **no mapping is required for defaults to hold** — this task only adds *optional* overrides if the wire carries them. If the `RawConfig` (the `config_raw.json` deserialize target in `lantern.rs`) has no stall fields, add `#[serde(default)]` optional fields to it (e.g. `stall_window_seconds: Option<u64>`) and, after `Config::default()`, apply any present overrides:

```rust
    if let Some(v) = raw.stall_window_seconds {
        cfg.transport.stall_window_secs = v;
    }
```

(Repeat for the other five knobs with matching `Option` fields. If the wire schema is frozen, keep only the `#[serde(default)]` optionals so unknown keys are ignored and defaults hold — the test above still passes.)

- [ ] **Step 3: Run** `cargo test -p spark-core --features multi-server --lib config::lantern` — Expected: PASS.
- [ ] **Step 4: Commit** `git add core/src/config/lantern.rs && git commit -m "feat(config): map optional stall knobs from lantern config"`

---

### Task 11: whole-workspace gate + PR

**Files:** none (verification)

- [ ] **Step 1: Format** `cargo fmt -p spark-core`
- [ ] **Step 2: Base build (no multi-server) must be clean**

Run: `cargo build -p spark-core`
Expected: `Finished` with no warnings (all stall code is gated).

- [ ] **Step 3: Core clippy (all-targets, config-fetch)**

Run: `cargo clippy -p spark-core --all-targets --features config-fetch -- -D warnings`
Expected: `Finished`, no errors.

- [ ] **Step 4: Full core tests**

Run: `cargo test -p spark-core --features multi-server`
Expected: all PASS.

- [ ] **Step 5: Downstream + Android JNI target** (spark-core API touch — per the "verify whole workspace" rule)

Run: `cargo clippy -p spark-ffi -p spark-service -p spark-cli -p spark-apple --all-targets -- -D warnings`
Run: `cargo ndk -t arm64-v8a clippy -p spark-android -- -D warnings`
Expected: both `Finished`, no errors.

- [ ] **Step 6: Push + open PR + run the review loop**

```bash
git push -u origin fisk/stall-detection
gh pr create --base main --title "Runtime stall detection + live failover (TCP + UDP)" --body "<summary + link to the spec; note the 4 phases>"
```
Then run the review-pr loop (request Copilot, address/verify, resolve, loop until clean), as with #76/#77.

---

## Notes for the implementer

- **`record_stall`/`record_flow_ok` are called from flow tasks** (the guard's `report_stall`/`Drop`), which run concurrently with `members_and_order`. All member-health mutation goes through `self.health` (a `std::sync::Mutex`); never hold it across `.await` (none of these methods are async). Keep `health` lock scopes tiny, and never nest it inside the `selection` lock or vice-versa (they're independent — a stall report touches only `health`; selection filtering reads `health` then drops it before locking `selection`). Establish and keep that ordering to avoid a deadlock.
- **`SelectingTransport` must be reachable as `Arc<Self>` from the dial methods** — that's what the `Weak<Self>` (`me`) field + `arc()` accessor provide. The `Drop` on `StallTracker` holds `Arc<dyn StallSink>` (i.e. an `Arc<SelectingTransport>`), so the pool outlives its in-flight flows' guards — which is correct (a flow's guard reporting after the pool is gone would upgrade-fail only if we used `Weak`; here the `Arc` in the tracker keeps it alive until the flow ends).
- **Trial routing is best-effort:** leading `order` with the trial member gives it flows; its guard re-quarantines it quickly if still bad. Don't over-engineer per-flow trial-slot accounting in v1 — `stall_trial_flows` clean `record_flow_ok`s restore it, one trial stall re-quarantines it.
