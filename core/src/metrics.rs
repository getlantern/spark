//! Data-path counters surfaced over the control plane (ADR 0004, slice 2).
//!
//! Cheap atomics shared (`Arc`) into the TCP forwarder: bytes each direction (live, via a counting
//! stream wrapper — one relaxed add per poll, not per byte) and session counts (an RAII guard, so an
//! aborted flow still decrements `active`). Read as a [`MetricsSnapshot`] via the engine. Currently
//! TCP-only; UDP metrics are a follow-up.

use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Process-lifetime data-path counters. Cloned into the forwarder; read via [`Metrics::snapshot`].
#[derive(Debug, Default)]
pub struct Metrics {
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
    sessions_active: AtomicU64,
    sessions_total: AtomicU64,
}

/// An immutable read of [`Metrics`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MetricsSnapshot {
    /// Bytes sent app→upstream (egress).
    pub bytes_up: u64,
    /// Bytes received upstream→app (ingress).
    pub bytes_down: u64,
    /// Flows currently open.
    pub sessions_active: u64,
    /// Flows opened since start (cumulative).
    pub sessions_total: u64,
}

impl Metrics {
    /// Read the current counts (Relaxed — counters are advisory, not synchronization).
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            bytes_up: self.bytes_up.load(Ordering::Relaxed),
            bytes_down: self.bytes_down.load(Ordering::Relaxed),
            sessions_active: self.sessions_active.load(Ordering::Relaxed),
            sessions_total: self.sessions_total.load(Ordering::Relaxed),
        }
    }
}

/// Counts a flow as active for exactly its lifetime: bumps `sessions_total` + `sessions_active` on
/// construction and decrements `sessions_active` on drop — so an aborted forwarder task (the
/// supervisor is `abort()`ed on stop) still releases its active count.
pub struct SessionGuard(Arc<Metrics>);

impl SessionGuard {
    /// Open a session (increments the totals).
    pub fn open(metrics: Arc<Metrics>) -> Self {
        metrics.sessions_total.fetch_add(1, Ordering::Relaxed);
        metrics.sessions_active.fetch_add(1, Ordering::Relaxed);
        Self(metrics)
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.0.sessions_active.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Wraps a stream to tally bytes: writes count toward `bytes_up`, reads toward `bytes_down`. Put it
/// on the *upstream* half of the bidirectional copy, so app→upstream writes are egress and
/// upstream→app reads are ingress.
pub struct Counting<S> {
    inner: S,
    metrics: Arc<Metrics>,
    /// When the first byte arrived from the wrapped half, for time-to-first-byte.
    ///
    /// A plain field, not an atomic: the flow owns this wrapper and reads the stamp after the copy
    /// returns, so nothing observes it concurrently. `poll_read` is the hot path, and the check is
    /// one `Option` test that stops being taken after the first byte.
    first_read: Option<std::time::Instant>,
}

impl<S> Counting<S> {
    /// Wrap `inner`, attributing its writes/reads to `metrics`.
    pub fn new(inner: S, metrics: Arc<Metrics>) -> Self {
        Self {
            inner,
            metrics,
            first_read: None,
        }
    }

    /// When the first byte was read, or `None` if the flow never received one — a dial that
    /// connected and then said nothing, which is a distinct outcome from a slow one and must not be
    /// reported as a latency of zero.
    pub fn first_read_at(&self) -> Option<std::time::Instant> {
        self.first_read
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Counting<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let r = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &r {
            let n = (buf.filled().len() - before) as u64;
            this.metrics.bytes_down.fetch_add(n, Ordering::Relaxed);
            // A `Ready(Ok)` with zero bytes is EOF or a spurious wakeup, not a first byte.
            if n > 0 && this.first_read.is_none() {
                this.first_read = Some(std::time::Instant::now());
            }
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counting<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let r = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &r {
            this.metrics
                .bytes_up
                .fetch_add(*n as u64, Ordering::Relaxed);
        }
        r
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn session_guard_tracks_active_and_total() {
        let m = Arc::new(Metrics::default());
        let g1 = SessionGuard::open(Arc::clone(&m));
        let g2 = SessionGuard::open(Arc::clone(&m));
        assert_eq!(m.snapshot().sessions_active, 2);
        assert_eq!(m.snapshot().sessions_total, 2);
        drop(g1);
        assert_eq!(m.snapshot().sessions_active, 1);
        drop(g2);
        let s = m.snapshot();
        assert_eq!(s.sessions_active, 0, "active released on drop (abort-safe)");
        assert_eq!(s.sessions_total, 2, "total is cumulative");
    }

    #[tokio::test]
    async fn counting_tallies_writes_as_up_and_reads_as_down() {
        let m = Arc::new(Metrics::default());
        // A duplex: write into one end (counted as up), read from it (counted as down).
        let (a, b) = tokio::io::duplex(64);
        let mut counted = Counting::new(a, Arc::clone(&m));
        let (mut br, mut bw) = tokio::io::split(b);

        counted.write_all(b"hello").await.unwrap(); // 5 bytes up
        let mut got = [0u8; 5];
        br.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello");

        bw.write_all(b"hi").await.unwrap(); // 2 bytes the counted side will read as down
        let mut g = [0u8; 2];
        counted.read_exact(&mut g).await.unwrap();

        let s = m.snapshot();
        assert_eq!(s.bytes_up, 5);
        assert_eq!(s.bytes_down, 2);
    }
}
