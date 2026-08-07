//! Aggregate counters for the DNS-tunnel server.
//!
//! **Why counters and not spans.** The legacy Go `dnstt-server` emits a span per session, and that
//! shape does not survive this server's hygiene rule (ADR 0011 / GOAL.md: never record the tunnel
//! zone, target addresses, or client/resolver IPs). A per-session span is an identity-shaped record
//! by construction — even without a `target` attribute, a ConnectionID correlates one user's activity
//! across every line it appears on, in a system many people can query. Aggregates carry the
//! operational signal without ever holding a row that describes one user.
//!
//! **The cardinality rule.** Every attribute here is drawn from a set fixed at compile time:
//! [`Metrics::egress_connect_failed`] keys on [`io::ErrorKind`], which is a closed enum, and nothing
//! else is keyed at all. No destination, IP, ConnectionID, or StreamID is ever an attribute or a
//! metric name. A reviewer should be able to enumerate every series this file can produce.
//!
//! All counters are cumulative and monotonic: the process reports a running total and the backend
//! computes rates. That makes a missed export interval a gap in resolution rather than lost counts.

use std::collections::BTreeMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// Process-wide counters, shared by the UDP loop and every egress task.
///
/// Scalar counters are plain atomics on the hot path — `Relaxed` is sufficient because each is an
/// independent tally and nothing branches on their values. Only the keyed map takes a lock, and only
/// on a failure path.
#[derive(Debug, Default)]
pub struct Metrics {
    /// DNS queries accepted from the socket, before any parsing.
    queries: AtomicU64,
    /// Answers written back to the socket. `queries - answers` is the share of queries the session
    /// layer chose not to answer (unparseable, unauthenticated, or replayed).
    answers: AtomicU64,
    /// Streams for which an egress task was spawned.
    streams_opened: AtomicU64,
    /// SYN targets the shared codec could not decode. A non-zero rate means client/server drift.
    undecodable_targets: AtomicU64,
    /// Streams torn down for exceeding `MAX_STREAM_BACKLOG` — a wedged TCP target, not a hot path.
    backlog_drops: AtomicU64,
    /// Egress connects that exceeded `EGRESS_CONNECT_TIMEOUT` (includes blackholed name lookups).
    connect_timeouts: AtomicU64,
    /// Sessions retired by the idle sweep.
    sessions_swept: AtomicU64,
    /// Bytes handed to egress sockets (client → target).
    bytes_uplink: AtomicU64,
    /// Bytes read from egress sockets (target → client).
    bytes_downlink: AtomicU64,
    /// Egress connect failures, keyed by [`io::ErrorKind`]'s label.
    ///
    /// A `Mutex` rather than an atomic because the key set, while closed, is not known until a
    /// failure happens. The critical section is a map bump and is never held across an `.await`.
    connect_failures: Mutex<BTreeMap<&'static str, u64>>,
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn query_received(&self) {
        self.queries.fetch_add(1, Ordering::Relaxed);
    }

    pub fn answer_sent(&self) {
        self.answers.fetch_add(1, Ordering::Relaxed);
    }

    pub fn stream_opened(&self) {
        self.streams_opened.fetch_add(1, Ordering::Relaxed);
    }

    pub fn undecodable_target(&self) {
        self.undecodable_targets.fetch_add(1, Ordering::Relaxed);
    }

    pub fn backlog_drop(&self) {
        self.backlog_drops.fetch_add(1, Ordering::Relaxed);
    }

    pub fn connect_timeout(&self) {
        self.connect_timeouts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn sessions_swept(&self, n: u64) {
        self.sessions_swept.fetch_add(n, Ordering::Relaxed);
    }

    pub fn uplink(&self, n: u64) {
        self.bytes_uplink.fetch_add(n, Ordering::Relaxed);
    }

    pub fn downlink(&self, n: u64) {
        self.bytes_downlink.fetch_add(n, Ordering::Relaxed);
    }

    /// Record an egress connect failure under its [`io::ErrorKind`].
    ///
    /// Takes the kind rather than the error so a caller cannot accidentally pass a `Display` string:
    /// a resolver error's message can contain the hostname it failed to resolve, which is exactly the
    /// value this module exists to keep out of the metrics backend.
    pub fn egress_connect_failed(&self, kind: io::ErrorKind) {
        let label = kind_label(kind);
        // A poisoned lock means another thread panicked mid-bump. Losing a counter increment is not
        // worth propagating a panic into the egress path, so recover the guard and carry on.
        let mut map = match self.connect_failures.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        *map.entry(label).or_insert(0) += 1;
    }

    /// A consistent-enough read of every counter for one export.
    ///
    /// Not atomic across fields: counters are read one at a time while traffic continues, so a
    /// snapshot can straddle an increment. That is correct for cumulative monotonic sums — the next
    /// export includes whatever this one missed, and no count is lost.
    pub fn snapshot(&self) -> Snapshot {
        let connect_failures = match self.connect_failures.lock() {
            Ok(g) => g.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        Snapshot {
            queries: self.queries.load(Ordering::Relaxed),
            answers: self.answers.load(Ordering::Relaxed),
            streams_opened: self.streams_opened.load(Ordering::Relaxed),
            undecodable_targets: self.undecodable_targets.load(Ordering::Relaxed),
            backlog_drops: self.backlog_drops.load(Ordering::Relaxed),
            connect_timeouts: self.connect_timeouts.load(Ordering::Relaxed),
            sessions_swept: self.sessions_swept.load(Ordering::Relaxed),
            bytes_uplink: self.bytes_uplink.load(Ordering::Relaxed),
            bytes_downlink: self.bytes_downlink.load(Ordering::Relaxed),
            connect_failures,
        }
    }
}

/// One export's worth of counter values.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Snapshot {
    pub queries: u64,
    pub answers: u64,
    pub streams_opened: u64,
    pub undecodable_targets: u64,
    pub backlog_drops: u64,
    pub connect_timeouts: u64,
    pub sessions_swept: u64,
    pub bytes_uplink: u64,
    pub bytes_downlink: u64,
    pub connect_failures: BTreeMap<&'static str, u64>,
}

/// A stable, low-cardinality label for an [`io::ErrorKind`].
///
/// Hand-mapped rather than `format!("{kind:?}")` for two reasons: the `Debug` rendering is not a
/// stability guarantee across Rust releases (a renamed variant would silently split a dashboard's
/// series in two), and `ErrorKind` is `#[non_exhaustive]`, so anything unrecognised must collapse
/// into a single `other` bucket rather than minting a new series.
fn kind_label(kind: io::ErrorKind) -> &'static str {
    match kind {
        io::ErrorKind::ConnectionRefused => "connection_refused",
        io::ErrorKind::ConnectionReset => "connection_reset",
        io::ErrorKind::ConnectionAborted => "connection_aborted",
        io::ErrorKind::TimedOut => "timed_out",
        io::ErrorKind::NotConnected => "not_connected",
        io::ErrorKind::AddrNotAvailable => "addr_not_available",
        io::ErrorKind::NetworkUnreachable => "network_unreachable",
        io::ErrorKind::HostUnreachable => "host_unreachable",
        io::ErrorKind::PermissionDenied => "permission_denied",
        io::ErrorKind::InvalidInput => "invalid_input",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_accumulate() {
        let m = Metrics::new();
        m.query_received();
        m.query_received();
        m.answer_sent();
        m.uplink(100);
        m.downlink(250);
        m.sessions_swept(3);

        let s = m.snapshot();
        assert_eq!(s.queries, 2);
        assert_eq!(s.answers, 1);
        assert_eq!(s.bytes_uplink, 100);
        assert_eq!(s.bytes_downlink, 250);
        assert_eq!(s.sessions_swept, 3);
    }

    #[test]
    fn connect_failures_key_by_kind() {
        let m = Metrics::new();
        m.egress_connect_failed(io::ErrorKind::ConnectionRefused);
        m.egress_connect_failed(io::ErrorKind::ConnectionRefused);
        m.egress_connect_failed(io::ErrorKind::TimedOut);

        let s = m.snapshot();
        assert_eq!(s.connect_failures.get("connection_refused"), Some(&2));
        assert_eq!(s.connect_failures.get("timed_out"), Some(&1));
        assert_eq!(s.connect_failures.len(), 2);
    }

    /// `ErrorKind` is `#[non_exhaustive]`, so an unmapped variant must land in `other` rather than
    /// creating a series per variant the next compiler release invents.
    #[test]
    fn unmapped_kinds_collapse_into_other() {
        let m = Metrics::new();
        m.egress_connect_failed(io::ErrorKind::UnexpectedEof);
        m.egress_connect_failed(io::ErrorKind::WouldBlock);

        let s = m.snapshot();
        assert_eq!(s.connect_failures.get("other"), Some(&2));
        assert_eq!(s.connect_failures.len(), 1);
    }

    /// The whole point of the module: a snapshot is a fixed set of scalars plus a map keyed only by
    /// `ErrorKind` labels. If a future change lets an arbitrary string in, this catches it.
    #[test]
    fn every_label_comes_from_the_closed_kind_set() {
        let m = Metrics::new();
        for kind in [
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::TimedOut,
            io::ErrorKind::UnexpectedEof,
            io::ErrorKind::HostUnreachable,
        ] {
            m.egress_connect_failed(kind);
        }
        let known = [
            "connection_refused",
            "connection_reset",
            "connection_aborted",
            "timed_out",
            "not_connected",
            "addr_not_available",
            "network_unreachable",
            "host_unreachable",
            "permission_denied",
            "invalid_input",
            "other",
        ];
        for label in m.snapshot().connect_failures.keys() {
            assert!(known.contains(label), "unexpected metric label: {label}");
        }
    }

    /// A poisoned lock must not take the egress path down with it.
    #[test]
    fn poisoned_lock_still_records() {
        use std::sync::Arc;
        let m = Arc::new(Metrics::new());
        let m2 = Arc::clone(&m);
        let _ = std::thread::spawn(move || {
            let _g = m2.connect_failures.lock().unwrap();
            panic!("poison the mutex");
        })
        .join();

        m.egress_connect_failed(io::ErrorKind::ConnectionRefused);
        assert_eq!(
            m.snapshot().connect_failures.get("connection_refused"),
            Some(&1)
        );
    }
}
