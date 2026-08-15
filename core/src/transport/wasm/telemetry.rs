//! Egress-side telemetry for the [splitting egress](super::splitter): what our cover infrastructure
//! is doing, and who is knocking without valid auth.
//!
//! # What is recorded, and what deliberately is not
//!
//! **Untagged peers are recorded with their address. Tunnel clients are not.** That asymmetry is the
//! whole design, and it is not an oversight to be tidied up later:
//!
//! - A tunnel client presented a valid side-door tag, so it is *our user*. `docs/GOAL.md` says we do
//!   not write down who our users are or where they go, and an exit host is exactly the machine an
//!   adversary would seize to find out. So the tunnel branch increments a counter and records nothing
//!   identifying.
//! - An untagged peer is, by definition, not a tunnel user: it is either a real Bitcoin peer or
//!   somebody probing us. Neither is a person we owe log silence to, and the second is the one we need
//!   to see.
//!
//! [`EgressTelemetry::on_tunnel`] therefore takes no address at all — the type makes the rule
//! unbreakable rather than relying on a reviewer noticing.
//!
//! # Why the summary is emitted on close, not on accept
//!
//! Most untagged connections are legitimate Bitcoin peers — that is the point of the cover story — so
//! an event per *accept* would label the entire Bitcoin network as suspicious and bury the real signal.
//! What separates an active prober from a peer is what it does **after** connecting: a prober opens,
//! sends its probe, and leaves; a peer stays and moves data. So the record is written when the
//! connection ends and carries the discriminating fields — how long it lasted and how many bytes
//! crossed in each direction.
//!
//! The sharpest signal is [`Opening::Silent`]: a peer that connects and says nothing at all. A real
//! Bitcoin node always speaks first, so a silent connection is a port-scan or a liveness probe rather
//! than a peer. Before this module those were dropped with no record whatsoever.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tracing::info;

/// How an untagged peer opened the conversation, which is the cheapest probe signal available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opening {
    /// Sent nothing before the classification deadline, or half-closed at once. A real Bitcoin node
    /// speaks first, so this is a scan rather than a peer.
    Silent,
    /// Spoke, but sent fewer bytes than a v2 opening would carry. Ordinary for a v1 peer, and also
    /// what a hand-rolled prober that sends a stub and waits looks like.
    Short { bytes: usize },
    /// Sent a full opening burst whose side-door tag did not verify — the ordinary real-peer case, and
    /// also what a prober replaying a captured handshake would look like.
    Untagged,
}

impl fmt::Display for Opening {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Opening::Silent => f.write_str("silent"),
            Opening::Short { .. } => f.write_str("short"),
            Opening::Untagged => f.write_str("untagged"),
        }
    }
}

/// How an untagged peer's connection ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Relayed to a real node and closed normally.
    Relayed,
    /// Dropped without dialing an upstream — a silent peer, which we refuse to amplify against the
    /// real node.
    Dropped,
    /// No upstream in the pool could be reached. An operational failure on our side, not the peer's,
    /// and the one case here that is genuinely alarming: it means untagged peers are getting nothing,
    /// which is the anomaly the cover story exists to prevent.
    UpstreamUnreachable,
    /// The relay itself failed part-way.
    RelayFailed,
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Outcome::Relayed => f.write_str("relayed"),
            Outcome::Dropped => f.write_str("dropped"),
            Outcome::UpstreamUnreachable => f.write_str("upstream_unreachable"),
            Outcome::RelayFailed => f.write_str("relay_failed"),
        }
    }
}

/// Process-lifetime egress counters, plus the per-connection event stream.
///
/// Counters are `Relaxed` atomics: they are advisory operational figures, never used to synchronize
/// anything, and the cost has to stay negligible on the accept path.
#[derive(Debug, Default)]
pub struct EgressTelemetry {
    tunnel_sessions: AtomicU64,
    untagged_total: AtomicU64,
    untagged_silent: AtomicU64,
    untagged_short: AtomicU64,
    untagged_relayed: AtomicU64,
    upstream_unreachable: AtomicU64,
    bytes_to_upstream: AtomicU64,
    bytes_from_upstream: AtomicU64,
}

/// An immutable read of [`EgressTelemetry`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EgressSnapshot {
    /// Tunnel clients served since start. A count only — never an address.
    pub tunnel_sessions: u64,
    /// Untagged (non-tunnel) connections seen since start.
    pub untagged_total: u64,
    /// Untagged connections that sent nothing: the strongest single probe signal.
    pub untagged_silent: u64,
    /// Untagged connections that spoke but sent less than a full opening.
    pub untagged_short: u64,
    /// Untagged connections successfully relayed to a real node — the cover story working.
    pub untagged_relayed: u64,
    /// Untagged connections we could not give a real node to. Non-zero means the cover is degraded.
    pub upstream_unreachable: u64,
    /// Bytes relayed peer→node and node→peer, across untagged connections only.
    pub bytes_to_upstream: u64,
    pub bytes_from_upstream: u64,
}

impl EgressTelemetry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Read the current counts.
    pub fn snapshot(&self) -> EgressSnapshot {
        EgressSnapshot {
            tunnel_sessions: self.tunnel_sessions.load(Ordering::Relaxed),
            untagged_total: self.untagged_total.load(Ordering::Relaxed),
            untagged_silent: self.untagged_silent.load(Ordering::Relaxed),
            untagged_short: self.untagged_short.load(Ordering::Relaxed),
            untagged_relayed: self.untagged_relayed.load(Ordering::Relaxed),
            upstream_unreachable: self.upstream_unreachable.load(Ordering::Relaxed),
            bytes_to_upstream: self.bytes_to_upstream.load(Ordering::Relaxed),
            bytes_from_upstream: self.bytes_from_upstream.load(Ordering::Relaxed),
        }
    }

    /// Record that a *tunnel* client was served.
    ///
    /// Takes no address on purpose — see the module docs. A tunnel client is a user of ours, and this
    /// signature is what stops a future edit from casually adding `peer = %ip` to the one branch where
    /// it would be a privacy regression rather than telemetry.
    pub fn on_tunnel(&self) {
        self.tunnel_sessions.fetch_add(1, Ordering::Relaxed);
    }

    /// Begin recording an untagged connection. The summary is emitted when the returned guard drops.
    pub fn on_untagged(self: &Arc<Self>, peer: IpAddr, opening: Opening) -> UntaggedSession {
        self.untagged_total.fetch_add(1, Ordering::Relaxed);
        match opening {
            Opening::Silent => {
                self.untagged_silent.fetch_add(1, Ordering::Relaxed);
            }
            Opening::Short { .. } => {
                self.untagged_short.fetch_add(1, Ordering::Relaxed);
            }
            Opening::Untagged => {}
        }
        UntaggedSession {
            telemetry: Arc::clone(self),
            peer,
            opening,
            started: Instant::now(),
            upstream: None,
            outcome: Outcome::Dropped,
            bytes_to_upstream: 0,
            bytes_from_upstream: 0,
        }
    }

    /// Log the running totals. Called periodically by the exit so an operator sees the shape of the
    /// traffic without having to aggregate per-connection lines.
    pub fn log_summary(&self) {
        let s = self.snapshot();
        info!(
            tunnel_sessions = s.tunnel_sessions,
            untagged_total = s.untagged_total,
            untagged_silent = s.untagged_silent,
            untagged_short = s.untagged_short,
            untagged_relayed = s.untagged_relayed,
            upstream_unreachable = s.upstream_unreachable,
            bytes_to_upstream = s.bytes_to_upstream,
            bytes_from_upstream = s.bytes_from_upstream,
            "egress summary"
        );
    }
}

/// One untagged connection, in flight. Emits its summary event on drop.
///
/// Drop rather than an explicit call so an aborted or panicking relay task still produces a record —
/// a probe that makes us fail is exactly the one whose record must not go missing.
pub struct UntaggedSession {
    telemetry: Arc<EgressTelemetry>,
    peer: IpAddr,
    opening: Opening,
    started: Instant,
    upstream: Option<SocketAddr>,
    outcome: Outcome,
    bytes_to_upstream: u64,
    bytes_from_upstream: u64,
}

impl UntaggedSession {
    /// Note which real node this peer was given.
    pub fn routed_to(&mut self, upstream: SocketAddr) {
        self.upstream = Some(upstream);
    }

    /// Record the end state of the relay.
    pub fn finished(&mut self, outcome: Outcome, to_upstream: u64, from_upstream: u64) {
        self.outcome = outcome;
        self.bytes_to_upstream = to_upstream;
        self.bytes_from_upstream = from_upstream;
    }

    /// Record a terminal failure that produced no byte counts.
    pub fn failed(&mut self, outcome: Outcome) {
        self.outcome = outcome;
    }
}

impl Drop for UntaggedSession {
    fn drop(&mut self) {
        let duration_ms = self.started.elapsed().as_millis() as u64;
        if matches!(self.outcome, Outcome::Relayed) {
            self.telemetry
                .untagged_relayed
                .fetch_add(1, Ordering::Relaxed);
        }
        if matches!(self.outcome, Outcome::UpstreamUnreachable) {
            self.telemetry
                .upstream_unreachable
                .fetch_add(1, Ordering::Relaxed);
        }
        self.telemetry
            .bytes_to_upstream
            .fetch_add(self.bytes_to_upstream, Ordering::Relaxed);
        self.telemetry
            .bytes_from_upstream
            .fetch_add(self.bytes_from_upstream, Ordering::Relaxed);

        // `info`, not `debug`: this is the record the operator is asking for. It is emitted only for
        // peers that failed authentication, so it cannot leak a tunnel user's address — see the module
        // docs for why that asymmetry is deliberate.
        //
        // `opening`, `duration_ms` and the byte counts together are what separate a prober from a
        // peer. A prober shows up as a short, low-byte session (often `silent`), and repeatedly from
        // one address; a real peer stays connected and moves data. Neither fact is visible from the
        // connection alone, which is why none of these fields is optional.
        info!(
            peer = %self.peer,
            opening = %self.opening,
            opening_bytes = match self.opening {
                Opening::Silent => 0,
                Opening::Short { bytes } => bytes,
                Opening::Untagged => super::splitter::PEEK_LEN,
            },
            upstream = ?self.upstream,
            outcome = %self.outcome,
            duration_ms,
            bytes_to_upstream = self.bytes_to_upstream,
            bytes_from_upstream = self.bytes_from_upstream,
            "untagged peer"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn peer() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))
    }

    #[test]
    fn a_tunnel_client_is_counted_but_never_identified() {
        let t = EgressTelemetry::new();
        t.on_tunnel();
        t.on_tunnel();
        let s = t.snapshot();
        assert_eq!(s.tunnel_sessions, 2);
        // The real guarantee is structural: `on_tunnel` takes no address, so there is nothing for the
        // tunnel branch to log. This test pins the counter; the type pins the privacy property.
        assert_eq!(
            s.untagged_total, 0,
            "a tunnel client must never land in the untagged (probe) bucket"
        );
    }

    #[test]
    fn openings_are_bucketed_for_probe_triage() {
        let t = Arc::new(EgressTelemetry::new());
        drop(t.on_untagged(peer(), Opening::Silent));
        drop(t.on_untagged(peer(), Opening::Short { bytes: 12 }));
        drop(t.on_untagged(peer(), Opening::Untagged));
        let s = t.snapshot();
        assert_eq!(s.untagged_total, 3);
        assert_eq!(
            s.untagged_silent, 1,
            "silent peers are the strongest signal"
        );
        assert_eq!(s.untagged_short, 1);
    }

    #[test]
    fn a_relayed_session_records_its_bytes_and_counts_as_cover() {
        let t = Arc::new(EgressTelemetry::new());
        {
            let mut sess = t.on_untagged(peer(), Opening::Untagged);
            sess.routed_to(SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 8333)));
            sess.finished(Outcome::Relayed, 4096, 8192);
        }
        let s = t.snapshot();
        assert_eq!(s.untagged_relayed, 1);
        assert_eq!(s.bytes_to_upstream, 4096);
        assert_eq!(s.bytes_from_upstream, 8192);
    }

    /// The one counter that should page someone: untagged peers getting nothing means the cover story
    /// is broken, which is worse than being blocked.
    #[test]
    fn an_unreachable_upstream_is_counted_separately() {
        let t = Arc::new(EgressTelemetry::new());
        {
            let mut sess = t.on_untagged(peer(), Opening::Untagged);
            sess.failed(Outcome::UpstreamUnreachable);
        }
        let s = t.snapshot();
        assert_eq!(s.upstream_unreachable, 1);
        assert_eq!(s.untagged_relayed, 0, "a failed relay is not cover");
    }

    /// A probe that makes the relay task die must still leave a record — that is the whole reason the
    /// summary rides a `Drop` impl rather than an explicit call at the end of the happy path.
    #[test]
    fn a_dropped_session_still_records() {
        let t = Arc::new(EgressTelemetry::new());
        let sess = t.on_untagged(peer(), Opening::Silent);
        // No `finished` call at all, as if the task were aborted mid-relay.
        drop(sess);
        assert_eq!(t.snapshot().untagged_total, 1);
    }
}
