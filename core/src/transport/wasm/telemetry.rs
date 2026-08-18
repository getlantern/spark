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

use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Instant;

use tracing::{debug, info};

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
/// How many distinct silent sources to remember.
///
/// Bounded because the set is fed by unauthenticated peers: without a cap, a scan from
/// a large address range is a memory-growth primitive against the exit. Past the cap we
/// stop tracking new sources and log every silent drop, which is the safe direction —
/// noisier, never quieter.
const MAX_TRACKED_SILENT_SOURCES: usize = 4096;

#[derive(Debug, Default)]
pub struct EgressTelemetry {
    /// Sources already reported silent, so a repeat offender costs one line, not one
    /// per connection. See [`EgressTelemetry::on_untagged`].
    ///
    /// A `Mutex` rather than an actor: the critical section is a hash lookup and never
    /// spans an `.await` (CLAUDE.md permits exactly this shape).
    silent_sources: Mutex<HashSet<IpAddr>>,
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
    /// Untagged connections that sent nothing.
    pub untagged_silent: u64,
    /// DISTINCT sources among those, which is the number that actually means something:
    /// many silent connections from one address is a health checker, the same count
    /// spread across many addresses is a scan. Saturates at
    /// `MAX_TRACKED_SILENT_SOURCES`.
    pub untagged_silent_sources: u64,
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
            untagged_silent_sources: self
                .silent_sources
                .lock()
                .map(|set| set.len() as u64)
                .unwrap_or(0),
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
        let mut first_silent_from_source = true;
        match opening {
            Opening::Silent => {
                self.untagged_silent.fetch_add(1, Ordering::Relaxed);
                first_silent_from_source = self.note_silent_source(peer);
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
            reportable: first_silent_from_source,
            upstream: None,
            outcome: Outcome::Dropped,
            bytes_to_upstream: 0,
            bytes_from_upstream: 0,
        }
    }

    /// Record a silent source, reporting whether this is the first time we have seen it.
    ///
    /// Repeats are the norm, not the exception: our own reachability sweep dials every
    /// published route and closes without sending a byte, which is indistinguishable
    /// from a port scan and, on a quiet exit, is ~all of the silent traffic. Logging a
    /// line per connection buries a real scan under known monitoring — first observed
    /// in prod, where one address produced 77 of 89 untagged records.
    ///
    /// Past the cap every silent drop reports, which keeps the failure direction noisy
    /// rather than silent.
    fn note_silent_source(&self, peer: IpAddr) -> bool {
        match self.silent_sources.lock() {
            Ok(mut set) => {
                if set.len() >= MAX_TRACKED_SILENT_SOURCES {
                    return true;
                }
                set.insert(peer)
            }
            // A poisoned lock must not silence telemetry.
            Err(_) => true,
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
            untagged_silent_sources = s.untagged_silent_sources,
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
    /// Whether this record earns an `info` line. False only for a repeat silent source
    /// — the counters still move, so nothing is lost from the roll-up.
    reportable: bool,
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

        // `info`, not `debug`: this is the record the operator is asking for. It is
        // emitted only for peers that failed authentication, so it cannot leak a tunnel
        // user's address — see the module docs for why that asymmetry is deliberate.
        //
        // `opening`, `duration_ms` and the byte counts together are what separate a
        // prober from a peer. A prober shows up as a short, low-byte session (often
        // `silent`), and repeatedly from one address; a real peer stays connected and
        // moves data. Neither fact is visible from the connection alone, which is why
        // none of these fields is optional.
        //
        // A repeat silent source drops to `debug`: it is almost always our own
        // reachability sweep, which dials and closes without sending, and one line per
        // sweep per route buries a real scan. The first sighting still logs at `info`,
        // and `untagged_silent_sources` in the roll-up is what distinguishes one noisy
        // address from many.
        let opening_bytes = match self.opening {
            Opening::Silent => 0,
            Opening::Short { bytes } => bytes,
            Opening::Untagged => super::splitter::PEEK_LEN,
        };
        if self.reportable {
            info!(
                peer = %self.peer,
                opening = %self.opening,
                opening_bytes,
                upstream = ?self.upstream,
                outcome = %self.outcome,
                duration_ms,
                bytes_to_upstream = self.bytes_to_upstream,
                bytes_from_upstream = self.bytes_from_upstream,
                "untagged peer"
            );
        } else {
            debug!(
                peer = %self.peer,
                opening = %self.opening,
                opening_bytes,
                outcome = %self.outcome,
                duration_ms,
                "untagged peer (repeat silent source)"
            );
        }
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

    /// One noisy source must not drown a real scan.
    ///
    /// Our own reachability sweep dials every published route and closes without
    /// sending, which is byte-for-byte a port scan. In prod one such address produced
    /// 77 of 89 untagged records, so per-connection reporting made the sharpest probe
    /// signal useless. Repeats stop being reportable; the counters still move.
    #[test]
    fn a_repeat_silent_source_is_reported_once() {
        let t = Arc::new(EgressTelemetry::new());
        let noisy = peer();

        let first = t.on_untagged(noisy, Opening::Silent);
        assert!(
            first.reportable,
            "the first sighting of a source must be reported"
        );
        drop(first);

        for _ in 0..20 {
            let again = t.on_untagged(noisy, Opening::Silent);
            assert!(
                !again.reportable,
                "a repeat from the same source must not be reported"
            );
            drop(again);
        }

        let s = t.snapshot();
        assert_eq!(s.untagged_silent, 21, "every connection still counts");
        assert_eq!(s.untagged_silent_sources, 1, "...but they are one source");
    }

    /// The distinction the metric exists to draw: same volume, different shape.
    #[test]
    fn distinct_sources_separate_a_scan_from_a_health_check() {
        let health = Arc::new(EgressTelemetry::new());
        for _ in 0..30 {
            drop(health.on_untagged(peer(), Opening::Silent));
        }

        let scan = Arc::new(EgressTelemetry::new());
        for n in 0..30u8 {
            drop(scan.on_untagged(IpAddr::V4(Ipv4Addr::new(198, 51, 100, n)), Opening::Silent));
        }

        assert_eq!(
            health.snapshot().untagged_silent,
            scan.snapshot().untagged_silent
        );
        assert_eq!(health.snapshot().untagged_silent_sources, 1);
        assert_eq!(scan.snapshot().untagged_silent_sources, 30);
    }

    /// Only silent drops dedup. A peer that actually spoke is always reported — those
    /// carry the duration and byte counts that make a record worth having.
    #[test]
    fn non_silent_openings_are_always_reported() {
        let t = Arc::new(EgressTelemetry::new());
        for _ in 0..5 {
            assert!(t.on_untagged(peer(), Opening::Untagged).reportable);
            assert!(
                t.on_untagged(peer(), Opening::Short { bytes: 12 })
                    .reportable
            );
        }
        assert_eq!(
            t.snapshot().untagged_silent_sources,
            0,
            "no silent sources tracked"
        );
    }

    /// The set is fed by unauthenticated peers, so it must not grow without bound —
    /// otherwise a scan from a large range is a memory-growth primitive. Past the cap
    /// everything reports, which is the noisy (safe) direction.
    #[test]
    fn tracked_silent_sources_are_bounded() {
        let t = Arc::new(EgressTelemetry::new());
        for n in 0..(MAX_TRACKED_SILENT_SOURCES + 500) {
            let ip = IpAddr::V4(Ipv4Addr::from((n as u32).to_be_bytes()));
            drop(t.on_untagged(ip, Opening::Silent));
        }
        let s = t.snapshot();
        assert!(
            s.untagged_silent_sources <= MAX_TRACKED_SILENT_SOURCES as u64,
            "tracked sources must saturate at the cap, got {}",
            s.untagged_silent_sources
        );
        assert_eq!(
            s.untagged_silent,
            (MAX_TRACKED_SILENT_SOURCES + 500) as u64,
            "the raw count keeps rising even after tracking saturates"
        );
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
