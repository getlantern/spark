//! TCP NAT table for the system (kernel-TCP) netstack.
//!
//! Maps each application connection's **source** `addr:port` to a synthetic port (`natPort`). The
//! redirect gateway rewrites an outbound SYN's source to `gateway:natPort` and its destination to
//! the local listener; on `accept()` the listener's peer port *is* the `natPort`, so [`lookup_back`]
//! recovers the original `(source, destination)` — the upstream to dial and the app to reply to.
//! See `docs/system-stack-design.md` and [`super::rewrite`].
//!
//! One table per address family (the synthetic port space is per-listener). `now` is passed in
//! rather than read from the clock so the eviction logic is deterministically testable.
//!
//! [`lookup_back`]: TcpNat::lookup_back

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// FIN seen from the application (`app → target`) direction.
const FIN_APP: u8 = 0b01;
/// FIN seen from the peer (`target → app`, i.e. via the kernel listener) direction.
const FIN_PEER: u8 = 0b10;

/// A live NAT mapping: the original endpoints, when the flow was last seen (for idle eviction), and
/// which directions have sent a FIN (so a gracefully-closing connection is reaped on a short
/// timeout rather than the long idle one).
struct Session {
    source: SocketAddr,
    destination: SocketAddr,
    last_seen: Instant,
    fin: u8,
}

impl Session {
    /// A connection that has FINed in both directions is closing — reclaim it on the short timeout.
    fn is_closing(&self) -> bool {
        self.fin == (FIN_APP | FIN_PEER)
    }
}

/// Bidirectional source⇄natPort NAT table. Not thread-safe by itself; the netstack owns it behind
/// the single pump task (or a `Mutex` shared with the accept loop).
pub struct TcpNat {
    /// Original source `addr:port` → synthetic port. Lets repeated packets of one flow reuse it.
    by_source: HashMap<SocketAddr, u16>,
    /// Synthetic port → session. Keyed by what the listener observes as the peer port on `accept`.
    by_port: HashMap<u16, Session>,
    /// Rolling allocation cursor over the synthetic port space.
    next_port: u16,
}

impl Default for TcpNat {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpNat {
    /// An empty table.
    pub fn new() -> Self {
        Self {
            by_source: HashMap::new(),
            by_port: HashMap::new(),
            next_port: 1,
        }
    }

    /// Number of live mappings.
    pub fn len(&self) -> usize {
        self.by_port.len()
    }

    /// Whether the table holds no mappings.
    pub fn is_empty(&self) -> bool {
        self.by_port.is_empty()
    }

    /// Map `source` to its synthetic port, allocating and recording the `(source, destination)`
    /// session on first sight and refreshing `last_seen` on every call. Returns `None` only if the
    /// synthetic port space is exhausted (~65k concurrent flows).
    ///
    /// Keyed on `source` alone: if an application reuses an ephemeral source port for a *different*
    /// destination before the old mapping is evicted (or removed on FIN/RST), the stale destination
    /// is returned. Connection-lifecycle removal lives in the pump, not here.
    pub fn lookup(
        &mut self,
        source: SocketAddr,
        destination: SocketAddr,
        now: Instant,
    ) -> Option<u16> {
        if let Some(&port) = self.by_source.get(&source) {
            if let Some(s) = self.by_port.get_mut(&port) {
                s.last_seen = now;
            }
            return Some(port);
        }
        let port = self.alloc_port()?;
        self.by_source.insert(source, port);
        self.by_port.insert(
            port,
            Session {
                source,
                destination,
                last_seen: now,
                fin: 0,
            },
        );
        Some(port)
    }

    /// Recover `(source, destination)` for a synthetic `port`, refreshing `last_seen`. `None` if no
    /// such mapping (stale/closed).
    pub fn lookup_back(&mut self, port: u16, now: Instant) -> Option<(SocketAddr, SocketAddr)> {
        let s = self.by_port.get_mut(&port)?;
        s.last_seen = now;
        Some((s.source, s.destination))
    }

    /// Drop the mapping for a synthetic `port` (e.g. on an observed RST — the connection is
    /// aborted). No-op if absent.
    pub fn remove(&mut self, port: u16) {
        if let Some(s) = self.by_port.remove(&port) {
            self.by_source.remove(&s.source);
        }
    }

    /// Record a FIN for a `port`'s session in the given direction, refreshing `last_seen`. Once both
    /// directions have FINed the mapping becomes "closing" and is reaped on the short timeout.
    pub fn note_fin(&mut self, port: u16, from_app: bool, now: Instant) {
        if let Some(s) = self.by_port.get_mut(&port) {
            s.fin |= if from_app { FIN_APP } else { FIN_PEER };
            s.last_seen = now;
        }
    }

    /// Evict mappings idle past their timeout: `closing` (both-FIN) sessions use the shorter
    /// `closing_timeout`, all others the longer `active_timeout`. Returns how many were removed.
    pub fn evict_idle(
        &mut self,
        now: Instant,
        active_timeout: Duration,
        closing_timeout: Duration,
    ) -> usize {
        let stale: Vec<(u16, SocketAddr)> = self
            .by_port
            .iter()
            .filter(|(_, s)| {
                let timeout = if s.is_closing() {
                    closing_timeout
                } else {
                    active_timeout
                };
                now.duration_since(s.last_seen) >= timeout
            })
            .map(|(&port, s)| (port, s.source))
            .collect();
        for (port, source) in &stale {
            self.by_port.remove(port);
            self.by_source.remove(source);
        }
        stale.len()
    }

    /// Allocate the next free synthetic port, scanning from the rolling cursor. `None` if full.
    fn alloc_port(&mut self) -> Option<u16> {
        for _ in 0..u16::MAX {
            let p = self.next_port;
            self.next_port = self.next_port.checked_add(1).unwrap_or(1);
            if p != 0 && !self.by_port.contains_key(&p) {
                return Some(p);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn lookup_is_idempotent_per_source() {
        let mut nat = TcpNat::new();
        let now = Instant::now();
        let p1 = nat
            .lookup(sa("10.0.0.2:5000"), sa("1.1.1.1:443"), now)
            .unwrap();
        let p2 = nat
            .lookup(sa("10.0.0.2:5000"), sa("1.1.1.1:443"), now)
            .unwrap();
        assert_eq!(p1, p2, "same source reuses its port");
        assert_eq!(nat.len(), 1);
    }

    #[test]
    fn distinct_sources_get_distinct_ports_and_round_trip() {
        let mut nat = TcpNat::new();
        let now = Instant::now();
        let a = nat
            .lookup(sa("10.0.0.2:5000"), sa("1.1.1.1:443"), now)
            .unwrap();
        let b = nat
            .lookup(sa("10.0.0.2:5001"), sa("2.2.2.2:80"), now)
            .unwrap();
        assert_ne!(a, b);
        assert_eq!(
            nat.lookup_back(a, now),
            Some((sa("10.0.0.2:5000"), sa("1.1.1.1:443")))
        );
        assert_eq!(
            nat.lookup_back(b, now),
            Some((sa("10.0.0.2:5001"), sa("2.2.2.2:80")))
        );
        assert_eq!(nat.lookup_back(40000, now), None);
    }

    #[test]
    fn remove_drops_both_indices() {
        let mut nat = TcpNat::new();
        let now = Instant::now();
        let p = nat
            .lookup(sa("10.0.0.2:5000"), sa("1.1.1.1:443"), now)
            .unwrap();
        nat.remove(p);
        assert!(nat.is_empty());
        assert_eq!(nat.lookup_back(p, now), None);
        // A fresh lookup for the same source allocates anew.
        let p2 = nat
            .lookup(sa("10.0.0.2:5000"), sa("1.1.1.1:443"), now)
            .unwrap();
        assert_eq!(nat.len(), 1);
        assert_eq!(
            nat.lookup_back(p2, now),
            Some((sa("10.0.0.2:5000"), sa("1.1.1.1:443")))
        );
    }

    #[test]
    fn evicts_only_idle_entries() {
        let mut nat = TcpNat::new();
        let t0 = Instant::now();
        let timeout = Duration::from_secs(60);
        let old = nat
            .lookup(sa("10.0.0.2:5000"), sa("1.1.1.1:443"), t0)
            .unwrap();
        let later = t0 + Duration::from_secs(30);
        let fresh = nat
            .lookup(sa("10.0.0.2:5001"), sa("2.2.2.2:80"), later)
            .unwrap();

        // At t0+90s: `old` (idle 90s) evicts; `fresh` (idle 60s) is exactly at the threshold too.
        let evict_at = t0 + Duration::from_secs(90);
        let removed = nat.evict_idle(evict_at, timeout, timeout);
        assert_eq!(removed, 2);
        assert!(nat.is_empty());
        let _ = (old, fresh);
    }

    #[test]
    fn refreshing_keeps_an_entry_alive() {
        let mut nat = TcpNat::new();
        let t0 = Instant::now();
        let timeout = Duration::from_secs(60);
        let p = nat
            .lookup(sa("10.0.0.2:5000"), sa("1.1.1.1:443"), t0)
            .unwrap();
        // Touch it at t0+50s, then evict at t0+90s: idle is only 40s → survives.
        nat.lookup_back(p, t0 + Duration::from_secs(50));
        assert_eq!(
            nat.evict_idle(t0 + Duration::from_secs(90), timeout, timeout),
            0
        );
        assert_eq!(nat.len(), 1);
    }

    #[test]
    fn both_fins_make_a_session_closing_and_reaped_early() {
        let mut nat = TcpNat::new();
        let t0 = Instant::now();
        let active = Duration::from_secs(7200);
        let closing = Duration::from_secs(60);
        let p = nat
            .lookup(sa("10.0.0.2:5000"), sa("1.1.1.1:443"), t0)
            .unwrap();

        // One FIN: not closing yet → still on the long active timeout, survives at +120s.
        nat.note_fin(p, true, t0);
        assert_eq!(
            nat.evict_idle(t0 + Duration::from_secs(120), active, closing),
            0
        );

        // Both FINs: now closing → reaped once idle past the short closing timeout.
        nat.note_fin(p, false, t0 + Duration::from_secs(1));
        assert_eq!(
            nat.evict_idle(t0 + Duration::from_secs(30), active, closing),
            0,
            "still within the closing grace"
        );
        assert_eq!(
            nat.evict_idle(t0 + Duration::from_secs(120), active, closing),
            1,
            "reaped after the closing timeout"
        );
        assert!(nat.is_empty());
    }

    #[test]
    fn alloc_skips_occupied_ports() {
        let mut nat = TcpNat::new();
        let now = Instant::now();
        // Allocate a handful; all must be distinct and recoverable.
        let mut seen = std::collections::HashSet::new();
        for i in 0..1000u16 {
            let src = SocketAddr::from(([10, 0, 0, 2], 20000 + i));
            let p = nat.lookup(src, sa("1.1.1.1:443"), now).unwrap();
            assert!(seen.insert(p), "port {p} allocated twice");
        }
        assert_eq!(nat.len(), 1000);
    }

    // ---- property / stress tests (system-stack hardening pass) ----

    /// Deterministic PRNG (splitmix64) for reproducible randomized op sequences (no proptest dep).
    struct Rng(u64);
    impl Rng {
        fn new(seed: u64) -> Self {
            Rng(seed)
        }
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
    }

    /// The two indices must stay mutually consistent after every operation: equal size, and every
    /// `by_source` entry's port resolves to a session whose source is that key (a one-to-one
    /// source⇄port correspondence with no orphans and no port 0).
    fn check_consistent(nat: &TcpNat) {
        assert_eq!(
            nat.by_source.len(),
            nat.by_port.len(),
            "by_source and by_port diverged in size"
        );
        for (src, &port) in &nat.by_source {
            let s = nat
                .by_port
                .get(&port)
                .unwrap_or_else(|| panic!("by_source[{src}]={port} has no by_port entry"));
            assert_eq!(
                s.source, *src,
                "by_port[{port}].source != its by_source key"
            );
            assert_ne!(port, 0, "synthetic port 0 must never be allocated");
        }
    }

    #[test]
    fn randomized_ops_preserve_index_consistency() {
        let mut nat = TcpNat::new();
        let mut rng = Rng::new(0x5061_726B_5F6E_6174);
        let t0 = Instant::now();
        // Small pools so sources collide and ports get reused under churn.
        let sources: Vec<SocketAddr> = (0u16..16)
            .map(|i| SocketAddr::from(([10u8, 0, 0, 2], 5000 + i)))
            .collect();
        let dests: Vec<SocketAddr> = (0u16..4)
            .map(|i| SocketAddr::from(([1u8, 1, 1, 1], 80 + i)))
            .collect();

        for step in 0..20_000u64 {
            let now = t0 + Duration::from_millis(step * 7);
            match rng.next() % 5 {
                0 | 1 => {
                    let src = sources[(rng.next() % sources.len() as u64) as usize];
                    let dst = dests[(rng.next() % dests.len() as u64) as usize];
                    if let Some(port) = nat.lookup(src, dst, now) {
                        // A live mapping round-trips to its recorded source (the dest may be the
                        // earlier one — lookup is keyed on source and doesn't rebind the dest).
                        assert!(
                            matches!(nat.lookup_back(port, now), Some((s, _)) if s == src),
                            "lookup_back({port}) must return the mapped source"
                        );
                    }
                }
                2 => {
                    if let Some(&port) = nat.by_port.keys().next() {
                        nat.remove(port);
                    }
                }
                3 => {
                    if let Some(&port) = nat.by_port.keys().next() {
                        nat.note_fin(port, rng.next() & 1 == 0, now);
                    }
                }
                _ => {
                    nat.evict_idle(now, Duration::from_millis(100), Duration::from_millis(20));
                }
            }
            check_consistent(&nat);
        }
    }

    #[test]
    fn ephemeral_port_reuse_after_eviction_is_fresh() {
        let mut nat = TcpNat::new();
        let t0 = Instant::now();
        let src: SocketAddr = "10.0.0.2:51000".parse().unwrap();
        let d1: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let d2: SocketAddr = "2.2.2.2:80".parse().unwrap();

        let p1 = nat.lookup(src, d1, t0).unwrap();
        assert_eq!(nat.lookup_back(p1, t0), Some((src, d1)));

        // Idle past the timeout → evicted; the stale (src → d1) mapping is gone.
        let timeout = Duration::from_secs(60);
        assert_eq!(
            nat.evict_idle(t0 + Duration::from_secs(120), timeout, timeout),
            1
        );
        assert_eq!(nat.lookup_back(p1, t0), None);

        // The app reuses the same ephemeral source for a DIFFERENT destination: it must map fresh
        // to d2, never resurrect the evicted d1.
        let later = t0 + Duration::from_secs(121);
        let p2 = nat.lookup(src, d2, later).unwrap();
        assert_eq!(
            nat.lookup_back(p2, later),
            Some((src, d2)),
            "a reused source must map to the new destination, not the evicted one"
        );
    }

    #[test]
    fn port_space_exhaustion_returns_none_without_aliasing() {
        let mut nat = TcpNat::new();
        let now = Instant::now();
        let dst: SocketAddr = "1.1.1.1:443".parse().unwrap();
        // Distinct sources (vary the IP) until the 1..=65535 synthetic port space is exhausted.
        let mut ports = std::collections::HashSet::new();
        for n in 0..70_000u32 {
            let src = SocketAddr::from((n.to_be_bytes(), 12345u16));
            match nat.lookup(src, dst, now) {
                Some(port) => {
                    assert_ne!(port, 0);
                    assert!(ports.insert(port), "port {port} aliased a live mapping");
                }
                None => {
                    // Exhausted gracefully (no panic / no infinite scan) after filling the space.
                    assert_eq!(
                        ports.len(),
                        65535,
                        "should fill all of 1..=65535 before failing"
                    );
                    return;
                }
            }
        }
        panic!("port space never exhausted after 70000 distinct sources");
    }
}
