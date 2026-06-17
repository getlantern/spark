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

/// A live NAT mapping: the original endpoints, plus when the flow was last seen (for idle eviction).
struct Session {
    source: SocketAddr,
    destination: SocketAddr,
    last_seen: Instant,
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

    /// Drop the mapping for a synthetic `port` (e.g. on observed FIN/RST). No-op if absent.
    pub fn remove(&mut self, port: u16) {
        if let Some(s) = self.by_port.remove(&port) {
            self.by_source.remove(&s.source);
        }
    }

    /// Evict every mapping idle for at least `timeout`. Returns how many were removed.
    pub fn evict_idle(&mut self, now: Instant, timeout: Duration) -> usize {
        let stale: Vec<(u16, SocketAddr)> = self
            .by_port
            .iter()
            .filter(|(_, s)| now.duration_since(s.last_seen) >= timeout)
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
        let removed = nat.evict_idle(evict_at, timeout);
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
        assert_eq!(nat.evict_idle(t0 + Duration::from_secs(90), timeout), 0);
        assert_eq!(nat.len(), 1);
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
}
