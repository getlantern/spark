//! UDP forwarding (M5).
//!
//! UDP has no connection for the netstack to "accept", so the netstack surfaces every
//! datagram on a single stream (`UdpSocket::split() → (ReadHalf, WriteHalf)`, each item a
//! `(payload, client_src, original_dst)` — note the same source/destination naming
//! inversion as the TCP listener). To route replies back to the right client we keep a
//! [`NatTable`] of associations keyed by `(client_src, original_dst)`, each holding the
//! per-flow state needed to reach the target and reclaimed after [`idle_timeout`] of
//! silence (UDP has no FIN).
//!
//! **Session 1 (this commit):** the association table ([`NatTable`]) and the datagram
//! framing ([`crate::transport::tcp_tunnel::udp`]), both standalone and unit-tested.
//! **Session 2 (needs root):** enable the netstack UDP socket, drive the read loop
//! (per datagram: `table.get_or_insert_with` an association that dials the target via the
//! transport and spawns a reply pump that writes `(reply, original_dst, client_src)` back
//! to the `WriteHalf`), periodically `evict_expired`, and pass the live DNS/echo gate.
//!
//! [`idle_timeout`]: NatTable::new

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Default idle timeout before a UDP association is reclaimed. DNS is request/response and
/// short-lived; 60s comfortably covers a slow resolver round-trip without stranding state.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Identifies a UDP flow: the client's source address and the destination it addressed.
/// Datagrams sharing a key reuse one association; the reply path is keyed on it too.
pub type FlowKey = (SocketAddr, SocketAddr);

/// A NAT association table mapping a UDP [`FlowKey`] to per-flow state `V`, reclaiming
/// associations idle longer than the configured timeout.
///
/// Time is passed in (`now: Instant`) rather than read internally, so eviction is
/// deterministically testable. The orchestration loop supplies `Instant::now()`.
pub struct NatTable<V> {
    idle_timeout: Duration,
    entries: HashMap<FlowKey, Entry<V>>,
}

struct Entry<V> {
    value: V,
    last_seen: Instant,
}

impl<V> NatTable<V> {
    /// Create an empty table whose associations expire after `idle_timeout` of silence.
    pub fn new(idle_timeout: Duration) -> Self {
        Self {
            idle_timeout,
            entries: HashMap::new(),
        }
    }

    /// Number of live associations.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no live associations.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Look up the association for `key`, refreshing its activity timestamp to `now`.
    /// Returns `None` if there is no such association.
    pub fn get(&mut self, key: &FlowKey, now: Instant) -> Option<&V> {
        let entry = self.entries.get_mut(key)?;
        entry.last_seen = now;
        Some(&entry.value)
    }

    /// Get the association for `key`, creating it with `make` if absent. Either way its
    /// activity timestamp is refreshed to `now`.
    pub fn get_or_insert_with<F>(&mut self, key: FlowKey, now: Instant, make: F) -> &mut V
    where
        F: FnOnce() -> V,
    {
        let entry = self.entries.entry(key).or_insert_with(|| Entry {
            value: make(),
            last_seen: now,
        });
        entry.last_seen = now;
        &mut entry.value
    }

    /// Remove and return the association for `key`, if any.
    pub fn remove(&mut self, key: &FlowKey) -> Option<V> {
        self.entries.remove(key).map(|e| e.value)
    }

    /// Remove every association idle for longer than the idle timeout as of `now`,
    /// returning the reclaimed values so the caller can release their resources (e.g.
    /// close the per-flow socket to the tunnel server).
    pub fn evict_expired(&mut self, now: Instant) -> Vec<V> {
        let timeout = self.idle_timeout;
        // Collect keys first (the borrow ends before we mutate), then take the values out.
        // `FlowKey` is `Copy`, so this is cheap.
        let expired: Vec<FlowKey> = self
            .entries
            .iter()
            .filter(|(_, entry)| now.duration_since(entry.last_seen) > timeout)
            .map(|(key, _)| *key)
            .collect();
        expired
            .into_iter()
            .filter_map(|key| self.entries.remove(&key).map(|entry| entry.value))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timeout() -> Duration {
        Duration::from_secs(30)
    }

    #[test]
    fn get_or_insert_with_creates_then_reuses() {
        let mut table: NatTable<u32> = NatTable::new(timeout());
        let t0 = Instant::now();
        let key: FlowKey = (
            "10.0.0.2:1111".parse().unwrap(),
            "1.1.1.1:53".parse().unwrap(),
        );

        let mut calls = 0;
        *table.get_or_insert_with(key, t0, || {
            calls += 1;
            7
        }) += 1;
        // Second call to the same key must reuse, not re-create.
        let v = table.get_or_insert_with(key, t0, || {
            calls += 1;
            99
        });
        assert_eq!(*v, 8);
        assert_eq!(calls, 1);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn evicts_only_idle_entries_and_returns_them() {
        let mut table: NatTable<&'static str> = NatTable::new(timeout());
        let t0 = Instant::now();
        let a: FlowKey = ("10.0.0.2:1".parse().unwrap(), "1.1.1.1:53".parse().unwrap());
        let b: FlowKey = ("10.0.0.2:2".parse().unwrap(), "8.8.8.8:53".parse().unwrap());

        table.get_or_insert_with(a, t0, || "a");
        table.get_or_insert_with(b, t0, || "b");

        // Refresh only `b`, well after `a` would expire.
        let later = t0 + timeout() + Duration::from_secs(1);
        assert_eq!(table.get(&b, later), Some(&"b"));

        let evicted = table.evict_expired(later);
        assert_eq!(evicted, vec!["a"]);
        assert_eq!(table.len(), 1);
        assert!(table.get(&a, later).is_none());
        assert!(table.get(&b, later).is_some());
    }

    #[test]
    fn nothing_evicted_before_timeout() {
        let mut table: NatTable<u8> = NatTable::new(timeout());
        let t0 = Instant::now();
        let key: FlowKey = ("10.0.0.2:1".parse().unwrap(), "1.1.1.1:53".parse().unwrap());
        table.get_or_insert_with(key, t0, || 1);

        let within = t0 + timeout(); // exactly at the boundary is not "longer than"
        assert!(table.evict_expired(within).is_empty());
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn remove_takes_the_value() {
        let mut table: NatTable<u8> = NatTable::new(timeout());
        let t0 = Instant::now();
        let key: FlowKey = ("10.0.0.2:1".parse().unwrap(), "1.1.1.1:53".parse().unwrap());
        table.get_or_insert_with(key, t0, || 42);
        assert_eq!(table.remove(&key), Some(42));
        assert!(table.is_empty());
    }
}
