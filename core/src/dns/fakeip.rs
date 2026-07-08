//! Fake-IP allocator + bidirectional `domain ⇄ fakeip` map with TTL and an LRU cap.
//!
//! Every A/AAAA query gets a synthetic IP from a dedicated range — IPv4 `28.0.0.0/15` (dark DoD
//! space; see [`V4_BASE`] for why not the usual 198.18/15) and an IPv6 ULA — recorded so the
//! connecting flow's fake destination recovers its domain. A domain gets **one fake IP per family**
//! (an A and a AAAA query for the same host yield distinct v4/v6 fakes that both recover the same
//! domain).
//!
//! Loop safety: the pool only ever returns addresses from its fake ranges, never a routable IP a
//! user would reach, so a recovered-direct flow's real dial can't re-enter the fake-IP map.
//!
//! Time is passed in (`now: Instant`) rather than read from the clock, so TTL/LRU behavior is
//! deterministic under test. The type is not internally synchronized; share it behind a `Mutex`
//! (M4.3+) since the DNS server and the connect-time recovery touch it from different tasks.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

/// IPv4 fake-IP base — `28.0.0.0/15`, a slice of the US-DoD-allocated `28.0.0.0/8`. Chosen
/// deliberately over the conventional `198.18.0.0/15` (RFC 2544): browsers (Chromium's Local
/// Network Access) classify 198.18/15 — and every other reserved range — as the **local** address
/// space, and then block cross-origin subresource fetches from a public document to those "local"
/// fake IPs (observed: Google News thumbnails on `encrypted-tbn*.gstatic.com` failing with
/// "Permission was denied … access the `local` address space"). 28.0.0.0/8 is a real, globally
/// registered allocation (so Chrome treats it as **public**) that is never publicly announced, so
/// squatting it as fake-IP space collides with nothing a user would actually reach.
pub const V4_BASE: Ipv4Addr = Ipv4Addr::new(28, 0, 0, 0);
/// Address count in the `/15` (131072).
pub const V4_COUNT: u128 = 1 << 17;
/// IPv6 fake-IP base — a ULA prefix (`fd00:2018::/32`), well clear of real routable space.
pub const V6_BASE: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x2018, 0, 0, 0, 0, 0, 0);

/// Whether `addr` lies inside the IPv6 fake-IP pool (`[V6_BASE, V6_BASE + V6_COUNT)`).
///
/// The netstack uses this to tell *fake* v6 destinations (allocated by our DNS, recoverable to a
/// domain, deliverable) apart from *real* ones (e.g. from a browser's own DoH), which the tunnel
/// cannot currently egress — see `netstack::allow_flow_dst`.
pub fn is_fake_v6(addr: &Ipv6Addr) -> bool {
    let n = u128::from(*addr);
    let base = u128::from(V6_BASE);
    n >= base && n < base + V6_COUNT
}
/// IPv6 fake-IP address count offered (1M — far above any live-mapping cap; bounds arithmetic).
pub const V6_COUNT: u128 = 1 << 20;

/// One reserved address range, allocating offsets `1..count` (offset 0 — the network address — is
/// skipped). Freed offsets (from eviction/expiry) are reused before extending the high-water mark.
#[derive(Debug)]
struct Space {
    /// Range base as an integer (a v4 address zero-extended, or the full v6 address).
    base: u128,
    /// Number of addresses in the range.
    count: u128,
    /// Next never-yet-allocated offset.
    high_water: u128,
    /// Offsets returned by eviction/expiry, reused first (keeps the live set dense).
    free: Vec<u128>,
    /// IPv4 vs IPv6 (selects the address reconstruction).
    v4: bool,
}

impl Space {
    /// Take a free offset (reused first, else extend), or `None` if the range is exhausted.
    fn alloc_offset(&mut self) -> Option<u128> {
        if let Some(o) = self.free.pop() {
            return Some(o);
        }
        if self.high_water < self.count {
            let o = self.high_water;
            self.high_water += 1;
            Some(o)
        } else {
            None
        }
    }

    /// Reconstruct the address for `offset`.
    fn addr(&self, offset: u128) -> IpAddr {
        if self.v4 {
            IpAddr::V4(Ipv4Addr::from(
                (self.base as u32).wrapping_add(offset as u32),
            ))
        } else {
            IpAddr::V6(Ipv6Addr::from(self.base.wrapping_add(offset)))
        }
    }
}

/// A live `fakeip → domain` mapping.
#[derive(Debug)]
struct Mapping {
    /// The (lowercased) domain this fake IP stands for.
    domain: String,
    /// The address-space offset, returned to the free list on removal.
    offset: u128,
    /// Last allocate/recover touch, for TTL expiry and LRU eviction.
    last_used: Instant,
}

/// The fake-IP pool: allocate a fake IP for a domain, recover the domain from a fake IP.
#[derive(Debug)]
pub struct FakeIpPool {
    v4: Space,
    v6: Space,
    ttl: Duration,
    cap: usize,
    /// `(lowercased domain, is_v6) → fake IP`, so A and AAAA map independently.
    by_domain: HashMap<(String, bool), IpAddr>,
    /// `fake IP → mapping`, for connect-time recovery and LRU/TTL bookkeeping.
    by_ip: HashMap<IpAddr, Mapping>,
}

impl FakeIpPool {
    /// A pool over the default reserved ranges ([`V4_BASE`]`/15` + [`V6_BASE`]) with the given entry
    /// `ttl` and live-mapping `cap` (clamped to `1..range_size`). Exceeding `cap` LRU-evicts.
    pub fn new(ttl: Duration, cap: usize) -> Self {
        let cap = cap.clamp(1, (V4_COUNT.min(V6_COUNT) as usize) - 1);
        Self {
            v4: Space {
                base: u128::from(u32::from(V4_BASE)),
                count: V4_COUNT,
                high_water: 1,
                free: Vec::new(),
                v4: true,
            },
            v6: Space {
                base: u128::from(V6_BASE),
                count: V6_COUNT,
                high_water: 1,
                free: Vec::new(),
                v4: false,
            },
            ttl,
            cap,
            by_domain: HashMap::new(),
            by_ip: HashMap::new(),
        }
    }

    /// Number of live mappings.
    pub fn len(&self) -> usize {
        self.by_ip.len()
    }

    /// Whether the pool holds no mappings.
    pub fn is_empty(&self) -> bool {
        self.by_ip.is_empty()
    }

    /// Allocate (or reuse) the fake IP for `domain` in the requested family. A live mapping is reused
    /// (and its TTL refreshed); an expired one is replaced. When the pool is at `cap`, the globally
    /// least-recently-used mapping is evicted first.
    pub fn allocate(&mut self, domain: &str, want_v6: bool, now: Instant) -> IpAddr {
        let key = (domain.to_ascii_lowercase(), want_v6);
        if let Some(&ip) = self.by_domain.get(&key) {
            if let Some(m) = self.by_ip.get_mut(&ip) {
                if now.saturating_duration_since(m.last_used) <= self.ttl {
                    m.last_used = now;
                    return ip;
                }
            }
            // Expired (or an inconsistent half-mapping) — drop it and allocate afresh.
            self.remove_by_ip(ip);
        }
        if self.by_ip.len() >= self.cap {
            self.evict_lru();
        }
        let (ip, offset) = self.alloc_in(want_v6);
        self.by_domain.insert(key, ip);
        self.by_ip.insert(
            ip,
            Mapping {
                domain: domain.to_ascii_lowercase(),
                offset,
                last_used: now,
            },
        );
        ip
    }

    /// Recover the domain a fake IP stands for, refreshing its TTL. Returns `None` for an unknown or
    /// expired IP (an expired mapping is purged) — the caller then falls through to IP rules / proxy.
    pub fn recover(&mut self, ip: IpAddr, now: Instant) -> Option<String> {
        if let Some(m) = self.by_ip.get_mut(&ip) {
            if now.saturating_duration_since(m.last_used) <= self.ttl {
                m.last_used = now;
                return Some(m.domain.clone());
            }
        }
        // Absent or expired: purge if present so the offset is reclaimed.
        if self.by_ip.contains_key(&ip) {
            self.remove_by_ip(ip);
        }
        None
    }

    /// Allocate a fake IP in the requested family. The `cap ≤ range_size` invariant guarantees a free
    /// offset after the caller's cap-eviction; the same-family eviction retry and the final sentinel
    /// are defensive dead paths that keep this panic-free (no `expect`).
    fn alloc_in(&mut self, v6: bool) -> (IpAddr, u128) {
        for _ in 0..2 {
            let hit = {
                let space = if v6 { &mut self.v6 } else { &mut self.v4 };
                space.alloc_offset().map(|off| (space.addr(off), off))
            };
            if let Some(hit) = hit {
                return hit;
            }
            self.evict_lru_family(v6);
        }
        let space = if v6 { &self.v6 } else { &self.v4 };
        (space.addr(0), 0)
    }

    /// Remove the globally least-recently-used mapping (for the `cap` limit).
    fn evict_lru(&mut self) {
        let victim = self
            .by_ip
            .iter()
            .min_by_key(|(_, m)| m.last_used)
            .map(|(ip, _)| *ip);
        if let Some(ip) = victim {
            self.remove_by_ip(ip);
        }
    }

    /// Remove the least-recently-used mapping of a given family (only when that family's range is
    /// exhausted — unreachable under the cap invariant). Returns whether one was removed.
    fn evict_lru_family(&mut self, v6: bool) -> bool {
        let victim = self
            .by_ip
            .iter()
            .filter(|(ip, _)| ip.is_ipv6() == v6)
            .min_by_key(|(_, m)| m.last_used)
            .map(|(ip, _)| *ip);
        match victim {
            Some(ip) => {
                self.remove_by_ip(ip);
                true
            }
            None => false,
        }
    }

    /// Drop a mapping from both indexes and return its offset to the free list.
    fn remove_by_ip(&mut self, ip: IpAddr) {
        if let Some(m) = self.by_ip.remove(&ip) {
            self.by_domain.remove(&(m.domain, ip.is_ipv6()));
            if ip.is_ipv6() {
                self.v6.free.push(m.offset);
            } else {
                self.v4.free.push(m.offset);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool() -> FakeIpPool {
        FakeIpPool::new(Duration::from_secs(300), 4096)
    }

    #[test]
    fn is_fake_v6_accepts_only_the_fake_range() {
        // In range: the base and the last allocatable address.
        assert!(is_fake_v6(&V6_BASE));
        let last = Ipv6Addr::from(u128::from(V6_BASE) + V6_COUNT - 1);
        assert!(is_fake_v6(&last));
        // Out of range: one past the pool, a neighbouring ULA, a real global address,
        // link-local, and the unspecified address.
        let past = Ipv6Addr::from(u128::from(V6_BASE) + V6_COUNT);
        assert!(!is_fake_v6(&past));
        assert!(!is_fake_v6(&"fd00:2019::1".parse().unwrap()));
        assert!(!is_fake_v6(&"2607:f8b0:400f:807::2001".parse().unwrap()));
        assert!(!is_fake_v6(&"fe80::1".parse().unwrap()));
        assert!(!is_fake_v6(&Ipv6Addr::UNSPECIFIED));
    }

    #[test]
    fn allocated_v6_fakes_are_recognized() {
        let mut p = pool();
        let t0 = Instant::now();
        for d in ["a.com", "b.com", "c.com"] {
            match p.allocate(d, true, t0) {
                IpAddr::V6(a) => assert!(is_fake_v6(&a), "allocated fake {a} must be in range"),
                IpAddr::V4(a) => panic!("want_v6 allocation returned v4 {a}"),
            }
        }
    }

    #[test]
    fn allocation_is_stable_per_domain_within_ttl() {
        let mut p = pool();
        let t0 = Instant::now();
        let a = p.allocate("x.com", false, t0);
        let b = p.allocate("x.com", false, t0 + Duration::from_secs(5));
        assert_eq!(a, b, "same domain reuses its fake IP within TTL");
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn recover_returns_the_domain_case_insensitively() {
        let mut p = pool();
        let t0 = Instant::now();
        let ip = p.allocate("CDN.Example.com", false, t0);
        assert_eq!(p.recover(ip, t0), Some("cdn.example.com".to_string()));
        // An address never allocated recovers nothing.
        assert_eq!(p.recover("8.8.8.8".parse().unwrap(), t0), None);
    }

    #[test]
    fn a_and_aaaa_are_distinct_families_but_recover_the_same_domain() {
        let mut p = pool();
        let t0 = Instant::now();
        let v4 = p.allocate("d.com", false, t0);
        let v6 = p.allocate("d.com", true, t0);
        assert!(matches!(v4, IpAddr::V4(_)));
        assert!(matches!(v6, IpAddr::V6(_)));
        assert_ne!(v4, v6);
        assert_eq!(p.recover(v4, t0), Some("d.com".to_string()));
        assert_eq!(p.recover(v6, t0), Some("d.com".to_string()));
        // v4 in 28.0.0.0/15; v6 under fd00:2018::/32.
        if let IpAddr::V4(a) = v4 {
            let o = a.octets();
            assert_eq!(o[0], 28);
            assert!(o[1] == 0 || o[1] == 1);
        }
        if let IpAddr::V6(a) = v6 {
            let s = a.segments();
            assert_eq!((s[0], s[1]), (0xfd00, 0x2018));
        }
    }

    #[test]
    fn ttl_expiry_recovers_none_and_purges() {
        let mut p = FakeIpPool::new(Duration::from_secs(60), 100);
        let t0 = Instant::now();
        let ip = p.allocate("a.com", false, t0);
        // Within TTL: recovers and refreshes last_used to t0+30.
        assert_eq!(
            p.recover(ip, t0 + Duration::from_secs(30)),
            Some("a.com".to_string())
        );
        // Past TTL from the refresh: expired and purged.
        assert_eq!(p.recover(ip, t0 + Duration::from_secs(30 + 61)), None);
        assert_eq!(p.len(), 0, "expired mapping is purged on recover");
    }

    #[test]
    fn lru_eviction_removes_the_oldest_and_reuses_its_offset() {
        let mut p = FakeIpPool::new(Duration::from_secs(300), 2);
        let t0 = Instant::now();
        let ip1 = p.allocate("d1", false, t0);
        let ip2 = p.allocate("d2", false, t0 + Duration::from_secs(1));
        assert_eq!(p.len(), 2);
        // Touch d1 so d2 becomes the LRU.
        assert_eq!(
            p.recover(ip1, t0 + Duration::from_secs(2)),
            Some("d1".to_string())
        );
        // Allocating a third at cap evicts d2 (the LRU) and reuses its freed offset.
        let ip3 = p.allocate("d3", false, t0 + Duration::from_secs(3));
        assert_eq!(p.len(), 2);
        assert_eq!(ip3, ip2, "evicted d2's fake IP is reused for d3");
        let t4 = t0 + Duration::from_secs(4);
        assert_eq!(p.recover(ip1, t4), Some("d1".to_string())); // d1 survived
        assert_eq!(p.recover(ip3, t4), Some("d3".to_string())); // that IP now maps to d3
    }
}
