//! The pool of real Bitcoin nodes the [splitting egress](super::splitter) proxies non-tunnel peers to.
//!
//! A single upstream is a single point of failure in a way that is specific to this design: `bitcoind`
//! scores misbehaviour **per peer**, and from the upstream's point of view every peer we forward is
//! *us*. One malformed sender we proxy can get our address discouraged or banned, and once that
//! happens untagged peers get nothing — which is precisely the anomaly the cover story exists to
//! avoid. Spreading across several nodes turns that outage into the loss of 1/N of our cover capacity,
//! and keeps any one volunteer's node from seeing an unusual share of connections from one address.
//!
//! # Why the peer's address picks the node, and not round-robin
//!
//! A real Bitcoin node has **one** identity: one user agent, one set of service bits, one chain tip.
//! Rotating per connection would mean two probes of our address get two different identities, which no
//! real node does — trading a moderate risk (a ban) for a worse one (a trivially detectable listener).
//!
//! So the choice is a pure function of the peer's own address: any single observer always transits the
//! same upstream and sees one consistent node, while the pool as a whole still spreads load and
//! survives a ban. A censor probing from many addresses can still observe several identities behind
//! one IP, but that is a far higher bar than noticing a user agent change between two connections.
//!
//! Selection is [rendezvous hashing] rather than `hash % len` so that removing a dead node only
//! remaps the peers that were assigned *to that node* — with modulo, one node going down reshuffles
//! every peer's identity at once, which is the flapping this design is trying to avoid.
//!
//! [rendezvous hashing]: https://en.wikipedia.org/wiki/Rendezvous_hashing

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::net::TcpStream;

/// How long a node that failed to accept a connection is skipped for.
///
/// A banned or dead upstream refuses (or blackholes) every dial, so without this the peers mapped to
/// it would pay a connect failure each time before failing over. Long enough to stop paying that on
/// every connection, short enough that a node that restarts is back in rotation quickly.
const DEFAULT_COOLDOWN: Duration = Duration::from_secs(60);

/// A pool of real Bitcoin nodes, one of which is chosen per peer.
pub struct UpstreamPool {
    nodes: Vec<Upstream>,
    /// Dials attempted, for the test that pins "at most one attempt per node per call". A failed
    /// connect leaves nothing observable from outside — the port is dead by construction — so the
    /// count has to come from here.
    #[cfg(test)]
    attempts: AtomicU64,
    cooldown: Duration,
    /// Baseline for the `down_until` stamps. An `Instant` is not atomic, so health is kept as millis
    /// elapsed since this, which fits an `AtomicU64` and avoids a lock on the accept path.
    epoch: Instant,
}

struct Upstream {
    addr: SocketAddr,
    /// Millis-since-`epoch` before which this node is skipped. `0` means healthy.
    down_until: AtomicU64,
}

/// Why a pool could not be built.
#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    /// An egress with no upstream cannot proxy an untagged peer, and one that drops untagged peers is
    /// trivially distinguishable from a Bitcoin node — so this is refused at construction rather than
    /// discovered on the first real peer.
    #[error("upstream pool is empty: an egress with no real node behind it has no cover story")]
    Empty,
}

impl UpstreamPool {
    /// Build a pool from `addrs`, discarding duplicates.
    ///
    /// Duplicates are dropped rather than accepted because repeating an address in a rendezvous pool
    /// silently weights it — an operator listing the same node twice would double its share of peers
    /// while believing they had built a two-node pool.
    pub fn new(addrs: impl IntoIterator<Item = SocketAddr>) -> Result<Self, PoolError> {
        let mut nodes: Vec<Upstream> = Vec::new();
        for addr in addrs {
            if nodes.iter().any(|n| n.addr == addr) {
                continue;
            }
            nodes.push(Upstream {
                addr,
                down_until: AtomicU64::new(0),
            });
        }
        if nodes.is_empty() {
            return Err(PoolError::Empty);
        }
        Ok(Self {
            nodes,
            cooldown: DEFAULT_COOLDOWN,
            epoch: Instant::now(),
            #[cfg(test)]
            attempts: AtomicU64::new(0),
        })
    }

    /// A pool of exactly one node — the degenerate case, and what the tests use.
    pub fn single(addr: SocketAddr) -> Self {
        Self {
            nodes: vec![Upstream {
                addr,
                down_until: AtomicU64::new(0),
            }],
            cooldown: DEFAULT_COOLDOWN,
            epoch: Instant::now(),
            #[cfg(test)]
            attempts: AtomicU64::new(0),
        }
    }

    /// Override how long a failed node is skipped (default 60s).
    pub fn with_cooldown(mut self, cooldown: Duration) -> Self {
        self.cooldown = cooldown;
        self
    }

    /// The addresses in the pool, in the order given.
    pub fn addrs(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.nodes.iter().map(|n| n.addr)
    }

    /// How many nodes are in the pool.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Always false — [`UpstreamPool::new`] rejects an empty pool. Present because clippy asks for it
    /// alongside `len`, and because it documents the invariant.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Connect to the node this `peer` maps to, failing over in rendezvous order.
    ///
    /// Failover does change which identity that peer sees, which is the cost of staying up; the
    /// alternative is refusing the connection, and a listener that refuses peers is exactly what this
    /// design must not look like. The order is stable per peer, so a peer that failed over reaches the
    /// *same* second choice next time rather than wandering the pool.
    pub async fn connect_for(&self, peer: IpAddr) -> io::Result<TcpStream> {
        let key = identity_key(peer);
        let mut ranked: Vec<&Upstream> = self.nodes.iter().collect();
        // Descending score. Ties break on the address so the order is total and reproducible rather
        // than dependent on the input ordering.
        ranked.sort_by(|a, b| {
            score(&key, a.addr)
                .cmp(&score(&key, b.addr))
                .then_with(|| a.addr.cmp(&b.addr))
                .reverse()
        });

        // Partition ONCE, against a single `now`, so each node is attempted at most once per call.
        // Ordering the two groups rather than filtering twice is what guarantees that: a node that
        // fails in the healthy group is marked down, and re-testing the mark afterwards would put it
        // straight back in the queue — every connection would then dial each dead node twice during
        // an outage, which is exactly the cost the cooldown exists to avoid.
        let now = self.now_millis();
        let (healthy, cooling): (Vec<&&Upstream>, Vec<&&Upstream>) = ranked
            .iter()
            .partition(|n| n.down_until.load(Ordering::Relaxed) <= now);

        let mut last_err = None;
        // Cooling-down nodes are still tried, after the healthy ones: the mark is a heuristic, and
        // the alternative when every node carries one is a guaranteed failure.
        for node in healthy.into_iter().chain(cooling) {
            #[cfg(test)]
            self.attempts.fetch_add(1, Ordering::Relaxed);
            match TcpStream::connect(node.addr).await {
                Ok(stream) => {
                    node.down_until.store(0, Ordering::Relaxed);
                    return Ok(stream);
                }
                Err(e) => {
                    node.down_until.store(
                        self.now_millis()
                            .saturating_add(self.cooldown.as_millis() as u64),
                        Ordering::Relaxed,
                    );
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "no upstream could be reached")
        }))
    }

    fn now_millis(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }
}

/// The bytes that identify a peer for selection purposes.
///
/// IPv4 uses the whole address. IPv6 uses only the **/64 prefix**, because a single host is routinely
/// given an entire /64 and can source from any address inside it at will — keying on the full address
/// would let one machine walk its own subnet to collect a different node identity per connection,
/// which is the exact observation this scheme denies to everyone else.
fn identity_key(peer: IpAddr) -> [u8; 16] {
    let mut key = [0u8; 16];
    match peer {
        IpAddr::V4(v4) => key[..4].copy_from_slice(&v4.octets()),
        IpAddr::V6(v6) => key[..8].copy_from_slice(&v6.octets()[..8]),
    }
    key
}

/// Rendezvous weight of `addr` for a peer.
///
/// FNV-1a rather than [`std::collections::hash_map::DefaultHasher`]: the mapping should survive a
/// process restart, so that a peer reconnecting after we redeploy still reaches the node it saw
/// before. `DefaultHasher`'s output is explicitly not guaranteed stable across Rust releases, which
/// would make the identity a peer sees depend on which toolchain built the binary.
fn score(key: &[u8; 16], addr: SocketAddr) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = OFFSET;
    let mut feed = |bytes: &[u8]| {
        for b in bytes {
            hash ^= u64::from(*b);
            hash = hash.wrapping_mul(PRIME);
        }
    };
    feed(key);
    match addr.ip() {
        IpAddr::V4(v4) => feed(&v4.octets()),
        IpAddr::V6(v6) => feed(&v6.octets()),
    }
    feed(&addr.port().to_be_bytes());
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use tokio::net::TcpListener;

    fn addr(n: u8) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::new(10, 0, 0, n), 8333))
    }

    fn peer(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, n))
    }

    /// Bind a listener that accepts and immediately drops, standing in for a reachable bitcoind.
    async fn reachable() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let a = l.local_addr().expect("local addr");
        let h = tokio::spawn(async move { while l.accept().await.is_ok() {} });
        (a, h)
    }

    /// A bound-then-dropped port, which refuses rather than hanging.
    async fn refused() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        l.local_addr().expect("local addr")
    }

    #[test]
    fn an_empty_pool_is_refused() {
        assert!(matches!(UpstreamPool::new([]), Err(PoolError::Empty)));
    }

    #[test]
    fn duplicates_are_dropped_so_they_cannot_silently_weight_a_node() {
        let pool = UpstreamPool::new([addr(1), addr(2), addr(1)]).expect("pool");
        assert_eq!(pool.len(), 2, "the repeated address is collapsed");
    }

    /// The property the whole scheme rests on: one observer, one identity, every time.
    #[tokio::test]
    async fn a_peer_maps_to_the_same_node_on_every_connection() {
        let (a, _ha) = reachable().await;
        let (b, _hb) = reachable().await;
        let pool = UpstreamPool::new([a, b]).expect("pool");

        let first = pool
            .connect_for(peer(7))
            .await
            .expect("connect")
            .peer_addr()
            .expect("peer addr");
        for _ in 0..8 {
            let again = pool
                .connect_for(peer(7))
                .await
                .expect("connect")
                .peer_addr()
                .expect("peer addr");
            assert_eq!(
                first, again,
                "the same peer must always reach the same upstream, or our node appears to change identity between connections"
            );
        }
    }

    /// The pool is only worth having if it actually spreads. With two nodes and many distinct peers,
    /// both must see traffic — a hash that sent everyone to one node would pass the stability test
    /// above while delivering none of the benefit.
    #[tokio::test]
    async fn distinct_peers_are_spread_across_the_pool() {
        let (a, _ha) = reachable().await;
        let (b, _hb) = reachable().await;
        let pool = UpstreamPool::new([a, b]).expect("pool");

        let mut hit_a = 0;
        let mut hit_b = 0;
        for n in 0..64u8 {
            let got = pool
                .connect_for(peer(n))
                .await
                .expect("connect")
                .peer_addr()
                .expect("peer addr");
            if got == a {
                hit_a += 1;
            } else {
                hit_b += 1;
            }
        }
        assert!(
            hit_a > 8 && hit_b > 8,
            "expected both nodes to carry a real share, got a={hit_a} b={hit_b}"
        );
    }

    /// A host holding a whole /64 must not be able to walk its own subnet to collect identities.
    #[tokio::test]
    async fn an_ipv6_host_cannot_walk_its_own_64_for_a_different_node() {
        let (a, _ha) = reachable().await;
        let (b, _hb) = reachable().await;
        let pool = UpstreamPool::new([a, b]).expect("pool");

        let mut seen = None;
        for suffix in 0..16u16 {
            let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, suffix);
            let got = pool
                .connect_for(IpAddr::V6(v6))
                .await
                .expect("connect")
                .peer_addr()
                .expect("peer addr");
            match seen {
                None => seen = Some(got),
                Some(first) => assert_eq!(
                    first, got,
                    "addresses inside one /64 must map to one node, or a single host collects identities at will"
                ),
            }
        }
    }

    /// A ban on one node costs its share of cover, not all of it.
    #[tokio::test]
    async fn a_dead_node_fails_over_to_a_live_one() {
        let dead = refused().await;
        let (live, _h) = reachable().await;
        let pool = UpstreamPool::new([dead, live]).expect("pool");

        // Whichever peer maps to `dead` first must still end up connected — to `live`.
        for n in 0..32u8 {
            let got = pool
                .connect_for(peer(n))
                .await
                .expect("a dead upstream must fail over, not fail")
                .peer_addr()
                .expect("peer addr");
            assert_eq!(got, live, "only the live node can accept");
        }
    }

    /// Each node is dialed at most once per call.
    ///
    /// The scenario that matters is *all nodes healthy and all dead*: a node fails, is marked down,
    /// and a naive re-test of that mark puts it straight back in the queue — so every connection
    /// dials every dead node twice, which is the exact cost the cooldown exists to avoid. (A node
    /// that was already cooling down before the call does not exercise this.)
    #[tokio::test]
    async fn a_failed_node_is_not_retried_within_the_same_call() {
        let pool = UpstreamPool::new([refused().await, refused().await]).expect("pool");
        assert!(
            pool.connect_for(peer(3)).await.is_err(),
            "both nodes are dead, so the call must fail"
        );
        assert_eq!(
            pool.attempts.load(Ordering::Relaxed),
            2,
            "two nodes must cost two dials, not four — a node that just failed must not be retried"
        );
    }

    /// With everything down there is nothing to fail over to, and the caller must see the error rather
    /// than a connection to nowhere.
    #[tokio::test]
    async fn an_all_dead_pool_surfaces_the_error() {
        let pool = UpstreamPool::new([refused().await, refused().await]).expect("pool");
        assert!(pool.connect_for(peer(1)).await.is_err());
    }

    /// Recovery: a node marked down is retried once its cooldown lapses, so a restart brings it back
    /// without restarting us.
    #[tokio::test]
    async fn a_recovered_node_returns_to_rotation() {
        let (a, _ha) = reachable().await;
        let port = {
            // Take a port, learn it, then release it so the first dial fails.
            let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            l.local_addr().expect("local addr")
        };
        let pool = UpstreamPool::new([a, port])
            .expect("pool")
            .with_cooldown(Duration::from_millis(50));

        // Find a peer that prefers the dead node, so the first dial marks it down.
        let target = (0..64u8)
            .find(|n| {
                let key = identity_key(peer(*n));
                score(&key, port) > score(&key, a)
            })
            .expect("some peer prefers the second node");
        pool.connect_for(peer(target)).await.expect("fails over");

        // Bring it back on the same address, wait out the cooldown, and it should be preferred again.
        let l = TcpListener::bind(port).await.expect("rebind");
        let _h = tokio::spawn(async move { while l.accept().await.is_ok() {} });
        tokio::time::sleep(Duration::from_millis(80)).await;
        let got = pool
            .connect_for(peer(target))
            .await
            .expect("connect")
            .peer_addr()
            .expect("peer addr");
        assert_eq!(got, port, "a recovered node is retried after its cooldown");
    }
}
