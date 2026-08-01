//! Proxyless transport (ADR 0014): reach the real destination directly — no proxy, no exit hop.
//!
//! Ported from the Outline SDK smart dialer's proxyless path via `flint-proxyless`: find a
//! `(resolver, wire-shaping)` pairing the local network does not block, then use it for every flow.
//! Two ingredients, matching flint's two axes — an **un-poisoned resolver** so the destination address
//! is real, and **opening-handshake shaping** (record fragmentation, segment splitting, jitter) so a DPI
//! box cannot classify the first flight.
//!
//! # Why this does not terminate TLS
//!
//! `flint_proxyless::dial` completes a certificate-verified TLS handshake and hands back the TLS stream.
//! That is right where flint *is* the client (a kindling config fetch), and wrong here: [`Transport`]
//! must return a **raw byte stream** that the application's own bytes are spliced into. If spark
//! terminated TLS, the browser's ClientHello would never reach the origin and end-to-end TLS would be
//! broken — the transport would become a MITM of its own user.
//!
//! So spark returns shaped **TCP**, and the shaping applies to whatever the application writes first,
//! which for HTTPS is exactly its ClientHello. Authentication is not lost: the application verifies the
//! origin certificate itself, end to end, which is a stronger guarantee than anything this layer could
//! check on its behalf.
//!
//! The consequence is that spark has no certificate to use as a success oracle, so **strategy selection
//! happens out of band**: [`flint_proxyless::find_cached`] proves a candidate against real test domains
//! (verified handshakes, cert checked) once per network, and the winning pairing is then applied to raw
//! per-flow dials. Verification lives in the chooser, not the data path.
//!
//! # Where the DNS half applies
//!
//! [`Transport::dial`] receives a [`SocketAddr`] — the netstack surfaces the address the application
//! already resolved, so there is no name left to un-poison. The resolver half therefore only bites on
//! [`Transport::dial_addr`] with an [`Address::Domain`], which is spark's fake-IP smart-routing path
//! (`[dns] fake_ip` + the DoH resolvers in [`crate::dns`]). Without that path an application that
//! resolved through a poisoned system resolver hands us a bogus address and shaping alone cannot save
//! it. Proxyless is therefore most useful with spark's own DNS in front of it, which is also how
//! `flint-proxyless` picked the strategy in the first place.
//!
//! # Scope
//!
//! No exit hop means traffic leaves the user's own address for the real destination. This defeats
//! *blocking*, not *observation*: an on-path censor still sees which host is being contacted, it just
//! cannot classify or cut the handshake. It does nothing against IP-level blackholing. Treat it as a
//! reachability tool, not an anonymity one — it is deliberately a separate choice from the proxy pool
//! rather than a silent substitute for it.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use flint_proxyless::{Space, Strategy, StrategyCache};
use flint_shaping::{RecordFragmentingStream, SegmentShapingStream, WirePlan};
use tokio::net::UdpSocket;

use super::{
    protected_tcp_connect, protected_udp_socket, Address, BoxedPacketSink, BoxedPacketSource,
    DirectPacketSink, DirectPacketSource, Transport, UdpTransport,
};
use crate::config::ProxylessConfig;
use crate::net::SocketProtector;
use crate::BoxedStream;

/// Whether `next` should replace `prev` as the reported resolution failure.
///
/// A and AAAA fail independently, and taking whichever finished last loses information: if one family
/// times out while the other merely has no record, reporting the no-record error would say "no such
/// name" *and* skip eviction — hiding a resolver that genuinely failed behind an ordinary negative
/// answer for the other family. An indicting failure therefore outranks a non-indicting one, and once
/// one is held it is never downgraded.
fn outranks(prev: Option<&io::Error>, next: &io::Error) -> bool {
    match prev {
        None => true,
        Some(p) => !flint_dns::indicts_resolver(p) && flint_dns::indicts_resolver(next),
    }
}

/// Test domains a strategy must reach before it is trusted, when the config names none.
///
/// Two, on different operators and jurisdictions, because `find_cached` requires **all** of them: one
/// domain might be reachable by accident on an otherwise hostile network, and a single accidental
/// success would then vouch for a strategy that does not work.
const DEFAULT_TEST_DOMAINS: [&str; 2] = ["example.com", "www.wikipedia.org"];

/// A memoized strategy together with the network key it was selected under.
struct Chosen {
    /// The value [`ProxylessTransport::network_key`] returned when this was chosen. A later dial that
    /// computes a different key is on a different network, and this pairing no longer vouches for it.
    network: String,
    strategy: Strategy,
}

/// Reaches destinations directly using a searched-for `(resolver, shaping)` pairing.
pub struct ProxylessTransport {
    space: Space,
    cache: StrategyCache,
    network: String,
    test_domains: Vec<String>,
    /// The chosen pairing, memoized after the first search. A search costs verified handshakes, so it
    /// must not run per flow.
    ///
    /// Stored **with the network it was chosen on**, because a strategy is only meaningful for one
    /// network: the resolver that worked at home may be blocked at a café, and the shaping that was
    /// required there may be unnecessary here. Keeping the two together in one `Option` makes the pair
    /// atomic — as separate fields they could be read half-updated.
    chosen: RwLock<Option<Chosen>>,
    /// Single-flight gate around selection. Without it, every flow that arrives before the first search
    /// finishes sees `chosen == None` and starts its own — a thundering herd on the most expensive
    /// operation this transport has, precisely at startup when flows arrive together. A `tokio` mutex
    /// because it is deliberately **held across the `.await`**, which is the whole point; the `std`
    /// locks above are never held across one.
    selecting: tokio::sync::Mutex<()>,
    protector: Option<SocketProtector>,
}

impl ProxylessTransport {
    /// Build the transport from `[transport.proxyless]`.
    ///
    /// The resolver axis defaults to flint's diverse DoH pool; the shaping axis always includes the
    /// no-op plan first (so an open network is settled without paying for shaping) plus the configured
    /// `[transport.shaping]` plan when it does anything.
    pub fn new(
        cfg: &ProxylessConfig,
        wire: WirePlan,
        protector: Option<SocketProtector>,
    ) -> io::Result<Self> {
        let mut space = Space::new(flint_dns::default_pool());
        // Wire-major enumeration means the no-op plan is tried against every resolver first, so a
        // network that needs no shaping is settled at the cheapest end of the space.
        if !wire.is_noop() {
            space = space.with_wire(wire);
        }
        if let Some(max) = cfg.max_candidates {
            // Reject rather than clamp. This is user-authored config, and `0` can only be a mistake:
            // silently searching one candidate would contradict a documented strict bound, while
            // honouring it literally would disable the transport without saying so. (flint clamps
            // internally — a library defending itself — but the boundary is where input gets validated.)
            if max == 0 {
                return Err(io::Error::other(
                    "transport.proxyless.max_candidates must be at least 1 (0 would search nothing); omit it to search the whole space",
                ));
            }
            // Bounding the cold search matters because it is a search, not a dial; see
            // `flint_kindling::ProxylessTransport` for the budget arithmetic this mirrors.
            let capped = max;
            let wires = space.wires.len().max(1);
            if capped < space.len() {
                if capped < wires {
                    space.resolvers.truncate(1);
                    space.wires.truncate(capped);
                } else {
                    space.resolvers.truncate(capped / wires);
                }
            }
        }
        let test_domains = if cfg.test_domains.is_empty() {
            DEFAULT_TEST_DOMAINS.iter().map(|d| d.to_string()).collect()
        } else {
            cfg.test_domains.clone()
        };
        Ok(Self {
            space,
            cache: StrategyCache::new(),
            network: cfg.network.clone(),
            test_domains,
            chosen: RwLock::new(None),
            selecting: tokio::sync::Mutex::new(()),
            protector,
        })
    }

    /// The chosen pairing, searching for one on first use.
    ///
    /// Double-checked so the steady state is a read lock and no search: the lock is released before any
    /// `.await`, never held across one.
    async fn strategy(&self) -> io::Result<Strategy> {
        if let Some(chosen) = self.peek(self.network_key().as_deref()) {
            return Ok(chosen);
        }
        // Single-flight: only one search runs even if many flows arrive together. flint's cache records
        // a *completed* winner and has no in-progress state, so without this gate each concurrent first
        // dial would run its own full search.
        let _gate = self.selecting.lock().await;
        // Re-sample rather than reuse the key from before the gate. Waiting here can take as long as a
        // full verified search — seconds — and a network change during that wait would otherwise make us
        // search on the *new* network but file the winner under the *old* key, which is exactly the
        // cross-network reuse this whole mechanism exists to prevent.
        //
        // From here the key is threaded through unchanged, so the memo check, the cache lookup, and what
        // gets stored all describe one network. A change after this point still races, but benignly: the
        // entry is filed under the network it was proven on, and the next dial re-samples and rejects it.
        let key = self.network_key();
        // Re-check under the gate — whoever held it before us may already have chosen.
        if let Some(chosen) = self.peek(key.as_deref()) {
            return Ok(chosen);
        }
        let cache_key = key.unwrap_or_default();
        let chosen =
            flint_proxyless::find_cached(&self.space, &self.test_domains, &self.cache, &cache_key)
                .await
                .map_err(|e| {
                    io::Error::other(format!(
                        "no proxyless strategy reaches the test domains: {e}"
                    ))
                })?;
        tracing::info!(
            resolver = %chosen.resolver.name,
            shaped = !chosen.policy.wire.is_noop(),
            network = %cache_key,
            "selected proxyless strategy"
        );
        *self.chosen.write().unwrap_or_else(|e| e.into_inner()) = Some(Chosen {
            network: cache_key,
            strategy: chosen.clone(),
        });
        Ok(chosen)
    }

    /// The key identifying the current network, for both the memo and flint's per-network cache.
    ///
    /// An explicit `[transport.proxyless] network` wins: a deployment that pins it is asserting the
    /// network identity itself, and probing would only second-guess it. Otherwise this is measured
    /// from the host's current egress ([`crate::net::egress_fingerprint`]).
    ///
    /// `None` means the probe could not tell — no route, typically because the host is momentarily
    /// offline. That is deliberately *not* the same as "a new network": treating ignorance as change
    /// would throw away a good strategy every time connectivity blipped, and the next dial is going to
    /// fail on its own merits anyway.
    fn network_key(&self) -> Option<String> {
        if !self.network.is_empty() {
            return Some(self.network.clone());
        }
        crate::net::egress_fingerprint(self.protector.as_ref())
    }

    /// The memoized pairing, if a search has already succeeded **on the network `key` names**. Clones
    /// out so the guard drops here.
    ///
    /// A `key` of `None` means the network could not be determined, and the memo is returned unchanged:
    /// see [`Self::network_key`] for why ignorance must not count as change.
    ///
    /// Poisoning is recovered rather than treated as a miss (spark's convention — see
    /// [`crate::transport::fronted_meek`]). Treating it as a miss would be quietly expensive here: a
    /// panic anywhere else holding this lock would send *every* subsequent flow back through a full
    /// verified search, forever.
    fn peek(&self, key: Option<&str>) -> Option<Strategy> {
        let guard = self.chosen.read().unwrap_or_else(|e| e.into_inner());
        let chosen = guard.as_ref()?;
        match key {
            Some(k) if k != chosen.network => None,
            _ => Some(chosen.strategy.clone()),
        }
    }

    /// Record a resolution failure against the chosen strategy, dropping it only if the error indicts
    /// the **resolver** rather than the name.
    ///
    /// This gate is the whole reason the transport can self-heal at all. An earlier version evicted on
    /// any empty result and had to be reverted: flint reported NXDOMAIN and a dead resolver
    /// identically, so a user visiting a domain that does not exist would have discarded a working
    /// strategy and forced a full verified search on the next flow. `flint_dns::indicts_resolver` now
    /// separates the two, so only genuine resolver failure — unreachable, timed out, or an answer that
    /// cannot be believed — triggers re-selection.
    ///
    /// Deliberately not called for a failed *connect*: an unreachable destination says nothing about
    /// the strategy, and re-searching cannot fix it.
    fn note_resolution_failure(&self, chosen: &Strategy, err: &io::Error) {
        if !flint_dns::indicts_resolver(err) {
            return;
        }
        // Only evict the strategy that actually failed. Flows run concurrently, so a slow one can
        // arrive here holding a strategy that has already been replaced — dropping the *current* one
        // on that stale evidence would discard a working strategy and start another search, the churn
        // this eviction exists to avoid. Compared by resolver name because that is the identity the
        // failure is about (and the one `StrategyCache` keys on): a different resolver is simply not
        // what was indicted.
        // Compare and clear under a **single** write lock. Checking with `peek()` and then calling
        // `forget()` leaves a window between the read unlock and the write lock in which another flow
        // can install a fresh strategy — which this call would then wipe on evidence about the old one.
        // That is a narrower instance of the very race the comparison exists to prevent, so it has to
        // be atomic rather than merely unlikely. No `.await` here, so holding the lock is safe.
        {
            let mut current = self.chosen.write().unwrap_or_else(|e| e.into_inner());
            match current.as_ref() {
                Some(c) if c.strategy.resolver.name == chosen.resolver.name => *current = None,
                _ => return,
            }
        }
        // Deliberately does NOT clear the per-network cache. `find_cached` already re-verifies the
        // cached winner on its next call and forgets it only if *that* entry actually fails, so
        // clearing here would be redundant — and worse than redundant, because our clear is
        // unconditional: a concurrent search that had just recorded a fresh winner would lose it, the
        // same evict-on-stale-evidence flaw this method exists to avoid one level up. Dropping the memo
        // is enough to force the re-selection, and flint self-heals its own cache.
        tracing::debug!(
            resolver = %chosen.resolver.name,
            error = %err,
            "proxyless resolver failed; dropping the strategy so the next flow re-selects"
        );
    }

    /// Drop the memoized pairing so the next dial searches again — for a caller that has observed the
    /// current one failing.
    pub fn forget(&self) {
        // Forget the cache entry for whichever network the memo was actually filed under, not for
        // whatever the probe reports now — after a network change those differ, and clearing by the
        // current key would evict an innocent entry while leaving the failing one in place. Falls back
        // to the current key when there is no memo to read the network from.
        let key = {
            let guard = self.chosen.read().unwrap_or_else(|e| e.into_inner());
            guard.as_ref().map(|c| c.network.clone())
        };
        *self.chosen.write().unwrap_or_else(|e| e.into_inner()) = None;
        if let Some(key) = key.or_else(|| self.network_key()) {
            self.cache.forget(&key);
        }
    }

    /// Connect to `addr` and shape the opening write. The application's own bytes — its ClientHello
    /// first — are what get shaped.
    async fn shaped_connect(&self, addr: SocketAddr, wire: &WirePlan) -> io::Result<BoxedStream> {
        let tcp = protected_tcp_connect(addr, self.protector.as_ref()).await?;
        if wire.tcp_nodelay {
            // Each flushed segment should leave as its own packet, or the shaping is coalesced away —
            // so a failure here silently weakens the evasion rather than breaking the connection, which
            // is exactly the kind of thing worth a log line.
            if let Err(e) = tcp.set_nodelay(true) {
                tracing::warn!(peer = %addr, error = %e, "could not set TCP_NODELAY; shaped segments may coalesce");
            }
        }
        // Record fragmentation (Layer B) outermost over segment shaping (Layer C), matching
        // `flint_dial`'s ordering: the ClientHello is re-framed into records, then those bytes are split
        // across TCP segments.
        Ok(Box::new(RecordFragmentingStream::new(
            SegmentShapingStream::new(tcp, wire.clone()),
            wire.clone(),
        )))
    }
}

#[async_trait]
impl Transport for ProxylessTransport {
    async fn dial(&self, target: SocketAddr) -> io::Result<BoxedStream> {
        // Already an address, so only the shaping half applies — see the module docs on why the
        // resolver half needs a name to work with.
        let chosen = self.strategy().await?;
        self.shaped_connect(target, &chosen.policy.wire).await
    }

    async fn dial_addr(&self, target: Address) -> io::Result<BoxedStream> {
        match target {
            Address::Ip(addr) => self.dial(addr).await,
            Address::Domain { host, port } => {
                // The path where proxyless is fully itself: resolve through the chosen un-poisoned
                // resolver rather than whatever the network would have answered.
                let chosen = self.strategy().await?;
                // Both families, A first — asking only for A would strand a v6-only network, the same
                // reason `crate::dns::DohResolver` queries both. Either query may legitimately fail
                // (no AAAA record is normal), so only the empty union is an error.
                let (a, aaaa) = tokio::join!(
                    flint_dns::resolve_one_with(
                        &chosen.resolver,
                        &host,
                        flint_dns::TYPE_A,
                        &chosen.policy
                    ),
                    flint_dns::resolve_one_with(
                        &chosen.resolver,
                        &host,
                        flint_dns::TYPE_AAAA,
                        &chosen.policy
                    ),
                );
                // Keep the failures rather than discarding them: whether they indict the *resolver*
                // or merely say the *name* does not resolve is what decides re-selection below.
                let mut addrs = Vec::new();
                let mut failure: Option<io::Error> = None;
                for result in [a, aaaa] {
                    match result {
                        Ok(found) => addrs.extend(found),
                        Err(e) => {
                            if outranks(failure.as_ref(), &e) {
                                failure = Some(e);
                            }
                        }
                    }
                }
                if addrs.is_empty() {
                    let err = failure.unwrap_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotFound,
                            format!(
                                "proxyless resolver {} returned no address for {host}",
                                chosen.resolver.name
                            ),
                        )
                    });
                    self.note_resolution_failure(&chosen, &err);
                    return Err(err);
                }
                // Try each in order rather than committing to the first: on a single-stack network the
                // wrong family is unreachable, and the resolver cannot know which stack this host has.
                let mut last = None;
                for ip in addrs {
                    match self
                        .shaped_connect(SocketAddr::new(ip, port), &chosen.policy.wire)
                        .await
                    {
                        Ok(stream) => return Ok(stream),
                        Err(e) => last = Some(e),
                    }
                }
                Err(last.unwrap_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, format!("no address for {host}"))
                }))
            }
        }
    }
}

#[async_trait]
impl UdpTransport for ProxylessTransport {
    /// UDP goes straight out, unshaped.
    ///
    /// The shaping axis is TCP-segment and TLS-record framing, neither of which exists for a datagram,
    /// and there is no proxy to relay through — so this is a plain protected socket, identical to
    /// [`DirectTransport`](super::DirectTransport). Stated rather than silently implied: a QUIC/HTTP-3
    /// flow over proxyless gets un-poisoned DNS only where spark resolved the name, and no first-flight
    /// obfuscation at all.
    async fn dial_udp(
        &self,
        target: SocketAddr,
    ) -> io::Result<(BoxedPacketSink, BoxedPacketSource)> {
        let socket = protected_udp_socket(target, self.protector.as_ref())?;
        let socket = UdpSocket::from_std(socket.into())?;
        socket.connect(target).await?;
        let socket = Arc::new(socket);
        Ok((
            Box::new(DirectPacketSink(Arc::clone(&socket))),
            Box::new(DirectPacketSource(socket)),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> ProxylessConfig {
        ProxylessConfig::default()
    }

    #[test]
    fn defaults_to_the_diverse_doh_pool_and_the_no_op_plan_only() {
        let t = ProxylessTransport::new(&cfg(), WirePlan::default(), None).unwrap();
        assert_eq!(t.space.resolvers.len(), flint_dns::default_pool().len());
        // A no-op configured plan must not be added as a second axis entry: it would double the space
        // to search the same thing twice.
        assert_eq!(t.space.wires.len(), 1);
    }

    #[test]
    fn a_real_shaping_plan_becomes_a_second_axis_entry() {
        let wire = WirePlan {
            record_fragment: flint_shaping::RecordFragment::SniStraddle,
            ..Default::default()
        };
        let t = ProxylessTransport::new(&cfg(), wire, None).unwrap();
        assert_eq!(t.space.wires.len(), 2);
        assert!(
            t.space.wires[0].is_noop(),
            "the cheap plan must be tried first"
        );
    }

    #[test]
    fn the_candidate_cap_is_a_strict_upper_bound() {
        let wire = WirePlan {
            record_fragment: flint_shaping::RecordFragment::SniStraddle,
            ..Default::default()
        };
        for max in [1usize, 2, 3, 5, 8, 100] {
            let c = ProxylessConfig {
                max_candidates: Some(max),
                ..Default::default()
            };
            let t = ProxylessTransport::new(&c, wire.clone(), None).unwrap();
            // No escape hatch: the bound must hold for every cap, including caps larger than the space
            // (where no trim happens) and caps below the shaping-plan count (where plans give way).
            assert!(
                t.space.len() <= max,
                "cap {max} produced {} candidates",
                t.space.len()
            );
            assert!(!t.space.is_empty(), "cap {max} left nothing to search");
        }
    }

    #[test]
    fn test_domains_default_to_two_independent_operators() {
        let t = ProxylessTransport::new(&cfg(), WirePlan::default(), None).unwrap();
        assert_eq!(t.test_domains.len(), 2);
        let c = ProxylessConfig {
            test_domains: vec!["only.example".to_string()],
            ..Default::default()
        };
        let t = ProxylessTransport::new(&c, WirePlan::default(), None).unwrap();
        assert_eq!(t.test_domains, vec!["only.example".to_string()]);
    }

    #[test]
    fn a_zero_candidate_cap_is_rejected_rather_than_clamped() {
        // Config is user input: `0` can only be a mistake, and silently searching one candidate would
        // contradict the documented strict bound.
        let c = ProxylessConfig {
            max_candidates: Some(0),
            ..Default::default()
        };
        // Not `expect_err`: the Ok type is the transport, which has no `Debug`.
        let err = match ProxylessTransport::new(&c, WirePlan::default(), None) {
            Ok(_) => panic!("a zero cap must be rejected"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("must be at least 1"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn concurrent_first_dials_run_only_one_search() {
        // The single-flight gate: many flows arriving before the first search completes must not each
        // start their own. Proven without a network by pre-seeding the memo and checking that a racing
        // caller observes the same strategy rather than re-selecting.
        use std::sync::Arc as StdArc;
        // Pinned, so `network_key()` is deterministic and matches what the memo is seeded under.
        // Without this the transport measures the *test host's* network, rejects the seed as belonging
        // to another network, and every task falls through to a real search.
        let t =
            StdArc::new(ProxylessTransport::new(&pinned_cfg(), WirePlan::default(), None).unwrap());
        let seeded = flint_proxyless::Strategy {
            resolver: flint_dns::default_pool()[0].clone(),
            policy: Default::default(),
        };
        *t.chosen.write().unwrap() = Some(Chosen {
            network: TEST_NETWORK.to_string(),
            strategy: seeded.clone(),
        });

        let mut tasks = Vec::new();
        for _ in 0..8 {
            let t = StdArc::clone(&t);
            tasks.push(tokio::spawn(async move {
                t.strategy().await.map(|s| s.resolver.name)
            }));
        }
        for task in tasks {
            assert_eq!(task.await.unwrap().unwrap(), seeded.resolver.name);
        }
    }

    /// The network the test memo is filed under. Any fixed string works; what matters is that the
    /// assertions name it explicitly rather than depending on whatever network the test host is on.
    const TEST_NETWORK: &str = "v4=198.51.100.7 v6=-";

    /// A config pinned to [`TEST_NETWORK`], so `network_key()` is deterministic instead of measuring
    /// whatever network the test host happens to be attached to.
    fn pinned_cfg() -> ProxylessConfig {
        ProxylessConfig {
            network: TEST_NETWORK.to_string(),
            ..cfg()
        }
    }

    /// A transport with a strategy already chosen on [`TEST_NETWORK`], so eviction is observable.
    fn with_chosen() -> (ProxylessTransport, flint_proxyless::Strategy) {
        let t = ProxylessTransport::new(&pinned_cfg(), WirePlan::default(), None).unwrap();
        let strategy = flint_proxyless::Strategy {
            resolver: flint_dns::default_pool()[0].clone(),
            policy: Default::default(),
        };
        *t.chosen.write().unwrap() = Some(Chosen {
            network: TEST_NETWORK.to_string(),
            strategy: strategy.clone(),
        });
        (t, strategy)
    }

    #[test]
    fn a_name_that_does_not_resolve_keeps_the_strategy() {
        // The regression that forced this eviction to be reverted once: a user visiting a domain that
        // does not exist must not cost a working strategy, because the next flow would then pay for a
        // full verified search.
        let (t, chosen) = with_chosen();
        t.note_resolution_failure(
            &chosen,
            &io::Error::new(io::ErrorKind::NotFound, "NXDOMAIN"),
        );
        assert!(
            t.peek(Some(TEST_NETWORK)).is_some(),
            "a nonexistent domain must not evict the strategy"
        );
    }

    #[test]
    fn a_failing_resolver_drops_the_strategy_so_the_next_flow_reselects() {
        for kind in [
            io::ErrorKind::TimedOut,          // blackholed
            io::ErrorKind::ConnectionRefused, // actively refused
            io::ErrorKind::InvalidData,       // answered, but unbelievably (SERVFAIL, bogons, …)
        ] {
            let (t, chosen) = with_chosen();
            t.note_resolution_failure(&chosen, &io::Error::new(kind, "resolver is gone"));
            assert!(
                t.peek(Some(TEST_NETWORK)).is_none(),
                "{kind:?} should drop the strategy and force a re-select"
            );
        }
    }

    #[test]
    fn a_stale_failure_does_not_evict_a_newly_chosen_strategy() {
        // Flows run concurrently, so a slow one can arrive holding a strategy that has already been
        // replaced. Evicting on that stale evidence would discard a *working* strategy and start
        // another search — the churn this eviction exists to avoid.
        let (t, stale) = with_chosen();
        let current = flint_proxyless::Strategy {
            resolver: flint_dns::default_pool()[1].clone(),
            policy: Default::default(),
        };
        assert_ne!(stale.resolver.name, current.resolver.name);
        *t.chosen.write().unwrap() = Some(Chosen {
            network: TEST_NETWORK.to_string(),
            strategy: current,
        });

        t.note_resolution_failure(
            &stale,
            &io::Error::new(io::ErrorKind::TimedOut, "old resolver"),
        );
        assert!(
            t.peek(Some(TEST_NETWORK)).is_some(),
            "a failure from a superseded strategy must not evict the current one"
        );
    }

    #[test]
    fn an_indicting_failure_outranks_a_merely_absent_record() {
        let timeout = io::Error::new(io::ErrorKind::TimedOut, "resolver gone");
        let nxdomain = io::Error::new(io::ErrorKind::NotFound, "no AAAA");

        // Whichever family finishes last must not decide: an indicting failure wins either way.
        assert!(
            outranks(None, &nxdomain),
            "the first failure is always kept"
        );
        assert!(
            outranks(Some(&nxdomain), &timeout),
            "a timeout must replace a no-record answer"
        );
        assert!(
            !outranks(Some(&timeout), &nxdomain),
            "a no-record answer must not mask a timeout"
        );
        // Never downgrade, and never churn between two of equal rank.
        assert!(!outranks(Some(&timeout), &timeout));
        assert!(!outranks(Some(&nxdomain), &nxdomain));
    }

    #[test]
    fn our_own_bad_input_does_not_evict_either() {
        // `InvalidInput` means the query was never sent, so no resolver was involved — evicting would
        // churn selection over a caller error.
        let (t, chosen) = with_chosen();
        t.note_resolution_failure(
            &chosen,
            &io::Error::new(io::ErrorKind::InvalidInput, "unencodable name"),
        );
        assert!(
            t.peek(Some(TEST_NETWORK)).is_some(),
            "a caller-input error blames nobody"
        );
    }

    #[test]
    fn forget_clears_the_memoized_strategy() {
        let t = ProxylessTransport::new(&cfg(), WirePlan::default(), None).unwrap();
        assert!(
            t.peek(Some(TEST_NETWORK)).is_none(),
            "nothing chosen before the first dial"
        );

        // Actually install one, or this asserts None before and None after and proves nothing about
        // `forget` at all.
        let (t, _) = with_chosen();
        assert!(t.peek(Some(TEST_NETWORK)).is_some());
        t.forget();
        assert!(
            t.peek(Some(TEST_NETWORK)).is_none(),
            "forget must drop the memo"
        );
    }

    #[test]
    fn a_strategy_proven_on_one_network_is_not_reused_on_another() {
        // The whole point of carrying the network with the memo. Before this, the pairing chosen on
        // home wifi was handed to every flow on the café network for the life of the process — the
        // resolver may be blocked there, and the shaping may be wrong for its DPI.
        let (t, _) = with_chosen();
        assert!(t.peek(Some(TEST_NETWORK)).is_some(), "same network reuses");
        assert!(
            t.peek(Some("v4=203.0.113.9 v6=-")).is_none(),
            "a different network must force a fresh search"
        );
    }

    #[test]
    fn an_undeterminable_network_keeps_the_strategy_rather_than_discarding_it() {
        // `None` is "cannot tell", which happens when the host is momentarily offline. Treating that as
        // a change would throw away a good strategy on every connectivity blip — and the dial that
        // follows is going to fail on its own merits regardless, so nothing is gained by re-searching.
        let (t, _) = with_chosen();
        assert!(
            t.peek(None).is_some(),
            "ignorance is not evidence of change"
        );
    }

    #[test]
    fn an_explicit_network_setting_overrides_the_probe() {
        // A deployment that pins `network` is asserting the identity itself; probing would second-guess
        // it, and on a host with no route the probe would return `None` and silently disable the
        // pinning. Also the hook tests use to get a deterministic key.
        let mut c = cfg();
        c.network = "pinned-slot".to_string();
        let t = ProxylessTransport::new(&c, WirePlan::default(), None).unwrap();
        assert_eq!(t.network_key().as_deref(), Some("pinned-slot"));
    }

    #[test]
    fn with_no_explicit_setting_the_key_is_measured_from_the_host() {
        // Not asserting a specific value — that would just re-hardcode whatever this machine happens to
        // be on. The contract is that an unset `network` stops meaning "one global slot" and starts
        // meaning "whatever egress we actually have", including `None` on a host with no route.
        let t = ProxylessTransport::new(&cfg(), WirePlan::default(), None).unwrap();
        assert_eq!(t.network_key(), crate::net::egress_fingerprint(None));
    }
}
