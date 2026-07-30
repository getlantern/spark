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

/// Test domains a strategy must reach before it is trusted, when the config names none.
///
/// Two, on different operators and jurisdictions, because `find_cached` requires **all** of them: one
/// domain might be reachable by accident on an otherwise hostile network, and a single accidental
/// success would then vouch for a strategy that does not work.
const DEFAULT_TEST_DOMAINS: [&str; 2] = ["example.com", "www.wikipedia.org"];

/// Reaches destinations directly using a searched-for `(resolver, shaping)` pairing.
pub struct ProxylessTransport {
    space: Space,
    cache: StrategyCache,
    network: String,
    test_domains: Vec<String>,
    /// The chosen pairing, memoized after the first search. A search costs verified handshakes, so it
    /// must not run per flow.
    chosen: RwLock<Option<Strategy>>,
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
        if let Some(chosen) = self.peek() {
            return Ok(chosen);
        }
        // Single-flight: only one search runs even if many flows arrive together. flint's cache records
        // a *completed* winner and has no in-progress state, so without this gate each concurrent first
        // dial would run its own full search.
        let _gate = self.selecting.lock().await;
        // Re-check under the gate — whoever held it before us may already have chosen.
        if let Some(chosen) = self.peek() {
            return Ok(chosen);
        }
        let chosen = flint_proxyless::find_cached(
            &self.space,
            &self.test_domains,
            &self.cache,
            &self.network,
        )
        .await
        .map_err(|e| {
            io::Error::other(format!(
                "no proxyless strategy reaches the test domains: {e}"
            ))
        })?;
        tracing::info!(
            resolver = %chosen.resolver.name,
            shaped = !chosen.policy.wire.is_noop(),
            "selected proxyless strategy"
        );
        *self.chosen.write().unwrap_or_else(|e| e.into_inner()) = Some(chosen.clone());
        Ok(chosen)
    }

    /// The memoized pairing, if a search has already succeeded. Clones out so the guard drops here.
    ///
    /// Poisoning is recovered rather than treated as a miss (spark's convention — see
    /// [`crate::transport::fronted_meek`]). Treating it as a miss would be quietly expensive here: a
    /// panic anywhere else holding this lock would send *every* subsequent flow back through a full
    /// verified search, forever.
    fn peek(&self) -> Option<Strategy> {
        self.chosen
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Drop the memoized pairing so the next dial searches again — for a caller that has observed the
    /// current one failing.
    pub fn forget(&self) {
        *self.chosen.write().unwrap_or_else(|e| e.into_inner()) = None;
        self.cache.forget(&self.network);
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
                let mut addrs = a.unwrap_or_default();
                addrs.extend(aaaa.unwrap_or_default());
                if addrs.is_empty() {
                    // Deliberately does *not* evict the chosen strategy. It is tempting to read "no
                    // address" as "this resolver is dead, re-select" — but flint reports an ordinary
                    // negative answer the same way it reports a dead resolver: `parse_response` turns a
                    // non-zero RCODE into `Err(DnsError::Rcode)` and `validate_answers` errors on an
                    // empty set, so NXDOMAIN for a typo'd host is indistinguishable from a transport
                    // failure at this layer. Evicting here would throw away a perfectly good strategy —
                    // and force a full verified search on the next flow — every time a user visits a
                    // domain that does not exist.
                    //
                    // Re-selection therefore needs a signal this layer does not have; see ADR 0014.
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!(
                            "proxyless resolver {} returned no address for {host}",
                            chosen.resolver.name
                        ),
                    ));
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
        let t = StdArc::new(ProxylessTransport::new(&cfg(), WirePlan::default(), None).unwrap());
        let seeded = flint_proxyless::Strategy {
            resolver: flint_dns::default_pool()[0].clone(),
            policy: Default::default(),
        };
        *t.chosen.write().unwrap() = Some(seeded.clone());

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

    #[test]
    fn forget_clears_the_memoized_strategy() {
        let t = ProxylessTransport::new(&cfg(), WirePlan::default(), None).unwrap();
        assert!(t.peek().is_none(), "nothing chosen before the first dial");
        t.forget();
        assert!(t.peek().is_none());
    }
}
