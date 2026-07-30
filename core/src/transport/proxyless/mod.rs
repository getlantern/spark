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
            // Bounding the cold search matters because it is a search, not a dial; see
            // `flint_kindling::ProxylessTransport` for the budget arithmetic this mirrors.
            let capped = max.max(1);
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
        if let Ok(mut slot) = self.chosen.write() {
            *slot = Some(chosen.clone());
        }
        Ok(chosen)
    }

    /// The memoized pairing, if a search has already succeeded. Clones out so the guard drops here.
    fn peek(&self) -> Option<Strategy> {
        self.chosen.read().ok()?.clone()
    }

    /// Drop the memoized pairing so the next dial searches again — for a caller that has observed the
    /// current one failing.
    pub fn forget(&self) {
        if let Ok(mut slot) = self.chosen.write() {
            *slot = None;
        }
        self.cache.forget(&self.network);
    }

    /// Connect to `addr` and shape the opening write. The application's own bytes — its ClientHello
    /// first — are what get shaped.
    async fn shaped_connect(&self, addr: SocketAddr, wire: &WirePlan) -> io::Result<BoxedStream> {
        let tcp = protected_tcp_connect(addr, self.protector.as_ref()).await?;
        if wire.tcp_nodelay {
            // Each flushed segment should leave as its own packet, or the shaping is coalesced away.
            let _ = tcp.set_nodelay(true);
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
                let addrs = flint_dns::resolve_one_with(
                    &chosen.resolver,
                    &host,
                    flint_dns::TYPE_A,
                    &chosen.policy,
                )
                .await?;
                let ip = addrs.first().copied().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!(
                            "proxyless resolver {} returned no address for {host}",
                            chosen.resolver.name
                        ),
                    )
                })?;
                self.shaped_connect(SocketAddr::new(ip, port), &chosen.policy.wire)
                    .await
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
        for max in [0usize, 1, 2, 3, 5, 8, 100] {
            let c = ProxylessConfig {
                max_candidates: Some(max),
                ..Default::default()
            };
            let t = ProxylessTransport::new(&c, wire.clone(), None).unwrap();
            // No escape hatch: the bound must hold for every cap, including caps larger than the space
            // (where no trim happens) and caps below the shaping-plan count (where plans give way).
            let want = max.max(1);
            assert!(
                t.space.len() <= want,
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
    fn forget_clears_the_memoized_strategy() {
        let t = ProxylessTransport::new(&cfg(), WirePlan::default(), None).unwrap();
        assert!(t.peek().is_none(), "nothing chosen before the first dial");
        t.forget();
        assert!(t.peek().is_none());
    }
}
