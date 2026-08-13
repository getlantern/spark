//! TCP forwarder.
//!
//! For each flow the netstack surfaces, obtain an upstream stream from the configured
//! [`Transport`] and splice the two streams together with [`copy_bidirectional`]. The
//! transport decides *how* the upstream is reached: [`DirectTransport`](crate::transport::DirectTransport)
//! connects straight to the target (the M2 behavior), while the tunnel client routes the
//! bytes through a tunnel server (M4). The forwarder is identical either way.
//!
//! Log hygiene (a product privacy property — see `docs/GOAL.md`): destination addresses
//! are logged at `debug` only. The default (`info`) level reports byte counts on close,
//! which carry no destination.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::io::copy_bidirectional;
use tracing::{debug, info, warn};

use crate::metrics::{Counting, Metrics, SessionGuard};
use crate::netstack::{Netstack, TcpFlow};
use crate::proxy::{Decision, RouteHooks};
use crate::transport::{Address, Transport};
use crate::BoxedStream;

/// Run the accept→forward loop until the netstack stops yielding flows. For each flow, `hooks` (when
/// present) recover its domain (fake-IP DNS), decide the action, and resolve where needed; a proxied
/// flow dials through `proxy_transport`, a direct flow through `direct_transport`, a rejected flow is
/// dropped. With no `hooks` every flow is proxied by IP — today's behavior. `metrics` tallies per-flow
/// byte/session counts.
///
/// Each accepted flow is forwarded on its own task so that a slow (or hung) upstream dial — or a
/// per-flow DNS resolution — cannot stall acceptance of other flows.
pub async fn run<N: Netstack>(
    mut netstack: N,
    proxy_transport: Arc<dyn Transport>,
    direct_transport: Arc<dyn Transport>,
    hooks: Option<Arc<RouteHooks>>,
    metrics: Arc<Metrics>,
) {
    while let Some(flow) = netstack.accept_tcp().await {
        tokio::spawn(forward(
            flow,
            Arc::clone(&proxy_transport),
            Arc::clone(&direct_transport),
            hooks.clone(),
            Arc::clone(&metrics),
        ));
    }
    debug!("netstack accept loop ended");
}

/// Route and forward one flow: recover its domain, decide the action, dial the appropriate upstream
/// (resolving per action where the destination is a fake IP), then splice bytes until either side
/// closes. Runs on its own task so resolution/dial latency doesn't stall the accept loop.
async fn forward(
    flow: TcpFlow,
    proxy_transport: Arc<dyn Transport>,
    direct_transport: Arc<dyn Transport>,
    hooks: Option<Arc<RouteHooks>>,
    metrics: Arc<Metrics>,
) {
    let TcpFlow {
        original_dst,
        src,
        mut stream,
        abort,
    } = flow;

    // Count this flow as active for its whole lifetime — including if this task is aborted on stop
    // (the guard decrements on drop).
    let _session = SessionGuard::open(Arc::clone(&metrics));

    // Stamped before any of the flow's work — domain recovery, the routing decision, the dial — so
    // `connect_ms` and `ttfb_ms` measure what the user actually waits through. Placing it after
    // routing would silently exclude rule matching and fake-IP recovery, which is precisely the kind
    // of cost worth being able to see.
    let flow_start = std::time::Instant::now();

    let hooks = hooks.as_deref();
    // Recover the domain behind the (possibly fake) destination IP, then decide the action on it.
    let domain = hooks
        .and_then(|h| h.recoverer.as_deref())
        .and_then(|r| r.recover(original_dst.ip()));
    // With smart-routing/fake-IP active, Reject encrypted DNS to public resolvers (DoT :853, DoH
    // :443) so the client falls back to plain :53 — which the fake-IP server answers, keeping domains
    // visible for routing/ad-block (else Private DNS / browser DoH bypasses fake-IP entirely).
    let enc_dns = hooks.is_some() && super::is_encrypted_dns(original_dst, domain.as_deref());
    let decision = if enc_dns {
        Decision::Reject
    } else {
        hooks
            .map(|h| {
                h.router.decide(
                    original_dst.ip(),
                    domain.as_deref(),
                    src,
                    crate::process::Protocol::Tcp,
                )
            })
            .unwrap_or(Decision::Proxy)
    };
    if enc_dns {
        debug!(dst = %original_dst, "encrypted DNS to a public resolver — rejecting so DNS falls back to plain :53");
    }
    debug!(src = %src, dst = %original_dst, domain = domain.as_deref().unwrap_or("-"), ?decision, "tcp flow: routing");

    let upstream = match decision {
        // Reject with RST when the netstack offers it (fail fast — the client sees ECONNRESET in
        // milliseconds, like a real firewall REJECT); merely dropping `stream` leaves the client
        // socket dangling until its own timeout. Destination at debug only (log hygiene).
        Decision::Reject => {
            debug!(dst = %original_dst, "tcp flow rejected by routing rule");
            // Fire the abort hook FIRST (sets abort_pending + notifies → the netstack runner
            // aborts the socket with an RST), then drop the stream. Dropping first would race:
            // `TcpStream::drop` also notifies the runner (Close state), which could observe Close
            // and `socket.close()` (FIN) before `abort_pending` is set, losing the RST semantics.
            if let Some(abort) = abort {
                abort();
            }
            drop(stream);
            return;
        }
        Decision::Direct => {
            dial_direct(
                &direct_transport,
                &proxy_transport,
                hooks,
                domain.as_deref(),
                original_dst,
            )
            .await
        }
        Decision::Proxyless => match hooks.and_then(|h| h.proxyless_transport.clone()) {
            // Proxyless carries the domain itself: its transport resolves through the chosen
            // un-poisoned resolver, so unlike Direct there is nothing to pre-resolve here — handing it
            // the name is the whole point.
            Some(px) => match domain.as_deref().and_then(|dom| {
                Address::domain(dom, original_dst.port())
                    .inspect_err(
                        |e| debug!(domain = %dom, error = %e, "proxyless: unusable domain"),
                    )
                    .ok()
            }) {
                Some(addr) => match px.dial_addr(addr).await {
                    Ok(s) => Some(s),
                    Err(e) => {
                        warn!(error = %e, "proxyless dial-by-name failed");
                        None
                    }
                },
                // Real-IP flow (or an unusable name): dial the address. Shaping still applies; only
                // the un-poisoned-resolution half is unavailable without a name.
                None => dial_or_log(&px, original_dst).await,
            },
            None => {
                // Fail closed. A rule asked for circumvention; a plain direct dial would not provide
                // it, and the proxy would add the exit hop the rule declined. Neither is this rule.
                debug!(dst = %original_dst, "proxyless rule but no proxyless transport configured — rejecting");
                None
            }
        },
        Decision::Proxy => dial_proxy(&proxy_transport, domain.as_deref(), original_dst).await,
    };
    let Some(upstream) = upstream else {
        return; // dial failed (already logged)
    };
    // Wrap the upstream half so writes (app→upstream) count as `up` and reads (upstream→app) as
    // `down`. `&mut *stream` derefs the box to the `dyn` stream `copy_bidirectional` accepts.
    let mut upstream = Counting::new(upstream, metrics);
    // `connect_ms` is everything up to here: routing, the dial, and the transport's own handshake.
    let connect_ms = flow_start.elapsed().as_millis() as u64;
    // Timed so the flow's *throughput* is recoverable, not just its size. Byte counts alone cannot
    // answer "is the tunnel slow" — the question telemetry kept being asked and could not settle.
    let started = std::time::Instant::now();
    match copy_bidirectional(&mut *stream, &mut upstream).await {
        Ok((to_upstream, to_app)) => {
            let duration_ms = started.elapsed().as_millis() as u64;
            // From before the dial, so it covers connect + handshake + the origin's own think time —
            // what "how long until anything came back" actually means.
            let ttfb_ms = upstream
                .first_read_at()
                .map(|t| t.duration_since(flow_start).as_millis() as u64);
            info!(
                to_upstream,
                to_app, duration_ms, connect_ms, ttfb_ms, "tcp flow completed"
            );
            // Structured twin of the line above: the diag layer forwards only `message`, so these
            // numbers reach the collector as prose unless they are emitted as real fields.
            crate::diag::emit(crate::diag::events::proxy_flow_completed(
                duration_ms,
                to_upstream,
                to_app,
                connect_ms,
                ttfb_ms,
            ));
        }
        Err(e) => warn!(error = %e, "tcp flow error"),
    }
}

/// Dial a Direct flow. A **domain** flow's `original_dst` is a fake IP, so it must be resolved to a
/// real IP (via the local resolver) before a direct dial. It falls back to **Proxy** rather than drop
/// the flow if there is no resolver, resolution fails, *or* the direct dial itself fails (direct
/// egress temporarily unavailable) — and never dials the fake IP. A **real-IP** flow (no domain) is
/// direct-dialed as-is.
async fn dial_direct(
    direct: &Arc<dyn Transport>,
    proxy: &Arc<dyn Transport>,
    hooks: Option<&RouteHooks>,
    domain: Option<&str>,
    original_dst: SocketAddr,
) -> Option<BoxedStream> {
    let Some(dom) = domain else {
        return dial_or_log(direct, original_dst).await; // real-IP flow → direct-dial as-is
    };
    if let Some(res) = hooks.and_then(|h| h.direct_resolver.as_deref()) {
        if let Ok(ips) = res.resolve(dom).await {
            if let Some(ip) = pick_ip(&ips, original_dst.ip()) {
                if let Some(stream) =
                    dial_or_log(direct, SocketAddr::new(ip, original_dst.port())).await
                {
                    return Some(stream);
                }
                // Direct dial failed — fall through to proxy rather than drop the flow.
            }
        }
    }
    // No resolver, resolution failed, or the direct dial failed: never dial the fake IP — proxy it.
    debug!(domain = %dom, "direct egress unavailable; proxying instead");
    dial_proxy(proxy, domain, original_dst).await
}

/// Dial a Proxy flow. A **domain** flow behind a fake IP is dialed **by name**: the domain goes to
/// the exit so *it* resolves — no client DNS lookup, and exit-optimal CDN IPs.
///
/// There is no client-side fallback. `Transport::dial_addr` is a required method, so every proxy
/// transport carries a name; one that cannot fails the flow rather than resolving here, because a
/// client-side lookup would put the destination into a DNS query on the local network — the
/// disclosure proxying exists to prevent. A **real-IP** flow has no name to carry and is proxied by
/// IP.
async fn dial_proxy(
    proxy: &Arc<dyn Transport>,
    domain: Option<&str>,
    original_dst: SocketAddr,
) -> Option<BoxedStream> {
    let Some(dom) = domain else {
        return dial_or_log(proxy, original_dst).await; // real-IP flow → proxy by IP
    };
    // Hand the domain to the exit so *it* resolves. There is deliberately no client-side fallback:
    // resolving here would put the destination into a local DNS lookup, which is the disclosure
    // proxying exists to prevent. `Transport::dial_addr` is a required method precisely so a
    // transport cannot opt out of carrying the name and silently land us here.
    let addr = match Address::domain(dom, original_dst.port()) {
        Ok(a) => a,
        Err(e) => {
            // The error names the defect, never the destination — so it is safe at warn, and the
            // failure stays diagnosable without the domain.
            debug!(domain = %dom, "proxy: unusable domain target");
            warn!(error = %e, "proxy: unusable domain target");
            return None;
        }
    };
    match proxy.dial_addr(addr).await {
        Ok(s) => Some(s),
        Err(e) => {
            // Log hygiene: no destination at warn level (see the module docs); domain at debug.
            debug!(domain = %dom, "proxy dial-by-name failed");
            warn!(error = %e, "proxy dial-by-name failed");
            None
        }
    }
}

/// Pick a resolved IP whose family matches `want` (the flow's fake destination family — i.e. what the
/// app asked for via DNS: A→v4, AAAA→v6), falling back to the first result. Avoids, e.g., dialing a v6
/// address first for a v4 flow when the resolver returns both. (Full cross-family happy-eyeballs is a
/// future improvement.)
pub(crate) fn pick_ip(ips: &[IpAddr], want: IpAddr) -> Option<IpAddr> {
    ips.iter()
        .copied()
        .find(|ip| ip.is_ipv4() == want.is_ipv4())
        .or_else(|| ips.first().copied())
}

/// Dial `target` through `transport`, logging (destination at debug via the caller) and returning
/// `None` on failure.
async fn dial_or_log(transport: &Arc<dyn Transport>, target: SocketAddr) -> Option<BoxedStream> {
    match transport.dial(target).await {
        Ok(s) => Some(s),
        Err(e) => {
            warn!(error = %e, "dial to upstream failed");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use async_trait::async_trait;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use crate::transport::tcp_tunnel::client::TunnelClient;
    use crate::transport::tcp_tunnel::header::Address;
    use crate::transport::tcp_tunnel::stream::read_header;
    use crate::transport::DirectTransport;

    /// A `Netstack` that surfaces a single pre-built flow, then signals shutdown. Lets us
    /// exercise the forwarder's data path with no TUN and no userspace stack.
    struct OneFlow(Option<TcpFlow>);

    #[async_trait]
    impl Netstack for OneFlow {
        async fn accept_tcp(&mut self) -> Option<TcpFlow> {
            self.0.take()
        }
    }

    /// Spawn a loopback TCP echo server; return its address.
    async fn spawn_echo() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    loop {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) if sock.write_all(&buf[..n]).await.is_err() => break,
                            Ok(_) => {}
                        }
                    }
                });
            }
        });
        addr
    }

    /// Run a flow whose upstream is reached via `transport` (as the proxy transport, no router)
    /// and assert a payload echoes back to the application end of the flow.
    async fn assert_echo_through(transport: Arc<dyn Transport>, original_dst: SocketAddr) {
        let (mut app, flow_side) = tokio::io::duplex(1024);
        let flow = TcpFlow {
            original_dst,
            src: "10.0.0.2:12345".parse().unwrap(),
            stream: Box::new(flow_side),
            abort: None,
        };
        tokio::spawn(run(
            OneFlow(Some(flow)),
            transport,
            Arc::new(DirectTransport::default()),
            None,
            Arc::new(Metrics::default()),
        ));

        app.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        app.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");
    }

    /// `DirectTransport`: the flow's bytes reach the original destination directly and the
    /// reply makes it back — the M2 data path, now expressed through the `Transport` seam.
    #[tokio::test]
    async fn forwards_directly_to_original_dst() {
        let echo = spawn_echo().await;
        assert_echo_through(Arc::new(DirectTransport::default()), echo).await;
    }

    /// `TunnelClient`: the same flow, but the forwarder dials through a tunnel server. This
    /// is the full M4 integrated path (netstack flow → forwarder → transport → relay →
    /// echo) minus the TUN.
    #[tokio::test]
    async fn forwards_through_tunnel_transport() {
        let echo = spawn_echo().await;
        let relay = spawn_relay().await;
        assert_echo_through(Arc::new(TunnelClient::new(relay)), echo).await;
    }

    // ---- Routing (M3.2) ----

    use std::net::IpAddr;
    use std::sync::atomic::{AtomicBool, Ordering};

    use crate::proxy::{Decision, DomainRecoverer, FlowResolver, FlowRouter, RouteHooks};

    /// A `FlowRouter` that returns a fixed decision for every flow.
    struct StubRouter(Decision);

    impl FlowRouter for StubRouter {
        fn decide(
            &self,
            _ip: IpAddr,
            _domain: Option<&str>,
            _src: SocketAddr,
            _proto: crate::process::Protocol,
        ) -> Decision {
            self.0
        }
    }

    /// Hooks with a fixed-decision router and no recoverer/resolvers (the IP-only routing tests).
    fn hooks_for(decision: Decision) -> Arc<RouteHooks> {
        Arc::new(RouteHooks {
            router: Arc::new(StubRouter(decision)),
            recoverer: None,
            direct_resolver: None,
            proxyless_transport: None,
            proxyless_udp: None,
        })
    }

    /// A recoverer that maps every fake IP to one fixed domain (the fake-IP DNS connect-time half).
    struct StubRecoverer(&'static str);

    impl DomainRecoverer for StubRecoverer {
        fn recover(&self, _ip: IpAddr) -> Option<String> {
            Some(self.0.to_string())
        }
    }

    /// A resolver that returns one fixed IP for any domain, recording that it was consulted.
    struct StubResolver {
        ip: IpAddr,
        resolved: Arc<AtomicBool>,
    }

    #[async_trait]
    impl FlowResolver for StubResolver {
        async fn resolve(&self, _host: &str) -> std::io::Result<Vec<IpAddr>> {
            self.resolved.store(true, Ordering::SeqCst);
            Ok(vec![self.ip])
        }
    }

    /// A `Transport` that records whether it was dialed. Its `dial` always errors (the tests that
    /// use it only assert on whether the dial was attempted, not on the resulting stream).
    #[derive(Default)]
    struct RecordingTransport {
        dialed: AtomicBool,
    }

    #[async_trait]
    impl Transport for RecordingTransport {
        async fn dial(&self, _target: SocketAddr) -> std::io::Result<crate::BoxedStream> {
            self.dialed.store(true, Ordering::SeqCst);
            Err(std::io::Error::other(
                "recording transport does not connect",
            ))
        }

        /// Address-agnostic double: a domain dials exactly as an IP does.
        async fn dial_addr(
            &self,
            target: crate::transport::Address,
        ) -> std::io::Result<crate::BoxedStream> {
            match target {
                crate::transport::Address::Ip(sa) => self.dial(sa).await,
                crate::transport::Address::Domain { port, .. } => {
                    self.dial(std::net::SocketAddr::from(([127, 0, 0, 1], port)))
                        .await
                }
            }
        }
    }

    /// Build a one-flow netstack whose app side we keep, plus the flow to feed `run`.
    fn one_flow(original_dst: SocketAddr) -> (tokio::io::DuplexStream, OneFlow) {
        let (app, flow_side) = tokio::io::duplex(1024);
        let flow = TcpFlow {
            original_dst,
            src: "10.0.0.2:12345".parse().unwrap(),
            stream: Box::new(flow_side),
            abort: None,
        };
        (app, OneFlow(Some(flow)))
    }

    /// `Decision::Direct` → the flow is dialed via the DIRECT transport (an echo reachable only as
    /// the direct transport's target), never the proxy transport.
    #[tokio::test]
    async fn routes_direct_when_router_says_direct() {
        let echo = spawn_echo().await;
        let proxy = Arc::new(RecordingTransport::default());
        let (mut app, netstack) = one_flow(echo);
        tokio::spawn(run(
            netstack,
            proxy.clone() as Arc<dyn Transport>,
            Arc::new(DirectTransport::default()),
            Some(hooks_for(Decision::Direct)),
            Arc::new(Metrics::default()),
        ));

        app.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        app.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");
        assert!(
            !proxy.dialed.load(Ordering::SeqCst),
            "the proxy transport must not be dialed for a Direct decision"
        );
    }

    /// `Decision::Reject` → neither transport is dialed and the app side sees EOF (the flow's
    /// stream was dropped, closing the duplex).
    #[tokio::test]
    async fn rejects_flow_when_router_says_reject() {
        let proxy = Arc::new(RecordingTransport::default());
        let direct = Arc::new(RecordingTransport::default());
        let (mut app, netstack) = one_flow("203.0.113.7:443".parse().unwrap());
        tokio::spawn(run(
            netstack,
            proxy.clone() as Arc<dyn Transport>,
            direct.clone() as Arc<dyn Transport>,
            Some(hooks_for(Decision::Reject)),
            Arc::new(Metrics::default()),
        ));

        // The forwarder dropped the flow's stream half; the app side reads EOF.
        let mut buf = [0u8; 4];
        let n = app.read(&mut buf).await.unwrap();
        assert_eq!(n, 0, "a rejected flow's app side must see EOF");
        assert!(
            !proxy.dialed.load(Ordering::SeqCst),
            "the proxy transport must not be dialed for a Reject decision"
        );
        assert!(
            !direct.dialed.load(Ordering::SeqCst),
            "the direct transport must not be dialed for a Reject decision"
        );
    }

    /// `Decision::Reject` on a flow carrying an abort hook → the hook fires (RST to the client),
    /// so the client fails fast instead of hanging until its own timeout. (Dropping the smoltcp
    /// stream alone leaves the client socket ESTABLISHED — observed as ad-blocked hosts hanging
    /// browsers for 15+ s.)
    #[tokio::test]
    async fn reject_fires_the_flow_abort_hook() {
        let proxy = Arc::new(RecordingTransport::default());
        let direct = Arc::new(RecordingTransport::default());
        let aborted = Arc::new(AtomicBool::new(false));
        let (_app, flow_side) = tokio::io::duplex(1024);
        let flag = aborted.clone();
        let flow = TcpFlow {
            original_dst: "203.0.113.7:443".parse().unwrap(),
            src: "10.0.0.2:12345".parse().unwrap(),
            stream: Box::new(flow_side),
            abort: Some(Box::new(move || {
                flag.store(true, Ordering::SeqCst);
            })),
        };
        // Await `forward` directly (not `run`, which spawns it on a task) so the assertion
        // deterministically runs after the Reject arm completed.
        forward(
            flow,
            proxy.clone() as Arc<dyn Transport>,
            direct.clone() as Arc<dyn Transport>,
            Some(hooks_for(Decision::Reject)),
            Arc::new(Metrics::default()),
        )
        .await;

        assert!(
            aborted.load(Ordering::SeqCst),
            "Reject must fire the abort hook so the client gets an RST"
        );
    }

    /// `Decision::Proxy` (and, separately, no router) → the flow is dialed via the PROXY transport.
    #[tokio::test]
    async fn proxies_when_router_says_proxy_or_none() {
        // Explicit Proxy decision: dialed via the proxy transport (an echo), not the direct one.
        let echo = spawn_echo().await;
        let direct = Arc::new(RecordingTransport::default());
        let (mut app, netstack) = one_flow(echo);
        tokio::spawn(run(
            netstack,
            Arc::new(DirectTransport::default()),
            direct.clone() as Arc<dyn Transport>,
            Some(hooks_for(Decision::Proxy)),
            Arc::new(Metrics::default()),
        ));
        app.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        app.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");
        assert!(
            !direct.dialed.load(Ordering::SeqCst),
            "the direct transport must not be dialed for a Proxy decision"
        );

        // No router: same — the proxy transport carries the flow.
        let echo = spawn_echo().await;
        let direct = Arc::new(RecordingTransport::default());
        let (mut app, netstack) = one_flow(echo);
        tokio::spawn(run(
            netstack,
            Arc::new(DirectTransport::default()),
            direct.clone() as Arc<dyn Transport>,
            None,
            Arc::new(Metrics::default()),
        ));
        app.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        app.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");
        assert!(
            !direct.dialed.load(Ordering::SeqCst),
            "the direct transport must not be dialed with no router"
        );
    }

    // ---- Domain recovery + per-action resolution (M4.6) ----

    /// A fake destination IP, port matched to `echo` so a resolved dial reaches it.
    fn fake_dst_for(echo: SocketAddr) -> SocketAddr {
        SocketAddr::new("198.18.0.9".parse().unwrap(), echo.port())
    }

    /// A domain-capable transport (like the tunnel / shadowsocks / hysteria2): its `dial_addr` carries
    /// a domain to `echo` and records that dial-by-name was used; its plain `dial` errors so a test
    /// can prove the domain path was taken.
    struct DomainDialTransport {
        echo: SocketAddr,
        dialed_by_name: Arc<AtomicBool>,
    }

    #[async_trait]
    impl Transport for DomainDialTransport {
        async fn dial(&self, _target: SocketAddr) -> std::io::Result<crate::BoxedStream> {
            Err(std::io::Error::other("this stub only dials by name"))
        }
        async fn dial_addr(
            &self,
            target: crate::transport::Address,
        ) -> std::io::Result<crate::BoxedStream> {
            if matches!(target, crate::transport::Address::Domain { .. }) {
                self.dialed_by_name.store(true, Ordering::SeqCst);
            }
            Ok(Box::new(tokio::net::TcpStream::connect(self.echo).await?))
        }
    }

    /// A recovered domain over a domain-capable proxy transport is dialed **by name** (exit resolves);
    /// the client-side resolver is left untouched.
    #[tokio::test]
    async fn proxy_domain_flow_prefers_dial_by_name() {
        let echo = spawn_echo().await;
        let dialed_by_name = Arc::new(AtomicBool::new(false));
        let resolved = Arc::new(AtomicBool::new(false));
        let proxy = Arc::new(DomainDialTransport {
            echo,
            dialed_by_name: Arc::clone(&dialed_by_name),
        });
        let hooks = Arc::new(RouteHooks {
            proxyless_transport: None,
            proxyless_udp: None,
            router: Arc::new(StubRouter(Decision::Proxy)),
            recoverer: Some(Arc::new(StubRecoverer("cdn.example.com"))),
            direct_resolver: None,
            // Present, but must NOT be consulted when dial-by-name succeeds.
        });
        let (mut app, netstack) = one_flow(fake_dst_for(echo));
        tokio::spawn(run(
            netstack,
            proxy as Arc<dyn Transport>,
            Arc::new(DirectTransport::default()),
            Some(hooks),
            Arc::new(Metrics::default()),
        ));
        app.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        app.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");
        assert!(
            dialed_by_name.load(Ordering::SeqCst),
            "the domain was carried to the exit"
        );
        assert!(
            !resolved.load(Ordering::SeqCst),
            "client-side resolution must be skipped when dial-by-name works"
        );
    }

    /// Direct + a recovered domain: the fake IP is resolved (local resolver) to the real IP and
    /// direct-dialed — never the fake IP.
    #[tokio::test]
    async fn direct_domain_flow_resolves_then_dials_real_ip() {
        let echo = spawn_echo().await;
        let resolved = Arc::new(AtomicBool::new(false));
        let proxy = Arc::new(RecordingTransport::default());
        let hooks = Arc::new(RouteHooks {
            proxyless_transport: None,
            proxyless_udp: None,
            router: Arc::new(StubRouter(Decision::Direct)),
            recoverer: Some(Arc::new(StubRecoverer("cdn.example.com"))),
            direct_resolver: Some(Arc::new(StubResolver {
                ip: echo.ip(),
                resolved: Arc::clone(&resolved),
            })),
        });
        let (mut app, netstack) = one_flow(fake_dst_for(echo));
        tokio::spawn(run(
            netstack,
            proxy.clone() as Arc<dyn Transport>,
            Arc::new(DirectTransport::default()),
            Some(hooks),
            Arc::new(Metrics::default()),
        ));
        app.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        app.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");
        assert!(
            resolved.load(Ordering::SeqCst),
            "the direct resolver is consulted"
        );
        assert!(
            !proxy.dialed.load(Ordering::SeqCst),
            "the proxy transport must not be dialed for a resolved Direct flow"
        );
    }

    /// A transport that cannot carry a name must make the flow **fail**, never fall back to a
    /// client-side lookup.
    ///
    /// `DirectTransport` with no resolver is the one thing that still reports `Unsupported` for a
    /// domain, which makes it the only way to reach the branch the old fallback lived on. The
    /// resolver flag is watched deliberately: if the fallback ever comes back, this test sees a
    /// lookup happen and fails, rather than the leak returning silently because nothing looks.
    #[tokio::test]
    async fn a_transport_that_cannot_carry_a_name_fails_rather_than_resolving() {
        let echo = spawn_echo().await;
        let resolved = Arc::new(AtomicBool::new(false));
        let hooks = Arc::new(RouteHooks {
            proxyless_transport: None,
            proxyless_udp: None,
            router: Arc::new(StubRouter(Decision::Proxy)),
            recoverer: Some(Arc::new(StubRecoverer("cdn.example.com"))),
            direct_resolver: None,
        });
        let (mut app, netstack) = one_flow(fake_dst_for(echo));
        tokio::spawn(run(
            netstack,
            // No resolver → `dial_addr` reports `Unsupported` for the domain.
            Arc::new(DirectTransport::default()),
            Arc::new(RecordingTransport::default()) as Arc<dyn Transport>,
            Some(hooks),
            Arc::new(Metrics::default()),
        ));
        // The flow must not carry data: it is dropped, not silently rerouted through a local lookup.
        let mut buf = [0u8; 4];
        let _ = app.write_all(b"ping").await;
        assert_eq!(
            app.read(&mut buf).await.unwrap_or(0),
            0,
            "a name the transport cannot carry must drop the flow"
        );
        assert!(
            !resolved.load(Ordering::SeqCst),
            "the destination must never reach a client-side resolver for a proxied flow"
        );
    }

    /// Proxy + a recovered domain: the **exit** resolves. The name rides `dial_addr` to the
    /// transport, and no client-side lookup happens.
    #[tokio::test]
    async fn a_proxied_domain_flow_hands_the_name_to_the_exit() {
        let echo = spawn_echo().await;
        // Wired but must stay untouched: a proxied flow resolving here would put the destination
        // into a local DNS lookup, which is the disclosure proxying exists to prevent. This test
        // previously asserted the opposite — that the resolver *is* consulted — because the
        // forwarder fell back to client-side resolution whenever a transport reported it could not
        // carry a name. `Transport::dial_addr` is now required, so that fallback is gone.
        let resolved = Arc::new(AtomicBool::new(false));
        let by_name = Arc::new(AtomicBool::new(false));
        let proxy = Arc::new(DomainDialTransport {
            echo,
            dialed_by_name: Arc::clone(&by_name),
        });
        let hooks = Arc::new(RouteHooks {
            proxyless_transport: None,
            proxyless_udp: None,
            router: Arc::new(StubRouter(Decision::Proxy)),
            recoverer: Some(Arc::new(StubRecoverer("cdn.example.com"))),
            direct_resolver: None,
        });
        let (mut app, netstack) = one_flow(fake_dst_for(echo));
        tokio::spawn(run(
            netstack,
            // `run` takes (proxy, direct) in that order — the proxy is the one under test here.
            proxy as Arc<dyn Transport>,
            Arc::new(DirectTransport::default()),
            Some(hooks),
            Arc::new(Metrics::default()),
        ));
        app.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        app.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");
        assert!(
            by_name.load(Ordering::SeqCst),
            "the exit must receive the domain, not a client-resolved IP"
        );
        assert!(
            !resolved.load(Ordering::SeqCst),
            "no client-side lookup may happen for a proxied flow"
        );
    }

    /// Direct + a recovered domain but no local resolver: never dial the fake IP directly — fall back
    /// to Proxy (here the proxy resolver resolves it), leaving the direct transport untouched.
    #[tokio::test]
    async fn direct_domain_without_local_resolver_falls_back_to_proxy() {
        let echo = spawn_echo().await;
        let resolved = Arc::new(AtomicBool::new(false));
        let direct = Arc::new(RecordingTransport::default());
        let hooks = Arc::new(RouteHooks {
            proxyless_transport: None,
            proxyless_udp: None,
            router: Arc::new(StubRouter(Decision::Direct)),
            recoverer: Some(Arc::new(StubRecoverer("cdn.example.com"))),
            direct_resolver: None,
        });
        let (mut app, netstack) = one_flow(fake_dst_for(echo));
        // proxy transport dials the resolved IP; the (recording) direct transport must stay unused.
        tokio::spawn(run(
            netstack,
            // The "proxy" slot here is a direct transport, and it now resolves for itself: a
            // direct dial has no exit to delegate to, so a local lookup is correct rather than a
            // leak. Before `dial_addr` was required, this test reached the same place via the
            // forwarder's client-side fallback, which no longer exists.
            Arc::new(
                DirectTransport::default().with_resolver(Some(Arc::new(StubResolver {
                    ip: echo.ip(),
                    resolved: Arc::clone(&resolved),
                }))),
            ),
            direct.clone() as Arc<dyn Transport>,
            Some(hooks),
            Arc::new(Metrics::default()),
        ));
        app.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        app.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");
        assert!(
            resolved.load(Ordering::SeqCst),
            "Direct with no local resolver falls back to the proxy resolver"
        );
        assert!(
            !direct.dialed.load(Ordering::SeqCst),
            "the direct transport must not dial the fake IP when it falls back to proxy"
        );
    }

    /// Direct + a recovered domain, resolver succeeds, but the direct **dial** fails → fall back to
    /// Proxy rather than drop the flow (direct egress temporarily unavailable).
    #[tokio::test]
    async fn direct_dial_failure_falls_back_to_proxy() {
        let echo = spawn_echo().await;
        let direct = Arc::new(RecordingTransport::default()); // its dial always errors
        let resolved = Arc::new(AtomicBool::new(false));
        let hooks = Arc::new(RouteHooks {
            proxyless_transport: None,
            proxyless_udp: None,
            router: Arc::new(StubRouter(Decision::Direct)),
            recoverer: Some(Arc::new(StubRecoverer("cdn.example.com"))),
            direct_resolver: Some(Arc::new(StubResolver {
                ip: echo.ip(),
                resolved: Arc::new(AtomicBool::new(false)),
            })),
        });
        let (mut app, netstack) = one_flow(fake_dst_for(echo));
        // proxy transport reaches the echo; the direct transport is the failing recorder.
        tokio::spawn(run(
            netstack,
            // The "proxy" slot here is a direct transport, and it now resolves for itself: a
            // direct dial has no exit to delegate to, so a local lookup is correct rather than a
            // leak. Before `dial_addr` was required, this test reached the same place via the
            // forwarder's client-side fallback, which no longer exists.
            Arc::new(
                DirectTransport::default().with_resolver(Some(Arc::new(StubResolver {
                    ip: echo.ip(),
                    resolved: Arc::clone(&resolved),
                }))),
            ),
            direct.clone() as Arc<dyn Transport>,
            Some(hooks),
            Arc::new(Metrics::default()),
        ));
        app.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        app.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping", "flow succeeded via the proxy fallback");
        assert!(
            direct.dialed.load(Ordering::SeqCst),
            "direct was attempted first (then fell back on failure)"
        );
        assert!(
            resolved.load(Ordering::SeqCst),
            "the proxy resolver was used for the fallback"
        );
    }

    /// A domain-capable transport whose `dial_addr` fails with a **non-`Unsupported`** error (a
    /// transient dial failure), to check the fail-fast path.
    struct FailingDomainTransport;

    #[async_trait]
    impl Transport for FailingDomainTransport {
        async fn dial(&self, _t: SocketAddr) -> std::io::Result<crate::BoxedStream> {
            Err(std::io::Error::other("dial failed"))
        }
        async fn dial_addr(
            &self,
            _t: crate::transport::Address,
        ) -> std::io::Result<crate::BoxedStream> {
            Err(std::io::Error::other("transient dial failure")) // NOT ErrorKind::Unsupported
        }
    }

    /// A transient proxy dial-by-name failure (not `Unsupported`) fails fast — the flow is dropped
    /// without a client-side DNS lookup (no privacy/perf regression, no re-dial of the failing proxy).
    #[tokio::test]
    async fn proxy_domain_dial_failure_fails_fast_without_client_resolution() {
        let resolved = Arc::new(AtomicBool::new(false));
        let hooks = Arc::new(RouteHooks {
            proxyless_transport: None,
            proxyless_udp: None,
            router: Arc::new(StubRouter(Decision::Proxy)),
            recoverer: Some(Arc::new(StubRecoverer("cdn.example.com"))),
            direct_resolver: None,
        });
        let (mut app, netstack) = one_flow("198.18.0.9:443".parse().unwrap());
        tokio::spawn(run(
            netstack,
            Arc::new(FailingDomainTransport) as Arc<dyn Transport>,
            Arc::new(RecordingTransport::default()) as Arc<dyn Transport>,
            Some(hooks),
            Arc::new(Metrics::default()),
        ));
        let mut buf = [0u8; 4];
        let n = app.read(&mut buf).await.unwrap();
        assert_eq!(
            n, 0,
            "a transient dial-by-name failure drops the flow (fail fast)"
        );
        assert!(
            !resolved.load(Ordering::SeqCst),
            "no client-side DNS lookup on a non-Unsupported dial failure"
        );
    }

    /// End-to-end (sans TUN): compose the **real** fake-IP DNS server + a **real** `.srs`-built
    /// Router + the forwarder, and drive a flow the way the tunnel does — DNS query → fake IP →
    /// connect to it → connect-time domain recovery → routing decision from the real rule-sets → dial
    /// action. The per-layer tests each cover a piece; this proves they compose (in particular, that
    /// the DNS-assigned fake IP recovers to the same domain the Router matches against the real lists).
    #[cfg(feature = "smart-routing")]
    #[tokio::test]
    async fn e2e_fake_ip_dns_plus_real_rules_route_correctly() {
        use crate::dns::server::{shared_pool, DnsServer, FakeIpRecoverer, SharedFakeIp};
        use crate::rules::matcher::Matcher;
        use crate::rules::router::Router;
        use crate::rules::{srs, Action};
        use std::time::Duration;

        // Build an A-record query for `name`.
        fn a_query(name: &str) -> Vec<u8> {
            let mut b = vec![0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
            for label in name.split('.') {
                b.push(label.len() as u8);
                b.extend_from_slice(label.as_bytes());
            }
            b.push(0);
            b.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
            b.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
            b
        }
        // Decode the single A answer IP from a `build_response` reply (answer name is a pointer).
        fn answer_ip(resp: &[u8]) -> IpAddr {
            let mut i = 12;
            while resp[i] != 0 {
                i += 1 + resp[i] as usize; // walk the question name
            }
            i += 1 + 4; // root label + qtype + qclass
            i += 2 + 2 + 2 + 4 + 2; // answer: name ptr + type + class + ttl + rdlength
            IpAddr::from(<[u8; 4]>::try_from(&resp[i..i + 4]).unwrap())
        }
        fn fixture(name: &str) -> srs::RuleSet {
            srs::parse(&std::fs::read(format!("tests/fixtures/srs/{name}.srs")).unwrap()).unwrap()
        }
        // A resolver that maps any domain to `ip` (stands in for the real DoH — the network part isn't
        // what this test exercises).
        fn to(ip: IpAddr) -> Arc<dyn FlowResolver> {
            Arc::new(StubResolver {
                ip,
                resolved: Arc::new(AtomicBool::new(false)),
            })
        }

        // Real router from real rule-sets: ad/malware lists → Reject, the common list → Direct.
        let router: Arc<dyn FlowRouter> = Arc::new(Router::new(Matcher::build(vec![
            (Action::Reject, fixture("banad_v1")),
            (Action::Reject, fixture("category-ads_v2")),
            (Action::Reject, fixture("geoip-malware")),
            (Action::Direct, fixture("common_v3")),
        ])));
        let echo = spawn_echo().await;
        let pool = shared_pool(Duration::from_secs(300), 1000);
        let dns = DnsServer::new(Arc::clone(&pool), 30);

        // Resolve `domain` to its fake IP through the real DNS server, then run one flow to it through
        // the forwarder with the given transports. Returns the app end of the flow.
        async fn drive(
            domain: &str,
            proxy_t: Arc<dyn Transport>,
            direct_t: Arc<dyn Transport>,
            echo: SocketAddr,
            pool: SharedFakeIp,
            dns: &DnsServer,
            router: Arc<dyn FlowRouter>,
        ) -> tokio::io::DuplexStream {
            let fake = answer_ip(&dns.handle(&a_query(domain)).expect("dns response"));
            let hooks = Arc::new(RouteHooks {
                proxyless_transport: None,
                proxyless_udp: None,
                router,
                recoverer: Some(Arc::new(FakeIpRecoverer::new(pool))),
                direct_resolver: Some(to(echo.ip())),
            });
            // Flow to the fake IP on the echo's port, so a resolved (echo.ip, port) dial reaches it.
            let (app, netstack) = one_flow(SocketAddr::new(fake, echo.port()));
            tokio::spawn(run(
                netstack,
                proxy_t,
                direct_t,
                Some(hooks),
                Arc::new(Metrics::default()),
            ));
            app
        }

        // 1. Ad domain (banad_v1) → Reject: flow dropped, neither transport dialed.
        let proxy = Arc::new(RecordingTransport::default());
        let direct = Arc::new(RecordingTransport::default());
        let mut app = drive(
            "doubleclick.net",
            proxy.clone() as Arc<dyn Transport>,
            direct.clone() as Arc<dyn Transport>,
            echo,
            Arc::clone(&pool),
            &dns,
            Arc::clone(&router),
        )
        .await;
        let mut buf = [0u8; 4];
        assert_eq!(
            app.read(&mut buf).await.unwrap(),
            0,
            "ad domain is rejected (EOF)"
        );
        assert!(!proxy.dialed.load(Ordering::SeqCst) && !direct.dialed.load(Ordering::SeqCst));

        // 2. smart_routing common domain (common_v3) → Direct: dialed via the DIRECT transport.
        let proxy = Arc::new(RecordingTransport::default());
        let mut app = drive(
            "app.discord.com",
            proxy.clone() as Arc<dyn Transport>,
            Arc::new(DirectTransport::default()),
            echo,
            Arc::clone(&pool),
            &dns,
            Arc::clone(&router),
        )
        .await;
        app.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        app.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping", "direct domain reaches its upstream");
        assert!(
            !proxy.dialed.load(Ordering::SeqCst),
            "not via the proxy transport"
        );

        // 3. Unlisted domain → Proxy: dialed via the PROXY transport, not direct.
        let direct = Arc::new(RecordingTransport::default());
        let mut app = drive(
            "example-unlisted-xyz.test",
            // The proxy slot is a direct transport, so it needs its own resolver now: with
            // `dial_addr` required there is no forwarder-side fallback to resolve on its behalf.
            Arc::new(DirectTransport::default().with_resolver(Some(to(echo.ip())))),
            direct.clone() as Arc<dyn Transport>,
            echo,
            Arc::clone(&pool),
            &dns,
            Arc::clone(&router),
        )
        .await;
        app.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        app.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping", "unlisted domain is proxied to its upstream");
        assert!(
            !direct.dialed.load(Ordering::SeqCst),
            "not via the direct transport"
        );
    }

    /// Minimal in-test tunnel relay: read the address header, dial the named target,
    /// forward bytes read past the header, then splice. (Mirrors the M3b integration
    /// relay; kept here so the proxy crate's tests are self-contained.)
    async fn spawn_relay() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut client, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (target, leftover) = read_header(&mut client).await.unwrap();
                    let Address::Ip(dst) = target else {
                        panic!("test relay only dials IP targets");
                    };
                    let mut upstream = TcpStream::connect(dst).await.unwrap();
                    if !leftover.is_empty() {
                        upstream.write_all(&leftover).await.unwrap();
                    }
                    let _ = copy_bidirectional(&mut client, &mut upstream).await;
                });
            }
        });
        addr
    }
}
