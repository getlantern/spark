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
    } = flow;

    // Count this flow as active for its whole lifetime — including if this task is aborted on stop
    // (the guard decrements on drop).
    let _session = SessionGuard::open(Arc::clone(&metrics));

    let hooks = hooks.as_deref();
    // Recover the domain behind the (possibly fake) destination IP, then decide the action on it.
    let domain = hooks
        .and_then(|h| h.recoverer.as_deref())
        .and_then(|r| r.recover(original_dst.ip()));
    let decision = hooks
        .map(|h| h.router.decide(original_dst.ip(), domain.as_deref()))
        .unwrap_or(Decision::Proxy);
    debug!(src = %src, dst = %original_dst, domain = domain.as_deref().unwrap_or("-"), ?decision, "tcp flow: routing");

    let upstream = match decision {
        // Dropping `stream` (by returning) closes the flow. Destination at debug only (log hygiene).
        Decision::Reject => {
            debug!(dst = %original_dst, "tcp flow rejected by routing rule");
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
        Decision::Proxy => {
            dial_proxy(&proxy_transport, hooks, domain.as_deref(), original_dst).await
        }
    };
    let Some(upstream) = upstream else {
        return; // dial failed (already logged)
    };
    // Wrap the upstream half so writes (app→upstream) count as `up` and reads (upstream→app) as
    // `down`. `&mut *stream` derefs the box to the `dyn` stream `copy_bidirectional` accepts.
    let mut upstream = Counting::new(upstream, metrics);
    match copy_bidirectional(&mut *stream, &mut upstream).await {
        Ok((to_upstream, to_app)) => info!(to_upstream, to_app, "tcp flow completed"),
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
    dial_proxy(proxy, hooks, domain, original_dst).await
}

/// Dial a Proxy flow. For a **domain** flow behind a fake IP we prefer **dial-by-name**: carry the
/// domain to the exit so it resolves (no client DNS leak, exit-optimal CDN IPs) — the tunnel,
/// shadowsocks, and hysteria2 all carry a domain target. Only if the transport can't (its `dial_addr`
/// errors) do we fall back to **client-side** resolution (resilient un-poisoned DoH) + dial-by-IP,
/// which works for every transport. A **real-IP** flow is proxied by IP (today's behavior).
async fn dial_proxy(
    proxy: &Arc<dyn Transport>,
    hooks: Option<&RouteHooks>,
    domain: Option<&str>,
    original_dst: SocketAddr,
) -> Option<BoxedStream> {
    let Some(dom) = domain else {
        return dial_or_log(proxy, original_dst).await; // real-IP flow → proxy by IP
    };
    // Preferred: hand the domain to the exit. `dial_addr` errors for a transport that can't carry a
    // name (then we fall through to client-side resolution below).
    if let Ok(addr) = Address::domain(dom, original_dst.port()) {
        match proxy.dial_addr(addr).await {
            Ok(s) => return Some(s),
            Err(e) => {
                debug!(domain = %dom, error = %e, "proxy dial-by-name unavailable; resolving client-side")
            }
        }
    }
    // Fallback: resolve the domain ourselves (un-poisoned DoH, bypassing the TUN) and dial the real IP.
    if let Some(res) = hooks.and_then(|h| h.proxy_resolver.as_deref()) {
        if let Ok(ips) = res.resolve(dom).await {
            if let Some(ip) = pick_ip(&ips, original_dst.ip()) {
                return dial_or_log(proxy, SocketAddr::new(ip, original_dst.port())).await;
            }
        }
    }
    warn!(domain = %dom, "proxy: neither dial-by-name nor client-side resolution succeeded");
    None
}

/// Pick a resolved IP whose family matches `want` (the flow's fake destination family — i.e. what the
/// app asked for via DNS: A→v4, AAAA→v6), falling back to the first result. Avoids, e.g., dialing a v6
/// address first for a v4 flow when the resolver returns both. (Full cross-family happy-eyeballs is a
/// future improvement.)
fn pick_ip(ips: &[IpAddr], want: IpAddr) -> Option<IpAddr> {
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
        fn decide(&self, _ip: IpAddr, _domain: Option<&str>) -> Decision {
            self.0
        }
    }

    /// Hooks with a fixed-decision router and no recoverer/resolvers (the IP-only routing tests).
    fn hooks_for(decision: Decision) -> Arc<RouteHooks> {
        Arc::new(RouteHooks {
            router: Arc::new(StubRouter(decision)),
            recoverer: None,
            direct_resolver: None,
            proxy_resolver: None,
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
    }

    /// Build a one-flow netstack whose app side we keep, plus the flow to feed `run`.
    fn one_flow(original_dst: SocketAddr) -> (tokio::io::DuplexStream, OneFlow) {
        let (app, flow_side) = tokio::io::duplex(1024);
        let flow = TcpFlow {
            original_dst,
            src: "10.0.0.2:12345".parse().unwrap(),
            stream: Box::new(flow_side),
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
            router: Arc::new(StubRouter(Decision::Proxy)),
            recoverer: Some(Arc::new(StubRecoverer("cdn.example.com"))),
            direct_resolver: None,
            // Present, but must NOT be consulted when dial-by-name succeeds.
            proxy_resolver: Some(Arc::new(StubResolver {
                ip: echo.ip(),
                resolved: Arc::clone(&resolved),
            })),
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
            router: Arc::new(StubRouter(Decision::Direct)),
            recoverer: Some(Arc::new(StubRecoverer("cdn.example.com"))),
            direct_resolver: Some(Arc::new(StubResolver {
                ip: echo.ip(),
                resolved: Arc::clone(&resolved),
            })),
            proxy_resolver: None,
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

    /// Proxy + a recovered domain: with a proxy resolver present, the domain is resolved client-side
    /// and the real IP is dialed through the proxy transport (works for every transport).
    #[tokio::test]
    async fn proxy_domain_flow_resolves_client_side_then_dials() {
        let echo = spawn_echo().await;
        let resolved = Arc::new(AtomicBool::new(false));
        let direct = Arc::new(RecordingTransport::default());
        let hooks = Arc::new(RouteHooks {
            router: Arc::new(StubRouter(Decision::Proxy)),
            recoverer: Some(Arc::new(StubRecoverer("cdn.example.com"))),
            direct_resolver: None,
            proxy_resolver: Some(Arc::new(StubResolver {
                ip: echo.ip(),
                resolved: Arc::clone(&resolved),
            })),
        });
        let (mut app, netstack) = one_flow(fake_dst_for(echo));
        tokio::spawn(run(
            netstack,
            Arc::new(DirectTransport::default()),
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
            "the proxy resolver is consulted"
        );
        assert!(
            !direct.dialed.load(Ordering::SeqCst),
            "the direct transport must not be dialed for a Proxy flow"
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
            router: Arc::new(StubRouter(Decision::Direct)),
            recoverer: Some(Arc::new(StubRecoverer("cdn.example.com"))),
            direct_resolver: None,
            proxy_resolver: Some(Arc::new(StubResolver {
                ip: echo.ip(),
                resolved: Arc::clone(&resolved),
            })),
        });
        let (mut app, netstack) = one_flow(fake_dst_for(echo));
        // proxy transport dials the resolved IP; the (recording) direct transport must stay unused.
        tokio::spawn(run(
            netstack,
            Arc::new(DirectTransport::default()),
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
            router: Arc::new(StubRouter(Decision::Direct)),
            recoverer: Some(Arc::new(StubRecoverer("cdn.example.com"))),
            direct_resolver: Some(Arc::new(StubResolver {
                ip: echo.ip(),
                resolved: Arc::new(AtomicBool::new(false)),
            })),
            proxy_resolver: Some(Arc::new(StubResolver {
                ip: echo.ip(),
                resolved: Arc::clone(&resolved),
            })),
        });
        let (mut app, netstack) = one_flow(fake_dst_for(echo));
        // proxy transport reaches the echo; the direct transport is the failing recorder.
        tokio::spawn(run(
            netstack,
            Arc::new(DirectTransport::default()),
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
