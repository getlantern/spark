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

use std::sync::Arc;

use tokio::io::copy_bidirectional;
use tracing::{debug, info, warn};

use crate::metrics::{Counting, Metrics, SessionGuard};
use crate::netstack::{Netstack, TcpFlow};
use crate::proxy::{Decision, FlowRouter};
use crate::transport::Transport;

/// Run the accept→forward loop until the netstack stops yielding flows. For each flow, `router`
/// (when present) decides whether it is proxied, dialed direct, or rejected; a proxied flow dials
/// through `proxy_transport`, a direct flow through `direct_transport`. With no `router` every flow
/// is proxied — today's behavior. `metrics` tallies per-flow byte/session counts.
///
/// Each accepted flow is forwarded on its own task so that a slow (or hung) upstream
/// dial cannot stall acceptance of other flows.
pub async fn run<N: Netstack>(
    mut netstack: N,
    proxy_transport: Arc<dyn Transport>,
    direct_transport: Arc<dyn Transport>,
    router: Option<Arc<dyn FlowRouter>>,
    metrics: Arc<Metrics>,
) {
    while let Some(flow) = netstack.accept_tcp().await {
        // At L3 the domain is not yet known (it is recovered by the fake-IP DNS layer in M4).
        let decision = router
            .as_deref()
            .map(|r| r.decide(flow.original_dst.ip(), None))
            .unwrap_or(Decision::Proxy);
        match decision {
            Decision::Proxy => {
                tokio::spawn(forward(
                    flow,
                    Arc::clone(&proxy_transport),
                    Arc::clone(&metrics),
                ));
            }
            Decision::Direct => {
                tokio::spawn(forward(
                    flow,
                    Arc::clone(&direct_transport),
                    Arc::clone(&metrics),
                ));
            }
            Decision::Reject => {
                // Not forwarded: dropping `flow` closes its stream. Destination is logged at
                // debug only (log-hygiene note above).
                debug!(dst = %flow.original_dst, "tcp flow rejected by routing rule");
            }
        }
    }
    debug!("netstack accept loop ended");
}

/// Dial `flow.original_dst` through `transport` and copy bytes in both directions until
/// either side closes, tallying the flow into `metrics`.
async fn forward(flow: TcpFlow, transport: Arc<dyn Transport>, metrics: Arc<Metrics>) {
    let TcpFlow {
        original_dst,
        src,
        mut stream,
    } = flow;

    // Count this flow as active for its whole lifetime — including if this task is aborted on stop
    // (the guard decrements on drop).
    let _session = SessionGuard::open(Arc::clone(&metrics));

    debug!(src = %src, dst = %original_dst, "tcp flow: dialing upstream");

    let upstream = match transport.dial(original_dst).await {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "dial to upstream failed");
            return;
        }
    };
    // Wrap the upstream half so writes (app→upstream) count as `up` and reads (upstream→app) as
    // `down`. `&mut *stream` derefs the box to the `dyn` stream `copy_bidirectional` accepts.
    let mut upstream = Counting::new(upstream, metrics);
    match copy_bidirectional(&mut *stream, &mut upstream).await {
        Ok((to_upstream, to_app)) => {
            info!(to_upstream, to_app, "tcp flow completed");
        }
        Err(e) => warn!(error = %e, "tcp flow error"),
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

    use crate::proxy::{Decision, FlowRouter};

    /// A `FlowRouter` that returns a fixed decision for every flow.
    struct StubRouter(Decision);

    impl FlowRouter for StubRouter {
        fn decide(&self, _ip: IpAddr, _domain: Option<&str>) -> Decision {
            self.0
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
            Some(Arc::new(StubRouter(Decision::Direct))),
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
            Some(Arc::new(StubRouter(Decision::Reject))),
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
            Some(Arc::new(StubRouter(Decision::Proxy))),
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
