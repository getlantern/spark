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
use crate::transport::Transport;

/// Run the accept→forward loop until the netstack stops yielding flows, dialing each
/// flow's upstream through `transport`. `metrics` tallies per-flow byte/session counts.
///
/// Each accepted flow is forwarded on its own task so that a slow (or hung) upstream
/// dial cannot stall acceptance of other flows.
pub async fn run<N: Netstack>(
    mut netstack: N,
    transport: Arc<dyn Transport>,
    metrics: Arc<Metrics>,
) {
    while let Some(flow) = netstack.accept_tcp().await {
        tokio::spawn(forward(flow, Arc::clone(&transport), Arc::clone(&metrics)));
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

    /// Run a flow whose upstream is reached via `transport` and assert a payload echoes
    /// back to the application end of the flow.
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
