//! Plain TCP forwarder (M2).
//!
//! For each flow the netstack surfaces, dial the original destination **directly** and
//! splice the two streams together with [`copy_bidirectional`]. There is no tunnel
//! transport yet: this proves the full TUN → netstack → upstream → back pipeline in
//! isolation. At M4 the direct `TcpStream::connect(original_dst)` below is swapped for
//! `transport.dial(original_dst)`; the rest of this loop is unchanged.
//!
//! Log hygiene (a product privacy property — see `docs/GOAL.md`): destination addresses
//! are logged at `debug` only. The default (`info`) level reports byte counts on close,
//! which carry no destination.

use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::netstack::{Netstack, TcpFlow};

/// Run the accept→forward loop until the netstack stops yielding flows.
///
/// Each accepted flow is forwarded on its own task so that a slow (or hung) upstream
/// dial cannot stall acceptance of other flows.
pub async fn run<N: Netstack>(mut netstack: N) {
    while let Some(flow) = netstack.accept_tcp().await {
        tokio::spawn(forward(flow));
    }
    debug!("netstack accept loop ended");
}

/// Dial `flow.original_dst` directly and copy bytes in both directions until either
/// side closes.
async fn forward(flow: TcpFlow) {
    let TcpFlow {
        original_dst,
        src,
        mut stream,
    } = flow;

    debug!(src = %src, dst = %original_dst, "tcp flow: dialing upstream directly");

    let mut upstream = match TcpStream::connect(original_dst).await {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "direct dial to upstream failed");
            return;
        }
    };

    // `&mut *stream` derefs the box to `&mut (dyn AsyncReadWrite + Unpin + Send)`, which
    // satisfies `copy_bidirectional`'s `AsyncRead + AsyncWrite + Unpin + ?Sized` bound.
    match copy_bidirectional(&mut *stream, &mut upstream).await {
        Ok((to_upstream, to_app)) => {
            info!(to_upstream, to_app, "tcp flow completed");
        }
        Err(e) => warn!(error = %e, "tcp flow error"),
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    /// A `Netstack` that surfaces a single pre-built flow, then signals shutdown. Lets us
    /// exercise the forwarder's data path with no TUN and no userspace stack.
    struct OneFlow(Option<TcpFlow>);

    #[async_trait]
    impl Netstack for OneFlow {
        async fn accept_tcp(&mut self) -> Option<TcpFlow> {
            self.0.take()
        }
    }

    /// The flow's bytes reach the original destination and the destination's reply makes
    /// it back to the application — proving the dial + bidirectional copy through the
    /// boxed trait-object stream. The in-memory duplex stands in for the netstack
    /// `TcpStream`; a real loopback socket is the upstream.
    #[tokio::test]
    async fn forwards_bytes_to_original_dst_and_back() {
        // Upstream echo server on an ephemeral loopback port.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let original_dst = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 64];
            loop {
                match sock.read(&mut buf).await.unwrap() {
                    0 => break,
                    n => sock.write_all(&buf[..n]).await.unwrap(),
                }
            }
        });

        // `app` is the application end; `flow_side` is what the netstack would have handed us.
        let (mut app, flow_side) = tokio::io::duplex(1024);
        let flow = TcpFlow {
            original_dst,
            src: "10.0.0.2:12345".parse().unwrap(),
            stream: Box::new(flow_side),
        };

        tokio::spawn(run(OneFlow(Some(flow))));

        app.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        app.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");
    }
}
