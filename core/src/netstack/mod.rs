//! The netstack surface the proxy core depends on, plus the `netstack-smoltcp` impl.
//!
//! A TUN device hands us raw L3 IP packets; the proxy core wants L4 streams. The
//! netstack is what bridges the two: it runs a userspace TCP/IP stack (smoltcp, here)
//! that terminates the application's TCP connections and surfaces each as an accepted
//! byte stream tagged with the address the application originally dialed.
//!
//! The core depends only on the [`Netstack`] trait and [`TcpFlow`], never on
//! `netstack-smoltcp` directly, so the implementation can later be swapped for
//! `ipstack`, a hand-rolled smoltcp bridge, or a newer netstack without touching the
//! proxy. [`SmoltcpNetstack`] is the one M2 implementation.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use netstack_smoltcp::{StackBuilder, TcpListener};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::tun::Tun;

/// Marker for a bidirectional async byte stream. Blanket-implemented for every
/// `AsyncRead + AsyncWrite`, so a surfaced flow can carry either a netstack `TcpStream`
/// (M2, direct dial) or a tunnel-transport stream (M4) behind a single boxed type.
pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> AsyncReadWrite for T {}

/// A surfaced L4 TCP flow, independent of the netstack implementation.
pub struct TcpFlow {
    /// The address the application originally dialed — i.e. the upstream to connect to.
    pub original_dst: SocketAddr,
    /// The application's source address inside the tunnel. Not needed to forward a plain
    /// TCP flow, but kept for debug logging now and UDP NAT keying later.
    pub src: SocketAddr,
    /// The flow's byte stream: reading yields app→upstream bytes, writing delivers
    /// upstream→app bytes.
    pub stream: Box<dyn AsyncReadWrite + Unpin + Send>,
}

/// The netstack surface our proxy depends on. `netstack-smoltcp` is one impl.
#[async_trait]
pub trait Netstack: Send {
    /// Yield the next accepted TCP flow, or `None` once the netstack has shut down.
    async fn accept_tcp(&mut self) -> Option<TcpFlow>;
    // UDP surface added when the UDP path is built (M5).
}

/// A [`Netstack`] backed by the vendored `netstack-smoltcp` crate.
///
/// Owns the accept side of the stack (the TCP listener) plus the background tasks that
/// keep it alive — smoltcp's poll runner and the bidirectional TUN↔stack packet bridge.
/// All three are aborted when the handle is dropped.
pub struct SmoltcpNetstack {
    listener: TcpListener,
    /// Runner + the two bridge directions. Held so they can be aborted on drop rather
    /// than leaked (CLAUDE.md: store every spawned `JoinHandle` that isn't fire-and-forget).
    tasks: Vec<JoinHandle<()>>,
}

impl SmoltcpNetstack {
    /// Build the stack sized to the device MTU, spawn the poll runner and the
    /// bidirectional TUN↔stack bridge, and return a handle whose
    /// [`Netstack::accept_tcp`] yields surfaced TCP flows.
    ///
    /// `tun` is shared (`Arc`) because the two bridge directions read and write the same
    /// device concurrently from separate tasks; both `Tun::recv`/`Tun::send` take `&self`.
    pub fn new(tun: Arc<Tun>) -> io::Result<Self> {
        let mtu = tun.mtu();

        // UDP is disabled until M5. ICMP rides the TCP interface (smoltcp answers echo),
        // which preserves the M1 `ping <tun>` sanity check at no extra cost.
        let (stack, runner, _udp, listener) = StackBuilder::default()
            .enable_tcp(true)
            .enable_udp(false)
            .enable_icmp(true)
            .mtu(mtu)
            .build()?;

        let listener =
            listener.ok_or_else(|| io::Error::other("netstack built without a TCP listener"))?;

        let mut tasks = Vec::with_capacity(3);

        // The runner drives smoltcp's poll loop; it must run for the stack to make
        // progress. Its `io::Result<()>` output is normalized to `()` so all tasks share
        // one `JoinHandle` type.
        if let Some(runner) = runner {
            tasks.push(tokio::spawn(async move {
                if let Err(e) = runner.await {
                    warn!(error = %e, "netstack runner exited with error");
                }
            }));
        }

        let (mut sink, mut stream) = stack.split();

        // stack → TUN: write each outbound IP packet the netstack produces to the device.
        let tun_tx = Arc::clone(&tun);
        tasks.push(tokio::spawn(async move {
            while let Some(item) = stream.next().await {
                match item {
                    Ok(pkt) => {
                        if let Err(e) = tun_tx.send(&pkt).await {
                            warn!(error = %e, "TUN send failed; stopping stack→TUN bridge");
                            break;
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "netstack emitted an error frame; stopping stack→TUN bridge");
                        break;
                    }
                }
            }
            debug!("stack→TUN bridge ended");
        }));

        // TUN → stack: feed each inbound IP packet to the netstack. The stack's sink
        // takes an owned `AnyIpPktFrame` (= `Vec<u8>`), so we read directly into a
        // fresh MTU-sized `Vec` and hand it over — one allocation, no copy. (The owned
        // `Vec` is the vendored crate's API; a reusable buffer would force a `.to_vec()`.)
        let tun_rx = Arc::clone(&tun);
        tasks.push(tokio::spawn(async move {
            loop {
                let mut buf = vec![0u8; mtu];
                match tun_rx.recv(&mut buf).await {
                    Ok(0) => continue,
                    Ok(n) => {
                        buf.truncate(n);
                        if let Err(e) = sink.send(buf).await {
                            warn!(error = %e, "netstack sink closed; stopping TUN→stack bridge");
                            break;
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "TUN recv failed; stopping TUN→stack bridge");
                        break;
                    }
                }
            }
            debug!("TUN→stack bridge ended");
        }));

        Ok(Self { listener, tasks })
    }
}

#[async_trait]
impl Netstack for SmoltcpNetstack {
    async fn accept_tcp(&mut self) -> Option<TcpFlow> {
        // The listener yields `(stream, local_addr, remote_addr)`. In netstack-smoltcp
        // these accessors are inverted from the usual server-socket sense: `local_addr`
        // is the application's source (built from `packet.src_addr`) and `remote_addr`
        // is the original destination (`packet.dst_addr`) — the upstream the app dialed.
        // Verified against the vendored source (vendor/netstack-smoltcp/src/tcp.rs:118,
        // 132-133,165, where the socket `listen`s on `dst_addr`). Dial `remote_addr`.
        let (stream, src, original_dst) = self.listener.next().await?;
        Some(TcpFlow {
            original_dst,
            src,
            stream: Box::new(stream),
        })
    }
}

impl Drop for SmoltcpNetstack {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
