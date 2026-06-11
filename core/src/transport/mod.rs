//! Tunnel transports: how the proxy core reaches a target.
//!
//! Two surfaces, one per L4 protocol — matching the universal shape in sing-box, Leaf, and
//! the QUIC transports (see the `udp-transport-design-proposal` memory):
//!
//! - [`Transport`] (TCP): "give me a byte stream to this target."
//! - [`UdpTransport`] (UDP): "give me a connected datagram channel to this target," split
//!   into [`PacketSink`]/[`PacketSource`] halves so the send side can live in the netstack
//!   read loop while the recv side runs in a reply pump.
//!
//! The proxy forwarders depend only on the traits, so swapping a direct connection for a
//! tunneled one is a configuration choice, not a code change:
//!
//! - [`DirectTransport`] connects/sends straight to the target (the M2 behavior).
//! - [`tcp_tunnel::client::TunnelClient`] routes through a tunnel server (M3/M4 for TCP, M5
//!   for UDP-over-stream).

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::net::{TcpStream, UdpSocket};

use crate::BoxedStream;

pub mod tcp_tunnel;

/// A way to obtain a bidirectional byte stream to a target address.
///
/// The target is a [`SocketAddr`] because that is what the netstack surfaces (the original
/// destination an application dialed). A transport that addresses targets by name resolves
/// or forwards the name itself.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Open a stream to `target`. The returned stream relays application bytes
    /// transparently in both directions.
    async fn dial(&self, target: SocketAddr) -> io::Result<BoxedStream>;
}

/// The send half of a connected UDP association: datagrams to the negotiated target.
#[async_trait]
pub trait PacketSink: Send {
    /// Send one datagram to the association's target.
    async fn send(&mut self, payload: &[u8]) -> io::Result<()>;
}

/// The receive half of a connected UDP association: datagrams from the negotiated target.
#[async_trait]
pub trait PacketSource: Send {
    /// Receive one datagram into `buf`, returning its length. If `buf` is shorter than the
    /// datagram the excess is dropped (UDP truncation semantics), but the whole datagram is
    /// still consumed so a stream-backed source stays frame-aligned.
    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize>;
}

/// Boxed [`PacketSink`].
pub type BoxedPacketSink = Box<dyn PacketSink>;
/// Boxed [`PacketSource`].
pub type BoxedPacketSource = Box<dyn PacketSource>;

/// A way to obtain a connected UDP datagram channel to a target.
///
/// Returns the send/recv halves already split (rather than one `&self` object) because a
/// stream-backed implementation can't offer `&self` writes without holding a lock across an
/// `.await`. The split lets the netstack read loop own the sink (`&mut`) while a per-flow
/// reply pump owns the source.
#[async_trait]
pub trait UdpTransport: Send + Sync {
    /// Open a connected UDP association to `target`, returning its split halves.
    async fn dial_udp(
        &self,
        target: SocketAddr,
    ) -> io::Result<(BoxedPacketSink, BoxedPacketSource)>;
}

/// Connects/sends straight to the target with no tunnel — the direct behavior, expressed as
/// both a [`Transport`] (TCP) and a [`UdpTransport`] (UDP).
pub struct DirectTransport;

#[async_trait]
impl Transport for DirectTransport {
    async fn dial(&self, target: SocketAddr) -> io::Result<BoxedStream> {
        let stream = TcpStream::connect(target).await?;
        Ok(Box::new(stream))
    }
}

#[async_trait]
impl UdpTransport for DirectTransport {
    async fn dial_udp(
        &self,
        target: SocketAddr,
    ) -> io::Result<(BoxedPacketSink, BoxedPacketSource)> {
        // Bind an ephemeral local socket in the target's address family, then `connect` so
        // send/recv talk only to `target`.
        let bind = if target.is_ipv4() {
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        } else {
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
        };
        let socket = UdpSocket::bind(bind).await?;
        socket.connect(target).await?;
        let socket = Arc::new(socket);
        Ok((
            Box::new(DirectPacketSink(Arc::clone(&socket))),
            Box::new(DirectPacketSource(socket)),
        ))
    }
}

/// Send half over a connected [`UdpSocket`] (shared via `Arc`; tokio's UDP send/recv take
/// `&self`, so no lock is needed).
struct DirectPacketSink(Arc<UdpSocket>);

#[async_trait]
impl PacketSink for DirectPacketSink {
    async fn send(&mut self, payload: &[u8]) -> io::Result<()> {
        self.0.send(payload).await.map(|_| ())
    }
}

/// Receive half over the same connected [`UdpSocket`].
struct DirectPacketSource(Arc<UdpSocket>);

#[async_trait]
impl PacketSource for DirectPacketSource {
    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.recv(buf).await
    }
}
