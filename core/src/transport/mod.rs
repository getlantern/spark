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
use socket2::SockRef;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

use crate::config::{AnytlsConfig, Config};
use crate::net::SocketProtector;
use crate::BoxedStream;

pub mod anytls;
pub mod tcp_tunnel;

/// Connect a TCP stream to `addr`, optionally pinning the socket to a physical interface
/// (so the dial bypasses the tunnel route — see [`SocketProtector`]). Shared by
/// [`DirectTransport`] and the tunnel client (which dials its server).
pub(crate) async fn protected_tcp_connect(
    addr: SocketAddr,
    protector: Option<&SocketProtector>,
) -> io::Result<TcpStream> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    if let Some(p) = protector {
        p.protect(SockRef::from(&socket), addr.is_ipv4())?;
    }
    socket.connect(addr).await
}

/// Build a connected UDP socket to `target`, optionally pinned to a physical interface.
fn protected_udp_socket(
    target: SocketAddr,
    protector: Option<&SocketProtector>,
) -> io::Result<socket2::Socket> {
    let domain = if target.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    if let Some(p) = protector {
        p.protect(SockRef::from(&socket), target.is_ipv4())?;
    }
    let bind = if target.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    };
    socket.bind(&bind.into())?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

/// Build the TCP + UDP transports from `config`: a tunnel client when `transport.server` is
/// set, otherwise direct; both pinned to `transport.protect_interface` when configured.
pub fn from_config(config: &Config) -> io::Result<(Arc<dyn Transport>, Arc<dyn UdpTransport>)> {
    let protector = match config.transport.protect_interface.as_deref() {
        Some(name) => Some(SocketProtector::for_interface(name)?),
        None => None,
    };
    // AnyTLS takes precedence over the plain `server` tunnel when configured.
    if let Some(anytls) = &config.transport.anytls {
        return anytls_transport(anytls, protector);
    }
    Ok(match config.transport.server {
        Some(server) => {
            let mut client = tcp_tunnel::client::TunnelClient::new(server);
            if let Some(p) = protector {
                client = client.with_socket_protection(p);
            }
            let client = Arc::new(client);
            (
                client.clone() as Arc<dyn Transport>,
                client as Arc<dyn UdpTransport>,
            )
        }
        None => {
            let direct = Arc::new(DirectTransport::new(protector));
            (
                direct.clone() as Arc<dyn Transport>,
                direct as Arc<dyn UdpTransport>,
            )
        }
    })
}

/// Build the AnyTLS TCP transport (feature `anytls`). UDP-over-AnyTLS (sing UoT v2) is a follow-up,
/// so the UDP side is direct for now (DNS etc. bypass the AnyTLS tunnel).
#[cfg(feature = "anytls")]
fn anytls_transport(
    cfg: &AnytlsConfig,
    protector: Option<SocketProtector>,
) -> io::Result<(Arc<dyn Transport>, Arc<dyn UdpTransport>)> {
    let sni = cfg
        .sni
        .clone()
        .unwrap_or_else(|| cfg.server.ip().to_string());
    let tcp = Arc::new(anytls::AnytlsTransport::new(
        cfg.server,
        cfg.password.clone(),
        sni,
        protector.clone(),
    ));
    let udp = Arc::new(DirectTransport::new(protector));
    Ok((tcp as Arc<dyn Transport>, udp as Arc<dyn UdpTransport>))
}

/// Without the `anytls` feature, a configured AnyTLS transport is a hard error rather than a silent
/// fallback (the user asked for AnyTLS but the binary can't provide it).
#[cfg(not(feature = "anytls"))]
fn anytls_transport(
    _cfg: &AnytlsConfig,
    _protector: Option<SocketProtector>,
) -> io::Result<(Arc<dyn Transport>, Arc<dyn UdpTransport>)> {
    Err(io::Error::other(
        "transport.anytls is configured but spark was built without the `anytls` feature",
    ))
}

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
/// both a [`Transport`] (TCP) and a [`UdpTransport`] (UDP). An optional [`SocketProtector`]
/// pins its dials to a physical interface so they bypass the tunnel route.
#[derive(Default)]
pub struct DirectTransport {
    protector: Option<SocketProtector>,
}

impl DirectTransport {
    /// A direct transport, optionally pinning outbound sockets to a physical interface.
    pub fn new(protector: Option<SocketProtector>) -> Self {
        Self { protector }
    }
}

#[async_trait]
impl Transport for DirectTransport {
    async fn dial(&self, target: SocketAddr) -> io::Result<BoxedStream> {
        let stream = protected_tcp_connect(target, self.protector.as_ref()).await?;
        Ok(Box::new(stream))
    }
}

#[async_trait]
impl UdpTransport for DirectTransport {
    async fn dial_udp(
        &self,
        target: SocketAddr,
    ) -> io::Result<(BoxedPacketSink, BoxedPacketSource)> {
        // Build an ephemeral socket (pinned to the protected interface if any), then
        // `connect` so send/recv talk only to `target`.
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
