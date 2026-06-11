//! The TCP tunnel client: dial a tunnel server and announce the target address.

use std::io;
use std::net::SocketAddr;

use async_trait::async_trait;
use bytes::BytesMut;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use super::header::Address;
use super::stream::TunnelStream;
use super::udp::{udp_associate_sentinel, TunnelUdpSink, TunnelUdpSource};
use crate::transport::{BoxedPacketSink, BoxedPacketSource, Transport, UdpTransport};
use crate::BoxedStream;

/// A client for the plain TCP tunnel. Holds the tunnel server address; each dial opens a
/// fresh connection to it.
///
/// Note this dials the tunnel **server**, not the ultimate target — the target travels in
/// the address header. That indirection is what frees M4's TUN integration from the M2
/// direct-dial loop hazard: the OS route sends target traffic into the tunnel, while the
/// connection to the server (a different address) follows the normal route.
pub struct TunnelClient {
    server: SocketAddr,
}

impl TunnelClient {
    /// Create a client that tunnels through the server at `server`.
    pub fn new(server: SocketAddr) -> Self {
        Self { server }
    }

    /// Connect to the tunnel server, send the `target` address header, and return a relay
    /// stream. This is the address-typed entry point (it accepts domain targets); the
    /// [`Transport`] impl is the `SocketAddr` interface the proxy core uses.
    pub async fn dial(&self, target: Address) -> io::Result<TunnelStream<TcpStream>> {
        let mut conn = TcpStream::connect(self.server).await?;
        let mut header = BytesMut::with_capacity(target.encoded_len());
        target.encode(&mut header);
        conn.write_all(&header).await?;
        Ok(TunnelStream::new(conn))
    }
}

#[async_trait]
impl Transport for TunnelClient {
    async fn dial(&self, target: SocketAddr) -> io::Result<BoxedStream> {
        // Defer to the inherent address-typed `dial` (the `Address` argument disambiguates
        // it from this trait method) and box the relay stream.
        let stream = TunnelClient::dial(self, Address::Ip(target)).await?;
        Ok(Box::new(stream))
    }
}

#[async_trait]
impl UdpTransport for TunnelClient {
    async fn dial_udp(
        &self,
        target: SocketAddr,
    ) -> io::Result<(BoxedPacketSink, BoxedPacketSource)> {
        // UDP-associate handshake: send the magic sentinel (so the server switches to UDP
        // relay mode without changing the TCP header format), then the real target once
        // (connect-mode). After that the stream carries `[u16 len][payload]` datagrams.
        let mut conn = TcpStream::connect(self.server).await?;
        let mut header = BytesMut::new();
        udp_associate_sentinel().encode(&mut header);
        Address::Ip(target).encode(&mut header);
        conn.write_all(&header).await?;

        let (read, write) = conn.into_split();
        Ok((
            Box::new(TunnelUdpSink::new(write)),
            Box::new(TunnelUdpSource::new(read)),
        ))
    }
}
