//! The TCP tunnel client: dial a tunnel server and announce the target address.

use std::io;
use std::net::SocketAddr;

use bytes::BytesMut;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use super::header::Address;
use super::stream::TunnelStream;

/// A client for the plain TCP tunnel. Holds the tunnel server address; each
/// [`dial`](Self::dial) opens a fresh connection to it.
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
    /// stream over which application bytes flow transparently in both directions.
    pub async fn dial(&self, target: Address) -> io::Result<TunnelStream<TcpStream>> {
        let mut conn = TcpStream::connect(self.server).await?;
        let mut header = BytesMut::with_capacity(target.encoded_len());
        target.encode(&mut header);
        conn.write_all(&header).await?;
        Ok(TunnelStream::new(conn))
    }
}
