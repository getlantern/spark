//! Tunnel transports: how the proxy core reaches a target.
//!
//! The [`Transport`] trait abstracts "give me a byte stream to this target". The proxy
//! forwarder ([`crate::proxy::tcp`]) depends only on the trait, so swapping a direct
//! connection for a tunneled one is a configuration choice, not a code change:
//!
//! - [`DirectTransport`] connects straight to the target (the M2 behavior).
//! - [`tcp_tunnel::client::TunnelClient`] connects to a tunnel server and announces the
//!   target in a header (M3), so the bytes travel through the tunnel.

use std::io;
use std::net::SocketAddr;

use async_trait::async_trait;
use tokio::net::TcpStream;

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

/// Connects straight to the target with no tunnel — the M2 forwarder behavior, expressed
/// as a [`Transport`].
pub struct DirectTransport;

#[async_trait]
impl Transport for DirectTransport {
    async fn dial(&self, target: SocketAddr) -> io::Result<BoxedStream> {
        let stream = TcpStream::connect(target).await?;
        Ok(Box::new(stream))
    }
}
