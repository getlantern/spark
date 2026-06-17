//! The AnyTLS [`Transport`] (feature `anytls`, ADR 0001): dial targets through an AnyTLS session
//! over BoringSSL TLS to the configured server.
//!
//! A single session is established lazily and shared across dials (one TLS connection, many
//! multiplexed streams — AnyTLS's model). The idle-session **pool** (multiple sessions, sweep) and
//! session **reconnect** on death are follow-ups; this is the minimal working transport.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::BytesMut;
use tokio::io::AsyncWriteExt;
use tokio::sync::OnceCell;

use crate::net::SocketProtector;
use crate::transport::tcp_tunnel::header::Address;
use crate::transport::{protected_tcp_connect, Transport};
use crate::BoxedStream;

use super::{tls, PaddingScheme, Session};

/// An AnyTLS client transport over a single shared, lazily-established session.
pub struct AnytlsTransport {
    server: SocketAddr,
    password: String,
    sni: String,
    protector: Option<SocketProtector>,
    session: OnceCell<Arc<Session>>,
}

impl AnytlsTransport {
    /// Build a transport dialing `server` (TLS SNI `sni`), authenticating with `password`. The
    /// upstream TCP dial is pinned to `protector`'s interface so it bypasses the tunnel route.
    pub fn new(
        server: SocketAddr,
        password: String,
        sni: String,
        protector: Option<SocketProtector>,
    ) -> Self {
        Self {
            server,
            password,
            sni,
            protector,
            session: OnceCell::new(),
        }
    }

    /// The shared session, established (TCP → TLS → AnyTLS client handshake) on first use.
    async fn session(&self) -> io::Result<Arc<Session>> {
        self.session
            .get_or_try_init(|| async {
                let tcp = protected_tcp_connect(self.server, self.protector.as_ref()).await?;
                let tls = tls::connect(tcp, &self.sni).await?;
                let session = Session::client(tls, &self.password, PaddingScheme::default());
                Ok::<_, io::Error>(Arc::new(session))
            })
            .await
            .cloned()
    }
}

#[async_trait]
impl Transport for AnytlsTransport {
    async fn dial(&self, target: SocketAddr) -> io::Result<BoxedStream> {
        let session = self.session().await?;
        let mut stream = session.open_stream().await?;
        // AnyTLS choreography: the target address is the stream's first bytes (SOCKS5 grammar),
        // which also flushes the buffered cmdSettings+cmdSYN as padded packet 1.
        let mut addr = BytesMut::new();
        Address::Ip(target).encode(&mut addr);
        stream.write_all(&addr).await?;
        Ok(Box::new(stream))
    }
}
