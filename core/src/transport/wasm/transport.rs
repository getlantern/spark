//! The dynamic-transport client ([`WasmTransport`]) and its matching server ([`WasmServer`]).
//!
//! The wasm module is a byte-level obfuscation layer that sits **underneath** the existing tunnel
//! handshake. The client dials a spark server, wraps the connection in a [`TransformStream`], and
//! then runs the ordinary [`Address`] header exchange over that obfuscated stream; the server wraps
//! its accepted connection in the inverse transform and reads the same header back. So the
//! target-conveyance protocol is reused unchanged — the module only mangles bytes — and because the
//! header is simply the first bytes through `transform_out`/`transform_in`, the two endpoints' codec
//! state stays aligned (which matters for a stateful module).
//!
//! Both ends instantiate a fresh [`Transform`](super::Transform) per connection. The module itself
//! is loaded and authenticated out of band (see [`ModuleVerifier`](super::ModuleVerifier)); a
//! [`TransformModule`] here is already-trusted, compiled wasm.

use std::io;
use std::net::SocketAddr;

use async_trait::async_trait;
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use super::{TransformModule, TransformStream};
use crate::net::SocketProtector;
use crate::transport::tcp_tunnel::header::Address;
use crate::transport::tcp_tunnel::stream::read_header;
use crate::transport::{protected_tcp_connect, Transport};
use crate::BoxedStream;

/// A dynamic-transport client: dials a spark server, obfuscates the connection with a wasm module,
/// and announces the target over the obfuscated stream. One [`Transform`](super::Transform) is
/// instantiated per dial.
///
/// Like the plain tunnel client, this dials the **server**, not the ultimate target — the target
/// travels in the address header, so the OS route can send target traffic into the TUN while the
/// connection to the server follows the normal route (pin it with [`with_socket_protection`] when a
/// privileged daemon needs the dial to bypass the tunnel).
///
/// [`with_socket_protection`]: WasmTransport::with_socket_protection
pub struct WasmTransport {
    server: SocketAddr,
    module: TransformModule,
    protector: Option<SocketProtector>,
}

impl WasmTransport {
    /// Create a client that tunnels through `server`, obfuscating each connection with `module`.
    pub fn new(server: SocketAddr, module: TransformModule) -> Self {
        Self {
            server,
            module,
            protector: None,
        }
    }

    /// Pin connections to the server to a physical interface, so they bypass the tunnel route.
    pub fn with_socket_protection(mut self, protector: SocketProtector) -> Self {
        self.protector = Some(protector);
        self
    }
}

#[async_trait]
impl Transport for WasmTransport {
    async fn dial(&self, target: SocketAddr) -> io::Result<BoxedStream> {
        let conn = protected_tcp_connect(self.server, self.protector.as_ref()).await?;
        let transform = self
            .module
            .instantiate()
            .map_err(|e| io::Error::other(e.to_string()))?;
        let mut wrapped = TransformStream::new(conn, transform);

        // The address header is the first thing through the transform; the server reads it back
        // after applying the inverse, then relays the obfuscated stream that follows.
        let addr = Address::from(target);
        let mut header = BytesMut::with_capacity(addr.encoded_len());
        addr.encode(&mut header);
        wrapped.write_all(&header).await?;

        Ok(Box::new(wrapped))
    }
}

/// The server counterpart to [`WasmTransport`]: wraps an accepted connection in the inverse
/// transform and recovers the target the client announced.
pub struct WasmServer {
    module: TransformModule,
}

impl WasmServer {
    /// Create a server that deobfuscates connections with `module`.
    pub fn new(module: TransformModule) -> Self {
        Self { module }
    }

    /// Wrap an accepted connection in the inverse transform and read the tunnel address header.
    ///
    /// Returns the target [`Address`] the client announced, any payload bytes already read past the
    /// header (forward these to the target before relaying further), and the wrapped stream to relay
    /// through. A fresh [`Transform`](super::Transform) is instantiated for this connection.
    pub async fn accept<S>(&self, conn: S) -> io::Result<(Address, BytesMut, TransformStream<S>)>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let transform = self
            .module
            .instantiate()
            .map_err(|e| io::Error::other(e.to_string()))?;
        let mut wrapped = TransformStream::new(conn, transform);
        let (target, leftover) = read_header(&mut wrapped).await?;
        Ok((target, leftover, wrapped))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::wasm::testutil::xor_module;
    use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn client_server_obfuscated_tunnel_round_trips() {
        let module = xor_module();

        // A plain echo "target" the tunnel ultimately reaches.
        let echo = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
        let echo_addr = echo.local_addr().expect("echo addr");
        tokio::spawn(async move {
            while let Ok((mut s, _)) = echo.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 256];
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if s.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });

        // The wasm tunnel server: deobfuscate, read the announced target, relay to it.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind server");
        let server_addr = listener.local_addr().expect("server addr");
        let server = WasmServer::new(module.clone());
        tokio::spawn(async move {
            let (conn, _) = listener.accept().await.expect("accept");
            let (target, leftover, mut wrapped) = server.accept(conn).await.expect("read header");
            let mut upstream = match target {
                Address::Ip(sa) => TcpStream::connect(sa).await.expect("connect target"),
                Address::Domain { .. } => panic!("test announces an IP target"),
            };
            if !leftover.is_empty() {
                upstream
                    .write_all(&leftover)
                    .await
                    .expect("forward leftover");
            }
            let _ = copy_bidirectional(&mut wrapped, &mut upstream).await;
        });

        // The client dials the echo target *through* the obfuscated tunnel.
        let transport = WasmTransport::new(server_addr, module);
        let mut stream = transport.dial(echo_addr).await.expect("dial");
        let message = b"hello via the wasm-obfuscated tunnel";
        stream.write_all(message).await.expect("write");
        let mut got = vec![0u8; message.len()];
        stream.read_exact(&mut got).await.expect("read");
        assert_eq!(got.as_slice(), &message[..]);
    }
}
