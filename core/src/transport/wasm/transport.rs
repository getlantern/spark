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
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::{Buf, BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use super::{Transform, TransformModule, TransformStream};
use crate::net::SocketProtector;
use crate::transport::tcp_tunnel::header::Address;
use crate::transport::tcp_tunnel::stream::read_header;
use crate::transport::tcp_tunnel::udp::udp_associate_sentinel;
use crate::transport::{
    protected_tcp_connect, BoxedPacketSink, BoxedPacketSource, PacketSink, PacketSource, Transport,
    UdpTransport,
};
use crate::BoxedStream;

/// Scratch buffer size for a raw read from the connection before deobfuscation (UDP source).
const UDP_READ_SCRATCH: usize = 16 * 1024;

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
    config: Vec<u8>,
    protector: Option<SocketProtector>,
}

impl WasmTransport {
    /// Create a client that tunnels through `server`, obfuscating each connection with `module`.
    pub fn new(server: SocketAddr, module: TransformModule) -> Self {
        Self {
            server,
            module,
            config: Vec::new(),
            protector: None,
        }
    }

    /// Set the per-deployment configuration delivered to the module's `init` export on each dial
    /// (e.g. a key or seed). Empty by default.
    pub fn with_config(mut self, config: Vec<u8>) -> Self {
        self.config = config;
        self
    }

    /// Pin connections to the server to a physical interface, so they bypass the tunnel route.
    pub fn with_socket_protection(mut self, protector: SocketProtector) -> Self {
        self.protector = Some(protector);
        self
    }
}

impl WasmTransport {
    /// Connect, wrap in the transform, and announce `target` (an IP or a domain the exit resolves) in
    /// the address header. Shared by [`dial`]/[`dial_addr`].
    async fn dial_target(&self, target: Address) -> io::Result<BoxedStream> {
        let conn = protected_tcp_connect(self.server, self.protector.as_ref()).await?;
        let transform = self
            .module
            .instantiate_with_config(&self.config)
            .map_err(|e| io::Error::other(e.to_string()))?;
        let mut wrapped = TransformStream::new(conn, transform);

        // The address header is the first thing through the transform; the server reads it back
        // after applying the inverse, then relays the obfuscated stream that follows.
        let mut header = BytesMut::with_capacity(target.encoded_len());
        target.encode(&mut header);
        wrapped.write_all(&header).await?;

        Ok(Box::new(wrapped))
    }
}

#[async_trait]
impl Transport for WasmTransport {
    async fn dial(&self, target: SocketAddr) -> io::Result<BoxedStream> {
        self.dial_target(Address::Ip(target)).await
    }

    async fn dial_addr(&self, target: Address) -> io::Result<BoxedStream> {
        self.dial_target(target).await
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

#[async_trait]
impl UdpTransport for WasmTransport {
    async fn dial_udp(
        &self,
        target: SocketAddr,
    ) -> io::Result<(BoxedPacketSink, BoxedPacketSource)> {
        let mut conn = protected_tcp_connect(self.server, self.protector.as_ref()).await?;
        // One transform instance serves both directions; the split halves (which live in different
        // tasks — the netstack send loop and the reply pump) share it behind a Mutex. The transform
        // call is synchronous and the guard is never held across an `.await`.
        let transform = Arc::new(Mutex::new(
            self.module
                .instantiate_with_config(&self.config)
                .map_err(|e| io::Error::other(e.to_string()))?,
        ));

        // UDP-associate handshake (obfuscated): the sentinel switches the server to UDP relay mode,
        // then the real target follows (connect-mode — no per-datagram address after this).
        let mut header = BytesMut::new();
        udp_associate_sentinel().encode(&mut header);
        Address::from(target).encode(&mut header);
        let header_wire = transform_out(&transform, &header)?;
        conn.write_all(&header_wire).await?;

        let (read, write) = conn.into_split();
        Ok((
            Box::new(WasmUdpSink {
                write,
                transform: Arc::clone(&transform),
            }),
            Box::new(WasmUdpSource {
                read,
                transform,
                buf: BytesMut::new(),
                scratch: vec![0u8; UDP_READ_SCRATCH].into_boxed_slice(),
            }),
        ))
    }
}

/// Connect-mode UDP send half: frame each datagram as `[u16 BE len][payload]`, obfuscate it through
/// the shared transform, and write it to the connection.
///
/// Caveat: this assumes the module emits a datagram's wire bytes from the same `transform_out` call
/// (true for a stream cipher / per-call AEAD — the expected shapes). A module that *buffers* input
/// across calls before emitting could stall a datagram until the next `send`; such a module is unfit
/// for the UDP path. (TCP, a pure byte stream, has no such constraint.)
struct WasmUdpSink {
    write: OwnedWriteHalf,
    transform: Arc<Mutex<Transform>>,
}

#[async_trait]
impl PacketSink for WasmUdpSink {
    async fn send(&mut self, payload: &[u8]) -> io::Result<()> {
        if payload.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "UDP payload exceeds the 2-byte length field",
            ));
        }
        let mut frame = BytesMut::with_capacity(2 + payload.len());
        frame.put_u16(payload.len() as u16);
        frame.put_slice(payload);
        let wire = transform_out(&self.transform, &frame)?;
        self.write.write_all(&wire).await
    }
}

/// Connect-mode UDP receive half: read obfuscated bytes, deobfuscate through the shared transform,
/// and reassemble `[u16 BE len][payload]` frames.
struct WasmUdpSource {
    read: OwnedReadHalf,
    transform: Arc<Mutex<Transform>>,
    /// Deobfuscated bytes awaiting frame reassembly.
    buf: BytesMut,
    /// Reused scratch for raw reads (allocated once, not per datagram).
    scratch: Box<[u8]>,
}

#[async_trait]
impl PacketSource for WasmUdpSource {
    async fn recv(&mut self, out: &mut [u8]) -> io::Result<usize> {
        loop {
            // A whole `[u16 len][payload]` frame buffered? Deliver it (truncating to `out`, but
            // consuming the full datagram to stay frame-aligned — UDP truncation semantics).
            if self.buf.len() >= 2 {
                let len = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
                if self.buf.len() >= 2 + len {
                    self.buf.advance(2);
                    let n = len.min(out.len());
                    out[..n].copy_from_slice(&self.buf[..n]);
                    self.buf.advance(len);
                    return Ok(n);
                }
            }
            // Otherwise read more wire bytes and deobfuscate them into `buf`.
            let n = self.read.read(&mut self.scratch).await?;
            if n == 0 {
                return Ok(0); // connection closed
            }
            let recovered = transform_in(&self.transform, &self.scratch[..n])?;
            self.buf.extend_from_slice(&recovered);
        }
    }
}

/// Lock the shared transform, run `transform_out`, and release before returning (no guard is held
/// across an `.await`). Maps a poisoned lock or a transform error to an `io::Error`.
fn transform_out(transform: &Mutex<Transform>, input: &[u8]) -> io::Result<Vec<u8>> {
    let mut t = transform
        .lock()
        .map_err(|_| io::Error::other("wasm transform mutex poisoned"))?;
    t.transform_out(input)
        .map_err(|e| io::Error::other(e.to_string()))
}

/// The inbound counterpart to [`transform_out`].
fn transform_in(transform: &Mutex<Transform>, input: &[u8]) -> io::Result<Vec<u8>> {
    let mut t = transform
        .lock()
        .map_err(|_| io::Error::other("wasm transform mutex poisoned"))?;
    t.transform_in(input)
        .map_err(|e| io::Error::other(e.to_string()))
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

    /// `dial_addr` with a **domain** target: the client announces the name, and the server recovers it
    /// (the exit resolves it — no client-side DNS). Exercises the shared `Address::Domain` encode path
    /// (the same one anytls uses) end-to-end through the obfuscated tunnel.
    #[tokio::test]
    async fn dial_addr_carries_a_domain_to_the_server() {
        let module = xor_module();

        // The echo the exit would resolve the domain to (here, any domain → this loopback echo).
        let echo = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
        let echo_addr = echo.local_addr().expect("echo addr");
        tokio::spawn(async move {
            while let Ok((mut s, _)) = echo.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 256];
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) if s.write_all(&buf[..n]).await.is_err() => break,
                            Ok(_) => {}
                        }
                    }
                });
            }
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind server");
        let server_addr = listener.local_addr().expect("server addr");
        let server = WasmServer::new(module.clone());
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (conn, _) = listener.accept().await.expect("accept");
            let (target, leftover, mut wrapped) = server.accept(conn).await.expect("read header");
            let host = match target {
                Address::Domain { host, .. } => host,
                Address::Ip(_) => panic!("expected a domain target"),
            };
            let _ = tx.send(host); // report what the server recovered
            let mut upstream = TcpStream::connect(echo_addr).await.expect("connect echo");
            if !leftover.is_empty() {
                upstream.write_all(&leftover).await.expect("leftover");
            }
            let _ = copy_bidirectional(&mut wrapped, &mut upstream).await;
        });

        let transport = WasmTransport::new(server_addr, module);
        let mut stream = transport
            .dial_addr(Address::domain("cdn.example.com", 443).expect("domain"))
            .await
            .expect("dial_addr");
        let message = b"hello via a domain target";
        stream.write_all(message).await.expect("write");
        let mut got = vec![0u8; message.len()];
        stream.read_exact(&mut got).await.expect("read");
        assert_eq!(got.as_slice(), &message[..]);
        assert_eq!(
            rx.await.unwrap(),
            "cdn.example.com",
            "the server recovered the domain the client announced"
        );
    }

    /// Read the `[sentinel][target]` UDP-associate handshake from a (deobfuscating) stream, returning
    /// the announced target. Leftover bytes past the two addresses stay in `buf`.
    async fn read_udp_handshake<S: AsyncRead + Unpin>(
        stream: &mut S,
        buf: &mut BytesMut,
    ) -> Address {
        let mut chunk = [0u8; 512];
        loop {
            if let Ok((_sentinel, n1)) = Address::parse(buf) {
                if let Ok((target, n2)) = Address::parse(&buf[n1..]) {
                    buf.advance(n1 + n2);
                    return target;
                }
            }
            let n = stream.read(&mut chunk).await.expect("read handshake");
            assert!(n > 0, "EOF during UDP handshake");
            buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// Read one `[u16 len][payload]` frame from a (deobfuscating) stream, or `None` at EOF.
    async fn read_frame<S: AsyncRead + Unpin>(
        stream: &mut S,
        buf: &mut BytesMut,
    ) -> Option<Vec<u8>> {
        let mut chunk = [0u8; 512];
        loop {
            if buf.len() >= 2 {
                let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
                if buf.len() >= 2 + len {
                    buf.advance(2);
                    let payload = buf[..len].to_vec();
                    buf.advance(len);
                    return Some(payload);
                }
            }
            let n = stream.read(&mut chunk).await.ok()?;
            if n == 0 {
                return None;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    }

    #[tokio::test]
    async fn udp_round_trips_through_the_obfuscated_tunnel() {
        let module = xor_module();

        // The wasm UDP server: deobfuscate, read the associate handshake, echo framed datagrams.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind server");
        let server_addr = listener.local_addr().expect("server addr");
        let server_module = module.clone();
        tokio::spawn(async move {
            let (conn, _) = listener.accept().await.expect("accept");
            // The whole stream is owned by this one task (read + write), so no split is needed
            // server-side; TransformStream deobfuscates reads and obfuscates writes transparently.
            let mut wrapped =
                TransformStream::new(conn, server_module.instantiate().expect("instantiate"));
            let mut buf = BytesMut::new();
            let _target = read_udp_handshake(&mut wrapped, &mut buf).await;
            while let Some(payload) = read_frame(&mut wrapped, &mut buf).await {
                let mut reply = BytesMut::with_capacity(2 + payload.len());
                reply.put_u16(payload.len() as u16);
                reply.put_slice(&payload);
                if wrapped.write_all(&reply).await.is_err() {
                    break;
                }
                wrapped.flush().await.ok();
            }
        });

        let transport = WasmTransport::new(server_addr, module);
        let (mut sink, mut source) = transport
            .dial_udp("198.51.100.7:53".parse().expect("addr"))
            .await
            .expect("dial_udp");

        // Two datagrams, to prove the framed stream stays aligned across calls.
        sink.send(b"dns query").await.expect("send 1");
        let mut got = [0u8; 64];
        let n = source.recv(&mut got).await.expect("recv 1");
        assert_eq!(&got[..n], b"dns query");

        sink.send(b"second datagram").await.expect("send 2");
        let n = source.recv(&mut got).await.expect("recv 2");
        assert_eq!(&got[..n], b"second datagram");
    }
}
