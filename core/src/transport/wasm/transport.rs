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
use crate::transport::engine::{Genome, ModuleEngine, OpeningEngine};
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
    /// The module as an opening engine, so the TCP dial realizes its opening through the same seam a
    /// genome-selected engine does (ADR 0013 §7) rather than through a second, parallel code path.
    engine: Arc<ModuleEngine>,
    /// Dynamic opening plan for this transport (a postcard [`Genome`]); empty ⇒ use `fallback`.
    params: Vec<u8>,
    /// Always-realizable static plan (a postcard [`Genome`]), so connectivity never depends on a
    /// dynamic plan being usable.
    fallback: Vec<u8>,
    protector: Option<SocketProtector>,
}

impl WasmTransport {
    /// Create a client that tunnels through `server`, obfuscating each connection with `module`.
    ///
    /// The module is left **unnamed** as an engine, which is right for a locally configured module
    /// (nothing needs to look it up by name). Use [`with_engine`](Self::with_engine) when the name
    /// matters — production does, because a genome selects its engine *by* name.
    pub fn new(server: SocketAddr, module: TransformModule) -> Self {
        Self::with_engine(server, Arc::new(ModuleEngine::new(String::new(), module)))
    }

    /// Create a client whose opening is realized by an already-named [`ModuleEngine`].
    ///
    /// The name should be the one the signed artifact gives itself, so a genome cannot select this
    /// engine under a name nobody signed.
    pub fn with_engine(server: SocketAddr, engine: Arc<ModuleEngine>) -> Self {
        Self {
            server,
            engine,
            params: Vec::new(),
            fallback: Vec::new(),
            protector: None,
        }
    }

    /// Set the dynamic opening plan: a postcard [`Genome`] whose opaque `engine_params` become the
    /// module's `init` bytes. Falls back to [`with_config`](Self::with_config) if it is unusable.
    pub fn with_genome(mut self, genome: Vec<u8>) -> Self {
        self.params = genome;
        self
    }

    /// Set the per-deployment configuration delivered to the module's `init` export on each dial
    /// (e.g. a key or seed). Empty by default.
    ///
    /// These bytes *are* engine params; this wraps them in a genome addressed to this engine so the
    /// module sees exactly one kind of input. Kept because a locally configured module is a real use
    /// case, but it is now the **fallback** — a delivered genome supersedes it.
    pub fn with_config(mut self, config: Vec<u8>) -> Self {
        // A builder cannot return an error, and encoding this genome should never fail — it is an
        // in-memory postcard encode of a struct with no unsupported types. But an empty fallback is
        // indistinguishable from "no fallback configured", so a silent failure here would surface
        // much later as a module trapping on empty `init`. Say so instead of swallowing it.
        self.fallback = match Genome::new("static", self.engine.id(), Default::default(), config)
            .encode()
        {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    engine = %self.engine.id(),
                    "encoding the static fallback genome failed; this transport has no fallback plan"
                );
                Vec::new()
            }
        };
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
        // Resolve the opening plan once and use it for both jobs below — one postcard decode per
        // dial, not two, and no chance of the socket being tuned for a different plan than the one
        // the module runs.
        let (init, wire) = self.engine.plan(&self.params, &self.fallback);
        // `TCP_NODELAY` has to be set on the concrete socket — flint's shaper is generic over the
        // stream and only guarantees a flush per segment — so without this the segments a genome
        // asks for can still be coalesced into one packet by Nagle. It must happen here, while the
        // socket is still concrete: past this point the stream is boxed away behind the seam. A
        // failure to set it only forfeits the optimization, so it must not fail the dial.
        if wire.tcp_nodelay {
            let _ = conn.set_nodelay(true);
        }
        // Realize the opening through the engine: it instantiates the module with these engine
        // params, shapes the opening, and runs the interactive handshake if the module drives one
        // (e.g. BIP324). Identical to what a genome-selected engine does — it is the same code,
        // entered one step lower because the plan is already in hand.
        let mut wrapped = self
            .engine
            .realize_resolved(Box::new(conn), init, wire)
            .await?;

        // The address header is the first thing through the transform; the server reads it back
        // after applying the inverse, then relays the obfuscated stream that follows.
        let mut header = BytesMut::with_capacity(target.encoded_len());
        target.encode(&mut header);
        wrapped.write_all(&header).await?;

        // `realize` already returns a `BoxedStream`; re-boxing would put a second pointer hop on
        // every read and write for the life of the connection.
        Ok(wrapped)
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
    config: Vec<u8>,
}

impl WasmServer {
    /// Create a server that deobfuscates connections with `module`.
    pub fn new(module: TransformModule) -> Self {
        Self {
            module,
            config: Vec::new(),
        }
    }

    /// Set the per-deployment configuration delivered to the module's `init` export on each accept
    /// (e.g. the responder role + network magic for a handshake module). Empty by default.
    pub fn with_config(mut self, config: Vec<u8>) -> Self {
        self.config = config;
        self
    }

    /// Wrap an accepted connection in the inverse transform and read the tunnel address header.
    ///
    /// Returns the target [`Address`] the client announced, any payload bytes already read past the
    /// header (forward these to the target before relaying further), and the wrapped stream to relay
    /// through. A fresh [`Transform`](super::Transform) is instantiated for this connection.
    pub async fn accept<S>(
        &self,
        mut conn: S,
    ) -> io::Result<(Address, BytesMut, TransformStream<S>)>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut transform = self
            .module
            .instantiate_with_config(&self.config)
            .map_err(|e| io::Error::other(e.to_string()))?;
        // Mirror the client: run the module's interactive opening (as the responder) before steady
        // state. Transform-only modules skip this (protocol-blind).
        if transform.drives_handshake() {
            transform.run_handshake(&mut conn).await?;
        }
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
        self.dial_udp_addr(Address::Ip(target)).await
    }

    async fn dial_udp_addr(
        &self,
        target: Address,
    ) -> io::Result<(BoxedPacketSink, BoxedPacketSource)> {
        let mut conn = protected_tcp_connect(self.server, self.protector.as_ref()).await?;
        // Not through `realize`: that seam consumes a stream and returns a stream, while this path
        // needs the `Transform` itself (one instance shared between the split halves below). The
        // `init` bytes come from the same place the TCP path gets them, so the two cannot diverge on
        // what this transport's protocol parameters are.
        let mut transform = self
            .engine
            .module()
            .instantiate_with_config(&self.engine.init_bytes(&self.params, &self.fallback))
            .map_err(|e| io::Error::other(e.to_string()))?;
        // Run the interactive opening (as initiator) before steady state, mirroring the TCP dial path.
        // The server runs the responder handshake in `WasmServer::accept` for every connection — the
        // TCP-tunnel vs UDP-associate split happens later, from the address header — so a handshake
        // module would desync if the UDP client skipped it. (BIP324 is stream-shaped; whether it suits
        // the per-datagram UDP framing is a separate question — see `WasmUdpSink`.)
        if transform.drives_handshake() {
            transform.run_handshake(&mut conn).await?;
        }
        // One transform instance serves both directions; the split halves (which live in different
        // tasks — the netstack send loop and the reply pump) share it behind a Mutex. The transform
        // call is synchronous and the guard is never held across an `.await`.
        let transform = Arc::new(Mutex::new(transform));

        // UDP-associate handshake (obfuscated): the sentinel switches the server to UDP relay mode,
        // then the real target follows (connect-mode — an IP or a **domain** the exit resolves; no
        // per-datagram address after this).
        let mut header = BytesMut::new();
        udp_associate_sentinel().encode(&mut header);
        target.encode(&mut header);
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

    /// The full BIP324 dial path over real TCP: the client (initiator) and server (responder) each run
    /// the interactive handshake — driven by `run_handshake` now that it's wired into `dial_target` /
    /// `accept` — then the address header + tunneled bytes ride the steady-state transform to an echo
    /// and back. Uses the committed signed `bip324.spkw`. Proves a handshake-based module actually
    /// tunnels (which the obfs-xor test above, a transform-only module, cannot exercise).
    #[cfg(feature = "bip324")]
    #[tokio::test]
    async fn bip324_tunnel_round_trips_over_real_tcp() {
        use crate::transport::wasm::ModuleVerifier;

        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/wasm/bip324.spkw");
        let artifact = std::fs::read(&path).expect("read bip324.spkw");
        let module = ModuleVerifier::pinned()
            .verify(&artifact, 0)
            .expect("verify bip324 module")
            .into_module();

        // init_config: [role][network_magic(4)][k_srv_len(2)=0][garbage…]. Mainnet magic, no side-door.
        const MAGIC: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];
        let cfg = |role: u8| {
            let mut c = vec![role];
            c.extend_from_slice(&MAGIC);
            c.extend_from_slice(&[0, 0]); // k_srv_len = 0
            c
        };

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

        // BIP324 tunnel server (responder): accept → run the handshake → read the target → relay.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind server");
        let server_addr = listener.local_addr().expect("server addr");
        let server = WasmServer::new(module.clone()).with_config(cfg(1));
        tokio::spawn(async move {
            let (conn, _) = listener.accept().await.expect("accept");
            let (target, leftover, mut wrapped) =
                server.accept(conn).await.expect("accept + handshake");
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

        // Client (initiator): dial the echo target through the BIP324 tunnel.
        let transport = WasmTransport::new(server_addr, module).with_config(cfg(0));
        let mut stream = transport.dial(echo_addr).await.expect("dial");
        let message = b"hello through a bip324 wasm tunnel over real tcp";
        stream.write_all(message).await.expect("write");
        let mut got = vec![0u8; message.len()];
        stream.read_exact(&mut got).await.expect("read");
        assert_eq!(got.as_slice(), &message[..]);
    }

    /// Step 2: the module's `init` bytes come from a **genome**, not from `init_config`.
    ///
    /// Two cases in one harness, because the second is only meaningful against the first:
    ///   - a genome addressed to this engine supplies the params, and the tunnel works;
    ///   - a genome addressed to *another* engine is refused and the transport falls back to
    ///     `init_config`, so a misaddressed plan degrades to the static config instead of feeding
    ///     foreign bytes to `init` (which the guest answers by trapping).
    ///
    /// The fallback case is the one worth guarding: it is the difference between "a bad plan costs
    /// nothing" and "a bad plan takes the transport down".
    #[cfg(feature = "bip324")]
    #[tokio::test]
    async fn a_genome_supplies_init_bytes_and_a_misaddressed_one_falls_back() {
        use crate::transport::engine::{Genome, ModuleEngine};
        use crate::transport::wasm::ModuleVerifier;

        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/wasm/bip324.spkw");
        let artifact = std::fs::read(&path).expect("read bip324.spkw");
        let module = ModuleVerifier::pinned()
            .verify(&artifact, 0)
            .expect("verify bip324 module")
            .into_module();

        const MAGIC: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];
        let init = |role: u8| {
            let mut c = vec![role];
            c.extend_from_slice(&MAGIC);
            c.extend_from_slice(&[0, 0]); // k_srv_len = 0
            c
        };
        const ENGINE: &str = "bip324-genome-test";
        let genome_for = |engine: &str, role: u8| {
            Genome::new("dynamic", engine, Default::default(), init(role))
                .encode()
                .expect("encode genome")
        };

        // One echo target and one tunnel server serve both dials.
        let echo = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
        let echo_addr = echo.local_addr().expect("echo addr");
        tokio::spawn(async move {
            while let Ok((mut s, _)) = echo.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 256];
                    while let Ok(n) = s.read(&mut buf).await {
                        if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind server");
        let server_addr = listener.local_addr().expect("server addr");
        // `Arc` because one server serves both dials from separate tasks (`WasmServer` isn't `Clone`).
        let server = Arc::new(WasmServer::new(module.clone()).with_config(init(1)));
        tokio::spawn(async move {
            // Two connections: one per client dial below.
            for _ in 0..2 {
                let (conn, _) = listener.accept().await.expect("accept");
                let server = Arc::clone(&server);
                tokio::spawn(async move {
                    let (target, leftover, mut wrapped) =
                        server.accept(conn).await.expect("accept + handshake");
                    let mut upstream = match target {
                        Address::Ip(sa) => TcpStream::connect(sa).await.expect("connect target"),
                        Address::Domain { .. } => panic!("test announces an IP target"),
                    };
                    if !leftover.is_empty() {
                        upstream.write_all(&leftover).await.expect("leftover");
                    }
                    let _ = copy_bidirectional(&mut wrapped, &mut upstream).await;
                });
            }
        });

        let engine = Arc::new(ModuleEngine::new(ENGINE, module));

        // 1) A genome addressed to this engine drives the handshake. No `init_config` is set at all,
        //    so if the genome were ignored the module would get empty config and trap.
        let via_genome = WasmTransport::with_engine(server_addr, engine.clone())
            .with_genome(genome_for(ENGINE, 0));
        let mut stream = via_genome.dial(echo_addr).await.expect("dial via genome");
        let msg = b"driven by a genome";
        stream.write_all(msg).await.expect("write");
        let mut got = vec![0u8; msg.len()];
        stream.read_exact(&mut got).await.expect("read");
        assert_eq!(
            got.as_slice(),
            &msg[..],
            "the genome supplied the init bytes"
        );

        // 2) A genome for a different engine must be refused, leaving `init_config` to carry the dial.
        let via_fallback = WasmTransport::with_engine(server_addr, engine)
            .with_config(init(0))
            .with_genome(genome_for("some-other-engine", 0));
        let mut stream = via_fallback
            .dial(echo_addr)
            .await
            .expect("dial via fallback");
        stream.write_all(msg).await.expect("write");
        let mut got = vec![0u8; msg.len()];
        stream.read_exact(&mut got).await.expect("read");
        assert_eq!(
            got.as_slice(),
            &msg[..],
            "a misaddressed genome degrades to init_config rather than breaking the dial"
        );
    }

    /// Regression for the coalesced handshake→steady-state boundary. Over a real stream the initiator's
    /// final handshake message and its first steady-state packet can arrive in one read, so the
    /// responder's handshake driver over-reads the steady-state bytes into the module. Those bytes are
    /// no longer on the wire, so the reader must drain them from the module (via the empty-input path in
    /// `TransformStream::poll_read`) rather than block on a wire read that never returns. This forces
    /// the coalescing deterministically (the loopback test only hit it under load) and reads through a
    /// wire with no further bytes: without the drain it fails `UnexpectedEof` instead of hanging.
    #[cfg(feature = "bip324")]
    #[tokio::test]
    async fn poll_read_drains_steady_state_bytes_the_handshake_over_read() {
        use crate::transport::wasm::ModuleVerifier;

        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/wasm/bip324.spkw");
        let artifact = std::fs::read(&path).expect("read bip324.spkw");
        let module = ModuleVerifier::pinned()
            .verify(&artifact, 0)
            .expect("verify bip324 module")
            .into_module();

        const MAGIC: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];
        let cfg = |role: u8| {
            let mut c = vec![role];
            c.extend_from_slice(&MAGIC);
            c.extend_from_slice(&[0, 0]); // k_srv_len = 0 (side-door disabled)
            c
        };
        let mut initiator = module
            .instantiate_with_config(&cfg(0))
            .expect("instantiate initiator");
        let mut responder = module
            .instantiate_with_config(&cfg(1))
            .expect("instantiate responder");

        // Drive the 1.5-RTT handshake up to (but not through) the responder's final step.
        let (client_hello, done) = initiator.handshake_step(&[]).expect("init open");
        assert!(!done);
        let (empty, done) = responder.handshake_step(&[]).expect("resp open");
        assert!(
            empty.is_empty() && !done,
            "responder emits nothing at connect"
        );
        let (resp_reply, done) = responder
            .handshake_step(&client_hello)
            .expect("responder reply");
        assert!(!done, "responder still needs the initiator's final");
        let (init_final, done) = initiator.handshake_step(&resp_reply).expect("init final");
        assert!(done, "initiator completes after the responder's reply");

        // The initiator immediately sends its first two steady-state packets; on the wire they coalesce
        // with the handshake tail. Hand the responder ALL of it in one step — it completes the handshake
        // and buffers both packets (two complete frames), exercising the multi-frame drain.
        let payload1 = b"first steady-state packet, coalesced with the handshake tail";
        let payload2 = b"and a second packet right behind it";
        let mut coalesced = init_final;
        coalesced.extend_from_slice(&initiator.transform_out(payload1).expect("steady out 1"));
        coalesced.extend_from_slice(&initiator.transform_out(payload2).expect("steady out 2"));
        let (out, done) = responder
            .handshake_step(&coalesced)
            .expect("responder final");
        assert!(done && out.is_empty(), "responder completes, emits nothing");

        // Read through a wire with no further bytes, in sub-frame 7-byte chunks: every payload byte must
        // come from the module's buffer, served across many reads and never reporting a premature EOF
        // while buffered bytes remain. Without the drain the first read fails `UnexpectedEof`.
        let mut wrapped = TransformStream::new(tokio::io::empty(), responder);
        let mut expected = payload1.to_vec();
        expected.extend_from_slice(payload2);
        let mut got = Vec::new();
        let mut chunk = [0u8; 7];
        while got.len() < expected.len() {
            let n = wrapped
                .read(&mut chunk)
                .await
                .expect("drain the over-read steady-state bytes");
            assert_ne!(n, 0, "premature EOF with buffered bytes still pending");
            got.extend_from_slice(&chunk[..n]);
        }
        assert_eq!(got, expected);
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
