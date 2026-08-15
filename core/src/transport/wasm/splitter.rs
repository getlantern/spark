//! The BIP324 **splitting egress** (ADR 0013 §7 step 4, PR4b-2). A single listener that is
//! indistinguishable from a real Bitcoin v2 node: it peeks each incoming connection's opening
//! (`ellswift` + the leading garbage), checks the Lantern **side-door tag** keyed by a per-server
//! secret, and routes accordingly —
//!
//! - **tag matches** → a Lantern tunnel client: run the BIP324 responder handshake ([`WasmServer`]) and
//!   relay the tunnel to the address the client announced.
//! - **no match** → a real Bitcoin peer (random garbage, no `k_srv`): proxy the bytes untouched to a
//!   real node, chosen from the [`UpstreamPool`] by the peer's own address.
//!
//! Because the tag rides inside BIP324's opening garbage, a non-participant — including an active
//! prober — sees only a well-formed Bitcoin handshake, and blocking the egress means blocking Bitcoin
//! (the collateral-freedom goal). The classification is a bounded peek: the tag (when present) sits in
//! the same opening burst as the `ellswift`, so it arrives immediately; a real peer whose garbage is
//! shorter than the tag simply times out of the peek and is proxied.

use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Buf, Bytes};
use ring::hmac;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

use super::telemetry::{EgressTelemetry, Opening, Outcome, UntaggedSession};
use super::upstream::UpstreamPool;
use super::WasmServer;
use crate::transport::tcp_tunnel::header::Address;

use bip324_core::{ELLSWIFT_LEN, SIDE_DOOR_TAG_LEN};

/// Bytes to peek before classifying: the `ellswift` key plus the candidate side-door tag that a Lantern
/// client prepends to its garbage.
pub(super) const PEEK_LEN: usize = ELLSWIFT_LEN + SIDE_DOOR_TAG_LEN;

/// HMAC-SHA256 via `ring`, matching `bip324-core`'s side-door construction (which the guest computes via
/// the host's `host_hkdf_extract` — HKDF-Extract *is* HMAC-SHA256).
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), msg);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

/// A stream that yields `prefix` first, then the underlying stream — used to replay the bytes peeked
/// for classification so the chosen branch (handshake or proxy) sees the connection from byte 0.
struct PrefixedStream<S> {
    prefix: Bytes,
    inner: S,
}

impl<S> PrefixedStream<S> {
    fn new(prefix: Bytes, inner: S) -> Self {
        Self { prefix, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.prefix.is_empty() {
            let n = this.prefix.len().min(buf.remaining());
            buf.put_slice(&this.prefix[..n]);
            this.prefix.advance(n);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// A Bitcoin-v2 egress that splits Lantern tunnel clients from real peers by the side-door tag.
pub struct SplittingServer {
    wasm: WasmServer,
    k_srv: Vec<u8>,
    upstream: UpstreamPool,
    peek_timeout: Duration,
    telemetry: Arc<EgressTelemetry>,
}

impl SplittingServer {
    /// Create a splitter that runs the BIP324 tunnel via `wasm` for clients presenting a valid tag under
    /// `k_srv`, and proxies everything else to one of the real Bitcoin nodes in `upstream`.
    pub fn new(wasm: WasmServer, k_srv: Vec<u8>, upstream: UpstreamPool) -> Self {
        Self {
            wasm,
            k_srv,
            upstream,
            peek_timeout: Duration::from_secs(5),
            telemetry: Arc::new(EgressTelemetry::new()),
        }
    }

    /// The egress counters, for a periodic operational summary.
    pub fn telemetry(&self) -> Arc<EgressTelemetry> {
        Arc::clone(&self.telemetry)
    }

    /// Override the classification peek timeout (default 5s). Past it, a connection that hasn't sent a
    /// full `ellswift`+tag is treated as a real peer and proxied.
    pub fn with_peek_timeout(mut self, timeout: Duration) -> Self {
        self.peek_timeout = timeout;
        self
    }

    /// Classify one accepted connection and either run the BIP324 tunnel or proxy it to a real node.
    ///
    /// `peer` is the connection's source address, and is used only on the proxy branch, to pick which
    /// upstream this peer transits — see [`UpstreamPool`] for why that is a function of the peer
    /// rather than a rotation.
    pub async fn handle<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        mut conn: S,
        peer: IpAddr,
    ) -> io::Result<()> {
        // Peek ellswift + candidate tag. A Lantern client sends both in its opening burst (so they
        // arrive together); the timeout keeps a real peer with < tag-length garbage from stalling us.
        let mut peek = [0u8; PEEK_LEN];
        let n = peek_up_to(&mut conn, &mut peek, self.peek_timeout).await?;
        if n == 0 {
            // The peer sent nothing (idle until the peek timeout, or half-closed at once). Drop it
            // rather than dial `upstream` for a silent probe — that would amplify connections against
            // the real node, and a real node wouldn't dial out for a silent peer either.
            //
            // Recorded before returning: a connection that opens and says nothing is the single
            // clearest probe signature we get, and until this it left no trace at all.
            drop(self.telemetry.on_untagged(peer, Opening::Silent));
            return Ok(());
        }

        let is_tunnel = n == PEEK_LEN && {
            let mut ellswift = [0u8; ELLSWIFT_LEN];
            ellswift.copy_from_slice(&peek[..ELLSWIFT_LEN]);
            bip324_core::verify_side_door_tag_with(
                hmac_sha256,
                &self.k_srv,
                &ellswift,
                &peek[ELLSWIFT_LEN..],
            )
        };

        let replayed = PrefixedStream::new(Bytes::copy_from_slice(&peek[..n]), conn);
        if is_tunnel {
            // Counted, never identified: this peer authenticated, so it is one of our users.
            self.telemetry.on_tunnel();
            self.relay_tunnel(replayed).await
        } else {
            let opening = if n == PEEK_LEN {
                Opening::Untagged
            } else {
                Opening::Short { bytes: n }
            };
            let session = self.telemetry.on_untagged(peer, opening);
            self.proxy_upstream(replayed, peer, session).await
        }
    }

    /// Tunnel branch: run the responder handshake, then relay the client's announced target.
    async fn relay_tunnel<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        conn: PrefixedStream<S>,
    ) -> io::Result<()> {
        let (target, leftover, mut wrapped) = self.wasm.accept(conn).await?;
        let mut up = match target {
            Address::Ip(sa) => TcpStream::connect(sa).await?,
            Address::Domain { host, port } => TcpStream::connect((host.as_str(), port)).await?,
        };
        if !leftover.is_empty() {
            up.write_all(&leftover).await?;
        }
        tokio::io::copy_bidirectional(&mut wrapped, &mut up).await?;
        Ok(())
    }

    /// Proxy branch: forward the (replayed) bytes untouched to the real Bitcoin node this peer maps to.
    ///
    /// `session` carries the record for this peer and writes it when dropped, so every exit path here
    /// — including the `?` ones — produces one.
    async fn proxy_upstream<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        mut conn: PrefixedStream<S>,
        peer: IpAddr,
        mut session: UntaggedSession,
    ) -> io::Result<()> {
        let mut up = match self.upstream.connect_for(peer).await {
            Ok(up) => up,
            Err(e) => {
                // Untagged peers getting nothing is the anomaly this whole design exists to avoid, so
                // it is recorded as its own outcome rather than folded into a generic relay failure.
                session.failed(Outcome::UpstreamUnreachable);
                return Err(e);
            }
        };
        if let Ok(addr) = up.peer_addr() {
            session.routed_to(addr);
        }
        match tokio::io::copy_bidirectional(&mut conn, &mut up).await {
            Ok((to_upstream, from_upstream)) => {
                session.finished(Outcome::Relayed, to_upstream, from_upstream);
                Ok(())
            }
            Err(e) => {
                session.failed(Outcome::RelayFailed);
                Err(e)
            }
        }
    }
}

/// Read into `buf` until it is full, the peer half-closes, or `timeout` elapses — returning how many
/// bytes were read. The timeout is what lets a real peer whose opening garbage is shorter than the tag
/// be classified (and proxied) instead of hanging the peek waiting for bytes it won't send until it
/// gets a handshake reply.
async fn peek_up_to<S: AsyncRead + Unpin>(
    conn: &mut S,
    buf: &mut [u8],
    timeout: Duration,
) -> io::Result<usize> {
    let mut filled = 0;
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);
    while filled < buf.len() {
        tokio::select! {
            r = conn.read(&mut buf[filled..]) => match r? {
                0 => break, // peer half-closed
                n => filled += n,
            },
            _ = &mut deadline => break, // classify on what arrived
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use super::*;

    /// Any address: these tests exercise classification, and the peer only selects among a
    /// single-node pool here.
    const TEST_PEER: std::net::IpAddr =
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 9));
    use crate::transport::wasm::{ModuleVerifier, TransformModule, WasmTransport};
    use crate::transport::Transport;
    use tokio::net::TcpListener;

    const MAGIC: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];
    const K_SRV: &[u8] = b"per-server side-door secret";

    fn load_module() -> TransformModule {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/wasm/bip324.spkw");
        let artifact = std::fs::read(&path).expect("read bip324.spkw");
        ModuleVerifier::pinned()
            .verify(&artifact, 0)
            .expect("verify bip324 module")
            .into_module()
    }

    /// Client init config: `[role=0][magic][k_srv_len][k_srv]` — a Lantern initiator with the side-door.
    fn client_cfg() -> Vec<u8> {
        let mut c = vec![0u8];
        c.extend_from_slice(&MAGIC);
        c.extend_from_slice(&(K_SRV.len() as u16).to_be_bytes());
        c.extend_from_slice(K_SRV);
        c
    }

    /// Server init config: `[role=1][magic][k_srv_len=0]` — a plain responder (the splitter verifies the
    /// tag itself; the responder module is protocol-blind BIP324).
    fn server_cfg() -> Vec<u8> {
        let mut c = vec![1u8];
        c.extend_from_slice(&MAGIC);
        c.extend_from_slice(&[0, 0]);
        c
    }

    /// Spawn a stub that behaves like a real `bitcoind` rather than an echo server: it **speaks
    /// first**, unprompted, and keeps talking. Returns its address and a handle to what it received.
    ///
    /// The distinction matters. An echo server only ever speaks when spoken to, so it cannot catch a
    /// relay that pumps client→upstream correctly but only drains upstream→client on demand. A real
    /// node opens with its own `version`, then sends `ping`s and `inv` announcements with no prompt,
    /// and a peer that never sees them concludes we are broken and disconnects.
    async fn spawn_chatty_node() -> (SocketAddr, Arc<Mutex<Vec<u8>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind node");
        let addr = listener.local_addr().expect("node addr");
        let received = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&received);
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                let sink = Arc::clone(&sink);
                tokio::spawn(async move {
                    // Speak first, before the peer has said anything, the way a node announces itself.
                    if s.write_all(NODE_GREETING).await.is_err() {
                        return;
                    }
                    let mut buf = [0u8; 4096];
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                sink.lock().expect("sink lock").extend_from_slice(&buf[..n]);
                                // Answer with a *different*, larger payload so the test cannot pass by
                                // echoing, and so the upstream→client direction carries real volume.
                                let reply: Vec<u8> = (0..n * 3).map(|i| (i % 251) as u8).collect();
                                if s.write_all(&reply).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
        (addr, received)
    }

    /// `read_exact` with a deadline, so a relay that silently stops delivering fails the assertion
    /// rather than hanging the test binary until CI kills the job.
    async fn read_exact_by<S: AsyncRead + Unpin>(s: &mut S, buf: &mut [u8]) -> io::Result<()> {
        tokio::time::timeout(Duration::from_secs(5), s.read_exact(buf))
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "no bytes arrived before deadline")
            })?
            .map(|_| ())
    }

    /// Stands in for a node's opening `version` message: sent before the peer says anything.
    const NODE_GREETING: &[u8] = b"\xf9\xbe\xb4\xd9version-unprompted-from-the-real-node";

    /// Spawn a TCP echo server and return its address.
    async fn spawn_echo() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
        let addr = listener.local_addr().expect("echo addr");
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 512];
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
        addr
    }

    #[tokio::test]
    async fn lantern_client_is_tunneled_and_a_real_peer_is_proxied() {
        let module = load_module();
        let echo_addr = spawn_echo().await; // the tunnel client's announced target
        let upstream_addr = spawn_echo().await; // stands in for bitcoind

        // The splitting egress: BIP324 tunnel for tagged clients, proxy-to-upstream for everyone else.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind egress");
        let egress_addr = listener.local_addr().expect("egress addr");
        let server = WasmServer::new(module.clone()).with_config(server_cfg());
        let splitter = Arc::new(SplittingServer::new(
            server,
            K_SRV.to_vec(),
            UpstreamPool::single(upstream_addr),
        ));
        tokio::spawn(async move {
            while let Ok((conn, peer)) = listener.accept().await {
                let s = Arc::clone(&splitter);
                tokio::spawn(async move {
                    let _ = s.handle(conn, peer.ip()).await;
                });
            }
        });

        // 1) A Lantern client (tagged) dials the echo target through the BIP324 tunnel.
        let transport = WasmTransport::new(egress_addr, module).with_config(client_cfg());
        let mut tunneled = transport.dial(echo_addr).await.expect("tunnel dial");
        let msg = b"routed through the bip324 tunnel to the announced target";
        tunneled.write_all(msg).await.expect("tunnel write");
        let mut got = vec![0u8; msg.len()];
        tunneled.read_exact(&mut got).await.expect("tunnel read");
        assert_eq!(
            got.as_slice(),
            &msg[..],
            "tunnel client round-trips via the echo target"
        );

        // 2) A real Bitcoin peer (no valid tag) is proxied untouched to the upstream, which echoes.
        //    96 bytes of non-tag opening: the splitter peeks, the tag check fails, and it proxies —
        //    if it had wrongly taken the tunnel branch the BIP324 handshake would reject these bytes.
        let mut peer = TcpStream::connect(egress_addr).await.expect("peer connect");
        let opening: Vec<u8> = (0..PEEK_LEN).map(|i| i as u8).collect();
        peer.write_all(&opening).await.expect("peer write");
        let mut echoed = vec![0u8; opening.len()];
        peer.read_exact(&mut echoed)
            .await
            .expect("peer read (proxied to the upstream stub)");
        assert_eq!(
            echoed, opening,
            "real peer's bytes are proxied to the upstream and echoed back"
        );
    }

    /// Live end-to-end proof of the proxy branch against a real Bitcoin node: a non-Lantern opening
    /// reaches `bitcoind` through the splitter and gets a genuine BIP324 response. `#[ignore]`d — it
    /// needs a BIP324-capable `bitcoind`. Run it with:
    ///   `BIP324_BITCOIND=127.0.0.1:8333 cargo test -p spark-core --features bip324 -- --ignored real_bitcoin`
    #[tokio::test]
    #[ignore = "requires a BIP324-capable bitcoind (set BIP324_BITCOIND=host:port, default 127.0.0.1:8333)"]
    async fn real_bitcoin_peer_reaches_bitcoind_through_the_proxy_branch() {
        // Resolve via lookup_host so a hostname (e.g. localhost:8333) works, not just an IP literal.
        let target =
            std::env::var("BIP324_BITCOIND").unwrap_or_else(|_| "127.0.0.1:8333".to_string());
        let resolved: Vec<SocketAddr> = tokio::net::lookup_host(&target)
            .await
            .expect("resolve BIP324_BITCOIND (host:port)")
            .collect();
        // Prefer IPv4: `localhost` often resolves to `::1` first, but bitcoind may bind v4 only.
        let bitcoind = resolved
            .iter()
            .find(|a| a.is_ipv4())
            .or_else(|| resolved.first())
            .copied()
            .expect("BIP324_BITCOIND resolved to no address");

        let module = load_module();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind egress");
        let egress_addr = listener.local_addr().expect("egress addr");
        let server = WasmServer::new(module).with_config(server_cfg());
        let splitter = Arc::new(SplittingServer::new(
            server,
            K_SRV.to_vec(),
            UpstreamPool::single(bitcoind),
        ));
        tokio::spawn(async move {
            while let Ok((conn, peer)) = listener.accept().await {
                let s = Arc::clone(&splitter);
                tokio::spawn(async move {
                    let _ = s.handle(conn, peer.ip()).await;
                });
            }
        });

        // A non-Lantern opening (no valid tag) so the splitter takes the proxy branch. A BIP324
        // responder replies to any 64-byte ellswift with its own key + garbage, so reading 64 bytes
        // back proves the proxy delivered us to the real node and it answered.
        let mut peer = TcpStream::connect(egress_addr).await.expect("peer connect");
        let opening: Vec<u8> = (0..PEEK_LEN).map(|i| i as u8).collect();
        peer.write_all(&opening).await.expect("peer write");
        let mut ellswift = [0u8; ELLSWIFT_LEN];
        // Bound the read so a manual run against an unreachable/non-v2 node fails fast with a clear
        // message instead of hanging (peek_timeout + bitcoind's reply should be well under this).
        tokio::time::timeout(Duration::from_secs(10), peer.read_exact(&mut ellswift))
            .await
            .expect("timed out waiting for bitcoind — is BIP324_BITCOIND reachable and v2-capable?")
            .expect("bitcoind replied through the proxy branch with its ellswift key");
    }

    #[tokio::test]
    async fn a_silent_peer_is_dropped_without_dialing_upstream() {
        let module = load_module();
        // upstream points at a refused port: if `handle` dialed it, the proxy branch would error.
        let refused = "127.0.0.1:1".parse().expect("addr");
        let server = WasmServer::new(module).with_config(server_cfg());
        let splitter = SplittingServer::new(server, K_SRV.to_vec(), UpstreamPool::single(refused))
            .with_peek_timeout(Duration::from_millis(200));

        // A peer that sends nothing and is at EOF at once: peek reads 0 → drop early, no upstream dial.
        splitter
            .handle(tokio::io::empty(), TEST_PEER)
            .await
            .expect("silent peer dropped without dialing the refused upstream");
    }

    /// A real Bitcoin peer must get a *working node*, not merely a socket that doesn't refuse.
    ///
    /// This is the collateral-freedom property in its operational form: if we accept a real peer's
    /// connection but its transactions don't actually flow, we are a broken node — which is its own
    /// distinguishing signal, and worse than being closed. So the proxy branch has to be a plain
    /// byte relay in both directions, for the whole life of the connection, including data the
    /// upstream sends with nothing prompting it.
    #[tokio::test]
    async fn a_real_peer_gets_a_fully_working_bidirectional_relay() {
        let (bitcoind, received) = spawn_chatty_node().await;
        let module = load_module();
        let server = WasmServer::new(module.clone()).with_config(server_cfg());
        let splitter = Arc::new(
            SplittingServer::new(server, K_SRV.to_vec(), UpstreamPool::single(bitcoind))
                .with_peek_timeout(Duration::from_millis(200)),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind egress");
        let egress = listener.local_addr().expect("egress addr");
        tokio::spawn(async move {
            while let Ok((conn, peer)) = listener.accept().await {
                let s = Arc::clone(&splitter);
                tokio::spawn(async move {
                    let _ = s.handle(conn, peer.ip()).await;
                });
            }
        });

        let mut peer = TcpStream::connect(egress).await.expect("peer connect");

        // The peer's opening burst, shorter than the peek buffer — a real v1 `version` is, so this is
        // also the case that must not stall waiting for bytes that will never come.
        let opening = b"\xf9\xbe\xb4\xd9version-from-a-real-peer";
        peer.write_all(opening).await.expect("peer opening");

        // The node's unprompted greeting must reach the peer. An echo-based test cannot check this.
        //
        // Every read here is deadlined: a relay that has stopped pumping upstream→client does not
        // return an error, it simply never delivers, so a bare `read_exact` would hang the test run
        // instead of failing it. The deadline is what turns "the relay is broken" into a message.
        let mut greeting = vec![0u8; NODE_GREETING.len()];
        read_exact_by(&mut peer, &mut greeting)
            .await
            .expect("the node's unprompted greeting must reach the peer");
        assert_eq!(
            greeting, NODE_GREETING,
            "a real node speaks first; if that never arrives the peer sees a dead node"
        );

        // Then sustained traffic both ways, well past the classification peek, in several rounds —
        // the shape of a peer relaying transactions rather than just completing a handshake.
        let mut sent_total = opening.len();
        for round in 0..4usize {
            let payload: Vec<u8> = (0..1024 * (round + 1)).map(|i| (i % 253) as u8).collect();
            peer.write_all(&payload).await.expect("peer payload");
            sent_total += payload.len();

            // The stub answers 3x whatever it read; read at least one byte of the reply to prove the
            // return direction is still live this late in the connection.
            let mut back = [0u8; 1];
            read_exact_by(&mut peer, &mut back)
                .await
                .expect("the upstream→peer direction must stay open for the whole connection");
        }

        // Everything the peer sent — including the opening bytes the splitter peeked at to classify —
        // must reach the node, byte for byte. A peek that swallowed its buffer would show up here as
        // a short count, and a node that silently loses a peer's first message is not a working node.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let got = received.lock().expect("sink lock").len();
            if got >= sent_total {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "upstream received {got} of {sent_total} bytes: the peeked opening was not replayed intact"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let got = received.lock().expect("sink lock").clone();
        assert_eq!(
            &got[..opening.len()],
            &opening[..],
            "the bytes consumed by the classification peek must be replayed to the node first"
        );
    }
}
