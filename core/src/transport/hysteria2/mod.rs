//! Hysteria 2 transport (ADR 0010): QUIC client interoperable with apernet/hysteria, Salamander+Gecko obfuscation.

mod auth;
mod obfs;
mod tcp;
mod udp;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::AsyncReadExt;

use crate::net::SocketProtector;
use crate::transport::{
    protected_udp_socket, BoxedPacketSink, BoxedPacketSource, BoxedStream, PacketSink,
    PacketSource, Transport, UdpTransport,
};

// rustls is not a direct dependency of this crate; it is the exact same locked version re-exported
// by quinn, so we reach it through `quinn::rustls` to avoid declaring a redundant dependency.
use quinn::rustls;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{ring as ring_provider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, SignatureScheme};

use crate::config::{Hysteria2Config, Hysteria2Tls, Hysteria2TlsMode};

/// Errors raised while establishing and authenticating a Hysteria 2 QUIC connection.
///
/// One [`thiserror`]-derived enum per module (project standard). `Quic` and `Io` carry their
/// underlying error via `#[from]` (distinct source types, so no conflict); the remaining variants
/// are produced by manual `map_err` at the call sites.
#[derive(Debug, thiserror::Error)]
pub enum Hysteria2Error {
    /// `Endpoint::connect` rejected the configuration or address before the handshake began
    /// (e.g. no default client config, bad server name). Carries no inner error because quinn's
    /// `ConnectError` is not retained — only the failure point matters here.
    #[error("hysteria2: failed to initiate QUIC connection")]
    Connect,
    /// The server completed the QUIC handshake but rejected the `/auth` request with a non-233
    /// HTTP/3 `:status`. The carried code is the server's status (233 is the only success value).
    #[error("hysteria2: authentication rejected by server (status {0})")]
    Auth(u16),
    /// Building the rustls `ClientConfig` or converting it to a `QuicClientConfig` failed
    /// (e.g. the ring provider lacks a TLS 1.3 cipher suite, or a `PinSha256` config is missing
    /// its pin).
    #[error("hysteria2: TLS configuration error")]
    Tls,
    /// A QUIC-level error occurred during connect or stream I/O.
    #[error("hysteria2: QUIC connection error: {0}")]
    Quic(#[from] quinn::ConnectionError),
    /// An OS / socket I/O error occurred (binding the UDP socket, wrapping the obfs socket, or
    /// reading/writing the auth stream).
    #[error("hysteria2: I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// The `/auth` request could not be encoded or its response could not be decoded.
    #[error("hysteria2: auth frame codec error")]
    Codec,
}

/// Convert a configured downlink rate in Mbps to the bytes-per-second value Hysteria 2 carries in
/// the `Hysteria-CC-RX` header. `0` is passed through unchanged: per the protocol it means "rate
/// unknown", which tells the server to use BBR congestion control instead of a fixed Brutal rate.
fn rx_bps(down_mbps: u32) -> u64 {
    (down_mbps as u64) * 125_000
}

/// Lowercase-hex encode `bytes` without pulling in a `hex` dependency. Used only to render a
/// 32-byte SHA-256 certificate digest into the 64-char string compared against the configured pin.
fn to_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Normalize a configured SHA-256 pin for comparison: drop ASCII whitespace and `:` separators
/// (Hysteria/sing-box conventionally write pins as colon-separated hex) and lowercase. The result
/// is compared against the lowercase-hex digest of the server's leaf certificate.
fn normalize_pin(pin: &str) -> String {
    pin.chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != ':')
        .flat_map(|c| c.to_lowercase())
        .collect()
}

/// A [`ServerCertVerifier`] that accepts any certificate. Used only for `Hysteria2TlsMode::Insecure`
/// (e.g. self-signed test servers). It defeats TLS authentication entirely and must never be the
/// default — `Hysteria2TlsMode` defaults to `SystemRoots`.
#[derive(Debug)]
struct InsecureVerifier {
    /// The ring provider's signature schemes, advertised in `supported_verify_schemes` so the
    /// handshake offers schemes the (ignored) signature checks would nominally support.
    supported: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}

/// A [`ServerCertVerifier`] that pins the end-entity certificate by its SHA-256 fingerprint.
///
/// `verify_server_cert` ignores the chain-to-trust-anchor question entirely and instead requires
/// the leaf certificate's SHA-256 to equal the configured pin. The handshake-signature checks are
/// still performed properly (against the pinned cert's public key) using the ring provider's
/// algorithms, so a pinned connection is not downgraded to "accept any signature".
#[derive(Debug)]
struct PinVerifier {
    /// Normalized (no separators, lowercase) hex of the expected leaf-certificate SHA-256.
    pin_hex: String,
    /// The ring provider's signature-verification algorithms, used to verify the handshake
    /// signatures against the pinned certificate.
    supported: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let digest = ring::digest::digest(&ring::digest::SHA256, end_entity.as_ref());
        let got = to_hex_lower(digest.as_ref());
        if got.eq_ignore_ascii_case(&self.pin_hex) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}

/// Build the dangerous certificate verifier for the `PinSha256` / `Insecure` TLS modes.
///
/// `PinSha256` requires `tls.pin_sha256` to be set; a missing pin is a configuration error
/// ([`Hysteria2Error::Tls`]). For `SystemRoots` this returns `Tls` as well — system-roots
/// verification goes through rustls' built-in webpki verifier, not a custom one, so this is
/// only called for the two dangerous modes.
fn make_verifier(tls: &Hysteria2Tls) -> Result<Arc<dyn ServerCertVerifier>, Hysteria2Error> {
    let supported = ring_provider::default_provider().signature_verification_algorithms;
    match tls.mode {
        Hysteria2TlsMode::Insecure => Ok(Arc::new(InsecureVerifier { supported })),
        Hysteria2TlsMode::PinSha256 => {
            let pin = tls.pin_sha256.as_deref().ok_or(Hysteria2Error::Tls)?;
            let pin_hex = normalize_pin(pin);
            // A SHA-256 pin is exactly 32 bytes = 64 hex chars. Validate here so a malformed pin is a
            // clear config error rather than a confusing TLS handshake failure later.
            if pin_hex.len() != 64 || !pin_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(Hysteria2Error::Tls);
            }
            Ok(Arc::new(PinVerifier { pin_hex, supported }))
        }
        Hysteria2TlsMode::SystemRoots => Err(Hysteria2Error::Tls),
    }
}

/// Build the rustls [`ClientConfig`](rustls::ClientConfig) for a Hysteria 2 connection.
///
/// Always uses the ring crypto provider and restricts to TLS 1.3 (QUIC requires it, and quinn's
/// `QuicClientConfig::try_from` rejects any config that admits TLS 1.2). The trust model follows
/// `cfg.tls.mode`:
/// - `SystemRoots`: Mozilla's compiled-in CA bundle (`webpki-roots`).
/// - `PinSha256`: a custom verifier pinning the leaf certificate's SHA-256.
/// - `Insecure`: a custom verifier that accepts any certificate.
///
/// The ALPN is set to `h3`, which Hysteria 2 reuses.
fn rustls_client_config(cfg: &Hysteria2Config) -> Result<rustls::ClientConfig, Hysteria2Error> {
    let provider = Arc::new(ring_provider::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| Hysteria2Error::Tls)?;

    let mut config = match cfg.tls.mode {
        Hysteria2TlsMode::SystemRoots => {
            let root_store = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            builder
                .with_root_certificates(root_store)
                .with_no_client_auth()
        }
        Hysteria2TlsMode::PinSha256 | Hysteria2TlsMode::Insecure => builder
            .dangerous()
            .with_custom_certificate_verifier(make_verifier(&cfg.tls)?)
            .with_no_client_auth(),
    };

    config.alpn_protocols = vec![b"h3".to_vec()];
    Ok(config)
}

/// Open a QUIC connection to `server`, applying the obfuscation layer when `cfg.obfs` is set.
///
/// The data-plane UDP socket is created via [`protected_udp_socket`], so when a [`SocketProtector`]
/// is supplied the socket is pinned to the physical interface and its QUIC packets bypass the tunnel
/// route (otherwise the tunnel would capture the transport's own traffic and loop).
///
/// The returned [`quinn::Connection`] is not yet authenticated — the caller must invoke
/// [`authenticate`] before proxying. The connection's UDP endpoint is kept alive internally by
/// quinn (the spawned endpoint driver holds a strong reference to the `EndpointRef`, and the
/// `Connection` shares it), so this returns only the `Connection`; dropping the local `Endpoint`
/// handle does not tear down the live connection.
async fn connect(
    cfg: &Hysteria2Config,
    server: SocketAddr,
    protector: Option<&SocketProtector>,
) -> Result<quinn::Connection, Hysteria2Error> {
    let tls = rustls_client_config(cfg)?;
    let quic =
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(|_| Hysteria2Error::Tls)?;
    let client_config = quinn::ClientConfig::new(Arc::new(quic));

    // A UDP socket bound to 0.0.0.0:0 (family from `server`), pinned to the physical interface when a
    // protector is set so the QUIC data plane bypasses the tunnel route. Already non-blocking, as both
    // `quinn::Endpoint::new` and `tokio::net::UdpSocket::from_std` require.
    let udp: std::net::UdpSocket = protected_udp_socket(server, protector)
        .map_err(Hysteria2Error::Io)?
        .into();

    let mut endpoint = match &cfg.obfs {
        Some(o) => {
            let tokio_udp = tokio::net::UdpSocket::from_std(udp).map_err(Hysteria2Error::Io)?;
            let sock = obfs::SalamanderGeckoSocket::new(
                tokio_udp,
                o.password.clone().into_bytes(),
                o.gecko,
            )
            .map_err(Hysteria2Error::Io)?;
            quinn::Endpoint::new_with_abstract_socket(
                quinn::EndpointConfig::default(),
                None,
                Arc::new(sock),
                Arc::new(quinn::TokioRuntime),
            )
            .map_err(Hysteria2Error::Io)?
        }
        None => quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            udp,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(Hysteria2Error::Io)?,
    };
    endpoint.set_default_client_config(client_config);

    let sni = cfg.sni.clone().unwrap_or_else(|| server.ip().to_string());
    let conn = endpoint
        .connect(server, &sni)
        .map_err(|_| Hysteria2Error::Connect)?
        .await
        .map_err(Hysteria2Error::Quic)?;
    Ok(conn)
}

/// Run the Hysteria 2 `/auth` handshake over `conn`, returning whether the server relays UDP.
///
/// Opens a bidirectional QUIC stream, sends the HTTP/3 `POST /auth` request (with the credential
/// and advertised downlink rate), reads the response, and checks the `:status`. A status of `233`
/// is success; anything else is [`Hysteria2Error::Auth`]. The returned `bool` is the server's
/// `Hysteria-UDP` capability (default `true` when the header is absent). Must be called once,
/// immediately after [`connect`], before any proxy stream is opened.
async fn authenticate(
    conn: &quinn::Connection,
    cfg: &Hysteria2Config,
) -> Result<bool, Hysteria2Error> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(Hysteria2Error::Quic)?;

    let padding = auth::random_padding().map_err(Hysteria2Error::Io)?;
    let frame = auth::encode_auth_request(&cfg.auth, rx_bps(cfg.down_mbps), &padding);
    send.write_all(&frame)
        .await
        .map_err(|e| Hysteria2Error::Io(e.into()))?;
    send.finish().map_err(|e| Hysteria2Error::Io(e.into()))?;

    let resp = recv
        .read_to_end(64 * 1024)
        .await
        .map_err(|e| Hysteria2Error::Io(std::io::Error::other(e)))?;
    let parsed = auth::decode_auth_response(&resp).map_err(|_| Hysteria2Error::Codec)?;
    if parsed.status != 233 {
        return Err(Hysteria2Error::Auth(parsed.status));
    }
    Ok(parsed.udp)
}

/// Read exactly `buf.len()` bytes from `r` into `buf`, mapping any error to [`io::Error`].
///
/// Generic over the reader so that, inside this function, `read_exact` resolves to tokio's
/// [`AsyncReadExt::read_exact`] (with `io::Error` semantics) rather than quinn's inherent
/// `RecvStream::read_exact` (which returns `ReadExactError`). Callers pass `&mut RecvStream`,
/// which works because `RecvStream: tokio::io::AsyncRead`.
async fn read_exact<R: tokio::io::AsyncRead + Unpin>(r: &mut R, buf: &mut [u8]) -> io::Result<()> {
    r.read_exact(buf).await.map(|_| ())
}

/// Read and discard one varint-length-prefixed blob from `r`: a QUIC varint giving the byte
/// length, followed by that many bytes.
///
/// Used to skip the message and padding fields of a Hysteria 2 `TCPResponse`. The discard is
/// chunked through a fixed scratch buffer so a hostile or corrupt length cannot drive an
/// unbounded allocation; an oversized length simply reads until the stream ends (yielding an
/// `UnexpectedEof`). Generic over `R` for the same reason as [`read_exact`].
async fn drain_varint_blob<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> io::Result<()> {
    // Decode the QUIC varint length: the first byte's top 2 bits give the encoded width 2^n; the
    // remaining bytes are big-endian (matches `tcp::read_varint`).
    let mut first = [0u8; 1];
    read_exact(r, &mut first).await?;
    let len = 1usize << (first[0] >> 6);
    let mut value = (first[0] & 0x3f) as u64;
    if len > 1 {
        let mut rest = [0u8; 7];
        read_exact(r, &mut rest[..len - 1]).await?;
        for &b in &rest[..len - 1] {
            value = (value << 8) | b as u64;
        }
    }

    // Discard `value` bytes in bounded chunks so a garbage length can't allocate unboundedly.
    let mut remaining = value;
    let mut scratch = [0u8; 4096];
    while remaining > 0 {
        let take = remaining.min(scratch.len() as u64) as usize;
        read_exact(r, &mut scratch[..take]).await?;
        remaining -= take as u64;
    }
    Ok(())
}

/// Maps a live UDP `session_id` to its per-association delivery channel.
///
/// A `std::sync::Mutex` (not a tokio one): it is locked only for the brief insert/lookup/remove/
/// clone windows and the guard is always dropped before any `.await`. The delivery itself is a
/// synchronous `try_send` on the cloned [`Sender`](tokio::sync::mpsc::Sender), so no guard is ever
/// held across an await (project HARD RULE).
type SessionMap =
    std::sync::Mutex<std::collections::HashMap<u32, tokio::sync::mpsc::Sender<Vec<u8>>>>;

/// Per-connection shared state for a single authenticated Hysteria 2 QUIC connection.
///
/// Holds the connection, the server's UDP capability (from the `/auth` `Hysteria-UDP` header), the
/// live UDP session registry, and the datagram receive-pump task. The pump's [`JoinHandle`] is
/// owned here and aborted on drop, so the pump's lifetime is tied to this state (project rule: a
/// spawned task's handle must be stored somewhere that can cancel it).
///
/// [`JoinHandle`]: tokio::task::JoinHandle
struct ConnState {
    /// The authenticated QUIC connection (a cheap, clonable `Arc` handle).
    conn: quinn::Connection,
    /// Whether the server relays UDP (the `/auth` `Hysteria-UDP` header).
    udp_ok: bool,
    /// `session_id -> delivery channel` for every live UDP association on this connection.
    sessions: Arc<SessionMap>,
    /// The datagram receive pump; aborted when this state is dropped.
    pump: tokio::task::JoinHandle<()>,
}

impl Drop for ConnState {
    fn drop(&mut self) {
        // Tie the pump's lifetime to the connection state: once the cached state is replaced or
        // dropped, the pump (which borrows nothing else) is cancelled.
        self.pump.abort();
    }
}

/// The datagram receive pump for one connection: reads QUIC datagrams, reassembles fragmented
/// UDPMessages, and routes each completed payload to its session's delivery channel.
///
/// Runs as a spawned task owned by [`ConnState`] (aborted on drop). The [`UdpReassembler`] is owned
/// solely by this loop — no sharing, no lock. Unknown/closed sessions and full channels are dropped
/// silently (UDP is lossy); the loop ends when `read_datagram` errors (the connection closed).
///
/// [`UdpReassembler`]: udp::UdpReassembler
async fn udp_receive_pump(conn: quinn::Connection, sessions: Arc<SessionMap>) {
    let mut reasm = udp::UdpReassembler::new();
    // The loop ends when `read_datagram` errors (the connection closed): no more datagrams arrive.
    while let Ok(bytes) = conn.read_datagram().await {
        let Some(msg) = udp::decode_udp_message(&bytes) else {
            continue;
        };
        let sid = msg.session_id;
        if let Some(payload) = reasm.accept(msg) {
            // Clone the Sender under the lock, then drop the guard before `try_send`.
            let tx = match sessions.lock() {
                Ok(m) => m.get(&sid).cloned(),
                Err(p) => p.into_inner().get(&sid).cloned(),
            };
            if let Some(tx) = tx {
                // Drop the datagram if the channel is full or its source was dropped.
                let _ = tx.try_send(payload);
            }
        }
    }
}

/// A [`Transport`]/[`UdpTransport`] over a single Hysteria 2 QUIC connection: one bidirectional
/// stream per dialed TCP target, and QUIC datagrams (multiplexed by session id) for UDP.
///
/// The connection is cached as an [`Arc<ConnState>`] and reused across dials; a dropped or closed
/// connection is transparently re-established on the next dial via [`connect`] + [`authenticate`]
/// (which also spawns a fresh datagram receive pump). Replacing the cached state drops the old
/// [`ConnState`], aborting its pump.
pub struct Hysteria2Transport {
    cfg: Hysteria2Config,
    server: SocketAddr,
    /// Pins the QUIC data-plane socket to a physical interface so its packets bypass the tunnel
    /// route. `None` leaves the socket on the default route.
    protector: Option<SocketProtector>,
    /// The cached, authenticated connection state, or `None` before the first dial / after teardown.
    /// Guarded by a tokio mutex held only for the brief check/store windows — never across the
    /// `connect`/`authenticate` awaits (see [`Self::connection`]).
    conn: tokio::sync::Mutex<Option<Arc<ConnState>>>,
}

impl Hysteria2Transport {
    /// Build a transport for `cfg` against `server`, optionally pinning the QUIC socket to a physical
    /// interface via `protector`. No connection is opened until the first dial.
    pub fn new(
        cfg: Hysteria2Config,
        server: SocketAddr,
        protector: Option<SocketProtector>,
    ) -> Self {
        Self {
            cfg,
            server,
            protector,
            conn: tokio::sync::Mutex::new(None),
        }
    }

    /// Return live, authenticated connection state, reusing the cached one when possible.
    ///
    /// Double-checked locking keeps the mutex guard out of every `.await`: the guard is taken in a
    /// small block that ends before the (un-guarded) `connect`/`authenticate` awaits, and a fresh
    /// guard is taken afterward to store the result — re-checking so state another task built
    /// concurrently wins (our freshly built one is then dropped, aborting its pump).
    async fn connection(&self) -> Result<Arc<ConnState>, Hysteria2Error> {
        // Fast path: a live cached connection. Guard dropped at the end of this block.
        {
            let guard = self.conn.lock().await;
            if let Some(state) = guard.as_ref() {
                if state.conn.close_reason().is_none() {
                    return Ok(state.clone());
                }
            }
        }

        // Slow path: build a new connection with NO guard held across these awaits.
        let c = connect(&self.cfg, self.server, self.protector.as_ref()).await?;
        let udp_ok = authenticate(&c, &self.cfg).await?;
        let sessions: Arc<SessionMap> = Arc::new(std::sync::Mutex::new(Default::default()));
        let pump = tokio::spawn(udp_receive_pump(c.clone(), sessions.clone()));
        let state = Arc::new(ConnState {
            conn: c,
            udp_ok,
            sessions,
            pump,
        });

        // Re-lock and re-check: prefer a live connection another task installed meanwhile (our
        // freshly built `state` is then dropped, aborting its just-spawned pump).
        let mut guard = self.conn.lock().await;
        if let Some(existing) = guard.as_ref() {
            if existing.conn.close_reason().is_none() {
                return Ok(existing.clone());
            }
        }
        *guard = Some(state.clone());
        Ok(state)
    }
}

#[async_trait]
impl Transport for Hysteria2Transport {
    async fn dial(&self, target: SocketAddr) -> io::Result<BoxedStream> {
        let state = self.connection().await.map_err(io::Error::other)?;
        let conn = state.conn.clone();
        let (mut send, mut recv) = conn.open_bi().await.map_err(io::Error::other)?;

        // Send the TCPRequest. `write_all` here is quinn's inherent `SendStream::write_all`
        // (returning `WriteError`), shadowing tokio's extension method — map its error explicitly.
        send.write_all(&tcp::encode_tcp_request(&target.to_string()))
            .await
            .map_err(io::Error::other)?;

        // Read the TCPResponse: a status byte (0x00 = OK), then a varint-prefixed message and a
        // varint-prefixed padding block, both discarded. All reads route through the generic
        // helpers so tokio's `io::Error`-returning `read_exact` is used, not quinn's inherent one.
        let mut status = [0u8; 1];
        read_exact(&mut recv, &mut status).await?;
        if status[0] != 0x00 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "hysteria2 TCP error status",
            ));
        }
        drain_varint_blob(&mut recv).await?; // message
        drain_varint_blob(&mut recv).await?; // padding

        // Pair the recv (AsyncRead) and send (AsyncWrite) halves into one bidirectional stream.
        Ok(Box::new(tokio::io::join(recv, send)))
    }
}

#[async_trait]
impl UdpTransport for Hysteria2Transport {
    async fn dial_udp(
        &self,
        target: SocketAddr,
    ) -> io::Result<(BoxedPacketSink, BoxedPacketSource)> {
        let state = self.connection().await.map_err(io::Error::other)?;
        // Honor both the server's `Hysteria-UDP` capability AND the QUIC datagram extension: a
        // `max_datagram_size` of `None` means the peer never enabled datagrams, so UDP relay is
        // impossible. Either condition is a hard "unsupported".
        let max_datagram = match (state.udp_ok, state.conn.max_datagram_size()) {
            (true, Some(n)) => n,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "hysteria2 server did not enable UDP relay",
                ))
            }
        };

        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
        // Register the delivery channel under a fresh, collision-free 32-bit session id (the id keys
        // this association in the receive pump's registry). Retrying on the astronomically unlikely
        // clash avoids overwriting — and silently hijacking — a live association's channel. All
        // synchronous: the guard is never held across an `.await`.
        let session_id = {
            let mut sessions = match state.sessions.lock() {
                Ok(m) => m,
                Err(p) => p.into_inner(),
            };
            let mut sid_bytes = [0u8; 4];
            loop {
                ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut sid_bytes)
                    .map_err(|_| io::Error::other("hysteria2 UDP: rng failure"))?;
                let candidate = u32::from_be_bytes(sid_bytes);
                if let std::collections::hash_map::Entry::Vacant(e) = sessions.entry(candidate) {
                    e.insert(tx);
                    break candidate;
                }
            }
        };

        let sink = Hysteria2UdpSink {
            conn: state.conn.clone(),
            session_id,
            target: target.to_string(),
            packet_id: 0,
            max_datagram,
        };
        let source = Hysteria2UdpSource {
            rx,
            sessions: state.sessions.clone(),
            session_id,
        };
        Ok((Box::new(sink), Box::new(source)))
    }
}

/// The send half of a Hysteria 2 UDP association: encodes each datagram as one or more UDPMessage
/// fragments and ships them as QUIC datagrams.
///
/// `packet_id` is a per-association wrapping counter; `send` is `&mut self`, so a plain `u16`
/// suffices (no atomics). A datagram the codec cannot represent (no room for payload, or >255
/// fragments) yields an empty fragment list — `send` then sends nothing and returns `Ok`, the
/// intended drop behavior.
struct Hysteria2UdpSink {
    conn: quinn::Connection,
    session_id: u32,
    target: String,
    packet_id: u16,
    max_datagram: usize,
}

#[async_trait]
impl PacketSink for Hysteria2UdpSink {
    async fn send(&mut self, payload: &[u8]) -> io::Result<()> {
        let pid = self.packet_id;
        self.packet_id = self.packet_id.wrapping_add(1);
        for frag in udp::encode_udp_message(
            self.session_id,
            pid,
            &self.target,
            payload,
            self.max_datagram,
        ) {
            self.conn
                .send_datagram(bytes::Bytes::from(frag))
                .map_err(io::Error::other)?;
        }
        Ok(())
    }
}

/// The receive half of a Hysteria 2 UDP association: yields reassembled payloads the connection's
/// receive pump routed to this session's channel.
///
/// On drop it de-registers its `session_id` from the shared [`SessionMap`] so the pump stops
/// holding a stale [`Sender`](tokio::sync::mpsc::Sender) for a closed association.
struct Hysteria2UdpSource {
    rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    sessions: Arc<SessionMap>,
    session_id: u32,
}

#[async_trait]
impl PacketSource for Hysteria2UdpSource {
    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.rx.recv().await {
            Some(payload) => {
                // UDP truncation: copy what fits, drop the excess, but consume the whole datagram.
                let n = payload.len().min(buf.len());
                buf[..n].copy_from_slice(&payload[..n]);
                Ok(n)
            }
            None => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "hysteria2 UDP association closed",
            )),
        }
    }
}

impl Drop for Hysteria2UdpSource {
    fn drop(&mut self) {
        // De-register this session, recovering a poisoned lock (consistent with the rest of the
        // module) so a stale entry can't linger and keep the pump routing to a dead channel.
        let mut m = match self.sessions.lock() {
            Ok(m) => m,
            Err(p) => p.into_inner(),
        };
        m.remove(&self.session_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn drain_varint_blob_consumes_one_byte_blob_and_leaves_trailer() {
        // 1-byte varint length 3, then 3 payload bytes, then a trailer the drain must NOT touch.
        let buf = [0x03u8, 0xaa, 0xbb, 0xcc, b'X', b'Y', b'Z'];
        let mut r: &[u8] = &buf;
        drain_varint_blob(&mut r).await.expect("drain succeeds");
        // The reader is now positioned at the trailer.
        assert_eq!(r, b"XYZ");
    }

    #[tokio::test]
    async fn drain_varint_blob_handles_two_byte_varint_length() {
        // 2-byte varint length 200 (>= 64, so encoded as 0x4000 | 200), then 200 payload bytes.
        let mut buf = Vec::new();
        tcp::write_varint(&mut buf, 200);
        assert_eq!(buf.len(), 2, "200 must encode as a 2-byte QUIC varint");
        buf.extend(std::iter::repeat_n(0x5a, 200));
        buf.extend_from_slice(b"tail");
        let mut r: &[u8] = &buf;
        drain_varint_blob(&mut r).await.expect("drain succeeds");
        assert_eq!(r, b"tail");
    }

    #[tokio::test]
    async fn drain_varint_blob_handles_empty_blob() {
        // 1-byte varint length 0: nothing to discard; the trailer remains.
        let buf = [0x00u8, b'a', b'b'];
        let mut r: &[u8] = &buf;
        drain_varint_blob(&mut r).await.expect("drain succeeds");
        assert_eq!(r, b"ab");
    }

    #[tokio::test]
    async fn drain_varint_blob_errors_on_truncation() {
        // 1-byte varint length 5, but only 2 payload bytes present → unexpected EOF.
        let buf = [0x05u8, 0x01, 0x02];
        let mut r: &[u8] = &buf;
        assert!(drain_varint_blob(&mut r).await.is_err());
    }

    #[test]
    fn rx_bps_converts_mbps_to_bytes_per_second() {
        assert_eq!(rx_bps(0), 0); // 0 = "unknown" → server uses BBR
        assert_eq!(rx_bps(1), 125_000);
        assert_eq!(rx_bps(100), 12_500_000);
    }

    #[test]
    fn normalize_pin_strips_separators_and_lowercases() {
        assert_eq!(normalize_pin("BA:88:45"), "ba8845");
        assert_eq!(normalize_pin("ba 88\t45\n"), "ba8845");
        assert_eq!(normalize_pin("BA8845"), "ba8845");
        assert_eq!(normalize_pin(""), "");
    }

    #[test]
    fn auth_error_display_includes_status() {
        let msg = Hysteria2Error::Auth(403).to_string();
        assert!(!msg.is_empty());
        assert!(
            msg.contains("403"),
            "expected status in message, got: {msg}"
        );
    }

    #[tokio::test]
    async fn udp_source_delivers_truncates_and_deregisters_on_drop() {
        // A shared registry with this session registered, so the Drop dedup has something to remove.
        let session_id = 0x1234_5678u32;
        let sessions: Arc<SessionMap> = Arc::new(std::sync::Mutex::new(Default::default()));
        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4);
        sessions
            .lock()
            .expect("lock")
            .insert(session_id, tx.clone());

        let mut source = Hysteria2UdpSource {
            rx,
            sessions: sessions.clone(),
            session_id,
        };

        // A datagram that fits the buffer is copied verbatim.
        tx.try_send(b"hello".to_vec()).expect("send fits");
        let mut buf = [0u8; 16];
        let n = source.recv(&mut buf).await.expect("recv");
        assert_eq!(n, 5);
        assert_eq!(&buf[..n], b"hello");

        // A datagram longer than the buffer truncates to buf.len(), consuming the whole datagram.
        tx.try_send(vec![0xabu8; 32]).expect("send big");
        let mut small = [0u8; 8];
        let n = source.recv(&mut small).await.expect("recv truncated");
        assert_eq!(n, 8, "recv must truncate to the buffer length");
        assert_eq!(&small, &[0xab; 8]);

        // Dropping the source de-registers its session id from the shared registry.
        assert!(
            sessions.lock().expect("lock").contains_key(&session_id),
            "session must be registered before drop"
        );
        drop(source);
        assert!(
            !sessions.lock().expect("lock").contains_key(&session_id),
            "Drop must de-register the session id"
        );
    }
}
