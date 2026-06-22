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

use crate::transport::{BoxedStream, Transport};

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
            Ok(Arc::new(PinVerifier {
                pin_hex: normalize_pin(pin),
                supported,
            }))
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
/// The returned [`quinn::Connection`] is not yet authenticated — the caller must invoke
/// [`authenticate`] before proxying. The connection's UDP endpoint is kept alive internally by
/// quinn (the spawned endpoint driver holds a strong reference to the `EndpointRef`, and the
/// `Connection` shares it), so this returns only the `Connection`; dropping the local `Endpoint`
/// handle does not tear down the live connection.
async fn connect(
    cfg: &Hysteria2Config,
    server: SocketAddr,
) -> Result<quinn::Connection, Hysteria2Error> {
    let tls = rustls_client_config(cfg)?;
    let quic =
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(|_| Hysteria2Error::Tls)?;
    let client_config = quinn::ClientConfig::new(Arc::new(quic));

    let udp = std::net::UdpSocket::bind(("0.0.0.0", 0)).map_err(Hysteria2Error::Io)?;

    let mut endpoint = match &cfg.obfs {
        Some(o) => {
            // quinn-udp needs a non-blocking socket; tokio's `from_std` requires the same.
            udp.set_nonblocking(true).map_err(Hysteria2Error::Io)?;
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

/// Run the Hysteria 2 `/auth` handshake over `conn`.
///
/// Opens a bidirectional QUIC stream, sends the HTTP/3 `POST /auth` request (with the credential
/// and advertised downlink rate), reads the response, and checks the `:status`. A status of `233`
/// is success; anything else is [`Hysteria2Error::Auth`]. Must be called once, immediately after
/// [`connect`], before any proxy stream is opened.
async fn authenticate(
    conn: &quinn::Connection,
    cfg: &Hysteria2Config,
) -> Result<(), Hysteria2Error> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(Hysteria2Error::Quic)?;

    let frame = auth::encode_auth_request(&cfg.auth, rx_bps(cfg.down_mbps));
    send.write_all(&frame)
        .await
        .map_err(|e| Hysteria2Error::Io(e.into()))?;
    send.finish().map_err(|e| Hysteria2Error::Io(e.into()))?;

    let resp = recv
        .read_to_end(64 * 1024)
        .await
        .map_err(|e| Hysteria2Error::Io(std::io::Error::other(e)))?;
    let status = auth::decode_auth_status(&resp).map_err(|_| Hysteria2Error::Codec)?;
    if status != 233 {
        return Err(Hysteria2Error::Auth(status));
    }
    Ok(())
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

/// A [`Transport`] over a single Hysteria 2 QUIC connection, opening one bidirectional stream per
/// dialed TCP target.
///
/// The connection is cached (a [`quinn::Connection`] is a cheap, clonable `Arc` handle) and reused
/// across dials; a dropped or closed connection is transparently re-established on the next dial via
/// [`connect`] + [`authenticate`].
pub struct Hysteria2Transport {
    cfg: Hysteria2Config,
    server: SocketAddr,
    /// The cached, authenticated connection, or `None` before the first dial / after teardown.
    /// Guarded by a tokio mutex held only for the brief check/store windows — never across the
    /// `connect`/`authenticate` awaits (see [`Self::connection`]).
    conn: tokio::sync::Mutex<Option<quinn::Connection>>,
}

impl Hysteria2Transport {
    /// Build a transport for `cfg` against `server`. No connection is opened until the first dial.
    pub fn new(cfg: Hysteria2Config, server: SocketAddr) -> Self {
        Self {
            cfg,
            server,
            conn: tokio::sync::Mutex::new(None),
        }
    }

    /// Return a live, authenticated connection, reusing the cached one when possible.
    ///
    /// Double-checked locking keeps the mutex guard out of every `.await`: the guard is taken in a
    /// small block that ends before the (un-guarded) `connect`/`authenticate` awaits, and a fresh
    /// guard is taken afterward to store the result — re-checking so a connection another task built
    /// concurrently wins (our freshly built one is then dropped).
    async fn connection(&self) -> Result<quinn::Connection, Hysteria2Error> {
        // Fast path: a live cached connection. Guard dropped at the end of this block.
        {
            let guard = self.conn.lock().await;
            if let Some(c) = guard.as_ref() {
                if c.close_reason().is_none() {
                    return Ok(c.clone());
                }
            }
        }

        // Slow path: build a new connection with NO guard held across these awaits.
        let c = connect(&self.cfg, self.server).await?;
        authenticate(&c, &self.cfg).await?;

        // Re-lock and re-check: prefer a live connection another task installed meanwhile.
        let mut guard = self.conn.lock().await;
        if let Some(existing) = guard.as_ref() {
            if existing.close_reason().is_none() {
                return Ok(existing.clone());
            }
        }
        *guard = Some(c.clone());
        Ok(c)
    }
}

#[async_trait]
impl Transport for Hysteria2Transport {
    async fn dial(&self, target: SocketAddr) -> io::Result<BoxedStream> {
        let conn = self.connection().await.map_err(io::Error::other)?;
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
}
