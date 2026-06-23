//! The Samizdat [`Transport`] (ADR 0007): one Chrome-fingerprinted TLS session per server
//! connection, REALITY auth in the ClientHello `legacy_session_id`, and proxied flows multiplexed
//! as HTTP/2 CONNECT streams. Ties together [`auth`], [`session_id`], and [`super::h2_mux`], reusing
//! the AnyTLS boring connector ([`flint_tls::configure`]) for the Chrome hello.
//!
//! TCP via H2 CONNECT; UDP via sing-box **UDP-over-TCP v2** over a CONNECT stream whose `:authority`
//! is the UoT magic address (shared [`crate::transport::uot`] framing, same as AnyTLS).

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::net::SocketProtector;
use crate::transport::uot::{self, UOT_MAGIC};
use crate::transport::{
    protected_tcp_connect, BoxedPacketSink, BoxedPacketSource, BoxedStream, Transport, UdpTransport,
};
use flint_shaping::{SegmentShapingStream, WirePlan};
use flint_tls::Profile;

use super::auth;
use super::h2_mux::H2Conn;
use super::session_id;

/// A Samizdat client. Holds one lazily-established, shared HTTP/2 connection that multiplexes all
/// CONNECT tunnels (reconnected reactively when a dial finds it dead). A multi-connection pool is a
/// follow-up (mirroring `AnytlsTransport`).
pub struct SamizdatTransport {
    server: SocketAddr,
    server_pubkey: [u8; 32],
    short_id: [u8; 8],
    sni: String,
    profile: Profile,
    /// Opening-handshake shaping for each new TLS connection (ADR 0006 Phase 1): fragment the
    /// ClientHello across TCP segments (Samizdat's Geneva-style fragmentation). A default plan is a
    /// no-op, so this is opt-in via `[transport.shaping]`.
    wire: WirePlan,
    protector: Option<SocketProtector>,
    conn: Mutex<Option<Arc<H2Conn>>>,
}

impl SamizdatTransport {
    /// Build a Samizdat transport. The Chrome ClientHello profile is the default (Chrome-137) anchor;
    /// no connection is opened until the first [`dial`](Transport::dial).
    pub fn new(
        server: SocketAddr,
        server_pubkey: [u8; 32],
        short_id: [u8; 8],
        sni: String,
        wire: WirePlan,
        protector: Option<SocketProtector>,
    ) -> Self {
        Self {
            server,
            server_pubkey,
            short_id,
            sni,
            profile: Profile::default(),
            wire,
            protector,
            conn: Mutex::new(None),
        }
    }

    /// Establish a fresh TLS + HTTP/2 connection to the server: TCP → inject the auth SessionID into
    /// the Chrome ClientHello → TLS handshake → HTTP/2 handshake.
    async fn establish(&self) -> io::Result<Arc<H2Conn>> {
        let tcp = protected_tcp_connect(self.server, self.protector.as_ref()).await?;
        if self.wire.tcp_nodelay {
            // Best-effort: TCP_NODELAY keeps each shaped segment in its own packet (no Nagle
            // coalescing). The shaper flushes per segment regardless, so a failure only weakens the
            // effect — surface it rather than failing the dial over a non-fatal setsockopt error.
            if let Err(e) = tcp.set_nodelay(true) {
                tracing::warn!(error = %e, "samizdat: TCP_NODELAY not set; shaped segments may coalesce");
            }
        }
        let session_id_bytes = auth::session_id(&self.server_pubkey, &self.short_id)
            .map_err(|_| io::Error::other("samizdat: generating the auth SessionID failed"))?;
        let mut config = flint_tls::configure(&self.profile)?;
        session_id::inject_session_id(&mut config, &session_id_bytes)?;
        // Fragment the ClientHello across TCP segments per the wire plan (no-op by default).
        let shaped = SegmentShapingStream::new(tcp, self.wire.clone());
        let tls = tokio_boring2::connect(config, &self.sni, shaped)
            .await
            .map_err(|e| io::Error::other(format!("samizdat tls handshake: {e}")))?;
        if tls.ssl().selected_alpn_protocol() != Some(b"h2") {
            return Err(io::Error::other(
                "samizdat: server did not negotiate HTTP/2 (ALPN h2)",
            ));
        }
        Ok(Arc::new(H2Conn::handshake(tls).await?))
    }

    /// The shared connection, establishing one if absent. The TLS/H2 handshake runs **outside** the
    /// lock (never held across an `.await`); a racing establisher's connection is preferred.
    async fn conn(&self) -> io::Result<Arc<H2Conn>> {
        if let Some(existing) = self.locked().as_ref() {
            return Ok(existing.clone());
        }
        let fresh = self.establish().await?;
        let mut guard = self.locked();
        if let Some(existing) = guard.as_ref() {
            return Ok(existing.clone()); // another dial won the race
        }
        *guard = Some(fresh.clone());
        Ok(fresh)
    }

    /// Drop the cached connection if it is still `current`, so the next dial re-establishes.
    fn invalidate(&self, current: &Arc<H2Conn>) {
        let mut guard = self.locked();
        if guard.as_ref().is_some_and(|c| Arc::ptr_eq(c, current)) {
            *guard = None;
        }
    }

    /// Lock the connection slot, recovering from poisoning rather than panicking.
    fn locked(&self) -> std::sync::MutexGuard<'_, Option<Arc<H2Conn>>> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[async_trait]
impl Transport for SamizdatTransport {
    async fn dial(&self, target: SocketAddr) -> io::Result<BoxedStream> {
        // The CONNECT `:authority` is the original destination (an address — like spark's other
        // transports carry the target). Never logged: it's a destination.
        let authority = target.to_string();
        let conn = self.conn().await?;
        match conn.connect(&authority).await {
            Ok(stream) => Ok(Box::new(stream)),
            // A CONNECT rejection (non-200) is stream-level: the shared connection is healthy and
            // still serves other tunnels, and retrying a refused target won't help — surface it.
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => Err(e),
            // Any other error means the shared connection likely died — drop it and retry once on a
            // fresh one.
            Err(_) => {
                self.invalidate(&conn);
                let conn = self.conn().await?;
                Ok(Box::new(conn.connect(&authority).await?))
            }
        }
    }
}

#[async_trait]
impl UdpTransport for SamizdatTransport {
    async fn dial_udp(
        &self,
        target: SocketAddr,
    ) -> io::Result<(BoxedPacketSink, BoxedPacketSource)> {
        // UDP-over-stream via sing-box UoT v2 (the same framing AnyTLS uses): open a CONNECT stream
        // whose `:authority` is the UoT magic address, so the (sing-box) server switches that stream
        // into a UDP association, then run the shared UoT framing over the CONNECT body. The magic is
        // the *destination*, so it rides the authority here rather than in-band (see `transport::uot`).
        let authority = format!("{UOT_MAGIC}:0");
        let conn = self.conn().await?;
        let stream = match conn.connect(&authority).await {
            Ok(s) => s,
            // A CONNECT rejection is stream-level (the shared connection is fine); surface it.
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => return Err(e),
            // Otherwise the shared connection likely died — re-establish once and retry (mirrors `dial`).
            Err(_) => {
                self.invalidate(&conn);
                let conn = self.conn().await?;
                conn.connect(&authority).await?
            }
        };
        uot::associate(stream, target).await
    }
}

// UDP is exercised by the shared UoT framing tests in `crate::transport::uot`; samizdat's
// CONNECT-to-magic-authority path is covered by staging interop against a live sing-box server.
