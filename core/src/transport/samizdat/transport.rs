//! The Samizdat [`Transport`] (ADR 0007): one Chrome-fingerprinted TLS session per server
//! connection, REALITY auth in the ClientHello `legacy_session_id`, and proxied flows multiplexed
//! as HTTP/2 CONNECT streams. Ties together [`auth`], [`session_id`], and [`super::h2_mux`], reusing
//! the AnyTLS boring connector ([`crate::transport::anytls::tls::configure`]) for the Chrome hello.
//!
//! TCP only (v1). UDP is reported unsupported — see ADR 0007 §1 / the design doc §11.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::net::SocketProtector;
use crate::transport::anytls::profile::Profile;
use crate::transport::shaping::{SegmentShapingStream, WirePlan};
use crate::transport::{
    protected_tcp_connect, BoxedPacketSink, BoxedPacketSource, BoxedStream, Transport, UdpTransport,
};

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
            let _ = tcp.set_nodelay(true); // so each shaped segment leaves as its own packet
        }
        let session_id_bytes = auth::session_id(&self.server_pubkey, &self.short_id)
            .map_err(|_| io::Error::other("samizdat: generating the auth SessionID failed"))?;
        let mut config = crate::transport::anytls::tls::configure(&self.profile)?;
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
        _target: SocketAddr,
    ) -> io::Result<(BoxedPacketSink, BoxedPacketSource)> {
        // Samizdat is TCP-only (it proxies via HTTP/2 CONNECT). UDP-over-CONNECT would need server
        // support and is deferred (ADR 0007 §1, design §11).
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "samizdat: UDP is not supported (TCP-only transport)",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn udp_is_unsupported() {
        let t = SamizdatTransport::new(
            "192.0.2.1:443".parse().unwrap(),
            [0u8; 32],
            [0u8; 8],
            "cover.example".to_owned(),
            WirePlan::default(),
            None,
        );
        // The Ok tuple (boxed sink/source) isn't `Debug`, so match rather than `expect_err`.
        match t.dial_udp("192.0.2.2:53".parse().unwrap()).await {
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::Unsupported),
            Ok(_) => panic!("UDP must be unsupported"),
        }
    }
}
