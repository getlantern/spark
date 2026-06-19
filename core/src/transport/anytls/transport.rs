//! The AnyTLS [`Transport`] (feature `anytls`, ADR 0001): dial targets through pooled AnyTLS
//! sessions over BoringSSL TLS to the configured server.
//!
//! **Session pool + reconnect** (anytls-go's model): sessions are reused across dials (one TLS
//! connection multiplexes many streams), dead sessions are evicted and replaced (reconnect), and a
//! background sweep drops idle sessions beyond a warm minimum. Each dial reuses the newest healthy
//! session under a per-session stream cap, opening a fresh one only when none fits.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::BytesMut;
use tokio::io::AsyncWriteExt;
use tokio::task::JoinHandle;

use crate::net::SocketProtector;
use crate::transport::shaping::{SegmentShapingStream, WirePlan};
use crate::transport::tcp_tunnel::header::Address;
use crate::transport::{
    protected_tcp_connect, BoxedPacketSink, BoxedPacketSource, Transport, UdpTransport,
};
use crate::BoxedStream;

use super::{tls, udp, PaddingScheme, Session};

/// Open a new session once a session is carrying this many streams (spreads load / bounds HOL).
const MAX_STREAMS_PER_SESSION: usize = 64;
/// How often the idle-session sweep runs.
const IDLE_SWEEP_INTERVAL: Duration = Duration::from_secs(30);
/// Idle (zero-stream) sessions kept warm as spares; extras are swept.
const MIN_IDLE_SESSIONS: usize = 1;

/// An AnyTLS client transport over a pool of shared sessions.
pub struct AnytlsTransport {
    inner: Arc<Inner>,
    sweep: JoinHandle<()>,
}

struct Inner {
    server: SocketAddr,
    password: String,
    sni: String,
    protector: Option<SocketProtector>,
    /// Opening-handshake shaping for each new TLS connection (ADR 0006 Phase 1).
    wire: WirePlan,
    pool: Mutex<Vec<Arc<Session>>>,
}

impl AnytlsTransport {
    /// Build a transport dialing `server` (TLS SNI `sni`), authenticating with `password`. Upstream
    /// dials are pinned to `protector`'s interface so they bypass the tunnel route. Spawns the idle
    /// sweep (must be called within a tokio runtime).
    pub fn new(
        server: SocketAddr,
        password: String,
        sni: String,
        protector: Option<SocketProtector>,
        wire: WirePlan,
    ) -> Self {
        let inner = Arc::new(Inner {
            server,
            password,
            sni,
            protector,
            wire,
            pool: Mutex::new(Vec::new()),
        });
        let sweep = tokio::spawn(sweep_loop(Arc::clone(&inner)));
        Self { inner, sweep }
    }
}

impl Drop for AnytlsTransport {
    fn drop(&mut self) {
        self.sweep.abort();
    }
}

impl Inner {
    /// A session to open a stream on: reuse the newest healthy, non-full one; otherwise establish a
    /// fresh one (reconnect). Dead sessions are evicted under the lock; the TLS handshake for a new
    /// session happens **without** the lock held.
    async fn acquire(&self) -> io::Result<Arc<Session>> {
        {
            let mut pool = self.pool.lock().unwrap_or_else(|e| e.into_inner());
            pool.retain(|s| s.is_alive());
            if let Some(s) = pool
                .iter()
                .rev()
                .find(|s| s.active_streams() < MAX_STREAMS_PER_SESSION)
            {
                return Ok(Arc::clone(s));
            }
        }
        // No reusable session — connect a new one (no lock held across the handshake).
        let tcp = protected_tcp_connect(self.server, self.protector.as_ref()).await?;
        if self.wire.tcp_nodelay {
            let _ = tcp.set_nodelay(true); // so each shaped segment leaves as its own packet
        }
        // Shape the opening write (the ClientHello) — e.g. fragment it across the SNI boundary —
        // by sitting between boring and the socket (ADR 0006 Phase 1).
        let shaped = SegmentShapingStream::new(tcp, self.wire.clone());
        let tls = tls::connect(shaped, &self.sni).await?;
        let session = Arc::new(Session::client(
            tls,
            &self.password,
            PaddingScheme::default(),
        ));
        let mut pool = self.pool.lock().unwrap_or_else(|e| e.into_inner());
        pool.push(Arc::clone(&session));
        Ok(session)
    }
}

/// Periodically evict dead sessions and drop idle ones beyond [`MIN_IDLE_SESSIONS`]. Busy sessions
/// (open streams) are always kept; a dropped idle session's tasks abort and its connection closes.
async fn sweep_loop(inner: Arc<Inner>) {
    let mut tick = tokio::time::interval(IDLE_SWEEP_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let mut pool = inner.pool.lock().unwrap_or_else(|e| e.into_inner());
        let mut idle_kept = 0;
        let mut kept = Vec::with_capacity(pool.len());
        // Newest first: keep all busy + alive sessions, plus up to MIN_IDLE idle spares.
        for s in pool.drain(..).rev() {
            if !s.is_alive() {
                continue; // dead → drop
            }
            if s.active_streams() > 0 {
                kept.push(s);
            } else if idle_kept < MIN_IDLE_SESSIONS {
                idle_kept += 1;
                kept.push(s);
            } // else: idle beyond the warm minimum → drop (closes its connection)
        }
        kept.reverse();
        *pool = kept;
    }
}

#[async_trait]
impl Transport for AnytlsTransport {
    async fn dial(&self, target: SocketAddr) -> io::Result<BoxedStream> {
        let session = self.inner.acquire().await?;
        let mut stream = session.open_stream().await?;
        // AnyTLS choreography: the target address is the stream's first bytes (SOCKS5 grammar),
        // which also flushes the buffered cmdSettings+cmdSYN as padded packet 1.
        let mut addr = BytesMut::new();
        Address::Ip(target).encode(&mut addr);
        stream.write_all(&addr).await?;
        Ok(Box::new(stream))
    }
}

#[async_trait]
impl UdpTransport for AnytlsTransport {
    async fn dial_udp(
        &self,
        target: SocketAddr,
    ) -> io::Result<(BoxedPacketSink, BoxedPacketSource)> {
        // A UDP association is just another pooled stream, opened to the UoT v2 magic address.
        let session = self.inner.acquire().await?;
        let stream = session.open_stream().await?;
        udp::associate(stream, target).await
    }
}
