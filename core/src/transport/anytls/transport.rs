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
use crate::transport::tcp_tunnel::header::Address;
use crate::transport::{
    protected_tcp_connect, BoxedPacketSink, BoxedPacketSource, Transport, UdpTransport,
};
use crate::BoxedStream;
use flint_shaping::{SegmentShapingStream, WirePlan};

use super::{udp, PaddingScheme, Session};
use flint_tls::Profile;

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
    /// Static gambit-resolved ClientHello/record knobs (ADR 0006 P2); also the fallback when a
    /// dynamic [`Inner::gambit_source`] faults or yields a gambit boring can't realize.
    profile: Profile,
    /// Optional Path-B module that **computes** a fresh gambit per connection (ADR 0006 P3). When
    /// present, each new TLS session resolves its [`Profile`] from this module instead of `profile`.
    /// `Mutex` because the `wasmi` `Transform` is `!Sync` and stateful (a gambit may be
    /// adaptive/stateful across connections); the lock is held only for the synchronous compute,
    /// never across the handshake `.await`.
    #[cfg(feature = "wasm-transport")]
    gambit_source: Option<Mutex<crate::transport::wasm::Transform>>,
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
        profile: Profile,
    ) -> Self {
        Self::spawn(Inner {
            server,
            password,
            sni,
            protector,
            wire,
            profile,
            #[cfg(feature = "wasm-transport")]
            gambit_source: None,
            pool: Mutex::new(Vec::new()),
        })
    }

    /// Like [`new`](Self::new) but with a Path-B `gambit` module that computes a fresh gambit per
    /// connection (ADR 0006 P3). `profile` is the fallback used when the module faults or its gambit
    /// exceeds boring's capabilities, so connectivity never depends on the dynamic gambit succeeding.
    #[cfg(feature = "wasm-transport")]
    pub fn with_dynamic_gambit(
        server: SocketAddr,
        password: String,
        sni: String,
        protector: Option<SocketProtector>,
        wire: WirePlan,
        profile: Profile,
        gambit: crate::transport::wasm::Transform,
    ) -> Self {
        Self::spawn(Inner {
            server,
            password,
            sni,
            protector,
            wire,
            profile,
            gambit_source: Some(Mutex::new(gambit)),
            pool: Mutex::new(Vec::new()),
        })
    }

    /// Wrap an [`Inner`] in the shared `Arc` and spawn its idle sweep (must run within a tokio
    /// runtime).
    fn spawn(inner: Inner) -> Self {
        let inner = Arc::new(inner);
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
        let profile = self.resolve_profile();
        let tls = flint_tls::connect(shaped, &self.sni, &profile).await?;
        let session = Arc::new(Session::client(
            tls,
            &self.password,
            PaddingScheme::default(),
        ));
        let mut pool = self.pool.lock().unwrap_or_else(|e| e.into_inner());
        pool.push(Arc::clone(&session));
        Ok(session)
    }

    /// The boring [`Profile`] for a new TLS session. With a dynamic [`gambit_source`](Self::
    /// gambit_source) (ADR 0006 P3), compute a fresh gambit and resolve it onto boring; **fall back
    /// to the static `profile`** if the module faults, returns an undecodable gambit, or yields one
    /// boring can't realize — a dynamic gambit must never break connectivity (boring always
    /// completes the handshake; a declined gambit degrades to the portable default).
    #[cfg(feature = "wasm-transport")]
    fn resolve_profile(&self) -> Profile {
        let Some(source) = &self.gambit_source else {
            return self.profile.clone();
        };
        let mut transform = source.lock().unwrap_or_else(|e| e.into_inner());
        // Per-connection context (ADR 0006 P3): the host-controlled wall clock — the one fact a
        // sandboxed module can't self-source (it has its own CSPRNG + persistent state otherwise).
        let unix_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let ctx = flint_tls::gambit::GambitContext { unix_secs }.encode();
        match transform.compute_gambit(&ctx) {
            Ok(gambit) => match Profile::for_boring(&gambit) {
                Ok(resolved) => {
                    for note in &resolved.unrealizable {
                        tracing::warn!(
                            knob = note,
                            "computed gambit knob not realizable on boring"
                        );
                    }
                    resolved.profile
                }
                Err(e) => {
                    tracing::warn!(error = %e, "computed gambit declined by boring; using static profile");
                    self.profile.clone()
                }
            },
            Err(e) => {
                tracing::warn!(error = %e, "compute_gambit failed; using static profile");
                self.profile.clone()
            }
        }
    }

    /// Without the `wasm-transport` feature there is no dynamic source — the static profile is used.
    #[cfg(not(feature = "wasm-transport"))]
    fn resolve_profile(&self) -> Profile {
        self.profile.clone()
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

impl AnytlsTransport {
    /// Open a stream and announce `target` (an IP or a domain the exit resolves) in the SOCKS5-grammar
    /// header. Shared by [`dial`]/[`dial_addr`].
    async fn dial_target(&self, target: Address) -> io::Result<BoxedStream> {
        let session = self.inner.acquire().await?;
        let mut stream = session.open_stream().await?;
        // AnyTLS choreography: the target address is the stream's first bytes (SOCKS5 grammar),
        // which also flushes the buffered cmdSettings+cmdSYN as padded packet 1.
        let mut addr = BytesMut::new();
        target.encode(&mut addr);
        stream.write_all(&addr).await?;
        Ok(Box::new(stream))
    }
}

#[async_trait]
impl Transport for AnytlsTransport {
    async fn dial(&self, target: SocketAddr) -> io::Result<BoxedStream> {
        self.dial_target(Address::Ip(target)).await
    }

    async fn dial_addr(&self, target: Address) -> io::Result<BoxedStream> {
        // SOCKS5 ATYP=3 carries the domain to the exit (it resolves) — no client-side DNS.
        self.dial_target(target).await
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

#[cfg(all(test, feature = "wasm-transport"))]
mod tests {
    use super::*;
    use crate::transport::wasm::{Transform, TransformModule};
    use flint_tls::gambit::{Capability, ClientHello, EchMode, Gambit, Records};

    /// A Path-B module that, on `compute_gambit`, returns the postcard encoding of `g`.
    fn gambit_transform(g: &Gambit) -> Transform {
        let bytes = postcard::to_stdvec(g).expect("encode gambit");
        let escaped: String = bytes.iter().map(|b| format!("\\{b:02x}")).collect();
        let wat = format!(
            r#"
(module
  (memory (export "memory") 2)
  (data (i32.const 2048) "{escaped}")
  (func (export "alloc") (param $len i32) (result i32) (i32.const 1024))
  (func (export "compute_gambit") (param $p i32) (param $l i32) (result i64)
    (i64.or
      (i64.shl (i64.extend_i32_u (i32.const 2048)) (i64.const 32))
      (i64.extend_i32_u (i32.const {len})))))
"#,
            len = bytes.len()
        );
        TransformModule::load(&wat::parse_str(&wat).expect("assemble"))
            .expect("load")
            .instantiate()
            .expect("instantiate")
    }

    fn transport_with(gambit: &Gambit) -> AnytlsTransport {
        AnytlsTransport::with_dynamic_gambit(
            "127.0.0.1:1".parse().unwrap(),
            "pw".into(),
            "example.com".into(),
            None,
            WirePlan::default(),
            Profile::default(),
            gambit_transform(gambit),
        )
    }

    fn gambit(clienthello: ClientHello, requires: Vec<Capability>) -> Gambit {
        Gambit {
            genome_version: 1,
            version: 1,
            id: "dyn".into(),
            anchor: Default::default(),
            clienthello,
            records: Records::default(),
            wire: Default::default(),
            requires,
        }
    }

    #[tokio::test]
    async fn per_connection_compute_drives_the_profile() {
        let g = gambit(
            ClientHello {
                ech: Some(EchMode::Off),
                pq_kem: Some(false),
                ..Default::default()
            },
            vec![Capability::Ech],
        );
        let t = transport_with(&g);
        let profile = t.inner.resolve_profile();
        // The computed gambit (not the static Profile::default) shaped the handshake.
        assert!(!profile.ech_grease);
        assert!(!profile.pq_kem);
    }

    #[tokio::test]
    async fn a_gambit_beyond_boring_falls_back_to_the_static_profile() {
        // requires raw_clienthello → for_boring declines → resolve_profile must return the static
        // fallback (the default Chrome-137 profile), never break the connection.
        let g = gambit(
            ClientHello {
                ech: Some(EchMode::Off),
                ..Default::default()
            },
            vec![Capability::RawClienthello],
        );
        let t = transport_with(&g);
        let profile = t.inner.resolve_profile();
        assert_eq!(profile, Profile::default());
        assert!(profile.ech_grease); // the declined gambit's ech=off did NOT take effect
    }
}
