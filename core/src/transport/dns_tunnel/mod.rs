//! DNS-tunnel transport (ADR 0011): a [`Transport`] that tunnels a TCP byte-stream over DNS by
//! driving the sans-I/O [`dns_tunnel_core::session::ClientSession`] over UDP, spraying queries across a
//! pool of recursive resolvers ([`balancer::ResolverPool`]).
//!
//! The DNS carrier is request→response and the server can't push, so a background **pump** task per
//! dial keeps polling: it drains ready answers (attributing RTT/loss to the answering resolver),
//! picks resolver(s) for each outgoing query (with duplication + sticky failover), delivers received
//! bytes to the application, and wakes on a keepalive/RTO tick so downlink data and retransmits still
//! flow when the app is idle. Because the server keys sessions by ConnectionID (not source address),
//! answers relayed by *any* resolver reassemble into one tunnel — so a blocked / rate-limited /
//! mid-session-severed resolver never kills the session while one healthy resolver remains.
//!
//! Authoritative mode (talk straight to the server's UDP address) is just a one-entry pool.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::net::UdpSocket;

use dns_tunnel_core::session::{self, AnswerOutcome, ClientSession};

use crate::net::SocketProtector;
use crate::transport::{
    protected_udp_socket, BoxedPacketSink, BoxedPacketSource, Transport, UdpTransport,
};
use crate::BoxedStream;

/// Resolver pool + balancer (ADR 0011 §4): the headline resolver aggregation — pool parse/expand,
/// per-resolver RTT/loss health, duplication, and per-stream sticky failover. Wired into the pump.
pub mod balancer;

use balancer::{PoolConfig, ResolverPool};

/// The app-facing duplex buffer size (bytes) between the caller's stream and the pump.
const DUPLEX_BUF: usize = 64 * 1024;
/// The keepalive/RTO wakeup cadence (ms): drives downlink polling + retransmits while idle.
const TICK_MS: u64 = 20;
/// Downlink MTU-probe candidate sizes (payload bytes); the largest that survives the path wins.
const PROBE_CANDIDATES: &[u16] = &[400, 600, 800, 1000, 1200];
/// How long to collect probe responses before applying the discovered synced downlink MTU (ms).
const PROBE_WINDOW_MS: u64 = 400;

/// A DNS-tunnel transport. Cheap to clone; one pump task + resolver pool is spawned per `dial`.
#[derive(Clone)]
pub struct DnsTunnelTransport {
    inner: Arc<Inner>,
}

struct Inner {
    zone: String,
    psk: Vec<u8>,
    /// Resolver specs (authoritative mode = a single `server_ip:port`).
    resolvers: Vec<String>,
    pool_cfg: PoolConfig,
    cfg: session::Config,
    protector: Option<SocketProtector>,
}

impl DnsTunnelTransport {
    /// Build the transport. `psk` is the already-decoded pre-shared key (≥32 bytes); `resolvers` are
    /// the recursive resolvers to spray across (for authoritative mode, a single `ip:port`); `cfg`
    /// carries the cipher + ARQ/poll tuning; `pool_cfg` tunes the balancer.
    pub fn new(
        zone: String,
        psk: Vec<u8>,
        resolvers: Vec<String>,
        pool_cfg: PoolConfig,
        cfg: session::Config,
        protector: Option<SocketProtector>,
    ) -> Self {
        DnsTunnelTransport {
            inner: Arc::new(Inner {
                zone,
                psk,
                resolvers,
                pool_cfg,
                cfg,
                protector,
            }),
        }
    }
}

/// Encode a target `SocketAddr` as SOCKS5 address bytes (`ATYP ‖ addr ‖ port`) — the opaque payload the
/// SYN carries for the server to dial.
fn encode_target(addr: &SocketAddr) -> Vec<u8> {
    let mut v = Vec::with_capacity(19);
    match addr {
        SocketAddr::V4(a) => {
            v.push(0x01);
            v.extend_from_slice(&a.ip().octets());
        }
        SocketAddr::V6(a) => {
            v.push(0x04);
            v.extend_from_slice(&a.ip().octets());
        }
    }
    v.extend_from_slice(&addr.port().to_be_bytes());
    v
}

#[async_trait]
impl Transport for DnsTunnelTransport {
    async fn dial(&self, target: SocketAddr) -> io::Result<BoxedStream> {
        let i = &self.inner;
        let pool = ResolverPool::parse(&i.resolvers, i.pool_cfg)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let session = ClientSession::new(&i.psk, &i.zone, &encode_target(&target), i.cfg.clone())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

        // One protector-pinned, *unconnected* UDP socket (so its own packets bypass the tunnel route);
        // the pump `send_to`s the picked resolvers. Family follows a representative resolver.
        let sock = protected_udp_socket(pool.any_addr(), i.protector.as_ref())?;
        let std_sock: std::net::UdpSocket = sock.into();
        let udp = UdpSocket::from_std(std_sock)?;

        let timeout = i.cfg.query_timeout_ms;
        let (app_side, pump_side) = tokio::io::duplex(DUPLEX_BUF);
        let pump = tokio::spawn(run_pump(session, udp, pool, timeout, pump_side));
        Ok(Box::new(PumpStream {
            inner: app_side,
            pump,
        }))
    }
}

#[async_trait]
impl UdpTransport for DnsTunnelTransport {
    async fn dial_udp(
        &self,
        _target: SocketAddr,
    ) -> io::Result<(BoxedPacketSink, BoxedPacketSource)> {
        Err(io::Error::other(
            "dns-tunnel: UDP-over-tunnel is unsupported in this build (TCP only, ADR 0011 v1)",
        ))
    }
}

/// The transaction id is the first two bytes of a DNS message.
fn txn_of(msg: &[u8]) -> Option<u16> {
    (msg.len() >= 2).then(|| u16::from_be_bytes([msg[0], msg[1]]))
}

/// The background driver for one session over a resolver pool.
async fn run_pump(
    mut session: ClientSession,
    udp: UdpSocket,
    mut pool: ResolverPool,
    query_timeout_ms: u64,
    mut io: DuplexStream,
) {
    use tokio::io::AsyncReadExt as _;
    use tokio::io::AsyncWriteExt as _;

    let start = Instant::now();
    let mut dns_buf = vec![0u8; 2048];
    let mut app_buf = vec![0u8; 16 * 1024];
    // txn -> (resolvers the query was sent to, sent_at_ms) — for RTT/loss attribution.
    let mut pending: HashMap<u16, (Vec<SocketAddr>, u64)> = HashMap::new();
    let mut ticker = tokio::time::interval(Duration::from_millis(TICK_MS));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Downlink MTU probe state: fire one round of probes after the handshake, collect the largest
    // size that returns, then SetMtu it. Probe queries are deliberately NOT tracked in `pending`
    // (a probe failing at a too-large size is expected, not resolver loss).
    let (mut probe_sent, mut probe_done, mut probe_best, mut probe_deadline) =
        (false, false, 0u16, 0u64);

    loop {
        let now = start.elapsed().as_millis() as u64;

        // Drain every answer that's ready, attributing RTT to the resolver that answered.
        loop {
            match udp.try_recv_from(&mut dns_buf) {
                Ok((n, from)) => {
                    if let Some(txn) = txn_of(&dns_buf[..n]) {
                        if let Some((_, sent_at)) = pending.remove(&txn) {
                            pool.on_success(&from, now.saturating_sub(sent_at));
                        }
                    }
                    if let AnswerOutcome::ProbeResp { target } =
                        session.on_answer(&dns_buf[..n], now)
                    {
                        probe_best = probe_best.max(target);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => return,
            }
        }

        // Age out unanswered queries → loss on the resolver(s) they went to.
        if !pending.is_empty() {
            let expired: Vec<u16> = pending
                .iter()
                .filter(|(_, (_, t))| now.saturating_sub(*t) >= query_timeout_ms)
                .map(|(k, _)| *k)
                .collect();
            for txn in expired {
                if let Some((targets, _)) = pending.remove(&txn) {
                    pool.on_loss(&targets, now);
                }
            }
        }

        // Flush queries, each sprayed across the picked resolver(s).
        while let Some(q) = session.poll_query(now) {
            let targets = pool.pick(now);
            for t in &targets {
                let _ = udp.send_to(&q, t).await; // per-send errors (e.g. family mismatch) are non-fatal
            }
            if let Some(txn) = txn_of(&q) {
                pending.insert(txn, (targets, now));
            }
        }

        // MTU probe: once established, fire one round of downlink probes; after the collection window,
        // tell the server the largest size that survived the path (a synced-pool downlink MTU). Runs
        // alongside early data, which uses the conservative default until the probe settles.
        if !probe_done && session.is_established() {
            if !probe_sent {
                for &target in PROBE_CANDIDATES {
                    if let Some(q) = session.build_mtu_probe(target) {
                        for t in &pool.pick(now) {
                            let _ = udp.send_to(&q, t).await;
                        }
                    }
                }
                probe_sent = true;
                probe_deadline = now + PROBE_WINDOW_MS;
            } else if now >= probe_deadline {
                if probe_best > 0 {
                    if let Some(q) = session.build_set_mtu(probe_best) {
                        for t in &pool.pick(now) {
                            let _ = udp.send_to(&q, t).await;
                        }
                    }
                }
                probe_done = true;
            }
        }

        // Deliver received bytes to the application.
        let data = session.read();
        if !data.is_empty() && io.write_all(&data).await.is_err() {
            return;
        }

        if session.is_closed() {
            return;
        }

        tokio::select! {
            r = udp.readable() => {
                if r.is_err() {
                    return;
                }
            }
            r = io.read(&mut app_buf) => match r {
                Ok(0) => session.close(),
                Ok(n) => session.write(&app_buf[..n]),
                Err(_) => return,
            },
            _ = ticker.tick() => {}
        }
    }
}

/// The `BoxedStream` returned by `dial`: the app half of the duplex, owning the pump task so dropping
/// the stream aborts the pump (no orphaned task).
struct PumpStream {
    inner: DuplexStream,
    pump: tokio::task::JoinHandle<()>,
}

impl Drop for PumpStream {
    fn drop(&mut self) {
        self.pump.abort();
    }
}

impl AsyncRead for PumpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PumpStream {
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

#[cfg(test)]
mod tests {
    use super::*;
    use dns_tunnel_core::arq;
    use dns_tunnel_core::session::{Config as SessCfg, Server};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A minimal in-test authoritative server: answer tunnel queries and echo every received byte back
    /// (stand-in for the TCP egress, which is the M4c server binary's job).
    async fn echo_server(udp: UdpSocket, psk: Vec<u8>, zone: String, cfg: SessCfg) {
        let mut server = Server::new(&psk, &zone, cfg).unwrap();
        let start = Instant::now();
        let mut buf = vec![0u8; 2048];
        loop {
            let (n, from) = match udp.recv_from(&mut buf).await {
                Ok(x) => x,
                Err(_) => return,
            };
            let now = start.elapsed().as_millis() as u64;
            if let Some(ans) = server.on_query(&buf[..n], now) {
                if udp.send_to(&ans, from).await.is_err() {
                    return;
                }
            }
            for id in server.session_ids() {
                for sid in server.streams_of(&id) {
                    let d = server.take_from_client(&id, sid);
                    if !d.is_empty() {
                        server.deliver_to_client(&id, sid, &d);
                    }
                }
            }
        }
    }

    async fn spawn_echo_server(psk: Vec<u8>, zone: String, cfg: SessCfg) -> SocketAddr {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = udp.local_addr().unwrap();
        tokio::spawn(echo_server(udp, psk, zone, cfg));
        addr
    }

    /// Like `spawn_echo_server`, but records the max downlink segment any session reaches into
    /// `report` (so a test can observe the pump's MTU probe raising it via SetMtu).
    async fn spawn_echo_server_reporting(
        psk: Vec<u8>,
        zone: String,
        cfg: SessCfg,
        report: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) -> SocketAddr {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = udp.local_addr().unwrap();
        tokio::spawn(async move {
            let mut server = Server::new(&psk, &zone, cfg).unwrap();
            let start = Instant::now();
            let mut buf = vec![0u8; 4096];
            loop {
                let (n, from) = match udp.recv_from(&mut buf).await {
                    Ok(x) => x,
                    Err(_) => return,
                };
                let now = start.elapsed().as_millis() as u64;
                if let Some(ans) = server.on_query(&buf[..n], now) {
                    if udp.send_to(&ans, from).await.is_err() {
                        return;
                    }
                }
                for id in server.session_ids() {
                    if let Some(seg) = server.downlink_segment(&id) {
                        report.fetch_max(seg, std::sync::atomic::Ordering::Relaxed);
                    }
                    for sid in server.streams_of(&id) {
                        let d = server.take_from_client(&id, sid);
                        if !d.is_empty() {
                            server.deliver_to_client(&id, sid, &d);
                        }
                    }
                }
            }
        });
        addr
    }

    /// A `127.0.0.1` address with (almost certainly) nothing listening: bind to grab a free port,
    /// then drop the socket so sends there go unanswered.
    async fn dead_addr() -> SocketAddr {
        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a = s.local_addr().unwrap();
        drop(s);
        a
    }

    fn cfg() -> SessCfg {
        SessCfg {
            arq: arq::Config {
                initial_rto_ms: 60,
                min_rto_ms: 15,
                ..arq::Config::default()
            },
            query_timeout_ms: 150,
            max_query_inflight: 16,
            ..SessCfg::default()
        }
    }

    async fn round_trip(transport: DnsTunnelTransport, len: usize) {
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let stream = transport.dial(target).await.unwrap();
        let (mut rd, mut wr) = tokio::io::split(stream);
        let payload: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(37)).collect();
        let p2 = payload.clone();
        let writer = tokio::spawn(async move {
            wr.write_all(&p2).await.unwrap();
            wr.flush().await.unwrap();
        });
        let mut got = vec![0u8; len];
        rd.read_exact(&mut got).await.unwrap();
        writer.await.unwrap();
        assert_eq!(got, payload, "payload round-trips through the DNS tunnel");
    }

    #[tokio::test]
    async fn loopback_authoritative_round_trip() {
        // Authoritative mode = a one-entry pool. 512 KiB round-trip through the full stack.
        let psk = vec![0x11u8; 32];
        let zone = "t.example.com".to_string();
        let server = spawn_echo_server(psk.clone(), zone.clone(), cfg()).await;
        let transport = DnsTunnelTransport::new(
            zone,
            psk,
            vec![server.to_string()],
            PoolConfig {
                duplication: 1,
                ..PoolConfig::default()
            },
            cfg(),
            None,
        );
        round_trip(transport, 512 * 1024).await;
    }

    #[tokio::test]
    async fn aggregation_survives_a_dead_resolver_via_duplication() {
        // Pool = {live server, dead addr}, duplication 2 → every query is sent to both; the dead path
        // is silently ignored and the transfer completes. Proves multipath tolerance.
        let psk = vec![0x22u8; 32];
        let zone = "t.example.com".to_string();
        let server = spawn_echo_server(psk.clone(), zone.clone(), cfg()).await;
        let dead = dead_addr().await;
        let transport = DnsTunnelTransport::new(
            zone,
            psk,
            vec![server.to_string(), dead.to_string()],
            PoolConfig {
                duplication: 2,
                ..PoolConfig::default()
            },
            cfg(),
            None,
        );
        round_trip(transport, 128 * 1024).await;
    }

    #[tokio::test]
    async fn fails_over_when_the_sticky_resolver_is_dead() {
        // Pool = {dead (sticky first), live server}, duplication 1 → the first resolver is dead, so the
        // handshake/data time out on it; the balancer disables it and fails over to the live server,
        // and the transfer still completes. Proves per-stream sticky failover end-to-end.
        let psk = vec![0x33u8; 32];
        let zone = "t.example.com".to_string();
        let server = spawn_echo_server(psk.clone(), zone.clone(), cfg()).await;
        let dead = dead_addr().await;
        let transport = DnsTunnelTransport::new(
            zone,
            psk,
            vec![dead.to_string(), server.to_string()],
            PoolConfig {
                duplication: 1,
                failover_streak: 2,
                min_samples: 2.0,
                disable_loss: 0.8,
                ..PoolConfig::default()
            },
            cfg(),
            None,
        );
        round_trip(transport, 64 * 1024).await;
    }

    #[tokio::test]
    async fn probe_raises_downlink_mtu() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let psk = vec![0x99u8; 32];
        let zone = "t.example.com".to_string();
        let report = Arc::new(AtomicUsize::new(0));
        let server =
            spawn_echo_server_reporting(psk.clone(), zone.clone(), cfg(), report.clone()).await;
        let transport = DnsTunnelTransport::new(
            zone,
            psk,
            vec![server.to_string()],
            PoolConfig {
                duplication: 1,
                ..PoolConfig::default()
            },
            cfg(),
            None,
        );
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let stream = transport.dial(target).await.unwrap();
        let (mut rd, mut wr) = tokio::io::split(stream);
        // Establish + a tiny round-trip.
        wr.write_all(b"hi").await.unwrap();
        let mut b = [0u8; 2];
        rd.read_exact(&mut b).await.unwrap();
        // Hold the stream open past the probe window so the pump fires probes + SetMtu.
        tokio::time::sleep(Duration::from_millis(PROBE_WINDOW_MS + 300)).await;
        // Over loopback every candidate returns, so the pump discovers the largest (1200) and SetMtu's
        // it — proving the probe fired end-to-end and adapted the server's downlink segment.
        assert_eq!(
            report.load(Ordering::Relaxed),
            *PROBE_CANDIDATES.last().unwrap() as usize,
            "MTU probe raised the server downlink to the largest surviving candidate"
        );
    }
}
