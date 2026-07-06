//! DNS-tunnel transport (ADR 0011): a [`Transport`] that tunnels a TCP byte-stream over DNS by
//! driving the sans-I/O [`dns_tunnel_core::session::ClientSession`] over UDP, spraying queries across a
//! pool of recursive resolvers ([`balancer::ResolverPool`]).
//!
//! The DNS carrier is request→response and the server can't push, so a background **pump** task keeps
//! polling: it drains ready answers (attributing RTT/loss to the answering resolver), picks
//! resolver(s) for each outgoing query (with duplication + sticky failover), delivers received bytes
//! to the application, and wakes on a keepalive/RTO tick so downlink data and retransmits still flow
//! when the app is idle. Because the server keys sessions by ConnectionID (not source address),
//! answers relayed by *any* resolver reassemble into one tunnel — so a blocked / rate-limited /
//! mid-session-severed resolver never kills the session while one healthy resolver remains.
//!
//! **Multiplexing:** many `dial`s share **one** forward-secret session, pump, UDP socket, and resolver
//! pool. The first dial establishes the session (a cleartext ephemeral↔ephemeral handshake
//! authenticated by the server's public key) and opens the first stream to its target; each later dial
//! sends the pump an `Open` request, which allocates a new multiplexed stream over the same
//! ConnectionID. A tiny per-stream reader task fans the app's uplink bytes into the pump (tagged with
//! its StreamID), and the pump fans downlink bytes back out to each stream's duplex. When every stream
//! has been idle-closed for [`IDLE_GRACE_MS`], the pump tears the session down; the next dial rebuilds
//! one (so an idle tunnel stops querying rather than lingering).
//!
//! Authoritative mode (talk straight to the server's UDP address) is just a one-entry pool.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;

use dns_tunnel_core::session::{self, AnswerOutcome, ClientSession, PRIMARY_STREAM_ID};

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
/// How long the shared session lingers with no open streams before the pump tears it down (ms). A new
/// `dial` within this window reuses the session; after it, the pump exits and the next dial rebuilds.
const IDLE_GRACE_MS: u64 = 3_000;

/// A control message from `dial` to a running pump: open a new multiplexed stream to `target`, wiring
/// its app-facing duplex (the pump splits it into a downlink writer + an uplink reader task).
enum Ctl {
    Open {
        target: SocketAddr,
        pump_side: DuplexStream,
    },
}

/// A message from a per-stream reader task to the pump: app→session bytes, or app-side EOF.
enum Up {
    Data(u16, Vec<u8>),
    Eof(u16),
}

/// A handle on the running session's pump, stored in [`Inner`] and shared across dials.
struct SessionHandle {
    ctl_tx: mpsc::Sender<Ctl>,
}

/// A DNS-tunnel transport. Cheap to clone; all dials share **one** session/pump/socket (rebuilt on
/// demand after an idle teardown).
#[derive(Clone)]
pub struct DnsTunnelTransport {
    inner: Arc<Inner>,
}

struct Inner {
    zone: String,
    /// The server's static Ed25519 public key (authenticates the forward-secret handshake).
    server_pub: [u8; 32],
    /// Resolver specs (authoritative mode = a single `server_ip:port`).
    resolvers: Vec<String>,
    pool_cfg: PoolConfig,
    cfg: session::Config,
    protector: Option<SocketProtector>,
    /// The current shared session's pump handle, if one is running.
    session: Mutex<Option<SessionHandle>>,
}

impl DnsTunnelTransport {
    /// Build the transport. `server_pub` is the server's static Ed25519 public key (32 bytes);
    /// `resolvers` are the recursive resolvers to spray across (for authoritative mode, a single
    /// `ip:port`); `cfg` carries the cipher + ARQ/poll tuning; `pool_cfg` tunes the balancer.
    pub fn new(
        zone: String,
        server_pub: [u8; 32],
        resolvers: Vec<String>,
        pool_cfg: PoolConfig,
        cfg: session::Config,
        protector: Option<SocketProtector>,
    ) -> Self {
        DnsTunnelTransport {
            inner: Arc::new(Inner {
                zone,
                server_pub,
                resolvers,
                pool_cfg,
                cfg,
                protector,
                session: Mutex::new(None),
            }),
        }
    }

    /// Build the session's UDP socket + pump and return the boxed app stream for the primary (first)
    /// stream together with the handle to store. Called on the first dial (or after an idle teardown).
    fn spawn_session(
        &self,
        target: SocketAddr,
        app_side: DuplexStream,
        pump_side: DuplexStream,
    ) -> io::Result<(BoxedStream, SessionHandle)> {
        let i = &self.inner;
        let pool = ResolverPool::parse(&i.resolvers, i.pool_cfg)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let session = ClientSession::new(
            &i.server_pub,
            &i.zone,
            &encode_target(&target),
            i.cfg.clone(),
        )
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        // One protector-pinned, *unconnected* UDP socket (so its own packets bypass the tunnel route);
        // the pump `send_to`s the picked resolvers. Family follows a representative resolver.
        let sock = protected_udp_socket(pool.any_addr(), i.protector.as_ref())?;
        let std_sock: std::net::UdpSocket = sock.into();
        let udp = UdpSocket::from_std(std_sock)?;
        let timeout = i.cfg.query_timeout_ms;
        let (ctl_tx, ctl_rx) = mpsc::channel::<Ctl>(64);
        tokio::spawn(run_pump(session, udp, pool, timeout, pump_side, ctl_rx));
        Ok((Box::new(app_side), SessionHandle { ctl_tx }))
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
        let (app_side, pump_side) = tokio::io::duplex(DUPLEX_BUF);
        let mut guard = self.inner.session.lock().await;

        // Attach to the live session if one is running: hand the pump an Open for a new stream.
        if let Some(h) = guard.as_ref() {
            match h.ctl_tx.send(Ctl::Open { target, pump_side }).await {
                Ok(()) => return Ok(Box::new(app_side)),
                // The pump has exited (idle teardown / fatal): recover the duplex from the failed
                // send and rebuild a fresh session below, with this dial as the primary stream.
                Err(mpsc::error::SendError(Ctl::Open { pump_side, .. })) => {
                    let (stream, handle) = self.spawn_session(target, app_side, pump_side)?;
                    *guard = Some(handle);
                    return Ok(stream);
                }
            }
        }

        // No live session: establish one. This dial's target becomes stream 1 (rides the handshake).
        let (stream, handle) = self.spawn_session(target, app_side, pump_side)?;
        *guard = Some(handle);
        Ok(stream)
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

/// A per-stream reader task: forward the app's uplink bytes to the pump tagged with `sid`, and signal
/// EOF when the app closes its write side. One is spawned per open multiplexed stream.
async fn stream_reader(sid: u16, mut rd: ReadHalf<DuplexStream>, up: mpsc::Sender<Up>) {
    let mut b = vec![0u8; 16 * 1024];
    loop {
        match rd.read(&mut b).await {
            Ok(0) | Err(_) => {
                let _ = up.send(Up::Eof(sid)).await;
                return;
            }
            Ok(n) => {
                if up.send(Up::Data(sid, b[..n].to_vec())).await.is_err() {
                    return;
                }
            }
        }
    }
}

/// Handle a `Ctl::Open`: allocate the new stream's StreamID and split its duplex into a downlink
/// writer (kept by the pump) plus an uplink reader task.
fn open_stream_io(
    ctl: Ctl,
    session: &mut ClientSession,
    writers: &mut HashMap<u16, WriteHalf<DuplexStream>>,
    readers: &mut HashMap<u16, JoinHandle<()>>,
    up_tx: &mpsc::Sender<Up>,
) {
    let Ctl::Open { target, pump_side } = ctl;
    let sid = session.open_stream(&encode_target(&target));
    let (rd, wr) = tokio::io::split(pump_side);
    writers.insert(sid, wr);
    readers.insert(sid, tokio::spawn(stream_reader(sid, rd, up_tx.clone())));
}

/// Tear down a stream's app-side I/O: drop its downlink writer and abort its reader task.
fn teardown_io(
    sid: u16,
    writers: &mut HashMap<u16, WriteHalf<DuplexStream>>,
    readers: &mut HashMap<u16, JoinHandle<()>>,
) {
    writers.remove(&sid);
    if let Some(h) = readers.remove(&sid) {
        h.abort();
    }
}

/// The background driver for one multiplexed session over a resolver pool. Owns the `ClientSession`,
/// the UDP socket, the pool, and the per-stream app I/O; runs until the session is torn down (idle
/// grace with no streams, or a fatal socket error).
async fn run_pump(
    mut session: ClientSession,
    udp: UdpSocket,
    mut pool: ResolverPool,
    query_timeout_ms: u64,
    primary_pump_side: DuplexStream,
    ctl_rx: mpsc::Receiver<Ctl>,
) {
    let start = Instant::now();
    let mut dns_buf = vec![0u8; 2048];
    // txn -> (resolvers the query was sent to, sent_at_ms) — for RTT/loss attribution.
    let mut pending: HashMap<u16, (Vec<SocketAddr>, u64)> = HashMap::new();
    let mut ticker = tokio::time::interval(Duration::from_millis(TICK_MS));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Downlink MTU probe state: fire one round of probes after the handshake, collect the largest
    // size that returns, then SetMtu it. Probe queries are deliberately NOT tracked in `pending`
    // (a probe failing at a too-large size is expected, not resolver loss).
    let (mut probe_sent, mut probe_done, mut probe_best, mut probe_deadline) =
        (false, false, 0u16, 0u64);

    // Per-stream app I/O. Stream 1 (the primary) is pre-registered from the handshake dial; further
    // streams arrive as `Ctl::Open`. Each stream's app→session bytes fan in through `up_rx`.
    let (up_tx, mut up_rx) = mpsc::channel::<Up>(1024);
    let mut writers: HashMap<u16, WriteHalf<DuplexStream>> = HashMap::new();
    let mut readers: HashMap<u16, JoinHandle<()>> = HashMap::new();
    {
        let (rd, wr) = tokio::io::split(primary_pump_side);
        writers.insert(PRIMARY_STREAM_ID, wr);
        readers.insert(
            PRIMARY_STREAM_ID,
            tokio::spawn(stream_reader(PRIMARY_STREAM_ID, rd, up_tx.clone())),
        );
    }
    // `ctl_rx` goes to `None` once we stop accepting new streams (during the idle-teardown drain).
    let mut ctl_rx = Some(ctl_rx);
    let mut last_active = 0u64;

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
                // Windows surfaces an ICMP port/host-unreachable from a dead resolver as
                // `ConnectionReset` on the *next* recv on this shared socket (Unix silently drops
                // it). It's a stale per-datagram error, not a socket failure — skip it and keep
                // draining so one dead resolver can't kill the pump or starve the live resolver's
                // replies. Failover then happens the same way it does on Unix: via RTO on `pending`.
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => continue,
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

        // Fan downlink bytes out to each stream's app duplex, and handle per-stream close.
        for sid in session.stream_ids() {
            let mut drop_io = false;
            if writers.contains_key(&sid) {
                let data = session.read_stream(sid);
                if !data.is_empty() {
                    if let Some(wr) = writers.get_mut(&sid) {
                        if wr.write_all(&data).await.is_err() {
                            // The app dropped its read side: close the stream and tear its I/O down.
                            session.close_stream(sid);
                            drop_io = true;
                        }
                    }
                }
            }
            if !drop_io && session.stream_remote_finished(sid) {
                // Remote half is done: signal EOF to the app once (drop the downlink writer). The
                // reader stays until the app closes its side, so uplink can still drain (half-close).
                if let Some(mut wr) = writers.remove(&sid) {
                    let _ = wr.shutdown().await;
                }
            }
            if drop_io {
                teardown_io(sid, &mut writers, &mut readers);
            }
        }
        // Reap fully-closed streams (both halves done): drop their ARQ state + any leftover I/O.
        for sid in session.reap_closed() {
            teardown_io(sid, &mut writers, &mut readers);
        }

        // Idle teardown: once no stream has been open for the grace window, exit so an idle tunnel
        // stops querying DNS (the next dial rebuilds a fresh session). Drain any `Open` that raced in
        // just before giving up so an accepted dial is never silently dropped.
        let active = !writers.is_empty() || !readers.is_empty() || !session.stream_ids().is_empty();
        if active {
            last_active = now;
        } else if now.saturating_sub(last_active) >= IDLE_GRACE_MS {
            match ctl_rx.as_mut() {
                Some(rx) => {
                    rx.close();
                    let mut opened = false;
                    while let Ok(ctl) = rx.try_recv() {
                        open_stream_io(ctl, &mut session, &mut writers, &mut readers, &up_tx);
                        opened = true;
                    }
                    if !opened {
                        return;
                    }
                    // Serve the late stream(s); stop accepting further Opens (they rebuild elsewhere).
                    ctl_rx = None;
                    last_active = now;
                }
                None => return,
            }
        }

        tokio::select! {
            biased;
            // New multiplexed stream from a dial. A `None` from `recv` means all dial senders dropped
            // (the transport was dropped); a pending future disables the arm once we stop accepting.
            ctl = async {
                match ctl_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending::<Option<Ctl>>().await,
                }
            } => match ctl {
                Some(c) => open_stream_io(c, &mut session, &mut writers, &mut readers, &up_tx),
                None => ctl_rx = None,
            },
            // App→session uplink bytes (or an app-side EOF) from a per-stream reader.
            up = up_rx.recv() => match up {
                Some(Up::Data(sid, b)) => session.write_stream(sid, &b),
                Some(Up::Eof(sid)) => session.close_stream(sid),
                None => {}
            },
            r = udp.readable() => {
                if r.is_err() {
                    return;
                }
            }
            _ = ticker.tick() => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_tunnel_core::arq;
    use dns_tunnel_core::crypto::{server_public_from_pkcs8, ServerStatic};
    use dns_tunnel_core::session::{Config as SessCfg, Server};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A fresh server identity (PKCS#8 private key) + its 32-byte public key, for tests: the private
    /// key goes to the in-test server, the public key to the transport.
    fn keypair() -> (Vec<u8>, [u8; 32]) {
        let pkcs8 = ServerStatic::generate().unwrap();
        let pubkey = server_public_from_pkcs8(&pkcs8).unwrap();
        (pkcs8, pubkey)
    }

    /// A minimal in-test authoritative server: answer tunnel queries and echo every received byte back
    /// (stand-in for the TCP egress, which is the M4c server binary's job).
    async fn echo_server(udp: UdpSocket, privkey: Vec<u8>, zone: String, cfg: SessCfg) {
        let mut server = Server::new(&privkey, &zone, cfg).unwrap();
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

    async fn spawn_echo_server(privkey: Vec<u8>, zone: String, cfg: SessCfg) -> SocketAddr {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = udp.local_addr().unwrap();
        tokio::spawn(echo_server(udp, privkey, zone, cfg));
        addr
    }

    /// Like `spawn_echo_server`, but records the max downlink segment any session reaches into
    /// `report` (so a test can observe the pump's MTU probe raising it via SetMtu).
    async fn spawn_echo_server_reporting(
        privkey: Vec<u8>,
        zone: String,
        cfg: SessCfg,
        report: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) -> SocketAddr {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = udp.local_addr().unwrap();
        tokio::spawn(async move {
            let mut server = Server::new(&privkey, &zone, cfg).unwrap();
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

    /// Like `spawn_echo_server`, but records the max number of concurrent sessions (distinct
    /// ConnectionIDs) it ever sees into `max_sessions` — so a test can prove many dials share one.
    async fn spawn_echo_server_counting(
        privkey: Vec<u8>,
        zone: String,
        cfg: SessCfg,
        max_sessions: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) -> SocketAddr {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = udp.local_addr().unwrap();
        tokio::spawn(async move {
            let mut server = Server::new(&privkey, &zone, cfg).unwrap();
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
                let ids = server.session_ids();
                max_sessions.fetch_max(ids.len(), std::sync::atomic::Ordering::Relaxed);
                for id in ids {
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
        let (privkey, server_pub) = keypair();
        let zone = "t.example.com".to_string();
        let server = spawn_echo_server(privkey, zone.clone(), cfg()).await;
        let transport = DnsTunnelTransport::new(
            zone,
            server_pub,
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
        let (privkey, server_pub) = keypair();
        let zone = "t.example.com".to_string();
        let server = spawn_echo_server(privkey, zone.clone(), cfg()).await;
        let dead = dead_addr().await;
        let transport = DnsTunnelTransport::new(
            zone,
            server_pub,
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
        let (privkey, server_pub) = keypair();
        let zone = "t.example.com".to_string();
        let server = spawn_echo_server(privkey, zone.clone(), cfg()).await;
        let dead = dead_addr().await;
        let transport = DnsTunnelTransport::new(
            zone,
            server_pub,
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

        let (privkey, server_pub) = keypair();
        let zone = "t.example.com".to_string();
        let report = Arc::new(AtomicUsize::new(0));
        let server =
            spawn_echo_server_reporting(privkey, zone.clone(), cfg(), report.clone()).await;
        let transport = DnsTunnelTransport::new(
            zone,
            server_pub,
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

    #[tokio::test]
    async fn two_dials_share_one_session() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let (privkey, server_pub) = keypair();
        let zone = "t.example.com".to_string();
        let max_sessions = Arc::new(AtomicUsize::new(0));
        let server =
            spawn_echo_server_counting(privkey, zone.clone(), cfg(), max_sessions.clone()).await;
        let transport = DnsTunnelTransport::new(
            zone,
            server_pub,
            vec![server.to_string()],
            PoolConfig {
                duplication: 1,
                ..PoolConfig::default()
            },
            cfg(),
            None,
        );

        // First dial establishes the session (stream 1); the second multiplexes over it (stream 2).
        let s1 = transport
            .dial("93.184.216.34:443".parse().unwrap())
            .await
            .unwrap();
        let s2 = transport
            .dial("198.51.100.7:443".parse().unwrap())
            .await
            .unwrap();
        let (mut r1, mut w1) = tokio::io::split(s1);
        let (mut r2, mut w2) = tokio::io::split(s2);

        // Distinct payloads (stream 2 = stream 1 + 128) so a cross-stream routing bug corrupts them.
        let len = 32 * 1024;
        let p1: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(37)).collect();
        let p2: Vec<u8> = p1.iter().map(|b| b.wrapping_add(128)).collect();
        let (q1, q2) = (p1.clone(), p2.clone());
        let writer = tokio::spawn(async move {
            w1.write_all(&q1).await.unwrap();
            w1.flush().await.unwrap();
            w2.write_all(&q2).await.unwrap();
            w2.flush().await.unwrap();
        });
        let read1 = tokio::spawn(async move {
            let mut g = vec![0u8; len];
            r1.read_exact(&mut g).await.unwrap();
            g
        });
        let read2 = tokio::spawn(async move {
            let mut g = vec![0u8; len];
            r2.read_exact(&mut g).await.unwrap();
            g
        });
        writer.await.unwrap();
        assert_eq!(read1.await.unwrap(), p1, "stream 1 echo intact");
        assert_eq!(
            read2.await.unwrap(),
            p2,
            "stream 2 echo intact and not crossed"
        );
        assert_eq!(
            max_sessions.load(Ordering::Relaxed),
            1,
            "both dials multiplexed over a single session (one ConnectionID)"
        );
    }

    /// An authoritative server that, on each opened stream, floods `blob` bytes downlink once (drains
    /// and ignores uplink). Models the browsing shape: a tiny request, a large response.
    async fn spawn_flood_server(
        privkey: Vec<u8>,
        zone: String,
        cfg: SessCfg,
        blob: usize,
    ) -> SocketAddr {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = udp.local_addr().unwrap();
        tokio::spawn(async move {
            let mut server = Server::new(&privkey, &zone, cfg).unwrap();
            let start = Instant::now();
            let mut buf = vec![0u8; 4096];
            let payload = vec![0xCDu8; blob];
            let mut fed: std::collections::HashSet<([u8; 8], u16)> =
                std::collections::HashSet::new();
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
                        let _ = server.take_from_client(&id, sid); // drain + ignore uplink
                        if fed.insert((id, sid)) {
                            server.deliver_to_client(&id, sid, &payload);
                        }
                    }
                }
            }
        });
        addr
    }

    /// A UDP relay that delays every datagram by `one_way_ms` in each direction — models recursive-
    /// resolver RTT (which dominates real throughput) on an otherwise-loopback path.
    async fn spawn_delay_relay(server: SocketAddr, one_way_ms: u64) -> SocketAddr {
        use std::sync::Mutex as StdMutex;
        let front = std::sync::Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = front.local_addr().unwrap();
        let back = std::sync::Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        back.connect(server).await.unwrap();
        let client: std::sync::Arc<StdMutex<Option<SocketAddr>>> =
            std::sync::Arc::new(StdMutex::new(None));
        let delay = Duration::from_millis(one_way_ms);
        // client → (delay) → server
        {
            let (front, back, client) = (front.clone(), back.clone(), client.clone());
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    let (n, from) = match front.recv_from(&mut buf).await {
                        Ok(x) => x,
                        Err(_) => return,
                    };
                    *client.lock().unwrap() = Some(from);
                    let (pkt, back) = (buf[..n].to_vec(), back.clone());
                    tokio::spawn(async move {
                        tokio::time::sleep(delay).await;
                        let _ = back.send(&pkt).await;
                    });
                }
            });
        }
        // server → (delay) → client
        {
            let (front, back, client) = (front.clone(), back.clone(), client.clone());
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    let n = match back.recv(&mut buf).await {
                        Ok(n) => n,
                        Err(_) => return,
                    };
                    let dst = *client.lock().unwrap();
                    if let Some(dst) = dst {
                        let (pkt, front) = (buf[..n].to_vec(), front.clone());
                        tokio::spawn(async move {
                            tokio::time::sleep(delay).await;
                            let _ = front.send_to(&pkt, dst).await;
                        });
                    }
                }
            });
        }
        addr
    }

    /// Downlink throughput benchmark (authoritative mode). Skips a warmup window so it measures steady
    /// state, not handshake + MTU-probe ramp. Not a correctness gate: `#[ignore]`d. Env knobs:
    /// `DNS_BENCH_MIB` (payload), `DNS_BENCH_RTT_MS` (one-way relay delay; 0 = loopback ceiling),
    /// `DNS_BENCH_INFLIGHT`, `DNS_BENCH_WINDOW`. Run: `cargo test -p spark-core --features dns-tunnel
    /// --release bench_downlink_throughput -- --ignored --nocapture`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "throughput benchmark; run with --ignored --nocapture"]
    async fn bench_downlink_throughput() {
        let env = |k: &str, d: u64| {
            std::env::var(k)
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(d)
        };
        let n = env("DNS_BENCH_MIB", 8) as usize * 1024 * 1024;
        let rtt_ms = env("DNS_BENCH_RTT_MS", 0);
        let inflight = env("DNS_BENCH_INFLIGHT", 16) as usize;
        let window = env("DNS_BENCH_WINDOW", 64.max(inflight as u64)) as u32;
        // Scale the RTO/timeout floors above the injected RTT so latency isn't read as loss.
        let round_trip = 2 * rtt_ms;
        let mut c = cfg();
        c.max_query_inflight = inflight;
        c.arq.send_window = window;
        c.arq.min_rto_ms = (round_trip * 2).max(15);
        c.arq.initial_rto_ms = (round_trip * 4).max(60);
        c.query_timeout_ms = (round_trip * 6).max(150);

        let (privkey, server_pub) = keypair();
        let zone = "t.example.com".to_string();
        let server = spawn_flood_server(privkey, zone.clone(), c.clone(), n).await;
        let entry = if rtt_ms > 0 {
            spawn_delay_relay(server, rtt_ms).await.to_string()
        } else {
            server.to_string()
        };
        let transport = DnsTunnelTransport::new(
            zone,
            server_pub,
            vec![entry],
            PoolConfig {
                duplication: 1,
                ..PoolConfig::default()
            },
            c.clone(),
            None,
        );
        let stream = transport
            .dial("93.184.216.34:443".parse().unwrap())
            .await
            .unwrap();
        let (mut rd, mut wr) = tokio::io::split(stream);
        wr.write_all(b"go").await.unwrap(); // kick the stream open → triggers the flood

        let warmup = (n / 8).min(1024 * 1024);
        let mut buf = vec![0u8; 64 * 1024];
        let mut got = 0usize;
        let mut mark: Option<(Instant, usize)> = None;
        while got < n {
            match rd.read(&mut buf).await {
                Ok(0) => break,
                Ok(k) => got += k,
                Err(_) => break,
            }
            if mark.is_none() && got >= warmup {
                mark = Some((Instant::now(), got));
            }
        }
        let (t0, start_bytes) = mark.expect("received at least the warmup");
        let measured = (got - start_bytes) as f64 / (1024.0 * 1024.0);
        let secs = t0.elapsed().as_secs_f64();
        let mibps = measured / secs;
        println!(
            "\n[bench_downlink] rtt={}ms(1-way) inflight={} window={} → steady-state {:.1} MiB in \
             {:.3}s = {:.2} MiB/s ({:.1} Mbit/s)\n",
            rtt_ms,
            c.max_query_inflight,
            c.arq.send_window,
            measured,
            secs,
            mibps,
            mibps * 8.0,
        );
    }

    /// Live end-to-end fetch through a **deployed** server (authoritative mode over the real WAN):
    /// dials a real target *through* the tunnel and does an HTTP GET. Env: `DNS_TUNNEL_SERVER=ip:port`
    /// (required — else the test skips), `DNS_TUNNEL_PUBKEY=<base64 Ed25519>`, `DNS_TUNNEL_ZONE`,
    /// `DNS_TUNNEL_TARGET=ip:port` (default `1.1.1.1:80`), `DNS_TUNNEL_HTTP_HOST` (Host header,
    /// default `one.one.one.one`), `DNS_TUNNEL_PATH` (default `/`). Prints status + bytes + throughput.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "live test; set DNS_TUNNEL_SERVER=ip:port to a deployed server"]
    async fn live_authoritative_fetch() {
        // `DNS_TUNNEL_SERVER` = comma-separated resolver/server list. Authoritative mode: a single
        // `ip:port` (the server). Recursive mode: many public resolvers, e.g. `1.1.1.1,8.8.8.8,9.9.9.9`.
        let Ok(server) = std::env::var("DNS_TUNNEL_SERVER") else {
            eprintln!("skip: set DNS_TUNNEL_SERVER=ip[:port][,ip…]");
            return;
        };
        let servers: Vec<String> = server.split(',').map(|s| s.trim().to_string()).collect();
        let pubkey_b64 = std::env::var("DNS_TUNNEL_PUBKEY").expect("DNS_TUNNEL_PUBKEY");
        let zone = std::env::var("DNS_TUNNEL_ZONE").unwrap_or_else(|_| "t.example.com".into());
        let target: SocketAddr = std::env::var("DNS_TUNNEL_TARGET")
            .unwrap_or_else(|_| "1.1.1.1:80".into())
            .parse()
            .expect("DNS_TUNNEL_TARGET must be ip:port");
        let host =
            std::env::var("DNS_TUNNEL_HTTP_HOST").unwrap_or_else(|_| "one.one.one.one".into());
        let path = std::env::var("DNS_TUNNEL_PATH").unwrap_or_else(|_| "/".into());

        let server_pub = dns_tunnel_core::crypto::decode_server_pub(&pubkey_b64)
            .expect("valid base64 server pubkey");
        let dup = std::env::var("DNS_TUNNEL_DUP")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1usize);
        let transport = DnsTunnelTransport::new(
            zone,
            server_pub,
            servers,
            PoolConfig {
                duplication: dup,
                ..PoolConfig::default()
            },
            SessCfg::default(),
            None,
        );
        let t0 = Instant::now();
        let stream = transport
            .dial(target)
            .await
            .expect("dial through the tunnel");
        let (mut rd, mut wr) = tokio::io::split(stream);
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: spark-dns-tunnel\r\nConnection: close\r\n\r\n"
        );
        wr.write_all(req.as_bytes()).await.expect("send request");
        wr.flush().await.unwrap();
        let mut resp = Vec::new();
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => resp.extend_from_slice(&buf[..n]),
                Err(e) => {
                    eprintln!("read error after {} bytes: {e}", resp.len());
                    break;
                }
            }
        }
        let secs = t0.elapsed().as_secs_f64();
        let text = String::from_utf8_lossy(&resp);
        let status_line = text.lines().next().unwrap_or("(no response)");
        println!(
            "\n[live] {server} → {target} : {} bytes in {:.2}s ({:.1} KB/s) | HTTP status: {}\n",
            resp.len(),
            secs,
            (resp.len() as f64 / 1024.0) / secs,
            status_line,
        );
        assert!(!resp.is_empty(), "received a response through the tunnel");
    }
}
