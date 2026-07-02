//! DNS-tunnel transport (ADR 0011): a [`Transport`] that tunnels a TCP byte-stream over DNS by
//! driving the sans-I/O [`dns_tunnel_core::session::ClientSession`] over a UDP socket.
//!
//! v1 is **authoritative mode**: `dial` talks DNS straight to the tunnel server's UDP address
//! (`transport.dns-tunnel.authoritative`). Recursive-resolver *aggregation* — spraying queries across
//! a pool of public resolvers with per-resolver health/failover — is the headline capability and lands
//! in M4 (this is the single-path skeleton it builds on).
//!
//! The DNS carrier is request→response and the server can't push, so a background **pump** task per
//! dial keeps polling: it flushes the session's outbound queries, drains all ready answers, delivers
//! received bytes to the application, and wakes on a keepalive/RTO tick so downlink data and
//! retransmits still flow when the app is idle. The returned stream owns the pump's `JoinHandle` and
//! aborts it on drop.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::net::UdpSocket;

use dns_tunnel_core::session::{self, ClientSession};

use crate::net::SocketProtector;
use crate::transport::{protected_udp_socket, Transport};
use crate::BoxedStream;

/// Resolver pool + balancer (ADR 0011 §4): the headline resolver aggregation — pool parse/expand,
/// per-resolver RTT/loss health, duplication, and per-stream sticky failover. Wired into the pump's
/// resolver mode.
pub mod balancer;

/// The app-facing duplex buffer size (bytes) between the caller's stream and the pump.
const DUPLEX_BUF: usize = 64 * 1024;
/// The keepalive/RTO wakeup cadence (ms): drives downlink polling + retransmits while idle.
const TICK_MS: u64 = 20;

/// A DNS-tunnel transport (authoritative mode). Cheap to clone; one pump task is spawned per `dial`.
#[derive(Clone)]
pub struct DnsTunnelTransport {
    inner: Arc<Inner>,
}

struct Inner {
    zone: String,
    psk: Vec<u8>,
    server: SocketAddr,
    cfg: session::Config,
    protector: Option<SocketProtector>,
}

impl DnsTunnelTransport {
    /// Build the transport. `psk` is the already-decoded pre-shared key (≥32 bytes); `server` is the
    /// authoritative tunnel-server UDP address; `cfg` carries the cipher + ARQ/poll tuning.
    pub fn new(
        zone: String,
        psk: Vec<u8>,
        server: SocketAddr,
        cfg: session::Config,
        protector: Option<SocketProtector>,
    ) -> Self {
        DnsTunnelTransport {
            inner: Arc::new(Inner {
                zone,
                psk,
                server,
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
        let session = ClientSession::new(&i.psk, &i.zone, &encode_target(&target), i.cfg.clone())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

        // A protector-pinned UDP socket, connected to the authoritative server so its own packets
        // bypass the tunnel route (like the other transports).
        let sock = protected_udp_socket(i.server, i.protector.as_ref())?;
        let std_sock: std::net::UdpSocket = sock.into();
        let udp = UdpSocket::from_std(std_sock)?;
        udp.connect(i.server).await?;

        let (app_side, pump_side) = tokio::io::duplex(DUPLEX_BUF);
        let pump = tokio::spawn(run_pump(session, udp, pump_side));
        Ok(Box::new(PumpStream {
            inner: app_side,
            pump,
        }))
    }
}

/// The background driver for one session: flush queries, drain answers, deliver downlink, tick.
async fn run_pump(mut session: ClientSession, udp: UdpSocket, mut io: DuplexStream) {
    use tokio::io::AsyncWriteExt;

    let start = Instant::now();
    let mut dns_buf = vec![0u8; 2048];
    let mut app_buf = vec![0u8; 16 * 1024];
    let mut ticker = tokio::time::interval(Duration::from_millis(TICK_MS));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        let now = start.elapsed().as_millis() as u64;

        // Drain every answer that's ready (bursts arrive faster than one select wake).
        loop {
            match udp.try_recv(&mut dns_buf) {
                Ok(n) => session.on_answer(&dns_buf[..n], now),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => return,
            }
        }

        // Flush all queries the session wants to send.
        while let Some(q) = session.poll_query(now) {
            if udp.send(&q).await.is_err() {
                return;
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

        // Wait for the next event: socket readable (then loop drains), app bytes, or the tick.
        tokio::select! {
            r = udp.readable() => {
                if r.is_err() {
                    return;
                }
            }
            r = io.read(&mut app_buf) => match r {
                Ok(0) => session.close(),          // app closed its write half → half-close
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

use tokio::io::AsyncReadExt as _; // for `io.read` in the pump

#[cfg(test)]
mod tests {
    use super::*;
    use dns_tunnel_core::arq;
    use dns_tunnel_core::session::{Config as SessCfg, Server};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A minimal in-test authoritative server: answer tunnel queries and echo every received byte back
    /// (stand-in for the TCP egress, which is the M4 server binary's job).
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
            // Echo egress: feed each session's received bytes straight back as downlink.
            for id in server.session_ids() {
                let d = server.take_from_client(&id);
                if !d.is_empty() {
                    server.deliver_to_client(&id, &d);
                }
            }
        }
    }

    fn test_cfg() -> SessCfg {
        SessCfg {
            arq: arq::Config {
                initial_rto_ms: 60,
                min_rto_ms: 15,
                ..arq::Config::default()
            },
            query_timeout_ms: 400,
            max_query_inflight: 16,
            ..SessCfg::default()
        }
    }

    #[tokio::test]
    async fn loopback_authoritative_round_trip() {
        // Scaled-down loopback gate: a real UDP round-trip through the full stack (dial → handshake →
        // stream → data → echo) proving multi-thousand-segment bidirectional reliable transfer.
        let server_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_udp.local_addr().unwrap();
        let psk = vec![0x11u8; 32];
        let zone = "t.example.com".to_string();
        let cfg = test_cfg();
        tokio::spawn(echo_server(
            server_udp,
            psk.clone(),
            zone.clone(),
            cfg.clone(),
        ));

        let transport = DnsTunnelTransport::new(zone, psk, server_addr, cfg, None);
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let stream = transport.dial(target).await.unwrap();
        let (mut rd, mut wr) = tokio::io::split(stream);

        const LEN: usize = 512 * 1024;
        let payload: Vec<u8> = (0..LEN).map(|i| (i as u8).wrapping_mul(37)).collect();
        let p2 = payload.clone();
        let writer = tokio::spawn(async move {
            wr.write_all(&p2).await.unwrap();
            wr.flush().await.unwrap();
        });

        let mut got = vec![0u8; LEN];
        rd.read_exact(&mut got).await.unwrap();
        writer.await.unwrap();
        assert_eq!(
            got, payload,
            "the full payload round-trips through the DNS tunnel"
        );
    }
}
