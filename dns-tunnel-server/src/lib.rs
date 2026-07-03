//! Server for spark's DNS-tunnel transport (ADR 0011): binds a UDP endpoint (the authoritative
//! nameserver side of the tunnel), runs the sans-I/O [`dns_tunnel_core::session::Server`], and does
//! **real TCP egress** — for each multiplexed stream it decodes the SYN's SOCKS5 target,
//! `TcpStream::connect`s it, and bridges that stream's byte channel to/from the socket. One crypto
//! session (ConnectionID) can carry many streams, each with its own independent TCP egress. Includes
//! an idle session sweep.
//!
//! **Log hygiene (ADR 0011 / GOAL.md):** never log the tunnel zone, target addresses, or client/
//! resolver IPs. Log only coarse, non-identifying events.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use dns_tunnel_core::session::{Config, Server};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;

/// A session ConnectionID (matches `dns_tunnel_core`'s 8-byte id).
type ConnId = [u8; 8];

/// A multiplexed stream, addressed by its session and StreamID — one TCP egress each.
type StreamKey = (ConnId, u16);

/// Server configuration.
pub struct ServerConfig {
    /// The delegated tunnel zone (e.g. `t.example.com`).
    pub zone: String,
    /// The server's static Ed25519 private key (PKCS#8 bytes). Its public key is distributed to
    /// clients; the private key authenticates each forward-secret handshake. Keep it secret.
    pub privkey: Vec<u8>,
    /// Session/ARQ tuning (must be compatible with clients — cipher, edns size).
    pub session: Config,
    /// Drop a session with no query for this long (ms).
    pub idle_timeout_ms: u64,
}

/// A message from an egress task back to the core loop.
enum Egress {
    /// Bytes read from the target TCP socket (to deliver to the client as downlink).
    Data(Vec<u8>),
    /// The target closed or the connect failed — tear the session down.
    Eof,
}

/// The core loop's handle on one session's egress task.
struct EgressHandle {
    /// core → egress: uplink bytes to write to the TCP socket.
    tx: mpsc::Sender<Vec<u8>>,
    task: tokio::task::JoinHandle<()>,
}

/// Decode SOCKS5 address bytes (`ATYP ‖ addr ‖ port`) into a `SocketAddr` — mirrors the client's
/// `encode_target`.
fn decode_target(b: &[u8]) -> Option<SocketAddr> {
    match b.first()? {
        0x01 => {
            let ip: [u8; 4] = b.get(1..5)?.try_into().ok()?;
            let port = u16::from_be_bytes(b.get(5..7)?.try_into().ok()?);
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port))
        }
        0x04 => {
            let ip: [u8; 16] = b.get(1..17)?.try_into().ok()?;
            let port = u16::from_be_bytes(b.get(17..19)?.try_into().ok()?);
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port))
        }
        _ => None,
    }
}

/// Run the server on `udp` until a fatal socket error. Does not return on the happy path.
pub async fn serve(udp: UdpSocket, cfg: ServerConfig) -> io::Result<()> {
    let mut server = Server::new(&cfg.privkey, &cfg.zone, cfg.session)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let start = Instant::now();
    let mut buf = vec![0u8; 2048];
    let (egress_tx, mut egress_rx) = mpsc::channel::<(StreamKey, Egress)>(1024);
    let mut egress: HashMap<StreamKey, EgressHandle> = HashMap::new();
    let mut sweep = tokio::time::interval(Duration::from_secs(5));

    loop {
        tokio::select! {
            r = udp.recv_from(&mut buf) => {
                let (n, from) = r?;
                let now = start.elapsed().as_millis() as u64;
                if let Some(ans) = server.on_query(&buf[..n], now) {
                    let _ = udp.send_to(&ans, from).await;
                }
                // Spawn TCP egress for any newly opened stream, then push each stream's uplink bytes.
                for id in server.session_ids() {
                    for (sid, target) in server.open_targets(&id) {
                        let key = (id, sid);
                        match decode_target(&target) {
                            Some(addr) => {
                                let (tx, rx) = mpsc::channel::<Vec<u8>>(64);
                                let task = tokio::spawn(egress_task(key, addr, rx, egress_tx.clone()));
                                egress.insert(key, EgressHandle { tx, task });
                            }
                            // An undecodable target: close just that stream (client sees the FIN).
                            None => server.close_stream(&id, sid),
                        }
                    }
                    for sid in server.streams_of(&id) {
                        let up = server.take_from_client(&id, sid);
                        if !up.is_empty() {
                            // `send().await` applies backpressure (no data loss). A slow target can
                            // stall the loop for other streams — acceptable for v1; fairness later.
                            if let Some(h) = egress.get(&(id, sid)) {
                                if h.tx.send(up.to_vec()).await.is_err() {
                                    drop_stream(&mut server, &mut egress, (id, sid));
                                }
                            }
                        }
                    }
                }
            }
            Some((key, msg)) = egress_rx.recv() => match msg {
                Egress::Data(d) => server.deliver_to_client(&key.0, key.1, &d),
                // The target closed: FIN the stream so the client sees EOF, and retire its egress.
                Egress::Eof => {
                    server.close_stream(&key.0, key.1);
                    if let Some(h) = egress.remove(&key) {
                        h.task.abort();
                    }
                }
            },
            _ = sweep.tick() => {
                let now = start.elapsed().as_millis() as u64;
                for id in server.sweep_idle(now, cfg.idle_timeout_ms) {
                    // Abort every egress task belonging to the swept session.
                    egress.retain(|(cid, _), h| {
                        if *cid == id { h.task.abort(); false } else { true }
                    });
                }
            }
        }
    }
}

fn drop_stream(server: &mut Server, egress: &mut HashMap<StreamKey, EgressHandle>, key: StreamKey) {
    server.close_stream(&key.0, key.1);
    if let Some(h) = egress.remove(&key) {
        h.task.abort();
    }
}

/// Per-stream TCP egress: connect the target, then bridge the TCP socket to/from the stream via
/// channels (reader: TCP → core as downlink; writer: core uplink → TCP).
async fn egress_task(
    key: StreamKey,
    addr: SocketAddr,
    mut rx: mpsc::Receiver<Vec<u8>>,
    etx: mpsc::Sender<(StreamKey, Egress)>,
) {
    let stream = match TcpStream::connect(addr).await {
        Ok(s) => s,
        Err(_) => {
            let _ = etx.send((key, Egress::Eof)).await;
            return;
        }
    };
    let (mut rd, mut wr) = stream.into_split();
    let etx2 = etx.clone();
    let reader = tokio::spawn(async move {
        let mut b = vec![0u8; 16 * 1024];
        loop {
            match rd.read(&mut b).await {
                Ok(0) | Err(_) => {
                    let _ = etx2.send((key, Egress::Eof)).await;
                    return;
                }
                Ok(n) => {
                    if etx2
                        .send((key, Egress::Data(b[..n].to_vec())))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
        }
    });
    while let Some(d) = rx.recv().await {
        if wr.write_all(&d).await.is_err() {
            break;
        }
    }
    reader.abort();
}
