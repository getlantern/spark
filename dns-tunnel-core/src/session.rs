//! Session layer (ADR 0011 §2.3): composes `crypto` + `frame` + `dns` + `arq` into a full DNS-tunnel
//! session, still **sans-I/O**. The caller owns the sockets and clock; this layer turns application
//! bytes into DNS query/answer wire and back.
//!
//! Model: DNS is strictly request→response and the server cannot push, so the **client polls**. Each
//! query carries one uplink frame (or a `KeepAlive` when idle, so the server gets a chance to answer
//! with downlink data); each answer carries at most one downlink frame. Many queries in flight at
//! once give throughput; a lost query is harmless because the ARQ layer re-emits any data frame on its
//! own RTO. A session here carries a **single** reliable stream (one proxied connection) — multiplexing
//! several streams over one session is future work.
//!
//! Handshake: the client sends a long-form `Syn` (carrying the cleartext salt and the target address
//! as payload) sealed with the handshake key; the server derives the per-session keys from
//! `(PSK, salt, ConnectionID)`, dials the target, and replies `SynAck`. Cookie/replay hardening (design
//! §2.3) is deferred to a later milestone; the loopback E2E does not need it.

use std::collections::HashMap;

use bytes::Bytes;

use crate::arq::{self, Stream};
use crate::crypto::{self, Aead, Cipher, SessionKeys, CONN_ID_LEN, SALT_LEN};
use crate::dns::{self, Name};
use crate::frame::{self, Frame, Kind, Wire};
use crate::mtu;

/// The fixed stream id for a session's single proxied connection (M3).
const STREAM_ID: u16 = 1;

/// Conservative upper bound on the inner frame header (version+kind+flags+stream_id+seq+frag+comp),
/// used to size ARQ segments so a sealed data frame always fits its DNS carrier.
const FRAME_HEADER_MAX: usize = 16;

/// Max uplink ARQ segment for a zone: payload bytes that fit in a short-form data frame packed base32
/// into the QNAME. Sizing the ARQ to this is essential — an oversized segment would make the DNS
/// query exceed the 255-byte name limit and never go out.
fn uplink_segment(zone: &Name) -> usize {
    mtu::max_uplink_payload(zone.wire_len(), FRAME_HEADER_MAX, false).max(1)
}

/// Max downlink ARQ segment: payload bytes that fit in a TXT answer, using the worst-case echoed
/// question size (a full 255-byte QNAME + QTYPE/QCLASS).
fn downlink_segment(edns_udp: u16) -> usize {
    const WORST_QUESTION: usize = 255 + 4;
    mtu::max_downlink_payload(edns_udp as usize, WORST_QUESTION, FRAME_HEADER_MAX).max(1)
}

/// Session-layer configuration (shared by client and server).
#[derive(Debug, Clone)]
pub struct Config {
    /// AEAD cipher for the session.
    pub cipher: Cipher,
    /// ARQ tuning.
    pub arq: arq::Config,
    /// EDNS0 UDP payload size advertised on queries/answers.
    pub edns_udp: u16,
    /// Max DNS queries the client keeps in flight at once.
    pub max_query_inflight: usize,
    /// How long (ms) to wait for an answer before freeing the query slot.
    pub query_timeout_ms: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            cipher: Cipher::ChaCha20Poly1305,
            arq: arq::Config::default(),
            edns_udp: 1232,
            max_query_inflight: 16,
            query_timeout_ms: 3_000,
        }
    }
}

/// Session-layer errors.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// The configured PSK was invalid.
    #[error(transparent)]
    Crypto(#[from] crypto::CryptoError),
    /// The tunnel zone was not a valid DNS name.
    #[error(transparent)]
    Dns(#[from] dns::DnsError),
}

/// Build the three directional AEADs for a session from its derived keys.
fn aeads(cipher: Cipher, keys: &SessionKeys) -> Result<(Aead, Aead, Aead), crypto::CryptoError> {
    Ok((
        Aead::new(cipher, &keys.up)?,
        Aead::new(cipher, &keys.down)?,
        Aead::new(cipher, &keys.handshake)?,
    ))
}

/// A DNS query the client has sent and is awaiting an answer for.
struct Outstanding {
    txn: u16,
    deadline: u64,
}

/// The client end of a DNS-tunnel session.
pub struct ClientSession {
    cfg: Config,
    zone: Name,
    conn_id: [u8; CONN_ID_LEN],
    salt: [u8; SALT_LEN],
    up: Aead,
    down: Aead,
    hs: Aead,
    stream: Stream,
    target: Bytes,
    handshake_acked: bool,
    txn: u16,
    outstanding: Vec<Outstanding>,
}

impl ClientSession {
    /// Create a client session for `target` (opaque address bytes the server will dial).
    pub fn new(psk: &[u8], zone: &str, target: &[u8], cfg: Config) -> Result<Self, SessionError> {
        let zone = Name::parse(zone)?;
        let conn_id = crypto::random_conn_id()?;
        let salt = crypto::random_salt()?;
        let keys = crypto::derive_session_keys(psk, &salt, &conn_id);
        let (up, down, hs) = aeads(cfg.cipher, &keys)?;
        // Size the ARQ send segment to the QNAME's uplink capacity for this zone.
        let mut arq_cfg = cfg.arq;
        arq_cfg.max_segment = uplink_segment(&zone);
        Ok(ClientSession {
            zone,
            conn_id,
            salt,
            up,
            down,
            hs,
            stream: Stream::new(STREAM_ID, arq_cfg, 0),
            target: Bytes::copy_from_slice(target),
            handshake_acked: false,
            txn: 0,
            outstanding: Vec::new(),
            cfg,
        })
    }

    /// Queue application bytes to send to the target.
    pub fn write(&mut self, data: &[u8]) {
        self.stream.write(data);
    }

    /// Take received (in-order) bytes from the target.
    pub fn read(&mut self) -> Bytes {
        self.stream.read()
    }

    /// Request a graceful close of the proxied connection.
    pub fn close(&mut self) {
        self.stream.close();
    }

    /// Whether the underlying stream is fully closed/reset.
    pub fn is_closed(&self) -> bool {
        self.stream.is_closed()
    }

    /// Whether the remote signalled EOF.
    pub fn remote_finished(&self) -> bool {
        self.stream.remote_finished()
    }

    fn next_txn(&mut self) -> u16 {
        self.txn = self.txn.wrapping_add(1);
        self.txn
    }

    /// Produce the next DNS query wire bytes to send, or `None` if the in-flight budget is full or
    /// there is nothing useful to send right now.
    pub fn poll_query(&mut self, now: u64) -> Option<Vec<u8>> {
        // Free timed-out query slots (their frames, if any, will be re-sent by ARQ's RTO).
        self.outstanding.retain(|o| o.deadline > now);
        if self.outstanding.len() >= self.cfg.max_query_inflight {
            return None;
        }

        // Choose the wire packet to carry. Before the handshake is acknowledged only the SYN is sent
        // (re-sent whenever no query is outstanding, so a lost SYN can't stall); data waits until the
        // session is established.
        let wire: Vec<u8> = if !self.handshake_acked {
            if !self.outstanding.is_empty() {
                return None; // a SYN is already in flight
            }
            let nonce = crypto::random_nonce().ok()?;
            let mut syn = Frame::new(Kind::Syn);
            syn.payload = self.target.clone();
            frame::seal_long(&self.hs, &self.conn_id, &self.salt, &nonce, &syn)
        } else if let Some(f) = self.stream.poll_transmit(now) {
            let nonce = crypto::random_nonce().ok()?;
            frame::seal_short(&self.up, &self.conn_id, &nonce, &f)
        } else if !self.stream.is_closed() {
            // Idle keepalive: poll the server for downlink data.
            let nonce = crypto::random_nonce().ok()?;
            frame::seal_short(
                &self.up,
                &self.conn_id,
                &nonce,
                &Frame::new(Kind::KeepAlive),
            )
        } else {
            return None;
        };

        let txn = self.next_txn();
        let query = dns::build_query(txn, &wire, &self.zone, self.cfg.edns_udp).ok()?;
        self.outstanding.push(Outstanding {
            txn,
            deadline: now + self.cfg.query_timeout_ms,
        });
        Some(query)
    }

    /// Process a DNS answer received for a prior query.
    pub fn on_answer(&mut self, answer: &[u8], now: u64) {
        let Ok(parsed) = dns::parse_answer(answer) else {
            return;
        };
        // Free the matching query slot.
        if let Some(pos) = self.outstanding.iter().position(|o| o.txn == parsed.txn_id) {
            self.outstanding.swap_remove(pos);
        }
        if parsed.data.is_empty() {
            return; // server had nothing to send
        }
        let Ok(wire) = frame::parse_wire(&parsed.data) else {
            return;
        };
        if !self.handshake_acked {
            // Expect the SynAck, sealed with the handshake key.
            if let Ok(f) = frame::open_frame(&self.hs, &wire) {
                if f.kind == Kind::SynAck {
                    self.handshake_acked = true;
                }
            }
        } else if let Ok(f) = frame::open_frame(&self.down, &wire) {
            self.stream.on_frame(&f, now);
        }
    }

    /// The current send-side timeout hint (ms) for scheduling the next `poll_query`.
    pub fn next_deadline(&self) -> Option<u64> {
        self.stream.next_deadline()
    }
}

/// One server-side session (created on a valid SYN), keyed by ConnectionID.
struct ServerSession {
    up: Aead,
    down: Aead,
    hs: Aead,
    stream: Stream,
    /// The target address bytes the client asked for (the server binary dials this).
    target: Bytes,
}

/// The server endpoint: routes DNS tunnel queries to per-ConnectionID sessions and produces answers.
/// I/O (binding UDP, the TCP egress) is the caller's job; this is the sans-I/O core.
pub struct Server {
    psk: Vec<u8>,
    zone: Name,
    cfg: Config,
    sessions: HashMap<[u8; CONN_ID_LEN], ServerSession>,
}

impl Server {
    /// Create a server for a tunnel `zone` and pre-shared key.
    pub fn new(psk: &[u8], zone: &str, cfg: Config) -> Result<Self, SessionError> {
        Ok(Server {
            psk: psk.to_vec(),
            zone: Name::parse(zone)?,
            cfg,
            sessions: HashMap::new(),
        })
    }

    /// The target a freshly-established session wants dialed (for the egress), if any new since last
    /// call. Returns `(conn_id, target_bytes)` — the caller wires up TCP egress for it.
    pub fn take_new_target(&mut self, conn_id: &[u8; CONN_ID_LEN]) -> Option<Bytes> {
        self.sessions.get(conn_id).map(|s| s.target.clone())
    }

    /// Feed egress bytes (from the dialed target) into a session's stream.
    pub fn deliver_to_client(&mut self, conn_id: &[u8; CONN_ID_LEN], data: &[u8]) {
        if let Some(s) = self.sessions.get_mut(conn_id) {
            s.stream.write(data);
        }
    }

    /// Take bytes a session has received from the client (to write to the egress).
    pub fn take_from_client(&mut self, conn_id: &[u8; CONN_ID_LEN]) -> Bytes {
        self.sessions
            .get_mut(conn_id)
            .map(|s| s.stream.read())
            .unwrap_or_default()
    }

    /// Whether a session exists.
    pub fn has_session(&self, conn_id: &[u8; CONN_ID_LEN]) -> bool {
        self.sessions.contains_key(conn_id)
    }

    /// The ConnectionIDs of all live sessions (so the caller can pump each one's TCP egress).
    pub fn session_ids(&self) -> Vec<[u8; CONN_ID_LEN]> {
        self.sessions.keys().copied().collect()
    }

    /// Process a DNS tunnel query and produce the answer wire bytes. Returns `None` for a query that
    /// is not a valid tunnel query under our zone (the caller drops it — ordinary malformed DNS).
    pub fn on_query(&mut self, query: &[u8], now: u64) -> Option<Vec<u8>> {
        let parsed = dns::parse_query(query, &self.zone).ok()?;
        let wire = frame::parse_wire(&parsed.data).ok()?;

        if wire.salt.is_some() {
            self.handle_syn(query, &wire)
        } else {
            self.handle_data(query, &wire, now)
        }
    }

    fn handle_syn(&mut self, query: &[u8], wire: &Wire<'_>) -> Option<Vec<u8>> {
        let salt = wire.salt?;
        let keys = crypto::derive_session_keys(&self.psk, &salt, &wire.conn_id);
        let (up, down, hs) = aeads(self.cfg.cipher, &keys).ok()?;
        // Authenticate + read the SYN under the handshake key.
        let syn = frame::open_frame(&hs, wire).ok()?;
        if syn.kind != Kind::Syn {
            return None;
        }
        // Size the server's ARQ send segment to the TXT answer's downlink capacity.
        let mut arq_cfg = self.cfg.arq;
        arq_cfg.max_segment = downlink_segment(self.cfg.edns_udp);
        // (Re)establish the session. A repeated SYN (retransmit) just resets it — fine for M3.
        self.sessions.insert(
            wire.conn_id,
            ServerSession {
                up,
                down,
                hs,
                stream: Stream::new(STREAM_ID, arq_cfg, 0),
                target: syn.payload.clone(),
            },
        );
        // Reply SynAck under the handshake key.
        let sess = self.sessions.get(&wire.conn_id)?;
        let nonce = crypto::random_nonce().ok()?;
        let ack_wire =
            frame::seal_short(&sess.hs, &wire.conn_id, &nonce, &Frame::new(Kind::SynAck));
        dns::build_answer(query, &ack_wire, self.cfg.edns_udp).ok()
    }

    fn handle_data(&mut self, query: &[u8], wire: &Wire<'_>, now: u64) -> Option<Vec<u8>> {
        let sess = self.sessions.get_mut(&wire.conn_id)?;
        // Open the uplink frame and feed the ARQ.
        if let Ok(f) = frame::open_frame(&sess.up, wire) {
            sess.stream.on_frame(&f, now);
        }
        // Answer with the next downlink frame (data / ack / …), or an empty answer if none.
        let downlink = match sess.stream.poll_transmit(now) {
            Some(f) => {
                let nonce = crypto::random_nonce().ok()?;
                frame::seal_short(&sess.down, &wire.conn_id, &nonce, &f)
            }
            None => Vec::new(),
        };
        dns::build_answer(query, &downlink, self.cfg.edns_udp).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic query/answer sim: carries DNS *bytes* between client and server with loss +
    /// reorder + latency. (Duplication is exercised by the ARQ tests; here we focus on the poll loop.)
    struct Net {
        latency: u64,
        drop_pct: u32,
        reorder_pct: u32,
        rng: u64,
        counter: u64,
        // (deliver_at, tiebreak, bytes)
        queries: Vec<(u64, u64, Vec<u8>)>,
        answers: Vec<(u64, u64, Vec<u8>)>,
    }

    impl Net {
        fn new(latency: u64, drop_pct: u32, reorder_pct: u32, seed: u64) -> Self {
            Net {
                latency,
                drop_pct,
                reorder_pct,
                rng: seed | 1,
                counter: 0,
                queries: Vec::new(),
                answers: Vec::new(),
            }
        }
        fn rand(&mut self) -> u32 {
            let mut x = self.rng;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.rng = x;
            (x.wrapping_mul(0x2545F491_4F6CDD1D) >> 33) as u32
        }
        fn chance(&mut self, pct: u32) -> bool {
            self.rand() % 100 < pct
        }
        fn push(&mut self, to_server: bool, bytes: Vec<u8>, now: u64) {
            if self.chance(self.drop_pct) {
                return;
            }
            let extra = if self.chance(self.reorder_pct) {
                self.latency + (self.rand() as u64 % 40)
            } else {
                0
            };
            let at = now + self.latency + extra;
            let c = self.counter;
            self.counter += 1;
            if to_server {
                self.queries.push((at, c, bytes));
            } else {
                self.answers.push((at, c, bytes));
            }
        }
        fn due(&mut self, from_server_side: bool, now: u64) -> Vec<Vec<u8>> {
            let q = if from_server_side {
                &mut self.queries
            } else {
                &mut self.answers
            };
            let mut due: Vec<(u64, u64, Vec<u8>)> =
                q.iter().filter(|(at, _, _)| *at <= now).cloned().collect();
            q.retain(|(at, _, _)| *at > now);
            due.sort_by_key(|(at, c, _)| (*at, *c));
            due.into_iter().map(|(_, _, b)| b).collect()
        }
    }

    fn payload_of(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(53).wrapping_add(17))
            .collect()
    }

    /// Drive a full echo session: client sends `payload`; the server echoes every byte back; assert the
    /// client receives the echo intact. Exercises handshake + bidirectional data over the poll model.
    fn run_echo(net: &mut Net, payload: &[u8], max_steps: u64) -> Vec<u8> {
        let psk = [0x11u8; 32];
        let zone = "t.example.com";
        let cfg = Config {
            arq: arq::Config {
                initial_rto_ms: 80,
                min_rto_ms: 20,
                ..arq::Config::default()
            },
            query_timeout_ms: 500,
            max_query_inflight: 8,
            ..Config::default()
        };
        let mut client = ClientSession::new(&psk, zone, b"1.2.3.4:443", cfg.clone()).unwrap();
        let mut server = Server::new(&psk, zone, cfg).unwrap();
        client.write(payload);
        client.close(); // half-close after the payload so the echo terminates

        let conn = client.conn_id;
        let mut echoed = Vec::new();
        for now in 0..max_steps {
            while let Some(q) = client.poll_query(now) {
                net.push(true, q, now);
            }
            for q in net.due(true, now) {
                if let Some(ans) = server.on_query(&q, now) {
                    net.push(false, ans, now);
                }
            }
            // Server egress = echo: whatever the client sent, write straight back.
            if server.has_session(&conn) {
                let got = server.take_from_client(&conn);
                if !got.is_empty() {
                    server.deliver_to_client(&conn, &got);
                }
            }
            for ans in net.due(false, now) {
                client.on_answer(&ans, now);
            }
            echoed.extend_from_slice(&client.read());
            if echoed.len() >= payload.len() {
                break;
            }
        }
        echoed
    }

    #[test]
    fn manual_flow_handshake_uplink_downlink() {
        // Step the handshake + one uplink + one downlink by hand (no sim) to pin each stage.
        let psk = [0x11u8; 32];
        let zone = "t.example.com";
        let cfg = Config::default();
        let mut client = ClientSession::new(&psk, zone, b"1.2.3.4:443", cfg.clone()).unwrap();
        let mut server = Server::new(&psk, zone, cfg).unwrap();
        client.write(b"hello world");
        let conn = client.conn_id;

        let q = client.poll_query(0).expect("SYN query");
        let a = server.on_query(&q, 0).expect("SYNACK answer");
        client.on_answer(&a, 0);
        assert!(client.handshake_acked, "handshake completes");

        let q2 = client.poll_query(1).expect("data query");
        let _a2 = server.on_query(&q2, 1).expect("data answer");
        assert_eq!(
            &server.take_from_client(&conn)[..],
            b"hello world",
            "server delivers the uplink bytes"
        );

        // Echo back, then poll for the downlink.
        server.deliver_to_client(&conn, b"hello world");
        let q3 = client.poll_query(2).expect("poll query");
        let a3 = server.on_query(&q3, 2).expect("downlink answer");
        client.on_answer(&a3, 2);
        assert_eq!(
            &client.read()[..],
            b"hello world",
            "client receives the echo"
        );
    }

    #[test]
    fn handshake_and_echo_over_perfect_net() {
        let mut net = Net::new(5, 0, 0, 0xC0FFEE);
        let payload = payload_of(8_192);
        let echoed = run_echo(&mut net, &payload, 2_000_000);
        assert_eq!(echoed, payload);
    }

    #[test]
    fn handshake_and_echo_over_lossy_reordering_net() {
        let mut net = Net::new(5, 20, 30, 0xBADF00D);
        let payload = payload_of(4_096);
        let echoed = run_echo(&mut net, &payload, 5_000_000);
        assert_eq!(echoed, payload);
    }

    #[test]
    fn server_ignores_garbage_and_wrong_zone() {
        let cfg = Config::default();
        let mut server = Server::new(&[0x22u8; 32], "t.example.com", cfg.clone()).unwrap();
        // Random garbage is not a tunnel query.
        assert!(server.on_query(b"\x00\x01\x02not-dns", 0).is_none());
        // A well-formed query under the wrong zone is refused.
        let other = Name::parse("t.evil.example").unwrap();
        let q = dns::build_query(1, &[0u8; 40], &other, 1232).unwrap();
        assert!(server.on_query(&q, 0).is_none());
    }
}
