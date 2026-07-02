//! Session layer (ADR 0011 §2.3): composes `crypto` + `frame` + `dns` + `arq` into a full DNS-tunnel
//! session, still **sans-I/O**. The caller owns the sockets and clock; this layer turns application
//! bytes into DNS query/answer wire and back.
//!
//! Model: DNS is strictly request→response and the server cannot push, so the **client polls**. Each
//! query carries one uplink frame (or a `KeepAlive` when idle, so the server gets a chance to answer
//! with downlink data); each answer carries at most one downlink frame. Many queries in flight at
//! once give throughput; a lost query is harmless because the ARQ layer re-emits any data frame on its
//! own RTO.
//!
//! Multiplexing: one crypto session (one ConnectionID + key schedule) carries **many** reliable
//! streams, each an independent [`Stream`] keyed by a 16-bit StreamID. The uplink poll and the downlink
//! poll both **round-robin** across a session's streams so no single stream starves the others. This is
//! the DNS-tunnel analogue of HTTP/2 or smux: the expensive part (the handshake / key schedule) is
//! paid once, and new proxied connections are cheap logical streams over it.
//!
//! Handshake & stream open: the client sends a long-form `Syn` (carrying the cleartext salt and the
//! *first* stream's target as payload) sealed with the handshake key; the server derives the
//! per-session keys from `(PSK, salt, ConnectionID)`, opens stream 1 to that target, and replies
//! `SynAck` — so the first proxied connection costs a single round trip. Additional streams open after
//! establishment with a cheap short-form `Syn` (StreamID + target, sealed under the session's uplink
//! key), retried until the server returns a per-stream `SynAck`. Cookie/replay hardening (design §2.3)
//! is deferred to a later milestone; the loopback E2E does not need it.

use std::collections::BTreeMap;

use bytes::Bytes;

use crate::arq::{self, Stream};
use crate::crypto::{self, Aead, Cipher, SessionKeys, CONN_ID_LEN, SALT_LEN};
use crate::dns::{self, Name};
use crate::frame::{self, Frame, Kind, Wire};
use crate::mtu;

/// A session ConnectionID.
type ConnId = [u8; CONN_ID_LEN];

/// The StreamID of the first stream, which opens as part of the session handshake (its target rides
/// the SYN). The single-stream convenience API (`write`/`read`/`close`) operates on this stream.
pub const PRIMARY_STREAM_ID: u16 = 1;

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
    /// Max DNS queries the client keeps in flight at once. This is the **dominant throughput lever**:
    /// a DNS tunnel is bandwidth-delay-product bound, so goodput ≈ `max_query_inflight × (downlink
    /// bytes per answer) / RTT`. Raising it scales throughput ~linearly (loopback bench: 50 ms RTT
    /// gives ~2.6 Mbit/s at 16, ~10 at 64, ~20 at 128). It should be spread across the resolver pool
    /// so no single recursive resolver sees more than ~`max_query_inflight / pool_size` concurrent
    /// queries (which would look anomalous / get rate-limited).
    pub max_query_inflight: usize,
    /// How long (ms) to wait for an answer before freeing the query slot.
    pub query_timeout_ms: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            cipher: Cipher::ChaCha20Poly1305,
            // Deepen the ARQ pipeline to match the query budget: the send window must be ≥ the query
            // budget or it re-bottlenecks the pull model, and the receive window absorbs the reorder
            // from spraying that many queries across resolvers with differing latencies.
            arq: arq::Config {
                send_window: 256,
                recv_window: 1024,
                ..arq::Config::default()
            },
            edns_udp: 1232,
            // 64 (vs a timid 16) ≈ 4× real-world throughput; still modest per-resolver once spread
            // across a pool. See `max_query_inflight`.
            max_query_inflight: 64,
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

/// Largest MTU-probe payload the server will pad a response to (a sane DNS-over-UDP ceiling).
const MAX_PROBE_PAYLOAD: usize = 4096;

/// Read a big-endian u16 from the front of `b`.
fn read_u16(b: &[u8]) -> Option<u16> {
    b.get(..2).map(|s| u16::from_be_bytes([s[0], s[1]]))
}

/// What [`ClientSession::on_answer`] did with an answer, so the pump can react to control frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnswerOutcome {
    /// A normal answer (SYN-ACK, data, ack, or empty) was consumed into the session.
    Consumed,
    /// A downlink MTU-probe response for `target` payload bytes returned intact — that downlink size
    /// works on the path the answer came back over.
    ProbeResp { target: u16 },
}

/// A DNS query the client has sent and is awaiting an answer for.
struct Outstanding {
    txn: u16,
    deadline: u64,
}

/// One logical stream on the client side of a session.
struct ClientStream {
    stream: Stream,
    /// The opaque target address bytes the server dials for this stream.
    target: Bytes,
    /// The stream's open has been acknowledged (its `SynAck` arrived).
    open_acked: bool,
    /// This stream opened as part of the session handshake (stream 1) — no separate open `Syn`.
    via_handshake: bool,
    /// When the open `Syn` was last (re)sent (ms) — for open retransmission (streams ≥ 2).
    last_open_ms: Option<u64>,
}

/// The client end of a DNS-tunnel session, multiplexing many streams over one key schedule.
pub struct ClientSession {
    cfg: Config,
    zone: Name,
    conn_id: ConnId,
    salt: [u8; SALT_LEN],
    up: Aead,
    down: Aead,
    hs: Aead,
    /// ARQ config for new streams (uplink-segment sized for this zone).
    up_arq_cfg: arq::Config,
    /// Live streams, ordered by id for deterministic round-robin.
    streams: BTreeMap<u16, ClientStream>,
    /// Next StreamID to hand out (stream 1 is taken by the handshake).
    next_stream_id: u16,
    /// Round-robin cursor: the id served most recently by the uplink poll.
    rr_last: u16,
    handshake_acked: bool,
    txn: u16,
    outstanding: Vec<Outstanding>,
}

impl ClientSession {
    /// Create a client session whose first stream targets `target` (opaque address bytes the server
    /// will dial). The first stream opens as part of the handshake; open more with [`open_stream`].
    ///
    /// [`open_stream`]: Self::open_stream
    pub fn new(psk: &[u8], zone: &str, target: &[u8], cfg: Config) -> Result<Self, SessionError> {
        let zone = Name::parse(zone)?;
        let conn_id = crypto::random_conn_id()?;
        let salt = crypto::random_salt()?;
        let keys = crypto::derive_session_keys(psk, &salt, &conn_id);
        let (up, down, hs) = aeads(cfg.cipher, &keys)?;
        // Size the ARQ send segment to the QNAME's uplink capacity for this zone.
        let mut up_arq_cfg = cfg.arq;
        up_arq_cfg.max_segment = uplink_segment(&zone);
        let mut streams = BTreeMap::new();
        streams.insert(
            PRIMARY_STREAM_ID,
            ClientStream {
                stream: Stream::new(PRIMARY_STREAM_ID, up_arq_cfg, 0),
                target: Bytes::copy_from_slice(target),
                open_acked: false,
                via_handshake: true,
                last_open_ms: None,
            },
        );
        Ok(ClientSession {
            zone,
            conn_id,
            salt,
            up,
            down,
            hs,
            up_arq_cfg,
            streams,
            next_stream_id: PRIMARY_STREAM_ID + 1,
            rr_last: 0,
            handshake_acked: false,
            txn: 0,
            outstanding: Vec::new(),
            cfg,
        })
    }

    /// Open a new multiplexed stream to `target` and return its StreamID. The open `Syn` is sent (and
    /// retried) by [`poll_query`] once the session handshake has completed; bytes written before the
    /// stream's `SynAck` arrives are buffered and flushed after it opens.
    ///
    /// [`poll_query`]: Self::poll_query
    pub fn open_stream(&mut self, target: &[u8]) -> u16 {
        // Skip 0 and the primary id on wrap (collisions are astronomically unlikely in practice).
        let mut sid = self.next_stream_id;
        while sid == 0 || sid == PRIMARY_STREAM_ID || self.streams.contains_key(&sid) {
            sid = sid.wrapping_add(1);
        }
        self.next_stream_id = sid.wrapping_add(1);
        self.streams.insert(
            sid,
            ClientStream {
                stream: Stream::new(sid, self.up_arq_cfg, 0),
                target: Bytes::copy_from_slice(target),
                open_acked: false,
                via_handshake: false,
                last_open_ms: None,
            },
        );
        sid
    }

    /// Queue application bytes for stream `sid`.
    pub fn write_stream(&mut self, sid: u16, data: &[u8]) {
        if let Some(s) = self.streams.get_mut(&sid) {
            s.stream.write(data);
        }
    }

    /// Take received (in-order) bytes for stream `sid`.
    pub fn read_stream(&mut self, sid: u16) -> Bytes {
        self.streams
            .get_mut(&sid)
            .map(|s| s.stream.read())
            .unwrap_or_default()
    }

    /// Request a graceful close of stream `sid`.
    pub fn close_stream(&mut self, sid: u16) {
        if let Some(s) = self.streams.get_mut(&sid) {
            s.stream.close();
        }
    }

    /// Whether stream `sid` is fully closed/reset (or gone).
    pub fn is_stream_closed(&self, sid: u16) -> bool {
        self.streams
            .get(&sid)
            .map(|s| s.stream.is_closed())
            .unwrap_or(true)
    }

    /// Whether stream `sid`'s remote half signalled EOF.
    pub fn stream_remote_finished(&self, sid: u16) -> bool {
        self.streams
            .get(&sid)
            .map(|s| s.stream.remote_finished())
            .unwrap_or(false)
    }

    /// The live StreamIDs (for the caller to drive per-stream I/O), ordered by id.
    pub fn stream_ids(&self) -> Vec<u16> {
        self.streams.keys().copied().collect()
    }

    /// Drop fully-closed streams and return their ids (so the caller can tear down their I/O). Keeps
    /// the session alive for its remaining streams.
    pub fn reap_closed(&mut self) -> Vec<u16> {
        let closed: Vec<u16> = self
            .streams
            .iter()
            .filter(|(_, s)| s.stream.is_closed())
            .map(|(id, _)| *id)
            .collect();
        for id in &closed {
            self.streams.remove(id);
        }
        closed
    }

    /// Queue application bytes on the primary stream (single-stream convenience).
    pub fn write(&mut self, data: &[u8]) {
        self.write_stream(PRIMARY_STREAM_ID, data);
    }

    /// Take received bytes from the primary stream (single-stream convenience).
    pub fn read(&mut self) -> Bytes {
        self.read_stream(PRIMARY_STREAM_ID)
    }

    /// Gracefully close the primary stream (single-stream convenience).
    pub fn close(&mut self) {
        self.close_stream(PRIMARY_STREAM_ID);
    }

    /// Whether the primary stream is fully closed (single-stream convenience).
    pub fn is_closed(&self) -> bool {
        self.is_stream_closed(PRIMARY_STREAM_ID)
    }

    /// Whether the primary stream's remote signalled EOF (single-stream convenience).
    pub fn remote_finished(&self) -> bool {
        self.stream_remote_finished(PRIMARY_STREAM_ID)
    }

    /// Whether the session handshake has completed (the SYN-ACK arrived).
    pub fn is_established(&self) -> bool {
        self.handshake_acked
    }

    /// Whether stream `sid` is open (its open has been acknowledged, or it rode the handshake).
    fn stream_open(&self, sid: u16) -> bool {
        match self.streams.get(&sid) {
            Some(s) => s.open_acked || (s.via_handshake && self.handshake_acked),
            None => false,
        }
    }

    /// Whether any stream is still alive (so a keepalive is worth sending to poll for downlink).
    fn any_stream_alive(&self) -> bool {
        self.streams.values().any(|s| !s.stream.is_closed())
    }

    fn next_txn(&mut self) -> u16 {
        self.txn = self.txn.wrapping_add(1);
        self.txn
    }

    /// Build the next pending stream-open `Syn` (short form) whose retransmit timer is due, if any.
    fn next_open_syn(&mut self, now: u64) -> Option<Vec<u8>> {
        let open_rto = self.up_arq_cfg.initial_rto_ms;
        let sid = self
            .streams
            .iter()
            .find(|(_, s)| {
                !s.open_acked
                    && !s.via_handshake
                    && s.last_open_ms
                        .is_none_or(|t| now.saturating_sub(t) >= open_rto)
            })
            .map(|(id, _)| *id)?;
        let target = self.streams.get(&sid)?.target.clone();
        let nonce = crypto::random_nonce().ok()?;
        let mut syn = Frame::new(Kind::Syn);
        syn.stream_id = Some(sid);
        syn.payload = target;
        let wire = frame::seal_short(&self.up, &self.conn_id, &nonce, &syn);
        if let Some(s) = self.streams.get_mut(&sid) {
            s.last_open_ms = Some(now);
        }
        Some(wire)
    }

    /// Round-robin the streams and pull the next frame to transmit from the first open stream that has
    /// one, so no stream starves the others under a shared query budget.
    fn next_stream_frame(&mut self, now: u64) -> Option<Frame> {
        let ids: Vec<u16> = self.streams.keys().copied().collect();
        if ids.is_empty() {
            return None;
        }
        let start = ids.iter().position(|&id| id > self.rr_last).unwrap_or(0);
        let n = ids.len();
        for k in 0..n {
            let id = ids[(start + k) % n];
            if !self.stream_open(id) {
                continue;
            }
            if let Some(s) = self.streams.get_mut(&id) {
                if let Some(f) = s.stream.poll_transmit(now) {
                    self.rr_last = id;
                    return Some(f);
                }
            }
        }
        None
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
        // (re-sent whenever no query is outstanding, so a lost SYN can't stall). After establishment:
        // first flush any pending stream-open, then round-robin stream data, then an idle keepalive.
        let wire: Vec<u8> = if !self.handshake_acked {
            if !self.outstanding.is_empty() {
                return None; // a SYN is already in flight
            }
            let nonce = crypto::random_nonce().ok()?;
            let mut syn = Frame::new(Kind::Syn);
            syn.payload = self
                .streams
                .get(&PRIMARY_STREAM_ID)
                .map(|s| s.target.clone())
                .unwrap_or_default();
            frame::seal_long(&self.hs, &self.conn_id, &self.salt, &nonce, &syn)
        } else if let Some(w) = self.next_open_syn(now) {
            w
        } else if let Some(f) = self.next_stream_frame(now) {
            let nonce = crypto::random_nonce().ok()?;
            frame::seal_short(&self.up, &self.conn_id, &nonce, &f)
        } else if self.any_stream_alive() {
            // Idle keepalive: poll the server for downlink data (and any pending stream SynAck).
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
    pub fn on_answer(&mut self, answer: &[u8], now: u64) -> AnswerOutcome {
        let Ok(parsed) = dns::parse_answer(answer) else {
            return AnswerOutcome::Consumed;
        };
        // Free the matching query slot (probe/SetMtu queries aren't tracked here — the pump owns them).
        if let Some(pos) = self.outstanding.iter().position(|o| o.txn == parsed.txn_id) {
            self.outstanding.swap_remove(pos);
        }
        if parsed.data.is_empty() {
            return AnswerOutcome::Consumed; // server had nothing to send
        }
        let Ok(wire) = frame::parse_wire(&parsed.data) else {
            return AnswerOutcome::Consumed;
        };
        if !self.handshake_acked {
            // Expect the session SynAck, sealed with the handshake key; it also opens stream 1.
            if let Ok(f) = frame::open_frame(&self.hs, &wire) {
                if f.kind == Kind::SynAck {
                    self.handshake_acked = true;
                    if let Some(s) = self.streams.get_mut(&PRIMARY_STREAM_ID) {
                        s.open_acked = true;
                    }
                }
            }
            return AnswerOutcome::Consumed;
        }
        if let Ok(f) = frame::open_frame(&self.down, &wire) {
            match f.kind {
                Kind::MtuProbeResp => {
                    return AnswerOutcome::ProbeResp {
                        target: read_u16(&f.payload).unwrap_or(0),
                    };
                }
                // A per-stream open acknowledgement (streams ≥ 2).
                Kind::SynAck => {
                    if let Some(sid) = f.stream_id {
                        if let Some(s) = self.streams.get_mut(&sid) {
                            s.open_acked = true;
                        }
                    }
                }
                // Stream data / ack / nack / fin / rst: route to the addressed stream.
                _ => {
                    if let Some(sid) = f.stream_id {
                        if let Some(s) = self.streams.get_mut(&sid) {
                            s.stream.on_frame(&f, now);
                        }
                    }
                }
            }
        }
        AnswerOutcome::Consumed
    }

    /// Build a downlink MTU-probe query requesting a padded response of ~`target` bytes. The pump sends
    /// it to a chosen resolver; if the padded response returns, that downlink size survives that path.
    pub fn build_mtu_probe(&mut self, target: u16) -> Option<Vec<u8>> {
        let nonce = crypto::random_nonce().ok()?;
        let mut f = Frame::new(Kind::MtuProbe);
        f.payload = Bytes::copy_from_slice(&target.to_be_bytes());
        let wire = frame::seal_short(&self.up, &self.conn_id, &nonce, &f);
        dns::build_query(self.next_txn(), &wire, &self.zone, self.cfg.edns_udp).ok()
    }

    /// Build a query telling the server to cap its downlink segment at `size` bytes (post-probe). The
    /// server applies it session-wide (all streams share the DNS path MTU).
    pub fn build_set_mtu(&mut self, size: u16) -> Option<Vec<u8>> {
        let nonce = crypto::random_nonce().ok()?;
        let mut f = Frame::new(Kind::SetMtu);
        f.payload = Bytes::copy_from_slice(&size.to_be_bytes());
        let wire = frame::seal_short(&self.up, &self.conn_id, &nonce, &f);
        dns::build_query(self.next_txn(), &wire, &self.zone, self.cfg.edns_udp).ok()
    }

    /// Retune every stream's uplink send-segment (the DNS path MTU is shared across the session).
    pub fn set_uplink_segment(&mut self, size: usize) {
        self.up_arq_cfg.max_segment = size.max(1);
        for s in self.streams.values_mut() {
            s.stream.set_max_segment(size);
        }
    }

    /// The earliest send-side retransmit deadline across all streams (ms), for scheduling.
    pub fn next_deadline(&self) -> Option<u64> {
        self.streams
            .values()
            .filter_map(|s| s.stream.next_deadline())
            .min()
    }
}

/// One server-side stream (one proxied connection / TCP egress).
struct ServerStream {
    stream: Stream,
    /// The target address bytes the client asked for (the server binary dials this).
    target: Bytes,
    /// The caller has been handed this stream's target to dial (so it isn't dialed twice).
    dialed: bool,
}

/// One server-side session (created on a valid SYN), keyed by ConnectionID. Multiplexes many streams.
struct ServerSession {
    up: Aead,
    down: Aead,
    hs: Aead,
    /// Live streams, ordered by id for deterministic round-robin.
    streams: BTreeMap<u16, ServerStream>,
    /// Round-robin cursor: the id served most recently by the downlink poll.
    rr_last: u16,
    /// Time (ms) of the last query for this session — for idle expiry.
    last_seen: u64,
}

impl ServerSession {
    /// Round-robin the streams and pull the next downlink frame from the first stream that has one.
    fn poll_downlink(&mut self, now: u64) -> Option<Frame> {
        let ids: Vec<u16> = self.streams.keys().copied().collect();
        if ids.is_empty() {
            return None;
        }
        let start = ids.iter().position(|&id| id > self.rr_last).unwrap_or(0);
        let n = ids.len();
        for k in 0..n {
            let id = ids[(start + k) % n];
            if let Some(s) = self.streams.get_mut(&id) {
                if let Some(f) = s.stream.poll_transmit(now) {
                    self.rr_last = id;
                    return Some(f);
                }
            }
        }
        None
    }
}

/// The server endpoint: routes DNS tunnel queries to per-ConnectionID sessions (each multiplexing many
/// streams) and produces answers. I/O (binding UDP, the TCP egress) is the caller's job; this is the
/// sans-I/O core.
pub struct Server {
    psk: Vec<u8>,
    zone: Name,
    cfg: Config,
    sessions: BTreeMap<ConnId, ServerSession>,
}

impl Server {
    /// Create a server for a tunnel `zone` and pre-shared key.
    pub fn new(psk: &[u8], zone: &str, cfg: Config) -> Result<Self, SessionError> {
        Ok(Server {
            psk: psk.to_vec(),
            zone: Name::parse(zone)?,
            cfg,
            sessions: BTreeMap::new(),
        })
    }

    /// Streams newly opened on `conn_id` that the caller has not yet been told to dial. Returns
    /// `(stream_id, target_bytes)` pairs and marks them dialed, so each is handed out exactly once.
    pub fn open_targets(&mut self, conn_id: &ConnId) -> Vec<(u16, Bytes)> {
        let mut out = Vec::new();
        if let Some(sess) = self.sessions.get_mut(conn_id) {
            for (id, st) in sess.streams.iter_mut() {
                if !st.dialed {
                    st.dialed = true;
                    out.push((*id, st.target.clone()));
                }
            }
        }
        out
    }

    /// Feed egress bytes (from the dialed target) into a stream.
    pub fn deliver_to_client(&mut self, conn_id: &ConnId, sid: u16, data: &[u8]) {
        if let Some(st) = self
            .sessions
            .get_mut(conn_id)
            .and_then(|s| s.streams.get_mut(&sid))
        {
            st.stream.write(data);
        }
    }

    /// Take bytes a stream has received from the client (to write to its egress).
    pub fn take_from_client(&mut self, conn_id: &ConnId, sid: u16) -> Bytes {
        self.sessions
            .get_mut(conn_id)
            .and_then(|s| s.streams.get_mut(&sid))
            .map(|st| st.stream.read())
            .unwrap_or_default()
    }

    /// Gracefully close a stream (e.g. its target closed) — flushes queued downlink, then FINs.
    pub fn close_stream(&mut self, conn_id: &ConnId, sid: u16) {
        if let Some(st) = self
            .sessions
            .get_mut(conn_id)
            .and_then(|s| s.streams.get_mut(&sid))
        {
            st.stream.close();
        }
    }

    /// Whether a stream's client half signalled EOF (so the egress can half-close its write side).
    pub fn stream_remote_finished(&self, conn_id: &ConnId, sid: u16) -> bool {
        self.sessions
            .get(conn_id)
            .and_then(|s| s.streams.get(&sid))
            .map(|st| st.stream.remote_finished())
            .unwrap_or(false)
    }

    /// Whether a session exists.
    pub fn has_session(&self, conn_id: &ConnId) -> bool {
        self.sessions.contains_key(conn_id)
    }

    /// The ConnectionIDs of all live sessions (so the caller can pump each one's egress).
    pub fn session_ids(&self) -> Vec<ConnId> {
        self.sessions.keys().copied().collect()
    }

    /// The live StreamIDs of a session, ordered by id.
    pub fn streams_of(&self, conn_id: &ConnId) -> Vec<u16> {
        self.sessions
            .get(conn_id)
            .map(|s| s.streams.keys().copied().collect())
            .unwrap_or_default()
    }

    /// Process a DNS tunnel query and produce the answer wire bytes. Returns `None` for a query that
    /// is not a valid tunnel query under our zone (the caller drops it — ordinary malformed DNS).
    pub fn on_query(&mut self, query: &[u8], now: u64) -> Option<Vec<u8>> {
        let parsed = dns::parse_query(query, &self.zone).ok()?;
        let wire = frame::parse_wire(&parsed.data).ok()?;

        if wire.salt.is_some() {
            self.handle_syn(query, &wire, now)
        } else {
            self.handle_data(query, &wire, now)
        }
    }

    /// Remove a session (idle expiry or egress teardown).
    pub fn remove_session(&mut self, conn_id: &ConnId) {
        self.sessions.remove(conn_id);
    }

    /// Drop sessions with no query in the last `idle_ms`; returns the removed ConnectionIDs so the
    /// caller can tear down their egress.
    pub fn sweep_idle(&mut self, now: u64, idle_ms: u64) -> Vec<ConnId> {
        let stale: Vec<ConnId> = self
            .sessions
            .iter()
            .filter(|(_, s)| now.saturating_sub(s.last_seen) >= idle_ms)
            .map(|(k, _)| *k)
            .collect();
        for id in &stale {
            self.sessions.remove(id);
        }
        stale
    }

    /// Build a `ServerStream` sized for the downlink (TXT) capacity.
    fn new_server_stream(&self, sid: u16, target: Bytes) -> ServerStream {
        let mut arq_cfg = self.cfg.arq;
        arq_cfg.max_segment = downlink_segment(self.cfg.edns_udp);
        ServerStream {
            stream: Stream::new(sid, arq_cfg, 0),
            target,
            dialed: false,
        }
    }

    /// Re-ack an already-established session under its handshake key (idempotent SYN retransmit).
    fn reack_session(&self, query: &[u8], conn_id: &ConnId) -> Option<Vec<u8>> {
        let sess = self.sessions.get(conn_id)?;
        let nonce = crypto::random_nonce().ok()?;
        let ack_wire = frame::seal_short(&sess.hs, conn_id, &nonce, &Frame::new(Kind::SynAck));
        dns::build_answer(query, &ack_wire, self.cfg.edns_udp).ok()
    }

    fn handle_syn(&mut self, query: &[u8], wire: &Wire<'_>, now: u64) -> Option<Vec<u8>> {
        // A repeated SYN for a live session just re-acks — never wipe an established multi-stream
        // session (its streams ≥ 2 are not in the handshake SYN and would be lost).
        if self.has_session(&wire.conn_id) {
            return self.reack_session(query, &wire.conn_id);
        }
        let salt = wire.salt?;
        let keys = crypto::derive_session_keys(&self.psk, &salt, &wire.conn_id);
        let (up, down, hs) = aeads(self.cfg.cipher, &keys).ok()?;
        // Authenticate + read the SYN under the handshake key.
        let syn = frame::open_frame(&hs, wire).ok()?;
        if syn.kind != Kind::Syn {
            return None;
        }
        // Establish the session with stream 1 targeting the SYN payload (the fast-path first stream).
        let stream1 = self.new_server_stream(PRIMARY_STREAM_ID, syn.payload.clone());
        let mut streams = BTreeMap::new();
        streams.insert(PRIMARY_STREAM_ID, stream1);
        self.sessions.insert(
            wire.conn_id,
            ServerSession {
                up,
                down,
                hs,
                streams,
                rr_last: 0,
                last_seen: now,
            },
        );
        // Reply SynAck under the handshake key (this also opens stream 1 on the client).
        self.reack_session(query, &wire.conn_id)
    }

    fn handle_data(&mut self, query: &[u8], wire: &Wire<'_>, now: u64) -> Option<Vec<u8>> {
        // Session lookup first (immutable) so the stream-open branch can size a new stream from
        // `self.cfg` without conflicting borrows.
        if !self.has_session(&wire.conn_id) {
            return None;
        }
        // Decode the inner frame under the session's uplink key.
        let f = {
            let sess = self.sessions.get_mut(&wire.conn_id)?;
            sess.last_seen = now;
            frame::open_frame(&sess.up, wire).ok()
        };
        if let Some(f) = f {
            match f.kind {
                Kind::MtuProbe => {
                    // Reply with a response padded to the requested size. If it's too big for the
                    // path it won't return, and the client's probe at that size fails.
                    let target = read_u16(&f.payload)
                        .map(|t| (t as usize).clamp(2, MAX_PROBE_PAYLOAD))
                        .unwrap_or(2);
                    let mut payload = (target as u16).to_be_bytes().to_vec();
                    payload.resize(target, 0);
                    let mut resp = Frame::new(Kind::MtuProbeResp);
                    resp.payload = Bytes::from(payload);
                    let sess = self.sessions.get(&wire.conn_id)?;
                    let nonce = crypto::random_nonce().ok()?;
                    let out = frame::seal_short(&sess.down, &wire.conn_id, &nonce, &resp);
                    return dns::build_answer(query, &out, self.cfg.edns_udp).ok();
                }
                Kind::SetMtu => {
                    // The DNS path MTU is shared: resize every stream's downlink segment.
                    if let Some(sz) = read_u16(&f.payload) {
                        if let Some(sess) = self.sessions.get_mut(&wire.conn_id) {
                            for st in sess.streams.values_mut() {
                                st.stream.set_max_segment(sz as usize);
                            }
                        }
                    }
                    // Fall through to a normal answer.
                }
                Kind::Syn => {
                    // Open (or, on retransmit, re-ack) a multiplexed stream ≥ 2.
                    if let Some(sid) = f.stream_id {
                        if !self.streams_of(&wire.conn_id).contains(&sid) {
                            let st = self.new_server_stream(sid, f.payload.clone());
                            if let Some(sess) = self.sessions.get_mut(&wire.conn_id) {
                                sess.streams.insert(sid, st);
                            }
                        }
                        let sess = self.sessions.get(&wire.conn_id)?;
                        let mut ack = Frame::new(Kind::SynAck);
                        ack.stream_id = Some(sid);
                        let nonce = crypto::random_nonce().ok()?;
                        let out = frame::seal_short(&sess.down, &wire.conn_id, &nonce, &ack);
                        return dns::build_answer(query, &out, self.cfg.edns_udp).ok();
                    }
                }
                // A bare KeepAlive is just a downlink poll — no stream state to touch.
                Kind::KeepAlive => {}
                // Stream data / ack / nack / fin / rst: route to the addressed stream.
                _ => {
                    if let Some(sid) = f.stream_id {
                        if let Some(st) = self
                            .sessions
                            .get_mut(&wire.conn_id)
                            .and_then(|s| s.streams.get_mut(&sid))
                        {
                            st.stream.on_frame(&f, now);
                        }
                    }
                }
            }
        }
        // Answer with the next downlink frame (round-robin across streams), or an empty answer.
        let sess = self.sessions.get_mut(&wire.conn_id)?;
        let downlink = match sess.poll_downlink(now) {
            Some(f) => {
                let nonce = crypto::random_nonce().ok()?;
                frame::seal_short(&sess.down, &wire.conn_id, &nonce, &f)
            }
            None => Vec::new(),
        };
        dns::build_answer(query, &downlink, self.cfg.edns_udp).ok()
    }

    /// The current downlink send-segment size for a session's first stream (telemetry/tests) —
    /// reflects any `SetMtu` (which is applied session-wide).
    pub fn downlink_segment(&self, conn_id: &ConnId) -> Option<usize> {
        self.sessions
            .get(conn_id)
            .and_then(|s| s.streams.values().next())
            .map(|st| st.stream.max_segment())
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
            // Server egress = echo: whatever the client sent on a stream, write back on that stream.
            if server.has_session(&conn) {
                for sid in server.streams_of(&conn) {
                    let got = server.take_from_client(&conn, sid);
                    if !got.is_empty() {
                        server.deliver_to_client(&conn, sid, &got);
                    }
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
            &server.take_from_client(&conn, PRIMARY_STREAM_ID)[..],
            b"hello world",
            "server delivers the uplink bytes"
        );

        // Echo back, then poll for the downlink.
        server.deliver_to_client(&conn, PRIMARY_STREAM_ID, b"hello world");
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
    fn mtu_probe_round_trips() {
        let psk = [0x66u8; 32];
        let zone = "t.example.com";
        let cfg = Config::default();
        let mut client = ClientSession::new(&psk, zone, b"1.2.3.4:443", cfg.clone()).unwrap();
        let mut server = Server::new(&psk, zone, cfg).unwrap();
        // Handshake.
        let q = client.poll_query(0).unwrap();
        let a = server.on_query(&q, 0).unwrap();
        client.on_answer(&a, 0);
        assert!(client.handshake_acked);
        // Probe downlink at 300 bytes; the padded response round-trips and reports the target.
        let pq = client.build_mtu_probe(300).unwrap();
        let pa = server.on_query(&pq, 1).expect("probe answer");
        assert_eq!(
            client.on_answer(&pa, 1),
            AnswerOutcome::ProbeResp { target: 300 }
        );
    }

    #[test]
    fn set_mtu_resizes_server_downlink() {
        let psk = [0x77u8; 32];
        let zone = "t.example.com";
        let cfg = Config::default();
        let mut client = ClientSession::new(&psk, zone, b"1.2.3.4:443", cfg.clone()).unwrap();
        let mut server = Server::new(&psk, zone, cfg).unwrap();
        let conn = client.conn_id;
        // Establish the session (server side needs only the SYN).
        let q = client.poll_query(0).unwrap();
        server.on_query(&q, 0).unwrap();
        let before = server.downlink_segment(&conn).unwrap();
        assert_ne!(before, 200);
        // SetMtu caps the server's downlink segment.
        let sq = client.build_set_mtu(200).unwrap();
        server.on_query(&sq, 1).unwrap();
        assert_eq!(server.downlink_segment(&conn), Some(200));
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
    fn two_streams_multiplex_independently() {
        // One session, two streams to different targets, distinct payloads. A routing bug (wrong
        // StreamID on a frame, or shared ARQ state) would cross or corrupt the byte streams.
        let psk = [0x33u8; 32];
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
        let mut client = ClientSession::new(&psk, zone, b"1.1.1.1:443", cfg.clone()).unwrap();
        let mut server = Server::new(&psk, zone, cfg).unwrap();
        let conn = client.conn_id;

        // Distinct payloads: stream 2's bytes are stream 1's + 128, so any cross-talk shows up.
        let p1 = payload_of(3_000);
        let p2: Vec<u8> = p1.iter().map(|b| b.wrapping_add(128)).collect();

        // Stream 1's data rides the handshake; stream 2 opens after the session is established.
        client.write_stream(PRIMARY_STREAM_ID, &p1);
        let mut sid2: Option<u16> = None;

        let mut net = Net::new(3, 0, 0, 0x2222);
        let (mut got1, mut got2) = (Vec::new(), Vec::new());
        for now in 0..2_000_000u64 {
            if sid2.is_none() && client.is_established() {
                let s = client.open_stream(b"2.2.2.2:443");
                client.write_stream(s, &p2);
                sid2 = Some(s);
            }
            while let Some(q) = client.poll_query(now) {
                net.push(true, q, now);
            }
            for q in net.due(true, now) {
                if let Some(ans) = server.on_query(&q, now) {
                    net.push(false, ans, now);
                }
            }
            // Per-stream echo.
            for sid in server.streams_of(&conn) {
                let d = server.take_from_client(&conn, sid);
                if !d.is_empty() {
                    server.deliver_to_client(&conn, sid, &d);
                }
            }
            for ans in net.due(false, now) {
                client.on_answer(&ans, now);
            }
            got1.extend_from_slice(&client.read_stream(PRIMARY_STREAM_ID));
            if let Some(s) = sid2 {
                got2.extend_from_slice(&client.read_stream(s));
            }
            if got1.len() >= p1.len() && got2.len() >= p2.len() {
                break;
            }
        }
        assert_eq!(sid2, Some(2), "second stream got the next id");
        assert_eq!(got1, p1, "stream 1 echo intact");
        assert_eq!(
            got2, p2,
            "stream 2 echo intact and not crossed with stream 1"
        );
        assert_eq!(
            server.streams_of(&conn).len(),
            2,
            "server tracks both streams"
        );
    }

    #[test]
    fn server_sweeps_idle_sessions() {
        let psk = [0x44u8; 32];
        let zone = "t.example.com";
        let cfg = Config::default();
        let mut client = ClientSession::new(&psk, zone, b"1.2.3.4:443", cfg.clone()).unwrap();
        let mut server = Server::new(&psk, zone, cfg).unwrap();
        // Handshake establishes the session at t=0.
        let q = client.poll_query(0).unwrap();
        server.on_query(&q, 0).unwrap();
        assert!(server.has_session(&client.conn_id));
        // Within the idle window → kept.
        assert!(server.sweep_idle(1_000, 5_000).is_empty());
        assert!(server.has_session(&client.conn_id));
        // Past the idle window → swept.
        let removed = server.sweep_idle(10_000, 5_000);
        assert_eq!(removed.len(), 1);
        assert!(!server.has_session(&client.conn_id));
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
