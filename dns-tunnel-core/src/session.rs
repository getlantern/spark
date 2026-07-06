//! Session layer (ADR 0011 §2.3/§2.4): composes `crypto` + `frame` + `dns` + `arq` into a full
//! DNS-tunnel session, still **sans-I/O**. The caller owns the sockets and clock; this layer turns
//! application bytes into DNS query/answer wire and back.
//!
//! Model: DNS is strictly request→response and the server cannot push, so the **client polls**. Each
//! query carries one uplink frame (or a `KeepAlive` when idle, so the server gets a chance to answer
//! with downlink data); each answer carries at most one downlink frame. Many queries in flight at
//! once give throughput; a lost query is harmless because the ARQ layer re-emits any data frame on its
//! own RTO.
//!
//! Multiplexing: one crypto session (one ConnectionID + key schedule) carries **many** reliable
//! streams, each an independent [`Stream`] keyed by a 16-bit StreamID. The uplink poll and the downlink
//! poll both **round-robin** across a session's streams so no single stream starves the others.
//!
//! **Forward-secret handshake (§2.4, anonymous client / Noise-NK-style).** The server owns a static
//! Ed25519 identity; its *public* key is what clients hold (safe to distribute — no shared secret). A
//! session is established by a cleartext ephemeral↔ephemeral X25519 exchange:
//! `client → Syn(client_eph)`; `server → SynAck(server_eph, sig)` where `sig` is the server's Ed25519
//! signature over the transcript (`client_eph ‖ server_eph ‖ ConnectionID`). Both sides derive the
//! session keys from the ephemeral↔ephemeral shared secret only, so a later compromise of the static
//! key cannot decrypt past traffic (forward secrecy); the signature authenticates the server (anti
//! MITM). The client is anonymous (anyone with the server's public key can connect). Streams — the
//! first included — then open *after* the handshake with a cheap short-form `Syn` (StreamID + target,
//! sealed under the session uplink key), retried until the server returns a per-stream `SynAck`.

use std::collections::BTreeMap;

use bytes::Bytes;

use crate::arq::{self, Stream};
use crate::crypto::{
    self, Aead, Cipher, Ephemeral, ServerStatic, CONN_ID_LEN, ED25519_PUB_LEN, X25519_PUB_LEN,
};
use crate::dns::{self, Name};
use crate::frame::{self, Frame, Kind, Packet};
use crate::mtu;

/// A session ConnectionID.
type ConnId = [u8; CONN_ID_LEN];

/// The StreamID of the first stream. The single-stream convenience API (`write`/`read`/`close`)
/// operates on this stream. (Unlike the old PSK design, no stream rides the handshake — all streams,
/// including this one, open with a short-form `Syn` after the session is established.)
pub const PRIMARY_STREAM_ID: u16 = 1;

/// Domain-separation prefix for the handshake transcript signature.
const SIG_CONTEXT: &[u8] = b"spark-dns-tunnel v1 synack";

/// Conservative upper bound on the inner frame header (version+kind+flags+stream_id+seq+frag+comp),
/// used to size ARQ segments so a sealed data frame always fits its DNS carrier.
const FRAME_HEADER_MAX: usize = 16;

/// Max uplink ARQ segment for a zone: payload bytes that fit in a short-form data frame packed base32
/// into the QNAME. Sizing the ARQ to this is essential — an oversized segment would make the DNS
/// query exceed the 255-byte name limit and never go out.
fn uplink_segment(zone: &Name) -> usize {
    mtu::max_uplink_payload(zone.wire_len(), FRAME_HEADER_MAX).max(1)
}

/// Max downlink ARQ segment: payload bytes that fit in a TXT answer, using the worst-case echoed
/// question size (a full 255-byte QNAME + QTYPE/QCLASS).
fn downlink_segment(edns_udp: u16) -> usize {
    const WORST_QUESTION: usize = 255 + 4;
    mtu::max_downlink_payload(edns_udp as usize, WORST_QUESTION, FRAME_HEADER_MAX).max(1)
}

/// The transcript bound into the handshake key schedule and signature.
fn transcript(
    client_eph: &[u8; X25519_PUB_LEN],
    server_eph: &[u8; X25519_PUB_LEN],
    conn_id: &ConnId,
) -> Vec<u8> {
    let mut t = Vec::with_capacity(2 * X25519_PUB_LEN + CONN_ID_LEN);
    t.extend_from_slice(client_eph);
    t.extend_from_slice(server_eph);
    t.extend_from_slice(conn_id);
    t
}

/// The exact bytes the server signs and the client verifies (context ‖ transcript).
fn signed_msg(transcript: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(SIG_CONTEXT.len() + transcript.len());
    m.extend_from_slice(SIG_CONTEXT);
    m.extend_from_slice(transcript);
    m
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
    /// A crypto operation (key setup, agreement, RNG) failed.
    #[error(transparent)]
    Crypto(#[from] crypto::CryptoError),
    /// The tunnel zone was not a valid DNS name.
    #[error(transparent)]
    Dns(#[from] dns::DnsError),
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
    /// The stream's open has been acknowledged (its per-stream `SynAck` arrived).
    open_acked: bool,
    /// When the open `Syn` was last (re)sent (ms) — for open retransmission.
    last_open_ms: Option<u64>,
}

/// The client end of a DNS-tunnel session, multiplexing many streams over one forward-secret key
/// schedule established from the server's public key.
pub struct ClientSession {
    cfg: Config,
    zone: Name,
    conn_id: ConnId,
    /// The server's static Ed25519 public key (used to authenticate the SynAck signature).
    server_pub: [u8; ED25519_PUB_LEN],
    /// The client's ephemeral X25519 key — consumed when the SynAck completes the handshake.
    client_eph: Option<Ephemeral>,
    /// The client ephemeral public key (kept for the transcript after `client_eph` is consumed).
    client_eph_pub: [u8; X25519_PUB_LEN],
    /// Session AEADs — `None` until the handshake completes.
    up: Option<Aead>,
    down: Option<Aead>,
    /// ARQ config for new streams (uplink-segment sized for this zone).
    up_arq_cfg: arq::Config,
    /// Live streams, ordered by id for deterministic round-robin.
    streams: BTreeMap<u16, ClientStream>,
    /// Next StreamID to hand out.
    next_stream_id: u16,
    /// Round-robin cursor: the id served most recently by the uplink poll.
    rr_last: u16,
    handshake_acked: bool,
    txn: u16,
    outstanding: Vec<Outstanding>,
}

impl ClientSession {
    /// Create a client session to a server identified by its static Ed25519 public key, whose first
    /// stream targets `target` (opaque address bytes the server will dial). All streams — including
    /// the first — open after the handshake; open more with [`open_stream`](Self::open_stream).
    pub fn new(
        server_pub: &[u8; ED25519_PUB_LEN],
        zone: &str,
        target: &[u8],
        cfg: Config,
    ) -> Result<Self, SessionError> {
        let zone = Name::parse(zone)?;
        let conn_id = crypto::random_conn_id()?;
        let client_eph = Ephemeral::generate()?;
        let client_eph_pub = client_eph.public();
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
                last_open_ms: None,
            },
        );
        Ok(ClientSession {
            zone,
            conn_id,
            server_pub: *server_pub,
            client_eph: Some(client_eph),
            client_eph_pub,
            up: None,
            down: None,
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
    /// retried) by [`poll_query`](Self::poll_query) once the session handshake has completed; bytes
    /// written before the stream's `SynAck` arrives are buffered and flushed after it opens.
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

    /// Whether the session handshake has completed (the SynAck arrived and keys are established).
    pub fn is_established(&self) -> bool {
        self.handshake_acked
    }

    /// Whether stream `sid` is open (its per-stream open has been acknowledged).
    fn stream_open(&self, sid: u16) -> bool {
        self.streams
            .get(&sid)
            .map(|s| s.open_acked)
            .unwrap_or(false)
    }

    /// Whether any stream is still alive (so a keepalive is worth sending to poll for downlink).
    fn any_stream_alive(&self) -> bool {
        self.streams.values().any(|s| !s.stream.is_closed())
    }

    fn next_txn(&mut self) -> u16 {
        self.txn = self.txn.wrapping_add(1);
        self.txn
    }

    /// Build the next pending stream-open `Syn` (short form, under the uplink key) whose retransmit
    /// timer is due, if any. Only callable post-handshake (needs the uplink key).
    fn next_open_syn(&mut self, now: u64) -> Option<(u16, Vec<u8>)> {
        let up = self.up.as_ref()?;
        let open_rto = self.up_arq_cfg.initial_rto_ms;
        let sid = self
            .streams
            .iter()
            .find(|(_, s)| {
                !s.open_acked
                    && s.last_open_ms
                        .is_none_or(|t| now.saturating_sub(t) >= open_rto)
            })
            .map(|(id, _)| *id)?;
        let target = self.streams.get(&sid)?.target.clone();
        let nonce = crypto::random_nonce().ok()?;
        let mut syn = Frame::new(Kind::Syn);
        syn.stream_id = Some(sid);
        syn.payload = target;
        let wire = frame::seal_short(up, &self.conn_id, &nonce, &syn);
        if let Some(s) = self.streams.get_mut(&sid) {
            s.last_open_ms = Some(now);
        }
        Some((sid, wire))
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
        self.poll_query_tagged(now).map(|(_, q)| q)
    }

    /// Like [`poll_query`](Self::poll_query) but also returns the StreamID the query belongs to (`None`
    /// for session-level control: the handshake `Syn` and idle keepalives). The pump uses the tag to
    /// route each stream's queries to that stream's affinity resolver.
    pub fn poll_query_tagged(&mut self, now: u64) -> Option<(Option<u16>, Vec<u8>)> {
        // Free timed-out query slots (their frames, if any, will be re-sent by ARQ's RTO).
        self.outstanding.retain(|o| o.deadline > now);
        if self.outstanding.len() >= self.cfg.max_query_inflight {
            return None;
        }

        // Before the handshake completes only the (cleartext) Syn is sent — re-sent whenever no Syn is
        // outstanding, so a lost Syn can't stall. After establishment: flush any pending stream-open,
        // then round-robin stream data, then an idle keepalive.
        let (stream, wire): (Option<u16>, Vec<u8>) = if !self.handshake_acked {
            if !self.outstanding.is_empty() {
                return None; // a Syn is already in flight
            }
            (None, frame::build_syn(&self.conn_id, &self.client_eph_pub))
        } else if let Some((sid, w)) = self.next_open_syn(now) {
            (Some(sid), w)
        } else if let Some(f) = self.next_stream_frame(now) {
            let up = self.up.as_ref()?;
            let nonce = crypto::random_nonce().ok()?;
            (
                f.stream_id,
                frame::seal_short(up, &self.conn_id, &nonce, &f),
            )
        } else if self.any_stream_alive() {
            // Idle keepalive: poll the server for downlink data (and any pending stream SynAck).
            let up = self.up.as_ref()?;
            let nonce = crypto::random_nonce().ok()?;
            (
                None,
                frame::seal_short(up, &self.conn_id, &nonce, &Frame::new(Kind::KeepAlive)),
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
        Some((stream, query))
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
        let Ok(packet) = frame::parse_packet(&parsed.data) else {
            return AnswerOutcome::Consumed;
        };

        if !self.handshake_acked {
            // Expect the server handshake: verify the signature, agree, and derive the session keys.
            if let Packet::SynAck {
                server_eph, sig, ..
            } = packet
            {
                self.finish_handshake(&server_eph, &sig);
            }
            return AnswerOutcome::Consumed;
        }

        // Established: a Data frame under the downlink key.
        if let Packet::Data {
            nonce, ciphertext, ..
        } = packet
        {
            let Some(down) = self.down.as_ref() else {
                return AnswerOutcome::Consumed;
            };
            if let Ok(f) = frame::open_frame(down, &nonce, ciphertext) {
                match f.kind {
                    Kind::MtuProbeResp => {
                        return AnswerOutcome::ProbeResp {
                            target: read_u16(&f.payload).unwrap_or(0),
                        };
                    }
                    // A per-stream open acknowledgement.
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
        }
        AnswerOutcome::Consumed
    }

    /// Verify the server's SynAck signature, complete the ephemeral↔ephemeral agreement, and install
    /// the forward-secret session keys. A bad signature or agreement leaves the handshake incomplete
    /// (the client keeps retrying the Syn).
    fn finish_handshake(&mut self, server_eph: &[u8; X25519_PUB_LEN], sig: &[u8]) {
        let transcript = transcript(&self.client_eph_pub, server_eph, &self.conn_id);
        if crypto::verify_server_sig(&self.server_pub, &signed_msg(&transcript), sig).is_err() {
            return; // not our server / tampered — ignore and keep retrying
        }
        let Some(eph) = self.client_eph.take() else {
            return;
        };
        let Ok(ee) = eph.agree(server_eph) else {
            return;
        };
        let keys = crypto::derive_session_keys_ecdh(&ee, &transcript);
        if let (Ok(up), Ok(down)) = (
            Aead::new(self.cfg.cipher, &keys.up),
            Aead::new(self.cfg.cipher, &keys.down),
        ) {
            self.up = Some(up);
            self.down = Some(down);
            self.handshake_acked = true;
        }
    }

    /// Build a downlink MTU-probe query requesting a padded response of ~`target` bytes. The pump sends
    /// it to a chosen resolver; if the padded response returns, that downlink size survives that path.
    pub fn build_mtu_probe(&mut self, target: u16) -> Option<Vec<u8>> {
        let up = self.up.as_ref()?;
        let nonce = crypto::random_nonce().ok()?;
        let mut f = Frame::new(Kind::MtuProbe);
        f.payload = Bytes::copy_from_slice(&target.to_be_bytes());
        let wire = frame::seal_short(up, &self.conn_id, &nonce, &f);
        dns::build_query(self.next_txn(), &wire, &self.zone, self.cfg.edns_udp).ok()
    }

    /// Build a query telling the server to cap its downlink segment at `size` bytes (post-probe). The
    /// server applies it session-wide (all streams share the DNS path MTU).
    pub fn build_set_mtu(&mut self, size: u16) -> Option<Vec<u8>> {
        let up = self.up.as_ref()?;
        let nonce = crypto::random_nonce().ok()?;
        let mut f = Frame::new(Kind::SetMtu);
        f.payload = Bytes::copy_from_slice(&size.to_be_bytes());
        let wire = frame::seal_short(up, &self.conn_id, &nonce, &f);
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

/// One server-side session (created on a valid Syn), keyed by ConnectionID. Multiplexes many streams.
struct ServerSession {
    up: Aead,
    down: Aead,
    /// The cached SynAck wire bytes, replayed verbatim if the client retransmits its Syn (so both
    /// sides keep the same ephemeral-derived keys — regenerating would diverge them).
    synack: Vec<u8>,
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
/// streams) and produces answers. Holds the static Ed25519 identity. I/O (binding UDP, the TCP egress)
/// is the caller's job; this is the sans-I/O core.
pub struct Server {
    static_key: ServerStatic,
    zone: Name,
    cfg: Config,
    sessions: BTreeMap<ConnId, ServerSession>,
}

impl Server {
    /// Create a server for a tunnel `zone` from the server's static Ed25519 private key (PKCS#8).
    pub fn new(server_privkey_pkcs8: &[u8], zone: &str, cfg: Config) -> Result<Self, SessionError> {
        Ok(Server {
            static_key: ServerStatic::from_pkcs8(server_privkey_pkcs8)?,
            zone: Name::parse(zone)?,
            cfg,
            sessions: BTreeMap::new(),
        })
    }

    /// The server's public key (Ed25519, 32 bytes) — distribute this to clients.
    pub fn public_key(&self) -> [u8; ED25519_PUB_LEN] {
        self.static_key.public_key()
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

    /// In-order bytes reassembled from the client but not yet taken (peek; does **not** consume).
    /// Lets a caller decide whether to `take_from_client` — e.g. only when a downstream egress queue
    /// has room — without draining the ARQ delivery buffer if it can't yet hand the bytes off.
    pub fn readable_from_client(&self, conn_id: &ConnId, sid: u16) -> usize {
        self.sessions
            .get(conn_id)
            .and_then(|s| s.streams.get(&sid))
            .map(|st| st.stream.readable())
            .unwrap_or(0)
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

    /// Process a DNS tunnel query and produce the answer wire bytes. A valid `Syn`/`Data` packet is
    /// handled; a query **under our zone** that isn't a tunnel packet (the apex, or the SOA/NS/A probes
    /// a QNAME-minimizing resolver sends) gets a benign NOERROR/NODATA so the resolver proceeds; a
    /// query **not** under our zone returns `None` (the caller drops it — not ours to answer).
    pub fn on_query(&mut self, query: &[u8], now: u64) -> Option<Vec<u8>> {
        let parsed = match dns::parse_query(query, &self.zone) {
            Ok(q) => q,
            Err(dns::DnsError::WrongZone) => return None,
            Err(_) => return dns::build_nodata(query, &self.zone, self.cfg.edns_udp).ok(),
        };
        match frame::parse_packet(&parsed.data) {
            Ok(Packet::Syn {
                conn_id,
                client_eph,
            }) => self.handle_syn(query, &conn_id, &client_eph, now),
            Ok(Packet::Data {
                conn_id,
                nonce,
                ciphertext,
            }) => self.handle_data(query, &conn_id, &nonce, ciphertext, now),
            // A SynAck (servers never receive one) or an unparseable packet under our zone → NODATA.
            _ => dns::build_nodata(query, &self.zone, self.cfg.edns_udp).ok(),
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

    /// Handle a client `Syn`: run the forward-secret handshake and establish the session. A repeated
    /// `Syn` for a live session replays the cached SynAck (so a retransmit doesn't regenerate — and
    /// thereby diverge — the ephemeral keys).
    fn handle_syn(
        &mut self,
        query: &[u8],
        conn_id: &ConnId,
        client_eph: &[u8; X25519_PUB_LEN],
        now: u64,
    ) -> Option<Vec<u8>> {
        if let Some(sess) = self.sessions.get(conn_id) {
            return dns::build_answer(query, &sess.synack, self.cfg.edns_udp).ok();
        }
        let server_eph = Ephemeral::generate().ok()?;
        let se_pub = server_eph.public();
        let ee = server_eph.agree(client_eph).ok()?;
        let transcript = transcript(client_eph, &se_pub, conn_id);
        let sig = self.static_key.sign(&signed_msg(&transcript));
        let keys = crypto::derive_session_keys_ecdh(&ee, &transcript);
        let up = Aead::new(self.cfg.cipher, &keys.up).ok()?;
        let down = Aead::new(self.cfg.cipher, &keys.down).ok()?;
        let synack = frame::build_synack(conn_id, &se_pub, &sig);
        self.sessions.insert(
            *conn_id,
            ServerSession {
                up,
                down,
                synack: synack.clone(),
                streams: BTreeMap::new(),
                rr_last: 0,
                last_seen: now,
            },
        );
        dns::build_answer(query, &synack, self.cfg.edns_udp).ok()
    }

    fn handle_data(
        &mut self,
        query: &[u8],
        conn_id: &ConnId,
        nonce: &[u8; crypto::NONCE_LEN],
        ciphertext: &[u8],
        now: u64,
    ) -> Option<Vec<u8>> {
        if !self.has_session(conn_id) {
            // Data for an unknown session (e.g. after an idle sweep) → benign NODATA.
            return dns::build_nodata(query, &self.zone, self.cfg.edns_udp).ok();
        }
        // Decode the inner frame under the session's uplink key.
        let f = {
            let sess = self.sessions.get_mut(conn_id)?;
            sess.last_seen = now;
            frame::open_frame(&sess.up, nonce, ciphertext).ok()
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
                    let sess = self.sessions.get(conn_id)?;
                    let nonce = crypto::random_nonce().ok()?;
                    let out = frame::seal_short(&sess.down, conn_id, &nonce, &resp);
                    return dns::build_answer(query, &out, self.cfg.edns_udp).ok();
                }
                Kind::SetMtu => {
                    // The DNS path MTU is shared: resize every stream's downlink segment.
                    if let Some(sz) = read_u16(&f.payload) {
                        if let Some(sess) = self.sessions.get_mut(conn_id) {
                            for st in sess.streams.values_mut() {
                                st.stream.set_max_segment(sz as usize);
                            }
                        }
                    }
                    // Fall through to a normal answer.
                }
                Kind::Syn => {
                    // Open (or, on retransmit, re-ack) a multiplexed stream.
                    if let Some(sid) = f.stream_id {
                        if !self.streams_of(conn_id).contains(&sid) {
                            let st = self.new_server_stream(sid, f.payload.clone());
                            if let Some(sess) = self.sessions.get_mut(conn_id) {
                                sess.streams.insert(sid, st);
                            }
                        }
                        let sess = self.sessions.get(conn_id)?;
                        let mut ack = Frame::new(Kind::SynAck);
                        ack.stream_id = Some(sid);
                        let nonce = crypto::random_nonce().ok()?;
                        let out = frame::seal_short(&sess.down, conn_id, &nonce, &ack);
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
                            .get_mut(conn_id)
                            .and_then(|s| s.streams.get_mut(&sid))
                        {
                            st.stream.on_frame(&f, now);
                        }
                    }
                }
            }
        }
        // Answer with the next downlink frame (round-robin across streams), or an empty answer.
        let sess = self.sessions.get_mut(conn_id)?;
        let downlink = match sess.poll_downlink(now) {
            Some(f) => {
                let nonce = crypto::random_nonce().ok()?;
                frame::seal_short(&sess.down, conn_id, &nonce, &f)
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

    /// A fresh server identity + its public key, for tests.
    fn keypair() -> (Vec<u8>, [u8; ED25519_PUB_LEN]) {
        let pkcs8 = ServerStatic::generate().unwrap();
        let pubkey = crypto::server_public_from_pkcs8(&pkcs8).unwrap();
        (pkcs8, pubkey)
    }

    /// Drive a full echo session: client sends `payload`; the server echoes every byte back; assert the
    /// client receives the echo intact. Exercises handshake + stream open + bidirectional data.
    fn run_echo(net: &mut Net, payload: &[u8], max_steps: u64) -> Vec<u8> {
        let (pkcs8, pubkey) = keypair();
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
        let mut client = ClientSession::new(&pubkey, zone, b"1.2.3.4:443", cfg.clone()).unwrap();
        let mut server = Server::new(&pkcs8, zone, cfg).unwrap();
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

    /// Drive client↔server one query/answer at a time until `done`, echoing per-stream. A tiny helper
    /// for tests that need the session established without a full `Net`.
    fn pump_until(
        client: &mut ClientSession,
        server: &mut Server,
        conn: &ConnId,
        max_steps: u64,
        done: impl Fn(&ClientSession, &Server) -> bool,
    ) {
        for now in 0..max_steps {
            // Drain queries into answers FIRST (so the in-flight budget fills and the drain ends),
            // then feed the answers back — processing them inline would free a slot each iteration and
            // spin forever on keepalives.
            let mut answers = Vec::new();
            while let Some(q) = client.poll_query(now) {
                if let Some(a) = server.on_query(&q, now) {
                    answers.push(a);
                }
            }
            for a in answers {
                client.on_answer(&a, now);
            }
            if server.has_session(conn) {
                for sid in server.streams_of(conn) {
                    let d = server.take_from_client(conn, sid);
                    if !d.is_empty() {
                        server.deliver_to_client(conn, sid, &d);
                    }
                }
            }
            if done(client, server) {
                return;
            }
        }
    }

    #[test]
    fn forward_secret_handshake_then_echo() {
        // A hand-stepped handshake + one stream open + a small echo, to pin each stage.
        let (pkcs8, pubkey) = keypair();
        let zone = "t.example.com";
        let cfg = Config::default();
        let mut client = ClientSession::new(&pubkey, zone, b"1.2.3.4:443", cfg.clone()).unwrap();
        let mut server = Server::new(&pkcs8, zone, cfg).unwrap();
        client.write(b"hello world");
        let conn = client.conn_id;

        // Cleartext Syn → SynAck completes the forward-secret handshake.
        let syn = client.poll_query(0).expect("Syn query");
        let synack = server.on_query(&syn, 0).expect("SynAck answer");
        client.on_answer(&synack, 0);
        assert!(
            client.is_established(),
            "handshake completes from the server pubkey"
        );

        // Then drive: stream-1 open + the uplink echo. Drain queries into answers before feeding them
        // back (inline processing frees a slot each loop and spins on keepalives).
        let mut got = Vec::new();
        for now in 1..2000u64 {
            let mut answers = Vec::new();
            while let Some(q) = client.poll_query(now) {
                if let Some(a) = server.on_query(&q, now) {
                    answers.push(a);
                }
            }
            for a in answers {
                client.on_answer(&a, now);
            }
            for sid in server.streams_of(&conn) {
                let d = server.take_from_client(&conn, sid);
                if !d.is_empty() {
                    server.deliver_to_client(&conn, sid, &d);
                }
            }
            got.extend_from_slice(&client.read());
            if got.len() >= b"hello world".len() {
                break;
            }
        }
        assert_eq!(
            &got[..],
            b"hello world",
            "client receives the echo over the FS session"
        );
    }

    #[test]
    fn wrong_server_key_never_establishes() {
        // A client holding a *different* server's public key must reject the SynAck (bad signature).
        let (pkcs8, _real_pub) = keypair();
        let (_other_pkcs8, other_pub) = keypair();
        let zone = "t.example.com";
        let cfg = Config::default();
        let mut client = ClientSession::new(&other_pub, zone, b"1.2.3.4:443", cfg.clone()).unwrap();
        let mut server = Server::new(&pkcs8, zone, cfg).unwrap();
        let syn = client.poll_query(0).unwrap();
        let synack = server.on_query(&syn, 0).unwrap();
        client.on_answer(&synack, 0);
        assert!(
            !client.is_established(),
            "a mismatched server key must not complete the handshake"
        );
    }

    #[test]
    fn mtu_probe_round_trips() {
        let (pkcs8, pubkey) = keypair();
        let zone = "t.example.com";
        let cfg = Config::default();
        let mut client = ClientSession::new(&pubkey, zone, b"1.2.3.4:443", cfg.clone()).unwrap();
        let mut server = Server::new(&pkcs8, zone, cfg).unwrap();
        // Handshake.
        let syn = client.poll_query(0).unwrap();
        let synack = server.on_query(&syn, 0).unwrap();
        client.on_answer(&synack, 0);
        assert!(client.is_established());
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
        let (pkcs8, pubkey) = keypair();
        let zone = "t.example.com";
        let cfg = Config::default();
        let mut client = ClientSession::new(&pubkey, zone, b"1.2.3.4:443", cfg.clone()).unwrap();
        let mut server = Server::new(&pkcs8, zone, cfg).unwrap();
        let conn = client.conn_id;
        // Establish + open stream 1 (so there's a stream whose segment SetMtu can resize).
        pump_until(&mut client, &mut server, &conn, 200, |c, s| {
            c.is_established() && !s.streams_of(&conn).is_empty()
        });
        let before = server.downlink_segment(&conn).expect("stream 1 open");
        assert_ne!(before, 200);
        // SetMtu caps the server's downlink segment.
        let sq = client.build_set_mtu(200).unwrap();
        server.on_query(&sq, 1_000).unwrap();
        assert_eq!(server.downlink_segment(&conn), Some(200));
    }

    #[test]
    fn two_streams_multiplex_independently() {
        // One session, two streams to different targets, distinct payloads. A routing bug (wrong
        // StreamID on a frame, or shared ARQ state) would cross or corrupt the byte streams.
        let (pkcs8, pubkey) = keypair();
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
        let mut client = ClientSession::new(&pubkey, zone, b"1.1.1.1:443", cfg.clone()).unwrap();
        let mut server = Server::new(&pkcs8, zone, cfg).unwrap();
        let conn = client.conn_id;

        // Distinct payloads: stream 2's bytes are stream 1's + 128, so any cross-talk shows up.
        let p1 = payload_of(3_000);
        let p2: Vec<u8> = p1.iter().map(|b| b.wrapping_add(128)).collect();

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
    fn server_answers_nodata_for_qname_min_probe() {
        // A QNAME-minimizing resolver probes the apex (no tunnel labels) before forwarding tunnel
        // data; the server must answer NOERROR/NODATA, not drop, or the resolver SERVFAILs.
        let (pkcs8, _pub) = keypair();
        let mut server = Server::new(&pkcs8, "t.example.com", Config::default()).unwrap();
        let zone = Name::parse("t.example.com").unwrap();
        let probe = dns::build_query(0x1234, b"", &zone, 1232).unwrap();
        let ans = server
            .on_query(&probe, 0)
            .expect("benign NODATA, not a drop");
        assert_eq!(ans[2] & 0x80, 0x80, "QR set");
        assert_eq!(ans[3] & 0x0f, 0, "RCODE NOERROR");
        assert_eq!(
            u16::from_be_bytes([ans[8], ans[9]]),
            1,
            "SOA in the authority section"
        );
        // A query outside our zone is still not ours → dropped.
        let other = Name::parse("t.evil.example").unwrap();
        let q = dns::build_query(1, &[0u8; 8], &other, 1232).unwrap();
        assert!(server.on_query(&q, 0).is_none());
    }

    #[test]
    fn server_sweeps_idle_sessions() {
        let (pkcs8, pubkey) = keypair();
        let zone = "t.example.com";
        let cfg = Config::default();
        let mut client = ClientSession::new(&pubkey, zone, b"1.2.3.4:443", cfg.clone()).unwrap();
        let mut server = Server::new(&pkcs8, zone, cfg).unwrap();
        // Handshake establishes the session at t=0.
        let syn = client.poll_query(0).unwrap();
        server.on_query(&syn, 0).unwrap();
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
        let (pkcs8, _pub) = keypair();
        let mut server = Server::new(&pkcs8, "t.example.com", Config::default()).unwrap();
        // Random garbage is not a tunnel query.
        assert!(server.on_query(b"\x00\x01\x02not-dns", 0).is_none());
        // A well-formed query under the wrong zone is refused.
        let other = Name::parse("t.evil.example").unwrap();
        let q = dns::build_query(1, &[0u8; 40], &other, 1232).unwrap();
        assert!(server.on_query(&q, 0).is_none());
    }
}
