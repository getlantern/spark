//! ARQ: a reliable, ordered, per-stream byte channel over the unreliable frame carrier (ADR 0011 §3).
//!
//! **Sans-I/O.** [`Stream`] is a pure state machine driven by a virtual monotonic clock (`now`, in
//! milliseconds) that the caller supplies. The caller:
//! - [`Stream::write`]s application bytes to send,
//! - pulls frames to put on the wire with [`Stream::poll_transmit`] (call until it returns `None`),
//! - feeds arriving frames back with [`Stream::on_frame`],
//! - and [`Stream::read`]s the in-order bytes that have been delivered.
//!
//! [`Stream::next_deadline`] tells the caller when to next call `poll_transmit` for a retransmit.
//!
//! Sequence numbers are **per segment** (each `Data` frame carries one segment), not per byte — the
//! right granularity for ARQ over a datagram carrier. Reliability = cumulative ACK + selective NACK
//! fast-retransmit + adaptive RFC-6298 RTO retransmit. The FIN occupies one sequence number (a
//! phantom segment) so half-close is acknowledged in order; RST is best-effort. There is deliberately
//! **no congestion control** (§3): the send window + resolver rate-limit govern the rate.

use std::collections::{BTreeMap, VecDeque};

use bytes::{Bytes, BytesMut};

use crate::frame::{Frame, Kind};

/// A segment sequence number.
pub type Seq = u32;

/// `true` if `a` is strictly before `b` in serial-number arithmetic (RFC 1982, 32-bit).
fn seq_lt(a: Seq, b: Seq) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

/// Stream lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Open in both directions.
    Open,
    /// A `FIN` has been sent (local half closed); may still be receiving.
    FinSent,
    /// A `FIN` has been received (remote half closed); may still be sending.
    FinRcvd,
    /// Both halves closed cleanly.
    Closed,
    /// Abruptly reset.
    Reset,
}

/// ARQ tuning. Defaults are conservative for the very-high-latency DNS channel.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// Max payload bytes per `Data` segment (set from the negotiated MTU).
    pub max_segment: usize,
    /// Max in-flight (sent, unacked) segments — the send window.
    pub send_window: u32,
    /// Max buffered out-of-order segments on the receive side.
    pub recv_window: u32,
    /// Initial RTO before any RTT sample (ms).
    pub initial_rto_ms: u64,
    /// RTO floor (ms).
    pub min_rto_ms: u64,
    /// RTO ceiling (ms).
    pub max_rto_ms: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            max_segment: 128,
            send_window: 64,
            recv_window: 256,
            initial_rto_ms: 1_000,
            min_rto_ms: 200,
            max_rto_ms: 30_000,
        }
    }
}

/// A sent-but-unacked segment.
#[derive(Debug, Clone)]
struct Sent {
    data: Bytes,
    /// When it was last (re)transmitted (ms).
    sent_at: u64,
    /// Retransmission count (Karn: RTT is sampled only when this is 0).
    retx: u32,
    /// This "segment" is the phantom FIN (carries no bytes).
    is_fin: bool,
}

/// One reliable stream (client or server side are symmetric).
#[derive(Debug)]
pub struct Stream {
    stream_id: u16,
    cfg: Config,
    state: State,

    // --- send side ---
    snd_una: Seq,
    snd_nxt: Seq,
    outbox: BytesMut,
    inflight: BTreeMap<Seq, Sent>,
    /// Seqs the peer NACKed, to fast-retransmit ahead of the RTO.
    fast_retx: VecDeque<Seq>,
    /// Local close requested (a FIN will be sent once the outbox drains).
    closing: bool,
    /// The seq assigned to our FIN, once sent.
    fin_seq: Option<Seq>,
    /// Our FIN has been acknowledged by the peer.
    local_fin_acked: bool,
    /// An RST is queued to send.
    rst_pending: bool,

    // --- receive side ---
    rcv_nxt: Seq,
    reorder: BTreeMap<Seq, Bytes>,
    delivered: BytesMut,
    /// The seq at which the remote's FIN sits (one past its last data segment).
    remote_fin_seq: Option<Seq>,
    /// The remote FIN has been delivered in order.
    remote_fin_recvd: bool,

    // --- ack / nack ---
    ack_pending: bool,
    /// The first missing seq to NACK, if a gap is open.
    nack_pending: Option<Seq>,

    // --- rtt / rto (ms) ---
    srtt_ms: Option<f64>,
    rttvar_ms: f64,
    rto_ms: u64,
}

impl Stream {
    /// Create a stream. Both peers must start from the same `initial_seq` (0 in practice).
    pub fn new(stream_id: u16, cfg: Config, initial_seq: Seq) -> Self {
        let rto_ms = cfg.initial_rto_ms;
        Stream {
            stream_id,
            cfg,
            state: State::Open,
            snd_una: initial_seq,
            snd_nxt: initial_seq,
            outbox: BytesMut::new(),
            inflight: BTreeMap::new(),
            fast_retx: VecDeque::new(),
            closing: false,
            fin_seq: None,
            local_fin_acked: false,
            rst_pending: false,
            rcv_nxt: initial_seq,
            reorder: BTreeMap::new(),
            delivered: BytesMut::new(),
            remote_fin_seq: None,
            remote_fin_recvd: false,
            ack_pending: false,
            nack_pending: None,
            srtt_ms: None,
            rttvar_ms: 0.0,
            rto_ms,
        }
    }

    /// Current lifecycle state.
    pub fn state(&self) -> State {
        self.state
    }

    /// Current retransmit timeout (ms) — exposed for tests/telemetry.
    pub fn rto_ms(&self) -> u64 {
        self.rto_ms
    }

    /// `true` once the remote's FIN has been delivered in order (application EOF).
    pub fn remote_finished(&self) -> bool {
        self.remote_fin_recvd
    }

    /// `true` when the stream is fully closed or reset.
    pub fn is_closed(&self) -> bool {
        matches!(self.state, State::Closed | State::Reset)
    }

    /// Queue application bytes for reliable, ordered delivery to the peer.
    pub fn write(&mut self, data: &[u8]) {
        self.outbox.extend_from_slice(data);
    }

    /// Request a graceful half-close: a FIN is sent after all queued bytes, and acknowledged in order.
    pub fn close(&mut self) {
        self.closing = true;
    }

    /// Abort the stream: queue an RST, drop send/receive buffers (delivered bytes are kept readable).
    pub fn reset(&mut self) {
        self.state = State::Reset;
        self.rst_pending = true;
        self.inflight.clear();
        self.outbox.clear();
        self.reorder.clear();
        self.fast_retx.clear();
    }

    /// Take the in-order bytes delivered so far (drains the delivery buffer).
    pub fn read(&mut self) -> Bytes {
        self.delivered.split().freeze()
    }

    /// Bytes currently available to [`read`](Self::read).
    pub fn readable(&self) -> usize {
        self.delivered.len()
    }

    /// Number of segments currently in flight (sent, unacked).
    fn inflight_count(&self) -> u32 {
        self.snd_nxt.wrapping_sub(self.snd_una)
    }

    /// The earliest RTO deadline among in-flight segments, if any (ms).
    pub fn next_deadline(&self) -> Option<u64> {
        self.inflight
            .values()
            .map(|s| s.sent_at + self.rto_ms)
            .min()
    }

    /// Process an incoming frame for this stream at time `now`.
    pub fn on_frame(&mut self, f: &Frame, now: u64) {
        match f.kind {
            Kind::Data => {
                if let Some(seq) = f.seq {
                    self.on_data(seq, f.payload.clone());
                }
            }
            Kind::Ack => {
                if let Some(ack) = f.seq {
                    self.on_ack(ack, now);
                }
            }
            Kind::Nack => {
                if let Some(seq) = f.seq {
                    if self.inflight.contains_key(&seq) && !self.fast_retx.contains(&seq) {
                        self.fast_retx.push_back(seq);
                    }
                }
            }
            Kind::Fin => {
                if let Some(seq) = f.seq {
                    self.on_fin(seq);
                }
            }
            Kind::Rst => {
                self.state = State::Reset;
                self.inflight.clear();
                self.outbox.clear();
                self.reorder.clear();
                self.fast_retx.clear();
            }
            Kind::KeepAlive => {
                self.ack_pending = true;
            }
            // SYN/SynAck are handled by the session layer, not the stream.
            Kind::Syn | Kind::SynAck => {}
        }
    }

    fn on_data(&mut self, seq: Seq, payload: Bytes) {
        // Always ack — even for duplicates/gaps — so the sender learns our cumulative position.
        self.ack_pending = true;

        if seq_lt(seq, self.rcv_nxt) {
            return; // already delivered
        }
        // Drop segments beyond the receive window.
        if !seq_lt(seq, self.rcv_nxt.wrapping_add(self.cfg.recv_window)) {
            return;
        }
        if seq == self.rcv_nxt {
            self.delivered.extend_from_slice(&payload);
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            self.advance_recv();
        } else {
            self.reorder.entry(seq).or_insert(payload);
            self.nack_pending = Some(self.rcv_nxt); // gap at rcv_nxt
        }
    }

    fn on_fin(&mut self, seq: Seq) {
        self.ack_pending = true;
        if self.remote_fin_seq.is_none() {
            self.remote_fin_seq = Some(seq);
        }
        self.advance_recv();
    }

    /// Deliver contiguous buffered segments, then consume the remote FIN if it sits at `rcv_nxt`.
    fn advance_recv(&mut self) {
        loop {
            if let Some(next) = self.reorder.remove(&self.rcv_nxt) {
                self.delivered.extend_from_slice(&next);
                self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
                continue;
            }
            if self.remote_fin_seq == Some(self.rcv_nxt) && !self.remote_fin_recvd {
                self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
                self.remote_fin_recvd = true;
                self.update_state();
            }
            break;
        }
        // A gap remains iff there are still buffered out-of-order segments.
        self.nack_pending = if self.reorder.is_empty() {
            None
        } else {
            Some(self.rcv_nxt)
        };
    }

    fn on_ack(&mut self, ack: Seq, now: u64) {
        // `ack` is the peer's next-expected seq: everything strictly before it is acknowledged.
        let mut newest_rtt: Option<u64> = None;
        let acked: Vec<Seq> = self
            .inflight
            .keys()
            .copied()
            .filter(|&s| seq_lt(s, ack))
            .collect();
        for s in acked {
            if let Some(sent) = self.inflight.remove(&s) {
                if sent.retx == 0 && !sent.is_fin {
                    // Karn's algorithm: sample RTT only from never-retransmitted data segments.
                    newest_rtt = Some(now.saturating_sub(sent.sent_at));
                }
            }
        }
        if seq_lt(self.snd_una, ack) {
            self.snd_una = ack;
        }
        if let Some(fs) = self.fin_seq {
            if seq_lt(fs, ack) {
                self.local_fin_acked = true;
            }
        }
        if let Some(r) = newest_rtt {
            self.update_rto(r as f64);
        }
        self.update_state();
    }

    /// RFC 6298 RTO estimator (ms).
    fn update_rto(&mut self, r: f64) {
        match self.srtt_ms {
            None => {
                self.srtt_ms = Some(r);
                self.rttvar_ms = r / 2.0;
            }
            Some(srtt) => {
                self.rttvar_ms = 0.75 * self.rttvar_ms + 0.25 * (srtt - r).abs();
                self.srtt_ms = Some(0.875 * srtt + 0.125 * r);
            }
        }
        let srtt = self.srtt_ms.unwrap_or(r);
        // RTO = SRTT + 4*RTTVAR, with a 1 ms granularity floor, clamped to [min, max].
        let rto = (srtt + 4.0 * self.rttvar_ms).max(1.0) as u64;
        self.rto_ms = rto.clamp(self.cfg.min_rto_ms, self.cfg.max_rto_ms);
    }

    fn update_state(&mut self) {
        if self.state == State::Reset {
            return;
        }
        let local_fin_sent = self.fin_seq.is_some();
        let local_done = local_fin_sent && self.local_fin_acked;
        self.state = match (local_done, self.remote_fin_recvd, local_fin_sent) {
            (true, true, _) => State::Closed,
            (_, true, _) => State::FinRcvd,
            (_, false, true) => State::FinSent,
            _ => State::Open,
        };
    }

    /// Pull the next frame to transmit at time `now`, or `None` if nothing is due. Priority:
    /// RST, NACK-triggered fast-retransmit, RTO retransmit, NACK, ACK, new data, FIN.
    pub fn poll_transmit(&mut self, now: u64) -> Option<Frame> {
        // RST preempts everything (and must go out even though state == Reset).
        if self.rst_pending {
            self.rst_pending = false;
            return Some(self.rst_frame());
        }
        if self.state == State::Reset {
            return None;
        }
        if self.state == State::Closed {
            // TIME_WAIT-ish: keep acknowledging the peer's FIN retransmits (so its FIN can still be
            // acked and it too can close), but send nothing new.
            if self.ack_pending {
                self.ack_pending = false;
                return Some(self.ack_frame());
            }
            return None;
        }

        // 1) Fast-retransmit a NACKed segment (no RTO backoff — a NACK is not a timeout).
        while let Some(seq) = self.fast_retx.pop_front() {
            if let Some(sent) = self.inflight.get_mut(&seq) {
                sent.sent_at = now;
                sent.retx += 1;
                let (data, is_fin) = (sent.data.clone(), sent.is_fin);
                return Some(self.seg_frame(seq, data, is_fin));
            }
        }

        // 2) Retransmit the lowest-seq segment whose RTO has expired.
        if let Some((&seq, _)) = self
            .inflight
            .iter()
            .find(|(_, s)| now >= s.sent_at + self.rto_ms)
        {
            let (data, is_fin) = {
                let sent = self.inflight.get_mut(&seq).expect("just found");
                sent.sent_at = now;
                sent.retx += 1;
                (sent.data.clone(), sent.is_fin)
            };
            // Exponential backoff on the RTO for repeated loss.
            self.rto_ms = (self.rto_ms.saturating_mul(2)).min(self.cfg.max_rto_ms);
            return Some(self.seg_frame(seq, data, is_fin));
        }

        // 3) A NACK for the first missing segment.
        if let Some(seq) = self.nack_pending.take() {
            return Some(self.nack_frame(seq));
        }

        // 4) A standalone ACK if one is pending.
        if self.ack_pending {
            self.ack_pending = false;
            return Some(self.ack_frame());
        }

        // 5) A new segment, if the window has room and there are queued bytes.
        if self.inflight_count() < self.cfg.send_window && !self.outbox.is_empty() {
            let take = self.outbox.len().min(self.cfg.max_segment);
            let data = self.outbox.split_to(take).freeze();
            let seq = self.snd_nxt;
            self.snd_nxt = self.snd_nxt.wrapping_add(1);
            self.inflight.insert(
                seq,
                Sent {
                    data: data.clone(),
                    sent_at: now,
                    retx: 0,
                    is_fin: false,
                },
            );
            return Some(self.seg_frame(seq, data, false));
        }

        // 6) The FIN, once all data is queued/sent and the window has room.
        if self.closing
            && self.fin_seq.is_none()
            && self.outbox.is_empty()
            && self.inflight_count() < self.cfg.send_window
        {
            let seq = self.snd_nxt;
            self.snd_nxt = self.snd_nxt.wrapping_add(1);
            self.fin_seq = Some(seq);
            self.inflight.insert(
                seq,
                Sent {
                    data: Bytes::new(),
                    sent_at: now,
                    retx: 0,
                    is_fin: true,
                },
            );
            self.update_state();
            return Some(self.seg_frame(seq, Bytes::new(), true));
        }

        None
    }

    fn seg_frame(&self, seq: Seq, payload: Bytes, is_fin: bool) -> Frame {
        Frame {
            kind: if is_fin { Kind::Fin } else { Kind::Data },
            stream_id: Some(self.stream_id),
            seq: Some(seq),
            fragment: None,
            comp_algo: None,
            payload,
        }
    }

    fn ack_frame(&self) -> Frame {
        Frame {
            kind: Kind::Ack,
            stream_id: Some(self.stream_id),
            seq: Some(self.rcv_nxt),
            fragment: None,
            comp_algo: None,
            payload: Bytes::new(),
        }
    }

    fn nack_frame(&self, seq: Seq) -> Frame {
        Frame {
            kind: Kind::Nack,
            stream_id: Some(self.stream_id),
            seq: Some(seq),
            fragment: None,
            comp_algo: None,
            payload: Bytes::new(),
        }
    }

    fn rst_frame(&self) -> Frame {
        Frame {
            kind: Kind::Rst,
            stream_id: Some(self.stream_id),
            seq: None,
            fragment: None,
            comp_algo: None,
            payload: Bytes::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic pseudo-random channel between two streams: configurable drop / duplicate /
    /// reorder, plus a fixed one-way latency, driven by the virtual clock.
    struct Sim {
        latency: u64,
        drop_pct: u32,
        dup_pct: u32,
        reorder_pct: u32,
        rng: u64,
        a_to_b: Vec<(u64, u64, Frame)>,
        b_to_a: Vec<(u64, u64, Frame)>,
        counter: u64,
    }

    impl Sim {
        fn new(latency: u64, drop_pct: u32, dup_pct: u32, reorder_pct: u32, seed: u64) -> Self {
            Sim {
                latency,
                drop_pct,
                dup_pct,
                reorder_pct,
                rng: seed | 1,
                a_to_b: Vec::new(),
                b_to_a: Vec::new(),
                counter: 0,
            }
        }
        fn next_rand(&mut self) -> u32 {
            let mut x = self.rng;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.rng = x;
            (x.wrapping_mul(0x2545F491_4F6CDD1D) >> 33) as u32
        }
        fn chance(&mut self, pct: u32) -> bool {
            self.next_rand() % 100 < pct
        }
        fn send(&mut self, from_a: bool, frame: Frame, now: u64) {
            if self.chance(self.drop_pct) {
                return;
            }
            let copies = if self.chance(self.dup_pct) { 2 } else { 1 };
            for _ in 0..copies {
                let extra = if self.chance(self.reorder_pct) {
                    self.latency + (self.next_rand() as u64 % 50)
                } else {
                    0
                };
                let at = now + self.latency + extra;
                let c = self.counter;
                self.counter += 1;
                if from_a {
                    self.a_to_b.push((at, c, frame.clone()));
                } else {
                    self.b_to_a.push((at, c, frame.clone()));
                }
            }
        }
        fn deliver_due(&mut self, to_b: bool, now: u64) -> Vec<Frame> {
            let q = if to_b {
                &mut self.a_to_b
            } else {
                &mut self.b_to_a
            };
            let mut due: Vec<(u64, u64, Frame)> =
                q.iter().filter(|(at, _, _)| *at <= now).cloned().collect();
            q.retain(|(at, _, _)| *at > now);
            due.sort_by_key(|(at, c, _)| (*at, *c));
            due.into_iter().map(|(_, _, f)| f).collect()
        }
        fn empty(&self) -> bool {
            self.a_to_b.is_empty() && self.b_to_a.is_empty()
        }
    }

    /// Advance the virtual clock to the next interesting instant: the earliest pending delivery or
    /// RTO deadline strictly after `now` (or `now + 1` if nothing is pending).
    fn next_time(a: &Stream, b: &Stream, sim: &Sim, now: u64) -> u64 {
        let mut cand: Vec<u64> = Vec::new();
        cand.extend(sim.a_to_b.iter().map(|(at, _, _)| *at));
        cand.extend(sim.b_to_a.iter().map(|(at, _, _)| *at));
        cand.extend(a.next_deadline());
        cand.extend(b.next_deadline());
        cand.into_iter()
            .filter(|&x| x > now)
            .min()
            .unwrap_or(now + 1)
    }

    /// Pump both streams through the sim until `done` holds or the step budget runs out.
    fn pump(
        a: &mut Stream,
        b: &mut Stream,
        sim: &mut Sim,
        got: &mut Vec<u8>,
        max_steps: u64,
        done: impl Fn(&Stream, &Stream, &Sim, &[u8]) -> bool,
    ) {
        let mut now = 0u64;
        for _ in 0..max_steps {
            while let Some(f) = a.poll_transmit(now) {
                sim.send(true, f, now);
            }
            while let Some(f) = b.poll_transmit(now) {
                sim.send(false, f, now);
            }
            for f in sim.deliver_due(true, now) {
                b.on_frame(&f, now);
            }
            for f in sim.deliver_due(false, now) {
                a.on_frame(&f, now);
            }
            got.extend_from_slice(&b.read());
            if done(a, b, sim, got) {
                return;
            }
            now = next_time(a, b, sim, now);
        }
    }

    fn run_transfer(
        a: &mut Stream,
        b: &mut Stream,
        sim: &mut Sim,
        payload: &[u8],
        max_steps: u64,
    ) -> Vec<u8> {
        a.write(payload);
        let mut got = Vec::new();
        let want = payload.len();
        pump(a, b, sim, &mut got, max_steps, |_, _, s, g| {
            g.len() >= want && s.empty()
        });
        got
    }

    fn payload_of(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(7))
            .collect()
    }

    #[test]
    fn perfect_channel_delivers_in_order() {
        let cfg = Config::default();
        let mut a = Stream::new(1, cfg, 0);
        let mut b = Stream::new(1, cfg, 0);
        let mut sim = Sim::new(10, 0, 0, 0, 0xABCD);
        let payload = payload_of(5000);
        let got = run_transfer(&mut a, &mut b, &mut sim, &payload, 100_000);
        assert_eq!(got, payload);
    }

    #[test]
    fn lossy_channel_recovers_via_rto() {
        let cfg = Config {
            initial_rto_ms: 100,
            min_rto_ms: 20,
            ..Config::default()
        };
        let mut a = Stream::new(1, cfg, 0);
        let mut b = Stream::new(1, cfg, 0);
        let mut sim = Sim::new(10, 30, 0, 0, 0x1357);
        let payload = payload_of(3000);
        let got = run_transfer(&mut a, &mut b, &mut sim, &payload, 1_000_000);
        assert_eq!(got, payload);
    }

    #[test]
    fn reordering_and_duplication_still_deliver() {
        let cfg = Config {
            initial_rto_ms: 100,
            min_rto_ms: 20,
            ..Config::default()
        };
        let mut a = Stream::new(1, cfg, 0);
        let mut b = Stream::new(1, cfg, 0);
        let mut sim = Sim::new(10, 10, 40, 60, 0x2468);
        let payload = payload_of(4000);
        let got = run_transfer(&mut a, &mut b, &mut sim, &payload, 1_000_000);
        assert_eq!(got, payload);
    }

    #[test]
    fn window_bounds_inflight() {
        let cfg = Config {
            send_window: 4,
            max_segment: 10,
            ..Config::default()
        };
        let mut a = Stream::new(1, cfg, 0);
        a.write(&payload_of(1000));
        let mut sent = 0;
        while let Some(f) = a.poll_transmit(0) {
            if f.kind == Kind::Data {
                sent += 1;
            }
        }
        assert_eq!(sent, 4, "in-flight is capped at the send window");
    }

    #[test]
    fn rto_adapts_to_measured_rtt() {
        let cfg = Config::default();
        let mut a = Stream::new(1, cfg, 0);
        a.write(&payload_of(50));
        let f = a.poll_transmit(0).unwrap();
        assert_eq!(f.kind, Kind::Data);
        let ack = Frame {
            kind: Kind::Ack,
            stream_id: Some(1),
            seq: Some(1),
            fragment: None,
            comp_algo: None,
            payload: Bytes::new(),
        };
        a.on_frame(&ack, 40);
        assert!(
            a.rto_ms() < 1_000,
            "RTO should drop after a fast RTT sample"
        );
        assert!(a.rto_ms() >= cfg.min_rto_ms);
    }

    #[test]
    fn receiver_nacks_first_missing_seq_on_gap() {
        let cfg = Config::default();
        let mut b = Stream::new(1, cfg, 0);
        // A future segment arrives while seq 0 is still missing → a gap at 0.
        let data1 = Frame {
            kind: Kind::Data,
            stream_id: Some(1),
            seq: Some(1),
            fragment: None,
            comp_algo: None,
            payload: Bytes::from_static(b"x"),
        };
        b.on_frame(&data1, 0);
        // NACK for the missing seq 0 is emitted (before the standalone ACK).
        let f = b.poll_transmit(0).unwrap();
        assert_eq!(f.kind, Kind::Nack);
        assert_eq!(f.seq, Some(0));
    }

    #[test]
    fn sender_fast_retransmits_on_nack_without_backoff() {
        let cfg = Config::default();
        let mut a = Stream::new(1, cfg, 0);
        a.write(&payload_of(300)); // several segments
                                   // Send three segments at t=0.
        for _ in 0..3 {
            assert_eq!(a.poll_transmit(0).unwrap().kind, Kind::Data);
        }
        let rto_before = a.rto_ms();
        // Peer NACKs seq 0.
        let nack = Frame {
            kind: Kind::Nack,
            stream_id: Some(1),
            seq: Some(0),
            fragment: None,
            comp_algo: None,
            payload: Bytes::new(),
        };
        a.on_frame(&nack, 5);
        let f = a.poll_transmit(5).unwrap();
        assert_eq!(f.kind, Kind::Data);
        assert_eq!(f.seq, Some(0), "fast-retransmits the NACKed segment");
        assert_eq!(a.rto_ms(), rto_before, "a NACK must not back off the RTO");
    }

    #[test]
    fn one_way_close_rests_at_fin_sent_and_delivers_eof() {
        // Only `a` closes: it should rest at FinSent (its FIN acked, but the peer hasn't FIN'd), and
        // `b` should see EOF (remote_finished) after all bytes.
        let cfg = Config {
            initial_rto_ms: 100,
            min_rto_ms: 20,
            ..Config::default()
        };
        let mut a = Stream::new(1, cfg, 0);
        let mut b = Stream::new(1, cfg, 0);
        let mut sim = Sim::new(10, 20, 10, 20, 0x9911);
        let payload = payload_of(2000);
        a.write(&payload);
        a.close();
        let want = payload.len();
        let mut got = Vec::new();
        pump(
            &mut a,
            &mut b,
            &mut sim,
            &mut got,
            1_000_000,
            |a, b, _, g| a.state() == State::FinSent && b.remote_finished() && g.len() >= want,
        );
        assert_eq!(got, payload, "all bytes delivered before EOF");
        assert!(b.remote_finished(), "receiver observed the FIN");
        assert_eq!(
            a.state(),
            State::FinSent,
            "one-way close: local FIN acked, peer still open"
        );
    }

    #[test]
    fn graceful_close_both_directions_reaches_closed() {
        let cfg = Config {
            initial_rto_ms: 100,
            min_rto_ms: 20,
            ..Config::default()
        };
        let mut a = Stream::new(1, cfg, 0);
        let mut b = Stream::new(1, cfg, 0);
        let mut sim = Sim::new(10, 20, 10, 20, 0x5AA5);
        let payload = payload_of(2000);
        a.write(&payload);
        a.close();
        b.close(); // symmetric close; b sends its own (data-less) FIN
        let mut got = Vec::new();
        pump(
            &mut a,
            &mut b,
            &mut sim,
            &mut got,
            1_000_000,
            |a, b, _, _| a.state() == State::Closed && b.state() == State::Closed,
        );
        assert_eq!(got, payload, "all bytes delivered");
        assert_eq!(a.state(), State::Closed);
        assert_eq!(b.state(), State::Closed);
    }

    #[test]
    fn reset_propagates_to_peer() {
        let cfg = Config::default();
        let mut a = Stream::new(1, cfg, 0);
        let mut b = Stream::new(1, cfg, 0);
        a.reset();
        let f = a.poll_transmit(0).expect("RST is emitted");
        assert_eq!(f.kind, Kind::Rst);
        assert_eq!(a.state(), State::Reset);
        b.on_frame(&f, 0);
        assert_eq!(b.state(), State::Reset);
        // No further frames after the RST.
        assert!(a.poll_transmit(1).is_none());
    }
}
