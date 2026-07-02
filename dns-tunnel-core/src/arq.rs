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
//! right granularity for ARQ over a datagram carrier. Reliability = cumulative ACK + RTO retransmit
//! (adaptive RFC-6298); NACK fast-retransmit and the FIN/RST lifecycle are layered on in later steps.
//! There is deliberately **no congestion control** (§3): the send window + resolver rate-limit govern
//! the rate.

use std::collections::BTreeMap;

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
    /// A `FIN` has been sent (local half closed); still receiving.
    FinSent,
    /// A `FIN` has been received (remote half closed); still sending.
    FinRcvd,
    /// Fully closed.
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

    // --- receive side ---
    rcv_nxt: Seq,
    reorder: BTreeMap<Seq, Bytes>,
    delivered: BytesMut,

    // --- ack ---
    ack_pending: bool,

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
            rcv_nxt: initial_seq,
            reorder: BTreeMap::new(),
            delivered: BytesMut::new(),
            ack_pending: false,
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

    /// Queue application bytes for reliable, ordered delivery to the peer.
    pub fn write(&mut self, data: &[u8]) {
        self.outbox.extend_from_slice(data);
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

    /// The earliest RTO deadline among in-flight segments, if any (ms). The caller schedules its next
    /// `poll_transmit` for this time.
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
            // Nack / Fin / Rst handled in later steps.
            _ => {}
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
            // Drain any now-contiguous buffered segments.
            while let Some(next) = self.reorder.remove(&self.rcv_nxt) {
                self.delivered.extend_from_slice(&next);
                self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            }
        } else {
            self.reorder.entry(seq).or_insert(payload);
        }
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
                if sent.retx == 0 {
                    // Karn's algorithm: sample RTT only from never-retransmitted segments.
                    newest_rtt = Some(now.saturating_sub(sent.sent_at));
                }
            }
        }
        if seq_lt(self.snd_una, ack) {
            self.snd_una = ack;
        }
        if let Some(r) = newest_rtt {
            self.update_rto(r as f64);
        }
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

    /// Pull the next frame to transmit at time `now`, or `None` if nothing is due. Priority:
    /// 1) an RTO-expired retransmit, 2) a pending ACK, 3) a new segment within the window.
    pub fn poll_transmit(&mut self, now: u64) -> Option<Frame> {
        if matches!(self.state, State::Closed | State::Reset) {
            return None;
        }

        // 1) Retransmit the lowest-seq segment whose RTO has expired.
        if let Some((&seq, _)) = self
            .inflight
            .iter()
            .find(|(_, s)| now >= s.sent_at + self.rto_ms)
        {
            let data = {
                let sent = self.inflight.get_mut(&seq).expect("just found");
                sent.sent_at = now;
                sent.retx += 1;
                sent.data.clone()
            };
            // Exponential backoff on the RTO for repeated loss.
            self.rto_ms = (self.rto_ms.saturating_mul(2)).min(self.cfg.max_rto_ms);
            return Some(self.data_frame(seq, data));
        }

        // 2) A standalone ACK if one is pending.
        if self.ack_pending {
            self.ack_pending = false;
            return Some(self.ack_frame());
        }

        // 3) A new segment, if the window has room and there are queued bytes.
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
                },
            );
            return Some(self.data_frame(seq, data));
        }

        None
    }

    fn data_frame(&self, seq: Seq, payload: Bytes) -> Frame {
        Frame {
            kind: Kind::Data,
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
        // (deliver_at, seq_counter, dir, frame) — seq_counter breaks ties deterministically.
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
            // xorshift64*
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
                return; // dropped
            }
            let copies = if self.chance(self.dup_pct) { 2 } else { 1 };
            for _ in 0..copies {
                // Reordering: occasionally deliver a bit later than normal.
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
        /// Drain frames due at or before `now` for the A→B (`to_b=true`) or B→A direction.
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

    /// Drive a one-way transfer of `payload` from `a` to `b` through `sim`; return the bytes `b`
    /// received. Panics if it does not complete within the step budget.
    fn run_transfer(
        a: &mut Stream,
        b: &mut Stream,
        sim: &mut Sim,
        payload: &[u8],
        max_steps: u64,
    ) -> Vec<u8> {
        a.write(payload);
        let mut got = Vec::new();
        let mut now = 0u64;
        for _ in 0..max_steps {
            // Transmit everything currently due from both sides.
            while let Some(f) = a.poll_transmit(now) {
                sim.send(true, f, now);
            }
            while let Some(f) = b.poll_transmit(now) {
                sim.send(false, f, now);
            }
            // Deliver frames due now.
            for f in sim.deliver_due(true, now) {
                b.on_frame(&f, now);
            }
            for f in sim.deliver_due(false, now) {
                a.on_frame(&f, now);
            }
            let chunk = b.read();
            got.extend_from_slice(&chunk);
            if got.len() >= payload.len() && sim.empty() {
                break;
            }
            // Advance to the next interesting time: min of pending deliveries and RTO deadlines.
            now = next_time(a, b, sim, now);
        }
        got
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
        // 30% loss, both directions (so ACKs drop too).
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
        // Heavy reorder + duplication, modest loss.
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
        // Drain new-data transmits at t=0 (no acks yet): at most `send_window` segments go out.
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
        // Ack it at t=40ms → an RTT sample of 40ms pulls the RTO well below the 1s initial.
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
}
