//! AnyTLS padding scheme — the parsed, server-pushable plan that shapes TLS *record sizes* to
//! defeat TLS-in-TLS fingerprinting (Xue et al., USENIX Security 2024).
//!
//! The scheme is newline-separated `key=value` text:
//!
//! ```text
//! stop=8
//! 0=30-30
//! 1=100-400
//! 2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
//! 3=9-9,500-1000
//! ...
//! ```
//!
//! - `stop=N` — only packets `0..N` (counted as TLS *write* operations) get padding treatment;
//!   later writes are sent as-is.
//! - `i=seg,seg,…` — the split/pad plan for the i-th write. Each segment is either a size range
//!   `LO-HI` (the chunk's plaintext size is chosen uniformly in `[LO, HI]`; `X-X` is a fixed size)
//!   or `c` ("check": if user data is exhausted at this point, stop padding this packet).
//!
//! Two pieces: the scheme [`PaddingScheme`] (parser/model) and the [`shape_records`] engine that
//! applies a scheme to an outgoing write — splitting it into record-sized chunks and emitting
//! `cmdWaste` fill — faithfully reproducing anytls-go's `session.writeConn`. (The `padding-md5`
//! settings field is computed elsewhere; see [`super::settings`].) Reference:
//! `anytls/anytls-go` `proxy/padding/padding.go` + `proxy/session/session.go`.

use bytes::{BufMut, Bytes, BytesMut};

use super::frame::{Command, HEADER_LEN, MAX_PAYLOAD};

/// One element of a packet's padding plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seg {
    /// Emit a chunk whose plaintext size is chosen uniformly in `[lo, hi]` (`lo == hi` is fixed).
    Size {
        /// Inclusive lower bound.
        lo: u32,
        /// Inclusive upper bound (`>= lo`).
        hi: u32,
    },
    /// "check": if user data is exhausted here, return from the write and stop padding this packet.
    Check,
}

/// The default scheme the server pushes if it has none configured (from `docs/protocol.md`).
pub const DEFAULT_SCHEME: &str = "stop=8\n\
    0=30-30\n\
    1=100-400\n\
    2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n\
    3=9-9,500-1000\n\
    4=500-1000\n\
    5=500-1000\n\
    6=500-1000\n\
    7=500-1000";

/// A parsed AnyTLS padding scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaddingScheme {
    stop: usize,
    /// Per-packet plans, indexed by write number `0..stop`. An unspecified packet has an empty plan.
    plans: Vec<Vec<Seg>>,
    /// The exact source text, kept verbatim for the `padding-md5` settings field (a later chunk).
    raw: String,
}

impl PaddingScheme {
    /// Parse a scheme from its `key=value` text. Lines beyond `stop` are accepted but ignored
    /// (they would never receive padding treatment).
    pub fn parse(s: &str) -> Result<PaddingScheme, PaddingError> {
        let mut stop: Option<usize> = None;
        let mut entries: Vec<(usize, Vec<Seg>)> = Vec::new();

        for line in s.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| PaddingError::MalformedLine(line.to_owned()))?;
            let (key, value) = (key.trim(), value.trim());
            if key == "stop" {
                stop = Some(parse_usize(value)?);
            } else {
                let idx = parse_usize(key)?;
                entries.push((idx, parse_segments(value)?));
            }
        }

        let stop = stop.ok_or(PaddingError::MissingStop)?;
        let mut plans = vec![Vec::new(); stop];
        for (idx, segs) in entries {
            if idx < stop {
                plans[idx] = segs; // last write of a duplicate index wins
            }
        }
        Ok(PaddingScheme {
            stop,
            plans,
            raw: s.to_owned(),
        })
    }

    /// Packets with index `>= stop` get no padding treatment.
    pub fn stop(&self) -> usize {
        self.stop
    }

    /// The plan for the `packet`-th TLS write — empty if `packet >= stop` or it was unspecified.
    pub fn plan(&self, packet: usize) -> &[Seg] {
        self.plans.get(packet).map_or(&[], Vec::as_slice)
    }

    /// The verbatim source text (for the `padding-md5` settings field).
    pub fn raw(&self) -> &str {
        &self.raw
    }
}

impl Default for PaddingScheme {
    /// The [`DEFAULT_SCHEME`]. Parsing it is a build-time invariant (guarded by a unit test).
    fn default() -> Self {
        PaddingScheme::parse(DEFAULT_SCHEME).expect("DEFAULT_SCHEME parses")
    }
}

fn parse_usize(tok: &str) -> Result<usize, PaddingError> {
    tok.parse()
        .map_err(|_| PaddingError::InvalidNumber(tok.to_owned()))
}

/// Parse the comma-separated segment list on the right of a packet line. Empty tokens are
/// tolerated (so a trailing comma is harmless).
fn parse_segments(value: &str) -> Result<Vec<Seg>, PaddingError> {
    let mut segs = Vec::new();
    for tok in value.split(',') {
        let tok = tok.trim();
        if tok.is_empty() {
            continue;
        }
        if tok == "c" {
            segs.push(Seg::Check);
            continue;
        }
        let (lo, hi) = tok
            .split_once('-')
            .ok_or_else(|| PaddingError::InvalidSegment(tok.to_owned()))?;
        let lo: u32 = lo
            .trim()
            .parse()
            .map_err(|_| PaddingError::InvalidSegment(tok.to_owned()))?;
        let hi: u32 = hi
            .trim()
            .parse()
            .map_err(|_| PaddingError::InvalidSegment(tok.to_owned()))?;
        if lo > hi {
            return Err(PaddingError::InvalidRange { lo, hi });
        }
        segs.push(Seg::Size { lo, hi });
    }
    Ok(segs)
}

/// Errors from parsing a padding scheme.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PaddingError {
    /// No `stop=N` line was present.
    #[error("padding scheme has no `stop` line")]
    MissingStop,
    /// A non-empty line without an `=`.
    #[error("malformed padding line: {0:?}")]
    MalformedLine(String),
    /// A key or `stop` value that is not a non-negative integer.
    #[error("invalid number in padding scheme: {0:?}")]
    InvalidNumber(String),
    /// A segment token that is neither `c` nor a `LO-HI` range.
    #[error("invalid padding segment: {0:?}")]
    InvalidSegment(String),
    /// A range whose lower bound exceeds its upper bound.
    #[error("invalid padding range: {lo} > {hi}")]
    InvalidRange {
        /// The (too-large) lower bound.
        lo: u32,
        /// The upper bound.
        hi: u32,
    },
}

/// Picks a concrete record size in `[lo, hi]` for a [`Seg::Size`] segment. Injected so the
/// [`shape_records`] engine is deterministic in tests; production uses [`SystemSampler`].
pub trait SizeSampler {
    /// A size in `[lo, hi]` (callers guarantee `lo <= hi`).
    fn sample(&mut self, lo: u32, hi: u32) -> u32;
}

/// Uniform sampling via the system CSPRNG (`ring`). A negligible modulo bias over a
/// hundreds-wide range is irrelevant for traffic shaping; falls back to `lo` if the RNG errors.
pub struct SystemSampler(ring::rand::SystemRandom);

impl SystemSampler {
    /// A new sampler.
    pub fn new() -> Self {
        SystemSampler(ring::rand::SystemRandom::new())
    }
}

impl Default for SystemSampler {
    fn default() -> Self {
        SystemSampler::new()
    }
}

impl SizeSampler for SystemSampler {
    fn sample(&mut self, lo: u32, hi: u32) -> u32 {
        use ring::rand::SecureRandom;
        if hi <= lo {
            return lo;
        }
        let span = (hi - lo) as u64 + 1;
        let mut b = [0u8; 4];
        match self.0.fill(&mut b) {
            Ok(()) => lo + (u32::from_le_bytes(b) as u64 % span) as u32,
            Err(_) => lo,
        }
    }
}

/// Append a `cmdWaste` frame carrying `data_len` zero bytes (clamped to the 2-byte length).
fn push_waste(dst: &mut BytesMut, data_len: usize) {
    let data_len = data_len.min(MAX_PAYLOAD);
    dst.reserve(HEADER_LEN + data_len);
    dst.put_u8(Command::Waste as u8);
    dst.put_u32(0); // session-level, stream 0
    dst.put_u16(data_len as u16);
    dst.resize(dst.len() + data_len, 0); // zero padding, no separate allocation
}

/// Split the already-encoded outgoing bytes `data` for the `pkt`-th TLS write into record-sized
/// chunks per `scheme`, inserting `cmdWaste` frames to fill — one returned [`Bytes`] per record
/// (each is one transport write). Faithful to anytls-go `session.writeConn`:
///
/// - `pkt >= scheme.stop()` → no padding: the data is returned as a single record (or none if empty).
/// - otherwise, for each sampled record size `l` in the packet's plan: emit `l` real bytes if at
///   least that many remain; else emit the remaining real bytes plus a `cmdWaste` frame filling the
///   record to `l` (only if the `> HEADER_LEN`-byte gap fits a frame); else emit a `cmdWaste` frame
///   carrying `l` bytes. A [`Seg::Check`] reached with the payload exhausted stops padding the
///   packet; any real bytes left after the plan are written directly.
///
/// `pkt` is 1-based to match the reference (the first non-buffered write is packet 1; the `0=` line
/// is never consulted).
pub fn shape_records(
    scheme: &PaddingScheme,
    pkt: usize,
    data: Bytes,
    sampler: &mut dyn SizeSampler,
) -> Vec<Bytes> {
    if pkt >= scheme.stop() {
        return if data.is_empty() {
            Vec::new()
        } else {
            vec![data]
        };
    }

    let mut records = Vec::new();
    let mut b = data;
    for seg in scheme.plan(pkt) {
        let l = match *seg {
            Seg::Check => {
                if b.is_empty() {
                    return records; // payload exhausted at a check → stop padding this packet
                }
                continue;
            }
            Seg::Size { lo, hi } => sampler.sample(lo, hi) as usize,
        };
        if b.len() > l {
            // A full record of real payload.
            records.push(b.slice(..l));
            b = b.slice(l..);
        } else if !b.is_empty() {
            // The last of the real payload, padded up to `l` with a waste frame if the gap fits.
            let real = b.len();
            let mut rec = BytesMut::with_capacity(l.max(real + HEADER_LEN));
            rec.extend_from_slice(&b);
            if l > real + HEADER_LEN {
                push_waste(&mut rec, l - real - HEADER_LEN);
            }
            records.push(rec.freeze());
            b = Bytes::new();
        } else {
            // A pure-padding record: a waste frame carrying `l` bytes (HEADER_LEN + l on the wire).
            let mut rec = BytesMut::with_capacity(HEADER_LEN + l);
            push_waste(&mut rec, l);
            records.push(rec.freeze());
        }
    }
    if !b.is_empty() {
        records.push(b); // remainder after the plan → sent directly
    }
    records
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_scheme_parses_as_documented() {
        let s = PaddingScheme::default();
        assert_eq!(s.stop(), 8);
        assert_eq!(s.plan(0), &[Seg::Size { lo: 30, hi: 30 }]);
        assert_eq!(s.plan(1), &[Seg::Size { lo: 100, hi: 400 }]);
        assert_eq!(
            s.plan(2),
            &[
                Seg::Size { lo: 400, hi: 500 },
                Seg::Check,
                Seg::Size { lo: 500, hi: 1000 },
                Seg::Check,
                Seg::Size { lo: 500, hi: 1000 },
                Seg::Check,
                Seg::Size { lo: 500, hi: 1000 },
                Seg::Check,
                Seg::Size { lo: 500, hi: 1000 },
            ]
        );
        assert_eq!(
            s.plan(3),
            &[Seg::Size { lo: 9, hi: 9 }, Seg::Size { lo: 500, hi: 1000 }]
        );
        // Packets at/after `stop` get no treatment.
        assert!(s.plan(8).is_empty());
        assert!(s.plan(100).is_empty());
        // raw() preserves the source for the future padding-md5.
        assert_eq!(s.raw(), DEFAULT_SCHEME);
    }

    #[test]
    fn tolerates_whitespace_blank_lines_and_trailing_commas() {
        let s = PaddingScheme::parse("  stop = 2 \n\n0 = 10-20 , \n 1=c\n").expect("parse");
        assert_eq!(s.stop(), 2);
        assert_eq!(s.plan(0), &[Seg::Size { lo: 10, hi: 20 }]);
        assert_eq!(s.plan(1), &[Seg::Check]);
    }

    #[test]
    fn ignores_packet_indices_at_or_beyond_stop() {
        let s = PaddingScheme::parse("stop=1\n0=10-10\n5=99-99").expect("parse");
        assert_eq!(s.plan(0), &[Seg::Size { lo: 10, hi: 10 }]);
        assert!(s.plan(5).is_empty(), "index 5 >= stop 1 is ignored");
    }

    #[test]
    fn rejects_missing_stop() {
        assert_eq!(
            PaddingScheme::parse("0=10-20").err(),
            Some(PaddingError::MissingStop)
        );
    }

    #[test]
    fn rejects_malformed_lines_and_numbers() {
        assert!(matches!(
            PaddingScheme::parse("stop=2\nnotakeyvalue"),
            Err(PaddingError::MalformedLine(_))
        ));
        assert!(matches!(
            PaddingScheme::parse("stop=abc"),
            Err(PaddingError::InvalidNumber(_))
        ));
        assert!(matches!(
            PaddingScheme::parse("stop=2\nx=10-20"),
            Err(PaddingError::InvalidNumber(_))
        ));
    }

    #[test]
    fn rejects_bad_segments_and_ranges() {
        assert!(matches!(
            PaddingScheme::parse("stop=1\n0=notarange"),
            Err(PaddingError::InvalidSegment(_))
        ));
        assert_eq!(
            PaddingScheme::parse("stop=1\n0=1000-500").err(),
            Some(PaddingError::InvalidRange { lo: 1000, hi: 500 })
        );
    }

    // ---- padding engine ----

    /// Deterministic sampler: always the low end of a range.
    struct MinSampler;
    impl SizeSampler for MinSampler {
        fn sample(&mut self, lo: u32, _hi: u32) -> u32 {
            lo
        }
    }

    #[test]
    fn no_padding_at_or_beyond_stop() {
        let scheme = PaddingScheme::default(); // stop=8
        let data = Bytes::from_static(b"already-encoded frames");
        assert_eq!(
            shape_records(&scheme, 8, data.clone(), &mut MinSampler),
            vec![data]
        );
        assert!(shape_records(&scheme, 9, Bytes::new(), &mut MinSampler).is_empty());
    }

    #[test]
    fn real_payload_is_preserved_and_waste_is_separable() {
        use crate::transport::anytls::frame::Frame;
        // Two whole frames as the outgoing data.
        let mut data = BytesMut::new();
        Frame::new(Command::Psh, 1, Bytes::from_static(b"the target address"))
            .unwrap()
            .encode(&mut data);
        Frame::new(Command::Psh, 1, Bytes::from_static(b"hello world payload"))
            .unwrap()
            .encode(&mut data);
        let data = data.freeze();

        // pkt 1 plan = [Size{100,400}]; MinSampler → 100, and 100 > data.len() so the record is the
        // real bytes padded to 100 with a waste frame.
        let recs = shape_records(&PaddingScheme::default(), 1, data.clone(), &mut MinSampler);

        // Concatenate the records, parse the frame stream, drop waste, and re-encode the rest.
        let mut joined = BytesMut::new();
        for r in &recs {
            joined.extend_from_slice(r);
        }
        let mut rebuilt = BytesMut::new();
        while let Some(f) = Frame::decode(&mut joined).unwrap() {
            if f.command != Command::Waste {
                f.encode(&mut rebuilt);
            }
        }
        assert_eq!(
            rebuilt.freeze(),
            data,
            "real payload round-trips, waste removed"
        );
    }

    #[test]
    fn check_stops_padding_once_payload_is_exhausted() {
        // pkt 2 = [400-500, c, 500-1000, c, ...]; MinSampler → first size 400. 50 bytes of payload
        // fill one 400-byte record (real + waste), then the `c` with payload gone stops padding.
        let recs = shape_records(
            &PaddingScheme::default(),
            2,
            Bytes::from(vec![0xCDu8; 50]),
            &mut MinSampler,
        );
        assert_eq!(recs.len(), 1, "check stops padding after payload exhausted");
        assert_eq!(recs[0].len(), 400, "record padded up to the sampled size");
    }

    #[test]
    fn payload_larger_than_plan_is_chunked_then_sent_directly() {
        // pkt 1 = [Size{100,400}]; MinSampler → 100. 1000 bytes → one 100-byte record, then the
        // 900-byte remainder sent directly. No waste (payload exceeds the plan).
        let data = Bytes::from(vec![0xABu8; 1000]);
        let recs = shape_records(&PaddingScheme::default(), 1, data.clone(), &mut MinSampler);
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].len(), 100);
        assert_eq!(recs[1].len(), 900);
        let total: usize = recs.iter().map(Bytes::len).sum();
        assert_eq!(total, 1000, "no waste added when payload exceeds the plan");
    }
}
