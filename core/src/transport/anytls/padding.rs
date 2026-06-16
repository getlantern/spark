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
//! This module is the **parser + model** only. The *engine* that applies a plan to an outgoing
//! write — splitting/padding the bytes and emitting `cmdWaste` fill — and the `padding-md5`
//! settings field are later chunks. Reference: `anytls/anytls-go` `docs/protocol.md`.

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
}
