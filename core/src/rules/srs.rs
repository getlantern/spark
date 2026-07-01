//! Parser for sing-box compiled rule-sets (`.srs`).
//!
//! Wire format (pinned against the real getlantern/KaringX rule-sets in the config): ASCII `"SRS"`
//! magic (3 bytes) + a 1-byte version + a zlib stream. Versions 1, 2, and 3 are all in active use
//! across the configured rule-sets, so all three are accepted. The decompressed body is a
//! `uvarint` rule count followed by typed rule records; domains are stored in sing-box's succinct
//! domain set. Authoritative encoding: `sagernet/sing-box` `common/srs` + `sagernet/sing`
//! `common/domain`.
//!
//! This file currently implements the envelope (magic/version/inflate); the rule-record + domain-set
//! decode lands in the next tasks.

// TEMP (remove at task M1.4): the envelope is currently exercised only by unit tests; the public
// `parse()` that consumes it lands in M1.4. Allow dead code so incremental commits stay clippy-clean.
#![allow(dead_code)]

use std::io::Read;

/// Errors from parsing a sing-box `.srs` rule-set.
#[derive(Debug, thiserror::Error)]
pub enum SrsError {
    /// The input does not start with the `"SRS"` magic.
    #[error(".srs: bad magic (not \"SRS\")")]
    BadMagic,
    /// The input ended before a required field was fully read.
    #[error(".srs: truncated input")]
    Truncated,
    /// The version byte is outside the supported range (1..=3).
    #[error(".srs: unsupported version {0} (supported: 1..=3)")]
    UnsupportedVersion(u8),
    /// The zlib body failed to inflate.
    #[error(".srs: zlib inflate failed: {0}")]
    Inflate(#[from] std::io::Error),
    /// The decompressed rule body was malformed.
    #[error(".srs: malformed rule body: {0}")]
    Malformed(&'static str),
}

/// The `"SRS"` magic that prefixes every rule-set.
const MAGIC: &[u8; 3] = b"SRS";

/// The `.srs` envelope after magic + version have been stripped and the body inflated.
#[derive(Debug)]
pub(crate) struct Envelope {
    /// The format version byte (1, 2, or 3).
    pub version: u8,
    /// The zlib-inflated rule body.
    pub body: Vec<u8>,
}

/// Decode the `.srs` envelope: 3-byte `"SRS"` magic, a 1-byte version (1..=3), then a zlib stream.
pub(crate) fn decode_envelope(bytes: &[u8]) -> Result<Envelope, SrsError> {
    if bytes.len() < 4 {
        return Err(SrsError::Truncated);
    }
    if &bytes[..3] != MAGIC {
        return Err(SrsError::BadMagic);
    }
    let version = bytes[3];
    if !(1..=3).contains(&version) {
        return Err(SrsError::UnsupportedVersion(version));
    }
    let mut body = Vec::new();
    flate2::read::ZlibDecoder::new(&bytes[4..]).read_to_end(&mut body)?;
    Ok(Envelope { version, body })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `cargo test` runs with the crate root (`core/`) as the working directory, so the fixtures
    /// (real rule-sets from the live config) resolve at `tests/fixtures/srs/`.
    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!("tests/fixtures/srs/{name}.srs"))
            .unwrap_or_else(|e| panic!("read fixture {name}: {e}"))
    }

    #[test]
    fn envelope_accepts_v1_v2_v3() {
        for (name, want_ver) in [("common_v3", 3u8), ("banad_v1", 1), ("category-ads_v2", 2)] {
            let env = decode_envelope(&fixture(name)).expect("decode envelope");
            assert_eq!(env.version, want_ver, "{name} version");
            assert!(!env.body.is_empty(), "{name}: decompressed body is empty");
        }
    }

    #[test]
    fn envelope_rejects_bad_magic_and_truncation() {
        assert!(matches!(
            decode_envelope(b"ZZZ\x01").unwrap_err(),
            SrsError::BadMagic
        ));
        assert!(matches!(
            decode_envelope(b"SR").unwrap_err(),
            SrsError::Truncated
        ));
        assert!(matches!(
            decode_envelope(b"SRS\x09").unwrap_err(),
            SrsError::UnsupportedVersion(9)
        ));
    }
}
