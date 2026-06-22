//! Hysteria 2 /auth HTTP/3 request construction and response parsing.
//!
//! Hysteria 2 authenticates by sending a single HTTP/3 request on a QUIC bidi stream:
//!
//! ```text
//! :method POST   :path /auth   :scheme https   :authority hysteria
//! Hysteria-Auth: <credential>
//! Hysteria-CC-RX: <uint>      (client rx rate, bytes/s; 0 = unknown)
//! Hysteria-Padding: <random>  (ignored)
//! ```
//!
//! The server replies with HTTP status **233** ("HyOK") on success.
//!
//! An HTTP/3 message is a sequence of HTTP/3 frames (RFC 9114). The headers are a single
//! **HEADERS frame** (RFC 9114 §7.2.2): `varint(type=0x01) ‖ varint(len) ‖ field-section`,
//! where the field section is QPACK-encoded (RFC 9204).
//!
//! This is a deliberately minimal, hand-rolled QPACK codec that uses an **empty dynamic
//! table** and only the static-table *names* it needs. It is NOT a general QPACK
//! implementation; it does exactly what the Hysteria 2 /auth exchange requires.

// Consumed by the auth handshake (Task 8); remove at the final sweep.
#![allow(dead_code)]

use std::io;

use super::tcp::{read_varint, write_varint};

/// HTTP/3 HEADERS frame type (RFC 9114 §7.2.2).
const H3_FRAME_HEADERS: u64 = 0x01;

// ---------------------------------------------------------------------------
// QPACK static-table names we care about (RFC 9204 Appendix A).
//
// We only need to map an index -> field *name* (values are read from the literal that
// follows a name-reference, never from the table). The `:status` pseudo-header appears at
// several indices; we list all of them so a name reference to any `:status` entry resolves
// correctly regardless of which one quic-go's qpack happens to pick.
// ---------------------------------------------------------------------------

/// `:status` lives at these static-table indices (RFC 9204 Appendix A): 24 (103), 25 (200),
/// 26 (304), 27 (404), 28 (503), and 63..=71 (100/204/206/302/400/403/421/425/500).
const STATUS_INDICES: &[u64] = &[24, 25, 26, 27, 28, 63, 64, 65, 66, 67, 68, 69, 70, 71];

/// Resolve a QPACK static-table index to its field *name*, for the handful of indices the
/// /auth response can plausibly use. Returns `None` for indices we do not model; callers must
/// still be able to advance the parser past such field lines (which they do — the encoding
/// carries its own lengths).
fn static_name(index: u64) -> Option<&'static str> {
    if STATUS_INDICES.contains(&index) {
        return Some(":status");
    }
    match index {
        0 => Some(":authority"),
        1 => Some(":path"),
        15..=21 => Some(":method"),
        22 | 23 => Some(":scheme"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// RFC 7541 §5.1 prefixed integers.
// ---------------------------------------------------------------------------

/// Append `value` as an RFC 7541 §5.1 prefixed integer with a `prefix_bits`-bit prefix.
///
/// `flags` is OR'd into the high bits of the first byte (the bits above the prefix), e.g. the
/// `001` pattern for a literal-with-literal-name name length, or `0x00` for a bare value.
fn encode_prefixed_int(out: &mut Vec<u8>, prefix_bits: u8, flags: u8, value: u64) {
    let max = (1u64 << prefix_bits) - 1;
    if value < max {
        out.push(flags | value as u8);
        return;
    }
    out.push(flags | max as u8);
    let mut v = value - max;
    while v >= 128 {
        out.push((v % 128 + 128) as u8);
        v /= 128;
    }
    out.push(v as u8);
}

/// Read an RFC 7541 §5.1 prefixed integer with a `prefix_bits`-bit prefix from the front of
/// `buf`. The non-prefix (flag) bits of the first byte are ignored. Returns `(value, rest)`.
fn read_prefixed_int(buf: &[u8], prefix_bits: u8) -> Option<(u64, &[u8])> {
    let (&first, mut rest) = buf.split_first()?;
    let max = (1u64 << prefix_bits) - 1;
    let value = (first as u64) & max;
    if value < max {
        return Some((value, rest));
    }
    // Continuation bytes: 7 bits each, low byte first, high bit = "more".
    let mut value = max;
    let mut shift = 0u32;
    loop {
        let (&b, tail) = rest.split_first()?;
        rest = tail;
        value = value.checked_add(((b & 0x7f) as u64).checked_shl(shift)?)?;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        // A 64-bit value never needs more than ~10 continuation bytes; guard against a
        // malicious encoder spinning us forever.
        if shift > 63 {
            return None;
        }
    }
    Some((value, rest))
}

// ---------------------------------------------------------------------------
// QPACK field-line encoders (empty dynamic table; everything literal).
// ---------------------------------------------------------------------------

/// Encode a "Literal Field Line With Literal Name" (RFC 9204 §4.5.6), Huffman off, N=0.
///
/// First byte: `001` pattern (`0x20`) plus a 3-bit-prefix name length, then the name bytes;
/// then the value as an 8-bit-prefix (7-bit length) string literal with the H bit clear.
fn encode_literal_field(out: &mut Vec<u8>, name: &str, value: &str) {
    // Name: 001 N H NameLen(3-bit) — pattern 0x20, N=0, H=0.
    encode_prefixed_int(out, 3, 0x20, name.len() as u64);
    out.extend_from_slice(name.as_bytes());
    // Value: H + 7-bit length, H=0.
    encode_prefixed_int(out, 7, 0x00, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}

/// Build a QPACK field section (the body of a HEADERS frame) from `(name, value)` pairs.
///
/// Begins with the Encoded Field Section Prefix (RFC 9204 §4.5.1): Required Insert Count = 0
/// (`0x00`) and Base = 0 / Sign = 0 (`0x00`), i.e. no dynamic-table references.
fn encode_field_section(headers: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.push(0x00); // Required Insert Count = 0
    out.push(0x00); // S=0, Delta Base = 0
    for (name, value) in headers {
        encode_literal_field(&mut out, name, value);
    }
    out
}

/// Wrap a QPACK field section in an HTTP/3 HEADERS frame: `varint(0x01) ‖ varint(len) ‖ body`.
fn headers_frame(field_section: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(field_section.len() + 4);
    write_varint(&mut out, H3_FRAME_HEADERS);
    write_varint(&mut out, field_section.len() as u64);
    out.extend_from_slice(field_section);
    out
}

/// Encode the Hysteria 2 /auth request as a single HTTP/3 HEADERS frame.
///
/// `credential` is the shared secret sent in `Hysteria-Auth`; `rx_bps` is the client's
/// declared receive rate in bytes/s (`0` means "unknown") sent in `Hysteria-CC-RX`.
pub fn encode_auth_request(credential: &str, rx_bps: u64) -> Vec<u8> {
    let rx = rx_bps.to_string();
    let headers: [(&str, &str); 6] = [
        (":method", "POST"),
        (":path", "/auth"),
        (":scheme", "https"),
        (":authority", "hysteria"),
        ("hysteria-auth", credential),
        ("hysteria-cc-rx", &rx),
    ];
    headers_frame(&encode_field_section(&headers))
}

// ---------------------------------------------------------------------------
// QPACK field-section decoder (enough to extract `:status`).
// ---------------------------------------------------------------------------

fn eof(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, msg)
}

fn malformed(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// Read a `prefix_bits`-bit-prefix string literal (RFC 9204 §4.1.2): one H bit (which we
/// reject when set — we don't implement Huffman) followed by the length, then the bytes.
/// The H bit is the most-significant bit of the first byte, i.e. bit `1 << prefix_bits`.
fn read_string_literal(buf: &[u8], prefix_bits: u8) -> io::Result<(Vec<u8>, &[u8])> {
    let &first = buf.first().ok_or_else(|| eof("string literal: empty"))?;
    if first & (1 << prefix_bits) != 0 {
        return Err(malformed("string literal: Huffman not supported"));
    }
    let (len, rest) =
        read_prefixed_int(buf, prefix_bits).ok_or_else(|| eof("string literal: bad length"))?;
    let len = len as usize;
    let bytes = rest
        .get(..len)
        .ok_or_else(|| eof("string literal: truncated"))?;
    Ok((bytes.to_vec(), &rest[len..]))
}

/// One decoded field line: its name (resolved if it came from the static table) and value.
struct FieldLine {
    name: Option<String>,
    value: Option<String>,
}

/// Parse a single QPACK field-line representation from the front of `buf`, returning the
/// decoded line and the remaining bytes. Handles the three forms quic-go can emit:
/// Indexed (§4.5.2), Literal w/ Name Reference (§4.5.4), Literal w/ Literal Name (§4.5.6).
fn parse_field_line(buf: &[u8]) -> io::Result<(FieldLine, &[u8])> {
    let &first = buf.first().ok_or_else(|| eof("field line: empty"))?;

    if first & 0x80 != 0 {
        // Indexed Field Line: 1 T <6-bit index>. T (0x40) selects static/dynamic. No value
        // follows — the entry carries both name and value. We resolve the name when we can
        // (only static entries) and never have a literal value here.
        let t_static = first & 0x40 != 0;
        let (index, rest) = read_prefixed_int(buf, 6).ok_or_else(|| eof("indexed: bad index"))?;
        let name = if t_static {
            static_name(index).map(str::to_owned)
        } else {
            None
        };
        return Ok((FieldLine { name, value: None }, rest));
    }

    if first & 0x40 != 0 {
        // Literal Field Line With Name Reference: 01 N T <4-bit index>, then a value string
        // literal (8-bit prefix). T (0x10) selects static/dynamic.
        let t_static = first & 0x10 != 0;
        let (index, rest) = read_prefixed_int(buf, 4).ok_or_else(|| eof("name-ref: bad index"))?;
        let name = if t_static {
            static_name(index).map(str::to_owned)
        } else {
            None
        };
        let (value, rest) = read_string_literal(rest, 7)?;
        let value = String::from_utf8(value).map_err(|_| malformed("name-ref: value not UTF-8"))?;
        return Ok((
            FieldLine {
                name,
                value: Some(value),
            },
            rest,
        ));
    }

    if first & 0x20 != 0 {
        // Literal Field Line With Literal Name: 001 N H <3-bit name len>, name bytes, then a
        // value string literal (8-bit prefix). The name is a 4-bit-prefix string literal
        // (H bit at 1<<3, 3-bit length).
        let (name, rest) = read_string_literal(buf, 3)?;
        let name = String::from_utf8(name).map_err(|_| malformed("literal: name not UTF-8"))?;
        let (value, rest) = read_string_literal(rest, 7)?;
        let value = String::from_utf8(value).map_err(|_| malformed("literal: value not UTF-8"))?;
        return Ok((
            FieldLine {
                name: Some(name),
                value: Some(value),
            },
            rest,
        ));
    }

    // Remaining patterns (0001 post-base indexed, 0000 post-base name ref) reference the
    // dynamic table, which an /auth response built against our empty table must never use.
    Err(malformed("field line: unsupported QPACK representation"))
}

/// Parse an HTTP/3 HEADERS frame containing the /auth response and return the HTTP status.
///
/// Reads the frame header (type must be `0x01`, then the length), then walks the QPACK field
/// section looking for the `:status` pseudo-header. Success is status **233**; the caller
/// decides what to do with any other value.
pub fn decode_auth_status(headers_frame: &[u8]) -> io::Result<u16> {
    let (frame_type, rest) =
        read_varint(headers_frame).ok_or_else(|| eof("HEADERS frame: missing type"))?;
    if frame_type != H3_FRAME_HEADERS {
        return Err(malformed("expected HTTP/3 HEADERS frame (type 0x01)"));
    }
    let (len, rest) = read_varint(rest).ok_or_else(|| eof("HEADERS frame: missing length"))?;
    let mut section = rest
        .get(..len as usize)
        .ok_or_else(|| eof("HEADERS frame: truncated field section"))?;

    // Field Section Prefix: Required Insert Count (8-bit prefix int) then S + Delta Base
    // (7-bit prefix int). We don't use the dynamic table, so we just skip past both — a
    // well-formed empty-table response carries `[0x00, 0x00]`, but skip robustly regardless.
    let (_ric, after_ric) =
        read_prefixed_int(section, 8).ok_or_else(|| eof("field prefix: bad insert count"))?;
    let (_base, after_base) =
        read_prefixed_int(after_ric, 7).ok_or_else(|| eof("field prefix: bad base"))?;
    section = after_base;

    while !section.is_empty() {
        let (line, rest) = parse_field_line(section)?;
        section = rest;
        if line.name.as_deref() == Some(":status") {
            let value = line
                .value
                .ok_or_else(|| malformed(":status had no literal value"))?;
            return value
                .parse::<u16>()
                .map_err(|_| malformed(":status value not a number"));
        }
    }
    Err(malformed(
        ":status pseudo-header not found in /auth response",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a response HEADERS frame with `:status <n>` encoded as a Literal Field Line With
    /// Literal Name, plus a dummy header so the parser must advance past another line first.
    fn test_response_headers_literal(status: u16) -> Vec<u8> {
        let status = status.to_string();
        let section = encode_field_section(&[("content-type", "text/plain"), (":status", &status)]);
        headers_frame(&section)
    }

    /// Build a response HEADERS frame with `:status <n>` encoded as a Literal Field Line With
    /// Name Reference (static index 24 = `:status`), the form quic-go's qpack is most likely
    /// to emit. Prepends a dummy literal header so name references aren't the only line.
    fn test_response_headers_nameref(status: u16) -> Vec<u8> {
        let status = status.to_string();
        let mut section = Vec::with_capacity(32);
        section.push(0x00); // Required Insert Count = 0
        section.push(0x00); // S=0, Delta Base = 0
        encode_literal_field(&mut section, "content-type", "text/plain");
        // Literal Field Line With Name Reference: 01 N T <4-bit index>. N=0, T=1 (static),
        // index = 24 (a `:status` entry). 0x40 | 0x10 = 0x50; 24 >= 15 so the 4-bit prefix
        // overflows into a continuation byte (handled by encode_prefixed_int).
        encode_prefixed_int(&mut section, 4, 0x50, 24);
        // Value as an 8-bit-prefix string literal, H=0.
        encode_prefixed_int(&mut section, 7, 0x00, status.len() as u64);
        section.extend_from_slice(status.as_bytes());
        headers_frame(&section)
    }

    #[test]
    fn prefixed_int_round_trips() {
        for &bits in &[3u8, 4, 5, 7, 8] {
            for &v in &[
                0u64,
                1,
                5,
                14,
                15,
                16,
                127,
                128,
                233,
                1000,
                16384,
                u32::MAX as u64,
            ] {
                let mut out = Vec::new();
                encode_prefixed_int(&mut out, bits, 0, v);
                let (got, rest) = read_prefixed_int(&out, bits).unwrap();
                assert_eq!(got, v, "bits={bits} v={v}");
                assert!(rest.is_empty(), "bits={bits} v={v} leftover={rest:?}");
            }
        }
    }

    #[test]
    fn auth_request_is_an_h3_headers_frame() {
        let f = encode_auth_request("mysecret", 0);
        assert_eq!(f[0], 0x01); // HEADERS frame type
        let (flen, rest) = super::super::tcp::read_varint(&f[1..]).unwrap();
        assert_eq!(flen as usize, rest.len()); // length covers exactly the field section
        assert_eq!(&rest[..2], &[0x00, 0x00]); // QPACK field-section prefix: RIC=0, Base=0
    }

    #[test]
    fn round_trip_status_via_literal_name() {
        let frame = test_response_headers_literal(233);
        assert_eq!(decode_auth_status(&frame).unwrap(), 233);
        assert_eq!(
            decode_auth_status(&test_response_headers_literal(404)).unwrap(),
            404
        );
    }

    #[test]
    fn round_trip_status_via_name_reference() {
        let frame = test_response_headers_nameref(233);
        assert_eq!(decode_auth_status(&frame).unwrap(), 233);
        // A non-success status still parses (the caller decides it's a failure).
        assert_eq!(
            decode_auth_status(&test_response_headers_nameref(401)).unwrap(),
            401
        );
    }

    #[test]
    fn indexed_status_line_is_skipped_then_status_found() {
        // A response that opens with an Indexed Field Line for some other static entry
        // (`:scheme https` = index 23) followed by `:status 233` via name reference. The
        // indexed line has no value and must be skipped without confusing the parser.
        let mut section = Vec::new();
        section.push(0x00);
        section.push(0x00);
        // Indexed Field Line, static, index 23: 1 T <6-bit index> = 0x80 | 0x40 | 23.
        encode_prefixed_int(&mut section, 6, 0xc0, 23);
        encode_prefixed_int(&mut section, 4, 0x50, 25); // name ref :status (index 25)
        encode_prefixed_int(&mut section, 7, 0x00, 3); // value len 3
        section.extend_from_slice(b"233");
        let frame = headers_frame(&section);
        assert_eq!(decode_auth_status(&frame).unwrap(), 233);
    }

    #[test]
    fn wrong_frame_type_is_error() {
        // DATA frame (0x00), not HEADERS.
        let mut frame = Vec::new();
        write_varint(&mut frame, 0x00);
        write_varint(&mut frame, 0);
        assert!(decode_auth_status(&frame).is_err());
    }

    #[test]
    fn missing_status_is_error() {
        let section = encode_field_section(&[("content-type", "text/plain")]);
        assert!(decode_auth_status(&headers_frame(&section)).is_err());
    }

    #[test]
    fn truncated_field_section_is_error() {
        let mut frame = Vec::new();
        write_varint(&mut frame, H3_FRAME_HEADERS);
        write_varint(&mut frame, 10); // claims 10 bytes
        frame.extend_from_slice(&[0x00, 0x00]); // only 2 present
        assert!(decode_auth_status(&frame).is_err());
    }
}
