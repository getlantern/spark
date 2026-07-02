//! Minimal DNS wire codec for the tunnel (ADR 0011 §7): build/parse the TXT query (uplink bytes packed
//! base32 into the QNAME) and the TXT answer (downlink bytes in the RDATA), plus an EDNS0 OPT RR so
//! responses can exceed 512 bytes. Hand-rolled and deliberately tiny — no general DNS library — and a
//! primary fuzz/robustness target.
//!
//! Only the shapes we use are supported: one question, TXT/IN, optional OPT in the additional section,
//! and TXT answers whose RDATA is one or more character-strings we concatenate. Names are read
//! tolerantly (a compression pointer terminates a name; we never *emit* uncompressed answer names —
//! the answer reuses a pointer to the question name at offset 12).
//!
//! **Base32 is decoded case-insensitively**: a recursive resolver may apply 0x20 case randomization,
//! so the case the server receives need not match what the client sent. We always *encode* lower-case.

/// TXT record type.
pub const TYPE_TXT: u16 = 16;
/// EDNS0 OPT pseudo-record type.
pub const TYPE_OPT: u16 = 41;
/// IN class.
pub const CLASS_IN: u16 = 1;
/// Maximum total encoded domain-name length (RFC 1035).
pub const MAX_NAME_LEN: usize = 255;
/// Maximum single-label length.
pub const MAX_LABEL_LEN: usize = 63;
/// Maximum TXT character-string length.
const MAX_CHAR_STRING: usize = 255;
/// The fixed DNS header length.
const HEADER_LEN: usize = 12;

/// Errors from DNS (de)serialization.
#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    /// The buffer ended before a required field.
    #[error("DNS message truncated")]
    Truncated,
    /// A label exceeded 63 bytes or the name exceeded 255.
    #[error("DNS name too long")]
    NameTooLong,
    /// The base32 payload in the QNAME did not decode.
    #[error("bad base32 in QNAME")]
    BadBase32,
    /// The query's QNAME was not under the expected tunnel zone.
    #[error("QNAME not under tunnel zone")]
    WrongZone,
    /// The message had no question where one was required.
    #[error("DNS message has no question")]
    NoQuestion,
    /// A name compression pointer was malformed.
    #[error("bad name compression pointer")]
    BadPointer,
}

// ---- base32 (RFC 4648 alphabet, lower-case, no padding) -------------------------------------------

const B32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

fn b32_encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len().div_ceil(5) * 8);
    let (mut acc, mut bits) = (0u64, 0u32);
    for &b in data {
        acc = (acc << 8) | b as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32_ALPHABET[((acc >> bits) & 0x1f) as usize]);
        }
    }
    if bits > 0 {
        out.push(B32_ALPHABET[((acc << (5 - bits)) & 0x1f) as usize]);
    }
    out
}

fn b32_val(c: u8) -> Option<u8> {
    match c {
        b'a'..=b'z' => Some(c - b'a'),
        b'A'..=b'Z' => Some(c - b'A'), // case-insensitive (0x20 randomization)
        b'2'..=b'7' => Some(c - b'2' + 26),
        _ => None,
    }
}

fn b32_decode(s: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let (mut acc, mut bits) = (0u64, 0u32);
    for &c in s {
        acc = (acc << 5) | b32_val(c)? as u64;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    // Leftover (<8) bits are encode padding; they must be zero for a canonical encoding, but we do
    // not enforce that (lenient decode).
    Some(out)
}

// ---- names ----------------------------------------------------------------------------------------

/// A parsed domain name (the tunnel zone), as a list of labels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Name {
    labels: Vec<Vec<u8>>,
}

impl Name {
    /// Parse a dotted name like `"t.example.com"`. Rejects empty or over-long labels.
    pub fn parse(s: &str) -> Result<Name, DnsError> {
        let s = s.trim_end_matches('.');
        if s.is_empty() {
            return Ok(Name { labels: Vec::new() });
        }
        let mut labels = Vec::new();
        for part in s.split('.') {
            let b = part.as_bytes();
            if b.is_empty() || b.len() > MAX_LABEL_LEN {
                return Err(DnsError::NameTooLong);
            }
            labels.push(b.to_vec());
        }
        Ok(Name { labels })
    }

    /// Wire length including the terminating zero (only meaningful as a standalone name).
    pub fn wire_len(&self) -> usize {
        self.labels.iter().map(|l| 1 + l.len()).sum::<usize>() + 1
    }
}

fn eq_ci(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|(x, y)| x.eq_ignore_ascii_case(y))
}

// ---- query ----------------------------------------------------------------------------------------

/// A parsed tunnel query: the transaction id (to echo in the answer) and the recovered uplink bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    /// DNS transaction id.
    pub txn_id: u16,
    /// The uplink payload recovered from the QNAME.
    pub data: Vec<u8>,
}

/// Build a TXT query carrying `data` (base32 in the QNAME under `zone`) with an EDNS0 OPT advertising
/// `edns_udp` bytes. Errors if the encoded name would exceed 255 bytes.
pub fn build_query(txn_id: u16, data: &[u8], zone: &Name, edns_udp: u16) -> Result<Vec<u8>, DnsError> {
    let enc = b32_encode(data);
    let data_labels: Vec<&[u8]> = if enc.is_empty() {
        Vec::new()
    } else {
        enc.chunks(MAX_LABEL_LEN).collect()
    };
    let name_len =
        data_labels.iter().map(|l| 1 + l.len()).sum::<usize>() + zone.wire_len();
    if name_len > MAX_NAME_LEN {
        return Err(DnsError::NameTooLong);
    }

    let mut msg = Vec::with_capacity(HEADER_LEN + name_len + 4 + 11);
    // Header: id, flags (RD=1), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=1 (OPT).
    msg.extend_from_slice(&txn_id.to_be_bytes());
    msg.extend_from_slice(&[0x01, 0x00]);
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    // Question: QNAME = data labels ‖ zone labels ‖ 0.
    for l in &data_labels {
        msg.push(l.len() as u8);
        msg.extend_from_slice(l);
    }
    for l in &zone.labels {
        msg.push(l.len() as u8);
        msg.extend_from_slice(l);
    }
    msg.push(0);
    msg.extend_from_slice(&TYPE_TXT.to_be_bytes());
    msg.extend_from_slice(&CLASS_IN.to_be_bytes());
    // EDNS0 OPT: root name, TYPE=OPT, CLASS=UDP size, TTL=0, RDLENGTH=0.
    msg.push(0);
    msg.extend_from_slice(&TYPE_OPT.to_be_bytes());
    msg.extend_from_slice(&edns_udp.to_be_bytes());
    msg.extend_from_slice(&[0, 0, 0, 0]);
    msg.extend_from_slice(&0u16.to_be_bytes());
    Ok(msg)
}

/// Parse a tunnel query: read the question QNAME, verify it is under `zone`, and base32-decode the
/// leading labels into the uplink bytes.
pub fn parse_query(buf: &[u8], zone: &Name) -> Result<Query, DnsError> {
    let mut r = Reader::new(buf);
    let txn_id = r.u16()?;
    let _flags = r.u16()?;
    let qd = r.u16()?;
    let _an = r.u16()?;
    let _ns = r.u16()?;
    let _ar = r.u16()?;
    if qd < 1 {
        return Err(DnsError::NoQuestion);
    }
    let labels = r.read_labels()?;
    if labels.len() < zone.labels.len() {
        return Err(DnsError::WrongZone);
    }
    let split = labels.len() - zone.labels.len();
    for (got, want) in labels[split..].iter().zip(&zone.labels) {
        if !eq_ci(got, want) {
            return Err(DnsError::WrongZone);
        }
    }
    let mut enc = Vec::new();
    for l in &labels[..split] {
        enc.extend_from_slice(l);
    }
    let data = b32_decode(&enc).ok_or(DnsError::BadBase32)?;
    Ok(Query { txn_id, data })
}

// ---- answer ---------------------------------------------------------------------------------------

/// Build a TXT answer to `request`, carrying `downlink` in the RDATA (split into ≤255-byte
/// character-strings), reusing the request's transaction id and echoing the question via a
/// compression pointer to offset 12. Includes an EDNS0 OPT advertising `edns_udp`.
pub fn build_answer(request: &[u8], downlink: &[u8], edns_udp: u16) -> Result<Vec<u8>, DnsError> {
    let qend = question_end(request)?;
    let txn_id = u16::from_be_bytes([request[0], request[1]]);

    let mut msg = Vec::with_capacity(qend + 16 + downlink.len() + 11);
    // Header: id echoed; flags QR=1, RD=1, RA=1 (0x8180); QD=1, AN=1, NS=0, AR=1.
    msg.extend_from_slice(&txn_id.to_be_bytes());
    msg.extend_from_slice(&[0x81, 0x80]);
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    // Echo the question section verbatim (everything after the header up to `qend`).
    msg.extend_from_slice(&request[HEADER_LEN..qend]);
    // Answer RR: NAME = pointer to the question name at offset 12 (0xC00C), TYPE=TXT, CLASS=IN, TTL=0.
    msg.extend_from_slice(&[0xC0, 0x0C]);
    msg.extend_from_slice(&TYPE_TXT.to_be_bytes());
    msg.extend_from_slice(&CLASS_IN.to_be_bytes());
    msg.extend_from_slice(&0u32.to_be_bytes());
    // RDATA = one or more character-strings (len-prefixed, ≤255).
    let mut rdata = Vec::with_capacity(downlink.len() + downlink.len() / MAX_CHAR_STRING + 1);
    if downlink.is_empty() {
        rdata.push(0); // one empty character-string
    } else {
        for chunk in downlink.chunks(MAX_CHAR_STRING) {
            rdata.push(chunk.len() as u8);
            rdata.extend_from_slice(chunk);
        }
    }
    msg.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    msg.extend_from_slice(&rdata);
    // EDNS0 OPT.
    msg.push(0);
    msg.extend_from_slice(&TYPE_OPT.to_be_bytes());
    msg.extend_from_slice(&edns_udp.to_be_bytes());
    msg.extend_from_slice(&[0, 0, 0, 0]);
    msg.extend_from_slice(&0u16.to_be_bytes());
    Ok(msg)
}

/// A parsed tunnel answer: the transaction id and the recovered downlink bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// DNS transaction id.
    pub txn_id: u16,
    /// The downlink payload recovered from the TXT RDATA.
    pub data: Vec<u8>,
}

/// Parse a tunnel answer: skip the question section, then concatenate the character-strings of every
/// TXT answer record into the downlink bytes.
pub fn parse_answer(buf: &[u8]) -> Result<Answer, DnsError> {
    let mut r = Reader::new(buf);
    let txn_id = r.u16()?;
    let _flags = r.u16()?;
    let qd = r.u16()?;
    let an = r.u16()?;
    let _ns = r.u16()?;
    let _ar = r.u16()?;
    for _ in 0..qd {
        r.skip_name()?;
        r.skip(4)?; // QTYPE + QCLASS
    }
    let mut data = Vec::new();
    for _ in 0..an {
        r.skip_name()?;
        let rtype = r.u16()?;
        let _class = r.u16()?;
        let _ttl = r.u32()?;
        let rdlen = r.u16()? as usize;
        let rdata = r.take(rdlen)?;
        if rtype == TYPE_TXT {
            // RDATA is a sequence of character-strings; concatenate them.
            let mut i = 0;
            while i < rdata.len() {
                let clen = rdata[i] as usize;
                i += 1;
                let end = i.checked_add(clen).ok_or(DnsError::Truncated)?;
                let s = rdata.get(i..end).ok_or(DnsError::Truncated)?;
                data.extend_from_slice(s);
                i = end;
            }
        }
    }
    Ok(Answer { txn_id, data })
}

/// Return the offset one past the first question's QTYPE/QCLASS (i.e. the end of the question
/// section), for echoing.
fn question_end(buf: &[u8]) -> Result<usize, DnsError> {
    let mut r = Reader::new(buf);
    r.skip(HEADER_LEN)?; // fixed header
    let qd = u16::from_be_bytes([buf[4], buf[5]]);
    if qd < 1 {
        return Err(DnsError::NoQuestion);
    }
    r.skip_name()?;
    r.skip(4)?; // QTYPE + QCLASS
    Ok(r.pos)
}

// ---- reader ---------------------------------------------------------------------------------------

/// A bounds-checked, panic-free DNS message reader.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], DnsError> {
        let end = self.pos.checked_add(n).ok_or(DnsError::Truncated)?;
        let s = self.buf.get(self.pos..end).ok_or(DnsError::Truncated)?;
        self.pos = end;
        Ok(s)
    }
    fn skip(&mut self, n: usize) -> Result<(), DnsError> {
        self.take(n).map(|_| ())
    }
    fn u16(&mut self) -> Result<u16, DnsError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32, DnsError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    /// Read an uncompressed name as its labels. A compression pointer terminates the name (we consume
    /// the 2 pointer bytes but do not follow it — sufficient for our own messages).
    fn read_labels(&mut self) -> Result<Vec<Vec<u8>>, DnsError> {
        let mut labels = Vec::new();
        let mut total = 0usize;
        loop {
            let len = self.take(1)?[0];
            match len & 0xC0 {
                0x00 => {
                    if len == 0 {
                        return Ok(labels);
                    }
                    let l = self.take(len as usize)?;
                    total += 1 + l.len();
                    if total > MAX_NAME_LEN {
                        return Err(DnsError::NameTooLong);
                    }
                    labels.push(l.to_vec());
                }
                0xC0 => {
                    self.take(1)?; // second pointer byte; pointer terminates the name
                    return Ok(labels);
                }
                _ => return Err(DnsError::BadPointer), // 0x40 / 0x80 reserved
            }
        }
    }
    /// Skip a name (labels or a terminating compression pointer) without materializing it.
    fn skip_name(&mut self) -> Result<(), DnsError> {
        loop {
            let len = self.take(1)?[0];
            match len & 0xC0 {
                0x00 => {
                    if len == 0 {
                        return Ok(());
                    }
                    self.skip(len as usize)?;
                }
                0xC0 => {
                    self.take(1)?;
                    return Ok(());
                }
                _ => return Err(DnsError::BadPointer),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_round_trips_all_remainders() {
        for len in 0..40usize {
            let data: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(37).wrapping_add(11)).collect();
            let enc = b32_encode(&data);
            assert!(enc.iter().all(|&c| b32_val(c).is_some()));
            assert_eq!(b32_decode(&enc).unwrap(), data, "len {len}");
        }
    }

    #[test]
    fn base32_decode_is_case_insensitive() {
        let data = b"tunnel payload 0x20";
        let enc = b32_encode(data);
        let upper: Vec<u8> = enc.iter().map(|c| c.to_ascii_uppercase()).collect();
        // Mixed case, as a 0x20-randomizing resolver might produce.
        let mixed: Vec<u8> = enc
            .iter()
            .enumerate()
            .map(|(i, &c)| if i % 2 == 0 { c.to_ascii_uppercase() } else { c })
            .collect();
        assert_eq!(b32_decode(&upper).unwrap(), data);
        assert_eq!(b32_decode(&mixed).unwrap(), data);
    }

    #[test]
    fn query_round_trips_and_checks_zone() {
        let zone = Name::parse("t.example.com").unwrap();
        let data = b"the quick brown fox jumps over".to_vec();
        let q = build_query(0xABCD, &data, &zone, 1232).unwrap();
        // EDNS0 OPT present → ARCOUNT = 1.
        assert_eq!(u16::from_be_bytes([q[10], q[11]]), 1);
        let parsed = parse_query(&q, &zone).unwrap();
        assert_eq!(parsed.txn_id, 0xABCD);
        assert_eq!(parsed.data, data);

        // A query under a different zone is rejected.
        let other = Name::parse("t.evil.example").unwrap();
        assert!(matches!(parse_query(&q, &other), Err(DnsError::WrongZone)));
    }

    #[test]
    fn query_rejects_oversized_name() {
        let zone = Name::parse("t.example.com").unwrap();
        // 200 bytes base32-expands to 320 chars → well over the 255-name limit.
        let big = vec![0x5A; 200];
        assert!(matches!(
            build_query(1, &big, &zone, 1232),
            Err(DnsError::NameTooLong)
        ));
    }

    #[test]
    fn answer_round_trips_including_multi_char_string() {
        let zone = Name::parse("t.example.com").unwrap();
        let q = build_query(0x1234, b"up", &zone, 1232).unwrap();
        // 600 bytes → 3 character-strings (255+255+90).
        let downlink: Vec<u8> = (0..600u16).map(|i| (i & 0xff) as u8).collect();
        let a = build_answer(&q, &downlink, 1232).unwrap();
        let parsed = parse_answer(&a).unwrap();
        assert_eq!(parsed.txn_id, 0x1234);
        assert_eq!(parsed.data, downlink);
        // Response bit set.
        assert_eq!(a[2] & 0x80, 0x80);
    }

    #[test]
    fn answer_round_trips_empty_downlink() {
        let zone = Name::parse("t.example.com").unwrap();
        let q = build_query(7, b"", &zone, 512).unwrap();
        let a = build_answer(&q, &[], 512).unwrap();
        let parsed = parse_answer(&a).unwrap();
        assert_eq!(parsed.txn_id, 7);
        assert!(parsed.data.is_empty());
    }

    #[test]
    fn parsers_reject_truncation_without_panicking() {
        let zone = Name::parse("t.example.com").unwrap();
        let q = build_query(1, b"hello", &zone, 1232).unwrap();
        let a = build_answer(&q, b"world", 1232).unwrap();
        for n in 0..q.len() {
            let _ = parse_query(&q[..n], &zone); // must not panic
        }
        for n in 0..a.len() {
            let _ = parse_answer(&a[..n]); // must not panic
        }
    }

    #[test]
    fn parsers_never_panic_on_random_input() {
        // Poor-man's fuzz: deterministic pseudo-random garbage of many lengths. (Formal `cargo fuzz`
        // targets are a follow-up; this guards the panic-free contract in the normal suite.)
        let zone = Name::parse("t.example.com").unwrap();
        let mut state = 0x9E3779B97F4A7C15u64;
        for len in 0..300usize {
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                buf.push((state >> 33) as u8);
            }
            let _ = parse_query(&buf, &zone);
            let _ = parse_answer(&buf);
        }
    }
}
