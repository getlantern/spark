//! Minimal server-side DNS wire codec: parse the app's query, build the fake-IP answer.
//!
//! `flint_dns::codec` only covers the *client* leg (`build_query` / `parse_response`), so the fake-IP
//! DNS **server** needs its own tiny codec. Scope is deliberately narrow — exactly what the fake-IP
//! server needs (RFC 1035 §4): read the first question of a standard query, and build a NOERROR
//! response echoing that question with zero or more A/AAAA answer records. No recursion, no
//! authority/additional sections, no compression on build (the single answer name is a pointer to the
//! question at offset 12). Everything else the server handles by returning an empty (NODATA) answer.

use std::net::IpAddr;

use thiserror::Error;

/// DNS record/query type: IPv4 address.
pub const TYPE_A: u16 = 1;
/// DNS record/query type: IPv6 address.
pub const TYPE_AAAA: u16 = 28;
/// DNS query type: HTTPS service binding (RFC 9460). The server returns NODATA so clients fall back
/// to A/AAAA (an HTTPS/SVCB record can carry IP hints / ECH that would bypass fake-IP).
pub const TYPE_HTTPS: u16 = 65;
/// DNS class: Internet.
pub const CLASS_IN: u16 = 1;

/// The fixed DNS message header length (RFC 1035 §4.1.1).
const HEADER_LEN: usize = 12;
/// Max encoded name length (RFC 1035 §3.1): 255 octets including length bytes and the root.
const MAX_NAME_LEN: usize = 255;
/// Max single-label length (the two high bits are reserved for compression).
const MAX_LABEL_LEN: usize = 63;

/// A malformed or truncated DNS message.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DnsError {
    /// The buffer ended before a required field.
    #[error("dns message truncated")]
    Truncated,
    /// A structural violation (bad flags, no question, compression where none is allowed, …).
    #[error("dns message malformed: {0}")]
    Malformed(&'static str),
    /// The encoded question name exceeds 255 octets.
    #[error("dns name exceeds 255 octets")]
    NameTooLong,
}

/// A parsed DNS query — the fields the fake-IP server needs to route and to build a matching reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    /// Transaction id, echoed verbatim into the response.
    pub id: u16,
    /// The RD (recursion-desired) bit, echoed into the response flags.
    pub recursion_desired: bool,
    /// The first question's name, dot-joined, lowercased, without a trailing dot (`""` for the root).
    pub name: String,
    /// The first question's QTYPE (e.g. [`TYPE_A`]).
    pub qtype: u16,
    /// The first question's QCLASS (normally [`CLASS_IN`]).
    pub qclass: u16,
    /// The raw question section (name + qtype + qclass) exactly as received, echoed verbatim into the
    /// response so 0x20 case-randomization and the wire name survive untouched.
    question_wire: Vec<u8>,
}

/// Parse a standard DNS query, extracting the header essentials and its **first** question.
///
/// Rejects responses (QR set), question-less messages, and compression pointers inside the question
/// name (a well-formed stub-resolver query never compresses its QNAME). Only the first question is
/// read; multi-question queries are vanishingly rare and unsupported by most resolvers.
pub fn parse_query(buf: &[u8]) -> Result<Query, DnsError> {
    if buf.len() < HEADER_LEN {
        return Err(DnsError::Truncated);
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags0 = buf[2];
    // QR bit (0x80) set → this is a response, not a query.
    if flags0 & 0x80 != 0 {
        return Err(DnsError::Malformed("QR set (not a query)"));
    }
    let recursion_desired = flags0 & 0x01 != 0;
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    if qdcount == 0 {
        return Err(DnsError::Malformed("no question"));
    }
    let (name, name_end) = read_qname(buf, HEADER_LEN)?;
    // QTYPE + QCLASS (2 + 2) follow the name.
    if buf.len() < name_end + 4 {
        return Err(DnsError::Truncated);
    }
    let qtype = u16::from_be_bytes([buf[name_end], buf[name_end + 1]]);
    let qclass = u16::from_be_bytes([buf[name_end + 2], buf[name_end + 3]]);
    let question_wire = buf[HEADER_LEN..name_end + 4].to_vec();
    Ok(Query {
        id,
        recursion_desired,
        name,
        qtype,
        qclass,
        question_wire,
    })
}

/// Build a NOERROR response to `query` carrying `answers` as A/AAAA records (each tagged by its
/// address family). An empty `answers` slice is a valid NODATA reply (the fake-IP server uses it for
/// non-A/AAAA queries). The answer name is a compression pointer to the question at offset 12, so the
/// reply is compact and the name matches byte-for-byte.
pub fn build_response(query: &Query, answers: &[IpAddr], ttl: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + query.question_wire.len() + answers.len() * 28);
    // Header: id echoed; QR=1, Opcode=0, AA=0, TC=0, RD echoed; RA=1, Z=0, RCODE=0 (NOERROR).
    out.extend_from_slice(&query.id.to_be_bytes());
    out.push(0x80 | u8::from(query.recursion_desired));
    out.push(0x80);
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
                                                // ANCOUNT is bounded by the answer count; the server never emits more than a couple.
    let ancount = u16::try_from(answers.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&ancount.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
                                                // Question, echoed verbatim (its name starts at offset 12, the pointer target below).
    out.extend_from_slice(&query.question_wire);
    for ip in answers.iter().take(ancount as usize) {
        out.extend_from_slice(&[0xC0, 0x0C]); // NAME → pointer to the question name at offset 12
        match ip {
            IpAddr::V4(v4) => {
                out.extend_from_slice(&TYPE_A.to_be_bytes());
                out.extend_from_slice(&CLASS_IN.to_be_bytes());
                out.extend_from_slice(&ttl.to_be_bytes());
                out.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
                out.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                out.extend_from_slice(&TYPE_AAAA.to_be_bytes());
                out.extend_from_slice(&CLASS_IN.to_be_bytes());
                out.extend_from_slice(&ttl.to_be_bytes());
                out.extend_from_slice(&16u16.to_be_bytes()); // RDLENGTH
                out.extend_from_slice(&v6.octets());
            }
        }
    }
    out
}

/// Read a question name starting at `start`, returning it (dot-joined, lowercased, no trailing dot)
/// and the offset of the byte immediately after the terminating zero label. Compression pointers are
/// rejected: a QNAME is never compressed, so a pointer here is malformed (or hostile).
fn read_qname(buf: &[u8], start: usize) -> Result<(String, usize), DnsError> {
    let mut labels: Vec<String> = Vec::new();
    let mut i = start;
    let mut total = 1usize; // the terminating root label counts toward the 255-octet limit
    loop {
        let len = *buf.get(i).ok_or(DnsError::Truncated)? as usize;
        if len == 0 {
            i += 1; // consume the root label
            break;
        }
        if len & 0xC0 != 0 {
            return Err(DnsError::Malformed(
                "compression/reserved bits in question name",
            ));
        }
        if len > MAX_LABEL_LEN {
            return Err(DnsError::Malformed("label too long"));
        }
        i += 1;
        let end = i + len;
        let label_bytes = buf.get(i..end).ok_or(DnsError::Truncated)?;
        total += len + 1;
        if total > MAX_NAME_LEN {
            return Err(DnsError::NameTooLong);
        }
        // Domain labels are ASCII (IDNs arrive as punycode `xn--…`); map each byte and lowercase.
        let label: String = label_bytes
            .iter()
            .map(|b| char::from(b.to_ascii_lowercase()))
            .collect();
        labels.push(label);
        i = end;
    }
    Ok((labels.join("."), i))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Hand-encode a standard query (one question, no compression) for round-trip tests.
    fn make_query(id: u16, name: &str, qtype: u16, rd: bool) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&id.to_be_bytes());
        b.push(u8::from(rd)); // RD in the low bit; QR=0
        b.push(0x00);
        b.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        b.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        b.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        b.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        for label in name.split('.') {
            b.push(label.len() as u8);
            b.extend_from_slice(label.as_bytes());
        }
        b.push(0); // root
        b.extend_from_slice(&qtype.to_be_bytes());
        b.extend_from_slice(&CLASS_IN.to_be_bytes());
        b
    }

    /// Walk a response's answer section and return the A/AAAA addresses (an independent decoder, so it
    /// genuinely checks [`build_response`] rather than mirroring it).
    fn extract_answers(resp: &[u8]) -> Vec<IpAddr> {
        let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
        let (_name, mut i) = read_qname(resp, HEADER_LEN).unwrap();
        i += 4; // qtype + qclass
        let mut out = Vec::new();
        for _ in 0..ancount {
            // Answer NAME: a compression pointer (2 bytes) or an inline name.
            if resp[i] & 0xC0 == 0xC0 {
                i += 2;
            } else {
                let (_n, ni) = read_qname(resp, i).unwrap();
                i = ni;
            }
            let rtype = u16::from_be_bytes([resp[i], resp[i + 1]]);
            i += 2 + 2 + 4; // type + class + ttl
            let rdlen = u16::from_be_bytes([resp[i], resp[i + 1]]) as usize;
            i += 2;
            let rdata = &resp[i..i + rdlen];
            i += rdlen;
            match rtype {
                TYPE_A => {
                    let b: [u8; 4] = rdata.try_into().unwrap();
                    out.push(IpAddr::from(b));
                }
                TYPE_AAAA => {
                    let b: [u8; 16] = rdata.try_into().unwrap();
                    out.push(IpAddr::from(b));
                }
                _ => {}
            }
        }
        out
    }

    #[test]
    fn parse_query_reads_header_and_first_question() {
        let q = parse_query(&make_query(0x1234, "Example.COM", TYPE_A, true)).unwrap();
        assert_eq!(q.id, 0x1234);
        assert!(q.recursion_desired);
        assert_eq!(q.name, "example.com"); // lowercased, no trailing dot
        assert_eq!(q.qtype, TYPE_A);
        assert_eq!(q.qclass, CLASS_IN);
    }

    #[test]
    fn build_response_echoes_id_flags_and_a_record() {
        let q = parse_query(&make_query(0xABCD, "ads.example.com", TYPE_A, true)).unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 7));
        let resp = build_response(&q, std::slice::from_ref(&ip), 30);
        assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), 0xABCD); // id echoed
        assert_eq!(resp[2], 0x81); // QR=1, RD=1
        assert_eq!(resp[3], 0x80); // RA=1, RCODE=0
        assert_eq!(u16::from_be_bytes([resp[4], resp[5]]), 1); // QDCOUNT
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1); // ANCOUNT
                                                               // extract_answers decodes through the answer's compression pointer, so a correct IP here
                                                               // also proves the 0xC0 0x0C pointer-to-the-question was emitted.
        assert_eq!(extract_answers(&resp), vec![ip]);
    }

    #[test]
    fn build_response_carries_aaaa_and_mixed_families() {
        let q = parse_query(&make_query(1, "example.com", TYPE_AAAA, false)).unwrap();
        assert!(!resp_flag_rd(&build_response(&q, &[], 30))); // RD=0 echoed back
        let v6 = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x2a));
        let v4 = IpAddr::V4(Ipv4Addr::new(198, 19, 1, 2));
        let resp = build_response(&q, &[v6, v4], 60);
        assert_eq!(extract_answers(&resp), vec![v6, v4]);
    }

    fn resp_flag_rd(resp: &[u8]) -> bool {
        resp[2] & 0x01 != 0
    }

    #[test]
    fn empty_answer_is_noerror_nodata() {
        let q = parse_query(&make_query(2, "example.com", TYPE_HTTPS, true)).unwrap();
        let resp = build_response(&q, &[], 30);
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0); // ANCOUNT = 0
        assert_eq!(resp[3] & 0x0F, 0); // RCODE = NOERROR
        assert!(extract_answers(&resp).is_empty());
    }

    #[test]
    fn rejects_malformed_and_truncated() {
        assert_eq!(parse_query(&[0u8; 4]), Err(DnsError::Truncated));
        // QR bit set → a response, not a query.
        let mut resp = make_query(1, "example.com", TYPE_A, false);
        resp[2] |= 0x80;
        assert_eq!(
            parse_query(&resp),
            Err(DnsError::Malformed("QR set (not a query)"))
        );
        // QDCOUNT = 0.
        let mut noq = make_query(1, "example.com", TYPE_A, false);
        noq[4] = 0;
        noq[5] = 0;
        assert_eq!(parse_query(&noq), Err(DnsError::Malformed("no question")));
        // A compression pointer inside the question name is rejected.
        let mut compressed = Vec::new();
        compressed.extend_from_slice(&1u16.to_be_bytes());
        compressed.extend_from_slice(&[0x01, 0x00]); // flags
        compressed.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        compressed.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN/NS/AR
        compressed.extend_from_slice(&[0xC0, 0x0C]); // pointer where a label should be
        assert_eq!(
            parse_query(&compressed),
            Err(DnsError::Malformed(
                "compression/reserved bits in question name"
            ))
        );
    }

    /// Oracle cross-check: build a real query with `flint_dns`, parse it, answer it, and let
    /// `flint_dns` parse the answer back — the IPs must round-trip. Gated on `bootstrap-dns` (which
    /// supplies `flint_dns`); the `--all-features` test job exercises it.
    #[cfg(feature = "bootstrap-dns")]
    #[test]
    fn round_trips_against_flint_dns_oracle() {
        let wire = flint_dns::codec::build_query("cdn.example.net", flint_dns::TYPE_A).unwrap();
        let q = parse_query(&wire).unwrap();
        assert_eq!(q.name, "cdn.example.net");
        assert_eq!(q.qtype, TYPE_A);
        let ips = vec![
            IpAddr::V4(Ipv4Addr::new(198, 18, 3, 4)),
            IpAddr::V4(Ipv4Addr::new(198, 18, 3, 5)),
        ];
        let resp = build_response(&q, &ips, 30);
        let parsed = flint_dns::codec::parse_response(&resp).unwrap();
        assert_eq!(parsed, ips);
    }
}
