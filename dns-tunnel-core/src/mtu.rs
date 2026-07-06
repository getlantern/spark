//! MTU / capacity math (ADR 0011 §5): how many payload bytes fit in a QNAME (uplink) or a TXT answer
//! (downlink) given the tunnel zone and the negotiated EDNS0 UDP size. Pure arithmetic; the actual
//! per-resolver probing that *uses* these bounds lives in the client (M4).

use crate::crypto::{CONN_ID_LEN, NONCE_LEN, TAG_LEN};

/// RFC 1035 maximum encoded name length.
pub const MAX_NAME_LEN: usize = 255;
/// The wire header form byte.
const FORM_LEN: usize = 1;

/// Largest number of base32 chars that fit in `budget` QNAME bytes, accounting for the 1 length byte
/// each ≤63-char label costs (a full label is 63 chars + 1 length byte = 64 wire bytes).
pub fn max_base32_chars(budget: usize) -> usize {
    let full = budget / 64;
    let rem = budget % 64;
    full * 63 + rem.saturating_sub(1)
}

/// Bytes recoverable from `chars` base32 characters (8 chars carry 5 bytes).
pub fn base32_capacity_bytes(chars: usize) -> usize {
    chars * 5 / 8
}

/// The largest wire packet (bytes) that base32-fits in a QNAME under a zone of `zone_wire_len` bytes.
pub fn max_uplink_wire_bytes(zone_wire_len: usize) -> usize {
    let budget = MAX_NAME_LEN.saturating_sub(zone_wire_len);
    base32_capacity_bytes(max_base32_chars(budget))
}

/// Fixed per-packet wire overhead on a data frame: cleartext form byte + ConnectionID + nonce + AEAD
/// tag. (The forward-secret handshake packets — cleartext `FORM_SYN`/`FORM_SYNACK` — are sized
/// separately and carry no salt.)
pub const fn wire_overhead() -> usize {
    FORM_LEN + CONN_ID_LEN + NONCE_LEN + TAG_LEN
}

/// Max uplink *payload* bytes, given the zone size, the inner frame header length, and the header form.
pub fn max_uplink_payload(zone_wire_len: usize, header_len: usize) -> usize {
    max_uplink_wire_bytes(zone_wire_len).saturating_sub(wire_overhead() + header_len)
}

/// Approximate DNS response envelope overhead: header + echoed question + answer RR header + OPT.
fn answer_envelope_overhead(question_wire_len: usize) -> usize {
    12                      // DNS header
        + question_wire_len // echoed question (name + QTYPE + QCLASS)
        + 2                 // answer NAME compression pointer
        + 10                // TYPE + CLASS + TTL + RDLENGTH
        + 11 // EDNS0 OPT RR
}

/// The largest wire packet (bytes) that fits in a TXT answer for the negotiated `edns_udp` size and
/// echoed `question_wire_len`. Conservatively accounts for a character-string length byte per 255 B.
pub fn max_downlink_wire_bytes(edns_udp: usize, question_wire_len: usize) -> usize {
    let raw = edns_udp.saturating_sub(answer_envelope_overhead(question_wire_len));
    raw.saturating_sub(raw.div_ceil(256))
}

/// Max downlink *payload* bytes (short form downstream; no salt).
pub fn max_downlink_payload(edns_udp: usize, question_wire_len: usize, header_len: usize) -> usize {
    max_downlink_wire_bytes(edns_udp, question_wire_len)
        .saturating_sub(wire_overhead() + header_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{build_query, DnsError, Name};

    #[test]
    fn max_base32_chars_known_values() {
        assert_eq!(max_base32_chars(0), 0);
        assert_eq!(max_base32_chars(1), 0); // 1 spare byte cannot form a label
        assert_eq!(max_base32_chars(2), 1); // 1 length byte + 1 char
        assert_eq!(max_base32_chars(64), 63); // one full label
        assert_eq!(max_base32_chars(65), 63); // 1 spare, still one label
        assert_eq!(max_base32_chars(66), 64); // second label: 1 len + 1 char
        assert_eq!(max_base32_chars(128), 126); // two full labels
    }

    #[test]
    fn base32_capacity_is_five_eighths() {
        assert_eq!(base32_capacity_bytes(8), 5);
        assert_eq!(base32_capacity_bytes(16), 10);
        assert_eq!(base32_capacity_bytes(7), 4); // floor
    }

    #[test]
    fn uplink_bound_matches_build_query_exactly() {
        // The cross-check: `max_uplink_wire_bytes` must equal the largest `data` (wire packet) that
        // `dns::build_query` will base32-pack into a valid ≤255-byte QNAME under the zone.
        let zone = Name::parse("t.example.com").unwrap();
        let w = max_uplink_wire_bytes(zone.wire_len());
        assert!(w > 0);
        assert!(
            build_query(0, &vec![0u8; w], &zone, 1232).is_ok(),
            "a {w}-byte wire packet must fit"
        );
        assert!(
            matches!(
                build_query(0, &vec![0u8; w + 1], &zone, 1232),
                Err(DnsError::NameTooLong)
            ),
            "one byte more must overflow the QNAME"
        );
    }

    #[test]
    fn a_longer_zone_leaves_less_uplink_room() {
        let short = Name::parse("t.ex.io").unwrap();
        let long = Name::parse("tunnel.a-much-longer-subdomain.example.co.uk").unwrap();
        assert!(max_uplink_wire_bytes(long.wire_len()) < max_uplink_wire_bytes(short.wire_len()));
    }

    #[test]
    fn uplink_payload_subtracts_overhead_and_header() {
        let zone = Name::parse("t.example.com").unwrap();
        let zl = zone.wire_len();
        let wire = max_uplink_wire_bytes(zl);
        // A 3-byte minimal inner header.
        let payload = max_uplink_payload(zl, 3);
        assert_eq!(payload, wire - wire_overhead() - 3);
    }

    #[test]
    fn downlink_capacity_is_bounded_and_monotonic() {
        let q = 40; // typical echoed-question length
        let small = max_downlink_wire_bytes(512, q);
        let big = max_downlink_wire_bytes(1232, q);
        assert!(small < big, "more EDNS room → more downlink capacity");
        assert!(big < 1232, "capacity is under the advertised UDP size");
        assert!(max_downlink_payload(1232, q, 5) > 0);
    }
}
