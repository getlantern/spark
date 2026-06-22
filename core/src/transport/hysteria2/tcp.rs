//! Hysteria 2 TCP proxy: QUIC bidirectional stream framing for proxied TCP flows.

/// Append a QUIC varint (RFC 9000 §16: the 2 most-significant bits of the first byte encode the
/// length 2^n, the remaining 62 bits are the value, big-endian).
pub fn write_varint(out: &mut Vec<u8>, v: u64) {
    debug_assert!(v < (1u64 << 62), "QUIC varint overflow: {v} >= 2^62");
    if v < 64 {
        out.push(v as u8);
    } else if v < 16384 {
        out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes());
    } else if v < 1_073_741_824 {
        out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes());
    }
}

/// Number of bytes [`write_varint`] would emit for `v` (RFC 9000 §16: 1/2/4/8).
pub fn varint_len(v: u64) -> usize {
    if v < 64 {
        1
    } else if v < 16384 {
        2
    } else if v < 1_073_741_824 {
        4
    } else {
        8
    }
}

/// Read a QUIC varint; returns `(value, rest)` or `None` if truncated.
pub fn read_varint(buf: &[u8]) -> Option<(u64, &[u8])> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    let bytes = buf.get(..len)?;
    let mut v = (first & 0x3f) as u64;
    for &b in &bytes[1..] {
        v = (v << 8) | b as u64;
    }
    Some((v, &buf[len..]))
}

/// Hysteria 2 TCPRequest stream-type ID (protocol spec §"Proxy Requests / TCP").
const TCP_REQUEST_ID: u64 = 0x401;

/// Encode a TCPRequest: `varint(0x401) ‖ varint(addrlen) ‖ addr ‖ varint(padlen=0)`.
pub fn encode_tcp_request(addr: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(addr.len() + 8);
    write_varint(&mut out, TCP_REQUEST_ID);
    write_varint(&mut out, addr.len() as u64);
    out.extend_from_slice(addr.as_bytes());
    write_varint(&mut out, 0); // no padding (the client MAY pad; 0 is valid)
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_round_trips() {
        for v in [0u64, 63, 64, 16383, 16384, 0x401, 1 << 30, (1u64 << 30) - 1] {
            let mut buf = Vec::new();
            write_varint(&mut buf, v);
            let (got, rest) = read_varint(&buf).unwrap();
            assert_eq!(got, v);
            assert!(rest.is_empty());
        }
    }

    #[test]
    fn tcp_request_encodes_0x401() {
        let req = encode_tcp_request("example.com:80");
        assert_eq!(&req[..2], &[0x44, 0x01]); // 0x401 as a 2-byte QUIC varint
        let (id, rest) = read_varint(&req).unwrap();
        assert_eq!(id, 0x401);
        let (alen, rest) = read_varint(rest).unwrap();
        assert_eq!(alen, 14);
        assert_eq!(&rest[..14], b"example.com:80");
    }

    #[test]
    fn read_varint_truncated_is_none() {
        assert!(read_varint(&[]).is_none());
        assert!(read_varint(&[0x80, 0x01]).is_none()); // claims 4 bytes, only 2 present
    }
}
