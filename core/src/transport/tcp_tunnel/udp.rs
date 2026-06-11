//! Per-datagram framing for UDP carried over the tunnel.
//!
//! A stream connection (TCP, or TLS over TCP) erases datagram boundaries, so each relayed
//! UDP datagram is self-delimited by a length prefix and tagged with its peer address:
//!
//! ```text
//! [ ADDR (SOCKS5-style ATYP|ADDR|PORT) ][ LEN(2, big-endian) ][ payload (LEN bytes) ]
//! ```
//!
//! `ADDR` is the **target** for a client→server datagram and the **source** for a
//! server→client reply. The address reuses the M3a [`Address`] codec; the only addition
//! is the `u16` length. As with the TCP header, [`parse`] distinguishes "need more bytes"
//! ([`UdpFrameError::Incomplete`]) from a malformed frame, so a stream reader can buffer
//! partial datagrams.

use bytes::{BufMut, BytesMut};

use super::header::{Address, HeaderError};

/// Encode a framed datagram (`target` address, then `u16` length, then `payload`) onto
/// `dst`. Fails if `payload` exceeds [`u16::MAX`] (a UDP payload never legitimately does,
/// but the wire field cannot express it).
pub fn encode(target: &Address, payload: &[u8], dst: &mut BytesMut) -> Result<(), UdpFrameError> {
    if payload.len() > u16::MAX as usize {
        return Err(UdpFrameError::PayloadTooLong(payload.len()));
    }
    dst.reserve(target.encoded_len() + 2 + payload.len());
    target.encode(dst);
    dst.put_u16(payload.len() as u16);
    dst.put_slice(payload);
    Ok(())
}

/// Parse one framed datagram from the front of `src`, returning the peer address, the
/// payload (borrowed from `src`), and the total number of bytes consumed.
///
/// Returns [`UdpFrameError::Incomplete`] when `src` holds only a truncated prefix — the
/// caller should read more and retry.
pub fn parse(src: &[u8]) -> Result<(Address, &[u8], usize), UdpFrameError> {
    let (addr, addr_len) = match Address::parse(src) {
        Ok(parsed) => parsed,
        Err(HeaderError::Incomplete) => return Err(UdpFrameError::Incomplete),
        Err(e) => return Err(UdpFrameError::Address(e)),
    };
    let rest = &src[addr_len..];
    if rest.len() < 2 {
        return Err(UdpFrameError::Incomplete);
    }
    let payload_len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
    let payload_start = addr_len + 2;
    let payload_end = payload_start + payload_len;
    if src.len() < payload_end {
        return Err(UdpFrameError::Incomplete);
    }
    Ok((addr, &src[payload_start..payload_end], payload_end))
}

/// Errors from encoding or parsing a UDP tunnel frame.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UdpFrameError {
    /// `src` holds only a truncated prefix of a frame; read more and retry.
    #[error("incomplete UDP frame")]
    Incomplete,
    /// The address portion was malformed (a non-`Incomplete` [`HeaderError`]).
    #[error("bad UDP frame address: {0}")]
    Address(#[source] HeaderError),
    /// The payload is larger than the 2-byte length field can express.
    #[error("UDP payload too long: {0} bytes (max 65535)")]
    PayloadTooLong(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(target: Address, payload: &[u8]) {
        let mut buf = BytesMut::new();
        encode(&target, payload, &mut buf).unwrap();

        // Append a trailing second frame's worth of bytes to prove `parse` stops at the
        // datagram boundary and reports the right consumed length.
        let trailer = b"NEXTFRAME";
        buf.extend_from_slice(trailer);

        let (addr, got, consumed) = parse(&buf).unwrap();
        assert_eq!(addr, target);
        assert_eq!(got, payload);
        assert_eq!(consumed, target.encoded_len() + 2 + payload.len());
        assert_eq!(&buf[consumed..], trailer);
    }

    #[test]
    fn round_trips_ipv4_with_payload() {
        round_trip(Address::Ip("192.0.2.5:53".parse().unwrap()), b"dns query");
    }

    #[test]
    fn round_trips_ipv6_and_domain() {
        round_trip(
            Address::Ip("[2001:db8::53]:53".parse().unwrap()),
            b"\x00\x01\x02",
        );
        round_trip(Address::domain("resolver.example", 53).unwrap(), b"payload");
    }

    #[test]
    fn round_trips_empty_payload() {
        round_trip(Address::Ip("198.51.100.9:9".parse().unwrap()), b"");
    }

    #[test]
    fn truncated_frame_is_incomplete() {
        let mut buf = BytesMut::new();
        encode(
            &Address::Ip("192.0.2.5:53".parse().unwrap()),
            b"hello",
            &mut buf,
        )
        .unwrap();
        for n in 0..buf.len() {
            assert_eq!(
                parse(&buf[..n]),
                Err(UdpFrameError::Incomplete),
                "prefix len {n}"
            );
        }
    }

    #[test]
    fn payload_over_u16_is_rejected_on_encode() {
        let big = vec![0u8; u16::MAX as usize + 1];
        let err = encode(
            &Address::Ip("192.0.2.5:53".parse().unwrap()),
            &big,
            &mut BytesMut::new(),
        );
        assert_eq!(err, Err(UdpFrameError::PayloadTooLong(big.len())));
    }
}
