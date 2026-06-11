//! SOCKS5-style target-address codec for the TCP tunnel request header.
//!
//! The tunnel request is just an encoded target address followed by the relayed payload:
//!
//! ```text
//! ATYP(1) | ADDR | PORT(2, big-endian)
//!   ATYP=1 → IPv4   (4 bytes)
//!   ATYP=3 → DOMAIN (1-byte length prefix + name)
//!   ATYP=4 → IPv6   (16 bytes)
//! ```
//!
//! This is the SOCKS5 address grammar (RFC 1928 §4) minus the SOCKS framing, reused
//! because it is compact, self-delimiting, and already understood by off-the-shelf relay
//! servers. [`Address::parse`] separates "need more bytes" ([`HeaderError::Incomplete`])
//! from "malformed", so the relay's partial-read buffering (M3b) can retry on the former
//! and fail fast on the latter.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::{BufMut, BytesMut};

/// SOCKS5 address-type tags (RFC 1928 §4).
mod atyp {
    pub const IPV4: u8 = 1;
    pub const DOMAIN: u8 = 3;
    pub const IPV6: u8 = 4;
}

/// The maximum domain length the 1-byte length prefix can express.
const MAX_DOMAIN_LEN: usize = u8::MAX as usize;

/// A tunnel target address: either a resolved socket address or an unresolved
/// `(host, port)` to be resolved by the tunnel server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    /// An IP socket address. Encodes as ATYP 1 (v4) or ATYP 4 (v6).
    Ip(SocketAddr),
    /// A domain name and port, resolved server-side. Encodes as ATYP 3. The `host` is
    /// guaranteed non-empty and ≤ 255 bytes by [`Address::domain`].
    Domain { host: String, port: u16 },
}

impl Address {
    /// Construct a domain-name target, validating it fits the wire format (non-empty and
    /// ≤ 255 bytes, the limit of the 1-byte length prefix).
    pub fn domain(host: impl Into<String>, port: u16) -> Result<Self, HeaderError> {
        let host = host.into();
        if host.is_empty() {
            return Err(HeaderError::EmptyDomain);
        }
        if host.len() > MAX_DOMAIN_LEN {
            return Err(HeaderError::DomainTooLong(host.len()));
        }
        Ok(Address::Domain { host, port })
    }

    /// The target port.
    pub fn port(&self) -> u16 {
        match self {
            Address::Ip(sa) => sa.port(),
            Address::Domain { port, .. } => *port,
        }
    }

    /// The number of bytes [`encode`](Self::encode) will append.
    pub fn encoded_len(&self) -> usize {
        match self {
            Address::Ip(SocketAddr::V4(_)) => 1 + 4 + 2,
            Address::Ip(SocketAddr::V6(_)) => 1 + 16 + 2,
            Address::Domain { host, .. } => 1 + 1 + host.len() + 2,
        }
    }

    /// Append the SOCKS5-style encoding of this address to `dst`. Infallible: the only
    /// length constraint (domain ≤ 255 bytes) is enforced at construction.
    pub fn encode(&self, dst: &mut BytesMut) {
        dst.reserve(self.encoded_len());
        match self {
            Address::Ip(SocketAddr::V4(v4)) => {
                dst.put_u8(atyp::IPV4);
                dst.put_slice(&v4.ip().octets());
                dst.put_u16(v4.port());
            }
            Address::Ip(SocketAddr::V6(v6)) => {
                dst.put_u8(atyp::IPV6);
                dst.put_slice(&v6.ip().octets());
                dst.put_u16(v6.port());
            }
            Address::Domain { host, port } => {
                dst.put_u8(atyp::DOMAIN);
                dst.put_u8(host.len() as u8); // ≤ 255 guaranteed by `domain()`
                dst.put_slice(host.as_bytes());
                dst.put_u16(*port);
            }
        }
    }

    /// Parse a single address from the front of `src`, returning it and the number of
    /// bytes consumed (so the caller knows where the relayed payload begins).
    ///
    /// Returns [`HeaderError::Incomplete`] when `src` holds only a truncated prefix of an
    /// otherwise-valid address — the caller should read more bytes and retry. Other
    /// errors are permanent (malformed input).
    pub fn parse(src: &[u8]) -> Result<(Address, usize), HeaderError> {
        let &type_byte = src.first().ok_or(HeaderError::Incomplete)?;
        match type_byte {
            atyp::IPV4 => {
                const LEN: usize = 1 + 4 + 2;
                let buf: &[u8; LEN] = first_chunk(src)?;
                let ip = Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
                let port = u16::from_be_bytes([buf[5], buf[6]]);
                Ok((Address::Ip(SocketAddr::new(IpAddr::V4(ip), port)), LEN))
            }
            atyp::IPV6 => {
                const LEN: usize = 1 + 16 + 2;
                let buf: &[u8; LEN] = first_chunk(src)?;
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[1..17]);
                let port = u16::from_be_bytes([buf[17], buf[18]]);
                Ok((
                    Address::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)),
                    LEN,
                ))
            }
            atyp::DOMAIN => {
                // Need the type byte + length byte before we know the full size.
                let &dlen = src.get(1).ok_or(HeaderError::Incomplete)?;
                let dlen = dlen as usize;
                if dlen == 0 {
                    return Err(HeaderError::EmptyDomain);
                }
                let total = 1 + 1 + dlen + 2;
                if src.len() < total {
                    return Err(HeaderError::Incomplete);
                }
                let name = std::str::from_utf8(&src[2..2 + dlen])
                    .map_err(|_| HeaderError::InvalidDomain)?;
                let port = u16::from_be_bytes([src[2 + dlen], src[3 + dlen]]);
                Ok((
                    Address::Domain {
                        host: name.to_owned(),
                        port,
                    },
                    total,
                ))
            }
            other => Err(HeaderError::UnknownAtyp(other)),
        }
    }
}

/// Borrow the first `N` bytes of `src` as a fixed-size array, or [`HeaderError::Incomplete`]
/// if `src` is shorter than `N`.
fn first_chunk<const N: usize>(src: &[u8]) -> Result<&[u8; N], HeaderError> {
    src.get(..N)
        .ok_or(HeaderError::Incomplete)?
        .try_into()
        .map_err(|_| HeaderError::Incomplete)
}

impl From<SocketAddr> for Address {
    fn from(sa: SocketAddr) -> Self {
        Address::Ip(sa)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::Ip(sa) => write!(f, "{sa}"),
            Address::Domain { host, port } => write!(f, "{host}:{port}"),
        }
    }
}

/// Errors from encoding or parsing a tunnel address header.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HeaderError {
    /// `src` holds only a truncated prefix of a valid address; read more and retry.
    #[error("incomplete address header")]
    Incomplete,
    /// The ATYP byte is not one of 1 (IPv4), 3 (domain), or 4 (IPv6).
    #[error("unknown address type byte {0}")]
    UnknownAtyp(u8),
    /// A domain name with a zero-length prefix.
    #[error("empty domain name")]
    EmptyDomain,
    /// A domain name longer than the 1-byte length prefix can express (got {0} bytes).
    #[error("domain name too long: {0} bytes (max 255)")]
    DomainTooLong(usize),
    /// A domain name whose bytes are not valid UTF-8.
    #[error("domain name is not valid UTF-8")]
    InvalidDomain,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode then parse yields the original address and consumes exactly the encoded
    /// length, leaving any trailing payload untouched.
    fn round_trip(addr: Address) {
        let mut buf = BytesMut::new();
        addr.encode(&mut buf);
        assert_eq!(
            buf.len(),
            addr.encoded_len(),
            "encoded_len disagrees with encode"
        );

        // Append a payload to prove parse reports the right consumed length and stops at
        // the address boundary.
        let payload = b"PAYLOAD";
        buf.extend_from_slice(payload);

        let (parsed, consumed) = Address::parse(&buf).expect("parse");
        assert_eq!(parsed, addr);
        assert_eq!(consumed, addr.encoded_len());
        assert_eq!(&buf[consumed..], payload, "payload boundary");
    }

    #[test]
    fn round_trips_ipv4() {
        round_trip(Address::Ip("192.0.2.10:443".parse().unwrap()));
    }

    #[test]
    fn round_trips_ipv6() {
        round_trip(Address::Ip("[2001:db8::1]:8443".parse().unwrap()));
    }

    #[test]
    fn round_trips_domain() {
        round_trip(Address::domain("example.com", 80).unwrap());
    }

    #[test]
    fn port_is_big_endian() {
        let mut buf = BytesMut::new();
        Address::Ip("1.2.3.4:443".parse().unwrap()).encode(&mut buf);
        // 443 = 0x01BB; the two port bytes are the last two, most-significant first.
        assert_eq!(&buf[buf.len() - 2..], &[0x01, 0xBB]);
    }

    #[test]
    fn domain_constructor_rejects_empty_and_too_long() {
        assert_eq!(Address::domain("", 80), Err(HeaderError::EmptyDomain));
        let long = "a".repeat(256);
        assert_eq!(
            Address::domain(long, 80),
            Err(HeaderError::DomainTooLong(256))
        );
        // Exactly 255 is allowed.
        assert!(Address::domain("a".repeat(255), 80).is_ok());
    }

    #[test]
    fn truncated_inputs_report_incomplete() {
        // Build a full IPv6 header, then assert every strict prefix is Incomplete.
        let mut buf = BytesMut::new();
        Address::Ip("[2001:db8::1]:8443".parse().unwrap()).encode(&mut buf);
        for n in 0..buf.len() {
            assert_eq!(
                Address::parse(&buf[..n]),
                Err(HeaderError::Incomplete),
                "prefix of len {n} should be Incomplete"
            );
        }

        // A domain that announces 10 bytes but supplies fewer is Incomplete, not malformed.
        assert_eq!(
            Address::parse(&[atyp::DOMAIN, 10, b'a', b'b']),
            Err(HeaderError::Incomplete)
        );
    }

    #[test]
    fn rejects_malformed_headers() {
        assert_eq!(Address::parse(&[9, 0, 0]), Err(HeaderError::UnknownAtyp(9)));
        assert_eq!(
            Address::parse(&[atyp::DOMAIN, 0, 0, 0]),
            Err(HeaderError::EmptyDomain)
        );
        // ATYP=domain, len=2, bytes 0xFF 0xFE (invalid UTF-8), then a port.
        assert_eq!(
            Address::parse(&[atyp::DOMAIN, 2, 0xFF, 0xFE, 0x00, 0x50]),
            Err(HeaderError::InvalidDomain)
        );
    }
}
