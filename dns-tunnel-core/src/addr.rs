//! The stream target encoding carried by a `Syn` — SOCKS5 address bytes (`ATYP ‖ addr ‖ port`).
//!
//! The frame and session layers treat a stream's target as opaque [`bytes::Bytes`], which is the right
//! call for them: nothing below this module needs to know what a destination *is*. But "opaque" only
//! works if the two ends agree, and until this module existed they agreed by coincidence — the client
//! hand-wrote an encoder and the server hand-wrote a decoder, each covering only the ATYP values it
//! happened to need. The wire format allowed [`ATYP_DOMAIN`] the whole time; neither side implemented
//! it, so a domain target was unrepresentable in practice.
//!
//! Both ends now share this codec, and the round-trip is tested here rather than in either binary.
//!
//! # Why a domain form matters
//!
//! With [`Target::Domain`] the **exit** resolves the name. The client never asks a local resolver, so
//! a network that poisons or blocks DNS cannot interfere with the destination lookup — which is the
//! whole point of reaching for a DNS tunnel in the first place. Sending a name is also *cheaper* than
//! sending an address: the client would otherwise have to resolve it somehow before dialing.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// SOCKS5 `ATYP` for a 4-byte IPv4 address.
pub const ATYP_IPV4: u8 = 0x01;
/// SOCKS5 `ATYP` for a length-prefixed domain name.
pub const ATYP_DOMAIN: u8 = 0x03;
/// SOCKS5 `ATYP` for a 16-byte IPv6 address.
pub const ATYP_IPV6: u8 = 0x04;

/// Longest domain the wire format can carry: SOCKS5 gives the name a single length byte, so this is
/// the format's ceiling rather than a policy choice.
pub const MAX_DOMAIN_LEN: usize = u8::MAX as usize;

/// Where a stream should be connected, as named by the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// An already-resolved socket address.
    Ip(SocketAddr),
    /// A name for the **exit** to resolve, plus its port.
    Domain(String, u16),
}

impl Target {
    /// The destination port, whichever form this is.
    pub fn port(&self) -> u16 {
        match self {
            Target::Ip(sa) => sa.port(),
            Target::Domain(_, p) => *p,
        }
    }
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Target::Ip(sa) => write!(f, "{sa}"),
            Target::Domain(h, p) => write!(f, "{h}:{p}"),
        }
    }
}

/// Why a target could not be encoded or parsed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AddrError {
    /// A domain of zero length, which names nothing.
    #[error("empty domain name")]
    EmptyDomain,
    /// A domain longer than the single length byte can express.
    #[error("domain is {0} bytes, over the {MAX_DOMAIN_LEN}-byte wire limit")]
    DomainTooLong(usize),
    /// The first byte was not a known `ATYP`.
    #[error("unknown address type {0:#04x}")]
    UnknownAtyp(u8),
    /// The buffer ended before the address this `ATYP` promised.
    #[error("truncated address: {got} bytes, need {need}")]
    Truncated {
        /// Bytes available.
        got: usize,
        /// Bytes the declared form requires.
        need: usize,
    },
    /// A domain that was not valid UTF-8 — it could never name a host.
    #[error("domain is not valid UTF-8")]
    InvalidUtf8,
}

/// Encode `target` as `ATYP ‖ addr ‖ port`.
///
/// Fallible only for a domain the length byte cannot express. Truncating instead would silently
/// produce a *different* destination, which is the one failure mode worth refusing outright.
pub fn encode(target: &Target) -> Result<Vec<u8>, AddrError> {
    let mut v = Vec::with_capacity(1 + 16 + 2);
    match target {
        Target::Ip(SocketAddr::V4(a)) => {
            v.push(ATYP_IPV4);
            v.extend_from_slice(&a.ip().octets());
        }
        Target::Ip(SocketAddr::V6(a)) => {
            v.push(ATYP_IPV6);
            v.extend_from_slice(&a.ip().octets());
        }
        Target::Domain(host, _) => {
            let name = host.as_bytes();
            if name.is_empty() {
                return Err(AddrError::EmptyDomain);
            }
            if name.len() > MAX_DOMAIN_LEN {
                return Err(AddrError::DomainTooLong(name.len()));
            }
            v.push(ATYP_DOMAIN);
            v.push(name.len() as u8);
            v.extend_from_slice(name);
        }
    }
    v.extend_from_slice(&target.port().to_be_bytes());
    Ok(v)
}

/// Parse `ATYP ‖ addr ‖ port` from the front of `b`.
///
/// Trailing bytes are ignored: the caller hands over exactly the `Syn` payload, and a future protocol
/// revision appending fields should not make today's targets unparseable.
pub fn parse(b: &[u8]) -> Result<Target, AddrError> {
    let atyp = *b.first().ok_or(AddrError::Truncated { got: 0, need: 1 })?;
    let need = |n: usize| AddrError::Truncated {
        got: b.len(),
        need: n,
    };
    match atyp {
        ATYP_IPV4 => {
            let ip: [u8; 4] = b
                .get(1..5)
                .ok_or(need(7))?
                .try_into()
                .map_err(|_| need(7))?;
            let port = port_at(b, 5)?;
            Ok(Target::Ip(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(ip)),
                port,
            )))
        }
        ATYP_IPV6 => {
            let ip: [u8; 16] = b
                .get(1..17)
                .ok_or(need(19))?
                .try_into()
                .map_err(|_| need(19))?;
            let port = port_at(b, 17)?;
            Ok(Target::Ip(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(ip)),
                port,
            )))
        }
        ATYP_DOMAIN => {
            let len = *b.get(1).ok_or(need(2))? as usize;
            if len == 0 {
                return Err(AddrError::EmptyDomain);
            }
            let end = 2 + len;
            let name = b.get(2..end).ok_or(need(end + 2))?;
            let host = std::str::from_utf8(name)
                .map_err(|_| AddrError::InvalidUtf8)?
                .to_owned();
            let port = port_at(b, end)?;
            Ok(Target::Domain(host, port))
        }
        other => Err(AddrError::UnknownAtyp(other)),
    }
}

/// Read the big-endian port at `off`.
fn port_at(b: &[u8], off: usize) -> Result<u16, AddrError> {
    let raw: [u8; 2] = b
        .get(off..off + 2)
        .ok_or(AddrError::Truncated {
            got: b.len(),
            need: off + 2,
        })?
        .try_into()
        .map_err(|_| AddrError::Truncated {
            got: b.len(),
            need: off + 2,
        })?;
    Ok(u16::from_be_bytes(raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(t: Target) {
        let encoded = encode(&t).expect("encodes");
        assert_eq!(parse(&encoded).expect("parses"), t, "round trip for {t}");
    }

    #[test]
    fn round_trips_every_form() {
        roundtrip(Target::Ip("1.2.3.4:443".parse().unwrap()));
        roundtrip(Target::Ip("[2606:4700::1111]:853".parse().unwrap()));
        roundtrip(Target::Domain("df.iantem.io".into(), 443));
        roundtrip(Target::Domain("a".into(), 1));
        roundtrip(Target::Domain("x".repeat(MAX_DOMAIN_LEN), 65535));
    }

    /// The byte layout is the interoperability contract, so pin it literally rather than only
    /// round-tripping — a matched encoder/decoder pair can agree on a format and still be wrong.
    #[test]
    fn the_wire_layout_is_socks5() {
        assert_eq!(
            encode(&Target::Ip("1.2.3.4:443".parse().unwrap())).unwrap(),
            vec![0x01, 1, 2, 3, 4, 0x01, 0xbb]
        );
        assert_eq!(
            encode(&Target::Domain("ab".into(), 80)).unwrap(),
            vec![0x03, 2, b'a', b'b', 0x00, 0x50]
        );
    }

    /// The pre-existing hand-written decoder accepted exactly these two forms. Parsing its output
    /// proves the shared codec is wire-compatible with already-deployed servers.
    #[test]
    fn parses_what_the_old_ip_only_decoder_produced() {
        assert_eq!(
            parse(&[0x01, 93, 184, 216, 34, 0x01, 0xbb]).unwrap(),
            Target::Ip("93.184.216.34:443".parse().unwrap())
        );
        let mut v6 = vec![0x04];
        v6.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        v6.extend_from_slice(&443u16.to_be_bytes());
        assert_eq!(
            parse(&v6).unwrap(),
            Target::Ip("[::1]:443".parse().unwrap())
        );
    }

    #[test]
    fn a_domain_too_long_for_the_length_byte_is_refused_not_truncated() {
        let long = "x".repeat(MAX_DOMAIN_LEN + 1);
        assert_eq!(
            encode(&Target::Domain(long, 443)),
            Err(AddrError::DomainTooLong(MAX_DOMAIN_LEN + 1))
        );
    }

    #[test]
    fn an_empty_domain_is_refused_on_both_sides() {
        assert_eq!(
            encode(&Target::Domain(String::new(), 443)),
            Err(AddrError::EmptyDomain)
        );
        assert_eq!(
            parse(&[0x03, 0x00, 0x01, 0xbb]),
            Err(AddrError::EmptyDomain)
        );
    }

    /// Untrusted input: every truncation of a valid encoding must be an error, never a panic and
    /// never a silently different target. This parses attacker-controlled bytes.
    #[test]
    fn every_truncation_errors_rather_than_panicking() {
        for t in [
            Target::Ip("1.2.3.4:443".parse().unwrap()),
            Target::Ip("[2606:4700::1111]:853".parse().unwrap()),
            Target::Domain("df.iantem.io".into(), 443),
        ] {
            let full = encode(&t).unwrap();
            for cut in 0..full.len() {
                assert!(
                    parse(&full[..cut]).is_err(),
                    "{t}: {cut}-byte prefix parsed but should not have"
                );
            }
            assert_eq!(parse(&full).unwrap(), t);
        }
    }

    #[test]
    fn an_unknown_atyp_is_reported_not_guessed() {
        assert_eq!(parse(&[0x02, 1, 2, 3]), Err(AddrError::UnknownAtyp(0x02)));
        assert_eq!(parse(&[]), Err(AddrError::Truncated { got: 0, need: 1 }));
    }

    #[test]
    fn a_non_utf8_domain_is_rejected() {
        assert_eq!(
            parse(&[0x03, 0x02, 0xff, 0xfe, 0x01, 0xbb]),
            Err(AddrError::InvalidUtf8)
        );
    }

    /// Trailing bytes are ignored so a later protocol revision can append fields.
    #[test]
    fn trailing_bytes_are_ignored() {
        let mut b = encode(&Target::Domain("a.example".into(), 443)).unwrap();
        b.extend_from_slice(b"future field");
        assert_eq!(parse(&b).unwrap(), Target::Domain("a.example".into(), 443));
    }
}
