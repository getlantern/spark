//! In-place TCP/IP header rewriting for the system (kernel-TCP) netstack.
//!
//! The system stack is a NAT redirect gateway (see `docs/system-stack-design.md`): it reads IP
//! packets from the TUN, rewrites the TCP 4-tuple so the host kernel routes the connection to/from
//! a local listener, and writes the packet back. This module is the pure, allocation-free packet
//! surgery — parsing just enough of the IPv4/IPv6 + TCP headers to read the endpoints and to set
//! new ones, then recomputing the affected checksums.
//!
//! Only TCP is handled here (the system stack's reason to exist); UDP/ICMP take other paths. IPv6
//! is handled only when the TCP header follows the fixed 40-byte base header directly (no extension
//! headers) — the common case; anything else is rejected so the caller can fall back.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Protocol number for TCP in the IPv4 `protocol` / IPv6 `next header` field.
const PROTO_TCP: u8 = 6;

/// TCP `FIN` flag (the connection's sender is done) in the flags byte.
pub const TCP_FIN: u8 = 0x01;
/// TCP `RST` flag (the connection is being aborted).
pub const TCP_RST: u8 = 0x04;

/// Why a packet could not be parsed/rewritten as TCP — the caller treats any of these as "not a
/// rewritable TCP packet" and handles it on another path.
#[derive(Debug, PartialEq, Eq)]
pub enum RewriteError {
    /// Too short to contain the headers it claims.
    Truncated,
    /// Not IPv4 or IPv6.
    NotIp,
    /// Not a TCP packet.
    NotTcp,
    /// IPv6 with extension headers (next header is not TCP) — unsupported.
    Ipv6Extension,
    /// The replacement address family didn't match the packet's.
    FamilyMismatch,
}

/// The byte layout of a TCP packet's mutable fields, resolved once per packet so a parse and a
/// rewrite don't re-walk the headers.
struct Layout {
    /// Offset of the IP source address (4 bytes for v4, 16 for v6).
    ip_src: usize,
    /// Offset of the IP destination address.
    ip_dst: usize,
    /// Address length (4 or 16).
    addr_len: usize,
    /// Offset of the IPv4 header checksum (v4 only; `None` for v6, which has none).
    ip_checksum: Option<usize>,
    /// Offset of the TCP header (start of the TCP segment).
    tcp: usize,
    /// `true` for IPv6.
    v6: bool,
}

impl Layout {
    /// Resolve the layout of `pkt` if it is an IPv4/IPv6 TCP packet, else the reason it isn't.
    fn parse(pkt: &[u8]) -> Result<Layout, RewriteError> {
        let first = *pkt.first().ok_or(RewriteError::Truncated)?;
        match first >> 4 {
            4 => {
                let ihl = (first & 0x0f) as usize * 4;
                if ihl < 20 || pkt.len() < ihl + 20 {
                    return Err(RewriteError::Truncated);
                }
                if pkt[9] != PROTO_TCP {
                    return Err(RewriteError::NotTcp);
                }
                Ok(Layout {
                    ip_src: 12,
                    ip_dst: 16,
                    addr_len: 4,
                    ip_checksum: Some(10),
                    tcp: ihl,
                    v6: false,
                })
            }
            6 => {
                if pkt.len() < 40 + 20 {
                    return Err(RewriteError::Truncated);
                }
                // Next header at byte 6. We only handle TCP directly after the base header.
                if pkt[6] != PROTO_TCP {
                    return Err(if pkt[6] == 17 || pkt[6] == 58 {
                        RewriteError::NotTcp
                    } else {
                        RewriteError::Ipv6Extension
                    });
                }
                Ok(Layout {
                    ip_src: 8,
                    ip_dst: 24,
                    addr_len: 16,
                    ip_checksum: None,
                    tcp: 40,
                    v6: true,
                })
            }
            _ => Err(RewriteError::NotIp),
        }
    }
}

/// Read the TCP source, destination, and flags byte of `pkt` (for classification + connection
/// lifecycle), or the reason it isn't a rewritable TCP packet. The flags byte carries
/// [`TCP_FIN`]/[`TCP_RST`] etc.
pub fn tcp_header(pkt: &[u8]) -> Result<(SocketAddr, SocketAddr, u8), RewriteError> {
    let l = Layout::parse(pkt)?;
    let src_ip = read_ip(pkt, l.ip_src, l.addr_len);
    let dst_ip = read_ip(pkt, l.ip_dst, l.addr_len);
    let src_port = u16::from_be_bytes([pkt[l.tcp], pkt[l.tcp + 1]]);
    let dst_port = u16::from_be_bytes([pkt[l.tcp + 2], pkt[l.tcp + 3]]);
    let flags = pkt[l.tcp + 13]; // TCP flags byte
    Ok((
        SocketAddr::new(src_ip, src_port),
        SocketAddr::new(dst_ip, dst_port),
        flags,
    ))
}

/// Read just the TCP endpoints of `pkt` (classification), discarding the flags.
pub fn tcp_endpoints(pkt: &[u8]) -> Result<(SocketAddr, SocketAddr), RewriteError> {
    tcp_header(pkt).map(|(s, d, _)| (s, d))
}

/// Rewrite `pkt`'s TCP 4-tuple to `new_src`/`new_dst` in place and recompute the IPv4 (if any) and
/// TCP checksums. Both replacement addresses must match the packet's family.
pub fn rewrite_tcp(
    pkt: &mut [u8],
    new_src: SocketAddr,
    new_dst: SocketAddr,
) -> Result<(), RewriteError> {
    let l = Layout::parse(pkt)?;
    if new_src.is_ipv6() != l.v6 || new_dst.is_ipv6() != l.v6 {
        return Err(RewriteError::FamilyMismatch);
    }

    write_ip(pkt, l.ip_src, &new_src.ip());
    write_ip(pkt, l.ip_dst, &new_dst.ip());
    pkt[l.tcp..l.tcp + 2].copy_from_slice(&new_src.port().to_be_bytes());
    pkt[l.tcp + 2..l.tcp + 4].copy_from_slice(&new_dst.port().to_be_bytes());

    // IPv4 header checksum (covers the addresses we just changed). IPv6 has none.
    if let Some(off) = l.ip_checksum {
        pkt[off] = 0;
        pkt[off + 1] = 0;
        let csum = checksum(&pkt[..l.tcp], 0);
        pkt[off..off + 2].copy_from_slice(&csum.to_be_bytes());
    }

    // TCP checksum: pseudo-header (addresses + protocol + TCP length) over the TCP segment.
    let tcp_len = pkt.len() - l.tcp;
    pkt[l.tcp + 16] = 0;
    pkt[l.tcp + 17] = 0;
    let pseudo = pseudo_header_sum(&new_src.ip(), &new_dst.ip(), tcp_len);
    let csum = checksum(&pkt[l.tcp..], pseudo);
    pkt[l.tcp + 16..l.tcp + 18].copy_from_slice(&csum.to_be_bytes());
    Ok(())
}

fn read_ip(pkt: &[u8], off: usize, len: usize) -> IpAddr {
    if len == 4 {
        IpAddr::V4(Ipv4Addr::new(
            pkt[off],
            pkt[off + 1],
            pkt[off + 2],
            pkt[off + 3],
        ))
    } else {
        let mut b = [0u8; 16];
        b.copy_from_slice(&pkt[off..off + 16]);
        IpAddr::V6(Ipv6Addr::from(b))
    }
}

fn write_ip(pkt: &mut [u8], off: usize, ip: &IpAddr) {
    match ip {
        IpAddr::V4(a) => pkt[off..off + 4].copy_from_slice(&a.octets()),
        IpAddr::V6(a) => pkt[off..off + 16].copy_from_slice(&a.octets()),
    }
}

/// The TCP/UDP pseudo-header contribution to the checksum: source addr, dest addr, the protocol,
/// and the TCP length. Returned as an unfolded accumulator to seed [`checksum`].
fn pseudo_header_sum(src: &IpAddr, dst: &IpAddr, tcp_len: usize) -> u32 {
    let mut acc = 0u32;
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            acc = sum16(&s.octets(), acc);
            acc = sum16(&d.octets(), acc);
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            acc = sum16(&s.octets(), acc);
            acc = sum16(&d.octets(), acc);
        }
        _ => {}
    }
    acc += PROTO_TCP as u32;
    acc += tcp_len as u32;
    acc
}

/// Internet checksum (RFC 1071) of `data`, seeded with `init` (e.g. a pseudo-header sum): one's
/// complement of the folded one's-complement 16-bit sum.
fn checksum(data: &[u8], init: u32) -> u16 {
    !fold(sum16(data, init))
}

/// Accumulate the one's-complement 16-bit sum of `data` into `acc` (big-endian words; a trailing
/// odd byte is the high byte of a final word).
fn sum16(data: &[u8], mut acc: u32) -> u32 {
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        acc += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        acc += (*last as u32) << 8;
    }
    acc
}

/// Fold a 32-bit accumulator to 16 bits by adding the carries back in.
fn fold(mut acc: u32) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    acc as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddrV4;

    /// Build a minimal IPv4 TCP packet `src -> dst` with `payload`, valid IP + TCP checksums.
    fn ipv4_tcp(src: SocketAddrV4, dst: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
        let total = 20 + 20 + payload.len();
        let mut p = vec![0u8; total];
        p[0] = 0x45; // v4, IHL=5
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[8] = 64; // TTL
        p[9] = PROTO_TCP;
        p[12..16].copy_from_slice(&src.ip().octets());
        p[16..20].copy_from_slice(&dst.ip().octets());
        // TCP
        p[20..22].copy_from_slice(&src.port().to_be_bytes());
        p[22..24].copy_from_slice(&dst.port().to_be_bytes());
        p[32] = 0x50; // data offset = 5 (20 bytes), no flags set beyond
        p[33] = 0x10; // ACK
        p[20 + 20..].copy_from_slice(payload);
        // checksums
        let ipc = checksum(&p[..20], 0);
        p[10..12].copy_from_slice(&ipc.to_be_bytes());
        let pseudo = pseudo_header_sum(
            &IpAddr::V4(*src.ip()),
            &IpAddr::V4(*dst.ip()),
            20 + payload.len(),
        );
        let tc = checksum(&p[20..], pseudo);
        p[36..38].copy_from_slice(&tc.to_be_bytes());
        p
    }

    /// A correctly-formed packet's checksums verify to zero (sum of all words incl. checksum == FFFF).
    fn ipv4_checksums_ok(p: &[u8]) -> bool {
        let ip_ok = checksum(&p[..20], 0) == 0;
        let pseudo = pseudo_header_sum(&read_ip(p, 12, 4), &read_ip(p, 16, 4), p.len() - 20);
        let tcp_ok = checksum(&p[20..], pseudo) == 0;
        ip_ok && tcp_ok
    }

    fn v4(s: &str) -> SocketAddrV4 {
        s.parse().unwrap()
    }

    #[test]
    fn parses_endpoints_and_builds_valid_checksums() {
        let p = ipv4_tcp(v4("10.0.0.2:51000"), v4("93.184.216.34:443"), b"hello");
        let (s, d) = tcp_endpoints(&p).unwrap();
        assert_eq!(s, "10.0.0.2:51000".parse().unwrap());
        assert_eq!(d, "93.184.216.34:443".parse().unwrap());
        assert!(ipv4_checksums_ok(&p), "freshly built packet must verify");
    }

    #[test]
    fn rewrite_sets_tuple_and_keeps_checksums_valid() {
        let mut p = ipv4_tcp(v4("10.0.0.2:51000"), v4("93.184.216.34:443"), b"payload!");
        let new_src: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let new_dst: SocketAddr = "10.0.0.7:51000".parse().unwrap();
        rewrite_tcp(&mut p, new_src, new_dst).unwrap();

        let (s, d) = tcp_endpoints(&p).unwrap();
        assert_eq!(s, new_src);
        assert_eq!(d, new_dst);
        assert!(
            ipv4_checksums_ok(&p),
            "checksums must still verify after rewrite"
        );
    }

    #[test]
    fn rewrite_round_trips_back_to_original() {
        let orig = ipv4_tcp(v4("10.0.0.2:40000"), v4("1.2.3.4:80"), b"abcde");
        let mut p = orig.clone();
        // Rewrite away and back; payload + checksums must match the original byte-for-byte.
        rewrite_tcp(
            &mut p,
            "5.6.7.8:1234".parse().unwrap(),
            "9.10.11.12:5678".parse().unwrap(),
        )
        .unwrap();
        rewrite_tcp(
            &mut p,
            "10.0.0.2:40000".parse().unwrap(),
            "1.2.3.4:80".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(
            p, orig,
            "round-trip rewrite must reproduce the original packet"
        );
    }

    #[test]
    fn rejects_non_tcp_and_family_mismatch() {
        let mut udp = ipv4_tcp(v4("10.0.0.2:1"), v4("1.1.1.1:1"), b"");
        udp[9] = 17; // UDP
        assert_eq!(tcp_endpoints(&udp), Err(RewriteError::NotTcp));

        let mut p = ipv4_tcp(v4("10.0.0.2:1"), v4("1.1.1.1:1"), b"");
        let v6: SocketAddr = "[::1]:1".parse().unwrap();
        assert_eq!(
            rewrite_tcp(&mut p, v6, "1.1.1.1:1".parse().unwrap()),
            Err(RewriteError::FamilyMismatch)
        );
    }

    #[test]
    fn odd_length_payload_checksum_is_valid() {
        // 3-byte payload exercises the odd-byte tail in sum16.
        let mut p = ipv4_tcp(v4("10.0.0.2:51000"), v4("8.8.8.8:53"), b"odd");
        rewrite_tcp(
            &mut p,
            "8.8.8.8:53".parse().unwrap(),
            "10.0.0.9:51000".parse().unwrap(),
        )
        .unwrap();
        assert!(ipv4_checksums_ok(&p));
    }
}
