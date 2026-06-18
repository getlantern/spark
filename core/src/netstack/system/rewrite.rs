//! In-place TCP/IP header rewriting for the system (kernel-TCP) netstack.
//!
//! The system stack is a NAT redirect gateway (see `docs/system-stack-design.md`): it reads IP
//! packets from the TUN, rewrites the TCP 4-tuple so the host kernel routes the connection to/from
//! a local listener, and writes the packet back. This module is the pure, allocation-free packet
//! surgery — parsing just enough of the IPv4/IPv6 + TCP headers to read the endpoints and to set
//! new ones, then recomputing the affected checksums.
//!
//! Handles TCP (the redirect: parse + in-place 4-tuple rewrite) and UDP (parse + build a fresh
//! packet, for the mixed stack's datagram path). IPv6 is handled only when the L4 header follows the
//! fixed 40-byte base header directly (no extension headers) — the common case; anything else is
//! rejected so the caller can fall back.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Protocol number for TCP in the IPv4 `protocol` / IPv6 `next header` field.
const PROTO_TCP: u8 = 6;
/// Protocol number for UDP.
const PROTO_UDP: u8 = 17;

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
    /// Not a UDP packet.
    NotUdp,
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

/// Rewrite `pkt`'s TCP 4-tuple to `new_src`/`new_dst` in place, **incrementally** fixing the IPv4
/// (if any) and TCP checksums (RFC 1624) — O(1) in the changed fields rather than O(payload), since
/// only the addresses + ports change. Requires the packet's existing checksums to be valid (true
/// for non-offloaded packets read from a TUN). Both replacement addresses must match the family.
pub fn rewrite_tcp(
    pkt: &mut [u8],
    new_src: SocketAddr,
    new_dst: SocketAddr,
) -> Result<(), RewriteError> {
    let l = Layout::parse(pkt)?;
    if new_src.is_ipv6() != l.v6 || new_dst.is_ipv6() != l.v6 {
        return Err(RewriteError::FamilyMismatch);
    }

    // Snapshot the old fields, then write the new ones; the checksum deltas use old vs. new bytes.
    let mut old_src = [0u8; 16];
    let mut old_dst = [0u8; 16];
    old_src[..l.addr_len].copy_from_slice(&pkt[l.ip_src..l.ip_src + l.addr_len]);
    old_dst[..l.addr_len].copy_from_slice(&pkt[l.ip_dst..l.ip_dst + l.addr_len]);
    let old_sport = [pkt[l.tcp], pkt[l.tcp + 1]];
    let old_dport = [pkt[l.tcp + 2], pkt[l.tcp + 3]];

    write_ip(pkt, l.ip_src, &new_src.ip());
    write_ip(pkt, l.ip_dst, &new_dst.ip());
    let new_sport = new_src.port().to_be_bytes();
    let new_dport = new_dst.port().to_be_bytes();
    pkt[l.tcp..l.tcp + 2].copy_from_slice(&new_sport);
    pkt[l.tcp + 2..l.tcp + 4].copy_from_slice(&new_dport);

    let (a, n) = (l.ip_src, l.addr_len);
    let new_src_b = {
        let mut b = [0u8; 16];
        b[..n].copy_from_slice(&pkt[a..a + n]);
        b
    };
    let new_dst_b = {
        let mut b = [0u8; 16];
        b[..n].copy_from_slice(&pkt[l.ip_dst..l.ip_dst + n]);
        b
    };

    // IPv4 header checksum covers the addresses only (not ports). IPv6 has no header checksum.
    if let Some(off) = l.ip_checksum {
        let mut c = u16::from_be_bytes([pkt[off], pkt[off + 1]]);
        c = csum_replace(c, &old_src[..n], &new_src_b[..n]);
        c = csum_replace(c, &old_dst[..n], &new_dst_b[..n]);
        pkt[off..off + 2].copy_from_slice(&c.to_be_bytes());
    }

    // TCP checksum covers the pseudo-header (addresses) + the ports; payload is unchanged.
    let toff = l.tcp + 16;
    let mut c = u16::from_be_bytes([pkt[toff], pkt[toff + 1]]);
    c = csum_replace(c, &old_src[..n], &new_src_b[..n]);
    c = csum_replace(c, &old_dst[..n], &new_dst_b[..n]);
    c = csum_replace(c, &old_sport, &new_sport);
    c = csum_replace(c, &old_dport, &new_dport);
    pkt[toff..toff + 2].copy_from_slice(&c.to_be_bytes());
    Ok(())
}

/// The IP protocol / next-header byte of `pkt` (`6` = TCP, `17` = UDP), or `None` if not IPv4/IPv6.
/// Cheap classifier so the pump can route a packet to the TCP or UDP path before full parsing.
pub fn ip_protocol(pkt: &[u8]) -> Option<u8> {
    match pkt.first()? >> 4 {
        4 => pkt.get(9).copied(),
        6 => pkt.get(6).copied(),
        _ => None,
    }
}

/// Parse an IPv4/IPv6 UDP packet: returns `(source, destination, payload_offset)` where
/// `payload_offset` is the byte index of the UDP payload (`pkt[payload_offset..]`). IPv6 is only
/// handled when UDP follows the base header directly (no extension headers).
pub fn udp_endpoints(pkt: &[u8]) -> Result<(SocketAddr, SocketAddr, usize), RewriteError> {
    let first = *pkt.first().ok_or(RewriteError::Truncated)?;
    let (ip_src, ip_dst, addr_len, l4) = match first >> 4 {
        4 => {
            let ihl = (first & 0x0f) as usize * 4;
            if ihl < 20 || pkt.len() < ihl + 8 {
                return Err(RewriteError::Truncated);
            }
            if pkt[9] != PROTO_UDP {
                return Err(RewriteError::NotUdp);
            }
            (12usize, 16usize, 4usize, ihl)
        }
        6 => {
            if pkt.len() < 40 + 8 {
                return Err(RewriteError::Truncated);
            }
            if pkt[6] != PROTO_UDP {
                return Err(RewriteError::NotUdp);
            }
            (8usize, 24usize, 16usize, 40usize)
        }
        _ => return Err(RewriteError::NotIp),
    };
    let src = SocketAddr::new(
        read_ip(pkt, ip_src, addr_len),
        u16::from_be_bytes([pkt[l4], pkt[l4 + 1]]),
    );
    let dst = SocketAddr::new(
        read_ip(pkt, ip_dst, addr_len),
        u16::from_be_bytes([pkt[l4 + 2], pkt[l4 + 3]]),
    );
    Ok((src, dst, l4 + 8))
}

/// Build a complete IPv4/IPv6 UDP packet `src -> dst` carrying `payload` into `out` (cleared first),
/// with valid IP (v4) and UDP checksums. Used to inject a UDP reply back onto the TUN. Both
/// addresses must share a family.
pub fn build_udp(
    src: SocketAddr,
    dst: SocketAddr,
    payload: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), RewriteError> {
    if src.is_ipv6() != dst.is_ipv6() {
        return Err(RewriteError::FamilyMismatch);
    }
    let udp_len = 8 + payload.len();
    out.clear();
    let l4 = match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let total = 20 + udp_len;
            out.resize(total, 0);
            out[0] = 0x45; // v4, IHL=5
            out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            out[8] = 64; // TTL
            out[9] = PROTO_UDP;
            out[12..16].copy_from_slice(&s.octets());
            out[16..20].copy_from_slice(&d.octets());
            let ipc = checksum(&out[..20], 0);
            out[10..12].copy_from_slice(&ipc.to_be_bytes());
            20
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let total = 40 + udp_len;
            out.resize(total, 0);
            out[0] = 0x60; // v6
            out[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes()); // payload length
            out[6] = PROTO_UDP; // next header
            out[7] = 64; // hop limit
            out[8..24].copy_from_slice(&s.octets());
            out[24..40].copy_from_slice(&d.octets());
            40
        }
        _ => return Err(RewriteError::FamilyMismatch),
    };
    // UDP header + payload.
    out[l4..l4 + 2].copy_from_slice(&src.port().to_be_bytes());
    out[l4 + 2..l4 + 4].copy_from_slice(&dst.port().to_be_bytes());
    out[l4 + 4..l4 + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    out[l4 + 8..].copy_from_slice(payload);
    // UDP checksum (mandatory for IPv6; we always set it). 0 is encoded as 0xFFFF.
    let pseudo = pseudo_header_sum(&src.ip(), &dst.ip(), PROTO_UDP, udp_len);
    let csum = checksum(&out[l4..], pseudo);
    let csum = if csum == 0 { 0xFFFF } else { csum };
    out[l4 + 6..l4 + 8].copy_from_slice(&csum.to_be_bytes());
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
/// and the L4 length. Returned as an unfolded accumulator to seed [`checksum`].
fn pseudo_header_sum(src: &IpAddr, dst: &IpAddr, proto: u8, l4_len: usize) -> u32 {
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
    acc += proto as u32;
    acc += l4_len as u32;
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

/// RFC 1624 incremental checksum update for one 16-bit word changing `old` → `new`:
/// `HC' = ~(~HC + ~old + new)` in one's-complement 16-bit arithmetic.
fn csum_replace_word(csum: u16, old: u16, new: u16) -> u16 {
    !fold((!csum as u32) + (!old as u32) + (new as u32))
}

/// Apply [`csum_replace_word`] across an even-length field changing `old` → `new` (e.g. a 4/16-byte
/// address or a 2-byte port), threading the running checksum word by word.
fn csum_replace(mut csum: u16, old: &[u8], new: &[u8]) -> u16 {
    for (o, n) in old.chunks_exact(2).zip(new.chunks_exact(2)) {
        csum = csum_replace_word(
            csum,
            u16::from_be_bytes([o[0], o[1]]),
            u16::from_be_bytes([n[0], n[1]]),
        );
    }
    csum
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
            PROTO_TCP,
            20 + payload.len(),
        );
        let tc = checksum(&p[20..], pseudo);
        p[36..38].copy_from_slice(&tc.to_be_bytes());
        p
    }

    /// A correctly-formed packet's checksums verify to zero (sum of all words incl. checksum == FFFF).
    fn ipv4_checksums_ok(p: &[u8]) -> bool {
        let ip_ok = checksum(&p[..20], 0) == 0;
        let pseudo = pseudo_header_sum(
            &read_ip(p, 12, 4),
            &read_ip(p, 16, 4),
            PROTO_TCP,
            p.len() - 20,
        );
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
    fn incremental_rewrite_matches_full_recompute() {
        // `ipv4_tcp` builds checksums by full recompute; `rewrite_tcp` fixes them incrementally.
        // Rewriting A's tuple to B's must yield exactly the packet a fresh full build of B produces.
        let payload = b"some bytes here, odd?";
        let mut a = ipv4_tcp(v4("10.0.0.2:51000"), v4("93.184.216.34:443"), payload);
        rewrite_tcp(
            &mut a,
            "5.6.7.8:1234".parse().unwrap(),
            "9.10.11.12:5678".parse().unwrap(),
        )
        .unwrap();
        let b = ipv4_tcp(v4("5.6.7.8:1234"), v4("9.10.11.12:5678"), payload);
        assert_eq!(
            a, b,
            "incremental rewrite must equal a from-scratch full recompute"
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
    fn build_udp_round_trips_through_udp_endpoints() {
        for (src, dst, payload) in [
            ("10.0.0.1:51000", "8.8.8.8:53", &b"dns query"[..]),
            (
                "[2001:db8::1]:51000",
                "[2606:4700:4700::1111]:53",
                &b"odd!"[..],
            ),
            ("10.0.0.1:1", "1.2.3.4:5", &b""[..]),
        ] {
            let src: SocketAddr = src.parse().unwrap();
            let dst: SocketAddr = dst.parse().unwrap();
            let mut out = Vec::new();
            build_udp(src, dst, payload, &mut out).unwrap();

            assert_eq!(ip_protocol(&out), Some(PROTO_UDP));
            let (s, d, off) = udp_endpoints(&out).unwrap();
            assert_eq!((s, d), (src, dst));
            assert_eq!(&out[off..], payload);

            // UDP checksum verifies to zero over the segment (with pseudo-header).
            let l4 = if src.is_ipv6() { 40 } else { 20 };
            let pseudo = pseudo_header_sum(&src.ip(), &dst.ip(), PROTO_UDP, out.len() - l4);
            assert_eq!(checksum(&out[l4..], pseudo), 0, "udp checksum invalid");
        }
    }

    #[test]
    fn ip_protocol_classifies_tcp_vs_udp() {
        let tcp = ipv4_tcp(v4("10.0.0.1:1"), v4("1.1.1.1:1"), b"");
        assert_eq!(ip_protocol(&tcp), Some(6));
        let mut out = Vec::new();
        build_udp(
            "10.0.0.1:1".parse().unwrap(),
            "1.1.1.1:1".parse().unwrap(),
            b"",
            &mut out,
        )
        .unwrap();
        assert_eq!(ip_protocol(&out), Some(17));
        assert_eq!(udp_endpoints(&tcp), Err(RewriteError::NotUdp));
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

    // ---- property + fuzz tests (system-stack hardening pass) ----

    /// A tiny deterministic PRNG (splitmix64) so the property sweeps are reproducible without
    /// pulling in a proptest dependency.
    struct Rng(u64);
    impl Rng {
        fn new(seed: u64) -> Self {
            Rng(seed)
        }
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn port(&mut self) -> u16 {
            (self.next() % 65535) as u16 + 1 // 1..=65535
        }
        fn v4(&mut self) -> SocketAddrV4 {
            SocketAddrV4::new(Ipv4Addr::from(self.next() as u32), self.port())
        }
        fn v6_addr(&mut self) -> Ipv6Addr {
            let mut b = [0u8; 16];
            b[..8].copy_from_slice(&self.next().to_be_bytes());
            b[8..].copy_from_slice(&self.next().to_be_bytes());
            Ipv6Addr::from(b)
        }
        fn payload(&mut self) -> Vec<u8> {
            let len = (self.next() % 41) as usize; // 0..=40, incl. odd lengths (sum16 tail)
            (0..len).map(|_| self.next() as u8).collect()
        }
    }

    /// Build a minimal IPv6 TCP packet `src -> dst` with `payload` and a valid TCP checksum (IPv6
    /// has no IP-header checksum).
    fn ipv6_tcp(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
        let (sip, dip) = match (src.ip(), dst.ip()) {
            (IpAddr::V6(s), IpAddr::V6(d)) => (s, d),
            _ => panic!("ipv6_tcp needs v6 addresses"),
        };
        let mut p = vec![0u8; 40 + 20 + payload.len()];
        p[0] = 0x60; // v6
        p[4..6].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes()); // payload length
        p[6] = PROTO_TCP; // next header
        p[7] = 64; // hop limit
        p[8..24].copy_from_slice(&sip.octets());
        p[24..40].copy_from_slice(&dip.octets());
        p[40..42].copy_from_slice(&src.port().to_be_bytes());
        p[42..44].copy_from_slice(&dst.port().to_be_bytes());
        p[40 + 12] = 0x50; // data offset = 5
        p[40 + 13] = 0x10; // ACK
        p[40 + 20..].copy_from_slice(payload);
        let pseudo = pseudo_header_sum(&src.ip(), &dst.ip(), PROTO_TCP, 20 + payload.len());
        let tc = checksum(&p[40..], pseudo);
        p[40 + 16..40 + 18].copy_from_slice(&tc.to_be_bytes());
        p
    }

    /// The IPv6 TCP checksum folds to zero (valid).
    fn ipv6_tcp_checksum_ok(p: &[u8]) -> bool {
        let pseudo = pseudo_header_sum(
            &read_ip(p, 8, 16),
            &read_ip(p, 24, 16),
            PROTO_TCP,
            p.len() - 40,
        );
        checksum(&p[40..], pseudo) == 0
    }

    #[test]
    fn prop_v4_rewrite_matches_full_recompute_and_round_trips() {
        let mut rng = Rng::new(0x5061_726B_5F76_3401);
        for _ in 0..2000 {
            let (s0, d0) = (rng.v4(), rng.v4());
            let payload = rng.payload();
            let orig = ipv4_tcp(s0, d0, &payload);

            let (s1, d1) = (rng.v4(), rng.v4());
            let mut p = orig.clone();
            rewrite_tcp(&mut p, SocketAddr::V4(s1), SocketAddr::V4(d1)).unwrap();

            // Incremental (RFC 1624) rewrite must equal a from-scratch full rebuild, and verify.
            assert_eq!(
                p,
                ipv4_tcp(s1, d1, &payload),
                "incremental != full recompute"
            );
            assert!(ipv4_checksums_ok(&p));
            assert_eq!(
                tcp_endpoints(&p).unwrap(),
                (SocketAddr::V4(s1), SocketAddr::V4(d1))
            );

            // Rewriting back to the original tuple reproduces the original bytes exactly.
            rewrite_tcp(&mut p, SocketAddr::V4(s0), SocketAddr::V4(d0)).unwrap();
            assert_eq!(p, orig, "round-trip must reproduce the original packet");
        }
    }

    #[test]
    fn prop_v6_rewrite_round_trips_and_keeps_checksum_valid() {
        let mut rng = Rng::new(0x5061_726B_5F76_3602);
        for _ in 0..2000 {
            let s0 = SocketAddr::new(IpAddr::V6(rng.v6_addr()), rng.port());
            let d0 = SocketAddr::new(IpAddr::V6(rng.v6_addr()), rng.port());
            let payload = rng.payload();
            let orig = ipv6_tcp(s0, d0, &payload);

            let s1 = SocketAddr::new(IpAddr::V6(rng.v6_addr()), rng.port());
            let d1 = SocketAddr::new(IpAddr::V6(rng.v6_addr()), rng.port());
            let mut p = orig.clone();
            rewrite_tcp(&mut p, s1, d1).unwrap();
            assert_eq!(tcp_endpoints(&p).unwrap(), (s1, d1));
            assert!(
                ipv6_tcp_checksum_ok(&p),
                "v6 tcp checksum invalid after rewrite"
            );

            rewrite_tcp(&mut p, s0, d0).unwrap();
            assert_eq!(p, orig, "v6 round-trip must reproduce the original");
        }
    }

    #[test]
    fn ipv6_extension_header_is_rejected() {
        // A v6 packet whose next-header is an extension (here 44 = Fragment) can't be rewritten in
        // place — the parser reports Ipv6Extension so the caller falls back. (The config selector
        // is IPv4-only today; this pins the v6 boundary the rewriter does and doesn't handle.)
        let mut p = ipv6_tcp(
            "[2001:db8::1]:1".parse().unwrap(),
            "[2001:db8::2]:2".parse().unwrap(),
            b"",
        );
        p[6] = 44; // Fragment extension header
        assert_eq!(tcp_endpoints(&p), Err(RewriteError::Ipv6Extension));
        assert_eq!(
            rewrite_tcp(
                &mut p,
                "[2001:db8::3]:3".parse().unwrap(),
                "[2001:db8::4]:4".parse().unwrap()
            ),
            Err(RewriteError::Ipv6Extension)
        );
    }

    #[test]
    fn parsers_never_panic_on_arbitrary_bytes() {
        // Fuzz the untrusted-packet surface: random buffers (and structured near-packets) must
        // return Ok/Err, never panic or over-read. The test completing IS the assertion.
        let mut rng = Rng::new(0x5061_726B_5F76_3603);
        let dummy: SocketAddr = "1.2.3.4:5".parse().unwrap();
        for _ in 0..20_000 {
            let len = (rng.next() % 81) as usize; // 0..=80
            let mut buf: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
            // Sometimes force a plausible IP version nibble to push past the version switch into
            // the length/header checks.
            if len > 0 && rng.next() & 1 == 0 {
                buf[0] = (buf[0] & 0x0f) | if rng.next() & 1 == 0 { 0x40 } else { 0x60 };
            }
            let _ = ip_protocol(&buf);
            let _ = tcp_endpoints(&buf);
            let _ = udp_endpoints(&buf);
            let _ = rewrite_tcp(&mut buf.clone(), dummy, dummy);
        }
    }
}
