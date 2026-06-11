//! Minimal, zero-copy IP packet inspection for the TUN data path.
//!
//! This is deliberately tiny: a TUN device in IP mode hands us raw L3 packets, and
//! all M1 needs is to read the version, protocol, and addresses, plus synthesize an
//! ICMP echo reply. We do not pull a general packet library — the parser views borrow
//! the original buffer and copy only scalars out, so there is no per-packet allocation
//! on the inspection path. Reply construction (the cold path) does allocate.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::BytesMut;

/// IP protocol numbers we distinguish. Values are the IANA assignments.
pub mod proto {
    pub const ICMP: u8 = 1;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
    pub const ICMPV6: u8 = 58;
}

/// Human-readable name for an IP protocol number, for logging.
pub fn protocol_name(proto: u8) -> &'static str {
    match proto {
        proto::ICMP => "icmp",
        proto::TCP => "tcp",
        proto::UDP => "udp",
        proto::ICMPV6 => "icmpv6",
        _ => "other",
    }
}

/// A parsed, read-only view over an IPv4 or IPv6 packet. Borrows the backing slice.
pub enum IpPacket<'a> {
    V4(Ipv4View<'a>),
    V6(Ipv6View<'a>),
}

impl<'a> IpPacket<'a> {
    /// Parse the IP version nibble and return the matching view, or `None` if the
    /// buffer is too short or the version is neither 4 nor 6.
    pub fn parse(bytes: &'a [u8]) -> Option<Self> {
        match bytes.first()? >> 4 {
            4 => Ipv4View::new(bytes).map(IpPacket::V4),
            6 => Ipv6View::new(bytes).map(IpPacket::V6),
            _ => None,
        }
    }

    /// The L4 protocol number (IPv4 `protocol` / IPv6 `next_header`).
    pub fn protocol(&self) -> u8 {
        match self {
            IpPacket::V4(p) => p.protocol(),
            IpPacket::V6(p) => p.next_header(),
        }
    }

    pub fn src(&self) -> IpAddr {
        match self {
            IpPacket::V4(p) => IpAddr::V4(p.src()),
            IpPacket::V6(p) => IpAddr::V6(p.src()),
        }
    }

    pub fn dst(&self) -> IpAddr {
        match self {
            IpPacket::V4(p) => IpAddr::V4(p.dst()),
            IpPacket::V6(p) => IpAddr::V6(p.dst()),
        }
    }

    /// Total packet length in bytes as the parser sees it (the backing slice length).
    pub fn len(&self) -> usize {
        match self {
            IpPacket::V4(p) => p.bytes.len(),
            IpPacket::V6(p) => p.bytes.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A view over an IPv4 packet. Validated to have at least a full 20-byte header whose
/// IHL fits within the slice.
pub struct Ipv4View<'a> {
    bytes: &'a [u8],
}

impl<'a> Ipv4View<'a> {
    fn new(bytes: &'a [u8]) -> Option<Self> {
        let ihl = (*bytes.first()? & 0x0f) as usize * 4;
        if bytes.len() < 20 || ihl < 20 || ihl > bytes.len() {
            return None;
        }
        Some(Self { bytes })
    }

    /// Header length in bytes (IHL × 4).
    pub fn header_len(&self) -> usize {
        (self.bytes[0] & 0x0f) as usize * 4
    }

    pub fn protocol(&self) -> u8 {
        self.bytes[9]
    }

    pub fn src(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.bytes[12],
            self.bytes[13],
            self.bytes[14],
            self.bytes[15],
        )
    }

    pub fn dst(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.bytes[16],
            self.bytes[17],
            self.bytes[18],
            self.bytes[19],
        )
    }

    /// The L4 payload (everything past the IPv4 header).
    pub fn payload(&self) -> &'a [u8] {
        &self.bytes[self.header_len()..]
    }
}

/// A view over an IPv6 packet. Validated to have the fixed 40-byte header.
pub struct Ipv6View<'a> {
    bytes: &'a [u8],
}

impl<'a> Ipv6View<'a> {
    const HEADER_LEN: usize = 40;

    fn new(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() < Self::HEADER_LEN {
            return None;
        }
        Some(Self { bytes })
    }

    /// The `next_header` field. We treat it as the L4 protocol; extension headers are
    /// not parsed (out of scope for M1's ICMP echo path).
    pub fn next_header(&self) -> u8 {
        self.bytes[6]
    }

    pub fn src(&self) -> Ipv6Addr {
        let mut o = [0u8; 16];
        o.copy_from_slice(&self.bytes[8..24]);
        Ipv6Addr::from(o)
    }

    pub fn dst(&self) -> Ipv6Addr {
        let mut o = [0u8; 16];
        o.copy_from_slice(&self.bytes[24..40]);
        Ipv6Addr::from(o)
    }

    pub fn payload(&self) -> &'a [u8] {
        &self.bytes[Self::HEADER_LEN..]
    }
}

// ICMP / ICMPv6 message type numbers we act on.
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;
const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;

/// If `request` is an ICMP (v4) or ICMPv6 echo request, build the matching echo reply
/// with addresses swapped and checksums recomputed. Returns `None` for anything else.
///
/// The reply reuses the request's identifier, sequence, and payload, so a `ping`
/// against the TUN address round-trips. This is the M1 liveness proof, not a general
/// ICMP responder.
pub fn icmp_echo_reply(request: &[u8]) -> Option<BytesMut> {
    match IpPacket::parse(request)? {
        IpPacket::V4(p) => v4_echo_reply(&p),
        IpPacket::V6(p) => v6_echo_reply(&p),
    }
}

fn v4_echo_reply(p: &Ipv4View<'_>) -> Option<BytesMut> {
    if p.protocol() != proto::ICMP {
        return None;
    }
    let hdr = p.header_len();
    let icmp = p.payload();
    if *icmp.first()? != ICMP_ECHO_REQUEST {
        return None;
    }

    let mut out = BytesMut::from(p.bytes);

    // Swap source/destination in the IPv4 header.
    let src: [u8; 4] = out[12..16].try_into().ok()?;
    let dst: [u8; 4] = out[16..20].try_into().ok()?;
    out[12..16].copy_from_slice(&dst);
    out[16..20].copy_from_slice(&src);

    // Echo request -> echo reply, then recompute the ICMP checksum (no pseudo-header).
    out[hdr] = ICMP_ECHO_REPLY;
    out[hdr + 2] = 0;
    out[hdr + 3] = 0;
    let icmp_ck = checksum(&out[hdr..]);
    out[hdr + 2..hdr + 4].copy_from_slice(&icmp_ck.to_be_bytes());

    // Recompute the IPv4 header checksum (covers the header only).
    out[10] = 0;
    out[11] = 0;
    let ip_ck = checksum(&out[..hdr]);
    out[10..12].copy_from_slice(&ip_ck.to_be_bytes());

    Some(out)
}

fn v6_echo_reply(p: &Ipv6View<'_>) -> Option<BytesMut> {
    if p.next_header() != proto::ICMPV6 {
        return None;
    }
    let off = Ipv6View::HEADER_LEN;
    let icmp = p.payload();
    if *icmp.first()? != ICMPV6_ECHO_REQUEST {
        return None;
    }

    let mut out = BytesMut::from(p.bytes);

    // Swap source/destination in the IPv6 header.
    let src: [u8; 16] = out[8..24].try_into().ok()?;
    let dst: [u8; 16] = out[24..40].try_into().ok()?;
    out[8..24].copy_from_slice(&dst);
    out[24..40].copy_from_slice(&src);

    out[off] = ICMPV6_ECHO_REPLY;
    out[off + 2] = 0;
    out[off + 3] = 0;

    // ICMPv6 checksum covers a pseudo-header (reply src/dst, upper-layer length, the
    // next-header value 58) followed by the ICMPv6 message.
    let msg_len = out.len() - off;
    let mut sum = 0u32;
    csum_acc(&mut sum, &dst); // reply source address (= original destination)
    csum_acc(&mut sum, &src); // reply destination address (= original source)
    csum_acc(&mut sum, &(msg_len as u32).to_be_bytes());
    csum_acc(&mut sum, &[0, 0, 0, proto::ICMPV6]);
    csum_acc(&mut sum, &out[off..]);
    let ck = csum_fold(sum);
    out[off + 2..off + 4].copy_from_slice(&ck.to_be_bytes());

    Some(out)
}

/// Standard internet checksum (RFC 1071): one's-complement sum of 16-bit big-endian
/// words, folded and inverted.
fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    csum_acc(&mut sum, data);
    csum_fold(sum)
}

/// Accumulate `data` into a running 16-bit one's-complement sum (kept in a `u32`).
fn csum_acc(sum: &mut u32, data: &[u8]) {
    let mut chunks = data.chunks_exact(2);
    for c in chunks.by_ref() {
        *sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        *sum += (*last as u32) << 8;
    }
}

/// Fold carries down into 16 bits and invert.
fn csum_fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A minimal IPv4 ICMP echo request: 20-byte IP header + 8-byte ICMP echo header.
    // src 10.0.0.2 -> dst 10.0.0.1, id 0x1234, seq 1, no data.
    fn v4_echo_request() -> Vec<u8> {
        let mut pkt = vec![
            0x45,
            0x00,
            0x00,
            0x1c, // ver/ihl, dscp, total len = 28
            0x00,
            0x01,
            0x00,
            0x00, // id, flags/frag
            0x40,
            proto::ICMP,
            0x00,
            0x00, // ttl, proto, hdr checksum (filled below)
            10,
            0,
            0,
            2, // src
            10,
            0,
            0,
            1, // dst
            ICMP_ECHO_REQUEST,
            0x00,
            0x00,
            0x00, // type, code, checksum (filled below)
            0x12,
            0x34,
            0x00,
            0x01, // id, seq
        ];
        let ip_ck = checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&ip_ck.to_be_bytes());
        let icmp_ck = checksum(&pkt[20..]);
        pkt[22..24].copy_from_slice(&icmp_ck.to_be_bytes());
        pkt
    }

    #[test]
    fn parses_ipv4_header() {
        let pkt = v4_echo_request();
        let parsed = IpPacket::parse(&pkt).expect("should parse");
        assert_eq!(parsed.protocol(), proto::ICMP);
        assert_eq!(parsed.src(), "10.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.dst(), "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.len(), 28);
    }

    #[test]
    fn rejects_short_and_unknown() {
        assert!(IpPacket::parse(&[]).is_none());
        assert!(IpPacket::parse(&[0x45]).is_none()); // claims v4 but truncated
        assert!(IpPacket::parse(&[0x70, 0, 0, 0]).is_none()); // version 7
    }

    #[test]
    fn v4_reply_swaps_addresses_and_has_valid_checksums() {
        let req = v4_echo_request();
        let reply = icmp_echo_reply(&req).expect("echo request should produce a reply");

        let parsed = IpPacket::parse(&reply).unwrap();
        assert_eq!(parsed.src(), "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.dst(), "10.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(reply[20], ICMP_ECHO_REPLY);

        // A valid checksum makes the one's-complement sum over the covered bytes zero.
        assert_eq!(checksum(&reply[..20]), 0, "IPv4 header checksum invalid");
        assert_eq!(checksum(&reply[20..]), 0, "ICMP checksum invalid");
    }

    #[test]
    fn non_echo_traffic_yields_no_reply() {
        let mut req = v4_echo_request();
        req[9] = proto::TCP; // not ICMP anymore
        assert!(icmp_echo_reply(&req).is_none());
    }
}
