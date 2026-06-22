//! Hysteria 2 UDP proxy: QUIC datagram framing, fragmentation/reassembly.

// consumed by dial_udp in Task 10; remove at final sweep
#![allow(dead_code)]

use super::tcp::{read_varint, varint_len, write_varint};

/// A decoded Hysteria 2 UDPMessage datagram.
pub struct UdpMessage {
    pub session_id: u32,
    pub packet_id: u16,
    pub frag_id: u8,
    pub frag_count: u8,
    pub addr: String,
    pub payload: Vec<u8>,
}

/// Bytes of fixed header + varint-encoded addr length prefix + addr bytes, for a given address.
fn header_len(addr: &str) -> usize {
    4 + 2 + 1 + 1 + varint_len(addr.len() as u64) + addr.len()
}

/// Encode (and fragment) one UDP packet into one or more UDPMessage datagrams, each ≤ `max_datagram`.
///
/// Wire format per fragment: `[u32 session_id][u16 packet_id][u8 frag_id][u8 frag_count]
/// [varint addr_len][addr bytes][payload chunk]`.
///
/// Returns an empty `Vec` (the caller drops the datagram) when the packet cannot be represented:
/// `max_datagram` leaves no room for even one payload byte after the header, or the payload would
/// need more than 255 fragments. Both are pathological for real QUIC datagram sizes (~1200 bytes).
pub fn encode_udp_message(
    session_id: u32,
    packet_id: u16,
    addr: &str,
    payload: &[u8],
    max_datagram: usize,
) -> Vec<Vec<u8>> {
    debug_assert!(
        !addr.is_empty(),
        "hysteria2 UDPMessage requires a non-empty address"
    );
    let hlen = header_len(addr);
    let room = max_datagram.saturating_sub(hlen);
    if room == 0 {
        return Vec::new(); // no room for payload — drop (don't emit oversized fragments)
    }
    let needed = payload.len().div_ceil(room).max(1);
    if needed > 255 {
        return Vec::new(); // can't fragment into >255 parts — drop (don't truncate)
    }
    let frag_count = needed as u8;
    let mut out = Vec::with_capacity(frag_count as usize);
    for frag_id in 0..frag_count {
        let start = (frag_id as usize) * room;
        let end = (start + room).min(payload.len());
        let chunk = if start < payload.len() {
            &payload[start..end]
        } else {
            &[]
        };
        let mut m = Vec::with_capacity(hlen + chunk.len());
        m.extend_from_slice(&session_id.to_be_bytes());
        m.extend_from_slice(&packet_id.to_be_bytes());
        m.push(frag_id);
        m.push(frag_count);
        write_varint(&mut m, addr.len() as u64);
        m.extend_from_slice(addr.as_bytes());
        m.extend_from_slice(chunk);
        out.push(m);
    }
    out
}

/// Decode a UDPMessage datagram. Returns `None` if the buffer is truncated or invalid UTF-8.
pub fn decode_udp_message(buf: &[u8]) -> Option<UdpMessage> {
    let session_id = u32::from_be_bytes(buf.get(0..4)?.try_into().ok()?);
    let packet_id = u16::from_be_bytes(buf.get(4..6)?.try_into().ok()?);
    let frag_id = *buf.get(6)?;
    let frag_count = *buf.get(7)?;
    let (alen, rest) = read_varint(buf.get(8..)?)?;
    let alen = alen as usize;
    let addr = std::str::from_utf8(rest.get(..alen)?).ok()?.to_owned();
    let payload = rest.get(alen..)?.to_vec();
    Some(UdpMessage {
        session_id,
        packet_id,
        frag_id,
        frag_count,
        addr,
        payload,
    })
}

/// Reassembles fragments keyed by (session_id, packet_id). Bounded to `UDP_MAX_PARTIAL` in-flight
/// packets; evicts all partial state on overflow to avoid unbounded memory growth.
pub struct UdpReassembler {
    partial: std::collections::HashMap<(u32, u16), Vec<Option<Vec<u8>>>>,
}

const UDP_MAX_PARTIAL: usize = 256;

impl UdpReassembler {
    pub fn new() -> Self {
        UdpReassembler {
            partial: std::collections::HashMap::new(),
        }
    }

    /// Returns the reassembled payload when `m` completes its packet, else `None`.
    pub fn accept(&mut self, m: UdpMessage) -> Option<Vec<u8>> {
        if m.frag_count <= 1 {
            return Some(m.payload);
        }
        let key = (m.session_id, m.packet_id);
        if self.partial.len() >= UDP_MAX_PARTIAL && !self.partial.contains_key(&key) {
            self.partial.clear();
        }
        let slot = self
            .partial
            .entry(key)
            .or_insert_with(|| vec![None; m.frag_count as usize]);
        if slot.len() != m.frag_count as usize {
            self.partial.remove(&key);
            return None;
        }
        match slot.get_mut(m.frag_id as usize) {
            Some(cell) if cell.is_none() => *cell = Some(m.payload),
            Some(_) => {} // duplicate fragment — ignore
            None => {
                self.partial.remove(&key);
                return None;
            }
        }
        if slot.iter().all(|c| c.is_some()) {
            let slot = self.partial.remove(&key)?;
            let mut out = Vec::new();
            for c in slot {
                out.extend_from_slice(&c?);
            }
            return Some(out);
        }
        None
    }
}

impl Default for UdpReassembler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_message_round_trips_single_fragment() {
        let msgs = encode_udp_message(7, 3, "8.8.8.8:53", b"query", 1500);
        assert_eq!(msgs.len(), 1);
        let m = decode_udp_message(&msgs[0]).unwrap();
        assert_eq!(m.session_id, 7);
        assert_eq!(m.packet_id, 3);
        assert_eq!(m.frag_count, 1);
        assert_eq!(m.addr, "8.8.8.8:53");
        assert_eq!(m.payload, b"query");
    }

    #[test]
    fn udp_message_fragments_when_over_max() {
        let big = vec![0xabu8; 4000];
        let msgs = encode_udp_message(1, 1, "8.8.8.8:53", &big, 1200);
        assert!(msgs.len() > 1, "expected fragmentation, got {}", msgs.len());
        // each fragment must fit in max
        for m in &msgs {
            assert!(m.len() <= 1200, "fragment {} exceeds max", m.len());
        }
        let mut r = UdpReassembler::new();
        let mut done = None;
        for m in &msgs {
            if let Some(p) = r.accept(decode_udp_message(m).unwrap()) {
                done = Some(p);
            }
        }
        assert_eq!(done.unwrap(), big);
    }

    #[test]
    fn udp_reassembler_handles_out_of_order_and_ignores_dup() {
        let big = vec![0x5au8; 3000];
        let mut msgs = encode_udp_message(2, 9, "1.1.1.1:53", &big, 1100);
        msgs.reverse(); // out of order
        let mut r = UdpReassembler::new();
        let mut done = None;
        for m in msgs.iter().chain(msgs.iter()) {
            // feed twice (dups)
            if let Some(p) = r.accept(decode_udp_message(m).unwrap()) {
                done = Some(p);
            }
        }
        assert_eq!(done.unwrap(), big);
    }

    #[test]
    fn decode_udp_message_rejects_truncated() {
        assert!(decode_udp_message(&[0, 0, 0]).is_none());
    }

    #[test]
    fn encode_drops_when_no_room_for_payload() {
        // max_datagram smaller than the header => no room => empty (caller drops), never an
        // oversized fragment or a silently-truncated payload.
        assert!(encode_udp_message(1, 1, "8.8.8.8:53", b"x", 4).is_empty());
        // an empty payload still encodes as a single zero-length-payload fragment.
        let msgs = encode_udp_message(1, 1, "8.8.8.8:53", b"", 1500);
        assert_eq!(msgs.len(), 1);
        assert!(decode_udp_message(&msgs[0]).unwrap().payload.is_empty());
    }
}
