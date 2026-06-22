//! Salamander XOR obfuscation and Gecko handshake-fragmentation layer.
//!
//! # Salamander
//! Prepends an 8-byte random salt to the datagram and XORs the payload with a repeating
//! BLAKE2b-256(key ‖ salt) keystream (32-byte block, repeated), per the Hysteria 2 spec
//! §Salamander.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

type Blake2b256 = Blake2b<U32>;

/// BLAKE2b with a 256-bit (32-byte) output.
fn blake2b256(input: &[u8]) -> [u8; 32] {
    let mut h = Blake2b256::new();
    h.update(input);
    h.finalize().into()
}

const SALT_LEN: usize = 8;

/// Fill `buf` from the OS CSRNG, surfacing a (practically impossible) failure as an [`io::Error`].
///
/// The obfuscation send path is `try_send` (which returns `io::Result`), so an RNG failure is
/// propagated rather than panicked or silently ignored — per the project anti-patterns (no `expect`
/// outside tests, never ignore a `Result`).
fn fill_random(buf: &mut [u8]) -> io::Result<()> {
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), buf)
        .map_err(|_| io::Error::other("hysteria2 obfs: OS RNG failure"))
}

/// Salamander: prepend an 8-byte random salt and XOR the packet with the BLAKE2b-256(key‖salt)
/// keystream (repeating every 32 bytes), per the Hysteria 2 spec §Salamander.
pub fn salamander_obfuscate(key: &[u8], packet: &[u8]) -> io::Result<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    fill_random(&mut salt)?;
    let mut payload = packet.to_vec();
    salamander_xor_with_salt(key, &salt, &mut payload);
    let mut out = Vec::with_capacity(SALT_LEN + payload.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Reverse of [`salamander_obfuscate`]. Returns `None` if the datagram is too short to carry a salt.
pub fn salamander_deobfuscate(key: &[u8], datagram: &[u8]) -> Option<Vec<u8>> {
    if datagram.len() < SALT_LEN {
        return None;
    }
    let (salt, body) = datagram.split_at(SALT_LEN);
    let salt: [u8; SALT_LEN] = salt.try_into().ok()?;
    let mut payload = body.to_vec();
    salamander_xor_with_salt(key, &salt, &mut payload);
    Some(payload)
}

/// XOR `payload` in place with the BLAKE2b-256(key‖salt) keystream (32-byte block, repeated).
fn salamander_xor_with_salt(key: &[u8], salt: &[u8; SALT_LEN], payload: &mut [u8]) {
    let mut material = Vec::with_capacity(key.len() + SALT_LEN);
    material.extend_from_slice(key);
    material.extend_from_slice(salt);
    let hash = blake2b256(&material);
    for (i, b) in payload.iter_mut().enumerate() {
        *b ^= hash[i % 32];
    }
}

// ── Gecko ────────────────────────────────────────────────────────────────────

const GECKO_FLAG: u8 = 0x80;

/// Split a QUIC packet into Gecko frames.
///
/// Short-header packets (`packet[0] & 0x80 == 0`) pass through unchanged (a
/// single element). Long-header packets are split into 2..=8 chunks, each
/// wrapped in a Gecko frame with random padding.
///
/// Frame layout: `[1] flags=0x80 | [1] msgID | [1] chunkIdx:4|totalChunks:4 |
/// [2] padLen(be) | [padLen] padding | [..] chunk`
///
/// `seed` perturbs the msgID per call (callers pass a per-packet value; tests
/// pass a fixed one). Split sizing, padding, and msgID are sender-side choices
/// (not negotiated with the server).
pub fn gecko_split(packet: &[u8], seed: u8) -> io::Result<Vec<Vec<u8>>> {
    // A Gecko frame needs >= 2 chunks of >= 1 byte each; a long-header packet smaller than 2 bytes
    // can't be framed, so it (and short-header / empty packets) passes through unchanged.
    if packet.len() < 2 || packet[0] & GECKO_FLAG == 0 {
        return Ok(vec![packet.to_vec()]);
    }
    let mut rb = [0u8; 2];
    fill_random(&mut rb)?;
    // Clamp the chunk count to the packet length so every chunk gets >= 1 byte (base >= 1); for the
    // real (large) long-header packets this is always 2..=8, unchanged. Avoids empty chunks / extra
    // datagrams on pathologically small packets.
    let max_chunks = packet.len().min(8);
    let total = 2 + (rb[0] as usize % (max_chunks - 1)); // 2..=max_chunks
    let msg_id = rb[1] ^ seed;
    let base = packet.len() / total;
    let mut frames = Vec::with_capacity(total);
    let mut off = 0;
    for idx in 0..total {
        let end = if idx == total - 1 {
            packet.len()
        } else {
            off + base
        };
        let chunk = &packet[off..end];
        off = end;
        let mut padb = [0u8; 1];
        fill_random(&mut padb)?;
        let pad_len = (padb[0] % 16) as usize;
        let mut padding = vec![0u8; pad_len];
        fill_random(&mut padding)?;
        let mut frame = Vec::with_capacity(5 + pad_len + chunk.len());
        frame.push(GECKO_FLAG);
        frame.push(msg_id);
        frame.push(((idx as u8) << 4) | (total as u8));
        frame.extend_from_slice(&(pad_len as u16).to_be_bytes());
        frame.extend_from_slice(&padding);
        frame.extend_from_slice(chunk);
        frames.push(frame);
    }
    Ok(frames)
}

/// Reassembles Gecko frames keyed by msgID.
///
/// Bounded to [`GECKO_MAX_MSGS`] concurrent message IDs; on overflow the
/// partial-reassembly map is cleared (best-effort — QUIC retransmits any lost
/// handshake packets).
#[derive(Debug)]
pub struct GeckoReassembler {
    partial: std::collections::HashMap<u8, GeckoEntry>,
}

#[derive(Debug)]
struct GeckoEntry {
    total: u8,
    chunks: Vec<Option<Vec<u8>>>,
    have: u8,
}

const GECKO_MAX_MSGS: usize = 16;

impl GeckoReassembler {
    pub fn new() -> Self {
        GeckoReassembler {
            partial: std::collections::HashMap::new(),
        }
    }

    /// Feed one (already Salamander-deobfuscated) datagram.
    ///
    /// A Gecko frame is identified by a leading byte of *exactly* `0x80` (the documented frame
    /// marker, with the low 7 bits zero); anything else is a complete QUIC packet returned as-is.
    /// Matching the exact byte rather than just the high bit matters because a QUIC long-header
    /// packet also has the high bit set (`0xC0`+) — a non-fragmented long-header packet must pass
    /// through, not be misparsed as a frame and dropped. A Gecko frame is buffered; the reassembled
    /// QUIC packet is returned when its msgID completes. Malformed frames return `None`.
    pub fn accept(&mut self, datagram: &[u8]) -> Option<Vec<u8>> {
        let &flags = datagram.first()?;
        if flags != GECKO_FLAG {
            return Some(datagram.to_vec());
        }
        if datagram.len() < 5 {
            return None;
        }
        let msg_id = datagram[1];
        let idx = (datagram[2] >> 4) as usize;
        let total = (datagram[2] & 0x0f) as usize;
        if !(2..=8).contains(&total) || idx >= total {
            return None;
        }
        let pad_len = u16::from_be_bytes([datagram[3], datagram[4]]) as usize;
        let chunk = datagram.get(5 + pad_len..)?.to_vec();

        if self.partial.len() >= GECKO_MAX_MSGS && !self.partial.contains_key(&msg_id) {
            self.partial.clear();
        }
        let entry = self.partial.entry(msg_id).or_insert_with(|| GeckoEntry {
            total: total as u8,
            chunks: vec![None; total],
            have: 0,
        });
        if entry.total as usize != total {
            self.partial.remove(&msg_id);
            return None;
        }
        if entry.chunks[idx].is_none() {
            entry.chunks[idx] = Some(chunk);
            entry.have += 1;
        }
        if entry.have as usize == total {
            let entry = self.partial.remove(&msg_id)?;
            let mut out = Vec::new();
            for c in entry.chunks {
                out.extend_from_slice(&c?);
            }
            return Some(out);
        }
        None
    }
}

impl Default for GeckoReassembler {
    fn default() -> Self {
        Self::new()
    }
}

// ── SalamanderGeckoSocket ──────────────────────────────────────────────────────

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

/// Largest UDP payload we will receive in one datagram (QUIC datagrams stay well under this).
const RECV_SCRATCH: usize = 65535;

/// A [`quinn::AsyncUdpSocket`] that applies Gecko (optional) + Salamander on send and the
/// reverse on receive, wrapping a real Tokio UDP socket.
///
/// GSO is disabled ([`max_transmit_segments`](Self::max_transmit_segments) returns `1`) and GRO is
/// disabled ([`max_receive_segments`](Self::max_receive_segments) returns `1`) so every `try_send`
/// is exactly one QUIC packet and every receive yields whole datagrams — giving clean per-packet
/// obfuscation. Each Gecko frame / QUIC packet is independently Salamander-obfuscated (its own
/// salt), so coalescing would break the transform.
#[derive(Debug)]
pub struct SalamanderGeckoSocket {
    inner: tokio::net::UdpSocket,
    state: quinn_udp::UdpSocketState,
    key: Vec<u8>,
    gecko: bool,
    reassembler: std::sync::Mutex<GeckoReassembler>,
}

impl SalamanderGeckoSocket {
    /// Wrap an existing Tokio UDP socket. `key` is the Salamander pre-shared key; `gecko` enables
    /// the handshake-fragmentation layer.
    pub fn new(inner: tokio::net::UdpSocket, key: Vec<u8>, gecko: bool) -> io::Result<Self> {
        let state = quinn_udp::UdpSocketState::new((&inner).into())?;
        Ok(Self {
            inner,
            state,
            key,
            gecko,
            reassembler: std::sync::Mutex::new(GeckoReassembler::new()),
        })
    }

    /// Encode one outgoing QUIC packet into one or more on-wire datagrams: Gecko-split (if enabled)
    /// then Salamander-obfuscate each resulting piece. Surfaces an OS-RNG failure as an `io::Error`.
    fn encode_out(&self, packet: &[u8], seed: u8) -> io::Result<Vec<Vec<u8>>> {
        let pieces = if self.gecko {
            gecko_split(packet, seed)?
        } else {
            vec![packet.to_vec()]
        };
        pieces
            .iter()
            .map(|p| salamander_obfuscate(&self.key, p))
            .collect()
    }
}

impl quinn::AsyncUdpSocket for SalamanderGeckoSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(SalamanderGeckoPoller { socket: self })
    }

    fn try_send(&self, transmit: &quinn_udp::Transmit<'_>) -> io::Result<()> {
        // Seed the Gecko msgID per destination so concurrent flows do not collide on msgID.
        let seed = transmit.destination.port() as u8;
        for dg in self.encode_out(transmit.contents, seed)? {
            let t = quinn_udp::Transmit {
                destination: transmit.destination,
                ecn: transmit.ecn,
                contents: &dg,
                // GSO disabled: one datagram per Transmit.
                segment_size: None,
                src_ip: transmit.src_ip,
            };
            // Mirror quinn's own tokio AsyncUdpSocket::try_send: drive the obfuscated send through
            // quinn-udp's UdpSocketState (for ECN cmsgs) on the borrowed Tokio socket. Propagate
            // WouldBlock so quinn re-arms the poller and retries; a partially sent Gecko burst is
            // fine — QUIC retransmits.
            self.inner.try_io(tokio::io::Interest::WRITABLE, || {
                self.state.try_send((&self.inner).into(), &t)
            })?;
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [quinn_udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // Hoisted out of the loop: the receive scratch (64 KiB) and meta are fully overwritten by each
        // `recv`, so a single allocation is reused across retries (buffered Gecko fragments / spurious
        // readiness) instead of reserving a large stack frame every iteration.
        let mut scratch = [0u8; RECV_SCRATCH];
        let mut raw_meta = [quinn_udp::RecvMeta::default()];
        loop {
            // Register the waker if the inner socket is not yet readable.
            std::task::ready!(self.inner.poll_recv_ready(cx))?;

            // Receive one raw on-wire datagram into scratch, capturing ECN/src via quinn-udp.
            let res = self.inner.try_io(tokio::io::Interest::READABLE, || {
                let mut slices = [io::IoSliceMut::new(&mut scratch)];
                self.state
                    .recv((&self.inner).into(), &mut slices, &mut raw_meta)
            });
            let n = match res {
                Ok(n) => n,
                // The readiness was spurious; loop and re-poll readiness.
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Poll::Ready(Err(e)),
            };
            if n == 0 {
                continue;
            }

            let rm = raw_meta[0];
            // GRO disabled, but split defensively by stride in case the kernel coalesced anyway:
            // each on-wire datagram is an independent Salamander unit.
            let stride = if rm.stride == 0 { rm.len } else { rm.stride };
            let total = rm.len.min(RECV_SCRATCH);

            let mut emitted = 0usize;
            let mut off = 0usize;
            while off < total && emitted < bufs.len() {
                let end = (off + stride).min(total);
                let raw = &scratch[off..end];
                off = end;

                let Some(plain) = salamander_deobfuscate(&self.key, raw) else {
                    continue; // not for us / malformed — drop
                };

                // Resolve to zero or more complete QUIC packets.
                let packet = if self.gecko {
                    // Lock is sync-only and dropped before any further poll; never held across await.
                    let mut reasm = match self.reassembler.lock() {
                        Ok(g) => g,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    reasm.accept(&plain)
                } else {
                    Some(plain)
                };
                let Some(packet) = packet else {
                    continue; // buffered Gecko fragment; nothing complete yet
                };

                let dst = bufs[emitted].as_mut();
                // Drop a packet that doesn't fit rather than truncating it — a truncated QUIC packet
                // would corrupt the stream. (quinn sizes its recv buffers to the max datagram, so this
                // is a defensive guard, not an expected path.)
                if packet.len() > dst.len() {
                    continue;
                }
                let len = packet.len();
                dst[..len].copy_from_slice(&packet);
                meta[emitted] = quinn_udp::RecvMeta {
                    addr: rm.addr,
                    len,
                    stride: len,
                    ecn: rm.ecn,
                    // Preserve the local-address metadata quinn-udp captured (quinn may use it for
                    // path / connection-migration logic).
                    dst_ip: rm.dst_ip,
                };
                emitted += 1;
            }

            if emitted > 0 {
                return Poll::Ready(Ok(emitted));
            }
            // Only incomplete Gecko fragments / dropped datagrams this round: loop and poll again.
        }
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    /// GSO disabled: one QUIC packet per send so each is cleanly obfuscated.
    fn max_transmit_segments(&self) -> usize {
        1
    }

    /// GRO disabled: each received datagram is an independent Salamander unit.
    fn max_receive_segments(&self) -> usize {
        1
    }
}

/// [`quinn::UdpPoller`] for [`SalamanderGeckoSocket`]. quinn's own `UdpPollHelper` is private, so we
/// implement the trait directly over the inner Tokio socket's write-readiness.
#[derive(Debug)]
struct SalamanderGeckoPoller {
    socket: Arc<SalamanderGeckoSocket>,
}

impl quinn::UdpPoller for SalamanderGeckoPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.socket.inner.poll_send_ready(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn salamander_round_trips() {
        let key = b"presharedkey";
        let packet = b"a fake QUIC packet payload";
        let on_wire = salamander_obfuscate(key, packet).unwrap();
        assert_eq!(on_wire.len(), 8 + packet.len()); // salt + xored
        let back = salamander_deobfuscate(key, &on_wire).unwrap();
        assert_eq!(back.as_slice(), packet.as_ref());
    }

    #[test]
    fn salamander_rejects_too_short() {
        assert!(salamander_deobfuscate(b"k", &[0u8; 4]).is_none()); // < 8-byte salt
    }

    #[test]
    fn salamander_keystream_matches_blake2b() {
        // hash = BLAKE2b-256(key ‖ salt); payload[i] ^= hash[i % 32]
        let key: &[u8] = b"k";
        let salt = [9u8; 8];
        let mut p = vec![0u8; 40]; // XOR of zeros yields the raw keystream
        salamander_xor_with_salt(key, &salt, &mut p);
        let expected = blake2b256(&[key, &salt].concat());
        for i in 0..p.len() {
            assert_eq!(p[i], expected[i % 32]);
        }
    }

    #[test]
    fn gecko_short_header_passes_through() {
        // high bit clear => short header => one piece, unchanged
        let packet = vec![0x40, 1, 2, 3];
        let frames = gecko_split(&packet, 7).unwrap();
        assert_eq!(frames, vec![packet]);
    }

    #[test]
    fn gecko_long_header_splits_and_reassembles() {
        // high bit set => long header
        let packet: Vec<u8> = (0..300u32)
            .map(|i| (i % 256) as u8)
            .map(|b| b | (0x80_u8 * (b == 0) as u8))
            .collect();
        let mut packet = packet;
        packet[0] = 0xC0; // ensure long header
        let frames = gecko_split(&packet, 0x55).unwrap();
        assert!(
            frames.len() >= 2 && frames.len() <= 8,
            "got {} frames",
            frames.len()
        );
        let mut r = GeckoReassembler::new();
        let mut done = None;
        for f in &frames {
            if let Some(pkt) = r.accept(f) {
                done = Some(pkt);
            }
        }
        assert_eq!(done.unwrap(), packet);
    }

    #[test]
    fn gecko_reassembler_rejects_malformed() {
        let mut r = GeckoReassembler::new();
        assert!(r.accept(&[0x80, 1]).is_none()); // truncated frame (< 5 bytes header)
                                                 // a short-header datagram (flags high bit clear) is returned as-is (passthrough), not None:
        assert_eq!(r.accept(&[0x40, 9, 9]).unwrap(), vec![0x40, 9, 9]);
        // a QUIC long-header packet (0xC0, high bit set but != 0x80) must pass through, NOT be
        // misparsed as a Gecko frame and dropped:
        assert_eq!(r.accept(&[0xc0, 1, 2, 3]).unwrap(), vec![0xc0, 1, 2, 3]);
        // totalChunks out of range (frame = flags, msgID, packed, padLen_hi, padLen_lo):
        assert!(r.accept(&[0x80, 0, 0x09, 0, 0]).is_none()); // total=9 (>8)
        assert!(r.accept(&[0x80, 0, 0x01, 0, 0]).is_none()); // total=1 (<2)
                                                             // chunkIdx >= totalChunks (idx=3, total=2):
        assert!(r.accept(&[0x80, 0, 0x32, 0, 0]).is_none());
        // padLen pointing past the datagram end:
        assert!(r.accept(&[0x80, 0, 0x02, 0xff, 0xff]).is_none());
    }
}
