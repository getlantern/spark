//! SS-2022 UDP: native packet build/parse + sliding-window replay filter.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use tokio::net::UdpSocket;

use crate::config::SsMethod;
use crate::transport::{PacketSink, PacketSource};

use super::crypto::{session_subkey, AesBlock, Cipher, CryptoError};
use super::{read_socks_addr, write_socks_addr};

const PKT_TYPE_CLIENT: u8 = 0;
const PKT_TYPE_SERVER: u8 = 1;
const MAX_SKEW_SECS: u64 = 30;
const TAG: usize = 16;

/// Size of the replay window (bits behind the highest accepted packet ID).
const WINDOW: u64 = 64;

/// Cap on tracked server sessions per UDP association (bounds memory against session-ID rotation).
const MAX_SERVER_SESSIONS: usize = 8;

/// Current Unix time in seconds (SIP022 timestamps).
// TODO(sweep): consolidate with tcp::now_secs into a shared pub(super) helper in mod.rs.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Build a client→server UDP packet (AES methods only).
pub fn build_client_packet(
    method: SsMethod,
    psk: &[u8],
    session_id: [u8; 8],
    packet_id: u64,
    target: &SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut sep = [0u8; 16];
    sep[..8].copy_from_slice(&session_id);
    sep[8..].copy_from_slice(&packet_id.to_be_bytes());

    let mut body = Vec::with_capacity(1 + 8 + 2 + 19 + payload.len() + TAG);
    body.push(PKT_TYPE_CLIENT);
    body.extend_from_slice(&now_secs().to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes()); // no padding for connected single-target flows
    write_socks_addr(target, &mut body);
    body.extend_from_slice(payload);

    let subkey = session_subkey(method, psk, &session_id);
    let cipher = Cipher::new(method, &subkey)?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&sep[4..16]);
    cipher.seal(nonce, &mut body);

    let block = AesBlock::new(psk)?;
    block.encrypt(&mut sep);
    let mut out = Vec::with_capacity(16 + body.len());
    out.extend_from_slice(&sep);
    out.extend_from_slice(&body);
    Ok(out)
}

/// A parsed server→client UDP packet.
pub struct ServerPacket {
    pub server_session_id: [u8; 8],
    pub packet_id: u64,
    pub payload: Vec<u8>,
}

/// Parse and validate a server→client UDP packet (AES methods only). Does NOT advance any replay
/// window — the caller does that after this returns Ok (so invalid packets don't poison the window).
pub fn parse_server_packet(
    method: SsMethod,
    psk: &[u8],
    expected_client_sid: [u8; 8],
    pkt: &[u8],
) -> Result<ServerPacket, CryptoError> {
    if pkt.len() < 16 + TAG {
        return Err(CryptoError::Auth);
    }
    let block = AesBlock::new(psk)?;
    let mut sep = [0u8; 16];
    sep.copy_from_slice(&pkt[..16]);
    block.decrypt(&mut sep);
    let server_session_id: [u8; 8] = sep[..8].try_into().map_err(|_| CryptoError::Auth)?;
    let packet_id = u64::from_be_bytes(sep[8..].try_into().map_err(|_| CryptoError::Auth)?);

    let subkey = session_subkey(method, psk, &server_session_id);
    let cipher = Cipher::new(method, &subkey)?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&sep[4..16]);
    let mut body = pkt[16..].to_vec();
    let plain_len = cipher.open(nonce, &mut body)?.len(); // decrypts in place; trailing 16 bytes = tag
    body.truncate(plain_len);

    // Server main header: type ‖ timestamp ‖ client_session_id(8) ‖ padding_len(2) ‖ padding ‖ SOCKS addr ‖ payload.
    if body.first() != Some(&PKT_TYPE_SERVER) {
        return Err(CryptoError::Auth);
    }
    let ts = u64::from_be_bytes(
        body.get(1..9)
            .ok_or(CryptoError::Auth)?
            .try_into()
            .map_err(|_| CryptoError::Auth)?,
    );
    if now_secs().abs_diff(ts) > MAX_SKEW_SECS {
        return Err(CryptoError::Auth);
    }
    let csid = body.get(9..17).ok_or(CryptoError::Auth)?;
    if csid != expected_client_sid {
        return Err(CryptoError::Auth);
    }
    let pad_len = u16::from_be_bytes(
        body.get(17..19)
            .ok_or(CryptoError::Auth)?
            .try_into()
            .map_err(|_| CryptoError::Auth)?,
    ) as usize;
    let addr_off = 19 + pad_len;
    let (_addr, consumed) =
        read_socks_addr(body.get(addr_off..).ok_or(CryptoError::Auth)?).ok_or(CryptoError::Auth)?;
    let payload = body
        .get(addr_off + consumed..)
        .ok_or(CryptoError::Auth)?
        .to_vec();

    Ok(ServerPacket {
        server_session_id,
        packet_id,
        payload,
    })
}

/// Test-only: build a server→client packet (mirror of `build_client_packet` with the server header).
#[cfg(test)]
pub fn build_server_packet_for_test(
    method: SsMethod,
    psk: &[u8],
    server_sid: [u8; 8],
    packet_id: u64,
    client_sid: [u8; 8],
    src: &SocketAddr,
    payload: &[u8],
) -> Vec<u8> {
    let mut sep = [0u8; 16];
    sep[..8].copy_from_slice(&server_sid);
    sep[8..].copy_from_slice(&packet_id.to_be_bytes());
    let mut body = Vec::new();
    body.push(PKT_TYPE_SERVER);
    body.extend_from_slice(&now_secs().to_be_bytes());
    body.extend_from_slice(&client_sid);
    body.extend_from_slice(&0u16.to_be_bytes());
    write_socks_addr(src, &mut body);
    body.extend_from_slice(payload);
    let subkey = session_subkey(method, psk, &server_sid);
    let cipher = Cipher::new(method, &subkey).unwrap();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&sep[4..16]);
    cipher.seal(nonce, &mut body);
    let block = AesBlock::new(psk).unwrap();
    block.encrypt(&mut sep);
    let mut out = sep.to_vec();
    out.extend_from_slice(&body);
    out
}

/// Send half of an SS-2022 UDP association (AES methods).
pub struct ShadowsocksUdpSink {
    socket: Arc<UdpSocket>,
    method: SsMethod,
    psk: Vec<u8>,
    target: SocketAddr,
    session_id: [u8; 8],
    packet_id: u64,
}

impl ShadowsocksUdpSink {
    pub fn new(
        socket: Arc<UdpSocket>,
        method: SsMethod,
        psk: Vec<u8>,
        target: SocketAddr,
        session_id: [u8; 8],
    ) -> Self {
        ShadowsocksUdpSink {
            socket,
            method,
            psk,
            target,
            session_id,
            packet_id: 0,
        }
    }
}

#[async_trait]
impl PacketSink for ShadowsocksUdpSink {
    async fn send(&mut self, payload: &[u8]) -> io::Result<()> {
        let pkt = build_client_packet(
            self.method,
            &self.psk,
            self.session_id,
            self.packet_id,
            &self.target,
            payload,
        )
        .map_err(io::Error::other)?;
        self.packet_id = self.packet_id.wrapping_add(1);
        self.socket.send(&pkt).await.map(|_| ())
    }
}

/// Receive half of an SS-2022 UDP association (AES methods).
///
/// Drops malformed or replayed datagrams and keeps reading so that one bad packet never
/// surfaces as an error to the netstack.
pub struct ShadowsocksUdpSource {
    socket: Arc<UdpSocket>,
    method: SsMethod,
    psk: Vec<u8>,
    client_session_id: [u8; 8],
    windows: HashMap<[u8; 8], ReplayWindow>,
    scratch: Vec<u8>,
}

impl ShadowsocksUdpSource {
    pub fn new(
        socket: Arc<UdpSocket>,
        method: SsMethod,
        psk: Vec<u8>,
        client_session_id: [u8; 8],
    ) -> Self {
        ShadowsocksUdpSource {
            socket,
            method,
            psk,
            client_session_id,
            windows: HashMap::new(),
            scratch: vec![0u8; 64 * 1024], // reused across recvs (one datagram at a time)
        }
    }
}

#[async_trait]
impl PacketSource for ShadowsocksUdpSource {
    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Loop until a valid, non-replayed packet arrives; drop and keep reading otherwise so one
        // bad datagram never surfaces as an error to the netstack.
        loop {
            let n = self.socket.recv(&mut self.scratch).await?;
            let parsed = match parse_server_packet(
                self.method,
                &self.psk,
                self.client_session_id,
                &self.scratch[..n],
            ) {
                Ok(p) => p,
                Err(_) => continue, // malformed / failed auth -> drop
            };
            // Bound the per-server-session window map: a server rotates session IDs rarely (SIP022
            // clients only need the current + one prior), so a much higher cap than that can only be
            // hit by a misbehaving server, and we evict an arbitrary entry rather than grow unbounded.
            if !self.windows.contains_key(&parsed.server_session_id)
                && self.windows.len() >= MAX_SERVER_SESSIONS
            {
                if let Some(victim) = self.windows.keys().next().copied() {
                    self.windows.remove(&victim);
                }
            }
            let window = self.windows.entry(parsed.server_session_id).or_default();
            if !window.accept(parsed.packet_id) {
                continue; // replay / out-of-window -> drop
            }
            let len = parsed.payload.len().min(buf.len());
            buf[..len].copy_from_slice(&parsed.payload[..len]);
            return Ok(len);
        }
    }
}

/// A sliding-window replay filter over u64 packet IDs (SIP022 §3.2.4).
pub struct ReplayWindow {
    highest: u64,
    bitmap: u64, // bit i set => (highest - i) was seen
    seen_any: bool,
}

impl ReplayWindow {
    pub fn new() -> Self {
        ReplayWindow {
            highest: 0,
            bitmap: 0,
            seen_any: false,
        }
    }

    /// Check `id`: returns true if it is fresh (and records it), false if duplicate/out-of-window.
    pub fn accept(&mut self, id: u64) -> bool {
        if !self.seen_any {
            self.seen_any = true;
            self.highest = id;
            self.bitmap = 1; // bit 0 = highest seen
            return true;
        }
        if id > self.highest {
            let shift = id - self.highest;
            self.bitmap = if shift >= 64 { 0 } else { self.bitmap << shift };
            self.bitmap |= 1;
            self.highest = id;
            true
        } else {
            let back = self.highest - id;
            if back >= WINDOW {
                return false; // too old
            }
            let mask = 1u64 << back;
            if self.bitmap & mask != 0 {
                false // already seen
            } else {
                self.bitmap |= mask;
                true
            }
        }
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::super::crypto::{session_subkey, AesBlock, Cipher};
    use super::*;
    use crate::config::SsMethod;
    use crate::transport::{PacketSink, PacketSource};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::net::UdpSocket;

    /// Server-side decrypt of a client packet (mirror of `parse_server_packet` for the client header).
    ///
    /// Client body layout: type(1) | ts(8) | padlen(2) | padding(padlen) | socks-addr | payload.
    fn parse_client_payload(
        method: SsMethod,
        psk: &[u8],
        expect_sid: [u8; 8],
        pkt: &[u8],
    ) -> Vec<u8> {
        let block = AesBlock::new(psk).unwrap();
        let mut sep = [0u8; 16];
        sep.copy_from_slice(&pkt[..16]);
        block.decrypt(&mut sep);
        assert_eq!(&sep[..8], &expect_sid);
        let cipher = Cipher::new(method, &session_subkey(method, psk, &sep[..8])).unwrap();
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&sep[4..16]);
        let mut body = pkt[16..].to_vec();
        let plain = cipher.open(nonce, &mut body).unwrap().to_vec();
        // body: type(1) ts(8) padlen(2) padding(padlen) socks-addr payload
        // padlen field is at offset 9 (after type + 8-byte ts), 0 for our sink
        let pad_len = u16::from_be_bytes([plain[9], plain[10]]) as usize;
        let addr_off = 11 + pad_len;
        let (_a, consumed) = read_socks_addr(&plain[addr_off..]).unwrap();
        plain[addr_off + consumed..].to_vec()
    }

    #[tokio::test]
    async fn udp_halves_round_trip_over_loopback() {
        let method = SsMethod::Aes256Gcm;
        let psk = vec![5u8; 32];
        let target: SocketAddr = "8.8.8.8:53".parse().unwrap();

        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(server_addr).await.unwrap();
        let client = Arc::new(client);

        let session_id = [7u8; 8];
        let mut sink =
            ShadowsocksUdpSink::new(Arc::clone(&client), method, psk.clone(), target, session_id);
        let mut source =
            ShadowsocksUdpSource::new(Arc::clone(&client), method, psk.clone(), session_id);

        sink.send(b"ping").await.unwrap();

        let mut rbuf = [0u8; 2048];
        let (n, from) = server.recv_from(&mut rbuf).await.unwrap();
        assert_eq!(
            parse_client_payload(method, &psk, session_id, &rbuf[..n]),
            b"ping"
        );
        let reply =
            build_server_packet_for_test(method, &psk, [8u8; 8], 0, session_id, &target, b"pong");
        server.send_to(&reply, from).await.unwrap();

        let mut buf = [0u8; 2048];
        let n = source.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"pong");
    }

    #[test]
    fn client_packet_parses_as_a_server_would() {
        let method = SsMethod::Aes256Gcm;
        let psk = vec![5u8; 32];
        let target: SocketAddr = "1.2.3.4:53".parse().unwrap();
        let session_id = [1u8; 8];

        let pkt = build_client_packet(method, &psk, session_id, 0, &target, b"query").unwrap();

        // Server side: AES-ECB-decrypt the header, derive subkey, AES-GCM-open the body.
        let block = AesBlock::new(&psk).unwrap();
        let mut sep = [0u8; 16];
        sep.copy_from_slice(&pkt[..16]);
        block.decrypt(&mut sep);
        assert_eq!(&sep[..8], &session_id);
        let subkey = session_subkey(method, &psk, &sep[..8]);
        let cipher = Cipher::new(method, &subkey).unwrap();
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&sep[4..16]);
        let mut body = pkt[16..].to_vec();
        let body = cipher.open(nonce, &mut body).unwrap();
        assert_eq!(body[0], 0); // client packet type
    }

    #[test]
    fn parse_server_packet_round_trips() {
        let method = SsMethod::Aes256Gcm;
        let psk = vec![5u8; 32];
        let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let client_sid = [2u8; 8];
        let server_sid = [3u8; 8];

        let pkt = build_server_packet_for_test(
            method, &psk, server_sid, 0, client_sid, &target, b"answer",
        );
        let parsed = parse_server_packet(method, &psk, client_sid, &pkt).unwrap();
        assert_eq!(parsed.payload, b"answer");
        assert_eq!(parsed.server_session_id, server_sid);
        assert_eq!(parsed.packet_id, 0);
    }

    #[test]
    fn parse_server_packet_rejects_wrong_client_sid() {
        let method = SsMethod::Aes256Gcm;
        let psk = vec![5u8; 32];
        let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let pkt =
            build_server_packet_for_test(method, &psk, [3u8; 8], 0, [2u8; 8], &target, b"answer");
        // A response addressed to a different client session is rejected.
        assert!(parse_server_packet(method, &psk, [9u8; 8], &pkt).is_err());
    }

    #[test]
    fn parse_server_packet_rejects_truncated_and_tampered() {
        let method = SsMethod::Aes256Gcm;
        let psk = vec![5u8; 32];
        let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let client_sid = [2u8; 8];
        // Too short to hold a header + tag.
        assert!(parse_server_packet(method, &psk, client_sid, &[0u8; 8]).is_err());
        // Flipping a body byte fails AEAD authentication.
        let mut pkt =
            build_server_packet_for_test(method, &psk, [3u8; 8], 0, client_sid, &target, b"answer");
        let last = pkt.len() - 1;
        pkt[last] ^= 0xff;
        assert!(parse_server_packet(method, &psk, client_sid, &pkt).is_err());
    }

    #[test]
    fn window_accepts_in_order_and_rejects_replays() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(0));
        assert!(w.accept(1));
        assert!(w.accept(2));
        assert!(!w.accept(1)); // replay
        assert!(w.accept(100)); // jump forward
        assert!(!w.accept(100)); // replay of the new max
        assert!(w.accept(99)); // within window, not yet seen
        assert!(!w.accept(0)); // far behind the window now -> rejected
    }

    #[test]
    fn window_exact_boundaries() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(100));
        assert!(w.accept(37)); // back == 63: oldest acceptable
        assert!(!w.accept(36)); // back == 64: first rejected
        assert!(w.accept(164)); // shift == 64: window fully clears, new highest marked
        assert!(!w.accept(100)); // back == 64 from the new highest -> rejected
        assert!(w.accept(163)); // back == 1: not yet seen -> accepted
    }
}
