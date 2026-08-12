//! SS-2022 UDP: native packet build/parse + sliding-window replay filter.

use std::collections::HashMap;
use std::io;
// Test-only: the server→client packet builder echoes a real source IP, which is never a domain.
#[cfg(test)]
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use ring::rand::{SecureRandom, SystemRandom};
use tokio::net::UdpSocket;

use crate::config::SsMethod;
use crate::transport::{PacketSink, PacketSource};

use super::crypto::{session_subkey, AesBlock, Cipher, CryptoError, XChaCha};
#[cfg(test)]
use super::write_socks_addr;
use super::{now_secs, read_socks_addr, write_socks_target};
use crate::transport::Address;

const PKT_TYPE_CLIENT: u8 = 0;
const PKT_TYPE_SERVER: u8 = 1;
const MAX_SKEW_SECS: u64 = 30;
const TAG: usize = 16;

/// Size of the replay window (bits behind the highest accepted packet ID).
const WINDOW: u64 = 64;

/// Cap on tracked server sessions per UDP association (bounds memory against session-ID rotation).
const MAX_SERVER_SESSIONS: usize = 8;

/// Build a client→server UDP packet from pre-built primitives (no per-call key derivation).
fn build_client_packet_with(
    block: &AesBlock,
    cipher: &Cipher,
    session_id: [u8; 8],
    packet_id: u64,
    target: &Address,
    payload: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut sep = [0u8; 16];
    sep[..8].copy_from_slice(&session_id);
    sep[8..].copy_from_slice(&packet_id.to_be_bytes());

    let mut body = Vec::with_capacity(1 + 8 + 2 + 19 + payload.len() + TAG);
    body.push(PKT_TYPE_CLIENT);
    body.extend_from_slice(&now_secs().to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes()); // no padding for connected single-target flows
                                                 // The same SOCKS5 address format the TCP path already writes, and the reason a domain can
                                                 // ride here at all: SIP022 §3.1.3 puts a full SOCKS5 address in the datagram, so ATYP 3 is
                                                 // legal on the wire. Only spark's own plumbing was IP-only.
    write_socks_target(target, &mut body);
    body.extend_from_slice(payload);

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&sep[4..16]);
    cipher.seal(nonce, &mut body)?;

    block.encrypt(&mut sep);
    let mut out = Vec::with_capacity(16 + body.len());
    out.extend_from_slice(&sep);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Nonce length of the chacha UDP envelope (SIP022 §3.2.2); XChaCha20-Poly1305 takes 24 bytes.
const PACKET_NONCE: usize = 24;

/// Build a client→server UDP packet for `2022-blake3-chacha20-poly1305`.
///
/// A different frame from the AES one, not the same frame with another cipher: a random 24-byte
/// nonce goes out in the clear, and **everything after it** — session id and packet id included —
/// is sealed with XChaCha20-Poly1305 under the PSK. There is no separate header to block-encrypt
/// and no per-session subkey, which is why this cannot reuse `build_client_packet_with`.
///
/// Cross-checked field-by-field against `sing-shadowsocks`'
/// `clientPacketConn.WritePacket` (v0.2.8, the version the fleet runs): nonce, then session id,
/// packet id, header type, timestamp, padding length, address, payload.
fn build_client_packet_chacha(
    x: &XChaCha,
    session_id: [u8; 8],
    packet_id: u64,
    target: &Address,
    payload: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut nonce = [0u8; PACKET_NONCE];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| CryptoError::Rng)?;

    let mut body = Vec::with_capacity(8 + 8 + 1 + 8 + 2 + 19 + payload.len() + TAG);
    body.extend_from_slice(&session_id);
    body.extend_from_slice(&packet_id.to_be_bytes());
    body.push(PKT_TYPE_CLIENT);
    body.extend_from_slice(&now_secs().to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes()); // no padding for connected single-target flows
    write_socks_target(target, &mut body);
    body.extend_from_slice(payload);

    x.seal(&nonce, &mut body)?;
    let mut out = Vec::with_capacity(PACKET_NONCE + body.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Open a server→client chacha UDP packet, returning `(server_session_id, packet_id, payload)`.
///
/// Unlike the AES path there is nothing to authenticate *after* a cheap unauthenticated peek: the
/// session id only becomes readable once the whole packet has been opened, so a forged datagram is
/// rejected by the AEAD before any of its fields exist. The caller still advances the replay window
/// only after this returns.
fn open_server_packet_chacha(
    x: &XChaCha,
    pkt: &[u8],
    expected_client_sid: [u8; 8],
) -> Result<([u8; 8], u64, Vec<u8>), CryptoError> {
    if pkt.len() < PACKET_NONCE + TAG {
        return Err(CryptoError::Auth);
    }
    let nonce: [u8; PACKET_NONCE] = pkt[..PACKET_NONCE]
        .try_into()
        .map_err(|_| CryptoError::Auth)?;
    let mut body = pkt[PACKET_NONCE..].to_vec();
    let plain_len = x.open(&nonce, &mut body)?.len();
    body.truncate(plain_len);

    // Session id and packet id lead the plaintext here; the rest is the same header the AES path
    // parses, so hand the tail to the shared validator rather than duplicating it.
    let sid: [u8; 8] = body
        .get(..8)
        .ok_or(CryptoError::Auth)?
        .try_into()
        .map_err(|_| CryptoError::Auth)?;
    let pid = u64::from_be_bytes(
        body.get(8..16)
            .ok_or(CryptoError::Auth)?
            .try_into()
            .map_err(|_| CryptoError::Auth)?,
    );
    let payload = parse_server_header(
        body.get(16..).ok_or(CryptoError::Auth)?,
        expected_client_sid,
    )?;
    Ok((sid, pid, payload))
}

/// Build a client→server UDP packet (AES methods only). Convenience wrapper that builds the
/// primitives then delegates — used by tests / one-off callers. The hot send path goes through
/// `build_client_packet_with` with cached primitives, so this has no non-test caller in the lib.
#[cfg(test)]
pub fn build_client_packet(
    method: SsMethod,
    psk: &[u8],
    session_id: [u8; 8],
    packet_id: u64,
    target: &Address,
    payload: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let block = AesBlock::new(psk)?;
    let cipher = Cipher::new(method, &session_subkey(method, psk, &session_id))?;
    build_client_packet_with(&block, &cipher, session_id, packet_id, target, payload)
}

/// A parsed server→client UDP packet. Produced by the `parse_server_packet` convenience wrapper
/// (tests / one-off); the hot recv path uses the `decrypt_separate_header` + `open_server_body`
/// helpers directly and never materializes this struct.
#[cfg(test)]
pub struct ServerPacket {
    pub server_session_id: [u8; 8],
    pub packet_id: u64,
    pub payload: Vec<u8>,
}

/// Decrypt the 16-byte separate header with the PSK-keyed block cipher. Returns
/// (server_session_id, packet_id, the decrypted 16-byte header — its [4..16] is the AEAD nonce).
fn decrypt_separate_header(
    block: &AesBlock,
    pkt: &[u8],
) -> Result<([u8; 8], u64, [u8; 16]), CryptoError> {
    if pkt.len() < 16 + TAG {
        return Err(CryptoError::Auth);
    }
    let mut sep = [0u8; 16];
    sep.copy_from_slice(&pkt[..16]);
    block.decrypt(&mut sep);
    let sid: [u8; 8] = sep[..8].try_into().map_err(|_| CryptoError::Auth)?;
    let pid = u64::from_be_bytes(sep[8..].try_into().map_err(|_| CryptoError::Auth)?);
    Ok((sid, pid, sep))
}

/// Open the AEAD body with the session cipher and validate the server main header; return the payload.
/// `enc_body` is the bytes AFTER the 16-byte separate header; `sep` is the decrypted separate header.
fn open_server_body(
    cipher: &Cipher,
    sep: &[u8; 16],
    enc_body: &[u8],
    expected_client_sid: [u8; 8],
) -> Result<Vec<u8>, CryptoError> {
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&sep[4..16]);
    let mut body = enc_body.to_vec();
    let plain_len = cipher.open(nonce, &mut body)?.len(); // decrypts in place; trailing 16 bytes = tag
    body.truncate(plain_len);
    parse_server_header(&body, expected_client_sid)
}

/// Validate the server main header and return the payload.
///
/// Shared by both UDP envelopes because the header itself is identical between them — only the
/// encryption differs (AES seals it under a session subkey behind a separate header; chacha seals it
/// under the PSK behind a cleartext nonce). The chacha caller strips the leading session id ‖ packet
/// id first, since those live inside its ciphertext rather than in a separate header.
fn parse_server_header(body: &[u8], expected_client_sid: [u8; 8]) -> Result<Vec<u8>, CryptoError> {
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
    Ok(payload)
}

/// Parse and validate a server→client UDP packet (AES methods only). Does NOT advance any replay
/// window — the caller does that after this returns Ok (so invalid packets don't poison the window).
/// Convenience wrapper (tests / one-off) that builds the primitives then delegates. The hot recv
/// path uses the cached-primitive helpers directly, so this has no non-test caller in the lib.
#[cfg(test)]
pub fn parse_server_packet(
    method: SsMethod,
    psk: &[u8],
    expected_client_sid: [u8; 8],
    pkt: &[u8],
) -> Result<ServerPacket, CryptoError> {
    let block = AesBlock::new(psk)?;
    let (server_session_id, packet_id, sep) = decrypt_separate_header(&block, pkt)?;
    let cipher = Cipher::new(method, &session_subkey(method, psk, &server_session_id))?;
    let payload = open_server_body(&cipher, &sep, &pkt[16..], expected_client_sid)?;
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
    cipher.seal(nonce, &mut body).unwrap();
    let block = AesBlock::new(psk).unwrap();
    block.encrypt(&mut sep);
    let mut out = sep.to_vec();
    out.extend_from_slice(&body);
    out
}

/// Send half of an SS-2022 UDP association (AES methods).
/// The send-side UDP envelope. Two frames, not two ciphers — see [`XChaCha`].
enum SinkSeal {
    /// AES: PSK-keyed block cipher over the separate header, session-subkey AEAD over the body.
    Aes {
        block: Box<AesBlock>,
        cipher: Box<Cipher>,
    },
    /// Chacha: cleartext nonce, PSK-keyed XChaCha20-Poly1305 over everything after it.
    XChaCha(XChaCha),
}

pub struct ShadowsocksUdpSink {
    socket: Arc<UdpSocket>,
    target: Address,
    session_id: [u8; 8],
    packet_id: u64,
    seal: SinkSeal,
}

impl ShadowsocksUdpSink {
    pub fn new(
        socket: Arc<UdpSocket>,
        method: SsMethod,
        psk: &[u8],
        target: Address,
        session_id: [u8; 8],
    ) -> Result<Self, CryptoError> {
        let seal = match method {
            SsMethod::Chacha20Poly1305 => SinkSeal::XChaCha(XChaCha::new(psk)?),
            _ => SinkSeal::Aes {
                block: Box::new(AesBlock::new(psk)?),
                cipher: Box::new(Cipher::new(
                    method,
                    &session_subkey(method, psk, &session_id),
                )?),
            },
        };
        Ok(ShadowsocksUdpSink {
            socket,
            target,
            session_id,
            packet_id: 0,
            seal,
        })
    }
}

#[async_trait]
impl PacketSink for ShadowsocksUdpSink {
    async fn send(&mut self, payload: &[u8]) -> io::Result<()> {
        let pkt = match &self.seal {
            SinkSeal::Aes { block, cipher } => build_client_packet_with(
                block,
                cipher,
                self.session_id,
                self.packet_id,
                &self.target,
                payload,
            ),
            SinkSeal::XChaCha(x) => build_client_packet_chacha(
                x,
                self.session_id,
                self.packet_id,
                &self.target,
                payload,
            ),
        }
        .map_err(io::Error::other)?;
        self.packet_id = self.packet_id.wrapping_add(1);
        self.socket.send(&pkt).await.map(|_| ())
    }
}

/// Per-server-session state: the replay window plus the session-keyed AEAD (derived once on
/// first sight of the server session ID, then reused for every datagram in that session).
struct SessionState {
    window: ReplayWindow,
    /// `None` for the chacha envelope, which opens every packet with the source's own
    /// PSK-keyed key — there is no per-server-session subkey to cache.
    cipher: Option<Cipher>,
}

/// Receive half of an SS-2022 UDP association (AES methods).
///
/// Drops malformed or replayed datagrams and keeps reading so that one bad packet never
/// surfaces as an error to the netstack.
/// The receive-side UDP envelope. AES derives a fresh cipher per server session id; chacha opens
/// every packet with the one PSK-keyed key, so it needs no per-session material at all.
enum SourceSeal {
    Aes {
        method: SsMethod,
        psk: Vec<u8>,
        block: AesBlock,
    },
    XChaCha(XChaCha),
}

pub struct ShadowsocksUdpSource {
    socket: Arc<UdpSocket>,
    client_session_id: [u8; 8],
    seal: SourceSeal,
    sessions: HashMap<[u8; 8], SessionState>,
    scratch: Vec<u8>,
}

impl ShadowsocksUdpSource {
    pub fn new(
        socket: Arc<UdpSocket>,
        method: SsMethod,
        psk: Vec<u8>,
        client_session_id: [u8; 8],
    ) -> Result<Self, CryptoError> {
        let seal = match method {
            SsMethod::Chacha20Poly1305 => SourceSeal::XChaCha(XChaCha::new(&psk)?),
            _ => SourceSeal::Aes {
                block: AesBlock::new(&psk)?,
                method,
                psk,
            },
        };
        Ok(ShadowsocksUdpSource {
            socket,
            client_session_id,
            seal,
            sessions: HashMap::new(),
            scratch: vec![0u8; 64 * 1024], // reused across recvs (one datagram at a time)
        })
    }
}

#[async_trait]
impl PacketSource for ShadowsocksUdpSource {
    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Loop until a valid, non-replayed packet arrives; drop and keep reading otherwise so one
        // bad datagram never surfaces as an error to the netstack.
        loop {
            let n = self.socket.recv(&mut self.scratch).await?;

            // Chacha first: its AEAD covers the whole datagram, so the session id is unreadable
            // until the packet has already authenticated. The ordering hazard the AES path below
            // guards against — acting on an attacker-influenceable `sid` — cannot arise here.
            if let SourceSeal::XChaCha(x) = &self.seal {
                let (sid, pid, payload) = match open_server_packet_chacha(
                    x,
                    &self.scratch[..n],
                    self.client_session_id,
                ) {
                    Ok(v) => v,
                    Err(_) => continue, // malformed / forged / bad header -> drop
                };
                match self.sessions.get_mut(&sid) {
                    Some(st) => {
                        if !st.window.accept(pid) {
                            continue; // replay / out-of-window -> drop
                        }
                    }
                    // Same capacity rule as the AES path, for the same reason (SIP022 §3.2.4).
                    None => {
                        if self.sessions.len() >= MAX_SERVER_SESSIONS {
                            continue;
                        }
                        let mut window = ReplayWindow::new();
                        window.accept(pid);
                        self.sessions.insert(
                            sid,
                            SessionState {
                                window,
                                cipher: None,
                            },
                        );
                    }
                }
                let len = payload.len().min(buf.len());
                buf[..len].copy_from_slice(&payload[..len]);
                return Ok(len);
            }
            // Everything below is the AES envelope. The `continue` is unreachable — the branch above
            // returns for the only other variant — and is used rather than a panic to keep this
            // loop's no-panic contract; it costs one extra `recv` in a state that cannot occur.
            let SourceSeal::Aes { method, psk, block } = &self.seal else {
                continue;
            };
            // The separate header is only AES-ECB-decrypted here — keyed but UNAUTHENTICATED, so `sid`
            // is attacker-influenceable (a spoofed datagram on the server's 4-tuple decrypts to some
            // pseudo-random sid). We therefore authenticate the AEAD body BEFORE mutating any session
            // state, so a forged packet can never create/evict a tracked replay window.
            let (sid, pid, sep) = match decrypt_separate_header(block, &self.scratch[..n]) {
                Ok(v) => v,
                Err(_) => continue, // malformed -> drop
            };
            let enc_body = &self.scratch[16..n];

            // Fast path: an already-tracked server session — open with its cached cipher.
            if let Some(st) = self.sessions.get_mut(&sid) {
                let Some(cached) = st.cipher.as_ref() else {
                    continue; // an AES session always caches its cipher; nothing to open with
                };
                let payload = match open_server_body(cached, &sep, enc_body, self.client_session_id)
                {
                    Ok(p) => p,
                    Err(_) => continue, // failed auth / bad header -> drop, window untouched
                };
                if !st.window.accept(pid) {
                    continue; // replay / out-of-window -> drop
                }
                let len = payload.len().min(buf.len());
                buf[..len].copy_from_slice(&payload[..len]);
                return Ok(len);
            }

            // New server session id: derive a cipher and AUTHENTICATE before touching the map.
            let cipher = match Cipher::new(*method, &session_subkey(*method, psk, &sid)) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let payload = match open_server_body(&cipher, &sep, enc_body, self.client_session_id) {
                Ok(p) => p,
                Err(_) => continue, // forged / unauthenticated -> drop, NO map mutation
            };
            // Authentic packet from a new server session. Refuse to start tracking once at capacity
            // rather than evicting an active window — evicting then accepting a reused id would reset
            // replay state (SIP022 §3.2.4). The cap is far above the current+prior a real server needs,
            // so this only bites a misbehaving server, which is itself the trust root here.
            if self.sessions.len() >= MAX_SERVER_SESSIONS {
                continue;
            }
            let mut window = ReplayWindow::new();
            window.accept(pid); // first packet of a fresh window — always fresh
            self.sessions.insert(
                sid,
                SessionState {
                    window,
                    cipher: Some(cipher),
                },
            );
            let len = payload.len().min(buf.len());
            buf[..len].copy_from_slice(&payload[..len]);
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
        let mut sink = ShadowsocksUdpSink::new(
            Arc::clone(&client),
            method,
            &psk,
            Address::Ip(target),
            session_id,
        )
        .unwrap();
        let mut source =
            ShadowsocksUdpSource::new(Arc::clone(&client), method, psk.clone(), session_id)
                .unwrap();

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

    #[tokio::test]
    async fn source_refuses_over_cap_sessions_instead_of_evicting() {
        // Once the per-association session map is full, an additional authentic server session must be
        // dropped — NOT accepted by evicting an active window (which would reset that window's replay
        // state). Authentication also happens before any map mutation, so this can't be driven by
        // forged packets. With the old arbitrary-eviction code this over-cap packet would be delivered.
        let method = SsMethod::Aes256Gcm;
        let psk = vec![5u8; 32];
        let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let client_sid = [1u8; 8];

        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(server_addr).await.unwrap();
        let client = Arc::new(client);
        let client_addr = client.local_addr().unwrap();
        let mut source =
            ShadowsocksUdpSource::new(Arc::clone(&client), method, psk.clone(), client_sid)
                .unwrap();

        // Fill the cap with distinct, authentic server sessions.
        for i in 0..MAX_SERVER_SESSIONS as u8 {
            let pkt =
                build_server_packet_for_test(method, &psk, [i; 8], 0, client_sid, &target, b"ok");
            server.send_to(&pkt, client_addr).await.unwrap();
            let mut buf = [0u8; 64];
            let n = source.recv(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"ok");
        }

        // A new (over-cap) authentic session must be refused — recv should time out, not deliver it.
        let over =
            build_server_packet_for_test(method, &psk, [0xAA; 8], 0, client_sid, &target, b"over");
        server.send_to(&over, client_addr).await.unwrap();
        let mut buf = [0u8; 64];
        let r = tokio::time::timeout(std::time::Duration::from_millis(300), source.recv(&mut buf))
            .await;
        assert!(
            r.is_err(),
            "over-cap session must be refused, not delivered by eviction"
        );
    }

    /// A domain target reaches the wire as SOCKS5 ATYP 3, so the **server** resolves it.
    ///
    /// SIP022 §3.1.3 always allowed this — the TCP path has carried domains since it was written,
    /// while UDP was IP-only, which left the forwarder resolving client-side for proxied UDP flows.
    /// The chacha envelope is a different frame, so assert its bytes rather than trusting symmetry
    /// with the AES one: cleartext 24-byte nonce, then a PSK-keyed XChaCha20-Poly1305 seal whose
    /// plaintext opens with session id ‖ packet id ‖ type ‖ timestamp ‖ padding_len ‖ ATYP.
    ///
    /// Decrypted here the way `sing-shadowsocks` does it — one `udpCipher.Open` over everything past
    /// the nonce, with no separate header and no session subkey — so a frame that merely round-trips
    /// against our own builder cannot pass.
    #[test]
    fn the_chacha_envelope_puts_a_cleartext_nonce_then_seals_everything_else() {
        let psk = vec![5u8; 32];
        let x = XChaCha::new(&psk).expect("psk");
        let session_id = [7u8; 8];
        let host = "example.com";
        let pkt = build_client_packet_chacha(
            &x,
            session_id,
            42,
            &Address::domain(host, 443).expect("domain"),
            b"hello",
        )
        .expect("build");

        assert!(pkt.len() > PACKET_NONCE + TAG);
        // The nonce is in the clear; the rest must not be.
        let nonce: [u8; 24] = pkt[..24].try_into().unwrap();
        assert!(
            !pkt[24..].windows(host.len()).any(|w| w == host.as_bytes()),
            "the hostname must not appear outside the seal"
        );

        let mut body = pkt[PACKET_NONCE..].to_vec();
        let plain = x
            .open(&nonce, &mut body)
            .expect("server-side open")
            .to_vec();

        assert_eq!(&plain[..8], &session_id, "session id leads the ciphertext");
        assert_eq!(
            u64::from_be_bytes(plain[8..16].try_into().unwrap()),
            42,
            "packet id follows it"
        );
        assert_eq!(plain[16], PKT_TYPE_CLIENT, "then the header type");
        // session(8) ‖ packet(8) ‖ type(1) ‖ time(8) ‖ padding_len(2) ‖ ATYP
        let atyp_at = 8 + 8 + 1 + 8 + 2;
        assert_eq!(plain[atyp_at], 3, "ATYP 3 = domain");
        assert_eq!(plain[atyp_at + 1] as usize, host.len(), "length byte");
        assert_eq!(
            &plain[atyp_at + 2..atyp_at + 2 + host.len()],
            host.as_bytes(),
            "the exit receives the name, not an address we resolved"
        );
        let payload_at = atyp_at + 2 + host.len() + 2; // + port
        assert_eq!(&plain[payload_at..], b"hello");
    }

    /// A tampered byte anywhere past the nonce must fail authentication rather than parse.
    #[test]
    fn the_chacha_envelope_rejects_a_tampered_packet() {
        let x = XChaCha::new(&[5u8; 32]).unwrap();
        let pkt = build_client_packet_chacha(
            &x,
            [7u8; 8],
            1,
            &Address::domain("example.com", 443).unwrap(),
            b"hi",
        )
        .unwrap();
        let nonce: [u8; 24] = pkt[..24].try_into().unwrap();
        let mut body = pkt[PACKET_NONCE..].to_vec();
        body[0] ^= 1;
        assert!(x.open(&nonce, &mut body).is_err());
    }

    /// This asserts the encoded bytes, not just that the call compiles.
    #[test]
    fn a_domain_target_is_encoded_as_atyp3_in_the_datagram() {
        let method = SsMethod::Aes256Gcm;
        let psk = vec![9u8; 32];
        let session_id = [3u8; 8];
        let host = "example.com";
        let pkt = build_client_packet(
            method,
            &psk,
            session_id,
            0,
            &Address::domain(host, 443).expect("domain"),
            b"q",
        )
        .expect("build");

        // Decrypt the way the server does: AES-ECB the separate header, then AEAD-open the body.
        let block = AesBlock::new(&psk).unwrap();
        let mut sep = [0u8; 16];
        sep.copy_from_slice(&pkt[..16]);
        block.decrypt(&mut sep);
        let cipher = Cipher::new(method, &session_subkey(method, &psk, &sep[..8])).unwrap();
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&sep[4..16]);
        let mut buf = pkt[16..].to_vec();
        let body = cipher.open(nonce, &mut buf).expect("open");

        // type(1) ‖ time(8) ‖ padding_len(2) ‖ ATYP ...
        let atyp_at = 1 + 8 + 2;
        assert_eq!(
            body[atyp_at],
            0x03,
            "a domain must be ATYP 3, not a client-resolved IP: {:?}",
            &body[..atyp_at + 4]
        );
        assert_eq!(body[atyp_at + 1] as usize, host.len(), "domain length byte");
        assert_eq!(
            &body[atyp_at + 2..atyp_at + 2 + host.len()],
            host.as_bytes(),
            "the hostname itself must be on the wire"
        );
    }

    #[test]
    fn client_packet_parses_as_a_server_would() {
        let method = SsMethod::Aes256Gcm;
        let psk = vec![5u8; 32];
        let target: SocketAddr = "1.2.3.4:53".parse().unwrap();
        let session_id = [1u8; 8];

        let pkt = build_client_packet(method, &psk, session_id, 0, &Address::Ip(target), b"query")
            .unwrap();

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
