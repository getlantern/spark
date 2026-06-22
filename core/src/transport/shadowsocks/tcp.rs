//! SS-2022 TCP: request/response codec + the AsyncRead+AsyncWrite chunk-framing stream.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BytesMut};
use ring::rand::{SecureRandom, SystemRandom};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::config::SsMethod;

use super::crypto::{session_subkey, Cipher, CryptoError, NonceCounter};
use super::{now_secs, write_socks_addr};

const HEADER_TYPE_CLIENT: u8 = 0;

/// The encoded request prefix plus the salt and the send-side cipher/counter the stream keeps using.
pub struct Request {
    pub bytes: Vec<u8>,
    pub salt: Vec<u8>,
    pub cipher: Cipher,
    pub counter: NonceCounter,
}

/// Build the SS-2022 request prefix: `salt ‖ enc[fixed header] ‖ enc[variable header]`.
///
/// Fixed header (11 bytes plaintext): `type(0) ‖ timestamp(u64be) ‖ length(u16be of variable header)`.
/// Variable header: `SOCKS addr ‖ padding_len(u16be) ‖ padding` (1–64 random bytes of padding).
pub fn encode_request(
    method: SsMethod,
    psk: &[u8],
    target: &SocketAddr,
) -> Result<Request, CryptoError> {
    let rng = SystemRandom::new();

    // Generate a fresh random salt for this session.
    let mut salt = vec![0u8; method.salt_len()];
    rng.fill(&mut salt).map_err(|_| CryptoError::Rng)?;
    let subkey = session_subkey(method, psk, &salt);
    let cipher = Cipher::new(method, &subkey)?;
    let mut counter = NonceCounter::new();

    // Variable-length header plaintext: SOCKS addr ‖ padding_len(u16be) ‖ padding.
    let mut var = Vec::with_capacity(19 + 2 + 64); // max IPv6 SOCKS addr + pad_len field + max padding
    write_socks_addr(target, &mut var);
    let mut pad_byte = [0u8; 1];
    rng.fill(&mut pad_byte).map_err(|_| CryptoError::Rng)?;
    let pad_len = (pad_byte[0] % 64) as u16 + 1; // 1..=64
    var.extend_from_slice(&pad_len.to_be_bytes());
    let mut padding = vec![0u8; pad_len as usize];
    rng.fill(&mut padding).map_err(|_| CryptoError::Rng)?;
    var.extend_from_slice(&padding);

    // Fixed-length header plaintext (11 bytes): type ‖ timestamp(u64be) ‖ var_len(u16be).
    let mut fixed = Vec::with_capacity(11);
    fixed.push(HEADER_TYPE_CLIENT);
    fixed.extend_from_slice(&now_secs().to_be_bytes());
    fixed.extend_from_slice(&(var.len() as u16).to_be_bytes());

    // Assemble: salt ‖ enc[fixed] ‖ enc[var]  (each AEAD chunk appends a 16-byte tag).
    let mut bytes = Vec::with_capacity(salt.len() + fixed.len() + 16 + var.len() + 16);
    bytes.extend_from_slice(&salt);
    cipher.seal(counter.next(), &mut fixed)?;
    bytes.extend_from_slice(&fixed);
    cipher.seal(counter.next(), &mut var)?;
    bytes.extend_from_slice(&var);

    Ok(Request {
        bytes,
        salt,
        cipher,
        counter,
    })
}

/// Decoded response head: the response-side cipher/counter (for subsequent chunks) and the length of
/// the first payload chunk (the fixed header doubles as the first length chunk).
pub struct ResponseHead {
    pub cipher: Cipher,
    pub counter: NonceCounter,
    pub first_chunk_len: usize,
}

/// Maximum tolerated clock skew on a timestamp (SIP022 §3.1.3).
const MAX_SKEW_SECS: u64 = 30;
const HEADER_TYPE_SERVER: u8 = 1;

/// The number of `salt ‖ enc[fixed header]` bytes for a response (`salt + 1 + 8 + salt + 2 + 16`).
pub fn response_head_len(method: SsMethod) -> usize {
    let sl = method.salt_len();
    sl + (1 + 8 + sl + 2) + 16
}

/// Parse and validate the response head from `wire` (at least `response_head_len(method)` bytes).
pub fn decode_response_head(
    method: SsMethod,
    psk: &[u8],
    request_salt: &[u8],
    wire: &[u8],
) -> Result<ResponseHead, CryptoError> {
    let sl = method.salt_len();
    if wire.len() < response_head_len(method) {
        return Err(CryptoError::Auth); // too short to be a valid head
    }
    let resp_salt = &wire[..sl];
    let subkey = session_subkey(method, psk, resp_salt);
    let cipher = Cipher::new(method, &subkey)?;
    let mut counter = NonceCounter::new();

    let mut fixed_buf = wire[sl..sl + (1 + 8 + sl + 2) + 16].to_vec();
    let fixed = cipher.open(counter.next(), &mut fixed_buf)?;

    if fixed[0] != HEADER_TYPE_SERVER {
        return Err(CryptoError::Auth);
    }
    let ts = u64::from_be_bytes(fixed[1..9].try_into().map_err(|_| CryptoError::Auth)?);
    let now = now_secs();
    if now.abs_diff(ts) > MAX_SKEW_SECS {
        return Err(CryptoError::Auth);
    }
    if &fixed[9..9 + sl] != request_salt {
        return Err(CryptoError::Auth);
    }
    let len_off = 9 + sl;
    let first_chunk_len = u16::from_be_bytes(
        fixed[len_off..len_off + 2]
            .try_into()
            .map_err(|_| CryptoError::Auth)?,
    ) as usize;

    Ok(ResponseHead {
        cipher,
        counter,
        first_chunk_len,
    })
}

/// The largest plaintext payload per chunk (SIP022 §3.1.2 raised the cap to 0xFFFF).
const MAX_PAYLOAD: usize = 0xFFFF;
const TAG: usize = 16;

/// Read-side state machine over the encrypted chunk stream.
#[allow(clippy::enum_variant_names)] // the shared `Need` prefix reads as intent: each is a wait state
enum RxState {
    NeedHead,
    NeedLen,
    NeedPayload { plain: usize },
}

/// An SS-2022 TCP stream: a transparent `AsyncRead+AsyncWrite` over the encrypted chunk framing.
pub struct ShadowsocksStream<S> {
    inner: S,
    method: SsMethod,
    psk: Vec<u8>,
    tx: Cipher,
    tx_ctr: NonceCounter,
    tx_pending: BytesMut,
    rx: Option<ResponseHead>,
    rx_state: RxState,
    rx_raw: BytesMut,
    rx_plain: BytesMut,
    request_salt: Vec<u8>,
}

impl<S> ShadowsocksStream<S> {
    /// Wrap `inner` after the request prefix in `req` has been (or will be) written. Takes ownership
    /// of the send-side cipher/counter from `req`.
    pub fn new(inner: S, method: SsMethod, psk: Vec<u8>, req: Request) -> Self {
        let mut tx_pending = BytesMut::with_capacity(req.bytes.len());
        tx_pending.extend_from_slice(&req.bytes);
        ShadowsocksStream {
            inner,
            method,
            psk,
            tx: req.cipher,
            tx_ctr: req.counter,
            tx_pending,
            rx: None,
            rx_state: RxState::NeedHead,
            rx_raw: BytesMut::with_capacity(16 * 1024),
            rx_plain: BytesMut::with_capacity(16 * 1024),
            request_salt: req.salt,
        }
    }
}

impl<S: AsyncRead + Unpin> ShadowsocksStream<S> {
    /// Pull at least `want` raw bytes into `rx_raw`. `Ok(true)` = have them; `Ok(false)` = EOF.
    fn fill_raw(&mut self, cx: &mut Context<'_>, want: usize) -> Poll<io::Result<bool>> {
        while self.rx_raw.len() < want {
            let mut tmp = [0u8; 16 * 1024];
            let mut rb = ReadBuf::new(&mut tmp);
            match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    let n = rb.filled().len();
                    if n == 0 {
                        return Poll::Ready(Ok(false));
                    }
                    self.rx_raw.extend_from_slice(rb.filled());
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(true))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ShadowsocksStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        loop {
            if !me.rx_plain.is_empty() {
                let n = me.rx_plain.len().min(buf.remaining());
                buf.put_slice(&me.rx_plain[..n]);
                me.rx_plain.advance(n);
                return Poll::Ready(Ok(()));
            }
            match me.rx_state {
                RxState::NeedHead => {
                    let head_len = response_head_len(me.method);
                    match me.fill_raw(cx, head_len) {
                        Poll::Ready(Ok(true)) => {}
                        Poll::Ready(Ok(false)) => return Poll::Ready(Ok(())),
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                    let head_bytes = me.rx_raw.split_to(head_len);
                    let head =
                        decode_response_head(me.method, &me.psk, &me.request_salt, &head_bytes)
                            .map_err(|_| {
                                io::Error::new(io::ErrorKind::InvalidData, "ss response head")
                            })?;
                    let first = head.first_chunk_len;
                    me.rx = Some(head);
                    me.rx_state = RxState::NeedPayload { plain: first };
                }
                RxState::NeedLen => {
                    match me.fill_raw(cx, 2 + TAG) {
                        Poll::Ready(Ok(true)) => {}
                        Poll::Ready(Ok(false)) => return Poll::Ready(Ok(())),
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                    let mut chunk = me.rx_raw.split_to(2 + TAG); // BytesMut derefs to &mut [u8] for open()
                                                                 // Fetch the head set during NeedHead; error rather than panic if absent.
                    let head = match me.rx.as_mut() {
                        Some(h) => h,
                        None => {
                            return Poll::Ready(Err(io::Error::other("ss: response head missing")))
                        }
                    };
                    let nonce = head.counter.next();
                    let plain = head
                        .cipher
                        .open(nonce, &mut chunk)
                        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "ss len chunk"))?;
                    let plain_len = u16::from_be_bytes([plain[0], plain[1]]) as usize;
                    me.rx_state = RxState::NeedPayload { plain: plain_len };
                }
                RxState::NeedPayload { plain } => {
                    match me.fill_raw(cx, plain + TAG) {
                        Poll::Ready(Ok(true)) => {}
                        Poll::Ready(Ok(false)) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "ss payload chunk truncated",
                            )))
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                    let mut chunk = me.rx_raw.split_to(plain + TAG); // BytesMut derefs to &mut [u8] for open()
                                                                     // Fetch the head set during NeedHead; error rather than panic if absent.
                    let head = match me.rx.as_mut() {
                        Some(h) => h,
                        None => {
                            return Poll::Ready(Err(io::Error::other("ss: response head missing")))
                        }
                    };
                    let nonce = head.counter.next();
                    let payload = head
                        .cipher
                        .open(nonce, &mut chunk)
                        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "ss payload"))?;
                    me.rx_plain.extend_from_slice(payload);
                    me.rx_state = RxState::NeedLen;
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> ShadowsocksStream<S> {
    /// Flush `tx_pending` to `inner`. `Ready(Ok(()))` only when fully drained.
    fn flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.tx_pending.is_empty() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.tx_pending) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "ss write zero",
                    )))
                }
                Poll::Ready(Ok(n)) => {
                    self.tx_pending.advance(n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ShadowsocksStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        match me.flush_pending(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let take = buf.len().min(MAX_PAYLOAD);
        let mut len_chunk = (take as u16).to_be_bytes().to_vec();
        if let Err(e) = me.tx.seal(me.tx_ctr.next(), &mut len_chunk) {
            return Poll::Ready(Err(io::Error::other(e)));
        }
        let mut payload = buf[..take].to_vec();
        if let Err(e) = me.tx.seal(me.tx_ctr.next(), &mut payload) {
            return Poll::Ready(Err(io::Error::other(e)));
        }
        me.tx_pending.extend_from_slice(&len_chunk);
        me.tx_pending.extend_from_slice(&payload);
        // Opportunistically push the chunk now. Surface an immediate write error (e.g. broken pipe)
        // rather than hiding it until a later flush; a `Pending` flush is fine — the bytes are buffered
        // and drain on the next poll_write/poll_flush.
        if let Poll::Ready(Err(e)) = me.flush_pending(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(take))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        match me.flush_pending(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut me.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        match me.flush_pending(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut me.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_head_validates_request_salt() {
        let method = SsMethod::Aes256Gcm;
        let psk = vec![5u8; 32];
        let request_salt = vec![5u8; 32];

        // Build a server response head the way a server would.
        let rng = ring::rand::SystemRandom::new();
        let mut resp_salt = vec![0u8; 32];
        ring::rand::SecureRandom::fill(&rng, &mut resp_salt).unwrap();
        let subkey = session_subkey(method, &psk, &resp_salt);
        let cipher = Cipher::new(method, &subkey).unwrap();
        let mut ctr = NonceCounter::new();
        let mut fixed = Vec::new();
        fixed.push(1u8); // server stream
        fixed.extend_from_slice(&now_secs().to_be_bytes());
        fixed.extend_from_slice(&request_salt); // echoes our salt
        fixed.extend_from_slice(&77u16.to_be_bytes()); // first payload length
        cipher.seal(ctr.next(), &mut fixed).unwrap();
        let mut wire = resp_salt.clone();
        wire.extend_from_slice(&fixed);

        let head = decode_response_head(method, &psk, &request_salt, &wire).unwrap();
        assert_eq!(head.first_chunk_len, 77);

        // A wrong request_salt is rejected.
        let bad_salt = vec![9u8; 32];
        assert!(decode_response_head(method, &psk, &bad_salt, &wire).is_err());
    }

    #[test]
    fn request_prefix_decodes_back() {
        let method = SsMethod::Aes256Gcm;
        let psk = vec![5u8; 32];
        let target: std::net::SocketAddr = "1.2.3.4:443".parse().unwrap();

        let req = encode_request(method, &psk, &target).unwrap();

        // Pull the salt off the front, derive the subkey, decrypt the two header chunks.
        let salt = &req.bytes[..method.salt_len()];
        let subkey = session_subkey(method, &psk, salt);
        let cipher = Cipher::new(method, &subkey).unwrap();
        let mut ctr = NonceCounter::new();
        let mut off = method.salt_len();

        let mut fixed = req.bytes[off..off + 11 + 16].to_vec();
        let fixed = cipher.open(ctr.next(), &mut fixed).unwrap().to_vec();
        assert_eq!(fixed[0], 0); // type = client stream
        let var_len = u16::from_be_bytes([fixed[9], fixed[10]]) as usize;
        off += 11 + 16;

        // The timestamp is a recent epoch second (sanity check it's set).
        assert!(u64::from_be_bytes(fixed[1..9].try_into().unwrap()) > 0);

        let mut var = req.bytes[off..off + var_len + 16].to_vec();
        let var = cipher.open(ctr.next(), &mut var).unwrap();
        assert_eq!(var[0], 0x01); // ATYP IPv4
        assert_eq!(&var[1..5], &[1, 2, 3, 4]); // the target IP
        assert_eq!(u16::from_be_bytes([var[5], var[6]]), 443); // the target port
        let pad_len = u16::from_be_bytes([var[7], var[8]]);
        assert!((1..=64).contains(&pad_len)); // non-zero, bounded padding
        assert_eq!(var.len(), 7 + 2 + pad_len as usize); // addr + pad_len field + padding, no initial payload
        assert_eq!(off + var_len + 16, req.bytes.len());
        assert_eq!(req.salt, salt.to_vec());
    }

    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    /// A minimal in-test SS-2022 server half: reads a request, then sends one response payload chunk.
    async fn ss_echo_peer(mut sock: tokio::io::DuplexStream, method: SsMethod, psk: Vec<u8>) {
        let sl = method.salt_len();
        let mut head = vec![0u8; sl + 11 + 16];
        sock.read_exact(&mut head).await.unwrap();
        let req_salt = head[..sl].to_vec();
        let subkey = session_subkey(method, &psk, &req_salt);
        let rx = Cipher::new(method, &subkey).unwrap();
        let mut rxc = NonceCounter::new();
        let mut fixed = head[sl..].to_vec();
        let fixed = rx.open(rxc.next(), &mut fixed).unwrap().to_vec();
        let var_len = u16::from_be_bytes([fixed[9], fixed[10]]) as usize;
        let mut var = vec![0u8; var_len + 16];
        sock.read_exact(&mut var).await.unwrap();
        rx.open(rxc.next(), &mut var).unwrap();

        let rng = ring::rand::SystemRandom::new();
        let mut resp_salt = vec![0u8; sl];
        ring::rand::SecureRandom::fill(&rng, &mut resp_salt).unwrap();
        let tx = Cipher::new(method, &session_subkey(method, &psk, &resp_salt)).unwrap();
        let mut txc = NonceCounter::new();
        let payload = b"pong";
        let mut hdr = vec![1u8];
        hdr.extend_from_slice(&now_secs().to_be_bytes());
        hdr.extend_from_slice(&req_salt);
        hdr.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        tx.seal(txc.next(), &mut hdr).unwrap();
        let mut body = payload.to_vec();
        tx.seal(txc.next(), &mut body).unwrap();
        let mut out = resp_salt;
        out.extend_from_slice(&hdr);
        out.extend_from_slice(&body);
        sock.write_all(&out).await.unwrap();
        sock.flush().await.unwrap();
    }

    #[tokio::test]
    async fn stream_round_trips_against_a_spec_peer() {
        let method = SsMethod::Aes256Gcm;
        let psk = vec![5u8; 32];
        let target: std::net::SocketAddr = "1.2.3.4:443".parse().unwrap();
        let (client_io, server_io) = duplex(64 * 1024);
        let peer = tokio::spawn(ss_echo_peer(server_io, method, psk.clone()));

        let req = encode_request(method, &psk, &target).unwrap();
        let mut stream = ShadowsocksStream::new(client_io, method, psk.clone(), req);
        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();

        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
        peer.await.unwrap();
    }

    /// A peer that sends a known `blob` after the request head, split into MAX_PAYLOAD-capped chunks.
    async fn ss_blob_peer(
        mut sock: tokio::io::DuplexStream,
        method: SsMethod,
        psk: Vec<u8>,
        blob: Vec<u8>,
    ) {
        let sl = method.salt_len();
        let mut head = vec![0u8; sl + 11 + 16];
        sock.read_exact(&mut head).await.unwrap();
        let req_salt = head[..sl].to_vec();
        let rx = Cipher::new(method, &session_subkey(method, &psk, &req_salt)).unwrap();
        let mut rxc = NonceCounter::new();
        let mut fixed = head[sl..].to_vec();
        let fixed = rx.open(rxc.next(), &mut fixed).unwrap().to_vec();
        let var_len = u16::from_be_bytes([fixed[9], fixed[10]]) as usize;
        let mut var = vec![0u8; var_len + 16];
        sock.read_exact(&mut var).await.unwrap();
        rx.open(rxc.next(), &mut var).unwrap();

        let rng = ring::rand::SystemRandom::new();
        let mut resp_salt = vec![0u8; sl];
        ring::rand::SecureRandom::fill(&rng, &mut resp_salt).unwrap();
        let tx = Cipher::new(method, &session_subkey(method, &psk, &resp_salt)).unwrap();
        let mut txc = NonceCounter::new();
        let mut out = resp_salt;

        let mut chunks = blob.chunks(0xFFFF);
        let first = chunks.next().unwrap_or(&[]);
        let mut hdr = vec![1u8];
        hdr.extend_from_slice(&now_secs().to_be_bytes());
        hdr.extend_from_slice(&req_salt);
        hdr.extend_from_slice(&(first.len() as u16).to_be_bytes());
        tx.seal(txc.next(), &mut hdr).unwrap();
        out.extend_from_slice(&hdr);
        let mut body = first.to_vec();
        tx.seal(txc.next(), &mut body).unwrap();
        out.extend_from_slice(&body);

        for chunk in chunks {
            let mut len = (chunk.len() as u16).to_be_bytes().to_vec();
            tx.seal(txc.next(), &mut len).unwrap();
            out.extend_from_slice(&len);
            let mut payload = chunk.to_vec();
            tx.seal(txc.next(), &mut payload).unwrap();
            out.extend_from_slice(&payload);
        }
        sock.write_all(&out).await.unwrap();
        sock.flush().await.unwrap();
    }

    #[tokio::test]
    async fn stream_handles_a_large_chunked_download() {
        let method = SsMethod::Aes256Gcm;
        let psk = vec![5u8; 32];
        let target: std::net::SocketAddr = "1.2.3.4:443".parse().unwrap();
        let blob: Vec<u8> = (0..200 * 1024).map(|i| (i % 251) as u8).collect();

        let (client_io, server_io) = duplex(8 * 1024); // small duplex => many partial reads
        let peer = tokio::spawn(ss_blob_peer(server_io, method, psk.clone(), blob.clone()));

        let req = encode_request(method, &psk, &target).unwrap();
        let mut stream = ShadowsocksStream::new(client_io, method, psk.clone(), req);
        stream.flush().await.unwrap();

        let mut got = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = stream.read(&mut chunk).await.unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&chunk[..n]);
            if got.len() == blob.len() {
                break;
            }
        }
        assert_eq!(got, blob);
        peer.await.unwrap();
    }
}
