//! The DNS-tunnel binary frame (ADR 0011 §2.2): the inner (AEAD-sealed) header + payload codec, and
//! the on-wire sealed-frame layout.
//!
//! # Wire layout
//!
//! Three packet forms (first byte). Data is AEAD-sealed; the two handshake packets are cleartext
//! Diffie-Hellman (there is no shared key until the ephemerals meet — ADR 0011 §2.4, forward-secret
//! handshake):
//!
//! ```text
//! Data:    FORM_SHORT(1)  ‖ ConnectionID(8) ‖ nonce(12) ‖ AEAD(inner)
//! Syn:     FORM_SYN(1)    ‖ ConnectionID(8) ‖ client_ephemeral_pub(32)
//! SynAck:  FORM_SYNACK(1) ‖ ConnectionID(8) ‖ server_ephemeral_pub(32) ‖ Ed25519_sig(64)
//! ```
//!
//! The **ConnectionID is cleartext** so the server can look up (or, on a Syn, create) the session
//! before decrypting. The handshake ephemeral public keys are public by nature. The server signs the
//! transcript (`client_eph ‖ server_eph ‖ ConnectionID`) with its static Ed25519 key so the client
//! authenticates it (the signature is the anti-MITM guarantee). Session keys derive only from the
//! ephemeral↔ephemeral shared secret, so they are forward-secret. For a Data frame the AEAD tag
//! authenticates the entire inner header + payload; the session key is bound to the ConnectionID via
//! the handshake transcript, so a ciphertext cannot be moved to a different id.
//!
//! # Inner (sealed) plaintext
//!
//! ```text
//! version(1)=1  kind(1)  flags(1)
//! [FLAG_STREAM]      stream_id(u16 BE)
//! [FLAG_SEQ]         seq(u32 BE)
//! [FLAG_FRAGMENT]    frag_idx(1) frag_cnt(1)
//! [FLAG_COMPRESSED]  comp_algo(1)
//! payload (rest)
//! ```

use bytes::Bytes;

use crate::crypto::{
    Aead, CryptoError, CONN_ID_LEN, ED25519_SIG_LEN, NONCE_LEN, TAG_LEN, X25519_PUB_LEN,
};

/// Current protocol version (inner header byte 0).
pub const VERSION: u8 = 1;

/// Wire packet form: an AEAD data frame — `FORM_SHORT ‖ conn_id ‖ nonce ‖ AEAD(inner)`.
pub const FORM_SHORT: u8 = 0x00;
/// Wire packet form: the client handshake — `FORM_SYN ‖ conn_id ‖ client_ephemeral_pub(32)`.
pub const FORM_SYN: u8 = 0x01;
/// Wire packet form: the server handshake — `FORM_SYNACK ‖ conn_id ‖ server_ephemeral_pub(32) ‖ sig(64)`.
pub const FORM_SYNACK: u8 = 0x02;

/// `stream_id` field present.
pub const FLAG_STREAM: u8 = 0b0000_0001;
/// `seq` field present.
pub const FLAG_SEQ: u8 = 0b0000_0010;
/// `frag_idx`/`frag_cnt` fields present.
pub const FLAG_FRAGMENT: u8 = 0b0000_0100;
/// `comp_algo` field present.
pub const FLAG_COMPRESSED: u8 = 0b0000_1000;
/// The union of all defined flag bits; any other bit set is rejected on decode.
const FLAG_KNOWN: u8 = FLAG_STREAM | FLAG_SEQ | FLAG_FRAGMENT | FLAG_COMPRESSED;

/// Packet kind (inner header byte 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    /// Session open (long form; carries the salt + proposed params in the payload).
    Syn = 1,
    /// Session open acknowledgement (accepted params + cookie in the payload).
    SynAck = 2,
    /// Stream data (carries `seq`).
    Data = 3,
    /// Cumulative acknowledgement (carries the acked `seq`).
    Ack = 4,
    /// Selective negative acknowledgement (carries the first missing `seq`).
    Nack = 5,
    /// Stream half-close.
    Fin = 6,
    /// Abrupt reset.
    Rst = 7,
    /// Idle keep-alive / poll (lets the server answer with pending data).
    KeepAlive = 8,
    /// MTU probe (client→server): a control frame whose payload is `dir(1) ‖ target(u16)`. For a
    /// downlink probe the server replies with a `MtuProbeResp` padded to `target`; for an uplink probe
    /// the (large) probe QNAME itself is the test and the server confirms receipt. Not ARQ data.
    MtuProbe = 9,
    /// MTU probe response (server→client): echoes `dir(1) ‖ target(u16)` then padding (downlink probes
    /// are padded to `target` so an oversized answer fails to return). Not ARQ data.
    MtuProbeResp = 10,
    /// Set the server's downlink segment size (client→server): payload `size(u16)`. Sent after the
    /// client has probed a synced pool MTU. Not ARQ data.
    SetMtu = 11,
}

impl Kind {
    fn from_u8(v: u8) -> Option<Kind> {
        Some(match v {
            1 => Kind::Syn,
            2 => Kind::SynAck,
            3 => Kind::Data,
            4 => Kind::Ack,
            5 => Kind::Nack,
            6 => Kind::Fin,
            7 => Kind::Rst,
            8 => Kind::KeepAlive,
            9 => Kind::MtuProbe,
            10 => Kind::MtuProbeResp,
            11 => Kind::SetMtu,
            _ => return None,
        })
    }
}

/// Errors from frame (de)serialization.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// The buffer ended before a required field.
    #[error("frame truncated")]
    Truncated,
    /// The inner header version is not [`VERSION`].
    #[error("unsupported frame version {0}")]
    Version(u8),
    /// The `kind` byte is not a known [`Kind`].
    #[error("unknown packet kind {0}")]
    UnknownKind(u8),
    /// An undefined flag bit was set.
    #[error("unknown header flags {0:#010b}")]
    UnknownFlags(u8),
    /// The wire form byte is neither [`FORM_SHORT`] nor [`FORM_LONG`].
    #[error("bad wire form {0}")]
    BadForm(u8),
    /// AEAD open failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// The inner (AEAD-sealed) frame: the header fields plus the payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Packet kind.
    pub kind: Kind,
    /// Stream identifier (multiplexing) — present for stream-scoped frames.
    pub stream_id: Option<u16>,
    /// Sequence / ack / nack number — present for `Data`/`Ack`/`Nack` and any reliable frame.
    pub seq: Option<u32>,
    /// Fragment `(index, count)` when a logical frame is split across DNS messages.
    pub fragment: Option<(u8, u8)>,
    /// Compression algorithm id (see `compress` module) — present when the payload is compressed.
    pub comp_algo: Option<u8>,
    /// The frame payload (already compressed if `comp_algo` is set).
    pub payload: Bytes,
}

impl Frame {
    /// A minimal frame of `kind` with no optional fields and an empty payload.
    pub fn new(kind: Kind) -> Self {
        Frame {
            kind,
            stream_id: None,
            seq: None,
            fragment: None,
            comp_algo: None,
            payload: Bytes::new(),
        }
    }

    /// Serialize the inner plaintext (version ‖ kind ‖ flags ‖ optional fields ‖ payload).
    pub fn encode(&self) -> Vec<u8> {
        let mut flags = 0u8;
        if self.stream_id.is_some() {
            flags |= FLAG_STREAM;
        }
        if self.seq.is_some() {
            flags |= FLAG_SEQ;
        }
        if self.fragment.is_some() {
            flags |= FLAG_FRAGMENT;
        }
        if self.comp_algo.is_some() {
            flags |= FLAG_COMPRESSED;
        }

        let mut out = Vec::with_capacity(3 + 9 + self.payload.len());
        out.push(VERSION);
        out.push(self.kind as u8);
        out.push(flags);
        if let Some(s) = self.stream_id {
            out.extend_from_slice(&s.to_be_bytes());
        }
        if let Some(q) = self.seq {
            out.extend_from_slice(&q.to_be_bytes());
        }
        if let Some((i, c)) = self.fragment {
            out.push(i);
            out.push(c);
        }
        if let Some(a) = self.comp_algo {
            out.push(a);
        }
        out.extend_from_slice(&self.payload);
        out
    }

    /// Parse the inner plaintext produced by [`Frame::encode`].
    pub fn decode(buf: &[u8]) -> Result<Frame, FrameError> {
        let mut cur = Cursor::new(buf);
        let version = cur.u8()?;
        if version != VERSION {
            return Err(FrameError::Version(version));
        }
        let kind = Kind::from_u8(cur.u8()?).ok_or(FrameError::UnknownKind(buf[1]))?;
        let flags = cur.u8()?;
        if flags & !FLAG_KNOWN != 0 {
            return Err(FrameError::UnknownFlags(flags));
        }
        let stream_id = if flags & FLAG_STREAM != 0 {
            Some(cur.u16()?)
        } else {
            None
        };
        let seq = if flags & FLAG_SEQ != 0 {
            Some(cur.u32()?)
        } else {
            None
        };
        let fragment = if flags & FLAG_FRAGMENT != 0 {
            Some((cur.u8()?, cur.u8()?))
        } else {
            None
        };
        let comp_algo = if flags & FLAG_COMPRESSED != 0 {
            Some(cur.u8()?)
        } else {
            None
        };
        let payload = Bytes::copy_from_slice(cur.rest());
        Ok(Frame {
            kind,
            stream_id,
            seq,
            fragment,
            comp_algo,
            payload,
        })
    }
}

/// A parsed wire packet: the ConnectionID (always cleartext, for routing) plus the form-specific
/// body. The server/client dispatch on the variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet<'a> {
    /// Client handshake: the client's ephemeral X25519 public key.
    Syn {
        /// Session ConnectionID.
        conn_id: [u8; CONN_ID_LEN],
        /// The client's ephemeral X25519 public key.
        client_eph: [u8; X25519_PUB_LEN],
    },
    /// Server handshake: the server's ephemeral X25519 public key + Ed25519 transcript signature.
    SynAck {
        /// Session ConnectionID.
        conn_id: [u8; CONN_ID_LEN],
        /// The server's ephemeral X25519 public key.
        server_eph: [u8; X25519_PUB_LEN],
        /// Ed25519 signature over the transcript (client_eph ‖ server_eph ‖ conn_id).
        sig: [u8; ED25519_SIG_LEN],
    },
    /// AEAD data frame: the nonce + sealed inner (open with [`open_frame`]).
    Data {
        /// Session ConnectionID.
        conn_id: [u8; CONN_ID_LEN],
        /// The AEAD nonce.
        nonce: [u8; NONCE_LEN],
        /// The sealed inner frame (ciphertext ‖ tag).
        ciphertext: &'a [u8],
    },
}

impl Packet<'_> {
    /// The ConnectionID, whichever form this is.
    pub fn conn_id(&self) -> [u8; CONN_ID_LEN] {
        match self {
            Packet::Syn { conn_id, .. }
            | Packet::SynAck { conn_id, .. }
            | Packet::Data { conn_id, .. } => *conn_id,
        }
    }
}

/// Parse a wire packet (no key needed). The caller dispatches on the [`Packet`] variant; for `Data`
/// it then calls [`open_frame`] with the session's direction key.
pub fn parse_packet(buf: &[u8]) -> Result<Packet<'_>, FrameError> {
    let mut cur = Cursor::new(buf);
    let form = cur.u8()?;
    let conn_id = cur.array::<CONN_ID_LEN>()?;
    match form {
        FORM_SYN => Ok(Packet::Syn {
            conn_id,
            client_eph: cur.array::<X25519_PUB_LEN>()?,
        }),
        FORM_SYNACK => Ok(Packet::SynAck {
            conn_id,
            server_eph: cur.array::<X25519_PUB_LEN>()?,
            sig: cur.array::<ED25519_SIG_LEN>()?,
        }),
        FORM_SHORT => {
            let nonce = cur.array::<NONCE_LEN>()?;
            let ciphertext = cur.rest();
            if ciphertext.len() < TAG_LEN {
                return Err(FrameError::Truncated);
            }
            Ok(Packet::Data {
                conn_id,
                nonce,
                ciphertext,
            })
        }
        other => Err(FrameError::BadForm(other)),
    }
}

/// Build a client handshake packet: `FORM_SYN ‖ conn_id ‖ client_eph`.
pub fn build_syn(conn_id: &[u8; CONN_ID_LEN], client_eph: &[u8; X25519_PUB_LEN]) -> Vec<u8> {
    let mut w = Vec::with_capacity(1 + CONN_ID_LEN + X25519_PUB_LEN);
    w.push(FORM_SYN);
    w.extend_from_slice(conn_id);
    w.extend_from_slice(client_eph);
    w
}

/// Build a server handshake packet: `FORM_SYNACK ‖ conn_id ‖ server_eph ‖ sig`.
pub fn build_synack(
    conn_id: &[u8; CONN_ID_LEN],
    server_eph: &[u8; X25519_PUB_LEN],
    sig: &[u8; ED25519_SIG_LEN],
) -> Vec<u8> {
    let mut w = Vec::with_capacity(1 + CONN_ID_LEN + X25519_PUB_LEN + ED25519_SIG_LEN);
    w.push(FORM_SYNACK);
    w.extend_from_slice(conn_id);
    w.extend_from_slice(server_eph);
    w.extend_from_slice(sig);
    w
}

/// Seal `frame` into a data wire packet: `FORM_SHORT ‖ conn_id ‖ nonce ‖ AEAD(inner)`.
pub fn seal_short(
    aead: &Aead,
    conn_id: &[u8; CONN_ID_LEN],
    nonce: &[u8; NONCE_LEN],
    frame: &Frame,
) -> Vec<u8> {
    let mut ct = frame.encode();
    aead.seal(nonce, &mut ct);
    let mut wire = Vec::with_capacity(1 + CONN_ID_LEN + NONCE_LEN + ct.len());
    wire.push(FORM_SHORT);
    wire.extend_from_slice(conn_id);
    wire.extend_from_slice(nonce);
    wire.extend_from_slice(&ct);
    wire
}

/// Open a `Data` packet's sealed inner frame with `aead` (the session's direction key).
pub fn open_frame(
    aead: &Aead,
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Frame, FrameError> {
    let mut ct = ciphertext.to_vec();
    let plain = aead.open(nonce, &mut ct)?;
    Frame::decode(plain)
}

/// A tiny bounds-checked big-endian read cursor (avoids `bytes::Buf`'s panic-on-underflow).
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], FrameError> {
        let end = self.pos.checked_add(n).ok_or(FrameError::Truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or(FrameError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }
    fn u8(&mut self) -> Result<u8, FrameError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, FrameError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32, FrameError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], FrameError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }
    fn rest(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{random_conn_id, random_nonce, Aead, Cipher};

    fn test_aead() -> Aead {
        Aead::new(Cipher::ChaCha20Poly1305, &[0x5A; 32]).unwrap()
    }

    #[test]
    fn inner_round_trips_bare() {
        let f = Frame::new(Kind::Fin);
        let enc = f.encode();
        assert_eq!(enc.len(), 3); // version + kind + flags, no options, no payload
        assert_eq!(Frame::decode(&enc).unwrap(), f);
    }

    #[test]
    fn inner_round_trips_full() {
        let f = Frame {
            kind: Kind::Data,
            stream_id: Some(0xBEEF),
            seq: Some(0x0123_4567),
            fragment: Some((2, 5)),
            comp_algo: Some(1),
            payload: Bytes::from_static(b"hello dns tunnel"),
        };
        let enc = f.encode();
        let dec = Frame::decode(&enc).unwrap();
        assert_eq!(dec, f);
        assert_eq!(dec.stream_id, Some(0xBEEF));
        assert_eq!(dec.seq, Some(0x0123_4567));
        assert_eq!(dec.fragment, Some((2, 5)));
        assert_eq!(&dec.payload[..], b"hello dns tunnel");
    }

    #[test]
    fn inner_decode_rejects_malformed() {
        assert!(matches!(Frame::decode(&[]), Err(FrameError::Truncated)));
        // Bad version.
        assert!(matches!(
            Frame::decode(&[9, Kind::Data as u8, 0]),
            Err(FrameError::Version(9))
        ));
        // Unknown kind.
        assert!(matches!(
            Frame::decode(&[VERSION, 250, 0]),
            Err(FrameError::UnknownKind(250))
        ));
        // Undefined flag bit set.
        assert!(matches!(
            Frame::decode(&[VERSION, Kind::Data as u8, 0b1000_0000]),
            Err(FrameError::UnknownFlags(_))
        ));
        // FLAG_SEQ set but the 4 seq bytes are missing.
        assert!(matches!(
            Frame::decode(&[VERSION, Kind::Data as u8, FLAG_SEQ, 0, 0]),
            Err(FrameError::Truncated)
        ));
    }

    #[test]
    fn data_packet_seal_parse_open_round_trips() {
        let aead = test_aead();
        let conn = random_conn_id().unwrap();
        let nonce = random_nonce().unwrap();
        let frame = Frame {
            kind: Kind::Data,
            stream_id: Some(7),
            seq: Some(42),
            fragment: None,
            comp_algo: None,
            payload: Bytes::from_static(b"payload bytes"),
        };
        let wire = seal_short(&aead, &conn, &nonce, &frame);
        assert_eq!(wire[0], FORM_SHORT);

        match parse_packet(&wire).unwrap() {
            Packet::Data {
                conn_id,
                nonce: n,
                ciphertext,
            } => {
                assert_eq!(conn_id, conn);
                assert_eq!(n, nonce);
                assert_eq!(open_frame(&aead, &n, ciphertext).unwrap(), frame);
            }
            other => panic!("expected Data, got {other:?}"),
        }
    }

    #[test]
    fn syn_and_synack_round_trip() {
        let conn = random_conn_id().unwrap();
        let client_eph = [0x11u8; X25519_PUB_LEN];
        let server_eph = [0x22u8; X25519_PUB_LEN];
        let sig = [0x33u8; ED25519_SIG_LEN];

        let syn = build_syn(&conn, &client_eph);
        assert_eq!(syn[0], FORM_SYN);
        assert_eq!(
            parse_packet(&syn).unwrap(),
            Packet::Syn {
                conn_id: conn,
                client_eph
            }
        );

        let synack = build_synack(&conn, &server_eph, &sig);
        assert_eq!(synack[0], FORM_SYNACK);
        assert_eq!(
            parse_packet(&synack).unwrap(),
            Packet::SynAck {
                conn_id: conn,
                server_eph,
                sig
            }
        );
    }

    #[test]
    fn open_rejects_tampered_ciphertext_and_nonce() {
        let aead = test_aead();
        let conn = random_conn_id().unwrap();
        let nonce = random_nonce().unwrap();
        let frame = {
            let mut f = Frame::new(Kind::Data);
            f.seq = Some(1);
            f.payload = Bytes::from_static(b"abcd");
            f
        };
        let mut wire = seal_short(&aead, &conn, &nonce, &frame);

        // Flip a ciphertext byte (last byte is in the tag region) → open fails.
        let last = wire.len() - 1;
        wire[last] ^= 0x01;
        if let Packet::Data {
            nonce, ciphertext, ..
        } = parse_packet(&wire).unwrap()
        {
            assert!(matches!(
                open_frame(&aead, &nonce, ciphertext),
                Err(FrameError::Crypto(_))
            ));
        } else {
            panic!("expected Data");
        }

        // Flip a nonce byte → open fails.
        let mut wire2 = seal_short(&aead, &conn, &nonce, &frame);
        wire2[1 + CONN_ID_LEN] ^= 0x01; // first nonce byte (after form + conn_id)
        if let Packet::Data {
            nonce, ciphertext, ..
        } = parse_packet(&wire2).unwrap()
        {
            assert!(matches!(
                open_frame(&aead, &nonce, ciphertext),
                Err(FrameError::Crypto(_))
            ));
        } else {
            panic!("expected Data");
        }
    }

    #[test]
    fn parse_packet_rejects_bad_form_and_short_buffers() {
        // Unknown form byte.
        let mut buf = vec![0x09];
        buf.extend_from_slice(&[0u8; CONN_ID_LEN + NONCE_LEN + TAG_LEN]);
        assert!(matches!(parse_packet(&buf), Err(FrameError::BadForm(9))));
        // Truncated (no room for conn_id).
        assert!(matches!(
            parse_packet(&[FORM_SHORT, 1, 2, 3]),
            Err(FrameError::Truncated)
        ));
        // Data ciphertext shorter than a tag.
        let mut short = vec![FORM_SHORT];
        short.extend_from_slice(&[0u8; CONN_ID_LEN + NONCE_LEN]);
        short.extend_from_slice(&[0u8; TAG_LEN - 1]);
        assert!(matches!(parse_packet(&short), Err(FrameError::Truncated)));
        // Syn missing its ephemeral key.
        let mut syn_short = vec![FORM_SYN];
        syn_short.extend_from_slice(&[0u8; CONN_ID_LEN]);
        assert!(matches!(
            parse_packet(&syn_short),
            Err(FrameError::Truncated)
        ));
    }

    #[test]
    fn parsers_never_panic_on_random_input() {
        // Poor-man's fuzz guarding the panic-free contract (formal `cargo fuzz` is a follow-up).
        let aead = test_aead();
        let mut state = 0x0DDF_00D5_1234_5678u64;
        for len in 0..300usize {
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                buf.push((state >> 33) as u8);
            }
            let _ = Frame::decode(&buf);
            if let Ok(Packet::Data {
                nonce, ciphertext, ..
            }) = parse_packet(&buf)
            {
                let _ = open_frame(&aead, &nonce, ciphertext);
            }
        }
    }
}
