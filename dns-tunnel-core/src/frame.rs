//! The DNS-tunnel binary frame (ADR 0011 §2.2): the inner (AEAD-sealed) header + payload codec, and
//! the on-wire sealed-frame layout.
//!
//! # Wire layout
//!
//! A QUIC-style long/short header form keeps the cleartext prefix minimal while letting the server
//! parse routing fields *before* it has a key:
//!
//! ```text
//! Short (data / most frames):  FORM_SHORT(1) ‖ ConnectionID(8) ‖ nonce(12) ‖ AEAD(inner)
//! Long  (SYN / handshake):     FORM_LONG(1)  ‖ ConnectionID(8) ‖ salt(16) ‖ nonce(12) ‖ AEAD(inner)
//! ```
//!
//! The **ConnectionID is cleartext** so the server can look up (or, on a SYN, create) the session and
//! its key before decrypting; the **salt is cleartext on the SYN** so the server can run the HKDF key
//! schedule. Neither is bound as AEAD AAD, and it does not need to be: the session key is
//! HKDF-derived with the ConnectionID in its `info` (see [`crate::crypto::derive_session_keys`]), so a
//! ciphertext is already cryptographically bound to its ConnectionID — an attacker cannot move it to a
//! different id. Tampering the cleartext salt or nonce simply makes [`open_frame`] fail (wrong key /
//! bad tag). The AEAD tag authenticates the entire inner header + payload.
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

use crate::crypto::{Aead, CryptoError, CONN_ID_LEN, NONCE_LEN, SALT_LEN, TAG_LEN};

/// Current protocol version (inner header byte 0).
pub const VERSION: u8 = 1;

/// Wire header form: a short header (no salt) — data and most frames.
pub const FORM_SHORT: u8 = 0x00;
/// Wire header form: a long header (carries the cleartext session salt) — the SYN / handshake.
pub const FORM_LONG: u8 = 0x01;

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

/// The cleartext prefix parsed from a wire packet, plus the sealed ciphertext slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wire<'a> {
    /// [`FORM_SHORT`] or [`FORM_LONG`].
    pub form: u8,
    /// The session ConnectionID (server routing key).
    pub conn_id: [u8; CONN_ID_LEN],
    /// The per-session HKDF salt — `Some` only on a long (SYN) header.
    pub salt: Option<[u8; SALT_LEN]>,
    /// The AEAD nonce.
    pub nonce: [u8; NONCE_LEN],
    /// The sealed inner frame (ciphertext ‖ tag).
    pub ciphertext: &'a [u8],
}

/// Parse the cleartext wire prefix (no key needed). The server calls this first to route by
/// ConnectionID (and, on a SYN, to get the salt for the key schedule).
pub fn parse_wire(buf: &[u8]) -> Result<Wire<'_>, FrameError> {
    let mut cur = Cursor::new(buf);
    let form = cur.u8()?;
    let conn_id = cur.array::<CONN_ID_LEN>()?;
    let salt = match form {
        FORM_SHORT => None,
        FORM_LONG => Some(cur.array::<SALT_LEN>()?),
        other => return Err(FrameError::BadForm(other)),
    };
    let nonce = cur.array::<NONCE_LEN>()?;
    let ciphertext = cur.rest();
    if ciphertext.len() < TAG_LEN {
        return Err(FrameError::Truncated);
    }
    Ok(Wire {
        form,
        conn_id,
        salt,
        nonce,
        ciphertext,
    })
}

/// Seal `frame` into a short (data) wire packet: `FORM_SHORT ‖ conn_id ‖ nonce ‖ AEAD(inner)`.
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

/// Seal `frame` into a long (SYN) wire packet, carrying the cleartext `salt`:
/// `FORM_LONG ‖ conn_id ‖ salt ‖ nonce ‖ AEAD(inner)`.
pub fn seal_long(
    aead: &Aead,
    conn_id: &[u8; CONN_ID_LEN],
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
    frame: &Frame,
) -> Vec<u8> {
    let mut ct = frame.encode();
    aead.seal(nonce, &mut ct);
    let mut wire = Vec::with_capacity(1 + CONN_ID_LEN + SALT_LEN + NONCE_LEN + ct.len());
    wire.push(FORM_LONG);
    wire.extend_from_slice(conn_id);
    wire.extend_from_slice(salt);
    wire.extend_from_slice(nonce);
    wire.extend_from_slice(&ct);
    wire
}

/// Open a parsed wire packet with `aead` (the session key for `wire.conn_id`) and decode the inner
/// frame. `aead` must be keyed by the direction key derived for this session.
pub fn open_frame(aead: &Aead, wire: &Wire<'_>) -> Result<Frame, FrameError> {
    let mut ct = wire.ciphertext.to_vec();
    let plain = aead.open(&wire.nonce, &mut ct)?;
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
    use crate::crypto::{random_conn_id, random_nonce, random_salt, Aead, Cipher};

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
    fn short_wire_seal_parse_open_round_trips() {
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

        let parsed = parse_wire(&wire).unwrap();
        assert_eq!(parsed.form, FORM_SHORT);
        assert_eq!(parsed.conn_id, conn);
        assert_eq!(parsed.salt, None);
        assert_eq!(parsed.nonce, nonce);

        let opened = open_frame(&aead, &parsed).unwrap();
        assert_eq!(opened, frame);
    }

    #[test]
    fn long_wire_carries_salt_and_round_trips() {
        let aead = test_aead();
        let conn = random_conn_id().unwrap();
        let salt = random_salt().unwrap();
        let nonce = random_nonce().unwrap();
        let mut frame = Frame::new(Kind::Syn);
        frame.payload = Bytes::from_static(b"proposed params");

        let wire = seal_long(&aead, &conn, &salt, &nonce, &frame);
        assert_eq!(wire[0], FORM_LONG);

        let parsed = parse_wire(&wire).unwrap();
        assert_eq!(parsed.salt, Some(salt));
        assert_eq!(parsed.conn_id, conn);
        assert_eq!(open_frame(&aead, &parsed).unwrap(), frame);
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
        let parsed = parse_wire(&wire).unwrap();
        assert!(matches!(
            open_frame(&aead, &parsed),
            Err(FrameError::Crypto(_))
        ));

        // Flip a nonce byte → open fails.
        let mut wire2 = seal_short(&aead, &conn, &nonce, &frame);
        wire2[1 + CONN_ID_LEN] ^= 0x01; // first nonce byte (after form + conn_id)
        let parsed2 = parse_wire(&wire2).unwrap();
        assert!(matches!(
            open_frame(&aead, &parsed2),
            Err(FrameError::Crypto(_))
        ));
    }

    #[test]
    fn parse_wire_rejects_bad_form_and_short_buffers() {
        // Unknown form byte.
        let mut buf = vec![0x09];
        buf.extend_from_slice(&[0u8; CONN_ID_LEN + NONCE_LEN + TAG_LEN]);
        assert!(matches!(parse_wire(&buf), Err(FrameError::BadForm(9))));
        // Truncated (no room for conn_id).
        assert!(matches!(
            parse_wire(&[FORM_SHORT, 1, 2, 3]),
            Err(FrameError::Truncated)
        ));
        // Ciphertext shorter than a tag.
        let mut short = vec![FORM_SHORT];
        short.extend_from_slice(&[0u8; CONN_ID_LEN + NONCE_LEN]);
        short.extend_from_slice(&[0u8; TAG_LEN - 1]);
        assert!(matches!(parse_wire(&short), Err(FrameError::Truncated)));
    }

    #[test]
    fn parsers_never_panic_on_random_input() {
        // Poor-man's fuzz guarding the panic-free contract (formal `cargo fuzz` is a follow-up).
        let aead = test_aead();
        let mut state = 0x0DDF_00D5_1234_5678u64;
        for len in 0..300usize {
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                buf.push((state >> 33) as u8);
            }
            let _ = Frame::decode(&buf);
            if let Ok(w) = parse_wire(&buf) {
                let _ = open_frame(&aead, &w);
            }
        }
    }
}
