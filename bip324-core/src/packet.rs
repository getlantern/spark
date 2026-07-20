//! BIP324 packet framing: a 3-byte length under [`FSChaCha20`], then `[header || contents]` under
//! [`FSChaCha20Poly1305`]. [`Session`] is the steady-state channel after the handshake.

use alloc::vec::Vec;

use crate::crypto::Bip324Crypto;
use crate::session::{FSChaCha20, FSChaCha20Poly1305, Keys};
use crate::{
    Error, Result, Role, AEAD_TAG_LEN, HEADER_LEN, IGNORE_BIT, LENGTH_FIELD_LEN, MAX_CONTENTS_LEN,
};

/// Encrypt one v2 packet: FSChaCha20 over the 3-byte little-endian length, then FSChaCha20Poly1305 over
/// `[header || contents]` (header bit 7 = the ignore/decoy flag). Returns `enc_length || aead`. `aad` is
/// non-empty only for the first packet in a direction (garbage authentication).
pub fn encrypt_packet<C: Bip324Crypto>(
    crypto: &C,
    l: &mut FSChaCha20,
    p: &mut FSChaCha20Poly1305,
    contents: &[u8],
    aad: &[u8],
    ignore: bool,
) -> Result<Vec<u8>> {
    if contents.len() > MAX_CONTENTS_LEN {
        return Err(Error::ContentsTooLong);
    }
    let mut length = [0u8; LENGTH_FIELD_LEN];
    length.copy_from_slice(&(contents.len() as u32).to_le_bytes()[..LENGTH_FIELD_LEN]);
    l.crypt(crypto, &mut length);

    let mut plaintext = Vec::with_capacity(HEADER_LEN + contents.len());
    plaintext.push(if ignore { IGNORE_BIT } else { 0 });
    plaintext.extend_from_slice(contents);
    let aead = p.encrypt(crypto, aad, &plaintext);

    let mut out = Vec::with_capacity(LENGTH_FIELD_LEN + aead.len());
    out.extend_from_slice(&length);
    out.extend_from_slice(&aead);
    Ok(out)
}

/// Decrypt a 3-byte encrypted length field into a contents length (advances the length cipher).
pub fn decrypt_length<C: Bip324Crypto>(
    crypto: &C,
    l: &mut FSChaCha20,
    enc_len: &[u8; LENGTH_FIELD_LEN],
) -> usize {
    let mut buf = *enc_len;
    l.crypt(crypto, &mut buf);
    (buf[0] as usize) | ((buf[1] as usize) << 8) | ((buf[2] as usize) << 16)
}

/// A decrypted packet: whether it was a decoy (ignore bit), and the genuine contents.
pub struct DecryptedPacket {
    pub ignore: bool,
    pub contents: Vec<u8>,
}

/// Decrypt one packet's AEAD ciphertext (`[header || contents] + tag`). Advances the packet cipher;
/// [`Error::Decrypt`] on authentication failure.
pub fn decrypt_packet<C: Bip324Crypto>(
    crypto: &C,
    p: &mut FSChaCha20Poly1305,
    aead_ciphertext: &[u8],
    aad: &[u8],
) -> Result<DecryptedPacket> {
    let pt = p
        .decrypt(crypto, aad, aead_ciphertext)
        .ok_or(Error::Decrypt)?;
    let header = *pt.first().ok_or(Error::Decrypt)?;
    Ok(DecryptedPacket {
        ignore: header & IGNORE_BIT != 0,
        contents: pt[HEADER_LEN..].to_vec(),
    })
}

/// The established BIP324 session — the steady-state packet channel after a completed handshake. Owns
/// the four ciphers (already advanced past the handshake's version packets) and buffers partial inbound
/// packets across [`Session::decrypt`] calls.
pub struct Session {
    role: Role,
    session_id: [u8; 32],
    send_l: FSChaCha20,
    send_p: FSChaCha20Poly1305,
    recv_l: FSChaCha20,
    recv_p: FSChaCha20Poly1305,
    recv_buf: Vec<u8>,
    pending_len: Option<usize>,
}

impl Session {
    /// Construct from the post-handshake [`Keys`] (ciphers already advanced past the version exchange).
    pub(crate) fn new(role: Role, keys: Keys) -> Self {
        Self {
            role,
            session_id: keys.session_id,
            send_l: keys.send_l,
            send_p: keys.send_p,
            recv_l: keys.recv_l,
            recv_p: keys.recv_p,
            recv_buf: Vec::new(),
            pending_len: None,
        }
    }

    pub fn role(&self) -> Role {
        self.role
    }

    /// The 32-byte session id (BIP324 channel binding); identical on both peers.
    pub fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    /// Encrypt application `contents` into one wire packet (steady state: empty AAD, genuine).
    pub fn encrypt<C: Bip324Crypto>(&mut self, crypto: &C, contents: &[u8]) -> Result<Vec<u8>> {
        encrypt_packet(
            crypto,
            &mut self.send_l,
            &mut self.send_p,
            contents,
            &[],
            false,
        )
    }

    /// Encrypt a decoy packet (random `contents`, ignore bit set) for traffic shaping.
    pub fn encrypt_decoy<C: Bip324Crypto>(
        &mut self,
        crypto: &C,
        contents: &[u8],
    ) -> Result<Vec<u8>> {
        encrypt_packet(
            crypto,
            &mut self.send_l,
            &mut self.send_p,
            contents,
            &[],
            true,
        )
    }

    /// Feed inbound wire bytes; return zero or more complete genuine messages (decoys dropped).
    /// Buffers partial packets across calls. [`Error::Decrypt`] is terminal for the session.
    pub fn decrypt<C: Bip324Crypto>(&mut self, crypto: &C, wire: &[u8]) -> Result<Vec<Vec<u8>>> {
        self.recv_buf.extend_from_slice(wire);
        let mut out = Vec::new();
        loop {
            match self.pending_len {
                None => {
                    if self.recv_buf.len() < LENGTH_FIELD_LEN {
                        break;
                    }
                    let mut enc = [0u8; LENGTH_FIELD_LEN];
                    enc.copy_from_slice(&self.recv_buf[..LENGTH_FIELD_LEN]);
                    let len = decrypt_length(crypto, &mut self.recv_l, &enc);
                    self.recv_buf.drain(..LENGTH_FIELD_LEN);
                    self.pending_len = Some(len);
                }
                Some(len) => {
                    let need = HEADER_LEN + len + AEAD_TAG_LEN;
                    if self.recv_buf.len() < need {
                        break;
                    }
                    // Decrypt in place from the buffer; drain only after authentication succeeds.
                    let packet =
                        decrypt_packet(crypto, &mut self.recv_p, &self.recv_buf[..need], &[])?;
                    self.recv_buf.drain(..need);
                    self.pending_len = None;
                    if !packet.ignore {
                        out.push(packet.contents);
                    }
                }
            }
        }
        Ok(out)
    }
}
