//! BIP324 key schedule + the two forward-secure rekeying ciphers.
//!
//! [`derive`] runs HKDF-SHA256 over the tagged-hash ECDH secret into the four direction keys + session
//! id + garbage terminators. [`FSChaCha20`] is the length-field stream cipher and [`FSChaCha20Poly1305`]
//! the packet AEAD; both re-key every [`REKEY_INTERVAL`] messages for forward secrecy.

use alloc::vec::Vec;

use crate::crypto::Bip324Crypto;
use crate::{Role, GARBAGE_TERMINATOR_LEN, REKEY_INTERVAL};

const KEY_LEN: usize = 32;

/// The per-connection keys derived from the ECDH shared secret. `send_*`/`recv_*` are already assigned
/// for our [`Role`]; the caller (handshake) moves these into a running session.
pub struct Keys {
    pub session_id: [u8; 32],
    pub send_l: FSChaCha20,
    pub send_p: FSChaCha20Poly1305,
    pub recv_l: FSChaCha20,
    pub recv_p: FSChaCha20Poly1305,
    pub send_garbage_terminator: [u8; GARBAGE_TERMINATOR_LEN],
    pub recv_garbage_terminator: [u8; GARBAGE_TERMINATOR_LEN],
}

/// Derive the session keys (BIP324 "Keys and session ID derivation"): HKDF-Extract with
/// salt = `"bitcoin_v2_shared_secret" || network_magic` and ikm = the tagged-hash ECDH secret, then five
/// HKDF-Expand labels. Send/recv are assigned by role.
pub fn derive<C: Bip324Crypto>(
    crypto: &C,
    ecdh_secret: &[u8; 32],
    network_magic: &[u8; 4],
    role: Role,
) -> Keys {
    let mut salt = Vec::with_capacity(24 + 4);
    salt.extend_from_slice(b"bitcoin_v2_shared_secret");
    salt.extend_from_slice(network_magic);
    let prk = crypto.hkdf_extract(&salt, ecdh_secret);

    let expand = |info: &[u8], out: &mut [u8]| crypto.hkdf_expand(&prk, info, out);
    let mut session_id = [0u8; 32];
    expand(b"session_id", &mut session_id);
    let mut initiator_l = [0u8; KEY_LEN];
    expand(b"initiator_L", &mut initiator_l);
    let mut initiator_p = [0u8; KEY_LEN];
    expand(b"initiator_P", &mut initiator_p);
    let mut responder_l = [0u8; KEY_LEN];
    expand(b"responder_L", &mut responder_l);
    let mut responder_p = [0u8; KEY_LEN];
    expand(b"responder_P", &mut responder_p);
    let mut terminators = [0u8; 2 * GARBAGE_TERMINATOR_LEN];
    expand(b"garbage_terminators", &mut terminators);

    let mut initiator_gt = [0u8; GARBAGE_TERMINATOR_LEN];
    initiator_gt.copy_from_slice(&terminators[..GARBAGE_TERMINATOR_LEN]);
    let mut responder_gt = [0u8; GARBAGE_TERMINATOR_LEN];
    responder_gt.copy_from_slice(&terminators[GARBAGE_TERMINATOR_LEN..]);

    // "initiator_*" is the initiator's *send* direction; the responder receives on it.
    let (send_l, send_p, send_gt, recv_l, recv_p, recv_gt) = if role.is_initiator() {
        (
            initiator_l,
            initiator_p,
            initiator_gt,
            responder_l,
            responder_p,
            responder_gt,
        )
    } else {
        (
            responder_l,
            responder_p,
            responder_gt,
            initiator_l,
            initiator_p,
            initiator_gt,
        )
    };

    Keys {
        session_id,
        send_l: FSChaCha20::new(send_l),
        send_p: FSChaCha20Poly1305::new(send_p),
        recv_l: FSChaCha20::new(recv_l),
        recv_p: FSChaCha20Poly1305::new(recv_p),
        send_garbage_terminator: send_gt,
        recv_garbage_terminator: recv_gt,
    }
}

/// FSChaCha20: the length-field stream cipher. A single ChaCha20 cipher's keystream is consumed
/// sequentially across chunks (3 bytes each); every [`REKEY_INTERVAL`] chunks it re-keys off the next
/// 32 keystream bytes and resets the block counter. Encryption and decryption are identical.
pub struct FSChaCha20 {
    key: [u8; KEY_LEN],
    block_counter: u32,
    chunk_counter: u64,
    /// Buffered keystream for the current epoch; `ks_pos` is the consumed offset (advanced, not
    /// drained, so the hot path never allocates or shifts — the buffer is cleared on each re-key).
    keystream: Vec<u8>,
    ks_pos: usize,
}

impl FSChaCha20 {
    fn new(key: [u8; KEY_LEN]) -> Self {
        Self {
            key,
            block_counter: 0,
            chunk_counter: 0,
            keystream: Vec::new(),
            ks_pos: 0,
        }
    }

    /// Nonce for the current epoch: 4 zero bytes + the LE64 re-key count.
    fn nonce(&self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&(self.chunk_counter / REKEY_INTERVAL).to_le_bytes());
        n
    }

    /// Ensure at least `n` unconsumed keystream bytes are buffered, generating 64-byte blocks (XOR
    /// against zeros) as needed.
    fn fill<C: Bip324Crypto>(&mut self, crypto: &C, n: usize) {
        while self.keystream.len() - self.ks_pos < n {
            let nonce = self.nonce();
            let mut block = [0u8; 64];
            crypto.chacha20_apply(&self.key, &nonce, self.block_counter, &mut block);
            self.keystream.extend_from_slice(&block);
            self.block_counter += 1;
        }
    }

    /// XOR `chunk` in place with the next keystream bytes, then advance (re-keying on the boundary).
    pub fn crypt<C: Bip324Crypto>(&mut self, crypto: &C, chunk: &mut [u8]) {
        self.fill(crypto, chunk.len());
        for (b, k) in chunk.iter_mut().zip(&self.keystream[self.ks_pos..]) {
            *b ^= *k;
        }
        self.ks_pos += chunk.len();
        if (self.chunk_counter + 1) % REKEY_INTERVAL == 0 {
            self.fill(crypto, KEY_LEN);
            self.key
                .copy_from_slice(&self.keystream[self.ks_pos..self.ks_pos + KEY_LEN]);
            self.block_counter = 0;
            self.keystream.clear();
            self.ks_pos = 0;
        }
        self.chunk_counter += 1;
    }
}

/// FSChaCha20Poly1305: the packet AEAD. Each packet uses a fresh nonce derived from the packet counter;
/// every [`REKEY_INTERVAL`] packets it re-keys by sealing 32 zero bytes under a sentinel nonce.
pub struct FSChaCha20Poly1305 {
    key: [u8; KEY_LEN],
    packet_counter: u64,
}

impl FSChaCha20Poly1305 {
    fn new(key: [u8; KEY_LEN]) -> Self {
        Self {
            key,
            packet_counter: 0,
        }
    }

    /// Nonce: LE32(counter % interval) || LE64(counter / interval).
    fn nonce(&self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..4].copy_from_slice(&((self.packet_counter % REKEY_INTERVAL) as u32).to_le_bytes());
        n[4..].copy_from_slice(&(self.packet_counter / REKEY_INTERVAL).to_le_bytes());
        n
    }

    /// After a successful crypt: re-key on the interval boundary (sentinel nonce = 0xffffffff || the
    /// rekey-count half of `nonce`), then advance the packet counter.
    fn advance<C: Bip324Crypto>(&mut self, crypto: &C, nonce: &[u8; 12]) {
        if (self.packet_counter + 1) % REKEY_INTERVAL == 0 {
            let mut rekey_nonce = *nonce;
            rekey_nonce[..4].copy_from_slice(&[0xFF; 4]);
            let out = crypto.aead_seal(&self.key, &rekey_nonce, &[], &[0u8; KEY_LEN]);
            self.key.copy_from_slice(&out[..KEY_LEN]);
        }
        self.packet_counter += 1;
    }

    pub fn encrypt<C: Bip324Crypto>(
        &mut self,
        crypto: &C,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Vec<u8> {
        let nonce = self.nonce();
        let ct = crypto.aead_seal(&self.key, &nonce, aad, plaintext);
        self.advance(crypto, &nonce);
        ct
    }

    /// Returns the plaintext, or `None` on auth failure (state is *not* advanced on failure — the
    /// connection tears down).
    pub fn decrypt<C: Bip324Crypto>(
        &mut self,
        crypto: &C,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Option<Vec<u8>> {
        let nonce = self.nonce();
        let pt = crypto.aead_open(&self.key, &nonce, aad, ciphertext)?;
        self.advance(crypto, &nonce);
        Some(pt)
    }
}
