//! Crypto for the DNS-tunnel core (ADR 0011 §2.4): base64 PSK decode, the HKDF-SHA256 per-session
//! key schedule, `ring` AEAD wrappers, and secure-random helpers.
//!
//! AEAD is ChaCha20-Poly1305 (default) or AES-256-GCM — both 32-byte key, 12-byte nonce, 16-byte tag.
//! Keys are derived per session: `PRK = HKDF-Extract(salt = session_salt, ikm = PSK)`, then
//! `HKDF-Expand(PRK, info = "spark-dns-tunnel v1 " ‖ <role> ‖ ConnectionID)` yields independent
//! upload / download / handshake keys and a key-commitment value. Per-session key separation keeps
//! the random-nonce birthday bound *per session*, not global.
//!
//! The `ring` idioms here mirror the (live-gated) in-repo uses: `hkdf` from
//! `core/src/transport/samizdat/auth.rs` and `aead::LessSafeKey` from
//! `core/src/transport/shadowsocks/crypto.rs`.

use ring::aead;
use ring::hkdf;
use ring::rand::{SecureRandom, SystemRandom};

/// AEAD key length (bytes) — both ciphers use 256-bit keys.
pub const KEY_LEN: usize = 32;
/// AEAD nonce length (bytes).
pub const NONCE_LEN: usize = 12;
/// AEAD tag length (bytes).
pub const TAG_LEN: usize = 16;
/// Per-session HKDF salt length (bytes).
pub const SALT_LEN: usize = 16;
/// ConnectionID length (bytes) — a wide random id (TurboTunnel ClientID), keys the server session.
pub const CONN_ID_LEN: usize = 8;
/// Key-commitment length (bytes).
pub const COMMIT_LEN: usize = 16;
/// Minimum accepted decoded PSK length (bytes).
pub const MIN_PSK_LEN: usize = 32;

/// HKDF info prefix; the per-role label and ConnectionID are appended (as separate `info` segments).
const HKDF_BASE: &[u8] = b"spark-dns-tunnel v1";

/// Crypto errors for the DNS-tunnel core.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// The configured PSK was not valid base64.
    #[error("PSK is not valid base64")]
    BadBase64,
    /// The decoded PSK was shorter than [`MIN_PSK_LEN`].
    #[error("decoded PSK is {got} bytes; need at least {min}")]
    PskTooShort { got: usize, min: usize },
    /// AEAD open failed (bad tag / tampered / wrong key or nonce).
    #[error("AEAD authentication failed")]
    Auth,
    /// AEAD key setup failed (should be unreachable for a 32-byte key).
    #[error("AEAD key setup failed")]
    KeySetup,
    /// The secure RNG failed to produce bytes.
    #[error("secure RNG failure")]
    Rng,
}

/// The AEAD cipher for a session (negotiated in the handshake).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    /// ChaCha20-Poly1305 — the default (constant-time in software, no AES-NI dependency).
    ChaCha20Poly1305,
    /// AES-256-GCM — optional (fast where AES-NI is available).
    Aes256Gcm,
}

impl Cipher {
    fn algorithm(self) -> &'static aead::Algorithm {
        match self {
            Cipher::ChaCha20Poly1305 => &aead::CHACHA20_POLY1305,
            Cipher::Aes256Gcm => &aead::AES_256_GCM,
        }
    }
}

/// Decode the base64 PSK and check it meets [`MIN_PSK_LEN`].
pub fn decode_psk(b64: &str) -> Result<Vec<u8>, CryptoError> {
    let psk = base64_decode(b64).ok_or(CryptoError::BadBase64)?;
    if psk.len() < MIN_PSK_LEN {
        return Err(CryptoError::PskTooShort {
            got: psk.len(),
            min: MIN_PSK_LEN,
        });
    }
    Ok(psk)
}

/// Standard base64 decode (RFC 4648, `=`-padded). Hand-rolled to avoid a dependency, matching the
/// repo's hand-rolled-codec convention (cf. `shadowsocks/crypto.rs`).
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let s = s.trim().as_bytes();
    if s.is_empty() || s.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for chunk in s.chunks(4) {
        let pad = chunk.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 {
            return None;
        }
        let mut acc = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            let v = if c == b'=' {
                if i < 4 - pad {
                    return None; // '=' before the padding region
                }
                0
            } else {
                val(c)?
            };
            acc = (acc << 6) | v as u32;
        }
        out.push((acc >> 16) as u8);
        if pad < 2 {
            out.push((acc >> 8) as u8);
        }
        if pad < 1 {
            out.push(acc as u8);
        }
    }
    Some(out)
}

/// The per-session key material derived from the PSK, session salt, and ConnectionID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionKeys {
    /// Client→server (uplink) AEAD key.
    pub up: [u8; KEY_LEN],
    /// Server→client (downlink) AEAD key.
    pub down: [u8; KEY_LEN],
    /// Handshake AEAD key (SYN / SYN-ACK).
    pub handshake: [u8; KEY_LEN],
    /// Key-commitment value (prepended to the first frame to avoid AEAD partitioning ambiguity).
    pub commit: [u8; COMMIT_LEN],
}

/// Derive the per-session keys (ADR 0011 §2.4). Deterministic in `(psk, salt, conn_id)`.
pub fn derive_session_keys(
    psk: &[u8],
    salt: &[u8; SALT_LEN],
    conn_id: &[u8; CONN_ID_LEN],
) -> SessionKeys {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(psk);
    SessionKeys {
        up: expand::<KEY_LEN>(&prk, &[HKDF_BASE, b" up", conn_id]),
        down: expand::<KEY_LEN>(&prk, &[HKDF_BASE, b" down", conn_id]),
        handshake: expand::<KEY_LEN>(&prk, &[HKDF_BASE, b" hs", conn_id]),
        commit: expand::<COMMIT_LEN>(&prk, &[HKDF_BASE, b" commit", conn_id]),
    }
}

/// HKDF-Expand `prk` with `info` into an `N`-byte array. Infallible for the small `N` used here
/// (32 / 16, far under HKDF's 255·HashLen cap), so the two `ring` calls cannot fail — this runs at
/// session setup, not on the data path.
fn expand<const N: usize>(prk: &hkdf::Prk, info: &[&[u8]]) -> [u8; N] {
    struct Len<const M: usize>;
    impl<const M: usize> hkdf::KeyType for Len<M> {
        fn len(&self) -> usize {
            M
        }
    }
    let okm = prk
        .expand(info, Len::<N>)
        .expect("HKDF-SHA256 expand within the 255*HashLen cap");
    let mut out = [0u8; N];
    okm.fill(&mut out)
        .expect("okm length matches the output buffer");
    out
}

/// An AEAD keyed by a 32-byte session key. The caller supplies the 12-byte nonce per operation
/// (we use a fresh random nonce per DNS message — the datagram-correct construction over a
/// reordering/dropping carrier), so `ring::aead::LessSafeKey` is the right primitive.
pub struct Aead(aead::LessSafeKey);

impl Aead {
    /// Build the AEAD for `cipher` from a 32-byte `key`.
    pub fn new(cipher: Cipher, key: &[u8; KEY_LEN]) -> Result<Self, CryptoError> {
        let unbound =
            aead::UnboundKey::new(cipher.algorithm(), key).map_err(|_| CryptoError::KeySetup)?;
        Ok(Aead(aead::LessSafeKey::new(unbound)))
    }

    /// Seal in place with empty AAD: `buf` becomes ciphertext ‖ 16-byte tag. Nonce uniqueness is the
    /// caller's contract (a fresh random nonce per message).
    pub fn seal(&self, nonce: &[u8; NONCE_LEN], buf: &mut Vec<u8>) {
        // Infallible for a valid key/nonce (mirrors the in-repo shadowsocks idiom); documented so.
        self.0
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(*nonce),
                aead::Aad::empty(),
                buf,
            )
            .expect("ring seal is infallible for a valid key and nonce");
    }

    /// Open in place with empty AAD: `buf` is ciphertext ‖ tag; returns the plaintext slice.
    pub fn open<'a>(
        &self,
        nonce: &[u8; NONCE_LEN],
        buf: &'a mut [u8],
    ) -> Result<&'a [u8], CryptoError> {
        // `open_in_place` yields `&mut [u8]`; binding then `Ok(plain)` applies the &mut→& coercion
        // (it does not fire through the `Result` if returned directly from the `.map_err` chain).
        let plain = self
            .0
            .open_in_place(
                aead::Nonce::assume_unique_for_key(*nonce),
                aead::Aad::empty(),
                buf,
            )
            .map_err(|_| CryptoError::Auth)?;
        Ok(plain)
    }
}

/// Fill `buf` with cryptographically-secure random bytes.
pub fn fill_random(buf: &mut [u8]) -> Result<(), CryptoError> {
    SystemRandom::new().fill(buf).map_err(|_| CryptoError::Rng)
}

/// A fresh random 12-byte AEAD nonce.
pub fn random_nonce() -> Result<[u8; NONCE_LEN], CryptoError> {
    let mut n = [0u8; NONCE_LEN];
    fill_random(&mut n)?;
    Ok(n)
}

/// A fresh random 8-byte ConnectionID (the client picks this; the server keys its session table on it).
pub fn random_conn_id() -> Result<[u8; CONN_ID_LEN], CryptoError> {
    let mut id = [0u8; CONN_ID_LEN];
    fill_random(&mut id)?;
    Ok(id)
}

/// A fresh random 16-byte per-session HKDF salt.
pub fn random_salt() -> Result<[u8; SALT_LEN], CryptoError> {
    let mut s = [0u8; SALT_LEN];
    fill_random(&mut s)?;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_psk_accepts_valid_and_rejects_short_or_nonbase64() {
        // 32 'A' bytes, base64-encoded ("QUFB..." → 32 bytes of 0x41). 32 bytes / 3 → 44 b64 chars.
        let b64_32 = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=";
        let psk = decode_psk(b64_32).unwrap();
        assert_eq!(psk.len(), 32);
        assert!(psk.iter().all(|&b| b == 0x41));
        // Too short (16 bytes) is rejected.
        assert!(matches!(
            decode_psk("QUFBQUFBQUFBQUFBQUFBQQ=="),
            Err(CryptoError::PskTooShort { got: 16, min: 32 })
        ));
        // Non-base64 is rejected.
        assert!(matches!(
            decode_psk("not valid base64 !!!"),
            Err(CryptoError::BadBase64)
        ));
    }

    #[test]
    fn base64_decode_matches_known_vector() {
        // "Man" → "TWFu"; "hello world" → "aGVsbG8gd29ybGQ=".
        assert_eq!(base64_decode("TWFu").unwrap(), b"Man");
        assert_eq!(base64_decode("aGVsbG8gd29ybGQ=").unwrap(), b"hello world");
        assert!(base64_decode("").is_none());
    }

    #[test]
    fn session_keys_are_deterministic_distinct_and_sensitive() {
        let psk = [7u8; 40];
        let salt = [9u8; SALT_LEN];
        let conn = [3u8; CONN_ID_LEN];

        let k1 = derive_session_keys(&psk, &salt, &conn);
        let k2 = derive_session_keys(&psk, &salt, &conn);
        assert_eq!(k1, k2, "deterministic in (psk, salt, conn_id)");

        // The three keys + commitment are independent.
        assert_ne!(k1.up, k1.down);
        assert_ne!(k1.up, k1.handshake);
        assert_ne!(k1.down, k1.handshake);

        // Changing the salt changes every key.
        let mut salt2 = salt;
        salt2[0] ^= 0xff;
        let k3 = derive_session_keys(&psk, &salt2, &conn);
        assert_ne!(k1.up, k3.up);
        assert_ne!(k1.down, k3.down);

        // Changing the ConnectionID changes every key.
        let mut conn2 = conn;
        conn2[0] ^= 0xff;
        let k4 = derive_session_keys(&psk, &salt, &conn2);
        assert_ne!(k1.up, k4.up);
    }

    #[test]
    fn aead_round_trips_for_both_ciphers() {
        for cipher in [Cipher::ChaCha20Poly1305, Cipher::Aes256Gcm] {
            let key = [5u8; KEY_LEN];
            let aead = Aead::new(cipher, &key).unwrap();
            let nonce = [1u8; NONCE_LEN];
            let plain = b"the quick brown fox".to_vec();
            let mut buf = plain.clone();
            aead.seal(&nonce, &mut buf);
            assert_eq!(buf.len(), plain.len() + TAG_LEN);
            let opened = aead.open(&nonce, &mut buf).unwrap();
            assert_eq!(opened, &plain[..]);
        }
    }

    #[test]
    fn aead_open_rejects_tamper_and_wrong_nonce() {
        let key = [5u8; KEY_LEN];
        let aead = Aead::new(Cipher::ChaCha20Poly1305, &key).unwrap();
        let nonce = [2u8; NONCE_LEN];
        let mut buf = b"secret".to_vec();
        aead.seal(&nonce, &mut buf);

        // Flip a ciphertext byte → auth failure.
        let mut tampered = buf.clone();
        tampered[0] ^= 0x80;
        assert!(matches!(
            aead.open(&nonce, &mut tampered),
            Err(CryptoError::Auth)
        ));

        // Wrong nonce → auth failure.
        let wrong = [3u8; NONCE_LEN];
        let mut buf2 = buf.clone();
        assert!(matches!(
            aead.open(&wrong, &mut buf2),
            Err(CryptoError::Auth)
        ));
    }

    #[test]
    fn keys_from_derive_actually_decrypt() {
        // End-to-end: derive keys, seal with `up`, open with `up`.
        let psk = [0xABu8; 32];
        let salt = random_salt().unwrap();
        let conn = random_conn_id().unwrap();
        let keys = derive_session_keys(&psk, &salt, &conn);
        let up = Aead::new(Cipher::ChaCha20Poly1305, &keys.up).unwrap();
        let nonce = random_nonce().unwrap();
        let mut buf = b"uplink frame".to_vec();
        up.seal(&nonce, &mut buf);
        assert_eq!(up.open(&nonce, &mut buf).unwrap(), b"uplink frame");
    }

    #[test]
    fn random_helpers_are_sized_and_vary() {
        let a = random_nonce().unwrap();
        let b = random_nonce().unwrap();
        assert_eq!(a.len(), NONCE_LEN);
        assert_ne!(a, b, "two random nonces should differ (probabilistic)");
        assert_eq!(random_conn_id().unwrap().len(), CONN_ID_LEN);
        assert_eq!(random_salt().unwrap().len(), SALT_LEN);
    }
}
