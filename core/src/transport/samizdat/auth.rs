//! Samizdat REALITY-style authentication: the 32-byte TLS `legacy_session_id` the client stamps
//! and the server reads to authenticate (otherwise it masquerades to the cover site).
//!
//! Layout + crypto match `getlantern/samizdat`'s `auth.go` exactly:
//!
//! ```text
//! PSK       = HKDF-SHA256(ikm = serverPubKey, salt = shortID, info = "SAMIZDAT")   (32 bytes)
//! SessionID = shortID(8) ‖ nonce(8) ‖ HMAC-SHA256(PSK, nonce)[:16]                 (32 bytes)
//! ```
//!
//! There is no client-side ECDH — the server's public-key *bytes* are the HKDF IKM directly.

use ring::rand::{SecureRandom, SystemRandom};
use ring::{hkdf, hmac};

/// HKDF info label (samizdat `auth.go` `authLabel`).
const AUTH_LABEL: &[u8] = b"SAMIZDAT";
/// Short-ID length, in bytes.
pub const SHORT_ID_LEN: usize = 8;
/// Auth-nonce length, in bytes.
const NONCE_LEN: usize = 8;
/// Truncated HMAC-SHA256 tag length packed into the SessionID.
const TAG_LEN: usize = 16;
/// TLS SessionID length.
pub const SESSION_ID_LEN: usize = 32;

/// 32-byte output-length marker for ring's HKDF `Prk::expand`.
struct PskLen;
impl hkdf::KeyType for PskLen {
    fn len(&self) -> usize {
        32
    }
}

/// Derive the pre-shared key from the server's public key and a short ID
/// (samizdat `derivePSK`): HKDF-SHA256 with the public key as IKM, the short ID as salt,
/// and `"SAMIZDAT"` as info.
pub fn derive_psk(server_pubkey: &[u8], short_id: &[u8; SHORT_ID_LEN]) -> [u8; 32] {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, short_id).extract(server_pubkey);
    // Infallible by construction: a 32-byte output is far under HKDF's 255·HashLen cap and the
    // fill buffer length matches `PskLen`, so neither call can fail short of a ring invariant break.
    let okm = prk
        .expand(&[AUTH_LABEL], PskLen)
        .expect("HKDF-SHA256 expand to 32 bytes");
    let mut psk = [0u8; 32];
    okm.fill(&mut psk).expect("okm length matches the buffer");
    psk
}

/// Build the SessionID for a specific `nonce` (deterministic; [`session_id`] is the random-nonce
/// production entry point).
fn session_id_with_nonce(
    server_pubkey: &[u8],
    short_id: &[u8; SHORT_ID_LEN],
    nonce: &[u8; NONCE_LEN],
) -> [u8; SESSION_ID_LEN] {
    let psk = derive_psk(server_pubkey, short_id);
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &psk), nonce);
    let mut out = [0u8; SESSION_ID_LEN];
    out[..SHORT_ID_LEN].copy_from_slice(short_id);
    out[SHORT_ID_LEN..SHORT_ID_LEN + NONCE_LEN].copy_from_slice(nonce);
    out[SHORT_ID_LEN + NONCE_LEN..].copy_from_slice(&tag.as_ref()[..TAG_LEN]);
    out
}

/// Build a fresh SessionID with a random nonce (the production entry point).
pub fn session_id(
    server_pubkey: &[u8],
    short_id: &[u8; SHORT_ID_LEN],
) -> Result<[u8; SESSION_ID_LEN], ring::error::Unspecified> {
    let mut nonce = [0u8; NONCE_LEN];
    SystemRandom::new().fill(&mut nonce)?;
    Ok(session_id_with_nonce(server_pubkey, short_id, &nonce))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Authoritative vectors captured from getlantern/samizdat (`auth.go`) and cross-checked through
    // the package's own `VerifySessionID` (ok=true). Generator: /tmp/sz-vec.
    fn server_pubkey() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = 0xA0 + i as u8;
        }
        k
    }
    const SHORT_ID: [u8; 8] = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
    const NONCE: [u8; 8] = [0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27];
    // 662ff27f66e971c501dea3c286aca61b35fcf5cdffef623c35506923014e7742
    const PSK: [u8; 32] = [
        0x66, 0x2f, 0xf2, 0x7f, 0x66, 0xe9, 0x71, 0xc5, 0x01, 0xde, 0xa3, 0xc2, 0x86, 0xac, 0xa6,
        0x1b, 0x35, 0xfc, 0xf5, 0xcd, 0xff, 0xef, 0x62, 0x3c, 0x35, 0x50, 0x69, 0x23, 0x01, 0x4e,
        0x77, 0x42,
    ];
    // 101112131415161720212223242526279bd1c54a7fda9aa75cf628740af4bc23
    const SESSION_ID: [u8; 32] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
        0x27, 0x9b, 0xd1, 0xc5, 0x4a, 0x7f, 0xda, 0x9a, 0xa7, 0x5c, 0xf6, 0x28, 0x74, 0x0a, 0xf4,
        0xbc, 0x23,
    ];

    #[test]
    fn derive_psk_matches_samizdat_vector() {
        assert_eq!(derive_psk(&server_pubkey(), &SHORT_ID), PSK);
    }

    #[test]
    fn session_id_matches_samizdat_vector() {
        assert_eq!(
            session_id_with_nonce(&server_pubkey(), &SHORT_ID, &NONCE),
            SESSION_ID
        );
    }

    #[test]
    fn random_session_id_carries_short_id_and_recomputes() {
        let sid = session_id(&server_pubkey(), &SHORT_ID).expect("rng");
        // shortID is the plaintext prefix the server uses to look up the PSK.
        assert_eq!(&sid[..SHORT_ID_LEN], &SHORT_ID);
        // The embedded nonce must reproduce the same SessionID deterministically.
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&sid[SHORT_ID_LEN..SHORT_ID_LEN + NONCE_LEN]);
        assert_eq!(
            session_id_with_nonce(&server_pubkey(), &SHORT_ID, &nonce),
            sid
        );
    }
}
