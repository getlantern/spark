//! AnyTLS client auth — the first bytes the client sends after the TLS handshake.
//!
//! ```text
//! sha256(password)(32) | padding0 length(2, big-endian) | padding0
//! ```
//!
//! `padding0` is initial padding (AnyTLS recommends zero bytes); in a full client it is the
//! packet-0 chunk of the [`super::padding`] scheme. The server recomputes `sha256(password)` to
//! authenticate, or falls back to a cover service on mismatch. This is "packet 0" and its padding
//! cannot be split. Client-side only (encode); the server verify path is out of scope.

use bytes::{BufMut, BytesMut};
use ring::digest;

/// The SHA-256 password-hash prefix length.
pub const PASSWORD_HASH_LEN: usize = 32;

/// Append the client auth record for `password` (prefixed by `padding0`) to `dst`.
///
/// `padding0` must be ≤ 65535 bytes (the 2-byte length field).
pub fn encode_auth(password: &str, padding0: &[u8], dst: &mut BytesMut) -> Result<(), AuthError> {
    if padding0.len() > u16::MAX as usize {
        return Err(AuthError::PaddingTooLong(padding0.len()));
    }
    let hash = digest::digest(&digest::SHA256, password.as_bytes());
    dst.reserve(PASSWORD_HASH_LEN + 2 + padding0.len());
    dst.put_slice(hash.as_ref()); // exactly PASSWORD_HASH_LEN bytes for SHA-256
    dst.put_u16(padding0.len() as u16);
    dst.put_slice(padding0);
    Ok(())
}

/// Errors from building an auth record.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    /// `padding0` exceeds the 2-byte length field.
    #[error("auth padding0 too long: {0} bytes (max 65535)")]
    PaddingTooLong(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SHA-256("abc") — the canonical FIPS 180-2 test vector.
    const SHA256_ABC: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];

    #[test]
    fn auth_record_layout_and_hash() {
        let mut buf = BytesMut::new();
        encode_auth("abc", &[], &mut buf).unwrap();
        // 32-byte hash + 2-byte length(0) + 0 padding.
        assert_eq!(buf.len(), PASSWORD_HASH_LEN + 2);
        assert_eq!(
            &buf[..PASSWORD_HASH_LEN],
            &SHA256_ABC,
            "sha256(password) prefix"
        );
        assert_eq!(
            &buf[PASSWORD_HASH_LEN..],
            &[0x00, 0x00],
            "big-endian padding0 length 0"
        );
    }

    #[test]
    fn padding0_is_length_prefixed_big_endian() {
        let mut buf = BytesMut::new();
        let pad = [0xABu8; 0x0102];
        encode_auth("secret", &pad, &mut buf).unwrap();
        assert_eq!(buf.len(), PASSWORD_HASH_LEN + 2 + pad.len());
        assert_eq!(
            &buf[PASSWORD_HASH_LEN..PASSWORD_HASH_LEN + 2],
            &[0x01, 0x02]
        );
        assert_eq!(&buf[PASSWORD_HASH_LEN + 2..], &pad);
    }

    #[test]
    fn rejects_oversized_padding() {
        let mut buf = BytesMut::new();
        let pad = vec![0u8; u16::MAX as usize + 1];
        assert_eq!(
            encode_auth("p", &pad, &mut buf),
            Err(AuthError::PaddingTooLong(u16::MAX as usize + 1))
        );
    }
}
