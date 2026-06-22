//! SS-2022 crypto: base64 PSK decode, BLAKE3 subkey derivation, ring AEAD, raw-AES block.

// Items here are consumed by tcp.rs / udp.rs in subsequent tasks; suppress dead-code until then.
#![allow(dead_code)]

use crate::config::SsMethod;

/// Errors from SS-2022 crypto setup.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("password is not valid base64")]
    BadBase64,
    #[error("decoded PSK is {got} bytes but method {method:?} needs {want}")]
    KeyLength {
        method: SsMethod,
        got: usize,
        want: usize,
    },
}

/// Decode the base64 PSK and check its length matches the method (SIP022 §2.1).
pub fn decode_psk(method: SsMethod, password: &str) -> Result<Vec<u8>, CryptoError> {
    let psk = base64_decode(password).ok_or(CryptoError::BadBase64)?;
    let want = method.key_len();
    if psk.len() != want {
        return Err(CryptoError::KeyLength {
            method,
            got: psk.len(),
            want,
        });
    }
    Ok(psk)
}

/// Standard base64 decode (RFC 4648, with `=` padding). Hand-rolled to avoid a dependency, matching
/// the repo's hand-rolled-codec convention (cf. the DNS codec, `decode_hex_n`).
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
    let mut pad_seen = false;
    for chunk in s.chunks(4) {
        if pad_seen {
            return None; // padding may only appear in the final 4-byte group (RFC 4648 §3.3)
        }
        let pad = chunk.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 {
            return None;
        }
        if pad > 0 {
            pad_seen = true;
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

/// Derive the per-session subkey: `blake3::derive_key(context, PSK ‖ salt)`, truncated to the
/// method's key length (SIP022 §2.2).
pub fn session_subkey(method: SsMethod, psk: &[u8], salt: &[u8]) -> Vec<u8> {
    const CONTEXT: &str = "shadowsocks 2022 session subkey";
    let mut key_material = Vec::with_capacity(psk.len() + salt.len());
    key_material.extend_from_slice(psk);
    key_material.extend_from_slice(salt);
    let full = blake3::derive_key(CONTEXT, &key_material); // [u8; 32]
    full[..method.key_len()].to_vec()
}

/// A 96-bit little-endian AEAD nonce counter, incremented after each seal/open (SIP022 §3.1.1).
#[derive(Debug)]
pub struct NonceCounter([u8; 12]);

impl NonceCounter {
    pub fn new() -> Self {
        NonceCounter([0u8; 12])
    }

    /// Return the current nonce, then increment the little-endian counter for next time.
    pub fn next(&mut self) -> [u8; 12] {
        let nonce = self.0;
        for byte in self.0.iter_mut() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
        nonce
    }
}

impl Default for NonceCounter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_psk_validates_length() {
        // "c29tZS0xNi1ieXRlLWtleQ==" decodes to "some-16-byte-key" (16 bytes).
        let psk = decode_psk(SsMethod::Aes128Gcm, "c29tZS0xNi1ieXRlLWtleQ==").unwrap();
        assert_eq!(psk, b"some-16-byte-key");
        // Wrong length for the method is rejected.
        assert!(decode_psk(SsMethod::Aes256Gcm, "c29tZS0xNi1ieXRlLWtleQ==").is_err());
        // Non-base64 is rejected.
        assert!(decode_psk(SsMethod::Aes128Gcm, "not valid base64!!!").is_err());
    }

    #[test]
    fn subkey_is_deterministic_and_method_sized() {
        let psk = [7u8; 32];
        let salt = [9u8; 32];
        let k1 = session_subkey(SsMethod::Aes256Gcm, &psk, &salt);
        let k2 = session_subkey(SsMethod::Aes256Gcm, &psk, &salt);
        assert_eq!(k1, k2);
        assert_eq!(k1.len(), 32);
        // A 16-byte method truncates the 32-byte BLAKE3 output to 16.
        let k128 = session_subkey(SsMethod::Aes128Gcm, &[7u8; 16], &[9u8; 16]);
        assert_eq!(k128.len(), 16);
    }

    #[test]
    fn nonce_counter_increments_little_endian() {
        let mut c = NonceCounter::new();
        assert_eq!(c.next(), [0u8; 12]);
        let mut want = [0u8; 12];
        want[0] = 1;
        assert_eq!(c.next(), want);
    }

    #[test]
    fn nonce_counter_carries_across_a_byte_boundary() {
        let mut c = NonceCounter::new();
        for _ in 0..256 {
            c.next(); // advance through 0..=255, leaving the counter at 256
        }
        let mut want = [0u8; 12];
        want[1] = 1; // 256 little-endian = [0x00, 0x01, 0x00, ...]
        assert_eq!(c.next(), want);
    }

    #[test]
    fn base64_rejects_padding_in_a_non_final_group() {
        assert!(base64_decode("TWE=TWFu").is_none());
    }
}
