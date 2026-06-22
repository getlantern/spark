//! SS-2022 TCP: request/response codec + the AsyncRead+AsyncWrite chunk-framing stream.
#![allow(dead_code)] // consumed by ShadowsocksStream (Task 8) + ShadowsocksTransport (Task 12); remove at the final sweep.

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use ring::rand::{SecureRandom, SystemRandom};

use crate::config::SsMethod;

use super::crypto::{session_subkey, Cipher, CryptoError, NonceCounter};
use super::write_socks_addr;

const HEADER_TYPE_CLIENT: u8 = 0;

/// The encoded request prefix plus the salt and the send-side cipher/counter the stream keeps using.
pub struct Request {
    pub bytes: Vec<u8>,
    pub salt: Vec<u8>,
    pub cipher: Cipher,
    pub counter: NonceCounter,
}

/// Current Unix time in seconds (SIP022 timestamps). Mirrors samizdat/session_id.rs.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
    cipher.seal(counter.next(), &mut fixed);
    bytes.extend_from_slice(&fixed);
    cipher.seal(counter.next(), &mut var);
    bytes.extend_from_slice(&var);

    Ok(Request {
        bytes,
        salt,
        cipher,
        counter,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
