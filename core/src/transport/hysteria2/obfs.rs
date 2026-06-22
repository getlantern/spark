//! Salamander XOR obfuscation and Gecko handshake-fragmentation layer.
//!
//! # Salamander
//! Prepends an 8-byte random salt to the datagram and XORs the payload with a repeating
//! BLAKE2b-256(key ‖ salt) keystream (32-byte block, repeated), per the Hysteria 2 spec
//! §Salamander.

// Consumed by SalamanderGeckoSocket (Task 4); remove at the final sweep.
#![allow(dead_code)]

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

type Blake2b256 = Blake2b<U32>;

/// BLAKE2b with a 256-bit (32-byte) output.
fn blake2b256(input: &[u8]) -> [u8; 32] {
    let mut h = Blake2b256::new();
    h.update(input);
    h.finalize().into()
}

const SALT_LEN: usize = 8;

/// Salamander: prepend an 8-byte random salt and XOR the packet with the BLAKE2b-256(key‖salt)
/// keystream (repeating every 32 bytes), per the Hysteria 2 spec §Salamander.
pub fn salamander_obfuscate(key: &[u8], packet: &[u8]) -> Vec<u8> {
    let mut salt = [0u8; SALT_LEN];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut salt).expect("OS RNG"); // infallible-in-practice OS CSRNG; per-packet hot path, unrecoverable on failure
    let mut payload = packet.to_vec();
    salamander_xor_with_salt(key, &salt, &mut payload);
    let mut out = Vec::with_capacity(SALT_LEN + payload.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&payload);
    out
}

/// Reverse of [`salamander_obfuscate`]. Returns `None` if the datagram is too short to carry a salt.
pub fn salamander_deobfuscate(key: &[u8], datagram: &[u8]) -> Option<Vec<u8>> {
    if datagram.len() < SALT_LEN {
        return None;
    }
    let (salt, body) = datagram.split_at(SALT_LEN);
    let salt: [u8; SALT_LEN] = salt.try_into().ok()?;
    let mut payload = body.to_vec();
    salamander_xor_with_salt(key, &salt, &mut payload);
    Some(payload)
}

/// XOR `payload` in place with the BLAKE2b-256(key‖salt) keystream (32-byte block, repeated).
fn salamander_xor_with_salt(key: &[u8], salt: &[u8; SALT_LEN], payload: &mut [u8]) {
    let mut material = Vec::with_capacity(key.len() + SALT_LEN);
    material.extend_from_slice(key);
    material.extend_from_slice(salt);
    let hash = blake2b256(&material);
    for (i, b) in payload.iter_mut().enumerate() {
        *b ^= hash[i % 32];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn salamander_round_trips() {
        let key = b"presharedkey";
        let packet = b"a fake QUIC packet payload";
        let on_wire = salamander_obfuscate(key, packet);
        assert_eq!(on_wire.len(), 8 + packet.len()); // salt + xored
        let back = salamander_deobfuscate(key, &on_wire).unwrap();
        assert_eq!(back.as_slice(), packet.as_ref());
    }

    #[test]
    fn salamander_rejects_too_short() {
        assert!(salamander_deobfuscate(b"k", &[0u8; 4]).is_none()); // < 8-byte salt
    }

    #[test]
    fn salamander_keystream_matches_blake2b() {
        // hash = BLAKE2b-256(key ‖ salt); payload[i] ^= hash[i % 32]
        let key: &[u8] = b"k";
        let salt = [9u8; 8];
        let mut p = vec![0u8; 40]; // XOR of zeros yields the raw keystream
        salamander_xor_with_salt(key, &salt, &mut p);
        let expected = blake2b256(&[key, &salt].concat());
        for i in 0..p.len() {
            assert_eq!(p[i], expected[i % 32]);
        }
    }
}
