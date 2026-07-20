//! The crypto-provider seam. The protocol logic in this crate calls only these primitives; a provider
//! maps them either to the WASM `env` host functions (guest) or to RustCrypto + secp256k1 (native).
//!
//! The set mirrors the host ABI in `core/src/transport/wasm/mod.rs` 1:1, so the WASM provider (PR2) is
//! a mechanical shim: `ellswift_generate`/`ellswift_ecdh` → `host_secp256k1_ellswift_*`, `sha256` →
//! `host_hash`, `hkdf_*` → `host_hkdf_*`, `chacha20_apply` → `host_chacha20`, `aead_*` →
//! `host_aead_seal`/`open`, `fill_random` → `host_rand`.

use alloc::vec::Vec;

use crate::{ECDH_SHARED_LEN, ELLSWIFT_LEN};

/// The primitives BIP324 composes. Deliberately low-level and stateless (except keygen/ECDH/RNG) so
/// both a sandboxed host-fn provider and a native provider satisfy it identically.
pub trait Bip324Crypto {
    /// An in-flight ephemeral secp256k1 key. The secret never leaves the provider — in the WASM provider
    /// it is an opaque host-side key handle, natively a `SecretKey`. Consumed one-shot by
    /// [`Self::ellswift_ecdh`], matching the host's `Option::take` key store.
    type Ephemeral;

    /// Generate an ephemeral secp256k1 keypair; return the handle and its 64-byte ElligatorSwift pubkey.
    fn ellswift_generate(&mut self) -> (Self::Ephemeral, [u8; ELLSWIFT_LEN]);

    /// X-only ECDH: the **raw** shared x-coordinate of `key` × decode(`peer_ellswift`). This is *not*
    /// BIP324's tagged-hash secret — [`crate::ecdh::v2_ecdh`] composes that on top via [`Self::sha256`].
    fn ellswift_ecdh(
        &mut self,
        key: Self::Ephemeral,
        peer_ellswift: &[u8; ELLSWIFT_LEN],
    ) -> [u8; ECDH_SHARED_LEN];

    /// SHA-256 of `data`.
    fn sha256(&self, data: &[u8]) -> [u8; 32];

    /// HKDF-Extract (HMAC-SHA256) → the 32-byte PRK.
    fn hkdf_extract(&self, salt: &[u8], ikm: &[u8]) -> [u8; 32];

    /// HKDF-Expand `out.len()` bytes (≤ 8160) from a 32-byte PRK and `info`.
    fn hkdf_expand(&self, prk: &[u8; 32], info: &[u8], out: &mut [u8]);

    /// XOR `buf` in place with the IETF ChaCha20 keystream for `key`/`nonce` starting at 32-bit block
    /// `counter`. Encryption and decryption are identical; passing a zeroed `buf` yields raw keystream
    /// (used to build the FSChaCha20 length cipher).
    fn chacha20_apply(&self, key: &[u8; 32], nonce: &[u8; 12], counter: u32, buf: &mut [u8]);

    /// ChaCha20-Poly1305 seal (RFC 8439): returns ciphertext with the 16-byte tag appended
    /// (`plaintext.len() + 16` bytes).
    fn aead_seal(&self, key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8>;

    /// ChaCha20-Poly1305 open (RFC 8439): the plaintext, or `None` on authentication failure.
    fn aead_open(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Option<Vec<u8>>;

    /// Fill `out` with cryptographically secure random bytes (garbage / decoy contents).
    fn fill_random(&mut self, out: &mut [u8]);
}
