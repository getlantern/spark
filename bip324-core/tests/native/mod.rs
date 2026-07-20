//! A native [`Bip324Crypto`] provider backing the protocol logic with real crypto (secp256k1 + ring +
//! chacha20), used only to validate `bip324-core` against the official vectors and the rust-bitcoin
//! reference. It mirrors the WASM host's `env` primitives (`core/src/transport/wasm/mod.rs`).
#![allow(dead_code)]

use bip324_core::crypto::Bip324Crypto;

use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use ring::rand::{SecureRandom, SystemRandom};
use ring::{digest, hmac};
use secp256k1::ellswift::{ElligatorSwift, ElligatorSwiftSharedSecret, Party};
use secp256k1::{All, Secp256k1, SecretKey};

pub struct NativeCrypto {
    secp: Secp256k1<All>,
    rng: SystemRandom,
}

impl NativeCrypto {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            secp: Secp256k1::new(),
            rng: SystemRandom::new(),
        }
    }

    /// Build an ephemeral from known bytes — for the deterministic KAT vectors (real keygen is random).
    pub fn ephemeral_from_parts(
        &self,
        priv_bytes: [u8; 32],
        ellswift: [u8; 64],
    ) -> (SecretKey, ElligatorSwift) {
        let sk = SecretKey::from_byte_array(priv_bytes).expect("valid test scalar");
        (sk, ElligatorSwift::from_array(ellswift))
    }
}

impl Bip324Crypto for NativeCrypto {
    type Ephemeral = (SecretKey, ElligatorSwift);

    fn ellswift_generate(&mut self) -> (Self::Ephemeral, [u8; 64]) {
        loop {
            let mut seed = [0u8; 64];
            self.rng.fill(&mut seed).expect("csprng");
            let mut sk_bytes = [0u8; 32];
            sk_bytes.copy_from_slice(&seed[..32]);
            if let Ok(sk) = SecretKey::from_byte_array(sk_bytes) {
                let mut aux = [0u8; 32];
                aux.copy_from_slice(&seed[32..]);
                let ell = ElligatorSwift::from_seckey(&self.secp, sk, Some(aux));
                return ((sk, ell), ell.to_array());
            }
        }
    }

    fn ellswift_ecdh(&mut self, key: Self::Ephemeral, peer: &[u8; 64]) -> [u8; 32] {
        let (sk, own_ell) = key;
        let shared = ElligatorSwift::shared_secret_with_hasher(
            own_ell,
            ElligatorSwift::from_array(*peer),
            sk,
            Party::Initiator,
            |x, _own, _peer| ElligatorSwiftSharedSecret::from_secret_bytes(x),
        );
        *shared.as_secret_bytes()
    }

    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        let d = digest::digest(&digest::SHA256, data);
        let mut out = [0u8; 32];
        out.copy_from_slice(d.as_ref());
        out
    }

    fn hkdf_extract(&self, salt: &[u8], ikm: &[u8]) -> [u8; 32] {
        let key = hmac::Key::new(hmac::HMAC_SHA256, salt);
        let tag = hmac::sign(&key, ikm);
        let mut out = [0u8; 32];
        out.copy_from_slice(tag.as_ref());
        out
    }

    fn hkdf_expand(&self, prk: &[u8; 32], info: &[u8], out: &mut [u8]) {
        // RFC 5869 HKDF-Expand over HMAC-SHA256 (matches the reference `hkdf_sha256`).
        let key = hmac::Key::new(hmac::HMAC_SHA256, prk);
        let mut t: Vec<u8> = Vec::new();
        let mut pos = 0;
        let mut i = 1u8;
        while pos < out.len() {
            let mut ctx = hmac::Context::with_key(&key);
            ctx.update(&t);
            ctx.update(info);
            ctx.update(&[i]);
            t = ctx.sign().as_ref().to_vec();
            let n = core::cmp::min(t.len(), out.len() - pos);
            out[pos..pos + n].copy_from_slice(&t[..n]);
            pos += n;
            i += 1;
        }
    }

    fn chacha20_apply(&self, key: &[u8; 32], nonce: &[u8; 12], counter: u32, buf: &mut [u8]) {
        let mut c = ChaCha20::new_from_slices(key, nonce).expect("chacha20 key/nonce");
        c.seek((counter as u64) * 64);
        c.apply_keystream(buf);
    }

    fn aead_seal(&self, key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let lsk = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, key).expect("aead key"));
        let mut in_out = plaintext.to_vec();
        lsk.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(*nonce),
            Aad::from(aad),
            &mut in_out,
        )
        .expect("seal");
        in_out
    }

    fn aead_open(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Option<Vec<u8>> {
        let lsk = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, key).expect("aead key"));
        let mut in_out = ciphertext.to_vec();
        lsk.open_in_place(
            Nonce::assume_unique_for_key(*nonce),
            Aad::from(aad),
            &mut in_out,
        )
        .ok()
        .map(|pt| pt.to_vec())
    }

    fn fill_random(&mut self, out: &mut [u8]) {
        self.rng.fill(out).expect("csprng");
    }
}
