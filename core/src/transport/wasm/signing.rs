//! Verified loading of delivered transform modules (ADR 0003, decision point 4).
//!
//! A dynamic transport is foreign code delivered out-of-band, so it must be authenticated before it
//! is trusted. Every module ships as a **signed artifact**: a small manifest (magic, version, name,
//! wasm) plus a detached **Ed25519** signature over that manifest. [`ModuleVerifier`] checks the
//! signature against a public key **pinned in the signed binary**, enforces a monotonic version
//! floor (anti-rollback — a correctly-signed *old* module is still an attack), and only then compiles
//! the wasm. lantern-water's SHA-256-only integrity check is insufficient for this; a hash proves the
//! bytes arrived intact, not that *we* authored them.
//!
//! # Artifact layout
//!
//! ```text
//! ┌─────────── signed payload (the signature covers exactly this) ───────────┐
//! │ MAGIC "SPKW" │ version: u32 BE │ name_len: u16 BE │ name │ wasm_len: u32 BE │ wasm │
//! └──────────────────────────────────────────────────────────────────────────┘ signature: 64 bytes
//! ```
//!
//! Signing happens in trusted tooling (which holds the private key); this module only **assembles**
//! ([`signing_payload`], [`build_artifact`]) and **verifies**. The private key never lives here.

use ring::signature::{UnparsedPublicKey, ED25519};

use super::{TransformModule, WasmError};

/// Artifact magic ("spark wasm").
const MAGIC: &[u8; 4] = b"SPKW";
/// Ed25519 signature length.
const SIG_LEN: usize = 64;
/// Ed25519 public-key length.
const PUBKEY_LEN: usize = 32;
/// Smallest possible artifact: the fixed header (magic+version+name_len+wasm_len) with an empty name
/// and empty wasm, plus the trailing signature.
const MIN_ARTIFACT_LEN: usize = 4 + 4 + 2 + 4 + SIG_LEN;

/// Errors from verifying or loading a signed module artifact.
#[derive(Debug, thiserror::Error)]
pub enum ModuleError {
    /// The artifact is shorter than a well-formed artifact can be, or a length field runs past the
    /// end of the (authenticated) payload.
    #[error("signed module artifact is truncated or malformed")]
    Truncated,
    /// The payload does not start with the expected magic.
    #[error("not a spark wasm module artifact (bad magic)")]
    BadMagic,
    /// The Ed25519 signature did not verify against the pinned public key.
    #[error("Ed25519 signature verification failed")]
    BadSignature,
    /// The module name was not valid UTF-8.
    #[error("module name is not valid UTF-8")]
    BadName,
    /// The module's version is older than the installed floor (a rollback attack).
    #[error(
        "rollback rejected: module version {version} is older than the installed floor {floor}"
    )]
    Rollback {
        /// The version carried by the artifact.
        version: u32,
        /// The anti-rollback floor the caller required.
        floor: u32,
    },
    /// The (authenticated) wasm failed to compile.
    #[error(transparent)]
    Compile(#[from] WasmError),
}

/// A verified, compiled module together with its authenticated identity. The caller uses
/// [`SignedModule::version`] to advance its anti-rollback floor.
pub struct SignedModule {
    name: String,
    version: u32,
    module: TransformModule,
}

impl SignedModule {
    /// The module's authenticated name (e.g. a transport identifier).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The module's authenticated, monotonic version.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The compiled module, ready to [`TransformModule::instantiate`].
    pub fn module(&self) -> &TransformModule {
        &self.module
    }

    /// Consume the wrapper, yielding the compiled module.
    pub fn into_module(self) -> TransformModule {
        self.module
    }
}

/// Verifies delivered module artifacts against an Ed25519 public key pinned at build time.
///
/// In production the key is a compile-time constant baked into the signed binary; pass it to
/// [`ModuleVerifier::new`]. The verifier holds only the public key — never a private key.
pub struct ModuleVerifier {
    public_key: [u8; PUBKEY_LEN],
}

impl ModuleVerifier {
    /// Create a verifier for the given pinned Ed25519 public key (raw 32 bytes).
    pub fn new(public_key: [u8; PUBKEY_LEN]) -> Self {
        Self { public_key }
    }

    /// Verify, parse, and compile a signed module `artifact`.
    ///
    /// `min_version` is the anti-rollback floor — the highest module version installed so far; an
    /// artifact carrying a lower version is rejected. The signature is checked over the whole payload
    /// **before** any field is parsed, so the length-prefixed `name`/`wasm` fields are authenticated
    /// before they are acted on.
    pub fn verify(&self, artifact: &[u8], min_version: u32) -> Result<SignedModule, ModuleError> {
        if artifact.len() < MIN_ARTIFACT_LEN {
            return Err(ModuleError::Truncated);
        }
        let (payload, signature) = artifact.split_at(artifact.len() - SIG_LEN);

        // 1. Authenticate the entire payload before trusting any byte of it.
        UnparsedPublicKey::new(&ED25519, &self.public_key)
            .verify(payload, signature)
            .map_err(|_| ModuleError::BadSignature)?;

        // 2. Parse the now-authenticated payload.
        let (name, version, wasm) = parse_payload(payload)?;

        // 3. Reject rollbacks (a correctly-signed but stale module).
        if version < min_version {
            return Err(ModuleError::Rollback {
                version,
                floor: min_version,
            });
        }

        // 4. Compile.
        let module = TransformModule::load(wasm)?;
        Ok(SignedModule {
            name: name.to_string(),
            version,
            module,
        })
    }
}

/// Assemble the bytes a signature must cover: `MAGIC || version || name || wasm`. The detached
/// signature over this is appended to form a full artifact ([`build_artifact`]).
pub fn signing_payload(name: &str, version: u32, wasm: &[u8]) -> Vec<u8> {
    let name = name.as_bytes();
    let mut out = Vec::with_capacity(4 + 4 + 2 + name.len() + 4 + wasm.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&(name.len() as u16).to_be_bytes());
    out.extend_from_slice(name);
    out.extend_from_slice(&(wasm.len() as u32).to_be_bytes());
    out.extend_from_slice(wasm);
    out
}

/// Assemble a complete signed artifact from its parts. `signature` must be the detached Ed25519
/// signature over `signing_payload(name, version, wasm)`.
pub fn build_artifact(name: &str, version: u32, wasm: &[u8], signature: &[u8; SIG_LEN]) -> Vec<u8> {
    let mut out = signing_payload(name, version, wasm);
    out.extend_from_slice(signature);
    out
}

/// Parse an authenticated payload into `(name, version, wasm)`. All lengths are bounds-checked
/// against the payload, so a length running past the end is a [`ModuleError::Truncated`].
fn parse_payload(payload: &[u8]) -> Result<(&str, u32, &[u8]), ModuleError> {
    let mut cur = payload;
    if take(&mut cur, 4)? != MAGIC {
        return Err(ModuleError::BadMagic);
    }
    let version = take_u32(&mut cur)?;
    let name_len = take_u16(&mut cur)? as usize;
    let name = std::str::from_utf8(take(&mut cur, name_len)?).map_err(|_| ModuleError::BadName)?;
    let wasm_len = take_u32(&mut cur)? as usize;
    let wasm = take(&mut cur, wasm_len)?;
    if !cur.is_empty() {
        return Err(ModuleError::Truncated); // trailing bytes the layout doesn't account for
    }
    Ok((name, version, wasm))
}

/// Split `n` bytes off the front of `cur`, advancing it. Errors if fewer than `n` remain.
fn take<'a>(cur: &mut &'a [u8], n: usize) -> Result<&'a [u8], ModuleError> {
    if cur.len() < n {
        return Err(ModuleError::Truncated);
    }
    let (head, tail) = cur.split_at(n);
    *cur = tail;
    Ok(head)
}

/// Read a big-endian `u32` off the front of `cur`.
fn take_u32(cur: &mut &[u8]) -> Result<u32, ModuleError> {
    let b = take(cur, 4)?;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Read a big-endian `u16` off the front of `cur`.
fn take_u16(cur: &mut &[u8]) -> Result<u16, ModuleError> {
    let b = take(cur, 2)?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

#[cfg(test)]
mod tests {
    use super::super::testutil::XOR_WAT;
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn keypair() -> Ed25519KeyPair {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate key");
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse key")
    }

    fn public_key(kp: &Ed25519KeyPair) -> [u8; 32] {
        let mut k = [0u8; 32];
        k.copy_from_slice(kp.public_key().as_ref());
        k
    }

    /// Sign `(name, version, wasm)` with `kp` and return the full artifact.
    fn sign(kp: &Ed25519KeyPair, name: &str, version: u32, wasm: &[u8]) -> Vec<u8> {
        let signature = kp.sign(&signing_payload(name, version, wasm));
        let mut sig = [0u8; 64];
        sig.copy_from_slice(signature.as_ref());
        build_artifact(name, version, wasm, &sig)
    }

    fn xor_wasm() -> Vec<u8> {
        wat::parse_str(XOR_WAT).expect("assemble fixture")
    }

    #[test]
    fn verifies_and_loads_a_signed_module() {
        let kp = keypair();
        let artifact = sign(&kp, "obfs-xor", 7, &xor_wasm());
        let signed = ModuleVerifier::new(public_key(&kp))
            .verify(&artifact, 0)
            .expect("verify");
        assert_eq!(signed.name(), "obfs-xor");
        assert_eq!(signed.version(), 7);
        // The verified module is the real, working module.
        let mut t = signed.module().instantiate().expect("instantiate");
        let wire = t.transform_out(b"hi there").expect("out");
        assert_eq!(t.transform_in(&wire).expect("in"), b"hi there");
    }

    #[test]
    fn rejects_tampered_wasm() {
        let kp = keypair();
        let mut artifact = sign(&kp, "obfs", 1, &xor_wasm());
        let idx = artifact.len() - 64 - 8; // a byte inside the wasm region
        artifact[idx] ^= 0xff;
        assert!(matches!(
            ModuleVerifier::new(public_key(&kp)).verify(&artifact, 0),
            Err(ModuleError::BadSignature)
        ));
    }

    #[test]
    fn rejects_a_different_key() {
        let signer = keypair();
        let attacker_view = keypair();
        let artifact = sign(&signer, "obfs", 1, &xor_wasm());
        assert!(matches!(
            ModuleVerifier::new(public_key(&attacker_view)).verify(&artifact, 0),
            Err(ModuleError::BadSignature)
        ));
    }

    #[test]
    fn rejects_rollback_but_accepts_current_and_newer() {
        let kp = keypair();
        let artifact = sign(&kp, "obfs", 3, &xor_wasm());
        let verifier = ModuleVerifier::new(public_key(&kp));
        // Floor 5: a v3 module is a rollback.
        assert!(matches!(
            verifier.verify(&artifact, 5),
            Err(ModuleError::Rollback {
                version: 3,
                floor: 5
            })
        ));
        // Floor 3 (re-install of the current version) and floor 0 (older floor) are accepted.
        assert!(verifier.verify(&artifact, 3).is_ok());
        assert!(verifier.verify(&artifact, 0).is_ok());
    }

    #[test]
    fn rejects_truncated_artifact() {
        let kp = keypair();
        assert!(matches!(
            ModuleVerifier::new(public_key(&kp)).verify(b"too short", 0),
            Err(ModuleError::Truncated)
        ));
    }

    #[test]
    fn rejects_bad_magic_even_when_correctly_signed() {
        // A correctly-signed payload whose magic is wrong must reach BadMagic — proving the parse
        // runs on authenticated bytes (signature checked first), not that magic gates the signature.
        let kp = keypair();
        let mut payload = b"XXXX".to_vec();
        payload.extend_from_slice(&1u32.to_be_bytes());
        payload.extend_from_slice(&0u16.to_be_bytes()); // name_len 0
        payload.extend_from_slice(&0u32.to_be_bytes()); // wasm_len 0
        let signature = kp.sign(&payload);
        let mut artifact = payload;
        artifact.extend_from_slice(signature.as_ref());
        assert!(matches!(
            ModuleVerifier::new(public_key(&kp)).verify(&artifact, 0),
            Err(ModuleError::BadMagic)
        ));
    }
}
