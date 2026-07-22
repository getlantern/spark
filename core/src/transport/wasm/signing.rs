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
//! The signature + versioned framing + anti-rollback are the generic [`flint_verify`]
//! `SignedBlobVerifier` (extracted from this module); this file keeps only the WASM-specific layer:
//! the pinned key, and compiling the authenticated payload into a [`TransformModule`]. The artifact
//! layout is flint's, with spark's `SPKW` magic:
//!
//! ```text
//! ┌─────────── signed payload (the signature covers exactly this) ───────────┐
//! │ MAGIC "SPKW" │ version: u32 BE │ name_len: u16 BE │ name │ wasm_len: u32 BE │ wasm │
//! └──────────────────────────────────────────────────────────────────────────┘ signature: 64 bytes
//! ```
//!
//! Signing happens in trusted tooling (which holds the private key); this module only **assembles**
//! ([`signing_payload`], [`build_artifact`]) and **verifies**. The private key never lives here.

use flint_verify::{SignedBlobVerifier, VerifyError};

use super::{TransformModule, WasmError};

/// Artifact magic ("spark wasm"). Namespaces spark's module artifacts within flint's generic format.
const MAGIC: [u8; 4] = *b"SPKW";
/// Ed25519 signature length.
const SIG_LEN: usize = 64;
/// Ed25519 public-key length.
const PUBKEY_LEN: usize = 32;

/// The **development** module-signing public key — the fallback when no production key is pinned at
/// build time. Its private half lives only in tests/tooling, never in a shipped binary, so it must
/// not be relied on for production trust. Production builds inject the real key via the
/// `SPARK_MODULE_PUBKEY_HEX` build-time environment variable (see [`SPARK_MODULE_PUBKEY`]).
// In a release build that pins a real key, this dev fallback is unreferenced (the `None` arm panics
// at compile time instead) — that's expected, not dead weight.
#[cfg_attr(not(debug_assertions), allow(dead_code))]
const DEV_MODULE_PUBKEY: [u8; PUBKEY_LEN] = [
    114, 43, 155, 15, 166, 26, 80, 178, 3, 21, 71, 211, 20, 223, 38, 197, 127, 114, 13, 201, 119,
    147, 135, 224, 208, 160, 39, 52, 129, 224, 249, 213,
];

/// The Ed25519 public key signed transform modules are verified against, **pinned at build time**
/// (ADR 0003). A release build injects the real key via `SPARK_MODULE_PUBKEY_HEX` (64 hex chars);
/// the private half never enters this repo. A malformed override is a compile error (const-eval
/// panic). When the env var is unset, a **debug/test** build falls back to [`DEV_MODULE_PUBKEY`] for
/// convenience, but a **release** build *fails to compile* — shipping a binary that trusts the
/// repo-published dev key (whose private half lives in the test tree) would be fail-open, so we
/// refuse rather than silently degrade.
const SPARK_MODULE_PUBKEY: [u8; PUBKEY_LEN] = match option_env!("SPARK_MODULE_PUBKEY_HEX") {
    Some(hex) => parse_pubkey_hex(hex),
    #[cfg(debug_assertions)]
    None => DEV_MODULE_PUBKEY,
    #[cfg(not(debug_assertions))]
    None => panic!(
        "SPARK_MODULE_PUBKEY_HEX must be set for a release build with the `wasm-transport` feature: \
         refusing to fall back to the public development module-signing key"
    ),
};

/// Const-eval parse of a 64-char hex string into the 32-byte pinned key. Panics (→ compile error)
/// on a wrong length or a non-hex digit, so a bad `SPARK_MODULE_PUBKEY_HEX` fails the build loudly.
const fn parse_pubkey_hex(s: &str) -> [u8; PUBKEY_LEN] {
    let bytes = s.as_bytes();
    assert!(
        bytes.len() == PUBKEY_LEN * 2,
        "SPARK_MODULE_PUBKEY_HEX must be 64 hex characters"
    );
    let mut out = [0u8; PUBKEY_LEN];
    let mut i = 0;
    while i < PUBKEY_LEN {
        out[i] = (hex_nibble(bytes[2 * i]) << 4) | hex_nibble(bytes[2 * i + 1]);
        i += 1;
    }
    out
}

/// One hex digit → its value, or a compile-time panic on a non-hex byte.
const fn hex_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("SPARK_MODULE_PUBKEY_HEX contains a non-hex digit"),
    }
}

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

/// Map flint's generic verification errors onto this module's WASM-flavored variants, so the public
/// error surface (and its callers/tests) is unchanged by the extraction.
impl From<VerifyError> for ModuleError {
    fn from(e: VerifyError) -> Self {
        match e {
            VerifyError::Truncated => ModuleError::Truncated,
            VerifyError::BadMagic => ModuleError::BadMagic,
            VerifyError::BadSignature => ModuleError::BadSignature,
            VerifyError::BadName => ModuleError::BadName,
            VerifyError::Rollback { version, floor } => ModuleError::Rollback { version, floor },
        }
    }
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

/// Verifies delivered module artifacts against an Ed25519 public key.
///
/// Production uses [`ModuleVerifier::pinned`], whose key is a compile-time constant baked into the
/// signed binary ([`SPARK_MODULE_PUBKEY`]); [`ModuleVerifier::new`] takes an explicit key (tests,
/// tooling). The verifier holds only the public key — never a private key.
pub struct ModuleVerifier {
    public_key: [u8; PUBKEY_LEN],
}

impl ModuleVerifier {
    /// Create a verifier for the given Ed25519 public key (raw 32 bytes).
    pub fn new(public_key: [u8; PUBKEY_LEN]) -> Self {
        Self { public_key }
    }

    /// A verifier using the key [`pinned at build time`](SPARK_MODULE_PUBKEY) — the production path.
    pub fn pinned() -> Self {
        Self::new(SPARK_MODULE_PUBKEY)
    }

    /// Verify, parse, and compile a signed module `artifact`.
    ///
    /// `min_version` is the anti-rollback floor — the highest module version installed so far; an
    /// artifact carrying a lower version is rejected. The signature is checked over the whole payload
    /// (by [`flint_verify`]) **before** any field is parsed, so the length-prefixed `name`/`wasm`
    /// fields are authenticated before they are acted on.
    pub fn verify(&self, artifact: &[u8], min_version: u32) -> Result<SignedModule, ModuleError> {
        // 1. Authenticate + parse the framed artifact (signature checked before any field is trusted).
        let blob = SignedBlobVerifier::new(self.public_key, MAGIC).verify(artifact, min_version)?;
        // 2. Compile the now-authenticated wasm payload.
        let module = TransformModule::load(blob.payload)?;
        Ok(SignedModule {
            name: blob.name.to_string(),
            version: blob.version,
            module,
        })
    }
}

/// Assemble the bytes a signature must cover: `MAGIC || version || name || wasm`. The detached
/// signature over this is appended to form a full artifact ([`build_artifact`]).
pub fn signing_payload(name: &str, version: u32, wasm: &[u8]) -> Vec<u8> {
    flint_verify::signing_payload(&MAGIC, name, version, wasm)
}

/// Assemble a complete signed artifact from its parts. `signature` must be the detached Ed25519
/// signature over `signing_payload(name, version, wasm)`.
pub fn build_artifact(name: &str, version: u32, wasm: &[u8], signature: &[u8; SIG_LEN]) -> Vec<u8> {
    flint_verify::build_artifact(&MAGIC, name, version, wasm, signature)
}

/// Sign `wasm` into a complete `.spkw` artifact with `keypair` — the offline operation the
/// `sign-module` tool performs (the one place the private key is used). Assembles the
/// [`signing_payload`], signs it (Ed25519), and appends the detached signature via [`build_artifact`].
/// Compiled only under the off-by-default `module-signer` feature, so it never enters a shipped binary.
#[cfg(feature = "module-signer")]
pub fn sign_artifact(
    keypair: &ring::signature::Ed25519KeyPair,
    name: &str,
    version: u32,
    wasm: &[u8],
) -> Vec<u8> {
    let signature = keypair.sign(&signing_payload(name, version, wasm));
    // ring's Ed25519 signature is always 64 bytes; copy into the fixed array `build_artifact` wants —
    // the same infallible shape this file's test helper uses.
    let mut sig = [0u8; SIG_LEN];
    sig.copy_from_slice(signature.as_ref());
    build_artifact(name, version, wasm, &sig)
}

/// Generate a fresh Ed25519 **module-signing keypair**, PKCS#8-encoded — the `sign-module keygen`
/// operation. The returned bytes are the *private* key: write them to secret storage (never the repo),
/// sign modules with them via [`sign_artifact`], and pin the matching public key
/// ([`public_key_hex`]) into the client build with `SPARK_MODULE_PUBKEY_HEX`. Compiled only under the
/// off-by-default `module-signer` feature, so no shipped binary can mint a signing key.
#[cfg(feature = "module-signer")]
pub fn generate_keypair_pkcs8() -> Vec<u8> {
    let rng = ring::rand::SystemRandom::new();
    ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
        .expect("ring Ed25519 PKCS#8 generation")
        .as_ref()
        .to_vec()
}

/// The 64-hex-char Ed25519 public key of `keypair` — the value to set as `SPARK_MODULE_PUBKEY_HEX` so a
/// release build trusts modules signed by this key (see [`SPARK_MODULE_PUBKEY`]). Only the public half.
#[cfg(feature = "module-signer")]
pub fn public_key_hex(keypair: &ring::signature::Ed25519KeyPair) -> String {
    use ring::signature::KeyPair;
    let mut s = String::with_capacity(PUBKEY_LEN * 2);
    for byte in keypair.public_key().as_ref() {
        s.push(char::from_digit((byte >> 4) as u32, 16).expect("nibble"));
        s.push(char::from_digit((byte & 0x0f) as u32, 16).expect("nibble"));
    }
    s
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

    /// The production-key flow end to end: `keygen` mints a keypair, `public_key_hex` yields the value
    /// that would be pinned via `SPARK_MODULE_PUBKEY_HEX`, a module signed by that key verifies under a
    /// verifier built from the hex, and a different key's verifier rejects it.
    #[cfg(feature = "module-signer")]
    #[test]
    fn generated_keypair_signs_a_module_and_its_pubkey_hex_verifies() {
        let pkcs8 = generate_keypair_pkcs8();
        let kp = Ed25519KeyPair::from_pkcs8(&pkcs8).expect("parse generated key");
        let hex = public_key_hex(&kp);
        assert_eq!(hex.len(), 64, "pubkey hex is 32 bytes");
        // The hex round-trips to the raw pubkey the verifier pins.
        assert_eq!(parse_pubkey_hex(&hex), public_key(&kp));

        let artifact = sign_artifact(&kp, "obfs-xor", 1, &xor_wasm());
        ModuleVerifier::new(parse_pubkey_hex(&hex))
            .verify(&artifact, 0)
            .expect("the keygen'd pubkey accepts its own signature");
        // A verifier for a different key rejects the artifact. (`SignedModule` isn't `Debug`, so map
        // the Ok away before `expect_err`.)
        let other = Ed25519KeyPair::from_pkcs8(&generate_keypair_pkcs8()).expect("parse other key");
        ModuleVerifier::new(public_key(&other))
            .verify(&artifact, 0)
            .map(|_| ())
            .expect_err("a different pubkey must reject the signature");
    }

    #[test]
    fn pinned_verifier_accepts_a_dev_signed_module() {
        // Cross-checks that the baked `DEV_MODULE_PUBKEY` const is the public half of the baked
        // `DEV_MODULE_PKCS8`: an artifact signed by the dev key must verify under `pinned()`.
        let artifact = sign(
            &crate::transport::wasm::testutil::dev_keypair(),
            "obfs",
            1,
            &xor_wasm(),
        );
        let signed = ModuleVerifier::pinned()
            .verify(&artifact, 0)
            .expect("pinned() must accept a dev-signed module");
        assert_eq!(signed.name(), "obfs");
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
