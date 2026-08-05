//! Path B dynamic transport — a `wasmi`-hosted byte-transform module (ADR 0003, design §8.4).
//!
//! A dynamic transport is delivered as a WebAssembly module the client loads at runtime, so a new
//! obfuscation can ship in hours instead of a client release. Path B keeps the module's job and its
//! capabilities minimal: it is a **pure byte transform**. The host owns the network sockets; the
//! module only sees bytes and the host functions below. It cannot open a connection, touch the
//! filesystem, or otherwise reach the outside world — there is no WASI, no network import. That is
//! the sandbox property Path B buys over a WATER-style host (design doc §8.2/§8.4).
//!
//! # ABI
//!
//! The module **exports** (`memory` + `alloc` always; then at least one *mode* — the byte-transform
//! pair, the gambit-compute export, and/or the interactive-handshake export):
//! - `memory` — its linear memory.
//! - `alloc(len: i32) -> i32` — return a pointer to `len` writable bytes (the host writes input here).
//! - `transform_out(ptr: i32, len: i32) -> i64` — *byte-transform mode*; transform `len` bytes at
//!   `ptr` on the application → wire direction. Returns the output region packed as
//!   `(out_ptr << 32) | out_len`.
//! - `transform_in(ptr: i32, len: i32) -> i64` — the inverse (wire → application), same packing.
//! - `compute_gambit(ctx_ptr: i32, ctx_len: i32) -> i64` — *gambit-compute mode* (ADR 0006 P3);
//!   invoked once per connection with a (reserved) per-connection context, returns **opaque engine
//!   params** packed the same way — the opening *plan*, not stream bytes. The core does not parse
//!   them; the engine that consumes them (the TLS engine, `engine::tls`) decodes + realizes them
//!   (ADR 0013 §7 step 1). Lets a plan be **computed per connection** (adaptive/stateful) rather than
//!   shipped as static signed config.
//! - `handshake_step(in_ptr: i32, in_len: i32) -> i64` — *interactive-handshake mode* (ADR 0013 §7
//!   step 3); drive one step of an opening handshake. Output is packed the same way but **framed** as
//!   `[status: u8][outbound_wire …]` (status 0 = continue, 1 = done). Called with empty input at
//!   connect (emit-at-connect), then per inbound chunk until done — the one mode where an inbound read
//!   drives an outbound write. The module keeps handshake state + derived keys for the steady-state
//!   `transform_*` to use.
//! - `init(config_ptr: i32, config_len: i32)` — *optional*; called once after instantiation to
//!   deliver per-deployment configuration (e.g. a key or seed). See [`TransformModule::instantiate_with_config`].
//! - `reset()` — *optional*; called by the host after each transform (and after `init`) so a module
//!   can rewind a per-call scratch arena without growing memory; persistent state in globals survives.
//!
//! The module **imports** (host functions, under module `env`) — this is its entire capability
//! surface, and a module may be restricted to a subset of it.
//!
//! # Capabilities
//!
//! Because there is no WASI and no network import, the host-function table below *is* the sandbox
//! boundary. Restricting it is therefore the only way to grant one module less authority than
//! another — which is what makes running a transport somebody else wrote a bounded risk rather than
//! an open one.
//!
//! A module loaded from a signed **bundle** is scoped to the allow-list inside that bundle's signed
//! payload, so its authority is fixed by whoever signed it and cannot be widened by editing config.
//! A module loaded directly from a local `.spkw` path is unrestricted — it is as trusted as the
//! filesystem it came from. An import outside the grant is simply not linked, so the module fails to
//! **instantiate**, loudly and by name, rather than receiving a stub that errors later somewhere
//! that looks like a protocol fault. See [`TransformModule::load_scoped`].
//! - `host_rand(ptr, len)` — fill `len` bytes with cryptographically secure random bytes.
//! - `host_hash(in_ptr, in_len, out_ptr)` — SHA-256, writing 32 bytes.
//! - `host_aead_seal(key_ptr, nonce_ptr, aad_ptr, aad_len, in_ptr, in_len, out_ptr) -> i64` —
//!   ChaCha20-Poly1305 seal (returns `in_len + 16`; `aad_len` may be 0).
//! - `host_aead_open(key_ptr, nonce_ptr, aad_ptr, aad_len, in_ptr, in_len, out_ptr) -> i64` — the
//!   inverse; returns the plaintext length, or `-1` on authentication failure.
//!
//! The **handshake-crypto menu** (ADR 0006 P4) — primitives a module needs to drive a TLS 1.3
//! handshake itself in the *unconstrained* regime; bulk work runs natively here, not in the
//! interpreter:
//! - `host_hkdf_extract(salt_ptr, salt_len, ikm_ptr, ikm_len, out_ptr) -> i64` — HKDF-Extract
//!   (HMAC-SHA256); writes the 32-byte PRK, returns 32. `salt_len` may be 0 (unsalted).
//! - `host_hkdf_expand(prk_ptr, info_ptr, info_len, out_ptr, out_len) -> i64` — HKDF-Expand
//!   (SHA-256) of the 32-byte PRK at `prk_ptr`; writes `out_len` bytes (the module builds its own
//!   `HKDF-Expand-Label` info), returns `out_len`. `out_len` ≤ 255×32.
//! - `host_aes_gcm_seal(key_ptr, key_len, nonce_ptr, aad_ptr, aad_len, in_ptr, in_len, out_ptr) -> i64`
//!   — AES-GCM seal; `key_len` 16 ⇒ AES-128-GCM, 32 ⇒ AES-256-GCM; 12-byte nonce, 16-byte tag.
//! - `host_aes_gcm_open(key_ptr, key_len, nonce_ptr, aad_ptr, aad_len, in_ptr, in_len, out_ptr) -> i64`
//!   — the inverse; `-1` on authentication failure.
//! - `host_x25519_generate(out_pub_ptr) -> i64` — generate an ephemeral X25519 keypair, write the
//!   32-byte public key to `out_pub_ptr`, and return an opaque **key id** (the private key stays
//!   host-side — it never enters guest memory). `-1` on fault.
//! - `host_x25519_agree(key_id, peer_pub_ptr, out_ptr) -> i64` — X25519 ECDH between the stored
//!   private key `key_id` (consumed) and the 32-byte peer public key at `peer_pub_ptr`, writing the
//!   32-byte shared secret to `out_ptr`. Returns 32, or `-1` on fault.
//! - `host_chacha20(key_ptr, nonce_ptr, counter, in_ptr, in_len, out_ptr) -> i64` — raw IETF ChaCha20
//!   keystream (no AEAD tag): 32-byte key, 12-byte nonce, 32-bit initial block `counter`. XORs the
//!   input with the keystream; returns the length, or `-1` on fault. A general stream cipher.
//!
//! Under the `bip324` feature, two more (secp256k1 + ElligatorSwift, a general curve + uniform-point
//! encoding), mirroring the X25519 key-handle pattern:
//! - `host_secp256k1_ellswift_generate(out_ellswift_ptr) -> i64` — generate a secp256k1 keypair, write
//!   the 64-byte ElligatorSwift-encoded public key to `out_ellswift_ptr`, return an opaque key id (the
//!   secret stays host-side). `-1` on fault.
//! - `host_secp256k1_ellswift_ecdh(key_id, peer_ellswift_ptr, out_ptr) -> i64` — X-only ECDH between
//!   the stored key `key_id` (consumed) and the 64-byte peer ElligatorSwift key, writing the raw
//!   32-byte shared x-coordinate (no protocol-specific hashing). Returns 32, or `-1` on fault.
//!
//! Bulk per-byte crypto runs **natively** through these host functions, not in the interpreter — the
//! module interprets only its control/framing logic. (Measured: bulk work in the interpreter caps a
//! flow at <1 Gb/s, whereas sealing via the native AEAD host fn runs >10 Gb/s.)
//!
//! Each `transform_*` call is self-contained: the host calls `alloc`, writes the input, calls the
//! transform, reads the packed output, then calls `reset` (if exported). A module that exports
//! `reset` can allocate per-call scratch freely; one that does not must avoid unbounded memory growth
//! across calls itself (e.g. reuse a fixed scratch region).

use std::io;
use std::sync::Arc;

use ring::rand::{SecureRandom, SystemRandom};
use ring::{aead, agreement, digest, hkdf, hmac};
use wasmi::{
    Caller, Config, Engine, Extern, Linker, Memory, Module, Store, StoreLimits, StoreLimitsBuilder,
    TypedFunc,
};

use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::{ChaCha20, Key, Nonce};
#[cfg(feature = "bip324")]
use secp256k1::ellswift::{ElligatorSwift, ElligatorSwiftSharedSecret, Party};
#[cfg(feature = "bip324")]
use secp256k1::SecretKey;
use tokio::io::{AsyncRead, AsyncWrite};

mod signing;
#[cfg(feature = "bip324")]
mod splitter;
mod stream;
mod transport;
pub use signing::{build_artifact, signing_payload, ModuleError, ModuleVerifier, SignedModule};
/// The offline artifact-signing helper — only compiled for the `sign-module` tool.
#[cfg(feature = "module-signer")]
pub use signing::{generate_keypair_pkcs8, public_key_hex, sign_artifact};
#[cfg(feature = "bip324")]
pub use splitter::SplittingServer;
pub use stream::TransformStream;
pub use transport::{WasmServer, WasmTransport};

/// PKCS#8 of the **development** module-signing keypair — the private half of
/// `signing::DEV_MODULE_PUBKEY` (the dev fallback `ModuleVerifier::pinned()` trusts when no production
/// key is pinned). Compiled only under `#[cfg(test)]` or the off-by-default `module-signer` feature —
/// which shipped/product builds never enable — so the private key stays out of every shipped binary.
#[cfg(any(test, feature = "module-signer"))]
const DEV_MODULE_PKCS8: &[u8] = &[
    48, 81, 2, 1, 1, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32, 47, 96, 208, 79, 38, 102, 119, 122,
    12, 75, 231, 119, 191, 58, 165, 37, 216, 16, 180, 152, 96, 30, 105, 41, 180, 223, 163, 204, 55,
    11, 100, 103, 129, 33, 0, 114, 43, 155, 15, 166, 26, 80, 178, 3, 21, 71, 211, 20, 223, 38, 197,
    127, 114, 13, 201, 119, 147, 135, 224, 208, 160, 39, 52, 129, 224, 249, 213,
];

/// The development signing keypair (see [`DEV_MODULE_PKCS8`]).
#[cfg(any(test, feature = "module-signer"))]
pub fn dev_keypair() -> ring::signature::Ed25519KeyPair {
    ring::signature::Ed25519KeyPair::from_pkcs8(DEV_MODULE_PKCS8).expect("dev pkcs8")
}

/// Import module name the host functions are defined under.
const HOST_MODULE: &str = "env";
/// Import: cryptographically secure random fill (`host_rand(ptr, len)`).
const HOST_RAND: &str = "host_rand";
/// Import: SHA-256 (`host_hash(in_ptr, in_len, out_ptr)` → 32 bytes).
const HOST_HASH: &str = "host_hash";
/// Import: ChaCha20-Poly1305 seal (`host_aead_seal(key_ptr, nonce_ptr, aad_ptr, aad_len, in_ptr, in_len, out_ptr)`).
const HOST_AEAD_SEAL: &str = "host_aead_seal";
/// Import: ChaCha20-Poly1305 open (`host_aead_open(key_ptr, nonce_ptr, aad_ptr, aad_len, in_ptr, in_len, out_ptr)`).
const HOST_AEAD_OPEN: &str = "host_aead_open";
/// Import: HKDF-Extract / HMAC-SHA256 (`host_hkdf_extract(salt_ptr, salt_len, ikm_ptr, ikm_len, out_ptr)`).
const HOST_HKDF_EXTRACT: &str = "host_hkdf_extract";
/// Import: HKDF-Expand / SHA-256 (`host_hkdf_expand(prk_ptr, info_ptr, info_len, out_ptr, out_len)`).
const HOST_HKDF_EXPAND: &str = "host_hkdf_expand";
/// Import: AES-GCM seal (`host_aes_gcm_seal(key_ptr, key_len, nonce_ptr, aad_ptr, aad_len, in_ptr, in_len, out_ptr)`).
const HOST_AES_GCM_SEAL: &str = "host_aes_gcm_seal";
/// Import: AES-GCM open (`host_aes_gcm_open(key_ptr, key_len, nonce_ptr, aad_ptr, aad_len, in_ptr, in_len, out_ptr)`).
const HOST_AES_GCM_OPEN: &str = "host_aes_gcm_open";
/// Import: X25519 ephemeral keygen (`host_x25519_generate(out_pub_ptr) -> key_id`).
const HOST_X25519_GENERATE: &str = "host_x25519_generate";
/// Import: X25519 ECDH (`host_x25519_agree(key_id, peer_pub_ptr, out_ptr)`).
const HOST_X25519_AGREE: &str = "host_x25519_agree";
/// Import: raw ChaCha20 keystream (`host_chacha20(key_ptr, nonce_ptr, counter, in_ptr, in_len, out_ptr)`).
const HOST_CHACHA20: &str = "host_chacha20";
/// Import: secp256k1 ElligatorSwift keygen (`host_secp256k1_ellswift_generate(out_ellswift_ptr) -> key_id`).
#[cfg(feature = "bip324")]
const HOST_SECP256K1_ELLSWIFT_GENERATE: &str = "host_secp256k1_ellswift_generate";
/// Import: secp256k1 ElligatorSwift X-only ECDH (`host_secp256k1_ellswift_ecdh(key_id, peer_ellswift_ptr, out_ptr)`).
#[cfg(feature = "bip324")]
const HOST_SECP256K1_ELLSWIFT_ECDH: &str = "host_secp256k1_ellswift_ecdh";

/// Export: the module's linear memory.
const EXPORT_MEMORY: &str = "memory";
/// Export (optional): `init(config_ptr, config_len)` — called once after instantiation to deliver
/// per-deployment configuration (e.g. a key or seed).
const EXPORT_INIT: &str = "init";
/// Export (optional): `reset()` — rewinds the module's per-call scratch arena, called by the host
/// after each transform (and after `init`). Lets a module reclaim per-call buffers without growing
/// memory, while keeping its persistent state (in globals/fixed memory) intact.
const EXPORT_RESET: &str = "reset";
/// Export: `alloc(len) -> ptr`.
const EXPORT_ALLOC: &str = "alloc";
/// Export: `transform_out(ptr, len) -> packed`.
const EXPORT_TRANSFORM_OUT: &str = "transform_out";
/// Export: `transform_in(ptr, len) -> packed`.
const EXPORT_TRANSFORM_IN: &str = "transform_in";
/// Export (optional): `compute_gambit(ctx_ptr, ctx_len) -> packed` — emits opaque per-connection
/// engine params (the opening plan), not stream bytes; the consuming engine decodes them (ADR 0006 P3).
const EXPORT_COMPUTE_GAMBIT: &str = "compute_gambit";
/// Export (optional): `handshake_step(in_ptr, in_len) -> packed` — one step of an interactive opening
/// handshake (ADR 0013 §7 step 3). The output region is framed `[status: u8][outbound_wire …]`: status
/// 0 = continue, 1 = done. Called with empty input at connect (emit-at-connect), then per inbound chunk.
const EXPORT_HANDSHAKE_STEP: &str = "handshake_step";
/// Chunk size for reading inbound handshake bytes; the module buffers partial reads internally.
const HANDSHAKE_READ_CHUNK: usize = 4096;

/// Upper bound on a single transform's input or output length. Caps how much guest memory one call
/// can drive the host to touch or allocate — the module is untrusted, so every length crossing the
/// boundary is checked against this before any allocation.
const MAX_TRANSFORM_LEN: usize = 1 << 20; // 1 MiB

/// Cap on a guest's linear memory. Fuel bounds *compute*, not *allocation* — a module could
/// `memory.grow` to exhaust host RAM without spending much fuel. 16 MiB is far above what a byte
/// transform needs (a 1 MiB `MAX_TRANSFORM_LEN` chunk in + out + scratch arena) while bounding a
/// runaway. Enforced per-store via `wasmi`'s [`StoreLimits`]; an over-cap grow traps the call.
const MAX_WASM_MEMORY_BYTES: usize = 16 * 1024 * 1024;
/// Cap on a guest's table size (function/extern references). A byte transform needs few or none;
/// this bounds a `table.grow` runaway the same way the memory cap bounds `memory.grow`.
const MAX_WASM_TABLE_ELEMENTS: usize = 4096;

/// ChaCha20-Poly1305 key length (the AEAD the crypto host fns expose).
const AEAD_KEY_LEN: usize = 32;
/// ChaCha20-Poly1305 nonce length.
const AEAD_NONCE_LEN: usize = 12;
/// Poly1305 authentication tag length (appended to the ciphertext on seal).
const AEAD_TAG_LEN: usize = 16;
/// SHA-256 digest length.
const HASH_LEN: usize = 32;
/// HKDF-SHA256 pseudo-random-key length (= the hash output).
const HKDF_PRK_LEN: usize = 32;
/// HKDF-Expand's output ceiling: 255 × HashLen (RFC 5869).
const HKDF_MAX_EXPAND_LEN: usize = 255 * HKDF_PRK_LEN;
/// X25519 public-key / shared-secret length.
const X25519_KEY_LEN: usize = 32;
/// Cap on a session's *live* (un-consumed) X25519 ephemeral keys — a handshake needs one; this
/// bounds a module that spams keygen without agreeing.
const MAX_X25519_KEYS: usize = 16;
/// Raw ChaCha20 key length (IETF variant).
const CHACHA20_KEY_LEN: usize = 32;
/// Raw ChaCha20 nonce length (IETF 96-bit).
const CHACHA20_NONCE_LEN: usize = 12;
/// secp256k1 ElligatorSwift public-key encoding length.
#[cfg(feature = "bip324")]
const SECP256K1_ELLSWIFT_LEN: usize = 64;
/// secp256k1 X-only ECDH shared-secret (raw x-coordinate) length.
#[cfg(feature = "bip324")]
const SECP256K1_SHARED_LEN: usize = 32;
/// Cap on a session's *live* (un-consumed) secp256k1 keys (see [`MAX_X25519_KEYS`]).
#[cfg(feature = "bip324")]
const MAX_SECP256K1_KEYS: usize = 16;

/// Per-call fuel budget = [`FUEL_BASE`] + `input_len` × [`FUEL_PER_BYTE`]. Fuel meters the module's
/// own interpreted bytecode (host-fn crypto runs natively and costs no fuel), so this bounds a
/// runaway/buggy module without penalizing bulk work. Deliberately generous — a legit transform
/// (even one that touches every byte in the interpreter, ~a handful of ops/byte) never approaches it.
const FUEL_BASE: u64 = 5_000_000;
/// Per-input-byte fuel allowance (see [`FUEL_BASE`]). ~1000 ops/byte of headroom.
const FUEL_PER_BYTE: u64 = 1024;

/// Errors from loading or running a dynamic transform module.
#[derive(Debug, thiserror::Error)]
pub enum WasmError {
    /// The module bytes failed to compile.
    #[error("compile transform module: {0}")]
    Compile(wasmi::Error),
    /// Instantiation (including the module's `start`) failed.
    #[error("instantiate transform module: {0}")]
    Instantiate(wasmi::Error),
    /// Defining a host import on the linker failed.
    #[error("define host import: {0}")]
    Link(String),
    /// The module is missing a required ABI export (or it has the wrong type).
    #[error("transform module is missing required export `{0}`")]
    MissingExport(&'static str),
    /// A call into the guest trapped or otherwise failed.
    #[error("calling guest `{func}`: {source}")]
    Call {
        /// The exported function that failed.
        func: &'static str,
        /// The underlying wasmi error.
        source: wasmi::Error,
    },
    /// A guest-memory read or write was out of bounds.
    #[error("guest memory fault: {0}")]
    Memory(String),
    /// A host function recorded a fault during the guest call (CSPRNG failure, bad length, …).
    #[error("host function fault: {0}")]
    HostFault(String),
    /// `handshake_step` returned a malformed frame (empty, or a status byte that isn't 0/1).
    #[error("handshake_step returned a malformed frame: {0}")]
    HandshakeFrame(String),
    /// The module exports no *mode* entrypoint (needs at least one of `transform_out`,
    /// `transform_in`, `compute_gambit`, or `handshake_step`).
    #[error(
        "transform module exports no mode entrypoint (transform_out / transform_in / compute_gambit / handshake_step)"
    )]
    NoMode,
    /// The module exhausted its per-call execution fuel — a runaway or pathologically slow module.
    #[error("fuel: {0}")]
    Fuel(String),
    /// The transform input exceeds [`MAX_TRANSFORM_LEN`].
    #[error("transform input of {len} bytes exceeds the {max}-byte limit")]
    InputTooLarge {
        /// The offending input length.
        len: usize,
        /// The configured limit.
        max: usize,
    },
    /// The guest returned an output region whose length is implausible.
    #[error("guest returned an out-of-range output length {len} (limit {max})")]
    BadOutputLen {
        /// The length the guest packed into its return value.
        len: usize,
        /// The configured limit.
        max: usize,
    },
}

/// A loaded, compiled transform module. Cheap to clone and share (`Arc`-backed compiled module +
/// the `wasmi` engine); instantiate one [`Transform`] per connection from it.
#[derive(Clone)]
pub struct TransformModule {
    engine: Engine,
    module: Arc<Module>,
    /// Host functions this module may import. `None` grants the full table.
    ///
    /// The import table *is* the sandbox boundary — there is no WASI and no network — so restricting
    /// it is the only meaningful way to give one module less authority than another. That matters
    /// once modules can come from someone other than us: a transport that only reshapes bytes has no
    /// business holding an X25519 private key or drawing from the CSPRNG.
    ///
    /// `None` rather than "all names" so the distinction between *unrestricted* and *happens to list
    /// everything* stays visible; a locally provisioned `.spkw` is unrestricted, a delivered bundle
    /// declares what it needs.
    capabilities: Option<Arc<[String]>>,
}

impl TransformModule {
    /// Compile a transform module from its WebAssembly bytes.
    ///
    /// This only validates and compiles; it does not run the module. Per-connection state is
    /// created by [`TransformModule::instantiate`].
    pub fn load(wasm: &[u8]) -> Result<Self, WasmError> {
        Self::load_scoped(wasm, None)
    }

    /// Compile a module that may import only `capabilities` (host-function names).
    ///
    /// A module importing anything outside the list fails to **instantiate**, loudly, rather than
    /// receiving a stub that returns an error at some later call — the failure belongs at load time,
    /// where it names the module, not mid-handshake where it looks like a protocol fault.
    pub fn load_scoped(wasm: &[u8], capabilities: Option<Vec<String>>) -> Result<Self, WasmError> {
        // Enable fuel metering so a runaway module is bounded per call (see `fuel_for`).
        let mut config = Config::default();
        config.consume_fuel(true);
        let engine = Engine::new(&config);
        let module = Module::new(&engine, wasm).map_err(WasmError::Compile)?;
        Ok(Self {
            engine,
            module: Arc::new(module),
            capabilities: capabilities.map(Arc::from),
        })
    }

    /// The host functions this module is permitted to import, or `None` when unrestricted.
    pub fn capabilities(&self) -> Option<&[String]> {
        self.capabilities.as_deref()
    }

    /// Instantiate a fresh transform session with its own linear memory and host state.
    pub fn instantiate(&self) -> Result<Transform, WasmError> {
        Transform::new(self, &[])
    }

    /// Like [`instantiate`](Self::instantiate), but deliver `config` to the module's optional `init`
    /// export (e.g. a per-deployment key or seed). If the module has no `init` export, `config` must
    /// be empty — otherwise the configuration can't be delivered and this errors.
    pub fn instantiate_with_config(&self, config: &[u8]) -> Result<Transform, WasmError> {
        Transform::new(self, config)
    }
}

/// Host state bound to a [`Transform`]'s `Store`. Carries the CSPRNG the `host_rand` import draws
/// from, a fault slot (host-function failures are recorded here and surfaced after the guest call,
/// so the host function itself stays infallible at the wasmi boundary), and a byte counter exposed
/// as telemetry via [`Transform::entropy_drawn`].
struct HostState {
    rng: SystemRandom,
    fault: Option<String>,
    rand_bytes: u64,
    /// Host-held X25519 ephemeral private keys, indexed by the id returned from
    /// `host_x25519_generate` (ADR 0006 P4). `agree` `take`s the key (one-shot, matching one ECDH
    /// per handshake); freed slots are reused so the vec stays ≤ [`MAX_X25519_KEYS`]. Keeping
    /// private keys host-side means a buggy/hostile module can never read or leak them.
    x25519_keys: Vec<Option<agreement::EphemeralPrivateKey>>,
    /// Host-held secp256k1 keypairs (secret + its ElligatorSwift encoding), indexed by the id from
    /// `host_secp256k1_ellswift_generate`; `ecdh` `take`s the entry (one-shot). Same host-side-only
    /// privacy property as `x25519_keys`; bounded by [`MAX_SECP256K1_KEYS`].
    #[cfg(feature = "bip324")]
    secp256k1_keys: Vec<Option<(SecretKey, ElligatorSwift)>>,
    /// Caps the guest's linear-memory + table growth (fuel bounds compute, not allocation). Read by
    /// the store limiter wired up in [`Transform::new`].
    limits: StoreLimits,
}

/// One instantiated transform session: owns the guest instance + linear memory and drives the byte
/// transforms. `Send` (so it can move into a per-connection task) but not `Sync` — the `wasmi`
/// `Store` is single-threaded, which matches one session per connection.
pub struct Transform {
    store: Store<HostState>,
    memory: Memory,
    alloc: TypedFunc<i32, i32>,
    /// Byte-transform mode (application → wire); absent for a gambit-compute-only module.
    transform_out: Option<TypedFunc<(i32, i32), i64>>,
    /// Byte-transform mode (wire → application); absent for a gambit-compute-only module.
    transform_in: Option<TypedFunc<(i32, i32), i64>>,
    /// Gambit-compute mode (ADR 0006 P3); absent for a byte-transform-only module.
    compute_gambit: Option<TypedFunc<(i32, i32), i64>>,
    /// Interactive-handshake mode (ADR 0013 §7 step 3); absent unless the module drives a handshake.
    handshake_step: Option<TypedFunc<(i32, i32), i64>>,
    /// Optional `reset()` — rewinds the module's scratch arena after each transform.
    reset: Option<TypedFunc<(), ()>>,
}

/// Which direction a [`Transform::run`] applies.
enum Direction {
    Out,
    In,
}

impl Transform {
    fn new(module: &TransformModule, config: &[u8]) -> Result<Self, WasmError> {
        if config.len() > MAX_TRANSFORM_LEN {
            return Err(WasmError::InputTooLarge {
                len: config.len(),
                max: MAX_TRANSFORM_LEN,
            });
        }
        let mut store = Store::new(
            &module.engine,
            HostState {
                rng: SystemRandom::new(),
                fault: None,
                rand_bytes: 0,
                x25519_keys: Vec::new(),
                #[cfg(feature = "bip324")]
                secp256k1_keys: Vec::new(),
                limits: StoreLimitsBuilder::new()
                    .memory_size(MAX_WASM_MEMORY_BYTES)
                    .table_elements(MAX_WASM_TABLE_ELEMENTS)
                    // Trap on an over-cap grow rather than handing the guest a -1 it may ignore.
                    .trap_on_grow_failure(true)
                    .build(),
            },
        );
        // Bound guest allocation (linear memory + tables): fuel meters compute, not `memory.grow`.
        store.limiter(|state| &mut state.limits as &mut dyn wasmi::ResourceLimiter);
        // Fuel metering is on, so the store starts empty; grant a budget that covers the module's
        // `start` function (if any) and the `init` hook below. Per-transform calls refill in `run`.
        set_fuel(&mut store, fuel_for(config.len()))?;

        // Register the host functions the module is allowed to hold — its entire capability surface,
        // since there is no WASI and no network import. Bulk crypto runs natively here so modules
        // don't pay the interpreter's per-byte cost (ADR 0003); the module interprets only its
        // control/framing.
        // Only wrap the imports this module is allowed to hold. An unrestricted module (a locally
        // provisioned artifact) gets the whole table; a scoped one gets exactly what it declared, and
        // importing anything else fails instantiation below with a missing-import error naming it.
        let allowed = |name: &str| match module.capabilities.as_deref() {
            None => true,
            Some(caps) => caps.iter().any(|c| c == name),
        };
        let mut linker = Linker::<HostState>::new(&module.engine);
        if allowed(HOST_RAND) {
            linker
                .func_wrap(HOST_MODULE, HOST_RAND, host_rand)
                .map_err(|e| WasmError::Link(e.to_string()))?;
        }
        if allowed(HOST_HASH) {
            linker
                .func_wrap(HOST_MODULE, HOST_HASH, host_hash)
                .map_err(|e| WasmError::Link(e.to_string()))?;
        }
        if allowed(HOST_AEAD_SEAL) {
            linker
                .func_wrap(HOST_MODULE, HOST_AEAD_SEAL, host_aead_seal)
                .map_err(|e| WasmError::Link(e.to_string()))?;
        }
        if allowed(HOST_AEAD_OPEN) {
            linker
                .func_wrap(HOST_MODULE, HOST_AEAD_OPEN, host_aead_open)
                .map_err(|e| WasmError::Link(e.to_string()))?;
        }
        if allowed(HOST_HKDF_EXTRACT) {
            linker
                .func_wrap(HOST_MODULE, HOST_HKDF_EXTRACT, host_hkdf_extract)
                .map_err(|e| WasmError::Link(e.to_string()))?;
        }
        if allowed(HOST_HKDF_EXPAND) {
            linker
                .func_wrap(HOST_MODULE, HOST_HKDF_EXPAND, host_hkdf_expand)
                .map_err(|e| WasmError::Link(e.to_string()))?;
        }
        if allowed(HOST_AES_GCM_SEAL) {
            linker
                .func_wrap(HOST_MODULE, HOST_AES_GCM_SEAL, host_aes_gcm_seal)
                .map_err(|e| WasmError::Link(e.to_string()))?;
        }
        if allowed(HOST_AES_GCM_OPEN) {
            linker
                .func_wrap(HOST_MODULE, HOST_AES_GCM_OPEN, host_aes_gcm_open)
                .map_err(|e| WasmError::Link(e.to_string()))?;
        }
        if allowed(HOST_X25519_GENERATE) {
            linker
                .func_wrap(HOST_MODULE, HOST_X25519_GENERATE, host_x25519_generate)
                .map_err(|e| WasmError::Link(e.to_string()))?;
        }
        if allowed(HOST_X25519_AGREE) {
            linker
                .func_wrap(HOST_MODULE, HOST_X25519_AGREE, host_x25519_agree)
                .map_err(|e| WasmError::Link(e.to_string()))?;
        }
        if allowed(HOST_CHACHA20) {
            linker
                .func_wrap(HOST_MODULE, HOST_CHACHA20, host_chacha20)
                .map_err(|e| WasmError::Link(e.to_string()))?;
        }
        #[cfg(feature = "bip324")]
        if allowed(HOST_SECP256K1_ELLSWIFT_GENERATE) {
            linker
                .func_wrap(
                    HOST_MODULE,
                    HOST_SECP256K1_ELLSWIFT_GENERATE,
                    host_secp256k1_ellswift_generate,
                )
                .map_err(|e| WasmError::Link(e.to_string()))?;
        }
        #[cfg(feature = "bip324")]
        if allowed(HOST_SECP256K1_ELLSWIFT_ECDH) {
            linker
                .func_wrap(
                    HOST_MODULE,
                    HOST_SECP256K1_ELLSWIFT_ECDH,
                    host_secp256k1_ellswift_ecdh,
                )
                .map_err(|e| WasmError::Link(e.to_string()))?;
        }

        let instance = linker
            .instantiate_and_start(&mut store, &module.module)
            .map_err(WasmError::Instantiate)?;

        let memory = instance
            .get_memory(&store, EXPORT_MEMORY)
            .ok_or(WasmError::MissingExport(EXPORT_MEMORY))?;
        let alloc = instance
            .get_typed_func::<i32, i32>(&store, EXPORT_ALLOC)
            .map_err(|_| WasmError::MissingExport(EXPORT_ALLOC))?;
        // Mode exports: a module provides byte transforms, gambit-compute (P3), or both. `alloc` +
        // `memory` are mandatory; the modes are looked up optionally and a module with none is
        // rejected (it has no usable entry point).
        let transform_out = instance
            .get_typed_func::<(i32, i32), i64>(&store, EXPORT_TRANSFORM_OUT)
            .ok();
        let transform_in = instance
            .get_typed_func::<(i32, i32), i64>(&store, EXPORT_TRANSFORM_IN)
            .ok();
        let compute_gambit = instance
            .get_typed_func::<(i32, i32), i64>(&store, EXPORT_COMPUTE_GAMBIT)
            .ok();
        let handshake_step = instance
            .get_typed_func::<(i32, i32), i64>(&store, EXPORT_HANDSHAKE_STEP)
            .ok();
        if transform_out.is_none()
            && transform_in.is_none()
            && compute_gambit.is_none()
            && handshake_step.is_none()
        {
            return Err(WasmError::NoMode);
        }
        // Optional `reset()` — arena management; absent for modules that manage memory themselves.
        let reset = instance.get_typed_func::<(), ()>(&store, EXPORT_RESET).ok();

        // Optional `init` config hook. If the module exports `init`, hand it the config bytes; if it
        // does not and config was supplied, the configuration can't be delivered, so reject it.
        match instance.get_typed_func::<(i32, i32), ()>(&store, EXPORT_INIT) {
            Ok(init) => {
                let ptr = alloc
                    .call(&mut store, config.len() as i32)
                    .map_err(|source| WasmError::Call {
                        func: EXPORT_ALLOC,
                        source,
                    })?;
                memory
                    .write(&mut store, ptr as usize, config)
                    .map_err(|e| WasmError::Memory(e.to_string()))?;
                init.call(&mut store, (ptr, config.len() as i32))
                    .map_err(|source| WasmError::Call {
                        func: EXPORT_INIT,
                        source,
                    })?;
                if let Some(msg) = store.data_mut().fault.take() {
                    return Err(WasmError::HostFault(msg));
                }
                // Reclaim the config scratch (and anything `init` allocated) before the first transform.
                if let Some(reset) = reset {
                    reset
                        .call(&mut store, ())
                        .map_err(|source| WasmError::Call {
                            func: EXPORT_RESET,
                            source,
                        })?;
                }
            }
            Err(_) if !config.is_empty() => return Err(WasmError::MissingExport(EXPORT_INIT)),
            Err(_) => {}
        }

        Ok(Self {
            store,
            memory,
            alloc,
            transform_out,
            transform_in,
            compute_gambit,
            handshake_step,
            reset,
        })
    }

    /// Apply the module's outbound transform: application bytes → wire bytes.
    pub fn transform_out(&mut self, input: &[u8]) -> Result<Vec<u8>, WasmError> {
        self.run(Direction::Out, input)
    }

    /// Apply the module's inbound transform: wire bytes → application bytes.
    pub fn transform_in(&mut self, input: &[u8]) -> Result<Vec<u8>, WasmError> {
        self.run(Direction::In, input)
    }

    /// Invoke the module's `compute_gambit` export (ADR 0006 P3): pass the per-connection context and
    /// return the raw computed-gambit bytes — **opaque** here. The core no longer parses them; the
    /// engine that consumes them (the TLS engine) decodes + gates them (ADR 0013 §7 step 1). The trust
    /// root is the module's own signature (the bytes are not separately signed).
    /// Errors with [`WasmError::MissingExport`] if the module is byte-transform-only.
    pub fn compute_gambit(&mut self, ctx: &[u8]) -> Result<Vec<u8>, WasmError> {
        let func = self
            .compute_gambit
            .ok_or(WasmError::MissingExport(EXPORT_COMPUTE_GAMBIT))?;
        self.call_io(func, EXPORT_COMPUTE_GAMBIT, ctx)
    }

    /// Whether the module drives an interactive opening handshake (exports `handshake_step`). The dial
    /// path runs [`run_handshake`](Self::run_handshake) before steady-state iff this is true — so the
    /// wiring stays protocol-blind (a transform-only module like obfs-xor returns false and is dialed
    /// straight through).
    pub fn drives_handshake(&self) -> bool {
        self.handshake_step.is_some()
    }

    /// Drive one step of an interactive opening handshake (ADR 0013 §7 step 3): feed the module the
    /// `inbound` wire bytes (empty at connect — emit-at-connect) and return `(outbound_wire, done)`.
    /// The module frames its output as `[status: u8][outbound …]`; `done` is `status == 1`. Keys the
    /// handshake derives stay in the module and are used by the steady-state `transform_*` afterward.
    /// Errors with [`WasmError::MissingExport`] if the module has no `handshake_step`, or
    /// [`WasmError::HandshakeFrame`] on a malformed frame.
    pub fn handshake_step(&mut self, inbound: &[u8]) -> Result<(Vec<u8>, bool), WasmError> {
        let func = self
            .handshake_step
            .ok_or(WasmError::MissingExport(EXPORT_HANDSHAKE_STEP))?;
        let mut out = self.call_io(func, EXPORT_HANDSHAKE_STEP, inbound)?;
        if out.is_empty() {
            return Err(WasmError::HandshakeFrame(
                "empty frame (no status byte)".into(),
            ));
        }
        let done = match out.remove(0) {
            0 => false,
            1 => true,
            other => {
                return Err(WasmError::HandshakeFrame(format!(
                    "status byte {other} is not 0 (continue) or 1 (done)"
                )))
            }
        };
        Ok((out, done))
    }

    /// Drive an interactive opening handshake to completion over `stream` (ADR 0013 §7 step 3): emit
    /// the module's opening message (emit-at-connect), then loop — write each outbound message, read
    /// the peer's reply, step again — until the module signals done. The module owns all protocol
    /// state + derived keys; the caller then runs the steady-state byte transforms (e.g. via
    /// [`TransformStream`]) on the same `stream`. Returns `UnexpectedEof` if the peer closes mid-handshake.
    pub async fn run_handshake<S>(&mut self, stream: &mut S) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // One reusable stack buffer across steps (no per-iteration alloc). `n == 0` on the first
        // iteration is emit-at-connect: the module produces its opening message from empty input.
        let mut buf = [0u8; HANDSHAKE_READ_CHUNK];
        let mut n = 0usize;
        loop {
            let (outbound, done) = self.handshake_step(&buf[..n]).map_err(io::Error::other)?;
            if !outbound.is_empty() {
                stream.write_all(&outbound).await?;
                stream.flush().await?;
            }
            if done {
                return Ok(());
            }
            n = stream.read(&mut buf).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "peer closed during handshake",
                ));
            }
        }
    }

    /// Total bytes this session has drawn from the `host_rand` capability — observability for how
    /// much entropy the module consumes.
    pub fn entropy_drawn(&self) -> u64 {
        self.store.data().rand_bytes
    }

    fn run(&mut self, dir: Direction, input: &[u8]) -> Result<Vec<u8>, WasmError> {
        let (func, name) = match dir {
            Direction::Out => (self.transform_out, EXPORT_TRANSFORM_OUT),
            Direction::In => (self.transform_in, EXPORT_TRANSFORM_IN),
        };
        let func = func.ok_or(WasmError::MissingExport(name))?;
        self.call_io(func, name, input)
    }

    /// The shared guest-call sequence for any `(ptr, len) -> packed(out_ptr, out_len)` export
    /// (`transform_out`/`transform_in`/`compute_gambit`/`handshake_step`): refill fuel, `alloc` + write the input,
    /// call `func`, read the packed output region, then `reset` the scratch arena (if any).
    fn call_io(
        &mut self,
        func: TypedFunc<(i32, i32), i64>,
        name: &'static str,
        input: &[u8],
    ) -> Result<Vec<u8>, WasmError> {
        if input.len() > MAX_TRANSFORM_LEN {
            return Err(WasmError::InputTooLarge {
                len: input.len(),
                max: MAX_TRANSFORM_LEN,
            });
        }
        let len = input.len() as i32;
        // `TypedFunc`/`Memory` are `Copy`, so copy the handles out and borrow only `self.store`.
        let alloc = self.alloc;
        let memory = self.memory;

        // Refill the per-call fuel budget so a runaway module traps instead of spinning forever.
        set_fuel(&mut self.store, fuel_for(input.len()))?;

        let ptr = alloc
            .call(&mut self.store, len)
            .map_err(|source| classify_call(EXPORT_ALLOC, source))?;
        memory
            .write(&mut self.store, ptr as usize, input)
            .map_err(|e| WasmError::Memory(e.to_string()))?;

        let packed = func
            .call(&mut self.store, (ptr, len))
            .map_err(|source| classify_call(name, source))? as u64;
        self.take_fault()?;

        let out_ptr = (packed >> 32) as usize;
        let out_len = (packed & 0xFFFF_FFFF) as usize;
        if out_len > MAX_TRANSFORM_LEN {
            return Err(WasmError::BadOutputLen {
                len: out_len,
                max: MAX_TRANSFORM_LEN,
            });
        }
        let mut out = vec![0u8; out_len];
        memory
            .read(&self.store, out_ptr, &mut out)
            .map_err(|e| WasmError::Memory(e.to_string()))?;

        // Output is copied out, so reclaim the module's per-call scratch arena (if it has one). State
        // the module keeps in globals/fixed memory survives — `reset` only rewinds the bump arena.
        if let Some(reset) = self.reset {
            reset
                .call(&mut self.store, ())
                .map_err(|source| classify_call(EXPORT_RESET, source))?;
        }
        Ok(out)
    }

    /// Take and clear any fault a host function recorded during the last guest call.
    fn take_fault(&mut self) -> Result<(), WasmError> {
        match self.store.data_mut().fault.take() {
            Some(msg) => Err(WasmError::HostFault(msg)),
            None => Ok(()),
        }
    }
}

/// The per-call fuel budget for an input of `input_len` bytes (see [`FUEL_BASE`]).
fn fuel_for(input_len: usize) -> u64 {
    FUEL_BASE.saturating_add((input_len as u64).saturating_mul(FUEL_PER_BYTE))
}

/// Set the store's remaining fuel. Fuel metering is always enabled (see [`TransformModule::load`]),
/// so this only fails on an internal invariant violation.
fn set_fuel(store: &mut Store<HostState>, fuel: u64) -> Result<(), WasmError> {
    store
        .set_fuel(fuel)
        .map_err(|e| WasmError::Fuel(format!("set fuel: {e}")))
}

/// Map a failed guest call to an error, distinguishing fuel exhaustion (a runaway module) from other
/// traps — wasmi reports an out-of-fuel trap whose message mentions fuel.
fn classify_call(func: &'static str, source: wasmi::Error) -> WasmError {
    if source.to_string().contains("fuel") {
        WasmError::Fuel(format!(
            "`{func}` exhausted its execution budget (possible runaway)"
        ))
    } else {
        WasmError::Call { func, source }
    }
}

/// The `host_rand(ptr, len)` import: fill `len` guest bytes at `ptr` with CSPRNG output.
///
/// Infallible at the wasmi boundary — any failure (bad length, CSPRNG error, out-of-bounds write)
/// is recorded in [`HostState::fault`] and surfaced by [`Transform::take_fault`] after the guest
/// call returns. The length is range-checked before allocating, because the guest is untrusted and
/// a negative `i32` would otherwise become a huge `usize`.
fn host_rand(mut caller: Caller<HostState>, ptr: i32, len: i32) {
    if caller.data().fault.is_some() {
        return;
    }
    if !(0..=MAX_TRANSFORM_LEN as i32).contains(&len) {
        caller.data_mut().fault = Some(format!("host_rand: invalid length {len}"));
        return;
    }
    let mut buf = vec![0u8; len as usize];
    let fill = caller.data().rng.fill(&mut buf);
    if let Err(e) = fill {
        caller.data_mut().fault = Some(format!("host_rand: CSPRNG failed: {e}"));
        return;
    }
    let Some(memory) = caller
        .get_export(EXPORT_MEMORY)
        .and_then(Extern::into_memory)
    else {
        caller.data_mut().fault = Some("host_rand: no memory export".to_string());
        return;
    };
    if let Err(e) = memory.write(&mut caller, ptr as usize, &buf) {
        caller.data_mut().fault = Some(format!("host_rand: memory write: {e}"));
        return;
    }
    caller.data_mut().rand_bytes += len as u64;
}

/// The `host_hash(in_ptr, in_len, out_ptr)` import: write the SHA-256 ([`HASH_LEN`] bytes) of
/// `in_len` bytes at `in_ptr` to `out_ptr`. Faults are recorded and surfaced after the guest call.
fn host_hash(mut caller: Caller<HostState>, in_ptr: i32, in_len: i32, out_ptr: i32) {
    if caller.data().fault.is_some() {
        return;
    }
    let data = match read_guest(&caller, in_ptr, in_len) {
        Ok(d) => d,
        Err(msg) => {
            caller.data_mut().fault = Some(format!("host_hash: {msg}"));
            return;
        }
    };
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(digest::digest(&digest::SHA256, &data).as_ref());
    if let Err(msg) = write_guest(&mut caller, out_ptr, &out) {
        caller.data_mut().fault = Some(format!("host_hash: {msg}"));
    }
}

/// The `host_aead_seal(key_ptr, nonce_ptr, aad_ptr, aad_len, in_ptr, in_len, out_ptr) -> i64` import:
/// ChaCha20-Poly1305 seal of `in_len` plaintext bytes under the 32-byte key at `key_ptr` and 12-byte
/// nonce at `nonce_ptr`, binding `aad_len` associated-data bytes at `aad_ptr` (use length 0 for none),
/// writing `in_len + 16` (ciphertext+tag) bytes to `out_ptr`. Returns the output length, or `-1` with
/// a recorded fault.
#[allow(clippy::too_many_arguments)]
fn host_aead_seal(
    mut caller: Caller<HostState>,
    key_ptr: i32,
    nonce_ptr: i32,
    aad_ptr: i32,
    aad_len: i32,
    in_ptr: i32,
    in_len: i32,
    out_ptr: i32,
) -> i64 {
    if caller.data().fault.is_some() {
        return -1;
    }
    let sealed = match aead_seal(
        &caller, key_ptr, nonce_ptr, aad_ptr, aad_len, in_ptr, in_len,
    ) {
        Ok(s) => s,
        Err(msg) => {
            caller.data_mut().fault = Some(format!("host_aead_seal: {msg}"));
            return -1;
        }
    };
    match write_guest(&mut caller, out_ptr, &sealed) {
        Ok(()) => sealed.len() as i64,
        Err(msg) => {
            caller.data_mut().fault = Some(format!("host_aead_seal: {msg}"));
            -1
        }
    }
}

/// The `host_aead_open(key_ptr, nonce_ptr, aad_ptr, aad_len, in_ptr, in_len, out_ptr) -> i64` import:
/// the inverse of [`host_aead_seal`]. Reads `in_len` ciphertext+tag bytes (with the same AAD), writes
/// `in_len - 16` plaintext bytes to `out_ptr`, and returns the plaintext length. On authentication
/// failure (or any error) it returns `-1` and records a fault — a tampered or forged frame fails closed.
#[allow(clippy::too_many_arguments)]
fn host_aead_open(
    mut caller: Caller<HostState>,
    key_ptr: i32,
    nonce_ptr: i32,
    aad_ptr: i32,
    aad_len: i32,
    in_ptr: i32,
    in_len: i32,
    out_ptr: i32,
) -> i64 {
    if caller.data().fault.is_some() {
        return -1;
    }
    let plaintext = match aead_open(
        &caller, key_ptr, nonce_ptr, aad_ptr, aad_len, in_ptr, in_len,
    ) {
        Ok(p) => p,
        Err(msg) => {
            caller.data_mut().fault = Some(format!("host_aead_open: {msg}"));
            return -1;
        }
    };
    match write_guest(&mut caller, out_ptr, &plaintext) {
        Ok(()) => plaintext.len() as i64,
        Err(msg) => {
            caller.data_mut().fault = Some(format!("host_aead_open: {msg}"));
            -1
        }
    }
}

/// ChaCha20-Poly1305 seal, reading key/nonce/aad/plaintext from guest memory. Returns ciphertext+tag.
#[allow(clippy::too_many_arguments)]
fn aead_seal(
    caller: &Caller<HostState>,
    key_ptr: i32,
    nonce_ptr: i32,
    aad_ptr: i32,
    aad_len: i32,
    in_ptr: i32,
    in_len: i32,
) -> Result<Vec<u8>, String> {
    let key = read_guest_array::<AEAD_KEY_LEN>(caller, key_ptr)?;
    let nonce = read_guest_array::<AEAD_NONCE_LEN>(caller, nonce_ptr)?;
    let aad = read_guest(caller, aad_ptr, aad_len)?;
    let mut buf = read_guest(caller, in_ptr, in_len)?;
    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key).map_err(|_| "bad key")?,
    );
    key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(nonce),
        aead::Aad::from(aad.as_slice()),
        &mut buf,
    )
    .map_err(|_| "seal failed")?;
    Ok(buf)
}

/// ChaCha20-Poly1305 open, reading key/nonce/aad/ciphertext+tag from guest memory. Returns plaintext.
#[allow(clippy::too_many_arguments)]
fn aead_open(
    caller: &Caller<HostState>,
    key_ptr: i32,
    nonce_ptr: i32,
    aad_ptr: i32,
    aad_len: i32,
    in_ptr: i32,
    in_len: i32,
) -> Result<Vec<u8>, String> {
    let key = read_guest_array::<AEAD_KEY_LEN>(caller, key_ptr)?;
    let nonce = read_guest_array::<AEAD_NONCE_LEN>(caller, nonce_ptr)?;
    let aad = read_guest(caller, aad_ptr, aad_len)?;
    let mut buf = read_guest(caller, in_ptr, in_len)?;
    if buf.len() < AEAD_TAG_LEN {
        return Err("ciphertext shorter than the tag".to_string());
    }
    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key).map_err(|_| "bad key")?,
    );
    let plaintext = key
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(aad.as_slice()),
            &mut buf,
        )
        .map_err(|_| "authentication failed")?;
    Ok(plaintext.to_vec())
}

/// The `host_hkdf_extract(salt_ptr, salt_len, ikm_ptr, ikm_len, out_ptr) -> i64` import: HKDF-Extract
/// (== HMAC-SHA256 over the IKM keyed by the salt) writing the 32-byte PRK to `out_ptr`. `salt_len`
/// may be 0 (an unsalted extract, which HMAC pads to the zero key — equivalent to HKDF's default).
/// Returns 32, or `-1` with a recorded fault.
fn host_hkdf_extract(
    mut caller: Caller<HostState>,
    salt_ptr: i32,
    salt_len: i32,
    ikm_ptr: i32,
    ikm_len: i32,
    out_ptr: i32,
) -> i64 {
    if caller.data().fault.is_some() {
        return -1;
    }
    let prk = match hkdf_extract(&caller, salt_ptr, salt_len, ikm_ptr, ikm_len) {
        Ok(p) => p,
        Err(msg) => {
            caller.data_mut().fault = Some(format!("host_hkdf_extract: {msg}"));
            return -1;
        }
    };
    match write_guest(&mut caller, out_ptr, &prk) {
        Ok(()) => prk.len() as i64,
        Err(msg) => {
            caller.data_mut().fault = Some(format!("host_hkdf_extract: {msg}"));
            -1
        }
    }
}

/// The `host_hkdf_expand(prk_ptr, info_ptr, info_len, out_ptr, out_len) -> i64` import: HKDF-Expand
/// (SHA-256) of the 32-byte PRK at `prk_ptr` with the `info_len`-byte info at `info_ptr` (the module
/// builds its own TLS `HKDF-Expand-Label` info), writing `out_len` bytes to `out_ptr`. Returns
/// `out_len`, or `-1` with a recorded fault (including `out_len` > 255×32, HKDF's ceiling).
fn host_hkdf_expand(
    mut caller: Caller<HostState>,
    prk_ptr: i32,
    info_ptr: i32,
    info_len: i32,
    out_ptr: i32,
    out_len: i32,
) -> i64 {
    if caller.data().fault.is_some() {
        return -1;
    }
    let out = match hkdf_expand(&caller, prk_ptr, info_ptr, info_len, out_len) {
        Ok(o) => o,
        Err(msg) => {
            caller.data_mut().fault = Some(format!("host_hkdf_expand: {msg}"));
            return -1;
        }
    };
    match write_guest(&mut caller, out_ptr, &out) {
        Ok(()) => out.len() as i64,
        Err(msg) => {
            caller.data_mut().fault = Some(format!("host_hkdf_expand: {msg}"));
            -1
        }
    }
}

/// HKDF-Extract via HMAC-SHA256 (the PRK is the HMAC tag), reading salt + IKM from guest memory.
fn hkdf_extract(
    caller: &Caller<HostState>,
    salt_ptr: i32,
    salt_len: i32,
    ikm_ptr: i32,
    ikm_len: i32,
) -> Result<[u8; HKDF_PRK_LEN], String> {
    let salt = read_guest(caller, salt_ptr, salt_len)?;
    let ikm = read_guest(caller, ikm_ptr, ikm_len)?;
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &salt), &ikm);
    let mut prk = [0u8; HKDF_PRK_LEN];
    prk.copy_from_slice(tag.as_ref());
    Ok(prk)
}

/// HKDF-Expand (SHA-256), reading the 32-byte PRK + info from guest memory. Returns `out_len` bytes.
fn hkdf_expand(
    caller: &Caller<HostState>,
    prk_ptr: i32,
    info_ptr: i32,
    info_len: i32,
    out_len: i32,
) -> Result<Vec<u8>, String> {
    if !(0..=HKDF_MAX_EXPAND_LEN as i32).contains(&out_len) {
        return Err(format!("invalid expand length {out_len}"));
    }
    let prk_bytes = read_guest_array::<HKDF_PRK_LEN>(caller, prk_ptr)?;
    let info = read_guest(caller, info_ptr, info_len)?;
    let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &prk_bytes);
    // `info_slices` must outlive `okm` — the returned `Okm` borrows the info until `fill`.
    let info_slices = [info.as_slice()];
    let okm = prk
        .expand(&info_slices, HkdfLen(out_len as usize))
        .map_err(|_| "expand failed")?;
    let mut out = vec![0u8; out_len as usize];
    okm.fill(&mut out).map_err(|_| "fill failed")?;
    Ok(out)
}

/// A [`hkdf::KeyType`] for an arbitrary HKDF-Expand output length (ring keys `expand` on the output
/// type; this lets the module request a raw byte length).
struct HkdfLen(usize);
impl hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// The `host_aes_gcm_seal(key_ptr, key_len, nonce_ptr, aad_ptr, aad_len, in_ptr, in_len, out_ptr) -> i64`
/// import: AES-GCM seal (`key_len` 16 ⇒ AES-128-GCM, 32 ⇒ AES-256-GCM), 12-byte nonce, writing
/// `in_len + 16` (ciphertext+tag) bytes to `out_ptr`. Returns the output length, or `-1` with a fault.
#[allow(clippy::too_many_arguments)]
fn host_aes_gcm_seal(
    mut caller: Caller<HostState>,
    key_ptr: i32,
    key_len: i32,
    nonce_ptr: i32,
    aad_ptr: i32,
    aad_len: i32,
    in_ptr: i32,
    in_len: i32,
    out_ptr: i32,
) -> i64 {
    if caller.data().fault.is_some() {
        return -1;
    }
    let sealed = match aes_gcm_seal(
        &caller, key_ptr, key_len, nonce_ptr, aad_ptr, aad_len, in_ptr, in_len,
    ) {
        Ok(s) => s,
        Err(msg) => {
            caller.data_mut().fault = Some(format!("host_aes_gcm_seal: {msg}"));
            return -1;
        }
    };
    match write_guest(&mut caller, out_ptr, &sealed) {
        Ok(()) => sealed.len() as i64,
        Err(msg) => {
            caller.data_mut().fault = Some(format!("host_aes_gcm_seal: {msg}"));
            -1
        }
    }
}

/// The `host_aes_gcm_open(...) -> i64` import: the inverse of [`host_aes_gcm_seal`]. Writes
/// `in_len - 16` plaintext bytes to `out_ptr`, returns the plaintext length, or `-1` on
/// authentication failure (a tampered or forged frame fails closed).
#[allow(clippy::too_many_arguments)]
fn host_aes_gcm_open(
    mut caller: Caller<HostState>,
    key_ptr: i32,
    key_len: i32,
    nonce_ptr: i32,
    aad_ptr: i32,
    aad_len: i32,
    in_ptr: i32,
    in_len: i32,
    out_ptr: i32,
) -> i64 {
    if caller.data().fault.is_some() {
        return -1;
    }
    let plaintext = match aes_gcm_open(
        &caller, key_ptr, key_len, nonce_ptr, aad_ptr, aad_len, in_ptr, in_len,
    ) {
        Ok(p) => p,
        Err(msg) => {
            caller.data_mut().fault = Some(format!("host_aes_gcm_open: {msg}"));
            return -1;
        }
    };
    match write_guest(&mut caller, out_ptr, &plaintext) {
        Ok(()) => plaintext.len() as i64,
        Err(msg) => {
            caller.data_mut().fault = Some(format!("host_aes_gcm_open: {msg}"));
            -1
        }
    }
}

/// The AES-GCM algorithm selected by key length: 16 ⇒ AES-128-GCM, 32 ⇒ AES-256-GCM.
fn aes_gcm_alg(key_len: i32) -> Result<&'static aead::Algorithm, String> {
    match key_len {
        16 => Ok(&aead::AES_128_GCM),
        32 => Ok(&aead::AES_256_GCM),
        n => Err(format!(
            "unsupported AES-GCM key length {n} (want 16 or 32)"
        )),
    }
}

/// AES-GCM seal, reading key/nonce/aad/plaintext from guest memory. Returns ciphertext+tag.
#[allow(clippy::too_many_arguments)]
fn aes_gcm_seal(
    caller: &Caller<HostState>,
    key_ptr: i32,
    key_len: i32,
    nonce_ptr: i32,
    aad_ptr: i32,
    aad_len: i32,
    in_ptr: i32,
    in_len: i32,
) -> Result<Vec<u8>, String> {
    let alg = aes_gcm_alg(key_len)?;
    let key = read_guest(caller, key_ptr, key_len)?;
    let nonce = read_guest_array::<AEAD_NONCE_LEN>(caller, nonce_ptr)?;
    let aad = read_guest(caller, aad_ptr, aad_len)?;
    let mut buf = read_guest(caller, in_ptr, in_len)?;
    let key = aead::LessSafeKey::new(aead::UnboundKey::new(alg, &key).map_err(|_| "bad key")?);
    key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(nonce),
        aead::Aad::from(aad.as_slice()),
        &mut buf,
    )
    .map_err(|_| "seal failed")?;
    Ok(buf)
}

/// AES-GCM open, reading key/nonce/aad/ciphertext+tag from guest memory. Returns plaintext.
#[allow(clippy::too_many_arguments)]
fn aes_gcm_open(
    caller: &Caller<HostState>,
    key_ptr: i32,
    key_len: i32,
    nonce_ptr: i32,
    aad_ptr: i32,
    aad_len: i32,
    in_ptr: i32,
    in_len: i32,
) -> Result<Vec<u8>, String> {
    let alg = aes_gcm_alg(key_len)?;
    let key = read_guest(caller, key_ptr, key_len)?;
    let nonce = read_guest_array::<AEAD_NONCE_LEN>(caller, nonce_ptr)?;
    let aad = read_guest(caller, aad_ptr, aad_len)?;
    let mut buf = read_guest(caller, in_ptr, in_len)?;
    if buf.len() < AEAD_TAG_LEN {
        return Err("ciphertext shorter than the tag".to_string());
    }
    let key = aead::LessSafeKey::new(aead::UnboundKey::new(alg, &key).map_err(|_| "bad key")?);
    let plaintext = key
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(aad.as_slice()),
            &mut buf,
        )
        .map_err(|_| "authentication failed")?;
    Ok(plaintext.to_vec())
}

/// The `host_x25519_generate(out_pub_ptr) -> i64` import: generate an ephemeral X25519 keypair,
/// write the 32-byte public key to `out_pub_ptr`, store the private key host-side, and return its
/// id. The private key never enters guest memory. `-1` with a recorded fault on error (including
/// more than [`MAX_X25519_KEYS`] live keys).
fn host_x25519_generate(mut caller: Caller<HostState>, out_pub_ptr: i32) -> i64 {
    if caller.data().fault.is_some() {
        return -1;
    }
    let live = caller
        .data()
        .x25519_keys
        .iter()
        .filter(|k| k.is_some())
        .count();
    if live >= MAX_X25519_KEYS {
        caller.data_mut().fault = Some(format!(
            "host_x25519_generate: too many live keys (max {MAX_X25519_KEYS})"
        ));
        return -1;
    }
    // A fresh `SystemRandom` is the same OS entropy source as `HostState::rng` and avoids borrowing
    // `caller` immutably while we also mutate the key registry below.
    let rng = SystemRandom::new();
    let private = match agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng) {
        Ok(p) => p,
        Err(_) => {
            caller.data_mut().fault = Some("host_x25519_generate: keygen failed".to_string());
            return -1;
        }
    };
    let public = match private.compute_public_key() {
        Ok(p) => p,
        Err(_) => {
            caller.data_mut().fault =
                Some("host_x25519_generate: public-key derivation failed".to_string());
            return -1;
        }
    };
    if let Err(msg) = write_guest(&mut caller, out_pub_ptr, public.as_ref()) {
        caller.data_mut().fault = Some(format!("host_x25519_generate: {msg}"));
        return -1;
    }
    // Reuse a freed slot if one exists so the registry stays bounded by the live cap.
    let keys = &mut caller.data_mut().x25519_keys;
    match keys.iter().position(Option::is_none) {
        Some(id) => {
            keys[id] = Some(private);
            id as i64
        }
        None => {
            let id = keys.len();
            keys.push(Some(private));
            id as i64
        }
    }
}

/// The `host_x25519_agree(key_id, peer_pub_ptr, out_ptr) -> i64` import: X25519 ECDH between the
/// stored private key `key_id` (consumed) and the 32-byte peer public key at `peer_pub_ptr`, writing
/// the 32-byte shared secret to `out_ptr`. Returns 32, or `-1` with a recorded fault (unknown/
/// already-consumed key id, or a bad peer point).
fn host_x25519_agree(
    mut caller: Caller<HostState>,
    key_id: i32,
    peer_pub_ptr: i32,
    out_ptr: i32,
) -> i64 {
    if caller.data().fault.is_some() {
        return -1;
    }
    if key_id < 0 {
        caller.data_mut().fault = Some(format!("host_x25519_agree: invalid key id {key_id}"));
        return -1;
    }
    let private = match caller
        .data_mut()
        .x25519_keys
        .get_mut(key_id as usize)
        .and_then(Option::take)
    {
        Some(p) => p,
        None => {
            caller.data_mut().fault = Some(format!(
                "host_x25519_agree: unknown or already-consumed key id {key_id}"
            ));
            return -1;
        }
    };
    let peer = match read_guest_array::<X25519_KEY_LEN>(&caller, peer_pub_ptr) {
        Ok(p) => p,
        Err(msg) => {
            caller.data_mut().fault = Some(format!("host_x25519_agree: {msg}"));
            return -1;
        }
    };
    let shared = agreement::agree_ephemeral(
        private,
        &agreement::UnparsedPublicKey::new(&agreement::X25519, peer),
        |secret| secret.to_vec(),
    );
    let shared = match shared {
        Ok(s) => s,
        Err(_) => {
            caller.data_mut().fault = Some("host_x25519_agree: agreement failed".to_string());
            return -1;
        }
    };
    match write_guest(&mut caller, out_ptr, &shared) {
        Ok(()) => shared.len() as i64,
        Err(msg) => {
            caller.data_mut().fault = Some(format!("host_x25519_agree: {msg}"));
            -1
        }
    }
}

/// The `host_chacha20(key_ptr, nonce_ptr, counter, in_ptr, in_len, out_ptr) -> i64` import: raw IETF
/// ChaCha20 keystream (no AEAD tag) — a general stream cipher. 32-byte key, 12-byte nonce, and a
/// 32-bit initial block `counter` (so a caller can seek / rekey, e.g. FSChaCha20). XORs `in_len` bytes
/// at `in_ptr` with the keystream into `out_ptr`; returns the byte length, or `-1` with a recorded
/// fault. Encrypt and decrypt are the same operation.
fn host_chacha20(
    mut caller: Caller<HostState>,
    key_ptr: i32,
    nonce_ptr: i32,
    counter: i32,
    in_ptr: i32,
    in_len: i32,
    out_ptr: i32,
) -> i64 {
    if caller.data().fault.is_some() {
        return -1;
    }
    let key = match read_guest_array::<CHACHA20_KEY_LEN>(&caller, key_ptr) {
        Ok(k) => k,
        Err(msg) => {
            caller.data_mut().fault = Some(format!("host_chacha20: {msg}"));
            return -1;
        }
    };
    let nonce = match read_guest_array::<CHACHA20_NONCE_LEN>(&caller, nonce_ptr) {
        Ok(n) => n,
        Err(msg) => {
            caller.data_mut().fault = Some(format!("host_chacha20: {msg}"));
            return -1;
        }
    };
    let mut buf = match read_guest(&caller, in_ptr, in_len) {
        Ok(b) => b,
        Err(msg) => {
            caller.data_mut().fault = Some(format!("host_chacha20: {msg}"));
            return -1;
        }
    };
    let mut cipher = ChaCha20::new(&Key::from(key), &Nonce::from(nonce));
    // Start at block `counter` (64 bytes/block). `counter as u32` reinterprets a negative i32 as a
    // valid 32-bit block index; `try_*` variants return an error (not panic) if the guest overruns.
    if cipher.try_seek((counter as u32 as u64) * 64).is_err() {
        caller.data_mut().fault = Some("host_chacha20: counter out of range".to_string());
        return -1;
    }
    if cipher.try_apply_keystream(&mut buf).is_err() {
        caller.data_mut().fault = Some("host_chacha20: keystream exhausted".to_string());
        return -1;
    }
    match write_guest(&mut caller, out_ptr, &buf) {
        Ok(()) => buf.len() as i64,
        Err(msg) => {
            caller.data_mut().fault = Some(format!("host_chacha20: {msg}"));
            -1
        }
    }
}

/// The `host_secp256k1_ellswift_generate(out_ellswift_ptr) -> key_id` import: generate a secp256k1
/// keypair, write the 64-byte ElligatorSwift encoding of the public key to `out_ellswift_ptr`, store
/// the secret (with its encoding) host-side, and return its id. The secret never enters guest memory.
/// `-1` with a recorded fault on error (including more than [`MAX_SECP256K1_KEYS`] live keys).
/// A process-wide secp256k1 context (ecmult-gen tables built once). Needed for ElligatorSwift keygen:
/// this `secp256k1-sys` build has no static ecmult-gen table, so the no-precomp context can't derive a
/// public key. Contexts are `Sync` and meant to be long-lived + shared, so one lazy global suffices.
#[cfg(feature = "bip324")]
fn secp_context() -> &'static secp256k1::Secp256k1<secp256k1::All> {
    use std::sync::OnceLock;
    static CTX: OnceLock<secp256k1::Secp256k1<secp256k1::All>> = OnceLock::new();
    CTX.get_or_init(secp256k1::Secp256k1::new)
}

#[cfg(feature = "bip324")]
fn host_secp256k1_ellswift_generate(mut caller: Caller<HostState>, out_ellswift_ptr: i32) -> i64 {
    if caller.data().fault.is_some() {
        return -1;
    }
    let live = caller
        .data()
        .secp256k1_keys
        .iter()
        .filter(|k| k.is_some())
        .count();
    if live >= MAX_SECP256K1_KEYS {
        caller.data_mut().fault = Some(format!(
            "host_secp256k1_ellswift_generate: too many live keys (max {MAX_SECP256K1_KEYS})"
        ));
        return -1;
    }
    // Draw the secret key + the ElligatorSwift aux randomness from the OS CSPRNG (no `rand`-trait dep).
    // A uniform 32-byte scalar is out of range only with ~2^-128 probability; retry the draw a few
    // times rather than sticky-fault (brick) the module on that near-impossible event.
    let rng = SystemRandom::new();
    let mut found = None;
    for _ in 0..8 {
        let mut seed = [0u8; 64];
        if rng.fill(&mut seed).is_err() {
            caller.data_mut().fault =
                Some("host_secp256k1_ellswift_generate: CSPRNG failed".to_string());
            return -1;
        }
        let mut sk_bytes = [0u8; 32];
        sk_bytes.copy_from_slice(&seed[..32]);
        if let Ok(secret) = SecretKey::from_byte_array(sk_bytes) {
            let mut aux = [0u8; 32];
            aux.copy_from_slice(&seed[32..]);
            found = Some((secret, aux));
            break;
        }
    }
    let (secret, aux) = match found {
        Some(pair) => pair,
        None => {
            caller.data_mut().fault =
                Some("host_secp256k1_ellswift_generate: no valid scalar after retries".to_string());
            return -1;
        }
    };
    let ellswift = ElligatorSwift::from_seckey(secp_context(), secret, Some(aux));
    if let Err(msg) = write_guest(&mut caller, out_ellswift_ptr, &ellswift.to_array()) {
        caller.data_mut().fault = Some(format!("host_secp256k1_ellswift_generate: {msg}"));
        return -1;
    }
    // Reuse a freed slot if one exists so the registry stays bounded by the live cap.
    let keys = &mut caller.data_mut().secp256k1_keys;
    match keys.iter().position(Option::is_none) {
        Some(id) => {
            keys[id] = Some((secret, ellswift));
            id as i64
        }
        None => {
            let id = keys.len();
            keys.push(Some((secret, ellswift)));
            id as i64
        }
    }
}

/// The `host_secp256k1_ellswift_ecdh(key_id, peer_ellswift_ptr, out_ptr) -> i64` import: secp256k1
/// X-only ECDH between the stored key `key_id` (consumed) and the peer's 64-byte ElligatorSwift key at
/// `peer_ellswift_ptr`, writing the **raw 32-byte shared x-coordinate** to `out_ptr`. Returns 32, or
/// `-1` with a recorded fault. The shared x is protocol-neutral (no BIP324 tagged hash) — a transport
/// composes its own KDF over it in-guest.
#[cfg(feature = "bip324")]
fn host_secp256k1_ellswift_ecdh(
    mut caller: Caller<HostState>,
    key_id: i32,
    peer_ellswift_ptr: i32,
    out_ptr: i32,
) -> i64 {
    if caller.data().fault.is_some() {
        return -1;
    }
    if key_id < 0 {
        caller.data_mut().fault = Some(format!(
            "host_secp256k1_ellswift_ecdh: invalid key id {key_id}"
        ));
        return -1;
    }
    let (secret, own_ell) = match caller
        .data_mut()
        .secp256k1_keys
        .get_mut(key_id as usize)
        .and_then(Option::take)
    {
        Some(k) => k,
        None => {
            caller.data_mut().fault = Some(format!(
                "host_secp256k1_ellswift_ecdh: unknown or already-consumed key id {key_id}"
            ));
            return -1;
        }
    };
    let peer = match read_guest_array::<SECP256K1_ELLSWIFT_LEN>(&caller, peer_ellswift_ptr) {
        Ok(p) => p,
        Err(msg) => {
            caller.data_mut().fault = Some(format!("host_secp256k1_ellswift_ecdh: {msg}"));
            return -1;
        }
    };
    // Raw X-only ECDH: the hasher returns the shared point's x-coordinate verbatim (no BIP324 tagged
    // hash). `Party::Initiator` with (own, peer) ordering yields the symmetric shared x — identical on
    // both sides regardless of protocol role — so no initiator flag is needed here.
    let shared = ElligatorSwift::shared_secret_with_hasher(
        own_ell,
        ElligatorSwift::from_array(peer),
        secret,
        Party::Initiator,
        |x, _own, _peer| ElligatorSwiftSharedSecret::from_secret_bytes(x),
    );
    match write_guest(&mut caller, out_ptr, shared.as_secret_bytes()) {
        Ok(()) => SECP256K1_SHARED_LEN as i64,
        Err(msg) => {
            caller.data_mut().fault = Some(format!("host_secp256k1_ellswift_ecdh: {msg}"));
            -1
        }
    }
}

/// Read `len` bytes at `ptr` from the caller's guest memory, range-checking `len` against
/// [`MAX_TRANSFORM_LEN`] before allocating (the guest is untrusted; a negative `i32` would become a
/// huge `usize`).
fn read_guest(caller: &Caller<HostState>, ptr: i32, len: i32) -> Result<Vec<u8>, String> {
    if !(0..=MAX_TRANSFORM_LEN as i32).contains(&len) {
        return Err(format!("invalid length {len}"));
    }
    let memory = guest_memory(caller)?;
    let mut buf = vec![0u8; len as usize];
    memory
        .read(caller, ptr as usize, &mut buf)
        .map_err(|e| e.to_string())?;
    Ok(buf)
}

/// Read a fixed `N` bytes at `ptr` from the caller's guest memory (for keys, nonces).
fn read_guest_array<const N: usize>(
    caller: &Caller<HostState>,
    ptr: i32,
) -> Result<[u8; N], String> {
    let memory = guest_memory(caller)?;
    let mut buf = [0u8; N];
    memory
        .read(caller, ptr as usize, &mut buf)
        .map_err(|e| e.to_string())?;
    Ok(buf)
}

/// Write `bytes` at `ptr` into the caller's guest memory.
fn write_guest(caller: &mut Caller<HostState>, ptr: i32, bytes: &[u8]) -> Result<(), String> {
    let memory = guest_memory(caller)?;
    memory
        .write(caller, ptr as usize, bytes)
        .map_err(|e| e.to_string())
}

/// The caller's exported linear memory, or an error if it has none.
fn guest_memory(caller: &Caller<HostState>) -> Result<Memory, String> {
    caller
        .get_export(EXPORT_MEMORY)
        .and_then(Extern::into_memory)
        .ok_or_else(|| "no memory export".to_string())
}

/// Test-only fixtures, shared by this module's tests and the [`stream`] adapter's tests.
#[cfg(test)]
pub(crate) mod testutil {
    use super::TransformModule;

    /// A minimal Path B transform module, in WebAssembly text. It XORs every byte with `0x5A`
    /// (length-preserving and involutive, so `transform_in` undoes `transform_out`) and, in
    /// `transform_out`, calls the `host_rand` import once — proving the host capability is wired.
    pub const XOR_WAT: &str = r#"
(module
  (import "env" "host_rand" (func $host_rand (param i32 i32)))
  (memory (export "memory") 40)
  (global $bump (mut i32) (i32.const 1024))
  (func (export "alloc") (param $len i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $bump))
    (global.set $bump (i32.add (global.get $bump) (local.get $len)))
    (local.get $p))
  (func $xor (param $ptr i32) (param $len i32)
    (local $i i32)
    (block $done
      (loop $loop
        (br_if $done (i32.ge_u (local.get $i) (local.get $len)))
        (i32.store8
          (i32.add (local.get $ptr) (local.get $i))
          (i32.xor
            (i32.load8_u (i32.add (local.get $ptr) (local.get $i)))
            (i32.const 0x5a)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $loop))))
  (func (export "transform_out") (param $ptr i32) (param $len i32) (result i64)
    (call $host_rand (i32.const 0) (i32.const 4))
    (call $xor (local.get $ptr) (local.get $len))
    (i64.or
      (i64.shl (i64.extend_i32_u (local.get $ptr)) (i64.const 32))
      (i64.extend_i32_u (local.get $len))))
  (func (export "transform_in") (param $ptr i32) (param $len i32) (result i64)
    (call $xor (local.get $ptr) (local.get $len))
    (i64.or
      (i64.shl (i64.extend_i32_u (local.get $ptr)) (i64.const 32))
      (i64.extend_i32_u (local.get $len)))))
"#;

    /// Compile the XOR fixture into a [`TransformModule`].
    pub fn xor_module() -> TransformModule {
        let wasm = wat::parse_str(XOR_WAT).expect("assemble fixture");
        TransformModule::load(&wasm).expect("load module")
    }

    // The dev signing key + keypair moved to the module level (`super`), gated
    // `#[cfg(any(test, feature = "module-signer"))]` so the `sign-module` tool can reuse them. Kept
    // reachable here as `testutil::dev_keypair` for the existing tests.
    pub(crate) use super::dev_keypair;
}

#[cfg(test)]
mod capability_tests {
    use super::testutil::XOR_WAT;
    use super::*;

    /// The XOR fixture imports exactly one host function, `host_rand`, which makes it a precise probe
    /// for the allow-list: grant it and the module loads, withhold it and instantiation must fail.
    #[test]
    fn a_module_may_only_import_what_it_was_granted() {
        let wasm = wat::parse_str(XOR_WAT).expect("assemble fixture");

        // Unrestricted (a locally provisioned artifact) — the whole table, as before.
        TransformModule::load(&wasm)
            .expect("compile")
            .instantiate()
            .expect("an unrestricted module keeps the full host table");

        // Scoped to exactly what it needs.
        TransformModule::load_scoped(&wasm, Some(vec![HOST_RAND.to_owned()]))
            .expect("compile")
            .instantiate()
            .expect("granting host_rand is sufficient for the XOR fixture");

        // Scoped to something else: the import it needs is simply not in the linker, so
        // instantiation fails. This is the property the whole feature rests on — if this passed,
        // scoping would be decorative.
        let err = TransformModule::load_scoped(&wasm, Some(vec![HOST_HASH.to_owned()]))
            .expect("compile")
            .instantiate()
            .map(|_| ())
            .expect_err("a module must not instantiate without an import it uses");
        let msg = err.to_string();
        assert!(
            msg.contains(HOST_RAND) || msg.to_lowercase().contains("import"),
            "the error should identify the missing import, got: {msg}"
        );

        // The empty list is a real restriction, not a synonym for "unrestricted".
        assert!(
            TransformModule::load_scoped(&wasm, Some(Vec::new()))
                .expect("compile")
                .instantiate()
                .map(|_| ())
                .is_err(),
            "an empty allow-list must grant nothing"
        );
    }

    /// Scoping must not weaken a module that stays within its grant: the transform still works, and
    /// the granted capability is genuinely usable rather than a stub.
    #[test]
    fn a_scoped_module_still_functions_within_its_grant() {
        let wasm = wat::parse_str(XOR_WAT).expect("assemble fixture");
        let mut t = TransformModule::load_scoped(&wasm, Some(vec![HOST_RAND.to_owned()]))
            .expect("compile")
            .instantiate()
            .expect("instantiate");
        let out = t.transform_out(b"hello").expect("transform");
        assert_eq!(out, b"hello".iter().map(|b| b ^ 0x5A).collect::<Vec<_>>());
        assert!(
            t.entropy_drawn() > 0,
            "the granted host_rand was actually called, not stubbed"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::xor_module;
    use super::*;
    use crate::transport::engine::Genome;
    use flint_tls::gambit::Gambit;

    /// Throughput floor of the transform layer: a trivial XOR transform whose `alloc` resets to a
    /// fixed scratch base each call (no arena growth), so it isolates wasmi dispatch + host
    /// marshalling + the per-call `Vec` allocation — not transform logic. Release-only and ignored;
    /// run: `cargo test --release --features wasm-transport -- --ignored --nocapture bench_transform`.
    #[cfg(not(debug_assertions))]
    #[test]
    #[ignore = "throughput benchmark — run explicitly with --release --ignored --nocapture"]
    fn bench_transform_throughput() {
        const BENCH_WAT: &str = r#"
(module
  (memory (export "memory") 32)
  (func (export "alloc") (param $len i32) (result i32) (i32.const 1024))
  (func $xor (param $ptr i32) (param $len i32)
    (local $i i32)
    (block $done (loop $loop
      (br_if $done (i32.ge_u (local.get $i) (local.get $len)))
      (i32.store8 (i32.add (local.get $ptr) (local.get $i))
        (i32.xor (i32.load8_u (i32.add (local.get $ptr) (local.get $i))) (i32.const 0x5a)))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $loop))))
  (func (export "transform_out") (param $ptr i32) (param $len i32) (result i64)
    (call $xor (local.get $ptr) (local.get $len))
    (i64.or (i64.shl (i64.extend_i32_u (local.get $ptr)) (i64.const 32))
            (i64.extend_i32_u (local.get $len))))
  (func (export "transform_in") (param $ptr i32) (param $len i32) (result i64)
    (call $xor (local.get $ptr) (local.get $len))
    (i64.or (i64.shl (i64.extend_i32_u (local.get $ptr)) (i64.const 32))
            (i64.extend_i32_u (local.get $len)))))
"#;
        let module = TransformModule::load(&wat::parse_str(BENCH_WAT).expect("wat")).expect("load");
        let mut t = module.instantiate().expect("instantiate");

        for &chunk in &[1500usize, 16384, 65536] {
            let data = vec![0xABu8; chunk];
            for _ in 0..200 {
                let _ = t.transform_out(&data).expect("warm");
            }
            let iters = (512 * 1024 * 1024 / chunk).max(2000);
            let start = std::time::Instant::now();
            for _ in 0..iters {
                let out = t
                    .transform_out(std::hint::black_box(&data))
                    .expect("transform");
                std::hint::black_box(&out);
            }
            let el = start.elapsed();
            let gbps = (iters as f64 * chunk as f64 * 8.0) / el.as_secs_f64() / 1e9;
            let ns = el.as_nanos() as f64 / iters as f64;
            println!("wasm transform_out chunk={chunk:>6}: {gbps:7.2} Gb/s   {ns:9.0} ns/call");
        }

        // Marshalling-only floor: a passthrough transform that does NO per-byte work in the
        // interpreter (just returns the region). This is what a well-structured module pays per call
        // — the ADR keeps bulk byte work native (host fns) and interprets only control/framing — so
        // it bounds the overhead of a module that ISN'T mangling every byte in the interpreter.
        const PASS_WAT: &str = r#"
(module
  (memory (export "memory") 32)
  (func (export "alloc") (param $len i32) (result i32) (i32.const 1024))
  (func (export "transform_out") (param $ptr i32) (param $len i32) (result i64)
    (i64.or (i64.shl (i64.extend_i32_u (local.get $ptr)) (i64.const 32))
            (i64.extend_i32_u (local.get $len))))
  (func (export "transform_in") (param $ptr i32) (param $len i32) (result i64)
    (i64.or (i64.shl (i64.extend_i32_u (local.get $ptr)) (i64.const 32))
            (i64.extend_i32_u (local.get $len)))))
"#;
        let pass = TransformModule::load(&wat::parse_str(PASS_WAT).expect("wat")).expect("load");
        let mut pt = pass.instantiate().expect("instantiate");
        for &chunk in &[1500usize, 16384, 65536] {
            let data = vec![0xABu8; chunk];
            for _ in 0..200 {
                let _ = pt.transform_out(&data).expect("warm");
            }
            let iters = (512 * 1024 * 1024 / chunk).max(2000);
            let start = std::time::Instant::now();
            for _ in 0..iters {
                let out = pt
                    .transform_out(std::hint::black_box(&data))
                    .expect("transform");
                std::hint::black_box(&out);
            }
            let el = start.elapsed();
            let gbps = (iters as f64 * chunk as f64 * 8.0) / el.as_secs_f64() / 1e9;
            let ns = el.as_nanos() as f64 / iters as f64;
            println!("wasm passthrough   chunk={chunk:>6}: {gbps:7.2} Gb/s   {ns:9.0} ns/call");
        }

        // Bulk crypto done the RIGHT way (ADR 0003): a module that seals each chunk via the native
        // ChaCha20-Poly1305 host fn, interpreting nothing per byte. This is the realistic overhead of
        // an encrypting transport — contrast the XOR-in-interpreter number above.
        const AEAD_BENCH_WAT: &str = r#"
(module
  (import "env" "host_aead_seal" (func $seal (param i32 i32 i32 i32 i32 i32 i32) (result i64)))
  (memory (export "memory") 64)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "transform_out") (param $ptr i32) (param $len i32) (result i64)
    (local $n i64)
    ;; seal(key=0, nonce=32, aad=0 len 0, in=ptr len, out=524288)
    (local.set $n (call $seal (i32.const 0) (i32.const 32) (i32.const 0) (i32.const 0) (local.get $ptr) (local.get $len) (i32.const 524288)))
    (i64.or (i64.shl (i64.const 524288) (i64.const 32)) (local.get $n)))
  (func (export "transform_in") (param i32 i32) (result i64) (i64.const 0)))
"#;
        let aead =
            TransformModule::load(&wat::parse_str(AEAD_BENCH_WAT).expect("wat")).expect("load");
        let mut at = aead.instantiate().expect("instantiate");
        for &chunk in &[1500usize, 16384, 65536] {
            let data = vec![0xABu8; chunk];
            for _ in 0..200 {
                let _ = at.transform_out(&data).expect("warm");
            }
            let iters = (512 * 1024 * 1024 / chunk).max(2000);
            let start = std::time::Instant::now();
            for _ in 0..iters {
                let out = at.transform_out(std::hint::black_box(&data)).expect("seal");
                std::hint::black_box(&out);
            }
            let el = start.elapsed();
            let gbps = (iters as f64 * chunk as f64 * 8.0) / el.as_secs_f64() / 1e9;
            let ns = el.as_nanos() as f64 / iters as f64;
            println!("wasm host-AEAD     chunk={chunk:>6}: {gbps:7.2} Gb/s   {ns:9.0} ns/call");
        }

        // Native XOR baseline (the same work, no wasm) for scale.
        let chunk = 65536usize;
        let data = vec![0xABu8; chunk];
        let mut sink = vec![0u8; chunk];
        let iters = 512 * 1024 * 1024 / chunk;
        let start = std::time::Instant::now();
        for _ in 0..iters {
            for i in 0..chunk {
                sink[i] = data[i] ^ 0x5a;
            }
            std::hint::black_box(&sink);
        }
        let el = start.elapsed();
        let gbps = (iters as f64 * chunk as f64 * 8.0) / el.as_secs_f64() / 1e9;
        println!("native XOR baseline   chunk={chunk:>6}: {gbps:7.2} Gb/s");
    }

    #[test]
    fn round_trips_through_the_module() {
        let module = xor_module();
        let mut t = module.instantiate().expect("instantiate");
        let plaintext = b"the quick brown fox jumps over the lazy dog";
        let wire = t.transform_out(plaintext).expect("transform_out");
        assert_ne!(
            wire.as_slice(),
            &plaintext[..],
            "wire bytes must be transformed"
        );
        let recovered = t.transform_in(&wire).expect("transform_in");
        assert_eq!(
            recovered.as_slice(),
            &plaintext[..],
            "round-trip must recover the input"
        );
    }

    /// End-to-end proof of the Rust→wasm32 build-and-sign pipeline (ADR 0013 §7 step 4): load the
    /// committed, dev-key-signed `obfs-xor.spkw` — compiled by `scripts/build-module.sh` from the
    /// Rust guest in `modules/obfs-xor`, which mirrors [`testutil::XOR_WAT`] — through the exact
    /// production path (`ModuleVerifier::pinned().verify` → `instantiate`) and round-trip bytes
    /// through it. Needs no wasm32 toolchain: it consumes the committed artifact.
    #[test]
    fn signed_module_fixture_verifies_and_round_trips() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/wasm/obfs-xor.spkw");
        let artifact = std::fs::read(&path).expect("read the committed obfs-xor.spkw fixture");

        // The pinned key is the dev key in a debug/test build (signing::SPARK_MODULE_PUBKEY); a zero
        // anti-rollback floor accepts the fixture's version.
        let signed = ModuleVerifier::pinned()
            .verify(&artifact, 0)
            .expect("verify + compile the signed fixture");
        assert_eq!(signed.name(), "obfs-xor");
        assert_eq!(signed.version(), 1);

        let mut t = signed.into_module().instantiate().expect("instantiate");
        let plaintext = b"hello pipeline";
        let wire = t.transform_out(plaintext).expect("transform_out");
        assert_ne!(
            wire.as_slice(),
            &plaintext[..],
            "compiled module transformed the bytes"
        );
        let recovered = t.transform_in(&wire).expect("transform_in");
        assert_eq!(
            recovered.as_slice(),
            &plaintext[..],
            "round-trip recovers the input"
        );
        // Large-input coverage isn't automatable here: a single big transform overflows wasmi's
        // debug interpreter stack (the release-only `transforms_a_large_payload_in_one_call_release`
        // artifact), and a release build can't reach `pinned()` without `SPARK_MODULE_PUBKEY_HEX`. The
        // guest arena is sized to the host's `MAX_TRANSFORM_LEN`, so no valid input is rejected.
    }

    #[test]
    fn empty_input_round_trips() {
        let module = xor_module();
        let mut t = module.instantiate().expect("instantiate");
        let wire = t.transform_out(b"").expect("transform_out");
        assert!(wire.is_empty());
        assert!(t.transform_in(&wire).expect("transform_in").is_empty());
    }

    #[test]
    fn host_rand_capability_is_invoked() {
        let module = xor_module();
        let mut t = module.instantiate().expect("instantiate");
        assert_eq!(t.entropy_drawn(), 0);
        let _ = t.transform_out(b"abc").expect("transform_out");
        // `transform_out` calls `host_rand(_, 4)` exactly once.
        assert_eq!(
            t.entropy_drawn(),
            4,
            "guest must have drawn 4 bytes from host_rand"
        );
    }

    // Release-only: a single large transform (256 KiB) round-trips. wasmi's interpreter uses
    // tail-call threading, which LLVM turns into constant stack under optimization but NOT at
    // opt-level 0 — so in debug a large single call exhausts the test thread's stack (a debug-only
    // artifact). This guards that release execution is genuinely constant-stack, so handing
    // `transform_*` inputs up to `MAX_TRANSFORM_LEN` is safe in production builds.
    #[cfg(not(debug_assertions))]
    #[test]
    fn transforms_a_large_payload_in_one_call_release() {
        let module = xor_module();
        let mut t = module.instantiate().expect("instantiate");
        let payload: Vec<u8> = (0..262_144u32).map(|i| (i % 251) as u8).collect();
        let wire = t.transform_out(&payload).expect("transform_out");
        assert_eq!(wire.len(), payload.len());
        let recovered = t.transform_in(&wire).expect("transform_in");
        assert_eq!(recovered, payload, "round-trip must recover a large input");
    }

    #[test]
    fn many_sequential_transforms_on_one_instance() {
        // Repeated calls on one instance must each reclaim their stack (mimics the stream pump).
        let module = xor_module();
        let mut t = module.instantiate().expect("instantiate");
        for _ in 0..40 {
            let out = t.transform_in(&[0u8; 64]).expect("transform_in");
            assert_eq!(out.len(), 64);
        }
    }

    /// An AEAD round-trip module: `transform_out` seals and `transform_in` opens, with the key at
    /// offset 0 (32 zero bytes from zero-init memory), nonce at offset 32 (12 zeros), and a 4-byte
    /// AAD at offset 48 — both directions bind the same AAD, exercising the non-empty AAD path.
    const AEAD_WAT: &str = r#"
(module
  (import "env" "host_aead_seal" (func $seal (param i32 i32 i32 i32 i32 i32 i32) (result i64)))
  (import "env" "host_aead_open" (func $open (param i32 i32 i32 i32 i32 i32 i32) (result i64)))
  (memory (export "memory") 4)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "transform_out") (param $ptr i32) (param $len i32) (result i64)
    (local $n i64)
    (local.set $n (call $seal (i32.const 0) (i32.const 32) (i32.const 48) (i32.const 4) (local.get $ptr) (local.get $len) (i32.const 8192)))
    (i64.or (i64.shl (i64.const 8192) (i64.const 32)) (local.get $n)))
  (func (export "transform_in") (param $ptr i32) (param $len i32) (result i64)
    (local $n i64)
    (local.set $n (call $open (i32.const 0) (i32.const 32) (i32.const 48) (i32.const 4) (local.get $ptr) (local.get $len) (i32.const 8192)))
    (i64.or (i64.shl (i64.const 8192) (i64.const 32)) (local.get $n))))
"#;

    fn aead_module() -> TransformModule {
        TransformModule::load(&wat::parse_str(AEAD_WAT).expect("assemble")).expect("load")
    }

    // --- ADR 0006 P4: the handshake-crypto host-fn menu (HKDF + AES-GCM) ---

    /// AES-256-GCM round-trip: seal in `transform_out`, open in `transform_in`, both with an
    /// all-zero 32-byte key (offset 0) + 12-byte nonce (offset 64), no AAD. `out` at 8192.
    const AES_GCM_WAT: &str = r#"
(module
  (import "env" "host_aes_gcm_seal" (func $seal (param i32 i32 i32 i32 i32 i32 i32 i32) (result i64)))
  (import "env" "host_aes_gcm_open" (func $open (param i32 i32 i32 i32 i32 i32 i32 i32) (result i64)))
  (memory (export "memory") 4)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "transform_out") (param $ptr i32) (param $len i32) (result i64)
    (local $n i64)
    (local.set $n (call $seal (i32.const 0) (i32.const 32) (i32.const 64) (i32.const 0) (i32.const 0) (local.get $ptr) (local.get $len) (i32.const 8192)))
    (i64.or (i64.shl (i64.const 8192) (i64.const 32)) (local.get $n)))
  (func (export "transform_in") (param $ptr i32) (param $len i32) (result i64)
    (local $n i64)
    (local.set $n (call $open (i32.const 0) (i32.const 32) (i32.const 64) (i32.const 0) (i32.const 0) (local.get $ptr) (local.get $len) (i32.const 8192)))
    (i64.or (i64.shl (i64.const 8192) (i64.const 32)) (local.get $n))))
"#;

    #[test]
    fn host_aes_gcm_seals_and_opens() {
        let module =
            TransformModule::load(&wat::parse_str(AES_GCM_WAT).expect("assemble")).expect("load");
        let mut t = module.instantiate().expect("instantiate");
        let plaintext = b"attack at dawn";
        let wire = t.transform_out(plaintext).expect("seal");
        assert_eq!(
            wire.len(),
            plaintext.len() + 16,
            "the 16-byte tag is appended"
        );
        assert_ne!(
            &wire[..plaintext.len()],
            &plaintext[..],
            "ciphertext differs"
        );
        let recovered = t.transform_in(&wire).expect("open");
        assert_eq!(
            recovered.as_slice(),
            &plaintext[..],
            "open recovers the plaintext"
        );
    }

    #[test]
    fn host_aes_gcm_open_rejects_a_bad_key_length() {
        // key_len 24 is neither AES-128 (16) nor AES-256 (32) → recorded fault.
        const WAT: &str = r#"
(module
  (import "env" "host_aes_gcm_seal" (func $seal (param i32 i32 i32 i32 i32 i32 i32 i32) (result i64)))
  (memory (export "memory") 4)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "transform_out") (param $ptr i32) (param $len i32) (result i64)
    (drop (call $seal (i32.const 0) (i32.const 24) (i32.const 64) (i32.const 0) (i32.const 0) (local.get $ptr) (local.get $len) (i32.const 8192)))
    (i64.const 0))
  (func (export "transform_in") (param i32 i32) (result i64) (i64.const 0)))
"#;
        let module = TransformModule::load(&wat::parse_str(WAT).expect("assemble")).expect("load");
        let mut t = module.instantiate().expect("instantiate");
        assert!(matches!(
            t.transform_out(b"x"),
            Err(WasmError::HostFault(_))
        ));
    }

    /// HKDF (extract→expand) over the input as IKM: unsalted extract → 32-byte PRK at 2048, then
    /// expand 42 bytes (empty info) to 4096. Returns the 42-byte OKM.
    const HKDF_WAT: &str = r#"
(module
  (import "env" "host_hkdf_extract" (func $extract (param i32 i32 i32 i32 i32) (result i64)))
  (import "env" "host_hkdf_expand" (func $expand (param i32 i32 i32 i32 i32) (result i64)))
  (memory (export "memory") 4)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "transform_out") (param $ptr i32) (param $len i32) (result i64)
    (drop (call $extract (i32.const 0) (i32.const 0) (local.get $ptr) (local.get $len) (i32.const 2048)))
    (drop (call $expand (i32.const 2048) (i32.const 0) (i32.const 0) (i32.const 4096) (i32.const 42)))
    (i64.or (i64.shl (i64.const 4096) (i64.const 32)) (i64.const 42)))
  (func (export "transform_in") (param i32 i32) (result i64) (i64.const 0)))
"#;

    #[test]
    fn host_hkdf_matches_ring() {
        struct L(usize);
        impl ring::hkdf::KeyType for L {
            fn len(&self) -> usize {
                self.0
            }
        }
        let module =
            TransformModule::load(&wat::parse_str(HKDF_WAT).expect("assemble")).expect("load");
        let mut t = module.instantiate().expect("instantiate");
        let ikm = b"input keying material";
        let got = t.transform_out(ikm).expect("transform_out");

        // Native HKDF-SHA256: unsalted extract (HMAC empty key) → expand 42 bytes, empty info.
        let prk_tag = ring::hmac::sign(&ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &[]), ikm);
        let prk = ring::hkdf::Prk::new_less_safe(ring::hkdf::HKDF_SHA256, prk_tag.as_ref());
        let info: [&[u8]; 1] = [&[]];
        let okm = prk.expand(&info, L(42)).expect("expand");
        let mut want = vec![0u8; 42];
        okm.fill(&mut want).expect("fill");
        assert_eq!(got, want, "host HKDF must equal native HKDF-SHA256");
    }

    /// X25519 ECDH: the module generates a keypair (public key A) and agrees with a peer public key
    /// B fed in as the transform input; it returns `A || shared`. The test plays the *other* party
    /// natively (it holds B's private key) and checks `agree(priv_B, A) == shared`.
    const X25519_WAT: &str = r#"
(module
  (import "env" "host_x25519_generate" (func $gen (param i32) (result i64)))
  (import "env" "host_x25519_agree" (func $agree (param i32 i32 i32) (result i64)))
  (memory (export "memory") 2)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "transform_out") (param $ptr i32) (param $len i32) (result i64)
    (local $id i32)
    ;; pub_A at 16384; shared at 16416 — adjacent, returned as one 64-byte blob.
    (local.set $id (i32.wrap_i64 (call $gen (i32.const 16384))))
    (drop (call $agree (local.get $id) (local.get $ptr) (i32.const 16416)))
    (i64.or (i64.shl (i64.const 16384) (i64.const 32)) (i64.const 64)))
  (func (export "transform_in") (param i32 i32) (result i64) (i64.const 0)))
"#;

    #[test]
    fn host_x25519_agrees_with_a_native_peer() {
        use ring::agreement;
        use ring::rand::SystemRandom;

        let rng = SystemRandom::new();
        let priv_b =
            agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng).expect("keygen B");
        let pub_b = priv_b.compute_public_key().expect("pub B");

        let module =
            TransformModule::load(&wat::parse_str(X25519_WAT).expect("assemble")).expect("load");
        let mut t = module.instantiate().expect("instantiate");
        let blob = t.transform_out(pub_b.as_ref()).expect("transform_out");
        assert_eq!(blob.len(), 64, "pub_A || shared");
        let (pub_a, shared_module) = blob.split_at(32);

        // The other side of the ECDH, natively: agree(priv_B, pub_A) must equal the module's secret.
        let shared_native = agreement::agree_ephemeral(
            priv_b,
            &agreement::UnparsedPublicKey::new(&agreement::X25519, pub_a),
            |s| s.to_vec(),
        )
        .expect("native agree");
        assert_eq!(
            shared_module,
            &shared_native[..],
            "module ECDH shared secret must match the native peer's"
        );
        assert_ne!(
            shared_module, &[0u8; 32],
            "shared secret must be non-trivial"
        );
    }

    #[test]
    fn host_x25519_agree_rejects_an_unknown_key_id() {
        const WAT: &str = r#"
(module
  (import "env" "host_x25519_agree" (func $agree (param i32 i32 i32) (result i64)))
  (memory (export "memory") 2)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "transform_out") (param $ptr i32) (param $len i32) (result i64)
    (drop (call $agree (i32.const 7) (local.get $ptr) (i32.const 8192)))
    (i64.const 0))
  (func (export "transform_in") (param i32 i32) (result i64) (i64.const 0)))
"#;
        let module = TransformModule::load(&wat::parse_str(WAT).expect("assemble")).expect("load");
        let mut t = module.instantiate().expect("instantiate");
        // No key was ever generated, so id 7 is unknown → recorded fault.
        assert!(matches!(
            t.transform_out(&[0u8; 32]),
            Err(WasmError::HostFault(_))
        ));
    }

    #[test]
    fn host_chacha20_matches_native_keystream() {
        // The guest ChaCha20s its input at a fixed key/nonce and block counter 5; the test recomputes
        // the same keystream natively and checks equality — verifying the host fn's arg plumbing +
        // counter seek. Then it re-applies to confirm the stream round-trips (encrypt == decrypt).
        let key: [u8; 32] = std::array::from_fn(|i| i as u8 + 1);
        let nonce: [u8; 12] = std::array::from_fn(|i| i as u8);
        let counter = 5u32;
        let key_esc: String = key.iter().map(|b| format!("\\{b:02x}")).collect();
        let nonce_esc: String = nonce.iter().map(|b| format!("\\{b:02x}")).collect();
        let wat = format!(
            r#"
(module
  (import "env" "host_chacha20" (func $cc (param i32 i32 i32 i32 i32 i32) (result i64)))
  (memory (export "memory") 2)
  (data (i32.const 8192) "{key_esc}")
  (data (i32.const 8224) "{nonce_esc}")
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "transform_out") (param $ptr i32) (param $len i32) (result i64)
    (drop (call $cc (i32.const 8192) (i32.const 8224) (i32.const {counter}) (local.get $ptr) (local.get $len) (i32.const 16384)))
    (i64.or (i64.shl (i64.const 16384) (i64.const 32)) (i64.extend_i32_u (local.get $len))))
  (func (export "transform_in") (param i32 i32) (result i64) (i64.const 0)))
"#
        );
        let module = TransformModule::load(&wat::parse_str(&wat).expect("assemble")).expect("load");
        let mut t = module.instantiate().expect("instantiate");
        let plaintext: &[u8] = b"raw chacha20 keystream through the wasm host abi";
        let ct = t.transform_out(plaintext).expect("transform_out");

        let mut cipher = ChaCha20::new(&Key::from(key), &Nonce::from(nonce));
        cipher.seek(counter as u64 * 64);
        let mut expected = plaintext.to_vec();
        cipher.apply_keystream(&mut expected);
        assert_eq!(
            ct, expected,
            "host_chacha20 must match the native ChaCha20 keystream"
        );
        assert_ne!(
            ct.as_slice(),
            plaintext,
            "ciphertext must differ from plaintext"
        );

        let rt = t.transform_out(&ct).expect("re-apply");
        assert_eq!(
            rt.as_slice(),
            plaintext,
            "re-applying the same keystream recovers the plaintext"
        );
    }

    #[cfg(feature = "bip324")]
    #[test]
    fn host_secp256k1_ellswift_agrees_with_a_native_peer() {
        use secp256k1::ellswift::{ElligatorSwift, ElligatorSwiftSharedSecret, Party};
        use secp256k1::{Secp256k1, SecretKey};

        // Native peer B: a fixed, known-valid scalar + ellswift aux (fed to the guest as the input).
        // Deterministic — no keygen draw, so no vanishing-probability out-of-range panic in the test.
        let secp = Secp256k1::new();
        let sk_b = SecretKey::from_byte_array([7u8; 32]).expect("valid scalar");
        let ell_b = ElligatorSwift::from_seckey(&secp, sk_b, Some([9u8; 32]));

        // The guest generates its own ellswift key (A) and ECDHs against B's ellswift; it returns
        // `ell_A || shared_x`.
        const WAT: &str = r#"
(module
  (import "env" "host_secp256k1_ellswift_generate" (func $gen (param i32) (result i64)))
  (import "env" "host_secp256k1_ellswift_ecdh" (func $ecdh (param i32 i32 i32) (result i64)))
  (memory (export "memory") 2)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "transform_out") (param $ptr i32) (param $len i32) (result i64)
    (local $id i32)
    ;; ell_A at 16384 (64B); shared_x at 16448 (32B) — returned as one 96-byte blob.
    (local.set $id (i32.wrap_i64 (call $gen (i32.const 16384))))
    (drop (call $ecdh (local.get $id) (local.get $ptr) (i32.const 16448)))
    (i64.or (i64.shl (i64.const 16384) (i64.const 32)) (i64.const 96)))
  (func (export "transform_in") (param i32 i32) (result i64) (i64.const 0)))
"#;
        let module = TransformModule::load(&wat::parse_str(WAT).expect("assemble")).expect("load");
        let mut t = module.instantiate().expect("instantiate");
        let blob = t.transform_out(&ell_b.to_array()).expect("transform_out");
        assert_eq!(blob.len(), 96, "ell_A || shared_x");
        let (ell_a_bytes, shared_module) = blob.split_at(64);
        let ell_a = ElligatorSwift::from_array(ell_a_bytes.try_into().unwrap());

        // The other side of the same X-only ECDH, natively (identity hasher → raw shared x). By ECDH
        // symmetry, sk_B·pub_A == sk_A·pub_B, so both must land on the same x.
        let shared_native = ElligatorSwift::shared_secret_with_hasher(
            ell_b,
            ell_a,
            sk_b,
            Party::Initiator,
            |x, _, _| ElligatorSwiftSharedSecret::from_secret_bytes(x),
        );
        assert_eq!(
            shared_module,
            shared_native.as_secret_bytes(),
            "raw X-only ECDH shared x must match the native peer's"
        );
        assert_ne!(shared_module, &[0u8; 32], "shared x must be non-trivial");
    }

    /// End-to-end proof of the BIP324 WASM module (ADR 0013 §7 step 4, PR2): load the committed, signed
    /// `bip324.spkw` through the production verify path, instantiate an initiator + a responder from it,
    /// drive the handshake through the real runtime + host-fn provider, and round-trip application bytes
    /// both ways (incl. a fragmented, past-the-rekey burst). Gated on `bip324` so the module's
    /// secp256k1 host imports resolve.
    #[cfg(feature = "bip324")]
    #[test]
    fn bip324_module_handshakes_and_round_trips() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/wasm/bip324.spkw");
        let artifact = std::fs::read(&path).expect("read the committed bip324.spkw fixture");
        let module = ModuleVerifier::pinned()
            .verify(&artifact, 0)
            .expect("verify + compile the signed bip324 module")
            .into_module();

        // Config blob: [role][network_magic(4)][k_srv_len(2)=0][garbage…]. Mainnet magic, no side-door.
        const MAGIC: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];
        let cfg = |role: u8, garbage: &[u8]| {
            let mut c = vec![role];
            c.extend_from_slice(&MAGIC);
            c.extend_from_slice(&[0, 0]); // k_srv_len = 0
            c.extend_from_slice(garbage);
            c
        };
        let mut initiator = module
            .instantiate_with_config(&cfg(0, b"initiator garbage"))
            .expect("instantiate initiator");
        let mut responder = module
            .instantiate_with_config(&cfg(1, b"resp garbage"))
            .expect("instantiate responder");

        // Two independent wasm instances (each has its own memory + state). Drive the 1.5-RTT handshake
        // by shuttling handshake_step outputs, emit-at-connect first.
        let (mut to_r, mut init_done) = initiator.handshake_step(&[]).expect("init open");
        let (mut to_i, mut resp_done) = responder.handshake_step(&[]).expect("resp open");
        for _ in 0..8 {
            if !init_done && !to_i.is_empty() {
                let (out, done) = initiator
                    .handshake_step(&std::mem::take(&mut to_i))
                    .expect("init step");
                to_r.extend_from_slice(&out);
                init_done = done;
            }
            if !resp_done && !to_r.is_empty() {
                let (out, done) = responder
                    .handshake_step(&std::mem::take(&mut to_r))
                    .expect("resp step");
                to_i.extend_from_slice(&out);
                resp_done = done;
            }
            if init_done && resp_done {
                break;
            }
        }
        assert!(init_done && resp_done, "both sides complete the handshake");

        // App bytes round-trip both directions through the steady-state transforms.
        let wire = initiator
            .transform_out(b"hello via wasm bip324")
            .expect("out");
        assert_eq!(
            responder.transform_in(&wire).expect("in"),
            b"hello via wasm bip324"
        );
        let wire = responder.transform_out(b"pong").expect("out");
        assert_eq!(initiator.transform_in(&wire).expect("in"), b"pong");

        // A burst past the 224-message rekey, fed to transform_in in 5-byte fragments (buffering path).
        let mut stream = Vec::new();
        let mut expected = Vec::new();
        for i in 0..300u32 {
            let msg = format!("msg {i}");
            stream.extend_from_slice(&initiator.transform_out(msg.as_bytes()).expect("out"));
            expected.extend_from_slice(msg.as_bytes());
        }
        let mut recovered = Vec::new();
        for chunk in stream.chunks(5) {
            recovered.extend_from_slice(&responder.transform_in(chunk).expect("in"));
        }
        assert_eq!(
            recovered, expected,
            "all messages recovered across the rekey"
        );
    }

    /// The guest reads a non-empty `k_srv` from its init config and prepends the side-door tag to the
    /// initiator's opening garbage, without breaking the handshake. The tag's *value* is validated in
    /// `bip324-core`; here we prove the guest wiring end-to-end through the real runtime — the tag is
    /// present in the opening and a tagged tunnel still completes + round-trips against a plain responder.
    #[cfg(feature = "bip324")]
    #[test]
    fn bip324_module_side_door_tags_the_opening_and_still_round_trips() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/wasm/bip324.spkw");
        let artifact = std::fs::read(&path).expect("read the committed bip324.spkw fixture");
        let module = ModuleVerifier::pinned()
            .verify(&artifact, 0)
            .expect("verify + compile the signed bip324 module")
            .into_module();

        // Config: [role][network_magic(4)][k_srv_len: u16 BE][k_srv][garbage]. A non-empty k_srv on the
        // initiator enables the side-door; k_srv_len == 0 disables it.
        const MAGIC: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];
        const ELLSWIFT_LEN: usize = 64;
        const SIDE_DOOR_TAG_LEN: usize = 32; // bip324_core::SIDE_DOOR_TAG_LEN
        let cfg = |role: u8, k_srv: &[u8], garbage: &[u8]| {
            let k_srv_len = u16::try_from(k_srv.len()).expect("k_srv length fits in u16");
            let mut c = vec![role];
            c.extend_from_slice(&MAGIC);
            c.extend_from_slice(&k_srv_len.to_be_bytes());
            c.extend_from_slice(k_srv);
            c.extend_from_slice(garbage);
            c
        };
        let garbage = b"tail";
        let mut initiator = module
            .instantiate_with_config(&cfg(0, b"per-server side-door secret", garbage))
            .expect("instantiate initiator");
        let mut responder = module
            .instantiate_with_config(&cfg(1, b"", b"resp garbage"))
            .expect("instantiate responder (no side-door key)");

        // The initiator opens with ellswift ‖ the 32-byte side-door tag ‖ its configured garbage.
        let (mut to_r, mut init_done) = initiator.handshake_step(&[]).expect("init open");
        assert!(!init_done);
        assert_eq!(
            to_r.len(),
            ELLSWIFT_LEN + SIDE_DOOR_TAG_LEN + garbage.len(),
            "opening carries the side-door tag ahead of the configured garbage"
        );
        // Pin the layout PR4b-2 classifies on: ellswift(64) ‖ tag(32) ‖ garbage — the tag sits
        // immediately after the ellswift, and the configured garbage stays at the end (not the tag
        // appended after it, which the length check alone wouldn't catch).
        assert_eq!(
            &to_r[ELLSWIFT_LEN + SIDE_DOOR_TAG_LEN..],
            garbage,
            "the configured garbage remains at the end, so the tag is the 32 bytes right after ellswift"
        );

        // The tagged handshake still completes against a plain responder, and app bytes round-trip.
        let (mut to_i, mut resp_done) = responder.handshake_step(&[]).expect("resp open");
        for _ in 0..8 {
            if !init_done && !to_i.is_empty() {
                let (out, done) = initiator
                    .handshake_step(&std::mem::take(&mut to_i))
                    .expect("init step");
                to_r.extend_from_slice(&out);
                init_done = done;
            }
            if !resp_done && !to_r.is_empty() {
                let (out, done) = responder
                    .handshake_step(&std::mem::take(&mut to_r))
                    .expect("resp step");
                to_i.extend_from_slice(&out);
                resp_done = done;
            }
            if init_done && resp_done {
                break;
            }
        }
        assert!(
            init_done && resp_done,
            "both sides complete despite the tagged garbage"
        );

        let wire = initiator
            .transform_out(b"through a side-door tunnel")
            .expect("out");
        assert_eq!(
            responder.transform_in(&wire).expect("in"),
            b"through a side-door tunnel"
        );
    }

    #[cfg(feature = "bip324")]
    #[test]
    fn host_secp256k1_ellswift_ecdh_rejects_an_unknown_key_id() {
        const WAT: &str = r#"
(module
  (import "env" "host_secp256k1_ellswift_ecdh" (func $ecdh (param i32 i32 i32) (result i64)))
  (memory (export "memory") 2)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "transform_out") (param $ptr i32) (param $len i32) (result i64)
    (drop (call $ecdh (i32.const 3) (local.get $ptr) (i32.const 8192)))
    (i64.const 0))
  (func (export "transform_in") (param i32 i32) (result i64) (i64.const 0)))
"#;
        let module = TransformModule::load(&wat::parse_str(WAT).expect("assemble")).expect("load");
        let mut t = module.instantiate().expect("instantiate");
        // No key was ever generated, so id 3 is unknown → recorded fault.
        assert!(matches!(
            t.transform_out(&[0u8; 64]),
            Err(WasmError::HostFault(_))
        ));
    }

    /// A toy 2-step handshake module: emit-at-connect → `(continue, "PING")`; any inbound →
    /// `(done, "OK")`. The output is the `[status: u8][outbound]` frame the ABI defines.
    const HANDSHAKE_WAT: &str = r#"
(module
  (memory (export "memory") 2)
  (data (i32.const 8192) "\00PING")
  (data (i32.const 8200) "\01OK")
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "handshake_step") (param $ptr i32) (param $len i32) (result i64)
    (if (result i64) (i32.eqz (local.get $len))
      (then (i64.or (i64.shl (i64.const 8192) (i64.const 32)) (i64.const 5)))
      (else (i64.or (i64.shl (i64.const 8200) (i64.const 32)) (i64.const 3))))))
"#;

    #[test]
    fn handshake_step_frames_status_and_outbound() {
        let module =
            TransformModule::load(&wat::parse_str(HANDSHAKE_WAT).expect("assemble")).expect("load");
        let mut t = module.instantiate().expect("instantiate");
        // Emit-at-connect: empty inbound → the opening message, not done.
        let (out, done) = t.handshake_step(&[]).expect("step 1");
        assert_eq!(out, b"PING");
        assert!(!done);
        // Any inbound → the final message + done.
        let (out, done) = t.handshake_step(b"PONG").expect("step 2");
        assert_eq!(out, b"OK");
        assert!(done);
    }

    #[tokio::test]
    async fn run_handshake_drives_to_completion() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let module =
            TransformModule::load(&wat::parse_str(HANDSHAKE_WAT).expect("assemble")).expect("load");
        let mut t = module.instantiate().expect("instantiate");
        let (mut client, mut peer) = tokio::io::duplex(1024);

        // Native peer: read the opening PING, reply PONG, read the final OK.
        let peer_task = tokio::spawn(async move {
            // read_exact: `read` may return a partial buffer; these messages have known lengths.
            let mut ping = [0u8; 4];
            peer.read_exact(&mut ping).await.expect("read ping");
            assert_eq!(&ping, b"PING");
            peer.write_all(b"PONG").await.expect("write pong");
            peer.flush().await.expect("flush");
            let mut ok = [0u8; 2];
            peer.read_exact(&mut ok).await.expect("read ok");
            assert_eq!(&ok, b"OK");
        });

        t.run_handshake(&mut client).await.expect("handshake");
        peer_task.await.expect("peer task");
    }

    #[test]
    fn handshake_step_absent_on_a_transform_only_module() {
        // The XOR fixture exports transforms but not handshake_step.
        let mut t = xor_module().instantiate().expect("instantiate");
        assert!(matches!(
            t.handshake_step(&[]),
            Err(WasmError::MissingExport(EXPORT_HANDSHAKE_STEP))
        ));
    }

    #[test]
    fn handshake_step_rejects_an_empty_frame() {
        // A module whose handshake_step returns a zero-length region — no status byte → malformed.
        const WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "handshake_step") (param $ptr i32) (param $len i32) (result i64)
    (i64.const 0)))
"#;
        let module = TransformModule::load(&wat::parse_str(WAT).expect("assemble")).expect("load");
        let mut t = module.instantiate().expect("instantiate");
        assert!(matches!(
            t.handshake_step(&[]),
            Err(WasmError::HandshakeFrame(_))
        ));
    }

    #[test]
    fn host_hash_matches_ring() {
        const WAT: &str = r#"
(module
  (import "env" "host_hash" (func $hash (param i32 i32 i32)))
  (memory (export "memory") 2)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "transform_out") (param $ptr i32) (param $len i32) (result i64)
    (call $hash (local.get $ptr) (local.get $len) (i32.const 64))
    (i64.or (i64.shl (i64.const 64) (i64.const 32)) (i64.const 32)))
  (func (export "transform_in") (param i32 i32) (result i64) (i64.const 0)))
"#;
        let module = TransformModule::load(&wat::parse_str(WAT).expect("assemble")).expect("load");
        let mut t = module.instantiate().expect("instantiate");
        let input = b"the quick brown fox";
        let got = t.transform_out(input).expect("transform_out");
        let want = ring::digest::digest(&ring::digest::SHA256, input);
        assert_eq!(
            got.as_slice(),
            want.as_ref(),
            "host_hash must equal native SHA-256"
        );
    }

    #[test]
    fn host_aead_seals_and_opens() {
        let mut t = aead_module().instantiate().expect("instantiate");
        let plaintext = b"attack at dawn";
        let wire = t.transform_out(plaintext).expect("seal");
        assert_eq!(
            wire.len(),
            plaintext.len() + 16,
            "the 16-byte tag is appended"
        );
        assert_ne!(
            &wire[..plaintext.len()],
            &plaintext[..],
            "ciphertext must differ from plaintext"
        );
        let recovered = t.transform_in(&wire).expect("open");
        assert_eq!(
            recovered.as_slice(),
            &plaintext[..],
            "open must recover the plaintext"
        );
    }

    #[test]
    fn host_aead_open_rejects_tampered_ciphertext() {
        let mut t = aead_module().instantiate().expect("instantiate");
        let mut wire = t.transform_out(b"secret message").expect("seal");
        wire[0] ^= 0xff; // flip a ciphertext byte
        assert!(
            matches!(t.transform_in(&wire), Err(WasmError::HostFault(_))),
            "a tampered frame must fail authentication"
        );
    }

    #[test]
    fn reset_reclaims_the_arena_across_many_calls() {
        // A 1-page (64 KiB) module whose `alloc` bumps an arena and whose `reset` rewinds it. Without
        // `reset` the arena would overflow after ~1000 un-freed 64-byte allocations; because the host
        // calls `reset` after each transform, thousands of calls stay within one page.
        const RESET_WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (global $arena (mut i32) (i32.const 1024))
  (func (export "alloc") (param $len i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $arena))
    (global.set $arena (i32.add (global.get $arena) (local.get $len)))
    (local.get $p))
  (func (export "reset") (global.set $arena (i32.const 1024)))
  (func $xor (param $ptr i32) (param $len i32)
    (local $i i32)
    (block $done (loop $loop
      (br_if $done (i32.ge_u (local.get $i) (local.get $len)))
      (i32.store8 (i32.add (local.get $ptr) (local.get $i))
        (i32.xor (i32.load8_u (i32.add (local.get $ptr) (local.get $i))) (i32.const 0x5a)))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $loop))))
  (func (export "transform_out") (param $ptr i32) (param $len i32) (result i64)
    (call $xor (local.get $ptr) (local.get $len))
    (i64.or (i64.shl (i64.extend_i32_u (local.get $ptr)) (i64.const 32)) (i64.extend_i32_u (local.get $len))))
  (func (export "transform_in") (param $ptr i32) (param $len i32) (result i64)
    (call $xor (local.get $ptr) (local.get $len))
    (i64.or (i64.shl (i64.extend_i32_u (local.get $ptr)) (i64.const 32)) (i64.extend_i32_u (local.get $len)))))
"#;
        let module =
            TransformModule::load(&wat::parse_str(RESET_WAT).expect("assemble")).expect("load");
        let mut t = module.instantiate().expect("instantiate");
        let input = [0xABu8; 64];
        for _ in 0..5000 {
            assert_eq!(t.transform_out(&input).expect("transform_out").len(), 64);
        }
    }

    #[test]
    fn init_delivers_config_to_the_module() {
        // A module whose `init` stores the first config byte as an XOR key, then uses it.
        const WAT: &str = r#"
(module
  (memory (export "memory") 2)
  (global $key (mut i32) (i32.const 0))
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "init") (param $ptr i32) (param $len i32)
    (if (i32.gt_u (local.get $len) (i32.const 0))
      (then (global.set $key (i32.load8_u (local.get $ptr))))))
  (func $xor (param $ptr i32) (param $len i32)
    (local $i i32)
    (block $done (loop $loop
      (br_if $done (i32.ge_u (local.get $i) (local.get $len)))
      (i32.store8 (i32.add (local.get $ptr) (local.get $i))
        (i32.xor (i32.load8_u (i32.add (local.get $ptr) (local.get $i))) (global.get $key)))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $loop))))
  (func (export "transform_out") (param $ptr i32) (param $len i32) (result i64)
    (call $xor (local.get $ptr) (local.get $len))
    (i64.or (i64.shl (i64.extend_i32_u (local.get $ptr)) (i64.const 32)) (i64.extend_i32_u (local.get $len))))
  (func (export "transform_in") (param $ptr i32) (param $len i32) (result i64)
    (call $xor (local.get $ptr) (local.get $len))
    (i64.or (i64.shl (i64.extend_i32_u (local.get $ptr)) (i64.const 32)) (i64.extend_i32_u (local.get $len)))))
"#;
        let module = TransformModule::load(&wat::parse_str(WAT).expect("assemble")).expect("load");
        // Configured with key 0x42, transform_out XORs each byte with 0x42.
        let mut t = module
            .instantiate_with_config(&[0x42])
            .expect("instantiate");
        assert_eq!(
            t.transform_out(b"A").expect("transform_out"),
            vec![0x41 ^ 0x42]
        );
        // A different config yields a different transform — proving init actually delivered it.
        let mut t2 = module
            .instantiate_with_config(&[0x99])
            .expect("instantiate");
        assert_eq!(
            t2.transform_out(b"A").expect("transform_out"),
            vec![0x41 ^ 0x99]
        );
    }

    #[test]
    fn config_without_init_export_is_rejected() {
        // The XOR fixture has no `init` export, so supplying config can't be honored.
        assert!(
            matches!(
                xor_module().instantiate_with_config(&[1, 2, 3]),
                Err(WasmError::MissingExport(_))
            ),
            "config for a module without `init` must be rejected"
        );
    }

    // Release-only: in debug, wasmi's non-TCO interpreter overflows the test stack on a runaway
    // before fuel can trip (see the large-payload test); in release it runs constant-stack until the
    // fuel budget is exhausted and traps.
    #[cfg(not(debug_assertions))]
    #[test]
    fn fuel_metering_stops_a_runaway_module() {
        const SPIN_WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "transform_out") (param i32 i32) (result i64)
    (loop $spin (br $spin))
    (unreachable))
  (func (export "transform_in") (param i32 i32) (result i64) (i64.const 0)))
"#;
        let module =
            TransformModule::load(&wat::parse_str(SPIN_WAT).expect("assemble")).expect("load");
        let mut t = module.instantiate().expect("instantiate");
        let err = t
            .transform_out(b"hi")
            .expect_err("a runaway must be stopped by fuel");
        assert!(
            matches!(err, WasmError::Fuel(_)),
            "expected a fuel error, got: {err:?}"
        );
    }

    #[test]
    fn a_module_with_no_mode_export_is_rejected() {
        // `memory` + `alloc` present but no mode entrypoint (transform_out/in, compute_gambit,
        // handshake_step) → `NoMode` (not a misleading single-export error).
        let wasm = wat::parse_str(
            r#"(module (memory (export "memory") 1) (func (export "alloc") (param i32) (result i32) (i32.const 0)))"#,
        )
        .expect("assemble");
        let module = TransformModule::load(&wasm).expect("load");
        assert!(matches!(module.instantiate(), Err(WasmError::NoMode)));
    }

    #[test]
    fn invalid_bytes_fail_to_compile() {
        assert!(
            matches!(
                TransformModule::load(b"not wasm"),
                Err(WasmError::Compile(_))
            ),
            "non-wasm bytes must fail to compile"
        );
    }

    #[test]
    fn memory_grow_beyond_the_cap_is_denied() {
        // A module that tries to grow ~64 MiB (1000 pages) on transform_out. Fuel wouldn't stop it
        // (one instruction), but the 16 MiB store limit denies the grow and traps the call — so a
        // runaway can't exhaust host RAM. Confirms the limiter is wired, not just configured.
        const BOMB_WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "alloc") (param $len i32) (result i32) (i32.const 1024))
  (func (export "transform_out") (param $ptr i32) (param $len i32) (result i64)
    (drop (memory.grow (i32.const 1000)))
    (i64.or
      (i64.shl (i64.extend_i32_u (local.get $ptr)) (i64.const 32))
      (i64.extend_i32_u (local.get $len))))
  (func (export "transform_in") (param $ptr i32) (param $len i32) (result i64)
    (i64.or
      (i64.shl (i64.extend_i32_u (local.get $ptr)) (i64.const 32))
      (i64.extend_i32_u (local.get $len)))))
"#;
        let module = TransformModule::load(&wat::parse_str(BOMB_WAT).expect("wat")).expect("load");
        let mut t = module.instantiate().expect("instantiate");
        assert!(
            t.transform_out(b"x").is_err(),
            "an over-cap memory.grow must be denied (trap), not allowed to exhaust host memory"
        );
    }

    #[test]
    fn region_packing_round_trips() {
        // The (ptr, len) packing the ABI relies on, for arbitrary 32-bit values.
        for (ptr, len) in [
            (0u32, 0u32),
            (1024, 19),
            (65000, 1234),
            (u32::MAX, u32::MAX),
        ] {
            let packed = ((ptr as u64) << 32) | (len as u64);
            assert_eq!((packed >> 32) as u32, ptr);
            assert_eq!((packed & 0xFFFF_FFFF) as u32, len);
        }
    }

    // --- ADR 0006 P3: a module that *computes* a gambit (the open/shape mode) ---

    /// A module that, on `compute_gambit`, returns `g` wrapped in a neutral `Genome` (held in a data
    /// segment) — the minimal gambit-compute-mode module: `memory` + `alloc` + `compute_gambit`,
    /// **no** `transform_*` exports.
    fn gambit_module_emitting(g: &Gambit) -> TransformModule {
        // Emit the neutral Genome the TLS engine expects (engine = `tls`, engine_params = postcard `g`).
        let bytes = Genome::new(
            "wasm-computed",
            crate::transport::engine::TLS,
            Default::default(),
            postcard::to_stdvec(g).expect("encode gambit"),
        )
        .encode()
        .expect("encode genome");
        let escaped: String = bytes.iter().map(|b| format!("\\{b:02x}")).collect();
        let wat = format!(
            r#"
(module
  (memory (export "memory") 2)
  (data (i32.const 2048) "{escaped}")
  (func (export "alloc") (param $len i32) (result i32) (i32.const 1024))
  (func (export "compute_gambit") (param $p i32) (param $l i32) (result i64)
    (i64.or
      (i64.shl (i64.extend_i32_u (i32.const 2048)) (i64.const 32))
      (i64.extend_i32_u (i32.const {len})))))
"#,
            len = bytes.len()
        );
        TransformModule::load(&wat::parse_str(&wat).expect("assemble")).expect("load")
    }

    fn sample_gambit() -> Gambit {
        use flint_tls::gambit::{Capability, ClientHello, EchMode, Records, Wire};
        Gambit {
            genome_version: 1,
            version: 5,
            id: "wasm-computed".into(),
            anchor: Default::default(),
            clienthello: ClientHello {
                ech: Some(EchMode::Off),
                pq_kem: Some(false),
                ..Default::default()
            },
            records: Records::default(),
            wire: Wire {
                segment_split: "sni_boundary".into(),
                ..Default::default()
            },
            requires: vec![Capability::Ech],
        }
    }

    #[test]
    fn computes_a_gambit_genome() {
        let expected = sample_gambit();
        let module = gambit_module_emitting(&expected);
        let mut t = module.instantiate().expect("instantiate");
        // The per-connection context is reserved; an empty ctx is valid. `compute_gambit` returns the
        // module's raw bytes verbatim (opaque to the core) — here, the neutral Genome wrapping `expected`.
        let got = t.compute_gambit(&[]).expect("compute gambit");
        let genome = Genome::decode(&got).expect("decode genome");
        assert_eq!(genome.engine, crate::transport::engine::TLS);
        let inner: Gambit = postcard::from_bytes(&genome.engine_params).expect("decode gambit");
        assert_eq!(inner, expected);
    }

    #[test]
    fn compute_gambit_absent_on_a_transform_only_module() {
        // The XOR fixture exports transforms but not compute_gambit.
        let mut t = xor_module().instantiate().expect("instantiate");
        assert!(matches!(
            t.compute_gambit(&[]),
            Err(WasmError::MissingExport(EXPORT_COMPUTE_GAMBIT))
        ));
    }

    #[test]
    fn compute_gambit_returns_bytes_opaquely() {
        // A module whose compute_gambit returns a single 0xFF byte. The core no longer validates it
        // (decoding is the consuming engine's job); compute_gambit hands the bytes back verbatim.
        const WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (data (i32.const 2048) "\ff")
  (func (export "alloc") (param $len i32) (result i32) (i32.const 1024))
  (func (export "compute_gambit") (param $p i32) (param $l i32) (result i64)
    (i64.or (i64.shl (i64.extend_i32_u (i32.const 2048)) (i64.const 32)) (i64.const 1))))
"#;
        let module = TransformModule::load(&wat::parse_str(WAT).expect("assemble")).expect("load");
        let mut t = module.instantiate().expect("instantiate");
        assert_eq!(
            t.compute_gambit(&[]).expect("returns raw bytes"),
            vec![0xFF]
        );
    }

    /// End-to-end P3 (needs both features): a module computes a genome, and it resolves onto the
    /// boring executor — module → Genome → engine_params → `Profile::for_boring`.
    #[cfg(feature = "anytls")]
    #[test]
    fn computed_gambit_resolves_on_the_boring_executor() {
        use flint_tls::Profile;
        let module = gambit_module_emitting(&sample_gambit());
        let mut t = module.instantiate().expect("instantiate");
        // compute_gambit is opaque now; decode the Genome + its engine_params (as the TLS engine does).
        let bytes = t.compute_gambit(&[]).expect("compute gambit");
        let genome = Genome::decode(&bytes).expect("decode genome");
        let gambit: Gambit = postcard::from_bytes(&genome.engine_params).expect("decode gambit");
        let resolved = Profile::for_boring(&gambit).expect("within boring capabilities");
        // The gambit set ech=off and pq_kem=off; boring honors both.
        assert!(!resolved.profile.ech_grease);
        assert!(!resolved.profile.pq_kem);
    }
}
