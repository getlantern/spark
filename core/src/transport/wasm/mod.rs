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
//! The module **exports**:
//! - `memory` — its linear memory.
//! - `alloc(len: i32) -> i32` — return a pointer to `len` writable bytes (the host writes input here).
//! - `transform_out(ptr: i32, len: i32) -> i64` — transform `len` bytes at `ptr` on the
//!   application → wire direction. Returns the output region packed as `(out_ptr << 32) | out_len`.
//! - `transform_in(ptr: i32, len: i32) -> i64` — the inverse (wire → application), same packing.
//! - `init(config_ptr: i32, config_len: i32)` — *optional*; called once after instantiation to
//!   deliver per-deployment configuration (e.g. a key or seed). See [`TransformModule::instantiate_with_config`].
//!
//! The module **imports** (host functions, under module `env`) — this is its entire capability
//! surface:
//! - `host_rand(ptr, len)` — fill `len` bytes with cryptographically secure random bytes.
//! - `host_hash(in_ptr, in_len, out_ptr)` — SHA-256, writing 32 bytes.
//! - `host_aead_seal(key_ptr, nonce_ptr, in_ptr, in_len, out_ptr) -> i64` — ChaCha20-Poly1305 seal
//!   (returns `in_len + 16`).
//! - `host_aead_open(key_ptr, nonce_ptr, in_ptr, in_len, out_ptr) -> i64` — the inverse; returns the
//!   plaintext length, or `-1` on authentication failure.
//!
//! Bulk per-byte crypto runs **natively** through these host functions, not in the interpreter — the
//! module interprets only its control/framing logic. (Measured: bulk work in the interpreter caps a
//! flow at <1 Gb/s, whereas sealing via the native AEAD host fn runs >10 Gb/s.)
//!
//! Each `transform_*` call is self-contained: the host calls `alloc`, writes the input, calls the
//! transform, then reads the packed output. **Limitation:** the host does not free guest buffers, so
//! a module must avoid unbounded memory growth across calls (e.g. reset an internal arena at the
//! start of each transform). A future ABI revision negotiates explicit `dealloc`/arena reset.

use std::sync::Arc;

use ring::rand::{SecureRandom, SystemRandom};
use ring::{aead, digest};
use wasmi::{Caller, Config, Engine, Extern, Linker, Memory, Module, Store, TypedFunc};

mod signing;
mod stream;
mod transport;
pub use signing::{build_artifact, signing_payload, ModuleError, ModuleVerifier, SignedModule};
pub use stream::TransformStream;
pub use transport::{WasmServer, WasmTransport};

/// Import module name the host functions are defined under.
const HOST_MODULE: &str = "env";
/// Import: cryptographically secure random fill (`host_rand(ptr, len)`).
const HOST_RAND: &str = "host_rand";
/// Import: SHA-256 (`host_hash(in_ptr, in_len, out_ptr)` → 32 bytes).
const HOST_HASH: &str = "host_hash";
/// Import: ChaCha20-Poly1305 seal (`host_aead_seal(key_ptr, nonce_ptr, in_ptr, in_len, out_ptr)`).
const HOST_AEAD_SEAL: &str = "host_aead_seal";
/// Import: ChaCha20-Poly1305 open (`host_aead_open(key_ptr, nonce_ptr, in_ptr, in_len, out_ptr)`).
const HOST_AEAD_OPEN: &str = "host_aead_open";

/// Export: the module's linear memory.
const EXPORT_MEMORY: &str = "memory";
/// Export (optional): `init(config_ptr, config_len)` — called once after instantiation to deliver
/// per-deployment configuration (e.g. a key or seed).
const EXPORT_INIT: &str = "init";
/// Export: `alloc(len) -> ptr`.
const EXPORT_ALLOC: &str = "alloc";
/// Export: `transform_out(ptr, len) -> packed`.
const EXPORT_TRANSFORM_OUT: &str = "transform_out";
/// Export: `transform_in(ptr, len) -> packed`.
const EXPORT_TRANSFORM_IN: &str = "transform_in";

/// Upper bound on a single transform's input or output length. Caps how much guest memory one call
/// can drive the host to touch or allocate — the module is untrusted, so every length crossing the
/// boundary is checked against this before any allocation.
const MAX_TRANSFORM_LEN: usize = 1 << 20; // 1 MiB

/// ChaCha20-Poly1305 key length (the AEAD the crypto host fns expose).
const AEAD_KEY_LEN: usize = 32;
/// ChaCha20-Poly1305 nonce length.
const AEAD_NONCE_LEN: usize = 12;
/// Poly1305 authentication tag length (appended to the ciphertext on seal).
const AEAD_TAG_LEN: usize = 16;
/// SHA-256 digest length.
const HASH_LEN: usize = 32;

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
}

impl TransformModule {
    /// Compile a transform module from its WebAssembly bytes.
    ///
    /// This only validates and compiles; it does not run the module. Per-connection state is
    /// created by [`TransformModule::instantiate`].
    pub fn load(wasm: &[u8]) -> Result<Self, WasmError> {
        // Enable fuel metering so a runaway module is bounded per call (see `fuel_for`).
        let mut config = Config::default();
        config.consume_fuel(true);
        let engine = Engine::new(&config);
        let module = Module::new(&engine, wasm).map_err(WasmError::Compile)?;
        Ok(Self {
            engine,
            module: Arc::new(module),
        })
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
}

/// One instantiated transform session: owns the guest instance + linear memory and drives the byte
/// transforms. `Send` (so it can move into a per-connection task) but not `Sync` — the `wasmi`
/// `Store` is single-threaded, which matches one session per connection.
pub struct Transform {
    store: Store<HostState>,
    memory: Memory,
    alloc: TypedFunc<i32, i32>,
    transform_out: TypedFunc<(i32, i32), i64>,
    transform_in: TypedFunc<(i32, i32), i64>,
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
            },
        );
        // Fuel metering is on, so the store starts empty; grant a budget that covers the module's
        // `start` function (if any) and the `init` hook below. Per-transform calls refill in `run`.
        set_fuel(&mut store, fuel_for(config.len()))?;

        // Register the host functions (the module's entire capability surface): a CSPRNG, SHA-256,
        // and ChaCha20-Poly1305 seal/open. Bulk crypto runs natively here so modules don't pay the
        // interpreter's per-byte cost (ADR 0003); the module interprets only its control/framing.
        let mut linker = Linker::<HostState>::new(&module.engine);
        linker
            .func_wrap(HOST_MODULE, HOST_RAND, host_rand)
            .map_err(|e| WasmError::Link(e.to_string()))?;
        linker
            .func_wrap(HOST_MODULE, HOST_HASH, host_hash)
            .map_err(|e| WasmError::Link(e.to_string()))?;
        linker
            .func_wrap(HOST_MODULE, HOST_AEAD_SEAL, host_aead_seal)
            .map_err(|e| WasmError::Link(e.to_string()))?;
        linker
            .func_wrap(HOST_MODULE, HOST_AEAD_OPEN, host_aead_open)
            .map_err(|e| WasmError::Link(e.to_string()))?;

        let instance = linker
            .instantiate_and_start(&mut store, &module.module)
            .map_err(WasmError::Instantiate)?;

        let memory = instance
            .get_memory(&store, EXPORT_MEMORY)
            .ok_or(WasmError::MissingExport(EXPORT_MEMORY))?;
        let alloc = instance
            .get_typed_func::<i32, i32>(&store, EXPORT_ALLOC)
            .map_err(|_| WasmError::MissingExport(EXPORT_ALLOC))?;
        let transform_out = instance
            .get_typed_func::<(i32, i32), i64>(&store, EXPORT_TRANSFORM_OUT)
            .map_err(|_| WasmError::MissingExport(EXPORT_TRANSFORM_OUT))?;
        let transform_in = instance
            .get_typed_func::<(i32, i32), i64>(&store, EXPORT_TRANSFORM_IN)
            .map_err(|_| WasmError::MissingExport(EXPORT_TRANSFORM_IN))?;

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

    /// Total bytes this session has drawn from the `host_rand` capability — observability for how
    /// much entropy the module consumes.
    pub fn entropy_drawn(&self) -> u64 {
        self.store.data().rand_bytes
    }

    fn run(&mut self, dir: Direction, input: &[u8]) -> Result<Vec<u8>, WasmError> {
        if input.len() > MAX_TRANSFORM_LEN {
            return Err(WasmError::InputTooLarge {
                len: input.len(),
                max: MAX_TRANSFORM_LEN,
            });
        }
        let len = input.len() as i32;
        // `TypedFunc`/`Memory` are `Copy`, so copy the handles out and borrow only `self.store`.
        let (func, name) = match dir {
            Direction::Out => (self.transform_out, EXPORT_TRANSFORM_OUT),
            Direction::In => (self.transform_in, EXPORT_TRANSFORM_IN),
        };
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

/// The `host_aead_seal(key_ptr, nonce_ptr, in_ptr, in_len, out_ptr) -> i64` import: ChaCha20-Poly1305
/// seal of `in_len` plaintext bytes under the 32-byte key at `key_ptr` and 12-byte nonce at
/// `nonce_ptr`, writing `in_len + 16` (ciphertext+tag) bytes to `out_ptr`. Returns the output length,
/// or `-1` with a recorded fault. (AAD is empty in v0.)
fn host_aead_seal(
    mut caller: Caller<HostState>,
    key_ptr: i32,
    nonce_ptr: i32,
    in_ptr: i32,
    in_len: i32,
    out_ptr: i32,
) -> i64 {
    if caller.data().fault.is_some() {
        return -1;
    }
    let sealed = match aead_seal(&caller, key_ptr, nonce_ptr, in_ptr, in_len) {
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

/// The `host_aead_open(key_ptr, nonce_ptr, in_ptr, in_len, out_ptr) -> i64` import: the inverse of
/// [`host_aead_seal`]. Reads `in_len` ciphertext+tag bytes, writes `in_len - 16` plaintext bytes to
/// `out_ptr`, and returns the plaintext length. On authentication failure (or any error) it returns
/// `-1` and records a fault — a tampered or forged frame fails closed.
fn host_aead_open(
    mut caller: Caller<HostState>,
    key_ptr: i32,
    nonce_ptr: i32,
    in_ptr: i32,
    in_len: i32,
    out_ptr: i32,
) -> i64 {
    if caller.data().fault.is_some() {
        return -1;
    }
    let plaintext = match aead_open(&caller, key_ptr, nonce_ptr, in_ptr, in_len) {
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

/// ChaCha20-Poly1305 seal, reading key/nonce/plaintext from guest memory. Returns ciphertext+tag.
fn aead_seal(
    caller: &Caller<HostState>,
    key_ptr: i32,
    nonce_ptr: i32,
    in_ptr: i32,
    in_len: i32,
) -> Result<Vec<u8>, String> {
    let key = read_guest_array::<AEAD_KEY_LEN>(caller, key_ptr)?;
    let nonce = read_guest_array::<AEAD_NONCE_LEN>(caller, nonce_ptr)?;
    let mut buf = read_guest(caller, in_ptr, in_len)?;
    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key).map_err(|_| "bad key")?,
    );
    key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(nonce),
        aead::Aad::empty(),
        &mut buf,
    )
    .map_err(|_| "seal failed")?;
    Ok(buf)
}

/// ChaCha20-Poly1305 open, reading key/nonce/ciphertext+tag from guest memory. Returns plaintext.
fn aead_open(
    caller: &Caller<HostState>,
    key_ptr: i32,
    nonce_ptr: i32,
    in_ptr: i32,
    in_len: i32,
) -> Result<Vec<u8>, String> {
    let key = read_guest_array::<AEAD_KEY_LEN>(caller, key_ptr)?;
    let nonce = read_guest_array::<AEAD_NONCE_LEN>(caller, nonce_ptr)?;
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
            aead::Aad::empty(),
            &mut buf,
        )
        .map_err(|_| "authentication failed")?;
    Ok(plaintext.to_vec())
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

    /// PKCS#8 of the **development** module-signing keypair — the private half of
    /// `signing::DEV_MODULE_PUBKEY`. Test-only (this never compiles into a shipped binary), so tests
    /// can produce artifacts that `ModuleVerifier::pinned()` accepts when no production key is pinned.
    pub const DEV_MODULE_PKCS8: &[u8] = &[
        48, 81, 2, 1, 1, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32, 47, 96, 208, 79, 38, 102, 119,
        122, 12, 75, 231, 119, 191, 58, 165, 37, 216, 16, 180, 152, 96, 30, 105, 41, 180, 223, 163,
        204, 55, 11, 100, 103, 129, 33, 0, 114, 43, 155, 15, 166, 26, 80, 178, 3, 21, 71, 211, 20,
        223, 38, 197, 127, 114, 13, 201, 119, 147, 135, 224, 208, 160, 39, 52, 129, 224, 249, 213,
    ];

    /// The development signing keypair (see [`DEV_MODULE_PKCS8`]).
    pub fn dev_keypair() -> ring::signature::Ed25519KeyPair {
        ring::signature::Ed25519KeyPair::from_pkcs8(DEV_MODULE_PKCS8).expect("dev pkcs8")
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::xor_module;
    use super::*;

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
  (import "env" "host_aead_seal" (func $seal (param i32 i32 i32 i32 i32) (result i64)))
  (memory (export "memory") 64)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "transform_out") (param $ptr i32) (param $len i32) (result i64)
    (local $n i64)
    (local.set $n (call $seal (i32.const 0) (i32.const 32) (local.get $ptr) (local.get $len) (i32.const 524288)))
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

    /// An AEAD round-trip module: `transform_out` seals and `transform_in` opens, both with the key
    /// at offset 0 (32 zero bytes from zero-init memory) and nonce at offset 32 (12 zero bytes).
    const AEAD_WAT: &str = r#"
(module
  (import "env" "host_aead_seal" (func $seal (param i32 i32 i32 i32 i32) (result i64)))
  (import "env" "host_aead_open" (func $open (param i32 i32 i32 i32 i32) (result i64)))
  (memory (export "memory") 4)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "transform_out") (param $ptr i32) (param $len i32) (result i64)
    (local $n i64)
    (local.set $n (call $seal (i32.const 0) (i32.const 32) (local.get $ptr) (local.get $len) (i32.const 8192)))
    (i64.or (i64.shl (i64.const 8192) (i64.const 32)) (local.get $n)))
  (func (export "transform_in") (param $ptr i32) (param $len i32) (result i64)
    (local $n i64)
    (local.set $n (call $open (i32.const 0) (i32.const 32) (local.get $ptr) (local.get $len) (i32.const 8192)))
    (i64.or (i64.shl (i64.const 8192) (i64.const 32)) (local.get $n))))
"#;

    fn aead_module() -> TransformModule {
        TransformModule::load(&wat::parse_str(AEAD_WAT).expect("assemble")).expect("load")
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
    fn missing_export_is_rejected() {
        // A module with no `transform_out` export must fail to instantiate as a transform.
        let wasm = wat::parse_str(r#"(module (memory (export "memory") 1))"#).expect("assemble");
        let module = TransformModule::load(&wasm).expect("load");
        assert!(
            matches!(module.instantiate(), Err(WasmError::MissingExport(_))),
            "a module without transform exports must be rejected"
        );
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
}
