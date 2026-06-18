//! Path B dynamic transport — a `wasmi`-hosted byte-transform module (ADR 0003, design §8.4).
//!
//! A dynamic transport is delivered as a WebAssembly module the client loads at runtime, so a new
//! obfuscation can ship in hours instead of a client release. Path B keeps the module's job and its
//! capabilities minimal: it is a **pure byte transform**. The host owns the network sockets; the
//! module only sees bytes and may draw entropy from a host function. It cannot open a connection,
//! touch the filesystem, or otherwise reach the outside world — there is no WASI, no network import.
//! That is the sandbox property Path B buys over a WATER-style host (design doc §8.2/§8.4).
//!
//! # ABI (v0)
//!
//! The module **exports**:
//! - `memory` — its linear memory.
//! - `alloc(len: i32) -> i32` — return a pointer to `len` writable bytes (the host writes input here).
//! - `transform_out(ptr: i32, len: i32) -> i64` — transform `len` bytes at `ptr` on the
//!   application → wire direction. Returns the output region packed as `(out_ptr << 32) | out_len`.
//! - `transform_in(ptr: i32, len: i32) -> i64` — the inverse (wire → application), same packing.
//!
//! The module **imports** (host functions, under module `env`):
//! - `host_rand(ptr: i32, len: i32)` — fill `len` bytes at `ptr` with cryptographically secure
//!   random bytes. This is the module's entire capability surface.
//!
//! Each `transform_*` call is self-contained: the host calls `alloc`, writes the input, calls the
//! transform, then reads the packed output. **v0 limitation:** the host does not free guest buffers,
//! so a module must avoid unbounded memory growth across calls (e.g. reset an internal arena at the
//! start of each transform). A future ABI revision negotiates explicit `dealloc`/arena reset.

use std::sync::Arc;

use ring::rand::{SecureRandom, SystemRandom};
use wasmi::{Caller, Engine, Extern, Linker, Memory, Module, Store, TypedFunc};

mod stream;
pub use stream::TransformStream;

/// Import module name the host functions are defined under.
const HOST_MODULE: &str = "env";
/// Import: cryptographically secure random fill (`host_rand(ptr, len)`).
const HOST_RAND: &str = "host_rand";

/// Export: the module's linear memory.
const EXPORT_MEMORY: &str = "memory";
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
        let engine = Engine::default();
        let module = Module::new(&engine, wasm).map_err(WasmError::Compile)?;
        Ok(Self {
            engine,
            module: Arc::new(module),
        })
    }

    /// Instantiate a fresh transform session with its own linear memory and host state.
    pub fn instantiate(&self) -> Result<Transform, WasmError> {
        Transform::new(self)
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
    fn new(module: &TransformModule) -> Result<Self, WasmError> {
        let mut store = Store::new(
            &module.engine,
            HostState {
                rng: SystemRandom::new(),
                fault: None,
                rand_bytes: 0,
            },
        );

        let mut linker = Linker::<HostState>::new(&module.engine);
        linker
            .func_wrap(HOST_MODULE, HOST_RAND, host_rand)
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

        let ptr = alloc
            .call(&mut self.store, len)
            .map_err(|source| WasmError::Call {
                func: EXPORT_ALLOC,
                source,
            })?;
        memory
            .write(&mut self.store, ptr as usize, input)
            .map_err(|e| WasmError::Memory(e.to_string()))?;

        let packed = func
            .call(&mut self.store, (ptr, len))
            .map_err(|source| WasmError::Call { func: name, source })? as u64;
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
}

#[cfg(test)]
mod tests {
    use super::testutil::xor_module;
    use super::*;

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
