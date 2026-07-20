//! `obfs-xor` — the reference dynamic-transport guest module (ADR 0013 §7).
//!
//! The smallest *real* Rust→wasm32 transform module: `scripts/build-module.sh` compiles it, signs it
//! with the module-signing key, and writes `core/tests/fixtures/wasm/obfs-xor.spkw`, which the core's
//! wasm-transport round-trip test loads through the exact production path. It mirrors the inline
//! `XOR_WAT` fixture (`core/src/transport/wasm/mod.rs`) so the compiled artifact is a drop-in
//! equivalent: XOR every byte with `0x5A` (involutive, so `transform_in` undoes `transform_out`) and
//! call the `host_rand` `env` import once — proving a *compiled* module binds a host capability, not
//! only the hand-written `wat!` fixtures do.
//!
//! ABI (see the core `wasm` module header): the host calls `alloc(len)` for an input buffer, writes
//! the bytes into the exported `memory` there, then calls a transform with `(ptr, len)`; each returns
//! the packed `(ptr << 32) | len` region to read the output from.
#![no_std]

use core::panic::PanicInfo;
use core::ptr::addr_of_mut;

/// The transform key. Involutive XOR, so `transform_in` reverses `transform_out`.
const XOR_KEY: u8 = 0x5A;

/// Scratch arena inside the exported linear memory. `alloc` hands out one buffer at offset 0 per call.
/// Sized to the host's 1 MiB `MAX_TRANSFORM_LEN` — the largest input the host will pass — so no valid
/// transform is rejected; `alloc` traps on anything larger.
const ARENA: usize = 1 << 20;
static mut MEM: [u8; ARENA] = [0; ARENA];

/// A dedicated sink for the `host_rand` binding-proof write, so it never scribbles offset 0 (which a
/// cdylib may place the shadow stack / static data at).
static mut SCRATCH: [u8; 4] = [0; 4];

#[link(wasm_import_module = "env")]
extern "C" {
    /// Host RNG: fill `len` bytes at `ptr` (a core `env` import the host always provides).
    fn host_rand(ptr: i32, len: i32);
}

/// The host's per-transform allocation hook. `call_io` invokes it exactly once before each transform,
/// so every call reuses the one buffer at offset 0. Traps deterministically on a negative or oversized
/// request rather than letting unchecked pointer math corrupt adjacent linear memory.
#[no_mangle]
pub extern "C" fn alloc(len: i32) -> i32 {
    if len < 0 || len as usize > ARENA {
        core::arch::wasm32::unreachable()
    }
    addr_of_mut!(MEM) as *mut u8 as i32
}

/// Pack a `(ptr, len)` pair into the ABI's `i64` return.
fn packed(ptr: i32, len: i32) -> i64 {
    ((ptr as u32 as i64) << 32) | (len as u32 as i64)
}

/// XOR `len` bytes at `ptr` with [`XOR_KEY`], in place.
unsafe fn xor(ptr: i32, len: i32) {
    let p = ptr as usize as *mut u8;
    for i in 0..len as usize {
        *p.add(i) ^= XOR_KEY;
    }
}

/// App → wire. Calls `host_rand` once (binding proof; the bytes are discarded), then XORs in place.
#[no_mangle]
pub extern "C" fn transform_out(ptr: i32, len: i32) -> i64 {
    unsafe {
        host_rand(addr_of_mut!(SCRATCH) as i32, 4);
        xor(ptr, len);
    }
    packed(ptr, len)
}

/// Wire → app. XOR is involutive, so this reverses `transform_out`.
#[no_mangle]
pub extern "C" fn transform_in(ptr: i32, len: i32) -> i64 {
    unsafe { xor(ptr, len) }
    packed(ptr, len)
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}
