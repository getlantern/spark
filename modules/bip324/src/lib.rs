//! `bip324` — the BIP324 dynamic-transport guest module (ADR 0013 §7 step 4, PR2).
//!
//! A wasm32 cdylib that wraps [`bip324_core`] in the Path-B module ABI. All crypto is delegated to the
//! `env` host functions via [`HostCrypto`] (an implementation of `bip324_core::Bip324Crypto`), so the
//! sandbox holds no crypto of its own — the point of the framework. The module runs the BIP324
//! handshake via `handshake_step`, then frames application bytes via `transform_out`/`transform_in`.
//!
//! ABI (host contract in `core/src/transport/wasm/mod.rs`): the host calls `alloc(len)` for an input
//! buffer, writes the bytes into the exported `memory` there, then calls `init` / `handshake_step` /
//! `transform_*` with `(ptr, len)`. `init` returns nothing; `handshake_step` and `transform_*` return
//! the packed `(ptr << 32) | len` region of their output. `handshake_step`'s output is framed
//! `[status: u8][outbound…]` (0 = continue, 1 = done).
#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::ptr::addr_of_mut;

use bip324_core::{Bip324Crypto, Handshake, Role, Session};

#[global_allocator]
static ALLOC: dlmalloc::GlobalDlmalloc = dlmalloc::GlobalDlmalloc;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

// The host crypto primitives (see the module-header doc in the host). Each takes/returns byte regions
// by guest-memory offset; the secp256k1 pair is present only when the host is built with `bip324`.
#[link(wasm_import_module = "env")]
extern "C" {
    fn host_rand(ptr: i32, len: i32);
    fn host_hash(in_ptr: i32, in_len: i32, out_ptr: i32);
    fn host_hkdf_extract(
        salt_ptr: i32,
        salt_len: i32,
        ikm_ptr: i32,
        ikm_len: i32,
        out_ptr: i32,
    ) -> i64;
    fn host_hkdf_expand(
        prk_ptr: i32,
        info_ptr: i32,
        info_len: i32,
        out_ptr: i32,
        out_len: i32,
    ) -> i64;
    fn host_aead_seal(
        key_ptr: i32,
        nonce_ptr: i32,
        aad_ptr: i32,
        aad_len: i32,
        in_ptr: i32,
        in_len: i32,
        out_ptr: i32,
    ) -> i64;
    fn host_aead_open(
        key_ptr: i32,
        nonce_ptr: i32,
        aad_ptr: i32,
        aad_len: i32,
        in_ptr: i32,
        in_len: i32,
        out_ptr: i32,
    ) -> i64;
    fn host_chacha20(
        key_ptr: i32,
        nonce_ptr: i32,
        counter: i32,
        in_ptr: i32,
        in_len: i32,
        out_ptr: i32,
    ) -> i64;
    fn host_secp256k1_ellswift_generate(out_ellswift_ptr: i32) -> i64;
    fn host_secp256k1_ellswift_ecdh(key_id: i32, peer_ellswift_ptr: i32, out_ptr: i32) -> i64;
}

/// A `Bip324Crypto` provider that forwards to the `env` host functions. Zero-sized: all state (keys) is
/// held host-side (the ephemeral is an opaque key id). A host fault returns `-1` and is only surfaced
/// after the whole *export* returns (the host records it, then discards the output) — so these
/// infallible shims trap immediately on a negative return rather than compute on garbage until then.
/// `aead_open`'s `-1` is instead a normal auth failure → `None`, which BIP324 turns into a teardown.
struct HostCrypto;

impl Bip324Crypto for HostCrypto {
    type Ephemeral = i32;

    fn ellswift_generate(&mut self) -> (i32, [u8; 64]) {
        let mut out = [0u8; 64];
        let id = unsafe { host_secp256k1_ellswift_generate(out.as_mut_ptr() as i32) };
        if id < 0 {
            abort();
        }
        (id as i32, out)
    }

    fn ellswift_ecdh(&mut self, key: i32, peer: &[u8; 64]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let n = unsafe {
            host_secp256k1_ellswift_ecdh(key, peer.as_ptr() as i32, out.as_mut_ptr() as i32)
        };
        if n < 0 {
            abort();
        }
        out
    }

    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        // Void host fn — a fault (if any) is surfaced by the host after the export returns.
        unsafe {
            host_hash(
                data.as_ptr() as i32,
                data.len() as i32,
                out.as_mut_ptr() as i32,
            )
        };
        out
    }

    fn hkdf_extract(&self, salt: &[u8], ikm: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let n = unsafe {
            host_hkdf_extract(
                salt.as_ptr() as i32,
                salt.len() as i32,
                ikm.as_ptr() as i32,
                ikm.len() as i32,
                out.as_mut_ptr() as i32,
            )
        };
        if n < 0 {
            abort();
        }
        out
    }

    fn hkdf_expand(&self, prk: &[u8; 32], info: &[u8], out: &mut [u8]) {
        let n = unsafe {
            host_hkdf_expand(
                prk.as_ptr() as i32,
                info.as_ptr() as i32,
                info.len() as i32,
                out.as_mut_ptr() as i32,
                out.len() as i32,
            )
        };
        if n < 0 {
            abort();
        }
    }

    fn chacha20_apply(&self, key: &[u8; 32], nonce: &[u8; 12], counter: u32, buf: &mut [u8]) {
        // In-place: `in` and `out` are the same region (ChaCha20 XOR is positional, so this is sound).
        let p = buf.as_mut_ptr() as i32;
        let n = buf.len() as i32;
        let ret = unsafe {
            host_chacha20(
                key.as_ptr() as i32,
                nonce.as_ptr() as i32,
                counter as i32,
                p,
                n,
                p,
            )
        };
        if ret < 0 {
            abort();
        }
    }

    fn aead_seal(&self, key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut out = alloc::vec![0u8; plaintext.len() + 16];
        let n = unsafe {
            host_aead_seal(
                key.as_ptr() as i32,
                nonce.as_ptr() as i32,
                aad.as_ptr() as i32,
                aad.len() as i32,
                plaintext.as_ptr() as i32,
                plaintext.len() as i32,
                out.as_mut_ptr() as i32,
            )
        };
        if n < 0 {
            abort();
        }
        out
    }

    fn aead_open(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Option<Vec<u8>> {
        if ciphertext.len() < 16 {
            return None;
        }
        let mut out = alloc::vec![0u8; ciphertext.len() - 16];
        let n = unsafe {
            host_aead_open(
                key.as_ptr() as i32,
                nonce.as_ptr() as i32,
                aad.as_ptr() as i32,
                aad.len() as i32,
                ciphertext.as_ptr() as i32,
                ciphertext.len() as i32,
                out.as_mut_ptr() as i32,
            )
        };
        if n < 0 {
            None
        } else {
            out.truncate(n as usize);
            Some(out)
        }
    }

    fn fill_random(&mut self, out: &mut [u8]) {
        unsafe { host_rand(out.as_mut_ptr() as i32, out.len() as i32) };
    }
}

/// The module's connection state: driving the handshake, then framing steady-state packets.
enum ModuleState {
    Handshaking(Handshake<HostCrypto>),
    Established(Session),
}

// Single-threaded wasm — accessed only through `addr_of_mut!` raw pointers (never a `&mut` to the
// static directly), so no data races and no `static_mut_refs`.
static mut STATE: Option<ModuleState> = None;

/// Input scratch: the host writes each call's input here (one live input at a time). 1 MiB matches the
/// host's `MAX_TRANSFORM_LEN`.
const ARENA: usize = 1 << 20;
static mut IN_ARENA: [u8; ARENA] = [0; ARENA];

/// Output holder: each export stores its output here and returns a pointer into it. Kept alive until
/// the next call (which frees the previous), so the host reads valid bytes right after the call.
static mut OUT: Vec<u8> = Vec::new();

/// Host allocation hook: hand back the input arena (reset each call), trapping on an oversized request.
#[no_mangle]
pub extern "C" fn alloc(len: i32) -> i32 {
    if len < 0 || len as usize > ARENA {
        core::arch::wasm32::unreachable()
    }
    addr_of_mut!(IN_ARENA) as *mut u8 as i32
}

fn packed(ptr: i32, len: i32) -> i64 {
    ((ptr as u32 as i64) << 32) | (len as u32 as i64)
}

/// The input the host wrote at `(ptr, len)` (borrows the 'static input arena; valid for this call).
///
/// The sole caller is the trusted host runtime, which passes `(ptr, len)` from [`alloc`] — so `ptr` is
/// the arena base and `len ≤ ARENA`. Validate the range against `IN_ARENA` anyway: a stray `(ptr, len)`
/// (negative `len`, or a range past the arena) would be immediate Rust UB in `from_raw_parts`, even if
/// the resulting wasm loads would trap. Trap loud (as `alloc` does) rather than fabricate a slice.
unsafe fn input<'a>(ptr: i32, len: i32) -> &'a [u8] {
    let base = addr_of_mut!(IN_ARENA) as usize;
    let p = ptr as usize;
    let within =
        len >= 0 && p >= base && p.checked_add(len as usize).is_some_and(|pe| pe <= base + ARENA);
    if !within {
        core::arch::wasm32::unreachable()
    }
    core::slice::from_raw_parts(p as *const u8, len as usize)
}

/// Store `bytes` as the current output and return its packed pointer/length.
unsafe fn emit(bytes: Vec<u8>) -> i64 {
    let out = &mut *addr_of_mut!(OUT);
    *out = bytes;
    packed(out.as_ptr() as i32, out.len() as i32)
}

/// Trap: a protocol/auth error or a call in the wrong state tears the connection down (the host maps a
/// wasm trap to a transport error).
fn abort() -> ! {
    core::arch::wasm32::unreachable()
}

/// `init(config)`: `[role: u8 (0=initiator, 1=responder)][network_magic: 4][k_srv_len: u16 BE]
/// [k_srv: k_srv_len bytes][garbage: rest]`. A non-empty `k_srv` enables the Lantern side-door on the
/// initiator (the tag is prepended to the opening garbage — see bip324-core `with_side_door`);
/// `k_srv_len == 0` disables it. Starts the handshake.
#[no_mangle]
pub extern "C" fn init(ptr: i32, len: i32) {
    let cfg = unsafe { input(ptr, len) };
    // role(1) + magic(4) + k_srv_len(2) = 7-byte minimum (k_srv_len may be 0, garbage may be empty).
    if cfg.len() < 7 {
        abort();
    }
    let role = match cfg[0] {
        0 => Role::Initiator,
        1 => Role::Responder,
        _ => abort(),
    };
    let mut magic = [0u8; 4];
    magic.copy_from_slice(&cfg[1..5]);
    let k_srv_len = u16::from_be_bytes([cfg[5], cfg[6]]) as usize;
    let ks_end = 7 + k_srv_len;
    if cfg.len() < ks_end {
        abort();
    }
    let k_srv = &cfg[7..ks_end];
    let garbage = &cfg[ks_end..];
    // with_side_door is a no-op for an empty key or the responder, so call it unconditionally.
    let hs = match Handshake::<HostCrypto>::new(role, magic, garbage) {
        Ok(h) => h.with_side_door(k_srv),
        Err(_) => abort(),
    };
    unsafe { *addr_of_mut!(STATE) = Some(ModuleState::Handshaking(hs)) };
}

/// One handshake step: feed inbound wire bytes, emit `[status][outbound]`. On completion the module
/// transitions to the steady-state session.
#[no_mangle]
pub extern "C" fn handshake_step(ptr: i32, len: i32) -> i64 {
    let inbound = unsafe { input(ptr, len) };
    let mut crypto = HostCrypto;
    let step = {
        let state = unsafe { (*addr_of_mut!(STATE)).as_mut() };
        let hs = match state {
            Some(ModuleState::Handshaking(hs)) => hs,
            _ => abort(),
        };
        match hs.step(&mut crypto, inbound) {
            Ok(s) => s,
            Err(_) => abort(),
        }
    };
    let mut frame = Vec::with_capacity(1 + step.outbound.len());
    frame.push(u8::from(step.session.is_some()));
    frame.extend_from_slice(&step.outbound);
    if let Some(session) = step.session {
        unsafe { *addr_of_mut!(STATE) = Some(ModuleState::Established(session)) };
    }
    unsafe { emit(frame) }
}

/// The established session, or trap if the handshake hasn't completed.
unsafe fn established<'a>() -> &'a mut Session {
    match (*addr_of_mut!(STATE)).as_mut() {
        Some(ModuleState::Established(s)) => s,
        _ => abort(),
    }
}

/// App → wire: seal the application bytes into one BIP324 packet.
#[no_mangle]
pub extern "C" fn transform_out(ptr: i32, len: i32) -> i64 {
    let app = unsafe { input(ptr, len) };
    let session = unsafe { established() };
    match session.encrypt(&HostCrypto, app) {
        Ok(wire) => unsafe { emit(wire) },
        Err(_) => abort(),
    }
}

/// Wire → app: decrypt complete packets (buffering partial ones), returning the concatenated genuine
/// contents (empty while a packet is still incomplete, or if only decoys arrived).
#[no_mangle]
pub extern "C" fn transform_in(ptr: i32, len: i32) -> i64 {
    let wire = unsafe { input(ptr, len) };
    let session = unsafe { established() };
    match session.decrypt(&HostCrypto, wire) {
        Ok(messages) => {
            // Concatenate the recovered contents into the app byte stream; allocate once.
            let total: usize = messages.iter().map(|m| m.len()).sum();
            let mut app = Vec::with_capacity(total);
            for m in messages {
                app.extend_from_slice(&m);
            }
            unsafe { emit(app) }
        }
        Err(_) => abort(),
    }
}
