//! `spark-apple` — the C-ABI static library (`libspark_apple.a`) linked into the Apple
//! NetworkExtension Packet Tunnel Provider on iOS and macOS.
//!
//! The Swift provider resolves the `utun` file descriptor (KVC `socket.fileDescriptor` → a
//! public-symbol fd-scan fallback — the WireGuard/sing-box/Mullvad/Proton/lantern technique) and
//! calls `spark_tunnel_run(fd, mtu)`; `spark_tunnel_stop()` on teardown. Packets never cross the
//! FFI — Rust owns the fd and runs the whole netstack ([`spark_core::fd_tunnel`]), so the C ABI
//! is control-only (mirroring the Android JNI). One core surface, two thin platform adapters.
//!
//! (A `readPacketObjects`/`writePackets` packet-object path is a documented follow-up fallback,
//! for the day Apple's socket-less migration removes the fd. See `platforms/apple/README.md`.)
//!
//! On non-Apple targets the symbols are `cfg`-d out, so the crate builds as an empty staticlib.

#[cfg(any(target_os = "ios", target_os = "macos"))]
mod ffi {
    use std::ffi::{CStr, CString};
    use std::net::SocketAddr;
    use std::os::raw::{c_char, c_int};
    use std::ptr;

    use spark_core::config::Config;

    /// Run the tunnel on the provided `utun` `fd` with `mtu`. Blocks the calling thread until
    /// [`spark_tunnel_stop`] (or the data path exits). Returns 0 on a clean stop, -1 on error.
    ///
    /// The caller (the Swift NE provider) hands ownership of `fd` to native for the tunnel's
    /// lifetime; the core closes it on stop.
    ///
    /// `config` selects the data path (dual-mode for back-compat):
    /// - null/empty → forward each flow **directly** (no tunnel).
    /// - a bare `host:port` IP literal → tunnel every flow through that **plain spark relay**.
    /// - any other string → a full **TOML [`Config`]** (AnyTLS + handshake shaping + gambit, …),
    ///   parsed via [`Config::from_toml_str`]; the whole transport stack applies (ADR 0006). AnyTLS
    ///   requires the staticlib to be built with the `anytls` feature (the macOS slice is), else the
    ///   core returns -1.
    ///
    /// A non-null, non-empty `config` that is neither a `SocketAddr` nor valid TOML returns -1.
    ///
    /// # Safety
    /// `config` must be null or a valid NUL-terminated C string for the duration of this call.
    #[no_mangle]
    pub unsafe extern "C" fn spark_tunnel_run(
        fd: c_int,
        mtu: c_int,
        config: *const c_char,
    ) -> c_int {
        // SAFETY: caller contract — `config` is null or a valid NUL-terminated C string.
        let config = match unsafe { build_config(config) } {
            Some(c) => c,
            None => return -1,
        };
        // `run_fd` is the shared run + status-code convention; the core builds the transport from the
        // config (direct / plain relay / AnyTLS) and owns the netstack.
        spark_core::fd_tunnel::run_fd(fd, mtu as u16, config)
    }

    /// Resolve the C `config` arg into a [`Config`]: null/empty → direct; a bare `host:port` → the
    /// plain relay (today's behavior); otherwise a full config — spark's native TOML or a Lantern
    /// `config_raw.json` payload (auto-detected). `None` signals a parse error (`-1` to the caller).
    /// The NE always uses the userspace stack (`system` is Android-only).
    ///
    /// # Safety
    /// `ptr` must be null or a valid NUL-terminated C string.
    unsafe fn build_config(ptr: *const c_char) -> Option<Config> {
        if ptr.is_null() {
            return Some(Config::default());
        }
        // SAFETY: caller contract.
        let s = unsafe { CStr::from_ptr(ptr) }.to_str().ok()?.trim();
        if s.is_empty() {
            return Some(Config::default());
        }
        // Back-compat: a bare host:port is the plain-relay server (the `SPARK_PROXY` path).
        if let Ok(addr) = s.parse::<SocketAddr>() {
            let mut c = Config::default();
            c.transport.server = Some(addr);
            return Some(c);
        }
        // Otherwise a full config — spark's native TOML (AnyTLS, shaping, gambit, …) or a Lantern
        // `config_raw.json` payload, auto-detected and adapted by `Config::from_config_str`.
        Config::from_config_str(s).ok()
    }

    /// Signal a running [`spark_tunnel_run`] to stop (from `stopTunnel`).
    #[no_mangle]
    pub extern "C" fn spark_tunnel_stop() {
        spark_core::fd_tunnel::stop();
    }

    /// The active server pool as the UI's JSON array (see `spark.h` / `fd_tunnel::servers_json`), or
    /// `"[]"` when no pool is active. Heap-allocated; the caller frees it with [`spark_string_free`].
    /// Returns null only on allocation failure (our JSON has no interior NUL, so `CString::new` can't
    /// fail on content).
    #[no_mangle]
    pub extern "C" fn spark_servers_json() -> *mut c_char {
        let json = spark_core::fd_tunnel::servers_json();
        CString::new(json)
            .map(|c| c.into_raw())
            .unwrap_or(ptr::null_mut())
    }

    /// Free a string returned by [`spark_servers_json`].
    ///
    /// # Safety
    /// `s` must be null or a pointer previously returned by [`spark_servers_json`] and not yet freed.
    #[no_mangle]
    pub unsafe extern "C" fn spark_string_free(s: *mut c_char) {
        if !s.is_null() {
            // SAFETY: caller contract — `s` came from `CString::into_raw` in `spark_servers_json`.
            drop(unsafe { CString::from_raw(s) });
        }
    }

    /// Pin which pool member new flows dial first: `index >= 0` pins that member; `index < 0` selects
    /// auto (latency-ranked). Returns 0 on success, -1 if no server pool is active.
    #[no_mangle]
    pub extern "C" fn spark_select_server(index: c_int) -> c_int {
        let pin = if index < 0 {
            None
        } else {
            Some(index as usize)
        };
        if spark_core::fd_tunnel::select_server(pin) {
            0
        } else {
            -1
        }
    }
}
