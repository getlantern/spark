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
    use std::ffi::CStr;
    use std::net::SocketAddr;
    use std::os::raw::{c_char, c_int};

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
    /// plain relay (today's behavior); otherwise a full TOML config. `None` signals a parse error
    /// (`-1` to the caller). The NE always uses the userspace stack (`system` is Android-only).
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
        // Otherwise a full TOML config — AnyTLS, handshake shaping, gambit, etc.
        Config::from_toml_str(s).ok()
    }

    /// Signal a running [`spark_tunnel_run`] to stop (from `stopTunnel`).
    #[no_mangle]
    pub extern "C" fn spark_tunnel_stop() {
        spark_core::fd_tunnel::stop();
    }
}
