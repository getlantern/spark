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

    /// Run the tunnel on the provided `utun` `fd` with `mtu`. Blocks the calling thread until
    /// [`spark_tunnel_stop`] (or the data path exits). Returns 0 on a clean stop, -1 on error.
    ///
    /// The caller (the Swift NE provider) hands ownership of `fd` to native for the tunnel's
    /// lifetime; the core closes it on stop.
    ///
    /// `server` selects the data path: null/empty forwards each flow **directly**; a `host:port` IP
    /// literal tunnels every flow through that **plain spark relay** (so egress is the relay's IP).
    /// A non-null, non-empty `server` that doesn't parse as a `SocketAddr` returns -1.
    ///
    /// # Safety
    /// `server` must be null or a valid NUL-terminated C string for the duration of this call.
    #[no_mangle]
    pub unsafe extern "C" fn spark_tunnel_run(
        fd: c_int,
        mtu: c_int,
        server: *const c_char,
    ) -> c_int {
        // The NE always uses the cross-platform userspace stack (the `system` stack is Android-only).
        let mut config = spark_core::config::Config::default();
        if !server.is_null() {
            // SAFETY: caller contract — `server` is a valid NUL-terminated C string when non-null.
            let s = match unsafe { CStr::from_ptr(server) }.to_str() {
                Ok(s) => s.trim(),
                Err(_) => return -1,
            };
            if !s.is_empty() {
                match s.parse::<SocketAddr>() {
                    Ok(addr) => config.transport.server = Some(addr),
                    Err(_) => return -1,
                }
            }
        }
        // `run_fd` is the shared run + status-code convention. With `transport.server` set, the core
        // tunnels TCP/UDP flows through the plain relay instead of dialing them directly.
        spark_core::fd_tunnel::run_fd(fd, mtu as u16, config)
    }

    /// Signal a running [`spark_tunnel_run`] to stop (from `stopTunnel`).
    #[no_mangle]
    pub extern "C" fn spark_tunnel_stop() {
        spark_core::fd_tunnel::stop();
    }
}
