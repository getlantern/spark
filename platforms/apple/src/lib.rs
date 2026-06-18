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
    use std::os::raw::c_int;

    /// Run the tunnel on the provided `utun` `fd` with `mtu`. Blocks the calling thread until
    /// [`spark_tunnel_stop`] (or the data path exits). Returns 0 on a clean stop, -1 on error.
    ///
    /// The caller (the Swift NE provider) hands ownership of `fd` to native for the tunnel's
    /// lifetime; the core closes it on stop.
    #[no_mangle]
    pub extern "C" fn spark_tunnel_run(fd: c_int, mtu: c_int) -> c_int {
        // The NE always uses the cross-platform userspace stack (the `system` stack is Android-only),
        // so the default config is right; `run_fd` is the shared run + status-code convention.
        spark_core::fd_tunnel::run_fd(fd, mtu as u16, spark_core::config::Config::default())
    }

    /// Signal a running [`spark_tunnel_run`] to stop (from `stopTunnel`).
    #[no_mangle]
    pub extern "C" fn spark_tunnel_stop() {
        spark_core::fd_tunnel::stop();
    }
}
