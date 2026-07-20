//! `spark-apple` — the C-ABI static library (`libspark_apple.a`) linked into the Apple
//! NetworkExtension Packet Tunnel Provider on iOS and macOS.
//!
//! The Swift provider resolves the `utun` file descriptor (KVC `socket.fileDescriptor` → a
//! public-symbol fd-scan fallback — the WireGuard/sing-box/Mullvad/Proton/lantern technique) and
//! calls `spark_tunnel_run(fd, mtu, config, data_dir, split_tunnel, routing_mode)`; `spark_tunnel_stop()` on
//! teardown. Packets never cross the
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
    use std::os::raw::{c_char, c_int};
    use std::ptr;

    use spark_core::config::Config;

    /// Run the tunnel on the provided `utun` `fd` with `mtu`. Blocks the calling thread until
    /// [`spark_tunnel_stop`] (or the data path exits). Returns 0 on a clean stop, -1 on error.
    ///
    /// The caller (the Swift NE provider) hands ownership of `fd` to native for the tunnel's
    /// lifetime; the core closes it on stop.
    ///
    /// `config` selects the data path. The daemon owns config acquisition: the **absence** of an
    /// explicit config is the signal to self-fetch — the fetch must bypass the tunnel, and only the
    /// extension can guarantee that (its own dials egress the real interface by design), so the
    /// decision lives here, not in the controlling app. The Apple staticlib carries `config-fetch` on
    /// **every** slice (iOS device, iOS simulator, macOS — BoringSSL cross-compiles for all), so
    /// self-fetch works identically across them; the policy itself lives in the shared
    /// [`run_fd_dispatch`](spark_core::fd_tunnel::run_fd_dispatch) — the same one the Android JNI calls.
    /// - null/empty (or the explicit `"lantern-api"` sentinel) → **self-fetch** config from the
    ///   Lantern config-new API into `data_dir` (the app-group container path) and run the tunnel from
    ///   it, refreshing in the background; `data_dir` must be non-null (it caches `device_id` and the
    ///   fetched config), else the connect fails.
    /// - a bare `IP:port` literal (an IP address, not a hostname) → tunnel every flow through that
    ///   **plain spark relay**
    ///   (explicit override, e.g. dev/testing).
    /// - any other string → a full **[`Config`]** — spark's native TOML *or* a Lantern
    ///   `config_raw.json` payload (auto-detected), parsed via [`Config::from_config_str`]; the whole
    ///   transport stack applies (ADR 0006), all on the BoringSSL/`anytls` backend every slice carries.
    ///
    /// A non-null, non-empty explicit `config` — other than the reserved `"lantern-api"` sentinel
    /// (handled above) — that is neither a `SocketAddr` nor a valid TOML / `config_raw.json` config
    /// returns -1.
    ///
    /// # Safety
    /// `config` must be null or a valid NUL-terminated C string for the duration of this call.
    /// `data_dir` must be null or a valid NUL-terminated C string for the duration of this call.
    /// `split_tunnel` must be null or a valid NUL-terminated C string for the duration of this call.
    /// `routing_mode` must be null or a valid NUL-terminated C string for the duration of this call.
    #[no_mangle]
    pub unsafe extern "C" fn spark_tunnel_run(
        fd: c_int,
        mtu: c_int,
        config: *const c_char,
        data_dir: *const c_char,
        split_tunnel: *const c_char,
        routing_mode: *const c_char,
    ) -> c_int {
        // Resolve the config string (a null pointer means "no explicit config"). A *non-null* pointer
        // that isn't valid UTF-8 is a caller error — an explicit config was provided but is garbage —
        // so fail closed (close the transferred fd, return -1) rather than silently collapsing it to
        // "no config" (which would wrongly self-fetch instead of honoring the caller's intent).
        // SAFETY: caller contract — `config` is null or a valid NUL-terminated C string.
        let cfg: Option<&str> = if config.is_null() {
            None
        } else {
            match unsafe { CStr::from_ptr(config) }.to_str() {
                Ok(s) => Some(s),
                Err(_) => {
                    spark_core::fd_tunnel::abandon_fd(fd);
                    return -1;
                }
            }
        };

        // The app-group container path; the core caches `device_id` + the fetched `config_raw.json`
        // here in self-fetch mode. Reject empty (an empty path would cache into the process cwd); an
        // invalid-UTF-8 path is treated as absent (self-fetch then fails closed for want of a dir).
        // SAFETY: caller contract — `data_dir` is null or a valid NUL-terminated C string.
        let dir: Option<std::path::PathBuf> = if data_dir.is_null() {
            None
        } else {
            unsafe { CStr::from_ptr(data_dir) }
                .to_str()
                .ok()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(std::path::PathBuf::from)
        };

        // The bypass list is optional and non-critical — invalid UTF-8 is treated as absent
        // rather than failing the tunnel, since a bad bypass list should never block the VPN.
        // SAFETY: caller contract — `split_tunnel` is null or a valid NUL-terminated C string.
        let split: Option<&str> = if split_tunnel.is_null() {
            None
        } else {
            unsafe { CStr::from_ptr(split_tunnel) }.to_str().ok()
        };

        // The routing mode is optional and non-critical — null or invalid UTF-8 is treated as
        // absent rather than failing the tunnel, since a bad mode must not block the VPN.
        // SAFETY: caller contract — `routing_mode` is null or a valid NUL-terminated C string.
        let mode: Option<&str> = if routing_mode.is_null() {
            None
        } else {
            unsafe { CStr::from_ptr(routing_mode) }.to_str().ok()
        };

        // The shared, cross-platform policy home (the Apple C-ABI + Android JNI call it today; the
        // desktop service is a documented follow-up): direct / plain relay / full config / daemon
        // self-fetch, decided in core. The NE always owns a *userspace* utun (the kernel `system`
        // stack is Android-only), so the tun base is the userspace default.
        spark_core::fd_tunnel::run_fd_dispatch(
            fd,
            mtu as u16,
            cfg,
            dir.as_deref(),
            Config::default(),
            split,
            mode,
        )
    }

    /// Bridge the core's `tracing` events to a host logger (the Swift provider logs them via
    /// `os_log`, so the fetch path shows up in Console.app). Without this, the NE has no `tracing`
    /// subscriber and every core `info!`/`warn!` is dropped. Call once at startup, before
    /// [`spark_tunnel_run`], so cold-start fetch logs are captured. `cb` is the sink (`level`,
    /// NUL-terminated UTF-8 `msg` valid only for the call); a null `cb` is ignored. Idempotent — a
    /// second call (the `tracing` global default is already set) is a no-op.
    #[no_mangle]
    pub extern "C" fn spark_set_log_callback(
        cb: Option<extern "C" fn(level: u8, msg: *const c_char)>,
    ) {
        if let Some(cb) = cb {
            spark_core::log_bridge::install(cb);
        }
    }

    /// Signal a running [`spark_tunnel_run`] to stop (from `stopTunnel`).
    #[no_mangle]
    pub extern "C" fn spark_tunnel_stop() {
        spark_core::fd_tunnel::stop();
        // Clean-shutdown disarm for the tunnel diagnostics' unclean-exit sentinel.
        // Here (not only in the run loop's own exit path) because `stopTunnel` is the
        // one hook that runs on EVERY orderly teardown, and the OS may kill this
        // process before the (async) run loop finishes unwinding — disarming now
        // closes that window. Idempotent and a safe no-op when diagnostics never
        // initialized; the run loop's exit also disarms (belt and suspenders).
        // Same gate as the init in `run_fd_lantern_api`: macOS NE only for now.
        #[cfg(all(feature = "config-fetch", target_os = "macos"))]
        spark_core::diag::tunnel_host::disarm_sentinel();
    }

    /// Mark the tunnel **connecting** before the data path is up. The provider calls this
    /// **synchronously** in `startTunnel` *before* spawning the `spark_tunnel_run` worker, so a
    /// later [`spark_tunnel_wait_ready`] can't observe a stale ready/down state from a prior connect.
    #[no_mangle]
    pub extern "C" fn spark_tunnel_mark_connecting() {
        spark_core::fd_tunnel::mark_connecting();
    }

    /// Block until the running tunnel's data path is actually servicing the fd, returning `0`; or `-1`
    /// if it doesn't come up within `timeout_ms` or it stops first. The provider gates
    /// `completionHandler(nil)` on a `0` here so it never reports the tunnel up while `lantern-api`
    /// cold-start is still fetching config (which would blackhole traffic); on `-1` it should
    /// [`spark_tunnel_stop`] and fail the connection instead.
    #[no_mangle]
    pub extern "C" fn spark_tunnel_wait_ready(timeout_ms: c_int) -> c_int {
        spark_core::fd_tunnel::wait_ready(timeout_ms.max(0) as u32)
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

    /// Update the running tunnel's split-tunnel bypass list live. `json` is a NUL-terminated
    /// `{enabled,domains,ips}` payload. Returns 0 if applied; -1 if `json` is null, not valid UTF-8,
    /// not valid JSON, or there is no active router to update (no tunnel running, or a tunnel running
    /// without smart-routing — e.g. a plain relay/proxy path has no router).
    ///
    /// # Safety
    /// `json` must be null or a valid NUL-terminated C string.
    #[no_mangle]
    pub unsafe extern "C" fn spark_set_split_tunnel(json: *const c_char) -> c_int {
        if json.is_null() {
            return -1;
        }
        match unsafe { CStr::from_ptr(json) }.to_str() {
            Ok(s) if spark_core::fd_tunnel::set_split_tunnel(s) => 0,
            _ => -1,
        }
    }

    /// Update the running tunnel's app-bypass list live. `json` is a NUL-terminated JSON array of
    /// canonical `.app` bundle-root paths (`["/Applications/Foo.app", ...]`), matched by prefix
    /// against the resolved process path so in-bundle helpers match too — NOT executable paths.
    /// Returns 0 if applied; -1 if `json` is null, not valid UTF-8, not valid JSON, or there is no
    /// active router to update (no tunnel running, or a tunnel running without smart-routing — e.g. a
    /// plain relay/proxy path has no router). The listed apps route Direct (absolute). A flow whose
    /// owning process can't be resolved is **not** force-bypassed — it falls through to the normal
    /// routing decision (which may itself be Direct via a domain/IP rule), so app-bypass never leaks
    /// a flow it can't attribute.
    ///
    /// # Safety
    /// `json` must be null or a valid NUL-terminated C string.
    #[no_mangle]
    pub unsafe extern "C" fn spark_set_app_bypass(json: *const c_char) -> c_int {
        if json.is_null() {
            return -1;
        }
        match unsafe { CStr::from_ptr(json) }.to_str() {
            Ok(s) if spark_core::fd_tunnel::set_app_bypass(s) => 0,
            _ => -1,
        }
    }

    /// Update the running tunnel's routing mode live. `mode` is a NUL-terminated `"smart"`/`"full"`.
    /// Returns 0 if applied; -1 if `mode` is null, not valid UTF-8, or there is no active router to
    /// update (no tunnel running, or a tunnel running without smart-routing — e.g. a plain
    /// relay/proxy path has no router).
    ///
    /// # Safety
    /// `mode` must be null or a valid NUL-terminated C string.
    #[no_mangle]
    pub unsafe extern "C" fn spark_set_routing_mode(mode: *const c_char) -> c_int {
        if mode.is_null() {
            return -1;
        }
        match unsafe { CStr::from_ptr(mode) }.to_str() {
            Ok(s) if spark_core::fd_tunnel::set_routing_mode(s) => 0,
            _ => -1,
        }
    }

    /// Enable (`enabled != 0`) or disable (`0`) ad-block on the running tunnel live. Returns 0 if
    /// applied; -1 if there is no active router (no tunnel, or one without smart-routing).
    #[no_mangle]
    pub extern "C" fn spark_set_ad_block_enabled(enabled: c_int) -> c_int {
        if spark_core::fd_tunnel::set_ad_block_enabled(enabled != 0) {
            0
        } else {
            -1
        }
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
