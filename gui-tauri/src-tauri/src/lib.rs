// U1a spike (NE Model A): prove the Tauri-desktop Rust side can reach macOS
// NetworkExtension directly via objc2 — no Swift toolchain. We read the tunnel
// connection status synchronously (NETunnelProviderManager → connection →
// status), the read path that needs no NE entitlement, so it runs unsigned in
// dev. If this returns a real NEVPNStatus, the bridge for U1b (load/save/start/
// stop via the same objc2 binding) is proven.
#[cfg(target_os = "macos")]
pub mod ne_spike {
    use objc2_network_extension::NETunnelProviderManager;

    /// Raw NEVPNStatus of a fresh manager's connection (Invalid=0, Disconnected=1,
    /// Connecting=2, Connected=3, Reasserting=4, Disconnecting=5).
    pub fn probe_status_raw() -> isize {
        // SAFETY: NETunnelProviderManager/NEVPNConnection are plain ObjC objects;
        // `new` + the `connection`/`status` getters are side-effect-free reads.
        unsafe {
            let manager = NETunnelProviderManager::new();
            let connection = manager.connection();
            connection.status().0
        }
    }

    /// Human-readable status name for the spike's report.
    pub fn status_name(raw: isize) -> &'static str {
        match raw {
            0 => "invalid",
            1 => "disconnected",
            2 => "connecting",
            3 => "connected",
            4 => "reasserting",
            5 => "disconnecting",
            _ => "unknown",
        }
    }

    /// U1b machinery proof: enumerate the app's saved tunnel managers via the
    /// async `loadAllFromPreferences` completion handler — the real status source
    /// (U1a's synchronous `new()` was only a bridge probe). The completion fires on
    /// the main queue, so the caller must service the main run loop; this drives it
    /// in 0.1s slices for up to ~3s. Returns (manager_count, first_status_raw);
    /// first_status_raw is -1 when there are no managers. The same completion-block
    /// pattern carries connect/disconnect (saveToPreferences/startVPNTunnel) in U1c.
    ///
    /// MUST be called on the main thread (the example does; in the Tauri app the
    /// command hops to the main thread). Needs no NE entitlement — read-only.
    pub fn load_first_status_blocking() -> (usize, isize) {
        use std::sync::mpsc::channel;

        use block2::RcBlock;
        use objc2_foundation::{NSArray, NSDate, NSDefaultRunLoopMode, NSError, NSRunLoop};

        let (tx, rx) = channel::<(usize, isize)>();
        let handler = RcBlock::new(
            move |arr: *mut NSArray<NETunnelProviderManager>, _err: *mut NSError| {
                // SAFETY: `arr` is the framework-owned managers array (or null).
                let result = unsafe {
                    if arr.is_null() {
                        (0usize, -1isize)
                    } else {
                        let arr = &*arr;
                        let count = arr.count();
                        let status = if count > 0 {
                            arr.objectAtIndex(0).connection().status().0
                        } else {
                            -1
                        };
                        (count, status)
                    }
                };
                let _ = tx.send(result);
            },
        );

        // SAFETY: standard NE async-read API; the handler outlives the call via RcBlock.
        unsafe { NETunnelProviderManager::loadAllFromPreferencesWithCompletionHandler(&handler) };

        // Drive the main run loop until the main-queue completion fires (~3s cap).
        let run_loop = NSRunLoop::currentRunLoop();
        for _ in 0..30 {
            if let Ok(v) = rx.try_recv() {
                return v;
            }
            let until = NSDate::dateWithTimeIntervalSinceNow(0.1);
            unsafe { run_loop.runMode_beforeDate(NSDefaultRunLoopMode, &until) };
        }
        rx.try_recv().unwrap_or((0, -2))
    }
}

/// Spike command: returns the macOS NE connection status (proves the bridge).
/// macOS only; U1b grows this into the real SparkBackend command surface.
#[cfg(target_os = "macos")]
#[tauri::command]
fn ne_probe() -> String {
    let raw = ne_spike::probe_status_raw();
    format!("{} ({})", ne_spike::status_name(raw), raw)
}

#[cfg(not(target_os = "macos"))]
#[tauri::command]
fn ne_probe() -> String {
    "unsupported on this platform".to_owned()
}

// U0: shell only — the UI runs against a TypeScript MockBackend. U1a adds the
// `ne_probe` spike command; U1b adds the real SparkBackend command surface
// (status/connect/disconnect) driving NETunnelProviderManager via the same
// objc2 binding (NE Model A — system extension, no spark-ipc on macOS).
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![ne_probe])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
