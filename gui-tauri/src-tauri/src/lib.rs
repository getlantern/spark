mod config;

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

    /// App-context status read: same async `loadAllFromPreferences`, but instead of
    /// driving a run loop it blocks the *calling* (worker) thread on a channel —
    /// the Tauri app's own main loop services the main-queue completion. Use this
    /// from a Tauri command (never the main thread). Returns (count, first_status).
    pub fn load_first_status(timeout: std::time::Duration) -> (usize, isize) {
        use std::sync::mpsc::channel;

        use block2::RcBlock;
        use objc2_foundation::{NSArray, NSError};

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
        rx.recv_timeout(timeout).unwrap_or((0, -2))
    }

    /// Map a raw NEVPNStatus to the four UI states the frontend SparkBackend uses.
    pub fn ui_state(raw: isize) -> &'static str {
        match raw {
            3 => "connected",
            2 | 4 => "connecting", // connecting / reasserting
            _ => "disconnected",   // invalid / disconnected / disconnecting
        }
    }
}

/// The SparkBackend status shape the frontend renders (mirrors the TS interface).
#[derive(serde::Serialize)]
struct SparkStatus {
    state: String,
    protocol: String,
    routing: String,
    #[serde(rename = "failOpen")]
    fail_open: bool,
}

/// Real tunnel status: read the live NE connection state (U1b machinery). macOS
/// reads NETunnelProviderManager; elsewhere it's a stub until those platforms land.
#[cfg(target_os = "macos")]
#[tauri::command]
fn spark_status() -> SparkStatus {
    let (_count, raw) = ne_spike::load_first_status(std::time::Duration::from_secs(3));
    let state = ne_spike::ui_state(raw);
    SparkStatus {
        state: state.to_owned(),
        protocol: "AnyTLS".to_owned(),
        routing: "Full tunnel".to_owned(),
        fail_open: state != "connected",
    }
}

#[cfg(not(target_os = "macos"))]
#[tauri::command]
fn spark_status() -> SparkStatus {
    SparkStatus {
        state: "disconnected".to_owned(),
        protocol: "AnyTLS".to_owned(),
        routing: "Full tunnel".to_owned(),
        fail_open: true,
    }
}

// connect/disconnect: the data-path config resolves here (config.toml → baked →
// proxy → direct); the NETunnelProviderManager save/start + system-extension
// activation that consume it are U1b-2b (and need the embedded, signed extension
// + first-run approval). Returns an explicit error until then rather than a silent
// no-op, so the UI shows the honest state.
#[tauri::command]
fn spark_connect() -> Result<(), String> {
    let has_cfg = config::resolve().is_some();
    Err(format!(
        "connect not wired yet (U1b-2b: NETunnelProviderManager save/start + system-extension activation). data-path config: {}",
        if has_cfg { "resolved" } else { "none (would run direct)" }
    ))
}

#[tauri::command]
fn spark_disconnect() -> Result<(), String> {
    Err("disconnect not wired yet (U1b-2b)".to_owned())
}

// U1b-2a: the UI now drives a real SparkBackend command surface — `spark_status`
// reads the live NE connection state; `spark_connect`/`spark_disconnect` resolve
// config and report honest "pending" until the U1b-2b write path lands. (The U1a
// `ne_probe` diagnostic now lives only in examples/.)
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            spark_status,
            spark_connect,
            spark_disconnect
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
