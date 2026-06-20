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

    use std::sync::mpsc::Sender;
    use std::time::Duration;

    use block2::RcBlock;
    use objc2::rc::Retained;
    use objc2::runtime::AnyObject;
    use objc2_foundation::{ns_string, NSArray, NSDictionary, NSError, NSString};
    use objc2_network_extension::NETunnelProviderProtocol;

    fn err_str(e: *mut NSError) -> String {
        // SAFETY: caller passes a non-null framework NSError*.
        unsafe { (*e).localizedDescription().to_string() }
    }

    /// U1b-2b: bring the tunnel up. NE completion handlers fire on the main queue
    /// and NETunnelProviderManager isn't Send, so the whole load→save→reload→start
    /// chain runs inside the loadAll completion (on the main thread, via nested
    /// completion blocks); this (worker) thread just waits on a channel for the
    /// final verdict. `config` is the resolved data-path config (TOML/host:port),
    /// handed to the extension via providerConfiguration["config"].
    ///
    /// Assumes the org.getlantern.spark.tunnel system extension is already
    /// activated (U1b-2b-ii adds OSSystemExtensionRequest activation for fresh
    /// installs). Needs the NE entitlement (present in the signed product build).
    pub fn connect(config: Option<String>) -> Result<(), String> {
        let (tx, rx) = std::sync::mpsc::channel::<Result<(), String>>();
        let outer = RcBlock::new(
            move |arr: *mut NSArray<NETunnelProviderManager>, _e: *mut NSError| {
                let mgr: Retained<NETunnelProviderManager> = unsafe {
                    if !arr.is_null() && (*arr).count() > 0 {
                        (*arr).objectAtIndex(0)
                    } else {
                        NETunnelProviderManager::new()
                    }
                };
                let proto = unsafe { NETunnelProviderProtocol::new() };
                unsafe {
                    proto.setProviderBundleIdentifier(Some(ns_string!(
                        "org.getlantern.spark.tunnel"
                    )));
                    proto.setServerAddress(Some(ns_string!("Spark")));
                    if let Some(ref c) = config {
                        // providerConfiguration is NSDictionary<NSString, AnyObject>; upcast the
                        // NSString value (NSString → NSObject → AnyObject) so the value type matches.
                        let val: Retained<AnyObject> =
                            NSString::from_str(c).into_super().into_super();
                        let dict =
                            NSDictionary::from_retained_objects(&[ns_string!("config")], &[val]);
                        proto.setProviderConfiguration(Some(&dict));
                    }
                    mgr.setProtocolConfiguration(Some(&proto));
                    mgr.setLocalizedDescription(Some(ns_string!("Spark")));
                    mgr.setEnabled(true);
                }
                // save → (on completion) reload → (on completion) start.
                let tx_save = tx.clone();
                let mgr_save = mgr.clone();
                let save_block = RcBlock::new(move |serr: *mut NSError| {
                    if !serr.is_null() {
                        let _ = tx_save.send(Err(format!("save failed: {}", err_str(serr))));
                        return;
                    }
                    let tx_load = tx_save.clone();
                    let mgr_start = mgr_save.clone();
                    let load_block = RcBlock::new(move |lerr: *mut NSError| {
                        if !lerr.is_null() {
                            let _ = tx_load.send(Err(format!("reload failed: {}", err_str(lerr))));
                            return;
                        }
                        let r = unsafe { mgr_start.connection().startVPNTunnelAndReturnError() }
                            .map_err(|e| format!("start failed: {e}"));
                        let _ = tx_load.send(r);
                    });
                    unsafe { mgr_save.loadFromPreferencesWithCompletionHandler(&load_block) };
                });
                unsafe { mgr.saveToPreferencesWithCompletionHandler(Some(&save_block)) };
            },
        );
        // SAFETY: NE copies the escaping completion block, so it outlives this call.
        unsafe { NETunnelProviderManager::loadAllFromPreferencesWithCompletionHandler(&outer) };
        rx.recv_timeout(Duration::from_secs(25))
            .map_err(|_| "connect timed out".to_owned())?
    }

    /// Bring the tunnel down: stop the first manager's connection (the stop call
    /// runs inside the loadAll completion, on the main thread).
    pub fn disconnect() -> Result<(), String> {
        let (tx, rx): (Sender<Result<(), String>>, _) = std::sync::mpsc::channel();
        let h = RcBlock::new(
            move |arr: *mut NSArray<NETunnelProviderManager>, _e: *mut NSError| {
                let r = unsafe {
                    if !arr.is_null() && (*arr).count() > 0 {
                        (*arr).objectAtIndex(0).connection().stopVPNTunnel();
                        Ok(())
                    } else {
                        Err("no tunnel configured".to_owned())
                    }
                };
                let _ = tx.send(r);
            },
        );
        unsafe { NETunnelProviderManager::loadAllFromPreferencesWithCompletionHandler(&h) };
        rx.recv_timeout(Duration::from_secs(10))
            .map_err(|_| "disconnect timed out".to_owned())?
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

// connect/disconnect (U1b-2b): the data-path config resolves here (config.toml →
// baked → proxy → direct) and is handed to the system extension via the
// NETunnelProviderManager save/start chain. Assumes the extension is activated
// (OSSystemExtensionRequest activation for fresh installs is U1b-2b-ii).
#[cfg(target_os = "macos")]
#[tauri::command]
fn spark_connect() -> Result<(), String> {
    ne_spike::connect(config::resolve())
}

#[cfg(target_os = "macos")]
#[tauri::command]
fn spark_disconnect() -> Result<(), String> {
    ne_spike::disconnect()
}

#[cfg(not(target_os = "macos"))]
#[tauri::command]
fn spark_connect() -> Result<(), String> {
    Err("connect unsupported on this platform".to_owned())
}

#[cfg(not(target_os = "macos"))]
#[tauri::command]
fn spark_disconnect() -> Result<(), String> {
    Err("disconnect unsupported on this platform".to_owned())
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
