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
