// The app crate is now a UI shell only. All VPN control (status/connect/disconnect,
// server selection, split-tunnel + routing-mode persistence, and the macOS
// NetworkExtension bridge that used to live here as `ne_spike`) has moved into
// `tauri-plugin-spark-vpn`, which registers its own `plugin:spark-vpn|*` commands
// via its `init()`. The frontend invokes those directly, so this crate carries no
// app-level commands or `config` module anymore.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_spark_vpn::init())
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
