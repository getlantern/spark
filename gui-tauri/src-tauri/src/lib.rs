// U0: shell only — the UI runs against a TypeScript MockBackend, so there are no
// Tauri commands yet. U1 adds the invoke() command surface implementing
// SparkBackend (status/connect/disconnect) over the real spark core / spark-ipc.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
