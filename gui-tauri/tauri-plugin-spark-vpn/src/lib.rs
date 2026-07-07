mod commands;
mod control;
mod error;
mod models;
pub(crate) mod persist;

#[cfg(not(target_os = "android"))]
mod desktop;

#[cfg(target_os = "android")]
mod mobile;

pub use control::TunnelControl;
pub use error::{Error, Result};
pub use models::{ServerInfo, Status};

use tauri::{
    plugin::{Builder, TauriPlugin},
    Manager, Runtime,
};

mod platform {
    use tauri::{AppHandle, Manager, Runtime};

    pub(crate) fn control<R: Runtime>(
        app: &AppHandle<R>,
    ) -> crate::Result<Box<dyn crate::TunnelControl>> {
        // Resolve the platform-provided config dir once and pass it into the control struct.
        // On macOS this is `~/Library/Application Support/org.getlantern.spark`, which is the
        // same directory that `gui-tauri/src-tauri/src/config.rs::config_dir()` produces —
        // so the plugin reads/writes the same files as the existing app.
        //
        // Tauri 2's `app_config_dir()` resolves to `config_dir()/${bundle_identifier}` (see
        // tauri-2.x/src/path/desktop.rs), so the identifier is already embedded in the path.
        // No manual join of "org.getlantern.spark" is needed.
        #[cfg(not(target_os = "android"))]
        let base = app
            .path()
            .app_config_dir()
            .map_err(|e| crate::Error::Platform(format!("no app config dir: {e}")))?;

        #[cfg(target_os = "macos")]
        {
            Ok(Box::new(crate::desktop::AppleControl { base }))
        }

        #[cfg(target_os = "android")]
        {
            // Android: base dir comes from Kotlin in a later task; stub for now.
            let _ = app; // suppress unused warning
            Ok(Box::new(crate::mobile::AndroidControl))
        }

        #[cfg(all(not(target_os = "macos"), not(target_os = "android")))]
        {
            Ok(Box::new(crate::desktop::ServiceControl { base }))
        }
    }
}

/// Initialise the `spark-vpn` plugin. Wire this into the Tauri builder via
/// `.plugin(tauri_plugin_spark_vpn::init())`.
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("spark-vpn")
        .invoke_handler(tauri::generate_handler![
            commands::connect,
            commands::disconnect,
            commands::status,
            commands::servers,
            commands::select_server,
            commands::get_split_tunnel,
            commands::set_split_tunnel,
            commands::get_routing_mode,
            commands::set_routing_mode,
        ])
        .setup(|app, _api| {
            let ctl = platform::control(app)?;
            app.manage(ctl);
            Ok(())
        })
        .build()
}
