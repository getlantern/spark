mod commands;
mod control;
mod error;
mod models;

// Durable settings persistence is used only by the desktop control (AppleControl/ServiceControl).
// On Android, persistence lives behind the JNI core (P3.2), so gate the module the same as desktop
// to avoid dead-code warnings on the android target.
#[cfg(not(target_os = "android"))]
pub(crate) mod persist;

#[cfg(not(target_os = "android"))]
mod desktop;

// macOS installed-apps catalog for desktop app-based split tunneling (AppleControl uses it).
#[cfg(target_os = "macos")]
mod apps_darwin;

#[cfg(target_os = "android")]
mod mobile;

pub use control::TunnelControl;
pub use error::{Error, Result};
pub use models::{ServerInfo, Status};

use tauri::{
    plugin::{Builder, TauriPlugin},
    Manager, Runtime,
};

// Desktop control construction. On Android the control is built in `init`'s setup from the
// registered plugin handle (which is not available here), so this module is desktop-only.
#[cfg(not(target_os = "android"))]
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
        let base = app
            .path()
            .app_config_dir()
            .map_err(|e| crate::Error::Platform(format!("no app config dir: {e}")))?;

        #[cfg(target_os = "macos")]
        {
            Ok(Box::new(crate::desktop::AppleControl { base }))
        }

        #[cfg(not(target_os = "macos"))]
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
            commands::list_installed_apps,
            commands::get_excluded_apps,
            commands::set_excluded_apps,
        ])
        .setup(|app, _api| {
            #[cfg(target_os = "android")]
            {
                // Register the Kotlin plugin (SparkVpnPlugin, package org.getlantern.spark.vpn) and
                // wrap its handle in the AndroidControl seam. The JNI/run_mobile_plugin calls are
                // wired in P3.2.
                let handle =
                    _api.register_android_plugin("org.getlantern.spark.vpn", "SparkVpnPlugin")?;
                let ctl: Box<dyn crate::TunnelControl> =
                    Box::new(crate::mobile::AndroidControl::new(handle));
                app.manage(ctl);
            }
            #[cfg(not(target_os = "android"))]
            {
                let ctl = platform::control(app)?;
                app.manage(ctl);
            }
            Ok(())
        })
        .build()
}
