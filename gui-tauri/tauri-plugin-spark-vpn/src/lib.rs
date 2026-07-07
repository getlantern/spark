mod commands;
mod control;
mod error;
mod models;

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
    use tauri::{AppHandle, Runtime};

    pub(crate) fn control<R: Runtime>(
        _app: &AppHandle<R>,
    ) -> crate::Result<Box<dyn crate::TunnelControl>> {
        #[cfg(target_os = "macos")]
        {
            Ok(Box::new(crate::desktop::AppleControl))
        }

        #[cfg(target_os = "android")]
        {
            Ok(Box::new(crate::mobile::AndroidControl))
        }

        #[cfg(all(not(target_os = "macos"), not(target_os = "android")))]
        {
            Ok(Box::new(crate::desktop::ServiceControl))
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
