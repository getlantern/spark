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

// Unbounded (volunteer-proxy) control + aggregation loop + `spark://unbounded` event. Depends on
// `persist` (durable settings) and `spark-sharing` (the peer-proxy pool). Gated the same as
// `persist` — desktop only; the Android sharing path lands in a later Unbounded phase.
#[cfg(not(target_os = "android"))]
mod unbounded;

// Phase 2a: app-side startup config fetch (links spark-core's kindling fetch). Desktop only —
// Android fetches in the :vpn process over IPC (Phase 2b).
#[cfg(not(target_os = "android"))]
mod config_fetch;

// macOS installed-apps catalog for desktop app-based split tunneling (AppleControl uses it).
#[cfg(target_os = "macos")]
mod apps_darwin;

// Desktop system tray (macOS menu bar / Windows + Linux tray). Desktop-only.
#[cfg(desktop)]
mod tray;

// Desktop control over spark-ipc (Windows named pipe / Linux unix socket). Compiled off android;
// on macOS it provides the transport-agnostic ipc client that AppleControl doesn't use but which
// unit-tests here (its unix path == the Linux path).
#[cfg(not(target_os = "android"))]
mod service_ipc;

#[cfg(target_os = "android")]
mod mobile;

pub use control::TunnelControl;
pub use error::{Error, Result};
pub use models::{ServerInfo, Status};

use tauri::{
    plugin::{Builder, TauriPlugin},
    Manager, Runtime,
};
// `Emitter` provides `.emit()` (Phase 2a startup fetch emits `spark://servers`); unused on Android,
// which doesn't run the desktop startup fetch.
#[cfg(not(target_os = "android"))]
use tauri::Emitter;

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

        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            Ok(Box::new(crate::desktop::AppleControl { base }))
        }

        #[cfg(all(not(target_os = "macos"), not(target_os = "ios")))]
        {
            Ok(Box::new(crate::desktop::ServiceControl::new(base)))
        }
    }
}

/// Convert the `select_server` i32 arg to a pin (negative → auto/None). Lives here (not in the
/// desktop-only `tray` module) so the commands, which run on mobile too, can use it.
pub(crate) fn tray_pin(index: i32) -> Option<usize> {
    if index < 0 {
        None
    } else {
        Some(index as usize)
    }
}

/// Convert a pin back to the i32 wire value (None → -1). A pin is a small pool index by
/// construction, but use a checked conversion rather than `as i32` so an out-of-range value can
/// never silently wrap into a wrong server index — it falls back to auto (-1) instead.
pub(crate) fn tray_pin_to_i32(pin: Option<usize>) -> i32 {
    pin.and_then(|i| i32::try_from(i).ok()).unwrap_or(-1)
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
            commands::get_selected_server,
            commands::get_split_tunnel,
            commands::set_split_tunnel,
            commands::get_routing_mode,
            commands::set_routing_mode,
            commands::get_ad_block_enabled,
            commands::set_ad_block_enabled,
            commands::list_installed_apps,
            commands::get_excluded_apps,
            commands::set_excluded_apps,
            // Unbounded (volunteer-proxy) commands. Desktop only — gated the same as the module.
            #[cfg(not(target_os = "android"))]
            unbounded::unbounded_start,
            #[cfg(not(target_os = "android"))]
            unbounded::unbounded_stop,
            #[cfg(not(target_os = "android"))]
            unbounded::unbounded_status,
            #[cfg(not(target_os = "android"))]
            unbounded::unbounded_available,
            #[cfg(not(target_os = "android"))]
            unbounded::unbounded_get_settings,
            #[cfg(not(target_os = "android"))]
            unbounded::unbounded_set_settings,
        ])
        .setup(|app, _api| {
            app.manage(commands::SelectedServer::default());
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

                // Unbounded (volunteer-proxy) live handles: the running sharing pool + its
                // aggregation-loop task + latest status. Default = nothing running.
                app.manage(unbounded::UnboundedState::default());

                // Phase 2a: on every launch, fetch the config into the app's OWN cache dir —
                // independent of VPN state — so the location list refreshes even before/without
                // connecting (stale-while-revalidate on top of the instant cache read). Fully
                // detached: a failure never blocks startup, the window, or connect. On a *changed*
                // config, emit `spark://servers` so the window re-pulls `servers()`; the tray's
                // `refresh()` re-reads it too. On 304/unchanged or failure, the cached list is intact.
                //
                // The cache lives under the app's `app_config_dir` (Application Support) — NOT the
                // app-group container — to avoid the macOS "access data from other apps" TCC prompt
                // and the NE-sandbox EPERM (see desktop::app_config_cache_dir).
                let handle = app.app_handle().clone();
                tauri::async_runtime::spawn(async move {
                    let Ok(base) = handle.path().app_config_dir() else {
                        return;
                    };
                    let dir = crate::desktop::app_config_cache_dir(&base);
                    let _ = std::fs::create_dir_all(&dir);
                    match crate::config_fetch::fetch_into_cache(&dir).await {
                        Ok(true) => {
                            let _ = handle.emit("spark://servers", ());
                        }
                        Ok(false) => {} // 304 / unchanged — nothing to do
                        Err(e) => eprintln!("[spark-vpn] startup config fetch failed: {e}"),
                    }
                });

                // Gated startup auto-enable for Unbounded (volunteer proxy). Two gates, both must
                // pass: (1) the user opted in (`auto_enable`, default false — see persist.rs), and
                // (2) the server allows it AND the config carries the endpoints to dial
                // (`unbounded_available`, backed by `features.unbounded` + the `unbounded` block —
                // Task 7.1). `unbounded_start` self-gates on the same availability check, but check
                // it explicitly here so we don't even spawn the task when the feature is off, and so
                // the "skipped" log distinguishes not-available from a real start failure. Detached
                // so it can't block startup or the window.
                let handle = app.app_handle().clone();
                tauri::async_runtime::spawn(async move {
                    let Ok(base) = handle.path().app_config_dir() else {
                        return;
                    };
                    if !crate::persist::load_unbounded_auto_enable(&base) {
                        return;
                    }
                    match unbounded::unbounded_available(handle.clone()).await {
                        Ok(true) => {
                            if let Err(e) = unbounded::unbounded_start(handle).await {
                                eprintln!("[spark-vpn] unbounded auto-enable failed: {e}");
                            }
                        }
                        Ok(false) => {} // feature not available for this client — nothing to do
                        Err(e) => eprintln!("[spark-vpn] unbounded availability check failed: {e}"),
                    }
                });
            }
            #[cfg(desktop)]
            tray::init(app)?;
            Ok(())
        })
        .build()
}
