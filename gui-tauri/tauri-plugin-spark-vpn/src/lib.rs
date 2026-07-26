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
// `persist` (durable settings) and `spark-sharing` (the peer-proxy pool).
//
// `cfg(desktop)` — i.e. NOT iOS and NOT Android. Acting as a sharing proxy is a desktop-only role:
// a phone in an uncensored region should not be relaying strangers' traffic (battery, data plan, NAT,
// and the legal exposure of being the visible source of that traffic). Being a censored *consumer* of
// Unbounded is a separate concern and is deliberately NOT gated here — that path lives behind
// spark-sharing's `spark-transport` feature (`ConsumerTransport`) and is wired independently.
#[cfg(desktop)]
mod unbounded;

// §C6 diagnostic timeline + §C3a session traces for the Unbounded pool: a pure
// PoolEvent → diag-action mapper applied fire-and-forget by `unbounded`'s aggregation
// loop. Gated with `unbounded` (desktop only), whose span queue it feeds via `diag_host`.
#[cfg(desktop)]
mod unbounded_diag;

// Phase 2a: app-side startup config fetch (links spark-core's kindling fetch). Desktop only —
// Android fetches in the :vpn process over IPC (Phase 2b).
#[cfg(not(target_os = "android"))]
mod config_fetch;

// Diagnostics host for the APP process (diag design §C4/§5): sink + panic hook + tracing capture
// layer + config-gated OTLP uploader, plus the webview error-report / opt-out commands. Compiled
// everywhere except Android (desktop today, iOS when it lands), like the other spark-core-backed
// modules — Android's diagnostics ride the tunnel-process phase (spec Phase B).
#[cfg(not(target_os = "android"))]
mod diag_host;

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
            // Unbounded (volunteer-proxy) commands. Desktop only — gated the same as the module, so
            // on iOS/Android they are not registered at all and the UI's `unboundedAvailable()` probe
            // fails closed (the tab stays hidden).
            #[cfg(desktop)]
            unbounded::unbounded_start,
            #[cfg(desktop)]
            unbounded::unbounded_stop,
            #[cfg(desktop)]
            unbounded::unbounded_status,
            #[cfg(desktop)]
            unbounded::unbounded_available,
            #[cfg(desktop)]
            unbounded::unbounded_get_settings,
            #[cfg(desktop)]
            unbounded::unbounded_set_settings,
            // Diagnostics commands (webview error report + opt-out toggle). Desktop only —
            // gated the same as the diag_host module.
            #[cfg(not(target_os = "android"))]
            diag_host::diag_report_webview_error,
            #[cfg(not(target_os = "android"))]
            diag_host::diag_set_enabled,
            #[cfg(not(target_os = "android"))]
            diag_host::diag_get_enabled,
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
                // Diagnostics first (diag design §C4/§5), so the panic hook and tracing
                // capture layer are in place before the startup tasks below spawn and any
                // of their failures can be captured. Infallible and internally detached —
                // never blocks or fails setup. No-op when the user opted out.
                diag_host::init(app);

                let ctl = platform::control(app)?;
                app.manage(ctl);

                // Unbounded (volunteer-proxy) live handles: the running sharing pool + its
                // aggregation-loop task + latest status. Default = nothing running. Desktop only —
                // phones don't act as sharing proxies (see `mod unbounded`).
                #[cfg(desktop)]
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
                    // Refresh the cached `features.unbounded` gate from whatever config we now have
                    // (fresh or cached) and repaint the tray. This is the ONLY place that needs to
                    // re-derive it from disk — the tray and the sharing loop read the cached flag, so
                    // neither re-parses the whole config on a timer.
                    #[cfg(desktop)]
                    let _ = crate::unbounded::refresh_availability(&handle);
                    #[cfg(desktop)]
                    crate::tray::refresh(&handle);
                });

                // Gated startup for Unbounded (volunteer proxy). Two gates, both must pass:
                // (1) the user's persisted on/off state (`unbounded_enabled`, default false — written when
                // the user toggles Unbounded; this is the state the UI + tray read, so resuming it here is
                // what keeps a restart from showing "enabled" while nothing runs — Copilot #90), and
                // (2) the server allows it AND the config carries the endpoints to dial
                // (`unbounded_available`, backed by `features.unbounded` + the `unbounded` block). The
                // separate `unbounded_auto_enable` preference does NOT gate this resume path. `unbounded_start`
                // self-gates on the same availability check, but check it explicitly here so we don't even
                // spawn the task when the feature is off, and so the "skipped" log distinguishes
                // not-available from a real start failure. Detached so it can't block startup or the window.
                //
                // Desktop only: a phone never resumes as a sharing proxy (see `mod unbounded`).
                #[cfg(desktop)]
                {
                    let handle = app.app_handle().clone();
                    tauri::async_runtime::spawn(async move {
                        let Ok(base) = handle.path().app_config_dir() else {
                            return;
                        };
                        // Two durable flags, and BOTH must say yes — Unbounded never starts unless the
                        // user explicitly authorized it:
                        //   `unbounded_enabled`    the user's current on/off choice
                        //   `unbounded_auto_enable` the user's "start automatically when Spark opens"
                        // Requiring only `enabled` would resume at login for a user who deliberately
                        // left auto-start off; requiring only `auto_enable` would leave the UI showing
                        // "on" with nothing running. So: resume on both, and when `enabled` is set
                        // WITHOUT auto-start, clear it so the persisted state matches reality (nothing
                        // is relaying) instead of advertising an enrolment that isn't live.
                        let enabled = crate::persist::load_unbounded_enabled(&base);
                        let auto = crate::persist::load_unbounded_auto_enable(&base);
                        if !enabled || !auto {
                            if enabled && !auto {
                                let _ = crate::persist::save_unbounded_enabled(&base, false);
                            }
                            return;
                        }
                        match unbounded::unbounded_available(handle.clone()).await {
                            Ok(true) => {
                                if let Err(e) = unbounded::unbounded_start(handle).await {
                                    eprintln!("[spark-vpn] unbounded auto-enable failed: {e}");
                                }
                            }
                            Ok(false) => {} // feature not available for this client — nothing to do
                            Err(e) => {
                                eprintln!("[spark-vpn] unbounded availability check failed: {e}")
                            }
                        }
                    });
                } // end cfg(desktop) — Unbounded startup resume
            }
            #[cfg(desktop)]
            tray::init(app)?;
            Ok(())
        })
        .on_event(|_app, event| {
            // Clean-shutdown disarm for the unclean-exit sentinel (diag §C2a). Exit
            // only — NOT ExitRequested, which can be cancelled (a cancelled exit that
            // disarmed would leave the rest of the session crash-blind). Known false
            // positive: OS logout/shutdown may SIGKILL the process before Exit fires,
            // slightly inflating `error.unclean_exit` during real OS shutdowns; a
            // SIGTERM disarm hook is a possible future refinement.
            if let tauri::RunEvent::Exit = event {
                #[cfg(not(target_os = "android"))]
                if let Some(s) = diag_host::sentinel() {
                    s.disarm();
                }
            }
        })
        .build()
}
