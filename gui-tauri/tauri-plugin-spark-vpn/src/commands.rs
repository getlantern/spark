use std::sync::Mutex;

use tauri::{AppHandle, Manager, Runtime};

use crate::control::TunnelControl;
use crate::models::{ServerInfo, Status};

/// The user's selected-location pin, shared between the window and the tray. `None` = Smart/auto,
/// `Some(i)` = a pinned pool index. Promoted here from frontend-ephemeral state so the tray can
/// read it (and so it survives a UI reload). Managed as Tauri state in `lib.rs`.
#[derive(Default)]
pub(crate) struct SelectedServer(pub Mutex<Option<usize>>);

type Ctl = Box<dyn TunnelControl>;

#[tauri::command]
pub(crate) async fn connect<R: Runtime>(app: AppHandle<R>) -> crate::Result<()> {
    app.state::<Ctl>().connect()?;
    #[cfg(desktop)]
    crate::tray::refresh(&app);
    Ok(())
}

#[tauri::command]
pub(crate) async fn disconnect<R: Runtime>(app: AppHandle<R>) -> crate::Result<()> {
    app.state::<Ctl>().disconnect()?;
    #[cfg(desktop)]
    crate::tray::refresh(&app);
    // Fetching comes back to the app now that the tunnel is down. Refresh so the list the user sees
    // while disconnected is the app's own current one, rather than whatever the NE last published
    // before it stopped — the two are independent assignments and the NE's is now stale by
    // definition. Detached: a failure leaves the cached list intact, exactly as at startup.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    resume_app_fetching(&app);
    Ok(())
}

/// Re-take config fetching after the tunnel goes down.
///
/// Spawned rather than awaited because `disconnect()` only *requests* the stop: the status can
/// still read `connected` for a moment after it returns, and a fetch issued in that window would
/// see the tunnel as the owner and skip — leaving the list frozen at the NE's last one. The poll
/// waits out that window instead of guessing a delay. It does not wait for teardown to finish:
/// `disconnecting` already reads as `disconnected` (`ui_state`), and fetching alongside a tunnel
/// that is on its way down is harmless — it will not refresh again.
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn resume_app_fetching<R: Runtime>(app: &AppHandle<R>) {
    use tauri::Emitter;

    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        // Bounded: if the tunnel is somehow still up after 5s, skip rather than fetch under it.
        // The next app start or disconnect refreshes, so the cost of skipping is a stale list, not
        // a wrong one.
        for _ in 0..10 {
            if crate::config_fetch::app_owns_fetching() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        if !crate::config_fetch::app_owns_fetching() {
            return;
        }
        let Ok(base) = handle.path().app_config_dir() else {
            return;
        };
        let dir = crate::desktop::app_config_cache_dir(&base);
        let _ = std::fs::create_dir_all(&dir);
        match crate::config_fetch::fetch_into_cache(&dir).await {
            Ok(true) => {
                let _ = handle.emit("spark://servers", ());
            }
            Ok(false) => {}
            Err(e) => eprintln!("[spark-vpn] post-disconnect config fetch failed: {e}"),
        }
    });
}

#[tauri::command]
pub(crate) async fn status<R: Runtime>(app: AppHandle<R>) -> crate::Result<Status> {
    app.state::<Ctl>().status()
}

#[tauri::command]
pub(crate) async fn servers<R: Runtime>(app: AppHandle<R>) -> crate::Result<Vec<ServerInfo>> {
    let list = app.state::<Ctl>().servers()?;
    sync_pin_from_snapshot(&app, &list);
    Ok(list)
}

/// Re-point [`SelectedServer`] at the pin's current index, from the tunnel's own snapshot.
///
/// The cache holds an INDEX, and an index only means anything within one config generation: a refresh
/// can reorder members, after which the cached index names a *different* server — which is how the UI
/// came to show a location the tunnel wasn't using. The tunnel tracks the pin by identity and carries it
/// across a refresh, so `is_pinned` is where that server ended up.
///
/// Absence of a pin deliberately does NOT clear the cache — matching `$lib/selection`, which owns the
/// same policy on the window side, so the tray and the window can't disagree. It is ambiguous (auto, or
/// a pick the tunnel hasn't taken up yet, which the window re-pushes), and pre-connect lists never
/// carry a pin at all.
pub(crate) fn sync_pin_from_snapshot<R: Runtime>(app: &AppHandle<R>, servers: &[ServerInfo]) {
    if let Some(pin) = pin_from_snapshot(servers) {
        *app.state::<SelectedServer>().0.lock().expect("pin lock") = Some(pin);
    }
}

/// The pin a snapshot implies, or `None` to leave the cache as it stands. Split out from
/// [`sync_pin_from_snapshot`] so the leave-it-alone policy is testable without a Tauri app handle.
fn pin_from_snapshot(servers: &[ServerInfo]) -> Option<usize> {
    servers.iter().find(|s| s.is_pinned).map(|s| s.index)
}

#[tauri::command]
pub(crate) async fn select_server<R: Runtime>(app: AppHandle<R>, index: i32) -> crate::Result<()> {
    app.state::<Ctl>().select_server(index)?;
    *app.state::<SelectedServer>().0.lock().expect("pin lock") = crate::tray_pin(index);
    #[cfg(desktop)]
    crate::tray::refresh(&app);
    Ok(())
}

/// The current selected-location pin as an i32 (-1 = Smart/auto). Read by the window on load and by
/// the tray so both render the same selection.
#[tauri::command]
pub(crate) async fn get_selected_server<R: Runtime>(app: AppHandle<R>) -> crate::Result<i32> {
    let pin = *app.state::<SelectedServer>().0.lock().expect("pin lock");
    Ok(crate::tray_pin_to_i32(pin))
}

#[tauri::command]
pub(crate) async fn get_split_tunnel<R: Runtime>(app: AppHandle<R>) -> crate::Result<String> {
    app.state::<Ctl>().get_split_tunnel()
}

#[tauri::command]
pub(crate) async fn set_split_tunnel<R: Runtime>(
    app: AppHandle<R>,
    json: String,
) -> crate::Result<()> {
    app.state::<Ctl>().set_split_tunnel(&json)
}

#[tauri::command]
pub(crate) async fn get_routing_mode<R: Runtime>(app: AppHandle<R>) -> crate::Result<String> {
    app.state::<Ctl>().get_routing_mode()
}

#[tauri::command]
pub(crate) async fn set_routing_mode<R: Runtime>(
    app: AppHandle<R>,
    mode: String,
) -> crate::Result<()> {
    app.state::<Ctl>().set_routing_mode(&mode)?;
    #[cfg(desktop)]
    crate::tray::refresh(&app);
    Ok(())
}

#[tauri::command]
pub(crate) async fn get_ad_block_enabled<R: Runtime>(app: AppHandle<R>) -> crate::Result<bool> {
    app.state::<Ctl>().get_ad_block_enabled()
}

#[tauri::command]
pub(crate) async fn set_ad_block_enabled<R: Runtime>(
    app: AppHandle<R>,
    enabled: bool,
) -> crate::Result<()> {
    app.state::<Ctl>().set_ad_block_enabled(enabled)?;
    #[cfg(desktop)]
    crate::tray::refresh(&app);
    Ok(())
}

#[tauri::command]
pub(crate) async fn list_installed_apps<R: Runtime>(app: AppHandle<R>) -> crate::Result<String> {
    app.state::<Ctl>().list_installed_apps()
}

#[tauri::command]
pub(crate) async fn get_excluded_apps<R: Runtime>(app: AppHandle<R>) -> crate::Result<String> {
    app.state::<Ctl>().get_excluded_apps()
}

#[tauri::command]
pub(crate) async fn set_excluded_apps<R: Runtime>(
    app: AppHandle<R>,
    json: String,
) -> crate::Result<()> {
    app.state::<Ctl>().set_excluded_apps(&json)
}

#[cfg(test)]
mod tests {
    use super::{pin_from_snapshot, SelectedServer};
    use crate::models::ServerInfo;

    #[test]
    fn selected_server_defaults_to_auto() {
        let s = SelectedServer::default();
        assert_eq!(*s.0.lock().unwrap(), None);
    }

    fn member(index: usize, is_current: bool, is_pinned: bool) -> ServerInfo {
        ServerInfo {
            index,
            name: None,
            country: None,
            country_code: None,
            city: None,
            protocol: None,
            latency_ms: None,
            healthy: true,
            is_current,
            is_pinned,
        }
    }

    #[test]
    fn pin_follows_the_snapshot_to_its_new_index() {
        // The whole point: the pinned server moved to index 2 after a config refresh, so the cached
        // index must move with it rather than keep naming whatever now sits in the old slot.
        let snap = [
            member(0, false, false),
            member(1, false, false),
            member(2, true, true),
        ];
        assert_eq!(pin_from_snapshot(&snap), Some(2));
    }

    #[test]
    fn no_pin_in_the_snapshot_leaves_the_cache_alone() {
        // Both an auto tunnel and a pre-connect list look like this, and one of them (a pick the tunnel
        // hasn't taken up yet) is an intent worth keeping — so this must not read as "clear the pin".
        let live_on_auto = [member(0, true, false), member(1, false, false)];
        assert_eq!(pin_from_snapshot(&live_on_auto), None);
        assert_eq!(pin_from_snapshot(&[]), None);
    }
}
