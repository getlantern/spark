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
    app.state::<Ctl>().connect()
}

#[tauri::command]
pub(crate) async fn disconnect<R: Runtime>(app: AppHandle<R>) -> crate::Result<()> {
    app.state::<Ctl>().disconnect()
}

#[tauri::command]
pub(crate) async fn status<R: Runtime>(app: AppHandle<R>) -> crate::Result<Status> {
    app.state::<Ctl>().status()
}

#[tauri::command]
pub(crate) async fn servers<R: Runtime>(app: AppHandle<R>) -> crate::Result<Vec<ServerInfo>> {
    app.state::<Ctl>().servers()
}

#[tauri::command]
pub(crate) async fn select_server<R: Runtime>(app: AppHandle<R>, index: i32) -> crate::Result<()> {
    app.state::<Ctl>().select_server(index)?;
    *app.state::<SelectedServer>().0.lock().expect("pin lock") = crate::tray_pin(index);
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
    app.state::<Ctl>().set_routing_mode(&mode)
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
    app.state::<Ctl>().set_ad_block_enabled(enabled)
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
    use super::SelectedServer;

    #[test]
    fn selected_server_defaults_to_auto() {
        let s = SelectedServer::default();
        assert_eq!(*s.0.lock().unwrap(), None);
    }
}
