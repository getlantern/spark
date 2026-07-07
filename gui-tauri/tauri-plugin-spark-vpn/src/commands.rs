use tauri::{AppHandle, Manager, Runtime};

use crate::control::TunnelControl;
use crate::models::{ServerInfo, Status};

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
    app.state::<Ctl>().select_server(index)
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
