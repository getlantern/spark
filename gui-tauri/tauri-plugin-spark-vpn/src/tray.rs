//! Desktop system tray for the Spark VPN plugin (macOS menu bar / Windows + Linux tray).
//! Drives the same `TunnelControl` as the window; see
//! docs/superpowers/specs/2026-07-10-desktop-system-tray-design.md.
#![cfg(desktop)]

/// Map a 2-letter ISO 3166-1 alpha-2 country code to its Unicode flag emoji (two regional
/// indicator symbols). Returns "" for anything that isn't exactly two ASCII letters.
pub(crate) fn flag_emoji(cc: &str) -> String {
    let cc = cc.trim();
    let bytes = cc.as_bytes();
    if bytes.len() != 2 || !bytes.iter().all(u8::is_ascii_alphabetic) {
        return String::new();
    }
    bytes
        .iter()
        .filter_map(|b| char::from_u32(0x1F1E6 + u32::from(b.to_ascii_uppercase() - b'A')))
        .collect()
}

/// Menu id for a location item. `None` → Smart/auto.
pub(crate) fn loc_menu_id(index: Option<usize>) -> String {
    match index {
        Some(i) => format!("loc:{i}"),
        None => "loc:smart".to_string(),
    }
}

/// Parse a `loc:*` menu id back to a pin. `Some(None)` = smart, `Some(Some(i))` = pinned index,
/// `None` = not a location id.
pub(crate) fn parse_loc_menu_id(id: &str) -> Option<Option<usize>> {
    if id == "loc:smart" {
        return Some(None);
    }
    id.strip_prefix("loc:")
        .and_then(|s| s.parse::<usize>().ok())
        .map(Some)
}

/// Status-header text for a `Status.state` value.
pub(crate) fn header_text(state: &str) -> &'static str {
    match state {
        "connected" => "Connected",
        "connecting" => "Connecting…",
        "disconnecting" => "Disconnecting…",
        _ => "Disconnected",
    }
}

/// (label, menu-id, enabled) for the Connect/Disconnect toggle, from `Status.state`.
pub(crate) fn connect_item(state: &str) -> (&'static str, &'static str, bool) {
    match state {
        "connected" => ("Disconnect", "disconnect", true),
        "connecting" => ("Connecting…", "connect", false),
        "disconnecting" => ("Disconnecting…", "disconnect", false),
        _ => ("Connect", "connect", true),
    }
}

use tauri::{
    menu::{MenuBuilder, MenuItemBuilder},
    tray::TrayIconBuilder,
    AppHandle, Manager, Runtime,
};

/// Build the system tray and register it. Called once from the plugin `.setup()`.
pub(crate) fn init<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<()> {
    let show = MenuItemBuilder::with_id("show", "Show Spark").build(app)?;
    let quit = MenuItemBuilder::with_id("quit", "Quit Spark").build(app)?;
    let menu = MenuBuilder::new(app).item(&show).item(&quit).build()?;

    let icon = tauri::include_image!("icons/tray.png");
    TrayIconBuilder::with_id("spark-tray")
        .icon(icon)
        .icon_as_template(true) // macOS: adapt to light/dark menu bar; ignored elsewhere
        .tooltip("Spark")
        .menu(&menu)
        .show_menu_on_left_click(true)
        .on_menu_event(move |app, event| match event.id().as_ref() {
            "show" => show_main_window(app),
            "quit" => {
                let _ = app.state::<Box<dyn crate::TunnelControl>>().disconnect();
                app.exit(0);
            }
            _ => {}
        })
        .build(app)?;
    Ok(())
}

/// Show + focus the main window.
fn show_main_window<R: Runtime>(app: &AppHandle<R>) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.show();
        let _ = win.set_focus();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_emoji_maps_valid_two_letter_codes() {
        assert_eq!(flag_emoji("US"), "🇺🇸");
        assert_eq!(flag_emoji("au"), "🇦🇺");
        assert_eq!(flag_emoji(" GB "), "🇬🇧");
    }

    #[test]
    fn flag_emoji_rejects_bad_codes() {
        assert_eq!(flag_emoji("USA"), "");
        assert_eq!(flag_emoji(""), "");
        assert_eq!(flag_emoji("1A"), "");
        assert_eq!(flag_emoji("U"), "");
    }

    #[test]
    fn pin_round_trips_through_i32() {
        assert_eq!(crate::tray_pin(-1), None);
        assert_eq!(crate::tray_pin(0), Some(0));
        assert_eq!(crate::tray_pin(5), Some(5));
        assert_eq!(crate::tray_pin_to_i32(None), -1);
        assert_eq!(crate::tray_pin_to_i32(Some(5)), 5);
    }

    #[test]
    fn loc_menu_id_round_trips() {
        assert_eq!(loc_menu_id(None), "loc:smart");
        assert_eq!(loc_menu_id(Some(3)), "loc:3");
        assert_eq!(parse_loc_menu_id("loc:smart"), Some(None));
        assert_eq!(parse_loc_menu_id("loc:3"), Some(Some(3)));
        assert_eq!(parse_loc_menu_id("routing:full"), None);
        assert_eq!(parse_loc_menu_id("loc:x"), None);
    }

    #[test]
    fn header_and_connect_item_track_state() {
        assert_eq!(header_text("connected"), "Connected");
        assert_eq!(header_text("disconnected"), "Disconnected");
        assert_eq!(header_text("weird"), "Disconnected");
        assert_eq!(connect_item("disconnected"), ("Connect", "connect", true));
        assert_eq!(connect_item("connected"), ("Disconnect", "disconnect", true));
        assert_eq!(connect_item("connecting").2, false);
    }
}
