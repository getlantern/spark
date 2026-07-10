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
    menu::{
        CheckMenuItem, CheckMenuItemBuilder, Menu, MenuBuilder, MenuItem, MenuItemBuilder, Submenu,
        SubmenuBuilder,
    },
    tray::TrayIconBuilder,
    AppHandle, Emitter, Manager, Runtime,
};

/// Build the system tray from current state and register it + its handles. Called once from setup.
pub(crate) fn init<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<()> {
    let (status, servers, routing, adblock, selected) = read_state(app);
    let (menu, handles) = build_menu(app, &status, &servers, &routing, adblock, selected)?;
    app.manage(handles);

    // Hide the window to the tray on close instead of quitting — the VPN keeps running. The tray's
    // "Show Spark" reveals it again; "Quit Spark" is the only real exit.
    if let Some(win) = app.get_webview_window("main") {
        let win_for_event = win.clone();
        win.on_window_event(move |event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = win_for_event.hide();
            }
        });
    }

    let icon = tauri::include_image!("icons/tray.png");
    let builder = TrayIconBuilder::with_id("spark-tray")
        .icon(icon)
        .icon_as_template(true)
        .tooltip("Spark")
        .menu(&menu)
        .on_menu_event(on_menu_event);
    // Click convention differs by platform: macOS/Linux open the menu on left-click; Windows opens
    // the menu on right-click and reveals the window on left-click (the Windows tray convention).
    #[cfg(target_os = "windows")]
    let builder = builder
        .show_menu_on_left_click(false)
        .on_tray_icon_event(|tray, event| {
            if let tauri::tray::TrayIconEvent::Click {
                button: tauri::tray::MouseButton::Left,
                button_state: tauri::tray::MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        });
    #[cfg(not(target_os = "windows"))]
    let builder = builder.show_menu_on_left_click(true);
    builder.build(app)?;

    // Light poll so the tray reflects autonomous tunnel state changes (the NE/service connecting or
    // dropping on its own — no command fired). `refresh` is cheap and marshals menu updates to the
    // main thread itself, so a plain background thread is fine. ~1.5s balances freshness vs. cost.
    let poll_app = app.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_millis(1500));
        refresh(&poll_app);
    });

    Ok(())
}

/// Patch the tray's dynamic items in place from current control state. Cheap; safe to call often.
/// The location submenu is rebuilt only when the server pool actually changed.
pub(crate) fn refresh<R: Runtime>(app: &AppHandle<R>) {
    let handles = match app.try_state::<TrayHandles<R>>() {
        Some(h) => h,
        None => return, // tray not built yet
    };
    let (status, servers, routing, adblock, selected) = read_state(app);

    let _ = handles.header.set_text(header_text(&status.state));
    let (t_label, _t_id, t_enabled) = connect_item(&status.state);
    let _ = handles.toggle.set_text(t_label);
    let _ = handles.toggle.set_enabled(t_enabled);
    let _ = handles.routing_smart.set_checked(routing == "smart");
    let _ = handles.routing_full.set_checked(routing == "full");
    let _ = handles.adblock.set_checked(adblock);

    // Location check-marks: patch in place if the pool is unchanged, else rebuild the submenu's
    // children. Hold `pool_sig` across the whole rebuild so two concurrent refreshes (poll thread +
    // menu-event thread) can't both see "changed" and double-remove/append. Lock order is always
    // pool_sig → locations (never reversed), so no deadlock.
    let new_sig: Vec<String> = servers.iter().map(server_sig).collect();
    let mut sig = handles.pool_sig.lock().expect("sig lock");
    if *sig != new_sig {
        if let Ok(items) = build_location_items(app, &servers, selected) {
            let mut stored = handles.locations.lock().expect("loc lock");
            for (_, old) in stored.iter() {
                let _ = handles.location_submenu.remove(old); // CheckMenuItem: IsMenuItem
            }
            for (_, it) in &items {
                let _ = handles.location_submenu.append(it);
            }
            *stored = items;
            *sig = new_sig;
        }
    } else {
        for (pin, item) in handles.locations.lock().expect("loc lock").iter() {
            let _ = item.set_checked(*pin == selected);
        }
    }
}

/// Show + focus the main window.
fn show_main_window<R: Runtime>(app: &AppHandle<R>) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.show();
        let _ = win.set_focus();
    }
}

/// Menu-item handles kept so `refresh` can patch them in place instead of rebuilding the menu.
/// Managed as Tauri state. The location submenu items are rebuilt only when the server pool changes.
pub(crate) struct TrayHandles<R: Runtime> {
    pub header: MenuItem<R>,
    pub toggle: MenuItem<R>,
    pub routing_smart: CheckMenuItem<R>,
    pub routing_full: CheckMenuItem<R>,
    pub adblock: CheckMenuItem<R>,
    /// (pin, item) for each location entry incl. Smart (pin = None).
    pub locations: std::sync::Mutex<Vec<(Option<usize>, CheckMenuItem<R>)>>,
    /// Server pool signature (index+cc+city) used to detect when the submenu must be rebuilt.
    pub pool_sig: std::sync::Mutex<Vec<String>>,
    pub location_submenu: Submenu<R>,
}

/// A stable signature for one server, so we can tell when the pool actually changed.
fn server_sig(s: &crate::models::ServerInfo) -> String {
    format!(
        "{}|{}|{}",
        s.index,
        s.country_code.as_deref().unwrap_or(""),
        s.city.as_deref().unwrap_or("")
    )
}

/// Human label for a server: "🇦🇺 Australia — Melbourne" (flag omitted if no country code).
fn server_label(s: &crate::models::ServerInfo) -> String {
    let flag = s
        .country_code
        .as_deref()
        .map(flag_emoji)
        .unwrap_or_default();
    let country = s.country.as_deref().unwrap_or("Unknown");
    let mut label = if flag.is_empty() {
        country.to_string()
    } else {
        format!("{flag} {country}")
    };
    if let Some(city) = s.city.as_deref() {
        label.push_str(" — ");
        label.push_str(city);
    }
    label
}

/// Build the location check-items (Smart + one per server), `selected` marking the checked one.
fn build_location_items<R: Runtime>(
    app: &AppHandle<R>,
    servers: &[crate::models::ServerInfo],
    selected: Option<usize>,
) -> tauri::Result<Vec<(Option<usize>, CheckMenuItem<R>)>> {
    let mut items: Vec<(Option<usize>, CheckMenuItem<R>)> = Vec::with_capacity(servers.len() + 1);
    let smart = CheckMenuItemBuilder::with_id(loc_menu_id(None), "Smart Location")
        .checked(selected.is_none())
        .build(app)?;
    items.push((None, smart));
    for s in servers {
        let item = CheckMenuItemBuilder::with_id(loc_menu_id(Some(s.index)), server_label(s))
            .checked(selected == Some(s.index))
            .build(app)?;
        items.push((Some(s.index), item));
    }
    Ok(items)
}

/// Build the whole tray menu from current control state, returning the menu + the handle store.
fn build_menu<R: Runtime>(
    app: &AppHandle<R>,
    status: &crate::models::Status,
    servers: &[crate::models::ServerInfo],
    routing: &str,
    adblock: bool,
    selected: Option<usize>,
) -> tauri::Result<(Menu<R>, TrayHandles<R>)> {
    let header = MenuItemBuilder::with_id("header", header_text(&status.state))
        .enabled(false)
        .build(app)?;

    // Stable id: a muda MenuItem's id can't change after build, so `refresh` only updates the label/
    // enabled. The event handler (Task 6) branches on live status, not this id.
    let (t_label, _t_id, t_enabled) = connect_item(&status.state);
    let toggle = MenuItemBuilder::with_id("toggle", t_label)
        .enabled(t_enabled)
        .build(app)?;

    let locations = build_location_items(app, servers, selected)?;
    let mut loc_builder = SubmenuBuilder::with_id(app, "submenu-location", "Select Location");
    for (_, item) in &locations {
        loc_builder = loc_builder.item(item);
    }
    let location_submenu = loc_builder.build()?;
    let pool_sig: Vec<String> = servers.iter().map(server_sig).collect();

    let routing_smart = CheckMenuItemBuilder::with_id("routing:smart", "Smart")
        .checked(routing == "smart")
        .build(app)?;
    let routing_full = CheckMenuItemBuilder::with_id("routing:full", "Full")
        .checked(routing == "full")
        .build(app)?;
    let routing_submenu = SubmenuBuilder::with_id(app, "submenu-routing", "Routing Mode")
        .item(&routing_smart)
        .item(&routing_full)
        .build()?;

    let adblock_item = CheckMenuItemBuilder::with_id("adblock", "Ad Blocking")
        .checked(adblock)
        .build(app)?;
    let split = MenuItemBuilder::with_id("split", "Split Tunneling…").build(app)?;
    let show = MenuItemBuilder::with_id("show", "Show Spark").build(app)?;
    let quit = MenuItemBuilder::with_id("quit", "Quit Spark").build(app)?;

    let menu = MenuBuilder::new(app)
        .item(&header)
        .item(&toggle)
        .separator()
        .item(&location_submenu)
        .item(&routing_submenu)
        .item(&adblock_item)
        .item(&split)
        .separator()
        .item(&show)
        .item(&quit)
        .build()?;

    let handles = TrayHandles {
        header,
        toggle,
        routing_smart,
        routing_full,
        adblock: adblock_item,
        locations: std::sync::Mutex::new(locations),
        pool_sig: std::sync::Mutex::new(pool_sig),
        location_submenu,
    };
    Ok((menu, handles))
}

/// Read the current UI-relevant state from the control (best-effort; errors → sensible defaults).
fn read_state<R: Runtime>(
    app: &AppHandle<R>,
) -> (
    crate::models::Status,
    Vec<crate::models::ServerInfo>,
    String,
    bool,
    Option<usize>,
) {
    let ctl = app.state::<Box<dyn crate::TunnelControl>>();
    let status = ctl.status().unwrap_or(crate::models::Status {
        state: "disconnected".into(),
        protocol: String::new(),
        fail_open: false,
    });
    let servers = ctl.servers().unwrap_or_default();
    let routing = ctl.get_routing_mode().unwrap_or_else(|_| "smart".into());
    let adblock = ctl.get_ad_block_enabled().unwrap_or(true);
    let selected = *app
        .state::<crate::commands::SelectedServer>()
        .0
        .lock()
        .expect("pin lock");
    (status, servers, routing, adblock, selected)
}

/// Tray menu-event handler: run the corresponding control action, then refresh + notify the window.
/// Log a failed tray action and surface it to the window (a `spark://error` the UI can toast) so
/// tray-initiated failures aren't silent. The menu stays responsive regardless.
fn report_tray_action<R: Runtime>(app: &AppHandle<R>, action: &str, result: crate::Result<()>) {
    if let Err(e) = result {
        eprintln!("[spark-tray] {action} failed: {e}");
        let _ = app.emit("spark://error", format!("{action} failed: {e}"));
    }
}

fn on_menu_event<R: Runtime>(app: &AppHandle<R>, event: tauri::menu::MenuEvent) {
    let id = event.id().as_ref().to_string();
    let ctl = app.state::<Box<dyn crate::TunnelControl>>();

    match id.as_str() {
        // The toggle's id is stable ("toggle"); decide the action from live status, not the id
        // (a muda item's id can't change, so it can't encode connect-vs-disconnect).
        "toggle" => {
            let connected = ctl
                .status()
                .map(|s| s.state == "connected")
                .unwrap_or(false);
            if connected {
                report_tray_action(app, "disconnect", ctl.disconnect());
            } else {
                report_tray_action(app, "connect", ctl.connect());
            }
        }
        "routing:smart" => {
            report_tray_action(app, "set routing mode", ctl.set_routing_mode("smart"))
        }
        "routing:full" => report_tray_action(app, "set routing mode", ctl.set_routing_mode("full")),
        "adblock" => match ctl.get_ad_block_enabled() {
            Ok(enabled) => {
                report_tray_action(app, "set ad-block", ctl.set_ad_block_enabled(!enabled))
            }
            Err(e) => report_tray_action(app, "read ad-block", Err(e)),
        },
        "split" => {
            show_main_window(app);
            let _ = app.emit("spark://navigate", "/split-tunneling");
        }
        "show" => show_main_window(app),
        "quit" => {
            // Best-effort teardown; we're exiting regardless, so logging a failure adds no value.
            let _ = ctl.disconnect();
            app.exit(0);
            return;
        }
        other => {
            if let Some(pin) = parse_loc_menu_id(other) {
                let result = ctl.select_server(crate::tray_pin_to_i32(pin));
                // Only record the pin if the selection actually took, so the tray/window check-mark
                // can't drift from the live tunnel selection on a failed call.
                if result.is_ok() {
                    *app.state::<crate::commands::SelectedServer>()
                        .0
                        .lock()
                        .expect("pin lock") = pin;
                }
                report_tray_action(app, "select server", result);
            }
        }
    }

    refresh(app);
    let _ = app.emit("spark://state", ());
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
        // Out-of-range pin (can't happen with a real pool index) falls back to auto, never wraps.
        assert_eq!(crate::tray_pin_to_i32(Some(usize::MAX)), -1);
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
        assert_eq!(
            connect_item("connected"),
            ("Disconnect", "disconnect", true)
        );
        assert!(!connect_item("connecting").2);
    }
}
