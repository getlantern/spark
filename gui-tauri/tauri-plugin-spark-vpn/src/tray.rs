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

/// The disabled status line for Unbounded (volunteer proxy): "Unbounded: off" when disabled,
/// "Unbounded: helping N" when enabled (N = peers currently helped, may be 0).
pub(crate) fn unbounded_tray_label(enabled: bool, helping_now: usize) -> String {
    if !enabled {
        "Unbounded: off".to_string()
    } else {
        format!("Unbounded: helping {helping_now}")
    }
}

/// Status line gated on server availability: "Unbounded: unavailable" when the server gate
/// (`features.unbounded`) is off — otherwise the normal enabled/off/helping label. The tray toggle is
/// also disabled when unavailable, so a user can't interact with Unbounded that the server hasn't
/// enabled for this client. (With [`unbounded_tray_visible`] the items are normally absent rather than
/// shown as "unavailable"; this stays the label for the window between the tray being built and the
/// first config read resolving availability.)
pub(crate) fn unbounded_status_text(available: bool, enabled: bool, helping_now: usize) -> String {
    if !available {
        "Unbounded: unavailable".to_string()
    } else {
        unbounded_tray_label(enabled, helping_now)
    }
}

/// Whether the tray surfaces its Unbounded items at all.
///
/// Deliberately the same condition as the tab — `unboundedVisible(serverEnabled, hidden)` in
/// `gui-tauri/src/lib/unbounded.ts` — so "Hide Unbounded" means hidden *everywhere*, not just in the
/// window. Both inputs default false, so an unknown server gate keeps the items out of the menu.
///
/// Note hiding is presentational only: it never stops a running pool. A volunteer who hides the
/// feature while sharing keeps sharing, and the Settings → Unbounded row stays reachable so the
/// choice is reversible.
///
/// `hidden` is a closure, not a bool, because reading that preference touches the disk and this is
/// evaluated on the 1.5s tray poll: taking it eagerly meant a file read every poll for every user
/// whose server gate is off (the common case). `&&` short-circuits, so it's only consulted when the
/// feature is available at all.
pub(crate) fn unbounded_tray_visible(available: bool, hidden: impl FnOnce() -> bool) -> bool {
    available && !hidden()
}

/// The disabled top-of-menu header: connection status plus the selected location. A manual pin
/// (`Some(index)`) shows that server's label; `None` is "Smart Location" — Spark auto-choosing —
/// which is never shown for a manually picked location.
fn header_label(
    status: &crate::models::Status,
    servers: &[crate::models::ServerInfo],
    selected: Option<usize>,
) -> String {
    let location = match selected {
        Some(i) => servers
            .iter()
            .find(|s| s.index == i)
            .map(server_label)
            .unwrap_or_else(|| "Selected location".to_string()),
        None => "Smart Location".to_string(),
    };
    format!("{} · {}", header_text(&status.state), location)
}

use tauri::{
    menu::{
        CheckMenuItem, CheckMenuItemBuilder, Menu, MenuBuilder, MenuItem, MenuItemBuilder, Submenu,
        SubmenuBuilder,
    },
    tray::TrayIconBuilder,
    AppHandle, Emitter, Manager, Runtime,
};

/// Menu id for the Unbounded enable/disable toggle. The status line above it is a disabled
/// (non-clickable) text item, so it needs no id.
const MENU_UNBOUNDED_TOGGLE: &str = "unbounded_toggle";

/// Menu index the Unbounded block sits at: separator, status line, toggle. Ties to `build_menu`'s
/// fixed prefix — header, connect toggle, separator, Location, Routing, Ad Blocking, Split Tunneling
/// — so keep the two in step if that prefix ever changes.
const UNBOUNDED_BLOCK_AT: usize = 7;

/// Toggle label for the Unbounded enable/disable item, given the current enabled state.
pub(crate) fn unbounded_toggle_label(enabled: bool) -> &'static str {
    if enabled {
        "Disable Unbounded"
    } else {
        "Enable Unbounded"
    }
}

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

    let _ = handles
        .header
        .set_text(header_label(&status, &servers, selected));
    let (t_label, _t_id, t_enabled) = connect_item(&status.state);
    let _ = handles.toggle.set_text(t_label);
    let _ = handles.toggle.set_enabled(t_enabled);
    let _ = handles.routing_smart.set_checked(routing == "smart");
    let _ = handles.routing_full.set_checked(routing == "full");
    let _ = handles.adblock.set_checked(adblock);

    // Re-gate Unbounded on server availability, and take the status line from LIVE state (is a pool
    // running, how many peers) rather than the persisted flag — that is what keeps the line honest
    // between peer deltas. It previously changed only at menu build and on join/leave, so a running
    // volunteer with no peer yet showed "Unbounded: off" directly above "Disable Unbounded".
    let ub_available = crate::unbounded::unbounded_available_sync(app);
    let (ub_running, ub_helping) = crate::unbounded::live_view(app);

    // Show/hide the whole block on a transition. muda items have no `set_visible`, so this
    // inserts/removes them — and only when the desired state actually changed, since this runs on the
    // 1.5s poll. Availability arrives after the first config read and "Hide Unbounded" is a settings
    // toggle, so both directions take effect live, with no restart.
    let want_shown = unbounded_tray_visible(ub_available, || read_unbounded_hidden(app));
    {
        let mut shown = handles
            .unbounded_shown
            .lock()
            .expect("unbounded_shown lock");
        if *shown != want_shown {
            // Clear the block first, in reverse order so an earlier removal can't shift the ones still
            // to go. Errors are ignored HERE on purpose: the items may legitimately not be in the menu,
            // and starting from "known absent" makes the whole reconcile idempotent — so a retry after
            // a partial failure re-inserts cleanly instead of duplicating items.
            let _ = handles.menu.remove(&handles.unbounded_toggle);
            let _ = handles.menu.remove(&handles.unbounded_status);
            let _ = handles.menu.remove(&handles.unbounded_sep);

            let applied = if want_shown {
                handles
                    .menu
                    .insert(&handles.unbounded_sep, UNBOUNDED_BLOCK_AT)
                    .and_then(|()| {
                        handles
                            .menu
                            .insert(&handles.unbounded_status, UNBOUNDED_BLOCK_AT + 1)
                    })
                    .and_then(|()| {
                        handles
                            .menu
                            .insert(&handles.unbounded_toggle, UNBOUNDED_BLOCK_AT + 2)
                    })
            } else {
                // Hiding IS the removals above. A failed remove almost certainly means the item was
                // already gone, which is the state we wanted.
                Ok(())
            };
            match applied {
                // Commit only on success. Flipping the flag regardless would desync it from the real
                // menu and stop every later refresh from reconciling — leaving the menu wrong for the
                // rest of the run. Left unflipped, the ~1.5s poll simply retries.
                Ok(()) => *shown = want_shown,
                Err(e) => tracing::warn!(
                    error = %e,
                    want_shown,
                    "tray: could not apply Unbounded visibility; will retry on the next refresh"
                ),
            }
        }
    }

    // Patching text/enabled is harmless while the block is out of the menu, so it stays unconditional.
    let _ = handles.unbounded_toggle.set_enabled(ub_available);
    let _ = handles
        .unbounded_toggle
        .set_text(unbounded_toggle_label(ub_running));
    let _ = handles.unbounded_status.set_text(unbounded_status_text(
        ub_available,
        ub_running,
        ub_helping,
    ));

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
    /// Disabled status line showing `unbounded_tray_label(...)`.
    pub unbounded_status: MenuItem<R>,
    /// Enable/disable toggle, label from `unbounded_toggle_label(...)`.
    pub unbounded_toggle: MenuItem<R>,
    /// The separator that leads the Unbounded block. Held because hiding the block removes this too —
    /// otherwise hiding would leave two adjacent separators in the menu.
    pub unbounded_sep: tauri::menu::PredefinedMenuItem<R>,
    /// Whether the Unbounded block is currently IN the menu. muda menu items have no `set_visible`
    /// (only `set_enabled`), so showing/hiding means inserting/removing them — and that must only
    /// happen on an actual transition, not on every 1.5s poll.
    pub unbounded_shown: std::sync::Mutex<bool>,
    /// The tray menu itself, needed for those inserts/removes.
    pub menu: Menu<R>,
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
    let header = MenuItemBuilder::with_id("header", header_label(status, servers, selected))
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

    // Unbounded (volunteer proxy): a disabled status line + an enable/disable toggle. The toggle's
    // action is decided from the live persisted state in the handler, not this id.
    let (ub_enabled, ub_helping) = read_unbounded_state(app);
    let ub_available = crate::unbounded::unbounded_available_sync(app);
    let unbounded_status = MenuItemBuilder::with_id(
        "unbounded_status",
        unbounded_status_text(ub_available, ub_enabled, ub_helping),
    )
    .enabled(false)
    .build(app)?;
    // Disabled when the server hasn't gated Unbounded on for this client (Copilot #90): the toggle
    // must not be interactive for a feature that isn't available to this client.
    let unbounded_toggle =
        MenuItemBuilder::with_id(MENU_UNBOUNDED_TOGGLE, unbounded_toggle_label(ub_enabled))
            .enabled(ub_available)
            .build(app)?;
    // Built whether or not it's shown, so a later un-hide can insert the same handles.
    let unbounded_sep = tauri::menu::PredefinedMenuItem::separator(app)?;
    let ub_shown = unbounded_tray_visible(ub_available, || read_unbounded_hidden(app));

    let show = MenuItemBuilder::with_id("show", "Show Spark").build(app)?;
    let quit = MenuItemBuilder::with_id("quit", "Quit Spark").build(app)?;

    // The Unbounded block (its leading separator + the two items) is included only when it should be
    // visible; `refresh` inserts/removes it at UNBOUNDED_BLOCK_AT on a transition. Either way exactly
    // one separator sits above Show/Quit.
    let mut builder = MenuBuilder::new(app)
        .item(&header)
        .item(&toggle)
        .separator()
        .item(&location_submenu)
        .item(&routing_submenu)
        .item(&adblock_item)
        .item(&split);
    if ub_shown {
        builder = builder
            .item(&unbounded_sep)
            .item(&unbounded_status)
            .item(&unbounded_toggle);
    }
    let menu = builder.separator().item(&show).item(&quit).build()?;

    let handles = TrayHandles {
        header,
        toggle,
        routing_smart,
        routing_full,
        adblock: adblock_item,
        unbounded_status,
        unbounded_toggle,
        unbounded_sep,
        unbounded_shown: std::sync::Mutex::new(ub_shown),
        menu: menu.clone(),
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
    // Resync before reading the pin: the tray calls the control directly rather than going through
    // the `servers` command, so without this it would keep rendering ✓ against a stale index.
    crate::commands::sync_pin_from_snapshot(app, &servers);
    let selected = *app
        .state::<crate::commands::SelectedServer>()
        .0
        .lock()
        .expect("pin lock");
    (status, servers, routing, adblock, selected)
}

/// Read the current Unbounded state for building the tray: `(enabled, helping_now)`. `enabled` comes
/// from the persisted opt-in flag; `helping_now` is 0 at build time (no pool has started yet — the
/// live count arrives later via `refresh_unbounded_label` from `emit_snapshot`). Best-effort: a
/// missing config dir yields `(false, 0)`.
fn read_unbounded_state<R: Runtime>(app: &AppHandle<R>) -> (bool, usize) {
    let enabled = match app.path().app_config_dir() {
        Ok(base) => crate::persist::load_unbounded_enabled(&base),
        Err(_) => false,
    };
    (enabled, 0)
}

/// The persisted "Hide Unbounded" preference. Unreadable config dir → not hidden (the server gate in
/// [`unbounded_tray_visible`] is what fails closed).
fn read_unbounded_hidden<R: Runtime>(app: &AppHandle<R>) -> bool {
    match app.path().app_config_dir() {
        Ok(base) => crate::persist::load_unbounded_hidden(&base),
        Err(_) => false,
    }
}

/// Patch the Unbounded status line + toggle label in place from `(enabled, helping_now)`. Called
/// from `unbounded::emit_snapshot` after each pool change, and from the tray's own event handler.
/// Mirrors `refresh`: cheap, safe to call often, and a no-op if the tray isn't built yet.
pub(crate) fn refresh_unbounded_label<R: Runtime>(
    app: &AppHandle<R>,
    enabled: bool,
    helping_now: usize,
) {
    let handles = match app.try_state::<TrayHandles<R>>() {
        Some(h) => h,
        None => return, // tray not built yet
    };
    let available = crate::unbounded::unbounded_available_sync(app);
    let _ =
        handles
            .unbounded_status
            .set_text(unbounded_status_text(available, enabled, helping_now));
    let _ = handles
        .unbounded_toggle
        .set_text(unbounded_toggle_label(enabled));
    let _ = handles.unbounded_toggle.set_enabled(available);
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

    // Window / exit actions involve no blocking IPC — run them promptly on the current (main) thread.
    match id.as_str() {
        "show" => {
            show_main_window(app);
            return;
        }
        "split" => {
            show_main_window(app);
            let _ = app.emit("spark://navigate", "/split-tunneling");
            return;
        }
        "quit" => {
            // Best-effort teardown; we're exiting regardless, so a failure needs no logging.
            let _ = app.state::<Box<dyn crate::TunnelControl>>().disconnect();
            app.exit(0);
            return;
        }
        _ => {}
    }

    // Optimistically move the location check-mark on click so the menu feels instant; the off-thread
    // work below reconciles it (and a later `refresh` reverts it if the selection call fails).
    if let Some(pin) = parse_loc_menu_id(&id) {
        if let Some(h) = app.try_state::<TrayHandles<R>>() {
            for (p, item) in h.locations.lock().expect("loc lock").iter() {
                let _ = item.set_checked(*p == pin);
            }
        }
    }

    // Everything else hits the control (blocking IPC). Run it off the main thread so the menu /
    // event loop doesn't stall — the synchronous IPC here caused the click-to-switch hiccup.
    // `refresh` and the menu setters marshal back to the main thread internally.
    let app = app.clone();
    std::thread::spawn(move || {
        let ctl = app.state::<Box<dyn crate::TunnelControl>>();
        match id.as_str() {
            // Stable id "toggle": decide the action from live status, not the id (a muda item's id
            // can't change, so it can't encode connect-vs-disconnect).
            "toggle" => {
                let connected = ctl
                    .status()
                    .map(|s| s.state == "connected")
                    .unwrap_or(false);
                if connected {
                    report_tray_action(&app, "disconnect", ctl.disconnect());
                } else {
                    report_tray_action(&app, "connect", ctl.connect());
                }
            }
            "routing:smart" => {
                report_tray_action(&app, "set routing mode", ctl.set_routing_mode("smart"))
            }
            "routing:full" => {
                report_tray_action(&app, "set routing mode", ctl.set_routing_mode("full"))
            }
            "adblock" => match ctl.get_ad_block_enabled() {
                Ok(enabled) => {
                    report_tray_action(&app, "set ad-block", ctl.set_ad_block_enabled(!enabled))
                }
                Err(e) => report_tray_action(&app, "read ad-block", Err(e)),
            },
            MENU_UNBOUNDED_TOGGLE => {
                // Unbounded start/stop are async commands; dispatch them on the async runtime
                // rather than blocking this worker thread. Decide the action from the persisted
                // enabled flag. `emit_snapshot` refreshes the tray label once the command settles.
                let toggle_app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let enabled = match toggle_app.path().app_config_dir() {
                        Ok(base) => crate::persist::load_unbounded_enabled(&base),
                        Err(e) => {
                            eprintln!("[spark-tray] unbounded toggle: no config dir: {e}");
                            return;
                        }
                    };
                    let result = if enabled {
                        crate::unbounded::unbounded_stop(toggle_app.clone()).await
                    } else {
                        crate::unbounded::unbounded_start(toggle_app.clone()).await
                    };
                    report_tray_action(&toggle_app, "toggle unbounded", result);
                });
            }
            other => {
                if let Some(pin) = parse_loc_menu_id(other) {
                    let result = ctl.select_server(crate::tray_pin_to_i32(pin));
                    // Only record the pin if the selection took, so the tray/window check-mark can't
                    // drift from the live tunnel selection on a failed call.
                    if result.is_ok() {
                        *app.state::<crate::commands::SelectedServer>()
                            .0
                            .lock()
                            .expect("pin lock") = pin;
                    }
                    report_tray_action(&app, "select server", result);
                }
            }
        }
        refresh(&app);
        let _ = app.emit("spark://state", ());
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirrors `unboundedVisible`'s test in gui-tauri/src/lib/unbounded.ts — the tray and the tab must
    /// agree, so "Hide Unbounded" hides it everywhere.
    #[test]
    fn unbounded_tray_shows_only_when_available_and_not_hidden() {
        assert!(unbounded_tray_visible(true, || false));
        assert!(!unbounded_tray_visible(true, || true), "hidden wins");
        assert!(
            !unbounded_tray_visible(false, || false),
            "server gate off ⇒ nothing surfaced"
        );
        assert!(!unbounded_tray_visible(false, || true));

        // Reading the hidden preference touches the disk, and this runs on the 1.5s tray poll — so it
        // must not be consulted at all when the feature isn't available (the common case).
        let mut consulted = false;
        assert!(!unbounded_tray_visible(false, || {
            consulted = true;
            false
        }));
        assert!(
            !consulted,
            "hidden must not be read when the feature is unavailable"
        );
    }

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
    fn unbounded_tray_label_reflects_state() {
        assert_eq!(unbounded_tray_label(false, 0), "Unbounded: off");
        assert_eq!(unbounded_tray_label(true, 9), "Unbounded: helping 9");
        assert_eq!(unbounded_tray_label(true, 0), "Unbounded: helping 0");
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

    fn status(state: &str) -> crate::models::Status {
        crate::models::Status {
            state: state.into(),
            protocol: String::new(),
            fail_open: false,
        }
    }

    #[test]
    fn header_label_distinguishes_smart_from_manual() {
        // No pin → Spark auto-choosing ("Smart Location").
        assert_eq!(
            header_label(&status("disconnected"), &[], None),
            "Disconnected · Smart Location"
        );
        // A manual pin shows that location — never "Smart Location".
        let s = crate::models::ServerInfo {
            index: 2,
            name: None,
            country: Some("U.S.A.".into()),
            country_code: Some("US".into()),
            city: Some("Ashburn".into()),
            protocol: None,
            latency_ms: None,
            healthy: true,
            is_current: false,
            is_pinned: true,
        };
        let label = header_label(&status("connected"), &[s], Some(2));
        assert_eq!(label, "Connected · 🇺🇸 U.S.A. — Ashburn");
        assert!(!label.contains("Smart"));
    }
}
