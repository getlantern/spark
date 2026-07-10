# Desktop System Tray Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a macOS/Windows/Linux system-tray menu to the Spark Tauri app that reflects and drives the same VPN state as the SvelteKit window (status, selected location, routing mode, ad-block).

**Architecture:** A `#[cfg(desktop)]` `tray.rs` module inside `tauri-plugin-spark-vpn`, initialized from the plugin's `.setup()`. It drives the existing `TunnelControl` (the single source of truth) and reuses `ServerInfo`/`Status`. Tray ↔ window consistency (approach A): a `refresh_tray` patches menu items in place, driven by (1) tray actions, (2) a notify hook on state-mutating commands that also emits a `spark://state` event to the window, and (3) a light ~1.5 s status poll for autonomous connect/drop. The selected-location pin is promoted from frontend-ephemeral state to plugin-held shared state so the tray can read it.

**Tech Stack:** Rust, Tauri v2 (2.11.x) `TrayIcon`/menu API, SvelteKit/TypeScript frontend.

**Spec:** `docs/superpowers/specs/2026-07-10-desktop-system-tray-design.md`
**Branch:** `fisk/desktop-tray`

**Verified facts (do not re-derive):**
- Plugin crate root: `gui-tauri/tauri-plugin-spark-vpn/` (its own `[workspace]`; built as a path dep of `gui-tauri/src-tauri`).
- `TunnelControl` (`src/control.rs`): `connect/disconnect/status/servers/select_server(i32)/get_routing_mode/set_routing_mode/get_ad_block_enabled/set_ad_block_enabled`. `crate::Result<T>` = `Result<T, crate::Error>`.
- `ServerInfo` (`src/models.rs`): `index: usize`, `country: Option<String>`, `country_code: Option<String>`, `city: Option<String>`, `is_current: bool`, `healthy: bool`. `Status`: `state: String`, `protocol: String`, `fail_open: bool`.
- Commands are `#[tauri::command] pub(crate) async fn …(app: AppHandle<R>, …)` in `src/commands.rs`, registered in `src/lib.rs` `generate_handler!`.
- Plugin `.setup()` manages `Box<dyn TunnelControl>`; retrieve with `app.state::<Box<dyn TunnelControl>>()`.
- `select_server(-1)` = Smart/auto (frontend `tauri_backend.ts` sends `index ?? -1`).
- Main window label is `"main"` (no `label` in `tauri.conf.json` → Tauri default).
- Frontend backend seam: `gui-tauri/src/lib/tauri_backend.ts`; capabilities: `gui-tauri/src-tauri/capabilities/default.json` has `core:default` (includes event listen/emit).
- Tauri v2 tray/menu API (tauri-2.11.5): `TrayIconBuilder::with_id(id).icon(Image).menu(&menu).show_menu_on_left_click(bool).on_menu_event(|app, ev| …).on_tray_icon_event(|tray, ev| …).build(app)`; `CheckMenuItem::set_checked/set_text/set_enabled(...) -> tauri::Result<()>`; `MenuItem::set_text/set_enabled`.

---

## File structure

- **Create** `gui-tauri/tauri-plugin-spark-vpn/src/tray.rs` — the entire desktop tray: pure helpers (`flag_emoji`, id format/parse, view-model), menu construction, `TrayHandles`, `refresh`, `init`, event dispatch, window-close/quit. `#[cfg(desktop)]`. One focused file.
- **Create** `gui-tauri/tauri-plugin-spark-vpn/icons/tray-macos.png` (+ `tray.png` for Windows/Linux) — tray icon assets.
- **Modify** `gui-tauri/tauri-plugin-spark-vpn/src/lib.rs` — `#[cfg(desktop)] mod tray;`, manage `SelectedServer` state, register `get_selected_server`, call `tray::init` in setup.
- **Modify** `gui-tauri/tauri-plugin-spark-vpn/src/commands.rs` — `SelectedServer` state type + `parse_pin`/`pin_to_i32` usage; `select_server` records the pin; new `get_selected_server`; state-mutating commands call `tray::refresh` + emit.
- **Modify** `gui-tauri/tauri-plugin-spark-vpn/Cargo.toml` — add `tray-icon`, `image-png` to the `tauri` feature list.
- **Modify** `gui-tauri/src/lib/tauri_backend.ts` + `gui-tauri/src/lib/spark_backend.ts` — `getSelectedServer()`; listen for `spark://state`; split-tunnel navigation.

---

## Task 1: Pure tray helpers (flag emoji, menu ids, view-model)

**Files:**
- Create: `gui-tauri/tauri-plugin-spark-vpn/src/tray.rs`
- Modify: `gui-tauri/tauri-plugin-spark-vpn/src/lib.rs` (add `#[cfg(desktop)] mod tray;`)

- [ ] **Step 1: Create `tray.rs` with the module gate and pure helpers**

```rust
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

/// Convert the `select_server` i32 arg to a pin: negative → auto (None).
pub(crate) fn parse_pin(index: i32) -> Option<usize> {
    if index < 0 {
        None
    } else {
        Some(index as usize)
    }
}

/// Convert a pin back to the i32 wire value (None → -1).
pub(crate) fn pin_to_i32(pin: Option<usize>) -> i32 {
    pin.map_or(-1, |i| i as i32)
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
        assert_eq!(parse_pin(-1), None);
        assert_eq!(parse_pin(0), Some(0));
        assert_eq!(parse_pin(5), Some(5));
        assert_eq!(pin_to_i32(None), -1);
        assert_eq!(pin_to_i32(Some(5)), 5);
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
```

- [ ] **Step 2: Register the module in `lib.rs`**

Add after the existing `#[cfg(target_os = "macos")] mod apps_darwin;` block (around line 17):

```rust
// Desktop system tray (macOS menu bar / Windows + Linux tray). Desktop-only.
#[cfg(desktop)]
mod tray;
```

- [ ] **Step 3: Run the tests to verify they pass**

Run: `cargo test --manifest-path gui-tauri/tauri-plugin-spark-vpn/Cargo.toml tray::`
Expected: 5 tests pass. (On the macOS dev host `cfg(desktop)` is true, so the module + tests compile.)

- [ ] **Step 4: Commit**

```bash
git add gui-tauri/tauri-plugin-spark-vpn/src/tray.rs gui-tauri/tauri-plugin-spark-vpn/src/lib.rs
git commit -m "tray: pure helpers (flag emoji, menu ids, view-model) + module gate"
```

---

## Task 2: Selected-server pin as shared plugin state + `get_selected_server`

**Files:**
- Modify: `gui-tauri/tauri-plugin-spark-vpn/src/commands.rs`
- Modify: `gui-tauri/tauri-plugin-spark-vpn/src/lib.rs`

- [ ] **Step 1: Add the `SelectedServer` state type + a failing test in `commands.rs`**

At the top of `commands.rs`, after the existing `use` lines, add:

```rust
use std::sync::Mutex;

/// The user's selected-location pin, shared between the window and the tray. `None` = Smart/auto,
/// `Some(i)` = a pinned pool index. Promoted here from frontend-ephemeral state so the tray can
/// read it (and so it survives a UI reload). Managed as Tauri state in `lib.rs`.
#[derive(Default)]
pub(crate) struct SelectedServer(pub Mutex<Option<usize>>);
```

Then add this test module at the end of `commands.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::SelectedServer;

    #[test]
    fn selected_server_defaults_to_auto() {
        let s = SelectedServer::default();
        assert_eq!(*s.0.lock().unwrap(), None);
    }
}
```

- [ ] **Step 2: Run to verify it compiles + passes**

Run: `cargo test --manifest-path gui-tauri/tauri-plugin-spark-vpn/Cargo.toml selected_server_defaults`
Expected: PASS.

- [ ] **Step 3: Record the pin in `select_server` and add `get_selected_server`**

Replace the existing `select_server` command in `commands.rs` with:

```rust
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
```

Note: `crate::tray_pin` / `crate::tray_pin_to_i32` are thin re-exports so this compiles on non-desktop too (the `tray` module is desktop-only). Add them to `lib.rs` in the next step.

- [ ] **Step 4: Wire state + command + pin helpers in `lib.rs`**

In `lib.rs`, add these platform-agnostic pin helpers (the `tray` module's `parse_pin`/`pin_to_i32` are desktop-only, so mirror them here for the command to use everywhere):

```rust
/// Convert the `select_server` i32 arg to a pin (negative → auto/None). Mirrors `tray::parse_pin`
/// but available on all targets (the command runs on mobile too).
pub(crate) fn tray_pin(index: i32) -> Option<usize> {
    if index < 0 {
        None
    } else {
        Some(index as usize)
    }
}

/// Convert a pin back to the i32 wire value (None → -1).
pub(crate) fn tray_pin_to_i32(pin: Option<usize>) -> i32 {
    pin.map_or(-1, |i| i as i32)
}
```

Register the new command in `generate_handler!` (add after `commands::select_server,`):

```rust
            commands::get_selected_server,
```

Manage the state in `.setup()` — add this line inside the setup closure, before the `#[cfg(target_os = "android")]` block (so it runs on all platforms):

```rust
            app.manage(commands::SelectedServer::default());
```

- [ ] **Step 5: Run the whole plugin test + build to verify**

Run: `cargo test --manifest-path gui-tauri/tauri-plugin-spark-vpn/Cargo.toml`
Expected: all pass (Task 1 + Task 2 tests).

- [ ] **Step 6: Commit**

```bash
git add gui-tauri/tauri-plugin-spark-vpn/src/commands.rs gui-tauri/tauri-plugin-spark-vpn/src/lib.rs
git commit -m "tray: promote selected-server pin to shared plugin state + get_selected_server"
```

---

## Task 3: Cargo features + tray icon asset + minimal tray skeleton

**Files:**
- Modify: `gui-tauri/tauri-plugin-spark-vpn/Cargo.toml`
- Create: `gui-tauri/tauri-plugin-spark-vpn/icons/tray.png`
- Modify: `gui-tauri/tauri-plugin-spark-vpn/src/tray.rs`
- Modify: `gui-tauri/tauri-plugin-spark-vpn/src/lib.rs`

- [ ] **Step 1: Enable the tray Cargo features**

In `gui-tauri/tauri-plugin-spark-vpn/Cargo.toml`, change the `tauri` dependency line (currently `tauri = { version = "2" }`) to:

```toml
tauri = { version = "2", features = ["tray-icon", "image-png"] }
```

- [ ] **Step 2: Add a tray icon asset**

Create a monochrome template PNG (works as a macOS menu-bar template icon and a Windows/Linux tray icon). Reuse the existing app icon as a starting point:

```bash
mkdir -p gui-tauri/tauri-plugin-spark-vpn/icons
cp gui-tauri/src-tauri/icons/32x32.png gui-tauri/tauri-plugin-spark-vpn/icons/tray.png
```

(A dedicated monochrome template asset can replace this later; `32x32.png` is a valid stand-in that compiles + renders.)

- [ ] **Step 3: Add `init` + a minimal Show/Quit menu to `tray.rs`**

Append to `tray.rs` (after the pure helpers, before `#[cfg(test)]`):

```rust
use tauri::{
    menu::{MenuBuilder, MenuItemBuilder},
    tray::TrayIconBuilder,
    AppHandle, Manager, Runtime,
};

/// The tray icon PNG, embedded at compile time.
const TRAY_ICON_PNG: &[u8] = include_bytes!("../icons/tray.png");

/// Build the system tray and register it. Called once from the plugin `.setup()`.
pub(crate) fn init<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<()> {
    let show = MenuItemBuilder::with_id("show", "Show Spark").build(app)?;
    let quit = MenuItemBuilder::with_id("quit", "Quit Spark").build(app)?;
    let menu = MenuBuilder::new(app).item(&show).item(&quit).build()?;

    let icon = tauri::image::Image::from_bytes(TRAY_ICON_PNG)?;
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
```

- [ ] **Step 4: Call `tray::init` from the plugin setup**

In `lib.rs` `.setup()`, add at the end of the closure (before `Ok(())`):

```rust
            #[cfg(desktop)]
            tray::init(app)?;
```

- [ ] **Step 5: Build to verify it compiles**

Run: `cargo build --manifest-path gui-tauri/tauri-plugin-spark-vpn/Cargo.toml`
Expected: builds clean. (If `items(&[...])` or `icon_as_template` name differs in 2.11.x, adjust to the compiler's suggestion — the API family is confirmed present.)

- [ ] **Step 6: Manual smoke (macOS)**

Run: `cd gui-tauri && npm run tauri dev`
Expected: a Spark icon appears in the menu bar; clicking it shows a menu with "Show Spark" and "Quit Spark"; Quit exits the app. Then stop dev.

- [ ] **Step 7: Commit**

```bash
git add gui-tauri/tauri-plugin-spark-vpn/Cargo.toml gui-tauri/tauri-plugin-spark-vpn/icons/tray.png gui-tauri/tauri-plugin-spark-vpn/src/tray.rs gui-tauri/tauri-plugin-spark-vpn/src/lib.rs
git commit -m "tray: minimal Show/Quit tray skeleton + icon + cargo features"
```

---

## Task 4: Full menu construction + `TrayHandles`

**Files:**
- Modify: `gui-tauri/tauri-plugin-spark-vpn/src/tray.rs`

- [ ] **Step 1: Add a `TrayHandles` struct + full-menu builder**

Add to `tray.rs` (extend the `use` for menu types, then add the builder). Replace the `use tauri::{menu::{MenuBuilder, MenuItemBuilder}, …}` line with:

```rust
use tauri::{
    menu::{CheckMenuItem, CheckMenuItemBuilder, Menu, MenuBuilder, MenuItem, MenuItemBuilder, Submenu, SubmenuBuilder},
    tray::TrayIconBuilder,
    AppHandle, Manager, Runtime,
};
```

Add the handle store (patched in place by `refresh`, Task 5) and the builder:

```rust
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
    let flag = s.country_code.as_deref().map(flag_emoji).unwrap_or_default();
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
/// Returns just the items so both the initial submenu build and the pool-change rebuild can share
/// this (the rebuild appends these into the existing submenu — no new Submenu handle needed).
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

    let (t_label, t_id, t_enabled) = connect_item(&status.state);
    let toggle = MenuItemBuilder::with_id(t_id, t_label)
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
) -> (crate::models::Status, Vec<crate::models::ServerInfo>, String, bool, Option<usize>) {
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
```

- [ ] **Step 2: Build to verify it compiles**

Run: `cargo build --manifest-path gui-tauri/tauri-plugin-spark-vpn/Cargo.toml`
Expected: builds clean. (All builder methods used — `MenuBuilder::item/items/separator`, `SubmenuBuilder::with_id(manager,id,text)/item`, `CheckMenuItemBuilder::with_id/checked`, `MenuItemBuilder::with_id/enabled` — are verified present in tauri-2.11.x.)

- [ ] **Step 3: Commit**

```bash
git add gui-tauri/tauri-plugin-spark-vpn/src/tray.rs
git commit -m "tray: full menu construction (location/routing/adblock/split) + TrayHandles"
```

---

## Task 5: `refresh` (patch-in-place) + wire the full menu into `init`

**Files:**
- Modify: `gui-tauri/tauri-plugin-spark-vpn/src/tray.rs`

- [ ] **Step 1: Add `refresh` and rebuild `init` to use the full menu + manage `TrayHandles`**

Replace the `init` fn body from Task 3 with the full version, and add `refresh`:

```rust
/// Build the system tray from current state and register it + its handles. Called once from setup.
pub(crate) fn init<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<()> {
    let (status, servers, routing, adblock, selected) = read_state(app);
    let (menu, handles) = build_menu(app, &status, &servers, &routing, adblock, selected)?;
    app.manage(handles);

    let icon = tauri::image::Image::from_bytes(TRAY_ICON_PNG)?;
    TrayIconBuilder::with_id("spark-tray")
        .icon(icon)
        .icon_as_template(true)
        .tooltip("Spark")
        .menu(&menu)
        .show_menu_on_left_click(true)
        // Placeholder handler (show/quit only); Task 6 replaces this with `on_menu_event`.
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
    // children in place (remove the stored old items, append freshly built ones).
    let new_sig: Vec<String> = servers.iter().map(server_sig).collect();
    let pool_changed = *handles.pool_sig.lock().expect("sig lock") != new_sig;
    if pool_changed {
        if let Ok(items) = build_location_items(app, &servers, selected) {
            {
                let mut stored = handles.locations.lock().expect("loc lock");
                for (_, old) in stored.iter() {
                    let _ = handles.location_submenu.remove(old); // CheckMenuItem: IsMenuItem
                }
                for (_, it) in &items {
                    let _ = handles.location_submenu.append(it);
                }
                *stored = items;
            }
            *handles.pool_sig.lock().expect("sig lock") = new_sig;
        }
    } else {
        for (pin, item) in handles.locations.lock().expect("loc lock").iter() {
            let _ = item.set_checked(*pin == selected);
        }
    }
}
```

`Submenu::remove(&dyn IsMenuItem)` and `Submenu::append(&dyn IsMenuItem)` are verified present in tauri-2.11.x; `CheckMenuItem` implements `IsMenuItem`, so `remove(old)` / `append(it)` type-check directly (no `MenuItemKind` handling needed).

- [ ] **Step 2: Build to verify it compiles**

Run: `cargo build --manifest-path gui-tauri/tauri-plugin-spark-vpn/Cargo.toml`
Expected: builds clean.

- [ ] **Step 3: Commit**

```bash
git add gui-tauri/tauri-plugin-spark-vpn/src/tray.rs
git commit -m "tray: refresh() patches items in place; init builds the full menu"
```

---

## Task 6: Menu event dispatch (`on_menu_event`)

**Files:**
- Modify: `gui-tauri/tauri-plugin-spark-vpn/src/tray.rs`

- [ ] **Step 1: Add the dispatcher**

Add to `tray.rs`:

```rust
use tauri::Emitter;

/// Tray menu-event handler: run the corresponding control action, then refresh + notify the window.
fn on_menu_event<R: Runtime>(app: &AppHandle<R>, event: tauri::menu::MenuEvent) {
    let id = event.id().as_ref().to_string();
    let ctl = app.state::<Box<dyn crate::TunnelControl>>();

    match id.as_str() {
        "connect" => {
            let _ = ctl.connect();
        }
        "disconnect" => {
            let _ = ctl.disconnect();
        }
        "routing:smart" => {
            let _ = ctl.set_routing_mode("smart");
        }
        "routing:full" => {
            let _ = ctl.set_routing_mode("full");
        }
        "adblock" => {
            let enabled = ctl.get_ad_block_enabled().unwrap_or(true);
            let _ = ctl.set_ad_block_enabled(!enabled);
        }
        "split" => {
            show_main_window(app);
            let _ = app.emit("spark://navigate", "/split-tunneling");
        }
        "show" => show_main_window(app),
        "quit" => {
            let _ = ctl.disconnect();
            app.exit(0);
            return;
        }
        other => {
            if let Some(pin) = parse_loc_menu_id(other) {
                let _ = ctl.select_server(pin_to_i32(pin));
                *app.state::<crate::commands::SelectedServer>()
                    .0
                    .lock()
                    .expect("pin lock") = pin;
            }
        }
    }

    refresh(app);
    let _ = app.emit("spark://state", ());
}
```

- [ ] **Step 2: Point `init` at the real dispatcher**

In `init` (Task 5), replace the placeholder `.on_menu_event(move |app, event| … )` closure with the named function:

```rust
        .on_menu_event(on_menu_event)
```

- [ ] **Step 3: Build to verify it compiles**

Run: `cargo build --manifest-path gui-tauri/tauri-plugin-spark-vpn/Cargo.toml`
Expected: builds clean.

- [ ] **Step 4: Manual smoke (macOS)**

Run: `cd gui-tauri && npm run tauri dev`. From the tray: Connect → status header flips to "Connected", toggle becomes "Disconnect"; open Select Location, pick a city → its check-mark moves; toggle Routing Mode + Ad Blocking → check-marks update; Split Tunneling… → window shows. Stop dev.

- [ ] **Step 5: Commit**

```bash
git add gui-tauri/tauri-plugin-spark-vpn/src/tray.rs
git commit -m "tray: menu event dispatch (connect/location/routing/adblock/split/show/quit)"
```

---

## Task 7: Hide-to-tray on window close

**Files:**
- Modify: `gui-tauri/tauri-plugin-spark-vpn/src/tray.rs`

- [ ] **Step 1: Intercept the main window close in `init`**

In `init` (after `app.manage(handles);`, before building the tray), add:

```rust
    if let Some(win) = app.get_webview_window("main") {
        let win_for_event = win.clone();
        win.on_window_event(move |event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = win_for_event.hide();
            }
        });
    }
```

- [ ] **Step 2: Build + manual smoke**

Run: `cargo build --manifest-path gui-tauri/tauri-plugin-spark-vpn/Cargo.toml`, then `cd gui-tauri && npm run tauri dev`.
Expected: closing the window hides it (app stays alive in the tray, VPN keeps running); tray "Show Spark" brings it back; "Quit Spark" disconnects + exits. Stop dev.

- [ ] **Step 3: Commit**

```bash
git add gui-tauri/tauri-plugin-spark-vpn/src/tray.rs
git commit -m "tray: hide window to tray on close (VPN keeps running; Quit exits)"
```

---

## Task 8: Notify the tray from state-mutating commands

**Files:**
- Modify: `gui-tauri/tauri-plugin-spark-vpn/src/commands.rs`

- [ ] **Step 1: Refresh the tray after window-driven mutations**

So a change made in the *window* updates the tray, add `#[cfg(desktop)] crate::tray::refresh(&app);` at the end of each state-mutating command. Update these commands in `commands.rs` (add the line before the final `Ok(())` / after the control call):

`connect`, `disconnect`, `select_server` (already added pin write — add refresh after), `set_routing_mode`, `set_ad_block_enabled`. Example for `connect`:

```rust
#[tauri::command]
pub(crate) async fn connect<R: Runtime>(app: AppHandle<R>) -> crate::Result<()> {
    app.state::<Ctl>().connect()?;
    #[cfg(desktop)]
    crate::tray::refresh(&app);
    Ok(())
}
```

Apply the same `#[cfg(desktop)] crate::tray::refresh(&app);` line to `disconnect`, `select_server`, `set_routing_mode`, and `set_ad_block_enabled` (each after its control call, before `Ok(())`).

- [ ] **Step 2: Build to verify it compiles (desktop)**

Run: `cargo build --manifest-path gui-tauri/tauri-plugin-spark-vpn/Cargo.toml`
Expected: builds clean.

- [ ] **Step 3: Commit**

```bash
git add gui-tauri/tauri-plugin-spark-vpn/src/commands.rs
git commit -m "tray: refresh the tray after window-driven state changes"
```

---

## Task 9: Light status poll for autonomous connect/drop

**Files:**
- Modify: `gui-tauri/tauri-plugin-spark-vpn/src/tray.rs`

- [ ] **Step 1: Spawn a poll loop in `init`**

At the end of `init` (after building the tray, before `Ok(())`), add a ~1.5 s poll that refreshes the tray so autonomous NE/service state changes (connect/drop the app didn't initiate) show up:

```rust
    let poll_app = app.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_millis(1500));
        refresh(&poll_app);
    });
```

(A plain thread is used rather than an async task to avoid assuming a runtime handle in the plugin's setup; `refresh` only calls control getters + menu setters, which are cheap and thread-safe.)

- [ ] **Step 2: Build + manual smoke**

Run: `cargo build --manifest-path gui-tauri/tauri-plugin-spark-vpn/Cargo.toml`, then `cd gui-tauri && npm run tauri dev`. Connect from the *window*; within ~1.5 s the tray header/toggle reflect "Connected" without opening the menu. Disconnect from the window; the tray updates. Stop dev.

- [ ] **Step 3: Commit**

```bash
git add gui-tauri/tauri-plugin-spark-vpn/src/tray.rs
git commit -m "tray: light 1.5s status poll for autonomous connect/drop"
```

---

## Task 10: Frontend — read pin on load, listen for `spark://state`, split-tunnel nav

**Files:**
- Modify: `gui-tauri/src/lib/spark_backend.ts`
- Modify: `gui-tauri/src/lib/tauri_backend.ts`
- Modify: `gui-tauri/src/lib/selection.ts`
- Modify: `gui-tauri/src/routes/+layout.svelte`

- [ ] **Step 1: Add `getSelectedServer` to the backend interface + Tauri impl + Mock**

In `spark_backend.ts`, add to the `SparkBackend` interface (near `selectServer`):

```typescript
  getSelectedServer(): Promise<number | null>;
```

In the Mock backend (`class MockBackend`, ~line 91) in `spark_backend.ts`, add (the mock's shared state var is `mockState`, and `selectServer` already sets `mockState.pinned`):

```typescript
  async getSelectedServer(): Promise<number | null> { return mockState.pinned; }
```

In `tauri_backend.ts`, add (after `selectServer`):

```typescript
  async getSelectedServer(): Promise<number | null> {
    // -1 (Smart/auto) maps back to null; any non-negative index is a pin.
    const i = await invoke<number>("plugin:spark-vpn|get_selected_server");
    return i < 0 ? null : i;
  }
```

- [ ] **Step 2: Initialize the pin store from the backend on load**

There is no app-wide backend singleton — each route does `isTauri() ? new TauriBackend() : new MockBackend()`. Mirror that in `selection.ts`. Add these imports at the top of `selection.ts`:

```typescript
import { isTauri, TauriBackend } from "./tauri_backend";
import { MockBackend, type SparkBackend } from "./spark_backend";
```

Then, after the `export const selectedIndex` declaration, add:

```typescript
/// Load the persisted pin (tray/window shared state) into the store, so it survives a UI reload and
/// matches the tray. Constructs a backend inline, like the routes do.
export async function initSelectedIndex(): Promise<void> {
  const backend: SparkBackend = isTauri() ? new TauriBackend() : new MockBackend();
  try {
    selectedIndex.set(await backend.getSelectedServer());
  } catch {
    // leave the default (null = auto) on any error
  }
}
```

- [ ] **Step 3: Listen for `spark://state` + `spark://navigate` in the layout**

`+layout.svelte` uses Svelte 5 runes (no `onMount`). Add these imports to its `<script>`:

```typescript
import { listen } from "@tauri-apps/api/event";
import { goto } from "$app/navigation";
import { initSelectedIndex } from "$lib/selection";
```

Then add a run-once `$effect` (empty dep set → runs on mount, returns a cleanup) alongside the existing `$effect`s:

```typescript
  // Tray ↔ window sync: pull the pin on load + whenever the tray changes state; handle tray-driven
  // navigation. Guarded so it's a no-op in a plain browser (no Tauri event bridge).
  $effect(() => {
    initSelectedIndex();
    const state = listen("spark://state", () => initSelectedIndex());
    const nav = listen<string>("spark://navigate", (e) => goto(e.payload));
    return () => {
      state.then((f) => f());
      nav.then((f) => f());
    };
  });
```

(Adjust imports to the file's existing style; if `onMount` already exists, merge into it. `core:default` in `capabilities/default.json` already permits `listen`.)

- [ ] **Step 4: Type-check the frontend**

Run: `cd gui-tauri && npm run check`
Expected: no type errors. (Per user global pref: run type checks after modifying TypeScript.)

- [ ] **Step 5: Manual smoke (macOS)**

Run: `cd gui-tauri && npm run tauri dev`. Pick a location in the *tray* → the window's location screen reflects it (check-mark / bolt). Pick one in the *window* → the tray reflects it. Split Tunneling… from the tray navigates the window to `/split-tunneling`. Reload the window (Cmd-R) → the pinned location persists. Stop dev.

- [ ] **Step 6: Commit**

```bash
git add gui-tauri/src/lib/spark_backend.ts gui-tauri/src/lib/tauri_backend.ts gui-tauri/src/lib/selection.ts gui-tauri/src/routes/+layout.svelte
git commit -m "tray: frontend syncs via spark://state, reads pin on load, handles split-tunnel nav"
```

---

## Task 11: Whole-workspace gate + PR

**Files:** none (verification + PR).

- [ ] **Step 1: Rust gate (plugin)**

Run:
```bash
cargo fmt --manifest-path gui-tauri/tauri-plugin-spark-vpn/Cargo.toml --all
cargo clippy --manifest-path gui-tauri/tauri-plugin-spark-vpn/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path gui-tauri/tauri-plugin-spark-vpn/Cargo.toml
```
Expected: fmt clean, clippy clean, tests pass.

- [ ] **Step 2: App build gate**

Run: `cd gui-tauri && npm run check && npm run tauri build -- --debug` (or a full `npm run tauri build` if signing/notarization is desired for on-device verification).
Expected: the app bundles with the tray.

- [ ] **Step 3: Cross-target compile check (Windows/Linux code paths)**

Since only macOS is verified this round, at minimum confirm the desktop cfg code has no macOS-only assumptions: review `tray.rs` for any `#[cfg(target_os = "macos")]`-only calls (there should be none — the whole module is `#[cfg(desktop)]`, platform-neutral). Note in the PR that Windows/Linux are code-review-only this round.

- [ ] **Step 4: Push + open PR**

```bash
git push -u origin fisk/desktop-tray
gh pr create --repo getlantern/spark --title "Desktop system tray (macOS/Windows/Linux)" --body "$(cat <<'EOF'
## Summary
Adds a system-tray / menu-bar menu to the Spark desktop app, modeled on Lantern's tray: status header, Connect/Disconnect, Select Location (Smart + flag list), Routing Mode (Smart/Full), Ad Blocking, Split Tunneling…, Show, Quit. Closing the window hides to the tray (VPN keeps running); Quit disconnects + exits.

Tray ↔ window stay in sync via a plugin-held source of truth: `refresh` patches menu items in place, driven by tray actions, a notify hook on state-mutating commands (which also emits `spark://state`), and a light 1.5s status poll. The selected-location pin is promoted from frontend-ephemeral state to plugin-held shared state (`get_selected_server`), which also fixes the "pin doesn't survive reload" limitation.

Spec: `docs/superpowers/specs/2026-07-10-desktop-system-tray-design.md`.

## Test Plan
- [x] `cargo fmt` + `cargo clippy -D warnings` + `cargo test` (plugin): pure helpers (flag emoji, menu ids, view-model) and the pin state.
- [x] `npm run check` (frontend type-check).
- [x] macOS on-device: connect/disconnect, switch location, toggle routing/ad-block from the tray; window and tray stay in sync both directions; close-hides-to-tray; Quit disconnects + exits; pin survives reload.
- [ ] Windows/Linux: code review this round; on-device verification is a follow-up.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 5: Run the review loop** (Copilot/CodeRabbit) via the `review-pr` skill until settled.
