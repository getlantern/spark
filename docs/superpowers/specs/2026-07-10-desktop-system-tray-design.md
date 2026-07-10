# Desktop System Tray — Design

**Status:** Approved 2026-07-10. Ready for implementation planning.

**Goal:** Give the Spark desktop app a system-tray / menu-bar presence — modeled on Lantern's tray — that both reflects and drives the same VPN state as the SvelteKit window (connection status, selected location, routing mode, ad-block).

**Platforms:** macOS, Windows, Linux via Tauri v2's cross-platform `TrayIcon`. Fully verified on macOS this round; Windows/Linux ship the code + assets with on-device verification as a follow-up.

## Motivation

The app is windowed-only today. A tray lets the user connect/disconnect, switch location, and change routing mode without opening the window, and keeps the VPN running when the window is closed — the standard model for a consumer VPN (and what Lantern does). Reference: the Lantern macOS menu-bar menu (status header · Connect · Select Location ▸ · Routing Mode ▸ · Join Server · Show · Quit).

## Scope

**In:**
- Tray icon on all three desktop OSes.
- Menu: status header (disabled), Connect/Disconnect, Select Location submenu (Smart Location + flag-labeled server list), Routing Mode submenu (Smart/Full), Ad Blocking (checkable), Split Tunneling… (opens window on that screen), Show, Quit.
- Hide-to-tray on window close; the VPN keeps running. Quit tears the tunnel down and exits.
- Tray ↔ window state consistency in both directions.

**Out (YAGNI):**
- "Join Server" (Lantern-specific; Spark has no device-as-server feature).
- Inline split-tunnel editing (too complex for a menu — the item just navigates).
- Per-server latency in the menu; custom tray theming.

## Architecture

### Placement
A new `#[cfg(desktop)]` module `tray.rs` **inside `tauri-plugin-spark-vpn`**, initialized from the plugin's existing `.setup()` immediately after the `Box<dyn TunnelControl>` is `manage`d. Rationale: the tray drives the same `TunnelControl` and reuses the `ServerInfo` / `Status` models, so co-locating it keeps the app shell (`gui-tauri/src-tauri/src/lib.rs`) a thin shell and avoids re-exposing the control. The `cfg(desktop)` gate excludes it from Android/iOS builds.

### Single source of truth
`TunnelControl` remains the sole source of truth. The tray holds no duplicate state store; it derives a view each refresh from `status()`, `servers()`, `get_routing_mode()`, and `get_ad_block_enabled()`.

### State sync (approach A)
A `refresh_tray(app)` function reads the control and **patches menu items in place** (`MenuItem::set_text`, `CheckMenuItem::set_checked`, `set_enabled`) — no full-menu rebuild, so no flicker. The Select Location submenu is rebuilt only when the server list actually changes (compared by length + per-item identity). `refresh_tray` is driven three ways:

1. **After any tray action** — called immediately once the `TunnelControl` call returns.
2. **After any webview command that mutates state** — a notify hook fires `refresh_tray` and **emits a `spark://state` event** so the window reflects tray-initiated changes.
3. **A light status poll (~1.5s)** — required for *autonomous* state changes (the NE/service connecting or dropping on its own; `TunnelControl` is pull-only, with no status subscription today) and as a safety net. This mirrors the window's existing status polling.

Both surfaces therefore derive from one source: user actions propagate immediately via notify + event; autonomous status rides the light poll.

**Selected-location pin — shared state (required refinement).** `status()`, `get_routing_mode()`, and `get_ad_block_enabled()` are all queryable, but the *selected-server pin* is not: it lives only in the frontend as an ephemeral `selectedIndex` writable that (by its own comment) "does not survive a full UI reload." The tray (Rust) cannot read it, so it could not render the correct Select Location check-mark consistent with the window. This work promotes the pin to plugin-held state: `select_server(index)` records it in a plugin `Mutex<Option<usize>>` (i32 `-1` = Smart/auto → `None`), and a new `get_selected_server()` command/getter lets both `refresh_tray` and the window (on load) read it. Bonus: this also fixes the frontend's "pin doesn't survive reload" v1 limitation. `ServerInfo.is_current` (the *actively-used* server) still marks which server the selector is on under auto, but the check-mark reflects the *pin* (Smart vs a specific index), matching the window's ⚡/✓ semantics.

### Menu item IDs & dispatch
Each item carries a stable string id. The tray's `on_menu_event` matches:

| id | action |
|---|---|
| `connect` / `disconnect` | `TunnelControl::connect()` / `disconnect()` |
| `loc:smart` | `select_server(-1)` (Smart/auto) |
| `loc:<index>` | `select_server(index)` |
| `routing:smart` / `routing:full` | `set_routing_mode("smart"/"full")` |
| `adblock` | toggle `set_ad_block_enabled(!current)` |
| `split` | show window + navigate to `/split-tunneling` |
| `show` | show + focus the main window |
| `quit` | `disconnect()` then `app.exit(0)` |

Handlers call the control, then `refresh_tray` + emit `spark://state`.

### Flag rendering
`flag_emoji(country_code: &str) -> String`: map a 2-letter ISO 3166-1 alpha-2 code to its two Unicode regional-indicator codepoints. Dependency-free. Labels render as `🇦🇺 Australia — Melbourne` from `ServerInfo { country_code, country, city }`. A missing/invalid code falls back to no flag.

### View-model derivation
Pure helpers (unit-testable without a Tauri runtime):
- `header_text(status) -> String`: `"Disconnected"` / `"Connecting…"` / `"Connected"` (with location when connected).
- `connect_item(state) -> (label, id, enabled)`: `("Connect","connect",true)` when disconnected, `("Disconnect","disconnect",true)` when connected, disabled label while connecting/disconnecting.

## Platform behavior

One shared `TrayIconBuilder`. Differences:
- **macOS:** monochrome **template** menu-bar icon (adapts to light/dark bar); menu shows on click.
- **Windows:** left-click shows/focuses the window; right-click shows the menu (Windows convention).
- **Linux:** appindicator (`libayatana-appindicator` at runtime); menu on click.

The icon reflects connected vs disconnected (filled vs outline) as a small enhancement; if it complicates the first pass, fall back to a single static icon and rely on the status header.

## Close & quit lifecycle

Intercept the main window's `CloseRequested` event → prevent default + hide the window; the VPN keeps running. **Show** (or Windows left-click) reveals it. **Quit** calls `disconnect()` then `app.exit(0)` so quitting cleanly tears down the tunnel (matches Lantern; avoids leaving a tunnel running with no UI).

## Error handling

Tray actions that fail (e.g. `connect()` returns an error) log the error and emit an error event the window can surface as a toast; the menu stays responsive. No modal dialogs originate from the tray.

## Testing

- **Rust unit (pure functions, no Tauri runtime):** `flag_emoji()` (code → emoji, invalid → fallback); menu-id parse/format round-trip (`loc:<index>`); `header_text()` and `connect_item()` view-model derivation across every `Status.state`.
- **Tray build + event dispatch:** requires a Tauri runtime, so covered by macOS on-device verification (connect/disconnect from the tray, switch location, toggle routing/ad-block, confirm the window and tray stay in sync both directions; close-hides-to-tray; Quit disconnects + exits). Windows/Linux: code review this round, on-device verification as a follow-up.
- **Frontend:** a test for the `spark://state` event listener updating the store, and for the Split Tunneling navigation.

## Files

**Add:**
- `tauri-plugin-spark-vpn/src/tray.rs` — tray module (`#[cfg(desktop)]`): builder, menu construction, `refresh_tray`, `on_menu_event` dispatch, `flag_emoji`, view-model helpers, window-close interception.
- Tray icon assets (template monochrome for macOS; colored for Windows/Linux), under the plugin or app icon dir.

**Modify:**
- `tauri-plugin-spark-vpn/src/lib.rs` — call `tray::init(app)` from `.setup()` under `#[cfg(desktop)]`; register the new `get_selected_server` command.
- `tauri-plugin-spark-vpn/src/commands.rs` — the state-mutating commands (`connect`, `disconnect`, `select_server`, `set_routing_mode`, `set_ad_block_enabled`) fire the notify hook after mutating; `select_server` records the pin in shared state; add `get_selected_server`.
- Frontend (`gui-tauri/src/lib/…`) — listen for `spark://state` to refresh the store; read `get_selected_server()` on load (replacing the ephemeral-only `selectedIndex`); handle the split-tunneling navigation trigger.

**Reuse:** `TunnelControl`, `ServerInfo`, `Status`, the existing plugin commands, the main window handle.

## Open questions resolved during brainstorming
- Close → **hide to tray** (VPN keeps running).
- Extra items → **Ad Block toggle + Split Tunneling shortcut** both.
- Platforms → **all desktop, macOS-tested** this round.
- State sync → **approach A** (shared source of truth + patch-in-place + notify/event + light poll).
- Quit → **disconnects then exits**.
