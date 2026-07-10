# Location List Before VPN — Design

**Status:** Approved 2026-07-10. Ready for implementation planning.

**Goal:** Make the server/location list available in the UI (window + tray) before the VPN is turned on — instantly from an on-disk cache on startup, and always refreshed by a background kindling fetch on every launch, regardless of VPN state.

**Approach:** Stale-while-revalidate. Two phases, shipped in order.

## Motivation

Today the location list is empty until the tunnel connects. The UI's `servers()` reads only a `SPARK_CONFIG` TOML dev-override (`desktop.rs::resolve()`); the real pool arrives from the tunnel process via `send_provider_message({"cmd":"servers"})` and only when connected. The config fetch (kindling, `config::fetch::load_or_fetch`, cache-first) lives in `spark-core` and is invoked only from the tunnel bringup (`fd_tunnel.rs`), and the app/plugin does not link `spark-core`. Result: nothing to pick from until you connect once.

## Decisions (confirmed with stakeholder)

- **Phased:** Phase 1 (read/persist cache) ships first; Phase 2 (app-side startup fetch) follows.
- **Fetch mechanism:** link a **fetch-only build of `spark-core`** into `tauri-plugin-spark-vpn` and run the kindling fetch in the app process (uniform across platforms, reuses the exact cache-first fetch, shares the cache with the tunnel).
- **Always fetch on startup:** on every launch, run the fetch regardless of whether a cache exists (conditional via ETag → cheap 304 when unchanged).
- **Refresh event:** a dedicated `spark://servers` event (not overloading `spark://state`).
- **Platform scope for Phase 2:** desktop-first (macOS/Windows/Linux). Android's core runs in-process (JNI) and already fetches, so app-side fetch there is a lower-priority follow-up; Phase 1 cache-read still applies wherever a shared cache exists.

## Architecture / data flow

On app startup, independent of VPN state:

1. **Instant (Phase 1):** load the cached `config_raw.json` from the shared data dir, parse its `servers[]` geo list into `ServerInfo`, render the location list immediately.
2. **Background (Phase 2):** always run a kindling config fetch (`load_or_fetch` against the shared cache dir). On a **changed** config, rewrite the shared cache and emit `spark://servers`; the window re-pulls `servers()` and the tray `refresh()`es. On 304/unchanged, no-op. On failure, keep the cached list.

The tunnel process continues to use the **same** shared cache, so an app-side fetch also warms the next connect (and vice versa). When connected, live latency/health/current still overlay from the NE (`send_provider_message`), unchanged.

```
app startup ─┬─▶ read shared config_raw.json ──▶ render list now        (Phase 1)
             └─▶ kindling load_or_fetch (bg) ──▶ changed? rewrite cache
                                                  + emit spark://servers  (Phase 2)
                                                        │
window + tray ◀── re-pull servers() / refresh() ◀──────┘
```

## Phase 1 — read + persist the cached list

**What:** the plugin reads the shared `config_raw.json` and exposes its `servers[]` as the location list whenever there is no `SPARK_CONFIG` dev-override and the live pool isn't available (not connected).

- `config_raw.json` is the Lantern JSON shape; its `servers[]` entries carry `city`, `country`, `country_code` (geo). Parse those into `ServerInfo { index, country, country_code, city, protocol: None, latency_ms: None, healthy: false, is_current: false }`, indexed by position — the same shape `servers_from_config()` already produces from TOML.
- Wire this into `desktop.rs::servers()`: when the TOML static list (`servers_from_config()`) is empty, fall back to parsing the shared `config_raw.json` cache. Live overlay from the NE is unchanged (only when connected).
- The cache already persists across sessions (the tunnel writes it); Phase 1 is purely the read side.

**Shared cache dir (the crux):** the app must read the *same* `config_raw.json` the tunnel writes.
- **macOS:** the NE caches into the **app-group container**; the app must resolve that same app-group path (it has the group entitlement) rather than its plain `app_config_dir`. Resolving the app-group path in the plugin is part of this work.
- **Windows/Linux:** the app and the privileged service must agree on the cache dir; the plan pins the exact shared path.
- **Android:** core runs in-process; the cache is in the app files dir — already shared.

## Phase 2 — fetch-only `spark-core` + startup fetch

- **`fetch` cargo feature on `spark-core`:** compiles only `config::fetch` (+ its kindling/HTTP/cache deps) and the minimal `config`/`Config` types it needs, excluding `tun`, `netstack`, transports, `quinn`, `boringtun`, etc. Goal: a lean fetch surface the app can link without the full data-plane.
- **`tauri-plugin-spark-vpn`** depends on `spark-core` with `features = ["fetch"]` (desktop targets).
- **Startup fetch routine:** in the plugin `setup` (desktop), spawn a background task that runs the fetch against the shared cache dir on every launch. On a changed config, write the shared cache and `app.emit("spark://servers", ())`. Never blocks startup or the UI.
- **Frontend:** listen for `spark://servers` and re-pull `servers()` (window); the tray's existing `refresh()` re-reads `servers()` so it updates too. Guarded by `isTauri()` like the existing tray-sync effect.

## Error handling

- First launch offline (no cache + fetch fails): empty list; retry with backoff; UI shows an empty/"loading" state, fills when a fetch succeeds.
- Fetch fails but a cache exists: keep showing the cached list (no clobber).
- 304 / unchanged: no cache rewrite, no event.
- The background fetch is fully detached — a failure never blocks startup, the window, or connect.

## Files

**Add/Modify (Phase 1):**
- `gui-tauri/tauri-plugin-spark-vpn/src/desktop.rs` — `servers()` falls back to parsing the shared `config_raw.json` cache when the TOML static list is empty; a helper to resolve the shared cache dir (app-group container on macOS).

**Add/Modify (Phase 2):**
- `core/Cargo.toml` — a `fetch` feature exposing `config::fetch` with a minimal dependency set.
- `core/src/lib.rs` / `config/mod.rs` — ensure `config::fetch` + the `ServerInfo`/pool geo types are reachable under the `fetch` feature without pulling the data-plane.
- `gui-tauri/tauri-plugin-spark-vpn/Cargo.toml` — `spark-core = { path = "../../core", features = ["fetch"] }` (desktop targets).
- `gui-tauri/tauri-plugin-spark-vpn/src/lib.rs` — background startup-fetch task in `setup` (desktop); emit `spark://servers`.
- Frontend (`gui-tauri/src/routes/+layout.svelte` / `src/lib/…`) — listen for `spark://servers`, re-pull the list.

**Reuse:** `config::fetch::{load_or_fetch, FetchEnv, cache}`, kindling (embedded `fronted.yaml.gz`), the existing `ServerInfo` model, the tray `refresh()`.

## Phased rollout

- **Phase 1** — cache-read/persist. Locations show instantly on startup and survive restarts (after any prior fetch by the tunnel). Small, all-platform where a shared cache exists. Independently shippable + testable (connect once, quit, relaunch → list present before connecting).
- **Phase 2** — fetch-only `spark-core` + always-fetch-on-startup. Fresh install shows the list without ever connecting; every launch refreshes it. Desktop-first.

## Verification

- **Unit:** `config_raw.json` `servers[]` → `ServerInfo` parsing (fixtures); the fetch-only feature builds standalone and `load_or_fetch` works against a fixture/staging endpoint; stale-while-revalidate ordering (cache rendered before the fetch resolves).
- **Binary size:** measure the app-binary delta from linking `spark-core` `features=["fetch"]`; confirm the fetch feature excludes the data-plane crates (`cargo tree` shows no `tun-rs`/`netstack`/`quinn` under the app).
- **macOS on-device:** fresh profile (no cache) → launch without connecting → list appears after the background fetch; quit + relaunch → list appears instantly from cache, then refreshes; connect → live latency/health overlays; confirm the tunnel and app share one `config_raw.json`.
