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
- **Platform scope for Phase 2:** all platforms, with platform-appropriate mechanisms (below): desktop (macOS/Windows/Linux) links the fetch-only `spark-core` into the app; **Android** triggers the fetch in the existing `:vpn` process over the app↔service IPC **without establishing the tunnel** (no VPN consent for a plain HTTPS fetch); **iOS** mirrors macOS (fetch-only `spark-core` in the app + shared app-group cache) and rides on the in-flight iOS-support work. Android and iOS are wanted as soon as possible, not deferred.

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

**Shared cache dir (the crux):** the app must read the *same* `config_raw.json` the tunnel writes. There is **one canonical copy**, not per-process copies.
- **macOS (confirmed on-device 2026-07-10):** the NE (`org.getlantern.spark.tunnel`) runs as **root**, and `PacketTunnelProvider.swift` self-resolves its cache dir via `containerURL(forSecurityApplicationGroupIdentifier:)` — which resolves **per-user**, so as root it lands in `/var/root/Library/Group Containers/group.org.getlantern.spark/config/config_raw.json` (`root:wheel`, `644`). That's a *different physical dir* than the user app's `~/Library/Group Containers/...`, and `/var/root` is mode `700` so the user cannot even traverse into it. The app's Phase 1 read therefore finds nothing today.
  - **Fix — move the write to the user's container, don't copy.** The app passes its **own** app-group container path (`~/Library/Group Containers/group.org.getlantern.spark/config`) to the NE via `providerConfiguration["dataDir"]`; the NE prefers that over its self-resolution. The app pre-creates the dir so it is **user-owned** (`700`). Result: one canonical copy in the user's container that (a) the app can read before connecting, (b) is private via the `700` parent dir (no `chown`/`chmod` needed even though the NE writes root-owned files into it), and (c) is atomically replaceable by the user in Phase 2 (the dir is user-owned + **non-sticky**, so a cross-uid `rename` over a root-created file is permitted). Both the read side and the injected `dataDir` use the same `shared_config_cache_dir()` helper, so they can never disagree.
  - **Scope note:** this makes Phase 1 touch the NE (`PacketTunnelProvider.swift`) + the plugin's `AppleControl::connect` (`desktop.rs`) in addition to the `servers()` read path — not the single-file change the original plan assumed. Without the NE change the read is inert (nothing to read).
- **Windows/Linux:** the app and the privileged service must agree on the cache dir; the plan pins the exact shared path.
- **Android:** core runs in-process; the cache is in the app files dir — already shared.

## Concurrency / file locking (single canonical copy)

The cache is written atomically per file — `core/src/config/fetch/cache.rs::write_atomic` does temp-write + `rename(2)` (same-filesystem, atomic). Consequences:

- **Readers never lock.** `rename` guarantees a reader opens the whole old or whole new `config_raw.json`, never a torn write. Keeping the Phase 1 read lock-free means startup never blocks on a lock a root fetch might hold.
- **Phase 1 needs no writer lock** — there is exactly one writer (the NE's tunnel-bringup fetch).
- **Phase 2 introduces a second writer** (the app's own startup fetch) and with it two hazards:
  1. *Benign:* `config_raw.json` and `config_meta.json` are not updated as one unit, so an interleave can pair one writer's body with the other's meta — cache.rs already documents this as harmless (worst case one redundant conditional fetch, self-healing).
  2. *Real:* `write_atomic` uses a **fixed** temp name (`config_raw.tmp`), so two concurrent writers write the same temp path and can corrupt it. Latent today (one writer); activated by Phase 2.
- **Phase 2 resolution:** give temp files **unique names** (`config_raw.<pid>.tmp` or random suffix) to kill the shared-temp corruption, and take a single **advisory exclusive lock** on a *stable* `config.lock` sidecar around the raw+meta write so the pair updates atomically w.r.t. the other writer. Lock the stable sidecar, never `config_raw.json` itself (the atomic rename swaps that file's inode). Advisory locks (`flock`/`O_EXLOCK`) are cooperative and **uid-agnostic**, so the root NE and the user app coordinate correctly. Because `load_or_fetch` is conditional (ETag/If-Modified-Since), the common case is a 304 with no write at all, so real contention is rare — the lock is cheap insurance for the changed-config window.

## Phase 2 — fetch-only `spark-core` + startup fetch

- **`fetch` cargo feature on `spark-core`:** compiles only `config::fetch` (+ its kindling/HTTP/cache deps) and the minimal `config`/`Config` types it needs, excluding `tun`, `netstack`, transports, `quinn`, `boringtun`, etc. Goal: a lean fetch surface the app can link without the full data-plane.
- **`tauri-plugin-spark-vpn`** depends on `spark-core` with `features = ["fetch"]` (desktop targets).
- **Startup fetch routine (desktop):** in the plugin `setup`, spawn a background task that runs the fetch against the shared cache dir on every launch. On a changed config, write the shared cache and `app.emit("spark://servers", ())`. Never blocks startup or the UI.
- **Frontend:** listen for `spark://servers` and re-pull `servers()` (window); the tray's existing `refresh()` re-reads `servers()` so it updates too. Guarded by `isTauri()` like the existing tray-sync effect.

### Android

The core (with `config::fetch`/kindling) already runs in the `:vpn` process; do **not** load it into the main app process. Add a `fetchConfig` command to the app↔`:vpn` IPC (the existing `SparkControlClient`/`SparkVpnPlugin` Messenger channel) plus a `spark-android` JNI entry (e.g. `nativeFetchConfig(dataDir)`) that runs `load_or_fetch` **without** calling `VpnService.Builder.establish()` — a plain HTTPS fetch needs no VPN consent and no tunnel. The app triggers it on startup; the cache lands in the app files dir (shared across the app's processes), and the plugin's `AndroidControl::servers()` reads it (Phase 1). Emit the servers-changed signal back over the same IPC so the UI refreshes.

### iOS

Same shape as macOS: the Tauri iOS app links the fetch-only `spark-core` and runs the startup fetch against the shared **app-group container**, which the NE also uses. This depends on the iOS-support work (the plugin, NE app-extension, and app group must exist on iOS first — see `spark-ios-support`); implement as part of / immediately after that lands, using the same fetch-only feature and `spark://servers` wiring as desktop.

## Error handling

- First launch offline (no cache + fetch fails): empty list; retry with backoff; UI shows an empty/"loading" state, fills when a fetch succeeds.
- Fetch fails but a cache exists: keep showing the cached list (no clobber).
- 304 / unchanged: no cache rewrite, no event.
- The background fetch is fully detached — a failure never blocks startup, the window, or connect.

## Files

**Add/Modify (Phase 1):**
- `gui-tauri/tauri-plugin-spark-vpn/src/desktop.rs` — `servers()` falls back to parsing the shared `config_raw.json` cache when the TOML static list is empty; a helper to resolve the shared cache dir (app-group container on macOS).

**Add/Modify (Phase 2 — desktop):**
- `core/Cargo.toml` — a `fetch` feature exposing `config::fetch` with a minimal dependency set.
- `core/src/lib.rs` / `config/mod.rs` — ensure `config::fetch` + the `ServerInfo`/pool geo types are reachable under the `fetch` feature without pulling the data-plane.
- `gui-tauri/tauri-plugin-spark-vpn/Cargo.toml` — `spark-core = { path = "../../core", features = ["fetch"] }` (desktop targets).
- `gui-tauri/tauri-plugin-spark-vpn/src/lib.rs` — background startup-fetch task in `setup` (desktop); emit `spark://servers`.
- Frontend (`gui-tauri/src/routes/+layout.svelte` / `src/lib/…`) — listen for `spark://servers`, re-pull the list.

**Add/Modify (Phase 2 — Android):**
- `spark-android` (JNI) — a `nativeFetchConfig(dataDir)` entry that runs `config::fetch::load_or_fetch` without `VpnService.Builder.establish()`.
- `SparkVpnPlugin` (Kotlin, `:vpn` process) + `SparkControlClient` (main-process IPC client) — a `fetchConfig` command + a servers-changed signal back to the app.
- `gui-tauri/tauri-plugin-spark-vpn/src/mobile.rs` (`AndroidControl`) — trigger `fetchConfig` on startup; `servers()` reads the app-files-dir cache (Phase 1).

**Add/Modify (Phase 2 — iOS):** rides on the iOS-support branch; reuses the desktop fetch-only feature + `spark://servers` wiring against the shared app-group container. No new mechanism — same as macOS once the iOS plugin/NE/app-group exist.

**Reuse:** `config::fetch::{load_or_fetch, FetchEnv, cache}`, kindling (embedded `fronted.yaml.gz`), the existing `ServerInfo` model, the tray `refresh()`.

## Phased rollout

- **Phase 1** — cache-read/persist. Locations show instantly on startup and survive restarts (after any prior fetch by the tunnel). Small, all-platform where a shared cache exists. Independently shippable + testable (connect once, quit, relaunch → list present before connecting).
- **Phase 2a — desktop** — fetch-only `spark-core` linked into the app + always-fetch-on-startup. Fresh install shows the list without ever connecting; every launch refreshes it.
- **Phase 2b — Android** — IPC-triggered `fetchConfig` in the `:vpn` process (no tunnel establish) on startup, same stale-while-revalidate + `spark://servers` refresh. Land right after (or alongside) 2a.
- **Phase 2c — iOS** — same fetch-only mechanism as desktop against the shared app-group container; gated on the iOS-support work landing, then done as soon as it does.

## Phase 2a spike result (2026-07-11) — approach B (link `config-fetch` as-is)

Measured, not assumed:
- `config-fetch` builds standalone (`cargo build -p spark-core --no-default-features --features config-fetch`, ~32s) and its dep tree pulls **BoringSSL** (`boring2`/`boring-sys2`/`tokio-boring2`) + `flint-fronted`/`flint-kindling` **and** the data plane (`netstack-smoltcp`, `tun-rs`) — the data plane is non-optional today.
- **Cost is dominated by BoringSSL:** the `libboring_sys2` rlib alone is **8.3 MB** (the whole `config-fetch` `libspark_core.rlib` is 12.7 MB unstripped). `netstack-smoltcp` (~1K SLoC) + `tun-rs` (thin) are negligible by comparison.
- `config::fetch` hard-depends on `crate::transport::{probe::tls_wrap, DirectTransport, Transport}` + `transport::probe::parse_status_code`, so a "lean" feature can't drop the transport layer regardless.

**Decision: approach B — link `config-fetch` as-is; do NOT build a data-plane-gated `fetch` feature.** Gating the small data plane to save a few hundred KB while carrying an unavoidable 8 MB BoringSSL (required by `anytls`, required by `config-fetch`, which is the whole point of reusing the censorship-resistant fetch) is not worth the refactor risk. The Tauri app is already excluded from the core's size-tuned profile (root `Cargo.toml`), so the `<3 MB` core target does not apply to it. Plan Tasks 1 (core gating) is dropped; Task 2 uses `features = ["config-fetch"]`.

**Noted future optimization (not now):** on Windows/Linux the privileged `spark-service` is a persistent daemon that could perform the startup fetch over IPC (no BoringSSL in the app there), unlike macOS where the NE only runs while connected so the app must fetch itself. v1 keeps the uniform "app links the fetch" approach the spec chose; revisit if desktop app size becomes a concern.

## Verification

- **Unit:** `config_raw.json` `servers[]` → `ServerInfo` parsing (fixtures); the fetch-only feature builds standalone and `load_or_fetch` works against a fixture/staging endpoint; stale-while-revalidate ordering (cache rendered before the fetch resolves).
- **Binary size:** measure the app-binary delta from linking `spark-core` `features=["fetch"]`; confirm the fetch feature excludes the data-plane crates (`cargo tree` shows no `tun-rs`/`netstack`/`quinn` under the app).
- **macOS on-device:** fresh profile (no cache) → launch without connecting → list appears after the background fetch; quit + relaunch → list appears instantly from cache, then refreshes; connect → live latency/health overlays; confirm the tunnel and app share one `config_raw.json`.
