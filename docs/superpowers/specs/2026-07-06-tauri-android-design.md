# Tauri-on-Android — Design

**Status:** Approved (brainstorm), pending implementation plan.
**Goal:** Run the existing Tauri/SvelteKit UI shell (`gui-tauri/`) as a native Android VPN app at full feature parity with desktop, by extracting VPN control into one cross-platform Tauri plugin. **macOS + Android** ship in this milestone; **Windows + iOS** are reserved seams, not built.

## Context

ADR 0008 makes the Tauri shell the single UI across desktop **and** mobile (client priority: Android, Windows, iOS, macOS, Linux — Android first). Today the SvelteKit screens (Home, Routing Mode, Split Tunneling, Servers) run only on macOS. Android has a **separate, older native Jetpack Compose demo** (`platforms/android/demo`) that proved the `VpnService` + JNI data path but is not the product UI.

Already merged and reusable: `spark-core` (routing-mode + split-tunnel, cross-platform), the Android JNI bridge (`nativeRun(…, splitTunnel, routingMode)`, `nativeSetRoutingMode`, `nativeSetSplitTunnel`, `nativeServers`, `nativeSelectServer`, `nativeMarkConnecting`, `nativeWaitReady`), and the working demo `VpnService`/`VpnController`/foreground-service Kotlin. What's missing is the **Tauri Android app scaffold** and a **`VpnService` Tauri plugin** to drive the tunnel from the webview.

Decisions locked during brainstorming:
- **Scope:** full feature parity on Android in one milestone (connect + servers + split-tunnel + routing-mode all functional).
- **Architecture:** one cross-platform plugin owns VPN control on all platforms (the macOS NE control moves into it).
- **Demo:** migrate its Kotlin into the plugin as the single source of truth and **delete the demo**.
- **Forward-compat:** Windows + iOS must slot in later without restructuring, but are not built now.

## The crux: process model differs by platform

Per `docs/process-architecture-and-ipc.md`, the tunnel runs in a **separate process (and user)** on macOS (system extension), iOS (Packet Tunnel Provider app-extension), Windows/Linux (privileged `spark-service`), and **in-process, same-UID** on Android (`VpnService`, no `android:process`). The design must not assume a single process model.

Therefore the plugin is, on every platform, the **unprivileged control client** — it never touches packets. What varies is *how it reaches the tunnel*, captured by one seam:

```
TunnelControl (Rust trait — the plugin's seam)
  connect / disconnect / status / servers / select_server
  get|set_split_tunnel / get|set_routing_mode
    ├─ AppleControl   (macOS now, iOS later)  CROSS-PROCESS → system extension
    │     NETunnelProviderManager (start/stop/status) + sendProviderMessage (live)
    │     = the moved `ne_spike`; the core lives in the sysext, NOT the app
    ├─ AndroidControl (this milestone)         IN-PROCESS (same UID) → VpnService
    │     start/stop the foreground service + JNI (nativeRun / nativeSet*) directly
    │     = core .so loaded in THIS process
    └─ ServiceControl (Windows/Linux, future)  CROSS-PROCESS → spark-service
          spark-ipc (crates already exist); trait seam only, not built now
```

The trait gives one command surface without pretending the transports are the same.

## What the process model forces

1. **Durable settings** (`routing_mode`, `split_tunnel`) are owned **app-side / unprivileged on every platform** — the cross-platform Rust persistence (`routing_mode.txt`/`split_tunnel.json`, today in `gui-tauri/src-tauri/src/config.rs`) moves into the plugin and is shared. The **settings directory is platform-provided** (not hardcoded env logic), so desktop dirs, the Android files dir, and the iOS sandbox all slot in.
2. **Delivery of settings differs by transport**: at connect via `providerConfiguration` (Apple), `nativeRun` args (Android), or a start-IPC message (service); live via `sendProviderMessage` (Apple), a JNI setter (Android), or `spark-ipc` (service). Hidden behind `TunnelControl`.
3. **Live core state + config self-fetch live in the tunnel process** (separate on desktop/iOS, in-process on Android). The plugin forwards; it never owns the router or holds proxy secrets (which stay tunnel-side).
4. **`status` sources differ honestly**: `NETunnelProviderManager → connection.status` (Apple) / `spark-ipc` (service) across the boundary, vs. an in-process state flag the `VpnService` reports (Android).

## The `connect` contract (generalized from the proven macOS model)

`gui-tauri/src-tauri/src/lib.rs::ne_spike::connect` is a sequenced, async, permission-gated state machine and is the reference. Every platform implements the same shape:

> authorize (one or more OS permission gates) → deliver durable settings to the tunnel → start → gate on the data path actually being up → resolve, or reject with a clear reason (e.g. consent denied).

| Step | macOS (`AppleControl`, cross-process) | Android (`AndroidControl`, in-process) |
|---|---|---|
| Auth gate 1 | sysext activation + approval (`OSSystemExtensionRequest`) | `VpnService.prepare()` consent (Activity-for-result) |
| Auth gate 2 | VPN-config permission (`saveToPreferences` prompt) | `POST_NOTIFICATIONS` (Android 13+, foreground-service notification) |
| Deliver settings | `providerConfiguration` NSDictionary | `nativeRun(…, splitTunnel, routingMode)` args |
| Start | `startVPNTunnel` | `startForegroundService` → `nativeRun` on a worker |
| Gate-on-ready | `connection.status` / wait | `nativeWaitReady` |
| Live update | `sendProviderMessage` | JNI `nativeSet*` |
| Status source | `loadAllFromPreferences → status` | in-process state flag from the `VpnService` |

The macOS reference already handles: the full `OSSystemExtensionRequestDelegate` (`needs_user_approval`, `did_finish`, `did_fail`, `action_for_replacing → Replace`, `WillCompleteAfterReboot`); the nested-completion chain on the main queue (NETunnelProviderManager isn't `Send`); the user-declines-VPN-permission case; two persistence locations (app-side settings file **and** the app-group container `group.org.getlantern.spark` the sysext writes its fetched-config cache into). All of this lifts verbatim into `AppleControl`.

## Frontend seam

Because the plugin owns the commands on **all** platforms, `TauriBackend` switches its invoke targets from app commands (`invoke("spark_connect")`) to plugin commands (`invoke("plugin:spark-vpn|connect")`) — **uniformly, no per-platform branch**. `MockBackend` and every screen stay byte-for-byte unchanged. That is the payoff of the `SparkBackend` seam.

## Android integration

Kotlin migrated from the demo into the plugin's `android/`:
- A `@TauriPlugin` class owns the `VpnService` lifecycle; the plugin's Rust `mobile.rs` reaches it via Tauri's mobile bridge. `connect` runs the two gates from the webview: `VpnService.prepare()` → if an Intent is returned, launch via the plugin's Activity + activity-result callback (resolve on grant / reject on denial), then request `POST_NOTIFICATIONS` on Android 13+.
- Foreground service (`vpn`/`specialUse` type), `addDisallowedApplication(self)`, the `ACTION_STOP` self-stop, and the `nativeMarkConnecting`/`nativeWaitReady` readiness gate — lifted verbatim from the working demo.
- Tunnel core rides `libspark_android.so` (the `spark-android` JNI crate), loaded by the plugin's Kotlin; data dir = app files dir; CA roots already handled in core (SSL_CERT_FILE → bundled webpki roots). The plugin contributes the manifest bits (`BIND_VPN_SERVICE`, `FOREGROUND_SERVICE` + type, `POST_NOTIFICATIONS`, the `<service>`).

## Build & packaging

`tauri android init` generates `gen/android` (a Gradle project); Rust cross-compiles for the emulator ABIs via Tauri's Gradle integration, reusing the installed NDK + cargo-ndk; output is a debug APK. The macOS `packaging/macos/build-tauri-dmg.sh` path is unchanged — the plugin is just where the code now lives; the DMG still archives the app + sysext.

## Forward-compat seams (reserved, not built)

- **iOS:** `AppleControl` is shared macOS/iOS — Apple's NE API is common and the xcframework already builds iOS slices. Future iOS work is *packaging* the existing NE as an iOS app-extension inside a Tauri iOS target (ADR 0008 flags this as unproven), not rewriting control logic. The plugin ships an `ios/` stub dir.
- **Windows/Linux:** `ServiceControl` over the existing `spark-ipc` → `spark-service`. `desktop.rs` is cfg-branched — macOS impl now, a Windows stub returning a clear "unimplemented" now.

## Testing / acceptance

- **Android (emulator):** UI renders both themes; connect → consent → tunnel up; servers list populates; split-tunnel + routing-mode switches take effect (reuse `docs/smart-routing-on-device-validation.md` to confirm a domain routes per mode).
- **macOS no-regression gate:** rebuild the notarized DMG; the existing smoke test — connect + routing/split screens + live updates — must behave identically to today.
- Whole-workspace + android-target (`cargo ndk`) clippy/tests green; `svelte-check` 0/0; Windows/iOS stubs must still compile.

## Retire the demo

After migrating its `VpnService`/`VpnController`/foreground-service Kotlin + manifest into the plugin, delete `platforms/android/demo` and update `docs/STATE.md`.

## Risks / open questions

- Tauri-mobile + a `VpnService` plugin is the genuinely new engineering (ADR 0008).
- NE-in-Tauri-iOS packaging is unproven — deferred.
- **One-`.so`-vs-two on Android** (keep `libspark_android.so` as the tunnel artifact vs. fold JNI into the Tauri app lib): settle with a spike in the plan; leaning toward keeping `libspark_android.so` (clean tunnel-core vs. UI-glue separation).
- Exact Tauri v2 plugin macro / activity-result / permission-JSON API signatures: verify against current Tauri docs during planning before coding.

## Files

**Add:** `gui-tauri/tauri-plugin-spark-vpn/` (`src/{lib,commands,desktop,mobile}.rs`, `android/` Kotlin, `ios/` stub, `permissions/`); `gui-tauri/src-tauri/gen/android/` (generated by `tauri android init`).

**Modify:** `gui-tauri/src-tauri/src/lib.rs` (remove `ne_spike` + `spark_*` command bodies; register the plugin; keep UI-shell only); `gui-tauri/src-tauri/src/config.rs` (move persistence into the plugin; platform-provided dir); `gui-tauri/src/lib/tauri_backend.ts` (invoke plugin commands); `gui-tauri/src-tauri/tauri.conf.json` / capabilities (enable the plugin); `docs/STATE.md`.

**Delete:** `platforms/android/demo`.

**Reuse:** `spark-core`, the Android JNI (`platforms/android/src/lib.rs`), the demo's Kotlin (migrated), `spark-ipc`/`spark-service` (future `ServiceControl`), the smart-routing on-device checklist.

## Goal prompt (< 4000 chars)

```
# GOAL — Tauri-on-Android (execution)

## Mission
Run the existing Tauri/SvelteKit UI (gui-tauri/) as a native Android VPN app at full
desktop parity, by extracting VPN control into ONE cross-platform Tauri plugin
`tauri-plugin-spark-vpn`. Ship macOS (migrated) + Android (new); Windows/iOS = compiling
stubs. Branch: fisk/tauri-android. Spec+plan: docs/superpowers/{specs,plans}/2026-07-06-tauri-android*.

## Architecture (fixed)
Plugin = unprivileged control client everywhere, behind a `TunnelControl` trait (connect/
disconnect/status/servers/select_server/get|set_split_tunnel/get|set_routing_mode). Impls:
AppleControl (macOS, CROSS-PROCESS to the system extension = migrated ne_spike);
AndroidControl (IN-PROCESS same-UID: foreground VpnService + JNI); ServiceControl
(Windows/Linux future stub over spark-ipc). Durable settings persist app-side (shared Rust,
platform-provided dir); delivery/live/status differ per transport behind the trait.
Frontend: TauriBackend invokes plugin:spark-vpn|* uniformly; MockBackend + screens unchanged.

## Phases (risk-first)
P0 Spike: (0.1) fetch current Tauri v2 plugin docs; record exact @TauriPlugin/
run_mobile_plugin/activity-result/permission-JSON forms — write NO Tauri API code before
this. (0.2) `tauri android init`; build+run the UI on the emulator (MockBackend), check
dark mode. (0.3) confirm libspark_android.so loads+JNIs in the Tauri app process; keep it
as the tunnel .so.
P1 Skeleton: error.rs (thiserror), models.rs (mirror TS Status/ServerInfo/SplitTunnel),
control.rs (TunnelControl), persist.rs (move routing_mode/split_tunnel out of config.rs;
dir passed in, not hardcoded; port tests), commands.rs (#[command]→trait); register plugin
+ capabilities.
P2 macOS (GATED): relocate ne_spike VERBATIM into desktop.rs as AppleControl
(activate_extension, OSSystemExtensionRequestDelegate, connect state machine,
providerConfiguration inject, send_provider_message, status); move config.rs
ServerInfo/resolve; delete old app-crate spark_* cmds; point TauriBackend at plugin cmds.
GATE: rebuild notarized DMG + smoke test identical to PR #51. Do NOT start P3 until green.
P3 Android: migrate demo VpnService/VpnController/SparkBridge into plugin android/ (keep
package org.getlantern.spark so JNI symbols match) + cargoNdkBuild gradle task;
SparkVpnPlugin.kt (@TauriPlugin @Command handlers, in-process state flag for status);
connect = VpnService.prepare() consent (activity-result) → POST_NOTIFICATIONS (API33+) →
startForegroundService → nativeRun(settings) → nativeWaitReady; manifest (BIND_VPN_SERVICE,
FOREGROUND_SERVICE[_SPECIAL_USE], POST_NOTIFICATIONS, <service>); mobile.rs forwards via
run_mobile_plugin; filesDir persistence + null config (self-fetch).
P4 Seams+retire: Windows ServiceControl stub (Err unimplemented), ios/ stub; delete
platforms/android/demo; update docs/STATE.md; final gate.

## Acceptance
- Android emulator: UI both themes; connect→consent→tunnel up; servers populate+pin;
  Routing Mode→Full reroutes a normally-Direct domain while ad-blocked stays blocked and a
  bypassed domain stays Direct; disconnect tears down; reconnect needs no 2nd consent.
- macOS no-regression: notarized DMG smoke test identical to PR #51.
- cargo fmt + clippy --workspace --all-features -D warnings + cargo ndk clippy
  (spark-android + plugin) + cargo test -p spark-core --features smart-routing +
  npm run check all green; Windows/iOS stubs compile.

## Constraints
- macOS code is RELOCATED, not rewritten — no behavior change.
- Verify Tauri/JNI APIs vs current docs before coding (P0 gates this).
- Repo std: no unwrap/expect outside tests, thiserror at boundaries, no new crates without
  asking, cargo fmt, branch-not-main. Execute via superpowers:subagent-driven-development.
```
