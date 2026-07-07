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
# GOAL — Tauri-on-Android: run the Spark UI as a real Android VPN app

## Mission
Bring up the existing Tauri/SvelteKit UI shell (gui-tauri/) as a native Android
VPN app at full feature parity with desktop, by extracting VPN control into ONE
cross-platform Tauri plugin. macOS + Android ship in this milestone; Windows and
iOS are reserved seams, not built.

## Why
ADR 0008 makes the Tauri shell the single UI across desktop + mobile (Android is
priority #1). Today the SvelteKit screens run only on macOS; Android has a separate
throwaway native Compose demo. The core routing-mode + split-tunnel features and the
Android JNI bridge already exist and are merged — what's missing is the Android app
scaffold + a VpnService plugin to drive the tunnel.

## Architecture (decided)
- One in-repo Tauri v2 plugin `tauri-plugin-spark-vpn` owns VPN control on ALL
  platforms. It is the UNPRIVILEGED control client — it never touches packets.
- Central seam = `TunnelControl` trait: connect / disconnect / status / servers /
  select_server / get|set_split_tunnel / get|set_routing_mode. Per-platform impls:
  - AppleControl (macOS now, iOS later): CROSS-PROCESS to the system extension via
    NETunnelProviderManager + sendProviderMessage. This is the moved `ne_spike` —
    lift it verbatim (relocation, not rewrite).
  - AndroidControl (this milestone): IN-PROCESS, same-UID — start the foreground
    VpnService + JNI (nativeRun / nativeSet*) directly; core .so loaded in-process.
  - ServiceControl (Windows/Linux, future stub): CROSS-PROCESS over the existing
    spark-ipc → spark-service crates.
- The process model is the crux: separate process + user on macOS/iOS/Windows/Linux;
  in-process on Android. Do NOT build a leaky "always in-process" abstraction.
- Durable settings (routing_mode / split_tunnel) persist app-side — shared
  cross-platform Rust; the settings dir is PLATFORM-PROVIDED, not hardcoded env.
  Delivery differs: providerConfiguration / nativeRun args at connect;
  sendProviderMessage / JNI live.
- `connect` contract (generalized from ne_spike's proven state machine): authorize
  (N OS permission gates) → deliver settings → start → gate on data-path-ready →
  resolve, or reject with a clear reason. macOS gates: sysext activation + VPN-config
  permission. Android gates: VpnService.prepare() consent + POST_NOTIFICATIONS.

## Deliverables
1. tauri-plugin-spark-vpn (Rust commands + TunnelControl + shared persistence;
   android/ Kotlin; ios/ stub; permissions/ capability JSON).
2. macOS control migrated verbatim into AppleControl; app crate keeps UI-shell only
   and registers the plugin.
3. `tauri android init` → gen/android; VpnService/foreground-service/consent Kotlin
   migrated from the demo; manifest permissions; debug APK builds for emulator ABIs.
4. TauriBackend invoke targets switch to plugin commands UNIFORMLY (no per-platform
   branch); MockBackend + all screens unchanged.
5. Delete platforms/android/demo.

## Acceptance
- Android emulator: UI renders (light+dark); connect → consent → tunnel up; servers
  populate; split-tunnel + routing-mode switches take effect (verify a domain routes
  per mode via the smart-routing on-device checklist).
- macOS no-regression: rebuild the notarized DMG; the existing smoke test behaves
  identically (connect, routing/split screens, live updates).
- Whole-workspace + android-target clippy/tests green; svelte-check 0/0; Windows/iOS
  stubs compile.

## Constraints
- NO macOS regression — the moved NE code is a relocation, not a rewrite.
- Verify exact Tauri v2 plugin macro / activity-result / permission-JSON APIs against
  current docs BEFORE coding.
- Repo standards: no unwrap/expect outside tests, thiserror at boundaries,
  clippy -D warnings, cargo fmt, no new crates without asking.
- Spike the one-.so-vs-two question on Android before committing to it.
```
