# Android `:vpn` Process Split — Design

## Context

Most Spark users are on low-end Android devices (e.g. a 2–4 GB Redmi). On-device profiling
of the connected app found the tunnel core is *lean* — ~1.3 MB native heap, ~3.2% CPU while
streaming YouTube through the tunnel, negligible battery — but the whole process idles at
63–71 MB PSS and climbs to ~121 MB PSS (174 MB RSS, ~56 MB swapped) under traffic, dominated
by the **Tauri WebView** (Chromium): ~54 MB "System", ~24 Mali GPU driver threads, 95 threads
total. On a low-RAM device that WebView memory is what gets swap-thrashed and risks LMK kills.

**Root cause:** `SparkVpnService` is declared in the plugin manifest with **no
`android:process`** attribute, so the `VpnService`, the Rust core, *and* the WebView all share
one process. A foreground `VpnService` keeps that whole process resident, so the WebView's
~50 MB + GPU threads cannot be reclaimed while the tunnel is connected — even when the UI is
backgrounded and the user is only streaming.

**The fix:** run the VPN service (and the core it hosts) in a private `:vpn` process, separate
from the UI/WebView. Then, when the user connects and backgrounds the app, Android can trim or
kill the UI process (reclaiming the WebView + GPU threads) while the lean `:vpn` process keeps
the tunnel alive.

This is a real refactor, not a one-line manifest change: today the core runs *inside* the
service (`SparkVpnService.kt` → `SparkBridge.nativeRun`), and the UI process's Tauri plugin
drives the core with **direct JNI calls** and reads an in-process state singleton. Once the
core lives in `:vpn`, those calls must cross a process boundary.

### Decisions (confirmed with stakeholder)
- **Mechanism: `Messenger` (Handler-based control-plane RPC).** Chosen over AIDL (typed but
  boilerplate-heavy; its concurrency is unused for our low-frequency, serialized control plane)
  and over broadcasts/file-polling (no natural request/reply channel; polling is the exact
  battery/wakeup cost we're cutting). Messenger is the smallest correct mechanism and matches
  the desktop "control channel only, data stays in-process" model.
- **Acceptance bar: structural correctness + measured evidence.** The split must land (tunnel
  survives UI-process death; every command works across the boundary), and a before/after
  Redmi `dumpsys meminfo` capture documents the WebView reclaim. The memory number is
  *evidence*, not a hard pass/fail gate (achievable reclaim depends on OS timing we don't
  fully control).
- **Scope: Android only.** The `tauri-plugin-spark-vpn` crate is shared with desktop/iOS; this
  change touches only the Android sources and manifest. Desktop/iOS behavior is unchanged and
  must stay green.

### Ground-truth constraints (verified against the current code)
- The Tauri plugin (`SparkVpnPlugin`, main process) today calls `SparkBridge.native*`
  **directly** for `servers` (`nativeServers`), `selectServer` (`nativeSelectServer`),
  `setSplitTunnel` (`nativeSetSplitTunnel`), and `setRoutingMode` (`nativeSetRoutingMode`), and
  reads the `SparkState` singleton for `status` and the connect-readiness gate. After the split
  these would hit a **second, core-less copy** of the `.so` in the main process, and the main
  process's `SparkState` would never update. These six paths are exactly what must move to IPC.
- `VpnController.start`/`stop`/`applyExcludedApps` already use **Intents**, which cross process
  boundaries unchanged. Connect, disconnect, and the live excluded-apps apply need no new IPC.
- `filesDir` (`/data/data/<pkg>/files/`) is **shared across the app's processes** — durable
  settings (`split_tunnel.json`, `routing_mode.txt`, `excluded_apps.json`, the self-fetch
  `config/` cache, the installed-apps cache) are visible to both processes. Persistence and the
  installed-apps enumeration can stay in the main-process plugin unchanged.
- `VpnService.onBind` returns a binder **only** for the `SERVICE_INTERFACE`
  (`android.net.VpnService`) action and null otherwise; the docs require an overriding subclass
  to "identify the intent and return the corresponding interface accordingly." So overriding
  `onBind` to return our control `Messenger` binder for a custom action while delegating to
  `super.onBind(intent)` for `SERVICE_INTERFACE` is the sanctioned pattern. (Verified against
  the Android/Microsoft `VpnService.onBind` reference, 2026-07-09.)
- VPN consent (`VpnService.prepare`) is **per-app (per-UID), not per-process**, and must be
  launched from an Activity — so it stays in the main-process plugin, and the `:vpn` service can
  `establish()` once consent is granted. The split does not change the consent flow.

## Architecture

Add `android:process=":vpn"` to the `<service android:name="…SparkVpnService">` element in the
plugin's `AndroidManifest.xml`. That moves `SparkVpnService` and everything it references —
`SparkBridge` (and thus `System.loadLibrary("spark_android")`), the Rust core, the TUN fd, the
network watcher, the foreground notification — into the private `<pkg>:vpn` process. The Tauri
runtime, the WebView, and `SparkVpnPlugin` remain in the main process.

**Load-bearing invariant:** after this change, `SparkBridge` is referenced **only** from
`:vpn`. The main-process plugin must not import or call `SparkBridge` at all, so the native lib
never loads (and never holds state) in the main process. Enforced by removing the four direct
`SparkBridge.*` call sites from `SparkVpnPlugin` and routing them through IPC.

Packets never cross the boundary: the core runs wholly inside `:vpn` with the fd. Only the
control plane (commands, status, server list) crosses, over a `Messenger`.

## Components

### `:vpn` process

**`SparkVpnService` (modified)** — unchanged core role (owns TUN/fd, runs `nativeRun`, network
watcher, foreground). Additions:
- A control `Handler` (on a dedicated `HandlerThread`, so control messages never touch the main
  looper) wrapped in a `Messenger`; its `IBinder` is returned from `onBind`.
- `onBind(intent)` dispatch: `if (intent?.action == SERVICE_INTERFACE) super.onBind(intent)
  else controlMessenger.binder`.
- `handleControlMessage(msg)`: `REGISTER` (store `msg.replyTo` as the client, immediately reply
  with current state), `UNREGISTER` (clear it), `GET_SERVERS` (reply `nativeServers()`),
  `SELECT_SERVER` (reply `nativeSelectServer(index)`), `SET_SPLIT_TUNNEL` /`SET_ROUTING_MODE`
  (one-way; call the native setter).
- A broadcaster: on every `SparkState` transition, send `MSG_STATE` to the registered client.

**`SparkState` (modified)** — add a single nullable hook `onChange: ((VpnState) -> Unit)?`
invoked at the end of `set()`. In `:vpn` the service wires it to its broadcaster; in the main
process it stays null. The main-process `SparkState` is the UI-observed mirror: written by
`SparkControlClient` from pushed `MSG_STATE` updates, plus the plugin's existing optimistic
`set(CONNECTING)` at connect start (harmless — an authoritative push overwrites it). The two
processes hold independent singletons; each has exactly one authoritative writer (the service in
`:vpn`, the client in main).

**`SparkBridge` (unchanged)** — loaded only in `:vpn`.

### Main process

**`SparkControlClient` (new)** — encapsulates all IPC plumbing so the plugin's command logic
stays clean:
- Binds to the `:vpn` control service (explicit Intent, component = `SparkVpnService`, action
  = `ACTION_CONTROL`) and registers a reply `Messenger`; rebinds transparently after
  `onServiceDisconnected`/`onBindingDied`.
- A **pending-request registry** (pure Kotlin, no Android types): `requestId → CompletableDeferred`
  with timeout eviction and reply dispatch. This is the primary unit-tested piece.
- A `VpnState`↔wire-ordinal mapper (pure Kotlin, unit-tested).
- Writes the main-process `SparkState` mirror on each pushed `MSG_STATE`.
- Public surface: `suspend fun getServers(): String`, `suspend fun selectServer(index): Boolean`,
  `fun setSplitTunnel(json)`, `fun setRoutingMode(mode)`, plus `bind()`/`unbind()`.

**`SparkVpnPlugin` (modified)** — `servers`/`selectServer`/`setSplitTunnel`/`setRoutingMode`
route through `SparkControlClient` instead of `SparkBridge`; `status` and `startAndAwaitReady`
keep reading `SparkState` (now the client-fed mirror). Binds the client in `init`; unbinds on
teardown. **All `SparkBridge` imports removed.**

**`VpnController` (unchanged)** — Intent-based `start`/`stop`/`applyExcludedApps` already cross
processes.

## Data flow

**Connect** — plugin `connect` → consent in main process → `VpnController.start` (Intent) starts
the `:vpn` foreground service → `startTunnel`/`nativeRun` → service sets `SparkState`
`CONNECTING`→`CONNECTED`/`FAILED`, each transition broadcast as `MSG_STATE` →
`SparkControlClient` writes the main-process `SparkState` mirror → `startAndAwaitReady` (reading
the mirror) resolves/rejects the Invoke. The client binds at plugin `init`, so it is already
receiving pushes before any connect. On `REGISTER` the service replies with current state,
closing the bind/connect race.

**Status / state (push)** — `status` reads the mirror synchronously (no round-trip). Because
`REGISTER` triggers an immediate state reply, a UI that (re)binds after the tunnel is already up
— e.g. the app reopened while `:vpn` kept running — syncs correctly. **New capability:** the
tunnel survives UI-process death, and the reopened UI shows the true state.

**Servers / selectServer (request/reply)** — `SparkControlClient` sends `MSG_GET_SERVERS` /
`MSG_SELECT_SERVER` with `replyTo` + a request id; the service handler calls the native method
and replies with the same id; the registry completes the deferred. Lenient fallbacks preserve
today's behavior: unbound or timeout → `"[]"` for servers, `false` for selectServer.

**Live setters (one-way)** — `setSplitTunnel`/`setRoutingMode` persist to the shared `filesDir`
on the UI side first (with the existing validation/canonicalization), then send a one-way
`MSG_SET_*` for the live push; the service calls the native setter. No reply — persistence is
the source of truth and the tunnel re-reads files on (re)start. `setExcludedApps` stays on the
existing `ACTION_APPLY_APPS` Intent.

## Lifecycle & error handling

- **onBind dispatch:** `SERVICE_INTERFACE` → `super.onBind` (VPN framework binder); `ACTION_CONTROL`
  → control `Messenger.binder`. The bind Intent is explicit (component set) so it can never be
  mistaken for the VPN-framework bind.
- **Bind lifetime vs tunnel lifetime:** the tunnel's lifetime is the *started* foreground
  service (started on connect, `stopSelf` on disconnect/failure/readiness-timeout). Binding is
  only the talk channel and must not drive the tunnel's lifetime. Concretely:
  - **At plugin `init`:** attempt a **non-auto-create** bind (`flags = 0`). This adopts an
    already-running `:vpn` (the reopened-while-connected re-sync). If no tunnel is running the
    bind is a no-op — crucially, it must **not** spawn an idle `:vpn` process (which
    `BIND_AUTO_CREATE` would).
  - **On connect:** `VpnController.start` has already created the foreground service, so a bind
    connects once it is up (the `ServiceConnection` fires on creation). The client sends
    `REGISTER` from `onServiceConnected`.
  - **On disconnect / service stop:** unbind, so no lingering binding keeps an otherwise-stopped
    `:vpn` alive.

  When the UI process is backgrounded/killed the binding drops and `:vpn` keeps running (it is a
  started foreground service, independent of any binding); on return the client rebinds and
  re-syncs via `REGISTER`. When disconnected there is no `:vpn` process at all (matches today).
- **Unbound / timeout:** every request/reply has a bounded timeout; on timeout or not-yet-bound,
  return the lenient default (`"[]"` / `false`). One-way setters issued while unbound are
  dropped — the persisted file still applies on the next (re)start.
- **Connection churn:** `onServiceDisconnected`/`onBindingDied` clear the bound `Messenger` and
  fail in-flight deferreds to their defaults; the client re-binds on next use.
- **Single client:** last-registered `Messenger` wins (the UI is the only client); a rebind
  replaces it. No multi-client fan-out is built (YAGNI).

## Testing & measurement

- **Pure unit tests (TDD, host, no Looper):** the pending-request registry
  (`register`→`resolve`, timeout eviction, unknown/duplicate id ignored) and the
  `VpnState`↔wire-ordinal mapping, each extracted into plain-Kotlin classes that take a `send`
  lambda and hold no Android types. The project has **no Robolectric**, so the
  `Messenger`/`Handler`/`bindService`/`onBind` glue is not host-unit-tested — the same posture
  used for the Windows SCM/pipe layers (validated on-device, flagged in the PR).
- **Compile gates:** the plugin's Android Kotlin must compile and the `.so` must build via
  `cargo-ndk` (`cargo ndk -t arm64-v8a clippy -p spark-android`); the shared plugin crate must
  stay green on the host (`cargo clippy`/`cargo test` in `gui-tauri/tauri-plugin-spark-vpn`) and
  its desktop/iOS paths unchanged.
- **On-device (Redmi — the acceptance evidence):** build/install; connect; verify all six
  cross-boundary commands (status, servers list, select server, live split-tunnel toggle, live
  routing-mode toggle, excluded-apps apply); **background the app and confirm the tunnel keeps
  working while the main process is trimmed/killed**; reopen and confirm state re-syncs. Capture
  **before/after `dumpsys meminfo` of the main process, backgrounded-while-connected**, as the
  documented memory win. Restore any masked device state (`dumpsys battery reset`) afterward.

## Files

**Modify:**
- `gui-tauri/tauri-plugin-spark-vpn/android/src/main/AndroidManifest.xml` — add
  `android:process=":vpn"` to the `<service>`.
- `.../java/org/getlantern/spark/SparkVpnService.kt` — control `Handler`/`Messenger`,
  `onBind` dispatch, `handleControlMessage`, state broadcaster; wire `SparkState.onChange`.
- `.../java/org/getlantern/spark/SparkState.kt` — add the `onChange` hook.
- `.../java/org/getlantern/spark/vpn/SparkVpnPlugin.kt` — route the four commands through
  `SparkControlClient`; bind/unbind the client; remove all `SparkBridge` references.

**Add:**
- `.../java/org/getlantern/spark/SparkControlClient.kt` — the main-process IPC client.
- `.../java/org/getlantern/spark/control/PendingRequests.kt` — pure-Kotlin correlation registry.
- `.../java/org/getlantern/spark/control/ControlProtocol.kt` — message codes + the
  `VpnState`↔wire mapper (pure Kotlin).
- Unit tests for `PendingRequests` and the state mapper (host, no Android runtime).

**Reuse (unchanged):** `SparkBridge` (now `:vpn`-only), `VpnController`, all `filesDir`
persistence + installed-apps enumeration in `SparkVpnPlugin`, the Rust `AndroidControl`/`mobile.rs`
bridge, the SvelteKit UI (the command surface is unchanged from the frontend's view).

## Out of scope
- Desktop/iOS behavior (unchanged; must stay green).
- The "cheaper wins" (WebView `onTrimMemory`, GPU/hardware-layer release, tokio worker tuning) —
  a possible follow-up, not part of this split.
- Multi-client control fan-out; a typed AIDL contract.
