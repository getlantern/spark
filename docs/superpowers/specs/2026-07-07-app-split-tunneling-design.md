# App-based Split Tunneling — Design

**Status:** Approved design (brainstormed 2026-07-07), ready for implementation planning.
**Scope:** Android, macOS, Windows, Linux. **iOS is out** (not technically possible — see below).

## Goal

Let the user **exclude specific apps from the VPN** — an excluded app's traffic egresses
**Direct** (its real IP), never through the tunnel. This complements the existing
**destination-based** split tunnel (`domains`/`ips`, which route by *where* a flow goes) with
**source-based** split tunneling (which route by *which local app* opened the flow).

Semantics mirror the existing feature: **exclude/bypass** (listed apps → Direct), matching the
UI's framing ("Add apps & websites to bypass the VPN"). An allowlist mode ("only these apps
tunnel") is explicitly **out of scope for v1**.

## The core insight: app-ST is source-attribution, not destination-matching

The existing split tunnel is **destination-based**: `rules::router::decide(dst_ip, domain)` picks
Direct-vs-Proxy from where the flow is going. That logic is shared in `spark-core` and works
identically everywhere.

**App split tunneling is *source*-attribution** — "which local app opened this flow" — which is a
**platform concern**, not something a destination-router can see. So it does **not** share one
implementation; the mechanism differs per OS. This design isolates that divergence behind two
seams (an in-core `ProcessResolver` for desktop, and the VpnService layer for Android) so the
config and UI stay shared.

Prior art we follow (verified 2026-07-07):
- **sing-box** `common/process/searcher_{darwin,windows,linux}.go` — attributes a flow to a
  process from the flow's **source (local) endpoint** via kernel socket tables, entirely in
  userspace (no special driver / NE provider). This is the desktop mechanism.
- **lantern-box** (`ruleset/`) uses sing-box's `process_name`/`process_path` filters — desktop
  keys on **process path**, Android on **package name**.
- **Lantern** `lantern-core/apps/` — per-OS installed-app *enumeration* with icons + a disk cache
  (`apps_darwin.go` scans `.app` bundles; `apps_windows.go` registry/Start-Menu; `apps_other.go`
  Linux `.desktop`; `app_mobile.go` Android PackageManager). This is the catalog mechanism.

## Three-layer architecture

App split tunneling decomposes into three concerns with clean boundaries.

### Layer 1 — Enforcement ("is this flow's app excluded? → Direct")

**Desktop (macOS / Windows / Linux): in `spark-core`.**
The netstack already surfaces the flow's source on `TcpFlow { original_dst, src, stream }`. Add a
per-OS **`ProcessResolver`** that maps `flow.src` → owning PID → **executable path**, and an
**app-bypass matcher** (a set of exe paths) checked in the router alongside the existing
`user_bypass` (absolute → `Direct`). Backends, mirroring sing-box:

- **macOS:** `sysctl(net.inet.tcp.pcblist_n | net.inet.udp.pcblist_n)` → scan for the PCB whose
  local endpoint matches `flow.src` → `so_last_pid` → `proc_pidpath(pid)` → exe path.
- **Windows:** `GetExtendedTcpTable/UdpTable(TCP_TABLE_OWNER_PID_ALL)` → PID →
  `QueryFullProcessImageName`.
- **Linux:** netlink `sock_diag` (or `/proc/net/{tcp,udp}`) → socket inode → `/proc/<pid>/fd`
  → `/proc/<pid>/exe`.

A small **LRU cache keyed on `flow.src`** (short TTL) avoids a kernel scan per flow — sing-box
does the same. The resolver returns `Option<PathBuf>`; `None` (unresolved) falls through to the
normal destination-based decision (fail-open into the tunnel, never fail-closed to leak).

**Android: in the VpnService (not core).**
Extend `SparkVpnService`'s existing `addDisallowedApplication(<self>)` loop to also exclude the
user's chosen packages. The OS enforces per-UID; excluded traffic never enters the TUN, so
`spark-core` is uninvolved. This is strictly cleaner than an in-core resolver on Android.

### Layer 2 — App catalog / picker (app layer, NOT core)

Per-OS enumeration of installed apps → `AppEntry { id, displayName, iconPngBytes, execPaths }`,
cached to disk (enumeration is slow). This is a **UI concern**, separate from enforcement, and
lives in the app layer (Tauri desktop backend / Android plugin), not `spark-core`.

- **Android:** `PackageManager` — installed apps, labels, icons, package names. (Kotlin, in the
  plugin.)
- **macOS:** scan `/Applications`, `/System/Applications`, `~/Applications` for `.app` bundles;
  read `Info.plist` (`CFBundleIdentifier`, `CFBundleName`, `CFBundleExecutable` → exec path);
  icon from the bundle. Filter helper/system bundles (cf. Lantern `apps_exclude_darwin.go`).
- **Windows:** Start-Menu `.lnk` + registry uninstall keys → exe path; extract icons. (Lantern's
  `apps_windows.go` is the heaviest reference; v1 may trim to Start-Menu + icon extraction.)
- **Linux:** XDG `.desktop` files → `Exec` → binary path; icon from the icon theme.

Reference structure to mirror in Rust: Lantern's `lantern-core/apps/` (per-OS
`loadInstalledAppsPlatform` + `getAppID` + icon loaders + a cache file in the data dir).

### Layer 3 — Config + UI (shared)

The bypass list gains **apps**. Because the match key is platform-specific and a device is one
platform, the on-disk list stores the **current platform's key** directly:

- **Android:** package names (e.g. `com.android.chrome`).
- **Desktop:** executable path(s) (e.g. `/Applications/Firefox.app/Contents/MacOS/firefox`).

The catalog (Layer 2) maps the user's selection (display name + icon) to the stored key. The UI's
existing **"Apps" tab** in `/split-tunneling` (currently "Coming soon") becomes the picker:
searchable installed-apps list, multi-select, persisted to config.

**Config schema.** Extend the persisted split-tunnel document with an `apps` array (a list of
platform-native keys). Enforcement delivery reuses the existing seams:

- **Desktop:** a new live-swappable app-bypass matcher in the core, delivered like `split_tunnel`
  today (a `spark_set_app_bypass(json)` C-ABI + the NE `handleAppMessage` `appBypass` case /
  Windows-Linux service IPC). **Live reload — no reconnect.**
- **Android:** the excluded-package list flows to `SparkVpnService`; changing it triggers
  **`restartTunnel`** — a live `establish()` swap (see below). Not delivered through the JNI data
  path (the OS enforces it at the TUN boundary, before the core).

## Android live rebuild (no reconnect)

Changing `addDisallowedApplication` requires a new `Builder.establish()` — but that does **not**
require tearing down the VpnService. `SparkVpnService.restartTunnel` (used today for Wi-Fi↔cellular
roaming) already performs exactly the needed operation: `nativeStop()` + join → build a fresh
`Builder` → `establish()` a new fd → `nativeRun` on it, on a dedicated `HandlerThread` (avoids
ANR), guarded by a generation counter so a stale readiness thread can't tear down the rebuild.

Applying a new app list = rebuild the `Builder` with the updated exclusion set and reuse
`restartTunnel`. The VpnService stays authorized (no consent re-prompt) and the system VPN stays
"connected" (no VPN-off flicker); the only visible effect is a brief data blip as in-flight
connections reset — the OS floor for this operation.

## Data flow

- **Desktop flow-open:** netstack yields `TcpFlow{src, original_dst}` → `ProcessResolver.resolve(src)`
  (cache-first) → if exe path ∈ app-bypass → `Direct`; else the existing domain/IP/routing-mode
  decision runs unchanged.
- **Android connect / list-change:** `SparkVpnService` builds the TUN with
  `addDisallowedApplication(self + excluded pkgs)`; excluded apps' sockets bypass the TUN at the
  OS level. A list change re-runs `restartTunnel`.

## Risks & spikes

1. **[P0 spike, gates desktop] macOS NE sandbox:** can the `org.getlantern.spark.tunnel` system
   extension read `net.inet.tcp.pcblist_n` via `sysctl`? It runs as root, so likely yes, but the
   NE sandbox may restrict it. If blocked, fallbacks (privileged helper, or a transparent-proxy
   provider) are materially uglier — so verify **first**.
2. **macOS source matching:** a flow's `src` in the NE packet tunnel is `10.0.0.2:<ephemeral>`;
   confirm the PCB's local endpoint matches (the ephemeral port is the disambiguator). Part of the
   P0 spike.
3. **Per-flow performance:** kernel socket-table scans are costly → the `src`-keyed LRU cache.
4. **Windows catalog effort:** Lantern's enumerator is ~1900 lines; scope v1 to Start-Menu + icon
   extraction, expand later.
5. **UDP / fake-IP interaction:** ensure process resolution also works for UDP flows (DNS etc.);
   `udp.pcblist_n` / UDP owner tables cover this.

## Phasing (each independently shippable)

- **P0 — macOS sysctl spike.** Prove the NE system extension can read `net.inet.tcp.pcblist_n` and
  match a known flow → PID → exe path. Gates the desktop path. *(Does not block P2.)*
- **P1 — core resolver + macOS backend.** `ProcessResolver` trait, macOS `sysctl` backend,
  `src`-keyed cache, app-bypass matcher, router wiring, `spark_set_app_bypass` FFI. Unit-tested.
- **P2 — Android (first, in parallel with P0/P1).** VpnService exclusion + `restartTunnel` live
  rebuild + PackageManager catalog + the "Apps" picker screen + config/persistence. Ships the
  easy, high-value platform end-to-end without waiting on the spike.
- **P3 — desktop catalog + UI.** macOS installed-apps enumeration + icons + the desktop Apps
  picker + config live-push (NE `handleAppMessage` `appBypass`). Completes macOS end-to-end.
- **P4 — Windows + Linux.** Their `ProcessResolver` backends + catalogs + service-IPC delivery.

## Out of scope (v1)

- **iOS.** Per-app VPN (`NEAppRule`) is honored **only for MDM-managed configurations**; a consumer
  App Store app cannot enumerate other apps or attribute flows. Not possible without enterprise MDM.
- **Allowlist mode** ("only these apps tunnel"). Exclude-only for v1.
- A polished Windows installed-apps catalog with full icon fidelity (trim for v1; expand later).

## Verification

- **Unit:** app-bypass matcher (exe-path match, absolute-Direct precedence over base rules);
  `ProcessResolver` cache (hit/miss/TTL); macOS PCB parse against a recorded `sysctl` blob;
  config (de)serialization with the new `apps` field.
- **macOS end-to-end:** exclude a browser, connect, load an IP-echo in that browser → real IP;
  a non-excluded browser → VPN IP. Confirm live-push (toggle an app while connected, no reconnect).
- **Android end-to-end (emulator + Redmi):** exclude an app, connect; verify its traffic egresses
  direct (and the VPN key stays up during a list change — `restartTunnel`, no re-consent).
- **Guardrail:** an unresolved process (`resolve → None`) fails **open** into the tunnel (never
  leaks a flow that should be tunneled).
