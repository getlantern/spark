# iOS Support — Design

## Context

Spark ships today on macOS, Windows, and Android from a single Tauri (SvelteKit) UI plus the
shared `tauri-plugin-spark-vpn` plugin and the Rust `spark-core`. ADR 0008 mandates Tauri on **all
five platforms** (macOS, Windows, iOS, Android, Linux). iOS is the remaining gap.

**This adds iOS as a new *platform target* of the existing shared `tauri-plugin-spark-vpn`** — the
same plugin that already serves macOS and Android. It is *not* a new plugin, a new app, or a forked
control layer. iOS reuses the plugin's existing `AppleControl`/`ne_spike` control code (the same
code macOS uses), enabled for iOS via `cfg` gating, plus iOS-specific packaging. The SvelteKit UI is
unchanged (one screen difference, below).

### How much already exists (verified 2026-07-09)
Exploration found iOS is largely "finish on an existing foundation," not "build from scratch":
- **Rust core + Apple C-ABI** (`platforms/apple/src/lib.rs`) are already `#[cfg(any(target_os =
  "ios", target_os = "macos"))]` and compile for iOS. `spark_tunnel_run` → `fd_tunnel::run_fd_dispatch`
  is platform-agnostic (same entry Android's JNI uses).
- **`SparkCore.xcframework`** already ships `ios-arm64` + `ios-arm64-simulator` slices;
  `platforms/apple/build-xcframework.sh` already builds `aarch64-apple-ios` + `-sim` (BoringSSL /
  anytls / smart-routing all cross-compile, verified 2026-06-23).
- **`Sources/SparkNE/{PacketTunnelProvider,FdResolver}.swift`** were written for **both** iOS and
  macOS — no platform branches; the docstring states "one subclass for iOS and macOS (the OS
  difference is confined to fd resolution)." `FdResolver` already has the iOS KVC + fd-scan fallback.
- **The plugin's `AppleControl`/`ne_spike`** already drive `NETunnelProviderManager` /
  `sendProviderMessage` / `handleAppMessage` via `objc2` — **identical APIs on iOS**.

### Decisions (confirmed with stakeholder)
- **Approach A (NE as an app-extension target inside the Tauri iOS Xcode project), spike-first.**
  Chosen over B (separate NE build + post-build embed; kept as documented fallback) and C (native
  SwiftUI app; ruled out by ADR 0008). The single unproven risk — packaging + co-signing the NE
  inside a Tauri iOS `.ipa` — is proven on device in Phase 0 before anything is built on top.
- **Reuse the existing plugin; add iOS as a target.** No new plugin/control layer.
- **Control via the Rust `ne_spike` path, no Swift plugin shim** (unless a Phase-1 verify shows one
  is required). iOS is *simpler* than macOS: no system-extension activation — the NE is a bundled
  app-extension, so skip `OSSystemExtensionRequest` and go straight to
  `loadAllFromPreferences → saveToPreferences` (which fires iOS's "Allow VPN configuration" consent
  prompt — the iOS analog of Android's `VpnService.prepare`) → `startVPNTunnel`.
- **v1 scope: full feature parity minus app-based split tunneling** (impossible on iOS): connect/
  disconnect/status, server list + selection, domain/IP split-tunnel, routing mode (smart/full),
  ad-block. The "Apps" split-tunnel option is hidden on iOS.
- **DoD: working tunnel on a physical iPhone** (Apple Developer provisioning ready, team
  `ACZRKC3LQ9`). NE packet tunnels don't run in the simulator, so connect is device-only.

## Architecture & phasing

Sequenced **de-risk → reuse → wire → validate** so the one unknown surfaces first.

**Phase 0 — packaging spike (the gate).** `tauri ios init` → `gui-tauri/src-tauri/gen/apple/`. Add
a `PacketTunnelProvider` **app-extension target** to that Xcode project, referencing the *real*
`PacketTunnelProvider.swift` but with a stub `startTunnel` that only applies
`setTunnelNetworkSettings` and completes (no core yet). iOS entitlements (`packet-tunnel-provider`)
+ app group + provisioning. `tauri ios build` → install on the iPhone → prove the `.appex` is
embedded + co-signed and a `NETunnelProviderManager` can start it (even if it no-ops packets).
**Decision gate:** works → continue with A; intractable → fall back to B. Nothing downstream begins
until this passes.

**Phase 1 — control plane for iOS (reuse).** In `tauri-plugin-spark-vpn`, gate `AppleControl`/
`ne_spike` for `any(target_os = "macos", target_os = "ios")`; split the macOS-only
`objc2-system-extensions` usage (the `activate_extension()` / `OSSystemExtensionRequest` path) so
iOS skips it entirely. Verify `invoke('plugin:spark-vpn|…')` reaches the Rust commands on the Tauri
iOS target; if some API forces app context, add a thin `tauri-plugin-spark-vpn/ios/` Swift shim
**only** for that (fallback).

**Phase 2 — real tunnel + feature wiring.** Replace the spike's stub `startTunnel` with the real
`spark_tunnel_run(fd, …)` (Swift already shared with macOS). Wire every command through — servers,
select, split-tunnel, routing mode, ad-block — which already have `ne_spike` senders +
`handleAppMessage` handlers.

**Phase 3 — iOS polish + on-device gate.** Hide app-based split-tunnel in the UI on iOS; tune
smoltcp buffers for the 50 MiB NE cap; full on-device validation.

## Control flow

`invoke('plugin:spark-vpn|connect')` → plugin Rust command → `AppleControl` (Rust, in the Tauri app
process) → `NETunnelProviderManager` (via `objc2`, **identical to macOS** minus activation) → the
bundled `PacketTunnelProvider.appex` → `spark_tunnel_run(fd, …)` → `spark-core` netstack + forwarder
(packets never cross FFI). Live control (servers/select/splitTunnel/routingMode/adBlock) rides
`ne_spike::send_provider_message` → `PacketTunnelProvider.handleAppMessage` (both already exist).
Consent = the `saveToPreferences` VPN prompt; a denial surfaces as a clean connect failure.

## NE packaging (Approach A specifics)

- **Committed `gen/apple/`.** Tauri v2 treats `gen/apple` as generated-once-then-owned, so commit
  it and add the extension target directly to the `.pbxproj` (`tauri.conf.json` can't model extra
  Xcode targets). Re-init steps documented so the target can be re-applied if ever regenerated.
- **Shared Swift, one source of truth.** The extension target *references*
  `platforms/apple/Sources/SparkNE/{PacketTunnelProvider,FdResolver}.swift` (file refs, not copies)
  and links the `ios-arm64` / `ios-arm64-simulator` slices of the existing `SparkCore.xcframework`.
- **Bundle IDs match `ne_spike`:** app `org.getlantern.spark`, extension `org.getlantern.spark.tunnel`
  (the `providerBundleIdentifier` `ne_spike` already sets) — so control code is unchanged.
- **Entitlements (iOS flavor):** app + extension get `com.apple.developer.networking.networkextension
  = [packet-tunnel-provider]` (app-extension flavor, **not** `-systemextension`) and
  `application-groups = group.org.getlantern.spark`; the extension also keeps `network.client` /
  `network.server`. App IDs under team `ACZRKC3LQ9` with the Network Extensions capability.
- **Extension `Info.plist`:** `NSExtension` dict with `NSExtensionPointIdentifier =
  com.apple.networkextension.packet-tunnel` and `NSExtensionPrincipalClass = PacketTunnelProvider`
  (replacing the macOS system-extension keys).

## iOS-specific concerns

1. **50 MiB NE process cap (hard iOS limit).** The core runs *inside* the NE process, so the whole
   netstack + proxy + transports must fit. Mitigations: `cfg(target_os = "ios")` small smoltcp
   per-socket buffers (16–32 KiB), flow cap, buffer reuse; the already-merged 2-tokio-worker cap also
   helps (fewer thread stacks). Measured on-device once Phase 2 has a real tunnel; exceeding 50 MiB
   under load ⇒ the OS kills the tunnel, so this is a first-class gate, not polish.
2. **App-based split tunneling is impossible on iOS.** Hide the "Apps" split-tunnel row/screen when
   `platform() === 'ios'` (`@tauri-apps/plugin-os`, already a dependency). Domain/IP split-tunnel is
   unchanged; `apps_darwin.rs` stays `cfg(macos)`.
3. **Consent** = the iOS "Allow VPN configuration" prompt from `saveToPreferences`; connect handles
   grant/deny cleanly.
4. **fd resolution + data dir.** `FdResolver.swift` already handles iOS. `dataDir` for
   `spark_tunnel_run` uses the **app-group container** so the self-fetch config cache persists across
   the app/extension boundary (same pattern as macOS).

## Testing & DoD

- **Host / simulator:** Rust workspace gate (fmt/clippy/test) with the iOS targets compiling via
  `build-xcframework.sh` (`aarch64-apple-ios` + `-sim`); the SvelteKit UI runs in the **iOS
  simulator** to confirm screens render and the Apps row is hidden. NE can't run in the simulator, so
  connect is device-only.
- **On-device gate (physical iPhone — acceptance evidence):** install via `tauri ios build`/Xcode;
  grant the VPN prompt; verify connect/status, server list + selection, domain split-tunnel, routing
  mode, ad-block; **measure the NE process stays under 50 MiB under real traffic**; confirm traffic
  routes through the tunnel (ping-through / real browsing, like the Redmi).
- **Not host-unit-testable** (validated on-device, flagged in the PR): the Swift NE, the
  packaging/co-signing, and the `objc2` `NETunnelProviderManager` iOS path. Pure-Rust changes (buffer
  tuning, `cfg` gating) are covered by workspace tests.

## Files

- **Reuse as-is:** `core/`, `platforms/apple/src/lib.rs` (C-ABI), `SparkCore.xcframework` iOS slices,
  `platforms/apple/Sources/SparkNE/*.swift`, the SvelteKit UI, `ne_spike` senders + `handleAppMessage`.
- **Modify:** `tauri-plugin-spark-vpn/src/{lib.rs,desktop.rs}` (gate `AppleControl` for
  `any(macos, ios)`; `activate_extension` → macOS-only); `tauri-plugin-spark-vpn/Cargo.toml`
  (`objc2-system-extensions` macOS-only, `objc2-network-extension` macOS + iOS);
  `gui-tauri/src-tauri/tauri.conf.json` (iOS bundle config); the split-tunneling Svelte page (hide
  Apps on iOS); `core/` smoltcp buffer sizing (`cfg(ios)`).
- **Add:** committed `gui-tauri/src-tauri/gen/apple/` with the NE extension target; iOS app +
  extension entitlements; the extension `Info.plist`; an `release.yml` iOS build job (later phase). A
  thin `tauri-plugin-spark-vpn/ios/` Swift shim **only if** the Phase-1 verify shows `invoke` can't
  reach the Rust commands without one (fallback).

## Out of scope (v1)
- App-based (per-app) split tunneling — not possible on iOS.
- On-demand / always-on VPN rules (`isOnDemandEnabled`) — later.
- App Store submission / TestFlight distribution — separate effort; v1 is device install via Xcode.
- Linux (the fifth ADR platform) — separate effort.
