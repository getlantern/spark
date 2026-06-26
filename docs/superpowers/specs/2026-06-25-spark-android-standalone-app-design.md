# Spark Standalone Android App — Design

**Status:** Approved (brainstorm 2026-06-25)
**Goal:** Promote `platforms/android/` from a demo/test harness into a shippable, hardened,
localized standalone VPN app for high-risk users in **Iran and Russia** (Android-only audience).
No integration with the existing Lantern Android app — this app stands alone.

## Context

The Rust core (`libspark_android.so`) is in good shape: it cross-compiles for `arm64-v8a` +
`x86_64`, all 293 core logic tests pass, egress is sound (`addDisallowedApplication` excludes the
in-process proxy from the tunnel, covering TCP **and** UDP/QUIC), and the full transport set is
wired (anytls, samizdat, shadowsocks, hysteria2, **fronted-meek**) along with config-fetch + the
fronted/scanner cold-start bootstrap.

The **app layer** (`platforms/android/demo/`) is a bare harness: auto-connects on launch, two
unstyled buttons, no foreground service, IPv4-only routing, no reconnection, no localization. This
project turns it into a real product while reusing the proven core unchanged.

## Decisions (locked during brainstorm)

- **Scope:** polished standalone app (not just the functional blockers).
- **Visual design:** mirror the existing Tauri/macOS app's design language, translated to
  **Android-native Jetpack Compose**.
- **Localization:** **Farsi + Russian + English**, with **full RTL** for Farsi. Strings are
  **reused from Lantern's existing translations** (`lantern/assets/locales/{en,ru,fa}.po`, gettext)
  rather than translated from scratch.
- **No settings screen.** Protocol/server choice lives in the server-selection screen
  (auto/"smart location" vs pinned, exactly like the Tauri app).
- **No protocol card on the home screen.** The protocol detail stays on the server-selection
  screen (the per-member subtitle shipped in spark #28/#29).
- **Kill-switch policy: fail-open.** Keep the current behavior — on cold-start failure / tunnel
  down the readiness gate stops the VPN and traffic falls back to direct. No kill-switch / no
  fail-closed work.

## Non-goals (explicitly out of scope)

- Lantern Android app integration.
- A settings screen.
- Fail-closed / kill-switch.
- Per-app split tunneling.
- Any change to the Rust transport/fetch core beyond **adding JNI bridge methods** that wrap
  existing core seams.

## Architecture

Five work areas, implemented in four phases (below). The Rust **data-path core is unchanged**;
all new native code is thin JNI glue over seams the Apple shim already exposes.

### 1. Native bridge (`platforms/android/src/lib.rs`, Rust/JNI)

The Compose UI needs live pool + status data the demo never surfaced. Because the core runs
**in-process** on Android (unlike Apple's out-of-process NE channel), these are direct calls — no
IPC. Add three JNI methods wrapping the same `fd_tunnel` seams the Apple C-ABI shim
(`spark_servers_json` / `spark_select` / `spark_status`) already wraps:

- `nativeServers(): String` — the live pool snapshot JSON (`transport::snapshot_to_json`),
  including the `protocol` field (spark #28/#29). Empty array when no pool is active.
- `nativeSelectServer(index: Int): Boolean` — pin a member (`index >= 0`) or auto (`index < 0`);
  returns whether it applied (mirrors the Apple `spark_select`).
- `nativeStatus(): String` — `disconnected | connecting | connected` so the UI reflects real
  state (mirrors `spark_status`).

If a needed `fd_tunnel` accessor is C-ABI-only today, expose a small `pub` Rust function in
`fd_tunnel` that both the Apple shim and this JNI method call (no logic duplication).

### 2. VpnService hardening (`SparkVpnService.kt`)

Keep the proven parts (`addDisallowedApplication` egress, fd handoff, the 30s readiness gate,
fail-open). Add the three blockers for real-world use:

- **Foreground service.** Create a notification channel and call `startForeground()` with a
  persistent, localized notification immediately on start. Manifest gains
  `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_SPECIAL_USE` (targetSdk 35) with the required
  `PROPERTY_SPECIAL_USE_FGS_SUBTYPE`, and `POST_NOTIFICATIONS`; the service declares the matching
  `android:foregroundServiceType`. The activity starts it via `startForegroundService()`.
  *Result: the tunnel survives the user backgrounding the app.*
- **IPv6.** Add an IPv6 tun address (ULA, e.g. `fd00:0:0:0::2/64`) and `addRoute("::", 0)` so IPv6
  is captured by the tunnel. If the core cannot proxy a v6 destination it fails closed for that
  flow — never leaks to the censored network. *Result: no IPv6 leak on dual-stack carriers.* The
  Apple tunnel has the **same IPv4-only gap today** (`PacketTunnelProvider.swift:79-81` configures
  only `ipv4Settings`, no `ipv6Settings`), so §6 backports the equivalent fix there for parity.
- **Reconnection.** Register a `ConnectivityManager.NetworkCallback` for the default network;
  on a usable-network change (Wi-Fi↔cellular), tear down and re-establish the tunnel so a moving
  mobile user stays connected. Debounce transient flaps.

### 3. Compose UI (mirrors the Tauri app)

Replace the demo `MainActivity` with a Compose app (Activity + `NavHost`, a `VpnViewModel` that
polls `nativeStatus`/`nativeServers` and drives a bound `SparkVpnService`). Two screens, styled to
the Tauri design language (surface/card radii, latency-pill colors, type scale):

- **Home:** a connect/disconnect control, live status (disconnected / connecting / connected /
  reconnecting), and the current location. **No protocol card.** Hardened VPN-consent flow
  (`VpnService.prepare` via the modern Activity Result API) triggered by the connect control.
- **Server selection:** "Smart location" (auto, ⚡) + all locations grouped by country (flag +
  latency pill + **protocol subtitle**), with pin/auto selection — the Android twin of
  `gui-tauri/src/routes/servers/+page.svelte`, fed by `nativeServers` / `nativeSelectServer`.

### 4. Localization (Farsi + Russian + English, full RTL)

- Extract the VPN-relevant strings from `lantern/assets/locales/{en,ru,fa}.po` and emit Android
  resources: `res/values/strings.xml` (en, default), `res/values-ru/strings.xml`,
  `res/values-fa/strings.xml`. A small build/dev script does the `.po` → `strings.xml` conversion
  so re-pulling updated Lantern translations is repeatable.
- RTL: rely on Compose's start/end semantics; mirror directional glyphs (back chevron, list
  chevron) for Farsi; verify each screen in an RTL preview. The manifest already has no
  `android:supportsRtl="false"`; set `supportsRtl="true"` explicitly.

### 5. Build / release wiring

Wire the native build into Gradle so the `.so` is never stale (the current manual-`cargo ndk`
footgun): a Gradle pre-build task runs
`cargo ndk -t arm64-v8a -t x86_64 -P 24 -o <jniLibs> build --release -p spark-android` and the APK
packs the produced `libspark_android.so`. App id, label ("Spark"), launcher icon, and version are
set for a real (non-demo) build.

### 6. Apple IPv6 parity (backport)

The IPv6 leak is cross-platform, so fix Apple too: in
`platforms/apple/Sources/SparkNE/PacketTunnelProvider.swift`, add `NEIPv6Settings` with a default
included route (`NEIPv6Route.default()`) alongside the existing `ipv4Settings`, so the macOS/iOS
tunnel captures IPv6 instead of letting it leak. Small, self-contained Swift change; ships as its
own commit/PR. No Rust-core change (the userspace netstack already receives whatever the OS routes
into the tun fd; if it can't service v6 the flow fails closed, same as Android).

## Module layout

Promote the app out of `demo/` into a real module (keep the existing `platforms/android/src/lib.rs`
crate as the JNI lib). Concretely: rename/restructure `platforms/android/demo/app` →
`platforms/android/app` (the shippable app), update `settings.gradle`/`build.gradle` accordingly,
and keep the Kotlin under `org.getlantern.spark`. Compose, ViewModel, the VpnService, the two
screens, and the string resources live here.

## Phasing (each phase is independently shippable + verifiable)

1. **Native bridge + VpnService hardening (+ Apple IPv6 backport).** Add the 3 JNI methods; add
   foreground service + notification, IPv6 capture, and network-change reconnection; backport
   `NEIPv6Settings` to the Apple `PacketTunnelProvider` (§6). *Gate:* on a device, the tunnel
   survives backgrounding, shows no IPv6 leak (test on a dual-stack network /
   `test-ipv6.com`-style check), and survives a Wi-Fi↔cellular switch; `nativeServers/status`
   return correct JSON while connected; the Apple build still connects with v6 captured.
2. **Compose UI.** Home + server-selection screens wired to the bridges, replacing the demo
   activity (no auto-connect). *Gate:* connect/disconnect works from the UI, status is live, the
   server list shows flags/latency/protocol and pinning takes effect.
3. **Localization.** `.po` → `strings.xml` for en/ru/fa; RTL verified for Farsi. *Gate:* switching
   device language to Farsi/Russian localizes all visible strings; Farsi renders RTL with mirrored
   chevrons.
4. **Build/release wiring.** `cargo-ndk` Gradle task + app id/label/icon/version. *Gate:* a clean
   `assembleRelease` (no manual pre-step) yields an APK with a current `.so` for both ABIs that
   installs and connects on a physical device.

## Verification

- **Native:** `cargo ndk -t arm64-v8a -t x86_64 build --release -p spark-android` builds both ABIs;
  the existing core test suite stays green (`cargo test -p spark-core --features <android set>`).
- **App (instrumented / manual on device):** the four phase gates above. Key in-country-relevant
  checks: tunnel persists in background (foreground service), no IPv4 **or** IPv6 leak (egress +
  v6 route), reconnects across network changes, and the fail-open path keeps the device usable on
  a cold-start fetch failure.
- **Localization:** visual RTL check for Farsi; spot-check Russian/Farsi strings against the
  Lantern `.po` source.

## Risks / notes

- **`FOREGROUND_SERVICE_SPECIAL_USE` review:** Play Store scrutinizes special-use FGS. Since this
  ships as a sideloaded/test build to Iran/Russia (not necessarily via Play), this is low-risk now,
  but note it if a Play listing is ever pursued.
- **IPv6 proxying:** routing `::/0` assumes the core either proxies v6 or fails the flow closed.
  Confirm during Phase 1 that v6 flows don't error in a way that breaks v4 (they should be
  independent); if the netstack can't accept v6 at all, fall back to **blocking** v6 (still no
  leak) rather than routing it.
- **Translation coverage:** the Lantern `.po` files may not contain every new spark string; any
  gaps get added to the English source and flagged for translation (English fallback meanwhile).
