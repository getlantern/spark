# iOS support — on-device validation (iPhone)

Device: **iPhone 16 (iPhone17,3), iOS 26.5**. Date: 2026-07-09.
Build: **Tauri iOS debug `.ipa`** of branch `fisk/ios-support`, built with `npm run tauri ios build --debug`.
Signing: automatic provisioning (`-allowProvisioningUpdates`), Apple Development identity, team `ACZRKC3LQ9`;
profiles auto-created for `org.getlantern.spark` (app) + `org.getlantern.spark.tunnel` (NE extension).

## What this validates

iOS shipped as a **new platform target of the existing `tauri-plugin-spark-vpn`** — the same plugin
serving macOS + Android — reusing its `AppleControl`/`ne_spike` control path via `cfg(any(macos, ios))`,
with the Network Extension packaged as an **app-extension** inside the Tauri iOS app. No new plugin,
no Swift plugin shim (control is the Rust `ne_spike` → `NETunnelProviderManager` path, identical to
macOS minus system-extension activation).

## Packaging (the design's one flagged risk — retired)

- ✅ `SparkTunnel.appex` (the NE) compiles the shared `platforms/apple/Sources/SparkNE/{PacketTunnelProvider,FdResolver}.swift`
  against the Rust core's `SparkCore` module (from `SparkCore.xcframework`, iOS slice) — validated
  first by an unsigned iphonesimulator build (`BUILD SUCCEEDED`), then a signed device build.
- ✅ The signed `Spark.ipa` embeds a **co-signed** `PlugIns/SparkTunnel.appex`.
- ✅ Installed on the physical iPhone (`bundleID: org.getlantern.spark`) via `devicectl`.
- ✅ Launched on device; **both processes run** — `Spark.app/Spark` (UI) + `PlugIns/SparkTunnel.appex/SparkTunnel`
  (the NE, its own process), confirming the app + NE process model on iOS.

## Functional (device-verified)

- ✅ **UI renders** (SvelteKit in WKWebView) — home screen, controls.
- ✅ **Connect works** — the iOS "Allow VPN configuration" consent prompt (the `saveToPreferences`
  step) → tunnel establishes.
- ✅ **Traffic routes through the tunnel** — YouTube streamed through the connected tunnel.

## Memory — the 50 MiB NE jetsam cap (the iOS gate)

Measured the NE process (`SparkTunnel`, pid 4596) with `xctrace` (Activity Monitor template, attached),
12-second capture **while streaming YouTube through the tunnel** (worst case):

| Metric | Value |
|---|---:|
| **memory-physical-footprint (jetsam metric)** | **~8.4 MiB** (steady 8.42–8.45 MiB over 13 samples) |
| iOS packet-tunnel cap | 50 MiB |
| Headroom | **~6× under the cap** (~17% of the limit) |

This is a **debug** build (unstripped, `opt-level=0`); a release build will be smaller still. The
smoltcp buffer-tuning contingency is therefore **not needed** — the core comfortably fits the cap.
(`memory-real`/resident showed ~40 MiB, but that counts shared OS framework pages and is not what
jetsam kills on; the physical footprint is the enforced metric.)

## Not eyeballed this session (spot-check pending)

The individual control commands — server list + selection, website (domain/IP) split-tunnel,
routing mode (smart/full), ad-block — were **not visually verified on device** this session. They
reuse the exact `ne_spike::send_provider_message` → `PacketTunnelProvider.handleAppMessage` handlers
already proven on macOS (no iOS-specific code path), so they are expected to work, but a device
eyeball is a follow-up. App-based ("Apps") split tunneling is **hidden on iOS** (impossible on the
platform); domain/IP ("Websites") split tunneling remains available.

## Build/toolchain notes

- The iPhone runs iOS 26.5; building for it required the Xcode iOS platform component
  (`xcodebuild -downloadPlatform iOS`).
- Direct `xcodebuild` fails the app's "Build Rust Code" phase (it connects to a Tauri-run local
  server); build via `npm run tauri ios build`.
- `build-xcframework.sh` now pins `IPHONEOS_DEPLOYMENT_TARGET=14.0` / `MACOSX_DEPLOYMENT_TARGET=12.0`
  per slice so its objects target the same deployment target the apps link against. This clears the
  cosmetic `ld` "object file built for newer iOS version than being linked" warnings on a **clean**
  build (an incremental rebuild can retain cached BoringSSL objects at the old min; the warnings are
  harmless either way — the binary links and runs correctly).
- The NE Swift, packaging/co-signing, and the `objc2` `NETunnelProviderManager` iOS path are
  validated on-device (not host-unit-testable, no Robolectric-equivalent) — same posture as the
  Windows SCM/pipe and Android Messenger layers. The pure-Rust `cfg`-gating is covered by the
  workspace build/clippy/test gate.

## Bundle hygiene — `libapp.a` removed from Resources (2026-07-13, re-verified on device)

Copilot's #75 review flagged that the app bundle shipped `libapp.a` (the `gui_tauri_lib`
staticlib = the app's own Rust code) in **Resources/** on top of the Frameworks link. It was
redundant: a `.a` is a build-time link input compiled into the app binary, not a runtime bundle
resource, and the NE (`SparkTunnel`) links its own `SparkCore.xcframework` and never references
`libapp.a`. Root cause: `- path: Externals` was a `sources:` group, so xcodegen bucketed the `.a`
it finds there into the Resources copy phase.

Fixed via `buildPhase: none` on the Externals group in `project.yml` (source of truth) **and** by
removing the two `libapp.a in Resources` entries from the committed `pbxproj` — necessary because
`tauri ios build` runs `xcodebuild` on the committed `pbxproj` directly and does **not** regenerate
it from `project.yml`.

Re-verified on the iPhone 16: `npm run tauri ios build --debug` builds clean, the built `Spark.app`
bundle contains **no `.a`**, and the app installs, launches, **connects, and routes traffic** on
device — confirming the Resources copy was dead weight (the tunnel data path is unaffected; the NE
never used `libapp.a`).
