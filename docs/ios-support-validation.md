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

## TestFlight release build (App Store Connect) — 2026-07-24

The `--debug` build above is for on-device validation. For a **TestFlight** upload, one command:

```bash
ASC_API_KEY_ID=<KEYID> ASC_ISSUER_ID=<issuer-uuid> packaging/ios/build-testflight.sh
```

(`<KEYID>` is the `AuthKey_<KEYID>.p8` in `~/.appstoreconnect/private_keys/`; `<issuer-uuid>` is App
Store Connect → Users and Access → Integrations. The private `.p8` never enters the repo.)

**Gotcha the script works around:** `tauri ios build --export-method app-store-connect` archives fine,
but its own `exportArchive` uses **automatic** signing → on a headless machine (no Apple ID in Xcode) it
fails with `No Accounts` / `No profiles for 'org.getlantern.spark' were found`, *even with the profiles
installed*. The script keeps the archive Tauri built and re-exports it with a **manual**-signing
`ExportOptions` (`packaging/ios/ExportOptions-appstore.plist`, mapping each bundle id → its App Store
profile), which uses the local profiles and needs no account, then uploads with `altool`. Each run
defaults `BUILD_NUMBER` to a timestamp so TestFlight never sees a duplicate.

Verified 2026-07-24: **v0.1.0 build `2607241019`** built + exported + uploaded from a headless Mac
(no Apple ID signed into Xcode) — `UPLOAD SUCCEEDED`.

### `UPLOAD SUCCEEDED` does NOT mean the build reached testers

Export compliance is a separate gate, and it is silent: a build with no answer to Apple's
"non-exempt encryption?" question processes to `VALID` but sits at
`internalBuildState = MISSING_EXPORT_COMPLIANCE` and is delivered to **nobody**. Three uploads
(`2607241019`, `2607251356`, `2607261714`) were stuck this way before anyone noticed, because the
upload step reports success either way.

`ITSAppUsesNonExemptEncryption = false` now lives in
`gui-tauri/src-tauri/gen/apple/gui-tauri_iOS/Info.plist`, so uploads no longer land in that state.
(Tauri's generated plist doesn't include the key, which is why every upload re-asked. It's set on the
app bundle only — if a future upload still lands MISSING, check the `SparkTunnel` appex plist next.)

**Verifying an upload actually landed** — don't infer it from `altool`. Query App Store Connect:

```
GET /v1/builds?filter[app]=<appId>&sort=-uploadedDate      # processingState should be VALID
GET /v1/builds/<buildId>/buildBetaDetail                   # internalBuildState should be
                                                           # READY_FOR_BETA_TESTING
```
`org.getlantern.spark` is app id `6790541695`. Auth is an ES256 JWT from the same ASC API key the
upload uses (`kid` = key id, `aud` = `appstoreconnect-v1`); note JOSE wants the signature as raw
`r||s`, not the DER form most crypto libraries return.

To clear a build that is already stuck, `PATCH /v1/builds/<buildId>` with
`{"attributes": {"usesNonExemptEncryption": false}}` — it flips to `READY_FOR_BETA_TESTING` within
seconds. Note this is a **compliance declaration about the app's cryptography**, not a build setting:
confirm it with whoever owns that call before answering for a new crypto surface.

### The second silent gate: beta-group attachment

Compliance is only gate one. A build can be `VALID` **and** `READY_FOR_BETA_TESTING` and still reach
nobody, because a beta group with `hasAccessToAllBuilds = false` shows **only the builds explicitly
attached to it** — and a fresh upload is attached to nothing. `org.getlantern.spark` has one group,
**Team** (internal), with that flag `false`, and the only builds visible in it had been attached by hand.
The July 24–26 uploads were therefore invisible for two distinct reasons in sequence.

This one **cannot** be fixed once on the group: `hasAccessToAllBuilds` is create-only, and a PATCH is
rejected with

```
409 ENTITY_ERROR.ATTRIBUTE.NOT_ALLOWED
The attribute 'hasAccessToAllBuilds' can not be included in a 'UPDATE' operation
```

(Flipping "Automatically distribute builds" in the App Store Connect **UI** is the only way to change it
on an existing group; the API cannot.) So the fix lives on the build side:
`packaging/ios/build-testflight.sh` now ends by running **`packaging/ios/asc-attach.sh <build-number>`**,
which waits for processing, attaches the build to `TESTFLIGHT_GROUP` (default `Team`), and then
*verifies* the result instead of inferring it. Re-attaching is idempotent (HTTP 204), so re-running after
a timeout is safe. `TESTFLIGHT_GROUP=""` skips the step and says out loud that the build reaches no
testers.

Two states both count as success, and the distinction matters when reading the output:
`READY_FOR_BETA_TESTING` = processed and compliant but not yet distributed; **`IN_BETA_TESTING`** = being
distributed to a group, i.e. testers can actually install it.

Note the build number that reaches the API is not the one you passed: Tauri stamps `CFBundleVersion` as
`<marketing-version>.<build-number>`, so `BUILD_NUMBER=2607270436` appears as `0.1.0.2607270436` — the
script matches either form.

`asc-attach.sh` mints its own ES256 JWT with `openssl`, deliberately avoiding a Python/`PyJWT`
dependency (only Homebrew's Python has `cryptography` on the signing host). The trap is signature
encoding: `openssl dgst -sign` emits ASN.1 DER, while JOSE wants raw `r‖s` as two fixed 32-byte
integers — DER omits leading zero bytes and prepends one when the high bit is set, so both halves must be
re-padded to exactly 32 bytes.

### The third gate: build ORDERING within a version train

A build can pass both gates above — `VALID`, compliance answered, attached, `IN_BETA_TESTING` — and still
go unnoticed, because TestFlight groups builds by **marketing version** (`CFBundleShortVersionString`) and
orders them by `CFBundleVersion` **component-wise**. If your build doesn't rank as newest in its train, it
is delivered but not surfaced.

This cost three rounds of "the new build never appeared." Every `0.1.0` upload lost to a two-week-old one:

| Build | `CFBundleVersion` | First component |
|---|---|---:|
| Jul 13 | `20260713213236` | 20260713213236 |
| Jul 24–27 | `0.1.0.<timestamp>` | **0** |

Because Tauri stamps `CFBundleVersion` as `<marketing-version>.<--build-number>`, every build in the
`0.1.0` train is prefixed `0.1.0.` — so **no build number can ever outrank that single 14-digit
component**. The train is permanently poisoned; the only escapes are to bump the marketing version
(what we did — `0.1.1`, verified 2026-07-27 with build `2607271505`) or to detach the offending build
from the group.

**So don't stop at "is it delivered?" — check "is it the top build in its train?":**

```bash
# every build with its marketing version (the train) and CFBundleVersion (the ordering key)
GET /v1/builds?filter[app]=6790541695&sort=-uploadedDate     # → attributes.version
GET /v1/builds/<buildId>/preReleaseVersion                   # → attributes.version (the train)
```

Keep build numbers monotonic **and** single-component going forward. Note `0.1.1.<timestamp>` is still
four components where Apple's spec allows three; ASC tolerates it, and ordering is correct within the
train, but a two-component marketing version (`0.1`) would yield a spec-clean three.
