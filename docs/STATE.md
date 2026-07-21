# STATE

> Cross-session memory. Read at session start, update at session end. Append to the
> decisions log; never rewrite history. (Template + rules: PLAN.md Appendix A / §2.)

## Current position

**2026-06-19 — PICK UP HERE. The macOS AnyTLS product works end-to-end, with a Lantern-style GUI.**

What's DONE (this and prior sessions; all on `main`, pushed):
- **Full desktop stack** M1–M7 (TUN → netstack → transports → IPC service), **Android** M9, **Apple**
  M10 (now *live* — see below), **M11** AnyTLS transport.
- **ADR 0006 opening-gambit pipeline** (see [[opening-gambit-discovery-pipeline]] memory + the gambit
  log entries below): genome (`core/src/transport/gambit.rs`), boring executor mapping
  (`anytls/profile.rs` `for_boring`), Phase-1 wire shaping (`shaping/`), Path-B `compute_gambit` ABI +
  the P4 crypto menu (HKDF/AES-GCM/X25519 in `wasm/mod.rs`), the GA+JA4 inner loop (`discovery.rs`),
  and the **anchor/JA4 drift control** (`ja4.rs` + `anytls/anchor.rs`) with a scheduled CI oracle
  (`.github/workflows/anchor-drift.yml`) — **full JA4 parity with live Chrome, CI-verified**.
- **Live gates PASSED on macOS:** AnyTLS over both anytls-go (reference) *and* **sing-box** (production),
  **TCP + UDP/UoT**; egress = the relay.
- **macOS NE-AnyTLS PRODUCT (Model A)** — the headline: the DMG-installed Flutter app bundles the
  `SparkTunnel.systemextension`; **one-click Connect → full-tunnel over gambit-shaped AnyTLS → IP
  changes to the relay** (verified 2026-06-19 at whatismyipaddress.com), no service/sudo/manual routes.
  Enabled by the config-driven C ABI (`platforms/apple/src/lib.rs` `spark_tunnel_run` takes a TOML
  config) + `providerConfiguration["config"]` (Swift NE + `gui/macos/SparkVPN.swift`) + Dart `NEBackend`
  (`--dart-define=SPARK_CONFIG=<base64 TOML>`); `spark-apple` has an `anytls` feature on the macOS
  xcframework slice. Build: `packaging/macos/build-gui-dmg.sh` (bakes `SPARK_CONFIG`, notarizes).
- **GUI restyled to the Lantern look** (`gui/lib/main.dart`): light theme (#F8FAFB / cyan #00BDD6),
  the sliding pill toggle, a fixed **390×760 portrait window** (`MainFlutterWindow.swift` — needs
  `makeKeyAndOrderFront` or it launches hidden), AppBar + a VPN-status/Protocol/Routing settings card.
- **Samizdat transport — design + kID spike DONE 2026-06-19 (branch `samizdat-transport`, PR #1).**
  Second M11 transport: client-side, **wire-interop with deployed lantern-box/sing-box
  `"samizdat"` servers**. Design: `docs/samizdat-transport-design.md` + **ADR 0007**. Decisions —
  single TLS 1.3 + **H2 CONNECT mux via the `h2` crate** (scoped no-hyper exception; H2 is inside TLS
  so its fingerprint is moot), REALITY auth in the TLS `legacy_session_id`, reuse the AnyTLS Chrome
  connector + `shaping/` + `ring` + the session-pool pattern. **kID SessionID-injection spike PASSED**
  (`/tmp/kid-spike`): a chosen 32-byte `legacy_session_id` reaches the wire in a Chrome TLS-1.3 ClientHello with
  JA4 intact, on **stock boring2 (NO fork)** — the `boring-sys2` patch is a recorded-but-unused
  fallback. **Verified API facts (don't re-verify):** the kID recipe = `SSL_SESSION_new(ctx)` →
  `SSL_SESSION_set_protocol_version(TLS1_2_VERSION)` → `SSL_SESSION_set1_id(&sid32)` →
  `SSL_SESSION_set_time(now)`/`SSL_SESSION_set_timeout(big)` → `SSL_set_session(ssl, s)` →
  `SSL_SESSION_free(s)`; BoringSSL classifies kID from id-present + ticketless and emits it as
  `legacy_session_id` even in a 1.3 hello (NO cipher/master-key setter — neither needed nor exposed by
  BoringSSL). boring2's `SslRef::as_ptr` needs `foreign_types_shared::ForeignTypeRef` in scope. Client
  auth needs **no ECDH** — `derivePSK` HKDFs the server pubkey bytes directly as IKM.

**NEXT (in rough priority):**
0. **Samizdat (branch `samizdat-transport`) — chunked build per §10 of the design doc.**
   - **Chunk 1 — auth.rs DONE 2026-06-19 (TDD; commit `977242e`).** New `samizdat = []` cargo feature
     gates `core/src/transport/samizdat/`. `auth.rs` = PSK + 32-byte SessionID in pure `ring`
     (`HKDF-SHA256(ikm=serverPubKey, salt=shortID, info="SAMIZDAT")` → `HMAC-SHA256(PSK, nonce)[:16]`,
     layout `shortID(8)‖nonce(8)‖tag(16)`). 3 tests vs vectors captured from Go `auth.go` +
     cross-checked through the package's `VerifySessionID` (ok=true; generator `/tmp/sz-vec`). clippy
     -Dwarnings + fmt clean (feature on/off); default build unaffected.
   - **Chunk 2 — session_id.rs DONE 2026-06-19 (TDD; commit `aff48c8`).** `inject_session_id(config,
     &id)` installs the 32-byte auth SessionID as the ClientHello `legacy_session_id` via the kID
     trick on stock boring2 (FFI: `SSL_SESSION_new`→`set_protocol_version(TLS1_2)`→`set1_id`→
     `set_time`/`set_timeout`→`SSL_set_session`+`SSL_SESSION_free`). `samizdat` feature now =
     `["dep:boring2","dep:tokio-boring2","dep:boring-sys2","dep:foreign-types-shared"]`
     (added `boring-sys2` + `foreign-types-shared` to workspace deps — FFI access to the already-present
     boring2). Test = in-tree hermetic ClientHello capture (asserts the id lands + TLS 1.3 still
     offered). clippy/fmt clean; default build unaffected. NOTE: `samizdat` does NOT yet enable the
     `anytls` feature — the next TLS-connect wiring should reuse `anytls/tls.rs`'s Chrome connector
     (add `"anytls"` to the feature then, or extract a shared connector helper).
   - **Chunk 3 — h2_mux.rs DONE 2026-06-19 (TDD; commit `fe2265e`).** `H2Conn::handshake` (client
     handshake + driver task aborted on drop) + `H2Conn::connect(target)` (CONNECT with
     `:authority=target`, no `:scheme`/`:path`); `H2Stream` adapts `(SendStream, RecvStream)` ⇄
     `AsyncRead+AsyncWrite` with real H2 flow control (reserve/poll_capacity on write,
     release_capacity on read; `poll_shutdown`→END_STREAM half-close). New deps `h2` + `http`
     (samizdat feature only). Test = in-process h2 CONNECT→echo round-trip. 5 samizdat tests green.
     Verified-API note (don't re-verify): h2 0.4.15 / http 1.4.2; CONNECT request = build
     `Authority` then `Uri::from_parts` (authority-only is valid; `"host:port"` parses ambiguously
     as a URI); `Pseudo::request` drops scheme/path for CONNECT.
   - **Chunk 4 — transport.rs + config wiring DONE 2026-06-19 (commit `f95e8b2`).** `SamizdatTransport`
     impls `Transport` (one shared, reactively-reconnecting `H2Conn` multiplexes all CONNECT tunnels)
     + `UdpTransport` (Unsupported, TCP-only v1). `establish()` = TCP → `inject_session_id` into the
     Chrome ClientHello → `tokio_boring2::connect` (assert ALPN==h2) → `H2Conn::handshake`. Reuse:
     **extracted `anytls::tls::configure()`** (behavior-preserving split of `connect()`) so samizdat
     shares the JA4-verified connector; `samizdat` feature now enables `anytls`. Config
     `SamizdatConfig{server,server_pubkey hex32,short_id hex8,sni}` + `TransportConfig.samizdat` +
     `from_config` precedence (after anytls) + `not(samizdat)` hard-error stub. Tests: TOML parse,
     from_config builds/rejects bad hex, UDP-unsupported. 10 samizdat tests green; anytls still green;
     clippy/fmt/workspace/default all clean. **The full client stack now compiles + unit-passes; the
     remaining work is purely live verification (no server stood up in this session).**
   - **Chunk 5 — INTEROP GATE PASSED 2026-06-19 (commit `40dcb6e`). ✅✅** The spark client tunneled
     an HTTP request through a **real `getlantern/samizdat` server** (local harness) and got
     **`HTTP/1.1 200 OK` + body** back. **Proves the two things the kID spike could not:** (1) boring's
     kID-session Chrome ClientHello handshake **completes** against a real Go `tls.Server` (the
     fabricated TLS-1.2 session for injection doesn't break the 1.3 handshake), and (2) the Go server's
     `VerifySessionID` **accepts** spark's SessionID → wire-exact REALITY auth interop. Client half =
     `core/examples/samizdat_interop.rs` (`from_config` → `dial` → GET → assert 200; run with
     `--features samizdat`). **Reproduce the harness** (`/tmp/sz-interop`, throwaway — Go module with a
     `replace` to the local samizdat checkout): `main.go` = `samizdat.GenerateKeyPair`/`GenerateShortID`
     + a self-signed ecdsa cert + `samizdat.NewServer{PrivateKey,ShortIDs,CertPEM,KeyPEM,Handler}` where
     `Handler` dials `destination` + `io.Copy`s both ways (== the unexported `defaultConnHandler`) +
     an origin `http.Server`; prints `SZ_SERVER/PUBKEY/SHORTID/TARGET`. Then
     `SZ_*=… cargo run -p spark-core --example samizdat_interop --features samizdat`. Gotcha found+fixed:
     the client must `shutdown()` (H2 END_STREAM half-close) after writing, else the server's upload
     copy never EOFs and `read_to_end` hangs.
   - **NEXT (optional live step): `sudo spark run` TUN gate.** Needs root + a real Samizdat server;
     use an **IP** target (`curl https://1.1.1.1` — avoids DNS, since samizdat is TCP-only). Lower
     marginal value now — the netstack→`Transport` seam is transport-agnostic and already TUN-gated for
     AnyTLS; the interop gate proved the samizdat-specific stack.
   - **Chunk 6 — shaping reuse DONE 2026-06-19 (commit `e15752a`). ✅** `SamizdatTransport` wraps the
     TCP in `SegmentShapingStream` per the shared `[transport.shaping]` `WirePlan` (TCP_NODELAY +
     Geneva ClientHello fragmentation), mirroring AnyTLS — the Go client fragments by default. No-op
     unless configured. **Re-live-gated with `SZ_SHAPING=sni_boundary`:** a fragmented ClientHello
     still completes the handshake + interops → HTTP 200. (The example now reads `SZ_SHAPING`.)
   - **Deferred follow-ups (non-blocking):** a multi-conn pool + idle sweep (currently one shared conn,
     reactively reconnected), UDP-over-CONNECT, and the optional `sudo spark run` TUN gate. **MERGE:**
     branch `samizdat-transport` → **PR #1** (https://github.com/getlantern/spark/pull/1); client
     complete + unit-tested + live-gated (incl. fragmentation); ADR 0007 + design doc committed.
1. **Runtime relay config — file-read DONE 2026-06-19; verify + harden next.** `NEBackend`
   (`gui/lib/ne_backend.dart`) now reads a runtime **`config.toml`** from the app-support dir (macOS:
   `~/Library/Application Support/org.getlantern.spark/config.toml`) on connect, precedence:
   file → baked `SPARK_CONFIG` → `SPARK_PROXY` → direct. So the relay is no longer pinned at build
   time — drop a TOML there (download / fetch from a trusted location / a future in-app importer) and
   Connect uses it. **Remaining:** (a) live-verify with a notarized DMG built *without* `SPARK_CONFIG`
   + a `config.toml` + a relay; (b) an **in-app importer/fetcher** (file picker / fetch-from-URL) +
   surfacing server/region in the UI; (c) **config trust** — since it "can come from anywhere",
   sign+verify the config (reuse the `SignedGambit` Ed25519 pattern) before trusting a relay/password.
2. **A lasting AnyTLS server** (a real deployment) instead of the ephemeral gate droplets the live
   gates used — so an installed app keeps working.
3. **iOS** NE-AnyTLS: the macOS slice has `anytls`; iOS returns -1 (BoringSSL-for-iOS unbuilt).
4. **P4 unconstrained** regime (module emits raw CH bytes + drives the handshake via the crypto menu)
   — deferred; "build only if constrained can't beat a censor."
5. **Server-side P5 outer loop** (arrivals oracle, A/B bandit, LLM, signed deploy) — lives in
   **lantern-cloud / Go**, NOT this repo (design §5.5); spark exposes the seam.

**Ephemeral relay status (2026-06-19): TORN DOWN.** The demo anytls-go droplet (`192.34.56.224`, DO
id `578876805`) + its ssh-key were deleted at session end. So the installed `dist/spark-gui-ip-...dmg`
app's **Connect now fails** (relay gone) — rebuild + re-provision to use it again. Re-provision recipe
(≈5 min, see the live-gate entries below): a fresh DO droplet + ephemeral ssh-key → anytls-go
`v0.0.12` linux-amd64 zip (extract with python3, no `unzip`) → systemd `anytls-server -l 0.0.0.0:443
-p <pw>` → write `[transport.anytls] server/password/sni` + `[transport.shaping] segment_split =
sni_boundary` → `base64` it → `SPARK_CONFIG=<b64> ./packaging/macos/build-gui-dmg.sh` → install,
approve sysext, Connect → IP changes. (No standing infra remains on the Lantern DO account.)

### Milestone history
- Milestone: **M7 — control-plane IPC + service split. DONE 2026-06-15** (code + through-the-
  service gate live-verified on macOS; design in `ipc-service-split-design-m7` memory). The full
  desktop stack (M1–M7) is now live on macOS. **M8 packaging session 1 done 2026-06-15:**
  cross-build checks, systemd/launchd units + example config in `packaging/`,
  `scripts/size-budget.sh` (both binaries ~40% of the 3 MB budget). **Windows named-pipe control
  transport done 2026-06-15** — the *whole* workspace now cross-builds for Windows
  (`cargo check --target x86_64-pc-windows-msvc`, warning-free), not just core/ipc: `service::pipe`
  serves an admin-only named pipe (SDDL DACL = the auth boundary, no `SO_PEERCRED` analog), and
  `main.rs`/`cli` cfg-split the bind/connect. **M8 packaging session 2 done 2026-06-15:**
  `.github/workflows/ci.yml` (fmt+clippy+test on all 3 OSes + both cross-checks + size budget)
  and `release.yml` (on a `v*` tag: per-target release build → size gate → package → publish to
  the GitHub Release); packaging defs — `packaging/debian/build-deb.sh` (hand-rolled `dpkg-deb`,
  no cargo-deb), `packaging/homebrew/spark.rb`, Windows `.zip`. **Windows SCM service handler done
  2026-06-15:** `spark-service` is now a dual-mode binary (`service::winsvc` via the
  `windows-service` crate) — runs as a real Windows service under the SCM (RUNNING / STOP /
  STOPPED) or in the foreground from a console; `sc create spark …` registers it and it responds
  to `sc stop/start`. The daemon body moved to a shared lib module (`service::daemon`); `main.rs`
  is a thin shim; unix behavior unchanged. **Windows MSI done 2026-06-15:**
  `packaging/windows/spark.wxs` (WiX v4/v5, built in CI via the `wix` dotnet tool) installs both
  binaries + registers the service (`ServiceInstall`/`ServiceControl`, LocalSystem auto-start) +
  ships the example config; well-formed XML, first real build happens in CI. M8 packaging is now
  feature-complete; remaining are **live verifications**: a **release run** (push a tag),
  Homebrew-tap push, a **live Windows run** (no host yet), and service logging→Event Log. GUI
  deliberately deferred (M7 scope; CLI is the client).
  **M7 refinements all landed 2026-06-15** (3 commits): (1) kill-switch signaling — unexpected
  data-path exit fires `FellOpenToDirect` + sets `direct_fallback`, `[kill_switch] fail_closed`
  knob; (2) **supplementary-group resolution** — `service::groups` resolves a peer uid's full
  login group set (`getpwuid_r`+`getgrouplist`) so `spark` membership counts as a *secondary*
  group, not just primary; (3) **backpressure** — a slow subscriber is kept and told how many
  pushes it missed via `Push::Dropped{count}` (drop-newest + accounting); (4) **active
  route-management** — opt-in `[routing] manage` full-tunnel via `core::routing::RouteManager`
  (split-default 0/1+128/1 covers; `Teardown::RestoreDirect`/`Block` for fail-open/closed). The
  only remaining M7 piece is the **live route gate under root** (command construction is
  unit-tested but the `route`/`ip` calls aren't yet exercised live). The M4 tunnel-server / M6
  SIGINT live gates also pending.
- **M9 (Android) DONE 2026-06-16 — gate PASSED on the emulator.** s1: `spark-core` cross-compiles
  for `aarch64-linux-android` + `Tun::from_fd` seam (`Tun::open`/`name` gated off android). s2:
  `platforms/android` cdylib (`libspark_android.so`) + `core::android::run_tunnel` (adopts the
  `VpnService` fd → netstack → direct forwarder; `nativeStop` fires a global `Notify`); primitive
  JNI (no `jni` crate); core `tracing` → logcat via a liblog bridge. s3: `platforms/android/demo`
  Gradle app (AGP 8.9.1/Gradle 8.11.1/Kotlin 2.1.21, minSdk 24) — `SparkVpnService` establishes a
  full-tunnel + `addDisallowedApplication(self)` + `detachFd` → `nativeRun`. **Gate (Medium_Phone_
  API_35, arm64):** Android reports VPN **CONNECTED + VALIDATED**; an `adb shell` HTTP request
  (uid 2000 → tun0 → spark → upstream) returned **`HTTP/1.1 204`**; logcat shows the core forwarding
  TCP flows; force-stop cleanly releases `tun0`. Remaining (later): richer config/tunnel-server on
  android, cargo-ndk as a Gradle pre-build task.
- **M10 (Apple) sessions 1–2 done 2026-06-16; live gate BLOCKED on provisioning.** s1: decided
  **fd-trick + packet-object fallback / C ABI / unified provider** (deep research, see decisions
  log); `core::android`→`core::fd_tunnel` (shared by Android JNI + Apple C ABI); `platforms/apple`
  staticlib builds for ios/ios-sim/darwin. s2: `SparkCore.xcframework` (3 slices); the **unified
  Swift `PacketTunnelProvider`** (iOS+macOS) + `FdResolver` (KVC → public fd-scan) + entitlements/
  Info.plist; `swift build` **compile-verifies the provider + the C FFI**. **Live gate can't run
  here:** only a Developer ID cert, no Xcode-logged-in team, 0 provisioning profiles, and
  `systemextensionsctl developer` is SIP-blocked. The NE entitlement needs a profile from team
  `ACZRKC3LQ9` (human step). Reachable path = macOS **app-extension** + automatic signing under
  that team; steps in `platforms/apple/README.md`. iOS gate needs a device.
- **M10 (Apple) session 3 (2026-06-16) — macOS app+extension BUILD+SIGN verified; live provider
  launch blocked.** After Adam signed Xcode into team `ACZRKC3LQ9`: XcodeGen project (`project.yml`)
  for SparkApp (SwiftUI harness) + SparkTunnel (Packet Tunnel app-extension embedding the
  xcframework + `Sources/SparkNE`). `xcodebuild -allowProvisioningUpdates` **auto-minted an Apple
  Development cert + `Mac Team Provisioning Profile: org.getlantern.spark{,.tunnel}` with the
  `packet-tunnel-provider` entitlement** — so spark NE signing is proven; the signed `.appex`
  carries the entitlement. **App side runs** (consent → save → `startVPNTunnel`). Fixes found live:
  the managing app ALSO needs the NE entitlement (else `saveToPreferences`=permission denied);
  app `GENERATE_INFOPLIST_FILE`; full extension Info.plist keys (CFBundleIdentifier) for the embed
  prefix check; `NSApplicationDelegate` auto-connect. **Blocker:** macOS won't *host the provider*
  — `startTunnel` never runs, connection → Disconnected. It's the NE host-validation gate for a
  **dev-signed, un-notarized** app. **Diagnosed (s3 cont.):** `nesessionmanager` *registers* the
  plugin but won't *host* the un-notarized app-extension; the Developer-ID export then proved the
  rule — non-App-Store macOS NE must be a **system extension** (`packet-tunnel-provider-systemextension`),
  not an app-extension (`packet-tunnel-provider` = App-Store only). **Converted to a system
  extension** (commit `da0f239`, lantern's model): `Sources/SparkTunnelMain/main.swift`
  (`NEProvider.startSystemExtensionMode`), `NetworkExtension` Info.plist dict, `-systemextension`
  entitlement (sandbox off), app `system-extension.install` + `OSSystemExtensionRequest` activation
  (`SysExt`). **Compiles** (`xcodebuild CODE_SIGNING_ALLOWED=NO build` SUCCEEDED). **Last mile
  (human, Xcode GUI):** `xcodebuild` CLI auto-provisioning mints a *development* profile that can't
  carry the systemextension entitlement — it's **distribution-only** (confirmed in both CLI and the
  Xcode GUI: "profile doesn't match the networkextension entitlement"). **Resolved the signing
  model by decoding lantern's working profile** (`MacOS Tunnel Development Profile` = a *Developer-ID*
  profile, `ProvisionsAllDevices=true`, entitlements `packet-tunnel-provider-systemextension` +
  `system-extension.install` + app group): lantern uses **MANUAL** signing + `Developer ID
  Application` + a portal-created Developer-ID profile per target, NOT automatic. `project.yml` now
  mirrors that (commit `f2cdf15`): Manual, `CODE_SIGN_IDENTITY[sdk=macosx*]="Developer ID
  Application"`, team `ACZRKC3LQ9`, profiles `Spark macOS App` / `Spark macOS Tunnel`. **Only
  remaining step (human, one-time portal): create those two Developer-ID profiles + the
  `group.org.getlantern.spark` App Group**; then the documented `archive → exportArchive →
  notarytool → stapler → /Applications` recipe (in `platforms/apple/README.md`) runs, and the
  runtime gate is two GUI approvals (sysext Allow + VPN consent). Rust core + FFI + Swift provider
  + sysext conversion are done/verified; only Apple portal provisioning + notarization remain.
- **M10 (Apple) session 4 (2026-06-16) — profiles created but CERT/KEY MISMATCH; archive blocked.**
  The two Developer-ID profiles now exist and are installed (`~/Library/Developer/Xcode/UserData/
  Provisioning Profiles/`: `Spark macOS Tunnel`=728ace7f…, `Spark macOS App`=d6fb84dc…). **Both embed
  exactly ONE signing cert, `D9868CA8…` (Developer ID Application, team ACZRKC3LQ9), whose private key
  is NOT in this keychain.** `security find-identity -v -p codesigning` shows we hold keys for three
  *other* Dev-ID-Application certs — `9558A60E…` (exp 2030-05-21), `FB8932C8…` (2030-02-11),
  `5C6882DC…` (2029-10-21) — none listed in the profiles. So `xcodebuild … archive` fails:
  *"Provisioning profile 'Spark macOS Tunnel' doesn't include signing certificate 'Developer ID
  Application…'"* (overriding `CODE_SIGN_IDENTITY` to a held SHA-1 is accepted but the profile must
  ALSO list that cert — it lists only D9868CA8). The profile is Apple-signed/immutable and there's no
  ASC API key / fastlane here to regenerate it programmatically. **Resolution (human, one-time):**
  (A, recommended) in the portal, edit both profiles to include a held cert (the one expiring
  2030-05-21 = `9558A60E`), re-download → reinstall → re-archive; or (B) import `D9868CA8`'s `.p12`
  (cert+key) from the machine that created it, then the existing profiles work as-is. Everything
  downstream (export → notarytool → stapler → /Applications → 2 GUI approvals → browse gate) is
  scripted in `platforms/apple/README.md`. Caveat verified via clean isolated profile decode
  (`security cms -D` + per-cert `plutil -extract DeveloperCertificates.$i` + `openssl x509
  -fingerprint`); a section-merging `awk` earlier gave a false "profiles contain held certs" reading.
- **M10 (Apple) session 5 (2026-06-16) — macOS LIVE GATE PASSED. ✅** Adam regenerated both
  Developer-ID profiles around a held cert (`9558A60E`, exp 2030-05-21) → reinstalled → `archive`
  signs clean (Developer ID Application → DICA → Apple Root, hardened runtime), `exportArchive`
  needed **manual** signing + an explicit `provisioningProfiles` map in `ExportOptions.plist`
  (automatic can't do Developer-ID sysext), notarytool **Accepted**, stapled, copied to
  `/Applications`. Then **three sysext activation bugs surfaced via `OSSystemExtensionRequest`**, each
  fixed (the unified log is unreadable from the agent shell, so diagnosed with a temporary
  `/tmp/spark_app_trace.log` file-trace + comparison against lantern's built `.systemextension`):
  (1) **code 4 extensionNotFound** — a sysext bundle MUST be named `<CFBundleIdentifier>.systemextension`
  with a matching executable; ours was `SparkTunnel.systemextension`. Fix: `PRODUCT_NAME =
  org.getlantern.spark.tunnel` in `project.yml` (also makes `$(PRODUCT_MODULE_NAME)` →
  `org_getlantern_spark_tunnel`, so the Info.plist principal class resolves). (2) **code 8 code
  signature invalid** — Developer-ID sysext must be notarized; the plain `build` wasn't. Fix: ship
  the archive/notarize path. (3) **code 9** — network_extension sysext requires
  `NSSystemExtensionUsageDescription`; added it to `xcode/Extension-Info.plist`. After those: sysext
  → `[activated waiting for user]` → Adam approved in System Settings → `[activated enabled]`, provider
  process runs from `/Library/SystemExtensions/…`, VPN **(Connected)** (reused prior consent, no new
  dialog). **Browse gate PASSED:** default route → `utun14` (10.0.0.2); `generate_204` → HTTP 204 in
  0.19s; `https://example.com` → HTTP 200 — curl → utun → netstack → direct forwarder → upstream.
  Diagnostic file-trace scaffolding removed from `SparkApp.swift` after the gate (clean source
  rebuilds green). **M10 macOS is DONE; iOS device gate still pending (NE doesn't run on the sim).**
- **M11 (additional transports) STARTED 2026-06-16 — TLS-backend decision + AnyTLS chunk 1.**
  After a deep TLS-backend investigation (rustls can't mimic Chrome — maintainers refuse + no
  SessionID API; budget relaxed to ~10 MB; evaluated rustls/boring/Cronet/OS-native/curl-impersonate;
  empirical spike proved `wreq`'s **Chrome137 profile == real Chrome149** byte-for-byte on
  JA4/peetprint/H2-Akamai), wrote **`docs/adr/0001-chrome-mimicry-tls-backend.md`**: keep
  rustls+ring baseline; adopt **`btls`** (patched-BoringSSL fork) for *mimicry* transports (explicit
  scoped exception to the rustls-only lock); first transport = **AnyTLS-on-`btls`**; pin/vendor +
  CI JA4-drift check + curl-impersonate as escape-hatch/QUIC reference. Full rationale in the
  `m11-transport-candidates-anytls-samizdat` memory. **Chunk 1 (this session): AnyTLS protocol core,
  pure (bytes+thiserror, no TLS/deps yet), green.** `core/src/transport/anytls/`: `frame.rs` (the
  `command|streamId|dataLen|data` session-frame codec + `Command` enum, encode/parse with
  Incomplete-vs-malformed, mirrors `tcp_tunnel/header.rs`), `padding.rs` (the server-pushable
  padding-scheme parser/model: `stop=N` + per-write `LO-HI`/`c` segment plans, `DEFAULT_SCHEME`),
  `mod.rs` (layering doc + version consts). 58 core tests pass (15 new), clippy `-D warnings` clean.
  **Chunk 2 (2026-06-16): the session multiplexer, green.** Added `anytls/io.rs` (`FrameReader`/
  `FrameWriter` — async framed I/O over any `AsyncRead`/`AsyncWrite`, using the new zero-copy
  `Frame::decode(&mut BytesMut)`) and `anytls/session.rs` (`Session` + `Stream`). **Actor-style, no
  shared Mutex** (the `anytls-rs` deadlock-avoidance answer): transport is `tokio::io::split` into a
  reader task (owns `ReadHalf` + the `HashMap<stream_id, inbound sender>`; demuxes `cmdPSH`/`cmdFIN`)
  and a writer task (owns `WriteHalf`; serializes all outbound frames, coalesces bursts). `Stream`
  is `AsyncRead+AsyncWrite`; `open_stream` registers via an **oneshot-acked** control msg *before*
  sending SYN (no reply-before-registered race). Tested over an in-memory `duplex`: open/relay/close,
  two-stream demux, peer-FIN→EOF. **Client-side only** (spark opens; no accept). 65 core tests pass
  (7 new); clippy clean. Known follow-ups noted in-code: outbound is **unbounded** for now
  (backpressure becomes bounded poll-reserve when wired to TLS in chunk 4); inbound is bounded but
  HOL-blocks across streams until per-stream flow control. **Idle-session pool moved to chunk 4**
  (it owns session *creation*, which needs the TLS factory).
  **Chunk 3 (2026-06-16): auth + settings + padding engine, green.** Added `ring` (locked-stack
  crypto) to the workspace + core. `anytls/auth.rs`: `encode_auth` — the client record
  `sha256(password)(32) | padding0 len(2) | padding0` (ring SHA-256; test vs the FIPS sha256("abc")
  vector). `anytls/settings.rs`: `Settings` build/parse for `cmdSettings` (`v`/`client`/`padding-md5`,
  unknown keys ignored). `anytls/padding.rs` (extended): the **engine** `shape_records(scheme, pkt,
  data, sampler) -> Vec<Bytes>` + `SizeSampler` trait (`SystemSampler` = ring CSPRNG; injected so
  tests are deterministic). **Verified against the actual anytls-go source** (fetched
  `proxy/padding/padding.go` + `proxy/session/session.go`) rather than reconstructed: faithfully
  reproduces `writeConn` — per sampled record size `l`, `len>l`→`l` real bytes; else+nonempty→remaining
  real + a `cmdWaste` frame filling to `l` (only if the gap `> 7`); else→a `cmdWaste` of `l` bytes
  (wire `7+l`); a `Check` with payload gone stops the packet; remainder after the plan sent direct.
  `pkt` is 1-based (matches the reference; the `0=` line is never consulted). 77 core tests pass
  (12 new); clippy clean. **MD5 deliberately deferred:** `ring` has no MD5, so `padding-md5` (a
  non-security scheme identifier) is *passed into* `Settings`; its hash source is a chunk-4 dep
  decision (likely the `md-5` crate — needs sign-off per the no-new-deps rule).
  **Chunk 4 STARTED 2026-06-16 — 4a (md5 plumbing) done, green.** Added `md-5` (RustCrypto, tiny,
  pure-Rust; for the NON-security `padding-md5` identifier `ring` omits) to workspace+core.
  `PaddingScheme::md5()` (lowercase-hex md5 of the raw scheme, = anytls-go `fmt.Sprintf("%x",
  md5.Sum(raw))`) + `Settings::for_scheme(v, client, &scheme)`. 79 core tests pass (2 new); clippy
  clean. **VERIFIED the full client handshake against anytls-go source** (`cmd/client/myclient.go`
  `createOutboundConnection`, `main.go`, `proxy/session/{client,session}.go`) so 4b is de-risked:
  (1) **auth record** is written by the *dialer* right after TLS connect — `sha256(password)(32) |
  u16(paddingLen) | zeros(paddingLen)` where `paddingLen = GenerateRecordPayloadSizes(0)[0]` (the
  packet-0 scheme size; default `0=30-30`→30) — THIS is why the `0=` line exists and the session
  pktCounter starts at 1; (2) client `Session.Run`: buffering=true, send `cmdSettings`
  {v,client,padding-md5} (buffered); (3) `OpenStream` sends `cmdSYN` (buffered), buffering=false;
  (4) the consumer writes the **SOCKS5 target address** (`M.SocksaddrSerializer`, == spark's existing
  `tcp_tunnel/header.rs::Address` grammar) as the stream's first bytes → flushes settings+syn+addr as
  **packet 1** (shaped); (5) later writes = packets 2.. shaped while `pkt<stop`, then unpadded.
  Idle-session pool: `NewClient(..., idleCheck=30s, idleTimeout=30s, minIdleSession)`; reuse newest
  (`SkipList` keyed `MaxUint64-seq`), sweep on a timer.
  **Chunk 4b (2026-06-16): client handshake + padding-applied writer, green.** Refactored
  `session.rs`: the outbound channel now carries `Out{Frame|EndBuffering}`; the writer splits into
  `raw_writer` (chunk-2 behavior, `Session::new`) and `client_writer` (`Session::client`). The client
  writer writes the **auth record** (packet 0) first, **buffers** `cmdSettings`+`cmdSYN` until
  `EndBuffering` (sent by `open_stream` after the SYN), then shapes each subsequent write into padded
  records via `shape_records` (1-based pktCounter; passthrough past `stop`). `Session::client(transport,
  password, scheme)` computes the auth (padLen = packet-0 size) + sends `Settings::for_scheme`. The
  SOCKS5 target address is the stream's first write → flushes settings+syn+addr as padded packet 1.
  Still generic over the byte stream. New end-to-end test (`anytls_server` mock over a duplex):
  verifies the auth sha256, the buffered cmdSettings (v=2 + padding-md5), the SYN, address/data
  delivery through padded records (waste discarded), and the echo round-trip. 80 core tests pass
  (chunk-2 raw-mux tests still green). clippy clean. Deferred (in-code): dynamic
  `cmdUpdatePaddingScheme`, `cmdSYNACK` error reporting (client sends optimistically), bounded
  outbound backpressure.
  **Chunk 4c (2026-06-16): AnyTLS transport productized + VERIFIED END-TO-END AGAINST A REMOTE
  DIGITALOCEAN SERVER. ✅** Added `boring2`/`tokio-boring2` (BoringSSL) behind a new core `anytls`
  **feature** (off by default → base build stays rustls/ring-only, no C build). `anytls/tls.rs`:
  `connect(TcpStream, sni) -> SslStream` (vanilla boring, cert-verify NONE — AnyTLS auth is the
  password; Chrome-profile is a follow-up). `anytls/transport.rs`: `AnytlsTransport` impl `Transport`
  — a single lazily-established shared `Session` (`OnceCell`), `dial(target)` opens a stream + writes
  the SOCKS5 target via `tcp_tunnel::header::Address` (idle-pool + reconnect deferred). `config`:
  `AnytlsConfig{server,password,sni}` + `TransportConfig.anytls`; `from_config` builds it (errors if
  the feature is off). cli: `anytls` feature passthrough; builds with and without.
  **E2E proof:** stood up the `anytls-go` reference server (built from source) on a **DO droplet
  (159.89.39.6:8443, ID 578209897, systemd `anytls.service`, password in /tmp not the repo)**; spark's
  Rust client reached `example.com` through it → **HTTP 200**, both via the raw `Session::client`
  spike AND via the productized `AnytlsTransport::dial` (dialing a resolved IP as the netstack would).
  Local interop (anytls-go server on 127.0.0.1) also green. The full protocol stack (frame/mux/
  padding-engine/auth/settings/handshake/boring-TLS) interops with the canonical Go implementation.
  **FULL `sudo spark run` TUN GATE PASSED 2026-06-16. ✅** `curl https://1.1.1.1` → spark TUN
  (utun14) → netstack (`dst=1.1.1.1:443`) → `AnytlsTransport` → DO server (159.89.39.6) →
  1.1.1.1:443 → TLS → **HTTP 301** (Cloudflare's genuine redirect; a 301 *received* means the inner
  TLS completed through the relay — a leak/failure would be a curl error, not a real status). The
  spark product tunnels real TLS traffic through AnyTLS to a remote DO server, live-verified. Gate
  script `/tmp/spark-anytls-gate.sh` (writes config with the detected egress, routes one dst into the
  tun, curls, cleans up). Also fixed a cosmetic cli log ("no tunnel" while tunneling AnyTLS).
  **M11 AnyTLS is functionally complete + live-gated end-to-end.** **DO droplet 578209897 DESTROYED.**
- **M11 AnyTLS Chrome fingerprint profile DONE + JA4-VERIFIED 2026-06-16. ✅** Ported the Chrome-137
  profile from `wreq-util` onto the boring connector (`anytls/tls.rs`): cipher/sigalg/curve order
  (CURVES_3 incl PQ X25519MLKEM768 — needs boring2 `pq-experimental`), GREASE, `permute_extensions`,
  brotli cert-compression (boring2 `cert-compression` feature), ALPN h2+http/1.1, OCSP stapling, SCT,
  ALPS (new codepoint), ECH grease. **Verified against `tls.peet.ws` (h2 client spike `/tmp/ja4-check`):
  spark's JA4 = `t13d1516h2_8daaf6152771_d8a2da3f94cd` == real Chrome 149 EXACTLY.** (peetprint differs
  = per-connection extension-order permutation, expected; h2-akamai differs = the spike's h2 client,
  not spark — irrelevant since AnyTLS relays raw bytes.) Getting there: cipher hash matched first try;
  the last 2 extensions (OCSP+SCT) were missing → `enable_ocsp_stapling()`+`enable_signed_cert_timestamps()`
  closed it (14→16 extensions). **Re-verified e2e still works** with the Chrome profile (productized
  `AnytlsTransport` → local anytls-go server → HTTP 200). clippy clean, 80 tests pass.
  **CI JA4-drift check:** the `/tmp/ja4-check` spike (boring connect → tls.peet.ws → assert JA4) is the
  check to wire into CI (needs network).
- **M11 AnyTLS idle-session pool + reconnect DONE 2026-06-16. ✅** `Session` gained `active_streams()`
  (an `Arc<AtomicUsize>` incremented in `open_stream`, decremented on `Stream` drop) and `is_alive()`
  (both bg tasks still running). `AnytlsTransport` replaced its single `OnceCell` with a
  `Mutex<Vec<Arc<Session>>>` pool: `acquire()` reuses the newest healthy session under a 64-stream
  cap, evicts dead ones (reconnect = create fresh when none reusable), and connects new sessions
  WITHOUT holding the lock (std Mutex, poison-tolerant `into_inner`, no await held). A 30s background
  sweep (aborted on Drop) evicts dead sessions and drops idle (0-stream) ones beyond
  `MIN_IDLE_SESSIONS=1` warm spare. Verified: unit test (counter inc/dec on stream drop, liveness) +
  a 2-dial e2e vs a local anytls-go server (both HTTP 200, 2nd reuses the pooled session). 81 core
  tests pass; clippy clean.
- **Perf arc (data path) 2026-06-17.** Benchmarked the userspace (smoltcp) data path on a throwaway
  DO droplet via Linux netns (`bench/netns-throughput.sh`; single-box macOS e2e is impossible — the
  kernel hairpins local IPs past the route table). Three findings: **(1) opt-level fix — DONE.**
  Release profile was `opt-level="z"` (size); it ~halved data-path throughput. Switched to
  `opt-level=3` (`Cargo.toml`): ~2× (0.81→1.61 Gb/s up single-stream) for +540 KB (base 1.26→1.80 MB,
  still < the old 3 MB target). **(2) Download-concurrency collapse — characterized, partial
  mitigation, full fix deferred.** ≥2 concurrent download streams collapse to ~0.2 Gb/s aggregate
  (upload fine). Root-caused to netstack-smoltcp's single dispatch task being super-linearly
  inefficient at servicing multiple concurrently-*sending* sockets; ruled out buffer depth, park
  pacing, ingress/egress coupling, retransmit storm, and congestion control (it's `None`). Bumped
  `stack_buffer_size`/`tcp_buffer_size` in `core/src/netstack/mod.rs` as a partial mitigation (raises
  the collapsed floor ~14×, 0.03→0.42 Gb/s @ 4 streams; doesn't cure it). The structural fix is the
  system stack (independent kernel sockets) or a netstack per-flow rework — see
  `docs/system-stack-design.md` §9. **(3) GSO prototype — NEXT.** **TODO: tune the bumped buffer
  sizes down / make configurable for the iOS Packet-Tunnel memory cap.** CLAUDE.md's documented
  release profile still says `opt-level="z"` and should be updated to `3`.
- **System (kernel-TCP) netstack — chunks 1–4 BUILT 2026-06-17 (behind `system-stack` feature, off
  by default; TCP-only so far).** A second `Netstack` impl (NAT redirect gateway → kernel listener;
  sing-box's `stack=system`) under `core/src/netstack/system/`: `nat.rs` (source⇄natPort table),
  `rewrite.rs` (in-place TCP/IP 4-tuple rewrite + checksum recompute), `pump.rs` (`Gateway`:
  classify + rewrite both directions, resolve accepts), `stack.rs` (`SystemNetstack`: TUN pump loop
  + per-family kernel listener accept loop + idle reaper, impls `Netstack`). Selected via
  `[tun] stack = "userspace"|"system"` (`config::StackKind`) routed through `netstack::build(...)`
  (all 3 construction sites — cli/fd_tunnel/service); a blanket `impl Netstack for Box<dyn Netstack>`
  keeps `proxy::tcp::run` generic. 102 core tests pass with `--features system-stack`; workspace
  green default.
- **System stack — chunk 5 LIVE-GATED + A/B'd on a netns droplet 2026-06-17. ✅✅ It eliminates the
  concurrent-download collapse.** `bench/netns-throughput.sh --stack {userspace,system}` (the bench
  now A/Bs both). Download Gb/s by stream count — userspace vs system: 1→0.51/1.19, **2→0.13/1.09
  (~8×)**, 4→0.30/0.95, 8→0.41/0.87. Userspace craters under concurrent download; the system stack
  holds ~1 Gb/s and is stable across concurrency (download symmetric with upload). Tradeoff:
  single-stream upload peak lower (system ~1.2 vs userspace ~1.67) — the single pump task rewrites
  every packet, so the pump is itself a serialization point (future: multi-pump / GSO-on-pump). CPU
  comparable (~130–140%). It tunnels end-to-end on Linux on the first try. **Confirmed-live caveats:**
  needs `rp_filter=0` on the redirected path (the bench sets it); NAT cleanup is idle-eviction-only
  (no FIN/RST); TCP-only (no UDP/DNS over it yet — the "mixed" stack is future). Full A/B table +
  rationale: `docs/system-stack-design.md` §9 ("Validated"); doc status now Built+live-gated.
  **Follow-ups (non-blocking):** FIN/RST-driven NAT removal; the "mixed" stack (UDP/ICMP); pump
  parallelism / GSO to lift the single-stream peak; consider promoting the design doc to an ADR.
- **System stack — FIN/RST removal + mixed (UDP) stack + ADR DONE 2026-06-17. ✅** (1) **FIN/RST NAT
  removal:** the pump removes a mapping on RST and marks both-FIN connections "closing" for a short
  60s reclaim (2h idle safety net) — no more hours-long port hold under churn. (2) **Mixed stack:**
  the pump bridges UDP to spark's existing UDP proxy (`build_udp`/`udp_endpoints`/`ip_protocol` in
  `rewrite.rs`; pump `select!`s TUN reads vs UDP replies; `SystemNetstack` now yields a `UdpSurface`
  via `take_udp`), so DNS/UDP work over the kernel-TCP stack. **Live-gated on a netns droplet:** a
  socat UDP echo round-trips through the system stack ('SPARK-UDP-PING' returned), TCP sanity
  1494 Mbps. (3) **ADR `docs/adr/0002-system-netstack.md`** records the decision. 106 core tests
  with `--features system-stack`; workspace + rustdoc green.
- **System stack — incremental checksum + single-stream-peak finding 2026-06-17.** Switched the
  pump's TCP checksum from full recompute to **incremental (RFC 1624)** — proven byte-equal to full
  recompute (107 core tests). **On-box A/B (system stack):** full-recompute 1.39/1.27 vs incremental
  1.46/1.33 Gb/s up (1/4 streams) — **within noise, CPU unchanged**, so the checksum was NOT the
  bottleneck: **per-packet syscall overhead (`tun.recv`+`tun.send`) is.** The single-stream-peak
  lever is therefore **syscall batching: GSO via `IFF_VNET_HDR` (Linux)** — and the system stack is
  the *right* place for GSO (its bottleneck is at the boundary GSO batches; the userspace stack's
  isn't). Incremental is kept as the GSO prerequisite (offloaded checksums must be adjusted
  incrementally). See `docs/system-stack-design.md` §9. **Remaining (non-blocking):** GSO/vnet-header
  (Linux) or multi-pump for the single-stream peak; IPv6 in the selection path; production `rp_filter`.
- **CORRECTION 2026-06-17: the system stack is NOT desktop-only — it works on Android too.** Verified
  against `sing-tun@v0.7.11`: `tun_linux.go New()` adopts a passed tun fd (the `FileDescriptor != 0`
  branch) with no platform gate, and the system stack runs on it identically — **sing-box ships
  `stack: system` on Android** by adopting the `VpnService` Linux tun fd. My earlier ADR/design-doc
  "desktop-only / fights the mobile sandbox" claim conflated Android (Linux tun fd → works) with
  **iOS** (`NEPacketTunnelFlow`, no kernel tun → genuinely doesn't apply). GSO is **orthogonal**:
  `enableGSO()` is a runtime `IFF_VNET_HDR` check that *gracefully degrades to single-packet* if
  absent (standard `VpnService` lacks it), so the system stack runs on Android with or without GSO.
  **Implication: the concurrent-download collapse fix could reach Android** — spark's android build
  just doesn't enable the `system-stack` feature yet (a choice). Android-specific work to enable it:
  turn on the feature for `platforms/android`, route the `VpnService` fd into `SystemNetstack`, and
  use `VpnService.protect()` for upstream-socket protection. Docs corrected (ADR 0002, design §7).
- **Dynamic-transports design exploration 2026-06-17.** `docs/dynamic-transports-design.md`: how to
  let transports be delivered/updated independently of client releases (the WATER idea). Grounded in
  `getlantern/water` (Go/wazero) + `refraction-networking/water-rs` (Rust/wasmtime) + the corpus +
  a research-agent synthesis. **Conclusion: full WASM via water-rs is the WRONG default for spark** —
  wasmtime+Cranelift is ~15–20 MB (5–7× budget; the lean build can't load dynamically), wasmtime 17
  has no interpreter so it won't run on iOS at all (no JIT for 3rd-party apps), and App-Store 2.5.2
  is policy-grey for downloaded modules. WATER throughput 1.64 MB/s vs 15.3 native on localhost (but
  only +3.5% over a real 37 ms link — fine for RTT-bound, brutal for throughput). lantern-water has
  a real **integrity≠authenticity gap** (SHA-256 only, no signature). **Recommendation: two tiers —
  (1) config-composition of native primitives (signed/versioned pipeline of uTLS fingerprint +
  padding + framing + fragmentation; extends AnyTLS's server-pushed padding scheme; covers ~80% of
  censor responses, ~0 size, mobile-compliant); (2) `wasmi` (interpreted WASM) as the full-logic
  escape hatch for novel wire formats, bulk crypto stays native.** wasmtime never in the Rust core
  (15-20MB, iOS-dead). **Tier-2 runtime micro-bench (`/tmp/tr-spike`, 2026-06-17, doc §8.1): `wasmi`
  +0.84 MB / 103 ns control-op BEATS rhai (+1.55 MB / 1840 ns) and rune (+2.19 MB / 1367 ns) on BOTH
  size and speed** — so the practical "interpreted Rust" (Rust→wasm→wasmi) is the leanest+fastest
  dynamic-load runtime; the scripting-interpreter detour doesn't pay off; a bespoke DSL VM is a
  fallback only if <0.84 MB is needed. Record-through-interpreter (wasmi 28× slower than native,
  rhai/rune ~300×) makes "keep bulk native, interpret only the control path" a measured ABI rule.
  **Runtime ≠ ABI (doc §8.2):** `wasmi` is the *runtime*; "WATER-compatible" is an *ABI* (the
  `water_*` host imports + `_water_*` exports + WASI preview1). No wasmi-based WATER host exists
  (`water-rs`=wasmtime; both local `water` copies are Go/wazero), but `wasmi_wasi` (2.0.0-beta) gives
  the WASI layer. **Recommend targeting WATER ABI-compat ON wasmi** (so a transport authored once
  runs on lantern's WATER *and* spark — the getlantern strategic win). **water-rs runtime-abstraction
  probe RESOLVED 2026-06-17 (cloned + inspected):** NO abstraction — hard-wired to wasmtime 17; its
  traits abstract the transport *role*, not the engine; `wasmtime::` coupling localized to 4 files
  (`core.rs` engine/WASI setup + `v0/v1/funcs.rs` host-fn `func_wrap`). → **don't port water-rs**
  (stale: wasmtime 17 / 0.1.0); **write a focused fresh wasmi host for just the v1 dialer/stream
  ABI** (ABI-compatible, small). **THE crux / next probe:** WATER's data path is wasmtime-wasi's
  `Socket::from(tcp) → push_file → guest fd`; the only real wasmtime lock-in is that `push_file` —
  so the decisive question is whether `wasmi_wasi` (2.0.0-beta) can insert a custom host socket as a
  WASI fd. **RESOLVED YES 2026-06-17 (inspected the crate):** `wasmi_wasi` is built on `wasi-common`
  v36 (same crate water-rs uses at v17), re-exports `WasiCtx`/`WasiFile`, and `wasi-common` v36 has
  `push_file` + `TcpStream::from_cap_std` + a tokio variant — exactly WATER's `Socket::from(tcp) →
  push_file → guest fd`. So the wasmtime "lock-in" was a `wasi-common` feature; `wasmi_wasi` and
  `wasmtime-wasi` are siblings over the same crate → the port is adaptation not reinvention (engine
  1:1, host fns via `wasmi::Linker::func_wrap`, data path via `wasmi_wasi` push_file). Residual:
  `wasi-common` 17→36 API drift + `wasmi_wasi` is beta. **Path A (WATER-ABI-compat on wasmi) is
  de-risked.** Size caveat: bare wasmi was +0.84 MB but Path A adds the WASI stack
  (wasmi_wasi+wasi-common+cap-std+wiggle) → several MB, still ≪ wasmtime's 15-20 MB; a no-WASI Path B
  stays near +0.84 MB. **Decision recorded: ADR 0003** (`docs/adr/0003-dynamic-transports.md`,
  Accepted) — Tier 1 config-composition first, Tier 2 WATER-ABI-compat on wasmi. Pushed to origin.
  **PROTOTYPE PROVEN 2026-06-17 (`/tmp/wt-proto`, throwaway):** a wasmi + wasmi_wasi host inserted a
  real TCP socket as guest fd 3 via `push_file`; a wasm32-wasip1 reactor did fd_write/fd_read on it;
  echo round-trip PASSED → WATER's data path runs on wasmi+wasmi_wasi (the working API recipe is in
  doc §8.3, the durable artifact). Scope: mechanism only (sync, custom `run` export + fd-3-by-
  convention — NOT yet the full WATER v1 ABI, not async). **PIVOT 2026-06-17 → Path B is primary
  (user: Go/WATER-ecosystem reuse is "a lesser concern… not used widely atm").** Path A's *only* real
  edge over Path B was write-once-run-on-lantern's-WATER, which is now de-prioritized — so spark
  targets **Path B (spark-specific minimal ABI on bare `wasmi`, no WASI/network):** the module is a
  pure byte-transform; the **host owns both sockets** and the module imports only native crypto/
  entropy host fns. Leanest (~+0.84 MB, no WASI stack) and tightest sandbox (module can't reach the
  network). **Path B PROTOTYPE PROVEN 2026-06-17 (`/tmp/pathb-proto`, throwaway):** guest cdylib →
  `wasm32-unknown-unknown` exporting `alloc(len)→*mut u8` + `transform_out(ptr,len)→u64` (packs
  `(out_ptr<<32)|out_len`) + `transform_in`, importing `env::host_rand`; host = bare `wasmi
  =2.0.0-beta.2` (NO wasmi_wasi), `Linker::<()>::func_wrap("env","host_rand",…)`,
  `instantiate_and_start`, drove the transform via alloc + linear-memory r/w; echo-server round-trip
  PASSED with an 11 KB module (recipe captured in doc §8.4). **Path A (WATER-ABI-compat on wasmi)
  stays fully de-risked but optional/deferred** — revivable cheaply (mechanism proven, §8.3) *if* Go
  reuse ever becomes a driver. ADR 0003 + design doc §8 updated to record the pivot. **Next
  increments (Path B):** (1) richer ABI — a handshake/negotiate phase + host-fn AEAD/hash beyond
  `host_rand`; (2) wire into spark's `Transport` trait (host owns the protected upstream socket, feeds
  bytes through `transform_out`/`transform_in`); (3) Ed25519 module signing + anti-rollback version
  counter + out-of-band delivery.
  **HOST RUNTIME BUILT IN-TREE 2026-06-17 (chunk 1 of the Path B build).** Promoted the `/tmp` PoC into
  `core/src/transport/wasm/mod.rs` behind a `wasm-transport` feature (off by default → base build
  carries no WASM runtime; `wasmi = "=2.0.0-beta.2"` is the only added dep, ADR-authorized). Surface:
  `TransformModule::load(&[u8])` (compile, `Arc`-shareable) → `.instantiate()` → `Transform` with
  `transform_out`/`transform_in(&[u8]) -> Vec<u8>` + `entropy_drawn()`. ABI v0 = exports
  `memory`/`alloc(len)->ptr`/`transform_{out,in}(ptr,len)->i64` packed `(out_ptr<<32)|out_len`; sole
  import `env::host_rand(ptr,len)` wired to `ring` `SystemRandom`. Host-fn faults recorded in
  `Store` data + surfaced after the call (no `wasmi::Error` construction); every guest→host length
  range-checked vs `MAX_TRANSFORM_LEN=1 MiB` before any alloc (untrusted-module hardening). 6 unit
  tests green (round-trip recovers input, host_rand fires/`entropy_drawn==4`, empty input,
  missing-export + non-wasm rejected, packing math) via an inline `.wat` XOR fixture assembled by a
  `wat` dev-dep; `cargo clippy --features wasm-transport -Dwarnings` + default clippy + fmt + workspace
  check all clean. wasmi API verified against docs.rs 2.0.0-beta.2 (`Linker::func_wrap`/
  `instantiate_and_start`, `Instance::get_typed_func`/`get_memory`, `Memory::read`/`write`,
  `Caller::get_export`, `TypedFunc::call`).
  **STREAM ADAPTER BUILT 2026-06-17 (chunk 2).** `core/src/transport/wasm/stream.rs`:
  `TransformStream<S>` (`S: AsyncRead+AsyncWrite+Unpin`) impls `AsyncRead`+`AsyncWrite`, pumping the
  underlying stream through the module as a **stateful stream codec** — writes run `transform_out`,
  reads run `transform_in`; no length-preservation or 1:1-call assumption, and the host adds NO wire
  framing (a host length-prefix would be a fingerprint; framing lives inside the module). Poll-based
  buffering (`write_buf: BytesMut` FIFO, `read_buf: Bytes`, reused 16 KiB read scratch) → cancel-safe;
  backpressure at the top of `poll_write` (won't transform new app bytes until prior output drains →
  bounded buffering). 4 stream tests (both-direction duplex round-trip, wire-is-obfuscated, chunked
  reassembly via a self-yielding reader, + the release-only large-transform). **wasmi debug-stack
  gotcha (root-caused):** wasmi uses tail-call threading → LLVM TCO makes it **constant-stack in
  release** (proven: 256 KiB single transform passes release) but **stack ∝ instructions executed at
  opt-level 0** → a large single transform overflows the ~2 MB test thread *in debug only*. No
  production impact (release is constant-stack; `MAX_TRANSFORM_LEN` safe); debug tests just keep
  per-call sizes small and the large-transform test is `#[cfg(not(debug_assertions))]`. Also avoid
  always-`Ready` mock readers in async tests (they collapse a transfer into one giant synchronous
  poll); the chunked test's reader yields `Pending` like a real socket.
  **SIGNED MODULE LOADING BUILT 2026-06-17 (chunk 3; user picked this over Transport-wiring as the
  next step).** `core/src/transport/wasm/signing.rs`: a delivered module is a signed artifact —
  `MAGIC "SPKW" || version:u32 BE || name_len:u16 || name || wasm_len:u32 || wasm || sig:64`, the
  Ed25519 signature covering everything before it. `ModuleVerifier::new([u8;32] pinned pubkey)
  .verify(artifact, min_version) -> SignedModule{name,version,module}`: (1) authenticate the WHOLE
  payload (ring `UnparsedPublicKey`+`ED25519`) BEFORE parsing, so the length-prefixed name/wasm
  fields are trusted when read (no malicious-length over-read/alloc); (2) anti-rollback — reject
  `version < min_version` (a correctly-signed *old* module is still an attack; caller supplies the
  floor = highest installed); (3) compile via `TransformModule::load`. Private key never in core —
  signing is external tooling; core only assembles (`signing_payload`/`build_artifact`) + verifies.
  6 tests (verify+load+run, tampered-wasm→BadSignature, wrong-key→BadSignature, rollback rejected /
  current+newer accepted, truncated, bad-magic-even-when-signed). Debug 16 / release 17 tests green;
  clippy (feature+default) + fmt + workspace check clean.
  **TRANSPORT + SERVER BUILT 2026-06-17 (chunk 4; user picked this next).** `core/src/transport/
  wasm/transport.rs`: `WasmTransport` (client, impls `Transport`) + `WasmServer` (server). Design:
  the wasm transform is a byte-obfuscation layer **underneath the EXISTING tunnel handshake** — the
  client dials the spark server, wraps the socket in `TransformStream`, then runs the ordinary
  `tcp_tunnel::header::Address` exchange over it; the server wraps its accept in the inverse
  transform and `read_header`s the target back. So target-conveyance is reused unchanged (no new
  handshake), the module stays a pure byte transform, and the header being the first bytes through
  `transform_out`/`transform_in` keeps the two endpoints' codec state aligned (matters for a
  stateful module). `WasmTransport::new(server, module)` (+`with_socket_protection`); `WasmServer::
  new(module).accept(conn) -> (Address, leftover, TransformStream<conn>)`; fresh `Transform` per
  connection. End-to-end test over real TCP (client → wasm server → echo) round-trips through the
  XOR module. **Bug found+fixed during this chunk:** `poll_write` buffered the transform output and
  only drained on the NEXT poll_write/flush → `write_all`+`read` (no flush) deadlocked with bytes
  stuck in `write_buf`. Fix: drain eagerly inside `poll_write` (buffer only what the socket can't
  accept); regression-covered by removing the explicit flush from the both-directions stream test.
  Debug 17 / release 18 tests green; clippy (feature+default)+fmt+workspace clean.
  **RICHER ABI BUILT 2026-06-17 (chunk 5 = item b; user ordered "b then fuel metering").** Added
  native crypto host fns + an `init` config hook, so a real encrypting transport runs at native
  speed instead of the interpreter floor. New host imports (the module's whole capability surface):
  `host_hash(in,len,out)` = SHA-256 (ring `digest`); `host_aead_seal`/`host_aead_open(key_ptr,
  nonce_ptr,in_ptr,in_len,out_ptr)->i64` = ChaCha20-Poly1305 (ring `aead::LessSafeKey`,
  `seal_in_place_append_tag`/`open_in_place`, empty AAD in v0); plus existing `host_rand`. All read
  key/nonce/data from guest memory via `read_guest`/`read_guest_array::<N>`/`write_guest`/
  `guest_memory` helpers, range-check lengths, and record faults (auth failure on open → fault →
  `HostFault`, fail-closed). Optional `init(config_ptr,config_len)` export: `TransformModule::
  instantiate_with_config(&[u8])` allocs+writes config, calls `init`; no `init` export + non-empty
  config → `MissingExport`. wasmi `func_wrap` handles the 5-arg host fns fine. **PERF PAYOFF measured
  (release bench `bench_transform_throughput`):** XOR-in-interpreter ~0.77 Gb/s vs **host-AEAD
  (native ChaCha20-Poly1305) ~11–14 Gb/s** (~18× faster while doing real AEAD, ~9× over the ~1.6 Gb/s
  tunnel → transform no longer the bottleneck); passthrough/marshalling floor 120–250 Gb/s; native
  XOR 28 Gb/s. Validates the ADR "bulk native, interpret only control" rule with numbers. 5 new tests
  (host_hash == ring SHA-256; AEAD seal/open round-trip; tampered ct → HostFault; init delivers
  config / different key → different transform; config-without-init rejected). Debug 22 / release 23
  green; clippy+fmt+workspace clean.
  **FUEL METERING BUILT 2026-06-17 (chunk 6; the second half of the user's "b then fuel" order).**
  `TransformModule::load` now builds the engine with `Config::consume_fuel(true)`; each guest entry
  refills a per-call budget via `Store::set_fuel` — `fuel_for(len) = FUEL_BASE(5M) + len*FUEL_PER_BYTE
  (1024)`, set before `instantiate_and_start` (covers a `start` fn), before `init`, and before every
  `alloc`+transform in `run`. Fuel meters only the module's INTERPRETED bytecode — host-fn crypto
  runs natively and costs no fuel — so it bounds a runaway without penalizing bulk work. A failed
  guest call is routed through `classify_call`, which maps an out-of-fuel trap to a dedicated
  `WasmError::Fuel` (vs `Call` for other traps). New release-only test
  `fuel_metering_stops_a_runaway_module`: an infinite-loop module returns `WasmError::Fuel` instead
  of hanging. (Release-only because in debug wasmi's non-TCO interpreter overflows the stack on a
  runaway *before* any sane fuel budget trips — same artifact as the large-transform test; fuel is a
  release/production safeguard.) Perf: re-ran the bench with fuel ON — host-AEAD ~11–14 Gb/s and
  passthrough 113–255 Gb/s **unchanged within noise** (negligible interpreted work to meter), so fuel
  is effectively free on the realistic path. Debug 22 / release 24 green; clippy(feature+default)+fmt+
  workspace clean.
  **UDP PATH BUILT 2026-06-17 (chunk 7 = item a).** `impl UdpTransport for WasmTransport::dial_udp`:
  mirrors the tunnel client's UoT — obfuscated associate handshake (`udp_associate_sentinel` +
  target via `transform_out`), then `TcpStream::into_split()` into `WasmUdpSink` (PacketSink) +
  `WasmUdpSource` (PacketSource). The two halves live in different tasks (netstack send loop / reply
  pump) but ONE `Transform` serves both directions, so it's shared via `Arc<std::sync::Mutex<
  Transform>>` — locked only for the synchronous transform call, **never across an `.await`** (free
  `transform_out`/`transform_in` helpers enforce this). Sink frames `[u16 len][payload]` →
  transform_out → write; source reads → transform_in → reassembles frames in a buffer (truncation
  semantics, EOF = Ok(0), matching `TunnelUdpSource`). Server side stays single-task: a whole
  `TransformStream` (read plaintext / write plaintext, obfuscation transparent), so no split/mutex
  there. End-to-end test: two datagrams round-trip through an in-test obfuscated UDP echo relay
  (proves frame alignment holds across calls). Debug 23 / release 25 green; clippy(feature+default)+
  fmt+workspace clean.
  **PATH B STATUS: the in-process pipeline is complete + hardened, TCP + UDP** — signed/verified load
  → instantiate (+config) → native-crypto host fns → obfuscated `Transport`+`UdpTransport`/
  `WasmServer` tunnel, fuel-bounded.
  **CONFIG WIRING + VERIFIED LOAD BUILT 2026-06-17 (chunk 8 = item c, the in-`core` half).** Added
  `config::WasmConfig { server, module (artifact path), public_key (hex Ed25519), min_version,
  init_config (hex), floor_path }` + `TransportConfig.wasm`; `from_config` now builds the wasm
  transport (precedence: anytls > wasm > plain server > direct), feature-gated `wasm_transport()`
  (with a non-feature stub that errors like anytls). It: hex-decodes the pinned key (hand-rolled
  `decode_hex`, no `hex` crate), reads the artifact file, `ModuleVerifier::verify(artifact,
  min_version)` (authenticate BEFORE trusting the name), then a persisted per-name floor
  (`wasm_floor` mod: TOML `name=version` map; get/bump; missing file = empty) as a second
  anti-rollback gate that survives restarts, then `WasmTransport::new(..).with_config(init)` (new
  `config: Vec<u8>` field → `instantiate_with_config` per dial/dial_udp). 4 from_config tests (builds
  a verified transport; rejects rollback via min_version; rejects wrong pinned key; persisted floor
  enforced+bumped — install v5 then reject v4). Also fixed `cli/main.rs`'s explicit `TransportConfig`
  literal (+`wasm: None`). Debug 112 lib / release 25 wasm tests green; clippy(feature+default)+fmt+
  workspace clean.
  **PINNED SIGNING KEY BUILT 2026-06-17 (chunk 9 = item d).** The verification key is now pinned in
  the binary, not config. `signing.rs`: `const SPARK_MODULE_PUBKEY: [u8;32] = match
  option_env!("SPARK_MODULE_PUBKEY_HEX") { Some(h) => parse_pubkey_hex(h) /* const-fn, malformed →
  compile error */, None => DEV_MODULE_PUBKEY }` — release builds inject the real key at build time;
  the dev fallback's private half (`testutil::DEV_MODULE_PKCS8`/`dev_keypair()`) is `#[cfg(test)]`
  only, never shipped. `ModuleVerifier::pinned()` uses it; `from_config` now verifies via `pinned()`
  and `WasmConfig.public_key` is REMOVED (config can't swap the trusted key). Tests sign with the dev
  key; a cross-check test (`pinned_verifier_accepts_a_dev_signed_module`) proves the baked pubkey
  const matches the baked pkcs8; from_config tests updated (happy/rollback/floor sign with dev,
  not-pinned-key rejection signs random). Debug 29 / release 31 wasm tests green; clippy(feature+
  default)+fmt+workspace clean. **Remaining (lower priority):** the network-delivery half of (c) —
  actually *fetch* the artifact over the config/fronting channel into `module` (verify/load/floor is
  done; a client/service+fronting integration, out of `core`); v0 ABI niceties (`dealloc`/arena-reset,
  AAD param on the AEAD host fns, UDP-source per-call-buffering caveat) — **doing the ABI niceties next.**
  **ABI NICETIES BUILT 2026-06-17 (chunk 10).** (1) **`reset()` arena management** — optional export;
  the host calls it after each transform (and after `init`) so a module can rewind a per-call scratch
  arena without growing memory, while state in globals survives (reset only rewinds the bump pointer).
  `Transform.reset: Option<TypedFunc<(),()>>`, fuel-covered, errors via `classify_call`. Replaces the
  v0 "host never frees → modules must self-limit" caveat. Test: a 1-page module does 5000 transforms
  (would overflow the arena after ~1000 without reset) — passes. (2) **AAD on the AEAD host fns** —
  `host_aead_seal`/`host_aead_open` gained `aad_ptr, aad_len` (now 7-arg; wasmi `func_wrap` handles
  it), passed to ring `Aad::from`; lets a transport bind a frame header/counter to the ciphertext.
  `AEAD_WAT` fixture updated to a non-empty 4-byte AAD (round-trip proves the path); bench fixture
  updated to 7-arg (host-AEAD still ~11–14 Gb/s). (3) **UDP-source caveat** documented on `WasmUdpSink`:
  the UDP path assumes the module emits a datagram's wire bytes per `transform_out` call (true for
  stream-cipher/per-call-AEAD shapes; a cross-call-buffering module is unfit for UDP — TCP has no such
  constraint). Debug 30 / release 32 wasm tests green; clippy(feature+default)+fmt+workspace clean.
  **PATH B COMPLETE in-`core`.** Only out-of-core work remains: the network-delivery half of (c) —
  *fetch* the artifact over the config/fronting channel into `module` (a client/service+fronting
  integration; verify/load/floor is done).
- **`spark-ffi` control-plane binding BUILT 2026-06-18.** New workspace crate `spark-ffi/` — a typed
  `Backend` over the **real `spark_ipc::Client`** generated as Swift/Kotlin via **UniFFI 0.31**, so any
  UI (desktop GUI, mobile app) drives a running `spark-service` through one type-safe API. Supersedes
  the CLI's hand-written control client (`cli/src/main.rs::control`/`connect_control`). **Grew out of
  the framework/generic-backend assessment** (Google Doc `1Lbsd8eXu0vY2S13r1EJ35ax_NyeYHYyJLe9-tyXk3os`
  Part 2); de-risked first with a throwaway `ffi-spike/` (now removed). **Control surface ONLY — the
  FFI split:** the data path stays in the platform shims (`platforms/android` JNI + `platforms/apple`
  C-ABI), which run `core::fd_tunnel::run_tunnel(fd)` IN-PROCESS on an OS-provided fd; `spark-ffi` is a
  *different* surface (commands/status/events over the control socket), not that. **Runtime model:**
  `Backend` owns a multi-thread `tokio::runtime::Runtime`; `connect`/`disconnect`/`status` are sync
  (`block_on` one `connect_control → Client::new → handshake → request` round-trip per call — per-command
  connections, matching the CLI, control ops are infrequent); `subscribe(listener)` `rt.spawn`s a task on
  a dedicated connection (`Subscribe{events:true,logs:false}` → loop `next_push` → `EventListener::on_event`),
  `unsubscribe`/`Drop` abort it. Mirror types `TunnelState`/`TunnelStatus`/`TunnelEvent`/`BackendError`
  (the latter maps `ipc::ErrorCode` + a `Transport{message}` bucket for connect/io/handshake) with
  `From` conversions; `EventListener` is a `callback_interface`. **`uniffi` enters the product** as a new
  workspace member, but isolated to the `spark-ffi` cdylib — NOT linked into `core`/`cli`/`service`, so
  their binary sizes are unaffected. **Gate (all green):** `cargo test -p spark-ffi` = 2 pass
  (`error_codes_map_to_typed_errors` + `control_roundtrips_over_a_real_socket`, the latter drives
  `Backend` connect→status→subscribe-receives-event→disconnect against a mock `spark-ipc` responder over
  a real temp unix socket, no `spark-service` dep); bindings generate non-empty Swift (1231 lines) +
  Kotlin (1851) exposing `Backend`/`EventListener`/the mirror types; `clippy -p spark-ffi -D warnings` +
  `fmt` + `cargo check --workspace` clean. **Test gotcha:** `tokio::net::UnixListener::from_std` panics on
  a blocking fd → `set_nonblocking(true)` before adopting the std listener. **Out of scope (noted):**
  packaging integration (xcframework/cargo-ndk bundling the cdylib + bindings), the desktop GUI, the
  JSON-RPC/web facade, a Windows named-pipe test, event-stream auto-reconnect, and data-path shim
  unification. **Landed `d2e4789`** (`bindings/` gitignored — regenerated during packaging).
  **ASYNC EXPORTS 2026-06-18 (commit pending).** Converted `connect`/`disconnect`/`status` from sync
  `block_on` to `async fn` → Swift `func … async throws` / Kotlin `suspend fun` (verified in the
  regenerated bindings); `subscribe`/`unsubscribe`/`new` stay sync. **Chose the single-owned-runtime
  model over `#[uniffi::export(async_runtime = "tokio")]`:** verified against the uniffi-macros 0.31.2
  source that the tokio attribute wraps the future in `::uniffi::deps::async_compat::Compat` — a HIDDEN
  global runtime entered at poll time. That's fine for request/response but `subscribe`'s long-lived
  push task wants an explicit, cancellable home, so instead each async method `runtime.spawn`s its
  round-trip and awaits the `JoinHandle` (works from any foreign polling thread — `Runtime::spawn` and
  `JoinHandle` poll need no ambient context — so the IO still has a reactor), and the subscription
  shares that same one runtime; no `async_compat`, no second runtime, no attribute. `round_trip` is now
  a free fn; new private `Backend::call` does the spawn+join (a `JoinError` → `Transport`). Test is
  `#[tokio::test]`, awaits the calls, and drops `Backend` via `spawn_blocking` — dropping its owned
  runtime inside another runtime panics (a TEST-only artifact; foreign callers drop on an off-runtime
  thread). Gate green: `cargo test -p spark-ffi` 2 pass, clippy `-D warnings` + fmt + `cargo check
  --workspace` clean. **Landed `51122d1`.**
  **WINDOWS TEST + EVENT-STREAM RECONNECT 2026-06-18.** (1) **Auto-reconnect:**
  `subscribe`'s task no longer `return`s on the first error — it's now a `subscription_loop` with
  capped exponential backoff (`run_subscription_session` per attempt; `MIN 250ms` … `MAX 30s`, doubles
  while unreachable, resets to the floor once a session is *established* = handshake + `Subscribe`
  succeeded). So it survives a service restart / dropped control connection. `sleep` + `next_push` are
  the only await points → an abort (`unsubscribe`/`Drop`) still tears it down cleanly. Events during a
  gap are MISSED (state-event stream, not a log) — documented; after a gap the caller can re-query
  `status()`. No synthetic "reconnected" signal added (would mean a binding-only `TunnelEvent` variant
  — left as a possible follow-up). The exported FFI surface is unchanged (`subscribe`/`unsubscribe`
  sigs identical) → bindings need no regen. (2) **Windows named-pipe test:** refactored
  `tests/control.rs` — the mock responder + `Backend` driver moved to a transport-agnostic `mod harness`
  (the responder is generic `handle_conn<S: AsyncRead + AsyncWrite + Unpin>`, so it serves a
  `UnixStream` or a `NamedPipeServer` unchanged). `#[cfg(unix)] mod unix_e2e` (now tokio-`bind` +
  `tokio::spawn` accept loop, no std-listener/`from_std`/`set_nonblocking` dance) + a new
  `subscribe_reconnects_after_the_stream_drops` test (mock pushes one event per connection then closes;
  ≥2 events ⇒ it reconnected). `#[cfg(windows)] mod windows_e2e::control_roundtrips_over_a_named_pipe`
  (`ServerOptions::first_pipe_instance(true).create` before the client opens, pre-create the next
  instance after each `connect().await`). **Gate green:** 3 unix tests pass; host clippy `-D warnings`
  + fmt clean; **`cargo clippy -p spark-ffi --all-targets --target x86_64-pc-windows-msvc -D warnings`
  clean** (the named-pipe test type-checks + lints; runs live only in CI on Windows — no host here);
  `cargo check --workspace` clean. **Landed `7bab14b`.**
  **MOBILE PACKAGING 2026-06-18 (commit pending).** `spark-ffi` now ships consumable mobile artifacts.
  **Prereq fix:** the crate enabled `uniffi`'s `cli`+`tokio` features unconditionally (via the
  workspace dep) — `cli` drags `uniffi_bindgen` + host-only deps (askama/toml/goblin) into EVERY
  build's feature-unified graph, so an iOS/Android cross-compile of the shipped lib would needlessly
  compile (maybe fail) the bindgen toolchain. Fixed: workspace `uniffi` dep now featureless; spark-ffi
  gates the CLI behind a bin-only feature `uniffi-bindgen = ["uniffi/cli"]` + `[[bin]] required-features
  = ["uniffi-bindgen"]`, so `cargo build --lib --target <ios/android>` never sees the CLI deps. Also
  DROPPED `uniffi/tokio` — that feature only powers `async_runtime = "tokio"` (`async-compat`'s global
  runtime), which the owned-runtime model doesn't use (verified: lib + 3 tests still green without it).
  crate-type `["cdylib","lib"]` → `["cdylib","staticlib","lib"]` (staticlib for the Apple xcframework).
  **Apple (`spark-ffi/apple/`):** `build-xcframework.sh` builds the staticlib for `aarch64-apple-{ios,
  ios-sim,darwin}`, generates the Swift glue + C header from a host cdylib (UniFFI reads metadata by
  dlopen — iOS libs can't load on host), bundles header+`module.modulemap` per slice, assembles
  `SparkFFI.xcframework` (3 slices: ios-arm64 / ios-arm64-simulator / macos-arm64) + drops
  `Sources/SparkFFI/spark_ffi.swift`. `Package.swift` = binaryTarget `spark_ffiFFI` (the xcframework) +
  Swift target `SparkFFI`. **Verified: `swift build` compiles the generated Swift against the macOS
  slice.** Mirrors `platforms/apple/build-xcframework.sh`. **Android (`spark-ffi/android/`):**
  `build-android.sh` = `cargo ndk -t arm64-v8a -t x86_64 -P 24 -o jniLibs build --release -p spark-ffi
  --lib` (mirrors `platforms/android`) + Kotlin generation from a host cdylib. **Verified: both
  `libspark_ffi.so` build (aarch64 + x86_64 stripped ELF) + the Kotlin (`Backend`/`EventListener`/
  `suspend connect|disconnect|status`, loads lib `spark_ffi`) generates.** `build.gradle.kts` = an
  Android library module (sourceSets → `kotlin/` + `jniLibs/`; deps `net.java.dev.jna:jna:5.14.0@aar`
  for the FFI + `kotlinx-coroutines-core` for the `suspend` calls — both confirmed from the generated
  `.kt`'s imports). No `.aar` built here (no standalone gradle project; documented as the consumer/CI
  step, consistent with `platforms/android` deferring its AAR). Shell-bug found+fixed mid-build: under
  `set -o pipefail`, `ls a b | head` returns `ls`'s non-zero when one path is absent → aborts; replaced
  with an explicit `[ -f … ]` host-lib check. **All generated outputs gitignored** (xcframework, Swift
  glue, jniLibs, Kotlin); tracked = the scripts/manifests/READMEs only. **Gate green:** 3 tests, host
  clippy `-D warnings` (incl. the bin w/ feature) + fmt, windows cross-clippy, `cargo check --workspace`
  — all clean. **Landed `b0c45eb`.** **Remaining spark-ffi out-of-scope:** desktop GUI,
  JSON-RPC/web facade, standalone-AAR gradle wrapper.
  **DATA-PATH SHIM UNIFICATION + RECONNECT RESYNC EVENT 2026-06-18.**
  (1) **Shim unification:** the Android JNI + Apple C-ABI shims duplicated the `Result` → `0/-1`
  status-code convention, and the config-from-primitives builder lived only in the Android shim.
  Both now live in `core::fd_tunnel`: `fd_config(addr, prefix, system_stack) -> Config` (the shared
  builder; `StackKind::System` is always present — only its *use* needs the `system-stack` feature,
  erroring at startup otherwise — so this compiles on Apple where the feature is off) and
  `run_fd(fd, mtu, config) -> i32` (the single home of the status-code convention). The shims are now
  pure marshalling: Apple `spark_tunnel_run` = `run_fd(fd, mtu, Config::default())` (NE always uses
  the userspace stack — `system` is Android-only — so default is right; 2-arg C ABI **unchanged**, no
  Swift/`spark.h` edit, no risk to the live-gated macOS NE), Android `nativeRun` = `run_fd(fd, mtu,
  fd_config(addr, prefix, system_stack))`. Removed the now-redundant `run_tunnel` (2-arg default) and
  the Android-local `config()`; fixed a stale `[`spark_core::android`]` doc link → `fd_tunnel`. New
  `fd_config` unit test. **Verified:** `cargo test -p spark-core` (fd_config) + workspace check + host
  clippy (core+apple, macOS compiles the Apple shim) + **`cargo ndk -t arm64-v8a clippy -p
  spark-android` clean** (Android shim cross-compiles with `system-stack`). Behavior-identical refactor
  (macOS NE live gate not re-run — no host capability — but `run_fd(.., default)` ≡ old
  `run_tunnel`). (2) **Reconnect resync event:** `spark-ffi`'s `TunnelEvent` gains a binding-only
  variant `StreamReconnected` (the `From<spark_ipc::TunnelEvent>` mapping is unchanged — the variant
  is synthesized, never sent by the service). `subscription_loop` tracks `established_before` and
  passes `emit_reconnect` to `run_subscription_session`, which fires `StreamReconnected` to the
  listener the moment a subscription **re**-establishes (NOT the first connect, even after connect
  retries), before pumping — so a UI knows there was a gap and re-queries `status()`. Reconnect test
  now asserts a `StreamReconnected` arrives (via a new `harness::wait_for` predicate waiter,
  `#[cfg(unix)]` since only the unix reconnect test uses it — else dead-code on Windows). Exported FFI
  surface changed (+1 enum variant) → bindings regenerate (confirmed `StreamReconnected` in the Swift
  output; they're gitignored/regenerated at packaging). **Gate green:** 3 spark-ffi tests + host/bin
  clippy + fmt + windows cross-clippy. **Landed `3546afc`.**
  **CONTROL-PLANE CORRECTNESS 2026-06-18.** From the external (codex) review — two
  of the cheap, high-value items it flagged in `service/`. (1) **Honor `Subscribe { events, logs }`:**
  the actor discarded the flags (`Subscribe { .. }`) and registered a full subscriber. `Subscriber`
  now carries `events`/`logs`; `broadcast` filters by push kind (`wants`: `Push::Event` needs
  `events`, `Push::Log` needs `logs`, `Push::Dropped` always passes — it's per-subscriber delivery
  metadata, never broadcast). So a logs-only client stops getting state spam, forward-compatible for
  when log production lands. (2) **Transitional states:** `Connect` now emits `Connecting` *before*
  `engine.start` (so a UI shows "Connecting…" during the slow bring-up) → `Connected`/`Failed`;
  `Disconnect` emits `Disconnecting` before `engine.stop` → `Disconnected` (skipped when already
  `Disconnected` so a defensive disconnect stays a quiet no-op — `transition` is idempotent and the
  `direct_fallback` reset still runs). `TunnelState::Connecting`/`Disconnecting` already existed in
  the protocol, just unused; `spark-ffi`'s mirror already carries them, so no FFI change. Updated the
  `conn.rs` integration test (Connect now yields Ack + Connecting + Connected = 3 frames, not 2) + 2
  new `service.rs` tests (flag filtering; Connect/Disconnect transitional sequence via `run_service`
  + `FakeEngine`). **NOT done (deferred, own chunk):** actual log *streaming* — `Push::Log(LogLine)`
  exists but is never produced; wiring it needs a `tracing` layer → actor channel + redaction
  (`core::redact`) + touches `main.rs`/`run_service` signature. **Gate green:** `cargo test --workspace
  --all-features` 174 pass (spark-service 19, +2), clippy `-D warnings` + fmt clean. **Landed
  `09e9968`.**
  **SYSTEM-STACK PROPERTY/FUZZ HARDENING 2026-06-18.** From the codex review —
  test-only hardening of the novel kernel-TCP rewrite/NAT code (no production change). Deterministic
  splitmix64 PRNG in each test mod (reproducible; no proptest dep, per the no-new-deps rule).
  **`netstack/system/rewrite.rs`** (+4 tests): `prop_v4_rewrite_matches_full_recompute_and_round_trips`
  (2000 random tuples — the incremental RFC-1624 checksum rewrite must be byte-identical to a
  from-scratch full rebuild, then round-trip back to the original); `prop_v6_rewrite_round_trips_and_
  keeps_checksum_valid` (new `ipv6_tcp` builder; v6 has no IP checksum, TCP must still fold to zero);
  `ipv6_extension_header_is_rejected` (pins the v6 boundary codex flagged — next-header ≠ TCP →
  `Ipv6Extension`, caller falls back; config selector is IPv4-only today); `parsers_never_panic_on_
  arbitrary_bytes` (20k random + structured-near-packet buffers through `tcp_endpoints`/`udp_endpoints`/
  `ip_protocol`/`rewrite_tcp` — the untrusted-input surface, no panic/over-read). **`netstack/system/
  nat.rs`** (+3 tests): `randomized_ops_preserve_index_consistency` (20k random lookup/lookup_back/
  remove/note_fin/evict ops over a small src/dst pool to force reuse; a `check_consistent` invariant —
  `by_source ⇄ by_port` bijection, equal size, no orphan/port-0 — runs after EVERY op, catching dual-
  index desync); `ephemeral_port_reuse_after_eviction_is_fresh` (the stale-mapping caveat's safe
  boundary: after eviction, reusing a source maps to the NEW dest, never resurrects the old);
  `port_space_exhaustion_returns_none_without_aliasing` (fill all 1..=65535, graceful `None`, no
  aliasing/port-0/infinite scan). **Gate green:** `cargo test --workspace --all-features` 181 pass
  (+7; 30 in the system module), `clippy --features system-stack` + `--all-features` `-D warnings` +
  fmt clean. **Landed `ebcddbb`.**
  **WASM SIGNING FAIL-CLOSED + MEMORY CAP 2026-06-18 (commit pending).** Review item A — closes the
  one confirmed fail-OPEN gap + a resource-limit gap, both in the `wasm-transport` path.
  (1) **Signing fail-closed:** `signing.rs` fell back to `DEV_MODULE_PUBKEY` when
  `SPARK_MODULE_PUBKEY_HEX` was unset — but the dev key's private half is in the test tree
  (`testutil::DEV_MODULE_PKCS8`), so a *release* binary built without the env var would trust a
  repo-published key anyone could sign with. Now the `None` arm is cfg-split: `#[cfg(debug_assertions)]`
  keeps the dev fallback (tests/dev), `#[cfg(not(debug_assertions))]` is a const-eval `panic!` → a
  **release build with `wasm-transport` and no pinned key fails to compile** (`error[E0080]:
  evaluation panicked: SPARK_MODULE_PUBKEY_HEX must be set …`). Verified all 3: debug-no-key compiles
  (dev fallback), `cargo check --release …` no-key FAILS, release WITH key compiles. CI unaffected —
  `ci.yml` runs `--all-features` in debug (dev fallback) and `release.yml` builds only spark/spark-
  service without wasm-transport. (2) **Memory/table cap:** fuel bounds compute, not allocation — a
  module could `memory.grow` to exhaust host RAM cheaply. Added a `wasmi` `StoreLimits` (16 MiB
  linear memory, 4096 table elements, `trap_on_grow_failure(true)`) on `HostState`, wired via
  `store.limiter(…)` in `Transform::new`. New test `memory_grow_beyond_the_cap_is_denied` (a module
  growing ~64 MiB on transform_out traps instead of allocating). wasmi 2.0.0-beta.2 API verified
  against the vendored source (`StoreLimitsBuilder::{memory_size,table_elements,trap_on_grow_failure,
  build}`, `Store::limiter`, `ResourceLimiter`). **Gate green:** `cargo test --workspace --all-features`
  182 pass (+1), clippy `--all-features -D warnings` + fmt clean. **Still open from the review:** log
  streaming; backend contract (richer IPC/FFI + handle); domain-target preservation (`Target` + DNS).
  **BACKEND CONTRACT — ADR 0004 (Proposed) 2026-06-18 (committed `91521de`).** Review item #2/#5 design:
  the control plane is launch-time-config + 4 verbs (service loads one `Config` at start, never
  mutates; `spark-ffi` mirrors connect/disconnect/status/subscribe) — a surface gap, not structural.
  `docs/adr/0004-backend-contract.md` records the decision: grow `spark-ipc` + `spark-ffi` into a
  versioned product backend contract, **additive + version-negotiated** (append enum variants —
  postcard encodes by index so v1 decoding is preserved; bump `PROTOCOL_VERSION → 2`; never emit a v2
  frame to a v1-negotiated peer), **profiles in the privileged store with write-only secrets** (the
  config tree holds `AnytlsConfig.password` + wasm `init_config`; never echoed — redacted reads,
  write-only sets, per CLAUDE.md), **counters stay in-process** (atomics → snapshots, no per-packet
  IPC), and a **`TunnelHandle`** replacing `fd_tunnel`'s process-global stop for the embedded path.
  **Slices (each shippable):** 1 capabilities+richer-status (read-only, start), 2 metrics, 3 profiles
  (CRUD + connect-by-profile, the big one), 4 log streaming (folds in review item B), 5 embedded
  handle model. Approved direction; building 1 then 2.
  **BACKEND CONTRACT — SLICE 1 (capabilities + richer status) 2026-06-18 (commit pending).** Read-only,
  additive. **`PROTOCOL_VERSION → 2`**. New `core::caps::compiled()` reports the build's optional
  features (`cfg!(feature = anytls|wasm-transport|system-stack)`). ipc gains `RequestPayload::
  {GetCapabilities,GetDetails}` + `ResponsePayload::{Capabilities,Details}` + types `Capabilities`
  (protocol/build version, supported `transports`/`stacks`, `os/arch` platform), `Details` (state,
  direct_fallback, selected transport/stack, `module: Option<ModuleInfo>` [None until a later slice],
  kill_switch, last_error), and the ipc-local enums `TransportKind`/`NetStack`/`KillSwitchMode`
  (portable — ipc has no core dep). The actor (`run_service`) now takes a `BackendInfo` (computed once
  at startup by `service::backend_info(&config)` from caps + the selected transport/stack); it tracks
  `negotiated: Option<ProtocolVersion>` (replacing `handshook`) and `last_error` (set on connect
  failure + kill-switch, cleared on connect). **v2 requests are version-gated:** a v1-negotiated peer
  gets `InvalidRequest` rather than an undecodable frame (ADR principle). `spark-ffi` mirrors the
  types + adds async `Backend::capabilities()`/`details()` (Swift `func … async throws -> Capabilities/
  Details` confirmed in regenerated bindings); the CLI gains `spark capabilities`/`spark details`
  subcommands. **Gate green:** `cargo test --workspace --all-features` 184 pass (+2 service tests:
  capabilities/details-reflect-info + v1-gate; spark-ffi e2e extended to exercise both); clippy
  `--all-features -D warnings` + fmt + windows cross-clippy clean. **(committed `5045eb6`.)**
  **BACKEND CONTRACT — SLICE 2 (metrics) 2026-06-18 (commit pending).** Data-path counters, still v2.
  New `core::metrics`: `Metrics` (atomic `bytes_up`/`bytes_down`/`sessions_active`/`sessions_total`),
  `MetricsSnapshot`, a `Counting<S>` stream wrapper (live byte tally — one Relaxed add per poll, not
  per byte; on the *upstream* half so writes=up, reads=down), and an RAII `SessionGuard` (inc total+
  active on open, dec active on drop — so an aborted forwarder task still releases its active count).
  `proxy::tcp::run`/`forward` thread `Arc<Metrics>` (the upstream is wrapped in `Counting`, the flow
  scoped by a `SessionGuard`); the 4 callers (engine, fd_tunnel, cli, proxy test) updated — `CoreEngine`
  owns the `Arc<Metrics>` (cumulative across connect/disconnect) and the others pass a local counter.
  `TunnelEngine` gains `fn metrics(&self) -> MetricsSnapshot` (CoreEngine → snapshot; FakeEngine →
  default). ipc adds `RequestPayload::GetMetrics` + `ResponsePayload::Metrics` + the `Metrics` wire
  type (version-gated with the other v2 reqs). `spark-ffi` mirrors `Metrics` + async `Backend::
  metrics()`; CLI gains `spark metrics`. **Counting is on flow COMPLETION-independent (live per poll);
  TCP-only — UDP metrics + periodic `Push::Metrics` are follow-ups.** **Gate green:** `cargo test
  --workspace --all-features` 186 pass (+2 core: `session_guard_tracks…`, `counting_tallies…`;
  GetMetrics folded into the slice-1 service + spark-ffi e2e tests); clippy `--all-features -D warnings`
  + fmt + windows cross-clippy clean; Kotlin bindings carry `metrics`/`class Metrics`. **(committed
  `a5e6b2a`, pushed.)**
  **BACKEND CONTRACT — SLICE 3a (profile management) 2026-06-18 (commit pending).** Connection-profile
  CRUD, still v2. A **profile = a named `core::config::Config`** stored in the privileged service.
  **Secrets are write-only over IPC** (CLAUDE.md): the AnyTLS `password` + wasm `init_config` are
  blanked on read and a blanked field on write keeps the stored value — so a read→edit→write round-trip
  never needs the client to have seen the secret. Represented as a **redacted TOML doc** (not a typed
  mirror) to keep the ipc surface small and the redaction in one place. New `service::profiles`
  (`ProfileStore`: in-memory `BTreeMap<name, Config>` + active; `set` parses TOML + `keep_blanked_
  secrets` merge; `get_redacted` clears secrets + `to_toml_string`; `list`→summaries; `validate`).
  ipc adds `RequestPayload::{ListProfiles,GetProfile,SetProfile,DeleteProfile,SetActiveProfile,
  ValidateProfile}` + `ResponsePayload::{Profiles,Profile,Validated}` + `ProfileSummary`/`ProfileDoc`/
  `Validation` (all version-gated with the v2 reqs). The actor holds a `ProfileStore` + handlers;
  `selected_transport`/`netstack_of` promoted to `pub(crate)` and reused. `spark-ffi` mirrors the
  types + adds async `list_profiles`/`get_profile`/`set_profile`/`delete_profile`/`set_active_profile`/
  `validate_profile` (Swift bindings confirmed); CLI gains `spark profiles`. **DEFERRED to slice 3b
  (own chunk, touches the live-gated connect/engine path):** connect-by-active-profile (the
  `TunnelEngine::start(config)` refactor + `Details` reflecting the active profile) and **disk
  persistence** (the store is in-memory — profiles are lost on daemon restart). **Gate green:** `cargo
  test --workspace --all-features` 191 pass (+5: 4 `ProfileStore` unit tests incl. the secret
  round-trip + redaction, 1 actor CRUD/redaction e2e; spark-ffi e2e exercises the FFI CRUD); clippy
  `--all-features -D warnings` + fmt + windows cross-clippy clean. **(committed `581e2c1`, pushed.)**
  **BACKEND CONTRACT — SLICE 3b (connect-by-active + disk persistence) 2026-06-18 (commit pending).**
  Makes profiles fully live. (1) **Connect-by-active-profile:** `TunnelEngine::start` now takes the
  `Config` per call (`start(config, exit)`), so `CoreEngine` no longer stores one — `new()` is
  argless and the actor passes the *effective* config (the active profile's, or the launch/base
  config if none) on each Connect. `BackendInfo` reshaped: dropped the static `selected_transport`/
  `selected_stack` (now derived live from the active profile or base), added `base_config` +
  `profiles_path`. `GetDetails` reflects the active profile's transport/stack. (2) **Disk
  persistence:** `ProfileStore` now persists to a single root-owned TOML file (`StoredProfiles`
  wrapper; profile names are map keys, **not** path components — no filesystem traversal from a
  profile name), loaded at startup, rewritten on every mutation (best-effort, logged on failure;
  missing = empty, unparseable = logged + ignored so a corrupt file can't wedge the daemon). daemon
  gains a `--profiles` arg (default `/var/lib/spark/profiles.toml`; `C:\ProgramData\spark\…` on
  Windows, mirroring the `socket` arg). Added `serde`+`toml` to `spark-service` (both workspace-locked,
  already used by `core` — not new external deps). `FakeEngine` now records the config it was started
  with so the test can prove Connect used the active profile. **Profiles are full `Config`s** (the
  effective config is the active profile's, not a merge with base) — documented. **Gate green:** `cargo
  test --workspace --all-features` 193 pass (+2: `connect_uses_the_active_profile`,
  `persists_across_reload_including_secrets_and_active`); host clippy `--all-features -D warnings` +
  fmt clean. **Windows cross-check not run here** — `ring`'s C build needs a Windows toolchain this
  macOS host lacks (pre-existing; CI covers it); the one Windows-specific addition (the `--profiles`
  arg) mirrors the working `socket` arg. **SLICE 3 COMPLETE (profiles end-to-end).** ADR 0004 remaining:
  slice 4 (log streaming), slice 5 (embedded `TunnelHandle`). **(committed `91ec21c`, pushed.)**
  **BACKEND CONTRACT — SLICE 4 (log streaming) 2026-06-18 (commit pending).** Produces the `Push::Log`
  stream the `logs` subscribe flag (wired in the earlier control-plane-correctness chunk) already
  filters on. New `service::logbus`: a `LogForwarder` `tracing` Layer turns each event into a redacted
  `LogLine` (`core::redact::redact_addrs` strips address literals — the GOAL.md privacy property) and
  `try_send`s it (lossy on backpressure — never blocks a logging call) onto a process-global channel;
  `logbus::init()` creates the channel + registers the global sender, returning the receiver. The
  daemon's `init_tracing` switched from `fmt().init()` to a `registry().with(filter).with(fmt).with(
  LogForwarder)`. `run_service` gained `log_rx: Option<Receiver<LogLine>>` (a `next_log` helper pends
  forever when `None` so the `select!` branch never busy-loops; on close it sets `None`); it drains the
  channel and `broadcast`s `Push::Log` (the `wants` filter drops it for events-only subscribers).
  `spark-ffi` now CONSUMES logs: mirror `LogLine`/`LogLevel`, `EventListener` gained `on_log`, and the
  subscription loop requests `logs: true` + routes `Push::Log → on_log` (Swift `onLog`/`LogLine`/
  `LogLevel` in regenerated bindings). **Gate green:** `cargo test --workspace --all-features` 195 pass
  (+2: `log_lines_stream_to_logs_subscribers_only` — a fed log reaches a `logs:true` subscriber but not
  an events-only one; `logbus::maps_tracing_levels`); clippy `--all-features -D warnings` + fmt +
  windows-ffi cross-clippy clean. **SLICE 4 COMPLETE.** ADR 0004 remaining: slice 5 (embedded
  `TunnelHandle`). **(committed `35e8895`.)**
  **BACKEND CONTRACT — SLICE 5 (embedded TunnelHandle) 2026-06-18 (commit pending).** Replaces
  `fd_tunnel`'s single process-global stop `Notify` with a **registry of per-tunnel `Arc<Notify>`**:
  each running tunnel registers its own signal for its lifetime; the no-arg `stop()` (the shim
  teardown) signals them all, while a new `TunnelHandle::stop()` signals only its own — so independent
  tunnels tear down independently (codex #5). The shared impl `run_with_handle(fd, mtu, config, stop)`
  registers/deregisters the signal and waits on it; `run_tunnel_with_config` (→ `run_fd`, the shims)
  delegates with a private signal, so the **JNI/C-ABI ABIs + behavior are unchanged** (for one
  tunnel: register one signal, `stop()` wakes it = identical to the old single global) — the
  live-gated mobile paths aren't touched. New `pub fn spawn_tunnel(fd, mtu, config) -> TunnelHandle`:
  a **non-blocking** start (runs on a background thread + private runtime) returning a handle that
  stops the tunnel via `stop()` or on `Drop` (RAII) — the per-tunnel API for a future in-process
  embedder (start failures are logged, not returned — a status callback is a later refinement). **Gate
  green:** `cargo test --workspace --all-features` 196 pass (+1: `registered_stop_wakes_only_its_own_
  waiter` — an independent waiter isn't woken by another tunnel's stop, but the global `stop()` wakes
  all); host clippy `--all-features -D warnings` + fmt + **`cargo ndk -t arm64-v8a clippy -p
  spark-android`** clean (the Apple shim on macОS is covered by host clippy). Windows full-workspace
  cross-check still ring-blocked here (CI). **SLICE 5 COMPLETE — ADR 0004 (the backend contract) is
  DONE end-to-end: capabilities, details, metrics, profiles (CRUD + connect-by-active + persistence),
  log streaming, and the embedded handle model, all over `spark-ipc` + mirrored in `spark-ffi`.**
  **GUI — Flutter v1 (connect/disconnect/status) 2026-06-18 (commit pending).** First product GUI
  (direction in the [[gui-direction-flutter]] memory): a **Flutter** app in `gui/` (macOS target),
  one screen — a state-reactive "signal orb", connect/disconnect toggle, fail-open warning — polling
  status every 2s. **Integration via a `SparkBackend` abstraction** (`lib/spark_backend.dart`, same
  `status`/`connect`/`disconnect` shape as `spark-ffi`'s `Backend`); the v1 impl `CliBackend` shells
  out to the built `spark` CLI (which speaks `spark-ipc` to `spark-service`) — **zero FFI, works
  today**, and the UI is unchanged when the real bindings slot in (desktop = `flutter_rust_bridge`
  over `spark_ipc::Client`; mobile = platform channel → native VpnService/NE shim + the `spark-ffi`
  UniFFI bindings). Distinctive dark "signal" theme (Sora + JetBrains Mono via `google_fonts`,
  teal/amber/rose state colours, pulsing orb). **Verified:** `flutter analyze` clean, `flutter test`
  (widget smoke test vs a fake backend) passes, **`flutter build macos --debug` → `spark_gui.app`**.
  Build artifacts (`build/`, `.dart_tool/`) gitignored. **Runtime caveat:** the macOS App Sandbox
  blocks `CliBackend` spawning `spark` — disable the sandbox for dev, or use the (follow-up)
  in-process `flutter_rust_bridge` backend. **Next:** real frb desktop backend; ios/android +
  platform-channel backend; richer screens (capabilities/details/metrics/logs/profiles) off the
  ADR-0004 contract.
  **GUI-AGNOSTIC BACKEND — `spark-backend` extracted 2026-06-18 (commit pending).** Made the whole
  control backend Flutter-/binding-agnostic so any GUI can swap in (the user's explicit ask). New
  workspace crate **`spark-backend/`**: a typed async `Backend` over `spark_ipc::Client` —
  `connect`/`disconnect`/`status`/`capabilities`/`details`/`metrics`, the profile CRUD, and a
  reconnecting `run_subscription(on_event: impl FnMut(BackendEvent))` — that **returns plain
  `spark-ipc` types, carries NO binding annotations, and owns NO runtime**. It's `Clone` (just the
  endpoint path, no connection) so a binding clones it into its own spawned task and drives the
  `async fn`s on whatever executor it has. `BackendEvent` (`Event`/`Log`/`Reconnected`) is the
  binding-agnostic stream item; `BackendError` keeps the typed `ErrorCode` categories plus a
  `Transport` bucket (with the `From<ErrorCode>` mapping that used to live in `spark-ffi`).
  **`spark-ffi` is now a thin UniFFI binding over it**: it keeps the `#[derive(uniffi::*)]` mirror
  types + `From<spark_ipc::*>` conversions, owns the tokio runtime the foreign calls are driven on,
  and each method `clone()`s the inner backend and `spawn`s the delegated call (`spawn<T,F>` helper
  → `JoinError` ⇒ `Transport`, the backend's error ⇒ `From`); `subscribe` maps `BackendEvent` to the
  `EventListener` callbacks (`Reconnected` ⇒ `TunnelEvent::StreamReconnected`). All the reconnect /
  per-call-connection / wire logic moved *down* into `spark-backend`; the binding holds none of it.
  **Litmus test holds:** dependency arrows point INTO `spark-backend` (`spark-ffi`, and later a
  `flutter_rust_bridge` bridge / Tauri / Dioxus / CLI all depend on it; it depends on nothing
  binding-shaped). **Gate green:** `cargo test --workspace --all-features` (spark-ffi's e2e
  roundtrip + reconnect tests pass unchanged — the UniFFI `Backend` public API is byte-for-byte
  preserved; new `spark-backend` unit tests + a rewritten `spark-ffi` 1:1-mirror test); host clippy
  `--all-targets --all-features -D warnings` + **spark-ffi Windows cross-clippy** + fmt all clean;
  **Swift + Kotlin bindings regenerate with the full 14-method `Backend` surface intact**. **Next
  (deferred):** the real `flutter_rust_bridge` desktop backend — a thin bridge crate over
  `spark-backend` + a Dart `FrbBackend implements SparkBackend` (note: `flutter_rust_bridge_codegen`
  is not yet installed).
  **DESKTOP FLUTTER BACKEND — `spark-bridge` (flutter_rust_bridge) 2026-06-18 (commit pending).** The
  real desktop binding, a thin **`flutter_rust_bridge`** layer over `spark-backend` (the deferred
  follow-up from the agnostic extraction). New workspace crate **`spark-bridge/`**: an opaque
  `SparkBridge` frb object (cdylib + lib) that owns a tokio runtime and `block_on`s the delegated
  `spark-backend` calls (same owned-runtime model as `spark-ffi`, so it never touches frb's own async
  executor — frb runs the blocking methods on its worker pool and Dart still gets `Future`s); mirror
  types `BridgeState`/`BridgeStatus`/`BridgeError` (`From<spark_ipc::*>`/`From<spark_backend::*>`, 1:1)
  keep the generated Dart small. **Toolchain:** installed `flutter_rust_bridge_codegen` **2.12.0** —
  pinned to EXACTLY match the `flutter_rust_bridge` crate (`=2.12.0`, added to workspace deps,
  spark-bridge-only) and the Dart `flutter_rust_bridge` package (added to `gui/pubspec.yaml` with
  `freezed`/`build_runner`); all three must agree. Config `flutter_rust_bridge.yaml` (repo root) scans
  `spark-bridge::api` → emits Dart into `gui/lib/src/rust/`; the generated Dart + Rust glue
  (`spark-bridge/src/frb_generated.rs`) are **checked in** (so a build needs no codegen tool — `frb`'s
  `cfg(frb_expand)` declared via a `check-cfg` lint so `-D warnings` stays clean). **Dart side:**
  `gui/lib/frb_backend.dart` — `FrbBackend implements SparkBackend` (`FrbBackend.create()` inits
  `RustLib` once, binds the socket), remapping the generated sealed `BridgeError` to the UI's
  `SparkException` via an **exhaustive `switch`** (a new Rust error variant fails Dart analysis until
  handled). **Gate green:** `cargo test --workspace --all-features` (+3 spark-bridge mapping tests),
  host clippy `--all-targets --all-features -D warnings` (incl. the generated glue) + fmt,
  `flutter analyze` clean + `flutter test` passes. **REMAINING (deferred, like other live gates):**
  the **native build integration** (cargokit / `rust_builder`) so `flutter build macos` compiles +
  bundles `libspark_bridge.dylib` and `RustLib`'s loader finds it (the generated default
  `ioDirectory` assumes a per-crate `target/`, not the workspace `target/`); then swap `FrbBackend` in
  as the default desktop backend (it needs no subprocess → works under the App Sandbox, unlike
  `CliBackend`) and run a live gate against a running `spark-service`. `flutter_rust_bridge` is linked
  ONLY by `spark-bridge` — never core/cli/service.
  **DESKTOP FLUTTER BACKEND — native build wired + `FrbBackend` is now the default 2026-06-18 (commit
  pending).** Closed the "remaining" item from the prior entry: `flutter build macos` now compiles +
  links the Rust bridge, and `FrbBackend` is the desktop default. **cargokit integration:** harvested
  the version-matched `rust_builder/` plugin from `flutter_rust_bridge_codegen create` into `gui/`,
  repointed at `spark-bridge` (each relative crate path gains one `../` since the crate sits *outside*
  the `gui/` app dir → `../../../spark-bridge`; plugin named `spark_bridge`). **Gotcha hit + fixed:**
  cargokit builds the expected artifact filename as `lib<cargo-package-name>.a` **verbatim**, but
  cargo normalizes hyphens → underscores — so a `spark-bridge` package made it hunt for
  `libspark-bridge.a` while cargo emits `libspark_bridge.a` ("unable to find bundle for dynamic
  library"). Fix: renamed the cargo **package** to `spark_bridge` (underscore; dir stays
  `spark-bridge/`, lib name was already `spark_bridge`) — the frb template uses underscore names for
  exactly this reason. Added `staticlib` to the crate-type (cargokit force-loads `libspark_bridge.a`
  into the app on macOS/iOS). `gui/pubspec.yaml` deps on the `spark_bridge` plugin (`path:
  rust_builder`); `gui/analysis_options.yaml` excludes `rust_builder/**` (vendored build tooling, not
  app code). **`main.dart`** now builds `FrbBackend` as the desktop default with a **graceful
  fallback to `CliBackend`** if `RustLib` can't init (so the app always launches). **Verified
  (build/link level):** `flutter build macos --debug` → `spark_gui.app` with **`spark_bridge.framework`
  (11.9 MB) bundled** — `nm` confirms the Rust staticlib + frb's `frbgen_spark_gui_rust_arc_*` exports
  + `Dart_PostCObject_DL` are force-loaded in; `flutter analyze` clean + `flutter test` passes; Rust
  workspace `cargo test --workspace --all-features` + clippy `-D warnings` + fmt clean after the
  package rename. **Runtime-verified end-to-end** via a **flutter integration test**
  (`gui/integration_test/frb_bridge_test.dart`, run with `flutter test integration_test -d macos`):
  unlike `flutter test` (bare Dart VM, no native lib), this launches the real macOS app so the
  cargokit-linked framework actually loads, then `FrbBackend.create()` + `status()` against a dead
  socket surfaces a typed `SparkException` — proving `RustLib.init()` loaded the framework, the FFI
  call dispatched into Rust, `spark-backend` attempted the connection, and the error round-tripped
  back through the bridge. (Ran headless here — "Failed to foreground app" since there's no window
  server, but the test executed + passed.) **STILL pending = the *successful*-connect path:** launch
  against a running `spark-service` (needs the daemon + sandbox disabled / a socket entitlement for
  `/var/run/spark.sock`). The `FrbBackend.create()` → `CliBackend` fallback de-risks a bad load.
  **Fonts bundled (privacy) 2026-06-18 (commit pending).** A first `flutter run` showed `google_fonts`
  throwing on every launch trying to fetch Sora/JetBrains Mono from `fonts.gstatic.com` (App Sandbox
  blocks it — `errno=1`), and for a privacy/VPN tool the GUI must not beacon to Google regardless.
  Bundled the 5 static TTFs (Sora Regular/SemiBold/Bold + JetBrains Mono Regular/SemiBold, SIL OFL 1.1,
  licenses alongside) under `gui/assets/fonts/`; `google_fonts` 6.3.3 checks the asset bundle before
  fetching (`_findFamilyWithVariantAssetPath` matches the `<Family>-<Variant>` filename), so the
  `GoogleFonts.*` calls are unchanged and there's now **zero runtime network fetch** for fonts (works
  offline + sandboxed). Verified bundled into `spark_gui.app`; analyze + widget test clean.
  **macOS distribution model — ADR 0005 (Proposed) 2026-06-18 (commit pending).** Researched the ask
  "create a notarized release build" + the follow-up "app bundle w/ embedded system extension (DMG)
  vs `.pkg` + launchd". Wrote `docs/adr/0005-macos-distribution-and-privileged-component.md` (external
  research agent, cited). **Key reframe:** it's "which privileged component," not "DMG vs pkg" — modern
  `SMAppService` (macOS 13+) lets the *daemon* model also ship in a drag-installed app bundle, so
  `.pkg` is only the legacy daemon path. **Model A** = NE *system extension* embedded in the app, DMG
  (already built/notarized/**live-gated** in `platforms/apple`; control via `NETunnelProviderManager`/
  `sendProviderMessage`, NOT `FrbBackend`). **Model B** = `spark-service` launchd daemon
  (SMAppService or pkg; reuses the `FrbBackend`/`spark-bridge`/`spark-ipc` stack we just built).
  Confirmed constraint: non-App-Store ⇒ must be a *system extension* (NE app-extensions are App-Store
  only — Tailscale). **Recommendation: Model A for the macOS consumer product** (lowest risk — extends
  the proven sysext; Apple-idiomatic; no always-on root daemon; DMG drag-install + delete-to-uninstall;
  future-proofs an App-Store NE build), **keep Model B + `FrbBackend` for Linux/Windows desktop + the
  CLI/Homebrew/enterprise channel** (matches the doc's "one path per channel"). **Main consequence:**
  the macOS GUI backend becomes a NE/platform-channel adapter, not `FrbBackend` — the `SparkBackend`
  Dart seam makes that swap clean; `FrbBackend` stays the Linux/Windows path. **Awaiting the user's
  pick before building the `packaging/macos/` notarize pipeline** (decided inputs already: script
  called by CI; unsandboxed + hardened runtime).
  **macOS DMG notarize pipeline BUILT (Model A chosen) 2026-06-18 (commit pending).** User picked
  Model A (NE sysext + DMG). Built **`packaging/macos/build-dmg.sh`** (source of truth, CI calls it):
  `build-xcframework.sh` → `xcodegen` → `xcodebuild archive` (Developer-ID, manual) → `-exportArchive`
  with `platforms/apple/ExportOptions.plist` → notarize+staple the `.app` → `hdiutil` DMG
  (drag-to-`/Applications`) → sign+notarize+staple the DMG → verify (`codesign`/`spctl`/`stapler`).
  Creds: `NOTARY_PROFILE` *or* `AC_USERNAME`+`AC_PASSWORD`; `SKIP_NOTARIZE=1` for a no-creds dry run.
  **Validated end-to-end locally** (sandbox off so codesign reaches `timestamp.apple.com`): archive +
  export SUCCEEDED, DMG built with the embedded `org.getlantern.spark.tunnel.systemextension`, `.app`
  passes `codesign --verify --deep` with **hardened runtime + secure timestamp + Team ACZRKC3LQ9**;
  only the `notarytool` submit is unrun here (needs the user's Apple creds — none stored on this box).
  **Bug found+fixed during validation:** signing the DMG by the identity *name* was ambiguous (3
  same-named Developer-ID certs in the keychain) → resolve to the SHA-1 hash and sign by that
  (`SIGN_IDENTITY` override). **CI:** `release.yml` gains a `package-macos-app` job (macos runner,
  imports cert + profiles from secrets, runs the script, uploads the DMG to the Release), **gated by
  repo var `MACOS_APP_PACKAGING=true`** so releases work before signing is configured; `publish` now
  `needs: [build, package-macos-app]` with `always() && build success` so a skipped app job doesn't
  block it. `dist/` gitignored. CI job is **not yet run** (needs the repo secrets/var). **Follow-up:**
  the controlling app is still the `platforms/apple` SwiftUI harness; making the Flutter `gui/` app the
  controlling app (embed the sysext + a NE platform-channel backend) is the ADR-0005 integration.
  **NOTARIZATION PROVEN + FLUTTER-AS-CONTROLLING-APP (slice 1) 2026-06-18 (commit pending).**
  (1) **Notarization works:** `AC_USERNAME`/`AC_PASSWORD` are set in the env (same convention as
  lantern's Makefile, team ACZRKC3LQ9). Ran `notarytool submit` on the existing signed DMG → **status
  Accepted**, `stapler staple` + `validate` OK, `spctl --assess` → **"accepted, source=Notarized
  Developer ID"**. So `build-dmg.sh` produces a genuinely notarized DMG end-to-end (proven on the
  SwiftUI-harness app). (2) **Flutter is now the macOS controlling app (Model A):** the `gui/` app's
  bundle id → **`org.getlantern.spark`** (reuses the "Spark macOS App" Developer-ID profile + the
  `group.org.getlantern.spark` App Group + NE entitlements); `Release`/`DebugProfile.entitlements`
  mirror `platforms/apple` (NE `packet-tunnel-provider-systemextension` + `system-extension.install` +
  app-group, unsandboxed); `AppInfo.xcconfig` + the Runner pbxproj configs set **manual Developer-ID
  signing** (style Manual, identity "Developer ID Application", profile "Spark macOS App", hardened
  runtime). New `macos/Runner/SparkVPN.swift` = the NE control (lifted from `SparkApp.swift`:
  `OSSystemExtensionRequest` activation + `NETunnelProviderManager` start/stop/status) behind a
  `MethodChannel("spark/ne")`; new Dart `gui/lib/ne_backend.dart` (`NEBackend implements
  SparkBackend`); `main.dart` selects `NEBackend` on macOS, `FrbBackend`/`CliBackend` elsewhere.
  **Verified:** `flutter build macos --release` → `spark_gui.app` (45 MB — the Flutter engine, vs
  <1 MB SwiftUI) **signed Developer-ID as org.getlantern.spark with the NE entitlements**; `flutter
  analyze` + `flutter test` clean. (`get-task-allow=true` is present — the known `flutter build`
  non-archive quirk; the packaging re-sign strips it for notarization.) **REMAINING (slice 2):** embed
  the `SparkTunnel.systemextension` into the Flutter app bundle + re-sign inside-out + DMG + notarize
  (the packaging step for the Flutter app); then the live gate (activate sysext + connect). Also: the
  unused `spark_bridge` framework still builds into the macOS app (bloat) — exclude it from macOS later.
  **FLUTTER NOTARIZED-DMG PACKAGING (slice 2) 2026-06-18 (commit pending).** `packaging/macos/
  build-gui-dmg.sh`: builds the signed `SparkTunnel.systemextension` via the platforms/apple archive,
  `flutter build macos --release`, **embeds the sysext** into `spark_gui.app/Contents/Library/
  SystemExtensions/`, **re-signs the app top-level** (no `--deep`: seals the sysext + re-signs the main
  exec with `Release.entitlements`, which omits `get-task-allow` → notarizable, + `--options runtime`;
  nested Flutter frameworks + the sysext keep their own signatures), then DMG → notarize+staple
  (.app + DMG) → verify. Same creds/flags as `build-dmg.sh` (`SKIP_NOTARIZE=1` dry run). **Dry-run
  validated end-to-end:** archive SUCCEEDED, flutter build → 45 MB app, embed + re-sign → `codesign
  --verify --deep --strict` **"valid on disk / satisfies its Designated Requirement"**, DMG built; the
  final app verified to have the embedded `org.getlantern.spark.tunnel.systemextension`, **hardened
  runtime + Developer-ID + secure timestamp + `get-task-allow` STRIPPED** (notarization-ready), and the
  sysext still validly signed. **FULL NOTARIZATION CONFIRMED:** a no-`SKIP_NOTARIZE` run notarized
  both the `spark_gui.app` (embedded-sysext) and the DMG — `notarytool` **status Accepted** for each,
  both stapled, `stapler validate` OK, `spctl --assess` → **"accepted, source = Notarized Developer
  ID"**. So `dist/spark-gui-<ver>-macos-arm64.dmg` (19 MB) is a Gatekeeper-ready notarized release of
  the Flutter controlling app. **REMAINING:** the live gate (launch the Flutter app → approve sysext →
  connect → browse); a CI job for the GUI DMG (mirror `package-macos-app`); drop the unused
  `spark_bridge` framework from the macOS build.
  **PROXY ROUTING WIRED INTO THE NE DATA PATH + DO RELAY 2026-06-18 (commit pending).** Made the app
  actually tunnel through a remote proxy (not just direct-forward). (1) **A throwaway DO droplet**
  (`137.184.47.220`, sfo3, ID `578689132`) runs `scripts/spark-plain-relay.py` — a ~50-line relay
  speaking spark's plain SOCKS5-style header (`ATYP|ADDR|PORT` then splice; see `tcp_tunnel/header.rs`)
  on `:9000`. **Internet-proven:** mimicking spark's plain client from the laptop (target
  `icanhazip.com:80`) returned `137.184.47.220` — egress is the relay. (2) **Apple C ABI extended:**
  `spark_tunnel_run(fd, mtu, server)` — `server` null/empty → direct; a `host:port` IP literal sets
  `Config.transport.server` so the core tunnels every flow through that plain relay. `PacketTunnelProvider`
  reads `providerConfiguration["server"]` and passes it (already full-tunnel routes). (3) **Flutter
  app:** `SparkVpn.connect(server:)` sets `providerConfiguration["server"]`; `NEBackend` sources it
  from `--dart-define=SPARK_PROXY=host:port` (empty → direct, no throwaway IP committed); `build-gui-dmg.sh`
  forwards `SPARK_PROXY`. So **toggling the app on → routes through the relay → egress = relay IP.**
  **Verified (compile level):** `cargo clippy -p spark-apple` (macOS+iOS) + fmt; `swift build` (the
  sysext provider against the new ABI); `flutter analyze` + `flutter build macos --release
  --dart-define=SPARK_PROXY=…`. Also `scripts/spark-plain-gate.sh` = the `sudo spark run` CLI gate
  (closes M4). **REMAINING (live, human):** run the gate / install the proxy-baked notarized DMG,
  approve the sysext, connect, confirm the egress IP flips to the relay. Plaintext relay (demo, not
  circumvention-grade — that's the AnyTLS path). **Tear down droplet 578689132 after testing.**
- **ADR 0006 — early-bytes handshake shaping + portable gambit + discovery (Proposed) 2026-06-18
  (commit pending).** From a design discussion (not yet built): censors classify on the **first ~5
  packets**, so specialize the substrate on the **opening gambit** (ClientHello content + record
  framing + TCP-segment fragmentation + timing); bulk stays native. Key reframes: (1) most of this is
  **Tier-1** (a signed, parameterized native gambit config), not Path B; (2) **Path B narrows to a
  handshake-shaper** that emits a *plan* (knobs|bytes + framing + timing), with a **constrained** mode
  (boring stays the TLS engine) primary and an **unconstrained** byte-level mode (module drives the
  handshake via new X25519/HKDF/AES-GCM host fns) as the parser-differential escape hatch; (3) **don't
  carve Cronet** — `boring2`+profile already *is* the byte-exact Chrome CH parcel; Cronet = CI
  ground-truth oracle only; (4) the gambit is a **portable parameter genome** — `boring` (Rust/spark)
  and **uTLS** (Go/lantern) are two executors, so **discover once, deploy to both fleets**; (5) a
  **discovery loop** (GA + LLM grounded in the corpus; anchor at genuine Chrome and penalize anomaly;
  Ed25519-signed deploy). **Telemetry is SERVER-SIDE only (decided 2026-06-19):** the server is the
  oracle — a connection that reaches+auths to one of our (rotating) servers *is* the success datum
  (gambit id signaled inside the authenticated tunnel; no client phone-home). The server sees only
  arrivals (no failures), so fitness is **comparative A/B over sub-populations** + **server rotation
  isolates gambit-quality from server-blockedness** (search and rotation co-evolve). Docs:
  `docs/adr/0006-early-bytes-handshake-shaping.md` (decision) + `docs/handshake-gambit-design.md`
  (**genome schema locked v1** — field reference, signed envelope, capability tags, executor-mapping
  table, the server-side discovery harness, open questions) + `docs/phase1-handshake-framing.md`
  (**Phase 1 build spec** — the socket-layer `SegmentShapingStream` for SNI-boundary fragmentation +
  timing, the minimal CH/SNI parser, the `WirePlan` = genome Layer C, and `capture-clienthello` +
  JA4-drift test; build-ready, live-gate via tcpdump on the DO box). **Go
  angle:** uTLS (the every-knob CH lib spark lacks in Rust) + wazero are already in lantern
  (samizdat/water), so the Go fleet is the lower-effort home for CH manipulation; the portable genome
  ties both. **Build order:** P0 anchor capture/CI drift → P1 socket-layer segment/timing (SNI frag) →
  P2 constrained CH knobs as signed config (lock the genome here) → P3 Path B computes the gambit → P4
  unconstrained byte-builder → P5 the harness. Value lands at P1–P2 (buildable now on the DO relay).
- **NE-AnyTLS PRODUCT GATE PASSED on macOS (Model A, ADR 0005/0006) 2026-06-19.** The *real* macOS
  product path now tunnels over AnyTLS: the **DMG-installed Flutter app** (bundled
  `SparkTunnel.systemextension`) → approve the sysext once → click **Connect** → **full-tunnel over
  AnyTLS, no service, no sudo, no manual routes** (egress = the droplet). First-ever live run of the
  NE data path. Enabled by the config-driven C ABI (`ea699e5`): `spark_tunnel_run`'s 3rd arg is now
  dual-mode (host:port plain relay *or* a full TOML `Config` via `Config::from_toml_str`), threaded
  through `providerConfiguration["config"]` (Swift NE + gui/macos) and the Dart `NEBackend` (from
  `--dart-define=SPARK_CONFIG=<base64 TOML>`); `spark-apple` got an `anytls` feature built into the
  macOS xcframework slice (iOS shares the ABI, returns -1 for AnyTLS until BoringSSL-for-iOS).
  `build-gui-dmg.sh` bakes `SPARK_CONFIG`; the notarized DMG (sysext + app, Developer-ID + stapled)
  built clean. The OS-managed full-tunnel (`includedRoutes`) is why Connect needs no manual routes —
  answering the two product questions from the FrbBackend gate.
- **GUI restyle → Lantern look 2026-06-19.** `gui/lib/main.dart` home page restyled to match
  getlantern/lantern: **light theme** (near-white `#F8FAFB`, white cards), the Lantern **cyan brand
  `#00BDD6`** for connected / grey `#616569` off, and a **large sliding pill toggle** with a white
  knob + in-knob spinner during transitions (mirrors lantern's `VPNSwitch`/`actionToggle*` palette) —
  replacing the dark "signal orb" aesthetic. Backend wiring unchanged; `flutter analyze` + widget test
  + `flutter build macos` green. Applies to both the NE (product) and FrbBackend paths.
- **SING-BOX INTEROP + UDP GATE PASSED on macOS (ADR 0006 / AnyTLS) 2026-06-19.** spark's clean-room
  Rust anytls client validated against the **production ecosystem server** (not just the anytls-go
  reference): `sing-box 1.13.13` `anytls` inbound on a fresh DO droplet (:443, self-signed EC cert,
  password auth, default padding scheme), same gambit config (chrome-137 anchor + `sni_boundary`
  shaping). **TCP:** `curl https://1.1.1.1/cdn-cgi/trace` → `ip=67.205.156.185` (the droplet). **UDP
  (first live test of the UoT-v2 path):** `dig @9.9.9.9 example.com` through `utun15` → resolved (A
  records) — spark's UDP-over-anytls interops with sing-box's UoT. Proves protocol correctness +
  padding-scheme adoption + UoT v2 against the dominant deployed implementation. Ephemeral infra torn
  down post-gate. So the AnyTLS transport is now gated against **both** anytls-go (reference) and
  sing-box (production), TCP **and** UDP.
- **GAMBIT LIVE GATE PASSED on macOS (ADR 0006) 2026-06-19.** End-to-end over the internet: `sudo
  spark run --config gate.toml` (AnyTLS → a fresh DO droplet running anytls-go 0.0.12 on :443, with
  `[transport.anytls.clienthello]` = chrome-137 anchor + `[transport.shaping] segment_split =
  sni_boundary`), then `route add 1.1.1.1 -interface utunN` + `curl https://1.1.1.1/cdn-cgi/trace`
  → **`ip=137.184.138.90` (the droplet)**, not the host's `97.118.44.235`. Proves the full gambit
  path live: spark netstack → AnytlsTransport (gambit-shaped boring **Chrome ClientHello**,
  SNI-boundary TCP fragmentation) → anytls-go server → Cloudflare, egressing as the droplet. Infra was
  ephemeral (droplet + DO ssh-key + local key all destroyed post-gate). `protect_interface = en0`
  kept the upstream dial off the tun. This is the gambit-era successor to the M11 AnyTLS live gate.
- **ANCHOR drift CI — scheduled live-Chrome oracle (ADR 0006 §4) 2026-06-19 (committed `f185529`,
  pushed; both jobs VERIFIED GREEN in CI).** The `chrome-oracle` job captured real current Chrome's
  JA4 = **`t13d1516h2_8daaf6152771_d8a2da3f94cd`** — the *entire* JA4 (incl. JA4_c) equals our
  `ANCHOR_JA4`, i.e. **full JA4 parity with live Chrome**, not just the cipher prefix. New
  `.github/workflows/anchor-drift.yml` (weekly cron + `workflow_dispatch` + push on the profile/JA4
  files). Two jobs: **`profile-drift`** (deterministic, reliable) re-runs the `ANCHOR_JA4` +
  `ja4` tests under `--features anytls` — does *our* boring ClientHello still emit the pinned anchor;
  **`chrome-oracle`** (best-effort) sets up stable Chrome (`browser-actions/setup-chrome`), captures
  real Chrome's JA4 from the `tls.peet.ws` fingerprint echo (grepped by JA4 shape, schema-independent,
  5× retry), and compares the **JA4_a+JA4_b prefix** (`EXPECTED_CHROME_PREFIX=t13d1516h2_8daaf6152771`
  — the cipher-stable part our anchor matches) — a mismatch means real Chrome moved past chrome-137 →
  refresh the profile + `ANCHOR_JA4`. Note: the per-push main CI already runs the deterministic guard
  via `--all-features`; this adds the cadence + the live-Chrome half. Injection-safe (only the trusted
  setup-chrome output crosses into a `run:`, via `env:` + quoting); YAML validated; the test selector
  confirmed to hit the 4 anchor/ja4 tests. **Remaining:** an even-truer oracle would use the Cronet
  capture path (ADR 0006 Decision 4) instead of the external echo service.
- **P5 (chunk 1) — discovery harness inner loop (ADR 0006, design §5.2) 2026-06-19 (committed
  `eb95dbd`, pushed).**
  The full search loop is **server-side** (§5.5 — servers are sensors, fitness = arrival rate, client
  stays thin); spark owns the **inner tier** because it has the boring engine. New
  `core/src/transport/discovery.rs`: (pure, always-on) a seeded `SplitMix64` PRNG + GA **`mutate`**
  (perturb one Layer-A/B/C knob) and **`crossover`** (recombine A=clienthello / B=records / C=wire —
  layers are the natural crossover units, §5.1), both deterministic for reproducible/auditable search;
  (feature `anytls`) `run_inner_loop` — generate a population, **realize each candidate through boring**
  (`Profile::for_boring` → `capture_client_hello` → `ja4`), score **fidelity to the anchor** (JA4 match
  + structural distance = GREASE-stripped cipher/ext symmetric-diff + ALPN/version), and select the
  fittest **distinct-JA4** survivors per generation (novelty pressure, so the population doesn't
  collapse onto one fingerprint). The reference is always `Profile::default` (genuine Chrome-137), not
  the seed. This is the cheap, **no-censor-contact** pre-filter that guards the composite fitness's
  `fidelity_floor` — it does **not** judge evasion (that's the server arrivals oracle); its output is a
  fidelity-ranked, diverse candidate set for the outer loop to field-trial. **Honest limitation
  (documented):** for *constrained* gambits the JA4 signal is coarse (boring keeps them Chrome-faithful
  by construction; only ECH/ALPS/record_size_limit move the JA4) — the scorer earns its keep on the
  *unconstrained* (P4) regime. **Verified:** 7 tests (PRNG determinism; mutate reproducible+changes;
  crossover layer-sourcing; population sizing; + `anytls`: seed→anchor distance 0/match, ALPS-off
  lowers fidelity, loop ranks-faithful-first + stays diverse); all-features 192, clippy `-D warnings`
  clean default + all-features, fmt + workspace green. **Remaining P5 (server-side, separate repo):**
  the outer loop — arrivals oracle, A/B bandit over gambits, server rotation, LLM warm-start/
  reasoning-mutation, signed deploy (lantern-cloud / Go; spark exposes the genome + `for_boring` +
  `capture`/JA4 + signed gambit modules as the seam).
- **ANCHOR / JA4 drift control (ADR 0006 §4, deferred P0) 2026-06-19 (committed `3311ab7` + `5415433`,
  pushed).** Two commits. (1) `core/src/transport/ja4.rs` (always-on): a pure ClientHello parser + the **FoxIO JA4**
  fingerprint (`JA4_a` version/SNI/cipher-count/ext-count/ALPN + `JA4_b` sorted-cipher hash + `JA4_c`
  sorted-extension+sigalg hash; GREASE-stripped, extension-sorted ⇒ invariant to our per-connection
  GREASE+permutation but flips on a real profile change). The spec verified against the pinned FoxIO
  source; **validated against the spec's own worked example** `t13d1516h2_8daaf6152771_e5627efa2ab1`
  reproduced byte-for-byte (committed `3311ab7`). (2) `anytls/anchor.rs` (feature `anytls`):
  `capture_client_hello(profile, sni)` runs the boring handshake against an in-memory EOF peer to
  record the exact ClientHello (no network), + a drift test pinning `ANCHOR_JA4` =
  **`t13d1516h2_8daaf6152771_d8a2da3f94cd`** — the `t13d1516h2_8daaf6152771` prefix (15 ciphers, 16
  exts, h2, canonical Chrome **cipher hash**) matches the well-known Chrome JA4, evidence the profile
  fingerprints as Chrome. Plus a `capture-clienthello` example tool (`cargo run -p spark-core
  --example capture_clienthello --features anytls -- [sni]`) printing the CH hex + JA4 + drift status.
  **Verified:** JA4 = SNI-invariant in practice (same JA4 for `example.com` vs `cloudflare.com`); 4
  new tests; all-features 185, clippy `-D warnings` clean default + all-features, fmt + workspace
  green. **Remaining (deferred):** wire the drift test into a scheduled CI job that re-captures from a
  live Chrome/Cronet oracle and proposes a refreshed anchor (ADR 0006 §4) — needs a Chrome capture
  source. **Next: P5** (discovery harness).
- **P4 (chunk 1) — handshake-crypto host-fn menu (ADR 0006) 2026-06-19 (committed `b3cbfc7` +
  `2bae867`, pushed).** The
  *unconstrained* regime needs a Path-B module to drive a TLS 1.3 handshake itself; this adds the
  crypto primitives beside the existing `host_rand`/`host_hash`/ChaCha20-Poly1305 menu (verified
  against the pinned ring 0.17.14 source; same fault-recording + bounds-checking discipline):
  `host_hkdf_extract` (HKDF-Extract == HMAC-SHA256, returns the raw 32-byte PRK so the module can run
  the TLS key schedule), `host_hkdf_expand` (HKDF-Expand-SHA256, module supplies its own
  `HKDF-Expand-Label` info, bounded 255×32), `host_aes_gcm_seal`/`open` (key_len 16 ⇒ AES-128-GCM,
  32 ⇒ AES-256-GCM; mirrors the ChaCha20-Poly1305 pattern), and X25519 ECDH via a **host-held
  ephemeral-key registry** — `host_x25519_generate(out_pub) -> key_id` (private key stays host-side,
  never enters guest memory — a sandbox win) + `host_x25519_agree(key_id, peer_pub, out)` (consumes
  the key; one ECDH per handshake; ≤`MAX_X25519_KEYS` live, freed slots reused). Two commits:
  `b3cbfc7` (HKDF + AES-GCM, stateless) + the X25519 commit (adds `HostState::x25519_keys`).
  **Verified:** 5 new wat-fixture tests (HKDF vs native ring; AES-GCM round-trip + bad-key-len fault;
  X25519 agrees with a native peer [module is one party, test the other, shared secrets match] +
  unknown-key-id fault); all-features 181, clippy `-D warnings` clean default + all-features, fmt +
  workspace green. **Next P4 increment (large, own design):** the *module-owns-the-handshake* ABI —
  a handshake-driving loop (host does socket I/O; module produces/consumes raw bytes and runs the
  TLS-1.3 state machine via these primitives) so a module can emit a raw/malformed ClientHello boring
  can't continue. Build only if constrained variation (P2/P3) can't beat a given censor (ADR 0006
  "build only if needed"). Crypto menu is the prerequisite, now in place.
- **P3 (chunk 3) — config-driven signed gambit module + per-connection `ctx` (ADR 0006) 2026-06-19
  (committed `740eaec`). P3 is now end-to-end from config.** `[transport.anytls.gambit]` (new
  `GambitModuleConfig` {module, min_version, floor_path}) names a **signed Path-B module**;
  `anytls_transport` loads + verifies it via `load_gambit_module` — the **same pinned key + config &
  persisted anti-rollback floors as `wasm_transport`** (the module is the trust root for the gambits
  it computes) — then attaches it through `AnytlsTransport::with_dynamic_gambit`. The inline
  `clienthello`/`records` knobs become the **fallback** profile. Per-connection context is now real:
  `GambitContext` (in `gambit.rs`) — a fixed-offset LE header `[version:u8 @0][unix_secs:u64 @8]`
  (`GAMBIT_CONTEXT_LEN`=16) — carries the host wall-clock (the one fact a sandboxed module can't
  self-source; host-supplied ⇒ pinnable for tests/eval); `resolve_profile` builds it per session.
  **Decision recorded:** ctx carries *only* what the sandbox can't self-source — entropy is
  `host_rand`, rotation is module-internal state, static facts (server/SNI) go via `init`,
  connection-outcome feedback is a deliberately-separate future export. Feature gating: the dynamic
  branch + `load_gambit_module` are `#[cfg(all(anytls, wasm-transport))]`; an `anytls`-only build
  hard-errors if `[transport.anytls.gambit]` is set (mirroring the no-feature AnyTLS error). **Verified
  across all four feature combos** (default / anytls / wasm-transport / all): 4 new tests
  (`GambitContext` v1 layout; config parse of `[transport.anytls.gambit]`; `from_config` attaches a
  dev-key-signed gambit module under `#[tokio::test]`; rollback rejected), all-features 176, clippy
  `-D warnings` clean for default + all-features, `cargo check` green for every combo, fmt + workspace
  green. **P3 complete.** Next: **P4** (unconstrained byte-builder + crypto host fns — the module
  emits raw CH bytes and drives the handshake via X25519/HKDF/AES-GCM host fns), or the **P5**
  discovery harness. **Adaptive feedback is server-side (decision 2026-06-19):** there is no
  client→server outcome-reporting export — we can't universally rely on a client being able to report
  (the reporting channel can itself be blocked/observed; many clients can't report at all). The
  authoritative fitness signal is the server-side **arrivals oracle** (design doc §5.2). A stateful P3
  module may still adapt to outcomes the host observes **locally** (did this handshake complete? did
  the connection survive?), fed in with no network round-trip — that steers only the module's own next
  move and is optional (a module that can't observe still works). See design doc §5.2 "Per-connection
  module adaptation is local-only, never a report."
- **P3 (chunk 2) — per-connection computed gambit wired into AnyTLS (ADR 0006) 2026-06-19 (committed
  `40fe3f1`).** `AnytlsTransport` gains an optional dynamic gambit source: `with_dynamic_gambit(...,
  gambit: wasm::Transform)` stores the Path-B module behind a `Mutex` (the `wasmi` `Transform` is
  `!Sync` and stateful — a gambit may adapt across connections; the lock is held only for the
  synchronous compute, never across the handshake `.await`). `Inner::resolve_profile()` — called by
  `acquire()` per new TLS session — computes a fresh gambit, runs `Profile::for_boring`, and **falls
  back to the static `profile`** on any fault / undecodable genome / capability decline, so a dynamic
  gambit can never break connectivity (boring always completes the handshake; a declined gambit
  degrades to the portable default). Feature-combo isolated cleanly: the field + `with_dynamic_gambit`
  + the dynamic `resolve_profile` are `#[cfg(feature = "wasm-transport")]` inside the already
  `anytls`-gated file; an `anytls`-only build keeps a static-profile `resolve_profile`. **Verified:**
  2 new `#[cfg(all(test, feature = "wasm-transport"))]` `#[tokio::test]`s (per-connection compute
  drives ech=off/pq=off; a `raw_clienthello` gambit is declined → static fallback, ech-grease stays
  on); all-features 172 tests, anytls-only 106, clippy clean for `anytls` + `--all-features`, fmt +
  workspace check green. **Still pending for P3:** the config-driven *source* — a signed Path-B
  gambit module loaded + verified (pinned key + persisted floor, mirroring `wasm_transport`) and
  attached via `with_dynamic_gambit` in `anytls_transport`; plus the per-connection `ctx` payload
  design (target/seq/region, ADR 0006 §6). Then P4 (unconstrained byte-builder + crypto host fns).
- **P3 (chunk 1) — Path B computes the gambit: the `open`/shape ABI (ADR 0006) 2026-06-19 (committed
  `2d4abfe`).** The `wasmi` Path B module (`core/src/transport/wasm/`) gains a third **mode** beside the
  byte-transform pair: a `compute_gambit(ctx_ptr, ctx_len) -> packed` export, invoked once per
  connection, that emits a **postcard-encoded `Gambit` genome** (the opening *plan* — CH knobs +
  record/segment framing) rather than stream bytes. `Transform::compute_gambit(&[u8]) -> Result<Gambit,
  WasmError>` calls it via the shared `call_io` sequence (refactored out of `run`) and postcard-decodes
  the result (new `WasmError::GambitDecode`). ABI change: `transform_out`/`transform_in` are now
  **optional** (a module exports the transform pair, `compute_gambit`, or both; `memory`+`alloc` stay
  mandatory; a module with no mode is rejected) — so a *constrained* P3 module that only computes a
  gambit (boring does the bytes) instantiates without dummy transforms. **Trust model:** the genome is
  **not** separately signed — the module's own signature (`ModuleVerifier`/`SignedModule`) is the
  trust root; the consumer still gates the computed gambit through `Profile::for_boring` so boring only
  runs gambits it can realize (constrained regime; ADR 0006 §"Path B narrows"). **Verified:** 4 new
  wasm tests (computes a known genome via a data-segment `wat` fixture; `compute_gambit` absent on the
  transform-only XOR module → MissingExport; undecodable bytes → GambitDecode; **end-to-end
  module→Gambit→`Profile::for_boring` under `--all-features`**); core `--all-features` 170, clippy
  clean for default / `wasm-transport` / `--all-features`, fmt + `cargo check --workspace --all-features`
  green. **Next P3 increment:** wire `compute_gambit` into the AnyTLS dial path — a per-connection
  gambit source on `AnytlsTransport` (compute → `for_boring` → `Profile` per `acquire()`), needing both
  the `anytls` and `wasm-transport` features; plus deciding the per-connection `ctx` payload (target/
  seq/region). Then P4 (unconstrained byte-builder + crypto host fns).
- **P2 — gambit knobs drive the boring connector (ADR 0006) 2026-06-19 (committed `c4cdc6a`).** The
  AnyTLS TLS connector is no longer a hardcoded Chrome-137 profile — it applies a gambit's Layer-A
  (ClientHello) + Layer-B (records) knobs. New `core/src/transport/anytls/profile.rs` (feature
  `anytls`): `Profile::resolve(&ClientHello, &Records) -> Resolved {profile, unrealizable}` maps the
  genome onto boring, and `Profile::for_boring(&Gambit)` gates a *signed* gambit's `requires` against
  `BORING_CAPABILITIES = [Ech, Alps, PqKem]` (declines `session_id_inject`/`raw_clienthello` — uTLS-now
  / spark-P4). `tls::connect` now takes `&Profile`; it parameterizes GREASE, extension permutation,
  the PQ supported-group (`CHROME_CURVES_NO_PQ` when `pq_kem` off), `record_size_limit`, ECH grease,
  and ALPS — the cipher/sigalg lists + cert-compression + ALPN + OCSP/SCT stay the fixed anchor.
  **`Profile::default()` is the byte-exact Chrome-137 baseline, so the live gate is unchanged.**
  Verified API surface against the boring2 4.15 source first (per the repo's verification discipline):
  **expressible** = GREASE on/off, permute on/off (no seed), groups list, `set_record_size_limit`,
  ECH grease, ALPS; **not expressible** = explicit order-by-id, exact GREASE/permute seed,
  ClientHello padding-to-length, `legacy_session_id` inject, record split_offsets — these are
  **surfaced (logged `warn` once at construction), never silently dropped**, awaiting the P4
  byte-builder. Made live via inline `[transport.anytls.clienthello]` / `[transport.anytls.records]`
  TOML (reuses the already-`Deserialize` genome types — an operator-set *local* profile; signed
  remote delivery is the next chunk). **Verified:** 5 profile unit tests (baseline; expressible knobs;
  unrealizable-knobs-surfaced; for_boring accept/decline) + 1 config parse test; core `--all-features`
  166 tests, default 101, clippy `--all-features -D warnings` + fmt + `cargo check --workspace
  --all-features` green. **Next P2 increment:** signed-gambit *delivery* — a verified file source
  (pinned Ed25519 key + persisted anti-rollback floor, mirroring `wasm_transport`) feeding
  `Profile::for_boring`, plus real ECH (ECHConfig) wiring; then P3 (Path B computes the gambit).
- **P2 STARTED — gambit genome decode + signed envelope (ADR 0006) 2026-06-19 (committed `d561ccd`).**
  New `core/src/transport/gambit.rs` (always-on): the **locked v1 genome as Rust** (design doc §2) —
  `Gambit` {genome_version, version (monotonic), id, anchor, clienthello (Layer A), records (Layer B),
  wire (Layer C), requires}, the `Capability` closed vocabulary (`ech`/`alps`/`pq_kem`/
  `session_id_inject`/`raw_clienthello`), and supporting enums (`Perm` permute-seed|explicit,
  `EchMode`, `SessionId`). Delivery is the `SignedGambit` {gambit, key_id, sig} envelope:
  `verify(&PinnedKeys, floor)` checks the **Ed25519** signature (ring `UnparsedPublicKey`/`ED25519`)
  over the **canonical postcard encoding** *before* the anti-rollback floor check, then returns the
  gambit; capability gating is the executor's separate call (`Gambit::check_supported`). `Wire::
  to_wire_plan()` bridges Layer C to the Phase 1 `WirePlan` (same string grammar as `ShapingConfig`).
  Design note: postcard is non-self-describing, so `skip_serializing_if` is deliberately omitted —
  it would drop bytes the positional deserializer still expects; `Option` already encodes as a 1-byte
  discriminant, keeping the signing pre-image deterministic. The Layer-A ClientHello knobs are
  **modeled + round-tripped, not yet applied** to the boring connector (next P2 increment). **Verified:**
  5 unit tests (postcard round-trip; sign/verify above floor; reject tamper/unknown-key/rollback;
  capability gating; wire→WirePlan), core `--all-features` 160 tests, clippy `--all-features
  -D warnings` + fmt clean, `cargo check --workspace --all-features` green. **Next P2 increment:**
  refactor `anytls/tls.rs` to take parameterized ClientHello knobs (from a `Gambit`) instead of the
  hardcoded Chrome-137 profile, so a signed gambit actually drives the handshake (Layers A+B), not
  just Layer C. Cross-fleet (Go/uTLS) postcard canonicalization remains the noted open question.
- **PHASE 1 WIRED INTO ANYTLS (ADR 0006) 2026-06-19 (committed `a42d50b`).** The shaper now drives the
  real AnyTLS handshake. `[transport.shaping]` config (`ShapingConfig` {segment_split, delay_ms,
  tcp_nodelay}, default = no-op) → `WirePlan::from_config` → `AnytlsTransport` carries the `WirePlan`
  and, per new TLS session in `acquire()`, sets `TCP_NODELAY` + wraps the socket in
  `SegmentShapingStream` before the boring handshake — so the Chrome ClientHello is fragmented (e.g.
  at the SNI boundary) as it leaves. `tls::connect` is now generic over the carrier (`SslStream<S>`;
  `Session::client<S>` was already generic), error formatting switched Debug→Display to drop the
  `S: Debug` bound. **Verified:** `cargo test --workspace` (19 groups) + core `--all-features` (155)
  green incl. the config round-trip with a non-default shaping block; clippy `--all-features
  -D warnings` + fmt clean. **Remaining Phase 1 (follow-on):** `capture-clienthello` anchor tool +
  JA4-drift test, and the tcpdump live gate (sudo + a TLS endpoint — re-provision DO when gating).
- **PHASE 1 BUILT — socket-layer handshake shaper (ADR 0006) 2026-06-19 (committed `2be763e`).** New
  `core/src/transport/shaping/` (always-on, no feature gate): `SegmentShapingStream<S>` — an
  `AsyncRead+AsyncWrite` wrapper that shapes only the **opening write** (the ClientHello) by splitting
  it into separate flushed TCP segments — **at the SNI boundary** (mid-hostname, defeating
  SNI-keyword DPI) or explicit offsets — with an optional fixed/jitter inter-segment delay, then is a
  zero-overhead passthrough. `shaping/sni.rs` = a total, bounds-checked SNI-host locator (walks only
  to `server_name`; any truncation/non-match → `None`, never breaks a connection). `WirePlan`
  {segment_split, inter_segment_delay, tcp_nodelay} = **genome Layer C** as a native struct — the
  seam P2 (signed gambit) and P3 (Path-B module) will both populate. **Verified:** 6 unit tests
  (SNI locator on a built ClientHello fixture + truncation rejection; shaper splits at explicit
  offsets, splits mid-SNI, passthrough after the opening write, no-op plan = single write); full
  `cargo test --workspace --all-features` green; core clippy `-D warnings` + fmt clean. **Remaining
  Phase 1:** wire the shaper into the AnyTLS dial path (`[transport.shaping]` config), the
  `capture-clienthello` anchor tool + JA4-drift test, and the tcpdump live gate (needs a TLS endpoint
  + sudo — DO box is torn down, re-provision when gating). Then P2 (constrained CH knobs + the
  genome decode on the locked v1 schema).
- **System stack ENABLED for Android 2026-06-17. ✅** Android's `VpnService` hands a Linux tun fd,
  so the kernel-TCP stack works there (the correction above). Wiring: (1) `fd_tunnel` split into
  `run_tunnel(fd,mtu)` (default, unchanged — keeps the Apple NE path) + `run_tunnel_with_config(fd,
  mtu, Config)`; (2) the JNI `nativeRun` extended to `(fd, mtu, addr, prefix, systemStack)` — `addr`
  is the tun IPv4 packed big-endian into a `jint` (primitive-only bridge, no `jni` crate), and it
  builds a `Config` selecting `StackKind::System` when `systemStack != 0`; (3) `system-stack`
  feature **target-gated** to android in `platforms/android/Cargo.toml` (`cargo tree` confirms
  non-android builds stay free of it). **Validated:** `cargo ndk -t arm64-v8a check/clippy -p
  spark-android` clean (full aarch64 build incl. ring's C cross-compile + the system module + the
  JNI mod); macOS workspace unregressed (84 default / 107 system-stack core tests). **Caller
  contract (Android app, separate repo):** Kotlin must update `external fun nativeRun(fd, mtu, addr,
  prefix, systemStack)`; pass the same addr it gave `VpnService.Builder.addAddress(addr, prefix)`,
  with `prefix` covering addr+1 (the synthetic gateway), and `addDisallowedApplication(self)` so
  upstream dials bypass the tun (loop avoidance — no per-socket protect). **Remaining: on-device
  gate — SCOPED in `docs/android-system-stack-gate.md`** (runbook + pass criteria + reference Kotlin
  `SparkBridge`/`VpnService` + risk register). Needs a device + the host app; not yet executed. Key
  risks to watch: local delivery of the redirect + per-UID/fwmark routing (both de-risked by
  sing-box doing the same on Android); `rp_filter` should pass strict naturally but an unrooted app
  can't `sysctl` it if not.
- **M11 AnyTLS UDP-over-AnyTLS (sing UoT v2) DONE 2026-06-16. ✅** `anytls/udp.rs`: `associate(stream,
  target)` opens a stream, writes the UoT magic SOCKS5 addr (`sp.v2.udp-over-tcp.arpa:0`) + the UoT
  request `IsConnect=1 | Destination(SOCKS5)`, then frames datagrams connected-mode `[u16 BE len]
  [payload]` (verified against `sing/common/uot` protocol.go+conn.go — interops with anytls-go's
  `proxyOutboundUoT`). `AnytlsTransport` now impls `UdpTransport` too; `from_config` serves TCP+UDP
  from ONE pooled transport. **e2e verified:** a DNS query (A example.com) through the UoT path →
  local anytls-go server → 8.8.8.8:53 → valid response (id match, QR set, 2 answers). clippy clean.
- **M11 AnyTLS protocol-robustness loose ends DONE 2026-06-16. ✅** (1) **dynamic
  `cmdUpdatePaddingScheme`** — the writer's scheme is now `Arc<Mutex<PaddingScheme>>` shared with the
  reader; on a server update the reader parses + swaps it (malformed → ignored), so the client honors
  the server's anti-blocklist scheme rotation. (2) **`cmdSYNACK` error close** — a non-empty SYNACK
  (the server's upstream-dial error) now removes the stream → its reader unblocks (was: hung). (3)
  **`cmdFIN` on `Stream` drop** (when not already shut down) — closes UDP associations promptly
  (split halves never call poll_shutdown) and hardens TCP. Unit tests for the scheme swap +
  SYNACK-error close; 83 core tests pass; clippy clean.
- **M11 AnyTLS outbound backpressure DONE 2026-06-16. ✅** The session's shared outbound frame
  channel is now **bounded** (`OUTBOUND_CAP = 64`, was unbounded). `Stream::poll_write` drives it
  through `tokio_util::sync::PollSender` (`poll_reserve` → `send_item`), so a slow transport makes
  writes return `Pending` (backpressure) instead of buffering without limit; control frames
  (SYN/EndBuffering/Settings) use the plain bounded sender (`.await`/`try_send` on a fresh channel),
  and `cmdFIN` from `poll_shutdown`/`Drop` is best-effort `try_send` (no waker in `Drop`).
  `tokio-util` promoted to a direct `core` dep (already in the tree transitively — no version churn).
  New unit test asserts `poll_write` backpressures once the channel fills (accepts ~`OUTBOUND_CAP`
  then `Pending`); 84 core tests pass, clippy + rustdoc clean both feature configs. **STILL
  OUTSTANDING (non-blocking):** per-stream flow control (one shared channel = HOL across streams
  under backpressure); wiring the JA4-drift spike into CI; M10 iOS device gate.
- **M2 live curl gate PASSED on macOS 2026-06-15** (with `--protect-interface`): curl → tun →
  netstack → forwarder → socket-protected dial → upstream → back. Direct TCP data path verified
  end-to-end.
- **M7 through-the-service gate PASSED on macOS 2026-06-15.** `spark-service` (root, with
  `--spark-gid` + `--protect-interface`) + `spark connect`/`status` + curl: the unprivileged
  client drove the privileged daemon to bring the tunnel up and real traffic forwarded through
  it. The full ship-shaped desktop architecture is live.
- **M5 UDP gate PASSED on macOS 2026-06-15:** `dig @9.9.9.9 example.com` (routed into the tun,
  `spark run --protect-interface`) resolved through the tunnel — TUN → netstack UDP → `run_udp`
  NAT association → protected UDP dial → reply pump → back. UDP path live.
- **Live-verified: M1 (ICMP), M2 (direct TCP), M5 (UDP), M7 (service TCP).** The desktop data
  path is confirmed live across TCP+UDP, direct + through-service. Not yet live: M4 (tunnel-server
  path, needs a relay binary), M6 (SIGINT teardown), and the M7 kill-switch refinements above.
- **M7 s3 live smoke (no root, real processes over a real unix socket):** `spark-service`
  daemon + `spark` client verified end-to-end — peer-cred auth refuses a non-root uid under a
  root-only policy AND allows it under `--spark-gid 20`; `Hello` handshake + `GetStatus`
  (Disconnected) round-trip; `connect` → `CoreEngine::start` opens the TUN, fails cleanly
  without root, and the structured `Error` propagates back through the IPC; status then shows
  `Failed`. Only the actual privileged TUN+routing+curl is unverified.
- Last gate passed: **M0**..**M6** as before; **M7 s1** (ipc protocol crate) + **M7 s2** (service
  no-root core) green 2026-06-14. s2: `spark-ipc` gained `ServerMessage` (response/push demux
  envelope) + a feature-gated async `stream` layer (`read_frame`/`write_frame`); `spark-service`
  got `auth` (PeerCreds + AuthPolicy root+`spark`-group, pure/testable), `engine::TunnelEngine`
  trait, `run_service` actor loop (channels-over-locks, `Hello`-gated, broadcasts state changes),
  and `serve_connection` (cancel-safe: a dedicated reader task feeds a `select!` that interleaves
  responses and pushes). Hermetic duplex tests cover handshake/connect/status, pre-handshake
  rejection, version-mismatch rejection, and subscribe→push delivery.
- Tree status: **green** — `cargo clippy --workspace --all-targets --all-features -D warnings`
  / `fmt --check` clean; `cargo test --workspace --all-features` all pass (core **43** + 3 integ +
  doctest; **spark-ipc 10** incl. stream; **spark-service 17**); release `spark` **1,257,040 bytes
  (~1.20 MB, 41%)** / `spark-service` **1,274,400 bytes (~1.21 MB, 42%)** of the 3 MB budget.
  (`spark` unchanged — routing is dead-code-eliminated there; `spark-service` +17 KB for routing +
  `tokio::process`.) NB: the ipc `stream` tests need the feature → use `--all-features` (or
  `-p spark-ipc --features stream`).

**2026-07-11 — Rust Unbounded/Spark connection-sharing integration, lifecycle slice DONE.**
Added an unprivileged `spark-sharing` crate, with no dependency edge into `spark-core`,
`spark-service`, the CLI, backend, or platform bindings. It pins `getlantern/unbounded-rs` commit
`5cbfd9c13b56720329de53a14def8e610bd89360` with `default-features = false`, so Unbounded's native
`reqwest`/`env_logger` client is absent. `SharingConfig` maps Spark-owned settings into the real
five-slot-capable peer-proxy supervisor; `start_sharing` returns an explicit cancel/wait/stop handle
and accepts lifecycle events plus an injected `Signaler`. The test runs the real supervisor through
an injected signaling attempt and proves orderly cancellation and aggregate counters. Dependency
audit: `spark-sharing` production edges contain no `reqwest`, `hyper`, or `env_logger`; existing
Spark product crates contain no Unbounded/sharing edge. Gate:
`cargo test --manifest-path spark-sharing/Cargo.toml --locked`,
package clippy `-D warnings`, formatting, and full `cargo check --workspace --locked` all green.

**2026-07-11 — Connection sharing, Spark-native Freddie signaling DONE.** Added
`FreddieSignaler`, a concrete injected signaler using raw Tokio TCP + rustls 0.23/ring (Mozilla roots),
with no reqwest/hyper. Default constructors require HTTPS; plaintext HTTP requires the explicitly
named `new_insecure_http` local-testing constructor. It sends Freddie's existing POST form and `X-BF-Version`, maps 404/418/other
statuses into Unbounded's typed errors, decodes the Go signaling envelope, supports fixed-length,
close-delimited, and chunked HTTP/1.1 responses, and enforces 32 KiB headers plus configurable body
and chunk-wire limits. Tests cover exact form/header/envelope behavior, statuses, size rejection,
chunking, dropped-future cancellation, endpoint parsing, and a hermetic certificate-verified rustls
exchange. Async lifecycle tests use explicit five-second bounds on every network/supervisor wait;
the cancellation test verifies future/task cancellation without depending on platform-specific
remote TCP EOF timing. The Unbounded pin advanced to the merged peer-proxy commit
`5cbfd9c13b56720329de53a14def8e610bd89360`, which makes its generic `Transport(String)` error
available without reqwest; both default and no-default Unbounded
test/clippy gates pass. Also corrected `scripts/size-budget.sh` to build only the two binaries it
measures, matching `release.yml`; a whole-workspace release build had feature-unified the optional
WebRTC graph into `spark-service`. Sharing: 16 unit tests + doctest, clippy `-D warnings`, standalone
check, release build, and dependency isolation all green. `spark-sharing` is now a standalone
workspace excluded from the size-sensitive root workspace, with its own lockfile and three-OS CI job.
This is required because Cargo unifies features across workspace members even when the size script
selects only the two product binaries. With the standalone boundary, the root `Cargo.lock` is
byte-identical to `origin/main` and
the corrected size gate reports spark 2,343,824 B (55%) and spark-service 3,006,080 B (71%). Verified
API facts: rustls 0.23.41
`builder_with_provider(ring).with_safe_default_protocol_versions()`; tokio-rustls 0.26.4
`TlsConnector::connect(ServerName<'static>, IO)`; `RootCertStore` accepts cloned webpki trust anchors.

## Next chunk (exactly what the next session should do)

**(C) Connection sharing — one unprivileged frontend integration.** Wire `FreddieSignaler` plus the
sharing handle into a single unprivileged frontend behind an explicit compile-time feature and
runtime opt-in config. The frontend must own start/stop, surface slot lifecycle status without logging
consumer identifiers or ICE addresses, and stop the pool during application shutdown. Keep
`spark-core` and `spark-service` untouched. Choose the currently shipping frontend only after
confirming its runtime/process ownership from the code; do not wire every binding in one chunk.

Two independent tracks — pick by whether a privileged box is available:

**(A) Privileged live gates (root) — the box is privileged now.** Build (`cargo build --release`),
then run with `sudo`. **macOS curl recipe (loop-free via socket protection):**
```
EGRESS=$(route -n get default | awk '/interface:/{print $2}')   # e.g. en0
sudo ./target/release/spark run --addr 10.0.0.1 --prefix 24 --protect-interface "$EGRESS"
# note device=utunN in the log; in another terminal:
sudo route -n add -host 1.1.1.1 -interface utunN     # send just this dest into the tun
curl -v --max-time 10 https://1.1.1.1                # spark dials 1.1.1.1 pinned to $EGRESS → no loop
sudo route -n delete -host 1.1.1.1                   # cleanup
```
1. **M1 PASSED** (ping). **M2 curl PASSED on macOS 2026-06-15** via the recipe above (socket
   protection breaks the loop). The direct TCP data path is live-verified end-to-end.
2. **M7 through-the-service gate (now runnable).** NB: the daemon creates the TUN on `connect`,
   NOT at startup — so `connect` comes first, and the device name appears in the daemon log
   (`tunnel up device=utunN`) only then.
   ```
   sudo ./target/release/spark-service --socket /tmp/spark.sock --spark-gid $(id -g) --protect-interface "$EGRESS"
   ./target/release/spark connect --socket /tmp/spark.sock   # → ok; daemon logs "tunnel up device=utunN"
   sudo route -n add -host 1.1.1.1 -interface <utunN>        # use the device from that log line
   ./target/release/spark status  --socket /tmp/spark.sock   # → Connected
   curl -v --max-time 10 https://1.1.1.1                     # flows through the daemon
   # kill the client → tunnel stays; kill the daemon → routing reverts
   ```
   (Daemon TUN defaults to 10.0.0.1/24; pass `--config` for other settings.)
3. **M5 UDP gate:** route a resolver into the tun, e.g.
   `sudo route -n add -host 9.9.9.9 -interface <utunN>`, then
   `dig @9.9.9.9 example.com` (or `nslookup example.com 9.9.9.9`) while `spark run
   --protect-interface "$EGRESS"` is up — expect an answer + a UDP association in the log.
   Linux alternative for TCP: `curl --interface tun0` (no route/protect needed).
2. **M7 data-path-through-service gate:** `sudo ./target/release/spark-service --socket
   /var/run/spark.sock --spark-gid <gid>` (or run client as root); then `spark connect` →
   tunnel comes up; `spark status` → Connected; curl gate passes; kill the **client** → tunnel
   stays; kill the **service** → routing restored (+ `FellOpenToDirect`); unauthorized uid
   refused (already shown); version mismatch rejected.
3. **M5 UDP gate** (DNS/echo) and **M6 SIGINT/device-teardown** once the device is up.
Then fold in the s2 refinements: real `SO_PEERCRED` supplementary-group resolution, route
install/restore (fail-open kill-switch + the `FellOpenToDirect` emit), drop-oldest +
`Push::Dropped` backpressure, socket perms (chown root:spark 0660).

**(B) Other root-gated live verification, do when a privileged window opens:**
- **M6 SIGINT/device-teardown gate** — bring the device up, send SIGINT, confirm the TUN
  interface is removed cleanly (Drop-driven). Also confirm default-level logs show no IPs
  during a real session (the redaction backstop + level convention).
- **M5 live UDP gate** — with the device up, a DNS query (UDP/53) and a UDP echo both
  round-trip through the tunnel; idle associations are reclaimed after 60s
  (`DEFAULT_IDLE_TIMEOUT`). DNS strategy = proxy-through-tunnel (no :53 special-casing).
  Run `spark` (direct) or `spark --server <addr>` (tunneled, needs a server that speaks the
  UDP-associate protocol: magic sentinel `udp-associate.spark.invalid` + target header, then
  `[u16 len][payload]` datagrams).
- **M4 live gate** — stand up a tunnel server, run `spark --server <addr>` with a route into
  the TUN, `curl --interface tun0 https://1.1.1.1`; verify server-side it saw the connection.
  macOS works here (the dial targets the server, so no M2 loop hazard).
- **M2 live curl gate** — `spark` (no `--server`), README "M2 plain-TCP-forwarder gate"
  (Linux: bring up `tun0`, loosen `rp_filter`, `curl -v --interface tun0 https://1.1.1.1`).
  Loop hazard: do NOT route the target into the tun; `--interface` binds only the client.
- **M1 live ping gate** — see Blockers.
- Record routing cmds + poll/latency in the Decisions log and tick M1/M2/M4 as they pass.

## Blockers / waiting on human
- **M1 live ICMP gate — PASSED on macOS 2026-06-15.** `sudo spark run --addr 10.0.0.1
  --prefix 24` brought up the `utunN` (ifconfig showed `inet 10.0.0.1`, UP), and
  `ping 10.0.0.2` got replies with `rx proto=icmp` in the log. The TUN + netstack data path
  is confirmed alive on a real OS. (Agent still has no passwordless sudo; the human ran it.)
- **macOS TCP loop — SOLVED via socket protection 2026-06-15.** `core/src/net.rs`
  `SocketProtector` pins upstream dials to a physical interface (`IP_BOUND_IF`/`IP_UNICAST_IF`
  via `socket2::bind_device_by_index_v4/v6`, index from `libc::if_nametoindex`), so spark's
  own dial bypasses the global route-into-the-tun → no loop. Wired through `transport::from_config`
  + the `--protect-interface <if>` flag / `[transport] protect_interface` config. **IP_BOUND_IF
  verified working on this box** (the `protect_binds_a_socket_without_error` test passes, no root).
  The live curl gate is now runnable here — see "Next chunk (A)". (Linux also works via the same
  binding; the Apple NE path gets protection from the OS instead.)
- Upcoming (not blocking yet): if a transport TLS-wraps its relay, confirm the `rustls` client
  config (verification + roots) before trusting it.

## Verified API facts (RE-CONFIRMED at M0 on rustc 1.93.1 against vendored 0.2.2 source — trust)
- netstack-smoltcp **0.2.2** vendored at `vendor/netstack-smoltcp/` (src copied from the
  crates.io 0.2.2 tarball via `static.crates.io`; lib-only manifest; `smoltcp` pinned `=0.12.0`).
- `StackBuilder::default()` is fluent — `.enable_tcp(bool).enable_udp(bool).enable_icmp(bool)
  .stack_buffer_size(n).tcp_buffer_size(n).udp_buffer_size(n).mtu(n).build()` →
  `io::Result<(Stack, Option<Runner>, Option<UdpSocket>, Option<TcpListener>)>`.
  (Confirmed: `src/stack.rs:103` `build()` returns exactly that tuple; `.mtu()` at `src/stack.rs:97`.)
  Builder defaults: stack_buffer 1024, udp 512, tcp 512, **mtu 1504** (1500 + 4 VLAN).
- `enable_icmp(true)` requires `enable_tcp(true)` — builder returns `InvalidInput "ICMP
  requires TCP"` otherwise (`src/stack.rs:129`). ICMP echo is serviced by the TCP Interface.
- `Runner`, if present, must be `tokio::spawn`'d (drives the smoltcp poll loop).
- `Stack: Stream<Item = std::io::Result<AnyIpPktFrame>>` + `Sink<AnyIpPktFrame, Error =
  io::Error>` (`src/stack.rs:203,216`). Note the **`io::Result` wrapper on the stream item** —
  the bridge does `while let Some(Ok(pkt)) = stream.next().await`. `stack.split()` gives the
  two halves. `AnyIpPktFrame = Vec<u8>` (`src/packet.rs:5`).
- `TcpListener: Stream<Item = (TcpStream, SocketAddr, SocketAddr)>` =
  `(stream, local_addr, remote_addr)` (`src/tcp.rs:414`). **CORRECTION (M2, verified
  against the construction site `src/tcp.rs:118,132-133,165` where the socket `listen`s
  on `dst_addr`):** netstack-smoltcp **inverts** the usual server-socket naming. The 2nd
  tuple element (`local_addr` = `TcpStream::local_addr()` = the `src_addr` field) is the
  **app's source** (`packet.src_addr`); the 3rd element (`remote_addr` = `dst_addr` field)
  is the **original destination** (`packet.dst_addr`) — the upstream the app dialed.
  **Dial the 3rd element.** The prior M0 note claimed `local_addr` was the original
  destination — that was inferred from the never-fired smoke example and is WRONG; the
  smoke example's variable name has been corrected. `TcpStream: tokio AsyncRead +
  AsyncWrite` (`src/tcp.rs:464,501`) and is `Unpin` (fields: 2×SocketAddr + 2 Arc-style
  shared handles) → `copy_bidirectional` works directly (`&mut *boxed` satisfies its
  `?Sized` bound; compiled + unit-tested at M2).
- `.mtu()` exists in 0.2.x but **not** 0.1.x — do not assume builder methods across versions.
- Toolchain floor: `smoltcp 0.12` needs rustc ≥1.80; `tun-rs` 2.8.x pulls an edition-2024
  dep → effective MSRV **≥ 1.85**. Dev box ran rustc **1.93.1** (active `stable`); MSRV floor
  enforced via `rust-version = "1.85"` in every manifest, not by pinning the toolchain.

### tun-rs (VERIFIED at M1 against the 2.8.5 source — trust)
- `tun_rs::DeviceBuilder::new().ipv4(addr, prefix_or_mask, dst: Option<IPv4>).ipv6(addr,
  prefix).name(S: Into<String>).mtu(u16).build_async() -> io::Result<AsyncDevice>`
  (`src/builder.rs:902,962,980,906,917,1355`). `.ipv4` mask arg is generic `ToIpv4Netmask`;
  a `u8` prefix works (we pass `24`). `build_sync()` also exists.
- `AsyncDevice::recv(&self, &mut [u8]).await -> io::Result<usize>` and `send(&self, &[u8])
  .await -> io::Result<usize>` (inherent; `&self` → shareable via `Arc`)
  (`src/async_device/unix|macos|windows/mod.rs`). `try_recv`/`try_send` exist too.
- `AsyncDevice: Deref<Target = DeviceImpl>`, so `dev.name() -> io::Result<String>` and
  `dev.mtu() -> io::Result<u16>` (and `addresses()`) work via auto-deref
  (`src/async_device/*/mod.rs` Deref; `src/platform/macos/device.rs:182,230`).
- **fd adoption (mobile, VERIFIED at M9 s1 against 2.8.5):** `unsafe AsyncDevice::from_fd(fd:
  RawFd) -> io::Result<AsyncDevice>` (`src/async_device/{unix,macos}/mod.rs`; takes ownership) and
  `borrow_raw(fd)` (doesn't). `SyncDevice::from_fd` is `#[cfg(unix)]`. **Android + iOS caveat:**
  tun-rs on `target_os="android"` AND `target_os="ios"` exposes only the fd path — **no
  `DeviceBuilder`** and **no `AsyncDevice::name()`** (verified: `cargo check --target
  aarch64-linux-android` AND `--target aarch64-apple-ios` both error E0432 + E0599 until
  `Tun::open`/`name` are gated `not(any(android, ios))`). macOS keeps them (`spark run` opens a
  device there). `recv`/`send`/`mtu`/`from_fd` work on all. **`spark-core` + `spark-apple`
  build for `aarch64-apple-ios`/`-ios-sim`/`-darwin` (M10 s1).**
- **macOS normalizes utun frames to raw IP** — no 4-byte AF prefix to strip; the parser
  keys on `buf[0] >> 4` on every platform (matches tun-rs's own cross-platform example).
- Framed bridge (for M2): `tun_rs::async_framed::{DeviceFramed, BytesCodec}` behind the
  `async_framed` feature; `DeviceFramed::new(dev, BytesCodec::new())` is a `Stream<Item=
  io::Result<BytesMut>>` + `Sink<BytesMut>`. We added only the `async` feature at M1.

## Baseline binary size
- **socket protection:** `spark` = **1,256,976 bytes (~1.20 MB)**, `spark-service` =
  **1,257,360 bytes (~1.20 MB)** — +~16 KB on `spark` for the protected-connect path (`socket2`
  was already transitive via tokio; `libc` is tiny). Both well under the 3 MB budget.
- **M7 (s3):** two binaries: `spark` = **1,240,448 bytes (~1.18 MB)** (client mode links
  `spark-ipc` + postcard). `spark-service` = **1,257,344 bytes (~1.20 MB)** (core + ipc + service).
- **M6:** `target/release/spark` = **1,223,760 bytes (~1.17 MB)**, stripped Mach-O arm64.
  +~114 KB over M5 — `toml` + `serde` pull in a real TOML parser/serializer (the largest
  single dep jump so far). Budget <3 MB — still comfortable, but watch dep weight from here.
- **M5:** `target/release/spark` = **1,107,152 bytes (~1.06 MB)**, stripped Mach-O arm64.
  +~33 KB over M4 — the UDP transports + `run_udp` orchestration + netstack UDP surface are
  now linked. Budget <3 MB — comfortable.
- **M4:** `target/release/spark` = **1,073,584 bytes (~1.05 MB)**, stripped Mach-O arm64.
  +~16 KB over M2 — the transport (Transport trait + TunnelClient + DirectTransport) is now
  linked into the binary (M3's transport was lib-only, dead-code-eliminated until M4 wired
  it in). Budget <3 MB — still comfortable.
- **M2:** `target/release/spark` = **1,057,008 bytes (~1.03 MB)**, stripped Mach-O arm64.
  +~133 KB over M1 — adds the vendored netstack-smoltcp + smoltcp + async-trait. Budget:
  <3 MB stripped — still comfortable headroom.
- **M1:** 923,344 bytes (~902 KB) — links tun-rs + tokio(full) + clap + tracing-subscriber.
  (M0 was ~280 KB — empty CLI.)

## Decisions log (append-only)
- 2026-06-25 (config-fetch fronting — kindling-fronted auto-fetch DONE + live-verified): **the
  censored cold-start config fetch now races a direct plain-TLS request against a domain-fronted
  one-shot h2 request** (spark #30; flint #7/#8/#9; `config-new-fetch-design.md §9` marked DONE).
  config-new is fetched over `flint_fronted::FrontedTlsDialer::request`, seeded from the embedded
  `core/src/config/fetch/fronted.yaml.gz` (the `domainfront` config — aliyun/akamai/cloudfront, with
  **Alibaba Cloud now a first-class fronting provider**). `fetch_once` runs `fetch_once_direct`
  (HTTP/1.1 via `probe::tls_wrap`, unchanged — keeps ETag/304) and `fetch_once_fronted`, taking the
  first usable config via `first_ok` (an early *failure* doesn't pre-empt the other attempt). The empty
  country code selects each provider's `default` SNI bucket (Alibaba's `img.alicdn.com` et al.). All
  pinned flint crates bumped to one rev (`76c5cd3`) so they resolve to a single checkout.
  **Live-verified against prod** (`live_fronted_fetch`): config-new returned a non-empty server pool
  *strictly* through the fronting path (decoy SNI → CDN edge, `Host: df.dcdn.getiantem.org`).
  **Three flint primitives built + merged:** (#7) `Provider::expanded` now applies the `default` SNI
  bucket even with no country code — the production client passes none, and the old `getlantern/fronted`
  gate left the new `aliyun` provider's SNIs permanently inert (the transport was otherwise a faithful
  port: schema, GlobalSign-R3 root pinning, SNI↔verify-host decoupling all already correct, matching
  `domainfront::ExpandedProvider`); (#8) `DirectH2Dialer`, a non-fronted h2 request-stream (the
  unfronted sibling of `FrontedMeekDialer`); (#9) a **one-shot** request (`OneshotRequest`/
  `HttpResponse`/`h2_oneshot` + `request()` on both dialers), separate from the meek tunnel.
  **Key architectural finding:** meek's `MeekStream` is *respond-first* (sends request headers, then
  awaits the response before exposing the write half) — correct for a meek server or a GET, but
  config-new is a read-body-then-respond **POST** that meek would **deadlock**; so a request-first
  one-shot primitive was split out from the meek transport (Adam's call). NB the §9 sketch said
  "connector swap in `http.rs`" — superseded by this one-shot design. Follow-ups (not done):
  AMP→smart→DNSTT escalation; apply the full-connection race (a candidate wins only after a complete
  response) to flint's `race_materialized_with` meek path as `DirectH2Dialer` got; release-binary size
  delta of the 69 KB embedded config.
- 2026-06-16 (M10 s1 — Apple packet-I/O architecture DECIDED + C-ABI staticlib): **fd-trick
  primary (+ packet-object fallback), hand-rolled C ABI, one provider for iOS+macOS.** Decided
  with Adam after deep research (3 agent passes: lantern's own NE, the Rust↔Swift FFI landscape,
  NE packet-I/O + iOS/macOS unification, then a second pass on Mullvad/Proton/Tailscale + Apple's
  official line). **Field survey:** WireGuard-apple, sing-box, **our own lantern** (team
  `ACZRKC3LQ9`), **Mullvad**, and **Proton** (incl. Proton's *Rust* tunnel) all use the fd-trick
  (`packetFlow.value(forKeyPath:"socket.fileDescriptor")` → public-symbol fd-scan fallback);
  **Tailscale** alone uses the official `readPacketObjects`/`writePackets` (for correct multipath
  egress). 5 of 6 → fd-trick, App-Store-proven for years. **Apple's official line (DTS/eskimo):**
  the fd-trick is *unsupported* ("don't start down that path") — non-public ivar (Guideline
  2.5.1), and Apple is migrating to a socket-less stack so the fd "may not exist" someday; blessed
  path is `packetFlow`; WWDC25 steers toward Network Relays/MASQUE. **Resolution:** fd-primary
  (reuses our entire `Tun::from_fd` netstack — max iOS/macOS/Android/desktop unification, leaner
  under the 50 MiB packet-tunnel cap, proven under *our* Apple account) **+ a packet-object
  fallback** as a documented follow-up that also future-proofs against Apple removing the fd. FFI
  = **hand-rolled C ABI** (the FFI research's pick: unifies with the Android JNI — packets don't
  cross the boundary in fd-mode, so the surface is control-only `run(fd)/stop`; uniffi/swift-bridge
  rejected — uniffi only wins if we also migrate Android to Kotlin). **This deviates from PLAN.md's
  M10 packet-object default; this entry supersedes it.** Built: `core::android`→`core::fd_tunnel`
  (shared android+ios+macos), `platforms/apple` staticlib (`spark_tunnel_run`/`stop`), builds for
  `aarch64-apple-ios`/`-ios-sim`/`-darwin`. Live gate target = macOS NE on this box (Developer ID
  cert present; iOS needs a device; NE doesn't run on the simulator) — build-verify now, macOS
  live gate next. Memory: tune smoltcp buffers 16–32 KiB/socket for the 50 MiB cap (iOS only).
- 2026-06-16 (M9 s3 — Android VpnService app + emulator gate PASSED): **`platforms/android/demo`
  drives the tunnel end-to-end on an emulator.** Minimal single-module Gradle app (AGP 8.9.1 /
  Gradle 8.11.1 / Kotlin 2.1.21, minSdk 24, compileSdk 35, framework-only — no AndroidX);
  `SparkVpnService:VpnService` does `Builder().setMtu(1500).addAddress("10.0.0.2",24)
  .addRoute("0.0.0.0",0).addDisallowedApplication(packageName).establish()` → `detachFd()` →
  `SparkBridge.nativeRun(fd, mtu)` on a worker thread; `onDestroy`→`nativeStop`. `MainActivity`
  handles consent + auto-connects (test harness). **Gate on Medium_Phone_API_35 (arm64):** VPN
  **CONNECTED + VALIDATED** (Android's own probe passed through spark); `adb shell` (uid 2000,
  through tun0) HTTP→connectivitycheck.gstatic.com/generate_204 = **204**; `adb logcat -s spark`
  showed `tunnel up` + `tcp flow … dst=8.8.8.8:853` + `tcp flow completed`; force-stop released
  `tun0`. **Gotchas:** (1) the `ACTIVATE_VPN` appop does NOT suppress the consent dialog on API 35
  — must tap OK once (uiautomator → button1 bounds), after which spark is the prepared VPN and
  `prepare()` returns null; (2) the `am start -S` cold-start is needed so `onCreate` re-fires the
  auto-connect; (3) `am startservice` can't start the VpnService from shell (BIND_VPN_SERVICE,
  uid 10208 only). `demo/` build outputs (jniLibs/, build/, .gradle/, local.properties)
  gitignored; gradle wrapper committed. Build artifacts NOT committed.
- 2026-06-16 (M9 s2 — Android JNI native library): **`platforms/android` cdylib +
  `core::android` run the data path on the VpnService fd; primitive-only JNI (no `jni` crate);
  loop avoidance via `addDisallowedApplication`.** New workspace member `platforms/android`
  (`crate-type=["cdylib"]`, `libspark_android.so`) depends on `spark-core`; its JNI symbols are
  `cfg(target_os="android")` so on desktop it's an empty cdylib (stays in the green-checked set).
  `core::android::run_tunnel(fd, mtu)` = `Tun::from_fd` → `transport::from_config` (default,
  direct) → `SmoltcpNetstack` → `proxy::tcp::run` + `run_udp`, on a private tokio runtime, racing
  a process-global `Notify` that `stop()` fires. JNI is **primitive-only** (`nativeRun(fd, mtu)
  -> jint`, `nativeStop()`; `extern "system"`, raw `*mut c_void` for env/class we don't deref) so
  **no `jni` crate** — chosen because the first cut needs no string/callback marshalling. **Loop
  avoidance = the Kotlin side's `VpnService.addDisallowedApplication(<self>)`** (excludes the
  in-process proxy's own upstream dials from the tunnel — the Android analog of the desktop
  `SocketProtector`), so no per-socket JNI `protect()` callback. Build tool: **cargo-ndk 4.1.2**
  (`-P` is the API level, NOT `-p` which collides with cargo's package flag); `ANDROID_NDK_HOME`
  → the lantern-pinned NDK **28.2.13676358**; ABIs arm64-v8a + x86_64, API 24. **Verified**: both
  `.so`s build; arm64 `libspark_android.so` exports `nativeRun`/`nativeStop` (llvm-nm) and DT_NEEDED
  is only libc/libm/libdl (tun-rs statically linked; cargo-ndk's stray `libtun_rs-*.so` dylib
  byproduct is dropped — tun-rs declares an extra dylib crate-type). `jniLibs/` gitignored. Prior
  art: lantern's `LanternVpnService.kt` (`establish()`/`detachFd`/`protect`); lantern uses gomobile
  (Go) so only its Kotlin VpnService + Gradle (NDK 28.2, minSdk 24, abiFilters arm64-v8a) transfer.
- 2026-06-15 (M9 s1 — Android core foundation): **Mobile adopts an fd, doesn't open a device;
  `spark-core` now cross-compiles for `aarch64-linux-android`.** Added `Tun::from_fd(fd, mtu)`
  (`#[cfg(unix)]`) wrapping `tun_rs::AsyncDevice::from_fd` — the seam for Android
  `VpnService.establish()`+`detachFd` (and Apple `NEPacketTunnelFlow` at M10); MTU passed in (the
  platform side sets it, the fd has no queryable interface). Verified against tun-rs 2.8.5 source:
  `from_fd`/`borrow_raw` are `#[cfg(unix)]`; tun-rs supports android (`target_os="android"` cfgs,
  `aarch64-linux-android` in its target list) but exposes **only** the fd path there — no
  `DeviceBuilder`, no `AsyncDevice::name()`. So `Tun::open`/`Tun::name` are now
  `#[cfg(not(target_os="android"))]` (desktop creates the device; mobile adopts the fd). The
  cross-check caught both gaps — would've been invisible without `--target aarch64-linux-android`.
  No C deps in the tree yet (no ring/rustls), so the android `cargo check` needs **no NDK**
  (check doesn't link). Building a real `.so`/cdylib + the JNI/Kotlin/Gradle layers + the
  on-device gate are the next chunks and DO need an Android toolchain (NDK + SDK + emulator), not
  present on this box. `spark-service`/`spark` are **not** built for android (VpnService is
  in-process, same-uid — no privileged-daemon split per M9 design; only `core` ships there).
- 2026-06-15 (M8 — Windows SCM service handler): **`spark-service` is a dual-mode binary; SCM
  integration via the `windows-service` crate; daemon body shared in a lib module.** Asked Adam
  re: FFI layer → **`windows-service` crate** (Mullvad's; +1 Windows-only dep, approved) over
  hand-rolling the SCM trio with `windows-sys` — type-safe, far less untestable unsafe FFI.
  `service::winsvc`: `service_dispatcher::start` → if launched by the SCM it runs the service to
  completion (returns true), else returns `Error::Winapi(1063
  ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)` → caller runs foreground. Control handler fires a
  `oneshot` on STOP/SHUTDOWN; the daemon's `select!` ends its `listen` future → drops `cmd_tx` →
  event loop winds down; STOPPED reported only after `block_on` returns. Because the SCM entry is
  a *sync* callback that must own its tokio runtime, the daemon body moved to a shared lib module
  **`service::daemon`** (`Args`, `run()`, `serve_daemon(args, shutdown)`); `main.rs` → thin shim;
  dropped `#[tokio::main]` (explicit `Runtime` in both entries); **unix behavior unchanged**
  (foreground, supervisor-signalled). `run_service` now does `engine.stop(RestoreDirect)` when its
  command channel closes, so a service STOP restores routing gracefully (not just on runtime drop).
  Deps: `windows-service 0.7` + transitive `windows-sys 0.52` fan-out (all target-gated). Verified
  via `cargo check --target x86_64-pc-windows-msvc --all-targets` (-D warnings); macOS (74 tests)
  + Linux cross-check green. **Not run under a real SCM** (no Windows host). MSI now unblocked;
  Event-Log logging is a follow-up.
- 2026-06-15 (M8 s2 — CI + release automation + packaging defs): **GitHub Actions for gates +
  tag-driven release; hand-rolled `dpkg-deb` over cargo-deb; GUI stays deferred (CLI is the
  client).** Asked Adam re: UI → **defer GUI** (matches M7's "the client may be a CLI" + the
  whole-project DoD), so M8 packages service + CLI only. `ci.yml`: fmt/clippy(`-D warnings`)/test
  on ubuntu+macos+windows, the Windows+Linux `--all-targets` cross-checks (warnings=errors), and
  `size-budget.sh` on ubuntu+macos. `release.yml`: on `v*`, a target matrix (macOS arm64+x86_64,
  linux x86_64, windows x86_64) builds release → size gate → packages (tar.gz+sha / `.deb` /
  `.zip`) → `softprops/action-gh-release`. **Hand-rolled the `.deb`** (`packaging/debian/build-deb.sh`
  + `control.template`/`postinst`/`prerm`/`conffiles`) instead of cargo-deb, so the layout/modes
  are fully explicit and don't depend on a tool's metadata schema — `/usr/bin/spark`,
  `/usr/sbin/spark-service`, systemd unit, `/etc/spark/config.toml` (conffile). `homebrew/spark.rb`
  = binary formula + root launchd service; release fills per-arch url+sha256 → tap. Windows = a
  `.zip` of the `.exe`s + config; a proper **SCM service + MSI is deferred** (needs a
  service-control handler in `spark-service`, e.g. the `windows-service` crate — don't ship a
  half-working `ServiceInstall`). Workflow-injection safe (`github.ref_name` only via `$REF_NAME`).
  Validated: YAML (ruby), formula (`ruby -c`), scripts (`bash -n`), `.deb` staging dry-run
  (tree + rendered control; `dpkg-deb` itself runs on the runner). Not yet run live: no tag
  pushed, no CI run observed (can't execute Actions locally).
- 2026-06-15 (M8 — Windows control transport): **Named pipe with an admin-only DACL is the
  Windows control channel; the DACL is the auth boundary (no `SO_PEERCRED` analog).** The
  per-connection serve loop (`conn::serve_connection`) was already transport-generic, so only the
  accept+auth front is platform-specific. New `service::pipe` creates the pipe with
  `create_with_security_attributes_raw` + a `SECURITY_ATTRIBUTES` from SDDL
  `D:P(A;;GA;;;SY)(A;;GA;;;BA)` (full control to Local System + Built-in Administrators only) —
  an unprivileged process can't `open` it, so there's no per-conn cred check (the structural
  analog of unix peer-cred, per CLAUDE.md's pipe-DACL note). Accept loop uses the tokio idiom
  (create instance → `connect().await` → create *next* instance before serving → no
  `ERROR_PIPE_BUSY`). `lib.rs` gates the transport: `listener` (unix socket) on unix, `pipe` on
  Windows, both exporting `serve`; `groups` is unix-only. `main.rs`/`cli` cfg-split bind/connect
  (`--socket` path + `AuthPolicy` + `secure_socket` on unix; `\\.\pipe\spark` on Windows). `libc`
  → unix-only dep; `windows-sys` (already locked transitively) added Windows-only for the DACL.
  Verified: the **whole workspace** now `cargo check --target x86_64-pc-windows-msvc`es
  warning-free (was core/ipc only); Linux full-workspace + macOS native stay green. Live Windows
  run not yet done (no Windows host) — gated with the other live gates.
- 2026-06-15 (M7 refinement — active route management): **Opt-in full-tunnel via the
  split-default trick; `Teardown::{RestoreDirect,Block}` actuates the kill-switch.** Decided
  with Adam (asked: own-the-table vs operator-driven) → **opt-in `[routing] manage`** (default
  off keeps the manual dev gates; on = spark owns routing). `core::routing::RouteManager`
  installs `0.0.0.0/1` + `128.0.0.0/1` via the TUN — more specific than the `0.0.0.0/0` default,
  so they win, while the real default is never touched → restore = delete the covers (or let the
  TUN vanish; the kernel removes its routes), crash-safe with no state to reconstruct. Upstream
  dials bypass via `SocketProtector` (why that was built first). `TunnelEngine::stop` now takes a
  `Teardown`: `RestoreDirect` (disconnect / fail-open) deletes covers; `Block` (fail-closed)
  blackholes both halves (Linux `ip route add blackhole`, macOS `route … -interface lo0`, both
  TUN-independent so they outlive teardown). All ops clear stale covers first → order-independent
  + self-heal on reconnect-after-block. IPv4 only (TUN is v4-only; v6 split-default deferred).
  Command construction unit-tested per platform; **live `route`/`ip` calls not yet run under
  root** (gated with the other live gates). Deps: none new (`tokio::process` from existing full
  features). `spark-service` +17 KB; `spark` unchanged (DCE — `spark run` doesn't manage routes).
- 2026-06-15 (M7 refinement — peer supplementary groups): **Resolve the peer uid's full login
  group set so `spark` membership counts as a secondary group.** `peer_cred()` reports only the
  primary gid; admins normally add users to `spark` as a *supplementary* group. New
  `service::groups::resolve_groups` does `getpwuid_r` (uid→name) + `getgrouplist` (name→groups),
  best-effort (any failure → just `[gid]`). `PeerCreds` gained `groups: Vec<u32>` (resolved off
  the live socket in the listener); `AuthPolicy::authorize` stays a pure fn but now matches
  `spark_gid` against primary gid OR any supplementary group. `getgrouplist`'s group-element type
  differs by platform (Apple `c_int` vs Linux `gid_t`, both 32-bit) — handled with a cfg alias.
  Verified signatures against vendored libc 0.2.186 source before writing the FFI.
- 2026-06-15 (M7 refinement — push backpressure): **Drop-newest + `Push::Dropped{count}`
  accounting; a slow subscriber is kept, not silently starved.** `broadcast` previously dropped
  events on a full subscriber channel with no signal. Now each `Subscriber` carries an overflow
  counter; on a full channel the item is dropped + counted (delivery stays non-blocking so a
  wedged client never stalls the loop), and the count rides out as a `Push::Dropped` once the
  channel drains — the client's cue to re-sync via `GetStatus`. NOT literal drop-oldest (a tokio
  mpsc sender can't evict the oldest without a shared broadcast ring, which would dismantle the
  per-connection subscriber model); correctness is identical for state since the freshest truth
  is one `GetStatus` away. `Push::Dropped` already existed in the protocol — this wires the
  producer.
- 2026-06-15 (M7 kill-switch, signaling half): **An unexpected data-path exit fails open
  loudly; `[kill_switch] fail_closed` overrides to fail closed. Active route-restore deferred.**
  `engine::CoreEngine::start` now takes an `exit: mpsc::Sender<()>` and runs the TCP+UDP
  forwarders under ONE supervisor task; the task fires `exit` only if a forwarder loop returns
  on its own (a deliberate `stop` aborts the task before that line, so a clean disconnect never
  signals). `run_service` owns the `exit_rx` and selects on it: while `state == Connected`, an
  exit signal calls `engine.stop()` (reclaims the dead device), then — fail-open (default) —
  sets `direct_fallback = true` + transitions `Disconnected`, or — fail-closed — transitions
  `Failed`; either way it broadcasts `Push::Event(FellOpenToDirect)` and `warn!`s. (The
  `FellOpenToDirect` event + `TunnelStatus.direct_fallback` flag already existed in the M7-s2
  protocol; this wires the producer.) `core::config::KillSwitchConfig { fail_closed: bool }`
  (default false = fail open, per process-architecture §5); `spark-service` reads it and passes
  `fail_closed` into `run_service`. `spark status` prints a loud `WARNING: failed open …` when
  `direct_fallback`. `FakeEngine` grew a `kill()` to simulate the exit; 2 new hermetic tests
  (`unexpected_exit_fails_open_loudly` / `…fails_closed_when_configured`) over the duplex.
  **Signaling only** — the *active* route-table restore / traffic-blocking is still the deferred
  platform/root half (tracked with supplementary-group resolution + drop-oldest backpressure).
  Sizes unchanged at ~1.20 MB each.
- 2026-06-15 (M8 s1): **Desktop packaging — cross-build checks + service units + size gate.**
  Release profile already locked (opt-level=z/lto=fat/cu=1/strip/panic=abort). `cargo check
  --target` verified Linux (full workspace) and Windows (`spark-core`+`spark-ipc`); the Windows
  control transport (`UnixListener`/`UnixStream` are unix-only) needs a named-pipe port before
  `spark-service`/`spark` build there — tracked. `packaging/`: a `config.example.toml`, a
  systemd unit (`spark.service`) and a launchd plist (`org.getlantern.spark.plist`) — both
  config-driven, root-only control by default (opt into a group via `--spark-gid`), TUN defaults
  10.0.0.1/24. `scripts/size-budget.sh` builds + fails over the 3 MB/binary budget (both ~1.20 MB
  = 39%). macOS daemon path = launchd (the App-Store/iOS NE path is M10). Full distro packages
  (deb/Homebrew/MSI) + multi-platform run deferred.
- 2026-06-15 (socket protection): **`core::net::SocketProtector` pins upstream dials to a
  physical interface so they bypass the tunnel route (fixes the macOS forwarding loop).**
  `IP_BOUND_IF`/`IP_UNICAST_IF` via `socket2::bind_device_by_index_v4/v6` (feature `all`), index
  from `libc::if_nametoindex`; no-op on platforms without it. TCP via `tokio::TcpSocket` +
  `SockRef` pre-connect; UDP built via `socket2::Socket` then `UdpSocket::from_std`. Both
  `DirectTransport` and `TunnelClient` carry `Option<SocketProtector>`; built centrally by the
  new `transport::from_config(&Config)` (used by `spark run` and `CoreEngine`). New
  `[transport] protect_interface` config + `--protect-interface` flag. Verified live (no root)
  that the setsockopt applies on macOS. Deps added: `socket2` (already transitive via tokio),
  `libc`. Sizes ~1.20 MB each.
- 2026-06-15 (M7 s3): **Live daemon path — `spark-service` binary + `spark` client subcommands;
  peer creds via tokio `UnixStream::peer_cred` (no libc).** `service::listener::serve` accepts on
  a `UnixListener`, reads `peer_cred()` (works on macOS via `LOCAL_PEERCRED`/`getpeereid`, Linux
  via `SO_PEERCRED`), applies `AuthPolicy`, spawns `serve_connection`. `engine::CoreEngine` is the
  real `TunnelEngine` (opens TUN, runs `SmoltcpNetstack` + proxy — same as `spark run`; needs
  root). `cli` refactored to subcommands: `run` (in-process driver) + `connect`/`disconnect`/
  `status` (control client via `ipc::Client`). `ipc::Client` (stream feature) does the handshake
  + request, skipping interleaved pushes. **Control plane live-verified without root** over a real
  unix socket (auth refuse+allow, handshake, status, connect→clean-error, state→Failed). `libc`
  is a service dev-dep only (test `getuid`). Binaries: `spark` ~1.18 MB (+ipc/postcard for client),
  `spark-service` ~1.20 MB. Privileged TUN+routing+curl gate still pending (shares M1–M6 queue).
- 2026-06-14 (M7 s2): **Service = actor event loop; `ServerMessage` demux envelope; feature-gated
  async `stream` layer; auth policy pure+testable.** Added `ipc::ServerMessage` (Response|Push) so
  the client can demux replies from pushes on one connection (gap found while wiring s2). Async
  framing (`read_frame`/`write_frame`) lives behind ipc's `stream` feature (off by default →
  message-oriented mobile transports stay tokio-free). `service::run_service` is a single task
  owning state (no `Arc<Mutex>`), `Hello`-gated, broadcasting `StateChanged` to subscribers;
  `serve_connection` is cancel-safe — `read_frame` (not cancel-safe) runs in a dedicated reader
  task feeding a `select!` that interleaves responses + pushes (NOT `read_frame` directly in
  select). `auth::AuthPolicy` (root + `spark` gid + optional uids) is a pure function of
  `(uid,gid)`; live `SO_PEERCRED` extraction + supplementary-group resolution deferred to s3.
  Subscriber backpressure is best-effort drop-newest for now; drop-oldest + `Push::Dropped` is a
  noted s3 refinement. All hermetic over `tokio::io::duplex`; ipc/service not yet linked into the
  `spark` binary (the cli client mode in s3 links them).
- 2026-06-14 (M7 design + s1): **Control-plane IPC = postcard + length-delimited framing over
  a unix socket; `SO_PEERCRED` + `spark` group; service actor loop; protocol is mobile-portable.**
  Decided with Adam after researching Mullvad (Rust, gRPC/tonic) and Tailscale (Go, HTTP/JSON
  LocalAPI + operator model). gRPC ruled out by CLAUDE.md's no-hyper rule + the <3 MB budget;
  HTTP needs a stack — so postcard (already in serde) + a `u32`-LE length frame. **Split the
  message codec from the framing** so message-oriented transports (Apple NE `sendProviderMessage`,
  Android in-process) reuse the messages WITHOUT framing; only stream transports frame. Service =
  one event loop (`mpsc<Command>`+`oneshot`, no locks) broadcasting to bounded subscribers.
  Auth = root + `spark` group via `SO_PEERCRED` (Linux/macOS-daemon only; Android has no boundary,
  iOS uses code-signing + App Group). Full design + mobile analysis in the
  `ipc-service-split-design-m7` memory. **Session 1 landed:** `spark-ipc` (types + codec + framing
  + `negotiate`), pure/no-async, 8 tests. `MAX_FRAME_LEN` (1 MiB) caps hostile-peer allocation.
- 2026-06-14 (M6): **TOML config (serde+toml) + IP-redaction backstop + `--config` rule.**
  `core/src/config`: `Config` with per-section defaults (`#[serde(default, deny_unknown_fields)]`
  so partial files work and typos error); `Option` fields use `skip_serializing_if` for clean
  round-trips. Sections: `[tun]`/`[transport]`/`[udp]`/`[log]`. Added `serde` + `toml` (locked
  stack). CLI: `--config <file>` loads the full config and the individual flags are ignored
  when set; otherwise flags build the `Config` (`Cli::to_config`). **Log hygiene = level
  convention + redaction backstop:** addresses only in `debug!` (filtered at default `info`),
  AND a `RedactingWriter` scrubs IPv4 dotted-quads + bracketed IPv6 from output unless `--debug`
  (`core/src/redact.rs`, dep-free; no regex). Redaction deliberately skips hostnames/bare-IPv6
  (false-positive risk on module paths / version strings) — those rely on the level convention.
  Graceful shutdown: `select!` drop + explicit `drop(tun)` → Drop tears the device down. Live
  SIGINT-device gate needs root. Binary +~114 KB (toml/serde parser) → ~1.17 MB.
- 2026-06-11 (M5 s2): **UDP transport surface = split `PacketSink`/`PacketSource` +
  `UdpTransport::dial_udp`; own framing, connect-mode, magic-sentinel dispatch; netstack
  reply via mpsc drain.** Researched prior art (sing-box UoT `common/uot`, sing-quic
  hysteria, Leaf) — see the `udp-transport-design-proposal` memory. Decided with Adam:
  (1) separate traits, not folded into `Transport`; (2) own framing in `tcp_tunnel` (NOT
  UoT-byte-compat — framing is per-transport so a future SS/sing-box transport can speak UoT
  without touching the core); (3) **split halves, not `&self`** (a stream-backed conn can't
  do `&self` writes without locking across `.await`); (4) **connect-mode** — announce the
  target once, then `[u16 len][payload]` datagrams; (5) **UDP-associate dispatch = magic
  sentinel address** (`udp-associate.spark.invalid`, `.invalid` per RFC 2606), leaving the
  M3 TCP header unchanged; (6) **netstack reply = mpsc drain task** owning the smoltcp UDP
  `WriteHalf` (reply pumps clone the `Sender`), avoiding shared-Sink locking. `DirectTransport`
  and `TunnelClient` both impl `UdpTransport`. `SmoltcpNetstack` now `enable_udp(true)` +
  `take_udp()`. Verified orientation: `UdpMsg = (payload, local=client_src, remote=original_dst)`,
  inverted like TCP; reply sent to the stack as `(payload, original_dst, client_src)`.
- 2026-06-11 (M5 s1): **UDP-over-tunnel framing + NAT table; DNS = proxy-through-tunnel;
  idle timeout = 60s.** Datagram framing (`transport/tcp_tunnel/udp.rs`):
  `[Address][LEN(u16,be)][payload]` — reuses the M3a `Address` codec, length-prefixed so it
  survives a stream (TCP/TLS) that erases datagram boundaries; `parse` returns
  `(Address, &payload, consumed)` and distinguishes `Incomplete` (truncated) from malformed,
  like the TCP header. NAT table (`proxy/udp.rs`): generic `NatTable<V>` keyed by
  `(client_src, original_dst)`, `now`-injected for deterministic eviction tests,
  `evict_expired` returns reclaimed values so the orchestration can close per-flow sockets.
  `DEFAULT_IDLE_TIMEOUT = 60s` (DNS is short-lived; covers a slow resolver without stranding
  state). DNS strategy = **proxy-through-tunnel** (no special-casing :53 — it rides the UDP
  path like any datagram), per the standing decision. Netstack UDP socket left disabled
  until session 2 (enabling it without draining `ReadHalf` would back-pressure the stack).
- 2026-06-11 (M4): **`Transport` trait is the direct/tunnel seam; `dial` takes `SocketAddr`.**
  `core/src/transport/mod.rs`: `#[async_trait] trait Transport: Send + Sync { async fn
  dial(&self, target: SocketAddr) -> io::Result<BoxedStream> }`. `DirectTransport` (M2
  behavior) and `TunnelClient` both impl it; the forwarder takes `Arc<dyn Transport>` and is
  identical for both. `dial` takes `SocketAddr` (what the netstack surfaces), not the richer
  `Address`, to decouple the trait from the tunnel header type — the tunnel impl wraps it as
  `Address::Ip` internally. `TunnelClient` keeps an inherent `dial(Address)` (domain-capable,
  used by M3b tests); the trait method delegates to it (the `Address` arg disambiguates the
  overload). **Moved `AsyncReadWrite` + added `BoxedStream` alias to the crate root** (`lib.rs`)
  so netstack flows and transport streams share one boxed type. CLI selects transport with
  `--server <addr>` (tunnel) vs absent (direct). Live gate (curl through a real server) is
  root+server-gated and deferred.
- 2026-06-11 (M3b): **Header sent eagerly in `dial`; `TunnelStream` is a transparent
  pass-through.** `TunnelClient::dial(target)` opens TCP to the server, `write_all`s the
  encoded header, then returns `TunnelStream<TcpStream>` which just delegates
  `AsyncRead`/`AsyncWrite` to the inner connection. (Lazily coalescing the header into the
  first `poll_write` saves a syscall but adds partial-write state — deferred as an
  optimization; the gate is a correctness echo.) Server-side header recovery lives in
  `stream::read_header` (partial-read buffering: loop `Address::parse`, treat `Incomplete`
  as read-more, map permanent errors → `InvalidData`, mid-header EOF → `UnexpectedEof`); it
  returns `(Address, leftover_payload_bytes)` so a relay forwards bytes read past the header.
  Integration test uses an in-test relay (Appendix B opt 1); the relay tries all resolved
  candidate addresses (localhost → ::1 then 127.0.0.1) to stay order-independent. No TLS yet.
- 2026-06-11 (M3a): **Tunnel header = SOCKS5 address grammar (RFC 1928 §4), no SOCKS
  framing.** `ATYP(1) | ADDR | PORT(2, big-endian)`, ATYP 1=IPv4 / 3=domain(len-prefixed) /
  4=IPv6. Chosen because it's compact, self-delimiting, and off-the-shelf relays already
  speak it. `Address` enum = `Ip(SocketAddr)` (covers v4+v6) | `Domain{host,port}` (domain
  validated non-empty + ≤255 at construction via `Address::domain`, so `encode` is
  infallible). `parse` returns `(Address, consumed_len)` and distinguishes
  `HeaderError::Incomplete` (truncated → caller reads more; M3b's buffering retry signal)
  from permanent errors (`UnknownAtyp`/`EmptyDomain`/`InvalidDomain`). Lives in
  `core/src/transport/tcp_tunnel/header.rs`; the `Transport` trait is deferred to M4.
- 2026-06-10 (M2): **Original-destination address fix.** netstack-smoltcp inverts the usual
  server-socket naming: the `TcpListener` tuple's **3rd** element (`remote_addr`) is the
  original destination to dial, not the 2nd. Verified at the construction site
  (`vendor/.../src/tcp.rs:118,132-133,165`, socket `listen`s on `dst_addr`). Corrected the
  STATE verified-facts line and the (never-fired, hence latently-wrong) smoke-example label.
- 2026-06-10 (M2): **Bridge = raw `recv`/`send` loop, not `DeviceFramed`.** Kept the M1
  `Tun::recv`/`send` surface (shared via `Arc<Tun>`, both take `&self`) over adding the
  `tun-rs` `async_framed` feature — fewer moving parts and lower API risk. The stack `Sink`
  item is owned `Vec<u8>` (`AnyIpPktFrame`), so the TUN→stack direction reads into a fresh
  `vec![0u8; mtu]` and `truncate`s — one alloc, zero copy (the alloc is forced by the
  vendored sink signature; eliminating it means patching the vendor to take `BytesMut`).
- 2026-06-10 (M2): Stack built `enable_tcp(true).enable_udp(false).enable_icmp(true)`,
  `.mtu(tun.mtu())`. ICMP rides the TCP interface for free and keeps the M1 ping sanity
  check; UDP deferred to M5. `SmoltcpNetstack` owns the runner + both bridge tasks as
  `JoinHandle`s and aborts them on `Drop` (no orphaned tasks).
- 2026-06-10 (M2): Added `async-trait` (pre-approved in CLAUDE.md for trait objects) for the
  `Netstack` trait. `TcpFlow.stream: Box<dyn AsyncReadWrite + Unpin + Send>`; forwarder
  passes `&mut *stream` to `copy_bidirectional` (its `?Sized` bound accepts the trait object,
  which auto-implements the `AsyncRead`/`AsyncWrite` supertraits).
- 2026-06-10 (M2): **M2 macOS curl gate deferred to M4.** Direct dial + routing the target
  into the tun loops on macOS (no `SO_BINDTODEVICE`); the loop vanishes at M4 when spark
  dials a tunnel server at a different address. Linux gate (per-socket bind) is the M2 check.
- 2026-06-10 (M0): Vendored `netstack-smoltcp` **0.2.2** by copying the published crates.io
  0.2.2 source (via `static.crates.io`) into `vendor/netstack-smoltcp/`, rewritten to a
  lib-only manifest (examples/tests/dev-deps dropped) with `smoltcp` pinned to `=0.12.0`.
  Excluded from `[workspace.members]` (`exclude` in root manifest) so its dev-deps don't
  enter our lock; depended on by `path` via `[workspace.dependencies]`.
- 2026-06-10 (M0): Workspace members = `core` (`spark-core`), `cli` (`spark-cli`, bin
  `spark`), `ipc` (`spark-ipc`, empty stub), `service` (`spark-service`, empty stub).
  `netstack-spike` and `circ-tool` also `exclude`d. Release profile (opt-level=z, lto=fat,
  cu=1, strip, panic=abort) lives in the **root** manifest (profiles only apply from root).
- 2026-06-10 (M0): `rust-toolchain.toml` uses `channel = "stable"` (not a hard pin); MSRV
  floor ≥1.85 enforced by `rust-version` in each manifest. Active stable on dev box = 1.93.1.
- 2026-06-10 (M1): **Hand-rolled** the IP parser + ICMP echo logic (`core/src/packet/`)
  instead of pulling `pnet_packet` (what the tun-rs example uses) — a TUN in IP mode never
  sees L2/ARP, and keeping it dep-free protects the size budget. ~120 lines, unit-tested
  (RFC-1071 checksum; v4 IP+ICMP and v6 ICMPv6 pseudo-header).
- 2026-06-10 (M1): **Log hygiene enforced from M1, not deferred to M6.** The driver logs
  `proto`+`len` at `info`; src/dst addresses only at `debug` (`--debug` or `RUST_LOG=debug`).
  Satisfies M1's "logs show parsed packets" without leaking destinations by default.
- 2026-06-10 (M1): tun-rs added with the `async` feature only (tokio AsyncDevice, raw
  recv/send loop). `async_framed` deferred to M2 when the netstack bridge needs it.
- Language/stack: Rust + tokio + rustls(ring) + ring; netstack = **vendored** netstack-smoltcp
  over smoltcp; TUN = tun-rs (desktop). Rationale in CLAUDE.md (locked stack).
- MSRV ≥ 1.85 (toolchain floor above).
- Process model: privileged tunnel process + unprivileged client; **data plane in-process**,
  control-plane IPC only (`ipc/` crate, serde+postcard, length-prefixed, versioned handshake).
- Kill-switch: **fail open** (restore direct routing on crash, surfaced loudly) with a
  per-profile fail-closed override. (process-architecture-and-ipc.md §5.)
- DNS strategy default: **proxy-through-tunnel** (revisit at M5 if needed).
- FFI (mobile): **uniffi-rs** preferred (confirm at M10).
- Config format: TOML (alternate import formats deferred).

- 2026-06-19 (UI — DECIDED: migrate the GUI from Flutter → **Tauri v2**; ADR 0008): After a wholesale
  re-eval of UI frameworks with Adam (client priorities Android > Windows > iOS > macOS > Linux;
  install size first-class), chose **Tauri v2** over Compose Multiplatform and over keeping Flutter.
  Rationale: Tauri uses the **system WebView** (no bundled engine → smallest install, on-ethos with
  the <3 MB core), its backend **is** Rust (the core links in directly; collapses today's two bindings
  — `flutter_rust_bridge` desktop + platform-channels mobile — into one `invoke()`/event surface), and
  the Lantern look is pure CSS (proven: `docs/mockups/spark-tauri-lantern-look.html` reproduces
  `gui/lib/main.dart`'s `_Palette` exactly). Compose was runner-up (best Android polish, reuses
  Kotlin/UniFFI) but its desktop path needs a bundled JVM (fights the size goal). **Scope = UI shell
  only:** `core/`, netstack, transports, `ipc/`, `spark-ffi`/UniFFI, the privileged `spark-service`,
  and the `platforms/{android,apple}` tunnel shims are all reused unchanged; the process/privilege
  model (ADR 0005) is unchanged (Tauri app = unprivileged client). Migration = UI track **U0–U4** in
  PLAN.md §4 (macOS-first proof → Android → Windows/iOS/Linux; retire `gui/` only at parity). Open
  sub-decision deferred to U0: front-end stack (Svelte+Vite recommended, vanilla TS fallback). **Hard
  constraint:** the Tauri dep tree must not pull `openssl-sys` (verify at U0); keep Tauri out of `core/`.

- 2026-06-19 (U0 DONE — Tauri shell + Lantern web UI, mock backend): Scaffolded `gui-tauri/`
  (Tauri **v2.11.3** + **SvelteKit/svelte-ts**, adapter-static SPA, `ssr=false`; Svelte 5 runes).
  Ported the Lantern connect screen from `docs/mockups/spark-tauri-lantern-look.html` into
  `src/routes/+page.svelte` (the `_Palette` tokens verbatim; window 390×760 non-resizable, title
  "Spark", identifier `org.getlantern.spark`). Added the `SparkBackend` TS seam + `MockBackend`
  (`src/lib/spark_backend.ts`); the screen polls `status()` every 500ms exactly as it will against
  the real service. `src-tauri/src/lib.rs` is shell-only (no commands yet). Root `Cargo.toml`
  `exclude`s `gui-tauri/src-tauri` so Tauri stays out of the core workspace graph. **Gate PASSED:**
  `npm run tauri build` green on macOS → `Spark.app` **8.3 MB** / `Spark_0.1.0_aarch64.dmg` **2.9 MB**
  (vs Flutter's bundled-engine floor — direct Flutter-DMG comparison deferred to U1); `cargo tree -i
  openssl-sys` empty (CLAUDE.md hard rule holds — no openssl/native-tls in the tree); `cargo fmt
  --check` + `cargo clippy --release` clean; SPA bundle ~4.8 kB JS + 4.4 kB CSS. Not done in U0:
  bundle the Sora font (system fallback for now), CSP hardening (left `csp:null`), a visual
  screenshot (UI is a verbatim port of the rendered mockup). **Next chunk = U1** (macOS to parity:
  real `invoke()` command surface implementing SparkBackend over `spark` core / `spark-ipc`, runtime
  `config.toml` precedence, connect-e2e gate + Flutter-DMG size delta).

- 2026-06-19 (U1 DECISION + decomposition — macOS = NE Model A, spike-first): Adam chose **NE Model A**
  (one-click, no sudo) for the macOS Tauri app over the `spark-service` daemon path. So `connect()`
  drives `NETunnelProviderManager` (Swift port of `gui/macos/Runner/SparkVPN.swift`), **not**
  `spark-backend`/`spark-ipc`. Code-grounded findings: the `SparkTunnel` **system-extension** target in
  `platforms/apple` (project.yml; links `SparkCore.xcframework`, NE + system-extension.install
  entitlements) and the embed/sign/notarize recipe in `packaging/macos/build-gui-dmg.sh` (build
  `.systemextension` → copy into `App.app/Contents/Library/SystemExtensions/` → re-sign with NE
  entitlements → notarize) are **reused as-is**; data-path config flows via
  `providerConfiguration["config"]`. **The unproven part** (do NOT guess — CLAUDE.md): Tauri's macOS
  *desktop* build is not Xcode-based, so calling Swift `NETunnelProviderManager` from a Tauri
  `invoke()` command is unverified. U1 is decomposed in PLAN.md §4: **U1a** = Swift-bridge spike (prove
  the Rust→Swift→NE path; smallest-first: C-ABI NE fns in `platforms/apple` / Swift staticlib via
  build.rs / Tauri-v2 Swift plugin-on-desktop) → **U1b** = embed+sign+wire (invoke surface, config.toml
  precedence, swap MockBackend→TauriBackend, adapt build-gui-dmg.sh for the Tauri .app; size vs Flutter
  DMG) → **U1c** = live connect-e2e gate. **Human-blocked:** U1c needs the NE provisioning profile
  (team `ACZRKC3LQ9`, distribution-only) — same blocker as M10; added to PLAN.md §3. **Next chunk =
  U1a** (its own focused session — research-led spike, stop-and-report). No code written this turn
  (the next step is the spike, not guessable glue).

- 2026-06-19 (U1a DONE — Swift-bridge spike: bridge PROVEN, pure-Rust objc2): The Tauri-desktop Rust
  side reaches macOS NetworkExtension **directly via `objc2` + `objc2-network-extension` 0.3.2 — no
  Swift toolchain, no Tauri Swift plugin, no Xcode.** `cargo run --example ne_probe` (in
  `gui-tauri/src-tauri`) printed `NEVPNStatus = invalid (0)` via `NETunnelProviderManager::new()` →
  `connection()` → `status()` — the read path that needs no NE entitlement, so it runs unsigned in dev.
  **Recommendation = Approach A (pure-Rust objc2)**; the Swift→C shim and Tauri-Swift-plugin options are
  rejected. Added (macOS target only): deps `objc2` 0.6 + `objc2-network-extension` 0.3; `ne_spike`
  module + `ne_probe` Tauri command (registered in the invoke handler) + `examples/ne_probe.rs`.
  fmt+clippy clean; `cargo tree -i openssl-sys` still empty (no regression). **Note for crates.io:**
  0.3.x exposes all NE classes by default — there are NO per-class features (available: alloc, block2,
  libc, objc2-security, std). **For U1b:** the WRITE/activate path
  (`loadAllFromPreferencesWithCompletionHandler` / `saveToPreferences` / `startVPNTunnel` +
  `OSSystemExtensionRequest`) uses completion-handler **blocks** → add the `block2` feature and await
  via a oneshot on Tauri's main runloop, and define the `OSSystemExtensionRequestDelegate` with objc2
  `define_class!`; that write/activate path needs the NE entitlement + provisioning (U1c, human). **Next
  chunk = U1b** (embed the systemextension + invoke surface + config.toml precedence + MockBackend→
  TauriBackend; size vs Flutter DMG).

- 2026-06-19 (U1b machinery PROVEN — async loadAllFromPreferences via block2 + run loop): Built the
  real status source (U1a's synchronous `new()` was only a bridge probe). `ne_spike::
  load_first_status_blocking()` calls `NETunnelProviderManager::loadAllFromPreferencesWithCompletionHandler`
  with a `block2::RcBlock` completion, then drives `NSRunLoop::currentRunLoop().runMode_beforeDate` in
  0.1s slices (~3s cap) so the main-queue completion fires; reads `objectAtIndex(0).connection().status()`.
  `cargo run --example ne_probe_async` printed **"2 saved manager(s); first status = connected (3)"** —
  i.e. it read the machine's *real* `org.getlantern.spark` NE configs (one live), proving the block2 +
  run-loop completion machinery that connect/disconnect (saveToPreferences/startVPNTunnel) will reuse.
  Added (macOS): deps `block2` 0.6 + `objc2-foundation` 0.3 (feature `block2`); `objc2-network-extension`
  gains feature `block2`; `examples/ne_probe_async.rs`. clippy `-D warnings` + fmt clean; `cargo tree -i
  openssl-sys` still empty. **Still TODO in U1b** (not yet built): hop the `status` Tauri command to the
  main thread + return this; `connect`/`disconnect` write path = `define_class!`
  `OSSystemExtensionRequestDelegate` + saveToPreferences/startVPNTunnel; config.toml precedence;
  MockBackend→TauriBackend swap; embed the `platforms/apple` systemextension + adapt build-gui-dmg.sh.
  **Write/activate needs the NE entitlement + provisioning (U1c, human-blocked).**

- 2026-06-20 (U1b-1 DONE + PROVISIONING UNBLOCKED — system extension builds & signs): The M10-era
  provisioning blocker is cleared. Root cause was a Developer ID cert mismatch: the "Spark macOS
  App"/"Spark macOS Tunnel" profiles pinned Developer ID Application serial `52097FEB` (exp May 2030),
  but this Mac's only codesigning private key is serial `47D77D` (exp Feb 2030). Confirmed `52097FEB`'s
  key is nowhere here (no .p12 in Downloads/Desktop/Documents/home; importing its public .cer added a
  keyless cert, no new identity). Fix (Adam, portal): regenerated both profiles selecting the
  **Feb-2030 / 47D77D** "Developer ID Application" cert (NOT the "Developer ID Installer" rows — those
  sign .pkg, not the app/extension). Reinstalled them into the Xcode store (UUIDs f19f7cab = App,
  470ae1fc = Tunnel), removed the stale 52097FEB ones (0571d9e8/2ce5e0e9). `xcodebuild archive SparkApp`
  now SUCCEEDS → `org.getlantern.spark.tunnel.systemextension` (3.7 MB) signed Developer ID
  (ACZRKC3LQ9) + hardened runtime, NE entitlements baked (packet-tunnel-provider-systemextension +
  group.org.getlantern.spark). Also committed `edad6bc`: build-xcframework.sh bash-3.2 unbound-array
  fix (`${feat[@]+…}`) — latent since the full archive had never run here. **Remaining U1b:** U1b-2 =
  objc2 connect/disconnect/status write path (OSSystemExtensionRequest activate via `define_class!`
  delegate + NETunnelProviderManager save/start/stop); U1b-3 = config.toml precedence +
  MockBackend→TauriBackend; U1b-4 = embed the .systemextension into the Tauri .app + Release.entitlements
  + app profile + sign + notarize → product DMG (sign+notarize pipeline already proven on the shell DMG).
  **Next chunk = U1b-2.**

- 2026-06-20 (U1b-2a DONE — config precedence + real status command + frontend TauriBackend swap):
  Added `gui-tauri/src-tauri/src/config.rs` — data-path config precedence (config.toml → SPARK_CONFIG
  → SPARK_PROXY → direct), 5 unit tests. Added `ne_spike::load_first_status(timeout)` (recv_timeout,
  app-context variant of the proven loadAll — no run-loop drive; the Tauri main loop services the
  completion) + `ui_state` mapping. Command surface: **`spark_status`** (real live NE state),
  `spark_connect`/`spark_disconnect` (resolve config, return an explicit "pending U1b-2b" error — no
  silent no-op). Frontend: `tauri_backend.ts` (`TauriBackend` over invoke + `isTauri()`); `+page.svelte`
  picks TauriBackend in the app / MockBackend in a plain browser, polls 2s, surfaces connect errors in
  the substatus. Verified: cargo build + clippy clean; **5 config tests pass; svelte-check 0 errors**;
  full **signed** `tauri build` → Spark.app/DMG 3.9M. **Remaining U1b-2b** (the last compile-only piece;
  runtime-testable only after embed+sign + first-run approval = U1c): NETunnelProviderManager write path
  (NETunnelProviderProtocol providerBundleIdentifier=`org.getlantern.spark.tunnel` +
  providerConfiguration["config"] → save → start; connection.stopVPNTunnel) + OSSystemExtensionRequest
  activation via objc2 `define_class!` OSSystemExtensionRequestDelegate. Then **U1b-4**: embed the
  systemextension into the Tauri .app + Release.entitlements + app profile + notarize → product DMG.

- 2026-06-20 (U1b-4 DONE — product-structured NOTARIZED DMG: Tauri app + embedded system extension):
  Embedded `org.getlantern.spark.tunnel.systemextension` (3.7M) + the "Spark macOS App"
  provisioning profile into the Tauri Spark.app; re-signed with `gui-tauri/src-tauri/Release.entitlements`
  (NE packet-tunnel-provider-systemextension + system-extension.install + group.org.getlantern.spark) +
  Developer ID + hardened runtime; **notarized + stapled BOTH the app and the DMG** (notary: Accepted).
  Gatekeeper: app "accepted, source=Notarized Developer ID"; `stapler validate` OK. Sizes: app **12M**
  (8.3M shell + 3.7M extension), **DMG 6.1M**. Codified as reusable `packaging/macos/build-tauri-dmg.sh`
  (Tauri analogue of build-gui-dmg.sh: build sysext → build Tauri app → embed + profile → re-sign →
  notarize/staple app → dmg → notarize/staple; env SIGN_IDENTITY/APP_PROFILE auto-detected,
  NOTARY_PROFILE | AC_USERNAME+AC_PASSWORD, SKIP_NOTARIZE). **The app now carries the NE entitlement +
  the embedded extension → U1b-2b (connect/disconnect write path + OSSystemExtensionRequest activation)
  is now RUNTIME-testable** (install, approve the sysext on first launch, test connect vs a relay) rather
  than compile-only-blind. **Next chunk = U1b-2b** (unblocked for real verification).

- 2026-06-20 (U1b-2b code DONE [compile-verified] — connect/disconnect write path wired):
  `ne_spike::connect(config)` brings the tunnel up via the proven block2 pattern — the
  load→configure→save→reload→start chain runs INSIDE the loadAll completion (on the main queue;
  NETunnelProviderManager isn't Send, so nested completion blocks keep every object on main, and the
  worker command waits on a channel for the verdict): builds NETunnelProviderProtocol
  (providerBundleIdentifier=`org.getlantern.spark.tunnel`, serverAddress, providerConfiguration["config"]
  = resolved config, NSString upcast to AnyObject) → setProtocolConfiguration/setEnabled →
  saveToPreferencesWithCompletionHandler → loadFromPreferencesWithCompletionHandler →
  connection.startVPNTunnelAndReturnError. `disconnect()` = loadAll → stopVPNTunnel. spark_connect/
  spark_disconnect now call these (config via config::resolve). cargo build + clippy + fmt clean; 5
  config tests pass; no openssl. **Compile-verified ONLY** — runtime needs the signed product build
  (done) + the extension activated + a relay `config.toml` (= U1c). Assumes the extension is already
  activated (fresh-install OSSystemExtensionRequest activation = U1b-2b-ii, deferred — if connect
  errors with a "no provider"/activation failure, that's the signal to add it). Building the product
  DMG with this connect path for the live test.

- 2026-06-20 (UI fidelity pass — match getlantern/lantern's Flutter home, not spark's mockup): Adam
  wants pixel-fidelity to the REAL Lantern app. Reverse-engineered the lantern repo's Flutter UI
  (`lib/features/home/home.dart`, `vpn_switch.dart`, `vpn_status.dart`, `core/common/app_colors.dart`,
  `app_text_styles.dart`, `app_semantic_colors.dart`, `widgets/setting_tile.dart`, `divider_space.dart`)
  and rebuilt `+page.svelte` to match: **Urbanist** (the real Lantern font — NOT Sora; bundled
  `@fontsource/urbanist` 400/500/600/700, removed `@fontsource/sora`); the VPNSwitch pill (120×70, 60
  knob, 5 pad, fully rounded, brand #00BDD6 / off gray7 #616569, white knob, spinner while
  transitioning); the SettingTile card (radius 16, **teal shadow #19006162 blur 32 offset 0,4**) with
  two-line rows (icon24 + label [Urbanist 14/400, textSecondary **gray8 #3E464E**] on top; value
  [16/600, textPrimary gray9] indented 32 below; trailing dot/chevron) — VPN status (globe; "Connected"
  in **green8 #00531F**; indicator dot), Protocol (lock, AnyTLS), Routing (route, Full tunnel); AppBar
  = menu + "Spark" wordmark + hairline + soft elevation. Removed the earlier mockup's invented
  orb/heading/in-pill-text. svelte-check 0 errors; frontend builds. Preview (Urbanist embedded):
  `docs/mockups/spark-lantern-screen.html`. **Figma:** the Lantern VPN Design System is referenced in
  `app_text_styles.dart` → figma.com/design/JTguURC2QTtsi904f6mACo (node 2097-43525) — pull exact
  specs via the Figma MCP once OAuth'd. (App/DMG will carry the new UI on the next build.)

- 2026-06-20 (UI fidelity pass 2 — Figma-MCP token verification + VPNSwitch geometry FIX): Figma is
  connected; pulled the canonical design-system tokens via the MCP. The Lantern VPN Design System file
  (`JTguURC2QTtsi904f6mACo`) only exposes a Cover page + the **Text Scale** node (`2097:43525`); the
  assembled home-screen mockup lives in a separate product file we don't have a key for, so the
  **Flutter source remains ground truth**. `get_variable_defs` confirmed the type scale exactly
  (Urbanist; Label/Large 14/500, Subtitle/Medium=titleMedium 16/600, etc.) and `get_libraries`
  confirmed only the one team library. Re-read the Flutter source and **corrected the VPNSwitch
  geometry**: `vpn_switch.dart` uses `indicatorSize 60` + `spacing 10` + wrapper `padding 5` ⇒ track
  is **140×70 (not 120×70)** with knob travel **70px (not 50)**, and the connecting spinner is
  `strokeWidth 8` inside the 60 indicator with `padding 8` ⇒ **44px ring, 8px stroke** (was 50/6).
  Verified the rest already matched the shipping app: labelLarge **14/400** (`app_text_styles.dart`,
  not the design-system's 500), titleMedium 16/600, statusSuccessText green8 only when `connected`
  (else textPrimary), divider gray2, card teal shadow `rgba(0,97,98,.098)` blur 32 offset 0,4,
  toggle colors (brand blue4 / disabled gray7 / knob gray0). Card bottom gap 16→10 (`SizedBox(10.h)`).
  Wordmark stays "Spark" (Adam OK'd "spark instead of lantern for now"). svelte-check 0 errors. Preview
  regenerated with embedded Urbanist + 3 states (disconnected/connecting/connected) via
  `docs/mockups/gen-preview.mjs` → `spark-lantern-screen.html`. **Main screen is now geometry-exact to
  the Flutter home.** (App/DMG carries it on next build.)

- 2026-06-20 (U1c live finding + main-thread fix + U1b-2b-ii activation): First live test of the
  notarized DMG surfaced two things. (1) **UI froze / force-quit.** Root cause: `spark_status`/
  `spark_connect`/`spark_disconnect` were synchronous `#[tauri::command]`s → ran on the **main
  thread**, but every NE call blocks on a channel waiting for a completion delivered **on the main
  queue** → main thread deadlocks on its own callback. Fixed by marking all three
  `#[tauri::command(async)]` (off-main), so the run loop stays free to fire the completions; also
  show the toggle spinner while `busy`. (commit b8ffb6e.) (2) After that fix, connect got far enough
  to trigger the **"Spark would like to add VPN configurations"** prompt (= `saveToPreferences`
  succeeded) but **no system-extension approval prompt** and the tunnel didn't come up, no error —
  because `startVPNTunnel` returns ok (request accepted) while the provider can't launch: the
  **system extension was never activated**. Implemented **U1b-2b-ii**: added `objc2-system-extensions`
  + `dispatch2` deps; an `OSSystemExtensionRequestDelegate` via `define_class!`
  (`SparkSysExtDelegate`, ivar = result `Sender`); `ne_spike::activate_extension()` submits
  `OSSystemExtensionRequest::activationRequestForExtension_queue(id, DispatchQueue::main())`, sets the
  delegate, waits (150s, off-main) for didFinish/didFail — `replace`→Replace, `needsUserApproval`
  logged, request+delegate held alive across the approval window so a pending approval can complete.
  `connect()` now calls `activate_extension()?` before the save/start chain. cargo check + clippy +
  svelte-check: 0 errors/warnings. Verified the API against docs.rs (objc2-system-extensions 0.3.2,
  objc2 0.6, dispatch2 0.3) before writing — no guessing. **Expected first-run flow:** tap Connect →
  spinner → macOS prompts to approve the Spark extension → approve → activation completes → tunnel
  starts. **Next:** live retest (does the sysext prompt appear + approval lead to a real tunnel?).

- 2026-06-20 (U1c CONNECT PROVEN live + e2e relay groundwork): Live retest of the activation DMG
  **connected** — the system extension activated/approved and the tunnel came up (no VPN re-prompt;
  config already approved). Now standing up a relay for a real-traffic e2e. Mapped the wire protocol
  (plain `tcp_tunnel`): TCP = `[Address]` header → splice; UDP = sentinel + `[target Address]` then
  connect-mode `[u16 len][payload]` frames. **No relay server existed** (CLI is client-only), so wrote
  **`cli/src/bin/relay.rs`** (`spark-relay`) reusing the core codec (`read_header`/`Address`/
  `udp_associate_sentinel`) for wire-compat: TCP splice + connect-mode UDP relay, `--listen`. Builds +
  clippy clean (`cargo build -p spark-cli --bin relay`). Decision (Adam): run it on a **remote
  DigitalOcean droplet** (remote avoids the full-tunnel routing loop a local relay would hit). **Blocked
  on:** DO access in this session (no `doctl`, no token). Deploy plan: cross-compile to Linux (Docker is
  running) → scp single binary → run on droplet → open the port → write `config.toml` with `[transport]
  server="<droplet-ip>:9000"`, `protect_interface="en1"` (en1 = active iface, 192.168.4.25). **Next:** get
  DO token or an existing droplet+SSH, deploy, generate config, user reconnects + curls through it.

- 2026-06-21 (U1c FULLY PROVEN — real traffic e2e through a remote relay): Deployed `spark-relay`
  to a DigitalOcean droplet and ran the full end-to-end test. **doctl** installed via brew + authed
  (Lantern team, see [[digitalocean-access]]); droplet `spark-relay-test` (s-1vcpu-1gb, nyc3,
  `<droplet-ip>`) with a cloud firewall locking SSH+9000 to Adam's IP (<client-ip>) and outbound
  open. Relay **cross-compiled to x86_64-linux with `cargo zigbuild`** (cross/Docker-emulation both
  failed; zigbuild on the Mac worked — 37s, 885KB ELF), scp'd + run as a systemd unit
  (`spark-relay.service`, `--listen 0.0.0.0:9000`). Wrote `~/Library/Application Support/
  org.getlantern.spark/config.toml` = `[transport] server="<droplet-ip>:9000"
  protect_interface="en1"`. Adam reconnected Spark; **the relay log showed hundreds of live TCP+UDP
  flows** from <client-ip> to real destinations (Google/Cloudflare/Apple/Telegram on :443), QUIC
  included. This proves the whole NE Model A data path end-to-end: app → utun (sysext
  `org.getlantern.spark.tunnel`) → core netstack → plain `tcp_tunnel` client → remote relay →
  internet, both directions, TCP + UDP/DNS. **The Flutter→Tauri macOS migration (U1) is functionally
  complete and validated against a real server.** Cleanup pending: tear down the droplet+firewall
  (`doctl compute droplet delete spark-relay-test`) when done testing.

- 2026-06-21 (Shadowsocks 2022 transport SHIPPED — live-gated vs shadowsocks-rust 1.24.0; ADR 0009):
  Added **Shadowsocks 2022 (SIP022)** as a spark client `Transport` (TCP) + `UdpTransport` (UDP),
  **implemented from scratch in Rust** (no `shadowsocks-rust` dependency), wire-interoperable with
  deployed shadowsocks-rust / sing-box SS-2022 servers. Gated behind a new `shadowsocks` cargo
  feature (`= ["dep:blake3", "dep:aes"]`, OFF by default → base build untouched, stays
  rustls/ring-only + cmake-free). Code: `core/src/transport/shadowsocks/{mod,crypto,tcp,udp}.rs`;
  config `ServerSpec::Shadowsocks` + `[transport.shadowsocks]`; the bootstrap `resolve_endpoints` SNI
  slot was made optional (SS has no SNI). **TCP** carries the three `2022-blake3-*` ciphers
  (`aes-128-gcm`, `aes-256-gcm`, `chacha20-poly1305`); **UDP** carries the two AES methods only —
  `2022-blake3-chacha20-poly1305` is TCP-only in v1 (UDP needs XChaCha20-Poly1305, which `ring`
  lacks; chacha-over-UDP returns a clear `Unsupported` error, never a silent fallback; XChaCha UDP
  deferred). Crypto backend = `ring` for the AEADs (`LessSafeKey`, 12-byte nonces) + RustCrypto
  `blake3` (session-subkey KDF) + `aes` (raw block for the UDP separate-header); base64 PSK decode
  hand-rolled (no `base64` dep) — a deliberate, scoped deviation from CLAUDE.md's named `aws-lc-rs`
  fallback (`blake3`+`aes` are pure-Rust + cmake-free + feature-gated). Out of scope v1: EIH /
  multi-user, legacy SS AEAD (SIP004/007), UDP-over-TCP, obfuscation/cover, the server side.
  **Live-interop gate PASSED** against a real `shadowsocks-rust` 1.24.0 server: TCP HTTP 200 + UDP
  DNS through the tunnel, zero codec fixes on first interop. All feature combos build/clippy/test
  clean. Threat-model note: plain SS-2022 is high-entropy "look-like-nothing" traffic (FET-detectable
  by the GFW) — positioned as an interop / arm / inner-layer transport, NOT a frontline evader
  (design §10); AnyTLS/Samizdat remain the spearhead. Design: `docs/shadowsocks-design.md`
  (status flipped to Accepted); decision: **ADR 0009**.

- 2026-06-22 (Hysteria 2 transport SHIPPED — spark's first QUIC transport; live-gated vs
  apernet/hysteria v2.9.2; ADR 0010): Added **Hysteria 2** as a spark client `Transport` (TCP) +
  `UdpTransport` (UDP), **implemented from scratch in Rust** (no apernet/hysteria dependency),
  wire-interoperable with deployed `apernet/hysteria` servers. Gated behind a new `hysteria2` cargo
  feature (`= ["dep:quinn", "dep:quinn-udp", "dep:blake2", "dep:webpki-roots"]`, OFF by default →
  base build untouched; `cargo tree` confirms no quinn/blake2/webpki-roots leak). Code:
  `core/src/transport/hysteria2/{mod,obfs,tcp,udp,auth}.rs`; config `ServerSpec::Hysteria2` +
  `[transport.hysteria2]`. **QUIC stack = quinn 0.11 on rustls/ring** (NOT aws-lc-rs — avoids a 2nd
  C crypto lib next to the boring fork); **"quinn now, noq later"** — the QUIC lib sits behind the
  transport traits, so the future `noq`/multipath swap is one module (strategic seam for QUIC-
  everywhere: slipstream/unbounded-QUIC). **TCP** = one bidi stream/flow (`varint(0x401) ‖ addr ‖
  pad`, parse TCPResponse, relay via `tokio::io::join`); **UDP** = QUIC datagrams (RFC 9221) carrying
  UDPMessage `(session_id,packet_id,frag_id,frag_count,addr,payload)` + client fragmentation, one
  per-connection receive pump routing to per-session mpsc; honors `Hysteria-UDP:false`. **Auth** =
  hand-rolled minimal HTTP/3 + QPACK `POST /auth` (`Hysteria-Auth` → require status 233). **Obfs** =
  `SalamanderGeckoSocket` (a `quinn::AsyncUdpSocket`): **Salamander** (8-byte salt + BLAKE2b-256
  keystream XOR/packet) and **Gecko** (long-header packets fragmented into 2–8 padded frames, each
  Salamander-obfs'd; wraps Salamander w/ the same password) — GSO/GRO disabled for clean per-packet
  obfs; wire format byte-exact to upstream `extras/obfs/gecko*.go`. TLS = rustls/ring, TLS1.3-only,
  ALPN `h3`, verifier modes system-roots (webpki-roots, chosen over rustls-platform-verifier for a
  small portable mobile-clean bundle)/pin-sha256 (normalized, sig still verified)/insecure. **The one
  interop fix the live gate surfaced:** the quic-go server **Huffman-encodes** QPACK response values,
  so the `/auth` decoder needed an **RFC 7541 Appendix B Huffman decoder** (T7 had flagged this risk);
  with it, auth=233 + TCP+UDP worked on first interop. **Live-interop gate PASSED** against
  apernet/hysteria v2.9.2: TCP HTTP 200 + UDP DNS through the tunnel with **obfs off, Salamander, and
  Gecko** (all 2×3 = 6 green). **`SocketProtector` IS applied** to the QUIC data-plane socket (via
  the shared `protected_udp_socket`, threaded `hysteria2_transport → new → connect`) so the
  transport's own packets bypass the tunnel route on a routed full-tunnel setup — re-validated live
  after wiring it. Out of scope v1: Brutal CC, port hopping, masquerade site, server side, multipath
  (the noq swap). All feature combos build/clippy/test clean; base build stays rustls/ring-only. Design: `docs/hysteria2-design.md` (status flipped to Accepted); decision:
  **ADR 0010**.

- 2026-07-07 (Tauri-on-Android — one UI for desktop + mobile; branch `fisk/tauri-android`): promoted the
  Tauri/SvelteKit UI (`gui-tauri/`) to Android per ADR 0008 by extracting all VPN control into a new
  cross-platform plugin **`gui-tauri/tauri-plugin-spark-vpn`** behind a `TunnelControl` trait: `AppleControl`
  (cross-process NE = the **relocated `ne_spike`**, macOS untouched-behaviour, no-regression DMG gate passed),
  `AndroidControl` (in-process VpnService + JNI via `run_mobile_plugin`), `ServiceControl` (Win/Linux stub over
  `ipc`/`service`, deferred), iOS stub (deferred, reuses AppleControl). App crate is now UI-shell-only; frontend
  invokes `plugin:spark-vpn|*` uniformly (MockBackend/screens unchanged). **Android emulator end-to-end PASSED**:
  tap-connect → VPN consent (activity-result) → POST_NOTIFICATIONS → foreground VpnService → `nativeRun` →
  self-fetch pool (real server U.S.A.–Ashburn) → smart-routing rulesets fetched over h2 → Connected; disconnect
  tears down clean. Fixed a shipped split-tunnel toggle clip (border-box, PR #51). **`platforms/android/demo`
  RETIRED** (Kotlin migrated into the plugin). PR #51 (Figma UI + Routing Mode) merged to `main` first.
  Spec/plan/goal: `docs/superpowers/{specs,plans}/2026-07-06-tauri-android*.md`.
- 2026-07-20 (ADR 0013 §7 step 4 — Rust→wasm32 build-and-sign pipeline): the missing half of the
  dynamic-transport goal (every module was inline `wat!` — no wasm32 build, no signer, no on-disk
  artifact) now exists. `modules/obfs-xor` is a workspace-**excluded** `no_std` cdylib reference guest
  (mirrors `XOR_WAT`); `scripts/build-module.sh` compiles it to `wasm32-unknown-unknown` and signs it
  via the `sign-module` tool (`core/src/bin/sign-module.rs`, off-by-default `module-signer` feature,
  reusing `signing::sign_artifact` + the dev key) into the committed
  `core/tests/fixtures/wasm/obfs-xor.spkw`. A toolchain-free `cargo test`
  (`transport::wasm::tests::signed_module_fixture_verifies_and_round_trips`) loads it through the
  production `ModuleVerifier::pinned().verify` → `instantiate` path and round-trips — so `cargo test`
  and CI stay wasm32-free; only the fixture-regen script needs the target. Base build stays C-free (the
  feature + bin never build in release). Next: the BIP324 WASM module itself (step 4 proper).
- 2026-07-20 (ADR 0013 §7 step 4 — BIP324 protocol core `bip324-core`, PR1 of several): the intricate
  BIP324 crypto now lives in a new sans-io workspace crate `bip324-core` (`#![no_std]`, zero runtime
  deps) generic over a `Bip324Crypto` provider trait whose method set mirrors the wasm `env` host fns
  1:1. Implements the ellswift tagged-hash ECDH (`ecdh.rs`), the HKDF key schedule + FSChaCha20 length
  cipher + FSChaCha20Poly1305 rekeying packet cipher (`session.rs`), packet framing + a streaming
  steady-state `Session` (`packet.rs`), and the both-roles handshake state machine (`handshake.rs`,
  emit-at-connect, garbage/terminator scan, version packet, v1/wrong-network detection). Validated
  byte-exact against the official BIP324 packet-encoding vectors (`tests/vectors.rs` — shared secret,
  session id, terminators, and full packet ciphertext incl. the high-index vectors that cross the
  224-message rekey; mainnet magic) and a core-vs-core handshake round-trip (`tests/handshake.rs` —
  both roles derive a matching session id, app messages round-trip, decoys drop, 500 messages survive
  a rekey boundary fed in 7-byte fragments), via a `NativeCrypto` test provider (secp256k1/ring/chacha20
  dev-deps — the base crate is C-free). **Deviation from the plan:** the live rust-bitcoin `bip324`
  interop round-trip moved from PR1 to PR2 (the wasm module's end-to-end test is its natural home, and
  the official vectors — which that crate is itself validated against — are the canonical oracle), so
  PR1 stays hermetic + deterministic (no threads/TCP). Next: PR2 = the `modules/bip324` wasm guest
  (host-fn provider + ABI + signed `.spkw`) driven against the rust-bitcoin crate end-to-end.
- 2026-07-20 (ADR 0013 §7 step 4 — BIP324 WASM module `modules/bip324`, PR2): the sans-io `bip324-core`
  is now wrapped as an actual signed WASM dynamic transport. `modules/bip324` is a workspace-excluded
  wasm32 cdylib (path-deps `bip324-core`; first heap-using guest → `dlmalloc` `#[global_allocator]`)
  whose `HostCrypto` provider is a 1:1 shim of the `env` host fns and whose exports are the module ABI:
  `init` (config `[role][magic:4][garbage]`), `handshake_step` (`[status][outbound]` framing), and
  `transform_out`/`transform_in` (steady-state packets; buffering `transform_in` is fine — `TransformStream`
  loops on empty output). `scripts/build-module.sh` now builds + signs BOTH modules; the committed
  `core/tests/fixtures/wasm/bip324.spkw` (~22 KB) is validated end-to-end by
  `transport::wasm::tests::bip324_module_handshakes_and_round_trips` (`#[cfg(feature = "bip324")]`):
  two module instances (initiator + responder) complete the handshake through the real `TransformModule`
  runtime + host-fn provider and round-trip app bytes both ways, incl. a 300-message burst past the 224
  rekey fed in 5-byte fragments. No host changes needed. **First transport expressed purely as a signed
  module + config — the north star in miniature.** Next: PR3 wires `run_handshake` into a dial path
  (today wired nowhere) + the transport/config surface; PR4 = bitcoind + side-door MAC; the live
  rust-bitcoin `bip324` interop lands with that real end-to-end.
- 2026-07-20 (ADR 0013 §7 step 4 — BIP324 dial-path wiring, PR3): the last framework gap closed —
  `Transform::run_handshake` (implemented since step 3) was **wired into no dial path**, so a
  handshake-based transport couldn't connect. Now `WasmTransport::dial_target` (client/initiator) and
  `WasmServer::accept` (server/responder) each run `run_handshake` on the raw connection before the
  steady-state `TransformStream`, gated on a new protocol-blind `Transform::drives_handshake()` (run iff
  the module exports `handshake_step`; obfs-xor and other transform-only modules are unaffected —
  backward-compat confirmed). `WasmServer` gained a `config` field (it called `instantiate()`); NO config
  schema change (`init_config` = `role ++ magic ++ garbage` reuses `ServerSpec::Wasm`/`WasmConfig`).
  Validated by `transport::wasm::transport::tests::bip324_tunnel_round_trips_over_real_tcp` (`#[cfg
  bip324]`): a real-TCP loopback where client + server both run the handshake and a byte round-trips
  through the BIP324 tunnel to an echo. **A latent `bip324-core` bug surfaced + fixed:** over a real
  stream the initiator's final handshake message coalesces with its first steady-state packet, so the
  responder's `run_handshake` reads past the handshake; those leftover bytes were being *dropped* when
  the `Handshake` became a `Session` (PR1/PR2 tests shuttled exact outputs, never over-reading). Fix:
  `Session::new` seeds `recv_buf` with the handshake leftover (`core::mem::take(&mut self.buf)`); guarded
  by `bip324-core`'s `handshake_carries_coalesced_steady_state_bytes` test. Fixture regenerated.
  **Follow-up (same PR, e266f16): the coalescing had a *second* home — the host.** The core seed buffers
  the leftover, but `TransformStream::poll_read` only fed *newly-read wire bytes* to `transform_in`, so a
  fully-buffered frame with no trailing wire bytes was stranded and the reader blocked forever on a wire
  read. Timing-dependent, so the tunnel test **passed in isolation but hung 120s** as the last test under
  the full `--workspace --all-features` suite (CI-deterministic across all 3 OSes; single-feature local
  runs missed it). **Boundary contract, now explicit:** after a handshake the host must drain the module
  before its first wire read — a one-shot `handshake_drain_pending` in `poll_read` (armed only when
  `drives_handshake()`) calls `transform_in(&[])` first. Guarded by the deterministic
  `poll_read_drains_steady_state_bytes_the_handshake_over_read` (forces the over-read; fails `UnexpectedEof`
  without the drain). Also ran `run_handshake` on the **UDP dial path** (`dial_udp_addr`): the server runs
  the responder handshake in `accept` for every connection (the TCP-tunnel/UDP-associate split comes later,
  from the header), so a handshake module would desync if the UDP client skipped it. 665 `--workspace
  --all-features` tests green. Next: PR4 = bitcoind on :8333 + the keyed-garbage side-door MAC + live
  rust-bitcoin interop.

## Milestone checklist
- [x] U0 (Tauri shell + Lantern UI; macOS .app 8.3M / .dmg 2.9M; no openssl; build+clippy+fmt green)
- [x] U1 (NE Model A — **DONE + PROVEN e2e 2026-06-21**: U1a/U1b/U1b-1/U1b-2a/U1b-4 + U1b-2b connect/disconnect + U1b-2b-ii OSSystemExtensionRequest activation; live test through a remote DO relay showed real TCP+UDP traffic egressing via the tunnel. Notarized DMG carries the Lantern-matched UI.)
- [ ] U2
- [ ] U3
- [ ] U4 (UI: Flutter→Tauri migration — ADR 0008, PLAN.md §4)
- [x] M0  [x] M1 (code+tests green; **live ICMP gate PASSED on macOS 2026-06-15**)
  [x] M2 (bridge+forwarder; **live curl gate PASSED on macOS 2026-06-15** via --protect-interface)
  [x] M3a (address codec + header)  [x] M3b (relay stream + client — integration-tested)
  [~] M4 (Transport trait + wiring + CLI flag green; live curl-through-server gate pending root)
  [x] M5 (framing + NAT table + orchestration + netstack UDP; **live DNS gate PASSED on macOS 2026-06-15** — dig @9.9.9.9 resolved through the tunnel)
  [~] M6 (config + redaction + CLI green+tested; live SIGINT/device-teardown gate pending root)
- [x] M7 (ipc + service + daemon/client; **through-the-service gate PASSED on macOS 2026-06-15** —
  client drove the daemon, traffic forwarded end-to-end. All refinements landed: kill-switch
  signaling (`FellOpenToDirect`/`direct_fallback`/`fail_closed`), peer supplementary-group
  resolution, push backpressure (`Push::Dropped`), and opt-in active route-management
  (`[routing] manage`, split-default, `Teardown` fail-open/closed). Only the live route gate
  under root remains.)
- [~] M8 (packaging: cross-build checks + systemd/launchd units + size-budget done; **Windows
  named-pipe transport done — whole workspace cross-builds for Windows**; **CI + tag-driven
  release workflows + deb/Homebrew/Windows-zip packaging defs done**; **Windows SCM service handler
  done — `spark-service` is dual-mode (service under SCM / foreground)**; **MSI (WiX) done —
  installs binaries + registers the service**. Packaging feature-complete; pending only live
  verifications: a release run [push a tag], Homebrew-tap push, live Windows run, Event-Log logging)
- [x] M9 (Android — **DONE; browse gate PASSED on the emulator 2026-06-16**: core cross-compiles
  for `aarch64-linux-android` + `Tun::from_fd`; `libspark_android.so` (cdylib) + `core::android`;
  `platforms/android/demo` `SparkVpnService` app — `adb shell` HTTP→204 through tun0→spark, VPN
  CONNECTED+VALIDATED, core forwarding in logcat)
- [~] M10 (Apple — **s1–s2 done: architecture decided (fd-trick + packet-object fallback, C ABI,
  unified provider); `core::fd_tunnel` shared with Android; `platforms/apple` staticlib +
  `SparkCore.xcframework`; unified Swift `PacketTunnelProvider` + `FdResolver` compile-verified
  (`swift build`).** Live gate BLOCKED on provisioning — needs a team-`ACZRKC3LQ9` profile for the
  NE entitlement [human step]; macOS app-extension path + iOS device gate pending.)
  [ ] M11 (transports)

---

**2026-07-01 — DNS-tunnel transport: M0 (spec) DONE.** New M11 transport filling the `DNSTT`
escalation tier. A **clean-slate** DNS-tunnel protocol inspired by MasterDnsVPN's architecture
(bespoke low-overhead ARQ, resolver load-balancing with duplication + per-stream sticky failover,
per-resolver MTU probing, LZ4 compression) but **NOT** wire-compatible with it / dnstt / Slipstream —
both the client and a Rust server are ours. Rejected Slipstream's QUIC-multipath: its only mature
stack (picoquic) is C+OpenSSL, violating the pure-Rust/no-C/<3 MB rules. Design:
`docs/dns-tunnel-design.md`; plan: `docs/dns-tunnel-plan.md`; **ADR 0011**. Fixes over MasterDnsVPN:
8-byte random ConnectionID (theirs was 1-byte → 255-session cap + path-coupled; wide ID = the
TurboTunnel ClientID that lets a session reassemble from frames via any resolver), **AEAD-only** via
`ring` (ChaCha20-Poly1305 default / AES-256-GCM; random 96-bit nonce per DNS message; HKDF-SHA256
per-session key schedule), dropped XOR / MD5-KDF / AES-192 / unauth-ChaCha20. Pure-Rust: `ring` +
`lz4_flex` (not C `zstd`), hand-rolled DNS codec, behind a `dns-tunnel` cargo feature (base build
unaffected). Crates: `dns-tunnel-core` (shared, no-I/O) + `dns-tunnel-server` (bin) + client
`core/src/transport/dns_tunnel/`. **NEXT: M1** — `dns-tunnel-core` codec (frame/AEAD/DNS/base32/EDNS0,
golden vectors + `cargo fuzz`; no network). Ladder M1→M5 in the plan. Open items: server crate home
(spark workspace vs lantern-box), `dns-tunnel-core`→`flint` migration, protocol codename.

**2026-07-01 — DNS-tunnel M1 (dns-tunnel-core codec) DONE.** New pure/no-I/O workspace crate
`dns-tunnel-core` (33 tests, clippy -D warnings / fmt clean, feature-independent — base build
untouched). Modules: `crypto` (base64 PSK decode; HKDF-SHA256 per-session schedule → up/down/
handshake keys + commitment; `ring` AEAD ChaCha20-Poly1305/AES-256-GCM with random 96-bit nonce/msg;
SystemRandom helpers — grounded in the samizdat/shadowsocks in-repo `ring` idioms), `frame` (inner
version/kind/flags header + optional stream_id/seq/fragment/comp_algo + payload; QUIC-style long/short
wire form — short=FORM|conn_id|nonce|AEAD, long/SYN adds cleartext salt; conn_id bound via the
HKDF key's info, not AAD, so no header-check byte), `dns` (hand-rolled TXT query/answer, base32 QNAME
packing [case-insensitive decode for 0x20], EDNS0 OPT, answer via 0xC00C compression pointer;
bounds-checked panic-free Reader), `compress` (LZ4 via lz4_flex, compress-if-smaller + anti-bomb size
cap), `mtu` (QNAME/base32 capacity math; a cross-check test proves the bound == dns::build_query's
exact QNAME budget). `cargo fuzz` deferred → in-suite randomized no-panic guards on both parsers cover
the contract for now. Design doc §2.2 synced to the implemented wire form. **NEXT: M2** — the ARQ core
(reliable per-stream state machine: seq/ack/NACK gap recovery, RFC-6298 RTO, windowed flow control,
lifecycle; tested on a simulated lossy/dup/reorder channel). The dominant lift.

**2026-07-01 — DNS-tunnel M2a (ARQ reliable data path) DONE.** `dns-tunnel-core/src/arq.rs`: a
sans-I/O `Stream` driven by a virtual ms clock — write/segment/transmit within a send window,
in-order delivery + reorder buffer, cumulative ACK, adaptive RFC-6298 RTO retransmit (exponential
backoff, Karn's algorithm), per-segment seq with RFC-1982 serial arithmetic, no congestion control
by design. Deterministic sim-channel harness (drop/dup/reorder/latency, seeded xorshift). 5 ARQ
tests (perfect delivery; recovery over 30% bidirectional loss; delivery under heavy reorder+dup;
send-window bound; RTO adapts to RTT). 38 crate tests total; clippy/fmt clean. (Also fixed a masked
fmt-check shell bug → reformatted the M1 modules; use `if cargo fmt -p X -- --check; then` — do NOT
pipe to `tail && echo`, which hides the exit code.) **NEXT: M2b** — NACK fast-retransmit (receiver
emits Nack(first-missing) on a gap; sender fast-retransmits without RTO backoff), then **M2c** —
FIN/RST lifecycle (FIN as a phantom seq, acked in order; RST best-effort) + a property-test matrix.
Then M3 (single-resolver E2E + minimal server).

**2026-07-01 — DNS-tunnel M2 (ARQ) COMPLETE.** Added to `arq.rs`: NACK fast-retransmit (receiver
Nack(first-missing) on a gap; sender fast-retransmits ahead of RTO, no backoff) and the FIN/RST
lifecycle (FIN = phantom seq acked in order; one-way close → FinSent, symmetric → Closed; RST
best-effort + propagates; a Closed stream still ACKs the peer's FIN retransmits — TIME_WAIT, fixed a
real last-ACK hang the graceful-close test caught). **`dns-tunnel-core` is now feature-complete: 43
tests (crypto/frame/dns/compress/mtu/arq), clippy -D warnings / fmt clean, pure no-I/O.** **NEXT:
M3 — single-resolver end-to-end.** Build (a) a minimal `dns-tunnel-server` bin crate (bind UDP, parse
tunnel TXT query via `dns::parse_query`, session table keyed by ConnectionID, per-session ARQ, single
TCP egress, answer via `dns::build_answer`), and (b) the client `core/src/transport/dns_tunnel/`
(`DnsTunnelTransport: Transport`, feature `dns-tunnel`, config `DnsTunnelConfig`, one resolver or
`authoritative` direct, session handshake, ARQ pump over UDP DNS, reuse `protected_udp_socket`).
Gate: 10 MiB loopback integrity in authoritative mode. Then M4 (balancer/multipath) + M5 (recursive
+ spark wiring). NOTE: M5's recursive gate + `sudo` TUN gate need real infra/root — flag as
human/infra steps when reached; the loopback E2E (M3) and multipath sim gates are self-contained.

**2026-07-01 — DNS-tunnel M3a (sans-I/O session layer) DONE.** `dns-tunnel-core/src/session.rs`
composes crypto+frame+dns+arq into a full session (still no-I/O): `ClientSession` + `Server`
(per-ConnectionID). Handshake = long-form Syn (cleartext salt + target payload) under the handshake
key → server derives keys, replies SynAck. Data = the poll model (query carries one uplink frame or a
KeepAlive; answer carries one downlink frame). **Verified E2E deterministically: full echo over a
perfect net AND a 20%-loss/30%-reorder net, plus a manual handshake/uplink/downlink step test and
garbage/wrong-zone rejection.** 47 crate tests, clippy/fmt clean. Two real bugs found + fixed en
route: (1) ACK starved downlink data (one frame per answer) → reordered ARQ `poll_transmit` to defer
standalone ACKs behind data/FIN; (2) the session didn't size ARQ `max_segment` from the MTU math, so
128-byte segments overflowed the QNAME and `build_query` silently failed — now sized via
`mtu::max_uplink_payload`/`max_downlink_payload`. **NEXT: M3b** — the tokio I/O wrappers (thin, since
the session is sans-I/O): a `dns-tunnel-server` bin crate (bind UDP:53/loopback, `Server::on_query`
loop, TCP egress pumping `take_from_client`/`deliver_to_client`) and the client
`core/src/transport/dns_tunnel/` (`DnsTunnelTransport: Transport` behind the `dns-tunnel` feature,
config wiring, a `protected_udp_socket` send/recv + `poll_query`/`on_answer` pump). Gate: a real
loopback UDP 10 MiB integrity test in authoritative mode. Then M4 (balancer/multipath) + M5.

**2026-07-01 — DNS-tunnel M3b-1 (spark config surface) DONE.** `core/src/config/mod.rs`:
`DnsTunnelConfig` (zone, psk, resolvers, optional `authoritative` endpoint, cipher, compression) +
`DnsTunnelCipher` (chacha20-poly1305 default / aes-256-gcm) + `DnsTunnelCompression` (off / lz4), and
`TransportConfig.dns_tunnel` + its Default. 2 round-trip tests; clippy/fmt clean; base build untouched.
Deliberately did NOT add `ServerSpec::DnsTunnel` yet — it forces exhaustive from_config/build_one
match arms that need the transport impl, and an error arm would be a stub. **NEXT: M3b-2** — the
transport impl, self-contained behind the `dns-tunnel` feature so it tests without from_config wiring:
(1) `core/Cargo.toml`: `dns-tunnel = ["dep:dns-tunnel-core"]` + optional path dep on the workspace
crate; (2) `#[cfg(feature="dns-tunnel")] pub mod dns_tunnel;` in `transport/mod.rs`;
(3) `core/src/transport/dns_tunnel/mod.rs`: `DnsTunnelTransport: Transport` — `dial(target)` builds a
`ClientSession`, binds `protected_udp_socket` connected to `authoritative` (M3 = authoritative mode),
spawns an async pump (`tokio::select!` over UDP recv / a `tokio::io::duplex` app side / a
keepalive+RTO tick driving `poll_query`/`on_answer`), returns the duplex half as `BoxedStream`;
(4) a `#[tokio::test]` loopback gate (in-test UDP server task using `session::Server` + echo egress;
client `dial`; 10 MiB round-trip). **Verify the `Transport` trait + `BoxedStream`/`Address` types and
`protected_udp_socket` signature in `transport/mod.rs` first — don't guess.** from_config/build_one/
`ServerSpec` + `bootstrap::resolve_endpoints` wiring → **M5**; the standalone `dns-tunnel-server` bin
(production TCP egress + session store) → **M4**.

**2026-07-01 — DNS-tunnel M3 COMPLETE (single-resolver E2E over real UDP).** M3b-2:
`core/src/transport/dns_tunnel/mod.rs` behind the new `dns-tunnel` feature — `DnsTunnelTransport`
impls `Transport`; `dial(target)` builds a `ClientSession`, opens a `protected_udp_socket` to the
authoritative server (authoritative mode), spawns an async pump (drain-ready-answers-via-`try_recv` +
flush-queries + deliver-downlink + keepalive/RTO tick), and returns a `PumpStream` that aborts the
pump `JoinHandle` on drop. Target encoded as SOCKS5 addr bytes in the SYN. Added `Server::session_ids()`
for egress enumeration. **Gate PASSED: a real loopback-UDP round-trip test moves 512 KiB bidirectionally
through the full stack (handshake→base32 DNS codec→ARQ→poll model) in ~0.2s.** Base build clean
(feature off), clippy/fmt clean (feature on). **NEXT: M4 — resolver balancer + multipath + the full
server.** Two parts: (a) client `core/src/transport/dns_tunnel/balancer.rs` — a resolver pool
(config `resolvers`, IP/CIDR expansion), per-resolver RTT/loss telemetry, selection strategy, packet
duplication across resolvers, per-stream sticky failover, health auto-disable/reactivate; the pump
sends each query to a chosen resolver instead of the single authoritative addr, and the server keys by
ConnectionID so answers from any resolver reassemble (already true). (b) the standalone
`dns-tunnel-server` bin crate (real TCP egress: dial the SYN target, pump the session stream ↔ TCP;
session store with idle expiry). Gates: multipath aggregation (throughput scales with pool) + mid-
session resolver-failover — both self-contained (sim or multi-loopback-resolver). Then M5 (recursive
NS-delegation gate + `from_config`/`ServerSpec` wiring + size/log-hygiene audit; the live recursive +
`sudo` TUN gates are the infra/human step).

**2026-07-01 — DNS-tunnel M4a+M4b DONE (resolver aggregation + failover, live over UDP).**
`core/src/transport/dns_tunnel/balancer.rs` (M4a): `ResolverPool` — parse/expand (IP/IP:port/IPv4
CIDR/CIDR:port/[v6], deduped, :53 default, bounded), per-resolver smoothed RTT + half-life-decayed
loss, `pick()` (sticky + healthiest others for duplication), `on_success`/`on_loss`, auto-disable +
reactivate, per-stream sticky failover. M4b: the pump now runs **resolver mode** — one unconnected
`protected_udp_socket`, each query `send_to` the picked resolver(s), `recv_from` attributes RTT to the
answerer, unanswered queries age out into per-resolver loss; authoritative mode = a one-entry pool.
**Headline capability proven end-to-end over real UDP:** `aggregation_survives_a_dead_resolver_via_
duplication` (dup=2, {live,dead} → completes) and `fails_over_when_the_sticky_resolver_is_dead`
({dead-first,live}, dup=1 → disables dead sticky, fails over, completes). 10 dns_tunnel tests
(7 balancer + 3 live-UDP); base build clean (feature off); clippy/fmt clean. **NEXT: M4c** — the
standalone `dns-tunnel-server` bin crate: a tokio wrapper around `session::Server` (bind UDP, on_query
loop) with **real TCP egress** — on a new session decode the SYN's SOCKS5 target, `TcpStream::connect`
it, and pump `take_from_client`→TCP-write / TCP-read→`deliver_to_client`; bounded session store with
idle expiry. Then **M5**: wire the transport into `from_config`/`build_one`/`ServerSpec::DnsTunnel` +
`bootstrap::resolve_endpoints` ("wire into transport selection"), decode the config PSK/cipher into the
transport, feature-gated release size delta, log-hygiene audit. Live recursive-NS + `sudo` TUN gates
remain the infra/human step.

**2026-07-01 — DNS-tunnel M4c DONE → M4 COMPLETE.** New workspace crate `dns-tunnel-server`: a tokio
wrapper around `session::Server` — `serve()` binds UDP, runs the on_query loop, and on each new
session decodes the SYN's SOCKS5 target, `TcpStream::connect`s it, and bridges the session stream ↔ TCP
via per-session channels (reader task TCP→downlink; writer uplink→TCP); idle sessions swept
(`session::Server` gained `last_seen`/`sweep_idle`/`remove_session`). clap `main.rs`
(--zone/--psk/--bind/--idle-secs), log-hygiene clean. **Gate PASSED: `tests/e2e.rs` drives a real
ClientSession over real UDP through `serve()` to a real TCP echo target (4 KiB round-trip through
actual TCP egress).** clippy/fmt clean; spark base build unaffected. **M4 done: aggregation +
multipath + failover + full server, all proven over real UDP/TCP.** **NEXT: M5 (final) — wire into
transport selection.** (a) config: add `ServerSpec::DnsTunnel(DnsTunnelConfig)` + the exhaustive match
arms in `core/src/config/mod.rs` (`first_unresolved_host`, `spec_kind` if any) and
`core/src/transport/mod.rs` (`build_one`); (b) a `dns_tunnel_transport(cfg, protector)` builder that
decodes the PSK (`crypto::decode_psk`), maps `DnsTunnelCipher`→`session::Cipher`, builds the resolver
list (config `resolvers`, or `[authoritative]`) + `DnsTunnelTransport::new`, gated with a
`#[cfg(not(feature="dns-tunnel"))]` hard-error stub (mirror shadowsocks); (c) `from_config` precedence
(single-transport `transport.dns_tunnel`) + `bootstrap::resolve_endpoints` no-SNI arm for
`authoritative`; (d) `cargo build --release --features dns-tunnel` size delta report + a log-hygiene
audit. The literal `<3 MB` in the docs is stale — the repo relaxed the base budget to ~10 MB
(opt-level=3); the real requirement is feature-gated-so-base-build-unaffected (verify via `cargo tree`
that base pulls no dns-tunnel deps). Live recursive-NS + `sudo` TUN gates = infra/human step.

**2026-07-01 — DNS-tunnel M5 DONE → transport COMPLETE (M0–M5).** Wired into transport selection:
`ServerSpec::DnsTunnel` (tag `dns-tunnel`) + `first_unresolved_host`/`build_one`/`spec_kind`/
`spec_label` arms; `dns_tunnel_transport()` builder (decode PSK, map cipher, resolvers-or-authoritative)
+ `#[cfg(not(feature))]` hard-error stub; `from_config` single-transport precedence
(`transport.dns_tunnel`); `bootstrap::resolve_endpoints` no-SNI arms; `DnsTunnelTransport` also impls
`UdpTransport` (TCP-only → dial_udp errors). **Audit green:** base build pulls ZERO dns-tunnel deps
(`cargo tree`) → base binary byte-identical; feature adds only `dns-tunnel-core`+`lz4_flex`; log
hygiene clean (only a content-free "listening" line anywhere); `dns-tunnel-server` release binary =
**1.22 MB**. Tests: dns-tunnel pool-entry parse + gated builder accept/reject; 15 dns_tunnel tests;
base + feature builds/clippy/fmt clean. Design doc + ADR 0011 flipped to Implemented/Accepted.
**The transport is complete and green end-to-end** across both crates (`dns-tunnel-core` +
`dns-tunnel-server`) and spark `core`. **Recursive mode is code-complete** (the resolver-pool path IS
recursive: the client sends to resolvers that forward to the NS-delegated authoritative zone; the
loopback/failover tests exercise the identical send-to-resolver mechanism). **Remaining = infra/human
only:** (1) deploy `dns-tunnel-server` behind an NS-delegated zone and run the client through a real
public resolver; (2) the `sudo spark run` full-TUN gate. Branch `fisk/spark-dns-tunnel` (not pushed —
push/PR is a human decision).
  Deferred sub-features (documented, not stubbed — all noted in `dns-tunnel-design.md` §1/§16):
  (1) **dynamic per-resolver MTU binary-search probing** — v1 uses a correct *conservative static* MTU
  from `mtu.rs` (sizes segments to the QNAME/TXT capacity for the zone); over-the-wire MTU_UP/DOWN
  probing to discover larger per-resolver limits is a throughput optimization (add MtuProbe frame
  kinds + a probe phase). (2) **cookie/replay handshake hardening** — v1 is PSK+HKDF per-session salt;
  the SYN cookie / anti-replay window is a future add. (3) **UDP-over-tunnel** (`UdpTransport` errors —
  out of scope v1). (4) **payload compression** wired at the config level (lz4_flex) but not yet
  applied in the session pump (off by default). (5) formal `cargo fuzz` targets → currently in-suite
  randomized no-panic guards. None affect the headline capability or correctness.

**2026-07-02 — DNS-tunnel: dynamic MTU probing DONE (deferred item #1 resolved).** Added the
over-the-wire probe loop that discovers a larger downlink MTU than the conservative static bound.
New frame kinds `MtuProbe`/`MtuProbeResp`/`SetMtu` + `arq::Stream::set_max_segment`; session:
`build_mtu_probe`/`build_set_mtu`/`on_answer → AnswerOutcome::ProbeResp`, and the server pads a
`MtuProbeResp` to the requested size (an oversized answer fails to return, so the client learns the
path limit) and applies `SetMtu` to its downlink segment. Client pump (`core/src/transport/
dns_tunnel/mod.rs`): after the handshake it fires one round of probes across `PROBE_CANDIDATES`
(400…1200 B), collects the largest that survives `PROBE_WINDOW_MS`, then `SetMtu`s it. Probe queries
are deliberately **not** tracked in the RTT/loss `pending` map — an expected over-MTU failure must not
demote a healthy resolver. Test `probe_raises_downlink_mtu` proves the server downlink reaches the
largest surviving candidate (1200) end-to-end over loopback. 16 dns_tunnel tests; clippy/fmt clean.
Commits `adb62dd`/`95ffbfd`/`7c2aa02` (MTU probing 1–3/3).

**2026-07-02 — DNS-tunnel: multi-stream multiplexing DONE.** One crypto session (one ConnectionID +
HKDF key schedule) now carries **many** independent ARQ streams keyed by StreamID — the DNS-tunnel
analogue of smux/HTTP-2, replacing the M3 "one session = one stream" model. **Core** (`session.rs`):
`ClientSession`/`Server` are multiplexers over a `BTreeMap<u16, …>` of streams; stream 1 still opens
via the handshake SYN (fast path, 1 RTT to first byte), streams ≥2 open with a cheap short-form SYN
(StreamID + target under the session uplink key) retried on a per-stream timer until a per-stream
SynAck; `handle_syn` is idempotent so a retransmitted session SYN can't wipe live streams; uplink
poll + server downlink both round-robin across streams; `SetMtu` applies session-wide; frames route by
StreamID. Single-stream facade (`write`/`read`/`close`) kept for compile-compat (operates on the
primary stream). `dns-tunnel-server` does per-`(ConnId,StreamID)` TCP egress (target EOF FINs just
that stream). **Transport** (`mod.rs`): all dials share **one** session/pump/UDP-socket/pool — first
dial establishes (target = stream 1), later dials hand the pump a `Ctl::Open` for a new stream; a
per-stream reader task fans uplink into the pump tagged with its StreamID, the pump fans downlink back
per stream + handles per-stream half-close/reap; idle lifecycle tears the session down after
`IDLE_GRACE_MS` (3 s) with no streams so an idle tunnel stops querying (next dial rebuilds), draining
any raced-in `Open` so an accepted dial is never dropped. Dropped the per-dial `PumpStream` wrapper (a
`DuplexStream` boxes directly as `BoxedStream`). New tests: `two_streams_multiplex_independently`
(core: two streams to different targets echo without crossing) + `two_dials_share_one_session`
(transport: two concurrent dials multiplex over one ConnectionID). 51 core + 1 server-e2e + 17
dns_tunnel tests; base + feature builds/clippy/fmt clean. Commits `e493595` (core) + `a7927a0`
(transport). Branch `fisk/spark-dns-tunnel` (not pushed). **Remaining deferred (unchanged):**
cookie/replay handshake hardening, UDP-over-tunnel, session-pump payload compression, formal
`cargo fuzz`; plus optional multi-session pooling (v1 shares a single session across all dials).

**2026-07-02 — DNS-tunnel: LIVE on DigitalOcean, recursive path proven, real throughput measured.**
Deployed `dns-tunnel-server` (static musl binary via `cargo zigbuild`, 1.7 MB) to a DO droplet
(`<droplet-name>`, nyc3, <old-droplet-ip>), systemd `spark-dns.service` on UDP:5300 with a
`:53→:5300` DNAT. Delegated **`<initial-tunnel-zone>`** on Cloudflare (NS + glue A → the droplet). Added a
server hardening (`dns::build_nodata` + `Server::on_query` rework, commit `ab2f31e`): the server now
answers QNAME-min probes (apex SOA/NS/A) with a benign NOERROR/NODATA instead of dropping — without it
1.1.1.1/8.8.8.8 SERVFAIL before forwarding tunnel queries. Verified end-to-end: authoritative fetch
(HTTP 301 relayed from 1.1.1.1:80) AND **recursive** fetch through the public resolver pool (Cloudflare
/Quad9/OpenDNS) via the getiantem.org delegation — real HTTP carried over DNS on the full
client→resolver→our-server→egress path. **Throughput (empirical):** loopback CPU ceiling ~560–690
Mbit/s; **~10 Mbit/s direct-to-server over a real 50 ms WAN** (matches the sim); **~0.1 Mbit/s
recursive via major public resolvers** — isolated to per-resolver rate-limiting of the
random-subdomain pattern (Cloudflare-only was as slow as the mixed pool; direct `:53`/DNAT was fast),
i.e. a resolver-side anti-abuse limit, not our stack. Confirms recursive = the reachability-under-
shutdown tier; throughput wants large resolver pools / non-throttling paths (the MasterDnsVPN approach).
Live-fetch harness generalized to a comma-separated resolver list (authoritative or recursive). Assets
to tear down when done: DO droplet `<old-droplet-id>`, DO SSH key (`<old-ssh-key-id>`), the two
Cloudflare records under getiantem.org (`t` NS + `ns-spark` A). PSK in the session scratchpad. New
build tooling installed locally: `zig` + `cargo-zigbuild` + the `x86_64-unknown-linux-musl` target.

**2026-07-02 — DNS-tunnel: recursive-throughput optimization — two negative results (both reverted).**
Investigated raising recursive throughput past the ~single-resolver ceiling. Measured against the live
`<initial-tunnel-zone>` deployment across a 23-IP public-resolver pool (14 operators). **Findings:**
(1) *Pool breadth helps sticky via selection* — 8→23 resolvers let the health-ranker find a better
single resolver (~15→78 KB/s), because operators throttle the DNS-tunnel pattern very unequally.
(2) **Per-query spread across the pool: 15× WORSE** (5 vs 78 KB/s). A single ordered ARQ stream sprayed
over 12–400 ms resolvers reorders badly + stalls on the slowest; and at single-stream volume you're
RTT-bound (~75 KB/s), not rate-limited, so spreading only adds head-of-line cost. (3) **Per-stream
resolver affinity (pin each mux stream to a distinct resolver): also WORSE in aggregate** — 8 conns
= 51 KB/s vs 1 conn = 73. Affinity pins but doesn't *chase* a good resolver (only reassigns on hard
disable), so streams pinned to throttlers crawl and drag the aggregate, and routing stream-1 through
affinity weakened the common-case single-conn failover. **Root cause / conclusion:** public resolvers
are heterogeneous *adversarial* DNS-tunnel throttlers; beating the per-good-resolver ~75 KB/s ceiling
needs throughput-aware selection (measure goodput, use only the good few, flee throttlers) which
converges back toward "few best," not "spread across many" — high effort, uncertain payoff against an
adversary. **Both `spread` and `affinity` experiments reverted; default stays sticky-to-best +
broad-pool selection** (empirically best for the common single connection). Recursive remains the
reachability-under-shutdown tier (~0.1 Mbit/s, throttle-bound); real throughput (~10 Mbit/s) lives on
non-throttling paths (our own server, or resolvers that don't throttle). No code shipped from this
investigation (tree unchanged); findings recorded so the dead ends aren't re-tried.

**2026-07-02 — DNS-tunnel: shutdown-subset resilience (the Iran case) — verified + `duplication`
exposed.** Unlike the throughput thread (uncensored vantage, all resolvers work, enemy = throttling),
a national shutdown means *most resolvers are blocked/hijacked and only a subset — often the mandated
local resolver — forwards anything*. This is the design's home turf, and here sticky-to-best + failover
is **correct** (the spread/affinity negatives don't apply). Verified live against the DO deployment
with a mostly-dead pool (3 RFC5737 TEST-NET dead IPs + 2 live resolvers): the tunnel disabled the dead
ones and carried real traffic (HTTP 301). **Key finding — duplication is the shutdown lever:** with
duplication=1 the working subset is discovered *serially* (time out through each dead resolver), 27 s to
first byte; raising duplication probes several per query → parallel discovery: **27 s (dup 1) → 4.6 s
(dup 3) → 0.30 s (dup 5)**. Shipped: `DnsTunnelConfig.duplication` (was hardcoded to 1 in the builder;
now configurable, default 1, set ~3–5 for shutdown profiles) + a `DNS_TUNNEL_DUP` live-harness knob
(commit `e3d6bc3`). **Remaining Iran gaps (not built):** (1) **auto-include the system/DHCP/local
resolver(s)** in the pool — during a total shutdown the mandated local resolver is often the ONLY thing
that forwards DNS (MasterDnsVPN's "even if forced onto the government resolver" thesis); the pool is
currently a static config list. Biggest practical gap. (2) **innocuous, unattributable tunnel zone** —
`getiantem.org` is a known Lantern domain a censor's resolver may refuse to forward; real deployment
needs a clean domain (our test zone is fine only from an uncensored vantage). (3) fundamental limit: the
working resolver must retain *some* upstream reach to the authoritative server IP. Throughput in this
regime is ~one-resolver's-worth (reachability, not streaming) — as intended for the last-resort tier.

**2026-07-02 — DNS-tunnel: system-resolver auto-include, unattributable zone, Linode prod path +
dnstt-infra reuse.** (1) **`system_resolvers()`** — the builder auto-includes the OS resolver(s)
(`/etc/resolv.conf` on Unix) in the recursive pool, gated by `DnsTunnelConfig.use_system_resolvers`
(default true; the shutdown lifeline). Commit `6a50e00`. (2) **Switched the live tunnel zone to an
unattributable domain** `<tunnel-zone>` (Cloudflare NS + glue), replacing known-Lantern
`<initial-tunnel-zone>` (a censor's resolver would filter it); validated recursive (1.1.1.1/9.9.9.9/8.8.8.8
NOERROR, HTTP 301 in 0.29 s at dup=3). getiantem.org records can be removed. (3) **Assessed reuse of
Lantern's dnstt infra** (`getlantern/dnstt`; lantern-cloud `ans/bootstrap-dnstt.yaml` → `dnstts_oci`
on OCI; zone `t.iantem.io` via TF `dns.yaml`; client config via `flashlight/genconfig` →
config-server; escalation slot in `kindling/dnstt`+radiance). spark's dns-tunnel is a **drop-in
modernization of the dnstt tier** (same `:5300`+zone+systemd+`:53`-DNAT shape). Reuse the *plumbing*
(provisioning, config distribution, escalation slot); keep *separate* binary/IP/zone (protocol
incompatibility) + *unattributable* domains. **Production targets Linode, not OCI** (Lantern already
uses Linode; `linode-cli`+`LINODE_TOKEN` on hand). Committed a reusable deploy kit under `deploy/`
(commit `37861e7`): `provision-linode.sh` + Ansible `bootstrap-spark-dns.yaml` + systemd template +
inventory + README, adapted from the dnstt playbook. Validated live: Linode us-east nanode
`<server-ip>` running it carried real traffic (HTTP 301, ~60 ms RTT). **Consolidated onto Linode:**
`ns-spark.<tunnel-domain>` A repointed → <server-ip>; verified recursive still worked with the DO
server *stopped* (definitive), then deleted the DO droplet `<old-droplet-id>` + its DO-account SSH key.
Sole live server is now **Linode `<server-instance-id>` @ <server-ip>** serving `<tunnel-zone>` (recursive
re-verified post-deletion). Local key `~/.ssh/spark-dns-tunnel` retained (Linode SSH). Remaining reuse
to build: `SparkDNSConfig` + genconfig/config-server wiring, and the escalation-tier hook.

**2026-07-03 — DNS-tunnel: forward-secret handshake replaces the PSK (§2.4 done).** Prerequisite for
client config distribution surfaced a real weakness: distributing a PSK to all clients + no FS meant a
leaked config could decrypt captured traffic (PSK + cleartext salt → session keys). Fixed by
implementing the deferred X25519 forward-secret handshake, **ring-only, Design A** (ring's X25519 is
ephemeral-only → static identity is Ed25519, not X25519): server has a static Ed25519 keypair whose
**public** key clients hold; per session a cleartext ephemeral↔ephemeral X25519 exchange derives the
keys and the server signs the transcript (`client_eph ‖ server_eph ‖ conn_id`) for auth. Session keys
depend only on the ephemerals → FS (static-key or config leak can't decrypt past traffic); client is
anonymous (dnstt-style). Migrated the whole stack: `crypto` (Ed25519/X25519/HKDF-from-ee, base64
encode + `decode_server_pub`), `frame` (cleartext Syn/SynAck packet forms + `parse_packet`/`Packet`
enum, replacing the salt long-form), `session` (handshake state machine; all streams incl. the first
open post-handshake via short-form Syn; server caches the SynAck to replay on Syn retransmit so
ephemeral keys don't diverge; +1 RTT to first byte), `dns-tunnel-server` (`keygen` subcommand +
`serve --privkey-file`), spark `config` (`DnsTunnelConfig.psk` → `server_pubkey`) + transport builder.
Commits `64ff4bd` (crypto foundation) + `0d34d2a` (migration, BREAKING) + `ea95191` (deploy). 57 core
+ server-e2e + 181 spark-core tests green; clippy/fmt clean; base build unaffected. **Re-keyed +
redeployed the live Linode server** (`serve --privkey-file`, zone <tunnel-zone>); verified the FS
handshake live — authoritative (0.21 s) AND recursive through the public-resolver pool (0.46 s), both
HTTP 301, client authenticating with only the server public key `pBayZhvFX4OMbyVRlgjZ1Yi/goXJuIFgxC71BUBGTPM=`
(the PSK is gone). Deploy kit updated to keypair/keygen. Considered dep alt B (x25519-dalek, keeps
1-RTT) — rejected to preserve the ring-only/no-C constraint; A's +1 RTT is one-time per session.

**2026-07-03 — SparkDNSConfig in flashlight: attempted, then REVERTED (wrong layer).** Briefly mirrored
dnstt's config pipeline in `getlantern/flashlight` (`common.SparkDNSConfig` + genconfig + template) to
distribute the spark dns-tunnel config through Lantern's config-server. **Reverted** — the transport is
**Rust (spark)**, and Lantern's config-server feeds the **Go** client (kindling/radiance), which builds
a Go dnstt and can't construct a Rust spark transport; wiring it there only makes sense with a
Go↔Rust bridge that isn't the model. Rule going forward: **Rust ⇒ wire into Spark only; Go ⇒ wire into
Lantern.** Flashlight branch `fisk/spark-dns-config` deleted (unpushed; commit
`185532ba72051a2fd6a17eb0730a6c3c75756ecf` recoverable via reflog if a bridge is ever built). The
correct config surface already exists Spark-side: `DnsTunnelConfig` (zone, `server_pubkey`, resolvers,
duplication, use_system_resolvers) consumed by `from_config`/transport-selection. Remaining follow-up
is also **Spark-side**: an escalation hook that has spark's own transport-selection reach for
`dns_tunnel` as a last resort — not a kindling/Go hook. Any remote config distribution is a spark-side
mechanism.

**2026-07-02 — DNS-tunnel: throughput characterized + pipeline deepened (~4×).** Added an `#[ignore]`d
loopback benchmark (`bench_downlink_throughput` + a flood server modelling small-req/large-resp, and a
UDP delay relay to inject RTT; knobs `DNS_BENCH_{MIB,RTT_MS,INFLIGHT,WINDOW}`). Findings: the impl's
**CPU ceiling is ~560–690 Mbit/s** on loopback (crypto/codec are NOT the bottleneck), but a DNS tunnel
is **bandwidth-delay-product bound** — at a realistic 50 ms recursive RTT, goodput scales ~linearly
with the in-flight query budget: inflight 16 → 2.6 Mbit/s, 64 → 10.7, 128 → 20.2, 256 → 38.2. So raised
`session::Config::default()`: `max_query_inflight` 16 → 64 and ARQ windows to match (`send_window`
64 → 256 so the pull pipeline isn't re-bottlenecked; `recv_window` 256 → 1024 to absorb reorder from
spraying queries across resolvers) → ~4× real-world throughput at the default. Doc note: the budget
should be spread across the resolver pool so no single recursive resolver sees an anomalous query rate
(`inflight/pool_size` each). Secondary levers (not changed): larger downlink MTU/EDNS (linear in
bytes/answer, capped by what resolvers carry) and broad pool breadth. Commit `e557477`. **Live
recursive throughput still pending the infra gate** (deployed NS-delegated server + real public
resolver); loopback+RTT-sim is the self-contained proxy for it.
