# spark-apple — the Apple NetworkExtension core (iOS + macOS)

`libspark_apple.a`: the C-ABI static library linked into a NetworkExtension **Packet Tunnel
Provider** on iOS and macOS. Only `spark-core` ships here (the data path runs in-process inside
the extension; no `spark-service`/daemon split — the OS provides the privileged context).

## Architecture (decided after research — see `docs/PLAN.md` M10)

```
NEPacketTunnelFlow ──utun fd──▶ spark_tunnel_run(fd, mtu)   [C ABI]
                                      │
                                      ▼
                          spark_core::fd_tunnel::run_tunnel(fd, mtu)
                            Tun::from_fd(fd) ▶ netstack ▶ forwarder (direct)
```

- **Packet I/O = the fd-trick** (primary). The Swift provider resolves the underlying `utun`
  file descriptor — `packetFlow.value(forKeyPath:"socket.fileDescriptor")`, with a public-symbol
  **fd-scan fallback** (enumerate fds, match the `com.apple.net.utun_control` socket via
  `getsockopt`/`getpeername`/`ioctl`) — and passes it to `spark_tunnel_run`. The core wraps it
  with `Tun::from_fd` and runs the **same netstack as desktop/Android**. This is what
  WireGuard-apple, sing-box, Mullvad, Proton (incl. their Rust tunnel), and our own **lantern**
  do; 5 of 6 surveyed VPNs use it, and it ships on the App Store under team `ACZRKC3LQ9`.
- **Packets never cross the FFI** — Rust owns the fd, so the C ABI is **control-only**
  (`spark_tunnel_run`/`spark_tunnel_stop`), mirroring the Android JNI. One core surface
  (`spark_core::fd_tunnel`), two thin adapters (`platforms/android` JNI, `platforms/apple` C ABI).
- **Loop avoidance:** the NE process's own upstream dials egress the real interface (they're not
  routed back through `packetFlow`), so no per-socket protection is needed.
- **Apple's caveat + our mitigation:** Apple's DTS officially *discourages* the fd-trick (it reads
  a non-public ivar; Apple is migrating toward a socket-less stack). The mitigation is a
  **`readPacketObjects`/`writePackets` packet-object fallback** — a documented follow-up that also
  future-proofs against the fd ever disappearing. Not built yet (the fd path works on current
  iOS/macOS).
- **Memory:** the iOS packet-tunnel process cap is **50 MiB** (whole process). Tune smoltcp
  per-socket buffers small (16–32 KiB), flow-cap, reuse buffers. macOS has no cap.

## Build the static library

```bash
rustup target add aarch64-apple-ios aarch64-apple-ios-sim   # one-time (aarch64-apple-darwin preinstalled)
for t in aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin; do
    cargo build --release -p spark-apple --target "$t"
done
# Then package the three .a's into SparkCore.xcframework (cargo-xcframework or `xcodebuild
# -create-xcframework`), with include/spark.h as the umbrella header. (Packaging = session 2.)
```

Exports (`include/spark.h`): `int32_t spark_tunnel_run(int32_t fd, int32_t mtu)` (blocks until
stop; 0 ok / -1 err) and `void spark_tunnel_stop(void)`.

## Swift provider (build-verified)

`Sources/SparkNE/` holds the **one** `PacketTunnelProvider: NEPacketTunnelProvider` for iOS *and*
macOS, plus `FdResolver` (KVC → public-symbol fd-scan). `startTunnel` configures a full-tunnel
route, resolves the `utun` fd, and runs `spark_tunnel_run(fd, mtu)` on a worker thread;
`stopTunnel` calls `spark_tunnel_stop`. `Package.swift` compile-verifies the Swift + the C FFI
against `SparkCore.xcframework`:

```bash
./build-xcframework.sh   # 3 .a's -> SparkCore.xcframework (ios-arm64, ios-arm64-simulator, macos-arm64)
swift build              # type-checks PacketTunnelProvider + FdResolver + the spark_tunnel_* FFI
```

`xcode/` has the `.entitlements` (extension: `packet-tunnel-provider` + App Group; app: App Group)
and the extension `Info.plist` (`NSExtensionPrincipalClass = $(PRODUCT_MODULE_NAME).PacketTunnelProvider`).

## Build it

```bash
brew install xcodegen                 # one-time
./build-xcframework.sh                # SparkCore.xcframework
xcodegen generate                     # -> Spark.xcodeproj (gitignored)
xcodebuild -project Spark.xcodeproj -scheme SparkApp -configuration Debug \
    -destination 'platform=macOS' -allowProvisioningUpdates build
```

`project.yml` defines the macOS **SparkApp** (SwiftUI harness) + the **SparkTunnel** Packet Tunnel
app-extension (embeds `SparkCore.xcframework` + `Sources/SparkNE`), automatic signing under team
`ACZRKC3LQ9`.

## Status & live-gate handoff (M10)

- **Verified here (sessions 1–3):** the whole stack **builds and signs** — `xcodebuild
  -allowProvisioningUpdates` auto-created the `Apple Development` cert + `Mac Team Provisioning
  Profile: org.getlantern.spark{,.tunnel}` with the `packet-tunnel-provider` entitlement, and the
  signed `.appex` carries it (`codesign -d --entitlements`). The **app side runs**: launch →
  `NETunnelProviderManager` save (one-time consent) → `startVPNTunnel` succeeds (the managing app
  needs the NE entitlement too, else `saveToPreferences` = *permission denied* — fixed in
  `SparkApp.entitlements`).
- **Converted to a SYSTEM EXTENSION (compiles).** `SparkTunnel` is now `type: system-extension`
  — a standalone executable (`Sources/SparkTunnelMain/main.swift` → `NEProvider.startSystemExtensionMode()`),
  a `NetworkExtension` Info.plist dict (`NEMachServiceName` + `NEProviderClasses`), the
  `packet-tunnel-provider-systemextension` entitlement (sandbox off), and the app carries
  `system-extension.install` + the `OSSystemExtensionRequest` activation flow (`SysExt` in
  `SparkApp.swift`). Verified: `xcodebuild … CODE_SIGNING_ALLOWED=NO build` → **BUILD SUCCEEDED**
  (this is lantern's `main.swift` + `SystemExtensionManager` model).
- **Signing = lantern's model (already configured in `project.yml`):** **Manual** signing,
  `CODE_SIGN_IDENTITY[sdk=macosx*] = "Developer ID Application"`, team `ACZRKC3LQ9`, and a named
  **Developer-ID provisioning profile** per target (`Spark macOS App`, `Spark macOS Tunnel`).
  Automatic *development* signing can't carry `packet-tunnel-provider-systemextension` (it's
  distribution-only — confirmed in both the CLI and the Xcode GUI), so manual + portal profiles is
  the only working path (verified by decoding lantern's `MacOS Tunnel Development Profile`, which is
  actually a Developer-ID profile: `ProvisionsAllDevices=true`, entitlements
  `packet-tunnel-provider-systemextension` + `system-extension.install` + the app group).
- **Remaining (human, one-time): create the two Developer-ID profiles in the Apple Developer portal**
  (developer.apple.com → Certificates, IDs & Profiles), then download (Xcode installs them):
  1. **App Group:** register `group.org.getlantern.spark` (Identifiers → App Groups).
  2. **App IDs** (register if not auto-created): `org.getlantern.spark` and
     `org.getlantern.spark.tunnel`, each with **Network Extensions** + **App Groups** + **System
     Extension** capabilities.
  3. **Profiles** (Profiles → + → **Developer ID**, the macOS distribution type that gives
     `ProvisionsAllDevices`): one for each App ID. Name them exactly **`Spark macOS App`** and
     **`Spark macOS Tunnel`** (matching `project.yml`).
- **Then build → notarize → run** (CLI, once the profiles are installed):
  ```bash
  ./build-xcframework.sh && xcodegen generate
  xcodebuild -project Spark.xcodeproj -scheme SparkApp -configuration Release \
      -destination 'generic/platform=macOS' -archivePath /tmp/Spark.xcarchive ARCHS=arm64 archive
  xcodebuild -exportArchive -archivePath /tmp/Spark.xcarchive -exportPath /tmp/SparkExport \
      -exportOptionsPlist ExportOptions.plist
  ditto -c -k --keepParent /tmp/SparkExport/SparkApp.app /tmp/spark.zip
  xcrun notarytool submit /tmp/spark.zip --apple-id "$AC_USERNAME" --password "$AC_PASSWORD" \
      --team-id ACZRKC3LQ9 --wait
  xcrun stapler staple /tmp/SparkExport/SparkApp.app
  cp -R /tmp/SparkExport/SparkApp.app /Applications/ && open /Applications/SparkApp.app
  ```
  Then approve the system extension (System Settings → Privacy & Security) + the VPN consent, and
  browse-test. Provider logs to subsystem `org.getlantern.spark` (Console.app). A notarized sysext
  loads **without** SIP-off.
- iOS live gate needs a physical device (NE packet tunnels don't run on the simulator).
- Cleanup from bring-up: a non-functional "Spark" VPN config + `/Applications/SparkApp.app` —
  remove via System Settings → VPN and `rm -rf /Applications/SparkApp.app`.
