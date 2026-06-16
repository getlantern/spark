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

## Status & live-gate handoff (M10)

- **Done — build-verified here (sessions 1–2):** `spark-core` + `spark-apple` build for
  `aarch64-apple-ios`/`-ios-sim`/`-darwin`; `SparkCore.xcframework` packages all three; the unified
  Swift provider + fd-resolver + FFI compile (`swift build`).
- **Live gate is BLOCKED on provisioning, not code.** On this box: only a *Developer ID* cert
  (no Apple-development identity), **zero provisioning profiles**, **no Xcode-logged-in team**, and
  `systemextensionsctl developer` is **blocked by SIP** (so a macOS *system extension* can't run in
  dev mode without disabling SIP / notarizing). The NE entitlement *cannot be self-authorized* — it
  needs a provisioning profile from team `ACZRKC3LQ9`.
- **Reachable path (no SIP changes):** package the macOS NE as an **app-extension** (not a system
  extension) and provision it. To run the live gate you (the human) need to:
  1. In Xcode, sign in to the Apple account for team `ACZRKC3LQ9` (Settings → Accounts).
  2. Create an Xcode project: a macOS (and/or iOS) **App** target + a **Network Extension**
     (Packet Tunnel) target embedding `SparkCore.xcframework` + the `Sources/SparkNE` Swift; set
     bundle IDs `org.getlantern.spark` / `org.getlantern.spark.tunnel`, the entitlements + Info.plist
     from `xcode/`, and enable automatic signing (Xcode will provision the App IDs + the NE
     capability under the team). (`brew install xcodegen` + a `project.yml` can generate this — ask
     and I'll add one.)
  3. Run the app, start the VPN (consent dialog), and browse — `log stream --predicate
     'subsystem == "org.getlantern.spark"'` shows the core forwarding (tag `tunnel`/`spark`).
- iOS live gate needs a physical device (NE packet tunnels don't run on the simulator).
