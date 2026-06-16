# STATE

> Cross-session memory. Read at session start, update at session end. Append to the
> decisions log; never rewrite history. (Template + rules: PLAN.md Appendix A / §2.)

## Current position
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

## Next chunk (exactly what the next session should do)
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

## Milestone checklist
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
