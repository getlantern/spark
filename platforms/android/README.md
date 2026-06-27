# spark-android — the Android JNI library + standalone app

`libspark_android.so`: the native library the Android `VpnService` loads to run the spark tunnel
data path on a TUN fd the OS hands it. There is **no privileged-daemon split** on Android (the
`VpnService` runs in-process, same uid), so only `spark-core` ships here — not
`spark-service`/`spark-ipc`.

`demo/` is the standalone Android app — a polished Jetpack Compose VPN client (en/ru/fa with full
RTL, no settings screen) that drives the library.

## Architecture

```
VpnService.establish() ──fd──▶ SparkBridge.nativeRun(fd, mtu, …, config, dataDir)  [JNI]
                                      │
                                      ▼
                spark_core  ▶ (self-fetch config / pool) ▶ netstack ▶ transports
```

- **JNI surface** (`SparkBridge`, package `org.getlantern.spark`, via the `jni` crate): the cdylib
  exports `nativeRun(fd, mtu, addr, prefix, systemStack, config, dataDir)` (blocks until stop;
  0 = clean, -1 = error), `nativeStop`, `nativeMarkConnecting`, `nativeWaitReady(timeoutMs)`,
  `nativeServers(): String?` (the live pool as JSON; null only on a catastrophic JNI string-alloc
  failure — callers treat null as `"[]"`), and `nativeSelectServer(index)` (pin a member, or
  `< 0` = auto). A null/empty/`"lantern-api"` `config` means self-fetch from the Lantern config-new
  API, caching `device_id` + the fetched config into `dataDir` (the app files dir); an `IP:port`
  literal is a plain relay; anything else is a full config (TOML or `config_raw.json`). The
  run/stop/fd-dispatch logic is in [`core/src/fd_tunnel.rs`](../../core/src/fd_tunnel.rs); the JNI
  shim (the `Java_org_getlantern_spark_*` exports) is [`platforms/android/src/lib.rs`](src/lib.rs).
- **Loop avoidance**: the `VpnService` calls `addDisallowedApplication(<own package>)` so the app's
  own sockets (this proxy's upstream dials) bypass the tunnel — the Android analog of the desktop
  `SocketProtector`. No per-socket JNI `protect()` callback is needed.
- Built with **NDK 28.2.13676358**, minSdk **24**, ABIs **arm64-v8a** (device) + **x86_64**
  (emulator). The `.so` is self-contained (links only `libc`/`libm`/`libdl`).

## The app (`demo/`)

A single-module Gradle app (AGP 8.9.1 / Gradle 8.11.1 / Kotlin 2.1.21, Compose BOM 2025.06.00,
minSdk 24 / targetSdk 35). Everything runs in one process — the `Activity`, the `VpnService`, and
the native core share a uid, so the Compose UI calls `SparkBridge` directly and observes a
singleton `StateFlow`. `SparkVpnService : VpnService` builds the tunnel, hands its fd to native, and
gates on `nativeWaitReady` before declaring `CONNECTED` (fail-open: a stuck self-fetch stops the VPN
so traffic falls back to direct rather than blackholing). The core's `tracing` events go to logcat
(tag `spark`) via the cdylib's liblog bridge.

## Build & run

The native lib is built **automatically** by Gradle — the `cargoNdkBuild` task cross-compiles it
into `src/main/jniLibs` (and drops cargo-ndk's stray `libtun_rs-*.so` byproduct) before the APK is
packaged. So a clean checkout builds end-to-end with one command; there is **no manual `cargo ndk`
step**. The task is up-to-date-keyed on the android crate + `core/src` + `Cargo.lock`, so plain
Kotlin/UI edits don't re-invoke cargo.

**Prerequisites** (one-time):

```bash
cargo install cargo-ndk
rustup target add aarch64-linux-android x86_64-linux-android
# Install NDK 28.2.13676358 (Android Studio SDK Manager, or `sdkmanager "ndk;28.2.13676358"`).
```

`cargo-ndk` must be on `PATH` (`~/.cargo/bin`). `ANDROID_NDK_HOME` is optional — it falls back to
`$ANDROID_HOME/ndk/28.2.13676358`. The task fails fast with a clear message if the NDK dir is
missing.

**Build & test** — all Gradle commands run from `platforms/android/demo`:

```bash
cd platforms/android/demo
./gradlew :app:assembleDebug        # builds the .so + the APK
./gradlew :app:testDebugUnitTest    # unit tests (parseServers JSON parsing)
```

The first build is slow (~80 s — it compiles the core for two ABIs); after that, Kotlin-only edits
are fast (`cargoNdkBuild` stays `UP-TO-DATE`). If you build from Android Studio and the task fails
with "no such command: ndk", Studio didn't inherit your shell `PATH` — launch it from a terminal or
add `~/.cargo/bin` to its environment.

**Run on an emulator/device** (APK path is relative to `demo/`):

```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell am start -n org.getlantern.spark/.MainActivity
# tap the toggle to connect; grant the VPN-consent dialog once on first run.
```

**Logs:**

```bash
adb logcat -s SparkVpn       # the VpnService (connect / reconnect / teardown)
adb logcat | grep spark      # the Rust core's tracing events (probes, pool, readiness)
```

**Localization / RTL** (per-app locale, API 33+ — no reboot; the device language otherwise drives
it, there's no in-app picker):

```bash
adb shell cmd locale set-app-locales org.getlantern.spark --locales fa-IR   # Farsi (RTL)
adb shell cmd locale set-app-locales org.getlantern.spark --locales ru-RU   # Russian
adb shell cmd locale set-app-locales org.getlantern.spark --locales ""      # system default
adb shell am force-stop org.getlantern.spark   # then relaunch to apply
```

**Verify traffic actually flows the tunnel** (optional — a request from a non-app uid should egress
via `tun0` → spark → upstream, while connected):

```bash
adb shell 'printf "GET /generate_204 HTTP/1.1\r\nHost: connectivitycheck.gstatic.com\r\nConnection: close\r\n\r\n" | nc connectivitycheck.gstatic.com 80 | head -1'
# => HTTP/1.1 204 No Content   ✓   (and `adb logcat -s spark` shows the forwarded TCP flows)
```

> **Manual `.so` build** (only if you can't use the Gradle task — e.g. a CI image without it).
> Run from the **repo root** with explicit paths so the output dir is unambiguous:
> ```bash
> cargo ndk -t arm64-v8a -t x86_64 -P 24 \
>     -o platforms/android/demo/app/src/main/jniLibs build --release -p spark-android
> rm -f platforms/android/demo/app/src/main/jniLibs/*/libtun_rs-*.so
> ```
> Output lands in `platforms/android/demo/app/src/main/jniLibs/<abi>/libspark_android.so` (gitignored — a build artifact).
