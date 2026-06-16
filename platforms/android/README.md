# spark-android — the Android JNI library

`libspark_android.so`: the native library the Android `VpnService` loads to run the spark
tunnel data path on a TUN fd the OS hands it. There is **no privileged-daemon split** on Android
(the `VpnService` runs in-process, same uid), so only `spark-core` ships here — not
`spark-service`/`spark-ipc`.

## Architecture

```
VpnService.establish() ──fd──▶ SparkBridge.nativeRun(fd, mtu)  [JNI]
                                      │
                                      ▼
                          spark_core::android::run_tunnel(fd, mtu)
                            Tun::from_fd(fd) ▶ netstack ▶ forwarder (direct)
```

- **JNI surface** (primitive-only, so no `jni` crate): the cdylib exports
  `Java_org_getlantern_spark_SparkBridge_nativeRun(fd: jint, mtu: jint) -> jint` (blocks until
  stop; 0 = clean, -1 = error) and `…_nativeStop()`. Run/stop logic is in
  [`spark_core::android`](../../core/src/android.rs).
- **Loop avoidance**: the `VpnService` must call `addDisallowedApplication(<own package>)` so the
  app's own sockets (this proxy's upstream dials) bypass the tunnel — the Android analog of the
  desktop `SocketProtector`. So no per-socket JNI `protect()` callback is needed.
- Built with **NDK 28.2.13676358**, minSdk **24**, ABIs **arm64-v8a** (device) + **x86_64**
  (emulator). The `.so` is self-contained (links only `libc`/`libm`/`libdl`).

## Build the .so

```bash
cargo install cargo-ndk            # one-time
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/28.2.13676358"
cargo ndk -t arm64-v8a -t x86_64 -P 24 -o platforms/android/jniLibs \
    build --release -p spark-android
# Drop cargo-ndk's stray copy of tun-rs's dylib byproduct (we statically link it):
rm -f platforms/android/jniLibs/*/libtun_rs-*.so
```

Output lands in `platforms/android/jniLibs/<abi>/libspark_android.so` (gitignored — it's a build
artifact). The eventual Gradle module runs this as a pre-build step and bundles `jniLibs/`.

## Demo app + emulator gate

`demo/` is a minimal single-module Gradle app (AGP 8.9.1 / Gradle 8.11.1 / Kotlin 2.1.21,
minSdk 24) that drives the library: `SparkVpnService : VpnService` builds the tunnel
(`setMtu(1500).addAddress("10.0.0.2",24).addRoute("0.0.0.0",0).addDisallowedApplication(packageName).establish()`),
`detachFd()`s, and runs `SparkBridge.nativeRun(fd, mtu)` on a worker thread; `MainActivity`
handles VPN consent. The core's `tracing` events go to logcat (tag `spark`) via the cdylib's
liblog bridge.

**M9 gate — PASSED on an emulator (Medium_Phone_API_35, arm64) 2026-06-16:**

```bash
# 1. build the .so into the app, then the APK
cargo ndk -t arm64-v8a -t x86_64 -P 24 -o demo/app/src/main/jniLibs build --release -p spark-android
rm -f demo/app/src/main/jniLibs/*/libtun_rs-*.so
(cd demo && ./gradlew assembleDebug)
adb install -r demo/app/build/outputs/apk/debug/app-debug.apk
# 2. start it; grant the VPN consent dialog once (tap OK) — spark becomes the prepared VPN
adb shell am start -n org.getlantern.spark/.MainActivity
# 3. browse test from a non-app uid (adb shell uid 2000 → tun0 → spark → upstream):
adb shell 'printf "GET /generate_204 HTTP/1.1\r\nHost: connectivitycheck.gstatic.com\r\nConnection: close\r\n\r\n" | nc connectivitycheck.gstatic.com 80 | head -1'
# => HTTP/1.1 204 No Content   ✓   (and `adb logcat -s spark` shows the forwarded TCP flows)
```

Android reported the VPN `CONNECTED` **+ VALIDATED** (its own connectivity probe passed through
spark). Force-stopping the app cleanly releases `tun0` (fail-open via OS fd cleanup).

## Still to do (later)

- A richer config path (host-specific config / a tunnel server) — the demo runs the default
  direct forwarder. Would want the `jni` crate once strings/callbacks are involved.
- Wire `cargo ndk` as a Gradle pre-build task so `assembleDebug` rebuilds the `.so` automatically.
