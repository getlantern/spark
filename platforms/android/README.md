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

## Still to do (M9 completion)

- `platforms/android/` Kotlin: a `SparkVpnService : VpnService` that builds the tunnel
  (`Builder().setMtu(...).addAddress(...).addRoute("0.0.0.0", 0).addDisallowedApplication(packageName).establish()`),
  `detachFd()`, and calls `SparkBridge.nativeRun(fd, mtu)` on a worker thread; `onDestroy` →
  `nativeStop()`. (See lantern's `LanternVpnService.kt` for the establish pattern.)
- A minimal Gradle module/app + the cargo-ndk pre-build wiring.
- The on-device/emulator browse-test gate.
