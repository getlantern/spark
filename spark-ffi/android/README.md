# spark-ffi — Android packaging (jniLibs + UniFFI Kotlin, library module)

Packages the `spark-ffi` control-plane binding for Android: an Android library module whose Kotlin
API is the UniFFI-generated, type-safe surface (`Backend`, `EventListener`, the `suspend`
`connect`/`disconnect`/`status`, the `TunnelState`/`TunnelStatus`/`TunnelEvent` mirror types) over a
running `spark-service`'s control socket.

> **Control plane only.** This is the surface an app uses to drive the service. The data path (the
> tunnel itself) is the separate `libspark_android.so` JNI shim from `platforms/android`, which runs
> the core in-process on the `VpnService` fd. An app uses *both*.

## Build

```bash
./build-android.sh
```

Requires `cargo-ndk` + the Android NDK (NDK 28.x — see `platforms/android/README.md`). It builds
the cdylib for `arm64-v8a` (device) + `x86_64` (emulator) via cargo-ndk and generates the Kotlin
glue from a host build (UniFFI reads crate metadata by dlopen, so generation uses a host cdylib —
the android `.so` can't load on the host). Output (gitignored, regenerate with the script):

- `jniLibs/<abi>/libspark_ffi.so`
- `kotlin/uniffi/spark_ffi/spark_ffi.kt`

## Use from an app

Include this directory as a Gradle module:

```kotlin
// settings.gradle.kts
include(":spark-ffi")
project(":spark-ffi").projectDir = file("../spark/spark-ffi/android")
```

```kotlin
// app/build.gradle.kts
dependencies { implementation(project(":spark-ffi")) }
```

Then:

```kotlin
import uniffi.spark_ffi.Backend

val backend = Backend("/data/local/tmp/spark/control.sock")
backend.connect()                       // suspend
val status = backend.status()           // suspend
backend.subscribe(myListener)           // auto-reconnecting event stream
```

The module declares its runtime deps (JNA for the FFI, kotlinx-coroutines for the `suspend` calls).

To produce a standalone `.aar`, add a `settings.gradle.kts` (with the AGP/Kotlin plugin versions in
`pluginManagement`) + a gradle wrapper here, then `./gradlew assembleRelease`.

## Layout

| Path | Tracked? | What |
|------|----------|------|
| `build-android.sh` | yes | cargo-ndk build + Kotlin generation |
| `build.gradle.kts` | yes | the Android library module (sourceSets + JNA/coroutines deps) |
| `jniLibs/`, `kotlin/`, `build/` | no | generated build outputs |
