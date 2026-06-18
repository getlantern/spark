#!/usr/bin/env bash
# Build the spark-ffi cdylib for Android ABIs (via cargo-ndk) + generate the Kotlin binding, so an
# Android app can drive a running spark-service through the generated, type-safe Kotlin API
# (`Backend`, `EventListener`, the `suspend` `connect`/`disconnect`/`status`, …). Mirrors the
# cargo-ndk recipe in platforms/android.
#
# Requires cargo-ndk + the Android NDK (NDK 28.x; see platforms/android/README.md).
#
# Output (all gitignored — regenerate with this script):
#   spark-ffi/android/jniLibs/<abi>/libspark_ffi.so   (arm64-v8a device, x86_64 emulator)
#   spark-ffi/android/kotlin/uniffi/spark_ffi/spark_ffi.kt
set -euo pipefail
cd "$(dirname "$0")/../.."  # repo root

PKG="spark-ffi/android"
JNILIBS="$PKG/jniLibs"
KOTLIN="$PKG/kotlin"

# arm64-v8a (device) + x86_64 (emulator); minSdk 24 — matches platforms/android.
echo "building cdylib via cargo-ndk for: arm64-v8a x86_64" >&2
cargo ndk -t arm64-v8a -t x86_64 -P 24 -o "$JNILIBS" build --release -p spark-ffi --lib >&2
# cargo-ndk may also copy transitive cdylibs (e.g. libtun_rs) it finds; keep only our lib.
find "$JNILIBS" -type f -name '*.so' ! -name 'libspark_ffi.so' -delete

# Generate the Kotlin glue from a host build (UniFFI reads crate metadata by dlopen; the android
# .so can't load on the host, so generate from the host cdylib — the bindings are arch-independent).
cargo build --release -p spark-ffi --lib >&2
if [ -f target/release/libspark_ffi.dylib ]; then
    HOST_LIB=target/release/libspark_ffi.dylib   # macOS host
else
    HOST_LIB=target/release/libspark_ffi.so       # Linux host (CI)
fi
rm -rf "$KOTLIN"
mkdir -p "$KOTLIN"
cargo run --release -q -p spark-ffi --features uniffi-bindgen --bin uniffi-bindgen -- generate \
    --library "$HOST_LIB" --language kotlin --out-dir "$KOTLIN" >&2

echo "jniLibs: $JNILIBS"
echo "kotlin:  $KOTLIN"
