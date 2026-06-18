#!/usr/bin/env bash
# Build SparkFFI.xcframework + the Swift binding for the spark-ffi control-plane crate, so an
# iOS/macOS app can drive a running spark-service through the generated, type-safe Swift API
# (`Backend`, `EventListener`, the async `connect`/`disconnect`/`status`, …).
#
# UniFFI flow: build the Rust staticlib per Apple target, generate the Swift glue + C header from a
# host build (UniFFI reads a crate's metadata by dlopen'ing it — the iOS libs can't load on the
# host, so a host cdylib is used for generation only), bundle the header + modulemap into the
# xcframework, and drop the generated Swift where Package.swift's `SparkFFI` target reads it. The
# Swift glue imports the xcframework's `spark_ffiFFI` clang module.
#
# Output (all gitignored — regenerate with this script):
#   spark-ffi/apple/SparkFFI.xcframework
#   spark-ffi/apple/Sources/SparkFFI/spark_ffi.swift
set -euo pipefail
cd "$(dirname "$0")/../.."  # repo root

TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin)
PKG="spark-ffi/apple"
GEN="$PKG/.generated"       # scratch: generated header / modulemap / swift
HEADERS="$GEN/headers"
OUT="$PKG/SparkFFI.xcframework"
SWIFT_DST="$PKG/Sources/SparkFFI"

echo "building staticlib for: ${TARGETS[*]}" >&2
for t in "${TARGETS[@]}"; do
    rustup target add "$t" >/dev/null 2>&1 || true
    cargo build --release -p spark-ffi --lib --target "$t" >&2
done

# Generate the Swift binding + C header/modulemap from a host build of the cdylib.
cargo build --release -p spark-ffi --lib >&2
rm -rf "$GEN"
mkdir -p "$GEN" "$HEADERS" "$SWIFT_DST"
cargo run --release -q -p spark-ffi --features uniffi-bindgen --bin uniffi-bindgen -- generate \
    --library target/release/libspark_ffi.dylib --language swift --out-dir "$GEN" >&2

# The xcframework headers dir: the C header + a `module.modulemap` (renamed from the generated
# `spark_ffiFFI.modulemap` so clang treats it as the slice's module map). One header dir is shared
# by all slices — the FFI header is arch-independent.
cp "$GEN/spark_ffiFFI.h" "$HEADERS/"
cp "$GEN/spark_ffiFFI.modulemap" "$HEADERS/module.modulemap"

# The Swift glue is the SparkFFI target's only source.
cp "$GEN/spark_ffi.swift" "$SWIFT_DST/"

rm -rf "$OUT"
args=()
for t in "${TARGETS[@]}"; do
    args+=(-library "target/$t/release/libspark_ffi.a" -headers "$HEADERS")
done
xcodebuild -create-xcframework "${args[@]}" -output "$OUT" >&2
echo "$OUT"
