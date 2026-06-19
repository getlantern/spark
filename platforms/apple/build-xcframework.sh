#!/usr/bin/env bash
# Build SparkCore.xcframework from the spark-apple staticlib for the Apple targets, so the Swift
# NetworkExtension provider can link it. iOS device + iOS simulator + macOS, all arm64.
#
# Output: platforms/apple/SparkCore.xcframework (gitignored — regenerate with this script).
set -euo pipefail
cd "$(dirname "$0")/../.."

TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin)
HEADERS="platforms/apple/include"
OUT="platforms/apple/SparkCore.xcframework"

echo "building staticlib for: ${TARGETS[*]}" >&2
for t in "${TARGETS[@]}"; do
    rustup target add "$t" >/dev/null 2>&1 || true
    # AnyTLS (BoringSSL) builds for the macOS host arch; BoringSSL-for-iOS is a separate concern, so
    # only the macOS slice gets `anytls` — the iOS slices share the ABI but return -1 for AnyTLS.
    feat=()
    [[ "$t" == *darwin* ]] && feat=(--features anytls)
    cargo build --release -p spark-apple --target "$t" "${feat[@]}" >&2
done

rm -rf "$OUT"
args=()
for t in "${TARGETS[@]}"; do
    args+=(-library "target/$t/release/libspark_apple.a" -headers "$HEADERS")
done
xcodebuild -create-xcframework "${args[@]}" -output "$OUT" >&2
echo "$OUT"
