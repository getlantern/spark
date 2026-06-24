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
    # BoringSSL cross-compiles for every Apple target — iOS device, iOS simulator, and macOS (verified
    # 2026-06-23) — so all slices get the SAME feature set rather than the former macOS-only set:
    # `anytls`/`samizdat`/`shadowsocks`/`hysteria2` transports, the `multi-server` latency pool,
    # `bootstrap-dns` for hostname pool members, and `config-fetch` for `lantern-api` self-fetch.
    # Keeping the fetch on the BoringSSL Chrome connector on every platform means the cold-start config
    # fetch presents the same Chrome JA4 fingerprint everywhere — a censor can't tell iOS Lantern's
    # fetch from macOS's. See docs/config-fetch-cross-platform-design.md.
    feat=(--features anytls,multi-server,bootstrap-dns,config-fetch,samizdat,shadowsocks,hysteria2)
    cargo build --release -p spark-apple --target "$t" "${feat[@]}" >&2
done

rm -rf "$OUT"
args=()
for t in "${TARGETS[@]}"; do
    args+=(-library "target/$t/release/libspark_apple.a" -headers "$HEADERS")
done
xcodebuild -create-xcframework "${args[@]}" -output "$OUT" >&2
echo "$OUT"
