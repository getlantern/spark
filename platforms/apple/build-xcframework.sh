#!/usr/bin/env bash
# Build SparkCore.xcframework from the spark-apple staticlib for the Apple targets, so the Swift
# NetworkExtension provider can link it. iOS device + iOS simulator + macOS (arm64 by default;
# MAC_ARCH=x86_64 selects the Intel macOS slice for a separate Intel build).
#
# Env: MAC_ARCH   macOS slice arch — arm64 (default) or x86_64.
#
# Output: platforms/apple/SparkCore.xcframework (gitignored — regenerate with this script).
set -euo pipefail
cd "$(dirname "$0")/../.."

# Select the Rust macOS target from MAC_ARCH so this script (and build-tauri-dmg.sh) can produce the
# xcframework for either an Apple-Silicon or an Intel macOS build. The iOS slices are always arm64.
MAC_ARCH="${MAC_ARCH:-arm64}"
case "$MAC_ARCH" in
    arm64)  MAC_TARGET=aarch64-apple-darwin ;;
    x86_64) MAC_TARGET=x86_64-apple-darwin ;;
    *) echo "MAC_ARCH must be arm64 or x86_64 (got: $MAC_ARCH)" >&2; exit 1 ;;
esac

TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim "$MAC_TARGET")
HEADERS="platforms/apple/include"
OUT="platforms/apple/SparkCore.xcframework"

echo "building staticlib for: ${TARGETS[*]}" >&2
for t in "${TARGETS[@]}"; do
    rustup target add "$t" >/dev/null 2>&1 || true
    # Pin the macOS slice's min-OS to the project floor (platforms/apple/project.yml = 12.0) so its
    # objects (incl. BoringSSL's) match the app/sysext deployment target — without this an x86_64
    # slice defaults to a newer min-OS and the linker warns "object built for newer macOS version".
    case "$t" in
        *-apple-darwin) export MACOSX_DEPLOYMENT_TARGET=12.0 ;;
        *) unset MACOSX_DEPLOYMENT_TARGET ;;
    esac
    # BoringSSL cross-compiles for every Apple target — iOS device, iOS simulator, and macOS (verified
    # 2026-06-23) — so all slices get the SAME feature set rather than the former macOS-only set:
    # `anytls`/`samizdat`/`shadowsocks`/`hysteria2` transports, the `multi-server` latency pool,
    # `bootstrap-dns` for hostname pool members, and `config-fetch` for `lantern-api` self-fetch.
    # Building BoringSSL on every slice means the cold-start config fetch uses one uniform
    # (cert-verifying) BoringSSL handshake everywhere — no per-platform TLS-stack split. NB: v1's fetch
    # is a *plain* boring connector (not yet Chrome-mimicked); Chrome-mimicry for the fetch is the
    # deferred fronting milestone. See docs/config-fetch-cross-platform-design.md.
    feat=(--features anytls,multi-server,bootstrap-dns,config-fetch,samizdat,shadowsocks,hysteria2,fronted-meek,smart-routing)
    cargo build --release -p spark-apple --target "$t" "${feat[@]}" >&2
done

rm -rf "$OUT"
args=()
for t in "${TARGETS[@]}"; do
    args+=(-library "target/$t/release/libspark_apple.a" -headers "$HEADERS")
done
xcodebuild -create-xcframework "${args[@]}" -output "$OUT" >&2
echo "$OUT"
