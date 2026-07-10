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
    # Pin each slice's minimum-OS so its objects (incl. BoringSSL's) target the SAME deployment
    # target the consuming apps link against — otherwise the linker warns "object file built for
    # newer iOS/macOS version than being linked". iOS 14 matches the Tauri iOS project.yml + the
    # SPM Package.swift floor; macOS 12 matches platforms/apple/project.yml. cc/clang honor these.
    case "$t" in
        aarch64-apple-ios | aarch64-apple-ios-sim)
            export IPHONEOS_DEPLOYMENT_TARGET=14.0
            unset MACOSX_DEPLOYMENT_TARGET
            ;;
        aarch64-apple-darwin)
            export MACOSX_DEPLOYMENT_TARGET=12.0
            unset IPHONEOS_DEPLOYMENT_TARGET
            ;;
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
