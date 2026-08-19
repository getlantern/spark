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
    # Pin each slice's minimum-OS so its objects (incl. BoringSSL's) target the SAME deployment
    # target the consuming apps link against — otherwise the linker warns "object file built for
    # newer iOS/macOS version than being linked". iOS 14 matches the Tauri iOS project.yml + the
    # SPM Package.swift floor; macOS 12 matches platforms/apple/project.yml. cc/clang honor these.
    # The macOS arm matches both aarch64- and x86_64-apple-darwin so an Intel (MAC_ARCH=x86_64)
    # build is pinned too.
    case "$t" in
        aarch64-apple-ios | aarch64-apple-ios-sim)
            export IPHONEOS_DEPLOYMENT_TARGET=14.0
            unset MACOSX_DEPLOYMENT_TARGET
            ;;
        *-apple-darwin)
            export MACOSX_DEPLOYMENT_TARGET=12.0
            unset IPHONEOS_DEPLOYMENT_TARGET
            ;;
        *)
            # A target matching neither arm: clear both so a prior slice's min-OS can't leak in.
            unset IPHONEOS_DEPLOYMENT_TARGET MACOSX_DEPLOYMENT_TARGET
            ;;
    esac
    # `prod` is the shared shipping set, defined once in core/Cargo.toml and forwarded by
    # spark-apple. It used to be spelled out here as a literal list, which is how the three platforms
    # drifted apart — desktop shipped for months without transports these slices carried. Changing
    # what ships now means editing core/Cargo.toml, and every platform follows.
    #
    # BoringSSL cross-compiles for every Apple target — iOS device, iOS simulator, and macOS (verified
    # 2026-06-23) — so all slices get the SAME set. Building it on every slice means the cold-start
    # config fetch uses one uniform (cert-verifying) BoringSSL handshake everywhere, with no
    # per-platform TLS-stack split. NB: v1's fetch is a *plain* boring connector (not yet
    # Chrome-mimicked); that is the deferred fronting milestone. See
    # docs/config-fetch-cross-platform-design.md.
    #
    # `system-stack` is absent on purpose: this one list covers the iOS slices, which cannot hand over
    # a tun fd in the shape it needs, and enabling it would have them advertise a capability they do
    # not have.
    features="prod"
    # `bip324` (ADR 0013 §7) adds the dynamic-transport wasmi host + secp256k1 primitives + splitting
    # egress, so a signed bip324/obfs-xor module can be delivered by config with no app release. It's
    # opt-in: a *release* build with `wasm-transport` refuses the dev module-signing key (fail-closed),
    # so it's enabled only when a production module-signing pubkey is pinned via SPARK_MODULE_PUBKEY_HEX.
    # secp256k1 cross-compiles for every Apple slice (verified 2026-07-21, aarch64-apple-ios).
    if [[ -n "${SPARK_MODULE_PUBKEY_HEX:-}" ]]; then
      features="$features,bip324"
      echo "  (bip324 enabled — pinning SPARK_MODULE_PUBKEY_HEX)" >&2
    fi
    # The Unbounded consumer is the one place these slices deliberately diverge, the same way
    # `system-stack` is absent above: macOS gets it, iOS does not. webrtc-rs has never been
    # cross-built for aarch64-apple-ios here and no CI job would catch a break, and the iOS NE runs on
    # roughly a tenth of desktop's memory budget with the netstack already in it. Revisit with a real
    # iOS cross-build, not by deleting this case.
    case "$t" in
        *-apple-darwin)
            features="$features,unbounded"
            echo "  (unbounded consumer enabled — macOS slice only)" >&2
            ;;
    esac
    cargo build --release -p spark-apple --target "$t" --features "$features" >&2
done

rm -rf "$OUT"
args=()
for t in "${TARGETS[@]}"; do
    args+=(-library "target/$t/release/libspark_apple.a" -headers "$HEADERS")
done
xcodebuild -create-xcframework "${args[@]}" -output "$OUT" >&2
echo "$OUT"
