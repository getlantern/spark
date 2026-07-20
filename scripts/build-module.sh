#!/usr/bin/env bash
# Build a dynamic-transport guest module (ADR 0013 §7) from Rust to wasm32 and sign it into the
# `.spkw` artifact the core's wasm-transport test loads. This is the ONLY step that needs the wasm32
# toolchain — `cargo build` / `cargo test` / CI never touch it; they consume the committed artifact.
#
# Regenerate the reference fixture after editing modules/obfs-xor:
#     bash scripts/build-module.sh
set -euo pipefail
cd "$(dirname "$0")/.."

# The reference module. A second module (e.g. BIP324) adds another block like this.
MODULE=obfs-xor          # crate + artifact name
LIB=obfs_xor             # cdylib output stem (crate name, `-` → `_`)
VERSION=1
OUT="core/tests/fixtures/wasm/${MODULE}.spkw"

TARGET=wasm32-unknown-unknown

echo "==> ensuring $TARGET is installed" >&2
rustup target list --installed | grep -qx "$TARGET" || rustup target add "$TARGET"

echo "==> building modules/$MODULE (release, $TARGET)" >&2
# --locked: the artifact is committed, so build against the committed lockfiles (no silent resolve).
cargo build --release --locked --target "$TARGET" --manifest-path "modules/$MODULE/Cargo.toml"
WASM="modules/$MODULE/target/$TARGET/release/${LIB}.wasm"

echo "==> signing $WASM with the dev key -> $OUT" >&2
mkdir -p "$(dirname "$OUT")"
# `sign-module` lives behind the `module-signer` feature (never in a shipped build). `--dev` uses the
# development key that `ModuleVerifier::pinned()` accepts in a debug build; a release artifact would
# pass `--key-pkcs8 <real-key>` instead.
cargo run --quiet --locked -p spark-core --features module-signer --bin sign-module -- \
    --dev --name "$MODULE" --version "$VERSION" --wasm "$WASM" --out "$OUT"

echo "==> done: $OUT" >&2
