#!/usr/bin/env bash
# Build the dynamic-transport guest modules (ADR 0013 §7) from Rust to wasm32 and sign each into the
# `.spkw` artifact the core's wasm-transport tests load. This is the ONLY step that needs the wasm32
# toolchain — `cargo build` / `cargo test` / CI never touch it; they consume the committed artifacts.
#
# Regenerate the committed fixtures after editing a module (or bip324-core):
#     bash scripts/build-module.sh
set -euo pipefail
cd "$(dirname "$0")/.."

TARGET=wasm32-unknown-unknown
echo "==> ensuring $TARGET is installed" >&2
rustup target list --installed | grep -qx "$TARGET" || rustup target add "$TARGET"

# build_and_sign <module-dir/artifact-name> <cdylib-output-stem> <version>
build_and_sign() {
    local module="$1" lib="$2" version="$3"
    local out="core/tests/fixtures/wasm/${module}.spkw"
    echo "==> building modules/$module (release, $TARGET)" >&2
    # --locked: the artifacts are committed, so build against the committed lockfiles (no silent resolve).
    cargo build --release --locked --target "$TARGET" --manifest-path "modules/$module/Cargo.toml"
    local wasm="modules/$module/target/$TARGET/release/${lib}.wasm"

    echo "==> signing $wasm with the dev key -> $out" >&2
    mkdir -p "$(dirname "$out")"
    # `sign-module` lives behind the `module-signer` feature (never in a shipped build). `--dev` uses the
    # development key that `ModuleVerifier::pinned()` accepts in a debug build; a release artifact would
    # pass `--key-pkcs8 <real-key>` instead.
    cargo run --quiet --locked -p spark-core --features module-signer --bin sign-module -- \
        --dev --name "$module" --version "$version" --wasm "$wasm" --out "$out"
    echo "==> done: $out" >&2
}

# module dir/name    cdylib stem (crate name, `-` → `_`)    version
build_and_sign obfs-xor obfs_xor 1
build_and_sign bip324   bip324   1
