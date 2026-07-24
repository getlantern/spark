#!/usr/bin/env bash
# Build the dynamic-transport guest modules (ADR 0013 §7) from Rust to wasm32 and sign each into the
# `.spkw` artifact the core's wasm-transport tests load. This is the ONLY step that needs the wasm32
# toolchain — `cargo build` / `cargo test` / CI never touch it; they consume the committed artifacts.
#
# Regenerate the committed dev-signed test fixtures after editing a module (or bip324-core):
#     bash scripts/build-module.sh
#
# Produce a PRODUCTION artifact (signed with a real key, written to OUT_DIR — default dist/modules,
# gitignored — so the committed dev fixtures are left untouched). See docs/prod-module-signing-runbook.md:
#     MODULE_SIGNING_KEY=/path/to/prod-module.pkcs8 bash scripts/build-module.sh
set -euo pipefail
cd "$(dirname "$0")/.."

TARGET=wasm32-unknown-unknown
echo "==> ensuring $TARGET is installed" >&2
rustup target list --installed | grep -qx "$TARGET" || rustup target add "$TARGET"

# build_and_sign <module-dir/artifact-name> <cdylib-output-stem> <version>
build_and_sign() {
    local module="$1" lib="$2" version="$3"
    echo "==> building modules/$module (release, $TARGET)" >&2
    # --locked: the artifacts are committed, so build against the committed lockfiles (no silent resolve).
    cargo build --release --locked --target "$TARGET" --manifest-path "modules/$module/Cargo.toml"
    local wasm="modules/$module/target/$TARGET/release/${lib}.wasm"

    # `sign-module` lives behind the `module-signer` feature (never in a shipped build). Two modes, and the
    # OUTPUT PATH differs between them so production signing never clobbers the committed dev fixtures:
    #   - default → dev key into the committed fixture (what `ModuleVerifier::pinned()` accepts in a debug
    #     build; this regenerates the test fixtures byte-identically — Ed25519 is deterministic).
    #   - MODULE_SIGNING_KEY set → that real PKCS#8 key (mint one with `sign-module keygen`) into
    #     $OUT_DIR (default dist/modules, gitignored) for distribution; the matching pubkey must be pinned
    #     into the client build via SPARK_MODULE_PUBKEY_HEX. See docs/prod-module-signing-runbook.md.
    local out key_args
    if [[ -n "${MODULE_SIGNING_KEY:-}" ]]; then
        out="${OUT_DIR:-dist/modules}/${module}.spkw"
        key_args=(--key-pkcs8 "$MODULE_SIGNING_KEY")
        echo "==> signing $wasm with $MODULE_SIGNING_KEY (production) -> $out" >&2
    else
        out="core/tests/fixtures/wasm/${module}.spkw"
        key_args=(--dev)
        echo "==> signing $wasm with the dev key (fixture) -> $out" >&2
    fi
    mkdir -p "$(dirname "$out")"
    cargo run --quiet --locked -p spark-core --features module-signer --bin sign-module -- \
        sign "${key_args[@]}" --name "$module" --version "$version" --wasm "$wasm" --out "$out"
    echo "==> done: $out" >&2
}

# module dir/name    cdylib stem (crate name, `-` → `_`)    version
build_and_sign obfs-xor obfs_xor 1
build_and_sign bip324   bip324   1
