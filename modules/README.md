# Dynamic-transport guest modules

Signed WASM transports for the Path B runtime (ADR 0003 / ADR 0013 §7). Each crate here is a
**workspace-excluded** `wasm32-unknown-unknown` `cdylib`: a different target, ABI, and build profile
than the host `spark-core`, so it must stay out of the core workspace graph and the size-tuned release
profile (see the root `Cargo.toml` `exclude` comment). `cargo build` / `cargo test` / CI never touch
these; they consume the committed, signed `.spkw` artifact.

- **`obfs-xor/`** — the reference module. A minimal byte-transform (XOR `0x5A`, involutive) that mirrors
  the inline `XOR_WAT` fixture in `core/src/transport/wasm/mod.rs`, plus one `host_rand` `env` call to
  prove a *compiled* module binds a host capability.

## The ABI

The host owns the sockets and drives the module (see the module header in
`core/src/transport/wasm/mod.rs`). A guest exports `memory`, `alloc(len) -> ptr`, and at least one mode
— `transform_out` / `transform_in` (byte transform), `compute_gambit`, or `handshake_step` — each
returning the packed `(ptr << 32) | len` region to read its output from. Its only capabilities are the
`env` host functions (`host_rand`, `host_hash`, the AEAD/HKDF/x25519/… crypto menu); no WASI, no
network.

## Adding a module

1. Create `modules/<name>/` as a `cdylib` (copy `obfs-xor/`), implementing the ABI above.
2. Add `"modules/<name>"` to the root `Cargo.toml` `exclude` list.
3. Add a build+sign block for it to `scripts/build-module.sh` and run the script to produce the signed
   `.spkw`.
4. Commit the `.spkw` under `core/tests/fixtures/wasm/` and add a load/verify/round-trip test.

## Build + sign

```sh
bash scripts/build-module.sh   # builds every module to wasm32 and signs it into a committed .spkw
```

The script signs with the development key via `sign-module` (`--dev`), which
`ModuleVerifier::pinned()` accepts in a debug build. A production artifact is signed with a real
Ed25519 key: `cargo run -p spark-core --features module-signer --bin sign-module -- --key-pkcs8 <key>
--name <name> --version <n> --wasm <in.wasm> --out <out.spkw>`. The private key never lives in the repo
or a shipped binary.
