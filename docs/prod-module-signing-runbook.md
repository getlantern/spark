# Prod module-signing pipeline (spark WASM transports)

**Model: sign offline, verify everywhere.** The private module-signing key **never touches CI or the
repo**. CI carries only the *public* key; the private key lives in Vault and is materialized only on a
trusted operator host for the duration of a signing run. This is the deliberate split from
[`dynamic-transport-framework-design.md` §7](./dynamic-transport-framework-design.md) — do not "automate"
it by putting the key in GitHub Actions; that would defeat the whole point.

A new transport is a **distribution artifact, not a code release**: sign a WASM module offline, push it
and its config over the signed config/fronting channel, and an already-shipped client that pinned the
matching pubkey loads it with no app-store release.

## Current state (2026-06-29)

| Piece | Status |
|---|---|
| Prod keypair minted | ✅ |
| **Private half** in Vault | ✅ `secret/lantern_cloud/spark` field `SPARK_MODULE_SIGNING_KEY` (base64 of the DER PKCS#8) |
| **Public half** pinned in CI | ✅ repo variable `SPARK_MODULE_PUBKEY_HEX = 1f090afa…85ce` on `getlantern/spark`; `release.yml` builds `--features bip324` when set |
| Pubkey ↔ Vault-key match | ✅ verified (derived pubkey == pinned variable) |
| Committed `.spkw` (`bip324`, `obfs-xor`) | ⚠️ **dev-key-signed test fixtures only** — not for prod |
| **Prod-signed module produced / distributed** | ❌ **gap** — nothing prod-signed exists yet, and the module *distribution* step isn't built |

## The pipeline (offline, on a trusted host)

### A. Materialize the key from Vault (ephemeral, never logged)
```bash
# Best assurance: run on an ephemeral host or point $TMPDIR at a tmpfs/ramdisk so the key never hits
# persistent disk. `rm -rf` is portable (GNU rm has no `-P`; BSD/macOS secure-overwrite isn't reliable
# across filesystems anyway — don't count on it).
umask 077; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
# from lantern-cloud/, prod env:
mise -E prod x -- bin/vault kv get -mount=secret -field=SPARK_MODULE_SIGNING_KEY lantern_cloud/spark \
  | base64 -d > "$tmp/prod-module.pkcs8"
```

### B. Build + sign the modules with the prod key
```bash
cd spark
MODULE_SIGNING_KEY="$tmp/prod-module.pkcs8" bash scripts/build-module.sh
```
With `MODULE_SIGNING_KEY` set, the script writes each `.spkw` to `OUT_DIR` (default `dist/modules/`,
gitignored) instead of the committed dev fixtures — so a prod signing run never clobbers
`core/tests/fixtures/wasm/`. Set `OUT_DIR` to land the artifacts elsewhere.

### C. Verify before shipping
First, **confirm the key you pulled is the one clients pin** — `sign-module pubkey` re-derives a key's
pubkey hex, which must equal the pinned `SPARK_MODULE_PUBKEY_HEX`:
```bash
cargo run -q -p spark-core --features module-signer --bin sign-module -- pubkey --key-pkcs8 "$tmp/prod-module.pkcs8"
# → must print: 1f090afa1b640732f5d1e8536ee49fe7a9bf73581f313101c7543d5ff13a85ce
```
That guards against signing with the wrong key. Then **confirm the signed artifact itself validates** under
that pinned pubkey — this runs the exact check the client runs (`ModuleVerifier::verify`):
```bash
cargo run -q -p spark-core --features module-signer --bin sign-module -- \
  verify dist/modules/bip324.spkw --pubkey-hex 1f090afa1b640732f5d1e8536ee49fe7a9bf73581f313101c7543d5ff13a85ce
# → OK: 'bip324' v1 verifies under the given pubkey (…)   [exit 0; non-zero + "verification FAILED" on mismatch]
```
**Do not distribute an artifact that doesn't verify.**

### C2. Bundle it — the form the delivery path installs
A bare `.spkw` is what the *local* `transport.wasm.module` path consumes. Anything **delivered over
the config channel** ships as a `.spkb` **bundle** instead: the engine name, its opening plans, the
module, and the capability grant signed together. That is what gets the store's persisted
anti-rollback floors (a bare module's floor only survives a restart if a `floor_path` is configured)
and what carries capability scoping inside the signature, where config cannot widen it. See
[`module-distribution-and-trust-design.md`](./module-distribution-and-trust-design.md) Part A.

```bash
cargo run -q -p spark-core --features module-signer --bin sign-module -- \
  bundle --engine bip324 --version 1 --key-pkcs8 "$tmp/prod-module.pkcs8" \
  --wasm modules/bip324/target/wasm32-unknown-unknown/release/bip324.wasm \
  --genome-id bip324-mainnet --genome-version 1 --engine-params 00f9beb4d9 \
  --out dist/modules/bip324.spkb
```
`bundle` self-verifies against its own signing key before it writes anything, so an engine/name
mismatch or a misaddressed genome fails here rather than after distribution. It does **not** replace
step C: the self-check cannot catch signing with the *wrong key*, which succeeds locally and fails on
every client. Run `verify` against the pinned pubkey on the `.spkb` too — it dispatches on the
artifact's magic, so it is the same invocation:
```bash
cargo run -q -p spark-core --features module-signer --bin sign-module -- \
  verify dist/modules/bip324.spkb --pubkey-hex 1f090afa1b640732f5d1e8536ee49fe7a9bf73581f313101c7543d5ff13a85ce
# → OK: bundle 'bip324' v1 verifies under the given pubkey — 1 genome(s), 23292 bytes wasm, …
```

### D. Distribute over the config/fronting channel
Push the prod-signed `.spkb` + its outbound through the config channel clients already consume
(lantern-cloud config distribution). Client pins `SPARK_MODULE_PUBKEY_HEX`, verifies, installs, loads
— **no client release**. *(This step is the unbuilt part — see the gap issue below.)*

Note the channel is **not** signed — `core/src/config/fetch/mod.rs` is explicit that trust there is
TLS. That is by design: the trust anchor is the artifact's own Ed25519 signature, which is what makes
it safe to carry over a channel we do not have to trust. Nothing security-relevant may live in the
config *around* the artifact.

### E. Custody hygiene
- The `trap` in step A removes the temp key on exit (best-effort — secure erase isn't guaranteed on all filesystems, so prefer a tmpfs/ramdisk or an ephemeral host for the signing run). Never `git add` a prod `.spkw` next to the dev fixtures.
- Never place the key, or `MODULE_SIGNING_KEY`, into any GitHub Actions workflow. CI stays pubkey-only.

## What CI does (and must keep doing)
`release.yml` sets `SPARK_MODULE_PUBKEY_HEX` from the repo **variable** (public) and builds `--features
bip324`. That's the entire CI role. No secret, no signing.

## Open work (needs design + build)
1. **Module distribution over the config channel** — the wire schema (a `wasm` outbound carrying the
   bundle inline or by mirror URL), the client-side install into `BundleStore`, per-region/bandit
   rollout, rollback. This is the real remaining pipeline and the highest-value piece. Decided design
   in [`module-distribution-and-trust-design.md`](./module-distribution-and-trust-design.md) Part A;
   it is a **two-repo** change (spark + lantern-cloud).

*(Done: the `build-module.sh` `OUT_DIR` override, the `sign-module verify` helper, and `sign-module
bundle` — steps B, C, and C2 above.)*
