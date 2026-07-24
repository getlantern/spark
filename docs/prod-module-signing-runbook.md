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

### D. Distribute over the signed config/fronting channel
Push the prod-signed `.spkw` + its `TransportConfig` through the same signed-config channel clients already
consume (lantern-cloud config distribution). Client pins `SPARK_MODULE_PUBKEY_HEX`, verifies, loads — **no
client release**. *(This step is the unbuilt part — see the gap issue below.)*

### E. Custody hygiene
- The `trap` in step A removes the temp key on exit (best-effort — secure erase isn't guaranteed on all filesystems, so prefer a tmpfs/ramdisk or an ephemeral host for the signing run). Never `git add` a prod `.spkw` next to the dev fixtures.
- Never place the key, or `MODULE_SIGNING_KEY`, into any GitHub Actions workflow. CI stays pubkey-only.

## What CI does (and must keep doing)
`release.yml` sets `SPARK_MODULE_PUBKEY_HEX` from the repo **variable** (public) and builds `--features
bip324`. That's the entire CI role. No secret, no signing.

## Open work (needs design + build)
1. **Module distribution over the config channel** — where the `.spkw` lives (inline in config vs a fetched
   URL; `bip324.spkw` is ~23 KB), versioning, per-region/bandit rollout, rollback. This is the real
   remaining pipeline and the highest-value piece. Design in
   [`module-distribution-and-trust-design.md`](./module-distribution-and-trust-design.md).

*(Done: the `build-module.sh` `OUT_DIR` override and the `sign-module verify` helper — steps B and C above.)*
