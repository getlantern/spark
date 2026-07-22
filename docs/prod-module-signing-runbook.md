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
umask 077; tmp="$(mktemp -d)"; trap 'rm -Pf "$tmp"/* 2>/dev/null; rmdir "$tmp"' EXIT
# from lantern-cloud/, prod env:
mise -E prod x -- bin/vault kv get -mount=secret -field=SPARK_MODULE_SIGNING_KEY lantern_cloud/spark \
  | base64 -d > "$tmp/prod-module.pkcs8"
```

### B. Build + sign the modules with the prod key
```bash
cd spark
MODULE_SIGNING_KEY="$tmp/prod-module.pkcs8" bash scripts/build-module.sh
```
⚠️ **Needs a small fix first:** `build-module.sh` hard-codes `--out core/tests/fixtures/wasm/<mod>.spkw`.
Signing prod there would overwrite the committed **dev** fixtures. Add an output-dir override (e.g.
`OUT_DIR=dist/modules`) so prod artifacts land in a dist dir and the dev fixtures stay untouched. (Tracked
below.)

### C. Verify before shipping
Confirm the freshly-signed artifact verifies under the pinned pubkey (the production
`ModuleVerifier::pinned()` path). The full pinned key (no ellipsis) is:
```
1f090afa1b640732f5d1e8536ee49fe7a9bf73581f313101c7543d5ff13a85ce
```
There is **no per-artifact verify CLI yet** — `sign-module` exposes only `sign` / `keygen`. A
`sign-module verify <spkw> --pubkey-hex <hex>` helper is tracked in #114 and is the intended one-liner for
this step. Until it lands, verify by exercising the existing `ModuleVerifier` tests in
`core/src/transport/wasm/` (they load a `.spkw` through `pinned().verify`). **Do not distribute an artifact
that doesn't verify against the hex above.**

### D. Distribute over the signed config/fronting channel
Push the prod-signed `.spkw` + its `TransportConfig` through the same signed-config channel clients already
consume (lantern-cloud config distribution). Client pins `SPARK_MODULE_PUBKEY_HEX`, verifies, loads — **no
client release**. *(This step is the unbuilt part — see the gap issue below.)*

### E. Custody hygiene
- The `trap` in step A shreds the temp key on exit. Never `git add` a prod `.spkw` next to the dev fixtures.
- Never place the key, or `MODULE_SIGNING_KEY`, into any GitHub Actions workflow. CI stays pubkey-only.

## What CI does (and must keep doing)
`release.yml` sets `SPARK_MODULE_PUBKEY_HEX` from the repo **variable** (public) and builds `--features
bip324`. That's the entire CI role. No secret, no signing.

## Open work (needs design + build)
1. **Module distribution over the config channel** — where the `.spkw` lives (inline in config vs a fetched
   URL; `bip324.spkw` is ~23 KB), versioning, per-region/bandit rollout, rollback. This is the real
   remaining pipeline and the highest-value piece.
2. **`build-module.sh` output-dir override** — so prod signing doesn't clobber the committed dev fixtures.
3. **A `verify` convenience** in `sign-module` (if not already) to check a `.spkw` against a given pubkey
   hex, for step C.
