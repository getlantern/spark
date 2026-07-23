# Module distribution & multi-signer trust — design

Status: **draft / RFC** · Tracks: [#114](https://github.com/getlantern/spark/issues/114) · Builds on:
[`dynamic-transport-framework-design.md`](./dynamic-transport-framework-design.md) §7,
[`prod-module-signing-runbook.md`](./prod-module-signing-runbook.md)

## Goals

1. **Distribute** a prod-signed WASM transport module + its `TransportConfig` to already-shipped clients
   over the signed config/fronting channel — a new/updated transport ships in hours, **no app-store
   release** (the framework's north star).
2. **Trust more than one signer.** Today a single Lantern key is compiled into the client. We want to
   trust **third-party contributor keys** so external authors can ship transports — *without* handing out
   Lantern's key and *without* a client release to add or revoke a contributor.

Both must preserve the existing invariant: **sign offline, verify everywhere** — private keys never touch
CI or the client; the client only ever *verifies*.

## Non-goals

- Automating signing in CI (explicitly rejected in §7 — private keys stay offline).
- Replacing the wasmi sandbox as the isolation boundary for module *execution* (separate concern; noted
  under Open questions).
- A general package manager. This is transport modules only.

## Background — the current single-key model

Every module is a `.spkw` artifact (flint signed-blob framing):

```
MAGIC "SPKW" │ version: u32 BE │ name_len: u16 BE │ name │ wasm_len: u32 BE │ wasm   +   Ed25519 sig (64B)
```

`ModuleVerifier::pinned().verify(artifact, min_version)` checks the detached Ed25519 signature against a
**single** public key compiled in via `SPARK_MODULE_PUBKEY_HEX` (dev-key fallback in debug builds) and
enforces a **monotonic version floor** (anti-rollback — a correctly-signed *old* module is still an
attack). The private half lives only in Vault (`secret/lantern_cloud/spark → SPARK_MODULE_SIGNING_KEY`).

Two limits for our goals: (a) there is no delivery path from a signed `.spkw` to a running client, and
(b) the trust anchor is exactly one key with no signer identity in the artifact.

---

## Part A — Distribution (near-term, single key)

### Delivery
The client already consumes a **signed config** over the fronting channel. Extend the config with a
**module descriptor**:

```
ModuleDescriptor {
  name, version,                     // must match the .spkw manifest
  artifact: Inline(b64) | Ref { url, sha256 },     // small modules inline (base64); large ones referenced
  targeting: <reuse config targeting> // region / bandit track / % rollout
}
```

- **Inline vs referenced.** `obfs-xor.spkw` ≈ 722 B (inline is free); `bip324.spkw` ≈ 23 KB (inlining it
  into every config fetch is wasteful — reference it by URL + `sha256` so the client fetches once and
  caches). Trust/integrity/authenticity come entirely from the `.spkw`'s own Ed25519 signature + anti-
  rollback — verified after fetch, exactly as for an inline module. The `sha256` in `Ref` is **not** the
  security boundary; it's a fetch-consistency check that binds the descriptor to a specific artifact and
  fails a corrupted/wrong download fast, before verification.
- **Rollout / rollback.** Targeting reuses the existing config machinery (region, bandit track, staged
  %). Rollback = revert the config (stop offering the descriptor) and/or the anti-rollback floor prevents
  a *downgrade* to a known-bad older version. A kill-switch is "descriptor absent → module not loaded" —
  which only holds if **loading is gated on the *current* config carrying a matching, targeted descriptor**.
  The referenced-fetch cache is a performance optimization for the artifact *bytes only*, **never an
  authorization signal**: a cached `.spkw` is not loaded unless the live config still offers it. (This also
  means a true kill depends on config freshness — see the freshness/TTL open question.)

### Client flow
receive descriptor → obtain the `.spkw` (inline or fetch+hash-check) → `ModuleVerifier::pinned().verify(…)` against the
pinned key with the config's `min_version` → instantiate. No release.

### Producer flow
Offline per the runbook: pull key from Vault → sign → **publish the descriptor** to the lantern-cloud
config service. (New: the "publish to config" step + the `build-module.sh` out-dir fix and `sign-module
verify` helper from #114.)

---

## Part B — Multi-signer trust (target: trust contributors' keys)

### The problem
One hardcoded key means: to trust a new contributor you'd either share Lantern's private key (unacceptable)
or ship a client release that bakes in their key (defeats "no release", and is too slow/coarse). We want a
**dynamic, scoped, revocable** trust set that updates over the same config channel.

### Threat model (what a bad/compromised contributor key must NOT be able to do)
- **Impersonate a core transport** — sign a module named `bip324`/`obfs-xor` and get it loaded.
- **Rollback** — force clients back to an old module or an old trust set.
- **Persist after revocation** — keep being trusted once we pull the key.
- (Execution risk — a rogue module is arbitrary WASM in the dial path — is bounded by the wasmi sandbox +
  host-capability surface; see Open questions.)

### Design: root-delegated, config-distributed key registry (TUF-style delegation)
Analogy: Apple notarization — one Apple root vouches for many developer certs; the OS pins only the root.

1. **Pin one root key** in the client (rarely used, air-gapped/HSM; *separate* from operational signing
   keys). This becomes the sole hardcoded anchor (rename `SPARK_MODULE_PUBKEY_HEX` → a root pubkey, or add
   `SPARK_MODULE_ROOT_PUBKEY_HEX`).
2. **Root signs a key registry** — a versioned, root-signed document distributed over the config channel:
   ```
   KeyRegistry {
     registry_version: u64,          // monotonic; clients reject anything ≤ highest seen (anti-rollback)
     not_before, not_after,          // validity window for the registry itself
     signers: [ SignerEntry {
        key_id,                        // fingerprint of the signer pubkey
        pubkey,                        // Ed25519
        scope: [name-glob, …],         // which module names this key may sign (e.g. "contrib/foo-*")
        not_before, not_after,         // per-signer validity
     } … ],
     revoked: [ key_id … ],           // explicit denylist (belt-and-suspenders)
   }                                   + root Ed25519 signature
   ```
3. **Contributors sign their own modules offline** with their own keys, submitting only their **public**
   key to Lantern for inclusion (scoped) in the registry. The `.spkw` gains a **signer `key_id`** so the
   verifier knows which registry entry to check (format v2, below).
4. **Client verify** becomes:
   1. verify registry signature against the pinned **root**; reject if `registry_version` ≤ highest seen or
      outside its validity window;
   2. resolve the module's `key_id` → `SignerEntry`; reject if absent, revoked, or expired;
   3. check the module `name` matches the entry's `scope` globs;
   4. verify the module signature against the entry's `pubkey`;
   5. enforce the per-module anti-rollback floor (unchanged).
5. **Scoping bounds blast radius.** A contributor key authorized only for `contrib/foo-*` cannot sign
   `bip324`. Lantern's operational key keeps a broad scope; contributors get narrow namespaces.
6. **Revocation** = publish a new registry (higher version) that drops/denies the key. Anti-rollback stops
   an attacker from replaying an older registry that still trusted it.

### Root vs operational key split
Mint a **fresh air-gapped root** whose only job is signing the registry (rare, high-ceremony). The key we
just put in Vault becomes the **first operational Lantern signer entry** — the one that signs `bip324` /
`obfs-xor` day to day. Root compromise is catastrophic, so it's used seldom and could later be M-of-N
threshold.

### Alternatives considered
- **A. Static baked-in multi-key allowlist** — compile in a *set* of keys. Simplest, but adding/revoking a
  signer needs a client release. Good **stepping stone**, wrong as the target.
- **C. Transparency log / Sigstore (keyless OIDC + append-only log)** — strong public auditability, heavier
  infra + online dependency. A plausible *future layer on top of B* for verifiability, not the first cut.

## Format changes
- **`.spkw` v2** — add a `key_id` (32-byte fingerprint) to the manifest so the verifier selects the signer
  without trial-verifying every key. Note the current framing (`MAGIC "SPKW" || version || name || wasm`)
  has **no format-version field** — its `version` is the *module* version (anti-rollback), a different
  axis. So v2 needs a real format discriminator: a **new magic** (e.g. `SPK2`) or a leading format-version
  byte. During migration, legacy `SPKW` (v1) artifacts carry no `key_id` and are verified against the
  **single migrating operational key** — *not* the root (root ≠ operational signer in this design; the root
  only ever signs the registry).
- **New `SPKR` registry artifact** — root-signed, its own magic, its own anti-rollback (`registry_version`).
- **`ModuleVerifier`** grows from one key to `{ pinned_root, current_registry }` and the multi-step check
  above. `sign-module` grows `registry` subcommands (build/sign a registry) alongside `sign`/`keygen`/`pubkey`.

## Phasing / migration
- **Phase 1 (#114):** distribution, single key (current). Ship prod-signed `bip324`/`obfs-xor` over config.
- **Phase 2:** introduce root + registry; current key → first operational signer entry; client verifies via
  the registry with a fallback to the pinned single key during rollout. `.spkw` v2 with `key_id`.
- **Phase 3:** onboard external contributors — scoped, expiring keys; revocation; a documented contributor
  process (identity check, pubkey-only submission, scope grant, "sign offline / submit public key" custody
  guidance mirroring the runbook).

## Security invariants (must hold in every phase)
- Sign offline, verify everywhere — root, operational, and contributor private keys never enter CI/the repo.
- Exactly **one** hardcoded trust anchor (the root); everything else is delegated and revocable over config.
- **No client release** to ship a module, add a signer, or revoke one.
- Anti-rollback on **both** the module version and the registry version.
- Delegated trust is **scoped + expiring**, so a compromised contributor key has a bounded, time-limited,
  namespace-limited blast radius.

## Open questions
1. **Root custody** — HSM? air-gapped host? M-of-N threshold from the start, or added later?
2. **Revocation latency** — the config channel's push cadence bounds how fast a revocation reaches clients;
   is that fast enough, or do we need a shorter-TTL "timestamp" role (TUF-style) for freshness?
3. **Third-party WASM isolation** — is the wasmi sandbox + host-capability set a sufficient boundary for
   *untrusted-author* modules, or do contributor modules need a tighter capability profile than first-party?
4. **`key_id`** — fingerprint vs full pubkey in the manifest (size vs. self-containment).
5. **Registry size** in the config payload as the signer set grows (inline vs referenced, like modules).
6. **Contributor onboarding policy** — who approves a key + its scope, and how is contributor identity
   established.

## Work breakdown (feeds #114 and follow-ups)
- [ ] Phase 1: `ModuleDescriptor` schema + config-channel plumbing (inline + ref/hash), client fetch/verify/
      load path, rollout/rollback controls, E2E test. *(#114 core.)*
- [ ] Tooling: `build-module.sh` out-dir, `sign-module verify`. *(#114.)*
- [ ] Phase 2: `.spkw` v2 (`key_id`), `SPKR` registry artifact + `sign-module registry`, root keygen +
      custody, `ModuleVerifier` multi-key + registry verification, migration/fallback.
- [ ] Phase 3: contributor onboarding doc + policy; scoped/expiring delegation; revocation flow + test.
