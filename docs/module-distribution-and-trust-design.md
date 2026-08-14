# Module distribution & multi-signer trust — design

Status: **Part A decided (2026-08-13), Part B draft / RFC** · Tracks:
[#114](https://github.com/getlantern/spark/issues/114) · Builds on:
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

A second artifact type already exists alongside it. A **bundle** (`SPKB` magic, `engine/bundle.rs`)
signs an engine name, its opening plans (genomes), an optional module, and a `capabilities` list
*together*, under the same pinned key — closing the gap where the code that could ship arbitrary WASM
was authenticated but the genome telling it what protocol to speak was not. `BundleStore`
(`engine/store.rs`) installs bundles by engine name and persists a per-engine
`Floor { bundle, genome }` so anti-rollback survives a restart. Part A delivers bundles, not bare
modules, for exactly those two properties.

Two limits for our goals: (a) there is no delivery path from a signed artifact to a running client —
`BundleStore::install` is reached only from tests, nothing installs a delivered artifact — and (b) the
trust anchor is exactly one key with no signer identity in the artifact.

---

## Part A — Distribution (near-term, single key)

**Status: decided 2026-08-13.** Four decisions, each recorded with its reason — two of them reverse
an earlier draft of this section, so the reasoning matters more than the conclusion.

1. **Inline first, spark only.** Lantern consumes no modules at all, so spark is the sole consumer and
   there is nobody to coordinate a rollout with. Mirrors stay in the schema from day one, so switching
   later is a config change rather than a schema migration.
2. **Delivered artifacts are `.spkb` bundles installed through `BundleStore`** — even when the bytes
   arrive inline. This is what buys anti-rollback that survives a restart, plus capability scoping.
3. **The module rides the outbound**, shaped as sing-box's `rule_set` union — *not* a top-level
   registry keyed by engine name, which is what the previous draft of this section proposed.
4. **Clients declare what they already hold**, so a module's bytes cross the wire once rather than on
   every config change.

### Correction: there is no signed config channel

The issue title and this document's first draft both say "the signed config/fronting channel." There
isn't one. `core/src/config/fetch/mod.rs:7` is explicit: *"Trust is TLS — no signature, matching
radiance."*

This does not weaken the design — the trust anchor was never meant to be the channel. It is the
Ed25519 signature over the artifact, verified against the compiled-in `SPARK_MODULE_PUBKEY_HEX`, which
is exactly what makes an arbitrary mirror set safe to race. But it does change what rollback means: a
config revert is an API-side action protected by TLS and by control of the endpoint, not a
signed-artifact revocation. Anything that must be unforgeable has to ride inside the signed artifact,
never in the config that points at it.

### What the consumer path actually does today (verified 2026-08-13)

The gap is one layer deeper than "add a descriptor." Three facts, each checked against the code:

- **`WasmConfig` is unreachable from a fetched config.** Production config is `config_raw.json` from
  lantern-cloud `config-new`, adapted by `core/src/config/lantern.rs`. That adapter starts from
  `Config::default()` (so `transport.wasm` is always `None`), its `map_outbound()` handles exactly
  `samizdat | hysteria2 | shadowsocks | meek`, and it contains **zero** references to wasm. There is
  no wire shape today that can produce a `WasmConfig` at all.
- **Every existing load path needs a file that already exists.** `wasm_transport()`
  (`core/src/transport/mod.rs:815`) accepts `module = <path>` or `engine = <name>` + `bundle_dir`;
  `load_gambit_module()` accepts a path. Nothing in the codebase ever writes one —
  `BundleStore::install` is called only from tests.
- **`ModuleVerifier::pinned().verify()` takes bytes, not a path** (`wasm/signing.rs:203`). Inline
  delivery therefore needs no filesystem to *verify*; the store is required for the reasons below,
  not to make verification possible.

Two things already work in our favour, and the design leans on both: `ServerSpec::Wasm` is already a
pool-member variant that `build_from_spec` handles, and `build_members` **skips** an un-buildable
member with a warning rather than propagating (`transport/mod.rs:459-470`) — its doc comment says
outright that "a future protocol in a fetched config can't brick the tunnel."

### Why bundles, not bare modules

Routing delivery through `BundleStore::install` (`engine/store.rs:92`) rather than verifying a bare
`.spkw` in memory buys three things a bare module cannot express:

- **Anti-rollback that survives a restart.** `verify()` enforces the config's `min_version`, but the
  *persisted* floor needs either a `floor_path` or the store. Without one, an adversary who can serve
  a stale-but-validly-signed config pins a client to an old module version indefinitely — and the
  kill-switch argument below depends on config freshness that the same adversary controls. The store
  persists `Floor { bundle, genome }` in `floors.toml`, so **both** the module version and the genome
  version ratchet.
- **Capability scoping.** `capabilities` lives inside the signed payload, so config cannot widen a
  module's authority. The host-import table is the entire sandbox boundary, which makes this the lever
  Part B needs to run a third-party transport at all.
- **Module persistence between runs**, which is what makes the "ship the bytes once" optimization
  below meaningful rather than a per-process cache.

The consequence: **the delivered artifact must be `.spkb`, not `.spkw`.** `install()` runs
`BundleVerifier::pinned()`, which requires `SPKB` magic — `bundle.rs` has an explicit test asserting
`"SPKW must not pass as SPKB"`. Nothing currently produces a `.spkb` (`Bundle::new` is called only
from tests), so **a bundle producer was the first thing to build** — `sign-module bundle`, landed as
Phase 1a.

`install()` is already shaped correctly for delivery: it verifies before writing anything, using a
two-pass floor lookup (verify at zero floors to learn the signed engine name, then re-verify against
that engine's real floors), writes atomically, and advances floors only once the artifact is safely on
disk. A rejected bundle leaves the store byte-identical.

### Schema — the outbound carries the module

Modeled on sing-box's `rule_set`, which is a three-arm discriminated union (verified against current
`option/rule_set.go` and the rule-set docs):

```jsonc
{"type": "inline", "tag": "", "rules": []}
{"type": "local",  "tag": "", "format": "source"|"binary", "path": ""}
{"type": "remote", "tag": "", "format": "source"|"binary", "url": "",
 "initial_path": "", "http_client": ""|{}, "update_interval": ""}
```

Note `inline` is a **first-class sing-box arm** — embedding content in the config is idiomatic there,
not a Lantern extension. A spark wasm outbound mirrors that shape:

```jsonc
{"type": "wasm", "tag": "ir-1", "server": "192.0.2.7", "server_port": 8333,
 "engine": "bip324", "min_version": 3,
 "module": {"type": "inline", "format": "spkb", "content": "<hex .spkb>"}}
//         {"type": "local",  "format": "spkb", "path": "…"}
//         {"type": "remote", "format": "spkb", "url": […mirrors…], "sha256": "…"}
```

- **Inline content is hex, not base64.** This reverses the obvious choice, on a measurement. Hex
  doubles the artifact uncompressed but uses 16 highly regular symbols, so DEFLATE compresses it far
  better than base64's near-random 64-symbol output. On `bip324.spkb` (23,429 B):

  | encoding | uncompressed | **gzipped** |
  |---|---|---|
  | base64 | 31,240 B | 12,190 B |
  | hex | 46,858 B | **10,077 B** |

  Hex is **17% smaller on the wire** — the only size that is ever paid. It also needs no new
  dependency (there is no base64 crate in the tree, and `spark-core` has a hex decoder already), and
  it is what `init_config` and `genome` already use, so config carries binary exactly one way. The
  cost is a real constraint, in the next section.
- `local` is the `module = <path>` case that already works today, for free, in the same union.
- **`min_version`**, not `version`: it is the anti-rollback *floor* the config asserts, a different
  axis from the artifact's own signed version. Naming it `version` invited exactly the confusion the
  `.spkw` framing already suffers from (see Format changes).
- **Mirrors are our one genuine divergence**: sing-box `remote` takes a single `url`. Handle it the way
  this codebase already handles the same problem — `RawRouteRule.ip_cidr` is a `StrOrVec`
  (`lantern.rs`), accepting string-or-array leniently. That keeps the shape upstream-compatible for a
  single value while carrying a mirror set for us, and makes "let `url` accept an array" a small,
  defensible upstream proposal rather than a schema fork. A mirror list matters because one URL is one
  thing to block; a set can be raced the way the config fetch races its avenues.
- **Do not model on `download_detour`** — deprecated, removed in sing-box 1.16.0, replaced by
  `http_client`.
- **`initial_path` is worth adopting**: read a local file at startup while the remote updates in the
  background. That is "ship `obfs-xor` with the app, update it over the wire," which beats cold-fetching
  on first connect.

A hash in the descriptor stays worthwhile as a **fetch-consistency check** for the `remote` arm — it
fails a corrupted or wrong download fast, before verification — but it is explicitly **not** the
security boundary. The signature is.

Wire compatibility is favourable: `RawRoot`/`RawOutbound` are lenient serde with no
`deny_unknown_fields`, so new fields are invisible to shipped clients and an old client simply skips
an outbound type it cannot represent. (`WasmConfig` *does* carry `deny_unknown_fields`, but that
governs only native TOML, never the wire.)

### Why not a top-level module registry

The previous draft put modules in a top-level registry referenced by engine name, on the grounds that
N outbounds sharing a module would otherwise duplicate its bytes. Measured, that argument does not
hold.

First, what a bundle actually costs over the bare module it wraps — measured on real artifacts from
`sign-module bundle`, not extrapolated:

| artifact | raw | gzip(base64) |
|---|---|---|
| `obfs-xor.spkw` (module) | 722 B | 693 B |
| `obfs-xor.spkb` (bundle) | 786 B | 734 B |
| `bip324.spkw` (module) | 23,376 B | 12,129 B |
| `bip324.spkb` (bundle) | 23,429 B | **12,190 B** |

The bundle envelope costs **+53 B** on bip324 — postcard framing plus one genome. Choosing bundles
over bare modules is free at wire scale; it is paid for in tooling, not bytes.

Then the duplication question, on a body carrying N identical bip324 outbounds each with the full
artifact. Both encodings, because the answer differs sharply:

| outbounds | base64 gzipped | hex gzipped |
|---|---|---|
| 1 | 12,362 B | **10,286 B** |
| 2 | 12,773 B | 20,152 B |
| 6 | 14,089 B | 59,514 B |

With base64, six copies cost +1.7 KB over one — DEFLATE back-references absorb them, because the
31 KB base64 blob *just* fits inside the 32 KiB sliding window. With hex it does not fit (46.9 KB), so
copies cannot back-reference and the cost goes linear at ~9.8 KB each.

**So the encoding and the placement decision are coupled, and the honest statement is this:** hex is
the cheapest option when the artifact appears **once per body**, and the most expensive when it is
repeated. base64's dedup is not a property to rely on either — it is an accident of bip324 landing
~3% under the window, and a slightly larger module loses it silently, with no signal until a payload
blows up. Hex converts a hidden cliff into a cost that shows up immediately and forces the right
emission policy.

That policy is: **emit the artifact on one outbound per engine per body, and omit `module` from the
rest.** No schema change is needed for it — `module` is already optional, and an outbound naming only
`engine` means "already installed."

✅ **This policy is safe as of Phase 1c.** Provisioning is a pre-pass over every wasm outbound that
runs before any pool member is built (`provision_one`, called from `build_members`), so where the
server chose to put the artifact no longer decides which members work. An earlier draft of this
section warned the opposite, because provisioning then happened per member in iteration order — an
outbound that omitted `module` and was built *before* the one carrying it failed its store lookup and
was skipped. `an_outbound_can_use_a_bundle_a_later_outbound_delivered` pins the fixed behaviour, with
the carrier listed second.

With the efficiency argument settled, the placement decision rests on upstream shape, where
per-outbound wins clearly: an upstream contribution is *an outbound type*, and one that also requires
a new top-level config section is a much larger ask. Keeping our wire shape identical to the upstream
shape also avoids maintaining a translation layer we would have to unwind at contribution time.

This stays reversible in the cheap direction: if per-body emission proves awkward, a registry arrives
as a pure optimisation — the outbound *gains* a `{"type": "ref", "tag": "…"}` arm rather than losing
the ones it has.

### Shipping the bytes only once

Inline delivery would otherwise re-send a module on every config change, because the config body
changes on every bandit reassignment even when the module does not. So the client declares what it
already holds, and the server omits those bytes.

This belongs in the **request body**, not a header: the fetch is already a `POST` whose JSON body
carries client facts (`platform`, `version`, `protocols: Vec<String>` — `config/fetch/request.rs`).
A `modules` field fits that existing pattern, with `skip_serializing_if` making it invisible for
clients holding none. A header would mean CRLF-safety handling plus keeping two request builders
(HTTP/1.1 and fronted h2) in lockstep for no benefit.

**Declare the version, not a hash.** `BundleStore::floors()` already returns
`BTreeMap<String, Floor>`, so "what do I hold" is a map lookup over data we already persist —
`{"bip324": 3}`. `engine/store.rs:10-13` argues the case directly: the store is keyed by name rather
than content hash because the signature already authenticates the bytes, so a hash would add a second
identity for the same thing.

Two properties this must preserve:

- **The declaration is a hint, never authorization.** If the server omits bytes and the store turns out
  not to hold the module, the client skips that outbound — which `build_members` already does safely —
  rather than failing the pool. A client that lies only degrades itself.
- **Server-side `ETag` must cover the body actually returned.** Once the response varies by what the
  request declared, an `ETag` minted for a body that *included* the bytes would let a client that just
  installed a module receive a `304` and cache a config it never fully received. This is distinct from
  the existing whole-body conditional (`request.rs:279`), which 304s rarely because the config churns;
  the two mechanisms are complementary, not redundant.

### Client flow

receive outbound → resolve `module` (inline bytes, local path, or race the mirror set) →
`BundleStore::install()` — which verifies the signature against the pinned key, enforces both
persisted floors, and writes atomically → `load(engine)` → instantiate. No release.

The store is a cache for the artifact **bytes only**, never an authorization signal: an installed
bundle is not loaded unless the live config still offers a matching, targeted outbound. A true kill
therefore depends on config freshness — see the open questions.

### Producer flow

Offline per the runbook: pull the key from Vault → build the module's `.wasm` → `sign-module bundle`
it (engine name, genomes, capabilities, module) → `sign-module verify` against the pinned pubkey →
publish the outbound to the lantern-cloud config service. Worked example, dev key:

```sh
sign-module bundle --engine bip324 --version 1 --key-pkcs8 prod-module.pkcs8 \
  --wasm modules/bip324/target/wasm32-unknown-unknown/release/bip324.wasm \
  --genome-id bip324-mainnet --genome-version 1 --engine-params 00f9beb4d9 \
  --out dist/modules/bip324.spkb
sign-module verify dist/modules/bip324.spkb --pubkey-hex "$SPARK_MODULE_PUBKEY_HEX"
```

`bundle` self-verifies against its own signing key before writing, so the separate `verify` is not
redundant: it checks the artifact against the key **clients actually pin**, which is the failure the
self-check cannot see (signing with the wrong key succeeds locally and fails everywhere else).

Everything through `verify` has landed. The publish step has not — it is the cross-repo half.

### Rollout, rollback, kill-switch

Targeting reuses the existing config machinery (region, bandit track, staged %). Three independent
safety properties, all of which already exist:

- **A bad module degrades one pool member, not the pool** — `build_members` skips it with a warning.
- **Withdrawal takes effect within a poll interval, with no reconnect** — the poll loop live-reloads
  via `pool.reload_from_config` (`fd_tunnel.rs:972-983`).
- **Downgrade to a known-bad older version is refused** by the persisted floors, which is precisely
  what routing through the store buys.

### Cross-repo scope

Both halves — the `modules` request field and the outbound schema — need lantern-cloud (Go) changes
alongside spark's. The issue reads as spark-only; it is not. Recommended sequencing: build and test
the spark side against a local fixture `config_raw.json` first, so the client path is provably working
before the lantern-cloud work is scheduled. The e2e deliverable then only needs the server to start
emitting a shape spark already parses.

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
- **`.spkb` needs the same `key_id`.** Part A delivers *bundles*, so the signer-identity change lands on
  `SPKB` too — and more cheaply: `Bundle` is a postcard envelope with an explicit `SCHEMA_VERSION`
  (currently 2) and an append-only field discipline, so `key_id` is an appended field plus a version
  bump, not a new magic. Whichever of the two formats a contributor actually ships, it is the bundle,
  since that is what carries the `capabilities` scoping a third-party module needs.
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

### Part A
1. **Config freshness bounds the kill-switch.** Withdrawal only takes effect when a client next polls,
   and the poll floor is 10s with a 10-minute default (`fetch::poll_after`). A client that cannot
   reach config-new keeps running the last module it was offered. Is "kill within one poll interval,
   assuming reachability" sufficient, or does a bad module need a faster path?
2. **Brotli, re-evaluated once something is inlined.** Measured on the 8,758 B payload: gzip 2,709 B,
   zstd −45 B (1.7%), brotli −269 B (10%). Brotli's ~120 KB static dictionary does not pay for itself
   against a <3 MB stripped binary at that size — but inlining bip324 takes the body to ~14 KB, which
   is the trigger to re-measure. Note the server currently answers `br`/`zstd` **uncompressed**, so
   this is a two-repo change too.
3. **Where the store lives on each platform.** `<data_dir>/bundles/` — `engine::store::default_dir`,
   which already existed (unused) and is now what the runtime fills in; it follows the `<data_dir>/rulesets/`
   precedent and `data_dir` is already threaded to the tunnel (`fd_tunnel.rs:1014`), but the Apple
   app-group container and the Android files dir want confirming against real deployments.
4. **Whether the mirror fetch reuses `FrontedRuleSetFetcher`.** It already fetches arbitrary URLs over
   the embedded fronting config with keep-last-known-good discipline and tag sanitisation — the same
   "must survive a censor" property. Reuse, or a module-specific fetcher?

### Part B
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
- [x] Tooling: `build-module.sh` out-dir, `sign-module verify`.
- [x] **Phase 1a — bundle producer.** `sign-module bundle` (engine, genomes, capabilities, optional
      module → signed `.spkb`), self-verifying before it writes; `sign-module verify` dispatches on
      magic so it checks either form. Covered by `sign_bundle_round_trips_through_the_verifier`,
      `sign_bundle_refuses_a_name_that_is_not_the_declared_engine`, and — the seam that matters —
      `a_tool_signed_bundle_installs_and_loads`, which drives a tool-signed artifact through
      `BundleStore::install` + `load`.
- [x] **Phase 1b — wire schema.** `RawOutbound` gained a `wasm` arm mapping to `ServerSpec::Wasm`;
      `WasmConfig` gained `source: Option<ModuleSource>` — the `rule_set`-shaped union, with
      string-or-array `url`. Inline install landed with it (`install_delivered`), because a config
      field the builder silently ignored would be worse than one that isn't there. Mirrors parse and
      fail loud as not-yet-fetchable. Covered by
      `a_wasm_outbound_becomes_a_pool_member_carrying_its_delivered_bundle`,
      `mirror_urls_accept_both_a_bare_string_and_an_array`,
      `an_unusable_wasm_outbound_is_skipped_rather_than_fatal`,
      `a_config_delivered_bundle_installs_and_becomes_a_transport`, and
      `a_bad_delivered_source_is_refused_and_installs_nothing`.
- [x] **Phase 1c (1 of 2) — install ordering + store location.** Provisioning moved out of the
      per-member build into `provision_one`, called from a **pre-pass** over every wasm outbound
      before any member is built (and once for the single-transport path, where it is fatal rather
      than logged). `default_bundle_dirs` fills an unset `bundle_dir` from the platform data dir at
      both bringup and config reload, using the pre-existing `engine::store::default_dir`
      (`<data_dir>/bundles/`); an explicitly configured store always wins. Covered by
      `an_outbound_can_use_a_bundle_a_later_outbound_delivered` (the carrier is deliberately listed
      *second*; verified to fail without the pre-pass) and
      `default_bundle_dirs_fills_only_what_config_left_unset`.
      **The ⚠️ emit-once constraint above is now lifted** — the server may send the artifact once per
      body and omit `module` from the other outbounds for that engine.
- [ ] **Phase 1c (2 of 2) — mirror fetch.** Race the URL set over the fronted machinery
      `FrontedRuleSetFetcher` already has, with the `sha256` fast-fail. Wire into pool live-reload as
      well as build. Until then a `remote` source parses and fails loud as not-yet-fetchable.
- [x] **Phase 1d — ship-once (client half).** `ConfigRequest.modules: {engine: version}`, sourced from
      `BundleStore::installed` — the floors **intersected with the artifacts on disk**, because a floor
      outlives its artifact and a floors-only list would claim an engine the store can no longer load.
      Omitted when empty, so a cold client or a non-`wasm-transport` build sends a byte-identical
      request. Both request builders serialize the same struct, so the fronted h2 path carries it for
      free. Covered by `declares_held_modules_in_the_body_and_omits_the_field_when_empty` and
      `installed_declares_only_engines_still_on_disk`.
      **Server half outstanding** (lantern-cloud): omit bytes for declared modules, and `ETag` the body
      *actually returned* — otherwise a client that just installed a module can `304` onto a config it
      never fully received.
- [ ] **Phase 1e — rollout/rollback controls** (region / track / staged %) + **E2E test**: a prod-signed
      `obfs-xor` delivered via config, installed, loaded by a client pinned to the prod pubkey, dialing
      end to end.
- [ ] Phase 1 cross-repo: lantern-cloud emits the outbound shape and honours the `modules` declaration.
- [ ] Phase 2: `.spkw` v2 (`key_id`), `SPKR` registry artifact + `sign-module registry`, root keygen +
      custody, `ModuleVerifier` multi-key + registry verification, migration/fallback.
- [ ] Phase 3: contributor onboarding doc + policy; scoped/expiring delegation; revocation flow + test.
