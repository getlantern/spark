# Handshake-gambit design — the portable genome + the discovery harness

Companion to **ADR 0006** (early-bytes handshake shaping). The ADR decides *what* and *why*; this doc
specifies the two things it deferred: **(1) the gambit genome** (the portable opening-gambit
specification shared across executors) and **(2) the discovery harness** (the closed loop that finds,
scores, and ships gambits).

**Status (2026-06-22):** **partially built.** P1 (socket-layer segment/timing) and P2 (the genome +
the boring executor mapping + the `SignedGambit` envelope) are implemented in `flint-tls`
(`gambit.rs`, `profile.rs`) and `flint-shaping`; P3 (per-connection compute) has its ABI and the
offline inner-GA (`core/src/transport/{wasm,discovery}.rs`). **Not yet built:** consuming a
*server-assigned* gambit over the control plane, P4 (the unconstrained byte-builder), and P5 (the
live discovery loop, which is server-side in lantern-cloud). The genome §2 sketch below was written
ahead of the code; **§3.5 (Client realization) is the authoritative account of what the spark client
actually decodes, can realize today, and does with a gambit** — read it for the precise client-side
contract.

Terminology: a **gambit** is the specification of a flow's *opening* — the bytes a censor judges in
the first ~5 packets — **and nothing after** (§3.6). In the v1 **TLS dialect** that opening is the
ClientHello content, the TLS-record framing, and the TCP-segment/timing; the genome is
dialect-extensible to other protocols' openings (QUIC, DNS, WebRTC, HTTP, …), of which TLS is the one
realized today — see §3.7. An **executor** runs a gambit on the wire (`boring`/`btls` in spark/Rust;
`uTLS` in lantern/Go). The genome is the *interchange format* between the discovery loop and both
executors.

---

## 1. Design principles

1. **Anchor-relative.** A gambit is expressed as *deltas/choices over a named genuine-Chrome template*
   (the anchor), not from scratch. This makes the fidelity floor explicit ("never worse than this
   Chrome"), keeps the genome compact, and makes the search a *local* exploration of Chrome's
   neighborhood.
2. **Executor-portable.** The genome speaks the TLS-extension + framing/timing vocabulary that *both*
   `boring` and `uTLS` can realize. Each knob carries a capability tag so a gambit that needs more than
   an executor offers is rejected, not silently mis-run.
3. **Constrained by default.** Most knobs produce a *well-formed* ClientHello (reorder, GREASE,
   padding, ECH, ALPS, curve/cipher choice) → both executors, and `boring` stays the TLS engine.
   **Byte-level / malformed** knobs (parser-differentials, arbitrary `session_id`) are a separate,
   tagged, review-gated class.
4. **Signed + versioned.** A gambit ships inside the ADR-0003 §4 envelope: detached **Ed25519**
   signature against the binary-pinned key + a monotonic version counter (anti-rollback). Unsigned or
   rollback gambits are refused.
5. **Three layers, one of which boring doesn't own.** A=ClientHello content (executor/TLS lib),
   B=TLS record framing (lib + socket), C=TCP segment + timing (socket layer, layer-agnostic — where
   SNI fragmentation lives).

---

## 2. The genome schema (v1)

The interchange contract between the discovery loop and both executors. Serde/postcard-portable (the
canonical signing encoding; the Go side decodes the *same* document). A conformant gambit:

> **Implemented vs. specified.** This JSONC sketch is the *target* vocabulary; the **implemented**
> `flint_tls::gambit` v1 types are a deliberate subset of it. Implemented today: `genome_version`,
> `version`, `id`, `anchor`; **A** `extension_order`, `cipher_order`, `grease_seed`, `padding_target`,
> `ech`, `alps`, `pq_kem`, `session_id`; **B** `size_limit`, `split_offsets`; **C** `segment_split`,
> `delay_ms`, `delay_jitter_ms`, `tcp_nodelay`; plus `requires`. **Specified-but-not-yet-coded** (so a
> producer must not emit them yet): `origin`, `clienthello.{supported_groups.order, alpn,
> cert_compression, ext_toggles, sni, raw}`, and `wire.first_data_delay_ms`. New optional fields are
> added within v1 (defaulted, forward-compatible per §2.5); the *realizable* subset on a given
> executor is narrower still — see §3.5.

```jsonc
{
  "genome_version": 1,
  "id": "g_2026w25_003",
  "anchor": "chrome-137",            // names a byte-exact template both executors carry (§4)
  "origin": { "kind": "discovered", "generation": 14, "parents": ["g_...","g_..."] },

  // --- Layer A: ClientHello content (deltas over the anchor) ---
  "clienthello": {
    "extension_order": { "permute_seed": 91823 },     // or { "explicit": [..ext ids..] }
    "cipher_order":    { "permute_seed": 91823 },
    "grease":          { "seed": 4471 },
    "supported_groups": { "pq_x25519mlkem768": true, "order": ["x25519","p256","p384"] },
    "alpn": ["h2","http/1.1"],
    "padding": { "target_len": 700 },                  // pad CH to N bytes, or null
    "ech": { "mode": "grease" },                       // off | grease | real(config_ref)
    "alps": { "mode": "on" },
    "cert_compression": ["brotli"],
    "session_id": { "mode": "random" },                // random | resumption | inject(hex)  ← inject is tagged
    "sni": { "source": "config_domain", "omit": false },
    "ext_toggles": { "status_request": true, "sct": true, "ems": true }
  },

  // --- Layer B: TLS record framing ---
  "records": { "size_limit": null, "split_offsets": [] },

  // --- Layer C: TCP segment + timing (socket layer) ---
  "wire": {
    "segment_split": { "mode": "sni_boundary" },       // none | sni_boundary | explicit([offsets])
    "inter_segment_delay_ms": { "jitter": { "min": 5, "max": 25 } },
    "tcp_nodelay": true,
    "first_data_delay_ms": 0
  },

  // --- Capability requirements (executor gating) ---
  "requires": ["ech", "alps"]                          // e.g. add "session_id_inject" / "raw_clienthello"
}
```

Design notes: **permutations are seeds**, not explicit orders, so a gambit reproduces Chrome's
per-connection permutation deterministically and compactly (the search mutates one integer);
everything in `clienthello` is a **delta over the anchor** (absent ⇒ inherit the anchor's value).

### 2.1 Signed envelope

A gambit is delivered wrapped (ADR 0003 §4):

```jsonc
{ "gambit": { /* the document above */ },
  "key_id": "...", "version_counter": 42,
  "sig": "ed25519(detached, over the canonically-encoded gambit)" }
```

Decode **rejects**: bad signature, unknown `key_id`, or `version_counter ≤` the last accepted
(anti-rollback). `genome_version` gates schema compat; unknown *optional* fields are ignored on decode
(forward-compatible).

### 2.2 Field reference (v1)

| Field | Type | Default (= anchor) | Class |
|---|---|---|---|
| `anchor` | enum (`chrome-137`,…) | required | — |
| `clienthello.extension_order` / `.cipher_order` | `{permute_seed:u32}` \| `{explicit:[id]}` | anchor's | constrained |
| `clienthello.grease` | `{seed:u32}` | anchor's | constrained |
| `clienthello.supported_groups` | `{pq_x25519mlkem768:bool, order:[str]}` | anchor's | constrained (`pq_kem` if PQ on) |
| `clienthello.alpn` / `.cert_compression` / `.ext_toggles` | lists / map | anchor's | constrained |
| `clienthello.padding.target_len` | `u16` \| null | null | constrained |
| `clienthello.ech` | `{mode: off\|grease\|real, config_ref?}` | `grease` | `ech` |
| `clienthello.alps` | `{mode: off\|on, settings?}` | anchor's | `alps` |
| `clienthello.session_id` | `{mode: random\|resumption\|inject, hex?}` | `random` | **`session_id_inject`** if inject |
| `clienthello.sni` | `{source: config_domain\|fronted, omit:bool}` | `config_domain` | constrained |
| `clienthello.raw` | `{bytes_hex}` (overrides all of `clienthello.*`) | absent | **`raw_clienthello`** |
| `records.size_limit` / `.split_offsets` | `u16`\|null / `[usize]` | null / [] | constrained |
| `wire.segment_split` | `{mode: none\|sni_boundary\|explicit, offsets?}` | `none` | constrained |
| `wire.inter_segment_delay_ms` | `{fixed:u32}` \| `{jitter:{min,max}}` \| null | null | constrained |
| `wire.tcp_nodelay` / `.first_data_delay_ms` | bool / u32 | true / 0 | constrained |
| `requires` | `[capability-tag]` | `[]` | — |

### 2.3 Capability tags (`requires`) — closed vocabulary

An executor declines a gambit whose `requires` it can't satisfy (and falls back to its best portable
gambit). v1 tags: `ech`, `alps`, `pq_kem`, `session_id_inject`, `raw_clienthello`. **Untagged knobs
(reorder, GREASE, padding, curve/cipher choice, records, segment-split, timing) run everywhere.**

### 2.4 Classes

- **Constrained (default, untagged):** produces a *well-formed* ClientHello; boring stays the TLS
  engine; portable to both executors **today**. Layers B (records) and C (segment/timing) are *always*
  constrained.
- **Tagged (`requires` non-empty):** needs a capability beyond the well-formed-CH baseline
  (`session_id_inject`, `raw_clienthello`); **review-gated**; runs only on capable executors
  (uTLS now; spark via patched-boring / the P4 byte-builder).

### 2.5 Versioning

`genome_version` = the schema version (v1 = this doc). Optional knobs may be *added* within v1
(defaulted; ignored if unknown → forward-compatible). Removing/retyping a field bumps to v2; executors
advertise the max version they speak, and the search loop only emits gambits ≤ the min version across
the target fleet.

---

## 3. Executor mapping (what makes it portable)

| Genome knob | `boring`/`btls` (Rust/spark) | `uTLS` (Go/lantern) |
|---|---|---|
| cipher/curve/sigalg order | `set_cipher_list` / `set1_curves_list` / sigalgs | `ClientHelloSpec` lists |
| extension permutation | `permute_extensions` (seedable) | spec order / `ApplyPreset` |
| GREASE | `set_grease_enabled` | spec GREASE placeholders |
| PQ `X25519MLKEM768` | boring2 `pq-experimental` | utls group |
| ALPN, OCSP, SCT, EMS | boring setters | spec extensions |
| cert compression (brotli/zstd) | btls patch | utls compression ext |
| ALPS | btls patch | utls (ApplicationSettings) |
| ECH (grease/real) | boring ECH API | utls ECH |
| **padding to target_len** | padding ext knob | spec padding ext |
| **session_id inject** | ✅ stock boring via the `kID` recipe (P4a; `requires: session_id_inject`) | ✅ mutate `HandshakeState.Hello.SessionId` |
| **raw / malformed CH** | ❌ unconstrained byte-builder + module-driven handshake (ADR 0006 P4b) | ✅ `MarshalClientHello` raw mode |
| **B: record framing** | lib + socket | lib + socket |
| **C: segment split + timing** | socket-layer write control | socket-layer write control |

Takeaways: the **constrained** rows are a clean shared subset (run on both today). `session_id_inject`
now runs on **both** — uTLS natively, spark via the stock-boring `kID` recipe (P4a, no fork).
`raw/malformed` is uTLS-now / spark-**P4b** (the byte-builder). Layers B/C are layer-agnostic — both
control them at the socket. So **a constrained gambit is fully portable today; tagged gambits degrade
gracefully** (an executor that can't satisfy `requires` declines the gambit and falls back to its best
portable one).

### Worked example

`{anchor: chrome-137, padding.target_len: 700, ech: grease, wire.segment_split: sni_boundary,
inter_segment_delay_ms: jitter(5,25)}` → **both** executors: emit a byte-exact Chrome-137 CH, padded
to 700 B, with ECH-GREASE, then write it as ≥2 TCP segments split at the SNI with 5–25 ms between
them. No `requires` beyond `ech`/`alps` → portable, well-formed, keeps a working handshake on boring.

### 3.5 Client realization (spark/boring, TLS dialect) — the authoritative client-side contract

What the spark client actually *does* with a gambit, against the real `flint_tls` APIs. The decode →
verify → gate → realize → fall-back chain:

1. **Decode + verify** — `SignedGambit { gambit, key_id, sig }.verify(pinned_keys, floor)`: looks up
   `key_id` among the **binary-pinned** Ed25519 keys, verifies the detached signature over the
   **postcard-canonical** `Gambit`, and rejects `version ≤ floor` (anti-rollback). Returns the `Gambit`.
2. **Capability gate** — `Profile::for_boring(&gambit)` calls `gambit.check_supported(BORING_CAPABILITIES)`,
   where `BORING_CAPABILITIES = [ech, alps, pq_kem, session_id_inject]` (P4a added `session_id_inject`).
   Only a gambit whose `requires` includes `raw_clienthello` is now **declined**
   (`GambitError::Unsupported`); the caller falls back to its best portable gambit (the static config
   profile, or the Chrome-137 default). **A dynamic gambit never breaks connectivity** — boring always
   completes a handshake.
3. **Realize Layers A + B** — `Profile::resolve(&clienthello, &records)` maps the genome onto the
   boring connector's decisions (`Profile { grease, permute_extensions, pq_kem, ech_grease, alps,
   record_size_limit, extension_order, cipher_order, session_id }` — the last three added by P4a:
   explicit `Perm::Explicit` orders and a valid-hex `session_id` inject), and folds
   `records.split_offsets` into the Layer-B record-fragmenting shaper. Every knob boring2 4.15 can't
   fully honor (seeded permute, padding-to-length, raw CH) is collected into `Resolved.unrealizable` —
   **logged, never silently dropped.**
4. **Realize Layer C** — `gambit.wire_plan()` → `WirePlan` drives the native `SegmentShapingStream`
   (split the opening write into TCP segments ± inter-segment delay/jitter; `tcp_nodelay`).
5. **Dial** — boring emits the resolved ClientHello; the shaper splits/times the opening write; the
   handshake completes; the connection proceeds (Layer C then passes through — §3.6).

**Encodable ≠ realizable.** The genome can *encode* far more than boring can *realize today*. The
precise status of each knob on the spark/boring executor:

| Genome knob | boring (spark), today | Status |
|---|---|---|
| `ech` (off / grease) | honored | ✅ realized |
| `alps` | honored | ✅ realized |
| `pq_kem` (X25519MLKEM768) | honored (supported-groups) | ✅ realized |
| `records.size_limit` | honored (`record_size_limit` ext) | ✅ realized |
| `wire.*` (segment_split / delay / jitter / tcp_nodelay) | honored via the native shaper | ✅ realized |
| `grease_seed` | GREASE on/off only; exact seed not honored | ⚠️ approximated |
| `extension_order: permute_seed` | permute on/off only; seed not honored | ⚠️ approximated |
| `ech: real` | no ECHConfig wiring → uses grease | ⚠️ approximated |
| `extension_order: explicit` | honored via `set_extension_permutation` (ids → `ExtensionType`) | ✅ realized (P4a) |
| `cipher_order: explicit` | honored via ordered `set_cipher_list` | ✅ realized (P4a) |
| `records.split_offsets` | honored via flint-shaping's `RecordFragment::Offsets` | ✅ realized (P4a) |
| `session_id: inject` | honored via the `kID` recipe (`session_id_inject` capability) | ✅ realized (P4a) |
| `cipher_order: permute_seed` | ordered list only; no boring cipher-permute seed | ⚠️ approximated |
| `padding_target` | no boring2 4.15 API; needs the P4b byte-builder | ❌ ignored (logged) |
| `clienthello.raw` | requires `raw_clienthello` | ⛔ declined (cap-gated) |

So **the discoverable space on the spark client today** (after P4a) = `{ech-grease, alps, pq_kem,
record_size_limit, GREASE on/off, extension-permute on/off, explicit extension order, explicit cipher
order, session_id inject}` (Layer A) × `{record split-offsets}` (Layer B) × the **full** Layer-C wire
knobs. Only the remaining byte-exact Layer-A moves — an exact GREASE/permute **seed**,
**padding-to-length**, and a **raw ClientHello** — still light up only with the **P4b byte-builder**
(spark) or on the **uTLS fleet** (Go), and the capability tags keep that honest: a gambit needing more
than boring offers (today, just `raw_clienthello`) is declined, never mis-run.

### 3.6 Scope: a gambit is the *opening* only (+ a reserved Layer D)

Layers A/B/C all govern the **opening**. The native shaper shapes **only the opening write (the
ClientHello)** and then **passes through untouched for the rest of the connection**; once the
handshake completes, the gambit's job is done. What happens to traffic *after* the early bytes is the
**transport's data plane, not the gambit's** — for AnyTLS the server-pushed padding scheme
(`cmdUpdatePaddingScheme`, record-size shaping) + stream mux; for hysteria2 the QUIC framing +
Salamander/Gecko obfs. This split is deliberate (the opening-book thesis: the censor's verdict comes
early, the leverage is in the opening, and the opening is cheap — a few hundred bytes, once per
connection). The data plane is high-volume, expensive to shape, and already owned per-transport.

**Reserved Layer D (post-opening).** So the discovery loop *can* grow into data-plane shaping later
without a v1 break, the genome reserves a `genome_version`-gated **Layer D: `post_opening`** slot —
the future home for e.g. a record-size distribution, inter-record timing, or padding/chaff policy. It
is **unspecified and unimplemented in v1**: a v1 executor ignores an absent Layer D
(forward-compatible, §2.5). Introducing Layer-D fields that *change behavior* bumps the genome to v2,
and at that point the transport and the gambit must agree on **who owns data-plane shaping** (the
gambit or the transport's own scheme) to avoid double-shaping. This is a documented reservation, not
code.

### 3.7 Protocol dialects — the gambit beyond TLS

A gambit shapes a flow's **opening**, and an opening is whatever a protocol leads with — not
necessarily a TLS ClientHello. The genome's structure — a signed, versioned, anchor-relative set of
opening deltas, scored by what reaches the server — is **dialect-agnostic by design**: a template for
*any* opening whose fingerprint a censor judges in the first packets. **TLS is the first dialect, not
the boundary** — the one realized in the client today (§3.5), with the rest of the family on the
roadmap.

A **dialect** binds the genome to one protocol's opening: the protocol's anchor (a genuine sample of
its real traffic), the layers that opening exposes to shaping, and the executor that emits them.
Everything else — signing, versioning, capability-gating, anchor/drift control, the discovery loop —
is reused **unchanged** across dialects; only the opening surface and the executor differ. The
intended family:

| Dialect | The opening it shapes | Status |
|---|---|---|
| **TLS** | ClientHello content + TLS-record framing + TCP segment/timing (Layers A/B/C), on boring/btls (spark) and uTLS (Go) | ✅ **realized** — the v1 dialect (§3.5) |
| **QUIC** | the QUIC Initial — an encrypted ClientHello inside QUIC crypto frames — plus the UDP datagram shape | roadmap (hysteria2 already shapes its QUIC opening via Salamander/Gecko; a dialect folds that into the genome) |
| **DNS** | the query itself — name encoding, EDNS options, transport (Do53 / DoT / DoH) — the resolution every flow needs first | roadmap |
| **WebRTC** | the STUN binding + DTLS handshake — the shape of every video call | roadmap |
| **HTTP** | the request line + headers, and CDN-fronting (a `Host`≠SNI / ECH-fronted opening — i.e. domain fronting / meek) | roadmap |
| **STARTTLS-pattern** (RDP, SMTP/IMAP) | a cleartext line-protocol prelude on a fixed port before the inline TLS upgrade | roadmap |
| **TURN/STUN** | the STUN magic-cookie framing on the media ports (3478 / 5349) | roadmap |

Each dialect inherits its protocol's **collateral-freedom** and takes the **port** it speaks on as
part of the move — block the port and you block the real thing that lives there. The roadmap dialects
are **not yet realized in the client** (only the TLS dialect is built today), but they are the
deliberate shape of the genome, not an afterthought: adding one is a new opening surface + executor
binding, **not a new genome**. v1 ships the TLS dialect; the dialect family is how the book widens.

---

## 4. The anchor template + drift control

- An **anchor** (`chrome-137`, …) is a byte-exact Chrome ClientHello, captured from `boring2`+profile
  and **CI-validated against a real Chrome/Cronet** (the JA4-drift check, generalized). Both executors
  carry the same anchors (boring reproduces it; uTLS via its matching preset).
- A CI job (the existing JA4 spike, scheduled) re-captures from a live Chrome on a cadence, fails on
  drift, and proposes a refreshed anchor. Anchors are versioned; a gambit names its anchor, so an old
  gambit against a retired anchor is flagged.
- **Cronet's only role here is oracle** — ground truth for capture/validation — never a shipped
  component (ADR 0006 Decision 4).

---

## 5. The discovery harness

```
 circumvention-corpus ──grounds──▶ LLM (proposer / mutator / DPI-critic)
                                          │  proposals are just genomes — no trust; all go through fitness
 gambit population ──▶ operators ─────────┤
   (GA: mutate/crossover/select           │
    + LLM reasoning-mutations)            ▼
                              ┌─ inner fitness (cheap, offline, safe) ─┐
                              │   surrogate censor (classifier / LLM)  │ filter thousands
                              │   + anomaly score + fidelity-vs-anchor │
                              └────────────────┬───────────────────────┘
                                               ▼  survivors only
                              ┌─ outer fitness (ground truth) ─────────┐
                              │  SERVER-OBSERVED arrivals per (gambit,  │ verify the few
                              │  region); A/B over sub-populations;     │ (no client telemetry)
                              │  rotation isolates gambit vs server     │
                              └────────────────┬───────────────────────┘
                                               ▼
              selection (per-region niches + novelty; keep a PORTFOLIO, not one winner)
                                               ▼
                 review gate ──▶ Ed25519-sign + version ──▶ signed delivery ──▶ fleets (boring + uTLS)
                                               ▲                                        │
                                               └─────────── telemetry closes the loop ──┘
```

### 5.1 Search operators
- **GA:** mutation (perturb one knob: bump a permute_seed, toggle an extension, shift a segment offset
  or delay, change padding target), crossover (recombine layers A/B/C across two gambits — layers are
  natural crossover units), tournament selection, **diversity/novelty pressure** (so the population
  doesn't collapse onto one fingerprint — which would itself become an anomaly).
- **LLM (grounded in the corpus):** (a) **warm-start** with educated gambits ("for SNI-keyword
  blocking, try SNI fragmentation + ECH"); (b) **reasoning-mutation** — given a gambit + its failure
  signal, propose a *targeted* delta ("RST right after the SNI segment ⇒ move the split to the SNI
  boundary, or enable real ECH"); (c) **surrogate DPI-critic** for the inner loop. LLM output is never
  trusted — it's a genome that must pass the same fitness gate.

### 5.2 Fitness — two tiers
- **Inner (cheap, fast, no censor contact):** an offline **surrogate censor** — a trained classifier
  and/or an LLM-as-DPI scoring (i) **bucket-match** ("would DPI classify this as Chrome TLS?"), (ii)
  **anomaly** ("how distinctive/abnormal is it?"), and (iii) **fidelity vs the anchor** (how far from
  genuine Chrome). Pre-filters the population before any field trial.
- **Outer (ground truth) — the *server* is the oracle (no client telemetry).** A gambit "works" iff a
  connection using it **reaches and completes auth to one of our servers.** The server logs, per
  *successful* connection only, the **gambit id** (signaled by the client inside the authenticated
  tunnel once connected), a **coarse region** (source-IP geo), and the **epoch + server id** → fitness
  is the **arrival rate per (gambit, region)**. There is **no client phone-home and no separate
  telemetry channel** — *a working proxy connection is itself the success datum*, which is both simpler
  and more private than client reporting. The server inherently can't see *failures* (a blocked attempt
  never arrives), so absolute success-rate isn't directly observable — resolved by comparison + rotation
  (§5.3).
- **Composite fitness = f(arrival_rate, −anomaly, fidelity_floor).** Crucially **not** arrivals
  alone: a gambit that beats one censor by becoming a glaring anomaly elsewhere must score poorly (the
  inner-loop anomaly score guards this before a gambit ever reaches the population).
- **Per-connection module adaptation is local-only, never a report.** A stateful P3 module (the
  per-connection gambit computer) may adapt to outcomes the *host already observes locally* — did this
  handshake complete? did the connection survive? — fed in as module input with **no network
  round-trip**. There is deliberately **no client→server outcome-reporting export**: we can't
  universally rely on a client being able to report (the reporting channel can itself be blocked or
  fingerprinted, and many clients can't report at all). Authoritative fitness stays **server-side**
  (the arrivals oracle above); a client-local signal only steers a module's *own* next move, and a
  module that can't observe outcomes still works — local adaptation is an optimization, never a
  dependency.

### 5.3 Comparison, server rotation & non-stationarity
- **Comparative A/B, not absolute rates.** Since the server sees only arrivals (no denominator),
  *compare* candidate gambits assigned across **comparable client sub-populations** in a region and
  pick the one with the higher **arrival volume** — a multi-armed bandit over gambits. Relative volume
  over comparable populations ≈ relative success, so no failure-reporting is needed.
- **Client fallback ladder supplies the negative signal implicitly.** A client tries its assigned
  gambits until one connects; the server observes *the one that worked*. Natural client behavior +
  server-observed arrivals ⇒ "which gambit ends up working most in region R" without explicit failure
  reports.
- **Server rotation isolates gambit-quality from server-blockedness.** Servers are ephemeral (IPs
  burn → rotate). If a server's IP is blocked, *all* gambits to it drop together — a *server* signal,
  not a gambit signal. A gambit's quality is its arrival rate **across multiple fresh servers**;
  comparing gambits *per server* and servers *over time* separates the two. **Gambit search and server
  rotation co-evolve against the live fleet** — they are one system, not two.
- **Non-stationary.** The censor adapts ⇒ continuous co-evolution, not one-shot. Fitness **decays**;
  the loop re-searches perpetually.
- Score/select **per region** (a winner in A may fail in B); ship a **portfolio** of good gambits per
  region and **rotate** among them (polymorphism), never a single global "best" (a static target).

### 5.4 Deployment gate & safety
- Every shipped gambit passes a **review/policy gate** before signing — stricter for `requires`
  tagged with `session_id_inject` / `raw_clienthello` (the malformed/unconstrained class).
- **Prefer evolving parameters of vetted blocks over generating code:** a constrained genome *cannot*
  express an unsafe transport, only a recipe of safe pieces. If the unconstrained byte-builder (P4) is
  ever in play, its outputs get the strongest review (the sandbox bounds blast radius, but the signing
  model assumes review).
- Sign (Ed25519, pinned key) → version-counter → deliver over the existing signed config/transport
  channel → both fleets consume by genome.

### 5.5 Where the loop runs
- **Centralized search; the *servers* are the sensors.** The GA/LLM loop runs server-side, *with* the
  servers' arrival logs (the fitness signal originates exactly where the search lives). The only
  things crossing to clients are **signed gambit assignments** (which gambits to try, for the A/B
  bandit) going out, and **successful connections** coming in (the implicit fitness). The client stays
  thin and carries no telemetry logic; the search is fully auditable server-side. (A fully on-device
  adaptive variant is a later option with a much tighter safety story.)

---

## 6. Open questions

- **Gambit-id signaling:** how the client conveys its gambit id to the server *inside the
  authenticated tunnel* (so attribution can't be spoofed/observed by the censor), and at what
  granularity region is derived from the source IP without storing per-user data.
- **A/B assignment + bandit design:** how to split comparable sub-populations per region, the bandit
  policy (explore/exploit), and how much the missing denominator (server sees only arrivals) biases
  selection — plus whether a coarse assignment count is worth keeping as an approximate denominator.
- **Coupling search with server rotation:** the search runs against an ephemeral, rotating server
  fleet — how to schedule rotation vs. evaluation windows so a gambit is judged across enough fresh
  servers to separate gambit-quality from server-blockedness.
- **Surrogate-censor fidelity:** how well an offline classifier/LLM predicts a real censor — risk that
  the inner loop confidently mis-ranks. Calibrate the surrogate against outer-loop ground truth.
- **Shared-knob vocabulary:** enumerate + *test* the exact constrained subset that boring and uTLS
  realize identically (byte-for-byte JA4 parity per knob), so "portable" is verified, not assumed.
- **Exploration budget:** field trials per region before a gambit is trusted/retired; cold-start
  (human + LLM seeds) before telemetry exists.
- **Patched-boring scope:** how much of `session_id_inject`/raw-CH spark needs vs deferring those
  gambits to the Go fleet.

---

## 7. Build order (per ADR 0006)

P0 anchor capture + CI drift check → P1 socket-layer segment/timing (SNI fragmentation) → P2
constrained CH knobs as signed config (the Tier-1 gambit; define this schema alongside) → P3 Path B
computes the gambit (constrained) → P4 unconstrained byte-builder + crypto host fns → P5 the harness
above. **The genome schema (§2) is the artifact to lock down at P2**, because it's the contract for
the executors *and* the search loop.
