# Handshake-gambit design — the portable genome + the discovery harness

Companion to **ADR 0006** (early-bytes handshake shaping). The ADR decides *what* and *why*; this doc
specifies the two things it deferred: **(1) the gambit genome** (the portable opening-gambit
specification shared across executors) and **(2) the discovery harness** (the closed loop that finds,
scores, and ships gambits). Status: **draft** — schema sketch + harness architecture for review, not
yet implemented.

Terminology: a **gambit** is the specification of a flow's *opening* — the ClientHello content, the
TLS record framing, and the TCP-segment/timing of the first ~5 packets. An **executor** runs a gambit
on the wire (`boring`/`btls` in spark/Rust; `uTLS` in lantern/Go). The genome is the *interchange
format* between the discovery loop and both executors.

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

## 2. The genome schema (sketch)

Serde/JSON-portable (the Go side decodes the same document). Illustrative, not final:

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

Notes:
- **Permutations as seeds**, not explicit orders, so a gambit reproduces Chrome's per-connection
  permutation behavior deterministically and compactly (and the search can mutate one integer).
- `padding.target_len`, `segment_split`, and `inter_segment_delay_ms` are the **highest-value, fully
  portable, well-formed** knobs — they're the first ones to wire up (ADR 0006 P1–P2).
- `session_id.inject` and a future `raw_clienthello` are the **unconstrained** class — they go in
  `requires`, get review-gated, and only run on capable executors.

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
| **session_id inject** | ❌ needs *patched* fork → `requires: session_id_inject` | ✅ mutate `HandshakeState.Hello.SessionId` |
| **raw / malformed CH** | ❌ unconstrained byte-builder + module-driven handshake (ADR 0006 P4) | ✅ `MarshalClientHello` raw mode |
| **B: record framing** | lib + socket | lib + socket |
| **C: segment split + timing** | socket-layer write control | socket-layer write control |

Takeaways: the **constrained** rows are a clean shared subset (run on both today). `session_id_inject`
runs on uTLS now, on spark only after the patched-boring work. `raw/malformed` is uTLS-now /
spark-P4. Layers B/C are layer-agnostic — both control them at the socket. So **a constrained gambit
is fully portable today; tagged gambits degrade gracefully** (an executor that can't satisfy
`requires` declines the gambit and falls back to its best portable one).

### Worked example

`{anchor: chrome-137, padding.target_len: 700, ech: grease, wire.segment_split: sni_boundary,
inter_segment_delay_ms: jitter(5,25)}` → **both** executors: emit a byte-exact Chrome-137 CH, padded
to 700 B, with ECH-GREASE, then write it as ≥2 TCP segments split at the SNI with 5–25 ms between
them. No `requires` beyond `ech`/`alps` → portable, well-formed, keeps a working handshake on boring.

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
                              │   PASSIVE fleet telemetry, per-region  │ verify the few
                              │   aggregate success of canary fetches  │
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
- **Outer (ground truth):** **passive fleet telemetry.** Clients already running a gambit report a
  per-gambit, per-region, per-epoch **aggregate** success signal (did a connection to a known-reachable
  canary complete?). We **observe real usage** — *no active probing* (which burns vantages and trains
  the censor). Privacy by design: aggregate counts only, k-anonymity thresholds before a cell counts,
  optional DP noise, no per-user traces.
- **Composite fitness = f(field_success, −anomaly, fidelity_floor).** Crucially **not** got-through
  alone: a gambit that beats one censor by becoming a glaring anomaly elsewhere must score poorly.

### 5.3 Non-stationarity & portfolio
- The censor adapts ⇒ this is **continuous co-evolution**, not one-shot. Fitness **decays**; the loop
  re-searches perpetually.
- Score and select **per region** (a winner in region A may fail in B).
- Ship a **portfolio** of good gambits per region and **rotate** among them (polymorphism), rather
  than a single global "best" (which becomes a static target).

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
- **Centralized search, fleet as sensors** is the likely shape: the GA/LLM loop runs server-side
  (cheap inner loop there), the *only* distributed part is passive telemetry + signed gambit delivery.
  This keeps the client thin and the search auditable. (A fully on-device adaptive variant is a
  later option, with a much tighter safety/telemetry story.)

---

## 6. Open questions

- **Telemetry minimality vs utility:** the smallest per-gambit/per-region signal that's still a useful
  fitness gradient *and* privacy-safe (count + region + epoch? success-rate buckets? DP budget?).
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
