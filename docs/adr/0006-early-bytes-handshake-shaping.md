# ADR 0006 — Specialize the substrate on the opening handshake (early-bytes shaping + a portable gambit + discovery)

- **Status:** Proposed — 2026-06-18. Direction for review. Builds directly on **ADR 0003**
  (dynamic transports: Tier-1 native composition / Tier-2 `wasmi` Path B) and **ADR 0001** (BoringSSL
  Chrome-mimicry TLS backend). Refines what Path B is *for* and adds a discovery loop; changes neither
  the locked stack nor the `Transport` seam.
- **Scope:** How spark concentrates its evasion effort — and its dynamic-delivery machinery — on the
  part of a flow a censor actually inspects: the opening handshake. Covers (a) what this does to Path
  B, (b) why most of it is Tier-1, (c) the ClientHello/framing/timing knob surface, (d) a *portable
  gambit* shared with the Go fleet, and (e) an automated discovery loop.
- **Prompted by:** the observation that censors classify on the first ~5 packets, plus the AnyTLS/
  Samizdat/lanturn analysis (this session) showing Path B can't do TLS-fingerprint or behavioral
  mimicry — but *can* shape the opening cheaply.
- **Analysis:** this ADR records the decision; **`docs/handshake-gambit-design.md`** expands the
  **gambit genome schema**, the executor mapping, and the **discovery harness**.

## Context

**The early-bytes fact.** Real censors run *classify-then-treat*: they bucket a flow (TLS / QUIC /
DNS / WebRTC / SSH / …) from the **first ~5 packets** — ClientHello, SNI, JA3/JA4, packet sizes,
entropy — apply per-bucket policy, then mostly stop deep-inspecting. Two corollaries: (1) the opening
handshake is where ~all the leverage is, and it's *cheap* (low volume); (2) "uncategorizable" is now
its own, increasingly *punished* bucket (entropy/fully-encrypted blocking), so **positive mimicry of
an allowed bucket beats random scrambling**.

**What spark already has.** ADR 0001's `boring2`/`btls` + the wreq-util Chrome-137 profile produces a
**byte-exact Chrome ClientHello** (spike-verified JA4 == real Chromium 149). ADR 0003's two tiers:
Tier-1 = signed config composing native primitives; Tier-2 = a `wasmi` Path B module that today is a
**whole-stream byte transform**.

**The mismatch.** Path B's whole-stream-transform shape is both the *wrong shape* and *perf-fraught*
for the thing that matters (the opening), and — the key realization — **the opening gambit is mostly a
parameterized composition of native primitives, i.e. Tier-1, not Tier-2.** Meanwhile the AnyTLS/
Samizdat/lanturn study showed mimicry's fidelity-critical pieces (the TLS fingerprint, timing) must be
native. So the substrate should be *specialized around the opening*, with the right work at the right
tier.

## Decision

1. **Specialize on the opening gambit.** Spend the polymorphism budget on the first ~5 packets — the
   **ClientHello content + TLS record framing + TCP-segment fragmentation + timing**. Everything after
   the handshake (record layer + bulk) stays native; it's past the censor's decision, so it gets
   neither manipulation nor an interpreter tax.

2. **The gambit is primarily Tier-1, not Path B.** The opening gambit is a *parameterized native
   composition*, which is ADR-0003 Tier-1's exact domain. A **static, signed gambit config** (these
   CH knobs + this padding + fragment-the-SNI-here + this jitter) needs **no WASM**. Build this first;
   it delivers the bulk of the value.

3. **Path B narrows to a handshake-shaper for the computed/novel tail.** Path B gains an
   **`open`/shape mode**: invoked once per connection, it emits a **plan** — `{CH knobs *or* CH bytes,
   record-split offsets, segment offsets + inter-segment delays}` — *not* stream bytes; the host
   executes it. Use Path B only when the gambit must be **computed per connection** (adaptive/stateful)
   or go **byte-level** (parser-differential). Two regimes:
   - **Constrained (primary):** the module sets boring's knobs; **boring stays the TLS engine and
     completes the handshake**, so the connection always works. Covers reorder/permute, GREASE,
     padding-to-size, ECH, ALPS, curve/cipher selection — plus host-controlled SNI fragmentation +
     timing. Low risk, high coverage.
   - **Unconstrained (escape hatch):** the module emits raw CH bytes and **drives the handshake
     itself** via new native crypto host fns (**X25519/ECDH, HKDF, AES-GCM** added to the Path B
     menu), for malformed/parser-differential discovery. boring can't continue a CH it didn't
     generate, so this regime owns the handshake — more power, more correctness risk; build only if
     constrained variation can't beat a given censor.

4. **boring is the engine; do not carve Cronet.** `boring2`/`btls` + the Chrome profile *is* the
   byte-exact ClientHello "parcel" (proven), at ~1–3 MB vs Cronet's 8–15 MB + Chromium build + iOS-
   dropped maintenance. **Cronet's role is CI ground-truth oracle** (capture a real Chrome CH →
   refresh the template + JA4-drift check), and separately a *future* QUIC/H3 mimicry transport — not
   a carved CH component. boring is a *parameterized assembler* (well-formed CHs only); arbitrary
   bytes / malformation / arbitrary `legacy_session_id` need the unconstrained regime or a patched
   fork.

5. **A portable "gambit" genome.** The opening gambit is a **parameter set** (CH knobs + framing +
   timing), independent of the executor. boring (Rust/spark) and **uTLS (Go/lantern)** are two
   *executors* of the same genome (they share the TLS-extension vocabulary; framing/timing is
   layer-agnostic). **Discover once, deploy across both fleets.** The genome tags per-knob executor
   needs (e.g. SessionID injection: trivial in uTLS, needs patched boring).

6. **A discovery loop, anchored at genuine Chrome (learning from Geneva).** Geneva's lesson is *the
   closed loop against an in-situ fitness signal*, not the GA per se. Search the gambit genome with a
   **hybrid GA + LLM** (the LLM grounded in the circumvention-corpus proposes/mutates and reasons
   about failures — "RST after the SNI segment → fragment the SNI / enable ECH"; the GA keeps
   diversity). **Two-tier fitness:** a cheap offline surrogate (a classifier, or an LLM-as-DPI critic)
   for the inner loop; **passive fleet telemetry** (per-config, per-region success rates) for ground
   truth — *observe* real usage, don't actively probe. **Anchor at byte-exact Chrome and mutate
   outward**, and have fitness **penalize anomaly**, not only reward got-through (mutating away from
   Chrome can make you *more* fingerprintable). Auto-discovered strategies ship via the existing
   **Ed25519-signed** delivery (ADR 0003 §4).

## The knob surface (the searchable space)

Three layers; boring owns only the first.

- **A. ClientHello content** — TLS-version list/order; **cipher order** + GREASE; **extension set +
  order** (Chrome permutes) and each extension's contents: **SNI**, supported_groups (+ PQ
  X25519MLKEM768), sig_algs, key_share, ALPN, psk_modes, OCSP/SCT, **padding** (to target size),
  cert-compression (brotli/zstd), **ALPS**, **ECH** (hide SNI), `legacy_session_id` (REALITY/Samizdat
  channel), GREASE sprinkling/permutation seed.
- **B. TLS record framing** — how the CH splits across records; `record_size_limit`.
- **C. TCP segment + timing** — **where the CH fragments across segments (esp. the SNI boundary)**,
  MSS/`TCP_NODELAY` flush points, **inter-segment timing/jitter**, first-data timing.

(uTLS is the reference for the full A-surface "every knob + raw mode"; boring exposes most of A via
its API + btls patches; B and C are host/socket-layer, not boring.)

## Consequences

**Positive.** The perf tension dissolves (substrate touches ~5 packets; bulk native). The search
space is small and aimed exactly at the censor's decision point. Most value is Tier-1 (config), so the
first phases need no WASM. The portable genome turns one discovery effort into deployments across the
Go-lantern fleet *and* spark. Anchoring at genuine Chrome gives a fidelity floor.

**Negative / risks.**
- **Anomaly floor (cuts both ways):** a variant that beats censor A's SNI matcher may trip censor B's
  "not real Chrome" detector → fitness must penalize anomaly, and the search is per-region.
- **Server compatibility constrains malformation:** fronting/REALITY to a *real* CDN means the genuine
  site must accept the CH (little malformation freedom); talking to *our own relay* gives more room.
- **Template drift:** Chrome moves → CI must re-capture the byte-exact template or the floor rots.
- **Parser-differentials are perishable + adversarial:** censors patch the differential and it can
  itself be a detection signal.
- **Auto-generated-strategy safety:** prefer evolving *parameters of vetted blocks* over generating
  WASM code; any generated code passes the signing/review gate (the sandbox bounds blast radius, but
  the signing model assumes review). This is an argument for keeping the searchable surface
  parameterized.
- **Non-stationarity:** it's continuous co-evolution, not one-shot — the loop runs forever.
- **Opsec of fitness:** active probing burns vantages and trains the censor → prefer passive,
  privacy-preserving fleet telemetry.
- **Unconstrained regime owns handshake crypto** (correctness risk; loses reuse of boring's
  maintained fidelity).

## Staged plan

| Phase | What | Tier | Path B? |
|---|---|---|---|
| 0 | Capture a byte-exact Chrome CH **template** from boring2, CI-validated vs real Chrome (JA4-drift check generalized) | tooling | no |
| 1 | **Framing/timing layer**: host-side segment fragmentation (SNI boundary) + inter-segment delays | native | no |
| 2 | **Constrained CH knobs as signed config** (order/permute/GREASE/padding/ECH/ALPS/sessionID-if-patched) → a parameterized Tier-1 gambit | Tier-1 | no |
| 3 | **Path B computes the gambit** per connection (constrained; boring stays engine) — the `open`/shape ABI | Tier-2 | yes |
| 4 | **Unconstrained**: byte-level CH + module-driven handshake via new crypto host fns | Path B | yes |
| 5 | **Discovery loop**: GA+LLM over the genome, two-tier fitness, signed deploy | R&D | — |

Value lands at **P1–P2** (buildable in spark now, testable on the existing DO relay; no Path B
change). Define the **portable genome** alongside P2, since it's the interchange format for both
executors and the search loop.

## Go / cross-fleet

Doing this from Go is **easier** for the CH-manipulation part: **uTLS** is exactly the "every knob +
raw-bytes mode" library spark lacks in Rust (full `ClientHelloSpec`, Chrome presets, SessionID
mutation — Lantern's samizdat already uses it), and **wazero** is the Go equivalent of `wasmi` (already
used by `getlantern/water`). So the Go-lantern stack already has every building block. The unifying
move (Decision 5): the discovered gambit is a **portable parameter set**, so the **Go fleet (uTLS) and
spark (boring) consume the same genome**; the discovery loop is language-agnostic. If a capability
targets lantern, Go is the lower-effort home; spark uses boring; neither blocks the other.

## Alternatives considered (rejected / deferred)

- **Carve Cronet for "just the ClientHello"** — rejected: `boring2`+profile already reproduces it
  byte-exactly; Cronet adds the Chromium build + iOS-drop burden for ~0 CH-fidelity gain. (Keep Cronet
  as a CI oracle / future QUIC-H3 transport.)
- **Full WATER / Path A (module gets a socket, does its own TLS)** — the module would carry the
  fingerprint *in WASM* → it drifts from real Chrome and runs the handshake interpreted → *inferior*
  fidelity for the early-byte surface. Keep Path A (ADR 0003) as the escape hatch for *unanticipated
  novelty/topology*, not for fingerprint mimicry.
- **Ship portable WASM modules instead of a portable gambit** — heavier, and the fingerprint-critical
  pieces want to be native anyway; the **gambit-parameter genome** is the lighter, more robust portable
  artifact across fleets.
- **Pure high-entropy obfuscation as the default** (Path B's classic sweet spot) — "uncategorizable"
  is increasingly punished; for the bucket world, mimicry > scrambling.

## References

ADR 0001 (BoringSSL Chrome-mimicry), ADR 0003 (dynamic transports / tiers / wasmi / Path A–B),
`docs/dynamic-transports-design.md`; Geneva (Bock et al., CCS 2019) + application-layer Geneva; NDSS
2024 "programmable/polymorphic protocols"; `refraction-networking/utls`; `getlantern/water` (wazero),
`getlantern/samizdat` (uTLS SessionID), `getlantern/lanturn`; memory
`m11-transport-candidates-anytls-samizdat`; spark `core/src/transport/{anytls,wasm}/`.
