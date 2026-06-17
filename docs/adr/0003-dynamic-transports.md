# ADR 0003 — Dynamically-loaded transports: tiered, a lean `wasmi` ABI (Path B)

- **Status:** Accepted — 2026-06-17. Direction decided; staged (Tier 1 first, Tier 2 next).
- **Updated 2026-06-17:** Tier 2's ABI = **Path B (spark-specific, no WASI)** as primary; WATER-ABI
  compat (Path A) is **optional/deferred** — Go/WATER-ecosystem reuse (Path A's only real advantage)
  was de-prioritized as a nice-to-have. Both paths are de-risked and prototyped (design doc §8.3/§8.4);
  the runtime choice (`wasmi`) is unchanged.
- **Scope:** How spark delivers/updates transports independently of client releases. Adds no
  coupling to the proxy core — a dynamic transport is another impl behind the existing `Transport`
  seam.
- **Analysis:** `docs/dynamic-transports-design.md` (the full design-space study, the runtime
  micro-bench §8.1, the runtime-vs-ABI analysis §8.2). This ADR records the decision; the doc is the
  reasoning.

## Context

Censorship is adversarial and fast; the **client release pipeline is itself a chokepoint** (app-store
review is days-to-weeks and globally observable). When a protocol is blocked, the response time must
be hours, not a release cycle. The fix is transports whose *logic is data* — signed, delivered
out-of-band over the existing fronting/config channel, loaded at runtime. NDSS 2024 recommends
"programmable/polymorphic protocols (Geneva, WATER/WASM, Marionette)" as the counter to host-based
ML classification. getlantern already ships WATER (Go/wazero); spark is Rust and lean (<3 MB target,
relaxed to ~10 MB; no-C-preferred; perf-sensitive; cross-platform incl. iOS).

Grounding established this session: full WASM via `water-rs` is the wrong default (wasmtime+Cranelift
~15–20 MB = 5–7× budget; wasmtime 17 has no interpreter so it won't run on iOS; the lean wasmtime
build can only run precompiled `.cwasm`, killing dynamic delivery). A runtime micro-bench (§8.1)
showed `wasmi` (interpreted WASM) is both the leanest *and* fastest interpreted option (+0.84 MB,
103 ns control-op) — beating `rhai`/`rune`. And the decisive check passed: `wasmi_wasi` (on
`wasi-common` v36, same crate `water-rs` uses) supports `push_file`/socket-as-guest-fd, so WATER's
data path ports to `wasmi` as adaptation, not reinvention.

## Decision

1. **Two tiers, primary first.**
   - **Tier 1 — config-composition of native primitives.** A signed, versioned pipeline spec
     (uTLS fingerprint + padding/timing + framing + fragmentation + prefix + mux) composing audited
     Rust blocks. Leanest (~0 added size), native speed, mobile-store-compliant, cleanest security
     (no foreign code). Extends what AnyTLS already does (server-pushed padding scheme). Covers the
     ~80% of censor responses that are recombinations/parameter tweaks. **Build this first.**
   - **Tier 2 — a `wasmi`-hosted WASM module** for genuinely novel wire formats. Runtime = `wasmi`
     (pure-Rust, no-JIT, iOS-safe; measured leanest+fastest interpreter). **ABI = Path B (primary):**
     the module is a pure byte-transform; the **host owns both sockets** and the module imports only
     native crypto/entropy host fns — no WASI, no network capability (tightest sandbox, leanest: bare
     `wasmi`, 11 KB modules). Proven end-to-end (design §8.4). **WATER-ABI compat (Path A) is
     optional/deferred** — fully de-risked (mechanism proven on `wasmi`+`wasmi_wasi`; both v0+v1 WATMs
     load), so it can be added cheaply *if* Go-ecosystem reuse ever becomes a driver, but it's not
     built now (it pulls a WASI stack + the `_water_*` choreography for compat we don't currently
     need).
2. **`wasmi`, never `wasmtime`, in the lean Rust core.** wasmtime's 15–20 MB + iOS-JIT death rule it
   out; `wasmi` is pure-Rust, no-JIT (iOS-safe), and the measured leanest+fastest interpreted option.
3. **Bulk crypto/copy stays native; interpret only the control path.** Measured: bytes-through-
   interpreter is 28× (wasmi) / ~300× (rhai/rune) slower than native — so this is an ABI requirement,
   not a guideline. Host functions expose native AEAD/hash/`rand` + the single protected upstream fd,
   nothing reaching a second egress (capability-scope via the `InsertConn`/dialer path).
4. **Integrity → authenticity.** Every delivered transport (config or module) is verified by a
   detached **Ed25519** signature against a **public key pinned in the signed binary**, plus a
   monotonic version counter (anti-rollback). (lantern-water's SHA-256-only model is insufficient.)

## Consequences

**Positive:** transports deploy in hours not release-cycles; targeted per-region without a release;
binary stays lean and reveals less; Tier 2 gives org-wide write-once-run-on-both-clients; the
`Transport` seam means zero core/forwarder churn.

**Negative / risks:** `wasmi_wasi` is `2.0.0-beta` (pin carefully) and `wasi-common` drifted 17→36
(adapt `water-rs`'s host, don't copy); Tier 2 pulls a WASI stack (wasmi_wasi+wasi-common+cap-std+
wiggle) — several MB, still ≪ wasmtime, but more than bare `wasmi`'s +0.84 MB; we build+maintain the
wasmi WATER host (none exists). iOS: `wasmi` runs (no JIT) but *downloading* a module that adds a
protocol is App-Store 2.5.2-grey → **bundle modules on iOS, download on desktop/Android.** Tier 1/2
decouple parameters/compositions/formats from releases but **not** genuinely new primitives (rare).

## Alternatives considered (rejected; see design doc §5)

- **Full WATER via `water-rs`/wasmtime** — 15–20 MB, iOS-JIT-dead, lean build can't load dynamically.
- **Embedded scripting interpreters (Rhai/Rune)** — measured larger *and* slower than `wasmi` (§8.1);
  niche guest language.
- **Downloaded native `.so` / dlopen** — no sandbox; banned on both mobile stores.
- **A purpose-built bytecode VM / transport DSL** — viable (Proteus/Marionette lineage) and tiniest,
  but you design+maintain an ISA and cap expressiveness; kept as a fallback only if `wasmi`'s size
  ever binds.

## References

`docs/dynamic-transports-design.md`; FOCI 2024 `2024-chi-just`; NDSS 2024 `2024-wails-precisely`;
local `getlantern/water` (Go/wazero), `refraction-networking/water-rs` (wasmtime, no runtime
abstraction), `wasmi_wasi 2.0.0-beta` on `wasi-common` v36; spark `core/src/transport/` + ADR 0001.
