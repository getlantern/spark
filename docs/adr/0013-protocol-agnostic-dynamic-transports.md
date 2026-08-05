# ADR 0013 — Protocol-agnostic dynamic transports: generic primitives + opaque engine params, toward WASM+config transports with no client release

- **Status:** Accepted — 2026-07-19; **largely implemented** as of 2026-08-04. Design + work
  breakdown: `docs/dynamic-transport-framework-design.md`. Implementation status below.
- **North star:** create and distribute a new transport as a **signed WASM module + config, runnable by
  an unchanged client** — remove the app-store release pipeline from the censorship-response loop
  (extends ADR 0003; the release pipeline is the chokepoint).
- **Scope:** generalize the opening-move / gambit framework from "a TLS gambit run by the native boring
  engine" (ADR 0006, TLS-only) to a protocol-agnostic set of **generic primitives** that a
  distributable engine composes. The core gains only generic primitives — **no TLS types and no Bitcoin
  types in core.** BIP324 (ADR 0012) is the forcing function.
- **Builds on / relates to:** ADR 0003 (dynamic transports, `wasmi` Path-B ABI), ADR 0006 (opening
  shaping + gambit + discovery — generalized here beyond TLS), ADR 0012 (BIP324 — reframed as the first
  WASM+config transport, native engine as fallback). Reuses `flint-verify` (signing) and `flint-shaping`
  (wire) unchanged.

## Context

The opening-move framework is TLS-hardwired: the `Gambit` genome (Chrome anchor + `ClientHello` +
`Records`), the sole `Profile::for_boring` executor, the closed TLS `Capability` vocabulary, the
`compute_gambit` return type, and the discovery GA all assume TLS. `flint-verify` and `flint-shaping`
are already neutral. Because of the coupling, every new transport (samizdat, hysteria2, anytls, the
BIP324 native fallback) needs native code and a client release — the exact chokepoint censorship races.

Designing BIP324 (ADR 0012) surfaced the primitives a non-TLS handshake protocol needs, and showed the
byte-transform ABI can't express an interactive handshake — which is *why* it forced a native engine.
Rather than accumulate one native engine per protocol, generalize the framework so protocols are
expressed by composing generic primitives, distributable as WASM+config.

## Decision

1. **Core = generic primitives + an opaque `engine_params` seam + an engine registry.** Nothing
   protocol-specific in core. A transport is a (WASM) engine composing host primitives + a signed
   config; TLS `ClientHello`/`Records` move into the TLS engine's param schema.
2. **Add generic primitives** (each general, exposed to WASM via the host ABI): secp256k1 +
   ElligatorSwift + X-only ECDH and raw ChaCha20 (crypto); opening random-padding with a sampled length
   distribution + scheduled decoy/cover injection, and generalize `record_fragment` (shaping); and two
   ABI additions — a **generic interactive-handshake channel** (`handshake_step(inbound) ->
   (outbound_wire, done)`), the gap that today forces handshake protocols to be native, and a
   **mid-stream engine-composition seam** (`upgrade_to`), which unlocks the STARTTLS family (RDP,
   SMTP/IMAP/POP3, …).
   Datagram/UDP transport + DTLS + legacy STUN crypto (HMAC-SHA1/MD5/CRC-32) are **explicitly deferred**
   — no current forcing function; TURN's worthwhile variants ride TLS, not datagrams (design §3, §6.1).
3. **De-TLS the structure:** neutral genome (header + generic wire + opaque params), engine registry
   keyed by engine-id, open/extensible capability vocabulary, `compute_gambit` returns the neutral
   genome, discovery GA over generic shaping + per-engine param hooks.
4. **BIP324 is the forcing function and first fully-dynamic transport** — it exercises every primitive
   with nothing Bitcoin-specific in core. The ADR 0012 native engine is a documented fallback, not the
   target.

## Implementation status (2026-08-04)

Recorded because the ADR sat at "Proposed" while most of it shipped, which makes it read as a plan
when it is now mostly a description. Decision numbers refer to the list above.

**Done.**

- **1 — core = generic primitives + opaque seam + registry.** `core/src/transport/engine/`: the
  neutral `Genome` (header + generic wire + opaque `engine_params`), `OpeningEngine`, and a registry
  resolving a name to either compiled-in code or a delivered module. Core parses no protocol.
- **2 (crypto + ABI).** secp256k1 + ElligatorSwift + X-only ECDH and raw ChaCha20 are host
  primitives; `handshake_step` and `upgrade_to` both exist, the latter with a composition test.
- **3 — de-TLS the structure.** Neutral genome, registry keyed by engine id, `compute_gambit`
  returning the neutral genome, and GA operators over generic shaping with a per-engine
  `EngineDiscovery` hook.
- **4 — BIP324 as the forcing function.** `modules/bip324` is a signed WASM transport, selectable by
  a genome's `engine` string, with nothing Bitcoin-specific in core. The ADR 0012 native engine was
  never needed.

**Done beyond what this ADR specified** — the north star ("no client release") needed a delivery and
trust story the ADR left implicit:

- Signed transport **bundles** (`SPKB`): genomes and their module signed together, which is what
  finally made `Genome.version` enforceable rather than merely carried.
- A **bundle store**, so config names an engine rather than an artifact path — the last step between
  "signed config + module" and "a server can introduce a transport".
- **Capability scoping**: a module is restricted to the host imports inside its signed grant. The
  import table is the whole sandbox boundary, so this is what makes a third-party transport a bounded
  risk.

**Not done.**

- **2 (shaping primitives).** Opening random-padding with a sampled length distribution, and
  scheduled decoy/cover injection, were never built as generic primitives. The only `random_padding`
  in the tree is Hysteria-2's own, not a shared one.
- **§7 step 5 — non-Chrome anchor set + a STARTTLS proof.** The `upgrade_to` seam RDP-SSL and
  TURNS-over-TCP need exists and is tested, but the Schannel/OpenSSL and WebRTC-TLS anchors are
  unwritten, so neither worked example has been demonstrated. This is anchor *data* authoring, not
  core code.
- **§7 step 6 — discovery generalization, in practice.** The hook is protocol-neutral and the GA
  operators evolve the neutral genome, but `TlsDiscovery` is still the only implementation. Fitness
  is scored as JA4 distance from a TLS anchor, which is meaningless for a Bitcoin opening — so
  discovery cannot yet evolve a non-TLS transport, only carry one.
- **Third-party signing.** The verifier trusts a single pinned Ed25519 key, so an outside
  contributor's module still has to be signed by us. Capability scoping makes a key set or delegation
  scheme *safe* to introduce; it does not introduce one.

## Consequences

- **Positive:** new transports expressible from the primitive set ship as WASM+config with **no client
  release**; the core stays lean and protocol-blind; `flint-verify`/`flint-shaping` reused; the TLS path
  is unchanged (it just becomes "the TLS engine"); each future cover protocol is an engine + params +
  maybe one primitive. Worked examples (design §6.1): **RDP-SSL** and **TURNS-over-TCP** both fall
  inside the envelope after only engine composition + a non-Chrome anchor set — no datagram work, no new
  crypto — while plain TURN and TURN-over-DTLS are correctly excluded (positive-fingerprint liability /
  not real browser cover).
- **Anchor-set boundary:** the TLS engine's anchor is Chrome-singular today (`flint-tls/src/anchor.rs`);
  non-browser and WebRTC anchors (+ a randomize mode, à la `covert-dtls`) are recurring config/data
  authoring, not core primitives.
- **Negative / boundary:** a genuinely new primitive (curve, cipher, ABI feature) still needs a release
  to add — the goal holds only for transports inside the primitive envelope (BIP324 is the stress test
  that makes the envelope wide). Opaque params → core can't GA/validate protocol specifics (engine
  owns that). WASM interpreter caps bulk throughput (native crypto primitives keep bulk off the
  interpreter); iOS is interpreter-only. Capability/anti-rollback negotiation grows and must fail loud,
  not silent.
