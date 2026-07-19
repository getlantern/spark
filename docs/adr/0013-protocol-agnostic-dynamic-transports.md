# ADR 0013 — Protocol-agnostic dynamic transports: generic primitives + opaque engine params, toward WASM+config transports with no client release

- **Status:** Proposed — 2026-07-19. Design + work breakdown: `docs/dynamic-transport-framework-design.md`.
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
   ABI additions — a **generic interactive-handshake channel** (`handshake_step(inbound) -> (outbound,
   done)`), the gap that today forces handshake protocols to be native, and a **mid-stream
   engine-composition seam** (`upgrade_to`), which unlocks the STARTTLS family (RDP, SMTP/IMAP/POP3, …).
   Datagram/UDP transport + DTLS + legacy STUN crypto (HMAC-SHA1/MD5/CRC-32) are **explicitly deferred**
   — no current forcing function; TURN's worthwhile variants ride TLS, not datagrams (design §3, §6.1).
3. **De-TLS the structure:** neutral genome (header + generic wire + opaque params), engine registry
   keyed by engine-id, open/extensible capability vocabulary, `compute_gambit` returns the neutral
   genome, discovery GA over generic shaping + per-engine param hooks.
4. **BIP324 is the forcing function and first fully-dynamic transport** — it exercises every primitive
   with nothing Bitcoin-specific in core. The ADR 0012 native engine is a documented fallback, not the
   target.

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
