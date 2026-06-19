---
name: opening-gambit-discovery-pipeline
description: "ADR 0006 opening-gambit + discovery pipeline — what's built in spark (P1–P5 inner) and the cross-repo boundary: the P5 OUTER loop is server-side (lantern-cloud / Go), not spark"
metadata: 
  node_type: memory
  type: project
  originSessionId: b2538e8f-ad8a-4bf8-9b44-09f600c6d2c8
---

The censorship-circumvention "opening gambit" + discovery work (spark ADR 0006, design doc `docs/handshake-gambit-design.md`, public explainer = the **getlantern/opening-book** GitHub Pages site). Premise: censors classify in the first ~5 packets, so specialize the *opening* (ClientHello content + TLS record framing + TCP-segment timing) while bulk traffic stays native. See also [[m11-transport-candidates-anytls-samizdat]] (the AnyTLS/boring transport this rides on).

**Built in spark (Rust), as of 2026-06-19 — all on `main`, ~192 core tests green:**
- **Genome** (`core/src/transport/gambit.rs`): the locked-v1 `Gambit` (3 layers A=ClientHello / B=records / C=wire + `requires` + monotonic version); `SignedGambit` = Ed25519-over-canonical-postcard + anti-rollback + capability gating.
- **Both-executor mapping** (`anytls/profile.rs`): `Profile::for_boring(&Gambit)` gates a gambit's `requires` against `BORING_CAPABILITIES = [Ech, Alps, PqKem]` (declines `session_id_inject`/`raw_clienthello`) and resolves Layer-A/B onto the boring connector; unrealizable knobs logged, never silently dropped.
- **Phase 1 wire shaping** (`transport/shaping/`): SNI-boundary TCP-segment fragmentation, wired into the live AnyTLS dial path.
- **Path B compute ABI** (`transport/wasm/`): `compute_gambit` export — a wasmi module computes a `Gambit` per connection; wired into `AnytlsTransport::with_dynamic_gambit` (fail-safe to static profile). Plus the **P4 unconstrained crypto menu** (HKDF, AES-GCM, X25519 ECDH via host-held ephemeral keys) so a module can drive a TLS 1.3 handshake itself. NOTE: the P4 *module-owns-the-handshake ABI* (raw/malformed CH + module-driven handshake) is NOT built — "build only if constrained can't beat a censor."
- **Anchor / drift control** (`transport/ja4.rs` + `anytls/anchor.rs`): a spec-validated **JA4** fingerprinter + boring-ClientHello capture + a pinned `ANCHOR_JA4` (`t13d1516h2_8daaf6152771_d8a2da3f94cd`; the `8daaf6152771` cipher hash is canonical Chrome) drift test + `capture-clienthello` example tool.
- **Discovery INNER loop** (`transport/discovery.rs`): seeded GA `mutate`/`crossover` over the genome + `run_inner_loop` that realizes candidates through boring and scores JA4 fidelity vs the anchor (the cheap, no-censor pre-filter / fidelity_floor guard).

**Cross-repo boundary (the durable fact):** the discovery **OUTER loop is server-side**, NOT spark (design §5.5: "centralized search; the servers are the sensors"). It belongs in **lantern-cloud / Go**: the arrivals oracle (a connection that reaches+auths = the only fitness datum — **no client telemetry / no client→server outcome report**, since clients can't be relied on to report), the A/B bandit over gambits, server rotation, LLM warm-start/reasoning-mutation, and signed deploy. **Spark exposes the seam:** the `Gambit` genome (postcard, signable), `Profile::for_boring`, `capture_client_hello`+JA4 (inner-loop fitness), and signed wasm gambit modules. The Go fleet (uTLS executor) re-encodes the *same* genome — "discover once, deploy to both fleets." Open question: cross-fleet postcard canonicalization.

**How to apply:** when building the discovery outer loop, do it in lantern-cloud/Go against this seam — don't add server-side search/telemetry to spark (the client stays thin). Keep fitness server-side.
