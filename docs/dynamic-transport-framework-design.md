# Protocol-agnostic dynamic transports — design

- **Status:** Proposed — 2026-07-19. Recorded as **ADR 0013**. Extends **ADR 0003** (dynamically-loaded
  transports / the `wasmi` Path-B ABI) and generalizes the opening-move framework of **ADR 0006**
  (which is TLS-only today). No code yet.
- **North star:** be able to **create and distribute a new transport as a signed WASM module +
  config, runnable by an unchanged client** — no client release in the loop. Censorship is fast; the
  app-store release pipeline is the chokepoint (ADR 0003 §1). A transport we can ship in hours is worth
  more than a perfect one gated on a weeks-long release.
- **Scope:** generalize the opening-move / gambit framework from "a TLS gambit executed by the native
  boring engine" to "a protocol-agnostic set of **primitives** that a distributable engine composes."
  The core gains only *generic* primitives; nothing protocol-specific (no TLS types, no Bitcoin types)
  lives in it. BIP324 (`docs/bitcoin-transport-design.md`, ADR 0012) is the **forcing function** that
  defines the primitive set and the first transport to prove the model end-to-end.

## 1. Today: the framework is TLS-hardwired

Two layers are already protocol-neutral and stay as-is:

- **`flint-verify`** — Ed25519 + versioned framing + anti-rollback. Both spark's `SignedModule`
  (`core/src/transport/wasm/signing.rs`) and flint's `SignedGambit` build on it.
- **`flint-shaping`** — Layer-C `WirePlan` (segment splits, inter-segment delay, `tcp_nodelay`).

Everything else assumes TLS (`flint ·` = the `getlantern/flint` repo; `spark ·` = this repo):

| Piece | Repo · path | TLS coupling |
|---|---|---|
| genome `Gambit` | flint · `crates/flint-tls/src/gambit.rs` | bundles a generic header (`id`/`version`/`requires`/`wire`) with `anchor: Chrome137` + Layer-A `ClientHello` + Layer-B `Records` |
| executor `Profile::for_boring` | flint · `crates/flint-tls/src/profile.rs` | the *only* engine — resolves the genome onto the boring/btls TLS connector |
| `Capability` vocabulary | flint · `crates/flint-tls/src/gambit.rs` | closed set, all TLS (`Ech`/`Alps`/`PqKem`/`SessionIdInject`/`RawClienthello`) |
| `compute_gambit` return type | spark · `core/src/transport/wasm/mod.rs`, `core/src/transport/mod.rs` | returns a `flint_tls::gambit::Gambit` |
| discovery GA | spark · `core/src/transport/discovery.rs` | `mutate`/`crossover` operate on ClientHello/records/wire |
| `record_fragment` | flint · `crates/flint-shaping/src/lib.rs` | TLS-record-shaped, in the otherwise-generic shaper |

Consequence: **every new transport today needs native code + a client release** — samizdat, hysteria2,
anytls, and (as currently specced) the BIP324 native-engine fallback are all native. That is exactly
the release-pipeline chokepoint the north star is trying to remove.

## 2. The model: generic primitives + opaque engine params + an engine registry

- The genome carries a **generic header** (`id`, `version`, `requires`), a **generic wire-shaping
  plan**, and an **opaque, signed `engine_params` blob** that only the engine interprets. The core
  validates signature / version / capabilities and hands the params to the engine — it never parses
  them.
- An **engine registry** keyed by engine-id routes a plan to its engine. Engines are protocol-specific
  and live *outside* the core; the core is protocol-blind.
- A **transport = a (WASM) engine that composes host primitives + a signed config** (the params /
  gambit). Both are signed, versioned, capability-gated, and delivered over the existing config /
  fronting channel — so a new transport is a distribution artifact, not a code release.
- TLS `ClientHello`/`Records` stop being core types — they become the *TLS engine's* param schema
  (staying in `flint-tls`). Bitcoin's params live in the Bitcoin engine. The core mentions neither.

The performance escape hatch (ADR 0003 §2) is what makes WASM engines viable: **heavy per-byte crypto
runs natively via host primitives; the module runs only the light, changeable choreography**
(handshake sequencing, framing, param interpretation). WASM-interpreter overhead is irrelevant for
RTT-bound handshakes and is never on the bulk-crypto path.

## 3. The generic primitives to add (Bitcoin exercises them; all general)

This is the heart of "the primitives we need, nothing protocol-specific." Each is a general capability
usable by many transports, exposed to WASM modules via the host `env` ABI:

1. **Crypto menu** — add **secp256k1 keygen + ElligatorSwift encode/decode + X-only ECDH** and a **raw
   ChaCha20 stream** cipher, alongside the existing X25519 / AES-GCM / ChaCha20-Poly1305 / HKDF-SHA256 /
   SHA-256 / CSRNG. secp256k1+ellswift is a general curve + uniform-point encoding (Bitcoin, Nostr,
   others); raw ChaCha20 is a general stream cipher. Neither is "BIP324."
2. **Shaping** (`flint-shaping` today has only `segment_split` + `inter_segment_delay` + `tcp_nodelay`
   + the TLS-ish `record_fragment`) — add **opening random-padding with a sampled length distribution**
   and **scheduled decoy / cover-traffic injection**, and **generalize `record_fragment`** (or move it
   into the TLS engine). "Garbage of length uniform[0,4095]" and "decoy packets" then become a transport
   *parameterizing generic knobs*, not core concepts.
3. **ABI — two additions.** (a) **A generic interactive-handshake channel.** Today's byte-transform
   pair (`transform_out(app)→wire`, `transform_in(wire)→app`) cannot express an interactive opening: no
   channel for an inbound read to trigger an outbound wire write, and no emit-at-connect. Add a generic
   handshake driver (e.g. `handshake_step(inbound) -> (outbound_wire, done)`) so *any* interactive-
   opening protocol runs in the sandbox. **This is the single most important addition** — it is the gap
   that today forces handshake protocols to be native. (b) **Engine composition — a mid-stream
   sub-engine upgrade** (`upgrade_to(sub_engine)`). Today an engine owns a connection end to end;
   STARTTLS-shaped protocols (cleartext prelude on a fixed port, then an inline TLS upgrade on the
   *same* connection) can't be expressed because one engine can't hand the live byte-stream to another
   (typically the TLS engine) and resume. This unlocks the whole STARTTLS family — RDP, SMTP/IMAP/POP3,
   XMPP, LDAP, FTPS — as composed engines instead of native code. The boring connector already takes an
   *established byte stream* (`connect<S: AsyncRead + AsyncWrite + Unpin>(stream, sni, profile)` in
   `flint-tls/src/connector.rs`), so the handoff is mechanically close; the missing pieces are the
   orchestration seam and non-Chrome anchors (§6.1).

**Deferred primitives — named, not built (no current forcing function).** Keeping the set driven by
real transports, not speculation: a **datagram/UDP transport + per-packet ABI + DTLS handshake mode**
(forcing function = DTLS-SRTP UDP-media cover, which Lantern already ships *outside* spark in Unbounded
`common/covertdtls/`; no spark transport needs it, and TURN does **not** justify it — §6.1), and
**legacy fidelity crypto** (HMAC-SHA1 / MD5 / CRC-32, only needed for plain STUN/TURN on 3478, which
§6.1 concludes we should not pursue). Revisit only when a UDP-media cover enters spark's scope.

## 4. Structural de-TLS-ing (removes coupling, adds nothing protocol-specific)

4. **Neutral genome** = header + generic wire plan + opaque `engine_params` (reuses `flint-verify` +
   `flint-shaping` unchanged). Home it in a protocol-neutral crate (`flint-gambit`) or spark
   `core/src/transport/gambit/`. TLS's `ClientHello`/`Records` become the TLS engine's param schema.
5. **Engine registry** keyed by engine-id / capability; each engine decodes its own params. `for_boring`
   becomes "the TLS engine" behind the seam — no behavior change to the TLS path. Its **anchor is
   Chrome-singular today** (`flint-tls/src/anchor.rs` pins one Chrome-137 JA4); the TLS engine grows an
   **anchor *set*** — non-browser stacks (Schannel, OpenSSL) and a WebRTC profile, plus a per-connection
   randomize mode — carried as signed config/data, not as a core primitive (§6.1).
6. **Open/extensible capability vocabulary** — capabilities name the *generic host primitives* above,
   so adding a transport that needs a new primitive doesn't force edits to a closed core enum.
7. **`compute_gambit` returns the neutral genome;** the discovery GA mutates the generic shaping knobs
   generically and delegates protocol-param mutation to an optional per-engine hook.

## 5. BIP324 as the forcing function / first fully-dynamic transport

BIP324 exercises **every** primitive above — secp256k1/ellswift, raw ChaCha20, the interactive
handshake, opening random-padding (garbage), decoy injection — **without** adding one Bitcoin concept
to the core. Its Bitcoin-specific parts (handshake sequence, garbage semantics, the keyed-garbage
side-door MAC, message framing, port 8333) live entirely in the Bitcoin engine + its signed config.
Proving BIP324 as **WASM module + config** validates the whole model: if a protocol this demanding
(custom curve, interactive handshake, custom framing) ships without a client release, the framework has
met the north star.

**Sequencing / fallback (honest):** the native BIP324 engine in ADR 0012 remains a documented fallback
for the initial ship or if the interpreter can't meet the interactive-handshake bar — but it does *not*
advance the north star (each native transport needs a release). The strategic investment is the core
primitives + handshake ABI (§3), after which BIP324 is authored as WASM+config and every subsequent
transport is too.

## 6. Distribution & the boundary of the goal

Delivery reuses the signed path: Ed25519 (`flint-verify`), key-pinned, versioned (anti-rollback),
capability-gated, over the config/fronting channel (HTTPS + BitTorrent-magnet per `lantern-water`). The
client advertises the **capabilities** (primitives + ABI features) it provides; a transport's
module+config declares `requires`; the client runs it iff supported.

**The honest boundary:** a transport expressible from the **existing** primitive set ships as pure
WASM+config — **no release**. A transport needing a **genuinely new primitive** (a curve, cipher, or
ABI feature the host doesn't expose) still gates on a client release to add that primitive. The design's
job is to make the primitive set rich enough that the second case is rare. BIP324 is the stress test:
after its primitives land, the set covers "interactive handshake + AEAD stream + uniform-key KEX +
opening shaping" — most cover-protocol transports fall inside that envelope.

### 6.1 Worked examples: RDP and TURN (what "inside the envelope" costs)

Two candidate cover protocols make the boundary concrete. Both mostly ride TLS — but *not* the
Chrome-HTTPS profile the engine pins today, so "**what** TLS?" is the real question, and the answers
diverge by variant:

| Variant | TLS? | Stack | Verdict |
|---|---|---|---|
| **RDP** modern, TCP/3389 | yes — real TLS **after** a cleartext X.224 prelude (STARTTLS) | Schannel (mstsc.exe) / OpenSSL (FreeRDP, xrdp) — never Chrome | **Pursue.** Needs the `upgrade_to` engine-composition seam (§3) + a Schannel/OpenSSL anchor (§4) + a real `xrdp` backing. Crypto is free (existing connector) |
| **TURNS-over-TCP**, best on 443 | yes — TLS wrapping the whole TURN exchange | WebRTC BoringSSL / NSS / Apple / Schannel | **Pursue.** Reuses the TLS engine wholesale + a WebRTC-TLS anchor + a real `coturn`. The only high-value TURN variant |
| **Plain TURN**, UDP/3478 | **no** — raw STUN, cleartext control plane | n/a | **Skip.** The magic-cookie shape is a *positive-fingerprint liability* (classified from one packet), has no collateral umbrella, no prior art — it would cost the whole deferred datagram + legacy-crypto bill for negative value |
| **TURN-over-DTLS**, UDP/5349 | DTLS | — | **Not real cover.** RFC 8835 browsers dial `turns:` over TCP+TLS only, never UDP+DTLS; real WebRTC UDP-DTLS is DTLS-SRTP media on ephemeral ports — the **cover-dtls** surface, not TURN |

So both worthwhile variants (RDP-SSL, TURNS-over-TCP) fall **inside** the envelope after two cheap,
protocol-agnostic additions — the **`upgrade_to` engine-composition seam** (§3) and a **non-Chrome anchor set** (§4) —
with *no* datagram transport and *no* new crypto. The recurring config-layer cost is anchor authoring:
one profile plus its JA4/JA4D validation per stack.

**Caution for any DTLS-adjacent path:** `pion/dtls`'s default ClientHello is a *blocked* fingerprint —
TSPU/Russia matched it in March 2026 (net4people#603), breaking Snowflake. Any DTLS transport must
randomize per-connection or replay a real browser exactly (Psiphon's `covert-dtls`, already vendored in
Unbounded). That live attack surface is precisely why the datagram/DTLS primitive stays *deferred*
rather than speculative — it belongs in scope only with a concrete UDP-media cover target.

## 7. Work breakdown

Critical path (each builds on the last):

1. **Neutral genome + engine-registry seam** — extract header + opaque `engine_params`; make the
   existing TLS path "the TLS engine." No new transport, no behavior change. (Lowest-churn first step.)
2. **Generic primitives** — crypto (secp256k1/ellswift, raw ChaCha20), shaping (opening padding from a
   distribution, decoy injection; generalize `record_fragment`), each exposed as a host capability.
3. **ABI — interactive handshake + engine composition** — the `handshake_step` channel (enabler for
   handshake protocols in WASM) and the `upgrade_to` sub-engine seam (enabler for the STARTTLS family).
4. **BIP324 as a WASM engine + signed config** — the first fully-dynamic transport, composing 1–3.
   (Native engine per ADR 0012 only as fallback.)
5. **Non-Chrome anchor set + a STARTTLS proof (RDP-SSL / TURNS-over-TCP)** — author the Schannel/OpenSSL
   and WebRTC-TLS anchors and validate one composed engine end to end (§6.1). No datagram work — that
   primitive stays deferred.
6. **Discovery generalization** — GA over the generic shaping knobs + per-engine param hooks.

**Status (2026-07-21):** steps 1–4 and 6 are **complete** — the engine seam + neutral genome + generalized
discovery, the crypto primitives, `handshake_step` + `upgrade_to`, and **BIP324 shipped end to end as a
signed WASM module + config** (PR1 `bip324-core` → PR2 the guest → PR3 dial-path wiring → PR4a/b/c the
side-door egress + rust-bitcoin interop; see the step-4 detail below). Only step 5 (non-Chrome anchors +
a STARTTLS proof) remains, independent of BIP324. The historical narrative below is kept as written.

Step 4's original prerequisite — the **Rust→wasm32 build-and-sign pipeline** that was missing (every
module was inline
prerequisite — the **Rust→wasm32 build-and-sign pipeline** that was missing (every module was inline
`wat!`) — now exists. `modules/obfs-xor` is a reference guest module compiled and signed by
`scripts/build-module.sh` (via the `sign-module` tool, `--features module-signer`) into a committed
`.spkw` fixture that a toolchain-free `cargo test` loads through the production
`ModuleVerifier::pinned().verify` path and round-trips.

**Step 4 in progress (2026-07-20):** the BIP324 protocol logic now lives in a sans-io **`bip324-core`**
crate (`no_std`, zero runtime deps) generic over a crypto-provider trait — the ellswift tagged-hash
ECDH, HKDF key schedule, FSChaCha20 length cipher, FSChaCha20Poly1305 rekeying packets, and the
both-roles handshake state machine. It is validated byte-exact against the official BIP324
packet-encoding vectors (incl. the 224-message rekey boundary) and a core-vs-core handshake round-trip.
The WASM guest **`modules/bip324`** now wraps it: a host-fn `Bip324Crypto` provider (a mechanical 1:1
shim of the `env` primitives) + the `init` / `handshake_step` / `transform_*` ABI, built + signed into a
committed `bip324.spkw`. Validated end-to-end by running an initiator + a responder instance against each
other through the real `TransformModule` runtime (handshake + app round-trip incl. a fragmented,
past-the-rekey burst) — a full BIP324 transport as a signed WASM module + config, crypto entirely via
host primitives. The interactive handshake is now **wired into the dial path** (PR3): `WasmTransport`
(client/initiator) and `WasmServer` (server/responder) each run `run_handshake` on the raw connection
before the steady-state transform, gated on a protocol-blind `Transform::drives_handshake()` (run it iff
the module exports `handshake_step`; transform-only modules like obfs-xor are unaffected) — reusing
`ServerSpec::Wasm` / `WasmConfig` with no schema change (`init_config` was `role ++ magic ++ garbage`
at PR3 — later extended with a `k_srv_len ++ k_srv` field for the side-door in PR4b-1, see below; the
outer `WasmConfig` still carries the opaque `init_config` blob unchanged).
Validated by a real-TCP loopback tunnel (client ↔ server, both handshaking, byte round-trip through the
BIP324 tunnel to an echo). PR3 also fixed the coalescing bug the streaming path surfaced, in two places:
the handshake's leftover bytes (the peer's first steady-state packet, coalesced with the handshake over
TCP) must seed the session's receive buffer in `bip324-core`, **and** the host `TransformStream::poll_read`
must drain those buffered bytes before its first wire read (otherwise it blocks on bytes already inside
the module — this is the boundary contract: after a handshake the host drains the module first).

**PR4a landed (2026-07-20): the keyed-garbage side-door MAC in `bip324-core`.** A tunnel client
(initiator) prepends `tag = HMAC-SHA256(k_srv, DOMAIN ‖ ellswift)` (domain-separated) to its opening garbage; a Lantern egress
sharing the per-server secret `k_srv` recomputes the tag from the client's ellswift and matches it
against the leading garbage — a match routes to the BIP324 tunnel, a mismatch (a real Bitcoin peer, whose
garbage is random and who lacks `k_srv`) proxies to the real node. The tag keys on the *ephemeral*
ellswift, so it is unique per connection with **no clock** (a captured `(ellswift, tag)` can't complete a
handshake, so replay confirms nothing) — and HMAC reuses the provider's existing `hkdf_extract`
(HKDF-Extract *is* HMAC), so the whole side-door adds **no new host primitive** and stays release-free.
`Handshake::with_side_door(k_srv)` weaves the tag into the initiator's opening (it counts toward the
garbage AAD, so the peer authenticates the same bytes it scans past); `verify_side_door_tag` is the
egress's constant-time check.

**PR4b split into two slices; PR4b-1 landed (2026-07-21): the guest wiring.** The `modules/bip324` guest
`init` config grew a `k_srv` field — `[role][network_magic(4)][k_srv_len: u16 BE][k_srv][garbage]` — and
the guest passes `k_srv` to `Handshake::with_side_door` (a no-op for an empty key or the responder). So a
client instantiated with a non-empty `k_srv` now emits the side-door tag ahead of its garbage, entirely
via the signed WASM module — no host code knows about Bitcoin or the side-door. The `bip324.spkw` fixture
was regenerated; a module-level test drives a `k_srv`-configured initiator against a plain responder
through the real runtime (tag present in the opening, tagged tunnel still completes + round-trips).

**PR4b-2 landed (2026-07-21): the splitting egress.** `SplittingServer` (host, `wasm/splitter.rs`, gated
`bip324`) is a Bitcoin-v2 egress indistinguishable from a real node: it peeks each connection's opening
(`ellswift` + the leading garbage, a bounded peek), checks the side-door tag via
`bip324-core::verify_side_door_tag_with` (fed `ring`'s HMAC — spark-core now takes a `bip324-core` dep),
and routes — **tag matches** → run the BIP324 responder (`WasmServer`) and relay the client's announced
target; **no match** → proxy the bytes untouched to the real node. A `PrefixedStream` replays the peeked
bytes so the chosen branch sees the connection from byte 0; the peek is timeout-bounded so a real peer
whose garbage is shorter than the tag is proxied rather than stalling the peek. The classification uses
HMAC only (`verify_side_door_tag_with` — no full `Bip324Crypto` on the host). Validated by a loopback
test: a tagged Lantern client tunnels to its announced echo target, and an untagged peer is proxied to a
stub upstream and echoed back (if it had wrongly taken the tunnel branch the BIP324 handshake would
reject its bytes).

**PR4c landed (2026-07-21): live interop — step 4 COMPLETE.** Two proofs. (1) **Hermetic wire-compat
against the rust-bitcoin `bip324` reference crate** (`bip324-core/tests/interop.rs`, gated `native-crypto`):
our sans-io core drives a real BIP324 handshake + packet exchange over a TCP loopback against the
canonical implementation's `io::Protocol`, in **both** role assignments — if the reference can't tell our
core apart from a Bitcoin node, neither can a censor's DPI. This runs in CI (`--all-features`). (2) **A live
`bitcoind` proof** (`#[ignore]`d, run manually with `BIP324_BITCOIND=host:port`): a non-Lantern opening
reaches a real `bitcoind` through the splitter's proxy branch and gets a genuine BIP324 response, closing
the loop that the egress is a real Bitcoin node to everyone without `k_srv`.

**§7 step 4 (BIP324 as a WASM engine + signed config) is complete**: a protocol with a custom curve, an
interactive handshake, custom framing, and a Lantern-specific anti-probing side-door — shipped end to end
as a signed WASM module + config, crypto entirely via host primitives, wire-compatible with the reference,
deployable to an unchanged client. The north star, demonstrated. Remaining framework work is §7 step 5
(non-Chrome anchors + a STARTTLS proof), independent of BIP324.

## 8. Tradeoffs (stated plainly)

- **Opaque engine params** → the core can't validate or GA-optimize protocol-specific fields; the
  engine owns that. The generic shaping layer stays core-GA-able, so the "discovered against the live
  network" property survives where most opening-move adaptivity lives.
- **WASM interpreter perf** is fine for RTT-bound handshakes and framing but caps bulk throughput; the
  native-crypto host primitives keep the bulk path off the interpreter (ADR 0003 §3 numbers).
- **iOS is interpreter-only** (no JIT) — the reason spark is on `wasmi`; all of the above must hold in
  the interpreter.
- **Capability/version surface** grows: clients and transports must negotiate primitives and
  anti-rollback carefully. The gate **must fail loud** — log/alert on an unmet `requires` — never
  silently disable a transport; silent disable is the failure mode to design against (this is the
  required behavior in ADR 0013's consequences, stated here as the risk it guards against).
