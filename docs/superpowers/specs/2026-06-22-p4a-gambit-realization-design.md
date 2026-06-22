# P4a — gambit realization: wire the stock-boring knobs

**Goal:** Realize the gambit knobs that the spark/boring executor *can* do on **stock boring2 4.15**
but currently doesn't wire — moving `session_id` injection, explicit extension order, explicit cipher
order, and `records.split_offsets` from *declined/ignored* to **realized** — so the client's
discoverable opening space matches more of the genome's encodable breadth, **with no boring fork, no
byte-builder, and full Chrome fidelity preserved.**

**Companion to:** ADR 0006 (P4), `docs/handshake-gambit-design.md` (§3.5 client realization). This is
the P4a slice; P4b (the genuinely-hard tail) is deferred (see §7).

---

## 1. Why this is cheap (the grounding finding)

`flint-tls`'s `profile.rs` lists these knobs as boring "cannot" do — but that's conservative/stale.
Verified against boring2 4.15.15 + spark's own code:

| Knob | Stock boring2 reality |
|---|---|
| `session_id` inject | **Already solved on stock boring2** — Samizdat's kID recipe (`SSL_SESSION_new` → `set_protocol_version(TLS1_2)` → `set1_id` → `SSL_set_session`) injects a chosen `legacy_session_id` into a TLS-1.3 hello, tested in `core/src/transport/samizdat/session_id.rs`. The `profile.rs` claim is out of date. |
| `extension_order: explicit` | **Available, unwired** — `SslConnectorBuilder::set_extension_permutation(&[ExtensionType])` exists; the connector only calls `set_permute_extensions(bool)`. |
| `cipher_order: explicit` | **Available, hardcoded** — `set_cipher_list` preserves order; spark pins `CHROME_CIPHERS` unconditionally. |
| `records.split_offsets` | **Realizable via the native shaper** — boring has no API (correct), but `flint_shaping::RecordFragmentingStream` (Layer B) already fragments the ClientHello; the gambit field just isn't routed to it. |

Genuinely *not* on stock boring2 (→ P4b, §7): exact GREASE/permute **seed**, ClientHello
**padding-to-length**, **raw ClientHello** bytes.

## 2. Scope

**In:** wire the four knobs above; correct `profile.rs`'s stale notes; re-gate `BORING_CAPABILITIES`
to advertise `session_id_inject`; share the kID recipe into `flint-tls`; route `records.split_offsets`
through the shaper; update the `handshake-gambit-design.md` §3.5 realizability matrix.

**Out (P4b / later):** exact seeds, padding-to-length, raw CH, any boring fork, the WASM-module-driven
handshake, non-TLS opening dialects (§7).

**Realized variants are the `Explicit` ones.** `extension_order`/`cipher_order` have two genome
variants: `PermuteSeed(u32)` and `Explicit([id])`. Stock boring exposes an explicit *list*
(`set_extension_permutation`) and an ordered cipher *list*, but **no seed control** and **no cipher
permutation**. So P4a realizes `Explicit(...)`; `PermuteSeed(...)` stays "approximated" (boring's own
Chrome-faithful permute, seed uncontrolled) — unchanged from today, and explicitly documented.

## 3. Components & changes

### 3.1 `flint-tls` (the executor)
- **`gambit.rs`** — no schema change (the fields already exist). The `BORING_CAPABILITIES`-facing
  contract gains `session_id_inject`.
- **`profile.rs`**
  - Add `Capability::SessionIdInject` to `BORING_CAPABILITIES` (now `[Ech, Alps, PqKem,
    SessionIdInject]`). `RawClienthello` stays excluded (P4b).
  - Extend `Profile` with the now-realizable decisions:
    - `extension_order: Option<Vec<u16>>` — explicit ext-id order (None ⇒ boring's permute as today).
    - `cipher_order: Option<Vec<u16>>` — explicit cipher-id order (None ⇒ the pinned Chrome list).
    - `session_id: Option<[u8; 32]>` — injected `legacy_session_id` (None ⇒ boring default).
  - `resolve()` populates these from the genome instead of pushing them to `unrealizable`. Remaining
    `unrealizable` entries: `grease_seed` (approximated), `extension_order/cipher_order: PermuteSeed`
    (approximated for ext, ignored for cipher-permute), `padding_target`, `ech: real`. `split_offsets`
    is no longer "ignored" — it's realized by the dialer's shaper (see 3.2), so `resolve()` notes it as
    *handled by the Layer-B shaper* rather than unrealizable.
  - `for_boring()` unchanged in shape (gate then resolve); now passes a `session_id_inject` gambit.
- **`connector.rs`**
  - Apply `Profile.extension_order` via `set_extension_permutation(&[ExtensionType])` (map `u16` →
    `ExtensionType`); fall back to `set_permute_extensions` when `None`.
  - Apply `Profile.cipher_order` via an ordered `set_cipher_list` (map `u16` cipher ids → boring's
    cipher-name string in order); fall back to the pinned `CHROME_CIPHERS` when `None`.
  - Apply `Profile.session_id` via a **shared** `inject_session_id` (moved here from spark's
    `samizdat/session_id.rs`, which already proved the recipe on stock boring2; samizdat then re-uses
    the flint-tls function and drops its private copy).

### 3.2 `spark`
- **realize path** (`core/src/transport/mod.rs::anytls_transport` / `AnytlsTransport`) — pass the
  richer `Profile` to the connector (mechanical: `Profile` gained fields, the connector applies them);
  advertise the updated `BORING_CAPABILITIES` so a `session_id_inject` gambit is no longer declined.
- **Layer-B record split** — map the gambit's `records.split_offsets` (a `Vec<usize>`) onto the
  native `flint_shaping::RecordFragment` and feed it to the `RecordFragmentingStream` the dialer
  already stacks. If `flint_shaping`'s `RecordFragment` lacks an explicit-offsets variant (it has
  `None | SniStraddle | Chunks(usize)`), add a `RecordFragment::Offsets(Vec<usize>)` variant in
  `flint-shaping` and honor it in `record_fragment.rs`.
- **`docs/handshake-gambit-design.md` §3.5** — flip the four matrix rows to ✅ realized (with the
  `Explicit`-only nuance), and generalize §3.7 per §7 below. (Applied last, on then-current `main`, to
  avoid colliding with the open capability-spec PR.)

### 3.3 Samizdat (no behavior change)
`samizdat/session_id.rs::inject_session_id` moves to `flint-tls`'s connector module as the shared
implementation; samizdat calls the shared fn. Its existing CH-parse test stays (or moves with it). No
wire change to samizdat.

## 4. Per-knob realization detail

- **session_id inject** — `Profile.session_id: Some([u8;32])` ⇒ `inject_session_id(config, &id)` on
  the `ConnectConfiguration` before connect. The recipe yields a TLS-1.3 hello whose
  `legacy_session_id` is exactly `id` (verified by the existing parse test). Capability-gated by
  `SessionIdInject` (now in `BORING_CAPABILITIES`).
- **explicit extension order** — `Profile.extension_order: Some(vec![ext_id,…])` ⇒
  `set_extension_permutation(&ids.map(ExtensionType::from))`. Unknown/unsupported ext ids: decide at
  build (skip-with-log vs decline-gambit) — **skip-with-log**, consistent with "never break
  connectivity," and surface in `unrealizable`.
- **explicit cipher order** — `Profile.cipher_order: Some(vec![cipher_id,…])` ⇒ ordered
  `set_cipher_list`. Needs a `u16` cipher-id → boring cipher-name map for the ciphers the anchor uses;
  unknown ids skipped-with-log.
- **record split_offsets** — `records.split_offsets` ⇒ `RecordFragment::Offsets(offsets)` on the
  `RecordFragmentingStream`. Empty ⇒ `None` (today's behavior).

## 5. Fidelity & testing

The risk: reordering / injection breaks the handshake or wrecks JA4 fidelity. Tests:
1. **Unit (flint-tls):** `resolve()` maps each knob to the new `Profile` fields (and the right
   `unrealizable` residue); a `session_id_inject` gambit passes `for_boring`.
2. **CH-parse (flint-tls, `boring` feature):** realize a gambit with explicit extension order +
   injected session_id, capture the emitted ClientHello, assert (a) `legacy_session_id` == injected
   bytes, (b) extension order matches the requested list, (c) it still offers TLS 1.3 — mirrors
   `samizdat/session_id.rs`'s parse test.
3. **JA4 anchor (flint-tls `ja4.rs` + the anchor-drift harness):** a reordered hello's JA4 changes
   *predictably* (this is exactly the fidelity signal the discovery inner-loop scores). Confirms the
   knob moves JA4 in the expected way rather than producing a broken/garbage hello.
4. **Live gate (spark, AnyTLS):** the existing AnyTLS live gate with a P4a gambit applied — prove a
   real server still completes the handshake with the reordered + session-id-injected hello.
5. **Fallback:** a gambit boring still can't realize (or that errors) falls back to the portable
   default — connectivity never depends on the dynamic gambit (unchanged invariant).

## 6. Cross-repo build order & rev-pin mechanics

1. **flint PR** (in `getlantern/flint`): `flint-shaping` `RecordFragment::Offsets`; `flint-tls`
   `profile.rs` (+caps), `connector.rs` (+ shared `inject_session_id`), unit + CH-parse + JA4 tests.
   Merge **non-squash** (project rule for flint PRs).
2. **Bump spark's pinned flint rev** — `flint-tls` *and* `flint-shaping` to the **same** new rev in
   `core/Cargo.toml`; `cargo update -p flint-tls -p flint-shaping`; commit `Cargo.toml` + `Cargo.lock`
   together.
3. **spark PR:** the realize-path wiring, the `records.split_offsets` → shaper mapping, capability
   advertisement, samizdat dedup, and the §3.5/§3.7 doc update; the AnyTLS live gate.

Subagent-driven (implementer + spec/quality review per task), live gate as the authoritative check —
the hysteria2 flow.

## 7. Forward-looking: P4b and opening dialects beyond TLS

**P4b (deferred):** exact GREASE/permute seed (needs a C-level boring fork), ClientHello
padding-to-length (fork or byte-builder), raw ClientHello (a `client_hello_cb`-style hook boring2 4.15
lacks → a patched fork, a native byte-builder, or the WASM-module-driven handshake via the already-
wired crypto menu). Build only when a censor demands a knob P4a's constrained set can't reach.

**Opening dialects beyond TLS (a future track, not P4).** The genome + everything above it
(signed-gambit envelope, capability gating, the anchor concept, the server-as-oracle discovery loop,
the bandit, two-fleet portability) is **dialect-agnostic**. Only the genome's Layer-A/B/C *content*
and the boring/uTLS executors are TLS-specific. A non-TLS opening — e.g. **TURN** (a STUN
magic-cookie Allocate on a media port 3478/5349), **RDP** (a cleartext X.224 prelude on 3389 that
upgrades to TLS inline — a STARTTLS pattern with a *different wire shape than TLS-at-byte-0*), or
**STARTTLS-mail** (587/143) — is the same *shape* of problem (the censor's verdict still comes in the
opening) and would slot in as a sibling **dialect**:
- a new `Anchor` family (a real TURN/RDP/SMTP opening template),
- a **`port`** as a first-class genome field (today absent — non-TLS dialects are port-defined, and
  per the cover-protocol catalog **port is a distinct collateral-freedom axis** from wire shape:
  blocking 3478 also blocks Teams/Zoom media; blocking 3389 blocks remote-desktop),
- a new executor + a new capability tag,
- reusing signing, discovery, the bandit, and the opening-book thesis unchanged.

These are already analyzed as mimicry targets in the protocol-designer **cover catalog**
(`cover-turn`, `cover-rdp`, `cover-starttls-mail`). The genome's evolution path **reserves room** for
them (a `genome_version` bump adds the dialect/port axis), the same way Layer-D is reserved for the
data plane — so P4a doesn't paint us into a TLS-only corner. Designing a concrete non-TLS dialect is
its own protocol-designer + brainstorming cycle.

## 8. Risks / edge cases

- **Cipher-id → name mapping** is the fiddliest piece; bound it to the anchor's cipher set, skip
  unknowns with a log (don't fail the dial).
- **JA4 shifts are expected, not bugs** — an explicit reorder *should* change JA4; the test asserts
  the *expected* shift, and the inner-loop fidelity score (not P4a) decides if a shift is too far.
- **session_id inject + resumption** are mutually exclusive (the kID recipe sets a fresh session);
  document that a gambit can't both inject an id and resume.
- **flint rev discipline** — bump `flint-tls` and `flint-shaping` to one rev together (existing rule).
