# P4a — Wire the Stock-Boring Gambit Knobs — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Realize the gambit knobs boring2 4.15 *can* do but spark doesn't wire — explicit extension order, explicit cipher order, `legacy_session_id` injection, and `records.split_offsets` — moving them from declined/ignored to realized, no fork, Chrome fidelity preserved.

**Architecture:** Cross-repo. `flint` (the `flint-shaping` + `flint-tls` crates) gains the executor support; spark bumps its pinned `flint` rev and wires the realize path + the Layer-B shaper + capability advertisement. Only the genome's `Explicit(...)` order variants are realized; `PermuteSeed(...)` stays boring's seed-uncontrolled permute (documented, unchanged). The AnyTLS live gate is the authoritative check.

**Tech Stack:** Rust; `boring2`/`boring-sys2` 4.15 (the impersonation fork spark pins) + `tokio-boring2`; `flint-tls` (boring connector + gambit executor) and `flint-shaping` (opening-write shapers); spark `core` (`anytls` feature).

**Spec:** `docs/superpowers/specs/2026-06-22-p4a-gambit-realization-design.md`.

**VERIFY discipline (project rule):** Some `boring2` 4.15 calls below are version-sensitive. Where a step says **VERIFY**, the implementer MUST confirm the exact signature against the `boring2`/`boring-sys2` 4.15.15 source under `~/.cargo/registry/src/` (and spark's existing usage) before writing it — do not guess. The deterministic parts (struct fields, `resolve()` logic, the shaper variant, test scaffolding) are given complete.

**Worktrees:** flint work in a fresh worktree of `/Users/afisk/go/src/github.com/getlantern/flint` (branch off `main` @ `d22dcb5`); spark work in the existing `spark-p4a` worktree (branch `p4a-gambit-realization`).

---

## File structure

**flint repo:**
- `crates/flint-shaping/src/lib.rs` — add `RecordFragment::Offsets(Vec<usize>)` variant.
- `crates/flint-shaping/src/record_fragment.rs` — honor `Offsets` in the fragmenting logic; test.
- `crates/flint-tls/src/profile.rs` — extend `Profile`; `BORING_CAPABILITIES += SessionIdInject`; `resolve()` populates the new fields; unit tests.
- `crates/flint-tls/src/connector.rs` — apply the new `Profile` fields; host the shared `inject_session_id`; CH-parse + JA4 tests.

**spark repo (`spark-p4a` worktree):**
- `core/Cargo.toml` + `Cargo.lock` — bump `flint-tls` + `flint-shaping` to the new same rev.
- `core/src/transport/mod.rs` (`anytls_transport`) and/or `core/src/transport/anytls/transport.rs` — map `records.split_offsets` → `RecordFragment::Offsets`; pass the richer `Profile`; advertise capabilities.
- `core/src/transport/samizdat/session_id.rs` — delegate to the shared `flint-tls` `inject_session_id`.
- `docs/handshake-gambit-design.md` — §3.5 matrix flip + §3.7 generalization (after PR #16 merges; see Task 7).
- `core/tests/` (the AnyTLS live gate) — a P4a-gambit-applied case.

---

## Phase A — flint (executor support)

### Task 1: `flint-shaping` — `RecordFragment::Offsets`

**Files:**
- Modify: `crates/flint-shaping/src/lib.rs` (the `RecordFragment` enum)
- Modify: `crates/flint-shaping/src/record_fragment.rs`
- Test: inline `#[cfg(test)]` in `record_fragment.rs`

- [ ] **Step 1: Write the failing test** (in `record_fragment.rs` tests)

```rust
#[tokio::test]
async fn offsets_fragments_the_clienthello_at_given_cuts() {
    use tokio::io::AsyncWriteExt;
    // A fake ClientHello record: 16 03 01 <len:2> <payload>. Offsets are into the *payload*.
    let payload = (0..30u8).collect::<Vec<_>>();
    let mut rec = vec![0x16, 0x03, 0x01, 0x00, payload.len() as u8];
    rec.extend_from_slice(&payload);
    let plan = WirePlan { record_fragment: RecordFragment::Offsets(vec![10, 20]), ..Default::default() };
    let mut buf = Vec::new();
    let mut s = RecordFragmentingStream::new(&mut buf, plan);
    s.write_all(&rec).await.unwrap();
    s.flush().await.unwrap();
    // Expect 3 TLS records (cuts at 10 and 20), each with its own 16 03 01 header, payloads
    // concatenating back to the original.
    let records = parse_tls_records(&buf); // helper below
    assert_eq!(records.len(), 3);
    assert_eq!(records.iter().flat_map(|r| r.clone()).collect::<Vec<_>>(), payload);
    assert_eq!(records[0].len(), 10);
    assert_eq!(records[1].len(), 10);
    assert_eq!(records[2].len(), 10);
}

// Minimal TLS-record splitter for the assertion: returns each record's payload.
fn parse_tls_records(mut b: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while b.len() >= 5 {
        let len = u16::from_be_bytes([b[3], b[4]]) as usize;
        out.push(b[5..5 + len].to_vec());
        b = &b[5 + len..];
    }
    out
}
```

- [ ] **Step 2: Run it, expect FAIL** — `RecordFragment::Offsets` doesn't exist.
  Run: `cargo test -p flint-shaping offsets_fragments -- --nocapture`
  Expected: compile error `no variant Offsets`.

- [ ] **Step 3: Add the variant** in `crates/flint-shaping/src/lib.rs`'s `RecordFragment` enum (it currently has `None | SniStraddle | Chunks(usize)`):

```rust
    /// Fragment the ClientHello's record payload at these absolute payload byte offsets, emitting a
    /// separate TLS record per piece. Offsets out of range or unordered are clamped/sorted; an empty
    /// list is a no-op. (Gambit Layer B `records.split_offsets`.)
    Offsets(Vec<usize>),
```

- [ ] **Step 4: Honor it** in `record_fragment.rs` — extend the existing match that turns the buffered ClientHello payload into record chunks. **VERIFY** the existing chunking shape in `record_fragment.rs` (how `SniStraddle`/`Chunks` produce the `Vec` of payload slices), then add an `Offsets(offs)` arm that sorts+dedups+clamps `offs` to `(0, payload_len)` and cuts the payload at those offsets. Reuse the existing record-reframing path (the `16 03 01 <len>` re-header logic) — do NOT duplicate it.

- [ ] **Step 5: Run it, expect PASS.**
  Run: `cargo test -p flint-shaping offsets_fragments -- --nocapture` → PASS.
  Also: `cargo test -p flint-shaping` (all green), `cargo clippy -p flint-shaping -- -D warnings`.

- [ ] **Step 6: Commit.**
```bash
git add crates/flint-shaping/src/lib.rs crates/flint-shaping/src/record_fragment.rs
git commit -m "feat(flint-shaping): RecordFragment::Offsets — explicit CH record-split offsets"
```

### Task 2: `flint-tls` `profile.rs` — realize the knobs in the data mapping

**Files:**
- Modify: `crates/flint-tls/src/profile.rs`
- Test: inline `#[cfg(test)] mod tests` in `profile.rs`

- [ ] **Step 1: Write failing tests** (extend the existing `tests` mod):

```rust
#[test]
fn realizes_explicit_orders_and_session_id() {
    use crate::gambit::{Perm, SessionId};
    let ch = ClientHello {
        extension_order: Some(Perm::Explicit(vec![0x0000, 0x0017, 0x002b])),
        cipher_order: Some(Perm::Explicit(vec![0x1301, 0x1302])),
        session_id: Some(SessionId::Inject("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".into())),
        ..Default::default()
    };
    let r = Profile::resolve(&ch, &Records::default());
    assert_eq!(r.profile.extension_order.as_deref(), Some(&[0x0000u16, 0x0017, 0x002b][..]));
    assert_eq!(r.profile.cipher_order.as_deref(), Some(&[0x1301u16, 0x1302][..]));
    assert_eq!(r.profile.session_id.unwrap().len(), 32);
    // explicit order + inject are now realized → not in `unrealizable`.
    assert!(!r.unrealizable.iter().any(|m| m.contains("extension_order.explicit")));
    assert!(!r.unrealizable.iter().any(|m| m.contains("session_id.inject")));
}

#[test]
fn permute_seed_stays_approximated() {
    use crate::gambit::Perm;
    let ch = ClientHello { extension_order: Some(Perm::PermuteSeed(7)), ..Default::default() };
    let r = Profile::resolve(&ch, &Records::default());
    assert!(r.profile.extension_order.is_none()); // not an explicit list
    assert!(r.profile.permute_extensions);        // boring's own permute stays on
    assert!(r.unrealizable.iter().any(|m| m.contains("extension_order seed approximated")));
}

#[test]
fn boring_now_advertises_session_id_inject() {
    assert!(BORING_CAPABILITIES.contains(&Capability::SessionIdInject));
    assert!(!BORING_CAPABILITIES.contains(&Capability::RawClienthello)); // still P4b
}
```

- [ ] **Step 2: Run, expect FAIL** — new `Profile` fields + capability not present.
  Run: `cargo test -p flint-tls --features boring profile:: -- --nocapture` (profile is pure but build with the crate's default features; **VERIFY** whether `profile.rs` compiles without `boring` — it's pure data, so plain `cargo test -p flint-tls profile::` should work).
  Expected: compile errors (`extension_order` field missing, `SessionIdInject` not in slice).

- [ ] **Step 3: Extend `Profile`** (in `profile.rs`) — add three fields with the Chrome-default (None) semantics, and update `Default`:

```rust
    /// Explicit extension order by id (gambit `extension_order: Explicit`). `None` ⇒ boring's own
    /// (seed-uncontrolled) permute, per `permute_extensions`.
    pub extension_order: Option<Vec<u16>>,
    /// Explicit cipher order by id (gambit `cipher_order: Explicit`). `None` ⇒ the pinned Chrome list.
    pub cipher_order: Option<Vec<u16>>,
    /// Injected `legacy_session_id` (gambit `session_id: Inject`). `None` ⇒ boring default.
    pub session_id: Option<[u8; 32]>,
```
Add `extension_order: None, cipher_order: None, session_id: None` to `impl Default for Profile`.

- [ ] **Step 4: Add the capability** — `BORING_CAPABILITIES` becomes `&[Capability::Ech, Capability::Alps, Capability::PqKem, Capability::SessionIdInject]`.

- [ ] **Step 5: Populate in `resolve()`** — replace the current "ignored/approximated" handling for these knobs:

```rust
    // extension order: explicit list is realized via set_extension_permutation; a seed only toggles
    // boring's own permute (seed uncontrolled).
    match &ch.extension_order {
        None => {}
        Some(Perm::PermuteSeed(_)) => {
            p.permute_extensions = true;
            un.push("extension_order seed approximated (boring: permute on/off only)");
        }
        Some(Perm::Explicit(ids)) => p.extension_order = Some(ids.clone()),
    }
    match &ch.cipher_order {
        None => {}
        Some(Perm::PermuteSeed(_)) => un.push("cipher_order.permute ignored (boring has no cipher permutation)"),
        Some(Perm::Explicit(ids)) => p.cipher_order = Some(ids.clone()),
    }
    // session_id: Inject is realized via the kID recipe (decode the hex to 32 bytes).
    if let Some(crate::gambit::SessionId::Inject(hex)) = &ch.session_id {
        match decode_hex_32(hex) {
            Some(id) => p.session_id = Some(id),
            None => un.push("session_id.inject ignored (pin must be 64 hex chars)"),
        }
    }
    // records.split_offsets is realized by the Layer-B shaper at the dialer (not boring) — no longer
    // "ignored". (resolve() does not see the shaper; the dialer maps the gambit field directly.)
```
Add a small `fn decode_hex_32(s: &str) -> Option<[u8;32]>` helper (or reuse spark's existing hex decode pattern — **VERIFY** if `flint-tls` already has one; if not, a 12-line local decoder). Remove the old `records.split_offsets ignored` push.

- [ ] **Step 6: Run, expect PASS.**
  Run: `cargo test -p flint-tls profile:: -- --nocapture` → PASS; `cargo clippy -p flint-tls -- -D warnings`.

- [ ] **Step 7: Commit.**
```bash
git add crates/flint-tls/src/profile.rs
git commit -m "feat(flint-tls): resolve explicit orders + session-id inject onto Profile (+SessionIdInject cap)"
```

### Task 3: `flint-tls` `connector.rs` — apply the knobs to boring

**Files:**
- Modify: `crates/flint-tls/src/connector.rs`
- Test: inline `#[cfg(test)]` in `connector.rs` (boring-feature-gated) + reuse the JA4 harness in `ja4.rs`

- [ ] **Step 1: Port the kID recipe** — add `pub fn inject_session_id(config: &mut ConnectConfiguration, id: &[u8; 32]) -> io::Result<()>` to `connector.rs`, copied from spark's proven `core/src/transport/samizdat/session_id.rs` (the `SSL_SESSION_new → SSL_SESSION_set_protocol_version(TLS1_2) → SSL_SESSION_set1_id → SSL_set_session → SSL_SESSION_free` sequence). **VERIFY** the `boring_sys2` symbol names against the version `flint-tls` pins (they must match spark's — both pin boring2 4.15). Keep the safety comment.

- [ ] **Step 2: Write the failing CH-parse test** (boring-gated):

```rust
#[cfg(feature = "boring")]
#[tokio::test]
async fn applies_explicit_order_and_injected_session_id() {
    // Capture the ClientHello bytes boring emits for a Profile with the new knobs, parse them.
    let id = [0xABu8; 32];
    let profile = Profile {
        extension_order: Some(vec![/* a valid Chrome ext subset, see VERIFY */]),
        session_id: Some(id),
        ..Profile::default()
    };
    let ch = capture_client_hello(&profile).await; // helper: see VERIFY note
    let parsed = parse_client_hello(&ch);           // reuse ja4.rs / the existing CH parser
    assert_eq!(parsed.legacy_session_id, &id[..]);
    assert_eq!(parsed.extension_ids_in_order(), profile.extension_order.unwrap());
    assert!(parsed.offers_tls13());
}
```
**VERIFY:** how to capture the emitted ClientHello in `flint-tls` — the `ja4.rs` anchor/drift harness already realizes a `Profile` through boring and inspects the CH (the JA4 spike). Reuse that capture path (`capture_client_hello` / the anchor harness's realize-and-parse) rather than inventing one. Pick the extension-id subset from the anchor's actual extension set.

- [ ] **Step 3: Run, expect FAIL** — connector doesn't apply the new fields yet.

- [ ] **Step 4: Apply the fields** in `configure()` (around the existing `set_permute_extensions`/`set_cipher_list` block at `connector.rs:101-111`):

```rust
    // Explicit extension order (gambit Layer A); else boring's own permute.
    match &profile.extension_order {
        Some(ids) => b.set_extension_permutation(&ids_to_extension_types(ids)).map_err(|e| ssl(e, "ext-permutation"))?,
        None => b.set_permute_extensions(profile.permute_extensions),
    }
    // Cipher list: explicit order (gambit) or the pinned Chrome order.
    let cipher_list = match &profile.cipher_order {
        Some(ids) => cipher_ids_to_list(ids),   // owned String of ":"-joined names, in order
        None => CHROME_CIPHERS.to_owned(),
    };
    b.set_cipher_list(&cipher_list).map_err(|e| ssl(e, "ciphers"))?;
```
and at the end (after `config` is built, near `set_enable_ech_grease`):
```rust
    if let Some(id) = &profile.session_id {
        inject_session_id(&mut config, id)?;
    }
```
**VERIFY:** (a) `SslConnectorBuilder::set_extension_permutation` exact signature + the `ExtensionType` enum + how a `u16` ext id maps to `ExtensionType` (a `from_u16`/`From` or a match); unknown ids → skip-with-`tracing::warn!`, never fail. (b) the `boring2` cipher-name strings for the anchor's cipher ids (build `cipher_ids_to_list` as an id→name match over the anchor's cipher set; unknown ids → skip-with-warn). Write these two small mappers (`ids_to_extension_types`, `cipher_ids_to_list`) in `connector.rs`.

- [ ] **Step 5: Run, expect PASS** + JA4 check.
  Run: `cargo test -p flint-tls --features boring connector:: -- --nocapture` → PASS.
  Then a JA4-shift assertion (Step 6).

- [ ] **Step 6: JA4 test** — add a test that a reordered hello's JA4 differs from the anchor's *in the extension-order field only* (the `ja4.rs` harness computes JA4 from a realized Profile). This proves the reorder took effect and didn't corrupt the hello. **VERIFY** the `ja4.rs` API for computing a JA4 from a `Profile`.

- [ ] **Step 7: Commit.**
```bash
git add crates/flint-tls/src/connector.rs
git commit -m "feat(flint-tls): apply explicit ext/cipher order + session-id inject on the boring connector"
```

- [ ] **Step 8: Open the flint PR** (non-squash per project rule), get it merged, and note the merge commit SHA for Task 4.

---

## Phase B — pin the new flint rev in spark

### Task 4: Bump `flint-tls` + `flint-shaping` to the new rev

**Files:** `core/Cargo.toml`, `Cargo.lock` (spark-p4a worktree)

- [ ] **Step 1:** In `core/Cargo.toml`, set both `flint-tls` and `flint-shaping` `rev = "<new flint merge SHA from Task 3 Step 8>"` (they MUST be the same rev — project rule).
- [ ] **Step 2:** `cargo update -p flint-tls -p flint-shaping` (from spark-p4a root).
- [ ] **Step 3:** `cargo build -p spark-core --features anytls` → succeeds (the new `Profile` fields + `RecordFragment::Offsets` compile against spark).
- [ ] **Step 4: Commit** `core/Cargo.toml` + `Cargo.lock` together:
```bash
git add core/Cargo.toml Cargo.lock
git commit -m "build(spark): bump flint-tls + flint-shaping to <SHA> (P4a executor knobs)"
```

---

## Phase C — spark wiring + docs + live gate (spark-p4a worktree)

### Task 5: Realize path — Layer-B split + capability advertisement

**Files:**
- Modify: `core/src/transport/mod.rs` (`anytls_transport`) and/or `core/src/transport/anytls/transport.rs`
- Test: inline `#[cfg(all(test, feature = "anytls"))]`

- [ ] **Step 1: Write the failing test** — a gambit with `records.split_offsets` produces a dialer whose `WirePlan.record_fragment` is `Offsets(...)`, and a gambit requiring `session_id_inject` is no longer declined. **VERIFY** the exact realize entry point (`anytls_transport` builds the connector + the shaped dialer; `transport.rs::resolve_profile` resolves the gambit). Assert on the constructed `WirePlan` / that `Profile::for_boring` accepts a `session_id_inject` gambit (the capability now advertised).

- [ ] **Step 2: Run, expect FAIL.**

- [ ] **Step 3: Wire it** — where the gambit's Layer C is mapped to `WirePlan` (the `wire_plan()` bridge), also map Layer B: set `WirePlan.record_fragment = RecordFragment::Offsets(gambit.records.split_offsets.clone())` when non-empty (else `None`). **VERIFY** where spark constructs the `WirePlan` for the AnyTLS dialer (the `gambit.wire_plan()` call only maps Layer C today — Layer B is "carried separately by the dialer" per the genome docs; this is where it gets carried). Confirm spark advertises `flint_tls::profile::BORING_CAPABILITIES` (now incl. `SessionIdInject`) wherever it gates a gambit.

- [ ] **Step 4: Run, expect PASS** + `cargo clippy -p spark-core --features anytls -- -D warnings`.

- [ ] **Step 5: Commit.**
```bash
git add core/src/transport/mod.rs core/src/transport/anytls/transport.rs
git commit -m "feat(anytls): realize Layer-B split + session-id-inject gambits"
```

### Task 6: Samizdat dedup

**Files:** `core/src/transport/samizdat/session_id.rs`

- [ ] **Step 1:** Replace samizdat's private `inject_session_id` body with a call to the shared `flint_tls::connector::inject_session_id` (re-export or `pub use`), keeping samizdat's public signature stable. **VERIFY** the shared fn is reachable from spark under the `anytls`/`samizdat` feature (flint-tls's `boring` feature is on).
- [ ] **Step 2:** Run samizdat's existing `injects_chosen_session_id_into_a_tls13_hello` test → still PASS.
- [ ] **Step 3: Commit** `git commit -m "refactor(samizdat): use the shared flint-tls inject_session_id"`.

### Task 7: Docs — flip the §3.5 matrix + §3.7 generalization

**Files:** `docs/handshake-gambit-design.md`

> **Dependency:** this doc's §3.5/§3.7 were introduced by PR #16 (the capability spec), which branches from the same `main`. **Rebase `p4a-gambit-realization` onto `main` after PR #16 merges**, then edit the now-present §3.5/§3.7. If #16 hasn't merged when you reach this task, do Task 8 first and return here.

- [ ] **Step 1:** In §3.5's realizability matrix, move these rows to ✅ realized: `session_id: inject`, `extension_order: explicit`, `cipher_order: explicit`, `records.split_offsets` (note: via the Layer-B shaper). Keep `PermuteSeed`/seed rows as ⚠️ approximated and `padding_target`/`raw`/`ech:real` as ❌/⛔ (P4b). Update the "discoverable space today" sentence to include explicit orders + session-id-inject.
- [ ] **Step 2:** §3.7 already notes QUIC as a future dialect — extend it to the generalized "opening dialects beyond TLS" (TURN/RDP/STARTTLS-mail + the `port` axis), matching the spec §7. (The opening-book site already carries this — keep the wording consistent.)
- [ ] **Step 3: Commit** `git commit -m "docs(gambit): P4a realizes explicit orders + session-id inject + record split (§3.5)"`.

### Task 8: AnyTLS live gate with a P4a gambit

**Files:** the existing AnyTLS interop gate under `core/tests/` (**VERIFY** its filename/env-gating).

- [ ] **Step 1:** Add a case (or env knob) to the existing live gate that applies a P4a gambit (explicit extension order over the anchor's set + an injected `legacy_session_id` + a `records.split_offsets`) and dials the live anytls-go / sing-box server, asserting the handshake completes and bytes round-trip — proving a real server accepts the reordered+injected+fragmented hello.
- [ ] **Step 2: Run live** (env-gated, against a local anytls server per the existing gate's README). Expected: handshake OK + round-trip. If it fails on the reorder/inject, that's a real bug — fix `connector.rs` (Task 3) until the live server accepts it.
- [ ] **Step 3: Commit** `git commit -m "test(anytls): live gate with a P4a gambit (explicit order + session-id + split)"`.

---

## Self-review notes (for the implementer)

- **Spec coverage:** §2 scope → Tasks 1–8; §3.1 flint → T1–T3; §3.2 spark → T5–T7; §3.3 samizdat → T6; §4 per-knob → T2/T3/T5; §5 testing → T2/T3 (unit+CH-parse+JA4) + T8 (live); §6 build order → T1–T8 ordering + T4 rev bump; §7 (P4b/dialects) → out of scope here, captured in T7 §3.7 doc only.
- **Type consistency:** `Profile.extension_order/cipher_order: Option<Vec<u16>>`, `Profile.session_id: Option<[u8;32]>`, `RecordFragment::Offsets(Vec<usize>)`, `BORING_CAPABILITIES` incl. `SessionIdInject` — used identically across T2/T3/T5.
- **VERIFY (not placeholders) — version-sensitive boring2 surface:** `set_extension_permutation` signature + `ExtensionType` mapping (T3), cipher-id→name list (T3), the `boring_sys2` kID symbols (T3 S1), the `ja4.rs` capture/JA4 API (T3 S2/S6), and spark's exact `WirePlan` construction site + live-gate file (T5/T8). Confirm each against source before writing — per spark's verification discipline; the surrounding logic and tests are given complete.
- **Never break connectivity:** unknown ext/cipher ids skip-with-warn; an unrealizable/erroring gambit falls back to the portable default (unchanged invariant) — assert the fallback still holds after T5.
