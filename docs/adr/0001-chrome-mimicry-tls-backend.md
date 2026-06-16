# ADR 0001 — Chrome-fingerprint TLS backend for mimicry transports (M11)

- **Status:** Accepted — 2026-06-16
- **Scope:** M11 (additional transports). Establishes the TLS strategy spark uses when a
  transport must resist TLS fingerprinting.
- **Supersedes (narrowly):** the "rustls only, never `openssl-sys`" line of the locked stack in
  `CLAUDE.md`, **for mimicry transports only**. rustls + ring remains the default everywhere else.

## Context

- spark is a censorship-circumvention tunnel. For a TLS-based transport, **TLS-fingerprint
  resistance is a primary requirement**, not a nice-to-have.
- The locked stack (`CLAUDE.md`) mandates `rustls` + `ring` and forbids `native-tls` /
  `openssl-sys`; the original binary budget was < 3 MB.
- **rustls structurally cannot mimic a chosen TLS fingerprint.** Maintainers closed the JA3/JA4
  request as "not planned" (rustls #2498, 2025-06-16) and *deliberately randomize* extension order
  to resist parroting. There is no API to control cipher / extension order, GREASE, or the 32-byte
  `legacy_session_id`. So neither a Chrome-exact ClientHello nor REALITY/samizdat-style
  SessionID-embedded auth is possible on rustls.
- The whole-app size budget was **relaxed to ~10 MB** (2026-06-16), which reopens BoringSSL-based
  options that the 3 MB cap had excluded.
- Candidates were researched in depth (see memory `m11-transport-candidates-anytls-samizdat`):
  vanilla rustls, BoringSSL via `boring`/`btls`, Cronet (Chromium net stack), OS-native TLS
  (SChannel / Network.framework / Android Conscrypt), and curl-impersonate (libcurl).

## Decision

1. **Keep `rustls` + `ring` as the baseline TLS** for transports that need no browser mimicry
   (`DirectTransport`, the plain TCP tunnel). Unchanged.
2. **Adopt `btls` — a maintained patched-BoringSSL fork (`btls` / `btls-sys` / `tokio-btls`,
   Apache-2.0 OR MIT) — as the TLS backend for *mimicry* transports**, behind the `Transport`
   trait. This is an explicit, documented exception to the rustls-only / no-`openssl-sys`
   constraint, justified because rustls cannot produce a chosen Chrome fingerprint. `btls` is a
   distinct C BoringSSL dependency, **not** `openssl-sys`.
3. **First M11 transport: AnyTLS-on-`btls`.** AnyTLS brings its own session multiplexing +
   record-size padding — the defense (Xue et al., USENIX Security 2024) against **TLS-in-TLS
   fingerprinting**, the dominant *passive* threat that no ClientHello perfection addresses.
   Running it on `btls` adds a near-genuine Chrome ClientHello, fixing AnyTLS's one fingerprint
   weakness (its reference impls run on plain rustls/Go-tls, leaving an identifiable CH).
4. **Source the Chrome profile from `wreq-util`'s `Emulation::Chrome<N>` tables** (pinned or
   vendored), wired the way `wreq` wires it. Raw `tokio-btls` carries no profile of its own.
5. **Ship a CI fingerprint-drift check:** from the built client, hit a reflector (tls.peet.ws) and
   assert JA4 == a captured real-Chrome JA4. Detect staleness rather than assume freshness.
6. **Keep `curl-impersonate` as the documented escape-hatch and the reference for a future
   QUIC / HTTP-3-mimicry transport** (the one capability `btls` lacks). Not a primary dependency:
   it is HTTP-client-shaped (libcurl), has no maintained Rust binding, and fights tokio on the
   data path.

## Empirical evidence

Spike (2026-06-16, `/tmp/btls-spike`): `wreq` `Emulation::Chrome137` → `tls.peet.ws/api/all`
produced **JA4 `t13d1516h2_8daaf6152771_d8a2da3f94cd`, peetprint `1d4ffe9b…`, H2 Akamai
`1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`** — **byte-identical to a real Chromium 149**
(captured via Playwright on the same endpoint), including the ALPS (`44cd`) and ECH (`fe0d`)
extensions that were the supposed fork-only hard part. Only JA3 differs, which is *expected*
(GREASE + extension order are randomized per connection; JA4 normalizes both). A Chrome**137**
profile matching a Chrome**149** browser (12 versions apart) confirms the fingerprint changes far
slower than the version number.

## Alternatives considered (why not the primary)

- **Vanilla rustls** — cannot produce a chosen Chrome fingerprint or inject the SessionID
  (maintainers refuse). Remains the baseline for non-mimicry transports only.
- **Cronet (Chromium net stack)** — the *real* Chrome (TLS + H2 + H3), tunnels via H2/H3 CONNECT
  (naive-style), and `getlantern/cronet` already exists. Rejected as primary: 8–15 MB/arch, Google
  dropped Cronet iOS at M108 (fork-and-maintain), and it owns the TLS socket (HTTP-client-shaped →
  cannot do AnyTLS/samizdat/REALITY). Retained as a possible desktop+Android "genuine Chrome"
  specialist.
- **OS-native TLS** — ~0 size on Windows/Apple, but Android has no NDK TLS C API (per-record JNI to
  `SSLEngine`, impractical), Linux has none, the fingerprint fragments per-OS, and no OS stack
  permits SessionID injection. Niche: an iOS-only AnyTLS camouflage option later.
- **curl-impersonate** — better-resourced and has H3, but it is `libcurl` (HTTP-client-shaped, like
  Cronet), has no maintained Rust binding, fights tokio, and exposes neither a TLS-record-size API
  (AnyTLS-hostile) nor SessionID injection. Retained as escape-hatch + QUIC reference.

## Consequences

**Positive:** byte-exact, staleness-robust Chrome mimicry (proven); a clean tokio
`AsyncRead + AsyncWrite` that drops into `Transport::dial → BoxedStream`; ~1–3 MB; uniform across
desktop + Android + iOS; unlocks the full protocol space (AnyTLS now; samizdat/REALITY later via
raw BoringSSL SessionID access).

**Costs / risks:**
- A C BoringSSL + cmake build dependency for mimicry builds (Android/iOS cross-compile work);
  rustls/ring remain for everything else.
- An explicit, scoped exception to the locked stack. `btls` is the *smallest* such deviation
  (Cronet and curl-impersonate are larger).
- **MEDIUM upstream-dependency risk** — solo maintainer (`0x676e67`), pre-1.0 crates, ~yearly
  repo/crate renames (reqwest-impersonate→rquest→wreq; boring→boring2→btls). **Fingerprint-staleness
  specifically is LOW** (proven). Mitigations: pin/vendor exact versions; the CI JA4-drift check;
  curl-impersonate as fallback; budget to self-port a profile (~a few/year) during a stall.

## Build order (matches spark's "prove the core in isolation" discipline)

1. **AnyTLS protocol core** — frame codec + padding-scheme engine (+ auth) over a generic byte
   stream, unit-tested, **no TLS yet**. ← this session (chunk 1: frame + padding).
2. AnyTLS session/stream **multiplexer** + idle-session pool.
3. Wire **`btls`/`tokio-btls`** as the TLS layer under the protocol; the `Transport` impl + config
   selection.
4. **Live gate:** the AnyTLS transport passes the same curl/DNS gates as the plain TCP tunnel; the
   CI JA4-drift check is green.
