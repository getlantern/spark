# ADR 0007 — Samizdat transport (interop client): h2-CONNECT mux + no-fork SessionID injection

- **Status:** Accepted (design) — 2026-06-19. The load-bearing TLS mechanism is spike-validated;
  implementation is chunked on branch `samizdat-transport` per PLAN.md §2. Full design +
  build order: `docs/samizdat-transport-design.md`.
- **Scope:** Add Lantern's **Samizdat** protocol as a spark `Transport`, **wire-interoperable with
  deployed `lantern-box` / sing-box `"samizdat"` servers** (client side only). Does not change the
  proxy core, the netstack, or the existing transports.
- **Builds on:** ADR 0001 (BoringSSL Chrome-mimicry), ADR 0006 (`Capability::SessionIdInject`), the
  `m11-transport-candidates-anytls-samizdat` memory, and the in-tree AnyTLS transport it reuses.

## Context

`getlantern/samizdat` (Go, in production) is a REALITY-style protocol: **one** outer TLS 1.3 session
(Chrome uTLS ClientHello, cover SNI), REALITY auth embedded in the TLS `legacy_session_id`
(`shortID(8) ‖ nonce(8) ‖ HMAC-SHA256(PSK, nonce)[:16]`, `PSK = HKDF-SHA256(serverPubKey, shortID,
"SAMIZDAT")`), proxied flows multiplexed as **HTTP/2 CONNECT** streams, with a masquerade fallback to
the cover domain on bad auth. Interop pins every wire detail. Two gaps vs. spark's locked stack:

1. **H2 CONNECT mux** — spark relays raw byte streams; CLAUDE.md forbids `hyper`/`reqwest`.
2. **Arbitrary `legacy_session_id`** — `boring2`'s public API has no client SessionID setter
   (`ConnectConfiguration::set_session` = resumption only); the bytes must also be present *before*
   the TLS transcript hash, ruling out an on-wire splice.

## Decision

1. **Build a Samizdat client, interop-exact** with deployed servers. The server (masquerade,
   short-ID registry) stays in Go. **TCP only in v1** (Samizdat is TCP-only); UDP deferred.

2. **HTTP/2 CONNECT mux via the `h2` crate** (sans-hyper) — a scoped, documented exception to the
   no-hyper rule, in the same spirit as the ADR-0001 boring exception. Justified: the H2 layer is
   **inside TLS**, so its wire fingerprint is encrypted and is *not* an evasion surface (the Go server
   uses stock `x/net/http2`); the choice is about correct CONNECT interop + flush control + dependency
   weight, and `h2` is the smallest dep that does it (no `tower`/`http`-server/openssl). `hyper` itself
   stays out.

3. **SessionID injection via the `kID` session trick on stock `boring2` — no fork.** A fabricated
   TLS-1.2, session-ID-based, ticketless session whose `session_id` is the auth bytes makes BoringSSL
   emit those bytes as `legacy_session_id` even in a 1.3-offering Chrome hello (BoringSSL
   `handshake_client.cc`: the `kID` branch is checked before compatibility-mode, and `ssl_session_get_type`
   keys off id-present + ticketless — no cipher/master-key needed). Because boring builds the hello,
   the transcript is correct. The **`boring-sys2` patch** (a `SSL_set1_client_session_id` overlay) is
   recorded as a fallback but is **not adopted** — keeping unmodified crates.io `boring2` that
   auto-tracks Chrome (the maintenance property we wanted).

4. **Reuse, don't duplicate:** the AnyTLS boring Chrome connector (`anytls/tls.rs`) + the gambit
   profile, the opening-handshake `shaping/` (Geneva CH fragmentation + jitter), `ring`
   (HKDF/HMAC/RNG; no client-side ECDH), and the AnyTLS session-pool pattern.

## Evidence

Hermetic spike (2026-06-19, `/tmp/kid-spike`) against spark's real Chrome connector: the chosen
32-byte `legacy_session_id` reaches the wire (baseline run = random compat id); `supported_versions`
still includes TLS 1.3 (no version cap from the 1.2 session); cipher list + extension set are
identical to baseline (extension order permutes per-connection, as real Chrome does → JA4 unchanged).
Working sequence: `SSL_SESSION_new` → `SSL_SESSION_set_protocol_version(TLS1_2)` → `SSL_SESSION_set1_id`
→ `set_time`/`set_timeout` → `SSL_set_session` → `SSL_SESSION_free`. Both follow-on checks are now
**confirmed**: `core/examples/samizdat_interop.rs` tunnels through a real `getlantern/samizdat` Go
server — the full handshake completes with the session set, the server's `VerifySessionID` accepts
spark's auth, and a request returns HTTP 200 (including with `sni_boundary` ClientHello fragmentation).

## Consequences

**Positive.** Full interop path with no BoringSSL fork (Chrome currency stays automatic via the
profile tables + JA4-drift CI); reuses the existing mimicry/shaping/crypto/pool machinery; one small
new dep (`h2`); fills `Capability::SessionIdInject` for the boring executor (also enables REALITY
later, now without a patch).

**Costs / risks.** A new `h2` dependency (scoped to the `samizdat` feature). A few lines of `unsafe`
FFI to fabricate the kID session (`boring-sys2` symbols; `SslRef::as_ptr` needs
`foreign_types_shared::ForeignTypeRef` in scope). Interop + handshake-completion remain to be gated
live. Cover-SNI / server-pubkey / short-ID come from lantern's config distribution (as AnyTLS's
`server`/`password` do).

## References

`docs/samizdat-transport-design.md`; ADR 0001, ADR 0006; `getlantern/samizdat` (`auth.go`,
`client.go`, `h2transport.go`); memory `m11-transport-candidates-anytls-samizdat`; spike `/tmp/kid-spike`.
