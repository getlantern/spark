# ADR 0009 — Shadowsocks 2022 transport (interop client): from-scratch SIP022 on `ring` + RustCrypto

- **Status:** Accepted — implemented and **live-gated** end-to-end against `shadowsocks-rust` 1.24.0
  (TCP HTTP 200 + UDP DNS through the tunnel), 2026-06-21. Full design + build order:
  `docs/shadowsocks-design.md`.
- **Scope:** Add **Shadowsocks 2022 (SIP022)** as a spark `Transport` (TCP) + `UdpTransport` (UDP),
  **wire-interoperable with deployed `shadowsocks-rust` / sing-box SS-2022 servers** (client side
  only). Does not change the proxy core, the netstack, or the existing transports.
- **Builds on:** the `Transport`/`UdpTransport` trait seam, the `ServerSpec`/`ServerEntry` config
  model, the bootstrap endpoint resolver, and the feature-gating + config-wiring pattern established
  by AnyTLS (ADR 0001) and Samizdat (ADR 0007).

## Context

`shadowsocks-rust` (and sing-box) deploy SS-2022 (SIP022) in production: a pre-shared-key AEAD tunnel
with BLAKE3 session-subkey derivation, salted length-chunk AEAD framing with standalone header
chunks, timestamp/salt replay binding, and a session-ID/packet-ID UDP packet format with a sliding
replay window. Interop pins every wire detail. Three things had to be decided: whether to take the
upstream crate as a dependency, which crypto backend to use given spark's locked stack, and how far
to take the spec in v1.

## Decision

1. **Implement SS-2022 (SIP022) from scratch in Rust — no `shadowsocks-rust` dependency.** A
   wire-interoperable client whose wire format is ours to audit and that keeps the binary lean
   (`shadowsocks-rust` pulls a large relay/server tree we don't need on a client). The reference
   spec (`Shadowsocks-NET/shadowsocks-specs` `2022-1`) and `shadowsocks-rust`'s `crypto/src/v2/*`
   serve as the interop oracle / test-vector source, not as a code dependency.

2. **Crypto backend = `ring` for the AEADs + RustCrypto `blake3` + `aes`.** `ring` (`LessSafeKey`,
   12-byte nonces) does AES-128/256-GCM and ChaCha20-Poly1305; RustCrypto `blake3` derives the
   per-session subkey (the SIP022 KDF), and `aes` provides the raw block cipher for the UDP
   separate-header. This is a deliberate, **scoped** deviation from CLAUDE.md's named `aws-lc-rs`
   fallback: `aws-lc-rs` would pull a C/cmake library, whereas `blake3` + `aes` are pure-Rust,
   cmake-free, and **feature-gated** so the <3 MB base build is untouched. base64 PSK decode is
   hand-rolled (no `base64` dependency).

3. **v1 UDP supports the two AES methods only.** `2022-blake3-chacha20-poly1305` is **TCP-only** in
   v1: SS-2022 UDP for the chacha method needs **XChaCha20-Poly1305**, a primitive `ring` lacks.
   chacha-over-UDP returns a clear `Unsupported` error — **never a silent fallback**. The XChaCha UDP
   path is deferred.

4. **Out of scope (v1), explicitly:** EIH / multi-user, legacy Shadowsocks AEAD (SIP004/007),
   UDP-over-TCP, obfuscation / cover layers, and the server side.

## Consequences

**Positive.** Full interop path with no upstream-crate dependency; the wire format is auditable and
self-contained; the base build stays rustls/ring-only and cmake-free (the extra crypto is behind the
feature flag). Live-gated against a real `shadowsocks-rust` 1.24.0 server with zero codec fixes on
first interop.

**Costs / risks.** A scoped deviation from the named crypto fallback (justified above). Two
pure-Rust crypto crates (`blake3`, `aes`) added behind the `shadowsocks` feature. chacha-over-UDP is
unsupported in v1 (errors loudly, doesn't fall back). PSK / method come from config distribution (as
AnyTLS's `password` does).

**Wiring / shape.** Gated behind a `shadowsocks` cargo feature
(`shadowsocks = ["dep:blake3", "dep:aes"]`); code lives in
`core/src/transport/shadowsocks/{mod,crypto,tcp,udp}.rs`. Config is `ServerSpec::Shadowsocks` +
`[transport.shadowsocks]`. The bootstrap `resolve_endpoints` SNI slot was made **optional** because
Shadowsocks has no SNI (the resolver entry carries `Option<&mut Option<String>>`).

**Threat-model note.** Plain SS-2022 is high-entropy "look-like-nothing" traffic and is
FET-detectable by the GFW (Wu et al., USENIX Security 2023) — it is positioned as an interop / arm /
inner-layer transport, **not** a frontline evader. The mimicry-first transports (AnyTLS / Samizdat)
remain the spearhead. See the design doc §10.

## References

`docs/shadowsocks-design.md` (esp. §10 threat model, §11 build order); ADR 0001 (BoringSSL mimicry +
TLS backend), ADR 0007 (Samizdat transport); `Shadowsocks-NET/shadowsocks-specs`
(`2022-1-shadowsocks-2022-edition.md`); `shadowsocks/shadowsocks-rust` (`crypto/src/v2/*`) as the
interop oracle.
