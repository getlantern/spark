# ADR 0010 — Hysteria 2 transport (interop client): from-scratch QUIC on quinn + rustls/ring, with Salamander + Gecko

- **Status:** Accepted — implemented and **live-gated** end-to-end against `apernet/hysteria` v2.9.2
  (TCP HTTP 200 + UDP DNS through the tunnel) with **obfs off, Salamander, and Gecko** all green,
  2026-06-22. Full design + build order: `docs/hysteria2-design.md`.
- **Scope:** Add **Hysteria 2** as a spark `Transport` (TCP) + `UdpTransport` (UDP),
  **wire-interoperable with deployed `apernet/hysteria` servers** (client side only). spark's first
  **QUIC** transport. Does not change the proxy core, the netstack, or the existing transports.
- **Builds on:** the `Transport`/`UdpTransport` trait seam, the `ServerSpec`/`ServerEntry` config
  model, the bootstrap endpoint resolver, and the feature-gating + config-wiring pattern established
  by AnyTLS (ADR 0001), Samizdat (ADR 0007), and Shadowsocks (ADR 0009).

## Context

`apernet/hysteria` deploys Hysteria 2 in production: QUIC (RFC 9000) + the unreliable-datagram
extension (RFC 9221), an HTTP/3 `POST /auth` handshake (`Hysteria-Auth` → status `233 HyOK`), raw
QUIC bidi streams for proxied TCP (a `0x401` TCPRequest varint frame), QUIC datagrams for proxied UDP
(a session/packet/fragment UDPMessage format), and optional **Salamander** packet obfuscation plus
the newer **Gecko** handshake-fragmentation layer. The user flagged Salamander+Gecko as the
censorship-relevant priority (evidence Salamander works in China; Gecko is part of the recent
anti-blocking changes) and QUIC as strategically important for spark generally (future slipstream /
unbounded-QUIC tunneling). Interop pins every wire detail. Three things had to be decided: which QUIC
stack to adopt given spark's locked stack, how the obfuscation layer attaches to it, and how far to
take the protocol in v1.

## Decision

1. **QUIC stack = `quinn` 0.11 on the `rustls`/`ring` provider — "quinn now, noq later".** `quinn`
   re-exports `rustls` 0.23 and uses `quinn-udp` 0.5; we run it on `rustls`'s **ring** provider, NOT
   `aws-lc-rs` (which would link a second C crypto library alongside the boring fork that the mimicry
   transports already pull). `noq` (iroh's quinn hard-fork — the future multipath / NAT-traversal
   foundation) is **deferred**: the QUIC library sits entirely behind spark's `Transport`/
   `UdpTransport` traits, so swapping it later touches one module. This is the strategic seam for the
   QUIC-everywhere direction (slipstream, unbounded QUIC).

2. **Implement the Hysteria 2 protocol from scratch — no `apernet/hysteria` dependency** (it is a Go
   server tree). The reference is the interop oracle, not a code dependency. The data paths:
   - **TCP:** one QUIC **bidi stream** per flow — `varint(0x401) ‖ varint(addrlen) ‖ addr ‖
     varint(padlen)`, then parse the TCPResponse status byte (drain the varint-prefixed message +
     padding), then relay via `tokio::io::join(recv, send)`.
   - **UDP:** QUIC **datagrams** carrying UDPMessage `(session_id, packet_id, frag_id, frag_count,
     addr, payload)` with client-side fragmentation; a single per-connection **receive pump**
     reassembles and routes completed payloads to per-session `mpsc` channels.
   - **Auth:** a **hand-rolled minimal HTTP/3 + QPACK** `/auth` exchange on a single bidi stream
     (no full `h3`/`h2`/QPACK-dynamic-table stack) — an HTTP/3 HEADERS frame with a QPACK field
     section built from literal field lines, and a response parser that walks field lines for
     `:status` (require 233) and `Hysteria-UDP`.

3. **Obfuscation is a `quinn::AsyncUdpSocket` wrapper.** `SalamanderGeckoSocket` wraps the Tokio UDP
   socket and applies, per packet: **Salamander** (8-byte random salt + `BLAKE2b-256(key‖salt)`
   keystream XOR) and, when enabled, **Gecko** (QUIC long-header packets fragmented into 2–8
   randomly-padded frames — `[0x80][msgID][chunkIdx:4|total:4][padLen u16be][padding][chunk]` — each
   independently Salamander-obfuscated; short-header packets pass through). Gecko **wraps** Salamander
   with the **same password**, matching upstream. **GSO/GRO are disabled**
   (`max_transmit_segments`/`max_receive_segments` → 1) so every datagram is one cleanly-obfuscated
   QUIC packet. `blake2` is the only crypto primitive added (the AEADs are QUIC's, inside quinn).

4. **Out of scope (v1), explicitly:** Brutal congestion control (fixed-rate), port hopping, the
   masquerade/decoy HTTP site, the server side, and multipath (the `noq` swap). `Hysteria-CC-RX` is
   advertised from `down_mbps` (0 = unknown → server uses BBR), but spark does not implement Brutal.

## Consequences

**Positive.** spark's first QUIC transport, with no upstream-crate dependency; the wire format is
auditable and self-contained behind our traits, so the eventual `noq`/multipath swap is a
single-module change. Salamander **and** Gecko are both shipped and live-validated — the
censorship-relevant requirement. The base build stays rustls/ring-only and free of the QUIC stack
(everything is behind the `hysteria2` feature, OFF by default; `cargo tree` confirms no
quinn/blake2/webpki-roots leak into the base build).

**The one interop fix the live gate surfaced:** the real (quic-go) server **Huffman-encodes** its
QPACK response header names and values, so the hand-rolled `/auth` response decoder needed an
**RFC 7541 Appendix B Huffman decoder** (the T7 design flagged this as the realistic risk; the gate
confirmed it). With the decoder added, auth returned 233 with zero further fixes, and TCP+UDP worked
on first interop across all three obfs modes.

**Costs / risks.** Four crates added **behind the `hysteria2` feature** (no base-build impact):
`quinn`, `quinn-udp`, `blake2`, and `webpki-roots` (Mozilla's compiled-in CA bundle for the
`system-roots` TLS mode — chosen over `rustls-platform-verifier` for a small, portable, mobile-clean
bundle with no OS-trust-store integration; see the CA-roots decision below). The auth path is a
**minimal** HTTP/3 (single bidi stream, no SETTINGS/control streams) — sufficient for `/auth` against
the real server, validated live, but not a general H3 client.

**Deferred limitation (tracked):** `SocketProtector` is **not yet applied** to the QUIC/obfs UDP
socket — `connect()` binds `0.0.0.0:0` and the `hysteria2_transport` builder accepts the protector
only for signature symmetry. On a routed-tunnel setup the data-plane UDP socket would not be pinned
to the protected interface; threading it through is follow-up work.

**TLS.** `rustls`/`ring`, **TLS 1.3 only**, ALPN `h3`. Three verifier modes (config `tls.mode`):
`system-roots` (webpki-roots), `pin-sha256` (leaf-cert SHA-256 pin, normalized to tolerate the
colon-separated form, with the handshake signature still verified against the pinned cert — not a
blanket accept), and `insecure` (self-signed test servers). The default is `system-roots`; the
permissive verifier is reachable **only** for `insecure`/`pin-sha256`.

**Wiring / shape.** Gated behind a `hysteria2` cargo feature
(`= ["dep:quinn", "dep:quinn-udp", "dep:blake2", "dep:webpki-roots"]`); code lives in
`core/src/transport/hysteria2/{mod,obfs,tcp,udp,auth}.rs`. Config is `ServerSpec::Hysteria2` +
`[transport.hysteria2]` (`server`, `auth`, `sni?`, `down_mbps?`, `[.tls]`, `[.obfs]`); the bootstrap
`resolve_endpoints` carries the SNI slot. A `#[cfg(not(feature = "hysteria2"))]` builder stub makes a
configured-but-not-built transport a clear hard error (mirrors anytls/shadowsocks/wasm).

**Threat-model note.** Plain QUIC + the `h3` ALPN is increasingly fingerprinted/SNI-blocked by the
GFW; **Salamander** (proven in China) and **Gecko** (handshake-shape obfuscation) are the
censorship-resistance layers and are both shipped. As with the other transports, this is positioned
as one arm in the pool, not a universal solution; full QUIC mimicry (matching a real browser's QUIC
fingerprint) and the masquerade site are future work.

## CA-roots decision (sub-decision for `system-roots`)

`rustls`/`quinn` are in the tree but ship no roots source. For the `system-roots` mode we adopted
**`webpki-roots`** (Mozilla's compiled-in CA bundle) over `rustls-platform-verifier`: it is pure
Rust, identical on every platform including the required Android/Apple mobile targets, needs no
OS-trust-store integration (JNI/SecTrust), and is small — at the cost of not honoring private/
corporate CAs and needing periodic bundle bumps. For a circumvention transport (public-CA servers,
or self-signed servers covered by `pin-sha256`/`insecure`), that trade is right. Compiled only when
the `hysteria2` feature is on.

## References

`docs/hysteria2-design.md` (full wire format, build order, threat model); ADR 0001 (BoringSSL mimicry
+ TLS backend), ADR 0007 (Samizdat), ADR 0009 (Shadowsocks); `apernet/hysteria` (the protocol +
`extras/obfs/gecko*.go`, `salamander.go`) as the interop oracle; RFC 9000 (QUIC), RFC 9221 (QUIC
datagrams), RFC 9114 (HTTP/3), RFC 9204 (QPACK), RFC 7541 (HPACK prefixed integers + the Appendix B
Huffman table). `m11-transport-candidates-anytls-samizdat` memory (QUIC-stack + TLS-backend research).
