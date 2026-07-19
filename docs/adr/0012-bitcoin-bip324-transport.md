# ADR 0012 — Bitcoin (BIP324) opening-move transport: be the real v2 wire protocol on port 8333

- **Status:** Proposed — 2026-07-18. Design only, no code yet. Full analysis + build order:
  `docs/bitcoin-transport-design.md`.
- **Scope:** Add a spark client `Transport` (TCP byte-stream) that carries proxied traffic inside the
  **genuine Bitcoin P2P v2 encrypted transport (BIP324)** on **TCP 8333**, so DPI classifies the flow
  as a Bitcoin node connection. The blockable part (opening choreography + framing) ships as a signed,
  dynamically-delivered opening-move WASM byte-transform; the heavy crypto stays native. The matching
  server runs a real `bitcoind` with a keyed side-door for probe resistance (new infra Lantern deploys).
- **Builds on:** the `Transport` seam (`core/src/transport/mod.rs`); the dynamic-transport WASM sandbox
  (ADR 0003) — pure byte-transform, no WASI/sockets, native crypto via `env` imports; the early-bytes /
  opening-shaping thesis (ADR 0006); the signed/key-pinned/versioned gambit delivery
  (`core/src/transport/wasm/signing.rs`); and the feature-gating + `ServerSpec` config wiring of AnyTLS
  (0001), Shadowsocks (0009), Hysteria 2 (0010), DNS-tunnel (0011).

## Context

Every mimicry transport fights the "Parrot is Dead" problem: to look like protocol X you must
replicate all of X's behavior, and you never fully do. Bitcoin removes the problem. Since Bitcoin Core
26 (2023) the P2P protocol has an official encrypted transport, **BIP324 ("v2")**, whose *explicit
design goal* is that every byte on the wire is pseudorandom and carries no distinguisher — it was
built to deny DPI a Bitcoin fingerprint. So instead of mimicking Bitcoin we **implement genuine
BIP324** and put our tunnel bytes where the Bitcoin messages would go; a BIP324 session carrying proxy
data is byte-indistinguishable from one carrying real `tx`/`block`/`inv` traffic (both are an
unfingerprintable opening + AEAD ciphertext).

This is strictly easier than the TLS/ClientHello gambits (ADR 0006): TLS has a huge cleartext
fingerprint surface that must stay pinned to a real Chrome; BIP324 has no fingerprint to match.

The offsetting cost — recorded honestly so it drives deployment policy — is **weak collateral
freedom**: unlike TLS-to-a-CDN, blocking port 8333 / Bitcoin is politically cheap for censors who
already restrict crypto (e.g. China). We defeat generic DPI, not a decision to target Bitcoin.

## Decision

1. **Be BIP324, don't mimic it.** v2-only for the initial design (v1 legacy framing documented as a
   fallback but not built). Port 8333.
2. **Opening move in the WASM sandbox (ADR 0003).** The module is a pure byte-transform doing the
   BIP324 handshake + packet framing; heavy crypto (secp256k1 ellswift/ECDH, HKDF, ChaCha20-Poly1305/
   FSChaCha20) is native via `env` imports (the performance escape hatch). Only the choreography —
   garbage lengths, decoy timing, keyed-auth encoding — is dynamic. Delivered signed/key-pinned/
   versioned as a "Bitcoin gambit," parameterized via the `gambit-compute` export so the repertoire
   stays polymorphic without reshipping the module.
3. **Probe resistance by being real.** The server runs an actual `bitcoind` on 8333 (joins the
   network, appears in `addr` gossip and node crawlers). A thin BIP324-terminating front reads a keyed
   MAC hidden in the client's BIP324 garbage: match → tunnel; no match (real peer or active prober) →
   hand the raw connection to `bitcoind`. REALITY-style: the prober reaches a genuine node.
4. **Deploy as one regional gambit, not a default** — appropriate where Bitcoin is tolerated, given
   the weak collateral freedom.

## Consequences

- **Positive:** no fingerprint to match (much cheaper to maintain than TLS gambits); genuine protocol
  = strongest possible wire-level indistinguishability; probe-resistant by running a real node; slots
  into the existing WASM/gambit + `Transport` seams with no core changes; new infra is a stock
  `bitcoind` plus a small front.
- **Negative / residual:** bulk-flow traffic shape ≠ a gossiping node (the real weakness — behavioral
  analysis is the exposure); weak collateral freedom against Bitcoin-specific blocking; **BIP324's
  random opening is *not* exempt from the GFW's fully-encrypted-traffic detector** — a v2 flow to a
  monitored VPS range is flagged, so the node must run on residential / non-flagged ASNs (design §6
  item 5); server IPs must actually run nodes to have node reputation. (v2 adoption is *not* a
  concern: it is now the majority of global Bitcoin P2P traffic, so v2-only is the mainstream case.)
- **Probe-resistance boundary:** holds against a *credential-less* censor; a censor who extracts a
  valid PSK from a captured client can probe as a real client (inherent to all credentialed
  probe-resistant designs). Contain via per-track/per-server PSKs + rotation (design §5.2).
- **Open questions** (see design doc §8): v2-only acceptability; shaping budget. The keyed-garbage
  authenticator is now specified (§5.1), and the raw-splice-vs-relay + timing-parity questions are
  resolved via Parrot-is-Dead reasoning (§5.2).
