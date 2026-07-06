# ADR 0011 — DNS-tunnel transport: a clean-slate protocol inspired by MasterDnsVPN, resolver-aggregating, pure-Rust

- **Status:** Accepted — implemented M0–M5 (`dns-tunnel-core` + client `DnsTunnelTransport` with
  resolver balancer/multipath/failover + `dns-tunnel-server` with real TCP egress), wired into
  transport selection. Self-contained gates green (loopback E2E, multi-resolver aggregation +
  mid-session failover, real-TCP-egress e2e); base build unaffected; log-hygiene clean. The live
  recursive-NS and `sudo` full-TUN runs need infrastructure/root — the documented human step. Full
  design + build order: `docs/dns-tunnel-design.md`; implementation plan: `docs/dns-tunnel-plan.md`.
- **Scope:** Add a **DNS-tunneling** transport — a spark client `Transport` (TCP byte-stream) that
  tunnels proxied traffic over DNS while **aggregating over many recursive resolvers**, plus a matching
  **Rust server** (authoritative nameserver + session store + TCP egress). Fills the `DNSTT` escalation
  tier named in `docs/config-new-fetch-design.md` / STATE.md. Client-side is one arm in the transport
  pool; the server is new infrastructure Lantern deploys.
- **Builds on:** the `Transport` trait seam, the `ServerSpec`/`ServerEntry` config model, the bootstrap
  endpoint resolver, `transport::protected_udp_socket` / `SocketProtector`, and the feature-gating +
  config-wiring pattern established by Shadowsocks (ADR 0009) and Hysteria 2 (ADR 0010).

## Context

During Iran's Feb 2026 total shutdown (net4people/bbs#586), DNS tunnels were among the only transports
passing any traffic. spark named DNSTT as an escalation tier but never built it. We want a DNS tunnel
whose differentiator over single-resolver tools is **resilience through resolver aggregation +
failover**: when one resolver is blocked, rate-limited, or severed on a censor's pulse schedule, the
tunnel keeps flowing over others.

We evaluated three references:
- **dnstt** (KCP+smux+Noise+TurboTunnel): interops with the volunteer server fleet, but its Rust story
  leans on thin KCP/smux/Noise crates, and it is single-resolver (multi-resolver would be a client-side
  add).
- **Slipstream** (QUIC-multipath over DNS): the most elegant — QUIC collapses reliability+mux+crypto
  and multipath aggregates resolvers with unified congestion control. **But** its only mature
  multipath-QUIC stack is **picoquic (C + OpenSSL + cmake)** (`Mygod/slipstream-rust` FFIs it); mainline
  `quinn` has no multipath and enforces the ≥1200-byte QUIC MTU floor. This violates spark's
  pure-Rust / no-C / <3 MB non-negotiables.
- **MasterDnsVPN** (`masterking32/MasterDnsVPN`, Go, MIT, 6.5k★): hand-rolls everything (bespoke ARQ,
  resolver load-balancing with duplication + sticky failover, per-resolver MTU probing, compression) in
  pure Go with trivial deps. Battle-tested through Iran's 88-day blackout. Because it depends on no
  exotic library, it is the **cleanest pure-Rust fit** and delivers multi-resolver resilience **without**
  a QUIC stack — at the cost of no unified congestion control (window + duplication + failover instead).

Three decisions had to be made: which design to base on, whether to interop with an existing
implementation, and how far to take v1.

## Decision

1. **Base on MasterDnsVPN's architecture, but implement spark's OWN clean-slate protocol** — not
   wire-compatible with MasterDnsVPN, dnstt, or Slipstream. Both client and server are ours, so every
   wire detail is ours to audit and modernize. This is the "design-only" choice: take the field-proven
   ideas, fix the weaknesses.
   - **Adopt:** compact binary framing; bespoke low-overhead ARQ (adaptive RFC-6298 RTO, SACK-like NACK
     gap recovery, windowed flow control, TCP-like lifecycle, **no congestion control** — correct for
     the DNS channel, where the resolver rate-limit is the bottleneck); resolver load-balancing (large
     pool with IP/CIDR expansion, per-resolver RTT/loss/MTU telemetry with half-life decay, selection
     strategies, **packet duplication**, **per-stream sticky failover**, health auto-disable/reactivate);
     per-resolver **MTU binary-search probing** + synced pool MTU; optional LZ4 compression; UDP:53 +
     TXT answers + base32 QNAME + EDNS0 + unique-QNAME cache-busting.
   - **Fix:** a **wide 8-byte random ConnectionID** (MasterDnsVPN's 1-byte SessionID capped a server at
     255 sessions and coupled identity to one path; a wide ID lifts the cap and is the TurboTunnel
     ClientID that lets a session reassemble from frames arriving via any resolver); **AEAD only**
     (ChaCha20-Poly1305 default, AES-256-GCM optional, via `ring`) with a **random 96-bit nonce per DNS
     message** (the datagram-correct construction — a counter would desync over a reordering/dropping
     carrier) and an **HKDF-SHA256 per-session key schedule** (per-session key separation bounds the
     nonce birthday risk); **dropped** XOR / none / MD5-KDF / AES-192 / unauthenticated ChaCha20.

2. **Pure-Rust, no C.** Crypto is `ring` (AEAD + HKDF + `SystemRandom`), already in base. Compression is
   **`lz4_flex`** (pure Rust), **not** the C-backed `zstd` crate. The DNS wire codec is hand-rolled and
   minimal (no heavyweight DNS crate). Everything is behind a `dns-tunnel` cargo feature, OFF by
   default, so the base build stays rustls/ring-only and within the <3 MB budget.

3. **Crate layout.** A shared no-I/O crate **`dns-tunnel-core`** (framing, AEAD+HKDF, ARQ, DNS codec,
   compression, MTU math), the client transport under `core/src/transport/dns_tunnel/` (balancer, MTU
   prober, runtime), and a **`dns-tunnel-server`** binary. `dns-tunnel-core` starts in the spark
   workspace and **may migrate to the `flint` repo** to become a shared `flint-*` crate (like
   `flint-shaping`/`flint-tls`) once stable.

4. **Out of scope (v1), explicitly:** UDP-over-tunnel (`UdpTransport` — a later increment; `dial_udp`
   errors clearly); ~~forward secrecy~~ (**subsequently implemented** — the PSK model was replaced by a
   forward-secret X25519 ephemeral↔ephemeral handshake authenticated by the server's static Ed25519 key;
   see the Status line, §2.4, and `dns-tunnel-core/src/session.rs`); DoH/DoT carriers (v1 is UDP:53, the
   shutdown-relevant path); traffic-shape
   mimicry beyond unique-QNAME cache-busting; and dnstt/Slipstream/MasterDnsVPN wire interop.

## Consequences

**Positive.** spark gains a shutdown-resilient escalation transport whose differentiator is resolver
aggregation + failover — the capability that mattered in the Iran blackout. Pure-Rust/no-C keeps the
base build lean and the <3 MB budget intact (feature-gated). Because both ends are ours and the design
is modernized (wide ConnectionID, AEAD-only, HKDF), we avoid MasterDnsVPN's security weaknesses and the
255-session cap. The ARQ/framing/DNS-codec logic is a shared, fuzzed crate reused verbatim by the server.

**Costs / risks.** This is the **largest** transport build to date: a bespoke ARQ (the dominant lift), a
full resolver balancer, per-resolver MTU probing, and a **server** (spark's transports have so far been
client-only). Two new crates. **No wire interop** with the volunteer dnstt server fleet — Lantern must
deploy `dns-tunnel-server` (a dnstt-interop mode to reuse volunteer servers is possible later, separate
ADR). **Detection:** tunnelling through a recursive resolver is inherently detectable by a DNS-aware
censor (high-entropy unique QNAMEs, high TXT volume to one NS) and is high-latency — this is a
last-resort escalation arm, not a stealthy frontline transport; lower-entropy encoding and query-timing
shaping are future work. **No congestion control** is a deliberate choice for the DNS channel that must
be validated under many parallel resolvers (add pacing if self-inflicted loss appears).

**Socket protection.** The tunnel's UDP sockets are created via `protected_udp_socket(resolver,
protector)` so that with a `SocketProtector` configured the transport's own DNS packets bypass the
tunnel route on a routed full-tunnel setup.

**Wiring / shape.** Gated behind a `dns-tunnel` cargo feature (`= ["dep:dns-tunnel-core",
"dep:lz4_flex"]`); client code in `core/src/transport/dns_tunnel/{mod,runtime,balancer,mtu}.rs`; config
is `ServerSpec::DnsTunnel` + `[transport.dns-tunnel]` (`zone`, `psk`, `resolvers`, `authoritative?`,
`cipher?`, `compression?`); bootstrap `resolve_endpoints` uses a no-SNI slot (like Shadowsocks). A
`#[cfg(not(feature = "dns-tunnel"))]` builder stub makes a configured-but-not-built transport a clear
hard error (mirrors shadowsocks/hysteria2).

## References

`docs/dns-tunnel-design.md` (full wire format, crypto, ARQ, balancer, DNS encoding, MTU, threat model);
`docs/dns-tunnel-plan.md` (milestone plan). ADR 0009 (Shadowsocks — from-scratch, `ring` AEAD idiom,
no-SNI resolve refactor), ADR 0010 (Hysteria 2 — QUIC-stack/no-C reasoning, `protected_udp_socket`
threading), ADR 0007 (Samizdat). Design sources: `masterking32/MasterDnsVPN` (architecture oracle —
`arq/`, `client/balancer.go`, `client/mtu.go`, `vpnproto/`, `security/`), `EndPositive/slipstream` +
`Mygod/slipstream-rust` (QUIC-multipath-over-DNS, rejected on the C-picoquic dependency), David
Fifield's dnstt / TurboTunnel (FOCI 2020 — the ClientID/decoupling model). net4people/bbs#586 (the
shutdown that motivates this).
