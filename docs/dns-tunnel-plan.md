# DNS-tunnel Transport Implementation Plan

> **For implementers:** work milestone-by-milestone, task-by-task — TDD each task (failing test
> first), keep the tree green at every boundary, and commit per task. This plan is at **milestone
> granularity**; the detailed per-task TDD steps for a milestone are expanded at the *start* of that
> milestone (so the doc doesn't drift ahead of the code). Steps use checkbox (`- [ ]`) syntax.

**Goal:** Add a **DNS-tunneling** transport to spark — a client `Transport` (TCP) that carries proxied
traffic over DNS while aggregating over many recursive resolvers, plus a matching Rust server. A
**clean-slate protocol** inspired by MasterDnsVPN's architecture; **not** wire-compatible with it,
dnstt, or Slipstream. Both ends are ours.

**Architecture:** A shared no-I/O crate `dns-tunnel-core` (framing, AEAD+HKDF, ARQ, DNS codec,
compression, MTU math), a client transport under `core/src/transport/dns_tunnel/` behind a `dns-tunnel`
cargo feature (resolver balancer + MTU prober + runtime), and a `dns-tunnel-server` binary
(authoritative NS + session store + TCP egress). AEAD is ChaCha20-Poly1305 (default) / AES-256-GCM via
`ring`; **forward-secret** key schedule — HKDF-SHA256 over an ephemeral↔ephemeral X25519 shared secret,
the server authenticated by its static Ed25519 key (the PSK model was replaced; see ADR 0011 +
`dns-tunnel-core/src/session.rs`); compression is `lz4_flex` (pure Rust).

**Tech Stack:** Rust, tokio, `ring` (AEAD/HKDF/rand), `lz4_flex` (feature-gated), `bytes`,
`async-trait`, `tokio-util::codec`. Spec: `docs/dns-tunnel-design.md`. ADR: `docs/adr/0011-dns-tunnel-transport.md`.

**Conventions (spark CLAUDE.md — every task):** one `thiserror` `Error` enum per module; no
`unwrap()`/`expect()` outside tests/startup; `BytesMut` (not `Vec<u8>`) on data paths, `with_capacity`;
no `MutexGuard` across `.await`; only cancel-safe futures in `select!`/`poll`; explicit `enum` state
machines for protocol cores; `cargo fmt` + `cargo clippy --all-targets -- -D warnings` clean before
every commit. **Verification discipline:** check exact `ring::aead` / `ring::hkdf` / `ring::rand` /
`lz4_flex` signatures against docs.rs before use — do not guess. The in-repo `ring::aead` idiom to
mirror is `core/src/transport/shadowsocks/crypto.rs` (`LessSafeKey` + `Nonce::assume_unique_for_key` +
`seal_in_place_append_tag` / `open_in_place`).

**Log hygiene (non-negotiable):** never log resolver IPs, the tunnel zone, target addresses, or the
PSK. Redact by default (CLAUDE.md / GOAL.md).

---

## Crate & file structure

| Path | Responsibility | Milestone |
|---|---|---|
| `Cargo.toml` (modify) | workspace members `dns-tunnel-core`, `dns-tunnel-server`; `[workspace.dependencies]` `lz4_flex` | M1 |
| `dns-tunnel-core/` (create) | pure no-I/O crate — see below | M1–M2 |
| `dns-tunnel-core/src/frame.rs` | frame header + flags + (de)serialization; header check | M1 |
| `dns-tunnel-core/src/crypto.rs` | PSK decode, HKDF key schedule, `ring` AEAD wrappers, SystemRandom | M1 |
| `dns-tunnel-core/src/dns.rs` | DNS TXT query/answer build+parse, QNAME base32 labels, EDNS0 OPT | M1 |
| `dns-tunnel-core/src/compress.rs` | LZ4 compress/decompress with threshold + bomb cap | M1 |
| `dns-tunnel-core/src/arq/` | reliable stream state machine (seq/ack/nack/RTO/window/lifecycle) | M2 |
| `dns-tunnel-core/src/mtu.rs` | MTU math (payload↔QNAME capacity, crypto overhead) | M1 |
| `dns-tunnel-core/fuzz/` | `cargo fuzz` targets: DNS parser, frame parser | M1 |
| `core/Cargo.toml` (modify) | `dns-tunnel` feature; optional `dns-tunnel-core`, `lz4_flex` deps | M3 |
| `core/src/config/mod.rs` (modify) | `DnsTunnelConfig`, `DnsTunnelCipher`, `DnsTunnelCompression`, `ServerSpec::DnsTunnel`, `TransportConfig.dns_tunnel`, `first_unresolved_host` arm | M3 |
| `core/src/bootstrap/mod.rs` (modify) | `resolve_endpoints` arm (no-SNI slot; resolver IPs literal) | M3 |
| `core/src/transport/mod.rs` (modify) | `dns_tunnel_transport` builder, `from_config` precedence, `build_one` arm, gated `pub mod dns_tunnel` | M3/M5 |
| `core/src/transport/dns_tunnel/mod.rs` (create) | `DnsTunnelTransport: impl Transport`; session bring-up | M3 |
| `core/src/transport/dns_tunnel/runtime.rs` (create) | UDP send/recv loops ⇄ frames ⇄ ARQ ⇄ streams | M3 |
| `core/src/transport/dns_tunnel/balancer.rs` (create) | resolver pool, telemetry, strategy, duplication, sticky failover, health | M4 |
| `core/src/transport/dns_tunnel/mtu.rs` (create) | per-resolver MTU probing + synced pool MTU | M4 |
| `dns-tunnel-server/` (create) | authoritative NS + session store + TCP egress (bin) | M3–M4 |
| `docs/adr/0011-dns-tunnel-transport.md` (create) | the ADR | M0 |

---

## M0 — Spec & docs  *(this milestone)*
- [x] `docs/dns-tunnel-design.md` — the wire/crypto/ARQ/balancer/DNS/MTU spec (the gate).
- [x] `docs/dns-tunnel-plan.md` — this plan.
- [x] `docs/adr/0011-dns-tunnel-transport.md` — the decision record.
- [x] Update `docs/STATE.md` (position + this transport's sub-milestones under M11).
- **Gate:** docs reviewed; the protocol is fully specified before any code.

## M1 — `dns-tunnel-core` codec (no network)
Tasks (TDD each; commit per task):
1. Workspace wiring: add `dns-tunnel-core` member + `lz4_flex` workspace dep; empty crate builds.
2. `crypto.rs`: forward-secret handshake — per-session X25519 ephemerals + a static Ed25519 server
   identity (verify the `SynAck` transcript signature); HKDF-SHA256 session-key schedule
   (upload/download labels) over the ephemeral↔ephemeral shared secret; `Aead` wrapper
   (ChaCha20-Poly1305 + AES-256-GCM via `ring::aead::LessSafeKey`); `SystemRandom` nonce/ID/ephemeral
   helpers. KATs + seal/open round-trip + tamper-reject + signature-verify.
3. `frame.rs`: header (version/flags/ConnectionID/StreamID/Seq/Frag/Comp) encode+decode; header check;
   `seal_frame`/`open_frame` (nonce ‖ ciphertext ‖ tag). Round-trip + malformed-reject tests.
4. `dns.rs`: build TXT query (QNAME base32 labels ≤63, total ≤253, EDNS0 OPT); parse; build/parse TXT
   answer (multi-string, multi-record, chunk header, name-compression). Golden vectors + round-trips.
5. `compress.rs`: LZ4 compress-if-smaller + threshold + decompress bomb cap. Round-trip + skip tests.
6. `mtu.rs`: payload↔QNAME-capacity math incl. base32 expansion + crypto overhead. Unit tests.
7. `fuzz/`: `cargo fuzz` targets for the DNS parser and frame parser; run briefly, fix any panics.
- **Gate:** `cargo test -p dns-tunnel-core` green; fuzz targets build and survive a short run; the
  crate has **no** tokio/network deps.

## M2 — ARQ core
Tasks:
1. `arq/` types: per-stream send/recv buffers, seq spaces, window, RTO (RFC-6298), NACK gap tracker.
2. Stream state machine (`Open`/`HalfClosed*`/`Closing`/`Draining`/`TimeWait`/`Reset`/`Closed`) with
   SYN/SYN-ACK/FIN/RST + control stop-and-wait ACK map.
3. A **simulated channel** test harness (configurable loss / duplication / reordering / latency).
4. Property tests: reliable, ordered delivery under loss+dup+reorder; RTO backoff; NACK recovery;
   no collapse on reorder-only signals; window backpressure.
- **Gate:** property tests green across a matrix of channel conditions; deterministic (seeded) repro.

## M3 — single-resolver end-to-end
Tasks:
1. `core` config types + `dns-tunnel` feature + module skeleton + `from_config`/`build_one`/
   `resolve_endpoints`/`first_unresolved_host` wiring (no-SNI). Workspace green with/without feature.
2. `dns-tunnel-server` skeleton: bind UDP, answer `*.<zone>` tunnel queries, session table keyed by
   ConnectionID, cookie gating, per-session ARQ, single-stream TCP egress (authoritative mode).
3. `DnsTunnelTransport::dial` + `runtime.rs`: one resolver (or direct `authoritative`), session
   handshake, open a stream with the target addr, pump ARQ over UDP DNS.
4. E2E integration test over loopback (server on :5300, client authoritative mode): 10 MiB each way,
   byte-integrity.
- **Gate:** loopback 10 MiB integrity gate passes; feature-off base build unaffected.

## M4 — resolver balancer + multipath
Tasks:
1. `balancer.rs`: pool parse (IP/CIDR expansion, dedup, default :53), per-resolver telemetry
   (RTT via txn-id match, windowed loss + half-life decay), selection strategies.
2. Duplication (N copies across resolvers; server dedups by ConnectionID+seq) + per-stream sticky
   failover (resend-streak threshold + cooldown → migrate) + health auto-disable/reactivate.
3. `mtu.rs` (client): per-resolver binary-search probing (up/down) + synced pool MTU; server MTU-probe
   handlers + policy clamp.
4. Server: full session store (idle expiry, bounds), SOCKS5/TCP egress, dedup, ASAP-respond/keep-alive.
- **Gates:** (a) aggregation — throughput scales with pool size; (b) mid-session failover — block/kill
  a resolver mid-transfer, flow continues.

## M5 — recursive mode + spark integration
Tasks:
1. Recursive-mode gate: delegate `t.<testdomain>` NS → our server; client via a public resolver
   (1.1.1.1) reaches a target → HTTP 200.
2. Wire into transport selection / the `domain-fronting → AMP → smart → DNS-tunnel` escalation tier.
3. `cargo build --release --features dns-tunnel` size delta report (<3 MB budget; base build clean).
4. Full `sudo spark run` TUN gate + log-hygiene audit (no resolver/zone/target/PSK in logs).
- **Gate:** recursive + TUN gates pass; size within budget; logs clean.

---

## The authoritative oracle is the E2E/recursive gate, not this prose.
Where a byte layout here disagrees with what the client and server actually agree on over the wire,
fix the code and the golden vectors — but since both ends are ours, the **spec (`dns-tunnel-design.md`)
is authoritative**; update it deliberately if the design changes, don't let code and doc drift.
