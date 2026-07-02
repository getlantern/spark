# DNS-tunnel transport — design

- **Status:** Proposed — clean-slate protocol, no live gate yet. ADR 0011.
- **Scope:** Add a **DNS-tunneling** transport: a spark client `Transport` (TCP byte-stream) that
  carries proxied traffic over DNS queries/responses, aggregating over **many recursive resolvers**
  for resilience, plus a matching **Rust server** (authoritative nameserver + egress). The protocol
  is **spark's own, clean-slate** design — *inspired by* MasterDnsVPN's architecture but **not**
  wire-compatible with it, and not with dnstt/Slipstream. Both ends are ours, so every wire detail is
  ours to audit and modernize.
- **Builds on:** the `Transport` trait seam (`core/src/transport/mod.rs`), the `ServerSpec`/
  `ServerEntry` config model (`core/src/config/mod.rs`), the bootstrap endpoint resolver
  (`core/src/bootstrap/mod.rs`), `transport::protected_udp_socket` / `SocketProtector`, and the
  feature-gating + config-wiring pattern established by Shadowsocks (ADR 0009) and Hysteria 2
  (ADR 0010). Fills the `DNSTT` escalation tier named in `docs/config-new-fetch-design.md` / STATE.md.
- **Design source (architecture, not code):** `masterking32/MasterDnsVPN` (Go, MIT) — battle-tested
  through Iran's 2026 88-day blackout. We take its *ideas* (bespoke low-overhead ARQ, resolver
  load-balancing with duplication + sticky failover, per-resolver MTU probing, compression) and fix
  its weaknesses (1-byte session id, weak/negotiable-to-XOR crypto, unauthenticated ChaCha20, MD5 KDF).
  We rejected **Slipstream** (QUIC-multipath): its only mature multipath-QUIC stack is picoquic
  (C + OpenSSL), which violates spark's pure-Rust / no-C / <3 MB non-negotiables.

---

## 1. Goal & scope

Give spark a transport that still passes traffic when almost nothing else does — a national DNS-only
regime — by tunnelling a reliable byte stream through recursive DNS resolvers, and staying alive when
individual resolvers are blocked, rate-limited, or severed mid-session by aggregating across a large
resolver pool.

DNS tunnelling through a recursive resolver is intrinsically **slow, high-latency, and detectable**
(see §14). This is a **last-resort escalation arm**, not a frontline transport. Its job is *reachability
under total shutdown*, and its differentiator vs. single-resolver tools (dnstt) is **resolver
aggregation + failover**.

**In scope (v1):**
- A `dns-tunnel` client `Transport` (TCP) behind a cargo feature, selectable via
  `[transport.dns-tunnel]` or a `kind = "dns-tunnel"` pool entry.
- A `dns-tunnel-core` crate (pure, no-I/O): wire framing, AEAD + key schedule, ARQ, DNS codec,
  compression, MTU math — shared by client and server, exhaustively unit/fuzz-tested.
- A `dns-tunnel-server` binary: authoritative nameserver for the tunnel zone + session store +
  TCP egress.
- Resolver aggregation: pool from config (IP/CIDR expansion), per-resolver RTT/loss/MTU telemetry,
  selection strategy, packet duplication, per-stream sticky failover, health auto-disable/reactivate.
- Per-resolver MTU probing + a synced pool MTU.
- AEAD (ChaCha20-Poly1305 default, AES-256-GCM optional) with an HKDF-SHA256 per-session key schedule.
- Optional payload compression (LZ4, off by default).
- **Recursive mode** (client → public resolver → our authoritative server; hides server IP; the
  censorship-relevant mode) and **authoritative mode** (client → server IP:53 directly; for testing /
  when the server IP is reachable).

**Out of scope (v1), explicitly:**
- **UDP-over-tunnel** (`UdpTransport`). v1 tunnels TCP streams only; the client's `dial_udp` returns a
  clear "unsupported in this build" error. UDP egress is a localized later increment.
- **Forward secrecy.** v1 is PSK + per-session HKDF salt (per-session key separation, no FS). An
  optional X25519 handshake is a documented future upgrade (§2.4, §16).
- **DoH/DoT carriers.** v1 is plain UDP:53 to resolvers (the shutdown-relevant path). DoH/DoT are a
  later carrier option (they look like HTTPS to fixed IPs and are easier to block during a shutdown).
- **Traffic-shape / anti-detection mimicry** beyond unique-QNAME cache-busting (§14). Lower-entropy
  encodings and query-timing shaping are future work (may reuse `flint-shaping`).
- **dnstt/Slipstream/MasterDnsVPN wire interop.** Deliberately our own protocol.

---

## 2. The protocol (clean-slate)

### 2.1 Carrier & roles
The client is a stub resolver-client: it emits **DNS TXT queries** whose QNAME encodes uplink bytes,
addressed to one of N configured recursive resolvers. The server is the **authoritative nameserver**
for a delegated zone `t.example.com` (an `NS` record delegates `t` to the server's `A`/`AAAA`); the
recursive resolver forwards `*.t.example.com` queries to it. Downlink bytes ride in the **TXT RDATA**
of the answer. An **EDNS0 OPT** RR advertises a larger UDP payload size so responses can exceed 512 B.

The tunnel is a **datagram carrier**: each query/response pair moves one (possibly fragmented) frame.
It is unreliable, reordering, duplicating, and rate-limited — the ARQ layer (§3) makes it reliable.
Following TurboTunnel's decoupling, the **session/reliability layer is independent of the DNS carrier**,
which is exactly what lets one session's frames flow over many resolvers (§4).

### 2.2 Frame format
A frame is `AEAD_seal(nonce, header ‖ payload)` where the plaintext framed structure is:

```
version(1)                      // protocol version + reserved flag bits
flags(1)                        // SYN ACK NACK FIN RST DATA CONTROL COMPRESSED FRAGMENT ...
ConnectionID(8)                 // random, client-chosen; keys the session on the server (see below)
StreamID(2)      [if stream]    // mux many proxied connections over one session
Seq(4)           [if DATA/ACK]  // per-stream sequence / ack number space
FragIdx(1) FragCnt(1) [if FRAGMENT]
CompAlgo(1)      [if COMPRESSED]
payload...
```

On the wire each DNS message carries: `nonce(12) ‖ AEAD_ciphertext ‖ tag(16)`, then base32-encoded into
the QNAME (uplink) or placed raw in TXT RDATA (downlink). The header is compact (variable, ~12–20 B
plaintext) — we keep MasterDnsVPN's low-overhead spirit but widen the identifiers for correctness:

**ConnectionID is 8 random bytes, not 1.** MasterDnsVPN's 1-byte SessionID capped a server at 255
concurrent sessions and tied identity to one path. A wide random ID (a) removes the cap, (b) is the
**TurboTunnel ClientID** that lets the server reassemble a session from frames arriving via *any*
resolver / any source address, and (c) is unguessable. The server keys its session table on it.

### 2.3 Session handshake
```
Client → SYN     : ConnectionID, proposed { cipher, max upload/download MTU, compression, ARQ params }
Server → SYN-ACK : accepted params (clamped to server policy), server cookie, verify token
Client → (data)  : streams opened with per-stream SYN carrying the SOCKS-style target address
```
The `SYN` is AEAD-sealed under the PSK-derived handshake key, so only PSK holders produce a valid first
frame — this is the auth. The server replies only after a valid `SYN` opens (unauthenticated garbage to
:53 is dropped as ordinary malformed DNS), and issues a random **cookie** the client must echo, which
gates session-table allocation against spoofed-source floods. A per-connection **verify token** lets
the server cheaply reject frames not belonging to a live session before doing AEAD work.

### 2.4 Crypto & key schedule
- **PSK** (config; base64, ≥32 bytes). Fixed shared secret; the server auto-generates one if absent.
- **Per-session salt**: 16 random bytes chosen by the client, sent in the clear in the `SYN` DNS
  message prefix (before the sealed frame). Key: `K = HKDF-SHA256(ikm = PSK, salt = session_salt,
  info = "spark-dns-tunnel v1 " ‖ ConnectionID)`. Separate `info` labels derive independent
  upload/download keys and the handshake key.
- **AEAD**: default **ChaCha20-Poly1305** (constant-time in software → mobile-friendly, no AES-NI
  dependency), optional **AES-256-GCM** (both via `ring::aead`). **Random 96-bit nonce per DNS
  message**, carried in the frame — the DNS carrier reorders/drops/duplicates, so a counter nonce
  would desync; per-message random nonce is the correct datagram construction. Per-session key
  separation (above) keeps the random-nonce birthday bound (~2³² messages) *per session*, not global.
- **Key commitment**: prepend a commitment tag (`HKDF(... info="commit")[..16]`) to the first frame to
  avoid AEAD partitioning-oracle ambiguity. (Cheap; only on `SYN`/`SYN-ACK`.)
- **Dropped from MasterDnsVPN**: XOR / none / MD5-KDF / AES-192 / unauthenticated ChaCha20. AEAD only.
- **Future (out of scope v1)**: an X25519 ephemeral handshake for forward secrecy, layered under the
  same framing (§16).

---

## 3. Reliability — the ARQ (`arq` module of `dns-tunnel-core`)

A per-stream reliable, ordered byte-stream over the unreliable frame carrier. Design mirrors
MasterDnsVPN's "QUIC-inspired ARQ" but is our own:

- **Sequence space**: per-stream `snd_nxt` / `rcv_nxt` (u32); send buffer keyed by seq; receive
  reorder buffer.
- **ACK**: cumulative + a bounded **selective NACK** for near-miss gaps (SACK-like), with an initial
  NACK delay and repeat interval and a bounded reorder gap (DNS resolvers reorder by *hundreds* of
  packets — we ignore out-of-order-only loss signals and rely on RACK-style timing, per the Slipstream
  observation).
- **Adaptive RTO**: RFC-6298 (`srtt`, `rttvar`, `RTO = srtt + 4·rttvar`), clamped; multiplicative
  backoff on retransmit.
- **Flow control**: fixed send/receive **window** with backpressure. **No congestion control** — rate
  is governed by window + duplication (§4) + the resolver's own rate-limit, which is the real
  bottleneck. (This is the deliberate, correct choice for the DNS channel; documented so it isn't
  mistaken for an omission.)
- **Stream lifecycle**: explicit `enum` state machine (CLAUDE.md pattern) — `Open`, `HalfClosedLocal`,
  `HalfClosedRemote`, `Closing`, `Draining`, `TimeWait`, `Reset`, `Closed` — with SYN/SYN-ACK,
  half-close (FIN + ACK), RST, and terminal drain timeouts.
- **Control reliability**: control frames (SYN, MTU probes) use a deterministic stop-and-wait
  ACK-type map.

Tested against a **simulated lossy + duplicating + reordering channel** (§13) before any network I/O.

---

## 4. Resolver balancer & multipath (client `balancer` module)

The headline capability. **Not** single-flow packet striping with unified congestion control (that is
Slipstream's QUIC-multipath, which we can't do in pure Rust); instead **query-level fan-out +
duplication + per-stream failover** over a large resolver pool — which aggregates the pool's collective
capacity because many concurrent queries spread across many independently-rate-limited resolvers.

- **Pool**: parsed from config — `IP`, `IP:port`, `CIDR`, `CIDR:port`, `[v6]:port`; **CIDRs expand to
  host IPs** (bounded cap), deduped, default port 53. Each `(resolver × zone)` is a path.
- **Per-resolver telemetry**: RTT (matching responses to sends by DNS txn-id via a sharded pending
  map), a **windowed loss counter with exponential half-life decay** (so stale samples fade), and the
  probed MTU (§5).
- **Selection strategies**: round-robin, weighted, least-loss, lowest-latency, hybrid, and
  "least-loss-top-then-rotate" (shortlist by health, rotate within to avoid pinning). Default: hybrid.
- **Duplication**: send `N` copies of a frame across `N` distinct resolvers for setup-critical or
  high-loss conditions (configurable; server dedups by ConnectionID + seq). Trades bandwidth for
  delivery probability — the key survival mechanism against pulse-severing.
- **Per-stream sticky failover**: each stream sticks to a preferred resolver; on a resend streak past a
  threshold (with cooldown) the stream migrates to a different resolver (`get_best_excluding`). A
  resolver blocked mid-session migrates its streams rather than stalling the session.
- **Health**: auto-disable a resolver on ~100% windowed loss (threshold scaled by pool size); a
  background loop re-probes disabled resolvers and reactivates healthy ones.

---

## 5. MTU discovery (client `mtu` module)
Per-resolver, per-direction **binary search**: upload MTU = how many payload bytes survive in the QNAME
via a given resolver (`MTU_UP_REQ`/`RES` echo); download MTU = how large a TXT response that resolver
will carry (`MTU_DOWN_REQ`/`RES`). Crypto overhead (12 B nonce + 16 B tag) and base32 expansion
(8 chars per 5 bytes) fold into the math. After probing, a **synced pool MTU** is chosen statistically
(e.g. p75 with a bounded drop ratio) so most of the healthy pool shares one MTU; the server clamps it
via handshake policy. Floors: upload ≥ small constant, download ≥ handshake reply size.

---

## 6. Compression (`compression` module)
Optional, applied to the **payload before encryption**, per-direction negotiated in the handshake.
v1 ships **LZ4** via `lz4_flex` (**pure Rust** — deliberately not the C-backed `zstd` crate). Only
compress if `len ≥ threshold` **and** the result is actually smaller (else send uncompressed and clear
the flag); a decompression-size cap guards against bombs. **Off by default** (like MasterDnsVPN) —
opt-in, because the win is situational on such small payloads.

---

## 7. DNS encoding (`dns` module of `dns-tunnel-core`)
- **Uplink (QNAME)**: `nonce ‖ ciphertext ‖ tag` → **base32** (lower-case, DNS-label-safe; hand-rolled
  or `data-encoding`), split into ≤63-byte labels, prefixed to the zone: `<labels>.t.example.com`,
  total ≤253 bytes. Query type **TXT**.
- **Downlink (TXT RDATA)**: raw bytes in TXT character-strings (≤255 B each), multiple strings/records
  for larger payloads with a chunk index header; DNS name-compression pointers on answer names.
- **EDNS0 OPT** on every query advertising a safe larger UDP payload size.
- **Cache-busting / detection**: the random per-message nonce makes **every QNAME unique**, so
  recursive resolvers can't serve cached answers and each query is a one-off lookup. Random DNS txn IDs.
- The DNS wire codec is **hand-rolled and minimal** (no heavyweight DNS crate) — build/parse just the
  query + answer shapes we use — and is the primary **fuzz** target (§13).

---

## 8. Where it sits in spark
A new `Transport` impl alongside `shadowsocks`/`hysteria2`/`samizdat`, reusing spark's dial + config
machinery. Not TLS → no ClientHello / `WirePlan`.

| Need | Reuse |
|---|---|
| Protected UDP dial (bypass tunnel route) | `transport::protected_udp_socket`, `SocketProtector` |
| AEAD + HKDF | `ring::aead` + `ring::hkdf` (already in base) |
| Secure random (nonces, ConnectionID, salt) | `ring::rand::SystemRandom` (no new `rand` dep) |
| Config gating + `from_config` precedence + feature stub | `transport/mod.rs`, `config/mod.rs` |
| Pool membership (latency selection) | `ServerSpec::DnsTunnel` → `build_one` arm |
| Startup name resolution | `bootstrap::resolve_endpoints` (no-SNI slot, like Shadowsocks) |

New client surface under `core/src/transport/dns_tunnel/`:
```
dns_tunnel/
  mod.rs        DnsTunnelTransport: impl Transport; config plumbing; session bring-up
  balancer.rs   resolver pool, telemetry, strategy, duplication, sticky failover, health
  mtu.rs        per-resolver MTU probing + synced pool MTU
  runtime.rs    async send/recv loops: UDP sockets ⇄ frames ⇄ ARQ ⇄ streams
```
Shared logic (framing, AEAD, ARQ, DNS codec, compression) lives in the **`dns-tunnel-core`** crate so
the server reuses it verbatim.

Feature gate: a new `dns-tunnel` cargo feature pulling `dep:dns-tunnel-core` + `dep:lz4_flex`
(+ `dep:data-encoding` if we don't hand-roll base32). Base build stays rustls/ring-only and unaffected.

---

## 9. Crates & dependencies
- **New workspace crates**: `dns-tunnel-core` (lib; pure, no-I/O) and `dns-tunnel-server` (bin).
  Placement: spark workspace initially (velocity, one repo); **`dns-tunnel-core` may migrate to the
  `flint` repo** later to become a `flint-*` shared crate like `flint-shaping`/`flint-tls` (open item).
- **Crypto**: `ring` (AEAD + HKDF + SystemRandom) — already base; no new crypto crate, no C.
- **Compression**: `lz4_flex` (pure Rust). **Not** `zstd` (C).
- **Base32**: hand-roll (small) or `data-encoding` (pure Rust) — decide at M1.
- All feature-gated behind `dns-tunnel`; verify exact `ring::aead`/`ring::hkdf`/`lz4_flex` APIs against
  docs.rs at implementation time (verification discipline).

---

## 10. Config
```rust
/// DNS-tunnel transport configuration (ADR 0011). Clean-slate protocol; see docs/dns-tunnel-design.md.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsTunnelConfig {
    /// The delegated tunnel zone, e.g. "t.example.com".
    pub zone: String,
    /// Pre-shared key, base64 (decoded ≥ 32 bytes). Proxy secret — privileged store only, never over IPC.
    pub psk: String,
    /// Recursive resolvers: IP, IP:port, CIDR, CIDR:port, [v6]:port. CIDRs expand. (Recursive mode.)
    pub resolvers: Vec<String>,
    /// Optional: dial the authoritative server directly (authoritative mode / testing).
    pub authoritative: Option<Endpoint>,
    /// AEAD: "chacha20-poly1305" (default) or "aes-256-gcm".
    #[serde(default)]
    pub cipher: DnsTunnelCipher,
    /// Compression: "off" (default) or "lz4".
    #[serde(default)]
    pub compression: DnsTunnelCompression,
}
```
- `ServerSpec` gains `DnsTunnel(DnsTunnelConfig)` (tag `kind = "dns-tunnel"`); `TransportConfig` gains
  `dns_tunnel: Option<DnsTunnelConfig>`.
- `bootstrap::resolve_endpoints`: DNS-tunnel has **no SNI** (like Shadowsocks) — push a `None` SNI slot;
  resolver IPs are literals (no resolution); `authoritative` (if set) resolves like any endpoint.
- Config validation: PSK base64-decodes to ≥32 B; `zone` is a valid DNS name; ≥1 resolver **or**
  `authoritative` set — else a clear build-time error.

---

## 11. Server (`dns-tunnel-server`)
Authoritative nameserver for the zone + session store + egress, reusing `dns-tunnel-core`:
- Binds UDP/TCP :53 (or an internal port behind a real NS/`iptables` redirect). Answers only
  `*.<zone>` tunnel queries; everything else is `REFUSED`/`NXDOMAIN`.
- **Session store** keyed by ConnectionID (not source address) — this is what makes multi-resolver work
  unmodified: frames for one session arrive from many resolver source IPs and reassemble by ID.
  Bounded, with idle expiry; cookie-gated allocation (§2.3); invalid-cookie tracking → drop.
- Per-session ARQ reassembly (shared code); per-stream **TCP egress** to the target address the client
  opened (SOCKS-style address in the stream SYN). SOCKS5 upstream mode optional (like MasterDnsVPN's
  microsocks pattern) for a decoupled egress.
- **Respond ASAP**: never buffer a query waiting for data (resolvers track authoritative RTT and drop
  slow answers); if there's no downlink data yet, answer with an empty/keep-alive frame. A keep-alive
  cadence lets the server push data by answering client polls.
- Placement TBD: spark workspace vs `lantern-box` (open item) — but the protocol crate is shared either
  way.

---

## 12. Dial flow

```mermaid
sequenceDiagram
    autonumber
    participant Net as netstack
    participant T as DnsTunnelTransport
    participant B as balancer + mtu
    participant R as recursive resolver
    participant S as dns-tunnel-server

    Net->>T: dial(target)
    T->>B: ensure session (ConnectionID, salt)
    B->>R: TXT SYN query base32(nonce ‖ sealed SYN).t.zone
    R->>S: forward *.t.zone
    S-->>R: TXT RDATA sealed SYN-ACK cookie + policy
    R-->>B: answer
    Note over T,S: session up; open a stream carrying target addr
    T->>B: stream SYN target=host:port
    B->>R: TXT DATA frames spread across N resolvers + duplication
    R->>S: forward
    S->>S: reassemble by ConnectionID, ARQ, egress to target
    S-->>R: TXT RDATA DATA frames
    R-->>B: answers
    B-->>Net: BoxedStream bytes both directions
```

---

## 13. Testing & gates
1. **Codec unit + golden vectors** (`dns-tunnel-core`): frame seal/open round-trips; DNS query/answer
   build+parse round-trips (including multi-label QNAME, multi-string TXT, EDNS0); base32 vectors.
2. **`cargo fuzz`** on the DNS parser and the frame parser (untrusted input).
3. **ARQ property tests**: reliable, ordered delivery over a simulated channel with configurable loss /
   duplication / reordering; throughput/latency don't collapse under reorder-only signals.
4. **E2E loopback gate**: `dns-tunnel-server` on UDP:5300, client in authoritative mode; push 10 MiB
   each direction through `Transport::dial`; verify byte-integrity.
5. **Recursive gate** (the real one): delegate `t.<testdomain>` NS → our server; client via a public
   resolver (1.1.1.1); reach a target → HTTP 200.
6. **Multipath gate**: N resolvers configured; block/kill one mid-transfer; assert failover + sustained
   flow (this is the differentiator, so it gets its own gate).
7. **Full `sudo spark run` TUN gate**: curl through TUN → netstack → DnsTunnelTransport → resolver →
   server → internet; **log-hygiene clean** (no resolver IPs, no zone, no PSK in logs).
8. **Workspace sweep**: build/clippy `-D warnings`/fmt clean **with and without** the `dns-tunnel`
   feature; base build pulls neither `dns-tunnel-core` nor `lz4_flex`. Report release binary size delta.

---

## 14. Threat model — why this is an escalation arm
Tunnelling through a recursive resolver is **inherently detectable** by a resolver-side or on-path
analyzer: high-entropy, long, unique QNAMEs and a high TXT-answer volume to one authoritative NS are a
strong signature, and latency is very high. This transport is **not** stealthy against a sophisticated
DNS-aware censor. Its value is **reachability when the alternative is nothing** — a total shutdown where
only DNS to forced local resolvers resolves — and its edge over single-resolver dnstt is **aggregation +
failover** so no single resolver block or pulse-sever kills the tunnel. It sits at the bottom of the
escalation ladder (`domain-fronting → AMP → smart → DNS-tunnel`). Future lower-entropy encodings and
query-timing shaping (possibly via `flint-shaping`) can raise the detection bar; out of scope v1.

---

## 15. Build order (milestones — one bounded chunk per session, green at each boundary)
- **M0 — this spec + `dns-tunnel-plan.md` + ADR 0011.** (Gate: docs reviewed; the protocol is defined.)
- **M1 — `dns-tunnel-core` codec (no network)**: frame framing + AEAD/HKDF; DNS query/answer codec +
  base32 + EDNS0. Golden vectors + fuzz. (No I/O.)
- **M2 — ARQ core**: stream state machine + windowed reliability, tested on a simulated
  lossy/dup/reorder channel. Dominant lift.
- **M3 — single-resolver E2E**: minimal `dns-tunnel-server` + `DnsTunnelTransport::dial` in
  authoritative mode over loopback; 10 MiB integrity gate.
- **M4 — resolver balancer + multipath**: pool/telemetry/strategy/duplication/failover + MTU probing;
  full server (session store + egress). Aggregation + mid-session-failover gates.
- **M5 — recursive mode + spark integration**: through a public resolver via NS delegation; wire into
  `from_config`/`build_one`/`resolve_endpoints` + the DNSTT escalation tier; feature-gated size check;
  log-hygiene audit; TUN gate.

---

## 16. Open questions / risks
- **Detection.** §14 — accept as an escalation arm; note lower-entropy encoding / shaping as future.
- **Server placement** (spark workspace vs `lantern-box`) and **`dns-tunnel-core` → `flint` migration.**
- **Codename.** Feature/crate use the literal `dns-tunnel`; a codename (spark uses `samizdat` etc.) is a
  cosmetic open item.
- **Default cipher.** ChaCha20-Poly1305 chosen for mobile/software constant-time; revisit if AES-NI
  targets dominate.
- **Forward secrecy.** PSK+HKDF v1; X25519 ephemeral handshake is the documented FS upgrade.
- **No congestion control** is intentional (§3) — validate under many parallel resolvers that window +
  duplication + resolver limits don't cause self-inflicted loss storms; add pacing if needed.
- **dnstt-interop mode** (reuse the volunteer dnstt server fleet on shutdown days) — a separate
  complementary transport, out of scope here; worth a future ADR note.
- **ADR.** On approval, record the decision (clean-slate DNS tunnel from MasterDnsVPN's architecture;
  AEAD-only via ring; `lz4_flex`; pure-Rust/no-C) as **ADR 0011**.
