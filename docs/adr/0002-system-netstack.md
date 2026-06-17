# ADR 0002 — System (kernel-TCP) netstack as a second `Netstack`

- **Status:** Accepted — 2026-06-17. Built behind the `system-stack` feature, live-gated on Linux
  (netns), and benchmarked. TCP + UDP (mixed); selected via `[tun] stack = "system"`.
- **Scope:** How spark terminates TCP from the TUN. Adds a kernel-TCP option alongside the userspace
  `SmoltcpNetstack`; does not change the proxy core, the transports, or the UDP proxy.
- **Complements:** `docs/tun-to-proxy-design.md` (the original userspace-netstack decision) and the
  full design + measurements in `docs/system-stack-design.md`.

## Context

- spark terminates the application's TCP connections in a **userspace** stack (`netstack-smoltcp`,
  backed by smoltcp) and forwards them through a `Transport`. This was the M2 decision and remains
  the cross-platform default.
- A throughput investigation (`bench/netns-throughput.sh`, 2026-06-17; see
  `docs/system-stack-design.md` §9) found a **severe, reproducible pathology**: with ≥2 concurrent
  download streams, aggregate download throughput **collapses to ~0.2 Gb/s** (vs ~1.5 single-stream)
  while upload is unaffected. Root cause: `netstack-smoltcp` runs `iface.poll()` + per-socket buffer
  shuffling for *all* flows in a **single dispatch task**, and servicing multiple concurrently-
  sending sockets is super-linearly inefficient. Ruled out (each built + benchmarked): channel
  buffer depth, poll-loop park pacing, the device's ingress/egress coupling, retransmit storms, and
  congestion control (smoltcp runs `CongestionControl::None`). A complete userspace fix means
  reworking the netstack's per-flow scheduling — comparable effort to a second stack, less upside.
- sing-box offers exactly this alternative as `stack = system`: a NAT redirect gateway that lets the
  **host kernel** own the TCP state machine. We verified the mechanism against `sing-tun@v0.7.11`.

## Decision

1. **Add a second `Netstack` implementation, the "system" stack**, behind a `system-stack` cargo
   feature (off by default; desktop-only — Linux/macOS), selected by config `[tun] stack = "system"`
   (default `"userspace"`). Selecting it without the feature is a hard startup error.
2. **Mechanism — a NAT redirect gateway** (`core/src/netstack/system/`): the tun's address is the
   `server` (a kernel TCP listener binds there); `gateway = server + 1` is a synthetic source. The
   pump rewrites each TUN packet's TCP 4-tuple — outbound `app→target` becomes `gateway:natPort →
   server:listener` (kernel routes it to the listener; `accept()`'s peer port is the `natPort`),
   inbound `listener→app` is rewritten back to `target → client` — recomputing checksums. A
   `TcpNat` recovers the original `(client, target)` on accept; the accepted **kernel `TcpStream`**
   is surfaced as the same `TcpFlow` the proxy already consumes.
3. **Reuse the trait seam.** The proxy core, forwarders, and every transport are untouched — the
   `Netstack`/`TcpFlow` abstraction plus a blanket `impl Netstack for Box<dyn Netstack>` make the
   stack a runtime choice. This is the payoff of the seam introduced at M2.
4. **Mixed stack for UDP.** UDP/ICMP can't be `accept()`ed, so the pump bridges UDP datagrams to
   spark's existing UDP proxy (which already dials kernel UDP sockets), i.e. sing-box's "mixed":
   kernel-TCP redirect + userspace UDP datagram path. DNS works.
5. **Connection lifecycle.** The pump removes a NAT mapping on RST and marks both-FIN connections
   "closing" for prompt (short-timeout) reclamation, with a long idle timeout as the safety net.

## Consequences

**Positive (measured, netns A/B):**
- **Eliminates the concurrent-download collapse.** Download Gb/s by stream count, userspace vs
  system: 1→0.51/1.19, **2→0.13/1.09 (~8×)**, 4→0.30/0.95, 8→0.41/0.87. The system stack holds
  ~1 Gb/s and stays stable across concurrency (download symmetric with upload) — independent kernel
  sockets, mature kernel congestion control, no shared poll loop, so the pathology cannot occur.
- Moves the TCP state machine (which parses fully untrusted segment streams) out of our binary into
  the hardened kernel; our added surface is a bounded header parse/rewrite, which is fuzzable.

**Negative / tradeoffs:**
- **Lower single-stream peak** (system ~1.2 vs userspace ~1.67 Gb/s up): the single pump task
  rewrites every packet, so it is itself a serialization point. For real workloads (many concurrent
  connections) the stable, collapse-free profile is the better trade; lifting the peak (multiple
  pump tasks, or GSO on the pump) is future work.
- **Desktop-only.** The local-listener + NAT model fits Linux/macOS; mobile keeps smoltcp. So we
  maintain *both* stacks. (Cross-platform default stays userspace.)
- **Operational:** redirected packets re-enter on the TUN destined to a local address, so Linux
  reverse-path filtering (`rp_filter`) must be relaxed on that path. NAT keys on source `addr:port`
  (a reused ephemeral port to a new target before cleanup returns a stale mapping). IPv6 not yet
  wired in the selection path.

**Neutral:** binary size — gated behind a feature, off by default; no impact on the base build.

## Alternatives considered

- **Rework the userspace netstack's per-flow scheduling** — fixes the collapse without a second
  stack, but is comparable effort with less upside (still userspace per-segment TCP) and risks the
  vendored crate we must audit.
- **GSO on the smoltcp TUN bridge** — analyzed; low payoff for spark's userspace path (the
  bottleneck is inside smoltcp's per-segment processing, not the TUN syscall boundary) and it
  doesn't address the collapse (a dispatch-loop, not a syscall, limit). Rejected as the primary fix.
- **Do nothing** — smoltcp is cross-platform and gate-passing, but the collapse is a real,
  user-visible defect under ordinary concurrent download (e.g. a browser).

## References

- `docs/system-stack-design.md` — full design, the sing-tun mechanism, and the §9 measurements.
- `bench/netns-throughput.sh` — the `--stack {userspace,system}` A/B harness.
- `core/src/netstack/system/` — `nat`, `rewrite`, `pump`, `stack`.
- sing-tun `@v0.7.11`: `stack_system.go`, `stack_system_nat.go` (the reference mechanism).
