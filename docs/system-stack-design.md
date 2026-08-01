# Design: System (kernel-TCP) Netstack — a second `Netstack` behind the trait

- **Status:** **Built + live-gated (TCP) — 2026-06-17.** Implemented behind the `system-stack`
  feature (`core/src/netstack/system/`), selected via `[tun] stack = "system"`. The netns A/B
  (below, §9 "Validated") confirms it eliminates the concurrent-download collapse. TCP + UDP (mixed
  stack). The decision is recorded in `docs/adr/0002-system-netstack.md`; this doc is the design +
  measurements behind it.
- **Scope:** A second implementation of the existing `core::netstack::Netstack` trait that lets the
  **host kernel** own the TCP state machine, as an alternative to the userspace `SmoltcpNetstack`.
  Mirrors sing-box's `stack = system` option. Does **not** change the proxy core, the transports
  (including the M11 AnyTLS one), or the UDP path.

## 1. Motivation

Today spark has exactly one netstack: `SmoltcpNetstack` (`core/src/netstack/mod.rs:74`), a *userspace*
TCP/IP stack. In sing-box terms that is the **gVisor** stack — the application's TCP connections are
terminated and reassembled by a TCP state machine running inside our process (smoltcp, where sing-box
uses gVisor's netstack).

sing-box also offers a **system** stack, where the **host kernel** runs the TCP state machine and the
tool is reduced to a packet-rewriting NAT gateway. The question this doc answers: *can spark offer the
same choice, and what would it cost?*

Why it's attractive:
- **Mature TCP**: kernel CUBIC/BBR, SACK, window scaling, PMTU discovery, ECN, and segmentation
  offload — all battle-tested, none of which a small userspace stack matches.
- **CPU / throughput**: no userspace reassembly; the kernel does the heavy lifting.
- **Smaller attack surface in *our* binary**: the TCP state machine (which parses fully untrusted
  segment streams) moves into the hardened kernel. We keep only a header-rewriting layer.

## 2. What "system stack" actually is (verified against `sing-tun@v0.7.11`)

The three sing-box stacks (`sing-tun/stack.go:39-58`) differ almost entirely in **how TCP is
handled**. UDP is a userspace flow-NAT in *every* mode.

### gvisor (`stack_gvisor.go`)
Full userspace TCP/IP. spark's `SmoltcpNetstack` is the direct equivalent.

### system (`stack_system.go`) — kernel TCP via a NAT redirect gateway
There is **no userspace TCP state machine**. The mechanism:

1. **Local listener.** On start it opens real kernel `net.Listener`s on the tun's gateway address
   (`stack_system.go:128-158`, v4 + v6) and remembers their ports (`tcpPort`/`tcpPort6`).
2. **NAT table.** A `TCPNat` (`stack_system_nat.go`) maps an original **source** `addr:port` → an
   allocated synthetic port (`addrMap map[netip.AddrPort]uint16`, `:18`). `Lookup(source, destination)`
   (`:83`) allocates on first sight and stores a `TCPSession{source, destination}` keyed by that port.
3. **Outbound rewrite.** An app SYN/segment `(src=clientSrc, dst=target)` is rewritten so the **kernel
   routes it to the local listener** — destination becomes the listener, source becomes
   `gateway:natPort` — and checksums are fixed. The kernel's own TCP stack now drives the connection.
4. **Accept + recover.** `acceptLoop` (`:319`) does `listener.Accept()` — a genuine kernel `TCPConn` —
   then `tcpNat.LookupBack(connPort)` (`:326`, `stack_system_nat.go:69`) recovers
   `(clientSrc, target)` from the synthetic port.
5. **Reply rewrite.** Packets from the listener are rewritten back to `(src=target, dst=clientSrc)`
   (`LookupBack` again at `:391` / `:486`), checksums fixed, written to the TUN.
6. **UDP** is *not* kernel-accepted (no connectionless `Accept`); it's a userspace UDP NAT
   (`udpnat2`, `:161`) that still dials real kernel UDP sockets upstream.

### mixed (`stack_mixed.go`)
Embeds `*System` for TCP (`:18`) and bolts a **gVisor UDP forwarder** on top
(`SetTransportProtocolHandler(udp.ProtocolNumber, …)`, `:47`). So: system TCP + gVisor UDP.

> **Key reframe.** The "stack" choice is really *"who owns the TCP state machine — our process or the
> kernel?"* For UDP there is no real choice: it's a flow-NAT to kernel sockets either way. **spark's
> UDP path already works exactly like the system stack's** — `DirectPacketSink` is a kernel
> `UdpSocket` and smoltcp only demuxes the TUN side — so a spark "system stack" is almost entirely a
> *TCP* feature, and combining it with our existing UDP path gives us sing-box's "mixed" for free.

## 3. Why spark fits this cleanly

The `Netstack` trait was put in this seam deliberately (CLAUDE.md; `core/src/netstack/mod.rs:8-11`).
The proxy core consumes only:

```rust
// core/src/netstack/mod.rs
pub struct TcpFlow {
    pub original_dst: SocketAddr,   // upstream to dial
    pub src: SocketAddr,            // app's source inside the tunnel
    pub stream: BoxedStream,        // Box<dyn AsyncReadWrite + Unpin + Send>
}

#[async_trait]
pub trait Netstack: Send {
    async fn accept_tcp(&mut self) -> Option<TcpFlow>;
}
```

The accept loop in `core/src/proxy/tcp.rs:27` is `while let Some(flow) = netstack.accept_tcp().await`.
A system-stack impl yields `TcpFlow`s where `stream` is a real kernel `tokio::net::TcpStream` — which
already `impl`s `AsyncRead + AsyncWrite`, hence `AsyncReadWrite` (`core/src/lib.rs:30`). So:

**The proxy core, every forwarder, and every transport — including the M11 AnyTLS transport — stay
byte-for-byte unchanged.** That is the entire payoff of the abstraction.

What we already own that this needs: raw TUN read/write (`tun-rs`, via `core::tun::Tun`), the routing
/ kill-switch manager, and — critically — `SocketProtector` / `protect_interface` for loop avoidance
(see §6).

## 4. Proposed implementation: `SystemNetstack`

A new module `core/src/netstack/system/` implementing `Netstack`. Sketch (illustrative, not final):

```rust
pub struct SystemNetstack {
    accept_rx: mpsc::Receiver<TcpFlow>, // fed by the accept loop
    tasks: Vec<JoinHandle<()>>,         // packet pump + accept loop + NAT reaper; aborted on drop
}

#[async_trait]
impl Netstack for SystemNetstack {
    async fn accept_tcp(&mut self) -> Option<TcpFlow> {
        self.accept_rx.recv().await
    }
}
```

Three cooperating tasks (all `JoinHandle`s stored, per CLAUDE.md):

1. **Packet pump** — owns `Arc<Tun>`. Reads IP packets; for TCP it rewrites headers per §2 and writes
   them back to the TUN so the kernel routes them to/from the local listener; for UDP/ICMP it forwards
   to the existing paths. The only genuinely new, fiddly code:
   - a **`TcpNat`** (bidirectional `source ⇆ natPort`, with a session record holding `src` +
     `original_dst`, and idle reaping);
   - **header rewrite + incremental IP/TCP checksum fixup** (RFC 1624 style — adjust, don't recompute
     from scratch on the hot path).
2. **Accept loop** — owns the kernel `TcpListener`(s) bound to the gateway address:
   ```rust
   let (stream, peer) = listener.accept().await?;
   let session = nat.lookup_back(peer.port())?;       // recover (src, original_dst)
   accept_tx.send(TcpFlow {
       original_dst: session.original_dst,
       src: session.src,
       stream: Box::new(stream),                       // kernel TcpStream ⇒ AsyncReadWrite
   }).await;
   ```
3. **NAT reaper** — evicts stale entries (FIN/RST observed, or idle timeout), mirroring sing-tun's
   timeout-driven cleanup.

**UDP**: reuse spark's existing netstack UDP surface unchanged (this is our "mixed"). We can keep
smoltcp purely for UDP demux while TCP goes through the kernel, or port UDP to its own NAT later — the
trait already separates the two surfaces.

## 5. Configuration surface

Mirror sing-box. A single knob on the TUN config:

```toml
[tun]
stack = "userspace"   # default — SmoltcpNetstack (cross-platform, already gate-passing)
# stack = "system"    # kernel TCP via the NAT gateway (desktop; see platform matrix)
```

`from_config`-style wiring picks the `Netstack` impl; everything downstream is trait-generic. (A
`"mixed"` value can be added if we ever want to be explicit, but our default UDP path already makes
`"system"` behave as mixed.)

## 6. Loop avoidance (the load-bearing correctness concern)

A NAT gateway that leans on the kernel must guarantee kernel-originated packets don't re-enter the
TUN and recurse. spark already solves the analogous problem for upstream dials with `SocketProtector`
/ `protect_interface` (the macOS-required, Linux-recommended pin to the egress NIC). For the system
stack:

- The **local listener** lives on the tun gateway address; its accepted sockets' traffic is what the
  packet pump rewrites — that loop is intentional and bounded by the NAT table.
- The **upstream dials** (made by the proxy after `accept_tcp`) must bypass the tunnel route — already
  handled by `protect_interface`.
- The **rewrite must never produce a packet whose routing sends it back through the TUN** except the
  intended listener delivery. This is the part to test adversarially.

## 7. Platform matrix

| Platform | Feasibility | Notes |
|---|---|---|
| **Linux** | Good | The userspace-NAT approach needs no `TPROXY`/iptables (sing-tun does the rewrite itself). Runs in the privileged tunnel process. |
| **macOS** | Good | utun + userspace NAT; runs in the M10 system extension that owns the utun. |
| **Windows** | More work | sing-tun keeps a *separate* `stack_system_windows.go` — bind/socket semantics differ. |
| **Android** | **Viable** (corrected 2026-06-17) | Android's `VpnService` hands the app a **Linux tun fd**; sing-tun adopts it (`tun_linux.go New()`, `FileDescriptor != 0` branch) with no platform restriction, and **sing-box runs `stack: system` on Android** this way. spark's android build just doesn't *enable* the `system-stack` feature yet — a choice, not a limit. Android-specific plumbing: use `VpnService.protect()` for upstream-socket protection (vs. `IP_UNICAST_IF`). This means the collapse fix could reach Android, not only desktop. |
| **iOS** | Keep userspace | `NEPacketTunnelFlow` (Network framework), **not** a Linux tun fd and no kernel tun — the redirect-to-local-listener mechanism doesn't apply. sing-box runs gVisor on iOS with shrunken TCP buffers (`stack_gvisor_tcpbuf_ios.go`). smoltcp stays the iOS path. |

> **Correction (2026-06-17):** an earlier version of this doc + ADR 0002 said the system stack was
> "desktop-only" because it "fights the mobile sandbox." That conflated Android with iOS. Android is
> Linux-with-a-tun-fd → the system stack works (verified against `sing-tun@v0.7.11`); only **iOS** is
> genuinely precluded (no kernel tun). GSO is orthogonal: `enableGSO()` is a runtime
> `IFF_VNET_HDR` check that *gracefully degrades to single-packet* if the fd lacks it (standard
> `VpnService` does), so the system stack runs on Android with or without GSO.

## 8. Security / attack surface

- **Removed from our binary:** the TCP state machine — the component that parses fully untrusted,
  adversarially-ordered segment streams. It moves into the kernel.
- **Added to our binary:** a header-parse-and-rewrite layer. Still untrusted-input-facing, but
  strictly *smaller* than a state machine — it inspects/edits IP+TCP headers and recomputes
  checksums, nothing more.
- Net: plausibly a **reduction** in our exposure, contingent on the checksum/rewrite code being
  correct (fuzz the rewrite path).

## 9. Performance — read this before claiming "system is faster"

The historical "system ≫ gVisor" throughput gap has **narrowed** because sing-tun added
**segmentation offload (GSO/GRO)** to the TUN path itself (`tun_offload.go`, `tun_linux.go:148-193`),
batching packets across the TUN boundary for *any* stack. So:

- The durable wins of system stack are **CPU efficiency**, **congestion-control maturity**, and
  **attack-surface reduction** — not a guaranteed headline throughput multiple.
- If raw throughput is the goal, **adding GSO to our existing smoltcp TUN bridge may be the
  cheaper lever** than a whole second stack. Worth benchmarking *before* committing to this design.

### Measured (2026-06-17, `bench/netns-throughput.sh`)

A throwaway 2-vCPU DigitalOcean droplet (Ubuntu 24.04, kernel 6.8), single TCP stream, 15s/direction.
The kernel baseline is veth/loopback-class (~20 Gb/s, no real NIC) — read the **absolute** spark
numbers and CPU, not the %.

| build | up (Gb/s) | down (Gb/s) | spark CPU |
|---|---|---|---|
| kernel baseline (veth) | ~20 | ~20 | — |
| spark smoltcp, `opt-level="z"` (ship profile) | 0.81 | 0.68 | ~130% |
| spark smoltcp, `opt-level=3` (speed) | 1.61 | 1.37 | ~121% |

Findings:
1. **The ship profile (`opt-level="z"`, for the <3 MB goal) costs ~2× throughput.** A speed build
   nearly doubled it. This is a free, low-risk lever independent of the stack question (use a speed
   profile for desktop, or `opt-level=3` on `core` only).
2. **No multi-flow scaling — a single serialized netstack pipeline.** At 4 parallel streams, upload
   *fell* to 1.27 Gb/s (below the 1.61 single-stream) and download collapsed to ~0.06 Gb/s; the
   download path also intermittently stalls outright. Parallelism adds contention on the one smoltcp
   poll-loop / bridge, it doesn't add throughput.
3. **Userspace ceiling ≈ 1.5 Gb/s single-stream at >1 core** (speed-built).

Implication: the userspace stack is a real throughput/CPU ceiling *and* has a concerning download
fragility + zero multi-flow scaling — all of which a kernel/system stack (each flow a real kernel
socket, kernel congestion control, no single poll loop) would address.

### Download-collapse investigation (2026-06-17)

The concurrent-download collapse was chased to root cause. Reproduction: with **≥2 concurrent
download streams** (`iperf3 -R -P N`), aggregate download throughput collapses to **~0.2 Gb/s** (vs
~1.5 single-stream), while upload is unaffected. The diagnostic (`iperf3 -J`): download starts
~290 Mb/s then settles to a steady ~100 Mb/s/flow with **low retransmits (21)** and 0 on upload — a
low *equilibrium*, not a loss/RTO storm.

Hypotheses tested and **ruled out** (each built + benchmarked on the netns droplet):
- **Channel buffer depth** — bumping `stack_buffer_size` 1024→16384 raised the collapsed floor ~14×
  (0.03→0.42 Gb/s at 4 streams) but did **not** restore full throughput. Kept as a partial
  mitigation (`core/src/netstack/mod.rs`).
- **Poll-loop park pacing** — capping the `poll_delay` park to 500 µs: no change.
- **Ingress/egress coupling** — `VirtualDevice::receive` refusing inbound packets when the egress
  channel is full (a real latent issue) decoupled: no change to the collapse (reverted for hygiene —
  no measured benefit, and it touches untrusted-packet code).
- **Congestion control** — N/A: the vendored crate enables neither `socket-tcp-cubic` nor
  `-reno`, so smoltcp runs `CongestionControl::None` (pure window-based).

Conclusion: the collapse is a **single-dispatch-task pathology** in netstack-smoltcp — one task runs
`iface.poll()` + per-socket buffer shuffling for *all* flows, and servicing multiple concurrently
*sending* sockets is super-linearly less efficient (1→2 download flows drops aggregate ~8×). This is
not a quick tunable; it is the structural limit the design doc predicts, and it is exactly what a
kernel/system stack avoids (independent kernel sockets, no shared poll loop). A complete userspace
fix means reworking the netstack's per-flow scheduling — comparable effort to the system stack, with
less upside.

**Order of operations going forward:** (a) `opt-level` fix — **done** (free ~2×). (b) Download
collapse — **characterized; partial mitigation landed; full fix deferred** (system stack or a
netstack per-flow rework). (c) GSO on the bridge — prototype next; it batches segments across the
TUN boundary and may *also* relieve the per-packet loop overhead behind the collapse. Decide on the
system stack after (c).

### Validated (2026-06-17, `bench/netns-throughput.sh --stack {userspace,system}`)

The system stack was built (chunks 1–5) and A/B'd against userspace on the same droplet. Single TCP
stream → N concurrent, 8s/direction; download is the collapse metric:

| streams | userspace ↓ (Gb/s) | system ↓ (Gb/s) | userspace ↑ | system ↑ |
|---|---|---|---|---|
| 1 | 0.51 | 1.19 | 1.67 | 1.20 |
| 2 | **0.13** | **1.09** | 1.47 | 1.16 |
| 4 | 0.30 | 0.95 | 1.29 | 1.09 |
| 8 | 0.41 | 0.87 | 1.23 | 1.02 |

**The system stack eliminates the concurrent-download collapse** — userspace craters to 0.13 Gb/s at
2 streams while the system stack holds ~1.09 (≈8×) and stays stable (0.9–1.2) across all concurrency;
download becomes symmetric with upload. Confirms the thesis: independent kernel sockets, no shared
poll loop, so the single-dispatch pathology cannot occur.

The tradeoff: single-stream *upload* peak is lower (system ~1.2 vs userspace ~1.67) because the
single pump task rewrites every packet — the pump is itself a serialization point. CPU is comparable
(~130–140%). For real workloads (browsers open many concurrent downloads) the stable, collapse-free
profile is the better trade.

### Where the single-stream peak goes (2026-06-17)

Chased the per-packet cost. Switched the pump's TCP checksum from full recompute (O(payload)) to an
**incremental update** (RFC 1624, O(1) in the changed fields) and A/B'd it on one box, system stack:
full-recompute 1.39/1.27 vs incremental 1.46/1.33 Gb/s (up, 1/4 streams) — **within run-to-run
noise, CPU unchanged**. So the checksum was *not* the bottleneck; the **per-packet syscall overhead
is** (`tun.recv` + `tun.send` per packet on the single pump task). The lever for the single-stream
peak is therefore **syscall batching**:
- **GSO/GRO via `IFF_VNET_HDR`** (Linux): the kernel hands/accepts large TSO super-buffers, so the
  pump does one rewrite + one syscall per *batch* of segments. This is the right place for GSO (the
  system-stack bottleneck is at the boundary GSO batches, unlike the userspace stack — §9 above).
  The incremental checksum is kept because the vnet-header/csum-offload path *requires* incremental
  pseudo-header adjustment (you can't full-recompute an offloaded checksum).
- **Multiple pump tasks** (shard flows across N tasks) — orthogonal, also lifts the peak.

Caveats confirmed live: needs `rp_filter=0` on the redirected path; NAT cleanup now handles FIN/RST;
UDP/DNS work via the mixed stack.

### Benchmarking on macOS (`bench/macos-throughput.sh`, added 2026-08-01)

**Not yet run — the system stack has never been exercised on macOS at all.** Every live gate so far
was Linux netns. The Rust has no platform gating and this module claims Linux/macOS/Android, but
"compiles" is not "works": use `--smoke` first, which stops after a 2s transfer, before trusting any
number.

The harness exists because the netns trick has no macOS equivalent. **A single-box tunnel benchmark
is impossible here**: the kernel hairpins traffic addressed to a local IP straight to `lo0` *before*
consulting the route table, so a route pointing that address at the TUN never fires. The peer must be
a genuinely different host — a LAN machine, a VM with its own routable IP (Lima/UTM; **not** Docker
Desktop, whose containers aren't routable from the host), or a cloud box. The script refuses to start
if `--peer` is an address configured on this Mac, because that mistake does not fail loudly — it
quietly measures loopback and reports plausible numbers.

```bash
# on the peer:  iperf3 -s -p 5201
sudo ./bench/macos-throughput.sh --peer <ip> --stack system --smoke      # does it work at all?
sudo ./bench/macos-throughput.sh --peer <ip> --stack userspace --streams 2
sudo ./bench/macos-throughput.sh --peer <ip> --stack system    --streams 2
```

What it can and cannot answer:
- **Can**: whether the concurrent-download collapse reproduces on macOS and whether the system stack
  fixes it. The collapse takes userspace to ~0.13 Gb/s, so it is visible on any link above roughly
  200 Mb/s — a WAN peer is good enough for this, which is the metric that matters.
- **Cannot**: peak throughput, if the link saturates first. Baseline and tunnel both pinned at line
  rate means the run is link-bound; the script says so in its output rather than letting the numbers
  be over-read.

If the system stack fails its smoke test on macOS, the first suspect is packet re-entry: redirected
packets arrive on the TUN destined to a *local* address, which on Linux required `rp_filter=0`. macOS
has no `rp_filter`, so this is genuinely unknown territory rather than a known fix.

## 10. Tradeoffs & alternatives

**For:** kernel TCP maturity/CPU; smaller in-binary attack surface; the trait makes it a drop-in
second impl with zero core/transport churn; UDP reuse gives "mixed" for free.

**Against:** real new code (NAT table + checksum-correct header rewriting + listener lifecycle +
reaper); per-platform divergence (Windows especially); a new rewrite layer to fuzz; loop-avoidance
must be airtight; mobile won't use it, so we maintain *both* stacks indefinitely.

**Alternatives considered:**
- *Do nothing* — smoltcp is cross-platform and already passes the live gates. Lowest risk.
- *GSO on smoltcp* (§9) — likely the bigger throughput win per unit effort; orthogonal and could ship
  first.
- *Adopt `ipstack` or another userspace netstack* — still userspace; doesn't get kernel TCP.

## 11. Recommendation & open questions

**Recommendation:** treat this as a future-milestone effort (an M11-adjacent or post-M11 "transport/
datapath" arc), gated on a benchmark. Before building, measure: (a) smoltcp throughput/CPU today, and
(b) the same with GSO added to the existing bridge. If GSO closes the gap, the system stack's case
rests on CPU + attack-surface + congestion control alone — still real, but no longer urgent.

**Open questions:**
1. Exact gateway-address / synthetic-port scheme for the rewrite (copy sing-tun's, or simpler since
   we control both ends?).
2. Do we want true `"mixed"` semantics, or is "system TCP + our existing UDP" sufficient (probably
   yes)?
3. Windows: worth the separate code path, or desktop = Linux/macOS only at first?
4. Where does this sit relative to the remaining M11 transport work and the deferred per-stream
   flow-control item?

## References

- sing-tun (`@v0.7.11`): `stack.go:39-58` (selection), `stack_system.go` (system stack),
  `stack_system_nat.go` (TCPNat), `stack_mixed.go` (mixed), `stack_gvisor*.go`, `tun_offload*.go` /
  `tun_linux.go` (GSO/GRO).
- spark: `core/src/netstack/mod.rs` (`Netstack`, `TcpFlow`, `SmoltcpNetstack`),
  `core/src/proxy/tcp.rs:27` (accept loop), `core/src/lib.rs:30` (`AsyncReadWrite`),
  `docs/tun-to-proxy-design.md` (the userspace-stack decision this complements).
