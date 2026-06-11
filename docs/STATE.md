# STATE

> Cross-session memory. Read at session start, update at session end. Append to the
> decisions log; never rewrite history. (Template + rules: PLAN.md Appendix A / §2.)

## Current position
- Milestone: **M1 — TUN scaffold** (not started)
- Last gate passed: **M0 (netstack compile gate)** on 2026-06-10 — `NETSTACK OK`,
  release build clean, clippy + fmt clean, on rustc 1.93.1.
- Tree status: **green** (`cargo check --workspace`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo fmt --check` all clean as of 2026-06-10).

## Next chunk (exactly what the next session should do)
Execute **M1 — TUN scaffold** (PLAN.md §4). One bounded session:
1. Add `tun-rs` (2.8.x, `async`/`async_framed` features) as a workspace dependency and
   wire it into `core/`. **Verify the `tun-rs` 2.8.x async API against docs.rs/source
   before writing against it** — the crate has both sync and async surfaces and the
   builder/`into_framed` shape has moved across minor versions.
2. `core/src/tun/`: an async TUN abstraction (open device, async read/write of IP
   packets, expose a framed Stream/Sink of `AnyIpPktFrame`-shaped buffers so it bridges
   straight into the netstack later).
3. `core/src/packet/`: a minimal zero-copy IPv4/IPv6 parser (version, proto, src/dst).
   Use `bytes` (add to the locked deps list — it's already named in CLAUDE.md).
4. `cli/src/main.rs`: replace the M0 banner with a driver that brings the device up,
   logs `{src,dst,proto,len}` for each packet, and replies to ICMP echo requests.
5. **Gate (Linux):** bring the device up, `ping <tun-addr>` returns ICMP echo replies
   produced by the tool; logs show parsed packets. NOTE: dev box is macOS (`utun`) — the
   gate is specified on Linux. Decide at session start whether to gate on a Linux box/VM
   or to bring up `utun` on macOS and adapt the ping test; record the platform caveat.

## Blockers / waiting on human
- None for M1.
- **M1 platform note:** PLAN's M1 gate is written for Linux (`ping <tun-addr>` → ICMP
  reply). This dev box is macOS arm64 (`utun`). Either run the gate on Linux or adapt to
  `utun` and note the naming/route caveat (PLAN M1 checkpoint asks for exactly this).
- Upcoming (not blocking yet): a simple TCP relay test server needed at **M3** (PLAN
  Appendix B); if a transport TLS-wraps its relay, confirm the `rustls` client config
  (verification + roots) before trusting it.

## Verified API facts (RE-CONFIRMED at M0 on rustc 1.93.1 against vendored 0.2.2 source — trust)
- netstack-smoltcp **0.2.2** vendored at `vendor/netstack-smoltcp/` (src copied from the
  crates.io 0.2.2 tarball via `static.crates.io`; lib-only manifest; `smoltcp` pinned `=0.12.0`).
- `StackBuilder::default()` is fluent — `.enable_tcp(bool).enable_udp(bool).enable_icmp(bool)
  .stack_buffer_size(n).tcp_buffer_size(n).udp_buffer_size(n).mtu(n).build()` →
  `io::Result<(Stack, Option<Runner>, Option<UdpSocket>, Option<TcpListener>)>`.
  (Confirmed: `src/stack.rs:103` `build()` returns exactly that tuple; `.mtu()` at `src/stack.rs:97`.)
  Builder defaults: stack_buffer 1024, udp 512, tcp 512, **mtu 1504** (1500 + 4 VLAN).
- `enable_icmp(true)` requires `enable_tcp(true)` — builder returns `InvalidInput "ICMP
  requires TCP"` otherwise (`src/stack.rs:129`). ICMP echo is serviced by the TCP Interface.
- `Runner`, if present, must be `tokio::spawn`'d (drives the smoltcp poll loop).
- `Stack: Stream<Item = std::io::Result<AnyIpPktFrame>>` + `Sink<AnyIpPktFrame, Error =
  io::Error>` (`src/stack.rs:203,216`). Note the **`io::Result` wrapper on the stream item** —
  the bridge does `while let Some(Ok(pkt)) = stream.next().await`. `stack.split()` gives the
  two halves. `AnyIpPktFrame = Vec<u8>` (`src/packet.rs:5`).
- `TcpListener: Stream<Item = (TcpStream, SocketAddr, SocketAddr)>` =
  `(stream, local_addr, remote_addr)` (`src/tcp.rs:414`); **`local_addr` is the original
  destination** (the tunnel target). `TcpStream: tokio AsyncRead + AsyncWrite` (`src/tcp.rs:464,501`)
  and is `Unpin` (fields: 2×SocketAddr + 2 Arc-style shared handles) → `copy_bidirectional`
  works directly (compiled in `core/examples/netstack_smoke.rs`).
- `.mtu()` exists in 0.2.x but **not** 0.1.x — do not assume builder methods across versions.
- Toolchain floor: `smoltcp 0.12` needs rustc ≥1.80; `tun-rs` 2.8.x pulls an edition-2024
  dep → effective MSRV **≥ 1.85**. Dev box ran rustc **1.93.1** (active `stable`); MSRV floor
  enforced via `rust-version = "1.85"` in every manifest, not by pinning the toolchain.

## Baseline binary size (M0)
- `target/release/spark` = **285,936 bytes (~280 KB)**, stripped Mach-O arm64. NOT yet a
  meaningful floor: the CLI links only the (empty) `spark-core` lib — the netstack is pulled
  in by the *example*, not the shipped binary. Real size tracking starts at M1/M2 when the
  CLI links the TUN + netstack paths. Budget: <3 MB stripped.

## Decisions log (append-only)
- 2026-06-10 (M0): Vendored `netstack-smoltcp` **0.2.2** by copying the published crates.io
  0.2.2 source (via `static.crates.io`) into `vendor/netstack-smoltcp/`, rewritten to a
  lib-only manifest (examples/tests/dev-deps dropped) with `smoltcp` pinned to `=0.12.0`.
  Excluded from `[workspace.members]` (`exclude` in root manifest) so its dev-deps don't
  enter our lock; depended on by `path` via `[workspace.dependencies]`.
- 2026-06-10 (M0): Workspace members = `core` (`spark-core`), `cli` (`spark-cli`, bin
  `spark`), `ipc` (`spark-ipc`, empty stub), `service` (`spark-service`, empty stub).
  `netstack-spike` and `circ-tool` also `exclude`d. Release profile (opt-level=z, lto=fat,
  cu=1, strip, panic=abort) lives in the **root** manifest (profiles only apply from root).
- 2026-06-10 (M0): `rust-toolchain.toml` uses `channel = "stable"` (not a hard pin); MSRV
  floor ≥1.85 enforced by `rust-version` in each manifest. Active stable on dev box = 1.93.1.
- Language/stack: Rust + tokio + rustls(ring) + ring; netstack = **vendored** netstack-smoltcp
  over smoltcp; TUN = tun-rs (desktop). Rationale in CLAUDE.md (locked stack).
- MSRV ≥ 1.85 (toolchain floor above).
- Process model: privileged tunnel process + unprivileged client; **data plane in-process**,
  control-plane IPC only (`ipc/` crate, serde+postcard, length-prefixed, versioned handshake).
- Kill-switch: **fail open** (restore direct routing on crash, surfaced loudly) with a
  per-profile fail-closed override. (process-architecture-and-ipc.md §5.)
- DNS strategy default: **proxy-through-tunnel** (revisit at M5 if needed).
- FFI (mobile): **uniffi-rs** preferred (confirm at M10).
- Config format: TOML (alternate import formats deferred).

## Milestone checklist
- [x] M0  [ ] M1  [ ] M2  [ ] M3a [ ] M3b [ ] M4 [ ] M5 [ ] M6
- [ ] M7 (IPC/service split)  [ ] M8 (packaging)  [ ] M9 (Android)  [ ] M10 (Apple)  [ ] M11 (transports)
