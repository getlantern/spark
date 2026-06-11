# STATE

> Cross-session memory. Read at session start, update at session end. Append to the
> decisions log; never rewrite history. (Template + rules: PLAN.md Appendix A / §2.)

## Current position
- Milestone: **M2 — plain TCP forwarder through the netstack** (session 1 of 1–2 done:
  bridge + accept loop + forwarder implemented, green, unit-tested. Live curl gate pending
  root — session 2).
- Last gate passed: **M0** on 2026-06-10. **M1 (TUN scaffold)** code+tests green
  2026-06-10; live `ping`→ICMP gate still pending a privileged run. **M2 session 1** done
  2026-06-10: TUN↔netstack bridge, accept loop, plain direct-dial TCP forwarder, all behind
  the `Netstack`/`TcpFlow` trait. Forward data-path proven by a hermetic loopback unit test
  (in-memory duplex flow → real echo server → bytes round-trip).
- Tree status: **green** — `cargo check/clippy --all-targets -D warnings/fmt --check`
  clean; `cargo test -p spark-core` = **5 passed**; `netstack_smoke` prints `NETSTACK OK`;
  release `spark` **~1.03 MB**.

## Next chunk (exactly what the next session should do)
**M2 session 2 — live curl gate (needs root; this box has none, so a human must run it).**
Session 1 (bridge + accept loop + forwarder) is done and green; the code path is in
`core/src/netstack/mod.rs` + `core/src/proxy/tcp.rs`, wired through `cli/src/main.rs`.
Remaining to close M2:
1. Run the **Linux** gate from the README "M2 plain-TCP-forwarder gate" section: bring up
   `tun0`, loosen `rp_filter` on the device, then `curl -v --interface tun0 https://1.1.1.1`.
   Expect a successful response + a `tcp flow completed` log line.
   - **Loop hazard (already documented):** do NOT add a routing-table entry for the target
     — `spark`'s own direct dial to that same target would re-enter the tun and loop.
     `curl --interface` (SO_BINDTODEVICE) forces only the client socket into the tun; spark's
     unbound dial stays on the default route. macOS lacks SO_BINDTODEVICE → defer its full
     route test to M4 (no loop once the dial targets a tunnel server at a different address).
2. Record actual routing commands + observed poll-tick/latency in the Decisions log, tick
   the M2 box, and (if a privileged window is open) finally close the M1 ping gate too.
3. Then start **M3a** (address codec + request header) per PLAN §4 — built against the
   Appendix B relay/echo server, NO TUN.

## Blockers / waiting on human
- **M1 live gate (pending, needs root):** run and confirm `ping` replies, then mark M1
  fully passed. macOS: `sudo RUST_LOG=debug ./target/release/spark --addr 10.0.0.1
  --prefix 24`, note the assigned `utunN` in the log, then `ping 10.0.0.2` (ping a *peer*
  in the subnet, not 10.0.0.1 which the host answers locally). Linux: same with
  `--name tun0`. Steps are in README "M1 ICMP-echo gate". This box has **no passwordless
  sudo**, so the agent cannot run it.
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
  `(stream, local_addr, remote_addr)` (`src/tcp.rs:414`). **CORRECTION (M2, verified
  against the construction site `src/tcp.rs:118,132-133,165` where the socket `listen`s
  on `dst_addr`):** netstack-smoltcp **inverts** the usual server-socket naming. The 2nd
  tuple element (`local_addr` = `TcpStream::local_addr()` = the `src_addr` field) is the
  **app's source** (`packet.src_addr`); the 3rd element (`remote_addr` = `dst_addr` field)
  is the **original destination** (`packet.dst_addr`) — the upstream the app dialed.
  **Dial the 3rd element.** The prior M0 note claimed `local_addr` was the original
  destination — that was inferred from the never-fired smoke example and is WRONG; the
  smoke example's variable name has been corrected. `TcpStream: tokio AsyncRead +
  AsyncWrite` (`src/tcp.rs:464,501`) and is `Unpin` (fields: 2×SocketAddr + 2 Arc-style
  shared handles) → `copy_bidirectional` works directly (`&mut *boxed` satisfies its
  `?Sized` bound; compiled + unit-tested at M2).
- `.mtu()` exists in 0.2.x but **not** 0.1.x — do not assume builder methods across versions.
- Toolchain floor: `smoltcp 0.12` needs rustc ≥1.80; `tun-rs` 2.8.x pulls an edition-2024
  dep → effective MSRV **≥ 1.85**. Dev box ran rustc **1.93.1** (active `stable`); MSRV floor
  enforced via `rust-version = "1.85"` in every manifest, not by pinning the toolchain.

### tun-rs (VERIFIED at M1 against the 2.8.5 source — trust)
- `tun_rs::DeviceBuilder::new().ipv4(addr, prefix_or_mask, dst: Option<IPv4>).ipv6(addr,
  prefix).name(S: Into<String>).mtu(u16).build_async() -> io::Result<AsyncDevice>`
  (`src/builder.rs:902,962,980,906,917,1355`). `.ipv4` mask arg is generic `ToIpv4Netmask`;
  a `u8` prefix works (we pass `24`). `build_sync()` also exists.
- `AsyncDevice::recv(&self, &mut [u8]).await -> io::Result<usize>` and `send(&self, &[u8])
  .await -> io::Result<usize>` (inherent; `&self` → shareable via `Arc`)
  (`src/async_device/unix|macos|windows/mod.rs`). `try_recv`/`try_send` exist too.
- `AsyncDevice: Deref<Target = DeviceImpl>`, so `dev.name() -> io::Result<String>` and
  `dev.mtu() -> io::Result<u16>` (and `addresses()`) work via auto-deref
  (`src/async_device/*/mod.rs` Deref; `src/platform/macos/device.rs:182,230`).
- **macOS normalizes utun frames to raw IP** — no 4-byte AF prefix to strip; the parser
  keys on `buf[0] >> 4` on every platform (matches tun-rs's own cross-platform example).
- Framed bridge (for M2): `tun_rs::async_framed::{DeviceFramed, BytesCodec}` behind the
  `async_framed` feature; `DeviceFramed::new(dev, BytesCodec::new())` is a `Stream<Item=
  io::Result<BytesMut>>` + `Sink<BytesMut>`. We added only the `async` feature at M1.

## Baseline binary size
- **M2:** `target/release/spark` = **1,057,008 bytes (~1.03 MB)**, stripped Mach-O arm64.
  +~133 KB over M1 — adds the vendored netstack-smoltcp + smoltcp + async-trait. Budget:
  <3 MB stripped — still comfortable headroom.
- **M1:** 923,344 bytes (~902 KB) — links tun-rs + tokio(full) + clap + tracing-subscriber.
  (M0 was ~280 KB — empty CLI.)

## Decisions log (append-only)
- 2026-06-10 (M2): **Original-destination address fix.** netstack-smoltcp inverts the usual
  server-socket naming: the `TcpListener` tuple's **3rd** element (`remote_addr`) is the
  original destination to dial, not the 2nd. Verified at the construction site
  (`vendor/.../src/tcp.rs:118,132-133,165`, socket `listen`s on `dst_addr`). Corrected the
  STATE verified-facts line and the (never-fired, hence latently-wrong) smoke-example label.
- 2026-06-10 (M2): **Bridge = raw `recv`/`send` loop, not `DeviceFramed`.** Kept the M1
  `Tun::recv`/`send` surface (shared via `Arc<Tun>`, both take `&self`) over adding the
  `tun-rs` `async_framed` feature — fewer moving parts and lower API risk. The stack `Sink`
  item is owned `Vec<u8>` (`AnyIpPktFrame`), so the TUN→stack direction reads into a fresh
  `vec![0u8; mtu]` and `truncate`s — one alloc, zero copy (the alloc is forced by the
  vendored sink signature; eliminating it means patching the vendor to take `BytesMut`).
- 2026-06-10 (M2): Stack built `enable_tcp(true).enable_udp(false).enable_icmp(true)`,
  `.mtu(tun.mtu())`. ICMP rides the TCP interface for free and keeps the M1 ping sanity
  check; UDP deferred to M5. `SmoltcpNetstack` owns the runner + both bridge tasks as
  `JoinHandle`s and aborts them on `Drop` (no orphaned tasks).
- 2026-06-10 (M2): Added `async-trait` (pre-approved in CLAUDE.md for trait objects) for the
  `Netstack` trait. `TcpFlow.stream: Box<dyn AsyncReadWrite + Unpin + Send>`; forwarder
  passes `&mut *stream` to `copy_bidirectional` (its `?Sized` bound accepts the trait object,
  which auto-implements the `AsyncRead`/`AsyncWrite` supertraits).
- 2026-06-10 (M2): **M2 macOS curl gate deferred to M4.** Direct dial + routing the target
  into the tun loops on macOS (no `SO_BINDTODEVICE`); the loop vanishes at M4 when spark
  dials a tunnel server at a different address. Linux gate (per-socket bind) is the M2 check.
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
- 2026-06-10 (M1): **Hand-rolled** the IP parser + ICMP echo logic (`core/src/packet/`)
  instead of pulling `pnet_packet` (what the tun-rs example uses) — a TUN in IP mode never
  sees L2/ARP, and keeping it dep-free protects the size budget. ~120 lines, unit-tested
  (RFC-1071 checksum; v4 IP+ICMP and v6 ICMPv6 pseudo-header).
- 2026-06-10 (M1): **Log hygiene enforced from M1, not deferred to M6.** The driver logs
  `proto`+`len` at `info`; src/dst addresses only at `debug` (`--debug` or `RUST_LOG=debug`).
  Satisfies M1's "logs show parsed packets" without leaking destinations by default.
- 2026-06-10 (M1): tun-rs added with the `async` feature only (tokio AsyncDevice, raw
  recv/send loop). `async_framed` deferred to M2 when the netstack bridge needs it.
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
- [x] M0  [~] M1 (code+tests green; live ping gate pending root)
  [~] M2 (session 1: bridge+forwarder green+unit-tested; live curl gate pending root)
  [ ] M3a [ ] M3b [ ] M4 [ ] M5 [ ] M6
- [ ] M7 (IPC/service split)  [ ] M8 (packaging)  [ ] M9 (Android)  [ ] M10 (Apple)  [ ] M11 (transports)
