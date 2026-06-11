# STATE

> Cross-session memory. Read at session start, update at session end. Append to the
> decisions log; never rewrite history. (Template + rules: PLAN.md Appendix A / §2.)

## Current position
- Milestone: **M2 — plain TCP forwarder through the netstack** (not started)
- Last gate passed: **M0** on 2026-06-10. **M1 (TUN scaffold) implemented + green +
  unit-tested on 2026-06-10**; the *live* `ping`→ICMP gate is **pending a privileged run**
  (no passwordless sudo on this box — see Blockers). Echo-reply logic itself is proven by
  unit tests (valid IPv4+ICMP checksums, swapped addresses).
- Tree status: **green** — `cargo check/clippy --all-targets -D warnings/fmt --check`
  clean; `cargo test -p spark-core` = 4 passed; release `spark` ~902 KB.

## Next chunk (exactly what the next session should do)
**First**, if not already done, run the M1 live gate to fully close M1 (one command, needs
root — see Blockers). Then execute **M2 — plain TCP forwarder through the netstack**
(PLAN.md §4), session 1 of 1–2:
1. `core/src/netstack/`: write the `Netstack`/`TcpFlow` trait (per CLAUDE.md) + the
   netstack-smoltcp impl. Bridge the TUN ↔ `Stack`: `stack.split()` → forward
   `tun.recv` bytes into the `Sink` and `Stream` items back out via `tun.send`. **Add the
   `tun-rs` `async_framed` feature now** and consider `DeviceFramed`/`BytesCodec` for the
   bridge, OR keep the raw `recv`/`send` loop and convert `BytesMut`↔`Vec<u8>`
   (`AnyIpPktFrame = Vec<u8>`; the `Stack` stream item is `io::Result<Vec<u8>>`).
2. Spawn the netstack `Runner` (required); accept loop pulls `(TcpStream, local_addr=
   original_dst, remote_addr)` from the `TcpListener`.
3. `core/src/proxy/tcp.rs`: for each flow, `tokio::net::TcpStream::connect(original_dst)`
   then `copy_bidirectional` (DIRECT dial — no tunnel transport yet; that's M3/M4).
4. Session-1 boundary: bridge + accept loop compiling green. Session 2: routing docs +
   the green `curl --interface <tun> https://1.1.1.1` gate (needs root + route setup).

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
  `(stream, local_addr, remote_addr)` (`src/tcp.rs:414`); **`local_addr` is the original
  destination** (the tunnel target). `TcpStream: tokio AsyncRead + AsyncWrite` (`src/tcp.rs:464,501`)
  and is `Unpin` (fields: 2×SocketAddr + 2 Arc-style shared handles) → `copy_bidirectional`
  works directly (compiled in `core/examples/netstack_smoke.rs`).
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

## Baseline binary size (M1)
- `target/release/spark` = **923,344 bytes (~902 KB)**, stripped Mach-O arm64. Now
  meaningful: links tun-rs + tokio(full) + clap + tracing-subscriber. (M0 was ~280 KB —
  empty CLI.) Budget: <3 MB stripped — comfortable headroom.

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
- [x] M0  [~] M1 (code+tests green; live ping gate pending root)  [ ] M2  [ ] M3a [ ] M3b [ ] M4 [ ] M5 [ ] M6
- [ ] M7 (IPC/service split)  [ ] M8 (packaging)  [ ] M9 (Android)  [ ] M10 (Apple)  [ ] M11 (transports)
