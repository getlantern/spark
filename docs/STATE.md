# STATE

> Cross-session memory. Read at session start, update at session end. Append to the
> decisions log; never rewrite history. (Template + rules: PLAN.md Appendix A / §2.)

## Current position
- Milestone: **M0 — Toolchain + netstack compile gate** (not started)
- Last gate passed: none yet (fresh repo)
- Tree status: no repo yet — first session creates the workspace

## Next chunk (exactly what the next session should do)
Execute M0 (PLAN.md §4):
1. Create the Cargo workspace: `core/`, `cli/`, `ipc/`, `service/`, `vendor/`.
   (`ipc/` and `service/` can be empty stubs for now; they're built at M7.)
2. Add `rust-toolchain.toml` pinning stable **≥ 1.85**; confirm `rustc --version` matches.
3. Vendor `netstack-smoltcp` (0.2.x) into `vendor/netstack-smoltcp/`; depend on it by `path`
   from `core/`. Pin `smoltcp` explicitly in the vendored manifest.
4. Write `core/examples/netstack_smoke.rs` per the M0 gate (build the stack with the buffer
   knobs + `.mtu(1500)`, spawn the runner, assert the `TcpListener` item shape and that
   `TcpStream: AsyncRead + AsyncWrite` via a non-executed `copy_bidirectional` branch). The
   provided `netstack-spike/src/main.rs` is a reference (verified on 0.1.x/rustc 1.75) —
   adapt it to vendored 0.2.x and **re-verify `.mtu()` and the exact `build()` tuple**.
5. Pass the gate: `cargo run --example netstack_smoke` prints `NETSTACK OK`;
   `cargo build --release` succeeds (record baseline size); `cargo clippy -- -D warnings`
   and `cargo fmt --check` clean.
Then checkpoint and stop (report toolchain version + baseline size + confirmed 0.2.x API).

## Blockers / waiting on human
- None for M0.
- Upcoming (not blocking yet): docker `sing-box` SS-2022 server needed at **M3** (PLAN
  Appendix B); human crypto sign-off required before trusting **M3a**; full threat-model
  paragraph needed before **M11** (anti-DPI work).

## Verified API facts (re-confirm on the pinned ≥1.85 toolchain during M0, then trust)
- netstack-smoltcp **0.2.2** (confirmed from crate source): `StackBuilder::default()` is
  fluent — `.enable_tcp(bool).enable_udp(bool).enable_icmp(bool).stack_buffer_size(n)
  .tcp_buffer_size(n).udp_buffer_size(n).mtu(n).build()` → `io::Result<(Stack,
  Option<Runner>, Option<UdpSocket>, Option<TcpListener>)>`.
- `enable_icmp(true)` requires `enable_tcp(true)` (builder errors otherwise).
- `Runner`, if present, must be `tokio::spawn`'d.
- `Stack` is `Stream<Item = AnyIpPktFrame>` + `Sink<AnyIpPktFrame>`; `stack.split()` bridges
  to the TUN packet source.
- `TcpListener` is `Stream<Item = (TcpStream, SocketAddr, SocketAddr)>` =
  `(stream, local_addr, remote_addr)`; **`local_addr` is the original destination** (the SS
  target). `TcpStream: AsyncRead + AsyncWrite` → `copy_bidirectional` works directly.
- `.mtu()` exists in 0.2.x but **not** 0.1.x — do not assume builder methods across versions.
- Toolchain floor: `smoltcp 0.12` needs rustc ≥1.80; `tun-rs` 2.8.x pulls an edition-2024
  dep → effective MSRV **≥ 1.85**.

## Decisions log (append-only)
- Language/stack: Rust + tokio + rustls(ring) + ring; netstack = **vendored** netstack-smoltcp
  over smoltcp; TUN = tun-rs (desktop). Rationale in circumvention-tool-prompt.md.
- MSRV ≥ 1.85 (toolchain floor above).
- Process model: privileged tunnel process + unprivileged client; **data plane in-process**,
  control-plane IPC only (`ipc/` crate, serde+postcard, length-prefixed, versioned handshake).
- Kill-switch: **fail open** (restore direct routing on crash, surfaced loudly) with a
  per-profile fail-closed override. (process-architecture-and-ipc.md §5.)
- DNS strategy default: **proxy-through-SS** (revisit at M5 if needed).
- FFI (mobile): **uniffi-rs** preferred (confirm at M10).
- Config format: TOML (SS URI / sing-box JSON deferred).

## Milestone checklist
- [ ] M0  [ ] M1  [ ] M2  [ ] M3a [ ] M3b [ ] M3c [ ] M4 [ ] M5 [ ] M6
- [ ] M7 (IPC/service split)  [ ] M8 (packaging)  [ ] M9 (Android)  [ ] M10 (Apple)  [ ] M11 (transports)
