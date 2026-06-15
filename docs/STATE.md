# STATE

> Cross-session memory. Read at session start, update at session end. Append to the
> decisions log; never rewrite history. (Template + rules: PLAN.md Appendix A / §2.)

## Current position
- Milestone: **M7 — control-plane IPC + service split. SESSIONS 1+2 (no-root core) DONE
  2026-06-14.** Design decided (`ipc-service-split-design-m7` memory). M2→M6 code-complete.
  **Remaining (needs root): the live privileged gate** — `UnixListener` accept + real
  `SO_PEERCRED` extraction + the real `TunnelEngine` (TUN + core) + `cli/` client subcommand.
- Last gate passed: **M0**..**M6** as before; **M7 s1** (ipc protocol crate) + **M7 s2** (service
  no-root core) green 2026-06-14. s2: `spark-ipc` gained `ServerMessage` (response/push demux
  envelope) + a feature-gated async `stream` layer (`read_frame`/`write_frame`); `spark-service`
  got `auth` (PeerCreds + AuthPolicy root+`spark`-group, pure/testable), `engine::TunnelEngine`
  trait, `run_service` actor loop (channels-over-locks, `Hello`-gated, broadcasts state changes),
  and `serve_connection` (cancel-safe: a dedicated reader task feeds a `select!` that interleaves
  responses and pushes). Hermetic duplex tests cover handshake/connect/status, pre-handshake
  rejection, version-mismatch rejection, and subscribe→push delivery.
- Tree status: **green** — `cargo clippy --workspace --all-targets --all-features -D warnings`
  / `fmt --check` clean; `cargo test --workspace --all-features` all pass (core 36 + 3 integ +
  doctest; **spark-ipc 10** incl. stream; **spark-service 8**); release `spark` **~1.17 MB**
  (unchanged — ipc/service not linked into the binary until the live cli client mode).
  NB: the ipc `stream` tests need the feature → use `--all-features` (or `-p spark-ipc
  --features stream`).

## Next chunk (exactly what the next session should do)
Two independent tracks — pick by whether a privileged box is available:

**(A) M7 session 3 — live privileged wiring (needs root).** The no-root core (s1+s2) is done.
Remaining:
1. `service/`: the `UnixListener` accept loop at `/run/spark/control.sock`, extracting real
   `SO_PEERCRED` (uid/gid, + resolve `spark` supplementary-group membership) → `auth::AuthPolicy`;
   the real `TunnelEngine` impl that brings up the TUN + runs `spark-core` (the existing
   `SmoltcpNetstack` + proxy); privilege drop after device/route setup; supervision; fail-open
   route-restore emitting `TunnelEvent::FellOpenToDirect`.
2. `cli/`: a client subcommand that connects, does the `Hello` handshake, sends a command, and
   prints the response/stream (reuses `spark-ipc` `read_frame`/`write_frame`).
3. *Live gate (root):* unprivileged client drives the service to connect (curl passes); killing
   the client leaves the tunnel up; killing the service restores direct routing + emits the drop
   event; a fail-closed profile blocks instead; an unauthorized uid is refused; an incompatible
   version handshake is rejected.
   Refinement to fold in: drop-oldest + `Push::Dropped` accounting on subscriber backpressure
   (s2 currently drops-newest, best-effort).

**(B) Root-gated live verification (human), do when a privileged window opens:**
- **M6 SIGINT/device-teardown gate** — bring the device up, send SIGINT, confirm the TUN
  interface is removed cleanly (Drop-driven). Also confirm default-level logs show no IPs
  during a real session (the redaction backstop + level convention).
- **M5 live UDP gate** — with the device up, a DNS query (UDP/53) and a UDP echo both
  round-trip through the tunnel; idle associations are reclaimed after 60s
  (`DEFAULT_IDLE_TIMEOUT`). DNS strategy = proxy-through-tunnel (no :53 special-casing).
  Run `spark` (direct) or `spark --server <addr>` (tunneled, needs a server that speaks the
  UDP-associate protocol: magic sentinel `udp-associate.spark.invalid` + target header, then
  `[u16 len][payload]` datagrams).
- **M4 live gate** — stand up a tunnel server, run `spark --server <addr>` with a route into
  the TUN, `curl --interface tun0 https://1.1.1.1`; verify server-side it saw the connection.
  macOS works here (the dial targets the server, so no M2 loop hazard).
- **M2 live curl gate** — `spark` (no `--server`), README "M2 plain-TCP-forwarder gate"
  (Linux: bring up `tun0`, loosen `rp_filter`, `curl -v --interface tun0 https://1.1.1.1`).
  Loop hazard: do NOT route the target into the tun; `--interface` binds only the client.
- **M1 live ping gate** — see Blockers.
- Record routing cmds + poll/latency in the Decisions log and tick M1/M2/M4 as they pass.

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
- **M6:** `target/release/spark` = **1,223,760 bytes (~1.17 MB)**, stripped Mach-O arm64.
  +~114 KB over M5 — `toml` + `serde` pull in a real TOML parser/serializer (the largest
  single dep jump so far). Budget <3 MB — still comfortable, but watch dep weight from here.
- **M5:** `target/release/spark` = **1,107,152 bytes (~1.06 MB)**, stripped Mach-O arm64.
  +~33 KB over M4 — the UDP transports + `run_udp` orchestration + netstack UDP surface are
  now linked. Budget <3 MB — comfortable.
- **M4:** `target/release/spark` = **1,073,584 bytes (~1.05 MB)**, stripped Mach-O arm64.
  +~16 KB over M2 — the transport (Transport trait + TunnelClient + DirectTransport) is now
  linked into the binary (M3's transport was lib-only, dead-code-eliminated until M4 wired
  it in). Budget <3 MB — still comfortable.
- **M2:** `target/release/spark` = **1,057,008 bytes (~1.03 MB)**, stripped Mach-O arm64.
  +~133 KB over M1 — adds the vendored netstack-smoltcp + smoltcp + async-trait. Budget:
  <3 MB stripped — still comfortable headroom.
- **M1:** 923,344 bytes (~902 KB) — links tun-rs + tokio(full) + clap + tracing-subscriber.
  (M0 was ~280 KB — empty CLI.)

## Decisions log (append-only)
- 2026-06-14 (M7 s2): **Service = actor event loop; `ServerMessage` demux envelope; feature-gated
  async `stream` layer; auth policy pure+testable.** Added `ipc::ServerMessage` (Response|Push) so
  the client can demux replies from pushes on one connection (gap found while wiring s2). Async
  framing (`read_frame`/`write_frame`) lives behind ipc's `stream` feature (off by default →
  message-oriented mobile transports stay tokio-free). `service::run_service` is a single task
  owning state (no `Arc<Mutex>`), `Hello`-gated, broadcasting `StateChanged` to subscribers;
  `serve_connection` is cancel-safe — `read_frame` (not cancel-safe) runs in a dedicated reader
  task feeding a `select!` that interleaves responses + pushes (NOT `read_frame` directly in
  select). `auth::AuthPolicy` (root + `spark` gid + optional uids) is a pure function of
  `(uid,gid)`; live `SO_PEERCRED` extraction + supplementary-group resolution deferred to s3.
  Subscriber backpressure is best-effort drop-newest for now; drop-oldest + `Push::Dropped` is a
  noted s3 refinement. All hermetic over `tokio::io::duplex`; ipc/service not yet linked into the
  `spark` binary (the cli client mode in s3 links them).
- 2026-06-14 (M7 design + s1): **Control-plane IPC = postcard + length-delimited framing over
  a unix socket; `SO_PEERCRED` + `spark` group; service actor loop; protocol is mobile-portable.**
  Decided with Adam after researching Mullvad (Rust, gRPC/tonic) and Tailscale (Go, HTTP/JSON
  LocalAPI + operator model). gRPC ruled out by CLAUDE.md's no-hyper rule + the <3 MB budget;
  HTTP needs a stack — so postcard (already in serde) + a `u32`-LE length frame. **Split the
  message codec from the framing** so message-oriented transports (Apple NE `sendProviderMessage`,
  Android in-process) reuse the messages WITHOUT framing; only stream transports frame. Service =
  one event loop (`mpsc<Command>`+`oneshot`, no locks) broadcasting to bounded subscribers.
  Auth = root + `spark` group via `SO_PEERCRED` (Linux/macOS-daemon only; Android has no boundary,
  iOS uses code-signing + App Group). Full design + mobile analysis in the
  `ipc-service-split-design-m7` memory. **Session 1 landed:** `spark-ipc` (types + codec + framing
  + `negotiate`), pure/no-async, 8 tests. `MAX_FRAME_LEN` (1 MiB) caps hostile-peer allocation.
- 2026-06-14 (M6): **TOML config (serde+toml) + IP-redaction backstop + `--config` rule.**
  `core/src/config`: `Config` with per-section defaults (`#[serde(default, deny_unknown_fields)]`
  so partial files work and typos error); `Option` fields use `skip_serializing_if` for clean
  round-trips. Sections: `[tun]`/`[transport]`/`[udp]`/`[log]`. Added `serde` + `toml` (locked
  stack). CLI: `--config <file>` loads the full config and the individual flags are ignored
  when set; otherwise flags build the `Config` (`Cli::to_config`). **Log hygiene = level
  convention + redaction backstop:** addresses only in `debug!` (filtered at default `info`),
  AND a `RedactingWriter` scrubs IPv4 dotted-quads + bracketed IPv6 from output unless `--debug`
  (`core/src/redact.rs`, dep-free; no regex). Redaction deliberately skips hostnames/bare-IPv6
  (false-positive risk on module paths / version strings) — those rely on the level convention.
  Graceful shutdown: `select!` drop + explicit `drop(tun)` → Drop tears the device down. Live
  SIGINT-device gate needs root. Binary +~114 KB (toml/serde parser) → ~1.17 MB.
- 2026-06-11 (M5 s2): **UDP transport surface = split `PacketSink`/`PacketSource` +
  `UdpTransport::dial_udp`; own framing, connect-mode, magic-sentinel dispatch; netstack
  reply via mpsc drain.** Researched prior art (sing-box UoT `common/uot`, sing-quic
  hysteria, Leaf) — see the `udp-transport-design-proposal` memory. Decided with Adam:
  (1) separate traits, not folded into `Transport`; (2) own framing in `tcp_tunnel` (NOT
  UoT-byte-compat — framing is per-transport so a future SS/sing-box transport can speak UoT
  without touching the core); (3) **split halves, not `&self`** (a stream-backed conn can't
  do `&self` writes without locking across `.await`); (4) **connect-mode** — announce the
  target once, then `[u16 len][payload]` datagrams; (5) **UDP-associate dispatch = magic
  sentinel address** (`udp-associate.spark.invalid`, `.invalid` per RFC 2606), leaving the
  M3 TCP header unchanged; (6) **netstack reply = mpsc drain task** owning the smoltcp UDP
  `WriteHalf` (reply pumps clone the `Sender`), avoiding shared-Sink locking. `DirectTransport`
  and `TunnelClient` both impl `UdpTransport`. `SmoltcpNetstack` now `enable_udp(true)` +
  `take_udp()`. Verified orientation: `UdpMsg = (payload, local=client_src, remote=original_dst)`,
  inverted like TCP; reply sent to the stack as `(payload, original_dst, client_src)`.
- 2026-06-11 (M5 s1): **UDP-over-tunnel framing + NAT table; DNS = proxy-through-tunnel;
  idle timeout = 60s.** Datagram framing (`transport/tcp_tunnel/udp.rs`):
  `[Address][LEN(u16,be)][payload]` — reuses the M3a `Address` codec, length-prefixed so it
  survives a stream (TCP/TLS) that erases datagram boundaries; `parse` returns
  `(Address, &payload, consumed)` and distinguishes `Incomplete` (truncated) from malformed,
  like the TCP header. NAT table (`proxy/udp.rs`): generic `NatTable<V>` keyed by
  `(client_src, original_dst)`, `now`-injected for deterministic eviction tests,
  `evict_expired` returns reclaimed values so the orchestration can close per-flow sockets.
  `DEFAULT_IDLE_TIMEOUT = 60s` (DNS is short-lived; covers a slow resolver without stranding
  state). DNS strategy = **proxy-through-tunnel** (no special-casing :53 — it rides the UDP
  path like any datagram), per the standing decision. Netstack UDP socket left disabled
  until session 2 (enabling it without draining `ReadHalf` would back-pressure the stack).
- 2026-06-11 (M4): **`Transport` trait is the direct/tunnel seam; `dial` takes `SocketAddr`.**
  `core/src/transport/mod.rs`: `#[async_trait] trait Transport: Send + Sync { async fn
  dial(&self, target: SocketAddr) -> io::Result<BoxedStream> }`. `DirectTransport` (M2
  behavior) and `TunnelClient` both impl it; the forwarder takes `Arc<dyn Transport>` and is
  identical for both. `dial` takes `SocketAddr` (what the netstack surfaces), not the richer
  `Address`, to decouple the trait from the tunnel header type — the tunnel impl wraps it as
  `Address::Ip` internally. `TunnelClient` keeps an inherent `dial(Address)` (domain-capable,
  used by M3b tests); the trait method delegates to it (the `Address` arg disambiguates the
  overload). **Moved `AsyncReadWrite` + added `BoxedStream` alias to the crate root** (`lib.rs`)
  so netstack flows and transport streams share one boxed type. CLI selects transport with
  `--server <addr>` (tunnel) vs absent (direct). Live gate (curl through a real server) is
  root+server-gated and deferred.
- 2026-06-11 (M3b): **Header sent eagerly in `dial`; `TunnelStream` is a transparent
  pass-through.** `TunnelClient::dial(target)` opens TCP to the server, `write_all`s the
  encoded header, then returns `TunnelStream<TcpStream>` which just delegates
  `AsyncRead`/`AsyncWrite` to the inner connection. (Lazily coalescing the header into the
  first `poll_write` saves a syscall but adds partial-write state — deferred as an
  optimization; the gate is a correctness echo.) Server-side header recovery lives in
  `stream::read_header` (partial-read buffering: loop `Address::parse`, treat `Incomplete`
  as read-more, map permanent errors → `InvalidData`, mid-header EOF → `UnexpectedEof`); it
  returns `(Address, leftover_payload_bytes)` so a relay forwards bytes read past the header.
  Integration test uses an in-test relay (Appendix B opt 1); the relay tries all resolved
  candidate addresses (localhost → ::1 then 127.0.0.1) to stay order-independent. No TLS yet.
- 2026-06-11 (M3a): **Tunnel header = SOCKS5 address grammar (RFC 1928 §4), no SOCKS
  framing.** `ATYP(1) | ADDR | PORT(2, big-endian)`, ATYP 1=IPv4 / 3=domain(len-prefixed) /
  4=IPv6. Chosen because it's compact, self-delimiting, and off-the-shelf relays already
  speak it. `Address` enum = `Ip(SocketAddr)` (covers v4+v6) | `Domain{host,port}` (domain
  validated non-empty + ≤255 at construction via `Address::domain`, so `encode` is
  infallible). `parse` returns `(Address, consumed_len)` and distinguishes
  `HeaderError::Incomplete` (truncated → caller reads more; M3b's buffering retry signal)
  from permanent errors (`UnknownAtyp`/`EmptyDomain`/`InvalidDomain`). Lives in
  `core/src/transport/tcp_tunnel/header.rs`; the `Transport` trait is deferred to M4.
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
  [x] M3a (address codec + header)  [x] M3b (relay stream + client — integration-tested)
  [~] M4 (Transport trait + wiring + CLI flag green; live curl-through-server gate pending root)
  [~] M5 (code complete: framing + NAT table + transports + orchestration + netstack UDP, green; live DNS gate pending root)
  [~] M6 (config + redaction + CLI green+tested; live SIGINT/device-teardown gate pending root)
- [~] M7 (s1 `ipc/` + s2 service no-root core green+tested; s3 live unix-socket/SO_PEERCRED/real-engine/cli-client + gate pending root)
- [ ] M7 (IPC/service split)  [ ] M8 (packaging)  [ ] M9 (Android)  [ ] M10 (Apple)  [ ] M11 (transports)
