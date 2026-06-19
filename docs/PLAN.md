# PLAN.md — Multi-Session Execution Plan

This is the operating manual for building the tool across many sessions. It assumes a
single implementing agent works one bounded chunk at a time, hands off via `STATE.md`, and
keeps the tree green at every boundary.

---

## 1. How to use this plan

Every session, in order:
1. Read **GOAL.md** (north star).
2. Read **§2 Session Operating Protocol** below.
3. Read **STATE.md** to find the current position (current milestone, last checkpoint,
   open blockers).
4. Read **only the current milestone** in §4 in detail. Skim adjacent ones at most.
5. Do the work for one bounded chunk (§2).
6. Run the gate, checkpoint, and stop (§2).

Do **not** read this whole document end-to-end every session — that wastes budget. The
session protocol + current milestone is all you need after the first session.

---

## 2. Session Operating Protocol (pacing)

The constraint: a session has a finite context/token budget. Burning it on re-reading,
over-exploration, or starting work you can't finish leads to broken handoffs. These rules
keep each session bounded and resumable.

### Start-of-session ritual (cheap, do every time)
- Read GOAL.md, this §2, and STATE.md.
- Confirm a green starting point: run the **previous** milestone's gate command (or at
  minimum `cargo check`). If it's red, your first job is to make it green again — note
  that in STATE.md and treat it as this session's chunk if needed.
- Restate, in one or two sentences in your first message, the single chunk you intend to
  complete this session. If it doesn't fit comfortably in a session, split it (§ below).

### Choosing the chunk
- One milestone per session is the default. If a milestone is marked multi-session, do
  exactly one of its listed sub-steps.
- A "chunk" must end at a **compiling boundary** with a meaningful, testable increment.
- If partway in you realize the chunk is too big, pick the largest sub-part that compiles
  on its own, finish that, and record the remainder as the next chunk in STATE.md.

### Token hygiene during the session
- **Don't re-read whole files you've seen.** Use targeted line ranges and `grep`/ripgrep
  to locate code. Read the minimum needed.
- **Prefer `cargo check` over `cargo build`** while iterating; it's faster and cheaper.
  Run full `cargo build --release` + `cargo clippy -- -D warnings` only at the gate.
- **Don't paste large files or large command outputs back into your reasoning.** Summarize
  what matters. If a build log is huge, grep it for `error` first.
- **Don't re-derive the design.** Cite the relevant section of the design doc and proceed.
- **Cap orientation.** If you've spent many tool calls orienting without writing code,
  write down your current understanding in STATE.md and start implementing.
- Verify external APIs against vendored source/docs.rs *before* writing against them, but
  read just the signature you need, not the whole module.

### Stop conditions (any one → wrap up now)
- The chunk's gate passes. (Success — checkpoint and stop.)
- Two consecutive fix attempts made no progress. (Stop, report state + exact error.)
- You sense the context budget getting tight. (Stop starting new work; finish the current
  compiling unit only.)
- You hit an ambiguity or a decision that isn't covered by the docs. (Stop and ask; don't
  guess at architecture or crypto.)

### End-of-session ritual (always leave it clean)
1. Ensure the tree compiles (`cargo check` minimum; the milestone gate if you reached it).
2. Commit with a clear message referencing the milestone (e.g. `M2: plain TCP forwarder
   through netstack — curl gate green`).
3. Update **STATE.md** (template in Appendix A): mark what's done, set the precise next
   chunk, list any blockers, and record any API facts you verified this session so the
   next session doesn't re-verify them.
4. End the session with a 3–5 line summary: what you did, gate status, exact next step.
   Do not start new work after this.

### Never
- Never end a session mid-edit with a non-compiling tree. If you must stop, revert the
  half-edit to the last compiling state and record what you were attempting.
- Never delete or rewrite STATE.md history; append/update it.

---

## 3. Human-owned prerequisites (not the agent's job)

These must exist before the milestones that depend on them. The agent should check STATE.md
for them and **stop and request** them if a milestone needs one that's missing.

- **IPC authorization policy.** Who is authorized to control the privileged service over the
  local control channel (the privileged service is a local-privilege-escalation target — see
  the process-architecture doc §3), and the **kill-switch policy (DECIDED: fail open, loud,
  with a per-profile fail-closed override)** — see the process-architecture doc §5. These
  drive M7.
- **TLS review (if used).** If a transport wraps its relay in TLS, use `rustls` (already in
  the locked stack) rather than hand-rolling crypto; a human confirms the `rustls` client
  config (verification, roots) before it's trusted. The plain TCP tunnel needs no bespoke
  crypto.
- **Test server.** A simple TCP relay/echo server reachable from the dev box, for M3+
  integration tests. Minimal setup in Appendix B. Needed at M3.

---

## 4. The Milestone Ladder

Each milestone lists: **Goal · In/Out of scope · Deliverables · Gate (exact, binary) ·
Sessions · Checkpoint**. The gate is the definition of done for that milestone. "Stop and
report" at every checkpoint.

> Build-order principle (from the design doc, do not violate): validate the **netstack
> pipeline with no tunnel first** (M2), then build the **tunnel transport in isolation** (M3),
> then **wire them together** (M4). Transport bugs and netstack bugs are externally
> indistinguishable; keeping them apart until each is independently proven saves days.

### M0 — Toolchain + netstack compile gate
- **Goal:** Prove the foundation compiles on the real toolchain before any feature code.
- **In:** `rust-toolchain.toml` (stable ≥1.85), Cargo workspace skeleton (`core/`, `cli/`,
  `vendor/`), vendored `netstack-smoltcp`, a `netstack_smoke` example.
- **Out:** Any TUN, protocol, or crypto code.
- **Deliverables:** workspace; vendored netstack as a `path` dep; `examples/netstack_smoke.rs`.
- **Gate:** `rustc --version` ≥1.85; `cargo run --example netstack_smoke` prints
  `NETSTACK OK`; `cargo build --release` succeeds and baseline size recorded;
  `cargo clippy -- -D warnings` and `cargo fmt --check` clean.
- **Sessions:** 1.
- **Checkpoint:** Report toolchain version, baseline binary size, and confirm the 0.2.x
  builder API (`.mtu()`, `build()` tuple) matches the vendored source.

### M1 — TUN scaffold
- **Goal:** Async read/write of IP packets through a real TUN device.
- **In:** `core/` TUN abstraction over `tun-rs`; minimal zero-copy IP packet parser
  (v4/v6, proto, src/dst); `cli/` driver that logs `{src,dst,proto,len}` and replies to
  ICMP echo.
- **Out:** netstack integration, any proxying.
- **Deliverables:** `core/src/tun/`, `core/src/packet/`, `cli/src/main.rs`, README test steps.
- **Gate:** On Linux, bring up the device and `ping <tun-addr>` returns ICMP echo replies
  produced by the tool. Logs show parsed packets.
- **Sessions:** 1.
- **Checkpoint:** Note macOS `utun`/Windows WinTun naming/driver caveats discovered.

### M2 — Plain TCP forwarder through the netstack (DIRECT DIAL — no tunnel)
- **Goal:** Validate the full TUN→netstack→upstream→back pipeline with no tunnel transport.
- **In:** Bridge TUN ↔ `netstack-smoltcp` Stack (Stream/Sink of packets); spawn the runner;
  accept TCP flows from the `TcpListener` stream; for each, dial
  `tokio::net::TcpStream::connect(original_dst)` and `copy_bidirectional`. Wrap behind the
  `Netstack`/`TcpFlow` trait. Routing setup documented in README.
- **Out:** the tunnel transport, UDP, config niceties.
- **Deliverables:** `core/src/netstack/` (the trait + the netstack-smoltcp impl),
  `core/src/proxy/tcp.rs` (plain forwarder), routing docs.
- **Gate:** With the device up and a route installed, `curl --interface <tun>
  https://1.1.1.1` (or an equivalent TCP echo through the tunnel) succeeds end-to-end.
- **Sessions:** 1–2 (session 1: bridge + accept loop compiling; session 2: routing + green
  curl gate).
- **Checkpoint:** Record the exact routing commands and the poll-tick/latency behavior.

### M3 — TCP tunnel transport in isolation (NO TUN)
- **Goal:** A correct, tested TCP tunnel client as a standalone `AsyncRead+AsyncWrite` stream.
- **Build against the simple TCP relay/echo server (Appendix B).**
- **Sub-steps (one per session):**
  - **M3a — Address codec + header.** SOCKS5-style address codec (ATYP v4/domain/v6);
    the request header that names the target `(host, port)`. *Gate:* round-trip
    encode/decode unit tests cover IPv4, domain, and IPv6.
  - **M3b — Relay stream + integration.** The `TunnelStream` that sends the header then
    relays bytes transparently in both directions, with partial-read buffering. Optionally
    wrap the connection in TLS via `rustls`. *Gate:* integration test connects through the
    relay server (Appendix B) and echoes a payload correctly both directions.
- **Out:** TUN wiring (that's M4), UDP (M5).
- **Deliverables:** `core/src/transport/tcp_tunnel/` (`header`, `stream`, `client`),
  tests in `tests/`.
- **Sessions:** 2 (one per sub-step).
- **Checkpoint:** After each sub-step. If TLS-wrapping the relay, confirm the `rustls`
  client config (verification + roots) before trusting it.

### M4 — Integrate the tunnel transport + netstack
- **Goal:** Route real tunneled traffic through the tunnel server.
- **In:** Define the `Transport` trait; make the TCP tunnel client implement it; swap M2's
  plain upstream dial for `transport.dial(original_dst)`.
- **Out:** UDP, additional protocols.
- **Deliverables:** `core/src/transport/mod.rs` (trait), wiring in `proxy/tcp.rs`.
- **Gate:** The same `curl --interface <tun> https://1.1.1.1` now flows through the tunnel
  server (verify on the server side it saw the connection).
- **Sessions:** 1.
- **Checkpoint:** Confirm log hygiene: default logs contain no destination addresses.

### M5 — UDP path
- **Goal:** UDP through the tunnel, including DNS.
- **In:** netstack UDP socket; per-packet UDP framing in the transport (length + target
  address); NAT association table keyed by `(client_src, original_dst)` with idle timeout;
  DNS strategy decision implemented (proxy-through-tunnel by default unless STATE.md says
  otherwise).
- **Out:** Additional protocols.
- **Deliverables:** `core/src/proxy/udp.rs`, UDP framing in the transport.
- **Gate:** A DNS query (UDP/53) and a UDP echo both resolve/round-trip through the tunnel;
  idle associations are reclaimed.
- **Sessions:** 2 (session 1: framing + association table compiling; session 2: green DNS gate).
- **Checkpoint:** Record the chosen DNS strategy and idle-timeout value.

### M6 — Config, CLI, log-hygiene hardening
- **Goal:** Production-shaped configuration and privacy properties.
- **In:** TOML config schema (`serde`); `clap` surface; `tracing` redaction layer
  (addresses redacted unless `--debug`); graceful shutdown; structured errors at module
  boundaries.
- **Out:** alternate config import formats (defer).
- **Deliverables:** `core/src/config/`, redaction in the logging init, shutdown handling.
- **Gate:** A test asserts default-level logs contain no IPs/hostnames; config round-trips;
  `SIGINT` tears down the device cleanly.
- **Sessions:** 1–2.
- **Checkpoint:** Document the config schema in the README.

### M7 — Control-plane IPC + privileged service split (desktop)
- **Goal:** Ship-shaped desktop architecture: a privileged tunnel process owns the
  TUN/WinTun + routes + the core; an unprivileged client drives it over a robust, secure,
  platform-native **control** channel. The data plane stays in-process in the service.
  (See process-architecture-and-ipc.md.)
- **In:** the `ipc/` crate (versioned message protocol, length-prefixed `postcard` framing,
  `Hello` version handshake, req_ids, timeouts, bounded log/event streams with drop-oldest);
  the `service/` target wrapping `core/` (owns the tunnel, supervises, serves IPC);
  per-platform transport + authz (Linux unix socket + `SO_PEERCRED`; Windows named pipe +
  SDDL; macOS launchd daemon + XPC peer code-signing — pick the platform you're on);
  privilege acquisition then drop where possible; per-uid config/secret scoping;
  route-restore on crash (**fail open**: restore direct routing and surface the drop loudly;
  per-profile fail-closed override available).
- **Out:** mobile (the OS provides the privileged context + control channel in M9/M10); GUI
  (the client may be a CLI).
- **Deliverables:** `ipc/`, `service/`, one platform transport with authz, supervisor
  integration (systemd/SCM/launchd), route-restore + the fail-open notification path.
- **Gate:** an unprivileged client commands the privileged service to connect and the curl
  gate passes; killing the **client** leaves the tunnel up; killing the **service** restores
  direct routing (no black-holed default route) **and emits a visible drop event** the client
  can surface; a profile set to fail-closed instead blocks traffic on the same crash; an
  **unauthorized** user is refused on the control channel; the version handshake rejects an
  incompatible client.
- **Sessions:** 3–4 (1: `ipc/` protocol crate + handshake/framing; 2: `service/` + one
  platform transport + authz; 3: lifecycle/supervision + fail-open route-restore + drop
  notification; 4: per-uid secret/config scoping + a second platform transport).
- **Checkpoint:** per platform transport; record the exact authz policy (peercred rule /
  SDDL / code-signing requirement). Kill-switch is decided (fail open, loud, per-profile
  override) — implement it, don't re-litigate.

### M8 — Desktop packaging + size budget
- **Goal:** Shippable desktop binaries within budget.
- **In:** Release profile finalization (`opt-level="z"`, `lto="fat"`, `codegen-units=1`,
  `strip`, `panic="abort"`); size measurement for **both** the `service` and client binaries;
  cross-build verification for the three desktop targets; service installer/registration.
- **Gate:** Release binaries within the size budget; service + client run on Linux, macOS,
  Windows.
- **Sessions:** 1–2.
- **Checkpoint:** Record final sizes per target/binary vs. budget.

### M9 — Android shim
- **Goal:** Tunnel on Android via `VpnService`.
- **In:** Kotlin module: consent flow + `VpnService.Builder.establish()` →
  `ParcelFileDescriptor` → `detachFd()`; JNI bridge passing the fd to the core; core
  consumes it via the same packet Stream/Sink bridge. Note: `VpnService` runs **in-process
  (same uid)** — there is no privileged-daemon split here, so the M7 cross-user authz model
  does **not** apply; control is in-process (or an in-app `Binder`).
- **Deliverables:** `platforms/android/`, JNI glue in `core` behind `cfg(target_os)`.
- **Gate:** Builds for `aarch64-linux-android`; a basic browse test works on device/emulator.
- **Sessions:** 2–3.
- **Checkpoint:** Note NDK toolchain pins.

### M10 — Apple shim (iOS + macOS NetworkExtension)
- **Goal:** Tunnel inside a Packet Tunnel Provider extension.
- **In:** Swift Packet Tunnel Provider owning `NEPacketTunnelFlow`
  (`readPacketObjects`/`writePackets`); FFI (uniffi-rs preferred) to the core; netstack
  buffer sizes tuned down for the extension memory cap. The core runs **inside the
  extension** (packets never leave it); the app↔extension **control** channel is
  `NETunnelProviderSession.sendProviderMessage` carrying the `ipc/` message enum as payload,
  with shared config via an App Group. (macOS may instead ship the M7 launchd-daemon path
  for non-App-Store distribution.)
- **Deliverables:** `platforms/apple/` (Swift package + uniffi bindings), FFI surface in core.
- **Gate:** Builds for `aarch64-apple-ios`; tunnel works in the extension without exceeding
  the memory cap under a sustained transfer.
- **Sessions:** 2–3.
- **Checkpoint:** Record the FFI strategy (uniffi vs cbindgen) and measured peak memory.

### M11 — Additional transports (open-ended)
- **Goal:** Prove the transport trait by adding at least one more protocol behind it.
- **In:** Each new transport implements `Transport` (e.g. a TLS-wrapped tunnel, or another
  relay protocol), selectable via config.
- **Gate:** New transport passes the same curl/DNS gates as the TCP tunnel, selectable via config.
- **Sessions:** Open-ended; one transport per arc.
- **Checkpoint:** Per transport.
- **Delivered:**
  - **AnyTLS (2026-06-16). ✅** TCP + UDP (UoT v2) behind the `anytls` cargo feature, selected via
    `[transport.anytls]`. Defeats TLS-in-TLS fingerprinting via a Chrome-mimicking BoringSSL
    ClientHello (JA4 matches real Chrome exactly) plus a server-pushable record-padding scheme;
    pooled, reconnecting sessions. e2e verified against a real anytls-go server on DigitalOcean
    (full `spark run tun` gate → HTTP 301; DNS over the UoT path → valid response). See ADR
    `docs/adr/0001-chrome-mimicry-tls-backend.md` and the STATE.md M11 entries for detail.

### UI Migration Track (Flutter → Tauri v2): U0–U4

> Per **ADR 0008**. Replaces the `gui/` Flutter app + its two core bindings (`flutter_rust_bridge`
> desktop + platform-channels mobile) with one **Tauri v2** app: web frontend → Rust backend via
> `invoke()` + events. Everything below the shell (core, netstack, transports, `ipc/`,
> `spark-ffi`/UniFFI, the privileged service, the `platforms/{android,apple}` tunnel shims) is reused
> unchanged; the process/privilege model (ADR 0005) is unchanged (Tauri app = unprivileged client).
> Android-weighted but **macOS-first** for the lowest-risk proof. Do **not** delete `gui/` until
> per-platform parity (U4). Keep Tauri confined to the UI-shell crate — `core/` stays Tauri-free.

#### U0 — Tauri shell + Lantern web UI (mock backend)
- **Goal:** A Tauri v2 app that builds and renders the Lantern connect screen against a mock backend.
- **In:** new `gui-tauri/` (Tauri v2 + Svelte+Vite — confirm stack here); port the screen + settings
  from `docs/mockups/spark-tauri-lantern-look.html`; a `SparkBackend` TS interface with a mock impl.
- **Out:** real core wiring; any mobile target.
- **Deliverables:** `gui-tauri/`, the web UI, the mock backend.
- **Gate:** `cargo tauri build` runs on macOS; the screen matches the mockup; **`cargo tree -i
  openssl-sys` is empty** (CLAUDE.md hard rule); shell bundle size reported.
- **Sessions:** 1–2.
- **Checkpoint:** confirm the front-end stack (Svelte vs vanilla TS) and the no-`openssl-sys` result.

#### U1 — macOS to parity (real core)
- **Goal:** One-click Connect on macOS equal to today's Flutter product, over the real core.
- **In:** Tauri commands/events implementing `SparkBackend` against `spark` core / `spark-ipc` (reuse
  the NE/service path from ADR 0005 + STATE M10); runtime `config.toml` read matching the current
  `NEBackend` precedence (file → baked `SPARK_CONFIG` → `SPARK_PROXY` → direct).
- **Out:** other platforms.
- **Deliverables:** the Rust command layer in `gui-tauri/src-tauri`, the status event stream, a macOS bundle.
- **Gate:** connect e2e on macOS (IP changes to the relay, as in the current macOS gate) **and the
  macOS app-bundle size measured vs the Flutter DMG**.
- **Sessions:** 2–3.
- **Checkpoint:** record the size delta and the command/event surface.

#### U2 — Android (priority platform)
- **Goal:** Connect e2e on Android via Tauri mobile.
- **In:** the Tauri v2 Android project; a **Tauri plugin** wrapping the existing `platforms/android`
  `VpnService` + UniFFI (M9); the same web UI.
- **Out:** iOS, Windows, Linux.
- **Deliverables:** the Android Tauri project + the VpnService plugin bridge.
- **Gate:** builds for `aarch64-linux-android`; browse/connect test passes on device/emulator; **APK
  size measured vs the Flutter APK**.
- **Sessions:** 2–4 (the plugin bridge is the main unknown).
- **Checkpoint:** note the plugin architecture, NDK pins, and the size.

#### U3 — Windows → iOS → Linux to parity
- **Goal:** each remaining platform to connect-parity, one at a time.
- **In:** Windows (WinTun/service path, WebView2); iOS (Tauri iOS + the NE plugin — **verify the NE
  extension packages inside the Tauri iOS project**); Linux (WebKitGTK + service path).
- **Gate (per platform):** connect e2e + size measured. iOS additionally: the NE entitlement/extension
  loads under the Tauri iOS project.
- **Sessions:** 2–3 each.
- **Checkpoint:** per platform; flag any WebView rendering fixes.

#### U4 — Retire Flutter; switch packaging + docs
- **Goal:** Tauri is the only client; Flutter removed.
- **In:** retire `gui/`; retarget `packaging/` to the Tauri bundler on all platforms; update
  README/STATE; produce the final five-platform size table.
- **Gate:** all five platforms ship from the Tauri app; `gui/` is out of the build; STATE + PLAN
  reflect it; final Flutter→Tauri size table recorded.
- **Sessions:** 1–2.
- **Checkpoint:** the final per-platform size comparison.

---

## 5. Definition of done (whole project)

All of: M0–M7 green (desktop end-to-end TCP+UDP through the tunnel, within size budget,
log-hygiene test passing); M8 and M9 green (mobile shims tunnel on real targets); M10
demonstrates at least one additional transport behind the trait. No stubs, no unapproved
TODOs, no destinations in default logs.

---

## Appendix A — STATE.md template

The agent creates `STATE.md` at the end of M0 and maintains it every session thereafter.

```markdown
# STATE

## Current position
- Milestone: M2 (plain TCP forwarder through netstack)
- Last gate passed: M1 (ping → ICMP reply) on <date>
- Tree status: green (`cargo check` clean as of <date>)

## Next chunk (exactly what the next session should do)
- Install the route and get `curl --interface tun0 https://1.1.1.1` green.
  Bridge + accept loop already compile; only routing + the end-to-end test remain.

## Blockers / waiting on human
- None.  (e.g. "Need the relay test server before M3" / "Need rustls config sign-off if TLS-wrapping")

## Verified API facts (don't re-verify)
- netstack-smoltcp 0.2.x: TcpListener Stream item is (TcpStream, SocketAddr, SocketAddr)
  = (stream, local_addr=src, remote_addr=original_dst) — naming is INVERTED vs the usual
  server-socket sense; DIAL the 3rd element. TcpStream: AsyncRead+AsyncWrite.
- StackBuilder has .mtu(n) in 0.2.x. build() -> io::Result<(Stack, Option<Runner>,
  Option<UdpSocket>, Option<TcpListener>)>.

## Decisions log (append-only)
- <date> DNS strategy: proxy-through-tunnel.
- <date> FFI: uniffi-rs.

## Milestone checklist
- [x] M0  [x] M1  [ ] M2  [ ] M3a [ ] M3b [ ] M4 [ ] M5 [ ] M6
- [ ] M7 (IPC/service split)  [ ] M8 (packaging)  [ ] M9 (Android)  [ ] M10 (Apple)  [ ] M11 (transports)
```

---

## Appendix B — Minimal TCP relay test server

For M3+ integration tests you just need something that accepts the tunnel client's address
header and relays bytes to the named target. Two easy options:

1. **A tiny in-test relay** (preferred — no external process): a `tokio` listener spawned in
   the test harness that reads the SOCKS5-style header, dials the target, and
   `copy_bidirectional`s. Lives in `tests/` so the integration test is self-contained.

2. **`socat` for a plain echo target**, if you want to exercise just the relay-stream
   buffering without a full server:

   ```bash
   # echo server on :9000 — the tunnel client relays to this as its "target"
   socat -v TCP-LISTEN:9000,reuseaddr,fork EXEC:'cat'
   ```

Integration tests target `127.0.0.1` with the relay's port. If a transport TLS-wraps the
relay, stand up the server side with a `rustls` self-signed cert and pin it in the test
client config.
