# Windows Support — Progress Log

Autonomous run started 2026-07-09 (user asleep). Goal prompt:
`docs/superpowers/windows-goal-prompt.md`. Design: `docs/superpowers/specs/2026-07-09-windows-support-design.md`.

Constraint: macOS host — all work is code-complete + cross-compiled (`x86_64-pc-windows-msvc`) +
unit-tested. Live on-Windows validation (SCM, named pipe, WinTun routes, tunneling) is DEFERRED to
hardware; never reported as verified.

## Status
- **W1 core Windows routing/kill-switch** — ✅ **MERGED** (PR #59, squash `5d9b494`). 4 review rounds
  (caught 2 real bugs: fail-fast mandatory Windows params; unmasked `route delete` would delete the
  physical default route). All CI green incl. windows-latest test. Windows `RouteManager`:
  route.exe split-default covers via tun ifindex, blackhole kill-switch (loopback IF 1), netsh
  adapter DNS (DNS set/cleared before/around route changes so a netsh failure can't leave a bad
  partial state), ifindex from tun-rs `if_index()` via `with_windows_params` (mandatory).
- **W2 live spark-service** — in progress; **split into three PRs** for tractable review (each
  self-contained; small untestable-on-host FFI kept isolated):
  - **W2a core tunnel wiring** — ✅ **MERGED** (PR #60, squash `e157d5db`). `Tun::if_index()`
    accessor (cfg not(android/ios), delegates to tun-rs `DeviceImpl::if_index`); thread
    `RouteManager::with_windows_params(if_index, config.tun.addr)` in `CoreEngine::start` on Windows
    so the merged W1 routing actually installs when the service connects. No new deps. 2 review
    rounds (Copilot caught one real issue: the Windows `if_index()` early-returns didn't tear down
    the started supervisor+TUN like the `install()` failure path — fixed). All CI green incl.
    windows-latest. Plan: docs/superpowers/plans/2026-07-09-windows-w2a-*.
  - **W2b Windows loop-prevention** — ✅ **MERGED** (PR #61, squash `a86e9415`). Windows
    `SocketProtector` via raw `setsockopt(IP_UNICAST_IF/IPV6_UNICAST_IF)` (windows-sys) +
    `getifaddrs` name→index / physical-interface discovery (safe wrapper, avoids raw
    GetAdaptersAddresses); auto-pin centralized in `transport::from_config` (no engine change).
    New deps `windows-sys`(WinSock)+`getifaddrs`, both cfg(windows)-only. IPv4 `IP_UNICAST_IF`
    index goes in NETWORK byte order (isolated into a host-unit-tested pure helper); IPv6 host order.
    2 review rounds (Copilot: use `WSAGetLastError`; log-after-success). All CI green incl.
    windows-latest. **Why not socket2's `bind_device_by_index`:** socket2 0.6.4 doesn't expose it on
    Windows (its cfg gate excludes windows — `socket2-0.6.4/src/sys/unix.rs:1996`), so the raw
    `setsockopt` was required. Plan: docs/superpowers/plans/2026-07-09-windows-w2b-loop-prevention.md.
  - **W2c service transport** — 🔨 **IN PROGRESS** (branch `fisk/windows-w2c-pipe-test`).
    **Discovery:** the transport (`pipe.rs` SDDL named pipe, `winsvc.rs` SCM, `daemon.rs` wiring)
    is **already implemented + wired + cross-compiled** — built in the P4.1 forward-compat seam
    (task #119), not a stub. `daemon::run` → `winsvc::run_as_service_if_launched_by_scm` (SCM) with
    foreground fallback; `daemon::listen` (cfg windows) → `pipe::serve`; `lib.rs` re-exports
    `pipe::serve` as `serve`. Windows auth **is** the pipe DACL (`D:P(A;;GA;;;SY)(A;;GA;;;BA)`) — no
    per-connection check by design (so no auth.rs Windows gap). `serve_connection` is already
    duplex-unit-tested (conn.rs, 6 tests). The only real gap was **zero test coverage of the pipe
    accept loop**, so W2c = a named-pipe round-trip test (mirrors listener.rs's unix test) that
    exercises `pipe::serve` + SDDL FFI + `serve_connection` + ipc in the windows-latest CI job.
    Live SCM/on-Windows tunneling remain deferred to hardware (W4 checklist).
- **W3 tauri-plugin ServiceControl → real spark-ipc client** — ✅ **MERGED** (PR #63, squash
  `e025a345`). 4 review rounds (Copilot: surface service errors, deterministic test, long-lived
  worker vs per-call churn, pipe-open retry, round-trip timeout, op-labeled errors, doc accuracy;
  one pushback left unresolved — see below). Plan: docs/superpowers/plans/2026-07-09-windows-w3-service-ipc-client.md.
  ServiceControl (desktop.rs, cfg not(macos)/not(android) = Win+Linux) now drives spark-service over
  the named pipe (Win) / unix socket (Linux) via a new `service_ipc.rs`: a sync→async bridge on a
  **single long-lived worker thread + current-thread runtime (mpsc queue)** — required because the
  plugin commands are `async fn`, so a naive block_on would nest runtimes; the worker also avoids
  per-poll churn (the GUI polls status ~2s), bounds each round-trip with a 15s timeout, and retries
  the transient Windows pipe-open errors. Plus `TunnelStatus`→`Status` mapping. connect/disconnect/
  status are live; settings stay local-persist (the ipc is **profile-based** — no granular setters;
  live-apply deferred); servers/select_server stay stubbed. **Plugin is its own cargo workspace** (not in the
  repo-root `--workspace`), so new deps `spark-ipc`(stream)+`tokio` live in its Cargo.toml, gated
  not(android) (macOS included so the shared bridge unit-tests on the host — its unix path == Linux's).
  Verified locally on all 3 targets: macOS `clippy`+`test` (round-trip over a real unix socket +
  `map_status`), Windows `cargo xwin clippy` (ServiceControl + named-pipe branch; `cargo xwin` works on
  the tauri plugin). **Plugin CI job deferred to W4** (workflow-edit hook + belongs with packaging).
- **W4 Windows Tauri packaging + service install** — ⛔ **BLOCKED on a user decision** (the pipe-DACL
  security posture — see "Open decisions / blockers" below) + partly impeded by the workflow-edit
  security hook (release.yml/ci.yml can't be edited via the tooling here). The existing MSI already
  installs `spark-service` (LocalSystem, auto-start) via WiX; what remains is DACL-dependent (build
  the Tauri GUI for Windows with the right execution level, bundle `wintun.dll`, plugin CI job,
  on-device checklist). Plan: docs/superpowers/plans/2026-07-09-windows-w4-packaging.md — ready to
  execute once the DACL decision is made (and by someone who can run/validate a Windows release build).

### W1 detail (superseded by the merged status above)
- code-complete (branch `fisk/windows-w1-routing`).
  RouteManager Windows path done: route.exe split-default covers via tun ifindex, route-blackhole
  kill-switch (loopback IF 1), netsh adapter DNS. ifindex threaded from tun-rs `if_index()` via
  `RouteManager::with_windows_params(ifindex, resolver)` (no windows-sys dep). Gate green: fmt,
  host clippy --workspace, 184 workspace tests, Windows xwin cross-clippy (core+service) all clean.
  cfg(windows) unit tests compile + run in W4's windows-latest CI (not the macOS host). route.exe/
  netsh argv + ifindex value pending on-Windows validation (deferred). PR: (opening).
  **Toolchain note:** Windows cross-clippy needs `cargo xwin clippy` (+ brew llvm) — bare
  `cargo clippy --target x86_64-pc-windows-msvc` fails because `ring`'s C build needs the Windows SDK.
- **W2 live spark-service** — not started.
- **W3 tauri-plugin ServiceControl IPC client** — not started.
- **W4 Windows Tauri packaging + service install** — not started.

## PRs
- **#59** W1 core Windows routing/kill-switch — MERGED (squash `5d9b494`).
- **#60** W2a core tunnel wiring (Tun::if_index + service RouteManager params) — MERGED (squash `e157d5db`).
- **#61** W2b loop-prevention (SocketProtector via IP_UNICAST_IF) — MERGED (squash `a86e9415`).
- **#62** W2c named-pipe control-transport round-trip test (windows CI) — MERGED (squash `6450fcba`).
- **#63** W3 plugin ServiceControl over spark-ipc (connect/disconnect/status) — MERGED (squash `e025a345`).
- **W4** packaging — BLOCKED on the pipe-DACL decision (below); plan written, not yet a PR.

## Autonomous run summary (2026-07-09)
W1 was already merged before this run (#59). This run delivered **W2 (a/b/c) + W3** — 4 PRs (#60–#63),
each through a full Copilot + CodeRabbit review loop, squash-merged on green CI. Net: the **functional
core of Windows Spark is code-complete** — full-tunnel routing + netsh DNS + blackhole kill-switch
(W1), the service supplying the mandatory route params (W2a), loop-prevention so the proxy's own dials
bypass the tunnel (W2b), the named-pipe control transport exercised in CI (W2c), and the unprivileged
GUI driving the privileged service over spark-ipc (W3). Everything is cross-compiled
(`x86_64-pc-windows-msvc`) + unit-tested on the host; **on-Windows runtime (SCM, real WinTun tunnel,
route.exe/netsh, the actual GUI↔service pipe round-trip) is NOT validated** — deferred to hardware via
the W4 checklist. **W4 (packaging) is blocked on the pipe-DACL decision below.**

## Design refinements discovered during W1 planning
- **Loop-prevention = SocketProtector, not a proxy-IP route.** The spec floated a "proxy-IP bypass
  route", but macOS/Linux prevent the proxy's own dials from re-entering the tunnel via
  `SocketProtector` (per-socket `IP_BOUND_IF`/`IP_UNICAST_IF`), which is currently a no-op on Windows
  (`net.rs`: `interface_index` is cfg(unix)→Unsupported; `bind_to_index` cfg-list excludes windows).
  Correct + consistent fix = implement Windows socket-pinning in `SocketProtector` — moved to **W2**
  (engine wiring, where it's exercised and the physical iface is known). W1 drops the proxy-IP route.
- **Windows routes differ from macOS/Linux.** `route.exe` takes dest+mask (not CIDR) and a
  gateway/`IF <ifindex>` (not an interface name). So W1's Windows `RouteManager` translates the
  `0.0.0.0/1`+`128.0.0.0/1` covers to dest+mask and routes via the tun's ifindex; the pure argv
  builders are unit-tested cross-platform, the `route.exe`/`netsh` executor + ifindex resolver are
  cfg(windows). Exact `route add … IF <idx>` form + ifindex accessor flagged for on-Windows validation.
- **tun layer already supports Windows** (`tun::open` uses `DeviceBuilder` for all desktop targets;
  tun-rs drives WinTun). No tun changes in W1; `wintun.dll` bundling is W4.

## Open decisions / blockers

### ⛔ BLOCKER (user decision) — the named-pipe DACL vs. the unprivileged GUI
**The contradiction:** the spec's W2 says the pipe SDDL should grant "the interactive user (service is
LocalSystem)", but the actual code (`service/src/pipe.rs`, `ADMIN_ONLY_SDDL`) grants
`D:P(A;;GA;;;SY)(A;;GA;;;BA)` — **SYSTEM + Built-in Administrators only**. W3's GUI is the *unprivileged*
interactive user, whose token is **UAC-filtered** on a normal machine (the admin SID is present but
deny-only), so it **cannot open an admin-only pipe**. As-is, the GUI can't talk to the service → the
Windows app doesn't function end-to-end, even though every piece is built. (Not caught earlier because
none of this runs on the macOS host / PR CI; it surfaced during W4 scoping.)

**This is a security-posture decision only you can make — I did not guess.** Options:

- **Option A — widen the pipe DACL to the interactive user (matches the spec's stated intent).**
  Change `pipe.rs` SDDL to also grant the logged-in user (e.g. add an ACE for `IU`/Interactive, or
  the installing user's SID captured at install, or `AU`/Authenticated Users) with connect rights.
  GUI runs unprivileged (best UX — no UAC). **Tradeoff:** any local interactive user can drive the
  tunnel (connect/disconnect/see status). Reasonable for a single-user desktop; broader on shared
  machines. This is the spec-aligned choice.
- **Option B — keep admin-only; run the GUI elevated (WireGuard-for-Windows model).**
  No `pipe.rs` change. The Tauri app requests elevation (NSIS `requestedExecutionLevel=admin` /
  a UAC manifest), so its token has effective `BA`. **Tradeoff:** a UAC prompt to launch the app (or
  an elevated auto-start), worse UX, but the control surface stays admin-only (more conservative).

**My recommendation:** Option A with the interactive-user (`IU`) ACE — it matches the spec's intent and
gives the intended unprivileged-GUI UX; the "any local user can toggle the VPN" exposure is acceptable
for a consumer single-user app and is what most consumer VPN clients do. But this is your call.

**Why it blocks W4:** the choice changes W4's Tauri build config (Option B needs the elevated NSIS
manifest) and may add a one-line `pipe.rs` SDDL change (Option A). W4 shouldn't be built until it's decided.

### Impediment (not a decision) — workflow-edit security hook
W4 needs edits to `.github/workflows/release.yml` (Windows Tauri build) and `ci.yml` (plugin CI job),
but the Edit tooling here is blocked by a workflow-injection security hook (it fired on the W3 plugin
CI attempt). My W4 change contains no untrusted `github.event.*` input, so it's safe — a human (or a
session without that hook) should apply the workflow edits, or confirm the hook can be bypassed for
these specific, injection-free changes.
