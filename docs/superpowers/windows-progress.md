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
- **W2 live spark-service** — in progress (branch `fisk/windows-w2-service` off `5d9b494`).
- **W3 / W4** — not started.

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
- (none yet)

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
- (none)
