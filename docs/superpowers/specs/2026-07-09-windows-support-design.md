# Spark on Windows — Design

**Status:** Approved (2026-07-09)

**Goal:** Make the Windows build a functional Spark VPN. An MSI-installed **LocalSystem
`spark-service`** owns the WinTun adapter + route table and runs `spark-core`; the unprivileged
**Tauri GUI** drives it over an SDDL-hardened **named pipe** using the existing `ipc` crate — through
**the same `tauri-plugin-spark-vpn` that macOS and Android already use** (its desktop `ServiceControl`
becomes the real IPC client; no parallel mechanism). Delivered **code-complete + cross-compiled
(`x86_64-pc-windows-msvc`) + unit-tested**; live on-Windows validation is deferred (needs hardware)
and captured as a manual checklist.

## Confirmed decisions
1. **Same plugin, same UI.** Windows uses `gui-tauri` + `tauri-plugin-spark-vpn` unchanged in shape —
   the plugin's `ServiceControl` (currently the "not yet implemented (spark-ipc)" stub) is implemented
   as the real named-pipe client. The Svelte/`SparkBackend` seam is untouched, so the GUI "just works".
2. **MSI installs the service** (LocalSystem, at install time). GUI connects to the pipe; **no
   per-connect UAC**.
3. **Routing shells out** (`route.exe`/`netsh`), matching the existing macOS/Linux `RouteManager`.
   Kill-switch = route-blackhole covers (WFP is future hardening).
4. **macOS host constraint:** everything is delivered code-complete + cross-compiles + unit-tested;
   SCM/pipe/WinTun/tunneling are **not** validated on real Windows here — that's a deferred manual step.

## Architecture (reuses the existing control/data split)
- **`ipc/`** — existing pure protocol (postcard messages + length framing). Unchanged; reused as the
  named-pipe payload.
- **`service/` (`spark-service`)** — already has `daemon.rs`/`winsvc.rs` (SCM)/`pipe.rs` (named pipe)/
  `conn.rs` (transport-generic serve loop)/`auth.rs`/`engine.rs` (`TunnelEngine` trait + fake),
  "type-checked against Windows but never run." This effort makes the Windows path **live**.
- **`core/`** — implement the Windows `RouteManager` (today a no-op) + confirm the WinTun tun/netstack
  data path.
- **GUI** (Tauri, logged-in user) — plugin `ServiceControl` → real pipe IPC client.

Process model (per `docs/process-architecture-and-ipc.md` §Windows): Windows Service as LocalSystem
owns WinTun + routes + core; UI unprivileged; control = named pipe with hardened SDDL;
reference = WireGuard for Windows.

## Milestones (one spec, paced W1→W4; each is its own PR)

### W1 — Core Windows routing/kill-switch (`core/src/routing.rs`, `#[cfg(target_os="windows")]`)
- Split-default covers via the tun **interface index** (Windows `route.exe` addresses interfaces by
  index, not name): `route add 0.0.0.0 mask 128.0.0.0 0.0.0.0 metric 1 IF <ifindex>` + `128.0.0.0
  mask 128.0.0.0 …` (override the physical default without deleting it; `0.0.0.0` gateway + `IF` =
  on-link). The ifindex comes from the open `tun-rs` device (`if_index()`), threaded via
  `RouteManager::with_windows_params(ifindex, resolver)` (mandatory — install/restore fail fast if
  absent).
- **Loop-prevention is NOT here.** macOS/Linux prevent the proxy's own dials from re-entering the
  tunnel via `SocketProtector` (per-socket `IP_BOUND_IF`/`IP_UNICAST_IF`), a no-op on Windows today.
  Implementing Windows socket-pinning is **W2** (engine wiring). W1 uses no proxy-IP route.
- Kill-switch/fail-closed: keep blackhole covers (route via loopback `IF 1`) when the data path
  drops (same cover/restore semantics as macOS/Linux).
- Adapter DNS → spark's fake-IP resolver: `netsh interface ipv4 set dnsservers <ifindex> static
  <resolver> primary` on install; reverted to `dhcp` (required op) on teardown.
- Teardown restores on disconnect. Mirror the macOS/Linux `RouteManager` structure; pure argv
  builders unit-tested (`half_to_dest_mask` + cross-platform structural tests on the host;
  `cfg(windows)` argv tests in the `windows-latest` CI job). `tun-rs` already drives WinTun via
  `DeviceBuilder` (no tun change).

### W2 — Live Windows `spark-service` (`service/`)
- Real `TunnelEngine` Windows path: WinTun up → install W1 routes → run `spark-core`
  (fd_tunnel/netstack/proxy).
- `pipe.rs`: named-pipe accept loop with an **SDDL** granting the interactive user (service is
  LocalSystem); framed `ipc` via `conn::serve_connection`.
- `winsvc.rs`/`daemon.rs`: SCM start/stop/status; foreground fallback for dev.
- `auth.rs`: Windows peer authz (pipe SDDL + client-token/session check).
- Unit-tested over the existing in-memory duplex; live SCM/pipe deferred.

### W3 — Tauri plugin `ServiceControl` IPC client (`gui-tauri/tauri-plugin-spark-vpn/src/desktop.rs`)
- Replace the stub with a named-pipe client: connect → send `ipc` Requests (connect / disconnect /
  status / routing-mode / ad-block / split-tunnel / servers) → map to `TunnelControl`; subscribe to
  Push (status/logs). This is the **same plugin** macOS/Android use. Unit-test the codec/mapping.

### W4 — Windows GUI packaging + service install (`release.yml`, `packaging/windows/`)
- `tauri build` for Windows (NSIS + MSI) added to `release.yml` (today: CLI zip/MSI + macOS DMG only).
- Installer bundles `wintun.dll` and registers + starts `spark-service` (LocalSystem) via the WiX
  service element / MSI custom action, applying the pipe SDDL.
- Add a `windows-latest` CI job running the workspace unit tests (beyond today's compile-only check).
- Write `docs/windows-on-device-validation.md` — a manual E2E checklist (install → connect → verify
  routing/kill-switch/DNS → disconnect restores), mirroring the Android on-device checklist.

## Data flow (connect)
GUI → pipe → service event loop → `engine.start(config)` → WinTun up + `RouteManager` covers + core
runs → status Push to GUI. Disconnect reverses (remove covers, tear down WinTun). Unexpected
data-path exit → engine fires `exit` → loop **fails closed** (covers stay) + alerts.

## Error handling
Route ops run sequentially and **stop at the first required-op failure** (the pre-clear deletes are
ignorable). There is **no automatic rollback** in v1: a mid-sequence failure surfaces the error, and
the split-default covers self-heal because `install`/`block`/`restore` each re-clear the covers first
(so a partial state is cleaned up on the next call, and `block` can still fail-closed). `restore`
reverts DNS before removing covers so a `netsh` failure can't leave direct routing + a stale tunnel
resolver. (Transactional rollback of a partially-applied cover set is possible future hardening.)
GUI pipe-connect failure → "service not installed/running"; SCM failures logged; unexpected data-path
exit → kill-switch.

## Testing
Unit: route-command emission, engine fake, `conn` serve loop, `ipc` codec, `ServiceControl` client
mapping. `cargo clippy --all-targets --target x86_64-pc-windows-msvc -D warnings` (and host clippy)
green; whole-workspace `cargo test`. A `windows-latest` CI unit-test job. **Deferred:** the manual
on-Windows checklist.

## Scope / non-goals (v1)
- Kill-switch = route-blackhole (WFP is future hardening).
- No per-connect UAC (MSI installs the service).
- Domain/IP split-tunnel works (core-level, cross-platform); **app-based (per-process) split-tunnel is
  out of scope on Windows** (needs WFP/AppId) — the plugin already reports it unsupported on desktop.
- Live on-Windows validation deferred to hardware.
