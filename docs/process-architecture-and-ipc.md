# Design: Multi-Process Architecture, IPC, and Privileges

How the tool splits into processes, what crosses the boundary between them, and how the
privileged side authenticates the unprivileged side. This is a reference doc — read the
section for the platform you're working on plus "§1 The core split."

---

## 1. The core split: control plane vs data plane

The single most important rule:

> **The packet data path never crosses a process boundary. Pass the file descriptor /
> handle once, not the packets.**

On every platform, the process that owns the OS tunnel primitive also runs the Rust core
(netstack + transports). Packets are read from the tunnel, terminated in the netstack,
forwarded through a transport, and written back — all **inside one process**. There is no
per-packet IPC. Shipping packets over a socket to another process would double-copy every
packet and destroy the performance budget; it is an anti-pattern.

What *does* cross the boundary is the **control plane**: a low-rate, structured channel
carrying commands (connect/disconnect/reconfigure), status/metrics, and log/event streams.
"Efficient" here means "doesn't get in the way"; the real requirements are **robustness**
(survives either side restarting) and **security** (the privileged side must authenticate
the caller, because the two processes typically run as different users).

### Why two processes at all?

Owning a TUN/WinTun device and editing the routing table requires elevated privilege
(root / `CAP_NET_ADMIN` / Administrator / a system-managed extension). You do **not** want
the UI — a large, frequently-updated, attack-exposed surface — running with that privilege.
So the privileged tunnel logic is isolated in a small, auditable process, and the UI is an
unprivileged client.

### Privilege separation without packet IPC: fd-passing

If you want the *core* itself to run unprivileged (defense in depth), you still don't ship
packets over IPC. Instead a tiny privileged shim opens the tunnel fd and **passes the fd**
to the unprivileged core (Linux: `SCM_RIGHTS` over a unix socket). After the handover the
core reads/writes the tunnel directly in its own address space. One fd crosses the
boundary, once; the data path stays local. (On Apple/Windows the primitive is owned inside
the privileged process already, so this is a Linux-flavored option.)

### Component layout

```
core/      Rust lib: netstack + transports + proxy. Knows NOTHING about processes or IPC.
ipc/       Rust lib: the control-plane protocol (message enum, framing, versioning).
service/   Privileged process: owns the tunnel + routes, embeds core/, serves ipc/.
cli/       Dev driver / unprivileged client. (Through M6 this runs everything in one
           process for convenience; the shipping desktop architecture is service + client.)
platforms/ Per-OS glue: Android (JNI), Apple (Swift + FFI). These embed core/ in the
           OS-provided privileged context and use the platform's own control channel.
```

`core/` staying process/IPC-agnostic is what lets the same core run inside a Linux daemon,
a Windows service, an Apple extension, and an Android service without change.

---

## 2. The control-plane IPC protocol (shared `ipc/` crate)

One protocol definition, reused across platforms; only the transport underneath differs.

### Messages (illustrative)
```rust
enum Request {
    Hello { client_version: u32 },          // version handshake, first message
    Connect { profile_id: ProfileId },
    Disconnect,
    Reconfigure { profile_id: ProfileId },
    GetStatus,
    Subscribe { events: bool, logs: bool },  // opt into streams
}
enum Response {
    Hello { service_version: u32, negotiated: u32 },
    Status(TunnelStatus),                    // service is the source of truth
    Ack { req_id: u64 },
    Error { req_id: u64, code: ErrorCode, msg: String },
}
enum Push { Event(TunnelEvent), Log(RedactedLogLine) }   // server-initiated streams
```

### Encoding & framing
- Length-prefixed frames (`u32` LE length + body). One message per frame.
- Body via `serde` + a compact binary codec (**`postcard`** preferred — small, stable,
  `no_std`-friendly). Allow a JSON encoding behind a `--debug-ipc` feature for inspection.
- Every message carries a protocol **version**; the `Hello` handshake negotiates the
  minimum common version so the UI and service can update independently.
- Requests carry a `req_id`; responses echo it. Commands are idempotent where possible.

### Robustness requirements (this is where "carefully designed" lives)
- **Service is the source of truth.** The UI is a view; on (re)connect it calls `GetStatus`
  and re-syncs full state rather than assuming continuity.
- **Either side may die.** The tunnel keeps running if the client exits (policy-dependent;
  see kill-switch). The client auto-reconnects with capped backoff if the service restarts.
- **Heartbeat / keepalive** so each side detects a dead peer; bound the detection time.
- **Backpressure on streams.** Log/event streams use a bounded channel with drop-oldest and
  a `dropped: N` marker, so a slow or stalled UI can never OOM the privileged service.
- **Graceful degradation.** If the control channel dies, the *data plane keeps forwarding*;
  only control becomes temporarily unavailable.
- **Timeouts** on every request; no unbounded waits.
- Keep the protocol small and explicit. Do **not** pull in a heavyweight RPC framework for a
  thin local channel.

---

## 3. Security & cross-user authentication

The two processes typically run as **different users** (privileged service vs. logged-in
user), so the channel is a privilege boundary and a local-privilege-escalation (LPE) target.
**Never trust a peer just because it connected.** Each platform has a native mechanism:

- **Linux** — `SO_PEERCRED` on the unix socket yields the peer's uid/gid/pid. Define an
  explicit policy: e.g. only root and members of a dedicated `tool` group may control the
  service. Set restrictive socket permissions in `/run/<tool>/` and verify peer creds in
  code (don't rely on filesystem perms alone). Per-uid config scoping so user A cannot read
  or drive user B's profile.
- **Windows** — Named pipe with an explicit **SDDL/DACL** granting only the intended SID(s)
  (e.g. Administrators or a specific service-managed group). Validate the connecting token;
  guard against impersonation. WireGuard's Windows manager/tunnel service split is the
  canonical reference for getting the pipe security descriptor right — a loose descriptor
  here is a classic LPE bug.
- **macOS (daemon path)** — XPC validates the peer's **code-signing requirement** (modern
  API: set a required code signature on the XPC connection) so only your signed app can
  command the daemon. Install the daemon via `SMAppService` (or legacy `SMJobBless`).
- **Apple (NE path) & iOS** — the OS mediates: app and extension share a team-scoped **App
  Group**, and trust is established by code-signing + entitlements. You don't roll your own
  authz here.

### Secret handling across the boundary
Proxy credentials (SS-2022 PSKs, keys) live in the **privileged side's** storage — a
root-owned `0600` file or the OS keychain/credential store — and are **never echoed back**
to clients over IPC. The UI submits a user-entered secret once (over the authenticated
channel); the service persists it. With multiple local users, scope secrets per-uid so one
user can't exfiltrate another's via the daemon.

---

## 4. Per-platform process model

### Linux
- **Privileged daemon** (systemd unit) owns `/dev/net/tun` and the routing table; runs the
  core. Acquire `CAP_NET_ADMIN` (or run as root), open the device and set routes, then
  **drop privileges** to a low-priv service user where possible (retain only what route
  changes need, or do all route changes up front).
- **Control transport:** unix domain socket (`SOCK_STREAM` + length-prefix framing; tokio
  `UnixListener`/`UnixStream` support this directly) in `/run/<tool>/control.sock`. (Optional
  `SOCK_SEQPACKET` if you want OS-level message boundaries, at the cost of more manual
  integration.) `SO_PEERCRED` for authz. D-Bus is an alternative if integrating with desktop
  environments.
- Optional fd-passing (`SCM_RIGHTS`) to run the core as a separate unprivileged process.

### Windows
- **Windows Service** running as `LocalSystem` (or a dedicated service account) owns the
  WinTun adapter and routes, and runs the core. The WinTun adapter creation/config needs
  admin, which is exactly why this lives in the service.
- **UI** runs as the logged-in user, unprivileged.
- **Control transport:** named pipe with a hardened **SDDL**. tokio exposes named pipes
  (`tokio::net::windows::named_pipe`); set the security descriptor via the Win32 layer.
- Reference architecture: WireGuard for Windows (a manager service + per-tunnel service).

### macOS — two distribution paths
- **NetworkExtension / System Extension (App Store, and the modern default):** the core runs
  **inside** the Packet Tunnel Provider extension, which owns `NEPacketTunnelFlow`. The main
  app is a separate unprivileged process that uses `NETunnelProviderManager` to install the
  config and `NETunnelProviderSession.sendProviderMessage(_:)` as the control channel. Reuse
  the `ipc/` message enum as the `sendProviderMessage` payload for consistency. Shared config
  via an App Group container. Requires the NetworkExtension entitlement, code-signing, and
  notarization. **No manual privilege elevation** — the entitlement grants the capability.
- **Privileged daemon (non-App-Store: Homebrew, enterprise, CLI):** a `launchd` daemon as
  root (installed via `SMAppService`) owns a `utun` device; the client talks to it over
  **XPC** with peer code-signing validation. Same `ipc/` protocol, XPC transport.
- Pick one path per distribution channel; they can share `core/`, `ipc/`, and `service/`
  logic, differing only in transport + activation.

### iOS
- **Only the NE path exists.** Core runs inside the Packet Tunnel Provider extension; packets
  stay in the extension. Control via `NETunnelProviderSession` provider messages; shared
  state via an App Group. **Hard memory cap** on the extension (historically small — verify
  the current limit at implementation time) dictates tuning the netstack buffer sizes down
  (`stack_buffer_size`/`tcp_buffer_size`/`udp_buffer_size` — the runtime knobs we already
  locked in). An unbounded-allocation data path gets the extension OOM-killed under load.

### Android — the exception (no cross-user split)
- `VpnService` is a **component within your own app's process** (same uid), not a separate
  privileged user. The OS grants the VPN capability to the app after a consent dialog. The
  core runs in-process (optionally in an isolated `:vpn` process via `android:process`, still
  the same uid). There is **no cross-user privilege boundary** and no daemon. "Control" is
  in-process (or an in-app bound-service `Binder`), so the §3 cross-user authz concerns do
  **not** apply here. Don't over-apply the daemon model to Android.

---

## 5. Lifecycle & supervision

- Register the privileged process with the OS service manager: systemd unit (Linux), SCM
  service (Windows), `SMAppService`/`launchd` (macOS daemon), system-extension activation
  (macOS NE), or it's app-managed (Android/iOS NE).
- Auto-start + crash-restart via the platform supervisor (`Restart=` / SCM recovery /
  `KeepAlive` / OS-managed for extensions).
- **Route restoration / kill-switch — DECIDED: fail open (loud).** On crash or shutdown the
  service must restore the routing table so the machine isn't left with a black-holed default
  route. The product default is **fail open**: restore direct routing on a crash, because the
  circumvention use case is about access and failing closed mostly looks like a broken app.
  Critically, fail-open must be **loud** — surface the drop prominently (status change +
  notification) so the user knows they are now connecting directly, never silently. Provide a
  **per-profile override** to fail *closed* (block traffic) for high-risk users who prefer
  exposure-prevention over availability; this does not change the global default.
- Service and UI version independently → the `ipc/` version handshake (§2) is mandatory, not
  optional.

---

## 6. Verify at implementation time

These are stable OS concepts, but exact API names / availability / limits drift — confirm
against current vendor docs before coding against them: the macOS XPC peer-code-signing API
and minimum OS version; `SMAppService` vs legacy `SMJobBless`; the current iOS NE extension
memory limit; tokio's named-pipe security-descriptor surface on Windows; whether you need a
small Swift/ObjC or C shim for XPC (likely) reusing the `ipc/` enum as payload.
