# ADR 0004 — Control plane → a stable cross-platform backend contract

- **Status:** Proposed — 2026-06-18. Direction for review; to be built in additive **slices** (below),
  each its own shippable change. Supersedes nothing; extends the M7 control plane (ADR-adjacent:
  `docs/process-architecture-and-ipc.md`).
- **Scope:** What the control plane (`spark-ipc` + the `spark-ffi` binding) exposes, so any UI —
  desktop GUI, mobile app, web facade — drives a running service through one typed API. Adds no
  coupling to the proxy core; the data path stays in-process (packets never cross IPC).
- **Prompted by:** the external (codex) review, items #2 ("promote IPC/FFI into a real product
  backend contract") and #5 ("unify mobile control/config with desktop backend APIs").

## Context

The control plane today is **launch-time config + four verbs**. `spark-service` loads exactly one
`core::config::Config` from a TOML file (or default) at daemon start (`daemon.rs:79`) and never
changes it; the IPC vocabulary is `Hello`/`Connect`/`Disconnect`/`GetStatus`/`Subscribe`
(`ipc/src/message.rs`), and `spark-ffi::Backend` mirrors exactly those. A UI therefore cannot:

- create/list/select/edit **connection profiles** (server, transport, stack, routing, credentials) —
  config is fixed at daemon launch;
- discover **capabilities** (which transports/stacks this build supports, the platform, the protocol
  version) to render only valid choices;
- see the **selected transport/stack**, the active **module name/version**, the **kill-switch mode**,
  the current **`direct_fallback`** beyond a single bool, or the **last error**;
- see **counters** (bytes up/down, active/total sessions);
- stream **logs** (the `Subscribe { logs }` flag is honored structurally but no `Push::Log` is
  produced yet — review item B);

…and the **embedded** data path (`core::fd_tunnel`) has a *process-global* stop signal
(`OnceLock<Notify>`, `fd_tunnel.rs:28`), so an embedder can't address a specific tunnel or run more
than one — the mobile shims pass a few primitives (`platforms/apple` `spark_tunnel_run(fd, mtu)`,
`platforms/android` ints) rather than a typed handle.

The architecture is sound (the M7 actor owns state; connections send `Envelope`s; `core` is
process-agnostic) — this is a **surface** gap, not a structural one. The fix is to grow the contract,
not rewrite anything behind it.

## Decision

Expand the control plane into a **versioned product backend contract**, delivered in additive slices.
Principles:

1. **Additive + version-negotiated.** New `RequestPayload`/`ResponsePayload`/`Push` variants append
   to the existing enums (postcard encodes variants by index, so appending preserves v1 decoding).
   Bump `PROTOCOL_VERSION` to `2` when the first new variant lands; `negotiate()` already picks the
   min. **The service must not emit a v2-only response/push to a peer that negotiated v1** — new
   features gate on the negotiated version. `MIN_SUPPORTED_VERSION` stays `1`.
2. **Profiles live in the privileged store; secrets are write-only.** A *profile* is a named,
   persisted connection config owned by `spark-service` (root-readable only). Per
   `process-architecture-and-ipc.md` §and `CLAUDE.md`, **secrets are never echoed back over IPC**:
   `AnytlsConfig.password` and wasm `init_config` are write-only — set on create/update, returned
   only as presence flags (`has_password: bool`) / masked on list/get. The proxy core never sends a
   secret to a client.
3. **Counters stay in the privileged process.** The data path tallies bytes/sessions via atomics in
   `core`; the service reports *snapshots* over IPC (poll + optional periodic push). No per-packet
   data crosses the boundary — consistent with the in-process data-path rule.
4. **One contract, two transports.** The same typed surface backs both the desktop IPC client and the
   embedded (mobile/NE) path. The embedded path gets a `TunnelHandle` replacing the process-global
   stop, so a UI gets the same lifecycle everywhere.
5. **`spark-ffi` mirrors each slice** so Swift/Kotlin track the contract in lockstep; the data-path
   shims remain a separate surface (they run the core, they don't carry control).

### Surface (grouped by slice)

```
Requests (client → service), appended to RequestPayload:
  GetCapabilities                          → Capabilities
  GetDetails                               → Details            (richer status)
  GetMetrics                               → Metrics
  ListProfiles                             → Profiles (redacted)
  GetProfile { id }                        → Profile (redacted)
  SetProfile { id?, profile, secrets }     → ProfileId          (create or update; secrets write-only)
  DeleteProfile { id }                     → Ack
  SetActiveProfile { id }                  → Ack
  ValidateProfile { profile }              → Validation
  Connect { profile: Option<ProfileId> }   → Ack                (extends today's no-arg Connect)

New response payloads: Capabilities, Details, Metrics, Profiles, Profile, ProfileId, Validation.
New pushes (Push): Metrics(MetricsSnapshot)  [periodic], Log(LogLine)  [exists, finally produced].
```

- **Capabilities**: `{ protocol_version, build_version, transports: [plain|anytls|wasm],
  stacks: [userspace|system], platform, manages_routing }` — derived from compiled features
  (`cfg!(feature = …)`) + target. Static, cheap.
- **Details**: `state`, `direct_fallback`, `selected_transport`, `selected_stack`, `module:
  Option<{name, version}>`, `kill_switch: fail_open|fail_closed`, `last_error: Option<String>`.
- **Metrics**: `{ bytes_up, bytes_down, sessions_active, sessions_total, since }`.
- **Profile** (redacted): the non-secret config + `{ has_password, has_init_config }`.

### Embedded handle model

Replace `fd_tunnel`'s `static OnceLock<Notify>` with a `TunnelHandle { stop: Arc<Notify> }` returned
by a non-global `run`/`spawn` entry; `stop()` becomes `handle.stop()`. The JNI/C-ABI shims keep their
thin signatures but route through a handle stored per-instance (a slab/registry keyed by an opaque
id) instead of the global — so teardown is addressable and a second tunnel is possible. (`run_fd`'s
status-code contract from the shim-unification commit is unchanged.)

## Rollout slices (each a standalone, shippable change)

1. **Capabilities + richer status (read-only).** `GetCapabilities`, `GetDetails`; bump
   `PROTOCOL_VERSION → 2`; `spark-ffi` mirrors. Additive, no config mutation, lowest risk. *(Start
   here.)*
2. **Metrics.** Atomic counters in `core::proxy::{tcp,udp}` → engine snapshot → `GetMetrics` +
   periodic `Push::Metrics`. Honors the `events`/`logs`/(new)`metrics` subscribe filter.
3. **Profiles.** `List/Get/Set/Delete/SetActiveProfile`, `ValidateProfile`, `Connect { profile }`;
   privileged persisted store; write-only secrets + redacted reads. The largest slice (persistence,
   redaction, config mutation, validation).
4. **Log streaming.** Produce `Push::Log(LogLine)` from a `tracing` layer → actor channel, redacted
   via `core::redact`; the `Subscribe { logs }` filter is already wired (review item B, folded here).
5. **Embedded handle model.** `TunnelHandle` replaces the process-global stop; update
   `platforms/{android,apple}` + `fd_tunnel`. (Review item #5.)

## Security

- Peer auth unchanged (SO_PEERCRED + `spark` group on unix; pipe DACL on Windows).
- **Secrets never leave the privileged store**: write-only on the wire, redacted on read. A profile
  round-trip (get → edit → set) must not require the client to have ever seen the secret.
- `ValidateProfile`/`SetProfile` error messages carry no secrets (the existing `Error.message`
  "no secrets" rule).
- New variants gate on the negotiated protocol version so a downgraded/old peer can't be fed frames
  it can't decode.

## Consequences

- **+** UIs become possible without per-feature IPC churn; the contract is the single integration
  point (desktop + mobile + web facade).
- **+** Profiles move config out of a root-edited TOML into a managed, validated store.
- **−** `PROTOCOL_VERSION` and the persisted profile store become compatibility surfaces to maintain;
  slices 3/5 are real work (persistence, redaction, an embedded lifecycle refactor).
- **Alternatives rejected:** (a) a JSON-RPC/HTTP facade *instead of* extending `spark-ipc` — deferred,
  not rejected; it's a thin adapter over this same contract for out-of-process/web UIs and rides on
  top once the contract exists. (b) Letting clients pass a full `Config` per `Connect` instead of
  profiles — loses persistence, validation, and the write-only-secret boundary.
