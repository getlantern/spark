---
name: ipc-service-split-design-m7
description: "DECIDED M7 control-plane IPC + service-split design for spark (postcard + length framing over unix socket, SO_PEERCRED+spark group, actor loop, mobile-portable protocol)"
metadata: 
  node_type: memory
  type: project
  originSessionId: b2538e8f-ad8a-4bf8-9b44-09f600c6d2c8
---

Design pass for spark M7 (control-plane IPC + privileged service split) at
`~/go/src/github.com/getlantern/spark`. Researched 2026-06-14 against Mullvad and Tailscale.
**Decisions CONFIRMED with Adam 2026-06-14:** postcard + length-delimited framing; service actor
loop; per-platform transport; crate boundaries; **auth = `SO_PEERCRED` with a `spark` group**
(not root-only; skip the operator-uid extra for now). The full reference design is in the repo at
`docs/process-architecture-and-ipc.md`; this records the prior-art comparison, the decisions, and
the mobile-portability analysis on top of it.

**Prior art (the IPC-protocol spectrum):**
- **Mullvad** (Rust, the closest analog: daemon + `mullvad-management-interface` crate + CLI/GUI):
  **gRPC/tonic** over a unix socket (`/var/run/mullvad-vpn`) on Linux/macOS, named pipe
  (`\\.\pipe\Mullvad VPN`) on Windows. Daemon is source of truth; RPC handler translates each
  call into an internal `DaemonCommand` enum sent to the single daemon event loop via a channel
  with a `oneshot` reply; `EventsListen` streams `DaemonEvent`s to all subscribers. Heavy deps
  (tonic→hyper→h2→tower→prost) → big binary; Mullvad has no size budget.
- **Tailscale** (Go): `tailscaled` daemon + `tailscale` CLI. **LocalAPI = HTTP/JSON over a unix
  socket** (`/var/run/tailscale/tailscaled.sock`); CLI is an HTTP client. Peer auth via socket
  creds + an **"operator"** model (`tailscale set --operator=<user>` lets a named non-root user
  drive the daemon). Streaming via `WatchIPNBus` long-poll of JSON `ipn.Notify`. On
  Windows/sandboxed-macOS falls back to **TCP loopback + a token** when unix-socket peer-creds
  aren't usable. Uses `MaskedPrefs` (per-field "set" flags) to avoid "unset field → default".

**Decisions (my recommendations):**
1. **Wire protocol = custom `postcard` + `u32`-length framing** (as `docs/process-architecture-
   and-ipc.md` §2 already specifies). gRPC (Mullvad) is effectively **forbidden** by CLAUDE.md's
   "never pull in hyper" rule + the <3 MB binary budget (tonic→hyper→h2 is ~hundreds of KB; we're
   at ~1.17 MB after M6). HTTP/JSON (Tailscale) still needs an HTTP stack. postcard reuses our
   existing `serde`, is tiny/`no_std`-friendly, and fits a low-rate single-peer-local channel. We
   hand-roll streaming (bounded mpsc → framed `Push`) and versioning (`Hello`) — little code,
   already specced. Allow a JSON encoding behind a `--debug-ipc` feature for curl-style debugging
   (a nod to Tailscale's inspectability without making JSON the default).
2. **Service = actor/event-loop (Mullvad pattern).** `service/` owns ONE core event loop holding
   all tunnel state. IPC handler authenticates the peer, then forwards each request as a
   `Command` over an mpsc to the loop and awaits a `oneshot` reply; state changes broadcast to
   subscribers via per-connection bounded mpsc (drop-oldest + `dropped:N`). Satisfies CLAUDE.md
   "channels over locks" — no `Arc<Mutex<TunnelState>>`.
3. **Transport + authz per platform, one protocol on top** (both confirm). Linux/macOS-daemon =
   unix socket + `SO_PEERCRED` authz — **CONFIRMED policy: root + a `spark` group** (operator-uid
   extra deferred). Windows = named pipe + SDDL. macOS-NE/iOS = the OS provider-message channel
   (reuse the same message enum). Implement **Linux first** (dev box, testable headless) for the
   M7 gate; others follow.
4. **Crate boundaries.** `ipc/` = pure protocol only (message enums, framing codec, version
   negotiation) — NO transport, NO tokio-net, so it unit-tests with zero I/O (mirrors Mullvad's
   `mullvad-management-interface`). `service/` = event loop + platform transport (tokio
   `UnixListener`) + authz + supervision + fail-open route-restore. `cli/` gains a client mode.
   `core/` stays IPC-agnostic (unchanged).
5. **Session-1 scope (no root):** the `ipc/` crate — `Request`/`Response`/`Push` enums, the
   length-prefixed postcard framing codec (encode/decode with partial-read buffering like our
   other codecs), and `Hello` version negotiation — is fully unit-testable with no socket. That
   IS PLAN M7 session 1. The unix-socket transport + `SO_PEERCRED` + the live "unprivileged
   client drives privileged service" gate need root → session 2+.

**Adopt regardless of wire format:** daemon-is-source-of-truth + client re-syncs via `GetStatus`
on (re)connect; event broadcast to subscribers; heartbeat + capped-backoff reconnect; bounded
streams. Kill-switch is DECIDED (fail open, loud, per-profile fail-closed override — doc §5);
implement, don't re-litigate. `MaskedPrefs`-style partial updates: defer — M7 `Reconfigure` can
send a full `Config` (we already have the TOML `Config` type); revisit if granular setters arise.

**Mobile portability (iOS/Android) — confirmed sound 2026-06-14.** The design holds because the
portable protocol (`ipc/`) and the platform transport (`service/`) are already separate; only the
protocol is reused on mobile, and the desktop transport/authz never cross-compiles there.
- **Refinement this forces (DO IT IN SESSION 1):** split the **message codec** (postcard
  `encode(&Request)->Vec<u8>` / `decode`) from the **length-delimited framing** (a `tokio-util`
  `LengthDelimitedCodec` adapter on top). Stream transports (unix socket, named pipe) use both;
  **message-oriented transports use the codec WITHOUT framing** — they already have message
  boundaries. So framing must NOT be baked into the message type; layer it (feature-gate the
  framing adapter so message-transport platforms don't pull tokio-util/streaming they don't need).
- **Android:** `VpnService` runs in the app's OWN process (same uid); no separate privileged user,
  no socket, no cross-user boundary → **`SO_PEERCRED`/`spark` group are N/A**; do NOT force the
  daemon model. Core runs in-process; UI↔core control is JNI (likely uniffi); `Push` = a callback/
  `Flow`, not a framed stream.
- **iOS (+ macOS NE):** app and Packet Tunnel Provider extension ARE separate processes, but the
  OS mediates trust (code-signing + shared **App Group**) — no peer-cred auth, none needed.
  Control = `NETunnelProviderSession.sendProviderMessage(_:)` (app→ext request/reply), one
  postcard-encoded `Request` per `Data` blob, **no length framing**. Server-initiated `Push` needs
  adaptation (ext can't initiate providerMessage): App Group + Darwin notification, `NEVPNStatusDidChange`,
  or app polls — protocol unchanged, delivery differs. Extension memory cap → the netstack buffer
  knobs we already locked. `service/` crate is desktop-only and never targets mobile; mobile embeds
  `core/` via `platforms/`.

**How to apply:** implement `ipc/` session 1 first — `Request`/`Response`/`Push` enums + postcard
**message codec** + a **separate** length-delimited framing adapter + `Hello` version negotiation,
all unit-tested (no socket, no root). Then session 2: `service/` + the Linux unix-socket transport
+ `SO_PEERCRED`/`spark`-group authz (needs root for the live gate). Build state + next chunk live
in the repo at `docs/STATE.md`. Relates to [[udp-transport-design-proposal]] (same "research prior
art → decide → memo → implement" flow).
