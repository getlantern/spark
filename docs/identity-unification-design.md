# Identity unification: one account per device

**Status:** design. **Date:** 2026-07-27. **Platforms:** macOS (system extension) + iOS (app
extension); Android/Windows unaffected by the container split but adopt the same ownership rule.

## The bug

The app and the tunnel each call `/user-create` when they find no identity in *their own* data
directory, so every install produces **two separate Lantern accounts**:

| | app | tunnel |
|---|---|---|
| `user_id` | `389150267` | `389172276` |
| `pro_token` | 54 chars | 54 chars, **different** |
| `device_id` | `eec8d7c4…` | `31220f9a…` |

Observed 2026-07-27 on a macOS install. `request.rs:69` documents the mechanism: `user_id` starts as
the anonymous placeholder `"0"` and the "real id [is] set from `/user-create`" — run independently by
each process, because on macOS they cannot share a container (`PacketTunnelProvider.swift:125`: the
system-extension sandbox denies the root NE access to the *user's* group container — EPERM, and the
tunnel hangs in "connecting" until it times out).

### Why it matters beyond tidiness

**The process that fetches the proxies is the tunnel** — so it is the *tunnel's* account whose tier
decides which servers you get. Sign-in and purchases land on the **app's** account. A user who buys Pro
therefore keeps receiving free-tier servers, and nothing reports an error. Both accounts are free-tier
on the observed device, which is exactly why this has gone unnoticed.

Two lesser consequences:

- **Telemetry double-counts.** One physical device reports two `client.device_id` values — already
  documented as a follow-up in `diag/tunnel_host.rs` ("Device identity (deliberate split)").
- **The server lists disagree.** `config-new` caches its assignment per `device_id`, so two device ids
  means two cache entries and two different server sets. This is the visible symptom that started the
  investigation: the pre-connect UI (app cache) listing servers the pool (tunnel cache) has never heard
  of. It is downstream of the identity split, not a separate problem.

## Ownership rule

Identity and config look alike — both JSON, both cached per device — but they differ in the two ways
that matter:

| | Identity (`user_id`, `pro_token`, `device_id`) | Config (`config_raw.json`) |
|---|---|---|
| Originates | The app: sign-in, purchase, receipts | The server, per fetch |
| Lifetime | The life of the install | **180 s** (`poll_interval_seconds`) |
| Correct count | Exactly one | Whatever is newest |
| Sensitive | Bearer token | Proxy credentials + otel ingestion key |

> **Identity is not a cache, so do not arbitrate it by freshness.** Freshness needs a tie-break, and
> every tie-break re-opens the divergence. Identity has an *owner*; config has a *lifetime*.

**The rule:** identity is created **once**, held durably in **one** place (the app), and **never
rewritten**. The tunnel *receives* it and never persists it — so no second copy exists to drift.

## Design

### Durable copy: app only

`<app-support>/org.getlantern.spark/config/{user.json, device_id}` — unchanged from today. The app
creates identity on first launch via the existing censorship-resilient fetch path (the same one that
reaches `config-new` over the `fronted` avenue when `direct` fails).

### Transport: `providerConfiguration`

The tunnel already reads `providerConfiguration` for `config`, `splitTunnel` and `routingMode`. Add
identity to it.

This is the right channel, and notably **not** a shared directory:

- It is part of the **saved VPN profile**, not live IPC — so it survives app termination and is present
  for on-demand and at-boot tunnel starts.
- It lives in OS-protected VPN preferences. A `/Users/Shared/…` file (the intuitive alternative) is mode
  1777, which would expose `pro_token` — a bearer token — to every local process. Rejected for that
  reason.

### Tunnel: receive, never persist, never register

- Read identity from `providerConfiguration`; pass it into `spark_tunnel_run`.
- Use it for `ConfigRequest` **and** for the diagnostics resource attributes, which closes the
  double-counted `client.device_id` follow-up in `tunnel_host.rs`.
- **Never** write `user.json` / `device_id` into the tunnel container.
- **Never** call `/user-create` on the NE path.

**When identity is absent, fail the start with a clear error** rather than registering. Self-registration
stays available only on the explicit dev/CLI path. This is what makes "exactly one account" true by
construction instead of by convention: there is no code path in the product that can mint a second one.
The app is responsible upstream — if its own identity file is missing or corrupt it recreates it (it is
the owner) before starting the tunnel.

### Config: unchanged, and it converges for free

The app keeps fetching. It needs `otel` (which carries an ingestion key), the `unbounded` block, and the
pre-connect list. That is now harmless: with one `device_id`, both fetches hit the **same `config-new`
assignment-cache entry** and get the same servers. The UI divergence resolves server-side, with no
shared file and no publication mechanism.

## Lifecycle

| Event | Behavior |
|---|---|
| **First launch** | App has no identity → creates it once → starts the tunnel with it in `providerConfiguration`. The tunnel never registers. |
| **Normal start** | App supplies identity; tunnel uses it in memory and fetches config as the canonical user. |
| **Next start** | Identical. Nothing to reconcile: one durable copy, one direction. |
| **Tunnel starts without the app** (on-demand, boot) | `providerConfiguration` persists in the profile → identity available. |
| **Sign-in / buy Pro** | `user_id` and `device_id` are unchanged — the same account gains entitlement. If `pro_token` is reissued, the app re-saves the profile (future starts) and pushes to the live session via `sendProviderMessage` so the tunnel re-fetches and Pro applies without reconnecting. A credential refresh, not an identity change. |
| **App data wiped / reinstall** | Treated as a new install: the app creates a new identity, and Pro is recovered by sign-in / restore-purchase. Deliberately *not* solved by reading the tunnel's copy, because there won't be one. |

## Verification

1. `app user_id == tunnel-reported user_id`, one `device_id`, and no `user.json`/`device_id` written in
   the tunnel container.
2. Both `config_raw.json` files identical (same assignment-cache entry) — the original symptom.
3. Telemetry shows one `client.device_id` per device, with `spark.component` still distinguishing
   `app` from `tunnel`.
4. Tunnel start with no identity supplied fails loudly instead of creating an account.

## Rollout

No migration. Spark has no field users — four internal testers, whose duplicate accounts are simply
abandoned. Reset is: delete both identity files, launch the app, let it create one.

## Phases

1. **Identity handoff** — app→tunnel via `providerConfiguration`; tunnel stops registering and stops
   persisting identity. *This is the bug.*
2. **Live push** on sign-in/purchase, so entitlement applies mid-session.
3. *Optional:* the app stops fetching config while connected (the UI already reads the NE snapshot
   then), removing the redundant round-trip. Not required for correctness once identity is unified.

## Open question

Does re-saving the VPN profile on a `pro_token` refresh re-prompt the user for VPN permission? Expected
not, after the initial approval — but it gates Phase 2 and should be confirmed on-device before building
it.
