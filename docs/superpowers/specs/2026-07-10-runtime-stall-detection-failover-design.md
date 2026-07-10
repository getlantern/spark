# Runtime Stall Detection + Live Failover — Design

## Problem

A proxy that passes its initial health probe is often **throttled or silently stalled by a censor
once real traffic flows** — the classic "worked on connect, dies under load" failure. Spark doesn't
notice today:

- Established TCP flows are pumped with `copy_bidirectional(stream, upstream)` on a per-flow task
  (`core/src/proxy/tcp.rs`) with **no idle/stall timeout**. A throttled or dropped-mid-transfer
  upstream just blocks until the OS TCP timeout (minutes).
- The health probe (`core/src/transport/probe.rs`) fetches a **small** callback URL through the
  transport (2xx = healthy) — so a server throttled on *bulk* traffic keeps passing its probe and
  keeps receiving flows.
- Dial *failures* already `demote()` + fail over, but a connection that dials fine and *then* stalls
  is invisible.

## Goal

Detect an **actively-stalled** flow at runtime, abort it (the app retries, as it already does on any
reset), attribute repeated stalls to the pool member that served them, and **quarantine a throttled
member** so traffic reroutes to a healthy server — restoring the member only once it carries real
**trial flows** again without stalling.

## Scope (v1)

- **TCP flows through the multi-server pool** (`SelectingTransport`). The lantern path always builds a
  pool, so this covers the real deployment.
- **Out of scope for v1:** UDP/QUIC stall detection (datagram semantics differ; QUIC has its own
  loss/congestion signals), direct/single-transport dials (no pool to reroute within), and
  transparent per-flow retry (a live TCP flow can't be migrated mid-stream).
- `multi-server`-gated, consistent with where the pool lives.

## Decisions (confirmed with stakeholder)

- **Reaction:** abort the stalled flow + demote/quarantine its member (not transparent per-flow
  retry — TCP can't migrate mid-stream).
- **Stall signal:** *active-stall* — a flow counts as stalled only if it recently moved bytes and
  then moved **zero** bytes in either direction for a stall window. Idle-from-start flows (keepalive,
  long-poll, SSE, websockets sitting quiet) are never aborted. Lowest false-positive.
- **Member penalty:** *threshold* — one stall just aborts that flow; a member is quarantined only
  after **K stalls within a window** (distinguishes a throttled proxy, which stalls many flows at
  once, from a single slow origin).
- **Recovery:** *passive trial-flow recovery* — after a cooldown, a quarantined member is re-admitted
  **on trial**; it's restored only once it carries a few real flows again *without* stalling, and
  re-quarantined (with exponential backoff) if a trial flow stalls. No blind timer, and no active
  bandwidth probe.
  - *Why not an active bandwidth probe:* the only per-arm URL the config provides is the **bandit
    callback** (`bandit_url_overrides` → `https://api.iantem.io/v1/bandit/callback?token=…`), which is
    a tiny, tokened, ~`poll_interval+30s`-expiring control-plane endpoint — unusable as a
    throughput target. A true active probe would need a new lantern-box download/echo endpoint
    (backend work). Passive trial recovery needs no new endpoint and measures the real server with
    real traffic, reusing the same `StallGuard` signal.

## Architecture

Detection and attribution live in the **pool layer** (`core/src/transport/select.rs`) — the only
place that knows which member served a flow and can demote/reroute. The generic byte-pump
(`proxy/tcp.rs`) is **unchanged**: it relays a member stream that can now surface a "stalled"
`io::Error`, which ends `copy_bidirectional`, tears the flow down (reset), and the app retries.

```
app flow ──accept──▶ proxy/tcp.rs::forward ──dial──▶ SelectingTransport::dial
                            │                              │ picks member i
                            │                              ▼
                            │                       StallGuard{ inner: member[i] stream,
                            │                                   pool, member_idx: i }
                            ▼                              │
                   copy_bidirectional(stream, ◀───────────┘ (returned as BoxedStream)
                     CountingStream(StallGuard))
                            │
              censor throttles → 0 bytes for stall_window while ever_active
                            ▼
        StallGuard: record_stall(i) on pool  +  return Err(TimedOut,"stalled")
                            ▼
        copy_bidirectional ends → flow reset → app retries → new flow avoids
        member i if it's now quarantined (K stalls) → routes to a healthy member
```

### Component 1 — `StallGuard` stream adapter (detection)

A stream wrapper (`AsyncRead + AsyncWrite`) that `SelectingTransport::dial` puts around the chosen
member's stream before returning it. It holds:
- a pinned reset-on-progress deadline (`tokio::time::Sleep`) of `stall_window`,
- an `ever_active` flag,
- the member index + an `Arc`/`Weak` handle to the pool's stall recorder.

On each `poll_read`/`poll_write`: if bytes moved, reset the deadline and set `ever_active`. Poll the
deadline alongside the inner I/O; if it fires with **zero progress since the last reset and
`ever_active == true`**, call `pool.record_stall(member_idx)` and return
`Err(io::ErrorKind::TimedOut, "flow stalled")`. Because both directions of `copy_bidirectional` pass
through the member/upstream stream, wrapping just that stream captures all progress. Idle-from-start
flows never set `ever_active`, so their deadline firing is a no-op (reset and keep waiting).

### Component 2 — member stall accounting + quarantine (policy)

Extend the pool's per-member state (under the existing `selection` mutex, consistent with the
reload/pin concurrency model already hardened in #77):
- a small ring/deque of recent stall timestamps per member,
- a `quarantined_until: Option<Instant>` (or a `quarantined: bool` cleared by the recovery probe).

`record_stall(i)`: push the timestamp; if the count within `stall_demote_window` ≥ `stall_demote_count`,
mark member `i` quarantined. `members_and_order()`/`order()`/`snapshot()` treat a quarantined member
like an unhealthy one — excluded from the dial order (so new flows avoid it), still shown in the UI
snapshot as unhealthy. Fail-open-to-direct still applies when every member is quarantined/unhealthy.
`reload()` clears all stall state (new generation of members).

Stall timestamps use **`tokio::time::Instant`** (not `std::time::Instant`) so tokio's test clock
(`tokio::time::pause` + `advance`) drives the `StallGuard` deadline **and** the stall accounting
deterministically in one place — no wall-clock flakiness, no hand-rolled clock injection.

### Component 3 — passive trial-flow recovery

No active probe and no new endpoint. A quarantined member walks a small state machine, all under the
`selection` lock:

```
Healthy ──(≥ K stalls in window)──▶ Quarantined(until = now + cooldown)
Quarantined ──(cooldown elapsed)──▶ OnTrial(clean_needed = stall_trial_flows)
OnTrial ──(a trial flow stalls)──▶ Quarantined(cooldown ×2, capped)   // exponential backoff
OnTrial ──(clean_needed trial flows finish without stalling)──▶ Healthy   // backoff reset
```

- **Quarantined** members are excluded from the dial order (new flows avoid them). The
  cooldown-elapsed → **OnTrial** transition is checked lazily in `members_and_order()` (no timer):
  when a quarantined member's `until` has passed, it flips to `OnTrial`.
- **OnTrial** members are re-admitted to the dial order but deliberately handed a *bounded* number of
  real flows so we get a signal: while any member is `OnTrial` with trial slots left, selection routes
  the next new flow to it (decrementing its slots) instead of the ranked best. Its `StallGuard`
  watches those flows.
- **Outcome reporting via `StallGuard::Drop`:** the guard already calls `record_stall(i)` on a stall.
  On drop of a guard that was `ever_active` and did **not** stall, it calls `record_flow_ok(i)`. During
  trial, each `record_flow_ok` decrements `clean_needed`; reaching zero **restores** the member
  (backoff reset). Any `record_stall` during trial **re-quarantines** it with doubled cooldown
  (capped at `stall_quarantine_max_secs`). Outside trial, `record_flow_ok` just clears the member's
  stall ring so transient single stalls age out.

The background prober (`prober_loop`) is **unchanged** — it keeps doing the cheap callback probe for
latency/health ranking; recovery is driven entirely by selection + `StallGuard` outcomes, not a probe.

## Config

New `TransportConfig` fields (plumbed from the lantern config alongside `probe_interval_secs`;
`multi-server`-gated; conservative defaults; enabled by default):

| field | default | meaning |
|---|---|---|
| `stall_window_secs` | 15 | no-progress-after-active → flow stall. **`0` disables the whole feature.** |
| `stall_demote_count` | 3 | stalls within the window before a member is quarantined |
| `stall_demote_window_secs` | 30 | the window for counting stalls |
| `stall_quarantine_secs` | 60 | base cooldown before a quarantined member goes on trial |
| `stall_quarantine_max_secs` | 600 | cap for the exponential backoff on repeated quarantine |
| `stall_trial_flows` | 2 | clean (non-stalling, ever-active) trial flows needed to restore a member |

## Data flow (worked example)

1. Flow dials member `i`; `StallGuard` wraps its stream; bytes flow normally (`ever_active = true`).
2. Censor throttles member `i` → 15 s with zero progress → `StallGuard` records stall(`i`) + errors →
   `copy_bidirectional` ends → flow reset → app retries.
3. Retry dials the pool again; member `i` is still eligible (only 1 stall), so it may be tried again.
4. As the censor throttles more flows through `i`, it accrues ≥3 stalls in 30 s → member `i`
   **quarantined** for 60 s → dropped from the dial order → new flows route to a healthy member.
5. After 60 s, `i` flips to **OnTrial**; selection hands it the next couple of real flows. If a trial
   flow stalls again → `i` re-quarantined for 120 s (backoff), and so on (capped at 600 s).
6. When `i` actually recovers (block lifts), its trial flows run without stalling; after
   `stall_trial_flows` clean flows it's **restored** to Healthy and re-ranked normally (backoff reset).

## Files

**Add:** `core/src/transport/stall.rs` — the `StallGuard` adapter (`AsyncRead + AsyncWrite`,
reset-on-progress deadline, `record_stall` on stall, `record_flow_ok` on clean `Drop`) + its unit tests.

**Modify:**
- `core/src/transport/select.rs` — wrap dialed member streams in `StallGuard`; per-member stall
  accounting + quarantine/trial state machine (`record_stall`/`record_flow_ok`); exclude quarantined
  members from `order`/`snapshot`, route trial flows to `OnTrial` members, flip cooldown→trial lazily
  in `members_and_order()`; clear all stall state on `reload`. `prober_loop` **unchanged**.
- `core/src/transport/mod.rs` — give each `StallGuard` a handle back to the pool's stall recorder when
  `build_selecting` builds the `SelectingTransport`; `build_members` unaffected.
- `core/src/config/mod.rs` + `core/src/config/lantern.rs` — the new `TransportConfig` fields + adapter
  mapping (defaults; `lantern.rs` maps any server-provided values).

**Reuse:** the `SelectingTransport` selection lock + `demote`/`order`/`members_and_order` machinery,
`CountingStream` (the metrics wrapper stays the outer layer). No `probe.rs` change (recovery is
passive — no bandwidth probe).

## Testing

Deterministic with `tokio::time` pause/advance:
- **StallGuard:** progress resets the deadline; no-progress-after-active fires (records stall +
  errors); idle-from-start never fires; a fake stream that goes silent mid-stream triggers exactly
  one stall.
- **Quarantine:** a member quarantines after `K` stalls within the window but not below it; a single
  stall does not quarantine; `order()`/`members_and_order()`/`snapshot()` exclude a quarantined
  member; `reload()` clears stall state.
- **Recovery:** after cooldown a quarantined member flips to `OnTrial`; `stall_trial_flows` clean
  (`record_flow_ok`) trial flows restore it; a `record_stall` during trial re-quarantines it with
  doubled (capped) cooldown; `StallGuard::Drop` reports `record_flow_ok` only when `ever_active` and
  not stalled.
- **Trial routing:** `members_and_order()` hands new flows to an `OnTrial` member until its slots are
  spent, then reverts to ranked order.
- **Whole-workspace gate** (spark-core API touch): base build (no `multi-server`) clean, clippy
  all-targets/`config-fetch`, and the spark-android JNI target (`cargo ndk clippy`).

## Verification

- Unit tests above (`cargo test -p spark-core --features multi-server`).
- Manual/staging: point a member at a server that accepts the connection then throttles (e.g. a `tc`
  netem rate limit, or a proxy that stalls after N bytes); confirm flows abort within
  `stall_window`, the member quarantines after `K` stalls, new flows route to a healthy member, and
  once the rate limit is lifted the member's trial flows run clean and it's restored to the pool.

## Phased rollout

- **Phase 1 — detection + abort:** `StallGuard` + wire into `SelectingTransport::dial`; stalled flows
  abort (app retries). No member penalty yet. Independently shippable + testable.
- **Phase 2 — quarantine:** per-member stall accounting + `record_stall` + exclude quarantined from
  selection + clear on reload. New flows route away from a throttled member.
- **Phase 3 — passive trial recovery:** the cooldown→trial→restore/re-quarantine state machine,
  `StallGuard::Drop` → `record_flow_ok`, trial-flow routing in `members_and_order()`, and exponential
  backoff. A recovered member rejoins the pool without a reconnect.
- **Phase 4 — config plumbing + gate:** `TransportConfig` fields + `lantern.rs` mapping; whole-
  workspace gate; PR + review loop.
