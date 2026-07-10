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
member** so traffic reroutes to a healthy server — restoring the member only once an **active
bandwidth probe** confirms real throughput.

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
- **Recovery:** *active bandwidth probe* (in v1) — a quarantined member is restored only once a
  bandwidth probe confirms real goodput, not on a blind timer.

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

### Component 3 — active bandwidth recovery probe

The background prober (`prober_loop`, `select.rs`) already runs each `probe_interval`. Extend it:
- **Healthy (non-quarantined) members:** the existing cheap callback probe (health + latency ranking) — unchanged.
- **Quarantined members:** an **active bandwidth probe** instead — dial the member, GET the configured
  `bandwidth_probe_url`, read up to `bandwidth_probe_max_bytes` (cap, e.g. 512 KiB) under a deadline,
  and compute goodput (KiB/s). If goodput ≥ `stall_recover_min_kbps`, **un-quarantine** the member
  (fresh chance; the prober re-ranks it normally next round). Otherwise it stays quarantined and is
  re-tested next round.

Cost is bounded: bandwidth-probe traffic is spent **only** on members already suspected of
throttling, not the whole pool. If `bandwidth_probe_url` is unset, fall back to a cooldown timer
(`stall_quarantine_secs`) so the feature still degrades gracefully without a configured URL. The
bandwidth probe reuses `probe.rs`'s hand-rolled HTTP(S)-through-a-transport client (extended to read a
capped body and time it) — no new HTTP dependency.

## Config

New `TransportConfig` fields (plumbed from the lantern config alongside `probe_interval_secs`;
`multi-server`-gated; conservative defaults; enabled by default):

| field | default | meaning |
|---|---|---|
| `stall_window_secs` | 15 | no-progress-after-active → flow stall. **`0` disables the whole feature.** |
| `stall_demote_count` | 3 | stalls within the window before a member is quarantined |
| `stall_demote_window_secs` | 30 | the window for counting stalls |
| `stall_quarantine_secs` | 60 | cooldown fallback when no `bandwidth_probe_url` is set |
| `bandwidth_probe_url` | none | URL of a sizeable resource fetched through a quarantined member to confirm recovery |
| `bandwidth_probe_max_bytes` | 524288 | cap on bytes read during a bandwidth probe |
| `stall_recover_min_kbps` | 200 | min goodput (KiB/s) to un-quarantine a member |

## Data flow (worked example)

1. Flow dials member `i`; `StallGuard` wraps its stream; bytes flow normally (`ever_active = true`).
2. Censor throttles member `i` → 15 s with zero progress → `StallGuard` records stall(`i`) + errors →
   `copy_bidirectional` ends → flow reset → app retries.
3. Retry dials the pool again; member `i` is still eligible (only 1 stall), so it may be tried again.
4. As the censor throttles more flows through `i`, it accrues ≥3 stalls in 30 s → member `i`
   **quarantined** → dropped from the dial order → new flows route to a healthy member.
5. Each prober round runs a bandwidth probe against `i`; while it stays slow, `i` stays quarantined.
6. When `i` recovers (or the block lifts), a bandwidth probe measures ≥200 KiB/s → `i` un-quarantined
   and re-ranked normally.

## Files

**Add:** `core/src/transport/stall.rs` — the `StallGuard` adapter + its unit tests.

**Modify:**
- `core/src/transport/select.rs` — wrap dialed member streams in `StallGuard`; per-member stall
  accounting + `record_stall` + quarantine; exclude quarantined members from `order`/`snapshot`;
  clear on `reload`; bandwidth-probe branch in `prober_loop`.
- `core/src/transport/probe.rs` — a `bandwidth_probe(transport, url, max_bytes, deadline) -> kbps`
  helper reusing the existing through-transport HTTP client.
- `core/src/transport/mod.rs` — thread the stall handle from `build_selecting`; `build_members`
  unaffected.
- `core/src/config/mod.rs` + `core/src/config/lantern.rs` — the new `TransportConfig` fields + adapter
  mapping (defaults; `lantern.rs` maps any server-provided values).

**Reuse:** the `SelectingTransport` selection lock + `demote`/`order` machinery, `prober_loop`, the
`probe.rs` through-transport HTTP client, `CountingStream` (the metrics wrapper stays the outer layer).

## Testing

Deterministic with `tokio::time` pause/advance:
- **StallGuard:** progress resets the deadline; no-progress-after-active fires (records stall +
  errors); idle-from-start never fires; a fake stream that goes silent mid-stream triggers exactly
  one stall.
- **Quarantine:** a member quarantines after `K` stalls within the window but not below it; a single
  stall does not quarantine; `order()`/`members_and_order()`/`snapshot()` exclude a quarantined
  member; `reload()` clears stall state.
- **Recovery:** a quarantined member with a bandwidth probe ≥ threshold is un-quarantined; below
  threshold stays quarantined; with no `bandwidth_probe_url`, the cooldown fallback restores it.
- **Bandwidth probe:** goodput math over a fake fixed-size body under a controlled clock.
- **Whole-workspace gate** (spark-core API touch): base build (no `multi-server`) clean, clippy
  all-targets/`config-fetch`, and the spark-android JNI target (`cargo ndk clippy`).

## Verification

- Unit tests above (`cargo test -p spark-core --features multi-server`).
- Manual/staging: point a member at a server that accepts the connection then throttles (e.g. a `tc`
  netem rate limit, or a proxy that stalls after N bytes); confirm flows abort within
  `stall_window`, the member quarantines after `K` stalls, new flows route to a healthy member, and
  the member is restored once the rate limit is lifted (bandwidth probe passes).

## Phased rollout

- **Phase 1 — detection + abort:** `StallGuard` + wire into `SelectingTransport::dial`; stalled flows
  abort (app retries). No member penalty yet. Independently shippable + testable.
- **Phase 2 — quarantine:** per-member stall accounting + `record_stall` + exclude quarantined from
  selection + clear on reload. New flows route away from a throttled member.
- **Phase 3 — active bandwidth recovery:** the `bandwidth_probe` helper + the quarantined-member
  branch in `prober_loop`; cooldown fallback when unconfigured.
- **Phase 4 — config plumbing + gate:** `TransportConfig` fields + `lantern.rs` mapping; whole-
  workspace gate; PR + review loop.
