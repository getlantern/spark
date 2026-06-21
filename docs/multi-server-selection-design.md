# Multi-server selection — design: latency-ranked server pool with periodic retesting

- **Status:** Proposed — 2026-06-21.
- **Builds on:** the `transport` layer (`Transport`/`UdpTransport` + per-kind builders), the bootstrap
  resolver (`spark_core::bootstrap`, resolves `Endpoint::Host`→`Ip` at startup), and `flint-dial`'s
  bounded-concurrency racing (`race_windowed`). See `docs/bootstrap-resolver-design.md`.

---

## 1. Why this exists

Today a spark `Config` selects **one** transport by precedence (`anytls` > `samizdat` > `wasm` >
plain `server`) and `transport::from_config` builds exactly one `Arc<dyn Transport>` for the whole
data path. A single configured server is a single point of failure and gives the client no way to
prefer a faster or working server when several are available.

We want the config to carry **multiple servers**, and spark to **test each one and route traffic
through the lowest-latency one that actually works**, **re-testing periodically** so the choice tracks
changing network conditions and server health.

### Relationship to existing concepts (what this is *not*)

- **Not the service "profiles" (ADR 0004).** Profiles are multiple *named whole configs* the **user**
  picks among manually (`Connect{profile_id}`), persisted in the privileged service. Multi-server is
  **automatic, latency-based** selection among **servers within a single config**, done in
  `spark-core` on the data path — independent of the service/IPC layer. A profile could itself contain
  a multi-server pool.
- **Not the server-side bandit (EXP3.S).** That is Lantern's *server-side* arm selection. This is a
  simple *client-side* latency probe + pick-lowest, not a learning algorithm.

It **is** the client-side analogue of Lantern's probe/URL-test pattern (client URL-tests *through* a
proxy to confirm it works end-to-end), applied to a local pool.

## 2. Goal & scope

**In scope:** extend `core::config` with a pool of full transport configs; a `SelectingTransport`
(in `spark-core`) that probes each server's **handshake latency** and verifies it **works end-to-end**
by fetching a configured **callback URL through the transport**, routes new flows through the current
lowest-latency healthy server, fails over on error, and **periodically re-probes** (in bounded
batches) to track the best server. Plus a small `flint-dial` enhancement: `probe_windowed`
(bounded-concurrency *collect-all-and-rank*, the sibling of `race_windowed`'s first-wins).

**Out of scope (designed-for, not built):** fetching the server pool from the Lantern API (the
bootstrap doc's future config-fetch consumer) — the pool is config-file-driven here, but the
`Vec<ServerEntry>` shape accepts a fetched list later. Also out: migrating in-flight connections on a
switch, expected-response-body matching on the health check, and any learning/bandit logic.

## 3. Design

### 3.1 Config schema (`core/src/config/mod.rs`)

A new array of **server entries** under `[transport]`, each a complete, *tagged* transport spec
reusing today's per-kind config structs, plus an optional per-entry callback override:

```toml
[transport]
callback_url = "https://www.example-canary.com/generate_204"   # global default health-check URL
probe_interval_secs = 300                                       # default 300
probe_window = 8                                                # bounded probe concurrency, default 8

[[transport.servers]]
kind = "anytls"
server = "proxy-a.example.com:443"      # Endpoint: IP:port or host:port (resolved at startup)
password = "..."
# sni / clienthello / records / gambit as in AnytlsConfig

[[transport.servers]]
kind = "samizdat"
server = "203.0.113.7:443"
server_pubkey = "..."
short_id = "..."
callback_url = "https://other-canary.example/ok"   # per-entry override of the global default
```

- **`ServerEntry`** is a serde-tagged enum (`kind = "anytls" | "samizdat" | "wasm" | "tunnel"`)
  wrapping the existing `AnytlsConfig` / `SamizdatConfig` / `WasmConfig` (and a `tunnel` variant = the
  plain `tcp_tunnel` client to a `server` address), plus `callback_url: Option<String>` (overrides
  `transport.callback_url`). The no-server `DirectTransport` is **not** a pool kind — there is nothing
  to rank, and "no tunnel" is the kill-switch fail-open behavior, not a server in the pool.
- **`server` fields stay `Endpoint`** (the bootstrap resolver resolves every `Host` entry to an `Ip`
  before probing — §3.5).
- **Backward compatibility:** when `transport.servers` is absent, the existing single-transport
  precedence path is used unchanged (it is equivalent to a one-entry pool). A config with `servers`
  ignores the legacy single fields. No migration required.
- **Probe knobs** (`callback_url`, `probe_interval_secs`, `probe_window`) live on `TransportConfig`
  with the documented defaults.

### 3.2 `build_one` and `from_config` (`core/src/transport/mod.rs`)

Today's per-kind branches of `from_config` are extracted into:

```
fn build_one(entry: &ServerEntry, protector: Option<&SocketProtector>, wire: &WirePlan)
    -> io::Result<(Arc<dyn Transport>, Arc<dyn UdpTransport>)>
```

`from_config` then:
- if `transport.servers` is set → build a `SelectingTransport` over the pool and return it as the
  `(Arc<dyn Transport>, Arc<dyn UdpTransport>)` pair (no forwarder change);
- else → the existing single-transport path (one `build_one` on the desugared lone entry).

**Extensibility (more transports are coming — e.g. hysteria2/QUIC).** `build_one` is the single seam
for transport kinds. Adding a transport is: a new `ServerEntry` variant + a `build_one` branch
(returning its `Transport`/`UdpTransport`); the `SelectingTransport`, prober, and probe are
kind-agnostic and need no change. A UDP-native transport returns a real `UdpTransport` (and a
TCP-over-its-transport `Transport` if it proxies TCP, as hysteria2 does).

### 3.3 Health probe (`core/src/transport/probe.rs`)

```
struct ProbeOutcome { latency: Duration, healthy: bool }   // healthy=false ⇒ disqualified
async fn probe(transport: &Arc<dyn Transport>, callback: &CallbackUrl) -> ProbeOutcome
```

`CallbackUrl` is a minimal hand-parsed `{ scheme, host, port, path }` (no `url` crate — consistent
with the no-new-deps rule and `flint-dns`'s hand-rolled codecs); parsing happens once at config load.

A probe:
1. **Times the transport establish** — bring the transport session to "ready". The *establish*
   is kind-specific (a TCP+TLS/Chrome-mimicry+auth handshake for anytls/samizdat/tunnel, a QUIC
   handshake for a future UDP/QUIC transport like hysteria2) — the prober doesn't care which; it just
   times "ready". This is the ranking latency and a liveness/blocking signal (a blocked/throttled
   server fails or times out).
2. **Verifies end-to-end** — open a proxied flow to the callback host and run a minimal **HTTP/1.1
   GET** of the callback URL over it; **`healthy = 2xx`.** This uses the transport's stream surface
   (`Transport::dial`), which works for any transport that proxies TCP — *including* UDP/QUIC-based
   ones such as hysteria2, which carry TCP flows over their UDP transport (the QUIC handshake is folded
   into the dial latency). A hypothetical **UDP-only** transport (no TCP surface at all) would need a
   UDP-based health check (e.g. a DNS query or QUIC echo to the callback); that variant is a clean
   extension of the probe, noted in the roadmap, and not built here.

**TLS for the callback (binary-budget decision).** `rustls` is **not** in spark's base build (only
`ring`), and the <3 MB base budget rules out adding it just for a health check. So:
- **`http://`** callbacks → plain HTTP/1.1 over the transport stream; works in **every** build.
- **`https://`** callbacks → TLS via the **boring** backend already linked by the transport features
  (a plain `tokio-boring2` `SslConnector` — no Chrome mimicry needed, since this TLS rides *inside* the
  tunnel where the censor can't see it). Gated `#[cfg(feature = "anytls")]` (which `samizdat` implies,
  and which any real anytls/samizdat pool already enables).
- An `https://` callback configured in a build **without** a boring-bearing feature → a clear error at
  probe time (mirroring the existing "feature not built" errors), never a silent skip.

The HTTP client is a tiny hand-rolled GET-status reader over the transport stream — consistent with
spark's "raw TLS + `tokio`, no `hyper`/`reqwest`" rule (cf. `flint-dns`'s hand-rolled DoH/h2). The
multi-server core (config, `SelectingTransport`, prober, the `http://` probe path) is **not**
feature-gated; only the `https://` TLS step rides `anytls`.
Each probe is bounded by a deadline so a hung dial can't stall a batch (same lesson as the bootstrap
resolver's per-attempt timeout).

### 3.4 Prober + `SelectingTransport` (`core/src/transport/select.rs`)

**`SelectingTransport`** implements both `Transport` and `UdpTransport` and is the value
`from_config` hands the forwarder. It holds:
- the built pool (each entry's `(Arc<dyn Transport>, Arc<dyn UdpTransport>)` + its callback URL),
- an **atomically-swappable current best** plus the ranked fallback order,
- a background **prober** task handle.

`dial`/`dial_udp` delegate to the **current best**; on a dial error the call **fails over** to the
next-best in rank order for that flow and **demotes** the failed server (triggering an off-cycle
re-probe). Existing connections are never migrated — only *new* flows see a swap.

**L4 capability & selection (forward-looking).** v1 keeps one current-best shared by TCP and UDP, and
ranks on the proxied-flow probe above; UDP rides the same selected server and inherits its UDP
capability (e.g. a TCP-only `samizdat` entry's `dial_udp` reports unsupported, exactly as today). This
is fine for today's kinds (anytls/wasm/tunnel carry both; samizdat is TCP-only). As **UDP-native**
transports arrive (hysteria2/QUIC) and kinds diverge in L4 support, selection becomes
**capability-aware**: rank only UDP-capable servers for the UDP best, independently from the TCP best
(two current-bests rather than one). The `ServerEntry`/`build_one`/prober seams already isolate this —
it's an internal change to ranking, not to the config or the forwarder. Tracked in the roadmap; not
built here.

**Prober** (uses `flint_dial::probe_windowed`):
- **Initial selection:** probe the pool in windowed batches; pick the lowest-latency healthy server
  from the first batch(es) that yield a healthy candidate — so connect isn't blocked on a huge pool —
  then keep ranking the rest in the background and swap to the global best (subject to hysteresis).
- **Periodic:** every `probe_interval_secs`, re-probe the pool (windowed) and re-rank.
- **Switch policy — failover + hysteresis:** immediate failover when the active server errors/dies; on
  a periodic re-rank, switch only if a challenger is **≥ 20% lower latency** *or* the current server is
  now **unhealthy**. This prevents flapping between near-equal servers.

**Lifecycle:** the prober task is spawned when the `SelectingTransport` is built (inside a tokio
context, like the AnyTLS idle-sweep), its `JoinHandle` is stored, and it is **aborted on drop** — no
orphaned task after teardown.

### 3.5 Composition with the bootstrap resolver

Each entry's `server` is an `Endpoint`. The existing startup bootstrap phase
(`resolve_bootstrap`/`resolve_endpoints`) resolves every `Endpoint::Host` across **all** pool entries
to an `Endpoint::Ip` before the pool is built/probed — multi-server simply widens what the bootstrap
phase iterates over. (It also preserves each entry's hostname as the default SNI, per the bootstrap
resolver design.)

### 3.6 `flint-dial::probe_windowed`

```
async fn probe_windowed<F, Fut, T>(count: usize, window: usize, probe_one: F) -> Vec<(usize, T)>
where F: FnMut(usize) -> Fut, Fut: Future<Output = T>
```

Runs all `count` probes with at most `window` in flight, refilling as each finishes, and returns
**every** result with its index (unlike `race_windowed`, which returns only the first `Ok`). Same
single-push-site, `Send`-preserving structure as `race_windowed`.

## 4. Data flow

```
load Config (transport.servers: pool of full transport configs)
  → bootstrap: resolve every Endpoint::Host across all entries → Ip  (default SNI = hostname)
  → build pool (build_one per entry)
  → SelectingTransport::new → spawn prober
        initial: probe_windowed → first healthy lowest-latency = current best  (fast connect)
        background: finish ranking → swap to global best (hysteresis)
  → hand SelectingTransport to the forwarder (as Arc<dyn Transport>/<dyn UdpTransport>)

per new flow:  SelectingTransport.dial(target) → current_best.dial(target)
                 └─ on error → next-best + demote failed → off-cycle re-probe

every probe_interval_secs:  probe_windowed(pool) → re-rank → swap if ≥20% better or current unhealthy
```

## 5. Error handling

- **No healthy server** (none pass the callback, at startup or after all fail): the current best is
  empty, so `dial`/`dial_udp` return a clear `no healthy server in the pool` error; the prober keeps
  re-probing on its interval. This **composes with the existing kill-switch** (fail-open/closed,
  process-architecture §5) unchanged — multi-server does not redefine kill-switch semantics.
- **A probe times out / fails:** that server is simply unhealthy for this round (disqualified from
  ranking); bounded per-probe deadline keeps a hung dial from stalling the batch or the all-fail case.
- **The active server fails mid-session:** immediate per-flow failover to next-best + demotion +
  off-cycle re-probe; no wait for the periodic timer.
- **A configured `host:port` fails to resolve at startup:** handled by the existing bootstrap phase
  (clear `couldn't resolve <host>` error; no silent fallthrough).
- **Empty pool / malformed entry:** config parse/validation error at load (fail fast).

## 6. Testing

- **Config:** parse a mixed-kind `[[transport.servers]]` pool; global `callback_url` + per-entry
  override; probe-knob defaults; backward-compat (single `[transport.anytls]` → one-entry pool); empty
  pool rejected.
- **(flint) `probe_windowed`** (unit, no network): never more than `window` in flight; refills;
  returns *all* results with indices; empty input → empty vec; result future is `Send`.
- **Health probe** (unit, no network): against a **fake `Transport`** + a fake in-memory callback
  responder — 2xx ⇒ healthy with measured latency; non-2xx / connection error ⇒ unhealthy; a hung dial
  ⇒ deadline ⇒ unhealthy.
- **`SelectingTransport`** (unit, no network, fake transports with scripted latencies/health):
  - picks the lowest-latency healthy server initially;
  - fails over to next-best when the current `dial` errors, and demotes it;
  - on re-rank, switches only when a challenger is ≥20% better or the current is unhealthy (no flap on
    near-equal);
  - returns the `no healthy server` error when none pass; recovers when one becomes healthy on re-probe;
  - aborts the prober task on drop.
- **HTTP-over-transport client** (unit): minimal GET, parses the status line, 2xx vs non-2xx, over a
  fake stream.
- **Live-gated `#[ignore]` e2e:** a small real pool resolves, probes, and selects a healthy server
  (needs network + boring), mirroring the bootstrap resolver's live test.

## 7. Roadmap (context — not built here)

| # | Follow-up | Depends on |
|---|---|---|
| 1 | **Multi-server selection (this doc)** | transport layer, bootstrap resolver, flint-dial |
| 2 | More transport kinds, incl. **UDP-native** (hysteria2/QUIC): new `ServerEntry` variant + `build_one` branch | 1 |
| 3 | **Capability-aware selection** — independent UDP-best vs TCP-best once kinds diverge in L4 support | 1 + 2 |
| 4 | **UDP-based health check** for UDP-only transports (DNS/QUIC-echo callback) | 1 + 2 |
| 5 | Server pool fetched from the Lantern API (proxyless/fronted config-fetch) | 1 + bootstrap resolver + flint-dial |
| 6 | Expected-response-body match on the health check (beyond 2xx) | 1 |
| 7 | Adaptive probe cadence (backoff when stable, faster when unstable) | 1 |

## 8. References

`docs/bootstrap-resolver-design.md` (Endpoint, bootstrap resolve, windowed racing, per-attempt
deadline, SNI-from-hostname); `docs/samizdat-transport-design.md` / `docs/adr/0007-samizdat-transport.md`
(per-kind transports + session pool); `docs/process-architecture-and-ipc.md` §5 (kill-switch),
ADR 0004 (profiles); `getlantern/flint` `flint-dial` (`race_windowed`).
