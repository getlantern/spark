# Bootstrap resolver — design: un-poisoned control-plane DNS for spark startup

- **Status:** Proposed — 2026-06-20.
- **Sub-project #1** of the bootstrap / split-tunneling architecture (see the roadmap at the end).
  This one is small and foundational; the per-flow router (#2) and the fake-IP DNS layer (#3) build
  on it.
- **Builds on:** the public `getlantern/flint` crate — `flint-dns` (the resilient DoH resolver:
  diverse pool, race → validate → cache) over `flint-dial` (the composable Chrome-mimicry
  `BootstrapDial` engine). See `flint/docs/design.md`.

---

## 1. Why this exists — two kinds of DNS

spark is a TUN VPN: every IP packet your apps send is routed to the TUN, reassembled by the netstack
into flows, and forwarded through the tunnel transport to the exit. A DNS query is just a UDP/53
datagram, so it rides that same path — **apps' DNS is "tunnelled DNS": the query travels inside the
encrypted tunnel and the exit resolves it.** spark has (correctly) no DNS code for this; the censor
never sees the query. This data-plane behaviour is **out of scope here and must not change.**

The gap is the **control plane**: before the tunnel exists, spark itself may need to reach a host
**by name** — and that lookup *can't* go through a tunnel that isn't up yet, so it goes out in the
clear, where a censor poisons it. Today spark sidesteps this by taking proxy servers as raw IPs
(`server: SocketAddr`), so there is no startup DNS at all. The moment spark must reach something by
hostname at startup, it needs an **un-poisoned resolver**. That is what `flint-dns` provides and what
this sub-project wires in.

| | In-tunnel (app) DNS | Control-plane (bootstrap) DNS — **this doc** |
|---|---|---|
| Who | apps | spark itself, at startup |
| Path | through the tunnel, exit resolves | direct, before the tunnel exists |
| Censor poisons it? | no (encrypted) | **yes (in the clear)** |
| Resolver | none (tunnelled) | `flint-dns` un-poisoned Chrome-mimicry DoH |

## 2. Goal & scope

**In scope:** a reusable spark-core component that resolves a hostname to **validated** IPs via a
**happy-eyeballs race over independent resolution strategies** — `flint-dns` un-poisoned Chrome-mimicry
DoH (the always-available path) and, when a proxy is configured **by IP**, resolving **through that
proxy** (dial it, tunnel a DNS query, the exit resolves upstream un-poisoned). First validated answer
wins. Plus its first consumer — letting a proxy `server` be named by **hostname** (not only an IP),
resolved at startup before dialing.

**First consumer (this doc):** proxy-server hostnames in `[transport.anytls]` / `[transport.samizdat]`.

**Designed-for next consumer (not built here):** **proxyless / domain-fronted dialing to the Lantern
API** (à la `kindling`) to fetch initial proxy configs on startup — `resolve(host) → validated IPs →
flint-dial BootstrapDial (proxyless/fronted) → API`. The resolver is therefore a *general*
control-plane name resolver, not coupled to transport config; it must compose with `flint-dial`.

**Out of scope (later sub-projects):** the per-flow router + rule engine (#2), the fake-IP DNS
interception + per-category resolver policy (#3), app-split via platform config (#4), and the actual
config-fetch/HTTP layer. This doc adds **only** un-poisoned name resolution for spark's own startup
dials.

## 3. Design

### 3.1 `spark_core::bootstrap` (feature `bootstrap-dns`)

`flint-dns`'s dial needs the boring Chrome connector, so this lives behind a new `bootstrap-dns`
feature that pulls `flint-dns` with its `boring` feature. The base build is unaffected.

- **`trait NameResolver`** — `async fn resolve(&self, host: &str, port: u16) -> io::Result<SocketAddr>`
  (the first validated address). A trait so the wiring is unit-testable with a fake (no network), each
  resolution *strategy* is one impl, and future callers (proxyless API dialing) depend on the
  abstraction, not a concrete pool.
- **`RacingResolver`** — `resolve`'s public face: holds an ordered set of strategy `NameResolver`s and
  races them happy-eyeballs via the already-public `flint_dial::race_with`, returning the first
  **validated** answer; errors only if every strategy fails.
- **Strategies (each a `NameResolver`):**
  - **`DohResolver`** — wraps `flint_dns::resolve_cached` over `flint_dns::default_pool()` with a held
    `flint_dns::ResolverCache` (per-network winner cache → one-shot steady state). The always-present,
    un-poisoned direct path.
  - **`ProxyResolver`** — given a configured proxy **by IP** (its `UdpTransport`), `dial_udp` a public
    resolver and run a query via `flint_dns`'s codec + answer validation; the exit resolves upstream.
    Added once per IP-addressed proxy. Independent of the data-plane tunnel — it only uses the
    transport client, so it works even when the TUN/netstack isn't running.

**Why exit-resolution is safe here.** The earlier WeChat-locality caveat does *not* apply to
control-plane names: a proxy/API host is reachable infra, not a GeoDNS-sensitive domestic service, so
exit-location answers are fine. Bogon validation still rejects poisoned/sentinel answers on every
strategy. **Chicken-and-egg:** a proxy named *by hostname* can't resolve *itself* through a proxy, so
`DohResolver` is the always-available path and `ProxyResolver` only adds racers when an IP-addressed
proxy exists. A/AAAA selection is v1-simple (A first); richer policy is a follow-up.

### 3.2 `config::Endpoint`

A proxy `server` becomes an `Endpoint` (was `SocketAddr`):

```rust
enum Endpoint { Ip(SocketAddr), Host { host: String, port: u16 } }
```

Custom `Deserialize` from a single string: parses as `IP:port` → `Ip`, otherwise → `Host`. Applies to
the `[transport.anytls]` and `[transport.samizdat]` `server` fields (the boring transports that pair
with the boring-dependent resolver). `Endpoint::Ip` is the default/unchanged path.

### 3.3 Bootstrap phase

Each entry point (`cli::run_tunnel`, `core::fd_tunnel::run_with_handle`, the service daemon) builds
the transport inside an async/tokio context right after loading `Config`. A new step runs there,
**before `transport::from_config`**:

> resolve every `Endpoint::Host` in the config to an `Endpoint::Ip` via the `NameResolver`.

`transport::from_config` stays synchronous and reads the resolved `SocketAddr`. The resolver is
constructed once per startup and reused (its cache persists for the process).

## 4. Data flow

```
load Config (server may be Host)
   → [feature bootstrap-dns] resolve Host → Ip via RacingResolver:
        race( DohResolver(flint pool) , ProxyResolver(each IP proxy) , … ) → first validated
   → Config with IPs
   → transport::from_config  → dial
apps' in-tunnel DNS: unchanged (still tunnelled to the exit)
```

## 5. Error handling

- All resolvers fail → the bootstrap step returns an error and startup fails with a clear
  `couldn't resolve <host>` message. **No silent fallthrough** to a poisoned/system lookup.
- A `Host` is configured but spark was built **without** `bootstrap-dns` → an explicit error at the
  resolve step (`hostname <host> requires the bootstrap-dns feature`), never a silent skip.
- An `Endpoint::Ip` never touches the resolver (works with the feature off).
- Per-network `ResolverCache` keeps steady-state startup to a single dial.

## 6. Testing

- `Endpoint` serde round-trip: `"1.2.3.4:443"` → `Ip`, `"proxy.example.com:443"` → `Host`; junk → error.
- `RacingResolver` (unit, no network, fake strategies): first validated wins; an immediately-failing
  strategy doesn't beat a good one; all strategies fail → error.
- `ProxyResolver` (unit, no network): against a **fake `UdpTransport`** that returns a canned DNS
  response, it parses + validates to the right `SocketAddr`; a bogon answer is rejected.
- Bootstrap phase: resolves `Host → Ip` against a **fake** `NameResolver`; all-fail → the startup
  error; feature-off + `Host` → the explicit feature error.
- Live-gated `#[ignore]` e2e: `DohResolver` resolves a real hostname to a public (non-bogon) IP —
  needs `boring` + network, mirroring `flint-dns`'s own live test.

## 7. Roadmap (context — not built here)

| # | Sub-project | Depends on |
|---|---|---|
| **1** | **Bootstrap / control-plane resolver (this doc)** | flint-dns |
| 2 | Per-flow router + rule config (direct/tunnel/block; IP-CIDR/app rules) | DirectTransport |
| 3 | Fake-IP DNS interception + per-category resolver policy (direct→local/domestic, blocked→resolve-at-exit, bootstrap→flint pool) | 1 + 2 |
| 4 | App-split via platform config (VpnService / NE include-exclude) | — |

Plus the proxyless/fronted **config-fetch** to the API (a consumer of #1's resolver + flint-dial),
its own sub-project.

## 8. References

`getlantern/flint` (`flint-dns`, `flint-dial`, `flint/docs/design.md`); `getlantern/kindling`
(proxyless bootstrap prior art); spark `docs/samizdat-transport-design.md`,
`docs/handshake-gambit-design.md`.
