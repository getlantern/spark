# Config fetch from the Lantern `config-new` endpoint — design (v1)

> Status: design (brainstormed 2026-06-22). Implements the deferred "fetch" half of Phase 3:
> Spark fetches its own config from the Lantern API and feeds it into the `config_raw.json`
> adapter already on `main` (`core::config::lantern`, PR #19). Reference implementations:
> `getlantern/radiance` (the client backend lantern uses) and `getlantern/lantern`.

## 1. Goal & scope

Spark obtains its server pool from the Lantern `config-new` API instead of only a hand-supplied
`config.toml` / `config_raw.json`. v1 is deliberately the smallest shippable slice:

- **Direct fetch only** (real TLS, no domain-fronting). Censored cold-start is the *next* milestone.
- **Anonymous account (free)**: a generated, persisted `device_id` **plus** an anonymous `user_id` +
  `pro_token` minted by `POST /user-create` on first use (persisted, reused). **This corrects the
  original v1 assumption** — config-new is *not* anonymously fetchable: it rejects a request without a
  token (`400 "pro_token is required"`) and one with too low a `version` (`400 "… version … too old"`).
  "pro_token" is a misnomer — every client, free included, gets one from `/user-create`; paid features
  (subscriptions, WireGuard) are layered on later and stay deferred. See §2a.
- We present as a **Lantern client** (`app_name = "lantern"`, a recent `version`, e.g. `9.1.13`) so the
  API accepts us and `/user-create` succeeds; a Spark-specific registered app identity is a later option.
- **Core module; the NE extension self-fetches** on connect (vs today's app-supplied config).
- **Disk-cached**, so startup is fast and offline is survivable.
- The response **is** `config_raw.json` (radiance's `ConfigResponse`) → fed straight into
  `Config::from_config_str` / `config::lantern::from_config_raw_json` (already shipped).
- **Trust = TLS.** Radiance does no signature verification; neither do we (no Ed25519 layer).

## 2. Wire contract (from radiance/lantern)

- **Endpoint**: `POST https://df.iantem.io/api/v1/config-new` (prod), `POST
  https://api.staging.iantem.io/v1/config-new` (staging). Env-selectable; default prod.
  (`radiance/common/constants.go:28`, `radiance/config/fetcher.go:151`.)
- **Request body** (JSON, `getlantern/common.ConfigRequest`, `common/types.go`): we send
  `device_id`, `user_id` (decimal string from `/user-create`), `pro_token` (from `/user-create`),
  `platform`, `app_name:"lantern"`, `backend:"sing-box"` (so the API returns the sing-box-options
  shape our adapter reads), `singbox_version`, `version` (a recent Lantern version — the server
  enforces a floor; `0.1.0` is rejected), `locale`, and
  `protocols:["samizdat","hysteria2","shadowsocks"]` — *only* the kinds our adapter maps, so the API
  doesn't return outbounds we'd skip. `preferred_location` optional. `wg_public_key` omitted (Pro/WG,
  deferred). **`user_id` + `pro_token` are required** (see §2a) — `user_id` is `strconv.ParseInt`-ed
  server-side, so an absent value is a `400`.
- **Request headers** (`radiance/common/headers.go:50`): `X-Lantern-App` (`lantern`), `-App-Version`,
  `-Version`, `-Platform`, `-Device-Id`, `-User-Id`, `-Time-Zone` + `Content-Type: application/json`,
  `Cache-Control: no-cache`, and conditional `If-Modified-Since` / `If-None-Match` from the cache.
  (`pro_token` rides the **body** only — radiance sends no `X-Lantern-Pro-Token` header for config-new.)
  `-Rand` (0–300 random padding chars) is still deferred to the fronting milestone (not required by the
  server — confirmed: its absence didn't cause the 400s; the token + version did).
- **Response**: JSON `ConfigResponse` (`common/types.go:73`) = the `config_raw.json` shape
  (`country`/`ip`/`servers`/`outbound_locations`/`options.outbounds`/`bandit_url_overrides`/
  `poll_interval_seconds`/…). We pass the raw body to the adapter; we do **not** re-model it.
- **Status codes** (`radiance/config/fetcher.go:198`): `200`/`206` → new config; `304`/`204` → no
  change (use cache); other → error.
- **Conditional / ETag**: store the `ETag` response header (the *only* response header radiance reads,
  `fetcher.go:189`) and the last-modified time; send them back as `If-None-Match` / `If-Modified-Since`.
- **Sleep cadence**: there is **no sleep HTTP header**. The server-recommended inter-fetch interval is
  the response **body** field `poll_interval_seconds` (`ConfigResponse.PollIntervalSeconds`), handled
  per `radiance/config/config.go:302-336` (see §6).

## 2a. Account pre-step: `/user-create` (`core::config::fetch::user`)

config-new needs an account, so before the first fetch we mint one (radiance's `ensureUser` →
`account.Client.NewUser`):

- **Endpoint**: `POST https://api.getiantem.org/user-create` (prod), `POST
  https://api.staging.iantem.io/pro-server/user-create` (staging) — a **different host** than config-new.
- **Request**: no body; headers `X-Lantern-App:"lantern"`, `-Version`, `-Platform`, `-Device-Id` (no
  token/user-id yet — that's what we're minting).
- **Response** (200): `{"userId": <number>, "token": "<string>", …}`. We map `userId` (a JSON number)
  → `user_id` decimal string and `token` → `pro_token`.
- **Persistence**: stored in the data dir as `user.json` and reused; created once per device. A
  persisted-but-unusable file (placeholder id / empty token) is treated as absent and re-created.
- **Trust = TLS** (same as config-new). No signature.

This is the one correction to the original design: the "free tier omits `/user-create`" assumption was
wrong — verified live (config-new returns `400 "pro_token is required"` without it). It's a thin slice
of the account surface; the rest (subscriptions, sign-up/login, WireGuard) stays deferred to Pro.

## 3. Components — new `core::config::fetch` module

Reuses what `core` already has — `serde_json` (PR #19), the hand-rolled HTTP/1.1 client in
`core::transport::probe` (extended GET→POST + request headers + status/ETag parsing — **no
`reqwest`/`hyper`**, per the locked stack), and the `boring2`/`tokio-boring2` TLS that
`probe::tls_wrap` already uses (pulled by the `anytls` feature) — not `rustls`, since the fetch dials
through the same boring connector as the probes.

- **`ConfigRequest`** (serde `Serialize`) — the body in §2.
- **header builder** — the `X-Lantern-*` + conditional set in §2.
- **`identity`** — generate a v4 `device_id` once; persist it in the app-group container; reuse.
- **`http`** — a hand-rolled HTTPS `POST` (extends `probe`'s TLS+HTTP): builds request line + headers
  + body, reads status line, `ETag`, and body. Direct dial to the endpoint host. Returns a typed
  `FetchOutcome`.
- **disk cache** — in the app-group container: last-good raw `config_raw.json` + a small
  `config_meta.json` (`etag`, `last_modified`, `fetched_at`, `poll_interval_seconds`).
- **lifecycle** — `fetch_once() -> FetchOutcome { New(String) | NotModified | Error(e) }`;
  `load_cached() -> Option<(raw, meta)>`; `run_loop(ctx)` (§6).

## 4. Data flow (extension self-fetch)

```mermaid
flowchart TD
    start([startTunnel]) --> hasCfg{App supplied an<br/>explicit config?}
    hasCfg -- yes --> useApp[use it: from_config_str<br/>today's behavior] --> up([bring tunnel up])
    hasCfg -- no --> cache{cached<br/>config_raw.json?}
    cache -- yes --> adaptCache[from_config_raw_json] --> up
    up --> loop[[run_loop: refresh + cache]]
    cache -- no --> cold[blocking fetch_once<br/>retry-with-backoff until success<br/>UI: 'fetching config (offline?)']
    cold -- New --> adaptNew[from_config_raw_json + cache] --> up
    loop -. server poll_interval / backoff .-> loop
```

Config resolution gains a source, selected by the config string the app already passes down
(`providerConfiguration["config"]`): a reserved sentinel **`lantern-api`** selects API mode; an
explicit config (TOML / host:port / config_raw) is used as today and takes precedence; an *empty*
config still means "direct / no tunnel" (unchanged — so API mode is opt-in via the sentinel, not the
default). In **API mode**, the cache boots the tunnel immediately and the loop refreshes in the
background, or it cold-fetches if there's no cache. The Swift NE shim passes the app-group container
path into `spark_tunnel_run` as the data dir (the extension can't compute it itself). Note the
extension's own dials egress the real interface by design (loop avoidance), so the refresh is a
**direct** dial in v1 — the *cache* is what makes warm start robust; the fronting milestone hardens
the dial.

## 5. Caching

Atomic-write the raw body to `{data_dir}/config_raw.json` and meta to `{data_dir}/config_meta.json` on
every `200`/`206`. `load_cached` reads both at startup. A `304`/`204`/error never overwrites the cache
(last-good is preserved). The adapter returning `NoSupportedOutbounds`/parse-error on a fetched body is
treated as a failed fetch — not cached.

## 6. Cadence & offline resilience

A single persistent loop (mirrors `radiance/config/config.go:302-336`), running for the life of the
tunnel and **never permanently giving up**:

- **Success → server-dictated sleep.** Sleep `poll_interval_seconds` from the freshly-fetched config
  **body**, clamped to a **≥10s** floor; if absent/0, default **10 min**. The server (bandit) owns the
  steady-state cadence; we never hardcode it.
- **Failure → fast backoff, keep trying.** Offline / DNS failure / connect refused / 5xx / a `304`
  with no cache → quadratic backoff capped at **2 min** (`common.NewBackoff`), retried indefinitely
  until the network returns, then the server cadence resumes on the next success.

**Offline is not terminal.** Warm start boots from cache and refreshes through outages. Cold start with
no cache keeps retrying; connect surfaces a **"waiting for config (offline?)"** state and proceeds the
moment the first fetch succeeds (cancellable; an optional long ceiling may give up with a clear
message, but the default is keep-trying).

**NE readiness gating.** Because the extension fetches config *before* it adopts the utun fd, reporting
the tunnel "up" eagerly would blackhole traffic into an fd nothing is servicing yet. The core exposes a
readiness signal (`fd_tunnel::{mark_connecting, wait_ready}`, C ABI `spark_tunnel_mark_connecting` /
`spark_tunnel_wait_ready`): the provider marks *connecting* before starting the worker, then gates
`completionHandler(nil)` on the data path actually coming up, with a bounded ceiling (30s) after which it
fails the connection cleanly (no blackhole) rather than reporting a dead tunnel. Warm cache comes up in
milliseconds; cold-start-online in a second or two; cold-start-offline fails at the ceiling and the user
retries.

## 7. Error handling (summary)

| Situation | Behavior |
|---|---|
| Warm start, fetch fails / `304` / malformed | keep last-good cache; tunnel runs; backoff-retry |
| Cold start, no cache, offline | not terminal — keep retrying; connect waits, then proceeds on success |
| Fetched body fails the adapter (`NoSupportedOutbounds`/parse) | treat as failed fetch; don't cache |
| `200`/`206` | adapt → cache → (re)build pool; sleep server interval |

## 8. Testing

- **Unit (no network):** `ConfigRequest` + header serialization vs the recorded radiance contract; the
  HTTP request builder + response parsing (`200`→raw, `304`→`NotModified`, errors); cache read/write +
  staleness + ETag/If-Modified-Since round-trip; `device_id` gen/persist; the loop's cadence selection
  (server interval clamp ≥10s, default 10min) and backoff-on-failure. Adapter mapping is already
  covered (PR #19).
- **Integration (manual/staged):** real fetch against **staging** (`api.staging.iantem.io`, proxyless)
  → confirm a pool builds and the tunnel connects; verify `304` on the second poll.

## 9. Deferred — own milestones

- **Fronting / kindling-equivalent** (domain-fronting → AMP → smart → DNSTT): the censored cold-start
  path. A connector swap inside `config::fetch::http` — uses `flint-tls`'s boring Chrome connector + a
  fronted host/SNI list. This is the natural next milestone after v1.
- **Pro tier**: `/user-create`, `user_id`, `pro_token`, the account flow, and WireGuard outbounds.
- **Smart-routing / DNS / ad-block** ingestion from the response (already deferred in the adapter).

## 10. References

- Adapter (merged): `core/src/config/lantern.rs`, `Config::from_config_str` (PR #19).
- Radiance: `config/fetcher.go` (request build + status handling), `config/config.go:302-336` (fetch
  loop, server poll interval clamp, backoff), `common/headers.go` (headers), `common/constants.go`
  (endpoints). `common/types.go` (`ConfigRequest`/`ConfigResponse`).
- Spark: `core/src/transport/probe.rs` (hand-rolled HTTP/TLS to extend), `docs/bootstrap-resolver-design.md`
  (names this fetch as its designed-for consumer).
