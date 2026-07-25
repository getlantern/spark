# Spark Diagnostics & Telemetry — Design

> **Status: v4 — approved; Phase A implemented (PR #91).** Privacy-sensitive and
> outward-facing: the §1 constraints are binding on any future change to this design.
>
> **v2 (2026-07-17):** destination switched to SigNoz via OTLP/HTTP, per author direction:
> optimize for continuous automated self-improvement; over-report during testing; version
> metadata on every batch.
> **v3 (2026-07-17):** report **exactly where radiance reports, keyed exactly the way
> radiance keys** (author direction): endpoint + auth headers arrive in the config
> response's existing `otel` block; gate on `features["otel.*"]`; attributes follow
> `getlantern/semconv`. This drops v2's invented `diagnostics` config block.
> **v4 (2026-07-17):** author refinements: (a) **unexpected-error capture is first-class**
> (§C2a: panic hook, ERROR bypasses sampling/eviction, expedited flush); (b) add a
> **scoped traces signal** for timing waterfalls (§C3a), riding the existing
> `features["otel.traces"]`; (c) an **unconditional local backup log**, written
> regardless of server config (§C2).
>
> **Date:** 2026-07-17 · **Branch context:** `fisk/unbounded-volunteer`

## 1. Goal

During the Unbounded testing phase, give ourselves **maximum visibility into what's
happening on users' devices** — automatically, without users submitting anything — so we
can diagnose failures and drive toward **automated remediation and continuous
self-improvement**. Built for Unbounded first, as a **reusable, app-wide** substrate.

**Non-negotiable constraints (this is outward-facing telemetry):**
- Default-on during testing, but **remotely killable** and **locally opt-out-able**.
- **No PII, no content, no secrets, no precise geolocation** ever leaves the device.
- Zero data-path impact (perf is Lantern's #1 hotspot).
- **Over-report on volume, never on sensitivity** (testing-phase posture).
- **Unexpected errors are never lost:** panics and ERROR-level events bypass sampling and
  ring eviction and get an expedited upload path (§C2a).

## 2. Reference implementation: radiance

Radiance already reports client telemetry to SigNoz; Spark copies its mechanism exactly
(`radiance/telemetry/otel.go`):

1. **The config response carries a top-level `otel` block** (`getlantern/common` `OTEL`):

   ```go
   type OTEL struct {
       Endpoint         string            `json:"endpoint,omitempty"`     // prod default: ingest.us.signoz.cloud:443
       Headers          map[string]string `json:"headers,omitempty"`      // ingestion key lives HERE, server-set
       TracesSampleRate float64           `json:"sample_rate,omitempty"`
       MetricsInterval  int               `json:"metrics_interval,omitempty"`
   }
   ```

   lantern-cloud emits it (`cmd/api/config.go:601-603`, `otelConfig` at `:746`) when
   `features["otel.traces"]` or `features["otel.metrics"]` is enabled; endpoint and
   headers come from server settings (`otel_endpoint`, `otel_headers`). **The key is
   never embedded in a client** — it's config-delivered and rotatable server-side.
2. **Client-side gating:** radiance initializes each signal only if its feature flag is
   on (`common.TRACES = "otel.traces"`, `common.METRICS = "otel.metrics"`), and skips
   everything if `Endpoint == ""`.
3. **Attributes follow `getlantern/semconv`** (per radiance's standing rules):
   `service.name`, `service.version`, `deployment.environment.name`, `os.name`,
   `os.version`, `host.arch`, `geo.country.iso_code`, `client.device_id`,
   `client.platform`, `client.is_pro`, locale/timezone.
4. Radiance exports OTLP/**gRPC** (traces + metrics signals only — no logs).

**Spark deltas from radiance (the only two):**
- **Wire protocol: OTLP/HTTP JSON instead of gRPC.** Spark's locked stack has no gRPC.
  Same destination: SigNoz Cloud ingest serves both gRPC and HTTP on the same
  host:443 — `https://ingest.us.signoz.cloud/v1/logs`, headers passed verbatim from the
  config block. *(Verify OTLP/HTTP-JSON acceptance with one live test at implementation.)*
- **Signal: logs.** Spark's diag stream is a logs signal, which radiance doesn't emit.
  Add `common.LOGS = "otel.logs"` beside TRACES/METRICS in `getlantern/common`, include
  `|| featureEnabled(common.LOGS)` in lantern-cloud's OTEL-emission condition
  (`config.go:601`), and gate Spark's uploader on that flag. Two one-line server-side
  changes; everything else is pure reuse. (Spark's **traces** signal (§C3a) needs no
  server change at all — it rides the existing `otel.traces` flag + `sample_rate`,
  exactly as radiance.)

## 3. What Spark already has (assemble, don't build)

| Need | Existing primitive | Where |
|------|-------------------|-------|
| Instrumentation | `tracing` everywhere + a lossy capture `Layer` | `service/src/logbus.rs` (`LogForwarder`) |
| Privacy backstop | IP-literal redaction | `core/src/redact.rs` (`redact_addrs`) |
| Upload transport | raw TLS POST, no reqwest/hyper | `core/src/config/fetch/http.rs` (`post_collect`) + `tls_wrap` |
| Device identity | stable pseudonymous id (same one radiance reports) | `core/src/config/fetch/` (`device_id`) |
| **`otel` block already delivered** | spark's adapter currently passes it through untouched | `core/src/config/lantern.rs:361` — just parse it |
| Backend | **the existing SigNoz** (radiance + lantern-box proxies already report there) | no new backend |
| **Remediation channel** | the config-fetch **response** (remote knobs, every ≤10 min) | `core/src/config/fetch/mod.rs` (`run_loop`) |

The closed self-improvement loop:

```
build N on devices ──diag──► SigNoz ──queries (Claude MCP / dashboards / alerts)──► diagnosis
        ▲                                                                              │
        │                                                                              ▼
   build N+1 ships ◄── fix ◄──────────────────────────────────────────────────── pattern found
        │
        └── same SigNoz query filtered by service.version verifies the fix landed
```

Plus per-device remediation without a release: flip a config knob → device applies it on
its next config fetch (≤10 min).

## 4. Architecture

```
  [tracing DEBUG+ (spark targets) / INFO+ (rest)]     [diag!(...) structured events]
        │                                                        │
   DiagLayer ────────────┐                     ┌─────────────────┘
   (redacts, tags)       ▼                     ▼
                      ┌─────────────┐        ┌────────────────────────┐
                      │  DiagSink   │──ring──►│ in-memory bounded ring │ (lossy, counts drops)
                      │  (§C2)      │──spool─►│ diagnostics.jsonl      │ (upload queue, survives restart)
                      │  errors→§C2a│──file──►│ diag.log (+ .1)        │ (unconditional local backup)
                      └─────────────┘        └────────────────────────┘
                                                        │
                    gate (§C4): config `otel` block + features["otel.logs"] + local opt-out
                                                        │
                                                        ▼
                                     ┌────────────────────────────────┐
                                     │ Uploader (§C3)                 │
                                     │ OTLP/HTTP JSON, gzip'd batch   │  hand-rolled envelope,
                                     │ POST https://{otel.endpoint}   │  tls_wrap + post_collect
                                     │      /v1/logs + /v1/traces     │  (no OTel SDK, no reqwest)
                                     │ + otel.headers verbatim        │
                                     └────────────────────────────────┘
                                                        │
                                                        ▼
                                SigNoz ──► queries/dashboards/alerts ──► config knob (remediation)
```

### C1. Diagnostic event model — `core/src/diag/` (new module)

Two capture sources, one typed record, one sink.

```rust
/// One diagnostic record. `ts` is unix-millis (SystemTime::now; SigNoz records receipt
/// time as the trusted clock). `kind` is a stable dotted namespace
/// ("unbounded.peer_connected", "config.fetch_failed", "log"). `session` correlates a
/// flow's events. `fields` is the redacted structured payload.
#[derive(Debug, Clone, Serialize)]
pub struct DiagEvent {
    pub ts: u64,
    pub level: DiagLevel,          // Error | Warn | Info | Debug
    pub component: &'static str,   // "app" | "tunnel" | "unbounded"
    pub kind: &'static str,        // dotted, stable — the schema key
    pub session: Option<String>,   // session_id for correlated flows
    pub fields: BTreeMap<String, serde_json::Value>,
}
```

- **Source A — existing logs, for free.** A `DiagLayer` (`tracing_subscriber::Layer`,
  modeled line-for-line on `logbus::LogForwarder`) captures **DEBUG+ for `spark_*`
  targets and INFO+ for everything else** (over-report posture), turns each event into
  `DiagEvent{kind:"log", fields:{message, target, level}}`, runs `message` through
  `redact_addrs`, and hands it to the sink. The entire existing log surface with **zero
  new instrumentation**.
- **Source B — new structured events.** A `diag!(kind, session?, { field: value, … })`
  macro builds a `DiagEvent`, runs every string-valued field through `redact_addrs`,
  enforces the per-kind field allowlist (§C5), and hands it to the sink. Used by the
  Unbounded timeline (§C6), config-fetch outcomes, and stall/quarantine events — it
  carries **structured** data, queryable in SigNoz without regex.

Why not force everything through `tracing`? `tracing`'s `Visit` API only cleanly yields
the formatted `message` (see `MessageVisitor` in logbus.rs) — extracting arbitrary typed
fields is clunky. A dedicated `diag!` is cleaner for structured events; the `DiagLayer`
still harvests the whole `tracing` stream so nothing is lost.

### C2. Capture / buffering — `DiagSink`

- **In-memory bounded ring** (`~4000` events — sized for the DEBUG+ posture; logbus uses
  256 for a live UI stream, we want a rich recent window). Lossy on overflow: drop oldest
  and increment a `dropped` counter that is itself emitted as `diag.buffer_dropped`
  (fills the "dropped events" blind spot).
- **Append-only spool** `diagnostics.jsonl` in the app's `app_config_dir()`
  (macOS `~/Library/Application Support/org.getlantern.spark/`; the plugin already
  resolves this in `unbounded.rs:44`). Size-capped with single-file rotation
  (`.jsonl` → `.jsonl.1` at ~4 MB). The spool is what makes "we get them without users
  submitting" durable: events survive a crash/restart and upload on next launch.
- **Unconditional local backup log.** Independent of the upload path, every event is also
  appended to `diag.log` (same JSONL encoding, same redaction; rotated to `diag.log.1` at
  ~5 MB) in `app_config_dir()` — **written regardless of the server's `otel` config or
  upload health**. It never leaves the device on its own; it exists so a broken upload
  path (or a disabled cohort) still leaves something a tester can hand over, and for
  local debugging. Only the local opt-out disables it.
- **Never blocks a hot path.** Push is a lossy `try_send`, exactly like
  `LogForwarder::on_event`'s `tx.try_send`.
- **Hard disk-footprint bound.** Every local file is size-capped with a single rotation
  generation (never a `.2`): spool 4 MB + `.1` 4 MB, backup log 5 MB + `.1` 5 MB —
  **worst-case ≈ 18 MB total** (plus a transient ≤4 MB take-file during an upload batch),
  and that worst case only occurs when uploads fail for an extended period at full DEBUG
  volume. Steady state is a few MB because the spool truncates on every successful
  upload. Oldest data is dropped at rotation, by design.

### C2a. Unexpected-error capture (first-class — never lose an error)

Errors are the highest-value records; they get stronger guarantees than the rest of the
stream:

- **Always captured, never sampled.** ERROR-level events bypass `sample_rate` and any
  `capture`-level filtering — sampling only thins INFO/DEBUG volume.
- **Never evicted.** Errors skip the lossy ring: they are written **synchronously to the
  spool** (and backup log) at emit time, so a crash right after the error still preserves
  it for next-launch upload.
- **Expedited upload.** An ERROR triggers a debounced flush (~5 s) instead of waiting for
  the 60 s tick.
- **Panics.** `std::panic::set_hook` (installed per process) writes
  `error.panic {message, location}` straight to the spool before the process dies —
  uploaded on next launch. The hook chains to the previous hook and must never panic
  itself.
- **Unclean exits.** A session marker (`diag.session`, armed at diagnostics init,
  heartbeat-refreshed ~every minute, removed on clean exit) catches the crash classes
  the panic hook can't see — segfault, OOM kill, watchdog, `kill -9`. A leftover
  marker at the next launch emits
  `error.unclean_exit {prev_started_ms, prev_last_alive_ms, prev_version}` through
  the error fast path.
- **Task failures.** Supervision points that `await` a `JoinHandle` emit
  `error.task_failed {task, error}` on join errors instead of silently dropping them.
- **Stray stderr.** Remaining `eprintln!` sites (e.g. the unbounded `total_helped`
  persist failure) convert to `tracing::error!` so they enter the pipeline.
- **Webview errors.** A `window.onerror` + `unhandledrejection` handler in the Svelte
  shell forwards `error.webview {message, source}` through a plugin command — UI-side
  failures are otherwise invisible.
- **Stable error taxonomy.** `error_kind` fields use enum-derived names
  (`PeerProxyError`/`EgressError`/`RelayError`/`SignalingError` variants), so SigNoz can
  group and count unexpected errors by kind and build.

### C3. Uploader — hand-rolled OTLP/HTTP into the radiance endpoint

A background `tokio` task. Triggers: periodic (default 60 s), ring high-watermark, or
Unbounded session end (flush a session's timeline promptly).

- **Destination + auth: verbatim from the config `otel` block** — POST to
  `https://{otel.endpoint}/v1/logs` with every `otel.headers` entry attached as an HTTP
  header (that's the ingestion key, exactly as radiance passes `cfg.Headers` to its
  exporters; CRLF-stripped via the existing `header_safe`). Nothing hardcoded; the server
  rotates the key by changing `otel_headers`.
- **Wire format: OTLP/HTTP JSON logs** (`Content-Type: application/json`,
  `Content-Encoding: gzip`). The envelope (`resourceLogs → scopeLogs → logRecords`) is
  hand-rolled with `serde_json` (~100 lines). **No OTel SDK on-device** — locked stack
  and binary-size constraints hold.
- **Resource attributes — `getlantern/semconv` names**, so Spark records are
  query-compatible with radiance's ("version number for each set of logs" requirement):
  - `service.name = "spark"`, `service.version` = app version,
    `deployment.environment.name` (prod/staging),
  - `client.device_id` (the config-fetch `device_id` — the same id radiance reports),
    `client.platform`, `geo.country.iso_code` (from the config response's country,
    as radiance does — never client-measured),
  - `os.name`, `os.version`, `host.arch`,
  - `spark.git_sha` = build-time git SHA (custom key, injected by `build.rs`),
    `spark.component` (`app`/`tunnel`).
- Each `DiagEvent` → one `logRecord`: `timeUnixNano`, `severityNumber/Text` from level,
  `body` = message (for `kind:"log"`) or the `kind` string, and `attributes` = `kind`,
  `session`, plus the flattened `fields`.
- **Transport:** existing raw-TLS machinery — resolve, `DirectTransport::dial`,
  `tls_wrap`, `post_collect`. Direct-only in Phase A (see §5 censorship note).
- On `2xx`: truncate the uploaded prefix of the spool. On failure: keep the spool and
  back off (reuse the quadratic `backoff(n)`, ≤2 min). Upload failure must never crash
  anything, matching `run_loop`'s "never returns an error" discipline.
- **Verify at implementation (live test):** SigNoz Cloud ingest accepts OTLP/HTTP JSON
  on the same `ingest.us.signoz.cloud:443` host radiance uses for gRPC. If JSON is
  rejected, fall back to OTLP/HTTP **protobuf** via `prost` (ask before adding the dep —
  locked stack).

### C3a. Traces — scoped spans for timing waterfalls

Logs answer *what happened*; traces answer *where the time went*. We add a **small,
deliberate set of spans** (not instrument-everything), hand-rolled the same way as logs
(`POST /v1/traces`, `resourceSpans → scopeSpans → spans`; 16-byte trace ids / 8-byte span
ids from `ring::rand::SystemRandom`, already a core dep):

- **Unbounded session** — a root span per session (the whole session shares one trace),
  child spans: `signaling`, `ice_gathering`, `nat_traversal`, `relay` (the long-lived
  data phase). The SigNoz waterfall then *shows* where a slow connect went.
- **Config fetch** — a root span per fetch, one child span per avenue
  (direct/fronted/scanned) with outcome — makes the race visible.
- **Log↔trace correlation:** session-scoped `DiagEvent`s set the OTLP `logRecord`
  `traceId`/`spanId` fields, so SigNoz links a session's logs to its trace.

Gating: the **existing** `features["otel.traces"]` flag + `otel.sample_rate` — exactly
radiance's client-side contract, zero new server work. Spans that end in an error status
follow the §C2a rule and bypass sampling.

### C4. Gate / kill switch (default-OFF ⇒ strictly opt-in)

> **REVISED 2026-07-25 — diagnostics are default-OFF and strictly opt-in.** This section originally
> specified default-on ("so the opt-out switch is load-bearing"). Reversed as a product decision:
> Spark's users include people in surveilled jurisdictions, and an Unbounded volunteer's diagnostics
> describe sessions they relayed **for censored users**, so nothing is reported until the user
> explicitly turns it on. Concretely: `persist::load_diagnostics_enabled` now fails closed (only an
> exact `"true"` enables it); turning it off **erases the local spool and backup log** rather than only
> stopping future writes; and the peer session id on `unbounded.*` events is replaced by a per-run
> pseudonym so diagnostics can't be joined against signaling into
> (censored user ↔ volunteer ↔ time). The server-side kill switch and the empty-endpoint rule below are
> unchanged — the local setting is now the *primary* gate rather than a secondary opt-out.

Reuse radiance's gating verbatim, extended by one flag for the logs signal:

1. **Server-side flag `features["otel.logs"]`** (new `common.LOGS` constant beside
   `TRACES`/`METRICS`; lantern-cloud emits the OTEL block when it's on —
   `config.go:601` gains `|| featureEnabled(common.LOGS)`). Flipping it off fleet-wide
   takes effect on the next config poll (≤10 min), no build. **This is the kill switch**,
   and rotating `otel_headers` server-side revokes the key.
2. **`otel.endpoint` empty/absent ⇒ everything off** — exactly radiance's
   `if configResponse.OTEL.Endpoint == "" { skip }`. No endpoint, no upload path.
3. **Local opt-out** — a persisted setting (and `SPARK_DIAGNOSTICS=off` env for dev).
   Even a testing-cohort user can turn it off.

Volume knobs, all server-side: `otel.sample_rate` (per-**device** hash vs rate, so a
sampled-in device reports *complete* sessions; testing = 1.0) and a `capture` level knob
(reuse `sample_rate`'s delivery path; testing = debug). Sampling and capture level never
drop errors (§C2a). Spark parses the `otel` block in `core/src/config/lantern.rs` (today
it passes through untouched — `lantern.rs:361`).

These gates govern **upload and collection volume**; the **local backup log (§C2) is
server-independent** and governed only by the local opt-out.

### C5. Privacy scoping (over-report on volume, never on sensitivity)

**Never emitted (deny-list, enforced in code + code review):**
- Raw IPs (backstopped by `redact_addrs` on every string field), destination
  hostnames / SNI / URLs, DNS queries, any session payload or byte content.
- Account tokens, `pro_token`, PSKs, keys, anything from `config_raw.json` (live
  secrets — the diag path must never read it).
- File paths containing usernames; precise geolocation (no lat/lon, no city).

**Allowed (allow-list):**
- `client.device_id` — **the same pseudonymous id radiance already reports to SigNoz**
  and the config API already receives. Not new identity exposure; it's what lets
  remediation target a device and lets queries follow one device across builds.
- App version / git SHA / platform / locale, event `kind` + timings, error taxonomy
  strings, aggregate counters (bytes/sessions from `MetricsSnapshot`), protocol names,
  WebRTC ICE candidate **types** (`host`/`srflx`/`relay` — never the addresses),
  **country-level** geo only (`geo.country.iso_code`, as radiance; for Unbounded peer
  regions reuse the `GeoResolver` country granularity, never finer).
- **Per-kind field schema (allowlist).** `diag!` rejects fields not declared for that
  `kind`; the declared set is reviewed for privacy. Freeform strings are always
  `redact_addrs`'d even inside allowlisted fields.

**device_id keying — the deliberate trade-off.** Correlating rich behavioral telemetry
with a stable id is more sensitive than a bare config fetch, but automated remediation
and cross-build comparisons *require* it — and it matches what radiance already does
(`client.device_id` is a standard attribute on its traces/metrics). Bounded by: SigNoz
retention, no cross-device linkage, and the three kill switches. A conscious decision,
not an accident.

### C6. The Unbounded diagnostic timeline (fills the identified blind spots)

Per-session structured events keyed by `session_id`, emitted from the plugin's
aggregation loop (`gui-tauri/tauri-plugin-spark-vpn/src/unbounded.rs`) and `spark-sharing`:

| Event `kind` | Fields | Blind spot it fills |
|---|---|---|
| `unbounded.attempt_started` | `slot` | — |
| `unbounded.ice_gathering` | `candidate_types:[host,srflx,relay]`, `count` | NAT-type visibility (no addresses) |
| `unbounded.peer_connected` | `session_id`, `nat_traversal_ms`, `selected_pair_type`, `peer_region` | **NAT traversal time** |
| `unbounded.throughput_sample` | `session_id`, `bytes_up`, `bytes_down`, `interval_ms` | **per-peer throughput** |
| `unbounded.peer_disconnected` | `session_id`, `duration_ms`, `bytes_total`, `reason` | session outcomes |
| `unbounded.attempt_failed` | `slot`, `error_kind` | error taxonomy (`PeerProxyError`/`EgressError`/`RelayError`/`SignalingError`) |
| `unbounded.geo_failed` | `reason` | **silent geo failures** |
| `unbounded.pool_snapshot` | `active_peers`, `slots_filled`, `total_helped` | steady-state health |
| `unbounded.signaling` | `state`, `latency_ms`, `error_kind?` | Freddie signaler visibility |
| `config.fetch_outcome` | `result`, `avenue` (direct/fronted/scanned), `latency_ms` | config-delivery health |
| `diag.buffer_dropped` | `count` | **dropped diag events** |
| `diag.lock_poisoned` | `site` | **lock poisoning** (the `lock_recover` sites) |
| `error.panic` / `error.task_failed` / `error.webview` | `message` + `location`/`task`/`source` | **crashes & silent failures** (§C2a) |
| `error.unclean_exit` | `prev_started_ms`, `prev_last_alive_ms`, `prev_version` | **non-panic crash classes** (segfault/OOM/watchdog/kill — §C2a sentinel) |
| `diag.config_applied` | `knob`, `value` | confirms remediation landed (§C7) |

With SigNoz these become directly chartable: NAT-traversal p50/p95 by version, error-kind
breakdown by build, throughput by region.

### C7. Analysis + automated remediation (SigNoz is the backend)

- **Analysis:** SigNoz queries, dashboards, and alerts over the ingested logs — plus the
  Claude SigNoz MCP access that already exists in our tooling, which is what makes the
  loop *automated*: query the fleet → find the failure pattern → fix → ship → verify the
  fix with the same query filtered by `service.version` / `spark.git_sha`.
- **Per-device remediation** rides the config-new response (no new channel): flip a knob
  for a device exhibiting a bad pattern (e.g. "disable unbounded on device X",
  "deprioritize protocol Y" — the server-driven cousin of the existing stall-quarantine).
- **Safety rails:** config only, **never code**; knobs must be **bounded, reversible,
  rate-limited, and logged**; the device emits `diag.config_applied` so the fix is
  verifiable in SigNoz.

## 5. Process model & censorship note

Unbounded runs **unprivileged, in the Tauri app process** (outbound-only WebRTC/QUIC).
The tunnel runs privileged (macOS NE sysext / Windows-Linux `spark-service`).

- **Per-process sinks:** each process runs its own `DiagSink` + uploader, tagging
  `spark.component`; SigNoz merges by `client.device_id`. No new IPC. **v1 needs only
  the app-process sink** (Unbounded lives there); the tunnel-process sink is Phase B.
- **Censorship:** Phase A uploads are **direct TLS only** — matching radiance, and fine
  because Unbounded volunteers are by definition *uncensored* users. When Phase B extends
  diagnostics to censored-user populations, add the fronted race
  (`FrontedTlsDialer`/`FrontedBootstrap`, exactly as config-fetch does) pointing at a
  fronted ingest proxy. The v1 code keeps the transport pluggable so this is additive.

## 6. Phasing (each phase independently shippable)

- **Phase A — Unbounded, app-process (the immediate ask).**
  - Spark: `core/src/diag/` (`DiagSink` ring + spool + backup log, `diag!` macro,
    `DiagLayer`), unexpected-error capture (§C2a: panic hook, error fast-path,
    `eprintln!` conversion, webview handler), the Unbounded timeline (§C6),
    Unbounded-session + config-fetch traces (§C3a), parse the `otel` block in
    `lantern.rs`, the gate (§C4), the OTLP/HTTP uploader (§C3, logs + traces), privacy
    allowlist (§C5), `build.rs` git-SHA injection.
  - Server: add `common.LOGS = "otel.logs"` (getlantern/common) + the one-line emission
    condition in lantern-cloud `config.go:601`; enable the flag + `otel_headers` for the
    testing cohort.
  - One live end-to-end verify (upload → queryable in SigNoz) + a starter dashboard for
    the §C6 timeline.
- **Phase B — app-wide.** `DiagLayer` + uploader on the tunnel process; instrument
  stall/quarantine, protocol selection; fronted ingest path for censored users.
- **Phase C — automated remediation.** Alert-driven per-device config knobs with the §C7
  safety rails; `diag.config_applied` verification loop.

## 7. Testing

- **Redaction:** property test that no serialized `DiagEvent` (and no OTLP batch)
  contains an IP literal (feed addresses through every field; extend `redact.rs`'s test
  style).
- **Gate:** flag off / endpoint absent / local opt-out each independently suppress both
  collection and upload; `sample_rate` hashing is stable per device.
- **Sink:** ring drops oldest + counts under overflow; spool rotates at cap; spool
  survives a simulated restart and uploads.
- **OTLP envelope:** golden-file test of the JSON encoding (semconv resource attrs incl.
  `service.version`/`client.device_id`, severity mapping, attribute flattening);
  duplex-pipe `post_collect` test (2xx truncates spool; 5xx retains + backs off),
  mirroring `config/fetch` tests.
- **Config parsing:** `lantern.rs` maps the `otel` block (endpoint/headers/sample_rate)
  and the `otel.logs` feature flag.
- **Timeline:** a scripted `SupervisorEvent` sequence produces the expected `kind` stream
  with correct `session` correlation and no addresses.
- **Allowlist:** `diag!` with an undeclared field is rejected (compile-time if
  macro-based, else a test).
- **Error fast-path:** a panic in a child test process leaves `error.panic` in the spool
  (subprocess test); ERROR events land in the spool even with the ring full and with
  `sample_rate 0.0`; the expedited flush debounces bursts.
- **Traces:** golden-file test of the OTLP trace envelope; a session's logs carry the
  session's `traceId`; span parentage matches the §C3a shape.
- **Backup log:** written when the server gate is off; rotates at cap; disabled only by
  local opt-out.
- **Live (ignored, like `live_fetch`):** one end-to-end OTLP/HTTP JSON upload to the
  radiance endpoint, verified queryable in SigNoz.

## 8. Open decisions (made with rationale — flag any you'd change)

1. **Destination + key = radiance's, verbatim** (author-directed): the config `otel`
   block delivers `endpoint` (prod default `ingest.us.signoz.cloud:443`) and `headers`
   (the ingestion key), server-rotatable; attributes follow `getlantern/semconv` so Spark
   and radiance are cross-queryable.
2. **Wire protocol = OTLP/HTTP JSON** (radiance uses gRPC; Spark's locked stack has no
   gRPC). Same host:443. *(Live-verify JSON acceptance; protobuf fallback via `prost` if
   needed — would ask before adding the dep.)*
3. **Logs gate = new `features["otel.logs"]`** mirroring `otel.traces`/`otel.metrics`
   (radiance has no logs signal). Two one-line server-side changes.
4. **Version metadata = OTel resource attributes on every batch** (`service.version` +
   `spark.git_sha` + `client.device_id` + platform) — the self-improvement primitive.
5. **Key on `client.device_id`** — the id radiance already reports. *(Required for
   remediation + cross-build correlation; bounded by retention + kill switches.)*
6. **Over-report posture:** DEBUG+ (spark targets) capture, `sample_rate 1.0`, full §C6
   timeline from day one; `sample_rate`/capture level are remote knobs to dial back
   without a release.
7. **Direct-only upload in Phase A; fronted path deferred to Phase B.** *(Matches
   radiance; volunteers are uncensored by definition; transport kept pluggable.)*
8. **Two per-process uploaders, merged in SigNoz by device id; v1 = app process only.**
   *(No new IPC.)*
9. **Unexpected errors are un-droppable** (§C2a): bypass sampling + ring, synchronous
   spool write, expedited flush, panic hook, task-failure + webview capture.
   *(Author-directed emphasis.)*
10. **Traces: yes, scoped** (§C3a) — Unbounded session + config fetch only, on the
    existing `otel.traces` flag; logs remain the primary firehose. *(Waterfalls justify
    the small extra envelope; instrument-everything does not.)*
11. **Unconditional local backup log**, server-independent, disabled only by local
    opt-out. *(Author-directed: a broken upload path must not mean data loss.)*

## 9. Explicitly out of scope

- On-device analysis/ML; the OTLP **metrics** signal (logs + the scoped §C3a traces cover
  the testing phase; radiance-style metrics can come later if query cost bites).
- Real-time streaming (batched, ≤60 s latency — fine for debugging).
- User-facing diagnostics UI ("view/export my logs") — possible later; the ask is
  *automatic* collection.
- Replacing the logbus live-log IPC stream (that's the in-app dev log viewer; this is the
  off-device pipeline — they coexist).
