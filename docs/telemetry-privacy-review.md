# Telemetry privacy review

> Reviews **every field that leaves a device or a server**, against the rule from #165: aggregate,
> low-cardinality attributes only — *never a destination, client IP, resolver IP, or ConnectionID*.
>
> Required before shipping (#165: "the review should gate the release, not follow it").
> **Date:** 2026-08-07 · **Reviewed at:** `feat/tunnel-process-telemetry`

## Method

Not a reading of the code's intent — an enumeration of what the encoders actually emit, cross-checked
against the tests that hold each claim. Where a claim has no test, that is stated as a residual risk
rather than glossed.

The enumeration is exhaustive by construction: attribute **keys** are a closed set enforced by
`every_emitted_attribute_key_is_from_a_closed_set` over both signals, so anything not listed here
fails the build.

## 1. Client — resource block (attached to every logs and traces payload)

`core/src/diag/otlp.rs::build_resource_attrs`. Names follow `getlantern/semconv`.

| attribute | value | verdict |
|---|---|---|
| `service.name` | constant `"spark"` | ✅ constant |
| `service.version` | build version | ✅ constant |
| `spark.git_sha` | build sha | ✅ constant — the point of the whole exercise (attribute a field report to a build) |
| `client.device_id` | 32 hex chars, randomly generated | ⚠️ **pseudonymous identifier** — see §5.1 |
| `client.platform` | `darwin` / `windows` / `linux` / `android` / `ios` | ✅ low cardinality |
| `geo.country.iso_code` | the **server's** country view of the client | ✅ country granularity only; no precise geolocation, and not derived on-device |
| `deployment.environment.name` | `prod` / `staging` | ✅ constant |
| `spark.component` | `app` / `tunnel` | ✅ constant |
| `os.name`, `os.version`, `host.arch` | platform strings | ✅ low cardinality |

No IP address, no hostname, no network identifier of any kind.

## 2. Client — log records

`build_record`. Attributes are `kind`, `session` when present, and the event's own fields — all keys
from the closed set (37 entries; see the test). Values:

- **Numeric fields** (durations, counts, byte totals, slots) — aggregate by nature. ✅
- **String fields** — every one passes through `DiagEvent::insert_str`, which applies
  `redact::redact_all` (IPv4/IPv6 literals → `[redacted-ip]`, `scheme://…` → `[redacted-url]`).
- **Body** — the `message` field for `kind == "log"`, else the kind string. Same redaction.
- **`session`** — a randomly generated spark session id. Not a user or account identifier.

One key deserves a note on sight: **`target` is the *tracing* target** (a module path such as
`spark_core::config`), **not** a network destination. The name collides with the forbidden class; the
allow-list comment says not to repurpose it.

### 2.1 Performance events (`transport.probe_result`, `proxy.flow_completed`)

These two exist so that *slowness* is measurable. The numbers were already being logged, but the diag
layer forwards only the `message` field and renders the rest into the body string, so latency and
byte counts arrived as prose — readable, but impossible to chart, alert on, or take a percentile of.
All fields but three reuse keys already in the closed set; `protocol`, `member`, and `throughput_bps`
are added to it.

`throughput_bps` is derived on-device from the flow's own duration and byte counts, so it discloses
nothing those two do not — it exists because `p50(duration_ms)` and `p50(bytes_down)` are drawn from
different flows, making their ratio nobody's throughput.

| event | fields | verdict |
| --- | --- | --- |
| `transport.probe_result` | `slot`, `protocol`, `result`, `latency_ms` | ✅ identifies a pool member by **index and protocol**, never by address |
| `proxy.flow_completed` | `duration_ms`, `bytes_up`, `bytes_down`, `bytes_total`, `throughput_bps` | ✅ **no destination** — describes the tunnel, not where the user went |
| `config.race_winner` | `member`, `latency_ms` | ✅ names the winning race member (`direct`, `proxyless`, `fronted-tls`, …), never a host or address |

Two choices are load-bearing:

- **The probe event carries no server label.** The `tracing` line it mirrors prints
  `server="samizdat 1.2.3.4:31464"`; that address is only kept off the wire by the `redact_all`
  backstop. Passing the pool index and protocol instead means there is no proxy address to redact in
  the first place. A hygiene-corpus entry feeds the constructor the log-style label to prove a caller
  reaching for it cannot leak one.
- **The flow event names no destination.** Duration and byte counts answer "is the tunnel slow"
  without recording what was visited, which is the whole reason a destination is in the forbidden
  class.

`proxy.flow_completed` fires once per proxied TCP flow, so it is emitted at `Debug` — a level the
server can switch off (`§C4` capture knob), and one that sampling applies to.

That mitigation did not hold when it was first written, and the gap is worth recording rather than
quietly fixing. The capture knob was enforced only inside `DiagLayer`, which sees `tracing` output;
every structured `events::*` record reaches the sink through `diag::emit` instead, so turning the
level down reduced log lines and left the per-flow events flowing. The claim above was asserted as
the mitigation for the highest-volume event in the system and nothing tested it — in a document
whose Method section promises an enumeration cross-checked against tests rather than a reading of
intent. `emit` now applies the same check (errors still always pass, §C2a). Two tests hold it:
`the_capture_knob_governs_structured_events_and_never_drops_errors` pins the predicate, and
`the_emit_path_applies_the_capture_knob_and_never_drops_errors` drives the emit path itself and reads
the spool — the second exists because the first alone did not catch deleting the guard from `emit`,
which is the same shape of hole as the claim above.

The protocol travels under `protocol` rather than `kind` for an encoding reason worth recording:
`build_record` emits `kind` and `session` itself, as structural attributes, *before* iterating
`fields`. A constructor that also inserts a field by either name puts the key on the wire twice, and
the backend keeps one arbitrarily — so either the event kind or the shadowing field vanishes, with a
well-formed payload either way. The closed-set test cannot see this, since both names are legitimately
in the set as structural keys; `no_constructor_shadows_a_structural_key` covers it instead.

## 3. Client — spans (traces signal)

`encode_spans`. Span `name` is `&'static str` — compile-time constants only. Attributes are the same
closed key set. Span `error` is redacted at construction (`redact_all`). `traceId`/`spanId` are
random per session.

## 4. Server — `dns-tunnel-server`

`dns-tunnel-server/src/otlp.rs`. Nine cumulative `Sum` counters (queries, answers, streams opened,
bytes up/down, backlog drops, sessions swept, undecodable targets, connect timeouts). The only keyed
metric is egress connect failures keyed on `io::ErrorKind`, a closed set. Identity is
`service.name` / `service.version` / `instance`, where `instance` is an **operator-chosen opaque
label**, explicitly never derived from the zone or the host's address.

Held by `every_emitted_attribute_value_is_from_a_closed_set` — the server can close *values* as well
as keys, because everything it emits is aggregate.

**Deliberately not emitted:** per-session spans. A session span is identity-shaped even with no
`target` attribute, because a ConnectionID correlates one user across every row.

## 5. Residual risks

### 5.1 `client.device_id` correlates a device's whole history

It is a random 32-hex value, not derived from hardware, and it is the *same* id the config requests
already use — so it discloses nothing the config plane does not. But it is a stable identifier that
joins every record from one install, which is what makes session reconstruction possible at all.

**Accepted**, because the alternative (a per-session id) makes "did this device recover after the
failure?" unanswerable, which is the question the field-optimization loop exists to ask. Worth
revisiting if retention grows.

### 5.2 A bare hostname in free-form message text would survive redaction

`redact_addrs` matches IP literals; `redact_urls` matches `scheme://…`. Neither matches a bare
hostname (deliberately — a hostname is not distinguishable from an ordinary word by shape).

**Mitigated, not eliminated.** The defences are structural rather than lexical: constructors are
typed and take no destination parameter; the key set is closed, so a `destination` field cannot be
added without failing a test; and `every_constructor_is_covered` stops the corpus from silently
falling behind. What remains is a developer putting a hostname into a *message string* — which the
`log` bridge would carry. This is the one place the rule still rests partly on care, and it should be
stated plainly rather than claimed as solved.

### 5.3 The embedded ingestion key is extractable

Inherent to embedding (§`config::lantern::embedded_otel`). A SigNoz ingestion key is **write-only**:
the exposure is junk telemetry and quota spend, never disclosure of collected data. Bounded by using
a **throwaway key separate from the Go services'**, so an extracted spark key cannot pollute
`radiance`/`flashlight`/`api`. Not rotatable without a release.

## 6. Consent

One shared gate for every host (#168): `diag::diagnostics_enabled()`. Diagnostics are **on by
default with a documented decline** (`SPARK_DIAGNOSTICS=off`), and the disclosure is the product
surface. A declining user reaches no sink, no files, and no uploader.

⚠️ **Known limitation, unchanged by this work:** `SPARK_DIAGNOSTICS` is an environment variable, so
on the tunnel-process hosts "declined" means whoever launched the process, not necessarily the person
using it. The app's user-facing toggle is plumbed for the Tauri app (`persist::load_diagnostics_enabled`)
but not through `providerConfiguration` to the Apple NE. **That remains open (#165), and is the one
consent gap a reader should not take this document as closing.**

## Verdict

**Cleared to ship** on the data-flow question: nothing enumerated above is a destination, client IP,
resolver IP, or ConnectionID, and the two properties that keep it that way (closed key set, typed
constructors) are enforced by tests over both signals rather than by review.

Two items are *not* cleared by this document and are tracked separately: the `providerConfiguration`
consent plumb (§6), and minting the throwaway ingestion key before the embedded path carries traffic
(§5.3).
