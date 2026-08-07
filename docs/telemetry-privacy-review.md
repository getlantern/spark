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
from the closed set (32 entries; see the test). Values:

- **Numeric fields** (durations, counts, byte totals, slots) — aggregate by nature. ✅
- **String fields** — every one passes through `DiagEvent::insert_str`, which applies
  `redact::redact_all` (IPv4/IPv6 literals → `[redacted-ip]`, `scheme://…` → `[redacted-url]`).
- **Body** — the `message` field for `kind == "log"`, else the kind string. Same redaction.
- **`session`** — a randomly generated spark session id. Not a user or account identifier.

One key deserves a note on sight: **`target` is the *tracing* target** (a module path such as
`spark_core::config`), **not** a network destination. The name collides with the forbidden class; the
allow-list comment says not to repurpose it.

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
