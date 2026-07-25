# Spark Diagnostics Phase A Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps
> use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Default-on client diagnostics for the Unbounded testing phase: capture structured events + logs on-device (ring/spool/backup-log), upload OTLP/HTTP JSON logs + scoped traces to the radiance SigNoz endpoint using the config-delivered `otel` block, with first-class unexpected-error capture.

**Architecture:** New `core/src/diag/` module (sink + typed events + OTLP encoder + uploader), a `tracing` capture layer modeled on `service/src/logbus.rs`, config plumbing through `core/src/config/lantern.rs`, wiring + Unbounded instrumentation in `gui-tauri/tauri-plugin-spark-vpn`, and a webview error bridge + opt-out toggle in the Svelte UI. Spec: `docs/superpowers/specs/2026-07-17-spark-diagnostics-design.md`.

**Tech Stack:** Rust (tokio, serde_json, ring, rustls via existing `tls_wrap`/`post_collect` — NO new deps without asking; NO gzip in v1, revisit if batches exceed ~256 KB), Tauri v2 plugin, Svelte 5.

**Branch:** `fisk/unbounded-diagnostics` (off `fisk/unbounded-volunteer`).

**Global conventions for every task:**
- TDD: write the failing test, run it (`cargo test -p spark-core diag`), watch it fail, implement, watch it pass.
- After each task: `cargo fmt --all && cargo clippy --all-targets -- -D warnings` in the touched workspace (root workspace for `core/`; `gui-tauri/src-tauri` workspace for the plugin — check both when core APIs change, per the whole-workspace rule).
- Commit per task with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- NEVER read or reference `config_raw.json` contents in diag code paths (live secrets).
- All diag code must be non-fatal: any I/O error inside diag logs at debug and continues.

---

### Task 1: `DiagEvent` model + JSONL serialization

**Files:**
- Create: `core/src/diag/mod.rs`
- Modify: `core/src/lib.rs` (add `pub mod diag;`)

- [ ] **Step 1: Write failing tests** in `core/src/diag/mod.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_serializes_to_stable_jsonl_shape() {
        let mut ev = DiagEvent::new(DiagLevel::Info, "app", "unbounded.peer_connected");
        ev.session = Some("sess-1".into());
        ev.fields.insert("nat_traversal_ms".into(), 812u64.into());
        let line = ev.to_jsonl();
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["kind"], "unbounded.peer_connected");
        assert_eq!(v["level"], "info");
        assert_eq!(v["component"], "app");
        assert_eq!(v["session"], "sess-1");
        assert_eq!(v["fields"]["nat_traversal_ms"], 812);
        assert!(v["ts"].as_u64().unwrap() > 1_700_000_000_000);
        assert!(!line.contains('\n'), "JSONL: one line per event");
    }

    #[test]
    fn string_fields_are_ip_redacted_on_insert() {
        let mut ev = DiagEvent::new(DiagLevel::Error, "app", "log");
        ev.insert_str("message", "dial 1.2.3.4:443 failed");
        assert_eq!(ev.fields["message"], "dial [redacted-ip]:443 failed");
    }
}
```

- [ ] **Step 2: Run** `cargo test -p spark-core diag` → FAIL (module missing).
- [ ] **Step 3: Implement** in `core/src/diag/mod.rs`:

```rust
//! On-device diagnostics: structured events captured to a ring/spool/backup-log and
//! uploaded as OTLP logs+traces to the config-delivered otel endpoint (design:
//! docs/superpowers/specs/2026-07-17-spark-diagnostics-design.md). Privacy: every
//! string field is IP-redacted on insert; kinds/fields follow the spec §C5 allowlist
//! (enforced by the typed constructors in `events`).

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DiagLevel {
    Error,
    Warn,
    Info,
    Debug,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiagEvent {
    pub ts: u64, // unix millis; SigNoz receipt time is the trusted clock
    pub level: DiagLevel,
    pub component: &'static str,
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    pub fields: BTreeMap<String, serde_json::Value>,
}

impl DiagEvent {
    pub fn new(level: DiagLevel, component: &'static str, kind: &'static str) -> Self {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        DiagEvent { ts, level, component, kind, session: None, fields: BTreeMap::new() }
    }

    /// Insert a string field, IP-redacted (the §C5 backstop applies to every string).
    pub fn insert_str(&mut self, key: &str, value: &str) {
        self.fields.insert(
            key.to_string(),
            crate::redact::redact_addrs(value).into_owned().into(),
        );
    }

    /// One-line JSON for the spool / backup log.
    pub fn to_jsonl(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".into())
    }
}
```

- [ ] **Step 4: Run** `cargo test -p spark-core diag` → PASS. Run fmt/clippy.
- [ ] **Step 5: Commit** `feat(diag): DiagEvent model with redacting field insert`

---

### Task 2: `DiagSink` — channel ring + spool + backup log + error fast-path

**Files:**
- Create: `core/src/diag/sink.rs`
- Modify: `core/src/diag/mod.rs` (add `pub mod sink;` re-export `sink::DiagSink`)

The sink is logbus-shaped: `push()` is a lossy bounded-channel `try_send` (the "ring", depth 4096); a writer task drains the channel and appends each event to BOTH the spool (`diagnostics.jsonl`, the upload queue) and the backup log (`diag.log`, unconditional). `push_error()` bypasses the channel: synchronous append to spool+backup (never lost), then notifies the flusher. Rotation: spool → truncate-after-upload + hard cap 4 MB (rotate to `.1`); backup log → rotate at 5 MB to `diag.log.1`.

- [ ] **Step 1: Write failing tests** (`#[tokio::test]`, tempdir per test via `std::env::temp_dir().join(format!("spark-diag-{}", line!()))`):
  - `push_reaches_spool_and_backup_log` — push 3 events, `sink.flush_writer().await`, both files contain 3 JSONL lines.
  - `push_error_is_synchronous` — `push_error` then read spool immediately (no await): line present.
  - `ring_overflow_drops_and_counts` — fill channel beyond 4096 without running writer; `sink.dropped()` > 0; after writer drains, a `diag.buffer_dropped` event with the count is appended.
  - `backup_log_rotates_at_cap` — set test cap 1 KB via `DiagSink::with_caps`, push until rotation, assert `diag.log.1` exists and `diag.log` is small.
  - `take_spool_batch_and_truncate` — push N, writer flush, `take_spool_batch(max_bytes)` returns the lines and truncates the consumed prefix; remaining lines survive.
  - `spool_survives_reopen` — write, drop sink, `DiagSink::new` again in same dir, `take_spool_batch` returns prior events (the crash-durability property).

- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** `sink.rs` (API surface — keep exactly these signatures so later tasks compose):

```rust
pub struct DiagSink { /* tx: mpsc::Sender<DiagEvent>, dirs, caps, dropped: AtomicU64,
                         files: Mutex<Files>, flush_notify: Arc<Notify> */ }

impl DiagSink {
    /// Creates the sink, opens/creates spool + backup log in `dir`, spawns the writer task.
    pub fn new(dir: &Path, component: &'static str) -> std::io::Result<Arc<DiagSink>>;
    pub fn with_caps(dir: &Path, component: &'static str, spool_cap: u64, log_cap: u64)
        -> std::io::Result<Arc<DiagSink>>;
    /// Lossy enqueue (hot-path safe). Increments `dropped` on a full channel.
    pub fn push(&self, ev: DiagEvent);
    /// Synchronous spool+backup write for errors (§C2a). Never lost; wakes the flusher.
    pub fn push_error(&self, ev: DiagEvent);
    pub fn dropped(&self) -> u64;
    /// Await the writer having drained everything queued so far (tests + shutdown).
    pub async fn flush_writer(&self);
    /// Read up to `max_bytes` of spool JSONL lines and truncate the consumed prefix.
    /// Returns whole lines only.
    pub fn take_spool_batch(&self, max_bytes: usize) -> std::io::Result<Vec<String>>;
    /// A Notify that fires when an error lands (uploader debounces on it).
    pub fn error_notify(&self) -> Arc<tokio::sync::Notify>;
}

/// Process-global sink, logbus-style: set once by the host process; `emit`/`emit_error`
/// are no-ops until installed (so core code can emit unconditionally).
static SINK: OnceLock<Arc<DiagSink>> = OnceLock::new();
pub fn install(sink: Arc<DiagSink>) -> bool;      // false if already installed
pub fn emit(ev: DiagEvent);                        // SINK.get() → push
pub fn emit_error(ev: DiagEvent);                  // SINK.get() → push_error
```

Implementation notes: writer task holds the file handles; `push_error` takes the file `Mutex` directly (short critical section, std Mutex, no `.await` inside — matches CLAUDE.md lock rules); truncate-prefix = read file, split at byte budget on a line boundary, rewrite remainder via temp-file + rename (spool is ≤4 MB so this is cheap and atomic-enough); all I/O errors → `tracing::debug!` + continue.

- [ ] **Step 4: Run → PASS.** fmt/clippy.
- [ ] **Step 5: Commit** `feat(diag): DiagSink with spool, backup log, error fast-path`

---

### Task 3: Typed event constructors (the §C5/§C6 allowlist)

**Files:**
- Create: `core/src/diag/events.rs`

Typed constructor functions instead of a `diag!` macro — the field allowlist becomes the function signature, enforced at compile time (stronger than the spec's macro sketch; spec §7 allows either).

- [ ] **Step 1: Write failing tests:**

```rust
#[test]
fn peer_connected_shape() {
    let ev = events::unbounded_peer_connected("s1", 812, "srflx", Some("DE"));
    assert_eq!(ev.kind, "unbounded.peer_connected");
    assert_eq!(ev.session.as_deref(), Some("s1"));
    assert_eq!(ev.fields["nat_traversal_ms"], 812);
    assert_eq!(ev.fields["selected_pair_type"], "srflx");
    assert_eq!(ev.fields["peer_region"], "DE");
}

#[test]
fn no_event_constructor_leaks_ip_literals() {
    // Property-style: feed addresses into every string parameter of every constructor.
    let evs = vec![
        events::log(DiagLevel::Warn, "dial 1.2.3.4:443", "spark_core::x"),
        events::unbounded_attempt_failed(0, "egress [2001:db8::1]:443 refused"),
        events::error_panic("panicked at 10.0.0.1", "src/main.rs:1"),
        events::unbounded_peer_disconnected("s", 1, 2, "reset by 8.8.8.8"),
    ];
    for ev in evs {
        let line = ev.to_jsonl();
        assert!(!line.contains("1.2.3.4") && !line.contains("2001:db8::1")
            && !line.contains("10.0.0.1") && !line.contains("8.8.8.8"), "{line}");
    }
}
```

- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** one constructor per spec §C6 row (every string param goes through `insert_str`). Signatures:

```rust
pub fn log(level: DiagLevel, message: &str, target: &str) -> DiagEvent;
pub fn unbounded_attempt_started(slot: usize) -> DiagEvent;
pub fn unbounded_ice_gathering(candidate_types: &[&str], count: u64) -> DiagEvent;
pub fn unbounded_peer_connected(session: &str, nat_traversal_ms: u64,
    selected_pair_type: &str, peer_region: Option<&str>) -> DiagEvent;
pub fn unbounded_throughput_sample(session: &str, bytes_up: u64, bytes_down: u64,
    interval_ms: u64) -> DiagEvent;
pub fn unbounded_peer_disconnected(session: &str, duration_ms: u64, bytes_total: u64,
    reason: &str) -> DiagEvent;
pub fn unbounded_attempt_failed(slot: usize, error_kind: &str) -> DiagEvent; // level=Error
pub fn unbounded_geo_failed(reason: &str) -> DiagEvent;
pub fn unbounded_pool_snapshot(active_peers: u64, slots_filled: u64, total_helped: u64) -> DiagEvent;
pub fn unbounded_signaling(state: &str, latency_ms: Option<u64>, error_kind: Option<&str>) -> DiagEvent;
pub fn config_fetch_outcome(result: &str, avenue: &str, latency_ms: u64) -> DiagEvent;
pub fn diag_buffer_dropped(count: u64) -> DiagEvent;
pub fn diag_lock_poisoned(site: &str) -> DiagEvent;                          // level=Error
pub fn diag_config_applied(knob: &str, value: &str) -> DiagEvent;
pub fn error_panic(message: &str, location: &str) -> DiagEvent;              // level=Error
pub fn error_task_failed(task: &str, error: &str) -> DiagEvent;              // level=Error
pub fn error_webview(message: &str, source: &str) -> DiagEvent;              // level=Error
```

`component` for all of these: `"app"` comes from the installed sink, so constructors set a placeholder `"app"`— NO: keep `component` on the sink, not the event constructors; `DiagSink::push` overwrites `ev.component` with the sink's component. Add that one line to `push`/`push_error` in this task (and a test asserting it).

- [ ] **Step 4: Run → PASS.** fmt/clippy.
- [ ] **Step 5: Commit** `feat(diag): typed event constructors (schema allowlist)`

---

### Task 4: `DiagLayer` — capture the existing tracing stream

**Files:**
- Create: `core/src/diag/layer.rs`

Modeled on `service/src/logbus.rs` `LogForwarder` (same `MessageVisitor` pattern). Level policy (spec §C1): DEBUG+ for targets starting with `spark`, INFO+ otherwise; ERROR-level events route via `emit_error` (fast-path). The layer consults an `AtomicU8` capture-level knob (`set_capture_level`) so the server's `capture` knob can dial it later; errors ignore the knob.

- [ ] **Step 1: Write failing tests** (install a scoped subscriber with `tracing::subscriber::with_default`, a test sink in a tempdir):
  - `captures_spark_debug_but_not_foreign_debug` — `tracing::debug!(target: "spark_core::x", "a")` captured; `tracing::debug!(target: "hyper::y", "b")` not.
  - `error_events_use_fast_path` — an `error!` lands in the spool without running the writer task.
  - `messages_are_redacted` — `warn!("dial 1.2.3.4")` → spool line contains `[redacted-ip]`.
  - `capture_level_error_only_still_records_errors` — with `set_capture_level(DiagLevel::Error)`, `info!` dropped, `error!` recorded.
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** `DiagLayer` (a `Layer<S>` whose `on_event` builds `events::log(...)` and calls `emit`/`emit_error`). Reuse a private copy of `MessageVisitor` (8 lines; service crate isn't a dependency of core, so duplicate with a comment pointing at logbus.rs).
- [ ] **Step 4: Run → PASS.** fmt/clippy.
- [ ] **Step 5: Commit** `feat(diag): tracing capture layer with level policy`

---### Task 5: OTLP logs envelope + semconv resource attributes

**Files:**
- Create: `core/src/diag/otlp.rs`

- [ ] **Step 1: Write failing golden test:**

```rust
#[test]
fn encodes_otlp_logs_envelope() {
    let res = ResourceAttrs {
        service_version: "0.3.0".into(), git_sha: "abc1234".into(),
        device_id: "d3adb33f".into(), platform: "darwin".into(),
        country: "US".into(), environment: "prod".into(), component: "app".into(),
        os_name: std::env::consts::OS.into(), os_version: "test".into(),
        arch: std::env::consts::ARCH.into(),
    };
    let mut ev = DiagEvent::new(DiagLevel::Warn, "app", "unbounded.geo_failed");
    ev.session = Some("s1".into());
    ev.fields.insert("reason".into(), "timeout".into());
    let body = otlp::encode_logs(&res, &[ev], Some(b"0123456789abcdef"));
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let attrs = &v["resourceLogs"][0]["resource"]["attributes"];
    let find = |k: &str| attrs.as_array().unwrap().iter()
        .find(|a| a["key"] == k).map(|a| a["value"]["stringValue"].clone());
    assert_eq!(find("service.name").unwrap(), "spark");
    assert_eq!(find("service.version").unwrap(), "0.3.0");
    assert_eq!(find("client.device_id").unwrap(), "d3adb33f");
    assert_eq!(find("geo.country.iso_code").unwrap(), "US");
    let rec = &v["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];
    assert_eq!(rec["severityText"], "WARN");
    assert_eq!(rec["severityNumber"], 13); // OTLP: WARN=13, ERROR=17, INFO=9, DEBUG=5
    assert_eq!(rec["body"]["stringValue"], "unbounded.geo_failed");
    assert_eq!(rec["traceId"], "30313233343536373839616263646566"); // hex of the 16 bytes
    let ra = rec["attributes"].as_array().unwrap();
    assert!(ra.iter().any(|a| a["key"] == "kind"));
    assert!(ra.iter().any(|a| a["key"] == "session"));
    assert!(ra.iter().any(|a| a["key"] == "reason"));
    assert!(rec["timeUnixNano"].as_str().unwrap().len() >= 18); // string per OTLP JSON
}
```

- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** `ResourceAttrs` struct + `encode_logs(res, events, trace_id: Option<&[u8;16]>) -> Vec<u8>`. Notes: OTLP/JSON encodes 64-bit ints as strings (`timeUnixNano`), trace/span ids as lowercase hex; severity mapping DEBUG=5, INFO=9, WARN=13, ERROR=17; `body` = message field for `kind=="log"`, else the kind; non-string field values map to the matching `intValue`/`doubleValue`/`boolValue`/`stringValue` (fallback: JSON-stringify).
- [ ] **Step 4: Run → PASS.** fmt/clippy.
- [ ] **Step 5: Commit** `feat(diag): OTLP/HTTP JSON logs encoder with semconv resource`

---

### Task 6: Spans + OTLP traces envelope

**Files:**
- Create: `core/src/diag/span.rs`
- Modify: `core/src/diag/otlp.rs` (add `encode_spans`)

- [ ] **Step 1: Write failing tests:**
  - `session_trace_has_root_and_children` — build a `SessionTrace::new("sess-1")`; `child("signaling")` → `finish_child(ok)`; `child("nat_traversal")` → finish; `finish(None)`; assert all spans share one `trace_id`, children's `parent_span_id` == root's `span_id`, root name `"unbounded.session"`.
  - `error_span_carries_status` — `finish(Some("EgressError::Refused"))` → root span `status.code == 2` (STATUS_CODE_ERROR) with redacted message.
  - `encodes_otlp_traces_envelope` — golden test mirroring Task 5 (resourceSpans → scopeSpans → spans; ids hex; times as string nanos).
  - `ids_are_random_and_correct_length` — two traces differ; trace_id 16 bytes, span_id 8 bytes (via `ring::rand::SystemRandom`).
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement:**

```rust
pub struct DiagSpan { pub trace_id: [u8;16], pub span_id: [u8;8],
    pub parent_span_id: Option<[u8;8]>, pub name: &'static str,
    pub start_unix_nano: u64, pub end_unix_nano: u64,
    pub error: Option<String>, pub attrs: BTreeMap<String, serde_json::Value> }

/// Builder for one Unbounded session's trace (spec §C3a). Completed spans accumulate;
/// the caller ships them (with the session's log events carrying `trace_id`) on finish.
pub struct SessionTrace { /* trace_id, root span_id, root start, done: Vec<DiagSpan>,
                             open: HashMap<&'static str, ([u8;8], u64)> */ }
impl SessionTrace {
    pub fn new(session_id: &str) -> Self;         // random ids; session attr on root
    pub fn trace_id(&self) -> [u8; 16];
    pub fn child_start(&mut self, name: &'static str);
    pub fn child_end(&mut self, name: &'static str, error: Option<&str>);
    pub fn finish(mut self, error: Option<&str>) -> Vec<DiagSpan>; // closes root
}
pub fn encode_spans(res: &ResourceAttrs, spans: &[DiagSpan]) -> Vec<u8>;
```

- [ ] **Step 4: Run → PASS.** fmt/clippy.
- [ ] **Step 5: Commit** `feat(diag): session spans + OTLP traces encoder`

---

### Task 7: Config plumbing — parse the `otel` block + feature flags

**Files:**
- Modify: `core/src/config/lantern.rs` (the adapter currently passes `otel` through untouched — see comment at `lantern.rs:361`)

- [ ] **Step 1: Write failing tests** (extend the existing lantern.rs test JSON at ~`:933` which already exercises `features`):

```rust
#[test]
fn parses_otel_block_and_flags() {
    let raw = r#"{ "options": { "outbounds": [ /* reuse an existing valid outbound */ ] },
      "otel": { "endpoint": "ingest.us.signoz.cloud:443",
                "headers": {"signoz-ingestion-key": "k1"}, "sample_rate": 0.5 },
      "features": { "otel.logs": true, "otel.traces": true } }"#;
    let cfg = Config::from_config_str(raw).unwrap();
    let otel = cfg.otel.as_ref().unwrap();
    assert_eq!(otel.endpoint, "ingest.us.signoz.cloud:443");
    assert_eq!(otel.headers, vec![("signoz-ingestion-key".to_string(), "k1".to_string())]);
    assert!((otel.sample_rate - 0.5).abs() < 1e-9);
    assert!(otel.logs_enabled && otel.traces_enabled);
}

#[test]
fn otel_absent_or_empty_endpoint_is_none() { /* both cases → cfg.otel == None,
    mirroring radiance's `Endpoint == "" ⇒ skip` */ }
```

- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** `OtelConfig { endpoint: String, headers: Vec<(String,String)>, sample_rate: f64, logs_enabled: bool, traces_enabled: bool }` on `Config` (`pub otel: Option<OtelConfig>`), populated from the raw JSON `otel` block + `features["otel.logs"]`/`features["otel.traces"]` (map absent flags to false, absent `sample_rate` to 1.0). Headers sorted for determinism.
- [ ] **Step 4: Run → PASS.** fmt/clippy — **whole workspace** (`cargo clippy --all-targets -- -D warnings` at root AND `gui-tauri/src-tauri`; Config is consumed downstream).
- [ ] **Step 5: Commit** `feat(config): parse otel endpoint/headers/flags from config-new`

---

### Task 8: Uploader task

**Files:**
- Create: `core/src/diag/upload.rs`

- [ ] **Step 1: Write failing tests.** Test the pure pieces + one wiring test:
  - `gate_predicate` — table test over `(otel: Option<OtelConfig>, local_opt_out, logs_enabled)` → upload on/off; endpoint empty ⇒ off.
  - `device_sampling_is_stable` — `sampled_in(device_id, rate)`: rate 1.0 always true, 0.0 false, same id+rate deterministic (hash first 8 hex chars of device_id / u32::MAX < rate).
  - `request_bytes_shape` — `build_upload_request("ingest.host:443", "/v1/logs", &headers, &body)` → starts `POST /v1/logs HTTP/1.1`, has `Host:`, each otel header (CRLF-stripped via the existing `header_safe` — make it `pub(crate)` in `config/fetch/request.rs`), `Content-Type: application/json`, correct `Content-Length`, `Connection: close`.
  - `upload_2xx_truncates_spool_5xx_retains` — duplex-pipe fake server (copy the `config/fetch/http.rs` test harness) + a real `DiagSink` in a tempdir: after a 200, `take_spool_batch` returns empty; after a 503, events still present and `next_backoff` grows (reuse quadratic backoff, ≤2 min — copy the 4-line `backoff` fn, don't couple to `config::fetch` internals).
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement:**

```rust
pub struct UploaderHandle { stop: Arc<AtomicBool> }

/// Spawn the uploader: every 60s tick (or ~5s after error_notify fires, debounced, or
/// when the spool exceeds 256 KB) take a spool batch, encode OTLP logs, POST to
/// `https://{endpoint}/v1/logs` via resolve→DirectTransport→tls_wrap→post_collect
/// (30s timeout). Pending spans (a shared `SpanQueue`) go to `/v1/traces` the same way,
/// gated on `traces_enabled`. 2xx ⇒ spool prefix already truncated by take; non-2xx or
/// error ⇒ REWRITE the batch back to the spool head is NOT done — instead take_spool_batch
/// is only called AFTER a successful probe? Simpler contract: read-without-truncate, then
/// truncate on 2xx: add `peek_spool_batch` + `truncate_spool(bytes)` to DiagSink (do it
/// in this task; adjust Task 2 tests accordingly if names shift).
pub fn spawn(sink: Arc<DiagSink>, cfg_rx: tokio::sync::watch::Receiver<Option<OtelConfig>>,
    res: ResourceAttrs, local_opt_out: bool, spans: Arc<SpanQueue>) -> UploaderHandle;

pub struct SpanQueue(Mutex<Vec<DiagSpan>>);  // finished session/fetch traces awaiting ship
```

Non-2xx handling: keep spool intact (peek/truncate split), quadratic backoff between attempts, all failures `tracing::debug!` (never error — would loop into ourselves).

- [ ] **Step 4: Run → PASS.** fmt/clippy (whole workspace).
- [ ] **Step 5: Commit** `feat(diag): uploader with gate, sampling, backoff, trace ship`

---

### Task 9: Panic hook + `config.fetch_outcome` instrumentation

**Files:**
- Create: `core/src/diag/panic_hook.rs`
- Modify: `core/src/config/fetch/mod.rs` (emit outcome events from `fetch_once_*`)

- [ ] **Step 1: Tests:**
  - Panic hook: subprocess test — a `#[test]` spawns `std::process::Command` running the test binary with `SPARK_DIAG_PANIC_CHILD=1` + a tempdir env; the child installs a sink + hook and panics; parent asserts the spool contains an `error.panic` line with `location`. (Pattern: guard child code with `#[test] fn panic_child() { if env absent { return; } ... }`.)
  - Fetch outcome: unit-test the small helper `fetch_outcome_event(result, avenue, started)` → correct kind/fields; wire-up is 3 call sites reviewed by eye (each avenue's Ok/Err in `fetch_once_direct/fronted/scanned`), each firing `diag::emit(events::config_fetch_outcome(...))`.
- [ ] **Step 2: Run → FAIL / implement / PASS.** Hook body: build `events::error_panic(&msg, &location)`, `emit_error` (synchronous spool write — survives the crash), then call the chained previous hook. Wrap everything in `catch_unwind`-free plain code that cannot itself panic (string ops only).
- [ ] **Step 3:** fmt/clippy whole workspace.
- [ ] **Step 4: Commit** `feat(diag): panic hook + config-fetch outcome events`

---

### Task 10: Plugin wiring — sink init, subscriber, config watch, opt-out

**Files:**
- Modify: `gui-tauri/tauri-plugin-spark-vpn/src/lib.rs` (plugin setup)
- Modify: `gui-tauri/tauri-plugin-spark-vpn/src/persist.rs` (new key `diagnostics_enabled`, default `true`)
- Modify: `gui-tauri/tauri-plugin-spark-vpn/build.rs` + `permissions/default.toml` (register the two new commands of Task 12 now to keep ACL churn in one place: `diag_report_webview_error`, `diag_set_enabled`, `diag_get_enabled`)
- Create: `gui-tauri/tauri-plugin-spark-vpn/src/diag_host.rs`

In plugin setup (mirror how `unbounded.rs` resolves `app_config_dir` at `unbounded.rs:44`):
1. `DiagSink::new(app_config_dir, "app")` + `diag::install`.
2. `panic_hook::install()`.
3. Tracing: `tracing_subscriber::registry().with(DiagLayer::new()).try_init()` — `try_init` so an existing subscriber (dev builds) isn't clobbered; if it fails, attach nothing and log.
4. Local opt-out: `SPARK_DIAGNOSTICS=off` env OR `persist::diagnostics_enabled() == false` ⇒ skip uploader spawn entirely (backup log still runs — it's part of the sink; only when opt-out ⇒ pass a flag to `DiagSink` to also skip spool+ring? NO — spec: local opt-out disables everything including the backup log. Gate ALL of steps 1-5 on the opt-out; when opted out, install nothing).
5. Build `ResourceAttrs` (version from `app.package_info().version`, git sha from `env!("SPARK_GIT_SHA")` — emitted by the plugin's existing `build.rs` via `git rev-parse --short HEAD` with `"unknown"` fallback; device_id + country parsed from the app's cached config dir — reuse the `desktop.rs:685` cache-dir helper; device_id via `spark_core::config::fetch::device_id(dir)`), then `upload::spawn` with a `watch` channel.
6. Config watch: parse `OtelConfig` from the cached `config_raw.json` at startup and re-parse wherever the plugin already reloads the cache (the locations refresh path in `desktop.rs`) — send into the watch channel.

- [ ] **Step 1:** persist tests (mirror existing persist.rs key tests): default true, set/get round-trip.
- [ ] **Step 2:** `diag_host::otel_from_cache(dir) -> Option<OtelConfig>` unit test against a fixture JSON written to a tempdir.
- [ ] **Step 3:** implement, then `cargo build` + `cargo clippy --all-targets -- -D warnings` in `gui-tauri/src-tauri`.
- [ ] **Step 4: Commit** `feat(plugin): diagnostics host wiring (sink, layer, uploader, opt-out)`

---

### Task 11: Unbounded instrumentation — §C6 timeline + session traces

**Files:**
- Modify: `gui-tauri/tauri-plugin-spark-vpn/src/unbounded.rs` (aggregation loop)

Map `PoolEvent`/`SupervisorEvent` (from `spark-sharing` re-exports; variants: `AttemptStarted`, `PeerConnected{session_id, remote}`, `PeerDisconnected{session_id}`, `SessionEnded`, `AttemptFailed`, `Stopped`) onto diag events + `SessionTrace`s:

- `AttemptStarted{slot}` → `emit(unbounded_attempt_started)`; start a pending `SessionTrace` with `child_start("signaling")`.
- `PeerConnected` → `child_end("signaling")`, `child_start("relay")`, `emit(unbounded_peer_connected)` with `nat_traversal_ms` = now − attempt start (Instant kept per slot), `peer_region` from the existing `GeoResolver` output the loop already has (country only).
- `PeerDisconnected`/`SessionEnded` → `child_end("relay")`, `trace.finish(None)` → push spans into the `SpanQueue`; `emit(unbounded_peer_disconnected)` with duration + bytes from the aggregator's `PeerView`.
- `AttemptFailed(e)` → `emit_error(unbounded_attempt_failed(slot, error_kind(&e)))` where `error_kind` renders the enum variant name (match on `PeerProxyError`/`EgressError`/`RelayError`/`SignalingError`, no payload → no addresses); `trace.finish(Some(kind))`.
- Geo `None` results (today silent) → `emit(unbounded_geo_failed("resolver_none"))`.
- Every 60s in the loop → `emit(unbounded_pool_snapshot(...))` from `Aggregator::status()`.
- The existing `eprintln!("[spark-unbounded] failed to persist total_helped: {e}")` → `tracing::error!` (flows through DiagLayer's fast path).
- Session-scoped log events: set `ev.session` and pass the session's `trace_id` when the uploader encodes them — plumbing: `SessionTrace` registry `HashMap<String,[u8;16]>` shared with the uploader via `SpanQueue::trace_id_for(session)`.

- [ ] **Step 1:** unit-test the pure mapper `fn diag_for_event(ev: &PoolEvent, state: &mut SlotState) -> Vec<DiagEvent>` over a scripted event sequence (started → connected → disconnected) asserting kinds, session correlation, `nat_traversal_ms` presence, and error path for `AttemptFailed`.
- [ ] **Step 2:** implement + wire into the loop. Run plugin workspace tests + clippy.
- [ ] **Step 3: Commit** `feat(unbounded): diagnostic timeline + session traces`

---

### Task 12: Webview error bridge + settings toggle

**Files:**
- Modify: `gui-tauri/tauri-plugin-spark-vpn/src/lib.rs` (commands `diag_report_webview_error`, `diag_set_enabled`, `diag_get_enabled` — ACL already registered in Task 10)
- Modify: `gui-tauri/src/lib/spark_backend.ts` (backend seam: `reportError`, `diagnosticsEnabled`, `setDiagnosticsEnabled` on both Mock and Tauri backends — remember the 4-layer field plumbing lesson: TS type + Mock + Tauri invoke + Rust command must all agree)
- Modify: `gui-tauri/src/routes/+layout.svelte` (global `window.onerror` + `unhandledrejection` → `backend.reportError(msg, source)`, fire-and-forget, try/catch so the handler can never throw)
- Modify: `gui-tauri/src/routes/settings/+page.svelte` (a "Share diagnostics" toggle row bound to the new commands, following the hub's existing row pattern)
- Modify: `gui-tauri/src/lib/i18n/spark/en.json` (keys `settings_diagnostics`, `settings_diagnostics_desc`)

- [ ] **Step 1:** Rust command bodies: `diag_report_webview_error(message, source)` → `emit_error(events::error_webview(...))`; toggle commands read/write the persist key (change takes effect on next launch — note that in the toggle's description text).
- [ ] **Step 2:** `npm run check` (svelte-check) + i18n key-coverage test + `cargo clippy` in the tauri workspace.
- [ ] **Step 3:** dev-server smoke: throw from console, verify an `error.webview` line lands in `diag.log`.
- [ ] **Step 4: Commit** `feat(diag): webview error bridge + settings opt-out toggle`

---

### Task 13: Final gate + live verify + docs

**Files:**
- Modify: `docs/STATE.md` (decisions-log entry)
- Create: `core/src/diag/live_test.rs` or an `#[ignore]`d test in `upload.rs`

- [ ] **Step 1:** Whole-tree gate: root workspace + `spark-sharing` + `gui-tauri/src-tauri` — `cargo fmt --all --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`; `npm run check` + `npx vitest run` in `gui-tauri`.
- [ ] **Step 2:** `#[ignore]` live test (like `live_fetch`): read `SPARK_OTEL_ENDPOINT` + `SPARK_OTEL_HEADERS` env (ask Adam to surface the radiance staging values, or pull from a staging config fetch), upload one synthetic batch, assert 2xx. Then verify queryability via the SigNoz MCP (`service.name = spark`) — manual step, record the query used in STATE.md.
- [ ] **Step 3:** Confirm the OTLP/HTTP **JSON** acceptance question (spec §C3 verify item). If the endpoint rejects JSON (some collectors are protobuf-only): STOP, report, and ask before adding `prost` (locked stack).
- [ ] **Step 4:** DMG smoke build (arm64) to confirm the app still notarizes/launches with the new init path.
- [ ] **Step 5: Commit** `chore(diag): phase A gate + live verify notes` and open PR against `fisk/unbounded-volunteer` (base = the unbounded branch until #90 merges, then retarget main).

---

### Task 14: Server-side enablement (separate repos, 2 small PRs)

**Files:**
- Modify: `getlantern/common` `types.go` (add `LOGS = "otel.logs"` beside `TRACES`/`METRICS` at `types.go:12-15`)
- Modify: `getlantern/lantern-cloud` `cmd/api/config.go:601` (`if featureEnabled(common.TRACES) || featureEnabled(common.METRICS) || featureEnabled(common.LOGS) {`) + `go get github.com/getlantern/common@<new-sha>` then **`go mod tidy`, commit `go.mod`+`go.sum` together** (standing rule).

- [ ] **Step 1:** common PR: constant + doc comment (`// Whether or not client-side logs should be enabled.`), matching house comment style.
- [ ] **Step 2:** lantern-cloud PR: bump + one-line condition + a config handler test exercising `otel.logs=true` emitting the OTEL block (mirror the existing TRACES test if present).
- [ ] **Step 3:** Run each repo's linter per its CI (`golangci-lint run --new-from-rev=origin/main ./...`).
- [ ] **Step 4:** Flag for Adam/ops: enable `features["otel.logs"]` + confirm `otel_headers`/`otel_endpoint` settings for the testing cohort (server settings, not code).

---

## Self-review (done at authoring time)

- **Spec coverage:** §C1→T1/3/4, §C2→T2, §C2a→T2/T4/T9/T11/T12, §C3→T5/T8, §C3a→T6/T8/T11, §C4→T7/T8/T10/T12, §C5→T1/T3 (redaction property tests), §C6→T3/T11, §C7 analysis→T13 live verify (remediation itself is Phase C), server deltas→T14. Gzip deliberately deferred (noted in Tech Stack) — spec §C3 says gzip; v1 ships identity encoding and revisits at >256 KB batches. ✔ deviation documented.
- **Type consistency:** `DiagSink::take_spool_batch` is superseded by `peek_spool_batch`+`truncate_spool` in Task 8 — Task 8 Step 3 explicitly owns that rename including fixing Task 2's tests.
- **No placeholders:** every task has concrete signatures, test bodies or exact assertions, and file paths.
