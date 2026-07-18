//! The diagnostics uploader (design §C3/§C4): ships spool batches as OTLP/HTTP JSON
//! logs — and queued session spans as traces — to the config-delivered otel endpoint.
//!
//! Reuses config-fetch's transport verbatim (resolve → `DirectTransport` → `tls_wrap`
//! → `post_collect`); the module only compiles under `feature = "config-fetch"` so the
//! real (boring) `tls_wrap` is always in play — a build where `tls_wrap` degrades to
//! the no-op passthrough cannot contain this uploader, so a plaintext upload is
//! impossible by construction.
//!
//! Failure discipline mirrors `config::fetch::run_loop`: nothing here ever returns an
//! error to a caller or crashes the process, and internal failures log at
//! `tracing::debug!` ONLY — this code runs beneath the capture layer, and reporting
//! its own failures at a captured level would re-enter the pipeline.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{watch, Notify};

use crate::config::fetch::http::post_collect;
use crate::config::fetch::request::header_safe;
use crate::config::lantern::OtelConfig;
use crate::transport::{probe::tls_wrap, DirectTransport, Transport};

use super::otlp::{encode_spans, encode_spool_logs, ResourceAttrs, SpoolEvent};
use super::sink::DiagSink;
use super::span::DiagSpan;

/// Steady-state flush cadence when the last upload succeeded.
const TICK: Duration = Duration::from_secs(60);
/// §C2a expedited flush: an error wakes the loop, debounced so a burst ships once.
const ERROR_DEBOUNCE: Duration = Duration::from_secs(5);
/// Per-upload spool budget. Well above any single line (the sink returns an empty
/// batch if the first line alone exceeds the budget) and well below memory concern.
const BATCH_BYTES: usize = 256 * 1024;
/// Queued-span bound: if trace uploads keep failing, drop the OLDEST spans rather
/// than grow without bound (the correlated log records still ship independently).
const MAX_QUEUED_SPANS: usize = 512;

/// A session's OTLP correlation pair: (trace id, root span id) — what
/// [`super::otlp::encode_spool_logs`] stamps onto that session's log records (§C3a).
pub type TraceCtx = ([u8; 16], [u8; 8]);

/// Finished spans awaiting ship, plus the session → [`TraceCtx`] registry used to
/// stamp log records with their session's trace context (§C3a).
///
/// The instrumentation side (the plugin's aggregation loop) registers a context at
/// session start and removes it after the session's spans are pushed; entries are
/// therefore bounded by the number of live sessions.
pub struct SpanQueue {
    spans: Mutex<Vec<DiagSpan>>,
    ctx: Mutex<HashMap<String, TraceCtx>>,
}

/// Same poison policy as the sink: a panicking pusher leaves the data structurally
/// sound, so keep going.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl SpanQueue {
    pub fn new() -> Arc<SpanQueue> {
        Arc::new(SpanQueue {
            spans: Mutex::new(Vec::new()),
            ctx: Mutex::new(HashMap::new()),
        })
    }

    /// Queue finished spans for the next trace upload, dropping the oldest past
    /// [`MAX_QUEUED_SPANS`].
    pub fn push_spans(&self, spans: Vec<DiagSpan>) {
        let mut q = lock(&self.spans);
        q.extend(spans);
        let len = q.len();
        if len > MAX_QUEUED_SPANS {
            let excess = len - MAX_QUEUED_SPANS;
            q.drain(..excess);
            tracing::debug!(
                dropped = excess,
                "diag: span queue cap reached, oldest dropped"
            );
        }
    }

    /// Register a session's trace context so its log records can be stamped (§C3a).
    pub fn set_trace_ctx(&self, session: &str, ctx: TraceCtx) {
        lock(&self.ctx).insert(session.to_string(), ctx);
    }

    pub fn trace_ctx_for(&self, session: &str) -> Option<TraceCtx> {
        lock(&self.ctx).get(session).copied()
    }

    pub fn remove_trace_ctx(&self, session: &str) {
        lock(&self.ctx).remove(session);
    }

    fn drain(&self) -> Vec<DiagSpan> {
        std::mem::take(&mut *lock(&self.spans))
    }
}

/// Handle to the spawned upload loop. Dropping it aborts the task; [`stop`][Self::stop]
/// asks it to exit at its next wakeup (≤1 s).
pub struct UploaderHandle {
    stop: Arc<AtomicBool>,
    join: tokio::task::JoinHandle<()>,
}

impl UploaderHandle {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Drop for UploaderHandle {
    fn drop(&mut self) {
        self.stop();
        self.join.abort();
    }
}

/// The gate predicate (§C4): upload only when the local opt-out is off, the config
/// delivered an otel block with a non-empty endpoint, the `otel.logs` feature is on,
/// and this device is sampled in.
pub fn upload_allowed(otel: Option<&OtelConfig>, local_opt_out: bool, device_id: &str) -> bool {
    if local_opt_out {
        return false;
    }
    let Some(o) = otel else { return false };
    !o.endpoint.is_empty() && o.logs_enabled && sampled_in(device_id, o.sample_rate)
}

/// Per-DEVICE sampling: hash the device id against `rate`, deterministically, so a
/// sampled-in device reports *complete* sessions rather than a scatter of fragments.
///
/// Note the §C2a nuance: errors are exempt from sampling at the *collection* stage
/// (they always reach the spool and backup log); this gate decides whether the
/// device's stream uploads at all — during testing keep `sample_rate` at 1.0.
pub fn sampled_in(device_id: &str, rate: f64) -> bool {
    if rate >= 1.0 {
        return true;
    }
    if rate <= 0.0 {
        return false;
    }
    // First 8 hex chars of the device id as the hash (ids are 32 lowercase hex from
    // config::fetch::device_id). A malformed id parses to 0 → sampled in for any
    // rate > 0, erring toward visibility.
    let h = u32::from_str_radix(device_id.get(..8).unwrap_or(""), 16).unwrap_or(0);
    (f64::from(h) / f64::from(u32::MAX)) < rate
}

/// Build the raw HTTP/1.1 POST bytes for an OTLP upload. Mirrors
/// `config::fetch::request::build_request_bytes`; every configured header value is
/// CRLF-stripped (`header_safe`) so a corrupt config can't inject request framing.
pub fn build_upload_request(
    host: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Vec<u8> {
    let mut head = String::new();
    head.push_str(&format!("POST {path} HTTP/1.1\r\n"));
    head.push_str(&format!("Host: {host}\r\n"));
    for (k, v) in headers {
        head.push_str(&format!("{}: {}\r\n", header_safe(k), header_safe(v)));
    }
    head.push_str("Content-Type: application/json\r\n");
    head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    head.push_str("Connection: close\r\n\r\n");
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}

/// Spawn the upload loop. `cfg_rx` carries the current otel block (`None` = off) and
/// is re-read every wakeup, so a config poll can flip endpoints, rotate keys, or kill
/// uploads fleet-wide within one cycle (§C4).
pub fn spawn(
    sink: Arc<DiagSink>,
    cfg_rx: watch::Receiver<Option<OtelConfig>>,
    res: ResourceAttrs,
    local_opt_out: bool,
    device_id: String,
    spans: Arc<SpanQueue>,
) -> UploaderHandle {
    let stop = Arc::new(AtomicBool::new(false));
    let join = tokio::spawn(run_loop(
        sink,
        cfg_rx,
        res,
        local_opt_out,
        device_id,
        spans,
        stop.clone(),
    ));
    UploaderHandle { stop, join }
}

async fn run_loop(
    sink: Arc<DiagSink>,
    mut cfg_rx: watch::Receiver<Option<OtelConfig>>,
    res: ResourceAttrs,
    local_opt_out: bool,
    device_id: String,
    spans: Arc<SpanQueue>,
    stop: Arc<AtomicBool>,
) {
    let notify = sink.error_notify();
    let mut fail = 0u32;
    loop {
        let wait = if fail > 0 { backoff(fail) } else { TICK };
        wait_wakeup(&notify, &stop, wait).await;
        if stop.load(Ordering::Relaxed) {
            return;
        }
        let cfg = cfg_rx.borrow_and_update().clone();
        if !upload_allowed(cfg.as_ref(), local_opt_out, &device_id) {
            // Off: leave the spool accumulating (its rotation cap bounds disk, §C2)
            // and re-check the gate next tick — the server may flip it back on.
            continue;
        }
        let Some(otel) = cfg else { continue };

        // Logs: take a batch, replay it as OTLP, restore it on any failure.
        match sink.take_spool_batch(BATCH_BYTES) {
            Ok(lines) if !lines.is_empty() => {
                let events = parse_spool(&lines);
                if !events.is_empty() {
                    let body = encode_spool_logs(&res, &events, |s| spans.trace_ctx_for(s));
                    match try_post(&otel, "/v1/logs", &body).await {
                        Ok(status) if (200..300).contains(&status) => fail = 0,
                        Ok(status) => {
                            tracing::debug!(status, "diag: log upload rejected");
                            sink.restore_batch(&lines);
                            fail = fail.saturating_add(1);
                            continue;
                        }
                        Err(e) => {
                            tracing::debug!(err = %e, "diag: log upload failed");
                            sink.restore_batch(&lines);
                            fail = fail.saturating_add(1);
                            continue;
                        }
                    }
                }
            }
            Ok(_) => {}
            Err(e) => tracing::debug!(err = %e, "diag: spool take failed"),
        }

        // Traces: ship queued spans; re-queue on failure (bounded by the queue cap).
        if otel.traces_enabled {
            let batch = spans.drain();
            if !batch.is_empty() {
                let body = encode_spans(&res, &batch);
                match try_post(&otel, "/v1/traces", &body).await {
                    Ok(status) if (200..300).contains(&status) => fail = 0,
                    Ok(status) => {
                        tracing::debug!(status, "diag: trace upload rejected");
                        spans.push_spans(batch);
                        fail = fail.saturating_add(1);
                    }
                    Err(e) => {
                        tracing::debug!(err = %e, "diag: trace upload failed");
                        spans.push_spans(batch);
                        fail = fail.saturating_add(1);
                    }
                }
            }
        }
    }
}

/// Sleep up to `max`, waking early on an error notification (then debouncing ~5 s so
/// an error burst ships as one batch) — and returning within ~1 s of `stop` flipping.
async fn wait_wakeup(notify: &Notify, stop: &AtomicBool, max: Duration) {
    let step = Duration::from_secs(1);
    let mut left = max;
    while left > Duration::ZERO && !stop.load(Ordering::Relaxed) {
        let s = left.min(step);
        tokio::select! {
            _ = notify.notified() => {
                let mut d = ERROR_DEBOUNCE;
                while d > Duration::ZERO && !stop.load(Ordering::Relaxed) {
                    let ds = d.min(step);
                    tokio::time::sleep(ds).await;
                    d = d.saturating_sub(ds);
                }
                return;
            }
            _ = tokio::time::sleep(s) => { left = left.saturating_sub(s); }
        }
    }
}

/// Parse spool JSONL lines back into events, skipping (and counting) unparseable
/// lines — a torn trailing line from a crash must not wedge the whole batch.
fn parse_spool(lines: &[String]) -> Vec<SpoolEvent> {
    let mut out = Vec::with_capacity(lines.len());
    let mut bad = 0usize;
    for line in lines {
        match serde_json::from_str::<SpoolEvent>(line) {
            Ok(ev) => out.push(ev),
            Err(_) => bad += 1,
        }
    }
    if bad > 0 {
        tracing::debug!(bad, "diag: unparseable spool lines skipped");
    }
    out
}

/// One network attempt: resolve, dial direct, TLS-wrap, POST, return the HTTP status.
/// Bounded by a 30 s timeout (mirrors `fetch_once_direct`).
async fn try_post(otel: &OtelConfig, path: &str, body: &[u8]) -> io::Result<u16> {
    const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(30);
    let (host, port) = split_host_port(&otel.endpoint);
    tokio::time::timeout(ATTEMPT_TIMEOUT, async {
        let addr = resolve(&host, port).await?;
        let stream = DirectTransport::new(None).dial(addr).await?;
        let tls = tls_wrap(stream, &host).await?;
        post_body(tls, &host, path, &otel.headers, body).await
    })
    .await
    .map_err(|_| io::Error::other("diag upload timed out"))?
}

/// Write the request and collect the response status over any duplex stream — the
/// testable half of [`try_post`].
async fn post_body<S>(
    stream: S,
    host: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> io::Result<u16>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let req = build_upload_request(host, path, headers, body);
    // 64 KiB response cap: OTLP ingest replies are tiny (empty JSON or a status body).
    let resp = post_collect(stream, &req, 64 * 1024).await?;
    Ok(resp.status)
}

/// Split a config `endpoint` (`host:port`, radiance convention) into host + port,
/// defaulting to 443 when no valid port is present.
fn split_host_port(endpoint: &str) -> (String, u16) {
    if let Some((h, p)) = endpoint.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return (h.to_string(), port);
        }
    }
    (endpoint.to_string(), 443)
}

/// Resolve a host:port to a socket address (IP literal fast-path, else system
/// resolver). A small local copy rather than a shared helper, for the same reason
/// `config::fetch::resolve` is: 8 lines of trivial std/tokio DNS beats coupling the
/// diag uploader to a fetch internal.
async fn resolve(host: &str, port: u16) -> io::Result<std::net::SocketAddr> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(std::net::SocketAddr::new(ip, port));
    }
    tokio::net::lookup_host((host, port))
        .await?
        .next()
        .ok_or_else(|| io::Error::other(format!("diag endpoint `{host}` resolved to no addresses")))
}

/// Quadratic backoff (10ms·n²) capped at 2 minutes — a local copy of
/// `config::fetch::backoff` (4 lines; not worth coupling the modules).
fn backoff(n: u32) -> Duration {
    let ms = (10u64).saturating_mul((n as u64).saturating_mul(n as u64));
    Duration::from_millis(ms.min(120_000))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diag::{DiagEvent, DiagLevel};
    use std::path::PathBuf;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn test_otel(endpoint: &str, logs: bool, rate: f64) -> OtelConfig {
        OtelConfig {
            endpoint: endpoint.to_string(),
            headers: vec![("signoz-ingestion-key".into(), "k1".into())],
            sample_rate: rate,
            logs_enabled: logs,
            traces_enabled: true,
        }
    }

    fn test_dir(line: u32) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("spark-diag-upload-{}-{}", std::process::id(), line));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn test_res() -> ResourceAttrs {
        ResourceAttrs {
            service_version: "0.0.0".into(),
            git_sha: "test".into(),
            device_id: "d".into(),
            platform: "darwin".into(),
            country: "US".into(),
            environment: "test".into(),
            component: "app".into(),
            os_name: "macos".into(),
            os_version: "0".into(),
            arch: "arm64".into(),
        }
    }

    /// Fake OTLP server over a duplex pipe: reads the request, sends `response`, EOFs.
    /// Returns what it received. (Same harness shape as config/fetch/http.rs tests.)
    async fn run_post(
        response: &'static [u8],
        headers: &[(String, String)],
        body: &[u8],
    ) -> (io::Result<u16>, String) {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let t = tokio::spawn(async move {
            let mut buf = vec![0u8; 16 * 1024];
            let n = server.read(&mut buf).await.unwrap();
            server.write_all(response).await.unwrap();
            drop(server); // EOF terminates the body
            String::from_utf8_lossy(&buf[..n]).to_string()
        });
        let status = post_body(client, "ingest.test", "/v1/logs", headers, body).await;
        (status, t.await.unwrap())
    }

    #[test]
    fn gate_predicate() {
        let did = "00000000abcdef0011223344556677889"; // hash prefix 0 → always sampled in
        assert!(!upload_allowed(None, false, did), "no otel block");
        assert!(
            !upload_allowed(Some(&test_otel("", true, 1.0)), false, did),
            "empty endpoint"
        );
        assert!(
            !upload_allowed(Some(&test_otel("h:443", false, 1.0)), false, did),
            "logs disabled"
        );
        assert!(
            !upload_allowed(Some(&test_otel("h:443", true, 1.0)), true, did),
            "local opt-out"
        );
        assert!(
            !upload_allowed(Some(&test_otel("h:443", true, 0.0)), false, did),
            "sampled out"
        );
        assert!(
            upload_allowed(Some(&test_otel("h:443", true, 1.0)), false, did),
            "all good"
        );
    }

    #[test]
    fn device_sampling_is_stable() {
        assert!(sampled_in("ffffffff00", 1.0), "rate 1.0 always in");
        assert!(!sampled_in("00000000ff", 0.0), "rate 0.0 always out");
        // Deterministic: same inputs, same answer.
        for _ in 0..3 {
            assert_eq!(sampled_in("8a2b3c4d99", 0.5), sampled_in("8a2b3c4d99", 0.5));
        }
        // Roughly half of a uniform id spread lands in a 0.5 rate (loose 30-70%).
        let step = u32::MAX / 200;
        let hits = (0..200u32)
            .filter(|i| sampled_in(&format!("{:08x}", i * step), 0.5))
            .count();
        assert!((60..=140).contains(&hits), "0.5 rate hit {hits}/200");
    }

    #[test]
    fn request_bytes_shape() {
        let headers = vec![
            ("signoz-ingestion-key".to_string(), "k1".to_string()),
            ("evil".to_string(), "v\r\nX-Injected: 1".to_string()),
        ];
        let body = br#"{"resourceLogs":[]}"#;
        let s = String::from_utf8(build_upload_request(
            "ingest.test",
            "/v1/logs",
            &headers,
            body,
        ))
        .unwrap();
        assert!(s.starts_with("POST /v1/logs HTTP/1.1\r\n"));
        assert!(s.contains("Host: ingest.test\r\n"));
        assert!(s.contains("signoz-ingestion-key: k1\r\n"));
        assert!(s.contains("Content-Type: application/json\r\n"));
        assert!(s.contains("Connection: close\r\n"));
        assert!(
            !s.contains("\r\nX-Injected:"),
            "CRLF in a header value must not inject a header"
        );
        let (head, b) = s.split_once("\r\n\r\n").unwrap();
        assert!(head.contains(&format!("Content-Length: {}", b.len())));
        assert!(b.starts_with(r#"{"resourceLogs""#));
    }

    #[test]
    fn endpoint_split() {
        assert_eq!(
            split_host_port("ingest.us.signoz.cloud:443"),
            ("ingest.us.signoz.cloud".to_string(), 443)
        );
        assert_eq!(split_host_port("bare.host"), ("bare.host".to_string(), 443));
        assert_eq!(
            split_host_port("h:notaport"),
            ("h:notaport".to_string(), 443)
        );
    }

    #[tokio::test]
    async fn upload_2xx_consumes_batch_5xx_restores() {
        let dir = test_dir(line!());
        let sink = DiagSink::new(&dir, "app").unwrap();
        for _ in 0..3 {
            sink.push(DiagEvent::new(DiagLevel::Info, "app", "test.up"));
        }
        sink.flush_writer().await;
        let lines = sink.take_spool_batch(usize::MAX).unwrap();
        assert_eq!(lines.len(), 3);

        // 200 → the batch is consumed (nothing to restore); spool stays empty.
        let (status, sent) = run_post(b"HTTP/1.1 200 OK\r\n\r\n{}", &[], b"{}").await;
        assert_eq!(status.unwrap(), 200);
        assert!(sent.starts_with("POST /v1/logs"));
        assert_eq!(
            std::fs::read_to_string(dir.join("diagnostics.jsonl")).unwrap(),
            ""
        );

        // 503 → the loop's contract is restore_batch; simulate it and verify.
        let (status, _) = run_post(b"HTTP/1.1 503 Service Unavailable\r\n\r\n", &[], b"{}").await;
        assert_eq!(status.unwrap(), 503);
        sink.restore_batch(&lines);
        let restored = sink.take_spool_batch(usize::MAX).unwrap();
        assert_eq!(restored, lines, "restored batch must round-trip intact");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn spool_lines_roundtrip_to_otlp() {
        let dir = test_dir(line!());
        let sink = DiagSink::new(&dir, "app").unwrap();
        let mut ev = DiagEvent::new(DiagLevel::Warn, "app", "unbounded.geo_failed");
        ev.session = Some("s1".into());
        ev.insert_str("reason", "timeout");
        sink.push(ev);
        sink.flush_writer().await;

        let lines = sink.take_spool_batch(usize::MAX).unwrap();
        let events = parse_spool(&lines);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "unbounded.geo_failed");
        assert_eq!(events[0].level, DiagLevel::Warn);

        let q = SpanQueue::new();
        q.set_trace_ctx("s1", (*b"0123456789abcdef", *b"01234567"));
        let body = encode_spool_logs(&test_res(), &events, |s| q.trace_ctx_for(s));
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let rec = &v["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];
        assert_eq!(rec["severityText"], "WARN");
        assert_eq!(rec["body"]["stringValue"], "unbounded.geo_failed");
        assert_eq!(rec["traceId"], "30313233343536373839616263646566");
        assert_eq!(rec["spanId"], "3031323334353637");
        let ra = rec["attributes"].as_array().unwrap();
        assert!(ra.iter().any(|a| a["key"] == "reason"));

        // Unparseable lines are skipped, not fatal.
        let mixed = vec![lines[0].clone(), "not json".to_string()];
        assert_eq!(parse_spool(&mixed).len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn span_queue_bounds_and_ctx() {
        let q = SpanQueue::new();
        let mk = |i: u64| DiagSpan {
            trace_id: [0; 16],
            span_id: [0; 8],
            parent_span_id: None,
            name: "x",
            start_unix_nano: i,
            end_unix_nano: i,
            error: None,
            attrs: Default::default(),
        };
        q.push_spans((0..600).map(mk).collect());
        let drained = q.drain();
        assert_eq!(drained.len(), MAX_QUEUED_SPANS);
        // Oldest dropped: the survivors are the most recent 512.
        assert_eq!(drained[0].start_unix_nano, 600 - MAX_QUEUED_SPANS as u64);

        q.set_trace_ctx("s", (*b"0123456789abcdef", *b"01234567"));
        assert!(q.trace_ctx_for("s").is_some());
        q.remove_trace_ctx("s");
        assert!(q.trace_ctx_for("s").is_none());
    }

    #[test]
    fn backoff_is_quadratic_and_capped() {
        assert_eq!(backoff(1), Duration::from_millis(10));
        assert_eq!(backoff(2), Duration::from_millis(40));
        assert_eq!(backoff(10_000), Duration::from_millis(120_000));
    }
}
