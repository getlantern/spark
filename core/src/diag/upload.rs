//! The diagnostics uploader (design §C3/§C4): ships spool batches as OTLP/HTTP JSON
//! logs — and queued session spans as traces — to the config-delivered otel endpoint.
//!
//! **Delivery is a race, not a dial** ([`diag_kindling`], #165). Telemetry goes out over the same
//! kindling machinery the config fetch uses — direct, proxyless, and the vantage-point scanner —
//! because the client with the most to report is the one that cannot reach anything, and a
//! direct-only uploader is silent exactly there. The dns-tunnel member is deliberately *not*
//! among them; see [`diag_kindling`] for why that one is different in kind.
//!
//! Every member is TLS, and the module only compiles under `feature = "config-fetch"` — so the
//! real (boring) `tls_wrap` is always in play and a build whose `tls_wrap` degrades to the no-op
//! passthrough cannot contain this uploader. A plaintext upload stays impossible by construction.
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

use bytes::Bytes;
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
/// How long a retired trace ctx stays queryable ([`SpanQueue::retire_trace_ctx`]):
/// 2.5 ticks — the batch holding a session's final spool lines has shipped by then.
const RETIRE_GRACE: Duration = Duration::from_secs(150);

/// A session's OTLP correlation pair: (trace id, root span id) — what
/// [`super::otlp::encode_spool_logs`] stamps onto that session's log records (§C3a).
pub type TraceCtx = ([u8; 16], [u8; 8]);

/// Finished spans awaiting ship, plus the session → [`TraceCtx`] registry used to
/// stamp log records with their session's trace context (§C3a).
///
/// The instrumentation side (the plugin's aggregation loop) registers a context at
/// session start and *retires* it after the session's spans are pushed; the uploader
/// prunes retired entries once their grace period lapses ([`Self::prune_retired`]).
/// Entries are therefore bounded by the live sessions plus a grace window of
/// recently ended ones.
pub struct SpanQueue {
    spans: Mutex<Vec<DiagSpan>>,
    ctx: Mutex<HashMap<String, TraceCtx>>,
    retired: Mutex<Vec<(String, std::time::Instant)>>,
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
            retired: Mutex::new(Vec::new()),
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

    /// Immediately drop a session's trace context. For tests/immediate use;
    /// production paths [`retire`][Self::retire_trace_ctx] instead.
    pub fn remove_trace_ctx(&self, session: &str) {
        lock(&self.ctx).remove(session);
    }

    /// Retire a session's trace context: mark it for removal but leave the `ctx`
    /// entry queryable for a grace period. The session's final spool lines
    /// (including the disconnect event itself) are encoded on a LATER uploader
    /// tick — removing the ctx immediately would strand them without correlation.
    /// [`Self::prune_retired`] performs the actual removal once the grace lapses.
    pub fn retire_trace_ctx(&self, session: &str) {
        lock(&self.retired).push((session.to_string(), std::time::Instant::now()));
    }

    /// Retire every live trace context (see [`Self::retire_trace_ctx`]) — for pool
    /// stop, where the per-session `Stopped` events may never arrive.
    pub fn retire_all_ctxs(&self) {
        let now = std::time::Instant::now();
        let mut retired = lock(&self.retired);
        for session in lock(&self.ctx).keys() {
            retired.push((session.clone(), now));
        }
    }

    /// Remove retired contexts older than `max_age`, keeping younger ones
    /// queryable. Lock order: `retired` then `ctx`; both sync, never held across
    /// an await.
    pub fn prune_retired(&self, max_age: Duration) {
        let mut retired = lock(&self.retired);
        if retired.is_empty() {
            return;
        }
        let mut ctx = lock(&self.ctx);
        retired.retain(|(session, at)| {
            if at.elapsed() < max_age {
                return true;
            }
            ctx.remove(session);
            false
        });
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
///
/// Deliberate asymmetry: `otel.logs` gates ALL uploads — `otel.traces` alone ships
/// nothing. Logs are the primary diagnostic signal; a trace without its correlated
/// log records is an orphan, so traces ride only alongside an enabled log stream.
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
/// `config::fetch::request::build_request_bytes`; every config-derived value — the
/// `Host` (from the server-delivered `otel.endpoint`) as well as each configured
/// header — is CRLF-stripped (`header_safe`) so a corrupt config can't inject
/// request framing. `path` is a compile-time constant at every production call site.
pub fn build_upload_request(
    host: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Vec<u8> {
    let mut head = String::new();
    head.push_str(&format!("POST {path} HTTP/1.1\r\n"));
    head.push_str(&format!("Host: {}\r\n", header_safe(host)));
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
    // Built on first use and reused across cycles — see `Avenues`.
    let mut avenues: Option<Avenues> = None;
    loop {
        if fail > 0 {
            // Backing off: sleep the full quadratic delay WITHOUT the error-notify
            // shortcut. A sustained failure typically keeps generating error events,
            // and letting each one cut the wait short would void the backoff into a
            // sub-second hammer on a dead endpoint. §C2a expedited flush applies to
            // the healthy path only.
            sleep_or_stop(crate::backoff::with_jitter(fail), &stop).await;
        } else {
            wait_wakeup(&notify, &stop, TICK).await;
        }
        if stop.load(Ordering::Relaxed) {
            return;
        }
        // Fall back to the build-time block when config-new has delivered nothing. Without this
        // the uploader is gated on the very fetch whose failure it most needs to report — see
        // `lantern::embedded_otel`.
        let cfg = crate::config::lantern::effective_otel(cfg_rx.borrow_and_update().clone());
        if !upload_allowed(cfg.as_ref(), local_opt_out, &device_id) {
            // Off: leave the spool accumulating (its rotation cap bounds disk, §C2)
            // and re-check the gate next tick — the server may flip it back on.
            continue;
        }
        let Some(otel) = cfg else { continue };

        // Build the avenues on first use, and rebuild only if the config re-points the endpoint at
        // a different host — otherwise proxyless would lose its learned strategy every cycle.
        let (host, port) = split_host_port(&otel.endpoint);
        if avenues.as_ref().is_none_or(|a| a.host != host) {
            avenues = Some(Avenues {
                kindling: diag_kindling(&host, port, &device_id),
                host,
            });
        }
        // Set immediately above; `continue` rather than unwrap keeps the loop's no-panic contract.
        let Some(avenues) = avenues.as_ref() else {
            continue;
        };

        // Logs: take a batch, replay it as OTLP, restore it on any failure.
        match sink.take_spool_batch(BATCH_BYTES) {
            Ok(lines) if !lines.is_empty() => {
                let events = parse_spool(&lines);
                if !events.is_empty() {
                    let body = encode_spool_logs(&res, &events, |s| spans.trace_ctx_for(s));
                    match try_post(avenues, &otel, "/v1/logs", &body).await {
                        Ok(status) if (200..300).contains(&status) => {
                            fail = 0;
                            // Ended sessions' ctx entries outlive them by RETIRE_GRACE
                            // so their final spool lines (encoded above, possibly on a
                            // later tick than the retirement) keep their correlation.
                            spans.prune_retired(RETIRE_GRACE);
                        }
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
                match try_post(avenues, &otel, "/v1/traces", &body).await {
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

/// Sleep `d`, returning within ~1 s of `stop` flipping (mirrors
/// `config::fetch::sleep_or_stop`). Used for the backoff path, where error
/// notifications must NOT shorten the wait.
async fn sleep_or_stop(d: Duration, stop: &AtomicBool) {
    let step = Duration::from_secs(1);
    let mut left = d;
    while left > Duration::ZERO && !stop.load(Ordering::Relaxed) {
        let s = left.min(step);
        tokio::time::sleep(s).await;
        left = left.saturating_sub(s);
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
///
/// Skipped lines are dropped from the upload queue BY DESIGN, not restored: they will
/// never parse, so restoring them would poison every future batch into an endless
/// take→fail→restore churn. The backup log (`diag.log`) retains the raw bytes for
/// forensics — the one deliberate exception to the sink's duplicates-over-loss rule.
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

/// The direct dial to the otel host, as a race member so it shares one race with the
/// censorship-resistant avenues instead of being the only way out.
///
/// A near-twin of `config::fetch`'s `DirectConfigTransport`, kept local for the reason
/// its `resolve` is: the shared thing would be six lines, and coupling the uploader to
/// a fetch internal costs more than the duplication.
struct DirectDiagTransport {
    port: u16,
}

#[async_trait::async_trait]
impl flint_kindling::ConnectionTransport for DirectDiagTransport {
    type Stream = crate::BoxedStream;

    fn name(&self) -> &str {
        "direct"
    }

    async fn connect(&self, host: &str) -> io::Result<Self::Stream> {
        let addr = resolve(host, self.port).await?;
        let stream = DirectTransport::new(None).dial(addr).await?;
        Ok(Box::new(tls_wrap(stream, host).await?))
    }

    // `connect_alpn` deliberately not overridden — `tls_wrap` offers no ALPN, so `None` is
    // accurate rather than a gap, and flint reads it as HTTP/1.1. Same as the config member.
}

/// The upload avenues for one otel host, built once and reused across cycles.
///
/// Reuse is the point, not just an optimization: proxyless's `StrategyCache` keeps whichever
/// resolver × shaping pair beat the local network, so rebuilding per upload would re-run the
/// search every minute.
struct Avenues {
    /// The host these avenues were built for; a config that re-points the endpoint rebuilds them.
    host: String,
    kindling: flint_kindling::Kindling,
}

/// Build the diagnostics upload race for `host` (#165).
///
/// **Why race at all.** The uploader used to dial direct only, which quietly excluded the
/// population whose telemetry is worth the most: a client that cannot reach the network cannot
/// report that it cannot reach the network. The spool persists across failed sends and restarts,
/// so this converts a permanently-lost signal into a delayed one.
///
/// **Members.** `direct`, `proxyless` (an un-poisoned resolver plus opening shaping), and the
/// vantage-point scanner, which discovers live CDN edges from the user's own network and so needs
/// no server-delivered front list for this host.
///
/// **Two deliberate omissions.**
///
/// * The **embedded fronted list** (`fronted.yaml.gz`) is keyed to the config host. Fronting the
///   otel host through it needs a server-side entry in `host_aliases`/`passthrough_patterns`;
///   until that exists the member could only ever fail, and racing a member that structurally
///   cannot win is noise in the logs, not resilience. One line to add once the entry lands.
/// * The **dns-tunnel** is excluded on purpose, and this is the load-bearing one. It is the
///   last-resort tier — it needs only that recursive DNS resolves at all — and it moves KB/s. A
///   256 KiB diag batch through it is minutes of hammering public resolvers, for diagnostics.
///   That tier is reserved for *reachability*: bootstrap must never be degraded to deliver
///   telemetry. Note this is an omission by construction, not a runtime check — the member is
///   simply never registered here, so no future config can turn it on by accident.
fn diag_kindling(host: &str, port: u16, device_id: &str) -> flint_kindling::Kindling {
    #[cfg_attr(not(feature = "proxyless"), allow(unused_mut))]
    let mut kindling = flint_kindling::Kindling::new().with_transport(DirectDiagTransport { port });
    #[cfg(feature = "proxyless")]
    {
        kindling = kindling.with_proxyless(crate::config::fetch::proxyless_transport_for(
            port,
            "diag-upload",
        ));
    }
    kindling = kindling.with_transport(
        flint_kindling::FrontedBootstrap::new(host.to_string())
            .with_seed(crate::config::fetch::seed_from_device_id(device_id)),
    );
    // Every member starts together, as in the config race: there is no tail to stagger at this
    // size, and holding one back would add its latency to the blocked case this exists for.
    let window = kindling.transport_count().max(1);
    kindling.with_race_options(flint_kindling::RaceOptions {
        window,
        attempt_timeout: Some(CONNECT_TIMEOUT),
    })
}

/// Ceiling on the connection race, leaving the rest of [`ATTEMPT_TIMEOUT`] for the HTTP exchange
/// that runs after a member wins. Mirrors `config::fetch`'s split, for the same reason: a connect
/// that consumed the whole window would leave nothing to send the batch with.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// How long one upload attempt gets, connection race included.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(30);

/// One upload attempt: race the avenues, then speak to the winner on **its** terms — HTTP/1.1 or
/// h2, and the winner's own authority, both read off the connection rather than assumed.
///
/// The members disagree on each and the disagreement is invisible from here: `direct` goes through
/// spark's ALPN-less connector and lands on HTTP/1.1, while the scanner goes through flint's Chrome
/// connector, which must offer `h2,http/1.1` because ALPN is part of the fingerprint it imitates —
/// and the peer chooses. Writing HTTP/1.1 at an h2 peer does not fail like an HTTP error; the
/// response simply never terminates, which is how an earlier proxyless avenue was silently broken.
async fn try_post(
    avenues: &Avenues,
    otel: &OtelConfig,
    path: &str,
    body: &[u8],
) -> io::Result<u16> {
    tokio::time::timeout(ATTEMPT_TIMEOUT, async {
        let conn = avenues
            .kindling
            .connect(&avenues.host)
            .await
            .map_err(io::Error::from)?;
        // A fronted winner must name the front's inner host so the edge re-originates; a direct
        // one has no opinion and falls back to the host we asked for. CRLF-stripped because this
        // is no longer a constant — a scanned authority comes from a live scan.
        let authority = header_safe(conn.authority(&avenues.host)).into_owned();
        if conn.is_h2() {
            let mut req = flint_kindling::OneshotRequest::post(path, Bytes::copy_from_slice(body))
                .header("content-type", "application/json");
            for (k, v) in &otel.headers {
                req = req.header(header_safe(k).into_owned(), header_safe(v).into_owned());
            }
            // Same 64 KiB response cap as the 1.1 path: OTLP ingest replies are tiny.
            req.max_body = MAX_RESPONSE_BYTES;
            let resp = flint_kindling::h2_oneshot(conn.stream, &authority, &req).await?;
            Ok(resp.status)
        } else {
            post_body(conn.stream, &authority, path, &otel.headers, body).await
        }
    })
    .await
    .map_err(|_| io::Error::other("diag upload timed out"))?
}

/// Cap on a collected upload response. OTLP ingest replies are tiny (empty JSON or a status body).
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

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
/// defaulting to 443 when no valid port is present. A bracketed IPv6 literal
/// (`[::1]:443`) parses via `SocketAddr` and returns the UNbracketed address, which
/// is what [`resolve`]'s `IpAddr` fast-path expects.
fn split_host_port(endpoint: &str) -> (String, u16) {
    if let Ok(sa) = endpoint.parse::<std::net::SocketAddr>() {
        return (sa.ip().to_string(), sa.port());
    }
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
        // Deliberate asymmetry: traces alone (logs off) ship NOTHING — logs are the
        // primary signal and gate all uploads. Don't "fix" without reading the
        // upload_allowed doc.
        let mut traces_only = test_otel("h:443", false, 1.0);
        traces_only.traces_enabled = true;
        assert!(
            !upload_allowed(Some(&traces_only), false, did),
            "otel.traces without otel.logs must not upload"
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
    fn host_header_strips_crlf() {
        // `host` derives from the server-delivered `otel.endpoint`; a CRLF smuggled
        // through a malformed/compromised config must not inject request framing.
        let s = String::from_utf8(build_upload_request(
            "evil.test\r\nX-Injected: 1",
            "/v1/logs",
            &[],
            b"{}",
        ))
        .unwrap();
        assert!(s.contains("Host: evil.testX-Injected: 1\r\n"));
        assert!(
            !s.contains("\r\nX-Injected:"),
            "CRLF in the Host value must not inject a header"
        );
    }

    #[test]
    fn endpoint_split() {
        assert_eq!(
            split_host_port("ingest.us.signoz.cloud:443"),
            ("ingest.us.signoz.cloud".to_string(), 443)
        );
        assert_eq!(split_host_port("bare.host"), ("bare.host".to_string(), 443));
        // Bracketed IPv6 → unbracketed address (what resolve's IpAddr fast-path wants).
        assert_eq!(split_host_port("[::1]:8443"), ("::1".to_string(), 8443));
        assert_eq!(
            split_host_port("h:notaport"),
            ("h:notaport".to_string(), 443)
        );
    }

    /// The upload race carries exactly the members it is meant to — and in particular does not
    /// grow a dns-tunnel one.
    ///
    /// `Kindling` exposes a count but not its members' names, so this pins the count. That is
    /// enough for what it guards: registering the dns-tunnel member (or any other) changes the
    /// count, and the failure message says what the change has to be checked against. The
    /// exclusion itself is structural — `diag_kindling` never constructs one — so this test exists
    /// to make a *future* addition deliberate rather than to detect a runtime toggle.
    ///
    /// Why it matters, from #165: the dns-tunnel is the last-resort reachability tier and moves
    /// KB/s. A 256 KiB diag batch through it is minutes of hammering public resolvers, spending
    /// the bootstrap path on telemetry.
    #[test]
    fn the_upload_race_excludes_the_dns_tunnel() {
        let kindling = diag_kindling("ingest.example", 443, "0123456789abcdef");
        // direct + the vantage-point scanner, plus proxyless where the feature is on.
        let expected = if cfg!(feature = "proxyless") { 3 } else { 2 };
        assert_eq!(
            kindling.transport_count(),
            expected,
            "the diag upload race changed shape — if a member was added, confirm it is not the \
             dns-tunnel (it must never carry telemetry; see diag_kindling)"
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
    fn retired_ctx_grace() {
        let q = SpanQueue::new();
        let ctx = (*b"0123456789abcdef", *b"01234567");
        q.set_trace_ctx("s1", ctx);
        q.set_trace_ctx("s2", ctx);

        // Retirement keeps the ctx queryable (the session's final spool lines are
        // encoded on a later uploader tick)...
        q.retire_trace_ctx("s1");
        assert!(q.trace_ctx_for("s1").is_some(), "retire must not remove");
        // ...through a within-grace prune...
        q.prune_retired(Duration::from_secs(3600));
        assert!(q.trace_ctx_for("s1").is_some(), "young entry must survive");
        // ...until the grace lapses.
        q.prune_retired(Duration::ZERO);
        assert!(q.trace_ctx_for("s1").is_none(), "expired entry pruned");
        assert!(
            q.trace_ctx_for("s2").is_some(),
            "unretired ctx must survive prune"
        );

        // retire_all_ctxs retires every live key (pool stop).
        q.retire_all_ctxs();
        assert!(q.trace_ctx_for("s2").is_some());
        q.prune_retired(Duration::ZERO);
        assert!(q.trace_ctx_for("s2").is_none());
    }

    /// Upload retry pacing is [`crate::backoff`]'s, shared with the config refresh loop — the curve
    /// is asserted there. This pins the wiring only.
    #[test]
    fn failure_delay_comes_from_the_shared_jittered_backoff() {
        for fail in [1u32, 5, 99] {
            let (lo, hi) = crate::backoff::bounds(fail);
            assert!((lo..=hi).contains(&crate::backoff::with_jitter(fail)));
        }
    }
}
