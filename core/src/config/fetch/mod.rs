//! Fetch Spark's server pool from the Lantern `config-new` API (design:
//! `docs/config-new-fetch-design.md`). A direct plain-TLS request is raced against two domain-fronted
//! one-shot avenues for censored cold-start resilience: the embedded `fronted.yaml.gz` list (a
//! known-good accelerator) and the vantage-point scanner (`flint_kindling::FrontedBootstrap`), which
//! discovers live edges from the user's own network and so self-heals when the embedded list is fully
//! blocked. Free-tier, disk-cached, fed into [`crate::config::Config::from_config_str`]. Trust is
//! TLS — no signature, matching radiance.

// cache is pub(crate): `diag::tunnel_host` re-parses the cached `config_raw.json`
// (via `cache::raw_path`) to feed its uploader's config watch channel.
pub(crate) mod cache;
// http + request are pub(crate): the diag uploader (`diag::upload`) reuses the same
// hand-rolled HTTP/1.1 POST + header hygiene for its OTLP uploads.
pub(crate) mod http;
pub(crate) mod request;
mod user;

use std::path::Path;
use std::time::Duration;

use ring::rand::{SecureRandom, SystemRandom};

/// Read the persisted device id from `{dir}/device_id`, or generate + persist a fresh one (16 random
/// bytes, lowercase hex). Stable across runs once written.
pub fn device_id(dir: &Path) -> std::io::Result<String> {
    let path = dir.join("device_id");
    if let Ok(s) = std::fs::read_to_string(&path) {
        let s = s.trim().to_string();
        if !s.is_empty() {
            return Ok(s);
        }
    }
    let mut bytes = [0u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| std::io::Error::other("device_id rng failed"))?;
    let id = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    std::fs::create_dir_all(dir)?;
    std::fs::write(&path, &id)?;
    Ok(id)
}

/// Choose the sleep before the next poll on a *successful* fetch: the server's `poll_interval_seconds`
/// clamped to a ≥10s floor, or the 10-minute default when the server gives 0/none.
pub fn poll_after(server_seconds: u64) -> Duration {
    const MIN: u64 = 10;
    const DEFAULT: u64 = 600;
    if server_seconds == 0 {
        Duration::from_secs(DEFAULT)
    } else {
        Duration::from_secs(server_seconds.max(MIN))
    }
}

use crate::config::fetch::cache::CacheMeta;
use crate::config::fetch::http::post_collect;
use crate::config::fetch::request::{
    build_oneshot_request, build_request_bytes, Conditional, ConfigRequest,
};
use crate::config::Config;
use crate::transport::{probe::tls_wrap, DirectTransport, Transport};
use flint_fronted::{FlintDnsResolver, FrontedTlsDialer};
use flint_kindling::FrontedBootstrap;

/// Where to fetch from: prod is `df.iantem.io`, staging is `api.staging.iantem.io`. The host is
/// dialed both directly and (for prod, which the embedded fronted config maps) through the fronting
/// providers; the fetch races the two.
#[derive(Debug, Clone)]
pub struct FetchEnv {
    pub host: String,
    pub path: String,
    pub port: u16,
    /// Pro/account host for the `/user-create` pre-step (a *different* host than config-new). Port 443.
    pub pro_host: String,
    pub pro_path: String,
}

impl FetchEnv {
    pub fn prod() -> Self {
        FetchEnv {
            host: "df.iantem.io".into(),
            path: "/api/v1/config-new".into(),
            port: 443,
            pro_host: "api.getiantem.org".into(),
            pro_path: "/user-create".into(),
        }
    }
    pub fn staging() -> Self {
        FetchEnv {
            host: "api.staging.iantem.io".into(),
            path: "/v1/config-new".into(),
            port: 443,
            pro_host: "api.staging.iantem.io".into(),
            pro_path: "/pro-server/user-create".into(),
        }
    }
    /// Select via `SPARK_CONFIG_ENV=staging`, else prod.
    pub fn from_env() -> Self {
        Self::select(std::env::var("SPARK_CONFIG_ENV").ok().as_deref())
    }
    /// Pure selector behind [`from_env`](Self::from_env): `Some("staging")` → staging, else prod.
    /// Split out so the choice is testable without mutating process-global env (parallel-test-safe).
    fn select(env_value: Option<&str>) -> Self {
        match env_value {
            Some("staging") => Self::staging(),
            _ => Self::prod(),
        }
    }
}

/// Result of one fetch attempt.
#[derive(Debug)]
pub enum FetchOutcome {
    /// New config body + the response `ETag` (for the next conditional request).
    New { raw: String, etag: Option<String> },
    /// Server says nothing changed (304/204) — keep the cache.
    NotModified,
}

/// A boxed config-fetch attempt, borrowing the request/env/dialer for the duration of the race.
type FetchAttempt<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<FetchOutcome>> + Send + 'a>>;

/// One config-new fetch: race a direct plain-TLS request against the fronted avenues, returning the
/// first usable outcome. Direct typically wins on an open network; the fronted paths win where the
/// direct dial is censored (DNS poisoning / SNI block / RST). Two fronted avenues run when available:
/// the embedded `fronted.yaml.gz` one-shot (a known-good accelerator) and the vantage-point scanner
/// (`bootstrap`), which discovers live edges from the user's own network and so self-heals when the
/// embedded front list is fully blocked.
async fn fetch_once(
    env: &FetchEnv,
    device_id: &str,
    creds: &user::Creds,
    cond: &Conditional,
    fronted: Option<&FrontedTlsDialer<FlintDnsResolver>>,
    bootstrap: Option<&FrontedBootstrap>,
) -> std::io::Result<FetchOutcome> {
    const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(30);

    let mut req = ConfigRequest::new(device_id.to_string());
    req.user_id = creds.user_id.clone();
    req.pro_token = creds.pro_token.clone();

    let mut attempts: Vec<FetchAttempt<'_>> = Vec::with_capacity(3);
    attempts.push(Box::pin(with_outcome(
        "direct",
        Box::pin(fetch_once_direct(env, &req, cond, ATTEMPT_TIMEOUT)),
    )));
    if let Some(dialer) = fronted {
        attempts.push(Box::pin(with_outcome(
            "fronted",
            Box::pin(fetch_once_fronted(env, &req, cond, dialer, ATTEMPT_TIMEOUT)),
        )));
    }
    if let Some(b) = bootstrap {
        attempts.push(Box::pin(with_outcome(
            "scanned",
            Box::pin(fetch_once_scanned(env, &req, cond, b, ATTEMPT_TIMEOUT)),
        )));
    }
    first_ok(attempts).await
}

/// Wrap one avenue's fetch future so its outcome (ok / not_modified / error) and
/// latency land in the diagnostics stream (§C6 `config.fetch_outcome`). Instrumented
/// here in `fetch_once` — one point covering all three avenues — rather than inside
/// each avenue fn. An avenue cancelled by losing the race emits nothing (it never
/// completes), which is the intent: only real outcomes are reported.
async fn with_outcome<'a>(
    avenue: &'static str,
    fut: FetchAttempt<'a>,
) -> std::io::Result<FetchOutcome> {
    let start = std::time::Instant::now();
    let result = fut.await;
    let latency_ms = start.elapsed().as_millis() as u64;
    crate::diag::emit(crate::diag::events::config_fetch_outcome(
        outcome_label(&result),
        avenue,
        latency_ms,
    ));
    result
}

/// The `result` label for a §C6 `config.fetch_outcome` event.
fn outcome_label(r: &std::io::Result<FetchOutcome>) -> &'static str {
    match r {
        Ok(FetchOutcome::New { .. }) => "ok",
        Ok(FetchOutcome::NotModified) => "not_modified",
        Err(_) => "error",
    }
}

/// The direct path: dial the API host directly, plain-boring TLS-wrap, send the HTTP/1.1 request, and
/// collect the response. Bounded by `timeout` (`post_collect` reads to EOF with no internal timeout).
async fn fetch_once_direct(
    env: &FetchEnv,
    req: &ConfigRequest,
    cond: &Conditional,
    timeout: Duration,
) -> std::io::Result<FetchOutcome> {
    let bytes =
        build_request_bytes(&env.host, &env.path, req, cond).map_err(std::io::Error::other)?;
    let resp = tokio::time::timeout(timeout, async {
        let addr = resolve(&env.host, env.port).await?;
        let stream = DirectTransport::new(None).dial(addr).await?;
        let tls = tls_wrap(stream, &env.host).await?;
        post_collect(tls, &bytes, 4 * 1024 * 1024).await
    })
    .await
    .map_err(|_| std::io::Error::other("config-new direct fetch timed out"))??;
    map_response(resp.status, resp.etag, resp.body)
}

/// The fronted path: run the config-new request as a one-shot h2 request over `dialer` (the fronting
/// providers from the embedded config). The provider addresses its fronted host and presents a decoy
/// SNI; the response is mapped exactly like the direct path. Bounded by `timeout`.
async fn fetch_once_fronted(
    env: &FetchEnv,
    req: &ConfigRequest,
    cond: &Conditional,
    dialer: &FrontedTlsDialer<FlintDnsResolver>,
    timeout: Duration,
) -> std::io::Result<FetchOutcome> {
    let oneshot = build_oneshot_request(&env.path, req, cond).map_err(std::io::Error::other)?;
    let resp = tokio::time::timeout(timeout, dialer.request(&env.host, &oneshot))
        .await
        .map_err(|_| std::io::Error::other("config-new fronted fetch timed out"))?
        .map_err(std::io::Error::other)?;
    let etag = resp.header("etag").map(ToOwned::to_owned);
    map_response(resp.status, etag, resp.body)
}

/// The scanner path: run the config-new request as a one-shot through `bootstrap`, which discovers
/// working fronts from the user's *own* network (Akamai local-DNS + CloudFront/Aliyun sampling) and
/// caches the winner. Self-bootstrapping — needs no embedded/server front list, so it self-heals when
/// the embedded list is fully blocked. Bounded by `timeout`.
async fn fetch_once_scanned(
    env: &FetchEnv,
    req: &ConfigRequest,
    cond: &Conditional,
    bootstrap: &FrontedBootstrap,
    timeout: Duration,
) -> std::io::Result<FetchOutcome> {
    let oneshot = build_oneshot_request(&env.path, req, cond).map_err(std::io::Error::other)?;
    let resp = tokio::time::timeout(timeout, bootstrap.request(&oneshot))
        .await
        .map_err(|_| std::io::Error::other("config-new scanned fetch timed out"))??;
    let etag = resp.header("etag").map(ToOwned::to_owned);
    map_response(resp.status, etag, resp.body)
}

/// Map an HTTP status + `ETag` + body into a [`FetchOutcome`] (shared by the direct and fronted paths).
fn map_response(status: u16, etag: Option<String>, body: Vec<u8>) -> std::io::Result<FetchOutcome> {
    match status {
        200 | 206 => {
            let raw = String::from_utf8(body)
                .map_err(|_| std::io::Error::other("config-new body not UTF-8"))?;
            Ok(FetchOutcome::New { raw, etag })
        }
        304 | 204 => Ok(FetchOutcome::NotModified),
        other => Err(std::io::Error::other(format!("config-new HTTP {other}"))),
    }
}

/// Race several fetch attempts, returning the first that succeeds; if all fail, return the last error.
/// Unlike a plain `select!`, an early *failure* doesn't end the race — the remaining attempts still
/// run, so a censored direct dial doesn't pre-empt the fronted ones (and vice versa).
async fn first_ok(mut attempts: Vec<FetchAttempt<'_>>) -> std::io::Result<FetchOutcome> {
    let mut last_err = std::io::Error::other("no config-new fetch attempt ran");
    while !attempts.is_empty() {
        let (result, _idx, remaining) = futures::future::select_all(attempts).await;
        match result {
            Ok(outcome) => return Ok(outcome),
            Err(e) => {
                last_err = e;
                attempts = remaining;
            }
        }
    }
    Err(last_err)
}

/// Build the fronted dialer from the embedded `domainfront/fronted.yaml.gz` (aliyun/akamai/cloudfront).
/// `None` (→ direct-only fetch) only if the embedded config fails to parse, which shouldn't happen.
/// The empty country code selects each provider's `default` SNI bucket (e.g. aliyun's `img.alicdn.com`),
/// matching the production client, which passes no country code.
pub(crate) fn fronted_dialer() -> Option<FrontedTlsDialer<FlintDnsResolver>> {
    const FRONTED_CONFIG_GZ: &[u8] = include_bytes!("fronted.yaml.gz");
    match FrontedTlsDialer::from_gzipped_config_with_default_dns(FRONTED_CONFIG_GZ, "", "") {
        Ok(dialer) => Some(dialer),
        Err(e) => {
            tracing::warn!(err = %e, "config-fetch: embedded fronted config failed to parse; direct-only");
            None
        }
    }
}

/// Build the self-bootstrapping fronted requester for the config API host. Fronts to `env.host`
/// directly via scanner-discovered edges (Akamai local-DNS + CloudFront/Aliyun sampling): a CDN that
/// doesn't re-originate the host just loses the race, so this is safe to always race and self-heals
/// whichever CDN does front it — the one avenue that can find a working edge when the embedded list is
/// fully blocked. `seed` (from the device id) diversifies CloudFront/Aliyun sampling across devices;
/// the Akamai local-DNS path is seed-independent.
fn fronted_bootstrap(env: &FetchEnv, seed: u64) -> FrontedBootstrap {
    FrontedBootstrap::new(env.host.clone()).with_seed(seed)
}

/// A stable per-device u64 seed from the hex device id (first 16 hex chars), for front-sampling
/// diversity. Falls back to 0 if the id is too short / non-hex (the Akamai path is unaffected).
/// `pub(crate)` so the smart-routing rule-set fetcher reuses the same per-device seed.
pub(crate) fn seed_from_device_id(did: &str) -> u64 {
    u64::from_str_radix(did.get(..16).unwrap_or(""), 16).unwrap_or(0)
}

/// Resolve a host:port to a socket address (IP literal fast-path, else system resolver). Deliberately
/// a small local copy of `transport::probe::resolve_callback_addr` rather than a shared helper —
/// it's 8 lines of trivial std/tokio DNS, and keeping it local avoids coupling `config::fetch` to a
/// `probe` internal (the names also differ by intent: "config host" vs "callback host").
async fn resolve(host: &str, port: u16) -> std::io::Result<std::net::SocketAddr> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(std::net::SocketAddr::new(ip, port));
    }
    tokio::net::lookup_host((host, port))
        .await?
        .next()
        .ok_or_else(|| {
            std::io::Error::other(format!("config host `{host}` resolved to no addresses"))
        })
}

/// Bootstrap a [`Config`] for connect: **always fetch fresh and overwrite the cache**, using the
/// last-good cache only as an offline fallback (not as a way to skip the fetch). So a cached copy never
/// suppresses the fetch — you get the latest pool on every connect, and the cache is the safety net
/// when the network/API is unavailable. Errors only when the fetch fails AND there's no usable cache
/// (cold start offline). Returns the adapted Config + meta.
pub async fn load_or_fetch(dir: &Path, env: &FetchEnv) -> std::io::Result<(Config, CacheMeta)> {
    let did = device_id(dir)?;
    let cached = cache::load(dir); // for the offline fallback below; does NOT short-circuit the fetch
                                   // config-new requires account creds; mint them once via /user-create (persisted, reused). If we
                                   // can't (first run offline) but have a usable cache, use it.
    let creds = match user::ensure_user(dir, &env.pro_host, &env.pro_path).await {
        Ok(c) => c,
        Err(e) => return cached_or_err(cached, e),
    };
    // Unconditional fetch (no If-None-Match): every connect pulls the current config and overwrites.
    // Race the direct request against both fronted avenues (embedded list + vantage-point scanner) for
    // censored cold-start resilience.
    let fronted = fronted_dialer();
    let bootstrap = fronted_bootstrap(env, seed_from_device_id(&did));
    match fetch_once(
        env,
        &did,
        &creds,
        &Conditional::default(),
        fronted.as_ref(),
        Some(&bootstrap),
    )
    .await
    {
        Ok(FetchOutcome::New { raw, etag }) => {
            let cfg = Config::from_config_str(&raw).map_err(std::io::Error::other)?;
            let meta = CacheMeta {
                etag,
                last_modified: None,
                poll_interval_seconds: server_poll_seconds(&raw),
            };
            cache::store(dir, &raw, &meta)?; // overwrite the old copy
            tracing::info!(
                servers = cfg.transport.servers.len(),
                bytes = raw.len(),
                "config-fetch: fetched fresh config, cache overwritten"
            );
            Ok((cfg, meta))
        }
        // We send no conditional, so a 304 isn't expected; fall back to the cache defensively.
        Ok(FetchOutcome::NotModified) => cached_or_err(
            cached,
            std::io::Error::other("config-new 304 with no cache"),
        ),
        Err(e) => cached_or_err(cached, e), // offline / API error → last-good cache
    }
}

/// Offline fallback for [`load_or_fetch`]: use the last-good cached config if it's present and still
/// adapts, otherwise return `err` (the fetch failure). Keeps connect working through outages without
/// letting a stale cache hide a reachable, changed config (the live fetch always runs first).
fn cached_or_err(
    cached: Option<(String, CacheMeta)>,
    err: std::io::Error,
) -> std::io::Result<(Config, CacheMeta)> {
    if let Some((raw, meta)) = cached {
        if let Ok(cfg) = Config::from_config_str(&raw) {
            tracing::warn!(err = %err, "config-fetch: fetch unavailable, using cached config");
            return Ok((cfg, meta));
        }
    }
    Err(err)
}

/// Extract the server-recommended `poll_interval_seconds` (a top-level `config_raw.json` body field)
/// without modelling the whole response. `0` when absent/unparseable (→ `poll_after`'s 10-min default).
/// Shared by `load_or_fetch` (to seed the cache meta) and `run_loop` (added in a later task).
fn server_poll_seconds(raw: &str) -> u64 {
    serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|v| v.get("poll_interval_seconds").and_then(|n| n.as_u64()))
        .unwrap_or(0)
}

/// Run the refresh loop until `should_stop()` returns true. On each successful `New` fetch it adapts +
/// caches + calls `on_config`, then sleeps the server-recommended interval; a `New` body that fails the
/// adapter, or any network failure, backs off (quadratic, ≤2min) and retries forever; `304`/NotModified
/// re-sleeps on the prior interval. Never returns an error — config refresh must not crash the tunnel.
pub async fn run_loop<F, Stop>(dir: &Path, env: &FetchEnv, mut on_config: F, should_stop: Stop)
where
    F: FnMut(Config),
    Stop: Fn() -> bool,
{
    let did = match device_id(dir) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(err = %e, "config-fetch: device_id failed, refresh loop will not run");
            return;
        }
    };
    // Account creds for every fetch; persisted by load_or_fetch on connect, so this just reads them.
    let creds = match user::ensure_user(dir, &env.pro_host, &env.pro_path).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(err = %e, "config-fetch: no account creds, refresh loop will not run");
            return;
        }
    };
    // Seed both the conditional state AND the initial sleep from the cached meta, so a warm start
    // (or a cold start whose first request 304s) uses the server's last-known cadence, not the default.
    let (mut cond, mut last_interval) = match cache::load(dir) {
        Some((_, m)) => (
            Conditional {
                etag: m.etag,
                last_modified: m.last_modified,
            },
            poll_after(m.poll_interval_seconds),
        ),
        None => (Conditional::default(), poll_after(0)),
    };
    // Build the fronted avenues once and reuse them across the loop: the embedded-config dialer, and
    // the vantage-point scanner (whose winning-front cache then persists for the loop's lifetime).
    let fronted = fronted_dialer();
    let bootstrap = fronted_bootstrap(env, seed_from_device_id(&did));
    let mut fail = 0u32;
    while !should_stop() {
        match fetch_once(env, &did, &creds, &cond, fronted.as_ref(), Some(&bootstrap)).await {
            Ok(FetchOutcome::New { raw, etag }) => match Config::from_config_str(&raw) {
                Ok(cfg) => {
                    fail = 0;
                    let secs = server_poll_seconds(&raw);
                    let meta = CacheMeta {
                        etag: etag.clone(),
                        last_modified: None,
                        poll_interval_seconds: secs,
                    };
                    if let Err(e) = cache::store(dir, &raw, &meta) {
                        tracing::debug!(err = %e, "config-fetch: cache write failed (non-fatal)");
                    }
                    cond.etag = etag;
                    last_interval = poll_after(secs);
                    on_config(cfg);
                    sleep_or_stop(last_interval, &should_stop).await;
                }
                Err(e) => {
                    tracing::debug!(err = %e, "config-fetch: unusable config body, backing off");
                    // A 200 with an unusable body (parse error / NoSupportedOutbounds) is treated as a
                    // failed fetch (design §7): don't cache, keep last-good, and back off — so a server
                    // serving a broken config isn't re-polled at the fast steady-state cadence.
                    fail = fail.saturating_add(1);
                    sleep_or_stop(backoff(fail), &should_stop).await;
                }
            },
            Ok(FetchOutcome::NotModified) => {
                fail = 0;
                sleep_or_stop(last_interval, &should_stop).await;
            }
            Err(e) => {
                tracing::debug!(err = %e, "config-fetch: fetch failed, backing off");
                fail = fail.saturating_add(1);
                sleep_or_stop(backoff(fail), &should_stop).await;
            }
        }
    }
    tracing::debug!("config-fetch: refresh loop stopped");
}

/// Quadratic backoff (10ms·n²) capped at 2 minutes — matches radiance's `common.NewBackoff`.
fn backoff(n: u32) -> Duration {
    let ms = (10u64).saturating_mul((n as u64).saturating_mul(n as u64));
    Duration::from_millis(ms.min(120_000))
}

/// Sleep `d`, but wake early (return) if `should_stop` flips. Polls the stop flag each second.
async fn sleep_or_stop<Stop: Fn() -> bool>(d: Duration, should_stop: &Stop) {
    let mut left = d;
    let step = Duration::from_secs(1);
    while left > Duration::ZERO && !should_stop() {
        let s = left.min(step);
        tokio::time::sleep(s).await;
        left = left.saturating_sub(s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_id_is_stable_and_persisted() {
        let dir = std::env::temp_dir().join(format!("spark-did-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let a = device_id(&dir).unwrap();
        let b = device_id(&dir).unwrap();
        assert_eq!(a, b, "device id stable across calls");
        assert_eq!(a.len(), 32, "16 bytes hex");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn poll_after_clamps_and_defaults() {
        assert_eq!(poll_after(0), Duration::from_secs(600)); // default
        assert_eq!(poll_after(5), Duration::from_secs(10)); // floor
        assert_eq!(poll_after(45), Duration::from_secs(45)); // server value
    }

    #[test]
    fn fetch_env_selects_staging_only_for_staging_value() {
        // Pure selector — no process-env mutation, so it's parallel-test-safe.
        assert_eq!(FetchEnv::select(None).host, "df.iantem.io");
        assert_eq!(FetchEnv::select(Some("prod")).host, "df.iantem.io");
        assert_eq!(
            FetchEnv::select(Some("staging")).host,
            "api.staging.iantem.io"
        );
    }

    #[test]
    fn server_poll_seconds_reads_body_field() {
        assert_eq!(server_poll_seconds(r#"{"poll_interval_seconds":45}"#), 45);
        assert_eq!(server_poll_seconds(r#"{"x":1}"#), 0);
        assert_eq!(server_poll_seconds("not json"), 0);
    }

    #[tokio::test]
    async fn load_or_fetch_falls_back_to_cache_when_unreachable() {
        // fetch-first: with an unreachable endpoint the fetch fails, and load_or_fetch falls back to
        // the last-good cache (offline resilience) rather than failing the connect. (`.invalid` is a
        // reserved TLD — DNS resolution fails fast and deterministically, so the test doesn't hang.)
        let dir = std::env::temp_dir().join(format!("spark-lof-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let raw = r#"{ "options": { "outbounds": [
            { "type": "samizdat", "tag": "s1", "server": "198.51.100.10", "server_port": 443,
              "public_key": "ab", "short_id": "cd", "server_name": "x" }
        ]}}"#;
        cache::store(&dir, raw, &CacheMeta::default()).unwrap();
        let env = FetchEnv {
            host: "config.invalid".into(),
            path: "/".into(),
            port: 443,
            pro_host: "pro.invalid".into(),
            pro_path: "/user-create".into(),
        };
        let (cfg, _meta) = load_or_fetch(&dir, &env).await.unwrap();
        assert_eq!(
            cfg.transport.servers.len(),
            1,
            "should serve the cached pool"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn outcome_label_maps_results() {
        assert_eq!(
            outcome_label(&Ok(FetchOutcome::New {
                raw: String::new(),
                etag: None
            })),
            "ok"
        );
        assert_eq!(
            outcome_label(&Ok(FetchOutcome::NotModified)),
            "not_modified"
        );
        assert_eq!(outcome_label(&Err(std::io::Error::other("x"))), "error");
    }

    #[test]
    fn backoff_is_quadratic_and_capped() {
        assert_eq!(backoff(1), Duration::from_millis(10));
        assert_eq!(backoff(2), Duration::from_millis(40));
        assert_eq!(backoff(10_000), Duration::from_millis(120_000)); // capped 2min
    }

    /// Live: hits real staging. Run:
    /// `SPARK_CONFIG_ENV=staging cargo test -p spark-core --features config-fetch -- --ignored live_fetch`
    #[tokio::test]
    #[ignore = "live: needs network"]
    async fn live_fetch() {
        let dir = std::env::temp_dir().join("spark-live-fetch");
        let _ = std::fs::remove_dir_all(&dir);
        let env = FetchEnv::staging();
        let (cfg, _m) = load_or_fetch(&dir, &env)
            .await
            .expect("staging fetch + adapt");
        assert!(
            !cfg.transport.servers.is_empty(),
            "staging should return a pool"
        );
    }

    /// Live: fetch **prod** config-new strictly through the domain-fronted path (aliyun/akamai/
    /// cloudfront via the embedded config), bypassing the direct dial — the end-to-end check that the
    /// Alibaba (and other) fronting actually reaches the origin. Run:
    /// `cargo test -p spark-core --features config-fetch -- --ignored live_fronted_fetch`
    #[tokio::test]
    #[ignore = "live: needs network + reachable fronting edges"]
    async fn live_fronted_fetch() {
        let dialer = fronted_dialer().expect("embedded fronted config parses");
        let env = FetchEnv::prod();
        let dir = std::env::temp_dir().join("spark-live-fronted");
        let _ = std::fs::remove_dir_all(&dir);
        let did = device_id(&dir).unwrap();
        // Creds are minted via the (direct) user-create pre-step; the config fetch itself is fronted.
        let creds = user::ensure_user(&dir, &env.pro_host, &env.pro_path)
            .await
            .expect("user-create");
        let mut req = ConfigRequest::new(did);
        req.user_id = creds.user_id.clone();
        req.pro_token = creds.pro_token.clone();
        let outcome = fetch_once_fronted(
            &env,
            &req,
            &Conditional::default(),
            &dialer,
            Duration::from_secs(30),
        )
        .await
        .expect("fronted config-new fetch");
        match outcome {
            FetchOutcome::New { raw, .. } => {
                let cfg = Config::from_config_str(&raw).expect("adapt fronted config");
                assert!(
                    !cfg.transport.servers.is_empty(),
                    "fronted fetch should return a pool"
                );
            }
            FetchOutcome::NotModified => panic!("unexpected 304 on unconditional fronted fetch"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
