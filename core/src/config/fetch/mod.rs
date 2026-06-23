//! Fetch Spark's server pool from the Lantern `config-new` API (design:
//! `docs/config-new-fetch-design.md`). Direct TLS (no fronting yet), free-tier, disk-cached, fed into
//! [`crate::config::Config::from_config_str`]. Trust is TLS — no signature, matching radiance.

mod cache;
mod http;
mod request;

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
use crate::config::fetch::request::{build_request_bytes, Conditional, ConfigRequest};
use crate::config::Config;
use crate::transport::{probe::tls_wrap, DirectTransport, Transport};

/// Where to fetch from. Prod fronts via `df.iantem.io`; staging hits the API host directly.
#[derive(Debug, Clone)]
pub struct FetchEnv {
    pub host: String,
    pub path: String,
    pub port: u16,
}

impl FetchEnv {
    pub fn prod() -> Self {
        FetchEnv {
            host: "df.iantem.io".into(),
            path: "/api/v1/config-new".into(),
            port: 443,
        }
    }
    pub fn staging() -> Self {
        FetchEnv {
            host: "api.staging.iantem.io".into(),
            path: "/v1/config-new".into(),
            port: 443,
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

/// Do one direct fetch: dial the API host directly, TLS-wrap, POST the request, collect the response.
/// Errors on any network/TLS/HTTP failure (the loop turns errors into backoff-retries). The whole
/// network sequence is bounded by `ATTEMPT_TIMEOUT` — `post_collect` reads to EOF with no internal
/// timeout, so a hung/keep-alive server would otherwise stall the refresh loop forever instead of
/// backing off. Timeout ⇒ error ⇒ backoff-retry, which is the offline-resilience contract.
pub async fn fetch_once(
    env: &FetchEnv,
    device_id: &str,
    cond: &Conditional,
) -> std::io::Result<FetchOutcome> {
    const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(30);

    let req = ConfigRequest::new(device_id.to_string());
    let bytes =
        build_request_bytes(&env.host, &env.path, &req, cond).map_err(std::io::Error::other)?;
    let resp = tokio::time::timeout(ATTEMPT_TIMEOUT, async {
        let addr = resolve(&env.host, env.port).await?;
        let stream = DirectTransport::new(None).dial(addr).await?;
        let tls = tls_wrap(stream, &env.host).await?;
        post_collect(tls, &bytes, 4 * 1024 * 1024).await
    })
    .await
    .map_err(|_| std::io::Error::other("config-new fetch timed out"))??;
    match resp.status {
        200 | 206 => {
            let raw = String::from_utf8(resp.body)
                .map_err(|_| std::io::Error::other("config-new body not UTF-8"))?;
            Ok(FetchOutcome::New {
                raw,
                etag: resp.etag,
            })
        }
        304 | 204 => Ok(FetchOutcome::NotModified),
        other => Err(std::io::Error::other(format!("config-new HTTP {other}"))),
    }
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

/// Bootstrap a [`Config`] for connect: prefer the on-disk cache (fast start), else do a blocking
/// fetch. Returns the adapted Config + the meta to seed the refresh loop. Errors only when there is
/// no cache AND the fetch fails (cold-start offline) — the caller surfaces "waiting for config".
pub async fn load_or_fetch(dir: &Path, env: &FetchEnv) -> std::io::Result<(Config, CacheMeta)> {
    let did = device_id(dir)?;
    if let Some((raw, meta)) = cache::load(dir) {
        if let Ok(cfg) = Config::from_config_str(&raw) {
            return Ok((cfg, meta));
        }
        // Corrupt/empty cache: fall through to a fetch.
    }
    let cond = Conditional::default();
    match fetch_once(env, &did, &cond).await? {
        FetchOutcome::New { raw, etag } => {
            let cfg = Config::from_config_str(&raw).map_err(std::io::Error::other)?;
            // Persist the server's requested cadence too, so a cold start that immediately 304s in
            // run_loop still sleeps the server interval (not the 600s default).
            let meta = CacheMeta {
                etag,
                last_modified: None,
                poll_interval_seconds: server_poll_seconds(&raw),
            };
            cache::store(dir, &raw, &meta)?;
            Ok((cfg, meta))
        }
        FetchOutcome::NotModified => Err(std::io::Error::other(
            "config-new returned 304 with no cached config",
        )),
    }
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
    let mut fail = 0u32;
    while !should_stop() {
        match fetch_once(env, &did, &cond).await {
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
    async fn load_or_fetch_uses_cache_without_network() {
        let dir = std::env::temp_dir().join(format!("spark-lof-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let raw = r#"{ "options": { "outbounds": [
            { "type": "samizdat", "tag": "s1", "server": "198.51.100.10", "server_port": 443,
              "public_key": "ab", "short_id": "cd", "server_name": "x" }
        ]}}"#;
        cache::store(&dir, raw, &CacheMeta::default()).unwrap();
        // A bogus env proves we never dial: cache hit short-circuits.
        let env = FetchEnv {
            host: "127.0.0.1".into(),
            path: "/".into(),
            port: 1,
        };
        let (cfg, _meta) = load_or_fetch(&dir, &env).await.unwrap();
        assert_eq!(cfg.transport.servers.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
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
}
