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
    /// Identity handed down by the controlling app. When set it is used verbatim, and NOTHING about
    /// identity is read from or written to the data dir — see [`Identity`].
    pub identity: Option<Identity>,
}

/// A device + account identity supplied by the controlling app instead of minted here.
///
/// The app owns the single durable copy; the tunnel receives it per start and keeps it in memory only.
/// That is the point: when each process minted its own (both calling `/user-create`, because on macOS
/// neither can see the other's container) every install produced **two** Lantern accounts — and since
/// the tunnel is the process that fetches the proxy config, entitlement bought against the app's
/// account never reached the servers actually in use. One copy cannot drift from itself.
/// See `docs/identity-unification-design.md`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct Identity {
    pub device_id: String,
    pub user_id: String,
    pub pro_token: String,
}

impl Identity {
    /// Parse the `{"device_id":…,"user_id":…,"pro_token":…}` blob handed across the FFI.
    ///
    /// `None` for blank input, malformed JSON, or **any** empty field — including the anonymous
    /// `user_id` placeholder `"0"`. A half-populated identity is worse than none: it would fetch as a
    /// partial user and still look like it worked. Callers turn `None` into a hard failure on the
    /// self-fetch path rather than falling back to registering.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        let id: Identity = serde_json::from_str(s).ok()?;
        let blank = id.device_id.trim().is_empty()
            || id.user_id.trim().is_empty()
            || id.user_id.trim() == "0"
            || id.pro_token.trim().is_empty();
        (!blank).then_some(id)
    }
}

impl FetchEnv {
    pub fn prod() -> Self {
        FetchEnv {
            host: "df.iantem.io".into(),
            path: "/api/v1/config-new".into(),
            port: 443,
            pro_host: "api.getiantem.org".into(),
            pro_path: "/user-create".into(),
            identity: None,
        }
    }
    pub fn staging() -> Self {
        FetchEnv {
            host: "api.staging.iantem.io".into(),
            path: "/v1/config-new".into(),
            port: 443,
            pro_host: "api.staging.iantem.io".into(),
            pro_path: "/pro-server/user-create".into(),
            identity: None,
        }
    }
    /// Use `id` for every fetch instead of the data dir's `device_id` + `/user-create` creds.
    pub fn with_identity(mut self, id: Identity) -> Self {
        self.identity = Some(id);
        self
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
    #[cfg(feature = "proxyless")] proxyless: &flint_kindling::ProxylessTransport,
) -> std::io::Result<FetchOutcome> {
    const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(30);

    let mut req = ConfigRequest::new(device_id.to_string());
    req.user_id = creds.user_id.clone();
    req.pro_token = creds.pro_token.clone();

    let mut attempts: Vec<FetchAttempt<'_>> = Vec::with_capacity(4);
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
    #[cfg(feature = "proxyless")]
    attempts.push(Box::pin(with_outcome(
        "proxyless",
        Box::pin(fetch_once_proxyless(
            env,
            &req,
            cond,
            proxyless,
            ATTEMPT_TIMEOUT,
        )),
    )));
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
    // Tag the error with its avenue, so the aggregate `first_ok` builds names which path produced
    // each failure rather than reporting an anonymous "connection refused".
    //
    // The `ErrorKind` is carried through rather than flattened. No caller matches on it today —
    // `cached_or_err` decides on whether a cache exists, not on the kind — so this is about not
    // destroying information on the way past, not about a contract anyone relies on. An earlier
    // version of this comment claimed `load_or_fetch` matched on it, which was simply untrue.
    result.map_err(|e| std::io::Error::new(e.kind(), format!("{avenue}: {e}")))
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

/// The proxyless path: reach config-new with **no proxy and no exit hop**, by searching for an
/// un-poisoned resolver plus opening-handshake shaping this network does not block (ADR 0014).
///
/// Why it belongs in this race: the other three avenues are all TLS-over-TCP/443 to a CDN or origin —
/// two of them the same technique with different edge lists — so they share a failure mode. A network
/// that poisons DNS or classifies the ClientHello takes out all three at once. Proxyless is the only
/// member that brings its own resolver *and* its own wire shaping, so it fails independently. It also
/// costs no infrastructure and burns no fronting domains, which makes it free to lose on an open
/// network where `direct` wins.
///
/// **It speaks h2, not HTTP/1.1.** The connection arrives already TLS-handshaked by flint's Chrome
/// connector, which offers `h2,http/1.1` (`flint-tls/src/connector.rs`) because ALPN is part of the
/// JA4 this transport exists to imitate. A modern origin therefore selects h2, and writing HTTP/1.1
/// onto that connection gets no valid response at all — it fails as "no header terminator" rather
/// than as an HTTP error, which is exactly how a first version of this avenue was silently broken.
/// Speaking HTTP/1.1 after a Chrome ClientHello would also be a fingerprint anomaly in its own right,
/// so the correct protocol and the convincing one are the same. `direct` differs because spark's own
/// `fetch_connector` sets no ALPN, leaving HTTP/1.1 as the default.
#[cfg(feature = "proxyless")]
async fn fetch_once_proxyless(
    env: &FetchEnv,
    req: &ConfigRequest,
    cond: &Conditional,
    transport: &flint_kindling::ProxylessTransport,
    timeout: Duration,
) -> std::io::Result<FetchOutcome> {
    let oneshot = build_oneshot_request(&env.path, req, cond).map_err(std::io::Error::other)?;
    let resp = tokio::time::timeout(timeout, async {
        // `ConnectionTransport` in scope only here: it provides `connect`, and a local import cannot
        // collide with spark's own `Transport` trait.
        use flint_kindling::ConnectionTransport as _;
        let stream = transport.connect(&env.host).await?;
        // The real host is the authority — unlike the fronted avenue, there is no decoy to address.
        flint_kindling::h2_oneshot(stream, &env.host, &oneshot).await
    })
    .await
    .map_err(|_| std::io::Error::other("config-new proxyless fetch timed out"))??;
    let etag = resp.header("etag").map(ToOwned::to_owned);
    map_response(resp.status, etag, resp.body)
}

/// Strict upper bound on candidates a single cold proxyless search will try, so its worst case is
/// predictable rather than proportional to the resolver pool. Sized to finish well inside the 30s
/// attempt window this race gives each avenue.
#[cfg(feature = "proxyless")]
const PROXYLESS_MAX_CANDIDATES: usize = 8;

/// Build the proxyless race member.
///
/// **Bounded on purpose.** The first connection on a new network is a *search*, not a dial — flint's
/// own docs flag the interaction with an attempt timeout — and this race gives every avenue 30s. An
/// unbounded search would simply spend that budget and lose, so the candidate count is capped: enough
/// to cover the common resolver/shaping combinations, few enough to finish inside the window. Built
/// once by the caller and reused, so its `StrategyCache` keeps the winning strategy for later fetches
/// (the same reason the fronted dialer and the scanner are hoisted out of the refresh loop).
#[cfg(feature = "proxyless")]
fn proxyless_transport(env: &FetchEnv) -> flint_kindling::ProxylessTransport {
    flint_kindling::ProxylessTransport::new(
        flint_kindling::Space::new(flint_dns::default_pool())
            .with_roots(crate::transport::probe::webpki_roots_pem()),
        "config-fetch",
    )
    .with_port(env.port)
    .with_max_candidates(PROXYLESS_MAX_CANDIDATES)
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

/// Race several fetch attempts, returning the first that succeeds.
///
/// If all of them fail, the error names **every** avenue and how each died, not just whichever
/// attempt happened to finish last — on a censored network that report is the only evidence anyone
/// gets. The `ErrorKind` is kept when all avenues agreed on one, since "they all timed out" and "they
/// failed four different ways" are different diagnoses. An empty attempt list is reported distinctly:
/// it is a programming error, and calling it "all 0 avenues failed" would read like a blocked network.
/// Unlike a plain `select!`, an early *failure* doesn't end the race — the remaining attempts still
/// run, so a censored direct dial doesn't pre-empt the fronted ones (and vice versa).
async fn first_ok(mut attempts: Vec<FetchAttempt<'_>>) -> std::io::Result<FetchOutcome> {
    if attempts.is_empty() {
        return Err(std::io::Error::other("no config-new fetch attempt ran"));
    }
    // Every avenue's error, not just the last. A censored cold start is the case where this report is
    // the only evidence available, and "the last future to finish said connection refused" describes
    // whichever attempt happened to lose the race rather than why the fetch failed. `with_outcome`
    // has already tagged each error with its avenue, so the joined message names all four.
    let mut errors: Vec<String> = Vec::with_capacity(attempts.len());
    let mut kinds: Vec<std::io::ErrorKind> = Vec::with_capacity(attempts.len());
    while !attempts.is_empty() {
        let (result, _idx, remaining) = futures::future::select_all(attempts).await;
        match result {
            Ok(outcome) => return Ok(outcome),
            Err(e) => {
                kinds.push(e.kind());
                errors.push(e.to_string());
                attempts = remaining;
            }
        }
    }
    // Keep the `ErrorKind` when every avenue agreed on one — "they all timed out" is a materially
    // different diagnosis from "they failed in four different ways", and flattening the aggregate to
    // `Other` would throw away the per-avenue kinds that `with_outcome` deliberately preserved.
    let kind = match kinds.split_first() {
        Some((first, rest)) if rest.iter().all(|k| k == first) => *first,
        _ => std::io::ErrorKind::Other,
    };
    Err(std::io::Error::new(
        kind,
        format!(
            "all {} config-new fetch avenues failed: {}",
            errors.len(),
            errors.join("; ")
        ),
    ))
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

/// The `(device_id, creds)` a fetch runs as.
///
/// With a supplied [`Identity`] this touches neither the filesystem nor `/user-create` — that is what
/// keeps the tunnel from minting a second account. Without one (CLI/dev, or a host that owns its own
/// identity) it falls back to the historical dir-backed pair: read-or-create `device_id`, then
/// cached-or-minted creds.
async fn resolve_identity(dir: &Path, env: &FetchEnv) -> std::io::Result<(String, user::Creds)> {
    if let Some(id) = &env.identity {
        return Ok((
            id.device_id.clone(),
            user::Creds {
                user_id: id.user_id.clone(),
                pro_token: id.pro_token.clone(),
            },
        ));
    }
    let did = device_id(dir)?;
    // config-new requires account creds; mint them once via /user-create (persisted, reused).
    let creds = user::ensure_user(dir, &env.pro_host, &env.pro_path).await?;
    Ok((did, creds))
}

/// Bootstrap a [`Config`] for connect: **always fetch fresh and overwrite the cache**, using the
/// last-good cache only as an offline fallback (not as a way to skip the fetch). So a cached copy never
/// suppresses the fetch — you get the latest pool on every connect, and the cache is the safety net
/// when the network/API is unavailable. Errors only when the fetch fails AND there's no usable cache
/// (cold start offline). Returns the adapted Config + meta.
pub async fn load_or_fetch(dir: &Path, env: &FetchEnv) -> std::io::Result<(Config, CacheMeta)> {
    let cached = cache::load(dir); // for the offline fallback below; does NOT short-circuit the fetch
    let (did, creds) = match resolve_identity(dir, env).await {
        Ok(v) => v,
        Err(e) => return cached_or_err(cached, e),
    };
    // Unconditional fetch (no If-None-Match): every connect pulls the current config and overwrites.
    // Race the direct request against both fronted avenues (embedded list + vantage-point scanner) for
    // censored cold-start resilience.
    let fronted = fronted_dialer();
    let bootstrap = fronted_bootstrap(env, seed_from_device_id(&did));
    #[cfg(feature = "proxyless")]
    let proxyless = proxyless_transport(env);
    match fetch_once(
        env,
        &did,
        &creds,
        &Conditional::default(),
        fronted.as_ref(),
        Some(&bootstrap),
        #[cfg(feature = "proxyless")]
        &proxyless,
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
    // Same identity the connect fetch used — supplied by the app, or dir-backed when it wasn't. Every
    // refresh MUST run as that same user: re-deriving here is how a second identity would creep back in.
    let (did, creds) = match resolve_identity(dir, env).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(err = %e, "config-fetch: no identity, refresh loop will not run");
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
    // Built once and reused for the loop's lifetime, so the strategy cache keeps the winning
    // resolver+shaping pair rather than re-searching on every poll.
    #[cfg(feature = "proxyless")]
    let proxyless = proxyless_transport(env);
    let mut fail = 0u32;
    while !should_stop() {
        match fetch_once(
            env,
            &did,
            &creds,
            &cond,
            fronted.as_ref(),
            Some(&bootstrap),
            #[cfg(feature = "proxyless")]
            &proxyless,
        )
        .await
        {
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
            identity: None,
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

    /// A failed cold start must report *every* avenue, not whichever future finished last. This is
    /// the case where the error message is the only evidence anyone gets, so losing three quarters of
    /// it is the difference between a diagnosable failure and a shrug.
    #[tokio::test]
    async fn a_total_failure_reports_every_avenue() {
        let attempt = |name: &'static str, kind: std::io::ErrorKind| -> FetchAttempt<'static> {
            Box::pin(with_outcome(
                name,
                Box::pin(async move { Err(std::io::Error::new(kind, "blocked")) }),
            ))
        };
        let timed_out = std::io::ErrorKind::TimedOut;
        let err = first_ok(vec![
            attempt("direct", timed_out),
            attempt("fronted", timed_out),
            attempt("scanned", timed_out),
            attempt("proxyless", timed_out),
        ])
        .await
        .map(|_| ())
        .expect_err("every avenue failed");
        let msg = err.to_string();
        for avenue in ["direct", "fronted", "scanned", "proxyless"] {
            assert!(msg.contains(avenue), "the report must name {avenue}: {msg}");
        }
        assert!(msg.contains("all 4"), "and how many failed: {msg}");
        assert_eq!(
            err.kind(),
            timed_out,
            "a unanimous kind survives — 'they all timed out' is its own diagnosis"
        );

        // Mixed kinds cannot honestly be summarised as any one of them.
        let err = first_ok(vec![
            attempt("direct", std::io::ErrorKind::TimedOut),
            attempt("fronted", std::io::ErrorKind::ConnectionRefused),
        ])
        .await
        .map(|_| ())
        .expect_err("both failed");
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
    }

    /// An empty attempt list is a programming error, not a network failure — it must not be reported
    /// as "all 0 avenues failed", which would read like a blocked network.
    #[tokio::test]
    async fn no_attempts_is_distinguishable_from_every_attempt_failing() {
        let err = first_ok(Vec::new())
            .await
            .map(|_| ())
            .expect_err("an empty race cannot succeed");
        assert!(err.to_string().contains("no config-new fetch attempt ran"));
    }

    /// The search space must carry trust anchors. Empty roots send flint to BoringSSL's
    /// `set_default_paths()`, which finds nothing on macOS (certificates live in the Keychain), and
    /// every candidate then fails verification instantly — a search that reports "all N failed" in a
    /// second, indistinguishable from a blocked network. Offline, because the failure it guards
    /// against is silent and platform-dependent.
    #[cfg(feature = "proxyless")]
    #[test]
    fn the_proxyless_space_pins_trust_anchors() {
        let roots = crate::transport::probe::webpki_roots_pem();
        assert!(
            roots.len() > 100,
            "expected the Mozilla root set, got {} anchors",
            roots.len()
        );
        assert!(
            roots
                .iter()
                .all(|p| p.starts_with("-----BEGIN CERTIFICATE-----")),
            "Space::roots wants PEM, not DER"
        );
    }

    /// The proxyless member must be *bounded*. A cold search is a search, not a dial, and this race
    /// gives every avenue 30s — an unbounded space would spend the whole budget and lose, making the
    /// avenue useless rather than absent, which is worse because it looks like it is covered.
    ///
    /// This guards our choice of bound: that it is a real restriction against the current resolver
    /// pool, so a pool that shrinks (or a constant someone raises) fails here rather than silently
    /// becoming unbounded. It does *not* re-test that flint honours `with_max_candidates` — that is
    /// flint's own invariant and it tests it.
    #[cfg(feature = "proxyless")]
    #[test]
    fn the_proxyless_member_searches_a_bounded_space() {
        let full = flint_kindling::Space::new(flint_dns::default_pool()).len();
        assert!(
            PROXYLESS_MAX_CANDIDATES < full,
            "the cap ({PROXYLESS_MAX_CANDIDATES}) must actually restrict the {full}-candidate space"
        );
        // (No `> 0` assertion: it is constant-true, and flint's `with_max_candidates` floors at 1.)
    }

    /// **2x2 isolation against the real origin.** The header capture showed exactly two differences
    /// between what `h2_oneshot` sends and what curl sends: flint adds a `host` header (curl never
    /// does, even when asked) and flint omits `content-length` (curl always sends it). Both of my
    /// earlier curl-based eliminations were therefore invalid — curl normalizes, so it never put on
    /// the wire what I believed I was testing.
    ///
    /// This sends all four combinations to the real origin over a real h2 connection and reports
    /// which reproduce the `PROTOCOL_ERROR`. One connection per variant, since the failure is a
    /// stream reset.
    ///
    /// `cargo test -p spark-core --features prod -- --ignored --nocapture isolate_h2_reset`
    // `samizdat` as well as `proxyless`: this hand-builds h2 requests, and `h2`/`http` are optional
    // deps that only `samizdat` turns on (`dep:h2`/`dep:http`). Without the second gate
    // `--features config-fetch,proxyless` fails to compile. `prod` carries both, so it still runs
    // wherever it is useful.
    #[cfg(all(feature = "proxyless", feature = "samizdat"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "diagnostic: needs network"]
    async fn isolate_h2_reset() {
        use flint_kindling::ConnectionTransport as _;

        let env = FetchEnv::prod();
        let transport = proxyless_transport(&env);
        let body = bytes::Bytes::from_static(b"{\"probe\":true}");

        for (with_host, with_len) in [(true, false), (false, false), (true, true), (false, true)] {
            let label = format!("host={:<5} content-length={:<5}", with_host, with_len);
            let stream = match transport.connect(&env.host).await {
                Ok(s) => s,
                Err(e) => {
                    println!("  {label} -> could not connect: {e}");
                    continue;
                }
            };
            let (send_request, connection) = match h2::client::handshake(stream).await {
                Ok(v) => v,
                Err(e) => {
                    println!("  {label} -> h2 handshake failed: {e}");
                    continue;
                }
            };
            let driver = tokio::spawn(async move {
                let _ = connection.await;
            });

            // `::http` — `config::fetch::http` shadows the crate name in this module.
            let mut b = ::http::Request::builder()
                .method(::http::Method::POST)
                .uri(format!("https://{}{}", env.host, env.path))
                .header(::http::header::CONTENT_TYPE, "application/json");
            if with_host {
                b = b.header(::http::header::HOST, env.host.as_str());
            }
            if with_len {
                b = b.header(::http::header::CONTENT_LENGTH, body.len());
            }
            let request = b.body(()).expect("request");

            let outcome = async {
                let mut sr = send_request.ready().await.map_err(|e| e.to_string())?;
                let (resp, mut send) =
                    sr.send_request(request, false).map_err(|e| e.to_string())?;
                send.send_data(body.clone(), true)
                    .map_err(|e| e.to_string())?;
                let resp = resp.await.map_err(|e| e.to_string())?;
                Ok::<u16, String>(resp.status().as_u16())
            }
            .await;
            match outcome {
                Ok(status) => println!("  {label} -> HTTP {status}"),
                Err(e) => println!("  {label} -> ERROR {e}"),
            }
            driver.abort();
        }
        println!("(an HTTP status of any kind means the request was accepted at the h2 layer)");
    }

    /// **Header-capture experiment.** Four hypotheses for the proxyless `PROTOCOL_ERROR` were
    /// eliminated by measurement from outside (ALPN is h2; content-length is not required by the
    /// origin; the `X-Lantern-*` set is accepted; `h2_oneshot` works against Akamai). What remains is
    /// the request itself, so this captures exactly what `h2_oneshot` puts on the wire and diffs it
    /// against curl, which the same origin accepts.
    ///
    /// A local h2 server with prior knowledge — no TLS — because the question is the HEADERS frame,
    /// not the transport. `h2_oneshot` takes any stream, so it can be pointed straight at it.
    ///
    /// `cargo test -p spark-core --features prod -- --ignored --nocapture capture_h2_headers`
    // Multi-thread on purpose: the curl control below is a *blocking* `std::process::Command`, and on
    // the default current-thread runtime it would starve the spawned server task — the client would
    // connect, the server could never accept, and the test would deadlock (it did).
    // Gated on `samizdat` for the same reason as `isolate_h2_reset`: it runs an h2 server, and
    // `h2`/`http` are optional deps that only that feature enables.
    #[cfg(feature = "samizdat")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "diagnostic: spawns a local server and shells out to curl"]
    async fn capture_h2_headers() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        // Accept two connections (flint, then curl) and record each request's head.
        let server = tokio::spawn(async move {
            let mut captured: Vec<(String, Vec<(String, String)>)> = Vec::new();
            for label in ["flint h2_oneshot", "curl --http2-prior-knowledge"] {
                // Bounded: if curl is missing or fails, the second accept would otherwise block
                // forever and hang the test rather than reporting what it did capture.
                let accepted =
                    tokio::time::timeout(Duration::from_secs(10), listener.accept()).await;
                let Ok(Ok((tcp, _))) = accepted else {
                    captured.push((
                        label.to_owned(),
                        vec![("<no connection>".into(), "client never connected".into())],
                    ));
                    continue;
                };
                let mut conn = match h2::server::handshake(tcp).await {
                    Ok(c) => c,
                    Err(e) => {
                        captured.push((
                            label.to_owned(),
                            vec![("<handshake failed>".into(), e.to_string())],
                        ));
                        continue;
                    }
                };
                // The h2 server connection must keep being polled for frames to flush — responding
                // and then dropping it means the response is never written and the client hangs
                // forever (which it did, the first time this was written). Loop on `accept`, which
                // drives the connection, and stop on close or a short deadline.
                // One request per connection is all this captures.
                let next = tokio::time::timeout(Duration::from_secs(5), conn.accept()).await;
                if let Ok(Some(Ok((request, mut respond)))) = next {
                    let (parts, mut body) = request.into_parts();
                    let mut head = vec![
                        (":method".to_owned(), parts.method.to_string()),
                        (
                            ":scheme".to_owned(),
                            parts.uri.scheme_str().unwrap_or("-").to_owned(),
                        ),
                        (
                            ":authority".to_owned(),
                            parts
                                .uri
                                .authority()
                                .map(|a| a.to_string())
                                .unwrap_or_else(|| "-".into()),
                        ),
                        (":path".to_owned(), parts.uri.path().to_owned()),
                    ];
                    for (k, v) in parts.headers.iter() {
                        head.push((
                            k.as_str().to_owned(),
                            v.to_str().unwrap_or("<non-utf8>").to_owned(),
                        ));
                    }
                    let mut n = 0usize;
                    while let Some(Ok(chunk)) = body.data().await {
                        n += chunk.len();
                        let _ = body.flow_control().release_capacity(chunk.len());
                    }
                    head.push(("<body bytes>".to_owned(), n.to_string()));
                    captured.push((label.to_owned(), head));
                    // `::http` — `config::fetch::http` shadows the crate name inside this module.
                    let resp = ::http::Response::builder().status(200).body(()).unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(bytes::Bytes::from_static(b"{}"), true);
                    }
                }
            }
            captured
        });

        // 1) flint's client.
        let req = ConfigRequest::new("probe-device".to_owned());
        let oneshot = build_oneshot_request(&FetchEnv::prod().path, &req, &Conditional::default())
            .expect("oneshot");
        let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let _ = flint_kindling::h2_oneshot(tcp, "df.iantem.io", &oneshot).await;

        // 2) curl, the control — same path, same body shape, prior-knowledge h2.
        let out = std::process::Command::new("curl")
            .args([
                "-s",
                "-o",
                "/dev/null",
                "--http2-prior-knowledge",
                "-X",
                "POST",
                "-H",
                "content-type: application/json",
                "--data-binary",
                "{}",
                &format!("http://{addr}/api/v1/config-new"),
            ])
            .output();
        if let Err(e) = &out {
            println!("(curl unavailable: {e})");
        }

        for (label, head) in server.await.expect("server task") {
            println!("\n=== {label} ===");
            for (k, v) in head {
                println!("  {k}: {v}");
            }
        }
    }

    /// **Diagnostic, not a test of spark.** `connect_cached` collapses every candidate's error into
    /// `AllFailed { tried }` (`.map_err(|_errors| ..)` — the reasons are collected and then dropped),
    /// so a failing search is undiagnosable from the outside. This walks the same space one candidate
    /// at a time via the public `probe` and prints what each one actually said.
    ///
    /// Run when the proxyless avenue fails and you need to know why:
    /// `cargo test -p spark-core --features prod -- --ignored --nocapture why_proxyless_fails`
    #[cfg(feature = "proxyless")]
    #[tokio::test]
    #[ignore = "diagnostic: needs network"]
    async fn why_proxyless_fails() {
        let env = FetchEnv::prod();
        let space = flint_kindling::Space::new(flint_dns::default_pool())
            .with_roots(crate::transport::probe::webpki_roots_pem());
        println!(
            "space: {} resolvers x {} wires = {} candidates, {} trust anchors",
            space.resolvers.len(),
            space.wires.len(),
            space.len(),
            space.roots.len()
        );
        let n = space.len().min(PROXYLESS_MAX_CANDIDATES);
        let mut ok = 0usize;
        for i in 0..n {
            let Some(strategy) = space.strategy(i) else {
                println!("  [{i}] no strategy at this index");
                continue;
            };
            match flint_proxyless::probe(&strategy, &env.host).await {
                Ok(()) => {
                    ok += 1;
                    println!("  [{i}] OK");
                }
                Err(e) => println!("  [{i}] FAILED: {e} (kind {:?})", e.kind()),
            }
        }
        println!("{ok}/{n} candidates reached {}", env.host);
        assert!(
            ok > 0,
            "no candidate reached {} — see the errors above",
            env.host
        );
    }

    /// Live: fetch prod config-new strictly through the **proxyless** avenue — no proxy, no exit hop,
    /// no fronting. The end-to-end check that the resolver+shaping search actually reaches the origin,
    /// which is the whole reason this member is in the race. Run:
    /// `cargo test -p spark-core --features config-fetch,proxyless -- --ignored live_proxyless_fetch`
    #[cfg(feature = "proxyless")]
    #[tokio::test]
    #[ignore = "live: needs network"]
    async fn live_proxyless_fetch() {
        let env = FetchEnv::prod();
        let transport = proxyless_transport(&env);
        let dir = std::env::temp_dir().join("spark-live-proxyless");
        // Deliberately NOT wiped. `device_id` and `ensure_user` cache credentials here, and
        // wiping mints a brand-new user on every run — enough repeated runs and `user-create`
        // starts answering 500, which then reads as a test failure rather than the throttling it
        // is. Reusing the cache keeps these tests repeatable and is kinder to the API.
        let did = device_id(&dir).unwrap();
        let creds = user::ensure_user(&dir, &env.pro_host, &env.pro_path)
            .await
            .expect("user-create");
        let mut req = ConfigRequest::new(did);
        req.user_id = creds.user_id.clone();
        req.pro_token = creds.pro_token.clone();
        let outcome = fetch_once_proxyless(
            &env,
            &req,
            &Conditional::default(),
            &transport,
            Duration::from_secs(30),
        )
        .await
        .expect("proxyless config-new fetch");
        match outcome {
            FetchOutcome::New { raw, .. } => {
                let cfg = Config::from_config_str(&raw).expect("adapt proxyless config");
                assert!(
                    !cfg.transport.servers.is_empty(),
                    "proxyless fetch should return a pool"
                );
            }
            FetchOutcome::NotModified => panic!("unexpected 304 on unconditional proxyless fetch"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **Design probe, not a regression test.** Decides how much of the fetch can move onto
    /// `Kindling`. It has been wrong twice, and both mistakes are worth keeping written down because
    /// each one was a silent failure rather than a loud one.
    ///
    /// First it addressed the inner request to config-new's own host and got a 400. A fronted edge
    /// routes by the *provider's* host (`front.fronted_host`) — SNI is the decoy, the inner `Host`
    /// selects the origin — so the edge was right to reject it.
    ///
    /// Then it spoke HTTP/1.1 and got "no header terminator", i.e. no valid response at all. flint's
    /// Chrome connector sets `ALPN_H2_HTTP11` unconditionally (`flint-tls/src/connector.rs`) because
    /// ALPN is part of the JA4 being imitated, so the edge selects **h2**. HTTP/1.1 over that is not
    /// an HTTP error, it is a protocol violation — which is why it surfaces as garbage rather than a
    /// status code.
    ///
    /// Both corrections point at the same structural finding: `ConnectionTransport::connect` returns
    /// `conn.stream` and drops `conn.front`, and a generic consumer of a kindling race therefore
    /// cannot address a fronted request correctly. The uniform interface erases the one thing this
    /// caller needs. That is fine for a tunnel, where nobody cares which edge carried it; a bootstrap
    /// HTTP request is the case where it is not.
    ///
    /// What this now answers: *if* the authority were available, does a fronted TLS connection carry
    /// an ordinary h2 request to config-new? Pass ⇒ the full move is worth a small flint change to
    /// surface the winning front alongside the stream. Fail ⇒ fronting stays a one-shot and only the
    /// connection-shaped members move. Run:
    /// `cargo test -p spark-core --features prod -- --ignored --nocapture fronted_connection_speaks_h2`
    #[tokio::test]
    #[ignore = "live: design probe, needs network + reachable fronting edges"]
    async fn fronted_connection_speaks_h2() {
        let dialer = fronted_dialer().expect("embedded fronted config parses");
        let env = FetchEnv::prod();
        // Reuse a persistent directory rather than wiping it. `ensure_user` caches credentials
        // there, and minting a fresh user on every run is both wasteful and self-defeating: repeated
        // runs of this probe earned an HTTP 500 from user-create, which then looks like a probe
        // failure rather than the rate-limiting it is.
        let dir = std::env::temp_dir().join("spark-probe-fronted-conn");
        let did = device_id(&dir).unwrap();
        let creds = user::ensure_user(&dir, &env.pro_host, &env.pro_path)
            .await
            .expect("user-create");
        let mut req = ConfigRequest::new(did);
        req.user_id = creds.user_id.clone();
        req.pro_token = creds.pro_token.clone();

        // `connect_fronted`, not the `ConnectionTransport` path, so the winning front survives.
        let conn = dialer
            .connect_fronted(&env.host)
            .await
            .expect("a fronted edge accepts a connection");
        let authority = conn.fronted_host().to_owned();
        println!("probe: edge accepted, inner authority = {authority}");

        let oneshot = build_oneshot_request(&env.path, &req, &Conditional::default())
            .expect("oneshot request");
        let resp = flint_kindling::h2_oneshot(conn.stream, &authority, &oneshot)
            .await
            .expect("h2 over the fronted connection");
        println!(
            "probe: status {}, {} body bytes",
            resp.status,
            resp.body.len()
        );
        assert_eq!(
            resp.status, 200,
            "h2 to {authority} should reach the origin"
        );
        let raw = String::from_utf8(resp.body).expect("utf-8 body");
        let cfg = Config::from_config_str(&raw).expect("adapt config from the fronted connection");
        assert!(!cfg.transport.servers.is_empty(), "should return a pool");
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
        // Deliberately NOT wiped. `device_id` and `ensure_user` cache credentials here, and
        // wiping mints a brand-new user on every run — enough repeated runs and `user-create`
        // starts answering 500, which then reads as a test failure rather than the throttling it
        // is. Reusing the cache keeps these tests repeatable and is kinder to the API.
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

    #[test]
    fn identity_parse_accepts_a_complete_blob() {
        let id =
            Identity::parse(r#"{"device_id":"abc123","user_id":"389150267","pro_token":"tok"}"#)
                .expect("complete identity parses");
        assert_eq!(id.device_id, "abc123");
        assert_eq!(id.user_id, "389150267");
        assert_eq!(id.pro_token, "tok");
    }

    #[test]
    fn identity_parse_rejects_partial_and_placeholder() {
        // A half-populated identity must not half-apply: it would fetch as a partial user and still
        // look like it worked, which is exactly the silent-wrong-account failure this replaces.
        for bad in [
            "",
            "   ",
            "not json",
            r#"{"device_id":"","user_id":"1","pro_token":"t"}"#,
            r#"{"device_id":"d","user_id":"","pro_token":"t"}"#,
            r#"{"device_id":"d","user_id":"1","pro_token":""}"#,
            // "0" is the anonymous placeholder from ConfigRequest::new, not an identity.
            r#"{"device_id":"d","user_id":"0","pro_token":"t"}"#,
            r#"{"user_id":"1","pro_token":"t"}"#, // missing field entirely
        ] {
            assert!(
                Identity::parse(bad).is_none(),
                "must reject partial identity: {bad}"
            );
        }
    }

    #[tokio::test]
    async fn supplied_identity_bypasses_the_data_dir_entirely() {
        // The load-bearing property: with an identity supplied, resolve_identity writes no `device_id`
        // file and never reaches /user-create. If it touched the dir, the tunnel would be persisting a
        // second identity again — the very thing that produced two accounts per install.
        let dir = std::env::temp_dir().join(format!("spark-ident-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let env = FetchEnv {
            host: "config.invalid".into(),
            path: "/".into(),
            port: 443,
            // Unreachable on purpose: reaching it at all would be the bug.
            pro_host: "pro.invalid".into(),
            pro_path: "/user-create".into(),
            identity: None,
        }
        .with_identity(Identity {
            device_id: "supplied-device".into(),
            user_id: "389150267".into(),
            pro_token: "supplied-token".into(),
        });

        let (did, creds) = resolve_identity(&dir, &env)
            .await
            .expect("no network needed");
        assert_eq!(did, "supplied-device");
        assert_eq!(creds.user_id, "389150267");
        assert_eq!(creds.pro_token, "supplied-token");
        assert!(
            !dir.join("device_id").exists(),
            "supplied identity must not persist a device_id"
        );
        assert!(
            !dir.join("user.json").exists(),
            "supplied identity must not persist creds"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
