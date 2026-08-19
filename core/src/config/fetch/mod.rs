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
/// Re-exported so a controlling app can declare it for the tunnel it starts — the capability
/// describes the installation, not the process fetching. See [`FetchEnv::with_capabilities`].
pub use request::{tunnel_runs_delivered_modules, CAPABILITY_TRANSPORT_MODULES};
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
    build_oneshot_request, build_request_bytes, Conditional, ConfigRequest, KindlingHeaders,
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
    /// Capabilities of the **installation**, when the caller knows better than this build's own
    /// features. `None` uses the build's set.
    ///
    /// Exists for Apple, where the app and the network extension are separate binaries: only the NE
    /// links the wasm host, but every tunnel runs in the NE, so the app must advertise what the NE
    /// can do. Otherwise the server withholds delivered-module outbounds from the app's fetch and the
    /// two processes disagree about which servers exist.
    pub capabilities: Option<Vec<String>>,
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

/// Apply an installation-level capability declaration over this build's own features.
///
/// A named function rather than two inline lines so the decision is testable: dropping it silently
/// reverts the app to advertising nothing, the server withholds delivered-module outbounds from it,
/// and the app's server list disagrees with the tunnel's — a failure that surfaces only as a
/// selectable server the tunnel has no member for.
fn apply_declared_capabilities(req: &mut ConfigRequest, env: &FetchEnv) {
    if let Some(caps) = &env.capabilities {
        req.capabilities = caps.clone();
    }
}

impl FetchEnv {
    /// Declare the installation's capabilities, overriding this build's own features.
    ///
    /// The Apple app uses this: it links spark-core without the wasm host, but the tunnel it starts
    /// is the network extension, which has it. Advertising the NE's capability is what keeps the
    /// app's server list and the tunnel's from disagreeing.
    pub fn with_capabilities(mut self, capabilities: Vec<String>) -> Self {
        self.capabilities = Some(capabilities);
        self
    }

    pub fn prod() -> Self {
        FetchEnv {
            host: "df.iantem.io".into(),
            path: "/api/v1/config-new".into(),
            port: 443,
            pro_host: "api.getiantem.org".into(),
            pro_path: "/user-create".into(),
            identity: None,
            capabilities: None,
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
            capabilities: None,
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

/// Ceiling on a decoded config body. Applies to the **decompressed** size on both branches, so a
/// gzip bomb is bounded by what the parser would receive rather than by its size on the wire.
const MAX_BODY: usize = 4 * 1024 * 1024;

/// The transport-module bundles this client already holds (`engine → version`), for the request's
/// `modules` declaration. Empty without the `wasm-transport` feature, and empty on a cold client —
/// in both cases the field is omitted and the request is byte-identical to what it was before.
///
/// Reads the same store the runtime installs into ([`crate::transport::engine::store::default_dir`]),
/// so the two cannot disagree about where bundles live.
fn installed_modules(dir: &Path) -> std::collections::BTreeMap<String, u32> {
    #[cfg(feature = "wasm-transport")]
    {
        crate::transport::engine::BundleStore::new(crate::transport::engine::store::default_dir(
            dir,
        ))
        .installed()
    }
    #[cfg(not(feature = "wasm-transport"))]
    {
        let _ = dir;
        std::collections::BTreeMap::new()
    }
}

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
    kindling: &flint_kindling::Kindling,
    dir: &Path,
) -> std::io::Result<FetchOutcome> {
    let mut req = ConfigRequest::new(device_id.to_string());
    req.user_id = creds.user_id.clone();
    req.pro_token = creds.pro_token.clone();
    req.modules = installed_modules(dir);
    apply_declared_capabilities(&mut req, env);
    with_outcome(
        "kindling",
        Box::pin(fetch_once_kindling(
            env,
            &req,
            cond,
            kindling,
            ATTEMPT_TIMEOUT,
        )),
    )
    .await
}

/// How long any one avenue gets before it loses the race.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(30);

/// Ceiling on the connection-level race, so the `Kindling` avenue cannot outlive the budget
/// [`fetch_once`] gives it. Left deliberately below [`ATTEMPT_TIMEOUT`]: the remainder is the HTTP
/// exchange that runs *after* a connection is won, and a connect that consumed the whole window would
/// leave nothing to send the request with.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// The direct config-host dial, expressed as a [`ConnectionTransport`] so it can share one race with
/// the other connection-level avenues instead of being a separate hand-rolled future.
///
/// [`ConnectionTransport`]: flint_kindling::ConnectionTransport
struct DirectConfigTransport {
    port: u16,
}

#[async_trait::async_trait]
impl flint_kindling::ConnectionTransport for DirectConfigTransport {
    type Stream = crate::BoxedStream;

    fn name(&self) -> &str {
        "direct"
    }

    async fn connect(&self, host: &str) -> std::io::Result<Self::Stream> {
        let addr = resolve(host, self.port).await?;
        let stream = DirectTransport::new(None).dial(addr).await?;
        Ok(Box::new(tls_wrap(stream, host).await?))
    }

    // `connect_alpn` is deliberately NOT overridden. `fetch_connector` offers no ALPN, so nothing is
    // negotiated and there is genuinely nothing to report — the default `None` is accurate, not a
    // gap. Per flint's contract that means "speak the version this transport was built for", which
    // for spark's own connector is HTTP/1.1; `fetch_once_kindling` reads it exactly that way.
}

/// The DNS-tunnel as a race member: reach config-new by tunnelling over DNS itself.
///
/// The last-resort leg. `direct` and `proxyless` both still need a TCP connection to the origin to
/// survive; this one needs only that *recursive DNS resolution works at all*, which is close to the
/// last thing a network turns off. It is slow — a DNS tunnel moves KB/s — so it is expected to lose
/// every race it does not have to win.
///
/// Two ways it differs from the other members:
///
/// * It hands back a **raw TCP** stream to the exit rather than a TLS one, so the TLS handshake
///   happens here, through the tunnel, against `host`. That keeps the certificate check end-to-end:
///   the tunnel exit carries bytes but cannot read or forge them.
/// * The target is a **domain**, resolved by the exit (spark#160). A member whose whole purpose is
///   surviving DNS interference must not begin by asking the local resolver for the origin's address.
#[cfg(feature = "dns-tunnel")]
struct DnsTunnelConfigTransport {
    tunnel: std::sync::Arc<dyn Transport>,
    port: u16,
}

#[cfg(feature = "dns-tunnel")]
#[async_trait::async_trait]
impl flint_kindling::ConnectionTransport for DnsTunnelConfigTransport {
    type Stream = crate::BoxedStream;

    fn name(&self) -> &str {
        "dns-tunnel"
    }

    async fn connect(&self, host: &str) -> std::io::Result<Self::Stream> {
        // The `HeaderError` goes in whole rather than stringified, so it survives as `source()`.
        // Safe for log hygiene: every variant reports a length or a byte, never the host itself.
        let target = crate::transport::Address::domain(host, self.port)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        let stream = self.tunnel.dial_addr(target).await?;
        Ok(Box::new(tls_wrap(stream, host).await?))
    }

    // No `connect_alpn` override, for the same reason as `DirectConfigTransport`: the TLS above is
    // spark's own `fetch_connector`, which offers no ALPN. Reports `None` → HTTP/1.1.
}

/// Build the bootstrap DNS-tunnel member from **build-time** parameters, or `None` if this build has
/// none pinned.
///
/// The zone and server key cannot come from the fetched config the way the runtime dns-tunnel
/// transport's do — this member exists to *perform* that fetch, so reading them from its result would
/// be circular. They are injected at build time instead, the same mechanism as
/// `SPARK_MODULE_PUBKEY_HEX`, which keeps live infrastructure identifiers out of a repo that is
/// intended to be public.
///
/// Absence is **not** an error, unlike the module-signing key. A missing signing key would be
/// fail-open, so that one refuses to build; a missing bootstrap tunnel just means one fewer avenue,
/// and the race still has `direct` and `proxyless`. Degrading quietly is the correct behaviour here.
#[cfg(feature = "dns-tunnel")]
fn bootstrap_dns_tunnel(env: &FetchEnv) -> Option<DnsTunnelConfigTransport> {
    let zone = option_env!("SPARK_BOOTSTRAP_DNS_ZONE")?;
    let server_pubkey = option_env!("SPARK_BOOTSTRAP_DNS_PUBKEY")?;
    let cfg = crate::config::DnsTunnelConfig {
        zone: zone.to_string(),
        server_pubkey: server_pubkey.to_string(),
        // Empty is fine: `dns_tunnel_transport` falls back to the OS resolvers, which is the right
        // default here — under a shutdown the mandated local resolver is often the only one still
        // forwarding, and it is the one every device already has.
        resolvers: option_env!("SPARK_BOOTSTRAP_DNS_RESOLVERS")
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().to_string())
            .collect(),
        authoritative: None,
        cipher: crate::config::DnsTunnelCipher::default(),
        compression: crate::config::DnsTunnelCompression::default(),
        // Bootstrap is one small fetch on a possibly-hostile network, and this is the leg that runs
        // when the others are already failing. Duplicating queries trades bandwidth for finding the
        // working resolver subset fast — measured at 27s → 0.3s time-to-first-byte against a mostly
        // dead pool. Worth it once, at startup.
        duplication: Some(3),
        use_system_resolvers: None,
    };
    match crate::transport::dns_tunnel_transport(&cfg, None) {
        Ok((tunnel, _udp)) => Some(DnsTunnelConfigTransport {
            tunnel,
            port: env.port,
        }),
        Err(e) => {
            // Log hygiene: `e` names the defect, never the zone.
            tracing::warn!(err = %e, "config-fetch: bootstrap dns-tunnel unusable, skipping that member");
            None
        }
    }
}

/// Build the connection-level race: the direct dial, plus proxyless where the feature is on.
///
/// Both members reach the *same* origin, so this is not a diversity play the way the fronted avenues
/// are — it is the two ways of reaching it directly, one of which brings its own resolver and wire
/// shaping. Built once by the caller and reused, so proxyless's `StrategyCache` keeps the winning
/// strategy across polls rather than re-searching each time.
///
/// The window is **derived from the members actually registered**, so every one starts together.
/// There is no tail to stagger at this size, and holding a member back would just add its latency to
/// the common case where the earlier one is blocked — which is the case this race exists for. Derived
/// rather than hardcoded because the member count is already conditional (`proxyless`), and because a
/// literal would silently start staggering the moment a third member is added.
fn config_kindling(env: &FetchEnv, seed: u64) -> flint_kindling::Kindling {
    #[cfg_attr(
        not(any(feature = "proxyless", feature = "dns-tunnel")),
        allow(unused_mut)
    )]
    let mut kindling =
        flint_kindling::Kindling::new().with_transport(DirectConfigTransport { port: env.port });
    #[cfg(feature = "proxyless")]
    {
        kindling = kindling.with_proxyless(proxyless_transport(env));
    }
    // The embedded front list: a known-good accelerator, and the avenue that survives when the origin
    // itself is unreachable but a CDN edge is not.
    if let Some(dialer) = fronted_dialer() {
        kindling = kindling.with_fronted_tls(dialer);
    }
    // The vantage-point scanner: discovers live edges from the user's *own* network, so it self-heals
    // when the embedded list is entirely blocked. Needs no server-delivered front list at all.
    kindling = kindling.with_transport(fronted_bootstrap(env, seed));
    // Registered last, and only when this build pinned a bootstrap tunnel. Order matters less than it
    // looks — the window below starts every member at once — but last reflects what it is: the leg
    // that wins only when the faster ones cannot.
    #[cfg(feature = "dns-tunnel")]
    if let Some(dns) = bootstrap_dns_tunnel(env) {
        kindling = kindling.with_transport(dns);
    }
    // `max(1)` mirrors `race_boxed`'s own floor; a zero window would never start anything.
    let window = kindling.transport_count().max(1);
    kindling.with_race_options(flint_kindling::RaceOptions {
        window,
        attempt_timeout: Some(CONNECT_TIMEOUT),
    })
}

/// Race every connection-level avenue, then speak to the winner on **its** terms.
///
/// Both the HTTP version and the address are read off the winning connection rather than assumed,
/// because the members disagree on each and the disagreement is invisible from here.
///
/// **Protocol.** `direct` and `dns-tunnel` go through spark's `fetch_connector`, which sets no ALPN
/// and so lands on HTTP/1.1; `proxyless` and both fronted members go through flint's Chrome
/// connector, which must offer `h2,http/1.1` because ALPN is part of the JA4 it exists to imitate —
/// and the *peer* chooses. Writing HTTP/1.1 at an h2 peer does not fail like an HTTP error; the
/// response never terminates ("no header terminator"), which is exactly how an earlier proxyless
/// avenue was silently broken.
///
/// **Authority.** A fronted connection must name the *front's* inner host so the edge re-originates
/// it, and that name differs per CDN. Addressing `env.host` there succeeds at the TLS layer and
/// routes wrong, which reads as the CDN being blocked rather than as a bug. `conn.authority` falls
/// back to `env.host` for every member that has no opinion, so the non-fronted paths are unchanged.
async fn fetch_once_kindling(
    env: &FetchEnv,
    req: &ConfigRequest,
    cond: &Conditional,
    kindling: &flint_kindling::Kindling,
    timeout: Duration,
) -> std::io::Result<FetchOutcome> {
    let (status, etag, body) = tokio::time::timeout(timeout, async {
        // `io::Error::from`, not `io::Error::other`: the race preserves the `ErrorKind` when every
        // member reported the same one, and `other` would flatten that back to `Other`. "They all
        // timed out" says the path is blackholed; "they failed five different ways" says the members
        // failed for their own reasons. Consolidating the avenues into the race lost that distinction
        // once already (#162) — this is what restores it.
        // Timed around the race alone, not the whole fetch: this is "how long until a member won",
        // which is the number that says whether the fast avenues are being crowded out.
        let race_started = std::time::Instant::now();
        let conn = kindling
            .connect(&env.host)
            .await
            .map_err(std::io::Error::from)?;
        // Attribute the request to the member that actually won. The transports cannot set a header
        // themselves — they hand back bytes and know nothing about HTTP — but the race reports the
        // winner's name, and this is the layer where HTTP exists.
        let attribution = KindlingHeaders::method(&conn.transport);
        // Record the same winner for ourselves. It was already being told to the server via the
        // header above and to nobody else, so "which member is actually carrying config fetches"
        // had no answer in our own telemetry — `config.fetch_outcome`'s `avenue` is hardcoded to
        // `"kindling"` for every path.
        crate::diag::emit(crate::diag::events::config_race_winner(
            &conn.transport,
            race_started.elapsed().as_millis() as u64,
        ));
        // ...and one event per member, so a member that never wins can be told apart from one that
        // is broken. The winner alone cannot say that: a losing member simply never appears, whether
        // it failed instantly or was merely a few ms slower. `pending` is explicitly NOT a failure —
        // see `events::config_race_member`.
        for attempt in &conn.attempts {
            let (result, kind) = race_result_labels(attempt.outcome);
            crate::diag::emit(crate::diag::events::config_race_member(
                &attempt.name,
                result,
                kind,
            ));
        }
        if conn.is_h2() {
            let oneshot = build_oneshot_request(&env.path, req, cond, attribution)
                .map_err(std::io::Error::other)?;
            // The winner's own authority — the origin for a direct-ish member, the front's inner
            // host for a fronted one. Never unconditionally `env.host`.
            //
            // CR/LF-stripped because it is no longer a constant: a fronted authority comes from
            // parsed config or a live scan, and an embedded newline would let it forge extra headers.
            // `h2_oneshot` builds a URI, whose parser would reject the value rather than inject — but
            // the guard belongs at the source so both branches are covered by one rule.
            let authority =
                crate::config::fetch::request::header_safe(conn.authority(&env.host)).into_owned();
            let resp = flint_kindling::h2_oneshot(conn.stream, &authority, &oneshot).await?;
            let etag = resp.header("etag").map(ToOwned::to_owned);
            // flint returns the body verbatim, so the fronted branch decodes here — through the same
            // helper the 1.1 branch uses, so the decoded-size cap cannot be forgotten on one path.
            // Read the header before moving the body out of `resp`.
            let enc = resp.header("content-encoding").map(ToOwned::to_owned);
            let body =
                crate::config::fetch::http::decode_body(resp.body, enc.as_deref(), MAX_BODY)?;
            Ok::<_, std::io::Error>((resp.status, etag, body))
        } else {
            // Same rule on the 1.1 path: the `Host:` header is the authority, so a fronted winner
            // needs the front's inner host here too. Only the header changes — the request line and
            // path are the origin's either way, since the edge re-originates by `Host`.
            // `build_request_bytes` strips CR/LF from the host for the reason above.
            let authority = conn.authority(&env.host).to_owned();
            let bytes = build_request_bytes(&authority, &env.path, req, cond, attribution)
                .map_err(std::io::Error::other)?;
            let resp = post_collect(conn.stream, &bytes, MAX_BODY).await?;
            Ok((resp.status, resp.etag, resp.body))
        }
    })
    .await
    .map_err(|_| std::io::Error::other("config-new kindling fetch timed out"))??;
    map_response(status, etag, body)
}

/// Map a race member's outcome onto the `result` / `error_kind` pair `config.race_member` reports.
///
/// `Pending` maps to its own label, never to a failure. A race returns on the first success, so on a
/// healthy pool *most* members are pending every time — folding that into "failed" would report the
/// whole pool as broken on exactly the races that went well, which is worse than emitting nothing.
fn race_result_labels(
    outcome: flint_transport::AttemptOutcome,
) -> (&'static str, Option<std::io::ErrorKind>) {
    match outcome {
        flint_transport::AttemptOutcome::Won => ("won", None),
        // Hand the kind on as a kind. Formatting it to a string here and passing that would put the
        // event back on a `&str` parameter, which is the thing the constructor now refuses.
        flint_transport::AttemptOutcome::Failed(k) => ("failed", Some(k)),
        flint_transport::AttemptOutcome::Pending => ("pending", None),
        flint_transport::AttemptOutcome::NotStarted => ("not_started", None),
    }
}

/// Wrap the fetch so its outcome (ok / not_modified / error) and latency land in the diagnostics
/// stream (§C6 `config.fetch_outcome`).
///
/// `avenue` is now always `"kindling"`: every path is one member of one connection race, so the
/// interesting question moved from *which avenue ran* to *which member won*, which the race reports
/// on the connection itself.
async fn with_outcome(
    avenue: &'static str,
    fut: std::pin::Pin<
        Box<dyn std::future::Future<Output = std::io::Result<FetchOutcome>> + Send + '_>,
    >,
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

/// Strict upper bound on candidates a single cold proxyless search will try, so its worst case is
/// predictable rather than proportional to the resolver pool. Sized to finish well inside the 30s
/// attempt window this race gives each avenue.
#[cfg(feature = "proxyless")]
const PROXYLESS_MAX_CANDIDATES: usize = 8;

/// Build the proxyless race member.
///
/// **Both axes.** Proxyless is documented as a search over `DNS strategy × TLS strategy`, and the
/// `Space` has carried a `wires` axis since flint#14 — but this space populated only the resolver
/// half, so it searched `resolvers × {no-op}` and could never defeat a censor that reads the
/// ClientHello. The two failures are genuinely different: a poisoned resolver is beaten by asking a
/// different resolver, and SNI-based blocking is beaten by making the SNI unreadable. Searching one
/// axis leaves the other class of network unreachable.
///
/// **Bounded on purpose.** The first connection on a new network is a *search*, not a dial — flint's
/// own docs flag the interaction with an attempt timeout — and this race gives every avenue 30s. An
/// unbounded search would simply spend that budget and lose, so the candidate count is capped: enough
/// to cover the common resolver/shaping combinations, few enough to finish inside the window. Built
/// once by the caller and reused, so its `StrategyCache` keeps the winning strategy for later fetches
/// (the same reason the fronted dialer and the scanner are hoisted out of the refresh loop).
#[cfg(feature = "proxyless")]
fn proxyless_transport(env: &FetchEnv) -> flint_kindling::ProxylessTransport {
    proxyless_transport_for(env.port, "config-fetch")
}

/// [`proxyless_transport`] parameterized by port and caller label, so a second bootstrap-shaped
/// race — the diagnostics uploader's, which targets the otel host rather than the config host — gets
/// the identical search rather than a re-derived near-copy of it.
///
/// `label` names the caller in proxyless's own reporting; each caller keeps its own
/// [`ProxylessTransport`] (and therefore its own `StrategyCache`), which is correct: a strategy that
/// works for one origin is not evidence about another.
///
/// [`ProxylessTransport`]: flint_kindling::ProxylessTransport
#[cfg(feature = "proxyless")]
pub(crate) fn proxyless_transport_for(
    port: u16,
    label: &'static str,
) -> flint_kindling::ProxylessTransport {
    let mut space = flint_kindling::Space::new(flint_dns::default_pool())
        .with_roots(crate::transport::probe::webpki_roots_pem());
    // `Space::new` seeds `wires[0]` with a no-op. Replace rather than append: appending would spend a
    // second candidate slot re-testing the unshaped case that `direct` and both fronted members
    // already cover, and `with_max_candidates` trims resolvers before plans, so that slot comes
    // straight out of resolver diversity.
    space.wires = vec![bootstrap_shaping()];
    flint_kindling::ProxylessTransport::new(space, label)
        .with_port(port)
        .with_max_candidates(PROXYLESS_MAX_CANDIDATES)
}

/// The **embedded bootstrap shaping default**, replacing the space's no-op plan.
///
/// Bootstrap cannot read `[transport.shaping]` — it *is* the code that fetches the config — so
/// unlike the data-path transport it has no configured plan to use. This is that missing
/// configuration, compiled in.
///
/// **Both layers in one plan, and no unshaped candidate.** A `WirePlan` carries every knob at once,
/// so SNI-targeting at Layer C (`SniBoundary`, TCP segment boundary) and Layer B (`SniStraddle`, TLS
/// record boundary) costs a single candidate slot rather than two. Slots are the scarce resource:
/// `with_max_candidates` trims resolvers before plans, so every extra plan is paid for in resolver
/// diversity.
///
/// Dropping the no-op plan is what buys that back — one plan at a cap of 8 searches **8 resolvers**,
/// where two searched 4. It costs nothing on an open network: shaping only changes where the
/// ClientHello is cut, the handshake completes either way, and both variants fall back to no-ops when
/// there is no locatable SNI. What it does add is a mild anomaly on networks that aren't blocking —
/// acceptable here because proxyless is one member of a race whose other members dial unshaped, so it
/// is not the only shape spark presents.
#[cfg(feature = "proxyless")]
fn bootstrap_shaping() -> flint_shaping::WirePlan {
    // Delegates rather than restating: the data-path transport defaults to the same plan, and two
    // copies of a shaping decision drift silently (they already had).
    crate::transport::default_shaping()
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
    // Race the connection-level avenues (direct + proxyless) against both fronted avenues (embedded
    // list + vantage-point scanner) for censored cold-start resilience.
    let kindling = config_kindling(env, seed_from_device_id(&did));
    match fetch_once(env, &did, &creds, &Conditional::default(), &kindling, dir).await {
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

    // Built once and reused for the loop's lifetime, so proxyless's strategy cache keeps the winning
    // resolver+shaping pair rather than re-searching on every poll.
    let kindling = config_kindling(env, seed_from_device_id(&did));
    let mut fail = 0u32;
    while !should_stop() {
        match fetch_once(env, &did, &creds, &cond, &kindling, dir).await {
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
                    sleep_or_stop(crate::backoff::with_jitter(fail), &should_stop).await;
                }
            },
            Ok(FetchOutcome::NotModified) => {
                fail = 0;
                sleep_or_stop(last_interval, &should_stop).await;
            }
            Err(e) => {
                tracing::debug!(err = %e, "config-fetch: fetch failed, backing off");
                fail = fail.saturating_add(1);
                sleep_or_stop(crate::backoff::with_jitter(fail), &should_stop).await;
            }
        }
    }
    tracing::debug!("config-fetch: refresh loop stopped");
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
mod declared_capability_tests {
    use super::*;

    /// The Apple case: the app links spark-core WITHOUT the wasm host, so its own capability set is
    /// empty — but every tunnel runs in the network extension, which has it. Declaring the tunnel's
    /// capability is what keeps the app's server list and the tunnel's from disagreeing about which
    /// servers exist.
    #[test]
    fn a_declaration_overrides_this_builds_own_capabilities() {
        // A sentinel no build produces on its own, so this holds whether or not this build has the
        // wasm host — CI exercises both configurations.
        let declared = vec!["declared-by-the-installation".to_string()];
        let env = FetchEnv::prod().with_capabilities(declared.clone());
        let mut req = ConfigRequest::new("dev".into());

        apply_declared_capabilities(&mut req, &env);
        assert_eq!(
            req.capabilities, declared,
            "the caller's declaration must reach the request and REPLACE the build's own set, or \
             the server withholds the delivered-module outbound from the app"
        );
    }

    /// An explicit EMPTY declaration is honored, and is distinct from no declaration. The server
    /// reads absence as "cannot", so a caller that means "this installation has nothing" must be
    /// able to say so without silently falling back to the build's own set.
    #[test]
    fn an_explicit_empty_declaration_is_honored() {
        let env = FetchEnv::prod().with_capabilities(Vec::new());
        let mut req = ConfigRequest::new("dev".into());
        apply_declared_capabilities(&mut req, &env);
        assert!(req.capabilities.is_empty());
    }

    /// No declaration leaves the build's own set alone — a single-process client (the CLI, the Linux
    /// service) is still described correctly by its own features and must not be overridden.
    #[test]
    fn no_declaration_leaves_the_builds_own_set() {
        let env = FetchEnv::prod();
        let mut req = ConfigRequest::new("dev".into());
        let own = req.capabilities.clone();
        apply_declared_capabilities(&mut req, &env);
        assert_eq!(req.capabilities, own);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use flint_transport::AttemptOutcome;

    /// `pending` must never be reported as a failure.
    ///
    /// A race returns on the first success, so on a *healthy* pool most members are still pending
    /// every single time. Folding that into "failed" would report the whole pool as broken on
    /// exactly the races that went well — worse than emitting nothing, because it would look like
    /// data.
    #[test]
    fn a_pending_member_is_not_reported_as_a_failure() {
        let (result, kind) = race_result_labels(AttemptOutcome::Pending);
        assert_eq!(result, "pending");
        assert_eq!(kind, None, "pending carries no error kind");
        assert_ne!(result, "failed");
    }

    /// The health signal: a member that errored before the winner finished, and how.
    #[test]
    fn a_failed_member_carries_its_error_kind() {
        let (result, kind) = race_result_labels(AttemptOutcome::Failed(
            std::io::ErrorKind::ConnectionRefused,
        ));
        assert_eq!(result, "failed");
        assert_eq!(kind, Some(std::io::ErrorKind::ConnectionRefused));
    }

    #[test]
    fn the_winner_and_unstarted_members_are_distinguishable() {
        assert_eq!(race_result_labels(AttemptOutcome::Won), ("won", None));
        assert_eq!(
            race_result_labels(AttemptOutcome::NotStarted),
            ("not_started", None),
            "never started says nothing about the member — not the same as pending"
        );
    }

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
            capabilities: None,
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

    /// The refresh loop's pacing lives in [`crate::backoff`] (jittered, shared with the diagnostics
    /// uploader) — its curve is asserted there. This only pins the wiring: the delay a failure
    /// produces must stay inside that module's bounds.
    #[test]
    fn failure_delay_comes_from_the_shared_jittered_backoff() {
        for fail in [1u32, 5, 99] {
            let (lo, hi) = crate::backoff::bounds(fail);
            assert!((lo..=hi).contains(&crate::backoff::with_jitter(fail)));
        }
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

    /// A failed cold start must report *every* member, not whichever attempt finished last. On a
    /// censored network that message is the only evidence anyone gets, so losing most of it is the
    /// difference between a diagnosable failure and a shrug.
    ///
    /// This property moved into flint's race when the avenues were consolidated — `RaceError::
    /// AllFailed` aggregates each member's error — so the test now covers it where it lives rather
    /// than being deleted along with `first_ok`.
    #[tokio::test]
    async fn a_total_failure_names_every_member() {
        use flint_kindling::ConnectionTransport;

        struct Dead(&'static str);

        #[async_trait::async_trait]
        impl ConnectionTransport for Dead {
            type Stream = crate::BoxedStream;

            fn name(&self) -> &str {
                self.0
            }

            async fn connect(&self, _host: &str) -> std::io::Result<Self::Stream> {
                Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "blocked"))
            }
        }

        let kindling = flint_kindling::Kindling::new()
            .with_race_options(flint_kindling::RaceOptions {
                window: 4,
                attempt_timeout: None,
            })
            .with_transport(Dead("direct"))
            .with_transport(Dead("proxyless"))
            .with_transport(Dead("fronted-tls"))
            .with_transport(Dead("fronted-scan"));

        let err = kindling
            .connect("api.example.com")
            .await
            .map(|_| ())
            .expect_err("every member failed");
        let msg = err.to_string();
        for member in ["direct", "proxyless", "fronted-tls", "fronted-scan"] {
            assert!(msg.contains(member), "the report must name {member}: {msg}");
        }
        assert!(msg.contains("all 4"), "and how many failed: {msg}");
    }

    /// The unanimous `ErrorKind` must survive all the way out of `fetch_once_kindling`, not merely
    /// out of flint's race. `io::Error::other` at the `map_err` would flatten it to `Other` and this
    /// is the only thing that would notice — which is how the distinction was lost in #162.
    #[tokio::test]
    async fn a_unanimous_member_failure_keeps_its_kind_through_the_fetch() {
        use flint_kindling::ConnectionTransport;

        struct Dead;

        #[async_trait::async_trait]
        impl ConnectionTransport for Dead {
            type Stream = crate::BoxedStream;

            fn name(&self) -> &str {
                "dead"
            }

            async fn connect(&self, _host: &str) -> std::io::Result<Self::Stream> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "blackholed",
                ))
            }
        }

        let kindling = flint_kindling::Kindling::new()
            .with_race_options(flint_kindling::RaceOptions {
                window: 2,
                attempt_timeout: None,
            })
            .with_transport(Dead)
            .with_transport(Dead);
        let env = FetchEnv::prod();
        let err = fetch_once_kindling(
            &env,
            &ConfigRequest::new("dev".into()),
            &Conditional::default(),
            &kindling,
            ATTEMPT_TIMEOUT,
        )
        .await
        .map(|_| ())
        .expect_err("every member failed");
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::TimedOut,
            "a blackholed path must not be reported as a generic failure: {err}"
        );
    }

    /// A race with no members is a programming error, not a blocked network, and must not read as one.
    #[tokio::test]
    async fn no_members_is_distinguishable_from_every_member_failing() {
        let err = flint_kindling::Kindling::new()
            .connect("api.example.com")
            .await
            .map(|_| ())
            .expect_err("an empty race cannot succeed");
        // Asserted on concepts, not flint's exact wording: the guarantee that matters is that an
        // empty race is distinguishable from every member failing, and pinning the phrase would
        // break on an upstream reword that changed nothing semantically.
        let msg = err.to_string().to_lowercase();
        assert!(msg.contains("no"), "must say there were none: {msg}");
        assert!(msg.contains("transport"), "must say of what: {msg}");
        assert!(
            !msg.contains("all "),
            "must not read like an AllFailed report: {msg}"
        );
    }

    /// A fronted authority is parsed config or scan output, not a constant, so a smuggled newline
    /// must not be able to forge headers. `build_request_bytes` used to take only `FetchEnv`'s
    /// compile-time host, which is why its `Host:` line needed no guard until this race made the
    /// value dynamic.
    #[test]
    fn a_newline_in_the_authority_cannot_forge_a_header() {
        let req = ConfigRequest::new("dev".into());
        let bytes = build_request_bytes(
            "evil.test\r\nX-Injected: 1",
            "/api/v1/config-new",
            &req,
            &Conditional::default(),
            KindlingHeaders::default(),
        )
        .expect("builds");
        let text = String::from_utf8_lossy(&bytes);
        // Stripping, not rejecting: `X-Injected: 1` survives as text *inside* the Host value, which
        // is harmless. What must not exist is a header LINE of that name — that is what "forge a
        // header" means, and asserting on the substring instead would fail on correct behaviour.
        assert!(
            !text.lines().any(|l| l.starts_with("X-Injected")),
            "CR/LF in the authority forged a header line:\n{text}"
        );
        assert!(
            text.contains("Host: evil.testX-Injected: 1\r\n"),
            "the value is stripped, not truncated or rejected: {}",
            text.lines().next().unwrap_or_default()
        );
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
    /// The bootstrap search must shape, and must shape at **both** layers.
    ///
    /// It searched only resolvers for a long time — the `wires` axis existed in the `Space` and was
    /// never populated — which left every SNI-blocking network unreachable no matter how many
    /// resolvers were tried.
    #[cfg(feature = "proxyless")]
    #[test]
    fn the_bootstrap_plan_shapes_at_both_layers() {
        use flint_shaping::{RecordFragment, SegmentSplit};

        let plan = bootstrap_shaping();
        assert!(
            matches!(plan.record_fragment, RecordFragment::SniStraddle),
            "Layer B: a censor parsing a single TLS record must not find the SNI"
        );
        assert!(
            matches!(plan.segment_split, SegmentSplit::SniBoundary),
            "Layer C: nor one matching SNI within a single TCP segment — different implementations, \
             both common, and one plan covers both for the price of one candidate slot"
        );
        assert!(!plan.is_noop(), "a no-op plan would silently add nothing");
    }

    /// Build the bootstrap space exactly as `proxyless_transport` does, so these tests exercise the
    /// shipping construction rather than a parallel one that could drift from it.
    #[cfg(feature = "proxyless")]
    fn bootstrap_space() -> flint_kindling::Space {
        let mut space = flint_kindling::Space::new(flint_dns::default_pool());
        space.wires = vec![bootstrap_shaping()];
        space
    }

    /// Exactly one plan, and it is the shaped one.
    ///
    /// `Space::new` seeds `wires[0]` with a no-op. Appending to it rather than replacing would spend
    /// a second candidate slot re-testing the unshaped case that `direct` and the fronted members
    /// already cover — and `with_max_candidates` trims resolvers before plans, so that slot is paid
    /// for out of resolver diversity.
    #[cfg(feature = "proxyless")]
    #[test]
    fn the_bootstrap_space_carries_one_shaped_plan_and_no_noop() {
        let space = bootstrap_space();
        assert_eq!(space.wires.len(), 1, "one plan, not the no-op plus one");
        assert!(
            !space.wires[0].is_noop(),
            "the surviving plan must be the shaped one, not the default no-op"
        );
    }

    /// Shaping must not be bought with resolver coverage.
    ///
    /// `with_max_candidates` trims resolvers before plans, so plan count and resolver count trade
    /// directly: at a cap of 8, one plan searches 8 resolvers and two searches 4. Keeping a single
    /// combined plan is what lets the search shape *and* keep the full resolver spread — the axis
    /// that handles DNS poisoning, which shaping cannot help with.
    #[cfg(feature = "proxyless")]
    #[test]
    fn shaping_does_not_cost_resolver_diversity() {
        let wires = bootstrap_space().wires.len();
        let resolvers_searched = PROXYLESS_MAX_CANDIDATES / wires;
        assert_eq!(
            (wires, resolvers_searched),
            (1, 8),
            "expected 8 resolvers x 1 combined plan; adding a second plan would halve the resolvers"
        );

        // Worst case must stay inside the connect budget: a stale cached winner costs one attempt
        // before the search starts, then ceil(candidates / window) attempts.
        //
        // These two mirror `flint_proxyless`'s `ATTEMPT_TIMEOUT` and `PROBE_WINDOW`, which are
        // **private** to that crate and so cannot be referenced here. Named rather than inlined so
        // the coupling is visible: if flint retunes either, this test still passes while describing
        // a budget that no longer exists. Exporting them from flint is the real fix.
        const FLINT_ATTEMPT_TIMEOUT_SECS: u64 = 5;
        const FLINT_PROBE_WINDOW: usize = 4;

        let candidates = resolvers_searched * wires;
        let attempts = 1 + candidates.div_ceil(FLINT_PROBE_WINDOW) as u64;
        let worst = std::time::Duration::from_secs(attempts * FLINT_ATTEMPT_TIMEOUT_SECS);
        assert!(
            worst < CONNECT_TIMEOUT,
            "worst-case search {worst:?} must finish inside {CONNECT_TIMEOUT:?} with margin, or the \
             race cancels it exactly when it would have cached a winner. If flint retuned \
             ATTEMPT_TIMEOUT or PROBE_WINDOW, update the mirrored constants above."
        );
    }

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
        let oneshot = build_oneshot_request(
            &FetchEnv::prod().path,
            &req,
            &Conditional::default(),
            KindlingHeaders::default(),
        )
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
        // A Kindling holding ONLY proxyless. Pointing this at `config_kindling` would test the race,
        // not the member: on any open network `direct` wins, and a proxyless avenue that had stopped
        // working entirely would still show green.
        let kindling = flint_kindling::Kindling::new()
            .with_race_options(flint_kindling::RaceOptions {
                window: 1,
                attempt_timeout: Some(CONNECT_TIMEOUT),
            })
            .with_proxyless(proxyless_transport(&env));
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
        let outcome = fetch_once_kindling(
            &env,
            &req,
            &Conditional::default(),
            &kindling,
            ATTEMPT_TIMEOUT,
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
        // NOT wiped — see the comment above. Removing the dir here would undo the credential reuse
        // it exists for, minting a fresh user on the next run after all.
    }

    /// The race as it actually ships, rather than one member of it.
    ///
    /// `live_proxyless_fetch` deliberately isolates proxyless; this covers the composed avenue —
    /// whichever member wins, the ALPN dispatch must pick an HTTP version that yields a usable body.
    ///
    /// Live: `cargo test -p spark-core --lib --features prod -- --ignored live_kindling_fetch`
    #[tokio::test]
    #[ignore = "live: needs network"]
    async fn live_kindling_fetch() {
        let env = FetchEnv::prod();
        let kindling = config_kindling(&env, 0);
        let dir = std::env::temp_dir().join("spark-live-kindling");
        // Not wiped, for the same credential-reuse reason as `live_proxyless_fetch`.
        let did = device_id(&dir).expect("device id");
        let creds = user::ensure_user(&dir, &env.pro_host, &env.pro_path)
            .await
            .expect("user-create");
        let mut req = ConfigRequest::new(did);
        req.user_id = creds.user_id.clone();
        req.pro_token = creds.pro_token.clone();
        let outcome = fetch_once_kindling(
            &env,
            &req,
            &Conditional::default(),
            &kindling,
            ATTEMPT_TIMEOUT,
        )
        .await
        .expect("kindling config-new fetch");
        match outcome {
            FetchOutcome::New { raw, .. } => {
                let cfg = Config::from_config_str(&raw).expect("adapt kindling config");
                assert!(
                    !cfg.transport.servers.is_empty(),
                    "kindling fetch should return a pool"
                );
            }
            FetchOutcome::NotModified => panic!("unexpected 304 on unconditional fetch"),
        }
    }

    /// **Diagnostic, not a test of spark.** Reports which member won and what it negotiated, so the
    /// The bootstrap dns-tunnel member is registered **exactly when this build pinned a zone**.
    ///
    /// Guards the build-time plumbing end to end, in the crate that reads it, rather than by
    /// grepping a linked binary — which is misleading here: `spark-service` never calls the fetch
    /// path, so LTO strips `config_kindling` wholesale and the zone literal is absent from that
    /// binary whether or not the build was configured correctly.
    ///
    /// The `option_env!` is read here for the same reason it is read in `bootstrap_dns_tunnel`:
    /// it is fixed at compile time, so the test asserts the *relationship* between how this build
    /// was configured and what the race carries. Run with the zone set to prove the wiring:
    /// `SPARK_BOOTSTRAP_DNS_ZONE=t.example SPARK_BOOTSTRAP_DNS_PUBKEY=<b64> cargo test -p spark-core
    /// --features prod bootstrap_dns_member`.
    #[cfg(feature = "dns-tunnel")]
    #[test]
    fn bootstrap_dns_member_present_exactly_when_pinned() {
        let env = FetchEnv::prod();
        let count = config_kindling(&env, 0).transport_count();
        // direct + fronted-scan always; proxyless and the embedded fronted list when available.
        let mut expected = 2;
        if cfg!(feature = "proxyless") {
            expected += 1;
        }
        if fronted_dialer().is_some() {
            expected += 1;
        }
        let pinned = option_env!("SPARK_BOOTSTRAP_DNS_ZONE").is_some_and(|z| !z.trim().is_empty())
            && option_env!("SPARK_BOOTSTRAP_DNS_PUBKEY").is_some();
        if pinned {
            expected += 1;
        }
        assert_eq!(
            count, expected,
            "config race has {count} members, expected {expected} (bootstrap dns-tunnel pinned: {pinned})"
        );
    }

    /// dispatch in [`fetch_once_kindling`] can be checked against reality rather than reasoned about.
    /// Expect `direct`/(no ALPN) on an open network — proxyless is meant to lose there.
    ///
    /// `cargo test -p spark-core --lib --features prod -- --ignored --nocapture which_member_wins`
    #[tokio::test]
    #[ignore = "diagnostic: needs network"]
    async fn which_member_wins() {
        let env = FetchEnv::prod();
        let kindling = config_kindling(&env, 0);
        for attempt in 1..=3 {
            match kindling.connect(&env.host).await {
                Ok(conn) => println!(
                    "  attempt {attempt}: winner={:<13} alpn={:<9} authority={:<22} -> {}",
                    conn.transport,
                    conn.info
                        .alpn
                        .as_deref()
                        .map(|a| String::from_utf8_lossy(a).into_owned())
                        .unwrap_or_else(|| "(none)".into()),
                    // Whether this differs from `env.host` is the whole reason the race carries it.
                    conn.authority(&env.host),
                    if conn.is_h2() {
                        "h2_oneshot"
                    } else {
                        "HTTP/1.1"
                    }
                ),
                Err(e) => println!("  attempt {attempt}: all members failed: {e}"),
            }
        }
    }

    #[test]
    fn the_direct_member_is_named_for_the_race_error_message() {
        use flint_kindling::ConnectionTransport as _;
        assert_eq!(DirectConfigTransport { port: 443 }.name(), "direct");
    }

    /// Pins the member count the race window is derived from — `direct` always, plus `proxyless`
    /// where the feature is on, plus `dns-tunnel` where the feature is on *and* this build pinned
    /// bootstrap parameters. The window itself is not publicly readable off `Kindling`, so this
    /// asserts the input to that one-line derivation rather than the window.
    ///
    /// The point is that a `config-fetch`-only build still gets a working single-member race, and
    /// that adding a member changes the window with it instead of leaving a stale literal.
    #[test]
    fn the_race_has_one_member_per_enabled_avenue() {
        let members = config_kindling(&FetchEnv::prod(), 0).transport_count();
        // direct, plus the vantage-point scanner — both unconditional.
        let mut expected = 2;
        if cfg!(feature = "proxyless") {
            expected += 1;
        }
        // The embedded front list is present unless its bundled config fails to parse, which would be
        // a build problem rather than a runtime one.
        if fronted_dialer().is_some() {
            expected += 1;
        }
        // Feature alone is not enough: without build-time parameters there is no tunnel to dial, so
        // the member is absent by design rather than broken.
        if cfg!(feature = "dns-tunnel") && bootstrap_is_pinned() {
            expected += 1;
        }
        assert_eq!(members, expected, "member count drives the race window");
    }

    /// The embedded front list must actually parse — every other test here would still pass with a
    /// corrupt `fronted.yaml.gz`, since a `None` dialer simply drops the member from the race.
    #[test]
    fn the_embedded_front_list_parses() {
        assert!(
            fronted_dialer().is_some(),
            "embedded fronted.yaml.gz failed to parse, silently costing the race a member"
        );
    }

    /// Whether this build pinned bootstrap DNS-tunnel parameters. Mirrors `bootstrap_dns_tunnel`'s
    /// own precondition so the count test states the rule rather than hardcoding today's answer.
    fn bootstrap_is_pinned() -> bool {
        option_env!("SPARK_BOOTSTRAP_DNS_ZONE").is_some()
            && option_env!("SPARK_BOOTSTRAP_DNS_PUBKEY").is_some()
    }

    /// An ordinary build pins nothing, so the member must be absent — not a half-built transport that
    /// fails at dial time inside the race, where it would burn an attempt slot on every fetch.
    #[cfg(feature = "dns-tunnel")]
    #[test]
    fn without_build_time_parameters_there_is_no_dns_tunnel_member() {
        if bootstrap_is_pinned() {
            return; // a build that pinned them legitimately has the member
        }
        assert!(
            bootstrap_dns_tunnel(&FetchEnv::prod()).is_none(),
            "unpinned build must not produce a dns-tunnel member"
        );
    }

    /// The name the race reports for this member — it is what appears in an `AllFailed` error, which
    /// on a censored network is the only evidence anyone gets about which avenues were tried.
    #[cfg(feature = "dns-tunnel")]
    #[test]
    fn the_dns_tunnel_member_is_named_for_the_race_error_message() {
        use flint_kindling::ConnectionTransport as _;
        let cfg = crate::config::DnsTunnelConfig {
            zone: "t.example.com".into(),
            // A syntactically valid but throwaway key: this asserts naming, not connectivity.
            server_pubkey: dns_tunnel_core::crypto::base64_encode(&[7u8; 32]),
            resolvers: vec!["127.0.0.1:5353".into()],
            authoritative: None,
            cipher: crate::config::DnsTunnelCipher::default(),
            compression: crate::config::DnsTunnelCompression::default(),
            duplication: Some(3),
            use_system_resolvers: Some(false),
        };
        let (tunnel, _) = crate::transport::dns_tunnel_transport(&cfg, None).expect("builds");
        assert_eq!(
            DnsTunnelConfigTransport { tunnel, port: 443 }.name(),
            "dns-tunnel"
        );
    }

    /// The contract [`fetch_once_kindling`] dispatches on: spark's `fetch_connector` offers no ALPN,
    /// so the direct member negotiates nothing and reports `None`, which the dispatch reads as
    /// HTTP/1.1. Asserting this needs a real handshake — a failed connect would report `None` too,
    /// and would prove nothing.
    ///
    /// Live: `cargo test -p spark-core --lib --features prod -- --ignored direct_member_negotiates_no_alpn`
    #[tokio::test]
    #[ignore = "live: needs network"]
    async fn direct_member_negotiates_no_alpn() {
        use flint_kindling::ConnectionTransport as _;
        let env = FetchEnv::prod();
        let (_stream, info) = DirectConfigTransport { port: env.port }
            .connect_info(&env.host)
            .await
            .expect("direct dial to the config host");
        assert_eq!(
            info.alpn, None,
            "fetch_connector sets no ALPN; if this changes, the HTTP/1.1 branch is wrong"
        );
        // And it must not claim an authority — only a fronted member routes by another name.
        assert_eq!(info.authority, None);
        assert_eq!(info.authority(&env.host), env.host);
    }

    /// Which protocol does a fronted edge actually speak? **It varies per connection**, which is the
    /// finding that decides whether fronting can join a kindling connection race.
    ///
    /// Measured over four runs, two fresh connections each:
    ///
    /// ```text
    /// run 1:  h2 -> HTTP 500          http/1.1 -> no header terminator
    /// run 2:  h2 -> frame size error  http/1.1 -> HTTP 500
    /// run 3:  h2 -> frame size error  http/1.1 -> HTTP 500
    /// run 4:  h2 -> frame size error  http/1.1 -> HTTP 500
    /// ```
    ///
    /// `GoAway(FRAME_SIZE_ERROR, Library)` is our *own* h2 client rejecting the bytes — the
    /// signature of parsing an HTTP/1.1 response as h2 frames. The dialer races several masquerade
    /// candidates and whichever edge wins may have negotiated either protocol, so a caller holding
    /// only the stream cannot know which to speak.
    ///
    /// Together with `conn.front` being dropped, that is two things
    /// `ConnectionTransport::connect` erases which an HTTP caller needs: the inner authority and the
    /// negotiated protocol. It is why flint has `dial_fronts_alpn` at all, and why the fronted
    /// avenue is a one-shot: `race_oneshot` runs the full dial *and* request per candidate, so a
    /// candidate wins only after a complete response — which inherently discards edges speaking a
    /// protocol the caller cannot handle. A connect-race would pick the fastest handshake and then
    /// discover the problem.
    ///
    /// (The HTTP 500s are the origin's answer to spark's request shape at the time of measurement,
    /// unrelated to the protocol question — what matters here is which protocol got *an* answer.)
    ///
    /// `cargo test -p spark-core --features prod -- --ignored --nocapture which_protocol_fronted`
    #[cfg(feature = "samizdat")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "diagnostic: needs network"]
    async fn which_protocol_fronted() {
        let dialer = fronted_dialer().expect("embedded fronted config parses");
        let env = FetchEnv::prod();
        let dir = std::env::temp_dir().join("spark-probe-fronted-conn");
        let did = device_id(&dir).unwrap();
        let creds = user::ensure_user(&dir, &env.pro_host, &env.pro_path)
            .await
            .expect("user-create");
        let mut req = ConfigRequest::new(did);
        req.user_id = creds.user_id.clone();
        req.pro_token = creds.pro_token.clone();

        // h2 over one connection.
        match dialer.connect_fronted(&env.host).await {
            Ok(conn) => {
                let authority = conn.fronted_host().to_owned();
                let oneshot = build_oneshot_request(
                    &env.path,
                    &req,
                    &Conditional::default(),
                    KindlingHeaders::default(),
                )
                .expect("oneshot");
                match flint_kindling::h2_oneshot(conn.stream, &authority, &oneshot).await {
                    Ok(r) => println!(
                        "  h2       -> HTTP {} ({} body bytes)",
                        r.status,
                        r.body.len()
                    ),
                    Err(e) => println!("  h2       -> ERROR {e}"),
                }
            }
            Err(e) => println!("  h2       -> could not connect: {e}"),
        }

        // HTTP/1.1 over another.
        match dialer.connect_fronted(&env.host).await {
            Ok(conn) => {
                let authority = conn.fronted_host().to_owned();
                let bytes = build_request_bytes(
                    &authority,
                    &env.path,
                    &req,
                    &Conditional::default(),
                    KindlingHeaders::default(),
                )
                .expect("request bytes");
                match post_collect(conn.stream, &bytes, MAX_BODY).await {
                    Ok(r) => println!(
                        "  http/1.1 -> HTTP {} ({} body bytes)",
                        r.status,
                        r.body.len()
                    ),
                    Err(e) => println!("  http/1.1 -> ERROR {e}"),
                }
            }
            Err(e) => println!("  http/1.1 -> could not connect: {e}"),
        }
        println!("(whichever answers is what the edge negotiated on that connection)");
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

        let oneshot = build_oneshot_request(
            &env.path,
            &req,
            &Conditional::default(),
            KindlingHeaders::default(),
        )
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
        // A Kindling holding ONLY the embedded-list fronted dialer, for the same reason
        // `live_proxyless_fetch` isolates its member: against the full race `direct` wins on an open
        // network, so a broken fronted avenue would still show green.
        let kindling = flint_kindling::Kindling::new()
            .with_race_options(flint_kindling::RaceOptions {
                window: 1,
                attempt_timeout: Some(CONNECT_TIMEOUT),
            })
            .with_fronted_tls(dialer);
        let outcome = fetch_once_kindling(
            &env,
            &req,
            &Conditional::default(),
            &kindling,
            ATTEMPT_TIMEOUT,
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
        // Not wiped — see the credential-reuse note above.
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
            capabilities: None,
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
