//! Diagnostics host for a TUNNEL process (design spec §5 / Phase B: the NE sysext on
//! macOS today). Mirrors the app-process host (the plugin's `diag_host.rs`): one-time
//! wiring of sink (spool + backup log), panic hook, unclean-exit sentinel, and the
//! config-gated OTLP uploader — fed by re-parsing the tunnel's own `config_raw.json`
//! cache. There is NO tracing-subscriber layer here: in the NE the `log_bridge` owns
//! the process-global subscriber slot and forwards into the sink itself (see
//! `log_bridge::BridgeSubscriber::event` + `layer::capture_decision`), so installing
//! this sink is what turns that forwarding on.
//!
//! ## Device identity (deliberate split)
//! The NE and the app run in separate containers by platform constraint — the root
//! sysext cannot read the user's App Group container (sandbox-denied), so there is no
//! shared `device_id` file. Each process derives its own id from its own data dir,
//! meaning one physical device reports TWO `client.device_id` values (`spark.component`
//! "app" vs "tunnel"). Unifying them by passing the app's id through
//! `providerConfiguration` is an explicit follow-up, not this module.
//!
//! ## Opt-out
//! Only the local `SPARK_DIAGNOSTICS=off` env override is honored here — the tunnel
//! has no persisted toggle (the app owns the user-facing setting, and its persistence
//! lives in the app container this process can't read). A follow-up can plumb the
//! toggle through `providerConfiguration` alongside the unified device id.
//!
//! Init is infallible by design (same contract as the app host): every step degrades
//! gracefully to less diagnostics, and internal failures log at `tracing::debug!`
//! ONLY (diag internals must never re-enter the capture pipeline at a captured level).

use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use super::otlp::ResourceAttrs;
use super::sentinel::SessionSentinel;
use super::upload::{self, SpanQueue, UploaderHandle};
use super::{panic_hook, DiagEvent, DiagSink};
use crate::config::lantern::{otel_from_config_raw_json, OtelConfig};

/// How often the uploader's config feed re-reads the cached `config_raw.json`. The
/// tunnel's own poll loop (`config::fetch::run_loop`) rewrites that cache while
/// connected, so a 60s re-parse tracks server-side gate flips (§C4 kill switch)
/// within about a minute of the cache changing. Matches the app host's cadence.
const CONFIG_REPARSE_INTERVAL: Duration = Duration::from_secs(60);

/// Live handles kept for the process lifetime: the uploader (dropping it would abort
/// the upload loop) and the span queue. The tunnel has no span producers yet — the
/// queue exists because `upload::spawn` requires one, and so that future tunnel
/// instrumentation (stall/quarantine traces, Phase B proper) has somewhere to push.
struct TunnelDiagState {
    _queue: Arc<SpanQueue>,
    _uploader: UploaderHandle,
}

/// Set once at the END of [`init_with_sink`]; never set when diagnostics are off.
static STATE: OnceLock<TunnelDiagState> = OnceLock::new();

/// The armed unclean-exit sentinel, set by [`arm_and_register`] the instant
/// `SessionSentinel::arm` returns. Deliberately separate from [`STATE`], which is
/// only set at the END of init (after uploader construction): the clean-stop disarm
/// ([`disarm_sentinel`], called from the NE's stop path) races the rest of init, so a
/// clean fast-stop in that window would find a `STATE`-backed accessor `None`, leave
/// the marker armed, and flag a false `error.unclean_exit` on the next launch.
/// Armed-to-reachable must be one atomic step. (Same rationale and pattern as the
/// plugin's `diag_host::SENTINEL`.)
static SENTINEL: OnceLock<Arc<SessionSentinel>> = OnceLock::new();

/// One-shot diagnostics init for a TUNNEL process (NE sysext today). **Must be called
/// from within a tokio runtime** — the sink writer, the config re-parse task, and the
/// uploader all `tokio::spawn`. Infallible; a second call is a no-op (the global sink
/// OnceLock rejects the duplicate install and we bail).
///
/// `data_dir` is the tunnel's own cache dir — the same one its config fetch uses
/// (`fetch::run_loop`), so the `device_id` and the re-parsed `config_raw.json` match
/// the identity/config of the requests this process actually makes.
pub fn init(data_dir: &Path, version: &str) {
    // Local opt-out (spec §C4.3): env override only — see the module doc for why the
    // tunnel has no persisted toggle.
    if std::env::var("SPARK_DIAGNOSTICS").as_deref() == Ok("off") {
        return;
    }
    // The sink: ring + `diagnostics.jsonl` spool + `diag.log` backup, directly under
    // the tunnel's data dir. An unwritable dir means no diagnostics this run.
    let Ok(sink) = DiagSink::new(data_dir, "tunnel") else {
        return;
    };
    // First-install-wins (OnceLock). Bail if an earlier caller beat us to it:
    // continuing would wire a second uploader rotating the same spool/log files as
    // the installed one, while emit() feeds only the winner.
    if !super::install(sink.clone()) {
        tracing::debug!("diag: sink already installed — skipping duplicate tunnel host init");
        return;
    }
    init_with_sink(sink, data_dir, version);
}

/// Clean-shutdown disarm for the unclean-exit sentinel. Safe to call at any time —
/// a no-op when diagnostics never initialized (or before the sentinel armed) — and
/// idempotent, so both the NE's `stop()` path and the lantern-api loop's clean exit
/// may call it (belt and suspenders).
pub fn disarm_sentinel() {
    if let Some(s) = SENTINEL.get() {
        s.disarm();
    }
}

/// The body of [`init`] after the opt-out gate and the global sink install, factored
/// so tests can drive it against a test sink without touching the global `SINK`
/// OnceLock (which can only be set once per process — installing it in a test would
/// leak into every other test; same constraint the sink/layer tests document).
fn init_with_sink(sink: Arc<DiagSink>, data_dir: &Path, version: &str) {
    // Crash capture (§C2a): a panic's message + location reach the spool before the
    // process dies, uploading on next launch. (Idempotent; chains the previous hook.)
    panic_hook::install();

    // Unclean-exit sentinel (§C2a): catches the crash classes the panic hook can't
    // see (segfault, OOM kill, watchdog, kill -9) — for the NE also the classic
    // "sysext died and nesessionmanager restarted it" cases. Armed AFTER the sink
    // exists so the previous session's `error.unclean_exit` lands via the error fast
    // path; armed and registered as ONE step (arm_and_register) so the clean-stop
    // disarm — which races everything below — can already reach it.
    if let Some(ev) = arm_and_register(data_dir, version) {
        sink.push_error(ev);
    }

    // Resource attributes stamped on every OTLP upload. The device id comes from the
    // SAME dir the tunnel's config fetch uses, so diagnostics and config requests
    // report one identity for this process (see the module doc for the app/tunnel
    // device-id split).
    let device_id = crate::config::fetch::device_id(data_dir).unwrap_or_else(|_| "unknown".into());
    let cache_path = crate::config::fetch::cache::raw_path(data_dir);
    let res = resource_attrs(version, &device_id, &cache_path);

    // The uploader's config feed: a watch channel seeded from the cached
    // config_raw.json, re-read every CONFIG_REPARSE_INTERVAL by a detached
    // (process-lifetime, genuinely fire-and-forget) task. This piggybacks on the
    // tunnel's own poll loop rewriting the cache, without coupling to the fetch path.
    let (cfg_tx, cfg_rx) = tokio::sync::watch::channel(otel_from_cache(&cache_path));
    // Cloned from the SENTINEL lock (the single source of truth since
    // arm_and_register) rather than a local binding.
    let beat_sentinel = SENTINEL.get().cloned();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(CONFIG_REPARSE_INTERVAL).await;
            // The sentinel heartbeat rides this existing 60s tick rather than owning
            // a timer task: one process-lifetime loop instead of two, and ~1 min
            // last_alive resolution is all an unclean-exit timestamp needs.
            if let Some(s) = &beat_sentinel {
                s.beat();
            }
            let next = otel_from_cache(&cache_path);
            // send_if_modified + PartialEq: wake the uploader's receiver only on a
            // real change, not on every re-parse.
            cfg_tx.send_if_modified(|cur| {
                if *cur == next {
                    false
                } else {
                    *cur = next;
                    true
                }
            });
        }
    });

    // The uploader. `local_opt_out = false`: the env opt-out already gated init() —
    // reaching this line means diagnostics are on for this launch. No span producers
    // exist in the tunnel yet (see TunnelDiagState).
    let queue = SpanQueue::new();
    let uploader = upload::spawn(sink, cfg_rx, res, false, device_id, queue.clone());
    let _ = STATE.set(TunnelDiagState {
        _queue: queue,
        _uploader: uploader,
    });
}

/// Arm the unclean-exit sentinel in `dir` and make it reachable via [`SENTINEL`] in
/// the same step, returning the previous session's leftover `error.unclean_exit`
/// event (if any) for the caller to emit.
///
/// Armed-to-reachable must be one atomic step: the moment `SessionSentinel::arm` has
/// written the marker, the clean-stop path must be able to disarm it — the stop path
/// races everything `init_with_sink` does after this call. Registering here closes
/// the fast-stop race down to the window inside `arm` itself (milliseconds, the same
/// accepted window as a crash before arm).
fn arm_and_register(dir: &Path, version: &str) -> Option<DiagEvent> {
    let (sentinel, prev) = SessionSentinel::arm(dir, version);
    // First-set-wins. A second call can't happen in production (the global sink
    // install gates duplicate host init before this point); if one ever did, the
    // registered sentinel owns the same marker path, so its beats/disarm still
    // cover it.
    let _ = SENTINEL.set(Arc::new(sentinel));
    prev
}

/// Build the [`ResourceAttrs`] for this process (spec §C3's resource block).
fn resource_attrs(version: &str, device_id: &str, cache_path: &Path) -> ResourceAttrs {
    ResourceAttrs {
        service_version: version.to_string(),
        // The plugin's build.rs sets SPARK_GIT_SHA for the PLUGIN crate only; core
        // has no build.rs, so this is "unknown" today. option_env! (not env!) so a
        // future core build-script can light it up without touching this line.
        git_sha: option_env!("SPARK_GIT_SHA")
            .unwrap_or("unknown")
            .to_string(),
        device_id: device_id.to_string(),
        platform: crate::config::fetch::request::lantern_platform(std::env::consts::OS).to_string(),
        country: country_from_cache(cache_path),
        // Mirrors FetchEnv::select: only an exact "staging" selects staging.
        environment: if std::env::var("SPARK_CONFIG_ENV").as_deref() == Ok("staging") {
            "staging"
        } else {
            "prod"
        }
        .to_string(),
        component: "tunnel".to_string(),
        os_name: std::env::consts::OS.to_string(),
        // Best-effort "": the app host shells out to `sw_vers`, but this process may
        // be a sandboxed sysext where spawning is unreliable — and the app process
        // already reports the device's OS version. Attrs are diagnostic garnish.
        os_version: String::new(),
        arch: std::env::consts::ARCH.to_string(),
    }
}

/// Best-effort top-level `"country"` string from the cached config response (the
/// server's geo view of this client). `""` when the cache or field is absent.
/// (Local copy of the app host's helper — the plugin crate can't be a core dep.)
fn country_from_cache(path: &Path) -> String {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
        .and_then(|v| v.get("country").and_then(|c| c.as_str()).map(str::to_owned))
        .unwrap_or_default()
}

/// Parse the cached `config_raw.json` at `path` into its [`OtelConfig`]. Absent or
/// unreadable cache, unparseable JSON, or a missing/empty `otel` block all yield
/// `None` (= uploads off), matching the uploader's gate contract.
fn otel_from_cache(path: &Path) -> Option<OtelConfig> {
    let raw = std::fs::read_to_string(path).ok()?;
    otel_from_config_raw_json(&raw).ok().flatten()
}

/// The tunnel's cached-config path — [`crate::config::fetch::cache::raw_path`], the
/// exact file `fetch::run_loop` writes, re-exported for the tests below.
#[cfg(test)]
fn cache_path(data_dir: &Path) -> std::path::PathBuf {
    crate::config::fetch::cache::raw_path(data_dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    /// Unique per-test scratch dir (pid + name), cleared and recreated.
    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "spark-diag-tunnel-host-{}-{}",
            std::process::id(),
            name
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create test dir");
        dir
    }

    #[test]
    fn cache_path_matches_what_the_fetch_loop_writes() {
        // Pin the coupling for real: store through the fetch cache and read the raw
        // body back through the tunnel host's path helper. If cache.rs ever renamed
        // its file, this breaks here rather than silently feeding the uploader None.
        let dir = test_dir("cache_path");
        crate::config::fetch::cache::store(
            &dir,
            r#"{ "country": "IR", "options": { "outbounds": [] } }"#,
            &Default::default(),
        )
        .expect("store cache");
        let path = cache_path(&dir);
        assert_eq!(path, dir.join("config_raw.json"));
        assert_eq!(country_from_cache(&path), "IR");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn otel_from_cache_parses_fixture() {
        let dir = test_dir("otel_from_cache");
        let path = cache_path(&dir);

        // Absent file → None (uploads off).
        assert_eq!(otel_from_cache(&path), None);

        // Hand-written fixture (never the real config_raw.json — its ingestion key
        // is live): otel block + both feature gates on.
        fs::write(
            &path,
            r#"{
              "features": { "otel.logs": true, "otel.traces": true },
              "otel": {
                "endpoint": "ingest.us.signoz.cloud:443",
                "headers": { "signoz-ingestion-key": "k1" },
                "sample_rate": 1.0
              },
              "options": { "outbounds": [] }
            }"#,
        )
        .expect("write fixture");
        let o = otel_from_cache(&path).expect("otel block should parse to Some");
        assert_eq!(o.endpoint, "ingest.us.signoz.cloud:443");
        assert!(o.logs_enabled);

        // Unparseable cache → None, not a panic.
        fs::write(&path, "not json").expect("write");
        assert_eq!(otel_from_cache(&path), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn resource_attrs_shape() {
        let dir = test_dir("resource_attrs");
        let path = cache_path(&dir);
        fs::write(
            &path,
            r#"{ "country": "DE", "options": { "outbounds": [] } }"#,
        )
        .expect("write");
        let res = resource_attrs("1.2.3", "abcd", &path);
        assert_eq!(res.component, "tunnel");
        assert_eq!(res.service_version, "1.2.3");
        assert_eq!(res.device_id, "abcd");
        assert_eq!(res.country, "DE");
        // core has no SPARK_GIT_SHA build plumbing (the plugin's build.rs covers the
        // plugin crate only) — so this is the documented fallback.
        assert_eq!(res.git_sha, "unknown");
        // Lantern platform convention (darwin, not macos) on this host.
        #[cfg(target_os = "macos")]
        assert_eq!(res.platform, "darwin");
        let _ = fs::remove_dir_all(&dir);
    }

    // The one test allowed to exercise init_with_sink: it sets the process-global
    // SENTINEL and STATE OnceLocks, which can only be set once per process — so it
    // owns the whole lifecycle (init → files exist → disarm). init() itself is NOT
    // driven here: it installs the process-global diag SINK, which would leak into
    // every other test in this binary (the documented constraint that init_with_sink
    // exists to work around).
    #[tokio::test]
    async fn init_with_sink_wires_files_sentinel_and_disarm() {
        let dir = test_dir("init_with_sink");
        assert!(
            SENTINEL.get().is_none(),
            "no sentinel before init — disarm_sentinel must be a safe no-op"
        );
        disarm_sentinel(); // must not panic pre-init

        let sink = DiagSink::new(&dir, "tunnel").expect("sink in tempdir");
        init_with_sink(sink, &dir, "9.9.9");

        // Sink files + the armed sentinel marker exist; no cache file is fine (the
        // watch channel seeds None and the uploader stays gated off).
        assert!(dir.join("diagnostics.jsonl").exists());
        assert!(dir.join("diag.log").exists());
        assert!(dir.join("diag.session").exists(), "sentinel must be armed");
        assert!(SENTINEL.get().is_some(), "sentinel reachable after init");
        assert!(STATE.get().is_some(), "uploader state set after init");

        // Clean-stop path: disarm removes the marker so next launch is clean.
        disarm_sentinel();
        assert!(
            !dir.join("diag.session").exists(),
            "disarm_sentinel must remove the marker"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
