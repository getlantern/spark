//! Diagnostics host for a TUNNEL process (design spec §5 / Phase B: the NE sysext on
//! macOS today). Mirrors the app-process host (the plugin's `diag_host.rs`): one-time
//! wiring of sink (spool + backup log), panic hook, and the config-gated OTLP
//! uploader — fed by re-parsing the tunnel's own `config_raw.json` cache — plus a
//! per-SESSION unclean-exit sentinel (see below). There is NO tracing-subscriber
//! layer here: in the NE the `log_bridge` owns the process-global subscriber slot and
//! forwards into the sink itself (see `log_bridge::BridgeSubscriber::event` +
//! `layer::capture_decision`), so installing this sink is what turns that
//! forwarding on.
//!
//! ## Sentinel lifetime — one tunnel SESSION, not one process
//! The NE sysext process persists across stopTunnel→startTunnel, so [`init`] runs
//! once per tunnel session while the once-only wiring (sink, panic hook, uploader,
//! config re-parse loop) runs once per process. The unclean-exit sentinel is the
//! per-session piece: armed on EVERY `init` (session start) and disarmed by
//! [`disarm_sentinel`] at clean stop — so every session is crash-protected. (An
//! earlier design early-returned whole on the second `init`, leaving the sentinel
//! disarmed after the first clean stop: a crash in any later session in the same
//! process went undetected.)
//!
//! ## Device identity
//! The NE and the app run in separate containers by platform constraint — the root
//! sysext cannot read the user's App Group container (sandbox-denied), so there is no
//! shared `device_id` file. The app therefore hands its id down through
//! `providerConfiguration` and [`init`] takes it as `device_id`, so one physical device
//! reports ONE `client.device_id` with `spark.component` ("app" / "tunnel")
//! distinguishing the processes. Only when no id is supplied (Android, CLI) does this
//! fall back to deriving one from the data dir — which also *persists* it, and is why
//! the supplied path must not fall through. See `docs/identity-unification-design.md`.
//!
//! ## Consent: informed, on by default
//! Diagnostics run unless explicitly declined ([`super::diagnostics_enabled`]). The user is
//! *told* that diagnostics are collected — the disclosure is the product surface — rather than
//! being asked to switch them on, which in a test build would mean collecting from almost nobody.
//!
//! The tunnel has no persisted toggle (the app owns the user-facing setting, and its persistence
//! lives in an app container this process can't read), so the decline arrives per launch via
//! `SPARK_DIAGNOSTICS=off`. Plumbing the app's toggle through `providerConfiguration` alongside
//! the unified device id is the production channel and the remaining piece.
//!
//! Init is infallible by design (same contract as the app host): every step degrades
//! gracefully to less diagnostics, and internal failures log at `tracing::debug!`
//! ONLY (diag internals must never re-enter the capture pipeline at a captured level).

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
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

/// The CURRENT session's armed unclean-exit sentinel, set by [`arm_and_register`]
/// the instant `SessionSentinel::arm` returns. Deliberately separate from [`STATE`],
/// which is only set at the END of init (after uploader construction): the
/// clean-stop disarm ([`disarm_sentinel`], called from the NE's stop path) races the
/// rest of init, so a clean fast-stop in that window would find a `STATE`-backed
/// accessor `None`, leave the marker armed, and flag a false `error.unclean_exit` on
/// the next launch. Armed-to-reachable must be one atomic step. (Same rationale and
/// pattern as the plugin's `diag_host::SENTINEL`.)
///
/// A `Mutex<Option<..>>`, NOT a OnceLock: the sentinel is per tunnel SESSION and the
/// NE process outlives sessions (see the module doc), so every [`init`] re-arms and
/// replaces the stored Arc.
static SENTINEL: Mutex<Option<Arc<SessionSentinel>>> = Mutex::new(None);

/// A poisoned lock means another thread panicked while swapping/reading the slot;
/// the `Option` inside is still structurally sound, so keep going (same posture as
/// `sink::lock_files` and `sentinel::lock_disarmed`).
fn lock_sentinel() -> MutexGuard<'static, Option<Arc<SessionSentinel>>> {
    SENTINEL.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Per-session diagnostics init for a TUNNEL process (NE sysext today). **Must be
/// called from within a tokio runtime** — the sink writer, the config re-parse task,
/// and the uploader all `tokio::spawn`. Infallible. The first call in a process does
/// the full once-only wiring; later calls (a new tunnel session in the same process)
/// only re-arm the unclean-exit sentinel (see the module doc).
///
/// `data_dir` is the tunnel's own cache dir — the same one its config fetch uses
/// (`fetch::run_loop`), so the re-parsed `config_raw.json` matches the config of the
/// requests this process actually makes.
///
/// `device_id` is the app-supplied one when the controlling app handed identity down.
/// Passing it matters twice over: telemetry then attributes one physical device to ONE
/// `client.device_id` (retiring the split described in the module doc), and — because the
/// fallback `fetch::device_id()` *creates and persists* a file — it is what keeps the
/// tunnel from minting its own identity behind the fetch path's back.
pub fn init(data_dir: &Path, version: &str, device_id: Option<&str>) {
    // Shared with the service host so the two cannot drift. On by default; see the module doc.
    if !super::diagnostics_enabled() {
        return;
    }
    // A later session in this same process (the NE persists across
    // stopTunnel→startTunnel): the once-only wiring is already up from the first
    // call — only the sentinel is per-session, so re-arm it and bail. Checked
    // BEFORE constructing a sink: a throwaway second `DiagSink` would race the live
    // one (its constructor folds any leftover take-file into its own spool handle,
    // colliding with an uploader take in flight).
    if super::sink::installed() {
        rearm_sentinel(data_dir, version);
        return;
    }
    // The sink: ring + `diagnostics.jsonl` spool + `diag.log` backup, directly under
    // the tunnel's data dir. An unwritable dir means no diagnostics this run.
    let Ok(sink) = DiagSink::new(data_dir, "tunnel") else {
        return;
    };
    // First-install-wins (OnceLock). Bail if a concurrent caller won the race
    // between the installed() check above and here: continuing would wire a second
    // uploader rotating the same spool/log files as the winner's, while emit() feeds
    // only the winner — and the winner's init arms the sentinel itself.
    if !super::install(sink.clone()) {
        tracing::debug!("diag: sink already installed — skipping duplicate tunnel host init");
        return;
    }
    init_with_sink(sink, data_dir, version, device_id);
}

/// Clean-shutdown disarm for the unclean-exit sentinel. Safe to call at any time —
/// a no-op when diagnostics never initialized (or before the sentinel armed) — and
/// idempotent, so both the NE's `stop()` path and the lantern-api loop's clean exit
/// may call it (belt and suspenders).
pub fn disarm_sentinel() {
    // Clone out of the lock so the marker-file I/O in disarm() runs without holding
    // the slot (a racing re-arm swaps the Arc, not the sentinel we're disarming).
    let current = lock_sentinel().clone();
    if let Some(s) = current {
        s.disarm();
    }
}

/// The body of [`init`] after the opt-out gate and the global sink install, factored
/// so tests can drive it against a test sink without touching the global `SINK`
/// OnceLock (which can only be set once per process — installing it in a test would
/// leak into every other test; same constraint the sink/layer tests document).
fn init_with_sink(sink: Arc<DiagSink>, data_dir: &Path, version: &str, device_id: Option<&str>) {
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

    // Resource attributes stamped on every OTLP upload. Prefer the app-supplied device id so
    // diagnostics report the SAME identity the config requests use. The dir-backed fallback is for
    // hosts that own their own identity (Android, CLI) — note it *persists* a `device_id` file, which
    // is precisely why the supplied path must not fall through to it.
    let device_id = device_id.map(str::to_owned).unwrap_or_else(|| {
        crate::config::fetch::device_id(data_dir).unwrap_or_else(|_| "unknown".into())
    });
    let cache_path = crate::config::fetch::cache::raw_path(data_dir);
    let res = resource_attrs(version, &device_id, &cache_path);

    // The uploader's config feed: a watch channel seeded from the cached
    // config_raw.json, re-read every CONFIG_REPARSE_INTERVAL by a detached
    // (process-lifetime, genuinely fire-and-forget) task. This piggybacks on the
    // tunnel's own poll loop rewriting the cache, without coupling to the fetch path.
    let (cfg_tx, cfg_rx) = tokio::sync::watch::channel(otel_from_cache(&cache_path));
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(CONFIG_REPARSE_INTERVAL).await;
            // The sentinel heartbeat rides this existing 60s tick rather than owning
            // a timer task: one process-lifetime loop instead of two, and ~1 min
            // last_alive resolution is all an unclean-exit timestamp needs. Read the
            // CURRENT sentinel from the lock each tick (never a captured Arc): this
            // task outlives tunnel sessions and re-arms replace the stored sentinel,
            // so beats must follow the live session's marker, not keep poking a
            // disarmed prior session's. Cloned out so the guard isn't held across
            // the marker-file I/O.
            let sentinel = lock_sentinel().clone();
            if let Some(s) = sentinel {
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

/// Sentinel-only init for the second and later tunnel sessions in one process: arm a
/// fresh sentinel — replacing the previous session's, which that session's clean
/// stop disarmed — and emit any leftover marker's event through the already-installed
/// global sink.
///
/// In practice the leftover emit is dead code on this path: a leftover here would
/// mean the previous session in this same process crashed, but a crash kills the
/// whole process, so the next `init` is a FIRST init in a fresh process and the
/// leftover surfaces there instead. The arm-time check is harmless, and keeping it
/// covers marker-file weirdness (partial disarm I/O failure, an externally restored
/// file) rather than special-casing it away.
fn rearm_sentinel(dir: &Path, version: &str) {
    if let Some(ev) = arm_and_register(dir, version) {
        super::emit_error(ev);
    }
}

/// Arm the unclean-exit sentinel in `dir` and make it the CURRENT one — the one
/// [`disarm_sentinel`] and the heartbeat reach via [`SENTINEL`] — in the same step,
/// returning the previous session's leftover `error.unclean_exit` event (if any) for
/// the caller to emit. Called once per tunnel SESSION (first init and every re-arm),
/// not once per process.
///
/// Armed-to-reachable must be one atomic step: the moment `SessionSentinel::arm` has
/// written the marker, the clean-stop path must be able to disarm it — the stop path
/// races everything `init_with_sink` does after this call. Registering here closes
/// the fast-stop race down to the window inside `arm` itself (milliseconds, the same
/// accepted window as a crash before arm).
fn arm_and_register(dir: &Path, version: &str) -> Option<DiagEvent> {
    let (sentinel, prev) = SessionSentinel::arm(dir, version);
    *lock_sentinel() = Some(Arc::new(sentinel));
    prev
}

/// Build the [`ResourceAttrs`] for this process (spec §C3's resource block).
fn resource_attrs(version: &str, device_id: &str, cache_path: &Path) -> ResourceAttrs {
    ResourceAttrs {
        service_version: version.to_string(),
        // Resolved by core's build script — see `crate::GIT_SHA` for why it is a constant here
        // rather than an `option_env!` at each host.
        git_sha: crate::GIT_SHA.to_string(),
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
        // Resolved by core's build script. Asserted as non-empty rather than as a literal: in a
        // checkout it is the short HEAD sha, and outside one the documented "unknown" fallback —
        // both legitimate, and an empty value is the only genuinely broken outcome.
        assert!(!res.git_sha.is_empty(), "git_sha must always be populated");
        // Lantern platform convention (darwin, not macos) on this host.
        #[cfg(target_os = "macos")]
        assert_eq!(res.platform, "darwin");
        let _ = fs::remove_dir_all(&dir);
    }

    /// The process-global [`SENTINEL`] slot is mutable (per-session re-arm), so the
    /// tests that arm/disarm through the module globals serialize here — otherwise a
    /// parallel test could swap the stored sentinel between one test's arm and its
    /// disarm assertions.
    static SENTINEL_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn serialize_sentinel_tests() -> MutexGuard<'static, ()> {
        SENTINEL_TEST_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn read_marker(dir: &Path) -> serde_json::Value {
        let raw = fs::read_to_string(dir.join("diag.session")).expect("marker must exist");
        serde_json::from_str(&raw).expect("marker parses")
    }

    // The one test allowed to exercise init_with_sink: it sets the process-global
    // STATE OnceLock, which can only be set once per process — so it owns the
    // uploader-wiring lifecycle (init → files exist → disarm). init() itself is NOT
    // driven here: it installs the process-global diag SINK, which would leak into
    // every other test in this binary (the documented constraint that init_with_sink
    // exists to work around).
    #[tokio::test]
    async fn init_with_sink_wires_files_sentinel_and_disarm() {
        let _serial = serialize_sentinel_tests();
        let dir = test_dir("init_with_sink");
        // Safe whenever: a no-op before any arm, idempotent after (whether the slot
        // is empty or holds another test's already-disarmed sentinel).
        disarm_sentinel();

        let sink = DiagSink::new(&dir, "tunnel").expect("sink in tempdir");
        init_with_sink(sink, &dir, "9.9.9", None);

        // Sink files + the armed sentinel marker exist; no cache file is fine (the
        // watch channel seeds None and the uploader stays gated off).
        assert!(dir.join("diagnostics.jsonl").exists());
        assert!(dir.join("diag.log").exists());
        assert!(dir.join("diag.session").exists(), "sentinel must be armed");
        assert!(lock_sentinel().is_some(), "sentinel reachable after init");
        assert!(STATE.get().is_some(), "uploader state set after init");

        // Clean-stop path: disarm removes the marker so next launch is clean.
        disarm_sentinel();
        assert!(
            !dir.join("diag.session").exists(),
            "disarm_sentinel must remove the marker"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    // Re-arm across tunnel sessions in ONE process (the NE sysext persists across
    // stopTunnel→startTunnel). Drives the exact pieces init()'s re-arm path uses —
    // arm_and_register, disarm_sentinel, and the SENTINEL slot the beat task reads —
    // NOT init()/rearm_sentinel themselves: init() installs the process-global SINK
    // (leaks into every other test) and rearm_sentinel only adds emit_error on top,
    // a no-op without that global sink. So what this can't cover is the leftover
    // event reaching the global sink and the 60s beat timer itself; the
    // beats-follow-re-arms property is asserted by beating through the stored Arc
    // the task clones each tick.
    #[test]
    fn rearm_after_disarm_protects_second_session() {
        let _serial = serialize_sentinel_tests();
        let dir = test_dir("rearm_second_session");

        // Session 1: arm, then clean stop.
        let prev = arm_and_register(&dir, "1.0.0");
        assert!(prev.is_none(), "fresh dir must not flag an unclean exit");
        assert!(dir.join("diag.session").exists());
        disarm_sentinel();
        assert!(
            !dir.join("diag.session").exists(),
            "clean stop removes the marker"
        );

        // Session 2 in the SAME process: the re-arm must write a fresh marker (the
        // old OnceLock design left the slot holding session 1's disarmed sentinel,
        // so a crash from here on was invisible).
        let prev = arm_and_register(&dir, "2.0.0");
        assert!(
            prev.is_none(),
            "a cleanly-stopped previous session must not flag an unclean exit"
        );
        let marker = read_marker(&dir);
        assert_eq!(
            marker["version"], "2.0.0",
            "marker must be the NEW session's"
        );

        // Beats follow the re-arm: the beat task clones the stored Arc each tick,
        // and that Arc must now be session 2's live sentinel (session 1's is
        // disarmed — beating it would be a no-op and last_alive would go stale).
        let current = lock_sentinel().clone().expect("re-arm stores the sentinel");
        std::thread::sleep(std::time::Duration::from_millis(10));
        current.beat();
        let beaten = read_marker(&dir);
        assert!(
            beaten["last_alive"].as_u64().unwrap() > marker["last_alive"].as_u64().unwrap(),
            "beat must refresh the re-armed session's marker"
        );

        // Session 2 "crashes" (a real crash kills the process, so simulate by never
        // disarming): the next arm must surface it — the re-armed session was
        // crash-protected.
        let ev = arm_and_register(&dir, "3.0.0")
            .expect("a leftover marker from the re-armed session must flag an unclean exit");
        assert_eq!(ev.kind, "error.unclean_exit");
        assert_eq!(ev.fields["prev_version"], "2.0.0");

        // Leave the slot disarmed and the dir clean for other tests.
        disarm_sentinel();
        let _ = fs::remove_dir_all(&dir);
    }
}
