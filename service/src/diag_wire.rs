//! Diagnostics wiring for the service process (design §5 Phase B-lite): capture at
//! startup, upload once the client app tells us where to send.
//!
//! The service is the tunnel process on Windows/Linux (`spark.component` "tunnel",
//! like the macOS NE). The NE reads its otel block out of the config cache it shares
//! with the app; the service has no such cache, because the daemon loads a local
//! config file handed to it at startup (`daemon::run`) and an `otel` block only
//! exists in config-new's payload — which the *client app* fetches, deliberately, the
//! tunnel process not fetching on its own behalf (#132).
//!
//! So the endpoint arrives over the control plane instead: the app forwards the block
//! it already has as [`spark_ipc::TelemetryConfig`], and [`set_telemetry`] starts the
//! uploader against it. Everything else the upload needs — BoringSSL, the CA anchors,
//! `diag::upload` itself — was already linked here. (An earlier version of this
//! comment blamed the feature set and a 4 MiB size budget for the absent uploader;
//! every premise in it was false, which is why it is worth saying what the real one
//! was. See #165 / #174.)
//!
//! Ferrying whole spool batches to the app for it to upload was the other candidate.
//! It is the heavier of the two, and was only preferable while the service was
//! assumed to have no TLS.
//!
//! **The key travels one way.** It is never echoed back to any IPC peer, and no
//! response, event, or `Details` field exposes it (CLAUDE.md).
//!
//! What runs at init is the capture side: the sink (spool + backup log under the
//! service state dir), the `DiagLayer` on the daemon's subscriber (see
//! `daemon::init_tracing`), the panic hook, and the unclean-exit sentinel. That side
//! is deliberately independent of the uploader — records accumulate in
//! `diagnostics.jsonl`/`diag.log` from process start, so a service that is never told
//! an endpoint (or never reaches it) has its startup diagnostics on disk rather than
//! lost, and ships them whenever a path opens.
//!
//! Same infallibility contract as the other diag hosts: every step degrades
//! gracefully to less diagnostics, and internal failures log at `tracing::debug!`
//! ONLY (diag internals must never re-enter the capture layer at a captured level).

use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use spark_core::diag::sentinel::SessionSentinel;
use spark_core::diag::{self, panic_hook, DiagSink};
use spark_ipc::TelemetryConfig;

/// How often the sentinel heartbeat refreshes `last_alive` — the same cadence as the
/// NE host's re-parse tick, so an unclean exit dates to ~1 min resolution.
const BEAT_INTERVAL: Duration = Duration::from_secs(60);

/// The armed unclean-exit sentinel, set the instant `SessionSentinel::arm` returns
/// (before anything else in init) so a shutdown racing the tail of init can already
/// reach it via [`disarm_sentinel`] — the same armed-to-reachable-in-one-step
/// rationale as the plugin's `diag_host` and core's `tunnel_host`.
static SENTINEL: OnceLock<Arc<SessionSentinel>> = OnceLock::new();

/// What [`set_telemetry`] needs from [`init`], which runs long before it: the sink to
/// upload from, and the build version for the OTLP resource block.
///
/// Set only on the success path of init, so its absence is exactly the condition
/// "this process is not collecting diagnostics" — whether because the user declined
/// or because the state dir was unwritable. [`set_telemetry`] reports that rather
/// than silently accepting an endpoint it will never send to.
// Without `config-fetch` there is no uploader to read these, but `set_telemetry` still consults the
// lock's presence to answer "am I collecting at all?" — so the struct stays and only its fields go
// unread.
#[cfg_attr(not(feature = "config-fetch"), allow(dead_code))]
struct Capture {
    sink: Arc<DiagSink>,
    version: String,
}

static CAPTURE: OnceLock<Capture> = OnceLock::new();

/// One-shot capture-only diagnostics init. **Must be called from within a tokio
/// runtime** (the sink writer and the heartbeat task spawn). Infallible; a second
/// call is a no-op (the global sink OnceLock rejects the duplicate install).
///
/// `state_dir` is the service state dir — the profiles file's parent
/// (`/var/lib/spark` / `C:\ProgramData\spark`), the same root-owned dir the profile
/// store already creates and writes, so the writability assumption is shared.
pub fn init(state_dir: &Path, version: &str) {
    // Shares the tunnel host's predicate rather than re-implementing it. Two gates that
    // could drift is how one entry point ends up disagreeing with the other about whether
    // the user declined. On by default; the user is informed, not asked.
    if !spark_core::diag::diagnostics_enabled() {
        return;
    }
    // An unwritable/unresolvable dir means no diagnostics this run.
    let Ok(sink) = DiagSink::new(state_dir, "tunnel") else {
        return;
    };
    // First-install-wins: bail rather than wire a second sentinel/heartbeat over
    // the same files as an earlier winner.
    if !diag::install(sink.clone()) {
        tracing::debug!("diag: sink already installed — skipping duplicate service init");
        return;
    }
    init_with_sink(sink, state_dir, version);
}

/// Clean-shutdown disarm for the unclean-exit sentinel. Idempotent, and a safe no-op
/// when diagnostics never initialized.
pub fn disarm_sentinel() {
    if let Some(s) = SENTINEL.get() {
        s.disarm();
    }
}

/// The body of [`init`] after the opt-out gate and the global sink install, factored
/// so tests can drive it against a test sink without touching the global `SINK`
/// OnceLock (settable once per process — installing it in a test would leak into
/// every other test; the same constraint core's diag tests document).
fn init_with_sink(sink: Arc<DiagSink>, state_dir: &Path, version: &str) {
    // Crash capture (§C2a): a panic's message + location reach the spool before the
    // process dies. (Idempotent; chains the previous hook.)
    panic_hook::install();

    // Unclean-exit sentinel (§C2a): catches segfault/OOM/kill -9/SCM-kill — armed
    // and registered as ONE step so the shutdown disarm (which races the rest of
    // init) can already reach it; the previous session's leftover flows through the
    // error fast path.
    let (sentinel, prev) = SessionSentinel::arm(state_dir, version);
    let sentinel = Arc::new(sentinel);
    let _ = SENTINEL.set(Arc::clone(&sentinel));
    if let Some(ev) = prev {
        sink.push_error(ev);
    }

    // Reachable by `set_telemetry`, which runs whenever the app gets around to
    // telling us where to upload — typically seconds to minutes after this.
    let _ = CAPTURE.set(Capture {
        sink,
        version: version.to_string(),
    });

    // Heartbeat (process-lifetime, genuinely fire-and-forget): the NE host rides its
    // config re-parse tick, but the service has no such loop — a daemon can run for
    // weeks, and without beats `last_alive` would stay at start time, making the
    // "when did it die" half of an unclean-exit report useless.
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(BEAT_INTERVAL).await;
            sentinel.beat();
        }
    });
}

/// Point the diagnostics uploader at a collector, starting it on the first usable
/// config and re-pointing it on every later one (`RequestPayload::SetTelemetry`).
///
/// **Must be called from within a tokio runtime** on the call that starts the
/// uploader. The service event loop is one, so every real call site qualifies.
///
/// An empty `endpoint` means "telemetry off", matching radiance's rule and
/// `upload_allowed`'s: it pushes `None` to a running uploader (which then ships
/// nothing until pointed somewhere again) and starts nothing if none is running yet.
/// A service that is never given a real endpoint therefore allocates no upload
/// machinery at all.
///
/// Returns `Err` with a caller-facing reason when this process cannot upload, so the
/// control plane answers honestly instead of `Ack`-ing into a void. Both reasons are
/// states of *this* build/launch, not faults in the request.
pub fn set_telemetry(cfg: &TelemetryConfig) -> Result<(), &'static str> {
    let Some(capture) = CAPTURE.get() else {
        return Err("diagnostics are not collected in this process");
    };
    #[cfg(not(feature = "config-fetch"))]
    {
        // The uploader reuses config-fetch's TLS/HTTP plumbing and only compiles with it
        // (core gates `diag::upload` on the same feature, so that a build whose `tls_wrap`
        // degrades to a plaintext passthrough cannot contain an uploader at all).
        let _ = (capture, cfg);
        Err("this build has no diagnostics uploader (built without `config-fetch`)")
    }
    #[cfg(feature = "config-fetch")]
    {
        upload_impl::set(capture, cfg);
        Ok(())
    }
}

/// The uploader half, compiled only where `diag::upload` exists.
#[cfg(feature = "config-fetch")]
mod upload_impl {
    use super::Capture;
    use std::sync::{Arc, OnceLock};

    use spark_core::config::lantern::OtelConfig;
    use spark_core::diag::otlp::ResourceAttrs;
    use spark_core::diag::upload::{self, SpanQueue, UploaderHandle};
    use spark_ipc::TelemetryConfig;
    use tokio::sync::watch;

    /// The running uploader. `cfg_tx` re-points it; the other two are held to keep
    /// them alive — dropping `UploaderHandle` aborts the upload loop.
    struct Running {
        cfg_tx: watch::Sender<Option<OtelConfig>>,
        _spans: Arc<SpanQueue>,
        _handle: UploaderHandle,
    }

    static RUNNING: OnceLock<Running> = OnceLock::new();

    /// Start-or-repoint. See [`super::set_telemetry`] for the contract.
    pub(super) fn set(capture: &Capture, cfg: &TelemetryConfig) {
        let otel = otel_config(cfg);
        // Nothing running and nothing to run for: don't allocate a channel and a task
        // to carry "off".
        if otel.is_none() && RUNNING.get().is_none() {
            return;
        }
        // `get_or_init` rather than `set`: it initializes exactly once even if two
        // peers race, and hands back the winner's channel so the loser's value still
        // lands. (The event loop serializes calls today; this does not depend on it.)
        let running = RUNNING.get_or_init(|| start(capture, cfg, otel.clone()));
        // Wake the upload loop only on a real change, not on every repeat of an
        // unchanged config — the app re-sends on a timer.
        running.cfg_tx.send_if_modified(|cur| {
            if *cur == otel {
                false
            } else {
                *cur = otel;
                true
            }
        });
    }

    /// Spawn the upload loop against `initial`.
    ///
    /// The resource block and the sampling identity are fixed here, at first start,
    /// and a later `SetTelemetry` re-points only the endpoint/gates. That is the
    /// intended asymmetry: `device_id` is the app's, and an app whose device id
    /// changed mid-run would be a different install, not a re-point.
    fn start(capture: &Capture, cfg: &TelemetryConfig, initial: Option<OtelConfig>) -> Running {
        let (cfg_tx, cfg_rx) = watch::channel(initial);
        let spans = SpanQueue::new();
        // `local_opt_out = false`: the opt-out already gated `init`, so a sink
        // existing means diagnostics are on for this launch.
        let handle = upload::spawn(
            capture.sink.clone(),
            cfg_rx,
            resource_attrs(&capture.version, cfg),
            false,
            cfg.device_id.clone(),
            spans.clone(),
        );
        Running {
            cfg_tx,
            _spans: spans,
            _handle: handle,
        }
    }

    /// The OTLP resource block for this process (design §C3).
    ///
    /// `device_id` and `country` come from the app rather than from disk: the tunnel
    /// process has no config cache to read them out of, and the point of taking the
    /// app's values is that both processes report under ONE identity — otherwise the
    /// tunnel's half of a session cannot be joined to the app's.
    fn resource_attrs(version: &str, cfg: &TelemetryConfig) -> ResourceAttrs {
        ResourceAttrs {
            service_version: version.to_string(),
            // No build script on this crate today; `option_env!` (not `env!`) so adding
            // one lights this up without touching this line.
            git_sha: option_env!("SPARK_GIT_SHA")
                .unwrap_or("unknown")
                .to_string(),
            device_id: cfg.device_id.clone(),
            platform: lantern_platform(std::env::consts::OS).to_string(),
            country: cfg.country.clone(),
            // Mirrors core's FetchEnv::select: only an exact "staging" selects staging.
            environment: if std::env::var("SPARK_CONFIG_ENV").as_deref() == Ok("staging") {
                "staging"
            } else {
                "prod"
            }
            .to_string(),
            component: "tunnel".to_string(),
            os_name: std::env::consts::OS.to_string(),
            // Left empty for the same reason the NE host does: the app process already
            // reports the device's OS version, and these attrs are diagnostic garnish
            // rather than anything a query keys on.
            os_version: String::new(),
            arch: std::env::consts::ARCH.to_string(),
        }
    }

    /// The Lantern platform convention ("darwin", not "macos"). A local copy of core's
    /// `config::fetch::request::lantern_platform`, which is `pub(crate)` there — the
    /// plugin's `diag_host` keeps the same copy, for the same reason: a 4-line match
    /// isn't worth widening core's public API.
    fn lantern_platform(os: &str) -> &str {
        match os {
            "macos" => "darwin",
            other => other,
        }
    }

    /// Map the wire type to core's, or `None` when the endpoint is empty — radiance's
    /// `Endpoint == "" ⇒ skip` rule, which `upload_allowed` also enforces.
    fn otel_config(cfg: &TelemetryConfig) -> Option<OtelConfig> {
        if cfg.endpoint.trim().is_empty() {
            return None;
        }
        Some(OtelConfig {
            endpoint: cfg.endpoint.clone(),
            headers: cfg.headers.clone(),
            sample_rate: cfg.sample_rate(),
            logs_enabled: cfg.logs_enabled,
            traces_enabled: cfg.traces_enabled,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn wire(endpoint: &str, ppm: u32) -> TelemetryConfig {
            TelemetryConfig {
                endpoint: endpoint.into(),
                headers: vec![("signoz-ingestion-key".into(), "k".into())],
                sample_rate_ppm: ppm,
                logs_enabled: true,
                traces_enabled: false,
                device_id: "d".into(),
                country: "US".into(),
            }
        }

        /// The wire→core mapping, including the empty-endpoint kill switch that lets the app turn
        /// the tunnel's uploader off without tearing the service down.
        #[test]
        fn empty_endpoint_maps_to_off_and_a_real_one_carries_every_gate() {
            assert!(otel_config(&wire("", 1_000_000)).is_none());
            assert!(
                otel_config(&wire("   ", 1_000_000)).is_none(),
                "whitespace is not an endpoint"
            );

            let otel = otel_config(&wire("ingest.example:443", 250_000)).expect("usable config");
            assert_eq!(otel.endpoint, "ingest.example:443");
            assert_eq!(
                otel.headers,
                vec![("signoz-ingestion-key".to_string(), "k".to_string())]
            );
            assert!((otel.sample_rate - 0.25).abs() < 1e-9);
            assert!(otel.logs_enabled);
            assert!(!otel.traces_enabled);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "spark-service-diag-wire-{}-{}",
            std::process::id(),
            name
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create test dir");
        dir
    }

    fn telemetry(endpoint: &str) -> TelemetryConfig {
        TelemetryConfig {
            endpoint: endpoint.into(),
            headers: vec![("signoz-ingestion-key".into(), "k".into())],
            sample_rate_ppm: 1_000_000,
            logs_enabled: true,
            traces_enabled: true,
            device_id: "0123456789abcdef0123456789abcdef".into(),
            country: "US".into(),
        }
    }

    // The one test allowed to exercise init_with_sink: it sets the process-global
    // SENTINEL and CAPTURE OnceLocks (settable once), so it owns the whole lifecycle
    // — none before init, present after — and every assertion that depends on either
    // has to live here rather than race it from another test. init() itself is NOT
    // driven (it installs the process-global diag SINK, which would leak into every
    // other test in this binary).
    #[tokio::test]
    async fn init_arms_the_sentinel_and_opens_the_telemetry_gate() {
        let dir = test_dir("wire");
        assert!(SENTINEL.get().is_none(), "no sentinel before init");
        disarm_sentinel(); // safe no-op pre-init

        // Before init this process collects nothing, so it must SAY so rather than accept an
        // endpoint it will never send to — an `Ok` here would tell the app telemetry is flowing.
        assert!(
            set_telemetry(&telemetry("ingest.example:443")).is_err(),
            "must not accept telemetry before diagnostics are collecting"
        );

        let sink = DiagSink::new(&dir, "tunnel").expect("sink in tempdir");
        init_with_sink(sink, &dir, "1.0.0");

        assert!(dir.join("diagnostics.jsonl").exists());
        assert!(dir.join("diag.log").exists());
        assert!(dir.join("diag.session").exists(), "sentinel must be armed");
        assert!(
            SENTINEL.get().is_some(),
            "sentinel reachable the instant init returns"
        );

        // After init the gate is open. An EMPTY endpoint deliberately: it exercises the accept
        // path without starting an uploader that would dial a real host from a unit test.
        assert!(
            set_telemetry(&telemetry("")).is_ok(),
            "collecting process must accept a telemetry config"
        );

        disarm_sentinel();
        assert!(
            !dir.join("diag.session").exists(),
            "disarm must remove the marker"
        );
        disarm_sentinel(); // idempotent
        let _ = fs::remove_dir_all(&dir);
    }
}
