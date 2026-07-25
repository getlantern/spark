//! Diagnostics host for the APP process (design spec §C4/§5): one-time wiring of the
//! core `diag` pipeline — sink (spool + backup log), panic hook, tracing capture layer,
//! and the config-gated OTLP uploader — plus the webview error-report and opt-out
//! commands.
//!
//! Gated entirely on the local opt-out (spec §C4.3): when diagnostics are disabled
//! (persisted toggle or `SPARK_DIAGNOSTICS=off`) nothing is installed at all — no sink,
//! no files, no layer, no uploader. The server-side gates (`features["otel.logs"]`,
//! `otel.endpoint`, sampling) govern *upload* and are re-checked by the uploader every
//! cycle from the watch channel fed here; the local backup log is server-independent.
//!
//! Init is infallible by design: every step degrades gracefully (a failure just means
//! less diagnostics), and nothing here can block or fail plugin setup.

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tauri::{AppHandle, Manager, Runtime};

use spark_core::config::lantern::{otel_from_config_raw_json, OtelConfig};
use spark_core::diag::layer::DiagLayer;
use spark_core::diag::otlp::ResourceAttrs;
use spark_core::diag::sentinel::SessionSentinel;
use spark_core::diag::upload::{self, SpanQueue, UploaderHandle};
use spark_core::diag::{self, events, panic_hook, DiagEvent, DiagSink};
use tracing_subscriber::prelude::*;

/// How often the uploader's config feed re-reads the cached `config_raw.json`. The app
/// refreshes that cache on every launch (lib.rs startup fetch) and the tunnel's poll
/// loop rewrites it while connected, so a 60s re-parse tracks server-side gate flips
/// (§C4 kill switch) within about a minute of the cache changing.
const CONFIG_REPARSE_INTERVAL: Duration = Duration::from_secs(60);

/// Live handles the rest of the plugin needs after init: the span queue (Task 11's
/// Unbounded session spans push here) and the uploader handle (kept alive for the
/// process lifetime — dropping it would abort the upload loop). The unclean-exit
/// sentinel deliberately does NOT live here — see [`SENTINEL`].
struct DiagState {
    queue: Arc<SpanQueue>,
    _uploader: UploaderHandle,
}

/// Set once by [`init`] when diagnostics are enabled; never set when they're off.
static STATE: OnceLock<DiagState> = OnceLock::new();

/// The armed unclean-exit sentinel, set by [`arm_and_register`] the instant
/// `SessionSentinel::arm` returns. Deliberately separate from [`STATE`], which is
/// only set at the END of `init_inner` (after uploader construction): the
/// `RunEvent::Exit` disarm hook races the rest of init, so a clean fast-quit in that
/// window would find a `STATE`-backed accessor `None`, leave the marker armed, and
/// flag a false `error.unclean_exit` on the next launch. Armed-to-reachable must be
/// one atomic step.
static SENTINEL: OnceLock<Arc<SessionSentinel>> = OnceLock::new();

/// The live [`SpanQueue`], for pushing finished session spans (spec §C3a). `None`
/// until [`init`] has completed its async body — or forever, when diagnostics are
/// disabled — so instrumentation callers (`unbounded_diag::apply_actions`) must treat
/// `None` as "spans off".
pub fn span_queue() -> Option<Arc<SpanQueue>> {
    STATE.get().map(|s| s.queue.clone())
}

/// The live unclean-exit [`SessionSentinel`] (spec §C2a), for the clean-shutdown
/// disarm in `lib.rs`'s `RunEvent::Exit` hook. Reads the dedicated [`SENTINEL`] lock
/// — populated the moment the marker is armed — NOT [`STATE`], so an Exit racing the
/// tail of init still finds the sentinel. `None` until [`arm_and_register`] runs, or
/// forever when diagnostics are off.
pub(crate) fn sentinel() -> Option<Arc<SessionSentinel>> {
    SENTINEL.get().cloned()
}

/// Arm the unclean-exit sentinel in `dir` and make it reachable via [`sentinel`] in
/// the same step, returning the previous session's leftover `error.unclean_exit`
/// event (if any) for the caller to emit.
///
/// Armed-to-reachable must be one atomic step: the moment `SessionSentinel::arm` has
/// written the marker, the `RunEvent::Exit` hook must be able to disarm it — the Exit
/// hook races everything `init_inner` does after this call. Registering here closes
/// the fast-quit race down to the window inside `arm` itself (milliseconds, the same
/// accepted window as a crash before arm).
pub(crate) fn arm_and_register(dir: &Path, version: &str) -> Option<DiagEvent> {
    let (sentinel, prev) = SessionSentinel::arm(dir, version);
    // First-set-wins. A second call can't happen in production (diag::install gates
    // duplicate host init before this point); if one ever did, the registered
    // sentinel owns the same marker path, so its beats/disarm still cover it.
    let _ = SENTINEL.set(Arc::new(sentinel));
    prev
}

/// One-time diagnostics init for the APP process (spec §C4/§5). Gated entirely on the
/// local opt-out: when diagnostics are disabled nothing is installed at all — no sink,
/// no files, no layer, no uploader.
///
/// Infallible: failures degrade to less (or no) diagnostics, never an error. The
/// runtime-dependent steps run on a detached `tauri::async_runtime` task because
/// `DiagSink::new` and `upload::spawn` call `tokio::spawn` and need the ambient tokio
/// context (tauri's async runtime IS tokio, but plugin setup itself isn't guaranteed
/// to run inside it).
pub fn init<R: Runtime>(app: &AppHandle<R>) {
    // Local gate (spec §C4, revised): dev env override first, then the persisted toggle — which is
    // strictly opt-in and defaults OFF, so this returns early on a fresh install and nothing is
    // captured or spooled until the user turns it on (see persist::load_diagnostics_enabled).
    if std::env::var("SPARK_DIAGNOSTICS").as_deref() == Ok("off") {
        return;
    }
    let Ok(base) = app.path().app_config_dir() else {
        return; // no config dir ⇒ nowhere to spool — run without diagnostics
    };
    if !crate::persist::load_diagnostics_enabled(&base) {
        return;
    }

    let app = app.clone();
    // Detached on purpose: the handle is dropped, so a panic inside init_inner is
    // swallowed by tokio's task machinery instead of unwinding plugin setup — the
    // "init is infallible" contract. Diagnostics must never take the app down.
    tauri::async_runtime::spawn(async move {
        init_inner(&app, &base);
    });
}

/// The tokio-context body of [`init`] — see its doc for the gating that already ran.
fn init_inner<R: Runtime>(app: &AppHandle<R>, base: &Path) {
    // 1. The sink: ring + `diagnostics.jsonl` spool + `diag.log` backup, directly
    //    under the app's config dir. An unwritable dir means no diagnostics this run.
    let Ok(sink) = DiagSink::new(base, "app") else {
        return;
    };
    // First-install-wins (OnceLock); setup runs once per process so this normally
    // wins. Bail if an earlier caller beat us to it: continuing would wire a second
    // sink + uploader rotating the same spool/log files as the installed one, while
    // the capture layer and emit() feed only the winner.
    if !diag::install(sink.clone()) {
        tracing::debug!("diag: sink already installed — skipping duplicate host init");
        return;
    }

    // 2. Crash capture (§C2a): a panic's message + location reach the spool before
    //    the process dies, uploading on next launch.
    panic_hook::install();

    // 2a. Unclean-exit sentinel (§C2a): catches the crash classes the panic hook
    //     can't see (segfault, OOM kill, watchdog, kill -9). Armed AFTER the sink is
    //     created + installed so the previous session's `error.unclean_exit` lands in
    //     the live sink via the error fast path; a crash before this point goes
    //     undetected (accepted — the window is milliseconds of init). Armed and
    //     registered as ONE step (arm_and_register) so the Exit-hook disarm — which
    //     races everything below — can already reach it.
    if let Some(ev) = arm_and_register(base, &app.package_info().version.to_string()) {
        diag::emit_error(ev);
    }

    // 3. The tracing capture layer. `try_init` so an existing global subscriber is
    //    never clobbered. Neither this plugin nor the app crate installs one today
    //    (verified: no tracing_subscriber init anywhere under gui-tauri), so this
    //    normally wins; if a future embedder installs one first, losing here degrades
    //    to typed-event-only diagnostics (direct `diag::emit` calls still flow — only
    //    the tracing-macro bridge is lost), which is acceptable for a diagnostics
    //    side-channel.
    let _ = tracing_subscriber::registry()
        .with(DiagLayer::new())
        .try_init();

    // 4. Resource attributes stamped on every OTLP upload. The device id comes from
    //    the SAME dir the app's config fetch uses (config_fetch.rs → load_or_fetch →
    //    device_id(dir)), so diagnostics and config requests report one identity.
    let cache_dir = crate::desktop::app_config_cache_dir(base);
    let device_id =
        spark_core::config::fetch::device_id(&cache_dir).unwrap_or_else(|_| "unknown".to_string());
    let cache_path = cache_dir.join("config_raw.json");
    let res = resource_attrs(app, &device_id, &cache_path);

    // 5. The uploader's config feed: a watch channel seeded from the cached
    //    config_raw.json, re-read every 60s by a detached (process-lifetime) task.
    //    This piggybacks on the app's existing config-refresh-on-launch (and the
    //    tunnel's poll loop rewriting the cache) without coupling to the fetch path;
    //    a fetch-completion hook can replace the polling later.
    let (cfg_tx, cfg_rx) = tokio::sync::watch::channel(otel_from_cache(&cache_path));
    // Cloned from the SENTINEL lock (the single source of truth since
    // arm_and_register) rather than a local binding.
    let beat_sentinel = sentinel();
    tauri::async_runtime::spawn(async move {
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

    // 6. The uploader. `local_opt_out = false`: the opt-out already gated init() —
    //    reaching this line means diagnostics are on for this launch.
    let queue = SpanQueue::new();
    let uploader = upload::spawn(sink, cfg_rx, res, false, device_id, queue.clone());
    let _ = STATE.set(DiagState {
        queue,
        _uploader: uploader,
    });
}

/// Build the [`ResourceAttrs`] for this process (spec §C3's resource block).
fn resource_attrs<R: Runtime>(
    app: &AppHandle<R>,
    device_id: &str,
    cache_path: &Path,
) -> ResourceAttrs {
    ResourceAttrs {
        service_version: app.package_info().version.to_string(),
        // Embedded by build.rs (`git rev-parse --short HEAD`, "unknown" off-git).
        git_sha: env!("SPARK_GIT_SHA").to_string(),
        device_id: device_id.to_string(),
        platform: lantern_platform(std::env::consts::OS).to_string(),
        country: country_from_cache(cache_path),
        // Mirrors core's FetchEnv::select: only an exact "staging" selects staging.
        environment: if std::env::var("SPARK_CONFIG_ENV").as_deref() == Ok("staging") {
            "staging"
        } else {
            "prod"
        }
        .to_string(),
        component: "app".to_string(),
        os_name: std::env::consts::OS.to_string(),
        os_version: os_version(),
        arch: std::env::consts::ARCH.to_string(),
    }
}

/// The Lantern platform convention ("darwin", not "macos"). A local copy of
/// `core/src/config/fetch/request.rs::lantern_platform`, which is `pub(crate)` there —
/// a 4-line match isn't worth widening core's public API.
fn lantern_platform(os: &str) -> &str {
    match os {
        "macos" => "darwin",
        other => other,
    }
}

/// Best-effort top-level `"country"` string from the cached config response (the
/// server's geo view of this client). `""` when the cache or field is absent.
fn country_from_cache(path: &Path) -> String {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
        .and_then(|v| v.get("country").and_then(|c| c.as_str()).map(str::to_owned))
        .unwrap_or_default()
}

/// Best-effort OS version: macOS asks `sw_vers -productVersion`; other platforms
/// report `""` rather than growing per-OS probing (attrs are diagnostic garnish).
fn os_version() -> String {
    #[cfg(target_os = "macos")]
    {
        if let Ok(out) = std::process::Command::new("sw_vers")
            .arg("-productVersion")
            .output()
        {
            if out.status.success() {
                if let Ok(s) = String::from_utf8(out.stdout) {
                    return s.trim().to_string();
                }
            }
        }
    }
    String::new()
}

/// Parse the cached `config_raw.json` at `path` into its [`OtelConfig`]. Absent or
/// unreadable cache, unparseable JSON, or a missing/empty `otel` block all yield
/// `None` (= uploads off), matching the uploader's gate contract.
fn otel_from_cache(path: &Path) -> Option<OtelConfig> {
    let raw = std::fs::read_to_string(path).ok()?;
    otel_from_config_raw_json(&raw).ok().flatten()
}

// ── Commands ──────────────────────────────────────────────────────────────────

/// Resolve the persistence base dir the same way `platform::control()` does in
/// `lib.rs` (small local copy, mirroring `unbounded::base_dir`).
fn base_dir<R: Runtime>(app: &AppHandle<R>) -> crate::Result<PathBuf> {
    app.path()
        .app_config_dir()
        .map_err(|e| crate::Error::Platform(format!("no app config dir: {e}")))
}

/// Spool a webview-reported error (JS exception, unhandled rejection, load failure)
/// through the §C2a error fast-path. The webview bridge that calls this lands in
/// Task 12; the command is registered now to keep ACL churn in one commit.
#[tauri::command]
pub(crate) async fn diag_report_webview_error<R: Runtime>(
    _app: AppHandle<R>,
    message: String,
    source: String,
) -> crate::Result<()> {
    report_webview_error(&message, &source);
    Ok(())
}

/// The testable body of [`diag_report_webview_error`]. `emit_error` is a no-op until
/// [`init`] installs the sink, so this is always safe — including when diagnostics
/// are disabled.
fn report_webview_error(message: &str, source: &str) {
    diag::emit_error(events::error_webview(message, source));
}

/// The persisted diagnostics toggle (default OFF — strictly opt-in).
#[tauri::command]
pub(crate) async fn diag_get_enabled<R: Runtime>(app: AppHandle<R>) -> crate::Result<bool> {
    Ok(crate::persist::load_diagnostics_enabled(&base_dir(&app)?))
}

/// Persist the diagnostics toggle. Takes effect on next launch: [`init`] runs once at
/// startup, and the installed global sink/subscriber/panic-hook can't be torn down
/// mid-run (OnceLock semantics) — the UI copy should say "applies after restart".
#[tauri::command]
pub(crate) async fn diag_set_enabled<R: Runtime>(
    app: AppHandle<R>,
    enabled: bool,
) -> crate::Result<()> {
    let base = base_dir(&app)?;
    crate::persist::save_diagnostics_enabled(&base, enabled)?;
    // Opting out also ERASES what was already written. For an Unbounded volunteer the spool and the
    // local backup log are a timestamped record of the sessions they relayed for censored users;
    // stopping future writes while leaving that history on disk is only half an opt-out, and there is
    // no other affordance to find or clear it. (The in-process sink keeps running until the next
    // launch — a still-live session can append again — but the accumulated history is gone and the
    // next launch starts clean.)
    if !enabled {
        spark_core::diag::sink::purge_local_records(&base);
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        // Per-process subdir so concurrent test processes / leftover state can't
        // interfere (same pattern as persist.rs).
        let dir = std::env::temp_dir()
            .join(format!("spark-vpn-diag-host-tests-{}", std::process::id()))
            .join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create test dir");
        dir
    }

    #[test]
    fn otel_from_cache_parses_fixture() {
        let dir = tmp("otel_from_cache_parses_fixture");
        let path = dir.join("config_raw.json");

        // Absent file → None (uploads off).
        assert_eq!(otel_from_cache(&path), None);

        // Hand-written fixture (never the real config_raw.json — its ingestion key
        // is live): otel block + both feature gates on.
        std::fs::write(
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
        assert!(o.traces_enabled);

        // Valid JSON without an otel block → None.
        std::fs::write(&path, r#"{ "options": { "outbounds": [] } }"#).expect("write");
        assert_eq!(otel_from_cache(&path), None);

        // Unparseable cache → None, not a panic.
        std::fs::write(&path, "not json").expect("write");
        assert_eq!(otel_from_cache(&path), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn country_from_cache_best_effort() {
        let dir = tmp("country_from_cache_best_effort");
        let path = dir.join("config_raw.json");
        assert_eq!(country_from_cache(&path), "", "absent file → empty");
        std::fs::write(
            &path,
            r#"{ "country": "US", "options": { "outbounds": [] } }"#,
        )
        .expect("write");
        assert_eq!(country_from_cache(&path), "US");
        std::fs::write(&path, r#"{ "options": { "outbounds": [] } }"#).expect("write");
        assert_eq!(country_from_cache(&path), "", "no country field → empty");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn platform_maps_macos_to_darwin() {
        assert_eq!(lantern_platform("macos"), "darwin");
        assert_eq!(lantern_platform("linux"), "linux");
        assert_eq!(lantern_platform("windows"), "windows");
    }

    #[test]
    fn report_webview_error_is_safe_without_sink() {
        // emit_error is a no-op before diag::install — must not panic. (No sink is
        // installed anywhere in this test binary; installing the process-global
        // OnceLock in a test would leak into every other test.)
        report_webview_error("fetch to 1.2.3.4 failed", "app.js");
    }

    #[test]
    fn span_queue_none_before_init() {
        // STATE is only set by init_inner, which no test runs.
        assert!(span_queue().is_none());
    }

    #[test]
    fn sentinel_reachable_the_instant_it_is_armed() {
        // SENTINEL is a process-global OnceLock, so this is the ONLY test allowed to
        // set it (tests share one process; a separate "none before init" test would
        // race this one's set). It therefore owns BOTH halves of the contract: None
        // before arm_and_register, Some immediately after.
        assert!(
            sentinel().is_none(),
            "no sentinel before arm_and_register — Exit-hook disarm must be a safe \
             no-op when diagnostics never initialized"
        );

        let dir = tmp("sentinel_reachable_the_instant_it_is_armed");
        let prev = arm_and_register(&dir, "9.9.9");
        assert!(prev.is_none(), "fresh dir must not flag an unclean exit");

        // The load-bearing ordering (the fast-quit race): the sentinel is reachable
        // via the accessor BEFORE any DiagState/STATE exists — init_inner's remaining
        // work (uploader construction, STATE.set) hasn't happened and never does in
        // this test, exactly like an Exit event firing mid-init.
        assert!(
            sentinel().is_some(),
            "sentinel must be reachable the instant arm_and_register returns"
        );
        assert!(
            span_queue().is_none(),
            "STATE must still be unset — registration must not wait for it"
        );

        // And the Exit-hook path works through the accessor: disarm removes the
        // marker, so the next launch is clean.
        sentinel().expect("just registered").disarm();
        assert!(
            !dir.join("diag.session").exists(),
            "disarm through the accessor must remove the marker"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
