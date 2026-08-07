//! Capture-only diagnostics wiring for the service process (design §5 Phase B-lite).
//!
//! The service is the tunnel process on Windows/Linux (`spark.component` "tunnel",
//! like the macOS NE), but unlike the NE it has **no config source**: it doesn't carry
//! spark-core's `config-fetch` feature (forcing it on would pull the BoringSSL build
//! and blow the 4 MiB size budget), so there is no `otel` block to gate an uploader
//! with — and `diag::tunnel_host` (cfg `config-fetch`) isn't even compiled in. What
//! runs here is the capture side only: the sink (spool + backup log under the service
//! state dir), the `DiagLayer` on the daemon's subscriber (see `daemon::init_tracing`),
//! the panic hook, and the unclean-exit sentinel. Captured events accumulate in
//! `diagnostics.jsonl`/`diag.log` for hand-collection; **upload arrives via a later
//! IPC plumb** (the client app, which does fetch config, hands the otel endpoint —
//! or ferries batches — across the control channel).
//!
//! Same infallibility contract as the other diag hosts: every step degrades
//! gracefully to less diagnostics, and internal failures log at `tracing::debug!`
//! ONLY (diag internals must never re-enter the capture layer at a captured level).

use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use spark_core::diag::sentinel::SessionSentinel;
use spark_core::diag::{self, panic_hook, DiagSink};

/// How often the sentinel heartbeat refreshes `last_alive` — the same cadence as the
/// NE host's re-parse tick, so an unclean exit dates to ~1 min resolution.
const BEAT_INTERVAL: Duration = Duration::from_secs(60);

/// The armed unclean-exit sentinel, set the instant `SessionSentinel::arm` returns
/// (before anything else in init) so a shutdown racing the tail of init can already
/// reach it via [`disarm_sentinel`] — the same armed-to-reachable-in-one-step
/// rationale as the plugin's `diag_host` and core's `tunnel_host`.
static SENTINEL: OnceLock<Arc<SessionSentinel>> = OnceLock::new();

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

    // The one test allowed to exercise init_with_sink: it sets the process-global
    // SENTINEL OnceLock (settable once), so it owns the whole lifecycle — none
    // before init, armed after, disarmed marker removal. init() itself is NOT
    // driven (it installs the process-global diag SINK, which would leak into every
    // other test in this binary).
    #[tokio::test]
    async fn init_with_sink_arms_sentinel_and_disarm_removes_marker() {
        let dir = test_dir("wire");
        assert!(SENTINEL.get().is_none(), "no sentinel before init");
        disarm_sentinel(); // safe no-op pre-init

        let sink = DiagSink::new(&dir, "tunnel").expect("sink in tempdir");
        init_with_sink(sink, &dir, "1.0.0");

        assert!(dir.join("diagnostics.jsonl").exists());
        assert!(dir.join("diag.log").exists());
        assert!(dir.join("diag.session").exists(), "sentinel must be armed");
        assert!(
            SENTINEL.get().is_some(),
            "sentinel reachable the instant init returns"
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
