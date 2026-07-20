//! Unclean-exit sentinel (spec §C2a): crash detection for the failure classes the
//! panic hook can't see — segfault, OOM kill, watchdog kill, `kill -9`. A session
//! marker (`diag.session`) is armed at diagnostics init, heartbeat-refreshed while the
//! process lives, and removed on clean shutdown. A marker still present at the NEXT
//! launch means the previous session died without running its exit path, and is
//! surfaced as an `error.unclean_exit` event for the §C2a error fast path.
//!
//! One sentinel per SESSION, host-owned. A `SessionSentinel` instance arms once and
//! is never itself re-armed; a host whose process outlives sessions (the NE sysext
//! persists across stopTunnel→startTunnel — see `tunnel_host`) arms a FRESH instance
//! per session, replacing the previous (disarmed) one, so every session is
//! crash-protected. Hosts whose process IS the session (app, service) arm once at
//! init and hold that sentinel for the process lifetime.
//!
//! A Rust panic leaves the marker too — an aborting panic ends the process without
//! `RunEvent::Exit`, so no disarm runs. One panic therefore produces BOTH an
//! `error.panic` (spooled at crash time by the panic hook) and an
//! `error.unclean_exit` (at the next launch). That double-report is expected: SigNoz
//! analyses should dedup crash counts by session (`prev_started_ms`) rather than
//! summing the two event kinds.
//!
//! A crash marker also survives a diagnostics-off period: the local opt-out skips
//! diag init entirely (nothing arms, reads, or removes the marker), so a crash
//! followed by any stretch of disabled diagnostics fires `error.unclean_exit` on the
//! first re-enabled launch. `prev_started_ms`/`prev_version` date the ACTUAL crash —
//! dashboards should bucket by those, not by receipt time.
//!
//! I/O failures here are logged at `tracing::debug!` and swallowed — diag internals
//! must never re-enter the capture layer at a captured-by-default level (same rule and
//! rationale as `sink.rs`), and crash detection must never break init.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::{events, DiagEvent};

/// Marker file name inside the diag sink dir.
const MARKER_NAME: &str = "diag.session";

/// On-disk marker shape: one JSON object, rewritten whole on every heartbeat.
#[derive(Debug, Serialize, Deserialize)]
struct Marker {
    /// Unix millis when the session armed the sentinel.
    started: u64,
    /// Unix millis of the last heartbeat — an unclean exit reports roughly WHEN the
    /// previous session died, not just that it did.
    last_alive: u64,
    /// The dying session's app version, for grouping crashes by build.
    version: String,
}

/// Crash detection for failure classes the panic hook can't see (segfault, OOM kill,
/// watchdog, kill -9): a session marker armed at init and removed on clean shutdown.
/// A marker still present at the NEXT launch means the previous session died without
/// running its exit path.
pub struct SessionSentinel {
    /// `None` when arm-time marker I/O failed: the sentinel is disarmed and
    /// [`beat`](SessionSentinel::beat)/[`disarm`](SessionSentinel::disarm) are no-ops.
    path: Option<PathBuf>,
    started_ms: u64,
    version: String,
    /// Guards marker I/O and latches disarm, so a heartbeat racing a clean shutdown
    /// can't rewrite the marker after `disarm` removed it (which would flag a false
    /// unclean exit on the next launch).
    disarmed: Mutex<bool>,
}

impl SessionSentinel {
    /// Arm the sentinel in `dir` (the diag sink dir): if a marker from a previous
    /// session is present, return its parsed remains as an `error.unclean_exit` event
    /// for the CALLER to emit (keeps this testable without the global sink); then
    /// write this session's marker. Marker I/O failures degrade to a disarmed
    /// sentinel (debug-logged) — crash detection must never break init.
    pub fn arm(dir: &Path, version: &str) -> (SessionSentinel, Option<DiagEvent>) {
        let path = dir.join(MARKER_NAME);
        let prev = read_leftover(&path);
        let started_ms = now_ms();
        let marker = Marker {
            started: started_ms,
            last_alive: started_ms,
            version: version.to_string(),
        };
        let armed_path = if write_marker(&path, &marker) {
            Some(path)
        } else {
            None
        };
        (
            SessionSentinel {
                path: armed_path,
                started_ms,
                version: version.to_string(),
                disarmed: Mutex::new(false),
            },
            prev,
        )
    }

    /// Refresh the marker's `last_alive` timestamp (call ~every minute) so an
    /// unclean exit reports roughly WHEN the previous session died, not just that
    /// it did.
    pub fn beat(&self) {
        let disarmed = lock_disarmed(&self.disarmed);
        // The latch check runs under the same lock as disarm's remove, so a beat
        // racing a clean shutdown can never rewrite the marker after removal.
        if *disarmed {
            return;
        }
        let Some(path) = &self.path else {
            return; // arm-time I/O failed — the sentinel is permanently disarmed
        };
        let marker = Marker {
            started: self.started_ms,
            last_alive: now_ms(),
            version: self.version.clone(),
        };
        write_marker(path, &marker);
    }

    /// Clean shutdown: remove the marker. Idempotent.
    pub fn disarm(&self) {
        let mut disarmed = lock_disarmed(&self.disarmed);
        if *disarmed {
            return;
        }
        *disarmed = true;
        let Some(path) = &self.path else {
            return;
        };
        if let Err(e) = fs::remove_file(path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::debug!(err = %e, "diag: sentinel disarm remove failed");
            }
        }
    }
}

/// Parse a leftover marker at `path` into the `error.unclean_exit` event, or `None`
/// when no previous session left one. Unreadable-but-present or unparseable markers
/// degrade to `started`/`last_alive` 0 + version `"unknown"` — a corrupt marker still
/// means the previous session never ran its exit path.
fn read_leftover(path: &Path) -> Option<DiagEvent> {
    let raw = match fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            tracing::debug!(err = %e, "diag: sentinel marker unreadable — treating as corrupt");
            return Some(events::error_unclean_exit(0, 0, "unknown"));
        }
    };
    let ev = match serde_json::from_str::<Marker>(&raw) {
        Ok(m) => events::error_unclean_exit(m.started, m.last_alive, &m.version),
        Err(e) => {
            tracing::debug!(err = %e, "diag: sentinel marker unparseable — treating as corrupt");
            events::error_unclean_exit(0, 0, "unknown")
        }
    };
    Some(ev)
}

/// Write the marker atomically enough — temp file + rename, matching the sink's
/// rename-based file handling — so a crash mid-write can't leave a torn marker that
/// next launch misparses as corrupt. Returns `false` on failure (debug-logged).
fn write_marker(path: &Path, marker: &Marker) -> bool {
    // Infallible for this shape (u64s + String); mirrors to_jsonl's posture.
    let json = match serde_json::to_string(marker) {
        Ok(j) => j,
        Err(e) => {
            tracing::debug!(err = %e, "diag: sentinel marker serialization failed");
            return false;
        }
    };
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    if let Err(e) = fs::write(&tmp, json) {
        tracing::debug!(err = %e, path = %tmp.display(), "diag: sentinel marker write failed");
        return false;
    }
    if let Err(e) = fs::rename(&tmp, path) {
        tracing::debug!(err = %e, path = %path.display(), "diag: sentinel marker rename failed");
        return false;
    }
    true
}

/// Current wall clock in unix millis; a pre-epoch clock maps to 0 (same rationale as
/// [`DiagEvent::new`] — a sentinel timestamp beats failing).
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A poisoned disarm lock means another thread panicked mid-marker-I/O; the latch bool
/// is still meaningful, so keep going (same posture as `sink::lock_files`).
fn lock_disarmed(m: &Mutex<bool>) -> std::sync::MutexGuard<'_, bool> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diag::DiagLevel;

    /// Unique per-test scratch dir (pid + call line), cleared and recreated.
    fn test_dir(line: u32) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "spark-diag-sentinel-{}-{}",
            std::process::id(),
            line
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn read_marker(dir: &Path) -> serde_json::Value {
        let raw = fs::read_to_string(dir.join(MARKER_NAME)).unwrap();
        serde_json::from_str(&raw).unwrap()
    }

    #[test]
    fn first_arm_emits_nothing_and_writes_marker() {
        let dir = test_dir(line!());
        let (_s, prev) = SessionSentinel::arm(&dir, "1.2.3");
        assert!(prev.is_none(), "fresh dir must not flag an unclean exit");
        let v = read_marker(&dir);
        assert!(v["started"].as_u64().unwrap() > 0);
        assert!(v["last_alive"].as_u64().unwrap() >= v["started"].as_u64().unwrap());
        assert_eq!(v["version"], "1.2.3");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn leftover_marker_emits_unclean_exit() {
        let dir = test_dir(line!());
        // Arm and DROP without disarm — the previous session "crashed".
        let (s1, _) = SessionSentinel::arm(&dir, "0.9.0");
        drop(s1);
        let (_s2, prev) = SessionSentinel::arm(&dir, "1.0.0");
        let ev = prev.expect("leftover marker must flag an unclean exit");
        assert_eq!(ev.kind, "error.unclean_exit");
        assert_eq!(ev.level, DiagLevel::Error);
        assert_eq!(ev.fields["prev_version"], "0.9.0");
        let started = ev.fields["prev_started_ms"].as_u64().unwrap();
        let last_alive = ev.fields["prev_last_alive_ms"].as_u64().unwrap();
        assert!(started > 0);
        assert!(last_alive >= started);
        // The new session must be armed too.
        let v = read_marker(&dir);
        assert_eq!(v["version"], "1.0.0");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn disarm_removes_marker_then_next_arm_is_clean() {
        let dir = test_dir(line!());
        let (s, _) = SessionSentinel::arm(&dir, "1.0.0");
        s.disarm();
        assert!(!dir.join(MARKER_NAME).exists(), "disarm must remove marker");
        s.disarm(); // idempotent — second call must not error or panic
        let (_s2, prev) = SessionSentinel::arm(&dir, "1.0.0");
        assert!(prev.is_none(), "clean exit must not flag an unclean exit");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn beat_advances_last_alive() {
        let dir = test_dir(line!());
        let (s, _) = SessionSentinel::arm(&dir, "1.0.0");
        let before = read_marker(&dir);
        std::thread::sleep(std::time::Duration::from_millis(10));
        s.beat();
        let after = read_marker(&dir);
        assert!(
            after["last_alive"].as_u64().unwrap() > before["last_alive"].as_u64().unwrap(),
            "beat must advance last_alive: before={before} after={after}"
        );
        assert_eq!(after["started"], before["started"], "started is immutable");
        assert_eq!(after["version"], before["version"]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_marker_still_flags_unclean_exit() {
        let dir = test_dir(line!());
        fs::write(dir.join(MARKER_NAME), b"not json {{{").unwrap();
        let (_s, prev) = SessionSentinel::arm(&dir, "1.0.0");
        let ev = prev.expect("a corrupt marker still means an unclean exit");
        assert_eq!(ev.kind, "error.unclean_exit");
        assert_eq!(ev.fields["prev_version"], "unknown");
        assert_eq!(ev.fields["prev_started_ms"], 0);
        assert_eq!(ev.fields["prev_last_alive_ms"], 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn beat_after_disarm_does_not_recreate_marker() {
        let dir = test_dir(line!());
        let (s, _) = SessionSentinel::arm(&dir, "1.0.0");
        s.disarm();
        s.beat();
        assert!(
            !dir.join(MARKER_NAME).exists(),
            "a post-disarm beat must not resurrect the marker (false positive next launch)"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
