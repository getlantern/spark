//! `DiagLayer`: a `tracing_subscriber::Layer` that feeds the diagnostics pipeline (spec §C1, §C2a).
//!
//! Modeled line-for-line on `service/src/logbus.rs` (`LogForwarder`). The service crate depends on
//! core, not vice versa, so sharing `MessageVisitor` would invert the dependency — the 8-line
//! visitor is duplicated here with a comment pointing back.
//!
//! ## Level policy (spec §C1)
//! - `spark*` targets: DEBUG and above captured.
//! - All other targets: INFO and above captured.
//! - TRACE: never captured.
//!
//! ## Re-entrancy guard
//! The sink's writer task logs at `tracing::debug!` (e.g. on append failures). Those events have
//! target `spark_core::diag::sink` (the module path). If they re-entered this layer they would
//! recurse back into the sink. Defense: events whose `target` starts with `"spark_core::diag"` are
//! dropped unconditionally. The module prefix `"spark_core::diag"` covers `::sink`, `::layer`,
//! `::events`, and any future sibling — a conservative boundary that never silences non-diag spark
//! code (those targets start with `"spark_core::"` but not `"spark_core::diag"`).
//!
//! ## Remote volume knob
//! `set_capture_level(DiagLevel)` adjusts what is forwarded at runtime (server-delivered; §C4).
//! ERROR events always pass regardless of the knob (§C2a: errors are never dropped).
//! Default = `DiagLevel::Debug` (capture everything the policy allows).
//!
//! ## Production vs test
//! `DiagLayer::new()` forwards events to the process-global `diag::emit`/`diag::emit_error` —
//! the production path. `DiagLayer::with_sink(Arc<DiagSink>)` targets a caller-supplied sink for
//! unit tests, since the global `SINK` `OnceLock` can only be set once per process (installing
//! it in a test would leak into every other test).

use std::fmt::Debug;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

use super::{events, sink::DiagSink, DiagLevel};
use crate::diag;

// ---------------------------------------------------------------------------
// Module-level capture-level knob
// ---------------------------------------------------------------------------

/// Explicit u8 encoding so we never `transmute`. Lower numeric value = more severe (ERROR = 0).
const LEVEL_ERROR: u8 = 0;
const LEVEL_WARN: u8 = 1;
const LEVEL_INFO: u8 = 2;
const LEVEL_DEBUG: u8 = 3;

fn diag_level_to_u8(l: DiagLevel) -> u8 {
    match l {
        DiagLevel::Error => LEVEL_ERROR,
        DiagLevel::Warn => LEVEL_WARN,
        DiagLevel::Info => LEVEL_INFO,
        DiagLevel::Debug => LEVEL_DEBUG,
    }
}

fn u8_to_diag_level(v: u8) -> DiagLevel {
    match v {
        LEVEL_ERROR => DiagLevel::Error,
        LEVEL_WARN => DiagLevel::Warn,
        LEVEL_INFO => DiagLevel::Info,
        _ => DiagLevel::Debug,
    }
}

/// The process-wide capture knob. Default = DEBUG (capture everything the policy allows).
/// Stored as a u8 via the explicit mapping above; never `transmute`d.
static CAPTURE_LEVEL: AtomicU8 = AtomicU8::new(LEVEL_DEBUG);

/// Set the remote capture-level knob (§C4). Events *below* this level (less severe) are dropped,
/// **except ERROR events which always pass** (§C2a). Thread-safe; takes effect immediately.
pub fn set_capture_level(level: DiagLevel) {
    CAPTURE_LEVEL.store(diag_level_to_u8(level), Ordering::Relaxed);
}

/// Read the current capture level.
pub fn capture_level() -> DiagLevel {
    u8_to_diag_level(CAPTURE_LEVEL.load(Ordering::Relaxed))
}

// ---------------------------------------------------------------------------
// Shared capture policy
// ---------------------------------------------------------------------------

/// The single capture-policy decision for a tracing event: `Some(level)` = capture at
/// that diag level, `None` = drop. Shared by [`DiagLayer`] (the app process's
/// subscriber layer) and `log_bridge::BridgeSubscriber` (the NE, where the bridge owns
/// the global subscriber slot and forwards into diag itself), so the two processes
/// apply one policy.
///
/// Encapsulates, in order:
/// 1. Self-suppression: `spark_core::diag*` targets are dropped unconditionally
///    (even ERROR) — diag internals must never re-enter the capture pipeline.
/// 2. Level policy (spec §C1): TRACE never; `spark*` targets DEBUG+; foreign INFO+.
/// 3. The remote capture-level knob (§C4), with the ERROR exemption (§C2a: errors
///    are never dropped by the knob).
pub(crate) fn capture_decision(level: &Level, target: &str) -> Option<DiagLevel> {
    // Re-entrancy guard: the sink internals log via tracing::debug! with target
    // "spark_core::diag::sink" (the module path). Capturing those events would recurse back
    // into the sink. Drop all events from the "spark_core::diag" prefix, which covers
    // ::sink, ::layer, ::events, and any future sibling.
    if target.starts_with("spark_core::diag") {
        return None;
    }

    // Level policy (spec §C1):
    // - TRACE: never captured.
    // - spark* targets: DEBUG and above.
    // - everything else: INFO and above.
    let is_spark = target.starts_with("spark");
    let passes_policy = match *level {
        Level::TRACE => false,
        Level::DEBUG => is_spark,
        Level::INFO | Level::WARN | Level::ERROR => true,
    };
    if !passes_policy {
        return None;
    }

    // Remote volume knob (§C4): drop events below the configured capture level,
    // but errors always pass (§C2a: errors are never dropped).
    if *level != Level::ERROR {
        let knob = CAPTURE_LEVEL.load(Ordering::Relaxed);
        let event_severity = tracing_level_to_u8(level);
        // Higher u8 = less severe; drop if the event is less severe than the knob.
        if event_severity > knob {
            return None;
        }
    }

    Some(tracing_level_to_diag(level))
}

// ---------------------------------------------------------------------------
// MessageVisitor — duplicated from `service/src/logbus.rs` (see module doc)
// ---------------------------------------------------------------------------

/// Pulls the `message` field out of a tracing event.
struct MessageVisitor(Option<String>);

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        if field.name() == "message" && self.0.is_none() {
            self.0 = Some(format!("{value:?}"));
        }
    }
}

// ---------------------------------------------------------------------------
// Sink routing enum (global vs supplied)
// ---------------------------------------------------------------------------

enum SinkRoute {
    /// Production: forward through `diag::emit` / `diag::emit_error` (global OnceLock).
    Global,
    /// Test: forward directly to a specific `DiagSink`.
    Specific(Arc<DiagSink>),
}

// ---------------------------------------------------------------------------
// DiagLayer
// ---------------------------------------------------------------------------

/// A `tracing_subscriber` `Layer` that captures events into the diagnostics pipeline (§C1/§C2a).
///
/// Use [`DiagLayer::new`] in production (forwards to the process-global sink installed by
/// [`diag::install`]). Use [`DiagLayer::with_sink`] in tests, where installing the global sink
/// would leak across the process.
pub struct DiagLayer {
    sink: SinkRoute,
}

impl DiagLayer {
    /// Production constructor: forwards events to the process-global `diag::emit` / `diag::emit_error`.
    /// A no-op until [`crate::diag::install`] has run.
    pub fn new() -> Self {
        DiagLayer {
            sink: SinkRoute::Global,
        }
    }

    /// Test constructor: forwards events to `sink` directly, bypassing the global `OnceLock`.
    /// The global `SINK` can only be set once per process, so tests must use this path.
    pub fn with_sink(sink: Arc<DiagSink>) -> Self {
        DiagLayer {
            sink: SinkRoute::Specific(sink),
        }
    }

    fn forward_event(&self, ev: super::DiagEvent, is_error: bool) {
        match &self.sink {
            SinkRoute::Global => {
                if is_error {
                    diag::emit_error(ev);
                } else {
                    diag::emit(ev);
                }
            }
            SinkRoute::Specific(sink) => {
                if is_error {
                    sink.push_error(ev);
                } else {
                    sink.push(ev);
                }
            }
        }
    }
}

impl Default for DiagLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Subscriber> Layer<S> for DiagLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        let target = meta.target();

        // The shared capture policy (self-suppression, §C1 level policy, §C4 knob
        // with the §C2a error exemption) — see [`capture_decision`].
        let Some(diag_level) = capture_decision(meta.level(), target) else {
            return;
        };
        // `tracing_level_to_diag` maps exactly `Level::ERROR` to `DiagLevel::Error`,
        // so this recovers the §C2a fast-path decision from the policy result.
        let is_error = diag_level == DiagLevel::Error;

        // Pull the message field (MessageVisitor pattern — see module doc).
        let mut visitor = MessageVisitor(None);
        event.record(&mut visitor);
        let Some(message) = visitor.0 else {
            return; // no message field — nothing to forward
        };

        let ev = events::log(diag_level, &message, target);

        // §C2a: for errors this blocks the calling thread on a mutex + two write_all
        // syscalls (the synchronous fast path). Accepted: errors are rare, and crash
        // durability outweighs the one-off latency.
        self.forward_event(ev, is_error);
    }
}

/// Map a `tracing::Level` to the u8 encoding (lower = more severe), for knob comparison.
fn tracing_level_to_u8(level: &Level) -> u8 {
    match *level {
        Level::ERROR => LEVEL_ERROR,
        Level::WARN => LEVEL_WARN,
        Level::INFO => LEVEL_INFO,
        Level::DEBUG => LEVEL_DEBUG,
        Level::TRACE => 4,
    }
}

/// Map a `tracing::Level` to `DiagLevel`. TRACE never reaches here (filtered above).
fn tracing_level_to_diag(level: &Level) -> DiagLevel {
    match *level {
        Level::ERROR => DiagLevel::Error,
        Level::WARN => DiagLevel::Warn,
        Level::INFO => DiagLevel::Info,
        Level::DEBUG | Level::TRACE => DiagLevel::Debug,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::Mutex;

    use tracing_subscriber::prelude::*;

    use super::*;
    use crate::diag::sink::DiagSink;
    use crate::diag::DiagLevel;

    /// Serializes tests that mutate the process-global CAPTURE_LEVEL. Any test that calls
    /// `set_capture_level` with a non-default value must hold this lock for the duration of
    /// its mutation window, so concurrent tests that depend on the default (Debug) don't race.
    static KNOB_LOCK: Mutex<()> = Mutex::new(());

    /// Unique per-test scratch dir keyed by pid + call-site line.
    fn test_dir(line: u32) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("spark-diag-layer-{}-{}", std::process::id(), line));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    /// Read all JSONL lines from the spool synchronously.
    fn read_spool(dir: &std::path::Path) -> Vec<serde_json::Value> {
        let path = dir.join("diagnostics.jsonl");
        if !path.exists() {
            return vec![];
        }
        fs::read_to_string(&path)
            .unwrap()
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    // -----------------------------------------------------------------------
    // Test 1: spark DEBUG captured, foreign DEBUG dropped
    //
    // Holds KNOB_LOCK to serialize with test 5 (which mutates the global CAPTURE_LEVEL).
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn captures_spark_debug_but_not_foreign_debug() {
        let dir = test_dir(line!());
        let sink = DiagSink::new(&dir, "app").unwrap();

        let layer = DiagLayer::with_sink(Arc::clone(&sink));
        let subscriber = tracing_subscriber::registry().with(layer);

        {
            let _guard = KNOB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            tracing::subscriber::with_default(subscriber, || {
                tracing::debug!(target: "spark_core::x", "a-msg");
                tracing::debug!(target: "hyper::y", "b-msg");
            });
        }

        sink.flush_writer().await;
        let lines = read_spool(&dir);
        let messages: Vec<&str> = lines
            .iter()
            .filter_map(|v| v["fields"]["message"].as_str())
            .collect();
        assert!(
            messages.iter().any(|m| m.contains("a-msg")),
            "spark debug should be captured; got {messages:?}"
        );
        assert!(
            !messages.iter().any(|m| m.contains("b-msg")),
            "foreign debug should not be captured; got {messages:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // Test 2: foreign INFO is captured
    //
    // Holds KNOB_LOCK to serialize with test 5.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn foreign_info_is_captured() {
        let dir = test_dir(line!());
        let sink = DiagSink::new(&dir, "app").unwrap();

        let layer = DiagLayer::with_sink(Arc::clone(&sink));
        let subscriber = tracing_subscriber::registry().with(layer);

        {
            let _guard = KNOB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            tracing::subscriber::with_default(subscriber, || {
                tracing::info!(target: "hyper::y", "c-msg");
            });
        }

        sink.flush_writer().await;
        let lines = read_spool(&dir);
        let messages: Vec<&str> = lines
            .iter()
            .filter_map(|v| v["fields"]["message"].as_str())
            .collect();
        assert!(
            messages.iter().any(|m| m.contains("c-msg")),
            "foreign INFO should be captured; got {messages:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // Test 3: ERROR events use the synchronous fast path (§C2a)
    //
    // Holds KNOB_LOCK to serialize with test 5.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn error_events_use_fast_path() {
        let dir = test_dir(line!());
        let sink = DiagSink::new(&dir, "app").unwrap();

        let layer = DiagLayer::with_sink(Arc::clone(&sink));
        let subscriber = tracing_subscriber::registry().with(layer);

        {
            let _guard = KNOB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            tracing::subscriber::with_default(subscriber, || {
                tracing::error!(target: "spark_core::x", "boom");
            });
        }

        // No flush_writer — the §C2a fast path writes synchronously to the spool.
        let lines = read_spool(&dir);
        assert!(
            !lines.is_empty(),
            "error should be in spool without flush_writer"
        );
        let messages: Vec<&str> = lines
            .iter()
            .filter_map(|v| v["fields"]["message"].as_str())
            .collect();
        assert!(
            messages.iter().any(|m| m.contains("boom")),
            "error message not found; got {messages:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // Test 4: messages are IP-redacted
    //
    // Holds KNOB_LOCK to serialize with test 5.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn messages_are_redacted() {
        let dir = test_dir(line!());
        let sink = DiagSink::new(&dir, "app").unwrap();

        let layer = DiagLayer::with_sink(Arc::clone(&sink));
        let subscriber = tracing_subscriber::registry().with(layer);

        {
            let _guard = KNOB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            tracing::subscriber::with_default(subscriber, || {
                tracing::warn!(target: "spark_core::x", "dial 1.2.3.4");
            });
        }

        sink.flush_writer().await;
        let raw = fs::read_to_string(dir.join("diagnostics.jsonl")).unwrap();
        assert!(
            !raw.contains("1.2.3.4"),
            "raw IP should be redacted; got: {raw}"
        );
        assert!(
            raw.contains("[redacted-ip]"),
            "should contain [redacted-ip]; got: {raw}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // Test 5: capture level knob — error still passes when knob = Error
    //
    // NOTE: This test mutates the process-global CAPTURE_LEVEL. It holds `KNOB_LOCK` for the
    // entire window where the knob ≠ Debug so concurrent tests that depend on the default (Debug)
    // don't observe the non-default setting.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn capture_level_error_only_still_records_errors() {
        let dir = test_dir(line!());
        let sink = DiagSink::new(&dir, "app").unwrap();

        // Hold the knob lock for the full mutation window (set → emit → restore) so concurrent
        // tests that depend on the default Debug level don't race on the global.
        {
            let _guard = KNOB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            set_capture_level(DiagLevel::Error);
            // Drop-based restore: a panic mid-test must not leave the process-global
            // knob at Error, which would spuriously filter the other tests' events.
            struct RestoreKnob;
            impl Drop for RestoreKnob {
                fn drop(&mut self) {
                    set_capture_level(DiagLevel::Debug);
                }
            }
            let _restore = RestoreKnob;

            let layer = DiagLayer::with_sink(Arc::clone(&sink));
            let subscriber = tracing_subscriber::registry().with(layer);

            tracing::subscriber::with_default(subscriber, || {
                tracing::info!(target: "spark_core::x", "should-be-dropped");
                tracing::error!(target: "spark_core::x", "must-survive");
            });
            // _restore then _guard drop here: knob restored before the lock releases.
        }

        // Error uses the §C2a synchronous fast path — no flush needed.
        // Info was dropped by the layer before push(), so flush is a no-op.
        sink.flush_writer().await;

        let lines = read_spool(&dir);
        let messages: Vec<&str> = lines
            .iter()
            .filter_map(|v| v["fields"]["message"].as_str())
            .collect();
        assert!(
            !messages.iter().any(|m| m.contains("should-be-dropped")),
            "info should be dropped at Error-only knob; got {messages:?}"
        );
        assert!(
            messages.iter().any(|m| m.contains("must-survive")),
            "error should always survive; got {messages:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // capture_decision matrix — the shared policy consumed by both DiagLayer
    // and log_bridge::BridgeSubscriber. Tested here (not in log_bridge) because
    // the bridge's diag forwarding goes through the process-global `diag::emit`
    // OnceLock, which no test may install (it would leak into every other test);
    // the policy itself is the testable seam.
    //
    // Holds KNOB_LOCK for the knob cases (serializes with test 5).
    // -----------------------------------------------------------------------

    #[test]
    fn capture_decision_matrix() {
        let _guard = KNOB_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        // TRACE: never captured, spark or foreign.
        assert_eq!(capture_decision(&Level::TRACE, "spark_core::x"), None);
        assert_eq!(capture_decision(&Level::TRACE, "hyper::y"), None);

        // DEBUG: spark targets only.
        assert_eq!(
            capture_decision(&Level::DEBUG, "spark_core::x"),
            Some(DiagLevel::Debug)
        );
        assert_eq!(capture_decision(&Level::DEBUG, "hyper::y"), None);

        // INFO+: everything.
        assert_eq!(
            capture_decision(&Level::INFO, "hyper::y"),
            Some(DiagLevel::Info)
        );
        assert_eq!(
            capture_decision(&Level::WARN, "spark_core::x"),
            Some(DiagLevel::Warn)
        );
        assert_eq!(
            capture_decision(&Level::ERROR, "hyper::y"),
            Some(DiagLevel::Error)
        );

        // Self-suppression: diag internals dropped unconditionally — even ERROR.
        assert_eq!(
            capture_decision(&Level::DEBUG, "spark_core::diag::sink"),
            None
        );
        assert_eq!(
            capture_decision(&Level::ERROR, "spark_core::diag::sink"),
            None
        );

        // Knob: below-knob events drop, errors always pass (§C2a). Drop-based
        // restore so a panicking assert can't leave the global knob at Error.
        set_capture_level(DiagLevel::Error);
        struct RestoreKnob;
        impl Drop for RestoreKnob {
            fn drop(&mut self) {
                set_capture_level(DiagLevel::Debug);
            }
        }
        let _restore = RestoreKnob;
        assert_eq!(capture_decision(&Level::INFO, "spark_core::x"), None);
        assert_eq!(capture_decision(&Level::WARN, "spark_core::x"), None);
        assert_eq!(
            capture_decision(&Level::ERROR, "spark_core::x"),
            Some(DiagLevel::Error)
        );
    }

    // -----------------------------------------------------------------------
    // Test 6: diag internal targets are suppressed (re-entrancy guard)
    //
    // Holds KNOB_LOCK to serialize with test 5.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn diag_internal_targets_are_suppressed() {
        let dir = test_dir(line!());
        let sink = DiagSink::new(&dir, "app").unwrap();

        let layer = DiagLayer::with_sink(Arc::clone(&sink));
        let subscriber = tracing_subscriber::registry().with(layer);

        {
            let _guard = KNOB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            tracing::subscriber::with_default(subscriber, || {
                tracing::debug!(target: "spark_core::diag::sink", "internal");
            });
        }

        sink.flush_writer().await;
        let lines = read_spool(&dir);
        assert!(
            lines.is_empty(),
            "diag internal events must be suppressed; got {lines:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
