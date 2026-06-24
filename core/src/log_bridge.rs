//! A dependency-free `tracing` → host-logger bridge.
//!
//! The Apple NE extension has no `tracing` subscriber installed, so every `info!`/`warn!` in the
//! core (notably the whole `config::fetch` path) is dropped on the floor — which makes on-device
//! debugging blind. This module implements a tiny [`tracing::Subscriber`] that forwards formatted
//! events to a C callback the host registers (Swift logs them via `os_log`, so they land in
//! Console.app alongside the provider's own logs). It needs only `tracing` itself — no
//! `tracing-subscriber` — keeping the locked dependency set intact.
//!
//! Spans are not surfaced (the bridge is event-only); span bookkeeping is the minimum the
//! `Subscriber` contract requires. Default level is **DEBUG** and more severe ([`DEFAULT_MAX`]), but
//! only for spark's own targets ([`is_spark_target`]) — so on-device diagnostics (per-member probe
//! failures, pool re-probes, dial failovers) are visible without dragging in dependency-internal
//! `DEBUG`/`TRACE` noise. `TRACE` is dropped.

use std::ffi::{c_char, CString};
use std::fmt::{self, Write as _};
use std::sync::atomic::{AtomicU64, Ordering};

use tracing::field::{Field, Visit};
use tracing::level_filters::LevelFilter;
use tracing::{span, Event, Level, Metadata, Subscriber};

/// Host log sink: `(level, msg)` where `level` is [`level_to_u8`] (0=ERROR … 4=TRACE) and `msg` is a
/// NUL-terminated UTF-8 C string valid only for the duration of the call (copy it synchronously).
pub type LogCallback = extern "C" fn(level: u8, msg: *const c_char);

/// DEBUG and more severe — forwarded to the host. DEBUG is included so the on-device diagnostics
/// (per-member probe failures, pool re-probe summaries, dial failovers) are visible; the target
/// filter below keeps dependency-internal DEBUG/TRACE noise out.
const DEFAULT_MAX: u8 = 3;

/// Only forward events from spark's own crates (`spark_core`, `spark_apple`), so turning DEBUG on
/// doesn't flood the host log with `tokio`/`h2`/`quinn`/`boring` internals.
fn is_spark_target(target: &str) -> bool {
    target.starts_with("spark")
}

/// Severity as a small integer the C side can map to `os_log` types. Lower = more severe.
fn level_to_u8(level: &Level) -> u8 {
    match *level {
        Level::ERROR => 0,
        Level::WARN => 1,
        Level::INFO => 2,
        Level::DEBUG => 3,
        Level::TRACE => 4,
    }
}

fn u8_to_level_filter(max: u8) -> LevelFilter {
    match max {
        0 => LevelFilter::ERROR,
        1 => LevelFilter::WARN,
        2 => LevelFilter::INFO,
        3 => LevelFilter::DEBUG,
        _ => LevelFilter::TRACE,
    }
}

/// Render the one-line form the callback receives: `[target] message field=value …`.
fn render_line(target: &str, message: &str, fields: &str) -> String {
    format!("[{target}] {message}{fields}")
}

/// Collects an event's `message` field (rendered first) and any other fields (` key=value`).
#[derive(Default)]
struct EventVisitor {
    message: String,
    fields: String,
}

impl Visit for EventVisitor {
    // The typed `record_*` methods all default to `record_debug`, so this single impl covers every
    // field kind: the `message` field is the event's text; everything else is appended as `key=value`.
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.message, "{value:?}");
        } else {
            let _ = write!(self.fields, " {}={:?}", field.name(), value);
        }
    }
}

/// An event-only [`Subscriber`] that forwards formatted records to a host [`LogCallback`].
pub struct BridgeSubscriber {
    cb: LogCallback,
    max: u8,
    next_id: AtomicU64,
}

impl BridgeSubscriber {
    /// Forward events at `max_level` (a [`level_to_u8`] value) and more severe to `cb`.
    pub fn new(cb: LogCallback, max_level: u8) -> Self {
        Self {
            cb,
            max: max_level,
            next_id: AtomicU64::new(1),
        }
    }
}

impl Subscriber for BridgeSubscriber {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        level_to_u8(metadata.level()) <= self.max && is_spark_target(metadata.target())
    }

    fn new_span(&self, _span: &span::Attributes<'_>) -> span::Id {
        // Span data is unused, but ids must be unique + non-zero per the contract.
        let id = self.next_id.fetch_add(1, Ordering::Relaxed).max(1);
        span::Id::from_u64(id)
    }

    fn record(&self, _span: &span::Id, _values: &span::Record<'_>) {}
    fn record_follows_from(&self, _span: &span::Id, _follows: &span::Id) {}

    fn event(&self, event: &Event<'_>) {
        let meta = event.metadata();
        let level = level_to_u8(meta.level());
        if level > self.max || !is_spark_target(meta.target()) {
            return;
        }
        let mut visitor = EventVisitor::default();
        event.record(&mut visitor);
        let line = render_line(meta.target(), &visitor.message, &visitor.fields);
        // CString::new fails only on an interior NUL (log lines don't carry one); skip if so.
        if let Ok(c) = CString::new(line) {
            (self.cb)(level, c.as_ptr());
        }
    }

    fn enter(&self, _span: &span::Id) {}
    fn exit(&self, _span: &span::Id) {}

    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(u8_to_level_filter(self.max))
    }
}

/// Install the bridge as the process-global `tracing` subscriber, forwarding INFO+ events to `cb`.
/// Idempotent: a second call (or any already-set global default) is a no-op, so the host can call it
/// unconditionally at startup.
pub fn install(cb: LogCallback) {
    let _ = tracing::subscriber::set_global_default(BridgeSubscriber::new(cb, DEFAULT_MAX));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;
    use std::sync::Mutex;

    // The callback is a bare `extern "C" fn` (no captures), so tests collect into a static.
    static CAPTURED: Mutex<Vec<(u8, String)>> = Mutex::new(Vec::new());

    extern "C" fn capture(level: u8, msg: *const c_char) {
        // SAFETY: the subscriber passes a valid NUL-terminated string for the call's duration.
        let s = unsafe { CStr::from_ptr(msg) }.to_str().unwrap().to_owned();
        CAPTURED.lock().unwrap().push((level, s));
    }

    #[test]
    fn level_mapping_is_severity_ordered() {
        assert_eq!(level_to_u8(&Level::ERROR), 0);
        assert_eq!(level_to_u8(&Level::WARN), 1);
        assert_eq!(level_to_u8(&Level::INFO), 2);
        assert_eq!(level_to_u8(&Level::TRACE), 4);
    }

    #[test]
    fn render_line_joins_target_message_and_fields() {
        assert_eq!(render_line("a::b", "hi", ""), "[a::b] hi");
        assert_eq!(render_line("a::b", "hi", " k=1"), "[a::b] hi k=1");
    }

    #[test]
    fn forwards_events_and_drops_below_max_level() {
        CAPTURED.lock().unwrap().clear();
        // INFO max (2): WARN + INFO forwarded, DEBUG dropped. with_default scopes it to this thread,
        // so the global default and parallel tests are unaffected.
        let sub = BridgeSubscriber::new(capture, 2);
        tracing::subscriber::with_default(sub, || {
            tracing::warn!(error = "boom", "config-fetch: failed");
            tracing::info!(servers = 5, "lantern-api: boot config ready");
            tracing::debug!("noisy internal detail");
        });
        let cap = CAPTURED.lock().unwrap();
        assert_eq!(cap.len(), 2, "DEBUG should be filtered out");
        assert_eq!(cap[0].0, 1, "WARN -> 1");
        assert!(cap[0].1.contains("config-fetch: failed"));
        assert!(cap[0].1.contains("error=") && cap[0].1.contains("boom"));
        assert_eq!(cap[1].0, 2, "INFO -> 2");
        assert!(cap[1].1.contains("lantern-api: boot config ready"));
        assert!(cap[1].1.contains("servers=5"));
    }
}
