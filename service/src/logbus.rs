//! Bridges `tracing` events into the control-plane log stream (ADR 0004, slice 4).
//!
//! A [`LogForwarder`] layer (added to the daemon's subscriber) turns each event into a redacted
//! [`LogLine`] and pushes it onto a process-global channel; the event loop drains it and broadcasts
//! `Push::Log` to clients that subscribed with `logs: true`. Messages are run through
//! [`spark_core::redact`] so address literals never reach a client at the default level. Delivery is
//! lossy (drop on a full channel) — logs must never stall the data path or wedge a logging call.

use std::fmt::Debug;
use std::sync::OnceLock;

use spark_ipc::{LogLevel, LogLine};
use tokio::sync::mpsc;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

/// Channel depth for buffered log lines before they start dropping.
const LOG_DEPTH: usize = 256;

/// The global sender the [`LogForwarder`] publishes to. Set once by [`init`]; until then (and in
/// tests, where no daemon subscriber is installed) events are simply dropped.
static LOG_TX: OnceLock<mpsc::Sender<LogLine>> = OnceLock::new();

/// Create the log channel and register the global sender (idempotent — only the first call wins).
/// Returns the receiver for the event loop to drain, or `None` if already initialized.
pub fn init() -> Option<mpsc::Receiver<LogLine>> {
    let (tx, rx) = mpsc::channel(LOG_DEPTH);
    LOG_TX.set(tx).ok().map(|()| rx)
}

/// A `tracing` [`Layer`] that forwards events to the control-plane log stream. Add it to the
/// daemon's subscriber; it's a no-op until [`init`] has run.
pub struct LogForwarder;

/// Pulls the `message` field out of a tracing event.
struct MessageVisitor(Option<String>);

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        if field.name() == "message" && self.0.is_none() {
            self.0 = Some(format!("{value:?}"));
        }
    }
}

impl<S: Subscriber> Layer<S> for LogForwarder {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let Some(tx) = LOG_TX.get() else {
            return; // channel not initialized (startup, or a non-daemon process)
        };
        let mut visitor = MessageVisitor(None);
        event.record(&mut visitor);
        let Some(message) = visitor.0 else {
            return; // an event with no message field — nothing to stream
        };
        let line = LogLine {
            level: level_of(event.metadata().level()),
            // Redact address literals as a backstop (a privacy property; see docs/GOAL.md).
            message: spark_core::redact::redact_addrs(&message).into_owned(),
        };
        let _ = tx.try_send(line); // lossy on backpressure — never block a logging call
    }
}

/// Map a `tracing` level to the wire [`LogLevel`].
fn level_of(level: &Level) -> LogLevel {
    match *level {
        Level::ERROR => LogLevel::Error,
        Level::WARN => LogLevel::Warn,
        Level::INFO => LogLevel::Info,
        Level::DEBUG => LogLevel::Debug,
        Level::TRACE => LogLevel::Trace,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_tracing_levels() {
        assert_eq!(level_of(&Level::ERROR), LogLevel::Error);
        assert_eq!(level_of(&Level::INFO), LogLevel::Info);
        assert_eq!(level_of(&Level::TRACE), LogLevel::Trace);
    }
}
