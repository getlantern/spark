//! On-device diagnostics: structured events captured to a ring/spool/backup-log and
//! uploaded as OTLP logs+traces to the config-delivered otel endpoint (design:
//! docs/superpowers/specs/2026-07-17-spark-diagnostics-design.md). Privacy: every
//! string field is IP-redacted on insert; kinds/fields follow the spec §C5 allowlist
//! (enforced by the typed constructors in `events`, a later task).

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// Severity level for a [`DiagEvent`], serialized in lowercase for JSONL / OTLP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DiagLevel {
    Error,
    Warn,
    Info,
    Debug,
}

/// A single structured diagnostic event, destined for the spool / backup log and
/// ultimately for OTLP upload (design §C1).
///
/// Fields are stored in a `BTreeMap` so JSONL output is deterministic across platforms
/// (useful for snapshot tests and diffing spool files).
#[derive(Debug, Clone, Serialize)]
pub struct DiagEvent {
    /// Unix timestamp in milliseconds. SigNoz receipt time is the trusted clock; this is
    /// the on-device capture time, used only for ordering within a spool file.
    pub ts: u64,
    pub level: DiagLevel,
    pub component: &'static str,
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    /// Raw field storage. Prefer [`DiagEvent::insert_str`] for strings — it applies IP
    /// redaction (spec §C5); inserting a string Value directly bypasses that backstop.
    /// Non-string values (numbers/bools/arrays) may be inserted directly.
    pub fields: BTreeMap<String, serde_json::Value>,
}

impl DiagEvent {
    /// Create a new event with the current wall-clock timestamp (unix millis).
    pub fn new(level: DiagLevel, component: &'static str, kind: &'static str) -> Self {
        // A pre-epoch clock (badly-synced device) maps to ts=0 rather than erroring:
        // the server's receipt time is the trusted clock (spec §C1), so a sentinel
        // timestamp is preferable to dropping the event.
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        DiagEvent {
            ts,
            level,
            component,
            kind,
            session: None,
            fields: BTreeMap::new(),
        }
    }

    /// Insert a string field, IP-redacted (the §C5 backstop applies to every string).
    pub fn insert_str(&mut self, key: &str, value: &str) {
        self.fields.insert(
            key.to_string(),
            crate::redact::redact_addrs(value).into_owned().into(),
        );
    }

    /// One-line JSON for the spool / backup log.
    pub fn to_jsonl(&self) -> String {
        // Serialization is infallible for this shape (serde_json::Number can't hold
        // NaN/Inf, everything else is primitives); the fallback is defense in depth.
        // debug!, not error!: diag internals must never re-enter the capture layer
        // at a captured-by-default level.
        serde_json::to_string(self).unwrap_or_else(|e| {
            tracing::debug!(err = %e, "diag: event serialization failed");
            "{}".into()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_serializes_to_stable_jsonl_shape() {
        let mut ev = DiagEvent::new(DiagLevel::Info, "app", "unbounded.peer_connected");
        ev.session = Some("sess-1".into());
        ev.fields.insert("nat_traversal_ms".into(), 812u64.into());
        let line = ev.to_jsonl();
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["kind"], "unbounded.peer_connected");
        assert_eq!(v["level"], "info");
        assert_eq!(v["component"], "app");
        assert_eq!(v["session"], "sess-1");
        assert_eq!(v["fields"]["nat_traversal_ms"], 812);
        assert!(v["ts"].as_u64().unwrap() > 1_700_000_000_000);
        assert!(!line.contains('\n'), "JSONL: one line per event");
    }

    #[test]
    fn string_fields_are_ip_redacted_on_insert() {
        let mut ev = DiagEvent::new(DiagLevel::Error, "app", "log");
        ev.insert_str("message", "dial 1.2.3.4:443 failed");
        assert_eq!(ev.fields["message"], "dial [redacted-ip]:443 failed");
    }
}
