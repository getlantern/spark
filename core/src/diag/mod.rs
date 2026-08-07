//! On-device diagnostics: structured events captured to a ring/spool/backup-log and
//! uploaded as OTLP logs+traces to the config-delivered otel endpoint (design:
//! docs/superpowers/specs/2026-07-17-spark-diagnostics-design.md). Privacy: every
//! string field is IP- and URL-redacted on insert; kinds/fields follow the spec §C5
//! allowlist (enforced by the typed constructors in `events`, a later task).

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

pub mod events;
pub mod layer;
pub mod otlp;
pub mod panic_hook;
pub mod sentinel;
pub mod sink;
pub mod span;
// The tunnel host wires the uploader + the fetch-cache re-parse, both of which only
// exist under `config-fetch` (and the tunnel process it serves is the self-fetching
// NE, which always builds with that feature).
#[cfg(feature = "config-fetch")]
pub mod tunnel_host;
// The uploader reuses config-fetch's HTTP/TLS plumbing, and its `tls_wrap` is a no-op
// passthrough without the `anytls` feature (which `config-fetch` implies) — gating the
// whole module on `config-fetch` makes a plaintext upload build impossible.
#[cfg(feature = "config-fetch")]
pub mod upload;

pub use sink::{emit, emit_error, install, DiagSink};

/// Whether this launch has the user's consent to collect diagnostics.
///
/// **Opt-in**: anything that is not an explicit yes is a no. A user who never saw the question, a
/// launch that could not read the setting, or a typo all resolve to *off* — the failure direction
/// that collects nothing, rather than the one that quietly collects from someone who never agreed.
///
/// This inverts the earlier opt-*out*, where a user who never saw the question was enrolled by
/// default and a config-server flag was enough to start their stream. Under opt-in the server can
/// only ever *narrow* what an opted-in device sends; it cannot enroll anyone.
///
/// Lives here rather than in either host so both share exactly one implementation — two gates that
/// could drift is how one entry point keeps collecting by default. (`tunnel_host` is
/// platform-gated, so it is not a home the service host can reach.)
///
/// `SPARK_DIAGNOSTICS` is the test-phase channel; the production one is the app's user-facing
/// toggle, plumbed through `providerConfiguration`, which is the remaining piece. Affirmatives are
/// matched case- and whitespace-insensitively because this gets set by hand and by scripts, and
/// consent should not fail on capitalisation.
pub fn opted_in() -> bool {
    consented(&std::env::var("SPARK_DIAGNOSTICS").unwrap_or_default())
}

/// The parsing rule behind [`opted_in`], split out so it is testable without mutating
/// process-global env (which a parallel test run would race on).
fn consented(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "on" | "1" | "true" | "yes"
    )
}

#[cfg(test)]
mod consent_tests {
    use super::consented;

    /// Consent is opt-**in**: anything that is not an explicit yes is a no.
    ///
    /// The declines matter more than the accepts. Unset (never asked), empty (unreadable), a typo,
    /// and the *old* opt-out value must all resolve to off.
    #[test]
    fn only_an_explicit_yes_enables_diagnostics() {
        for yes in ["on", "1", "true", "yes", "ON", "  True  "] {
            assert!(consented(yes), "{yes:?} should enable");
        }
        for no in ["", "off", "OFF", "0", "false", "no", "maybe", "onn", " "] {
            assert!(
                !consented(no),
                "{no:?} must NOT enable — absence of yes is no"
            );
        }
    }

    /// Under opt-in, the previous opt-out value and "never set" are the same answer. Pinned so the
    /// old flag can never be read as an accidental enabler.
    #[test]
    fn the_previous_opt_out_value_still_means_off() {
        assert_eq!(consented("off"), consented(""), "both are a decline");
    }
}

/// Per-field byte cap for string values, applied in [`DiagEvent::insert_str`].
///
/// Keeps any single spool line far below the uploader's 256 KiB batch budget: an
/// unbounded field (a huge webview error string, a pathological log message) would
/// otherwise produce a first line no `take_spool_batch` budget can fit, making every
/// take return an empty batch and stalling uploads until rotation discards the line.
const MAX_STR_FIELD: usize = 8 * 1024;
/// Marker appended when [`MAX_STR_FIELD`] truncates a field.
const TRUNCATED: &str = "…[truncated]";

/// Severity level for a [`DiagEvent`], serialized in lowercase for JSONL / OTLP.
/// `Deserialize` because the uploader re-reads spool lines to re-encode them as OTLP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

    /// Insert a string field with the §C5 backstops — IP-literal + URL redaction
    /// ([`redact_all`]) — and a size bound ([`MAX_STR_FIELD`], UTF-8-safe truncation).
    ///
    /// [`redact_all`]: crate::redact::redact_all
    pub fn insert_str(&mut self, key: &str, value: &str) {
        let clean = crate::redact::redact_all(value);
        let bounded: String = if clean.len() > MAX_STR_FIELD {
            // Walk down to a char boundary so truncation can't split a multibyte
            // char and produce invalid UTF-8 (which would fail serialization).
            let mut end = MAX_STR_FIELD;
            while !clean.is_char_boundary(end) {
                end -= 1;
            }
            let mut s = String::with_capacity(end + TRUNCATED.len());
            s.push_str(&clean[..end]);
            s.push_str(TRUNCATED);
            s
        } else {
            clean.into_owned()
        };
        self.fields.insert(key.to_string(), bounded.into());
    }

    /// One-line JSON for the spool / backup log.
    pub fn to_jsonl(&self) -> String {
        // Serialization is infallible for this shape (serde_json::Number can't hold
        // NaN/Inf, everything else is primitives); the fallback is defense in depth.
        // debug!, not error!: diag internals must never re-enter the capture layer
        // at a captured-by-default level. Known accepted exception to the panic
        // hook's "no tracing in the hook" rule: this arm is reachable from
        // panic_hook → emit_error → to_jsonl, but only on a serialization failure
        // that this shape cannot produce.
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

    #[test]
    fn string_fields_are_url_redacted_on_insert() {
        // §C5 deny-lists URLs; the general `log` bridge flows through here too.
        let mut ev = DiagEvent::new(DiagLevel::Info, "app", "log");
        ev.insert_str("message", "GET https://api.example.com/cfg?k=v failed");
        assert_eq!(ev.fields["message"], "GET [redacted-url] failed");
    }

    #[test]
    fn oversized_string_fields_truncate_on_char_boundary() {
        let mut ev = DiagEvent::new(DiagLevel::Error, "app", "log");
        // 2-byte chars so the byte cap lands mid-char: truncation must back up to a
        // boundary rather than produce invalid UTF-8.
        let big = "é".repeat(MAX_STR_FIELD); // 2 * MAX_STR_FIELD bytes
        ev.insert_str("message", &big);
        let stored = ev.fields["message"].as_str().unwrap();
        assert!(stored.ends_with(TRUNCATED));
        assert!(stored.len() <= MAX_STR_FIELD + TRUNCATED.len());
        // The resulting spool line stays far below the uploader's batch budget, so a
        // single event can never wedge take_spool_batch into empty batches.
        assert!(ev.to_jsonl().len() < 4 * MAX_STR_FIELD);
    }

    #[test]
    fn small_string_fields_are_not_truncated() {
        let mut ev = DiagEvent::new(DiagLevel::Info, "app", "log");
        ev.insert_str("message", "short");
        assert_eq!(ev.fields["message"], "short");
    }
}
