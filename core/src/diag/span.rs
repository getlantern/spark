//! Session-scoped OTLP spans for Unbounded timing waterfalls (design §C3a).
//!
//! Each [`SessionTrace`] covers one Unbounded session: a root span named
//! `"unbounded.session"` with named child spans (`signaling`, `nat_traversal`,
//! `relay`, …). The finished [`DiagSpan`] slice is passed to
//! [`super::otlp::encode_spans`] for upload alongside the session's log records.

use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use ring::rand::{SecureRandom, SystemRandom};

use crate::redact::redact_addrs;

// ---------------------------------------------------------------------------
// Shared RNG — constructed once, cheap to call repeatedly.
// Constructing SystemRandom per call is also cheap (it calls into the OS),
// but a shared instance avoids even that overhead on hot paths.
// ---------------------------------------------------------------------------
static RNG: OnceLock<SystemRandom> = OnceLock::new();

fn rng() -> &'static SystemRandom {
    RNG.get_or_init(SystemRandom::new)
}

/// Generate 16 random bytes for a trace id, falling back to the current
/// timestamp on RNG failure (practically impossible, but we must never panic).
fn gen_trace_id() -> [u8; 16] {
    let mut buf = [0u8; 16];
    if rng().fill(&mut buf).is_ok() {
        return buf;
    }
    // Fallback: fill from timestamp nanos (top 8 bytes) and zeros (low 8 bytes)
    let nanos = now_nanos().to_le_bytes();
    buf[..8].copy_from_slice(&nanos);
    buf
}

/// Generate 8 random bytes for a span id, with the same timestamp fallback.
fn gen_span_id() -> [u8; 8] {
    let mut buf = [0u8; 8];
    if rng().fill(&mut buf).is_ok() {
        return buf;
    }
    now_nanos().to_le_bytes()
}

/// Current wall-clock time as Unix nanoseconds.
///
/// Pre-epoch or badly-synced clocks map to 0 — the sentinel is preferable to
/// panicking; the server receipt time is the trusted clock (spec §C1).
fn now_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// One finished span, ready for OTLP encoding.
#[derive(Debug, Clone)]
pub struct DiagSpan {
    pub trace_id: [u8; 16],
    pub span_id: [u8; 8],
    /// Parent span id; `None` for the root span.
    pub parent_span_id: Option<[u8; 8]>,
    pub name: &'static str,
    pub start_unix_nano: u64,
    pub end_unix_nano: u64,
    /// Redacted error description; `Some` ⇒ OTLP status code ERROR (code 2).
    pub error: Option<String>,
    /// Arbitrary key/value attributes, values already redacted before insertion.
    pub attrs: BTreeMap<String, serde_json::Value>,
}

/// State of a child span that is still open.
struct OpenChild {
    name: &'static str,
    span_id: [u8; 8],
    start_unix_nano: u64,
}

/// Builder for one Unbounded session's trace (spec §C3a): a root span
/// `"unbounded.session"` with named child spans.
///
/// Children may overlap; unclosed children are closed at [`finish`][Self::finish]
/// with no error. The order of spans in the returned `Vec<DiagSpan>` is children
/// first then root — OTLP receivers accept any order.
pub struct SessionTrace {
    trace_id: [u8; 16],
    root_span_id: [u8; 8],
    root_start_nano: u64,
    /// Redacted session identifier attached as `session` attr on the root span.
    session_attr: String,
    open_children: Vec<OpenChild>,
    finished_children: Vec<DiagSpan>,
}

impl SessionTrace {
    /// Create a new trace for `session_id`. Allocates random trace / root-span ids.
    pub fn new(session_id: &str) -> Self {
        SessionTrace {
            trace_id: gen_trace_id(),
            root_span_id: gen_span_id(),
            root_start_nano: now_nanos(),
            session_attr: redact_addrs(session_id).into_owned(),
            open_children: Vec::new(),
            finished_children: Vec::new(),
        }
    }

    /// The 16-byte trace id shared by all spans in this session.
    pub fn trace_id(&self) -> [u8; 16] {
        self.trace_id
    }

    /// The root span's 8-byte span id — used by [`super::otlp::encode_logs`] as
    /// the `trace_ctx` span id so log records are correlated with the session trace.
    pub fn root_span_id(&self) -> [u8; 8] {
        self.root_span_id
    }

    /// Open a named child span.
    ///
    /// No-op (with a `tracing::debug!`) when a child with this name is already open,
    /// since overlapping children with the same name would be ambiguous at finish.
    pub fn child_start(&mut self, name: &'static str) {
        if self.open_children.iter().any(|c| c.name == name) {
            tracing::debug!(span = name, "diag: child_start ignored — span already open");
            return;
        }
        self.open_children.push(OpenChild {
            name,
            span_id: gen_span_id(),
            start_unix_nano: now_nanos(),
        });
    }

    /// Close the named child span, optionally recording a redacted error.
    ///
    /// No-op (silently) if no child with this name is currently open.
    pub fn child_end(&mut self, name: &'static str, error: Option<&str>) {
        let end_nano = now_nanos();
        let pos = self.open_children.iter().position(|c| c.name == name);
        let Some(idx) = pos else { return };
        let child = self.open_children.remove(idx);
        self.finished_children
            .push(self.make_child_span(child, end_nano, error));
    }

    /// Finish the session trace, closing any still-open children (with no error),
    /// then closing the root span. Returns all spans in an unspecified order
    /// (children first, then root — but OTLP receivers accept any ordering).
    pub fn finish(mut self, error: Option<&str>) -> Vec<DiagSpan> {
        let end_nano = now_nanos();

        // Close lingering children with no error.
        let lingering: Vec<OpenChild> = self.open_children.drain(..).collect();
        for child in lingering {
            let span = self.make_child_span(child, end_nano, None);
            self.finished_children.push(span);
        }

        // Build root span.
        let mut root_attrs = BTreeMap::new();
        root_attrs.insert(
            "session".to_string(),
            serde_json::Value::String(self.session_attr.clone()),
        );
        let root = DiagSpan {
            trace_id: self.trace_id,
            span_id: self.root_span_id,
            parent_span_id: None,
            name: "unbounded.session",
            start_unix_nano: self.root_start_nano,
            end_unix_nano: end_nano,
            error: error.map(|e| redact_addrs(e).into_owned()),
            attrs: root_attrs,
        };

        let mut out = self.finished_children;
        out.push(root);
        out
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn make_child_span(&self, child: OpenChild, end_nano: u64, error: Option<&str>) -> DiagSpan {
        DiagSpan {
            trace_id: self.trace_id,
            span_id: child.span_id,
            parent_span_id: Some(self.root_span_id),
            name: child.name,
            start_unix_nano: child.start_unix_nano,
            end_unix_nano: end_nano,
            error: error.map(|e| redact_addrs(e).into_owned()),
            attrs: BTreeMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests (TDD: written before implementation was complete)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_trace_has_root_and_children() {
        let mut t = SessionTrace::new("sess-1");
        t.child_start("signaling");
        t.child_end("signaling", None);
        t.child_start("nat_traversal");
        t.child_end("nat_traversal", None);
        let spans = t.finish(None);

        assert_eq!(spans.len(), 3, "expected root + 2 children");

        let root = spans
            .iter()
            .find(|s| s.name == "unbounded.session")
            .unwrap();
        let signaling = spans.iter().find(|s| s.name == "signaling").unwrap();
        let nat = spans.iter().find(|s| s.name == "nat_traversal").unwrap();

        // All share the same trace id
        for span in &spans {
            assert_eq!(span.trace_id, root.trace_id, "all spans share trace_id");
        }

        // Children point to root
        assert_eq!(signaling.parent_span_id, Some(root.span_id));
        assert_eq!(nat.parent_span_id, Some(root.span_id));
        assert!(root.parent_span_id.is_none());

        // Root carries session attr
        assert_eq!(
            root.attrs.get("session").and_then(|v| v.as_str()),
            Some("sess-1")
        );

        // Every span: end >= start
        for span in &spans {
            assert!(
                span.end_unix_nano >= span.start_unix_nano,
                "span {} end < start",
                span.name
            );
        }
    }

    #[test]
    fn error_span_carries_status() {
        let t = SessionTrace::new("sess-2");
        let spans = t.finish(Some("EgressError::Refused at 1.2.3.4"));
        let root = spans
            .iter()
            .find(|s| s.name == "unbounded.session")
            .unwrap();
        let err = root.error.as_deref().expect("root should have error");
        assert!(
            !err.contains("1.2.3.4"),
            "IP address must be redacted in error string"
        );
        assert!(
            err.contains("[redacted-ip]"),
            "redacted token must be present: {err:?}"
        );
    }

    #[test]
    fn unclosed_children_are_closed_at_finish() {
        let mut t = SessionTrace::new("sess-3");
        t.child_start("relay");
        let spans = t.finish(None);

        let relay = spans
            .iter()
            .find(|s| s.name == "relay")
            .expect("relay must exist");
        assert!(
            relay.end_unix_nano >= relay.start_unix_nano,
            "relay end >= start"
        );
        assert!(
            relay.error.is_none(),
            "auto-closed child must have no error"
        );
    }

    #[test]
    fn ids_are_random_and_correct_length() {
        let t1 = SessionTrace::new("a");
        let t2 = SessionTrace::new("b");

        // Type system enforces lengths (16 / 8 bytes), so just assert inequality.
        assert_ne!(
            t1.trace_id(),
            t2.trace_id(),
            "two sessions must have different trace ids"
        );
        assert_ne!(
            t1.root_span_id(),
            t2.root_span_id(),
            "two sessions must have different root span ids"
        );
    }
}
