//! Typed event constructors — the privacy allowlist for on-device diagnostics (spec §C5/§C6).
//!
//! Every string parameter flows through [`DiagEvent::insert_str`] (IP + URL redaction backstop).
//! Numeric parameters are inserted directly into `fields`. Optional parameters are omitted
//! when `None`. The set of constructors here is the exhaustive allowlist: adding a new event
//! kind means adding a new function with a typed signature, not reaching for `fields` directly.

use serde_json::Value;

use super::{DiagEvent, DiagLevel};

/// General log bridge: captures a tracing-style message and target.
pub fn log(level: DiagLevel, message: &str, target: &str) -> DiagEvent {
    let mut ev = DiagEvent::new(level, "app", "log");
    ev.insert_str("message", message);
    ev.insert_str("target", target);
    ev
}

/// Unbounded slot became active and is attempting to connect.
pub fn unbounded_attempt_started(slot: usize) -> DiagEvent {
    let mut ev = DiagEvent::new(DiagLevel::Info, "app", "unbounded.attempt_started");
    ev.fields.insert("slot".into(), (slot as u64).into());
    ev
}

/// ICE candidate gathering complete; records candidate types seen and count.
pub fn unbounded_ice_gathering(candidate_types: &[&str], count: u64) -> DiagEvent {
    let mut ev = DiagEvent::new(DiagLevel::Info, "app", "unbounded.ice_gathering");
    // Can't use insert_str (it takes &str, not arrays): apply the same composite
    // redaction (`redact_all`) per element so array fields keep the §C5 backstop.
    let arr: Value = candidate_types
        .iter()
        .map(|s| Value::String(crate::redact::redact_all(s).into_owned()))
        .collect();
    ev.fields.insert("candidate_types".into(), arr);
    ev.fields.insert("count".into(), count.into());
    ev
}

/// Peer successfully connected via WebRTC.
pub fn unbounded_peer_connected(
    session: &str,
    nat_traversal_ms: u64,
    selected_pair_type: &str,
    peer_region: Option<&str>,
) -> DiagEvent {
    let mut ev = DiagEvent::new(DiagLevel::Info, "app", "unbounded.peer_connected");
    // Session ids are opaque tokens in practice, but the §C5 backstop applies to every
    // string that reaches the wire — redact in case a caller embeds an address or URL.
    ev.session = Some(crate::redact::redact_all(session).into_owned());
    ev.fields
        .insert("nat_traversal_ms".into(), nat_traversal_ms.into());
    ev.insert_str("selected_pair_type", selected_pair_type);
    if let Some(region) = peer_region {
        ev.insert_str("peer_region", region);
    }
    ev
}

/// Periodic throughput sample for an active peer session.
pub fn unbounded_throughput_sample(
    session: &str,
    bytes_up: u64,
    bytes_down: u64,
    interval_ms: u64,
) -> DiagEvent {
    let mut ev = DiagEvent::new(DiagLevel::Debug, "app", "unbounded.throughput_sample");
    ev.session = Some(crate::redact::redact_all(session).into_owned());
    ev.fields.insert("bytes_up".into(), bytes_up.into());
    ev.fields.insert("bytes_down".into(), bytes_down.into());
    ev.fields.insert("interval_ms".into(), interval_ms.into());
    ev
}

/// Peer session ended.
pub fn unbounded_peer_disconnected(
    session: &str,
    duration_ms: u64,
    bytes_total: u64,
    reason: &str,
) -> DiagEvent {
    let mut ev = DiagEvent::new(DiagLevel::Info, "app", "unbounded.peer_disconnected");
    ev.session = Some(crate::redact::redact_all(session).into_owned());
    ev.fields.insert("duration_ms".into(), duration_ms.into());
    ev.fields.insert("bytes_total".into(), bytes_total.into());
    ev.insert_str("reason", reason);
    ev
}

/// An unbounded connection attempt on the given slot failed.
pub fn unbounded_attempt_failed(slot: usize, error_kind: &str) -> DiagEvent {
    let mut ev = DiagEvent::new(DiagLevel::Error, "app", "unbounded.attempt_failed");
    ev.fields.insert("slot".into(), (slot as u64).into());
    ev.insert_str("error_kind", error_kind);
    ev
}

/// Geographic peer selection failed.
pub fn unbounded_geo_failed(reason: &str) -> DiagEvent {
    let mut ev = DiagEvent::new(DiagLevel::Warn, "app", "unbounded.geo_failed");
    ev.insert_str("reason", reason);
    ev
}

/// Snapshot of the unbounded peer pool state.
pub fn unbounded_pool_snapshot(
    active_peers: u64,
    slots_filled: u64,
    total_helped: u64,
) -> DiagEvent {
    let mut ev = DiagEvent::new(DiagLevel::Info, "app", "unbounded.pool_snapshot");
    ev.fields.insert("active_peers".into(), active_peers.into());
    ev.fields.insert("slots_filled".into(), slots_filled.into());
    ev.fields.insert("total_helped".into(), total_helped.into());
    ev
}

/// Signaling channel state change. Level is `Error` when `error_kind` is provided.
pub fn unbounded_signaling(
    state: &str,
    latency_ms: Option<u64>,
    error_kind: Option<&str>,
) -> DiagEvent {
    let level = if error_kind.is_some() {
        DiagLevel::Error
    } else {
        DiagLevel::Info
    };
    let mut ev = DiagEvent::new(level, "app", "unbounded.signaling");
    ev.insert_str("state", state);
    if let Some(ms) = latency_ms {
        ev.fields.insert("latency_ms".into(), ms.into());
    }
    if let Some(kind) = error_kind {
        ev.insert_str("error_kind", kind);
    }
    ev
}

/// Config fetch result: succeeded or failed, which avenue was used, and how long it took.
pub fn config_fetch_outcome(result: &str, avenue: &str, latency_ms: u64) -> DiagEvent {
    let mut ev = DiagEvent::new(DiagLevel::Info, "app", "config.fetch_outcome");
    ev.insert_str("result", result);
    ev.insert_str("avenue", avenue);
    ev.fields.insert("latency_ms".into(), latency_ms.into());
    ev
}

/// Diagnostic ring overflowed; `count` events were dropped since the last report.
pub fn diag_buffer_dropped(count: u64) -> DiagEvent {
    let mut ev = DiagEvent::new(DiagLevel::Warn, "app", "diag.buffer_dropped");
    ev.fields.insert("count".into(), count.into());
    ev
}

/// A `Mutex` was poisoned at the given site.
pub fn diag_lock_poisoned(site: &str) -> DiagEvent {
    let mut ev = DiagEvent::new(DiagLevel::Error, "app", "diag.lock_poisoned");
    ev.insert_str("site", site);
    ev
}

/// A diagnostics configuration knob was applied.
pub fn diag_config_applied(knob: &str, value: &str) -> DiagEvent {
    let mut ev = DiagEvent::new(DiagLevel::Info, "app", "diag.config_applied");
    ev.insert_str("knob", knob);
    ev.insert_str("value", value);
    ev
}

/// A panic was caught; `location` is the `file:line` from `std::panic::Location`.
pub fn error_panic(message: &str, location: &str) -> DiagEvent {
    let mut ev = DiagEvent::new(DiagLevel::Error, "app", "error.panic");
    ev.insert_str("message", message);
    ev.insert_str("location", location);
    ev
}

/// A background task exited with an error.
pub fn error_task_failed(task: &str, error: &str) -> DiagEvent {
    let mut ev = DiagEvent::new(DiagLevel::Error, "app", "error.task_failed");
    ev.insert_str("task", task);
    ev.insert_str("error", error);
    ev
}

/// A webview error (JS exception, load failure, or similar).
///
/// Webview strings routinely embed full URLs (the reporting script's URL, a failed
/// fetch target), which the §C5 deny-list forbids exporting. `insert_str` handles URL
/// redaction in `message`; `source` is additionally reduced to its final path segment
/// (no scheme/host/query/fragment) before insertion. This is the collection point, so
/// every reporter (onerror, unhandledrejection, future callers of the plugin command)
/// is covered regardless of what it sends.
pub fn error_webview(message: &str, source: &str) -> DiagEvent {
    let mut ev = DiagEvent::new(DiagLevel::Error, "app", "error.webview");
    ev.insert_str("message", message);
    ev.insert_str("source", source_basename(source));
    ev
}

/// Reduce a webview `source` to its final path segment: strip any scheme+authority,
/// query, and fragment, then take the last `/`- (or `\`-) delimited component. A
/// path-less URL (bare origin) or empty result degrades to `"webview"` rather than
/// leaking the host. Non-URL markers (`window`, `unhandledrejection`) pass through.
fn source_basename(source: &str) -> &str {
    let path = match source.find("://") {
        // Skip scheme + authority; without a path there is only a host to leak.
        Some(i) => match source[i + 3..].find('/') {
            Some(j) => &source[i + 3 + j + 1..],
            None => return "webview",
        },
        None => source,
    };
    let no_query = path.split(['?', '#']).next().unwrap_or(path);
    let base = no_query.rsplit(['/', '\\']).next().unwrap_or(no_query);
    if base.is_empty() {
        "webview"
    } else {
        base
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_connected_shape() {
        let ev = unbounded_peer_connected("s1", 812, "srflx", Some("DE"));
        assert_eq!(ev.kind, "unbounded.peer_connected");
        assert_eq!(ev.session.as_deref(), Some("s1"));
        assert_eq!(ev.fields["nat_traversal_ms"], 812);
        assert_eq!(ev.fields["selected_pair_type"], "srflx");
        assert_eq!(ev.fields["peer_region"], "DE");
    }

    #[test]
    fn no_event_constructor_leaks_ip_literals() {
        let evs = vec![
            log(DiagLevel::Warn, "dial 1.2.3.4:443", "spark_core::x"),
            unbounded_attempt_failed(0, "egress [2001:db8::1]:443 refused"),
            error_panic("panicked at 10.0.0.1", "src/main.rs:1"),
            unbounded_peer_disconnected("s", 1, 2, "reset by 8.8.8.8"),
            unbounded_signaling("connect", Some(5), Some("timeout at 9.9.9.9")),
            error_webview("fetch to 172.16.0.1 failed", "app.js"),
            unbounded_ice_gathering(&["host", "srflx via 1.2.3.4"], 2),
            unbounded_peer_connected("peer-10.0.0.9", 1, "srflx", Some("region 10.0.0.1")),
            unbounded_geo_failed("geoip 192.168.1.1 not found"),
            config_fetch_outcome("ok", "direct from 1.2.3.4", 100),
            diag_lock_poisoned("at 172.16.0.1"),
            diag_config_applied("knob", "val with 8.8.8.8"),
            error_task_failed("uploader", "connect to 10.0.0.1 refused"),
        ];
        for ev in evs {
            let line = ev.to_jsonl();
            for ip in [
                "1.2.3.4",
                "2001:db8::1",
                "10.0.0.1",
                "8.8.8.8",
                "9.9.9.9",
                "172.16.0.1",
                "192.168.1.1",
                "10.0.0.9",
            ] {
                assert!(!line.contains(ip), "leaked {ip} in {line}");
            }
        }
    }

    #[test]
    fn webview_error_strips_urls_from_message_and_paths_from_source() {
        let ev = error_webview(
            "fetch https://api.example.com/config?key=abc failed, retry wss://sig.example.net/ws later",
            "https://app.example.com/assets/index-4f2a.js?v=1#L10",
        );
        let line = ev.to_jsonl();
        assert!(!line.contains("example.com"), "leaked host in {line}");
        assert!(!line.contains("example.net"), "leaked host in {line}");
        assert!(!line.contains("key=abc"), "leaked query in {line}");
        assert_eq!(
            ev.fields["message"],
            "fetch [redacted-url] failed, retry [redacted-url] later"
        );
        assert_eq!(ev.fields["source"], "index-4f2a.js");
    }

    #[test]
    fn webview_source_shapes() {
        // Bare origin (no path): nothing safe to keep — placeholder, never the host.
        assert_eq!(
            error_webview("m", "https://example.com").fields["source"],
            "webview"
        );
        assert_eq!(
            error_webview("m", "tauri://localhost/").fields["source"],
            "webview"
        );
        // Non-URL markers from the bridge pass through.
        assert_eq!(error_webview("m", "window").fields["source"], "window");
        assert_eq!(
            error_webview("m", "unhandledrejection").fields["source"],
            "unhandledrejection"
        );
        // Filesystem paths reduce to the basename (no user-bearing directories, §C5).
        assert_eq!(
            error_webview("m", "/Users/someone/app/bundle.js").fields["source"],
            "bundle.js"
        );
        assert_eq!(
            error_webview("m", "C:\\Users\\someone\\bundle.js").fields["source"],
            "bundle.js"
        );
    }

    #[test]
    fn error_kinds_are_error_level() {
        for ev in [
            unbounded_attempt_failed(0, "x"),
            diag_lock_poisoned("s"),
            error_panic("m", "l"),
            error_task_failed("t", "e"),
            error_webview("m", "s"),
        ] {
            assert_eq!(ev.level, DiagLevel::Error, "kind {}", ev.kind);
        }
    }
}
