//! Typed event constructors — the privacy allowlist for on-device diagnostics (spec §C5/§C6).
//!
//! Every string parameter flows through [`DiagEvent::insert_str`] (IP redaction backstop).
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
    let arr: Value = candidate_types
        .iter()
        .map(|s| Value::String(crate::redact::redact_addrs(s).into_owned()))
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
    ev.session = Some(session.to_string());
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
    ev.session = Some(session.to_string());
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
    ev.session = Some(session.to_string());
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
pub fn error_webview(message: &str, source: &str) -> DiagEvent {
    let mut ev = DiagEvent::new(DiagLevel::Error, "app", "error.webview");
    ev.insert_str("message", message);
    ev.insert_str("source", source);
    ev
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
            ] {
                assert!(!line.contains(ip), "leaked {ip} in {line}");
            }
        }
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
