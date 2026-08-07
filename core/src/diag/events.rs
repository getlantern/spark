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

/// The previous session ended without its clean-exit path (crash class unknown —
/// covers what the panic hook can't: segfaults, OOM/watchdog kills, kill -9).
pub fn error_unclean_exit(
    prev_started_ms: u64,
    prev_last_alive_ms: u64,
    prev_version: &str,
) -> DiagEvent {
    let mut ev = DiagEvent::new(DiagLevel::Error, "app", "error.unclean_exit");
    ev.fields
        .insert("prev_started_ms".into(), prev_started_ms.into());
    ev.fields
        .insert("prev_last_alive_ms".into(), prev_last_alive_ms.into());
    ev.insert_str("prev_version", prev_version);
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

    /// Every constructor, called with adversarial input in each of its string parameters, paired
    /// with its name so [`every_constructor_is_covered`] can check the list is complete.
    ///
    /// The planted values are the canaries the hygiene tests hunt for: an address is a
    /// destination, a resolver, or a peer depending only on which argument it landed in, so one
    /// corpus covers all three of those classes at once.
    fn dirty_events() -> Vec<(&'static str, DiagEvent)> {
        vec![
            (
                "log",
                log(DiagLevel::Warn, "dial 1.2.3.4:443", "spark_core::x"),
            ),
            ("unbounded_attempt_started", unbounded_attempt_started(3)),
            (
                "unbounded_ice_gathering",
                unbounded_ice_gathering(&["host", "srflx via 1.2.3.4"], 2),
            ),
            (
                "unbounded_peer_connected",
                unbounded_peer_connected("peer-10.0.0.9", 1, "srflx", Some("region 10.0.0.1")),
            ),
            (
                "unbounded_throughput_sample",
                unbounded_throughput_sample("session-192.168.1.1", 1, 2, 3),
            ),
            (
                "unbounded_peer_disconnected",
                unbounded_peer_disconnected("s", 1, 2, "reset by 8.8.8.8"),
            ),
            (
                "unbounded_attempt_failed",
                unbounded_attempt_failed(0, "egress [2001:db8::1]:443 refused"),
            ),
            (
                "unbounded_geo_failed",
                unbounded_geo_failed("geoip 192.168.1.1 not found"),
            ),
            ("unbounded_pool_snapshot", unbounded_pool_snapshot(1, 2, 3)),
            (
                "unbounded_signaling",
                unbounded_signaling("connect", Some(5), Some("timeout at 9.9.9.9")),
            ),
            (
                "config_fetch_outcome",
                config_fetch_outcome("ok", "direct from 1.2.3.4", 100),
            ),
            ("diag_buffer_dropped", diag_buffer_dropped(7)),
            ("diag_lock_poisoned", diag_lock_poisoned("at 172.16.0.1")),
            (
                "diag_config_applied",
                diag_config_applied("knob", "val with 8.8.8.8"),
            ),
            (
                "error_panic",
                error_panic("panicked at 10.0.0.1", "src/main.rs:1"),
            ),
            (
                "error_task_failed",
                error_task_failed("uploader", "connect to 10.0.0.1 refused"),
            ),
            (
                "error_unclean_exit",
                error_unclean_exit(1, 2, "version 10.0.0.1"),
            ),
            (
                "error_webview",
                error_webview(
                    "fetch to 172.16.0.1 failed https://evil.example/x",
                    "app.js",
                ),
            ),
        ]
    }

    /// The planted canaries: addresses and hosts that must not survive into anything uploaded.
    const CANARIES: &[&str] = &[
        "1.2.3.4",
        "2001:db8::1",
        "10.0.0.1",
        "8.8.8.8",
        "9.9.9.9",
        "172.16.0.1",
        "192.168.1.1",
        "10.0.0.9",
        "evil.example",
    ];

    /// No constructor leaks an address — checked on the spool line **and** on the encoded OTLP
    /// payload, which is what actually leaves the device.
    ///
    /// Checking only `to_jsonl` would miss anything the encoder adds or re-derives on the way out
    /// (the log body, for one, is lifted out of `fields["message"]` rather than copied from the
    /// attribute set).
    #[test]
    fn no_event_constructor_leaks_ip_literals() {
        for (name, ev) in dirty_events() {
            let line = ev.to_jsonl();
            for canary in CANARIES {
                assert!(!line.contains(canary), "{name} leaked {canary} in {line}");
            }
        }
        let encoded = String::from_utf8(encode_corpus()).expect("OTLP JSON is UTF-8");
        for canary in CANARIES {
            assert!(
                !encoded.contains(canary),
                "{canary} survived into the uploaded OTLP payload"
            );
        }
    }

    /// Run the whole corpus through the real spool → OTLP path and return the bytes that would be
    /// POSTed. Goes via `to_jsonl` + `SpoolEvent` deliberately: that round-trip is what the
    /// uploader does, and encoding the live events directly would skip it.
    fn encode_corpus() -> Vec<u8> {
        let spooled: Vec<crate::diag::otlp::SpoolEvent> = dirty_events()
            .into_iter()
            .map(|(name, ev)| {
                serde_json::from_str(&ev.to_jsonl())
                    .unwrap_or_else(|e| panic!("{name} spool line must re-parse: {e}"))
            })
            .collect();
        crate::diag::otlp::encode_spool_logs(&hygiene_res(), &spooled, |_| None)
    }

    fn hygiene_res() -> crate::diag::otlp::ResourceAttrs {
        crate::diag::otlp::ResourceAttrs {
            service_version: "0.0.0".into(),
            git_sha: "test".into(),
            device_id: "d".into(),
            platform: "darwin".into(),
            country: "US".into(),
            environment: "test".into(),
            component: "app".into(),
            os_name: "macos".into(),
            os_version: "0".into(),
            arch: "arm64".into(),
        }
    }

    /// [`dirty_events`] covers every constructor in this module — enforced against the source
    /// rather than against a reviewer's memory.
    ///
    /// Without this, the leak tests silently stop covering each newly added event kind, which is
    /// the failure mode a hand-maintained corpus always has. A new `pub fn` here fails this test
    /// until it is exercised above.
    #[test]
    fn every_constructor_is_covered() {
        let covered: Vec<&str> = dirty_events().into_iter().map(|(name, _)| name).collect();
        let declared: Vec<&str> = include_str!("events.rs")
            .lines()
            .filter_map(|l| l.strip_prefix("pub fn "))
            .filter_map(|l| l.split('(').next())
            .collect();
        assert!(
            !declared.is_empty(),
            "the source scan found no constructors — it has stopped testing anything"
        );
        for name in declared {
            assert!(
                covered.contains(&name),
                "`{name}` is not in dirty_events(), so no hygiene test covers it"
            );
        }
    }

    /// Every attribute KEY in an uploaded payload comes from a set fixed at compile time.
    ///
    /// This is the client-side form of the rule the DNS-tunnel server enforces over attribute
    /// *values* (`dns-tunnel-server/src/otlp.rs`). Values cannot be closed here — a log message is
    /// free-form text by nature, which is what the redaction backstop above is for — but the keys
    /// can be, and that is the check with teeth: a future `destination`, `client_ip`,
    /// `resolver_ip`, or `conn_id` field fails here no matter what value it carries, and no matter
    /// whether any redactor happens to recognize its shape. A ConnectionID in particular is
    /// 8 random bytes in hex, which no redactor can distinguish from an ordinary token — so the
    /// key is the only place it can be caught.
    #[test]
    fn every_emitted_attribute_key_is_from_a_closed_set() {
        // The resource block (`otlp::build_resource_attrs`) — `getlantern/semconv` names, all
        // build-time or identity values, none derived from anything the device connects to.
        // `geo.country.iso_code` is the server's own coarse view of the client, deliberately
        // country-granular: no precise geolocation ever leaves the device (design §1).
        const ALLOWED_RESOURCE: &[&str] = &[
            "service.name",
            "service.version",
            "spark.git_sha",
            "spark.component",
            "client.device_id",
            "client.platform",
            "deployment.environment.name",
            "geo.country.iso_code",
            "os.name",
            "os.version",
            "host.arch",
        ];
        // Structural keys, then one entry per field any constructor above can insert.
        const ALLOWED: &[&str] = &[
            "kind",
            "session",
            "active_peers",
            "avenue",
            "bytes_down",
            "bytes_total",
            "bytes_up",
            "candidate_types",
            "count",
            "duration_ms",
            "error",
            "error_kind",
            "interval_ms",
            "knob",
            "latency_ms",
            "location",
            "message",
            "nat_traversal_ms",
            "peer_region",
            "prev_last_alive_ms",
            "prev_started_ms",
            "prev_version",
            "reason",
            "result",
            "selected_pair_type",
            "site",
            "slot",
            "slots_filled",
            // The *tracing* target (a module path like `spark_core::config`), NOT a network
            // destination. The name collision with the forbidden class is unfortunate; do not
            // repurpose this key, and do not read its presence as a leak.
            "target",
            "task",
            "total_helped",
            "source",
            "state",
            "value",
        ];

        let payload: Value = serde_json::from_slice(&encode_corpus()).expect("payload parses");
        let mut keys = Vec::new();
        collect_attribute_keys(&payload, &mut keys);
        assert!(!keys.is_empty(), "the walk must actually find keys");
        for key in keys {
            assert!(
                ALLOWED.contains(&key.as_str()) || ALLOWED_RESOURCE.contains(&key.as_str()),
                "uploaded payload carries an attribute key outside the closed set: {key:?} — if \
                 this is a new field, confirm it cannot carry a destination, client IP, resolver \
                 IP, or ConnectionID, then add it above"
            );
        }
    }

    /// Every `{"key": ...}` inside an `attributes` array, at any depth. Resource attributes are
    /// included on purpose: they are uploaded too.
    fn collect_attribute_keys(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::Object(map) => {
                for (k, child) in map {
                    if k == "key" {
                        if let Some(s) = child.as_str() {
                            out.push(s.to_string());
                        }
                    } else {
                        collect_attribute_keys(child, out);
                    }
                }
            }
            Value::Array(items) => items.iter().for_each(|i| collect_attribute_keys(i, out)),
            _ => {}
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
            error_unclean_exit(0, 0, "unknown"),
        ] {
            assert_eq!(ev.level, DiagLevel::Error, "kind {}", ev.kind);
        }
    }
}
