//! Hand-rolled OTLP/HTTP JSON **metrics** encoder for `/v1/metrics`.
//!
//! The client already hand-rolls the logs and spans signals (`core/src/diag/otlp.rs`) to avoid the
//! OTel SDK's dependency weight against a <3 MB budget. Metrics is the signal neither side had, and
//! it is encoded here rather than there because the server cannot depend on `core` — that crate is
//! the whole client tunnel, TUN included.
//!
//! OTLP/JSON-1.x rules observed here, matching the client encoder:
//! - 64-bit integers are encoded as **strings** (`"asInt": "42"`), not JSON numbers.
//! - `timeUnixNano` / `startTimeUnixNano` are strings of nanoseconds.
//!
//! Everything emitted is a cumulative monotonic `Sum` (`aggregationTemporality: 2`) sharing one
//! `startTimeUnixNano` fixed at process start. A backend reading cumulative sums computes rates from
//! successive points, so a dropped export costs resolution, never counts — which matters for a server
//! whose whole reason to exist is being reachable when the network is hostile.

use serde_json::{json, Value};

use crate::metrics::Snapshot;

/// AggregationTemporality::CUMULATIVE in the OTLP enum.
const CUMULATIVE: u8 = 2;

/// Identity of the emitting process, attached to every export.
///
/// Deliberately nothing that identifies a *deployment target*: no zone, no public IP, no hostname
/// derived from the delegated domain. `instance` is an operator-chosen opaque label so two servers
/// can be told apart on a dashboard without the label itself disclosing where either one lives.
pub struct ResourceAttrs {
    pub service_name: String,
    pub service_version: String,
    pub instance: String,
}

/// Encode one snapshot as an OTLP/JSON `/v1/metrics` request body.
pub fn encode_metrics(
    res: &ResourceAttrs,
    snap: &Snapshot,
    start_unix_nanos: u128,
    now_unix_nanos: u128,
) -> Vec<u8> {
    let mut metrics = Vec::new();

    let mut sum = |name: &str, unit: &str, value: u64| {
        metrics.push(build_sum(
            name,
            unit,
            &[(Vec::new(), value)],
            start_unix_nanos,
            now_unix_nanos,
        ));
    };

    sum("dnstunnel.server.queries", "1", snap.queries);
    sum("dnstunnel.server.answers", "1", snap.answers);
    sum("dnstunnel.server.streams_opened", "1", snap.streams_opened);
    sum(
        "dnstunnel.server.undecodable_targets",
        "1",
        snap.undecodable_targets,
    );
    sum("dnstunnel.server.backlog_drops", "1", snap.backlog_drops);
    sum(
        "dnstunnel.server.connect_timeouts",
        "1",
        snap.connect_timeouts,
    );
    sum("dnstunnel.server.sessions_swept", "1", snap.sessions_swept);
    sum("dnstunnel.server.bytes_uplink", "By", snap.bytes_uplink);
    sum("dnstunnel.server.bytes_downlink", "By", snap.bytes_downlink);

    // The one metric with attributes. `kind` comes from `metrics::kind_label`'s closed set, so the
    // series count here is bounded by that match arm's size regardless of what the network does.
    if !snap.connect_failures.is_empty() {
        let points: Vec<(Vec<(&str, &str)>, u64)> = snap
            .connect_failures
            .iter()
            .map(|(kind, n)| (vec![("kind", *kind)], *n))
            .collect();
        metrics.push(build_sum(
            "dnstunnel.server.egress_connect_failures",
            "1",
            &points,
            start_unix_nanos,
            now_unix_nanos,
        ));
    }

    let body = json!({
        "resourceMetrics": [{
            "resource": { "attributes": build_resource_attrs(res) },
            "scopeMetrics": [{
                "scope": { "name": "spark-dns-tunnel-server" },
                "metrics": metrics,
            }],
        }],
    });
    // Practically unreachable — `body` is a `Value` built from owned strings and integers, which has
    // no failing Serialize path. Logged rather than swallowed anyway: an empty body would POST as a
    // 4xx forever with no local signal, and a panic here would take the tunnel down for a telemetry
    // bug. Visible and harmless beats silent or fatal.
    serde_json::to_vec(&body).unwrap_or_else(|e| {
        tracing::error!(error = %e, "failed to encode OTLP metrics body");
        Vec::new()
    })
}

fn build_resource_attrs(res: &ResourceAttrs) -> Vec<Value> {
    vec![
        str_attr("service.name", &res.service_name),
        str_attr("service.version", &res.service_version),
        str_attr("service.instance.id", &res.instance),
    ]
}

fn str_attr(key: &str, value: &str) -> Value {
    json!({ "key": key, "value": { "stringValue": value } })
}

fn build_sum(
    name: &str,
    unit: &str,
    points: &[(Vec<(&str, &str)>, u64)],
    start_unix_nanos: u128,
    now_unix_nanos: u128,
) -> Value {
    let data_points: Vec<Value> = points
        .iter()
        .map(|(attrs, value)| {
            json!({
                "startTimeUnixNano": start_unix_nanos.to_string(),
                "timeUnixNano": now_unix_nanos.to_string(),
                // OTLP/JSON encodes 64-bit ints as strings.
                "asInt": value.to_string(),
                "attributes": attrs.iter().map(|(k, v)| str_attr(k, v)).collect::<Vec<_>>(),
            })
        })
        .collect();

    json!({
        "name": name,
        "unit": unit,
        "sum": {
            "aggregationTemporality": CUMULATIVE,
            "isMonotonic": true,
            "dataPoints": data_points,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn res() -> ResourceAttrs {
        ResourceAttrs {
            service_name: "spark-dns-tunnel-server".into(),
            service_version: "0.1.0".into(),
            instance: "dns-1".into(),
        }
    }

    fn parse(bytes: &[u8]) -> Value {
        serde_json::from_slice(bytes).expect("encoder must emit valid JSON")
    }

    #[test]
    fn envelope_shape_matches_otlp() {
        let body = encode_metrics(&res(), &Snapshot::default(), 1_000, 2_000);
        let v = parse(&body);
        let scope = &v["resourceMetrics"][0]["scopeMetrics"][0];
        assert_eq!(scope["scope"]["name"], "spark-dns-tunnel-server");
        assert!(scope["metrics"].as_array().is_some_and(|m| !m.is_empty()));
    }

    /// OTLP/JSON requires 64-bit integers as strings. A number here is accepted by some collectors
    /// and silently dropped by others, which is the worst possible failure for a telemetry path.
    #[test]
    fn integers_are_strings() {
        let snap = Snapshot {
            queries: 42,
            ..Default::default()
        };
        let body = encode_metrics(&res(), &snap, 1_000, 2_000);
        let v = parse(&body);
        let point =
            &v["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0]["sum"]["dataPoints"][0];
        assert_eq!(point["asInt"], "42");
        assert_eq!(point["timeUnixNano"], "2000");
        assert_eq!(point["startTimeUnixNano"], "1000");
    }

    #[test]
    fn sums_are_cumulative_and_monotonic() {
        let body = encode_metrics(&res(), &Snapshot::default(), 1_000, 2_000);
        let v = parse(&body);
        for m in v["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
            .as_array()
            .expect("metrics array")
        {
            assert_eq!(m["sum"]["aggregationTemporality"], 2, "{}", m["name"]);
            assert_eq!(m["sum"]["isMonotonic"], true, "{}", m["name"]);
        }
    }

    #[test]
    fn connect_failures_carry_their_kind() {
        let mut snap = Snapshot::default();
        snap.connect_failures.insert("connection_refused", 7);
        let body = encode_metrics(&res(), &snap, 1_000, 2_000);
        let v = parse(&body);
        let m = v["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
            .as_array()
            .expect("metrics array")
            .iter()
            .find(|m| m["name"] == "dnstunnel.server.egress_connect_failures")
            .expect("failures metric present when non-empty");
        let point = &m["sum"]["dataPoints"][0];
        assert_eq!(point["asInt"], "7");
        assert_eq!(point["attributes"][0]["key"], "kind");
        assert_eq!(
            point["attributes"][0]["value"]["stringValue"],
            "connection_refused"
        );
    }

    /// The hygiene rule as an executable check.
    ///
    /// Asserted as an **allow-list over emitted attribute values**, not a substring scan for scary
    /// words. A scan is both too weak and too strong: it cannot anticipate the shape of a leak (an
    /// arbitrary hostname matches no fixed list), and it fires on innocent metric *names* like
    /// `undecodable_targets`, which describes a counter and discloses nothing. The property that
    /// actually matters is that every `stringValue` in the payload comes from a set fixed at compile
    /// time — so a future `target` attribute fails here no matter what value it carries.
    #[test]
    fn every_emitted_attribute_value_is_from_a_closed_set() {
        let mut snap = Snapshot::default();
        snap.connect_failures.insert("host_unreachable", 1);
        snap.connect_failures.insert("connection_refused", 2);
        snap.queries = 5;
        let v = parse(&encode_metrics(&res(), &snap, 1_000, 2_000));

        let allowed = [
            // resource identity, all operator-chosen or compile-time
            "spark-dns-tunnel-server",
            "0.1.0",
            "dns-1",
            // the only keyed attribute: `metrics::kind_label`'s closed set
            "connection_refused",
            "connection_reset",
            "connection_aborted",
            "timed_out",
            "not_connected",
            "addr_not_available",
            "network_unreachable",
            "host_unreachable",
            "permission_denied",
            "invalid_input",
            "other",
        ];

        let mut found = Vec::new();
        collect_string_values(&v, &mut found);
        assert!(!found.is_empty(), "the walk must actually find values");
        for value in found {
            assert!(
                allowed.contains(&value.as_str()),
                "encoded metrics carry an attribute value outside the closed set: {value:?}"
            );
        }
    }

    /// Every `{"stringValue": ...}` anywhere in the payload, at any depth.
    fn collect_string_values(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::Object(map) => {
                for (k, child) in map {
                    if k == "stringValue" {
                        if let Some(s) = child.as_str() {
                            out.push(s.to_string());
                        }
                    } else {
                        collect_string_values(child, out);
                    }
                }
            }
            Value::Array(items) => items.iter().for_each(|i| collect_string_values(i, out)),
            _ => {}
        }
    }

    /// An empty failure map must not emit a zero-point series — an all-zero metric with no data
    /// points is a shape some backends reject outright.
    #[test]
    fn no_failure_series_when_there_are_no_failures() {
        let body = encode_metrics(&res(), &Snapshot::default(), 1_000, 2_000);
        let v = parse(&body);
        let has = v["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
            .as_array()
            .expect("metrics array")
            .iter()
            .any(|m| m["name"] == "dnstunnel.server.egress_connect_failures");
        assert!(!has);
    }
}
