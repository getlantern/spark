//! Hand-rolled OTLP/HTTP JSON logs encoder (design §C3).
//!
//! Produces the OTLP/Logs JSON envelope accepted by SigNoz's `/v1/logs` endpoint.
//! No OTel SDK, no new deps beyond `serde_json`.
//!
//! # Wire format
//! `{"resourceLogs":[{"resource":{"attributes":[...]},"scopeLogs":[{"scope":{"name":"spark-diag"},"logRecords":[...]}]}]}`
//!
//! OTLP/JSON-1.x rules used here:
//! - 64-bit integers are encoded as **strings** in `intValue`.
//! - `timeUnixNano` is a string of nanoseconds.
//! - `traceId` = 32 lowercase hex chars; `spanId` = 16 lowercase hex chars.

use serde_json::{json, Value};

use super::{DiagEvent, DiagLevel};

/// Resource-level identity attached to every batch (getlantern/semconv names; the
/// version/build fields are what make per-build fleet queries possible).
#[derive(Debug, Clone)]
pub struct ResourceAttrs {
    /// `service.version`
    pub service_version: String,
    /// `spark.git_sha`
    pub git_sha: String,
    /// `client.device_id`
    pub device_id: String,
    /// `client.platform` (lantern convention, e.g. "darwin")
    pub platform: String,
    /// `geo.country.iso_code` (from the config response)
    pub country: String,
    /// `deployment.environment.name` ("prod"/"staging")
    pub environment: String,
    /// `spark.component` ("app"/"tunnel")
    pub component: String,
    /// `os.name`
    pub os_name: String,
    /// `os.version`
    pub os_version: String,
    /// `host.arch`
    pub arch: String,
}

/// Encode events as one OTLP/HTTP JSON logs payload.
///
/// `trace_id`, when given, is stamped on records whose `session` is `Some`
/// (log↔trace correlation, spec §C3a). The `trace_id` bytes are formatted as
/// 32 lowercase hex chars per OTLP/JSON spec.
pub fn encode_logs(
    res: &ResourceAttrs,
    events: &[DiagEvent],
    trace_id: Option<&[u8; 16]>,
) -> Vec<u8> {
    let resource_attrs = build_resource_attrs(res);
    let log_records: Vec<Value> = events
        .iter()
        .map(|ev| build_log_record(ev, trace_id))
        .collect();

    let payload = json!({
        "resourceLogs": [{
            "resource": {
                "attributes": resource_attrs
            },
            "scopeLogs": [{
                "scope": { "name": "spark-diag" },
                "logRecords": log_records
            }]
        }]
    });

    serde_json::to_vec(&payload).unwrap_or_else(|e| {
        tracing::debug!(err = %e, "diag: OTLP encoding failed");
        b"{}".to_vec()
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn str_attr(key: &str, value: &str) -> Value {
    json!({ "key": key, "value": { "stringValue": value } })
}

fn build_resource_attrs(res: &ResourceAttrs) -> Vec<Value> {
    vec![
        str_attr("service.name", "spark"),
        str_attr("service.version", &res.service_version),
        str_attr("spark.git_sha", &res.git_sha),
        str_attr("client.device_id", &res.device_id),
        str_attr("client.platform", &res.platform),
        str_attr("geo.country.iso_code", &res.country),
        str_attr("deployment.environment.name", &res.environment),
        str_attr("spark.component", &res.component),
        str_attr("os.name", &res.os_name),
        str_attr("os.version", &res.os_version),
        str_attr("host.arch", &res.arch),
    ]
}

fn severity_number(level: DiagLevel) -> u8 {
    match level {
        DiagLevel::Debug => 5,
        DiagLevel::Info => 9,
        DiagLevel::Warn => 13,
        DiagLevel::Error => 17,
    }
}

fn severity_text(level: DiagLevel) -> &'static str {
    match level {
        DiagLevel::Debug => "DEBUG",
        DiagLevel::Info => "INFO",
        DiagLevel::Warn => "WARN",
        DiagLevel::Error => "ERROR",
    }
}

/// Convert a `serde_json::Value` field into an OTLP attribute value object.
fn to_otlp_value(v: &Value) -> Value {
    match v {
        Value::String(s) => json!({ "stringValue": s }),
        Value::Number(n) => {
            if n.is_f64() {
                json!({ "doubleValue": n })
            } else {
                // OTLP/JSON: 64-bit ints encoded as strings in intValue
                json!({ "intValue": n.to_string() })
            }
        }
        Value::Bool(b) => json!({ "boolValue": b }),
        Value::Array(arr) => {
            // Map to arrayValue; each element treated as stringValue (spec: arrays of strings)
            let values: Vec<Value> = arr
                .iter()
                .map(|item| json!({ "stringValue": item.as_str().unwrap_or(&item.to_string()) }))
                .collect();
            json!({ "arrayValue": { "values": values } })
        }
        other => json!({ "stringValue": other.to_string() }),
    }
}

fn build_log_record(ev: &DiagEvent, trace_id: Option<&[u8; 16]>) -> Value {
    // timeUnixNano: millis * 1_000_000, as a string
    let time_unix_nano = (ev.ts as u128 * 1_000_000).to_string();

    // body: for "log" kind, use the "message" field; otherwise the kind string
    let body_str = if ev.kind == "log" {
        ev.fields
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or(ev.kind)
    } else {
        ev.kind
    };

    // attributes: kind, session (when Some), then fields EXCEPT "message" when kind=="log"
    let mut attributes: Vec<Value> = Vec::new();
    attributes.push(json!({
        "key": "kind",
        "value": { "stringValue": ev.kind }
    }));
    if let Some(session) = &ev.session {
        attributes.push(json!({
            "key": "session",
            "value": { "stringValue": session }
        }));
    }
    for (k, v) in &ev.fields {
        if ev.kind == "log" && k == "message" {
            // Already used as body — skip
            continue;
        }
        attributes.push(json!({
            "key": k,
            "value": to_otlp_value(v)
        }));
    }

    let mut record = json!({
        "timeUnixNano": time_unix_nano,
        "severityNumber": severity_number(ev.level),
        "severityText": severity_text(ev.level),
        "body": { "stringValue": body_str },
        "attributes": attributes
    });

    // traceId: stamped when both trace_id and session are present
    if let (Some(tid), Some(_)) = (trace_id, &ev.session) {
        let hex: String = tid.iter().map(|b| format!("{b:02x}")).collect();
        record["traceId"] = Value::String(hex);
    }

    record
}

// ---------------------------------------------------------------------------
// Tests (TDD: written before implementation was complete)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diag::{events, DiagLevel};

    fn test_res() -> ResourceAttrs {
        ResourceAttrs {
            service_version: "0.3.0".into(),
            git_sha: "abc1234".into(),
            device_id: "d3adb33f".into(),
            platform: "darwin".into(),
            country: "US".into(),
            environment: "prod".into(),
            component: "app".into(),
            os_name: "macOS".into(),
            os_version: "14.5".into(),
            arch: "arm64".into(),
        }
    }

    #[test]
    fn encodes_otlp_logs_envelope() {
        let res = test_res();
        let mut ev = DiagEvent::new(DiagLevel::Warn, "app", "unbounded.geo_failed");
        ev.session = Some("s1".into());
        ev.fields.insert("reason".into(), "timeout".into());
        let body = encode_logs(&res, std::slice::from_ref(&ev), Some(b"0123456789abcdef"));
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let attrs = &v["resourceLogs"][0]["resource"]["attributes"];
        let find = |k: &str| {
            attrs
                .as_array()
                .unwrap()
                .iter()
                .find(|a| a["key"] == k)
                .map(|a| a["value"]["stringValue"].clone())
        };
        assert_eq!(find("service.name").unwrap(), "spark");
        assert_eq!(find("service.version").unwrap(), "0.3.0");
        assert_eq!(find("client.device_id").unwrap(), "d3adb33f");
        assert_eq!(find("geo.country.iso_code").unwrap(), "US");
        assert_eq!(find("spark.git_sha").unwrap(), "abc1234");
        let rec = &v["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];
        assert_eq!(rec["severityText"], "WARN");
        assert_eq!(rec["severityNumber"], 13);
        assert_eq!(rec["body"]["stringValue"], "unbounded.geo_failed");
        assert_eq!(rec["traceId"], "30313233343536373839616263646566");
        let ra = rec["attributes"].as_array().unwrap();
        assert!(ra.iter().any(|a| a["key"] == "kind"));
        assert!(ra.iter().any(|a| a["key"] == "session"));
        assert!(ra.iter().any(|a| a["key"] == "reason"));
        assert!(rec["timeUnixNano"].as_str().unwrap().len() >= 18);
    }

    #[test]
    fn log_kind_uses_message_as_body_and_drops_dup_attr() {
        let res = test_res();
        let ev = events::log(DiagLevel::Info, "hello world", "spark_core::x");
        let body = encode_logs(&res, std::slice::from_ref(&ev), None);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let rec = &v["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];
        // body comes from the message field
        assert_eq!(rec["body"]["stringValue"], "hello world");
        // severityNumber for Info
        assert_eq!(rec["severityNumber"], 9);
        // "message" key must NOT appear in attributes (it is the body already)
        let ra = rec["attributes"].as_array().unwrap();
        assert!(
            !ra.iter().any(|a| a["key"] == "message"),
            "message must not be duplicated in attributes"
        );
    }

    #[test]
    fn no_trace_id_when_session_absent() {
        let res = test_res();
        let ev = DiagEvent::new(DiagLevel::Info, "app", "unbounded.attempt_started");
        // session is None (default)
        let body = encode_logs(&res, std::slice::from_ref(&ev), Some(b"0123456789abcdef"));
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let rec = &v["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];
        assert!(
            rec.get("traceId").is_none() || rec["traceId"].is_null(),
            "traceId must be absent when session is None"
        );
    }

    #[test]
    fn value_type_mapping() {
        let res = test_res();
        let mut ev = DiagEvent::new(DiagLevel::Debug, "app", "test.type_mapping");
        ev.fields.insert("count".into(), serde_json::json!(42u64));
        ev.fields.insert("enabled".into(), serde_json::json!(true));
        ev.fields.insert("ratio".into(), serde_json::json!(1.5f64));
        ev.fields
            .insert("tags".into(), serde_json::json!(["alpha", "beta"]));
        let body = encode_logs(&res, std::slice::from_ref(&ev), None);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let rec = &v["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];
        let ra = rec["attributes"].as_array().unwrap();

        let find_attr = |key: &str| -> Option<&Value> {
            ra.iter().find(|a| a["key"] == key).map(|a| &a["value"])
        };

        // int -> intValue as string "42"
        let count_val = find_attr("count").expect("count attr missing");
        assert_eq!(
            count_val["intValue"], "42",
            "int must be string-encoded in intValue"
        );

        // bool -> boolValue
        let enabled_val = find_attr("enabled").expect("enabled attr missing");
        assert_eq!(enabled_val["boolValue"], true);

        // float -> doubleValue
        let ratio_val = find_attr("ratio").expect("ratio attr missing");
        assert!(
            ratio_val["doubleValue"].as_f64().is_some(),
            "float must be doubleValue"
        );

        // array of strings -> arrayValue of stringValues
        let tags_val = find_attr("tags").expect("tags attr missing");
        let arr_vals = tags_val["arrayValue"]["values"]
            .as_array()
            .expect("arrayValue.values must be an array");
        assert_eq!(arr_vals[0]["stringValue"], "alpha");
        assert_eq!(arr_vals[1]["stringValue"], "beta");
    }
}
