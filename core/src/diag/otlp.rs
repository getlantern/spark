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

use std::collections::BTreeMap;

use serde_json::{json, Value};

use super::span::DiagSpan;
use super::{DiagEvent, DiagLevel};

/// An owned mirror of [`DiagEvent`] for spool replay: the live struct uses
/// `&'static str` for `component`/`kind` (a zero-alloc emit path), which cannot
/// `Deserialize` — spool lines re-enter as owned strings.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct SpoolEvent {
    pub ts: u64,
    pub level: DiagLevel,
    #[serde(default)]
    pub component: String,
    pub kind: String,
    #[serde(default)]
    pub session: Option<String>,
    #[serde(default)]
    pub fields: BTreeMap<String, Value>,
}

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
/// `trace_ctx`, when given as `Some((trace_id, span_id))`, is stamped on records whose
/// `session` is `Some` (log↔trace correlation, spec §C3a — spanId anchors the log to the
/// session's root span in the SigNoz waterfall). The `trace_id` bytes are formatted as 32
/// lowercase hex chars and `span_id` as 16 lowercase hex chars per OTLP/JSON spec.
pub fn encode_logs(
    res: &ResourceAttrs,
    events: &[DiagEvent],
    trace_ctx: Option<(&[u8; 16], &[u8; 8])>,
) -> Vec<u8> {
    let resource_attrs = build_resource_attrs(res);
    let log_records: Vec<Value> = events
        .iter()
        .map(|ev| build_log_record(ev, trace_ctx))
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
            } else if let Some(i) = n.as_i64() {
                // OTLP/JSON: 64-bit ints encoded as strings in intValue
                json!({ "intValue": i.to_string() })
            } else {
                // A u64 above i64::MAX doesn't fit OTLP's int64 `intValue`; ship it as
                // a string rather than risk the receiver rejecting the whole payload.
                json!({ "stringValue": n.to_string() })
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

fn build_log_record(ev: &DiagEvent, trace_ctx: Option<(&[u8; 16], &[u8; 8])>) -> Value {
    build_record(
        ev.ts,
        ev.level,
        ev.kind,
        ev.session.as_deref(),
        &ev.fields,
        trace_ctx,
    )
}

/// Encode spool-replayed events as one OTLP/HTTP JSON logs payload.
///
/// Unlike [`encode_logs`] (one trace context per batch), the context is looked up
/// **per record** via `ctx_for(session)`: a spool batch interleaves events from many
/// sessions, and OTLP stamps `traceId`/`spanId` per log record, so one payload can
/// carry them all.
pub fn encode_spool_logs<F>(res: &ResourceAttrs, events: &[SpoolEvent], mut ctx_for: F) -> Vec<u8>
where
    F: FnMut(&str) -> Option<([u8; 16], [u8; 8])>,
{
    let resource_attrs = build_resource_attrs(res);
    let log_records: Vec<Value> = events
        .iter()
        .map(|ev| {
            let ctx = ev.session.as_deref().and_then(&mut ctx_for);
            build_record(
                ev.ts,
                ev.level,
                &ev.kind,
                ev.session.as_deref(),
                &ev.fields,
                ctx.as_ref().map(|(t, s)| (t, s)),
            )
        })
        .collect();

    let payload = json!({
        "resourceLogs": [{
            "resource": { "attributes": resource_attrs },
            "scopeLogs": [{
                "scope": { "name": "spark-diag" },
                "logRecords": log_records
            }]
        }]
    });

    serde_json::to_vec(&payload).unwrap_or_else(|e| {
        tracing::debug!(err = %e, "diag: OTLP spool encoding failed");
        b"{}".to_vec()
    })
}

/// The shared log-record builder behind [`encode_logs`] (live `DiagEvent`s) and
/// [`encode_spool_logs`] (owned spool replays).
fn build_record(
    ts: u64,
    level: DiagLevel,
    kind: &str,
    session: Option<&str>,
    fields: &BTreeMap<String, Value>,
    trace_ctx: Option<(&[u8; 16], &[u8; 8])>,
) -> Value {
    // timeUnixNano: millis * 1_000_000, as a string
    let time_unix_nano = (ts as u128 * 1_000_000).to_string();
    // observedTimeUnixNano: time observed ≈ event time on-device; the server's receipt time
    // remains the trusted clock.
    let observed_time_unix_nano = time_unix_nano.clone();

    // body: for "log" kind, use the "message" field; otherwise the kind string
    let body_str = if kind == "log" {
        fields
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or(kind)
    } else {
        kind
    };

    // attributes: kind, session (when Some), then fields EXCEPT "message" when kind=="log"
    let mut attributes: Vec<Value> = Vec::new();
    attributes.push(json!({
        "key": "kind",
        "value": { "stringValue": kind }
    }));
    if let Some(session) = session {
        attributes.push(json!({
            "key": "session",
            "value": { "stringValue": session }
        }));
    }
    for (k, v) in fields {
        if kind == "log" && k == "message" {
            // Already used as body — skip
            continue;
        }
        // Omit Null fields — the pub fields map allows nulls but they carry no information
        if v.is_null() {
            continue;
        }
        attributes.push(json!({
            "key": k,
            "value": to_otlp_value(v)
        }));
    }

    let mut record = json!({
        "timeUnixNano": time_unix_nano,
        "observedTimeUnixNano": observed_time_unix_nano,
        "severityNumber": severity_number(level),
        "severityText": severity_text(level),
        "body": { "stringValue": body_str },
        "attributes": attributes
    });

    // traceId + spanId: stamped when both trace_ctx and session are present
    if let (Some((tid, sid)), Some(_)) = (trace_ctx, session) {
        record["traceId"] = Value::String(hex16(tid));
        record["spanId"] = Value::String(hex8(sid));
    }

    record
}

/// Encode finished spans as one OTLP/HTTP JSON traces payload.
///
/// Produces the OTLP/Traces JSON envelope accepted by SigNoz's `/v1/traces` endpoint:
/// `{"resourceSpans":[{"resource":{"attributes":[...]},"scopeSpans":[{"scope":{"name":"spark-diag"},"spans":[...]}]}]}`
///
/// Spans without an error carry no `status` field (OTLP interprets absence as OK).
/// Spans with `error: Some(msg)` carry `{"status":{"code":2,"message":msg}}` (code 2 =
/// STATUS_CODE_ERROR per the OTLP spec).
pub fn encode_spans(res: &ResourceAttrs, spans: &[DiagSpan]) -> Vec<u8> {
    let resource_attrs = build_resource_attrs(res);
    let span_objects: Vec<Value> = spans.iter().map(build_span_object).collect();

    let payload = json!({
        "resourceSpans": [{
            "resource": {
                "attributes": resource_attrs
            },
            "scopeSpans": [{
                "scope": { "name": "spark-diag" },
                "spans": span_objects
            }]
        }]
    });

    serde_json::to_vec(&payload).unwrap_or_else(|e| {
        tracing::debug!(err = %e, "diag: OTLP spans encoding failed");
        b"{}".to_vec()
    })
}

fn hex16(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex8(bytes: &[u8; 8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn build_span_object(span: &DiagSpan) -> Value {
    let mut obj = json!({
        "traceId": hex16(&span.trace_id),
        "spanId": hex8(&span.span_id),
        "name": span.name,
        // SPAN_KIND_INTERNAL = 1 (deliberate hand-coded spans only)
        "kind": 1,
        "startTimeUnixNano": span.start_unix_nano.to_string(),
        "endTimeUnixNano": span.end_unix_nano.to_string(),
        "attributes": build_span_attrs(&span.attrs)
    });

    if let Some(pid) = &span.parent_span_id {
        obj["parentSpanId"] = Value::String(hex8(pid));
    }

    // status: omit entirely for OK spans; set code=2 for errors.
    if let Some(msg) = &span.error {
        obj["status"] = json!({ "code": 2, "message": msg });
    }

    obj
}

fn build_span_attrs(attrs: &std::collections::BTreeMap<String, serde_json::Value>) -> Vec<Value> {
    attrs
        .iter()
        .filter(|(_, v)| !v.is_null())
        .map(|(k, v)| json!({ "key": k, "value": to_otlp_value(v) }))
        .collect()
}

// ---------------------------------------------------------------------------
// Tests (TDD: written before implementation was complete)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::diag::span::DiagSpan;
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
        let body = encode_logs(
            &res,
            std::slice::from_ref(&ev),
            Some((b"0123456789abcdef", b"01234567")),
        );
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
        assert_eq!(rec["spanId"], "3031323334353637");
        assert!(rec["observedTimeUnixNano"].as_str().unwrap().len() >= 18);
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
        let body = encode_logs(
            &res,
            std::slice::from_ref(&ev),
            None::<(&[u8; 16], &[u8; 8])>,
        );
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
        let body = encode_logs(
            &res,
            std::slice::from_ref(&ev),
            Some((b"0123456789abcdef", b"01234567")),
        );
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let rec = &v["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];
        assert!(
            rec.get("traceId").is_none() || rec["traceId"].is_null(),
            "traceId must be absent when session is None"
        );
        assert!(
            rec.get("spanId").is_none() || rec["spanId"].is_null(),
            "spanId must be absent when session is None"
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
        let body = encode_logs(
            &res,
            std::slice::from_ref(&ev),
            None::<(&[u8; 16], &[u8; 8])>,
        );
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

    #[test]
    fn u64_above_i64_max_falls_back_to_string_value() {
        // OTLP's intValue is an int64; a larger u64 must not be emitted there.
        let big = u64::MAX;
        let v = to_otlp_value(&serde_json::json!(big));
        assert!(v.get("intValue").is_none(), "must not overflow intValue");
        assert_eq!(v["stringValue"], big.to_string());
        // The i64 boundary itself still rides intValue.
        let edge = to_otlp_value(&serde_json::json!(i64::MAX as u64));
        assert_eq!(edge["intValue"], i64::MAX.to_string());
        // Negative ints ride intValue too.
        let neg = to_otlp_value(&serde_json::json!(-7));
        assert_eq!(neg["intValue"], "-7");
    }

    #[test]
    fn encodes_otlp_traces_envelope() {
        let res = test_res();

        // Span 1: no error, no parent.
        let mut attrs1 = BTreeMap::new();
        attrs1.insert("phase".to_string(), serde_json::json!("init"));
        let span1 = DiagSpan {
            trace_id: *b"0123456789abcdef",
            span_id: *b"01234567",
            parent_span_id: None,
            name: "unbounded.session",
            start_unix_nano: 1_700_000_000_000_000_000,
            end_unix_nano: 1_700_000_000_500_000_000,
            error: None,
            attrs: attrs1,
        };

        // Span 2: with error, with parent.
        let span2 = DiagSpan {
            trace_id: *b"0123456789abcdef",
            span_id: *b"89abcdef",
            parent_span_id: Some(*b"01234567"),
            name: "signaling",
            start_unix_nano: 1_700_000_000_100_000_000,
            end_unix_nano: 1_700_000_000_200_000_000,
            error: Some("boom".to_string()),
            attrs: BTreeMap::new(),
        };

        let body = encode_spans(&res, &[span1, span2]);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // Resource attributes
        let attrs = &v["resourceSpans"][0]["resource"]["attributes"];
        let find = |k: &str| {
            attrs
                .as_array()
                .unwrap()
                .iter()
                .find(|a| a["key"] == k)
                .map(|a| a["value"]["stringValue"].clone())
        };
        assert_eq!(find("service.name").unwrap(), "spark");

        let spans = v["resourceSpans"][0]["scopeSpans"][0]["spans"]
            .as_array()
            .unwrap();
        assert_eq!(spans.len(), 2);

        // Span 1 assertions
        let s1 = &spans[0];
        assert_eq!(s1["traceId"], "30313233343536373839616263646566");
        assert_eq!(s1["spanId"], "3031323334353637");
        assert!(
            s1.get("parentSpanId").is_none() || s1["parentSpanId"].is_null(),
            "root span must have no parentSpanId"
        );
        assert_eq!(s1["kind"], 1);
        assert_eq!(s1["startTimeUnixNano"], "1700000000000000000");
        assert_eq!(s1["endTimeUnixNano"], "1700000000500000000");
        // Attributes present
        let sa1 = s1["attributes"].as_array().unwrap();
        assert!(
            sa1.iter().any(|a| a["key"] == "phase"),
            "phase attr must be present"
        );
        // status ABSENT for no-error span
        assert!(
            s1.get("status").is_none() || s1["status"].is_null(),
            "status must be absent for an OK span"
        );

        // Span 2 assertions — parentSpanId is the hex of b"01234567" (span1's spanId)
        let s2 = &spans[1];
        assert_eq!(s2["parentSpanId"], "3031323334353637");
        assert_eq!(s2["status"]["code"], 2);
        assert_eq!(s2["status"]["message"], "boom");
    }

    #[test]
    fn null_fields_are_omitted() {
        let res = test_res();
        let mut ev = DiagEvent::new(DiagLevel::Info, "app", "test.null_field");
        ev.fields.insert("present".into(), serde_json::json!("yes"));
        ev.fields.insert("absent".into(), serde_json::Value::Null);
        let body = encode_logs(
            &res,
            std::slice::from_ref(&ev),
            None::<(&[u8; 16], &[u8; 8])>,
        );
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let rec = &v["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];
        let ra = rec["attributes"].as_array().unwrap();
        assert!(
            ra.iter().any(|a| a["key"] == "present"),
            "non-null field must appear"
        );
        assert!(
            !ra.iter().any(|a| a["key"] == "absent"),
            "null field must be omitted"
        );
    }
}
