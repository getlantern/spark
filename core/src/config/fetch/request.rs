//! The `config-new` request: the JSON body (`ConfigRequest`) + the HTTP request bytes (request line,
//! `X-Lantern-*` + conditional headers, body). Mirrors radiance `common.ConfigRequest` + headers.go.

use flint_fronted::OneshotRequest;
use serde::Serialize;

/// Free-tier `config-new` request body. `user_id`/`pro_token`/`wg_public_key` are intentionally
/// absent in v1. `backend = "sing-box"` so the API returns the `config_raw.json` shape the adapter
/// reads; `protocols` lists only the kinds the adapter maps, so we don't get unusable outbounds.
///
/// `time_zone` rides the `X-Lantern-Time-Zone` **header**, not the JSON body, so it is `#[serde(skip)]`.
#[derive(Debug, Clone, Serialize)]
pub struct ConfigRequest {
    pub device_id: String,
    /// Lantern account id (decimal string). config-new requires it — the server `ParseInt`s it, and an
    /// absent value is a 400. `"0"` is the anonymous placeholder; the real id comes from `/user-create`
    /// (see `super::user`). Always serialized.
    pub user_id: String,
    /// The universal token config-new requires (minted by `/user-create`; "pro" is a misnomer — free
    /// clients get one too). Omitted from the body when empty (matches the server's `omitempty`).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub pro_token: String,
    pub platform: String,
    pub app_name: String,
    pub backend: String,
    pub singbox_version: String,
    pub version: String,
    pub locale: String,
    pub protocols: Vec<String>,
    #[serde(skip)]
    pub time_zone: String,
}

/// Map Rust's `std::env::consts::OS` to the Lantern/Go platform convention (`runtime.GOOS`): macOS is
/// `"darwin"` there, not `"macos"`. The server keys outbound selection on this, so it must match.
fn lantern_platform(os: &str) -> &str {
    match os {
        "macos" => "darwin",
        other => other,
    }
}

/// The `X-Lantern-App` / `app_name` value. We identify as `lantern` (matching radiance) so the API
/// accepts the request and `/user-create` mints a valid token — the server keys on a known app. If
/// Spark ever registers its own app identity server-side, change this in one place.
pub(crate) const APP_NAME: &str = "lantern";

/// The client version reported to the API (`X-Lantern-{App-,}Version` + the body `version`). config-new
/// enforces a minimum ("bad client factors: version … too old"), so this is a recent Lantern version,
/// NOT spark-core's `CARGO_PKG_VERSION` (0.1.0, which the server rejects). Bump when the server raises
/// its floor. (Spark presents as a Lantern client; see [`APP_NAME`].)
pub(crate) const LANTERN_VERSION: &str = "9.1.13";

/// This build's platform string in the Lantern convention (`darwin`/`linux`/…). Shared by the
/// config-new request and the `/user-create` pre-step.
pub(crate) fn platform() -> &'static str {
    lantern_platform(std::env::consts::OS)
}

impl ConfigRequest {
    /// The free-tier default request for this build.
    pub fn new(device_id: String) -> Self {
        ConfigRequest {
            device_id,
            user_id: "0".to_string(), // anonymous placeholder; real id set from /user-create
            pro_token: String::new(), // set from /user-create before the fetch
            platform: platform().to_string(),
            app_name: APP_NAME.to_string(),
            backend: "sing-box".to_string(),
            singbox_version: "1.11.0".to_string(),
            version: LANTERN_VERSION.to_string(),
            locale: "en-US".to_string(),
            protocols: vec![
                "samizdat".to_string(),
                "hysteria2".to_string(),
                "shadowsocks".to_string(),
            ],
            time_zone: local_timezone(),
        }
    }
}

/// Best-effort IANA time zone (e.g. `"America/New_York"`) for the `X-Lantern-Time-Zone` header. Reads
/// the `/etc/localtime` symlink target on Unix (covers macOS + Linux — where Spark runs) and slices
/// after `zoneinfo/`; falls back to `"UTC"`. Std-only, no tz/chrono dependency (locked stack).
pub fn local_timezone() -> String {
    #[cfg(unix)]
    {
        if let Ok(target) = std::fs::read_link("/etc/localtime") {
            let s = target.to_string_lossy();
            if let Some(idx) = s.rfind("zoneinfo/") {
                let tz = &s[idx + "zoneinfo/".len()..];
                if !tz.is_empty() {
                    return tz.to_string();
                }
            }
        }
    }
    "UTC".to_string()
}

/// Conditional-fetch state from the cache: the prior `ETag` and `Last-Modified` (RFC1123).
#[derive(Debug, Clone, Default)]
pub struct Conditional {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

/// Strip CR/LF from a value before it's interpolated into a header line, so a tampered/corrupt
/// non-constant source (the on-disk device id, the env-derived timezone, or a cached server-origin
/// `ETag`/`Last-Modified`) can't inject extra headers or break request framing. Borrows when clean.
fn header_safe(v: &str) -> std::borrow::Cow<'_, str> {
    if v.contains(['\r', '\n']) {
        std::borrow::Cow::Owned(v.replace(['\r', '\n'], ""))
    } else {
        std::borrow::Cow::Borrowed(v)
    }
}

/// Build the full HTTP/1.1 request bytes for `POST {path}` to `host` with `body_json`.
///
/// Headers mirror radiance `common/headers.go`. `X-Lantern-Time-Zone` carries `req.time_zone` (the
/// real IANA zone via [`local_timezone`], `UTC` fallback). `X-Lantern-Rand` (0–300 random padding
/// chars) is **intentionally deferred**: its only purpose is request-size padding for traffic-analysis
/// resistance, which matters on the fronted/censored path (design §9, a later milestone), not on a
/// plain direct TLS fetch. Adding it now would also make these bytes non-deterministic to test.
pub fn build_request_bytes(
    host: &str,
    path: &str,
    req: &ConfigRequest,
    cond: &Conditional,
) -> Result<Vec<u8>, serde_json::Error> {
    let body = serde_json::to_vec(req)?;
    let mut head = String::new();
    head.push_str(&format!("POST {path} HTTP/1.1\r\n"));
    head.push_str(&format!("Host: {host}\r\n"));
    head.push_str(&format!("X-Lantern-App: {APP_NAME}\r\n"));
    head.push_str(&format!("X-Lantern-App-Version: {}\r\n", req.version));
    head.push_str(&format!("X-Lantern-Version: {}\r\n", req.version));
    head.push_str(&format!("X-Lantern-Platform: {}\r\n", req.platform));
    // `device_id` (read from a writable file) and `time_zone` (derived from the `/etc/localtime`
    // symlink) are not compile-time constants like the other values, so strip CR/LF in case a
    // tampered/corrupt source smuggles a newline — same guard as the cached server headers below.
    head.push_str(&format!(
        "X-Lantern-Device-Id: {}\r\n",
        header_safe(&req.device_id)
    ));
    // user_id is decimal-digits (or "0"); header-safe is belt-and-suspenders. (pro_token rides the
    // body only — radiance sends no X-Lantern-Pro-Token header for config-new.)
    head.push_str(&format!(
        "X-Lantern-User-Id: {}\r\n",
        header_safe(&req.user_id)
    ));
    head.push_str(&format!(
        "X-Lantern-Time-Zone: {}\r\n",
        header_safe(&req.time_zone)
    ));
    head.push_str("Content-Type: application/json\r\n");
    head.push_str("Cache-Control: no-cache\r\n");
    if let Some(etag) = &cond.etag {
        head.push_str(&format!("If-None-Match: {}\r\n", header_safe(etag)));
    }
    if let Some(lm) = &cond.last_modified {
        head.push_str(&format!("If-Modified-Since: {}\r\n", header_safe(lm)));
    }
    head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    head.push_str("Connection: close\r\n\r\n");
    let mut out = head.into_bytes();
    out.extend_from_slice(&body);
    Ok(out)
}

/// Build the one-shot fronted request for the h2 path — the same `X-Lantern-*` + conditional headers
/// and JSON body as [`build_request_bytes`], minus the bits h2 owns: the `Host`/`:authority` is set
/// from the connection's fronted host, and `Content-Length`/`Connection` are managed by h2, so they
/// are omitted here. Kept in lockstep with [`build_request_bytes`] so the direct and fronted requests
/// carry identical application headers.
pub fn build_oneshot_request(
    path: &str,
    req: &ConfigRequest,
    cond: &Conditional,
) -> Result<OneshotRequest, serde_json::Error> {
    let body = serde_json::to_vec(req)?;
    let mut out = OneshotRequest::post(path.to_owned(), body)
        .header("X-Lantern-App", APP_NAME)
        .header("X-Lantern-App-Version", req.version.clone())
        .header("X-Lantern-Version", req.version.clone())
        .header("X-Lantern-Platform", req.platform.clone())
        .header(
            "X-Lantern-Device-Id",
            header_safe(&req.device_id).into_owned(),
        )
        .header("X-Lantern-User-Id", header_safe(&req.user_id).into_owned())
        .header(
            "X-Lantern-Time-Zone",
            header_safe(&req.time_zone).into_owned(),
        )
        .header("Content-Type", "application/json")
        .header("Cache-Control", "no-cache");
    if let Some(etag) = &cond.etag {
        out = out.header("If-None-Match", header_safe(etag).into_owned());
    }
    if let Some(lm) = &cond.last_modified {
        out = out.header("If-Modified-Since", header_safe(lm).into_owned());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_has_required_fields_and_anonymous_creds() {
        let req = ConfigRequest::new("dev-123".into());
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"device_id\":\"dev-123\""));
        assert!(json.contains("\"backend\":\"sing-box\""));
        assert!(json.contains("\"app_name\":\"lantern\""));
        assert!(json.contains("samizdat") && json.contains("hysteria2"));
        // config-new requires user_id (server ParseInts it); "0" is the anonymous placeholder.
        assert!(json.contains("\"user_id\":\"0\""));
        // An empty pro_token is omitted from the body (matches the server's omitempty).
        assert!(
            !json.contains("pro_token"),
            "empty pro_token must be omitted"
        );
        assert!(
            !json.contains("time_zone"),
            "time_zone is a header, not a body field"
        );
    }

    #[test]
    fn body_includes_pro_token_when_set() {
        let mut req = ConfigRequest::new("d".into());
        req.user_id = "388687521".into();
        req.pro_token = "tok-abc".into();
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"user_id\":\"388687521\""));
        assert!(json.contains("\"pro_token\":\"tok-abc\""));
    }

    #[test]
    fn local_timezone_returns_nonempty() {
        // Real value is environment-dependent; just assert it produces something usable.
        assert!(!local_timezone().is_empty());
    }

    #[test]
    fn request_bytes_have_method_headers_conditional_and_body() {
        let mut req = ConfigRequest::new("dev-123".into());
        req.time_zone = "America/New_York".into(); // pin for a deterministic header assertion
        let cond = Conditional {
            etag: Some("\"abc\"".into()),
            last_modified: Some("Mon, 01 Jan 2024 00:00:00 GMT".into()),
        };
        let bytes = build_request_bytes("df.iantem.io", "/api/v1/config-new", &req, &cond).unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.starts_with("POST /api/v1/config-new HTTP/1.1\r\n"));
        assert!(s.contains("Host: df.iantem.io\r\n"));
        assert!(s.contains("X-Lantern-App: lantern\r\n"));
        assert!(s.contains("X-Lantern-Device-Id: dev-123\r\n"));
        assert!(s.contains("X-Lantern-User-Id: 0\r\n")); // anonymous placeholder by default
        assert!(s.contains("X-Lantern-Time-Zone: America/New_York\r\n"));
        assert!(
            !s.contains("X-Lantern-Rand"),
            "Rand is deferred to the fronting milestone"
        );
        assert!(s.contains("Content-Type: application/json\r\n"));
        assert!(s.contains("If-None-Match: \"abc\"\r\n"));
        assert!(s.contains("If-Modified-Since: Mon, 01 Jan 2024 00:00:00 GMT\r\n"));
        // Content-Length matches the JSON body that follows the blank line.
        let (head, body) = s.split_once("\r\n\r\n").unwrap();
        assert!(head.contains(&format!("Content-Length: {}", body.len())));
        assert!(body.contains("\"device_id\":\"dev-123\""));
    }

    #[test]
    fn omits_conditional_headers_when_absent() {
        let req = ConfigRequest::new("d".into());
        let s = String::from_utf8(
            build_request_bytes("h", "/p", &req, &Conditional::default()).unwrap(),
        )
        .unwrap();
        assert!(!s.contains("If-None-Match") && !s.contains("If-Modified-Since"));
    }

    #[test]
    fn lantern_platform_maps_macos_to_darwin() {
        assert_eq!(lantern_platform("macos"), "darwin");
        assert_eq!(lantern_platform("linux"), "linux");
        assert_eq!(lantern_platform("windows"), "windows");
        assert_eq!(lantern_platform("ios"), "ios");
    }

    #[test]
    fn conditional_header_values_are_crlf_stripped() {
        let req = ConfigRequest::new("d".into());
        let cond = Conditional {
            etag: Some("\"e\"\r\nX-Injected: 1".into()),
            last_modified: None,
        };
        let s = String::from_utf8(build_request_bytes("h", "/p", &req, &cond).unwrap()).unwrap();
        // CRLF stripped: X-Injected must NOT appear as its own header line.
        assert!(
            !s.contains("\r\nX-Injected:"),
            "CRLF in ETag must not inject a header"
        );
        assert!(s.contains("If-None-Match: \"e\"X-Injected: 1\r\n"));
    }

    #[test]
    fn identity_header_values_are_crlf_stripped() {
        // A tampered on-disk device id (or env-derived timezone) carrying CRLF must not inject a header.
        let mut req = ConfigRequest::new("dev\r\nX-Evil: 1".into());
        req.time_zone = "Zone\r\nX-Evil2: 2".into();
        let s = String::from_utf8(
            build_request_bytes("h", "/p", &req, &Conditional::default()).unwrap(),
        )
        .unwrap();
        assert!(
            !s.contains("\r\nX-Evil:"),
            "CRLF in device_id must not inject a header"
        );
        assert!(
            !s.contains("\r\nX-Evil2:"),
            "CRLF in time_zone must not inject a header"
        );
        assert!(s.contains("X-Lantern-Device-Id: devX-Evil: 1\r\n"));
        assert!(s.contains("X-Lantern-Time-Zone: ZoneX-Evil2: 2\r\n"));
    }

    #[test]
    fn oneshot_request_carries_lantern_headers_and_body() {
        // The fronted one-shot request must carry the same application headers + JSON body as the
        // direct HTTP/1.1 request, minus the h2-owned Host/Content-Length/Connection.
        let mut req = ConfigRequest::new("dev123".into());
        req.user_id = "42".into();
        let cond = Conditional {
            etag: Some("\"v1\"".into()),
            last_modified: None,
        };
        let os = build_oneshot_request("/api/v1/config-new", &req, &cond).unwrap();
        assert_eq!(os.method.as_str(), "POST");
        assert_eq!(os.path, "/api/v1/config-new");
        let has = |k: &str, v: &str| os.headers.iter().any(|(hk, hv)| hk == k && hv == v);
        assert!(has("X-Lantern-App", "lantern"));
        assert!(has("X-Lantern-Device-Id", "dev123"));
        assert!(has("X-Lantern-User-Id", "42"));
        assert!(has("Content-Type", "application/json"));
        assert!(has("If-None-Match", "\"v1\""));
        // No Host/Content-Length/Connection — h2 owns those.
        assert!(!os
            .headers
            .iter()
            .any(|(k, _)| ["host", "content-length", "connection"]
                .contains(&k.to_ascii_lowercase().as_str())));
        assert_eq!(
            os.body.as_ref(),
            serde_json::to_vec(&req).unwrap().as_slice()
        );
    }

    #[test]
    fn oneshot_request_omits_conditional_headers_when_absent() {
        let req = ConfigRequest::new("d".into());
        let os = build_oneshot_request("/p", &req, &Conditional::default()).unwrap();
        assert!(!os
            .headers
            .iter()
            .any(|(k, _)| k == "If-None-Match" || k == "If-Modified-Since"));
    }
}
