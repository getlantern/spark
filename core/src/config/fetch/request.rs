//! The `config-new` request: the JSON body (`ConfigRequest`) + the HTTP request bytes (request line,
//! `X-Lantern-*` + conditional headers, body). Mirrors radiance `common.ConfigRequest` + headers.go.

use std::borrow::Cow;

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
    /// Optional client behaviours the server can gate on (`common.Capability*` in lantern-cloud's
    /// shared types) — capability negotiation instead of version sniffing.
    ///
    /// Spark advertises only what it actually honours. `non_selectable_outbounds`, for instance, is
    /// deliberately absent: nothing here consumes `NonSelectableOutbounds`, and claiming it would
    /// invite the server to send infrastructure outbounds this client would then surface as
    /// selectable proxies.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    /// Transport-module bundles this client already holds, as `engine → bundle version`, so the
    /// server can omit bytes it would otherwise re-send.
    ///
    /// Without this, an inline module rides *every* config fetch that offers it — and the config body
    /// changes on every bandit reassignment, so the existing whole-body `ETag` almost never spares it.
    /// Declaring what we hold turns a per-fetch cost into a one-time one.
    ///
    /// The **version**, not a hash: the bundle store already persists exactly this, and the signature
    /// is what authenticates the bytes, so a hash would be a second identity for one thing (see
    /// `engine/store.rs`, which keys on name for the same reason).
    ///
    /// This is a **hint, never authorization**. If the server takes it at its word and the store turns
    /// out not to hold the engine, that pool member is skipped like any other un-buildable one — a
    /// client that lies only degrades itself. Omitted when empty, so a build without `wasm-transport`
    /// (or a client holding nothing) sends exactly what it sent before.
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub modules: std::collections::BTreeMap<String, u32>,
    #[serde(skip)]
    pub time_zone: String,
}

/// Map Rust's `std::env::consts::OS` to the Lantern/Go platform convention (`runtime.GOOS`): macOS is
/// `"darwin"` there, not `"macos"`. The server keys outbound selection on this, so it must match.
/// `pub(crate)`: `diag::tunnel_host` stamps the same convention on its OTLP resource attrs.
pub(crate) fn lantern_platform(os: &str) -> &str {
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
///
/// `9.2.0` is also the floor for the `meek_0.0.1` protocol: the config server only assigns meek tracks
/// to clients reporting `>= 9.2.0`, so advertising `"meek"` below this version would never get one.
pub(crate) const LANTERN_VERSION: &str = "9.2.0";

/// The server-side token for "this client can install and run a signed transport-module bundle
/// delivered in its config" (`common.CapabilityTransportModules`). The string is the wire contract —
/// it must match the Go constant exactly, so it lives in one named place here rather than inline.
#[cfg(feature = "wasm-transport")]
const CAPABILITY_TRANSPORT_MODULES: &str = "transport_modules";

/// What this build can actually do, for [`ConfigRequest::capabilities`].
///
/// Advertising module support cannot be inferred from `modules`: that field is omitted when empty, so
/// a client that supports delivery but holds nothing yet is byte-identical on the wire to one that
/// cannot use modules at all. Without this token the server has to guess, and both guesses are bad —
/// never bootstrap a client's first module, or send every client a module-bearing outbound it will
/// silently skip, with the module's bytes (the expensive part) attached.
fn capabilities() -> Vec<String> {
    #[allow(unused_mut)]
    let mut caps = Vec::new();
    #[cfg(feature = "wasm-transport")]
    caps.push(CAPABILITY_TRANSPORT_MODULES.to_string());
    caps
}

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
                "meek".to_string(),
                // Advertises Unbounded-volunteer capability. The config server emits the top-level
                // `unbounded` block (egress_addr/discovery_srv — what the sharing pool dials) ONLY
                // when the client both has the `unbounded` feature on AND lists "unbounded" here
                // (lantern-cloud config.go `shouldEmitUnboundedWidget`). Any `unbounded`-type
                // *outbound* the server also assigns is harmlessly skipped by lantern.rs.
                "unbounded".to_string(),
            ],
            capabilities: capabilities(),
            // Filled in by the fetch, which knows the data dir the store lives under.
            modules: std::collections::BTreeMap::new(),
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

/// Header naming the library that carried the request. Constant: it identifies the *racing layer*,
/// which is flint regardless of which member won or which app is asking.
pub(crate) const KINDLING_APP_HEADER: &str = "X-Kindling-App";
/// The one value [`KINDLING_APP_HEADER`] ever takes.
pub(crate) const KINDLING_APP: &str = "flint";
/// Header naming the winning race member (`direct`, `proxyless`, `fronted-tls`, …).
pub(crate) const KINDLING_METHOD_HEADER: &str = "X-Kindling-Method";

/// Translate a flint member name into the vocabulary the API already classifies on.
///
/// The `X-Kindling-Method` taxonomy is **Go kindling's**, not ours: `lantern-cloud`'s
/// `util.ConnectMethod` switches on `domainfront` / `dnstt` / `amp` / `smart`, which are exactly the
/// `TransportName` constants in `getlantern/kindling`. Every shipped Lantern client speaks it, so
/// the server is right and spark is the odd one out — flint arrived at the same concepts under
/// different names. Renaming server-side to match us would risk misclassifying the entire real
/// client population to accommodate a client population of roughly zero, so the translation belongs
/// here.
///
/// Only the two names whose meanings line up exactly are mapped — `proxyless` and `fronted-tls`.
/// The rest are deliberately left alone:
///
/// - `fronted-scan` is the vantage-point scanner. It is domain-fronted, but calling it
///   `domainfront` would merge a self-healing discovery path with a static embedded list — a
///   distinction worth more than the classification it would buy.
/// - `dns-tunnel` is *not* mapped to `dnstt`: they are different protocols, and equating them would
///   file spark's traffic under a wire format it does not speak.
/// - `direct` has no enum to hit and already lands on the server's `Direct` fallback correctly.
///
/// This is the **wire** vocabulary only. Our own `config.race_winner` events keep the flint names,
/// which are finer-grained than the server taxonomy can express.
/// The names on the left are the `ConnectionTransport::name()` values of the members
/// `config_kindling` actually registers — `proxyless` (`flint-kindling/src/proxyless.rs`) and
/// `fronted-tls` (`flint-fronted/src/lib.rs`, what `with_fronted_tls` registers). Matching on a name
/// no member reports is a silent no-op, since the fallback arm passes anything through unchanged.
fn wire_method(member: &str) -> Cow<'_, str> {
    match member {
        "proxyless" => Cow::Borrowed("smart"),
        "fronted-tls" => Cow::Borrowed("domainfront"),
        other => Cow::Borrowed(other),
    }
}

/// Which kindling member carried this request, for the server to attribute it to.
///
/// A `ConnectionTransport` hands back bytes and knows nothing about HTTP, so it cannot set a header
/// itself — but it does not need to. The race already reports the winner's name on the connection,
/// and this carries that name down to whichever HTTP builder runs. The transports stay
/// protocol-agnostic and the header still gets set.
///
/// [`Default`] is the no-attribution case: the request did not come through a race at all (the
/// `/user-create` pre-step dials directly), so the headers are omitted rather than guessed. An absent
/// header is honest; a wrong one corrupts the very attribution this exists for.
#[derive(Debug, Clone, Copy, Default)]
pub struct KindlingHeaders<'a> {
    method: Option<&'a str>,
}

impl<'a> KindlingHeaders<'a> {
    /// Attribute the request to the race member named `method`.
    pub fn method(method: &'a str) -> Self {
        Self {
            method: Some(method),
        }
    }

    /// The member name in the server's vocabulary, CR/LF-stripped, or `None` when there is nothing
    /// to attribute.
    ///
    /// Returns an `Option` rather than an empty string so both builders make the same
    /// something-to-attribute decision from one place; an empty value is not a weaker attribution,
    /// it is a wrong one.
    ///
    /// Stripped because the name originates from a transport's `name()` — a static string today, but
    /// it arrives here as ordinary data.
    fn method_value(&self) -> Option<String> {
        self.method
            .map(|m| header_safe(wire_method(m).as_ref()).into_owned())
    }

    /// The HTTP/1.1 header lines, or empty when there is nothing to attribute.
    /// Goes through [`Self::method_value`] rather than reading `self.method` directly, so this path
    /// and the h2 one cannot disagree about what goes on the wire. They already did once: the
    /// vocabulary translation was added to `method_value` alone, and HTTP/1.1 requests kept sending
    /// flint's untranslated name while h2 requests sent the server's — the same member attributed
    /// two different ways depending on which protocol the winner happened to negotiate.
    fn http1_lines(&self) -> String {
        match self.method_value() {
            None => String::new(),
            Some(m) => format!(
                "{KINDLING_APP_HEADER}: {KINDLING_APP}\r\n{KINDLING_METHOD_HEADER}: {m}\r\n"
            ),
        }
    }
}

/// Strip CR/LF from a value before it's interpolated into a header line, so a tampered/corrupt
/// non-constant source (the on-disk device id, the env-derived timezone, or a cached server-origin
/// `ETag`/`Last-Modified`) can't inject extra headers or break request framing. Borrows when clean.
pub(crate) fn header_safe(v: &str) -> std::borrow::Cow<'_, str> {
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
    kindling: KindlingHeaders<'_>,
) -> Result<Vec<u8>, serde_json::Error> {
    let body = serde_json::to_vec(req)?;
    let mut head = String::new();
    head.push_str(&format!("POST {path} HTTP/1.1\r\n"));
    // `host` is CR/LF-stripped like the other non-constant values below. It used to be a compile-time
    // constant from `FetchEnv`, which is why it once needed no guard — but a fronted connection is now
    // addressed by the *winning front's* inner host, which comes from parsed config or a live scan.
    head.push_str(&format!("Host: {}\r\n", header_safe(host)));
    head.push_str(&format!("X-Lantern-App: {APP_NAME}\r\n"));
    head.push_str(&kindling.http1_lines());
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
    // The server compresses when asked and not otherwise: measured 8,758 B identity vs 2,728 B gzip
    // for the same payload, a 3.2x saving on every fetch — paid on the censored paths this races
    // over, including the dns-tunnel tier that moves KB/s. Only gzip: the server also offers
    // deflate, but brotli and zstd are answered uncompressed, and a brotli decoder embeds a ~120 KB
    // static dictionary against a <3 MB binary budget to save ~270 B per fetch.
    head.push_str("Accept-Encoding: gzip\r\n");
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
    kindling: KindlingHeaders<'_>,
) -> Result<OneshotRequest, serde_json::Error> {
    let body = serde_json::to_vec(req)?;
    let mut out = OneshotRequest::post(path.to_owned(), body)
        // The on-the-wire cap the 1.1 path gets from `post_collect`'s read loop. Without it flint
        // buffers an unbounded *compressed* body before `decode_body` ever sees it, so the
        // decoded-size check would arrive too late to prevent the allocation. Slack over `MAX_BODY`
        // for headers and for a body that compresses poorly, mirroring the 1.1 loop's own margin.
        .with_max_body(super::MAX_BODY + 64 * 1024)
        // Same negotiation as the 1.1 path above; flint hands back headers + body verbatim and does
        // no decoding of its own, so the fronted branch decodes through the same `decode_body`.
        .header("Accept-Encoding", "gzip")
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
    // Attribution only when there is something to attribute — an unraced request must carry neither
    // header, exactly as on the HTTP/1.1 path. Emitting the pair with an empty method would attribute
    // the request to a member that never ran, which is the failure these headers exist to prevent.
    if let Some(method) = kindling.method_value() {
        out = out
            .header(KINDLING_APP_HEADER, KINDLING_APP)
            .header(KINDLING_METHOD_HEADER, method);
    }
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

    /// Both headers ride the HTTP/1.1 request when the fetch came through the race.
    #[test]
    fn the_http1_request_names_the_winning_member() {
        let req = ConfigRequest::new("dev".into());
        let bytes = build_request_bytes(
            "h",
            "/p",
            &req,
            &Conditional::default(),
            KindlingHeaders::method("fronted-tls"),
        )
        .unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("X-Kindling-App: flint\r\n"), "{text}");
        // `domainfront`, not `fronted-tls`: the wire carries the server's vocabulary (`wire_method`).
        assert!(
            text.contains("X-Kindling-Method: domainfront\r\n"),
            "{text}"
        );
    }

    /// A request that did not go through the race carries **neither** header, on **both** builders.
    /// Omitting is the point: a default would attribute the request to a member that never ran,
    /// corrupting exactly the signal these headers exist to provide.
    ///
    /// Both are asserted here because an earlier version checked only the HTTP/1.1 path while the h2
    /// one emitted `X-Kindling-App` with an empty method — the contract held on the branch under test
    /// and was broken on the branch that wasn't.
    #[test]
    fn a_non_raced_request_is_left_unattributed() {
        let req = ConfigRequest::new("dev".into());
        let text = String::from_utf8(
            build_request_bytes(
                "h",
                "/p",
                &req,
                &Conditional::default(),
                KindlingHeaders::default(),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(!text.contains("X-Kindling-"), "http/1.1 path: {text}");

        let oneshot = build_oneshot_request(
            "/p",
            &req,
            &Conditional::default(),
            KindlingHeaders::default(),
        )
        .unwrap();
        assert!(
            !oneshot
                .headers
                .iter()
                .any(|(k, _)| k.to_ascii_lowercase().starts_with("x-kindling-")),
            "h2 path: {:?}",
            oneshot.headers
        );
    }

    /// The h2 path carries the same pair — the member name reaches the server whichever protocol the
    /// winning edge negotiated, which is the whole point of attributing per connection.
    #[test]
    fn the_h2_request_names_the_winning_member() {
        let req = ConfigRequest::new("dev".into());
        let oneshot = build_oneshot_request(
            "/p",
            &req,
            &Conditional::default(),
            KindlingHeaders::method("proxyless"),
        )
        .unwrap();
        let has = |k: &str, v: &str| {
            oneshot
                .headers
                .iter()
                .any(|(hk, hv)| hk.eq_ignore_ascii_case(k) && hv == v)
        };
        assert!(has("X-Kindling-App", "flint"), "{:?}", oneshot.headers);
        // `smart`, not `proxyless`: the wire carries the server's vocabulary (see `wire_method`).
        assert!(has("X-Kindling-Method", "smart"), "{:?}", oneshot.headers);
    }

    /// Both protocols must attribute a given member identically. Otherwise the same winner is filed
    /// two different ways depending on whether the winning edge happened to negotiate h2 — which is
    /// exactly what happened when the translation was added to only one of the two builders.
    #[test]
    fn http1_and_h2_agree_on_the_attributed_name() {
        let req = ConfigRequest::new("dev".into());
        let headers = KindlingHeaders::method("proxyless");
        let h1 = headers.http1_lines();
        let oneshot =
            build_oneshot_request("/p", &req, &Conditional::default(), headers).expect("oneshot");
        let h2 = oneshot
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("X-Kindling-Method"))
            .map(|(_, v)| v.clone())
            .expect("h2 method header");
        assert!(
            h1.contains(&format!("{KINDLING_METHOD_HEADER}: {h2}\r\n")),
            "h1 {h1:?} disagrees with h2 {h2:?}"
        );
    }

    /// The member name reaches here as ordinary data, so it gets the same CR/LF guard as every other
    /// non-constant header value.
    #[test]
    fn a_newline_in_the_member_name_cannot_forge_a_header() {
        let req = ConfigRequest::new("dev".into());
        let text = String::from_utf8(
            build_request_bytes(
                "h",
                "/p",
                &req,
                &Conditional::default(),
                KindlingHeaders::method("direct\r\nX-Injected: 1"),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(
            !text.lines().any(|l| l.starts_with("X-Injected")),
            "forged a header line:\n{text}"
        );
    }

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

    /// The two names whose meanings line up exactly with Go kindling's taxonomy — the one the API
    /// actually switches on (`lantern-cloud` `util.ConnectMethod`). Sent under flint's own names
    /// these fell through the server's switch entirely and were misfiled as generic `Direct`/`Proxy`.
    #[test]
    fn the_two_aligned_members_go_out_in_go_kindlings_vocabulary() {
        assert_eq!(wire_method("proxyless"), "smart");
        assert_eq!(wire_method("fronted-tls"), "domainfront");
    }

    /// The non-mappings are choices, not omissions, so they are pinned too — otherwise a later
    /// "finish the job" edit would silently merge distinctions we decided to keep.
    #[test]
    fn the_other_members_are_left_alone_on_purpose() {
        // Domain-fronted, but the self-healing scanner is worth distinguishing from a static list.
        assert_eq!(wire_method("fronted-scan"), "fronted-scan");
        // Not a member any transport reports — `with_fronted_tls` registers a dialer whose `name()`
        // is `fronted-tls`. Mapping this instead would have been a silent no-op.
        assert_eq!(wire_method("fronted"), "fronted");
        // A different protocol from dnstt — mapping it would file spark under a wire format it
        // does not speak.
        assert_eq!(wire_method("dns-tunnel"), "dns-tunnel");
        // No enum to hit; already lands on the server's Direct fallback correctly.
        assert_eq!(wire_method("direct"), "direct");
        assert_eq!(wire_method("something-new"), "something-new");
    }

    /// The mapping has to reach the actual bytes, not just the helper.
    #[test]
    fn the_emitted_header_carries_the_translated_name() {
        let lines = KindlingHeaders::method("proxyless").http1_lines();
        assert!(
            lines.contains(&format!("{KINDLING_METHOD_HEADER}: smart\r\n")),
            "expected translated method header, got {lines:?}"
        );
        assert!(
            !lines.contains("proxyless"),
            "flint's own name must not reach the wire: {lines:?}"
        );
    }

    #[test]
    fn request_bytes_have_method_headers_conditional_and_body() {
        let mut req = ConfigRequest::new("dev-123".into());
        req.time_zone = "America/New_York".into(); // pin for a deterministic header assertion
        let cond = Conditional {
            etag: Some("\"abc\"".into()),
            last_modified: Some("Mon, 01 Jan 2024 00:00:00 GMT".into()),
        };
        let bytes = build_request_bytes(
            "df.iantem.io",
            "/api/v1/config-new",
            &req,
            &cond,
            KindlingHeaders::default(),
        )
        .unwrap();
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

    /// A build that can run delivered modules says so; one that cannot stays silent.
    ///
    /// This is the distinction `modules` cannot make on its own. That field is omitted when empty, so
    /// a client that supports delivery but holds nothing yet looks exactly like a client that cannot
    /// use modules at all — and the server needs to tell them apart to know whether to send the first
    /// one. Both halves are asserted here, because a capability nobody omits carries no information.
    #[test]
    fn the_transport_module_capability_tracks_the_build() {
        let req = ConfigRequest::new("d".into());
        let body = String::from_utf8(
            build_request_bytes(
                "h",
                "/p",
                &req,
                &Conditional::default(),
                KindlingHeaders::default(),
            )
            .unwrap(),
        )
        .unwrap()
        .split_once("\r\n\r\n")
        .unwrap()
        .1
        .to_string();

        if cfg!(feature = "wasm-transport") {
            assert!(
                body.contains(r#""capabilities":["transport_modules"]"#),
                "a build that can run delivered modules must advertise it: {body}"
            );
        } else {
            assert!(
                !body.contains("capabilities"),
                "a build that cannot run modules must send no capabilities at all: {body}"
            );
        }

        // Never advertised, in either build: nothing here consumes `NonSelectableOutbounds`, and
        // claiming it would invite the server to send outbounds this client would surface as
        // selectable proxies.
        assert!(!body.contains("non_selectable_outbounds"));
    }

    /// The `modules` declaration rides the JSON body and disappears when there is nothing to declare.
    ///
    /// Both halves matter. Present, it is what stops an inline module riding every config fetch —
    /// the body changes on each bandit reassignment, so the whole-body `ETag` almost never spares it.
    /// Absent, the request must be exactly what it was before this field existed, so a cold client or
    /// a build without `wasm-transport` cannot be told apart from an older one.
    #[test]
    fn declares_held_modules_in_the_body_and_omits_the_field_when_empty() {
        let body_of = |req: &ConfigRequest| {
            let s = String::from_utf8(
                build_request_bytes(
                    "h",
                    "/p",
                    req,
                    &Conditional::default(),
                    KindlingHeaders::default(),
                )
                .unwrap(),
            )
            .unwrap();
            s.split_once("\r\n\r\n").unwrap().1.to_string()
        };

        // Decode and look for the *key*, rather than searching the serialized text. A substring
        // search passes or fails for the wrong reason as soon as any other field's value contains
        // the word — which is not hypothetical: `"capabilities":["transport_modules"]` broke exactly
        // this assertion the moment that field was added.
        let key_absent = |body: &str, key: &str| {
            let v: serde_json::Value = serde_json::from_str(body).expect("the body is JSON");
            v.get(key).is_none()
        };

        let empty = ConfigRequest::new("d".into());
        let body = body_of(&empty);
        assert!(
            key_absent(&body, "modules"),
            "nothing held ⇒ the field is absent, not `\"modules\":{{}}`: {body}"
        );

        let mut held = ConfigRequest::new("d".into());
        held.modules = [("bip324".to_string(), 3u32), ("obfs-xor".to_string(), 1u32)]
            .into_iter()
            .collect();
        let body = body_of(&held);
        assert!(
            body.contains(r#""modules":{"bip324":3,"obfs-xor":1}"#),
            "held bundles are declared as engine → version, sorted: {body}"
        );
        // Content-Length must cover the grown body, or the server reads a truncated request.
        let s = String::from_utf8(
            build_request_bytes(
                "h",
                "/p",
                &held,
                &Conditional::default(),
                KindlingHeaders::default(),
            )
            .unwrap(),
        )
        .unwrap();
        let (head, body) = s.split_once("\r\n\r\n").unwrap();
        assert!(head.contains(&format!("Content-Length: {}", body.len())));
    }

    #[test]
    fn omits_conditional_headers_when_absent() {
        let req = ConfigRequest::new("d".into());
        let s = String::from_utf8(
            build_request_bytes(
                "h",
                "/p",
                &req,
                &Conditional::default(),
                KindlingHeaders::default(),
            )
            .unwrap(),
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
        let s = String::from_utf8(
            build_request_bytes("h", "/p", &req, &cond, KindlingHeaders::default()).unwrap(),
        )
        .unwrap();
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
            build_request_bytes(
                "h",
                "/p",
                &req,
                &Conditional::default(),
                KindlingHeaders::default(),
            )
            .unwrap(),
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
        let os = build_oneshot_request(
            "/api/v1/config-new",
            &req,
            &cond,
            KindlingHeaders::default(),
        )
        .unwrap();
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
        let os = build_oneshot_request(
            "/p",
            &req,
            &Conditional::default(),
            KindlingHeaders::default(),
        )
        .unwrap();
        assert!(!os
            .headers
            .iter()
            .any(|(k, _)| k == "If-None-Match" || k == "If-Modified-Since"));
    }
}
