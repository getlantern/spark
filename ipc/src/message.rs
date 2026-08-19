//! The control-plane message vocabulary: what the client and service say to each other.
//!
//! These types are the portable heart of the protocol — pure `serde`, no transport. They
//! are reused unchanged on every platform (desktop sockets, Apple NE provider messages,
//! Android in-process). [`encode_message`](crate::encode_message) turns them into bytes.

use serde::{Deserialize, Serialize};

/// The control-plane protocol version. Bumped on any breaking change to these types.
pub type ProtocolVersion = u32;

/// The version this build speaks. v2 (ADR 0004) adds the read-only backend-contract requests
/// [`RequestPayload::GetCapabilities`]/[`RequestPayload::GetDetails`] and their responses; v3 adds
/// [`RequestPayload::SetTelemetry`]; v4 adds [`RequestPayload::ApplyConfig`]. All additive
/// (appended enum variants), so older peers still decode the frames of their own version.
pub const PROTOCOL_VERSION: ProtocolVersion = 4;

/// The oldest version this build can still interoperate with.
pub const MIN_SUPPORTED_VERSION: ProtocolVersion = 1;

/// Correlates a [`Response`] with the [`Request`] that prompted it.
pub type ReqId = u64;

/// A client→service request. Every request carries a [`ReqId`] the response echoes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    /// Correlation id, echoed in the matching [`Response`].
    pub req_id: ReqId,
    /// What is being requested.
    pub payload: RequestPayload,
}

/// The body of a [`Request`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequestPayload {
    /// Version handshake — must be the first request on a connection.
    Hello {
        /// The client's [`PROTOCOL_VERSION`].
        client_version: ProtocolVersion,
    },
    /// Bring the tunnel up using the service's current configuration.
    Connect,
    /// Tear the tunnel down.
    Disconnect,
    /// Ask for the current [`TunnelStatus`].
    GetStatus,
    /// Opt into server-initiated [`Push`] streams.
    Subscribe {
        /// Stream tunnel events.
        events: bool,
        /// Stream (already-redacted) log lines.
        logs: bool,
    },
    /// (v2) Ask what this build supports — see [`Capabilities`]. Static; render valid UI choices.
    GetCapabilities,
    /// (v2) Ask for a richer status snapshot than [`GetStatus`](RequestPayload::GetStatus) — see
    /// [`Details`].
    GetDetails,
    /// (v2) Ask for the data-path counters — see [`Metrics`]. Poll for live values.
    GetMetrics,
    /// (v2) List the stored connection profiles (redacted). → [`ResponsePayload::Profiles`].
    ListProfiles,
    /// (v2) Fetch one profile as a redacted config document. → [`ResponsePayload::Profile`].
    GetProfile {
        /// The profile's name (its id).
        name: String,
    },
    /// (v2) Create or replace a profile from a TOML config document. Secrets are write-only: a
    /// blanked secret field (e.g. an empty `password`) keeps the stored value, so a
    /// read→edit→write round-trip never needs the client to have seen the secret. → `Ack`.
    SetProfile {
        /// The profile's name (its id).
        name: String,
        /// A `core::config::Config` as TOML (secret fields may be blank to keep the stored value).
        toml: String,
    },
    /// (v2) Delete a stored profile. → `Ack`.
    DeleteProfile {
        /// The profile's name (its id).
        name: String,
    },
    /// (v2) Select the active profile (the one a future `Connect` will use). → `Ack`.
    SetActiveProfile {
        /// The profile's name (its id).
        name: String,
    },
    /// (v2) Validate a TOML config document without storing it. → [`ResponsePayload::Validated`].
    ValidateProfile {
        /// A candidate `core::config::Config` as TOML.
        toml: String,
    },
    /// (v3) Point the tunnel process's diagnostics uploader at a collector — see
    /// [`TelemetryConfig`]. Write-only: nothing here is ever readable back over the control plane.
    /// → `Ack`.
    SetTelemetry(TelemetryConfig),
    /// (v4) Apply a config the **app** fetched to the running tunnel, live — no reconnect. → `Ack`.
    ///
    /// The connect-time handover: the app gives a starting session a pool it already holds (and any
    /// transport module delivered with it), so the tunnel serves traffic without waiting for its own
    /// first fetch. The tunnel still owns refresh once it is up — only its sockets are pinned to the
    /// physical interface, so only its fetch is guaranteed to bypass the tunnel itself.
    ///
    /// `raw` carries transport credentials, so it is redacted from `Debug` (see the impl below).
    ///
    /// Appended last, and the enum is only ever extended at the end, so an older peer's encodings
    /// keep their discriminants (postcard indexes variants by position).
    ApplyConfig {
        /// A config-new response body — the same bytes the app caches as `config_raw.json`.
        raw: String,
    },
}

/// A service→client response. `req_id` echoes the request it answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    /// The [`ReqId`] of the request this answers.
    pub req_id: ReqId,
    /// The response body.
    pub payload: ResponsePayload,
}

/// The body of a [`Response`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponsePayload {
    /// Reply to [`RequestPayload::Hello`]: the service's version and the negotiated one.
    Hello {
        /// The service's [`PROTOCOL_VERSION`].
        service_version: ProtocolVersion,
        /// The version both sides will use (see [`negotiate`]).
        negotiated: ProtocolVersion,
    },
    /// Reply to [`RequestPayload::GetStatus`].
    Status(TunnelStatus),
    /// (v2) Reply to [`RequestPayload::GetCapabilities`].
    Capabilities(Capabilities),
    /// (v2) Reply to [`RequestPayload::GetDetails`].
    Details(Details),
    /// (v2) Reply to [`RequestPayload::GetMetrics`].
    Metrics(Metrics),
    /// (v2) Reply to [`RequestPayload::ListProfiles`].
    Profiles(Vec<ProfileSummary>),
    /// (v2) Reply to [`RequestPayload::GetProfile`] — a redacted config document.
    Profile(ProfileDoc),
    /// (v2) Reply to [`RequestPayload::ValidateProfile`].
    Validated(Validation),
    /// A request succeeded with no payload.
    Ack,
    /// A request failed.
    Error {
        /// Machine-readable error category.
        code: ErrorCode,
        /// Human-readable detail (no secrets).
        message: String,
    },
}

/// Everything the service sends to the client on the wire. Because replies and pushes
/// share one connection, the client decodes this envelope and demultiplexes: a
/// [`Response`] correlates to a request by `req_id`; a [`Push`] is unsolicited stream data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerMessage {
    /// A reply to a client [`Request`].
    Response(Response),
    /// A server-initiated stream item.
    Push(Push),
}

/// A server-initiated push (no `req_id`); only sent after a [`RequestPayload::Subscribe`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Push {
    /// A tunnel state/lifecycle event.
    Event(TunnelEvent),
    /// A redacted log line.
    Log(LogLine),
    /// Backpressure marker: `count` stream items were dropped to a slow client.
    Dropped {
        /// Number of items dropped since the last marker.
        count: u64,
    },
}

/// Tunnel lifecycle state. The service is the source of truth for this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TunnelState {
    /// No tunnel; traffic is unaffected.
    Disconnected,
    /// Bringing the tunnel up.
    Connecting,
    /// Tunnel up and forwarding.
    Connected,
    /// Tearing the tunnel down.
    Disconnecting,
    /// The tunnel failed; see the accompanying event/status.
    Failed,
}

/// A snapshot of tunnel status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelStatus {
    /// Current lifecycle state.
    pub state: TunnelState,
    /// True if the kill-switch failed open and routing is currently direct (loud signal —
    /// the client should surface this; see process-architecture-and-ipc.md §5).
    pub direct_fallback: bool,
}

/// (v2) A transport a build supports or has selected. `Direct` means no tunnel server (dial the
/// original destination); the others tunnel through a server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum TransportKind {
    /// No tunnel — flows dial their original destination directly.
    #[default]
    Direct,
    /// The plain spark tunnel server.
    Plain,
    /// AnyTLS-over-TLS (ADR 0001).
    Anytls,
    /// Dynamic wasm transport (ADR 0003).
    Wasm,
}

/// (v2) A netstack a build supports or has selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum NetStack {
    /// Userspace smoltcp stack (cross-platform, the default).
    #[default]
    Userspace,
    /// Kernel-TCP "system" stack (ADR 0002; desktop/Android, build-gated).
    System,
}

/// (v2) Kill-switch behavior when the tunnel drops unexpectedly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum KillSwitchMode {
    /// Restore direct routing (loudly) — the product default.
    #[default]
    FailOpen,
    /// Block traffic instead of falling back to direct.
    FailClosed,
}

/// (v2) The active dynamic transform module (wasm), once loaded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleInfo {
    /// The signed module's name.
    pub name: String,
    /// The signed module's version (anti-rollback floor).
    pub version: u32,
}

/// (v2) What this build supports, so a UI offers only valid options. Static (compiled features +
/// platform); see [`RequestPayload::GetCapabilities`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Capabilities {
    /// The service's [`PROTOCOL_VERSION`].
    pub protocol_version: ProtocolVersion,
    /// The service's build version (`CARGO_PKG_VERSION`).
    pub build_version: String,
    /// Transports this build can use.
    pub transports: Vec<TransportKind>,
    /// Netstacks this build can use.
    pub stacks: Vec<NetStack>,
    /// `os/arch`, e.g. `"macos/aarch64"`.
    pub platform: String,
}

/// (v2) A one-line summary of a stored profile (no secrets); see [`RequestPayload::ListProfiles`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileSummary {
    /// The profile's name (its id).
    pub name: String,
    /// The transport the profile selects.
    pub transport: TransportKind,
    /// The netstack the profile selects.
    pub stack: NetStack,
    /// Whether the profile has an AnyTLS password stored (the value is never sent).
    pub has_password: bool,
    /// Whether this is the active profile.
    pub active: bool,
}

/// (v2) A profile as a redacted TOML config document; see [`RequestPayload::GetProfile`]. Secret
/// fields (AnyTLS `password`, wasm `init_config`) are blanked — edit and `SetProfile` to keep them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileDoc {
    /// The profile's name (its id).
    pub name: String,
    /// The profile's `core::config::Config` serialized as TOML, with secrets blanked.
    pub toml: String,
}

/// (v2) The result of [`RequestPayload::ValidateProfile`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Validation {
    /// Whether the document parsed as a valid config.
    pub valid: bool,
    /// The parse/validation error (no secrets), if invalid.
    pub error: Option<String>,
}

/// (v2) Data-path counters; see [`RequestPayload::GetMetrics`]. Cumulative since the service
/// started, with `sessions_active` reflecting currently-open flows. Currently TCP-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Metrics {
    /// Bytes sent app→upstream (egress).
    pub bytes_up: u64,
    /// Bytes received upstream→app (ingress).
    pub bytes_down: u64,
    /// Flows currently open.
    pub sessions_active: u64,
    /// Flows opened since start (cumulative).
    pub sessions_total: u64,
}

/// (v2) A richer status snapshot than [`TunnelStatus`]; see [`RequestPayload::GetDetails`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Details {
    /// Current lifecycle state.
    pub state: TunnelState,
    /// Kill-switch failed open and routing is currently direct (see [`TunnelStatus::direct_fallback`]).
    pub direct_fallback: bool,
    /// The transport the active config selects.
    pub selected_transport: TransportKind,
    /// The netstack the active config selects.
    pub selected_stack: NetStack,
    /// The loaded wasm module, if a wasm transport is connected (populated in a later slice).
    pub module: Option<ModuleInfo>,
    /// The kill-switch mode the active config sets.
    pub kill_switch: KillSwitchMode,
    /// The most recent error the service surfaced (cleared on a successful connect). No secrets.
    pub last_error: Option<String>,
}

/// (v3) Where the tunnel process should send its diagnostics; see [`RequestPayload::SetTelemetry`].
///
/// **Why this crosses the control plane at all.** The tunnel process has everything it needs to
/// upload — TLS stack, trust anchors, the uploader itself — and lacks only the collector's address
/// and key. Those live in config-new's payload, which the *client app* fetches and the tunnel
/// deliberately does not (#132: the tunnel does not fetch on its own behalf). So the app forwards
/// the block it already has rather than the tunnel growing a second fetch path.
///
/// **Write-only, in both directions of the word.** The values travel client→service and are never
/// echoed back: no response, event, or `Details` field exposes them (CLAUDE.md — proxy secrets live
/// in the privileged store only). And the service treats them as a destination to *send* to, never
/// as something to serve: it POSTs its own spool to fixed OTLP paths and reads nothing back but a
/// status code.
///
/// **Trust note.** An authenticated peer choosing the collector host is not a new class of
/// capability: the same peer can already `SetProfile` + `Connect` and route the machine's entire
/// traffic through a server it names. Peer-cred auth remains the boundary that matters.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryConfig {
    /// OTLP ingest endpoint as `host:port` (radiance's convention, e.g.
    /// `ingest.us.signoz.cloud:443`). Empty disables upload.
    pub endpoint: String,
    /// Headers attached verbatim to every upload — the ingestion key lives here. Opaque secrets:
    /// never log the values (the [`Debug`] impl below redacts them).
    pub headers: Vec<(String, String)>,
    /// Sampling rate in **parts per million** (`1_000_000` = every device). Integer rather than the
    /// `f64` the config block carries, because [`RequestPayload`] is `Eq` — and because a wire
    /// format is better off without NaN and without float equality. Convert with
    /// [`sample_rate_ppm`](Self::sample_rate_ppm) / [`sample_rate`](Self::sample_rate).
    pub sample_rate_ppm: u32,
    /// The `features["otel.logs"]` gate. False ships nothing — logs gate all uploads.
    pub logs_enabled: bool,
    /// The `features["otel.traces"]` gate.
    pub traces_enabled: bool,
    /// The app's device id, so the tunnel's records carry the SAME identity as the app's and the
    /// config requests'. Also the input to sampling, which is what keeps a device either wholly in
    /// or wholly out rather than reporting half a session.
    pub device_id: String,
    /// The server's geo view of this client (`country` in the config response), or empty. The
    /// tunnel process has no config cache to read it from.
    pub country: String,
}

impl TelemetryConfig {
    /// Convert a `[0.0, 1.0]` sample rate to [`Self::sample_rate_ppm`], clamping out-of-range and
    /// NaN inputs to the nearest valid rate. NaN maps to 0 (report nothing) rather than to
    /// everything: a malformed rate should not silently enroll a device.
    pub fn sample_rate_ppm(rate: f64) -> u32 {
        if rate.is_nan() {
            return 0;
        }
        (rate.clamp(0.0, 1.0) * 1_000_000.0).round() as u32
    }

    /// This config's sampling rate as a `[0.0, 1.0]` fraction, the form the uploader's gate wants.
    pub fn sample_rate(&self) -> f64 {
        f64::from(self.sample_rate_ppm.min(1_000_000)) / 1_000_000.0
    }
}

// Manual Debug: a config-new body carries transport credentials — Shadowsocks passwords, Samizdat
// keys, the bip324 `init_config` — and `Request` derives Debug, so any `{:?}` of a request frame (a
// trace line, a failing assertion, a panic message) would print the lot. Every other variant is
// spelled out rather than delegated — the set is small and stable, and an explicit match means a new
// variant carrying a secret cannot be added without this function failing to compile.
//
// The body LENGTH stays visible: it is the field that actually gets diagnosed (a stripped module
// bundle shows up as ~9 KB against ~56 KB with one), and a byte count reveals nothing.
impl std::fmt::Debug for RequestPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApplyConfig { raw } => f
                .debug_struct("ApplyConfig")
                .field("raw", &format_args!("[redacted {} bytes]", raw.len()))
                .finish(),
            Self::Hello { client_version } => f
                .debug_struct("Hello")
                .field("client_version", client_version)
                .finish(),
            Self::Connect => f.write_str("Connect"),
            Self::Disconnect => f.write_str("Disconnect"),
            Self::GetStatus => f.write_str("GetStatus"),
            Self::Subscribe { events, logs } => f
                .debug_struct("Subscribe")
                .field("events", events)
                .field("logs", logs)
                .finish(),
            Self::GetCapabilities => f.write_str("GetCapabilities"),
            Self::GetDetails => f.write_str("GetDetails"),
            Self::GetMetrics => f.write_str("GetMetrics"),
            Self::ListProfiles => f.write_str("ListProfiles"),
            Self::GetProfile { name } => f.debug_struct("GetProfile").field("name", name).finish(),
            // `toml` may carry a password on the way in; same treatment as `raw`.
            Self::SetProfile { name, toml } => f
                .debug_struct("SetProfile")
                .field("name", name)
                .field("toml", &format_args!("[redacted {} bytes]", toml.len()))
                .finish(),
            Self::DeleteProfile { name } => {
                f.debug_struct("DeleteProfile").field("name", name).finish()
            }
            Self::SetActiveProfile { name } => f
                .debug_struct("SetActiveProfile")
                .field("name", name)
                .finish(),
            Self::ValidateProfile { toml } => f
                .debug_struct("ValidateProfile")
                .field("toml", &format_args!("[redacted {} bytes]", toml.len()))
                .finish(),
            Self::SetTelemetry(cfg) => f.debug_tuple("SetTelemetry").field(cfg).finish(),
        }
    }
}

// Manual Debug: header values are ingestion keys, and `Request` derives Debug — so without this any
// `{:?}` of a request frame (a trace line, a test failure, a panic message) would print the key.
// Header NAMES stay visible: which headers are set is diagnostic signal, and none of it is secret.
// Mirrors `core::config::lantern::OtelConfig`'s impl, for the same reason.
impl std::fmt::Debug for TelemetryConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let headers: Vec<(&str, &str)> = self
            .headers
            .iter()
            .map(|(k, _)| (k.as_str(), "[redacted]"))
            .collect();
        f.debug_struct("TelemetryConfig")
            .field("endpoint", &self.endpoint)
            .field("headers", &headers)
            .field("sample_rate_ppm", &self.sample_rate_ppm)
            .field("logs_enabled", &self.logs_enabled)
            .field("traces_enabled", &self.traces_enabled)
            .field("device_id", &self.device_id)
            .field("country", &self.country)
            .finish()
    }
}

/// A tunnel event delivered over a [`Push`] stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TunnelEvent {
    /// The tunnel transitioned to a new state.
    StateChanged(TunnelState),
    /// The fail-open kill-switch fired: routing was restored to direct. Surface loudly.
    FellOpenToDirect,
}

/// A redacted log line forwarded to a subscribed client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogLine {
    /// Severity.
    pub level: LogLevel,
    /// The (already address-redacted) message.
    pub message: String,
}

/// Log severity, mirroring `tracing` levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogLevel {
    /// Error.
    Error,
    /// Warning.
    Warn,
    /// Informational.
    Info,
    /// Debug.
    Debug,
    /// Trace.
    Trace,
}

/// Machine-readable error categories for [`ResponsePayload::Error`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    /// The peer is not authorized to control the service.
    Unauthorized,
    /// The handshake found no common protocol version.
    UnsupportedVersion,
    /// The request was malformed or invalid in the current state.
    InvalidRequest,
    /// The operation requires an active tunnel.
    NotConnected,
    /// An unexpected internal failure.
    Internal,
}

/// Negotiate the protocol version each side will use: the lower of the two, provided both
/// support at least [`MIN_SUPPORTED_VERSION`]. Each side calls this with
/// `(PROTOCOL_VERSION, peer_version)`; both arrive at the same result. Returns `None` (reject
/// the connection) when no compatible version exists.
pub fn negotiate(ours: ProtocolVersion, theirs: ProtocolVersion) -> Option<ProtocolVersion> {
    let chosen = ours.min(theirs);
    (chosen >= MIN_SUPPORTED_VERSION).then_some(chosen)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiate_picks_lower_compatible_version() {
        assert_eq!(negotiate(1, 1), Some(1));
        // Each side caps at its own max, so the lower wins.
        assert_eq!(negotiate(1, 5), Some(1));
        assert_eq!(negotiate(5, 1), Some(1));
        assert_eq!(negotiate(3, 3), Some(3));
    }

    #[test]
    fn negotiate_rejects_below_minimum() {
        assert_eq!(negotiate(0, 1), None);
        assert_eq!(negotiate(1, 0), None);
    }

    fn telemetry(ppm: u32) -> TelemetryConfig {
        TelemetryConfig {
            endpoint: "ingest.example:443".into(),
            headers: vec![("signoz-ingestion-key".into(), "s3cr3t-key-value".into())],
            sample_rate_ppm: ppm,
            logs_enabled: true,
            traces_enabled: true,
            device_id: "d".into(),
            country: "US".into(),
        }
    }

    /// The ingestion key must never appear in a formatted request frame. `Request` derives
    /// `Debug`, so without the manual impl on `TelemetryConfig` any `{:?}` — a trace line, a
    /// failing `assert_eq!`, a panic message — would print the key verbatim.
    /// A config-new body carries transport credentials — Shadowsocks passwords, Samizdat keys, the
    /// bip324 `init_config`. `Request` derives `Debug`, so without the manual impl any `{:?}` of a
    /// request frame would print all of them. The byte count is kept deliberately: it is the field
    /// actually used in diagnosis (a stripped module bundle shows as ~9 KB against ~56 KB with one).
    #[test]
    fn debug_never_prints_a_config_body() {
        let raw = r#"{"options":{"outbounds":[{"password":"s3cr3t-proxy-password"}]}}"#.to_owned();
        let len = raw.len();
        let req = Request {
            req_id: 1,
            payload: RequestPayload::ApplyConfig { raw },
        };
        let rendered = format!("{req:?}");
        assert!(
            !rendered.contains("s3cr3t-proxy-password"),
            "config body leaked into Debug: {rendered}"
        );
        assert!(rendered.contains("[redacted"), "{rendered}");
        assert!(
            rendered.contains(&format!("{len} bytes")),
            "the length must survive: {rendered}"
        );
    }

    /// Same reasoning for a profile document, which carries a password on the way in.
    #[test]
    fn debug_never_prints_a_profile_document() {
        let req = Request {
            req_id: 2,
            payload: RequestPayload::SetProfile {
                name: "home".to_owned(),
                toml: "[transport.anytls]\npassword = \"s3cr3t-profile-pw\"\n".to_owned(),
            },
        };
        let rendered = format!("{req:?}");
        assert!(
            !rendered.contains("s3cr3t-profile-pw"),
            "profile secret leaked into Debug: {rendered}"
        );
        // The profile NAME stays: which profile is being written is diagnostic, not secret.
        assert!(rendered.contains("home"), "{rendered}");
    }

    #[test]
    fn debug_never_prints_a_header_value() {
        let req = Request {
            req_id: 1,
            payload: RequestPayload::SetTelemetry(telemetry(1_000_000)),
        };
        let rendered = format!("{req:?}");
        assert!(
            !rendered.contains("s3cr3t-key-value"),
            "header value leaked into Debug: {rendered}"
        );
        // The header NAME stays: knowing which headers are set is diagnostic signal, not a secret.
        assert!(rendered.contains("signoz-ingestion-key"), "{rendered}");
        assert!(rendered.contains("[redacted]"), "{rendered}");
    }

    /// The `[0.0, 1.0]` ⇄ ppm conversion, including the inputs a malformed config can produce.
    #[test]
    fn sample_rate_survives_the_ppm_round_trip() {
        for rate in [0.0, 0.25, 0.5, 1.0] {
            let ppm = TelemetryConfig::sample_rate_ppm(rate);
            assert!(
                (telemetry(ppm).sample_rate() - rate).abs() < 1e-6,
                "{rate} round-tripped through {ppm} ppm"
            );
        }
        // Out of range clamps to the nearest valid rate...
        assert_eq!(TelemetryConfig::sample_rate_ppm(1.5), 1_000_000);
        assert_eq!(TelemetryConfig::sample_rate_ppm(-1.0), 0);
        // ...and NaN reports NOTHING rather than everything: a rate that failed to parse must not
        // silently enroll a device at 100%.
        assert_eq!(TelemetryConfig::sample_rate_ppm(f64::NAN), 0);
        // A value beyond the encodable range still yields a legal fraction on the way back.
        assert_eq!(telemetry(u32::MAX).sample_rate(), 1.0);
    }

    /// The v3 variant survives the postcard round-trip the control plane puts it through.
    #[test]
    fn set_telemetry_round_trips_through_the_codec() {
        let req = Request {
            req_id: 7,
            payload: RequestPayload::SetTelemetry(telemetry(250_000)),
        };
        let bytes = crate::encode_message(&req).expect("encode");
        let back: Request = crate::decode_message(&bytes).expect("decode");
        assert_eq!(back, req);
    }
}
