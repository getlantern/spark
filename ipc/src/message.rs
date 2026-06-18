//! The control-plane message vocabulary: what the client and service say to each other.
//!
//! These types are the portable heart of the protocol — pure `serde`, no transport. They
//! are reused unchanged on every platform (desktop sockets, Apple NE provider messages,
//! Android in-process). [`encode_message`](crate::encode_message) turns them into bytes.

use serde::{Deserialize, Serialize};

/// The control-plane protocol version. Bumped on any breaking change to these types.
pub type ProtocolVersion = u32;

/// The version this build speaks. v2 (ADR 0004) adds the read-only backend-contract requests
/// [`RequestPayload::GetCapabilities`]/[`RequestPayload::GetDetails`] and their responses; all
/// additive (appended enum variants), so v1 peers still decode v1 frames.
pub const PROTOCOL_VERSION: ProtocolVersion = 2;

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
}
