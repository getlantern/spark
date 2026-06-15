//! The control-plane message vocabulary: what the client and service say to each other.
//!
//! These types are the portable heart of the protocol — pure `serde`, no transport. They
//! are reused unchanged on every platform (desktop sockets, Apple NE provider messages,
//! Android in-process). [`encode_message`](crate::encode_message) turns them into bytes.

use serde::{Deserialize, Serialize};

/// The control-plane protocol version. Bumped on any breaking change to these types.
pub type ProtocolVersion = u32;

/// The version this build speaks.
pub const PROTOCOL_VERSION: ProtocolVersion = 1;

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
