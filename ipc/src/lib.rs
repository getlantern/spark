//! `spark-ipc` — the control-plane IPC protocol (commands/status/logs between the
//! unprivileged client and the privileged tunnel service). The data plane never crosses
//! this channel.
//!
//! This crate is **pure protocol**: `serde` message types ([`message`]) plus their byte
//! [`codec`]. It has no transport and no async — so it cross-compiles and unit-tests
//! everywhere, and the same messages ride every platform's channel: a unix socket or named
//! pipe on desktop, an Apple NetworkExtension provider message on iOS/macOS, or an
//! in-process call on Android. The async transport, peer authentication, and the service
//! event loop live in `spark-service` (M7 session 2); see
//! `docs/process-architecture-and-ipc.md` and the `ipc-service-split-design-m7` decision.
//!
//! Two encoding layers (pick by transport):
//! - [`encode_message`]/[`decode_message`] — one message ↔ postcard bytes. For
//!   message-oriented transports that already delimit messages.
//! - [`encode_frame`]/[`decode_frame`] — length-delimited framing on top, for byte-stream
//!   transports (unix socket, named pipe).

pub mod codec;
pub mod message;
#[cfg(feature = "stream")]
pub mod stream;

pub use codec::{
    decode_frame, decode_message, encode_frame, encode_message, IpcError, MAX_FRAME_LEN,
};
pub use message::{
    negotiate, Capabilities, Details, ErrorCode, KillSwitchMode, LogLevel, LogLine, Metrics,
    ModuleInfo, NetStack, ProfileDoc, ProfileSummary, ProtocolVersion, Push, ReqId, Request,
    RequestPayload, Response, ResponsePayload, ServerMessage, TelemetryConfig, TransportKind,
    TunnelEvent, TunnelState, TunnelStatus, Validation, MIN_SUPPORTED_VERSION, PROTOCOL_VERSION,
};
#[cfg(feature = "stream")]
pub use stream::{read_frame, write_frame, Client};
