//! AnyTLS transport — a TLS-based tunnel that defeats **TLS-in-TLS fingerprinting** by combining
//! stream multiplexing with a server-pushable record-size [`padding`] scheme. Designed to run on a
//! BoringSSL (`btls`) TLS layer that emits a near-genuine Chrome ClientHello (see
//! `docs/adr/0001-chrome-mimicry-tls-backend.md`).
//!
//! Layering, top to bottom: `proxy stream → AnyTLS stream → AnyTLS session → TLS → TCP`. AnyTLS
//! owns the **stream** and **session** layers; TLS provides the encryption (hence "any in TLS").
//!
//! After the TLS handshake the client sends an auth record, then both sides speak a stream of
//! session [`frame`]s. Multiple logical streams are multiplexed over one session by `stream_id`;
//! idle sessions are pooled and reused so new requests rarely produce a fresh visible handshake.
//!
//! ## Status
//!
//! - [`frame`] — the session-frame codec ([`Command`], [`Frame`]).
//! - [`padding`] — the padding-scheme parser/model + the [`padding::shape_records`] engine.
//! - [`io`] — async framed I/O ([`io::FrameReader`]/[`io::FrameWriter`]) over a byte stream.
//! - [`session`] — the client-side multiplexer ([`Session`]/[`Stream`]); adopts a server
//!   `cmdUpdatePaddingScheme` and closes a stream on a `cmdSYNACK` error.
//! - [`auth`] — the client auth record (SHA-256, via `ring`).
//! - [`settings`] — the `cmdSettings` builder/parser ([`Settings`]) (the `padding-md5` value is
//!   computed via the `md-5` crate; `ring` has no MD5).
//! - `tls` — the Chrome-mimicking BoringSSL connector (feature `anytls`).
//! - `transport` — the [`super::Transport`]/[`super::UdpTransport`] impl over a pool of
//!   reconnecting TLS sessions (feature `anytls`).
//! - `udp` — UDP-over-TCP v2 (sing-box UoT) over a session stream (feature `anytls`).
//!
//! Remaining (non-blocking): the [`Stream`] write path's outbound channel is still unbounded, so a
//! slow transport buffers rather than backpressuring the writer — see [`session`].
//!
//! Reference: the AnyTLS protocol spec (`anytls/anytls-go`, `docs/protocol.md`) and the
//! `m11-transport-candidates-anytls-samizdat` memory.

pub mod auth;
pub mod frame;
pub mod io;
pub mod padding;
pub mod session;
pub mod settings;
// The BoringSSL TLS connector + the `Transport` impl are behind the `anytls` feature (the C build).
#[cfg(feature = "anytls")]
pub mod tls;
#[cfg(feature = "anytls")]
pub mod transport;
#[cfg(feature = "anytls")]
pub mod udp;

pub use auth::encode_auth;
pub use frame::{Command, Frame, FrameError};
pub use padding::{shape_records, PaddingError, PaddingScheme, Seg, SizeSampler, SystemSampler};
pub use session::{Session, Stream};
pub use settings::Settings;
#[cfg(feature = "anytls")]
pub use transport::AnytlsTransport;

/// The AnyTLS protocol version this implementation speaks (advertised in `cmdSettings` as `v=`).
/// v2 adds `SynAck`, the heartbeat commands, and `ServerSettings`.
pub const PROTOCOL_VERSION: u8 = 2;

/// The oldest protocol version this implementation interoperates with. A v2 peer that negotiates
/// down to v1 must not emit the v2-only commands (`SynAck`/`HeartRequest`/`HeartResponse`/
/// `ServerSettings`).
pub const MIN_PROTOCOL_VERSION: u8 = 1;
