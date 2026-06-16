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
//! ## Status (built vs. deferred)
//!
//! - [`frame`] — the session-frame codec ([`Command`], [`Frame`]). **Built.**
//! - [`padding`] — the padding-scheme parser/model ([`PaddingScheme`]). **Built.**
//! - [`io`] — async framed I/O ([`io::FrameReader`]/[`io::FrameWriter`]) over a byte stream. **Built.**
//! - [`session`] — the client-side multiplexer ([`Session`]/[`Stream`]). **Built.**
//! - Deferred to later chunks: the auth record (SHA-256) + `cmdSettings` (+ `padding-md5`, MD5);
//!   the padding *engine* that applies a plan to outgoing writes; the idle-session **pool**; and
//!   the [`super::Transport`] impl over a `btls` TLS stream (which also makes outbound backpressure
//!   bounded — see [`session`]).
//!
//! Reference: the AnyTLS protocol spec (`anytls/anytls-go`, `docs/protocol.md`) and the
//! `m11-transport-candidates-anytls-samizdat` memory.

pub mod frame;
pub mod io;
pub mod padding;
pub mod session;

pub use frame::{Command, Frame, FrameError};
pub use padding::{PaddingError, PaddingScheme, Seg};
pub use session::{Session, Stream};

/// The AnyTLS protocol version this implementation speaks (advertised in `cmdSettings` as `v=`).
/// v2 adds `SynAck`, the heartbeat commands, and `ServerSettings`.
pub const PROTOCOL_VERSION: u8 = 2;

/// The oldest protocol version this implementation interoperates with. A v2 peer that negotiates
/// down to v1 must not emit the v2-only commands (`SynAck`/`HeartRequest`/`HeartResponse`/
/// `ServerSettings`).
pub const MIN_PROTOCOL_VERSION: u8 = 1;
