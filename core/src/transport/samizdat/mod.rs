//! Samizdat transport (ADR 0007, `docs/samizdat-transport-design.md`).
//!
//! A client for Lantern's REALITY-style protocol, wire-interoperable with deployed
//! `lantern-box` / sing-box `"samizdat"` servers. The flow is a single outer TLS 1.3 session
//! (Chrome-mimicking ClientHello, reusing the AnyTLS boring connector) whose `legacy_session_id`
//! carries REALITY auth, with proxied flows multiplexed as HTTP/2 CONNECT streams.
//!
//! Built in chunks (design §10). This module currently provides:
//! - [`auth`]: the SessionID auth crypto (HKDF/HMAC over the server public key + short ID).
//! - [`session_id`]: the no-fork `kID` seam that injects the auth SessionID into the boring
//!   ClientHello's `legacy_session_id`.
//! - [`h2_mux`]: the HTTP/2 CONNECT multiplexer (one TLS conn → many tunnel streams).
//! - [`transport`]: the [`SamizdatTransport`](transport::SamizdatTransport) tying them together.

pub mod auth;
pub mod h2_mux;
pub mod session_id;
pub mod transport;

pub use transport::SamizdatTransport;
