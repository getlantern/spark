//! Samizdat transport (ADR 0007, `docs/samizdat-transport-design.md`).
//!
//! A client for Lantern's REALITY-style protocol, wire-interoperable with deployed
//! `lantern-box` / sing-box `"samizdat"` servers. The flow is a single outer TLS 1.3 session
//! (Chrome-mimicking ClientHello, reusing the AnyTLS boring connector) whose `legacy_session_id`
//! carries REALITY auth, with proxied flows multiplexed as HTTP/2 CONNECT streams.
//!
//! Built in chunks (design §10). This module currently provides:
//! - [`auth`]: the SessionID auth crypto (HKDF/HMAC over the server public key + short ID).

pub mod auth;
