//! The proxy core: turn surfaced netstack flows into forwarded connections.
//!
//! [`tcp`] is the TCP forwarder (M2 direct dial, M4 tunneled via the `Transport` trait).
//! [`udp`] is the UDP path (M5): its NAT association table (session 1) and, later, the
//! datagram orchestration (session 2).

pub mod tcp;
pub mod udp;
