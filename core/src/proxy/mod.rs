//! The proxy core: turn surfaced netstack flows into forwarded connections.
//!
//! M2 ships only the plain TCP forwarder ([`tcp`]), which dials the original
//! destination directly. The tunnel transport that replaces the direct dial lands at
//! M3/M4; UDP forwarding at M5.

pub mod tcp;
