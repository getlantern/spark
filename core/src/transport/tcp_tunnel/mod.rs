//! Plain TCP tunnel transport (first transport).
//!
//! The client opens a TCP connection to the tunnel server, sends a SOCKS5-style address
//! [`header`] naming the target, then relays application bytes transparently in both
//! directions. No bespoke crypto — a relay can be wrapped in TLS via `rustls` at the
//! connection layer (M3b, optional).
//!
//! M3a added the address codec ([`header`]). M3b adds the relay [`stream`] and the
//! [`client`] that dials a tunnel server and sends the header. The `Transport` trait that
//! abstracts over transports lands at M4.

pub mod client;
pub mod header;
pub mod stream;
