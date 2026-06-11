//! Plain TCP tunnel transport (first transport).
//!
//! The client opens a TCP connection to the tunnel server, sends a SOCKS5-style address
//! [`header`] naming the target, then relays application bytes transparently in both
//! directions. No bespoke crypto — a relay can be wrapped in TLS via `rustls` at the
//! connection layer (M3b, optional).
//!
//! M3a added the address codec ([`header`]). M3b adds the relay [`stream`] and the
//! [`client`] that dials a tunnel server and sends the header. M4 makes the client a
//! `Transport`. [`udp`] adds per-datagram framing for the UDP path (M5).

pub mod client;
pub mod header;
pub mod stream;
pub mod udp;
