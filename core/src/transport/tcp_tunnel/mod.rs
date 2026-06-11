//! Plain TCP tunnel transport (first transport).
//!
//! The client opens a TCP connection to the tunnel server, sends a SOCKS5-style address
//! [`header`] naming the target, then relays application bytes transparently in both
//! directions. No bespoke crypto — a relay can be wrapped in TLS via `rustls` at the
//! connection layer (M3b, optional).
//!
//! M3a (this commit) is the address codec only. The relay stream (`stream`) and the
//! `TunnelClient` (`client`) land at M3b/M4.

pub mod header;
