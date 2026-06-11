//! Tunnel transports: how the proxy core reaches a target through a tunnel server.
//!
//! The `Transport` trait that abstracts over transports — and the dial that swaps M2's
//! direct upstream connection for a tunneled one — lands at M4. M3 builds the first
//! concrete transport, the plain [`tcp_tunnel`], in isolation against a relay/echo
//! server (PLAN Appendix B), with no TUN involved.

pub mod tcp_tunnel;
