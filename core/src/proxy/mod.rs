//! The proxy core: turn surfaced netstack flows into forwarded connections.
//!
//! [`tcp`] is the TCP forwarder (M2 direct dial, M4 tunneled via the `Transport` trait).
//! [`udp`] is the UDP path (M5): its NAT association table (session 1) and, later, the
//! datagram orchestration (session 2).

use std::net::IpAddr;

pub mod tcp;
pub mod udp;

/// What to do with a flow. The proxy layer's own enum, so this module stays independent of the
/// (feature-gated) rules engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Dial through the proxy pool transport (today's behavior).
    Proxy,
    /// Dial through the direct transport, bypassing the proxy.
    Direct,
    /// Drop the flow.
    Reject,
}

/// A per-flow routing decision source. Implemented by `crate::rules::router::Router` behind the
/// `smart-routing` feature; `None` = proxy everything (today's behavior).
pub trait FlowRouter: Send + Sync {
    /// Decide what to do with a flow to `ip`. `domain` is `Some` once fake-IP DNS recovers it
    /// (M4); at L3 it is `None`.
    fn decide(&self, ip: IpAddr, domain: Option<&str>) -> Decision;
}
