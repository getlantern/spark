//! The proxy core: turn surfaced netstack flows into forwarded connections.
//!
//! [`tcp`] is the TCP forwarder (M2 direct dial, M4 tunneled via the `Transport` trait).
//! [`udp`] is the UDP path (M5): its NAT association table (session 1) and, later, the
//! datagram orchestration (session 2).

use std::net::IpAddr;
use std::sync::Arc;

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

/// Recovers the domain a flow's (fake) destination IP stands for — the connect-time half of the
/// fake-IP DNS layer (M4). `None` means the IP isn't a live fake (a real-IP flow), so the forwarder
/// routes and dials on the IP itself. Implemented by the `dns` layer; a feature-agnostic seam so the
/// forwarder needn't depend on it.
pub trait DomainRecoverer: Send + Sync {
    /// The domain behind fake IP `ip`, or `None` for a real / unknown IP.
    fn recover(&self, ip: IpAddr) -> Option<String>;
}

/// Resolves a recovered domain to real IP(s) over tunnel-bypassing sockets (so no fake-IP loop) —
/// used to dial a Direct flow's real destination, and, when a proxy transport can't carry a name to
/// the exit, to resolve a Proxy flow client-side. Implemented by the `dns` layer.
#[async_trait::async_trait]
pub trait FlowResolver: Send + Sync {
    /// Resolve `host` to one or more real IPs (empty/`Err` = resolution failed).
    async fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>>;
}

/// The smart-routing hooks the forwarders consult per flow: recover the domain behind a fake IP,
/// decide the action, and resolve a recovered domain to a real IP. Bundled so the forwarder takes one
/// optional handle; `None` (feature off / no rules) means proxy-everything. Any individual hook may be
/// `None` and the forwarder degrades safely (see the per-action dial logic in [`crate::proxy::tcp`]).
pub struct RouteHooks {
    /// Decides Proxy/Direct/Reject per flow.
    pub router: Arc<dyn FlowRouter>,
    /// Recovers a domain from a fake destination IP (fake-IP DNS). `None` → route on the IP only.
    pub recoverer: Option<Arc<dyn DomainRecoverer>>,
    /// Resolves a Direct flow's domain to its real (best local CDN) IP. `None` → Direct domain flows
    /// fall back to Proxy (never dial a fake IP directly).
    pub direct_resolver: Option<Arc<dyn FlowResolver>>,
    /// Resolves a Proxy flow's domain to a real IP client-side when the transport can't carry a name
    /// to the exit. `None` → fall back to dial-by-name (only domain-capable transports succeed).
    pub proxy_resolver: Option<Arc<dyn FlowResolver>>,
}
