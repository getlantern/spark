//! The proxy core: turn surfaced netstack flows into forwarded connections.
//!
//! [`tcp`] is the TCP forwarder (M2 direct dial, M4 tunneled via the `Transport` trait).
//! [`udp`] is the UDP path (M5): its NAT association table (session 1) and, later, the
//! datagram orchestration (session 2).

use std::net::{IpAddr, SocketAddr};
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
    /// Dial through the proxyless transport (ADR 0014) — still no proxy and no exit hop, but with an
    /// un-poisoned resolver and opening-handshake shaping.
    ///
    /// If no proxyless transport is configured the forwarder **rejects** the flow rather than falling
    /// back to [`Direct`](Self::Direct) or [`Proxy`](Self::Proxy). A rule asking for circumvention is
    /// not satisfied by a plain dial, and silently routing it through the proxy would send traffic via
    /// an exit hop the rule explicitly did not ask for.
    Proxyless,
    /// Drop the flow.
    Reject,
}

/// A per-flow routing decision source. Implemented by `crate::rules::router::Router` behind the
/// `smart-routing` feature; `None` = proxy everything (today's behavior).
pub trait FlowRouter: Send + Sync {
    /// Decide what to do with a flow to `ip`. `domain` is `Some` once fake-IP DNS recovers it
    /// (M4); at L3 it is `None`.
    ///
    /// `src` is the flow's local (source) endpoint — used by app split tunneling to attribute the
    /// flow to a process. `proto` is the flow's transport, so the process resolver reads the right
    /// kernel socket table (a QUIC/UDP flow isn't in the TCP table). Implementations that don't need
    /// them may ignore both.
    fn decide(
        &self,
        ip: IpAddr,
        domain: Option<&str>,
        src: SocketAddr,
        proto: crate::process::Protocol,
    ) -> Decision;
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
    /// Client-side resolver for a **UDP** flow whose transport cannot carry a domain
    /// (`dial_udp_addr` → `Unsupported`): shadowsocks, dns-tunnel, proxyless, fronted-meek.
    ///
    /// The TCP equivalent is gone. `Transport::dial_addr` is now a required method, so every TCP
    /// transport hands the name to the exit and a client-side lookup for a proxied TCP flow is
    /// unrepresentable. `UdpTransport::dial_udp_addr` still has an `Unsupported` default, so this
    /// remains until those four carry a UDP domain — at which point it should be deleted with it.
    ///
    /// It is a known disclosure while it lasts: a proxied UDP flow to a name resolves locally, which
    /// puts the destination in a DNS lookup on the local network.
    pub proxy_resolver: Option<Arc<dyn FlowResolver>>,
    /// The proxyless transport (ADR 0014) for [`Decision::Proxyless`] flows. `None` → such flows are
    /// **rejected**, not silently downgraded (see [`Decision::Proxyless`]).
    ///
    /// Lives here rather than as a forwarder parameter because a Proxyless decision can only come from
    /// the router, which is itself part of these hooks: where there are no hooks there is no rule that
    /// could ask for it. Bundling it keeps both forwarders' signatures unchanged.
    pub proxyless_transport: Option<Arc<dyn crate::transport::Transport>>,
    /// The UDP half of the same, for [`Decision::Proxyless`] datagram flows.
    pub proxyless_udp: Option<Arc<dyn crate::transport::UdpTransport>>,
}

/// Whether `dst` (with an optionally recovered `domain`) is an **encrypted-DNS** endpoint that
/// smart-routing should Reject, so the client falls back to plain `:53` — which the fake-IP DNS
/// server answers, keeping domains visible for routing/ad-block. Without this, a device with Private
/// DNS (DoT) or a browser doing DoH talks TLS/HTTPS straight to a public resolver, bypassing `:53`.
///
/// Matches port 853 (DNS-over-TLS/QUIC — a DNS-only port, any IP), or port 443 to a well-known
/// public DoH resolver (by recovered hostname, or by raw IP for the bootstrap connection). Only
/// meaningful when smart-routing/fake-IP is active; the forwarders gate the call on that.
pub(crate) fn is_encrypted_dns(dst: SocketAddr, domain: Option<&str>) -> bool {
    match dst.port() {
        853 => true,
        443 => domain.is_some_and(is_doh_hostname) || is_public_resolver_ip(dst.ip()),
        _ => false,
    }
}

/// A well-known DoH provider hostname (case- and trailing-dot-insensitive).
fn is_doh_hostname(host: &str) -> bool {
    // Allocation-free: this runs on every smart-routed :443 flow, so compare case-insensitively
    // against the (already-lowercase) known hosts rather than lowercasing into an owned String.
    const DOH_HOSTS: [&str; 8] = [
        "dns.google",
        "dns64.dns.google",
        "cloudflare-dns.com",
        "mozilla.cloudflare-dns.com",
        "one.one.one.one",
        "dns.quad9.net",
        "dns.alidns.com",
        "doh.opendns.com",
    ];
    let h = host.trim_end_matches('.');
    DOH_HOSTS
        .iter()
        .any(|candidate| h.eq_ignore_ascii_case(candidate))
}

/// A well-known public DNS-resolver IP — the endpoints a DoT/DoH client bootstraps to directly.
fn is_public_resolver_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => matches!(
            a.octets(),
            [8, 8, 8, 8] | [8, 8, 4, 4]                       // Google
            | [1, 1, 1, 1..=3] | [1, 0, 0, 1..=3]             // Cloudflare (+ family)
            | [9, 9, 9, 9..=11] | [149, 112, 112, 9..=11 | 112] // Quad9
            | [223, 5, 5, 5] | [223, 6, 6, 6]                 // AliDNS
            | [208, 67, 222, 222] | [208, 67, 220, 220] // OpenDNS
        ),
        IpAddr::V6(a) => matches!(
            a.segments(),
            [0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888 | 0x8844]           // Google
            | [0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111 | 0x1001]         // Cloudflare
            | [0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x9 | 0xfe | 0x10 | 0x11]     // Quad9
            | [0x2400, 0x3200, 0, 0, 0, 0, 0, 0x1]                          // AliDNS
            | [0x2400, 0x3200, 0xbaba, 0, 0, 0, 0, 0x1]
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn encrypted_dns_detection() {
        // DoT/DoQ port — any IP.
        assert!(is_encrypted_dns(sa("1.2.3.4:853"), None));
        assert!(is_encrypted_dns(sa("[2606:4700:4700::1111]:853"), None));
        // DoH :443 to a public resolver by raw IP (the bootstrap connection).
        assert!(is_encrypted_dns(sa("8.8.8.8:443"), None));
        assert!(is_encrypted_dns(sa("1.1.1.1:443"), None));
        assert!(is_encrypted_dns(sa("9.9.9.11:443"), None));
        assert!(is_encrypted_dns(sa("[2001:4860:4860::8844]:443"), None)); // observed on the Redmi
                                                                           // DoH :443 by recovered hostname (fake-IP path), trailing dot / case tolerant.
        assert!(is_encrypted_dns(sa("198.18.0.9:443"), Some("dns.google")));
        assert!(is_encrypted_dns(
            sa("198.18.0.9:443"),
            Some("Cloudflare-DNS.com.")
        ));
        // Ordinary HTTPS is untouched.
        assert!(!is_encrypted_dns(
            sa("93.184.216.34:443"),
            Some("example.com")
        ));
        assert!(!is_encrypted_dns(sa("1.2.3.4:443"), None));
        // Plain :53 is NOT rejected — that's the fake-IP server's job.
        assert!(!is_encrypted_dns(sa("8.8.8.8:53"), None));
    }
}
