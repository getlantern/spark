//! Real-IP resolution for recovered domains (the [`crate::proxy::FlowResolver`] seam).
//!
//! A Direct- or client-resolved Proxy flow arrives at a *fake* IP; spark recovers the domain and must
//! resolve it to a *real* IP to dial. It can't use the OS resolver — that DNS goes in-tunnel to
//! spark's own fake-IP server and would loop. So resolution rides an un-poisoned **DoH** resolver
//! (`flint_dns`) whose sockets bypass the TUN (`addDisallowedApplication` / NE bypass). Poisoning is a
//! non-issue for a Direct domain (it's unblocked — that's *why* it's direct); for the Proxy fallback
//! it likewise gives a real IP the exit can use. Distinct from control-plane bootstrap resolution
//! ([`crate::bootstrap`]).
//!
//! Without the `bootstrap-dns` feature there is no DoH stack, so [`local_resolver`] returns `None` and
//! the forwarder degrades: a Direct flow becomes Proxy, and a Proxy flow falls back to dial-by-name.
//!
//! v1 uses one un-poisoned DoH resolver for both the Direct (local, best-CDN) and Proxy (resilient)
//! seams; splitting them (a true local resolver for Direct, a racing resolver for Proxy) is a later
//! refinement — the two seams already exist in [`crate::proxy::RouteHooks`].

use std::sync::Arc;

use crate::proxy::FlowResolver;

// `io`/`IpAddr` are only used by the DoH impl (and the tests); without `bootstrap-dns` the module
// would otherwise carry two unused imports.
#[cfg(feature = "bootstrap-dns")]
use std::{io, net::IpAddr};

/// The DoH real-IP resolver for recovered domains, or `None` when the DoH stack isn't built in
/// (`bootstrap-dns` off) — the forwarder then degrades (Direct→Proxy, Proxy→dial-by-name).
#[cfg(feature = "bootstrap-dns")]
pub fn local_resolver() -> Option<Arc<dyn FlowResolver>> {
    Some(Arc::new(DohResolver {
        pool: flint_dns::default_pool(),
    }))
}

/// Without `bootstrap-dns` there is no DoH resolver.
#[cfg(not(feature = "bootstrap-dns"))]
pub fn local_resolver() -> Option<Arc<dyn FlowResolver>> {
    None
}

/// A [`FlowResolver`] over `flint_dns`'s un-poisoned DoH pool. Tries A first, then AAAA.
#[cfg(feature = "bootstrap-dns")]
struct DohResolver {
    pool: Vec<flint_dns::Resolver>,
}

#[cfg(feature = "bootstrap-dns")]
#[async_trait::async_trait]
impl FlowResolver for DohResolver {
    async fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        // Look up A and AAAA concurrently and return **both** families (A first), so the caller's
        // `pick_ip` can select the family the flow actually needs — returning only A would strand a
        // v6-requesting flow (or a v6-only network) even when a usable AAAA exists.
        let (a, aaaa) = tokio::join!(
            flint_dns::resolve(host, flint_dns::TYPE_A, &self.pool),
            flint_dns::resolve(host, flint_dns::TYPE_AAAA, &self.pool),
        );
        let mut ips = Vec::new();
        if let Ok(v) = a {
            ips.extend(v);
        }
        if let Ok(v) = aaaa {
            ips.extend(v);
        }
        if ips.is_empty() {
            return Err(io::Error::other("no A/AAAA records"));
        }
        Ok(ips)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io, net::IpAddr};

    /// A fixed-answer resolver, proving the [`FlowResolver`] seam the forwarder consumes. The real
    /// DoH impl hits the network and is exercised on-device / in integration, not here.
    struct Fake(Vec<IpAddr>);

    #[async_trait::async_trait]
    impl FlowResolver for Fake {
        async fn resolve(&self, _host: &str) -> io::Result<Vec<IpAddr>> {
            Ok(self.0.clone())
        }
    }

    #[tokio::test]
    async fn flow_resolver_trait_object_resolves() {
        let want: Vec<IpAddr> = vec!["1.2.3.4".parse().unwrap()];
        let r: Arc<dyn FlowResolver> = Arc::new(Fake(want.clone()));
        assert_eq!(r.resolve("cdn.example.com").await.unwrap(), want);
    }

    #[cfg(not(feature = "bootstrap-dns"))]
    #[test]
    fn no_local_resolver_without_bootstrap_dns() {
        assert!(local_resolver().is_none());
    }
}
