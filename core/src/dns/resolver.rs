//! Real-IP resolution for the **Direct** action.
//!
//! A Direct-routed flow arrives at a *fake* IP; spark recovers the domain and must resolve it to a
//! *real* IP to dial directly. It can't use the OS resolver — that DNS goes in-tunnel to spark's own
//! fake-IP server and would loop. So Direct resolution rides an un-poisoned **DoH** resolver
//! (`flint_dns`) whose sockets bypass the TUN (`addDisallowedApplication` / NE bypass). Poisoning is a
//! non-issue here: a Direct domain is unblocked (that's *why* it's routed direct), so we just want the
//! best real IPs. This is distinct from control-plane bootstrap resolution ([`crate::bootstrap`]).
//!
//! Without the `bootstrap-dns` feature there is no DoH stack, so [`local_resolver`] returns `None` and
//! the forwarder degrades a Direct flow to **Proxy** (dial by name / real IP through the pool) — safe,
//! just not direct.

use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;

/// Resolves a domain to real IP(s) for a Direct flow, over tunnel-bypassing sockets.
#[async_trait]
pub trait DirectResolver: Send + Sync {
    /// Resolve `host` to one or more real IPs (A preferred, AAAA fallback). Errors if none validate.
    async fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>>;
}

/// The local real-IP resolver for Direct flows, or `None` when the DoH stack isn't built in
/// (`bootstrap-dns` off) — the caller then proxies the flow instead of dialing it direct.
#[cfg(feature = "bootstrap-dns")]
pub fn local_resolver() -> Option<Arc<dyn DirectResolver>> {
    Some(Arc::new(DohDirectResolver {
        pool: flint_dns::default_pool(),
    }))
}

/// Without `bootstrap-dns` there is no DoH resolver; Direct flows fall back to Proxy.
#[cfg(not(feature = "bootstrap-dns"))]
pub fn local_resolver() -> Option<Arc<dyn DirectResolver>> {
    None
}

/// A [`DirectResolver`] over `flint_dns`'s un-poisoned DoH pool. Tries A first, then AAAA.
#[cfg(feature = "bootstrap-dns")]
struct DohDirectResolver {
    pool: Vec<flint_dns::Resolver>,
}

#[cfg(feature = "bootstrap-dns")]
#[async_trait]
impl DirectResolver for DohDirectResolver {
    async fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        if let Ok(ips) = flint_dns::resolve(host, flint_dns::TYPE_A, &self.pool).await {
            if !ips.is_empty() {
                return Ok(ips);
            }
        }
        let ips = flint_dns::resolve(host, flint_dns::TYPE_AAAA, &self.pool)
            .await
            .map_err(io::Error::other)?;
        if ips.is_empty() {
            return Err(io::Error::other("no A/AAAA records"));
        }
        Ok(ips)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed-answer resolver, proving the trait-object seam the forwarder consumes (M4.6). The real
    /// DoH impl hits the network and is exercised on-device / in integration, not here.
    struct Fake(Vec<IpAddr>);

    #[async_trait]
    impl DirectResolver for Fake {
        async fn resolve(&self, _host: &str) -> io::Result<Vec<IpAddr>> {
            Ok(self.0.clone())
        }
    }

    #[tokio::test]
    async fn direct_resolver_trait_object_resolves() {
        let want: Vec<IpAddr> = vec!["1.2.3.4".parse().unwrap()];
        let r: Arc<dyn DirectResolver> = Arc::new(Fake(want.clone()));
        assert_eq!(r.resolve("cdn.example.com").await.unwrap(), want);
    }

    #[cfg(not(feature = "bootstrap-dns"))]
    #[test]
    fn no_local_resolver_without_bootstrap_dns() {
        assert!(local_resolver().is_none());
    }
}
