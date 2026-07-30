//! Real-IP resolution for recovered domains (the [`crate::proxy::FlowResolver`] seam).
//!
//! A Direct- or client-resolved Proxy flow arrives at a *fake* IP; spark recovers the domain and must
//! resolve it to a *real* IP to dial. It can't use the OS resolver — that DNS goes in-tunnel to
//! spark's own fake-IP server and would loop. So resolution rides an un-poisoned **DoH** resolver
//! (`flint_dns`) whose sockets bypass the TUN (`addDisallowedApplication` / NE bypass). Distinct from
//! control-plane bootstrap resolution ([`crate::bootstrap`]).
//!
//! Two per-action seams, both honoring the config's `options.dns`:
//! - [`direct_resolver`] — the Direct action. Uses the config's `dns_local` DoH **alone** (racing it
//!   against foreign resolvers would defeat "best local IPs"). Poisoning isn't a concern — a Direct
//!   domain is unblocked, which is *why* it's direct.
//! - [`proxy_resolver`] — the Proxy client-side fallback (only for transports that can't carry a
//!   domain to the exit). These are the poisoning-risk lookups, so the config's `dns_remote` races
//!   *alongside* the resilient un-poisoned pool.
//!
//! Both fall back to `flint_dns`'s built-in diverse pool when the config has no usable endpoint, and
//! return `None` without the `bootstrap-dns` feature (the forwarder then degrades: Direct→Proxy,
//! Proxy→dial-by-name).

use std::sync::Arc;

use crate::config::DnsConfig;
use crate::proxy::FlowResolver;

#[cfg(feature = "bootstrap-dns")]
use crate::config::DohEndpoint;
#[cfg(feature = "bootstrap-dns")]
use std::{io, net::IpAddr};

/// The Direct action's resolver: the config's `dns_local` DoH alone (best-local answers), or the
/// built-in un-poisoned pool if `dns_local` is absent/unusable.
#[cfg(feature = "bootstrap-dns")]
pub fn direct_resolver(dns: &DnsConfig) -> Option<Arc<dyn FlowResolver>> {
    let pool = dns
        .local
        .as_ref()
        .and_then(endpoint_to_resolver)
        .map(|r| vec![r])
        .unwrap_or_else(flint_dns::default_pool);
    Some(Arc::new(DohResolver { pool }))
}

/// The Proxy client-side-resolution fallback: the config's `dns_remote` DoH raced alongside the
/// resilient un-poisoned pool.
#[cfg(feature = "bootstrap-dns")]
pub fn proxy_resolver(dns: &DnsConfig) -> Option<Arc<dyn FlowResolver>> {
    let mut pool = flint_dns::default_pool();
    if let Some(r) = dns.remote.as_ref().and_then(endpoint_to_resolver) {
        pool.insert(0, r); // configured remote leads, the diverse pool backs it up
    }
    Some(Arc::new(DohResolver { pool }))
}

/// Without `bootstrap-dns` there is no DoH stack.
#[cfg(not(feature = "bootstrap-dns"))]
pub fn direct_resolver(_dns: &DnsConfig) -> Option<Arc<dyn FlowResolver>> {
    None
}

/// Without `bootstrap-dns` there is no DoH stack.
#[cfg(not(feature = "bootstrap-dns"))]
pub fn proxy_resolver(_dns: &DnsConfig) -> Option<Arc<dyn FlowResolver>> {
    None
}

/// Build a flint DoH resolver from a config endpoint, or `None` if its IP isn't a **known** public
/// resolver. flint's boring DoH validates the cert against a hostname SNI, but the config gives only an
/// IP — so we supply the well-known DoH hostname for the recognized providers and skip anything else
/// (which falls back to the default pool). Mirrors the providers in `flint_dns::default_pool`.
#[cfg(feature = "bootstrap-dns")]
fn endpoint_to_resolver(ep: &DohEndpoint) -> Option<flint_dns::Resolver> {
    let ip: IpAddr = ep.server.parse().ok()?;
    let sni = known_resolver_sni(ip)?;
    // The typed constructor rather than a struct literal: `Resolver` now carries a transport `kind`
    // (DoH/DoT/plaintext/system), and `doh` is what pins this entry to DoH and its `host`/`path` fields.
    Some(flint_dns::Resolver::doh(
        "config",
        std::net::SocketAddr::new(ip, ep.port),
        sni,
        sni,
        normalize_doh_path(&ep.path),
    ))
}

/// Ensure a DoH request path is a usable absolute path — flint sends it verbatim as the HTTP request
/// target. An explicitly-empty path becomes the shared default (`/` alone is not a valid DoH
/// endpoint for the supported providers); a path missing its leading `/` (e.g. `dns-query`) is made
/// absolute.
#[cfg(feature = "bootstrap-dns")]
fn normalize_doh_path(path: &str) -> String {
    if path.is_empty() {
        crate::config::default_doh_path()
    } else if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

/// The DoH hostname (cert SAN + `:authority`) for a well-known public resolver IP, or `None` if
/// unrecognized — covers Quad9 (what Lantern configs use) plus the common alternates, for both IPv4
/// and IPv6 (the config may carry a v6 literal, which `parse_dns` also captures).
///
/// Matches only the providers' **exact** published DoH endpoint IPs, not their surrounding ranges: a
/// range match (e.g. `9.9.9.0/24`) would pin a provider SNI onto an unrelated or typoed address in
/// that block, whose cert then fails to validate — worse than returning `None` and letting the
/// caller fall back to the default pool.
#[cfg(feature = "bootstrap-dns")]
fn known_resolver_sni(ip: IpAddr) -> Option<&'static str> {
    Some(match ip {
        IpAddr::V4(a) => match a.octets() {
            [9, 9, 9, 9..=11] | [149, 112, 112, 9..=11 | 112] => "dns.quad9.net",
            [1, 1, 1, 1] | [1, 0, 0, 1] => "cloudflare-dns.com",
            [8, 8, 8, 8] | [8, 8, 4, 4] => "dns.google",
            [223, 5, 5, 5] | [223, 6, 6, 6] => "dns.alidns.com",
            _ => return None,
        },
        IpAddr::V6(a) => match a.segments() {
            // Quad9 2620:fe::fe / ::9 / ::10 / ::11
            [0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x9 | 0xfe | 0x10 | 0x11] => "dns.quad9.net",
            // Cloudflare 2606:4700:4700::1111 / ::1001
            [0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111 | 0x1001] => "cloudflare-dns.com",
            // Google 2001:4860:4860::8888 / ::8844
            [0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888 | 0x8844] => "dns.google",
            // AliDNS 2400:3200::1 / 2400:3200:baba::1
            [0x2400, 0x3200, 0, 0, 0, 0, 0, 0x1] | [0x2400, 0x3200, 0xbaba, 0, 0, 0, 0, 0x1] => {
                "dns.alidns.com"
            }
            _ => return None,
        },
    })
}

/// A [`FlowResolver`] over a `flint_dns` DoH pool. Tries A and AAAA concurrently.
#[cfg(feature = "bootstrap-dns")]
struct DohResolver {
    pool: Vec<flint_dns::Resolver>,
}

#[cfg(feature = "bootstrap-dns")]
#[async_trait::async_trait]
impl FlowResolver for DohResolver {
    async fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        // Return **both** families (A first) so the caller's `pick_ip` can select the family the flow
        // needs — returning only A would strand a v6-requesting flow (or a v6-only network).
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

    #[cfg(not(feature = "bootstrap-dns"))]
    #[test]
    fn no_resolvers_without_bootstrap_dns() {
        assert!(direct_resolver(&DnsConfig::default()).is_none());
        assert!(proxy_resolver(&DnsConfig::default()).is_none());
    }

    #[cfg(feature = "bootstrap-dns")]
    mod doh {
        use super::*;
        use crate::config::DohEndpoint;

        fn ep(server: &str) -> DohEndpoint {
            DohEndpoint {
                server: server.into(),
                port: 443,
                path: "/dns-query".into(),
            }
        }

        #[test]
        fn maps_known_resolver_ips_to_their_doh_hostname() {
            let quad9 = endpoint_to_resolver(&ep("9.9.9.9")).expect("quad9 is known");
            assert_eq!(quad9.host, "dns.quad9.net");
            assert_eq!(quad9.sni, "dns.quad9.net");
            assert_eq!(quad9.target, "9.9.9.9:443".parse().unwrap());
            assert_eq!(quad9.path, "/dns-query");
            assert_eq!(
                endpoint_to_resolver(&ep("1.1.1.1")).unwrap().host,
                "cloudflare-dns.com"
            );
            // An unknown IP can't be given a valid SNI → skipped (falls back to the default pool).
            assert!(endpoint_to_resolver(&ep("203.0.113.5")).is_none());
            // A hostname server (not an IP) is also skipped.
            assert!(endpoint_to_resolver(&ep("dns.quad9.net")).is_none());
        }

        #[test]
        fn maps_known_resolver_ipv6_to_their_doh_hostname() {
            // parse_dns captures IPv6 https servers too, so the SNI mapping must handle them.
            assert_eq!(
                endpoint_to_resolver(&ep("2620:fe::fe")).unwrap().host,
                "dns.quad9.net"
            );
            assert_eq!(
                endpoint_to_resolver(&ep("2606:4700:4700::1111"))
                    .unwrap()
                    .host,
                "cloudflare-dns.com"
            );
            assert_eq!(
                endpoint_to_resolver(&ep("2001:4860:4860::8888"))
                    .unwrap()
                    .host,
                "dns.google"
            );
            assert_eq!(
                endpoint_to_resolver(&ep("2400:3200::1")).unwrap().host,
                "dns.alidns.com"
            );
            // An unknown IPv6 literal is skipped like an unknown v4 one.
            assert!(endpoint_to_resolver(&ep("2001:db8::1")).is_none());
        }

        #[test]
        fn a_config_path_without_a_leading_slash_is_made_absolute() {
            let mut e = ep("9.9.9.9");
            e.path = "dns-query".into(); // no leading slash
            assert_eq!(endpoint_to_resolver(&e).unwrap().path, "/dns-query");
            // An already-absolute path is left untouched.
            let mut e = ep("9.9.9.9");
            e.path = "/resolve".into();
            assert_eq!(endpoint_to_resolver(&e).unwrap().path, "/resolve");
            // An explicitly-empty path becomes the default, not a bare "/".
            let mut e = ep("9.9.9.9");
            e.path = "".into();
            assert_eq!(endpoint_to_resolver(&e).unwrap().path, "/dns-query");
        }

        #[test]
        fn resolvers_build_from_config_and_fall_back() {
            // dns_local present + known → direct resolver builds.
            let dns = DnsConfig {
                local: Some(ep("9.9.9.9")),
                remote: Some(ep("1.1.1.1")),
            };
            assert!(direct_resolver(&dns).is_some());
            assert!(proxy_resolver(&dns).is_some());
            // Empty config → still Some (falls back to the built-in pool).
            assert!(direct_resolver(&DnsConfig::default()).is_some());
            assert!(proxy_resolver(&DnsConfig::default()).is_some());
        }
    }
}
