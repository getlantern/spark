//! Per-flow routing decision.
//!
//! Given a destination — the IP (always known) and the domain (known once the fake-IP DNS layer
//! recovers it in M4; `None` at L3) — [`Router::decide`] returns the [`Action`]. It is a thin,
//! precedence-aware wrapper over the compact [`Matcher`]: the matcher is built with the rule-sets
//! in descending precedence (ad_block → route.rules → smart_routing), and anything it doesn't
//! match falls back to [`Action::Proxy`] — the config's `route.final` (the bandit pool).

use std::net::IpAddr;

use super::matcher::Matcher;
use super::Action;

/// Decides the [`Action`] for each flow from the compiled rule matcher.
pub struct Router {
    matcher: Matcher,
}

impl Router {
    /// Wrap a compiled [`Matcher`] (built by the caller from the parsed rule-sets, in descending
    /// precedence order).
    pub fn new(matcher: Matcher) -> Self {
        Self { matcher }
    }

    /// The action for a flow. `domain` is `Some` once the fake-IP DNS layer has recovered it
    /// (M4); at L3 it is `None`, so only IP/CIDR rules can match. An unmatched flow is proxied.
    pub fn decide(&self, ip: IpAddr, domain: Option<&str>) -> Action {
        self.matcher.lookup(domain, ip).unwrap_or(Action::Proxy)
    }
}

/// The proxy layer's routing seam ([`crate::proxy::FlowRouter`]), mapping this module's [`Action`]
/// onto the proxy's `Decision`. Lets the (feature-agnostic) TCP forwarder consult the rules engine
/// without depending on it.
impl crate::proxy::FlowRouter for Router {
    fn decide(&self, ip: IpAddr, domain: Option<&str>) -> crate::proxy::Decision {
        // Call the inherent `Router::decide` explicitly — a bare `self.decide(..)` would resolve to
        // this trait method and recurse forever.
        match Router::decide(self, ip, domain) {
            Action::Proxy => crate::proxy::Decision::Proxy,
            Action::Direct => crate::proxy::Decision::Direct,
            Action::Reject => crate::proxy::Decision::Reject,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::srs::{parse, RuleSet};

    fn fixture(name: &str) -> RuleSet {
        let bytes = std::fs::read(format!("tests/fixtures/srs/{name}.srs"))
            .unwrap_or_else(|e| panic!("read fixture {name}: {e}"));
        parse(&bytes).unwrap_or_else(|e| panic!("parse {name}: {e}"))
    }

    /// Build a router the way M4 will: ad/malware lists at Reject (highest precedence), the
    /// smart-routing common list at Direct, everything else Proxy.
    fn router() -> Router {
        let entries = vec![
            (Action::Reject, fixture("banad_v1")),
            (Action::Reject, fixture("category-ads_v2")),
            (Action::Reject, fixture("geoip-malware")),
            (Action::Direct, fixture("common_v3")),
        ];
        Router::new(Matcher::build(entries))
    }

    #[test]
    fn decides_reject_direct_and_proxy_by_domain() {
        let r = router();
        // An ad domain → Reject (ad_block).
        assert_eq!(
            r.decide("1.2.3.4".parse().unwrap(), Some("doubleclick.net")),
            Action::Reject
        );
        // A smart-routing common domain → Direct.
        assert_eq!(
            r.decide("1.2.3.4".parse().unwrap(), Some("app.discord.com")),
            Action::Direct
        );
        // An unlisted domain → Proxy (route.final).
        assert_eq!(
            r.decide(
                "1.2.3.4".parse().unwrap(),
                Some("example-unlisted-xyz.test")
            ),
            Action::Proxy
        );
    }

    #[test]
    fn decides_on_ip_when_domain_unknown() {
        let r = router();
        // No domain (the L3 case) and an unlisted IP → Proxy.
        assert_eq!(
            r.decide("203.0.113.7".parse().unwrap(), None),
            Action::Proxy
        );
    }
}
