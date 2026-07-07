//! Per-flow routing decision.
//!
//! Given a destination — the IP (always known) and the domain (known once the fake-IP DNS layer
//! recovers it in M4; `None` at L3) — [`Router::decide`] returns the [`Action`]. It is a thin,
//! precedence-aware wrapper over the compact [`Matcher`]: the matcher is built with the rule-sets
//! in descending precedence (ad_block → route.rules → smart_routing), and anything it doesn't
//! match falls back to [`Action::Proxy`] — the config's `route.final` (the bandit pool).

use std::net::IpAddr;
use std::sync::RwLock;

use tracing::warn;

use super::matcher::Matcher;
use super::srs::{parse, IpCidr, RuleSet};
use super::Action;
use crate::config::{RouteAction, RuleSetRef, SmartRoutingConfig};

/// Decides the [`Action`] for each flow: a small, live-swappable user **bypass** matcher checked
/// first (any match => `Direct`, absolute), then the immutable base matcher from the fetched rules.
pub struct Router {
    base: Matcher,
    /// The user's split-tunnel bypass, compiled to its own tiny matcher; `None` = disabled/empty.
    /// Swapped live via [`set_user_bypass`](Router::set_user_bypass). Read per flow-open (not per
    /// packet) and never held across `.await`, so a plain `RwLock` is fine.
    user_bypass: RwLock<Option<Matcher>>,
    /// The routing mode. Full = suppress base Direct/Proxy and proxy everything not user-bypassed
    /// (ad-block Reject still honored). Swapped live like `user_bypass`.
    mode: RwLock<crate::routing_mode::RoutingMode>,
}

impl Router {
    /// Wrap a compiled base [`Matcher`] (built from the fetched rule-sets). The user bypass starts
    /// empty; seed it with [`set_user_bypass`](Router::set_user_bypass).
    pub fn new(base: Matcher) -> Self {
        Self {
            base,
            user_bypass: RwLock::new(None),
            mode: RwLock::new(crate::routing_mode::RoutingMode::default()),
        }
    }

    /// Replace the live user-bypass matcher. `Some(st)` with `st.enabled` and non-empty compiles a
    /// one-entry Direct matcher from its domains/IPs; anything else clears it. This is the live-reload
    /// entry point — only this tiny matcher is rebuilt; the base matcher is untouched.
    pub fn set_user_bypass(&self, st: Option<&crate::split_tunnel::SplitTunnel>) {
        let matcher = st.filter(|s| s.enabled && !s.is_empty()).map(|s| {
            Matcher::build(vec![(
                Action::Direct,
                RuleSet::from_domains_and_ips(&s.domains, &s.ips),
            )])
        });
        // Recover from a poisoned lock (`into_inner`) and apply the update rather than dropping it —
        // the inner Option is trivially consistent, and a poisoning event must not silently freeze or
        // disable split-tunnel bypass.
        *self.user_bypass.write().unwrap_or_else(|e| e.into_inner()) = matcher;
    }

    /// Set the routing mode live (poison-tolerant recovery, like `set_user_bypass`).
    pub fn set_mode(&self, mode: crate::routing_mode::RoutingMode) {
        *self.mode.write().unwrap_or_else(|e| e.into_inner()) = mode;
    }

    /// Build a router from the parsed [`SmartRoutingConfig`]. `load` supplies each rule-set's raw
    /// `.srs` bytes — from the on-disk cache in production, or fixtures in tests; a rule-set that
    /// fails to load or parse is skipped with a warning (never fatal — the tunnel still runs). The
    /// matcher is assembled in spec precedence order: ad_block (Reject) → inline `route.rules` →
    /// `smart_routing`, so cross-action conflicts resolve highest-first.
    pub fn build(
        sr: &SmartRoutingConfig,
        mut load: impl FnMut(&RuleSetRef) -> Option<Vec<u8>>,
    ) -> Self {
        let mut entries: Vec<(Action, RuleSet)> = Vec::new();

        // 1. ad_block rule-sets → Reject (highest precedence).
        for r in sr
            .rule_sets
            .iter()
            .filter(|r| r.action == RouteAction::Reject)
        {
            if let Some(rs) = load_ruleset(&mut load, r) {
                entries.push((Action::Reject, rs));
            }
        }
        // 2. inline route.rules (IP/CIDR), grouped per action, above smart_routing.
        for action in [RouteAction::Reject, RouteAction::Direct, RouteAction::Proxy] {
            let ip_cidr: Vec<IpCidr> = sr
                .inline_ip_rules
                .iter()
                .filter(|ir| ir.action == action)
                .filter_map(|ir| parse_cidr(&ir.cidr))
                .collect();
            if !ip_cidr.is_empty() {
                entries.push((map_action(action), RuleSet::ip_only(ip_cidr)));
            }
        }
        // 3. smart_routing rule-sets (non-Reject, e.g. Direct).
        for r in sr
            .rule_sets
            .iter()
            .filter(|r| r.action != RouteAction::Reject)
        {
            if let Some(rs) = load_ruleset(&mut load, r) {
                entries.push((map_action(r.action), rs));
            }
        }
        Router::new(Matcher::build(entries))
    }

    /// The action for a flow. The live user **bypass** wins (absolute) — any match => `Direct`;
    /// otherwise the base rules decide, and an unmatched flow is proxied (`route.final`). `domain`
    /// is `Some` once the fake-IP DNS layer recovers it (M4); at L3 it is `None`, so only IP/CIDR
    /// rules (base or bypass) can match.
    pub fn decide(&self, ip: IpAddr, domain: Option<&str>) -> Action {
        // Recover from a poisoned lock (`into_inner`) rather than silently skipping the bypass — the
        // inner matcher is always consistent, so a poisoning event must not quietly disable
        // split-tunnel bypass (and this per-flow path must not log-spam on every call).
        {
            let guard = self.user_bypass.read().unwrap_or_else(|e| e.into_inner());
            if let Some(m) = guard.as_ref() {
                if m.lookup(domain, ip).is_some() {
                    return Action::Direct;
                }
            }
        }
        let full = matches!(
            *self.mode.read().unwrap_or_else(|e| e.into_inner()),
            crate::routing_mode::RoutingMode::Full
        );
        match self.base.lookup(domain, ip) {
            Some(Action::Reject) => Action::Reject, // ad-block always wins
            Some(a) if !full => a,                  // Smart: base decides
            _ => Action::Proxy,                     // Full (or unmatched) → Proxy
        }
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

/// Map the config-layer [`RouteAction`] to the engine's [`Action`].
fn map_action(a: RouteAction) -> Action {
    match a {
        RouteAction::Proxy => Action::Proxy,
        RouteAction::Direct => Action::Direct,
        RouteAction::Reject => Action::Reject,
    }
}

/// Load + parse a rule-set's `.srs`, or `None` (logged) if it's missing or malformed. Never fatal:
/// a skipped rule-set just doesn't contribute rules — the tunnel still runs (proxy-everything for
/// the missing lists).
fn load_ruleset(
    load: &mut impl FnMut(&RuleSetRef) -> Option<Vec<u8>>,
    r: &RuleSetRef,
) -> Option<RuleSet> {
    let Some(bytes) = load(r) else {
        warn!(tag = %r.tag, "rules: rule-set unavailable; skipping");
        return None;
    };
    match parse(&bytes) {
        Ok(rs) => Some(rs),
        Err(e) => {
            warn!(tag = %r.tag, error = %e, "rules: failed to parse .srs; skipping");
            None
        }
    }
}

/// Parse `"a.b.c.d/len"` (or an IPv6 CIDR) into an [`IpCidr`]; `None` (logged) if malformed or the
/// prefix is out of range for the address family.
fn parse_cidr(s: &str) -> Option<IpCidr> {
    let (addr_s, prefix_s) = s.split_once('/')?;
    let addr: IpAddr = addr_s.trim().parse().ok()?;
    let prefix: u8 = prefix_s.trim().parse().ok()?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        warn!(cidr = %s, "rules: inline ip rule prefix out of range; skipping");
        return None;
    }
    Some(IpCidr { addr, prefix })
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn build_from_config_with_loader_and_inline_rules() {
        use crate::config::{InlineIpRule, RouteAction, RuleSetRef, SmartRoutingConfig};
        let sr = SmartRoutingConfig {
            rule_sets: vec![
                RuleSetRef {
                    action: RouteAction::Reject,
                    tag: "banad".into(),
                    url: "u".into(),
                },
                RuleSetRef {
                    action: RouteAction::Direct,
                    tag: "common".into(),
                    url: "u".into(),
                },
            ],
            inline_ip_rules: vec![InlineIpRule {
                cidr: "9.9.9.9/32".into(),
                action: RouteAction::Direct,
            }],
        };
        // Loader maps each rule-set's tag to the matching fixture file's bytes (production reads the
        // on-disk cache instead).
        let r = Router::build(&sr, |rs| {
            let name = match rs.tag.as_str() {
                "banad" => "banad_v1",
                "common" => "common_v3",
                _ => return None,
            };
            std::fs::read(format!("tests/fixtures/srs/{name}.srs")).ok()
        });
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        // ad_block list (Reject) beat everything.
        assert_eq!(r.decide(ip, Some("doubleclick.net")), Action::Reject);
        // smart_routing common list → Direct.
        assert_eq!(r.decide(ip, Some("app.discord.com")), Action::Direct);
        // inline route.rule: Quad9 IP → Direct even with no domain (L3).
        assert_eq!(r.decide("9.9.9.9".parse().unwrap(), None), Action::Direct);
        // unlisted → Proxy.
        assert_eq!(r.decide(ip, Some("nope-unlisted.test")), Action::Proxy);
    }

    #[test]
    fn user_bypass_forces_direct_and_beats_reject() {
        use crate::split_tunnel::SplitTunnel;
        let r = router(); // has doubleclick.net at Reject (ad_block)
                          // Before: an ad domain is Reject.
        assert_eq!(
            r.decide("1.2.3.4".parse().unwrap(), Some("doubleclick.net")),
            Action::Reject
        );
        // Add it to the bypass list -> Direct (absolute, wins over Reject).
        r.set_user_bypass(Some(&SplitTunnel {
            enabled: true,
            domains: vec!["doubleclick.net".into()],
            ips: vec![],
        }));
        assert_eq!(
            r.decide("1.2.3.4".parse().unwrap(), Some("doubleclick.net")),
            Action::Direct
        );
        // Subdomain of a bypass entry also Direct.
        assert_eq!(
            r.decide("1.2.3.4".parse().unwrap(), Some("ads.doubleclick.net")),
            Action::Direct
        );
        // A non-bypassed domain still follows base rules.
        assert_eq!(
            r.decide("1.2.3.4".parse().unwrap(), Some("app.discord.com")),
            Action::Direct
        ); // base
           // Removing the bypass restores base behavior.
        r.set_user_bypass(None);
        assert_eq!(
            r.decide("1.2.3.4".parse().unwrap(), Some("doubleclick.net")),
            Action::Reject
        );
    }

    #[test]
    fn user_bypass_ignored_when_disabled_or_empty() {
        use crate::split_tunnel::SplitTunnel;
        let r = router();
        r.set_user_bypass(Some(&SplitTunnel {
            enabled: false,
            domains: vec!["doubleclick.net".into()],
            ips: vec![],
        }));
        assert_eq!(
            r.decide("1.2.3.4".parse().unwrap(), Some("doubleclick.net")),
            Action::Reject
        );
        r.set_user_bypass(Some(&SplitTunnel {
            enabled: true,
            domains: vec![],
            ips: vec![],
        }));
        assert_eq!(
            r.decide("1.2.3.4".parse().unwrap(), Some("doubleclick.net")),
            Action::Reject
        );
    }

    #[test]
    fn user_bypass_matches_ip() {
        use crate::split_tunnel::SplitTunnel;
        let r = router();
        r.set_user_bypass(Some(&SplitTunnel {
            enabled: true,
            domains: vec![],
            ips: vec!["203.0.113.7".into()],
        }));
        assert_eq!(
            r.decide("203.0.113.7".parse().unwrap(), None),
            Action::Direct
        );
    }

    #[test]
    fn user_bypass_matches_cidr_range() {
        use crate::split_tunnel::SplitTunnel;
        let r = router();
        r.set_user_bypass(Some(&SplitTunnel {
            enabled: true,
            domains: vec![],
            ips: vec!["10.0.0.0/8".into()],
        }));
        // An address inside the bypassed CIDR routes Direct.
        assert_eq!(r.decide("10.1.2.3".parse().unwrap(), None), Action::Direct);
        // An address outside it follows base rules (unlisted => Proxy).
        assert_eq!(r.decide("192.0.2.1".parse().unwrap(), None), Action::Proxy);
    }

    #[test]
    fn build_skips_unloadable_rulesets_without_failing() {
        use crate::config::{RouteAction, RuleSetRef, SmartRoutingConfig};
        let sr = SmartRoutingConfig {
            rule_sets: vec![RuleSetRef {
                action: RouteAction::Reject,
                tag: "missing".into(),
                url: "u".into(),
            }],
            inline_ip_rules: Vec::new(),
        };
        // Loader returns None for everything → the router builds with no rules; all flows proxy.
        let r = Router::build(&sr, |_| None);
        assert_eq!(
            r.decide("1.2.3.4".parse().unwrap(), Some("doubleclick.net")),
            Action::Proxy
        );
    }

    #[test]
    fn full_tunnel_forces_proxy_but_keeps_reject_and_bypass() {
        use crate::routing_mode::RoutingMode;
        use crate::split_tunnel::SplitTunnel;
        let r = router(); // doubleclick.net → Reject; app.discord.com → Direct (base)
        r.set_mode(RoutingMode::Full);
        // A base-Direct domain is forced to Proxy in Full Tunnel.
        assert_eq!(
            r.decide("1.2.3.4".parse().unwrap(), Some("app.discord.com")),
            Action::Proxy
        );
        // Ad-block Reject still applies.
        assert_eq!(
            r.decide("1.2.3.4".parse().unwrap(), Some("doubleclick.net")),
            Action::Reject
        );
        // Split-tunnel bypass still routes Direct even in Full Tunnel.
        r.set_user_bypass(Some(&SplitTunnel {
            enabled: true,
            domains: vec!["app.discord.com".into()],
            ips: vec![],
        }));
        assert_eq!(
            r.decide("1.2.3.4".parse().unwrap(), Some("app.discord.com")),
            Action::Direct
        );
        // Back to Smart → base rules again (bypass cleared).
        r.set_user_bypass(None);
        r.set_mode(RoutingMode::Smart);
        assert_eq!(
            r.decide("1.2.3.4".parse().unwrap(), Some("app.discord.com")),
            Action::Direct
        );
    }
}
