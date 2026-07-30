//! Rule-based traffic routing: parse sing-box `.srs` rule-sets, match a flow's destination, and
//! decide whether it is proxied, sent direct, or rejected.
//!
//! Distinct from [`crate::routing`], which manages the OS route table (pointing the default route
//! at the TUN). This module is the *policy* layer: given a destination — an IP, and (via the
//! fake-IP DNS layer) a domain — it returns an [`Action`].
//!
//! Pipeline: [`srs`] parses `.srs` rule-sets → [`matcher`] builds a compact matcher → [`router`]
//! makes the per-flow decision.

pub mod matcher;
pub mod router;
pub mod ruleset;
pub mod srs;

/// The routing decision for a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Send through the proxy pool (the config's `auto` / `route.final`) — the default.
    Proxy,
    /// Dial directly on a protected socket, bypassing the proxy (unblocked traffic).
    Direct,
    /// Dial directly **with circumvention** (ADR 0014): un-poisoned resolution plus
    /// opening-handshake shaping, still with no proxy and no exit hop.
    ///
    /// Separate from [`Direct`](Self::Direct) on purpose — "direct" means a plain connection with no
    /// tricks, and redefining it would change every existing rule's behaviour.
    Proxyless,
    /// Drop the flow (`ad_block`: ads / malware / phishing).
    Reject,
}
