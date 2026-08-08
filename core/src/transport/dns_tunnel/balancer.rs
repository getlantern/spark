//! Resolver pool + balancer for the DNS-tunnel client (ADR 0011 §4) — the headline resolver
//! aggregation. It parses/expands a resolver list, tracks per-resolver RTT and (half-life-decayed)
//! loss, picks which resolver(s) to send each query to (with configurable duplication), does
//! per-stream sticky failover when a resolver goes bad mid-session, and auto-disables/reactivates
//! resolvers by health.
//!
//! Pure logic, no I/O: the pump feeds it `on_success`/`on_loss` events (from `recv_from` / query
//! timeouts) and calls [`ResolverPool::pick`] to choose targets. Because the server keys sessions by
//! ConnectionID (not source address), a session's queries can be sprayed across many resolvers and the
//! answers reassemble into one tunnel — so a blocked, rate-limited, or mid-session-severed resolver
//! never kills the session as long as one healthy resolver remains.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Balancer tuning.
#[derive(Debug, Clone, Copy)]
pub struct PoolConfig {
    /// How many distinct resolvers each query is sent to (>=1). >1 trades bandwidth for delivery
    /// probability on lossy/severing paths.
    pub duplication: usize,
    /// Cap on total resolvers after CIDR expansion.
    pub max_hosts: usize,
    /// Exponential decay applied to the loss counters per sample (half-life ~ ln2/(1-decay) samples).
    pub loss_decay: f64,
    /// Minimum decayed sample count before a resolver may be auto-disabled.
    pub min_samples: f64,
    /// Windowed loss ratio (0..=1) at/above which a resolver is auto-disabled.
    pub disable_loss: f64,
    /// Re-enable a disabled resolver this many ms after it was disabled (to re-probe).
    pub reenable_after_ms: u64,
    /// Consecutive resends on the sticky resolver before failing the stream over to another.
    pub failover_streak: u32,
}

impl Default for PoolConfig {
    fn default() -> Self {
        PoolConfig {
            duplication: 1,
            max_hosts: 4096,
            loss_decay: 0.98,
            min_samples: 5.0,
            disable_loss: 0.9,
            reenable_after_ms: 30_000,
            failover_streak: 3,
        }
    }
}

/// Errors parsing the resolver list.
#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    /// A resolver spec was not parseable.
    #[error("invalid resolver spec: {0}")]
    BadSpec(String),
    /// The resolver list was empty.
    #[error("resolver pool is empty")]
    Empty,
}

#[derive(Debug)]
struct Resolver {
    addr: SocketAddr,
    /// Smoothed RTT (ms); `None` until the first success.
    srtt_ms: Option<f64>,
    /// Decayed loss / total sample counters (windowed loss ratio = loss/total).
    loss: f64,
    total: f64,
    /// Whether the resolver is currently eligible.
    enabled: bool,
    /// When it was disabled (ms), for the re-enable timer.
    disabled_at: u64,
}

impl Resolver {
    fn new(addr: SocketAddr) -> Self {
        Resolver {
            addr,
            srtt_ms: None,
            loss: 0.0,
            total: 0.0,
            enabled: true,
            disabled_at: 0,
        }
    }
    fn loss_ratio(&self) -> f64 {
        if self.total <= 0.0 {
            0.0
        } else {
            self.loss / self.total
        }
    }
    /// A lower score is healthier: loss dominates, RTT breaks ties (unknown RTT = a neutral 200ms).
    fn score(&self) -> f64 {
        self.loss_ratio() * 10_000.0 + self.srtt_ms.unwrap_or(200.0)
    }
}

/// The resolver pool + balancer.
pub struct ResolverPool {
    resolvers: Vec<Resolver>,
    cfg: PoolConfig,
    /// Round-robin cursor for spreading load among equally-healthy resolvers.
    rr: usize,
    /// The stream's current preferred ("sticky") resolver index.
    sticky: usize,
    /// Consecutive resends observed on the sticky resolver.
    resend_streak: u32,
}

impl ResolverPool {
    /// Build a pool from resolver specs: `IP`, `IP:port`, `CIDR`, `CIDR:port` (IPv4), or `[v6]`/`[v6]:port`.
    /// IPv4 CIDRs expand to host addresses (bounded by `cfg.max_hosts`); duplicates are removed;
    /// the default port is 53.
    pub fn parse(specs: &[String], cfg: PoolConfig) -> Result<Self, PoolError> {
        let mut seen = BTreeSet::new();
        let mut resolvers = Vec::new();
        for spec in specs {
            for addr in parse_spec(spec, cfg.max_hosts)? {
                if resolvers.len() >= cfg.max_hosts {
                    break;
                }
                if seen.insert(addr) {
                    resolvers.push(Resolver::new(addr));
                }
            }
        }
        if resolvers.is_empty() {
            return Err(PoolError::Empty);
        }
        Ok(ResolverPool {
            resolvers,
            cfg,
            rr: 0,
            sticky: 0,
            resend_streak: 0,
        })
    }

    /// Number of resolvers in the pool.
    pub fn len(&self) -> usize {
        self.resolvers.len()
    }

    /// Whether the pool has no resolvers (never true after a successful `parse`).
    pub fn is_empty(&self) -> bool {
        self.resolvers.is_empty()
    }

    /// Number of currently-enabled resolvers.
    pub fn enabled_count(&self) -> usize {
        self.resolvers.iter().filter(|r| r.enabled).count()
    }

    /// Re-enable any resolver whose re-probe timer has elapsed.
    fn reactivate(&mut self, now: u64) {
        let after = self.cfg.reenable_after_ms;
        for r in &mut self.resolvers {
            if !r.enabled && now.saturating_sub(r.disabled_at) >= after {
                r.enabled = true;
                // Give it a clean slate so one stale window doesn't immediately re-disable it.
                r.loss = 0.0;
                r.total = 0.0;
            }
        }
    }

    /// Choose the resolver address(es) to send the next query to: the sticky resolver plus, for
    /// duplication, the next-healthiest distinct enabled resolvers. Falls back to re-enabling
    /// everything if all are disabled (better to try a bad resolver than stall).
    pub fn pick(&mut self, now: u64) -> Vec<SocketAddr> {
        self.reactivate(now);
        if self.enabled_count() == 0 {
            for r in &mut self.resolvers {
                r.enabled = true;
            }
        }
        // Health-ranked list of enabled indices.
        let mut ranked: Vec<usize> = (0..self.resolvers.len())
            .filter(|&i| self.resolvers[i].enabled)
            .collect();
        ranked.sort_by(|&a, &b| {
            self.resolvers[a]
                .score()
                .partial_cmp(&self.resolvers[b].score())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        if ranked.is_empty() {
            return Vec::new();
        }
        // Ensure the sticky index is valid + enabled; otherwise adopt the healthiest.
        if !self
            .resolvers
            .get(self.sticky)
            .map(|r| r.enabled)
            .unwrap_or(false)
        {
            self.sticky = ranked[0];
        }

        let want = self.cfg.duplication.max(1).min(ranked.len());
        let mut out = Vec::with_capacity(want);
        out.push(self.resolvers[self.sticky].addr);
        // Fill remaining duplication slots from the healthiest others (round-robin among ties).
        for k in 0..ranked.len() {
            if out.len() >= want {
                break;
            }
            let idx = ranked[(self.rr + k) % ranked.len()];
            let addr = self.resolvers[idx].addr;
            if !out.contains(&addr) {
                out.push(addr);
            }
        }
        self.rr = self.rr.wrapping_add(1);
        out
    }

    /// The current sticky resolver's address (for telemetry/tests).
    pub fn sticky_addr(&self) -> Option<SocketAddr> {
        self.resolvers.get(self.sticky).map(|r| r.addr)
    }

    /// A representative resolver address — used to choose the client UDP socket's address family.
    pub fn any_addr(&self) -> SocketAddr {
        self.resolvers[0].addr
    }

    fn index_of(&self, addr: &SocketAddr) -> Option<usize> {
        self.resolvers.iter().position(|r| &r.addr == addr)
    }

    fn decay(r: &mut Resolver, decay: f64) {
        r.loss *= decay;
        r.total *= decay;
    }

    /// Record that `addr` answered a query in `rtt_ms` — updates its RTT and loss window, and clears
    /// the failover streak (the sticky path is making progress).
    pub fn on_success(&mut self, addr: &SocketAddr, rtt_ms: u64) {
        let decay = self.cfg.loss_decay;
        if let Some(i) = self.index_of(addr) {
            let r = &mut self.resolvers[i];
            Self::decay(r, decay);
            r.total += 1.0;
            r.srtt_ms = Some(match r.srtt_ms {
                None => rtt_ms as f64,
                Some(s) => 0.875 * s + 0.125 * rtt_ms as f64,
            });
            if i == self.sticky {
                self.resend_streak = 0;
            }
        }
    }

    /// Record that a query sent to `addrs` was lost (timed out with no answer). Updates each
    /// resolver's loss window (auto-disabling any that cross the loss threshold) and, if the sticky
    /// resolver's resend streak crosses `failover_streak`, fails the stream over to a healthier one.
    pub fn on_loss(&mut self, addrs: &[SocketAddr], now: u64) {
        let (decay, min_s, disable) = (
            self.cfg.loss_decay,
            self.cfg.min_samples,
            self.cfg.disable_loss,
        );
        let mut sticky_hit = false;
        for addr in addrs {
            if let Some(i) = self.index_of(addr) {
                let r = &mut self.resolvers[i];
                Self::decay(r, decay);
                r.total += 1.0;
                r.loss += 1.0;
                if r.enabled && r.total >= min_s && r.loss_ratio() >= disable {
                    r.enabled = false;
                    r.disabled_at = now;
                }
                if i == self.sticky {
                    sticky_hit = true;
                }
            }
        }
        if sticky_hit {
            self.resend_streak += 1;
            let sticky_ok = self
                .resolvers
                .get(self.sticky)
                .map(|r| r.enabled)
                .unwrap_or(false);
            if self.resend_streak >= self.cfg.failover_streak || !sticky_ok {
                self.failover(now);
            }
        }
    }

    /// Move the sticky preference to the healthiest *other* enabled resolver.
    fn failover(&mut self, now: u64) {
        self.reactivate(now);
        let current = self.sticky;
        let best = (0..self.resolvers.len())
            .filter(|&i| i != current && self.resolvers[i].enabled)
            .min_by(|&a, &b| {
                self.resolvers[a]
                    .score()
                    .partial_cmp(&self.resolvers[b].score())
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
        if let Some(b) = best {
            self.sticky = b;
            self.resend_streak = 0;
        }
    }
}

/// Resolvers supplied by the host platform, for systems where the OS list cannot be read from a
/// file. Empty until a host sets it.
///
/// `RwLock`, not `OnceLock`: the set changes when the device roams between networks, and the host
/// re-pushes it each time (on Android the tunnel restarts on every default-network change, so this
/// is refreshed at exactly the moment the old list goes stale).
static PLATFORM_RESOLVERS: std::sync::RwLock<Vec<String>> = std::sync::RwLock::new(Vec::new());

/// Install the host platform's DNS resolvers, as pool specs (`ip:53`, IPv6 as `[ip]:53`).
///
/// **Android needs this and nothing else does.** Android has no `/etc/resolv.conf` — it resolves
/// through netd, and the resolver list is only reachable via
/// `ConnectivityManager.getLinkProperties(network).getDnsServers()` on the Java side. Without it
/// [`system_resolvers`] returns empty, `dns_tunnel_transport` refuses to build for want of any
/// resolver, and the bootstrap DNS-tunnel member — the last-resort reachability tier — silently
/// drops out of the config-fetch race on every Android device. (sing-box solves the same problem the
/// same way, via its platform interface; ours is one-way because the host already restarts the
/// tunnel on network change.)
///
/// Passing an empty list is meaningful: it clears the previous one rather than keeping a stale
/// network's resolvers.
///
/// **Log hygiene:** never log the values (spark rule: never a resolver IP). Log the count.
pub fn set_platform_resolvers(resolvers: Vec<String>) {
    match PLATFORM_RESOLVERS.write() {
        Ok(mut slot) => *slot = resolvers,
        // A poisoned lock means a writer panicked mid-swap; the Vec is still structurally sound, so
        // take it over rather than lose resolver discovery for the process lifetime.
        Err(poisoned) => *poisoned.into_inner() = resolvers,
    }
}

/// The OS-configured DNS resolver(s), as pool specs (`ip:53`, IPv6 as `[ip]:53`).
///
/// Host-supplied list first ([`set_platform_resolvers`]) — on Android that is the only source. Then
/// `/etc/resolv.conf`'s `nameserver` lines on Unix; other platforms return empty for now (a
/// follow-up can add the Windows adapter API). Used to auto-include the local resolver — during a
/// national shutdown the mandated local/ISP resolver is often the only one that still forwards DNS,
/// so it's the lifeline.
///
/// **Log hygiene:** callers must not log the returned IPs (spark rule: never log resolver IPs).
pub fn system_resolvers() -> Vec<String> {
    let platform = match PLATFORM_RESOLVERS.read() {
        Ok(slot) => slot.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    };
    if !platform.is_empty() {
        return platform;
    }
    #[cfg(unix)]
    {
        std::fs::read_to_string("/etc/resolv.conf")
            .map(|s| parse_resolv_conf(&s))
            .unwrap_or_default()
    }
    #[cfg(not(unix))]
    {
        Vec::new()
    }
}

/// Parse a host-supplied resolver list — the comma-separated bare IPs the Android side reads out of
/// `LinkProperties` — into pool specs. Invalid entries are dropped rather than failing the batch: a
/// malformed one must not cost us the others, and the caller has no way to fix it.
///
/// Deliberately no fallback to public resolvers when the result is empty (author direction): a
/// device with no discoverable resolver simply gets no DNS-tunnel member. Shipping hardcoded public
/// resolvers would be weaker under a shutdown than the OS one anyway, and it would put a fixed,
/// blockable list in every binary.
pub fn parse_platform_resolvers(csv: &str) -> Vec<String> {
    csv.split(',')
        .filter_map(|s| s.trim().parse::<IpAddr>().ok())
        .map(|ip| match ip {
            IpAddr::V4(v4) => format!("{v4}:53"),
            IpAddr::V6(v6) => format!("[{v6}]:53"),
        })
        .collect()
}

/// Parse `nameserver` lines from `resolv.conf` content into pool specs (`ip:53`; IPv6 bracketed as
/// `[ip]:53` so [`parse_spec`] accepts it). Comments (`#`/`;`) and non-`nameserver` directives are
/// skipped, as are unparseable addresses.
// Pure parser, but only *called* from the `#[cfg(unix)]` arm of `system_resolvers` (its unit test
// exercises it on every platform). Allow it to be unused off-Unix so `clippy -D warnings` (which
// implies `-D dead-code`) stays green on Windows.
#[cfg_attr(not(unix), allow(dead_code))]
fn parse_resolv_conf(contents: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let mut it = line.split_whitespace();
        if it.next() != Some("nameserver") {
            continue;
        }
        match it.next().and_then(|s| s.parse::<IpAddr>().ok()) {
            Some(IpAddr::V4(v4)) => out.push(format!("{v4}:53")),
            Some(IpAddr::V6(v6)) => out.push(format!("[{v6}]:53")),
            None => {}
        }
    }
    out
}

/// Parse one resolver spec into concrete `SocketAddr`s (expanding an IPv4 CIDR), defaulting port 53.
fn parse_spec(spec: &str, max_hosts: usize) -> Result<Vec<SocketAddr>, PoolError> {
    let spec = spec.trim();
    let bad = || PoolError::BadSpec(spec.to_string());

    // IPv6 in brackets: `[addr]` or `[addr]:port`. (No IPv6-CIDR expansion in v1.)
    if spec.starts_with('[') {
        return spec.parse::<SocketAddr>().map(|s| vec![s]).or_else(|_| {
            let inner = spec.trim_start_matches('[').trim_end_matches(']');
            inner
                .parse::<IpAddr>()
                .map(|ip| vec![SocketAddr::new(ip, 53)])
                .map_err(|_| bad())
        });
    }

    // Split an optional `:port` suffix (only when there's exactly one ':', so IPv6 literals aren't
    // mis-split; those must use brackets).
    let (host_part, port) = match spec.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => {
            let port: u16 = p.parse().map_err(|_| bad())?;
            (h, port)
        }
        _ => (spec, 53u16),
    };

    // CIDR?
    if let Some((base, prefix)) = host_part.split_once('/') {
        let base: Ipv4Addr = base.parse().map_err(|_| bad())?;
        let prefix: u32 = prefix.parse().map_err(|_| bad())?;
        if prefix > 32 {
            return Err(bad());
        }
        let count = 1u64 << (32 - prefix);
        let base_u = u32::from(base) & (!0u32).checked_shl(32 - prefix).unwrap_or(0);
        let n = count.min(max_hosts as u64) as usize;
        let mut out = Vec::with_capacity(n);
        for i in 0..n as u64 {
            let ip = Ipv4Addr::from(base_u.wrapping_add(i as u32));
            out.push(SocketAddr::new(IpAddr::V4(ip), port));
        }
        return Ok(out);
    }

    // Plain IPv4 (or a bracket-less IPv6 that happens to parse as an IpAddr with the default port).
    if let Ok(ip) = host_part.parse::<Ipv4Addr>() {
        return Ok(vec![SocketAddr::new(IpAddr::V4(ip), port)]);
    }
    if let Ok(ip) = host_part.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    Err(bad())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(specs: &[&str], cfg: PoolConfig) -> ResolverPool {
        let owned: Vec<String> = specs.iter().map(|s| s.to_string()).collect();
        ResolverPool::parse(&owned, cfg).unwrap()
    }

    #[test]
    fn parses_ips_ports_and_expands_cidr() {
        let p = pool(
            &["1.1.1.1", "8.8.8.8:5353", "9.9.9.0/30", "1.1.1.1"],
            PoolConfig::default(),
        );
        // 1.1.1.1:53, 8.8.8.8:5353, 9.9.9.0..3:53 → 2 + 4 = 6 (the duplicate 1.1.1.1 is deduped).
        assert_eq!(p.len(), 6);
    }

    #[test]
    fn cidr_expansion_is_bounded() {
        let cfg = PoolConfig {
            max_hosts: 100,
            ..PoolConfig::default()
        };
        // /16 is 65536 hosts; capped at max_hosts.
        let p = pool(&["10.0.0.0/16"], cfg);
        assert_eq!(p.len(), 100);
    }

    /// The Android path: a comma-separated `LinkProperties.getDnsServers()` list becomes pool specs.
    ///
    /// The empty case is the load-bearing one — it is what a device with no discoverable resolver
    /// produces, and it must yield no resolvers (hence no DNS-tunnel member) rather than anything
    /// invented. Author direction: no fallback to public resolvers.
    #[test]
    fn parses_platform_resolver_list() {
        assert_eq!(
            parse_platform_resolvers("8.8.8.8, 1.1.1.1 ,2606:4700:4700::1111"),
            vec![
                "8.8.8.8:53".to_string(),
                "1.1.1.1:53".to_string(),
                "[2606:4700:4700::1111]:53".to_string(),
            ]
        );
        // A malformed entry is dropped, never the whole batch: the caller cannot fix it, and one
        // bad address must not cost us the working ones.
        assert_eq!(
            parse_platform_resolvers("not-an-ip,9.9.9.9"),
            vec!["9.9.9.9:53".to_string()]
        );
        // Nothing discoverable ⇒ nothing invented.
        assert!(parse_platform_resolvers("").is_empty());
        assert!(parse_platform_resolvers("  ,  ").is_empty());
    }

    /// A host-supplied list takes precedence over `/etc/resolv.conf`, and clearing it falls back.
    ///
    /// Android has no resolv.conf at all, so the override IS the source there; the precedence only
    /// becomes visible on a Unix host, which is where this runs.
    #[test]
    fn platform_resolvers_override_and_clear() {
        set_platform_resolvers(vec!["203.0.113.53:53".to_string()]);
        assert_eq!(system_resolvers(), vec!["203.0.113.53:53".to_string()]);
        // Clearing must not strand the previous network's resolvers.
        set_platform_resolvers(Vec::new());
        assert!(!system_resolvers().contains(&"203.0.113.53:53".to_string()));
    }

    #[test]
    fn parses_resolv_conf_nameservers() {
        let sample = "\
# a comment
; another comment
nameserver 8.8.8.8
nameserver   1.1.1.1
search example.com
options edns0
nameserver 2606:4700:4700::1111
nameserver not-an-ip
";
        let specs = parse_resolv_conf(sample);
        assert_eq!(
            specs,
            vec![
                "8.8.8.8:53".to_string(),
                "1.1.1.1:53".to_string(),
                "[2606:4700:4700::1111]:53".to_string(),
            ]
        );
        // The emitted specs must round-trip through the pool parser (v4 + bracketed v6).
        let p = ResolverPool::parse(&specs, PoolConfig::default()).unwrap();
        assert_eq!(p.len(), 3);
    }

    #[test]
    fn rejects_garbage_and_empty() {
        assert!(ResolverPool::parse(&["not-an-ip".to_string()], PoolConfig::default()).is_err());
        assert!(ResolverPool::parse(&[], PoolConfig::default()).is_err());
    }

    #[test]
    fn pick_returns_duplication_distinct_resolvers() {
        let cfg = PoolConfig {
            duplication: 3,
            ..PoolConfig::default()
        };
        let mut p = pool(&["1.1.1.1", "8.8.8.8", "9.9.9.9", "8.8.4.4"], cfg);
        let picked = p.pick(0);
        assert_eq!(picked.len(), 3);
        let uniq: BTreeSet<_> = picked.iter().collect();
        assert_eq!(uniq.len(), 3, "duplication targets are distinct");
    }

    #[test]
    fn high_loss_disables_then_reactivates() {
        let cfg = PoolConfig {
            min_samples: 3.0,
            disable_loss: 0.8,
            reenable_after_ms: 10_000,
            duplication: 1,
            ..PoolConfig::default()
        };
        let mut p = pool(&["1.1.1.1", "8.8.8.8"], cfg);
        let bad: SocketAddr = "1.1.1.1:53".parse().unwrap();
        // Hammer 1.1.1.1 with losses → it gets disabled.
        for _ in 0..10 {
            p.on_loss(&[bad], 1_000);
        }
        assert_eq!(p.enabled_count(), 1, "the lossy resolver is auto-disabled");
        // After the re-enable window, it comes back.
        let _ = p.pick(1_000 + 10_000);
        assert_eq!(
            p.enabled_count(),
            2,
            "disabled resolver is reactivated after the timer"
        );
    }

    #[test]
    fn sticky_fails_over_after_resend_streak() {
        let cfg = PoolConfig {
            failover_streak: 3,
            duplication: 1,
            // Keep losses from disabling so we isolate the failover path.
            min_samples: 1_000.0,
            ..PoolConfig::default()
        };
        let mut p = pool(&["1.1.1.1", "8.8.8.8"], cfg);
        let first = p.sticky_addr().unwrap();
        // Losses on the sticky resolver, past the streak → switch to the other.
        for _ in 0..3 {
            p.on_loss(&[first], 0);
        }
        let now = p.sticky_addr().unwrap();
        assert_ne!(now, first, "the stream failed over to a different resolver");
    }

    #[test]
    fn healthiest_resolver_is_preferred() {
        let cfg = PoolConfig {
            duplication: 1,
            ..PoolConfig::default()
        };
        let mut p = pool(&["1.1.1.1", "8.8.8.8"], cfg);
        let good: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let bad: SocketAddr = "1.1.1.1:53".parse().unwrap();
        // 8.8.8.8 answers quickly; 1.1.1.1 accrues loss (but not enough to disable).
        for _ in 0..3 {
            p.on_success(&good, 20);
            p.on_loss(&[bad], 0);
        }
        // A fresh stream (reset sticky to the healthiest) prefers the good resolver.
        p.sticky = usize::MAX; // force pick() to re-adopt the healthiest
        let picked = p.pick(0);
        assert_eq!(picked[0], good, "the healthier resolver is chosen");
    }
}
