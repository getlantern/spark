# Spark Split Tunneling (domain-based) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let users route chosen domains/IPs **around** the tunnel ("bypass the VPN"), configured from a Split Tunneling UI, applied **live** while connected, with the routing logic shared in `core/` so it works on desktop (macOS/Tauri) now and Android next.

**Architecture:** A user "bypass" list becomes a small, **live-swappable** `Matcher` checked **before** the fetched-rules matcher in `Router` (bypass ⇒ `Direct`, absolute — wins over ad-block Reject). The list is injected into `core` at connect (macOS `providerConfiguration["splitTunnel"]` / Android `nativeRun` arg) and updated live via a runtime control handle + a `spark_set_split_tunnel` FFI (macOS provider message → NE `handleAppMessage`; Android JNI direct). The UI (Tauri/Svelte) persists the list and drives both paths through the `SparkBackend` seam.

**Tech Stack:** Rust (core + FFI), `serde`/`serde_json` (already core deps), Swift (macOS NE), SvelteKit/TypeScript + Tauri commands (desktop UI).

**Spec:** `docs/superpowers/specs/2026-07-06-spark-split-tunneling-design.md`.

**Scope of THIS plan:** shared core + Apple & Android FFI (the Android JNI signature must change for the workspace to compile) + macOS NE Swift + desktop Tauri/Svelte UI. **The Android Compose UI is a documented fast-follow (separate plan)** — Phase F below is a stub describing it.

**Standing constraints (from CLAUDE.md):** no `unwrap`/`expect` outside tests; `thiserror` at boundaries; `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean; `cargo fmt`; **whole-workspace build after any core API change** (cli + service + platforms depend on core); commit trailer `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`; never commit to `main` (work on `fisk/split-tunneling`).

---

## File structure

**Create:**
- `core/src/split_tunnel.rs` — `SplitTunnel` type, `parse`, `normalize`/`add_entries` (+ tests).
- `gui-tauri/src/routes/split-tunneling/+page.svelte` — master toggle + Apps/Websites rows.
- `gui-tauri/src/routes/split-tunneling/websites/+page.svelte` — add/remove domains.

**Modify:**
- `core/src/lib.rs` — `pub mod split_tunnel;`.
- `core/src/rules/srs.rs` — `RuleSet::from_domains_and_ips`, `parse_ip_or_cidr`.
- `core/src/rules/router.rs` — `Router { base, user_bypass }`, `decide`, `set_user_bypass`.
- `core/src/fd_tunnel.rs` — active-router control handle, `set_split_tunnel`, thread the list into `setup_routing_and_udp`, activation condition, clear on stop.
- `platforms/apple/src/lib.rs` — `spark_tunnel_run` gains `split_tunnel` arg; add `spark_set_split_tunnel`.
- `platforms/android/src/lib.rs` — `nativeRun` gains `splitTunnel` arg; add `nativeSetSplitTunnel`.
- `platforms/apple/Sources/SparkNE/PacketTunnelProvider.swift` — read `providerConfiguration["splitTunnel"]`; `handleAppMessage` `"splitTunnel"` case.
- `gui-tauri/src-tauri/src/lib.rs` — `spark_get_split_tunnel`/`spark_set_split_tunnel` commands + register; inject at connect; live push.
- `gui-tauri/src/lib/spark_backend.ts` — `SplitTunnel` type + `getSplitTunnel`/`setSplitTunnel` on the interface + `MockBackend`.
- `gui-tauri/src/lib/tauri_backend.ts` — `getSplitTunnel`/`setSplitTunnel` over `invoke`.
- `gui-tauri/src/routes/+page.svelte` — Split Tunneling row → `/split-tunneling`.

---

## Phase A — Core (shared, fully unit-tested)

### Task A1: `SplitTunnel` type + parse + normalize

**Files:**
- Create: `core/src/split_tunnel.rs`
- Modify: `core/src/lib.rs`

- [ ] **Step 1: Add the module declaration**

In `core/src/lib.rs`, add alongside the other `pub mod` lines:
```rust
pub mod split_tunnel;
```

- [ ] **Step 2: Write the failing tests** (`core/src/split_tunnel.rs`)

```rust
//! The user's split-tunnel "bypass the VPN" list — a per-device preference the UI edits and
//! injects into the tunnel. Parsed here (shared by every platform); applied by the router
//! (`crate::rules::router`). Bypass entries route Direct; see the design doc.

use serde::{Deserialize, Serialize};

/// The user's bypass list. `enabled` is the master toggle; when false the list is preserved but
/// ignored. `domains` match the host and its subdomains; `ips` are single IPs or CIDRs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SplitTunnel {
    pub enabled: bool,
    pub domains: Vec<String>,
    pub ips: Vec<String>,
}

/// The result of adding raw user text: what was kept (split into domains/ips) and what was rejected.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct AddOutcome {
    pub added_domains: Vec<String>,
    pub added_ips: Vec<String>,
    pub rejected: Vec<String>,
}

/// A parse failure at the FFI boundary.
#[derive(Debug, thiserror::Error)]
pub enum SplitTunnelError {
    #[error("invalid split-tunnel json: {0}")]
    Json(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_round_trips() {
        let st = SplitTunnel { enabled: true, domains: vec!["google.com".into()], ips: vec!["1.2.3.4".into()] };
        let json = serde_json::to_string(&st).unwrap();
        assert_eq!(parse(&json).unwrap(), st);
    }

    #[test]
    fn parse_defaults_missing_fields() {
        assert_eq!(parse("{}").unwrap(), SplitTunnel::default());
    }

    #[test]
    fn is_empty_ignores_enabled() {
        assert!(SplitTunnel { enabled: true, ..Default::default() }.is_empty());
        assert!(!SplitTunnel { enabled: false, domains: vec!["x.com".into()], ..Default::default() }.is_empty());
    }

    #[test]
    fn add_entries_splits_domains_ips_and_rejects_junk() {
        let mut st = SplitTunnel::default();
        let out = st.add_entries("google.com, https://Mail.Example.com/inbox , 1.2.3.4, 10.0.0.0/8, not a domain, ");
        assert_eq!(out.added_domains, vec!["google.com".to_string(), "mail.example.com".to_string()]);
        assert_eq!(out.added_ips, vec!["1.2.3.4".to_string(), "10.0.0.0/8".to_string()]);
        assert_eq!(out.rejected, vec!["not a domain".to_string()]);
        assert_eq!(st.domains, vec!["google.com".to_string(), "mail.example.com".to_string()]);
        assert_eq!(st.ips, vec!["1.2.3.4".to_string(), "10.0.0.0/8".to_string()]);
    }

    #[test]
    fn add_entries_dedupes_against_existing() {
        let mut st = SplitTunnel { enabled: true, domains: vec!["google.com".into()], ips: vec![] };
        let out = st.add_entries("google.com, GOOGLE.com, x.com");
        assert_eq!(out.added_domains, vec!["x.com".to_string()]); // google.com already present
        assert_eq!(st.domains, vec!["google.com".to_string(), "x.com".to_string()]);
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p spark-core --lib split_tunnel`
Expected: FAIL to **compile** — `parse`, `is_empty`, `add_entries` not defined.

- [ ] **Step 4: Implement `parse`, `is_empty`, `normalize`, `add_entries`**

Add to `core/src/split_tunnel.rs` (above the tests):
```rust
impl SplitTunnel {
    /// No entries (regardless of `enabled`).
    pub fn is_empty(&self) -> bool {
        self.domains.is_empty() && self.ips.is_empty()
    }

    /// Add comma-separated raw user text: each token is normalized, classified as an IP/CIDR or a
    /// plausible hostname, and appended if not already present. Returns what was added vs rejected so
    /// the UI can flag bad entries. Invalid tokens are neither added nor silently dropped.
    pub fn add_entries(&mut self, raw: &str) -> AddOutcome {
        let mut out = AddOutcome::default();
        for token in raw.split(',') {
            let host = normalize_one(token);
            if host.is_empty() {
                continue; // an empty field (trailing comma / whitespace) is not a rejection
            }
            if crate::rules::srs::parse_ip_or_cidr(&host).is_some() {
                if !self.ips.iter().any(|e| e == &host) {
                    self.ips.push(host.clone());
                    out.added_ips.push(host);
                }
            } else if is_plausible_hostname(&host) {
                if !self.domains.iter().any(|e| e == &host) {
                    self.domains.push(host.clone());
                    out.added_domains.push(host);
                }
            } else {
                out.rejected.push(token.trim().to_string());
            }
        }
        out
    }
}

/// Parse the JSON payload the platforms serialize (`{enabled, domains, ips}`).
pub fn parse(json: &str) -> Result<SplitTunnel, SplitTunnelError> {
    serde_json::from_str(json).map_err(|e| SplitTunnelError::Json(e.to_string()))
}

/// Normalize one raw entry to a bare host: trim, lowercase, strip a URL scheme, drop any
/// path/query/fragment (`https://Mail.Example.com/inbox` → `mail.example.com`).
fn normalize_one(entry: &str) -> String {
    let mut e = entry.trim().to_ascii_lowercase();
    for scheme in ["https://", "http://"] {
        if let Some(rest) = e.strip_prefix(scheme) {
            e = rest.to_string();
            break;
        }
    }
    if let Some(idx) = e.find(['/', '?', '#']) {
        e.truncate(idx);
    }
    e.trim().to_string()
}

/// A minimal hostname sanity check (not full RFC): at least one dot, only letters/digits/`-`/`.`,
/// no leading/trailing/adjacent dots. Keeps obvious junk ("not a domain") out of the list.
fn is_plausible_hostname(h: &str) -> bool {
    !h.starts_with('.')
        && !h.ends_with('.')
        && !h.contains("..")
        && h.contains('.')
        && h.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p spark-core --lib split_tunnel`
Expected: PASS (5 tests). (Depends on Task A2's `parse_ip_or_cidr`; if A2 isn't done yet, do A2 first — they're a pair. Recommended order: A2 then A1's Step 4/5.)

- [ ] **Step 6: Commit**

```bash
git add core/src/split_tunnel.rs core/src/lib.rs
git commit -m "feat(core): SplitTunnel type + parse/normalize for split tunneling"
```

### Task A2: `RuleSet::from_domains_and_ips` + `parse_ip_or_cidr`

**Files:**
- Modify: `core/src/rules/srs.rs`

- [ ] **Step 1: Write the failing tests**

Add to the `#[cfg(test)] mod tests` in `core/src/rules/srs.rs`:
```rust
    #[test]
    fn parse_ip_or_cidr_accepts_bare_ip_and_cidr() {
        assert_eq!(parse_ip_or_cidr("1.2.3.4").unwrap().prefix, 32);
        assert_eq!(parse_ip_or_cidr("10.0.0.0/8").unwrap().prefix, 8);
        assert_eq!(parse_ip_or_cidr("::1").unwrap().prefix, 128);
        assert!(parse_ip_or_cidr("nope").is_none());
        assert!(parse_ip_or_cidr("1.2.3.4/40").is_none()); // out of range
    }

    #[test]
    fn from_domains_and_ips_fills_suffix_and_cidr() {
        let rs = RuleSet::from_domains_and_ips(&["google.com".to_string()], &["1.2.3.4".to_string()]);
        assert_eq!(rs.domain_suffix, vec!["google.com".to_string()]);
        assert_eq!(rs.ip_cidr.len(), 1);
        assert!(rs.domain.is_empty() && rs.domain_keyword.is_empty());
    }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p spark-core --lib rules::srs::tests::from_domains_and_ips rules::srs::tests::parse_ip_or_cidr`
Expected: FAIL to compile — functions not defined.

- [ ] **Step 3: Implement**

In `core/src/rules/srs.rs`, add a `parse_ip_or_cidr` free function near `IpCidr` (ensure `use std::net::IpAddr;` is present at the top — it is, via `IpCidr`), and a `RuleSet::from_domains_and_ips` constructor next to `ip_only`:
```rust
/// Parse a bare IP (`1.2.3.4`, `::1`) or a CIDR (`10.0.0.0/8`) into an [`IpCidr`]. A bare IP gets a
/// host prefix (/32 or /128). `None` on malformed input or an out-of-range prefix.
pub fn parse_ip_or_cidr(s: &str) -> Option<IpCidr> {
    let s = s.trim();
    match s.split_once('/') {
        Some((addr_s, prefix_s)) => {
            let addr: IpAddr = addr_s.trim().parse().ok()?;
            let prefix: u8 = prefix_s.trim().parse().ok()?;
            let max = if addr.is_ipv4() { 32 } else { 128 };
            (prefix <= max).then_some(IpCidr { addr, prefix })
        }
        None => {
            let addr: IpAddr = s.parse().ok()?;
            let prefix = if addr.is_ipv4() { 32 } else { 128 };
            Some(IpCidr { addr, prefix })
        }
    }
}
```
And in `impl RuleSet`:
```rust
    /// A rule-set from the user's split-tunnel bypass list: domains become suffix matches (host +
    /// subdomains), IPs/CIDRs become `ip_cidr`. Unparseable IP entries are dropped (the UI validates
    /// on add, so this is belt-and-suspenders).
    pub fn from_domains_and_ips(domains: &[String], ips: &[String]) -> Self {
        Self {
            domain: Vec::new(),
            domain_suffix: domains.to_vec(),
            domain_keyword: Vec::new(),
            ip_cidr: ips.iter().filter_map(|s| parse_ip_or_cidr(s)).collect(),
        }
    }
```

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p spark-core --lib rules::srs`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add core/src/rules/srs.rs
git commit -m "feat(core): RuleSet::from_domains_and_ips + parse_ip_or_cidr"
```

### Task A3: `Router` — base + live-swappable user bypass

**Files:**
- Modify: `core/src/rules/router.rs`

- [ ] **Step 1: Write the failing tests**

Add to `#[cfg(test)] mod tests` in `core/src/rules/router.rs`:
```rust
    #[test]
    fn user_bypass_forces_direct_and_beats_reject() {
        use crate::split_tunnel::SplitTunnel;
        let r = router(); // has doubleclick.net at Reject (ad_block)
        // Before: an ad domain is Reject.
        assert_eq!(r.decide("1.2.3.4".parse().unwrap(), Some("doubleclick.net")), Action::Reject);
        // Add it to the bypass list → Direct (absolute, wins over Reject).
        r.set_user_bypass(Some(&SplitTunnel { enabled: true, domains: vec!["doubleclick.net".into()], ips: vec![] }));
        assert_eq!(r.decide("1.2.3.4".parse().unwrap(), Some("doubleclick.net")), Action::Direct);
        // Subdomain of a bypass entry also Direct.
        assert_eq!(r.decide("1.2.3.4".parse().unwrap(), Some("ads.doubleclick.net")), Action::Direct);
        // A non-bypassed domain still follows base rules.
        assert_eq!(r.decide("1.2.3.4".parse().unwrap(), Some("app.discord.com")), Action::Direct); // base
        // Removing the bypass restores base behavior.
        r.set_user_bypass(None);
        assert_eq!(r.decide("1.2.3.4".parse().unwrap(), Some("doubleclick.net")), Action::Reject);
    }

    #[test]
    fn user_bypass_ignored_when_disabled_or_empty() {
        use crate::split_tunnel::SplitTunnel;
        let r = router();
        r.set_user_bypass(Some(&SplitTunnel { enabled: false, domains: vec!["doubleclick.net".into()], ips: vec![] }));
        assert_eq!(r.decide("1.2.3.4".parse().unwrap(), Some("doubleclick.net")), Action::Reject);
        r.set_user_bypass(Some(&SplitTunnel { enabled: true, domains: vec![], ips: vec![] }));
        assert_eq!(r.decide("1.2.3.4".parse().unwrap(), Some("doubleclick.net")), Action::Reject);
    }

    #[test]
    fn user_bypass_matches_ip() {
        use crate::split_tunnel::SplitTunnel;
        let r = router();
        r.set_user_bypass(Some(&SplitTunnel { enabled: true, domains: vec![], ips: vec!["203.0.113.7".into()] }));
        assert_eq!(r.decide("203.0.113.7".parse().unwrap(), None), Action::Direct);
    }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p spark-core --lib rules::router`
Expected: FAIL to compile — `set_user_bypass` not defined.

- [ ] **Step 3: Restructure `Router`**

In `core/src/rules/router.rs`, add `use std::sync::RwLock;` and replace the struct + `new` + `decide` (lines ~18–80):
```rust
/// Decides the [`Action`] for each flow: a small, live-swappable user **bypass** matcher checked
/// first (any match ⇒ `Direct`, absolute), then the immutable base matcher from the fetched rules.
pub struct Router {
    base: Matcher,
    /// The user's split-tunnel bypass, compiled to its own tiny matcher; `None` = disabled/empty.
    /// Swapped live via [`set_user_bypass`](Router::set_user_bypass). Read per flow-open (not per
    /// packet) and never held across `.await`, so a plain `RwLock` is fine.
    user_bypass: RwLock<Option<Matcher>>,
}

impl Router {
    /// Wrap a compiled base [`Matcher`] (built from the fetched rule-sets). The user bypass starts
    /// empty; seed it with [`set_user_bypass`](Router::set_user_bypass).
    pub fn new(base: Matcher) -> Self {
        Self { base, user_bypass: RwLock::new(None) }
    }

    /// Replace the live user-bypass matcher. `Some(st)` with `st.enabled` and non-empty compiles a
    /// one-entry Direct matcher from its domains/IPs; anything else clears it. This is the live-reload
    /// entry point — only this tiny matcher is rebuilt; the base matcher is untouched.
    pub fn set_user_bypass(&self, st: Option<&crate::split_tunnel::SplitTunnel>) {
        let matcher = st
            .filter(|s| s.enabled && !s.is_empty())
            .map(|s| Matcher::build(vec![(Action::Direct, RuleSet::from_domains_and_ips(&s.domains, &s.ips))]));
        if let Ok(mut guard) = self.user_bypass.write() {
            *guard = matcher;
        }
    }

    /// The action for a flow. User bypass wins (absolute); otherwise the base rules; otherwise Proxy.
    pub fn decide(&self, ip: IpAddr, domain: Option<&str>) -> Action {
        if let Ok(guard) = self.user_bypass.read() {
            if let Some(m) = guard.as_ref() {
                if m.lookup(domain, ip).is_some() {
                    return Action::Direct;
                }
            }
        }
        self.base.lookup(domain, ip).unwrap_or(Action::Proxy)
    }
}
```
Leave `Router::build` (it calls `Router::new(Matcher::build(entries))` — still valid), `impl FlowRouter for Router` (calls `Router::decide` — unchanged), and the helpers as-is.

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p spark-core --lib rules::router`
Expected: PASS (existing 3 tests + 3 new).

- [ ] **Step 5: Commit**

```bash
git add core/src/rules/router.rs
git commit -m "feat(core): live-swappable user bypass matcher in Router"
```

### Task A4: `fd_tunnel` — control handle, `set_split_tunnel`, wiring, activation

**Files:**
- Modify: `core/src/fd_tunnel.rs`

- [ ] **Step 1: Add the active-router control handle + FFI-facing update**

In `core/src/fd_tunnel.rs`, near the existing `pool()`/`set_pool()` (around line 57), add (gate the whole block on `#[cfg(feature = "smart-routing")]` since `Router` is feature-gated):
```rust
/// The running tunnel's router, registered at connect so the live split-tunnel update
/// ([`set_split_tunnel`]) can reach it, and cleared on teardown. One tunnel per process (like the
/// pool handle), so a single global suffices.
#[cfg(feature = "smart-routing")]
fn active_router() -> &'static Mutex<Option<Arc<crate::rules::router::Router>>> {
    static R: OnceLock<Mutex<Option<Arc<crate::rules::router::Router>>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(None))
}

#[cfg(feature = "smart-routing")]
fn set_active_router(r: Option<Arc<crate::rules::router::Router>>) {
    *active_router().lock().unwrap() = r;
}

/// Update the running tunnel's split-tunnel bypass list live (no reconnect). `json` is the
/// `{enabled,domains,ips}` payload. Returns `true` if applied, `false` if the JSON was invalid or no
/// router is active (e.g. not connected, or connected with no smart-routing path — see the design's
/// activation caveat). Called across the platform FFI (Apple C-ABI / Android JNI).
#[cfg(feature = "smart-routing")]
pub fn set_split_tunnel(json: &str) -> bool {
    let Ok(st) = crate::split_tunnel::parse(json) else {
        return false;
    };
    match active_router().lock().unwrap().as_ref() {
        Some(r) => {
            r.set_user_bypass(Some(&st));
            true
        }
        None => false,
    }
}

/// Without `smart-routing`, live split-tunnel updates are unsupported.
#[cfg(not(feature = "smart-routing"))]
pub fn set_split_tunnel(_json: &str) -> bool {
    false
}
```

- [ ] **Step 2: Thread the initial list into `run_fd_dispatch` → data path → `setup_routing_and_udp`**

Change these signatures/calls (add an `Option<&str>` carrying the raw split-tunnel JSON):

`run_fd_dispatch` (line 198):
```rust
pub fn run_fd_dispatch(
    fd: i32,
    mtu: u16,
    config: Option<&str>,
    data_dir: Option<&std::path::Path>,
    tun_base: Config,
    split_tunnel: Option<&str>,
) -> i32 {
```
Thread `split_tunnel` through every path it dispatches to (`run_tunnel_data_path` at 336, and the self-fetch `run_fd_lantern_api` at 552, whichever it calls) down to `setup_routing_and_udp`. Add a `split_tunnel: Option<&str>` param to `run_tunnel_data_path` and `run_fd_lantern_api`, forwarding it to `setup_routing_and_udp`.

`setup_routing_and_udp` (line 418, `#[cfg(feature = "smart-routing")]` variant) — add the param and parse it:
```rust
fn setup_routing_and_udp(
    config: &Config,
    data_dir: Option<&std::path::Path>,
    udp_surface: Option<netstack::UdpSurface>,
    udp_transport: Arc<dyn transport::UdpTransport>,
    direct_udp: Arc<dyn transport::UdpTransport>,
    idle: Duration,
    split_tunnel: Option<&str>,
) -> Option<Arc<proxy::RouteHooks>> {
    let sr = &config.smart_routing;
    // The user's split-tunnel bypass list (a per-device pref injected at connect), if any.
    let user_bypass = split_tunnel
        .and_then(|j| crate::split_tunnel::parse(j).ok())
        .filter(|s| s.enabled && !s.is_empty());
    let has_rules = !sr.rule_sets.is_empty() || !sr.inline_ip_rules.is_empty();
    let (hooks, dns_server) = if !has_rules && user_bypass.is_none() {
        (None, None) // no fetched rules and no bypass — proxy everything (today's path)
    } else {
        let router = crate::rules::router::Router::build(sr, |r| {
            let dir = data_dir?;
            std::fs::read(crate::rules::ruleset::cache_path(dir, &r.tag)).ok()
        });
        router.set_user_bypass(user_bypass.as_ref());
        let router = Arc::new(router);
        set_active_router(Some(router.clone()));
        let pool = dns::server::shared_pool(FAKEIP_TTL, FAKEIP_CAP);
        let hooks = Arc::new(proxy::RouteHooks {
            router: router as Arc<dyn proxy::FlowRouter>,
            recoverer: Some(Arc::new(dns::server::FakeIpRecoverer::new(pool.clone()))),
            direct_resolver: dns::resolver::direct_resolver(&config.dns),
            proxy_resolver: dns::resolver::proxy_resolver(&config.dns),
        });
        let dns_server = Arc::new(dns::server::DnsServer::new(pool, DNS_ANSWER_TTL_SECS));
        info!(
            rule_sets = sr.rule_sets.len(),
            inline_ip_rules = sr.inline_ip_rules.len(),
            user_bypass = user_bypass.as_ref().map_or(0, |s| s.domains.len() + s.ips.len()),
            "smart-routing: fake-IP DNS + per-flow route hooks active"
        );
        (Some(hooks), Some(dns_server))
    };
    // ... unchanged UDP wiring below ...
```
Update the `#[cfg(not(feature = "smart-routing"))]` variant of `setup_routing_and_udp` (line 493) to accept and ignore the new `_split_tunnel: Option<&str>` param.

- [ ] **Step 3: Clear the handle on teardown**

In `pub fn stop()` (line 683) — after signaling stop — clear the router so a stale one can't be updated after teardown:
```rust
    #[cfg(feature = "smart-routing")]
    set_active_router(None);
```
(Place it alongside the existing `set_pool(None)` if present, or at the end of `stop`.)

- [ ] **Step 4: Update every `run_fd_dispatch` call site to the new arity**

Two in-repo Rust callers (the CLI does NOT call it): `platforms/apple/src/lib.rs` and `platforms/android/src/lib.rs` — done in Phase B. For now, to keep core compiling in isolation, this task's build check is core-only:

Run: `cargo build -p spark-core --all-features`
Expected: compiles. (`cargo build --workspace` will fail until Phase B updates the shims — expected; Phase B closes it.)

- [ ] **Step 5: Commit**

```bash
git add core/src/fd_tunnel.rs
git commit -m "feat(core): wire split-tunnel bypass into fd_tunnel + live set_split_tunnel handle"
```

### Task A5: Core gate

- [ ] **Step 1: Format + clippy + test the core crate**

```bash
cargo fmt -p spark-core
cargo clippy -p spark-core --all-features --all-targets -- -D warnings
cargo test -p spark-core --lib split_tunnel rules::router rules::srs
```
Expected: clean; all split-tunnel/router/srs tests pass.

- [ ] **Step 2: Commit any fmt fixes**

```bash
git add -A && git commit -m "chore(core): fmt/clippy for split tunneling" --allow-empty
```

---

## Phase B — Platform FFI (Apple + Android)

### Task B1: Apple C-ABI — `spark_tunnel_run` arg + `spark_set_split_tunnel`

**Files:**
- Modify: `platforms/apple/src/lib.rs`

- [ ] **Step 1: Add the `split_tunnel` param to `spark_tunnel_run`**

Change the signature (line 55) to add `split_tunnel: *const c_char` after `data_dir`, decode it like `config` (null → `None`; non-null invalid UTF-8 → treat as `None`, since a bad bypass list must not fail the whole tunnel), and pass it to `run_fd_dispatch`:
```rust
    pub unsafe extern "C" fn spark_tunnel_run(
        fd: c_int,
        mtu: c_int,
        config: *const c_char,
        data_dir: *const c_char,
        split_tunnel: *const c_char,
    ) -> c_int {
        // ... existing cfg + dir decoding ...
        // SAFETY: caller contract — `split_tunnel` is null or a valid NUL-terminated C string.
        let split: Option<&str> = if split_tunnel.is_null() {
            None
        } else {
            unsafe { CStr::from_ptr(split_tunnel) }.to_str().ok()
        };
        spark_core::fd_tunnel::run_fd_dispatch(fd, mtu as u16, cfg, dir.as_deref(), Config::default(), split)
    }
```

- [ ] **Step 2: Add `spark_set_split_tunnel`**

Next to `spark_servers_json` (line 150), add:
```rust
    /// Update the running tunnel's split-tunnel bypass list live. `json` is a NUL-terminated
    /// `{enabled,domains,ips}` payload. Returns 0 if applied, -1 on invalid JSON / no active tunnel.
    ///
    /// # Safety
    /// `json` must be null or a valid NUL-terminated C string.
    #[no_mangle]
    pub unsafe extern "C" fn spark_set_split_tunnel(json: *const c_char) -> c_int {
        if json.is_null() {
            return -1;
        }
        match unsafe { CStr::from_ptr(json) }.to_str() {
            Ok(s) if spark_core::fd_tunnel::set_split_tunnel(s) => 0,
            _ => -1,
        }
    }
```

- [ ] **Step 3: Add the header declaration**

If `platforms/apple/…/spark.h` (or the generated header) lists `spark_servers_json` etc., add:
```c
int spark_set_split_tunnel(const char *json);
```
(Find it: `grep -rn spark_servers_json platforms/apple` and mirror the location/style.)

- [ ] **Step 4: Verify the Apple crate builds**

Run: `cargo build -p spark-apple --features anytls,multi-server,bootstrap-dns,config-fetch,samizdat,shadowsocks,hysteria2,fronted-meek,smart-routing`
Expected: compiles.

- [ ] **Step 5: Commit**

```bash
git add platforms/apple/src/lib.rs platforms/apple/*.h 2>/dev/null; git commit -m "feat(apple-ffi): split_tunnel connect arg + spark_set_split_tunnel"
```

### Task B2: Android JNI — `nativeRun` arg + `nativeSetSplitTunnel`

**Files:**
- Modify: `platforms/android/src/lib.rs`
- Modify: `platforms/android/demo/app/src/main/kotlin/org/getlantern/spark/SparkBridge.kt`

- [ ] **Step 1: Add the `splitTunnel` param to `nativeRun` (JNI)**

In `platforms/android/src/lib.rs`, add `split_tunnel: JString<'local>` after `data_dir` in `Java_org_getlantern_spark_SparkBridge_nativeRun` (line 53), decode it leniently (null/bad → `None`; a bad bypass list must not fail the tunnel), and forward:
```rust
        let split = read_jstring(&mut env, &split_tunnel).ok().flatten();
        spark_core::fd_tunnel::run_fd_dispatch(
            fd,
            mtu as u16,
            cfg.as_deref(),
            dir.as_deref(),
            tun_base,
            split.as_deref(),
        )
```

- [ ] **Step 2: Add `nativeSetSplitTunnel` (JNI)**

Next to `nativeSelectServer` (mirror its shape), add:
```rust
    /// `SparkBridge.nativeSetSplitTunnel(json)` — update the running tunnel's bypass list live.
    /// Returns true if applied.
    #[no_mangle]
    pub extern "system" fn Java_org_getlantern_spark_SparkBridge_nativeSetSplitTunnel<'local>(
        mut env: JNIEnv<'local>,
        _obj: JObject<'local>,
        json: JString<'local>,
    ) -> jni::sys::jboolean {
        match read_jstring(&mut env, &json) {
            Ok(Some(s)) => spark_core::fd_tunnel::set_split_tunnel(&s) as jni::sys::jboolean,
            _ => 0,
        }
    }
```

- [ ] **Step 3: Declare the externs in Kotlin**

In `SparkBridge.kt`, update `nativeRun` to add the `splitTunnel: String?` parameter (last), and add:
```kotlin
    /** Update the running tunnel's split-tunnel bypass list live. Returns true if applied. */
    external fun nativeSetSplitTunnel(json: String): Boolean
```
Update the existing `nativeRun` caller(s) in `SparkVpnService.kt`/`VpnController.kt` to pass the persisted list (or `null` for now — the Compose UI wiring is Phase F).

- [ ] **Step 4: Build the Android core lib**

Run: `cargo build -p spark-android --features <android feature set>` (mirror `spark-ffi/android` build flags; if unsure: `cargo build -p spark-android`).
Expected: compiles.

- [ ] **Step 5: Commit**

```bash
git add platforms/android/src/lib.rs platforms/android/demo/app/src/main/kotlin/org/getlantern/spark/SparkBridge.kt platforms/android/demo/app/src/main/kotlin/org/getlantern/spark/*.kt
git commit -m "feat(android-ffi): nativeRun splitTunnel arg + nativeSetSplitTunnel"
```

### Task B3: Whole-workspace gate

- [ ] **Step 1: Build + clippy the whole workspace (all features)**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
```
Expected: clean. (This is the CLAUDE.md whole-workspace gate — cli/service/platforms all compile against the new core.)

- [ ] **Step 2: Commit**

```bash
git add -A && git commit -m "chore: whole-workspace green after split-tunnel FFI" --allow-empty
```

---

## Phase C — macOS NE (Swift)

### Task C1: Read `providerConfiguration["splitTunnel"]` at start

**Files:**
- Modify: `platforms/apple/Sources/SparkNE/PacketTunnelProvider.swift`

- [ ] **Step 1: Pass the initial list to `spark_tunnel_run`**

In `startTunnel` (line 67), where it reads `providerConfiguration["config"]` (line ~111) and calls `spark_tunnel_run(...)`, also read the optional `"splitTunnel"` string and pass it as the new 5th arg. Example (adapt to the existing call style):
```swift
let split = (provider?["splitTunnel"] as? String)
// ... existing config/dataDir C-string setup ...
let rc = split.withCStringOrNull { splitPtr in
    spark_tunnel_run(fd, mtu, configPtr, dataDirPtr, splitPtr)
}
```
(Use the same NUL-terminated `withCString`/null pattern already used for `config`/`dataDir`; if there's no helper, pass `nil` when `split == nil`.)

- [ ] **Step 2: Build the NE**

Run: `platforms/apple/build-xcframework.sh` (or `cargo build -p spark-apple ...` from B1 plus a Swift build if the harness has one). Minimum: confirm the Swift compiles as part of the xcframework/app build in Phase E's manual step.
Expected: builds.

- [ ] **Step 3: Commit**

```bash
git add platforms/apple/Sources/SparkNE/PacketTunnelProvider.swift
git commit -m "feat(macos-ne): pass providerConfiguration[splitTunnel] to spark_tunnel_run"
```

### Task C2: `handleAppMessage` `"splitTunnel"` case (live reload)

**Files:**
- Modify: `platforms/apple/Sources/SparkNE/PacketTunnelProvider.swift`

- [ ] **Step 1: Add the case**

In `handleAppMessage` (line 206), alongside `case "servers"` / `case "select"`, add:
```swift
        case "splitTunnel":
            // The app sends {"cmd":"splitTunnel","list":"<json>"} where <json> is {enabled,domains,ips}.
            let listJson = (obj["list"] as? String) ?? "{}"
            let rc = listJson.withCString { spark_set_split_tunnel($0) }
            log.notice("handleAppMessage: splitTunnel rc=\(rc)")
            completionHandler?(#"{"ok":\#(rc == 0 ? "true" : "false")}"#.data(using: .utf8))
```
(Match the exact reply-encoding style used by the `select` case.)

- [ ] **Step 2: Commit**

```bash
git add platforms/apple/Sources/SparkNE/PacketTunnelProvider.swift
git commit -m "feat(macos-ne): handleAppMessage splitTunnel -> spark_set_split_tunnel"
```

---

## Phase D — Desktop Tauri commands

### Task D1: Persist + expose `spark_get_split_tunnel` / `spark_set_split_tunnel`

**Files:**
- Modify: `gui-tauri/src-tauri/src/lib.rs`
- Modify: `gui-tauri/src-tauri/src/config.rs`

- [ ] **Step 1: Persistence helpers (config.rs)**

Add to `gui-tauri/src-tauri/src/config.rs` a small on-disk store for the bypass list (a JSON file in the app config dir), reusing `serde_json` (already available to src-tauri):
```rust
use std::path::PathBuf;

/// The persisted split-tunnel list path (app config dir). Created lazily.
fn split_tunnel_path() -> Option<PathBuf> {
    // Mirror however this crate already resolves an app dir; fall back to the OS config dir.
    let base = dirs_next_or_config_dir()?; // implement per existing pattern in this file
    Some(base.join("spark").join("split_tunnel.json"))
}

/// Read the persisted list, or the default `{enabled:false,...}` if none/unreadable.
pub fn load_split_tunnel() -> String {
    split_tunnel_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .unwrap_or_else(|| "{\"enabled\":false,\"domains\":[],\"ips\":[]}".to_string())
}

/// Persist the list (best-effort; returns an error string on failure).
pub fn save_split_tunnel(json: &str) -> Result<(), String> {
    let p = split_tunnel_path().ok_or("no config dir")?;
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    std::fs::write(&p, json).map_err(|e| e.to_string())
}
```
(Implement `dirs_next_or_config_dir` per whatever this file already uses to find app paths; if it uses Tauri's `PathResolver`, thread `AppHandle` into the commands instead. Keep it consistent with existing code in this file.)

- [ ] **Step 2: Commands + register (lib.rs)**

Add (macOS variant pushes live when connected; non-macOS just persists):
```rust
#[tauri::command]
fn spark_get_split_tunnel() -> Result<String, String> {
    Ok(config::load_split_tunnel())
}

#[cfg(target_os = "macos")]
#[tauri::command(async)]
fn spark_set_split_tunnel(json: String) -> Result<(), String> {
    config::save_split_tunnel(&json)?; // persist for the next connect
    // If connected, push live via the NE control channel (best-effort; ignore when down).
    let (_, raw) = ne_spike::load_first_status(std::time::Duration::from_secs(2));
    if ne_spike::ui_state(raw) == "connected" {
        let msg = serde_json::json!({"cmd":"splitTunnel","list": json}).to_string();
        let _ = ne_spike::send_provider_message(msg);
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
#[tauri::command]
fn spark_set_split_tunnel(json: String) -> Result<(), String> {
    config::save_split_tunnel(&json)
}
```
Register both in `invoke_handler` (line 691):
```rust
        .invoke_handler(tauri::generate_handler![
            spark_status, spark_connect, spark_disconnect,
            spark_servers, spark_select_server,
            spark_get_split_tunnel, spark_set_split_tunnel
        ])
```

- [ ] **Step 3: Inject the initial list at connect**

In the macOS `spark_connect` path (line 590) / the `ne_spike::connect` provider-configuration builder (line ~334, where the `"config"` key NSDictionary is built), add a `"splitTunnel"` key set to `config::load_split_tunnel()` so the NE receives it at start. Keep it out when the list is disabled/empty to avoid needless payload (optional).

- [ ] **Step 4: Build**

Run: `cd gui-tauri/src-tauri && cargo build`
Expected: compiles (both macOS and non-macOS cfg paths).

- [ ] **Step 5: Commit**

```bash
git add gui-tauri/src-tauri/src/lib.rs gui-tauri/src-tauri/src/config.rs
git commit -m "feat(tauri): split-tunnel get/set commands, persist + inject + live push"
```

---

## Phase E — Desktop UI (SvelteKit)

### Task E1: Backend seam (`SplitTunnel` type + Mock + Tauri)

**Files:**
- Modify: `gui-tauri/src/lib/spark_backend.ts`
- Modify: `gui-tauri/src/lib/tauri_backend.ts`

- [ ] **Step 1: Extend the interface + Mock**

In `spark_backend.ts` add:
```ts
export interface SplitTunnel {
  enabled: boolean;
  domains: string[];
  ips: string[];
}

// (add to interface SparkBackend)
  getSplitTunnel(): Promise<SplitTunnel>;
  setSplitTunnel(st: SplitTunnel): Promise<void>;
```
In `MockBackend` add an in-memory field + methods:
```ts
  private split: SplitTunnel = { enabled: false, domains: [], ips: [] };
  async getSplitTunnel(): Promise<SplitTunnel> { return structuredClone(this.split); }
  async setSplitTunnel(st: SplitTunnel): Promise<void> { this.split = structuredClone(st); }
```

- [ ] **Step 2: TauriBackend methods**

In `tauri_backend.ts`:
```ts
  async getSplitTunnel(): Promise<SplitTunnel> {
    return JSON.parse(await invoke<string>("spark_get_split_tunnel"));
  }
  async setSplitTunnel(st: SplitTunnel): Promise<void> {
    await invoke("spark_set_split_tunnel", { json: JSON.stringify(st) });
  }
```
Add `SplitTunnel` to the import from `./spark_backend`.

- [ ] **Step 3: Type-check**

Run: `cd gui-tauri && npm run check`
Expected: 0 errors.

- [ ] **Step 4: Commit**

```bash
git add gui-tauri/src/lib/spark_backend.ts gui-tauri/src/lib/tauri_backend.ts
git commit -m "feat(ui): SplitTunnel backend seam (interface + Mock + Tauri)"
```

### Task E2: Home — Split Tunneling row

**Files:**
- Modify: `gui-tauri/src/routes/+page.svelte`

- [ ] **Step 1: Add a Split Tunneling nav row + icon + state**

After the Routing row (line ~186), add a divider + a button row that navigates to `/split-tunneling`, showing `Enabled`/`Disabled`. Load the state on mount via the backend. Mirror the existing Smart-location button pattern (line 146) and the `route()` snippet style. Add a `split()` branch-icon snippet (from the Figma: a fork/branch glyph):
```svelte
  <div class="divider"></div>
  <!-- Split Tunneling row -->
  <button class="tile nav" onclick={() => goto("/split-tunneling")}>
    <div class="tile-head">
      <span class="ic">{@render split()}</span>
      <span class="label">Split Tunneling</span>
    </div>
    <div class="tile-body">
      <span class="value">{splitEnabled ? "Enabled" : "Disabled"}</span>
      <span class="chev">{@render chevron()}</span>
    </div>
  </button>
```
Script additions (near the other state/backend setup at the top):
```svelte
  let splitEnabled = $state(false);
  onMount(async () => {
    try { splitEnabled = (await backend.getSplitTunnel()).enabled; } catch {}
  });
```
Snippet (near the other `{#snippet ...}` blocks):
```svelte
{#snippet split()}
  <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M6 3v6a4 4 0 0 0 4 4h8"/><path d="M6 21v-6"/><polyline points="15 9 19 13 15 17"/></svg>
{/snippet}
```
(If `onMount`/`backend` aren't already imported/instantiated in this file, add them the same way `servers/+page.svelte` does.)

- [ ] **Step 2: Type-check + eyeball in dev**

Run: `cd gui-tauri && npm run check && npm run dev`
Expected: 0 type errors; the home shows a "Split Tunneling — Disabled ›" row that navigates.

- [ ] **Step 3: Commit**

```bash
git add gui-tauri/src/routes/+page.svelte
git commit -m "feat(ui): Split Tunneling row on the home control panel"
```

### Task E3: `/split-tunneling` screen (toggle + Apps/Websites rows)

**Files:**
- Create: `gui-tauri/src/routes/split-tunneling/+page.svelte`

- [ ] **Step 1: Build the screen**

Mirror `servers/+page.svelte` structure (appbar with back arrow + title; scroll; card). Card 1 = the master toggle ("Split Tunneling" / "Add apps & websites to bypass the VPN"). When enabled, show two rows: **Apps** (disabled, "Coming soon") and **Websites** (`{n} Sites ›` → `/split-tunneling/websites`). Load/persist via the backend; toggling writes immediately (live push happens in the Tauri command).
```svelte
<script lang="ts">
  import { onMount } from "svelte";
  import { goto } from "$app/navigation";
  import { MockBackend, type SparkBackend, type SplitTunnel } from "$lib/spark_backend";
  import { TauriBackend, isTauri } from "$lib/tauri_backend";

  const backend: SparkBackend = isTauri() ? new TauriBackend() : new MockBackend();
  let st = $state<SplitTunnel>({ enabled: false, domains: [], ips: [] });

  onMount(async () => { try { st = await backend.getSplitTunnel(); } catch {} });

  async function toggle() {
    st = { ...st, enabled: !st.enabled };
    try { await backend.setSplitTunnel(st); } catch {}
  }
  const siteCount = $derived(st.domains.length + st.ips.length);
</script>

<main class="app">
  <header class="appbar">
    <button class="iconbtn" aria-label="Back" onclick={() => goto("/")}>
      <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
    </button>
    <span class="title">Split Tunneling</span>
  </header>

  <div class="scroll">
    <div class="card">
      <div class="row toggle-row">
        <div class="meta"><div class="name">Split Tunneling</div><div class="sub">Add apps &amp; websites to bypass the VPN</div></div>
        <button class="switch" class:on={st.enabled} role="switch" aria-checked={st.enabled} onclick={toggle}><span class="knob"></span></button>
      </div>
    </div>

    {#if st.enabled}
      <div class="card" style="margin-top:12px">
        <button class="row" disabled>
          <span class="ic" aria-hidden="true">▦</span>
          <div class="meta"><div class="name">Apps</div><div class="sub">Coming soon</div></div>
        </button>
        <div class="divider"></div>
        <button class="row" onclick={() => goto("/split-tunneling/websites")}>
          <span class="ic" aria-hidden="true">🌐</span>
          <div class="meta"><div class="name">Websites</div></div>
          <span class="pill">{siteCount} Sites</span>
          <span class="chev">›</span>
        </button>
      </div>
    {/if}
  </div>
</main>

<style>
  /* Reuse the token vocabulary from servers/+page.svelte (var(--surface|border|brand|text-*)).
     Copy the .app/.appbar/.iconbtn/.title/.scroll/.card/.row/.meta/.name/.sub/.divider/.chev/.pill
     rules from servers/+page.svelte; add the toggle switch below. */
  .toggle-row { justify-content: space-between; }
  .switch { width: 46px; height: 28px; border-radius: 999px; border: none; background: #c8ccce; position: relative; cursor: pointer; transition: background .15s ease; }
  .switch.on { background: var(--brand, #1f9d55); }
  .knob { position: absolute; top: 3px; left: 3px; width: 22px; height: 22px; border-radius: 50%; background: #fff; transition: transform .15s ease; }
  .switch.on .knob { transform: translateX(18px); }
  .row[disabled] { opacity: .5; cursor: default; }
</style>
```
(Copy the shared card/row style rules from `servers/+page.svelte` so the look matches; keep only the switch-specific additions here.)

- [ ] **Step 2: Check + dev**

Run: `cd gui-tauri && npm run check && npm run dev`
Expected: toggling flips the switch, reveals Apps/Websites; Websites navigates.

- [ ] **Step 3: Commit**

```bash
git add gui-tauri/src/routes/split-tunneling/+page.svelte
git commit -m "feat(ui): split-tunneling screen (toggle + Apps/Websites rows)"
```

### Task E4: `/split-tunneling/websites` screen (add/remove domains) + snackbar

**Files:**
- Create: `gui-tauri/src/routes/split-tunneling/websites/+page.svelte`

- [ ] **Step 1: Build the screen**

"Enter URL or IP Address" input + **Add** (comma-separated), helper text, then "Websites bypassing the VPN (N):" list with ✕ removal; empty state "No websites selected". On any change, persist via `backend.setSplitTunnel` and show a snackbar. Client-side normalize/validate mirrors core (strip scheme/path, lowercase); rely on core's `add_entries` for the authoritative split, but do a light client validation for immediate feedback.
```svelte
<script lang="ts">
  import { onMount } from "svelte";
  import { goto } from "$app/navigation";
  import { MockBackend, type SparkBackend, type SplitTunnel } from "$lib/spark_backend";
  import { TauriBackend, isTauri } from "$lib/tauri_backend";

  const backend: SparkBackend = isTauri() ? new TauriBackend() : new MockBackend();
  let st = $state<SplitTunnel>({ enabled: true, domains: [], ips: [] });
  let entry = $state("");
  let snack = $state<string | null>(null);
  let changed = false;

  onMount(async () => { try { st = await backend.getSplitTunnel(); } catch {} });

  // A displayed row is any domain or ip; keep order domains-then-ips for a stable list.
  const rows = $derived([...st.domains, ...st.ips]);

  function normalize(raw: string): string {
    let e = raw.trim().toLowerCase().replace(/^https?:\/\//, "");
    const cut = e.search(/[\/?#]/);
    return (cut >= 0 ? e.slice(0, cut) : e).trim();
  }
  function classify(h: string): "domain" | "ip" | null {
    if (!h) return null;
    if (/^[0-9.]+$/.test(h) || h.includes(":") || /\/\d+$/.test(h)) return "ip"; // loose; core re-validates
    if (/^[a-z0-9.-]+$/.test(h) && h.includes(".") && !h.startsWith(".") && !h.endsWith(".") && !h.includes("..")) return "domain";
    return null;
  }

  async function persist(msg: string) {
    try { await backend.setSplitTunnel(st); changed = true; snack = msg; setTimeout(() => (snack = null), 2500); } catch {}
  }
  async function add() {
    let added = 0;
    for (const tok of entry.split(",")) {
      const h = normalize(tok);
      const kind = classify(h);
      if (kind === "domain" && !st.domains.includes(h)) { st.domains = [...st.domains, h]; added++; }
      else if (kind === "ip" && !st.ips.includes(h)) { st.ips = [...st.ips, h]; added++; }
    }
    entry = "";
    if (added) await persist(`Added ${added} ${added === 1 ? "site" : "sites"}`);
  }
  async function remove(host: string) {
    st.domains = st.domains.filter((d) => d !== host);
    st.ips = st.ips.filter((i) => i !== host);
    await persist("Removed");
  }
</script>

<main class="app">
  <header class="appbar">
    <button class="iconbtn" aria-label="Back" onclick={() => goto("/split-tunneling")}>
      <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
    </button>
    <span class="title">Website Split Tunneling</span>
  </header>

  <div class="scroll">
    <div class="seclabel">Enter URL or IP Address</div>
    <div class="addrow">
      <input class="input" placeholder="Enter URL" bind:value={entry} onkeydown={(e) => e.key === "Enter" && add()} />
      <button class="addbtn" onclick={add}>Add</button>
    </div>
    <p class="helper">Use commas to separate multiple URLs</p>

    <div class="header">Websites bypassing the VPN ({rows.length}):</div>
    <div class="card">
      {#if rows.length === 0}
        <div class="row empty">No websites selected</div>
      {:else}
        {#each rows as host, i (host)}
          {#if i > 0}<div class="divider"></div>{/if}
          <div class="row">
            <div class="meta"><div class="name">{host}</div></div>
            <button class="x" aria-label="Remove" onclick={() => remove(host)}>✕</button>
          </div>
        {/each}
      {/if}
    </div>
  </div>

  {#if snack}<div class="snack">{snack}</div>{/if}
</main>

<style>
  /* Reuse the shared .app/.appbar/.iconbtn/.title/.scroll/.seclabel/.helper/.header/.card/.row/.meta/.name/.divider
     rules from servers/+page.svelte; additions below. */
  .addrow { display: flex; align-items: center; gap: 12px; }
  .input { flex: 1; height: 48px; border: 1px solid var(--border); border-radius: 12px; padding: 0 14px; font-family: var(--font); font-size: 15px; background: var(--surface); color: var(--text-primary); }
  .addbtn { border: none; background: none; color: var(--brand); font-weight: 700; font-size: 15px; cursor: pointer; text-decoration: underline; padding: 8px; }
  .row .x { border: none; background: none; color: var(--text-tertiary); font-size: 16px; cursor: pointer; padding: 6px; }
  .row.empty { color: var(--text-tertiary); }
  .snack { position: fixed; left: 16px; right: 16px; bottom: 20px; background: #23282b; color: #fff; padding: 12px 16px; border-radius: 10px; font-size: 14px; box-shadow: 0 6px 24px rgba(0,0,0,.25); }
</style>
```

- [ ] **Step 2: Check + dev**

Run: `cd gui-tauri && npm run check && npm run dev`
Expected: add `google.com, 1.2.3.4` → two rows + snackbar; ✕ removes; count updates; empty state shows when cleared.

- [ ] **Step 3: Commit**

```bash
git add gui-tauri/src/routes/split-tunneling/websites/+page.svelte
git commit -m "feat(ui): website split-tunneling add/remove + snackbar"
```

### Task E5: End-to-end verification (desktop)

- [ ] **Step 1: Full check + lint**

```bash
cd gui-tauri && npm run check
cargo fmt --all && cargo clippy --workspace --all-targets --all-features -- -D warnings
```
Expected: 0 type errors; clean clippy.

- [ ] **Step 2: On-device (notarized build)**

Per the spec's manual test: build the notarized DMG (`packaging/macos/build-tauri-dmg.sh`), install, connect. Add `whatismyipaddress.com` to the bypass list **while connected** and confirm the page shows your real IP (Direct) **without reconnecting** (live reload); remove it and confirm it returns to the tunnel IP. Confirm an ad domain added to bypass loads (absolute precedence).

- [ ] **Step 3: Commit any fixes**

```bash
git add -A && git commit -m "chore: desktop split-tunneling verification fixes" --allow-empty
```

---

## Phase F — Android Compose UI (fast-follow; SEPARATE plan)

Not implemented in this plan (the shared core + FFI it needs are delivered above; `nativeRun`
already takes `splitTunnel` and `nativeSetSplitTunnel` exists). A follow-up plan will add the same
three screens in `platforms/android/demo/app/.../ui/`, persist the list (DataStore), pass it on
connect via `nativeRun`, and push live edits via `nativeSetSplitTunnel`. Write it with the
writing-plans skill once the desktop work lands.

---

## Self-review

**Spec coverage:** master toggle (E3) ✓; Apps row deferred/disabled (E3) ✓; Websites add/remove +
comma-split + IP support + empty state + snackbar (E4) ✓; bypass=Direct absolute + subdomain +
precedence-over-Reject (A3 tests) ✓; live reload (A4 handle + B/C/D push paths + E5 manual) ✓;
inject-at-connect (C1/D3) ✓; activation when only bypass is set (A4 condition) ✓; cross-platform
core + Android FFI (B2) ✓; persistence (D1) ✓; Android UI deferred (F) ✓.

**Placeholder scan:** the two spots that intentionally defer to existing local patterns —
`dirs_next_or_config_dir` (D1) and the "copy shared style rules from servers/+page.svelte" notes
(E3/E4) — are explicit "match the existing pattern in this file" instructions, not vague TODOs. All
code steps show real code.

**Type consistency:** `SplitTunnel { enabled, domains, ips }` identical across core Rust, the JSON
payload, the TS interface, and the Tauri command (`json` string param). `set_split_tunnel` (core) /
`spark_set_split_tunnel` (FFI + Tauri cmd) / `nativeSetSplitTunnel` (JNI) / `setSplitTunnel` (TS)
consistently named per layer. `RuleSet::from_domains_and_ips` and `parse_ip_or_cidr` used exactly as
defined in A2.
