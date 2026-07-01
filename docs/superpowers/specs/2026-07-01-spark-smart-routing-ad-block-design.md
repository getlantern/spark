# Spark Smart Routing + Ad-Block — Design

**Status:** approved design (brainstorm), pending implementation plan.
**Scope:** `core/` (cross-platform — Android, Apple, desktop all consume the same Lantern config).

## Goal

Honor the `smart_routing`, `ad_block`, `route`, and `dns` sections of the Lantern
`config_raw.json` (config-new): per-flow **rule-based routing** so some traffic goes **direct**
(bypassing the proxy), some is **proxied** (the default), and some (ads / malware / phishing) is
**rejected** — driven by sing-box `.srs` rule-sets, with a footprint small enough for low-end
mobile devices.

## Background — what the config carries (today: ignored)

`config_raw.json` is sing-box-style. Spark currently maps only `options.outbounds` → the proxy
pool (`core/src/config/lantern.rs`) and **explicitly ignores** `dns` / `route` / `smart_routing` /
`ad_block`. Today every flow is full-tunnel through the bandit-selected proxy; nothing is direct or
blocked.

- **`smart_routing`** — array of categories: `{ category, rule_sets:[{tag,url(.srs)}], outbounds }`.
  Live config: one `direct` category (US-common domains → `direct`). Rule-sets are hosted at
  `getlantern/rulesets` (Lantern-controlled).
- **`ad_block`** — flat list of `{tag,url(.srs)}` to **drop**: BanAD, category-ads, malware,
  phishing, cryptominers, geoip-malware/phishing (from `KaringX/karing-ruleset`, third-party).
- **`options.route`** — `final: "auto"` (the bandit pool), base rules (e.g. `9.9.9.9/32 → direct`
  = Quad9), `default_domain_resolver: dns_local`, and an **empty `rule_set`** — i.e. the client is
  expected to compile `smart_routing` + `ad_block` into the route itself.
- **`options.dns`** — `dns_remote` (DoH), `dns_local` (DoH), `dns_fakeip` (type `fakeip`).
- `direct` / `auto` / `block` are **referenced but not defined** as outbounds — the client
  synthesizes them (`auto` = the pool spark already builds).

Rules are predominantly **domain-based** (geosite/BanAD/common), but spark operates at L3 and only
sees `original_dst` IPs — the central problem this design solves.

## Locked decisions (from brainstorm)

1. **Domain visibility = fake-IP DNS** (the config's intended model; also covers UDP/QUIC).
2. **Reduction = client-side, compact, coverage-preserving** (suffix-trie/FST + CIDR-trie; collapse
   redundant children under a covering suffix; dedupe across lists). No coverage loss; measured on a
   real low-end device. Build-time/subset reduction deferred unless measurement demands it.
3. **Write a Rust `.srs` parser** (do not re-host rule-sets as plain lists).
4. **Resolver chosen per routing decision** (below): resilient DNS only where poisoning is the
   threat; local resolver for direct (unblocked) traffic to get best local CDN IPs.
5. **Verify each step carefully** — phased milestones, each independently tested and green before
   the next.

## Architecture

The feature lives in `core/` as a **router between the netstack and the outbound**, replacing
today's single-transport `proxy::forward()`.

### Runtime data flow

```
1. app DNS query "ads.example.com" ─▶ spark DNS server (VpnService/NE already point DNS in-tunnel)
2. spark allocates a fake IP (198.18.x.x / IPv6 ULA), stores fakeip→domain (TTL/LRU), answers
3. app connects to the fake IP:443 ─▶ netstack surfaces a flow, dst = the fake IP
4. Router: fakeip→domain lookup, then match domain (+ dst IP for real-IP flows) against the
   compact matcher ─▶ Action
5. Action:
     • Proxy  → dial the DOMAIN through the pool ("auto"); exit resolves; no client DNS leak
     • Direct → resolve real IP via dns_local (local, best CDN IPs), dial directly (protected socket)
     • Reject → drop the flow (ad_block / malware)
```

Because fake-IP **defers real resolution to connect time**, the router has already chosen
direct-vs-proxy before any real lookup — so resolution uses the resolver appropriate to that action.

### New `core/` modules (each small, single-purpose, independently testable)

- **`route/srs.rs`** — the Rust `.srs` parser: sing-box compiled rule-set → entries
  (`domain`, `domain_suffix`, `domain_keyword`, `ip_cidr`; `domain_regex` skipped on mobile).
- **`route/ruleset.rs`** — fetch + disk-cache + refresh of the `.srs` URLs, mirroring the existing
  config-fetch: offline-resilient, refreshed on `poll_interval_seconds`, cached under `data_dir`.
- **`route/matcher.rs`** — the compact matcher (domain suffix-trie/FST + CIDR-trie) with the
  coverage-preserving compaction; groups entries by resulting **Action**.
- **`route/router.rs`** — per-flow decision → `Action { Proxy, Direct, Reject }`.
- **`dns/`** — the fake-IP DNS server: fake-IP allocator + `fakeip→domain` map (TTL/LRU) + a
  **local resolver** (for Direct) and an injected resilient `NameResolver` (bootstrap/blocked).
- **`config/lantern.rs`** (extended) — parse `smart_routing` / `ad_block` / `options.route` /
  `options.dns` into a `RoutingConfig`; synthesize the `direct` and `reject` outbounds.
- **`proxy/tcp.rs` + `proxy/udp.rs`** — call the Router; add the `Direct` (protected dial) and
  `Reject` (drop) actions alongside the existing pool dial.

## Rule evaluation (precedence — first match wins)

The sections are compiled into one ordered decision:

1. **`ad_block` → Reject** (highest — a malware/ad domain is dropped even if it also matches a
   direct rule).
2. **`options.route.rules`** (explicit operator rules, e.g. Quad9 `9.9.9.9/32 → direct`) — as authored.
3. **`smart_routing` categories** (e.g. US-common → Direct).
4. **`route.final` → Proxy** (the bandit pool) — the default for everything unmatched.

Ordinary sites (in no list) hit rule 4 and are proxied exactly as today.

## DNS + per-action resolver

- **Interception is free** — the Android `VpnService.Builder` already sets an in-tunnel DNS server
  (`8.8.8.8`); the Apple NE sets one too. All DNS lands in spark's DNS server.
- **Fake-IP for all A/AAAA** (v1): every resolved domain gets a fake IP from a reserved range
  (IPv4 `198.18.0.0/15`, an IPv6 ULA range), `fakeip→domain` with TTL + LRU cap. Non-A/AAAA queries
  (HTTPS/SVCB, TXT, PTR…) are forwarded upstream (resilient resolver) or dropped if unneeded.
- **Resolver is chosen per routing decision:**

  | Flow decision | Client-side resolution | Resolver |
  |---|---|---|
  | **Proxy** (`route.final`/default) | none — dial by name (exit resolves) | — |
  | **Direct** (`smart_routing`/`route.rules`) | resolve real IP, direct egress | **`dns_local`** — local/direct DoH, best local CDN IPs. Poisoning is not a concern (the domain is unblocked, which is *why* it's direct). |
  | **Reject** | none | — |
  | **Bootstrap + poisoning-risk lookups** (proxy/config-fetch hostnames) | resilient race | **`bootstrap::RacingResolver`** (un-poisoned DoH pool + `ProxyResolver`) — existing `core/src/bootstrap/`, `bootstrap-dns` feature (already enabled in the mobile build) |

  The `dns/` module has exactly two resolver seams: a **local resolver** (Direct) and the injected
  **resilient `NameResolver`** (bootstrap/blocked). The resilient stack stays where it's needed —
  getting *to* the proxies — and direct traffic gets fast local IPs.
- **`dns_remote`/`dns_local`/`dns_fakeip`** from the config are *policy/seeds* (endpoints + fakeip
  intent); resilient resolution rides spark's race rather than trusting a single blockable server.
- **Loop safety:** the resolvers' own DoH/proxy dials are spark's own sockets
  (`addDisallowedApplication` / NE bypass) — they don't re-enter the TUN, so no fake-IP loop.

## Outbound actions

- **Direct** — a protected direct dial to the resolved real IP. On Android the app's own sockets
  already bypass the tunnel via `addDisallowedApplication`; on Apple the NE bypasses. Spark already
  does direct forwarding in the no-config case, so the primitive exists.
- **Reject** — drop the flow (close/RST). New trivial action.
- **Proxy** — the existing bandit pool ("auto"), dialed by domain.

## `.srs` parser + coverage-preserving compaction

- `.srs` is sing-box's **versioned compiled binary** rule-set (magic + version; domain matchers may
  be stored as a succinct set in newer versions). **First implementation step: download the actual
  `getlantern/rulesets` and `KaringX/karing-ruleset` files and pin the exact format version(s) we
  must parse**, against the sing-box source as the authoritative spec. Parse into entries; skip
  `domain_regex` on mobile (expensive) unless measurement shows it's needed.
- **Compaction** (at matcher build): parse all rule-sets for a given Action, then
  (a) collapse any domain that a broader `domain_suffix` in the same Action already covers,
  (b) dedupe across lists, (c) merge into one compact structure per Action
  (domains → suffix-trie/FST; IPs → CIDR-trie). Coverage is preserved; memory drops sharply.
- **Footprint budget:** measured on a real low-end device (the target Redmi-class hardware) against
  the <3 MB stripped binary budget + RAM. If still over budget, layer build-time/subset reduction
  (deferred) — do not do it pre-emptively.

## Error handling / resilience

- Rule-set fetch failures fall back to the **last cached** `.srs` on disk; if none, the router
  degrades to **proxy-everything** (today's behavior) — never fail the tunnel over a rule-set.
- A malformed/unknown-version `.srs` is skipped with a warning (that Action loses that list, not the
  tunnel), mirroring the outbound-skip pattern in `lantern.rs`.
- Fake-IP map exhaustion → LRU-evict oldest; a flow to an evicted fake IP with no mapping falls
  through to IP rules then `route.final` (proxy) — safe default.
- All new code obeys the repo standards: no `unwrap`/`expect` outside tests, `thiserror` at module
  boundaries, `clippy -D warnings`, `fmt`.

## Testing / verification (phased — each green before the next)

- **M1 — `.srs` parser.** Verify format version against real files; unit-test parsing of
  domain/suffix/keyword/ip_cidr against fixtures captured from the live rule-sets. No runtime wiring.
- **M2 — matcher + compaction.** Property tests: compaction preserves match results (a domain/IP
  matches the compacted structure iff it matched the raw entries); measure the size reduction.
- **M3 — router + Direct/Reject + IP rules.** Wire the Router into `proxy::forward`; add Direct
  (protected dial) and Reject; evaluate **IP/CIDR** rules on `original_dst` (Quad9 base rule,
  geoip-malware → reject). End-to-end testable at L3 with no DNS yet.
- **M4 — fake-IP DNS + domain rules.** The DNS server, fake-IP allocator/map, per-action resolver
  wiring (local + resilient), and domain-rule evaluation. Full `smart_routing` + `ad_block` for TCP
  and QUIC/UDP. Verify: an ad domain is dropped; a common-direct domain egresses direct with a local
  IP; an ordinary domain is proxied; DNS does not loop.
- **M5 — mobile footprint.** On-device (Redmi-class): memory + binary size within budget; tune
  compaction; confirm no jank/ANR.
- **M6 — ruleset fetch/cache/refresh + offline.** Refresh on `poll_interval_seconds`; offline uses
  cache; missing cache degrades to proxy-everything.

Test infra: `bin/testsetup` where a stack is needed; unit tests inline; the matcher/parser are pure
and fully unit-testable with fixtures.

## Non-goals (v1)

- Full sing-box rule grammar (logical rules, process/port/network match types, `domain_regex` on
  mobile) — only what the live config uses.
- SNI/Host sniffing fallback for DNS-bypassing apps — accepted small gap (those hit IP rules then
  proxy); revisit if it proves material.
- Build-time / server-side reduction and per-rule-set mobile subsetting — deferred behind
  measurement.
- Pro-tier-specific routing — same mechanism applies; no special handling in v1.

## Files

**Add:** `core/src/route/{mod,srs,ruleset,matcher,router}.rs`; `core/src/dns/{mod,fakeip,server,resolver}.rs`.
**Modify:** `core/src/config/lantern.rs` (parse the sections → `RoutingConfig`; synthesize
`direct`/`reject`); `core/src/config/mod.rs` (config model + the routing/dns config types);
`core/src/proxy/tcp.rs` + `core/src/proxy/udp.rs` (Router + Direct/Reject actions);
`core/src/fd_tunnel.rs` (build the DNS server + router into the running tunnel);
`core/src/lib.rs` (module wiring, feature gating). Reuse `core/src/bootstrap/` (resilient resolver),
the config-fetch cache pattern, and the existing pool/"auto" outbound.

## Appendix — /goal prompt (3399 chars, under the 4000 limit)

```
GOAL: Implement smart-routing + ad-block in spark's Rust core (core/, cross-platform) so the Lantern config's smart_routing/ad_block/route/dns sections are honored — per-flow routing: Direct (bypass proxy), Proxy (default), Reject (ads/malware/phishing) — driven by sing-box .srs rule-sets, with a footprint fit for low-end mobile. Full design: docs/superpowers/specs/2026-07-01-spark-smart-routing-ad-block-design.md.

Today spark ignores those sections (config/lantern.rs) and full-tunnels everything. Hard part: rules are domain-based, spark sees only IPs at L3.

Locked decisions:
- Domain visibility = fake-IP DNS. Spark runs the DNS server (VpnService/NE already send DNS in-tunnel), answers A/AAAA with fake IPs (198.18.0.0/15 + IPv6 ULA), maps fakeip->domain (TTL/LRU); the flow's dst fake IP recovers the domain at connect time.
- A Router sits between netstack and outbound (replaces the single-transport proxy::forward). Actions: Proxy (dial by name through the "auto" pool -- exit resolves, no client DNS leak), Direct (protected direct dial), Reject (drop).
- Precedence (first match wins): 1) ad_block->Reject; 2) options.route.rules (e.g. Quad9 9.9.9.9/32->direct); 3) smart_routing categories; 4) route.final->Proxy.
- Resolver PER ACTION: Direct resolves via dns_local (local/direct DoH -> best local CDN IPs; poisoning irrelevant since the domain is unblocked). Bootstrap + poisoning-risk lookups use the existing resilient resolver in core/src/bootstrap/ (RacingResolver: un-poisoned DoH pool + ProxyResolver; bootstrap-dns feature, already on in mobile). Proxy flows need no client resolution. Loop-safe: resolver sockets bypass the TUN.
- Write a Rust .srs parser (do NOT re-host as plain lists). Coverage-preserving compaction: per action, collapse domains under a covering suffix + dedupe across lists -> one compact matcher (domains: suffix-trie/FST; IPs: CIDR-trie). Full coverage, minimal RAM.

Modules -- add route/{srs,ruleset,matcher,router}.rs, dns/{fakeip,server,resolver}.rs; modify config/lantern.rs (parse sections -> RoutingConfig; synthesize direct/reject outbounds), proxy/{tcp,udp}.rs, fd_tunnel.rs, lib.rs. Reuse the bootstrap resolver + config-fetch cache pattern.

Resilience: rule-set fetch fail -> last cached .srs; none -> degrade to proxy-everything (never fail the tunnel). Malformed/unknown .srs -> skip+warn. Refresh on poll_interval_seconds. Standards: no unwrap/expect outside tests; thiserror at boundaries; clippy -D warnings; fmt; <3MB stripped.

Verify each step -- each milestone green before the next:
- M1 .srs parser -- FIRST pin the real format version(s) by downloading the actual getlantern/rulesets + KaringX/karing-ruleset files; unit-test domain/suffix/keyword/ip_cidr vs fixtures.
- M2 matcher + compaction -- property test: compacted matches iff raw matched; measure the size cut.
- M3 router + Direct/Reject + IP/CIDR rules on original_dst (Quad9, geoip-malware), wired end-to-end at L3, no DNS yet.
- M4 fake-IP DNS + domain rules -- per-action resolver; full smart_routing + ad_block for TCP + QUIC; verify ad dropped, common-direct goes direct with a local IP, ordinary domain proxied, no DNS loop.
- M5 mobile footprint on a Redmi-class device (RAM + binary within budget; no jank).
- M6 fetch/cache/refresh + offline.

Non-goals v1: full sing-box grammar; SNI-sniff fallback; build-time/subset reduction; Pro-specific routing.
```
