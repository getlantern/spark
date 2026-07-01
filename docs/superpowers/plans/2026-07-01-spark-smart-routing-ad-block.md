# Spark Smart Routing + Ad-Block Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Honor the Lantern config's `smart_routing` / `ad_block` / `route` / `dns` sections in spark's `core/` — per-flow Direct / Proxy / Reject routing driven by sing-box `.srs` rule-sets, with a mobile-fit footprint.

**Architecture:** A per-flow **Router** sits between the netstack and the outbound (replacing the single-transport `proxy::forward`). Destination domains come from a **fake-IP DNS** server (spark answers A/AAAA with synthetic IPs, maps `fakeip→domain`, recovers the domain at connect time). Rules come from `.srs` rule-sets parsed by a **Rust parser** into a **compact, coverage-preserving matcher**. Resolver is chosen per action (local `dns_local` for Direct; resilient `bootstrap::RacingResolver` for bootstrap/blocked).

**Tech Stack:** Rust (tokio, thiserror, tracing), `flate2`/`miniz_oxide` (pure-Rust zlib, already in-tree), the existing `core/src/bootstrap` resilient resolver, the config-fetch cache pattern.

**Design of record:** `docs/superpowers/specs/2026-07-01-spark-smart-routing-ad-block-design.md`.

---

## Scope & sequencing (read first)

This feature is large and naturally decomposes into the spec's six milestones, each independently testable and green before the next (per "verify each step carefully"). **Milestone M1 is fully specified below as bite-sized TDD tasks** — it is the immediate work and is fully knowable now (the `.srs` format is pinned). **M2–M6 are captured as scoped roadmap** (deliverables, interfaces, verification gates, open decisions); each will be expanded into its own bite-sized plan when reached, because their exact steps depend on the concrete types the prior milestone produces. Do not write speculative line-level steps for M2–M6 ahead of time.

### Dependencies to approve before coding (standing rule: no new crates without asking)
1. **`flate2` as a direct dep of `core/`** — for `.srs` zlib inflate. Already transitively in `Cargo.lock` via `miniz_oxide` (pure Rust, no C). Low cost. **Needs a yes.**
2. **M2 domain matcher structure** — hand-rolled suffix-trie vs the `fst` crate. Decide at M2 start; `fst` is a new dep (flag then). Not needed for M1.
uvarint reading is hand-rolled (no dep).

### File structure (created across the whole feature)
- `core/src/route/mod.rs` — module root; `Action { Proxy, Direct, Reject }`, `RoutingConfig`, public API.
- `core/src/route/srs.rs` — the `.srs` parser (M1).
- `core/src/route/matcher.rs` — compact matcher + coverage-preserving compaction (M2).
- `core/src/route/ruleset.rs` — fetch + cache + refresh of `.srs` URLs (M6).
- `core/src/route/router.rs` — per-flow decision (M3).
- `core/src/dns/{mod,fakeip,server,resolver}.rs` — fake-IP DNS subsystem (M4).
- `core/tests/fixtures/srs/{common_v3,banad_v1,category-ads_v2}.srs` — real rule-set fixtures (from `/tmp/srs`).
- **Modify (later milestones):** `core/src/config/lantern.rs`, `core/src/config/mod.rs`, `core/src/proxy/{tcp,udp}.rs`, `core/src/fd_tunnel.rs`, `core/src/lib.rs`, `core/Cargo.toml`.

---

## Milestone M1 — the `.srs` parser (TDD against real fixtures)

**Pinned format (recon done — do NOT re-derive):** `.srs` = ASCII `"SRS"` (3 bytes) + 1 version byte + a **zlib** stream (`0x78 0xda`). Versions **1, 2, and 3** are all in use (getlantern `common.srs`=v3, KaringX `category-ads`=v2, `BanAD`=v1) — the parser must accept all three. Decompressed body = `uvarint` rule count + typed rule records; domains are stored in sing-box's **succinct domain set** (not plain strings). Authoritative encoding: `sagernet/sing-box` `common/srs/binary.go` + `sagernet/sing` `common/domain/{matcher,set}.go`.

**Files:**
- Create: `core/src/route/mod.rs`, `core/src/route/srs.rs`
- Create fixtures: `core/tests/fixtures/srs/common_v3.srs`, `banad_v1.srs`, `category-ads_v2.srs`
- Modify: `core/src/lib.rs` (add `pub(crate) mod route;` behind the routing feature gate — see Task M1.0), `core/Cargo.toml` (add `flate2`)

### Task M1.0 — module scaffold, fixtures, and the flate2 dep

- [ ] **Step 1:** Copy the real fixtures into the repo:
```bash
mkdir -p core/tests/fixtures/srs
cp /tmp/srs/common.srs       core/tests/fixtures/srs/common_v3.srs
cp /tmp/srs/banad.srs        core/tests/fixtures/srs/banad_v1.srs
cp /tmp/srs/category-ads.srs core/tests/fixtures/srs/category-ads_v2.srs
```
- [ ] **Step 2:** Add `flate2` to `core/Cargo.toml` `[dependencies]` (workspace version; default features = the pure-Rust `miniz_oxide` backend). Add a comment: `# .srs rule-sets are zlib-compressed; pure-Rust backend (miniz_oxide), no C.`
- [ ] **Step 3:** Create `core/src/route/mod.rs` with the module doc + the `Action` enum and the `SrsError` re-export:
```rust
//! Rule-based routing: parse sing-box `.srs` rule-sets and decide per-flow actions.
pub mod srs;

/// What the router decides for a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Send through the proxy pool (the config's `auto` / `route.final`).
    Proxy,
    /// Dial directly (protected socket), bypassing the proxy.
    Direct,
    /// Drop the flow (ad_block / malware).
    Reject,
}
```
- [ ] **Step 4:** Wire the module into `core/src/lib.rs` (`mod route;`), matching the existing module-declaration style/placement.
- [ ] **Step 5:** `cargo build -p spark-core` — Expected: builds clean.
- [ ] **Step 6:** Commit: `git add core/Cargo.toml core/src/route/mod.rs core/src/lib.rs core/tests/fixtures/srs && git commit` — message `feat(route): scaffold route module + .srs fixtures + flate2 dep`.

### Task M1.1 — envelope: magic, version, zlib inflate

- [ ] **Step 1: Write the failing test** in `core/src/route/srs.rs` (`#[cfg(test)] mod tests`):
```rust
#[test]
fn envelope_accepts_v1_v2_v3_and_rejects_bad_magic() {
    for (name, want_ver) in [("common_v3", 3u8), ("banad_v1", 1), ("category-ads_v2", 2)] {
        let bytes = std::fs::read(format!("tests/fixtures/srs/{name}.srs")).unwrap();
        let env = decode_envelope(&bytes).unwrap();
        assert_eq!(env.version, want_ver);
        assert!(!env.body.is_empty(), "{name}: decompressed body empty");
    }
    assert!(matches!(decode_envelope(b"ZZZ\x01").unwrap_err(), SrsError::BadMagic));
    assert!(matches!(decode_envelope(b"SR").unwrap_err(), SrsError::Truncated));
}
```
- [ ] **Step 2: Run it — expect FAIL** (`decode_envelope`/`SrsError` undefined): `bin/testsetup cargo test -p spark-core route::srs::tests::envelope -- --nocapture` (or plain `cargo test` if no stack needed).
- [ ] **Step 3: Implement** in `core/src/route/srs.rs`:
```rust
use std::io::Read;

/// Errors from parsing a sing-box `.srs` rule-set.
#[derive(Debug, thiserror::Error)]
pub enum SrsError {
    #[error(".srs: bad magic (not \"SRS\")")]
    BadMagic,
    #[error(".srs: truncated input")]
    Truncated,
    #[error(".srs: unsupported version {0} (support 1..=3)")]
    UnsupportedVersion(u8),
    #[error(".srs: zlib inflate failed: {0}")]
    Inflate(#[from] std::io::Error),
    #[error(".srs: malformed rule body: {0}")]
    Malformed(&'static str),
}

const MAGIC: &[u8; 3] = b"SRS";

pub(crate) struct Envelope { pub version: u8, pub body: Vec<u8> }

/// Decode the `.srs` envelope: 3-byte magic, 1 version byte (1..=3), zlib body.
pub(crate) fn decode_envelope(bytes: &[u8]) -> Result<Envelope, SrsError> {
    if bytes.len() < 4 { return Err(SrsError::Truncated); }
    if &bytes[..3] != MAGIC { return Err(SrsError::BadMagic); }
    let version = bytes[3];
    if !(1..=3).contains(&version) { return Err(SrsError::UnsupportedVersion(version)); }
    let mut body = Vec::new();
    flate2::read::ZlibDecoder::new(&bytes[4..]).read_to_end(&mut body)?;
    Ok(Envelope { version, body })
}
```
- [ ] **Step 4: Run — expect PASS.** Same command as Step 2.
- [ ] **Step 5: Commit** — `feat(route): .srs envelope (magic/version/zlib) with v1-v3 support`.

### Task M1.2 — primitive readers (uvarint, bytes, string)

- [ ] **Step 1: Write failing tests** (uvarint against known LEB128 values + a bounds case):
```rust
#[test]
fn reads_uvarint_and_string() {
    let mut r = Reader::new(&[0xbb, 0x01, 0x03, b'a', b'b', b'c']);
    assert_eq!(r.uvarint().unwrap(), 187);          // 0xbb,0x01 = 59 + 128
    assert_eq!(r.string().unwrap(), "abc");          // len-prefixed
    assert!(r.uvarint().is_err());                   // exhausted → Truncated
}
```
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement** a `Reader` cursor over `&[u8]` in `srs.rs`: `uvarint()` (LEB128, max 10 bytes → u64), `u8()`, `bytes(n)`, `string()` (uvarint length + UTF-8, non-UTF-8 → `Malformed`). No `unwrap`; every path returns `Result<_, SrsError>` (`Truncated` on short read).
- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5: Commit** — `feat(route): .srs primitive readers (uvarint/bytes/string)`.

### Task M1.3 — build the domain/IP oracle for verification

The parser needs a ground-truth list to assert against. Generate it from the source lists (not by trusting our own parser).

- [ ] **Step 1:** Obtain the expected entries per fixture, in preference order:
  (a) if `sing-box` is installed, `sing-box rule-set decompile core/tests/fixtures/srs/common_v3.srs` → JSON; else
  (b) fetch the human-readable source the `.srs` was compiled from (getlantern/rulesets and KaringX repos host source `.json`/lists).
  Save the expected domain-suffix / domain / ip_cidr entries to `core/tests/fixtures/srs/expected/{common_v3,banad_v1,category-ads_v2}.json`.
- [ ] **Step 2:** Commit the expected fixtures — `test(route): expected-entries oracle for .srs fixtures`.
  *(Document in the commit which method (a/b) produced them.)*

### Task M1.4 — parse rule records → `RuleSet { domain_suffix, domain, domain_keyword, ip_cidr }` (the succinct-set decode)

This is the research-heavy task: decode the versioned rule body + sing-box succinct domain set. Work against the fixtures + the M1.3 oracle + the sing-box source.

- [ ] **Step 1: Write the failing test** (parse each fixture, assert against the oracle):
```rust
#[test]
fn parses_fixture_entries_matching_oracle() {
    for name in ["common_v3", "banad_v1", "category-ads_v2"] {
        let bytes = std::fs::read(format!("tests/fixtures/srs/{name}.srs")).unwrap();
        let rs = parse(&bytes).unwrap();
        let want: Expected = serde_json::from_slice(
            &std::fs::read(format!("tests/fixtures/srs/expected/{name}.json")).unwrap()).unwrap();
        assert_eq!(sorted(rs.domain_suffix), sorted(want.domain_suffix), "{name} suffixes");
        assert_eq!(sorted(rs.domain), sorted(want.domain), "{name} exact");
        assert_eq!(sorted(rs.ip_cidr.iter().map(|c| c.to_string())), sorted(want.ip_cidr), "{name} cidr");
    }
}
```
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement** `pub struct RuleSet { pub domain_suffix: Vec<String>, pub domain: Vec<String>, pub domain_keyword: Vec<String>, pub ip_cidr: Vec<IpNet> }` and `pub fn parse(bytes: &[u8]) -> Result<RuleSet, SrsError>`:
  - `decode_envelope` → `Reader` over the body.
  - Read `uvarint` rule count; for each rule read the sing-box rule record: a mode byte (default vs logical rule), then the default rule's typed items. Decode the item types this config uses: `domain` + `domain_suffix` (the succinct set — decode per `sing/common/domain`), `domain_keyword`, `ip_cidr` (IP set). Version differences (v1/v2/v3 item tags) handled by branching on `env.version`.
  - `domain_regex` and unused item types: skip (consume + ignore) — not needed on mobile (spec non-goal).
  - Represent `ip_cidr` with a minimal internal `IpNet` (addr + prefix) — no new crate; hand-roll parse/`Display`.
  - No `unwrap`/`expect`; every short/oddity → `SrsError`.
- [ ] **Step 4: Run — expect PASS** for all three fixtures (all three versions).
- [ ] **Step 5: Add negative tests:** a truncated body and an unknown item tag return `Err`, never panic. Run — PASS.
- [ ] **Step 6: `cargo clippy -p spark-core -- -D warnings` + `cargo fmt`** — clean.
- [ ] **Step 7: Commit** — `feat(route): parse .srs rule records (domain set + ip_cidr) for v1/v2/v3`.

### Task M1.5 — feature gate + robustness

- [ ] **Step 1:** Put the `route` module behind a `smart-routing` cargo feature (mirroring how `config-fetch` etc. are gated), so non-routing builds stay lean. Add the feature to the Android slice in `platforms/android/Cargo.toml` (alongside `config-fetch`, `bootstrap-dns`, …).
- [ ] **Step 2:** Verify `cargo build -p spark-core` (no feature) and `--features smart-routing` both build; `cargo test -p spark-core --features smart-routing` passes.
- [ ] **Step 3: Commit** — `feat(route): gate the route module behind the smart-routing feature`.

### M1 completion gate
`parse()` extracts the correct domain/suffix/keyword/ip_cidr entries from all three real fixtures (v1/v2/v3), matching the independent oracle; malformed input never panics; clippy/fmt clean; feature-gated. **Stop and verify before M2.**

---

## M2–M6 — roadmap (expand each into its own bite-sized plan when reached)

Each milestone below states its deliverable, public interface, verification gate, and open decisions. **Do not implement ahead of the gate; write the detailed task plan for a milestone at its start**, once the prior milestone's concrete types exist.

### M2 — compact matcher + coverage-preserving compaction
- **Deliverable:** `matcher.rs` — build one compact structure per `Action` from many `RuleSet`s: domains in a suffix-trie (or `fst`), IPs in a CIDR-trie; compaction = collapse any domain a broader suffix already covers, dedupe across lists. API: `Matcher::build(entries: &[(Action, RuleSet)]) -> Matcher`; `Matcher::lookup(domain: Option<&str>, ip: IpAddr) -> Option<Action>`.
- **Verify:** property test — for a large sample of domains/IPs, `lookup` on the compacted matcher returns the same Action as a naive linear scan of the raw entries (compaction preserves results). Report the size reduction (entries + bytes).
- **Open decision (flag then):** hand-rolled suffix-trie vs the `fst` crate (new dep). Default to hand-rolled unless `fst` wins clearly on size/speed.

### M3 — router + Direct/Reject actions + IP rules (no DNS yet)
- **Deliverable:** `router.rs` — `Router::decide(dst_ip, domain: Option<&str>) -> Action` applying the spec precedence (ad_block Reject → route.rules → smart_routing → final Proxy). Wire into `proxy/tcp.rs` + `udp.rs`: replace the single transport with a decision; add **Direct** (protected direct dial) and **Reject** (drop). Extend `config/lantern.rs` to parse `options.route.rules` (ip_cidr) + synthesize `direct`/`reject`.
- **Verify:** end-to-end at L3 with IP-only rules — the Quad9 `9.9.9.9/32→direct` base rule sends that flow direct; a geoip-malware CIDR is dropped; everything else proxied. No DNS required yet.

### M4 — fake-IP DNS + domain rules + per-action resolver
- **Deliverable:** `dns/` — DNS server on the in-tunnel resolver, fake-IP allocator (`198.18.0.0/15` + IPv6 ULA) + `fakeip→domain` map (TTL/LRU); connect-time domain recovery feeds the Router. Per-action resolver seams: **local** (`dns_local`) for Direct real-IP resolution; injected resilient `bootstrap::RacingResolver` for bootstrap/blocked. Parse `smart_routing`/`ad_block`/`options.dns` in `config/lantern.rs` → `RoutingConfig`.
- **Verify:** ad domain dropped; a `smart_routing` common-direct domain egresses direct with a local IP; an ordinary domain is proxied (dialed by name); QUIC/UDP honored; no DNS loop (resolver sockets bypass the TUN).

### M5 — mobile footprint
- **Deliverable:** measure RAM + stripped binary on a Redmi-class device with the full rule-sets loaded; tune compaction (and, only if over budget, add subsetting — deferred per spec).
- **Verify:** within the <3 MB stripped budget + acceptable RAM; no jank/ANR; document the numbers.

### M6 — ruleset fetch / cache / refresh + offline
- **Deliverable:** `ruleset.rs` — fetch the `.srs` URLs, disk-cache under `data_dir`, refresh on `poll_interval_seconds`, mirroring config-fetch; offline uses cache; missing cache degrades to proxy-everything.
- **Verify:** cold fetch populates cache; offline start uses cache; a corrupt/absent cache never fails the tunnel (proxy-everything fallback); refresh picks up an updated `.srs`.

---

## Self-review notes
- **Spec coverage:** `.srs` parser (M1) ✓; compact/coverage-preserving matcher (M2) ✓; precedence + Direct/Reject + IP rules (M3) ✓; fake-IP DNS + per-action resolver + resilient wiring (M4) ✓; mobile reduction/footprint (M5, + M2 compaction) ✓; fetch/cache/refresh/offline (M6) ✓; synthesize direct/reject outbounds (M3/M4) ✓. No spec section is unmapped.
- **No placeholders in M1** — every code step has real code; M2–M6 are explicitly roadmap (interfaces + gates), to be expanded per-milestone, not fake bite-sized steps.
- **Type consistency:** `Action`, `RuleSet`, `parse`, `decode_envelope`, `Matcher::{build,lookup}`, `Router::decide` are named consistently across tasks/milestones.
- **Decisions needing a yes:** (1) `flate2` direct dep now (M1); (2) matcher structure hand-rolled vs `fst` at M2.
