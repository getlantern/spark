# Spark Split Tunneling (domain-based) — Design

**Date:** 2026-07-06
**Branch:** `fisk/split-tunneling`
**Status:** Approved scope; ready for implementation planning.

## Goal

Let a user route specific destinations **around** the tunnel ("bypass the VPN") while
everything else stays tunneled. Ship **domain-based** split tunneling first (Websites),
with the shared routing logic living in `core/` so it works on **both** the desktop
(Tauri/macOS) and **Android** apps. App-based split tunneling, curated "default lists",
and the separate "Routing Mode" (Smart/Full) screen are explicitly deferred.

Design mirrors the Figma flow (`getlantern/Lantern-VPN`, node `30-19175`): a **Split
Tunneling** master toggle → **Apps** (deferred) / **Websites** rows → a Websites screen
that adds/removes domains or IPs shown as "Websites bypassing the VPN (N)".

## Semantics (the one-sentence contract)

A destination in the user's list is routed **Direct** (out the physical interface,
bypassing the proxy pool); everything else is routed as it is today (Smart Routing /
proxy). "Bypass" == `RouteAction::Direct`. The user list is the **highest-precedence**
rule — it wins over the fetched smart-routing rules (and over ad-block Reject; see
Decisions). Split tunneling is a per-device user preference, **not** part of the
server-fetched config.

## Why this fits the existing engine

`core/src/rules/router.rs` already decides per flow from a compiled `Matcher`, and
`Matcher` already does reversed-label **suffix** matching (`example.com` ⇒ `example.com` +
`*.example.com`) plus CIDR matching. `proxy::RouteHooks`/`Router` already take a recovered
`domain`. Because the user bypass is (a) always `Direct` and (b) absolute (wins over
everything, including ad-block Reject — Decision 1), we model it as a **small, separate,
live-swappable matcher checked first**, in front of the immutable base matcher built from
the fetched rules. This makes **live reload cheap**: an edit rebuilds only the handful of
user entries, never the large fetched matcher. No new matching machinery.

The catch (must handle): `fd_tunnel::setup_routing_and_udp` only builds the router +
fake-IP DNS when `sr.rule_sets` **or** `sr.inline_ip_rules` is non-empty
(`core/src/fd_tunnel.rs:427`). Domain recovery needs fake-IP DNS. So a **non-empty enabled
bypass list must also activate** the router/fake-IP path even when the fetched config
carries no rules.

## Architecture (cross-platform)

```
        ┌───────────────── UI (per platform) ─────────────────┐
        │  Tauri/Svelte (gui-tauri)      Android/Compose        │
        │  - Split Tunneling screens     - same screens         │
        │  - persist list locally        - persist list locally │
        └───────────────┬──────────────────────┬───────────────┘
                        │ inject at connect      │ inject at connect
                        │ (providerConfiguration)│ (nativeRun arg)
                        ▼                        ▼
        ┌──────────────── core (shared, once) ─────────────────┐
        │ fd_tunnel::run_fd_dispatch(config, dataDir, splitCfg) │
        │   → parse splitCfg → SplitTunnel                      │
        │   → setup_routing_and_udp: activate router if the     │
        │     fetched rules OR the bypass list is non-empty     │
        │   → Router::build(sr, user_bypass, load): prepend a   │
        │     highest-precedence (Direct, RuleSet) from the     │
        │     bypass domains/IPs                                │
        └──────────────────────────────────────────────────────┘
```

**Injection, not a shared file.** On macOS the UI process and the NE system extension are
separate processes with separate containers, so a `dataDir` file the UI writes is not
readable by the extension without an app-group container. To stay symmetric and
app-group-independent, the UI **passes the bypass list to core at connect** and **pushes
live updates while connected**:

*At connect (initial list):*
- macOS: a new `providerConfiguration["splitTunnel"]` key (sibling to `["config"]`),
  read by the Swift NE and forwarded to the C-ABI entrypoint.
- Android: a new argument to `SparkBridge.nativeRun(...)` forwarded to the JNI shim.

*While connected (live reload):* the running core exposes a runtime control handle
registered at connect — mirroring the existing `set_pool`/`PoolControl` +
`fd_tunnel::select_server` pattern — reachable via an FFI `spark_set_split_tunnel(json)`:
- macOS: the app sends the updated list via `NETunnelProviderSession.sendProviderMessage`;
  the NE's `handleAppMessage` decodes it and calls the C-ABI `spark_set_split_tunnel`.
- Android: the VpnService shares the app process, so the Compose app calls
  `SparkBridge.nativeSetSplitTunnel(json)` (JNI) directly on the running service.

Core applies the update by rebuilding only the small user-bypass matcher and swapping it
(see Core changes) — no reconnect, no fetched-matcher rebuild.

**Activation caveat:** live reload updates an *already-active* router. The router/fake-IP
path is built at connect only when there are fetched rules **or** a non-empty initial
bypass list (see below). In the shipping product the fetched config always carries
smart-routing rules (ad-block etc.), so the path is always active and live enable/disable
works. Edge case (no fetched rules **and** an empty initial list, e.g. a bare dev config):
enabling split tunneling then needs a reconnect. Not a production path.

Each platform **persists** its own copy locally (Tauri store; Android DataStore/file) so
the list survives restarts and is shown in the UI while disconnected. The **format is
shared** (defined in core) so both platforms serialize the same JSON.

## Data model

A small JSON payload, defined and parsed in core (`spark_core::split_tunnel`):

```json
{
  "enabled": true,
  "domains": ["google.com", "linkedin.com"],
  "ips": ["1.2.3.4", "10.0.0.0/8"]
}
```

- `enabled` — master toggle. When `false`, the list is ignored (but preserved).
- `domains` — bare hostnames; each matches the host **and its subdomains** (suffix).
- `ips` — single IPs or CIDRs; matched by the existing CIDR trie.
- `apps` — **not** in v1 (added later; Android package names / macOS bundle ids).

Validation (core): trim, lowercase, strip scheme/path if a full URL is pasted
(`https://x.com/y` → `x.com`), drop empties/dupes, reject syntactically invalid entries
and report them to the UI (so the "Add" action can surface a per-entry error). Comma-split
happens in core so both UIs share it.

## Core changes

**New module `core/src/split_tunnel.rs`** (always compiled — the UI needs the type/parse
even in non-routing builds):
- `struct SplitTunnel { enabled: bool, domains: Vec<String>, ips: Vec<String> }`
  with `serde` derive.
- `parse(json: &str) -> Result<SplitTunnel, SplitTunnelError>` (thiserror).
- `fn normalize(raw: &str) -> Vec<String>` — comma-split + scheme/path strip + lowercase +
  dedupe, used by the UI-facing "add" path and by parse.
- `fn add_entries(&mut self, raw: &str) -> AddOutcome` — returns accepted + rejected
  entries so the UI can show which failed.

**`core/src/rules/srs.rs`** — add a `RuleSet` constructor for user rules:
`RuleSet::from_domains_and_ips(domains: &[String], ips: &[String]) -> RuleSet`
(fills `domain_suffix` + `ip_cidr`, other vecs empty). `RuleSet::ip_only` already exists as
the pattern to follow.

**`core/src/rules/router.rs`** — restructure `Router` for a live-swappable bypass:
```rust
pub struct Router {
    base: Matcher,                          // fetched rules, immutable
    user_bypass: RwLock<Option<Matcher>>,   // small; None = disabled/empty
}
```
- `decide(ip, domain)`: if the `user_bypass` matcher (read lock) matches → `Direct`;
  otherwise `base.lookup(...).unwrap_or(Proxy)`. Checking bypass first makes it absolute
  (wins over ad-block Reject — Decision 1). `decide` is per-flow-open and synchronous, so
  a `std::sync::RwLock` read is fine (no new dep, no lock held across `.await`).
- `Router::build(sr, initial_bypass: Option<&SplitTunnel>, load)` builds `base` from the
  fetched rules (as today) and seeds `user_bypass` via `set_user_bypass`.
- `set_user_bypass(&self, st: Option<&SplitTunnel>)`: if `st.enabled` and non-empty, build
  a one-entry matcher `Matcher::build([(Direct, RuleSet::from_domains_and_ips(...))])` and
  store `Some`; else store `None`. This is the live-reload entry point (only the small
  matcher is rebuilt).

**`core/src/fd_tunnel.rs`** — `run_fd_dispatch` gains an optional split-tunnel JSON param;
parse to `SplitTunnel`. `setup_routing_and_udp`:
- activation condition becomes: build the router/fake-IP path if
  `!sr.rule_sets.is_empty() || !sr.inline_ip_rules.is_empty() ||
   initial_bypass.map_or(false, |s| s.enabled && !s.is_empty())`.
- pass `initial_bypass` into `Router::build`.
- **register a runtime control handle** for live reload: keep the `Arc<Router>` in a
  process global set at connect and cleared at teardown (mirror the existing `set_pool` in
  `fd_tunnel`), so the FFI update entrypoint can reach the running router. Guard the
  edge case where no router was built (return a "reconnect needed" status).

**FFI surface** (thin, per platform):
- Apple C-ABI (`platforms/apple/src/lib.rs`): (a) the tunnel entrypoint gains an optional
  split-tunnel string arg forwarded to `run_fd_dispatch`; (b) a new
  `spark_set_split_tunnel(json: *const c_char) -> i32` that parses + calls
  `router.set_user_bypass` on the registered handle.
- Android JNI (`platforms/android/src/lib.rs`): (a) `nativeRun(...)` gains a
  `splitTunnel: String?` arg; (b) a new `nativeSetSplitTunnel(json: String)`.
- The CLI `spark run` path is unaffected (passes `None`; no live handle).

## UI — desktop (Tauri/Svelte, v1)

Follow the existing `gui-tauri` patterns exactly (design tokens in `+layout.svelte`,
Urbanist font, the `/servers` sub-page as the appbar+card template; `SparkBackend`
abstraction with `MockBackend` for `npm run dev` and `TauriBackend` over `invoke()`).

- **Home** (`src/routes/+page.svelte`): add a **Split Tunneling** row to the control panel
  (branch icon per Figma; value `Enabled`/`Disabled`) → `goto("/split-tunneling")`. Leave
  the rest of the home unchanged (full home redesign is out of scope).
- **`/split-tunneling/+page.svelte`**: appbar "Split Tunneling"; a card with the master
  **toggle** ("Add apps & websites to bypass the VPN"). When on, two rows: **Apps**
  (`0 Apps`, disabled + "Coming soon") and **Websites** (`N Sites ›`) → `/split-tunneling/websites`.
- **`/split-tunneling/websites/+page.svelte`**: "Enter URL or IP Address" input + **Add**
  (comma-separated; core `add_entries` validates, per-entry errors surfaced), helper "Use
  commas to separate multiple URLs", divider, "Websites bypassing the VPN (N):" list with
  each row removable via ✕. Empty state "No websites selected."
- **Snackbar** on leaving Websites/Apps after a change (per Figma note).
- **Backend seam**: extend `SparkBackend` with
  `getSplitTunnel(): Promise<SplitTunnel>` / `setSplitTunnel(st): Promise<void>`.
  `MockBackend` stores in-memory; `TauriBackend` calls new Tauri commands
  `spark_get_split_tunnel` / `spark_set_split_tunnel`. `set` always **persists** to the app
  store (so it's injected via `providerConfiguration["splitTunnel"]` on the next
  `spark_connect`) and, **if connected, pushes it live** via
  `NETunnelProviderSession.sendProviderMessage` → NE `handleAppMessage` →
  `spark_set_split_tunnel`. So edits apply immediately when connected and are remembered
  when not.

## UI — Android (Compose, fast-follow)

Same three screens in `platforms/android/demo/app/.../ui/`, reusing the identical core
JSON format and the same activation/injection path. `SparkBridge.nativeRun` gains the
`splitTunnel` arg (initial list on connect); `SparkBridge.nativeSetSplitTunnel(json)` does
the live update while connected (same JNI the service already exposes). The app persists
the list (DataStore). Scoped as a **fast-follow** after the desktop UI + core land, since
the core (the hard, shared part) is already done by then.

## Decisions (defaults chosen; flagged for review)

1. **Bypass precedence = highest, wins over ad-block Reject.** A user explicitly bypassing
   a domain gets it Direct even if an ad-block rule-set would Reject it. Rationale: "bypass"
   is an explicit user override; predictable. Trade-off: a user could un-block an ad domain
   by bypassing it (acceptable footgun).
2. **Domain match includes subdomains** (`google.com` ⇒ `mail.google.com`). Matches user
   expectation for "bypass google.com".
3. **Toggle off preserves the list**, just stops applying it.
4. **Changes apply live while connected** (Decision confirmed). Editing the list swaps the
   small user-bypass matcher in the running router via the control handle + FFI — no
   reconnect. The initial list is also injected at connect. (Only exception is the non-
   production edge case of a router that was never built — see Activation caveat.)
5. **Injection at connect** (providerConfiguration / nativeRun arg), not a shared
   `dataDir` file — avoids the macOS app-group requirement and keeps one code path.

## Deferred (not in this effort)

- App-based split tunneling (Android package ids / macOS bundle ids, the searchable app
  list + Select All).
- Curated **default lists** ("one active default list with N sites").
- The separate **Routing Mode** (Smart Routing / Full Tunnel) screen and the full
  home-screen redesign to match Figma.

## Testing

- **Core unit tests** (`rules/router.rs`, `split_tunnel.rs`, `rules/srs.rs`):
  - user bypass domain ⇒ `Direct`, and **wins** over a Proxy/Direct smart_routing rule and
    over an ad-block Reject rule for the same domain (precedence);
  - subdomain match (`google.com` entry matches `mail.google.com`);
  - IP/CIDR bypass entry ⇒ `Direct`;
  - `normalize`/`add_entries`: comma-split, URL→host strip, lowercase, dedupe, invalid
    entries rejected with report;
  - `parse` round-trips the JSON; disabled or empty list ⇒ router/fake-IP **not** forced on
    when no fetched rules; enabled non-empty ⇒ forced on;
  - **live reload**: `set_user_bypass` on a built `Router` changes a domain's decision from
    Proxy→Direct (and back to Proxy when the entry is removed / disabled) without rebuilding
    or altering the base matcher (assert base decisions for other domains are unchanged).
- **Whole-workspace gate** after core API changes (cli + service + platforms compile):
  `cargo clippy --workspace --all-targets --all-features -D warnings`, `cargo fmt`.
- **Desktop manual**: `npm run dev` (MockBackend) drives the three screens + snackbar;
  then the notarized DMG path to verify a bypassed domain actually goes Direct on device
  (e.g. `whatismyipaddress.com` bypassed shows the real IP while tunnel is up), and that
  adding/removing it **while connected** flips the result **without reconnecting** (live
  reload).
- **Android**: fast-follow; validate on the Redmi that a bypassed domain egresses direct.

## Files

**Add (core):** `core/src/split_tunnel.rs`; tests inline.
**Modify (core):** `core/src/rules/srs.rs` (`RuleSet::from_domains_and_ips`),
`core/src/rules/router.rs` (`build` takes user bypass), `core/src/fd_tunnel.rs`
(`run_fd_dispatch` + `setup_routing_and_udp` activation & wiring), `core/src/lib.rs`
(export `split_tunnel`).
**Modify (FFI / core rust):** `platforms/apple/src/lib.rs` (connect arg +
`spark_set_split_tunnel`), `platforms/android/src/lib.rs` (`nativeRun` arg +
`nativeSetSplitTunnel`).
**Modify (macOS NE, Swift):** `platforms/apple/Sources/SparkNE/PacketTunnelProvider.swift`
— read `providerConfiguration["splitTunnel"]` at start; `handleAppMessage` → the C-ABI
`spark_set_split_tunnel`.
**Add (desktop UI):** `gui-tauri/src/routes/split-tunneling/+page.svelte`,
`gui-tauri/src/routes/split-tunneling/websites/+page.svelte`.
**Modify (desktop UI):** `gui-tauri/src/routes/+page.svelte` (Split Tunneling row),
`gui-tauri/src/lib/spark_backend.ts` (+ Mock), `gui-tauri/src/lib/tauri_backend.ts`,
`gui-tauri/src-tauri/src/lib.rs` (commands + inject at connect),
`gui-tauri/src-tauri/src/config.rs` (splitTunnel resolution).
**Fast-follow (Android UI):** `platforms/android/demo/app/.../ui/*`, `SparkBridge.kt`
(`nativeRun` arg + `nativeSetSplitTunnel`), `VpnController.kt`, `SparkVpnService.kt`.

## Resolved decisions (previously open)

- **Precedence over ad-block:** user-bypass is **absolute** — a bypassed domain goes Direct
  even if an ad-block rule-set would Reject it (checked first in `decide`).
- **Apply timing:** **live reload** while connected (no reconnect), via the runtime control
  handle + `spark_set_split_tunnel` FFI.
