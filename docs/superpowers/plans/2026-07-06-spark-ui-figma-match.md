# Spark Desktop UI — Figma Match Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Tauri desktop UI match the Figma exactly — OS-following light/dark, **SPARK** wordmark, the Pro Home layout (no free-tier chrome), a new **Routing Mode** screen with Smart/Full switching, and a split-tunnel exact-match pass.

**Architecture:** All screens theme off CSS variables in `gui-tauri/src/routes/+layout.svelte`; adding a dark palette there themes everything. The Home/split-tunnel work is pure frontend. Routing Mode adds a small cross-layer backend that **mirrors the already-merged split-tunnel slice** (Router live-swappable state → `fd_tunnel` control handle + FFI → NE message → Tauri command → `SparkBackend` seam).

**Tech Stack:** SvelteKit 5 (runes) + TypeScript + Tauri; Rust core + Apple C-ABI / Android JNI FFI; Swift NE.

**Spec:** `docs/superpowers/specs/2026-07-06-spark-ui-figma-match-design.md`.

**Branch:** `fisk/figma-ui-match` (off `main` incl. #49, #50). Single PR.

**Standing constraints:** no `unwrap`/`expect` outside tests; `thiserror` at boundaries; whole-workspace `cargo clippy --all-targets --all-features -D warnings` + `cargo fmt` after core changes; `npm run check` 0 errors after frontend changes; commit trailer `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.

**Figma reference:** Home Pro light `21:2112` / dark `4654:46429`; Routing Mode `4210-34619`; Split Tunneling `30-19175`. Row anatomy (from design-context): each status row is 72px, `py-12`; an **overline** (24px icon + `Label/Large` = Urbanist 14/500, `--text-tertiary`) above a **state** row (`pl-32`; `Subtitle/Medium` = Urbanist 16/600, `--text-primary`; trailing chevron/dot/bolt). Card: `--surface`, radius 16, 1px `--border`, `Card Shadow Light` (#0061631A). Toggle pill 150×80, knob 60. Header 80px tall, 16px padding, bottom `--border` hairline: menu (left) · SPARK (center) · account avatar (right).

---

## File structure

**Modify (frontend):**
- `gui-tauri/src/routes/+layout.svelte` — add the dark palette + a couple new theme vars.
- `gui-tauri/src/routes/+page.svelte` — Home: drop Protocol row, Routing→Routing Mode (→ `/routing`), add account avatar, SPARK wordmark, match metrics.
- `gui-tauri/src/routes/split-tunneling/+page.svelte` + `.../websites/+page.svelte` — variable-ize hardcoded colors; verify dark.
- `gui-tauri/src/lib/spark_backend.ts` + `tauri_backend.ts` — routing-mode seam.

**Add (frontend):** `gui-tauri/src/routes/routing/+page.svelte`.

**Modify (Routing Mode backend):** `core/src/routing_mode.rs` (new type), `core/src/lib.rs`, `core/src/rules/router.rs`, `core/src/fd_tunnel.rs`, `platforms/apple/src/lib.rs` + `include/spark.h`, `platforms/android/src/lib.rs` + `SparkBridge.kt`, `platforms/apple/Sources/SparkNE/PacketTunnelProvider.swift`, `gui-tauri/src-tauri/src/{lib.rs,config.rs}`.

---

## Phase A — Visual foundation (pure frontend)

### Task A1: Dark palette (OS-following) in `+layout.svelte`

**Files:** Modify `gui-tauri/src/routes/+layout.svelte`.

- [ ] **Step 1: Add two theme vars used by components (so nothing is hardcoded)**

In the `:global(:root)` block, after `--bolt`, add:
```css
    --snack-bg: #23282b;      /* toast background (dark on light) */
    --switch-off: #c8ccce;    /* small toggle track, off (split-tunnel screen) */
```

- [ ] **Step 2: Add the dark palette**

After the `:global(:root){…}` block, add a `prefers-color-scheme: dark` override of the same variables (values read from the Figma dark frames; fine-tuned in the Step 4 visual check):
```css
  @media (prefers-color-scheme: dark) {
    :global(:root) {
      --bg: #16181b;
      --surface: #1e2124;
      --brand: #00bdd6;
      --off: #4b5056;
      --knob: #ffffff;
      --text-primary: #f4f6f7;
      --text-secondary: #c2c7cc;
      --text-tertiary: #9aa0a6;
      --border: #2a2e33;
      --success: #34c759;        /* brighter green for contrast on dark */
      --indicator-off: #3a3f45;
      --shadow: rgba(0, 0, 0, 0.45);
      --bolt: #ffc105;
      --lat-good: #34c759;
      --lat-amber: #b7c94a;
      --lat-slow: #e0a52a;
      --snack-bg: #2e3439;
      --switch-off: #4b5056;
    }
  }
```

- [ ] **Step 3: Type-check**

Run: `cd gui-tauri && ([ -d node_modules ] || npm install) && npm run check`
Expected: 0 errors (CSS-only change).

- [ ] **Step 4: Visual check both themes**

Run: `cd gui-tauri && npm run dev`. Toggle macOS appearance (System Settings → Appearance) and confirm the whole app (home + split-tunnel) switches between the two palettes with no unreadable/hardcoded colors. Adjust the dark hexes to match the Figma dark frames (compare side-by-side). (This is the fine-tune step for the dark values.)

- [ ] **Step 5: Commit**
```bash
git add gui-tauri/src/routes/+layout.svelte
git commit -m "feat(ui): OS-following dark palette (theme all screens via CSS vars)"
```

### Task A2: Split-tunnel screens — variable-ize hardcoded colors

**Files:** Modify `gui-tauri/src/routes/split-tunneling/+page.svelte`, `gui-tauri/src/routes/split-tunneling/websites/+page.svelte`.

- [ ] **Step 1: Replace hardcoded colors with the theme vars**

In `split-tunneling/+page.svelte` `<style>`: change `.switch { … background: #c8ccce; … }` to `background: var(--switch-off);`. (The `.switch.on` already uses `var(--brand)`.)

In `split-tunneling/websites/+page.svelte` `<style>`: change `.snack { … background: #23282b; … }` to `background: var(--snack-bg);` and ensure `.snack` text stays `#fff` (readable on both `--snack-bg` values).

- [ ] **Step 2: Check + visual**

Run: `cd gui-tauri && npm run check` (0 errors); `npm run dev` → open `/split-tunneling` and `/split-tunneling/websites` in dark mode; confirm the toggle track, snackbar, cards, rows all theme correctly.

- [ ] **Step 3: Commit**
```bash
git add gui-tauri/src/routes/split-tunneling/+page.svelte gui-tauri/src/routes/split-tunneling/websites/+page.svelte
git commit -m "feat(ui): variable-ize split-tunnel colors so they theme in dark mode"
```

### Task A3: Home — match Figma Pro layout

**Files:** Modify `gui-tauri/src/routes/+page.svelte`.

Current Home is close (appbar + toggle + card). Changes to match the Figma Pro frame:
1. **Header:** wordmark → uppercase `SPARK`; add an **account-avatar** icon button on the right (inert); keep the menu button (inert). Header height 80 with the bottom hairline (`--border`).
2. **Rows:** remove the **Protocol** row entirely. Rename the **Routing** row to **Routing Mode**, make it a nav button → `/routing`, showing the current mode. Keep VPN Status, Smart Location, Split Tunneling.
3. **Metrics:** toggle 150×80 (knob 60, travel 70→ so `translateX(70px)` with 10px gap and 5px pad already ≈; bump track to 150×80, knob 60, top/left 10, `translateX(80px)`). Row label → `--text-tertiary` weight 500. Keep the rest.
4. **Routing-mode value:** add `routingMode` state polled alongside split state.

- [ ] **Step 1: Script — routing-mode state + remove protocol**

In the `<script>`, add routing-mode state + loader (mirrors `splitEnabled`/`loadSplit`), using the new backend method from Task B7 (`getRoutingMode()` returns `"smart" | "full"`; until B7 lands, `MockBackend` returns `"smart"`):
```ts
  let routingMode = $state<"smart" | "full">("smart");
  async function loadRouting() {
    try { routingMode = await backend.getRoutingMode(); } catch { /* keep last */ }
  }
  const routingModeLabel = $derived(routingMode === "full" ? "Full Tunnel" : "Smart Routing");
```
Add `loadRouting()` to the `onMount` initial calls and the poll interval body (next to `loadSplit()`). Remove the now-unused `status.routing`/`status.protocol` usages for these rows (the `protocol` row is deleted; `routing` row uses `routingModeLabel`).

- [ ] **Step 2: Template — header avatar + SPARK, drop Protocol, Routing Mode nav**

Header: change `<span class="wordmark">Spark</span>` to `<span class="wordmark">SPARK</span>` and add a trailing account button so the header is menu · wordmark · avatar:
```svelte
  <header class="appbar">
    <button class="iconbtn" aria-label="Menu">{@render menu()}</button>
    <span class="wordmark">SPARK</span>
    <button class="iconbtn" aria-label="Account">{@render account()}</button>
  </header>
```
(Extract the existing inline hamburger SVG into a `{#snippet menu()}` and add an `{#snippet account()}` — a `person`-in-circle glyph.)

Delete the entire **Protocol** `.tile` block (the `<div class="tile">…Protocol…</div>` and its following `<div class="divider">`).

Replace the **Routing** `.tile` (static) with a nav button to `/routing` showing the mode:
```svelte
  <button class="tile nav" onclick={() => goto("/routing")}>
    <div class="tile-head"><span class="ic">{@render route()}</span><span class="label">Routing Mode</span></div>
    <div class="tile-body"><span class="value">{routingModeLabel}</span><span class="chev">{@render chevron()}</span></div>
  </button>
```

Add the `account` snippet near the others:
```svelte
{#snippet account()}
  <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="10" r="3"/><path d="M6.5 19a5.5 5.5 0 0 1 11 0"/></svg>
{/snippet}
{#snippet menu()}
  <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
{/snippet}
```

- [ ] **Step 3: Style — header layout, SPARK, toggle metrics, label weight**

In `<style>`:
- `.appbar { justify-content: space-between; height: 64px; }` (three items spread; keep the hairline + elevation). Keep `.iconbtn` as-is.
- `.wordmark { font-size: 20px; font-weight: 700; letter-spacing: 1.5px; color: var(--text-primary); }` (uppercase comes from the literal text `SPARK`).
- Toggle: `.track { width: 150px; height: 80px; border-radius: 40px; }`, `.knob { width: 60px; height: 60px; top: 10px; left: 10px; }`, `.track.on .knob { transform: translateX(80px); }`, spinner recentred (`top: 18px; left: 18px;` for the 44px ring inside the 80px track).
- `.label { font-size: 14px; font-weight: 500; color: var(--text-tertiary); }` (match Figma overline).

- [ ] **Step 4: Check + visual (both themes)**

Run: `cd gui-tauri && npm run check` (0 errors); `npm run dev` → Home shows SPARK + avatar, no Protocol row, Routing Mode row → `/routing` (404 until B8), toggle sized per Figma, both light+dark match the Figma Pro frames.

- [ ] **Step 5: Commit**
```bash
git add gui-tauri/src/routes/+page.svelte
git commit -m "feat(ui): Home matches Figma Pro (SPARK + avatar, Routing Mode row, no Protocol)"
```

---

## Phase B — Routing Mode (screen + backend)

### Task B1: core `RoutingMode` type

**Files:** Create `core/src/routing_mode.rs`; modify `core/src/lib.rs`.

- [ ] **Step 1: Add module decl** — in `core/src/lib.rs`, add `pub mod routing_mode;`.

- [ ] **Step 2: Write failing tests** (`core/src/routing_mode.rs`)
```rust
//! The user's routing mode — Smart Routing (apply fetched rules) vs Full Tunnel (proxy everything
//! not user-bypassed). A per-device preference the UI sets; applied by the router.

use serde::{Deserialize, Serialize};

/// Smart = apply the fetched smart-routing rules (default). Full = force all non-bypassed flows
/// through the proxy (ad-block Reject still honored; split-tunnel bypass still Direct).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RoutingMode {
    #[default]
    Smart,
    Full,
}

/// Parse the wire token (`"smart"`/`"full"`); unknown → Smart (fail-safe default).
pub fn parse(s: &str) -> RoutingMode {
    match s.trim().to_ascii_lowercase().as_str() {
        "full" => RoutingMode::Full,
        _ => RoutingMode::Smart,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_tokens() {
        assert_eq!(parse("full"), RoutingMode::Full);
        assert_eq!(parse("Full"), RoutingMode::Full);
        assert_eq!(parse("smart"), RoutingMode::Smart);
        assert_eq!(parse("nonsense"), RoutingMode::Smart); // fail-safe
    }
    #[test]
    fn default_is_smart() {
        assert_eq!(RoutingMode::default(), RoutingMode::Smart);
    }
}
```

- [ ] **Step 3: Run** — `cargo test -p spark-core --lib routing_mode` → PASS (2 tests). (No feature gate — always compiled, like `split_tunnel`.)

- [ ] **Step 4: Commit**
```bash
git add core/src/routing_mode.rs core/src/lib.rs
git commit -m "feat(core): RoutingMode type (Smart/Full) + parse"
```

### Task B2: `Router` — live-swappable mode

**Files:** Modify `core/src/rules/router.rs`.

- [ ] **Step 1: Write failing tests** (append to `mod tests`)
```rust
    #[test]
    fn full_tunnel_forces_proxy_but_keeps_reject_and_bypass() {
        use crate::routing_mode::RoutingMode;
        use crate::split_tunnel::SplitTunnel;
        let r = router(); // doubleclick.net → Reject; app.discord.com → Direct (base)
        r.set_mode(RoutingMode::Full);
        // A base-Direct domain is forced to Proxy in Full Tunnel.
        assert_eq!(r.decide("1.2.3.4".parse().unwrap(), Some("app.discord.com")), Action::Proxy);
        // Ad-block Reject still applies.
        assert_eq!(r.decide("1.2.3.4".parse().unwrap(), Some("doubleclick.net")), Action::Reject);
        // Split-tunnel bypass still routes Direct even in Full Tunnel.
        r.set_user_bypass(Some(&SplitTunnel { enabled: true, domains: vec!["app.discord.com".into()], ips: vec![] }));
        assert_eq!(r.decide("1.2.3.4".parse().unwrap(), Some("app.discord.com")), Action::Direct);
        // Back to Smart → base rules again.
        r.set_user_bypass(None);
        r.set_mode(RoutingMode::Smart);
        assert_eq!(r.decide("1.2.3.4".parse().unwrap(), Some("app.discord.com")), Action::Direct);
    }
```

- [ ] **Step 2: Run** — `cargo test -p spark-core --lib --features smart-routing rules::router` → FAIL (no `set_mode`).

- [ ] **Step 3: Implement** — add a `mode` field + `set_mode` + Full handling in `decide`.

Add to `use` (already has `RwLock`). Add field to the struct:
```rust
    /// The routing mode. Full = suppress base Direct/Proxy and proxy everything not user-bypassed
    /// (ad-block Reject still honored). Swapped live like `user_bypass`.
    mode: RwLock<crate::routing_mode::RoutingMode>,
```
In `new`, init `mode: RwLock::new(crate::routing_mode::RoutingMode::default())`. Add:
```rust
    /// Set the routing mode live (poison-tolerant recovery, like `set_user_bypass`).
    pub fn set_mode(&self, mode: crate::routing_mode::RoutingMode) {
        *self.mode.write().unwrap_or_else(|e| e.into_inner()) = mode;
    }
```
In `decide`, after the user-bypass check (which returns `Direct`) and before the final `base` line, branch on mode:
```rust
        let full = matches!(
            *self.mode.read().unwrap_or_else(|e| e.into_inner()),
            crate::routing_mode::RoutingMode::Full
        );
        match self.base.lookup(domain, ip) {
            Some(Action::Reject) => Action::Reject,           // ad-block always wins
            Some(a) if !full => a,                            // Smart: base decides
            _ => Action::Proxy,                               // Full (or unmatched) → Proxy
        }
```
(Replace the existing `self.base.lookup(domain, ip).unwrap_or(Action::Proxy)` tail with the above match.)

- [ ] **Step 4: Run** — `cargo test -p spark-core --lib --features smart-routing rules::router` → PASS (existing + new).

- [ ] **Step 5: Commit**
```bash
git add core/src/rules/router.rs
git commit -m "feat(core): Router Full-Tunnel mode (proxy non-bypassed; keep Reject + bypass)"
```

### Task B3: `fd_tunnel` — mode handle, threading, `set_routing_mode`

**Files:** Modify `core/src/fd_tunnel.rs`.

Mirror the split-tunnel slice exactly (the `active_router()` handle already exists from #49):
- [ ] **Step 1:** Add `pub fn set_routing_mode(s: &str) -> bool` next to `set_split_tunnel` (both cfg variants): parse via `crate::routing_mode::parse`, clone the `active_router()` Arc under the poison-tolerant lock, `r.set_mode(mode)` → true; `None` → false. Non-`smart-routing` stub returns false.
- [ ] **Step 2:** Thread an initial `routing_mode: Option<&str>` param through `run_fd_dispatch` → the data-path chain → `setup_routing_and_udp` (same signature spots as `split_tunnel`); in `setup_routing_and_udp` (smart-routing variant), after building the router + `set_user_bypass`, call `router.set_mode(crate::routing_mode::parse(routing_mode.unwrap_or("smart")))`. Include it in the activation condition is unnecessary (mode alone doesn't need the router path; only rules/bypass do) — but if a bypass/rules path is built, apply the mode. Add `_routing_mode` to the non-smart-routing variant.
- [ ] **Step 3:** Build check (core only — FFI shims updated in B4/B5): `cargo build -p spark-core --all-features` + `cargo clippy -p spark-core --all-features -- -D warnings` + `cargo fmt`.
- [ ] **Step 4: Commit** `git add core/src/fd_tunnel.rs && git commit -m "feat(core): fd_tunnel set_routing_mode handle + thread initial mode"`

### Task B4: Apple C-ABI — `spark_set_routing_mode` + connect arg

**Files:** Modify `platforms/apple/src/lib.rs`, `platforms/apple/include/spark.h`.

- [ ] **Step 1:** Add `routing_mode: *const c_char` as the last arg of `spark_tunnel_run`, decode leniently (null/bad → None) like `split_tunnel`, pass to `run_fd_dispatch` (new last param).
- [ ] **Step 2:** Add `spark_set_routing_mode(mode: *const c_char) -> c_int` mirroring `spark_set_split_tunnel` (null → -1; else `fd_tunnel::set_routing_mode(s)` → 0/-1).
- [ ] **Step 3:** Update `include/spark.h`: add the `routing_mode` param to `spark_tunnel_run` and declare `int32_t spark_set_routing_mode(const char *mode);` (comment: -1 if NULL/invalid/no active tunnel).
- [ ] **Step 4:** Build: `cargo build -p spark-apple --features anytls,multi-server,bootstrap-dns,config-fetch,samizdat,shadowsocks,hysteria2,fronted-meek,smart-routing` (+ clippy/fmt).
- [ ] **Step 5: Commit** `feat(apple-ffi): routing_mode connect arg + spark_set_routing_mode`

### Task B5: Android JNI — `nativeSetRoutingMode` + `nativeRun` arg

**Files:** Modify `platforms/android/src/lib.rs`, `platforms/android/demo/app/src/main/kotlin/org/getlantern/spark/SparkBridge.kt`, `SparkVpnService.kt`.

- [ ] **Step 1:** Add `routing_mode: JString` as the last `nativeRun` arg, decode leniently, pass to `run_fd_dispatch` (last param). Add `Java_..._nativeSetRoutingMode(json: JString) -> jboolean` mirroring `nativeSetSplitTunnel`.
- [ ] **Step 2:** Kotlin: add `routingMode: String?` as the last `external fun nativeRun` param; add `external fun nativeSetRoutingMode(mode: String): Boolean`. Update the `nativeRun(...)` call in `SparkVpnService.kt` to pass `null` (Compose UI wiring is out of scope).
- [ ] **Step 3:** Build `cargo build -p spark-android` (+ clippy/fmt).
- [ ] **Step 4: Commit** `feat(android-ffi): nativeRun routingMode arg + nativeSetRoutingMode`

### Task B6: whole-workspace gate

- [ ] `cargo fmt --all` + `cargo clippy --workspace --all-targets --all-features -- -D warnings` → clean. Commit any fmt fixes.

### Task B7: macOS NE Swift — routingMode at start + live update

**Files:** Modify `platforms/apple/Sources/SparkNE/PacketTunnelProvider.swift`.

- [ ] **Step 1:** In `startTunnel`, read `providerConfiguration["routingMode"]` (String) and pass as the new last arg to `spark_tunnel_run`, using the same nested `withCString` pattern as `config`/`splitTunnel` (keep all C-strings live across the blocking call).
- [ ] **Step 2:** In `handleAppMessage`, add `case "routingMode":` — read `obj["mode"] as? String ?? "smart"`, call `spark_set_routing_mode` via `withCString`, reply `{"ok":true|false}` exactly like the `select`/`splitTunnel` cases.
- [ ] **Step 3:** Commit `feat(macos-ne): routingMode providerConfiguration + handleAppMessage live update`. (Swift compiles in the DMG build; verify there.)

### Task B8: Tauri commands — get/set routing mode

**Files:** Modify `gui-tauri/src-tauri/src/config.rs`, `gui-tauri/src-tauri/src/lib.rs`.

- [ ] **Step 1 (config.rs):** Add `load_routing_mode() -> String` / `save_routing_mode(mode: &str) -> Result<(),String>` — persist `routing_mode` (a plain `"smart"`/`"full"` string) to `<app-config-dir>/org.getlantern.spark/routing_mode.txt` (reuse the per-OS dir helper from `split_tunnel_path`; factor a shared `config_dir()` if clean). Validate the value is `"smart"`/`"full"` on save (else Err); default `"smart"` on load.
- [ ] **Step 2 (lib.rs):** Add `spark_get_routing_mode() -> Result<String,String>` and `spark_set_routing_mode(mode: String) -> Result<(),String>` (macOS: persist + live-push `{"cmd":"routingMode","mode":mode}` when connected, same gate as split-tunnel; non-macOS: persist). Register both in `generate_handler!`. Inject `providerConfiguration["routingMode"] = load_routing_mode()` at connect (extend the NSDictionary that already carries `config`/`splitTunnel`).
- [ ] **Step 3:** Build `cd gui-tauri/src-tauri && cargo build` (+ clippy/fmt).
- [ ] **Step 4: Commit** `feat(tauri): routing-mode get/set commands (persist + inject + live push)`

### Task B9: `SparkBackend` seam

**Files:** Modify `gui-tauri/src/lib/spark_backend.ts`, `gui-tauri/src/lib/tauri_backend.ts`.

- [ ] **Step 1:** Add to the interface: `getRoutingMode(): Promise<"smart" | "full">` / `setRoutingMode(mode: "smart" | "full"): Promise<void>`. Implement in `MockBackend` (in-memory, default `"smart"`).
- [ ] **Step 2:** `TauriBackend`: `getRoutingMode` → `invoke<string>("spark_get_routing_mode")` cast to the union; `setRoutingMode` → `invoke("spark_set_routing_mode", { mode })`.
- [ ] **Step 3:** `npm run check` → 0 errors.
- [ ] **Step 4: Commit** `feat(ui): routing-mode backend seam (interface + Mock + Tauri)`

### Task B10: `/routing` screen

**Files:** Create `gui-tauri/src/routes/routing/+page.svelte`.

Per Figma `4210-34619` (appbar + two radios + info note). Mirror the `/split-tunneling` screen's structure/classes (copy the shared `.app/.appbar/.iconbtn/.title/.scroll/.card` styles from `split-tunneling/+page.svelte`).

- [ ] **Step 1: Create the component**
```svelte
<script lang="ts">
  import { onMount } from "svelte";
  import { goto } from "$app/navigation";
  import { MockBackend, type SparkBackend } from "$lib/spark_backend";
  import { TauriBackend, isTauri } from "$lib/tauri_backend";

  const backend: SparkBackend = isTauri() ? new TauriBackend() : new MockBackend();
  let mode = $state<"smart" | "full">("smart");
  onMount(async () => { try { mode = await backend.getRoutingMode(); } catch {} });

  async function choose(m: "smart" | "full") {
    mode = m;
    try { await backend.setRoutingMode(m); } catch {}
    goto("/");
  }
</script>

<main class="app">
  <header class="appbar">
    <button class="iconbtn" aria-label="Back" onclick={() => goto("/")}>
      <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
    </button>
    <span class="title">Routing Mode</span>
  </header>

  <div class="scroll">
    <div class="card">
      <button class="row" onclick={() => choose("smart")}>
        <div class="meta"><div class="name">Smart Routing</div><div class="sub">Rule-based routing optimized for your region</div></div>
        <span class="radio" class:on={mode === "smart"} aria-hidden="true"></span>
      </button>
      <div class="divider"></div>
      <button class="row" onclick={() => choose("full")}>
        <div class="meta"><div class="name">Full Tunnel</div><div class="sub">Routes all traffic through VPN</div></div>
        <span class="radio" class:on={mode === "full"} aria-hidden="true"></span>
      </button>
    </div>
    <div class="note">
      <span class="ic" aria-hidden="true">ⓘ</span>
      <p>Smart Routing uses region-specific rules to automatically send traffic that needs the VPN through Spark. All other traffic goes direct for speed and reliability.</p>
    </div>
  </div>
</main>

<style>
  /* Copy shared .app/.appbar/.iconbtn/.title/.scroll/.card/.row/.meta/.name/.sub/.divider from
     split-tunneling/+page.svelte (trim unused to avoid svelte-check warnings). Additions: */
  .row { display: flex; align-items: center; gap: 12px; width: 100%; padding: 15px 16px; background: none; border: none; cursor: pointer; font-family: var(--font); text-align: left; }
  .radio { width: 22px; height: 22px; border-radius: 50%; border: 2px solid var(--text-tertiary); flex-shrink: 0; position: relative; }
  .radio.on { border-color: var(--brand); }
  .radio.on::after { content: ""; position: absolute; inset: 4px; border-radius: 50%; background: var(--brand); }
  .note { display: flex; gap: 12px; align-items: flex-start; margin-top: 12px; padding: 12px 16px; border: 1px solid var(--border); border-radius: 8px; }
  .note .ic { color: var(--text-tertiary); }
  .note p { margin: 0; font-size: 14px; font-weight: 500; line-height: 1.4; color: var(--text-secondary); }
</style>
```

- [ ] **Step 2: Check + visual (both themes)** — `npm run check` (0 errors); `npm run dev` → Home → Routing Mode → radios reflect + set the mode, note renders, both themes match Figma.

- [ ] **Step 3: Commit** `feat(ui): Routing Mode screen (Smart/Full + note)`

### Task B11: Final gate + on-device

- [ ] **Step 1:** `npm run check` (0), `cargo fmt --all`, `cargo clippy --workspace --all-targets --all-features -- -D warnings` (clean), `cargo test -p spark-core --features smart-routing` (green).
- [ ] **Step 2:** Notarized DMG: `packaging/macos/build-tauri-dmg.sh` (compiles the Swift → verifies B7). Install; confirm Home/Routing/Split-tunnel match Figma in **both** OS appearances; switch Routing Mode → Full and confirm a normally-Direct domain now goes through the proxy (and an ad domain still blocked, a bypassed domain still direct).
- [ ] **Step 3:** Commit any fixes.

---

## Self-review

**Spec coverage:** dark theming (A1) ✓; split-tunnel dark (A2) ✓; SPARK rebrand — wordmark already "Spark", A3 uppercases it + no other user-facing "Lantern" strings exist in `gui-tauri/src` (verify with a grep in A3) ✓; Home Pro layout, no free chrome, Routing Mode row (A3) ✓; Routing Mode screen (B10) + backend Smart/Full with Reject+bypass preserved (B1–B9) ✓; OS-follow dark (A1) ✓; app split-tunnel stays deferred (untouched) ✓; verification incl. both-theme visual diff + on-device (A1/A3/B10/B11) ✓.

**Placeholder scan:** dark hexes in A1 are concrete starting values with an explicit fine-tune-against-Figma step (A1 Step 4) — not a TODO. B3–B9 mechanical FFI tasks reference the just-merged split-tunnel functions as the exact pattern (they exist in-tree at named locations) and give the specific signatures/snippets to add. No "TBD"/"similar to".

**Type consistency:** `RoutingMode { Smart, Full }` (core) ↔ wire `"smart"`/`"full"` ↔ TS union `"smart" | "full"` ↔ `getRoutingMode`/`setRoutingMode` (seam) ↔ `spark_get/set_routing_mode` (Tauri) ↔ `spark_set_routing_mode`/`nativeSetRoutingMode` (FFI) ↔ `set_routing_mode`/`Router::set_mode` (core) — consistent. `routingModeLabel` (Home) derives "Smart Routing"/"Full Tunnel" from the union. `--snack-bg`/`--switch-off` defined in A1 and consumed in A2.
