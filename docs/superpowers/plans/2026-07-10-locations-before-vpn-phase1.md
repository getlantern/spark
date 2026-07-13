# Locations Before VPN — Phase 1 (read/persist cache) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Show the location list on macOS startup *before* the VPN is turned on, by reading the tunnel's shared on-disk `config_raw.json` cache (which persists between sessions).

**Architecture:** The NE caches the fetched `config_raw.json` into the shared **app-group container** (`group.org.getlantern.spark`, subdir `config/`). The plugin's `AppleControl::servers()` already returns a static list from a `SPARK_CONFIG` TOML dev-override before connecting; add a fallback that, when that TOML list is empty, parses the cached `config_raw.json`'s top-level `servers[]` (geo entries: `country`/`country_code`/`city`) into `ServerInfo`. Live latency/health overlay from the NE stays unchanged (only when connected).

**Tech Stack:** Rust, `serde_json`, Tauri v2 plugin (`tauri-plugin-spark-vpn`).

**Spec:** `docs/superpowers/specs/2026-07-10-locations-before-vpn-design.md` (Phase 1)
**Branch:** `fisk/locations-before-vpn`

**Verified facts (do not re-derive):**
- File: `gui-tauri/tauri-plugin-spark-vpn/src/desktop.rs`. It has a free fn `servers_from_config() -> Vec<ServerInfo>` (parses a TOML `[transport].servers` from `resolve()`), and `AppleControl::servers()` which does `let mut list = servers_from_config();` then overlays live data via `ne_spike::send_provider_message` **only when connected**.
- The NE writes the cache to `{app-group container}/config/config_raw.json`, where the container is `group.org.getlantern.spark` (PacketTunnelProvider.swift uses `containerURL(forSecurityApplicationGroupIdentifier: "group.org.getlantern.spark").appendingPathComponent("config")`). For the non-sandboxed macOS app (same user), that resolves to `~/Library/Group Containers/group.org.getlantern.spark/config/config_raw.json`.
- The Tauri app bundle **already carries** `com.apple.security.application-groups = group.org.getlantern.spark` (`gui-tauri/src-tauri/Release.entitlements`), so it can read the container — **no entitlement change needed**.
- `config_raw.json` is JSON with a **top-level** `servers` array; each entry has `city`, `country`, `country_code` (+ `latitude`/`longitude`, unused here).
- `serde_json` is already a dependency of the plugin crate.
- `crate::models::ServerInfo` fields: `index: usize`, `name: Option<String>`, `country: Option<String>`, `country_code: Option<String>`, `city: Option<String>`, `protocol: Option<String>`, `latency_ms: Option<u64>`, `healthy: bool`, `is_current: bool`.

**Scope:** macOS only in this plan (the reachable, testable target; the app-group path is macOS-specific). The JSON parser (`servers_from_cache_json`) is platform-agnostic and reused by the Windows/Linux/Android Phase-1 follow-ups (their shared-dir resolution differs and is out of scope here).

---

## File structure

- **Modify** `gui-tauri/tauri-plugin-spark-vpn/src/desktop.rs` — add `servers_from_cache_json` (pure parser, unit-tested), `shared_config_cache_dir` (macOS app-group path), `servers_from_cache` (read + parse), and a fallback in `AppleControl::servers()`.

No new files, no new deps.

---

## Task 1: `servers_from_cache_json` — parse config_raw.json servers[]

**Files:**
- Modify: `gui-tauri/tauri-plugin-spark-vpn/src/desktop.rs`

- [ ] **Step 1: Write the failing test**

Add this test module at the end of `desktop.rs`:

```rust
#[cfg(test)]
mod cache_tests {
    use super::servers_from_cache_json;

    #[test]
    fn parses_top_level_servers_geo_into_serverinfo() {
        let raw = r#"{
            "servers": [
                {"country": "U.S.A.", "country_code": "US", "city": "Ashburn", "latitude": 1.0, "longitude": 2.0},
                {"country": "Germany", "country_code": "DE", "city": "Frankfurt"}
            ],
            "options": {}
        }"#;
        let list = servers_from_cache_json(raw);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].index, 0);
        assert_eq!(list[0].country.as_deref(), Some("U.S.A."));
        assert_eq!(list[0].country_code.as_deref(), Some("US"));
        assert_eq!(list[0].city.as_deref(), Some("Ashburn"));
        assert_eq!(list[1].index, 1);
        assert_eq!(list[1].city.as_deref(), Some("Frankfurt"));
        // No live data is invented from the static cache.
        assert!(!list[0].healthy);
        assert!(list[0].latency_ms.is_none());
        assert!(!list[0].is_current);
    }

    #[test]
    fn empty_or_invalid_json_yields_empty_list() {
        assert!(servers_from_cache_json("").is_empty());
        assert!(servers_from_cache_json("not json").is_empty());
        assert!(servers_from_cache_json(r#"{"options":{}}"#).is_empty()); // no servers key
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --manifest-path gui-tauri/tauri-plugin-spark-vpn/Cargo.toml servers_from_cache_json`
Expected: FAIL to compile — `cannot find function servers_from_cache_json`.

- [ ] **Step 3: Implement the parser**

Add this free fn near `servers_from_config` in `desktop.rs`:

```rust
/// Parse a fetched `config_raw.json` body (Lantern shape) into the static location list. The
/// top-level `servers` array carries geo entries (`country`/`country_code`/`city`); index by
/// position, matching `servers_from_config`. No live fields are invented (healthy=false, etc.).
fn servers_from_cache_json(raw: &str) -> Vec<ServerInfo> {
    use serde::Deserialize;
    #[derive(Deserialize)]
    struct Root {
        #[serde(default)]
        servers: Vec<Entry>,
    }
    #[derive(Deserialize)]
    struct Entry {
        country: Option<String>,
        country_code: Option<String>,
        city: Option<String>,
    }
    let root: Root = match serde_json::from_str(raw) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    root.servers
        .into_iter()
        .enumerate()
        .map(|(i, e)| ServerInfo {
            index: i,
            name: None,
            country: e.country,
            country_code: e.country_code,
            city: e.city,
            protocol: None,
            latency_ms: None,
            healthy: false,
            is_current: false,
        })
        .collect()
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test --manifest-path gui-tauri/tauri-plugin-spark-vpn/Cargo.toml servers_from_cache_json`
Expected: 2 tests pass.

- [ ] **Step 5: Commit**

```bash
cd /Users/afisk/go/src/github.com/getlantern/spark-app-split-tunneling
git add gui-tauri/tauri-plugin-spark-vpn/src/desktop.rs
git commit -m "locations: parse config_raw.json servers[] into the static list"
```

---

## Task 2: shared cache dir + reader

**Files:**
- Modify: `gui-tauri/tauri-plugin-spark-vpn/src/desktop.rs`

- [ ] **Step 1: Add the macOS app-group cache dir resolver + reader**

Add these free fns to `desktop.rs`:

```rust
/// The shared app-group container dir where the NE caches `config_raw.json`. On macOS the app +
/// extension share `group.org.getlantern.spark`; for the non-sandboxed app (same user) this is
/// `~/Library/Group Containers/group.org.getlantern.spark/config`. Returns `None` if `$HOME` is
/// unset or on platforms without a resolved shared dir yet (Windows/Linux — a Phase-1 follow-up).
fn shared_config_cache_dir() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var_os("HOME")?;
        Some(
            PathBuf::from(home)
                .join("Library/Group Containers/group.org.getlantern.spark/config"),
        )
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

/// Location list read from the NE's shared `config_raw.json` cache, or empty if there's no cache
/// yet (never fetched) or it can't be read/parsed.
fn servers_from_cache() -> Vec<ServerInfo> {
    let Some(dir) = shared_config_cache_dir() else {
        return Vec::new();
    };
    match std::fs::read_to_string(dir.join("config_raw.json")) {
        Ok(raw) => servers_from_cache_json(&raw),
        Err(_) => Vec::new(),
    }
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo build --manifest-path gui-tauri/tauri-plugin-spark-vpn/Cargo.toml`
Expected: builds clean. `shared_config_cache_dir`/`servers_from_cache` are unused until Task 3 → a `dead_code` warning for them is EXPECTED here. Do NOT add `#[allow(dead_code)]`.

Run: `cargo test --manifest-path gui-tauri/tauri-plugin-spark-vpn/Cargo.toml` — Task 1 tests still pass.

- [ ] **Step 3: Commit**

```bash
cd /Users/afisk/go/src/github.com/getlantern/spark-app-split-tunneling
git add gui-tauri/tauri-plugin-spark-vpn/src/desktop.rs
git commit -m "locations: resolve shared app-group cache dir + read config_raw.json"
```

---

## Task 3: wire the cache fallback into `AppleControl::servers()`

**Files:**
- Modify: `gui-tauri/tauri-plugin-spark-vpn/src/desktop.rs`

- [ ] **Step 1: Add the fallback**

In `AppleControl::servers()`, the first line is `let mut list = servers_from_config();`. Immediately after it, insert the cache fallback so a fresh install with no `SPARK_CONFIG` override still shows the pool from the persisted cache:

```rust
        let mut list = servers_from_config();
        // No TOML dev-override → fall back to the NE's shared config_raw.json cache so the location
        // list shows before connecting (and persists between sessions).
        if list.is_empty() {
            list = servers_from_cache();
        }
```

Leave the rest of `servers()` (the connected live-overlay via `send_provider_message`) unchanged — it already overlays onto `list` by index, and no-ops when disconnected.

- [ ] **Step 2: Verify it compiles + tests pass**

Run: `cargo build --manifest-path gui-tauri/tauri-plugin-spark-vpn/Cargo.toml`
Expected: builds clean, no `dead_code` warnings now (both new fns are used).
Run: `cargo test --manifest-path gui-tauri/tauri-plugin-spark-vpn/Cargo.toml`
Expected: all pass.

- [ ] **Step 3: Commit**

```bash
cd /Users/afisk/go/src/github.com/getlantern/spark-app-split-tunneling
git add gui-tauri/tauri-plugin-spark-vpn/src/desktop.rs
git commit -m "locations: AppleControl::servers() falls back to the shared cache before connect"
```

---

## Task 4: gate + on-device verification + PR

**Files:** none (verification + PR).

- [ ] **Step 1: Rust gate (plugin)**

Run:
```bash
cd /Users/afisk/go/src/github.com/getlantern/spark-app-split-tunneling
PLUG=gui-tauri/tauri-plugin-spark-vpn
cargo fmt --manifest-path $PLUG/Cargo.toml --all -- --check
cargo clippy --manifest-path $PLUG/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path $PLUG/Cargo.toml
```
Expected: fmt clean, clippy clean, tests pass.

- [ ] **Step 2: On-device verification (macOS)**

Build the DMG (`./packaging/macos/build-tauri-dmg.sh`), install, and verify:
1. With the VPN **disconnected** (but after at least one prior connect so the cache exists), open the location list / tray Select Location → the pool is listed **without connecting**.
2. Quit the app fully, relaunch, and **before connecting** confirm the list is present (persisted between sessions).
3. Connect → live latency/health/current still overlay (unchanged behavior).

Note (expected limitation, addressed in Phase 2): a *fresh* profile that has never connected shows an empty list until the first connect — Phase 2 adds the startup fetch that fills it without connecting.

- [ ] **Step 3: Push + open PR**

```bash
git push -u origin fisk/locations-before-vpn
gh pr create --repo getlantern/spark --title "locations: show the list before VPN (Phase 1 — read shared cache)" --body "$(cat <<'EOF'
## Summary
Phase 1 of making the location list available before the VPN is on (spec: docs/superpowers/specs/2026-07-10-locations-before-vpn-design.md).

`AppleControl::servers()` now falls back to the NE's shared `config_raw.json` cache (app-group container `group.org.getlantern.spark/config`) when there's no `SPARK_CONFIG` TOML dev-override — so the location list shows on startup before connecting, and persists between sessions. The connected live-latency/health overlay is unchanged. The app already carries the app-group entitlement, so no signing change is needed.

Scope: macOS. The JSON parser is platform-agnostic and will be reused for the Windows/Linux/Android Phase-1 follow-ups; the always-fetch-on-startup piece is Phase 2.

## Test Plan
- [x] `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test` (plugin): `servers_from_cache_json` parsing (valid/empty/invalid).
- [x] macOS on-device: list shows before connect after a prior fetch; persists across relaunch; live overlay still works when connected.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 4: Review loop** (Copilot/CodeRabbit) via the `review-pr` skill until settled.

---

## Notes / known considerations (not Phase 1 work)

- **Index alignment:** the cached geo `servers[]` is indexed by position, matching the existing `servers_from_config` behavior; the connected overlay merges by that index. If the live pool ever reorders/skips entries (e.g. unsupported outbounds), cached-vs-live indices could drift — a pre-existing assumption, not introduced here. Revisit only if a mismatch is observed.
- **Windows/Linux Phase 1:** reuse `servers_from_cache_json`; add a `shared_config_cache_dir` arm once the service's cache dir shared with the app is confirmed.
- **Android Phase 1:** the cache lives in the app files dir (core runs in-process); `AndroidControl::servers()` reads it — separate task with the Android Phase-2 work.
