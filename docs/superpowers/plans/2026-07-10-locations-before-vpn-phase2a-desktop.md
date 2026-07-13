# Locations Before VPN — Phase 2a (Desktop) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** On every desktop launch, the app itself fetches the Lantern config (via the same kindling path the tunnel uses) into the shared cache — regardless of VPN state — so a fresh install shows the location list without ever connecting, and every launch refreshes it (stale-while-revalidate on top of Phase 1's instant cache read).

**Architecture:** Link a fetch-capable build of `spark-core` into `tauri-plugin-spark-vpn` (desktop targets only) and run `config::fetch::load_or_fetch` in a detached background task at plugin `setup`, against the same `shared_config_cache_dir()` Phase 1 reads. On a *changed* config, emit `spark://servers`; the window re-pulls `servers()` and the tray `refresh()`es. On 304/unchanged or failure, keep the cached list. The tunnel process keeps using the same cache, so an app-side fetch also warms the next connect.

**Tech Stack:** Rust (`spark-core` `config::fetch` + kindling/flint-fronted, BoringSSL via `anytls`), Tauri v2 plugin (`setup` background task, `app.emit`), SvelteKit frontend (`listen("spark://servers")`).

**Spec:** `docs/superpowers/specs/2026-07-10-locations-before-vpn-design.md` (Phase 2 + Phase 2a).

**Depends on:** Phase 1 (PR #82) merged — `shared_config_cache_dir()`, `servers_from_cache()`, and the NE `dataDir` write into the user container.

---

## Context an implementer must know

- **The plugin is its own cargo workspace** (`gui-tauri/tauri-plugin-spark-vpn/Cargo.toml` starts with `[workspace]`), depending on sibling crates by relative path (`spark-ipc = { path = "../../ipc" }`). Adding `spark-core = { path = "../../core", ... }` follows the same pattern.
- **`spark-core`'s data plane is NOT optional today.** `tun-rs`, `netstack-smoltcp`, `tokio`, and the `tun`/`netstack`/`proxy`/`transport`/`fd_tunnel` modules are always compiled (`core/src/lib.rs`, `core/Cargo.toml`). There is no existing way to compile "just the fetch surface."
- **`config-fetch` is heavy.** `core/Cargo.toml`: `config-fetch = ["anytls", "multi-server", "dep:flint-fronted", "dep:flint-kindling"]`, and `anytls` pulls `boring2`/`tokio-boring2` (BoringSSL + a cmake C build). This is unavoidable if we reuse the tunnel's censorship-resistant fetch path — which is the whole point of "reuse the exact cache-first fetch, share the cache." So **linking the fetch into the app grows the app binary by BoringSSL + kindling regardless of any data-plane gating.**
- The fetch entry point is `spark_core::config::fetch::load_or_fetch(dir: &Path, env: &FetchEnv) -> std::io::Result<(Config, CacheMeta)>` (`core/src/config/fetch/mod.rs:311`). `FetchEnv::from_env()` / `::prod()` / `::staging()` exist (`mod.rs:74-94`). It is cache-first + conditional (ETag/If-Modified-Since); a 304 does not rewrite the cache.
- The cache writer `core/src/config/fetch/cache.rs::store` → `write_atomic` (temp + rename) uses a **fixed** temp name `config_raw.tmp` — a real concurrent-writer hazard once the app writes too (Task 6).
- Events already in use: `app.emit("spark://state", ())`, `spark://navigate`, `spark://error` (`tray.rs:365,380,450`). The frontend listens in `gui-tauri/src/routes/+layout.svelte:47`. The window pulls the list through `SparkBackend.servers()` (`gui-tauri/src/lib/spark_backend.ts:55`, Tauri impl `tauri_backend.ts:22` → `invoke("plugin:spark-vpn|servers")`).
- The tray re-reads `servers()` via `crate::tray::refresh(&app)` (already called by mutating commands).

## File structure

- `core/Cargo.toml` — a `fetch` feature (Task 1 decides its exact contents from the spike).
- `core/src/lib.rs` — module gating so a fetch-only consumer compiles without the data plane (Task 1, only if the spike says lean is worth it).
- `core/src/config/fetch/cache.rs` — unique temp names + optional writer lock (Task 6).
- `gui-tauri/tauri-plugin-spark-vpn/Cargo.toml` — `spark-core` dep (desktop targets) with the chosen feature (Task 2).
- `gui-tauri/tauri-plugin-spark-vpn/src/config_fetch.rs` — new module: `fetch_into_shared_cache()` + changed-detection (Tasks 3–4).
- `gui-tauri/tauri-plugin-spark-vpn/src/lib.rs` — spawn the startup fetch task in `setup` (Task 5).
- `gui-tauri/src/routes/+layout.svelte` — `listen("spark://servers")` → re-pull (Task 7).

---

## Task 1: Spike — determine the fetch-only build feasibility + binary-size cost

**Goal:** Decide, with data, whether to (A) add a *lean* `fetch` feature that gates the data plane off, or (B) just link `config-fetch` as-is (accepting tun-rs/netstack ride along, since BoringSSL dominates either way). This is the load-bearing uncertainty; do it first and record the verdict in the spec.

**Files:**
- Modify (spike branch, may be reverted): `core/Cargo.toml`, `core/src/lib.rs`
- Record: append a "Phase 2a spike result" note to `docs/superpowers/specs/2026-07-10-locations-before-vpn-design.md`

- [ ] **Step 1: Baseline — does `config-fetch` even build in isolation on the host?**

Run: `cd core && cargo build --release --no-default-features --features config-fetch 2>&1 | tail -20`
Expected: either it builds, or it fails because `config`/`multi-server` need something. Record the outcome. (BoringSSL/cmake must be buildable on the dev host — it already is, since the tunnel builds.)

- [ ] **Step 2: Measure the size of `config-fetch` vs the full default build.**

Run:
```bash
cd core
cargo build --release 2>/dev/null && ls -l target/release/libspark_core.rlib | awk '{print "default:", $5}'
cargo build --release --no-default-features --features config-fetch 2>/dev/null && ls -l target/release/libspark_core.rlib | awk '{print "config-fetch:", $5}'
cargo tree --no-default-features --features config-fetch -e no-dev | grep -E "tun-rs|netstack|quinn|boring" || echo "none of tun/netstack/quinn/boring in tree"
```
Expected: confirm whether `tun-rs`/`netstack` are still pulled (they are, being non-optional) and that `boring` is present. This quantifies what a lean feature could save (the tun/netstack delta) vs what it can't (BoringSSL).

- [ ] **Step 3: Attempt the lean feature — gate the data plane.**

In `core/Cargo.toml`, make the data-plane deps optional and add features:
```toml
# in [dependencies], add `optional = true` to the data-plane-only deps:
netstack-smoltcp = { workspace = true, optional = true }
tun-rs = { workspace = true, optional = true }
# (tokio/bytes/futures stay non-optional — config::fetch needs tokio.)

[features]
# The OS data path (TUN + netstack + proxy + transports). Default-on so existing consumers
# (the tunnel builds) are unaffected; a fetch-only consumer turns default features off.
data-plane = ["dep:netstack-smoltcp", "dep:tun-rs"]
# Fetch-only surface: the kindling config fetch + cache, no data plane.
fetch = ["config-fetch"]
default = ["data-plane"]
```
In `core/src/lib.rs`, gate the data-plane modules:
```rust
#[cfg(feature = "data-plane")]
pub mod netstack;
#[cfg(feature = "data-plane")]
pub mod tun;
#[cfg(feature = "data-plane")]
pub mod proxy;
#[cfg(feature = "data-plane")]
pub mod packet;
// fd_tunnel already cfg'd to android/ios/macos — add `feature = "data-plane"` to that cfg.
```

- [ ] **Step 4: Try to compile the lean fetch surface.**

Run: `cd core && cargo build --release --no-default-features --features fetch 2>&1 | tail -40`

**Decision point (record the verdict):**
- **If it compiles cleanly** and the size saving vs `config-fetch`-with-data-plane is material (> ~500 KB in the rlib, or removes tun/netstack from the app's `cargo tree`): adopt approach **A (lean `fetch` feature)**. Keep these `core` changes; they become part of this task.
- **If `config::fetch`/`config`/`multi-server` transitively need `transport`/`netstack` types** (likely — `Config` and the pool selection reference transport configs) and untangling them balloons the diff: adopt approach **B**. **Revert the `core` changes**, and define `fetch = ["config-fetch"]` with `default = []`-style linkage left alone (the app just links `config-fetch`). The data plane rides along; BoringSSL was the dominant cost anyway.

- [ ] **Step 5: Record the verdict + numbers in the spec and commit.**

Append to the design spec under a new "## Phase 2a spike result (YYYY-MM-DD)" heading: which approach (A/B), the measured rlib sizes, and whether tun/netstack/quinn appear in the app's dep tree. Commit:
```bash
git add core/Cargo.toml core/src/lib.rs docs/superpowers/specs/2026-07-10-locations-before-vpn-design.md
git commit -m "locations phase2a: spike the fetch-only spark-core feature + record size verdict"
```
(For approach B, the commit only touches the spec + a `fetch = ["config-fetch"]` alias in `core/Cargo.toml`.)

---

## Task 2: Link the fetch feature into the plugin (desktop targets)

**Files:**
- Modify: `gui-tauri/tauri-plugin-spark-vpn/Cargo.toml`

- [ ] **Step 1: Add the dependency under the non-android desktop target.**

The plugin already has a `[target.'cfg(not(target_os = "android"))'.dependencies]` block. Add there (so Android, which fetches in-process via JNI in Phase 2b, does not link it):
```toml
# Fetch-only spark-core: run the kindling config fetch in the app process so the location list
# refreshes on every launch, independent of the tunnel. `fetch` = config-fetch (+ data-plane gated
# off per the Phase 2a spike). See docs/superpowers/plans/2026-07-10-locations-before-vpn-phase2a-desktop.md.
spark-core = { path = "../../core", default-features = false, features = ["fetch"] }
```
(If the spike chose approach B, `features = ["config-fetch"]` and drop `default-features = false`.)

- [ ] **Step 2: Verify it builds and links.**

Run: `cd gui-tauri/tauri-plugin-spark-vpn && cargo build 2>&1 | tail -20`
Expected: builds. Confirm the fetch symbols are reachable: `cargo tree -e no-dev | grep spark-core`.

- [ ] **Step 3: Commit.**

```bash
git add gui-tauri/tauri-plugin-spark-vpn/Cargo.toml gui-tauri/tauri-plugin-spark-vpn/Cargo.lock
git commit -m "locations phase2a: link fetch-only spark-core into the plugin (desktop)"
```

---

## Task 3: Plugin `config_fetch` module — `fetch_into_shared_cache`

**Files:**
- Create: `gui-tauri/tauri-plugin-spark-vpn/src/config_fetch.rs`
- Modify: `gui-tauri/tauri-plugin-spark-vpn/src/lib.rs` (add `#[cfg(not(target_os = "android"))] mod config_fetch;`)

- [ ] **Step 1: Write the failing test for change-detection.**

The one piece with real logic worth a unit test is "did the config change?" — we decide by comparing the on-disk `config_raw.json` bytes before and after the fetch (cheap, exact, no dependence on `load_or_fetch`'s internal 304 signalling). Create `config_fetch.rs` with a pure helper and its test:
```rust
//! App-side startup config fetch (desktop). Runs spark-core's kindling `load_or_fetch` against the
//! SAME shared cache dir the tunnel uses, so the location list refreshes on every launch regardless
//! of VPN state (Phase 2a). Change is detected by comparing the raw cache bytes before/after.

/// True if the cached raw config changed between `before` and `after` snapshots (either may be
/// `None` when the file was absent). Used to decide whether to emit `spark://servers`.
pub(crate) fn config_changed(before: &Option<Vec<u8>>, after: &Option<Vec<u8>>) -> bool {
    before != after
}

#[cfg(test)]
mod tests {
    use super::config_changed;

    #[test]
    fn detects_change_and_no_change() {
        let a = Some(b"{\"servers\":[]}".to_vec());
        let b = Some(b"{\"servers\":[{\"country\":\"US\"}]}".to_vec());
        assert!(config_changed(&None, &a)); // first fetch (absent -> present)
        assert!(config_changed(&a, &b)); // body changed
        assert!(!config_changed(&a, &a)); // unchanged (304)
        assert!(!config_changed(&None, &None)); // fetch failed, still nothing
    }
}
```

- [ ] **Step 2: Run it, watch it fail (module not wired).**

Add `#[cfg(not(target_os = "android"))] mod config_fetch;` to `lib.rs`.
Run: `cargo test config_fetch 2>&1 | tail -15`
Expected: compiles and PASS (the helper is trivial) — the failing-first value here is the compile wiring; if `config_changed` is missing it won't compile.

- [ ] **Step 3: Add the async fetch entry point (no unit test — it does real I/O/network).**

Append to `config_fetch.rs`:
```rust
use std::path::Path;

/// Read the raw cache bytes, or `None` if absent/unreadable.
fn snapshot(dir: &Path) -> Option<Vec<u8>> {
    std::fs::read(dir.join("config_raw.json")).ok()
}

/// Run one kindling fetch against the shared cache dir. Returns `Ok(true)` if the cached config
/// changed (caller emits `spark://servers`), `Ok(false)` on 304/unchanged, `Err` on fetch failure
/// (caller keeps the cached list — never clobbers). Never blocks the caller's critical path; run it
/// on a background task.
pub(crate) async fn fetch_into_shared_cache(dir: &Path) -> std::io::Result<bool> {
    let before = snapshot(dir);
    let env = spark_core::config::fetch::FetchEnv::from_env();
    // load_or_fetch writes the cache itself (cache-first, conditional). We ignore the returned
    // Config/CacheMeta here — Phase 1's servers_from_cache() re-reads the file on the next pull.
    let _ = spark_core::config::fetch::load_or_fetch(dir, &env).await?;
    let after = snapshot(dir);
    Ok(config_changed(&before, &after))
}
```

- [ ] **Step 4: Build.**

Run: `cargo build 2>&1 | tail -15`
Expected: builds (confirms `load_or_fetch`/`FetchEnv` signatures match).

- [ ] **Step 5: Commit.**

```bash
git add gui-tauri/tauri-plugin-spark-vpn/src/config_fetch.rs gui-tauri/tauri-plugin-spark-vpn/src/lib.rs
git commit -m "locations phase2a: config_fetch module (load_or_fetch into the shared cache + change detection)"
```

---

## Task 4: Resolve the shared cache dir for the fetch (reuse Phase 1's helper)

**Files:**
- Modify: `gui-tauri/tauri-plugin-spark-vpn/src/desktop.rs` (make `shared_config_cache_dir` reachable to `config_fetch` on desktop)

- [ ] **Step 1: Confirm the helper's visibility + cfg.**

Phase 1 defined `#[cfg(target_os = "macos")] fn shared_config_cache_dir() -> Option<PathBuf>` (`desktop.rs:691`). Phase 2a needs it on **all desktop targets** (Windows/Linux fetch too). Widen it and add the Windows/Linux arm the Phase 1 spec called out:
```rust
/// The shared cache dir the app + privileged tunnel both use. macOS: the app-group container the NE
/// now writes (Phase 1). Windows/Linux: a fixed machine path the service + app agree on.
#[cfg(not(target_os = "android"))]
pub(crate) fn shared_config_cache_dir() -> Option<std::path::PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var_os("HOME")?;
        Some(std::path::PathBuf::from(home).join("Library/Group Containers/group.org.getlantern.spark/config"))
    }
    #[cfg(target_os = "windows")]
    {
        // The service runs as LocalSystem; both agree on ProgramData.
        let base = std::env::var_os("ProgramData")?;
        Some(std::path::PathBuf::from(base).join("Lantern\\Spark\\config"))
    }
    #[cfg(target_os = "linux")]
    {
        // The service writes here; the app reads it. Matches the service's data dir.
        Some(std::path::PathBuf::from("/var/lib/spark/config"))
    }
}
```
Update Phase 1's macOS-only callers (`servers_from_cache`, the `connect` `dataDir` injection) to the widened item if the cfg changed — they were `#[cfg(target_os = "macos")]` and still compile since the macOS arm is unchanged.

> NOTE: the Windows/Linux **service** must actually write its cache to these same paths. If it currently uses a different dir, that is a small service-side change (out of this plan's plugin scope) — file it as a follow-up and, until then, gate the Windows/Linux startup fetch behind the dir existing. macOS is the primary target for this phase.

- [ ] **Step 2: Build for the host (macOS).**

Run: `cargo build 2>&1 | tail -15`
Expected: builds.

- [ ] **Step 3: Commit.**

```bash
git add gui-tauri/tauri-plugin-spark-vpn/src/desktop.rs
git commit -m "locations phase2a: widen shared_config_cache_dir to all desktop targets"
```

---

## Task 5: Spawn the startup fetch in plugin `setup` + emit `spark://servers`

**Files:**
- Modify: `gui-tauri/tauri-plugin-spark-vpn/src/lib.rs`

- [ ] **Step 1: Add the background fetch to `setup` (desktop only).**

In `init()`'s `.setup(|app, _api| { ... })`, after the existing control/tray wiring, add:
```rust
#[cfg(not(target_os = "android"))]
{
    // Always fetch on startup, regardless of VPN state, into the shared cache. Detached — a
    // failure never blocks startup, the window, or connect. On a *changed* config, tell the UI to
    // re-pull. Uses spark-core's own tokio runtime via Tauri's async runtime.
    let handle = app.handle().clone();
    tauri::async_runtime::spawn(async move {
        let Some(dir) = crate::desktop::shared_config_cache_dir() else { return };
        let _ = std::fs::create_dir_all(&dir);
        match crate::config_fetch::fetch_into_shared_cache(&dir).await {
            Ok(true) => {
                let _ = handle.emit("spark://servers", ());
            }
            Ok(false) => {} // 304 / unchanged — nothing to do
            Err(e) => {
                // Keep the cached list; surface under the NE debug channel for field diagnosis.
                crate::desktop::ne_spike::ne_debug(&format!("startup config fetch failed: {e}"));
            }
        }
    });
}
```
(`Emitter`/`emit` is already imported via `tauri::Manager` in `lib.rs`; add `use tauri::Emitter;` if `emit` isn't in scope.)

- [ ] **Step 2: Build.**

Run: `cd gui-tauri/tauri-plugin-spark-vpn && cargo build 2>&1 | tail -20`
Expected: builds. (`ne_spike::ne_debug` is macOS-only — if the fetch task compiles on Windows/Linux, guard the `ne_debug` call with `#[cfg(target_os = "macos")]` or use `tracing::warn!` instead. Prefer `tracing::warn!("startup config fetch failed: {e}")` for portability.)

- [ ] **Step 3: Commit.**

```bash
git add gui-tauri/tauri-plugin-spark-vpn/src/lib.rs
git commit -m "locations phase2a: spawn the startup config fetch in setup + emit spark://servers"
```

---

## Task 6: Make the cache writer safe for two concurrent writers

**Why:** Phase 2a introduces a second writer (the app) alongside the NE/tunnel. `write_atomic` reuses a fixed `config_raw.tmp` name, so two concurrent writers can corrupt the temp. Fix per the spec's staged-locking decision.

**Files:**
- Modify: `core/src/config/fetch/cache.rs`
- Test: inline `#[cfg(test)] mod tests` in the same file

- [ ] **Step 1: Write the failing test — unique temp names don't collide.**

Add a test that two `store` calls with distinct temp suffixes both succeed and the last body wins (simulating no corruption). Since temp uniqueness is process/thread-scoped, assert the temp path is not the fixed name:
```rust
#[test]
fn temp_path_is_unique_per_write() {
    let p = std::path::Path::new("/tmp/x/config_raw.json");
    let a = super::unique_tmp_path(p);
    let b = super::unique_tmp_path(p);
    assert_ne!(a, b, "two writers must not share a temp path");
    assert!(a.to_string_lossy().contains("config_raw"));
}
```

- [ ] **Step 2: Run it, watch it fail.**

Run: `cd core && cargo test --features fetch temp_path_is_unique 2>&1 | tail -10`
Expected: FAIL — `unique_tmp_path` not defined.

- [ ] **Step 3: Implement unique temp names.**

Replace the fixed-temp logic in `write_atomic`:
```rust
use std::sync::atomic::{AtomicU64, Ordering};
static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// A per-write temp path in the same dir as `path` (same-fs → atomic rename). Unique across
/// concurrent writers (pid + monotonic seq) so a second writer never clobbers the first's temp.
fn unique_tmp_path(path: &Path) -> PathBuf {
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("config");
    path.with_file_name(format!("{name}.{pid}.{seq}.tmp"))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = unique_tmp_path(path);
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}
```

- [ ] **Step 4: Run tests.**

Run: `cd core && cargo test --features fetch cache 2>&1 | tail -15`
Expected: PASS (new test + the existing `round_trips_raw_and_meta` / `store_overwrites_existing`).

- [ ] **Step 5: (Optional, if the spike/verification shows real contention) advisory writer lock.**

Only if on-device verification shows raw/meta inconsistency in practice: add a `config.lock` sidecar and take an exclusive advisory lock (`fs2::FileExt::lock_exclusive`) around the raw+meta `store`. Readers stay lock-free. Deferred by default — unique temp names remove the corruption; the raw/meta interleave is self-healing per cache.rs's own note. Document the decision in the commit message.

- [ ] **Step 6: Commit.**

```bash
git add core/src/config/fetch/cache.rs
git commit -m "config cache: unique temp names so concurrent writers (app + tunnel) can't corrupt the temp"
```

---

## Task 7: Frontend — listen for `spark://servers`, re-pull the list

**Files:**
- Modify: `gui-tauri/src/routes/+layout.svelte`

- [ ] **Step 1: Add the listener alongside the existing `spark://state` one.**

In the `onMount` where `spark://state`/`spark://navigate` are wired (`+layout.svelte:47`), add a `spark://servers` listener guarded by `isTauri()` like the others, that re-runs whatever the window uses to load the list (the same path `spark://state` triggers, e.g. `initSelectedIndex()` which pulls `servers()`, plus any home-screen store refresh):
```svelte
const servers = listen("spark://servers", () => void initSelectedIndex());
```
And in the cleanup:
```svelte
servers.then((f) => f()).catch((e) => console.error("[layout] unlisten spark://servers:", e));
```
If the location list is rendered from a store that isn't refreshed by `initSelectedIndex()`, call that store's reload here too (check the home screen's data source; the tray's `refresh()` already re-reads `servers()` on the Rust side, so no frontend change is needed for the tray).

- [ ] **Step 2: Type-check.**

Run: `cd gui-tauri && npm run check 2>&1 | tail -15`
Expected: no new errors.

- [ ] **Step 3: Commit.**

```bash
git add gui-tauri/src/routes/+layout.svelte
git commit -m "locations phase2a: re-pull the server list on spark://servers"
```

---

## Task 8: Gate + binary-size check + on-device verify + PR

**Files:** none (verification + PR).

- [ ] **Step 1: Rust gate (plugin + core).**

```bash
cd gui-tauri/tauri-plugin-spark-vpn && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
cd ../../core && cargo fmt --check && cargo clippy --features fetch -- -D warnings && cargo test --features fetch
```
Expected: all clean.

- [ ] **Step 2: Frontend gate.**

```bash
cd gui-tauri && npm run check && npm test
```

- [ ] **Step 3: Binary-size delta (spec verification item).**

Build the app bundle before/after linking `spark-core` and record the `Spark.app` size delta; confirm the app's dep tree matches the spike's approach (A: no tun/netstack/quinn under the app; B: they ride along):
```bash
cd gui-tauri/tauri-plugin-spark-vpn && cargo tree -e no-dev | grep -E "tun-rs|netstack|quinn|boring" || echo "clean"
```
Record the numbers in the PR description.

- [ ] **Step 4: On-device (macOS DMG) — controller/user builds + runs.**

Build the DMG (`packaging/macos/build-tauri-dmg.sh`). Verify on a **fresh profile that has never connected**:
- Delete the cache: `rm -rf "$HOME/Library/Group Containers/group.org.getlantern.spark/config"`.
- Launch the app **without connecting** → after the background fetch, the location list appears (this is the Phase 2a win Phase 1 couldn't deliver).
- Quit + relaunch → list appears **instantly** from cache (Phase 1), then refreshes.
- Confirm `config_raw.json` is present under `$HOME/Library/Group Containers/.../config` even though the VPN was never turned on.
- Connect → live latency/health overlay still works.

- [ ] **Step 5: Open the PR.**

Base off the merged Phase 1. PR body: summary, the spike verdict + size numbers, the stale-while-revalidate flow, and the on-device results. End with the `🤖 Generated with Claude Code` line. Since this crosses the app↔core↔cache boundary, include a mermaid `sequenceDiagram` of startup (read cache → render → bg fetch → changed? → emit → re-pull).

---

## Phase 2c — iOS (gated on iOS-support work)

iOS reuses this phase's mechanism verbatim once the iOS plugin + NE app-extension + app group exist (`spark-ios-support`, branch `fisk/ios-support`):
- The iOS app links the same `spark-core` `features=["fetch"]` (BoringSSL cross-compiles for iOS, as the tunnel already proves).
- Same startup-fetch task in `setup`, same `spark://servers` wiring, same `shared_config_cache_dir()` — but resolving the **iOS app-group container** (the sandboxed app resolves it directly; on iOS the app IS sandboxed, so `containerURL(forSecurityApplicationGroupIdentifier:)` returns the shared group container both app and NE app-extension see — no root/uid split like macOS, so the Phase 1 `dataDir` workaround is unnecessary on iOS).
- 50 MiB NE memory cap (per `spark-ios-support`) is not a concern here — the fetch runs in the **app**, not the NE.

Do not implement until iOS-support lands; then add an iOS arm to `shared_config_cache_dir()` and enable the `[target.'cfg(target_os = "ios")'.dependencies]` `spark-core` link.

---

## Self-review notes

- **Spec coverage:** Phase 2a items — fetch-only feature (Task 1–2), always-fetch-on-startup (Task 5), `spark://servers` (Task 5/7), stale-while-revalidate (Phase 1 read + Task 5 revalidate), share-the-cache (Task 4 same dir), keep-cache-on-failure (Task 3 `Err` → no emit), binary-size verification (Task 8 Step 3), concurrent-writer safety (Task 6). iOS (2c) sectioned. Android is Phase 2b (separate plan).
- **Honest uncertainty:** Task 1 is a spike because the data-plane gating feasibility is genuinely unknown until tried; both outcomes leave Tasks 2–8 valid (they only require `load_or_fetch` callable against a dir).
- **No new event bus:** reuses the existing `spark://` emit/listen convention.
