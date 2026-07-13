# Locations Before VPN — Phase 2b (Android) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** On Android, show the location list before the VPN is on and refresh it on every launch — by (1) reading the cached `config_raw.json` from the app files dir when not connected (the Android half of Phase 1, never done on macOS-only PR #82), and (2) triggering a kindling config fetch **in the existing `:vpn` process** over the app↔service IPC **without establishing the tunnel** (a plain HTTPS fetch needs no VPN consent).

**Architecture:** The native lib (`libspark_android`, the `spark-android` crate with `config-fetch`) already lives in the `:vpn` process (`SparkBridge`/`SparkVpnService`). Add a `nativeFetchConfig(dataDir)` JNI that runs `load_or_fetch` without `VpnService.Builder.establish()`. The main-process plugin triggers it on startup via the existing `SparkControlClient` → `SparkVpnService` Messenger channel; the service replies "servers changed", and the plugin emits `spark://servers`. Both processes share the app files dir, so `AndroidControl::servers()` (main process) reads the cache the `:vpn` process wrote.

**Tech Stack:** Rust JNI (`platforms/android/src/lib.rs`, `jni` 0.21), `spark-core` `config-fetch` (already compiled into `spark-android`), Kotlin (`SparkBridge`, `SparkVpnService` `:vpn`, `SparkControlClient` main), Tauri v2 plugin `mobile.rs` (`AndroidControl`).

**Spec:** `docs/superpowers/specs/2026-07-10-locations-before-vpn-design.md` (Phase 2 + "### Android").

**Depends on:** Phase 2a (desktop) for the `spark://servers` frontend listener (Task 7 there) — reuse it, don't re-add.

---

## Plan revisions from the 2026-07-11 investigation (these supersede the tasks below where they conflict)

Two findings from reading the actual code change the approach:

1. **The fetch needs bundled CA roots — add a core entry, don't call `load_or_fetch` directly.** On Android (and iOS) boring TLS can't read the system trust store; `run_fd_dispatch` installs bundled roots via `crate::ca_roots::install_bundled_roots(dir)` (`core/src/fd_tunnel.rs:355`) before fetching (this was task #71). `ca_roots` is a **private** module — there's no public fetch-only entry. So Phase 2b must **add a public `spark_core::fd_tunnel::fetch_config_only(dir: &Path) -> bool`** (or similar) that: installs the bundled roots, builds a small tokio runtime, runs `config::fetch::load_or_fetch`, and returns whether `config_raw.json` changed — **no tun, no `establish()`**. `nativeFetchConfig` is a thin JNI wrapper over it. (Desktop's `config_fetch.rs` calls `load_or_fetch` directly because macOS/Windows/Linux boring uses the system trust store; the `fetch_config_only` entry is the mobile/no-system-trust path, reusable by iOS Phase 2c.)

2. **Do BOTH the cache-read and the fetch in the `:vpn` process — the main process can't resolve the cache dir.** `SparkVpnService.kt:198` caches into `File(filesDir, "config")` = `<filesDir>/config`. The main-process Rust (`AndroidControl`) has **no verified mapping** to that Android `getFilesDir()` (Tauri's `app_data_dir()` may differ), and must not load the native lib. Guessing the path is the exact mistake that broke macOS Phase 1. So:
   - **Read (Android Phase 1):** extend the **existing `servers` IPC handler in `SparkVpnService.kt`** — when there's no live pool (disconnected), call a new `nativeCachedServers("<filesDir>/config")` JNI (core reads `<dir>/config_raw.json` + parses it to the same servers JSON) and return that instead of `"[]"`. `AndroidControl::servers()` (main) is **unchanged** — it already calls the `servers` IPC. No main-process path resolution, no new IPC command for the read.
   - **Fetch (Android Phase 2b):** a new `fetchConfig` IPC command → `:vpn` calls `nativeFetchConfig("<filesDir>/config")` (over `fetch_config_only`) → replies "changed" → main emits `spark://servers`.
   - Net: **all `filesDir` access + native-lib calls stay in `:vpn`**, which knows the path and already loads the lib. The plugin's `cache_parse.rs` (extracted 2026-07-11) is therefore for the **app-side** readers only (macOS `AppleControl`, iOS Phase 2c) — **not** Android, which parses core-side.

**Prep already landed (2026-07-11):** the `config_raw.json` parser is extracted to `gui-tauri/tauri-plugin-spark-vpn/src/cache_parse.rs` (shared by macOS/iOS app-side reads). Task 1 below is therefore partly done; its "widen the parser to Android" framing is superseded by revision #2 (Android parses core-side).

**Verification reality:** every task below is compile-gateable (`cargo ndk clippy`, Kotlin build) but the end-to-end behavior (fetch-without-consent, cache-read-when-disconnected, `filesDir` path correctness) can only be confirmed on a device/emulator. Do the on-device pass before merging.

---

## Context an implementer must read first

- **Process split (from the `:vpn` refactor, tasks #161–168):** the tunnel runs in a separate `:vpn` process. `SparkVpnService.kt` (`:vpn`) owns the JNI (`SparkBridge`). The main process talks to it via a `Messenger` channel; the client is `SparkControlClient.kt` (main) and the plugin bridge is `mobile.rs::AndroidControl`. **Read `SparkControlClient.kt` and `SparkVpnService.kt` before Task 3** to get the exact command constants / message `what` codes and the reply mechanism — this plan references them by role, and the implementer must match the existing enum.
- **Do NOT load the native lib in the main process.** The spec is explicit: trigger the fetch in `:vpn` over IPC. Loading `libspark_android` in main would duplicate it in memory.
- **The cache lives in the app files dir**, shared by both processes (`getFilesDir()` is per-app, not per-process). The `:vpn` process passes it to the core as `dataDir` in `nativeRun` today (`SparkBridge.nativeRun(..., dataDir, ...)`, `platforms/android/src/lib.rs:64`). The core caches `config_raw.json` + `config_meta.json` + `device_id` there (`SparkBridge.kt` nativeRun doc).
- **JNI is synchronous; `load_or_fetch` is async.** The existing `nativeRun` spawns a runtime; the new `nativeFetchConfig` must build a small tokio runtime, block on the fetch, and return. See how `platforms/android/src/lib.rs` sets up the runtime for `nativeRun`.
- **The `servers_from_cache_json` parser** (Phase 1, `desktop.rs`) is `#[cfg(any(target_os = "macos", test))]`. It parses the top-level `servers[]` geo array into `ServerInfo`. Android's `mobile.rs` needs the same parse — either widen the cfg and share it, or duplicate the tiny parser in `mobile.rs`.
- **`nativeServers()` returns "[]" before connect** (`SparkBridge.kt`) — that's why `AndroidControl::servers()` shows nothing pre-connect today. Phase 1-Android replaces that pre-connect empty with a cache read.

## File structure

- `platforms/android/src/lib.rs` — new `Java_..._nativeFetchConfig` JNI.
- `gui-tauri/tauri-plugin-spark-vpn/android/src/main/java/org/getlantern/spark/SparkBridge.kt` — `external fun nativeFetchConfig`.
- `.../org/getlantern/spark/SparkVpnService.kt` — handle a `fetchConfig` IPC command (`:vpn`), run it off the main thread, reply "changed".
- `.../org/getlantern/spark/SparkControlClient.kt` — `fetchConfig()` client call + a servers-changed callback.
- `gui-tauri/tauri-plugin-spark-vpn/src/mobile.rs` — `AndroidControl::servers()` reads the cache pre-connect; trigger `fetchConfig` on startup; emit `spark://servers` on the changed callback.
- `gui-tauri/tauri-plugin-spark-vpn/src/desktop.rs` — widen `servers_from_cache_json` cfg to include Android (or extract to a shared module).

---

## Task 1: Share the cache parser with Android

**Files:**
- Modify: `gui-tauri/tauri-plugin-spark-vpn/src/desktop.rs` (or extract to a new `cache_parse.rs`)

- [ ] **Step 1: Make `servers_from_cache_json` reachable on Android.**

`desktop.rs` is `#[cfg(not(target_os = "android"))]` (per `lib.rs:12`), so Android can't see it. Extract the pure parser into a new platform-neutral module:
```rust
// gui-tauri/tauri-plugin-spark-vpn/src/cache_parse.rs
//! Pure parser: a fetched `config_raw.json` body (Lantern shape) -> the static location list.
//! Shared by desktop (macOS AppleControl) and mobile (AndroidControl). No I/O, no platform deps.
use crate::models::ServerInfo;

/// Parse `config_raw.json`'s top-level `servers[]` geo entries into `ServerInfo`, indexed by
/// position. No live fields invented (healthy=false, latency=None, is_current=false).
pub(crate) fn servers_from_cache_json(raw: &str) -> Vec<ServerInfo> {
    // (move the existing body from desktop.rs verbatim)
}

#[cfg(test)]
mod tests { /* move the existing 3 tests verbatim */ }
```
Add `mod cache_parse;` to `lib.rs` (unconditional — it's platform-neutral). Replace `desktop.rs`'s copy with `use crate::cache_parse::servers_from_cache_json;`.

- [ ] **Step 2: Run the moved tests.**

Run: `cd gui-tauri/tauri-plugin-spark-vpn && cargo test cache_parse 2>&1 | tail -10`
Expected: the 3 parser tests PASS from their new home.

- [ ] **Step 3: Host build still green (desktop path unchanged).**

Run: `cargo build && cargo test 2>&1 | tail -10`
Expected: green (desktop still compiles against the shared parser).

- [ ] **Step 4: Commit.**

```bash
git add gui-tauri/tauri-plugin-spark-vpn/src/cache_parse.rs gui-tauri/tauri-plugin-spark-vpn/src/desktop.rs gui-tauri/tauri-plugin-spark-vpn/src/lib.rs
git commit -m "locations phase2b: extract the cache parser to a shared, platform-neutral module"
```

---

## Task 2: `AndroidControl::servers()` reads the cache before connect (Phase 1-Android)

**Files:**
- Modify: `gui-tauri/tauri-plugin-spark-vpn/src/mobile.rs`

- [ ] **Step 1: Resolve the app files dir in the main process.**

`AndroidControl` needs the app files dir path to read the cache. Read `mobile.rs` first to see how it already obtains paths (it may hold the Tauri `AppHandle` — use `app.path().app_data_dir()` / `app_local_data_dir()`, whichever maps to `getFilesDir()`; verify against what `SparkVpnService` passes as `dataDir` to `nativeRun`). Add a helper:
```rust
/// The app files dir where the :vpn core caches config_raw.json — the same dir passed to nativeRun.
/// Both processes share getFilesDir(), so the main process can read what :vpn wrote.
fn shared_config_cache_dir(app: &AppHandle<R>) -> Option<std::path::PathBuf> {
    // Resolve to the same path SparkVpnService passes as dataDir. Confirm the subdir ("config"?)
    // by reading how nativeRun's dataDir is built in SparkVpnService.kt.
    app.path().app_data_dir().ok().map(|d| d.join("config"))
}
```

- [ ] **Step 2: In `servers()`, fall back to the cache when the live pool is empty.**

Mirror the macOS `AppleControl::servers()` shape: when `nativeServers()` returns "[]" (not connected), read `config_raw.json` from the files dir and parse it:
```rust
// after getting the live list from nativeServers() and finding it empty:
if list.is_empty() {
    if let Some(dir) = shared_config_cache_dir(&self.app) {
        if let Ok(raw) = std::fs::read_to_string(dir.join("config_raw.json")) {
            list = crate::cache_parse::servers_from_cache_json(&raw);
        }
    }
}
```

- [ ] **Step 3: Build for Android.**

Per the "spark android target verify" convention, JNI/mobile code must be built for the Android target (host clippy misses the cfg'd mobile module):
Run: `cd gui-tauri/tauri-plugin-spark-vpn && cargo ndk -t arm64-v8a clippy -p tauri-plugin-spark-vpn 2>&1 | tail -20` (adjust package/target as the repo does elsewhere).
Expected: compiles for `aarch64-linux-android`.

- [ ] **Step 4: Commit.**

```bash
git add gui-tauri/tauri-plugin-spark-vpn/src/mobile.rs
git commit -m "locations phase2b: AndroidControl::servers() reads the cached config before connect"
```

---

## Task 3: `nativeFetchConfig` JNI — fetch without establishing the tunnel

**Files:**
- Modify: `platforms/android/src/lib.rs`
- Modify: `gui-tauri/tauri-plugin-spark-vpn/android/src/main/java/org/getlantern/spark/SparkBridge.kt`

- [ ] **Step 1: Declare the Kotlin external fn.**

In `SparkBridge.kt`, add:
```kotlin
/**
 * Run one Lantern config fetch (kindling) into [dataDir] WITHOUT establishing the tunnel — a plain
 * HTTPS fetch, no VPN consent needed. Caches config_raw.json + config_meta.json there (the same
 * cache nativeRun uses). Returns true if the cached config changed (caller signals the UI to
 * re-pull), false on 304/unchanged, false on failure (caller keeps the cached list). Blocking; call
 * off the main thread. Safe to call any time, connected or not.
 */
external fun nativeFetchConfig(dataDir: String): Boolean
```

- [ ] **Step 2: Implement the JNI in Rust.**

In `platforms/android/src/lib.rs`, add (mirroring the `nativeRun` runtime/`read_jstring` patterns already in the file — read them first for the exact helpers):
```rust
/// `SparkBridge.nativeFetchConfig(dataDir)` — one kindling config fetch into `dataDir`, no tunnel.
/// Returns JNI_TRUE if the cached config_raw.json changed, else JNI_FALSE (incl. on error).
#[no_mangle]
pub extern "system" fn Java_org_getlantern_spark_SparkBridge_nativeFetchConfig<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    data_dir: JString<'local>,
) -> jboolean {
    let Some(dir) = read_jstring(&mut env, &data_dir) else {
        return JNI_FALSE;
    };
    let dir = std::path::PathBuf::from(dir);
    let before = std::fs::read(dir.join("config_raw.json")).ok();
    // Small current-thread runtime; the fetch is one HTTPS round-trip. (Match how nativeRun builds
    // its runtime — reuse the same tokio setup helper if one exists.)
    let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(_) => return JNI_FALSE,
    };
    let env_cfg = spark_core::config::fetch::FetchEnv::from_env();
    let ok = rt.block_on(async {
        spark_core::config::fetch::load_or_fetch(&dir, &env_cfg).await.is_ok()
    });
    if !ok {
        return JNI_FALSE;
    }
    let after = std::fs::read(dir.join("config_raw.json")).ok();
    if before != after { JNI_TRUE } else { JNI_FALSE }
}
```
(Confirm `JNI_TRUE`/`JNI_FALSE`/`jboolean` imports and that `spark-android`'s Cargo enables `config-fetch` — it must, since self-fetch already works; verify in `platforms/android/Cargo.toml`.)

- [ ] **Step 3: Build for the Android target.**

Run: `cd platforms/android && cargo ndk -t arm64-v8a build 2>&1 | tail -20` (or the repo's build-android.sh).
Expected: `Java_..._nativeFetchConfig` symbol present. Verify: `nm -D <the .so> | grep nativeFetchConfig`.

- [ ] **Step 4: Commit.**

```bash
git add platforms/android/src/lib.rs gui-tauri/tauri-plugin-spark-vpn/android/src/main/java/org/getlantern/spark/SparkBridge.kt
git commit -m "locations phase2b: nativeFetchConfig JNI — kindling fetch without establishing the tunnel"
```

---

## Task 4: `fetchConfig` IPC command (main → :vpn) + servers-changed reply

**Files:**
- Modify: `.../org/getlantern/spark/SparkVpnService.kt` (`:vpn` handler)
- Modify: `.../org/getlantern/spark/SparkControlClient.kt` (main-process client)

- [ ] **Step 1: Read the existing Messenger protocol.**

Open `SparkControlClient.kt` + `SparkVpnService.kt` and note: the message `what` constants (connect/disconnect/status/servers), how a request correlates to a reply, and how the service pushes async updates back to the client (the `SparkState.onChange`/`spark://state` path from #163). Add the new command to the **same** enum/const set — do not invent a parallel channel.

- [ ] **Step 2: Add `fetchConfig` handling in `:vpn` (`SparkVpnService.kt`).**

Handle the new `what` by running the fetch off the main thread (it's blocking) and replying with a boolean "changed":
```kotlin
// in the Messenger handler switch, new case MSG_FETCH_CONFIG:
Thread {
    val dataDir = File(filesDir, "config").absolutePath   // same dir passed to nativeRun
    File(dataDir).mkdirs()
    val changed = SparkBridge.nativeFetchConfig(dataDir)
    // reply to the requesting Messenger with MSG_FETCH_CONFIG result = changed
    replyChanged(msg.replyTo, changed)
}.start()
```
Match `dataDir` to exactly what `nativeRun` is given elsewhere in this file (so both use one cache).

- [ ] **Step 3: Add `fetchConfig()` to `SparkControlClient.kt` (main).**

A client call that sends `MSG_FETCH_CONFIG` and routes the boolean reply to a callback the plugin registers (reuse the correlation registry from #162, or the onChange push from #163 if fetch results ride the same async-update channel):
```kotlin
fun fetchConfig(onResult: (changed: Boolean) -> Unit) { /* send MSG_FETCH_CONFIG, deliver reply */ }
```

- [ ] **Step 4: Android unit test for the new state mapping (if the reply reuses SparkState).**

If the changed-signal rides the existing state channel, extend `SparkStateTest.kt` to cover the new message; otherwise a Kotlin unit test for the client's request/reply correlation. Run the Android unit tests (`./gradlew :...:testDebugUnitTest` for the plugin module).

- [ ] **Step 5: Commit.**

```bash
git add gui-tauri/tauri-plugin-spark-vpn/android/src/main/java/org/getlantern/spark/SparkVpnService.kt gui-tauri/tauri-plugin-spark-vpn/android/src/main/java/org/getlantern/spark/SparkControlClient.kt gui-tauri/tauri-plugin-spark-vpn/android/src/test/java/org/getlantern/spark/SparkStateTest.kt
git commit -m "locations phase2b: fetchConfig IPC command (main -> :vpn) + servers-changed reply"
```

---

## Task 5: Trigger the fetch on startup + emit `spark://servers`

**Files:**
- Modify: `gui-tauri/tauri-plugin-spark-vpn/src/mobile.rs`
- Modify: `gui-tauri/tauri-plugin-spark-vpn/src/lib.rs` (Android arm of `setup`)

- [ ] **Step 1: Add an `AndroidControl` method to trigger the fetch.**

Wrap the plugin's `run_mobile_plugin`/Messenger call to invoke `SparkControlClient.fetchConfig`, wiring the boolean result back so the plugin can emit `spark://servers`. Read how `mobile.rs` invokes other Android plugin commands (e.g. `servers`, `select_server`) and follow that exact pattern.

- [ ] **Step 2: Call it on startup in `setup` (Android arm).**

In `lib.rs`'s `.setup(...)`, in the `#[cfg(target_os = "android")]` block (after the control is managed), trigger the fetch and emit on "changed":
```rust
#[cfg(target_os = "android")]
{
    let handle = app.handle().clone();
    // Fire-and-forget: ask the :vpn process to fetch; emit spark://servers if it changed.
    crate::mobile::trigger_startup_fetch(handle);
}
```
`trigger_startup_fetch` calls `fetchConfig` and, on `changed == true`, `handle.emit("spark://servers", ())` (the same event desktop uses; the frontend listener from Phase 2a Task 7 already handles it).

- [ ] **Step 3: Build for Android.**

Run: `cargo ndk -t arm64-v8a clippy -p tauri-plugin-spark-vpn 2>&1 | tail -20`
Expected: compiles.

- [ ] **Step 4: Commit.**

```bash
git add gui-tauri/tauri-plugin-spark-vpn/src/mobile.rs gui-tauri/tauri-plugin-spark-vpn/src/lib.rs
git commit -m "locations phase2b: trigger the startup fetch in :vpn on launch + emit spark://servers"
```

---

## Task 6: Gate + on-emulator verify + PR

- [ ] **Step 1: Rust gates (host + Android target).**

```bash
cd gui-tauri/tauri-plugin-spark-vpn && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
cargo ndk -t arm64-v8a clippy -p tauri-plugin-spark-vpn -- -D warnings
cd ../../platforms/android && cargo ndk -t arm64-v8a clippy -- -D warnings
```

- [ ] **Step 2: Kotlin build + unit tests.**

Build the plugin's Android module and run its unit tests (Gradle). Confirm no `:vpn`/main wiring regressions.

- [ ] **Step 3: On-emulator (per the emulator-headless-only convention — `-no-window` swiftshader, drive via adb).**

- Fresh install, **never connect**: launch → after the startup fetch (in `:vpn`, no VPN-consent dialog because no `establish()`), the location list appears.
- Confirm no VPN-consent prompt fired for the fetch (it's a plain HTTPS fetch).
- Kill + relaunch → list appears instantly from the cache, then refreshes.
- `adb shell run-as org.getlantern.spark ls files/config/` → `config_raw.json` present though the VPN was never on.
- Connect → live pool overlays; disconnect → cache list remains.
- Confirm the fetch ran in `:vpn` (not main): `adb shell ps | grep spark` shows the `:vpn` process; the main process did not load `libspark_android` (memory check per #168's meminfo method).

- [ ] **Step 4: Open the PR.**

Base off Phase 2a. Body: the no-establish fetch design, the IPC command, the on-emulator results, and a mermaid `sequenceDiagram` (main `setup` → SparkControlClient → `:vpn` SparkVpnService → nativeFetchConfig → cache write → changed reply → `spark://servers` → UI re-pull). End with the `🤖 Generated with Claude Code` line.

---

## Self-review notes

- **Spec coverage (Android section):** in-process fetch in `:vpn` without establish (Tasks 3–5), no native lib in main (Task 3 note + Task 6 memory check), cache in app files dir shared across processes (Task 2), `servers()` reads it pre-connect (Task 2), servers-changed signal back over IPC → `spark://servers` (Tasks 4–5), reuse the desktop frontend listener (no re-add).
- **Verify-before-code spots (called out, not placeholders):** the Messenger `what` constants + reply mechanism (Task 4 Step 1 — read the two Kotlin files), the exact files-dir path `nativeRun` uses (Task 2 Step 1 / Task 4 Step 2), and whether `spark-android`'s Cargo enables `config-fetch` (Task 3 Step 2). These are reads, not guesses — the implementer confirms against the existing code before writing.
- **Depends on Phase 2a** only for the frontend `spark://servers` listener; the Android backend is otherwise independent.
