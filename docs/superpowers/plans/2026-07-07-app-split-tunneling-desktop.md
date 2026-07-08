# App-based Split Tunneling — Desktop Implementation Plan (P1/P3/P4)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Exclude specific apps from the VPN on desktop (macOS first, then Windows/Linux) by resolving each flow's owning process in the core and routing matched apps `Direct`.

**Architecture:** The core resolves a flow's **source** endpoint → owning process → executable path (macOS `sysctl(net.inet.tcp.pcblist_n)`, already built in `core/src/process/`), and the router routes any flow whose exe path is on a live **app-bypass** list to `Direct` (absolute, like the existing domain/IP `user_bypass`; **fail-open** — an unresolved process is tunneled, never leaked). Delivery mirrors the existing split-tunnel live-push (`spark_set_app_bypass` FFI → `fd_tunnel::set_app_bypass` → `Router::set_app_bypass`). P3 wires the macOS NE + installed-apps catalog + picker; P4 adds Windows/Linux resolver backends.

**Tech Stack:** Rust (spark-core, `libc` for macOS syscalls — already a workspace dep), Swift NE (`PacketTunnelProvider`), Rust Tauri plugin (`tauri-plugin-spark-vpn`), SvelteKit UI (picker already built).

**Design:** `docs/superpowers/specs/2026-07-07-app-split-tunneling-design.md`
**Predecessor:** `docs/superpowers/plans/2026-07-07-app-split-tunneling.md` (P0.1 resolver committed `794614c`; P0.2 de-risked — sing-box does the same `sysctl` from its macOS NE; our sysext runs as root, more privileged).

**Branch/worktree:** work in `/Users/afisk/go/src/github.com/getlantern/spark-app-split-tunneling`. Base a new branch off `main` **after #53 merges**; if #53 isn't merged yet, stack on `fisk/app-split-tunneling` (`git checkout -b fisk/app-split-tunneling-desktop fisk/app-split-tunneling`) and rebase onto main after #53 lands.

**Semantics:** exclude/bypass (listed apps → Direct). iOS excluded (MDM-only).

---

## File Structure

**P1 (core — TDD, no build dependency):**
- Modify: `core/src/process/mod.rs` — add a `ProcessResolver` trait + a `CachingResolver` (src-keyed LRU/TTL) wrapping `resolve_tcp`.
- Modify: `core/src/proxy/mod.rs` — `FlowRouter::decide` gains a `src: SocketAddr` param.
- Modify: `core/src/proxy/tcp.rs` — pass `src` at the decide call site (line ~85) + the test `StubRouter`.
- Modify: `core/src/rules/router.rs` — `Router` gains a live `app_bypass` set + an optional `ProcessResolver`; `decide` consults it; add `set_app_bypass` + `set_process_resolver`.
- Modify: `core/src/fd_tunnel.rs` — `pub fn set_app_bypass(json) -> bool` (mirrors `set_split_tunnel`); inject the macOS resolver into the `Router` at build.
- Modify: `platforms/apple/src/lib.rs` + `platforms/apple/include/spark.h` — `spark_set_app_bypass` C-ABI.

**P3 (macOS delivery + catalog + picker — build/interactive):**
- Modify: `platforms/apple/Sources/SparkNE/PacketTunnelProvider.swift` — read `providerConfiguration["appBypass"]` at start + a `handleAppMessage "appBypass"` case → `spark_set_app_bypass`.
- Modify: `gui-tauri/tauri-plugin-spark-vpn/src/desktop.rs` — `AppleControl`: real `list_installed_apps` (scan `.app` bundles) + `get`/`set_excluded_apps` (persist + send provider message).
- Create: `gui-tauri/tauri-plugin-spark-vpn/src/apps_darwin.rs` — macOS installed-apps enumeration (à la Lantern `lantern-core/apps/apps_darwin.go`).

**P4 (Windows/Linux — outline only, see end).**

---

## Phase P1 — core: resolve process → app-bypass → Direct (TDD)

Everything here is unit-testable on the host (macOS dev machine) with no notarized build.

### Task P1.1: `ProcessResolver` trait + caching wrapper

**Files:**
- Modify: `core/src/process/mod.rs`

- [ ] **Step 1: Write the failing test** — append to `core/src/process/mod.rs`:

```rust
#[cfg(all(test, target_os = "macos"))]
mod resolver_tests {
    use super::*;
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};
    use std::time::Duration;

    #[test]
    fn caching_resolver_resolves_and_caches_own_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let mut client = TcpStream::connect(addr).expect("connect");
        let (_server, _) = listener.accept().expect("accept");
        client.write_all(b"x").expect("write");
        let src = client.local_addr().expect("local");

        let r = CachingResolver::new(Duration::from_secs(3), 128);
        let first = r.resolve(src).expect("resolve our own socket");
        assert!(first.ends_with(env!("CARGO_PKG_NAME")) || !first.is_empty(), "exe path: {first}");
        // Second call is served from cache (same value); just assert it stays consistent.
        assert_eq!(r.resolve(src).as_deref(), Some(first.as_str()));
    }
}
```

- [ ] **Step 2: Run it to verify it fails** — Run:
`cargo test -p spark-core process::resolver_tests::caching_resolver_resolves_and_caches_own_socket`
Expected: FAIL to compile (`ProcessResolver`/`CachingResolver` undefined).

- [ ] **Step 3: Implement** — in `core/src/process/mod.rs`, after the `ProcessInfo` struct add:

```rust
use std::net::SocketAddr;

/// Resolve the executable path of the process that owns a flow's local (source) endpoint. Desktop
/// app split tunneling uses this to route excluded apps Direct. `None` = couldn't attribute (the
/// caller must fail **open**: tunnel the flow, never leak it).
pub trait ProcessResolver: Send + Sync {
    fn resolve(&self, src: SocketAddr) -> Option<String>;
}

/// A [`ProcessResolver`] that caches results by source endpoint for a short TTL, so a per-flow
/// kernel PCB scan doesn't run on every connection. Bounded size (oldest entries evicted). macOS
/// backend (`resolve_tcp`); other platforms get their own backend in P4.
#[cfg(target_os = "macos")]
pub struct CachingResolver {
    ttl: std::time::Duration,
    cap: usize,
    // src -> (inserted_at, exe_path). std Mutex; never held across .await (per-flow sync call).
    cache: std::sync::Mutex<std::collections::HashMap<SocketAddr, (std::time::Instant, Option<String>)>>,
}

#[cfg(target_os = "macos")]
impl CachingResolver {
    pub fn new(ttl: std::time::Duration, cap: usize) -> Self {
        Self { ttl, cap, cache: std::sync::Mutex::new(std::collections::HashMap::new()) }
    }
}

#[cfg(target_os = "macos")]
impl ProcessResolver for CachingResolver {
    fn resolve(&self, src: SocketAddr) -> Option<String> {
        let now = std::time::Instant::now();
        {
            let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((at, path)) = cache.get(&src) {
                if now.duration_since(*at) < self.ttl {
                    return path.clone();
                }
            }
        }
        // Miss/expired: scan the PCB table (TCP only for v1; UDP flows tunnel).
        let path = resolve_tcp(src.ip(), src.port()).ok().flatten().map(|i| i.exe_path);
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if cache.len() >= self.cap {
            // Cheap bound: drop the oldest entry.
            if let Some(oldest) = cache.iter().min_by_key(|(_, (at, _))| *at).map(|(k, _)| *k) {
                cache.remove(&oldest);
            }
        }
        cache.insert(src, (now, path.clone()));
        path
    }
}
```

- [ ] **Step 4: Run the test to verify it passes** — Run:
`cargo test -p spark-core process::resolver_tests::caching_resolver_resolves_and_caches_own_socket`
Expected: PASS.

- [ ] **Step 5: Gate + commit** — `cargo clippy -p spark-core --all-targets -- -D warnings` clean; `cargo fmt`. Then:
```bash
git add core/src/process/mod.rs
git commit -m "feat(core): ProcessResolver trait + src-keyed CachingResolver (macOS) (P1.1)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task P1.2: thread `src` into `FlowRouter::decide`

**Files:**
- Modify: `core/src/proxy/mod.rs` (trait, ~line 27-30)
- Modify: `core/src/proxy/tcp.rs` (call site ~line 85; test `StubRouter` ~line 320-325)
- Modify: `core/src/rules/router.rs` (the `impl FlowRouter for Router`)

- [ ] **Step 1: Change the trait signature** — in `core/src/proxy/mod.rs`, change:
```rust
    fn decide(&self, ip: IpAddr, domain: Option<&str>) -> Decision;
```
to:
```rust
    /// `src` is the flow's local (source) endpoint — used by app split tunneling to attribute the
    /// flow to a process. Implementations that don't need it may ignore it.
    fn decide(&self, ip: IpAddr, domain: Option<&str>, src: SocketAddr) -> Decision;
```
Add `use std::net::SocketAddr;` to `proxy/mod.rs` if not already imported (check top of file).

- [ ] **Step 2: Update the call site** — in `core/src/proxy/tcp.rs` (~line 85), change:
```rust
            .map(|h| h.router.decide(original_dst.ip(), domain.as_deref()))
```
to:
```rust
            .map(|h| h.router.decide(original_dst.ip(), domain.as_deref(), src))
```
(`src` is already in scope — destructured from `TcpFlow` at line ~64.)

- [ ] **Step 3: Update the trait impl for `Router`** — in `core/src/rules/router.rs`, the `impl crate::proxy::FlowRouter for Router`: change `fn decide(&self, ip: IpAddr, domain: Option<&str>)` to `fn decide(&self, ip: IpAddr, domain: Option<&str>, src: std::net::SocketAddr)` and forward `src` to the inherent decide (updated in P1.3). For now (before P1.3) call `Router::decide(self, ip, domain, src)`.

- [ ] **Step 4: Update the test `StubRouter`** — in `core/src/proxy/tcp.rs` (~line 320), the `impl FlowRouter for StubRouter`'s `decide` signature gains `_src: std::net::SocketAddr` (add `use std::net::SocketAddr` in the test mod if needed). Any other `FlowRouter` impls in tests get the same param.

- [ ] **Step 5: Compile the tests** — Run: `cargo test -p spark-core proxy::tcp --no-run`
Expected: compiles (signature threaded through everywhere). Fix any missed `FlowRouter` impl.

- [ ] **Step 6: Commit** (with P1.3, since the inherent `Router::decide` signature also changes there — do P1.3 before running the full suite).

### Task P1.3: `Router` app-bypass matcher + resolver + decide integration

**Files:**
- Modify: `core/src/rules/router.rs`

- [ ] **Step 1: Write the failing test** — in `core/src/rules/router.rs`'s `#[cfg(test)] mod tests`, add:

```rust
#[test]
fn app_bypass_routes_matched_exe_direct_else_proxy() {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    // A stub resolver: any flow from port 5555 belongs to "/Applications/Excluded.app/x", else None.
    struct StubResolver;
    impl crate::process::ProcessResolver for StubResolver {
        fn resolve(&self, src: SocketAddr) -> Option<String> {
            if src.port() == 5555 { Some("/Applications/Excluded.app/x".into()) } else { None }
        }
    }

    let mut router = Router::new(Matcher::build(vec![])); // empty base → default Proxy
    router.set_process_resolver(Some(Arc::new(StubResolver)));
    router.set_app_bypass(&["/Applications/Excluded.app/x".to_string()]);

    let dst = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
    let excluded_src = SocketAddr::from(([10, 0, 0, 2], 5555));
    let other_src = SocketAddr::from(([10, 0, 0, 2], 6666));
    // Excluded app → Direct (absolute). A different app / unresolved → falls through (Proxy here).
    assert_eq!(router.decide(dst, None, excluded_src), Action::Direct);
    assert_eq!(router.decide(dst, None, other_src), Action::Proxy);

    // Empty app-bypass → never Direct via app path.
    router.set_app_bypass(&[]);
    assert_eq!(router.decide(dst, None, excluded_src), Action::Proxy);
}
```

- [ ] **Step 2: Run it to verify it fails** — Run:
`cargo test -p spark-core rules::router::tests::app_bypass_routes_matched_exe_direct_else_proxy`
Expected: FAIL to compile (`set_process_resolver`/`set_app_bypass` and the new `decide` arity undefined).

- [ ] **Step 3: Implement** — in `core/src/rules/router.rs`:

Add fields to `Router` (after `mode`):
```rust
    /// Live app split-tunnel bypass: executable paths that route Direct (absolute). Swapped via
    /// [`set_app_bypass`]. Empty/None = no app bypass.
    app_bypass: RwLock<Option<std::collections::HashSet<String>>>,
    /// Platform process resolver (macOS in P1; None elsewhere until P4). Consulted only when
    /// `app_bypass` is non-empty, so non-resolver platforms pay nothing.
    resolver: RwLock<Option<std::sync::Arc<dyn crate::process::ProcessResolver>>>,
```
Initialize both `RwLock::new(None)` in `Router::new`.

Add methods (near `set_user_bypass`):
```rust
    /// Replace the live app-bypass set (executable paths). Empty clears it. Poison-tolerant.
    pub fn set_app_bypass(&self, paths: &[String]) {
        let set = if paths.is_empty() {
            None
        } else {
            Some(paths.iter().cloned().collect::<std::collections::HashSet<String>>())
        };
        *self.app_bypass.write().unwrap_or_else(|e| e.into_inner()) = set;
    }

    /// Install (or clear) the platform process resolver. Called once at tunnel build on macOS.
    pub fn set_process_resolver(
        &self,
        r: Option<std::sync::Arc<dyn crate::process::ProcessResolver>>,
    ) {
        *self.resolver.write().unwrap_or_else(|e| e.into_inner()) = r;
    }
```

In the inherent `decide`, change the signature to `pub fn decide(&self, ip: IpAddr, domain: Option<&str>, src: std::net::SocketAddr) -> Action` and, **after** the `user_bypass` block and **before** the `mode`/base block, add:
```rust
        // App split tunneling: if the flow's owning process (resolved from its source endpoint) is
        // on the app-bypass list, route Direct (absolute). Only resolve when the list is non-empty
        // (the resolve is a kernel scan). Unresolved → fall through (fail open: the flow is tunneled,
        // never leaked).
        {
            let bypass = self.app_bypass.read().unwrap_or_else(|e| e.into_inner());
            if let Some(paths) = bypass.as_ref() {
                if !paths.is_empty() {
                    let resolver = self.resolver.read().unwrap_or_else(|e| e.into_inner());
                    if let Some(r) = resolver.as_ref() {
                        if let Some(exe) = r.resolve(src) {
                            if paths.contains(&exe) {
                                return Action::Direct;
                            }
                        }
                    }
                }
            }
        }
```

- [ ] **Step 4: Run the test to verify it passes** — Run:
`cargo test -p spark-core rules::router::tests::app_bypass_routes_matched_exe_direct_else_proxy`
Expected: PASS.

- [ ] **Step 5: Full core gate** — Run: `cargo test -p spark-core` (all pass, incl. the P1.2-updated tcp tests), then `cargo clippy -p spark-core --all-targets -- -D warnings` clean, `cargo fmt`.

- [ ] **Step 6: Commit**
```bash
git add core/src/proxy/mod.rs core/src/proxy/tcp.rs core/src/rules/router.rs
git commit -m "feat(core): app-bypass matcher + process resolver in Router.decide (src) (P1.2/P1.3)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task P1.4: `fd_tunnel::set_app_bypass` handle + inject the macOS resolver

**Files:**
- Modify: `core/src/fd_tunnel.rs`

- [ ] **Step 1: Add the live handle** — in `core/src/fd_tunnel.rs`, next to `pub fn set_split_tunnel` (~line 92), add (same `#[cfg]` split — real body when the smart-routing feature is on, no-op otherwise):

```rust
/// Live-push the app-bypass list (JSON array of executable paths) to the running router. Returns
/// false if no tunnel/router is active. Mirrors [`set_split_tunnel`].
pub fn set_app_bypass(json: &str) -> bool {
    let paths: Vec<String> = match serde_json::from_str(json) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("set_app_bypass: invalid JSON: {e}");
            return false;
        }
    };
    let guard = active_router().lock().unwrap_or_else(|e| e.into_inner());
    match guard.as_ref() {
        Some(r) => {
            r.set_app_bypass(&paths);
            true
        }
        None => false,
    }
}
```
Add the matching `#[cfg(not(...))]` stub `pub fn set_app_bypass(_json: &str) -> bool { false }` alongside the `set_split_tunnel` stub (~line 114).

- [ ] **Step 2: Inject the macOS resolver at build** — in `fd_tunnel.rs` where the `Router` is built and stashed into `active_router()` (near line 578 `router.set_user_bypass(...)`), add, right after the router is constructed:
```rust
        #[cfg(target_os = "macos")]
        router.set_process_resolver(Some(std::sync::Arc::new(
            crate::process::CachingResolver::new(std::time::Duration::from_secs(3), 1024),
        )));
```
(Non-macOS builds skip this; the app-bypass path then never resolves — correct until P4.)

- [ ] **Step 3: Gate** — Run: `cargo build -p spark-core` and `cargo clippy -p spark-core --all-targets -- -D warnings`. Expected: clean. (No new unit test — this is wiring; the behavior is covered by P1.3's Router test and P3's end-to-end.)

- [ ] **Step 4: Commit**
```bash
git add core/src/fd_tunnel.rs
git commit -m "feat(core): fd_tunnel set_app_bypass live handle + macOS resolver injection (P1.4)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task P1.5: `spark_set_app_bypass` C-ABI

**Files:**
- Modify: `platforms/apple/src/lib.rs` (mirror `spark_set_split_tunnel`, ~line 190)
- Modify: `platforms/apple/include/spark.h` (declare it, near `spark_set_split_tunnel`)

- [ ] **Step 1: Add the export** — in `platforms/apple/src/lib.rs`, mirror `spark_set_split_tunnel` exactly (same NUL/`CStr`/`catch_unwind` handling), calling `spark_core::fd_tunnel::set_app_bypass(json)`:
```rust
/// Live-push the app-bypass list (a JSON array of absolute executable paths) to the running tunnel.
/// Returns 0 on success, -1 on a NULL/invalid arg or if no tunnel is active. Safe to call anytime.
#[no_mangle]
pub unsafe extern "C" fn spark_set_app_bypass(json: *const c_char) -> c_int {
    // (mirror spark_set_split_tunnel's body: null-check, CStr::from_ptr, to_str, call, map bool->0/-1)
    todo!("copy the spark_set_split_tunnel body, calling fd_tunnel::set_app_bypass")
}
```
Replace the `todo!` by copying `spark_set_split_tunnel`'s real body (read it at `platforms/apple/src/lib.rs:190`) and swapping the inner call to `set_app_bypass`. Do NOT leave the `todo!`.

- [ ] **Step 2: Declare in the header** — in `platforms/apple/include/spark.h`, add next to `spark_set_split_tunnel`:
```c
/* Live-push the app-bypass list (JSON array of absolute exe paths). 0 = ok, -1 = bad arg / no tunnel. */
int32_t spark_set_app_bypass(const char *json);
```

- [ ] **Step 3: Gate** — Run: `cargo build -p spark-apple` (or the apple crate name — check `platforms/apple/Cargo.toml`) and `cargo clippy -p spark-apple -- -D warnings`. Expected: clean.

- [ ] **Step 4: Commit**
```bash
git add platforms/apple/src/lib.rs platforms/apple/include/spark.h
git commit -m "feat(apple): spark_set_app_bypass C-ABI (P1.5)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task P1.6: whole-workspace gate

- [ ] **Step 1** — Run `cargo build` + `cargo clippy --all-targets -- -D warnings` + `cargo test` from the repo root (per the memory: changing core APIs must build/clippy the WHOLE workspace — cli/service depend on it; the `FlowRouter::decide` signature change ripples). Fix any downstream `FlowRouter` impls (e.g. in `service/` or `cli/`).
- [ ] **Step 2** — Run `cargo ndk -t arm64-v8a clippy -p spark-android -- -D warnings` (the JNI target — the resolver is `#[cfg(target_os="macos")]` so Android just needs to still compile). Expected: clean.
- [ ] **Step 3: Commit** any downstream fixes: `git commit -am "chore(core): thread src through remaining FlowRouter impls (P1.6)"`.

---

## Phase P3 — macOS delivery + catalog + picker (the P0.2 sandbox verification)

P1 is inert until the NE calls `spark_set_app_bypass` with a real list and the picker offers real apps. **P3's first on-device test IS the P0.2 sandbox check** (does the sysext's `sysctl` read work).

### Task P3.1: NE reads + live-applies the app-bypass
**Files:** `platforms/apple/Sources/SparkNE/PacketTunnelProvider.swift`
- [ ] Read `providerConfiguration["appBypass"]` (a JSON array string) in `startTunnel`, and after the worker starts, call `spark_set_app_bypass(<json>)` (mirror how `splitTunnel` is threaded, but app-bypass is a *post-start live push*, not a `spark_tunnel_run` arg).
- [ ] Add a `handleAppMessage` `"appBypass"` case: `{"cmd":"appBypass","list":"<json array>"}` → `spark_set_app_bypass(list)` → reply `{"ok":bool}` (mirror the existing `splitTunnel` case at PacketTunnelProvider.swift ~line 265).
- [ ] Rebuild the xcframework (`platforms/apple/build-xcframework.sh`) so the new `spark_set_app_bypass` symbol is in `SparkCore.xcframework`; `swiftc -typecheck` the NE against the new header (avoid the PR#49→#50 Swift-ABI break class). Commit.

### Task P3.2: macOS installed-apps catalog
**Files:** create `gui-tauri/tauri-plugin-spark-vpn/src/apps_darwin.rs`; modify `desktop.rs`
- [ ] Implement `list_installed_apps()` for `AppleControl`: scan `/Applications`, `/System/Applications`, `~/Applications` for `.app` bundles; read `Contents/Info.plist` (`CFBundleName`/`CFBundleDisplayName`, `CFBundleExecutable` → `Contents/MacOS/<exe>` absolute path); return JSON `[{id: <exe path>, name, icon}]` (icon optional for v1 — a later pass can extract `.icns`). Reference heuristics: Lantern `lantern-core/apps/apps_darwin.go` + `apps_exclude_darwin.go` (skip helpers/system agents). The **`id` is the executable path** (what the resolver returns), not the bundle id.
- [ ] Cache to `<base>/installed_apps_cache.json` with stale-while-revalidate (mirror the Android plugin's approach). Commit.

### Task P3.3: `AppleControl` get/set excluded apps (persist + push)
**Files:** `desktop.rs`, `persist.rs`
- [ ] `set_excluded_apps(json)`: validate a JSON array of exe paths, persist to `<base>/excluded_apps.json` (add `load/save_excluded_apps` to `persist.rs`, mirroring `save_split_tunnel`), then push live via `ne_spike::send_provider_message('{"cmd":"appBypass","list":"<json>"}')` (mirror how `set_split_tunnel` sends its provider message). Replace the P1-era `Err(Platform("not yet supported"))` stub.
- [ ] `get_excluded_apps()`: return the persisted list. On `startTunnel`, the app also sets `providerConfiguration["appBypass"]` = the persisted list so it applies on connect (mirror `splitTunnel`). Commit.

### Task P3.4: notarized build + on-device end-to-end (= P0.2 sandbox verification)
- [ ] Rebuild xcframework → `xcodegen` → notarized archive → staple → reinstall the sysext (per `platforms/apple/README.md`; needs `AC_USERNAME`/`AC_PASSWORD` — do not commit them; don't skip notarization).
- [ ] **Verify (the gate):** connect; open Split Tunneling → Apps → the macOS installed-apps list renders; exclude a browser; in that browser load an IP-echo → **real IP**; a non-excluded app → **VPN IP**. Watch `log stream --predicate 'subsystem == "org.getlantern.spark"'` — a `Direct` decision for the excluded app's flow **confirms the sysext's `sysctl` PCB read works in the sandbox** (P0.2 answered GO). If the resolver returns `None` for every flow (`sysctl` EPERM in the sandbox), STOP and pivot (privileged helper / transparent-proxy provider) — document in the spec.
- [ ] Confirm live apply (toggle an app while connected, no reconnect) and persistence (reconnect → still excluded).

---

## Phase P4 — Windows + Linux (outline; own plan after P3)

Same core seam (`ProcessResolver` + `Router` app-bypass); add per-OS backends + catalogs + `ServiceControl` delivery over `ipc`/`service`.
- **Windows resolver:** `GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL)` (+ UDP) → PID → `QueryFullProcessImageName` → exe path; `#[cfg(windows)]` `CachingResolver` backend. Catalog: Start-Menu `.lnk` / registry uninstall keys → exe path + icon.
- **Linux resolver:** netlink `sock_diag` (or `/proc/net/{tcp,udp}` → inode → `/proc/<pid>/fd` → `/proc/<pid>/exe`); `#[cfg(target_os="linux")]` backend. Catalog: XDG `.desktop` files → `Exec` → binary path.
- **Delivery:** `ServiceControl::{list_installed_apps,get,set_excluded_apps}` real impls over the privileged service IPC; the service injects the resolver into its `Router` and calls `set_app_bypass`.
- Each backend gets a `resolves_our_own_socket` unit test like P0.1/P1.1.

---

## Self-Review (against the spec)

- **Spec "Desktop enforcement in core: flow.src → PID → exe path → app-bypass matcher, absolute Direct, fail-open"** → P1.1 (resolver+cache), P1.2 (src threaded), P1.3 (matcher + fail-open fall-through). ✓
- **"src-keyed cache"** → P1.1 `CachingResolver`. ✓
- **"live delivery mirroring split-tunnel"** → P1.4 `set_app_bypass` + P1.5 `spark_set_app_bypass` + P3.1 NE `handleAppMessage`. ✓
- **"macOS NE sandbox risk (#1)"** → P3.4 is the empirical verification (folded into the first end-to-end per the de-risk decision). ✓
- **"macOS installed-apps catalog à la Lantern"** → P3.2. **"wire the desktop picker"** → picker already built (#53); P3.2/P3.3 make `list/get/set` real so it populates + persists. ✓
- **"Windows/Linux"** → P4 outline. **"iOS out"** → not in scope. ✓
- **Placeholder scan:** the only `todo!` (P1.5 Step 1) is explicitly flagged "replace by copying spark_set_split_tunnel's real body — do NOT leave the todo!"; every other step has concrete code. The apple crate name in P1.5 Step 3 is flagged "check Cargo.toml". ✓
- **Type consistency:** `ProcessResolver::resolve(&self, SocketAddr) -> Option<String>`, `Router::set_app_bypass(&[String])`, `Router::decide(ip, domain, src)`, `FlowRouter::decide(ip, domain, src)`, `fd_tunnel::set_app_bypass(json)`, `spark_set_app_bypass(json)` — consistent across all tasks. The app-bypass identifier is the **executable path** everywhere (resolver output = catalog `id` = stored list). ✓
