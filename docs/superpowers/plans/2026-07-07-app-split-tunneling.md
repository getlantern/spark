# App-based Split Tunneling — Implementation Plan (P0 spike + P2 Android)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let users exclude specific apps from the VPN (excluded app → Direct). This plan covers the two tracks that can start immediately per the design: **P0** (de-risk the macOS `sysctl` PCB approach) and **P2** (Android app-exclusion end-to-end, which needs no spike). Desktop core/catalog phases (P1/P3/P4) get a separate plan once P0 resolves.

**Architecture:** App-ST is **source-attribution**, not destination-matching, so it does not share the core router the way domain/IP-ST does. On **Android** the OS enforces it at the `VpnService` layer (`addDisallowedApplication`) — the core is uninvolved; a list change reuses the existing `restartTunnel` live-rebuild (no reconnect/re-consent). On **desktop** (later) the core resolves `flow.src → PID → exe path` via `sysctl`(mac)/`GetExtendedTcpTable`(win)/`sock_diag`(linux); P0 proves the macOS piece. The excluded-apps list is a new persisted artifact (`excluded_apps.json`) with a shared TS backend seam; the match key is platform-specific (package name on Android, exe path on desktop).

**Tech Stack:** Rust (spark-core), Kotlin (`SparkVpnService`/`SparkVpnPlugin`, Android `PackageManager`), Rust Tauri plugin (`tauri-plugin-spark-vpn`), SvelteKit UI, Swift NE (P0 verification only). Reference prior art: sing-box `common/process/searcher_darwin.go` (fetched 2026-07-07), Lantern `lantern-core/apps/`.

**Design:** `docs/superpowers/specs/2026-07-07-app-split-tunneling-design.md`

**Worktree:** create off `main` before starting — `git worktree add .worktrees/app-split-tunneling -b fisk/app-split-tunneling main` (verify `.worktrees` is gitignored first). All paths below are relative to the repo root.

**Testing reality (read before starting):** this codebase has **no Kotlin or JS unit-test runner** — the UI gate is `npm run check` (svelte-check) + `MockBackend` manual verification (how the existing split-tunnel UI, tasks E1–E5, was built), and the Android platform gate is `npx tauri android build` (compile) + emulator/device functional verification (per `docs` on-device checklists). **True TDD applies to the P0 Rust resolver** (pure logic, host-testable) and any core logic; platform glue is compile+device-gated. Each task states its gate explicitly.

---

## File Structure

**P0 (macOS sysctl spike):**
- Create: `core/src/process/mod.rs` — `ProcessResolver` trait + `ProcessInfo { pid, exe_path }`.
- Create: `core/src/process/darwin.rs` — `sysctl(net.inet.tcp.pcblist_n)` parse → PID → `proc_pidpath` (port of sing-box `searcher_darwin.go`). `#[cfg(target_os = "macos")]`.
- Modify: `core/src/lib.rs` — `mod process;`.
- Create (temporary, removed at end of P0): `platforms/apple/include/spark.h` + core FFI `spark_spike_resolve_local(port) -> *mut c_char` and a Swift call in `PacketTunnelProvider.swift` logging the result — the NE-sandbox verification.

**P2 (Android):**
- Modify: `gui-tauri/tauri-plugin-spark-vpn/android/.../spark/SparkVpnService.kt` — read `excluded_apps.json`, exclusion loop, `ACTION_APPLY_APPS` live rebuild.
- Modify: `gui-tauri/tauri-plugin-spark-vpn/android/.../spark/VpnController.kt` — `applyExcludedApps(ctx)`.
- Modify: `gui-tauri/tauri-plugin-spark-vpn/android/.../spark/vpn/SparkVpnPlugin.kt` — `listInstalledApps`/`getExcludedApps`/`setExcludedApps` commands + persistence.
- Modify: `gui-tauri/tauri-plugin-spark-vpn/src/control.rs` — 3 new `TunnelControl` trait methods.
- Modify: `gui-tauri/tauri-plugin-spark-vpn/src/commands.rs` — 3 new `#[command]`s.
- Modify: `gui-tauri/tauri-plugin-spark-vpn/src/mobile.rs` — `AndroidControl` impls (`run_mobile_plugin`).
- Modify: `gui-tauri/tauri-plugin-spark-vpn/src/desktop.rs` — `AppleControl`/`ServiceControl` stubs (empty list / no-op) for now.
- Modify: `gui-tauri/tauri-plugin-spark-vpn/permissions/default.toml` — allow the 3 new commands.
- Modify: `gui-tauri/tauri-plugin-spark-vpn/build.rs` `COMMANDS` — register the 3 new commands.
- Modify: `gui-tauri/src/lib/spark_backend.ts` — `InstalledApp` type + 3 methods on `SparkBackend` + `MockBackend`.
- Modify: `gui-tauri/src/lib/tauri_backend.ts` — 3 methods over `invoke("plugin:spark-vpn|…")`.
- Create: `gui-tauri/src/routes/split-tunneling/apps/+page.svelte` — the app picker screen.
- Modify: `gui-tauri/src/routes/split-tunneling/+page.svelte` — make the "Apps" row navigate (drop "Coming soon").
- Modify: `gui-tauri/tauri-plugin-spark-vpn/android/.../AndroidManifest.xml` — `QUERY_ALL_PACKAGES` (see P2.2 note).

---

## Phase P0 — macOS `sysctl` PCB spike (gates desktop; does NOT block P2)

Proves (a) a userspace `sysctl(net.inet.tcp.pcblist_n)` parse can map a local endpoint → PID → exe path, and (b) it still works inside the NE **system-extension sandbox** (as root). If (b) fails, the desktop plan must pivot (privileged helper / transparent-proxy provider) — so run this first.

### Task P0.1: Host-side PCB resolver + test against our own socket

**Files:**
- Create: `core/src/process/mod.rs`
- Create: `core/src/process/darwin.rs`
- Modify: `core/src/lib.rs` (add `mod process;` near the other `mod` lines, e.g. after `mod rules;`)

- [ ] **Step 1: Write the failing test** — append to `core/src/process/darwin.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};

    // Open a real loopback TCP connection, take the CLIENT socket's local endpoint, and assert the
    // resolver maps it back to THIS test process (pid + an exe path ending in the test binary).
    #[test]
    fn resolves_our_own_tcp_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let mut client = TcpStream::connect(addr).expect("connect");
        let (mut server, _) = listener.accept().expect("accept");
        // Keep both ends alive + established while we scan the PCB table.
        client.write_all(b"x").expect("write");
        let local = client.local_addr().expect("local");

        let info = resolve_tcp(local.ip(), local.port())
            .expect("sysctl/parse ok")
            .expect("our socket is in the PCB table");
        assert_eq!(info.pid, std::process::id(), "must resolve to this process");
        assert!(
            !info.exe_path.is_empty(),
            "exe path must be non-empty, got {:?}",
            info.exe_path
        );
        drop(server);
    }
}
```

- [ ] **Step 2: Run it to verify it fails** — Run: `bin/testsetup go test` is Go; for Rust run:
`cargo test -p spark-core process::darwin::tests::resolves_our_own_tcp_socket`
Expected: FAIL to **compile** (`resolve_tcp` / `ProcessInfo` not defined).

- [ ] **Step 3: Write `core/src/process/mod.rs`**:

```rust
//! Source-app attribution for split tunneling: map a flow's local (source) endpoint to the owning
//! process. Desktop-only; each OS has its own backend (macOS: sysctl PCB table). Mirrors sing-box's
//! `common/process` (searcher_darwin.go), but in Rust and read from `flow.src` in the data path.

use std::net::IpAddr;

/// The process that owns a local socket endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    /// Absolute executable path (e.g. `/Applications/Firefox.app/Contents/MacOS/firefox`).
    pub exe_path: String,
}

#[cfg(target_os = "macos")]
mod darwin;
#[cfg(target_os = "macos")]
pub use darwin::resolve_tcp;
```

- [ ] **Step 4: Write `core/src/process/darwin.rs`** — port of sing-box `searcher_darwin.go` (verified 2026-07-07). Reads the kernel PCB list via `sysctl`, matches the local `ip:port`, reads `so_last_pid`, resolves the path via `proc_pidpath`:

```rust
//! macOS backend: `sysctl(net.inet.tcp.pcblist_n)` → match local endpoint → `so_last_pid` →
//! `proc_pidpath`. Ported from sing-box common/process/searcher_darwin.go. Offsets are from
//! darwin-xnu bsd/netinet/in_pcblist.c (get_pcblist_n); struct sizes are 8-byte aligned.

use super::ProcessInfo;
use std::net::IpAddr;

// libc gives us sysctlbyname + proc_pidpath.
use libc::{c_void, proc_pidpath};

/// `rup8(sizeof(xinpcb_n)) + rup8(sizeof(xsocket_n)) + 2*rup8(sizeof(xsockbuf_n)) +
/// rup8(sizeof(xsockstat_n))`. 408 on Darwin 22+ (macOS 13+), else 384. (sing-box's `structSize`.)
fn base_item_size() -> usize {
    // kern.osrelease major version.
    let mut buf = [0u8; 32];
    let mut len = buf.len();
    let name = b"kern.osrelease\0";
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr() as *const libc::c_char,
            buf.as_mut_ptr() as *mut c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return 384;
    }
    let s = String::from_utf8_lossy(&buf[..len.saturating_sub(1)]);
    let major: i64 = s.split('.').next().and_then(|m| m.parse().ok()).unwrap_or(0);
    if major >= 22 { 408 } else { 384 }
}

/// Read a native-endian u32 from a byte slice at `off`.
fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// Resolve the process owning the TCP socket whose local endpoint is `(ip, port)`.
/// Returns `Ok(None)` if no PCB matches; `Err` only on a sysctl failure.
pub fn resolve_tcp(ip: IpAddr, port: u16) -> std::io::Result<Option<ProcessInfo>> {
    let is_ipv4 = ip.is_ipv4();
    let name = b"net.inet.tcp.pcblist_n\0";

    // First call with a null buffer to get the size, then read.
    let mut needed: usize = 0;
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr() as *const libc::c_char,
            std::ptr::null_mut(),
            &mut needed,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut buf = vec![0u8; needed];
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr() as *const libc::c_char,
            buf.as_mut_ptr() as *mut c_void,
            &mut needed,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    buf.truncate(needed);

    // TCP: base item + rup8(sizeof(xtcpcb_n)) = +208.
    let item_size = base_item_size() + 208;

    // Layout per item (from sing-box): the xinpcb_n starts at `inp`, the xsocket_n at
    // `so = inp + <base xinpcb_n size>`. sing-box reads local port at inp+18 (be16), local IPv4 at
    // inp+76..80, local IPv6 at inp+64..80, the flag (v4/v6) at inp+44, and so_last_pid at so+68.
    let target_port_be = port.to_be();
    let mut i = 24usize; // skip the first xinpgen(24) header block
    while i + item_size <= buf.len() {
        let inp = i;
        let so = inp + base_item_size(); // xsocket_n follows the xinpcb_n

        // local port (network byte order) at inp+18
        let lport = u16::from_ne_bytes([buf[inp + 18], buf[inp + 19]]);
        if lport != target_port_be {
            i += item_size;
            continue;
        }

        // inp_vflag at inp+44 (0x1 = IPv4, 0x2 = IPv6)
        let flag = buf[inp + 44];
        let src_ip: IpAddr = if flag & 0x1 != 0 && is_ipv4 {
            IpAddr::from([buf[inp + 76], buf[inp + 77], buf[inp + 78], buf[inp + 79]])
        } else if flag & 0x2 != 0 && !is_ipv4 {
            let mut a = [0u8; 16];
            a.copy_from_slice(&buf[inp + 64..inp + 80]);
            IpAddr::from(a)
        } else {
            i += item_size;
            continue;
        };

        if src_ip == ip {
            let pid = read_u32(&buf, so + 68);
            return Ok(exe_path(pid).map(|exe_path| ProcessInfo { pid, exe_path }));
        }
        i += item_size;
    }
    Ok(None)
}

/// `proc_pidpath(pid)` → absolute executable path, or None on failure.
fn exe_path(pid: u32) -> Option<String> {
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let n = unsafe {
        proc_pidpath(pid as i32, buf.as_mut_ptr() as *mut c_void, buf.len() as u32)
    };
    if n <= 0 {
        return None;
    }
    buf.truncate(n as usize);
    String::from_utf8(buf).ok()
}
```

Add `libc` to `core/Cargo.toml` **only if not already present** (check first — `grep '^libc' core/Cargo.toml`). If absent, add under `[target.'cfg(target_os = "macos")'.dependencies]`:
```toml
libc = "0.2"
```
(`libc` is a std-adjacent, already-transitively-present crate; this does not violate the "no new deps without asking" rule — but if you're unsure, confirm before adding.)

- [ ] **Step 5: Run the test to verify it passes** — Run:
`cargo test -p spark-core process::darwin::tests::resolves_our_own_tcp_socket`
Expected: PASS. If the port matches but IP doesn't, the offsets differ on your macOS version — log the matched `flag`/bytes and adjust against `in_pcblist.c` for your `kern.osrelease`.

- [ ] **Step 6: Gate + commit** — Run `cargo clippy -p spark-core --all-targets -- -D warnings` and `cargo fmt`. Then:
```bash
git add core/src/process/ core/src/lib.rs core/Cargo.toml core/Cargo.lock
git commit -m "spike(core): macOS sysctl PCB → PID → exe path resolver (P0.1)"
```

### Task P0.2: Verify the resolver works inside the NE system-extension sandbox

The gating question: does the sandboxed system extension get `net.inet.tcp.pcblist_n` (it runs as root, but the sandbox may deny it)? Verify empirically.

**Files:**
- Modify: `core/src/lib.rs` or a `core/src/ffi_apple.rs` (wherever the `spark_*` C-ABI lives — `grep -rn 'pub extern "C" fn spark_' core/src platforms`) — add a temporary spike export.
- Modify: `platforms/apple/Sources/SparkNE/PacketTunnelProvider.swift` — call it once and log.

- [ ] **Step 1: Add the temporary FFI export** (in the same file as the other `spark_*` exports):

```rust
/// TEMPORARY (P0.2 spike): resolve the process owning loopback TCP local port `port`, returning a
/// heap C string "pid=<n> path=<p>" / "none" / "err=<e>". Freed by the caller via `spark_string_free`.
/// Remove once the sandbox question is answered.
#[cfg(target_os = "macos")]
#[no_mangle]
pub extern "C" fn spark_spike_resolve_local(port: u16) -> *mut std::os::raw::c_char {
    let msg = match crate::process::resolve_tcp("127.0.0.1".parse().unwrap(), port) {
        Ok(Some(info)) => format!("pid={} path={}", info.pid, info.exe_path),
        Ok(None) => "none".to_string(),
        Err(e) => format!("err={e}"),
    };
    std::ffi::CString::new(msg).unwrap().into_raw()
}
```
Declare it in `platforms/apple/include/spark.h` (mirror an existing `char*`-returning export like `spark_servers_json`).

- [ ] **Step 2: Call it from the NE and log** — in `PacketTunnelProvider.swift`, inside `handleAppMessage`'s `"servers"` case (piggyback so it's easy to trigger from the running tunnel), before the existing body add:
```swift
if let cstr = spark_spike_resolve_local(0) { // 0 = "scan only, expect none"; proves sysctl succeeds vs err=
    log.notice("SPIKE resolve_local: \(String(cString: cstr), privacy: .public)")
    spark_string_free(cstr)
}
```

- [ ] **Step 3: Rebuild the xcframework + NE, run, trigger** — rebuild the core for macOS, regenerate `SparkCore.xcframework`, build/notarize/run the app (per `platforms/apple/README.md`), connect, then open the server-selection screen (fires `handleAppMessage "servers"`).

- [ ] **Step 4: Read the verdict** — Run:
`log stream --predicate 'subsystem == "org.getlantern.spark"' --info | grep SPIKE`
Expected: `SPIKE resolve_local: none` or a `pid=…` — **`sysctl` succeeded in the sandbox → desktop path is GO.** If `err=Operation not permitted` (EPERM) → the sandbox blocks it → **STOP and escalate**: the desktop plan pivots to a privileged-helper or transparent-proxy approach (document in the spec's Risks section).

- [ ] **Step 5: Revert the spike wiring, keep the resolver** — remove `spark_spike_resolve_local`, its `.h` entry, and the Swift call (the `core/src/process/` resolver from P0.1 stays — P1 uses it). Commit:
```bash
git commit -am "spike(apple): confirm sysctl PCB readable in NE sandbox; revert probe wiring (P0.2)"
```

---

## Phase P2 — Android app split tunneling (runs first, in parallel with P0)

Ships app-exclusion end-to-end on Android with a live rebuild. No dependency on P0.

### Task P2.1: Shared TS backend seam (`InstalledApp` + 3 methods)

**Files:**
- Modify: `gui-tauri/src/lib/spark_backend.ts`
- Modify: `gui-tauri/src/lib/tauri_backend.ts`

**Gate:** `npm run check` (svelte-check). No JS unit runner — `MockBackend` is the manual-verification harness.

- [ ] **Step 1: Add the type + interface methods** — in `spark_backend.ts`, after the `SplitTunnel` interface (line 39) add:

```ts
/** An installed application the user can exclude from the VPN. `id` is the platform match key
 * (Android package name; desktop executable path). `icon` is an optional data-URL for display. */
export interface InstalledApp {
  id: string;
  name: string;
  icon?: string | null;
}
```
Then inside `SparkBackend` (after `setRoutingMode`, line 52) add:
```ts
  /** Installed apps the user can choose to exclude (platform-enumerated; empty on platforms w/o support). */
  listInstalledApps(): Promise<InstalledApp[]>;
  /** The currently-excluded app match keys (package names / exe paths). */
  getExcludedApps(): Promise<string[]>;
  /** Persist the excluded set; applied live (Android rebuilds the tunnel, no reconnect). */
  setExcludedApps(ids: string[]): Promise<void>;
```

- [ ] **Step 2: Extend `mockState` + `MockBackend`** — in `spark_backend.ts`, add `excludedApps: string[]` to the `mockState` object literal (line 62-68) as `excludedApps: []`, then add these methods to `MockBackend` (after `setRoutingMode`, line 128):

```ts
  async listInstalledApps(): Promise<InstalledApp[]> {
    return [
      { id: "com.android.chrome", name: "Chrome", icon: null },
      { id: "org.mozilla.firefox", name: "Firefox", icon: null },
      { id: "com.spotify.music", name: "Spotify", icon: null },
    ];
  }
  async getExcludedApps(): Promise<string[]> { return [...mockState.excludedApps]; }
  async setExcludedApps(ids: string[]): Promise<void> { mockState.excludedApps = [...ids]; }
```

- [ ] **Step 3: Add the TauriBackend impls** — in `tauri_backend.ts`, mirror the existing `getSplitTunnel`/`setSplitTunnel` invoke pattern. Add:

```ts
  async listInstalledApps(): Promise<InstalledApp[]> {
    // The plugin returns { value: "<json-array-string>" } (same wrapping as servers()).
    const res = await invoke<{ value: string }>("plugin:spark-vpn|list_installed_apps");
    return JSON.parse(res.value) as InstalledApp[];
  }
  async getExcludedApps(): Promise<string[]> {
    const res = await invoke<{ value: string }>("plugin:spark-vpn|get_excluded_apps");
    return JSON.parse(res.value) as string[];
  }
  async setExcludedApps(ids: string[]): Promise<void> {
    await invoke("plugin:spark-vpn|set_excluded_apps", { json: JSON.stringify(ids) });
  }
```
Add `InstalledApp` to the `import type { … }` from `./spark_backend` at the top of `tauri_backend.ts`.

- [ ] **Step 4: Verify** — Run: `cd gui-tauri && npm run check`. Expected: 0 errors.

- [ ] **Step 5: Commit**
```bash
git add gui-tauri/src/lib/spark_backend.ts gui-tauri/src/lib/tauri_backend.ts
git commit -m "feat(ui): backend seam for app split tunneling (list/get/set excluded apps)"
```

### Task P2.2: Android `PackageManager` catalog (`listInstalledApps`)

**Files:**
- Modify: `gui-tauri/tauri-plugin-spark-vpn/android/src/main/java/org/getlantern/spark/vpn/SparkVpnPlugin.kt`
- Modify: `gui-tauri/tauri-plugin-spark-vpn/android/src/main/AndroidManifest.xml`

**Gate:** `npx tauri android build --debug --apk --target aarch64` compiles + emulator functional check.

- [ ] **Step 1: Manifest — declare package visibility** — Android 11+ (API 30) hides other apps unless declared. For a user-facing "pick any app" list, add inside `<manifest>` (top level, sibling of `<application>`):
```xml
<uses-permission android:name="android.permission.QUERY_ALL_PACKAGES"
    tools:ignore="QueryAllPackagesPermission" />
```
(Add `xmlns:tools="http://schemas.android.com/tools"` to the `<manifest>` tag if not present. Note: Play Store requires a declaration justifying `QUERY_ALL_PACKAGES`; acceptable for a VPN app that offers per-app tunneling. If you'd rather avoid it for v1, fall back to a `<queries>` intent filter for `CATEGORY_LAUNCHER` — narrower but misses non-launcher apps.)

- [ ] **Step 2: Add the command** — in `SparkVpnPlugin.kt`, after the `servers` command block (line 200), add:

```kotlin
    // ── installed apps (split-tunnel picker) ───────────────────────────────────────

    /**
     * Enumerate launchable, non-system-critical apps for the exclude picker. Returns
     * `{value: "<jsonArray>"}` where each element is `{id, name, icon}` (id = package name,
     * icon = a `data:image/png;base64,…` URL). Excludes our own package (already tunnel-excluded).
     */
    @Command
    fun listInstalledApps(invoke: Invoke) {
        scope.launch {
            val pm = activity.packageManager
            val out = org.json.JSONArray()
            // Launchable apps only (have a launcher entry) — the useful, user-recognizable set.
            val launch = android.content.Intent(android.content.Intent.ACTION_MAIN)
                .addCategory(android.content.Intent.CATEGORY_LAUNCHER)
            val resolved = pm.queryIntentActivities(launch, 0)
            val seen = HashSet<String>()
            for (ri in resolved) {
                val pkg = ri.activityInfo.packageName
                if (pkg == activity.packageName || !seen.add(pkg)) continue
                val label = ri.loadLabel(pm).toString()
                val icon = runCatching { drawableToPngDataUrl(ri.loadIcon(pm)) }.getOrNull()
                out.put(
                    org.json.JSONObject()
                        .put("id", pkg)
                        .put("name", label)
                        .put("icon", icon ?: org.json.JSONObject.NULL),
                )
            }
            val ret = JSObject()
            ret.put("value", out.toString())
            invoke.resolve(ret)
        }
    }

    /** Rasterize a (possibly adaptive) launcher drawable to a small PNG data-URL for the web UI. */
    private fun drawableToPngDataUrl(d: android.graphics.drawable.Drawable): String {
        val size = 96
        val bmp = android.graphics.Bitmap.createBitmap(size, size, android.graphics.Bitmap.Config.ARGB_8888)
        val canvas = android.graphics.Canvas(bmp)
        d.setBounds(0, 0, size, size)
        d.draw(canvas)
        val baos = java.io.ByteArrayOutputStream()
        bmp.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, baos)
        bmp.recycle()
        val b64 = android.util.Base64.encodeToString(baos.toByteArray(), android.util.Base64.NO_WRAP)
        return "data:image/png;base64,$b64"
    }
```

- [ ] **Step 3: Build** — Run: `cd gui-tauri && npx tauri android build --debug --apk --target aarch64`. Expected: BUILD SUCCESSFUL.

- [ ] **Step 4: Commit**
```bash
git add gui-tauri/tauri-plugin-spark-vpn/android/src/main/java/org/getlantern/spark/vpn/SparkVpnPlugin.kt \
        gui-tauri/tauri-plugin-spark-vpn/android/src/main/AndroidManifest.xml
git commit -m "feat(android): PackageManager installed-apps catalog for split-tunnel picker"
```

### Task P2.3: Android excluded-apps persistence + get/set commands

**Files:** Modify `SparkVpnPlugin.kt`.

**Gate:** compile via `tauri android build`; behavioral check in P2.7.

- [ ] **Step 1: Add persistence helpers** — in `SparkVpnPlugin.kt`, near `splitTunnelFile()` (line 278) add:

```kotlin
    private fun excludedAppsFile(): File = File(activity.filesDir, "excluded_apps.json")

    /** Read the persisted excluded-app package list (a JSON string array); [] if missing/invalid. */
    private fun loadExcludedApps(): String =
        runCatching { excludedAppsFile().readText() }.getOrNull()
            ?.let { canonicalizeExcludedApps(it) } ?: "[]"

    /** Validate + canonicalize to a JSON array of non-blank strings; null on parse error. */
    private fun canonicalizeExcludedApps(raw: String): String? = runCatching {
        val arr = org.json.JSONArray(raw)
        val out = org.json.JSONArray()
        for (i in 0 until arr.length()) {
            val s = arr.optString(i).trim()
            if (s.isNotEmpty()) out.put(s)
        }
        out.toString()
    }.getOrNull()
```

- [ ] **Step 2: Add get/set commands** — after `setSplitTunnel` (line 238) add:

```kotlin
    /** Read `<filesDir>/excluded_apps.json`, resolving `{value: "<jsonArray>"}` (default "[]"). */
    @Command
    fun getExcludedApps(invoke: Invoke) {
        val ret = JSObject()
        ret.put("value", loadExcludedApps())
        invoke.resolve(ret)
    }

    /**
     * Persist the excluded-app package list to `<filesDir>/excluded_apps.json` and, if the tunnel is
     * up, apply it live by rebuilding the VpnService (new `addDisallowedApplication` set) — no
     * reconnect / re-consent. See [SparkVpnService.ACTION_APPLY_APPS].
     */
    @Command
    fun setExcludedApps(invoke: Invoke) {
        val args = invoke.parseArgs(JsonArgs::class.java)
        val canonical = canonicalizeExcludedApps(args.json)
        if (canonical == null) {
            invoke.reject("invalid excluded-apps JSON")
            return
        }
        try {
            excludedAppsFile().writeText(canonical)
        } catch (e: Exception) {
            invoke.reject("failed to persist excluded apps: ${e.message}")
            return
        }
        if (SparkState.state.value == VpnState.CONNECTED) {
            runCatching { VpnController.applyExcludedApps(activity) }
                .onFailure { Log.w(TAG, "applyExcludedApps failed", it) }
        }
        invoke.resolve()
    }
```

- [ ] **Step 3: Build** — `cd gui-tauri && npx tauri android build --debug --apk --target aarch64`. Expected: BUILD SUCCESSFUL (references `VpnController.applyExcludedApps` + `SparkVpnService.ACTION_APPLY_APPS`, added next — do P2.4 before building, or stub them first). **Order note:** implement P2.4 then build both together.

- [ ] **Step 4: Commit** (together with P2.4).

### Task P2.4: VpnService exclusion loop + `ACTION_APPLY_APPS` live rebuild

**Files:**
- Modify: `SparkVpnService.kt`
- Modify: `VpnController.kt`

**Gate:** `tauri android build` compiles; live-rebuild verified in P2.7.

- [ ] **Step 1: Read the excluded list in `startTunnel`** — in `SparkVpnService.kt`, after `loadRoutingMode()` is defined (line 216-219) add a sibling:

```kotlin
    /** Read persisted excluded-app packages (`<filesDir>/excluded_apps.json`); empty on any error. */
    private fun loadExcludedApps(): List<String> =
        runCatching {
            val arr = org.json.JSONArray(File(filesDir, "excluded_apps.json").readText())
            (0 until arr.length()).map { arr.getString(it) }.filter { it.isNotBlank() }
        }.getOrDefault(emptyList())
```

- [ ] **Step 2: Apply exclusions in the `Builder`** — in `startTunnel`, replace the existing self-exclusion block (lines 134-138):

```kotlin
        try {
            builder.addDisallowedApplication(packageName)
        } catch (e: Exception) {
            Log.e(TAG, "addDisallowedApplication failed", e)
        }
```
with:
```kotlin
        // Always exclude ourselves (loop avoidance) + the user's chosen apps (split tunneling).
        // A package that isn't installed throws NameNotFoundException — skip it, don't fail the tunnel.
        for (pkg in listOf(packageName) + loadExcludedApps()) {
            try {
                builder.addDisallowedApplication(pkg)
            } catch (e: Exception) {
                Log.w(TAG, "addDisallowedApplication($pkg) skipped: ${e.message}")
            }
        }
```

- [ ] **Step 3: Handle `ACTION_APPLY_APPS` in `onStartCommand`** — in `onStartCommand` (line 53-64), before the `EXTRA_CONFIG` handling add:

```kotlin
        if (intent?.action == ACTION_APPLY_APPS) {
            // Live-apply a changed exclusion set: rebuild the tunnel off the main thread (restartTunnel
            // blocks on nativeStop+join). Only meaningful while running; no-op otherwise.
            if (worker != null) {
                thread(name = "spark-apply-apps") { applyExcludedAppsLive() }
            }
            return START_STICKY
        }
```
Then add the method (near `restartTunnel`, line 322):
```kotlin
    /** Rebuild the tunnel with the freshly-persisted exclusion set. Reuses restartTunnel's machinery
     *  (nativeStop → new establish() → nativeRun), so the VpnService stays authorized — no re-consent,
     *  no VPN-off flicker; only in-flight connections reset. Runs off the main thread. */
    private fun applyExcludedAppsLive() {
        Log.i(TAG, "applyExcludedAppsLive: rebuilding tunnel with new exclusion set")
        restartTunnel()
    }
```

- [ ] **Step 4: Add the action constant** — in the `companion object` (after `ACTION_STOP`, line 381):
```kotlin
        const val ACTION_APPLY_APPS = "org.getlantern.spark.APPLY_APPS"
```

- [ ] **Step 5: Add `VpnController.applyExcludedApps`** — in `VpnController.kt`, mirroring `stop`:
```kotlin
    /** Ask the running service to rebuild with the latest excluded-apps list (live, no reconnect). */
    fun applyExcludedApps(ctx: Context) {
        ctx.startService(
            Intent(ctx, SparkVpnService::class.java).setAction(SparkVpnService.ACTION_APPLY_APPS),
        )
    }
```

- [ ] **Step 6: Build** — `cd gui-tauri && npx tauri android build --debug --apk --target aarch64`. Expected: BUILD SUCCESSFUL.

- [ ] **Step 7: Commit**
```bash
git add gui-tauri/tauri-plugin-spark-vpn/android/src/main/java/org/getlantern/spark/
git commit -m "feat(android): VpnService app-exclusion + ACTION_APPLY_APPS live rebuild"
```

### Task P2.5: Rust plugin command plumbing (trait + commands + mobile + desktop stubs + registration)

**Files:** `control.rs`, `commands.rs`, `mobile.rs`, `desktop.rs`, `permissions/default.toml`, `build.rs`.

**Gate:** from the plugin dir, `cargo ndk -t arm64-v8a clippy -p tauri-plugin-spark-vpn` (per memory: host clippy misses the cfg'd JNI mod; use cargo-ndk) + `cargo clippy -p tauri-plugin-spark-vpn` for the desktop cfg.

- [ ] **Step 1: Extend the `TunnelControl` trait** — in `control.rs`, add (mirroring `get_split_tunnel`/`set_split_tunnel`):
```rust
    /// Installed apps for the exclude picker, as a JSON array string of `{id,name,icon}`.
    fn list_installed_apps(&self) -> crate::Result<String>;
    /// The persisted excluded-app match keys, as a JSON array string.
    fn get_excluded_apps(&self) -> crate::Result<String>;
    /// Persist + live-apply the excluded-app match keys (JSON array string).
    fn set_excluded_apps(&self, json: String) -> crate::Result<()>;
```

- [ ] **Step 2: Add the `#[command]`s** — in `commands.rs`, mirror the split-tunnel commands. The plugin returns the wrapped `{value}` shape via `models` (check how `get_split_tunnel` returns — reuse its response type, e.g. `StringValue { value: String }`):
```rust
#[command]
pub(crate) async fn list_installed_apps<R: Runtime>(
    app: AppHandle<R>,
) -> Result<StringResponse> {
    app.spark_vpn().list_installed_apps().map(|value| StringResponse { value })
}

#[command]
pub(crate) async fn get_excluded_apps<R: Runtime>(app: AppHandle<R>) -> Result<StringResponse> {
    app.spark_vpn().get_excluded_apps().map(|value| StringResponse { value })
}

#[command]
pub(crate) async fn set_excluded_apps<R: Runtime>(
    app: AppHandle<R>,
    json: String,
) -> Result<()> {
    app.spark_vpn().set_excluded_apps(json)
}
```
Use the **exact** response/wrapper type the existing `get_split_tunnel`/`servers` commands use (grep for their signatures in `commands.rs` and match — the placeholder `StringResponse` above must equal that real type name).

- [ ] **Step 3: Register the commands** — in `build.rs`, add `"list_installed_apps"`, `"get_excluded_apps"`, `"set_excluded_apps"` to the `COMMANDS` array. In `permissions/default.toml`, add them to the allowed command list (mirror `get-split-tunnel`/`set-split-tunnel` entries, matching that file's naming convention — hyphen vs underscore).

- [ ] **Step 4: Implement on `AndroidControl`** — in `mobile.rs`, mirror `get_split_tunnel`/`set_split_tunnel`:
```rust
    fn list_installed_apps(&self) -> crate::Result<String> {
        self.run_mobile::<StringValue>("listInstalledApps", ()).map(|v| v.value)
    }
    fn get_excluded_apps(&self) -> crate::Result<String> {
        self.run_mobile::<StringValue>("getExcludedApps", ()).map(|v| v.value)
    }
    fn set_excluded_apps(&self, json: String) -> crate::Result<()> {
        self.run_mobile::<()>("setExcludedApps", JsonArgs { json }).map(|_| ())
    }
```
Match the actual helper name/signature `AndroidControl` uses for `run_mobile_plugin` and the arg/return structs used by `set_split_tunnel` (grep `mobile.rs`).

- [ ] **Step 5: Stub on desktop** — in `desktop.rs`, for both `AppleControl` and `ServiceControl` (P3 fills macOS in):
```rust
    fn list_installed_apps(&self) -> crate::Result<String> { Ok("[]".to_string()) }
    fn get_excluded_apps(&self) -> crate::Result<String> { Ok("[]".to_string()) }
    fn set_excluded_apps(&self, _json: String) -> crate::Result<()> { Ok(()) }
```

- [ ] **Step 6: Gate** — from `gui-tauri/tauri-plugin-spark-vpn`:
`cargo clippy -p tauri-plugin-spark-vpn -- -D warnings` (desktop cfg) and
`cargo ndk -t arm64-v8a clippy -p tauri-plugin-spark-vpn -- -D warnings` (android cfg). Both clean. `cargo fmt`.

- [ ] **Step 7: Commit**
```bash
git add gui-tauri/tauri-plugin-spark-vpn/src/ gui-tauri/tauri-plugin-spark-vpn/build.rs \
        gui-tauri/tauri-plugin-spark-vpn/permissions/default.toml
git commit -m "feat(plugin): app split-tunnel commands (list/get/set) + desktop stubs"
```

### Task P2.6: Svelte Apps picker screen

**Files:**
- Create: `gui-tauri/src/routes/split-tunneling/apps/+page.svelte`
- Modify: `gui-tauri/src/routes/split-tunneling/+page.svelte`

**Gate:** `npm run check` + `MockBackend` visual verification in `npm run dev`.

- [ ] **Step 1: Make the "Apps" row navigate** — in `split-tunneling/+page.svelte`, change the Apps row (line ~39, currently `<div class="sub">Coming soon</div>`) to a link to `/split-tunneling/apps` and drop "Coming soon", mirroring how the Websites row navigates to `/split-tunneling/websites` (copy that row's markup/handler exactly, swapping the label to "Apps" and the href/goto target to `apps`).

- [ ] **Step 2: Create the picker screen** — `gui-tauri/src/routes/split-tunneling/apps/+page.svelte`. Follow the existing `/split-tunneling/websites/+page.svelte` structure (app bar with back button, `.app`/`.body` layout, the shared design tokens). Core logic:

```svelte
<script lang="ts">
  import { onMount } from "svelte";
  import { isTauri } from "@tauri-apps/api/core";
  import { MockBackend, TauriBackend, type SparkBackend, type InstalledApp } from "$lib/spark_backend";
  import { TauriBackend as _ } from "$lib/tauri_backend"; // ensure correct import path per repo

  const backend: SparkBackend = isTauri() ? new TauriBackend() : new MockBackend();

  let apps = $state<InstalledApp[]>([]);
  let excluded = $state<Set<string>>(new Set());
  let loading = $state(true);
  let query = $state("");

  onMount(async () => {
    const [list, ex] = await Promise.all([backend.listInstalledApps(), backend.getExcludedApps()]);
    apps = list.sort((a, b) => a.name.localeCompare(b.name));
    excluded = new Set(ex);
    loading = false;
  });

  async function toggle(id: string) {
    const next = new Set(excluded);
    if (next.has(id)) next.delete(id); else next.add(id);
    excluded = next;
    await backend.setExcludedApps([...next]); // persists + live-applies (Android rebuilds)
  }

  const filtered = $derived(
    query.trim()
      ? apps.filter((a) => a.name.toLowerCase().includes(query.trim().toLowerCase()))
      : apps,
  );
</script>

<!-- app bar (back → /split-tunneling) + a search input bound to `query` + the list -->
<!-- each row: optional <img src={app.icon}> , app.name, and a checkbox/switch checked={excluded.has(app.id)} onchange={() => toggle(app.id)} -->
```
Match the exact import path for `TauriBackend` used elsewhere (grep `import.*TauriBackend` in the routes — the websites/home screens show the canonical path; remove the duplicate import stub above). Reuse the row/switch styling from `/split-tunneling/websites/+page.svelte` and the small toggle CSS variables (`--switch-off`, etc.) already in `+layout.svelte`.

- [ ] **Step 3: Verify (mock)** — Run: `cd gui-tauri && npm run check` (0 errors), then `npm run dev` and navigate Home → Split Tunneling → Apps: the 3 mock apps list, toggling persists across navigation (shared `mockState`).

- [ ] **Step 4: Commit**
```bash
git add gui-tauri/src/routes/split-tunneling/apps/+page.svelte gui-tauri/src/routes/split-tunneling/+page.svelte
git commit -m "feat(ui): app split-tunnel picker screen (installed apps, search, multi-select)"
```

### Task P2.7: Android end-to-end verification (emulator + device)

**Gate:** functional verification on a real device (the emulator can't easily prove real-app egress; use the Redmi).

- [ ] **Step 1: Build + install** — Run:
```bash
cd gui-tauri && npx tauri android build --debug --apk --target aarch64
adb -s <device> install -r src-tauri/gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk
```
- [ ] **Step 2: Pick an app to exclude** — launch Spark, connect, open Split Tunneling → Apps, exclude a browser (e.g. Chrome). Confirm the list renders with icons + names.
- [ ] **Step 3: Verify live rebuild (no reconnect)** — watch `adb logcat -s SparkVpn` while toggling the app: expect `applyExcludedAppsLive: rebuilding…` then `restartTunnel: tearing down + re-establishing`, and the VPN key in the status bar **stays up** (no consent re-prompt, no disconnect).
- [ ] **Step 4: Verify egress** — in the **excluded** browser, load an IP-echo page → **real (non-VPN) IP**. In a **non-excluded** browser (or the Spark app's own view), confirm the **VPN IP**. This is the core acceptance test.
- [ ] **Step 5: Verify persistence** — force-stop + relaunch Spark, reconnect; the excluded set persists (`excluded_apps.json`) and is applied on connect.
- [ ] **Step 6: Commit any fixes**, then this phase is complete.

---

## Deferred to the next plan (write after P0 resolves)

**P1 (core resolver + macOS backend), P3 (macOS catalog + desktop picker + NE live-push), P4 (Windows + Linux)** are intentionally not detailed here — P1's macOS backend shape depends on the P0.2 sandbox verdict (in-core `sysctl` vs a privileged-helper pivot), and detailing exact code before that is answered would be guesswork. Known task outline for the follow-up plan:
- **P1:** wire the P0.1 `ProcessResolver` into `rules::router` (extend `decide` to consult `flow.src` → exe path → app-bypass matcher, absolute Direct, `None` fails open); add a `src`-keyed LRU cache; `spark_set_app_bypass` FFI; unit tests for the matcher + cache.
- **P3:** macOS installed-apps enumeration (`.app` bundle scan → bundle id + exec path + icon, cf. Lantern `apps_darwin.go`) in the Tauri desktop backend; the desktop Apps picker reuses P2.6's screen; NE `handleAppMessage` `appBypass` case + `providerConfiguration` for live push; `AppleControl` fills in the P2.5 stubs.
- **P4:** Windows (`GetExtendedTcpTable` + registry/Start-Menu catalog) and Linux (`sock_diag`/`/proc` + `.desktop` catalog) resolver backends + `ServiceControl` delivery.

---

## Self-Review (against the spec)

- **Spec "enforcement / Android VpnService"** → P2.4. **"catalog"** → P2.2 (Android). **"config + UI"** → P2.1/P2.3/P2.6. **"Android live rebuild, no reconnect"** → P2.4 (`ACTION_APPLY_APPS` → `restartTunnel`) + P2.7 step 3. **"macOS sysctl + NE-sandbox risk (#1 spike)"** → P0.1/P0.2. **"exclude/bypass semantics"** → excluded set → `addDisallowedApplication` (Direct). **"iOS out"** → not in scope. ✓
- **Placeholder scan:** the two `StringResponse`/`StringValue`/`run_mobile` names in P2.5 are explicitly flagged "match the real type/helper name by grepping the existing split-tunnel command" — not silent placeholders; every other step has concrete code. ✓
- **Type consistency:** `InstalledApp {id,name,icon}` is identical across `spark_backend.ts`, `tauri_backend.ts`, the Kotlin JSON (`id`/`name`/`icon`), and the picker screen. `excluded_apps.json` is a JSON string-array everywhere (Kotlin `canonicalizeExcludedApps`, TS `string[]`). Command names match across `build.rs`/`permissions`/`commands.rs`/`tauri_backend.ts` (`list_installed_apps`/`get_excluded_apps`/`set_excluded_apps`). ✓
