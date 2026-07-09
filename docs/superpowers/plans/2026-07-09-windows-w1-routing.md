# Windows W1 — Core Routing/Kill-Switch Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the `#[cfg(target_os="windows")]` `RouteManager` path in `core/src/routing.rs` — split-default covers + route-blackhole kill-switch + adapter DNS — so a Windows tunnel can capture/restore traffic, matching the macOS/Linux structure.

**Architecture:** Keep the existing split: pure `RouteOp`-building functions (per-platform, produce argv) + a thin `run_one` executor. Windows routes translate the `0.0.0.0/1`+`128.0.0.0/1` covers to `route.exe` dest+mask via the tun's interface index, and set adapter DNS via `netsh`. CIDR→dest+mask translation is a non-cfg pure helper (host-testable); `route.exe`/`netsh` argv builders + the executor + ifindex resolution are `cfg(windows)`.

**Tech Stack:** Rust, `tokio::process::Command`, `tun-rs`; Windows `route.exe`/`netsh`; interface index via the `windows-sys` Win32 API (`ConvertInterfaceAliasToLuid`+`ConvertInterfaceLuidToIndex`) or a tun-rs index accessor if available.

**Spec:** `docs/superpowers/specs/2026-07-09-windows-support-design.md` · **Progress:** `docs/superpowers/windows-progress.md`

**Branch:** `fisk/windows-w1-routing` (off `main`; carries the spec + goal prompt + progress log).

**Validation constraint (host = macOS):** the `cfg(windows)` argv builders, `netsh`/`route.exe` executor, and ifindex resolver **cross-compile + lint** here (`cargo clippy --target x86_64-pc-windows-msvc`) and their `cfg(windows)` unit tests run in the `windows-latest` CI job added in **W4** — they do NOT run on the macOS host. Host-runnable coverage = the non-cfg pure helpers + the existing cross-platform structural tests. The exact `route add … IF <idx>` form and the ifindex API are **best-effort per Microsoft docs and flagged for on-Windows validation** in the PR — never reported as verified.

---

## File Structure
- Modify only `core/src/routing.rs` (the whole W1 lives here; no other core file changes — `tun` already supports Windows via `DeviceBuilder`, and loop-prevention/`SocketProtector` is W2).

---

## Task 1: CIDR→dest+mask helper (pure, host-testable, TDD)

**Files:** Modify `core/src/routing.rs`

- [ ] **Step 1: Write the failing test** — add to the `tests` module in `core/src/routing.rs`:
```rust
    #[test]
    fn half_to_dest_mask_translates_the_two_covers() {
        assert_eq!(half_to_dest_mask("0.0.0.0/1"), ("0.0.0.0", "128.0.0.0"));
        assert_eq!(half_to_dest_mask("128.0.0.0/1"), ("128.0.0.0", "128.0.0.0"));
    }
```

- [ ] **Step 2: Run to verify it fails** — `cargo test -p spark-core --features smart-routing routing::tests::half_to_dest_mask` → FAIL (function missing). (`--features smart-routing` isn't required for the routing module, but keeps one command across tasks; plain `cargo test -p spark-core routing::` also works.)

- [ ] **Step 3: Implement** — add near the other pure helpers (above the `tests` module), NOT cfg-gated so it compiles + tests on every host:
```rust
/// Translate one of the split-default `HALVES` (`"0.0.0.0/1"` / `"128.0.0.0/1"`) to the
/// `(dest, mask)` pair Windows `route.exe` wants. Only ever called with the two `HALVES`
/// constants, so the `/1` mask is fixed at `128.0.0.0`; returns static strs.
fn half_to_dest_mask(half: &str) -> (&'static str, &'static str) {
    match half {
        "0.0.0.0/1" => ("0.0.0.0", "128.0.0.0"),
        "128.0.0.0/1" => ("128.0.0.0", "128.0.0.0"),
        other => unreachable!("half_to_dest_mask called with non-HALVES value: {other}"),
    }
}
```

- [ ] **Step 4: Run to verify it passes** — `cargo test -p spark-core routing::tests::half_to_dest_mask` → PASS.

- [ ] **Step 5: Commit**
```bash
cd /Users/afisk/go/src/github.com/getlantern/spark-app-split-tunneling
git add core/src/routing.rs
git commit -m "feat(core/routing): CIDR-half -> dest+mask helper for Windows route.exe

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: Per-op program on `RouteOp` (route.exe + netsh), no macOS/Linux change

**Files:** Modify `core/src/routing.rs`

Windows needs two programs (`route.exe` for routes, `netsh` for DNS); the current `RouteOp` runs everything through one const `ROUTE_PROGRAM`. Give each op its own program (defaulting to the platform `ROUTE_PROGRAM`) so macOS/Linux are byte-identical and Windows can mix.

- [ ] **Step 1: Write the failing test** — add to `tests`:
```rust
    #[test]
    fn ops_default_to_the_platform_route_program() {
        // The generic constructors carry the platform's default route program.
        assert_eq!(RouteOp::required(vec!["x"]).program, ROUTE_PROGRAM);
        assert_eq!(RouteOp::ignorable(vec!["x"]).program, ROUTE_PROGRAM);
        // An explicit-program op carries what it was given.
        assert_eq!(RouteOp::required_with("netsh", vec!["x"]).program, "netsh");
    }
```
Note: this test references `ROUTE_PROGRAM`, which is cfg'd per platform — the test is host-agnostic (asserts equality, not the value), so it runs on macOS/Linux/Windows alike. It only compiles where `ROUTE_PROGRAM` is defined (macOS/Linux today; Windows after Task 3). That's fine — the host is macOS.

- [ ] **Step 2: Run to verify it fails** — `cargo test -p spark-core routing::tests::ops_default_to_the_platform_route_program` → FAIL (no `program` field / no `required_with`).

- [ ] **Step 3: Implement** — replace the `RouteOp` struct + its impl:
```rust
/// A single route-table (or DNS) mutation: the program to run, its args, and whether a non-zero
/// exit is tolerable (true for the pre-clear deletes, which legitimately fail when absent).
#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteOp {
    program: &'static str,
    args: Vec<String>,
    ignore_failure: bool,
}

impl RouteOp {
    fn required(args: Vec<&str>) -> Self {
        Self::required_with(ROUTE_PROGRAM, args)
    }
    fn ignorable(args: Vec<&str>) -> Self {
        Self::ignorable_with(ROUTE_PROGRAM, args)
    }
    fn required_with(program: &'static str, args: Vec<&str>) -> Self {
        Self { program, args: args.into_iter().map(String::from).collect(), ignore_failure: false }
    }
    fn ignorable_with(program: &'static str, args: Vec<&str>) -> Self {
        Self { program, args: args.into_iter().map(String::from).collect(), ignore_failure: true }
    }
}
```
Then update the two real `run_one`s (macOS/Linux path and — added in Task 3 — Windows) to launch `op.program` instead of the const:
```rust
    let output = tokio::process::Command::new(op.program)
        .args(&op.args)
        .stdin(std::process::Stdio::null())
        .output()
        .await?;
```
and the error message: `format!("`{} {}` failed ({}): {}", op.program, op.args.join(" "), output.status, stderr.trim())`.

- [ ] **Step 4: Run to verify it passes** — `cargo test -p spark-core routing::` → all routing tests PASS (existing macOS structural + new). Existing `macos_uses_route_with_interface`/`linux_uses_ip_route` still pass (they assert `argv`, unaffected).

- [ ] **Step 5: Gate + commit**
```bash
cd /Users/afisk/go/src/github.com/getlantern/spark-app-split-tunneling
cargo fmt --all --check && cargo clippy -p spark-core --all-targets -- -D warnings
git add core/src/routing.rs
git commit -m "refactor(core/routing): per-op program so Windows can mix route.exe + netsh

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: Windows route + DNS builders and executor (`cfg(windows)`)

**Files:** Modify `core/src/routing.rs`

Add the real Windows path and **narrow the existing `cfg(not(any(macos, linux)))` fallbacks to also exclude `windows`** so Windows uses the real builders. The Windows cover routes go via the tun's **interface index** (`route add DEST mask MASK 0.0.0.0 IF <idx> metric 1` — `0.0.0.0` gateway + `IF` = on-link via that interface). DNS is set with `netsh`.

Because Windows routing needs the tun **index** (not just the name), `install`/`block`/`restore` resolve it (Task 4) and pass it to the builders. To keep the pure cross-platform structural tests (`install_ops(tun)`) compiling on every host, the Windows builders keep the `(half, tun)` shape but treat `tun` as the **already-resolved interface index string** (RouteManager formats the index into the `tun` field on Windows — see Task 4); this keeps `install_ops`/`restore_ops`/`block_ops` signatures unchanged across platforms.

- [ ] **Step 1: Write the failing test** — add a `cfg(windows)` test (runs in W4's windows-latest CI, cross-compiles here):
```rust
    #[cfg(target_os = "windows")]
    #[test]
    fn windows_uses_route_exe_dest_mask_via_ifindex() {
        assert_eq!(ROUTE_PROGRAM, "route");
        // `tun` carries the resolved interface index on Windows.
        assert_eq!(
            argv(&via_tun_op("0.0.0.0/1", "12")),
            "add 0.0.0.0 mask 128.0.0.0 0.0.0.0 metric 1 IF 12"
        );
        assert_eq!(
            argv(&blackhole_op("0.0.0.0/1")),
            "add 0.0.0.0 mask 128.0.0.0 0.0.0.0 metric 1 IF 1" // loopback ifindex 1 = discard
        );
        assert_eq!(argv(&clear_op("128.0.0.0/1")), "delete 128.0.0.0");
    }
```

- [ ] **Step 2: Verify it fails to compile for Windows** — `cargo clippy -p spark-core --target x86_64-pc-windows-msvc --all-targets` → FAIL (Windows `ROUTE_PROGRAM`/builders missing; fallback builders still active).

- [ ] **Step 3: Implement** — add the Windows constants + builders, and narrow the fallback cfgs. Add:
```rust
#[cfg(target_os = "windows")]
const ROUTE_PROGRAM: &str = "route";

/// Delete the cover for `half` (ignorable). Windows `route delete <dest>` removes by destination.
#[cfg(target_os = "windows")]
fn clear_op(half: &str) -> RouteOp {
    let (dest, _mask) = half_to_dest_mask(half);
    RouteOp::ignorable(vec!["delete", dest])
}

/// Add the cover for `half` via the tun interface. `tun` is the resolved interface **index**
/// (see `RouteManager` on Windows). `0.0.0.0` gateway + `IF <idx>` routes on-link via that iface;
/// `metric 1` beats the physical default. VALIDATION-DEFERRED: exact IF/gateway form per MS docs.
#[cfg(target_os = "windows")]
fn via_tun_op(half: &str, tun: &str) -> RouteOp {
    let (dest, mask) = half_to_dest_mask(half);
    RouteOp::required(vec!["add", dest, "mask", mask, "0.0.0.0", "metric", "1", "IF", tun])
}

/// Blackhole the cover (fail-closed) independent of the tun: route via loopback (ifindex 1),
/// which discards. Survives tun teardown.
#[cfg(target_os = "windows")]
fn blackhole_op(half: &str) -> RouteOp {
    let (dest, mask) = half_to_dest_mask(half);
    RouteOp::required(vec!["add", dest, "mask", mask, "0.0.0.0", "metric", "1", "IF", "1"])
}
```
Change the three fallback builders and the no-op `run_one` from `cfg(not(any(target_os = "macos", target_os = "linux")))` to `cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))`. Add a Windows `run_one` identical to the macOS/Linux one (it uses `op.program` from Task 2), gated `#[cfg(target_os = "windows")]` (or widen the real `run_one` cfg to include windows — prefer widening: change `#[cfg(any(target_os="macos", target_os="linux"))]` on the real `run_one` to add `target_os="windows"`, and narrow the no-op to also exclude windows).

- [ ] **Step 4: Verify Windows compiles + host still green** —
```bash
cargo clippy -p spark-core --target x86_64-pc-windows-msvc --all-targets -- -D warnings   # PASS (compiles+lints)
cargo test -p spark-core routing::                                                          # host: macOS tests still PASS
```

- [ ] **Step 5: Gate + commit**
```bash
cd /Users/afisk/go/src/github.com/getlantern/spark-app-split-tunneling
cargo fmt --all --check
git add core/src/routing.rs
git commit -m "feat(core/routing): Windows route.exe covers + blackhole (cfg windows)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: Windows tun→ifindex resolution + DNS ops wired into RouteManager

**Files:** Modify `core/src/routing.rs`

`RouteManager::new(tun)` holds the tun name. On Windows, `install`/`block` need the interface **index** and `install`/`restore` set adapter DNS. Resolve the index once and set the DNS resolver (spark's fake-IP `:53` on the tun's own IP — the resolver the netstack answers).

- [ ] **Step 1: Write the failing test** — add a `cfg(windows)` test for the DNS argv builder:
```rust
    #[cfg(target_os = "windows")]
    #[test]
    fn windows_sets_and_clears_adapter_dns_via_netsh() {
        // set: point the adapter (by index) at the tunnel resolver.
        assert_eq!(
            argv(&dns_set_op("12", "10.6.7.1")),
            "interface ipv4 set dnsservers 12 static 10.6.7.1 primary"
        );
        assert_eq!(dns_set_op("12", "10.6.7.1").program, "netsh");
        // clear: revert to DHCP on teardown.
        assert_eq!(argv(&dns_clear_op("12")), "interface ipv4 set dnsservers 12 dhcp");
    }
```

- [ ] **Step 2: Verify it fails for Windows** — `cargo clippy -p spark-core --target x86_64-pc-windows-msvc --all-targets` → FAIL (`dns_set_op`/`dns_clear_op` missing).

- [ ] **Step 3: Implement** — add the netsh DNS builders (cfg windows) + the ifindex resolver + thread them through `RouteManager`. Add:
```rust
/// Set the tun adapter's DNS to the tunnel resolver (spark's fake-IP responder) so queries ride
/// the tunnel. `iface` is the interface index. VALIDATION-DEFERRED: netsh dnsservers syntax.
#[cfg(target_os = "windows")]
fn dns_set_op(iface: &str, resolver: &str) -> RouteOp {
    RouteOp::required_with(
        "netsh",
        vec!["interface", "ipv4", "set", "dnsservers", iface, "static", resolver, "primary"],
    )
}

/// Revert the adapter's DNS to DHCP on teardown.
#[cfg(target_os = "windows")]
fn dns_clear_op(iface: &str) -> RouteOp {
    RouteOp::ignorable_with("netsh", vec!["interface", "ipv4", "set", "dnsservers", iface, "dhcp"])
}

/// Resolve a Windows adapter alias (the tun name, e.g. "spark0") to its interface index.
/// VALIDATION-DEFERRED: prefer a `tun-rs` index accessor on the `AsyncDevice` if one exists
/// (confirm the 2.8 API during impl); otherwise use windows-sys
/// `ConvertInterfaceAliasToLuid` + `ConvertInterfaceLuidToIndex`. Returns the index as a string
/// (the form `via_tun_op` consumes).
#[cfg(target_os = "windows")]
fn resolve_ifindex(_alias: &str) -> io::Result<String> {
    // Implementation note for the engineer: if `tun-rs` exposes the index on the open device,
    // pass it into RouteManager from the engine (W2) instead of resolving by alias here — that is
    // more robust than a name lookup and avoids a windows-sys dependency. This resolver is the
    // fallback for the `spark run` CLI path (no engine). Wire the chosen approach and delete the
    // other. Do NOT ship an `unimplemented!()`.
    Err(io::Error::new(io::ErrorKind::Unsupported, "resolve_ifindex: wire tun-rs index or windows-sys"))
}
```
IMPORTANT (engineer): resolve the "how do we get the index" question **before** writing `resolve_ifindex` — check the pinned `tun-rs` 2.8 `AsyncDevice`/`SyncDevice` API for an index/LUID accessor (grep the crate source under `~/.cargo`), and prefer threading the index from the open device. If `tun-rs` exposes it, change `RouteManager` to accept the index (e.g. `RouteManager::new_windows(name, ifindex)` under cfg, or add a `set_ifindex`) and have `install` format it into the ops; drop `resolve_ifindex`. If not, implement `resolve_ifindex` with `windows-sys` (add it as a `[target.'cfg(windows)'.dependencies]` entry — a MINIMAL feature set: `Win32_NetworkManagement_IpHelper`, `Win32_Foundation`) and keep it. Either way, no `Err(...)`/`unimplemented!()` stub may remain at the end of this task.

Then in `RouteManager` (cfg windows), store the resolved index + resolver IP and include the DNS ops in `install_ops`/`restore_ops` on Windows (add `dns_set_op` to install, `dns_clear_op` to restore). Keep macOS/Linux `install_ops`/`restore_ops` unchanged (no DNS ops — they don't manage DNS). The tunnel resolver IP is the tun's own IPv4 (the address the netstack's fake-IP DNS answers on); thread it from `TunConfig.ipv4` via the engine in W2, defaulting for the CLI path.

- [ ] **Step 4: Verify** — `cargo clippy -p spark-core --target x86_64-pc-windows-msvc --all-targets -- -D warnings` PASS; `cargo test -p spark-core routing::` (host) PASS; `cargo fmt --all --check`.

- [ ] **Step 5: Commit**
```bash
cd /Users/afisk/go/src/github.com/getlantern/spark-app-split-tunneling
git add core/src/routing.rs core/Cargo.toml
git commit -m "feat(core/routing): Windows adapter DNS via netsh + ifindex resolution

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: Whole-workspace gate + progress log + PR

**Files:** Modify `docs/superpowers/windows-progress.md`

- [ ] **Step 1: Whole-workspace gate** (spark-core APIs feed cli+service — build the whole tree):
```bash
cd /Users/afisk/go/src/github.com/getlantern/spark-app-split-tunneling
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings                                   # host
cargo clippy --all-targets --target x86_64-pc-windows-msvc -- -D warnings   # windows cross-check
cargo test --workspace                                                       # host (runs the pure + macOS routing tests)
```
All must pass. (The `cfg(windows)` routing tests run in W4's `windows-latest` CI, not here.)

- [ ] **Step 2: Update the progress log** — set W1 to "code-complete (cross-compiled + host-tested); Windows-cfg tests pending windows-latest CI (W4); route.exe/netsh argv + ifindex pending on-Windows validation" and record the PR number after opening.

- [ ] **Step 3: Commit + push + open PR**
```bash
cd /Users/afisk/go/src/github.com/getlantern/spark-app-split-tunneling
git add docs/superpowers/windows-progress.md
git commit -m "docs: W1 progress + status

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
git push -u origin fisk/windows-w1-routing
gh pr create --base main --head fisk/windows-w1-routing --title "Windows W1: core routing/kill-switch (route.exe covers + netsh DNS)" --body "<see below>"
```
PR body must: summarize the RouteManager Windows path; state the whole-program plan (W1→W4) with this as W1; and **explicitly flag** that the `route.exe`/`netsh` argv and the ifindex resolution are cross-compiled + unit-tested-in-CI but **not validated on real Windows** (macOS host) — with the deferred on-Windows checklist coming in W4. Include a mermaid `sequenceDiagram` only if it adds clarity (probably not for W1).

- [ ] **Step 4: Review loop** — per the goal prompt: run the review-pr skill (request Copilot + CodeRabbit; verify each comment; fix or push back; reply + resolve; re-request; loop to a clean round or ~4 rounds; background-poll). Merge (squash) when review converges + all CI green + 0 unresolved threads. Then W2.

---

## Self-review
- **Spec coverage (W1 slice):** covers via route.exe (T1+T3), blackhole kill-switch (T3), netsh adapter DNS (T4), teardown/restore (T3+T4), pure testable builders (T1/T2 host-tested; T3/T4 cross-compiled + CI-tested). Proxy-IP bypass intentionally dropped → SocketProtector in W2 (recorded in progress log). tun WinTun already supported (no change). ✔
- **Placeholders:** none — every step has code. The one deliberate `Err(...)` in `resolve_ifindex` (T4 Step 3) is explicitly required to be replaced within the same task (tun-rs index or windows-sys), with a hard "no stub may remain" gate. ✔
- **Type consistency:** `RouteOp{program,args,ignore_failure}`, `required/ignorable/required_with/ignorable_with`, `half_to_dest_mask`, `via_tun_op/clear_op/blackhole_op/dns_set_op/dns_clear_op/resolve_ifindex`, `install_ops/restore_ops/block_ops` consistent across tasks. ✔
- **Honesty:** every Windows-runtime-form detail (route add IF, netsh syntax, ifindex API) is flagged VALIDATION-DEFERRED and must be surfaced in the PR; nothing is claimed as on-Windows-verified. ✔
