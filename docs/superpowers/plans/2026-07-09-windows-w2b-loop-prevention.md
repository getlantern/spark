# Windows W2b — Loop-Prevention (SocketProtector) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** On Windows, pin the proxy's own upstream dials to the physical egress interface (`IP_UNICAST_IF`/`IPV6_UNICAST_IF`) so they bypass W1's full-tunnel routes instead of looping back into the TUN — the loop-prevention deferred from W1.

**Architecture:** All changes are in `core/`. `SocketProtector` (`core/src/net.rs`) gains a live Windows path: a raw `setsockopt(IP_UNICAST_IF)` (via `windows-sys`), a name→index resolver and a physical-interface discovery (both via the `getifaddrs` crate, already in-tree). The transport builder (`transport::from_config`) falls back to the discovered physical interface on Windows when no explicit `protect_interface` is configured, so the service's proxy dials are pinned automatically. No `service/` or engine changes; the whole thing flows through the existing name-based protector plumbing.

**Tech Stack:** Rust (edition 2021, MSRV 1.85), `socket2` 0.6.4, `windows-sys` 0.61 (`Win32_Networking_WinSock`), `getifaddrs` 0.6.2. Cross-compile gate via `cargo xwin`.

---

## Context for the implementer (read before starting)

### Why this exists (the loop)
A transparent TUN proxy forwards a flow by dialing its destination. With W1's split-default covers (`0.0.0.0/1`+`128.0.0.0/1`) routed into the TUN, the proxy's **own** upstream dial would also match those covers and re-enter the TUN → infinite loop. macOS/Linux prevent this by pinning the proxy's outbound sockets to the physical interface (`IP_BOUND_IF`/`IP_UNICAST_IF`) via `SocketProtector`. On Windows this is currently a **no-op** (`net.rs`: `interface_index` returns `Unsupported` for non-unix; `bind_to_index`'s cfg-list excludes windows). W2b makes it live.

### Why NOT socket2's `bind_device_by_index` (the W1-progress-log finding, verified)
`socket2` 0.6.4 does **not** expose `bind_device_by_index_v4/v6` on Windows — its cfg gate (`socket2-0.6.4/src/sys/unix.rs:1996`) lists ios/macos/linux/android/etc. and excludes `windows`. So the Windows path needs a **raw `setsockopt`** via `windows-sys`.

### The IPv4 network-byte-order quirk (the #1 correctness risk — cannot be validated on the macOS host)
`IP_UNICAST_IF` (IPv4) takes the interface index as a `DWORD` in **network byte order** (big-endian). `IPV6_UNICAST_IF` (IPv6) takes it in **host byte order**. This asymmetry is a documented Windows gotcha (WireGuard-windows, curl, etc. all special-case it). Getting it wrong silently pins to the wrong/no interface. Task 1 isolates the v4 transform into a pure, host-unit-tested helper so the contract is nailed down even though the `setsockopt` itself only compiles under cross-clippy.

### Verified API facts (checked against the vendored crate sources — do not re-guess)
- **`windows-sys` 0.61.2**, feature `Win32_Networking_WinSock`, provides:
  `fn setsockopt(s: SOCKET, level: i32, optname: i32, optval: PCSTR, optlen: i32) -> i32`
  (`PCSTR = *const u8`; returns `0` on success, `SOCKET_ERROR` (-1) on failure → use `io::Error::last_os_error()`), and the consts `IP_UNICAST_IF`, `IPV6_UNICAST_IF`, `IPPROTO_IP`, `IPPROTO_IPV6`, and the `SOCKET` type. (`windows-sys` 0.61 is already a direct dep of `service/`, so the version is settled — a single 0.61.x lands in the tree.)
- **`socket2::SockRef`** derefs to `socket2::Socket` (`sockref.rs:71`), which on Windows implements `std::os::windows::io::AsRawSocket`. So `sock.as_raw_socket() as SOCKET` yields the handle for `setsockopt`. (Bring `use std::os::windows::io::AsRawSocket;` into the windows `bind_to_index`.)
- **`getifaddrs` 0.6.2** (already in-tree via tun-rs; works on Windows via `src/windows.rs`) exposes:
  - `getifaddrs() -> io::Result<impl Iterator<Item = Interface>>` — one `Interface` per interface/address.
  - `Interface { pub name: String, pub address: IpAddr, pub flags: InterfaceFlags, pub index: Option<InterfaceIndex> }` where `InterfaceIndex = u32` and `InterfaceFlags` has `UP`, `RUNNING`, `LOOPBACK` bits (bitflags).
  - We resolve name→index by **iterating and matching `.name`** (guaranteed consistent with our own discovery, which reads the same `.name` — avoids any `if_nametoindex` round-trip question).
- **`net.rs` current shape** (already in the file): `SocketProtector { interface: String, index: NonZeroU32 }`; `for_interface(name)` → `interface_index(name)?`; `protect(sock, ipv4)` → `bind_to_index(sock, self.index, ipv4)`; `interface_index` is `#[cfg(unix)]` (real) / `#[cfg(not(unix))]` (`Unsupported`); `bind_to_index` is gated to a unix-ish cfg-list (real) / else no-op; `default_physical_interface()` is `#[cfg(target_os="macos")]` (real, raw libc getifaddrs) / `#[cfg(not(target_os="macos"))]` (`None`).

### Design decisions (settled — technical, within the approved spec's W2b section)
1. **Name-based, fits existing plumbing.** Keep `config.transport.protect_interface: Option<String>` and `SocketProtector::for_interface(name)`. Windows just makes `interface_index` and `default_physical_interface` real, and `bind_to_index` do the setsockopt. No new index-based API, no config schema change.
2. **Discovery via the `getifaddrs` crate, not raw `GetAdaptersAddresses`.** It's a safe wrapper already compiled into the tree; minimizing hand-written unsafe FFI matters because none of it can be validated on the macOS host. Only the `setsockopt` itself is raw (unavoidable — socket2 lacks it on Windows).
3. **Auto-pin centralized in `transport::from_config_with_control`.** When `protect_interface` is `None`, fall back to `default_physical_interface()` on Windows (with a debug log). This is where every transport builder already constructs the protector, so the service, CLI, and any future caller get loop-prevention with no engine change and without making `core::net` items part of another crate's call path.
4. **macOS/Linux untouched.** All new code is `#[cfg(target_os = "windows")]` except the pure v4 byte-order helper (non-cfg, so it unit-tests on the host). The macOS `default_physical_interface` (raw libc) stays as-is — don't refactor a working path.

### CLAUDE.md constraints in force
- No `unwrap()`/`expect()` outside tests/startup; every `Result` handled. `unsafe` blocks need a `// SAFETY:` comment. No holding locks across `.await` (N/A here). `cargo fmt` + `clippy -D warnings` clean.
- **New deps:** `windows-sys` (pre-authorized by the goal prompt for Windows FFI; already in `service`) and `getifaddrs` (safe-wrapper choice to minimize unsafe FFI; already in-tree via tun-rs). Both **target-gated to `cfg(windows)`** so they add nothing to macOS/Linux/mobile builds. Declare them directly in `core/Cargo.toml` matching `service/Cargo.toml`'s style.
- Do not `git add -A`/`.` (untracked `gui-tauri/src-tauri/target`). Stage changed files explicitly. Commit trailer: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.

### What is NOT validated here (state in the PR)
Built on a macOS host. The Windows `setsockopt(IP_UNICAST_IF)`, the byte order on a real adapter, the `getifaddrs` discovery picking the right physical NIC, and that pinning actually breaks the loop — **none are validated on Windows**. Only the pure v4-byte-order helper is host-unit-tested; everything else is compile-verified via `cargo xwin` and deferred to the W4 on-device checklist.

---

## File Structure

- **Modify** `core/Cargo.toml` — add `[target.'cfg(windows)'.dependencies]` with `windows-sys` (WinSock) + `getifaddrs`.
- **Modify** `core/src/net.rs` — pure v4 byte-order helper (+test); Windows `bind_to_index`, `interface_index`, `default_physical_interface`.
- **Modify** `core/src/transport/mod.rs` — Windows discovery-fallback in the protector construction.

No new files.

---

## Task 1: IPv4 `IP_UNICAST_IF` byte-order helper (TDD)

**Files:**
- Modify: `core/src/net.rs` (add near the bottom, before `#[cfg(test)] mod tests`)
- Test: `core/src/net.rs` (in the existing `#[cfg(test)] mod tests`)

- [ ] **Step 1: Write the failing test**

Add to `mod tests` in `core/src/net.rs`:

```rust
    // IP_UNICAST_IF (IPv4) takes the interface index as a DWORD in NETWORK byte order, unlike
    // IPV6_UNICAST_IF (host order). The 4 bytes handed to setsockopt must be big-endian regardless
    // of host endianness: index 5 -> [0, 0, 0, 5].
    #[test]
    fn ipv4_unicast_if_index_is_network_order() {
        assert_eq!(ipv4_unicast_if_index(5).to_ne_bytes(), [0, 0, 0, 5]);
        assert_eq!(ipv4_unicast_if_index(1).to_ne_bytes(), [0, 0, 0, 1]);
        assert_eq!(ipv4_unicast_if_index(0x0102_0304).to_ne_bytes(), [1, 2, 3, 4]);
    }
```

- [ ] **Step 2: Run it — expect a compile failure (function undefined)**

Run: `cargo test -p spark-core net::tests::ipv4_unicast_if_index_is_network_order`
Expected: FAIL — `cannot find function ipv4_unicast_if_index`.

- [ ] **Step 3: Add the helper**

Add before `#[cfg(test)] mod tests` in `core/src/net.rs`:

```rust
/// The value to pass as the `IP_UNICAST_IF` option for `index`. IPv4's `IP_UNICAST_IF` expects the
/// interface index as a `DWORD` in **network byte order** (big-endian) — unlike `IPV6_UNICAST_IF`,
/// which uses host order. Isolated as a pure fn so the byte-order contract is unit-tested on the
/// host even though the `setsockopt` call only compiles for Windows.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn ipv4_unicast_if_index(index: u32) -> u32 {
    index.to_be()
}
```

Note the `#[cfg_attr(not(target_os = "windows"), allow(dead_code))]`: the helper is only *called* from the Windows `bind_to_index`, but it's compiled on all platforms so the host test can exercise it — the attribute silences the unused-fn warning off-Windows (same pattern `routing.rs::half_to_dest_mask` uses).

- [ ] **Step 4: Run the test — expect PASS**

Run: `cargo test -p spark-core net::tests::ipv4_unicast_if_index_is_network_order`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add core/src/net.rs
git commit -m "$(cat <<'EOF'
Windows W2b: IP_UNICAST_IF v4 network-byte-order helper (host-tested)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: core Windows deps + the live Windows `SocketProtector` path

**Files:**
- Modify: `core/Cargo.toml`
- Modify: `core/src/net.rs`

- [ ] **Step 1: Add the Windows deps to `core/Cargo.toml`**

After the `[dependencies]` block (and before `[dev-dependencies]`), add:

```toml
# Windows loop-prevention (W2b): pin the proxy's own upstream sockets to the physical egress
# interface so they bypass the full-tunnel routes.
# - windows-sys: raw setsockopt(IP_UNICAST_IF/IPV6_UNICAST_IF) — socket2 0.6 doesn't expose
#   bind_device_by_index on Windows. Version matches service/ (single 0.61.x in the tree).
# - getifaddrs: safe interface enumeration (name/index/flags) — avoids hand-written
#   GetAdaptersAddresses FFI. Already in the tree via tun-rs.
[target.'cfg(windows)'.dependencies]
windows-sys = { version = "0.61", features = ["Win32_Networking_WinSock"] }
getifaddrs = "0.6"
```

- [ ] **Step 2: Implement the Windows `bind_to_index` (the setsockopt)**

In `core/src/net.rs`, the current no-op `bind_to_index` is `#[cfg(not(any(<unix-ish list>)))]`. That negated cfg currently *includes* windows (so windows gets the no-op). Add a dedicated Windows impl **and** exclude windows from the no-op. Change the no-op's cfg to also exclude `target_os = "windows"`, then add:

```rust
// Windows: socket2 0.6 has no `bind_device_by_index` here, so pin via a raw setsockopt.
// IP_UNICAST_IF (v4) wants the index in network byte order; IPV6_UNICAST_IF (v6) in host order.
#[cfg(target_os = "windows")]
fn bind_to_index(sock: socket2::SockRef<'_>, index: NonZeroU32, ipv4: bool) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        setsockopt, IPPROTO_IP, IPPROTO_IPV6, IP_UNICAST_IF, IPV6_UNICAST_IF, SOCKET,
    };

    let s = sock.as_raw_socket() as SOCKET;
    let (level, optname, arg) = if ipv4 {
        (IPPROTO_IP, IP_UNICAST_IF, ipv4_unicast_if_index(index.get()))
    } else {
        (IPPROTO_IPV6, IPV6_UNICAST_IF, index.get())
    };
    // SAFETY: `s` is a live socket for the lifetime of `sock` (a borrowed SockRef); `&arg` is a
    // 4-byte DWORD matching the documented optlen for these options; setsockopt copies it and does
    // not retain the pointer.
    let rc = unsafe {
        setsockopt(
            s,
            level as i32,
            optname as i32,
            &arg as *const u32 as *const u8,
            std::mem::size_of::<u32>() as i32,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
```

Then update the existing no-op's cfg so windows no longer matches it. It is currently:

```rust
#[cfg(not(any(
    target_os = "ios",
    target_os = "visionos",
    target_os = "macos",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "illumos",
    target_os = "solaris",
    target_os = "linux",
    target_os = "android",
)))]
fn bind_to_index(_sock: socket2::SockRef<'_>, _index: NonZeroU32, _ipv4: bool) -> io::Result<()> {
    Ok(())
}
```

Add `target_os = "windows",` to that `any(...)` list so windows is excluded from the no-op (leaving the new windows impl as the only match on windows). The other non-windows, non-unix-ish targets (e.g. wasm) keep the no-op.

- [ ] **Step 3: Implement the Windows `interface_index` (name→index via getifaddrs)**

The current `#[cfg(not(unix))]` `interface_index` returns `Unsupported`. Change its cfg to `#[cfg(not(any(unix, target_os = "windows")))]` (so non-unix non-windows still errors), and add a Windows impl:

```rust
/// Resolve an interface name to its index by matching the `getifaddrs` enumeration. Uses the same
/// source as `default_physical_interface`, so a name that discovery returned always resolves here.
#[cfg(target_os = "windows")]
fn interface_index(interface: &str) -> io::Result<NonZeroU32> {
    let ifaces = getifaddrs::getifaddrs()?;
    for iface in ifaces {
        if iface.name == interface {
            if let Some(idx) = iface.index.and_then(NonZeroU32::new) {
                return Ok(idx);
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("unknown or index-less interface {interface:?}"),
    ))
}
```

- [ ] **Step 4: Implement Windows `default_physical_interface`**

Change the existing `#[cfg(not(target_os = "macos"))] pub fn default_physical_interface() -> Option<String>` (which returns `None`) to `#[cfg(not(any(target_os = "macos", target_os = "windows")))]`, and add a Windows impl:

```rust
/// Windows: pick the physical egress interface to pin the proxy's own sockets to (loop-prevention).
/// First up+running, non-loopback interface with an IPv4 address and a usable index, skipping our
/// own tun and other virtual adapters by name. `None` → caller leaves sockets unpinned.
#[cfg(target_os = "windows")]
pub fn default_physical_interface() -> Option<String> {
    let ifaces = getifaddrs::getifaddrs().ok()?;
    let mut fallback: Option<String> = None;
    for iface in ifaces {
        // One entry per address family; key off IPv4 (pinning by index covers v6 too).
        if !iface.address.is_ipv4() {
            continue;
        }
        let flags = iface.flags;
        if !flags.contains(getifaddrs::InterfaceFlags::UP)
            || !flags.contains(getifaddrs::InterfaceFlags::RUNNING)
            || flags.contains(getifaddrs::InterfaceFlags::LOOPBACK)
        {
            continue;
        }
        if iface.index.and_then(NonZeroU32::new).is_none() {
            continue; // unusable for IP_UNICAST_IF
        }
        let lname = iface.name.to_ascii_lowercase();
        // Skip our own tunnel + common virtual adapters (WinTun/OpenVPN/loopback/etc.).
        if ["wintun", "tun", "tap", "loopback", "isatap", "teredo", "pseudo"]
            .iter()
            .any(|p| lname.contains(p))
        {
            continue;
        }
        return Some(iface.name);
    }
    fallback.take()
}
```

Note: `fallback` is written to nowhere in this simple form (we return on the first match); keep it only if you add a weaker second-choice pass. To avoid an `unused_mut`/dead-store lint, **drop the `fallback` lines** and just `return None;` at the end unless you implement a real fallback pass. Final tail:

```rust
        return Some(iface.name);
    }
    None
}
```

- [ ] **Step 5: Verify the `InterfaceFlags` + `Interface.address` API names against the crate**

Before trusting the code above, confirm the exact names in `getifaddrs-0.6.2`:
Run: `grep -rn "pub const UP\|pub const RUNNING\|pub const LOOPBACK\|bitflags\|pub address" ~/.cargo/registry/src/*/getifaddrs-0.6.2/src/lib.rs`
Expected: `InterfaceFlags` bitflags with `UP`, `RUNNING`, `LOOPBACK`; `Interface.address: IpAddr` (so `.is_ipv4()` works). If a name differs (e.g. flags are `IFF_UP`), adjust the code to match. **Do not guess — match the crate.**

- [ ] **Step 6: Host build + clippy (windows blocks compiled out)**

Run: `cargo clippy -p spark-core --all-targets -- -D warnings`
Expected: clean. Only the pure helper is compiled on the host; the windows fns are cfg'd out.

- [ ] **Step 7: Windows cross-clippy (compiles all the new windows code + FFI)**

Run: `cargo xwin clippy -p spark-core --all-targets --target x86_64-pc-windows-msvc -- -D warnings`
Expected: clean. This is the real check for the `setsockopt` FFI, the `getifaddrs` calls, `AsRawSocket`, and the flag/address API names. Fix any mismatch here (wrong const type needing a cast, wrong flag name, etc.).

- [ ] **Step 8: Commit**

```bash
git add core/Cargo.toml core/src/net.rs Cargo.lock
git commit -m "$(cat <<'EOF'
Windows W2b: live SocketProtector via IP_UNICAST_IF + getifaddrs

socket2 0.6 has no bind_device_by_index on Windows, so pin the proxy's own
upstream sockets with a raw setsockopt(IP_UNICAST_IF/IPV6_UNICAST_IF)
(windows-sys). Name->index and physical-interface discovery go through the
getifaddrs crate (safe wrapper, already in-tree) to avoid hand-written
GetAdaptersAddresses FFI. Both deps are cfg(windows)-only. FFI cross-compiled,
not validated on Windows (deferred).

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Auto-pin on Windows in `transport::from_config`

**Files:**
- Modify: `core/src/transport/mod.rs` (the protector construction in `from_config_with_control`, ~line 367)

- [ ] **Step 1: Add the Windows discovery-fallback**

The current construction (`transport/mod.rs:367-370`) is:

```rust
    let protector = match config.transport.protect_interface.as_deref() {
        Some(name) => Some(SocketProtector::for_interface(name)?),
        None => None,
    };
```

Replace the `None =>` arm so Windows falls back to the discovered physical interface:

```rust
    let protector = match config.transport.protect_interface.as_deref() {
        Some(name) => Some(SocketProtector::for_interface(name)?),
        None => {
            // Windows: with no explicit egress configured, pin the proxy's own dials to the
            // discovered physical interface so they bypass W1's full-tunnel routes (loop-prevention).
            // Other platforms keep the prior behavior (macOS discovers in fd_tunnel; None here).
            #[cfg(target_os = "windows")]
            {
                match crate::net::default_physical_interface() {
                    Some(name) => {
                        tracing::debug!(interface = %name, "pinning upstream sockets to physical egress (loop-prevention)");
                        crate::net::SocketProtector::for_interface(&name).ok()
                    }
                    None => None,
                }
            }
            #[cfg(not(target_os = "windows"))]
            {
                None
            }
        }
    };
```

Note: `SocketProtector` is already imported at the top of `transport/mod.rs` (`use crate::net::SocketProtector;`), so the `Some(name) =>` arm is unchanged; the windows arm uses the fully-qualified `crate::net::` path (and `crate::net::default_physical_interface`) to avoid adding a windows-only `use`. Using `.ok()` (not `?`) means a discovery/resolve hiccup degrades to unpinned rather than failing tunnel bringup — matching the macOS "None → leave unpinned" tolerance.

- [ ] **Step 2: Host clippy**

Run: `cargo clippy -p spark-core --all-targets -- -D warnings`
Expected: clean (windows arm compiled out; the `None` arm is active).

- [ ] **Step 3: Windows cross-clippy (compiles the fallback arm)**

Run: `cargo xwin clippy -p spark-core --all-targets --target x86_64-pc-windows-msvc -- -D warnings`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add core/src/transport/mod.rs
git commit -m "$(cat <<'EOF'
Windows W2b: auto-pin upstream sockets to the physical egress in from_config

When no protect_interface is configured, Windows now falls back to the
discovered physical interface so the service's proxy dials bypass the
full-tunnel routes. No-op on other platforms.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Full gate + PR

**Files:** none (verification + PR).

- [ ] **Step 1: Format + host clippy (workspace)**

Run: `cargo fmt --all --check` (fix + re-stage if needed), then
`cargo clippy --workspace --all-targets -- -D warnings`
Expected: both clean.

- [ ] **Step 2: Windows cross-clippy (workspace)**

Run: `cargo xwin clippy --workspace --all-targets --target x86_64-pc-windows-msvc -- -D warnings`
Expected: clean.

- [ ] **Step 3: Whole-workspace tests (host)**

Run: `cargo test --workspace`
Expected: green, incl. the new `net::tests::ipv4_unicast_if_index_is_network_order`.

- [ ] **Step 4: Confirm only intended files changed + Cargo.lock is sane**

Run: `git status --porcelain` and `git diff origin/main --stat`
Expected: only `core/Cargo.toml`, `core/src/net.rs`, `core/src/transport/mod.rs`, `Cargo.lock` (+ the docs). `Cargo.lock` should add `getifaddrs`/`windows-sys` edges only if not already present at those versions; no unrelated version churn. If `Cargo.lock` shows large unrelated changes, STOP and investigate.

- [ ] **Step 5: Push + PR**

```bash
git push -u origin fisk/windows-w2b-loop-prevention
```

Open the PR (base `main`): summary + the loop-prevention rationale + the deferred-validation note + a mermaid diagram of the dial→pin flow. State clearly: on-Windows behavior (setsockopt, byte order, discovery picking the right NIC) is NOT validated on the macOS host; only the v4 byte-order helper is unit-tested; the rest is cross-compiled + deferred to the W4 checklist.

- [ ] **Step 6: review-pr loop**

Request Copilot + ensure CodeRabbit; verify each comment; fix or push back; reply + resolve; re-request; loop to a clean round or ~4 rounds; squash-merge when review converged AND all CI green (incl. windows-latest) AND 0 unresolved threads. Then proceed to W2c (live service transport: pipe/winsvc/auth).

---

## Self-Review (completed during planning)

- **Spec coverage:** implements the spec's W2b "Windows loop-prevention" section in full (IP_UNICAST_IF via windows-sys, byte-order note, interface_index, default_physical_interface, engine/transport wiring). The wiring landed in `transport::from_config` rather than the engine (cleaner; noted in the spec's "engine `protect_interface` wiring" — same effect, better location).
- **Placeholder scan:** the two "verify against the crate" steps (Task 2 Step 5, and the flag/address names) are deliberate verification gates, not placeholders — the code is fully written and adjusted only if the crate names differ. No TBDs.
- **Type consistency:** `ipv4_unicast_if_index(u32) -> u32` used by the v4 branch; `bind_to_index(SockRef, NonZeroU32, bool)` signature unchanged across all cfgs; `interface_index(&str) -> io::Result<NonZeroU32>` unchanged; `default_physical_interface() -> Option<String>` unchanged. `setsockopt` args cast to `i32` per its verified signature; `optval` is `*const u8` (PCSTR). All consistent with the verified crate APIs above.
- **Untestable-FFI honesty:** only Task 1 is host-unit-tested; Tasks 2–3 are cross-compile-verified + deferred — stated in the PR, matching W1/W2a precedent.
