# Live Config Reload Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Make the periodic remote-config refresh apply *live* — rebuild the running server pool from the refreshed server list, latency-probe the new servers, and reflect them in the UI without a reconnect, while retaining the best prior working proxy so there is no connectivity gap.

**Architecture:** Today the config-fetch loop (`core/src/config/fetch/mod.rs:389` `run_loop`) fetches/parses/caches fresh config every `poll_interval_seconds` but its `on_config` callback (`core/src/fd_tunnel.rs:880`) is a no-op (`|_cfg| {}`) — a deliberate "v1: no live swap, warms cache for next connect" choice. The pool (`SelectingTransport`, `core/src/transport/select.rs`) holds an **immutable** `Arc<Vec<Member>>`; a background `prober_loop` already re-probes existing members every `probe_interval_secs`.

This plan makes the pool's members **live-swappable** via a `std::sync::Mutex<Arc<Vec<Member>>>` (no new dependency — mirrors the existing `selection` mutex, short lock never held across `.await`). A new `reload(new_members)` swaps members, resets ranking, and triggers an immediate re-probe. **Prior-best retention:** before swapping, identify the current best *healthy* member by its `label` (`"{protocol} {addr}"`, a stable server identity); if the refreshed config dropped it, carry that `Member` over as a fallback and seed it as the incumbent (current + last-good latency) so traffic keeps flowing on the proven server until the new set proves itself (hysteresis lets a clearly-better new server take over; an unhealthy carried member drops out naturally). `on_config` derives the pool handle from `current_pool()` and calls the reload through a new `PoolControl::reload_from_config(&Config)` method (keeps the private `Member` type off the public trait surface).

**Tech Stack:** Rust, tokio, `std::sync::Mutex`, the vendored transport/prober. Feature-gated under `multi-server`.

---

### Task 1: Make `SelectingTransport` members live-swappable (refactor, no behavior change)

**Files:**
- Modify: `core/src/transport/select.rs`

- [ ] **Step 1:** Add `#[derive(Clone)]` to `struct Member` (all fields — `Arc<dyn Transport>`, `Arc<dyn UdpTransport>`, `CallbackUrl`, `ServerMeta`, `String`, `String` — are `Clone`).

- [ ] **Step 2:** Change the field `members: Arc<Vec<Member>>` to `members: Arc<std::sync::Mutex<Arc<Vec<Member>>>>`. Add a private accessor:

```rust
/// Cheap snapshot of the current member list (short lock, never held across `.await`).
fn members(&self) -> Arc<Vec<Member>> {
    self.members.lock().unwrap_or_else(|e| e.into_inner()).clone()
}
```

- [ ] **Step 3:** In `new()`, wrap members: `let members = Arc::new(std::sync::Mutex::new(Arc::new(members)));` and pass `Arc::clone(&members)` to `prober_loop`. `SelectingTransport { members, ... }`.

- [ ] **Step 4:** Update `order()`, `demote()`, `snapshot()`, `set_pin()` to read the member count/list via `self.members()` (a local `Arc<Vec<Member>>`) instead of `self.members`. In `order()`/`snapshot()` use the local snapshot's `len()`.

- [ ] **Step 5:** Update `dial`/`dial_addr`/`dial_udp`/`dial_udp_addr`: take `let members = self.members();` once at the top, iterate `order()`, and **bounds-guard** each index (`let Some(m) = members.get(i) else { continue };`) so a mid-dial reload can't panic on a stale index. Use `members.len()` in the fail-open warning.

- [ ] **Step 6:** Change `prober_loop`'s signature to take `members: Arc<std::sync::Mutex<Arc<Vec<Member>>>>`; at the **top of each round** load a local snapshot `let members = { members.lock().unwrap_or_else(|e| e.into_inner()).clone() };` and probe against it. (The existing `if sel.latest.len() != members.len()` guard already handles size changes.)

- [ ] **Step 7:** Update the test-only `selecting_with_direct` helper + the `member`/`snapshot` tests that touch `st.members`/`st.selection` to wrap members in the new `Arc<Mutex<Arc<Vec<Member>>>>` shape.

- [ ] **Step 8:** Run `cargo test -p spark-core --features multi-server transport::select` — all existing select tests still pass (pure refactor).

- [ ] **Step 9:** Commit: `refactor(transport): make SelectingTransport members live-swappable`

---

### Task 2: `SelectingTransport::reload` with prior-best retention (TDD)

**Files:**
- Modify: `core/src/transport/select.rs`

- [ ] **Step 1 (failing test):** `reload` swaps in a new member set and `snapshot()` reflects it:

```rust
#[tokio::test]
async fn reload_replaces_members() {
    let t = selecting(vec![member_with_meta(true, meta("old", "US"))], vec![0]);
    t.reload(vec![
        member_with_meta(true, meta("newA", "GB")),
        member_with_meta(true, meta("newB", "DE")),
    ]);
    let snap = t.snapshot();
    assert_eq!(snap.len(), 2);
    assert_eq!(snap[0].meta.name.as_deref(), Some("newA"));
    assert_eq!(snap[1].meta.name.as_deref(), Some("newB"));
}
```

- [ ] **Step 2 (failing test):** prior best *healthy* member (by label) is carried over when the new config drops it, seeded current + healthy:

```rust
#[tokio::test]
async fn reload_keeps_best_prior_working_proxy() {
    // A pool with a healthy, labeled incumbent that the new config omits.
    let keep = member_labeled(true, meta("keep", "US"), "samizdat 1.1.1.1:443");
    let t = selecting(vec![keep], vec![0]);
    { // mark the incumbent healthy (what the prober would record)
        let mut sel = t.selection.lock().unwrap();
        sel.latest = vec![Some(ProbeOutcome { latency: Duration::from_millis(30), healthy: true })];
    }
    // New config: a single different server.
    t.reload(vec![member_labeled(true, meta("fresh", "GB"), "hysteria2 2.2.2.2:443")]);
    let snap = t.snapshot();
    // The proven "keep" server is still present (carried over) …
    assert!(snap.iter().any(|s| s.meta.name.as_deref() == Some("keep")));
    // … and is current (leads new flows) with its last-good latency until re-probe.
    let kept = snap.iter().find(|s| s.meta.name.as_deref() == Some("keep")).unwrap();
    assert!(kept.is_current);
    assert!(kept.healthy);
    assert_eq!(kept.latency_ms, Some(30));
}
```

- [ ] **Step 3 (failing test):** when the new config *includes* the prior-best (same label), it is not duplicated and is seeded current:

```rust
#[tokio::test]
async fn reload_dedups_retained_best_when_present() {
    let t = selecting(vec![member_labeled(true, meta("keep", "US"), "samizdat 1.1.1.1:443")], vec![0]);
    { let mut sel = t.selection.lock().unwrap();
      sel.latest = vec![Some(ProbeOutcome { latency: Duration::from_millis(30), healthy: true })]; }
    t.reload(vec![
        member_labeled(true, meta("keep", "US"), "samizdat 1.1.1.1:443"), // same server
        member_labeled(true, meta("fresh", "GB"), "hysteria2 2.2.2.2:443"),
    ]);
    let snap = t.snapshot();
    assert_eq!(snap.len(), 2, "no duplicate of the retained server");
    assert_eq!(snap[0].meta.name.as_deref(), Some("keep"));
    assert!(snap[0].is_current);
}
```

- [ ] **Step 4 (implement):** add `member_labeled` test helper (`member_with_meta` + `.with_label(..)`), then implement:

```rust
/// Live-replace the pool's members with `new_members` (from a refreshed config), retaining the
/// best prior *working* proxy so traffic never gaps while the new set is probed. Resets the ranking
/// (carried-best first, then config order), seeds the carried member's last-good outcome, remaps the
/// manual pin by server identity (label), and wakes the prober for an immediate re-probe.
pub(crate) fn reload(&self, mut new_members: Vec<Member>) {
    let old = self.members();
    // Identify the prior best working member: pinned-if-valid, else ranked-first; must be healthy.
    let prior = {
        let sel = self.selection.lock().unwrap_or_else(|e| e.into_inner());
        let idx = sel.pinned.filter(|&p| p < old.len()).or_else(|| sel.ranked.first().copied());
        idx.and_then(|i| {
            let oc = sel.latest.get(i).copied().flatten();
            match oc {
                Some(o) if o.healthy && !old[i].label.is_empty() => Some((old[i].clone(), o)),
                _ => None,
            }
        })
    };
    let pinned_label = { // preserve a manual selection across the swap, by identity
        let sel = self.selection.lock().unwrap_or_else(|e| e.into_inner());
        sel.pinned.and_then(|p| old.get(p)).map(|m| m.label.clone())
    };
    // Carry the proven server over if the refreshed config dropped it.
    let mut carried: Option<(usize, ProbeOutcome)> = None;
    if let Some((m, oc)) = prior {
        match new_members.iter().position(|nm| !nm.label.is_empty() && nm.label == m.label) {
            Some(pos) => carried = Some((pos, oc)),
            None => { new_members.push(m); carried = Some((new_members.len() - 1, oc)); }
        }
    }
    let new_arc = Arc::new(new_members);
    let n = new_arc.len();
    {
        let mut sel = self.selection.lock().unwrap_or_else(|e| e.into_inner());
        *self.members.lock().unwrap_or_else(|e| e.into_inner()) = Arc::clone(&new_arc);
        // Carried-best leads (continuity), then the rest in config order.
        let mut ranked = Vec::with_capacity(n);
        if let Some((ci, _)) = carried { ranked.push(ci); }
        ranked.extend((0..n).filter(|&i| carried.map(|(ci, _)| ci) != Some(i)));
        sel.ranked = ranked.into();
        sel.latest = vec![None; n];
        if let Some((ci, oc)) = carried { sel.latest[ci] = Some(oc); }
        // Keep the manual pin only if that exact server survives the refresh.
        sel.pinned = pinned_label.and_then(|lbl| new_arc.iter().position(|m| m.label == lbl));
    }
    tracing::info!(members = n, "pool reloaded from refreshed config");
    self.reprobe.notify_one();
}
```

- [ ] **Step 5:** Run the three new tests → PASS. Run the full `transport::select` module → PASS.

- [ ] **Step 6:** Commit: `feat(transport): SelectingTransport::reload with prior-best retention`

---

### Task 3: Extract `build_members` from `build_selecting`

**Files:**
- Modify: `core/src/transport/mod.rs`

- [ ] **Step 1:** Extract the member-building loop (lines ~292-313) into:

```rust
/// Build pool members from `config.transport.servers`; un-buildable entries are skipped (reason
/// collected). Shared by initial pool construction and live reload.
#[cfg(feature = "multi-server")]
fn build_members(config: &Config, protector: Option<&SocketProtector>) -> (Vec<Member>, Vec<String>) {
    let wire = wire_plan_from_config(&config.transport.shaping);
    let mut members = Vec::with_capacity(config.transport.servers.len());
    let mut skipped = Vec::new();
    for entry in &config.transport.servers {
        match build_member(entry, config, protector, &wire) {
            Ok(m) => members.push(m),
            Err(e) => {
                let who = entry.name.as_deref().unwrap_or("<unnamed>");
                tracing::warn!(server = who, error = %e, "transport.servers: skipping un-buildable pool member");
                skipped.push(format!("{who}: {e}"));
            }
        }
    }
    (members, skipped)
}
```

(Note `build_member`'s current `protector: Option<&SocketProtector>` param — pass through as-is.) Import `Member` into scope (`use crate::transport::select::Member;`) if not already.

- [ ] **Step 2:** Rewrite `build_selecting` to call `build_members`, keep the empty-pool error, then build the `SelectingTransport` as today.

- [ ] **Step 3:** Run `cargo build -p spark-core --features multi-server` → clean.

- [ ] **Step 4:** Commit: `refactor(transport): extract build_members for reuse`

---

### Task 4: `PoolControl::reload_from_config` (TDD)

**Files:**
- Modify: `core/src/transport/mod.rs`, `core/src/transport/select.rs`

- [ ] **Step 1:** Add to the `PoolControl` trait a default-no-op method (keeps non-pool controls unaffected and `Member` off the public surface):

```rust
/// Live-rebuild the pool from a refreshed config (new servers probed, prior-best retained). Default
/// is a no-op; only the multi-server pool implements it. `io::Result` so the caller can log + keep
/// the current pool on a build failure (e.g. an all-unbuildable server set).
fn reload_from_config(&self, _config: &Config) -> std::io::Result<()> { Ok(()) }
```

- [ ] **Step 2 (failing test in select.rs):** reload_from_config on a live pool ingests a new config's servers. Build a minimal `Config` with two `transport.servers` and assert `snapshot().len()` grows. (Use the existing config test helpers / `Config` builders in `core/src/config`.)

- [ ] **Step 3 (implement):** in the `#[cfg(feature = "multi-server")] impl PoolControl for SelectingTransport`, override:

```rust
fn reload_from_config(&self, config: &Config) -> std::io::Result<()> {
    let protector = match config.transport.protect_interface.as_deref() {
        Some(name) => Some(super::SocketProtector::for_interface(name)?),
        None => None,
    };
    let (members, skipped) = super::build_members(config, protector.as_ref());
    if members.is_empty() {
        return Err(std::io::Error::other(format!(
            "reload: no buildable pool members ({} skipped)", skipped.len())));
    }
    self.reload(members);
    Ok(())
}
```

- [ ] **Step 4:** Test → PASS.

- [ ] **Step 5:** Commit: `feat(transport): PoolControl::reload_from_config`

---

### Task 5: Wire `on_config` to reload the live pool

**Files:**
- Modify: `core/src/fd_tunnel.rs`

- [ ] **Step 1:** Just before the refresh-loop `tokio::spawn` (~line 875), capture the resolved interface: `let reload_iface = config.transport.protect_interface.clone();`.

- [ ] **Step 2:** Replace the no-op closure at line 880 with a real handler:

```rust
let env = FetchEnv::from_env();
let on_cfg_iface = reload_iface.clone();
tokio::select! {
    _ = fetch::run_loop(&loop_dir, &env, move |mut cfg| {
        // A fetched config carries no protect_interface; reuse the one discovered at bringup so
        // the rebuilt members pin their sockets identically (UDP/QUIC tunnel bypass).
        cfg.transport.protect_interface = on_cfg_iface.clone();
        match current_pool() {
            Some(pool) => match pool.reload_from_config(&cfg) {
                Ok(()) => info!(servers = cfg.transport.servers.len(),
                    "config-fetch: live-reloaded server pool"),
                Err(e) => warn!(error = %e,
                    "config-fetch: pool reload failed; keeping current pool"),
            },
            // No live pool (direct/tunnel/single-transport): refresh still warms the cache for
            // the next connect, as before.
            None => {}
        }
    }, || false) => {}
    _ = loop_stop.notified() => {}
}
```

- [ ] **Step 3:** Confirm `current_pool`, `info!`, `warn!`, `FetchEnv` are in scope (they are — used nearby).

- [ ] **Step 4:** Commit: `feat(fd_tunnel): live-reload the server pool on config refresh`

---

### Task 6: Whole-workspace gate

- [ ] **Step 1:** `cargo fmt --all`
- [ ] **Step 2:** `cargo clippy --workspace --all-targets --features multi-server -- -D warnings` (spark-core API change — verify cli + service + ffi crates compile, per the "verify whole workspace" rule).
- [ ] **Step 3:** `cargo test --workspace --features multi-server` (or the repo's standard test invocation).
- [ ] **Step 4:** Android JNI target check: `cargo ndk -t arm64-v8a clippy -p spark-android` (per the android-target-verify rule) — only if the android toolchain is available; otherwise note it.
- [ ] **Step 5:** Commit any fmt/clippy fixups; open PR + run the review loop.
