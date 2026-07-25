# Unbounded Volunteer (Desktop v1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a strictly-opt-in desktop "Unbounded" tab that runs the `spark-sharing` peer-proxy so uncensored volunteers become bridges for censored users, with a live globe + stats, kept alive via the tray.

**Architecture:** The volunteer proxy runs unprivileged in the Tauri app process. `unbounded-rs` gains per-peer connection events; `spark-sharing` aggregates them (live set + geo) into a status snapshot; the `tauri-plugin-spark-vpn` plugin exposes start/stop/status commands, persists opt-in settings + a cumulative counter, mirrors state to the tray, and pushes `spark://unbounded` to the SvelteKit UI (tab + stats + globe + onboarding + settings). Server `Features.unbounded` gates the whole surface.

**Tech Stack:** Rust (tokio, `spark-sharing`, `unbounded-rs`, kindling/boring for geo fetch), Tauri v2 plugin, SvelteKit + TypeScript, a WebGL globe library.

**Spec:** `docs/superpowers/specs/2026-07-13-unbounded-volunteer-desktop-design.md`. **Branch:** `fisk/unbounded-volunteer`.

**Conventions (from CLAUDE.md):** `thiserror` at module boundaries; no `unwrap`/`expect` outside tests; no MutexGuard across `.await`; store `JoinHandle`s; `cargo fmt` + `cargo clippy -- -D warnings` clean before each commit. `spark-sharing` is its own workspace — run its gate from `spark-sharing/`. The plugin is its own workspace — run from `gui-tauri/tauri-plugin-spark-vpn/`. **`unbounded-rs` is an external crate we own** (`github.com/getlantern/unbounded-rs`); Phase 1 lands there and is consumed here via a pinned git rev bump.

---

## Shared type contract (used across tasks — keep names identical)

`unbounded-rs` (`src/supervisor.rs`), additive `SupervisorEvent` variants:
```rust
PeerConnected { slot: usize, session_id: String, remote: Option<std::net::SocketAddr> }
PeerDisconnected { slot: usize, session_id: String }
```

`spark-sharing`:
```rust
// geo.rs
pub struct Geo { pub country_code: String, pub lat: f64, pub lon: f64 }
// aggregate.rs
pub struct PeerView { pub session_id: String, pub geo: Option<Geo> }
pub struct SharingStatus { pub helping_now: usize, pub peers: Vec<PeerView> }
pub enum SharingDelta { Joined(PeerView), Left(String) } // String = session_id
```

Plugin `spark://unbounded` payload (JSON):
```json
{ "enabled": true, "helpingNow": 9, "totalHelped": 219,
  "peers": [ { "sessionId": "abc", "geo": { "countryCode": "IR", "lat": 35.7, "lon": 51.4 } } ] }
```

Persist keys (plugin `persist.rs`): `unbounded_enabled` (bool), `unbounded_auto_enable` (bool, **default false**), `unbounded_hidden` (bool, default false), `unbounded_welcome_seen` (bool, default false), `unbounded_total_helped` (u64).

---

## File Structure

**`unbounded-rs` (separate repo):** `src/supervisor.rs`, `src/peer_proxy.rs` — emit per-peer events.
**Create in this repo:**
- `spark-sharing/src/geo.rs` — IP→`Geo` lookup + per-process cache.
- `spark-sharing/src/aggregate.rs` — `PoolEvent` → `SharingStatus`/`SharingDelta`.
- `gui-tauri/tauri-plugin-spark-vpn/src/unbounded.rs` — commands, `SharingConfig` build, handle + aggregator ownership, tray + persistence glue.
- `gui-tauri/src/routes/unbounded/+page.svelte` — the Unbounded screen.
- `gui-tauri/src/lib/Globe.svelte` — WebGL globe with live arcs.
- `gui-tauri/src/routes/settings/unbounded/+page.svelte` — Unbounded settings screen.
**Modify:** `spark-sharing/src/lib.rs` (export geo/aggregate); `tauri-plugin-spark-vpn/src/{lib.rs,persist.rs,tray.rs}`; `gui-tauri/src/lib/{spark_backend.ts,tauri_backend.ts}`; the shell layout (tab); `core/src/config/lantern.rs` (config → `SharingConfig` + `Features.unbounded`); i18n locale JSON.

---

## Phase 1 — `unbounded-rs`: per-peer connection events

> Landed in the `unbounded-rs` repo (`~/.cargo/git` checkout is read-only; clone `github.com/getlantern/unbounded-rs`, branch off `main`, PR there). Then bump the pin here.

### Task 1.1: Emit `PeerConnected`/`PeerDisconnected` with the WebRTC remote address

**Files:**
- Modify: `unbounded-rs/src/supervisor.rs` (add the two `SupervisorEvent` variants)
- Modify: `unbounded-rs/src/peer_proxy.rs` (emit them from the peer-proxy session)
- Test: `unbounded-rs/src/peer_proxy.rs` (`#[cfg(test)] mod tests`)

- [ ] **Step 1: Verify the WebRTC API for the selected candidate pair.** Per CLAUDE.md verification discipline, before coding confirm against the pinned `webrtc` crate how to read the connected remote address: inspect `RTCPeerConnection` for `on_peer_connection_state_change` (→ `RTCPeerConnectionState::Connected`) and `sctp().transport().ice_transport().get_selected_candidate_pair()` → remote candidate `address`/`port`. Record the exact method names in the task before writing code.

- [ ] **Step 2: Add the event variants.** In `supervisor.rs` `enum SupervisorEvent`, add:
```rust
PeerConnected { slot: usize, session_id: String, remote: Option<std::net::SocketAddr> },
PeerDisconnected { slot: usize, session_id: String },
```
Note: existing forwarding in `supervise_peer_proxy_pool` already wraps every worker `SupervisorEvent` into `PoolEvent { slot, event }` — but those variants don't carry `slot`. Add `slot` here only if the worker knows it; otherwise emit `PeerConnected { session_id, remote }` WITHOUT `slot` and let the pool forwarder stamp the slot. **Chosen:** drop `slot` from the variants (the forwarder already stamps `PoolEvent.slot`); final variants:
```rust
PeerConnected { session_id: String, remote: Option<std::net::SocketAddr> },
PeerDisconnected { session_id: String },
```

- [ ] **Step 3: Write the failing test.** In `peer_proxy.rs` tests, drive a peer-proxy session against a mock/loopback WebRTC connection that reaches `Connected`, then closes; assert the worker event channel yields a `PeerConnected { session_id, remote: Some(_) }` followed by `PeerDisconnected { session_id }` with the same `session_id` (the `consumer_session_id`). If a full WebRTC mock is impractical, unit-test the smaller helper that maps a connection-state transition + selected-pair lookup into the event (extract that helper so it's testable without real ICE).

- [ ] **Step 4: Run it, expect FAIL** (`cargo test -p lantern-unbounded peer_proxy` — undefined variant / no emission).

- [ ] **Step 5: Implement emission.** In the peer-proxy run loop, register an `on_peer_connection_state_change` handler: on `Connected`, look up the selected candidate pair's remote `SocketAddr` (best-effort → `None` on failure) and send `SupervisorEvent::PeerConnected { session_id, remote }` on the worker event channel; on `Disconnected`/`Failed`/`Closed` (once), send `PeerDisconnected { session_id }`. `session_id` = the session's `consumer_session_id`.

- [ ] **Step 6: Run tests + gate.** `cargo test` + `cargo fmt --all` + `cargo clippy --all-targets -- -D warnings` in the `unbounded-rs` repo. Expected: PASS.

- [ ] **Step 7: Commit + PR in `unbounded-rs`.**
```bash
git add src/supervisor.rs src/peer_proxy.rs
git commit -m "supervisor: emit PeerConnected/PeerDisconnected per censored session"
git push -u origin <branch>   # open PR, merge, note the merged commit SHA
```

### Task 1.2: Bump the `unbounded-rs` pin in `spark-sharing`

**Files:** Modify: `spark-sharing/Cargo.toml` (the `lantern-unbounded` git `rev`), `spark-sharing/Cargo.lock`

- [ ] **Step 1:** `cd spark-sharing && cargo update -p lantern-unbounded --precise <merged-sha>` (or edit the `rev` in `Cargo.toml` then `cargo update -p lantern-unbounded`).
- [ ] **Step 2:** Build to confirm the new variants are visible: `cargo build`. Expected: OK.
- [ ] **Step 3: Commit.**
```bash
git add spark-sharing/Cargo.toml spark-sharing/Cargo.lock
git commit -m "spark-sharing: bump unbounded-rs for per-peer events"
```

---

## Phase 2 — `spark-sharing`: aggregation

### Task 2.1: `aggregate.rs` — PoolEvent → live set + deltas

**Files:**
- Create: `spark-sharing/src/aggregate.rs`
- Modify: `spark-sharing/src/lib.rs` (`mod aggregate; pub use aggregate::{PeerView, SharingStatus, SharingDelta, Aggregator};`)
- Test: inline `#[cfg(test)] mod tests` in `aggregate.rs`

- [ ] **Step 1: Write the failing test** (in `aggregate.rs`):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use lantern_unbounded::supervisor::{PoolEvent, SupervisorEvent};

    fn joined(id: &str) -> PoolEvent {
        PoolEvent { slot: 0, event: SupervisorEvent::PeerConnected { session_id: id.into(), remote: None } }
    }
    fn left(id: &str) -> PoolEvent {
        PoolEvent { slot: 0, event: SupervisorEvent::PeerDisconnected { session_id: id.into() } }
    }

    #[test]
    fn helping_now_refcounts_by_session_and_dedups() {
        let mut agg = Aggregator::new();
        assert_eq!(agg.apply(joined("a")), Some(SharingDelta::Joined(PeerView { session_id: "a".into(), geo: None })));
        // duplicate connect for the same session is ignored (no delta, no double count)
        assert_eq!(agg.apply(joined("a")), None);
        assert_eq!(agg.apply(joined("b")).is_some(), true);
        assert_eq!(agg.status().helping_now, 2);
        assert_eq!(agg.apply(left("a")), Some(SharingDelta::Left("a".into())));
        assert_eq!(agg.status().helping_now, 1);
        // total distinct sessions seen this run
        assert_eq!(agg.sessions_this_run(), 2);
    }

    #[test]
    fn ignores_unrelated_events_and_unknown_leaves() {
        let mut agg = Aggregator::new();
        assert_eq!(agg.apply(PoolEvent { slot: 0, event: SupervisorEvent::AttemptStarted { attempt: 1 } }), None);
        assert_eq!(agg.apply(left("nope")), None); // leave for a session we never saw
        assert_eq!(agg.status().helping_now, 0);
    }
}
```

- [ ] **Step 2: Run it, expect FAIL** (`cargo test -p spark-sharing aggregate` — `Aggregator` undefined).

- [ ] **Step 3: Implement `Aggregator`** (geo is filled in Task 3.2 — for now `PeerView.geo` is always `None`):
```rust
use std::collections::HashMap;
use lantern_unbounded::supervisor::{PoolEvent, SupervisorEvent};

#[derive(Debug, Clone, PartialEq)]
pub struct Geo { pub country_code: String, pub lat: f64, pub lon: f64 }

#[derive(Debug, Clone, PartialEq)]
pub struct PeerView { pub session_id: String, pub geo: Option<Geo> }

#[derive(Debug, Clone, PartialEq)]
pub struct SharingStatus { pub helping_now: usize, pub peers: Vec<PeerView> }

#[derive(Debug, Clone, PartialEq)]
pub enum SharingDelta { Joined(PeerView), Left(String) }

/// Folds the per-slot supervisor event stream into a live per-session view.
#[derive(Default)]
pub struct Aggregator {
    live: HashMap<String, Option<Geo>>,
    sessions_this_run: u64,
}

impl Aggregator {
    pub fn new() -> Self { Self::default() }

    /// Apply one pool event; returns a delta the caller should act on (bump the
    /// persisted counter on `Joined`, re-emit the snapshot on either), or `None`.
    pub fn apply(&mut self, ev: PoolEvent) -> Option<SharingDelta> {
        match ev.event {
            SupervisorEvent::PeerConnected { session_id, .. } => {
                if self.live.contains_key(&session_id) { return None; }
                self.live.insert(session_id.clone(), None);
                self.sessions_this_run += 1;
                Some(SharingDelta::Joined(PeerView { session_id, geo: None }))
            }
            SupervisorEvent::PeerDisconnected { session_id } => {
                if self.live.remove(&session_id).is_some() {
                    Some(SharingDelta::Left(session_id))
                } else { None }
            }
            _ => None,
        }
    }

    pub fn status(&self) -> SharingStatus {
        let peers = self.live.iter()
            .map(|(id, geo)| PeerView { session_id: id.clone(), geo: geo.clone() })
            .collect();
        SharingStatus { helping_now: self.live.len(), peers }
    }

    pub fn sessions_this_run(&self) -> u64 { self.sessions_this_run }
}
```

- [ ] **Step 4: Run tests, expect PASS.** `cargo test -p spark-sharing aggregate`.
- [ ] **Step 5: Gate + commit.** `cargo fmt --all && cargo clippy --all-targets --locked -- -D warnings` in `spark-sharing/`.
```bash
git add spark-sharing/src/aggregate.rs spark-sharing/src/lib.rs
git commit -m "spark-sharing: Aggregator folds per-peer events into a live view"
```

---

## Phase 3 — geo service

### Task 3.1: `geo.rs` — resolver with cache + graceful failure

**Files:**
- Create: `spark-sharing/src/geo.rs` (move the `Geo` struct here from `aggregate.rs`; `aggregate.rs` re-imports it via `use crate::geo::Geo;`)
- Modify: `spark-sharing/src/lib.rs` (`mod geo; pub use geo::{Geo, GeoResolver};`), `spark-sharing/src/aggregate.rs` (`use crate::geo::Geo;`, delete the local `Geo`)
- Test: inline tests in `geo.rs`

- [ ] **Step 1: Verify the fetch stack.** Confirm how `spark-sharing`/`spark-core` already makes an outbound HTTPS GET (the crate depends on `spark-core` with the `config-fetch`/kindling stack). Reuse that client to GET `https://geo.getiantem.org/lookup/<ip>`; record the exact client type/call before coding. If no reusable client is exposed, add a minimal `boring`+`hyper`-free GET via the existing `FreddieSignaler`-style raw TLS path already in `spark-sharing/src/freddie.rs` (it has a bounded HTTP/1.1 client — factor a tiny `get_json(url)` helper from it rather than adding `reqwest`).

- [ ] **Step 2: Write the failing test** (cache + parse; no network in the unit test — inject a fetch fn):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn caches_and_parses() {
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c = calls.clone();
        // fetch_fn returns the raw geo-service JSON body for an IP
        let resolver = GeoResolver::with_fetcher(move |_ip| {
            c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async { Ok::<_, GeoError>(r#"{"country":{"iso_code":"IR"},"location":{"latitude":35.7,"longitude":51.4}}"#.to_string()) })
        });
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        let g = resolver.resolve(ip).await;
        assert_eq!(g, Some(Geo { country_code: "IR".into(), lat: 35.7, lon: 51.4 }));
        let _ = resolver.resolve(ip).await; // second call hits cache
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn resolve_none_on_fetch_error() {
        let resolver = GeoResolver::with_fetcher(|_ip| Box::pin(async { Err(GeoError::Fetch("boom".into())) }));
        assert_eq!(resolver.resolve(IpAddr::V4(Ipv4Addr::LOCALHOST)).await, None);
    }
}
```

- [ ] **Step 3: Run it, expect FAIL** (`GeoResolver` undefined).

- [ ] **Step 4: Implement `GeoResolver`** — a `resolve(IpAddr) -> Option<Geo>` that checks an in-memory `Mutex<HashMap<IpAddr, Geo>>` cache (lock released before `.await` — do NOT hold across the fetch), calls the injected/default fetcher, parses the geo-service JSON (`country.iso_code`, `location.latitude/longitude`), inserts on success, returns `None` on any error (network/parse). Provide `GeoResolver::new()` (uses the real GET from Step 1) and `GeoResolver::with_fetcher(f)` for tests. `#[derive(thiserror::Error)] enum GeoError { Fetch(String), Parse(String) }`. Fetcher type: `Fn(IpAddr) -> Pin<Box<dyn Future<Output = Result<String, GeoError>> + Send>> + Send + Sync`.

- [ ] **Step 5: Run tests, expect PASS.**
- [ ] **Step 6: Gate + commit.**
```bash
git add spark-sharing/src/geo.rs spark-sharing/src/lib.rs spark-sharing/src/aggregate.rs
git commit -m "spark-sharing: geo resolver (Lantern geo service + per-process cache)"
```

### Task 3.2: Wire geo into the aggregator delta path

**Files:** Modify: `spark-sharing/src/aggregate.rs` (+ tests)

- [ ] **Step 1: Write the failing test** — an async `apply_with_geo` that, on `PeerConnected { remote: Some(ip) }`, resolves geo before emitting `Joined`:
```rust
#[tokio::test]
async fn joined_carries_resolved_geo() {
    let resolver = crate::geo::GeoResolver::with_fetcher(|_| Box::pin(async {
        Ok::<_, crate::geo::GeoError>(r#"{"country":{"iso_code":"IR"},"location":{"latitude":1.0,"longitude":2.0}}"#.to_string())
    }));
    let mut agg = Aggregator::new();
    let ev = PoolEvent { slot: 0, event: SupervisorEvent::PeerConnected {
        session_id: "a".into(), remote: "203.0.113.5:443".parse().ok() } };
    let delta = agg.apply_with_geo(ev, &resolver).await;
    assert_eq!(delta, Some(SharingDelta::Joined(PeerView {
        session_id: "a".into(),
        geo: Some(crate::geo::Geo { country_code: "IR".into(), lat: 1.0, lon: 2.0 }) })));
}
```

- [ ] **Step 2: Run it, expect FAIL** (`apply_with_geo` undefined).

- [ ] **Step 3: Implement `apply_with_geo(&mut self, ev, resolver) -> Option<SharingDelta>`** — same logic as `apply`, but for a new `PeerConnected` with `remote: Some(addr)`, call `resolver.resolve(addr.ip()).await`, store the geo in `self.live` and include it in the emitted `PeerView`. Keep the sync `apply` (geo `None`) for the pure unit tests. (The plugin uses `apply_with_geo`.)

- [ ] **Step 4: Run tests, expect PASS. Step 5: gate + commit.**
```bash
git add spark-sharing/src/aggregate.rs
git commit -m "spark-sharing: resolve peer geo on join"
```

---

## Phase 4 — plugin: commands, persistence, tray

### Task 4.1: Persist keys + accessors (opt-in defaults)

**Files:** Modify: `gui-tauri/tauri-plugin-spark-vpn/src/persist.rs` (+ its tests). Follow the EXACT pattern of the existing `load_split_tunnel`/`save_split_tunnel` (read/write a file under the plugin `base` dir).

- [ ] **Step 1: Write failing tests** mirroring existing persist tests — round-trip each key; assert the **defaults** when unset: `unbounded_auto_enable` → `false`, `unbounded_hidden` → `false`, `unbounded_welcome_seen` → `false`, `unbounded_enabled` → `false`, `unbounded_total_helped` → `0`.
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement** `load_/save_` pairs for the five keys, matching the file-per-setting pattern already in `persist.rs` (bool as `"true"/"false"`, u64 as decimal text; missing file → default).
- [ ] **Step 4: Run, expect PASS. Step 5: gate + commit** (`cargo fmt`+`clippy` in the plugin workspace).
```bash
git add gui-tauri/tauri-plugin-spark-vpn/src/persist.rs
git commit -m "plugin: persist unbounded settings + cumulative counter (opt-in defaults)"
```

### Task 4.2: `unbounded.rs` module — control + aggregation loop + `spark://unbounded`

**Files:**
- Create: `gui-tauri/tauri-plugin-spark-vpn/src/unbounded.rs`
- Modify: `gui-tauri/tauri-plugin-spark-vpn/src/lib.rs` (`mod unbounded;`, register commands, manage state)

- [ ] **Step 1: Verify the config source.** Confirm where `SharingConfig` inputs come from: inspect `core/src/config/lantern.rs` + a sample `config_raw.json` for an `unbounded`/sharing block (egress WS URL, Freddie signaling endpoint, STUN URLs) and a `features`/`Features.unbounded` flag. Record the exact keys. (If absent from the current config, Phase 7 Task 7.1 adds the mapping; for now, gate `unbounded_start` to return a typed `Error::Platform("unbounded config unavailable")` when the config block is missing.)

- [ ] **Step 2: Write the failing (host) test** for the pure aggregation-loop glue: a `fn on_delta(total: &mut u64, delta: &SharingDelta)` that increments `total` only on `Joined`. Test: two `Joined` + one `Left` → total = 2.
- [ ] **Step 3: Run, expect FAIL.**
- [ ] **Step 4: Implement the module:**
  - `struct UnboundedState { handle: Mutex<Option<SharingHandle>> }` managed via `app.manage`.
  - `unbounded_start(app)`: build `SharingConfig` from config (Step 1); construct `FreddieSignaler`; create an `mpsc::UnboundedChannel<PoolEvent>`; `let handle = start_sharing(cfg, signaler, Some(tx))`; store `handle`; spawn a task that owns an `Aggregator` + `GeoResolver`, loops `while let Some(ev) = rx.recv().await`, calls `agg.apply_with_geo(ev, &resolver).await`, and on each `Some(delta)`: if `Joined`, `total = load_total()+1; save_total(total)`; then `emit_snapshot(app, enabled=true, agg.status(), total)`. Persist `unbounded_enabled=true`.
  - `emit_snapshot` builds the `spark://unbounded` JSON (see contract) and `app.emit("spark://unbounded", payload)`; also calls the tray refresh (Task 4.3).
  - `unbounded_stop(app)`: take + drop the handle (cooperative cancel via `Drop` — do NOT abort), persist `unbounded_enabled=false`, emit a snapshot with `enabled=false, helpingNow=0, peers=[]` (keep `totalHelped`).
  - `unbounded_status(app) -> serde_json::Value`: `{ enabled, helpingNow, totalHelped, peers }` from current state (helpingNow/peers `0/[]` when stopped).
  - `unbounded_get_settings`/`unbounded_set_settings`: read/write `auto_enable`, `hidden`, `welcome_seen` via persist.
  - Use `thiserror`/`crate::Error`; no `unwrap` outside tests; the spawned task's `JoinHandle` is stored in state so `unbounded_stop`/drop can abort the loop.

- [ ] **Step 5:** register the six commands in `lib.rs` `invoke_handler!` and `app.manage(UnboundedState::default())` in `setup`.
- [ ] **Step 6: Run the host test + build the plugin** (`cargo build`, `cargo test`, gate). Expected: PASS/clean.
- [ ] **Step 7: Commit.**
```bash
git add gui-tauri/tauri-plugin-spark-vpn/src/unbounded.rs gui-tauri/tauri-plugin-spark-vpn/src/lib.rs
git commit -m "plugin: unbounded module (start/stop/status/settings + spark://unbounded)"
```

### Task 4.3: Tray status + toggle; startup auto-enable (gated, default-off)

**Files:** Modify: `gui-tauri/tauri-plugin-spark-vpn/src/tray.rs`, `src/lib.rs`

- [ ] **Step 1: Write a failing pure-helper test** in `tray.rs`: `fn unbounded_tray_label(enabled: bool, helping_now: usize) -> String` → `"Unbounded: off"` when disabled, `"Unbounded: helping 9"` when enabled with 9. (Mirrors the existing tray view-model helpers from #81.)
- [ ] **Step 2: Run, expect FAIL. Step 3: implement the helper.** **Step 4: run, PASS.**
- [ ] **Step 5: Wire it in** — add an "Unbounded" status line + enable/disable `MenuItem` to the tray build (following the existing tray menu construction), dispatch the menu event to `unbounded_start/stop`, and have `emit_snapshot` (Task 4.2) refresh the tray label. In `lib.rs` `setup`, after building control: if `load_unbounded_auto_enable(base)` AND the server flag allows (Phase 7 provides the flag; until then treat missing config as "not allowed"), call `unbounded_start` detached. (Default-off means this is a no-op until the user opts in.)
- [ ] **Step 6: Build + gate + commit.**
```bash
git add gui-tauri/tauri-plugin-spark-vpn/src/tray.rs gui-tauri/tauri-plugin-spark-vpn/src/lib.rs
git commit -m "plugin: tray Unbounded status + toggle; gated startup auto-enable"
```

---

## Phase 5 — UI: backend seam, tab, screen, onboarding, settings

### Task 5.1: Backend seam (`unbounded*` methods + types)

**Files:** Modify: `gui-tauri/src/lib/spark_backend.ts` (interface + `UnboundedStatus`/`UnboundedSettings` types + `MockBackend`), `gui-tauri/src/lib/tauri_backend.ts` (invoke). Follow the exact split-tunnel/routing seam pattern.

- [ ] **Step 1: Write a failing vitest** (`gui-tauri/src/lib/spark_backend.test.ts` or the existing seam test file): `MockBackend.unboundedStatus()` returns `{ enabled:false, helpingNow:0, totalHelped:0, peers:[] }`; `unboundedStart()` flips `enabled` to true and `unboundedStatus()` then reflects it; `unboundedGetSettings()` returns `{ autoEnable:false, hidden:false, welcomeSeen:false }`.
- [ ] **Step 2: Run, expect FAIL** (`npm run test` in `gui-tauri`).
- [ ] **Step 3: Implement** the `UnboundedStatus`/`UnboundedSettings` TS types, add `unboundedStart/Stop/Status/GetSettings/SetSettings` to the `SparkBackend` interface, implement in `TauriBackend` (`invoke("plugin:spark-vpn|unbounded_*")`) and in `MockBackend` (in-memory, with a simulated peer stream that increments `helpingNow`/`totalHelped` on a timer so the globe is dev-testable).
- [ ] **Step 4: Run, PASS. Step 5: commit.**
```bash
git add gui-tauri/src/lib/spark_backend.ts gui-tauri/src/lib/tauri_backend.ts gui-tauri/src/lib/spark_backend.test.ts
git commit -m "ui: unbounded backend seam (Tauri + Mock)"
```

### Task 5.2: `VPN | Unbounded` tab in the shell (gated)

**Files:** Modify: the shell/home layout that renders the top tab (per Figma; the same file that renders the VPN home header). Add a small `unboundedVisible(featureFlag, hidden)` helper.

- [ ] **Step 1: Write a failing vitest** for `unboundedVisible(serverEnabled: boolean, hidden: boolean)` → `true` only when `serverEnabled && !hidden`.
- [ ] **Step 2: Run FAIL → Step 3: implement helper → Step 4: run PASS.**
- [ ] **Step 5: Render the tab** — add the `VPN | Unbounded` switcher (Figma `Desktop / Main / Unbounded`), shown only when `unboundedVisible`, with a live green dot bound to `unboundedStatus().enabled`; navigate to `/unbounded`. Subscribe to `spark://unbounded` to keep the dot live. Manual-verify with `npm run tauri dev`.
- [ ] **Step 6: Commit.**
```bash
git add gui-tauri/src/lib/... gui-tauri/src/routes/...
git commit -m "ui: VPN|Unbounded tab (gated on server flag + hidden)"
```

### Task 5.3: `/unbounded` screen — stats + toggle + onboarding + auto-enable

**Files:**
- Create: `gui-tauri/src/routes/unbounded/+page.svelte`
- Modify: i18n locale JSON (new keys: `unbounded_title`, `unbounded_help_banner`, `unbounded_status`, `unbounded_helping_now`, `unbounded_total_helped`, `unbounded_auto_enable`, `unbounded_auto_enable_sub`, `unbounded_welcome_title`, `unbounded_welcome_body`) — copy from the Figma/onboarding text.

- [ ] **Step 1:** Build the screen per Figma (`Desktop / Unbounded` 4734:5498): info banner, a `<Globe>` placeholder (filled in Phase 6), `Status: Enabled` toggle bound to `unboundedStart/Stop`, `People you are helping right now` + `Total people helped to date` bound to the `spark://unbounded` snapshot (poll `unboundedStatus()` on mount + subscribe to the event), and the `Auto-enable Unbounded` checkbox bound to `unboundedGetSettings/SetSettings`. All strings via `$_()` + logical CSS (per the i18n conventions).
- [ ] **Step 2:** Onboarding — on first visit, if `!welcomeSeen`, show the "Welcome to Unbounded" dialog with the digital-bridges copy; on dismiss, `unboundedSetSettings({ welcomeSeen: true })`.
- [ ] **Step 3:** i18n key-coverage test must pass (the existing guard). Run `npm run test`.
- [ ] **Step 4:** Manual-verify against `MockBackend` (`npm run dev`): toggle flips, stats tick up via the mock peer stream, onboarding shows once.
- [ ] **Step 5: Commit.**
```bash
git add gui-tauri/src/routes/unbounded/+page.svelte gui-tauri/src/lib/i18n/... 
git commit -m "ui: /unbounded screen (stats, toggle, onboarding, auto-enable)"
```

### Task 5.4: Unbounded settings screen

**Files:** Create: `gui-tauri/src/routes/settings/unbounded/+page.svelte`; Modify: the settings hub route (add an "Unbounded" row, shown only when `unboundedVisible`).

- [ ] **Step 1:** Two toggles — `Auto-enable Unbounded` + `Hide Unbounded` — bound to `unboundedGetSettings/SetSettings`. Setting `hidden=true` removes the tab (via `unboundedVisible`).
- [ ] **Step 2:** i18n keys + key-coverage test. **Step 3:** manual verify. **Step 4: commit.**
```bash
git add gui-tauri/src/routes/settings/unbounded/+page.svelte gui-tauri/src/routes/settings/+page.svelte gui-tauri/src/lib/i18n/...
git commit -m "ui: Unbounded settings (auto-enable, hide)"
```

---

## Phase 6 — the globe

### Task 6.1: `Globe.svelte` — base sphere + live arcs, perf-guarded

**Files:** Create: `gui-tauri/src/lib/Globe.svelte`; Modify: `gui-tauri/src/routes/unbounded/+page.svelte` (mount `<Globe {peers} />`), `gui-tauri/package.json` (globe lib dep).

- [ ] **Step 1: Choose + verify the library.** Evaluate `globe.gl`/`three-globe` (three.js) for a Svelte-friendly, tree-shakeable globe with great-circle arcs; confirm bundle-size impact against the `size budget` CI job. Record the chosen lib + the arcs API before coding. (This is the one frontend-design choice deferred from the spec.)
- [ ] **Step 2: Implement** a `<Globe peers={PeerView[]}>` component: render a base sphere with the Spark styling; for each peer with `geo`, draw a great-circle arc from a fixed home point to `{geo.lat, geo.lon}`. **Perf (Lantern's #1 hotspot):** static at rest (no continuous rotation); rotate-to/animate an arc only when a new peer appears (diff the `peers` prop); **pause the render loop when the tab isn't visible** (`IntersectionObserver` on the canvas + `document.visibilitychange`); cap rendered arcs (e.g. 50); clear all arcs when `peers` goes empty (toggle-off).
- [ ] **Step 3:** Manual-verify with `MockBackend` — arcs appear/animate on simulated joins, settle static, disappear on leave, and the globe stops repainting when you switch to the VPN tab (verify via devtools frame profiler).
- [ ] **Step 4:** Re-run the `size budget` gate locally if available; keep the added JS within budget.
- [ ] **Step 5: Commit.**
```bash
git add gui-tauri/src/lib/Globe.svelte gui-tauri/src/routes/unbounded/+page.svelte gui-tauri/package.json gui-tauri/package-lock.json
git commit -m "ui: Unbounded globe with live arcs (static, animate-on-arrival, pause off-tab)"
```

---

## Phase 7 — config plumbing, gate, end-to-end

### Task 7.1: Map the Lantern config → `SharingConfig` + `Features.unbounded`

**Files:** Modify: `core/src/config/lantern.rs` (+ tests); `gui-tauri/tauri-plugin-spark-vpn/src/unbounded.rs` (consume it)

- [ ] **Step 1: Confirm the real keys** against a live `config_raw.json` (the sharing egress/signaling/STUN block + the `Features.unbounded` boolean). If the config server doesn't yet deliver them, coordinate the field names with the lantern-cloud config (out of this repo) and use those names.
- [ ] **Step 2: Write a failing test** in `lantern.rs`: parse a fixture `config_raw.json` containing the unbounded block → assert a `SharingConfig`-shaped struct (egress_url, stun_urls, signaling endpoint) + `features.unbounded == true`.
- [ ] **Step 3: Run FAIL → Step 4: implement the parse/mapping → Step 5: run PASS** (whole-workspace: `bin/testsetup`-style or `cargo test -p spark-core`).
- [ ] **Step 6:** In `unbounded.rs`, replace the Step-1 stub from Task 4.2 with the real config read; refuse `unbounded_start` (typed error) + hide the tab when `features.unbounded` is false or the block is missing. Thread the flag to the UI via `unbounded_status`/a `spark://unbounded` field or a dedicated `unbounded_available` command consumed by `unboundedVisible`.
- [ ] **Step 7: Commit.**
```bash
git add core/src/config/lantern.rs gui-tauri/tauri-plugin-spark-vpn/src/unbounded.rs
git commit -m "config: map unbounded sharing settings + Features.unbounded gate"
```

### Task 7.2: Whole-workspace gate + desktop end-to-end verification

- [ ] **Step 1:** Run the full gates: `cargo fmt --all --check` + `cargo clippy --workspace --all-targets --all-features -- -D warnings` (root), the `spark-sharing` gate, the plugin gate, and `gui-tauri` `npm run test` + type-check.
- [ ] **Step 2: Desktop end-to-end** (build a dev/DMG per `packaging/macos/build-tauri-dmg.sh` or `npm run tauri dev`): opt in (default was off) → onboarding shows once → toggle Unbounded on → confirm `helping now` + globe arcs update against a real or simulated peer → close the window → tray shows "Unbounded: helping N" and sharing keeps running → toggle off → live set + arcs clear → reopen, confirm `total helped` persisted across restart → set Hide Unbounded → tab disappears.
- [ ] **Step 3:** Update `docs/STATE.md` with the shipped state. **Step 4: open the PR** (`gh pr create` base `main`), run the review loop, merge when green.
```bash
git add docs/STATE.md
git commit -m "unbounded: desktop v1 end-to-end verified + STATE"
```

---

## Self-review notes (author)

- **Spec coverage:** runtime in-app/tray (Tasks 4.2/4.3), per-peer upstream events (1.1), aggregation (2.1/3.2), geo via Lantern service (3.1), plugin commands+persist+push (4.1/4.2), tray (4.3), tab+stats+onboarding+settings (5.2–5.4), globe (6.1), server gate + config (7.1), strict opt-in defaults (4.1 defaults + 4.3 gated startup), e2e (7.2) — all mapped.
- **Deferred-to-verification (not placeholders):** the WebRTC selected-pair API (1.1 Step 1), the geo fetch client (3.1 Step 1), the globe library (6.1 Step 1), and the exact Lantern config keys (4.2 Step 1 / 7.1 Step 1) — each is an explicit verify-then-implement step because it depends on an external API/live config, per CLAUDE.md's verification discipline.
- **Type consistency:** `Geo`/`PeerView`/`SharingStatus`/`SharingDelta`/`Aggregator` + the `spark://unbounded` JSON + the five persist keys are used identically across Phases 2–7.
