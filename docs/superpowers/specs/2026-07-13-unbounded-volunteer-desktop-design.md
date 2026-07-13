# Unbounded volunteer (uncensored-user) experience — Design (desktop v1)

**Status:** approved design, ready for implementation-plan
**Date:** 2026-07-13
**Builds on:** the merged `spark-sharing` crate (#83/#87), the desktop system tray (#81), and the shared SvelteKit UI shell.
**Figma:** Lantern-VPN `node-id=2403-19287` (frames `Desktop / Main / Unbounded` 4734:5499, `Desktop / Unbounded` 4734:5498, `Welcome to Unbounded` dialog 2486:35447, Unbounded settings).
**Prior art:** `getlantern/lantern` branches `fisk/unbounded-tab` (authoritative), `fisk/share-my-connection-ux`, `adam/atavism/unbounded-widget-proxy` (webview approach — tried and abandoned).

## 1. Goal

Let an **uncensored volunteer** turn their device into a "digital bridge": Spark runs the `spark-sharing` peer-proxy so censored users can relay through it. Ship a first-class **Unbounded** tab (globe + live stats + toggle), desktop-first, **strictly opt-in**.

## 2. Scope & decisions (locked)

- **Platforms:** desktop only for v1 (macOS/Windows/Linux). Mobile deferred (Android = future foreground service; iOS = the hard NE/foreground call, out of scope now).
- **Consent:** **strict opt-in** — sharing is OFF by default; the user must explicitly enable it after seeing the "Welcome to Unbounded" explainer. This is deliberately more conservative than Lantern's default (auto-enable = on).
- **Globe:** in v1 — full globe with live connection arcs. This requires new per-peer telemetry upstream (see §4.1).
- **Server gate:** the entire Unbounded UI surface is gated on a server `Features.unbounded` flag (regional control / plausible deniability), matching Lantern.
- **Runtime:** **unprivileged, in the Tauri app process**; the **tray** keeps it alive when the window is closed. No NE, no privileged service — sharing is outbound-only and needs no TUN/routes. (Prior art: Lantern's webview "widget-proxy" was abandoned in favor of in-process; our tray gives a cleaner always-on story than Lantern had.)

## 3. Non-goals (v1)

- Mobile (Android/iOS) volunteer sharing.
- The "Share My Connection" residential-IP proxy mode (Lantern's higher-risk SmC path with its own legal disclosure). We ship only the p2p Unbounded/broflake path, which needs no residential-IP disclosure.
- Precise geolocation guarantees — arcs are approximate. IP geolocation is region-level at best and reflects the peer's network egress, not a precise location. UI copy must not overclaim.

## 4. Architecture — one vertical slice, five layers

Data flow: `unbounded-rs` per-peer event → `spark-sharing` aggregates + geo-resolves → plugin emits a `spark://unbounded` snapshot → SvelteKit renders stats + globe; the tray mirrors the live count.

### 4.1 `unbounded-rs` (upstream Rust crate) — new per-peer telemetry

Today `SupervisorEvent` is **per-slot** (`AttemptStarted` / `SessionEnded{outcome: PeerProxyOutcome{consumer_session_id, relay_end, relay_duration}}` / `AttemptFailed` / `Stopped`) and exposes **no peer address**. The globe and an accurate "helping now" need a **per-peer connection signal**.

Add to `peer_proxy.rs` / `supervisor.rs` two new `SupervisorEvent` variants (carried through the existing `PoolEvent{slot, event}` channel):

- `PeerConnected { slot, session_id: String, remote: Option<SocketAddr> }` — emitted when the WebRTC connection reaches the connected state (read `remote` from the selected ICE candidate pair; `None` if unavailable).
- `PeerDisconnected { slot, session_id: String }` — emitted when that connection closes.

`session_id` = `consumer_session_id` (stable per censored session; the dedup key). `remote` feeds geo. This is an additive, backward-compatible change to a crate **we own** (github.com/getlantern/unbounded-rs); existing consumers ignore the new variants. Unit-tested in `unbounded-rs` with a mock WebRTC connection.

### 4.2 `spark-sharing` crate — volunteer runtime + telemetry aggregation

Already provides `start_sharing(config, signaler, events) -> SharingHandle` (`cancel`/`wait`/`stop`, cooperative-cancel `Drop`). Add:

- **`SharingStatus` aggregation:** consume the `PoolEvent` stream; maintain `helping_now` as a **refcount keyed by `session_id`** (`PeerConnected` → insert, `PeerDisconnected` → remove; ignore duplicate connects for the same session). `total_helped` is a monotone counter incremented once per **new** `session_id` first seen. (Semantics: "sessions served," honest and close to Lantern's unique-peer model. The plugin owns durable persistence of `total_helped`; the crate reports the in-run delta + current live set.)
- **Geo enrichment (`spark-sharing/src/geo.rs`):** resolve `remote` IP → `{ country_code, lat, lon }` via **Lantern's own geo service** (`https://geo.getiantem.org/lookup/<ip>`, fetched with the crate's existing kindling/boring stack — never a third party), cached per-process (stable IP→country). On failure or `remote: None`, fall back to no-arc (stats still count). Peer IPs never leave Lantern infra.
- **Outward event/snapshot API:** expose a `SharingStatus { enabled, helping_now, peers: Vec<PeerView{ session_id, geo: Option<Geo> }> }` snapshot + a change stream the plugin can subscribe to.

### 4.3 Plugin + desktop wiring (`tauri-plugin-spark-vpn`, new `unbounded` module)

Sharing lives in the existing plugin (it already owns the app-process control seam, `persist`, and tray) as a dedicated `unbounded.rs` module — kept clearly separate from the VPN control path.

- **Commands:** `unbounded_start`, `unbounded_stop`, `unbounded_status`, `unbounded_get_settings`, `unbounded_set_settings`.
- **Runtime:** `unbounded_start` builds `SharingConfig` from the Lantern config (§4.6), constructs a `FreddieSignaler`, calls `start_sharing`, and holds the `SharingHandle` in plugin state. `unbounded_stop` drops/`cancel`s it.
- **Persistence (reuse `persist`):** `unbounded_enabled` (resume last state), `unbounded_auto_enable` (**default false**), `unbounded_hidden` (default false), `unbounded_welcome_seen` (default false), `unbounded_total_helped` (u64, **cumulative, never reset**, seeded on start, incremented per new `session_id`).
- **Live push:** emit `spark://unbounded { enabled, helpingNow, totalHelped, peers:[{geo}] }` on every change (mirrors `spark://servers`/`spark://state`).
- **Tray (#81):** show "Unbounded: helping N" + an enable/disable item; keep sharing running when the window is closed; reflect live count. This is the desktop always-on mechanism.
- **Startup auto-enable:** in `setup`, if `unbounded_auto_enable` is set (and the server flag allows), start sharing detached (same pattern as the Phase-2a config fetch) — but default-off means this does nothing until the user opts in.

### 4.4 Geo — see §4.2 (lives in `spark-sharing`, consumed by the plugin telemetry).

### 4.5 SvelteKit UI (`gui-tauri/src`)

- **Top tab `VPN | Unbounded`** in the shell (matches Figma), shown only when `Features.unbounded` (server) AND not `unbounded_hidden`. The Unbounded tab shows a persistent status dot (green when sharing) even from the VPN tab.
- **`/unbounded` route** (`routes/unbounded/+page.svelte`): info banner ("Help others bypass censorship by securely sharing your connection."), the **globe**, `Status: Enabled` toggle, `People you are helping right now`, `Total people helped to date`, and the `Auto-enable Unbounded` checkbox.
- **Globe component (`lib/Globe.svelte`):** a WebGL globe (three-globe/globe.gl class library — exact choice in the plan per frontend-design) drawing a base sphere + a great-circle arc per live peer (from `peers[].geo`). **Perf, per Lantern's #1 hotspot:** no continuous rotation (static at rest), rotate-to/animate only on a new arc, and **pause rendering when the tab isn't visible** (visibility/IntersectionObserver). Cap concurrent arcs. Clear all arcs on toggle-off.
- **Onboarding:** "Welcome to Unbounded" dialog on first tab visit (`unbounded_welcome_seen`), with the digital-bridges explainer copy from the Figma; sets the flag on dismiss.
- **Unbounded settings** (in the existing settings hub): `Auto-enable Unbounded` + `Hide Unbounded`.
- **Backend seam:** add `unbounded*` methods to `spark_backend.ts` (interface), `tauri_backend.ts` (invoke), and `MockBackend` (dev/web) — a mock peer stream so the globe/stats are developable without a live network.

### 4.6 Config & gating

- `SharingConfig` inputs (egress WebSocket URL, Freddie signaling endpoint, STUN URLs, `concurrent_sessions`, timeouts) + the `Features.unbounded` gate are sourced from the Lantern config (`config_raw.json` / config-new), mapped in the spark config adapter (`core/src/config/lantern.rs`). **The exact config keys are confirmed against the live Lantern config during planning** (Lantern delivers these via radiance's config; we mirror the field names). If the server omits the config or sets `Features.unbounded=false`, the tab and auto-enable are hidden and start is refused.

## 5. Error handling

- **Start failure** (missing config, signaling unreachable): return an error to the UI, keep the toggle **off**, show an inline message; **preserve `total_helped`** (never wiped by a failed start).
- **Per-slot failures** self-heal via the supervisor's existing backoff/retry — surfaced only as telemetry, not user errors.
- **Geo failure / `remote: None`:** the peer still counts toward stats; it just gets no arc. Never blocks or errors the session.
- **Counter integrity:** `total_helped` is monotone, persisted, and re-seeded from disk on start — cleared only by a full app-data wipe.
- **Teardown:** on disable/drop, cooperative-cancel (NOT abort — abort truncates graceful WebRTC teardown, per the spark-sharing `Drop` contract) and clear the live peer set + globe arcs.

## 6. Testing

- **`unbounded-rs`:** unit-test the new `PeerConnected`/`PeerDisconnected` emission against a mock WebRTC connection (connected → event with remote; close → event).
- **`spark-sharing`:** unit-test aggregation with synthetic `PoolEvent`s — `helping_now` refcount (dup connect ignored, disconnect decrements), `total_helped` increments once per new `session_id` and never decrements; geo cache hit/miss + fallback.
- **Plugin:** host tests for the settings persistence round-trip + the status snapshot shape; auto-enable gating (default-off → no start).
- **Frontend:** `vitest` for the gating logic (server flag + hidden) and stats formatting; component render of `/unbounded` against `MockBackend`; globe smoke render behind the mock.
- **Desktop end-to-end (manual):** opt in → onboarding shows once → toggle on → simulate/real peer → `helping now` + globe arc update → close window, tray shows "helping N" and sharing continues → toggle off tears down cleanly → `total helped` persists across restart.

## 7. Phased implementation

1. **Upstream per-peer events** — add `PeerConnected`/`PeerDisconnected` to `unbounded-rs` (remote addr + session_id, open/close) with tests; bump the pin in `spark-sharing`.
2. **spark-sharing aggregation** — `SharingStatus` (helping-now refcount, total-helped delta, live peer set) + change stream, unit-tested with synthetic events.
3. **Geo service** — `spark-sharing/src/geo.rs` (Lantern geo lookup + per-process cache + fallback), unit-tested.
4. **Plugin + persistence + tray** — `unbounded` module (commands, `SharingConfig` build, handle mgmt), persist keys (opt-in defaults), `spark://unbounded` push, tray status + toggle, startup auto-enable (gated).
5. **UI: tab + stats + onboarding + settings** — `VPN|Unbounded` tab (gated), `/unbounded` route (toggle + stats), Welcome dialog, Unbounded settings, backend seam + MockBackend.
6. **Globe** — `Globe.svelte` with live arcs from `peers[].geo`, static/animate-on-arrival, pause-off-tab, arc cap.
7. **Config plumbing + gate + end-to-end verify** — map the Lantern config keys → `SharingConfig` + `Features.unbounded`; desktop end-to-end verification per §6.

## 8. Key risks

- **Upstream `unbounded-rs` change** (per-peer events): tractable (we own the crate). Arcs/geo are approximate regardless — IP geolocation is region-level and reflects the peer's network egress, not a precise location (we do not use TURN relays). Mitigate with honest UI copy; count stats even when `remote` is `None`.
- **Globe performance:** the biggest Lantern pitfall — mitigated by the static/animate-on-arrival/pause-off-tab pattern and an arc cap.
- **Config key drift:** the sharing config + `Features.unbounded` field names must match what the Lantern config server actually delivers — confirmed against the live config in Phase 7 before shipping.

## 9. File map

**Upstream (`getlantern/unbounded-rs`):** `src/peer_proxy.rs`, `src/supervisor.rs` — new per-peer events.
**Create:** `spark-sharing/src/geo.rs`; `gui-tauri/tauri-plugin-spark-vpn/src/unbounded.rs`; `gui-tauri/src/routes/unbounded/+page.svelte`; `gui-tauri/src/lib/Globe.svelte`.
**Modify:** `spark-sharing/src/lib.rs` (aggregation + status API); `tauri-plugin-spark-vpn/src/{lib.rs,commands.rs,persist.rs,tray.rs}` (commands, persist keys, tray, startup); `gui-tauri/src/lib/{spark_backend.ts,tauri_backend.ts}` + the Mock (seam); `gui-tauri/src/routes/+layout.svelte` / shell (tab); the settings hub route; `core/src/config/lantern.rs` (config → `SharingConfig` + `Features.unbounded`).
**Reuse:** `spark_sharing::{start_sharing, SharingHandle, SharingConfig, FreddieSignaler}`; the plugin's `persist` + tray (#81); the `spark://…` event + backend-seam patterns.
