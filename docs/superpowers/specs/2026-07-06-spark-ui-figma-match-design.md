# Spark Desktop UI — Figma Match (Home + Split Tunneling + Routing Mode, light + dark)

**Date:** 2026-07-06
**Branch:** `fisk/figma-ui-match` (off `main` incl. #49 split tunneling, #50 NE fix)
**Status:** Approved design; ready for implementation planning.

## Goal

Make the Tauri desktop UI (`gui-tauri/`) match the Figma designs exactly, in **both light and
dark** modes, for the **Home** and **Split Tunneling** screens, plus build the **Routing Mode**
screen. Rebrand the wordmark from **LANTERN** to **SPARK**.

Figma (`getlantern/Lantern-VPN`, file `hNlyYToB5TnX9SDBFDYJTq`): Home `4-995` (Pro frame `21:2112`
light / `4654:46429` dark), Routing Mode `4210-34619`, Split Tunneling `30-19175`.

## Decisions (confirmed)

- **Build the Pro Home layout, but the wordmark is just "SPARK"** (no "Pro"). The Pro layout is the
  target because it drops all free-tier chrome — **no Upgrade-to-Pro banner, no Sign-In, no Daily
  Data Usage bar, no Free/Expired/Data-Reached states.** Header shows a hamburger (left), **SPARK**
  wordmark (center), and an account avatar (right); menu + avatar are **inert** for now (no drawer /
  account system designed).
- **Dark mode follows the OS** (`prefers-color-scheme`) — no in-app toggle.
- **Build the Routing Mode screen + wire mode switching** (Smart Routing / Full Tunnel).
- **App-based split tunneling stays deferred** — the Apps row remains present but disabled ("Coming
  soon"); Websites is the working path. (Unchanged from #49.)
- Wordmark is a **text** wordmark (Urbanist bold), not a logo asset.

## Architecture overview

Pure-frontend for theming/rebrand/Home/split-tunnel polish. The Routing Mode feature adds a small
cross-layer backend slice that **mirrors the split-tunnel pattern already in the tree** (control
handle + FFI + NE message + Tauri command + `SparkBackend` seam), so it's well-precedented.

Everything themes off CSS variables in `gui-tauri/src/routes/+layout.svelte`; every screen already
consumes those variables, so adding a dark palette there themes all screens at once.

## 1. Theming — OS-following light/dark

`gui-tauri/src/routes/+layout.svelte` currently defines a single light palette on `:root`. Keep it
(it already matches the Figma light tokens — verified via `get_variable_defs`: `text/primary
#1b1c1d`, `Gray/200 #EDEFEF`, `status/warning-bg-dot #ffc105`, brand `#00bdd6`, `Card Shadow Light
#0061631A`). Add a dark palette that overrides the **same variable names** under
`@media (prefers-color-scheme: dark)`, so no per-screen changes are needed.

Dark values are taken from the Figma dark frames at implementation time (`get_design_context` on
`4654:46429` / the dark split-tunnel frames). Expected mapping (exact hexes pulled at impl):
`--bg` near-black, `--surface` slightly-elevated dark, `--text-primary` near-white,
`--text-secondary`/`--text-tertiary` lighter grays, `--border` a dark hairline, `--brand` `#00bdd6`
(unchanged), `--bolt` `#ffc105` (unchanged), `--shadow` a deeper/none shadow. A small set of
hardcoded colors in existing components (e.g. the split-tunnel `.snack` `#23282b`, the toggle
`.switch` off-color `#c8ccce`) are audited and moved onto variables so they theme too.

## 2. Rebrand LANTERN → SPARK

- The Home header wordmark renders **SPARK** (Urbanist 700). No "PRO".
- Grep `gui-tauri/src` for user-facing "Lantern" strings and swap to "Spark". Code comments that
  cite Lantern's design source (`app_colors.dart`, etc.) may remain — they document provenance.

## 3. Home — Pro layout (`gui-tauri/src/routes/+page.svelte` redesign)

Replace the current home body with the Figma Pro layout, reusing the existing `SparkBackend`
(`status`/`connect`/`disconnect`, plus `getSplitTunnel` for the row):

- **Header:** hamburger icon (left, inert), **SPARK** wordmark (center, Urbanist 700), account-avatar
  icon (right, inert). Bottom hairline border.
- **Connect control:** the large centered pill toggle (Figma), driven by `status.state`
  (disconnected/connecting/connected) + `connect()`/`disconnect()`; teal (`--brand`) when
  on/connected, grey when off; status text below reflects the state.
- **Status card** (bottom, elevated `--surface`): four rows matching Figma —
  - **VPN Status** — globe icon, "Connected"/"Connecting…"/"Not Connected" + a state dot.
  - **Smart Location** — pin icon, current location + bolt (auto) → `goto("/servers")`.
  - **Routing Mode** — route icon, current mode ("Smart Routing"/"Full Tunnel") → `goto("/routing")`.
  - **Split Tunneling** — branch icon, "Enabled"/"Disabled" → `goto("/split-tunneling")`.
- No free-tier chrome. Match Figma spacing/type/iconography (icons already exist as inline SVG
  snippets; adjust to the Figma glyphs where they differ).

Rows/values poll on the existing interval (as the current home already does for split-tunnel state);
add routing-mode to that poll.

## 4. Routing Mode — screen + backend

### Screen (`gui-tauri/src/routes/routing/+page.svelte`, new)
Per Figma `4210-34619`: appbar "Routing Mode" + back → `/`; a card with two radio rows — **Smart
Routing** ("Rule-based routing optimized for your region") and **Full Tunnel** ("Routes all traffic
through VPN"); an info **Note** ("Smart Routing uses region-specific rules … all other traffic goes
direct for speed and reliability."). Light + dark. Selecting a mode calls the backend and pops home.

### Backend (mirrors the split-tunnel slice)
- **core `RoutingMode`** (`core/src/routing_mode.rs` or fold into `split_tunnel`/config): an enum
  `Smart | Full`, serde, default `Smart`.
- **`Router`** gains a `mode: RwLock<RoutingMode>` (live-swappable, same pattern as `user_bypass`).
  `decide` semantics:
  - user bypass matches → `Direct` (unchanged, absolute).
  - **Full**: skip the base matcher's Direct/Proxy result and return `Proxy` for everything else —
    **but still honor ad-block `Reject`** from the base matcher (blocking is orthogonal to
    tunnel-vs-direct). Implement as: consult base; if base says `Reject`, return `Reject`; otherwise
    `Proxy`.
  - **Smart**: today's behavior (base matcher decides; unmatched → Proxy).
  - `set_mode(&self, RoutingMode)` swaps it live (poison-tolerant `into_inner`, like `set_user_bypass`).
- **`fd_tunnel`**: `set_routing_mode(json_or_str) -> bool` on the active-router handle (mirrors
  `set_split_tunnel`); thread an initial mode from `run_fd_dispatch` into `setup_routing_and_udp`
  (activate the router path if mode is set, same as bypass).
- **FFI (mirror split-tunnel exactly — parallel, not combined):** Apple C-ABI
  `spark_set_routing_mode` + a `routing_mode` connect arg on `spark_tunnel_run`; Android JNI
  `nativeSetRoutingMode` + a `nativeRun` arg; macOS NE reads `providerConfiguration["routingMode"]`
  at start + a `handleAppMessage` `"routingMode"` case. (A future refactor could fold `splitTunnel`
  + `routingMode` into one "routing config" JSON if the arg list grows; out of scope here — keep it
  a parallel slice so the diff is small and the pattern is identical to #49.)
- **Tauri**: `spark_get_routing_mode` / `spark_set_routing_mode` commands (persist to the per-OS
  config dir like the split-tunnel list; inject at connect; live-push when connected).
- **`SparkBackend`** seam: `getRoutingMode(): Promise<"smart"|"full">` /
  `setRoutingMode(m): Promise<void>` (Mock + Tauri).

**Semantic to confirm during review:** Full Tunnel = all non-bypassed flows Proxy, ad-block Reject
still honored, split-tunnel bypass still Direct. (Flagged in #49's spec style.)

## 5. Split Tunneling — exact-match pass

The toggle / Apps / Websites screens (from #49) already follow the Figma flow. This pass:
- Verifies they match the Figma pixel-close (spacing, type ramp, icons, the switch, the ✕/Add
  affordances) and fixes drift.
- Dark mode comes automatically from #1 (they use the shared variables); audit the few hardcoded
  colors (`.snack`, `.switch`) onto variables.
- Apps row stays **disabled ("Coming soon")** — app split tunneling is deferred.

## Files

**Modify (frontend):** `gui-tauri/src/routes/+layout.svelte` (dark palette), `+page.svelte` (Home
redesign + SPARK), `split-tunneling/+page.svelte` + `split-tunneling/websites/+page.svelte` (polish +
variable-ize hardcoded colors), `src/lib/spark_backend.ts` + `tauri_backend.ts` (routing-mode seam).
**Add (frontend):** `gui-tauri/src/routes/routing/+page.svelte`.
**Modify (Routing Mode backend):** `core/src/rules/router.rs` (mode), `core/src/fd_tunnel.rs`
(handle + threading + `set_routing_mode`), `core/src/config` or new `core/src/routing_mode.rs`
(type), `platforms/apple/src/lib.rs` + `include/spark.h`, `platforms/android/src/lib.rs` +
`SparkBridge.kt`, `platforms/apple/Sources/SparkNE/PacketTunnelProvider.swift`,
`gui-tauri/src-tauri/src/{lib.rs,config.rs}`.

## Phasing (single PR — internal build order)

Ships as **one PR**. The phases below are the build/commit order within it, not separate PRs:

- **Phase A — Visual foundation (pure frontend):** theming (dark), SPARK rebrand, Home Pro redesign,
  split-tunnel exact-match + variable-ize. Verifiable standalone via `npm run dev` (both themes).
- **Phase B — Routing Mode:** the `/routing` screen + the cross-layer backend mode slice (Router
  mode → fd_tunnel handle → FFI → NE → Tauri → seam). Built on top of Phase A.

The whole-workspace gate + a fresh notarized DMG run at the end validate the combined result before
review.

## Verification

- `npm run check` (0 errors) after each frontend change.
- **Visual diff each screen against the Figma in BOTH themes** (light + dark) via `npm run dev`
  (toggle OS appearance) — Home, Routing Mode, Split-tunnel (toggle/websites).
- Whole-workspace `cargo clippy --all-targets --all-features -D warnings` + `cargo fmt` +
  `cargo test -p spark-core` for the Routing Mode backend; unit-test `Router::decide` in Full mode
  (non-bypass → Proxy; ad domain → Reject; bypass → Direct) and Smart mode (unchanged).
- On-device notarized DMG: confirm both themes render per-Figma and Full/Smart switching changes
  routing live.

## Deferred (not this effort)

App-based split tunneling; the hamburger menu drawer + account/avatar screens; Sign-In / account /
subscription / Upgrade / data-usage (all free-tier or account chrome); Android Compose UI parity.
