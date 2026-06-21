# ADR 0008 — Client UI: migrate the GUI from Flutter to Tauri v2

- **Status:** Accepted (design) — 2026-06-19. Decided with Adam after a wholesale re-evaluation of
  cross-platform UI frameworks. Supersedes the Flutter GUI choice (under which the macOS one-click
  product and the Android M9 demo shipped). Migration is chunked as the **UI track U0–U4** in
  PLAN.md §4; execution runs through the normal session protocol (PLAN.md §2).
- **Scope:** Replace the client **UI shell only** — `gui/` (Flutter) and its *two* core bindings
  (`flutter_rust_bridge` on desktop + platform-channels → UniFFI on mobile) — with a single
  **Tauri v2** app: a web frontend calling the existing Rust as its backend via `invoke()` + events.
  Does **not** change `core/`, the netstack, transports, `ipc/`, `spark-ffi`/UniFFI, the privileged
  `spark-service`, or the platform tunnel integration (Android `VpnService`, Apple NE, desktop
  TUN/WinTun).
- **Builds on:** ADR 0004 (the `Backend` contract / `SparkBackend` seam — this is the swap point),
  ADR 0005 (macOS distribution + privileged component), and the `platforms/{android,apple}` shims +
  UniFFI from M9/M10.

## Context

The GUI is a thin control surface — connect/disconnect, live status, protocol/routing, server pick —
over a Rust core that already owns everything hard (netstack, transports, the privileged tunnel,
VpnService/NE integration). Today it is Flutter, carrying **two** distinct core bindings:
`flutter_rust_bridge` (desktop, in-process) and platform-channels → UniFFI (mobile).

Client platform priorities, in order: **Android, Windows, iOS, macOS, Linux**. **Install/download
size is a first-class concern** — users are often on constrained, censored networks and older Android
devices — consistent with the project's `<3 MB stripped` core ethos.

Re-evaluated against those priorities (2026):

- **Flutter** bundles its own rendering engine — an unshrinkable multi-MB size floor per platform —
  and carries the two-binding story above.
- **Tauri v2** uses the **system WebView** (no bundled engine), so install size is dominated by our
  own Rust binary; its backend **is** Rust, so the core links in directly and both bindings collapse
  into one uniform `invoke()`/event surface. The UI is simple enough that a web frontend is not a
  compromise, and the Lantern look is pure CSS — proven: `docs/mockups/spark-tauri-lantern-look.html`
  reproduces the current `_Palette` from `gui/lib/main.dart` exactly.
- **Compose Multiplatform** was the runner-up (best Android polish, reuses the Kotlin/UniFFI Android
  layer; iOS went Stable in 1.8.0, May 2025) but its desktop path needs a bundled JVM, which fights
  the size goal on Windows/Linux/macOS.

## Decision

1. **Adopt Tauri v2 as the single client UI framework on all five platforms.** Web frontend → Rust
   backend (the existing `spark-*` crates) via Tauri commands + events. The `SparkBackend` interface
   becomes a thin TypeScript module over `invoke()`.
2. **Front-end stack: Svelte + Vite** (small compiled output, reactive, good DX), with **vanilla TS**
   as the fallback. This is the one open sub-decision, confirmed at U0.
3. **Reuse, don't rebuild, everything below the shell:** core, netstack, transports, `ipc/`,
   `spark-ffi`/UniFFI, the privileged `spark-service`, and all platform tunnel integration. Mobile VPN
   entry points (`VpnService`/NE) are exposed to the app as a **Tauri plugin** wrapping the existing
   native shims + UniFFI.
4. **Process/privilege model unchanged** (ADR 0005 / process-architecture doc): the Tauri app is the
   **unprivileged client**; the data plane stays in the privileged service (desktop) or the
   NE/VpnService (mobile); only the control channel (`spark-ipc`) crosses the boundary. The UI never
   runs with tunnel privileges.
5. **Confine Tauri to a UI-shell crate** (`gui-tauri/` with its `src-tauri/`). `core/` and the locked
   stack stay Tauri-free. **Hard constraint:** the Tauri dependency tree must not introduce
   `openssl-sys` (CLAUDE.md) — verify at U0 (`cargo tree -i openssl-sys` empty) and pin `rustls`
   where Tauri offers the choice; the WebView is system-provided on every target.
6. **Android-weighted, macOS-first sequencing.** Bring macOS to parity first (most complete product
   today → lowest-risk proof), then Android (the priority), then Windows → iOS → Linux. Retire `gui/`
   only after per-platform parity.

## Consequences

- **Wins:** smallest install of the realistic options; one binding instead of two; the core becomes
  the app's actual backend (no FFI bridge on desktop); web skill-set + pixel-faithful Lantern look;
  all five targets from one shell.
- **Costs / risks:** Tauri **mobile** is younger than its desktop side — the `VpnService`/NE Tauri
  **plugin** is the real new engineering (it wraps code we already have). **iOS:** NE-extension
  packaging inside a Tauri iOS project is unproven for us (the NE logic itself ships today under
  Flutter). **WebView variance** across engines (WebKitGTK/Linux, Android System WebView versions,
  WKWebView) — low risk for a flat UI; covered by per-platform gates. Tauri is a **large new
  dependency surface** for the shell — accepted for the UI only, kept out of `core/`, gated on no
  `openssl-sys`.
- **Reversible:** the `SparkBackend` seam lets Flutter stay on a branch until Tauri reaches parity
  per platform. Nothing below the shell changes, so a rollback is shell-only.

## Evidence

- `docs/mockups/spark-tauri-lantern-look.html` — the current Lantern connect screen reproduced as a
  static web page (= a Tauri frontend) using the `_Palette` tokens from `gui/lib/main.dart`
  (rendered 2026-06-19).
- Tauri v2 is GA with stable desktop **and** mobile (iOS/Android) targets and system-WebView
  rendering (verified against the Tauri v2 docs, 2026-06).
- *To be produced by the gates:* measured bundle/APK/IPA sizes vs the current Flutter build at U1/U2,
  and a full five-platform size table at U4.
