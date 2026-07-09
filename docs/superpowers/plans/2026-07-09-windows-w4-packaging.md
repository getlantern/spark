# Windows W4 — GUI Packaging + Service Install Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> ✅ **DACL decision made: Option A** (widen the pipe DACL to the interactive user) — **Task 0 is
> implemented** in `service/src/pipe.rs` (`CONTROL_PIPE_SDDL` includes `(A;;GRGW;;;IU)`); the GUI ships
> unprivileged. The remaining tasks (1–5) are what's left. Note the **workflow-edit security hook**
> blocks `.github/workflows/*` edits via the current tooling; a human (or a session without that hook)
> must apply the release.yml / ci.yml changes (Tasks 1–3).

**Goal:** Ship the Windows Spark GUI as an installable app whose bundled MSI-installed LocalSystem
`spark-service` + WinTun make a working VPN — building on the already-merged W1–W3 core.

**Architecture:** The release workflow already builds `spark`+`spark-service` and an MSI that installs
the service (WiX `ServiceInstall`, LocalSystem, auto-start). W4 adds the **Tauri GUI** Windows build
(NSIS + MSI), **bundles `wintun.dll`** next to `spark-service.exe`, applies the chosen DACL/elevation
model, adds the deferred **plugin CI job**, and writes the **on-device validation checklist** (the real
end-to-end validation, since none of W1–W4 is exercised on Windows here).

**Tech Stack:** `tauri build` (NSIS + WiX/MSI bundlers), WiX v5 (`packaging/windows/spark.wxs`),
GitHub Actions `release.yml` (`workflow_dispatch` for dry-run validation) + `ci.yml`.

---

## Context (verified facts)

- **`release.yml`** (`on: push tags v*` + `workflow_dispatch`) already has a `x86_64-pc-windows-msvc`
  matrix leg that: builds `spark`+`spark-service`, zips them, and builds an MSI via `wix build … packaging/windows/spark.wxs` (WiX v5 dotnet tool). It does **not** build the Tauri GUI (the Tauri bundle is macOS-DMG-only via `package-macos-app`).
- **`packaging/windows/spark.wxs`** already: installs `spark.exe`+`spark-service.exe` to `Program Files\spark`, registers `spark-service` as a LocalSystem auto-start service (`ServiceInstall`), starts/stops/removes it (`ServiceControl`), ships the example config. **Missing:** `wintun.dll`, and the GUI app.
- **`wintun.dll` is not in the repo.** WinTun (wintun.net, Zerotier/WireGuard-maintained) ships as a signed redistributable DLL, loaded dynamically by `tun-rs` at runtime. It must sit next to `spark-service.exe` (the process that opens the adapter). Source it in CI by downloading the official zip + verifying its SHA-256 (do not commit the binary).
- **The pipe SDDL is applied at runtime** by `service/src/pipe.rs` (`PipeSecurity` when the service creates the pipe) — **no install-time SDDL step is needed** in the MSI.
- **The GUI↔service DACL decision is settled: Option A** — `pipe.rs`'s `CONTROL_PIPE_SDDL` already grants the interactive user (`IU`), so the GUI ships unprivileged (no NSIS admin manifest needed).
- **The plugin is its own workspace with no CI** (deferred from W3); its `Cargo.lock` is gitignored.
- **Verifiability:** the Windows Tauri build runs only on tag / `workflow_dispatch`, never on PRs. Nothing here is validatable on the macOS host. A `workflow_dispatch` dry-run validates the *build/packaging* (not the install or the tunnel). WiX service install + WinTun + the tunnel are **on-device only** (the checklist in Task 5).

---

## Task 0 (gate): apply the DACL decision — ✅ DONE (Option A)

- [x] **Option A (widen DACL) — implemented (PR #64).** `service/src/pipe.rs`'s `CONTROL_PIPE_SDDL`
  is now `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)` — grants `GENERIC_READ|GENERIC_WRITE` to the
  Interactive user (`IU`) alongside SYSTEM+Administrators full control. `cargo xwin clippy -p
  spark-service` clean; module doc + progress log updated. The exact `IU` access mask is on-device
  validated (W4 checklist). No NSIS admin manifest needed (GUI ships unprivileged).
- ~~Option B (elevated GUI)~~ — not taken; recorded in the progress log's decision section.

## Task 1: bundle `wintun.dll`

- [ ] In `release.yml`'s Windows leg (before the MSI/zip steps), download the official WinTun zip,
  verify its pinned SHA-256, extract `wintun.dll` for `amd64` into the bindir next to
  `spark-service.exe`. (No untrusted input; keep it injection-free for the workflow hook.)
- [ ] In `packaging/windows/spark.wxs`, add a `<File>` component for `wintun.dll` in `INSTALLFOLDER`
  and reference it from the `Main` feature, so the MSI installs it beside `spark-service.exe`.
- [ ] Add `wintun.dll` to the zip artifact too (for the CLI/service users).

## Task 2: build the Tauri GUI for Windows (NSIS + MSI)

- [ ] Add a Windows `tauri build` step (in `release.yml`, either extend the windows leg or a new job):
  install the frontend deps, `npm run build` the SvelteKit UI, `cargo tauri build` for
  `x86_64-pc-windows-msvc` → NSIS `.exe` + WiX `.msi` under the Tauri bundle output. Ensure the plugin
  (its own workspace) builds as part of the app (it does — the app depends on it).
- [ ] Apply the DACL decision's execution level (Option B: admin manifest; Option A: default per-user
  or per-machine as chosen).
- [ ] Decide GUI↔service packaging: either the Tauri installer bundles `spark-service.exe`+`wintun.dll`
  and registers the service (Tauri WiX fragment / bundled resources), OR the GUI installer + the
  existing service MSI are shipped together. Simplest: keep the **service MSI** (Task 1) as the
  privileged installer and have the Tauri GUI installer install the unprivileged app; document that
  both are required (or wrap them in a single bundle). Record the choice.
- [ ] Upload the NSIS + MSI as release artifacts.

## Task 3: plugin CI job (deferred from W3)

- [ ] Add a `plugin` job to `ci.yml` on `[macos-latest, windows-latest]` that `cd`s into
  `gui-tauri/tauri-plugin-spark-vpn` and runs `cargo fmt --all --check` + `cargo clippy --all-targets
  -D warnings` + `cargo test`. (macOS runs the `service_ipc` unix-socket round-trip test; Windows
  compiles `ServiceControl` + the named-pipe branch.) Linux is omitted (needs webkit2gtk system deps).
  — This is the exact job authored during W3; it's blocked only by the workflow-edit hook.

## Task 4: validate the build via `workflow_dispatch`

- [ ] Trigger a `release.yml` `workflow_dispatch` (manual dry-run — uses the branch name as version, no
  real release) and confirm the Windows Tauri build + MSI + wintun bundling steps succeed on
  windows-latest. Fix any packaging errors. (This validates build/packaging only — NOT install/tunnel.)

## Task 5: on-device validation checklist

- [ ] Write `docs/windows-on-device-validation.md` (mirror the Android on-device checklist): install
  the MSI + GUI on a real Windows box → service registered + running (SCM) → launch GUI → GUI connects
  to the service over the pipe (the DACL/elevation path) → Connect brings up WinTun + split-default
  routes + netsh DNS → traffic flows through the tunnel → kill-switch (blackhole) on data-path drop →
  Disconnect restores direct routing + DHCP DNS → uninstall removes the service. This is the real
  end-to-end validation of the entire W1–W4 stack, which was all deferred from hardware.

---

## Gate per task
`cargo xwin clippy` for any Rust change (Task 0 Option A); `workflow_dispatch` dry-run for the
release.yml changes (Tasks 1–2, 4); the `plugin` job itself validates Task 3. PR + review loop as usual.
Because the workflow files can't be edited via the current tooling (security hook), Tasks 1–3 may need a
human to apply the YAML, or confirmation that the hook can be bypassed for these injection-free changes.

## Self-Review
- Covers the spec's W4 (tauri NSIS+MSI, wintun bundling, service registration [already present], plugin
  CI job, on-device checklist). The service registration is already done in `spark.wxs` — W4 adds the
  GUI + wintun + the DACL/elevation model + the checklist.
- Honest about verifiability: build/packaging validatable via `workflow_dispatch`; install + tunnel are
  on-device only (Task 5). Nothing claimed as validated that isn't.
- Blocked-first: Task 0 (DACL) gates the rest; the workflow-hook impediment is called out per task.
