# Windows Support — Progress Log

Autonomous run started 2026-07-09 (user asleep). Goal prompt:
`docs/superpowers/windows-goal-prompt.md`. Design: `docs/superpowers/specs/2026-07-09-windows-support-design.md`.

Constraint: macOS host — all work is code-complete + cross-compiled (`x86_64-pc-windows-msvc`) +
unit-tested. Live on-Windows validation (SCM, named pipe, WinTun routes, tunneling) is DEFERRED to
hardware; never reported as verified.

## Status
- **W1 core Windows routing/kill-switch** — in progress (branch `fisk/windows-w1-routing`; spec +
  goal prompt + this log committed).
- **W2 live spark-service** — not started.
- **W3 tauri-plugin ServiceControl IPC client** — not started.
- **W4 Windows Tauri packaging + service install** — not started.

## PRs
- (none yet)

## Open decisions / blockers
- (none)
