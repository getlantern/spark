# Censorship Circumvention Tool

A from-scratch, multi-protocol censorship-circumvention VPN/proxy in Rust. A local TUN
tunnel terminates connections in a userspace netstack and forwards them through pluggable
circumvention transports (first: Shadowsocks-2022). Targets desktop (Linux/macOS/Windows)
and mobile (Android/iOS) over a shared Rust core.

## This repo is set up to be built by an AI coding agent (Claude Code)

The planning and design work is done; implementation is staged across many sessions.

- **CLAUDE.md** — standing instructions Claude Code loads automatically (code standards,
  locked stack, patterns/anti-patterns, process model).
- **docs/GOAL.md** — north star; read first every session.
- **docs/PLAN.md** — the session operating protocol (pacing) + the M0–M11 milestone ladder
  with binary pass/fail gates.
- **docs/STATE.md** — cross-session memory; currently set to start at **M0**.
- **docs/tun-to-shadowsocks-design.md** — netstack + Shadowsocks-2022 architecture.
- **docs/process-architecture-and-ipc.md** — privileged tunnel process vs. unprivileged
  client, control-plane IPC, and cross-platform permissions.
- **netstack-spike/** — a compiling reference for the netstack bridge (verified on the
  0.1.x API / rustc 1.75; re-verify against vendored 0.2.x on ≥1.85 at M0).

## How to run a session

Open Claude Code in this directory (select your model there) and say:

> Read GOAL.md, PLAN.md, and STATE.md, then execute the next chunk.

The protocol does the rest: confirm a green start, do one bounded chunk, run the gate,
commit, update STATE.md, and stop. Repeat next session.

## First session (M0)

Creates the Cargo workspace, pins the toolchain (stable ≥ 1.85), vendors `netstack-smoltcp`
into `vendor/`, and proves the netstack compiles via a `netstack_smoke` example. Gate
details in `docs/PLAN.md` §4 (M0). Bringing up real TUN devices and the privileged service
(M7) will require elevated privileges and your approval on those commands.
