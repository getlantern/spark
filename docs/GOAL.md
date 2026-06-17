# /goal

> Read this at the start of **every** session. It is the north star. It is short on
> purpose. Detailed instructions live in the other docs (see "Where things live").

## Mission

Build a from-scratch, multi-protocol VPN/proxy tunnel in Rust.
It runs a local TUN tunnel, terminates connections in a userspace netstack, and forwards
them through pluggable tunnel transports (first: a plain TCP tunnel). Performance
and small binary size are first-class constraints. Targets: Linux/macOS/Windows desktop,
plus Android and iOS via platform tunnel shims over a shared Rust core.

## Non-negotiables

- **Pure-Rust, small binary.** No C dependencies. Release binary stays within the size
  budget in PLAN.md. No dependency added without it being in the locked stack or approved.
- **Log hygiene.** Never log destination IPs/hostnames by default. Redact unless `--debug`.
  This is a user-privacy property of the product, not a nicety.
- **No fake work.** No stub functions returning `Ok(())`, no `todo!()`/`unimplemented!()`
  left in a "done" milestone, no TODO comments without approval. If you can't implement
  it, stop and ask.
- **Verify APIs, don't guess.** Before using a non-trivial API of tokio/rustls/ring/
  tun-rs/netstack-smoltcp/smoltcp, confirm the signature against the vendored source or
  docs.rs, or say you're unsure. Hallucinated signatures waste whole sessions.
- **Two-strike rule.** If two attempts at a fix make no progress, stop and report the
  state and the error. Do not thrash.
- **Green at every boundary.** Never end a session with a non-compiling tree.

## Definition of done (whole project)

A user can run the tool on desktop (and via the mobile shims), route traffic through a
configured tunnel server, and reach the internet — with TCP and UDP (incl. DNS) working,
logs free of destinations by default, and the binary within budget. At least one additional
transport is pluggable behind the transport trait.

## Where things live

- **GOAL.md** (this file) — north star; read first, every session.
- **PLAN.md** — the milestone ladder, the per-session operating protocol, and the gates.
  Read the session protocol every session; read only the *current* milestone in detail.
- **STATE.md** — cross-session memory: what's done, what's next, open blockers. You
  maintain this. Read it at session start, update it at session end. (Template in PLAN.md.)
- **CLAUDE.md (repo root)** — code standards, locked stack, patterns/anti-patterns.
- **tun-to-proxy-design.md** — the architecture reference (netstack, tunnel-transport wire
  format, the verified API surface). Consult the relevant section; don't re-derive it.
- **process-architecture-and-ipc.md** — the multi-process model: privileged tunnel process
  vs. unprivileged client, the control-plane IPC, and cross-user permissions per platform.
  Consult before any `service/`, `ipc/`, or platform-shim work.

## Prime directive on pacing

Work in **one bounded chunk per session**, sized to leave room to finish cleanly. End every
session at a compiling checkpoint with STATE.md updated. When you sense the context budget
getting tight, **stop starting new work** — finish the current compiling unit, commit,
checkpoint, and end. A clean handoff is worth more than one extra half-built feature.
