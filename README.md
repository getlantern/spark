# Spark — Multi-Protocol VPN/Proxy Tunnel

A from-scratch, multi-protocol VPN/proxy tunnel in Rust. A local TUN tunnel terminates
connections in a userspace netstack and forwards them through pluggable tunnel transports
(first: a plain TCP tunnel). Performance and small binary size are first-class constraints.
Targets desktop (Linux/macOS/Windows) and mobile (Android/iOS) over a shared Rust core.

## This repo is set up to be built by an AI coding agent (Claude Code)

The planning and design work is done; implementation is staged across many sessions.

- **CLAUDE.md** — standing instructions Claude Code loads automatically (code standards,
  locked stack, patterns/anti-patterns, process model).
- **docs/GOAL.md** — north star; read first every session.
- **docs/PLAN.md** — the session operating protocol (pacing) + the M0–M11 milestone ladder
  with binary pass/fail gates.
- **docs/STATE.md** — cross-session memory; currently set to start at **M0**.
- **docs/tun-to-proxy-design.md** — netstack + tunnel-transport architecture.
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

## Building and running

```bash
cargo build --release          # binary at target/release/spark
cargo test -p spark-core       # unit tests (packet parser + checksums)
cargo clippy --workspace --all-targets -- -D warnings
cargo run --example netstack_smoke -p spark-core   # prints NETSTACK OK (M0 gate)
```

### M1 ICMP-echo gate (requires root)

`spark` brings up a TUN device, logs each IP packet, and answers ICMP echo requests.
Creating a TUN device needs elevated privileges on every desktop OS.

**Linux:**

```bash
sudo RUST_LOG=debug ./target/release/spark --name tun0 --addr 10.0.0.1 --prefix 24
# in another terminal — ping a peer address in the TUN subnet (not the local 10.0.0.1,
# which the host answers itself), so the request is routed out the TUN to our responder:
ping 10.0.0.2
```

**macOS** (TUN devices are named `utunN`; the OS may pick the number):

```bash
sudo RUST_LOG=debug ./target/release/spark --addr 10.0.0.1 --prefix 24
# note the assigned utun name in the startup log, then:
ping 10.0.0.2
```

Expected: `ping` reports replies, and the `spark` log shows `rx proto=icmp` lines (plus
`rx addresses` lines at `RUST_LOG=debug`). Without `--debug`/`RUST_LOG=debug`, addresses
are never logged — a deliberate privacy property (see `docs/GOAL.md`).
