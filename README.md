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

**`make` lists every build target.** Each one wraps a script under `packaging/` or `scripts/`;
the Makefile exists so those don't have to be found by reading the release workflow.

```bash
make            # list targets
make check      # fmt + clippy + the full test suite — run before pushing
make release    # release build; binary at target/release/spark
make macos      # the macOS product DMG (see the warning below)
```

### Building the macOS app

Use **`make macos`**, not `npm run tauri build`.

`npm run tauri build` produces only the Tauri UI shell: no `org.getlantern.spark.tunnel`
system extension and an ad-hoc signature. It launches and looks correct, and it cannot tunnel —
which is why it is worth stating rather than leaving to be rediscovered.

`make macos` builds the UI, builds and embeds the system extension, signs with a Developer ID
identity **derived from the installed provisioning profiles** (nothing to name or configure), then
notarizes and staples.

Notarization is not optional: macOS refuses to activate an un-notarized system extension, so a
build without it launches fine and the tunnel silently never comes up.

Credentials come from the environment — `AC_USERNAME` (Apple ID) and `AC_PASSWORD` (an
app-specific password). On a machine that already exports them, `make macos` needs nothing else;
check with `env | grep '^AC_'` before assuming they are absent. Otherwise, either export those two
or store a notarytool profile once:

```bash
xcrun notarytool store-credentials spark \
  --apple-id <apple-id> --team-id ACZRKC3LQ9 --password <app-specific-password>

NOTARY_PROFILE=spark make macos      # -> dist/Spark.dmg
```

`make macos-fast` skips notarization for UI-only iteration. The tunnel will not work in that build.

```bash
cargo test -p spark-core       # unit tests (packet parser + checksums)
cargo run --example netstack_smoke -p spark-core   # prints NETSTACK OK (M0 gate)
```

## Configuration

`spark` is configured by `--config <file.toml>` or, when that is absent, by the individual
CLI flags (`--name`, `--addr`, `--prefix`, `--mtu`, `--server`, `--debug`). When `--config`
is given it provides the full configuration and the flags are ignored.

Every field has a default, so a partial file is valid; unknown keys are rejected. The full
schema (all values shown at their defaults):

```toml
[tun]
# name = "tun0"   # requested device name; omit to let the OS choose (utunN on macOS)
addr = "10.0.0.1" # IPv4 address assigned to the interface
prefix = 24       # IPv4 prefix length
# mtu = 1500      # MTU override; omit to use the device default

[transport]
# server = "203.0.113.1:8388"  # tunnel server; omit to dial destinations directly

[udp]
idle_timeout_secs = 60  # reclaim a UDP NAT association after this much silence

[log]
debug = false   # log src/dst addresses and disable IP redaction (also: --debug, RUST_LOG=debug)
```

**Log hygiene:** addresses are logged only at `debug` level, and at the default level the
log writer additionally redacts any IP literal as a backstop — so default-level logs never
contain destination IPs. `--debug` (or `debug = true`) disables both.

## Packaging (desktop)

Two binaries: the privileged `spark-service` daemon and the unprivileged `spark` client.
Service-install units (systemd / launchd), an example config, the size-budget check, and the
per-target cross-build status live in [`packaging/`](packaging/README.md). Quick check:

```bash
cargo build --release && ./scripts/size-budget.sh   # both binaries must be < 3 MB stripped
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

### M2 plain-TCP-forwarder gate (requires root)

At M2, `spark` no longer inspects packets itself: it bridges the TUN into a userspace
TCP/IP stack (`netstack-smoltcp`), accepts each terminated TCP flow, and forwards it to
the flow's original destination via a **direct** dial (no tunnel transport yet — that is
M3/M4). The gate is a TCP request that traverses TUN → netstack → upstream → back.

> ⚠️ **Loop hazard (intrinsic to M2's direct dial).** The upstream `spark` dials *is* the
> original destination. So you must NOT add a routing-table entry that sends that
> destination into the TUN — it would also catch `spark`'s own outbound dial and loop
> forever. The clean M2 test forces only the *client's* socket into the TUN (per-socket
> bind) while leaving `spark`'s dial on the default route. This awkwardness disappears at
> M4, where `spark` dials a tunnel **server** at a different address, so routing the
> destination into the TUN no longer captures the dial.

**Linux (clean — per-socket `SO_BINDTODEVICE`, no routing-table change):**

```bash
sudo RUST_LOG=info ./target/release/spark --name tun0 --addr 10.0.0.1 --prefix 24
# Return packets arrive on tun0 with a src the main route table reaches via eth0, so
# loosen reverse-path filtering on the device (else the kernel silently drops them):
sudo sysctl -w net.ipv4.conf.tun0.rp_filter=0 net.ipv4.conf.all.rp_filter=0
# `--interface tun0` binds curl's socket to tun0 (SO_BINDTODEVICE), forcing the request
# INTO the tun; spark's unbound upstream dial follows the default route out eth0:
curl -v --interface tun0 https://1.1.1.1
```

**macOS:** there is no `SO_BINDTODEVICE`; `curl --interface utunN` only sets the source
*address*, and egress is then chosen by the route table — so getting traffic into the tun
requires a `route add -host <dst> -interface utunN`, which re-triggers the loop above.
Run the M2 gate on Linux; defer the full macOS route test to M4 (no loop there).

Expected: `curl` completes the TLS handshake and returns a response; the `spark` log shows
a `tcp flow completed` line with `to_upstream`/`to_app` byte counts (addresses only at
`RUST_LOG=debug`).

> Status: the **bridge + accept loop + forwarder are implemented, compile green, and are
> unit-tested** (hermetic loopback forward test). The *live* root-required curl gate above
> is **pending a privileged run** — see `docs/STATE.md` Blockers.
