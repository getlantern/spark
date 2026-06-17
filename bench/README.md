# bench/ — data-path throughput benchmarks

Measures spark's data-path throughput and CPU so we can decide, with numbers, whether a kernel-TCP
"**system stack**" (see `docs/system-stack-design.md`) is worth building, or whether the userspace
`smoltcp` stack is already good enough. The decision is explicitly benchmark-gated (design doc §9, §11).

## `netns-throughput.sh` — userspace stack vs. kernel-TCP ceiling (Linux)

Compares, on one Linux host:

- **kernel-baseline** — iperf3 client → server straight over a veth (no tunnel). The ceiling a
  system stack would approach.
- **spark-smoltcp** — the same transfer routed through spark's TUN, so spark terminates the TCP
  connection in userspace (smoltcp) and re-dials the upstream. Reports throughput **and spark's CPU**.

The gap between the two — plus spark's CPU during the run — is the headroom a kernel/system stack
could recover. If `spark-smoltcp` already reaches ~100% of the baseline at low CPU, the system stack
isn't worth its complexity.

### Why Linux netns (and not macOS)

A single-box end-to-end tunnel benchmark is **impossible on macOS**: the kernel hairpins any traffic
addressed to a local IP straight to `lo0` *before* consulting the route table, so you cannot force
iperf-style traffic through the TUN to a same-box server. Network namespaces solve this cleanly — the
server lives in a *separate* namespace, so its IP isn't local to the namespace running spark; routing
it via the TUN actually takes effect, and spark's `--protect-interface` (Linux `IP_UNICAST_IF`) pins
the upstream dial to the veth so the forward doesn't loop back into the TUN. This is the standard
approach (sing-box, WireGuard) and it runs unattended in CI.

### Run

```bash
# on a Linux host, with the spark binary built THERE:
cargo build --release
sudo ./bench/netns-throughput.sh                 # defaults: 15s/direction, 1 stream
sudo ./bench/netns-throughput.sh --duration 30 --streams 4
SPARK_BIN=/path/to/spark sudo -E ./bench/netns-throughput.sh
```

Requires root (netns + TUN), `ip` (iproute2), `iperf3`, and `jq` or `python3`. Both directions are
measured (upload = app→upstream, exercises smoltcp reassembly; download = `-R`, exercises smoltcp
segmentation). The script builds the namespaces, runs the tests, prints a table, and tears
everything down on exit (even on failure).

### Reading the result

```
================ spark throughput benchmark ================
stack                 up(Gb/s)   down(Gb/s)   spark CPU
------------------ ------------ ------------ ----------
kernel-baseline          XX.XX        XX.XX        n/a
spark-smoltcp            YY.YY        YY.YY         ZZ%
```

- **YY/XX ratio** — how much of the kernel ceiling the userspace stack reaches.
- **spark CPU (ZZ%)** — utime+stime across all tokio threads over the test window (100% = one core).
  High CPU at a throughput well below baseline is the strongest argument *for* a system stack.

### Extending to the system stack

When spark grows a `stack = "system"` option (`docs/system-stack-design.md` §5), add a third row by
copying the `spark-smoltcp` block with the system stack selected, and push its result into
`RESULTS`. The report loop already prints any rows it's given. That turns this script into the
direct A/B that promotes the design doc to an ADR — or kills it.

### Companion lever to measure first

Per design doc §9, **adding GSO to the existing smoltcp TUN bridge** may recover much of the gap for
less effort than a whole second stack. Benchmark that with the same script (it's stack-agnostic)
before committing to the system stack.
