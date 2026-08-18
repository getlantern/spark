# Deploying a spark exit server — design

Status: **§3 and §4 decided; §5 step 1 built (#207); §1–§2 corrected — the live pipeline uses no container** · Tracks: [#114](https://github.com/getlantern/spark/issues/114) ·
Builds on: [`module-distribution-and-trust-design.md`](./module-distribution-and-trust-design.md)

## The problem

`spark-wasm-server` exists and works ([#207](https://github.com/getlantern/spark/pull/207)) — it verifies a
signed bundle, runs the module as responder, and for BIP324 fronts a real Bitcoin node. What does not
exist is any way to *deploy* it.

This is not a bip324 gap. **No spark server has ever been deployed through lantern-cloud.**
`dns-tunnel-server` is complete, ships in spark's `prod` feature set, and has zero presence in
lantern-cloud — no track, no image, nothing. It has been finished and undeployed for the same reason.
So whatever we build here is the pattern dns-tunnel needs too, and it is worth designing as
"deploy a spark server" rather than as a bip324 special case.

## 1. How a VPS is actually provisioned

**Corrected 2026-08-14 (afisk): there is no container.** An earlier revision of this note analysed
`vps/cloudinit.go`, which installs Docker and runs lantern-box in a container. That path still exists
and is still called from `cmd/vps-test`, but the production service does not use it:
`cmd/api/main.go:972` constructs the provisioning worker with `UsePacker: true`, and every packer
branch in `vps_provision_worker.go` routes to `PushConfigPacker`. The Docker path is dead code in the
live service, and designing against it produced the wrong answer.

What actually happens (`vps/cloudinit_packer.go` + `vps/ssh.go`):

1. Boot a **Packer image** carrying the base OS — no application version baked in.
2. **cloud-init installs a `.deb`**: it curls
   `github.com/getlantern/lantern-box/releases/download/v<tag>/lantern-box_<tag>_linux_<arch>.deb`
   and `apt-get install`s it. The comment there is the load-bearing detail — *"the packer image does
   not bake in a specific lantern-box version — cloud-init installs the tag the orchestrator picked
   for this route"* — so the version is per-route orchestrator state, not image state.
3. The `.deb` drops the binary and a **systemd unit, left disabled**.
4. **`PushConfigPacker`** SSHes in, writes config + TLS material under `/etc/lantern-box/`, opens the
   listen port, and runs `systemctl enable --now lantern-box`.

## 2. What a spark exit needs — much less than a container

The pieces are already generic on both sides, which is why this is small:

| piece | state |
|---|---|
| `renderDebCloudInitStep` | **already package-generic** — takes `pkg`, `url`, `detail`, `note` |
| `LanternBoxDebURL` | lantern-box-specific; needs a sibling for spark |
| spark `.deb` build | **already exists** — `packaging/debian/build-deb.sh`, run by `release.yml` on tags |
| systemd unit in a spark `.deb` | **already exists** — the package ships `packaging/systemd/spark.service` |
| per-route version selection | already the track's release tag |

So deploying an exit is: **publish `spark-wasm-server` in a `.deb`, add a URL helper and an install
step, ship a systemd unit, and let the existing config push write the file and start it.** No
registry, no image build, no entrypoint indirection — all of which the previous revision of this note
proposed against the wrong pipeline.

⚠️ **cloud-init has a hard size cap, and it is already tight.** Linode limits `user_data` to 16,384
bytes, and lantern-cloud's scripts outgrew it — as of `f187c3c4f` (2026-08-14) they are shipped as
`base64(gzip(script))`, which the commit puts at "roughly a quarter", with a hard error if even the
compressed form exceeds the cap. The `.deb` install step is a URL and a few lines of shell, so it
fits comfortably. **The module bundle must never go here.** A hex-encoded `bip324.spkb` is ~46 KB and
would threaten the cap on its own; it rides the config that `PushConfigPacker` writes over SSH, which
has no such limit. That is an independent argument for §3's decision, arrived at from the other
direction.

Two things still need deciding, and they are smaller than they were:

- **One `.deb` or two.** The existing package installs `spark` + `spark-service` for a *client* host.
  An exit wants neither, and shipping a client's systemd unit onto a server would be actively
  confusing. A separate `spark-wasm-server` package is probably right, reusing the same build script
  shape.
- **The unit and config paths.** `PushConfigPacker` writes to `/etc/lantern-box/` and starts a unit
  named `lantern-box`. Both are just names, but a spark exit reusing them would be a lie in the
  filesystem; parameterizing them is a handful of lines now that the Docker entrypoint question is
  moot.

## 3. Getting the bundle onto the exit — DECIDED: inline, hex-encoded

The exit needs its `.spkb`, and `ssh.go` only knows how to write `config.json` + TLS materials.

**Decided (afisk, 2026-08-14): carry it in the config, hex-encoded** — the same way the *client* receives it. Then
`run --config` installs it through `BundleStore` on startup, and the existing config-push path needs no
change at all. It also makes the symmetry exact: client and exit obtain the identical artifact by the
identical mechanism, and both verify it against the same pinned key before use.

The alternative — a second file pushed over SSH — needs an `ssh.go` change and creates a second
delivery path to keep in sync with the first.

Size is not a concern here: `bip324.spkb` is ~46 KB hex, against a config file with no meaningful
ceiling on a host we own.

## 4. The Bitcoin node — DECIDED: a rotating pool of public nodes first

`serve-bitcoin --upstream` must point at something that behaves like a real Bitcoin node, or the cover
story is gone. `spark-wasm-server` refuses to start without it for exactly this reason.

### The risk is concentration, not availability

Finding a public node is easy — bitnodes.io lists every reachable one. The problem is that proxying
routes *every* untagged peer through our single egress IP, and `bitcoind`'s abuse controls are
per-peer. From the upstream's point of view **we are one peer**, so:

- **One misbehaving peer we forward gets *us* discouraged or banned.** Misbehaviour is scored per
  peer; malformed traffic from anyone we proxy is attributed to our address. Once banned, the cover
  path fails outright — untagged peers get nothing, which is precisely the anomaly this design exists
  to avoid.
- **Slot exhaustion.** A node allows roughly 114–189 inbound connections in total. A busy egress can
  take a visible share of one node's slots from a single address, which is itself unusual.
- **No obligation.** A volunteer can restart, firewall us, or vanish, and our cover collapses with no
  warning. Their node also carries our proxied peers' traffic without them having agreed to it.

**Version floor: Core ≥ 27.0**, where BIP324 v2 transport is on by default (supported but off in
26.0). A v2 peer proxied to an older node falls back to v1 — a measurable behavioural difference on a
listener whose whole purpose is to look ordinary.

### Rotating a pool, keyed by peer

Spreading across several upstreams fixes all three: a ban costs 1/N of capacity instead of everything,
each node sees a fraction of our connections, and a dead upstream is survivable.

⚠️ **But do not rotate per connection.** A real node has one identity. Round-robin per connection means
two probes to our address get different user agents, service bits and chain heights — a node that
changes identity between connections is *more* detectable than one that consistently impersonates a
single peer, which would trade a small risk for a larger one.

**Rotate by source address instead** — pick the upstream by hashing the peer's IP, so any single
observer always sees one consistent node, while the pool as a whole spreads load and survives bans.
Failover on connect error, and drop an upstream that stops answering. A determined censor probing from
many addresses could still observe several identities behind one IP, but that is a far higher bar than
noticing a user agent change between two connections from the same host.

Worth noting the outbound side is *not* made worse by this: a real listening node keeps ~10 outbound
peer connections, and an egress proxying many inbound peers necessarily makes more than that no matter
how many upstreams it uses. Spreading them across a pool looks more like ordinary peering than
hammering one node does.

### Running our own — cheaper than this note previously claimed, in the way that matters

| method | time to usable (cloud VPS) | disk | downloaded |
|---|---|---|---|
| Pruned IBD | 8–24 hours | 5–7 GB | **~700–800 GB** |
| AssumeUTXO (Core ≥ 28.0) | **15–30 min** | 7–12 GB snapshot | snapshot + blocks since |

An earlier revision said a pruned node "costs ~7–10 GB of disk and an initial sync", which reads as
cheap and is misleading. **Pruning does not reduce sync time or bandwidth at all** — a pruned node
downloads and validates every block from genesis and then deletes them. The disk is cheap; the ~750 GB
download is not.

**AssumeUTXO is what changes the calculus**, and it suits this use case unusually well: we never need
to serve historical blocks, we need something that *behaves* like a node — which a snapshot-loaded
node does within half an hour. Two caveats: background validation still eventually pulls the full
chain, and there is no official snapshot distribution channel (generate from a node we control, or
take a community copy — the hash compiled into Core catches tampering).

Ongoing, a listening node uses **200+ GB/month of upload**. That is a real per-exit line item whichever
option we pick, because the cover traffic is real traffic.

**Decided (afisk, 2026-08-14): a rotating pool of public nodes on Core ≥ 27.0 for the first deploy**,
straight to **prod**. Then our own node — with AssumeUTXO, not a plain pruned sync — before an exit
carries meaningful load. Treat the public pool as scaffolding with a known expiry rather than a first
deployment: it is free and instant, and it fails as a *cover story* rather than merely as a service.

## 4b. Telemetry — DECIDED: log the infra, log the failed-auth peers, never the users

Two things an operator cannot run an exit without: which cover nodes it is actually using, and who is
knocking without valid auth.

### What is recorded

| | recorded | level |
|---|---|---|
| Upstream pool, at startup | each node's address | `info` |
| Untagged peer, at close | address, `opening`, `duration_ms`, bytes each way, `outcome`, which upstream | `info` |
| Egress roll-up, every 5 min | counters only | `info` |
| **Tunnel client** | **a count, and nothing else — no address, ever** | — |

### Why this is not a hole in the log-hygiene rule

`docs/GOAL.md` says we do not write down where users go, and calls it a product property rather than a
nicety. Nothing here weakens it:

- **Upstream nodes are our own cover infrastructure**, not a user's destination. Not logging them buys
  a user nothing and costs an operator the ability to tell a healthy exit from a degraded one.
- **An untagged peer is by definition not a tunnel user.** It failed the side-door check, so it is
  either a real Bitcoin peer or somebody probing us. Neither is a person we owe log silence to.
- **A tunnel client is a user**, and an exit host is exactly the machine an adversary would seize to
  learn who they are. So the tunnel branch counts and records nothing identifying.

That asymmetry is enforced by the type, not by review: `EgressTelemetry::on_tunnel()` takes no address,
so there is nothing for the tunnel branch to log. An integration test asserts the property against the
real `tracing` stream — that exactly one event carries a `peer` field and it is the untagged record —
and both halves are verified to fail when the behaviour is disabled.

Worth noting the redaction backstop in `core/src/redact.rs` does **not** apply here: it is wired into
the *client's* logger, and the exit installs a plain subscriber. So these addresses reach journald
intact, which is the intent — but it also means the exit has no second line of defence if someone adds
an address to the wrong branch. Hence the test.

### The record is written at close, not at accept

Most untagged connections are legitimate Bitcoin peers — that is the whole point of the cover story —
so an event per accept would label the Bitcoin network as suspicious and bury the signal. What
separates a prober from a peer is what it does *after* connecting: a prober opens, probes, and leaves;
a peer stays and moves data. Hence `duration_ms` and the byte counts, which are what make an address
actionable.

The sharpest signal is a peer that connects and says **nothing** (`opening=silent`) — a real node
always speaks first. Those were previously dropped with no record at all.

⚠️ **Our own monitoring is the loudest silent source.** `VPSReachabilityProbeWorker` dials every
published route and closes without sending a byte, which is byte-for-byte a port scan. On the first
prod exit it produced **77 of 89** untagged records. So a repeat silent source logs once at `info`
and thereafter at `debug`, and the roll-up carries `untagged_silent_sources` — the distinct-source
count is the number that means something: many connections from one address is a health check, the
same count spread across many addresses is a scan. The tracked set is bounded, because it is fed by
unauthenticated peers.

⚠️ **`untagged` is not a synonym for `prober`.** The bucket also holds every real Bitcoin peer, and —
importantly — *our own clients when they are misconfigured*: a wrong `k_srv`, a stale bundle, or a
magic mismatch all classify as untagged. So a spike in untagged records after a config push is far more
likely to be our own breakage than an attack, and triage should rule that out first.

### Scope

These are structured `tracing` events to journald. There is no otel/SigNoz pipeline on the exit — that
was the instrumentation we knowingly gave up by not running this inside lantern-box (§2), and wiring
one up is its own piece of work. The fields are structured, so shipping them later is a collector
config rather than a code change.

## 5. Sequencing

1. ~~`run --config` in `spark-wasm-server`, installing the inline bundle on startup~~ — **done**
   (#207). The config is JSON, carries the bundle as hex, and installs it *before* anything listens,
   so a bad artifact stops the deploy rather than the first connection. `k_srv` rides the file rather
   than argv, where any local `ps` would read it — the file therefore holds a secret and wants `0600`,
   the way the pipeline already treats a TLS private key.
2. **A `spark-wasm-server` `.deb`** — a sibling of `packaging/debian/build-deb.sh` with its own systemd
   unit, published by `release.yml` alongside the existing artifacts.
3. **A `SparkExitDebURL` helper + an install step** in the packer cloud-init (lantern-cloud). The
   step renderer is already package-generic, so this is a URL and a call.
4. **Parameterize the config path and unit name** in `PushConfigPacker`, or accept `lantern-box` as a
   misnomer on an exit host. Small either way, and no longer entangled with a container entrypoint.
5. A `wasm` arm in `pcfg` emitting the outbound spark already parses, plus a track carrying the
   engine, the release tag, and the launch config.
6. Upstream per §4 — a rotating pool of public nodes, keyed by peer address. `--upstream`
   currently takes one address; a pool needs it to take a list plus the source-hash pick and
   failover, which is the one piece of §4 not yet built.
7. Then the #114 e2e is meaningful: a signed module delivered by config to a client that dials an exit
   actually running it.

## Open questions

1. **One `.deb` or two?** See §2 — an exit wants neither `spark` nor `spark-service`, and shipping a
   client's systemd unit onto a server invites confusion.
2. **Does the exit need the same `SPARK_MODULE_PUBKEY_HEX` pinning ceremony as the client?** It does
   today — a release build refuses to compile without it, deliberately — so the `.deb` build needs the
   pubkey as a build-time variable, exactly as `release.yml` already passes it for the client.
3. **How does `k_srv` reach both sides?** The exit gets it from its config; the client must get the
   matching value through the config channel. That is a genome/`init_config` question this note does
   not answer, and it is the last seam where client and exit can each be correct and still not speak.

*(Resolved: "where does the container image build live" — there is no container. See §1.)*
