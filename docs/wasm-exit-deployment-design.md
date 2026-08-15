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

## 4. The Bitcoin node — DECIDED: a public node first

`serve-bitcoin --upstream` must point at something that behaves like a real Bitcoin node, or the cover
story is gone. `spark-wasm-server` refuses to start without it for exactly this reason.

**i. A pruned `bitcoind` on the same VPS, bound to localhost.** The egress owns the public
`0.0.0.0:8333`; bitcoind listens on `127.0.0.1:8334`; untagged peers are proxied to it. The node is
genuinely on the network — it syncs, relays, and answers exactly as a node does, because it *is* one.
Costs ~7–10 GB of disk and an initial sync. **Recommended for the real deployment.**

**ii. Proxy to a public node.** Free and instant, but every peer that reaches our IP is talking to
*someone else's* node, so our address presents that node's identity — version nonce, user agent,
services — and two IPs advertising one identity is a subtle but real anomaly. Also concentrates all our
cover traffic on one third party who did not agree to it.

**iii. A shared bitcoind for the fleet.** Halfway: one node we run, several egresses proxying to it.
Same identity-collision issue as (ii), among our own hosts.

**Decided (afisk, 2026-08-14): (ii) — a public node — for the first deploy**, then (i) before an exit
carries real users. The switch is one config field.

Two things this defers rather than solves, and they should not be forgotten when the switch happens:
our address presents *that node's* identity to every peer that reaches it, and all of our cover
traffic lands on a third party who did not agree to carry it. Both are acceptable while the point is
to prove the pipeline; neither is acceptable at scale.

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
6. `bitcoind` per §4 — a public node first.
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
