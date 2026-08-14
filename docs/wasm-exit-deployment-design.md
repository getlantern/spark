# Deploying a spark exit server — design

Status: **§2C, §3 and §4 decided; §5 step 1 built (#207)** · Tracks: [#114](https://github.com/getlantern/spark/issues/114) ·
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

## 1. What the pipeline hardcodes today

Verified against `lantern-cloud/cmd/api/vps/`. A VPS is provisioned in two phases:

**cloud-init** (`cloudinit.go`) installs Docker, pulls `cfg.DockerImage`, and writes a systemd unit:

```
[Unit] Description=sing-box proxy service
ExecStart=/usr/bin/docker run --rm --name sing-box \
    --net=host -v /etc/sing-box:/etc/sing-box \
    --entrypoint /usr/local/bin/lantern-box \
    IMAGE_PLACEHOLDER \
    run --config /etc/sing-box/config.json
```

**config push** (`ssh.go`) writes `/etc/sing-box/config.json` (plus optional `tls.crt`/`tls.key`),
re-pulls the image, and `systemctl enable --now sing-box`.

Four things are baked in, and a spark server matches none of them:

| baked in | value | spark exit needs |
|---|---|---|
| systemd unit name | `sing-box` | anything |
| container entrypoint | `/usr/local/bin/lantern-box` | `/usr/local/bin/spark-wasm-server` |
| config path | `/etc/sing-box/config.json` | somewhere for a config + a `.spkb` |
| CLI shape | `run --config <path>` | `serve-bitcoin --k-srv … --upstream …` |

Two things are already generic and worth keeping: the image ref comes from the track
(`Track.DockerImageRef`, and `IsSingboxTrack()` is only a *name* check, so a non-sing-box image is
representable rather than excluded), and `--net=host` plus the iptables rule on `cfg.ListenPort` mean
the listener is reachable without any port-mapping work.

## 2. Making a spark server fit — three options

**A. Impersonate lantern-box.** Ship the image with `spark-wasm-server` at
`/usr/local/bin/lantern-box` and teach it `run --config <path>`. Zero lantern-cloud changes; deployable
today. It also puts a binary at a path that lies about what it is, which will cost somebody an hour at
the worst possible moment.

**B. Parameterize the whole pipeline** — unit name, entrypoint, config path, argv — driven off the
track. Cleanest, and dns-tunnel inherits it. But it edits provisioning code that *every existing track
flows through*, to benefit a track that does not exist yet.

**C. Decided: `run --config` in spark, plus an entrypoint placeholder in cloud-init.**

Two small changes that meet in the middle:

- **spark side** — `spark-wasm-server run --config <path>`, reading the same arguments from a JSON
  file. Worth having regardless: the pipeline's whole config-delivery mechanism is "write a file, restart
  the unit," and a `k_srv` secret does not belong in a systemd `ExecStart` line where `ps` can read it.
- **lantern-cloud side** — the entrypoint becomes a placeholder exactly like the image already is
  (`sed -i 's|IMAGE_PLACEHOLDER|…|'` is the established pattern, one line away from
  `ENTRYPOINT_PLACEHOLDER`), defaulting to `/usr/local/bin/lantern-box` so every existing track is
  byte-identical.

The unit name and config path stay `sing-box` / `/etc/sing-box/config.json`. They are inaccurate for a
spark exit but they are *only names*, and leaving them alone keeps the diff to provisioning code near
zero. Renaming them is a follow-up that touches nothing functional.

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
2. Container image + its build (spark or a deploy repo — **where is an open question**; there is no
   existing image build for a spark binary).
3. `ENTRYPOINT_PLACEHOLDER` in cloud-init, defaulting to today's value (lantern-cloud, ~5 lines).
4. A `wasm` arm in `pcfg` emitting the outbound spark already parses, plus a track pointing at the new
   image (lantern-cloud).
5. `bitcoind` per §4.
6. Then, and only then, the #114 e2e is meaningful: a signed module delivered by config to a client
   that dials an exit actually running it.

## Open questions

1. **Where does the image build live?** No spark binary has one. A `Dockerfile` in spark plus a CI job
   is the obvious answer, but it is the first of its kind and wants a registry decision.
2. **Does the exit need the same `SPARK_MODULE_PUBKEY_HEX` pinning ceremony as the client?** It does
   today — a release build refuses to compile without it, which is deliberate — so the image build
   needs the pubkey as a build arg, the same way `release.yml` passes it.
3. **How does `k_srv` reach both sides?** The exit gets it from its config; the client must get the
   matching value through the signed config channel. That is a genome/`init_config` question this note
   does not answer.
