# Deploying `dns-tunnel-server` (ADR 0011)

The spark DNS-tunnel server is a **drop-in modernization of Lantern's dnstt escalation tier** and
deploys with the same shape as `getlantern/lantern-cloud`'s dnstt automation
(`ans/bootstrap-dnstt.yaml`): a static binary + a systemd unit + a `:53→:5300` DNAT, fed by a
delegated authoritative subdomain. The only substantive differences:

| | dnstt | spark dns-tunnel |
|---|---|---|
| binary | `linux-dnstt-server` | `dns-tunnel-server` (static musl) |
| key | Noise keypair (`server.key`/`.pub`) | static **Ed25519** keypair — public key distributed |
| wire | dnstt (KCP+smux+Noise) | spark's own (ADR 0011) — **not** interop |
| provider (prod) | OCI | **Linode** |
| zone | `t.iantem.io` | an **unattributable** domain (never named in this repo — see below) |

Because the wire protocols differ, spark needs its **own** server IP and its **own** delegated zone —
it cannot co-tenant dnstt's `:53`. They coexist fine (dnstt on `t.iantem.io`, spark elsewhere).

## Redeploying / debugging

`.claude/skills/redeploy-dns-tunnel/SKILL.md` is the runbook: an ordered health-check chain, the
silent failure modes (missing NS delegation, unpersisted DNAT, a proxied glue record), key recovery
without rotation, and the end-to-end test. Read it before changing a running deployment.

Requires `brew install ansible`.

## The zone is deliberately not in this repo

The tunnel zone is chosen to be **unattributable** — that is the entire reason it is not a Lantern
domain. Committing it here would hand a censor the one string needed to block the escalation tier,
and this repository is intended to be public, so naming the live zone would undo the property the
zone was picked for.

It lives with the deployment: the running host's systemd unit (`--zone`), the client build's
`SPARK_BOOTSTRAP_DNS_ZONE` repo variable, and the config server. Docs here say `t.<domain>`.

The same applies to the host IP and the server's private key. The server's **public** key is not a
secret — it is distributed to every client by design — but it is still deployment state, so it lives
in `/etc/spark-dns/pubkey` on the host and in the build variable, not here.

## What to reuse from lantern-cloud

- **Client config distribution.** Surface a spark-dns config (zone / server public key / resolvers) to
  clients **Spark-side** and slot it into the escalation tier. (An earlier flashlight-side
  `SparkDNSConfig` — `genconfig` → cloud.yaml → config-server, alongside `common.DNSTTConfig` — was
  reverted; distribution stays in Spark, not flashlight.)
- **The escalation slot + tuned resolver list** in the client.
- **Hardening tasks** (e.g. the dnstt CVE-mitigation playbook).

The Ansible playbook + systemd template here are provider-agnostic and intended to be merged into
`lantern-cloud/ans/` next to the dnstt ones.

## Steps

1. **Build the static server binary** (distro-agnostic; from the spark repo root):
   ```sh
   cargo zigbuild --release -p dns-tunnel-server --target x86_64-unknown-linux-musl
   cp target/x86_64-unknown-linux-musl/release/dns-tunnel-server deploy/ansible/files/
   #  (for ARM Linode/OCI hosts: --target aarch64-unknown-linux-musl)
   ```

2. **Provision the host** (Linode; needs `linode-cli` + `LINODE_TOKEN`):
   ```sh
   ./deploy/provision-linode.sh spark-dns-use1   # prints the public IP
   ```

3. **Delegate an unattributable zone** to that IP (at the domain's DNS host — e.g. Cloudflare),
   both records **DNS-only / unproxied**:
   ```
   ns-spark.<domain>   A    <host-ip>
   t.<domain>          NS   ns-spark.<domain>
   ```

4. **Generate the server keypair** and place the private key for the playbook (keep the public key
   for the client config — the private key never leaves the server):
   ```sh
   ./deploy/ansible/files/dns-tunnel-server keygen   # (or run the built binary anywhere)
   #   → prints:  privkey <base64>   /   pubkey <base64>
   echo '<base64 privkey>' > deploy/ansible/files/spark-dns.privkey
   #   put the pubkey in each client's DnsTunnelConfig.server_pubkey
   ```

5. **Deploy** (put the IP in `inventory/spark-dns.yaml`, then):
   ```sh
   ansible-playbook -i deploy/ansible/inventory/spark-dns.yaml \
     deploy/ansible/bootstrap-spark-dns.yaml -e zone=t.<domain>
   ```

6. **Verify** (recursive resolution reaches the server; then a real fetch through the tunnel):
   ```sh
   dig @1.1.1.1 SOA t.<domain>            # expect NOERROR (the QNAME-min / NODATA handling)
   # client-side: DnsTunnelConfig{ zone=t.<domain>, server_pubkey=<pubkey>, resolvers=[public pool] }
   ```

## Operational notes

- **Duplication** (`DnsTunnelConfig.duplication`, default 1): set **3–5** for shutdown/last-resort
  profiles — it turns serial failover through dead resolvers into parallel discovery of whichever
  subset still works (measured 27 s → 0.3 s time-to-first-byte through a mostly-dead pool).
- **System resolvers** (`use_system_resolvers`, default true): auto-includes the OS/ISP resolver —
  often the only one that still forwards DNS during a national shutdown.
- **Throughput** is throttle-bound recursively (~0.1 Mbit/s via public resolvers; ~10 Mbit/s
  direct-to-server on a non-throttling path). This is the reachability-under-shutdown tier.
- **Forward secrecy**: the server's static key only *authenticates* the handshake (Ed25519
  signature); per-session keys come from an ephemeral↔ephemeral X25519 exchange, so a compromised
  static key (or a leaked client config) cannot decrypt past traffic. The client is anonymous.
- **Log hygiene**: the server never logs the zone, keys, target, or resolver IPs.
