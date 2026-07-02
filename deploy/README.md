# Deploying `dns-tunnel-server` (ADR 0011)

The spark DNS-tunnel server is a **drop-in modernization of Lantern's dnstt escalation tier** and
deploys with the same shape as `getlantern/lantern-cloud`'s dnstt automation
(`ans/bootstrap-dnstt.yaml`): a static binary + a systemd unit + a `:53→:5300` DNAT, fed by a
delegated authoritative subdomain. The only substantive differences:

| | dnstt | spark dns-tunnel |
|---|---|---|
| binary | `linux-dnstt-server` | `dns-tunnel-server` (static musl) |
| key | Noise keypair (`server.key`/`.pub`) | one base64 **PSK** |
| wire | dnstt (KCP+smux+Noise) | spark's own (ADR 0011) — **not** interop |
| provider (prod) | OCI | **Linode** |
| zone | `t.iantem.io` | an **unattributable** domain (e.g. `t.ss7hc6jm.io`) |

Because the wire protocols differ, spark needs its **own** server IP and its **own** delegated zone —
it cannot co-tenant dnstt's `:53`. They coexist fine (dnstt on `t.iantem.io`, spark elsewhere).

## What to reuse from lantern-cloud

- **Client config distribution.** Add a spark-dns config (zone / PSK / resolvers) alongside
  `common.DNSTTConfig` and ship it through the same `flashlight/genconfig` → cloud.yaml → config-server
  pipeline; clients already know how to receive a DNS-tunnel config and slot it into the escalation
  tier (`kindling/dnstt`, radiance).
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

4. **Generate a PSK** and place it for the playbook:
   ```sh
   openssl rand -base64 32 > deploy/ansible/files/spark-dns.psk   # ship the same value to clients
   ```

5. **Deploy** (put the IP in `inventory/spark-dns.yaml`, then):
   ```sh
   ansible-playbook -i deploy/ansible/inventory/spark-dns.yaml \
     deploy/ansible/bootstrap-spark-dns.yaml -e zone=t.<domain>
   ```

6. **Verify** (recursive resolution reaches the server; then a real fetch through the tunnel):
   ```sh
   dig @1.1.1.1 SOA t.<domain>            # expect NOERROR (the QNAME-min / NODATA handling)
   # client-side: DnsTunnelConfig{ zone=t.<domain>, psk=<same>, resolvers=[public pool] }
   ```

## Operational notes

- **Duplication** (`DnsTunnelConfig.duplication`, default 1): set **3–5** for shutdown/last-resort
  profiles — it turns serial failover through dead resolvers into parallel discovery of whichever
  subset still works (measured 27 s → 0.3 s time-to-first-byte through a mostly-dead pool).
- **System resolvers** (`use_system_resolvers`, default true): auto-includes the OS/ISP resolver —
  often the only one that still forwards DNS during a national shutdown.
- **Throughput** is throttle-bound recursively (~0.1 Mbit/s via public resolvers; ~10 Mbit/s
  direct-to-server on a non-throttling path). This is the reachability-under-shutdown tier.
- **Log hygiene**: the server never logs the zone, PSK, target, or resolver IPs.
