---
name: redeploy-dns-tunnel
description: Deploy, redeploy, verify, or debug the spark DNS-tunnel server (the last-resort bootstrap tier). Use when the dns-tunnel race member is failing, after provisioning a new host, when rotating the zone or server key, or when asked to deploy/redeploy the DNS tunnel.
---

# Redeploying the DNS-tunnel server

The DNS tunnel is spark's **last-resort bootstrap tier**: it needs only that recursive DNS resolves
at all, which is close to the last thing a network turns off. It is slow (KB/s) and expected to lose
every config-fetch race it does not have to win.

**Read this before touching anything.** Most of the failure modes below are silent — the server keeps
answering correctly on its own port while being completely unreachable to every real client.

## Establish the current state first

There may already be a running server. Check before provisioning anything.

```sh
linode-cli --suppress-warnings linodes list --tags spark-dns --json |
  python3 -c "import sys,json;[print(x['label'], x['status'], x['ipv4'][0]) for x in json.load(sys.stdin)]"
```

Then walk the chain **in this order**, because each step only makes sense if the previous one holds:

| # | check | command | healthy |
|---|---|---|---|
| 1 | service up | `ssh root@HOST systemctl is-active spark-dns` | `active` |
| 2 | answers on its own port | `dig -p 5300 @HOST SOA <zone>` | `NOERROR`, `flags: qr aa` |
| 3 | DNAT `:53→:5300` | `ssh root@HOST iptables -t nat -L PREROUTING -n` | a `REDIRECT udp dpt:53 → 5300` |
| 4 | answers on :53 | `dig @HOST SOA <zone>` | `NOERROR` |
| 5 | no cloud firewall | `linode-cli linodes firewalls-list <id>` | none, or UDP/53 allowed |
| 6 | glue record | `dig +short A ns-spark.<domain>` | the host IP |
| 7 | **delegation** | `dig +norec NS t.example.com @<the domain's NS>` | `NS ns-spark.…` |
| 8 | recursive reachability | `dig @1.1.1.1 SOA t.example.com` | `NOERROR` |
| 9 | real traffic | see *End-to-end test* | an HTTP status line |

### Traps in that sequence

- **Query the zone, not an arbitrary name.** `dig @HOST SOA example.com` times out *by design* — the
  server ignores out-of-zone queries. That is not a port-53 problem, though it looks exactly like one.
- **Step 7 is the one that is usually missing.** The glue A record and the NS record are two separate
  records and it is easy to add only the first. Without the NS record nothing is delegated, so steps
  1–6 all pass and no client on earth can reach the server.
- **`dig +short NS t.<domain>` via a recursive resolver returns empty even when healthy** — our server
  is authoritative for that zone and answers NODATA for anything that is not tunnel traffic. Ask the
  *parent's* nameserver with `+norec`, as in the table.
- **A proxied glue record breaks everything.** If `dig +short A ns-spark.<domain>` returns a
  Cloudflare address (104.x / 172.67.x) instead of the host IP, the record is orange-clouded and UDP
  never reaches the host. It must be DNS-only.

## Redeploy

> Commands below use `example.com` as a stand-in — RFC 2606 reserves it, so a
> forgotten substitution fails loudly instead of deploying somewhere real. Replace it with the
> delegated zone, which is deliberately not written down in this repo.

```sh
# 1. Static binary (aarch64-unknown-linux-musl for ARM hosts)
cargo zigbuild --release -p dns-tunnel-server --target x86_64-unknown-linux-musl
cp target/x86_64-unknown-linux-musl/release/dns-tunnel-server deploy/ansible/files/

# 2. Private key — ONLY when standing up a new server (see "Key rotation" first)
./deploy/ansible/files/dns-tunnel-server keygen        # prints privkey + pubkey
echo '<privkey b64>' > deploy/ansible/files/spark-dns.privkey

# 3. Deploy (needs `brew install ansible`)
cp deploy/ansible/inventory/spark-dns.example.yaml deploy/ansible/inventory/spark-dns.yaml
#   …set ansible_host to the real IP…
ansible-playbook -i deploy/ansible/inventory/spark-dns.yaml \
  deploy/ansible/bootstrap-spark-dns.yaml -e zone=t.example.com
```

The playbook is idempotent; re-running it against a live host only restarts on a real change.

## Key rotation is destructive

The server's public key is what every client uses to authenticate it. **Running `keygen` against an
existing server orphans every client already configured for the old key** — they will fail to
handshake and the tier goes dark until a new client build ships.

To recover a *lost* public key without rotating, derive it from the private key the host already
holds — on the host, so the private half never moves:

```sh
scp target/x86_64-unknown-linux-musl/release/dns-tunnel-server root@HOST:/tmp/dts
ssh root@HOST '/tmp/dts pubkey --privkey-file /etc/spark-dns/privkey; rm -f /tmp/dts'
```

It is also cached at `/etc/spark-dns/pubkey` on the host. Keep it there.

## Changing the zone

Three places, and all three must agree or the tunnel silently fails:

1. `--zone` in `/etc/systemd/system/spark-dns.service` (the server answers for **one** zone only)
2. the two DNS records at the new domain — glue `ns-spark.<new>` A → host, then `t.<new>` NS → that
3. the `SPARK_BOOTSTRAP_DNS_ZONE` repo variable

The binary needs no rebuild. Restart with `systemctl daemon-reload && systemctl restart spark-dns`.

**Zone length is a throughput decision, not cosmetics.** Every query is `<base32 payload>.<zone>`
inside DNS's 255-byte name limit, so the zone comes straight off the uplink budget — roughly
0.5 bytes of payload per character of zone:

| zone | uplink bytes/query |
|---|---|
| `t.ab.io` | 151 |
| `t.xyz.uk` (8 chars) | 150 |
| `dns.mycompany-vpn.net` | 142 |
| `tunnel.some-longer-domain.example.org` | 129 |

**The domain must be unattributable.** Not a known Lantern domain, and ideally registered apart from
them. A censor who can name the zone blocks this tier without analysing a single packet — which is
the whole reason the tier exists. Never commit the live zone to this repo (it is intended to be
public); docs here say `t.<domain>`.

## Reboot persistence

The `:53→:5300` redirect must survive reboot, and its absence is invisible: systemd restores the
server on `:5300`, the service reports `active`, direct queries to `:5300` succeed, and every
recursive resolver gets nothing. It reads as "the tier is blocked".

The playbook installs `iptables-persistent` and saves the rules. Verify on any host you inherit:

```sh
ssh root@HOST 'systemctl is-enabled netfilter-persistent; grep -c 5300 /etc/iptables/rules.v4'
```

Expect `enabled` and `1`.

## End-to-end test

The client's live test drives a real HTTP request through the tunnel. `DNS_TUNNEL_SERVER` is a
resolver list, so the same test covers both modes — **run both**, because authoritative passing while
recursive fails is precisely the delegation bug above:

```sh
export DNS_TUNNEL_PUBKEY='PASTE_BASE64_PUBKEY' DNS_TUNNEL_ZONE='t.example.com'

# authoritative — proves the server and protocol
DNS_TUNNEL_SERVER="<host-ip>:53" \
  cargo test -p spark-core --lib --features dns-tunnel -- --ignored --nocapture live_authoritative_fetch

# recursive — proves what a censored client actually gets
DNS_TUNNEL_SERVER="1.1.1.1,8.8.8.8,9.9.9.9" \
  cargo test -p spark-core --lib --features dns-tunnel -- --ignored --nocapture live_authoritative_fetch
```

Both should print an HTTP status line. Recursive is slower (throttled by the resolvers) — that is
expected, not a fault.

## Turning the client member on

The member is absent unless the build pins its parameters, and absence is deliberate rather than
broken — an unpinned build simply races the other four avenues.

```sh
gh variable set SPARK_BOOTSTRAP_DNS_ZONE   --repo getlantern/spark --body 't.example.com'
gh variable set SPARK_BOOTSTRAP_DNS_PUBKEY --repo getlantern/spark --body 'PASTE_BASE64_PUBKEY'
# SPARK_BOOTSTRAP_DNS_RESOLVERS: leave unset. The client then uses the OS resolver, which is often
# the only one still forwarding under a shutdown, and hardcoded public IPs are both the first thing
# blocked and a static fingerprint in the binary.
```

Confirm the member registers by compiling with the values set:

```sh
SPARK_BOOTSTRAP_DNS_ZONE=... SPARK_BOOTSTRAP_DNS_PUBKEY=... \
  cargo test -p spark-core --lib --features prod -- the_race_has_one_member_per_enabled_avenue
```

That test derives its expectation from each member's real precondition, so it fails if the member
does not appear.

## What not to do

- Do not commit the zone, the host IP, or the private key. The public key is not secret, but it is
  deployment state — it belongs on the host and in the repo variable.
- Do not run `keygen` to "refresh" a working server. See *Key rotation is destructive*.
- Do not add a Linode cloud firewall without allowing UDP/53; the host has none today and iptables'
  `INPUT` policy is `ACCEPT`.
