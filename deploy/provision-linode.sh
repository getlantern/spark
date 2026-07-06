#!/usr/bin/env bash
# Provision a Linode instance for the spark dns-tunnel-server and print its public IP.
#
# Lantern runs dnstt on OCI (see lantern-cloud ans/bootstrap-dnstt.yaml); spark production targets
# Linode, which Lantern already uses (unbounded egress). Requires `linode-cli` + a LINODE_TOKEN with
# instance-create scope. After this, add the delegation records (see deploy/README.md), put the IP in
# the Ansible inventory, and run bootstrap-spark-dns.yaml.
set -euo pipefail

label="${1:-spark-dns}"
region="${LINODE_REGION:-us-east}"
plan="${LINODE_PLAN:-g6-nanode-1}" # 1 GB, ~$5/mo — plenty for the server
sshkey="${SPARK_DNS_SSHKEY:-$HOME/.ssh/spark-dns-tunnel.pub}"

[ -f "$sshkey" ] || { echo "missing SSH pubkey at $sshkey (set SPARK_DNS_SSHKEY)" >&2; exit 1; }

linode-cli --suppress-warnings linodes create \
  --type "$plan" --region "$region" --image linode/ubuntu24.04 \
  --label "$label" --root_pass "Spark-$(openssl rand -hex 16)!" \
  --authorized_keys "$(cat "$sshkey")" \
  --tags spark-dns --json \
  | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['ipv4'][0])"
