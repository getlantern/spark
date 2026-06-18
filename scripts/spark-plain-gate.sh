#!/usr/bin/env bash
# Live gate (macOS): tunnel one TCP destination through spark's PLAIN transport to a remote relay
# and prove the egress IP changes to the relay's. This is the M4 live gate against a real internet
# server (the relay = scripts/spark-plain-relay.py on a DigitalOcean droplet).
#
# Run with sudo (opens the TUN + adds a host route); it cleans both up on exit.
#   sudo RELAY=137.184.47.220:9000 scripts/spark-plain-gate.sh
#
# Env: RELAY (host:port of the relay), TARGET_HOST (an IP-echo service), SPARK (path to the binary).
set -euo pipefail

RELAY="${RELAY:?set RELAY=<droplet-ip>:9000}"
RELAY_IP="${RELAY%%:*}"
TARGET_HOST="${TARGET_HOST:-icanhazip.com}"
SPARK="${SPARK:-target/release/spark}"
[ -x "$SPARK" ] || { echo "build spark first: cargo build --release --bin spark" >&2; exit 1; }
[ "$(id -u)" = 0 ] || { echo "run with sudo (needs to open the TUN + add a route)" >&2; exit 1; }

# Physical egress interface — spark pins its dial to the relay here so it bypasses the tun route.
IFACE=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
# Resolve the target now, directly (DNS does NOT go through the tun); we route just this IP in.
TARGET_IP=$(dig +short "$TARGET_HOST" A | grep -E '^[0-9.]+$' | head -1)
[ -n "$IFACE" ] && [ -n "$TARGET_IP" ] || { echo "could not detect iface ($IFACE) / resolve $TARGET_HOST ($TARGET_IP)" >&2; exit 1; }
echo "egress iface: $IFACE   relay: $RELAY   target: $TARGET_HOST -> $TARGET_IP"

# 1. Bring up the tunnel (plain transport → the relay).
"$SPARK" run --server "$RELAY" --protect-interface "$IFACE" >/tmp/spark-gate.log 2>&1 &
SPARK_PID=$!
cleanup() {
  route -n delete -host "$TARGET_IP" >/dev/null 2>&1 || true
  kill "$SPARK_PID" 2>/dev/null || true
}
trap cleanup EXIT
sleep 3

# 2. Find spark's TUN (the interface carrying 10.0.0.1) and route the target IP into it.
TUN=$(ifconfig | awk '/^utun[0-9]+:/{d=$1} /inet 10\.0\.0\.1 /{print d}' | tr -d ':' | head -1)
[ -n "$TUN" ] || { echo "spark TUN did not come up. log:" >&2; cat /tmp/spark-gate.log >&2; exit 1; }
echo "tun: $TUN"
route -n add -host "$TARGET_IP" -interface "$TUN" >/dev/null

# 3. curl through the tun (pinned to the routed IP). The echoed IP should be the RELAY's.
echo "--- curl https://$TARGET_HOST through the tunnel (expect $RELAY_IP) ---"
SEEN=$(curl -s --max-time 25 --resolve "$TARGET_HOST:443:$TARGET_IP" "https://$TARGET_HOST" | tr -d '[:space:]')
echo "egress IP seen: $SEEN"
if [ "$SEEN" = "$RELAY_IP" ]; then
  echo "✅ PASS — traffic egressed via the relay ($RELAY_IP); the tunnel works over the internet."
else
  echo "❌ did not see the relay IP (got '$SEEN'). spark log:" >&2; cat /tmp/spark-gate.log >&2
  exit 1
fi
