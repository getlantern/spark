#!/usr/bin/env bash
# netns-throughput.sh — measure spark's userspace (smoltcp) data-path throughput + CPU against a
# raw-kernel-TCP baseline, using Linux network namespaces.
#
# WHY netns: a single-box end-to-end tunnel benchmark is impossible on macOS (the kernel hairpins
# traffic to a local IP straight to lo0, before the route table, so you can't force it through the
# TUN). On Linux we put the iperf3 server in its OWN namespace, so its IP is not local to the
# namespace running spark — routing it via the TUN actually takes effect, and there is no hairpin.
# This is how sing-box / WireGuard benchmark, and it runs unattended in CI.
#
# Topology (two namespaces joined by a veth pair):
#
#     ns sparkb-cli                                   ns sparkb-srv
#   ┌─────────────────────────────────┐             ┌──────────────────┐
#   │ iperf3 client                   │             │ iperf3 server    │
#   │   │ connect 10.200.0.2          │             │  (10.200.0.2)    │
#   │   ▼                             │   veth      │       ▲          │
#   │ route 10.200.0.2/32 dev tunX ──▶ tunX (spark) │       │          │
#   │                       spark dials 10.200.0.2 ─┼─ vbc ═╪═ vbs ─────┘
#   │                       pinned to vbc (IP_UNICAST_IF, skips the tun route)
#   └─────────────────────────────────┘
#
# BASELINE (kernel): client → server straight over the veth (no tun route). The ceiling a
# system/kernel stack would approach.
# TUNNEL (smoltcp): client → server via the TUN (spark terminates TCP in userspace, re-dials).
# The gap (and spark's CPU) is the headroom a kernel-TCP "system stack" could recover.
#
# Usage:  sudo ./bench/netns-throughput.sh [--spark PATH] [--duration SECS] [--streams N]
# Env:    SPARK_BIN, DURATION, STREAMS (flags win over env).
#
# Extensible: when spark grows a `stack = system` option, add a second measure_tunnel call with
# that stack — the report loop already prints whatever rows you push into RESULTS.

set -euo pipefail

# ---- config -----------------------------------------------------------------
SPARK_BIN="${SPARK_BIN:-./target/release/spark}"
DURATION="${DURATION:-15}"
STREAMS="${STREAMS:-1}"

NS_CLI=sparkb-cli
NS_SRV=sparkb-srv
VBC=vbc                 # veth, cli side
VBS=vbs                 # veth, srv side
CLI_IP=10.200.0.1
SRV_IP=10.200.0.2
VETH_CIDR=24
TUN_ADDR=10.0.0.1
TUN_PREFIX=24
TUN_NAME=sparkb0
PORT=5201

while [[ $# -gt 0 ]]; do
  case "$1" in
    --spark)    SPARK_BIN="$2"; shift 2 ;;
    --duration) DURATION="$2";  shift 2 ;;
    --streams)  STREAMS="$2";   shift 2 ;;
    -h|--help)  grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# ---- preflight --------------------------------------------------------------
[[ $EUID -eq 0 ]] || { echo "must run as root (netns + TUN need privilege)" >&2; exit 1; }
for tool in ip iperf3; do
  command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 1; }
done
[[ -x "$SPARK_BIN" ]] || { echo "spark binary not found/executable: $SPARK_BIN (build it on THIS host: cargo build --release)" >&2; exit 1; }
JQ=""; command -v jq >/dev/null && JQ=jq
PY=""; command -v python3 >/dev/null && PY=python3
[[ -n "$JQ" || -n "$PY" ]] || { echo "need jq or python3 to parse iperf3 JSON" >&2; exit 1; }

SPARK_PID=""
declare -a RESULTS=()   # "label|gbps_up|gbps_down|cpu_pct"

cleanup() {
  set +e
  [[ -n "$SPARK_PID" ]] && kill "$SPARK_PID" 2>/dev/null
  ip netns pids "$NS_SRV" 2>/dev/null | xargs -r kill 2>/dev/null
  ip netns del "$NS_CLI" 2>/dev/null
  ip netns del "$NS_SRV" 2>/dev/null
  ip link del "$VBC" 2>/dev/null   # harmless if already moved/deleted
}
trap cleanup EXIT

# parse iperf3 -J: bits/sec for the receiver (sum_received), the meaningful end-to-end number.
bps_received() {
  if [[ -n "$JQ" ]]; then jq -r '.end.sum_received.bits_per_second // 0' "$1"
  else "$PY" -c 'import json,sys; print(json.load(open(sys.argv[1]))["end"]["sum_received"]["bits_per_second"])' "$1"; fi
}
gbps() { awk -v b="$1" 'BEGIN{printf "%.2f", b/1e9}'; }

# ---- topology ---------------------------------------------------------------
echo "==> building netns topology ($NS_CLI <-veth-> $NS_SRV)"
cleanup   # clear any leftovers from a previous aborted run
ip netns add "$NS_CLI"
ip netns add "$NS_SRV"
ip link add "$VBC" type veth peer name "$VBS"
ip link set "$VBC" netns "$NS_CLI"
ip link set "$VBS" netns "$NS_SRV"
ip -n "$NS_CLI" addr add "$CLI_IP/$VETH_CIDR" dev "$VBC"
ip -n "$NS_SRV" addr add "$SRV_IP/$VETH_CIDR" dev "$VBS"
for ns in "$NS_CLI" "$NS_SRV"; do ip -n "$ns" link set lo up; done
ip -n "$NS_CLI" link set "$VBC" up
ip -n "$NS_SRV" link set "$VBS" up

echo "==> starting iperf3 server in $NS_SRV ($SRV_IP:$PORT)"
ip netns exec "$NS_SRV" iperf3 -s -p "$PORT" >/dev/null 2>&1 &
sleep 0.5

# ---- baseline: kernel TCP straight over the veth ----------------------------
run_iperf() {  # $1=outfile  $2=extra-args(e.g. -R)
  ip netns exec "$NS_CLI" iperf3 -c "$SRV_IP" -p "$PORT" -t "$DURATION" -P "$STREAMS" -J ${2:-} > "$1"
}
echo "==> baseline (kernel TCP, no tunnel): up + down, ${DURATION}s x ${STREAMS} stream(s)"
B_UP=$(mktemp); B_DN=$(mktemp)
run_iperf "$B_UP"
run_iperf "$B_DN" "-R"
RESULTS+=("kernel-baseline|$(gbps "$(bps_received "$B_UP")")|$(gbps "$(bps_received "$B_DN")")|n/a")

# ---- tunnel: spark userspace (smoltcp) --------------------------------------
echo "==> starting spark in $NS_CLI (direct mode, TUN $TUN_ADDR, pinned to $VBC)"
ip netns exec "$NS_CLI" "$SPARK_BIN" run \
  --name "$TUN_NAME" --addr "$TUN_ADDR" --prefix "$TUN_PREFIX" \
  --protect-interface "$VBC" >/tmp/sparkb.log 2>&1 &

# Resolve spark's PID by its unique --name arg rather than $! — `ip netns exec` may fork before it
# execs spark, so $! can be a short-lived wrapper. pgrep -f on the unique TUN name is reliable.
for _ in $(seq 1 25); do
  SPARK_PID=$(pgrep -f "name $TUN_NAME" | head -1 || true)
  [[ -n "$SPARK_PID" ]] && break
  sleep 0.2
done
[[ -n "$SPARK_PID" ]] || { echo "spark did not start; see /tmp/sparkb.log" >&2; cat /tmp/sparkb.log >&2; exit 1; }

# wait for the TUN to appear in the cli ns, then resolve its actual name (OS may rename)
TUN_IF=""
for _ in $(seq 1 50); do
  kill -0 "$SPARK_PID" 2>/dev/null || { echo "spark exited early; see /tmp/sparkb.log" >&2; cat /tmp/sparkb.log >&2; exit 1; }
  TUN_IF=$(ip -n "$NS_CLI" -o addr show 2>/dev/null | awk -v a="$TUN_ADDR" '$0 ~ a"/" {print $2}' | head -1)
  [[ -n "$TUN_IF" ]] && break
  sleep 0.2
done
[[ -n "$TUN_IF" ]] || { echo "spark TUN never came up; see /tmp/sparkb.log" >&2; cat /tmp/sparkb.log >&2; exit 1; }
echo "    spark TUN = $TUN_IF (pid $SPARK_PID)"

# route the server INTO the tunnel; spark's pinned dial (IP_UNICAST_IF=$VBC) skips this route.
ip -n "$NS_CLI" route add "$SRV_IP/32" dev "$TUN_IF"

# sanity: a 2s transfer must actually pass through the tunnel before we trust the numbers.
echo "==> sanity check: 2s transfer through the tunnel"
S=$(mktemp)
ip netns exec "$NS_CLI" iperf3 -c "$SRV_IP" -p "$PORT" -t 2 -J > "$S" 2>/dev/null || { echo "tunnel transfer FAILED; see /tmp/sparkb.log" >&2; cat /tmp/sparkb.log >&2; exit 1; }
awk -v b="$(bps_received "$S")" 'BEGIN{ if (b+0 <= 0) { print "tunnel carried 0 bits — aborting"; exit 1 } }'

# CPU of spark over the measured window: utime+stime (ticks) delta / CLK_TCK / wall, all threads.
cpu_of() {  # echoes utime+stime ticks for $SPARK_PID
  awk '{print $14+$15}' "/proc/$SPARK_PID/stat"
}
TICK=$(getconf CLK_TCK)
echo "==> tunnel (spark smoltcp): up + down, ${DURATION}s x ${STREAMS} stream(s)"
T_UP=$(mktemp); T_DN=$(mktemp)
# Normalize CPU ticks by the ACTUAL wall time around the transfers, not an assumed DURATION*2 —
# a stalled transfer runs long, and a fixed divisor then reports nonsensically high CPU.
c0=$(cpu_of); w0=$(date +%s.%N)
run_iperf "$T_UP"; run_iperf "$T_DN" "-R"
w1=$(date +%s.%N); c1=$(cpu_of)
CPU=$(awk -v a="$c0" -v b="$c1" -v tk="$TICK" -v w0="$w0" -v w1="$w1" \
      'BEGIN{printf "%.0f", (b-a)/tk/(w1-w0)*100}')
RESULTS+=("spark-smoltcp|$(gbps "$(bps_received "$T_UP")")|$(gbps "$(bps_received "$T_DN")")|${CPU}%")

# ---- report -----------------------------------------------------------------
echo
echo "================ spark throughput benchmark ================"
echo "duration=${DURATION}s/dir  streams=${STREAMS}  host=$(uname -srm)"
printf "%-18s %12s %12s %10s\n" "stack" "up(Gb/s)" "down(Gb/s)" "spark CPU"
printf -- "------------------ ------------ ------------ ----------\n"
for r in "${RESULTS[@]}"; do IFS='|' read -r l u d c <<<"$r"; printf "%-18s %12s %12s %10s\n" "$l" "$u" "$d" "$c"; done
echo
# headroom = how much of the kernel ceiling the userspace stack leaves on the table.
IFS='|' read -r _ bu bd _ <<<"${RESULTS[0]}"
IFS='|' read -r _ tu td tc <<<"${RESULTS[1]}"
awk -v bu="$bu" -v bd="$bd" -v tu="$tu" -v td="$td" -v tc="$tc" 'BEGIN{
  printf "NOTE: the kernel-baseline is loopback-class (no real NIC, giant GSO segments) — read the\n";
  printf "ABSOLUTE spark throughput + CPU, not the %% (the %% is an upper bound on possible headroom).\n";
  printf "userspace stack: %.2f/%.2f Gb/s up/down at %s CPU; %.0f%%/%.0f%% of the loopback ceiling.\n", tu, td, tc, tu/bu*100, td/bd*100;
  printf "A kernel/system stack makes each flow a real kernel socket (parallel, kernel congestion\n";
  printf "control, no single poll-loop bottleneck) + sheds reassembly CPU. If spark already saturates\n";
  printf "your real uplink at low CPU, the system stack is not worth its complexity (design doc §9).\n";
}'
rm -f "$B_UP" "$B_DN" "$T_UP" "$T_DN" "$S"
