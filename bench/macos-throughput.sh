#!/usr/bin/env bash
# macos-throughput.sh — measure spark's data-path throughput + CPU on macOS, userspace (smoltcp)
# vs the kernel-TCP `system` stack, against a REMOTE iperf3 peer.
#
# WHY A REMOTE PEER IS MANDATORY: on macOS a single-box tunnel benchmark is impossible. The kernel
# hairpins traffic addressed to a local IP straight to lo0 *before* the route table is consulted, so
# a route pointing that address at the TUN never takes effect. Linux sidesteps this with network
# namespaces (see netns-throughput.sh, which is why that harness exists); macOS has no equivalent.
# The peer must therefore be a genuinely different host — a machine on the LAN, a VM with its own
# routable IP (Lima/UTM, *not* Docker Desktop, whose containers aren't routable from the host), or a
# cloud box. Anything whose address is not configured on this Mac.
#
# Topology:
#
#   ┌──────────────────── this Mac ────────────────────┐          ┌─────────────┐
#   │ iperf3 client                                    │          │ iperf3 -s   │
#   │   │ connect $PEER                                │          │  ($PEER)    │
#   │   ▼                                              │          │      ▲      │
#   │ route -host $PEER -interface utunN ──▶ utunN ────┤          │      │      │
#   │                        spark dials $PEER pinned to $EGRESS ──┼──────┘      │
#   │                        (IP_BOUND_IF — skips the /32 above)  │             │
#   └──────────────────────────────────────────────────┘          └─────────────┘
#
# BASELINE: client → peer directly over $EGRESS (no /32 route). The ceiling for this link.
# TUNNEL:   client → peer via the TUN, spark terminating TCP in whichever stack is selected.
#
# The headline metric is NOT peak throughput — it is the CONCURRENT-DOWNLOAD COLLAPSE. On Linux the
# userspace stack craters from ~1.5 Gb/s to ~0.13 at two parallel downloads while the system stack
# holds ~1.09 (docs/system-stack-design.md §9). Run with --streams 1 and --streams 2+ and compare
# the download column; that gap is visible on any link faster than ~200 Mb/s.
#
# Usage:
#   sudo ./bench/macos-throughput.sh --peer 192.168.4.50 [--stack userspace|system]
#                                    [--duration SECS] [--streams N] [--spark PATH]
#                                    [--egress IFNAME] [--port N] [--smoke]
#
#   --smoke   run only the preflight + a 2s transfer, then exit. Use this FIRST for --stack system:
#             prove it carries traffic at all before trusting any numbers.
#
#   --udp     measure the UDP datagram path instead of TCP (--udp-rate, default 20M).
#             Worth its own mode because the two stacks handle UDP differently: the kernel "system"
#             stack terminates TCP in the kernel but keeps UDP in userspace (sing-box calls this
#             combination "mixed"), so a TCP-only run can pass on a build whose datagram path is
#             entirely dead. DNS rides that path, and a tunnel that resolves nothing is useless
#             however healthy TCP looks. Reports rate AND loss: either alone misleads.
#             Note UDP is open-loop — iperf3 sends at --udp-rate no matter what arrives — so keep
#             the rate under the link or you measure the wire saturating, not the stack.
#
# Peer setup: `iperf3 -s -p 5201` on the peer, reachable from this Mac.
#
# Build:  cargo build --release                          # userspace
#         cargo build --release --features system-stack  # required for --stack system
#
set -euo pipefail

# ---- config -----------------------------------------------------------------
SPARK_BIN="${SPARK_BIN:-./target/release/spark}"
DURATION="${DURATION:-15}"
STREAMS="${STREAMS:-1}"
STACK="${STACK:-userspace}"
PEER="${PEER:-}"
PORT="${PORT:-5201}"
EGRESS="${EGRESS:-}"
SMOKE=0
UDP=0
# UDP is an open-loop send: iperf3 blasts at this rate regardless of what gets through, so loss is
# only meaningful when the rate sits comfortably under the link. Above it, you measure the wire
# saturating and every stack looks broken.
UDP_RATE="${UDP_RATE:-20M}"
TUN_ADDR="10.7.7.1"
TUN_PREFIX=24

while [[ $# -gt 0 ]]; do
  case "$1" in
    --peer)     PEER="$2";      shift 2 ;;
    --spark)    SPARK_BIN="$2"; shift 2 ;;
    --duration) DURATION="$2";  shift 2 ;;
    --streams)  STREAMS="$2";   shift 2 ;;
    --stack)    STACK="$2";     shift 2 ;;
    --egress)   EGRESS="$2";    shift 2 ;;
    --port)     PORT="$2";      shift 2 ;;
    --smoke)    SMOKE=1;        shift   ;;
    --udp)      UDP=1;          shift   ;;
    --udp-rate) UDP_RATE="$2";  shift 2 ;;
    # Prints the header block by *shape* rather than by line number: this range has silently
    # drifted twice as the header grew, truncating --help mid-sentence with nothing to catch it.
    # Emit from line 2 until the first line that is not a comment.
    -h|--help)  awk 'NR>1 && !/^#/{exit} NR>1' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

die() { echo "error: $*" >&2; exit 1; }

# ---- preflight --------------------------------------------------------------
[[ "$(uname -s)" == Darwin ]] || die "this harness is macOS-only; on Linux use bench/netns-throughput.sh"
[[ $EUID -eq 0 ]] || die "must run as root (opening a TUN and editing the route table)"
[[ -n "$PEER" ]]  || die "--peer <ip> is required; see the header for why it cannot be this machine"
[[ -x "$SPARK_BIN" ]] || die "spark binary not found at $SPARK_BIN (cargo build --release)"
command -v iperf3 >/dev/null || die "iperf3 not found — brew install iperf3"
case "$STACK" in userspace|system) ;; *) die "--stack must be userspace or system" ;; esac

# The peer must not be one of OUR addresses, or every packet hairpins to lo0 and the whole run
# silently measures loopback instead of the tunnel. This is the single most important check here.
if ifconfig | awk '/inet /{print $2}' | grep -qx "$PEER"; then
  die "--peer $PEER is an address on this machine; macOS will hairpin it to lo0 and never consult
       the TUN route. Use a genuinely remote host (see the header)."
fi

# Resolve the physical egress BEFORE adding any route, so we pin spark to the real interface.
[[ -n "$EGRESS" ]] || EGRESS=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
[[ -n "$EGRESS" ]] || die "could not determine the default egress interface; pass --egress"
ifconfig "$EGRESS" >/dev/null 2>&1 || die "egress interface $EGRESS does not exist"

# A peer we cannot reach directly makes every later failure ambiguous.
nc -z -G 3 "$PEER" "$PORT" 2>/dev/null || die "cannot reach $PEER:$PORT — start 'iperf3 -s -p $PORT' there first"

JQ=$(command -v jq || true)
PY=$(command -v python3 || true)
[[ -n "$JQ" || -n "$PY" ]] || die "need jq or python3 to parse iperf3 JSON"

# macOS ships no GNU `timeout`; fall back to gtimeout, else run unguarded.
TIMEOUT=$(command -v timeout || command -v gtimeout || true)

echo "==> peer=$PEER:$PORT egress=$EGRESS stack=$STACK streams=$STREAMS duration=${DURATION}s"

# ---- cleanup ----------------------------------------------------------------
SPARK_PID=""
ROUTE_ADDED=0

# One private directory for every artifact this run creates, removed wholesale on exit — success,
# failure, and Ctrl-C alike — so repeated runs don't litter and concurrent runs can't collide.
#
# `mktemp -d` rather than fixed /tmp paths because this script runs as ROOT. /tmp is world-writable,
# so any unprivileged user can pre-create a symlink at a predictable name and root's `>` will follow
# it — an arbitrary-file-write as root. mktemp -d gives a 0700 directory with an unguessable name,
# which closes that off for everything below.
#
# A directory rather than a list of tracked files because the natural `f=$(new_tmp)` form runs in a
# subshell, where an append to a tracking variable is discarded in the parent and nothing would
# actually get cleaned. Named files also make a failed run inspectable before the trap fires.
WORKDIR=$(mktemp -d)
# The spark log lives here too. Every failure path below dumps it to stderr before exiting, so the
# trap removing it costs nothing diagnostically.
LOG="$WORKDIR/spark.log"
CONFIG="$WORKDIR/spark.toml"

cleanup() {
  # Order matters: drop the /32 first. A host route pointing at a utun that is about to disappear
  # would blackhole this Mac's traffic to the peer until someone noticed and deleted it by hand.
  if [[ "$ROUTE_ADDED" == 1 ]]; then
    route -n delete -host "$PEER" >/dev/null 2>&1 || true
    ROUTE_ADDED=0
  fi
  if [[ -n "$SPARK_PID" ]] && kill -0 "$SPARK_PID" 2>/dev/null; then
    kill "$SPARK_PID" 2>/dev/null || true
    for _ in $(seq 1 20); do kill -0 "$SPARK_PID" 2>/dev/null || break; sleep 0.1; done
    kill -9 "$SPARK_PID" 2>/dev/null || true
  fi
  # An `if` rather than `[[ ]] &&`: this is the last statement of an EXIT trap, and a false `&&` list
  # would return non-zero from the trap.
  if [[ -n "${WORKDIR:-}" ]]; then rm -rf "$WORKDIR"; fi
}
trap cleanup EXIT INT TERM

# ---- helpers ----------------------------------------------------------------
# iperf3 -J: bits/sec for the receiver (sum_received) — the meaningful end-to-end number.
bps_received() {  # robust to empty/invalid JSON (a timed-out run) → 0
  if [[ -n "$JQ" ]]; then jq -r '.end.sum_received.bits_per_second // 0' "$1" 2>/dev/null || echo 0
  else "$PY" -c 'import json,sys
try: print(json.load(open(sys.argv[1]))["end"]["sum_received"]["bits_per_second"])
except Exception: print(0)' "$1" 2>/dev/null || echo 0; fi
}
gbps() { awk -v b="$1" 'BEGIN{printf "%.3f", b/1e9}'; }

# UDP's numbers live in `.end.sum`, not `.end.sum_received` — and the field that matters is
# `lost_percent`, which has no TCP equivalent. A datagram path can be "fast" and still be useless.
# Echoes "<mbits>|<loss%>|<jitter_ms>|<packets>"; all zeros on unreadable JSON (a stalled run).
udp_stats() {
  if [[ -n "$JQ" ]]; then
    # The fallback lives in awk's END, not in a `|| echo`: when jq fails it prints nothing and exits
    # non-zero, but awk then reads empty input and exits *0*, so the `||` never fires and the
    # function returns an empty string instead of the zeros it promises.
    jq -r '[((.end.sum.bits_per_second // 0)/1e6), (.end.sum.lost_percent // 0), (.end.sum.jitter_ms // 0), (.end.sum.packets // 0)] | @tsv' "$1" 2>/dev/null \
      | awk -F'\t' '{printf "%.1f|%.2f|%.2f|%d", $1, $2, $3, $4; seen=1}
                     END{ if (!seen) printf "0.0|0.00|0.00|0" }'
  else
    "$PY" -c 'import json,sys
try:
    s=json.load(open(sys.argv[1]))["end"]["sum"]
    print("%.1f|%.2f|%.2f|%d" % (s.get("bits_per_second",0)/1e6, s.get("lost_percent",0), s.get("jitter_ms",0), s.get("packets",0)))
except Exception: print("0.0|0.00|0.00|0")' "$1" 2>/dev/null || echo "0.0|0.00|0.00|0"
  fi
}

# "<mbits> / <loss>%" — rate and loss together, because either alone misleads: a path can carry
# the full rate while dropping a third of it, and a path can drop nothing while carrying nothing.
udp_cell() {
  IFS='|' read -r mb loss _ pkts <<<"$(udp_stats "$1")"
  if [[ "${pkts:-0}" == 0 ]]; then echo "no datagrams"; else echo "$mb / $loss%"; fi
}

run_iperf() {  # $1=outfile  $2=extra-args (e.g. -R for download)
  # Guarded: a stalled direction must not hang the run. The userspace download path is exactly what
  # can stall here (§9), and an empty JSON reads back as 0 — i.e. "stalled" — so the run continues.
  #
  # Built up in the positional parameters rather than an array, because stock macOS is bash 3.2 where
  # expanding an EMPTY array under `set -u` aborts with "unbound variable". That is not hypothetical
  # here: `timeout` is a GNU tool absent from a stock macOS, so the no-coreutils machine — the most
  # likely one to run this — is exactly the case that would have an empty guard.
  local out="$1" extra="${2:-}"
  set -- iperf3 -c "$PEER" -p "$PORT" -t "$DURATION" -P "$STREAMS" -J
  # -u needs an explicit -b: iperf3's UDP default is 1 Mbit/s, which would "pass" on a dead path.
  [[ "$UDP" == 1 ]] && set -- "$@" -u -b "$UDP_RATE"
  [[ -n "$extra" ]] && set -- "$@" "$extra"
  [[ -n "$TIMEOUT" ]] && set -- "$TIMEOUT" "$((DURATION + 25))s" "$@"
  "$@" > "$out" 2>/dev/null \
    || echo "    (iperf timed out or errored — treating as stalled)" >&2
}

# Cumulative CPU seconds for the process, all threads. macOS has no /proc, so parse `ps -o cputime`
# ([HH:]MM:SS.ss).
cpu_secs() {
  ps -p "$SPARK_PID" -o cputime= 2>/dev/null \
    | awk -F: '{ if (NF==3) print $1*3600+$2*60+$3; else if (NF==2) print $1*60+$2; else print $1+0 }'
}

declare -a RESULTS=()   # "label|gbps_up|gbps_down|cpu_pct"

# ---- baseline: direct over the same link ------------------------------------
# The control. If baseline and tunnel are both pinned at the link rate, the run is link-bound and
# cannot discriminate between stacks on peak throughput — but the concurrency collapse still shows.
if [[ "$SMOKE" == 0 ]]; then
  echo "==> baseline (direct, no tunnel): up + down, ${DURATION}s x ${STREAMS} stream(s)"
  B_UP="$WORKDIR/base-up.json"; B_DN="$WORKDIR/base-down.json"
  run_iperf "$B_UP"
  run_iperf "$B_DN" "-R"
  if [[ "$UDP" == 1 ]]; then
    RESULTS+=("direct-baseline|$(udp_cell "$B_UP")|$(udp_cell "$B_DN")|n/a")
  else
    RESULTS+=("direct-baseline|$(gbps "$(bps_received "$B_UP")")|$(gbps "$(bps_received "$B_DN")")|n/a")
  fi
fi

# ---- start spark ------------------------------------------------------------
echo "==> starting spark ($STACK stack, TUN $TUN_ADDR, dials pinned to $EGRESS)"
if [[ "$STACK" == system ]]; then
  LABEL="spark-system"
  # `run`'s bare flags always select the userspace stack; `system` is reachable only via config.
  cat > "$CONFIG" <<TOML
[tun]
addr = "$TUN_ADDR"
prefix = $TUN_PREFIX
stack = "system"
[transport]
protect_interface = "$EGRESS"
TOML
  "$SPARK_BIN" run --config "$CONFIG" >"$LOG" 2>&1 &
else
  LABEL="spark-smoltcp"
  "$SPARK_BIN" run --addr "$TUN_ADDR" --prefix "$TUN_PREFIX" --protect-interface "$EGRESS" >"$LOG" 2>&1 &
fi
SPARK_PID=$!

# Wait for the utun to carry our address, resolving its kernel-assigned name (utunN is not stable).
TUN_IF=""
for _ in $(seq 1 60); do
  kill -0 "$SPARK_PID" 2>/dev/null || { echo "spark exited early:" >&2; cat "$LOG" >&2; exit 1; }
  for ifn in $(ifconfig -l); do
    if ifconfig "$ifn" 2>/dev/null | grep -q "inet $TUN_ADDR "; then TUN_IF="$ifn"; break; fi
  done
  [[ -n "$TUN_IF" ]] && break
  sleep 0.25
done
[[ -n "$TUN_IF" ]] || { echo "spark TUN never came up:" >&2; cat "$LOG" >&2; exit 1; }
echo "    spark TUN = $TUN_IF (pid $SPARK_PID)"

# Route the peer INTO the tunnel. The /32 beats any connected route, and spark's own dial skips it
# via IP_BOUND_IF on $EGRESS.
route -n add -host "$PEER" -interface "$TUN_IF" >/dev/null || die "could not add the host route"
ROUTE_ADDED=1

# ---- sanity: traffic must actually traverse the tunnel ----------------------
echo "==> sanity check: 2s $( [[ "$UDP" == 1 ]] && echo UDP || echo TCP ) transfer through the tunnel"
S="$WORKDIR/sanity.json"
# Speaks whichever protocol is under test. A TCP sanity check would report "ok" on a tunnel whose
# datagram path is completely dead, which is the exact failure this mode exists to find.
sanity_args=""
[[ "$UDP" == 1 ]] && sanity_args="-u -b $UDP_RATE"
if ! iperf3 -c "$PEER" -p "$PORT" -t 2 -J $sanity_args > "$S" 2>/dev/null; then
  echo "tunnel transfer FAILED — spark log:" >&2; cat "$LOG" >&2
  [[ "$STACK" == system ]] && cat >&2 <<'HINT'

NOTE: --stack system has never been live-gated on macOS (its only gate was Linux netns). The system
stack re-injects rewritten packets on the TUN destined to a LOCAL address, and on Linux that needed
reverse-path filtering relaxed (rp_filter=0). macOS has no rp_filter, but if packets are being
dropped on re-entry this is the first place to look. Also confirm the build has --features
system-stack: without it, selecting stack="system" fails at startup and the log says so.
HINT
  exit 1
fi
if [[ "$UDP" == 1 ]]; then
  IFS='|' read -r s_mb s_loss s_jit s_pkts <<<"$(udp_stats "$S")"
  # Datagrams *received* is the assertion. Rate alone would pass on a path that sends into a void,
  # since UDP is open-loop and iperf3 will happily report its own send rate.
  awk -v p="${s_pkts:-0}" 'BEGIN{ if (p+0 <= 0) { print "tunnel carried no datagrams — aborting"; exit 1 } }'
  echo "    ok — ${s_mb} Mb/s, ${s_loss}% loss, ${s_jit} ms jitter, ${s_pkts} datagrams over 2s"
else
  awk -v b="$(bps_received "$S")" 'BEGIN{ if (b+0 <= 0) { print "tunnel carried 0 bits — aborting"; exit 1 } }'
  echo "    ok — $(gbps "$(bps_received "$S")") Gb/s over 2s"
fi

if [[ "$SMOKE" == 1 ]]; then
  echo
  echo "smoke test PASSED: the $STACK stack carries traffic on macOS."
  exit 0
fi

# ---- measure ----------------------------------------------------------------
echo "==> tunnel ($LABEL): up + down, ${DURATION}s x ${STREAMS} stream(s)"
T_UP="$WORKDIR/tunnel-up.json"; T_DN="$WORKDIR/tunnel-down.json"
# Normalize CPU against the ACTUAL wall time spanned, not an assumed DURATION*2: a stalled transfer
# runs long, and a fixed divisor then reports nonsense.
c0=$(cpu_secs); w0=$(date +%s)
run_iperf "$T_UP"; run_iperf "$T_DN" "-R"
w1=$(date +%s); c1=$(cpu_secs)
CPU=$(awk -v a="${c0:-0}" -v b="${c1:-0}" -v w0="$w0" -v w1="$w1" \
      'BEGIN{ d=w1-w0; if (d<=0) { print "n/a"; exit } printf "%.0f%%", (b-a)/d*100 }')
if [[ "$UDP" == 1 ]]; then
  RESULTS+=("$LABEL|$(udp_cell "$T_UP")|$(udp_cell "$T_DN")|$CPU")
else
  RESULTS+=("$LABEL|$(gbps "$(bps_received "$T_UP")")|$(gbps "$(bps_received "$T_DN")")|$CPU")
fi

# ---- report -----------------------------------------------------------------
echo
if [[ "$UDP" == 1 ]]; then
  printf "%-18s %20s %20s %10s\n" "config" "up (Mb/s / loss)" "down (Mb/s / loss)" "spark CPU"
  printf "%-18s %20s %20s %10s\n" "------------------" "--------------------" "--------------------" "----------"
  for r in "${RESULTS[@]}"; do IFS='|' read -r l u d c <<<"$r"; printf "%-18s %20s %20s %10s\n" "$l" "$u" "$d" "$c"; done
else
  printf "%-18s %12s %12s %10s\n" "config" "up (Gb/s)" "down (Gb/s)" "spark CPU"
  printf "%-18s %12s %12s %10s\n" "------------------" "------------" "------------" "----------"
  for r in "${RESULTS[@]}"; do IFS='|' read -r l u d c <<<"$r"; printf "%-18s %12s %12s %10s\n" "$l" "$u" "$d" "$c"; done
fi
echo
cat <<'NOTE'
Reading this:
  * Compare --stack userspace vs --stack system at --streams 1 AND --streams 2+. The download
    column at 2+ streams is the point: on Linux, userspace collapses ~8x there while system holds.
  * If baseline and tunnel are both at the link rate, the run is link-bound — peak numbers say
    nothing about the stacks, but the concurrency collapse is still visible.
  * Single-stream upload is expected to be LOWER on the system stack (one rewrite pump is a
    serialization point). That is the known trade, not a regression.
NOTE
