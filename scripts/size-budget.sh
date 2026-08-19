#!/usr/bin/env bash
# Build the release binaries and fail if any exceeds the stripped size budget.
# Raised from the original 3 MiB to 4 MiB: the perf-driven `opt-level = 3` (over size's
# `opt-level = "z"`) grew the Linux ELF — `spark-service` lands ~3.0 MiB, just over 3 MiB — while
# the macOS Mach-O stays smaller. 4 MiB keeps a meaningful cap against bloat with headroom for both.
# Raised again to 4.25 MiB: capture-only diagnostics in the service (diag_wire — spool sink,
# panic hook, unclean-exit sentinel, DiagLayer) cost +66 KB on the Linux ELF, nudging
# spark-service from 98% to 8 KB past the 4 MiB line. Measured, deliberate feature weight —
# not dependency creep (serde_json's JSONL encode + the sink/sentinel machinery); no honest
# trim exists short of cutting the feature (a DiagLayer→LogForwarder fold was measured at
# only -1.3 KB net after LTO). 4.25 MiB keeps ~6% tripwire headroom on the fattest binary.
set -euo pipefail
cd "$(dirname "$0")/.."

# Gate the binaries we actually ship, not a default build nobody releases. This script measured
# `--bin spark --bin spark-service` with default features while release.yml shipped a much larger
# feature set, so the tripwire could not see the thing it was guarding: a regression behind any
# release-only feature was invisible until a tag was cut. It now builds the same `prod` set the
# release workflow does. (`bip324` is excluded, as it is in a release without a pinned module-signing
# key — it adds ~1.7 MiB and release.yml gates that branch separately.)
#
# The cost is honest: this pulls BoringSSL and a QUIC stack, so the job is slower than it was.
# A gate that measures the wrong binary is worse than a slow one.
#
# Budget headroom is sized for the *Linux* ELF, which is the fattest thing we build. The macOS/Linux
# ratio is measured: spark-service was 8.24 MiB on macOS arm64 and 10.75 MiB on x86_64 Linux — a 30%
# inflation from opt-level = 3, larger than the ~20% this script's older history implied. (A 10 MiB
# budget would have failed outright, which is how the real ratio was found.)
#
# Raised 12 -> 19 MiB for the Unbounded consumer, which `prod` now carries. This is the largest single
# feature cost in the tree and the number is measured on macOS arm64, same machine and profile, by
# building `prod` with and without it:
#
#   prod minus unbounded   9,156,000 B   8.73 MiB
#   prod                  13,345,680 B  12.73 MiB   (+4.00 MiB, +46%)
#
# The cost is webrtc-rs: 14 crates (webrtc + ice/dtls/sctp/srtp/turn/stun/mdns/rtp/rtcp/media/
# interceptor/data/util), and it is unavoidable rather than sloppy — the consumer speaks WebRTC to a
# volunteer by definition. Half of that graph (srtp/media/interceptor/rtp/rtcp) is media plumbing a
# DataChannel never touches, so a trimmed fork upstream is the only real lever if this needs to shrink.
#
# The Linux figure is PROJECTED, not measured: 12.73 x 1.30 (the ratio above) = ~16.6 MiB. 19 MiB
# leaves ~13% on that projection, in line with the ~11% this budget has always targeted. The CI `size`
# job on ubuntu-latest is what confirms it — if the real Linux ELF lands materially under ~16.6 MiB,
# tighten this back down rather than leaving slack a regression could hide in.
FEATURES=${FEATURES:-prod}
BUDGET=${BUDGET:-$((19 * 1024 * 1024))}   # 19 MiB; measured 12.73 MiB macOS arm64, ~16.6 MiB projected Linux
BINS=(spark spark-service)

echo "building release binaries (features: $FEATURES)..." >&2
cargo build --release --locked -p spark-cli -p spark-service --features "$FEATURES" >&2

status=0
for bin in "${BINS[@]}"; do
    path="target/release/$bin"
    # `stat -f%z` on macOS/BSD, `stat -c%s` on Linux.
    size=$(stat -f%z "$path" 2>/dev/null || stat -c%s "$path")
    pct=$((size * 100 / BUDGET))
    if [ "$size" -gt "$BUDGET" ]; then
        printf '%-16s %9d bytes  (%d%% of budget)  OVER BUDGET\n' "$bin" "$size" "$pct"
        status=1
    else
        printf '%-16s %9d bytes  (%d%% of budget)  ok\n' "$bin" "$size" "$pct"
    fi
done
exit $status
