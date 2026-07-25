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

BUDGET=$(((4 * 1024 + 256) * 1024))   # 4.25 MiB
BINS=(spark spark-service)

echo "building release binaries..." >&2
cargo build --release --locked --bin spark --bin spark-service >&2

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
