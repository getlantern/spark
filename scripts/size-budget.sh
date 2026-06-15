#!/usr/bin/env bash
# Build the release binaries and fail if any exceeds the stripped size budget.
# The budget is a product constraint (CLAUDE.md): < 3 MB stripped per binary.
set -euo pipefail
cd "$(dirname "$0")/.."

BUDGET=$((3 * 1024 * 1024))   # 3 MiB
BINS=(spark spark-service)

echo "building release binaries..." >&2
cargo build --release >&2

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
