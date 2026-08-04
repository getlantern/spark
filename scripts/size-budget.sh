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
# Budget headroom is sized for the *Linux* ELF, not the macOS Mach-O measured below. This script's
# own history records why: at the 4 MiB scale the Linux binary ran ~20% fatter (opt-level = 3), which
# is what forced 4 -> 4.25 MiB. Applying that ratio to the measured 8.24 MiB macOS spark-service puts
# Linux near 9.9 MiB, so a 10 MiB budget would sit at ~99% and fail on the first innocent change.
# 12 MiB leaves ~18% on the fattest expected binary.
FEATURES=${FEATURES:-prod}
BUDGET=${BUDGET:-$((12 * 1024 * 1024))}   # 12 MiB; measured 8.24 MiB spark-service on macOS arm64
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
