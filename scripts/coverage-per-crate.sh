#!/usr/bin/env bash
#
# Per-crate coverage gate (qiuth-patterns §6.4 deviation #1 follow-up).
#
# `cargo llvm-cov --fail-under-*` is workspace-wide; this script reads
# per-file JSON from the same llvm-cov run, sums (lines, covered) per
# workspace crate, and exits non-zero if any crate falls below its
# configured floor. Run AFTER `cargo llvm-cov --workspace --json
# --output-path coverage.json` has produced the report.
#
# Floors are intentionally conservative — each sits a few points below
# the measured value at the time the floor was set, leaving headroom for
# natural variance. Ratchet by bumping the `floor_for` cases below in a
# single-line PR alongside the test backfill that earned it. Workspace
# floors in `coverage.yml` are the wider safety net; per-crate floors
# protect the cleanly-covered crates from regression specifically.
#
# Usage:
#   ./scripts/coverage-per-crate.sh path/to/coverage.json

set -eu

if [ $# -ne 1 ]; then
    echo "usage: $0 <coverage.json>" >&2
    exit 2
fi
JSON="$1"

if ! command -v jq >/dev/null; then
    echo "error: jq is required" >&2
    exit 2
fi

# Per-crate line-coverage floors. Measured values as of 2026-05-16
# (rounds 1–8 of the §6.4 pure-helper backfill):
#   shared-types  100.00%  → floor 95
#   policy-engine  93.61%  → floor 88
#   proxy          48.91%  → floor 45
#   cli            13.95%  → floor 10
#
# Written as a case statement rather than an associative array so the
# script runs on bash 3 (the macOS system default) as well as bash 4+.
floor_for() {
    case "$1" in
        shared-types)  echo 95 ;;
        policy-engine) echo 88 ;;
        proxy)         echo 45 ;;
        cli)           echo 10 ;;
        *)             echo "" ;;
    esac
}

# Sum (lines_count, lines_covered) per crate by classifying each file's
# path. The classifier order has no overlap among current workspace
# crates, but be explicit.
AWK_SCRIPT='
{
    crate = "?"
    if ($3 ~ /\/shared-types\//) crate = "shared-types"
    else if ($3 ~ /\/policy-engine\//) crate = "policy-engine"
    else if ($3 ~ /\/cli\//) crate = "cli"
    else if ($3 ~ /\/proxy\//) crate = "proxy"
    total[crate] += $1
    covered[crate] += $2
}
END {
    for (c in total) {
        if (total[c] == 0) continue
        printf "%s %d %d %.4f\n", c, total[c], covered[c], 100.0 * covered[c] / total[c]
    }
}'

# Extract `lines_total lines_covered filename` per file, sum per crate.
rows=$(
    jq -r '.data[0].files[] | "\(.summary.lines.count) \(.summary.lines.covered) \(.filename)"' "$JSON" \
        | awk "$AWK_SCRIPT" \
        | sort
)

if [ -z "$rows" ]; then
    echo "error: no coverage rows extracted from $JSON" >&2
    exit 2
fi

printf "%-15s %10s %10s %8s %6s %-6s\n" "crate" "lines" "covered" "pct" "floor" "result"

fail=0
echo "$rows" | while IFS=' ' read -r crate lines covered pct; do
    floor=$(floor_for "$crate")
    if [ -z "$floor" ]; then
        printf "%-15s %10s %10s %7s%% %6s %-6s\n" \
            "$crate" "$lines" "$covered" "$pct" "—" "SKIP"
        echo "warning: no floor configured for crate '$crate' (add to floor_for in $0)" >&2
        continue
    fi
    # Truncate pct to integer for comparison; strictly < floor → fail.
    pct_int=${pct%.*}
    if [ "$pct_int" -lt "$floor" ]; then
        printf "%-15s %10s %10s %7s%% %5s%% %-6s\n" \
            "$crate" "$lines" "$covered" "$pct" "$floor" "FAIL"
        # Re-emit failure for the outer process: the while loop runs in a
        # subshell because of the pipe, so we tag-and-exit here.
        echo "GATE_FAIL: $crate $pct% < $floor%" >&2
        exit 1
    else
        printf "%-15s %10s %10s %7s%% %5s%% %-6s\n" \
            "$crate" "$lines" "$covered" "$pct" "$floor" "ok"
    fi
done || fail=1

if [ "$fail" -ne 0 ]; then
    echo "" >&2
    echo "Per-crate coverage gate FAILED. Either:" >&2
    echo "  - backfill tests on the failing crate, or" >&2
    echo "  - lower the floor in $0 if the regression is intentional." >&2
    exit 1
fi
