#!/usr/bin/env bash
# Run scheduler contract scenarios, one per timeout window. Exit: 0 all selected
# passed/skipped, 1 any fail/timeout, 2 usage/setup. Test exit 77 is SKIP; exit
# 4 is a failure. A cases-file scenario "-" runs the binary without arguments.
# Requires timeout or gtimeout (no fallback).
set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CASES="${SCHED_CASES:-$ROOT/tests/scheduler/cases.txt}"
MODE="${SCHED_MODE:-elfuse}"
ELFUSE="${ELFUSE:-$ROOT/build/elfuse}"
BINDIR="${SCHED_BIN_DIR:-}"
SYSROOT="${SCHED_SYSROOT:-}"
LIMIT="${SCHED_TIMEOUT:-45}"
FILTER="${SCHED_FILTER:-}"
LOG="${SCHED_LOG_DIR:-$ROOT/build/scheduler-logs}"
RESULTS="${SCHED_RESULTS:-$ROOT/build/scheduler-results.txt}"
LIST=0

usage() {
    echo "usage: $0 [--elfuse|--native] [--filter SUBSTR] [--timeout SEC]"
    echo "          [--bin-dir DIR] [--sysroot DIR] [--list]"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --elfuse) MODE=elfuse; shift ;;
        --native) MODE=native; shift ;;
        --filter) [ $# -ge 2 ] || { usage >&2; exit 2; }; FILTER="$2"; shift 2 ;;
        --timeout) [ $# -ge 2 ] || { usage >&2; exit 2; }; LIMIT="$2"; shift 2 ;;
        --bin-dir) [ $# -ge 2 ] || { usage >&2; exit 2; }; BINDIR="$2"; shift 2 ;;
        --sysroot) [ $# -ge 2 ] || { usage >&2; exit 2; }; SYSROOT="$2"; shift 2 ;;
        --list) LIST=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "error: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

emit() {
    printf "$@"
    printf "$@" >> "$RESULTS"
}

case "$LIMIT" in ''|*[!0-9]*) echo "error: bad timeout" >&2; exit 2 ;; esac
[ "$LIMIT" -gt 0 ] || { echo "error: bad timeout" >&2; exit 2; }
if [ "$MODE" = native ]; then
    [ "$(uname -s)" = Linux ] || {
        echo "error: --native requires Linux" >&2
        exit 2
    }
    BINDIR="${BINDIR:-$ROOT/build/native}"
else
    BINDIR="${BINDIR:-$ROOT/build}"
    [ -x "$ELFUSE" ] || { echo "error: missing $ELFUSE" >&2; exit 2; }
fi
[ -f "$CASES" ] || { echo "error: missing $CASES" >&2; exit 2; }

if command -v gtimeout >/dev/null 2>&1; then
    TO=gtimeout
elif command -v timeout >/dev/null 2>&1; then
    TO=timeout
else
    echo "error: need timeout or gtimeout on PATH" >&2
    exit 2
fi
if [ "$LIST" -eq 0 ]; then
    mkdir -p "$LOG" "$(dirname "$RESULTS")" || exit 2
    : > "$RESULTS"
fi

total=0 pass=0 fail=0 skipn=0 timedout=0
while read -r bin scenario _ || [ -n "${bin:-}" ]; do
    case "${bin:-}" in ''|\#*) continue ;; esac
    id="$bin/$scenario"
    [ "$scenario" = - ] && id="$bin"
    if [ -n "$FILTER" ]; then
        case "$id" in *"$FILTER"*) ;; *) continue ;; esac
    fi
    total=$((total + 1))
    if [ "$LIST" -eq 1 ]; then
        echo "$id"
        continue
    fi

    path="$BINDIR/$bin"
    if [ ! -x "$path" ]; then
        emit 'FAIL\t%s\tmissing %s\n' "$id" "$path"
        fail=$((fail + 1))
        continue
    fi
    cmd=()
    if [ "$MODE" = elfuse ]; then
        cmd=("$ELFUSE")
        [ -n "$SYSROOT" ] && cmd+=(--sysroot "$SYSROOT")
    fi
    cmd+=("$path")
    [ "$scenario" != - ] && cmd+=("$scenario")
    log="$LOG/$bin.${scenario//\//_}.log"

    start=$(date +%s)
    "$TO" -k 5 "$LIMIT" "${cmd[@]}" >"$log" 2>&1
    rc=$?
    elapsed=$(( $(date +%s) - start ))

    case "$rc" in
        0)
            emit 'PASS\t%s\t%ss\n' "$id" "$elapsed"
            pass=$((pass + 1))
            ;;
        77)
            reason=$(grep -m1 '^SKIP:' "$log" 2>/dev/null | sed 's/^SKIP:[[:space:]]*//')
            emit 'SKIP\t%s\t%ss\t%s\n' "$id" "$elapsed" "${reason:-unsupported}"
            skipn=$((skipn + 1))
            ;;
        124|137)
            emit 'TIMEOUT\t%s\t%ss\trc=%s\n' "$id" "$elapsed" "$rc"
            timedout=$((timedout + 1))
            ;;
        *)
            emit 'FAIL\t%s\t%ss\trc=%s\t%s\n' "$id" "$elapsed" "$rc" \
                "$(tail -n 4 "$log" 2>/dev/null | tr '\n' '|' | cut -c1-240)"
            fail=$((fail + 1))
            ;;
    esac
done < "$CASES"

if [ "$total" -eq 0 ]; then
    echo "error: no scenarios matched" >&2
    exit 2
fi
[ "$LIST" -eq 0 ] || exit 0
emit 'SUMMARY\tpass=%s\tfail=%s\tskip=%s\ttimeout=%s\ttotal=%s\n' \
    "$pass" "$fail" "$skipn" "$timedout" "$total"
[ "$fail" -eq 0 ] && [ "$timedout" -eq 0 ]
