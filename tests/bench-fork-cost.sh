#!/usr/bin/env bash

# Per-fork wall-clock cost for aarch64 vs x86_64-via-Rosetta
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0
#
# Measures the per-fork wall-clock cost of clone(SIGCHLD) (subshell fork without
# exec) at a few resident-memory levels, on the same host, comparing:
#
#   - aarch64-musl static busybox
#   - x86_64-musl  static busybox  (Rosetta helper path)
#
#   Both fork through one Mach copy-on-write entry over the guest slab.
#
# Issue #45 tracks the fork-cost gap that this benchmark quantifies.
#
# Method:
#   - Each fork-bench run is a single busybox sh that first inflates an
#     environment variable to KB bytes (controls parent RSS at fork time)
#     and then runs a tight subshell loop (:) which forks but does not
#     exec. Subshell fork keeps the per-iteration cost dominated by the
#     fork IPC (state transfer + posix_spawn + child bring-up) and stays
#     free of execve / interpreter setup.
#   - A baseline run with iter_count=0 captures elfuse and busybox-sh
#     startup, so the reported per-fork number subtracts startup off.
#   - Wall-clock is captured via python time.monotonic_ns, in line with
#     bench-rosetta.sh.
#
# Usage: tests/bench-fork-cost.sh [path/to/elfuse] [iterations]
#
#   iterations is the per-arch fork count. aarch64 uses iterations as-is;
#   x86_64-via-Rosetta uses max(2, iterations / 10) by default to keep the
#   helper-process path in reasonable wall-clock. Override with
#   ROSETTA_ITERATIONS=N.

set -euo pipefail

ELFUSE_INPUT="${1:-build/elfuse}"
ITERS="${2:-50}"
case "$ELFUSE_INPUT" in
    /*) ELFUSE="$ELFUSE_INPUT" ;;
    *) ELFUSE="$(pwd)/$ELFUSE_INPUT" ;;
esac

FIXTURES="${FIXTURES_DIR:-externals/test-fixtures}"
AARCH64_STATICBIN="${FIXTURES}/aarch64-musl/staticbin/bin"
X86_64_STATICBIN="${FIXTURES}/x86_64-musl/staticbin/bin"
ROSETTA_PATH="${MATRIX_ROSETTA_TRANSLATOR:-/Library/Apple/usr/libexec/oah/RosettaLinux/rosetta}"

SHORTDIR=/tmp/elfuse-bfc
ARM_DIR="${SHORTDIR}/arm"
X86_DIR="${SHORTDIR}/x86"

VCPU_TIMEOUT="${VCPU_TIMEOUT:-90}"

if [ ! -x "$ELFUSE" ]; then
    printf 'elfuse not found: %s\n' "$ELFUSE" >&2
    exit 1
fi
if [ ! -x "${AARCH64_STATICBIN}/busybox" ]; then
    printf 'aarch64-musl fixture missing at %s\n' "$AARCH64_STATICBIN" >&2
    printf 'stage via: bash tests/fetch-fixtures.sh\n' >&2
    exit 77
fi
have_rosetta=1
if [ ! -x "${X86_64_STATICBIN}/busybox" ]; then
    printf 'x86_64-musl fixture missing at %s\n' "$X86_64_STATICBIN" >&2
    printf 'stage via: INCLUDE_X86_64=1 bash tests/fetch-fixtures.sh\n' >&2
    have_rosetta=0
fi
if [ ! -x "$ROSETTA_PATH" ]; then
    printf 'rosetta translator not found at %s; skipping x86_64 side\n' \
        "$ROSETTA_PATH" >&2
    have_rosetta=0
fi

rm -rf "$SHORTDIR"
mkdir -p "$ARM_DIR" "$X86_DIR"

arm_busybox_abs="$(cd "$AARCH64_STATICBIN" && pwd)/busybox"
ln -s "$arm_busybox_abs" "${ARM_DIR}/busybox"
ln -s busybox "${ARM_DIR}/sh"
ln -s busybox "${ARM_DIR}/true"

if [ "$have_rosetta" = 1 ]; then
    x86_busybox_abs="$(cd "$X86_64_STATICBIN" && pwd)/busybox"
    ln -s "$x86_busybox_abs" "${X86_DIR}/busybox"
    ln -s busybox "${X86_DIR}/sh"
    ln -s busybox "${X86_DIR}/true"
fi

trap 'rm -rf "$SHORTDIR"' EXIT

# Capture best-of-N wall-clock for one configuration. Runs are retried up to
# MAX_TRIES per slot; only runs that exit 0 AND print the "OK" sentinel are
# accepted.
#
# Returns "FAIL" on stdout when no run succeeds, so the caller can mark the cell
# as unreliable rather than reporting a phantom-best time captured from a crash
# or out-of-memory bail. Args: <iter_count> <rss_bytes> <stagedir> [extra elfuse
# flags...]
run_one()
{
    local iters="$1" rss="$2" stagedir="$3"
    shift 3
    local samples=() runs="${BFC_RUNS:-3}" tries="${BFC_MAX_TRIES:-6}"
    local good=0 attempt=0
    local stdout_buf
    stdout_buf=$(mktemp -t bfc-stdout.XXXXXX)
    trap 'rm -f "$stdout_buf"' RETURN

    while [ "$good" -lt "$runs" ] && [ "$attempt" -lt "$tries" ]; do
        attempt=$((attempt + 1))
        local start_ns end_ns rc
        start_ns=$(python3 -c 'import time; print(time.monotonic_ns())')
        set +e
        "$ELFUSE" "$@" "${stagedir}/sh" -c \
            "x=\$(printf '%*s' ${rss} '');
             i=0;
             while [ \$i -lt ${iters} ]; do (:); i=\$((i+1)); done;
             echo BFC_OK" \
            > "$stdout_buf" 2> /dev/null
        rc=$?
        set -e
        end_ns=$(python3 -c 'import time; print(time.monotonic_ns())')
        if [ "$rc" -eq 0 ] && grep -q '^BFC_OK$' "$stdout_buf"; then
            samples+=("$((end_ns - start_ns))")
            good=$((good + 1))
        fi
    done

    if [ "$good" -eq 0 ]; then
        printf 'FAIL\n'
        return
    fi
    printf '%s\n' "${samples[@]}" | sort -n | head -1
}

# Args: <arch_label> <stagedir> <iter_count> [extra elfuse flags...]
# Echoes: rss_label rss_bytes baseline_best_ns iter_best_ns per_fork_ms
report()
{
    local arch_label="$1" stagedir="$2" iters="$3"
    shift 3

    printf '\n%s (iters=%d):\n' "$arch_label" "$iters"
    printf '  %-12s  %-12s  %-12s  %-12s  %s\n' \
        "rss" "baseline" "iter_total" "per_fork" "per_fork_excl_startup"

    local rss_label rss
    for spec in "0:0" "1MiB:1048576" "16MiB:16777216" "64MiB:67108864"; do
        rss_label="${spec%%:*}"
        rss="${spec##*:}"

        local base_ns iter_ns
        base_ns=$(run_one 0 "$rss" "$stagedir" "$@")
        iter_ns=$(run_one "$iters" "$rss" "$stagedir" "$@")

        if [ "$base_ns" = "FAIL" ] || [ "$iter_ns" = "FAIL" ]; then
            printf '  %-12s  %s\n' "$rss_label" \
                "FAIL (all retries crashed or exhausted resources)"
            continue
        fi

        local per_total_ms per_excl_ms
        per_total_ms=$(python3 -c \
            "print(f'{($iter_ns) / 1e6 / $iters:.2f}')")
        per_excl_ms=$(python3 -c "
diff = ($iter_ns) - ($base_ns)
print(f'{diff / 1e6 / $iters:.2f}' if diff > 0 else 'n/a')")

        printf '  %-12s  %8.1fms    %8.1fms    %8.2fms    %12s\n' \
            "$rss_label" \
            "$(python3 -c "print($base_ns / 1e6)")" \
            "$(python3 -c "print($iter_ns / 1e6)")" \
            "$per_total_ms" \
            "${per_excl_ms}ms"
    done
}

printf 'elfuse:        %s\n' "$ELFUSE"
printf 'aarch64 fxtr:  %s/busybox\n' "$AARCH64_STATICBIN"
if [ "$have_rosetta" = 1 ]; then
    printf 'x86_64 fxtr:   %s/busybox\n' "$X86_64_STATICBIN"
    printf 'rosetta:       %s\n' "$ROSETTA_PATH"
fi
printf 'iterations:    aarch64=%d  rosetta=%d  best-of-3 per cell\n' \
    "$ITERS" "${ROSETTA_ITERATIONS:-$((ITERS / 10 > 2 ? ITERS / 10 : 2))}"

# Warm caches. Rosetta translates lazily and caches per-binary in
# ~/.cache/elfuse-rosettad/; the first invocation pays the translation cost.
printf '\nWarming caches...\n'
"$ELFUSE" "${ARM_DIR}/sh" -c ':' > /dev/null 2>&1 || true
if [ "$have_rosetta" = 1 ]; then
    "$ELFUSE" --timeout "$VCPU_TIMEOUT" "${X86_DIR}/sh" -c ':' \
        > /dev/null 2>&1 || true
    "$ELFUSE" --timeout "$VCPU_TIMEOUT" "${X86_DIR}/sh" -c '(:)' \
        > /dev/null 2>&1 || true
fi

report "aarch64" "$ARM_DIR" "$ITERS"

if [ "$have_rosetta" = 1 ]; then
    rosetta_iters="${ROSETTA_ITERATIONS:-$((ITERS / 10 > 2 ? ITERS / 10 : 2))}"
    report "x86_64-via-Rosetta" "$X86_DIR" \
        "$rosetta_iters" --timeout "$VCPU_TIMEOUT"
fi

printf '\nNotes:\n'
printf '  - per_fork is total / iters (includes elfuse + sh startup).\n'
printf '  - per_fork_excl_startup is (iter_total - baseline) / iters and\n'
printf '    isolates the per-fork cost from elfuse + sh bring-up.\n'
printf '  - rss is the size of an inflated parent-sh variable, which\n'
printf '    sits in the parent guest brk and crosses the fork IPC.\n'
printf '  - Fork hands the child a copy-on-write view of the slab; the copy\n'
printf '    is paid per page by whichever side next writes it.\n'
printf '  - See issue #45 for context.\n'
