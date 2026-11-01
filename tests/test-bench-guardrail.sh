#!/usr/bin/env bash

# Hot-syscall performance guardrail
#
# Runs bench-hot-guard (musl-static) and, when the cross-glibc toolchain is
# available, bench-hot-guard-glibc (dynamic glibc) under elfuse, then enforces
# limits on four hot paths:
#
#   getpid                <= 200 ns/op    (shim identity fast path)
#   clock_gettime(libc)   <=  50 ns/op    (vDSO CNTVCT fast path)
#   read(/dev/urandom, 1) <= 400 ns/op    (shim urandom ring fast path)
#   FUTEX_WAIT (word moved) <= 400 ns/op  (shim futex fast path)
#   stat("/dev/null")     <= Nx getpid    (guest_read_path, no fast path)
#   read(empty nonblocking pipe) <= Nx getpid   (per-transfer overhead)
#   pipe write+read       <= Nx getpid    (transfer plus wait/wakeup)
#
# The first three are absolute; host-served lanes use same-run getpid ratios
# except fd-create, which uses a same-host native open/close baseline. See the
# threshold block below for the limits each measurement can establish.
#
# The static (musl) bench is the baseline; the dynamic-glibc bench verifies that
# glibc 2.41's vDSO probe (NT_GNU_ABI_TAG PT_NOTE) keeps clock_gettime on the
# trampolines instead of trapping. When LINUX_TOOLCHAIN is missing the glibc
# variant skips cleanly.

set -u

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ELFUSE="${ELFUSE:-${REPO_ROOT}/build/elfuse}"
BENCH_GUARDRAIL_DIR="${BENCH_GUARDRAIL_DIR:-${REPO_ROOT}/build}"
BENCH_FD_CREATE_HOST="${BENCH_FD_CREATE_HOST:-${REPO_ROOT}/build/bench-fd-create-host}"
BENCH_GUARDRAIL_REQUIRE_STATIC="${BENCH_GUARDRAIL_REQUIRE_STATIC:-1}"
STATIC_BENCH="${BENCH_GUARDRAIL_DIR}/bench-hot-guard"
GLIBC_BENCH="${BENCH_GUARDRAIL_DIR}/bench-hot-guard-glibc"
GLIBC_TOOLCHAIN="${LINUX_TOOLCHAIN:-/opt/toolchain/aarch64-linux-gnu}"

# Honor the makefile's CROSS_GLIBC_SYSROOT when it passes one: the prerequisite
# guard that decides whether bench-hot-guard-glibc gets built reads that
# variable, so deriving a different path here would run the benchmark against a
# sysroot the guard never checked.
GLIBC_SYSROOT="${GLIBC_SYSROOT:-${GLIBC_TOOLCHAIN}/aarch64-unknown-linux-gnu/sysroot}"
ITERS="${BENCH_GUARDRAIL_ITERS:-200000}"

# Absolute ceilings for the three shim/vDSO-served lanes. The wide headroom is
# deliberate and matches what these lanes actually check: each is served inline
# and regresses as a step function, not a slope. Losing the shim identity path
# takes getpid from ~50 ns to SVC time, and losing vDSO acceptance takes
# clock_gettime from ~5 ns to ~2000 ns. Both blow past any of these numbers, so
# tightening them buys nothing and only risks flaking on slower CI hardware.
# read-urandom1 keeps the widest margin of the three: on a loaded laptop it was
# observed up to ~280 ns/op across sequential runs, while an SVC bail lands past
# 1000 ns, so 400 separates them without chasing load noise.
THRESH_GETPID=200
THRESH_CLOCK_GETTIME=50
THRESH_URANDOM=400

# futex-eagain is the same shape as the two above and takes the same ceiling.
# Served at EL1 it measures ~51 ns, level with getpid; a bail to the host lands
# at the HVC floor, ~2000 ns on an idle host and higher under load. 400 sits an
# order of magnitude clear of the served value and well under the bail, so it
# catches "the fast path stopped being taken" without tracking load. Paired with
# tests/test-shim-futex-stats.sh, which asserts the path ran at all: that lane
# catches a dispatch that stops reaching it, this one catches a slowdown that
# still reaches it.
THRESH_FUTEX=400

# stat-path is checked as a ratio to getpid from the same run, not as an
# absolute figure. It is the only lane whose cost is a slope: it scales with
# what the guest-copy helpers charge per call, so it regresses by a percentage
# rather than by falling off a fast path. An absolute ceiling cannot catch that
# without being tuned to one machine. Dividing by getpid, measured on the same
# hardware moments earlier, cancels the machine out.
#
# The number this exists to catch: arming the SIGBUS recovery pad with sigsetjmp
# instead of _setjmp added two sigprocmask traps per guest copy and took stat
# from 4.2 us to 6.1 us, a ratio of 84 to 122. It tripped no ceiling here,
# because this lane did not exist.
#
# Observed 84 static and 407 dynamic, both within 3% across runs. The dynamic
# arm is 5x the static one because sysroot redirection resolves every path
# component. Ceilings sit ~1.25x over observed.
#
# The static arm is the detector. Restoring the sigsetjmp regression moves it 82
# -> 125, comfortably past 105, while the dynamic arm moved only 407 -> 488 and
# slipped under its ceiling on one run: sysroot resolution is so much of that
# 13.6 us that a per-copy cost is diluted to noise. Keep the dynamic arm for
# gross regressions, do not tighten it toward 450 chasing the small ones, and do
# not read a dynamic pass as evidence the copy helpers are clean.
THRESH_STAT_RATIO_STATIC=105
THRESH_STAT_RATIO_GLIBC=500

# The two transfer lanes, both ratios to getpid for the same reason stat-path
# is: they are host calls whose cost is a slope, and dividing by a lane measured
# on the same machine moments earlier cancels the machine out.
#
# pipe-eagain is the detector. A read of an empty pipe the guest set nonblocking
# reaches the fd lookup, the block-state decision and the transfer attempt, then
# returns without touching the pipe buffer or waking anything, so it measures
# per-transfer overhead and nothing else. Observed 52-66 across runs on a loaded
# machine, a 25% spread, which is tight enough to gate at 85.
#
# The number this exists to catch: read/write on a fd that can block used to
# probe with poll(), divert to the slow path when the probe said "not ready",
# and re-resolve the fd there. Measured on this lane at 259-857 against 52-66
# after that divert was removed. Anything that puts a host call or a lock
# acquisition back into the per-transfer path lands in the same range, and the
# guardrail had no lane that could see it: a 30-50% regression in the read/write
# path passed this script clean while it was being written.
#
# pipe-roundtrip moves a byte out and back, so it covers the wait and wakeup
# machinery pipe-eagain skips. It also inherits the scheduler noise that comes
# with them: observed 77-176 on the same runs where pipe-eagain held a 25%
# spread. It is a gross-regression arm, kept for the coverage and ceilinged so
# it does not flake. Do not tighten it toward the observed median chasing small
# regressions, and do not read a pass here as evidence the transfer path is
# clean; that is pipe-eagain's job.
THRESH_PIPE_EAGAIN_RATIO=85
THRESH_PIPE_RT_RATIO=220

# The same transfer with a sibling thread alive, divided by getpid from that
# same state, so the pair isolates what a second thread costs and nothing else.
# It is not a duplicate of pipe-eagain: with one active thread elfuse borrows
# the host fd, and with a sibling it dups and closes it around every fd syscall
# to keep a racing close from retiring it. That is two host syscalls a guest
# doing real work pays on every read and write, measured at 47.8x against 58.3x
# here, and no single-threaded lane can see it. Ceiled at 110 so the dup pair
# has room but a third host call does not.
THRESH_PIPE_EAGAIN_MT_RATIO=110

# Bulk transfer: a megabyte written into a pipe a sibling drains, so the write
# fills the buffer, waits, and resumes. Every other lane moves one byte, which
# is why the ready-poll rewrite could leave bulk writes 21-31% slower with
# nothing here to notice.
#
# This lane is a gross-regression arm, and the ceiling says so. It cannot catch
# the regression that motivated it: idle it measures ~6900x, a busy host alone
# put it at 9900x, and a 25% regression would read ~8600x -- inside the band
# load produces on its own. Bulk throughput is dominated by pipe capacity and
# scheduling rather than by syscall entry cost, so dividing by getpid does not
# cancel the load the way it does for stat-path. A tighter number here would
# fail on clean trees and be ignored, which costs more than it catches.
#
# What catches a 25% slope is the A/B in the TODO entry: two builds, alternating
# passes, medians, on an idle machine. The lane's job is to make that comparison
# possible at all by existing.
#
# The ceiling is 15000 against an idle figure near 6900, which is 2.17x: it
# trips just short of a 2.2x collapse, and lets a 2x one through. It is written
# that way because a busy host alone reached 1.4x, and the gap between the two
# is the whole margin this lane has: a number tight enough to catch 2x would
# fail on clean trees.
THRESH_PIPE_BULK_RATIO=15000

# fd-create is measured against native open/close on this host: filesystem and
# security policy latency can exceed the entire guest-getpid ratio ceiling. The
# median of three native passes brackets each guest run. Allowed extra runtime
# work is 15 us static and 35 us with glibc sysroot resolution; the static
# allowance covers the measured 8-12 us translation/descriptor cost.
THRESH_FD_CREATE_EXTRA_STATIC=15000
THRESH_FD_CREATE_EXTRA_GLIBC=35000
THRESH_PIPE_CREATE_RATIO=1000

C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_RESET='\033[0m'

if [ ! -x "$ELFUSE" ]; then
    echo "elfuse binary missing at $ELFUSE" >&2
    exit 1
fi
if [ ! -x "$BENCH_FD_CREATE_HOST" ]; then
    echo "native fd-create benchmark missing at $BENCH_FD_CREATE_HOST" >&2
    exit 1
fi

run_static=1
if [ ! -x "$STATIC_BENCH" ]; then
    if [ "$BENCH_GUARDRAIL_REQUIRE_STATIC" = 1 ]; then
        echo "bench-hot-guard missing at $STATIC_BENCH" >&2
        exit 1
    fi
    /usr/bin/printf "  ${C_YELLOW}SKIP${C_RESET}  static        bench-hot-guard absent: %s\n" \
        "$STATIC_BENCH"
    run_static=0
fi

failures=0
unmeasured=0
benchmarks_run=0

# Set by any failure a second run would reproduce, so run_and_check skips the
# retry. Reset per pass by run_and_check.
deterministic=0

# extract_ns <bench-output> <label> Prints the floating-point ns/op for the line
# whose first column is exactly <label>.
#
# Returns nothing if the line is absent.
extract_ns()
{
    awk -v label="$2" '$1 == label { print $2 }' "$1"
}

# A throughput ceiling is a claim about this machine when it is free to answer.
# On a loaded host the number measures the load, not the code: every lane that
# does host work inflates together while the shim-served ones barely move, so
# the getpid-relative ratios stop cancelling and the absolute ceilings blow out.
# Observed here at 2 to 3 times the idle figures with a prover run in the
# background, on code that was not the cause. Consulted only after a retry has
# also failed, so a real regression on an idle machine still fails twice and is
# reported.
. "$(dirname "${BASH_SOURCE[0]}")/lib/bash-compat.sh"

host_is_busy()
{
    test_host_is_busy
}

# check_threshold <variant> <label> <ns/op> <ceiling-ns>
check_threshold()
{
    local variant="$1" label="$2" actual="$3" ceiling="$4"
    if [ -z "$actual" ]; then
        printf "  ${C_RED}MISS${C_RESET}  %-12s %-22s no measurement reported\n" \
            "$variant" "$label" >&2
        failures=$((failures + 1))
        deterministic=1
        return
    fi
    awk -v a="$actual" -v c="$ceiling" 'BEGIN { exit !(a <= c) }'
    if [ $? -eq 0 ]; then
        printf "  ${C_GREEN}OK${C_RESET}    %-12s %-22s %7.1f ns/op  (ceiling %d)\n" \
            "$variant" "$label" "$actual" "$ceiling"
    else
        printf "  ${C_RED}FAIL${C_RESET}  %-12s %-22s %7.1f ns/op  > %d\n" \
            "$variant" "$label" "$actual" "$ceiling" >&2
        failures=$((failures + 1))
    fi
}

check_ratio()
{
    local variant="$1" label="$2" actual="$3" base="$4" ceiling="$5"
    if [ -z "$actual" ] || [ -z "$base" ]; then
        printf "  ${C_RED}MISS${C_RESET}  %-12s %-22s no measurement reported\n" \
            "$variant" "$label" >&2
        failures=$((failures + 1))
        deterministic=1
        return
    fi
    local ratio
    ratio="$(awk -v a="$actual" -v b="$base" \
        'BEGIN { if (b <= 0) print ""; else printf "%.1f", a / b }')"
    if [ -z "$ratio" ]; then
        printf "  ${C_RED}MISS${C_RESET}  %-12s %-22s getpid baseline was zero\n" \
            "$variant" "$label" >&2
        failures=$((failures + 1))
        deterministic=1
        return
    fi
    if awk -v r="$ratio" -v c="$ceiling" 'BEGIN { exit !(r <= c) }'; then
        printf "  ${C_GREEN}OK${C_RESET}    %-12s %-22s %7.1f ns/op  (%sx getpid, ceiling %dx)\n" \
            "$variant" "$label" "$actual" "$ratio" "$ceiling"
    else
        printf "  ${C_RED}FAIL${C_RESET}  %-12s %-22s %7.1f ns/op  %sx getpid > %dx\n" \
            "$variant" "$label" "$actual" "$ratio" "$ceiling" >&2
        failures=$((failures + 1))
    fi
}

run_one_pass()
{
    local variant="$1" bench="$2" stat_ratio="$3" fd_extra="$4"
    shift 4
    local out native_before native_after before_ns after_ns guest_ns
    out="$(mktemp)"
    native_before="$(mktemp)"
    native_after="$(mktemp)"
    if ! "$BENCH_FD_CREATE_HOST" "$ITERS" > "$native_before"; then
        echo "native fd-create benchmark failed" >&2
        failures=$((failures + 1))
        deterministic=1
        rm -f "$out" "$native_before" "$native_after"
        return
    fi
    if ! "$ELFUSE" "$@" "$bench" "$ITERS" > "$out" 2>&1; then
        echo "  ${C_RED}FAIL${C_RESET}  $variant bench exited non-zero" >&2
        cat "$out" >&2
        failures=$((failures + 1))
        deterministic=1
        rm -f "$out" "$native_before" "$native_after"
        return
    fi
    if ! "$BENCH_FD_CREATE_HOST" "$ITERS" > "$native_after"; then
        echo "native fd-create benchmark failed" >&2
        failures=$((failures + 1))
        deterministic=1
        rm -f "$out" "$native_before" "$native_after"
        return
    fi

    local getpid_ns
    getpid_ns="$(extract_ns "$out" getpid)"

    check_threshold "$variant" "getpid" "$getpid_ns" "$THRESH_GETPID"
    check_threshold "$variant" "clock_gettime" \
        "$(extract_ns "$out" clock_gettime)" "$THRESH_CLOCK_GETTIME"
    check_threshold "$variant" "read-urandom1" \
        "$(extract_ns "$out" read-urandom1)" "$THRESH_URANDOM"
    check_threshold "$variant" "futex-eagain" \
        "$(extract_ns "$out" futex-eagain)" "$THRESH_FUTEX"
    check_ratio "$variant" "stat-path" \
        "$(extract_ns "$out" stat-path)" "$getpid_ns" "$stat_ratio"
    check_ratio "$variant" "pipe-eagain" \
        "$(extract_ns "$out" pipe-eagain)" "$getpid_ns" \
        "$THRESH_PIPE_EAGAIN_RATIO"
    check_ratio "$variant" "pipe-roundtrip" \
        "$(extract_ns "$out" pipe-roundtrip)" "$getpid_ns" \
        "$THRESH_PIPE_RT_RATIO"
    before_ns="$(extract_ns "$native_before" fd-create)"
    after_ns="$(extract_ns "$native_after" fd-create)"
    guest_ns="$(extract_ns "$out" fd-create)"
    if ! awk -v b="$before_ns" -v a="$after_ns" -v g="$guest_ns" \
        'BEGIN { n="^[0-9]+([.][0-9]+)?$"; exit !(b ~ n && a ~ n && g ~ n && b > 0 && a > 0 && g > 0) }'; then
        echo "fd-create baseline or guest measurement missing or invalid" >&2
        failures=$((failures + 1))
        deterministic=1
    else
        local baseline ceiling increment
        baseline="$(awk -v b="$before_ns" -v a="$after_ns" 'BEGIN { print (b+a)/2 }')"
        ceiling="$(awk -v b="$baseline" -v e="$fd_extra" 'BEGIN { printf "%.0f", b+e }')"
        increment="$(awk -v g="$guest_ns" -v b="$baseline" 'BEGIN { printf "%.1f", g-b }')"
        printf '  native fd-create: %s ns/op; guest increment: %s ns/op (allowance %s)\n' \
            "$baseline" "$increment" "$fd_extra"
        check_threshold "$variant" fd-create "$guest_ns" "$ceiling"
    fi
    check_ratio "$variant" "pipe-create" \
        "$(extract_ns "$out" pipe-create)" "$getpid_ns" \
        "$THRESH_PIPE_CREATE_RATIO"
    check_ratio "$variant" "pipe-bulk" \
        "$(extract_ns "$out" pipe-bulk)" "$getpid_ns" \
        "$THRESH_PIPE_BULK_RATIO"

    # The sibling-alive lanes divide by their own getpid, measured with that
    # sibling running, so the ratio carries only the per-transfer difference.
    local getpid_mt_ns
    getpid_mt_ns="$(extract_ns "$out" getpid-mt)"
    check_ratio "$variant" "pipe-eagain-mt" \
        "$(extract_ns "$out" pipe-eagain-mt)" "$getpid_mt_ns" \
        "$THRESH_PIPE_EAGAIN_MT_RATIO"

    rm -f "$out" "$native_before" "$native_after"
}

# Re-measure once before failing, and report only what survives the retry.
#
# Every lane here shares the machine with whatever else is running, and the
# lanes do not degrade together: getpid is served inside the shim and never
# leaves the process, while stat-path makes a real host filesystem call. Under
# filesystem load the second moves and the first does not, so the ratio between
# them climbs on a build where nothing changed. Measured: a `make clean` build
# put stat-path at 205x against a 105x ceiling purely because Gatekeeper was
# scanning the binaries that had just been produced, and the same binary on a
# quiet machine came back at 87x.
#
# A retry separates the two cases at the cost of one extra run on the rare bad
# pass: real slowdowns are in the code and reproduce, load spikes usually do
# not. A gate that fails on a clean tree gets ignored, which costs more than the
# regressions it would have caught.
#
# Only a measurement over its limit is retried. A bench that exited non-zero or
# produced no number for a lane failed for a reason a second run reproduces, so
# re-running it would burn a full pass and report the wrong cause.
run_and_check()
{
    local variant="$1"
    local before=$failures
    benchmarks_run=$((benchmarks_run + 1))

    deterministic=0
    run_one_pass "$@"
    if [ "$failures" -eq "$before" ] || [ "$deterministic" -eq 1 ]; then
        return
    fi

    printf "  ${C_YELLOW}RETRY${C_RESET} %-12s first pass exceeded a limit; re-measuring\n" \
        "$variant"
    failures=$before
    deterministic=0
    run_one_pass "$@"

    if [ "$failures" -ne "$before" ] && [ "$deterministic" -eq 0 ] \
        && host_is_busy; then
        printf "  ${C_YELLOW}SKIP${C_RESET}  %-12s host load %s over %s cpus; throughput not measurable\n" \
            "$variant" "$(sysctl -n vm.loadavg 2> /dev/null | awk '{print $2}')" \
            "$(sysctl -n hw.ncpu 2> /dev/null)"
        failures=$before
        unmeasured=$((unmeasured + 1))
    fi
}

echo "=== bench-guardrail (iters=$ITERS) ==="

if [ "$run_static" = 1 ]; then
    echo "[static (musl)]"
    run_and_check static "$STATIC_BENCH" "$THRESH_STAT_RATIO_STATIC" \
        "$THRESH_FD_CREATE_EXTRA_STATIC"
fi

if [ -x "$GLIBC_BENCH" ] && [ -d "$GLIBC_SYSROOT" ]; then
    echo "[dynamic-glibc]"
    run_and_check dyn-glibc "$GLIBC_BENCH" "$THRESH_STAT_RATIO_GLIBC" \
        "$THRESH_FD_CREATE_EXTRA_GLIBC" --sysroot "$GLIBC_SYSROOT"
else
    /usr/bin/printf "  ${C_YELLOW}SKIP${C_RESET}  dyn-glibc      cross-toolchain absent: %s\n" \
        "$GLIBC_TOOLCHAIN"
fi

if [ "$benchmarks_run" -eq 0 ]; then
    echo
    echo "guardrail FAILED (no benchmark variants were available to run)" >&2
    exit 1
fi

if [ "$failures" -ne 0 ]; then
    echo
    echo "guardrail FAILED ($failures threshold violation(s))" >&2
    exit 1
fi

# A variant whose thresholds were exceeded twice and then dropped for host load
# was not measured, so this run is no evidence that the ceilings hold. It exits
# non-zero for the same reason it would on a real violation: make check is the
# CI gate, and a run that never exercised the ceilings must not report the same
# status as one that did.
#
# What the load check buys is the diagnosis, not the exit code. The bare
# threshold number this replaces said nothing about why, and cost more than one
# investigation before anyone thought to look at the host.
if [ "$unmeasured" -ne 0 ]; then
    echo
    echo "guardrail UNMEASURED ($unmeasured variant(s), host busy)" >&2
    echo "  the ceilings were not exercised; re-run on an idle host" >&2
    exit 1
fi
echo
echo "guardrail PASS"
exit 0
