#!/usr/bin/env bash
# test-vcpu-watchdog.sh -- the vCPU watchdog still kills a guest that never
# leaves EL0.
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0
#
# The run loop used to arm and disarm alarm() around every hv_vcpu_run, so the
# watchdog was a kernel timer covering exactly one iteration. It now arms one
# repeating timer and decides from a progress word the loop publishes, which
# trades two syscalls per guest syscall for slightly coarser detection: a tick
# that sees the word move records it and returns, so a hang is caught on the
# second tick rather than the first.
#
# That is a real behavior change to elfuse's only defence against a wedged
# guest, and nothing else in the suite exercises it. This lane does:
#
#   - a guest spinning in EL0 with no syscalls must be killed, and within two
#     periods rather than hanging or being killed immediately
#   - a guest that blocks for longer than a period in a host syscall must NOT be
#     killed, because a blocking syscall is not a wedged guest (the loop is
#     outside hv_vcpu_run, so the tick records progress instead of firing)
#   - --timeout 0 must disable the watchdog entirely
set -e -u -o pipefail

ELFUSE="${1:?usage: $0 <elfuse> <bindir>}"
BINDIR="${2:?usage: $0 <elfuse> <bindir>}"
PERIOD=2

# shellcheck source=tests/lib/report.sh
. "$(dirname "$0")/lib/report.sh"
# shellcheck source=tests/lib/bash-compat.sh
. "$(dirname "$0")/lib/bash-compat.sh"

# report.sh keeps the tallies in these; declare them so the exit check at the
# bottom is not reading a name shellcheck cannot see assigned.
# shellcheck disable=SC2034
pass=0
fail=0
# shellcheck disable=SC2034
skip=0

# Bare timeout(1) is not on stock macOS, which is why the tree wraps it.
# require_timeout resolves timeout or gtimeout into $TIMEOUT and exits 77 (suite
# skip) when neither exists, so a missing tool reads as a skip rather than as a
# watchdog regression.
require_timeout

# The guest fixtures are built from tests/ in a source checkout and are simply
# absent from a prebuilt binary tree, which the makefile cannot compile them
# into. Absent reads as a suite skip, the same answer require_timeout gives for
# a missing timeout(1), rather than as a watchdog regression.
for fixture in spin-forever test-sleep-long spin-thread; do
    if [ ! -x "$BINDIR/$fixture" ]; then
        printf 'vCPU watchdog: %s is not in %s; skipping\n' "$fixture" "$BINDIR"
        exit 77
    fi
done

# The outer cap bounds a broken watchdog; exit status and elapsed time must
# distinguish that cap from the process's own timeout.
test_host_busy_mark
start=$(date +%s)
rc=0
out="$("$TIMEOUT" $((PERIOD * 5)) "$ELFUSE" --timeout "$PERIOD" \
    "$BINDIR/spin-forever" 2>&1)" || rc=$?
elapsed=$(($(date +%s) - start))

if [ "$rc" -eq 124 ] && [ "$elapsed" -lt $((PERIOD * 5)) ]; then
    report_pass "spinning guest is killed (${elapsed}s)"
else
    report_fail "spinning guest is killed (rc=$rc, ${elapsed}s)"
    printf '%s\n' "$out" >&2
fi

# Detection takes two ticks: the first records the progress word, the second
# sees it unchanged and fires. The bound is three periods rather than two so a
# loaded host does not flake, which leaves exactly one period of jitter; six, as
# this once allowed, would have passed a regression that took five. One period
# of slack is also thin: the observed time is 4 s of a 6 s bound on an idle
# host, and this is a make check gate. A busy host turns that slack into a false
# failure rather than a finding, so the bound stays tight and an overrun is
# reported as a skip when the load explains it. The load is sampled at the mark
# before the timed run and again at the branch, because a host that was loaded
# during the run and idle by the time the verdict is read would otherwise turn a
# load artifact into a failure. driver.sh, test-sharun.sh and test-runner.sh use
# the same pair for the same reason. Strictly above one period, not at or above
# it. A kill on the first tick is the regression this bound exists to catch, and
# it lands at exactly PERIOD, so the old "at or above" form could not fail:
# every kill passes it. Two periods would be the exact expectation, but elapsed
# is whole seconds from date(1), so a correct run that straddles a second
# boundary can read one low; strictly-greater separates a first-tick kill from a
# two-tick one with a full period of margin either side.
max=$((PERIOD * 3))
if [ "$elapsed" -gt "$PERIOD" ] && [ "$elapsed" -le "$max" ]; then
    report_pass "killed within three periods"
elif [ "$elapsed" -gt "$max" ] && test_host_busy_since_mark; then
    report_skip "killed within three periods (${elapsed}s on a loaded host)"
else
    report_fail "killed within three periods (${elapsed}s outside (${PERIOD}, ${max}])"
fi

# 2. A guest blocked in a host syscall for longer than a period survives: the
#    word still moves, so the tick records it rather than firing.
# The marker matters as much as the exit code: a guest that returned without
# sleeping would also exit 0, and would not have tested anything.
start=$(date +%s)

# The wrapper bounds the other failure direction: a watchdog that never fires
# leaves a wedged guest here with nothing to stop it, and an unwrapped run would
# hang the suite instead of failing it.
if out="$("$TIMEOUT" $((PERIOD * 5)) "$ELFUSE" --timeout "$PERIOD" \
    "$BINDIR/test-sleep-long" $((PERIOD + 1)) 2>&1)" \
    && printf '%s' "$out" | grep -q "^slept$"; then
    elapsed=$(($(date +%s) - start))
    report_pass "long blocking syscall is not killed (${elapsed}s)"
else
    report_fail "long blocking syscall is not killed (no clean sleep)"
    printf '%s\n' "${out:-}" >&2
fi

# 3. --timeout 0 disables the watchdog, so the spinner must outlive it.
#
# The pass condition is rc 124, timeout's "I had to kill it", not merely a
# non-zero exit. Any other non-zero code means elfuse stopped on its own, which
# is the failure this checks for; treating "not zero" as success would report ok
# for a crash on startup.
rc=0
"$TIMEOUT" $((PERIOD * 2)) "$ELFUSE" --timeout 0 "$BINDIR/spin-forever" \
    > /dev/null 2>&1 || rc=$?
if [ "$rc" -eq 124 ]; then
    report_pass "--timeout 0 disables the watchdog (outlived $((PERIOD * 2))s)"
else
    report_fail "--timeout 0 disables the watchdog (elfuse exited rc=$rc)"
fi

# A timeout of either the leader or a scheduled worker ends the whole process.
# The outer cap also returns 124, so require completion before that cap with a
# parked sibling that cannot exit on its own.
for spinner in leader worker; do
    rc=0
    start=$(date +%s)
    out="$("$TIMEOUT" $((PERIOD * 5)) "$ELFUSE" --cpus 1 --timeout "$PERIOD" \
        "$BINDIR/spin-thread" "$spinner" 2>&1)" || rc=$?
    elapsed=$(($(date +%s) - start))
    if [ "$rc" -eq 124 ] && [ "$elapsed" -lt $((PERIOD * 5)) ]; then
        report_pass "$spinner timeout terminates parked sibling (${elapsed}s)"
    else
        report_fail "$spinner timeout leaves process alive (rc=$rc, ${elapsed}s)"
        printf '%s\n' "$out" >&2
    fi
done

report_summary
[ "$fail" -eq 0 ] || exit 1
