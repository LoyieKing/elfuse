#!/usr/bin/env bash

# test-initial-identity.sh -- Pin the explicit --pid/--ppid launch identity
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0
#
# Usage: tests/test-initial-identity.sh <elfuse-binary> <guest-elf>
#
# test-initial-identity checks getpid/getppid, the shim identity cache, the
# main thread's TID, /proc, the initial session/process group, and that a fork
# child skips both identity ids before execing itself. This script supplies the
# launcher side: the default identity stays 1/0 with a first child PID of 2,
# and the explicit lanes select the collision boundary (PID 2 with PPID 3, so
# the first child must take 4), a PID far above the sequence, and INT_MAX.

set -euo pipefail

ELFUSE="${1:?Usage: $0 <elfuse-binary> <guest-elf>}"
GUEST="${2:?Usage: $0 <elfuse-binary> <guest-elf>}"

# shellcheck source=tests/lib/report.sh
. "$(dirname "$0")/lib/report.sh"

# check <desc> <pid> <ppid> <first-child-pid> [launcher flags...]
check()
{
    local desc="$1" pid="$2" ppid="$3" child="$4"
    shift 4
    local out status=0
    out="$("$ELFUSE" "$@" "$GUEST" "$pid" "$ppid" "$child" 2>&1)" || status=$?
    if [ "$status" -ne 0 ]; then
        report_fail "$desc (exit $status)"
        printf '%s\n' "$out" >&2
        return
    fi
    local want="test-initial-identity: pid=$pid ppid=$ppid"
    if ! printf '%s' "$out" | grep -qF -- "$want"; then
        report_fail "$desc (guest did not observe $pid/$ppid)"
        printf '%s\n' "$out" >&2
        return
    fi
    report_pass "$desc"
}

check "default identity" 1 0 2
check "--pid 4242 --ppid 4241" 4242 4241 2 --pid 4242 --ppid 4241
check "--pid 2 --ppid 3 skips both reserved ids" 2 3 4 --pid 2 --ppid 3
check "--pid INT_MAX" 2147483647 0 2 --pid 2147483647

report_summary
# shellcheck disable=SC2154  # fail is incremented in tests/lib/report.sh
[ "$fail" -eq 0 ] || exit 1