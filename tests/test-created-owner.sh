#!/usr/bin/env bash
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ELFUSE="${1:?Usage: $0 <elfuse-binary> <guest-elf>}"
GUEST="${2:?Usage: $0 <elfuse-binary> <guest-elf>}"

# shellcheck source=tests/lib/report.sh
. "$(dirname "$0")/lib/report.sh"
require_timeout

work="$(mktemp -d)"
sysroot="$work/sysroot"
trap 'rm -rf "$work"' EXIT
mkdir -p "$sysroot/tmp"

run_phase()
{
    local uid="$1" phase="$2" out status=0
    out="$("$TIMEOUT" 60 "$ELFUSE" --sysroot "$sysroot" --user "$uid" \
        "$GUEST" "$phase" 2>&1)" || status=$?
    if [ "$status" -eq 0 ]; then
        report_pass "$phase as uid $uid"
    else
        report_fail "$phase as uid $uid (exit $status)"
        printf '%s\n' "$out" >&2
    fi
}

host_owner()
{
    if [ "$(uname -s)" = Darwin ]; then
        stat -f '%u:%g' "$1"
    else
        stat -c '%u:%g' "$1"
    fi
}

run_phase 2000 create
run_phase 10000 read-created
before="$(host_owner "$sysroot/tmp/creator-file")"
if [ "${before%%:*}" = "$(id -u)" ]; then
    report_pass "host creator uid is unchanged"
else
    report_fail "guest creation changed the real host uid"
fi
run_phase 10000 truncate
run_phase 10000 link-rename
run_phase 0 change-times
run_phase 0 partial-chown
run_phase 10000 read-partial
run_phase 0 explicit-chown
run_phase 10000 read-explicit
after="$(host_owner "$sysroot/tmp/creator-renamed")"
if [ "$after" = "$before" ]; then
    report_pass "guest chown leaves host ownership unchanged"
else
    report_fail "host ownership changed from $before to $after"
fi
report_summary
# shellcheck disable=SC2154
[ "$fail" -eq 0 ] || exit 1
