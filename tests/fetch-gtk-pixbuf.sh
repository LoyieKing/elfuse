#!/usr/bin/env bash
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
repo_root="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=tests/lib/fixture-cache.sh
. "$repo_root/tests/lib/fixture-cache.sh"

# The 2.42 loaders decode in-process. 2.44 requires glycin's Linux namespaces.
version=2.42.12-r1
want=365d51e1c5eb0b9e5198edb283f486dea63b5eafade16efef7152be9640125b6
url="https://dl-cdn.alpinelinux.org/alpine/v3.22/main/aarch64/gdk-pixbuf-$version.apk"
runtime="${FIXTURES_DIR:-$repo_root/externals/test-fixtures}/gtk-pixbuf/$version/aarch64"

fetch_pixbuf()
{
    local stage="$1"
    fixture_cache_download "$url" "$stage/package.apk" "gdk-pixbuf $version" || return $?
    fixture_cache_digest_ok "$stage/package.apk" "$want" 'gdk-pixbuf package' || return 1
    tar -xzf "$stage/package.apk" -C "$stage" usr || return 1
    rm "$stage/package.apk" || return 1
    [ -s "$stage/usr/lib/libgdk_pixbuf-2.0.so.0.4200.12" ] || return 1
    [ -s "$stage/usr/bin/gdk-pixbuf-query-loaders" ] || return 1
    (cd "$stage" && find usr -type f -exec shasum -a 256 {} \;) > "$stage/.sha256" || return 1
}

verify_pixbuf()
{
    local out=''
    [ -s "$1/.sha256" ] || return 1
    [ -s "$1/usr/lib/libgdk_pixbuf-2.0.so.0.4200.12" ] || return 1
    [ -s "$1/usr/bin/gdk-pixbuf-query-loaders" ] || return 1
    out="$(cd "$1" && shasum -a 256 -c .sha256 2>&1)" || {
        printf '%s\n' "$out" >&2
        return 1
    }
}

fixture_cache_build "$runtime" verify_pixbuf fetch_pixbuf || exit $?
printf '%s\n' "$runtime"
