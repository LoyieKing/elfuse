#!/usr/bin/env bash
# Fetch the pinned upstream LTP release and build the curated tests in
# ltp-list.txt with upstream configure/make, installing into build/ltp-install.
# No libltp reimplementation and no vendored test binaries.
#
#   Linux native:  ./fetch-and-build-ltp.sh
#   Cross aarch64: ./fetch-and-build-ltp.sh --host aarch64-linux-gnu
#   Darwin:        defaults to --host aarch64-linux-gnu, HOSTCC=clang
#   Import:        ./fetch-and-build-ltp.sh --check /path/to/ltp-install
#   Fetch only:    ./fetch-and-build-ltp.sh --fetch-only
#
# Static linking needs -pthread: libltp uses pthread mutexes and older glibc
# sysroots keep libpthread separate from libc.a.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CLASSIC="${ROOT}/tests/classic"
LOCK="${CLASSIC}/ltp-fixture.lock"
LIST="${CLASSIC}/ltp-list.txt"
PREFIX="${LTP_PREFIX:-${ROOT}/build/ltp-install}"
WORK="${LTP_WORK_DIR:-${ROOT}/externals/ltp}"
HOST="${LTP_HOST:-}"
SYSROOT="${LTP_SYSROOT:-}"
JOBS="${JOBS:-}"
FETCH_ONLY=0
CHECK_DIR=""

die() { echo "error: $*" >&2; exit 1; }
abs_path() { case "$1" in /*) printf '%s' "$1" ;; *) printf '%s/%s' "$PWD" "$1" ;; esac; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) [[ $# -ge 2 ]] || die "--host needs a triplet"; HOST="$2"; shift 2 ;;
    --prefix) [[ $# -ge 2 ]] || die "--prefix needs a directory"; PREFIX="$2"; shift 2 ;;
    --jobs) [[ $# -ge 2 ]] || die "--jobs needs a number"; JOBS="$2"; shift 2 ;;
    --sysroot) [[ $# -ge 2 ]] || die "--sysroot needs a directory"; SYSROOT="$2"; shift 2 ;;
    --fetch-only) FETCH_ONLY=1; shift ;;
    --check) [[ $# -ge 2 ]] || die "--check needs a directory"; CHECK_DIR="$2"; shift 2 ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done
PREFIX="$(abs_path "$PREFIX")"
WORK="$(abs_path "$WORK")"
if [[ -z "$HOST" && "$(uname -s)" != Linux ]]; then
  HOST="aarch64-linux-gnu"
fi
if [[ -z "$JOBS" ]]; then
  JOBS="$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)"
fi
case "$JOBS" in ''|*[!0-9]*) die "--jobs must be a positive integer" ;; esac
[[ "$JOBS" -gt 0 ]] || die "--jobs must be a positive integer"

TESTS=()
count=0
[[ -f "$LIST" ]] || die "missing $LIST"
while IFS= read -r line || [[ -n "$line" ]]; do
  line="${line%%#*}"
  line="${line#"${line%%[![:space:]]*}"}"
  line="${line%"${line##*[![:space:]]}"}"
  [[ -z "$line" ]] && continue
  TESTS+=("${line%%[[:space:]]*}")
  count=$((count + 1))
done < "$LIST"
[[ "$count" -gt 0 ]] || die "no tests in $LIST"

check_install() {
  local dir="$1" name bin desc bad=0
  command -v file >/dev/null 2>&1 || die "file(1) required"
  for name in ${TESTS[@]+"${TESTS[@]}"}; do
    bin="$dir/testcases/bin/$name"
    [[ -x "$bin" ]] || bin="$dir/$name"
    if [[ ! -x "$bin" ]]; then
      echo "MISSING $name"; bad=$((bad + 1)); continue
    fi
    desc="$(file "$bin" 2>/dev/null || true)"
    case "$desc" in *ELF*) ;; *) echo "NOT-ELF $name: $desc"; bad=$((bad + 1)); continue ;; esac
    case "$HOST" in
      aarch64*) case "$desc" in *aarch64*|*AArch64*) ;; *) echo "WRONG-ARCH $name: $desc"; bad=$((bad + 1)) ;; esac ;;
      x86_64*) case "$desc" in *x86-64*|*X86-64*) ;; *) echo "WRONG-ARCH $name: $desc"; bad=$((bad + 1)) ;; esac ;;
    esac
  done
  [[ "$bad" -eq 0 ]] || die "$bad of $count curated tests missing or invalid under $dir"
  echo "LTP install OK: $dir ($count tests)"
}
if [[ -n "$CHECK_DIR" ]]; then
  check_install "$(abs_path "$CHECK_DIR")"
  exit $?
fi

[[ -f "$LOCK" ]] || die "missing $LOCK"
# shellcheck disable=SC1090
. "$LOCK"
: "${LTP_VERSION:?missing LTP_VERSION}"
: "${LTP_URL:?missing LTP_URL}"
: "${LTP_SHA256:?missing LTP_SHA256}"

DL="${WORK}/downloads"
TARBALL="${DL}/ltp-full-${LTP_VERSION}.tar.xz"
SRC="${WORK}/ltp-full-${LTP_VERSION}"
MARK="${WORK}/.ltp-${LTP_VERSION}.extracted"

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  else die "need sha256sum or shasum"
  fi
}
download() {
  if command -v curl >/dev/null 2>&1; then curl -fL --retry 3 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then wget -O "$2" "$1"
  else die "need curl or wget"
  fi
}

mkdir -p "$WORK" "$DL"
if [[ -f "$TARBALL" && "$(sha256 "$TARBALL")" != "$LTP_SHA256" ]]; then
  echo "cached tarball checksum mismatch; refetching" >&2
  rm -f "$TARBALL"
fi
if [[ ! -f "$TARBALL" ]]; then
  echo "FETCH $LTP_URL"
  download "$LTP_URL" "${TARBALL}.part"
  [[ "$(sha256 "${TARBALL}.part")" == "$LTP_SHA256" ]] || {
    rm -f "${TARBALL}.part"
    die "checksum mismatch for $LTP_URL"
  }
  mv "${TARBALL}.part" "$TARBALL"
fi
[[ "$(sha256 "$TARBALL")" == "$LTP_SHA256" ]] || die "checksum mismatch: $TARBALL"

if [[ ! -f "$MARK" || ! -x "$SRC/configure" ]]; then
  echo "EXTRACT $TARBALL"
  tmp="${WORK}/.extract.$$"
  [[ ! -e "$SRC" ]] || die "source exists without extraction marker: $SRC"
  [[ ! -e "$tmp" ]] || die "extraction directory exists: $tmp"
  mkdir -p "$tmp"
  tar -xJf "$TARBALL" -C "$tmp" || { rm -rf "$tmp"; die "tar -xJf failed"; }
  mv "${tmp}/ltp-full-${LTP_VERSION}" "$SRC" || { rm -rf "$tmp"; die "unexpected tarball layout"; }
  rm -rf "$tmp"
  : > "$MARK"
fi

DIRS=()
add_dir() {
  local d="$1" e
  for e in ${DIRS[@]+"${DIRS[@]}"}; do [[ "$e" == "$d" ]] && return 0; done
  DIRS+=("$d")
}
for name in ${TESTS[@]+"${TESTS[@]}"}; do
  src="$(find "$SRC/testcases/kernel/syscalls" -type f -name "${name}.c" -print 2>/dev/null | sed -n '1p')"
  [[ -n "$src" ]] || die "no ${name}.c in LTP ${LTP_VERSION}"
  add_dir "$(dirname "${src#"$SRC/"}")"
done

if [[ "$FETCH_ONLY" -eq 1 ]]; then
  echo "LTP source: $SRC"
  echo "Tests: $count"
  printf 'Build dirs:\n'
  for d in ${DIRS[@]+"${DIRS[@]}"}; do echo "  $d"; done
  exit 0
fi

if [[ -n "$HOST" ]]; then
  CC="${LTP_CROSS_CC:-${HOST}-gcc}"
  STATIC=1
else
  CC="${CC:-cc}"
  STATIC=0
fi
command -v "$CC" >/dev/null 2>&1 || die "compiler not found: $CC"
HOSTCC="${HOSTCC:-$(command -v clang 2>/dev/null || command -v cc 2>/dev/null || true)}"
[[ -n "$HOSTCC" ]] || die "no host C compiler (set HOSTCC)"
command -v "$HOSTCC" >/dev/null 2>&1 || die "host compiler not found: $HOSTCC"
command -v make >/dev/null 2>&1 || die "GNU make required"
command -v pkg-config >/dev/null 2>&1 || command -v pkgconf >/dev/null 2>&1 || die "pkg-config/pkgconf required"
if ! command -v pkg-config >/dev/null 2>&1; then export PKG_CONFIG=pkgconf; fi

LDFLAGS_VAL="-pthread"
CFLAGS_VAL=""
[[ "$STATIC" -eq 1 ]] && LDFLAGS_VAL="-static $LDFLAGS_VAL"
if [[ -n "$SYSROOT" ]]; then
  SYSROOT="$(abs_path "$SYSROOT")"
  [[ -d "$SYSROOT" ]] || die "sysroot not found: $SYSROOT"
  CFLAGS_VAL="--sysroot=$SYSROOT"
  LDFLAGS_VAL="$LDFLAGS_VAL --sysroot=$SYSROOT"
fi
if [[ -n "$HOST" ]]; then
  pcroot="${SYSROOT:-$("$CC" -print-sysroot 2>/dev/null || true)}"
  if [[ -n "$pcroot" && "$pcroot" != "/" ]]; then
    export PKG_CONFIG_SYSROOT_DIR="$pcroot"
    export PKG_CONFIG_LIBDIR="$pcroot/usr/lib/pkgconfig:$pcroot/usr/share/pkgconfig"
  fi
fi

BUILD_TRIPLET="$("$SRC/config.guess" 2>/dev/null || true)"
ARGS=(--prefix="$PREFIX" --without-numa --without-tirpc --without-modules --disable-dependency-tracking)
[[ -n "$HOST" ]] && ARGS+=(--host="$HOST")
[[ -n "$BUILD_TRIPLET" ]] && ARGS+=(--build="$BUILD_TRIPLET")

LOG="${WORK}/build.log"
: > "$LOG"
echo "CONFIGURE host=${HOST:-native} cc=$CC hostcc=$HOSTCC static=$STATIC"
cd "$SRC"
if [[ -n "$CFLAGS_VAL" ]]; then
  env CC="$CC" HOSTCC="$HOSTCC" CFLAGS="$CFLAGS_VAL" LDFLAGS="$LDFLAGS_VAL" \
    ./configure "${ARGS[@]}" >>"$LOG" 2>&1 || { tail -40 "$LOG" >&2; die "configure failed: $LOG"; }
else
  env CC="$CC" HOSTCC="$HOSTCC" LDFLAGS="$LDFLAGS_VAL" \
    ./configure "${ARGS[@]}" >>"$LOG" 2>&1 || { tail -40 "$LOG" >&2; die "configure failed: $LOG"; }
fi

echo "BUILD libltp"
make -C "$SRC/lib" -j"$JOBS" all >>"$LOG" 2>&1 || { tail -40 "$LOG" >&2; die "libltp build failed: $LOG"; }
for d in ${DIRS[@]+"${DIRS[@]}"}; do
  echo "BUILD $d"
  make -C "$SRC/$d" -j"$JOBS" all >>"$LOG" 2>&1 || { tail -40 "$LOG" >&2; die "$d build failed: $LOG"; }
done

mkdir -p "$PREFIX"
for d in ${DIRS[@]+"${DIRS[@]}"}; do
  echo "INSTALL $d"
  make -C "$SRC/$d" install prefix="$PREFIX" >>"$LOG" 2>&1 || { tail -40 "$LOG" >&2; die "$d install failed: $LOG"; }
done

bad=0
READELF=""
if [[ -n "$HOST" ]] && command -v "${HOST}-readelf" >/dev/null 2>&1; then READELF="${HOST}-readelf"
elif command -v readelf >/dev/null 2>&1; then READELF=readelf; fi
for name in ${TESTS[@]+"${TESTS[@]}"}; do
  bin="$PREFIX/testcases/bin/$name"
  if [[ ! -x "$bin" ]]; then echo "MISSING $name" >&2; bad=$((bad + 1)); continue; fi
  desc="$(file "$bin" 2>/dev/null || true)"
  case "$desc" in *ELF*) ;; *) echo "NOT-ELF $name: $desc" >&2; bad=$((bad + 1)); continue ;; esac
  case "$HOST" in
    aarch64*) case "$desc" in *aarch64*|*AArch64*) ;; *) echo "WRONG-ARCH $name: $desc" >&2; bad=$((bad + 1)) ;; esac ;;
    x86_64*) case "$desc" in *x86-64*|*X86-64*) ;; *) echo "WRONG-ARCH $name: $desc" >&2; bad=$((bad + 1)) ;; esac ;;
  esac
  if [[ "$STATIC" -eq 1 && -n "$READELF" ]] && "$READELF" -l "$bin" 2>/dev/null | grep -q INTERP; then
    echo "NOT-STATIC $name" >&2; bad=$((bad + 1))
  fi
done
[[ "$bad" -eq 0 ]] || die "$bad of $count curated tests missing or invalid under $PREFIX"

echo "LTP install OK: $PREFIX ($count tests)"
echo "Run: $ROOT/tests/classic/run.sh --ltp --ltp-dir $PREFIX"
if [[ -n "$HOST" ]]; then
  echo "Binaries are $HOST ELF; use elfuse guest mode on $(uname -s)."
fi
