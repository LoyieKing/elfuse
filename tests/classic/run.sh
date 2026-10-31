#!/usr/bin/env bash
# Run curated classic kselftests (+ optional in-tree + curated LTP) under
# build/elfuse. LTP can also run natively on Linux with --ltp-native.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ELFUSE="${ELFUSE:-${ROOT}/build/elfuse}"
CLASSIC_BIN="${CLASSIC_BIN:-${ROOT}/build/classic}"
ELFROOT="${ELFROOT:-${ROOT}/build}"
OUT="${CLASSIC_RESULTS:-${ROOT}/build/classic-results.txt}"
LOGDIR="${CLASSIC_LOGDIR:-${ROOT}/build/classic-logs}"
TIMEOUT_SEC="${TEST_TIMEOUT:-120}"
CLASSIC_SYSROOT="${CLASSIC_SYSROOT:-${ROOT}/build/classic-sysroot}"
LTP_LIST="${LTP_LIST:-${ROOT}/tests/classic/ltp-list.txt}"
WITH_LTP=0
WITH_ELFUSE=1
WITH_KSFT=1
LTP_NATIVE=0
LTP_DIR="${LTP_DIR:-}"
LTP_EXPLICIT=0
LTP_FILTER="${LTP_FILTER:-}"

usage() {
  cat <<EOF
Usage: $0 [options]

  --ltp               run the curated LTP list (ltp-list.txt)
  --ltp-dir DIR       installed LTP tree (default: build/ltp-install)
  --ltp-native        run LTP binaries directly on a Linux host
  --ltp-only          run only the curated LTP list
  --filter REGEX      only run curated LTP tests matching REGEX
  --ksft-only         skip build/test-* (run kselftests + LTP)
  --elfuse-only       skip kselftests (run build/test-* + LTP)
  -h, --help          show this help

Guest LTP binaries are executed through build/elfuse. On Linux,
--ltp-native runs them without elfuse. Every LTP test has a hard timeout.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ltp) WITH_LTP=1 ;;
    --ltp-dir)
      [[ $# -ge 2 ]] || { echo "error: --ltp-dir requires DIR" >&2; exit 2; }
      LTP_DIR="$2"; shift ;;
    --ltp-native) LTP_NATIVE=1 ;;
    --ltp-only) WITH_LTP=1; WITH_KSFT=0; WITH_ELFUSE=0 ;;
    --ksft-only) WITH_ELFUSE=0 ;;
    --elfuse-only) WITH_KSFT=0 ;;
    --filter)
      [[ $# -ge 2 ]] || { echo "error: --filter requires REGEX" >&2; exit 2; }
      LTP_FILTER="$2"; shift ;;
    --help|-h) usage; exit 0 ;;
    *) echo "error: unknown option: $1 (try --help)" >&2; exit 2 ;;
  esac
  shift
done
if [[ -n "$LTP_DIR" ]]; then
  LTP_EXPLICIT=1
fi

mkdir -p "$LOGDIR"
: > "$OUT"
pass=0; fail=0; hang=0; skip=0; warn=0; total=0
HEAD=$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)
echo "START $(date) HEAD=$HEAD timeout=${TIMEOUT_SEC}s" | tee "${OUT}.meta"

have_timeout() {
  if command -v gtimeout >/dev/null 2>&1; then echo gtimeout
  elif command -v timeout >/dev/null 2>&1; then echo timeout
  else echo ""
  fi
}
TOBIN=$(have_timeout)
if [[ -z "$TOBIN" ]]; then
  echo "error: timeout(1) or gtimeout(1) required (coreutils)" >&2
  exit 1
fi

# Kill the test 5s after the TERM if it ignores the timeout.
run_timeout() {
  local secs="$1"; shift
  "$TOBIN" -k 5 "$secs" "$@"
}

run_one() {
  local label="$1" bin="$2"
  total=$((total+1))
  local log="$LOGDIR/${label//\//_}.log"
  if [[ ! -x "$bin" ]]; then
    printf '%s\tFAIL\t0s\tmissing binary\n' "$label" | tee -a "$OUT"
    fail=$((fail+1)); return
  fi
  local start end dur rc eff_timeout
  eff_timeout="$TIMEOUT_SEC"
  case "$label" in
    ks-raw_skew) eff_timeout=180 ;;
  esac
  start=$(date +%s)

  # Guest cwd tracks host cwd; helpers like pidfd_exec_helper are next to the
  # binary.
  (
    cd "$(dirname "$bin")" || exit 127
    elfuse_args=()
    if [[ -d "$CLASSIC_SYSROOT" ]]; then
      elfuse_args+=(--sysroot "$CLASSIC_SYSROOT")
    fi
    run_timeout "$eff_timeout" "$ELFUSE" "${elfuse_args[@]}" "$bin"
  ) >"$log" 2>&1
  rc=$?
  end=$(date +%s); dur=$((end-start))
  if [[ "$rc" -eq 124 || "$rc" -eq 137 || "$rc" -eq 142 || "$rc" -eq 143 ]]; then
    if [[ "$dur" -ge $((eff_timeout - 2)) ]]; then
      snippet=$(tr '\n' '|' < "$log" | cut -c1-160)
      printf '%s\tHANG\t%ss\t%s\n' "$label" "$dur" "$snippet" | tee -a "$OUT"
      hang=$((hang+1))
    else
      snippet=$(tr '\n' '|' < "$log" | cut -c1-160)
      printf '%s\tFAIL\t%ss\trc=%s; %s\n' "$label" "$dur" "$rc" "$snippet" | tee -a "$OUT"
      fail=$((fail+1))
    fi
  elif [[ "$rc" -eq 0 ]]; then
    printf '%s\tPASS\t%ss\t\n' "$label" "$dur" | tee -a "$OUT"
    pass=$((pass+1))
  elif [[ "$rc" -eq 4 ]]; then
    snippet=$(tr '\n' '|' < "$log" | cut -c1-120)
    printf '%s\tSKIP\t%ss\trc=4; %s\n' "$label" "$dur" "$snippet" | tee -a "$OUT"
    skip=$((skip+1))
  else
    snippet=$(tr '\n' '|' < "$log" | cut -c1-200)
    printf '%s\tFAIL\t%ss\trc=%s; %s\n' "$label" "$dur" "$rc" "$snippet" | tee -a "$OUT"
    fail=$((fail+1))
  fi
}

need_elfuse=0
if [[ "$WITH_KSFT" -eq 1 || "$WITH_ELFUSE" -eq 1 ]]; then
  need_elfuse=1
fi
if [[ "$WITH_LTP" -eq 1 && "$LTP_NATIVE" -eq 0 ]]; then
  need_elfuse=1
fi
if [[ "$WITH_LTP" -eq 1 && "$LTP_NATIVE" -eq 1 && "$(uname -s)" != "Linux" ]]; then
  echo "error: --ltp-native requires a Linux host; use guest mode on $(uname -s)" >&2
  exit 1
fi
if [[ "$WITH_LTP" -eq 1 && "$LTP_EXPLICIT" -eq 1 && ! -d "$LTP_DIR" ]]; then
  echo "error: --ltp-dir not found: $LTP_DIR" >&2
  exit 1
fi
if [[ "$need_elfuse" -eq 1 && ! -x "$ELFUSE" ]]; then
  echo "error: $ELFUSE missing; build elfuse first" >&2
  exit 1
fi

resolve_ltp_root() {
  local cand
  if [[ -n "$LTP_DIR" ]]; then
    [[ -d "$LTP_DIR" ]] || return 1
    (cd "$LTP_DIR" && pwd)
    return 0
  fi
  for cand in "$ROOT/build/ltp-install" "$CLASSIC_BIN/ltp"; do
    if [[ -d "$cand" ]]; then printf '%s' "$cand"; return 0; fi
  done
  return 1
}

ltp_binary() {
  local name="$1"
  if [[ -n "$LTP_ROOT" ]]; then
    if [[ -x "$LTP_ROOT/testcases/bin/$name" ]]; then
      printf '%s' "$LTP_ROOT/testcases/bin/$name"; return 0
    fi
    if [[ -x "$LTP_ROOT/$name" ]]; then
      printf '%s' "$LTP_ROOT/$name"; return 0
    fi
  fi
  return 1
}

ltp_snippet() {
  local log="$1" marker="$2" s
  s=$(grep -E "(^|[^A-Za-z])(${marker}):" "$log" 2>/dev/null | tail -n 1 | cut -c1-200)
  [[ -n "$s" ]] || s=$(tr '\n' '|' < "$log" | cut -c1-200)
  printf '%s' "$s"
}

run_ltp_one() {
  local name="$1"; shift
  local log="$LOGDIR/ltp_${name//\//_}.log"
  local bin runroot start end dur rc eff_timeout snippet
  total=$((total+1))
  if ! bin=$(ltp_binary "$name"); then
    printf '%s\tFAIL\t0s\tmissing binary; install LTP or fix --ltp-dir\n' "ltp:$name" | tee -a "$OUT"
    fail=$((fail+1)); return
  fi
  case "$bin" in
    */testcases/bin/*) runroot="${bin%/testcases/bin/*}" ;;
    *) runroot="$(dirname "$bin")" ;;
  esac
  eff_timeout="${LTP_TIMEOUT:-$TIMEOUT_SEC}"
  case "$eff_timeout" in ''|*[!0-9]*) eff_timeout="$TIMEOUT_SEC" ;; esac
  [[ "$eff_timeout" -ge 2 ]] || eff_timeout=2
  start=$(date +%s)
  (
    cd "$runroot" || exit 127
    export LTPROOT="$runroot"
    PATH="$(dirname "$bin"):$PATH"
    export PATH
    cmd=()
    if [[ "$LTP_NATIVE" -eq 1 ]]; then
      cmd+=("$bin")
    else
      elfuse_args=()
      [[ -d "$CLASSIC_SYSROOT" ]] && elfuse_args+=(--sysroot "$CLASSIC_SYSROOT")
      cmd+=("$ELFUSE" "${elfuse_args[@]}" "$bin")
    fi
    run_timeout "$eff_timeout" "${cmd[@]}" "$@"
  ) >"$log" 2>&1
  rc=$?
  end=$(date +%s); dur=$((end-start))
  if [[ "$rc" -eq 124 || "$rc" -eq 137 || "$rc" -eq 142 || ( "$rc" -eq 143 && "$dur" -ge $((eff_timeout - 2)) ) ]]; then
    snippet=$(tr '\n' '|' < "$log" | cut -c1-160)
    printf '%s\tHANG\t%ss\ttimeout=%ss; %s\n' "ltp:$name" "$dur" "$eff_timeout" "$snippet" | tee -a "$OUT"
    hang=$((hang+1))
  elif (( rc & 3 )); then
    snippet=$(ltp_snippet "$log" 'TFAIL|TBROK')
    printf '%s\tFAIL\t%ss\trc=%s; %s\n' "ltp:$name" "$dur" "$rc" "$snippet" | tee -a "$OUT"
    fail=$((fail+1))
  elif [[ "$rc" -eq 32 ]] && ! grep -Eq '(TFAIL|TBROK|TWARN):' "$log"; then
    snippet=$(ltp_snippet "$log" 'TCONF')
    printf '%s\tSKIP\t%ss\trc=%s; %s\n' "ltp:$name" "$dur" "$rc" "$snippet" | tee -a "$OUT"
    skip=$((skip+1))
  elif grep -Eq '(TFAIL|TBROK):' "$log"; then
    snippet=$(ltp_snippet "$log" 'TFAIL|TBROK')
    printf '%s\tFAIL\t%ss\trc=%s; %s\n' "ltp:$name" "$dur" "$rc" "$snippet" | tee -a "$OUT"
    fail=$((fail+1))
  elif grep -Eq 'TWARN:' "$log"; then
    snippet=$(ltp_snippet "$log" 'TWARN')
    printf '%s\tWARN\t%ss\tTWARN; %s\n' "ltp:$name" "$dur" "$snippet" | tee -a "$OUT"
    warn=$((warn+1))
  elif (( rc & 4 )); then
    snippet=$(ltp_snippet "$log" 'TWARN')
    printf '%s\tWARN\t%ss\tTWARN; %s\n' "ltp:$name" "$dur" "$snippet" | tee -a "$OUT"
    warn=$((warn+1))
  elif [[ "$rc" -eq 0 ]]; then
    printf '%s\tPASS\t%ss\t\n' "ltp:$name" "$dur" | tee -a "$OUT"
    pass=$((pass+1))
  else
    snippet=$(tr '\n' '|' < "$log" | cut -c1-200)
    printf '%s\tFAIL\t%ss\trc=%s; %s\n' "ltp:$name" "$dur" "$rc" "$snippet" | tee -a "$OUT"
    fail=$((fail+1))
  fi
}

LTP_ROOT=""
if [[ "$WITH_LTP" -eq 1 ]]; then
  LTP_ROOT="$(resolve_ltp_root || true)"
  if [[ "$LTP_EXPLICIT" -eq 1 && -z "$LTP_ROOT" ]]; then
    exit 1
  fi
fi

if [[ "$WITH_KSFT" -eq 1 ]]; then
  echo "=== kselftests ===" | tee -a "$OUT"
  if [[ -f "${ROOT}/tests/classic/ksft-binaries.txt" ]]; then
    while IFS= read -r name || [[ -n "$name" ]]; do
      [[ -z "$name" || "$name" == \#* ]] && continue
      run_one "$name" "${CLASSIC_BIN}/${name}"
    done < "${ROOT}/tests/classic/ksft-binaries.txt"
  else
    for bin in "${CLASSIC_BIN}"/ks-*; do
      [[ -e "$bin" ]] || continue
      run_one "$(basename "$bin")" "$bin"
    done
  fi
fi

if [[ "$WITH_ELFUSE" -eq 1 ]]; then
  echo "=== curated elfuse ===" | tee -a "$OUT"
  while IFS= read -r t || [[ -n "$t" ]]; do
    [[ -z "$t" || "$t" == \#* ]] && continue
    run_one "elfuse:$t" "${ELFROOT}/$t"
  done < "${ROOT}/tests/classic/curated-elfuse.txt"
fi

if [[ "$WITH_LTP" -eq 1 ]]; then
  echo "=== LTP subset ===" | tee -a "$OUT"
  if [[ -z "$LTP_ROOT" ]]; then
    echo "error: no LTP install found (tried build/ltp-install, build/classic/ltp); run tests/classic/fetch-and-build-ltp.sh or pass --ltp-dir" | tee -a "$OUT"
  fi
  if [[ ! -f "$LTP_LIST" ]]; then
    echo "error: missing $LTP_LIST" | tee -a "$OUT"
    fail=$((fail+1))
  else
    ltp_selected=0
    while IFS= read -r line || [[ -n "$line" ]]; do
      line="${line%%#*}"
      line="${line#"${line%%[![:space:]]*}"}"
      line="${line%"${line##*[![:space:]]}"}"
      [[ -z "$line" ]] && continue
      set -- $line
      name="$1"; shift
      if [[ -n "$LTP_FILTER" ]] && ! printf '%s\n' "$name" | grep -Eq "$LTP_FILTER"; then
        continue
      fi
      ltp_selected=$((ltp_selected + 1))
      run_ltp_one "$name" "$@"
    done < "$LTP_LIST"
    if [[ -n "$LTP_FILTER" && "$ltp_selected" -eq 0 ]]; then
      echo "error: --filter '$LTP_FILTER' matched no curated LTP tests" | tee -a "$OUT"
      fail=$((fail+1))
    fi
  fi
fi

echo "DONE $(date) pass=$pass fail=$fail hang=$hang skip=$skip warn=$warn total=$total" | tee -a "${OUT}.meta"
printf 'SUMMARY\tpass=%s\tfail=%s\thang=%s\tskip=%s\twarn=%s\ttotal=%s\n' "$pass" "$fail" "$hang" "$skip" "$warn" "$total" | tee -a "$OUT"
if [[ "$fail" -gt 0 || "$hang" -gt 0 || "$warn" -gt 0 || "$total" -eq 0 ]]; then
  exit 1
fi
exit 0
