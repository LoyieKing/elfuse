#!/usr/bin/env bash
# Sparse-fetch Linux kselftests and cross-build curated binaries into
# build/classic/.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${ROOT}/build/classic"
SRC="${ELFUSE_CLASSIC_SRC:-${ROOT}/externals/linux-kselftests}"
LINUX_URL="${LINUX_URL:-https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git}"
# Fall back to GitHub mirror if needed
LINUX_URL_FALLBACK="https://github.com/torvalds/linux.git"
CC="${CROSS_CC:-aarch64-linux-gnu-gcc}"
JOBS="${JOBS:-$(sysctl -n hw.ncpu 2>/dev/null || echo 4)}"

mkdir -p "$OUT" "${ROOT}/externals"

if [[ ! -d "$SRC/.git" ]]; then
  echo "Sparse-cloning linux kselftests into $SRC ..."
  rm -rf "$SRC"
  if ! git clone --depth 1 --filter=blob:none --sparse "$LINUX_URL" "$SRC" 2>/dev/null; then
    git clone --depth 1 --filter=blob:none --sparse "$LINUX_URL_FALLBACK" "$SRC"
  fi
  git -C "$SRC" sparse-checkout set \
    tools/testing/selftests/futex \
    tools/testing/selftests/timers \
    tools/testing/selftests/clone3 \
    tools/testing/selftests/rseq \
    tools/testing/selftests/pidfd \
    tools/testing/selftests/kcmp \
    tools/testing/selftests/kselftest.h \
    tools/testing/selftests/kselftest_harness.h \
    tools/testing/selftests/clone3/clone3_selftests.h \
    include/uapi/linux/futex.h \
    include/uapi/linux/prctl.h \
    include/uapi/asm-generic/unistd.h
fi

SHIM="${ROOT}/tests/classic/shims"
GETTID_CFLAGS=(-include "${SHIM}/gettid_fix.h")

build_one() {
  local name="$1"; shift
  local src="$1"; shift
  local out="${OUT}/ks-${name}"
  echo "CC ks-${name}"
  # shellcheck disable=SC2086
  "$CC" -static -O2 -g -pthread \
    -D_GNU_SOURCE \
    "${GETTID_CFLAGS[@]}" \
    -I"${SRC}/tools/testing/selftests" \
    -I"${SRC}/tools/testing/selftests/futex/include" \
    -I"${SRC}/include/uapi" \
    "$@" \
    -o "$out" "$src" || {
      echo "WARN: failed ks-${name}" >&2
      return 0
    }
}

FUTEX="${SRC}/tools/testing/selftests/futex/functional"
TIMERS="${SRC}/tools/testing/selftests/timers"
CLONE3="${SRC}/tools/testing/selftests/clone3"
RSEQ="${SRC}/tools/testing/selftests/rseq"
PIDFD="${SRC}/tools/testing/selftests/pidfd"
KCMP="${SRC}/tools/testing/selftests/kcmp"

# Futex functional
for s in \
  futex_requeue futex_wait futex_wait_timeout futex_wait_wouldblock \
  futex_wait_uninitialized_heap futex_wait_private_mapped_file \
  futex_waitv futex_requeue_pi futex_requeue_pi_mismatched_ops \
  futex_requeue_pi_signal_restart futex_lock_pi_exiting
do
  [[ -f "${FUTEX}/${s}.c" ]] || continue
  build_one "$s" "${FUTEX}/${s}.c"
done

# Prefer cmp_requeue_pi if present under a different name
if [[ -f "${FUTEX}/futex_cmp_requeue_pi.c" ]]; then
  build_one futex_cmp_requeue_pi "${FUTEX}/futex_cmp_requeue_pi.c"
fi

# Timers
for s in nanosleep nsleep-lat inconsistency-check posix_timers set-timer-lat \
         raw_skew threadtest mqueue-lat rtcpie
do
  # file names may use underscores
  f="${TIMERS}/${s}.c"
  [[ -f "$f" ]] || f="${TIMERS}/${s//-/_}.c"
  [[ -f "$f" ]] || continue
  extra=()
  [[ "$s" == "mqueue-lat" ]] && extra+=(-lrt)
  build_one "$s" "$f" "${extra[@]}"
done

# clone3
for s in clone3 clone3_clear_sighand clone3_set_tid; do
  [[ -f "${CLONE3}/${s}.c" ]] || continue
  build_one "$s" "${CLONE3}/${s}.c"
done

# rseq (basic + percpu)
if [[ -f "${RSEQ}/basic_test.c" ]]; then
  build_one rseq-basic_test "${RSEQ}/basic_test.c" "${RSEQ}/rseq.c" -I"${RSEQ}"
fi
if [[ -f "${RSEQ}/basic_percpu_ops_test.c" ]]; then
  build_one rseq-basic_percpu_ops_test "${RSEQ}/basic_percpu_ops_test.c" \
    "${RSEQ}/rseq.c" -I"${RSEQ}"
fi

# pidfd
for s in pidfd_test pidfd_open_test pidfd_poll_test pidfd_wait \
         pidfd_getfd_test pidfd_fdinfo_test pidfd_info_test; do
  [[ -f "${PIDFD}/${s}.c" ]] || continue
  build_one "$s" "${PIDFD}/${s}.c" -I"${PIDFD}"
done
# Helper exec'd by relative name from pidfd_info_test (AT_FDCWD); no ks- prefix.
if [[ -f "${PIDFD}/pidfd_exec_helper.c" ]]; then
  echo "CC pidfd_exec_helper"
  "$CC" -static -O2 -g -pthread -D_GNU_SOURCE \
    "${GETTID_CFLAGS[@]}" \
    -I"${SRC}/tools/testing/selftests" \
    -I"${SRC}/include/uapi" \
    -I"${PIDFD}" \
    -o "${OUT}/pidfd_exec_helper" "${PIDFD}/pidfd_exec_helper.c" || \
    echo "WARN: failed pidfd_exec_helper" >&2
fi

# kcmp + robust (timers tree sometimes has robust elsewhere)
if [[ -f "${KCMP}/kcmp_test.c" ]]; then
  build_one kcmp_test "${KCMP}/kcmp_test.c"
fi
# robust_list may live under futex or rseq-adjacent; try common paths
for cand in \
  "${SRC}/tools/testing/selftests/futex/functional/robust_list.c" \
  "${SRC}/tools/testing/selftests/futex/functional/futex_robust_list.c"
do
  if [[ -f "$cand" ]]; then
    build_one robust_list "$cand" -ldl
    break
  fi
done

echo "Built into $OUT:"
ls -1 "$OUT"/ks-* 2>/dev/null | wc -l
