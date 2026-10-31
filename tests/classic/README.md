# External Linux suites

The classic runner executes selected upstream kselftests and Linux Test
Project tests, plus an existing list of elfuse guest binaries. The
[scheduler reference](../../docs/scheduler.md) defines the compatibility
boundary; current failures remain failures.

## Kselftests

```sh
bash tests/classic/fetch-and-build.sh
make classic-tests
```

The kselftest fetcher uses externals/linux-kselftests or ELFUSE_CLASSIC_SRC.
Its current source is not revision-pinned. Record the exact checkout revision
with results; do not treat a moving checkout as a stable Linux reference.
Built ks-* binaries are in build/classic. The runner runs beside each binary
so sibling helpers can be found. ELFUSE selects the runtime executable and
CLASSIC_SYSROOT selects its optional sysroot.

## Linux Test Project

The fixture lock pins official LTP 20260930 source and its SHA-256 digest.
The source remains under externals/ltp and the installed tests under
build/ltp-install. The build uses upstream configure, libltp, test Makefiles,
and install rules. LTP sources and licenses are not copied into the runtime.

Required tools: make, a Linux-targeting C toolchain, pkg-config/pkgconf,
file, tar with xz support, curl/wget, and sha256sum/shasum. The release archive
contains configure. No Docker image or unpublished source checkout is needed.

On macOS, the default is static AArch64 Linux cross-compilation:

```sh
make ltp-tests-build
# Equivalent with a bounded build concurrency:
bash tests/classic/fetch-and-build-ltp.sh --jobs 2
```

The default target compiler is aarch64-linux-gnu-gcc. LTP_CROSS_CC selects
another executable; --host selects its target triplet. HOSTCC selects the
native build-tool compiler. --sysroot overrides the target sysroot. Static
cross builds need glibc headers and static libraries, including pthread.
The build log is externals/ltp/build.log. A selected missing source, build
failure, or missing installed binary fails the build.

Run a short slice before selecting the whole list:

```sh
bash tests/classic/run.sh --ltp-only --filter '^sched_getparam0[13]$'
bash tests/classic/run.sh --ltp-only --filter '^fork01$'
make ltp-tests
```

The list is tests/classic/ltp-list.txt. --filter is a regular expression over
LTP binary names. --ltp adds LTP to the kselftest/elfuse selection;
--ltp-only selects LTP alone. Tests run from their installation root with
LTPROOT and PATH set, so installed helpers remain accessible. The full
installed directories may contain additional upstream tests beyond the list.

An existing installation can be checked and used without rebuilding:

```sh
bash tests/classic/fetch-and-build-ltp.sh --check /path/to/ltp-install
bash tests/classic/run.sh --ltp-only --ltp-dir /path/to/ltp-install
```

The check verifies selected ELF binaries and target architecture. Transport
the complete installed directory, not just individual executables; helpers
and runtime resources can be test dependencies. The selected static build
needs no separate guest libc installation.

On Linux, a native build uses the host compiler; a cross build uses --host:

```sh
bash tests/classic/fetch-and-build-ltp.sh
bash tests/classic/run.sh --ltp-only --ltp-native
# Cross-build on Linux for the macOS AArch64 guest:
bash tests/classic/fetch-and-build-ltp.sh --host aarch64-linux-gnu
```

Run the native Linux reference in a disposable VM with the capabilities
required by the selected tests. Record kernel/configuration, CPU mask,
privileges, libc, compiler and source lock alongside results. An LTP TCONF
skip leaves that configuration-dependent requirement unverified.

## Results

The default outputs are build/classic-results.txt and build/classic-logs.
CLASSIC_RESULTS and CLASSIC_LOGDIR isolate separate runs. TEST_TIMEOUT is the
per-test timeout, with LTP_TIMEOUT as an LTP-specific override. The raw_skew
kselftest retains its 180-second limit. timeout/gtimeout is required.

The runner exits nonzero for failures, hangs, missing binaries, or zero
selected cases. kselftest exit 4 is SKIP. LTP uses a bitmask: TFAIL/TBROK,
TWARN and abnormal termination fail; pure TCONF (32) is SKIP; zero is PASS.
Linux expected results stay unchanged. Classify failures against the work
plan: same-VM scheduling and common fork/exec are required; cross-VM priority,
capacity and PI guarantees are accepted differences, and unsupported shared-mm
exec must be rejected safely. An accepted difference needs a matching observed
cause; it does not excuse crashes, hangs or unrelated failures. The runner
reports raw Linux results and does not encode these acceptance classifications.

The local [scheduler regressions](../scheduler/README.md) cover targeted
fork, task-state, signal migration and scheduler attribute contracts that
complement upstream selection. Neither selected external suite replaces the
complete cutover acceptance matrix.
