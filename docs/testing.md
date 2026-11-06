# Building And Testing

This document describes the development toolchain, the main `make` targets, and
how the repository validation flow is structured.

## Build Requirements

Host build requirements:

- Apple Silicon macOS host
- macOS 13 or newer
- Xcode Command Line Tools
- `clang`
- `codesign`
- GNU `make`
- GNU `objcopy` or `llvm-objcopy`
- GNU coreutils
- `bash` 3.2+ (the version Apple ships as `/bin/bash`) is sufficient for
  the test harness; no Homebrew `bash` is required. See
  `tests/lib/bash-compat.sh` for the cross-version shims (a portable
  microsecond clock and the parallel-array lookup pattern that replaces
  associative arrays). When editing a shell script under `tests/` or
  `scripts/`, the conventions in that file's header are the source of
  truth: no `EPOCHREALTIME`, no `declare -A`, no `mapfile`, no
  `${var^^}` / `${var,,}` case-conversion, and guard any potentially
  empty array expansion with `${arr[@]+"${arr[@]}"}` so `set -u` does
  not trip on it.
- Hypervisor entitlement: `com.apple.security.hypervisor`

Guest test builds additionally require:

- An AArch64 Linux cross-compiler for C test programs
- An AArch64 bare-metal toolchain for the assembly smoke test

`make elfuse-gtk` and `make test-gtk-native-host` additionally require GTK
4.24 or newer and `pkg-config` (`brew install gtk4 pkg-config`). These targets
do not add GTK to `build/elfuse` or to the default test gate. GUI guests need
their own Linux GTK libraries and fonts in the sysroot; see
[Native macOS GTK Windows](usage.md#native-macos-gtk-windows).

The toolchain defaults are defined in `mk/toolchain.mk`.
These variables are intended to be overridden when needed:

- `CROSS_COMPILE`
- `BAREMETAL_CROSS`
- `SIGN_IDENTITY`

### Installing the toolchains with Homebrew

The following block installs everything needed to run both `make check` and
the full `make test-matrix` (including the `qemu-aarch64` reference run). Run it
once on an Apple Silicon macOS host:

```sh
# GNU coreutils (gtimeout): required by the test harness timeout wrapper
brew install coreutils

# GNU objcopy
brew install binutils

# Bare-metal aarch64-none-elf toolchain used by `make check`
brew install --cask gcc-aarch64-embedded

# AArch64 Linux cross-compiler for guest test binaries (make test-matrix)
brew tap messense/macos-cross-toolchains
brew trust --formula messense/macos-cross-toolchains/aarch64-unknown-linux-gnu
brew install aarch64-unknown-linux-gnu

# QEMU: boots the Alpine minirootfs for the qemu-aarch64 reference run
brew install qemu
```

Depending on the setup, the bare-metal toolchain may also need adding to
`PATH`:

```sh
export PATH="/opt/homebrew/opt/aarch64-elf-gcc/bin:$PATH"
```

## Main Targets

The most useful development targets are:

```sh
make elfuse
make check
make test-rosetta-all
make test-gdbstub
make test-matrix
make verify
make lint
make clean
```

What they do:

- `make elfuse`: build and sign `build/elfuse`
- `make check`: fast elfuse-internal gate. Runs, in order:
  - `scripts/check-syscall-coverage.py` so any new `dispatch.tbl`
    entry without a direct or aliased test reference fails the build
  - `scripts/check-eintr-contract.py` so a new interruptible wait fails
    the build until it states whether it may be restarted (`forbids`,
    `restartable`, or `not-a-wait`), with the `forbids` claims checked
    against the source
  - `scripts/check-lock-order.py` so a new file-scope `pthread_mutex_t`
    or `pthread_rwlock_t` that the lock-ordering block at the top of
    `src/syscall/internal.h` does not name fails the build. Membership
    only: whether the lock belongs in the ordered list or the leaf list
    stays a judgement for review
  - `scripts/check-atomics.py` so a C11 atomic call written without its
    `_explicit` form, or a `__atomic_*` / `__sync_*` builtin, fails the
    build. Plain-operator access to an `_Atomic` object needs the
    declarations resolved and stays a review question
  - `scripts/check-ascii.py` so a source file carrying non-ASCII outside
    the comment-diagram set fails the build
  - `scripts/check-svc-tails.py` so an HVC #5 return tail cannot reach EL0
    without the X7 ptrace test
  - `scripts/check-skill-refs.py` so a path, make target, or docs section
    a skill names that no longer resolves fails the build
  - `scripts/check-proof-targets.py` so a header added under `src/proved/`
    with no proof target fails here rather than on the branch later. It
    asks make for the target list, which is the point: a `VERIFY_<T>_SRC`
    block written below the `:=` that builds `VERIFY_TARGETS` parses fine
    and generates no rule
  - the two harness self-tests, `test-config` (that `tests/test-config.sh`
    keeps its CLI mode separate from its sourced mode) and `test-runner`
    (the shared shell runner's output matching and exit-status checks), so
    the harness is known good before any lane leans on it
  - the unit suite from `tests/manifest.txt` -- deliberately narrow: the
    elfuse-internal implementation tests with no real Linux counterpart (the
    EL1 shim fast-path suite, `test-mremap-infra`, `test-mremap-fork-tracking`,
    and `test-oom-proc`), plus `test-mremap-tail-emfile`, whose host-reserve
    regression also runs in the elfuse matrix lane, and whatever
    `mk/tests.mk`'s `SANITIZER_SECTIONS`
    needs for the `check-{asan,ubsan,tsan}` lanes. Everything that is
    meaningful to cross-check against a real Linux kernel lives exclusively
    in `tests/test-matrix.sh`'s `run_unit_tests` instead (see Test Matrix
    below) -- `make check` alone is *not* a substitute for it
  - the TLBI RVAE1IS encoder unit test
  - the proctitle argv-tail and low-stack regressions
  - the BusyBox applet smoke suite (auto-resolved from
    `externals/test-fixtures/aarch64-musl/staticbin/bin/busybox` or
    downloaded into `build/busybox` on first run)
  - the filename codec and case-exact path resolution unit tests
  - the sysroot lanes, each a recipe in `mk/tests.mk` that provisions
    its own sysroot and asserts the on-disk shape host-side after the
    guest exits: the filename family (one representation per name,
    relative and dirfd-relative names, non-ASCII, full length,
    host-staged escape shapes, concurrent colliding creates), the
    edge shapes (sysroot at `/`, no sysroot, the guest-visible cwd),
    byte-exact lookup, host fallback, symlink escapes and targets,
    case collisions, the decode boundary (inotify names, exec
    identity, `PT_INTERP`, pathname `AF_UNIX` sockets), the host
    path ceiling (`ENAMETOOLONG` where macOS's 1024-byte `PATH_MAX`
    undercuts the guest's 4096, a macOS-only boundary, which is why
    the lane is absent from the qemu matrix), and the frozen-spelling
    corpus (on-disk escapes staged byte-for-byte from
    `tests/casefold-vectors.h` and read back through a live sysroot)
  - the byte-exact oracle lane (`check-name-caseexact`): the name
    suite re-run against a case-sensitive APFS sparsebundle. The
    volume itself enforces the byte-exact matching the tests assert,
    so a failure there means a test's expectation (not the volume)
    is wrong, whatever the folding lane says of it. The i18n lane
    runs in its `csapfs` mode, pinning the two divergences that
    configuration accepts (see `docs/filenames.md`)
  - the sysroot procfs exec, FUSE-on-Alpine, and `timeout=0` regressions
  - the Rosetta CLI gating regressions
  - the hot-syscall guardrail (`tests/test-bench-guardrail.sh`)
    asserting `getpid`, libc `clock_gettime`, and 1-byte
    `/dev/urandom` reads stay under their ns/op ceilings
- `make test-rosetta-all`: Rosetta-specific x86_64 acceptance scripts
  (`test-rosetta-cli`, `test-rosetta-failure-modes`,
  `test-rosetta-statics`, `test-rosetta-alpine`,
  `test-rosetta-audit`, `test-rosetta-jit`, `test-rosetta-glibc`)
- `make test-sysroot-name-soak`: minutes of threaded and forked churn over
  one case-colliding name set (`SECS=N` overrides the default 120). Excluded
  from `check` for its runtime; a pass is only the absence of a reproducer,
  and the invariants are stated in `tests/test-sysroot-name-soak.c`
- `make test-busybox`: just the BusyBox suite, useful when iterating on a
  single applet failure without rerunning the unit suite
- `make test-fuse-alpine`: validate guest `/dev/fuse` + `mount("fuse")`
  against the Alpine musl sysroot fixture
- `make test-gdbstub`: debugger integration checks against the built-in GDB stub
- `make test-sharun`: run sharun and its probe under elfuse in six arms of
  increasing host requirements. The prebuilt launcher (`--version`) is a static
  aarch64 ELF and runs anywhere elfuse does; the x86_64 build of the same
  release goes through the Rosetta path as a static-pie musl Rust binary, a
  shape no other lane covers, and skips without the translator. The cross-built
  probe covers the loader path (`DT_NEEDED`, `dlopen`, `$ORIGIN` rpath, libm,
  pthreads, fork) that no other aarch64 lane reaches, and skips without the
  cross-glibc sysroot. Three further arms drive a bundle: the probe under the
  real launcher, `--gen-lib-path` walking the tree and writing back to it from
  inside the guest, and the negative path where the `dlopen` target is removed
  and the loader's errno must surface rather than hang or crash. Nothing shells
  out to `lib4bin`, so there is no Linux dependency: `tests/build-sharun-bundle.sh`
  writes the bundle layout directly from the launcher, the probe, and a prebuilt
  Debian glibc fetched by `tests/fetch-glibc.sh`. Point `SHARUN_FIXTURE_DIR` at
  an unpacked bundle to test one built elsewhere instead. The lane skips
  entirely with status 77 in two cases: it cannot reach the launcher for the
  first arm, or that arm passed but every dynamic-loader arm skipped (no
  cross-glibc sysroot and no `SHARUN_FIXTURE_DIR`). The second
  keeps a run that covered only the static launcher from reporting the same
  green as one that exercised the loader. Launcher
  binaries and the glibc package are pinned and digest-checked by
  `tests/sharun-fixture.lock` and cached under `$FIXTURES_DIR`, so they download
  once and survive `make clean`. Every download happens inside the lane rather
  than as a make prerequisite, so an unreachable network skips the affected arms
  instead of failing `make check`. Editing a probe source under
  `tests/fixtures/sharun/` is picked up on the next run: make rebuilds
  `$(BUILD_DIR)/probe` and its two DSOs from those sources, and the bundle is
  assembled from the rebuilt binaries. It also runs as a lane of `make check`.
- `make test-matrix`: cross-check `elfuse` (aarch64), QEMU (aarch64),
  and `elfuse` (x86_64-via-Rosetta) on overlapping corpora
- `make verify`: every Frama-C WP proof target, one `frama-c` process each
  and parallel by default (`VERIFY_JOBS=1` for serial). Each target names a
  function set and discharges its obligations under `-wp-rte`; `mk/verify.mk`
  is the target list and records the data model and memory model each one
  assumes. Needs `opam install frama-c` plus `why3 config detect`; without
  the latter WP aborts with "Prover not found" instead of reporting unproved
  goals. `make verify-<name>` runs one target
- `make verify-mutants`: assert every proof target rejects a known-broken
  source, so a contract whose clauses do not bite fails. `MUTANT_TARGET=<name>`
  narrows it to one target, `MUTANT_SINCE=<ref>` to what a branch touched, and
  `MUTANT_JOBS=N` overrides the one-per-core default
- `make check-contracts`: rebuild with `-DELFUSE_CONTRACT_ASSERT` so the
  expressible `proved/gva.h` preconditions are checked on every call the suite
  makes. Separate from `make check` because those checks sit on the
  `guest_read` / `guest_write` hot path
- `make lint`: static analysis through `clang-tidy`

## Quick Iteration

For normal code changes touching syscall or runtime logic:

```sh
make elfuse
make check
make test-matrix-elfuse-aarch64
```

`make check` alone only covers elfuse-internal plumbing and the sanitizer
subset now; `test-matrix-elfuse-aarch64` is what actually exercises the full
unit-test surface against `build/elfuse` (no qemu boot needed, so it is about
as fast to iterate with as `make check` was before the split). For changes
that touch procfs, path handling, `/dev`, FUSE, networking, dynamic linking,
or guest process semantics, also cross-check against the qemu reference
kernel:

```sh
make test-matrix-qemu-aarch64
```

or run all matrix modes back-to-back with `make test-matrix`.

`make check` already runs the BusyBox applet suite as a second stage, so a
green `make check` covers BusyBox validation. Use `make test-busybox` to
iterate on a single applet failure without rerunning the unit suite.

## Test Matrix

The matrix driver lives in `tests/test-matrix.sh`. It currently covers three
execution modes:

- `elfuse-aarch64`: every binary is executed via `build/elfuse` on macOS
- `qemu-aarch64`: the same binaries run natively inside an Alpine
  `aarch64-linux-musl` minirootfs booted by `qemu-system-aarch64`
- `elfuse-x86_64`: Rosetta-for-Linux acceptance scripts against the staged
  Alpine x86_64 fixture tree

The goal is not to compare performance. The goal is to compare guest-observable
behavior against a ground-truth Linux AArch64 environment so that any divergence
in syscall translation, procfs emulation, or process semantics is caught early.

`run_unit_tests` in `tests/test-matrix.sh` is the full aarch64 unit-test
surface -- every binary that is meaningful to run against a real kernel, which
is almost everything. It deliberately excludes only the handful of tests that
assert elfuse-internal implementation details with no meaningful counterpart
on a real kernel (the EL1 shim fast-path suite, `test-mremap-infra`,
`test-mremap-fork-tracking`, and `test-oom-proc` -- these live solely in
`tests/manifest.txt` / `make check`, see that file's header for the full split
rationale). `test-mremap-tail-emfile` is the exception: it is also listed in
`run_unit_tests` for the `elfuse-aarch64` lane and is `QEMU_SKIP`'d because its
host-reserve assertion has no real-kernel counterpart. There is no separate
"core" vs "extended" test set inside the matrix; a test that has a real,
understood divergence from the qemu reference kernel is listed in
`QEMU_SKIP` with a comment explaining why instead -- see that variable in
`tests/test-matrix.sh` for the current list and rationale. `run_unit_tests`
runs in both `elfuse-aarch64` and `qemu-aarch64` modes, so most tests are
exercised twice per matrix run: once against `build/elfuse`, once against the
real kernel.

`ELFUSE_SKIP` is the same mechanism pointing the other way: tests that run only
against the reference kernel. A test belongs there when it needs something the
elfuse lane cannot provide: most often a writable, byte-exact root, which that
lane has no sysroot to give and which the macOS root is not. A skip is not a
pass, so the `elfuse-aarch64` row of `EXPECTED_BASELINES` does not move when a
test is added to the list.

Both lists match a test by its label, and a label matching nothing fails
silently while still reading as deliberate policy, so
`.ci/check-matrix-lists.sh` rejects a label that names no registered test and a
label present in both lists, which would run under no runner at all.

The filename tests are `ELFUSE_SKIP`'s main occupants. They assert that names
differing only in case, or only in Unicode normalization, stay distinct,
exactly what a case-folding host volume is entitled to get wrong. Running them
against the VM's tmpfs turns those expectations into measurements; their
elfuse-side coverage is the `make check` sysroot lanes, where a real sysroot
exists.

The x86_64 mode is narrower: it aggregates the Rosetta-specific acceptance
scripts and their per-binary summaries into the same matrix runner, including
the Rosetta thread/signal audit smoke, the LuaJIT guest-JIT probe, and the
glibc dynamic-binary acceptance helper.

Run a single mode with `bash tests/test-matrix.sh elfuse-aarch64`,
`bash tests/test-matrix.sh qemu-aarch64`, or
`bash tests/test-matrix.sh elfuse-x86_64`; `all` runs all three back-to-back.

Fixture handling is self-contained:

- On first use, `tests/fetch-fixtures.sh` downloads the required Alpine
  packages and the `linux-virt` kernel into `externals/test-fixtures/` and
  assembles an initramfs. Subsequent runs are zero-config.
- The same fixture tree is reused across the matrix modes.
- When Rosetta mode is requested and the translator is installed,
  `tests/test-matrix.sh` auto-fetches the x86_64 fixture tree
  (`INCLUDE_X86_64=1`) on demand.
- QEMU mode requires `qemu-system-aarch64` on `PATH` (Homebrew `qemu` provides it).
- musl is the only Alpine libc; the glibc-dynamic suite is skipped unless
  `GUEST_GLIBC_*` environment variables point at an external sysroot.

## Rosetta Limitations

`elfuse-x86_64` is expected to inherit two Rosetta-internal limitations that are
not treated as elfuse regressions:

- `SA_RESETHAND` is not reset reliably because Rosetta shadows guest signal
  handler state internally.
- `clone(..., CLONE_SETTLS, tls=0, ...)` can hang.

The x86_64 matrix branch is therefore a Rosetta acceptance gate, not a claim
that translated guests fully match native Linux thread and signal semantics.

## x86_64 Acceptance Inventory and Per-Host Baselines

The `elfuse-x86_64` matrix mode aggregates seven sub-suites. Each one
emits a deterministic per-binary pass list; the matrix runner sums
those into a single `Results:` line and compares against a per-host
baseline. The exact labels each sub-suite emits, and the contract
they verify, are:

- `tests/test-rosetta-cli.sh` (4): `rosetta-disabled-flag`,
  `rosetta-disabled-env`, `rosetta-gdb`, `rosetta-default` --
  command-line gating of the translator path (opt-out flag, env
  override, `--gdb` rejection, install-hint surface).

- `tests/test-rosetta-failure-modes.sh` (3): `no-rosetta-flag`,
  `no-rosetta-env`, `gdb-x86_64` -- command-line rejection paths.
  Self-contained against a synthesized minimal x86_64 ELF; no
  external fixture tree required. The dynamic-linker bring-up and
  mid-process execve scenarios that used to live here are now
  exclusively in the glibc and statics suites against the vendored
  rootfs (see `glibc-hello` / `glibc-hello-via-ldso` and
  `env-execve`).

- `tests/test-rosetta-statics.sh` (20): `echo`, `true`, `false`,
  `printenv`, `expr-zero`, `expr-mul`, `basename`, `dirname`,
  `stat-self`, `factor`, `seq`, `sha256sum`, `md5sum`, `uname-m`, `arch`,
  `busybox-arch-subcommand`, `date-utc`, `id-u`, `nproc`,
  `env-execve` -- statically-linked Alpine busybox applets,
  exercising VZ ioctl gate, `/proc/self/exe` redirect, high-VA mmap,
  and the kbuf alias.

- `tests/test-rosetta-alpine.sh` (33): `cat-fruits-first-line`,
  `wc-l-fruits`, `wc-l-lines`, `wc-c-lines`, `ls-data`, `stat-data`,
  `find-by-name`, `du-sk-data`, `sha256-fruits`,
  `sha256-lines-matches-host`, `sha512-lines`, `md5-fruits`,
  `cksum-fruits`, `sort-first`, `sort-reverse-first`, `pipe-sort-wc`,
  `pipe-tr-uppercase`, `pipe-cat-grep`, `pipe-sed-subst`,
  `pipe-awk-field`, `head-n3`, `tail-n3`, `pipe-sort-uniq`,
  `pipe-cut-field`, `pipe-rev`, `tac-reverse-first-line`, `seq-1-5`,
  `seq-step`, `factor-prime`, `factor-composite`, `diff-identical`,
  `diff-differs`, `pipe-base64-decode` -- broader file I/O, text
  processing, and host-shell pipelines stitched through Rosetta on
  every stage.

- `tests/test-rosetta-audit.sh` (2): `audit-known-limitations`,
  `tls0-known-hang` -- bookkeeping probe that asserts the documented
  Rosetta shadowing failures (above) remain the only divergences;
  fails loudly if a new threading/signal-state edge case starts
  diverging.

- `tests/test-rosetta-jit.sh` (2): `luajit-trace`,
  `luajit-coroutine` -- guest-side JIT under translation
  (LuaJIT trace emission + coroutine allocation), covering the
  small-mprotect RW->RX and per-thread icache observation path that
  rosetta's own JIT does not exercise.

- `tests/test-rosetta-glibc.sh` (7): `glibc-hello`,
  `glibc-hello-via-ldso`, `glibc-hello-list`, `glibc-dlopen`,
  `glibc-tls`, `glibc-gdtls`, `glibc-pthread-tls` --
  dynamically-linked glibc x86_64 binary acceptance through
  `--sysroot` against the staged minimal glibc rootfs under
  `externals/test-fixtures/x86_64-glibc/rootfs/`. The first three
  cover load-time `PT_INTERP` resolution and `ld.so --list`
  introspection. `glibc-dlopen` runs `dlopen("libm.so.6")` plus a
  `dlsym(sqrt)` round-trip to exercise the runtime fresh-`.so`-mmap
  codepath, which is distinct from the load-time path the first
  three probes touch. `glibc-tls` reads and writes two
  initial-exec `__thread` variables (one integer, one pointer) so a
  broken FS-register to `TPIDR_EL0` translation surfaces as a
  value mismatch rather than as a silent skip. `glibc-gdtls`
  `dlopen`s a companion `libgdtls.so` whose `__thread` variable
  must use the general-dynamic model (calls `__tls_get_addr`);
  this is the only probe that exercises that lowering path, which
  the initial-exec probe cannot reach. `glibc-pthread-tls`
  `pthread_create`s a worker thread that reads and writes its own
  `__thread` slot; the probe asserts the worker saw its own
  default value (not the main thread's overwritten marker) and that
  the main thread's slot survives the worker's write, so a broken
  per-thread `TPIDR_EL0` setup on additional threads surfaces as
  isolation failure rather than as a silent crash.

Total: 71 expected passes, 0 expected failures.

### Per-Host Baseline Capture

The matrix runner keys its `elfuse-x86_64` baseline by detected host
SoC class. Two classes matter because `sys_mmap_fixed_high_va` takes
different paths under different IPA widths:

- `apple-m1-m2`: 36-bit native IPA, exercises the overflow-segment
  path. Captured on this codebase against Apple M1 hardware
  (MacBookAir10,1). The seven sub-suites land at 71/0/0.

- `apple-m3-plus`: 40-bit native IPA, exercises the bisected-slab
  path (and the M5 slab-bisection variant). Currently held equal to
  `apple-m1-m2` pending operator capture on real M3+ hardware. When
  that capture lands, only the
  `"elfuse-x86_64:apple-m3-plus|<min_pass>|<max_fail>"` row in the
  `EXPECTED_BASELINES` array in `tests/test-matrix.sh` moves; the
  M1/M2 row stays intact.

- `apple-unknown`: fallback for SoC brand strings the detector does
  not recognise. Inherits the M1/M2 numbers and triggers a one-line
  warning so a new SoC does not silently graft onto an existing row.

Class detection reads `sysctl -n machdep.cpu.brand_string` and matches
against `Apple M1`/`Apple M2` (M1/M2) and `Apple M3`/`Apple M4`/`Apple
M5` (M3+). To exercise the M3+ row from an M1/M2 host (and vice
versa) without changing the detector, set
`MATRIX_HOST_CLASS_OVERRIDE=apple-m3-plus` (or `apple-m1-m2`,
`apple-unknown`) before invoking `tests/test-matrix.sh`.

When the seven sub-suites grow or trim a test, the per-sub-suite
counts in the comment block above `EXPECTED_BASELINES` and the
inventory list above must move in the same commit so the per-host
baseline stays in sync with reality. Each `EXPECTED_BASELINES` entry
is a pipe-separated `mode-key|min_pass|max_fail` triple parsed by
`expected_baseline_get()` in `tests/test-matrix.sh`.

## Test Inventory

The repository contains several layers of validation:

- unit-style guest tests compiled from `tests/*.c`
- shell integration suites such as BusyBox, coreutils, and dynamic-loader tests
- debugger integration tests for the GDB stub
- native macOS HVF checks such as multi-vCPU and RWX validation

The quick suite is driven by `tests/driver.sh`, which supports:

- `-f PATTERN` to filter tests
- `-l` to list them
- `-T` for TAP output

Example:

```sh
bash tests/driver.sh -f test-proc
```

## Fault Injection And Recorded Rows

Several failures these lanes have to pin cannot be provoked from a test: a
`malloc` coming back NULL part-way through a backing listing, a `readdir` that
fails part-way through a directory elfuse itself materialized, a slot replaced
inside a window that is sub-microsecond wide unaided, and, on the usbdevfs fd,
each of the three ways an open can fail before it returns. Each has an
environment hook, read once and with no effect at all when unset:

| Variable | Effect | Driven by |
|----------|--------|-----------|
| `ELFUSE_DIR_BACKING_FAULT=N` | the union drain fails with `ENOMEM` once it has buffered N names | `test-dir-backing-drain-error` |
| `ELFUSE_DIR_PRIMARY_READ_FAULT=N` | `readdir` on the synthetic stream fails with `EIO` after N entries | `test-dir-primary-read-error` |
| `ELFUSE_DIR_UNION_BACKING_DELAY_US=N` | widens the window between pinning a directory stream and looking its backing up | `test-dir-union-fd-reuse` |
| `ELFUSE_FD_IDENTITY_WINDOW_US=N` | widens the window between reading a descriptor's stamp and pinning its host fd | `test-fstatfs-fd-identity` |
| `ELFUSE_USBDEV_OPEN_FAULT=info\|blob\|pipe` | fails one step of a usbdevfs open: the model lookup or the descriptor copy with `ENOMEM`, the readiness pipe with `ENFILE` | `test-usbdev-faults` |
| `ELFUSE_USBDEV_PUBLISH_DELAY_US=N` | widens the window between `fd_alloc` publishing a usbdevfs fd and the side table binding it, where a close finds no entry | `test-usbdev-faults` |
| `ELFUSE_USBDEV_RETIRE_DELAY_US=N` | widens the window between the side table binding a usbdevfs fd and the open's recheck, where a close can reap the entry and a sibling open can take its slot | `test-usbdev-faults` |
| `ELFUSE_USBDEV_REAP_DELAY_US=N` | widens the window between the fd-table snapshot a `REAPURB` pass takes and the side-table entry it settles readiness on, where a close and reopen can swap the description underneath it | `test-usbdev-faults` |

`ELFUSE_USB_FIXTURE` is the same shape pointing at enumeration rather than
failure: it stands a deterministic synthetic USB tree up in place of whatever
IOKit reports, so the lanes below have devices to walk on any host.
`ELFUSE_USB_FIXTURE=overflow` stands up 129 address-less devices on one bus for
the `devnum` cap. `ELFUSE_USB_FIXTURE=badifnum` adds one device whose only
interface declares `bInterfaceNumber` 200: every byte is well formed and the
range is the field's own, but nothing anyone can plug in emits it, so it is the
only way to reach the paths that index by that number.

The lanes these drive:

| Lane | Property |
|------|----------|
| `test-usb-sysfs-matrix` | every entry point against every class of name `/sys` and `/dev/bus` can hold |
| `test-getdents64-small-buf` | a buffer that cannot take the next entry reports rather than ending, and the entry it could not take comes back |
| `test-dir-backing-drain-error` | a union listing that lost its backing half is reported, not ended |
| `test-dir-primary-read-error` | the same on the synthetic half |
| `test-dir-union-fd-reuse` | a walk answers for the directory it pinned, not for the fd number |
| `test-dir-union-alias` | every route to a second fd on one description shares one position and one union state |
| `test-dir-fd-budget-union` | a union directory fd costs one host descriptor, like a plain one |
| `test-fstatfs-fd-identity` | `fstatfs` answers for the descriptor it pinned, not for the fd number |
| `test-usbdev-faults` | an interface number wider than the table that indexes it, each open-time failure reported as itself, a close inside the fd publish window leaking nothing, and a reap that answers for the description it snapshotted rather than the fd number |
| `test-usbdev-ioctl-departed` | every usbdevfs ioctl this layer names, on a device that has gone: the return, the `errno`, the stamp on the fd that asked and the stamp on a peer fd, against the Linux answer recorded for that request |

Some lanes carry rows that are recorded rather than asserted, and print as
`XFAIL`. An `XFAIL` row is a measured Linux value the build knowingly does not
meet: it is neither a pass nor a failure, it does not turn the lane red, and the
value elfuse gives today is carried beside it so that a departure from either
number shows up as a diff in the lane's output. The alternative -- deleting the
row -- is what lets a known divergence become an unknown one.

`test-usb-sysfs-matrix` records its `escape-syn` column that way: a `..` chain
walking through the synthetic subtree and back out cannot be resolved here,
because the host walk has to traverse a `/sys/bus/usb` that exists only inside
the layer. `test-dir-union-alias` records its fork cross-close rows: a child
whose parent closes its copy of the fd before the backing has been drained
answers with its primary alone, because the backing half belongs to a stream
that has gone. Both rows are load-bearing in pairs -- neither number alone
separates the answers the site could give -- so both are printed.

`test-usbdev-ioctl-departed` is the same idea with the recording moved out of
the lane and into data. Its rows are generated from
`tests/usbdev-ioctl-departed.tbl`, one per usbdevfs ioctl, and a row that
diverges from Linux carries both tuples: the lane fails if the elfuse answer
stops matching the recorded one, and fails just as loudly if it starts matching
Linux's, because an XFAIL nobody notices closing is a row that should have been
retired. The generator refuses to emit at all unless every ioctl
`usbdev_ioctl` dispatches has a row, so the recording cannot fall behind the
surface it describes.

USB-layer coverage is split by what it needs. `test-uevent-socket` needs no
hardware and runs in the matrix like any other unit test. The two usbdevfs
lanes need no hardware either, and neither of them runs in the matrix:
`test-usbdev-ioctl` drives the fd against `ELFUSE_USB_FIXTURE`, whose devices
are modeled but have no IOKit service behind them, so every answer it asserts
is that model's and the reference kernel has nothing to adjudicate; and
`test-usbdev-urb-host` is a native macOS binary over
`src/syscall/usbdev-urb.h`, the URB bookkeeping that is decided before any
transfer -- the disconnect-watch refcon, `SUBMITURB`'s argument gate, the
transferred-count clamp, the `ZERO_PACKET` predicate and the endpoint start
gate -- and sits in `NATIVE_TESTS` (`mk/config.mk`), so it is never
cross-compiled for a guest runner at all. Both run under `make check` and
nowhere else, which is what `grep usbdev tests/test-matrix.sh` says: it is
empty. The comment above `SANITIZER_SECTIONS` in `mk/tests.mk` records the same
split from the other side. That header exists because the fixture stops at the
argument gate: the async engine's first review found five defects in code no
lane executed, and the arithmetic half of it is testable on any machine.

`test-usbdev-urb-loopback` covers the other half. IOKit publishes no loopback
device, so the fixture becomes one: in the `USB_LOOPBACK_FIXTURE=1` build that
links it (below), `ELFUSE_USB_FIXTURE=loopback` substitutes for the two IOKit
COM vtables and for nothing above them (see
[internals.md](internals.md#testing-the-engine-without-hardware)), which puts
submit, the per-endpoint queue, the completion callback on the event thread,
`DISCARDURB`, `REAPURB` blocking and non-blocking, poll and epoll readiness,
the `CAP_REAP_AFTER_DISCONNECT` drain and the `ZERO_PACKET` trailing packet
under assertion on any machine. The `wedge` script step adds the transfer
whose abort outlives the engine's 2 s drain deadline, which is what puts the
orphaning path and the two ioctls that refuse on it under assertion too;
nothing else in the vocabulary reaches them, because every other outstanding
transfer answers an abort at once. It is also what times the drain, from both
ends: the lane asserts that a `REAPURBNDELAY` which owes the post-disconnect
kill issues its aborts and answers without waiting for them, and that a loop of
them still reaches `ENODEV` a drain deadline later rather than spinning on
`EAGAIN` for as long as the wire withholds the abort. The elapsed time is the
whole measurement in both. A `terminate` with `wIndex` bit 1 tears the claimed
interface's pipes down and changes nothing else, so `GetPipeProperties` alone
answers `NoDevice`: that is the device vanishing between the `GetNumEndpoints`
that sizes a pipe map and the calls that fill it in, and it is the only way in
the vocabulary to reach a half-built map. Bit 2 is the same idea for the one
answer only an abort can give: `AbortPipe` and `USBDeviceAbortPipeZero` return
`NoDevice` and cancel nothing, which is what a `DISCARDURB` meets when the user
client behind its handle has gone. It is its own fact rather than a consequence
of `terminate`, because a disconnect drain issues aborts and IOKit lands those:
tying the two would leave every `never` transfer outstanding for ever and no
drain would ever finish.

Two things the lane asserts are not guest-visible at all, so the fixture counts
them and the guest reads the counts back through a control request. One so far:
device handles the layer released while the fixture still owned a transfer on
the default control pipe. On real IOKit that is a use-after-free and here it is
not -- the fixture frees a COM wrapper nothing dereferences again -- so the
count is what stands in for it, and it is read on a later fd because the
release happens at close.

One scenario runs in a process of its own (`test-usbdev-urb-loopback
terminate-race`): it terminates the device while an fd is closing, and every
other scenario still needs that device afterwards. What it asks is whether a
terminate delivered inside a close's two-second drain can stamp a guest fd
number that a sibling has already taken. Two fds on one node carry the other
cross-fd assertion, that a disconnect one of them provokes reaches the one that
never touched the device, and a budget filled with URBs that will not complete
carries the third, that a synchronous `CONTROL` is charged against the same
allowance a synchronous `BULK` is. `test-usbdev-ioctl-loopback` re-runs the
fd-contract lane with that device present, which is the check that the seam did
not reach a path it is not supposed to touch.

`test-usbdev-ioctl-departed` uses the same device for the one thing no other
lane can arrange: a device that leaves while fds are open on it. It terminates
the fixture's device once and then drives every usbdevfs ioctl the layer
implements, one fresh fd per request, asserting the return, the `errno`, the
poll revents on the fd that asked and the revents on a second fd open on the
same node. Three runs, because the first correct `ENODEV` stamps every fd on
the node: the requests that need a claim taken before the device left get a
process each. What the lane may assert is not written in it --
`scripts/gen-usbdev-ioctl-departed.py` reads the ioctl surface out of
`usbdev_ioctl`'s dispatch and joins it against
`tests/usbdev-ioctl-departed.tbl`, so an ioctl added to the layer fails `make
check` until somebody records what Linux answers for it on a departed device.
`make check-usbdev-departed` runs that join by itself.

The loopback lanes run `build/elfuse-loopback`, which they build by re-entering
make with `USB_LOOPBACK_FIXTURE=1`. That variable is also what names the
binary: `mk/config.mk` points `ELFUSE_BIN` at `$(ELFUSE_LOOPBACK_BIN)` for the
fixture flavor, so the two flavors never write the same path and `build/elfuse`
cannot be a stale copy of the fixture build. It could before, and the flavor
stamp in `mk/common.mk` had nothing to say about it, being keyed on `CFLAGS`
while the switch changes `SRCS`: `make clean; make elfuse; make
USB_LOOPBACK_FIXTURE=1 elfuse; make elfuse` printed `Nothing to be done` and
left `nm build/elfuse` finding `_usbdev_fixture_lock` until the next `make
clean`. That was measured before the split and cannot be re-measured after it;
the dated byte counts are in
[internals.md](internals.md#testing-the-engine-without-hardware).
`.ci/check-usb-fixture-bin.sh` asks make for both paths and fails if they are
the same; `make check` runs it. The model is therefore not in `build/elfuse`,
and so not in anything shipped: see
[internals.md](internals.md#testing-the-engine-without-hardware).

What the loopback cannot answer stays on the board, and the list is short and
worth keeping honest: real timing, NAKs, maxpacket segmentation, DMA alignment
and throughput; that IOKit really delivers completions on the runloop, and the
`IODispatchCalloutFromCFMessage` opacity that motivates the URB record's atomic
owner (a timer callout is fully visible to ThreadSanitizer, so that
justification is board-only); exclusive-access arbitration and kernel-driver
binding, so `GETDRIVER` and `DISCONNECT_CLAIM` against a real driver; a real
`SET_CONFIGURATION`, `SET_INTERFACE` pipe renumbering and port `RESET`; that a
device actually receives the zero-length packet, as opposed to elfuse emitting
it under the right predicate; and a physical unplug mid-transfer. Two of the
engine's own answers are board-only for the same reason, and breaking either
of them leaves the lane green: the `ZERO_PACKET` write's dropped `async_lock`
and its bounded timeout only matter against an endpoint that NAKs, and the
fixture answers a zero-length write immediately and ignores both timeout
arguments; and so is the bystander window `ep_aborting` shuts, because the
fixture retargets an aborted transfer's timer under its own lock and can never
start a follower into an abort that is still running. The guest probes for
those live out of tree. A hardware-dependent check that does move
in must be gated on an environment variable naming the device and must skip
with a stated reason when it is absent -- a skip is not a pass, and the
skip lists above are the model: deliberate, explained, and checked.

## Host Rlimits

Guest rlimits are guest state, but elfuse seeds them from its own host limits at
boot, and no other process can read the rlimits of an elfuse process.
`ELFUSE_HOST_RLIMIT_CHECK` makes each elfuse process record its host limits at
start and, when one has moved by exit, write a line to stderr and exit 86.
`test-rlimit-unchanged-host` runs `test-proc-limits` under it.
`test-rlimit-seed` goes the other way: it sets host limits with `ulimit` before
elfuse starts and reads what the guest's `/proc/self/limits` shows.

## Scheduler replacement acceptance

[Scheduler architecture](scheduler.md) describes state ownership and Linux
compatibility boundaries.
[Scheduler regressions](../tests/scheduler/README.md) contains the focused
guest test commands. [Classic suites](../tests/classic/README.md) documents
kselftest and Linux Test Project build, import, and execution.

The runtime uses a per-VM scheduler and lazy HVF worker pool. Acceptance covers
task scheduling and common fork/exec/wait behavior. Cross-VM scheduling
order/capacity and full shared-mm exec separation are accepted limits;
unsupported exec must fail safely. The focused guide classifies required
cases and diagnostic Linux comparisons. Runners preserve mismatches as FAIL
even when a documented comparison is outside the cutover gate. Run filtered
slices before selecting a full external suite.

Observed on Apple M4 Pro, macOS 26.5.1 (25F80), Apple clang 17.0.0 and
aarch64-unknown-linux-gnu GCC 15.2.0:

| Lane | Result |
|------|--------|
| focused scheduler | 21 PASS, 1 diagnostic cross-VM FIFO FAIL |
| elfuse-aarch64 matrix | 318 PASS, 0 FAIL, 10 SKIP |
| qemu-aarch64 matrix | 292 PASS, 0 FAIL, 35 SKIP |
| elfuse-x86_64 matrix | 78 PASS, 0 FAIL, 1 SKIP |
| LLDB integration | 18 PASS |
| FUSE contract | PASS, including single-CPU request progress |
| UBSAN | 77 runtime tests and shared lanes passed |

The Linux oracle is Alpine 6.18.59-0-virt, PREEMPT_DYNAMIC, root with
CapEff 000001ffffffffff, CPUs 0-3 and RT runtime 950000 us. Its kernel
SHA-256 is 25dcaf5ddff2dba4dfdb8eca510c43a282ec91bc822d7b369964c12aea0c5bfa.
The kernel configuration is not exported through /proc/config.gz. DEADLINE
throttle/yield and local PI also passed with only CPU 0 online.

The full check completed its functional lanes but returned nonzero at the
performance guardrail: host load exceeded 38 on 14 CPUs, so its verdict was
UNMEASURED. ASAN hangs and TSAN crashes during host runtime initialization;
empty programs built with the same sanitizers reproduce both failures.
Neither lane establishes memory or race safety on this host.

One final teardown spin run exceeded a 15-second harness limit. Subsequent
spin and bringup runs each exited with the expected status 42 in 45 of 45
attempts. No blocked stack was captured; the isolated timeout remains
unexplained and is not evidence of a resolved teardown race.


## Fork inheritance advice

`tests/test-madvise-fork.c` checks `MADV_DONTFORK` and `MADV_DOFORK` on
private and shared file mappings, partial restoration, protection splits,
mremap moves and growth, repeated/nested fork, address reuse, `CLONE_VM`,
alignment, zero lengths and ranges containing holes. Child reads must fault
with `SIGSEGV/SEGV_MAPERR` on excluded pages. The test also checks parent data,
shared backing contents and the `dc` flag in `smaps`.

`MADV_WIPEONFORK` and `MADV_KEEPONFORK` cases verify zero-filled child
bytes, unchanged parent contents, partial clearing, protection splits,
repeated/nested fork, mremap move/growth and `CLONE_VM` retention. Shared
and private file mappings reject WIPEONFORK with `EINVAL`; ranges with
holes return `ENOMEM` after updating mapped fragments. Synthetic `smaps`
reports the `wf` flag on retained wipe-on-fork regions.

Build and run the focused case with:

```sh
make elfuse build/test-madvise-fork
build/elfuse build/test-madvise-fork
bash tests/qemu-runner.sh exec /mnt/host/build/test-madvise-fork
```

The normal aarch64 matrices include the case for both elfuse and Linux.

## Synchronous signal waits

`tests/test-sigtimedwait.c` reproduces a waiter occupying a host worker while
another task on the same allowed CPU is READY. The producer must run before
the waited-for signal is released. The case also covers pending-signal
selection, RT payload ordering, signal competition, timeout deadlines,
`SA_RESTART` interruption, wake-before-park races and exit/exec cancellation.

```sh
make elfuse build/test-sigtimedwait
build/elfuse build/test-sigtimedwait
bash tests/qemu-runner.sh exec /mnt/host/build/test-sigtimedwait
```

The normal aarch64 matrices include this test for elfuse and Linux.

## Core synchronization and standalone ART

`tests/test-membarrier-sync-core.c` races 1,000 private expedited core
barriers against three threads making syscalls and computing a deterministic
64-bit sequence. It checks syscall results, arithmetic and completed work.
Both aarch64 matrices run this case.
Three synchronized callers also issue 300 overlapping expedited and
SYNC_CORE requests; every caller must complete without blocking another
inside its host handler.

```sh
make elfuse build/test-membarrier-sync-core
build/elfuse build/test-membarrier-sync-core
bash tests/qemu-runner.sh exec /mnt/host/build/test-membarrier-sync-core
```

The local `externals/art-arm64` fixture contains the Android 16 QPR2 ARM64
ART APEX, matching Bionic/i18n/conscrypt libraries, a boot image and the
`ArtSmoke` DEX. It is not fetched or built by the repository test suite.
Its `build-info.txt` records source revision and build commands.

```sh
bash externals/art-arm64/run.sh
```

The entrypoint enables JIT with warmup threshold 10 and compilation threshold
100. A successful run exits 0 with `ART_ARM64_OK sum=5000050000 threads=40000`.
The workload checks arithmetic, four Java threads, atomic increments,
allocation, explicit GC and an exception. Android logd packets captured from
the fixture's `dev/socket/logdw` confirm Baseline/Optimized/OSR compilation,
an OSR `Jumping to` transition, collection of 128 large objects and JIT
shutdown. Android framework, Binder services, zygote and applications are
outside this standalone fixture.

ATL's Alpine `art_standalone` package is a separate runtime from this APEX.
Its compiler path exercises fork/exec, boot image creation and fixed read-only
VDEX mappings. With a matching passwd entry and writable cache, boot image and
application dex compilation complete under elfuse. The package's
`AsynchronousCloseMonitor` signal-handler EINVAL and shutdown
`JavaVM::GetEnv()` abort also occur under Linux/HVF; a printed `ART_ARM64_OK`
followed by this abort is not a passing runtime exit. GTK display and APK
lifecycle remain outside this command-line runtime validation.

Slot CPU accounting and cross-worker live samples read `THREAD_BASIC_INFO`
user plus system time through the owner's cached Mach thread port. The shared
source excludes waiting and host descheduling. The static `fd-create` guardrail allows 15 us
above same-host native `open("/dev/null", O_RDWR)` plus close; the dynamic
glibc allowance is 35 us for sysroot resolution. `bench-fd-create-host` takes
the median of three passes before and after each guest pass; their average
is the baseline. Native open failures and absent or invalid measurements fail
the gate. The remaining getpid ratios and absolute ceilings are unchanged.
The native baseline isolates host filesystem/security-policy costs, measured
at 42.8-48.6 us here, which exceed the former 1,000-times-getpid ceiling.

`test-futex-wake-nowaiter` starts its round gate at `UINT32_MAX`; the first
waker cannot run until main resets the word and publishes round zero. The
stats-enabled lane exercises the same handshake without losing the first
wakeup to a late reset.

`test-sched-affinity` exercises eight compute threads pinned to one logical
CPU. The slice timer rejects wait snapshots invalidated by notifications
received during unlocked deadline sampling. FAIR dispatch renews an activation
whose finish or budget expired while queued; the owner safe point also checks
settled budget when its live sample is zero. Quiet pinned-spinner runs passed
10 consecutive times after these changes. RR rotation and interrupted quantum,
FIFO yield ordering, DEADLINE throttle/yield and exited-thread CPU accounting
passed with guest scheduling privilege enabled by `--fakeroot`.

`test-sched-wake-balance` parks two FAIR threads on one CPU, expands their
affinity to two CPUs, and wakes them together. Both CPUs must execute work;
a pinned control must remain on its single allowed CPU. Three allowed CPUs
are required so the controller cannot occupy a worker CPU. The test fails
on the shared-placement implementation and passes on aarch64 Linux.

The standalone ART throughput DEX (SHA256
`017df7544809a2227910c2bdcb69fff8cd0cb5564bea117d93f5ae41748eaf5c`)
uses independent xorshift64 work with checksum validation. On an M4 Pro,
three JIT processes, each with three 1-second warmups and five 1-second
samples per thread count, measured median throughput of 0.738, 1.430,
2.616 and 5.167 billion rounds/s at 1, 2, 4 and 8 threads with the pinned
Zircon placement and stealing paths. The earlier shared-placement process
medians were 0.741, 0.367, 0.717 and 0.701 billion rounds/s. These are workload
measurements, not an Android application score or a host-independent test
threshold. Eight-thread sample variation was 0.63%; 1- and 4-thread samples
retained occasional stalls. CPU placement does not resolve every latency outlier.

`test-sched-placement-host` drives the scheduler without HVF timing and checks
estimated-load selection with every CPU busy, the 25 us early-out boundary,
deadline-demand ties, affinity-predicate stealing, exact demand transfer,
source/target virtual-time conversion, peak/quarter decay, retirement,
user/service charges through quiet accounting, service-budget expiry and
exclusion of Linux RT/DL queues from stealing. Per-CPU worker condition
variables map Zircon target-CPU notifications; freeze and shutdown still wake
all owners. The existing pipe-bulk performance ceilings remain unchanged.
`test-exit-group-teardown wait` covers a bootstrap owner idle while another
CPU exits the group; scheduler shutdown must release its condition wait.
Wait, stopped-tracee and fork-barrier cases retain exit status 42.

## Anonymous backing policies

`make test-memory-mode` runs private zero fill, fixed replacement, discard,
fork isolation and concurrent reset under both policies. `make
test-memory-residency` checks untouched, written, discarded and `PROT_NONE`
backing through `mincore`; its elfuse target additionally requires immediate
`MADV_FREE` reclamation. The portable invocation accepts retained or zeroed
bytes and checks neighboring pages and subsequent writes. `make test-mmap-private`
checks private file writes,
host-page edges, fork (including mappings beyond EOF), initial `PROT_NONE`, EOF
tails, ELF segment replacement across EOF and mremap under both policies. It
also checks retained EOF-page SIGBUS delivery after replacement, fork and
permission regrant. Both aarch64 matrices run the default lazy guest cases.

```sh
make elfuse test-memory-mode test-memory-residency test-mmap-private
bash tests/qemu-runner.sh exec /mnt/host/build/test-memory-mode
```

`mincore`, guest `VmRSS` and stat RSS query actual host backing residency.
`stat` and `status` coalesce consecutive GPA spans before querying residency;
each open measures current backing without a cache. Aliased VMAs retain their
separate contributions, and `smaps` measures each VMA individually.
The reporting granule is still the host page: four 4 KiB guest pages can share
one resident 16 KiB host page. Host process RSS also includes elfuse/HVF and
shared cached files; Darwin `phys_footprint` excludes much of the shared slab.
Record matching DEX, heap limit, JIT flags and GC work for comparisons.

On Apple M4 Pro, anonymous lazy reset releases complete 16 KiB host pages.
A 128 MiB write/discard probe returned host RSS from 145.8 MiB to 17.8 MiB.
The same Linux/HVF probe returned from 128.3 MiB to its 0.3 MiB process baseline.
Both checked zero fill after discard. A 64 MiB sparse-touch refill measured
about 5 ms under elfuse; Linux with THP enabled measured 0.45 ms. Linux THP
provides a physical-page advantage that guest 2 MiB page-table blocks do not.

Android 16 QPR2 ART with `-Xmx128m`, JIT thresholds 10/100 and the identical
zero-checked 256-byte-object DEX measured lazy medians of 59.22/58.51/60.36 M
objects/s across three runs of five one-second rounds. Linux/HVF measured
48.51 M objects/s in the matching initial run and 16.76/25.80/55.91 M/s in a
later three-run sample (8 vCPUs, 4 GiB, 4 KiB pages, THP always). The strongest
Linux run is within about 6% of elfuse's median-of-medians; host scheduling and
warmup variability prevent a general claim of superiority. All runs completed
with `MEM_OK`.

Fork copies private anonymous and file-CoW backing into an independent shared
memory snapshot. This trades some fork cost for lower GC reset cost;
fork-heavy applications must be benchmarked separately. The shell fork
benchmark includes process spawn and should not be read as a page-table-only
CoW cost.

A synthetic 456 MiB private file plus 2 GiB split anonymous mapping checks
eight forks and a sibling heartbeat. One paired run measured 4.508 seconds
and a 655 ms maximum heartbeat gap with the saved file-snapshot binary,
versus 0.969 seconds and 149 ms with shared-memory snapshots and coalesced
backing scans. Both runs preserved parent and child bytes. This is one local
sample, not a latency bound.

The pre-recovery baseline for untouched 64 MiB private file mmap/unmap was
11.6 us under elfuse and 2.0 us under Linux. Both verified file/CoW bytes after
access and discard. The corresponding full checks reported 325 PASS, 0 FAIL
and 10 SKIP in the aarch64 matrix and a passing throughput guardrail. Linux
passed the memory-mode, residency and private-file regression binaries.

Bounded recovery runs with eager file page tables and redundant backing resets
removed measured 19.91/12.14/12.35 us for the same file probe. This variation
does not establish a stable speedup over the 19.82 us immediate baseline.
Private-file regressions passed all 47 checks under both backing policies;
the residency regression passed all eight. Anonymous regressions passed under
both policies, including fork isolation, concurrent reset and exec after
discard. Anonymous 64 MiB discard/refill measured 0.533/5.047 ms. Standalone
ART exited successfully with
`ART_ARM64_OK sum=5000050000 threads=40000`. Formatting, atomics, ASCII,
skill references, EINTR contracts, lock order, syscall coverage and shim
return-tail checks passed. The full matrix, Linux VM and ART throughput
workload were not rerun during recovery.

Pre-commit serial `make check` passed all 107 driver entries, host unit tests,
shared lanes, both memory policies and the static/dynamic-glibc throughput
guardrail. The aarch64 matrix reported 325 PASS, 0 FAIL and 10 SKIP. All 76
Rosetta-specific checks passed with native macOS tools selected through PATH;
an initial run selected guest tools while building its host-side corpus and
failed before the Alpine checks. `make check-format` and the source
security/newline scans passed. Linux/QEMU and ART throughput were not rerun.

## Host panic safety

On macOS 26.5.1 (25F80), two SPTM kernel panics named the standalone
hvprobe process and reported VIOLATION_ILLEGAL_MAPPING_TYPE at IPA 0x4000.
The probe used executable host backing for guest code; the exact mapping
combination that triggered the kernel defect is unconfirmed. This probe must
not be rerun on a development workstation. A process timeout cannot contain
a kernel panic. Keep diagnostic artifacts without executing their binaries.

Recovery validation uses the established elfuse bootstrap and host RW slab,
with guest page tables enforcing execution permissions. Run one bounded
guest at a time, build with limited parallelism, and do not resume interrupted
probe jobs. Avoid standalone HVF experiments with RX/RO host backing,
superpages, or in-place reclaim of live HVF memory. Preserve panic reports
before testing. A kernel-fault experiment requires a disposable machine and
explicit approval; a guest VM on the same macOS host is not containment.

## Validation Strategy By Change Type

Suggested minimum validation:

| Change area | Recommended validation |
|-------------|------------------------|
| `scripts/elfuse-oci.py` | `python3 scripts/test-elfuse-oci.py`, plus `make elfuse && ELFUSE_OCI_STORE=<dir> scripts/ci/oci-smoke.sh` on a Hypervisor.framework host |
| CLI, logging, docs-only build rules | `make elfuse` |
| Filename codec, case-exact walk, sysroot resolvers | `make check` (runs the codec unit tests, name lanes, and byte-exact oracle lane), plus `make test-sysroot-name-soak` for resolver concurrency. A red golden vector in `test-casefold-host` means the on-disk format moved: see `docs/filenames.md` before touching `tests/casefold-vectors.h` |
| General syscall or runtime logic | `make elfuse && make check && make test-matrix-elfuse-aarch64` |
| `/proc`, `/dev`, path, or BusyBox-sensitive behavior | `make elfuse && make check && make test-matrix-elfuse-aarch64` |
| Rosetta hosting, x86_64 dispatch, VZ ioctls, AOT cache | `make elfuse && make test-rosetta-all` |
| Broad behavioral changes | `make elfuse && make check && make test-matrix` |
| Debugger or ptrace flow | `make elfuse && make test-gdbstub` |
| ACSL contracts, `src/proved/`, `mk/verify.mk`, the mutation harness | `make verify && make verify-mutants`, in that order and never beside a runtime lane: both fan out, and the timing lanes fail under the load they create. Add `make check` only when the change touches code rather than annotations |

VMA storage changes have a focused runtime probe in `test-brk-stack`: 5,000
alternating writable and guarded pages, exact `/proc/self/maps` permissions,
a late hardware write fault, fork isolation, interior unmap, and fixed
replacements that exercise the single-interval removal count and snapshot
bound: interior and exact-boundary replacements, differently protected
neighbors, holes, and failed replacements that must restore bytes and
permissions. Run `make elfuse build/test-brk-stack && build/elfuse build/test-brk-stack`.
The descriptor-exhaustion fork tests use the `host_nofile=elfuse-minimum`
manifest setting so their filler reaches the host fd limit rather than relying
on the number of VMA records.

Exact anonymous `MAP_FIXED` replacement retains the original record until
backing preparation completes, then overwrites it through the normal region
initializer and neighbor merge rules. It avoids snapshot allocation and two
suffix copies; partial ranges, file backing and host overlays retain rollback
snapshots. `test-madvise-fork` checks that exact replacement clears both
`MADV_DONTFORK` and `MADV_WIPEONFORK`.

`make build/bench-mmap && build/elfuse build/bench-mmap 500` measures repeated
page replacements at the head, middle and tail of 100- and 5,000-pair guarded
mapping tables. Each position reports the median of five samples and checks
zero fill and neighboring bytes; latency is diagnostic, with no timing gate.

On the local M4 Pro, five-sample medians with 1,000 replacements per sample
were 43.004/21.384/1.588 us at head/middle/tail before exact-record overwrite,
and 1.376/1.372/1.146 us after it for the 5,000-pair table. Scheduler-only
quiet accounting measured 18.2 versus 7.9 ns per charge (median of five
million-iteration user/service batches). These microbenchmarks do not establish
an application-startup improvement.

The accounting and exact-replacement cutover passed `make check` (109 driver
entries plus host/shared lanes and the throughput guardrail) and
`make test-matrix-elfuse-aarch64` (327 PASS, 0 FAIL, 10 SKIP). `test-brk-stack`
passed 36 checks under lazy and eager backing; `test-madvise-fork` passed 15.
Standalone ART completed with `ART_ARM64_OK sum=5000050000 threads=40000`.
Touched C files passed clang-format 22.1.8 and commentflow. Full-tree formatting
remains blocked by existing comment reflow differences and two long comments
in `src/runtime/sched/vcpu_pool.c`; those files were left unchanged.

Frozen scheduler domains keep idle workers asleep on `sched_cond` until dispatch
resumes or shutdown begins. The formatted sources passed `test-exec-handoff`
(six scenarios), `test-mt-fork` (one snapshot scenario), the `fork-inherit-isolate`
scenario of `test-sched-fork-domain` (15 checks), and `test-negative` (43 checks).
The latter covers `unlinkat` returning `EISDIR` for a directory without
`AT_REMOVEDIR`. `make test-matrix-elfuse-aarch64` completed with 327 PASS,
0 FAIL and 10 SKIP. The latest `make check` reached the throughput guardrail
but did not pass: host load 51.64 and 79.36 over 14 CPUs made it unmeasurable.

Sparse fork snapshots passed `test-cow-fork`, `test-memory-mode`,
`test-cross-fork-mapshared`, `test-mremap-fork-tracking` and
`test-mremap-tail-emfile` through `tests/driver.sh`; the latter two require the
manifest's constrained host fd limit. `test-madvise-fork` passed 15 checks when
run directly, including nested DONTFORK and WIPEONFORK inheritance.
A 64 GiB anonymous mapping with dirty endpoint pages forked in
56.303/44.266/40.060 ms and preserved both endpoints and an untouched zero page.
These focused checks do not establish a new full-matrix baseline.

`test-vfork-sibling` holds a vfork child on a pipe while another parent thread
forks. Three checks pass: the sibling fork succeeds, a signal stays pending
until child release, and vfork returns the admitted child PID with its exit
status still waitable. The caller unmounts until child exec/exit rather than
blocking a CPU in the notification read.
The continuation retains REISSUE across stop/continue, and wait deadlines match
the task's park generation. A stopped-vfork smoke preserved the child's exit
status after 15 STOP/CONT cycles. Concurrent fork and mapping-reset smokes
completed without fork failures; high-VA replacement also passed under Rosetta.
Quiesce has a 2-second bound for admitted host handlers to drain backing pauses;
a failed freeze never authorizes a snapshot. Nested backing restoration keeps
the outer memory pause until its matching resume.

The PID allocator retains one close-on-exec sequence descriptor per host
process, with a local mutex and the existing cross-process flock. Nested
process/thread ID uniqueness and 18 other lifecycle cases passed. A 400-thread
creation smoke measured 0.939905/0.907108/0.884239 seconds before descriptor
reuse and 0.589498/0.591922/0.559472 seconds afterward.
For 200,000 host-forwarded sched_getscheduler calls, the solo FAIR sample
shortcut measured 0.394443/0.428115/0.399830 seconds before and
0.359322/0.338923/0.323372 seconds after. Forced preemption, RR rotation,
RR wake/quantum preservation, solo DEADLINE throttling and DEADLINE yield
passed. RT/DEADLINE scenarios ran with --fakeroot.

File-backed fork snapshots bypass page-disposition queries because every byte
is copied. A 128 MiB private file mapping smoke preserved dirty endpoints,
an untouched zero page and child-write isolation. The first before/after pair
was 0.160417/0.076859 seconds; a warmed pair was 0.075647/0.058361 seconds.
test-mmap-private passed 53 checks; test-cow-fork passed five checks;
test-madvise-fork passed 15 checks, including nested inheritance.
The native aarch64 matrix completed with 328 PASS, 0 FAIL and 10 SKIP after
the PID allocator, solo FAIR sampling and file snapshot changes.
make check reached the hot-syscall guardrail but exited nonzero: its second
static stat-path measurement was 119.2 times getpid against a 105-times limit.
The guest debugger integration passed 19 LLDB scenarios and 18 host checks,
including compute-thread freeze, parked-thread snapshots and detach recovery.
Real ART supplied all nine task register sets, resumed after repeated stops,
and exited zero after both detach and abrupt debugger disconnect.

A record-lock smoke held a conflicting lock for 20 ms. F_SETLKW returned after
201.119 ms with the descriptorless 200 ms recheck, and after 24.935 ms with
the 1 ms retry. Descriptor-backed fallback waits retain the 200 ms interval.
The repeated lock smoke measured 21.586 ms; flock, fd pin and msync each passed
nine checks. Solo FAIR timer suppression passed 26 scheduler host checks and
guest preemption, wake balance, CPU clocks, RR rotation and retained quantum,
and DEADLINE throttle/yield scenarios. RT/DEADLINE ran with --fakeroot.
make check-format passed with COMMENTFLOW=/private/tmp/commentflow.

The fork backing-pause regression passes four host checks; restoring the old
entry gate fails the quiescence assertion. Twelve real forks pass snapshot
ordering, backing reset completion and child reaping checks. vfork siblings,
multi-threaded fork, CoW isolation and SYNC_CORE tests pass. The threaded exec
chain completes 200 execs with eight live siblings per exec.



## Runtime Profile Regression

`make test-profile-host` checks disabled clock behavior, strict numeric
configuration, IO re-dispatch across worker migration, parked result/errno
completion, READY versus sleep residence, TID reuse, exec PC epoch identity,
bounded storage overflow and snapshots containing an open syscall while the
process is still alive. `make check` and `make check-sanitizer` include this
host test. It does not require Hypervisor entitlements.

For a guest smoke, use the same guest binary with profiling unset and with
`ELFUSE_PROFILE=/private/tmp/profile-smoke` set; compare its exit status and
stdout. A workload with a busy loop and a delayed pipe read/nanosleep should
have guest CPU for the busy task, IO/sleep residence for the blocked task and
one logical read with possibly multiple handler attempts. Capture a complete
snapshot before terminating the guest, then parse it with
`python3 scripts/elfuse-profile.py /private/tmp/profile-smoke.*.jsonl`.
Run a fork/exec workload with a fresh prefix to check separate host-PID files
and exec epoch markers. Invalid relative prefixes and unwritable output
parents should disable profiling with a diagnostic and preserve guest output.
Compare profiler-on/off wall and CPU time with fixed workload/CPU count;
profiling records measured span clock overhead and changes scheduling timing.
The [schema and sampling limits](usage.md#runtime-profile) define which
comparisons are valid. EL1-only syscall paths are intentionally not counted
as host-forwarded calls.

On Apple M4 Pro, a real two-task guest workload completes in about two seconds
with 11 periodic/final snapshots: the busy task has over 500 ms guest CPU, the
pipe reader over one second IO residence, and nanosleep over one second sleep
residence. The profiler host regression passes 12 checks. Scheduler scenarios
process-cputime-thread-exit, signal-affinity-migrate and affinity-migrate pass
with two CPUs; the host fork-quiesce regression passes four checks.

Three alternating runs of 30,000 forwarded fstat calls on one CPU have median
guest wall times 97.700 ms with Mach owner sampling and 65.561 ms with
CLOCK_THREAD_CPUTIME_ID owner sampling. Three further alternating runs of the
owner-sampled binary have medians 63.018 ms with profiling unset and 66.988 ms
with profiling enabled. These are syscall microbenchmarks, not APK startup or
frame-rate results. Foreign thread_info readings can lag owner readings;
the shared high-water sample keeps the clock monotonic.
Invalid relative and non-directory output prefixes both preserve the real
fstat workload's successful result and report profiling disabled on stderr.
The profiled real test-fork guest completes both normal and SIGUSR1 child
exits. Its parent and two helper files each contain a final snapshot. The
exporter starts after preemption signals are blocked; starting it earlier
allows Darwin SIGUSR2 to terminate the host instead of reaching sigwait.

## OCI Images

`python3 scripts/test-elfuse-oci.py` runs table cases over the parts of the OCI
front end that need no image. The self-hosted `oci-smoke` job runs it
at the start of its lane; see [oci-images.md](oci-images.md#validation) for the
lane's coverage and [usage.md](usage.md#running-the-smoke-lane-locally) for the
command.
