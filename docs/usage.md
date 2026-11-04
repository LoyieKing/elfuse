# Using elfuse

This document covers the command-line interface, common launch patterns,
dynamic linking through `--sysroot`, and debugger attachment.

## Command-Line Synopsis

```sh
build/elfuse [options] <elf-path> [args...]
```

Supported user-facing options:

| Option | Meaning |
|--------|---------|
| `-h`, `--help` | Print built-in usage help |
| `-V`, `--version` | Print the build version and exit |
| `-v`, `--verbose` | Enable syscall-level and loader diagnostics |
| `-t`, `--timeout N` | Guest execution watchdog, in seconds (default `10`, `0` disables) |
| `--cpus N` | Guest logical CPUs, from `1` to the host online CPU count (also `ELFUSE_CPUS=N`; the flag wins) |
| `--memory-mode=lazy\|eager` | Private anonymous backing policy (default `lazy`); `--memory-mode MODE` also works |
| `--sysroot PATH` | Resolve guest absolute paths under `PATH`, falling back to the host for paths it does not hold |
| `--create-sysroot PATH` | Provision a case-sensitive APFS sparsebundle mounted at `PATH`, then use it as the sysroot |
| `--no-rosetta` | Disable the x86_64-via-Rosetta translator (also `ELFUSE_NO_ROSETTA=1`) |
| `--fakeroot` | Start the guest as uid/gid 0 with full emulated capabilities (also `ELFUSE_FAKEROOT=1`) |
| `--gdb PORT` | Listen for a GDB RSP client on `PORT` (aarch64 guests only) |
| `--gdb-stop-on-entry` | Stop before the first guest instruction |
| `--user UID[:GID]` | Run the guest as `UID`, and `GID` when given (defaults to `UID`). Numeric only |
| `--workdir DIR` | Guest-absolute initial working directory, resolved under `--sysroot` |
| `--env KEY=VALUE` | Set a guest environment variable. Repeatable; a bare `KEY` imports the host value |
| `--clear-env` | Start from an empty environment; only `--env` entries apply |
| `--` | End `elfuse` option parsing; remaining tokens are guest argv |

The default CPU limit is half the host online CPUs, rounded down, with at least
one and at most four. Guest CPU files and affinity use that same logical CPU
domain. The limit is per VM, preserved across guest fork and exec, and does not
reserve host cores. `--clear-env` and `--env` affect the guest environment, not
the host-side `ELFUSE_CPUS` setting. Invalid counts fail before guest execution.

`ELFUSE_FAKEROOT_EXEC` has no flag form. It names one executable, by absolute
path, whose `execve` enters fakeroot mode, so a guest can run unprivileged and
raise privilege the way `sudo` does rather than paying for root over the whole
session. Two properties are worth knowing before using it:

- The match is on file identity, not on the pathname. Any spelling that reaches
  the marked executable elevates -- guest path or host path under `--sysroot`,
  through symlinks, relative or not -- and a spelling that reaches some other
  file does not. Replacing the file at that path replaces what elevates.
- Elevation is never dropped. The marked image, everything it `exec`s
  afterwards, and everything it forks all stay root. It is a `sudo`-shaped
  transition for a process tree, not a per-command one.

Unset, which is the default, no exec ever elevates. A value that is not an
absolute path is rejected at startup rather than ignored.

`--timeout` watches guest execution without exception progress across scheduler
preemption. Detection takes up to two periods; a blocked syscall does not count
as stalled execution. It does not cap total process runtime. Setting
`--timeout 0` disables the watchdog for long-running CPU-bound guests.

`--memory-mode=lazy` releases whole host pages on private anonymous discard,
unmap and exec reset. Fresh anonymous allocations remain zero-fill-on-demand.
`--memory-mode=eager` zeroes backing in place and retains it for reuse. Both
modes reserve the same guest address space and preserve Linux byte semantics;
neither commits the entire slab. Fork inherits the policy and exec preserves it.
Lazy mode releases anonymous backing and retains zero-fill semantics. Aligned
private file mappings use host CoW demand paging; unaligned host-page edges
use a byte snapshot. `mincore` and guest RSS query backing residency at host
page granularity. Shared-file coherence keeps its existing behavior.

## Guest Identity, Working Directory, And Environment

`--user`, `--workdir`, `--env`, and `--clear-env` select what the guest starts as,
where it starts, and what it sees in its environment. A contradictory `--user`
request or a malformed `--env` entry is rejected before the VM is created, and
`--workdir` is resolved during bring-up, before the first guest instruction, so
a bad request fails with a diagnostic instead of launching a guest that runs as
something other than what was asked for.

By default the guest inherits the host's real and effective UID/GID. Saved IDs
start at the corresponding effective IDs. These values initialize guest state;
later guest credential changes do not change the host process credentials.

Without account files in a sysroot, the synthetic passwd/group files associate
the guest's effective UID/GID with the existing user entry. Sysroot account
files take precedence; inheriting a numeric ID does not import macOS usernames.

`--user UID[:GID]` sets the identity the guest reports through `getuid` and
`getgid`. It does not change the host process credentials: elfuse translates the
guest's syscalls, so the number the guest sees is elfuse's to choose. The spec is
numeric, and a bare `UID` sets the group to the same value.

`--fakeroot` cannot be combined with a non-root `--user`. Fakeroot starts the guest
as uid/gid 0, and the setuid permission check grants every id switch on that basis,
so a guest that reported an unprivileged uid could still call `setuid(0)` at will.
Both halves must be root, which makes `--fakeroot --user 0:0` valid and
`--fakeroot --user 0:1000` a refusal.

`--workdir DIR` takes a guest-absolute path and is rejected otherwise. A relative
path would be resolved against the host working directory, silently starting the
guest outside the intended tree. The path is translated through `--sysroot` and
then entered, the same way a guest `chdir` into a real directory is handled,
with one launch-time restriction: the resolved directory must sit inside the
sysroot. For a path the sysroot does not hold, a guest syscall falls back to
the host, but a workdir that exists only on the host would start the guest
outside the requested tree, so the launch refuses it. FUSE-mounted,
`/proc`-virtual, and `/dev/shm` directories are not supported through this
flag: a guest `chdir` into `/dev/shm` does two things this flag does not (it
refuses a symlink leaf, and it keeps `getcwd` reporting the `/dev/shm`
spelling rather than the backing location).

`--env` follows `docker run -e`. It is repeatable: `KEY=VALUE` replaces that
variable when it is already present and appends it otherwise, while a bare `KEY`
imports the host's value for `KEY`. Unset and set-to-empty are distinct: a name
the host does not set is skipped rather than imported as an empty value, while a
host `KEY=` imports as `KEY=`. An empty variable name is rejected. Given neither
`--env` nor `--clear-env`, the guest inherits the host environment unchanged.
`--clear-env` starts from nothing, leaving only what `--env` puts back.

## Common Launch Patterns

Run a statically linked guest binary:

```sh
build/elfuse ./build/test-hello
```

Run with verbose tracing:

```sh
build/elfuse --verbose ./guest-program arg1 arg2
```

Pass guest arguments that begin with `-`:

```sh
build/elfuse -- ./guest-program --guest-flag
```

The guest's exit status is propagated as the `elfuse` exit status, so
`elfuse` composes with shell pipelines, `make`, CI scripts, and
anything else that inspects `$?`.

### Worked Examples

The guest reads and writes the host filesystem directly (no overlay,
no volume mount), so file arguments are just file arguments. Under
`--sysroot` the temporary directories are the exception; see
[Dynamic Linking And Sysroots](#dynamic-linking-and-sysroots).

Run a Linux static `jq` against a host JSON file:

```sh
build/elfuse ./jq-aarch64-static '.name' /tmp/data.json
```

Drop into an interactive `bash` session against a musl sysroot:

```sh
build/elfuse --sysroot ./aarch64-musl-sysroot \
    /path/to/aarch64-linux/bin/bash
```

Run a Linux `sqlite3` against a host database file:

```sh
build/elfuse ./sqlite3-aarch64-static /tmp/mydata.db \
    'SELECT name FROM sqlite_master WHERE type = "table";'
```

Run an x86_64 Linux binary (architecture is auto-detected; Rosetta
hosts the translator):

```sh
build/elfuse ./hello-x86_64-static
```

## x86_64-via-Rosetta

Statically linked `x86_64-linux` ELFs run through Apple's embedded
Rosetta translator hosted inside the guest VM. The architecture is
auto-detected from the ELF header, so the same `elfuse` invocation
works for both aarch64 and x86_64 inputs:

```sh
build/elfuse ./x86_64-static-binary
```

Rosetta is on by default. To force the aarch64-only path (or to
verify that a binary really is aarch64), pass `--no-rosetta` or
export `ELFUSE_NO_ROSETTA=1`:

```sh
build/elfuse --no-rosetta ./aarch64-program
```

Both statically and dynamically linked x86_64 binaries are supported.
Dynamic guests need an x86_64-linux sysroot:

```sh
build/elfuse --sysroot /path/to/x86_64-sysroot ./x86_64-dynamic-binary
```

The sysroot must contain the requested dynamic linker
(typically `/lib64/ld-linux-x86-64.so.2` for glibc, or
`/lib/ld-musl-x86_64.so.1` for musl) and any shared libraries the
guest opens. elfuse loads Rosetta into the VM and lets the translator
read the guest ELF; the translated x86_64 dynamic linker then maps
the interpreter and shared libraries through the sysroot like any
other guest process. Runtime `dlopen` and per-thread TLS are
exercised by `tests/test-rosetta-glibc.sh`.

Notes:

- `--gdb` is rejected for x86_64 guests: the stub serves the aarch64
  view Rosetta produces, not the original x86_64 architectural state.
- Fork uses an independent sparse snapshot, including Rosetta TTBR1 and kbuf
  state; snapshot allocation failure uses region copy.
- Two Rosetta-internal divergences are documented and not papered
  over: `SA_RESETHAND` is shadowed by Rosetta's own signal-handler
  state, and `clone(..., CLONE_SETTLS, tls=0, ...)` can hang.

The first x86_64 launch may pause briefly while the AOT cache under
`$HOME/.cache/elfuse-rosettad/` warms up; subsequent launches reuse
the SHA-256-keyed translations.

## Dynamic Linking And Sysroots

Dynamic Linux guests need a sysroot that contains the expected interpreter and
shared libraries. `elfuse` reads `PT_INTERP`, loads the requested interpreter
from the supplied sysroot, and redirects guest absolute-path opens to that tree,
falling back to the host filesystem for paths the sysroot does not hold.

Example:

```sh
build/elfuse --sysroot /path/to/sysroot ./hello-dynamic
```

This model supports both musl and glibc guest environments as long as the
expected interpreter path (for example `/lib/ld-musl-aarch64.so.1` or
`/lib/ld-linux-aarch64.so.1`) exists inside the sysroot.

Practical notes:

- The sysroot is consulted for guest absolute paths; relative paths resolve
  from the guest working directory, and inside the sysroot they receive the
  same byte-exact name semantics as absolute ones.
- `/tmp`, `/var/tmp`, and any `.ccache` directory are backed by the sysroot
  alone. A guest's temporary files go there so they cannot collide on a
  case-insensitive host `/tmp`, and every operation on those paths, including
  `stat`, `open`, and directory listings, addresses the same place. Host files
  under those directories are therefore invisible to the guest, and a guest
  program or interpreter stored there cannot be loaded; pass one from anywhere
  else.
- `..` stops at the guest's root as it does on Linux, so `/..` and
  `/../etc/hosts` name `/` and `/etc/hosts` inside the sysroot. The directory
  the sysroot itself lives in is not reachable from the guest.
- The sysroot setting is preserved across guest `fork` and `execve`, so spawned
  children see the same view of the filesystem.
- On case-insensitive macOS volumes, `elfuse` keeps Linux's byte-exact name
  semantics: a lookup whose spelling differs from the on-disk entry only by
  case or Unicode normalization form reports `ENOENT`, and a name the volume
  cannot store as itself is held under an escaped `.ef=<payload>` spelling the
  guest never sees. Guest names keep their full 255 bytes either way.
  [docs/filenames.md](filenames.md) describes the model.
- A sysroot holding `.ef_<token>` entries plus a `.elfuse_case_index` file
  per directory was written by a different on-disk encoding and is not
  readable: those entries decode to nothing and surface under their literal
  host names. Recreate the sysroot: unpack the rootfs again, with
  `--create-sysroot` if the volume folds case.
- Use `--create-sysroot PATH` if the host filesystem is case-insensitive
  (default APFS) and the sysroot is being provisioned for the first
  time; `elfuse` creates a case-sensitive APFS sparsebundle, mounts it
  at `PATH`, and uses it as the sysroot for this run.

## Native macOS GTK Windows

The optional `elfuse-gtk` executable presents GTK 4.24 Broadway surface
requests in macOS GtkWindows. It uses the local Unix-socket protocol;
no Broadway web daemon, browser, or X server is involved. PNG textures arrive
through passed file descriptors. The host reconstructs GSK nodes and draws
them through Cairo in a GtkDrawingArea. GTK remains optional for `elfuse`.

```sh
brew install gtk4 pkg-config
make elfuse-gtk
build/elfuse-gtk build/elfuse --sysroot "$SYSROOT" \
  --env GDK_BACKEND --env GSK_RENDERER --env BROADWAY_DISPLAY \
  --env XDG_RUNTIME_DIR "$SYSROOT/usr/bin/android-translation-layer" "$APK"
```

`elfuse-gtk` sets the four imported variables for its child and removes its
private socket directory when that child exits. Explicit imports are needed
when using `--clear-env`. Guest HOME, cache, application data, and a session
DBus address must also be supplied when the application requires them. Install
fonts in the guest sysroot (for Alpine, `apk add font-dejavu`); host GTK fonts
do not supply guest Pango fonts. Use an account present in the sysroot; the
evaluated Alpine fixture has only uid 0. `--user 0:0` selects that guest
identity without changing host uid.

Mouse buttons, motion, vertical scroll, keys, focus and size changes are
returned to the guest. Closing the host window terminates its child;
the guest's own drawn close control follows the application's close handler.
This transport does not supply Android services, EGL surfaces, clipboard,
IME, or a full host GObject/JNI bridge. It requires a guest GTK build with
the matching local Broadway protocol, which GTK 5 removes.

With Alpine `android-translation-layer 0_git20261019-r0`, GTK `4.24.1-r0`,
and `font-dejavu 2.37-r6`, the real `demo_app.apk` displays its
`demo_application` title, `hello PoC world!`, and `second one (static)`.
Its drawn close button reaches `onPause`, `onStop`, `onDestroy`, and exit
status 0. Without guest fonts, both the title and body text are absent.
The zero-size allocations of ATL's content wrappers are intentional and
do not prevent the text from rendering.

The unmodified `com.leocardz.multitouch.test_19.apk` also renders its
ActionBar and custom touch view. Its image resources require a guest
GdkPixbuf decoder. The tested configuration uses the ABI-compatible
`gdk-pixbuf 2.42.12-r1` loaders, which decode PNG/JPEG in-process.
GdkPixbuf 2.44 uses glycin and bubblewrap; its namespace sandbox is not
supported by elfuse. Selecting 2.42 leaves that sandbox enabled wherever
glycin is used and does not substitute fake namespace operations.

Fetch the pinned AArch64 decoder alongside the sysroot, then generate its
loader cache with the guest binary:

```sh
PIXBUF=$(bash tests/fetch-gtk-pixbuf.sh)
MODULES="$PIXBUF/usr/lib/gdk-pixbuf-2.0/2.10.0/loaders"
build/elfuse --sysroot "$SYSROOT" \
  --env "LD_LIBRARY_PATH=$PIXBUF/usr/lib" \
  --env "GDK_PIXBUF_MODULEDIR=$MODULES" \
  "$PIXBUF/usr/bin/gdk-pixbuf-query-loaders" > "$PIXBUF/loaders.cache"
```

Add these options to the `build/elfuse` arguments in the GTK launch above:

```sh
--env "LD_LIBRARY_PATH=$PIXBUF/usr/lib" \
--env "GDK_PIXBUF_MODULEDIR=$MODULES" \
--env "GDK_PIXBUF_MODULE_FILE=$PIXBUF/loaders.cache"
```

Validation covers a mouse press, a drag, release back to the idle screen,
and two simultaneous touch sequences with independent movement and release.
Closing the host GtkWindow terminates the guest with SIGTERM (status 143).
Touch sequences were injected into the live bridge protocol; physical
multitouch hardware and vibration are not validated.

`make test-gtk-native-host` checks retained scene descendants and malformed
frame rollback without starting a VM or opening a window.

## USB Devices

Linux USB tools see the Mac's attached devices. `/dev/bus/usb` and
`/sys/bus/usb/devices` are synthesized from the IOKit registry, and opening
a device node yields a usbfs-compatible fd driven over IOKit (see
[internals.md](internals.md), section "USB Device Passthrough").

What works unprivileged is what macOS itself leaves unclaimed: vendor-class
and bulk interfaces, which is the debug-probe and DFU population. `lsusb`,
libusb programs, and nusb-based tools such as the probe-rs family
enumerate, claim, and transfer against those directly, including async
URBs.

What does not: an interface bound to an Apple class driver (CDC serial,
HID, FTDI, mass storage) cannot be claimed, and `CLAIMINTERFACE` reports
`EBUSY` -- exactly what Linux reports for an interface a kernel driver
holds. For a CDC serial device, open the host's `/dev/cu.*` node from the
guest instead; the termios layer drives the real line.

A stock distribution `lsusb` does not run yet, and the reason is not the
USB layer. usbutils reaches libusb through libudev, whose monitor socket
wants `SO_ATTACH_FILTER`; elfuse's netlink layer answers that
`ENOPROTOOPT`, libudev's monitor never starts, and `libusb_init` gives up
with `-99`:

```console
$ build/elfuse --sysroot ./debian-sysroot /usr/bin/lsusb
unable to initialize libusb: -99
```

Programs that open the device nodes themselves, or that build libusb
without the udev backend, are unaffected.

## Debugging With GDB Or LLDB

`elfuse` includes a built-in GDB Remote Serial Protocol stub.

Start the guest and wait at entry:

```sh
build/elfuse --gdb 1234 --gdb-stop-on-entry ./guest-program
```

Attach with GNU GDB:

```sh
aarch64-linux-gnu-gdb -ex "target remote :1234" ./guest-program
```

Or attach with LLDB:

```sh
lldb --batch -o "gdb-remote 1234" ./guest-program
```

The stub supports all-stop debugging, up to 16 hardware breakpoints, up to 16
watchpoints, single-step (implemented as a temporary breakpoint), full register
and memory access, and per-thread inspection. Implementation details, including
the snapshot protocol used to keep Hypervisor.framework register access on the
owning thread, are documented in [internals.md](internals.md).

## Guest Compatibility Model

`elfuse` is designed for Linux user-space workloads, not for booting a Linux
kernel or presenting a complete Linux host environment. Compatibility comes
from targeted ABI translation and emulation at the syscall boundary.

That has a few direct implications:

- `/proc` and `/dev` are compatibility surfaces, not passthrough mounts.
- `uname` and `/proc/version` report Linux 6.18 LTS, a stable floor for
  version-gated feature detection; the implemented syscall set is
  `src/syscall/dispatch.tbl`. See [internals.md](internals.md), section
  "Reported Kernel Identity".
- macOS and Linux file, socket, and signal semantics are normalized in the host
  syscall layer.
- Behavior is strongest for normal command-line tools, language runtimes, test
  binaries, and debugger-driven workflows.
- Guest-internal FUSE means `/dev/fuse` and `mount(..., "fuse", ...)`
  work entirely inside the VM. Programs that link against `libfuse`
  (sshfs, ntfs-3g, AppImage runtimes) run without macFUSE, FUSE-T, or
  FSKit on the host.
- USB devices attached to the Mac are reachable: `/dev/bus/usb` and
  `/sys/bus/usb/devices` are built from the IOKit registry, and opening a
  device node gives a usbdevfs fd whose ioctls -- interface claim, control
  and bulk transfers, and asynchronous URBs -- drive the device through
  IOKit. macOS arbitrates per interface: a claim fails while a host driver
  holds that interface open. See
  [internals.md](internals.md), section "USB Device Passthrough", for the
  per-ioctl gaps.

## Diagnostic Environment Variables

Off by default, and useful when a guest misbehaves rather than in normal use:

- `ELFUSE_STARTUP_TRACE`: `steps` prints per-step VM bring-up timings,
  `syscalls` prints a per-syscall histogram of startup traffic (frozen at the
  first `execve`, so steady-state calls do not swamp it), `all` does both.
  Comma-separated tokens are accepted, and `1` is a legacy alias for `steps`.
- `ELFUSE_PROFILE=/absolute/prefix`: write versioned runtime profile snapshots
  to `prefix.<host-pid>.jsonl`. See [Runtime Profile](#runtime-profile).
- `ELFUSE_SHIM_STATS=1`: dump the EL1 shim counter table to stderr at exit, so
  a syscall that should be served inside the shim but takes the HVC #5 exit is
  attributed without a rebuild.
- `ELFUSE_DISABLE_TLBI_RANGE=1`: refuse `FEAT_TLBIRANGE` and fall back to
  per-page and broadcast invalidation, which separates a stale-TLB bug from
  the range-encoding path.

## Runtime Profile

```sh
ELFUSE_PROFILE=/private/tmp/elfuse-run \
  ELFUSE_PROFILE_INTERVAL_MS=1000 build/elfuse --cpus 4 guest-program
python3 scripts/elfuse-profile.py /private/tmp/elfuse-run.*.jsonl
python3 scripts/elfuse-profile.py /private/tmp/elfuse-run.12345.jsonl \
  --from-seq 2 --to-seq 8 --limit 15
```

The host environment selects profiling, independently of `--clear-env` and
guest `--env` entries. Embedded launches use the same host variables.
`ELFUSE_PROFILE` must be an absolute output prefix, with an existing writable
parent directory. Each host process creates a new mode-0600 file exclusively;
an existing file is an error. Relative paths, empty values, invalid numeric
knobs, allocation failures and output errors produce a host stderr diagnostic
and disable profiling without changing the guest's result. Unset profiling
has no profiling clock reads, storage allocation or locks on execution paths.

`ELFUSE_PROFILE_INTERVAL_MS` defaults to 1000 and accepts 100 through 60000.
The exporter sleeps on a relative host condition-variable timeout, then writes
one bounded snapshot. Slow writes delay the exporter, never a guest worker.
The exporter thread is created after SIGUSR2 and SIGALRM are blocked, so a
fork helper inherits that mask before a sibling doorbell can arrive.
No worker writes records or allocates per event. The exporter does not sample
Mach CPU clocks; it reads counters updated by existing accounting hooks.
Normal host exit joins the exporter and flushes a final snapshot. SIGTERM,
SIGKILL, crashes and harness termination retain completed periodic snapshots;
they need no exit handler. Files are not fsynced for power-loss durability.
Guest fork uses a new host process with its own file, counters and exporter.
The output descriptor is close-on-exec and is not transferred as a guest fd.

The schema is JSONL version 1 (`v: 1` on every record). Records are:

| `type` | Fields and meaning |
|---|---|
| `metadata` | Host PID/PPID, host architecture, clock, units, capacities, storage bytes and array field names |
| `snapshot` | `seq`, `mono_ns`, `elapsed_ns`, process `epoch`, `rosetta`, `final`, loss counters and `cpu_sample` counters |
| `thread` | `seq`, process-lifetime `task` index, guest `tid`, thread-slot `generation`, last mounted `worker`, state/kind, cumulative `values`/`wait_ns` and live span starts |
| `syscall` | `seq`, `task`, `tid`, AArch64 `nr`/`name`, cumulative `values`, `active_hist`, last return and bounded Linux errno counts |
| `pc` | `seq`, `task`, image `epoch`, PC/LR address pair, Rosetta flag and cumulative count |
| `snapshot_end` | `seq` and ending `epoch`; completes the snapshot |

A reader accepts only snapshots ending in a matching `snapshot_end`. A live
or terminated file can end with a partial line or incomplete snapshot. The
analyzer ignores this tail, rejects unsupported versions, ranks phases,
syscalls and task lifetimes, and subtracts optional complete snapshot
boundaries. Each file is analyzed separately. Counters are cumulative from
process start; maxima remain lifetime maxima, not interval maxima. A changed
epoch between the snapshot header and end indicates a concurrent guest exec.
Exec increments the marker without clearing runtime or syscall totals; PC
identities include their image epoch. Task indexes are never reused, so TID
reuse and migration cannot combine different thread lifetimes.

All durations and timestamps are integer nanoseconds on host
`CLOCK_MONOTONIC`. `thread.values` follows `metadata.thread_fields`:
`guest_cpu_ns`, `service_cpu_ns`, `guest_wall_ns`, `host_wall_ns`, `mounts`,
`preempts`, `wakes`. CPU totals reuse scheduler interval settlement from host
thread CPU accounting; they exclude parked time and can lag an active mount
by one accounting batch. Guest CPU includes EL0 and EL1 shim execution.
Service CPU includes syscall dispatch, accounting and other mounted host
work. Guest wall spans bracket HVF execution; host wall spans bracket mounted
host work. Both include host descheduling and are not CPU utilization.
Accounting's `cpu_sample.wall_ns` is a nested subset, not an additional phase.
Its owner and remote calls and nanoseconds measure the sources named in
metadata: owner CLOCK_THREAD_CPUTIME_ID and foreign Mach thread_info.
The shared high-water sample keeps their different freshness monotonic.
Sampling durations include profiler clock bracket overhead.

`thread.wait_ns` follows `metadata.wait_fields`: runnable READY residence,
then blocked unknown, futex, sleep, IO, mqueue, stop, wait, vfork, IPC, service
and signal residence. READY includes runnable bandwidth-throttled tasks.
Only committed scheduler transitions accrue these counters. A completion
racing before block publication contributes no blocked residence. The live
`state_start_ns`, `kind`, `phase_start_ns`, `phase_guest`, `open_nr` and
`open_start_ns` fields distinguish an active syscall or still-parked thread.
`open_nr: -1` means none. Live phase spans apply only to RUNNING tasks.
The analyzer adds open READY/BLOCKED residence at its snapshot boundary;
phase totals are completed spans only. State numbers are NEW=0, READY=1,
RUNNING=2, BLOCKED=3, DEAD=4. Kind numbers are unknown=0 through signal=10
in the blocked field order above.

`syscall.values` follows `metadata.syscall_fields`: logical host-forwarded
`calls`, handler `attempts`, `completed`, `parks`, `active_ns`,
`active_max_ns`, `latency_ns`, `latency_max_ns`, `errors`, `zero_returns`,
`positive_returns`, `io_bytes`. Active wall brackets dispatch work up to
handler return, excluding subsequent unmounted waits. Latency spans the
logical call through final return or parked-result injection, including
queue and blocked residence. IO park re-dispatch increments attempts, not
calls; completion injection does not create another call. Signal-triggered
SVC restart after an observed EINTR is another host-forwarded call, rather
than an asserted libc-level logical call. Successful exec is return zero;
rt_sigreturn's register-restoration sentinel is also completion zero.
The exit syscall's sentinel is completion zero, not its guest exit status.
Only returns -1 through -4095 count as Linux errors. `last_return` is one
final result, not a distribution of positive results. `errno_counts` retains
eight distinct errors per task/syscall; `errno_overflow` counts others.

`active_hist` contains 16 dispatch-duration buckets. Bucket zero is
0 through less than 2 microseconds. Bucket i (1 through 14) is
`[2^i, 2^(i+1))` microseconds, and bucket 15 is at least 32768 microseconds.
The buckets count attempts. `io_bytes` sums actual positive byte returns for
read/write, vectored and positioned IO, sendto/recvfrom, sendmsg/recvmsg,
sendfile and splice. Calls returning messages, descriptors or offsets do not
report fabricated bytes. The EL1 fast paths do not exit to the host, so they
are absent from these syscall counts; `ELFUSE_SHIM_STATS` can separately
describe shim traffic. Host-forwarded Rosetta calls use the AArch64 ABI.

Storage is bounded to 1024 task lifetimes, 64 distinct syscall numbers per
task and 64 PC/LR pairs per task. `storage_bytes` reports reserved diagnostic
storage. Later task lifetimes increment `task_overflow`; unrepresented
syscall attempts increment `syscall_overflow`. No old lifetime is overwritten.
`incomplete_calls` reports calls abandoned at death or replaced by another
number. `clock_errors` reports unsupported duration readings; affected spans
have zero duration rather than a guessed time. Snapshot fields are atomic
but not a transaction: concurrent updates can appear in adjacent snapshots
and a state/start pair can transiently disagree. The analyzer clamps live
and delta arithmetic to zero. These records rank costs; they are not an
event trace or exact causal timeline. Summed thread time overlaps across CPUs.

Optional `ELFUSE_PROFILE_PC_MS=10` collects a throttled address pair on
existing owner exits. Zero (the default) disables it; nonzero values through
60000 are milliseconds between attempts per task. The profiler creates no
extra exits and reads registers only on the owning worker. Direct EL0 exits
use PC/LR; syscall HVC #5 uses ELR_EL1 and the restored EL0 LR after verifying
SPSR_EL1. Other EL1 exits are rejected. `pc_non_el0` counts rejected/non-readable
samples, and `pc_overflow` counts pairs beyond capacity. Samples are exit-biased,
not uniform CPU samples or host callstacks. PC and LR are guest AArch64 virtual
addresses; under Rosetta they belong to translated AArch64 execution, not
guest x86 RIP.
No address-to-symbol mapping is inferred. For native hotspots, capture the
guest's `/proc/self/maps` during the same exec epoch and resolve file-backed
addresses against that image's ELF segments and load bias. Mmap/munmap or
JIT reuse within an epoch can invalidate a later map; no captured map means
the address stays unresolved. LR is an address, not an unwound caller chain.

## OCI Images

`scripts/elfuse-oci.py` runs OCI images under elfuse;
[oci-images.md](oci-images.md) describes the store, the sealed volumes, and the
per-run shadow. It needs crane and umoci (`brew install crane umoci`), and runs
`build/elfuse` from its checkout, else `elfuse` on `PATH`.

```sh
make elfuse
scripts/elfuse-oci.py run python:3.12-slim python3 -c 'print("hello")'
scripts/elfuse-oci.py clean
```

| Command | Effect |
|---------|--------|
| `pull REF` | Seal the `linux/arm64` image of `REF` unless the store holds it |
| `run [--entrypoint CMD] REF [ARG]...` | Run `REF` under elfuse, pulling it first when the store has no record of it |
| `clean` | Detach and remove every image, run, and interrupted pull in the store; refuse a non-empty directory that is not a store, and a store in use |
| `list` | Print each reference in the store with its image digest and size, and each unreferenced image as `<none>` |

`--entrypoint CMD` replaces the image Entrypoint and drops its Cmd; an empty
`CMD` leaves only the arguments. Every argument after `REF` goes to the guest.
The store is `$ELFUSE_OCI_STORE`, by default `~/.local/share/elfuse/oci`; a new
or empty directory becomes a store.

crane reads registry credentials from the Docker configuration
(`$DOCKER_CONFIG/config.json`, by default `~/.docker/config.json`) when one
exists, else from Podman's `$REGISTRY_AUTH_FILE` or
`$XDG_RUNTIME_DIR/containers/auth.json`.

### Running The Smoke Lane Locally

```sh
make elfuse
ELFUSE_OCI_STORE=/tmp/oci-scratch scripts/ci/oci-smoke.sh
```

The lane needs macOS with Hypervisor.framework and network access, and ends by
cleaning the store. Its coverage is in [oci-images.md](oci-images.md#validation).
