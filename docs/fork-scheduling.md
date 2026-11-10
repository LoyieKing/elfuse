# Fork and scheduling domains

Each VM has an independent [scheduler](scheduler.md). Darwin schedules the
VM host processes against each other; no common coordinator or cross-VM CPU
transfer protocol is used.

## Three separate objects

A Linux task is a schedulable thread. A thread group supplies process identity
and shared process resources. An mm is an address space. These relationships
are independent:

The CPU column describes Linux behavior before the elfuse-specific limits
below are applied.

| Operation | Tasks and groups | Address space | CPUs on Linux |
|-----------|------------------|---------------|---------------|
| pthread_create / CLONE_THREAD | another task in the same group | shared | existing CPU set |
| fork | one child task in a new group | private snapshot, with shared mappings retained | existing CPU set |
| CLONE_VM without CLONE_THREAD | task in another group | shared | existing CPU set |
| execve | calling group becomes the new image; group siblings terminate | caller obtains replacement mm | existing CPU set |

After a multithreaded process calls fork, the child contains the calling
thread only. Copying the parent's scheduler queues would also copy tasks that
must not exist in the child. The calling task's attributes and affinity are
inherited according to policy and RESET_ON_FORK rules; its prior execution
time is not copied as child CPU time.

## Why elfuse spawns another host process

The current HVF backend has one VM per host process. src/runtime/forkipc.c
implements fork using posix_spawn and IPC: another elfuse process creates a
VM, restores the child registers and resources, and maps a memory snapshot.
Present and paged-out runs are packed into one Mach copy-on-write entry;
the child maps those runs onto a fresh zero slab. File and overlay spans are
included whole. Linux shared mappings require child reattachment.

elfuse keeps this execution mechanism and gives the child an independent
local scheduler. Attribute inheritance remains required, but parent and
child do not share guest CPU capacity or priority ordering.

## What independent worker pools change

Suppose the runtime exposes one logical CPU, numbered 0. Parent A and child B
both have affinity {0}. If A is runnable FIFO priority 80 and B is FIFO
priority 10, B must wait while A remains runnable, subject to the configured
RT bandwidth rules. If A blocks on a pipe, B becomes eligible. Both CPUs and
priorities belong to the same runtime system.

The current arrangement instead gives A's host process a worker for its own
CPU 0 and gives B's host process another worker for another CPU 0. Their
queues do not compare priorities. Darwin chooses between the host workers,
without applying the guest FIFO attributes. They can run concurrently on
different host cores while both report guest CPU 0. On a one-core host,
Darwin can still alternate them contrary to guest FIFO order.

With N local CPUs and P backend processes, independent pools permit up to
P*N guest execution contexts. This is an accepted difference from Linux:
cross-VM FIFO/RR precedence, nice bandwidth ratios, affinity exclusion,
deadline admission, RT throttling and PI donation are not guaranteed.
Applications that rely on those properties across processes are outside the
compatibility target. Within one VM, Linux task scheduling remains required.

Create workers lazily from runnable demand, up to each VM's CPU limit. A
single-threaded child needs one worker; sleeping tasks do not justify more
workers. This bounds avoidable fork overhead but does not create a shared
CPU reservation. Track aggregate backend, worker and HVF memory consumption.

IPC still carries fork state, lifecycle events, signals, shared-resource
operations and supported remote task attribute requests. Local scheduling
does not require per-switch IPC or cross-VM stop/grant acknowledgments.

## Fork snapshot consistency

Stopping every vCPU is insufficient when host threads can mutate guest memory.
An IO completion can copy bytes to a guest buffer, a futex operation can
update a word, and a timeout can write a remaining-time result while vCPUs
are stopped. A memory snapshot taken during those writes need not describe a
valid boundary between guest operations.

The replacement freezes writes to the address space, waits for admitted
mutations and guest execution to reach valid boundaries, captures the
private-memory state, then resumes admission. READY and BLOCKED tasks do not
need to execute merely to arrive at a host-pthread barrier. Outstanding
service work must participate in the protocol. Shared mappings retain their
shared object identity rather than being converted into private snapshots.

Linux does not promise that racing guest writes form an application-level
transaction at fork. The runtime freeze protects emulator bookkeeping and
mapping consistency; it does not add transactional semantics to guest data.

## The separate CLONE_VM and exec issue

Ordinary fork gives parent and child private address spaces. CLONE_VM without
CLONE_THREAD is different: two processes share an address space. If one calls
execve, Linux gives it a new mm while the other keeps the old mm.

The current backend puts these tasks in one guest slab. Resetting that slab
for exec would erase the other process's memory. Safe mm separation for this
case is outside the target. Reject unsupported clone combinations, or reject
exec before its point of no return while independent process users retain
the shared mm. Never erase another process's image or fake exec success.
Record the exact unsupported combinations and error codes with the code.

Common fork/exec/wait, private-memory isolation, descriptor inheritance,
CLOEXEC, argv/envp, exit status and basic SIGCHLD behavior remain required.
Failed exec loading before the point of no return preserves the old image.
Snapshot and asynchronous guest-memory safety remain mandatory.

For non-leader exec in a pthread group, support ordinary callers when group
sibling teardown and replacement are safe. Exact de_thread identity/ptrace
corner cases are not a full-compatibility requirement. Unsupported cases
must fail before destructive changes; leader storage reuse never changes
another task's identity.

## TODO: vfork without a slab snapshot

`CLONE_VM|CLONE_VFORK` (bionic `vfork`, `posix_spawn`, Java
`ProcessBuilder`) shares live EL0 Mach backing with a helper process.
Infrastructure remains a private CoW span. Successful exec detaches child
backing before parent notification; failed exec and exit preserve shared
stores. Siblings remain runnable. There is no dirty-page copyback.

The supported launch path excludes independent mapping mutations and
cross-process futex synchronization. Live memory sharing alone does not
provide full shared-mm semantics. Helper spawn, state IPC and backing-object
export remain; resident-size-independent parent stop time is unverified.

Planned replacement:

1. Run the vfork child as an in-process task on the parent's slab, like
   `sys_clone_vm`, with the parent parked until exec or exit.
2. Give that task a private view of what children mutate before exec: fd
   table (inherited slots borrowed, so closing one drops only the child's
   slot), cwd, umask, signal dispositions, pgid/sid and effective ids. Bionic
   `posix_spawn` file actions and `ApplyAttrs`, and libcore `childProcess`,
   mutate exactly this set.
3. Raise a shim attention bit while such a task exists so EL1 fast paths
   (identity, urandom bitmap) defer to the host.
4. At `execve`, after `exec_preload_interp` succeeds (the last recoverable
   point), spawn a fresh elfuse with the resolved path, argv, envp, non-CLOEXEC
   fds, cwd, umask, creds, rlimits, session, signal state and chown overlay.
   Skip `thread_exec_de_thread` and the CLOEXEC sweep: neither may touch the
   parent. The spawned process owns the guest pid; the in-process task retires
   without reporting a vm-clone exit.
5. Exit before exec (libcore writes errno to its fail pipe and `_exit`s)
   reports through the process table, since libcore reaps from a different
   thread than the one that forked.

Acceptance: `tests/test-vfork-sibling`, a posix_spawn file-action and
attribute matrix, Java `ProcessBuilder` with a redirect and a failing exec,
and per-spawn parent stop time independent of resident size.

## Observable checks

Fork attribute inheritance, parent-child isolation, basic lifecycle and
supported remote task queries are required checks. The cross-fork FIFO case
records an accepted Linux difference and is not a cutover gate. Its Linux
reference requires suitable RT privileges; capability skips do not prove
the ordering behavior. Keep the assertion unchanged when recording a
deviation; do not label a Linux mismatch PASS.

Address-space freeze, private/shared mapping correctness and rejection of
unsupported CLONE_VM exec remain safety gates. Same-VM FIFO/RR, PI,
affinity, signal migration and CPU accounting retain strict acceptance.

## Planned reusable pre-Application template

This design is for umaru startup reuse; it is not implemented. It leaves the
ordinary fork/vfork contracts and outstanding work above unchanged. The umaru
plan is in ../umaru/docs/rendering-performance.md, section 9.

The reusable object contains a package-neutral ART runtime before Application
construction: matching boot jars and native registrations, initialized system
font data, and private preloaded heap/code state. ART runs with -Xzygote for
its fork lifecycle, without starting the Android Zygote service or system_server.
Process-local service instances, ApplicationSharedMemory, APK identity and
component database, application class initializers, renderer/GLES/media sockets,
account data, Binder RPC sessions and pending callbacks are excluded. umaru must
separate immutable preload from child specialization rather than snapshot its
current process-bound RuntimeBootstrap inside sLock.

Capture uses the ART pre-fork hooks before elfuse's address-space mutation
freeze. ART PreZygoteFork requires one remaining guest thread; stopping every
vCPU does not repair GC/JIT/daemon thread records or locks. The retained image
is captured at a trusted JNI fork barrier with no application work or held
framework monitor. The fork register/EL1-frame continuation must be the same
continuation the existing fork child resumes, with child return value zero.

A template owner retains the Mach CoW entry, span map, guest register state,
VMA metadata and an explicit descriptor restore policy. Each launch maps the
same immutable entry into a fresh elfuse host process using the existing
snapshot mapper and restore machinery. It does not recapture a live app, copy
the whole guest slab, spawn by host fork(), or replay a consumed IPC stream.
Serialize immutable memory metadata once; instantiate child-specific process
state for every request. Native handler userdata and host synchronization
objects are reconstructed rather than copied as pointers.

Every child receives authenticated session facts before application code:
session/user/uid/processName, the logical parent and process registry, sysroot
and private data mounts, abstract-socket namespace, capabilities, rlimits,
stdio, supervisor/renderer endpoints, environment and runtime properties.
Fresh entropy, current vvar clocks, signal state, CPU counters, worker pool and
private EL1 stacks/shim_data accompany ART post-fork Thread/GC/JIT/daemon setup.
Shared app/service descriptors and writable template MAP_SHARED objects are
not inherited between sessions. Immutable asset mappings may share backing;
file offsets must remain independent. Same-app processes share only the
session resources already allowed by that app's normal multi-process contract.

The owner survives individual session exit. Outstanding child leases retain
memory and artifact generations until restore or execution no longer uses
them; eviction blocks new leases, not existing children. Key templates by
elfuse/shim/fork format, ART/boot/native/font hashes, ABI/IPA/page layout and
runtime/GC/preload configuration. Mismatches create a new generation through
the real cold path. This is an in-memory snapshot retained across sessions,
not a disk checkpoint that promises resume across host restart or reboot.

Proposed operations are create, instantiate and release of a template handle.
Keep ordinary sys_clone resource inheritance and Linux child registration
separate from template instantiation; a template owner is not automatically
the app's logical parent. Reuse the low-level snapshot/restore functions, not
the entire parent-specific IPC header as a permanent launch descriptor.

Acceptance covers simultaneous same/different APK sessions and same-session
remote Activity, service-first Activity and headless service/provider launches.
Each child constructs its own Application and installs only its declared
providers. Check fresh identity/entropy and independent service/global state,
cross-child memory writes, descriptor offsets and namespace isolation, pending
signal/timer cleanup, class initialization and GC/JIT after restore, nested
ordinary fork/exec/wait, and child survival after session/template retirement.
Retain tests/test-fork-quiesce-memory, tests/test-fork-quiesce-host and the
ordinary fork/vfork lanes as regression gates. Benchmark one-time capture,
cache-hit restore/specialization and cold miss separately, including packed
bytes, spans, CoW faults, dirty memory, worker count and multiple concurrent
restores. No resident-size-independent or zero-copy timing is assumed.
