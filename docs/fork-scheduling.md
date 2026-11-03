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
A sparse file holds an independent snapshot of current guest backing. Linux
shared mappings require their own shared backing and child reattachment.

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
