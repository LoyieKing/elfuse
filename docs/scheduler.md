# Per-VM scheduling

Each host process owns one HVF VM and an independent scheduling domain.
Guest tasks share a lazy pool of HVF workers, bounded by the VM CPU limit.
A blocked task releases its logical CPU; worker count follows runnable demand.
Darwin schedules the host processes and worker pthreads.

## Sources and licensing

Fair scheduling derives from Zircon's
[zircon/kernel/kernel/scheduler.rs at 966c936b56d8d117a26ecbf2c583ec350b2325c8](https://fuchsia.googlesource.com/fuchsia/+/966c936b56d8d117a26ecbf2c583ec350b2325c8/zircon/kernel/kernel/scheduler.rs).
The retained license is [src/runtime/sched/LICENSE](../src/runtime/sched/LICENSE).
Linux ABI behavior follows v6.18 and these references:

- [Linux scheduling policies](https://man7.org/linux/man-pages/man7/sched.7.html)
- [Scheduler attributes](https://man7.org/linux/man-pages/man2/sched_setattr.2.html)
- [Deadline scheduling](https://docs.kernel.org/scheduler/sched-deadline.html)
- [RT mutex design](https://docs.kernel.org/locking/rt-mutex-design.html)
- [Zircon fair scheduler](https://fuchsia.dev/fuchsia-src/concepts/kernel/fair_scheduler)

## Ownership and execution

The scheduler core owns per-CPU queues, virtual timelines, runtime budgets,
accounting, affinity and scheduling attributes. Selection orders DEADLINE,
RT and FAIR classes. Local PI changes effective selection attributes while
preserving base attributes. Fair queues use a start-time ordered augmented
tree and a CPU-wide period.

A task owns guest registers, signal state, syscall continuation and restart
state. An HVF worker owns its vCPU handle, host pthread and architectural
scratch. Only the outer execution loop changes the current task. Yield and
affinity handlers request rescheduling after the calling task's return path.
An active host handler stack or arbitrary EL1 instruction is not a switch point.

A task executes on at most one logical CPU and appears on at most one ready
queue. Runtime is settled before migration. Thread/group CPU clocks, CPU
timers and scheduling budgets consume the same accounting source; waiting
and host descheduling do not count as guest execution.

Wait completion publishes its result before making a task runnable. Task
generation and wait sequence identify asynchronous work. Readiness, timeout,
signal and teardown compete for one completion. Stopped or exiting tasks do
not become eligible merely because a wait completes. Syscall-specific partial
results, restart rules and absolute deadlines survive suspension.

Fork freezes address-space access and waits for admitted guest writes and
execution to reach a consistent boundary. The child starts with one task,
inherited scheduling attributes and fresh CPU accounting. Shared mappings
retain their shared backing objects. Exit cleanup has one owner for robust
lists, PI, CLEARTID, accounting and lifecycle notification.

## Compatibility boundary

Scheduling order and capacity are local to a VM. Equal affinity CPU numbers
in different VMs do not imply mutual exclusion. Cross-VM FIFO/RR precedence,
nice bandwidth ratios, RT/deadline admission and PI donation are not guaranteed.
PRIO_PGRP and PRIO_USER sweeps enumerate local tasks; task-directed remote
attribute operations use control IPC. Host QoS does not guarantee physical
CPU placement or hard real-time latency.

Common fork/exec/wait behavior and supported pthread exec remain required.
Exec with independent live users of the same address space is rejected before
replacing that address space. Exact Linux de_thread/ptrace corner cases and
full shared-mm exec separation are outside the compatibility target.
[Fork and scheduling domains](fork-scheduling.md) explains these limits.

## Validation

[Scheduler regressions](../tests/scheduler/README.md) describes focused guest
cases. [Classic suites](../tests/classic/README.md) describes upstream Linux
comparisons. [Building and testing](testing.md#scheduler-replacement-acceptance)
records acceptance results and uncovered requirements. Cross-VM diagnostic
comparisons retain their Linux expected results; an accepted compatibility
limit does not turn a mismatch into PASS.
