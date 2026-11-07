# Per-VM scheduling

Each host process owns one HVF VM and an independent scheduling domain.
Guest tasks share a lazy pool of HVF workers, bounded by the VM CPU limit.
A blocked task releases its logical CPU; worker count follows runnable demand.
Darwin schedules the host processes and worker pthreads.

The default domain has half the host online CPUs, rounded down, with a minimum
of one and a maximum of four. `--cpus N` overrides `ELFUSE_CPUS=N`; an explicit
count can use all host online CPUs, up to the scheduler CPU-set limit. Fork
helpers receive the resolved domain count, and guest exec preserves it. Guest
CPU reporting and affinity share this domain. Each VM has its own limit, so
forked processes can together exceed it. HVF execution workers use Darwin
`QOS_CLASS_USER_INITIATED`; the signal/preemption consumer remains interactive.

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

FAIR wakeup follows the pinned Zircon `find_target_cpu` and
`CandidatePlacement` same-cluster path: start at the last logical CPU,
compare estimated queue time then deadline utilization, and stop searching
when the selected queue is at most 25 us and capacity is admissible.
`expected_runtime_ns` starts at 1 ms. Peaks follow the full sample; lower
samples decay by one quarter (`peak_decay_delta`, beta=1, alpha=1/4).
Samples use settled guest plus host-service CPU time, excluding host waits.
Insertion and removal transfer estimated demand once per active task.

An idle owner calls the pinned `steal_work` FAIR path before sleeping:
search remote queues, snap source eligibility, and select earliest eligible
finish through the affinity predicate. Start/finish offsets and consumed
budget convert between source and target virtual timelines. Normal wakeups
use the pinned legacy insertion activation reset. Host notification wakes
only the target CPU's condition variable; freeze and shutdown wake the domain.

The HVF backend supplies one equal-capacity logical cluster. Logical CPU
numbers do not identify physical cache clusters, and Darwin controls worker
placement. Consequently physical topology search, energy-model comparisons,
power-level demand caching and CPU hotplug are not transplanted. The existing
global scheduler mutex serializes queue moves instead of Zircon chain locks
and per-CPU spinlocks. Linux FIFO/RR queues and DEADLINE admission/GRUB remain
local and are not stolen; Zircon's deadline and critical-deadline policies
are not substitutes for those Linux contracts. All current wakes use normal
placement, not Zircon synchronous handoff placement.

Linux `exit_group` requests scheduler shutdown after publishing the process
exit status. This reaches idle owners outside HVF as well as mounted tasks;
the outer execution layer remains the sole owner of joins and VM destruction.

A task owns guest registers, signal state, syscall continuation and restart
state. An HVF worker owns its vCPU handle, host pthread and architectural
scratch. Only the outer execution loop changes the current task. Yield and
affinity handlers request rescheduling after the calling task's return path.
An active host handler stack or arbitrary EL1 instruction is not a switch point.

A task executes on at most one logical CPU and appears on at most one ready
queue. Runtime is settled before migration. Thread/group CPU clocks, CPU
timers and scheduling budgets consume the same accounting source; waiting
and host descheduling do not count as guest execution.

Accounting updates task totals and scheduling budgets under `sched_lock`.
The backend accumulates guest execution and syscall service separately and
charges them together at 1 ms or mount completion. Live samples include the
current phase. CPU-clock readers bracket settled counters with two samples
of the same backend generation so a settlement cannot lose or duplicate time.
An empty host-action set returns without copying callbacks or reacquiring
the lock; wake, kick, timer and priority actions retain normal dispatch.
Solo FAIR safe points and scheduler timer passes skip live budget sampling
when no other task is runnable on that CPU. A solo FAIR budget has no scheduler
deadline; the backend slice metronome still checks CPU-clock timers. Enqueue
notifies the timer backend to restore the contended budget deadline. Expired
budget remains expired, and CPU clocks, interval accounting and RT/DEADLINE
budget sampling remain active.

Wait completion publishes its result before making a task runnable. Task
generation and wait sequence identify asynchronous work. Readiness, timeout,
signal and teardown compete for one completion. Stopped or exiting tasks do
not become eligible merely because a wait completes. Syscall-specific partial
results, restart rules and absolute deadlines survive suspension.

Futex completion retires the old waiter, guest pointer and bucket charge before
publishing READY. The remounted task can immediately arm another wait; cleanup
after READY would race that publication and clear the new wait's metadata.

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
