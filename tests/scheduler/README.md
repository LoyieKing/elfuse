# Scheduler behavior regressions

These guest tests compare behavior with Linux for the
[per-VM scheduler](../../docs/scheduler.md). Same-VM task
scheduling and common fork/exec lifecycle are required. Cross-VM scheduling
comparisons document accepted differences. Assertions retain Linux expected
results; classification does not turn a mismatch into PASS.

## Build and run on macOS

```sh
make scheduler-tests-build
bash tests/scheduler/run.sh --list
bash tests/scheduler/run.sh --filter nice-inherit-isolate
bash tests/scheduler/run.sh --filter signal-affinity-migrate
bash tests/scheduler/run.sh --filter process-cputime-thread-exit
bash tests/scheduler/run.sh --filter fork-inherit-isolate
bash tests/scheduler/run.sh --filter rt-fifo-excludes-fork
bash tests/scheduler/run.sh --filter test-sched-attr-abi
bash tests/scheduler/run.sh --filter rr-rotation
bash tests/scheduler/run.sh --filter rr-preempt-quantum
bash tests/scheduler/run.sh --filter fifo-yield-order
bash tests/scheduler/run.sh --filter fifo-wake-preempt
bash tests/scheduler/run.sh --filter deadline-throttle
bash tests/scheduler/run.sh --filter deadline-yield
bash tests/scheduler/run.sh --filter affinity-migrate
bash tests/scheduler/run.sh --filter test-sched-preempt
bash tests/scheduler/run.sh --filter test-futex-pi-inherit
bash tests/scheduler/run.sh --filter test-threaded-exec
bash tests/scheduler/run.sh --filter test-thread-leader-exit
bash tests/scheduler/run.sh --filter test-eintr-restart
bash tests/scheduler/run.sh --filter test-mqueue
bash tests/scheduler/run.sh --filter test-sched-capabilities
```

The build uses CROSS_COMPILE and static Linux libc, like existing guest tests.
Each case runs in a separate process under timeout/gtimeout. Logs and results
are in build/scheduler-logs and build/scheduler-results.txt unless overridden
by SCHED_LOG_DIR and SCHED_RESULTS. SCHED_TIMEOUT controls the per-case limit.
Missing binaries, an empty selection, crashes, and timeouts fail the lane.
Exit 77 is an explicit prerequisite skip; an absent syscall is a failure.

`make scheduler-tests` builds the runtime and runs every listed comparison.
Its combined exit status can be nonzero for an accepted deviation; use the
case classification below for cutover decisions. Filter required cases
individually using the commands above. The script commands use the existing
build/elfuse. Do not overlap timing-sensitive test runs.

## Linux reference

Build on the reference Linux host with its own compiler:

```sh
mkdir -p build/native
cc -D_GNU_SOURCE -O2 -pthread -o build/native/test-sched-task-state tests/test-sched-task-state.c
cc -D_GNU_SOURCE -O2 -pthread -o build/native/test-sched-fork-domain tests/test-sched-fork-domain.c
cc -D_GNU_SOURCE -O2 -o build/native/test-sched-attr-abi tests/test-sched-attr-abi.c
cc -D_GNU_SOURCE -O2 -pthread -o build/native/test-sched-policy tests/test-sched-policy.c
cc -D_GNU_SOURCE -O2 -pthread -o build/native/test-sched-policy-rt tests/test-sched-policy-rt.c
cc -D_GNU_SOURCE -O2 -pthread -o build/native/test-sched-policy-dl tests/test-sched-policy-dl.c
cc -D_GNU_SOURCE -O2 -pthread -o build/native/test-sched-preempt tests/test-sched-preempt.c
cc -D_GNU_SOURCE -O2 -pthread -o build/native/test-futex-pi-inherit tests/test-futex-pi-inherit.c
cc -D_GNU_SOURCE -O2 -pthread -o build/native/test-threaded-exec tests/test-threaded-exec.c
cc -D_GNU_SOURCE -O2 -pthread -o build/native/test-thread-leader-exit tests/test-thread-leader-exit.c
bash tests/scheduler/run.sh --native
```

The task-state, fork-domain, policy, policy-rt, policy-dl, PI and leader-exit
binaries use the repository's raw syscall helper, which supports Linux AArch64
and x86_64. The attribute test uses architecture-provided SYS_* numbers. Pin
Linux version, configuration, compiler, libc, allowed CPU mask and privileges
with results. A native test run cannot be replaced by a macOS
cross-compilation result.

The RT comparisons need CAP_SYS_NICE or a sufficient RLIMIT_RTPRIO. The
DEADLINE and PI comparisons need CAP_SYS_NICE. The affinity migration
comparison needs two allowed CPUs.
Run their Linux reference in a disposable RT-enabled environment. A permission
or CPU-count skip does not establish behavior. Same-VM RT/DL coverage remains
mandatory for cutover. Signal migration requires two allowed CPUs.

The DEADLINE throttle/yield cases pin their task to one CPU. Linux admission
requires that CPU mask to cover the task's root domain. Use one online CPU or
an exclusive cpuset partition for these two cases; root alone is insufficient.
The namespace-rejection assertions in sched-capabilities describe elfuse's
unsupported namespace surface and are not Linux equivalence assertions.

## Cases

| Test | Observable contract | Classification |
|------|---------------------|----------------|
| task-state / nice-inherit-isolate | thread nice inheritance, mutation and creator isolation | required |
| task-state / signal-affinity-migrate | handler changes affinity; rt_sigreturn resumes state | required |
| task-state / process-cputime-thread-exit | process CPU time retains exited thread execution | required |
| fork-domain / fork-inherit-isolate | inherited attributes, parent/child isolation and remote queries | required for supported attribute APIs |
| fork-domain / rt-fifo-excludes-fork | FIFO excludes lower-class execution across fork on one CPU | diagnostic; cross-VM ordering is not guaranteed |
| attr-abi | sched_attr size/errors/flags, legacy consistency and fair nice mutation | required |
| policy | Linux scheduler policy, priority and nice ABI | required |
| policy-rt / rr-rotation | equal-priority RR peers both advance on one CPU | required |
| policy-rt / rr-preempt-quantum | higher-priority preemption keeps the RR head and unused quantum | required |
| policy-rt / fifo-yield-order | equal-priority wake goes to the tail; yield passes the CPU in queue order | required |
| policy-rt / fifo-wake-preempt | higher-priority FIFO wake preempts the runner | required |
| policy-dl / deadline-throttle | solo deadline task is cut off at runtime and replenished at its period | required |
| policy-dl / deadline-yield | deadline yield discards the remaining runtime until replenishment | required |
| policy-dl / affinity-migrate | remote setaffinity moves a running task and preserves its CPU-time ledger | required with two CPUs |
| preempt | fair spinners outnumber slots and every worker advances | required |
| futex-pi-inherit | PI donation lets a boosted owner release the lock during RT contention | required |
| threaded-exec (main/worker) | exec tears down live siblings; the new image is single-threaded | required for supported pthread exec |
| thread-leader-exit | leader exit then fork and non-leader exec preserve pid/tid and child waitability | required |
| eintr-restart | signal restart and committed partial IO survive waits | required |
| mqueue | queue waits release logical CPUs and preserve notifications | required |
| sched-capabilities | clock queries and unsupported namespace errors | required |

The RT ordering cases are bounded observation intervals, not throughput
benchmarks or hard real-time latency claims. Fork/leader-exit tests use
synchronization and child cleanup; the external timeout bounds runtime bugs.

Additional required cutover coverage includes quiescence, membarrier, signal
migration under load, and safe rejection of unsupported shared-mm exec. Full
CLONE_VM exec separation is outside the target. The scheduler reference defines
these boundaries; the listed cases do not cover the full matrix.
