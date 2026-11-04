/*
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>

struct thread_entry;
struct profile_task;

/* Initialized before worker publication; hot readers need only the flag. */
extern _Atomic bool profile_active;
static inline bool profile_enabled(void)
{
    return atomic_load_explicit(&profile_active, memory_order_relaxed);
}

/* Output is prepared before guest threads. The single exporter starts after
 * proc_preempt_init blocks SIGUSR2/SIGALRM, inheriting their signal mask.
 */
void profile_init(void);
void profile_start_writer(void);
void profile_attach(struct thread_entry *t);
void profile_state(struct thread_entry *t, int state, int kind, uint64_t now);
void profile_wake(struct thread_entry *t);
void profile_mount(struct thread_entry *t, int worker);
void profile_preempt(struct thread_entry *t);
void profile_phase(struct thread_entry *t, bool guest);
void profile_cpu(struct thread_entry *t, uint64_t guest, uint64_t service);
uint64_t profile_now_ns(void);
void profile_accounting(uint64_t start, bool success, int slot, bool owner);
void profile_syscall_begin(struct thread_entry *t, int nr);
void profile_syscall_end(struct thread_entry *t, int64_t result, bool parked);
void profile_syscall_resume(struct thread_entry *t);
void profile_exec(struct thread_entry *t);
bool profile_sample_due(struct thread_entry *t);
void profile_sample(struct thread_entry *t,
                    uint64_t pc,
                    uint64_t lr,
                    bool el0,
                    bool rosetta);
void profile_image(bool rosetta);
