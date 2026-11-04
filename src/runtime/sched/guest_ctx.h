/*
 * Migratable guest thread register context
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * A kernel task does not permanently own an HVF vCPU. Its runnable EL0/EL1
 * register state lives here and is saved/restored onto a pool-owned vCPU (CPU
 * worker) when the fair scheduler mounts the task.
 */

#pragma once

#include <Hypervisor/Hypervisor.h>
#include <stdbool.h>
#include <stdint.h>

#include "hvutil.h"

#include "core/guest.h"

typedef struct guest_thread_ctx {
    uint64_t gprs[31];
    vcpu_simd_state_t simd;
    uint64_t sp_el0;
    uint64_t sp_el1;
    uint64_t tpidr_el0;
    uint64_t elr_el1;
    uint64_t spsr_el1;
    uint64_t esr_el1;
    uint64_t far_el1;
    uint64_t pc;   /* HV_REG_PC at last save / initial entry */
    uint64_t cpsr; /* HV_REG_CPSR at last save / initial entry */
    bool valid;
} guest_thread_ctx_t;

/* Snapshot migratable state from a live vCPU (must run on the owning host
 * thread).
 */
void guest_ctx_save(hv_vcpu_t vcpu, guest_thread_ctx_t *ctx);

/* Load migratable state onto a pool vCPU and refresh per-thread shim identity
 * (CONTEXTIDR / TPIDR_EL1). MMU sysregs are assumed already configured on the
 * vCPU by the worker bring-up path.
 */
void guest_ctx_restore(hv_vcpu_t vcpu,
                       const guest_thread_ctx_t *ctx,
                       guest_t *g,
                       int64_t tid);
