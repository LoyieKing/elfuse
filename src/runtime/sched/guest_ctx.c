/*
 * Migratable guest thread register context
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "runtime/sched/guest_ctx.h"

#include "core/shim-globals.h"
#include "hvutil.h"

#include "debug/log.h"

void guest_ctx_save(hv_vcpu_t vcpu, guest_thread_ctx_t *ctx)
{
    if (!ctx)
        return;
    vcpu_snapshot_gprs(vcpu, ctx->gprs);
    vcpu_snapshot_simd(vcpu, &ctx->simd);
    ctx->sp_el0 = vcpu_get_sysreg(vcpu, HV_SYS_REG_SP_EL0);
    ctx->sp_el1 = vcpu_get_sysreg(vcpu, HV_SYS_REG_SP_EL1);
    ctx->tpidr_el0 = vcpu_get_sysreg(vcpu, HV_SYS_REG_TPIDR_EL0);
    ctx->elr_el1 = vcpu_get_sysreg(vcpu, HV_SYS_REG_ELR_EL1);
    ctx->spsr_el1 = vcpu_get_sysreg(vcpu, HV_SYS_REG_SPSR_EL1);
    ctx->pc = vcpu_get_reg(vcpu, HV_REG_PC);
    ctx->cpsr = vcpu_get_reg(vcpu, HV_REG_CPSR);
    ctx->valid = true;
}

void guest_ctx_restore(hv_vcpu_t vcpu,
                       const guest_thread_ctx_t *ctx,
                       guest_t *g,
                       int64_t tid)
{
    if (!ctx || !ctx->valid)
        return;

    vcpu_restore_gprs(vcpu, ctx->gprs);
    vcpu_restore_simd(vcpu, &ctx->simd);
    vcpu_set_sysreg(vcpu, HV_SYS_REG_SP_EL0, ctx->sp_el0);
    vcpu_set_sysreg(vcpu, HV_SYS_REG_SP_EL1, ctx->sp_el1);
    vcpu_set_sysreg(vcpu, HV_SYS_REG_TPIDR_EL0, ctx->tpidr_el0);
    vcpu_set_sysreg(vcpu, HV_SYS_REG_ELR_EL1, ctx->elr_el1);
    vcpu_set_sysreg(vcpu, HV_SYS_REG_SPSR_EL1, ctx->spsr_el1);
    vcpu_set_reg(vcpu, HV_REG_PC, ctx->pc);
    vcpu_set_reg(vcpu, HV_REG_CPSR, ctx->cpsr);

    if (g && shim_globals_install_per_vcpu(vcpu, g, tid) < 0)
        log_error(
            "guest_ctx_restore: shim_globals_install_per_vcpu tid=%lld failed",
            (long long) tid);
}
