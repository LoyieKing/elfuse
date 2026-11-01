/*
 * Structured crash report for GitHub issue filing
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Prints a structured diagnostic to stderr when elfuse encounters a fatal
 * error. Sections: environment, crash type, binary info, registers, memory
 * layout, and instructions for filing a GitHub issue.
 */

#include <stdio.h>
#include <string.h>
#include <sys/sysctl.h>

#include "version.h"

#include "debug/crashreport.h"

#include "syscall/proc.h"

/* Page-table descriptor bit definitions used by the diagnostic walker below.
 * The full set lives in src/core/guest.c next to the helpers that build
 * descriptors; the crash walker needs only the fields it prints, so keep the
 * duplication minimal rather than promoting a private header.
 */
#define CR_PT_VALID 1ULL
#define CR_PT_TABLE 2ULL
#define CR_PT_ADDR_MASK 0xFFFFFFFFF000ULL
#define CR_L2_BLOCK_ADDR_MASK 0xFFFFFFE00000ULL
#define CR_BLOCK_1GIB (1024ULL * 1024 * 1024)
#define CR_BLOCK_2MIB (2ULL * 1024 * 1024)
#define CR_PAGE_SIZE 4096ULL

/* Read a sysctl string into buf (NUL-terminated). Returns 0 on success. */
static int sysctl_str(const char *name, char *buf, size_t bufsz)
{
    size_t len = bufsz;
    if (sysctlbyname(name, buf, &len, NULL, 0) != 0) {
        buf[0] = '\0';
        return -1;
    }
    buf[bufsz - 1] = '\0';
    return 0;
}

/* Map crash_type_t to a human-readable label. */
static const char *crash_type_name(crash_type_t type)
{
    switch (type) {
    case CRASH_TIMEOUT:
        return "TIMEOUT";
    case CRASH_BAD_EXCEPTION:
        return "BAD_EXCEPTION";
    case CRASH_UNEXPECTED_HVC:
        return "UNEXPECTED_HVC";
    case CRASH_UNEXPECTED_EC:
        return "UNEXPECTED_EC";
    case CRASH_UNEXPECTED_EXIT:
        return "UNEXPECTED_EXIT";
    case CRASH_ELR_ZERO:
        return "ELR_ZERO";
    case CRASH_HV_CHECK:
        return "HV_CHECK";
    }
    return "UNKNOWN";
}

/* Decode ESR_EL1 exception class (bits [31:26]) to a short label. Values per
 * ARM DDI 0487 (ARMv8-A Architecture Reference Manual).
 */
static const char *esr_ec_name(uint64_t esr)
{
    unsigned ec = (unsigned) ((esr >> 26) & 0x3f);
    switch (ec) {
    case 0x00:
        return "Unknown reason";
    case 0x01:
        return "WFI/WFE trapped";
    case 0x07:
        return "FP/ASIMD access trapped";
    case 0x0e:
        return "Illegal execution state";
    case 0x15:
        return "SVC from AArch64";
    case 0x16:
        return "HVC from AArch64";
    case 0x17:
        return "SMC from AArch64";
    case 0x18:
        return "MSR/MRS/System trap";
    case 0x19:
        return "SVE access trapped";
    case 0x20:
        return "Instruction abort (lower EL)";
    case 0x21:
        return "Instruction abort (same EL)";
    case 0x22:
        return "PC alignment fault";
    case 0x24:
        return "Data abort (lower EL)";
    case 0x25:
        return "Data abort (same EL)";
    case 0x26:
        return "SP alignment fault";
    case 0x2c:
        return "FP exception";
    case 0x30:
        return "HW breakpoint (lower EL)";
    case 0x31:
        return "HW breakpoint (same EL)";
    case 0x32:
        return "SW step (lower EL)";
    case 0x33:
        return "SW step (same EL)";
    case 0x34:
        return "HW watchpoint (lower EL)";
    case 0x35:
        return "HW watchpoint (same EL)";
    case 0x3c:
        return "BRK from AArch64";
    default:
        return "unhandled EC";
    }
}

static bool esr_is_data_abort(uint64_t esr)
{
    unsigned ec = (unsigned) ((esr >> 26) & 0x3f);
    return ec == 0x24 || ec == 0x25;
}

/* Walk the guest stage-1 page tables for the supplied VA and print L0/L1/L2/L3
 * entries in raw form so the crash report localises an "unmapped" claim either
 * to the guest PT (entry is 0 or PT_VALID clear) or to a downstream stage-2
 * hole. The walker mirrors gva_translate_perm in src/core/guest.c but accepts
 * any PT_VALID descriptor instead of enforcing requested permissions, so a
 * non-executable or EL1-only page still prints with its actual contents.
 * Silently skips when g, host_base, or ttbr0 are missing -- the data needed for
 * the dump is gone before the walker can stage anything useful.
 */
static bool dump_pt_walk_for_va(const guest_t *g,
                                uint64_t va,
                                uint64_t *ipa_out)
{
    if (!g || !g->host_base || !g->ttbr0)
        return false;

    uint64_t base = g->ipa_base;
    if (g->ttbr0 < base || g->ttbr0 - base >= g->guest_size) {
        fprintf(stderr, "  PT walk: TTBR0 0x%llx out of slab range\n",
                (unsigned long long) g->ttbr0);
        return false;
    }
    uint64_t l0_off = g->ttbr0 - base;
    const uint64_t *l0 =
        (const uint64_t *) ((const uint8_t *) g->host_base + l0_off);
    unsigned l0_idx = (unsigned) (va / (512ULL * CR_BLOCK_1GIB));
    if (l0_idx >= 512) {
        fprintf(stderr, "  PT walk: L0 index %u out of range\n", l0_idx);
        return false;
    }
    uint64_t l0_entry = l0[l0_idx];
    fprintf(stderr, "  L0[%u]=0x%llx", l0_idx, (unsigned long long) l0_entry);
    if (!(l0_entry & CR_PT_VALID)) {
        fprintf(stderr, " INVALID\n");
        return false;
    }

    uint64_t l1_ipa = l0_entry & CR_PT_ADDR_MASK;
    if (l1_ipa < base || l1_ipa - base >= g->guest_size) {
        fprintf(stderr, " L1@0x%llx out-of-slab\n",
                (unsigned long long) l1_ipa);
        return false;
    }
    const uint64_t *l1 =
        (const uint64_t *) ((const uint8_t *) g->host_base + (l1_ipa - base));
    unsigned l1_idx = (unsigned) ((va / CR_BLOCK_1GIB) % 512);
    uint64_t l1_entry = l1[l1_idx];
    fprintf(stderr, " L1[%u]=0x%llx", l1_idx, (unsigned long long) l1_entry);
    if (!(l1_entry & CR_PT_VALID)) {
        fprintf(stderr, " INVALID\n");
        return false;
    }

    uint64_t l2_ipa = l1_entry & CR_PT_ADDR_MASK;
    if (l2_ipa < base || l2_ipa - base >= g->guest_size) {
        fprintf(stderr, " L2@0x%llx out-of-slab\n",
                (unsigned long long) l2_ipa);
        return false;
    }
    const uint64_t *l2 =
        (const uint64_t *) ((const uint8_t *) g->host_base + (l2_ipa - base));
    unsigned l2_idx = (unsigned) ((va / CR_BLOCK_2MIB) % 512);
    uint64_t l2_entry = l2[l2_idx];
    fprintf(stderr, " L2[%u]=0x%llx", l2_idx, (unsigned long long) l2_entry);
    if (!(l2_entry & CR_PT_VALID)) {
        fprintf(stderr, " INVALID\n");
        return false;
    }

    /* A valid L2 entry is either a 2MiB block (bit1=0) or a table descriptor
     * pointing at a 4KiB L3 page. Only the table case requires another walk.
     */
    if (!(l2_entry & CR_PT_TABLE)) {
        uint64_t block_ipa = l2_entry & CR_L2_BLOCK_ADDR_MASK;
        uint64_t translated_ipa = block_ipa + (va & (CR_BLOCK_2MIB - 1));
        fprintf(stderr, " (2MiB block -> IPA 0x%llx)\n",
                (unsigned long long) translated_ipa);
        if (ipa_out)
            *ipa_out = translated_ipa;
        return true;
    }

    uint64_t l3_ipa = l2_entry & CR_PT_ADDR_MASK;
    if (l3_ipa < base || l3_ipa - base >= g->guest_size) {
        fprintf(stderr, " L3@0x%llx out-of-slab\n",
                (unsigned long long) l3_ipa);
        return false;
    }
    const uint64_t *l3 =
        (const uint64_t *) ((const uint8_t *) g->host_base + (l3_ipa - base));
    unsigned l3_idx = (unsigned) ((va / CR_PAGE_SIZE) % 512);
    uint64_t l3_entry = l3[l3_idx];
    if (!(l3_entry & CR_PT_VALID)) {
        fprintf(stderr, " L3[%u]=0x%llx INVALID\n", l3_idx,
                (unsigned long long) l3_entry);
        return false;
    }

    uint64_t page_ipa = l3_entry & CR_PT_ADDR_MASK;
    uint64_t translated_ipa = page_ipa + (va & (CR_PAGE_SIZE - 1));
    fprintf(stderr, " L3[%u]=0x%llx -> IPA 0x%llx\n", l3_idx,
            (unsigned long long) l3_entry, (unsigned long long) translated_ipa);
    if (ipa_out)
        *ipa_out = translated_ipa;
    return true;
}

/* Print the HVF stage-2 backing range covering the supplied IPA plus the
 * region-tracker entry whose VA range includes the same address. A missing
 * stage-2 backing is the downstream analogue of an INVALID L3 entry above; a
 * missing region tracker is normal for non-tracked ranges (vDSO, shim) but
 * useful for "is this VA in a known ELF segment" reasoning.
 */
static void dump_segment_and_region_for(const guest_t *g,
                                        uint64_t va,
                                        bool have_ipa,
                                        uint64_t ipa)
{
    if (!g)
        return;

    if (have_ipa) {
        bool found_seg = ipa < g->guest_size;
        if (found_seg)
            fprintf(stderr, "  HVF primary backing: ipa=0x%llx size=0x%llx\n",
                    (unsigned long long) GUEST_IPA_BASE,
                    (unsigned long long) g->guest_size);
        if (!found_seg) {
            const guest_mapping_t *m = guest_find_mapping(g, ipa);
            if (m) {
                fprintf(stderr,
                        "  HVF mapping: gpa=0x%llx size=0x%zx "
                        "(covers translated IPA 0x%llx)\n",
                        (unsigned long long) m->gpa, m->size,
                        (unsigned long long) ipa);
                found_seg = true;
            }
        }
        if (!found_seg) {
            const guest_overflow_t *o = guest_find_overflow(g, ipa);
            if (o) {
                fprintf(stderr,
                        "  HVF overflow: ipa=0x%llx size=0x%llx "
                        "(covers translated IPA 0x%llx)\n",
                        (unsigned long long) o->ipa_start,
                        (unsigned long long) o->size, (unsigned long long) ipa);
                found_seg = true;
            }
        }
        if (!found_seg)
            fprintf(stderr,
                    "  HVF backing: NONE (stage-2 hole for IPA 0x%llx)\n",
                    (unsigned long long) ipa);
    } else {
        fprintf(stderr,
                "  HVF backing: not checked (no valid stage-1 translation)\n");
    }

    const guest_region_t *r = guest_region_find(g, va);
    if (r) {
        fprintf(stderr, "  region: [0x%llx, 0x%llx) prot=%c%c%c name=\"%s\"\n",
                (unsigned long long) r->start, (unsigned long long) r->end,
                (r->prot & 1) ? 'r' : '-', (r->prot & 2) ? 'w' : '-',
                (r->prot & 4) ? 'x' : '-', r->name[0] ? r->name : "(unnamed)");
    } else {
        fprintf(stderr, "  region: NONE\n");
    }
}

static void dump_translation_diagnostics_for(const guest_t *g,
                                             const char *label,
                                             uint64_t va)
{
    fprintf(stderr, "## Translation diagnostics (%s=0x%llx)\n", label,
            (unsigned long long) va);
    uint64_t ipa = 0;
    bool have_ipa = dump_pt_walk_for_va(g, va, &ipa);
    dump_segment_and_region_for(g, va, have_ipa, ipa);
    fprintf(stderr, "\n");
}

void crash_report(hv_vcpu_t vcpu,
                  const guest_t *g,
                  crash_type_t type,
                  const char *detail)
{
    fprintf(stderr,
            "\n╔══════════════════════════════════════════════════════════╗\n"
            "║                   elfuse crash report                    ║\n"
            "╚══════════════════════════════════════════════════════════╝\n\n");

    char os_version[64] = {0}, os_release[64] = {0};
    char hw_model[128] = {0};

    sysctl_str("kern.osproductversion", os_version, sizeof(os_version));
    sysctl_str("kern.osrelease", os_release, sizeof(os_release));

    /* machdep.cpu.brand_string is absent on Apple Silicon. Fall back to
     * hw.model so the report still names the host hardware.
     */
    if (sysctl_str("machdep.cpu.brand_string", hw_model, sizeof(hw_model)) != 0)
        sysctl_str("hw.model", hw_model, sizeof(hw_model));

    fprintf(stderr, "## Environment\n");
    fprintf(stderr, "- elfuse version: %s\n", ELFUSE_VERSION);
    fprintf(stderr, "- macOS: %s (Darwin %s)\n",
            os_version[0] ? os_version : "?", os_release[0] ? os_release : "?");
    fprintf(stderr, "- hardware: %s\n\n",
            hw_model[0] ? hw_model : "Apple Silicon");

    fprintf(stderr, "## Crash\n");
    fprintf(stderr, "- type: %s\n", crash_type_name(type));
    if (detail && detail[0])
        fprintf(stderr, "- detail: %s\n", detail);
    fprintf(stderr, "\n");

    const char *elf_path = proc_get_elf_path();
    size_t cmdline_len = 0;
    const char *cmdline = proc_get_cmdline(&cmdline_len);
    const char *sysroot = proc_get_sysroot();

    fprintf(stderr, "## Binary\n");
    fprintf(stderr, "- path: %s\n", elf_path ? elf_path : "(unknown)");
    if (sysroot)
        fprintf(stderr, "- sysroot: %s\n", sysroot);

    /* proc_get_cmdline() stores the guest argv vector as a NUL-separated blob.
     * Re-expand it into shell-like spacing for the human report.
     */
    if (cmdline && cmdline_len > 0) {
        fprintf(stderr, "- cmdline:");
        size_t pos = 0;
        while (pos < cmdline_len) {
            fprintf(stderr, " %s", cmdline + pos);
            pos += strlen(cmdline + pos) + 1;
        }
        fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");

    if (vcpu) {
        uint64_t pc = 0, cpsr = 0;
        hv_vcpu_get_reg(vcpu, HV_REG_PC, &pc);
        hv_vcpu_get_reg(vcpu, HV_REG_CPSR, &cpsr);

        uint64_t esr = 0, far_reg = 0, elr = 0, spsr = 0, sctlr = 0, sp_el0 = 0,
                 tpidr = 0;
        hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ESR_EL1, &esr);
        hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_FAR_EL1, &far_reg);
        hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ELR_EL1, &elr);
        hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_SPSR_EL1, &spsr);
        hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_SCTLR_EL1, &sctlr);
        hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_SP_EL0, &sp_el0);
        hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_TPIDR_EL0, &tpidr);

        /* The Rosetta breadcrumb has its own section header so downstream
         * parsers can keep treating "## Registers" as the first line of the
         * register section. Emitting the banner inline above that header used
         * to break that assumption.
         */
        if ((g && g->is_rosetta) || proc_rosetta_active()) {
            fprintf(stderr, "## Rosetta\n");
            fprintf(stderr,
                    "via Apple Rosetta: aarch64 PC=0x%016llx "
                    "ELR=0x%016llx TPIDR_EL0=0x%016llx\n\n",
                    (unsigned long long) pc, (unsigned long long) elr,
                    (unsigned long long) tpidr);
        }

        fprintf(stderr, "## Registers\n");
        fprintf(stderr, "PC   = 0x%016llx  CPSR = 0x%016llx\n",
                (unsigned long long) pc, (unsigned long long) cpsr);

        fprintf(stderr, "ESR  = 0x%016llx  EC=0x%02x (%s)\n",
                (unsigned long long) esr, (unsigned) ((esr >> 26) & 0x3f),
                esr_ec_name(esr));
        fprintf(stderr, "FAR  = 0x%016llx  ELR  = 0x%016llx\n",
                (unsigned long long) far_reg, (unsigned long long) elr);
        fprintf(stderr, "SPSR = 0x%016llx  SCTLR= 0x%016llx\n",
                (unsigned long long) spsr, (unsigned long long) sctlr);
        fprintf(stderr, "SP0  = 0x%016llx  TPIDR= 0x%016llx\n",
                (unsigned long long) sp_el0, (unsigned long long) tpidr);
        fprintf(stderr, "\n");

        /* Keep four registers per line so the report stays readable in issue
         * trackers and terminal captures.
         */
        for (int i = 0; i <= 30; i++) {
            uint64_t val = 0;
            hv_vcpu_get_reg(vcpu, (hv_reg_t) (HV_REG_X0 + i), &val);
            fprintf(stderr, "X%-2d  = 0x%016llx", i, (unsigned long long) val);
            if ((i % 4) == 3 || i == 30)
                fprintf(stderr, "\n");
            else
                fprintf(stderr, "  ");
        }
        fprintf(stderr, "\n");
    }

    if (g) {
        fprintf(stderr, "## Memory layout\n");
        fprintf(stderr, "guest_size  = 0x%llx (%llu MB, %u-bit IPA)\n",
                (unsigned long long) g->guest_size,
                (unsigned long long) (g->guest_size >> 20), g->ipa_bits);
        fprintf(stderr, "brk         = 0x%llx .. 0x%llx\n",
                (unsigned long long) g->brk_base,
                (unsigned long long) g->brk_current);
        fprintf(stderr, "mmap RW     = 0x%llx .. 0x%llx (next 0x%llx)\n",
                (unsigned long long) MMAP_BASE,
                (unsigned long long) g->mmap_end,
                (unsigned long long) g->mmap_next);
        fprintf(stderr, "mmap RX     = 0x%llx .. 0x%llx (next 0x%llx)\n",
                (unsigned long long) MMAP_RX_BASE,
                (unsigned long long) g->mmap_rx_end,
                (unsigned long long) g->mmap_rx_next);
        fprintf(stderr, "interp_base = 0x%llx  mmap_limit = 0x%llx\n",
                (unsigned long long) g->interp_base,
                (unsigned long long) g->mmap_limit);
        fprintf(stderr, "nregions    = %d\n", g->nregions);
        fprintf(stderr, "ttbr0       = 0x%llx\n\n",
                (unsigned long long) g->ttbr0);

        /* Dump stage-1 translation and stage-2 backing for PC and FAR to
         * distinguish permission faults from missing backing.
         */
        if (vcpu) {
            uint64_t pc = 0, esr = 0, far_reg = 0;
            hv_vcpu_get_reg(vcpu, HV_REG_PC, &pc);
            hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ESR_EL1, &esr);
            hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_FAR_EL1, &far_reg);
            if (pc)
                dump_translation_diagnostics_for(g, "PC", pc);
            if (esr_is_data_abort(esr) && far_reg && far_reg != pc)
                dump_translation_diagnostics_for(g, "FAR", far_reg);
        }
    }

    fprintf(stderr,
            "## How to report\n"
            "File an issue at:\n"
            "  https://github.com/sysprog21/elfuse/issues/new\n\n"
            "Include in the issue:\n"
            "  1. The full crash report above (everything from the ╔ banner)\n"
            "  2. Full command line used to invoke elfuse\n"
            "  3. Static or dynamically linked? (file <binary> to check)\n"
            "  4. Reproducible? (always / sometimes / first-time-only)\n"
            "  5. The guest binary, if redistributable\n\n");
}
