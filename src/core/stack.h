/*
 * Linux initial stack builder
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Constructs the initial stack layout expected by the Linux ABI: argc, argv
 * pointers, envp pointers, auxiliary vector, and string data.
 */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include "core/guest.h"
#include "core/elf.h"

/* Auxiliary vector types. */
#define AT_NULL 0
#define AT_EXECFD 2
#define AT_PHDR 3
#define AT_PHENT 4
#define AT_PHNUM 5
#define AT_PAGESZ 6
#define AT_BASE 7
#define AT_ENTRY 9
#define AT_UID 11
#define AT_EUID 12
#define AT_GID 13
#define AT_EGID 14
#define AT_HWCAP 16
#define AT_CLKTCK 17
#define AT_SECURE 23
#define AT_RANDOM 25
#define AT_HWCAP2 26
#define AT_SYSINFO_EHDR 33
#define AT_EXECFN 31
#define AT_PLATFORM 15
#define AT_MINSIGSTKSZ 51
/* Linux uapi/linux/auxvec.h: glibc getauxval for rseq feature discovery. */
#define AT_RSEQ_FEATURE_SIZE 27
#define AT_RSEQ_ALIGN 28

/* Maximum number of uint64_t words needed to serialize the auxv emitted by
 * build_linux_stack(), including the AT_NULL terminator pair.
 */
#define LINUX_STACK_AUXV_WORDS_MAX 48

typedef struct {
    uint64_t words[LINUX_STACK_AUXV_WORDS_MAX];
    size_t nwords;
} linux_stack_auxv_t;

/* Build a Linux-compatible initial stack at the given stack_top. Passes
 * argc/argv and envp (NULL-terminated array of "KEY=val" strings).
 * elf_load_base is the base address PIE executables were loaded at (0 for
 * ET_EXEC). interp_base is the load base of the dynamic linker (0 if statically
 * linked). vdso_base is the guest address of the vDSO ELF image (0 if no vDSO).
 * execfd is the pre-opened binary fd for binfmt_misc (AT_EXECFD); -1 if none.
 * execfn is the guest path handed to execve, reported as AT_EXECFN. Linux takes
 * that string from the execve filename rather than from argv[0], and the two
 * differ whenever the caller passed an alternate argv[0] or the kernel
 * prepended a binfmt_misc interpreter, so callers pass it explicitly instead of
 * leaving it to be inferred from argv's shape. NULL falls back to argv[0]. If
 * auxv_out is non-NULL, it receives the exact auxv words written to guest
 * memory, in the same order exposed by /proc/self/auxv.
 * Returns the initial SP (stack pointer) to pass to the guest.
 */
uint64_t build_linux_stack(guest_t *g,
                           uint64_t stack_top,
                           int argc,
                           const char **argv,
                           const char **envp,
                           const elf_info_t *elf_info,
                           uint64_t elf_load_base,
                           uint64_t interp_base,
                           uint64_t vdso_base,
                           int execfd,
                           const char *execfn,
                           linux_stack_auxv_t *auxv_out);
