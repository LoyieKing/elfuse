/*
 * Guest memory syscall interface
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Declarations for brk, mmap, munmap, mprotect, mremap, madvise, msync. All
 * sys_xxx functions assume mmap_lock is held by the caller, except sys_msync,
 * which is dispatched unlocked (SC_FORWARD, not SC_LOCKED) and manages
 * mmap_lock itself so it can defer fsync(2) until after releasing it.
 */

#pragma once

#include <stdint.h>
#include "core/guest.h"

typedef struct mmap_fork_anon_shared_txn mmap_fork_anon_shared_txn_t;
struct thread_entry;

/* Reset private GPA backing to zero. Lazy mode releases whole host pages; eager
 * mode zeroes in place. Caller holds mmap_lock and removes file overlays before
 * calling.
 *
 * Returns 0 or a negative Linux errno.
 */
int guest_memory_reset_range(guest_t *g, uint64_t gpa, uint64_t len);

/* Query physical backing residency, one byte per guest page. Caller holds
 * mmap_lock.
 *
 * Returns 0 or a negative Linux errno.
 */
int guest_memory_residency(const guest_t *g,
                           uint64_t gpa,
                           uint64_t len,
                           unsigned char *vec);

/* Count resident guest pages without producing a per-page vector. Page-aligned
 * range; caller holds mmap_lock.
 *
 * Returns 0 or a negative Linux errno.
 */
int guest_memory_resident_pages(const guest_t *g,
                                uint64_t gpa,
                                uint64_t len,
                                uint64_t *pages_out);

/* Record the host task's current resident bytes as the amount GUEST_RSS_APPROX
 * subtracts, so later readings describe guest pages rather than the whole
 * elfuse process. Called once during bring-up, before the guest maps its own
 * memory: taking it later would count guest pages as part of the baseline and
 * drive the reported value toward zero. Without a successful call the
 * approximate mode reports no resident pages rather than a fabricated figure.
 */
void guest_memory_rss_baseline_capture(void);

/* Count resident guest pages over every process VMA, coalescing only contiguous
 * backing. Also returns that VMA byte size. Caller holds mmap_lock.
 *
 * Returns 0 or a negative Linux errno.
 */
int guest_memory_mapped_resident_pages(const guest_t *g,
                                       uint64_t *vsize_out,
                                       uint64_t *pages_out);

/* One live piece of the primary slab inside a packed fork snapshot. gpa is the
 * offset from the parent's host_base; packed_off is where that piece sits in
 * the single Mach copy entry.
 */
#define GUEST_SNAPSHOT_MAX_SPANS 4096u
typedef struct {
    uint64_t gpa;
    uint64_t len;
    uint64_t packed_off;
    uint32_t shared;
} guest_snapshot_span_t;

/* Pack private fork bytes, or share live EL0 storage for CLONE_VM|CLONE_VFORK.
 * Infrastructure remains private. Caller holds mmap_lock and has quiesced
 * siblings. Owns the send right in *entry_out. spans_out holds *nspans_out
 * records, at most GUEST_SNAPSHOT_MAX_SPANS.
 *
 * Returns 0 or a negative Linux errno.
 */
int guest_memory_snapshot_entry(const guest_t *g,
                                bool share_vm,
                                uint32_t *entry_out,
                                guest_snapshot_span_t *spans_out,
                                uint32_t *nspans_out);

/* Build the fork child's slab: a zero reservation of @size, with each span of
 * the packed entry remapped at its gpa. Consumes the send right.
 *
 * Returns the mapping, or NULL on failure.
 */
void *guest_memory_map_snapshot(uint32_t entry,
                                uint64_t size,
                                const guest_snapshot_span_t *spans,
                                uint32_t nspans);

/* Successful vfork exec takes private backing before notifying the parent.
 * Caller holds mmap_lock and has stopped all child siblings.
 */
int guest_memory_detach_vfork(guest_t *g);

/* Remove private file EOF translations after fork restore or mprotect regrant.
 * Caller holds mmap_lock.
 *
 * Returns 0 or a negative Linux errno.
 */
int mmap_fork_invalidate_private_eof(guest_t *g, uint64_t start, uint64_t end);

/* brk: set/query program break */
int64_t sys_brk(guest_t *g, uint64_t addr);

/* mmap: map pages into guest address space */
int64_t sys_mmap(guest_t *g,
                 uint64_t addr,
                 uint64_t length,
                 int prot,
                 int flags,
                 int fd,
                 int64_t offset);

/* munmap: unmap pages from guest address space */
int64_t sys_munmap(guest_t *g, uint64_t addr, uint64_t length);

/* mprotect: change page permissions */
int64_t sys_mprotect(guest_t *g, uint64_t addr, uint64_t length, int prot);

/* mremap: remap/resize a mapping */
int64_t sys_mremap(guest_t *g,
                   uint64_t old_addr,
                   uint64_t old_size,
                   uint64_t new_size,
                   int flags,
                   uint64_t new_addr);

/* madvise: advise about memory usage */
int64_t sys_madvise(guest_t *g, uint64_t addr, uint64_t length, int advice);

/* msync: synchronize file-backed mappings to disk */
int64_t sys_msync(guest_t *g, uint64_t addr, uint64_t length, int flags);

/* Apply deferred guest-stack munmap work for an exiting thread. */
void mem_cleanup_deferred_stack_unmaps(guest_t *g, struct thread_entry *t);

/* Fork preparation: convert MAP_SHARED|MAP_ANONYMOUS regions that have no
 * backing fd into memfd-backed overlay regions. Each converted region gets a
 * private mkstemp+unlink temp file seeded from the current host bytes; a host
 * MAP_SHARED|MAP_FIXED overlay is then installed so the parent's subsequent
 * writes flow through the kernel page cache. The region's backing_fd is set to
 * a dup of the temp file so the regular SCM_RIGHTS handover feeds the child a
 * coherent fd.
 *
 * Caller must already hold sibling vCPUs quiesced and must hold mmap_lock, so
 * the fork that follows reads the same region table this converted. Per-region
 * failures are logged and skipped (snapshot fallback persists for those
 * regions); structural failure returns -errno. Regions whose start address is
 * not host-page-aligned are skipped (overlay-eligibility requirement). On
 * success, *txn_out owns rollback metadata that must later be committed or
 * aborted.
 */
int mmap_fork_prepare_anon_shared_locked(guest_t *g,
                                         mmap_fork_anon_shared_txn_t **txn_out);

/* Finalize or roll back mmap_fork_prepare_anon_shared_locked(). Callers must
 * still have sibling vCPUs quiesced when aborting so the host overlay removal
 * cannot race guest accesses. Abort takes mmap_lock itself, so the caller
 * releases it first.
 */
void mmap_fork_commit_anon_shared(mmap_fork_anon_shared_txn_t **txn_ptr);
int mmap_fork_abort_anon_shared(guest_t *g,
                                mmap_fork_anon_shared_txn_t **txn_ptr);

/* Fork restore: re-install host MAP_SHARED|MAP_FIXED overlays on the child
 * after IPC restore. parent_active[i] / parent_ovl_start[i] / parent_ovl_end[i]
 * capture each region's parent-side overlay metadata, sampled before
 * fork_ipc_recv_process_state cleared the inherited overlay flags. For each
 * region that was overlay-active in the parent and now has a valid backing_fd
 * (received via SCM_RIGHTS), the function calls hv_vm_unmap + mmap
 * MAP_FIXED|MAP_SHARED + hv_vm_map to bind the host VA to the same backing file
 * so the child observes parent writes (and vice-versa). Caller must hold no
 * locks; the child has not yet created worker vCPUs so no quiesce is needed.
 *
 * Per-region failures are logged and skipped.
 *
 * Returns 0 on full success or the last error encountered (best-effort: a
 * partial failure leaves snapshot semantics intact for the failed regions).
 */
int mmap_fork_restore_overlays(guest_t *g,
                               const bool *parent_active,
                               const uint64_t *parent_ovl_start,
                               const uint64_t *parent_ovl_end);

/* Undo every live MAP_SHARED host overlay before execve resets the address
 * space. guest_reset zeroes each tracked region by writing through its host VA,
 * and an overlay still installed there is the backing file's own page cache, so
 * those zeroes reach the file: a guest that mmaps a file MAP_SHARED and execs
 * truncates its contents to zero on the host. Removing the overlay first
 * restores plain slab backing, which is also what the new image needs, since an
 * overlay left in place would hand it a host file at that VA.
 *
 * Caller holds mmap_lock.
 *
 * Returns 0, or -errno with the overlays that could not be torn down still
 * marked active; the caller must not reset guest memory after a failure.
 */
int mmap_exec_drop_overlays(guest_t *g);
