#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/prctl.h>

#include "types.h"
#include "cr_options.h"
#include "servicefd.h"
#include "mem.h"
#include "parasite-syscall.h"
#include "parasite.h"
#include "page-pipe.h"
#include "page-xfer.h"
#include "log.h"
#include "kerndat.h"
#include "stats.h"
#include "vma.h"
#include "shmem.h"
#include "uffd.h"
#include "pstree.h"
#include "restorer.h"
#include "rst-malloc.h"
#include "rst-fmalloc.h"
#include "bitmap.h"
#include "sk-packet.h"
#include "files-reg.h"
#include "pagemap-cache.h"
#include "fault-injection.h"
#include "prctl.h"
#include "compel/infect-util.h"
#include "pidfd-store.h"

#include "protobuf.h"
#include "images/pagemap.pb-c.h"

#include "infect-priv.h"

static bool prst_vmas_updated = true;

static int task_reset_dirty_track(int pid)
{
	int ret;

	if (!opts.track_mem)
		return 0;

	BUG_ON(!kdat.has_dirty_track);

	ret = do_task_reset_dirty_track(pid);
	BUG_ON(ret == 1);
	return ret;
}

int do_task_reset_dirty_track(int pid)
{
	int fd, ret;
	char cmd[] = "4";

	pr_info("Reset %d's dirty tracking\n", pid);

	fd = __open_proc(pid, EACCES, O_RDWR, "clear_refs");
	if (fd < 0)
		return errno == EACCES ? 1 : -1;

	ret = write(fd, cmd, sizeof(cmd));
	if (ret < 0) {
		if (errno == EINVAL) /* No clear-soft-dirty in kernel */
			ret = 1;
		else {
			pr_perror("Can't reset %d's dirty memory tracker", pid);
			ret = -1;
		}
	} else {
		pr_info(" ... done\n");
		ret = 0;
	}

	close(fd);
	return ret;
}

unsigned long dump_pages_args_size(struct vm_area_list *vmas)
{
	/* In the worst case I need one iovec for each page */
	return sizeof(struct parasite_dump_pages_args) + vmas->nr * sizeof(struct parasite_vma_entry) +
	       (vmas->nr_priv_pages + 1) * sizeof(struct iovec);
}

static inline bool __page_is_zero(u64 pme)
{
	return (pme & PME_PFRAME_MASK) == kdat.zero_page_pfn;
}

static inline bool __page_in_parent(bool dirty)
{
	/*
	 * If we do memory tracking, but w/o parent images,
	 * then we have to dump all memory
	 */

	return opts.track_mem && opts.img_parent && !dirty;
}

bool should_dump_page(VmaEntry *vmae, u64 pme)
{
	/*
	 * vDSO area must be always dumped because on restore
	 * we might need to generate a proxy.
	 */
	if (vma_entry_is(vmae, VMA_AREA_VDSO))
		return true;
	/*
	 * In turn VVAR area is special and referenced from
	 * vDSO area by IP addressing (at least on x86) thus
	 * never ever dump its content but always use one provided
	 * by the kernel on restore, ie runtime VVAR area must
	 * be remapped into proper place..
	 */
	if (vma_entry_is(vmae, VMA_AREA_VVAR))
		return false;

	/*
	 * Optimisation for private mapping pages, that haven't
	 * yet being COW-ed
	 */
	if (vma_entry_is(vmae, VMA_FILE_PRIVATE) && (pme & PME_FILE))
		return false;
	if (vma_entry_is(vmae, VMA_AREA_AIORING))
		return true;
	if ((pme & (PME_PRESENT | PME_SWAP)) && !__page_is_zero(pme))
		return true;

	return false;
}

bool page_is_zero(u64 pme)
{
	return __page_is_zero(pme);
}

bool page_in_parent(bool dirty)
{
	return __page_in_parent(dirty);
}

static bool is_stack(struct pstree_item *item, unsigned long vaddr)
{
	int i;

	for (i = 0; i < item->nr_threads; i++) {
		uint64_t sp = dmpi(item)->thread_sp[i];

		if (!((sp ^ vaddr) & ~PAGE_MASK))
			return true;
	}

	return false;
}

/*
 * This routine finds out what memory regions to grab from the
 * dumpee. The iovs generated are then fed into vmsplice to
 * put the memory into the page-pipe's pipe.
 *
 * "Holes" in page-pipe are regions, that should be dumped, but
 * the memory contents is present in the pagent image set.
 */

static int generate_iovs(struct pstree_item *item, struct vma_area *vma, struct page_pipe *pp, u64 *map, u64 *off,
			 bool has_parent)
{
	u64 *at = &map[PAGE_PFN(*off)];
	unsigned long pfn, nr_to_scan;
	unsigned long pages[3] = {};
	int ret = 0;

	nr_to_scan = (vma_area_len(vma) - *off) / PAGE_SIZE;

	for (pfn = 0; pfn < nr_to_scan; pfn++) {
		unsigned long vaddr;
		unsigned int ppb_flags = 0;
		int st;

		if (!should_dump_page(vma->e, at[pfn]))
			continue;

		vaddr = vma->e->start + *off + pfn * PAGE_SIZE;

		if (vma_entry_can_be_lazy(vma->e) && !is_stack(item, vaddr))
			ppb_flags |= PPB_LAZY;

		/*
		 * If we're doing incremental dump (parent images
		 * specified) and page is not soft-dirty -- we dump
		 * hole and expect the parent images to contain this
		 * page. The latter would be checked in page-xfer.
		 */

		if (has_parent && page_in_parent(at[pfn] & PME_SOFT_DIRTY)) {
			ret = page_pipe_add_hole(pp, vaddr, PP_HOLE_PARENT);
			st = 0;
		} else {
			ret = page_pipe_add_page(pp, vaddr, ppb_flags);
			if (ppb_flags & PPB_LAZY && opts.lazy_pages)
				st = 1;
			else
				st = 2;
		}

		if (ret) {
			/* Do not do pfn++, just bail out */
			pr_debug("Pagemap full\n");
			break;
		}

		pages[st]++;
	}

	*off += pfn * PAGE_SIZE;

	cnt_add(CNT_PAGES_SCANNED, nr_to_scan);
	cnt_add(CNT_PAGES_SKIPPED_PARENT, pages[0]);
	cnt_add(CNT_PAGES_LAZY, pages[1]);
	cnt_add(CNT_PAGES_WRITTEN, pages[2]);

	pr_info("Pagemap generated: %lu pages (%lu lazy) %lu holes\n", pages[2] + pages[1], pages[1], pages[0]);
	return ret;
}

static struct parasite_dump_pages_args *
prep_dump_pages_args(struct parasite_ctl *ctl, struct vm_area_list *vma_area_list, bool skip_non_trackable)
{
	struct parasite_dump_pages_args *args;
	struct parasite_vma_entry *p_vma;
	struct vma_area *vma;

	args = compel_parasite_args_s (ctl, PARASITE_DUMP_PAGES_ARGS_REGION);

	p_vma = pargs_vmas(args);
	args->nr_vmas = 0;

	list_for_each_entry(vma, &vma_area_list->h, list) {
		if (!vma_area_is_private(vma, kdat.task_size))
			continue;
		/*
		 * Kernel write to aio ring is not soft-dirty tracked,
		 * so we ignore them at pre-dump.
		 */
		if (vma_entry_is(vma->e, VMA_AREA_AIORING) && skip_non_trackable)
			continue;
		if (vma->e->prot & PROT_READ)
			continue;

		p_vma->start = vma->e->start;
		p_vma->len = vma_area_len(vma);
		p_vma->prot = vma->e->prot;

		args->nr_vmas++;
		p_vma++;
	}

	return args;
}

static int drain_pages(struct page_pipe *pp, struct parasite_ctl *ctl, struct parasite_dump_pages_args *args)
{
	struct page_pipe_buf *ppb;
	int ret = 0;

	debug_show_page_pipe(pp);

	/* Step 2 -- grab pages into page-pipe */
	list_for_each_entry(ppb, &pp->bufs, l) {
		args->nr_segs = ppb->nr_segs;
		args->nr_pages = ppb->pages_in;
		pr_debug("PPB: %d pages %d segs %u pipe %d off\n", args->nr_pages, args->nr_segs, ppb->pipe_size,
			 args->off);

		ret = compel_rpc_call(PARASITE_CMD_DUMPPAGES, ctl);
		if (ret < 0)
			return -1;
		ret = compel_util_send_fd(ctl, ppb->p[1]);
		if (ret)
			return -1;

		ret = compel_rpc_sync(PARASITE_CMD_DUMPPAGES, ctl);
		if (ret < 0)
			return -1;

		args->off += args->nr_segs;
	}

	return 0;
}

static int xfer_pages(struct page_pipe *pp, struct page_xfer *xfer)
{
	int ret;

	/*
	 * Step 3 -- write pages into image (or delay writing for
	 *           pre-dump action (see pre_dump_one_task)
	 */
	timing_start(TIME_MEMWRITE);
	ret = page_xfer_dump_pages(xfer, pp);
	timing_stop(TIME_MEMWRITE);

	return ret;
}

static int detect_pid_reuse(struct pstree_item *item, struct proc_pid_stat *pps, InventoryEntry *parent_ie)
{
	unsigned long long dump_ticks;
	struct proc_pid_stat pps_buf;
	unsigned long long tps; /* ticks per second */
	int ret;

	/* Check pid reuse using pidfds */
	if (pidfd_store_ready())
		return pidfd_store_check_pid_reuse(item->pid->real);

	if (!parent_ie) {
		pr_err("Pid-reuse detection failed: no parent inventory, "
		       "check warnings in get_parent_inventory\n");
		return -1;
	}

	tps = sysconf(_SC_CLK_TCK);
	if (tps == -1) {
		pr_perror("Failed to get clock ticks via sysconf");
		return -1;
	}

	if (!pps) {
		pps = &pps_buf;
		ret = parse_pid_stat(item->pid->real, pps);
		if (ret < 0)
			return -1;
	}

	dump_ticks = parent_ie->dump_uptime / (USEC_PER_SEC / tps);

	if (pps->start_time >= dump_ticks) {
		/* Print "*" if unsure */
		pr_warn("Pid reuse%s detected for pid %d\n", pps->start_time == dump_ticks ? "*" : "", item->pid->real);
		return 1;
	}
	return 0;
}

static int generate_vma_iovs(struct pstree_item *item, struct vma_area *vma, struct page_pipe *pp,
			     struct page_xfer *xfer, struct parasite_dump_pages_args *args, struct parasite_ctl *ctl,
			     pmc_t *pmc, bool has_parent, bool pre_dump, int parent_predump_mode)
{
	u64 off = 0;
	u64 *map;
	int ret;

	if (!vma_area_is_private(vma, kdat.task_size) && !vma_area_is(vma, VMA_ANON_SHARED))
		return 0;

	/*
	 * To facilitate any combination of pre-dump modes to run after
	 * one another, we need to take extra care as discussed below.
	 *
	 * The SPLICE mode pre-dump, processes all type of memory regions,
	 * whereas READ mode pre-dump skips processing those memory regions
	 * which lacks PROT_READ flag.
	 *
	 * Now on mixing pre-dump modes:
	 * 	If SPLICE mode follows SPLICE mode	: no issue
	 *		-> everything dumped both the times
	 *
	 * 	If READ mode follows READ mode		: no issue
	 *		-> non-PROT_READ skipped both the time
	 *
	 * 	If READ mode follows SPLICE mode   	: no issue
	 *		-> everything dumped at first,
	 *		   the non-PROT_READ skipped later
	 *
	 * 	If SPLICE mode follows READ mode   	: Need special care
	 *
	 * If READ pre-dump happens first, then it has skipped processing
	 * non-PROT_READ regions. Following SPLICE pre-dump expects pagemap
	 * entries for all mappings in parent pagemap, but last READ mode
	 * pre-dump cycle has skipped processing & pagemap generation for
	 * non-PROT_READ regions. So SPLICE mode throws error of missing
	 * pagemap entry for encountered non-PROT_READ mapping.
	 *
	 * To resolve this, the pre-dump-mode is stored in current pre-dump's
	 * inventoy file. This pre-dump mode is read back from this file
	 * (present in parent pre-dump dir) as parent-pre-dump-mode during
	 * next pre-dump.
	 *
	 * If parent-pre-dump-mode and next-pre-dump-mode are in READ-mode ->
	 * SPLICE-mode order, then SPLICE mode doesn't expect mappings for
	 * non-PROT_READ regions in parent-image and marks "has_parent=false".
	 */

	if (!(vma->e->prot & PROT_READ)) {
		if (opts.pre_dump_mode == PRE_DUMP_READ && pre_dump)
			return 0;
		if ((parent_predump_mode == PRE_DUMP_READ && opts.pre_dump_mode == PRE_DUMP_SPLICE) || !pre_dump)
			has_parent = false;
	}

	if (vma_entry_is(vma->e, VMA_AREA_AIORING)) {
		if (pre_dump && !dump_aio_ring_flag)
			return 0;
		has_parent = false;
	}

	map = pmc_get_map(pmc, vma);
	if (!map)
		return -1;

	if (vma_area_is(vma, VMA_ANON_SHARED))
		return add_shmem_area(item->pid->real, vma->e, map);

again:
	ret = generate_iovs(item, vma, pp, map, &off, has_parent);
	if (ret == -EAGAIN) {
		BUG_ON(!(pp->flags & PP_CHUNK_MODE));

		ret = drain_pages(pp, ctl, args);
		if (!ret)
			ret = xfer_pages(pp, xfer);
		if (!ret) {
			page_pipe_reinit(pp);
			goto again;
		}
	}

	return ret;
}

static int __parasite_dump_pages_seized(struct pstree_item *item, struct parasite_dump_pages_args *args,
					struct vm_area_list *vma_area_list, struct mem_dump_ctl *mdc,
					struct parasite_ctl *ctl)
{
	pmc_t pmc = PMC_INIT;
	struct page_pipe *pp;
	struct vma_area *vma_area;
	struct page_xfer xfer = { .parent = NULL };
	int ret, exit_code = -1;
	unsigned cpp_flags = 0;
	unsigned long pmc_size;
	int possible_pid_reuse = 0;
	bool has_parent;
	int parent_predump_mode = -1;

	pr_info("\n");
	pr_info("Dumping pages (type: %d pid: %d)\n", CR_FD_PAGES, item->pid->real);
	pr_info("----------------------------------------\n");

	timing_start(TIME_MEMDUMP);

	pr_debug("   Private vmas %lu/%lu pages\n", vma_area_list->nr_priv_pages_longest, vma_area_list->nr_priv_pages);

	/*
	 * Step 0 -- prepare
	 */

	pmc_size = max(vma_area_list->nr_priv_pages_longest, vma_area_list->nr_shared_pages_longest);
	if (pmc_init(&pmc, item->pid->real, &vma_area_list->h, pmc_size * PAGE_SIZE))
		return -1;

	if (!(mdc->pre_dump || mdc->lazy))
		/*
		 * Chunk mode pushes pages portion by portion. This mode
		 * only works when we don't need to keep pp for later
		 * use, i.e. on non-lazy non-predump.
		 */
		cpp_flags |= PP_CHUNK_MODE;
	pp = create_page_pipe(vma_area_list->nr_priv_pages, mdc->lazy ? NULL : pargs_iovs(args), cpp_flags);
	if (!pp)
		goto out;

	if (!mdc->pre_dump) {

        // Shiv:
        // Indicate xfer-server that you want to send pages and pagemap.
        ret = init_page_transfer_xfer_server();
        if (ret < 0)
            goto out_pp;

		/*
		 * Regular dump -- create xfer object and send pages to it
		 * right here. For pre-dumps the pp will be taken by the
		 * caller and handled later.
		 */
		ret = open_page_xfer(&xfer, CR_FD_PAGEMAP, vpid(item));
		if (ret < 0)
			goto out_pp;

		xfer.transfer_lazy = !mdc->lazy;
	} else {
		ret = check_parent_page_xfer(CR_FD_PAGEMAP, vpid(item));
		if (ret < 0)
			goto out_pp;

		if (ret)
			xfer.parent = NULL + 1;
	}

	if (xfer.parent) {
		possible_pid_reuse = detect_pid_reuse(item, mdc->stat, mdc->parent_ie);
		if (possible_pid_reuse == -1)
			goto out_xfer;
	}

	/*
	 * Step 1 -- generate the pagemap
	 */
	args->off = 0;
	has_parent = !!xfer.parent && !possible_pid_reuse;
	if (mdc->parent_ie)
		parent_predump_mode = mdc->parent_ie->pre_dump_mode;

	list_for_each_entry(vma_area, &vma_area_list->h, list) {
		ret = generate_vma_iovs(item, vma_area, pp, &xfer, args, ctl, &pmc, has_parent, mdc->pre_dump,
					parent_predump_mode);
		if (ret < 0)
			goto out_xfer;
	}

	if (mdc->lazy)
		memcpy(pargs_iovs(args), pp->iovs, sizeof(struct iovec) * pp->nr_iovs);

	/*
	 * Faking drain_pages for pre-dump here. Actual drain_pages for pre-dump
	 * will happen after task unfreezing in cr_pre_dump_finish(). This is
	 * actual optimization which reduces time for which process was frozen
	 * during pre-dump.
	 */
	if (mdc->pre_dump && opts.pre_dump_mode == PRE_DUMP_READ)
		ret = 0;
	else
		ret = drain_pages(pp, ctl, args);

	if (!ret && !mdc->pre_dump)
		ret = xfer_pages(pp, &xfer);
	if (ret)
		goto out_xfer;

	timing_stop(TIME_MEMDUMP);

	/*
	 * Step 4 -- clean up
	 */

	ret = task_reset_dirty_track(item->pid->real);
	if (ret)
		goto out_xfer;
	exit_code = 0;

out_xfer:
	if (!mdc->pre_dump)
		xfer.close(&xfer);

out_pp:
    if (ret || !(mdc->pre_dump || mdc->lazy)) {

        // Destroy page-pipe and send termination of page-transfer to
        // xfer-server.
        destroy_page_pipe(pp);
        if (send_last_page_iov_cmd_xfer() < 0)
            pr_perror("Unable to send last page-xfer command (PS_IOV_FLUSH) to xfer-server");

    } else {
		dmpi(item)->mem_pp = pp;
    }

out:
    pmc_fini(&pmc);
    pr_info("----------------------------------------\n");
    return exit_code;

}

int parasite_dump_pages_seized (struct pstree_item *item
        , struct vm_area_list *vma_area_list, struct mem_dump_ctl *mdc
        , struct parasite_ctl *ctl) {

	int ret;
	struct parasite_dump_pages_args *pargs;

	pargs = prep_dump_pages_args(ctl, vma_area_list, mdc->pre_dump);

    // Added by Shiv
    ctl->args_offset = ((unsigned long) pargs) - ((unsigned long) ctl->args);

	/*
	 * Add PROT_READ protection for all VMAs we're about to
	 * dump if they don't have one. Otherwise we'll not be
	 * able to read the memory contents.
	 *
	 * Afterwards -- reprotect memory back.
	 *
	 * This step is required for "splice" mode pre-dump and dump.
	 * Skip this step for "read" mode pre-dump.
	 * "read" mode pre-dump delegates processing of non-PROT_READ
	 * regions to dump stage. Adding PROT_READ works fine for
	 * static processing (target process frozen during pre-dump)
	 * and fails for dynamic as explained below.
	 *
	 * Consider following sequence of instances to reason, why
	 * not to add PROT_READ in "read" mode pre-dump ?
	 *
	 *	CRIU- "read" pre-dump		    Target Process
	 *
	 *					1. Creates mapping M
	 *					   without PROT_READ
	 * 2. CRIU freezes target
	 *    process
	 * 3. Collect the mappings
	 * 4. Add PROT_READ to M
	 *    (non-PROT_READ region)
	 * 5. CRIU unfreezes target
	 *    process
	 *					6. Add flag PROT_READ
	 *					   to mapping M
	 *					7. Revoke flag PROT_READ
	 *					   from mapping M
	 * 8. process_vm_readv tries
	 *    to copy mapping M
	 *    (believing M have
	 *     PROT_READ flag)
	 * 9. syscall fails to copy
	 *    data from M
	 */

	if (!mdc->pre_dump || opts.pre_dump_mode == PRE_DUMP_SPLICE) {
		pargs->add_prot = PROT_READ;
		ret = compel_rpc_call_sync(PARASITE_CMD_MPROTECT_VMAS, ctl);
		if (ret) {
			pr_err("Can't dump unprotect vmas with parasite\n");
			goto err;
		}
	}

	if (fault_injected(FI_DUMP_PAGES)) {
		pr_err("fault: Dump VMA pages failure!\n");
        ret = -1;
		goto err;
	}

	ret = __parasite_dump_pages_seized(item, pargs, vma_area_list, mdc, ctl);
	if (ret) {
		pr_err("Can't dump page with parasite\n");
		/* Parasite will unprotect VMAs after fail in fini() */
		goto err;
	}

    if (!mdc->pre_dump || opts.pre_dump_mode == PRE_DUMP_SPLICE) {
        pargs->add_prot = 0;
        ret = compel_rpc_call_sync(PARASITE_CMD_MPROTECT_VMAS, ctl);
        if (ret) {
            pr_err("Can't rollback unprotected vmas with parasite\n");
            goto err;
        }
    }

    ret = 0;

err:
    ctl->args_offset = 0;       // Added by Shiv
    return ret;

}

static inline void set_vmas_premmapped (struct list_head *vmas, int curr_iter) {

    struct vma_area *vma;

    // Skip first iteration.
    if (unlikely (list_empty(vmas) || (curr_iter == 1)))
        return;

    // Add premapped bit for this iteration if it was previously premapped and
    // remove previously premapped bit.
    list_for_each_entry (vma, vmas, list) {
        if (vma_area_is (vma, VMA_PREV_PREMMAPED)) {
            vma->e->status |= VMA_PREMMAPED;
            vma->e->status &= ~VMA_PREV_PREMMAPED;
        }
    }

}

static void reset_vmas (struct list_head *vmas, int curr_iter) {

    struct vma_area *vma;

    // Skip first iteration.
    if (unlikely (list_empty(vmas) || (curr_iter == 1)))
        return;

    list_for_each_entry (vma, vmas, list) {

        // First mark all VMAs as deleted and non-added for this iteration.
        vma->e->is_deleted = true;
        vma->e->is_added = false;

		// Also mark all vma as non-mremapped (check premap_updated_priv_vmas function).
        vma->e->is_mremapped = false;

        // Now remove and save the VMA_PREMMAPED bit for the VMAs which have it.
        if (vma_area_is (vma, VMA_PREMMAPED)) {
            vma->e->status |= VMA_PREV_PREMMAPED;
            vma->e->status &= ~VMA_PREMMAPED;
        }

    }

}

static void clean_vmas (struct pstree_item *t) {

    struct vma_area *vma, *p;
    int curr_iter = t->curr_iter;
    struct list_head *vmas = &rsti(t)->vmas.h;

    // Skip first iteration (extra safety check).
    if (unlikely (list_empty(vmas) || (curr_iter == 1)))
        return;

    list_for_each_entry_safe (vma, p, vmas, list) {

        // Skip non-deleted vmas for this iteration.
        if (!vma->e->is_deleted)
            continue;

        list_del (&vma->list);
        fshfree_last (vma);

    }

}

static int __prst_unmap_remapped_vmas (struct list_head *vmas) {

    struct vma_area *vma;
	unsigned long size;
	void *addr = NULL;
	int ret = 0;

    list_for_each_entry (vma, vmas, list) {
        if (vma->e->is_deleted && !vma->e->is_mremapped) {
			size = vma_entry_len (vma->e);
			addr = decode_pointer (vma->premmaped_addr);
            ret = munmap (addr, size);
			if (ret < 0) {
				pr_perror ("Unable to unmap old vma (%lx-%lx) at %p\n", vma->e->start, vma->e->end, addr);
				return ret;
			}
            vma->e->is_mremapped = true;
		}
    }

    return ret;

}

static inline bool __prst_is_vmas_updated (struct list_head *vmas) {

    struct vma_area *vma;

    list_for_each_entry (vma, vmas, list) {
        if (vma->e->is_deleted || vma->e->is_added)
            return true;
    }

    // No vma update, hence return false.
    return false;

}

static inline int __prst_change_protection (struct vma_area *vma, int new_prot) {
    unsigned long size = vma_entry_len(vma->e);
    if (mprotect((void *)vma->premmaped_addr, size, new_prot)) {
        pr_perror ("Failed to change vma protection in successive iteration\n");
        return -1;
    }
    return 0;
}

/**
 * XXX: Design
 *
 * With the start and end of already prepared (from prev iteration) vmas list
 * and the new vma (of the current iteration), we can form 4 pairs:
 *      1.) (Sp op Sc)
 *      2.) (Sp op Ec)
 *      3.) (Ep op Sc)
 *      4.) (Ep op Ec)
 *          where,
 *          Sp is the start of prev VMA, Ep is the end of prev VMA
 *          Sc is the start of curr VMA, Ec is the end of curr VMA
 *          and op could be anything from the set (==, >, <)
 *
 * As stated above we need to handle 12 cases for the sake of completeness.
 * It may happen that some cases may not be feasible by the OS design itself.
 *
 */
static inline bool __vma_is_present (VmaEntry *ve, struct list_head *vmas
        , struct list_head **vma_list, int curr_iter, struct vma_area **found_vma) {

    struct vma_area *vma;
    int i = 0;

    // Skip first iteration.
    if (unlikely (list_empty(vmas) || (curr_iter == 1)))
        goto skip_vma_search;

    // Search for exact match (currently with start and end only).
    //
    // TODO: Later
    //
    // Will need to update this later to check for other matching info and
    // do something if start and end is same but other info is different.
    //
    // Cases handled in this version where start and end is same in successive
    // iteration but other info differs...
    // 1.) mprotect call on same vma.
    //
    // Case: (Sp == Sc) & (Ep op Ec)
    list_for_each_entry (vma, vmas, list) {

        // Only search in the previous iteration's VMAs list.
        if (unlikely (!(vma->e->is_deleted)))
            continue;

        if (vma->e->start == ve->start) {
            if (vma->e->end == ve->end) {
                // VMA is found from the previous iteration.
                // Mark this vma as non-deleted and non-modified in this iteration.
                vma->e->is_deleted = false;
                vma->e->is_added = false;
                *vma_list = NULL;
                *found_vma = vma;
                return true;
            } else {
                // This might be the case of shrink/ expand/ new VMA. Add this
                // new VMA to the tail of current VMA.
                *vma_list = vma->list.next;
                return false;
            }
        }

    }

    // Case: (Sp > Sc)
    //
    // Exact match is not found, so check for the case of shrink or expand
    // or split or delete or others (combinations of these).
    i = 0;
    list_for_each_entry (vma, vmas, list) {
        if (vma->e->start > ve->start) {
            *vma_list = &vma->list;
            return false;
        }
        i++;
    }

skip_vma_search:
    // VMA is not found.
    *vma_list = vmas;
    return false;

}

static inline void __update_vmas_globals (struct rst_info *ri) {

    struct list_head *vmas = &ri->vmas.h;
    struct vma_area *vma;

    list_for_each_entry (vma, vmas, list) {
        if (!(vma->e->is_deleted)) {
            ri->vmas.nr++;
            if (vma_area_is_private(vma, kdat.task_size)) {
                ri->vmas.rst_priv_size += vma_area_len(vma);
                if (vma_has_guard_gap_hidden(vma))
                    ri->vmas.rst_priv_size += PAGE_SIZE;
            }
        }
    }

}

int prepare_mm_pid (struct pstree_item *i) {

	pid_t pid = vpid(i);
	int ret = -1, vn = 0;
    int curr_iter = i->curr_iter;
    bool is_last_iter = i->is_last_iter;
	struct cr_img *img;
	struct rst_info *ri = rsti(i);

	img = open_image(CR_FD_MM, O_RSTR, pid);
	if (!img)
		return -1;

	ret = pb_read_one_eof(img, &ri->mm, PB_MM, true /*XXX: Later Check*/);
	close_image(img);
	if (ret <= 0)
		return ret;

	if (collect_special_file(ri->mm->exe_file_id) == NULL)
		return -1;

	pr_debug("Found %zd VMAs in image\n", ri->mm->n_vmas);
	img = NULL;
	if (ri->mm->n_vmas == 0) {
		/*
		 * Old image. Read VMAs from vma-.img
		 */
		img = open_image(CR_FD_VMAS, O_RSTR, pid);
		if (!img)
			return -1;
	}

    // Do the reset, then process and then set.
    // Mark all vmas as deleted.
    reset_vmas (&ri->vmas.h, curr_iter);
    ri->vmas.nr = 0;
    ri->vmas.rst_priv_size = 0;

	while (vn < ri->mm->n_vmas || img != NULL) {

        struct vma_area *vma = NULL;
        struct list_head *vma_list = NULL;
        VmaEntry *ve = ri->mm->vmas[vn];

        // Check whether a vma is already present in the list from previous
        // iteration.
        //
        // TODO: Later
        //
        // 1.) Here I am skipping the reuse of same vma, i.e. vma is munmapped
        //     and then again same vma is used by some other region type.
        //
        // XXX: Shiv
        // Old image saving technique (vma-.img) is not considered here for
        // iterative parallel restore.
        if (__vma_is_present (ve, &ri->vmas.h, &vma_list, curr_iter, &vma)) {

            // XXX: Shiv
            // There can be case that this vma has updated its protection using
            // mprotect in this iteration hence check for that and update it.
            if (vma->e->prot ^ ve->prot) {
                if (__prst_change_protection (vma, ve->prot)) {
                    return -1;
                }
            }
            goto skip_vma_add;

        }

		ret = -1;
		vma = alloc_vma_area (true);
		if (!vma)
			break;

		if (!img)
			vma->e = ri->mm->vmas[vn];
		else {
			ret = pb_read_one_eof(img, &vma->e, PB_VMA, false);
			if (ret <= 0) {
				xfree(vma);
				close_image(img);
				img = NULL;
				break;
			}
		}
        vma->e->is_deleted = false;
        vma->e->is_added = true;

        if (unlikely (curr_iter == 1)) {
            list_add_tail (&vma->list, &ri->vmas.h);
        } else {
            list_add_tail (&vma->list, vma_list);
        }

		pr_info("vma 0x%" PRIx64 " 0x%" PRIx64 "\n", vma->e->start, vma->e->end);

skip_vma_add:
        // XXX:
        // Collect shmem in the last iteration only.
		if (is_last_iter && vma_area_is(vma, VMA_ANON_SHARED))
			ret = collect_shmem(pid, vma);
		else if (vma_area_is(vma, VMA_FILE_PRIVATE) || vma_area_is(vma, VMA_FILE_SHARED))
			ret = collect_filemap(vma);
		else if (vma_area_is(vma, VMA_AREA_SOCKET))
			ret = collect_socket_map(vma);
		else
			ret = 0;
		if (ret)
			break;

        vn++;

	}

    // Update vmas global variables like nr, rst_priv_size.
    __update_vmas_globals (ri);

    // And finally close the image and return.
	if (img)
		close_image(img);
    return ret;

}

static inline bool check_cow_vmas(struct vma_area *vma, struct vma_area *pvma)
{
	/*
	 * VMAs that _may_[1] have COW-ed pages should ...
	 *
	 * [1] I say "may" because whether or not particular pages are
	 * COW-ed is determined later in restore_priv_vma_content() by
	 * memcmp'aring the contents.
	 */

	/* ... coincide by start/stop pair (start is checked by caller) */
	if (vma->e->end != pvma->e->end)
		return false;
	/* ... both be private (and thus have space in premmaped area) */
	if (!vma_area_is_private(vma, kdat.task_size))
		return false;
	if (!vma_area_is_private(pvma, kdat.task_size))
		return false;
	/* ... have growsdown and anon flags coincide */
	if ((vma->e->flags ^ pvma->e->flags) & (MAP_GROWSDOWN | MAP_ANONYMOUS))
		return false;
	/* ... belong to the same file if being filemap */
	if (!(vma->e->flags & MAP_ANONYMOUS) && vma->e->shmid != pvma->e->shmid)
		return false;

	pr_debug("Found two COW VMAs @0x%" PRIx64 "-0x%" PRIx64 "\n", vma->e->start, pvma->e->end);
	return true;
}

static inline bool vma_inherited(struct vma_area *vma)
{
	return (vma->pvma != NULL && vma->pvma != VMA_COW_ROOT);
}

static void prepare_cow_vmas_for(struct vm_area_list *vmas, struct vm_area_list *pvmas)
{
	struct vma_area *vma, *pvma;

	vma = list_first_entry(&vmas->h, struct vma_area, list);
	pvma = list_first_entry(&pvmas->h, struct vma_area, list);

	while (1) {
		if ((vma->e->start == pvma->e->start) && check_cow_vmas(vma, pvma)) {
			vma->pvma = pvma;
			if (pvma->pvma == NULL)
				pvma->pvma = VMA_COW_ROOT;
		}

		/* <= here to shift from matching VMAs and ... */
		while (vma->e->start <= pvma->e->start) {
			vma = vma_next(vma);
			if (&vma->list == &vmas->h)
				return;
		}

		/* ... no == here since we must stop on matching pair */
		while (pvma->e->start < vma->e->start) {
			pvma = vma_next(pvma);
			if (&pvma->list == &pvmas->h)
				return;
		}
	}
}

void prepare_cow_vmas(void)
{
	struct pstree_item *pi;

	for_each_pstree_item(pi) {
		struct pstree_item *ppi;
		struct vm_area_list *vmas, *pvmas;

        // Skip deleted task for this iteration.
        if (pi->pid->is_deleted)
            continue;

		ppi = pi->parent;
		if (!ppi)
			continue;

		vmas = &rsti(pi)->vmas;
		if (vmas->nr == 0) /* Zombie */
			continue;

		pvmas = &rsti(ppi)->vmas;
		if (pvmas->nr == 0) /* zombies cannot have kids,
				     * but helpers can (and do) */
			continue;

		if (rsti(pi)->mm->exe_file_id != rsti(ppi)->mm->exe_file_id)
			/*
			 * Tasks running different executables have
			 * close to zero chance of having cow-ed areas
			 * and actually kernel never creates such.
			 */
			continue;

		prepare_cow_vmas_for(vmas, pvmas);
	}
}

/**
 * The function check if a given vma of current iteration overlap with the
 * existing vma(s) from the previous iteration.
 *
 * It returns:
 *      1.) True, if yes with an additional value set to:
 *          1.1) 1: If it overlaps with its previous vma(s) only.
 *          1.2) 2: If it overlaps with its next vma(s) only.
 *          1.3) 3: If it overlaps with its previous and next vma(s).
 *      2.) False, if no.
 */
static inline bool is_overlapping_vma (struct list_head *head
        , struct vma_area *curr_vma, int *status) {

    struct vma_area *prev, *next;
    int i = 0;

    *status = 0;

    // Only one vma is there. Although it can not happen practically because
    // this is not the first iteration.
    if (unlikely ((curr_vma->list.prev == head) && (curr_vma->list.next == head)))
        return false;

    if (curr_vma->list.next == head) {

        prev = vma_prev (curr_vma);
        if (curr_vma->e->start < prev->e->end)
            *status = 1;

    } else if (curr_vma->list.prev == head) {

        next = vma_next (curr_vma);
        if (curr_vma->e->end > next->e->start)
            *status = 2;

    } else {

        i = 0;
        prev = vma_prev (curr_vma);
        next = vma_next (curr_vma);
        if (curr_vma->e->start < prev->e->end) {
            *status = 1;
            i++;
        }
        if (curr_vma->e->end > next->e->start) {
            *status = 2;
            i++;
        }
        *status = (i == 2) ? 3 : *status;

    }

    if (*status > 0)
        return true;
    else
        return false;

}

static int premap_updated_private_vma (struct pstree_item *t
        , struct vma_area *vma, void **tgt_addr) {

    int flag = 0;
    void *addr = NULL;
    unsigned long size;
    unsigned long ret = 0;
    unsigned long nr_pages = vma_entry_len (vma->e) / PAGE_SIZE;
    unsigned long pg_bitmap_size = (BITS_TO_LONGS (nr_pages) * sizeof(long));

    // A grow-down VMA has a guard page, which protect a VMA below it. So, one
    // more page is mapped here to restore content of the first page.
	if (vma_has_guard_gap_hidden (vma))
		vma->e->start -= PAGE_SIZE;

	size = vma_entry_len (vma->e);
    if (vma->e->is_deleted || vma->e->is_added) {

        if (!vma->e->is_added)
            return 0;

        // XXX: Shiv
        //
        // Blindly mmap added VMAs to new premmapped region of this iteration.
        // Handeling the cases of totally new or deleted or overlapping VMAs
        // will be done while restoring the content (restore_updated_priv_vma_content).
        //
        vma->page_bitmap = xzalloc (pg_bitmap_size);
        if (vma->page_bitmap == NULL)
            return -1;

        // Restore AIO ring buffer content to temporary anonymous area.
        // This will be placed in io_setup'ed AIO in restore_aio_ring().
        if (vma_entry_is (vma->e, VMA_AREA_AIORING))
            flag |= MAP_ANONYMOUS;
        else if (vma_area_is (vma, VMA_FILE_PRIVATE)) {
            ret = vma->vm_open (vpid(t), vma);
            if (ret < 0) {
                pr_err("Can't fixup VMA's fd\n");
                return -1;
            }
        }

        // All mappings here get PROT_WRITE regardless of whether we put any data
        // into it or not, because this area will get mremap()-ed (in child) so
        // we MIGHT need to have WRITE bits there. Ideally we'd check for the
        // whole COW-chain having any data in.
        prst_timing_start (TIME_MMAP);
        addr = mmap (*tgt_addr, size, vma->e->prot | PROT_WRITE
                , vma->e->flags | MAP_FIXED | flag, vma->e->fd, vma->e->pgoff);
        prst_timing_stop (TIME_MMAP);

        if (addr == MAP_FAILED) {
            pr_perror("Unable to map ANON_VMA");
            return -1;
        }

    } else {

        void *prev_addr;

        // First, clear the page_bitmap.
        memzero (vma->page_bitmap, pg_bitmap_size);

        // Now, remap this VMA to the memory layout of the current iteration.
        prev_addr = decode_pointer (vma->premmaped_addr);
        if (vma_has_guard_gap_hidden (vma))
            prev_addr -= PAGE_SIZE;

        prst_timing_start (TIME_MREMAP);
        addr = mremap (prev_addr, size, size, MREMAP_FIXED | MREMAP_MAYMOVE, *tgt_addr);
        prst_timing_stop (TIME_MREMAP);
        if (addr != *tgt_addr) {
            pr_perror("Unable to remap a private vma");
            return -1;
        }
		vma->e->is_mremapped = true;

    }

    vma->e->status |= VMA_PREMMAPED;
    vma->old_premmaped_addr = vma->premmaped_addr;
    vma->premmaped_addr = (unsigned long) addr;
    pr_debug ("\titerative premap %#016" PRIx64 "-%#016" PRIx64 " -> %016lx\n"
            , vma->e->start, vma->e->end, (unsigned long) addr);

    if (vma_has_guard_gap_hidden (vma)) { /* Skip guard page */
        vma->e->start += PAGE_SIZE;
        vma->premmaped_addr += PAGE_SIZE;
    }

    if (vma_area_is (vma, VMA_FILE_PRIVATE))
        vma->vm_open = NULL; /* prevent from 2nd open in prepare_vmas */

    *tgt_addr += size;
    return 0;

}

/* Map a private vma, if it is not mapped by a parent yet */
static int premap_private_vma(struct pstree_item *t, struct vma_area *vma, void **tgt_addr)
{
	int ret;
	void *addr;
	unsigned long nr_pages, size;

	nr_pages = vma_entry_len(vma->e) / PAGE_SIZE;
	vma->page_bitmap = xzalloc(BITS_TO_LONGS(nr_pages) * sizeof(long));
	if (vma->page_bitmap == NULL)
		return -1;

	/*
	 * A grow-down VMA has a guard page, which protect a VMA below it.
	 * So one more page is mapped here to restore content of the first page
	 */
	if (vma_has_guard_gap_hidden(vma))
		vma->e->start -= PAGE_SIZE;

	size = vma_entry_len(vma->e);
	if (!vma_inherited(vma)) {
		int flag = 0;
		/*
		 * The respective memory area was NOT found in the parent.
		 * Map a new one.
		 */

		/*
		 * Restore AIO ring buffer content to temporary anonymous area.
		 * This will be placed in io_setup'ed AIO in restore_aio_ring().
		 */
		if (vma_entry_is(vma->e, VMA_AREA_AIORING))
			flag |= MAP_ANONYMOUS;
		else if (vma_area_is(vma, VMA_FILE_PRIVATE)) {
			ret = vma->vm_open(vpid(t), vma);
			if (ret < 0) {
				pr_err("Can't fixup VMA's fd\n");
				return -1;
			}
		}

		/*
		 * All mappings here get PROT_WRITE regardless of whether we
		 * put any data into it or not, because this area will get
		 * mremap()-ed (branch below) so we MIGHT need to have WRITE
		 * bits there. Ideally we'd check for the whole COW-chain
		 * having any data in.
		 */
        prst_timing_start (TIME_MMAP);
		addr = mmap(*tgt_addr, size, vma->e->prot | PROT_WRITE, vma->e->flags | MAP_FIXED | flag, vma->e->fd,
			    vma->e->pgoff);
        prst_timing_stop (TIME_MMAP);

		if (addr == MAP_FAILED) {
			pr_perror("Unable to map ANON_VMA");
			return -1;
		}
	} else {
		void *paddr;

		/*
		 * The area in question can be COWed with the parent. Remap the
		 * parent area. Note, that it has already being passed through
		 * the restore_priv_vma_content() call and thus may have some
		 * pages in it.
		 */

		paddr = decode_pointer(vma->pvma->premmaped_addr);
		if (vma_has_guard_gap_hidden(vma))
			paddr -= PAGE_SIZE;

        prst_timing_start (TIME_MREMAP);
		addr = mremap(paddr, size, size, MREMAP_FIXED | MREMAP_MAYMOVE, *tgt_addr);
        prst_timing_stop (TIME_MREMAP);
		if (addr != *tgt_addr) {
			pr_perror("Unable to remap a private vma");
			return -1;
		}
	}

	vma->e->status |= VMA_PREMMAPED;
	vma->premmaped_addr = (unsigned long)addr;
	pr_debug("\tpremap %#016" PRIx64 "-%#016" PRIx64 " -> %016lx\n", vma->e->start, vma->e->end,
		 (unsigned long)addr);

	if (vma_has_guard_gap_hidden(vma)) { /* Skip guard page */
		vma->e->start += PAGE_SIZE;
		vma->premmaped_addr += PAGE_SIZE;
	}

	if (vma_area_is(vma, VMA_FILE_PRIVATE))
		vma->vm_open = NULL; /* prevent from 2nd open in prepare_vmas */

	*tgt_addr += size;
	return 0;
}

static inline bool vma_force_premap(struct vma_area *vma, struct list_head *head)
{
	/*
	 * On kernels with 4K guard pages, growsdown VMAs
	 * always have one guard page at the
	 * beginning and sometimes this page contains data.
	 * In case the VMA is premmaped, we premmap one page
	 * larger VMA. In case of in place restore we can only
	 * do this if the VMA in question is not "guarded" by
	 * some other VMA.
	 */
	if (vma->e->flags & MAP_GROWSDOWN) {
		if (vma->list.prev != head) {
			struct vma_area *prev;

			prev = list_entry(vma->list.prev, struct vma_area, list);
			if (prev->e->end == vma->e->start) {
				pr_debug("Force premmap for 0x%" PRIx64 ":0x%" PRIx64 "\n", vma->e->start, vma->e->end);
				return true;
			}
		}
	}

	return false;
}

/*
 * Ensure for s390x that vma is below task size on restore system
 */
static int task_size_check(pid_t pid, VmaEntry *entry)
{
#ifdef __s390x__
	if (entry->end <= kdat.task_size)
		return 0;
	pr_err("Can't restore high memory region %lx-%lx because kernel does only support vmas up to %lx\n",
	       entry->start, entry->end, kdat.task_size);
	return -1;
#else
	return 0;
#endif
}

/**
 * The function prepare a new premmapped region (new VMAs ground) for the
 * current iteration which will be used to fill the content.
 */
static int premap_updated_priv_vmas (struct pstree_item *t
        , struct vm_area_list *vmas, void **at) {

    struct vma_area *vma;
    unsigned long pstart = 0;
    int ret = 0;

    filemap_ctx_init (true);

    list_for_each_entry (vma, &vmas->h, list) {

        if (task_size_check(vpid(t), vma->e)) {
            ret = -1;
            break;
        }
        if (pstart > vma->e->start) {
            ret = -1;
            pr_err("VMA-s are not sorted in the image file\n");
            break;
        }
        pstart = vma->e->start;

        if (!vma_area_is_private(vma, kdat.task_size))
            continue;

        ret = premap_updated_private_vma (t, vma, at);
        if (ret < 0)
            break;

    }

    filemap_ctx_fini();
    return ret;

}

static int premap_priv_vmas(struct pstree_item *t, struct vm_area_list *vmas, void **at, struct page_read *pr)
{
	struct vma_area *vma;
	unsigned long pstart = 0;
	int ret = 0;
	LIST_HEAD(empty);

	filemap_ctx_init(true);

	list_for_each_entry(vma, &vmas->h, list) {
		if (task_size_check(vpid(t), vma->e)) {
			ret = -1;
			break;
		}
		if (pstart > vma->e->start) {
			ret = -1;
			pr_err("VMA-s are not sorted in the image file\n");
			break;
		}
		pstart = vma->e->start;

		if (!vma_area_is_private(vma, kdat.task_size))
			continue;

		if (vma->pvma == NULL && pr != NULL && pr->pieok && !vma_force_premap(vma, &vmas->h)) {
			/*
			 * VMA in question is not shared with anyone. We'll
			 * restore it with its contents in restorer.
			 * Now let's check whether we need to map it with
			 * PROT_WRITE or not.
			 */
			pr->advance(pr); /* shift to the 1st iovec */
			do {
				if (pr->pe->vaddr + pr->pe->nr_pages * PAGE_SIZE <= vma->e->start)
					continue;
				if (pr->pe->vaddr > vma->e->end)
					vma->e->status |= VMA_NO_PROT_WRITE;
				break;
			} while (pr->advance(pr));

			continue;
		}

		ret = premap_private_vma(t, vma, at);

		if (ret < 0)
			break;
	}

	filemap_ctx_fini();

	return ret;
}

static inline int __prst_remap_pages (unsigned long vaddr, struct vma_area *src_vma
        , unsigned long src_size, struct vma_area *tgt_vma, void *tgt_addr) {

    unsigned long off;//, tgt_size;
    void *src, *temp;

    BUG_ON (!src_vma->e->is_deleted);

    off = (vaddr - src_vma->e->start) / PAGE_SIZE;
    src = decode_pointer (((off) * PAGE_SIZE) + src_vma->premmaped_addr);
    //tgt_size = tgt_vma->e->end - vaddr;
    //temp = mremap (src, src_size, tgt_size, MREMAP_MAYMOVE | MREMAP_FIXED, tgt_addr);
    prst_timing_start (TIME_MEMCPY);
    temp = memcpy (tgt_addr, src, src_size);
    prst_timing_stop (TIME_MEMCPY);
    if (temp != tgt_addr) {
        pr_perror("Unable to copy.\n");
        return -1;
    }
    return 0;

}

/**
 * Function to copy pages from a source vma (processed in previous iteration)
 * to a target vma (used in current iteration).
 */
static inline int prst_read_pages (struct list_head *head, struct vma_area *tgt_vma
        , unsigned long vaddr, int nr_pages, void *tgt_addr) {

    unsigned long src_size;
    struct vma_area *src_vma = vma_prev (tgt_vma);
    src_size = nr_pages * PAGE_SIZE;

    if ((!src_vma->e->is_deleted) || (vaddr > src_vma->e->end))
        goto search_next;

    // Find pages in previous vmas.
    while (vaddr < src_vma->e->start) {
        if (src_vma->list.prev == head) {
            pr_perror ("Page (%lx) is outside of all the vmas.\n", vaddr);
            BUG();
            break;
        }
        src_vma = vma_prev (src_vma);
    }

    // Now do the remapping to move the pages to the appropriate vma.
    if (__prst_remap_pages (vaddr, src_vma, src_size, tgt_vma, tgt_addr))
        return -1;
    else
        return 0;

search_next:
    src_vma = vma_next (tgt_vma);
    BUG_ON (!src_vma->e->is_deleted);

    // Find pages in next vmas.
    while (vaddr >= src_vma->e->end) {
        if (src_vma->list.next == head) {
            pr_perror ("Page (%lx) is outside of all the vmas.\n", vaddr);
            BUG();
            break;
        }
        src_vma = vma_next (src_vma);
    }
    // Now do the remapping to move the pages to the appropriate vma.
    if (__prst_remap_pages (vaddr, src_vma, src_size, tgt_vma, tgt_addr))
        return -1;
    else
        return 0;

}

/**
 * The function restore page contents to the newly mapped VMA region for the
 * current iteration.
 *
 * XXX: Idea
 *
 * Now once you have continous VMA layout then just fill/ empty the content
 * if it is present/ not present/ parent present in this iteration. Here
 * you need to use page_bitmap array allocated in the first iteration.
 *
 * The algorithm to fill/ empty the content would be as follows:
 *      1.) Do memcpy to newly premmapped area if page is PE_PRESENT.
 *      2.) Do mremap from previously premmapped page to newly premmapped
 *          page region if page is PE_PARENT to avoid costly memcpy.
 *
 */
static int restore_updated_priv_vma_content (struct pstree_item *t
        , struct page_read *pr) {

    struct vma_area *vma;
    int ret = 0;
    struct list_head *vmas = &rsti(t)->vmas.h;

    unsigned int nr_restored = 0;
    unsigned int nr_prestored = 0;
    unsigned long va;

    vma = list_first_entry (vmas, struct vma_area, list);
    rsti(t)->pages_img_id = pr->pages_img_id;

    // Read page contents.
    //
    // XXX:
    // There are following assumptions:
    //      1.) Lazy page using userfaultfd is not considered.
    //      2.) VMAs are always premapped during premapping phase.
    while (1) {

        unsigned long off, nr_pages;
        void *p_new;

        ret = pr->advance(pr);
        if (ret <= 0)
            break;

        va = (unsigned long) decode_pointer (pr->pe->vaddr);
        nr_pages = pr->pe->nr_pages;

        // Now find suitable VMA to fill the pages.
        while (va >= vma->e->end || vma->e->is_deleted) {
            if (vma->list.next == vmas)
                goto err_addr;
            vma = vma_next(vma);
        }

        // Now, make sure the page address is inside existing VMA and the
        // VMA it refers to still private one, since there is no guarantee
        // that the data from pagemap is valid.
        if (va < vma->e->start || va >= vma->e->end) {
            goto err_addr;
        } else if (unlikely (!vma_area_is_private (vma, kdat.task_size))) {
            pr_err ("Trying to restore page for non-private VMA\n");
            goto err_addr;
        }

        if (vma->e->is_deleted) {
            pr_err ("The vma is deleted which was not expected during successive iteration\n");
            BUG();
            goto err_unexp;
        }

        if (!vma_area_is (vma, VMA_PREMMAPED)) {
            pr_err ("This was not expected during successive iteration\n");
            BUG();
            goto err_unexp;
        }

        // Get the offset and address of these pages in the current VMA layout.
        off = (va - vma->e->start) / PAGE_SIZE;
        p_new = decode_pointer (((off) * PAGE_SIZE) + vma->premmaped_addr);

        // Do mremap from premapped VMA region of previous iteration to the
        // premapped VMA region of the current iteration, if page is in parent.
        // Otherwise, fill the updated page content if it is present in current
        // iteration.
        if (pagemap_in_parent (pr->pe)) {

			BUG_ON (vma->page_bitmap == NULL);
            bitmap_set (vma->page_bitmap, off, nr_pages);
            if (!prst_vmas_updated || !vma->e->is_added)
                continue;

            /**
             * XXX: Shiv
             *
             * This is the case where the pages can be found in previously
             * processed vmas (case of vma shrink or expand).
             */
            prst_read_pages (&rsti(t)->vmas.h, vma, va, nr_pages, p_new);
            nr_prestored += nr_pages;

        } else if (pagemap_present (pr->pe)) {

            unsigned flags = opts.no_prestore ? PR_ASYNC : 0;
            prst_timing_start (TIME_READ);
            ret = pr->read_pages (pr, vma, va, nr_pages, p_new, flags);
            prst_timing_stop (TIME_READ);
            if (ret < 0)
                goto err_read;

            nr_restored += nr_pages;
			BUG_ON (vma->page_bitmap == NULL);
            bitmap_set (vma->page_bitmap, off, nr_pages);

        } else {
            pr_err ("The page is neither in parent nor in current iteration\n");
            BUG ();
        }

	// If you have encountered end marker while reading pipe data for pages
	// (in read_local_page) then it is the end of pagemap and pages reading.
	if (pr->last_pipe_data == -1) {
	    break;
	}

    }

err_read:
    if (pr->sync(pr))
        return -1;

    pr->close(pr);
    if (ret < 0)
        return ret;

    cnt_add (CNT_PAGES_RESTORED, nr_restored);
    cnt_add (CNT_PAGES_PRESTORED, nr_prestored);

    pr_info ("pc_live: nr_restored_pages: %d\n", nr_restored);
    pr_info ("pc_live: nr_prestored_pages: %d\n", nr_prestored);

    return 0;

err_addr:
    pr_err ("Page entry address %lx outside of VMA %lx-%lx\n", va
            , (long) vma->e->start, (long) vma->e->end);

err_unexp:
    return -1;

}

static int restore_priv_vma_content(struct pstree_item *t, struct page_read *pr)
{
	struct vma_area *vma;
	int ret = 0;
	struct list_head *vmas = &rsti(t)->vmas.h;
	struct list_head *vma_io = &rsti(t)->vma_io;

	unsigned int nr_restored = 0;
	unsigned int nr_shared = 0;
	unsigned int nr_dropped = 0;
	unsigned int nr_compared = 0;
	unsigned int nr_lazy = 0;
	unsigned long va;

	vma = list_first_entry(vmas, struct vma_area, list);
	rsti(t)->pages_img_id = pr->pages_img_id;

	/*
	 * Read page contents.
	 */
	while (1) {
		unsigned long off, i, nr_pages;

		ret = pr->advance(pr);
		if (ret <= 0)
			break;

		va = (unsigned long)decode_pointer(pr->pe->vaddr);
		nr_pages = pr->pe->nr_pages;

		/*
		 * This means that userfaultfd is used to load the pages
		 * on demand.
		 */
		if (opts.lazy_pages && pagemap_lazy(pr->pe)) {
			pr_debug("Lazy restore skips %ld pages at %lx\n", nr_pages, va);
			pr->skip_pages(pr, nr_pages * PAGE_SIZE);
			nr_lazy += nr_pages;
			continue;
		}

		for (i = 0; i < nr_pages; i++) {
			unsigned char buf[PAGE_SIZE];
			void *p;

			/*
			 * The lookup is over *all* possible VMAs
			 * read from image file.
			 */
			while (va >= vma->e->end) {
				if (vma->list.next == vmas)
					goto err_addr;
				vma = vma_next(vma);
			}

			/*
			 * Make sure the page address is inside existing VMA
			 * and the VMA it refers to still private one, since
			 * there is no guarantee that the data from pagemap is
			 * valid.
			 */
			if (va < vma->e->start)
				goto err_addr;
			else if (unlikely(!vma_area_is_private(vma, kdat.task_size))) {
				pr_err("Trying to restore page for non-private VMA\n");
				goto err_addr;
			}

			if (!vma_area_is(vma, VMA_PREMMAPED)) {
				unsigned long len = min_t(unsigned long, (nr_pages - i) * PAGE_SIZE, vma->e->end - va);

				if (vma->e->status & VMA_NO_PROT_WRITE) {
					pr_debug("VMA 0x%" PRIx64 ":0x%" PRIx64 " RO %#lx:%lu IO\n", vma->e->start,
						 vma->e->end, va, nr_pages);
					BUG();
				}

				if (pagemap_enqueue_iovec(pr, (void *)va, len, vma_io))
					return -1;

				pr->skip_pages(pr, len);

				va += len;
				len >>= PAGE_SHIFT;
				nr_restored += len;
				i += len - 1;
				pr_debug("Enqueue page-read\n");
				continue;
			}

			/*
			 * Otherwise to the COW restore
			 */

			off = (va - vma->e->start) / PAGE_SIZE;
			p = decode_pointer((off)*PAGE_SIZE + vma->premmaped_addr);

			if (vma_inherited(vma)) {
				clear_bit(off, vma->pvma->page_bitmap);

				ret = pr->read_pages(pr, vma, va, 1, buf, 0);
			    set_bit(off, vma->page_bitmap);
				if (ret < 0)
					goto err_read;

				va += PAGE_SIZE;
				nr_compared++;

                prst_timing_start (TIME_MEMCMP);
				if (memcmp(p, buf, PAGE_SIZE) == 0) {
                    prst_timing_stop (TIME_MEMCMP);
					nr_shared++; /* the page is cowed */
					continue;
				}

				nr_restored++;
                prst_timing_start (TIME_MEMCPY);
				memcpy(p, buf, PAGE_SIZE);
                prst_timing_stop (TIME_MEMCPY);
			} else {
				int nr;
                unsigned flags;

				/*
				 * Try to read as many pages as possible at once.
				 *
				 * Within the t pagemap we still have
				 * nr_pages - i pages (not all, as we might have
				 * switched VMA above), within the t VMA
				 * we have at most (vma->end - t_addr) bytes.
				 */

				nr = min_t(int, nr_pages - i, (vma->e->end - va) / PAGE_SIZE);

                flags = opts.no_prestore ? PR_ASYNC : 0;
                prst_timing_start (TIME_READ);
				ret = pr->read_pages(pr, vma, va, nr, p, flags);
                prst_timing_stop (TIME_READ);
				if (ret < 0)
					goto err_read;

				va += nr * PAGE_SIZE;
				nr_restored += nr;
				i += nr - 1;

				bitmap_set(vma->page_bitmap, off, nr);
			}
		}

		// If you have encountered end marker while reading pipe data for pages
		// (in read_local_page) then it is the end of pagemap and pages reading.
		if (pr->last_pipe_data == -1) {
		    break;
		}
	}

err_read:
	if (pr->sync(pr))
		return -1;

	pr->close(pr);
	if (ret < 0)
		return ret;

	/* Remove pages, which were not shared with a child */
	list_for_each_entry(vma, vmas, list) {
		unsigned long size, i = 0;
		void *addr = decode_pointer(vma->premmaped_addr);

		if (!vma_inherited(vma))
			continue;

		size = vma_entry_len(vma->e) / PAGE_SIZE;
		while (1) {
			/* Find all pages, which are not shared with this child */
			i = find_next_bit(vma->pvma->page_bitmap, size, i);

			if (i >= size)
				break;

			ret = madvise(addr + PAGE_SIZE * i, PAGE_SIZE, MADV_DONTNEED);
			if (ret < 0) {
				pr_perror("madvise failed");
				return -1;
			}
			i++;
			nr_dropped++;
		}
	}

	cnt_add(CNT_PAGES_COMPARED, nr_compared);
	cnt_add(CNT_PAGES_SKIPPED_COW, nr_shared);
	cnt_add(CNT_PAGES_RESTORED, nr_restored);

	pr_info("nr_restored_pages: %d\n", nr_restored);
	pr_info("nr_shared_pages:   %d\n", nr_shared);
	pr_info("nr_dropped_pages:   %d\n", nr_dropped);
	pr_info("nr_lazy:           %d\n", nr_lazy);

	return 0;

err_addr:
	pr_err("Page entry address %lx outside of VMA %lx-%lx\n", va, (long)vma->e->start, (long)vma->e->end);
	return -1;
}

static int maybe_disable_thp (struct pstree_item *t, struct page_read *pr) {

	MmEntry *mm = rsti(t)->mm;

	if (pr == NULL) {
		return 0;
	}

	/*
	 * There is no need to disable it if the page read doesn't
	 * have parent. In this case VMA will be empty until
	 * userfaultfd_register, so there would be no pages to
	 * collapse. And, once we register the VMA with uffd,
	 * khugepaged will skip it.
	 */
	if (opts.no_prestore && !(opts.lazy_pages && page_read_has_parent(pr)))
		return 0;

	if (!kdat.has_thp_disable)
		pr_warn("Disabling transparent huge pages. "
			"It may affect performance!\n");

	/*
	 * temporarily disable THP to avoid collapse of pages
	 * in the areas that will be monitored by uffd
	 */
	if (prctl(PR_SET_THP_DISABLE, 1, 0, 0, 0)) {
		pr_perror("Cannot disable THP");
		return -1;
	}

    if (!(mm->has_thp_disabled && mm->thp_disabled))
		rsti(t)->has_thp_enabled = true;

	return 0;

}

/**
 * XXX: Memory Subsystem Update Algorithm
 *
 * 1. Make new private memory layout for current iteration.
 * 2. Walk over VMAs of current iteration and do following:
 *      a.) If this VMA is present in prev iteration also, then do mremap to
 *          the new layout.
 *      b.) Else if VMA is completely new for this iteration, then do whatever
 *          is done for new VMA in premap_private_vma.
 *      c.) Else the VMA is partially updated, so do m(re)map to the new layout
 *          to perform expand or shrink.
 * 3. Now you have continous VMA layout then just fill/ empty the content
 *    if it is present/ not present/ parent present in this iteration.
 *
 * NOTE:
 *
 * 1. Above algorithm can be optimized by checking if there is any vma update
 *    happened in the current iteration before going for premap. However the
 *    filling/ emptying the content can not be optimized with this idea.
 * 2. Premapping the VMAs to the continous memory region is necessary to reduce
 *    number of munmap calls during cleaning of unwanted address space in
 *    restorer.
 */
int prst_update_mappings (struct pstree_item *t) {

    int ret = 0;
    void *addr = NULL;
    void *old_premmapped_addr = NULL;
    unsigned long old_premmapped_len;
    struct vm_area_list *vmas;
    struct page_read pr;

    vmas = &rsti(t)->vmas;
    if (vmas->nr == 0) /* Zombie */
        return 0;

    /**
    if (maybe_disable_thp (t, &pr))
        return -1;
        */

    // Skip premapping of VMAs, if there is no VMA update for this iteration.
    prst_vmas_updated = __prst_is_vmas_updated (&vmas->h);
    if (!prst_vmas_updated) {
        set_vmas_premmapped (&vmas->h, t->curr_iter);
        goto skip_premap;
    }

    pr_debug ("Going to make new vma memory layout for this iteration\n");
    addr = mmap (NULL, vmas->rst_priv_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if (addr == MAP_FAILED) {
        ret = -1;
        pr_perror("Unable to reserve memory (%lu bytes)", vmas->rst_priv_size);
        goto out;
    }
    old_premmapped_addr = rsti(t)->premmapped_addr;
    old_premmapped_len = rsti(t)->premmapped_len;
    rsti(t)->premmapped_addr = addr;
    rsti(t)->premmapped_len = vmas->rst_priv_size;

    ret = premap_updated_priv_vmas (t, vmas, &addr);
    if (ret < 0)
        goto out;

    /*
     * All VMAs may not be premmaped so find out the unused tail of the
     * premapped area and unmap it.
     */
    old_premmapped_len = addr - rsti(t)->premmapped_addr;
    if (old_premmapped_len < rsti(t)->premmapped_len) {

        unsigned long tail;
        tail = rsti(t)->premmapped_len - old_premmapped_len;
        ret = munmap(addr, tail);
        if (ret < 0)
            pr_perror("Unable to unmap %p(%lx)", addr, tail);
        rsti(t)->premmapped_len = old_premmapped_len;
        pr_info("Shrunk premap area to %p(%lx)\n", rsti(t)->premmapped_addr
                , rsti(t)->premmapped_len);

    }

skip_premap:
    // Global processing is finished, so clear the notification signal. Now wait
    // for CRIU to signal this process to start processing memory contents
    // from pagemap and pages images.
    futex_wait_until (&t->mem_notif, 1);

    pr.is_pagemaps_cached = false;
    ret = open_page_read (vpid(t), &pr, PR_TASK);
    if (ret <= 0)
        return -1;

    ret = restore_updated_priv_vma_content (t, &pr);
    if (ret < 0)
        goto out;

    // Reset the futex so that CRIU can signal next process, if any.
    futex_set (&t->mem_notif, 0);

	// Unmap all vmas from previous iteration which are not-mremapped in current iteration.
    if (old_premmapped_addr) {
        ret = __prst_unmap_remapped_vmas (&vmas->h);
        if (ret < 0) {
            pr_perror ("Unable to unmap old memory layout\n");
        }
    }

out:
    // Now clean the VMAs list to remove deleted vmas.
    clean_vmas (t);
    return ret;

}

int prepare_mappings (struct pstree_item *t) {

	int ret = 0;
	void *addr;
	struct vm_area_list *vmas;
	struct page_read pr;

	void *old_premmapped_addr = NULL;
	unsigned long old_premmapped_len;

	vmas = &rsti(t)->vmas;
	if (vmas->nr == 0) /* Zombie */
		goto out;

	/* Reserve a place for mapping private vma-s one by one */
	addr = mmap(NULL, vmas->rst_priv_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if (addr == MAP_FAILED) {
		ret = -1;
		pr_perror("Unable to reserve memory (%lu bytes)", vmas->rst_priv_size);
		goto out;
	}

	old_premmapped_addr = rsti(t)->premmapped_addr;
	old_premmapped_len = rsti(t)->premmapped_len;
	rsti(t)->premmapped_addr = addr;
	rsti(t)->premmapped_len = vmas->rst_priv_size;

	if (maybe_disable_thp(t, NULL))
		return -1;

	ret = premap_priv_vmas(t, vmas, &addr, NULL);
	if (ret < 0)
		goto out;

	//pr.reset(&pr);

    // Global processing is finished, so clear the notification signal. Now wait
    // for CRIU to signal this process to start processing memory contents
    // from pagemap and pages images, if it is pipelined restore.
    if (!opts.no_prestore) {
        futex_wait_until (&t->mem_notif, 1);
    }

    pr.is_pagemaps_cached = false;
	ret = open_page_read(vpid(t), &pr, PR_TASK);
	if (ret <= 0)
		return -1;

	ret = restore_priv_vma_content(t, &pr);
	if (ret < 0)
		goto out;

    // Reset the futex so that CRIU can signal next process, if any.
    if (!opts.no_prestore) {
        futex_set (&t->mem_notif, 0);
    }

	if (old_premmapped_addr) {
		ret = munmap(old_premmapped_addr, old_premmapped_len);
		if (ret < 0)
			pr_perror("Unable to unmap %p(%lx)", old_premmapped_addr, old_premmapped_len);
	}

	/*
	 * Not all VMAs were premmaped. Find out the unused tail of the
	 * premapped area and unmap it.
	 */
	old_premmapped_len = addr - rsti(t)->premmapped_addr;
	if (old_premmapped_len < rsti(t)->premmapped_len) {
		unsigned long tail;

		tail = rsti(t)->premmapped_len - old_premmapped_len;
		ret = munmap(addr, tail);
		if (ret < 0)
			pr_perror("Unable to unmap %p(%lx)", addr, tail);
		rsti(t)->premmapped_len = old_premmapped_len;
		pr_info("Shrunk premap area to %p(%lx)\n", rsti(t)->premmapped_addr, rsti(t)->premmapped_len);
	}

out:
	return ret;

}

bool vma_has_guard_gap_hidden(struct vma_area *vma)
{
	return kdat.stack_guard_gap_hidden && (vma->e->flags & MAP_GROWSDOWN);
}

/*
 * A guard page must be unmapped after restoring content and
 * forking children to restore COW memory.
 */
int unmap_guard_pages(struct pstree_item *t)
{
	struct vma_area *vma;
	struct list_head *vmas = &rsti(t)->vmas.h;

	if (!kdat.stack_guard_gap_hidden)
		return 0;

	list_for_each_entry(vma, vmas, list) {
		if (!vma_area_is(vma, VMA_PREMMAPED))
			continue;

		if (vma->e->flags & MAP_GROWSDOWN) {
			void *addr = decode_pointer(vma->premmaped_addr);

			if (munmap(addr - PAGE_SIZE, PAGE_SIZE)) {
				pr_perror("Can't unmap guard page");
				return -1;
			}
		}
	}

	return 0;
}

int open_vmas(struct pstree_item *t)
{
	int pid = vpid(t);
	struct vma_area *vma;
	struct vm_area_list *vmas = &rsti(t)->vmas;

	filemap_ctx_init(false);

	list_for_each_entry(vma, &vmas->h, list) {
		if (!vma_area_is(vma, VMA_AREA_REGULAR) || !vma->vm_open)
			continue;

		pr_info("Opening %#016" PRIx64 "-%#016" PRIx64 " %#016" PRIx64 " (%x) vma\n", vma->e->start,
			vma->e->end, vma->e->pgoff, vma->e->status);

		if (vma->vm_open(pid, vma)) {
			pr_err("`- Can't open vma\n");
			return -1;
		}

		/*
		 * File mappings have vm_open set to open_filemap which, in
		 * turn, puts the VMA_CLOSE bit itself. For all the rest we
		 * need to put it by hands, so that the restorer closes the fd
		 */
		if (!(vma_area_is(vma, VMA_FILE_PRIVATE) || vma_area_is(vma, VMA_FILE_SHARED)))
			vma->e->status |= VMA_CLOSE;
	}

	filemap_ctx_fini();

	return 0;
}

static int prepare_vma_ios(struct pstree_item *t, struct task_restore_args *ta)
{
	struct cr_img *pages;

	/*
	 * We optimize the case when rsti(t)->vma_io is empty.
	 *
	 * This is useful when using the image streamer, where all VMAs are
	 * premapped (pr->pieok is false). This avoids re-opening the
	 * CR_FD_PAGES file, which may only be readable only once.
	 */
	if (list_empty(&rsti(t)->vma_io)) {
		ta->vma_ios = NULL;
		ta->vma_ios_n = 0;
		ta->vma_ios_fd = -1;
		return 0;
	}

	/*
	 * If auto-dedup is on we need RDWR mode to be able to punch holes in
	 * the input files (in restorer.c)
	 */
	pages = open_image(CR_FD_PAGES, opts.auto_dedup ? O_RDWR : O_RSTR, rsti(t)->pages_img_id);
	if (!pages)
		return -1;

	ta->vma_ios_fd = img_raw_fd(pages);
	return pagemap_render_iovec(&rsti(t)->vma_io, ta);
}

int prepare_vmas(struct pstree_item *t, struct task_restore_args *ta)
{
	struct vma_area *vma;
	struct vm_area_list *vmas = &rsti(t)->vmas;

	ta->vmas = (VmaEntry *)rst_mem_align_cpos(RM_PRIVATE);
	ta->vmas_n = vmas->nr;

	list_for_each_entry(vma, &vmas->h, list) {
		VmaEntry *vme;

		vme = rst_mem_alloc(sizeof(*vme), RM_PRIVATE);
		if (!vme)
			return -1;

		/*
		 * Copy VMAs to private rst memory so that it's able to
		 * walk them and m(un|re)map.
		 */
		*vme = *vma->e;

		if (vma_area_is(vma, VMA_PREMMAPED))
			vma_premmaped_start(vme) = vma->premmaped_addr;
	}

	return prepare_vma_ios(t, ta);
}
