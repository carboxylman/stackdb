/*
 * Copyright (c) 2013 The University of Utah
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "binfile.h"
#include "target_xen_vm_process.h"
#include "target.h"
#include "target_api.h"
#include "target_xen_vm.h"

struct xen_vm_process_spec *xen_vm_process_build_spec(void) {
    return NULL;
}

void xen_vm_process_free_spec(struct xen_vm_process_spec *spec) {
    return;
}

/*
 * Prototypes.
 */
static int xen_vm_process_snprintf(struct target *target,
				   char *buf,int bufsiz);
static int xen_vm_process_init(struct target *target);
static int xen_vm_process_postloadinit(struct target *target);
static int xen_vm_process_attach(struct target *target);
static int xen_vm_process_detach(struct target *target);
static int xen_vm_process_fini(struct target *target);
static int xen_vm_process_loadspaces(struct target *target);
static int xen_vm_process_loadregions(struct target *target,
				      struct addrspace *space);
static int xen_vm_process_loaddebugfiles(struct target *target,
					 struct addrspace *space,
					 struct memregion *region);

static target_status_t xen_vm_process_overlay_event(struct target *overlay,
						    tid_t tid,ADDR ipval,
						    int *again);

static int xen_vm_process_attach_evloop(struct target *target,
					struct evloop *evloop);
static int xen_vm_process_detach_evloop(struct target *target);
static target_status_t xen_vm_process_status(struct target *target);
static int xen_vm_process_pause(struct target *target,int nowait);
static int xen_vm_process_resume(struct target *target);
static unsigned char *xen_vm_process_read(struct target *target,
					  ADDR addr,
					  unsigned long length,
					  unsigned char *buf);
static unsigned long xen_vm_process_write(struct target *target,
					  ADDR addr,
					  unsigned long length,
					  unsigned char *buf);
static char *xen_vm_process_reg_name(struct target *target,REG reg);
static REG xen_vm_process_dwregno_targetname(struct target *target,char *name);
static REG xen_vm_process_dw_reg_no(struct target *target,common_reg_t reg);

static tid_t xen_vm_process_gettid(struct target *target);
static void xen_vm_process_free_thread_state(struct target *target,void *state);
static struct array_list *xen_vm_process_list_available_tids(struct target *target);
static struct target_thread *xen_vm_process_load_thread(struct target *target,
							tid_t tid,int force);
static struct target_thread *xen_vm_process_load_current_thread(struct target *target,
								int force);
static int xen_vm_process_load_all_threads(struct target *target,int force);
static int xen_vm_process_load_available_threads(struct target *target,int force);
static int xen_vm_process_flush_thread(struct target *target,tid_t tid);
static int xen_vm_process_flush_current_thread(struct target *target);
static int xen_vm_process_flush_all_threads(struct target *target);
static int xen_vm_process_invalidate_all_threads(struct target *target);
static int xen_vm_process_thread_snprintf(struct target_thread *tthread,
					  char *buf,int bufsiz,
					  int detail,char *sep,char *kvsep);

static REGVAL xen_vm_process_read_reg(struct target *target,tid_t tid,REG reg);
static int xen_vm_process_write_reg(struct target *target,tid_t tid,REG reg,
				    REGVAL value);
static GHashTable *xen_vm_process_copy_registers(struct target *target,tid_t tid);
static struct target_memmod *
xen_vm_process_insert_sw_breakpoint(struct target *target,
				    tid_t tid,ADDR addr);
static int xen_vm_process_remove_sw_breakpoint(struct target *target,tid_t tid,
					       struct target_memmod *mmod);
static int xen_vm_process_enable_sw_breakpoint(struct target *target,tid_t tid,
					       struct target_memmod *mmod);
static int xen_vm_process_disable_sw_breakpoint(struct target *target,tid_t tid,
						struct target_memmod *mmod);
static int xen_vm_process_change_sw_breakpoint(struct target *target,tid_t tid,
					       struct target_memmod *mmod,
					       unsigned char *code,
					       unsigned long code_len);
static REG xen_vm_process_get_unused_debug_reg(struct target *target,tid_t tid);
static int xen_vm_process_set_hw_breakpoint(struct target *target,tid_t tid,
					    REG num,ADDR addr);
static int xen_vm_process_set_hw_watchpoint(struct target *target,tid_t tid,
					    REG num,ADDR addr,
					    probepoint_whence_t whence,
					    probepoint_watchsize_t watchsize);
static int xen_vm_process_unset_hw_breakpoint(struct target *target,tid_t tid,
					      REG num);
static int xen_vm_process_unset_hw_watchpoint(struct target *target,tid_t tid,
					      REG num);
int xen_vm_process_disable_hw_breakpoints(struct target *target,tid_t tid);
int xen_vm_process_enable_hw_breakpoints(struct target *target,tid_t tid);
int xen_vm_process_disable_hw_breakpoint(struct target *target,tid_t tid,
					 REG dreg);
int xen_vm_process_enable_hw_breakpoint(struct target *target,tid_t tid,
					REG dreg);
int xen_vm_process_notify_sw_breakpoint(struct target *target,ADDR addr,
					int notification);
int xen_vm_process_singlestep(struct target *target,tid_t tid,int isbp,
			      struct target *overlay);
int xen_vm_process_singlestep_end(struct target *target,tid_t tid,
				  struct target *overlay);


struct target_ops xen_vm_process_ops = {
    .snprintf = xen_vm_process_snprintf,

    .init = xen_vm_process_init,
    .fini = xen_vm_process_fini,
    .attach = xen_vm_process_attach,
    .detach = xen_vm_process_detach,
    .kill = NULL,
    .loadspaces = xen_vm_process_loadspaces,
    .loadregions = xen_vm_process_loadregions,
    .loaddebugfiles = xen_vm_process_loaddebugfiles,
    .postloadinit = xen_vm_process_postloadinit,

    /* Don't support overlays initially. */
    .instantiate_overlay = NULL,

    .overlay_event = xen_vm_process_overlay_event,

    .status = xen_vm_process_status,
    .pause = xen_vm_process_pause,
    .resume = xen_vm_process_resume,
    .monitor = NULL,
    .poll = NULL,
    .read = xen_vm_process_read,
    .write = xen_vm_process_write,
    .regname = xen_vm_process_reg_name,
    .dwregno_targetname = xen_vm_process_dwregno_targetname,
    .dwregno = xen_vm_process_dw_reg_no,

    .gettid = xen_vm_process_gettid,
    .free_thread_state = xen_vm_process_free_thread_state,

    /* There are never any untracked threads in this target. */
    .list_available_tids = target_list_tids,
    /* There are never any untracked threads in this target. */
    .load_available_threads = xen_vm_process_load_all_threads,
    .load_thread = xen_vm_process_load_thread,
    .load_current_thread = xen_vm_process_load_current_thread,
    .load_all_threads = xen_vm_process_load_all_threads,
    .pause_thread = NULL,
    .flush_thread = xen_vm_process_flush_thread,
    .flush_current_thread = xen_vm_process_flush_current_thread,
    .flush_all_threads = xen_vm_process_flush_all_threads,
    .invalidate_all_threads = xen_vm_process_invalidate_all_threads,
    .thread_snprintf = xen_vm_process_thread_snprintf,

    .attach_evloop = xen_vm_process_attach_evloop,
    .detach_evloop = xen_vm_process_detach_evloop,

    .readreg = xen_vm_process_read_reg,
    .writereg = xen_vm_process_write_reg,
    .copy_registers = xen_vm_process_copy_registers,
    .insert_sw_breakpoint = xen_vm_process_insert_sw_breakpoint,
    .remove_sw_breakpoint = xen_vm_process_remove_sw_breakpoint,
    .enable_sw_breakpoint = xen_vm_process_enable_sw_breakpoint,
    .disable_sw_breakpoint = xen_vm_process_disable_sw_breakpoint,
    .change_sw_breakpoint = xen_vm_process_change_sw_breakpoint,
    .get_unused_debug_reg = xen_vm_process_get_unused_debug_reg,
    //.set_hw_breakpoint = xen_vm_process_set_hw_breakpoint,
    //.set_hw_watchpoint = xen_vm_process_set_hw_watchpoint,
    //.unset_hw_breakpoint = xen_vm_process_unset_hw_breakpoint,
    //.unset_hw_watchpoint = xen_vm_process_unset_hw_watchpoint,
    //.disable_hw_breakpoints = xen_vm_process_disable_hw_breakpoints,
    //.enable_hw_breakpoints = xen_vm_process_enable_hw_breakpoints,
    //.disable_hw_breakpoint = xen_vm_process_disable_hw_breakpoint,
    //.enable_hw_breakpoint = xen_vm_process_enable_hw_breakpoint,
    .notify_sw_breakpoint = xen_vm_process_notify_sw_breakpoint,
    .singlestep = xen_vm_process_singlestep,
    .singlestep_end = xen_vm_process_singlestep_end,
};

static int xen_vm_process_snprintf(struct target *target,
				   char *buf,int bufsiz) {
    return snprintf(buf,bufsiz,"task(%d)",target->base_tid);
}

static int xen_vm_process_init(struct target *target) {
    struct xen_vm_thread_state *xtstate;
    struct target_thread *base_thread = target->base_thread;
    struct target *base = target->base;
    tid_t base_tid = target->base_tid;
    struct target_thread *orig_base_thread = NULL;

    /*
     * Setup target mode stuff.
     */
    target->threadctl = 0;
    target->live = base->live;
    target->writeable = base->writeable;
    target->mmapable = 0;
    /* NB: only native arch supported!  i.e., no 32-bit emu on 64-bit host. */
    target->endian = base->endian;
    target->wordsize = base->wordsize;
    target->ptrsize = base->ptrsize;

    /* Which register is the fbreg is dependent on host cpu type, not
     * target cpu type.
     */
#if __WORDSIZE == 64
    target->fbregno = 6;
    target->spregno = 7;
    target->ipregno = 16;
#else
    target->fbregno = 5;
    target->spregno = 4;
    target->ipregno = 8;
#endif

    target->breakpoint_instrs = malloc(1);
    *(char *)(target->breakpoint_instrs) = 0xcc;
    target->breakpoint_instrs_len = 1;
    target->breakpoint_instr_count = 1;

    target->ret_instrs = malloc(1);
    /* RET */
    *(char *)(target->ret_instrs) = 0xc3;
    target->ret_instrs_len = 1;
    target->ret_instr_count = 1;

    target->full_ret_instrs = malloc(2);
    /* LEAVE */
    *(char *)(target->full_ret_instrs) = 0xc9;
    /* RET */
    *(((char *)(target->full_ret_instrs))+1) = 0xc3;
    target->full_ret_instrs_len = 2;
    target->full_ret_instr_count = 2;

    /*
     * Make sure the base thread is loaded.
     */
    if (!(base_thread = target_load_thread(base,base_tid,0))) {
	verror("could not load base tid %d!\n",base_tid);
	return -1;
    }
    else if (base_thread != target->base_thread) {
	/*
	 * Catch stale threads; if there is a huge delay between
	 * target_instantiate and target_open, this could potentially
	 * happen -- but PID wraparound in the kernel would have to
	 * happen mighty fast!  Unlikely.
	 */
	vwarn("target->base_thread does not match with just-loaded thread"
	      " for %d; pid wraparound caused stale thread??\n",base_tid);
	target->base_thread = base_thread;
    }

    /*
     * First, check and see if this is the thread group leader.  If it
     * is not, attach to the group leader and "pivot" it into place as
     * our "real" base thread/tid.
     */
    xtstate = (struct xen_vm_thread_state *)base_thread->state;
    if (xtstate->tgid != base_tid) {
	vdebug(5,LA_TARGET,LF_XVP,
	       "user requested tid %d (not group leader); pivoting group leader into place...\n",
	       base_thread->tid);

	base_thread = target_load_thread(base,xtstate->tgid,0);
	if (!base_thread) {
	    verror("could not load group leader tid %"PRIiNUM
		   " (for user-requested tid %d)\n",
		   xtstate->tgid,base_tid);
	    return -1;
	}

	/*
	 * Pivot it into place; remove the old one.
	 *
	 * XXX: this is maybe kind of bad?  What if the user saves off
	 * the base_tid or something?  Hmmm.
	 */
	orig_base_thread = target->base_thread;
	target->base_thread = base_thread;
	target->base_tid = base_tid = base_thread->tid;

	g_hash_table_remove(base->overlays,
			    (gpointer)(uintptr_t)orig_base_thread->tid);
	g_hash_table_insert(base->overlays,(gpointer)(uintptr_t)base_tid,target);
    }

    /*
     * Just adjust for the user, don't error :)
     */
    if (target->spec->bpmode == THREAD_BPMODE_STRICT) {
	vwarn("auto-enabling SEMI_STRICT bpmode on Xen Process target.\n");
	target->spec->bpmode = THREAD_BPMODE_SEMI_STRICT;
    }

    /*
     * Initialize our state.
     */
    target->state = calloc(1,sizeof(struct xen_vm_process_state));

    /*
     * Don't do anything else here; do it in attach().
     */
    return 0;
}

static int xen_vm_process_fini(struct target *target) {
    return 0;
}

static int xen_vm_process_attach(struct target *target) {
    if (target_pause(target->base)) {
	verror("could not pause base target %s!\n",target->base->name);
	return -1;
    }

    target_set_status(target,TSTATUS_PAUSED);

    /*
     * Just grab all the threads in the thread group and create them.
     */
    target->current_thread = target_create_thread(target,target->base_tid,NULL);
    target_reuse_thread_as_global(target,target->current_thread);

    target_thread_set_status(target->current_thread,THREAD_STATUS_RUNNING);

    return 0;
}

static int xen_vm_process_detach(struct target *target) {
    /*
     * Just detach all our threads.
     */
    return 0;
}

static int xen_vm_process_loadspaces(struct target *target) {
    struct addrspace *space = addrspace_create(target,"NULL",target->base_tid);

    space->target = target;
    RHOLD(space,target);

    list_add_tail(&space->space,&target->spaces);

    return 0;
}

/*
 * loadregions is designed to work just fine as updateregions.
 *
 * Its performance is (much) better if its values are mmap'd.  Why?
 * Because we cache vm_area_struct values for each region in the task's
 * mmap, and we can compare the member values in the mmap'd value direct
 * with the region-cached values without copying.  If we have to load
 * the new 
 */
static int __xen_vm_process_loadregions(struct target *target,
					struct addrspace *space,
					int is_initial) {
    char buf[PATH_MAX];
    struct target_thread *base_thread = target->base_thread;
    struct xen_vm_thread_state *xtstate = \
	(struct xen_vm_thread_state *)target->base_thread->state;
    struct target *base = target->base;
    struct xen_vm_state *xstate = (struct xen_vm_state *)base->state;
    tid_t base_tid = target->base_tid;
    struct xen_vm_process_state *xvpstate = \
	(struct xen_vm_process_state *)target->state;
    struct memregion *region,*tregion;
    struct memrange *range;
    region_type_t rtype;
    struct value *vma;
    struct value *vma_prev;
    struct xen_vm_process_vma *new_vma,*cached_vma,*cached_vma_prev;
    struct xen_vm_process_vma *tmp_cached_vma,*tmp_cached_vma_d;
    ADDR mm_addr;
    ADDR vma_addr;
    ADDR vma_next_addr;
    ADDR start,end,offset;
    unum_t prot_flags;
    ADDR file_addr;
    char *prev_vma_member_name;
    struct value *file_value;
    int found;

    if (unlikely(is_initial))
	vdebug(5,LA_TARGET,LF_XVP,"tid %d (initial load)\n",target->base_tid);
    else
	vdebug(5,LA_TARGET,LF_XVP,"tid %d (rescanning)\n",target->base_tid);

    /*
     * Make sure the base thread is loaded.
     */
    if (!(base_thread = target_load_thread(base,base_tid,0))) {
	verror("could not load base tid %d!\n",base_tid);
	return -1;
    }

    /*
     * So, what do we have to do?  target_load_thread on the base target
     * will get us the task_struct; but from there we have to check
     * everything: first task->mm, then task->mm->mmap, then all the
     * task->mm->mmap->vm_next pointers that form the list of
     * vm_area_structs that compose the task's mmap.  Basically, we keep
     * a list of cached vm_area_struct values that mirrors the kernel's
     * list; for each vm_area_struct, we cache its value and its last
     * vm_next addr, and a non-VMI pointer to the next cached vma.
     *
     * (This code is written to use the value_refresh() API to quickly
     * see if a value has changed.  We don't care about the old value.)
     * 
     * The kernel maintains a sorted list, so figuring out which ranges
     * need updating is (somewhat) easier.  We simply run through the
     * kernel's list, comparing it to our list.  If the vaddr of the
     * i-th vma *does* match the cached vma's vaddr, we just check to
     * see if the value has changed.  If it has, we updated accordingly;
     * otherwise we proceed to the i+1-th entry.  If it *does not*
     * match, either our cached entry has been deleted; a new entry has
     * been inserted in the kernel; or both.  If it does not match, we
     * scan down our cached list until the i-th vma start addr >= our
     * i+j-th cached vma start addr, and delete all the cached entries
     * until that point.  At that point, if it does not match the i+j-th
     * cached vma addr, we insert it as a new mmap entry.  That's it!  :)
     *
     * One other note.  Each vm_area_struct gets its own memrange; we
     * combine memranges into memregions based on the files that back
     * them.  Only ranges with the same filename get combined into
     * memregions.
     */

    /* Grab the base task's mm address to see if it changed. */
    VLV(base,xstate->default_tlctxt,xtstate->task_struct,"mm",LOAD_FLAG_NONE,
	&mm_addr,NULL,err_vmiload);

    if (xvpstate->mm_addr && mm_addr == 0) {
	/*
	 * This should be impossible!  A task's mm should not go away.
	 */
	vwarn("tid %d's task->mm became NULL; removing all regions!\n",base_tid);

	/* Just remove all the existing ranges/regions... */
	xvpstate->mm_start_brk = 0;
	xvpstate->mm_brk = 0;
	xvpstate->mm_start_stack = 0;
	xvpstate->mm_addr = 0;
	value_free(xvpstate->mm);
	xvpstate->mm = NULL;

	cached_vma = xvpstate->vma_cache;
	while (cached_vma) {
	    range = cached_vma->range;

	    vdebug(5,LA_TARGET,LF_XVP,
		   "removing mm-gone stale range 0x%"PRIxADDR"-0x%"PRIxADDR":%"PRIiOFFSET"\n",
		   range->start,range->end,range->offset);
	    target_add_state_change(target,TID_GLOBAL,
				    TARGET_STATE_CHANGE_RANGE_DEL,
				    0,range->prot_flags,
				    range->start,range->end,range->region->name);
	    memrange_free(range);

	    cached_vma_prev = cached_vma;
	    cached_vma = cached_vma->next;

	    value_free(cached_vma_prev->vma);
	    free(cached_vma_prev);
	    cached_vma_prev = NULL;
	}

	/* Remove all the (now empty) regions. */
	list_for_each_entry_safe(region,tregion,&space->regions,region) {
	    vdebug(5,LA_TARGET,LF_XVP,
		   "removing mm-gone stale memregion(%s:%s:%s)\n",
		   region->space->idstr,region->name,REGION_TYPE(region->type));
	    target_add_state_change(target,TID_GLOBAL,
				    TARGET_STATE_CHANGE_REGION_DEL,
				    0,0,region->base_load_addr,0,region->name);
	    memregion_free(region);
	}
	
	xvpstate->vma_cache = NULL;
	xvpstate->vma_len = 0;

	return 0;
    }
    else if (xvpstate->mm_addr && xvpstate->mm_addr != mm_addr) {
	vwarn("tid %d's task->mm changed (0x%"PRIxADDR" to 0x%"PRIxADDR");"
	      " checking cached VMAs like normal!\n",
	      base_tid,xvpstate->mm_addr,mm_addr);

	/* Reload the mm struct first, and re-cache its members. */
	xvpstate->mm_start_brk = 0;
	xvpstate->mm_brk = 0;
	xvpstate->mm_start_stack = 0;
	xvpstate->mm_addr = 0;

	value_free(xvpstate->mm);
	xvpstate->mm = NULL;
	VL(base,xstate->default_tlctxt,xtstate->task_struct,"mm",
	   LOAD_FLAG_AUTO_DEREF,&xvpstate->mm,err_vmiload);
	xvpstate->mm_addr = value_addr(xvpstate->mm);
	VLV(base,xstate->default_tlctxt,xvpstate->mm,"start_brk",LOAD_FLAG_NONE,
	    &xvpstate->mm_start_brk,NULL,err_vmiload);
	VLV(base,xstate->default_tlctxt,xvpstate->mm,"brk",LOAD_FLAG_NONE,
	    &xvpstate->mm_brk,NULL,err_vmiload);
	VLV(base,xstate->default_tlctxt,xvpstate->mm,"start_stack",LOAD_FLAG_NONE,
	    &xvpstate->mm_start_stack,NULL,err_vmiload);

    }
    else if (xvpstate->mm_addr == 0) {
	vdebug(5,LA_TARGET,LF_XVP,"tid %d analyzing mmaps anew.\n",base_tid);

	/* Load the mm struct and cache its members. */
	VL(base,xstate->default_tlctxt,xtstate->task_struct,"mm",
	   LOAD_FLAG_AUTO_DEREF,&xvpstate->mm,err_vmiload);
	xvpstate->mm_addr = value_addr(xvpstate->mm);
	VLV(base,xstate->default_tlctxt,xvpstate->mm,"start_brk",LOAD_FLAG_NONE,
	    &xvpstate->mm_start_brk,NULL,err_vmiload);
	VLV(base,xstate->default_tlctxt,xvpstate->mm,"brk",LOAD_FLAG_NONE,
	    &xvpstate->mm_brk,NULL,err_vmiload);
	VLV(base,xstate->default_tlctxt,xvpstate->mm,"start_stack",LOAD_FLAG_NONE,
	    &xvpstate->mm_start_stack,NULL,err_vmiload);
    }
    else {
	/*
	 * XXX: when value_refresh is implemented, we want to use that
	 * to reload so we can try not to; for now, just do it manually.
	 */
	vdebug(5,LA_TARGET,LF_XVP,"tid %d refreshing task->mm.\n",base_tid);
	//value_refresh(xvpstate->mm,&vdiff,NULL);
	//if (vdiff != VALUE_DIFF_SAME) {

	xvpstate->mm_start_brk = 0;
	xvpstate->mm_brk = 0;
	xvpstate->mm_start_stack = 0;
	xvpstate->mm_addr = 0;

	value_free(xvpstate->mm);
	xvpstate->mm = NULL;
	VL(base,xstate->default_tlctxt,xtstate->task_struct,"mm",
	   LOAD_FLAG_AUTO_DEREF,&xvpstate->mm,err_vmiload);
	xvpstate->mm_addr = value_addr(xvpstate->mm);
	VLV(base,xstate->default_tlctxt,xvpstate->mm,"start_brk",LOAD_FLAG_NONE,
	    &xvpstate->mm_start_brk,NULL,err_vmiload);
	VLV(base,xstate->default_tlctxt,xvpstate->mm,"brk",LOAD_FLAG_NONE,
	    &xvpstate->mm_brk,NULL,err_vmiload);
	VLV(base,xstate->default_tlctxt,xvpstate->mm,"start_stack",LOAD_FLAG_NONE,
	    &xvpstate->mm_start_stack,NULL,err_vmiload);
    }

    /*
     * Now that we have loaded or re-cached our task's mm_struct, we
     * need to loop through its mmaps, and add/delete/modify as
     * necessary.
     */

    /* Now we have a valid task->mm; load the first vm_area_struct pointer. */
    VLV(base,xstate->default_tlctxt,xvpstate->mm,"mmap",LOAD_FLAG_NONE,
	&vma_addr,NULL,err_vmiload);
    cached_vma = xvpstate->vma_cache;
    cached_vma_prev = NULL;

    /* First time through, the value we load the vm_area_struct value
     * from is the mm_struct; after that, it is the previous
     * vm_area_struct.  The macros in the loop hide this.
     */
    vma_prev = xvpstate->mm;
    prev_vma_member_name = "mmap";

    VL(base,xstate->default_tlctxt,vma_prev,prev_vma_member_name,
       LOAD_FLAG_AUTO_DEREF,&vma,err_vmiload);
    VLV(base,xstate->default_tlctxt,vma,"vm_start",LOAD_FLAG_NONE,
	&start,NULL,err_vmiload);
    value_free(vma);

    /* If we have either a vma_addr to process, or a cached_vma, keep going. */
    while (vma_addr || cached_vma) {
	if (vma_addr && !cached_vma) {
	    /*
	     * New entry; load it and add/cache it.
	     *
	     * NB: do_new_unmatched comes from lower in the loop, where
	     * we 
	     */
	do_new_unmatched:

	    VL(base,xstate->default_tlctxt,vma_prev,prev_vma_member_name,
	       LOAD_FLAG_AUTO_DEREF,&vma,err_vmiload);
	    new_vma = calloc(1,sizeof(*new_vma));
	    new_vma->vma = vma;

	    /* Load the vma's start,end,offset,prot_flags,file,next addr. */
	    VLV(base,xstate->default_tlctxt,vma,"vm_start",LOAD_FLAG_NONE,
		&start,NULL,err_vmiload);
	    VLV(base,xstate->default_tlctxt,vma,"vm_end",LOAD_FLAG_NONE,
		&end,NULL,err_vmiload);
	    VLV(base,xstate->default_tlctxt,vma,"vm_page_prot",LOAD_FLAG_NONE,
		&prot_flags,NULL,err_vmiload);
	    VLV(base,xstate->default_tlctxt,vma,"vm_pgoff",LOAD_FLAG_NONE,
		&offset,NULL,err_vmiload);
	    VLV(base,xstate->default_tlctxt,vma,"vm_file",LOAD_FLAG_NONE,
		&file_addr,NULL,err_vmiload);
	    VLV(base,xstate->default_tlctxt,vma,"vm_next",LOAD_FLAG_NONE,
		&vma_next_addr,NULL,err_vmiload);

	    /* Figure out the region type. */
	    rtype = REGION_TYPE_ANON;
	    region = NULL;
	    buf[0] = '\0';

	    /* If it has a file, load the path! */
	    if (file_addr != 0) {
		file_value = NULL;
		VL(base,xstate->default_tlctxt,vma,"vm_file",LOAD_FLAG_AUTO_DEREF,
		   &file_value,err_vmiload);
		if (!linux_file_get_path(base,xtstate->task_struct,file_value,
					 buf,sizeof(buf))) {
		    vwarn("could not get filepath for struct file for new range;"
			  " continuing! (file 0x%"PRIxADDR")\n",file_addr);
		    file_addr = 0;
		}
		else {
		    /* Find the region this is in, if any. */
		    region = addrspace_find_region(space,buf);
		}
	    }

	    /* Create the region if we didn't find one. */
	    if (!region) {
		if (!file_addr) {
		    if (start <= xvpstate->mm_start_brk
			&& end >= xvpstate->mm_brk)
			rtype = REGION_TYPE_HEAP;
		    else if (start <= xvpstate->mm_start_stack
			     && end >= xvpstate->mm_start_stack)
			rtype = REGION_TYPE_STACK;
		    else
			rtype = REGION_TYPE_VDSO;
		}
		else {
		    /*
		     * Anything with a filename starts out as a lib; if
		     * we can't load it, it might become anon; if we can
		     * load it and it has a main(), we'll convert it to
		     * MAIN later.
		     */
		    rtype = REGION_TYPE_LIB;
		}

		region = memregion_create(space,rtype,
					  (buf[0] == '\0') ? NULL : buf);
		if (!region) 
		    goto err;

		vdebug(5,LA_TARGET,LF_XVP,
		       "created memregion(%s:%s:%s)\n",
		       region->space->idstr,region->name,
		       REGION_TYPE(region->type));
	    }

	    /* Create the range. */
	    if (!(range = memrange_create(region,start,end,offset,prot_flags))) 
		goto err;
	    new_vma->range = range;

	    vdebug(5,LA_TARGET,LF_XVP,
		   "created memrange(%s:%s:0x%"PRIxADDR",0x%"PRIxADDR","
		   "%"PRIiOFFSET",%u)\n",
		   range->region->name,REGION_TYPE(range->region->type),
		   range->start,range->end,range->offset,range->prot_flags);

	    /*
	     * Update list/metadata:
	     *
	     * Either make it the sole entry on list, or add it at tail.
	     * Either way, there is still no cached_vma to process; it's
	     * just that our previous one points to the new tail of the
	     * list for the next iteration.
	     */
	    if (!xvpstate->vma_cache) 
		xvpstate->vma_cache = new_vma;
	    else {
		cached_vma_prev->next = new_vma;
		cached_vma_prev->next_vma_addr = vma_addr;
	    }
	    ++xvpstate->vma_len;
	    cached_vma_prev = new_vma;

	    new_vma->next = cached_vma;

	    vma_addr = vma_next_addr;
	    vma_prev = vma;

	    /* After the first iteration, it's always this. */
	    prev_vma_member_name = "vm_next";

	    continue;
	}
	else if (!vma_addr && cached_vma) {
	    /*
	     * We don't have any more vm_area_structs from the kernel,
	     * so any cached entries are stale at this point.
	     */
	    tmp_cached_vma_d = cached_vma;

	    /*
	     * Update list/metadata:
	     */
	    if (cached_vma_prev) {
		cached_vma_prev->next = cached_vma->next;
		if (cached_vma->next && cached_vma->next->vma) 
		    cached_vma_prev->next_vma_addr = 
			value_addr(cached_vma->next->vma);
		else
		    cached_vma_prev->next_vma_addr = 0;
	    }
	    else {
		xvpstate->vma_cache = cached_vma->next;
		if (cached_vma->next && cached_vma->next->vma) 
		    xvpstate->vma_cache->next_vma_addr = 
			value_addr(cached_vma->next->vma);
		else
		    cached_vma_prev->next_vma_addr = 0;
	    }

	    cached_vma = cached_vma->next;
	    --xvpstate->vma_len;

	    vdebug(5,LA_TARGET,LF_XVP,
		   "removing stale memrange(%s:%s:0x%"PRIxADDR",0x%"PRIxADDR","
		   "%"PRIiOFFSET",%u)\n",
		   tmp_cached_vma_d->range->region->name,
		   REGION_TYPE(tmp_cached_vma_d->range->region->type),
		   tmp_cached_vma_d->range->start,tmp_cached_vma_d->range->end,
		   tmp_cached_vma_d->range->offset,
		   tmp_cached_vma_d->range->prot_flags);

	    /* delete range; delete empty regions when they empty. */
	    region = tmp_cached_vma_d->range->region;
	    memrange_free(tmp_cached_vma_d->range);
	    if (list_empty(&region->ranges)) {
		vdebug(5,LA_TARGET,LF_XVP,
		       "removing empty memregion(%s:%s:%s)\n",
		       region->space->idstr,region->name,
		       REGION_TYPE(region->type));

		memregion_free(region);
	    }

	    /* delete cached value stuff */
	    value_free(tmp_cached_vma_d->vma);
	    free(tmp_cached_vma_d);
	    tmp_cached_vma_d = NULL;

	    continue;
	}
	    /*
	     * Need to compare vma_addr with our cached_vma's addr; and...
	     * 
	     * If the vaddr of the i-th vma *does* match the cached
	     * vma's vaddr, we just check to see if the value has
	     * changed.  If it has, we updated accordingly; otherwise we
	     * proceed to the i+1-th entry.  If it *does not* match,
	     * either our cached entry has been deleted; a new entry has
	     * been inserted in the kernel; or both.  If it does not
	     * match, we scan down our cached list until the i-th vma
	     * start addr >= our i+j-th cached vma start addr, and
	     * delete all the cached entries until that point.  At that
	     * point, if it does not match the i+j-th cached vma addr,
	     * we insert it as a new mmap entry.
	     */
	else if (vma_addr == value_addr(cached_vma->vma)) {
	    /*
	     * Refresh the value; update the range.
	     */
	    vdebug(8,LA_TARGET,LF_XVP,
		   "tid %d refreshing vm_area_struct at 0x%"PRIxADDR"\n",
		   vma_addr);
	    value_refresh(cached_vma->vma,0);

	    /* Load the vma's start,end,prot_flags. */
	    VLV(base,xstate->default_tlctxt,cached_vma->vma,"vm_start",
		LOAD_FLAG_NONE,&start,NULL,err_vmiload);
	    VLV(base,xstate->default_tlctxt,cached_vma->vma,"vm_end",
		LOAD_FLAG_NONE,&end,NULL,err_vmiload);
	    VLV(base,xstate->default_tlctxt,cached_vma->vma,"vm_page_prot",
		LOAD_FLAG_NONE,&prot_flags,NULL,err_vmiload);
	    VLV(base,xstate->default_tlctxt,cached_vma->vma,"vm_pgoff",
		LOAD_FLAG_NONE,&offset,NULL,err_vmiload);
	    VLV(base,xstate->default_tlctxt,cached_vma->vma,"vm_next",
		LOAD_FLAG_NONE,&vma_next_addr,NULL,err_vmiload);

	    if (cached_vma->range->end == end 
		&& cached_vma->range->offset == offset 
		&& cached_vma->range->prot_flags == (unsigned int)prot_flags) {
		cached_vma->range->same = 1;

		vdebug(5,LA_TARGET,LF_XVP,
		       "no change to memrange(%s:%s:0x%"PRIxADDR",0x%"PRIxADDR","
		       "%"PRIiOFFSET",%u)\n",
		       cached_vma->range->region->name,
		       REGION_TYPE(cached_vma->range->region->type),
		       cached_vma->range->start,cached_vma->range->end,
		       cached_vma->range->offset,cached_vma->range->prot_flags);
	    }
	    else {
		cached_vma->range->end = end;
		cached_vma->range->offset = offset;
		cached_vma->range->prot_flags = prot_flags;

		cached_vma->range->updated = 1;

		if (start < cached_vma->range->region->base_load_addr)
		    cached_vma->range->region->base_load_addr = start;

		vdebug(5,LA_TARGET,LF_XVP,
		       "update to memrange(%s:%s:0x%"PRIxADDR",0x%"PRIxADDR","
		       "%"PRIiOFFSET",%u)\n",
		       cached_vma->range->region->name,
		       REGION_TYPE(cached_vma->range->region->type),
		       cached_vma->range->start,cached_vma->range->end,
		       cached_vma->range->offset,cached_vma->range->prot_flags);
	    }

	    /*
	     * Update list/metadata for next iteration:
	     */
	    cached_vma_prev = cached_vma;
	    cached_vma = cached_vma->next;

	    vma_addr = vma_next_addr;
	    vma_prev = cached_vma_prev->vma;

	    /* After the first iteration, it's always this. */
	    prev_vma_member_name = "vm_next";

	    continue;
	}
	else {
	    /*
	     * Load the next one enough to get its start addr, so we can
	     * do the comparison.  The load is not wasted; we goto
	     * (ugh, ugh, ugh) wherever we need after loading it.
	     */

	    /*
	     * Since we haven't loaded the vm_area_struct corresponding
	     * to vma_addr yet, the best we can do is look through the
	     * rest of our cached list, and see if we get a match on
	     * vma_addr and value_addr(tmp_cached_vma->vma).  If we do,
	     * *then* feel safe enough to delete the intervening
	     * entries.  If we do not -- we can only add a new entry,
	     * then continue to process the rest of our list -- so goto
	     * the top of the loop where we add new entries -- ugh!!!
	     */
	    tmp_cached_vma = cached_vma;

	    found = 0;
	    while (tmp_cached_vma) {
		if (vma_addr == value_addr(tmp_cached_vma->vma)) {
		    found = 1;
		    break;
		}
		tmp_cached_vma = tmp_cached_vma->next;
	    }

	    if (!found) {
		/* XXX: teleport! */
		goto do_new_unmatched;
	    }

	    /* Otherwise, proceed to delete the intermediate ones. */

	    tmp_cached_vma = cached_vma;

	    while (tmp_cached_vma && vma_addr != value_addr(tmp_cached_vma->vma)) {
		/*
		 * Update list/metadata:
		 */
		if (cached_vma_prev) {
		    cached_vma_prev->next = tmp_cached_vma->next;
		    if (tmp_cached_vma->next && tmp_cached_vma->next->vma) 
			cached_vma_prev->next_vma_addr = 
			    value_addr(tmp_cached_vma->next->vma);
		    else
			cached_vma_prev->next_vma_addr = 0;
		}
		else {
		    xvpstate->vma_cache = tmp_cached_vma->next;
		    if (tmp_cached_vma->next && tmp_cached_vma->next->vma) 
			xvpstate->vma_cache->next_vma_addr = 
			    value_addr(tmp_cached_vma->next->vma);
		    else
			cached_vma_prev->next_vma_addr = 0;
		}

		tmp_cached_vma_d = tmp_cached_vma;

		tmp_cached_vma = tmp_cached_vma->next;
		--xvpstate->vma_len;

		vdebug(5,LA_TARGET,LF_XVP,
		       "removing stale memrange(%s:%s:0x%"PRIxADDR",0x%"PRIxADDR","
		       "%"PRIiOFFSET",%u)\n",
		       tmp_cached_vma_d->range->region->name,
		       REGION_TYPE(tmp_cached_vma_d->range->region->type),
		       tmp_cached_vma_d->range->start,
		       tmp_cached_vma_d->range->end,
		       tmp_cached_vma_d->range->offset,
		       tmp_cached_vma_d->range->prot_flags);

		/* delete range; delete empty regions when they empty. */
		region = tmp_cached_vma_d->range->region;
		memrange_free(tmp_cached_vma_d->range);
		if (list_empty(&region->ranges))
		    memregion_free(region);

		/* delete cached value stuff */
		value_free(tmp_cached_vma_d->vma);
		free(tmp_cached_vma_d);
		tmp_cached_vma_d = NULL;
	    }

	    cached_vma = tmp_cached_vma;

	    /*
	     * Now that we deleted any stale/dead mmaps, check if we
	     * still have a cached vma.  If we do, and it is ==
	     * vma_addr, just continue the outer loop; handled by third
	     * case of outer loop.
	     */
	    if (cached_vma && vma_addr == value_addr(cached_vma->vma)) {
		vdebug(5,LA_TARGET,LF_XVP,
		       "continuing loop; cached_vma matches vma_addr (0x%"PRIxADDR");"
		       " memrange(%s:%s:0x%"PRIxADDR",0x%"PRIxADDR","
		       "%"PRIiOFFSET",%u)\n",
		       vma_addr,cached_vma->range->region->name,
		       REGION_TYPE(cached_vma->range->region->type),
		       cached_vma->range->start,cached_vma->range->end,
		       cached_vma->range->offset,cached_vma->range->prot_flags);
		continue;
	    }
	    /*
	     * Otherwise, we need to add a new one (handled by first
	     * case of main loop).
	     */
	    else if (cached_vma) {
		vdebug(5,LA_TARGET,LF_XVP,
		       "continuing loop; cached_vma does not match vma_addr (0x%"PRIxADDR");"
		       " cached_vma memrange(%s:%s:0x%"PRIxADDR",0x%"PRIxADDR","
		       "%"PRIiOFFSET",%u)\n",
		       vma_addr,cached_vma->range->region->name,
		       REGION_TYPE(cached_vma->range->region->type),
		       cached_vma->range->start,cached_vma->range->end,
		       cached_vma->range->offset,cached_vma->range->prot_flags);
		continue;
	    }
	    else {
		vdebug(5,LA_TARGET,LF_XVP,
		       "continuing loop; no more cached_vmas; all others will"
		       " be new!\n");
		continue;
	    }
	}
    }

    if (!is_initial) {
	/*
	 * For each loaded region, load one or more debugfiles and associate
	 * them with the region.  Also generate events.
	 */
	
    }

    /*
     * Clear the new/existing/same/updated bits no matter what.
     */

    return 0;

 err:
    // XXX cleanup the regions we added/modified??
    return -1;

 err_vmiload:
    return -1;
}

static int xen_vm_process_loadregions(struct target *target,
				      struct addrspace *space) {
    return __xen_vm_process_loadregions(target,space,1);
}

static int xen_vm_process_loaddebugfiles(struct target *target,
					 struct addrspace *space,
					 struct memregion *region) {
    int retval = -1;
    struct debugfile *debugfile = NULL;
    char rbuf[PATH_MAX];
    char *file;
    struct lsymbol *mainsymbol;
    int bfn = 0;
    int bfpn = 0;

    vdebug(5,LA_TARGET,LF_XVP,"tid %d\n",target->base_tid);

    if (!(region->type == REGION_TYPE_MAIN 
	  || region->type == REGION_TYPE_LIB)) {
	vdebug(4,LA_TARGET,LF_XVP,"region %s is not MAIN nor LIB; skipping!\n",
	       region->name);
	return 0;
    }

    if (!region->name || strlen(region->name) == 0)
	return -1;

    /* Try to find it, given all our paths and prefixes... */
    if (!debugfile_search_path(region->name,target->spec->debugfile_root_prefix,
			       NULL,NULL,rbuf,PATH_MAX)) {
	verror("could not find debugfile for region '%s': %s\n",
	       region->name,strerror(errno));
	return -1;
    }
    file = rbuf;

    debugfile = debugfile_from_file(file,
				    target->spec->debugfile_root_prefix,
				    target->spec->debugfile_load_opts_list);
    if (!debugfile)
	goto out;

    if (target_associate_debugfile(target,region,debugfile)) 
	goto out;

    /*
     * Try to figure out which binfile has the info we need.  On
     * different distros, they're stripped different ways.
     */
    if (debugfile->binfile_pointing) {
	binfile_get_root_scope_sizes(debugfile->binfile,&bfn,NULL,NULL,NULL);
	binfile_get_root_scope_sizes(debugfile->binfile_pointing,&bfpn,
				     NULL,NULL,NULL);
	if (bfpn > bfn) {
	    RHOLD(debugfile->binfile_pointing,region);
	    region->binfile = debugfile->binfile_pointing;
	}
    }

    if (!region->binfile) {
	RHOLD(debugfile->binfile,region);
	region->binfile = debugfile->binfile;
    }

    /*
     * Change type to REGION_TYPE_MAIN if it had a main() function.
     */
    if (region->type == REGION_TYPE_LIB) {
	mainsymbol = debugfile_lookup_sym(debugfile,"main",NULL,NULL,SYMBOL_TYPE_FUNC);
	if (mainsymbol) {
	    if (!mainsymbol->symbol->isdeclaration)
		region->type = REGION_TYPE_MAIN;
	    lsymbol_release(mainsymbol);
	}
    }

    /*
     * Propagate some binfile info...
     */
    region->base_phys_addr = region->binfile->base_phys_addr;
    region->base_virt_addr = region->binfile->base_virt_addr;

    retval = 0;

 out:
    return retval;
    
}
    /* Once regions and debugfiles are loaded, we call this -- it's a
     * second-pass init, basically.
     */
static int xen_vm_process_postloadinit(struct target *target) {

    return 0;
}

static int _xen_vm_process_active_memory_post_handler(struct probe *probe,
						      void *handler_data,
						      struct probe *trigger) {
    return 0;
}

static int xen_vm_process_set_active_probing(struct target *target,
					     active_probe_flags_t flags) {
    struct xen_vm_process_state *xvpstate = \
	(struct xen_vm_process_state *)target->state;
    struct xen_vm_state *xstate = \
	(struct xen_vm_state *)target->base->state;
    int retval = 0;

#if 0
    if ((flags & ACTIVE_PROBE_FLAG_MEMORY) 
	!= (target->active_probe_flags & ACTIVE_PROBE_FLAG_MEMORY)) {
	if (flags & ACTIVE_PROBE_FLAG_MEMORY) {
	    ;
	    if (!(xvpstate->active_memory_probe_mmap = 
		  linux_syscall_probe(target->base,target->base_tid,
				      "sys_mmap",NULL,
				      _xen_vm_process_active_memory_post_handler,
				      target))) {
		if (errno != ENOSYS) {
		    verror("could not register syscall probe on mmap;!\n");
		    --retval;
		}
	    }
	    //else if ...

	    if (retval < 0) {
		goto unprobe;
	    }
	    else {
		target->active_probe_flags |= ACTIVE_PROBE_FLAG_MEMORY;
	    }
	}
	else {
	unprobe:
	    if (xvpstate->active_memory_probe_uselib) {
		probe_free(xvpstate->active_memory_probe_uselib,0);
		xvpstate->active_memory_probe_uselib = NULL;
	    }
	    if (xvpstate->active_memory_probe_munmap) {
		probe_free(xvpstate->active_memory_probe_munmap,0);
		xvpstate->active_memory_probe_munmap = NULL;
	    }
	    if (xvpstate->active_memory_probe_mmap) {
		probe_free(xvpstate->active_memory_probe_mmap,0);
		xvpstate->active_memory_probe_mmap = NULL;
	    }
	    if (xvpstate->active_memory_probe_mprotect) {
		probe_free(xvpstate->active_memory_probe_mprotect,0);
		xvpstate->active_memory_probe_mprotect = NULL;
	    }
	    if (xvpstate->active_memory_probe_mremap) {
		probe_free(xvpstate->active_memory_probe_mremap,0);
		xvpstate->active_memory_probe_mremap = NULL;
	    }
	    if (xvpstate->active_memory_probe_mmap_pgoff) {
		probe_free(xvpstate->active_memory_probe_mmap_pgoff,0);
		xvpstate->active_memory_probe_mmap_pgoff = NULL;
	    }
	    if (xvpstate->active_memory_probe_madvise) {
		probe_free(xvpstate->active_memory_probe_madvise,0);
		xvpstate->active_memory_probe_madvise = NULL;
	    }
	    target->active_probe_flags &= ~ACTIVE_PROBE_FLAG_MEMORY;
	}
    }
#endif

    if ((flags & ACTIVE_PROBE_FLAG_THREAD_ENTRY) 
	!= (target->active_probe_flags & ACTIVE_PROBE_FLAG_THREAD_ENTRY)) {
	if (flags & ACTIVE_PROBE_FLAG_THREAD_ENTRY) {
	    --retval;

	    verror("cannot enable active thread_entry probes; unsupported!\n");
	}
	else {
	    target->active_probe_flags &= ~ACTIVE_PROBE_FLAG_THREAD_ENTRY;
	}
    }

    if ((flags & ACTIVE_PROBE_FLAG_THREAD_EXIT) 
	!= (target->active_probe_flags & ACTIVE_PROBE_FLAG_THREAD_EXIT)) {
	if (flags & ACTIVE_PROBE_FLAG_THREAD_EXIT) {
	    --retval;

	    verror("cannot enable active thread_exit probes; unsupported!\n");
	}
	else {
	    target->active_probe_flags &= ~ACTIVE_PROBE_FLAG_THREAD_EXIT;
	}
    }

    return retval;
}

#define EF_TF (0x00000100)
#define EF_IF (0x00000200)
#define EF_RF (0x00010000)

static target_status_t xen_vm_process_overlay_event(struct target *overlay,
						    tid_t tid,ADDR ipval,
						    int *again) {
    struct target_thread *tthread;
    struct target_thread *uthread;
    struct xen_vm_thread_state *xtstate;
    struct probepoint *dpp;
    struct addrspace *space;
    struct xen_vm_state *xstate;

    xstate = (struct xen_vm_state *)overlay->base->state;
    uthread = target_lookup_thread(overlay->base,tid);
    xtstate = (struct xen_vm_thread_state *)uthread->state;

    tthread = target_lookup_thread(overlay,tid);

    target_clear_state_changes(overlay);

    /*
     * If not active probing memory, we kind of want to update our
     * addrspaces aggressively (by checking the module list) so that
     * if a user lookups a module symbol, we already have it.
     *
     * Active probing memory for the Xen target is a big win.
     */
    if (!(overlay->active_probe_flags & ACTIVE_PROBE_FLAG_MEMORY)) {
	list_for_each_entry(space,&overlay->spaces,space) {
	    __xen_vm_process_loadregions(overlay,space,0);
	}
    }

    /* It will be loaded and valid; so just read regs and handle. */
    if (xtstate->context.debugreg[6] & 0x4000
	|| xtstate->context.user_regs.eflags & EF_TF
	|| (xstate->hvm && xstate->hvm_monitor_trap_flag_set)) {
	if (xtstate->context.debugreg[6] & 0x4000)
	    vdebug(3,LA_TARGET,LF_XVP,"new single step debug event\n");
	else
	    vdebug(3,LA_TARGET,LF_XVP,"inferred single step debug event\n");

	if (!tthread->tpc) {
	    verror("unexpected singlestep event at ip 0x%"PRIxADDR
		   " in tid %"PRIiTID"!\n",
		   ipval,tid);
	    goto out_err;
	}

	/*
	 * If this was supposed to be a single step in userspace, but
	 * instead we have stepped into the kernel, we have to abort the
	 * single step.  This can only happen in the HVM case when we
	 * use the Monitor Trap Flag.
	 */
	if (xstate->hvm && xstate->hvm_monitor_trap_flag_set
	    && ipval >= xstate->kernel_start_addr) {
	    vdebug(8,LA_TARGET,LF_XVP,
		   "single step event in overlay tid %"PRIiTID" INTO KERNEL"
		   " (at 0x%"PRIxADDR"); aborting breakpoint singlestep;"
		   " will be hit again!\n",
		   tid,ipval);
	    overlay->interrupted_ss_handler(overlay,tthread,
					    tthread->tpc->probepoint);
	}
	else
	    overlay->ss_handler(overlay,tthread,tthread->tpc->probepoint);

	/* Clear the status bits right now. */
	xtstate->context.debugreg[6] = 0;
	uthread->dirty = 1;
	tthread->dirty = 1;
	/*
	 * MUST DO THIS.  If we are going to modify both the
	 * current thread's CPU state possibly, and possibly
	 * operate on the global thread's CPU state, we need
	 * to clear the global thread's debug reg status
	 * here; this also has the important side effect of
	 * forcing a merge of the global thread's debug reg
	 * state; see flush_global_thread !
	 */
	/*
	gtstate->context.debugreg[6] = 0;
			target->global_thread->dirty = 1;
			vdebug(5,LA_TARGET,LF_XV,"cleared status debug reg 6\n");
	*/
	goto out_ss_again;
    }
    else {
	vdebug(3,LA_TARGET,LF_XVP,"new (breakpoint?) debug event\n");

	dpp = (struct probepoint *)				\
	    g_hash_table_lookup(overlay->soft_probepoints,
				(gpointer)(ipval - overlay->breakpoint_instrs_len));
	if (dpp) {
	    /* Run the breakpoint handler. */
	    overlay->bp_handler(overlay,tthread,dpp,
				xtstate->context.debugreg[6] & 0x4000);

	    /* Clear the status bits right now. */
	    xtstate->context.debugreg[6] = 0;
	    uthread->dirty = 1;
	    tthread->dirty = 1;
	    vdebug(5,LA_TARGET,LF_XVP,"cleared status debug reg 6\n");

	    goto out_bp_again;
	}
    }

 out_err:
    if (again)
	*again = 0;
    return TSTATUS_ERROR;

 out_bp_again:
    if (again)
	*again = 1;
    return TSTATUS_PAUSED;

 out_ss_again:
    if (again)
	*again = 2;
    return TSTATUS_PAUSED;
}

static int xen_vm_process_attach_evloop(struct target *target,
					struct evloop *evloop) {
    return 0;
}

static int xen_vm_process_detach_evloop(struct target *target) {
    return 0;
}

static target_status_t xen_vm_process_status(struct target *target) {
    return TSTATUS_RUNNING;
}

static int xen_vm_process_pause(struct target *target,int nowait) {
    int rc;

    rc = target_pause(target->base);
    if (rc) 
	return rc;
    target_set_status(target,target->base->status);

    return 0;
}

static int xen_vm_process_resume(struct target *target) {
    int rc;

    rc = target_resume(target->base);
    if (rc) 
	return rc;
    target_set_status(target,target->base->status);

    return 0;
}

static unsigned char *xen_vm_process_read(struct target *target,
					  ADDR addr,
					  unsigned long length,
					  unsigned char *buf) {
    return xen_vm_read_pid(target->base,target->base_tid,addr,length,buf);
}

static unsigned long xen_vm_process_write(struct target *target,
					  ADDR addr,
					  unsigned long length,
					  unsigned char *buf) {
    return xen_vm_write_pid(target->base,target->base_tid,addr,length,buf);
}

static char *xen_vm_process_reg_name(struct target *target,REG reg) {
    return target->base->ops->regname(target->base,reg);
}

static REG xen_vm_process_dwregno_targetname(struct target *target,char *name) {
    return target->base->ops->dwregno_targetname(target->base,name);
}

static REG xen_vm_process_dw_reg_no(struct target *target,common_reg_t reg) {
    return target->base->ops->dwregno(target->base,reg);
}

static tid_t xen_vm_process_gettid(struct target *target) {
    struct target_thread *tthread;

    // XXX: fix!
    return target->base_tid;

    if (target->current_thread && target->current_thread->valid)
	return target->current_thread->tid;

    tthread = xen_vm_process_load_current_thread(target,0);
    if (!tthread) {
	verror("could not load current thread to get TID!\n");
	return 0;
    }

    return tthread->tid;
}

static void xen_vm_process_free_thread_state(struct target *target,void *state) {
    if (state)
	free(state);
}

/*
 * XXX:
 *
 * Need to load/unload any new/stale threads in this function;
 * everything calls it, basically.  We need to keep a state bit in the
 * xen_vm_process_state struct saying if we scanned the list this pass
 * yet or not (and we can replace this with active probing, of course).
 */
static int __is_our_tid(struct target *target,tid_t tid) {
    if (g_hash_table_lookup(target->threads,(gpointer)(uintptr_t)tid))
	return 1;
    return 0;
}

/* XXX: obviously, need to reload the tgid list. */
static struct array_list *
xen_vm_process_list_available_tids(struct target *target) {
    struct array_list *retval;

    retval = array_list_create(1);
    array_list_append(retval,(void *)(uintptr_t)target->base_tid);

    return retval;
}

static struct target_thread *
xen_vm_process_load_thread(struct target *target,tid_t tid,int force) {
    if (!__is_our_tid(target,tid)) {
	verror("tid %d is not in tgid %d!\n",tid,target->base_tid);
	errno = ESRCH;
	return NULL;
    }

    if (!target_load_thread(target->base,tid,force))
	return NULL;

    return target_lookup_thread(target,tid);
}

static struct target_thread *
xen_vm_process_load_current_thread(struct target *target,int force) {
    struct target_thread *uthread;

    uthread = target_load_current_thread(target->base,force);
    if (!uthread) {
	verror("could not load base target current thread: %s\n",
	       strerror(errno));
	target->current_thread = NULL;
	return NULL;
    }

    /* XXX: should we return the primary thread, or NULL? */
    if (!__is_our_tid(target,uthread->tid)) {
	vwarnopt(9,LA_TARGET,LF_XVP,
		 "base target current tid %d is not in tgid %d!\n",
		 uthread->tid,target->base_tid);
	errno = ESRCH;
	target->current_thread = NULL;
	return NULL;
    }

    target->current_thread = target_lookup_thread(target,uthread->tid);

    return target->current_thread;
}

/* XXX: need to actually do them all! */
static int xen_vm_process_load_all_threads(struct target *target,int force) {
    if (xen_vm_process_load_thread(target,target->base_tid,force))
	return 0;
    return 1;
}

static int xen_vm_process_load_available_threads(struct target *target,
						 int force) {
    if (xen_vm_process_load_thread(target,target->base_tid,force))
	return 0;
    return -1;
}

static int xen_vm_process_flush_thread(struct target *target,tid_t tid) {
    struct target_thread *tthread;
    int rc;

    tthread = target_lookup_thread(target,tid);
    if (!tthread->dirty)
	return 0;

    if (!__is_our_tid(target,tid)) {
	verror("tid %d is not in tgid %d!\n",tid,target->base_tid);
	errno = ESRCH;
	return -1;
    }

    rc = target->base->ops->flush_thread(target->base,tid);
    if (rc) {
	verror("could not flush base target tid %d: %s\n",tid,strerror(errno));
	return rc;
    }

    tthread->dirty = 0;

    return 0;
}

static int xen_vm_process_flush_current_thread(struct target *target) {
    if (target->current_thread)
	return xen_vm_process_flush_thread(target,target->current_thread->tid);
    return 0;
}

static int xen_vm_process_flush_all_threads(struct target *target) {
    return xen_vm_process_flush_thread(target,target->base_tid);
}

static int xen_vm_process_invalidate_all_threads(struct target *target) {
    return __target_invalidate_all_threads(target);
}

static int xen_vm_process_thread_snprintf(struct target_thread *tthread,
					  char *buf,int bufsiz,
					  int detail,char *sep,char *kvsep) {
    struct target *target;

    target = tthread->target;

    if (!__is_our_tid(target,tthread->tid)) {
	verror("tid %d is not in tgid %d!\n",
	       tthread->tid,tthread->target->base_tid);
	errno = ESRCH;
	return -1;
    }

    return target->base->ops->thread_snprintf(target->base_thread,
					      buf,bufsiz,detail,sep,kvsep);
}

static REGVAL xen_vm_process_read_reg(struct target *target,tid_t tid,REG reg) {
    struct target_thread *base_tthread;

    if (!__is_our_tid(target,tid)) {
	verror("tid %d is not in tgid %d!\n",tid,target->base_tid);
	errno = ESRCH;
	return -1;
    }

    base_tthread = target_load_thread(target->base,tid,0);
    if (base_tthread->tidctxt == THREAD_CTXT_KERNEL
	&& target->base->ops->readreg_tidctxt) {
	if (0 && reg == target->spregno) {
	    vwarn("adjusting stack!\n");
	    return target->base->ops->readreg_tidctxt(target->base,tid,
						      THREAD_CTXT_USER,reg) - 8;
	}
	else {
	    return target->base->ops->readreg_tidctxt(target->base,tid,
						      THREAD_CTXT_USER,reg);
	}
    }

    return target->base->ops->readreg(target->base,tid,reg);
}

static int xen_vm_process_write_reg(struct target *target,tid_t tid,REG reg,
				    REGVAL value) {
    struct target_thread *tthread;
    struct target_thread *base_tthread;

    if (!__is_our_tid(target,tid)) {
	verror("tid %d is not in tgid %d!\n",tid,target->base_tid);
	errno = ESRCH;
	return -1;
    }

    tthread = target_lookup_thread(target,tid);
    tthread->dirty = 1;

    base_tthread = target_load_thread(target->base,tid,0);
    if (base_tthread->tidctxt == THREAD_CTXT_KERNEL
	&& target->base->ops->readreg_tidctxt)
	return target->base->ops->writereg_tidctxt(target->base,tid,
						   THREAD_CTXT_USER,reg,value);

    return target->base->ops->writereg(target->base,tid,reg,value);
}

static GHashTable *xen_vm_process_copy_registers(struct target *target,tid_t tid) {
    if (!__is_our_tid(target,tid)) {
	verror("tid %d is not in tgid %d!\n",tid,target->base_tid);
	errno = ESRCH;
	return NULL;
    }

    return target->base->ops->copy_registers(target->base,tid);
}

/*
 * NB: we return mmods bound to the underlying target -- not to us!
 */
static struct target_memmod *
xen_vm_process_insert_sw_breakpoint(struct target *target,
				    tid_t tid,ADDR addr) {
    struct target_thread *tthread;
    ADDR paddr = 0;

    tthread = target_lookup_thread(target,tid);
    if (!tthread) {
	verror("tid %"PRIiTID" does not exist!\n",tid);
	errno = ESRCH;
	return NULL;
    }

    /*
     * XXX NB: assume for now that anytime we put a breakpoint into a
     * text page in userspace, that this page might be shared between
     * processes.  We could check if the page is writeable, and then not
     * do this, but that will be a rare occurence, so don't bother for
     * now.
     */

    /* Resolve the phys page. */
    if (target_addr_v2p(target->base,tid,addr,&paddr)) {
	verror("could not translate vaddr 0x%"PRIxADDR" in tid %"PRIiTID"!\n",
	       addr,tid);
	return NULL;
    }

    return _target_insert_sw_breakpoint(target->base,tid,paddr,1);
}

static int xen_vm_process_remove_sw_breakpoint(struct target *target,tid_t tid,
					       struct target_memmod *mmod) {
    return target_remove_sw_breakpoint(target->base,tid,mmod);
}

static int xen_vm_process_enable_sw_breakpoint(struct target *target,tid_t tid,
					       struct target_memmod *mmod) {
    return target_enable_sw_breakpoint(target->base,tid,mmod);
}

static int xen_vm_process_disable_sw_breakpoint(struct target *target,tid_t tid,
						struct target_memmod *mmod) {
    return target_disable_sw_breakpoint(target->base,tid,mmod);
}

static int xen_vm_process_change_sw_breakpoint(struct target *target,tid_t tid,
					       struct target_memmod *mmod,
					       unsigned char *code,
					       unsigned long code_len) {
    return target_change_sw_breakpoint(target->base,tid,mmod,code,code_len);
}

static REG xen_vm_process_get_unused_debug_reg(struct target *target,tid_t tid) {
    errno = ENOTSUP;
    return -1;
}

int xen_vm_process_notify_sw_breakpoint(struct target *target,ADDR addr,
					int notification) {
    return target_notify_sw_breakpoint(target->base,addr,notification);
}

int xen_vm_process_singlestep(struct target *target,tid_t tid,int isbp,
			      struct target *overlay) {
    return target->base->ops->singlestep(target->base,tid,isbp,target);
}

int xen_vm_process_singlestep_end(struct target *target,tid_t tid,
				  struct target *overlay) {
    return target->base->ops->singlestep_end(target->base,tid,target);
}
