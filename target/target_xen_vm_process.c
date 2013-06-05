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
static char *xen_vm_process_tostring(struct target *target,
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
static char *xen_vm_process_thread_tostring(struct target *target,tid_t tid,int detail,
					    char *buf,int bufsiz);

static REGVAL xen_vm_process_read_reg(struct target *target,tid_t tid,REG reg);
static int xen_vm_process_write_reg(struct target *target,tid_t tid,REG reg,
				    REGVAL value);
static GHashTable *xen_vm_process_copy_registers(struct target *target,tid_t tid);
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
    .tostring = xen_vm_process_tostring,

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
    .list_available_overlay_tids = NULL,
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
    .thread_tostring = xen_vm_process_thread_tostring,

    .attach_evloop = NULL,
    .detach_evloop = NULL,

    .readreg = xen_vm_process_read_reg,
    .writereg = xen_vm_process_write_reg,
    .copy_registers = xen_vm_process_copy_registers,
    //.get_unused_debug_reg = xen_vm_process_get_unused_debug_reg,
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

static char *xen_vm_process_tostring(struct target *target,
				     char *buf,int bufsiz) {
    if (!buf) {
	bufsiz = strlen("lwp()") + 11 + 1;
	buf = malloc(bufsiz*sizeof(char));
    }
    snprintf(buf,bufsiz,"lwp(%d)",target->base_tid);

    return buf;
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
static int xen_vm_process_loadregions(struct target *target,
				      struct addrspace *space) {
    char buf[PATH_MAX];
    int rc;
    char *ret;
    int exists;
    int updated;

    struct target_thread *base_thread = target->base_thread;
    struct xen_vm_thread_state *xtstate = \
	(struct xen_vm_thread_state *)target->base_thread->state;
    struct target *base = target->base;
    tid_t base_tid = target->base_tid;
    struct xen_vm_process_state *xvpstate = \
	(struct xen_vm_process_state *)target->state;
    struct memregion *region,*tregion;
    struct memrange *range,*trange;
    region_type_t rtype;
    struct value *vma_new;
    struct value *vma;
    struct value *vma_prev;
    struct xen_vm_process_vma *cached_vma,*cached_vma_prev;
    ADDR mm_addr;
    ADDR vma_addr;
    ADDR vma_next_addr;
    ADDR start,end,offset;
    unum_t prot_flags;
    ADDR file_addr;
    char *prev_vma_member_name;
    struct value *file_value;

    vdebug(5,LA_TARGET,LF_XVP,"tid %d\n",target->base_tid);

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
    VLV(base,xtstate->task_struct,"mm",LOAD_FLAG_NONE,&mm_addr,NULL,err_vmiload);

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

	    vdebug(3,LA_TARGET,LF_XVP,
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
	    vdebug(3,LA_TARGET,LF_XVP,
		   "removing mm-gone stale region (%s:%s:%s)\n",
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
	vwarn("tid %d's task->mm changed; checking VMAs like normal though!\n",
	      base_tid);

	/* Reload the mm struct first, and re-cache its members. */
	xvpstate->mm_start_brk = 0;
	xvpstate->mm_brk = 0;
	xvpstate->mm_start_stack = 0;
	xvpstate->mm_addr = 0;

	value_free(xvpstate->mm);
	xvpstate->mm = NULL;
	VL(base,xtstate->task_struct,"mm",LOAD_FLAG_AUTO_DEREF,&xvpstate->mm,
	   err_vmiload);
	xvpstate->mm_addr = v_addr(xvpstate->mm);
	VLV(base,xvpstate->mm,"start_brk",LOAD_FLAG_NONE,
	    &xvpstate->mm_start_brk,NULL,err_vmiload);
	VLV(base,xvpstate->mm,"brk",LOAD_FLAG_NONE,
	    &xvpstate->mm_brk,NULL,err_vmiload);
	VLV(base,xvpstate->mm,"start_stack",LOAD_FLAG_NONE,
	    &xvpstate->mm_start_stack,NULL,err_vmiload);

    }
    else if (xvpstate->mm_addr == 0) {
	vdebug(3,LA_TARGET,LF_XVP,"tid %d analyzing mmaps anew.\n",base_tid);

	/* Load the mm struct and cache its members. */
	VL(base,xtstate->task_struct,"mm",LOAD_FLAG_AUTO_DEREF,&xvpstate->mm,
	   err_vmiload);
	xvpstate->mm_addr = v_addr(xvpstate->mm);
	VLV(base,xvpstate->mm,"start_brk",LOAD_FLAG_NONE,
	    &xvpstate->mm_start_brk,NULL,err_vmiload);
	VLV(base,xvpstate->mm,"brk",LOAD_FLAG_NONE,
	    &xvpstate->mm_brk,NULL,err_vmiload);
	VLV(base,xvpstate->mm,"start_stack",LOAD_FLAG_NONE,
	    &xvpstate->mm_start_stack,NULL,err_vmiload);
    }
    else {
	/*
	 * XXX: when value_refresh is implemented, we want to use that
	 * to reload so we can try not to; for now, just do it manually.
	 */
	vdebug(8,LA_TARGET,LF_XVP,"tid %d refreshing task->mm.\n",base_tid);
	//value_refresh(xvpstate->mm,&vdiff,NULL);
	//if (vdiff != VALUE_DIFF_SAME) {

	xvpstate->mm_start_brk = 0;
	xvpstate->mm_brk = 0;
	xvpstate->mm_start_stack = 0;
	xvpstate->mm_addr = 0;

	value_free(xvpstate->mm);
	xvpstate->mm = NULL;
	VL(base,xtstate->task_struct,"mm",LOAD_FLAG_AUTO_DEREF,&xvpstate->mm,
	   err_vmiload);
	xvpstate->mm_addr = v_addr(xvpstate->mm);
	VLV(base,xvpstate->mm,"start_brk",LOAD_FLAG_NONE,
	    &xvpstate->mm_start_brk,NULL,err_vmiload);
	VLV(base,xvpstate->mm,"brk",LOAD_FLAG_NONE,
	    &xvpstate->mm_brk,NULL,err_vmiload);
	VLV(base,xvpstate->mm,"start_stack",LOAD_FLAG_NONE,
	    &xvpstate->mm_start_stack,NULL,err_vmiload);
    }

    /*
     * Now that we have loaded or re-cached our task's mm_struct, we
     * need to loop through its mmaps, and add/delete/modify as
     * necessary.
     */

    /* Now we have a valid task->mm; load the first vm_area_struct pointer. */
    VLV(base,xvpstate->mm,"mmap",LOAD_FLAG_NONE,&vma_addr,NULL,err_vmiload);
    cached_vma = xvpstate->vma_cache;
    cached_vma_prev = NULL;

    /* First time through, the value we load the vm_area_struct value
     * from is the mm_struct; after that, it is the previous
     * vm_area_struct.  The macros in the loop hide this.
     */
    vma_prev = xvpstate->mm;
    prev_vma_member_name = "mmap";

    /* If we have either a vma_addr to process, or a cached_vma, keep going. */
    while (vma_addr || cached_vma) {
	if (vma_addr && !cached_vma) {
	    /*
	     * New entry; load it and add/cache it.
	     */
	    VL(base,vma_prev,prev_vma_member_name,LOAD_FLAG_AUTO_DEREF,
	       &vma,err_vmiload);
	    cached_vma = calloc(1,sizeof(*cached_vma));
	    cached_vma->vma = vma;

	    /* Load the vma's start,end,offset,prot_flags,file,next addr. */
	    VLV(base,vma,"vm_start",LOAD_FLAG_NONE,&start,NULL,err_vmiload);
	    VLV(base,vma,"vm_end",LOAD_FLAG_NONE,&end,NULL,err_vmiload);
	    VLV(base,vma,"vm_page_prot",LOAD_FLAG_NONE,&prot_flags,NULL,err_vmiload);
	    VLV(base,vma,"vm_pgoff",LOAD_FLAG_NONE,&offset,NULL,err_vmiload);
	    VLV(base,vma,"vm_file",LOAD_FLAG_NONE,&file_addr,NULL,err_vmiload);
	    VLV(base,vma,"vm_next",LOAD_FLAG_NONE,&vma_next_addr,NULL,err_vmiload);

	    /* Figure out the region type. */
	    rtype = REGION_TYPE_ANON;
	    region = NULL;
	    buf[0] = '\0';

	    /* If it has a file, load the path! */
	    if (file_addr != 0) {
		file_value = NULL;
		VL(base,vma,"vm_file",LOAD_FLAG_AUTO_DEREF,&file_value,err_vmiload);
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
	    }

	    /* Create the range. */
	    if (!(range = memrange_create(region,start,end,offset,0))) 
		goto err;

	    /*
	     * Either make it the sole entry on list, or add it at tail.
	     * Either way, there is still no cached_vma to process; it's
	     * just that our previous one points to the new tail of the
	     * list for the next iteration.
	     */
	    if (!xvpstate->vma_cache) 
		xvpstate->vma_cache = cached_vma;
	    else {
		cached_vma_prev->next = cached_vma;
		cached_vma_prev->next_vma_addr = vma_addr;
	    }
	    ++xvpstate->vma_len;
	    cached_vma_prev = cached_vma;
	    cached_vma = NULL;

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

	    // XXX: delete range; delete empty regions when they empty.

	}
	else {
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

	    if (vma_addr == v_addr(cached_vma->vma)) {
		/*
		 * XXX: when value_refresh is implemented, we want to use that
		 * to reload so we can try not to; for now, just do it manually.
		 */
		vdebug(8,LA_TARGET,LF_XVP,
		       "tid %d refreshing vm_area_struct at 0x%"PRIxADDR"\n",
		       vma_addr);
		//value_refresh(cached_vma->vma,&vdiff,NULL);
		//if (vdiff != VALUE_DIFF_SAME) {

		xvpstate->mm_start_brk = 0;
		xvpstate->mm_brk = 0;
		xvpstate->mm_start_stack = 0;
		xvpstate->mm_addr = 0;

		value_free(xvpstate->mm);
		xvpstate->mm = NULL;
		VL(base,xtstate->task_struct,"mm",LOAD_FLAG_AUTO_DEREF,&xvpstate->mm,
		   err_vmiload);
	    }
	    else {

	    }
	}
    }

    return 0;

 err:
    // XXX cleanup the regions we added/modified??
    return -1;

 err_vmiload:
    return -1;
}
    /* for each loaded region, load one or more debugfiles and associate
     * them with the region.
     */
static int xen_vm_process_loaddebugfiles(struct target *target,
					 struct addrspace *space,
					 struct memregion *region) {
    int retval = -1;
    struct debugfile *debugfile = NULL;
    char rbuf[PATH_MAX];
    struct stat statbuf;
    char *file;
    int rc;
    struct lsymbol *mainsymbol;

    vdebug(5,LA_TARGET,LF_XVP,"tid %d\n",target->base_tid);

    if (!(region->type == REGION_TYPE_MAIN 
	  || region->type == REGION_TYPE_LIB)) {
	vdebug(4,LA_TARGET,LF_XVP,"region %s is not MAIN nor LIB; skipping!\n",
	       region->name);
	return 0;
    }

    if (!region->name || strlen(region->name) == 0)
	return -1;

    /*
     * If target->debugfile_root_prefix was set, we have to prefix the
     * region's filename with it before we feed it to the debugfile
     * library; the debugfile library will use that prefix for any
     * subsequent loads.
     */
    if (target->spec->debugfile_root_prefix) {
	rc = snprintf(rbuf,PATH_MAX,"%s",target->spec->debugfile_root_prefix);
	snprintf(rbuf + rc,PATH_MAX - rc,"/%s",region->name);

	if (stat(rbuf,&statbuf)) {
	    verror("stat('%s') (for region '%s'): %s\n",
		   rbuf,region->name,strerror(errno));
	    return -1;
	}

	file = rbuf;
    }
    else
	file = region->name;

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
    if (debugfile->binfile_pointing 
	&& symtab_get_size_simple(debugfile->binfile_pointing->symtab) \
	> symtab_get_size_simple(debugfile->binfile->symtab)) {
	RHOLD(debugfile->binfile_pointing,region);
	region->binfile = debugfile->binfile_pointing;
    }
    else {
	RHOLD(debugfile->binfile,region);
	region->binfile = debugfile->binfile;
    }

    /*
     * Change type to REGION_TYPE_MAIN if it had a main() function.
     */
    if (region->type == REGION_TYPE_LIB) {
	mainsymbol = debugfile_lookup_sym(debugfile,"main",NULL,NULL,SYMBOL_TYPE_FUNCTION);
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

static target_status_t xen_vm_process_overlay_event(struct target *overlay,
						    tid_t tid,ADDR ipval,
						    int *again) {
    struct target_thread *tthread;
    struct target_thread *uthread;
    struct xen_vm_thread_state *xtstate;
    struct probepoint *dpp;

    uthread = target_lookup_thread(overlay->base,tid);
    xtstate = (struct xen_vm_thread_state *)uthread->state;

    tthread = target_lookup_thread(overlay,tid);

    /* It will be loaded and valid; so just read regs and handle. */
    if (xtstate->context.debugreg[6] & 0x4000) {
	vdebug(3,LA_TARGET,LF_XVP,"new single step debug event\n");

	if (!tthread->tpc) {
	    verror("unexpected singlestep event at ip 0x%"PRIxADDR
		   " in tid %"PRIiTID"!\n",
		   ipval,tid);
	    goto out_err;
	}

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

static char *xen_vm_process_thread_tostring(struct target *target,tid_t tid,
					    int detail,char *buf,int bufsiz) {
    if (!__is_our_tid(target,tid)) {
	verror("tid %d is not in tgid %d!\n",tid,target->base_tid);
	errno = ESRCH;
	return NULL;
    }

    return target->base->ops->thread_tostring(target->base,tid,detail,
					      buf,bufsiz);
}

static REGVAL xen_vm_process_read_reg(struct target *target,tid_t tid,REG reg) {
    if (!__is_our_tid(target,tid)) {
	verror("tid %d is not in tgid %d!\n",tid,target->base_tid);
	errno = ESRCH;
	return -1;
    }

    return target->base->ops->readreg(target->base,tid,reg);
}

static int xen_vm_process_write_reg(struct target *target,tid_t tid,REG reg,
				    REGVAL value) {
    struct target_thread *tthread;
    int rc;

    if (!__is_our_tid(target,tid)) {
	verror("tid %d is not in tgid %d!\n",tid,target->base_tid);
	errno = ESRCH;
	return -1;
    }

    tthread = target_lookup_thread(target,tid);
    tthread->dirty = 1;
    rc = target->base->ops->writereg(target->base,tid,reg,value);

    return rc;
}

static GHashTable *xen_vm_process_copy_registers(struct target *target,tid_t tid) {
    if (!__is_our_tid(target,tid)) {
	verror("tid %d is not in tgid %d!\n",tid,target->base_tid);
	errno = ESRCH;
	return NULL;
    }

    return target->base->ops->copy_registers(target->base,tid);
}

int xen_vm_process_notify_sw_breakpoint(struct target *target,ADDR addr,
					int notification) {

}

int xen_vm_process_singlestep(struct target *target,tid_t tid,int isbp,
			      struct target *overlay) {
    return target->base->ops->singlestep(target->base,tid,isbp,target);
}

int xen_vm_process_singlestep_end(struct target *target,tid_t tid,
				  struct target *overlay) {
    return target->base->ops->singlestep_end(target->base,tid,target);
}
