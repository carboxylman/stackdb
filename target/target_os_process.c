/*
 * Copyright (c) 2013, 2014 The University of Utah
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
#include <glib.h>

#include "common.h"
#include "glib_wrapper.h"
#include "object.h"
#include "binfile.h"
#include "target.h"
#include "target_api.h"
#include "target_event.h"
#include "target_os.h"
#include "target_os_linux_generic.h"
#include "target_os.h"
#include "target_os_process.h"

struct os_process_spec *os_process_build_spec(void) {
    return NULL;
}

void os_process_free_spec(struct os_process_spec *spec) {
    return;
}

/*
 * Prototypes.
 */
static int os_process_snprintf(struct target *target,char *buf,int bufsiz);
static int os_process_init(struct target *target);
static int os_process_postloadinit(struct target *target);
static int os_process_attach(struct target *target);
static int os_process_detach(struct target *target,int stay_paused);
static int os_process_fini(struct target *target);
static int os_process_loadspaces(struct target *target);
static int os_process_loadregions(struct target *target,struct addrspace *space);
static int os_process_loaddebugfiles(struct target *target,
				     struct addrspace *space,
				     struct memregion *region);
static target_status_t
os_process_handle_overlay_exception(struct target *overlay,
				    target_exception_flags_t flags,
				    tid_t tid,ADDR ipval,int *again);
static void os_process_handle_event(struct target *target,
				    struct target_event *event);
static struct target *
os_process_instantiate_overlay(struct target *target,
			       struct target_thread *tthread,
			       struct target_spec *spec,
			       struct target_thread **ntthread);
static struct target_thread *
os_process_lookup_overlay_thread_by_id(struct target *target,int id);
static struct target_thread *
os_process_lookup_overlay_thread_by_name(struct target *target,char *name);

static int os_process_attach_evloop(struct target *target,
				    struct evloop *evloop);
static int os_process_detach_evloop(struct target *target);
static target_status_t os_process_status(struct target *target);
static int os_process_pause(struct target *target,int nowait);
static int os_process_resume(struct target *target);
static unsigned char *os_process_read(struct target *target,ADDR addr,
				      unsigned long length,unsigned char *buf);
static unsigned long os_process_write(struct target *target,ADDR addr,
				      unsigned long length,unsigned char *buf);

static tid_t os_process_gettid(struct target *target);
static void os_process_free_thread_state(struct target *target,void *state);
static struct array_list *os_process_list_available_tids(struct target *target);
static struct target_thread *os_process_load_thread(struct target *target,
						    tid_t tid,int force);
static struct target_thread *os_process_load_current_thread(struct target *target,
							    int force);
static int os_process_load_all_threads(struct target *target,int force);
static int os_process_load_available_threads(struct target *target,int force);
static int os_process_flush_thread(struct target *target,tid_t tid);
static int os_process_flush_current_thread(struct target *target);
static int os_process_flush_all_threads(struct target *target);
static int os_process_thread_snprintf(struct target *target,
				      struct target_thread *tthread,
				      char *buf,int bufsiz,
				      int detail,char *sep,char *kvsep);

static REGVAL os_process_read_reg(struct target *target,tid_t tid,REG reg);
static int os_process_write_reg(struct target *target,tid_t tid,REG reg,
				REGVAL value);
static struct target_memmod *
os_process_insert_sw_breakpoint(struct target *target,
				tid_t tid,ADDR addr);
static int os_process_remove_sw_breakpoint(struct target *target,tid_t tid,
					   struct target_memmod *mmod);
static int os_process_enable_sw_breakpoint(struct target *target,tid_t tid,
					   struct target_memmod *mmod);
static int os_process_disable_sw_breakpoint(struct target *target,tid_t tid,
					    struct target_memmod *mmod);
static int os_process_change_sw_breakpoint(struct target *target,tid_t tid,
					   struct target_memmod *mmod,
					   unsigned char *code,
					   unsigned long code_len);
static REG os_process_get_unused_debug_reg(struct target *target,tid_t tid);
static int os_process_set_hw_breakpoint(struct target *target,tid_t tid,
					REG num,ADDR addr);
static int os_process_set_hw_watchpoint(struct target *target,tid_t tid,
					REG num,ADDR addr,
					probepoint_whence_t whence,
					probepoint_watchsize_t watchsize);
static int os_process_unset_hw_breakpoint(struct target *target,tid_t tid,
					  REG num);
static int os_process_unset_hw_watchpoint(struct target *target,tid_t tid,
					  REG num);
int os_process_disable_hw_breakpoints(struct target *target,tid_t tid);
int os_process_enable_hw_breakpoints(struct target *target,tid_t tid);
int os_process_disable_hw_breakpoint(struct target *target,tid_t tid,
				     REG dreg);
int os_process_enable_hw_breakpoint(struct target *target,tid_t tid,
				    REG dreg);
int os_process_notify_sw_breakpoint(struct target *target,ADDR addr,
				    int notification);
int os_process_singlestep(struct target *target,tid_t tid,int isbp,
			  struct target *overlay);
int os_process_singlestep_end(struct target *target,tid_t tid,
			      struct target *overlay);

struct target_ops os_process_ops = {
    .snprintf = os_process_snprintf,

    .init = os_process_init,
    .fini = os_process_fini,
    .attach = os_process_attach,
    .detach = os_process_detach,
    .kill = NULL,
    .loadspaces = os_process_loadspaces,
    .loadregions = os_process_loadregions,
    .loaddebugfiles = os_process_loaddebugfiles,
    .postloadinit = os_process_postloadinit,

    .set_active_probing = NULL,

    .instantiate_overlay = os_process_instantiate_overlay,
    .lookup_overlay_thread_by_id = os_process_lookup_overlay_thread_by_id,
    .lookup_overlay_thread_by_name = os_process_lookup_overlay_thread_by_name,

    .handle_overlay_exception = os_process_handle_overlay_exception,
    .handle_break = probepoint_bp_handler,
    .handle_step = probepoint_ss_handler,
    .handle_interrupted_step = probepoint_interrupted_ss_handler,
    .handle_event = os_process_handle_event,

    .status = os_process_status,
    .pause = os_process_pause,
    .resume = os_process_resume,
    .monitor = NULL,
    .poll = NULL,
    .read = os_process_read,
    .write = os_process_write,

    .gettid = os_process_gettid,
    .free_thread_state = os_process_free_thread_state,

    /* There are never any untracked threads in this target. */
    .list_available_tids = target_list_tids,
    /* There are never any untracked threads in this target. */
    .load_available_threads = os_process_load_all_threads,
    .load_thread = os_process_load_thread,
    .load_current_thread = os_process_load_current_thread,
    .load_all_threads = os_process_load_all_threads,
    .pause_thread = NULL,
    .flush_thread = os_process_flush_thread,
    .flush_current_thread = os_process_flush_current_thread,
    .flush_all_threads = os_process_flush_all_threads,
    .thread_snprintf = os_process_thread_snprintf,

    .attach_evloop = os_process_attach_evloop,
    .detach_evloop = os_process_detach_evloop,

    .readreg = os_process_read_reg,
    .writereg = os_process_write_reg,
    .insert_sw_breakpoint = os_process_insert_sw_breakpoint,
    .remove_sw_breakpoint = os_process_remove_sw_breakpoint,
    .enable_sw_breakpoint = os_process_enable_sw_breakpoint,
    .disable_sw_breakpoint = os_process_disable_sw_breakpoint,
    .change_sw_breakpoint = os_process_change_sw_breakpoint,
    .get_unused_debug_reg = os_process_get_unused_debug_reg,
    //.set_hw_breakpoint = os_process_set_hw_breakpoint,
    //.set_hw_watchpoint = os_process_set_hw_watchpoint,
    //.unset_hw_breakpoint = os_process_unset_hw_breakpoint,
    //.unset_hw_watchpoint = os_process_unset_hw_watchpoint,
    //.disable_hw_breakpoints = os_process_disable_hw_breakpoints,
    //.enable_hw_breakpoints = os_process_enable_hw_breakpoints,
    //.disable_hw_breakpoint = os_process_disable_hw_breakpoint,
    //.enable_hw_breakpoint = os_process_enable_hw_breakpoint,
    .notify_sw_breakpoint = os_process_notify_sw_breakpoint,
    .singlestep = os_process_singlestep,
    .singlestep_end = os_process_singlestep_end,
};

static int os_process_snprintf(struct target *target,
			       char *buf,int bufsiz) {
    return snprintf(buf,bufsiz,"task(%d)",target->base_tid);
}

static int os_process_init(struct target *target) {
    struct target_thread *base_thread = target->base_thread;
    struct target *base = target->base;
    tid_t base_tid = target->base_tid;

    if (target->spec->stay_paused) {
	verror("OS Process driver cannot leave target process closed on exit!\n");
	errno = EINVAL;
	return -1;
    }

    /*
     * Setup target mode stuff.
     */
    target->threadctl = base->threadctl;
    target->nodisablehwbponss = base->nodisablehwbponss;
    target->live = base->live;
    target->writeable = base->writeable;
    target->mmapable = base->mmapable;
    target->no_adjust_bp_ip = base->no_adjust_bp_ip;
    /* NB: only native arch supported!  i.e., no 32-bit emu on 64-bit host. */
    target->arch = base->arch;

    target->fbregno = base->fbregno;
    target->spregno = base->spregno;
    target->ipregno = base->ipregno;

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
     * Just adjust for the user, don't error :)
     */
    if (target->spec->bpmode == THREAD_BPMODE_STRICT) {
	vwarn("auto-enabling SEMI_STRICT bpmode on Xen Process target.\n");
	target->spec->bpmode = THREAD_BPMODE_SEMI_STRICT;
    }

    /*
     * Initialize our state.
     */
    target->state = calloc(1,sizeof(struct os_process_state));

    /*
     * Don't do anything else here; do it in attach().
     */
    return 0;
}

static int os_process_fini(struct target *target) {
    if (target->state)
	free(target->state);
    return 0;
}

static int os_process_attach(struct target *target) {
    if (target_pause(target->base)) {
	verror("could not pause base target %s!\n",target->base->name);
	return -1;
    }

    target_set_status(target,TSTATUS_PAUSED);

    /*
     * Just grab all the threads in the thread group and create them.
     */
    target->current_thread = target_create_thread(target,target->base_tid,
						  NULL,NULL);
    target_reuse_thread_as_global(target,target->current_thread);

    target_thread_set_status(target->current_thread,THREAD_STATUS_RUNNING);

    return 0;
}

static int os_process_detach(struct target *target,int stay_paused) {
    /*
     * Just detach all our threads.
     */
    return 0;
}

static int os_process_loadspaces(struct target *target) {
    struct os_process_state *ospstate;
    struct target_process *process;
    char nbuf[32];

    ospstate = (struct os_process_state *)target->state;
    /*
     * NB: between os_process_handle_event, os_process_loadregions, and
     * target_os_process_get(), there is a loop!  Break it by not
     * allowing any memory events that are bubbled up into
     * os_process_handle_event() to cause os_process_loadregions() to
     * get called multiple times -- or in this case, right here, we
     * don't want os_process_loadregions() to get called until after
     * os_process_loadspaces() finishes.
     */
    if (ospstate->loading_memory)
	return 0;
    else
	ospstate->loading_memory = 1;

    process = target_os_process_get(target->base,target->base_tid);
    if (!process) {
	verror("could not load process from underlying OS; not updating!\n");
	ospstate->loading_memory = 0;
	return -1;
    }
    snprintf(nbuf,sizeof(nbuf),"os_process(%d)",target->base_tid);
    addrspace_create(target,nbuf,process->space->tag);
    ospstate->loading_memory = 0;

    return 0;
}

static int os_process_loadregions(struct target *target,
				  struct addrspace *space) {
    struct os_process_state *ospstate;
    struct target_process *process;
    GList *t1,*t2,*t11,*t22,*t2x,*t22x;
    struct memregion *region1,*region2;
    struct memrange *range1,*range2;
    struct target_event *event;
    REFCNT trefcnt;

    ospstate = (struct os_process_state *)target->state;
    if (ospstate->loading_memory)
	return 0;
    else
	ospstate->loading_memory = 1;

    process = target_os_process_get(target->base,target->base_tid);
    if (!process) {
	verror("could not load process from underlying OS; not updating!\n");
	ospstate->loading_memory = 0;
	return -1;
    }

    /*
     * Take process->space, and update our target->space to mirror it!
     */

    /* Mark our existing space, regions, and ranges as dead. */
    OBJSDEAD(space,addrspace);

    if (process->space->tag != space->tag) {
	/*
	 * NB: necessary to catch processes whose VM is replaced,
	 * i.e. on exec().  Just update our tag; not much else we can
	 * do.
	 */
	space->tag = process->space->tag;
    }

    /*
     * Now, update, add, or mark live the ones that match.
     */

    /* Now compare the regions and ranges in the spaces: */
    v_g_list_foreach(process->space->regions,t1,region1) {
	v_g_list_foreach(space->regions,t2,region2) {
	    if (region1->type == region2->type
		&& region1->base_load_addr == region2->base_load_addr
		&& ((region1->name == NULL && region2->name == NULL)
		    || (region1->name && region2->name
			&& strcmp(region1->name,region2->name) == 0)))
		break;
	    else
		region2 = NULL;
	}

#warning "generate MOD events"

	if (region2 == NULL) {
	    region2 = memregion_create(space,region1->type,region1->name);
	    event = target_create_event(target,NULL,
					T_EVENT_PROCESS_REGION_NEW,region2);
	    target_broadcast_event(target,event);
	}

	/* Now compare the ranges. */
	v_g_list_foreach(region1->ranges,t11,range1) {
	    v_g_list_foreach(region2->ranges,t22,range2) {
		if (range1->start == range2->start)
		    break;
		else
		    range2 = NULL;
	    }

	    if (range2 == NULL) {
		range2 = memrange_create(region2,range1->start,range1->end,
					 range1->offset,range1->prot_flags);
		event = target_create_event(target,NULL,
					    T_EVENT_PROCESS_RANGE_NEW,range2);
		target_broadcast_event(target,event);
	    }
	    else if (range1->end != range2->end
		     || range1->prot_flags != range2->prot_flags
		     || range1->offset != range2->offset) {
		event = target_create_event(target,NULL,
					    T_EVENT_PROCESS_RANGE_MOD,range2);
		target_broadcast_event(target,event);
		OBJSMOD(range2);
	    }

	    OBJSLIVE(range2,memrange);
	}

	/* Now delete any dead ranges: */
	v_g_list_foreach_safe(region2->ranges,t22,t22x,range2) {
	    if (!OBJLIVE(range2)) {
		event = target_create_event(target,NULL,
					    T_EVENT_PROCESS_RANGE_DEL,range2);
		target_broadcast_event(target,event);

		v_g_list_foreach_remove(region2->ranges,t22,t22x);
		RPUT(range2,memrange,region2,trefcnt);
	    }
	}

	/* Mark the region (and all its ranges) as live. */
	OBJSLIVE(region2,memregion);
    }

    /* Now delete any dead regions: */
    v_g_list_foreach_safe(space->regions,t2,t2x,region2) {
	if (!OBJLIVE(region2)) {
	    event = target_create_event(target,NULL,
					T_EVENT_PROCESS_REGION_DEL,region2);
	    target_broadcast_event(target,event);

	    v_g_list_foreach_remove(space->regions,t2,t2x);
	    RPUT(region2,memregion,space,trefcnt);
	}
    }

    /*
     * Finally, mark it all as live.
     */
    OBJSLIVE(space,addrspace);

    ospstate->loading_memory = 0;

    return 0;
}

static int os_process_loaddebugfiles(struct target *target,
				     struct addrspace *space,
				     struct memregion *region) {
    int retval = -1;
    struct debugfile *debugfile = NULL;
    char rbuf[PATH_MAX];
    char *file;
    struct lsymbol *mainsymbol;
    int bfn = 0;
    int bfpn = 0;

    vdebug(5,LA_TARGET,LF_OSP,"tid %d\n",target->base_tid);

    if (!(region->type == REGION_TYPE_MAIN 
	  || region->type == REGION_TYPE_LIB)) {
	vdebug(4,LA_TARGET,LF_OSP,"region %s is not MAIN nor LIB; skipping!\n",
	       region->name);
	return 0;
    }

    if (!region->name || strlen(region->name) == 0)
	return -1;

    /* Try to find it, given all our paths and prefixes... */
    file = region->name;
    debugfile = debugfile_from_file(file,
				    target->spec->debugfile_root_prefix,
				    target->spec->debugfile_load_opts_list);
    if (!debugfile) {
	if (!debugfile_search_path(region->name,
				   target->spec->debugfile_root_prefix,
				   NULL,NULL,rbuf,PATH_MAX)) {
	    verror("could not find debugfile for region '%s': %s\n",
		   region->name,strerror(errno));
	    return -1;
	}

	file = rbuf;
	debugfile = debugfile_from_file(file,
					target->spec->debugfile_root_prefix,
					target->spec->debugfile_load_opts_list);
	if (!debugfile) {
	    verror("still could not find debugfile for region '%s': %s\n",
		   region->name,strerror(errno));
	    return -1;
	}
    }

    if (target_associate_debugfile(target,region,debugfile)) {
	goto out;
    }

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

    if (!target->arch) {
	target->arch = debugfile->binfile->arch;
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
static int os_process_postloadinit(struct target *target) {

    return 0;
}

static int os_process_set_active_probing(struct target *target,
					 active_probe_flags_t flags) {
    active_probe_flags_t baseflags = 0;

    /*
     * Filter out the default flags according to our personality.
     */
    if (flags & APF_THREAD_ENTRY) {
	flags &= ~APF_THREAD_ENTRY;
	flags |= APF_PROCESS_THREAD_ENTRY;
	/*
	 * Just use the OS thread tracking; it's the same (at least for
	 * Linux -- probably shouldn't assume it in general...
	 */
	baseflags |= APF_OS_THREAD_ENTRY;
    }
    if (flags & APF_THREAD_EXIT) {
	flags &= ~APF_THREAD_EXIT;
	flags |= APF_PROCESS_THREAD_EXIT;
	/*
	 * Just use the OS thread tracking; it's the same (at least for
	 * Linux -- probably shouldn't assume it in general...
	 */
	baseflags |= APF_OS_THREAD_EXIT;
    }
    if (flags & APF_MEMORY) {
	flags &= ~APF_MEMORY;
	flags |= APF_PROCESS_MEMORY;
    }

    /*
     * XXX: only allow user to set/unset process flags; we're going to
     * pass this to underlying target; so the user should not be able to
     * disable anything.  This isn't really good enough... we should
     * track who needs which flags.
     */
    flags &= APF_PROCESS | APF_OS;

    /* XXX: should we pass baseflags | target->base->ap_flags ? */
    return target_set_active_probing(target->base,baseflags);
				     
}

static struct target *
os_process_instantiate_overlay(struct target *target,
			       struct target_thread *tthread,
			       struct target_spec *spec,
			       struct target_thread **ntthread) {
    struct target *overlay;

    if (spec->target_type != TARGET_TYPE_PHP) {
	errno = EINVAL;
	return NULL;
    }

    /*
     * All we want to do here is create the overlay target.
     */
    overlay = target_create("php",spec);

    return overlay;
}

static struct target_thread *
os_process_lookup_overlay_thread_by_id(struct target *target,int id) {
    struct target_thread *retval;

    if (id < 0)
	id = TID_GLOBAL;

    retval = os_process_load_thread(target,id,0);
    if (!retval) {
	if (!errno)
	    errno = ESRCH;
	return NULL;
    }

    return retval;
}

static struct target_thread *
os_process_lookup_overlay_thread_by_name(struct target *target,char *name) {
    struct target_thread *retval = NULL;
    struct target_thread *tthread;
    int rc;
    GHashTableIter iter;

    if ((rc = os_process_load_all_threads(target,0)))
	vwarn("could not load %d threads; continuing anyway!\n",-rc);

    g_hash_table_iter_init(&iter,target->threads);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer)&tthread)) {
	if (tthread == target->global_thread)
	    continue;
	else if (tthread->name && strcmp(tthread->name,name) == 0) {
	    retval = tthread;
	    break;
	}
    }

    if (retval) {
	vdebug(5,LA_TARGET,LF_OSP,
	       "found overlay thread %"PRIiTID"\n",retval->tid);
	return tthread;
    }
    else {
	errno = ESRCH;
	return NULL;
    }
}

#define EF_TF (0x00000100)
#define EF_IF (0x00000200)
#define EF_RF (0x00010000)

static target_status_t 
os_process_handle_overlay_exception(struct target *overlay,
				    target_exception_flags_t flags,
				    tid_t tid,ADDR ipval,int *again) {
    struct target_thread *tthread;
    struct target_thread *uthread;
    struct probepoint *dpp;
    struct os_state *xstate;

    xstate = (struct os_state *)overlay->base->state;

    tthread = target_lookup_thread(overlay,tid);
    if (!tthread) {
	/*
	 * This is a new thread the overlay is insisting we manage!
	 * Just Do It.
	 */
	tthread = target_create_thread(overlay,tid,NULL,NULL);
	target_thread_set_status(tthread,THREAD_STATUS_RUNNING);
	target_attach_overlay_thread(overlay->base,overlay,tid);
    }

    /*
     * If not active probing memory, we kind of want to update our
     * addrspaces aggressively (by checking the underlying OS target's
     * process addrspace) so that if a user lookups a module symbol, we
     * already have it.  Really we should do this more lazily, like if a
     * lookup failed, maybe.
     */
    if (!(overlay->ap_flags & APF_PROCESS_MEMORY)) {
	os_process_loadregions(overlay,(struct addrspace *) \
			                  g_list_nth_data(overlay->spaces,0));
    }

    /* It will be loaded and valid; so just read regs and handle. */
    if (flags & EXCEPTION_SINGLESTEP) {
	vdebug(3,LA_TARGET,LF_OSP,"new single step debug event\n");

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
	if (flags & EXCEPTION_SINGLESTEP_BOGUS) {
	    /*xstate->hvm && xstate->hvm_monitor_trap_flag_set
	      && ipval >= xstate->kernel_start_addr*/
	    vdebug(8,LA_TARGET,LF_OSP,
		   "single step event in overlay tid %"PRIiTID" INTO KERNEL"
		   " (at 0x%"PRIxADDR"); aborting breakpoint singlestep;"
		   " will be hit again!\n",
		   tid,ipval);
	    overlay->ops->handle_interrupted_step(overlay,tthread,
						  tthread->tpc->probepoint);
	}
	else
	    overlay->ops->handle_step(overlay,tthread,tthread->tpc->probepoint);

	OBJSDIRTY(tthread);
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
	vdebug(3,LA_TARGET,LF_OSP,"new (breakpoint?) debug event\n");

	dpp = (struct probepoint *)				\
	    g_hash_table_lookup(overlay->soft_probepoints,
				(gpointer)(ipval - overlay->arch->breakpoint_instrs_len));
	if (dpp) {
	    /* Run the breakpoint handler. */
	    overlay->ops->handle_break(overlay,tthread,dpp,
				       flags & EXCEPTION_BREAKPOINT_STEP);

	    OBJSDIRTY(tthread);
	    vdebug(5,LA_TARGET,LF_OSP,"cleared status debug reg 6\n");

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

static void os_process_handle_event(struct target *target,
				    struct target_event *event) {
    struct addrspace *space;
    target_event_t et;
    struct target_thread *tthread,*othread;

    et = event->type;
    tthread = event->thread;
    space = (struct addrspace *)g_list_nth_data(target->spaces,0);

    if (T_EVENT_IS_OS_PROCESS(event)
	&& (T_EVENT_IS_SPACE(event,OS_PROCESS)
	    || T_EVENT_IS_REGION(event,OS_PROCESS)
	    || T_EVENT_IS_RANGE(event,OS_PROCESS))) {
	/*
	 * We definitely could optimize this, and only handle the
	 * specific change in the event... but eh.
	 */
	os_process_loadregions(target,space);
    }
    else if (et == T_EVENT_OS_THREAD_CREATED
	     || et == T_EVENT_OS_PROCESS_THREAD_CREATED) {
	if (!tthread) {
	    verror("malformed THREAD_CREATED event without thread set!\n");
	    return;
	}
	if (tthread->tid == target->base_tid)
	    /* Ignore our main thread; we already created it. */
	    return;
	if (target_lookup_thread(target,tthread->tid)) {
	    /* Ignore; we already have it (somehow?) */
	    vwarnopt(5,LA_TARGET,LF_OSP,
		     "underlying target tid %d is new; but already have it!\n",
		     tthread->tid);
	    return;
	}
	else {
	    /*
	     * Create a new thread.
	     */
	    target_create_thread(target,tthread->tid,NULL,NULL);
	}
    }
    else if (et == T_EVENT_OS_THREAD_EXITED
	     || et == T_EVENT_OS_THREAD_EXITING
	     || et == T_EVENT_OS_PROCESS_THREAD_EXITED
	     || et == T_EVENT_OS_PROCESS_THREAD_EXITING) {
	if (!tthread) {
	    verror("malformed THREAD_EXIT(ED|ING) event without thread set!\n");
	    return;
	}
	if (tthread->tid == target->base_tid)
	    /* Ignore our main thread; let it get detached with target */
	    return;
	othread = target_lookup_thread(target,tthread->tid);
	if (!othread) {
	    /* Ignore; we never hda it (somehow?) */
	    vwarnopt(5,LA_TARGET,LF_OSP,
		     "underlying target tid %d is exit(ed|ing);"
		     " but we do not have it!\n",tthread->tid);
	    return;
	}
	else {
	    /*
	     * Detach this thread from the target.
	     */
	    target_detach_thread(target,othread);
	}
    }

    return;
}

static int os_process_attach_evloop(struct target *target,
					struct evloop *evloop) {
    return 0;
}

static int os_process_detach_evloop(struct target *target) {
    return 0;
}

static target_status_t os_process_status(struct target *target) {
    return target_status(target->base);
}

static int os_process_pause(struct target *target,int nowait) {
    int rc;

    rc = target_pause(target->base);
    if (rc) 
	return rc;
    target_set_status(target,target->base->status);

    return 0;
}

static int os_process_resume(struct target *target) {
    int rc;

    rc = target_resume(target->base);
    if (rc) 
	return rc;
    target_set_status(target,target->base->status);

    return 0;
}

/*
 * XXX:
 *
 * Need to load/unload any new/stale threads in this function;
 * everything calls it, basically.  We need to keep a state bit in the
 * os_process_state struct saying if we scanned the list this pass
 * yet or not (and we can replace this with active probing, of course).
 */
static int __is_our_tid(struct target *target,tid_t tid) {
    if (g_hash_table_lookup(target->threads,(gpointer)(uintptr_t)tid))
	return 1;
    else
	return 0;
}

static int __we_are_current(struct target *target) {
    if (target->base->current_thread
	&& __is_our_tid(target,target->base->current_thread->tid))
	return 1;
    else
	return 0;
}

static unsigned char *os_process_read(struct target *target,ADDR addr,
				      unsigned long length,unsigned char *buf) {
    ADDR paddr = 0;

    /*
     * If we are the current thread in the base target, this is easy --
     * just read the current thread in the base.  Otherwise, do v2p
     * translation and read phys.
     *
     * XXX: for future, backend API read/write calls probably should
     * have just been parameterized by tid!  But this is what the
     * underlying target would have to do anyway...
     */
    if (__we_are_current(target))
	return target_read_addr(target->base,addr,length,buf);
    else {
	/* Resolve the phys page. */
	if (target_addr_v2p(target->base,target->base_tid,addr,&paddr)) {
	    verror("could not translate vaddr 0x%"PRIxADDR" in tid %"PRIiTID"!\n",
		   addr,target->base_tid);
	    return NULL;
	}

	return target_read_physaddr(target->base,paddr,length,buf);
    }
}

static unsigned long os_process_write(struct target *target,ADDR addr,
				      unsigned long length,unsigned char *buf) {
    ADDR paddr = 0;

    if (__we_are_current(target))
	return target_write_addr(target->base,addr,length,buf);
    else {
	/* Resolve the phys page. */
	if (target_addr_v2p(target->base,target->base_tid,addr,&paddr)) {
	    verror("could not translate vaddr 0x%"PRIxADDR" in tid %"PRIiTID"!\n",
		   addr,target->base_tid);
	    return 0;
	}

	return target_write_physaddr(target->base,paddr,length,buf);
    }
}

static tid_t os_process_gettid(struct target *target) {
    struct target_thread *tthread;

    // XXX: fix!
    return target->base_tid;

    if (target->current_thread && OBJVALID(target->current_thread))
	return target->current_thread->tid;

    tthread = os_process_load_current_thread(target,0);
    if (!tthread) {
	verror("could not load current thread to get TID!\n");
	return 0;
    }

    return tthread->tid;
}

static void os_process_free_thread_state(struct target *target,void *state) {
    if (state)
	free(state);
}

/* XXX: obviously, need to reload the tgid list. */
static struct array_list *
os_process_list_available_tids(struct target *target) {
    struct array_list *retval;

    retval = array_list_create(1);
    array_list_append(retval,(void *)(uintptr_t)target->base_tid);

    return retval;
}

static struct target_thread *
os_process_load_thread(struct target *target,tid_t tid,int force) {
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
os_process_load_current_thread(struct target *target,int force) {
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
	vwarnopt(9,LA_TARGET,LF_OSP,
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
static int os_process_load_all_threads(struct target *target,int force) {
    if (os_process_load_thread(target,target->base_tid,force))
	return 0;
    return 1;
}

static int os_process_load_available_threads(struct target *target,
						 int force) {
    if (os_process_load_thread(target,target->base_tid,force))
	return 0;
    return -1;
}

static int os_process_flush_thread(struct target *target,tid_t tid) {
    struct target_thread *tthread;
    int rc;

    tthread = target_lookup_thread(target,tid);
    if (!OBJDIRTY(tthread))
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

    OBJSCLEAN(tthread);

    return 0;
}

static int os_process_flush_current_thread(struct target *target) {
    if (target->current_thread)
	return os_process_flush_thread(target,target->current_thread->tid);
    return 0;
}

static int os_process_flush_all_threads(struct target *target) {
    struct array_list *tlist;
    void *tid;
    int i;
    int rc = 0;

    tlist = target_list_tids(target);
    array_list_foreach(tlist,i,tid) {
	rc += os_process_flush_thread(target,(tid_t)(uintptr_t)tid);
    }

    return rc;
}

static int os_process_thread_snprintf(struct target *target,
				      struct target_thread *tthread,
				      char *buf,int bufsiz,
				      int detail,char *sep,char *kvsep) {
    if (!__is_our_tid(target,tthread->tid)) {
	verror("tid %d is not in tgid %d!\n",
	       tthread->tid,tthread->target->base_tid);
	errno = ESRCH;
	return -1;
    }

    return target->base->ops->thread_snprintf(target->base,target->base_thread,
					      buf,bufsiz,detail,sep,kvsep);
}

static REGVAL os_process_read_reg(struct target *target,tid_t tid,REG reg) {
    struct target_thread *base_tthread;

    if (!__is_our_tid(target,tid)) {
	verror("tid %d is not in tgid %d!\n",tid,target->base_tid);
	errno = ESRCH;
	return -1;
    }

    base_tthread = target_load_thread(target->base,tid,0);
    if (base_tthread->tidctxt == THREAD_CTXT_KERNEL
	&& target->base->ops->readreg_tidctxt)
	return target->base->ops->readreg_tidctxt(target->base,tid,
						  THREAD_CTXT_USER,reg);
    else
	return target->base->ops->readreg(target->base,tid,reg);
}

static int os_process_write_reg(struct target *target,tid_t tid,REG reg,
				    REGVAL value) {
    struct target_thread *tthread;
    struct target_thread *base_tthread;

    if (!__is_our_tid(target,tid)) {
	verror("tid %d is not in tgid %d!\n",tid,target->base_tid);
	errno = ESRCH;
	return -1;
    }

    tthread = target_lookup_thread(target,tid);
    OBJSDIRTY(tthread);

    base_tthread = target_load_thread(target->base,tid,0);
    if (base_tthread->tidctxt == THREAD_CTXT_KERNEL
	&& target->base->ops->readreg_tidctxt)
	return target->base->ops->writereg_tidctxt(target->base,tid,
						   THREAD_CTXT_USER,reg,value);
    else
	return target->base->ops->writereg(target->base,tid,reg,value);
}

/*
 * NB: we return mmods bound to the underlying target -- not to us!
 */
static struct target_memmod *
os_process_insert_sw_breakpoint(struct target *target,
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

static int os_process_remove_sw_breakpoint(struct target *target,tid_t tid,
					       struct target_memmod *mmod) {
    return target_remove_sw_breakpoint(target->base,tid,mmod);
}

static int os_process_enable_sw_breakpoint(struct target *target,tid_t tid,
					       struct target_memmod *mmod) {
    return target_enable_sw_breakpoint(target->base,tid,mmod);
}

static int os_process_disable_sw_breakpoint(struct target *target,tid_t tid,
						struct target_memmod *mmod) {
    return target_disable_sw_breakpoint(target->base,tid,mmod);
}

static int os_process_change_sw_breakpoint(struct target *target,tid_t tid,
					       struct target_memmod *mmod,
					       unsigned char *code,
					       unsigned long code_len) {
    return target_change_sw_breakpoint(target->base,tid,mmod,code,code_len);
}

static REG os_process_get_unused_debug_reg(struct target *target,tid_t tid) {
    errno = ENOTSUP;
    return -1;
}

int os_process_notify_sw_breakpoint(struct target *target,ADDR addr,
					int notification) {
    return target_notify_sw_breakpoint(target->base,addr,notification);
}

int os_process_singlestep(struct target *target,tid_t tid,int isbp,
			      struct target *overlay) {
    return target->base->ops->singlestep(target->base,tid,isbp,target);
}

int os_process_singlestep_end(struct target *target,tid_t tid,
				  struct target *overlay) {
    return target->base->ops->singlestep_end(target->base,tid,target);
}
