/*
 * Copyright (c) 2011-2015 The University of Utah
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

#include "config.h"
#include "common.h"
#include "glib_wrapper.h"
#include "arch.h"

#include "target_api.h"
#include "target.h"
#include "target_os.h"
#include "target_process.h"
#include "probe_api.h"
#include "probe.h"

#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <signal.h>
#include <glib.h>

#include "target_linux_userproc.h"
#ifdef ENABLE_XENSUPPORT
#include "target_xen_vm.h"
#endif
#include "target_os_process.h"
#include "target_php.h"
#include "target_gdb.h"

/**
 ** The generic target API!
 **/

/*
 * Generic function that launches or attaches to a target, given @spec.
 */
struct target *target_instantiate(struct target_spec *spec,
				  struct evloop *evloop) {
    struct target *target = NULL;

    if (spec->target_type == TARGET_TYPE_PTRACE) {
	target = linux_userproc_instantiate(spec,evloop);
    }
#ifdef ENABLE_XENSUPPORT
    else if (spec->target_type == TARGET_TYPE_XEN) {
	target = xen_vm_instantiate(spec,evloop);
    }
#endif
    else if (spec->target_type == TARGET_TYPE_OS_PROCESS) {
	verror("cannot directly instantiate TARGET_TYPE_OS_PROCESS;"
	       " call target_instantiate_overlay instead.\n");
	errno = EINVAL;
	return NULL;
    }
    else if (spec->target_type == TARGET_TYPE_PHP) {
	verror("cannot directly instantiate TARGET_TYPE_PHP;"
	       " call target_instantiate_overlay instead.\n");
	errno = EINVAL;
	return NULL;
    }
    else if (spec->target_type == TARGET_TYPE_GDB) {
	target = gdb_instantiate(spec,evloop);
    }

    if (target) {
	target->spec = spec;
	return target;
    }

    errno = EINVAL;
    return NULL;
}

GList *target_instantiate_and_open(struct target_spec *primary_target_spec,
				   GList *base_target_specs,
				   GList *overlay_target_specs,
				   struct evloop *evloop,
				   GList **error_specs) {
    struct target *primary_target = NULL,*target = NULL,*base_target;
    struct target_spec *spec;
    int i;
    GList *tmp;
    GList *lcopy = NULL;
    GList *retval = NULL;

    i = 0;

    /*
     * Instantiate the primary target first; then the base targets;
     * then the overlay targets.  If an overlay target doesn't have a
     * base target id, then we assume and try the primary target created
     * from the primary target spec; otherwise we fail.
     */

    if (primary_target_spec) {
	primary_target = target_instantiate(primary_target_spec,evloop);
	if (!primary_target) {
	    if (error_specs) {
		vwarn("could not instantiate primary target; skipping!\n");
		*error_specs = g_list_append(*error_specs,primary_target_spec);
	    }
	    else {
		verror("could not instantiate primary target; aborting\n!");
		goto errout;
	    }
	}
	else {
	    if (!target_open(primary_target)) {
		vdebug(5,LA_TARGET,LF_TARGET,"instantiated primary target\n");
		retval = g_list_append(retval,primary_target);
	    }
	    else if (error_specs) {
		vwarn("could not open primary target spec %d\n",i);
		target_close(primary_target);
		target_finalize(primary_target);
		*error_specs = g_list_append(*error_specs,primary_target_spec);
	    }
	    else {
		verror("could not open primary target spec %d\n",i);
		target_close(primary_target);
		target_finalize(primary_target);
		primary_target = NULL;
		goto errout;
	    }
	}
    }

    if (base_target_specs) {
	lcopy = g_list_copy(base_target_specs);
	v_g_list_foreach(lcopy,tmp,spec) {
	    ++i;
	    target = target_instantiate(spec,evloop);

	    if (target) {
		target->spec = spec;
	    }
	    else if (error_specs) {
		vwarn("could not instantiate target spec %d\n",i);
		*error_specs = g_list_append(*error_specs,spec);
	    }
	    else {
		verror("could not instantiate target spec %d\n",i);
		goto errout;
	    }

	    if (!target_open(target)) {
		retval = g_list_append(retval,target);
	    }
	    else if (error_specs) {
		vwarn("could not instantiate target spec %d\n",i);
		target_close(target);
		target_finalize(target);
		*error_specs = g_list_append(*error_specs,spec);
	    }
	    else {
		verror("could not instantiate target spec %d\n",i);
		target_close(target);
		target_finalize(target);
		target = NULL;
		goto errout;
	    }
	}
	g_list_free(lcopy);
	lcopy = NULL;
    }

    if (overlay_target_specs) {
	lcopy = g_list_copy(overlay_target_specs);
	v_g_list_foreach(lcopy,tmp,spec) {
	    ++i;
	    if (spec->base_target_id <= 0)
		base_target = primary_target;
	    else
		base_target = target_lookup_target_id(spec->base_target_id);

	    if (!base_target) {
		if (!error_specs) {
		    verror("could not instantiate overlay target spec %d;"
			   " no base target with id %d\n",
			   i,spec->base_target_id);
		    goto errout;
		}
		else {
		    vwarn("could not instantiate overlay target spec %d;"
			  " no base target with id %d\n",
			  i,spec->base_target_id);
		    *error_specs = g_list_append(*error_specs,spec);
		    continue;
		}
	    }

	    if (spec->base_thread_name) {
		spec->base_thread_id =
		    target_lookup_overlay_thread_by_name(base_target,
							 spec->base_thread_name);
		if (spec->base_thread_id < 0) {
		    if (!error_specs) {
			verror("could not instantiate overlay target spec %d;"
			       " no base target thread named %s\n",
			       i,spec->base_thread_name);
			goto errout;
		    }
		    else {
			vwarn("could not instantiate overlay target spec %d;"
			      " no base target thread named %s\n",
			      i,spec->base_thread_name);
			*error_specs = g_list_append(*error_specs,spec);
		    }
		}
	    }

	    target = target_instantiate_overlay(base_target,
						spec->base_thread_id,spec);
	    if (target) {
		target->spec = spec;
		retval = g_list_append(retval,target);
	    }
	    else if (!error_specs) {
		verror("could not instantiate overlay target spec %d"
		       " on base thread %d\n",
		       i,spec->base_thread_id);
		goto errout;
	    }
	    else {
		vwarn("could not instantiate overlay target spec %d"
		      " on base thread %d\n",
		      i,spec->base_thread_id);
		*error_specs = g_list_append(*error_specs,spec);
	    }

	    if (!target_open(target)) {
		retval = g_list_append(retval,target);
	    }
	    else if (error_specs) {
		vwarn("could not instantiate target spec %d\n",i);
		target_close(target);
		target_finalize(target);
		*error_specs = g_list_append(*error_specs,spec);
	    }
	    else {
		verror("could not instantiate target spec %d\n",i);
		target_close(target);
		target_finalize(target);
		target = NULL;
		goto errout;
	    }
	}
	g_list_free(lcopy);
	lcopy = NULL;
    }

    return retval;

 errout:
    if (lcopy) {
	g_list_free(lcopy);
	lcopy = NULL;
    }
    if (retval) {
	retval = g_list_reverse(retval);
	v_g_list_foreach(retval,tmp,target) {
	    target_finalize(target);
	}
	g_list_free(retval);
    }
    return NULL;
}

GList *target_instantiate_and_open_list(GList *target_specs,
					struct evloop *evloop,
					GList **error_specs) {
    struct target *target = NULL;
    struct target_spec *spec;
    int i;
    GList *tmp,*tmp2;
    GList *lcopy;
    GList *retval = NULL;
    int progress,last_progress;
    struct target *base_target;
    tid_t base_thread_id;

    lcopy = g_list_copy(target_specs);

    /*
     * Instantiate all the base targets first, removing them as we go;
     * then instantiate the overlay targets if there is a matching
     * target, or if any target will accept them.
     */
    i = 0;
    /* Force at least two trips through the loop before we start giving
     * up on lookups.
     */
    progress = 1;
    while (1) {
	last_progress = progress;
	progress = 0;
	v_g_list_foreach_safe(lcopy,tmp,tmp2,spec) {
	    if (spec->target_type == TARGET_TYPE_PTRACE) {
		target = linux_userproc_instantiate(spec,evloop);
	    }
#ifdef ENABLE_XENSUPPORT
	    else if (spec->target_type == TARGET_TYPE_XEN) {
		target = xen_vm_instantiate(spec,evloop);
	    }
#endif
	    else if (spec->target_type == TARGET_TYPE_GDB) {
		target = gdb_instantiate(spec,evloop);
	    }
	    else {
		base_target = target_lookup_target_id(spec->base_target_id);

		if (!base_target && !last_progress) {
		    if (!error_specs) {
			verror("could not lookup base target id %d for"
			       " overlay target spec\n",spec->base_target_id);
			goto errout;
		    }
		    else {
			vwarn("could not lookup base target id %d for"
			       " target spec; skipping\n",spec->base_target_id);
			v_g_list_foreach_remove(lcopy,tmp,tmp2);
			*error_specs = g_list_append(*error_specs,spec);
			continue;
		    }
		}
		else if (!base_target) {
		    /* Try again until there is no progress */
		    continue;
		}

		if (!spec->base_thread_name)
		    base_thread_id = spec->base_thread_id;
		else {
		    base_thread_id =
			target_lookup_overlay_thread_by_name(base_target,
							     spec->base_thread_name);
		    if (base_thread_id < 0) {
			if (!error_specs) {
			    verror("could not lookup base target thread name %s"
				   " for overlay target spec\n",
				   spec->base_thread_name);
			    goto errout;
			}
			else {
			    vwarn("could not lookup base target thread name %s"
				  " for overlay target spec; skipping\n",
				  spec->base_thread_name);
			    v_g_list_foreach_remove(lcopy,tmp,tmp2);
			    *error_specs = g_list_append(*error_specs,spec);
			    continue;
			}
		    }
		}

		target = target_instantiate_overlay(base_target,base_thread_id,
						    spec);
	    }
	}

	if (target) {
	    ++progress;
	    target->spec = spec;
	    retval = g_list_append(retval,target);
	}
	else if (error_specs) {
	    vwarn("could not instantiate target spec %d\n",i);
	    *error_specs = g_list_append(*error_specs,spec);
	}
	else {
	    vwarn("could not instantiate target spec %d\n",i);
	    goto errout;
	}

		v_g_list_foreach_remove(lcopy,tmp,tmp2);
    }

    g_list_free(lcopy);
    return retval;

 errout:
    g_list_free(lcopy);
    if (retval) {
	retval = g_list_reverse(retval);
	v_g_list_foreach(retval,tmp,target) {
	    target_finalize(target);
	}
	g_list_free(retval);
    }
    return NULL;
}

struct target_spec *target_build_spec(target_type_t type,target_mode_t mode) {
    struct target_spec *tspec;

    if (type == TARGET_TYPE_NONE) {
	tspec = calloc(1,sizeof(*tspec));
    }
    else if (type == TARGET_TYPE_PTRACE) {
	tspec = calloc(1,sizeof(*tspec));
	tspec->backend_spec = linux_userproc_build_spec();
    }
#ifdef ENABLE_XENSUPPORT
    else if (type == TARGET_TYPE_XEN) {
	tspec = calloc(1,sizeof(*tspec));
	tspec->backend_spec = xen_vm_build_spec();
    }
#endif
    else if (type == TARGET_TYPE_OS_PROCESS) {
	tspec = calloc(1,sizeof(*tspec));
	tspec->backend_spec = os_process_build_spec();
    }
    else if (type == TARGET_TYPE_PHP) {
	tspec = calloc(1,sizeof(*tspec));
	tspec->backend_spec = php_build_spec();
    }
    else if (type == TARGET_TYPE_GDB) {
	tspec = calloc(1,sizeof(*tspec));
	tspec->backend_spec = gdb_build_spec();
    }
    else {
	errno = EINVAL;
	return NULL;
    }

    tspec->target_id = -1;
    tspec->target_type = type;
    tspec->target_mode = mode;
    tspec->style = PROBEPOINT_FASTEST;
    tspec->kill_on_close_sig = SIGKILL;
    tspec->read_only = 0;

    return tspec;
}

void target_free_spec(struct target_spec *spec) {
    int i;

    if (spec->backend_spec) {
	if (spec->target_type == TARGET_TYPE_PTRACE) {
	    linux_userproc_free_spec((struct linux_userproc_spec *)spec->backend_spec);
	}
#ifdef ENABLE_XENSUPPORT
	else if (spec->target_type == TARGET_TYPE_XEN) {
	    xen_vm_free_spec((struct xen_vm_spec *)spec->backend_spec);
	}
#endif
	else if (spec->target_type == TARGET_TYPE_OS_PROCESS) {
	    os_process_free_spec((struct os_process_spec *)spec->backend_spec);
	}
	else if (spec->target_type == TARGET_TYPE_PHP) {
	    php_free_spec((struct php_spec *)spec->backend_spec);
	}
	else if (spec->target_type == TARGET_TYPE_GDB) {
	    gdb_free_spec((struct gdb_spec *)spec->backend_spec);
	}
    }

    if (spec->debugfile_load_opts_list) {
	for (i = 0; i < array_list_len(spec->debugfile_load_opts_list); ++i) {
	    struct debugfile_load_opts *dlo_list = (struct debugfile_load_opts *) \
		array_list_item(spec->debugfile_load_opts_list,i);
	    debugfile_load_opts_free(dlo_list);
	}
	array_list_free(spec->debugfile_load_opts_list);
	spec->debugfile_load_opts_list = NULL;
    }
    if (spec->infile) {
	free(spec->infile);
	spec->infile = NULL;
    }
    if (spec->outfile) {
	free(spec->outfile);
	spec->outfile = NULL;
    }
    if (spec->errfile) {
	free(spec->errfile);
	spec->errfile = NULL;
    }

    free(spec);
}

target_type_t target_type(struct target *target) {
    return target->spec->target_type;
}

char *target_name(struct target *target) {
    return target->name;
}

int target_id(struct target *target) {
    return target->id;
}

int target_open(struct target *target) {
    int rc;
    struct addrspace *space;
    struct memregion *region;
    char buf[128];
    GList *t1,*t2;

    if (!target->spec) {
	verror("cannot open a target without a specification!\n");
	errno = EINVAL;
	return -1;
    }

    vdebug(5,LA_TARGET,LF_TARGET,"opening target type(%d)\n",target_type(target));

    /*
     * Try to load the user-specified personality if one exists, and if
     * the target did *NOT* load it alrady!
     */
    if (target->spec->personality && !target->personality_ops) {
	vdebug(5,LA_TARGET,LF_TARGET,
	       "loading user-specified personality '%s' (%s)\n",
	       target->spec->personality,target->spec->personality_lib ? : "");
	if ((rc = target_personality_attach(target,target->spec->personality,
					    target->spec->personality_lib))) {
	    verror("Failed to initialize user-specified personality (%d)!\n",rc);
	    return -1;
	}
    }
    else if (target->spec->personality_lib) {
	verror("cannot specify a personality library without a"
	       " personality name!\n");
	errno = EINVAL;
	return -1;
    }

    vdebug(5,LA_TARGET,LF_TARGET,"target type(%d): init\n",target_type(target));
    if ((rc = target->ops->init(target))) {
	return rc;
    }
    SAFE_PERSONALITY_OP_WARN(init,rc,0,target);

    if (target_snprintf(target,buf,sizeof(buf)) < 0)
	target->name = NULL;
    else 
	target->name = strdup(buf);

    if (target->spec->bpmode == THREAD_BPMODE_STRICT && !target->threadctl) {
	verror("cannot init a target in BPMODE_STRICT that does not have"
	       " threadctl!\n");
	errno = ENOTSUP;
	return -1;
    }

    SAFE_TARGET_OP(loadspaces,rc,0,target);
    v_g_list_foreach(target->spaces,t1,space) {
	SAFE_TARGET_OP(loadregions,rc,0,target,space);
    }

    v_g_list_foreach(target->spaces,t1,space) {
	v_g_list_foreach(space->regions,t2,region) {
	    if (region->type == REGION_TYPE_HEAP
		|| region->type == REGION_TYPE_STACK
		|| region->type == REGION_TYPE_VDSO
		|| region->type == REGION_TYPE_VSYSCALL) 
		continue;

	    SAFE_TARGET_OP_WARN_NORET(loaddebugfiles,rc,0,target,space,region);

	    /*
	     * Once the region has been loaded and associated with a
	     * debuginfo file, we calculate the phys_offset of the
	     * loaded code -- which is the base_phys_addr - base_virt_addr
	     * from the ELF program headers.
	     */
	    if (region->type == REGION_TYPE_MAIN)
		region->phys_offset = 0;
	    /*
	     * If it got loaded at the base_phys_addr from the binary,
	     * there is no offset.
	     */
	    else if (region->base_load_addr == region->base_phys_addr)
		region->phys_offset = 0;
	    else
		region->phys_offset = region->base_load_addr		\
		    + (region->base_phys_addr - region->base_virt_addr);

	    vdebug(5,LA_TARGET,LF_TARGET,
		   "target(%s:%s:0x%"PRIxADDR") finished region(%s:%s,"
		   "base_load_addr=0x%"PRIxADDR",base_phys_addr=0x%"PRIxADDR
		   ",base_virt_addr=0x%"PRIxADDR
		   ",phys_offset=%"PRIiOFFSET" (0x%"PRIxOFFSET"))\n",
		   target->name,space->name,space->tag,
		   region->name,REGION_TYPE(region->type),
		   region->base_load_addr,region->base_phys_addr,
		   region->base_virt_addr,region->phys_offset,
		   region->phys_offset);
	}
    }

    SAFE_TARGET_OP(postloadinit,rc,0,target);
    SAFE_TARGET_OP(attach,rc,0,target);

    target->opened = 1;

    /*
     * Set up active probing if requested, once we're opened.
     *
     * NB: it's better if the backend does everything it can to
     * pre-setup active probing -- i.e., making sure the necessary
     * symbols exist, and it will be possible to probe them, in
     * postloadinit().
     */
    SAFE_TARGET_OP(set_active_probing,rc,0,target,target->spec->ap_flags);

    SAFE_TARGET_OP(postopened,rc,0,target);

    return 0;
}

int target_set_active_probing(struct target *target,active_probe_flags_t flags) {
    int rc;

    if (!target->writeable && flags != AFP_NONE) {
	verror("target not writeable; cannot enable any active probing!\n");
	errno = EINVAL;
	return -1;
    }

    if (!target->ops->set_active_probing
	&& !target->personality_ops
	&& !target->personality_ops->set_active_probing) {
	vwarnopt(5,LA_TARGET,LF_TARGET,
		 "no active probing support in target(%s)\n",target->name);
	errno = ENOTSUP;
	return -1;
    }

    SAFE_TARGET_OP(set_active_probing,rc,0,target,flags);

    return rc;
}

struct array_list *target_list_available_overlay_tids(struct target *target,
						      target_type_t type) {
    struct array_list *retval;
    GHashTableIter iter;
    struct target_thread *tthread;

    vdebug(8,LA_TARGET,LF_TARGET,"loading available threads\n");

    if (target_load_available_threads(target,0)) {
	verror("could not load available threads!\n");
	return NULL;
    }

    retval = array_list_create(g_hash_table_size(target->threads));
    g_hash_table_iter_init(&iter,target->threads);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer)&tthread)) {
	if (tthread == target->global_thread)
	    continue;

	if ((type == TARGET_TYPE_NONE && tthread->supported_overlay_types) 
	    || (type & tthread->supported_overlay_types))
	    array_list_append(retval,(void *)(uintptr_t)tthread->tid);
    }
    array_list_compact(retval);

    vdebug(8,LA_TARGET,LF_TARGET,"can overlay available threads\n");

    return retval;
}

struct array_list *target_list_overlays(struct target *target) {
    if (g_hash_table_size(target->overlays) == 0)
	return NULL;

    return array_list_create_from_g_hash_table(target->overlays);
}

tid_t target_lookup_overlay_thread_by_id(struct target *target,int id) {
    struct target_thread *tthread;

    if (!target->ops->lookup_overlay_thread_by_id) {
	verror("no overlay support in target(%s)!\n",target->name);
	errno = ENOTSUP;
	return -1;
    }

    vdebug(16,LA_TARGET,LF_TARGET,"target(%s)\n",target->name);

    tthread = target->ops->lookup_overlay_thread_by_id(target,id);
    if (tthread)
	return tthread->tid;

    if (!errno)
	errno = ESRCH;
    return -1;
}

tid_t target_lookup_overlay_thread_by_name(struct target *target,char *name) {
    struct target_thread *tthread;

    if (!target->ops->lookup_overlay_thread_by_name) {
	verror("no overlay support in target(%s)!\n",target->name);
	errno = ENOTSUP;
	return -1;
    }

    vdebug(16,LA_TARGET,LF_TARGET,"target(%s)\n",target->name);

    tthread = target->ops->lookup_overlay_thread_by_name(target,name);
    if (tthread)
	return tthread->tid;

    if (!errno)
	errno = ESRCH;
    return -1;
    
}

struct target_spec *target_build_default_overlay_spec(struct target *target,
						      tid_t tid) {
    struct target_spec *retval;

    vdebug(16,LA_TARGET,LF_TARGET,
	   "target(%s) tid %"PRIiTID"\n",target->name,tid);

    if (!target->ops->build_default_overlay_spec) {
	errno = ENOTSUP;
	return NULL;
    }

    retval = target->ops->build_default_overlay_spec(target,tid);
    if (retval && target->writeable == 0 && retval->read_only == 0) {
	verror("base target not writeable; cannot enable writeable overlay!\n");
	errno = EINVAL;
	target_free_spec(retval);
	return NULL;
    }
    else
	return retval;
}

struct target *target_instantiate_overlay(struct target *target,tid_t tid,
					  struct target_spec *spec) {
    struct target *overlay;
    struct target_thread *tthread;
    struct target_thread *ntthread = NULL;

    if (!target->ops->instantiate_overlay) {
	verror("no overlay support in target(%s)!\n",target->name);
	errno = ENOTSUP;
	return NULL;
    }

    if (!target->writeable && !spec->read_only) {
	verror("base target not writeable; cannot enable writeable overlay!\n");
	errno = EINVAL;
	return NULL;
    }

    vdebug(16,LA_TARGET,LF_TARGET,
	   "target(%s) tid %"PRIiTID"\n",target->name,tid);

    if (g_hash_table_lookup(target->overlays,(gpointer)(uintptr_t)tid)
	|| g_hash_table_lookup(target->overlay_aliases,(gpointer)(uintptr_t)tid)) {
	verror("target(%s) tid %"PRIiTID" already has overlay!\n",
	       target->name,tid);
	errno = EALREADY;
	return NULL;
    }

    tthread = target_load_thread(target,tid,0);
    if (!tthread) {
	verror("target(%s) tid %d could not be loaded!\n",target->name,tid);
	errno = ESRCH;
	return NULL;
    }

    overlay = target->ops->instantiate_overlay(target,tthread,spec,&ntthread);
    if (!overlay) {
	verror("target(%s) tid %"PRIiTID" failed to create overlay!\n",
	       target->name,tid);
	return NULL;
    }

    if (ntthread)
	tthread = ntthread;

    overlay->base = target;
    RHOLDW(overlay->base,overlay);
    overlay->base_id = target->id;
    overlay->base_thread = tthread;
    RHOLDW(tthread,overlay);
    overlay->base_tid = tthread->tid;

    g_hash_table_insert(target->overlays,
			(gpointer)(uintptr_t)tthread->tid,overlay);
    RHOLD(overlay,target);

    if (tid == tthread->tid) {
	vdebug(8,LA_TARGET,LF_TARGET,
	       "target(%s) tid %"PRIiTID" new overlay target(%s) (id %d)\n",
	       target->name,tthread->tid,overlay->name,overlay->id);
    }
    else {
	vdebug(8,LA_TARGET,LF_TARGET,
	       "target(%s) tid %"PRIiTID" new overlay target(%s) (id %d)"
	       " (not using user-supplied thread %d; base target overrode it!)\n",
	       target->name,tthread->tid,overlay->name,overlay->id,tid);
    }

    return overlay;
}

int target_snprintf(struct target *target,char *buf,int bufsiz) {
    vdebug(16,LA_TARGET,LF_TARGET,"target(%s)\n",target->name);
    return target->ops->snprintf(target,buf,bufsiz);
}

int target_attach_evloop(struct target *target,struct evloop *evloop) {
    if (target->evloop) {
	verror("an evloop is already associated with target(%s)!\n",
	       target->name);
	errno = EINVAL;
	return -1;
    }
    vdebug(16,LA_TARGET,LF_TARGET,"target(%s)\n",target->name);
    target->evloop = evloop;
    return target->ops->attach_evloop(target,evloop);
}    

int target_detach_evloop(struct target *target) {
    int rc;

    if (!target->evloop) {
	vwarn("no evloop is associated with target(%s)!\n",
	       target->name);
	return -1;
    }

    vdebug(16,LA_TARGET,LF_TARGET,"target(%s)\n",target->name);
    rc = target->ops->detach_evloop(target);

    target->evloop = NULL;

    return rc;
}

int target_is_evloop_attached(struct target *target,struct evloop *evloop) {
    if (target->evloop && evloop && target->evloop == evloop)
	return 1;
    return 0;
}
    
target_status_t target_monitor(struct target *target) {
    if (target->status != TSTATUS_RUNNING) {
	verror("cannot monitor target(%s) in state %s; ERROR!\n",
	       target->name,TSTATUS(target->status));
	return TSTATUS_ERROR;
    }
    target_monitor_clear_global_interrupt();
    vdebug(8,LA_TARGET,LF_TARGET,"monitoring target(%s)\n",target->name);
    return target->ops->monitor(target);
}

int target_monitor_evloop(struct evloop *evloop,struct timeval *timeout,
			  struct target **target,target_status_t *status) {
    struct evloop_fdinfo *fdinfo;
    int hrc;
    int fdtype;
    int rc = 0;
    int nfds;
    struct timeval tv;
    struct target *t;

    target_monitor_clear_global_interrupt();

    if (timeout)
	tv = *timeout;

    while (evloop_maxsize(evloop) > -1) {
	if (target)
	    *target = NULL;
	if (status)
	    *status = TSTATUS_UNKNOWN;
	fdinfo = NULL;
	hrc = 0;
	fdtype = -1;

	vdebug(9,LA_TARGET,LF_TARGET,"monitoring evloop with up to %d FDs\n",
	       evloop_maxsize(evloop));

	/* Always reinit the timeout on new pass */
	if (timeout)
	    *timeout = tv;

	rc = evloop_handleone(evloop,EVLOOP_RETONINT,timeout,
			      &fdinfo,&fdtype,&hrc);

	if (rc < 0) {
	    if (errno == EINTR) {
		/*
		 * Did our default sighandler flag a signal as needing
		 * handling from the user?  If so, return; else keep
		 * going.
		 */
		if (target_monitor_was_interrupted(NULL))
		    break;
		else
		    continue;
	    }
	    else if (errno == EBADF || errno == EINVAL || errno == ENOMEM
		     || errno == ENOENT || errno == EBADSLT || errno == ENOTSUP) {
		vdebug(9,LA_TARGET,LA_TARGET,"evloop_handlone: '%s'\n",
		       strerror(errno));
	    }
	    else {
		vdebug(9,LA_TARGET,LA_TARGET,
		       "evloop_handlone: unexpected error '%s' (%d)\n",
		       strerror(errno),errno);
	    }
	    break;
	}
	else if (rc == 0) {
	    if (fdinfo) {
		/*
		 * Check this target and see if its status is one we
		 * want to punt to the user to notify/handle.
		 */
		if (fdtype == EVLOOP_FDTYPE_R)
		    t = (struct target *)fdinfo->rhstate;
		else if (fdtype == EVLOOP_FDTYPE_W)
		    t = (struct target *)fdinfo->whstate;
		else if (fdtype == EVLOOP_FDTYPE_X)
		    t = (struct target *)fdinfo->xhstate;
		else
		    t = NULL;

		if (t) {
		    if (t->status == TSTATUS_RUNNING
			|| t->status == TSTATUS_PAUSED)
			continue;
		    else
			break;
		}
		else
		    continue;
	    }
	    else if ((nfds = evloop_maxsize(evloop) < 0))
		/* Nothing left. */
		break;
	    else if (nfds) {
		/* Something left; keep going. */
		continue;
	    }
	    else {
		verror("evloop_handleone returned 0 but still FDs to handle!\n");
		errno = EINVAL;
		rc = -1;
		break;
	    }
	}
	else {
	    verror("evloop_handleone returned unexpected code '%d'; aborting!\n",
		   rc);
	    rc = -1;
	    break;
	}
    }

    if (target) {
	if (fdtype == EVLOOP_FDTYPE_R)
	    *target = (struct target *)fdinfo->rhstate;
	else if (fdtype == EVLOOP_FDTYPE_W)
	    *target = (struct target *)fdinfo->whstate;
	else if (fdtype == EVLOOP_FDTYPE_X)
	    *target = (struct target *)fdinfo->xhstate;
	else
	    *target = NULL;
    }
    if (status && *target)
	*status = (*target)->status;

    return rc;
}

target_status_t target_poll(struct target *target,struct timeval *tv,
			    target_poll_outcome_t *outcome,int *pstatus) {
    if (target->status != TSTATUS_RUNNING) {
	verror("cannot poll target(%s) in state %s; ERROR!\n",
	       target->name,TSTATUS(target->status));
	return TSTATUS_ERROR;
    }
    vdebug(8,LA_TARGET,LF_TARGET,"polling target(%s)\n",target->name);
    return target->ops->poll(target,tv,outcome,pstatus);
}
    
int target_resume(struct target *target) {
    if (target->status != TSTATUS_PAUSED && target->status != TSTATUS_EXITING) {
	verror("cannot resume target(%s) in state %s; ERROR!\n",
	       target->name,TSTATUS(target->status));
	return TSTATUS_ERROR;
    }
    if (target->status == TSTATUS_DONE) {
	vwarnopt(8,LA_TARGET,LF_TARGET,
		 "not pausing target(%s); already finished\n",target->name);
	return -1;
    }
    vdebug(8,LA_TARGET,LF_TARGET,"resuming target(%s)\n",target->name);
    return target->ops->resume(target);
}
    
int target_pause(struct target *target) {
    if (target->status == TSTATUS_PAUSED) {
	vdebug(16,LA_TARGET,LF_TARGET,
	       "not pausing target(%s); already paused\n",target->name);
	return 0;
    }
    if (target->status == TSTATUS_DONE) {
	vwarnopt(8,LA_TARGET,LF_TARGET,
		 "not pausing target(%s); already finished\n",target->name);
	return -1;
    }
    vdebug(8,LA_TARGET,LF_TARGET,"pausing target(%s)\n",target->name);
    return target->ops->pause(target,0);
}

int target_is_open(struct target *target) {
    return target->opened;
}

target_status_t target_status(struct target *target) {
    vdebug(9,LA_TARGET,LF_TARGET,
	   "calling backend to get target(%s) status\n",target->name);
    target->status = target->ops->status(target);
    return target->status;
}

unsigned char *target_read_addr(struct target *target,ADDR addr,
				unsigned long length,unsigned char *buf) {
    vdebug(16,LA_TARGET,LF_TARGET,"reading target(%s) at 0x%"PRIxADDR" into %p (%d)\n",
	   target->name,addr,buf,length);
    return target->ops->read(target,addr,length,buf);
}

unsigned long target_write_addr(struct target *target,ADDR addr,
				unsigned long length,unsigned char *buf) {
    vdebug(16,LA_TARGET,LF_TARGET,"writing target(%s) at 0x%"PRIxADDR" (%d)\n",
	   target->name,addr,length);
    if (!target->writeable) {
	verror("target not writeable!\n");
	errno = EINVAL;
	return 0;
    }
    return target->ops->write(target,addr,length,buf);
}

int target_addr_v2p(struct target *target,tid_t tid,ADDR vaddr,ADDR *paddr) {
    if (!target->ops->addr_v2p) {
	vwarn("target(%s) does not support v2p addr translation!\n",target->name);
	errno = ENOTSUP;
	return -1;
    }
    vdebug(16,LA_TARGET,LF_TARGET,
	   "translating v 0x%"PRIxADDR" in tid %"PRIiTID"\n",vaddr,tid);
    return target->ops->addr_v2p(target,tid,vaddr,paddr);
}

unsigned char *target_read_physaddr(struct target *target,ADDR paddr,
				    unsigned long length,unsigned char *buf) {
    if (!target->ops->read_phys) {
	vwarn("target(%s) does not support phys addr reads!\n",target->name);
	errno = ENOTSUP;
	return NULL;
    }
    vdebug(16,LA_TARGET,LF_TARGET,
	   "reading target(%s) at phys 0x%"PRIxADDR" into %p (%d)\n",
	   target->name,paddr,buf,length);
    return target->ops->read_phys(target,paddr,length,buf);
}

unsigned long target_write_physaddr(struct target *target,ADDR paddr,
				    unsigned long length,unsigned char *buf) {
    if (!target->ops->write_phys) {
	vwarn("target(%s) does not support phys addr writes!\n",target->name);
	errno = ENOTSUP;
	return 0;
    }
    vdebug(16,LA_TARGET,LF_TARGET,
	   "writing target(%s) at phys 0x%"PRIxADDR" (%d)\n",
	   target->name,paddr,length);
    if (!target->writeable) {
	verror("target not writeable!\n");
	errno = EINVAL;
	return 0;
    }
    return target->ops->write_phys(target,paddr,length,buf);
}

const char *target_regname(struct target *target,REG reg) {
    vdebug(16,LA_TARGET,LF_TARGET,"target(%s) reg name %d)\n",
	   target->name,reg);
    return arch_regname(target->arch,reg);
}

int target_regno(struct target *target,char *name,REG *reg) {
    vdebug(16,LA_TARGET,LF_TARGET,"target(%s) target reg %s)\n",
	   target->name,name);
    return arch_regno(target->arch,name,reg);
}

int target_cregno(struct target *target,common_reg_t creg,REG *reg) {
    vdebug(16,LA_TARGET,LF_TARGET,"target(%s) common reg %d)\n",
	   target->name,creg);
    return arch_cregno(target->arch,creg,reg);
}

REGVAL target_read_reg(struct target *target,tid_t tid,REG reg) {
    vdebug(16,LA_TARGET,LF_TARGET,"reading target(%s:%"PRIiTID") reg %d)\n",
	   target->name,tid,reg);
    if (target->ops->readreg)
	return target->ops->readreg(target,tid,reg);
    else
	return target->ops->readreg_tidctxt(target,tid,THREAD_CTXT_DEFAULT,reg);
}

int target_write_reg(struct target *target,tid_t tid,REG reg,REGVAL value) {
    vdebug(16,LA_TARGET,LF_TARGET,
	   "writing target(%s:%"PRIiTID") reg %d 0x%"PRIxREGVAL")\n",
	   target->name,tid,reg,value);
    if (!target->writeable) {
	verror("target not writeable!\n");
	errno = EINVAL;
	return -1;
    }
    if (target->ops->writereg)
	return target->ops->writereg(target,tid,reg,value);
    else
	return target->ops->writereg_tidctxt(target,tid,THREAD_CTXT_DEFAULT,
					     reg,value);
}

REGVAL target_read_reg_ctxt(struct target *target,tid_t tid,thread_ctxt_t tidctxt,
			    REG reg) {
    vdebug(16,LA_TARGET,LF_TARGET,
	   "reading target(%s:%"PRIiTID") reg %d tidctxt %d)\n",
	   target->name,tid,reg,tidctxt);
    return target->ops->readreg_tidctxt(target,tid,tidctxt,reg);
}

int target_write_reg_ctxt(struct target *target,tid_t tid,thread_ctxt_t tidctxt,
			  REG reg,REGVAL value) {
    vdebug(16,LA_TARGET,LF_TARGET,
	   "writing target(%s:%"PRIiTID") reg %d tidctxt %d 0x%"PRIxREGVAL")\n",
	   target->name,tid,reg,tidctxt,value);
    if (!target->writeable) {
	verror("target not writeable!\n");
	errno = EINVAL;
	return -1;
    }
    return target->ops->writereg_tidctxt(target,tid,tidctxt,reg,value);
}

REGVAL target_read_creg(struct target *target,tid_t tid,common_reg_t reg) {
    REG treg;

    if (target_cregno(target,reg,&treg))
	return 0;

    return target_read_reg(target,tid,treg);
}

int target_write_creg(struct target *target,tid_t tid,common_reg_t reg,
		      REGVAL value) {
    REG treg;

    if (!target->writeable) {
	verror("target not writeable!\n");
	errno = EINVAL;
	return -1;
    }

    if (target_cregno(target,reg,&treg))
	return 0;

    return target_write_reg(target,tid,treg,value);
}

GHashTable *target_copy_registers(struct target *target,tid_t tid) {
    vdebug(16,LA_TARGET,LF_TARGET,
	   "copying target(%s:%"PRIiTID") regs\n",
	   target->name,tid);
    return target->ops->copy_registers(target,tid);
}

struct array_list *target_list_tids(struct target *target) {
    struct array_list *retval;
    GHashTableIter iter;
    struct target_thread *tthread;
    gpointer key;

    if (g_hash_table_size(target->threads) == 0)
	return NULL;

    retval = array_list_create(g_hash_table_size(target->threads));

    g_hash_table_iter_init(&iter,target->threads);
    while (g_hash_table_iter_next(&iter,&key,(gpointer)&tthread)) {
	if ((tid_t)(uintptr_t)key == TID_GLOBAL
	    && tthread->tid != TID_GLOBAL) 
	    continue;

	array_list_append(retval,(void *)(ptr_t)tthread->tid);
    }

    return retval;
}

struct array_list *target_list_threads(struct target *target) {
    struct array_list *retval;
    GHashTableIter iter;
    struct target_thread *tthread;
    gpointer key;

    retval = array_list_create(g_hash_table_size(target->threads));

    g_hash_table_iter_init(&iter,target->threads);
    while (g_hash_table_iter_next(&iter,&key,(gpointer)&tthread)) {
	if ((tid_t)(uintptr_t)key == TID_GLOBAL
	    && tthread->tid != TID_GLOBAL)
	    continue;

	array_list_append(retval,tthread);
    }

    return retval;
}

GHashTable *target_hash_threads(struct target *target) {
    GHashTable *retval;
    GHashTableIter iter;
    gpointer key;
    struct target_thread *tthread;

    retval = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);

    g_hash_table_iter_init(&iter,target->threads);
    while (g_hash_table_iter_next(&iter,&key,(gpointer)&tthread)) 
	if ((tid_t)(uintptr_t)key == TID_GLOBAL
	    && tthread->tid != TID_GLOBAL)
	    continue;

	g_hash_table_insert(retval,key,tthread);

    return retval;
}

struct array_list *target_list_available_tids(struct target *target) {
    vdebug(12,LA_TARGET,LF_TARGET,"target(%s)\n",target->name);
    return target->ops->list_available_tids(target);
}

GHashTable *target_hash_available_tids(struct target *target) {
    int i;
    struct array_list *tids;
    GHashTable *retval;
    tid_t tid;

    tids = target_list_available_tids(target);
    if (!tids) {
	verror("could not load available tids!\n");
	return NULL;
    }

    retval = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);

    for (i = 0; i < array_list_len(tids); ++i) {
	tid = (tid_t)(ptr_t)array_list_item(tids,i);
	g_hash_table_insert(retval,(gpointer)(ptr_t)tid,(gpointer)(ptr_t)tid);
    }
    array_list_free(tids);

    return retval;
}

int target_load_available_threads(struct target *target,int force) {
    vdebug(12,LA_TARGET,LF_TARGET,"target(%s)\n",target->name);
    return target->ops->load_available_threads(target,force);
}

struct target_thread *target_load_current_thread(struct target *target,
						 int force) {
    vdebug(8,LA_TARGET,LF_TARGET,"loading target(%s) current thread\n",target->name);
    return target->ops->load_current_thread(target,force);
}

struct target_thread *target_load_thread(struct target *target,tid_t tid,
					 int force) {
    vdebug(8,LA_TARGET,LF_TARGET,"loading target(%s:%"PRIiTID") thread\n",
	   target->name,tid);
    return target->ops->load_thread(target,tid,force);
}

int target_load_all_threads(struct target *target,int force) {
    vdebug(8,LA_TARGET,LF_TARGET,"loading all target(%s) threads\n",target->name);
    return target->ops->load_all_threads(target,force);
}

int target_pause_thread(struct target *target,tid_t tid,int nowait) {
    vdebug(12,LA_TARGET,LF_TARGET,"pausing target(%s) thread %"PRIiTID" (nowait=%d)\n",
	   target->name,tid,nowait);
    return target->ops->pause_thread(target,tid,nowait);
}

int target_flush_current_thread(struct target *target) {
    vdebug(8,LA_TARGET,LF_TARGET,"flushing target(%s) current thread\n",target->name);
    return target->ops->flush_current_thread(target);
}

int target_flush_thread(struct target *target,tid_t tid) {
    vdebug(8,LA_TARGET,LF_TARGET,"flushing target(%s:%"PRIiTID") thread\n",
	   target->name,tid);
    return target->ops->flush_thread(target,tid);
}

int target_flush_all_threads(struct target *target) {
    GHashTableIter iter;
    struct target *overlay;
    int rc;

    vdebug(8,LA_TARGET,LF_TARGET,
	   "flushing all target(%s) threads\n",target->name);

    /*
     * Do it for all the overlays first.
     */
    g_hash_table_iter_init(&iter,target->overlays);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer)&overlay)) {
	vdebug(5,LA_TARGET,LF_TARGET,
	       "flushing all overlay target(%s) threads\n",overlay->name);
	rc = target_flush_all_threads(overlay);
	vdebug(5,LA_TARGET,LF_TARGET,
	       "flushing all overlay target(%s) threads (%d)\n",overlay->name,rc);
    }

    if (target->ops->flush_all_threads)
	return target->ops->flush_all_threads(target);
    else {
	errno = ENOTSUP;
	return -1;
    }
}

int target_gc_threads(struct target *target) {
    int rc = 0;
    int i;
    struct array_list *cached_tids;
    GHashTable *real_tids;
    tid_t tid;
    struct target_thread *tthread;

    vdebug(8,LA_TARGET,LF_TARGET,"garbage collecting cached threads (%s)\n",target->name);
    if (target->ops->gc_threads) 
	return target->ops->gc_threads(target);


    cached_tids = target_list_tids(target);
    if (!cached_tids) {
	verror("could not list cached threads!\n");
	return -1;
    }

    real_tids = target_hash_available_tids(target);
    if (!real_tids) {
	verror("could not load currently available threads!\n");
	array_list_free(cached_tids);
	return -1;
    }

    for (i = 0; i < array_list_len(cached_tids); ++i) {
	tid = (tid_t)(ptr_t)array_list_item(cached_tids,i);

	if (tid == TID_GLOBAL)
	    continue;

	if (!g_hash_table_lookup_extended(real_tids,(gpointer)(ptr_t)tid,
					  NULL,NULL)) {
	    if (target->current_thread && target->current_thread->tid == tid) {
		vwarn("thread %d seems to no longer exist, but is the"
		      " current thread; not detaching!\n",tid);
		continue;
	    }

	    vdebug(5,LA_TARGET,LF_TARGET | LF_THREAD,
		   "cached thread %"PRIiTID" no longer exists; detaching!\n",tid);
	    tthread = target_lookup_thread(target,tid);
	    target_detach_thread(target,tthread);
	    ++rc;
	}
    }
    array_list_free(cached_tids);
    g_hash_table_destroy(real_tids);

    if (rc)
	vdebug(5,LA_TARGET,LF_TARGET,"garbage collected %d cached threads (%s)\n",
	       rc,target->name);

    return rc;
}

int target_thread_snprintf(struct target *target,tid_t tid,
			   char *buf,int bufsiz,
			   int detail,char *sep,char *kvsep) {
    struct target_thread *tthread;
    int rc;

    if (!buf) {
	errno = EINVAL;
	return -1;
    }

    vdebug(16,LA_TARGET,LF_TARGET,"target(%s:%"PRIiTID") thread\n",
	   target->name,tid);

    if (!(tthread = target_lookup_thread(target,tid))) {
	verror("thread %"PRIiTID" does not exist?\n",tid);
	return -1;
    }

    if (!sep)
	sep = ",";
    if (!kvsep)
	kvsep = "=";

    if (detail < -1) 
	return snprintf(buf,bufsiz,"tid%s%"PRIiTID,kvsep,tthread->tid);
    else if (detail < 0) 
	return snprintf(buf,bufsiz,"tid%s%"PRIiTID "%s" "name%s%s" "%s"
			"curctxt%s%d" "%s",
			kvsep,tid,sep,kvsep,tthread->name,sep,
			kvsep,tthread->tidctxt,sep);
    else if (!target->ops->thread_snprintf)
	return snprintf(buf,bufsiz,
			"tid%s%"PRIiTID "%s" "name%s%s" "%s" "curctxt%s%d" "%s"
			"ptid%s%"PRIiTID "%s" "tgid%s%"PRIiTID "%s"
			"uid%s%d" "%s" "gid%s%d",
			kvsep,tthread->tid,sep,kvsep,tthread->name,sep, 
			kvsep,tthread->tidctxt,sep, 
			kvsep,tthread->ptid,sep,kvsep,tthread->tgid,sep,
			kvsep,tthread->uid,sep,kvsep,tthread->gid);
    else {
	rc =   snprintf(buf,bufsiz,
			"tid%s%"PRIiTID "%s" "name%s%s" "%s" "curctxt%s%d" "%s"
			"ptid%s%"PRIiTID "%s" "ptid%s%"PRIiTID "%s"
			"uid%s%d" "%s" "gid%s%d" "%s",
			kvsep,tthread->tid,sep,kvsep,tthread->name,sep, 
			kvsep,tthread->tidctxt,sep, 
			kvsep,tthread->ptid,sep,kvsep,tthread->tgid,sep,
			kvsep,tthread->uid,sep,kvsep,tthread->gid,sep);
	if (rc >= bufsiz)
	    rc += target->ops->thread_snprintf(target,tthread,NULL,0,
					       detail,sep,kvsep);
	else
	    rc += target->ops->thread_snprintf(target,tthread,buf + rc,bufsiz - rc,
					       detail,sep,kvsep);
	return rc;
    }
}

void target_dump_thread(struct target *target,tid_t tid,FILE *stream,int detail) {
    char buf[1024];
    struct target_thread *tthread;

    vdebug(16,LA_TARGET,LF_TARGET,"dumping target(%s:%"PRIiTID") thread\n",
	   target->name,tid);

    if (!(tthread = target_lookup_thread(target,tid)))
	verror("thread %"PRIiTID" does not exist?\n",tid);

    if (target_thread_snprintf(target,tid,buf,sizeof(buf),detail,NULL,NULL) < 0)
	fprintf(stream ? stream : stdout,"tid(%"PRIiTID"): <API ERROR>\n",tid);
    else 
	fprintf(stream ? stream : stdout,"tid(%"PRIiTID"): %s\n",tid,buf);
}

void target_dump_all_threads(struct target *target,FILE *stream,int detail) {
    struct target_thread *tthread;
    GHashTableIter iter;

    vdebug(16,LA_TARGET,LF_TARGET,"dumping all target(%s) threads\n",target->name);

    g_hash_table_iter_init(&iter,target->threads);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer)&tthread)) 
	target_dump_thread(target,tthread->tid,stream,detail);
}

int target_close(struct target *target) {
    int rc;
    GHashTableIter iter;
    struct probepoint *probepoint;
    struct target *overlay;
    struct target_memmod *mmod;
    unsigned int rlen;

    if (!target->opened) {
	vdebug(3,LA_TARGET,LF_TARGET,"target(%s) already closed\n",target->name);
	return target->status;
    }

    vdebug(5,LA_TARGET,LF_TARGET,"closing target(%s)\n",target->name);

    /* Make sure! */
    target_pause(target);

    /*
     * Do it for all the overlays first.
     */
    g_hash_table_iter_init(&iter,target->overlays);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer)&overlay)) {
	vdebug(5,LA_TARGET,LF_TARGET,
	       "closing overlay target(%s)\n",overlay->name);
	rc = target_close(overlay);
	vdebug(5,LA_TARGET,LF_TARGET,
	       "closed overlay target(%s) (%d)\n",overlay->name,rc);
    }

    if (target->evloop)
	target_detach_evloop(target);

    target_flush_all_threads(target);

    /* 
     * We have to free the soft probepoints manually, then remove all.  We
     * can't remove an element during an iteration, but we *can* free
     * the data :).
     */
    vdebug(2,LA_PROBE,LF_PROBEPOINT,"%d soft probepoints to free!\n",
	   g_hash_table_size(target->soft_probepoints));
    g_hash_table_iter_init(&iter,target->soft_probepoints);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer)&probepoint)) {
	probepoint_free_ext(probepoint);
    }
    g_hash_table_remove_all(target->soft_probepoints);

    /*
     * Free the memmods, if any are left.
     */
    g_hash_table_iter_init(&iter,target->mmods);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer)&mmod)) {
	g_hash_table_iter_remove(&iter);

	if (mmod->tmp)
	    free(mmod->tmp);
	/* Breakpoint hack */
	if (mmod->mod && mmod->mod != target->arch->breakpoint_instrs)
	    free(mmod->mod);

	if (mmod->orig) {
	    rlen = target_write_addr(target,mmod->addr,mmod->orig_len,mmod->orig);
	    if (rlen != mmod->orig_len) {
		verror("could not restore orig memory at 0x%"PRIxADDR";"
		       " but cannot do anything!\n",mmod->addr);
	    }
	}

	if (mmod->threads) {
	    array_list_free(mmod->threads);
	}
	if (mmod->orig)
	    free(mmod->orig);

	if (target_notify_sw_breakpoint(target,mmod->addr,0)) {
	    vwarnopt(9,LA_TARGET,LF_TARGET,
		     "sw bp removal notification failed; ignoring\n");
	}

	free(mmod);
    }

    /* XXX: should we deal with memcache?  No, let backends do it. */

    vdebug(5,LA_TARGET,LF_TARGET,"detach target(%s) (stay_paused = %d)\n",
	   target->name,target->spec->stay_paused);
    if ((rc = target->ops->detach(target,target->spec->stay_paused))) {
	verror("detach target(%s) failed: %s\n",target->name,strerror(errno));
    }

    if (target->spec->kill_on_close) 
	target_kill(target,target->spec->kill_on_close_sig);

    /*
     * Don't delete the threads yet; just unset current_thread.
     */
    target->current_thread = NULL;

    target->opened = 0;

    /*
     * Set the target and its core objects to be non-live.
     */
    OBJSDEAD(target,target);

    return target->status;
}

int target_obj_flags_propagate(struct target *target,
			       obj_flags_t orf,obj_flags_t nandf) {
    int retval;
    GHashTableIter iter;
    gpointer vp;
    struct target_thread *tthread;
    GList *t1;
    struct addrspace *space;

    /*
     * Notify all our children -- threads (which have no children),
     * spaces -- and call the target_ops propagation method too, if it
     * exists -- or call the personality method.
     */
    g_hash_table_iter_init(&iter,target->threads);
    while (g_hash_table_iter_next(&iter,NULL,&vp)) {
	tthread = (struct target_thread *)vp;
	tthread->obj_flags |= orf;
	tthread->obj_flags &= ~nandf;
    }

    v_g_list_foreach(target->spaces,t1,space) {
	space->obj_flags |= orf;
	space->obj_flags &= ~nandf;
	addrspace_obj_flags_propagate(space,orf,nandf);
    }

    SAFE_TARGET_OP(obj_flags_propagate,retval,0,target,orf,nandf);

    return retval;
}

int target_kill(struct target *target,int sig) {
    vdebug(5,LA_TARGET,LF_TARGET,"killing target(%s) with %d\n",target->name,sig);
    return target->ops->kill(target,sig);
}

void target_hold(struct target *target) {
    RHOLD(target,target);
}

void target_release(struct target *target) {
    REFCNT trefcnt;
    RPUT(target,target,target,trefcnt);
}

struct probe *target_lookup_probe(struct target *target,int probe_id) {
    return (struct probe *)g_hash_table_lookup(target->probes,
					       (gpointer)(uintptr_t)probe_id);
}

struct action *target_lookup_action(struct target *target,int action_id) {
    return (struct action *)g_hash_table_lookup(target->actions,
						(gpointer)(uintptr_t)action_id);
}

struct target_memmod *_target_insert_sw_breakpoint(struct target *target,
						   tid_t tid,ADDR addr,
						   int is_phys,int nowrite) {
    struct target_memmod *mmod;
    struct target_thread *tthread;

    tthread = target_lookup_thread(target,tid);
    if (!tthread) {
	verror("tid %"PRIiTID" does not exist!\n",tid);
	errno = ESRCH;
	return NULL;
    }

    mmod = target_memmod_lookup(target,tid,addr,is_phys);

    if (mmod) {
	if (mmod->type != MMT_BP) {
	    verror("mmod already at 0x%"PRIxADDR"; but not breakpoint!\n",addr);
	    errno = EADDRINUSE;
	    return NULL;
	}
	else if (mmod->state != MMS_SUBST) {
	    verror("mmod already at 0x%"PRIxADDR"; state is not SUBST (%d)!\n",
		   addr,mmod->state);
	    errno = EBUSY;
	    return NULL;
	}
	else {
	    /* Add us to the threads list if necessary. */
	    if (array_list_find(mmod->threads,tthread) < 0)
		array_list_append(mmod->threads,tthread);
	    else
		vwarn("tid %"PRIiTID" already on threads list; BUG!\n",tid);
	    return mmod;
	}
    }
    else {
	mmod = target_memmod_create(target,tid,addr,is_phys,MMT_BP,
				    target->arch->breakpoint_instrs,
				    target->arch->breakpoint_instrs_len,nowrite);
	if (!mmod) {
	    verror("could not create memmod for tid %"PRIiTID" at 0x%"PRIxADDR"!\n",
		   tid,addr);
	    return NULL;
	}

	if (target_notify_sw_breakpoint(target,addr,1)) 
	    vwarn("sw bp insertion notification failed; ignoring\n");

	return mmod;
    }
}

struct target_memmod *target_insert_sw_breakpoint(struct target *target,
						  tid_t tid,ADDR addr) {
    if (target->ops->insert_sw_breakpoint)
	return target->ops->insert_sw_breakpoint(target,tid,addr);
    else 
	/* Just default to sw breakpoints on virt addrs. */
	return _target_insert_sw_breakpoint(target,tid,addr,0,0);
}

int _target_remove_sw_breakpoint(struct target *target,tid_t tid,
				 struct target_memmod *mmod) {
    int retval;
    ADDR addr;

    addr = mmod->addr;
    retval = target_memmod_release(target,tid,mmod);
    if (retval) {
	verror("could not remove memmod at 0x%"PRIxADDR" for tid %"PRIiTID"\n",
	       addr,tid);
	return -1;
    }

    /* If this was the last thread, signal. */
    if (!target_memmod_lookup(target,tid,addr,mmod->is_phys)) {
	if (target_notify_sw_breakpoint(target,addr,0)) 
	    vwarn("sw bp removal notification failed; ignoring\n");
    }

    return 0;
}

int target_remove_sw_breakpoint(struct target *target,tid_t tid,
				struct target_memmod *mmod) {
    if (target->ops->remove_sw_breakpoint)
	return target->ops->remove_sw_breakpoint(target,tid,mmod);
    else
	return _target_remove_sw_breakpoint(target,tid,mmod);
}

int _target_enable_sw_breakpoint(struct target *target,tid_t tid,
				 struct target_memmod *mmod) {
    return target_memmod_set(target,tid,mmod);
}

int target_enable_sw_breakpoint(struct target *target,tid_t tid,
				struct target_memmod *mmod) {
    if (target->ops->enable_sw_breakpoint)
	return target->ops->enable_sw_breakpoint(target,tid,mmod);

    return _target_enable_sw_breakpoint(target,tid,mmod);
}

int _target_disable_sw_breakpoint(struct target *target,tid_t tid,
				  struct target_memmod *mmod) {
    return target_memmod_unset(target,tid,mmod);
}

int target_disable_sw_breakpoint(struct target *target,tid_t tid,
				 struct target_memmod *mmod) {
    if (target->ops->disable_sw_breakpoint)
	return target->ops->disable_sw_breakpoint(target,tid,mmod);
    else
	return _target_disable_sw_breakpoint(target,tid,mmod);
}

int _target_change_sw_breakpoint(struct target *target,tid_t tid,
				struct target_memmod *mmod,
				unsigned char *code,unsigned long code_len) {
    return target_memmod_set_tmp(target,tid,mmod,code,code_len);
}

int target_change_sw_breakpoint(struct target *target,tid_t tid,
				struct target_memmod *mmod,
				unsigned char *code,unsigned long code_len) {
    if (target->ops->change_sw_breakpoint)
	return target->ops->change_sw_breakpoint(target,tid,mmod,code,code_len);
    else
	return _target_change_sw_breakpoint(target,tid,mmod,code,code_len);
}

int _target_unchange_sw_breakpoint(struct target *target,tid_t tid,
				   struct target_memmod *mmod) {
    return target_memmod_set(target,tid,mmod);
}

int target_unchange_sw_breakpoint(struct target *target,tid_t tid,
				  struct target_memmod *mmod) {
    if (target->ops->unchange_sw_breakpoint)
	return target->ops->unchange_sw_breakpoint(target,tid,mmod);
    else
	return _target_unchange_sw_breakpoint(target,tid,mmod);
}

REG target_get_unused_debug_reg(struct target *target,tid_t tid) {
    REG retval;
    if (!target->ops->get_unused_debug_reg) {
	errno = ENOTSUP;
	return -1;
    }
    vdebug(5,LA_TARGET,LF_TARGET,"getting unused debug reg for target(%s):%"PRIiTID"\n",
	   target->name,tid);
    retval = target->ops->get_unused_debug_reg(target,tid);
    vdebug(5,LA_TARGET,LF_TARGET,"got unused debug reg for target(%s):%"PRIiTID": %"PRIiREG"\n",
	   target->name,tid,retval);
    return retval;
}

int target_set_hw_breakpoint(struct target *target,tid_t tid,REG reg,ADDR addr) {
    vdebug(8,LA_TARGET,LF_TARGET,
	   "setting hw breakpoint at 0x%"PRIxADDR" on target(%s:%"PRIiTID") dreg %d\n",
	   addr,target->name,tid,reg);
    return target->ops->set_hw_breakpoint(target,tid,reg,addr);
}

int target_set_hw_watchpoint(struct target *target,tid_t tid,REG reg,ADDR addr,
			     probepoint_whence_t whence,int watchsize) {
    vdebug(8,LA_TARGET,LF_TARGET,
	   "setting hw watchpoint at 0x%"PRIxADDR" on target(%s:%"PRIiTID") dreg %d (%d)\n",
	   addr,target->name,tid,reg,watchsize);
    return target->ops->set_hw_watchpoint(target,tid,reg,addr,whence,watchsize);
}

int target_unset_hw_breakpoint(struct target *target,tid_t tid,REG reg) {
    vdebug(8,LA_TARGET,LF_TARGET,
	   "removing hw breakpoint on target(%s:%"PRIiTID") dreg %d\n",
	   target->name,tid,reg);
    return target->ops->unset_hw_breakpoint(target,tid,reg);
}

int target_unset_hw_watchpoint(struct target *target,tid_t tid,REG reg) {
    vdebug(8,LA_TARGET,LF_TARGET,
	   "removing hw watchpoint on target(%s:%"PRIiTID") dreg %d\n",
	   target->name,tid,reg);
    return target->ops->unset_hw_watchpoint(target,tid,reg);
}

int target_disable_hw_breakpoints(struct target *target,tid_t tid) {
    vdebug(8,LA_TARGET,LF_TARGET,
	   "disable hw breakpoints on target(%s:%"PRIiTID")\n",target->name,tid);
    return target->ops->disable_hw_breakpoints(target,tid);
}

int target_enable_hw_breakpoints(struct target *target,tid_t tid) {
    vdebug(8,LA_TARGET,LF_TARGET,
	   "enable hw breakpoints on target(%s:%"PRIiTID")\n",target->name,tid);
    return target->ops->enable_hw_breakpoints(target,tid);
}

int target_disable_hw_breakpoint(struct target *target,tid_t tid,REG dreg) {
    vdebug(8,LA_TARGET,LF_TARGET,
	   "disable hw breakpoint %"PRIiREG" on target(%s:%"PRIiTID")\n",
	   dreg,target->name,tid);
    return target->ops->disable_hw_breakpoint(target,tid,dreg);
}

int target_enable_hw_breakpoint(struct target *target,tid_t tid,REG dreg) {
    vdebug(8,LA_TARGET,LF_TARGET,
	   "enable hw breakpoint %"PRIiREG" on target(%s:%"PRIiTID")\n",
	   dreg,target->name,tid);
    return target->ops->enable_hw_breakpoint(target,tid,dreg);
}

int target_notify_sw_breakpoint(struct target *target,ADDR addr,
				int notification) {
    if (target->ops->notify_sw_breakpoint) {
	vdebug(16,LA_TARGET,LF_TARGET,
	       "notify sw breakpoint (%d) on target(%s)\n",
	       notification,target->name);
	return target->ops->notify_sw_breakpoint(target,addr,notification);
    }
    else
	return 0;
}

int target_singlestep(struct target *target,tid_t tid,int isbp) {
    vdebug(5,LA_TARGET,LF_TARGET,"single stepping target(%s:%"PRIiTID") isbp=%d\n",
	   target->name,tid,isbp);
    return target->ops->singlestep(target,tid,isbp,NULL);
}

int target_singlestep_end(struct target *target,tid_t tid) {
    if (target->ops->singlestep_end) {
	vdebug(5,LA_TARGET,LF_TARGET,"ending single stepping of target(%s:%"PRIiTID")\n",
	       target->name,tid);
	return target->ops->singlestep_end(target,tid,NULL);
    }
    return 0;
}

tid_t target_gettid(struct target *target) {
    tid_t retval = 0;

    vdebug(9,LA_TARGET,LF_TARGET,"gettid target(%s)\n",target->name);
    retval = target->ops->gettid(target);
    vdebug(5,LA_TARGET,LF_TARGET,"gettid target(%s) -> 0x%"PRIx64" \n",
	   target->name,retval);

    return retval;
}

uint64_t target_get_tsc(struct target *target) {
    if (target->ops->get_tsc)
	return target->ops->get_tsc(target);
    errno = EINVAL;
    return UINT64_MAX;
}

uint64_t target_get_time(struct target *target) {
    if (target->ops->get_time)
	return target->ops->get_time(target);
    errno = EINVAL;
    return UINT64_MAX;
}

uint64_t target_get_counter(struct target *target) {
    if (target->ops->get_counter)
	return target->ops->get_counter(target);
    errno = EINVAL;
    return UINT64_MAX;
}

int target_enable_feature(struct target *target,int feature,void *arg) {
    if (target->ops->enable_feature)
	return target->ops->enable_feature(target,feature,arg);
    errno = EINVAL;
    return -1;
}

int target_disable_feature(struct target *target,int feature) {
    if (target->ops->disable_feature)
	return target->ops->disable_feature(target,feature);
    errno = EINVAL;
    return -1;
}

thread_status_t target_thread_status(struct target *target,tid_t tid) {
    struct target_thread *tthread;

    tthread = target_lookup_thread(target,tid);
    if (!tthread) {
	verror("no such thread %"PRIiTID"\n",tid);
	errno = EINVAL;
	return THREAD_STATUS_UNKNOWN;
    }

    return tthread->status;
}

