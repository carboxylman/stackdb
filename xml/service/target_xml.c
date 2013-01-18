/*
 * Copyright (c) 2012, 2013 The University of Utah
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

#include "target_xml.h"
#include "debuginfo_xml.h"
#include "util.h"
#include "alist.h"
#include "list.h"
#include "target.h"

target_type_t 
x_TargetTypeT_to_t_target_type_t(struct soap *soap,
				 enum vmi1__TargetTypeT type,
				 GHashTable *reftab,
				 target_type_t *out) {
    switch (type) {
    case vmi1__TargetTypeT__none:
	if (out)
	    *out = TARGET_TYPE_NONE;
	return TARGET_TYPE_NONE;
    case vmi1__TargetTypeT__ptrace:
	if (out)
	    *out = TARGET_TYPE_PTRACE;
	return TARGET_TYPE_PTRACE;
    case vmi1__TargetTypeT__xen:
	if (out)
	    *out = TARGET_TYPE_XEN;
	return TARGET_TYPE_XEN;
    default:
	verror("unknown TargetTypeT %d\n",type);
	return TARGET_TYPE_NONE;
    }
}

enum vmi1__TargetTypeT 
t_target_type_t_to_x_TargetTypeT(struct soap *soap,
				 target_type_t type,
				 GHashTable *reftab,
				 enum vmi1__TargetTypeT *out) {
    switch (type) {
    case TARGET_TYPE_NONE:
	if (out)
	    *out = vmi1__TargetTypeT__none;
	return vmi1__TargetTypeT__none;
    case TARGET_TYPE_PTRACE:
	if (out)
	    *out = vmi1__TargetTypeT__ptrace;
	return vmi1__TargetTypeT__ptrace;
    case TARGET_TYPE_XEN:
	if (out)
	    *out = vmi1__TargetTypeT__xen;
	return vmi1__TargetTypeT__xen;
    default:
	verror("unknown target_type_t %d\n",type);
	return vmi1__TargetTypeT__none;
    }
}

target_mode_t 
x_TargetModeT_to_t_target_mode_t(struct soap *soap,
				 enum vmi1__TargetModeT mode,
				 GHashTable *reftab,
				 target_mode_t *out) {
    switch (mode) {
    case vmi1__TargetModeT__none:
	if (out)
	    *out = TARGET_MODE_NONE;
	return TARGET_MODE_NONE;
    case vmi1__TargetModeT__live:
	if (out)
	    *out = TARGET_MODE_LIVE;
	return TARGET_MODE_LIVE;
    case vmi1__TargetModeT__replay:
	if (out)
	    *out = TARGET_MODE_REPLAY;
	return TARGET_MODE_REPLAY;
    case vmi1__TargetModeT__record:
	if (out)
	    *out = TARGET_MODE_RECORD;
	return TARGET_MODE_RECORD;
    default:
	verror("unknown TargetModeT %d\n",mode);
	return TARGET_MODE_NONE;
    }
}

enum vmi1__TargetModeT 
t_target_mode_t_to_x_TargetModeT(struct soap *soap,
				 target_mode_t mode,
				 GHashTable *reftab,
				 enum vmi1__TargetModeT *out) {
    switch (mode) {
    case TARGET_MODE_NONE:
	if (out)
	    *out = vmi1__TargetModeT__none;
	return vmi1__TargetModeT__none;
    case TARGET_MODE_LIVE:
	if (out)
	    *out = vmi1__TargetModeT__live;
	return vmi1__TargetModeT__live;
    case TARGET_MODE_REPLAY:
	if (out)
	    *out = vmi1__TargetModeT__replay;
	return vmi1__TargetModeT__replay;
    case TARGET_MODE_RECORD:
	if (out)
	    *out = vmi1__TargetModeT__record;
	return vmi1__TargetModeT__record;
    default:
	verror("unknown target_mode_t %d\n",mode);
	return vmi1__TargetModeT__none;
    }
}

thread_bpmode_t 
x_ThreadBPModeT_to_t_thread_bpmode_t(struct soap *soap,
				     enum vmi1__ThreadBPModeT mode,
				     GHashTable *reftab,
				     thread_bpmode_t *out) {
    switch (mode) {
    case vmi1__ThreadBPModeT__strict:
	if (out)
	    *out = THREAD_BPMODE_STRICT;
	return THREAD_BPMODE_STRICT;
    case vmi1__ThreadBPModeT__semiStrict:
	if (out)
	    *out = THREAD_BPMODE_SEMI_STRICT;
	return THREAD_BPMODE_SEMI_STRICT;
    case vmi1__ThreadBPModeT__loose:
	if (out)
	    *out = THREAD_BPMODE_LOOSE;
	return THREAD_BPMODE_LOOSE;
    default:
	verror("unknown ThreadBPModeT %d; returning STRICT!\n",mode);
	return THREAD_BPMODE_STRICT;
    }
}

enum vmi1__ThreadBPModeT 
t_thread_bpmode_t_to_x_ThreadBPModeT(struct soap *soap,
				     thread_bpmode_t mode,
				     GHashTable *reftab,
				     enum vmi1__ThreadBPModeT *out) {
    switch (mode) {
    case THREAD_BPMODE_STRICT:
	if (out)
	    *out = vmi1__ThreadBPModeT__strict;
	return vmi1__ThreadBPModeT__strict;
    case THREAD_BPMODE_SEMI_STRICT:
	if (out)
	    *out = vmi1__ThreadBPModeT__semiStrict;
	return vmi1__ThreadBPModeT__semiStrict;
    case THREAD_BPMODE_LOOSE:
	if (out)
	    *out = vmi1__ThreadBPModeT__loose;
	return vmi1__ThreadBPModeT__loose;
    default:
	verror("unknown thread_bpmode_t %d; returning STRICT!\n",mode);
	return vmi1__ThreadBPModeT__strict;
    }
}

struct target_spec *
x_TargetSpecT_to_t_target_spec(struct soap *soap,
			       struct vmi1__TargetSpecT *spec,
			       GHashTable *reftab,
			       struct target_spec *out) {
    struct target_spec *ospec;
    target_type_t type;
    target_type_t mode;

    type = x_TargetTypeT_to_t_target_type_t(soap,spec->type,reftab,NULL);
    mode = x_TargetTypeT_to_t_target_type_t(soap,spec->mode,reftab,NULL);

    if (out) {
	ospec = out;
	ospec->target_type = type;
	ospec->target_mode = mode;
    }
    else {
	ospec = target_build_spec(type,mode);
    }

    if (spec->startPaused == xsd__boolean__false_)
	ospec->start_paused = 0;
    else 
	ospec->start_paused = 1;

    if (type == TARGET_TYPE_PTRACE
	&& spec->backendSpec 
	&& spec->backendSpec->__union_backendSpec \
	       == SOAP_UNION__vmi1__union_backendSpec_targetPtraceSpec) 
	x_TargetPtraceSpecT_to_t_linux_userproc_spec(soap,
						     (struct vmi1__TargetPtraceSpecT *)spec->backendSpec->union_backendSpec.targetPtraceSpec,
						     reftab,
						     ospec->backend_spec);
#ifdef ENABLE_XENACCESS
    else if (type == TARGET_TYPE_XEN
	&& spec->backendSpec 
	&& spec->backendSpec->__union_backendSpec \
	       == SOAP_UNION__vmi1__union_backendSpec_targetXenSpec)
	x_TargetXenSpecT_to_t_xen_vm_spec(soap,
					  (struct vmi1__TargetXenSpecT *)spec->backendSpec->union_backendSpec.targetXenSpec,
					  reftab,
					  ospec->backend_spec);
#endif
    else {
	verror("bad target-specific spec (%d)\n",type);
	return NULL;
    }

    return ospec;
}

struct vmi1__TargetSpecT *
t_target_spec_to_x_TargetSpecT(struct soap *soap,
			       struct target_spec *spec,
			       GHashTable *reftab,
			       struct vmi1__TargetSpecT *out) {
    struct vmi1__TargetSpecT *ospec;

    if (out) {
	ospec = out;
    }
    else {
	ospec = SOAP_CALLOC(soap,1,sizeof(*ospec));
    }

    ospec->type = t_target_type_t_to_x_TargetTypeT(soap,spec->target_type,
						   reftab,NULL);
    ospec->mode = t_target_mode_t_to_x_TargetModeT(soap,spec->target_mode,
						   reftab,NULL);
    if (!spec->start_paused)
	ospec->startPaused = xsd__boolean__false_;
    else 
	ospec->startPaused = xsd__boolean__true_;

    if (spec->target_type == TARGET_TYPE_PTRACE) {
	ospec->backendSpec = SOAP_CALLOC(soap,1,sizeof(*ospec->backendSpec));
	ospec->backendSpec->__union_backendSpec = \
	    SOAP_UNION__vmi1__union_backendSpec_targetPtraceSpec;
	ospec->backendSpec->union_backendSpec.targetPtraceSpec = \
	    t_linux_userproc_spec_to_x_TargetPtraceSpecT(soap,
							 (struct linux_userproc_spec *)spec->backend_spec,
							 reftab,NULL);
    }
#ifdef ENABLE_XENACCESS
    else if (spec->target_type == TARGET_TYPE_XEN) {
	ospec->backendSpec = SOAP_CALLOC(soap,1,sizeof(*ospec->backendSpec));
	ospec->backendSpec->__union_backendSpec = \
	    SOAP_UNION__vmi1__union_backendSpec_targetXenSpec;
	ospec->backendSpec->union_backendSpec.targetXenSpec = \
	    t_xen_vm_spec_to_x_TargetXenSpecT(soap,
					      (struct xen_vm_spec *)spec->backend_spec,
					      reftab,NULL);
#endif

    return ospec;
}

#ifdef ENABLE_XENACCESS
struct xen_vm_spec *
x_TargetXenSpecT_to_t_xen_vm_spec(struct soap *soap,
				  struct vmi1__TargetXenSpecT *spec,
				  GHashTable *reftab,
				  struct xen_vm_spec *out) {
    struct xen_vm_spec *ospec;

    if (out)
	ospec = out;
    else 
	ospec = xen_vm_build_spec();

    if (spec->domain)
	ospec->domain = strdup(spec->domain);
    if (spec->configFile) 
	ospec->config_file = strdup(spec->configFile);
    if (spec->replay_dir)
	ospec->replay_dir = strdup(spec->replayDir);

    return ospec;
}

struct vmi1__TargetXenSpecT *
t_xen_vm_spec_to_x_TargetXenSpecT(struct soap *soap,
				  struct xen_vm_spec *spec,
				  GHashTable *reftab,
				  struct vmi1__TargetXenSpecT *out) {
    struct vmi1__TargetXenSpecT *ospec;

    if (out)
	ospec = out;
    else 
	ospec = SOAP_CALLOC(soap,1,sizeof(*ospec));

    if (spec->domain)
	SOAP_STRCPY(soap,ospec->domain,spec->domain);
    if (spec->config_file)
	SOAP_STRCPY(soap,ospec->configFile,spec->config_file);
    if (spec->replay_dir)
	SOAP_STRCPY(soap,ospec->replayDir,spec->replay_dir);

    return ospec;
}
#endif

struct linux_userproc_spec *
x_TargetPtraceSpecT_to_t_linux_userproc_spec(struct soap *soap,
					     struct vmi1__TargetPtraceSpecT *spec,
					     GHashTable *reftab,
					     struct linux_userproc_spec *out) {
    struct linux_userproc_spec *ospec;
    int i;

    if (out)
	ospec = out;
    else 
	ospec = linux_userproc_build_spec();

    if (spec->pid)
	ospec->pid = *(spec->pid);
    if (spec->program)
	ospec->program = strdup(spec->program);
    if (spec->arguments && spec->arguments->__sizeargument) {
	ospec->argv = calloc(spec->arguments->__sizeargument + 1,sizeof(char *));
	for (i = 0; i < spec->arguments->__sizeargument; ++i) 
	    ospec->argv[i] = strdup(spec->arguments->argument[i]);
	ospec->argv[i] = NULL;
    }
    if (spec->environment && spec->environment->__sizeenvvar) {
	ospec->envp = calloc(spec->environment->__sizeenvvar + 1,sizeof(char *));
	for (i = 0; i < spec->environment->__sizeenvvar; ++i) 
	    ospec->envp[i] = strdup(spec->environment->envvar[i]);
	ospec->envp[i] = NULL;
    }
    if (spec->closeStdin && *spec->closeStdin != xsd__boolean__false_)
	ospec->close_stdin = 1;
    else
	ospec->close_stdin = 0;
    if (spec->stdoutLogfile)
	ospec->stdout_logfile = strdup(spec->stdoutLogfile);
    if (spec->stderrLogfile)
	ospec->stderr_logfile = strdup(spec->stderrLogfile);

    return ospec;
}

struct vmi1__TargetPtraceSpecT *
t_linux_userproc_spec_to_x_TargetPtraceSpecT(struct soap *soap,
					     struct linux_userproc_spec *spec,
					     GHashTable *reftab,
					     struct vmi1__TargetPtraceSpecT *out) {
    struct vmi1__TargetPtraceSpecT *ospec;
    int len;
    int i;

    if (out)
	ospec = out;
    else
	ospec = SOAP_CALLOC(soap,1,sizeof(*ospec));

    if (spec->pid > 0) {
	ospec->pid = SOAP_CALLOC(soap,1,sizeof(*(ospec->pid)));
	*(ospec->pid) = spec->pid;
    }
    if (spec->program) 
	SOAP_STRCPY(soap,ospec->program,spec->program);
    if (spec->argv) {
	len = 0;
	for (i = 0; spec->argv[i] != NULL; ++i)
	    ;
	len = i;
	ospec->arguments = SOAP_CALLOC(soap,1,sizeof(*(ospec->arguments)));
	ospec->arguments->__sizeargument = len;
	ospec->arguments->argument = \
	    SOAP_CALLOC(soap,len,sizeof(*(ospec->arguments->argument)));
	for (i = 0; i < len; ++i) 
	    SOAP_STRCPY(soap,ospec->arguments->argument[i],spec->argv[i]);
    }
    if (spec->envp) {
	len = 0;
	for (i = 0; spec->envp[i] != NULL; ++i)
	    ;
	len = i;
	ospec->environment = SOAP_CALLOC(soap,1,sizeof(*(ospec->environment)));
	ospec->environment->__sizeenvvar = len;
	ospec->environment->envvar = \
	    SOAP_CALLOC(soap,len,sizeof(*(ospec->environment->envvar)));
	for (i = 0; i < len; ++i) 
	    SOAP_STRCPY(soap,ospec->environment->envvar[i],spec->envp[i]);
    }
    ospec->closeStdin = SOAP_CALLOC(soap,1,sizeof(*(ospec->closeStdin)));
    if (spec->close_stdin == 0)
	*ospec->closeStdin = xsd__boolean__false_;
    else
	*ospec->closeStdin = xsd__boolean__true_;
    if (spec->stdout_logfile)
	SOAP_STRCPY(soap,ospec->stdoutLogfile,spec->stdout_logfile);
    if (spec->stderr_logfile)
	SOAP_STRCPY(soap,ospec->stderrLogfile,spec->stderr_logfile);

    return ospec;
}



thread_status_t 
x_ThreadStatusT_to_t_thread_status_t(struct soap *soap,
				     enum vmi1__ThreadStatusT status,
				     GHashTable *reftab,
				     thread_status_t *out) {
    thread_status_t retval;

    switch (status) {
    case vmi1__ThreadStatusT__unknown:
	retval = THREAD_STATUS_UNKNOWN;
	break;
    case vmi1__ThreadStatusT__running:
	retval = THREAD_STATUS_RUNNING;
	break;
    case vmi1__ThreadStatusT__stopped:
	retval = THREAD_STATUS_STOPPED;
	break;
    case vmi1__ThreadStatusT__sleeping:
	retval = THREAD_STATUS_SLEEPING;
	break;
    case vmi1__ThreadStatusT__zombie:
	retval = THREAD_STATUS_ZOMBIE;
	break;
    case vmi1__ThreadStatusT__dead:
	retval = THREAD_STATUS_DEAD;
	break;
    case vmi1__ThreadStatusT__blockedio:
	retval = THREAD_STATUS_BLOCKEDIO;
	break;
    case vmi1__ThreadStatusT__paging:
	retval = THREAD_STATUS_PAGING;
	break;
    case vmi1__ThreadStatusT__paused:
	retval = THREAD_STATUS_PAUSED;
	break;

    default:
	verror("unknown ThreadStatusT %d\n",status);
	retval = THREAD_STATUS_UNKNOWN;
	break;
    }

    if (out)
	*out = retval;

    return retval;
}

enum vmi1__ThreadStatusT 
t_thread_status_t_to_x_ThreadStatusT(struct soap *soap,
				     thread_status_t status,
				     GHashTable *reftab,
				     enum vmi1__ThreadStatusT *out) {
    enum vmi1__ThreadStatusT retval;

    switch (status) {
    case THREAD_STATUS_UNKNOWN:
	retval = vmi1__ThreadStatusT__unknown;
	break;
    case THREAD_STATUS_RUNNING:
	retval = vmi1__ThreadStatusT__running;
	break;
    case THREAD_STATUS_STOPPED:
	retval = vmi1__ThreadStatusT__stopped;
	break;
    case THREAD_STATUS_SLEEPING:
	retval = vmi1__ThreadStatusT__sleeping;
	break;
    case THREAD_STATUS_ZOMBIE:
	retval = vmi1__ThreadStatusT__zombie;
	break;
    case THREAD_STATUS_DEAD:
	retval = vmi1__ThreadStatusT__dead;
	break;
    case THREAD_STATUS_BLOCKEDIO:
	retval = vmi1__ThreadStatusT__blockedio;
	break;
    case THREAD_STATUS_PAGING:
	retval = vmi1__ThreadStatusT__paging;
	break;
    case THREAD_STATUS_PAUSED:
	retval = vmi1__ThreadStatusT__paused;
	break;
    default:
	verror("unknown thread_status_t %d\n",status);
	retval = vmi1__ThreadStatusT__unknown;
	break;
    }

    if (out)
	*out = retval;

    return retval;
}

target_status_t 
x_TargetStatusT_to_t_target_status_t(struct soap *soap,
				     enum vmi1__TargetStatusT status,
				     GHashTable *reftab,
				     target_status_t *out) {
    target_status_t retval;

    switch (status) {
    case vmi1__TargetStatusT__unknown:
	retval = TSTATUS_UNKNOWN;
	break;
    case vmi1__TargetStatusT__running:
	retval = TSTATUS_RUNNING;
	break;
    case vmi1__TargetStatusT__paused:
	retval = TSTATUS_PAUSED;
	break;
    case vmi1__TargetStatusT__dead:
	retval = TSTATUS_DEAD;
	break;
    case vmi1__TargetStatusT__stopped:
	retval = TSTATUS_STOPPED;
	break;
    case vmi1__TargetStatusT__error:
	retval = TSTATUS_ERROR;
	break;
    case vmi1__TargetStatusT__done:
	retval = TSTATUS_DONE;
	break;
    default:
	verror("unknown TargetStatusT %d\n",status);
	retval = TSTATUS_UNKNOWN;
	break;
    }

    if (out)
	*out = retval;

    return retval;
}

enum vmi1__TargetStatusT 
t_target_status_t_to_x_TargetStatusT(struct soap *soap,
				     target_status_t status,
				     GHashTable *reftab,
				     enum vmi1__TargetStatusT *out) {

    enum vmi1__TargetStatusT retval;

    switch (status) {
    case TSTATUS_UNKNOWN:
	retval = vmi1__TargetStatusT__unknown;
	break;
    case TSTATUS_RUNNING:
	retval = vmi1__TargetStatusT__running;
	break;
    case TSTATUS_PAUSED:
	retval = vmi1__TargetStatusT__paused;
	break;
    case TSTATUS_DEAD:
	retval = vmi1__TargetStatusT__dead;
	break;
    case TSTATUS_STOPPED:
	retval = vmi1__TargetStatusT__stopped;
	break;
    case TSTATUS_ERROR:
	retval = vmi1__TargetStatusT__error;
	break;
    case TSTATUS_DONE:
	retval = vmi1__TargetStatusT__done;
	break;
    default:
	verror("unknown target_status_t %d\n",status);
	retval = vmi1__TargetStatusT__unknown;
	break;
    }

    if (out)
	*out = retval;

    return retval;
}

struct vmi1__ThreadT *
t_target_thread_to_x_ThreadT(struct soap *soap,
			     struct target_thread *thread,
			     GHashTable *reftab,
			     struct vmi1__ThreadT *out) {
    struct vmi1__ThreadT *othread;

    if (out)
	othread = out;
    else
	othread = SOAP_CALLOC(soap,1,sizeof(*othread));

    othread->thid = thread->tid;
    othread->tid = thread->target->id;
    othread->threadStatus = \
	t_thread_status_t_to_x_ThreadStatusT(soap,thread->status,
					     reftab,NULL);

    return othread;
}

struct vmi1__TargetT *
t_target_to_x_TargetT(struct soap *soap,
		      struct target *target,
		      GHashTable *reftab,
		      struct vmi1__TargetT *out) {
    struct vmi1__TargetT *otarget;
    struct array_list *threads;
    struct target_thread *thread;
    int i;
    int len;
    struct addrspace *space;

    if (out)
	otarget = out;
    else
	otarget = SOAP_CALLOC(soap,1,sizeof(*otarget));

    otarget->tid = target->id;

    if (target->name) {
	SOAP_STRCPY(soap,otarget->name,target->name);
    }
    else
	otarget->name = "";

    otarget->targetSpec = \
	t_target_spec_to_x_TargetSpecT(soap,target->spec,reftab,NULL);

    otarget->targetStatus = \
	t_target_status_t_to_x_TargetStatusT(soap,target_status(target),
					     reftab,NULL);

    threads = target_list_threads(target);
    if (threads && array_list_len(threads)) {
	otarget->__sizethread = array_list_len(threads);
	otarget->thread = SOAP_CALLOC(soap,array_list_len(threads),
				      sizeof(*(otarget->thread)));
	array_list_foreach(threads,i,thread) {
	    t_target_thread_to_x_ThreadT(soap,thread,reftab,
					       &otarget->thread[i]);
	}
    }

    len = 0;
    list_for_each_entry(space,&target->spaces,space)
	++len;
    if (len) {
	otarget->__sizeaddrSpace = len;
	otarget->addrSpace = SOAP_CALLOC(soap,len,sizeof(*(otarget->addrSpace)));
	i = 0;
	list_for_each_entry(space,&target->spaces,space) {
	    t_addrspace_to_x_AddrSpaceT(soap,space,reftab,
					&otarget->addrSpace[i]);
	    ++i;
	}
    }

    if (threads)
	array_list_free(threads);

    return otarget;
}

struct vmi1__AddrSpaceT *
t_addrspace_to_x_AddrSpaceT(struct soap *soap,
			    struct addrspace *space,
			    GHashTable *reftab,
			    struct vmi1__AddrSpaceT *out) {
    struct vmi1__AddrSpaceT *ospace;
    struct memregion *region;
    int i;
    int len;

    if (out)
	ospace = out;
    else 
	ospace = SOAP_CALLOC(soap,1,sizeof(*ospace));

    if (space->name)
	SOAP_STRCPY(soap,ospace->name,space->name);
    ospace->id = space->id;
    ospace->tid = space->target->id;

    len = 0;
    list_for_each_entry(region,&space->regions,region)
	++len;
    if (len) {
	ospace->__sizememRegion = len;
	ospace->memRegion = SOAP_CALLOC(soap,len,sizeof(*(ospace->memRegion)));
	i = 0;
	list_for_each_entry(region,&space->regions,region) {
	    t_memregion_to_x_MemRegionT(soap,region,reftab,
					&ospace->memRegion[i]);
	    ++i;
	}
    }

    return ospace;
}

enum vmi1__MemRegionTypeT 
t_region_type_t_to_x_MemRegionTypeT(struct soap *soap,
				    region_type_t rtype,
				    GHashTable *reftab,
				    enum vmi1__MemRegionTypeT *out) {

    enum vmi1__MemRegionTypeT retval;

    switch (rtype) {
    case REGION_TYPE_UNKNOWN:
	retval = vmi1__MemRegionTypeT__unknown;
	break;
    case REGION_TYPE_HEAP:
	retval = vmi1__MemRegionTypeT__heap;
	break;
    case REGION_TYPE_STACK:
	retval = vmi1__MemRegionTypeT__stack;
	break;
    case REGION_TYPE_VDSO:
	retval = vmi1__MemRegionTypeT__vdso;
	break;
    case REGION_TYPE_VSYSCALL:
	retval = vmi1__MemRegionTypeT__vsyscall;
	break;
    case REGION_TYPE_ANON:
	retval = vmi1__MemRegionTypeT__anon;
	break;
    case REGION_TYPE_MAIN:
	retval = vmi1__MemRegionTypeT__main;
	break;
    case REGION_TYPE_LIB:
	retval = vmi1__MemRegionTypeT__lib;
	break;
    default:
	verror("unknown region_type_t %d\n",rtype);
	retval = vmi1__MemRegionTypeT__unknown;
	break;
    }

    if (out)
	*out = retval;

    return retval;
}

struct vmi1__MemRegionT *
t_memregion_to_x_MemRegionT(struct soap *soap,
			    struct memregion *region,
			    GHashTable *reftab,
			    struct vmi1__MemRegionT *out) {
    struct vmi1__MemRegionT *oregion;
    int i;
    int len;
    struct memrange *range;
    GHashTableIter iter;
    struct debugfile *df;

    if (out)
	oregion = out;
    else
	oregion = SOAP_CALLOC(soap,1,sizeof(*oregion));

    if (region->name) {
	SOAP_STRCPY(soap,oregion->name,region->name);
    }
    else
	oregion->name = "";

    oregion->memRegionType = \
	t_region_type_t_to_x_MemRegionTypeT(soap,region->type,reftab,NULL);

    oregion->baseLoadAddr = region->base_load_addr;
    oregion->basePhysAddr = region->base_phys_addr;
    oregion->baseVirtAddr = region->base_virt_addr;
    oregion->physOffset = region->phys_offset;

    len = 0;
    list_for_each_entry(range,&region->ranges,range)
	++len;
    if (len) {
	oregion->__sizememRange = len;
	oregion->memRange = SOAP_CALLOC(soap,len,sizeof(*(oregion->memRange)));
	i = 0;
	list_for_each_entry(range,&region->ranges,range) {
	    t_memrange_to_x_MemRangeT(soap,range,reftab,&oregion->memRange[i]);
	    ++i;
	}
    }

    len = g_hash_table_size(region->debugfiles);
    if (len) {
	oregion->__sizedebugFileId = len;
	oregion->debugFileId = \
	    SOAP_CALLOC(soap,len,sizeof(*(oregion->debugFileId)));
	g_hash_table_iter_init(&iter,region->debugfiles);
	i = 0;
	while (g_hash_table_iter_next(&iter,NULL,(gpointer *)&df)) {
	    SOAP_STRCPY(soap,oregion->debugFileId[i],df->idstr);
	    ++i;
	}
    }

    return oregion;
}

struct vmi1__MemRangeT *
t_memrange_to_x_MemRangeT(struct soap *soap,
			  struct memrange *range,
			  GHashTable *reftab,
			  struct vmi1__MemRangeT *out) {
    struct vmi1__MemRangeT *orange;

    if (out)
	orange = out;
    else
	orange = SOAP_CALLOC(soap,1,sizeof(*orange));

    if (range->prot_flags & PROT_READ)
	orange->read = xsd__boolean__true_;
    else
	orange->read = xsd__boolean__false_;
    if (range->prot_flags & PROT_WRITE)
	orange->write = xsd__boolean__true_;
    else
	orange->write = xsd__boolean__false_;
    if (range->prot_flags & PROT_EXEC)
	orange->execute = xsd__boolean__true_;
    else
	orange->execute = xsd__boolean__false_;

    orange->start = range->start;
    orange->end = range->end;
    orange->offset = range->offset;

    return orange;
}

struct vmi1__ProbeT *
t_probe_to_x_ProbeT(struct soap *soap,
		    struct probe *probe,
		    GHashTable *reftab,
		    struct vmi1__ProbeT *out) {
    struct vmi1__ProbeT *oprobe;
    struct probepoint *pp;

    if (out)
	oprobe = out;
    else
	oprobe = SOAP_CALLOC(soap,1,sizeof(*oprobe));

    oprobe->pid = probe->id;
    SOAP_STRCPY(soap,oprobe->name,probe_name(probe));
    oprobe->addr = probe_addr(probe);
    if (probe->target)
	oprobe->tid = probe->target->id;
    if (probe->thread)
	oprobe->thid = probe->thread->tid;

    if (probe->probepoint) {
	pp = probe->probepoint;

	oprobe->type = t_probepoint_type_t_to_x_ProbepointTypeT(soap,pp->type);
	oprobe->style = t_probepoint_style_t_to_x_ProbepointStyleT(soap,pp->style);
	oprobe->whence = t_probepoint_whence_t_to_x_ProbepointWhenceT(soap,pp->whence);
	oprobe->size = t_probepoint_watchsize_t_to_x_ProbepointSizeT(soap,pp->watchsize);
    }

    return oprobe;
}

struct vmi1__ProbeEventT *
t_probe_to_x_ProbeEventT(struct soap *soap,
			 struct probe *probe,int type,struct probe *trigger,
			 GHashTable *reftab,
			 struct vmi1__ProbeEventT *out) {
    struct vmi1__ProbeEventT *oevent;
    GHashTable *regs;
    GHashTableIter iter;
    REGVAL *rvp;
    char *rname;
    int i;

    if (out)
	oevent = out;
    else
	oevent = SOAP_CALLOC(soap,1,sizeof(*oevent));

    if (type == 0) 
	oevent->eventType = _vmi1__ProbeEventT_eventType__pre;
    else if (type == 1) 
	oevent->eventType = _vmi1__ProbeEventT_eventType__post;

    oevent->probe = t_probe_to_x_ProbeT(soap,probe,reftab,NULL);
    oevent->thread = t_target_thread_to_x_ThreadT(soap,probe->thread,reftab,NULL);

    oevent->registerValues = SOAP_CALLOC(soap,1,sizeof(*oevent->registerValues));

    regs = target_copy_registers(probe->target,probe->thread->tid);
    if (regs) {
	g_hash_table_iter_init(&iter,regs);

	oevent->registerValues->__sizeregisterValue = g_hash_table_size(regs);
	oevent->registerValues->registerValue = 
	    SOAP_CALLOC(soap,g_hash_table_size(regs),
			sizeof(*oevent->registerValues->registerValue));
	i = 0;
	while (g_hash_table_iter_next(&iter,
				      (gpointer *)&rname,(gpointer *)&rvp)) {
	    oevent->registerValues->registerValue[i].name = rname;
	    oevent->registerValues->registerValue[i].value = *rvp;
	    ++i;
	}
	g_hash_table_destroy(regs);
    }
    else {
	oevent->registerValues->__sizeregisterValue = 0;
	oevent->registerValues->registerValue = NULL;
    }

    return oevent;
}

probepoint_type_t
x_ProbepointTypeT_to_t_probepoint_type_t(struct soap *soap,
					 enum vmi1__ProbepointTypeT in) {
    switch (in) {
    case vmi1__ProbepointTypeT__break_:
	return PROBEPOINT_BREAK;
    case vmi1__ProbepointTypeT__watch:
	return PROBEPOINT_WATCH;
    default:
	verror("unknown ProbepointTypeT %d!\n",in);
	return -1;
    }
}
enum vmi1__ProbepointTypeT 
t_probepoint_type_t_to_x_ProbepointTypeT(struct soap *soap,
					 probepoint_type_t in) {
    switch (in) {
    case PROBEPOINT_BREAK:
	return vmi1__ProbepointTypeT__break_;
    case PROBEPOINT_WATCH:
	return vmi1__ProbepointTypeT__watch;
    default:
	verror("unknown probepoint_type_t %d!\n",in);
	return -1;
    }
}

probepoint_style_t
x_ProbepointStyleT_to_t_probepoint_style_t(struct soap *soap,
					   enum vmi1__ProbepointStyleT in) {
    switch (in) {
    case vmi1__ProbepointStyleT__hw:
	return PROBEPOINT_HW;
    case vmi1__ProbepointStyleT__sw:
	return PROBEPOINT_SW;
    case vmi1__ProbepointStyleT__fastest:
	return PROBEPOINT_FASTEST;
    default:
	verror("unknown ProbepointStyleT %d!\n",in);
	return -1;
    }
}
enum vmi1__ProbepointStyleT 
t_probepoint_style_t_to_x_ProbepointStyleT(struct soap *soap,
					   probepoint_style_t in) {
    switch (in) {
    case PROBEPOINT_HW:
	return vmi1__ProbepointStyleT__hw;
    case PROBEPOINT_SW:
	return vmi1__ProbepointStyleT__sw;
    case PROBEPOINT_FASTEST:
	return vmi1__ProbepointStyleT__fastest;
    default:
	verror("unknown probepoint_style_t %d!\n",in);
	return -1;
    }
}

probepoint_whence_t
x_ProbepointWhenceT_to_t_probepoint_whence_t(struct soap *soap,
					     enum vmi1__ProbepointWhenceT in) {
    switch (in) {
    case vmi1__ProbepointWhenceT__auto_:
	return PROBEPOINT_WAUTO;
    case vmi1__ProbepointWhenceT__exec:
	return PROBEPOINT_EXEC;
    case vmi1__ProbepointWhenceT__write:
	return PROBEPOINT_WRITE;
    case vmi1__ProbepointWhenceT__readwrite:
	return PROBEPOINT_READWRITE;
    default:
	verror("unknown ProbepointWhenceT %d!\n",in);
	return -1;
    }
}
enum vmi1__ProbepointWhenceT 
t_probepoint_whence_t_to_x_ProbepointWhenceT(struct soap *soap,
					     probepoint_whence_t in) {
    switch (in) {
    case PROBEPOINT_WAUTO:
	return vmi1__ProbepointWhenceT__auto_;
    case PROBEPOINT_EXEC:
	return vmi1__ProbepointWhenceT__exec;
    case PROBEPOINT_WRITE:
	return vmi1__ProbepointWhenceT__write;
    case PROBEPOINT_READWRITE:
	return vmi1__ProbepointWhenceT__readwrite;
    default:
	verror("unknown probepoint_whence_t %d!\n",in);
	return -1;
    }
}

probepoint_watchsize_t
x_ProbepointSizeT_to_t_probepoint_watchsize_t(struct soap *soap,
					      enum vmi1__ProbepointSizeT in) {
    switch (in) {
    case vmi1__ProbepointSizeT__auto_:
	return PROBEPOINT_LAUTO;
    case vmi1__ProbepointSizeT__0:
	return PROBEPOINT_L0;
    case vmi1__ProbepointSizeT__2:
	return PROBEPOINT_L2;
    case vmi1__ProbepointSizeT__4:
	return PROBEPOINT_L4;
    case vmi1__ProbepointSizeT__8:
	return PROBEPOINT_L8;
    default:
	verror("unknown ProbepointSizeT %d!\n",in);
	return -1;
    }
}
enum vmi1__ProbepointSizeT 
t_probepoint_watchsize_t_to_x_ProbepointSizeT(struct soap *soap,
					      probepoint_watchsize_t in) {
    switch (in) {
    case PROBEPOINT_LAUTO:
	return vmi1__ProbepointSizeT__auto_;
    case PROBEPOINT_L0:
	return vmi1__ProbepointSizeT__0;
    case PROBEPOINT_L2:
	return vmi1__ProbepointSizeT__2;
    case PROBEPOINT_L4:
	return vmi1__ProbepointSizeT__4;
    case PROBEPOINT_L8:
	return vmi1__ProbepointSizeT__8;
    default:
	verror("unknown probepoint_watchsize_t %d!\n",in);
	return -1;
    }
}
