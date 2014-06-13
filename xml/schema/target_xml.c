/*
 * Copyright (c) 2012, 2013, 2014 The University of Utah
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

#include <signal.h>

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
    case vmi1__TargetTypeT__xenProcess:
	if (out)
	    *out = TARGET_TYPE_XEN_PROCESS;
	return TARGET_TYPE_XEN_PROCESS;
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
    case TARGET_TYPE_XEN_PROCESS:
	if (out)
	    *out = vmi1__TargetTypeT__xenProcess;
	return vmi1__TargetTypeT__xenProcess;
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

    if (spec->defaultProbeStyle)
	ospec->style = 
	    x_ProbepointStyleT_to_t_probepoint_style_t(soap,
						       *spec->defaultProbeStyle);

    if (spec->startPaused == xsd__boolean__false_)
	ospec->start_paused = 0;
    else 
	ospec->start_paused = 1;
    if ((spec->killOnClose && *spec->killOnClose == xsd__boolean__true_)
	|| spec->killOnCloseSignal) {
	ospec->kill_on_close = 1;
	ospec->kill_on_close_sig = 
	    (spec->killOnCloseSignal) ? *spec->killOnCloseSignal : SIGKILL;
    }
    if (spec->debugfileRootPrefix)
	ospec->debugfile_root_prefix = strdup(spec->debugfileRootPrefix);
    if (spec->activeProbeThreadEntry 
	&& *spec->activeProbeThreadEntry == xsd__boolean__true_)
	ospec->active_probe_flags |= ACTIVE_PROBE_FLAG_THREAD_ENTRY;
    if (spec->activeProbeThreadExit 
	&& *spec->activeProbeThreadExit == xsd__boolean__true_)
	ospec->active_probe_flags |= ACTIVE_PROBE_FLAG_THREAD_EXIT;
    if (spec->activeProbeMemory 
	&& *spec->activeProbeMemory == xsd__boolean__true_)
	ospec->active_probe_flags |= ACTIVE_PROBE_FLAG_MEMORY;
    if (spec->activeProbeOther 
	&& *spec->activeProbeOther == xsd__boolean__true_)
	ospec->active_probe_flags |= ACTIVE_PROBE_FLAG_OTHER;

    if (type == TARGET_TYPE_PTRACE
	&& spec->backendSpec 
	&& spec->backendSpec->__union_backendSpec \
	       == SOAP_UNION__vmi1__union_backendSpec_targetPtraceSpec) 
	x_TargetPtraceSpecT_to_t_linux_userproc_spec(soap,
						     (struct vmi1__TargetPtraceSpecT *)spec->backendSpec->union_backendSpec.targetPtraceSpec,
						     reftab,
						     ospec->backend_spec);
#ifdef ENABLE_XENSUPPORT
    else if (type == TARGET_TYPE_XEN
	&& spec->backendSpec 
	&& spec->backendSpec->__union_backendSpec \
	       == SOAP_UNION__vmi1__union_backendSpec_targetXenSpec)
	x_TargetXenSpecT_to_t_xen_vm_spec(soap,
					  (struct vmi1__TargetXenSpecT *)spec->backendSpec->union_backendSpec.targetXenSpec,
					  reftab,
					  ospec->backend_spec);
    else if (type == TARGET_TYPE_XEN_PROCESS) {
	spec->backendSpec = NULL;
    }
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

    ospec->defaultProbeStyle = 
	SOAP_CALLOC(soap,1,sizeof(*ospec->defaultProbeStyle));
    *ospec->defaultProbeStyle = 
	t_probepoint_style_t_to_x_ProbepointStyleT(soap,spec->style);

    /* XXX: this might be a lie. */
    ospec->dedicatedMonitor = xsd__boolean__false_;
    ospec->logStdout = SOAP_CALLOC(soap,1,sizeof(*ospec->logStdout));
    if (spec->outfile) 
	*ospec->logStdout = xsd__boolean__true_;
    else
	*ospec->logStdout = xsd__boolean__false_;
    ospec->logStderr = SOAP_CALLOC(soap,1,sizeof(*ospec->logStderr));
    if (spec->errfile) 
	*ospec->logStderr = xsd__boolean__true_;
    else
	*ospec->logStderr = xsd__boolean__false_;
    ospec->killOnClose = SOAP_CALLOC(soap,1,sizeof(*ospec->killOnClose));
    if (spec->kill_on_close) 
	*ospec->killOnClose = xsd__boolean__true_;
    else
	*ospec->killOnClose = xsd__boolean__false_;
    if (spec->kill_on_close) {
	ospec->killOnCloseSignal = 
	    SOAP_CALLOC(soap,1,sizeof(*ospec->killOnCloseSignal));
	*ospec->killOnCloseSignal = spec->kill_on_close_sig;
    }
    if (spec->debugfile_root_prefix)
	SOAP_STRCPY(soap,ospec->debugfileRootPrefix,spec->debugfile_root_prefix);
    ospec->activeProbeThreadEntry = 
	SOAP_CALLOC(soap,1,sizeof(*ospec->activeProbeThreadEntry));
    if (spec->active_probe_flags & ACTIVE_PROBE_FLAG_THREAD_ENTRY) 
	*ospec->activeProbeThreadEntry = xsd__boolean__true_;
    else
	*ospec->activeProbeThreadEntry = xsd__boolean__false_;
    ospec->activeProbeThreadExit = 
	SOAP_CALLOC(soap,1,sizeof(*ospec->activeProbeThreadExit));
    if (spec->active_probe_flags & ACTIVE_PROBE_FLAG_THREAD_EXIT) 
	*ospec->activeProbeThreadExit = xsd__boolean__true_;
    else
	*ospec->activeProbeThreadExit = xsd__boolean__false_;
    ospec->activeProbeMemory = 
	SOAP_CALLOC(soap,1,sizeof(*ospec->activeProbeMemory));
    if (spec->active_probe_flags & ACTIVE_PROBE_FLAG_MEMORY) 
	*ospec->activeProbeMemory = xsd__boolean__true_;
    else
	*ospec->activeProbeMemory = xsd__boolean__false_;
    ospec->activeProbeOther = 
	SOAP_CALLOC(soap,1,sizeof(*ospec->activeProbeOther));
    if (spec->active_probe_flags & ACTIVE_PROBE_FLAG_OTHER) 
	*ospec->activeProbeOther = xsd__boolean__true_;
    else
	*ospec->activeProbeOther = xsd__boolean__false_;

    if (spec->target_type == TARGET_TYPE_PTRACE) {
	ospec->backendSpec = SOAP_CALLOC(soap,1,sizeof(*ospec->backendSpec));
	ospec->backendSpec->__union_backendSpec = \
	    SOAP_UNION__vmi1__union_backendSpec_targetPtraceSpec;
	ospec->backendSpec->union_backendSpec.targetPtraceSpec = \
	    t_linux_userproc_spec_to_x_TargetPtraceSpecT(soap,
							 (struct linux_userproc_spec *)spec->backend_spec,
							 reftab,NULL);
    }
#ifdef ENABLE_XENSUPPORT
    else if (spec->target_type == TARGET_TYPE_XEN) {
	ospec->backendSpec = SOAP_CALLOC(soap,1,sizeof(*ospec->backendSpec));
	ospec->backendSpec->__union_backendSpec = \
	    SOAP_UNION__vmi1__union_backendSpec_targetXenSpec;
	ospec->backendSpec->union_backendSpec.targetXenSpec = \
	    t_xen_vm_spec_to_x_TargetXenSpecT(soap,
					      (struct xen_vm_spec *)spec->backend_spec,
					      reftab,NULL);
    }
    else if (spec->target_type == TARGET_TYPE_XEN_PROCESS) {
	ospec->backendSpec = SOAP_CALLOC(soap,1,sizeof(*ospec->backendSpec));
	ospec->backendSpec->__union_backendSpec = \
	    SOAP_UNION__vmi1__union_backendSpec_targetXenProcessSpec;
	ospec->backendSpec->union_backendSpec.targetXenProcessSpec = NULL;
    }
#endif

    return ospec;
}

#ifdef ENABLE_XENSUPPORT
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
    if (spec->kernelFilename)
	ospec->kernel_filename = strdup(spec->kernelFilename);
    if (spec->configFile) 
	ospec->config_file = strdup(spec->configFile);
    if (spec->noHVMSetContext && *spec->noHVMSetContext == xsd__boolean__true_)
	ospec->no_hvm_setcontext = 1;
    if (spec->clearMemCachesEachException
	&& *spec->clearMemCachesEachException == xsd__boolean__true_)
	ospec->clear_mem_caches_each_exception = 1;
#ifdef ENABLE_XENACCESS
    if (spec->useXenAccess && *spec->useXenAccess == xsd__boolean__true_)
	ospec->use_xenaccess = 1;
#endif
#ifdef ENABLE_LIBVMI
    if (spec->useLibVMI && *spec->useLibVMI == xsd__boolean__true_)
	ospec->use_libvmi = 1;
#endif
    if (spec->noClearHWDbgReg && *spec->noClearHWDbgReg == xsd__boolean__true_)
	ospec->no_hw_debug_reg_clear = 1;
    if (spec->noUseMultiplexer && *spec->noUseMultiplexer == xsd__boolean__true_)
	ospec->no_use_multiplexer = 1;
    if (spec->dominfoTimeout && *spec->dominfoTimeout > 0)
	ospec->dominfo_timeout = *spec->dominfoTimeout;

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
    if (spec->kernel_filename)
	SOAP_STRCPY(soap,ospec->kernelFilename,spec->kernel_filename);
    if (spec->config_file)
	SOAP_STRCPY(soap,ospec->configFile,spec->config_file);
    if (spec->no_hvm_setcontext) {
	ospec->noHVMSetContext = 
	    SOAP_CALLOC(soap,1,sizeof(*ospec->noHVMSetContext));
	*ospec->noHVMSetContext = xsd__boolean__true_;
    }
    if (spec->clear_mem_caches_each_exception) {
	ospec->clearMemCachesEachException = 
	    SOAP_CALLOC(soap,1,sizeof(*ospec->clearMemCachesEachException));
	*ospec->clearMemCachesEachException = xsd__boolean__true_;
    }
    if (spec->use_libvmi) {
	ospec->useLibVMI = 
	    SOAP_CALLOC(soap,1,sizeof(*ospec->useLibVMI));
	*ospec->useLibVMI = xsd__boolean__true_;
    }
    if (spec->use_xenaccess) {
	ospec->useXenAccess = 
	    SOAP_CALLOC(soap,1,sizeof(*ospec->useXenAccess));
	*ospec->useXenAccess = xsd__boolean__true_;
    }
    if (spec->no_hw_debug_reg_clear) {
	ospec->noClearHWDbgReg = 
	    SOAP_CALLOC(soap,1,sizeof(*ospec->noClearHWDbgReg));
	*ospec->noClearHWDbgReg = xsd__boolean__true_;
    }
    if (spec->no_use_multiplexer) {
	ospec->noUseMultiplexer = 
	    SOAP_CALLOC(soap,1,sizeof(*ospec->noUseMultiplexer));
	*ospec->noUseMultiplexer = xsd__boolean__true_;
    }
    if (spec->dominfo_timeout > 0) {
	ospec->dominfoTimeout = 
	    SOAP_CALLOC(soap,1,sizeof(*ospec->dominfoTimeout));
	*ospec->dominfoTimeout = spec->dominfo_timeout;
    }

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

    if (out) {
	ospec = out;
	ospec->pid = -1;
    }
    else 
	ospec = linux_userproc_build_spec();

    if (spec->pid)
	ospec->pid = *(spec->pid);
    if (spec->program)
	ospec->program = strdup(spec->program);
    if (spec->arguments && spec->arguments->__sizeargument) {
	ospec->argv = calloc(spec->arguments->__sizeargument + 1,sizeof(char *));
	for (i = 0; i < spec->arguments->__sizeargument; ++i) {
	    if (spec->arguments->argument[i].__size >= 0) {
		ospec->argv[i] = 
		    malloc(spec->arguments->argument[i].__size + 1);
		memcpy(ospec->argv[i],spec->arguments->argument[i].__ptr,
		       spec->arguments->argument[i].__size);
		/* NULL-terminate it; args are supposed to be strings. */
		ospec->argv[i][spec->arguments->argument[i].__size] = '\0';
	    }
	    else
		ospec->argv[i] = NULL;
	}
    }
    if (spec->environment && spec->environment->__sizeenvvar) {
	ospec->envp = calloc(spec->environment->__sizeenvvar + 1,sizeof(char *));
	for (i = 0; i < spec->environment->__sizeenvvar; ++i) 
	    ospec->envp[i] = strdup(spec->environment->envvar[i]);
	ospec->envp[i] = NULL;
    }

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
	for (i = 0; i < len; ++i) {
	    ospec->arguments->argument[i].__size = strlen(spec->argv[i]);
	    SOAP_STRCPY(soap,ospec->arguments->argument[i].__ptr,spec->argv[i]);
	}
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
    if (thread->name) {
	SOAP_STRCPY(soap,othread->name,thread->name);
    }
    else
	othread->name = "";
    if (thread->supported_overlay_types) 
	othread->canOverlay = xsd__boolean__true_;
    else
	othread->canOverlay = xsd__boolean__false_;

    return othread;
}

struct vmi1__TargetT *
t_target_id_to_x_TargetT(struct soap *soap,
			 int target_id,struct target_spec *spec,
			 GHashTable *reftab,
			 struct vmi1__TargetT *out) {
    struct vmi1__TargetT *otarget;

    if (out)
	otarget = out;
    else
	otarget = SOAP_CALLOC(soap,1,sizeof(*otarget));

    otarget->tid = target_id;
    otarget->name = "";

    /*
     * Since we don't have a target yet, probably, just use the spec
     * values for now.
     */
    otarget->activeProbeThreadEntry = 
	SOAP_CALLOC(soap,1,sizeof(*otarget->activeProbeThreadEntry));
    if (spec->active_probe_flags & ACTIVE_PROBE_FLAG_THREAD_ENTRY) 
	*otarget->activeProbeThreadEntry = xsd__boolean__true_;
    else
	*otarget->activeProbeThreadEntry = xsd__boolean__false_;
    otarget->activeProbeThreadExit = 
	SOAP_CALLOC(soap,1,sizeof(*otarget->activeProbeThreadExit));
    if (spec->active_probe_flags & ACTIVE_PROBE_FLAG_THREAD_EXIT) 
	*otarget->activeProbeThreadExit = xsd__boolean__true_;
    else
	*otarget->activeProbeThreadExit = xsd__boolean__false_;
    otarget->activeProbeMemory = 
	SOAP_CALLOC(soap,1,sizeof(*otarget->activeProbeMemory));
    if (spec->active_probe_flags & ACTIVE_PROBE_FLAG_MEMORY) 
	*otarget->activeProbeMemory = xsd__boolean__true_;
    else
	*otarget->activeProbeMemory = xsd__boolean__false_;
    otarget->activeProbeOther = 
	SOAP_CALLOC(soap,1,sizeof(*otarget->activeProbeOther));
    if (spec->active_probe_flags & ACTIVE_PROBE_FLAG_OTHER) 
	*otarget->activeProbeOther = xsd__boolean__true_;
    else
	*otarget->activeProbeOther = xsd__boolean__false_;

    otarget->targetSpec = \
	t_target_spec_to_x_TargetSpecT(soap,spec,reftab,NULL);

    otarget->targetStatus = vmi1__TargetStatusT__unknown;

    otarget->__sizethread = 0;
    otarget->thread = NULL;

    otarget->__sizeaddrSpace = 0;
    otarget->addrSpace = NULL;

    return otarget;
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

    otarget->activeProbeThreadEntry = 
	SOAP_CALLOC(soap,1,sizeof(*otarget->activeProbeThreadEntry));
    if (target->active_probe_flags & ACTIVE_PROBE_FLAG_THREAD_ENTRY) 
	*otarget->activeProbeThreadEntry = xsd__boolean__true_;
    else
	*otarget->activeProbeThreadEntry = xsd__boolean__false_;
    otarget->activeProbeThreadExit = 
	SOAP_CALLOC(soap,1,sizeof(*otarget->activeProbeThreadExit));
    if (target->active_probe_flags & ACTIVE_PROBE_FLAG_THREAD_EXIT) 
	*otarget->activeProbeThreadExit = xsd__boolean__true_;
    else
	*otarget->activeProbeThreadExit = xsd__boolean__false_;
    otarget->activeProbeMemory = 
	SOAP_CALLOC(soap,1,sizeof(*otarget->activeProbeMemory));
    if (target->active_probe_flags & ACTIVE_PROBE_FLAG_MEMORY) 
	*otarget->activeProbeMemory = xsd__boolean__true_;
    else
	*otarget->activeProbeMemory = xsd__boolean__false_;
    otarget->activeProbeOther = 
	SOAP_CALLOC(soap,1,sizeof(*otarget->activeProbeOther));
    if (target->active_probe_flags & ACTIVE_PROBE_FLAG_OTHER) 
	*otarget->activeProbeOther = xsd__boolean__true_;
    else
	*otarget->activeProbeOther = xsd__boolean__false_;

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
    char idbuf[12];

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
	    snprintf(idbuf,12,"i%d",df->id);
	    SOAP_STRCPY(soap,oregion->debugFileId[i],idbuf);
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
	oprobe->psize = t_probepoint_watchsize_t_to_x_ProbepointSizeT(soap,pp->watchsize);
    }

    return oprobe;
}

struct vmi1__ProbeEventT *
t_probe_to_x_ProbeEventT(struct soap *soap,
			 struct probe *probe,tid_t tid,int type,struct probe *trigger,struct probe *base,
			 GHashTable *reftab,
			 struct vmi1__ProbeEventT *out) {
    struct vmi1__ProbeEventT *oevent;
    GHashTable *regs;
    GHashTableIter iter;
    REGVAL *rvp;
    char *rname;
    int i;
    struct target_thread *tthread;

    tthread = target_lookup_thread(probe->target,tid);

    if (out)
	oevent = out;
    else
	oevent = SOAP_CALLOC(soap,1,sizeof(*oevent));

    if (type == 0) 
	oevent->probeEventType = _vmi1__probeEventType__pre;
    else if (type == 1) 
	oevent->probeEventType = _vmi1__probeEventType__post;

    oevent->probe = t_probe_to_x_ProbeT(soap,probe,reftab,NULL);
    if (tthread)
	oevent->thread = t_target_thread_to_x_ThreadT(soap,tthread,reftab,NULL);

    oevent->registerValues = SOAP_CALLOC(soap,1,sizeof(*oevent->registerValues));

    regs = target_copy_registers(probe->target,tid);
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

action_type_t
x_ActionTypeT_to_t_action_type_t(struct soap *soap,
				 enum vmi1__ActionTypeT in) {
    switch (in) {
    case vmi1__ActionTypeT__return_:
	return ACTION_RETURN;
    case vmi1__ActionTypeT__regmod:
	return ACTION_REGMOD;
    case vmi1__ActionTypeT__memmod:
	return ACTION_MEMMOD;
    case vmi1__ActionTypeT__singlestep:
	return ACTION_SINGLESTEP;
    default:
	verror("unknown ActionTypeT %d!\n",in);
	return -1;
    }
}
enum vmi1__ActionTypeT 
t_action_type_t_to_x_ActionTypeT(struct soap *soap,
				 action_type_t in) {
    switch (in) {
    case ACTION_RETURN:
	return vmi1__ActionTypeT__return_;
    case ACTION_REGMOD:
	return vmi1__ActionTypeT__regmod;
    case ACTION_MEMMOD:
	return vmi1__ActionTypeT__memmod;
    case ACTION_SINGLESTEP:
	return vmi1__ActionTypeT__singlestep;
    default:
	verror("unknown action_type_t %d!\n",in);
	return -1;
    }
}

action_whence_t
x_ActionWhenceT_to_t_action_whence_t(struct soap *soap,
				     enum vmi1__ActionWhenceT in) {
    switch (in) {
    case vmi1__ActionWhenceT__oneshot:
	return ACTION_ONESHOT;
    case vmi1__ActionWhenceT__repeatpre:
	return ACTION_REPEATPRE;
    case vmi1__ActionWhenceT__repeatpost:
	return ACTION_REPEATPOST;
    default:
	verror("unknown ActionWhenceT %d!\n",in);
	return -1;
    }
}
enum vmi1__ActionWhenceT 
t_action_whence_t_to_x_ActionWhenceT(struct soap *soap,
				     action_whence_t in) {
    switch (in) {
    case ACTION_ONESHOT:
	return vmi1__ActionWhenceT__oneshot;
    case ACTION_REPEATPRE:
	return vmi1__ActionWhenceT__repeatpre;
    case ACTION_REPEATPOST:
	return vmi1__ActionWhenceT__repeatpost;
    default:
	verror("unknown action_whence_t %d!\n",in);
	return -1;
    }
}

handler_msg_t
x_HandlerMsgT_to_t_handler_msg_t(struct soap *soap,
				 enum vmi1__HandlerMsgT in) {
    switch (in) {
    case vmi1__HandlerMsgT__success:
	return MSG_SUCCESS;
    case vmi1__HandlerMsgT__failure:
	return MSG_FAILURE;
    case vmi1__HandlerMsgT__stepping:
	return MSG_STEPPING;
    case vmi1__HandlerMsgT__stepping_USCOREat_USCOREbp:
	return MSG_STEPPING_AT_BP;
    default:
	verror("unknown HandlerMsgT %d!\n",in);
	return -1;
    }
}
enum vmi1__HandlerMsgT 
t_handler_msg_t_to_x_HandlerMsgT(struct soap *soap,
				 handler_msg_t in) {
    switch (in) {
    case MSG_SUCCESS:
	return vmi1__HandlerMsgT__success;
    case MSG_FAILURE:
	return vmi1__HandlerMsgT__failure;
    case MSG_STEPPING:
	return vmi1__HandlerMsgT__stepping;
    case MSG_STEPPING_AT_BP:
	return vmi1__HandlerMsgT__stepping_USCOREat_USCOREbp;
    default:
	verror("unknown handler_msg_t %d!\n",in);
	return -1;
    }
}

struct vmi1__ActionT *
t_action_to_x_ActionT(struct soap *soap,
		      struct action *action,
		      GHashTable *reftab,
		      struct vmi1__ActionT *out) {
    struct vmi1__ActionT *oaction;

    if (out)
	oaction = out;
    else
	oaction = SOAP_CALLOC(soap,1,sizeof(*oaction));

    oaction->actionId = action->id;
    oaction->actionSpec = SOAP_CALLOC(soap,1,sizeof(*oaction->actionSpec));
    oaction->actionSpec->tid = action->target->id;
    oaction->actionSpec->pid = action->probe->id;
    oaction->actionSpec->type = \
	t_action_type_t_to_x_ActionTypeT(soap,action->type);
    oaction->actionSpec->whence = \
	t_action_whence_t_to_x_ActionWhenceT(soap,action->whence);
    switch (action->type) {
    case ACTION_RETURN:
	oaction->actionSpec->__union_ActionSpecT = \
	    SOAP_UNION__vmi1__union_ActionSpecT_return_;
	oaction->actionSpec->union_ActionSpecT.return_ = \
	    SOAP_CALLOC(soap,1,sizeof(*oaction->actionSpec->union_ActionSpecT.return_));
	oaction->actionSpec->union_ActionSpecT.return_->code = \
	    action->detail.ret.retval;
	break;
    case ACTION_REGMOD:
	oaction->actionSpec->__union_ActionSpecT = \
	    SOAP_UNION__vmi1__union_ActionSpecT_regmod;
	oaction->actionSpec->union_ActionSpecT.regmod = \
	    SOAP_CALLOC(soap,1,sizeof(*oaction->actionSpec->union_ActionSpecT.regmod));
	oaction->actionSpec->union_ActionSpecT.regmod->registerValue = \
	    SOAP_CALLOC(soap,1,sizeof(*oaction->actionSpec->union_ActionSpecT.regmod->registerValue));
	SOAP_STRCPY(soap,
		    oaction->actionSpec->union_ActionSpecT.regmod->registerValue->name,
		    target_regname(action->target,action->detail.regmod.regnum));
	oaction->actionSpec->union_ActionSpecT.regmod->registerValue->value = \
	    action->detail.regmod.regval;
	break;
    case ACTION_MEMMOD:
	oaction->actionSpec->__union_ActionSpecT = \
	    SOAP_UNION__vmi1__union_ActionSpecT_memmod;
	oaction->actionSpec->union_ActionSpecT.memmod = \
	    SOAP_CALLOC(soap,1,sizeof(*oaction->actionSpec->union_ActionSpecT.memmod));
	oaction->actionSpec->union_ActionSpecT.memmod->addr = \
	    action->detail.memmod.destaddr;
	/* Convert to a hexBinary string */
	oaction->actionSpec->union_ActionSpecT.memmod->data.__ptr = \
	    (unsigned char *)action->detail.memmod.data;
	oaction->actionSpec->union_ActionSpecT.memmod->data.__size = \
	    action->detail.memmod.len;
	/*
	oaction->actionSpec->union_ActionSpecT.memmod->data = \
	    SOAP_CALLOC(soap,2 * action->detail.memmod.len + 1,1);
	for (i = 0; i < action->detail.memmod.len; ++i) 
	    sprintf(oaction->actionSpec->union_ActionSpecT.memmod->data + i * 2,
		    "%02x",action->detail.memmod.data[i]);
	oaction->actionSpec->union_ActionSpecT.memmod->data[action->detail.memmod.len] = '\0';
	*/
	break;
    case ACTION_SINGLESTEP:

	break;
    default:
	verror("unknown action type %d!\n",action->type);
	return NULL;
    }

    return oaction;
}

struct vmi1__ActionEventT *
t_action_to_x_ActionEventT(struct soap *soap,
			   struct action *action,struct target_thread *tthread,
			   handler_msg_t msg,int msg_detail,
			   GHashTable *reftab,
			   struct vmi1__ActionEventT *out) {
    struct vmi1__ActionEventT *oevent;
    GHashTable *regs;
    GHashTableIter iter;
    REGVAL *rvp;
    char *rname;
    int i;

    if (out)
	oevent = out;
    else
	oevent = SOAP_CALLOC(soap,1,sizeof(*oevent));

    oevent->handlerMsg = t_handler_msg_t_to_x_HandlerMsgT(soap,msg);

    if (action->type == ACTION_SINGLESTEP) {
	oevent->actionDetail = SOAP_CALLOC(soap,1,sizeof(*oevent->actionDetail));
	oevent->actionDetail->stepCount = \
	    SOAP_CALLOC(soap,1,sizeof(*oevent->actionDetail->stepCount));
	*oevent->actionDetail->stepCount = msg_detail;
    }

    oevent->action = t_action_to_x_ActionT(soap,action,reftab,NULL);
    oevent->thread = t_target_thread_to_x_ThreadT(soap,tthread,reftab,NULL);

    oevent->registerValues = SOAP_CALLOC(soap,1,sizeof(*oevent->registerValues));

    regs = target_copy_registers(tthread->target,tthread->tid);
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
