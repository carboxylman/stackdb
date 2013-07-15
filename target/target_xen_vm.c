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

#include <errno.h>
#include <assert.h>
#include <ctype.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include <endian.h>

#include <gelf.h>
#include <elf.h>
#include <libelf.h>
#include <argp.h>

#include "config.h"
#include "common.h"

#include "evloop.h"

#include "dwdebug.h"
#include "dwdebug_priv.h"
#include "target_api.h"
#include "target.h"
#include "probe_api.h"

#include <xenctrl.h>
#include <xs.h>
#ifdef ENABLE_XENACCESS
#include <xenaccess/xenaccess.h>
#include <xenaccess/xa_private.h>
#endif

#include "target_xen_vm.h"

/*
 * Prototypes.
 */
struct target *xen_vm_instantiate(struct target_spec *spec,
				  struct evloop *evloop);

static struct target *xen_vm_attach(struct target_spec *spec,
				    struct evloop *evloop);

static char *xen_vm_tostring(struct target *target,char *buf,int bufsiz);
static int xen_vm_init(struct target *target);
static int xen_vm_attach_internal(struct target *target);
static int xen_vm_detach(struct target *target);
static int xen_vm_fini(struct target *target);
static int xen_vm_kill(struct target *target,int sig);
static int xen_vm_loadspaces(struct target *target);
static int xen_vm_loadregions(struct target *target,struct addrspace *space);
static int xen_vm_updateregions(struct target *target,
				struct addrspace *space);
static int xen_vm_loaddebugfiles(struct target *target,struct addrspace *space,
				 struct memregion *region);
static int xen_vm_postloadinit(struct target *target);
static int xen_vm_postopened(struct target *target);
static int xen_vm_set_active_probing(struct target *target,
				     active_probe_flags_t flags);


static struct target *
xen_vm_instantiate_overlay(struct target *target,
			   struct target_thread *tthread,
			   struct target_spec *spec);
static struct target_thread *
xen_vm_lookup_overlay_thread_by_id(struct target *target,int id);
static struct target_thread *
xen_vm_lookup_overlay_thread_by_name(struct target *target,char *name);
static target_status_t xen_vm_status(struct target *target);
static int xen_vm_pause(struct target *target,int nowait);
static int __xen_vm_resume(struct target *target,int detaching);
static int xen_vm_resume(struct target *target);
static target_status_t xen_vm_monitor(struct target *target);
static target_status_t xen_vm_poll(struct target *target,struct timeval *tv,
				   target_poll_outcome_t *outcome,int *pstatus);
int xen_vm_attach_evloop(struct target *target,struct evloop *evloop);
int xen_vm_detach_evloop(struct target *target);
static unsigned char *xen_vm_read(struct target *target,ADDR addr,
				  unsigned long length,unsigned char *buf);
static unsigned long xen_vm_write(struct target *target,ADDR addr,
				  unsigned long length,unsigned char *buf);
static char *xen_vm_reg_name(struct target *target,REG reg);
static REG xen_vm_dwregno_targetname(struct target *target,char *name);
static REG xen_vm_dw_reg_no(struct target *target,common_reg_t reg);

static tid_t xen_vm_gettid(struct target *target);
static void xen_vm_free_thread_state(struct target *target,void *state);
static struct array_list *xen_vm_list_available_tids(struct target *target);
static struct target_thread *xen_vm_load_thread(struct target *target,tid_t tid,
						int force);
static struct target_thread *xen_vm_load_current_thread(struct target *target,
							int force);
static int xen_vm_load_all_threads(struct target *target,int force);
static int xen_vm_load_available_threads(struct target *target,int force);
static int xen_vm_pause_thread(struct target *target,tid_t tid,int nowait);
static int xen_vm_flush_thread(struct target *target,tid_t tid);
static int xen_vm_flush_current_thread(struct target *target);
static int xen_vm_flush_all_threads(struct target *target);
static char *xen_vm_thread_tostring(struct target *target,tid_t tid,int detail,
				    char *buf,int bufsiz);

static REGVAL xen_vm_read_reg(struct target *target,tid_t tid,REG reg);
static int xen_vm_write_reg(struct target *target,tid_t tid,REG reg,REGVAL value);
static GHashTable *xen_vm_copy_registers(struct target *target,tid_t tid);
static REG xen_vm_get_unused_debug_reg(struct target *target,tid_t tid);
static int xen_vm_set_hw_breakpoint(struct target *target,tid_t tid,REG num,ADDR addr);
static int xen_vm_set_hw_watchpoint(struct target *target,tid_t tid,REG num,ADDR addr,
				    probepoint_whence_t whence,
				    probepoint_watchsize_t watchsize);
static int xen_vm_unset_hw_breakpoint(struct target *target,tid_t tid,REG num);
static int xen_vm_unset_hw_watchpoint(struct target *target,tid_t tid,REG num);
int xen_vm_disable_hw_breakpoints(struct target *target,tid_t tid);
int xen_vm_enable_hw_breakpoints(struct target *target,tid_t tid);
int xen_vm_disable_hw_breakpoint(struct target *target,tid_t tid,REG dreg);
int xen_vm_enable_hw_breakpoint(struct target *target,tid_t tid,REG dreg);
int xen_vm_notify_sw_breakpoint(struct target *target,ADDR addr,
				int notification);
int xen_vm_singlestep(struct target *target,tid_t tid,int isbp,
		      struct target *overlay);
int xen_vm_singlestep_end(struct target *target,tid_t tid,
			  struct target *overlay);

uint64_t xen_vm_get_tsc(struct target *target);
uint64_t xen_vm_get_time(struct target *target);
uint64_t xen_vm_get_counter(struct target *target);

int xen_vm_enable_feature(struct target *target,int feature,void *arg);
int xen_vm_disable_feature(struct target *target,int feature);

int xen_vm_instr_can_switch_context(struct target *target,ADDR addr);

/* Internal prototypes. */
static int xen_vm_invalidate_all_threads(struct target *target);
static result_t xen_vm_active_memory_handler(struct probe *probe,
					     void *handler_data,
					     struct probe *trigger);
static result_t xen_vm_active_thread_entry_handler(struct probe *probe,
						   void *handler_data,
						   struct probe *trigger);
static result_t xen_vm_active_thread_exit_handler(struct probe *probe,
						  void *handler_data,
						  struct probe *trigger);

/* Format chars to print context registers. */
#if __WORDSIZE == 64
#define RF "lx"
#define DRF "lx"
#else
#define RF "x"
#define DRF "lx"
#endif

/*
 * Globals.
 */
static int xc_refcnt = 0;

#ifdef XENCTRL_HAS_XC_INTERFACE
static xc_interface *xc_handle = NULL;
static xc_interface *xce_handle = NULL;
#define XC_IF_INVALID (NULL)
#else
static int xc_handle = -1;
static int xce_handle = -1;
#define XC_IF_INVALID (-1)
#endif

#if !defined(XC_EVTCHN_PORT_T)
#error "XC_EVTCHN_PORT_T undefined!"
#endif
static XC_EVTCHN_PORT_T dbg_port = -1;

#define EF_TF (0x00000100)
#define EF_IF (0x00000200)
#define EF_RF (0x00010000)

/*
 * Set up the target interface for this library.
 */
struct target_ops xen_vm_ops = {
    .tostring = xen_vm_tostring,

    .init = xen_vm_init,
    .fini = xen_vm_fini,
    .attach = xen_vm_attach_internal,
    .detach = xen_vm_detach,
    .kill = xen_vm_kill,
    .loadspaces = xen_vm_loadspaces,
    .loadregions = xen_vm_loadregions,
    .loaddebugfiles = xen_vm_loaddebugfiles,
    .postloadinit = xen_vm_postloadinit,
    .postopened = xen_vm_postopened,
    .set_active_probing = xen_vm_set_active_probing,

    .instantiate_overlay = xen_vm_instantiate_overlay,
    .lookup_overlay_thread_by_id = xen_vm_lookup_overlay_thread_by_id,
    .lookup_overlay_thread_by_name = xen_vm_lookup_overlay_thread_by_name,

    .status = xen_vm_status,
    .pause = xen_vm_pause,
    .resume = xen_vm_resume,
    .monitor = xen_vm_monitor,
    .poll = xen_vm_poll,
    .read = xen_vm_read,
    .write = xen_vm_write,
    .regname = xen_vm_reg_name,
    .dwregno_targetname = xen_vm_dwregno_targetname,
    .dwregno = xen_vm_dw_reg_no,

    .gettid = xen_vm_gettid,
    .free_thread_state = xen_vm_free_thread_state,
    .list_available_tids = xen_vm_list_available_tids,
    .load_available_threads = xen_vm_load_available_threads,
    .load_thread = xen_vm_load_thread,
    .load_current_thread = xen_vm_load_current_thread,
    .load_all_threads = xen_vm_load_all_threads,
    .pause_thread = xen_vm_pause_thread,
    .flush_thread = xen_vm_flush_thread,
    .flush_current_thread = xen_vm_flush_current_thread,
    .flush_all_threads = xen_vm_flush_all_threads,
    .thread_tostring = xen_vm_thread_tostring,

    .attach_evloop = xen_vm_attach_evloop,
    .detach_evloop = xen_vm_detach_evloop,

    .readreg = xen_vm_read_reg,
    .writereg = xen_vm_write_reg,
    .copy_registers = xen_vm_copy_registers,
    .get_unused_debug_reg = xen_vm_get_unused_debug_reg,
    .set_hw_breakpoint = xen_vm_set_hw_breakpoint,
    .set_hw_watchpoint = xen_vm_set_hw_watchpoint,
    .unset_hw_breakpoint = xen_vm_unset_hw_breakpoint,
    .unset_hw_watchpoint = xen_vm_unset_hw_watchpoint,
    .disable_hw_breakpoints = xen_vm_disable_hw_breakpoints,
    .enable_hw_breakpoints = xen_vm_enable_hw_breakpoints,
    .disable_hw_breakpoint = xen_vm_disable_hw_breakpoint,
    .enable_hw_breakpoint = xen_vm_enable_hw_breakpoint,
    .notify_sw_breakpoint = xen_vm_notify_sw_breakpoint,
    .singlestep = xen_vm_singlestep,
    .singlestep_end = xen_vm_singlestep_end,
    .instr_can_switch_context = xen_vm_instr_can_switch_context,
    .get_tsc = xen_vm_get_tsc,
    .get_time = xen_vm_get_time,
    .get_counter = xen_vm_get_counter,
    .enable_feature = xen_vm_enable_feature,
    .disable_feature = xen_vm_disable_feature,
};

struct argp_option xen_vm_argp_opts[] = {
    /* These options set a flag. */
    { "domain",'m',"DOMAIN",0,"The Xen domain ID or name.",-4 },
    { "kernel-filename",'K',"FILE",0,
          "Override xenstore kernel filepath for guest.",-4 },
    { "configfile",'c',"FILE",0,"The Xen config file.",-4 },
    { "replaydir",'r',"DIR",0,"The XenTT replay directory.",-4 },
    { "xenlib-debug",'x',"LEVEL",0,"Increase/set the XenAccess/OpenVMI debug level.",-4 },
    { 0,0,0,0,0,0 }
};

int xen_vm_spec_to_argv(struct target_spec *spec,int *argc,char ***argv) {
    struct xen_vm_spec *xspec = 
	(struct xen_vm_spec *)spec->backend_spec;
    char **av = NULL;
    int ac = 0;
    int j;

    if (!xspec) {
	if (argv)
	    *argv = NULL;
	if (argc)
	    *argc = 0;
	return 0;
    }
	
    if (xspec->domain) 
	ac += 2;
    if (xspec->config_file)
	ac += 2;
    if (xspec->replay_dir)
	ac += 2;

    av = calloc(ac + 1,sizeof(char *));
    j = 0;
    if (xspec->domain) {
	av[j++] = strdup("-m");
	av[j++] = strdup(xspec->domain);
    }
    if (xspec->kernel_filename) {
	av[j++] = strdup("-K");
	av[j++] = strdup(xspec->kernel_filename);
    }
    if (xspec->config_file) {
	av[j++] = strdup("-c");
	av[j++] = strdup(xspec->config_file);
    }
    if (xspec->replay_dir) {
	av[j++] = strdup("-r");
	av[j++] = strdup(xspec->replay_dir);
    }
    av[j++] = NULL;

    if (argv)
	*argv = av;
    if (argc)
	*argc = ac;

    return 0;
}

error_t xen_vm_argp_parse_opt(int key,char *arg,struct argp_state *state) {
    struct target_argp_parser_state *tstate = \
	(struct target_argp_parser_state *)state->input;
    struct target_spec *spec;
    struct xen_vm_spec *xspec;
    struct argp_option *opti;
    int ourkey;

    if (key == ARGP_KEY_INIT)
	return 0;
    else if (!state->input)
	return ARGP_ERR_UNKNOWN;

    if (tstate)
	spec = tstate->spec;

    /*
     * Check to see if this is really one of our keys.  If it is, we
     * need to see if some other backend has already started parsing
     * args; if it has, we throw an error.  Otherwise, we assume we are
     * using this backend, and process the arg.
     */
    ourkey = 0;
    for (opti = &xen_vm_argp_opts[0]; opti->key != 0; ++opti) {
	if (key == opti->key) {
	    ourkey = 1;
	    break;
	}
    }

    if (ourkey) {
	if (spec->target_type == TARGET_TYPE_NONE) {
	    spec->target_type = TARGET_TYPE_XEN;
	    xspec = calloc(1,sizeof(*xspec));
	    spec->backend_spec = xspec;
	}
	else if (spec->target_type != TARGET_TYPE_XEN) {
	    verror("cannot mix arguments for Xen target (%c) with non-Xen"
		   " target!\n",key);
	    return EINVAL;
	}

	/* Only "claim" these args if this is our key. */
	if (spec->target_type == TARGET_TYPE_NONE) {
	    spec->target_type = TARGET_TYPE_XEN;
	    xspec = calloc(1,sizeof(*xspec));
	    spec->backend_spec = xspec;
	}
	else if (spec->target_type != TARGET_TYPE_XEN) {
	    verror("cannot mix arguments for Xen target with non-Xen target!\n");
	    return EINVAL;
	}
    }

    if (spec->target_type == TARGET_TYPE_XEN)
	xspec = (struct xen_vm_spec *)spec->backend_spec;
    else
	xspec = NULL;

    switch (key) {
    case ARGP_KEY_ARG:
    case ARGP_KEY_ARGS:
	/* Only handle these if you need arguments. */
	return ARGP_ERR_UNKNOWN;
    case ARGP_KEY_INIT:
    case ARGP_KEY_END:
    case ARGP_KEY_NO_ARGS:
	/* Nothing to do unless you malloc something in _INIT. */
	return 0;
    case ARGP_KEY_SUCCESS:
    case ARGP_KEY_ERROR:
    case ARGP_KEY_FINI:
	/* Check spec for sanity if necessary. */
	return 0;

    case 'm':
	xspec->domain = strdup(arg);
	break;
    case 'K':
	xspec->kernel_filename = strdup(arg);
	break;
    case 'c':
	xspec->config_file = strdup(arg);
	break;
    case 'r':
	xspec->replay_dir = strdup(arg);
	break;
    case 'x':
#if defined(ENABLE_XENACCESS)
#if defined(XA_DEBUG)
	if (arg)
	    xa_set_debug_level(atoi(arg));
	else
	    xa_set_debug_level(xa_get_debug_level() + 1);
#endif
#else
	verror("Xen support not compiled in!\n");
	return EINVAL;
#endif
	break;
    default:
	return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

struct argp xen_vm_argp = { 
    xen_vm_argp_opts,xen_vm_argp_parse_opt,NULL,NULL,NULL,NULL,NULL
};
char *xen_vm_argp_header = "Xen Backend Options";

/**
 ** These are the only user-visible functions.
 **/

struct target *xen_vm_instantiate(struct target_spec *spec,
				  struct evloop *evloop) {
    return xen_vm_attach(spec,evloop);
}

struct xen_vm_spec *xen_vm_build_spec(void) {
    struct xen_vm_spec *xspec;

    xspec = calloc(1,sizeof(*xspec));

    return xspec;
}

void xen_vm_free_spec(struct xen_vm_spec *xspec) {
    if (xspec->domain)
	free(xspec->domain);
    if (xspec->config_file)
	free(xspec->config_file);
    if(xspec->replay_dir)
	free(xspec->replay_dir);

    free(xspec);
}

/*
 * Attaches to domid.  We basically check the xenstore to figure out
 * what kernel the domain is running, and try to find vmlinux based on
 * that.  We also read how much mem the domain has; if it is
 * PAE-enabled; 
 */
struct target *xen_vm_attach(struct target_spec *spec,
			     struct evloop *evloop) {
    struct xen_vm_spec *xspec = (struct xen_vm_spec *)spec->backend_spec;
    struct target *target = NULL;
    struct xen_vm_state *xstate = NULL;
    struct xs_handle *xsh = NULL;
    xs_transaction_t xth = XBT_NULL;
    char *buf = NULL;
    char *tmp = NULL;
    char **domains = NULL;
    unsigned int size;
    unsigned int i;
    int have_id = 0;
    unsigned int slen;
    char *domain;

    domain = xspec->domain;
    
    if (geteuid() != 0) {
	verror("must be root!\n");
	errno = EPERM;
	return NULL;
    }

    vdebug(5,LA_TARGET,LF_XV,"attaching to domain %s\n",domain);

    if (!(target = target_create("xen_vm",spec)))
	return NULL;

    if (!(xstate = (struct xen_vm_state *)malloc(sizeof(*xstate)))) {
	free(target);
	return NULL;
    }
    memset(xstate,0,sizeof(*xstate));

    target->state = xstate;

    if (!(buf = malloc(PATH_MAX))) {
	verror("could not allocate tmp path buffer: %s\n",strerror(errno));
	goto errout;
    }

    if (!(xsh = xs_domain_open())) {
	verror("could not open xenstore!\n");
	goto errout;
    }

    xstate->evloop_fd = -1;

    /* First figure out whether we need to resolve the ID, or the name. */
    errno = 0;
    xstate->id = (domid_t)strtol(domain,&tmp,10);
    if (errno == ERANGE) {
	verror("bad domain id: %s\n",strerror(errno));
	goto errout;
    }
    else if (errno == EINVAL || tmp == domain) 
	have_id = 0;
    else {
	vdebug(4,LA_TARGET,LF_XV,"found id %d (from %s)\n",xstate->id,domain);
	have_id = 1;
    }
    tmp = NULL;

    /* We have to try to find the ID first. */
    if (!have_id) {
	domains = xs_directory(xsh,xth,"/local/domain",&size);
	for (i = 0; i < size; ++i) {
	    /* read in name */
	    snprintf(buf,PATH_MAX,"/local/domain/%s/name",domains[i]);
	    tmp = xs_read(xsh,xth,buf,NULL);

	    if (tmp && strcmp(domain,tmp) == 0) {
		vdebug(9,LA_TARGET,LF_XV,"dom %s (from %s) matches\n",tmp,domain);
		errno = 0;
		xstate->id = (domid_t)strtol(domains[i],NULL,10);
		if (errno) {
		    if (have_id) {
			free(tmp);
			break;
		    }
		    verror("matching domain name for %s; but bad domain id %s: %s\n",
			   tmp,domains[i],strerror(errno));
		    free(tmp);
		    goto errout;
		}
		if (have_id)
		    free(xstate->name);
		xstate->name = strdup(tmp);
		have_id = 1;
		vdebug(4,LA_TARGET,LF_XV,"dom %d (from %s) matches id\n",
		       xstate->id,domain);
	    }
	    free(tmp);
        }

	free(domains);
	domains = NULL;

	if (!have_id) {
	    verror("could not find domain id for %s!\n",domain);
	    errno = EINVAL;
	    goto errout;
	}
    }

    /* Once we have an ID, try that to find the name if we need. */
    if (!xstate->name) {
	snprintf(buf,PATH_MAX,"/local/domain/%d/name",xstate->id);
	xstate->name = xs_read(xsh,xth,buf,NULL);
	if (!xstate->name) 
	    vwarn("could not read name for dom %d; may cause problems!\n",
		  xstate->id);
    }

    /* Now try to find vmpath. */
    snprintf(buf,PATH_MAX,"/local/domain/%d/vm",xstate->id);
    xstate->vmpath = xs_read(xsh,xth,buf,NULL);
    if (!xstate->vmpath) 
	vwarn("could not read vmpath for dom %d; may cause problems!\n",
	      xstate->id);

    if (xstate->vmpath) {
	snprintf(buf,PATH_MAX,"%s/image/ostype",xstate->vmpath);
	xstate->ostype = xs_read(xsh,xth,buf,NULL);
	if (!xstate->ostype) 
	    vwarn("could not read ostype for dom %d; may cause problems!\n",
		  xstate->id);
	else if (strcmp(xstate->ostype,"hvm") == 0)
	    xstate->hvm = 1;
    }

    if (xstate->vmpath) {
	snprintf(buf,PATH_MAX,"%s/image/kernel",xstate->vmpath);
	xstate->kernel_filename = xs_read(xsh,xth,buf,NULL);
	if (!xstate->kernel_filename) 
	    vwarn("could not read kernel for dom %d; may cause problems!\n",
		  xstate->id);
    }

    if (xspec->kernel_filename) {
	vdebug(1,LA_TARGET,LF_XV,
	       "using kernel filename %s (overrides %s from xenstore)\n",
	       xspec->kernel_filename,xstate->kernel_filename);
	if (xstate->kernel_filename)
	    free(xstate->kernel_filename);
	xstate->kernel_filename = strdup(xspec->kernel_filename);
    }

    if (xsh) {
	xs_daemon_close(xsh);
	xsh = NULL;
    }

    free(buf);
    buf = NULL;

    /*
     * Now load up our {xa|vmi}_instance as much as we can now; we'll
     * try to do more when we load the debuginfo file for the kernel.
     */
#ifdef ENABLE_XENACCESS
    xstate->xa_instance.os_type = XA_OS_LINUX;
    if (xa_init_vm_id_strict_noos(xstate->id,&xstate->xa_instance) == XA_FAILURE) {
	if (xstate->xa_instance.sysmap)
	    free(xstate->xa_instance.sysmap);
        verror("failed to init xa instance for dom %d\n",xstate->id);
        goto errout;
    }
#endif
#ifdef ENABLE_LIBVMI
    if (vmi_init(&xstate->vmi_instance,
		 VMI_XEN|VMI_INIT_PARTIAL, xstate->name) == VMI_FAILURE) {
        verror("failed to init vmi instance for dom %d\n", xstate->id);
        goto errout;
    }
#endif

    target->live = 1;
    target->writeable = 1;
    target->mmapable = 0; /* XXX: change this once we get mmap API
			     worked out. */

    if (xstate->kernel_filename) {
	/* First, parse out its version.  We look for the first number
	 * followed by a dot.
	 */
	slen = strlen(xstate->kernel_filename);
	for (i = 0; i < slen; ++i) {
	    if (isdigit(xstate->kernel_filename[i])
		&& (i + 1) < slen
		&& xstate->kernel_filename[i + 1] == '.') {
		xstate->kernel_version = &xstate->kernel_filename[i];
		break;
	    }
	}

	if (!xstate->kernel_version) {
	    verror("could not parse kernel version info for %s!\n",
		   xstate->kernel_filename);
	    goto errout;
	}

	/*
	 * Figure out where the real ELF file is.  We look in three
	 * places:
	 *   /usr/lib/debug/lib/modules/<kernel_version>/vmlinux
	 *   /boot/vmlinux-<kernel_version>
	 *   /boot/vmlinux-syms-<kernel_version> (old A3 style)
	 */
	xstate->kernel_elf_filename = malloc(PATH_MAX);
	xstate->kernel_elf_filename[0] = '\0';

	if (xstate->kernel_elf_filename[0] == '\0') {
	    snprintf(xstate->kernel_elf_filename,PATH_MAX,
		     "%s/usr/lib/debug/lib/modules/%s/vmlinux",
		     (target->spec->debugfile_root_prefix)		\
		         ? target->spec->debugfile_root_prefix : "",
		     xstate->kernel_version);
	    if (access(xstate->kernel_elf_filename,R_OK))
		xstate->kernel_elf_filename[0] = '\0';
	}
	if (xstate->kernel_elf_filename[0] == '\0') {
	    snprintf(xstate->kernel_elf_filename,PATH_MAX,
		     "%s/boot/vmlinux-%s",
		     (target->spec->debugfile_root_prefix)		\
		         ? target->spec->debugfile_root_prefix : "",
		     xstate->kernel_version);
	    if (access(xstate->kernel_elf_filename,R_OK))
		xstate->kernel_elf_filename[0] = '\0';
	}
	if (xstate->kernel_elf_filename[0] == '\0') {
	    snprintf(xstate->kernel_elf_filename,PATH_MAX,
		     "%s/boot/vmlinux-syms-%s",
		     (target->spec->debugfile_root_prefix)		\
		         ? target->spec->debugfile_root_prefix : "",
		     xstate->kernel_version);
	    if (access(xstate->kernel_elf_filename,R_OK))
		xstate->kernel_elf_filename[0] = '\0';
	}

	if (xstate->kernel_elf_filename[0] == '\0') {
	    verror("could not find vmlinux binary for %s!\n",
		   xstate->kernel_version);
	    goto errout;
	}

	/*
	 * Figure out where the System.map file is.  We look in two
	 * places:
	 *   /lib/modules/<kernel_version>/System.map 
	 *   /boot/System.map-<kernel_version>
	 */
	xstate->kernel_sysmap_filename = malloc(PATH_MAX);
	xstate->kernel_sysmap_filename[0] = '\0';

	if (xstate->kernel_sysmap_filename[0] == '\0') {
	    snprintf(xstate->kernel_sysmap_filename,PATH_MAX,
		     "%s/lib/modules/%s/System.map",
		     (target->spec->debugfile_root_prefix)		\
		         ? target->spec->debugfile_root_prefix : "",
		     xstate->kernel_version);
	    if (access(xstate->kernel_sysmap_filename,R_OK))
		xstate->kernel_sysmap_filename[0] = '\0';
	}
	if (xstate->kernel_sysmap_filename[0] == '\0') {
	    snprintf(xstate->kernel_sysmap_filename,PATH_MAX,
		     "%s/boot/System.map-%s",
		     (target->spec->debugfile_root_prefix)		\
		         ? target->spec->debugfile_root_prefix : "",
		     xstate->kernel_version);
	    if (access(xstate->kernel_sysmap_filename,R_OK))
		xstate->kernel_sysmap_filename[0] = '\0';
	}

	if (xstate->kernel_sysmap_filename[0] == '\0') {
	    verror("could not find System.map file for %s!\n",
		   xstate->kernel_version);
	    goto errout;
	}

	/* Figure out where the modules are. */
	if ((tmp = strstr(xstate->kernel_filename,"vmlinuz-"))) {
	    xstate->kernel_module_dir = malloc(PATH_MAX);
	    snprintf(xstate->kernel_module_dir,PATH_MAX,
		     "/lib/modules/%s",tmp+strlen("vmlinuz-"));
	}
    }

    if (!xstate->kernel_elf_filename) {
	verror("could not infer kernel ELF file (vmlinux) from %s; aborting!\n",
	       xstate->kernel_filename);
	goto errout;
    }

    /* Then grab stuff from the ELF binary itself. */
    target->binfile = 
	binfile_open__int(xstate->kernel_elf_filename,
			  target->spec->debugfile_root_prefix,NULL);
    if (!target->binfile) {
	verror("binfile_open %s: %s\n",
	       xstate->kernel_elf_filename,strerror(errno));
	goto errout;
    }

    RHOLD(target->binfile,target);

    target->wordsize = target->binfile->wordsize;
    target->endian = target->binfile->endian;
    target->ptrsize = target->wordsize;

    vdebug(3,LA_TARGET,LF_XV,
	   "loaded ELF arch info for %s (wordsize=%d;endian=%s\n",
	   xstate->kernel_elf_filename,target->wordsize,
	   (target->endian == DATA_LITTLE_ENDIAN ? "LSB" : "MSB"));

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

    if (evloop && xstate->evloop_fd < 0) {
	/*
	 * Just save it off; we can't use it until in xen_vm_attach_internal.
	 */
	target->evloop = evloop;
    }

    vdebug(5,LA_TARGET,LF_XV,"opened dom %d\n",xstate->id);

    return target;

 errout:
    if (domains) {
	for (i = 0; i < size; ++i) {
	    free(domains[i]);
	}
	free(domains);
    }
    if (xstate->vmpath)
	free(xstate->vmpath);
    if (xstate->ostype)
	free(xstate->ostype);
    if (xstate->kernel_filename)
	free(xstate->kernel_filename);
    if (xstate->kernel_elf_filename)
	free(xstate->kernel_elf_filename);
    if (xstate->kernel_sysmap_filename)
	free(xstate->kernel_sysmap_filename);
    if (xstate->kernel_module_dir)
	free(xstate->kernel_module_dir);
    if (xstate->name)
	free(xstate->name);
    if (xsh)
	xs_daemon_close(xsh);
    if (xstate)
	free(xstate);
    if (target)
	free(target);

    return NULL;
}

/**
 ** Utility functions.
 **/

static int xen_vm_load_dominfo(struct target *target) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)(target->state);

    if (!xstate->dominfo_valid) {
        vdebug(4,LA_TARGET,LF_XV,
	       "load dominfo; current dominfo is invalid\n");
	memset(&xstate->dominfo,0,sizeof(xstate->dominfo));
	if (xc_domain_getinfo(xc_handle,xstate->id,1,
			      &xstate->dominfo) <= 0) {
	    verror("could not get domaininfo for %d\n",xstate->id);
	    errno = EINVAL;
	    return -1;
	}

	/*
	 * Only do this once, and use libxc directly.
	 */
	if (unlikely(!xstate->live_shinfo)) {
	    xstate->live_shinfo = 
		xc_map_foreign_range(xc_handle,xstate->id,PAGE_SIZE,PROT_READ,
				     xstate->dominfo.shared_info_frame);
	    if (!xstate->live_shinfo) {
		verror("could not mmap shared_info frame 0x%"PRIxADDR"!\n",
		       xstate->dominfo.shared_info_frame);
		errno = EFAULT;
		return -1;
	    }
	}

	/*
	 * Have to grab vcpuinfo out of shared frame, argh!  This can't
	 * be the only way to access the tsc, but I can't find a better
	 * libxc way to do it!
	 *
	 * XXX: Do we really have to do this every time the domain is
	 * interrupted?
	 */
	memcpy(&xstate->vcpuinfo,&xstate->live_shinfo->vcpu_info[0],
	       sizeof(xstate->vcpuinfo));

	xstate->dominfo_valid = 1;
    }
    else {
        vdebug(8,LA_TARGET,LF_XV,
	       "did not need to load dominfo; current dominfo is valid\n");
    }

    return 0;
}

static struct target_thread *xen_vm_load_cached_thread(struct target *target,
						       tid_t tid) {
    struct target_thread *tthread;

    tthread = target_lookup_thread(target,tid);
    if (!tthread)
	return NULL;

    if (!tthread->valid)
	return xen_vm_load_thread(target,tid,0);

    return tthread;
}

static int xen_get_cpl(struct target *target,tid_t tid) {
    REGVAL cs;
    struct target_thread *tthread;

    if (!(tthread = xen_vm_load_cached_thread(target,tid))) {
	if (!errno) 
	    errno = EINVAL;
	verror("could not load cached thread %"PRIiTID"\n",tid);
	return 0;
    }

    /* Load the CPL. */
    errno = 0;
    cs = 0x3 & xen_vm_read_reg(target,tthread->tid,
			       xen_vm_dw_reg_no(target,CREG_CS));
    if (errno) {
	verror("could not read CS register to find CPL!\n");
	return -1;
    }

    if (cs > 3) {
	verror("bogus CPL %d!\n",cs);
	errno = EFAULT;
	return -1;
    }

    return (int)cs;
}

struct target_thread *__xen_vm_load_thread_from_value(struct target *target,
						      struct value *taskv) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;
    struct target_thread *tthread;
    struct xen_vm_thread_state *tstate = NULL;
    tid_t tid;
    num_t tgid = 0;
    num_t task_flags = 0;
    struct value *threadinfov = NULL;
    unum_t tiflags = 0;
    num_t preempt_count = 0;
    struct value *threadv = NULL;
    struct value *v = NULL;
    int iskernel = 0;
    ADDR stack_top;
    char *comm = NULL;
    ADDR stack_member_addr;
    int i;
    int ip_offset;

    vdebug(5,LA_TARGET,LF_XV,"loading\n");

    v = target_load_value_member(target,taskv,"pid",NULL,LOAD_FLAG_NONE);
    if (!v) {
	verror("could not load pid in task value; BUG?\n");
	/* errno should be set for us. */
	goto errout;
    }
    tid = v_i32(v);
    value_free(v);
    v = NULL;

    v = target_load_value_member(target,taskv,"comm",NULL,LOAD_FLAG_NONE);
    if (!v) {
	verror("could not load comm in task value; BUG?\n");
	/* errno should be set for us. */
	goto errout;
    }
    comm = strndup(v->buf,v->bufsiz);
    value_free(v);
    v = NULL;

    v = target_load_value_member(target,taskv,"tgid",NULL,LOAD_FLAG_NONE);
    if (!v) {
	verror("could not load tgid in task %"PRIiTID"; BUG?\n",tid);
	/* errno should be set for us. */
	goto errout;
    }
    tgid = v_num(v);
    value_free(v);
    v = NULL;

    v = target_load_value_member(target,taskv,"flags",NULL,LOAD_FLAG_NONE);
    if (!v) {
	verror("could not load flags in task %"PRIiTID"; BUG?\n",tid);
	/* errno should be set for us. */
	goto errout;
    }
    task_flags = v_num(v);
    value_free(v);
    v = NULL;

    /*
     * Before loading anything else, check the cache.
     */
    tthread = target_lookup_thread(target,tid);
    if (tthread) {
	tstate = (struct xen_vm_thread_state *)tthread->state;

	/* Check if this is a cached entry for an old task */
	if (tstate->tgid != tgid 
	    || tstate->task_struct_addr != value_addr(taskv)) {
	    target_add_state_change(target,tid,TARGET_STATE_CHANGE_THREAD_EXITED,
				    0,0,0,0,NULL);
	    target_delete_thread(target,tthread,0);
	    tstate = NULL;
	    tthread = NULL;
	}
    }

    if (!tthread) {
	/* Build a new one. */
	tstate = (struct xen_vm_thread_state *)calloc(1,sizeof(*tstate));

	tthread = target_create_thread(target,tid,tstate);

	target_add_state_change(target,tid,TARGET_STATE_CHANGE_THREAD_CREATED,
				0,0,0,0,NULL);
    }
    else {
	/*
	 * If this is the current thread, we cannot load it from its
	 * task_struct value (especially its register state!).  The
	 * current_thread should have been loaded by now, so if it has
	 * been loaded, don't reload from the thread stack (because the
	 * thread stack does not have saved registers because the thread
	 * is running!).
	 *
	 * XXX: to support SMP, we would have to check the task_struct's
	 * running status, and only load from CPU in those cases.
	 */
	if (tthread == target->current_thread
	    && target->current_thread->valid) {
	    vdebug(8,LA_TARGET,LF_XV,
		   "not loading running, valid current thread %"PRIiTID" from"
		   " task_struct 0x%"PRIxADDR"; loaded from CPU of course\n",
		   tid,value_addr(taskv));
	    return target->current_thread;
	}
    }

    if (xstate->task_struct_has_thread_info) {
	threadinfov = target_load_value_member(target,taskv,"thread_info",NULL,
					       LOAD_FLAG_AUTO_DEREF);
	if (!threadinfov) {
	    verror("could not load thread_info in task %"PRIiTID"; BUG?\n",tid);
	    /* errno should be set for us. */
	    goto errout;
	}
    }
    else if (xstate->task_struct_has_stack) {
	v = target_load_value_member(target,taskv,"stack",NULL,LOAD_FLAG_NONE);
	if (!v) {
	    verror("could not load stack (thread_info) in task %"PRIiTID";"
		   " BUG?\n",tid);
	    /* errno should be set for us. */
	    goto errout;
	}
	stack_member_addr = v_addr(v);
	value_free(v);
	v = NULL;

	threadinfov = target_load_type(target,xstate->thread_info_type,
				       stack_member_addr,LOAD_FLAG_NONE);
	if (!threadinfov) {
	    verror("could not load stack (thread_info) in task %"PRIiTID";"
		   " BUG?\n",tid);
	    goto errout;
	}
    }
    else {
	verror("cannot load thread_info/stack; no thread support!\n");
	goto errout;
    }

    v = target_load_value_member(target,threadinfov,"flags",NULL,
				 LOAD_FLAG_NONE);
    if (!v) {
	verror("could not load thread_info.flags in task %"PRIiTID"; BUG?\n",tid);
	/* errno should be set for us. */
	goto errout;
    }
    tiflags = v_unum(v);
    value_free(v);
    v = NULL;

    v = target_load_value_member(target,threadinfov,"preempt_count",NULL,
				 LOAD_FLAG_NONE);
    if (!v) {
	verror("could not load thread_info.preempt_count in task %"PRIiTID";"
	       " BUG?\n",tid);
	/* errno should be set for us. */
	goto errout;
    }
    preempt_count = v_num(v);
    value_free(v);
    v = NULL;

    tstate->task_struct_addr = value_addr(taskv);
    tstate->task_struct = taskv;
    tstate->tgid = tgid;
    tstate->task_flags = task_flags;
    tstate->thread_info = threadinfov;
    tstate->thread_info_flags = tiflags;
    tstate->thread_info_preempt_count = preempt_count;

    /*
     * If we have the thread, we can load as much of the stuff in the
     * vcpu_guest_context struct as the kernel contains!
     */
    memset(&tstate->context,0,sizeof(vcpu_guest_context_t));

    v = target_load_value_member(target,taskv,"mm",NULL,LOAD_FLAG_NONE);
    if (!v) {
	verror("could not see if thread %"PRIiTID" was kernel or user\n",tid);
	goto errout;
    }
    tstate->mm_addr = v_addr(v);
    if (tstate->mm_addr == 0)
	iskernel = 1;
    value_free(v);
    v = NULL;

    if (tstate->mm_addr) {
	v = target_load_value_member(target,taskv,"mm.pgd",NULL,
				     LOAD_FLAG_AUTO_DEREF);
	if (!v) {
	    verror("could not load thread %"PRIiTID" pgd (for cr3 tracking)\n",
		   tid);
	    goto errout;
	}
	tstate->pgd = v_u64(v);
	value_free(v);
	v = NULL;
    }

    /*
     * In our world, a Linux thread will not be executing an interrupt
     * top/bottom half (ISR or softirq) if it is not running (i.e.,
     * ISRs/softirqs are not preemptible).  So, if the sleeping thread
     * is in kernel context, the task's state (registers) are on the
     * stack in the right place, unless we are in a section of the code
     * that is setting up the stack or tearing it down (i.e., preempted
     * during syscall init or something -- unless this is not possible
     * if the kernel disables interrupts in those critical
     * sections...).  BUT, even if this is true, the current machine
     * state will have been pushed on the stack to handle the interrupt
     * (and perhaps the following context switch, if there is one after
     * servicing the ISR/softirq(s)).
     *
     * Thus, we don't have to check what the thread is executing.
     *
     * It doesn't matter whether the thread is a kernel thread or not.
     */
    if (iskernel) {
	target_thread_set_status(tthread,THREAD_STATUS_RETURNING_KERNEL);
	tthread->supported_overlay_types = TARGET_TYPE_NONE;
    }
    else {
	target_thread_set_status(tthread,THREAD_STATUS_RETURNING_USER);
	tthread->supported_overlay_types = TARGET_TYPE_XEN_PROCESS;
    }

    if (tthread->name)
	free(tthread->name);
    tthread->name = comm;
    comm = NULL;

    /*
     * Load the stored registers from the kernel stack; except fs/gs and
     * the debug regs are in the task_struct->thread thread_struct
     * struct.
     */
    threadv = target_load_value_member(target,taskv,"thread",NULL,
				       LOAD_FLAG_NONE);
    if (!threadv) {
	verror("could not load thread_struct for task %"PRIiTID"!\n",tid);
	goto errout;
    }

    tstate->thread_struct = threadv;

    v = target_load_value_member(target,threadv,xstate->thread_sp_member_name,
				 NULL,LOAD_FLAG_NONE);
    if (!v) {
	verror("could not load thread.%s for task %"PRIiTID"!\n",
	       xstate->thread_sp_member_name,tid);
	goto errout;
    }
    tstate->esp = v_addr(v);
    value_free(v);
    v = NULL;

    /* The stack base is also the value of the task_struct->thread_info ptr. */
    tstate->stack_base = value_addr(threadinfov);
    stack_top = tstate->stack_base + THREAD_SIZE;

    /* See include/asm-i386/processor.h .  And since it doesn't explain
     * why it is subtracting 8, it's because fs/gs are not pushed on the
     * stack, so the ptrace regs struct doesn't really match with what's
     * on the stack ;).
     */
    if (iskernel && preempt_count) {
	if (target->wordsize == 8) {
	    tstate->ptregs_stack_addr = 
		stack_top - 0 - symbol_bytesize(xstate->pt_regs_type);
	}
	else {
	    tstate->ptregs_stack_addr = 
		stack_top - 8 - symbol_bytesize(xstate->pt_regs_type);
	}
	//tstate->ptregs_stack_addr = tstate->esp - 8 - 15 * 4;
	// + 8 - 7 * 4; // - 8 - 15 * 4;
    }
    /*
     * Registers are not saved if it's a sleeping, non-preempted kernel
     * thread.  All that was saved is the esp and eip, and fs/gs, in the
     * thread struct.  Registers are only saved on kernel interrupt, or
     * mode switch from user to kernel mode.  The best we could do is
     * look into schedule()'s frame and look at its saved registers so
     * that we could see what schedule's caller will have -- and then
     * look and see what the caller saved.  Anything else is trashed.
     */
    else if (iskernel) {
	tstate->ptregs_stack_addr = 0;
	/*
	v = target_load_addr_real(target,esp0,LOAD_FLAG_NONE,32*4);
	int i;
	for (i = 0; i < 32; ++i) {
	    vwarn("%d esp[%d] = 0x%x\n",tid,i,((int *)v->buf)[i]);
	}
	value_free(v);
	v = NULL;
	*/
    }
    else if (target->wordsize == 8) {
	tstate->ptregs_stack_addr = 
	    stack_top - 0 - symbol_bytesize(xstate->pt_regs_type);
    }
    else {
	tstate->ptregs_stack_addr = 
	    stack_top - 8 - symbol_bytesize(xstate->pt_regs_type);
    }

    vdebug(5,LA_TARGET,LF_XV,
	   "esp=%"PRIxADDR",stack_base=%"PRIxADDR",stack_top=%"PRIxADDR
	   ",ptregs_stack_addr=%"PRIxADDR"\n",
	   tstate->esp,stack_top,tstate->stack_base,tstate->ptregs_stack_addr);

    v = target_load_value_member(target,threadv,xstate->thread_sp0_member_name,
				 NULL,LOAD_FLAG_NONE);
    if (!v) 
	vwarn("could not load thread.%s for task %"PRIiTID"!\n",
	      xstate->thread_sp0_member_name,tid);
    tstate->esp0 = v_addr(v);
    value_free(v);
    v = NULL;

    /*
     * On x86_64, %ip is not tracked -- there's no point anyway --
     * either it's in the scheduler at context switch, or it's at
     * ret_from_fork -- no point loading.  But still, it's on the kernel
     * stack at *(thread.sp - 8).  That's how we load it.
     */
    if (xstate->thread_ip_member_name) {
	v = target_load_value_member(target,threadv,xstate->thread_ip_member_name,
				     NULL,LOAD_FLAG_NONE);
	if (!v) 
	    vwarn("could not load thread.%s for task %"PRIiTID"!\n",
		  xstate->thread_ip_member_name,tid);
	else {
	    tstate->eip = v_addr(v);
	    value_free(v);
	    v = NULL;
	}
    }
    else {
	v = target_load_addr_real(target,tstate->esp + 3 * target->wordsize,
				  LOAD_FLAG_NONE,target->wordsize);
	if (!v) 
	    vwarn("could not 64-bit IP (thread.ip) for task %"PRIiTID"!\n",
		  tid);
	else {
	    tstate->eip = v_addr(v);
	    value_free(v);
	    v = NULL;
	}
    }

    /*
     * For old i386 stuff, fs/gs are in the thread data structure.
     * For newer x86 stuff, only gs is saved in thread_struct; fs is on
     * the stack.
     *
     * For x86_64, ds/es are saved in thread_struct; some threads have
     * 64-bit fs/gs bases in thread_struct; the fs/gs segment selectors
     * are saved in fsindex/gsindex.  Not sure how to expose fs/gs in
     * this model... for now we ignore fsindex/gsindex.
     */
    if (xstate->thread_struct_has_fs) {
	v = target_load_value_member(target,threadv,"fs",NULL,LOAD_FLAG_NONE);
	if (!v) {
	    vwarn("could not load thread.fs for task %"PRIiTID"!\n",tid);
	    goto errout;
	}
	else {
	    tstate->fs = tstate->context.user_regs.fs = v_u16(v);
	    value_free(v);
	    v = NULL;
	}
    }
    else {
	/* Load this from pt_regs below if we can. */
	tstate->fs = tstate->context.user_regs.fs = 0;
    }

    /* Everybody always has gs. */
    v = target_load_value_member(target,threadv,"gs",NULL,LOAD_FLAG_NONE);
    if (!v) {
	verror("could not load thread.gs for task %"PRIiTID"!\n",tid);
	goto errout;
    }
    else {
	tstate->gs = tstate->context.user_regs.gs = v_u16(v);
	value_free(v);
	v = NULL;
    }

    if (xstate->thread_struct_has_ds_es) {
	v = target_load_value_member(target,threadv,"ds",NULL,LOAD_FLAG_NONE);
	if (!v) {
	    vwarn("could not load thread.ds for task %"PRIiTID"!\n",tid);
	    goto errout;
	}
	else {
	    if (target->wordsize == 8)
		tstate->context.user_regs.ds = v_u64(v);
	    else 
		tstate->context.user_regs.ds = v_u32(v);
	    value_free(v);
	    v = NULL;
	}

	v = target_load_value_member(target,threadv,"es",NULL,LOAD_FLAG_NONE);
	if (!v) {
	    vwarn("could not load thread.es for task %"PRIiTID"!\n",tid);
	    goto errout;
	}
	else {
	    if (target->wordsize == 8)
		tstate->context.user_regs.es = v_u64(v);
	    else 
		tstate->context.user_regs.es = v_u32(v);
	    value_free(v);
	    v = NULL;
	}
    }
    else {
	/* Load this from pt_regs below if we can. */
	tstate->context.user_regs.ds = 0;
	tstate->context.user_regs.es = 0;
    }

    if (tstate->ptregs_stack_addr) {
	/*
	 * The xen cpu_user_regs struct, and pt_regs struct, tend to
	 * align (no pun intended) reasonably well.  On i386, we can
	 * copy pt_regs::(e)bx--(e)ax directly to cpu_user_regs::ebx--eax;
	 * then copy pt_regs::(e)ip--(x)ss to cpu_user_regs::eip--ss.
	 * For x86_64, the same is basically true; the ranges are
	 * r15--(r)di, and (r)ip--ss.
	 *
	 * (The (X) prefixes are because the Linux kernel x86 and x86_64
	 * struct pt_regs member names have changed over the years; but
	 * by just doing this brutal copying, we can ignore all that --
	 * which is faster from a value-loading perspective.)
	 *
	 * (This all works because Xen's cpu_user_regs has been
	 * carefully mapped to x86 and x86_64 pt_regs structs, in the
	 * specific register ranges listed (the Xen structs have some
	 * other things in the middle and es/ds/fs/gs regs at the end,
	 * so it's not a complete alignment.)
	 */
	v = target_load_addr_real(target,tstate->ptregs_stack_addr,
				  LOAD_FLAG_NONE,
				  symbol_bytesize(xstate->pt_regs_type));
	if (!v) {
	    verror("could not load stack register save frame task %"PRIiTID"!\n",
		   tid);
	    goto errout;
	}

	/* Copy the first range. */
	if (target->wordsize == 8)
	    memcpy(&tstate->context.user_regs,v->buf,8 * 15);
	else
	    memcpy(&tstate->context.user_regs,v->buf,4 * 7);

	/* Copy the second range. */
	/**
	 ** WARNING: esp and ss may not be valid if the sleeping thread was
	 ** interrupted while it was in the kernel, because the interrupt
	 ** gate does not push ss and esp; see include/asm-i386/processor.h .
	 **/
#if __WORDSIZE == 64
	ip_offset = offsetof(struct vcpu_guest_context,user_regs.rip);
#else
	ip_offset = offsetof(struct vcpu_guest_context,user_regs.eip);
#endif
	if (target->wordsize == 8)
	    memcpy(((char *)&tstate->context) + ip_offset,
		   v->buf + xstate->pt_regs_ip_offset,8 * 5);
	else
	    memcpy(((char *)&tstate->context) + ip_offset,
		   v->buf + xstate->pt_regs_ip_offset,4 * 5);

	/*
	 * ds, es, fs, gs are all special; see other comments.
	 */
	if (!xstate->thread_struct_has_ds_es && xstate->pt_regs_has_ds_es) {
	    /* XXX: this works because we know the location of (x)ds/es;
	     * it's only on i386/x86; and because Xen pads its
	     * cpu_user_regs structs from u16s to ulongs for segment
	     * registers.  :)
	     */
	    memcpy(&tstate->context.user_regs.ds,
		   (char *)v->buf + 7 * target->wordsize,v->bufsiz);
	    memcpy(&tstate->context.user_regs.es,
		   (char *)v->buf + 8 * target->wordsize,v->bufsiz);
	}
	if (!xstate->thread_struct_has_fs && xstate->pt_regs_has_fs_gs) {
	    /* XXX: this is only true on newer x86 stuff; x86_64 and old
	     * i386 stuff did not save it on the stack.
	     */
	    memcpy(&tstate->context.user_regs.fs,
		   (char *)v->buf + 9 * target->wordsize,v->bufsiz);
	}

	value_free(v);
	v = NULL;
    }
    else {
	/*
	 * Either we could not load pt_regs due to lack of type info; or
	 * this thread was just context-switched out, not interrupted
	 * nor preempted, so we can't get its GP registers.  Get what we
	 * can...
	 */
	memset(&tstate->context,0,sizeof(vcpu_guest_context_t));
	tstate->context.user_regs.eip = tstate->eip;
	tstate->context.user_regs.esp = tstate->esp;
	tstate->context.user_regs.fs = tstate->fs;
	tstate->context.user_regs.gs = tstate->gs;

	/* eflags and ebp are on the stack. */
	v = target_load_addr_real(target,tstate->esp,LOAD_FLAG_NONE,
				  2 * target->wordsize);
	if (target->wordsize == 8) {
	    tstate->eflags = ((uint64_t *)v->buf)[1];
	    tstate->ebp = ((uint64_t *)v->buf)[0];
	}
	else {
	    tstate->eflags = ((uint32_t *)v->buf)[1];
	    tstate->ebp = ((uint32_t *)v->buf)[0];
	}		
	value_free(v);
	v = NULL;

	tstate->context.user_regs.eflags = tstate->eflags;
	tstate->context.user_regs.ebp = tstate->ebp;
    }

    /*
     * Load the current debug registers from the thread.
     */
    if (xstate->thread_struct_has_debugreg) {
	v = target_load_value_member(target,threadv,"debugreg",NULL,
				     LOAD_FLAG_AUTO_DEREF);
	if (!v) {
	    verror("could not load thread->debugreg for task %"PRIiTID"\n",tid);
	    goto errout;
	}
	if (target->wordsize == 8) {
	    tstate->context.debugreg[0] = ((uint64_t *)v->buf)[0];
	    tstate->context.debugreg[1] = ((uint64_t *)v->buf)[1];
	    tstate->context.debugreg[2] = ((uint64_t *)v->buf)[2];
	    tstate->context.debugreg[3] = ((uint64_t *)v->buf)[3];
	    tstate->context.debugreg[6] = ((uint64_t *)v->buf)[6];
	    tstate->context.debugreg[7] = ((uint64_t *)v->buf)[7];
	}
	else {
	    tstate->context.debugreg[0] = ((uint32_t *)v->buf)[0];
	    tstate->context.debugreg[1] = ((uint32_t *)v->buf)[1];
	    tstate->context.debugreg[2] = ((uint32_t *)v->buf)[2];
	    tstate->context.debugreg[3] = ((uint32_t *)v->buf)[3];
	    tstate->context.debugreg[6] = ((uint32_t *)v->buf)[6];
	    tstate->context.debugreg[7] = ((uint32_t *)v->buf)[7];
	}
	value_free(v);
	v = NULL;
    }
    else if (xstate->thread_struct_has_debugreg0) {
	/*
	 * This is old x86_64 style.
	 */
	static const char *dregmembers[8] = {
	    "debugreg0","debugreg1","debugreg2","debugreg3",
	    NULL,NULL,
	    "debugreg6","debugreg7"
	};

	for (i = 0; i < 8; ++i) {
	    if (!dregmembers[i])
		continue;

	    v = target_load_value_member(target,threadv,dregmembers[i],NULL,
					 LOAD_FLAG_AUTO_DEREF);
	    if (!v) {
		verror("could not load thread->%s for task %"PRIiTID"\n",
		       dregmembers[i],tid);
		goto errout;
	    }
	    if (target->wordsize == 8) 
		tstate->context.debugreg[i] = *(uint64_t *)v->buf;
	    else
		tstate->context.debugreg[i] = *(uint32_t *)v->buf;
	    value_free(v);
	    v = NULL;
	}
    }
    else if (xstate->thread_struct_has_perf_debugreg) {
	/*
	 * XXX: still need to load perf_events 0-3.
	 */

	v = target_load_value_member(target,threadv,"debugreg6",NULL,
				     LOAD_FLAG_AUTO_DEREF);
	if (!v) {
	    verror("could not load thread->debugreg6 for task %"PRIiTID"\n",tid);
	    goto errout;
	}
	if (target->wordsize == 8) 
	    tstate->context.debugreg[6] = *(uint64_t *)v->buf;
	else
	    tstate->context.debugreg[6] = *(uint32_t *)v->buf;
	value_free(v);
	v = NULL;

	v = target_load_value_member(target,threadv,"ptrace_dr7",NULL,
				     LOAD_FLAG_AUTO_DEREF);
	if (!v) {
	    verror("could not load thread->ptrace_dr7 for task %"PRIiTID"\n",tid);
	    goto errout;
	}
	if (target->wordsize == 8) 
	    tstate->context.debugreg[7] = *(uint64_t *)v->buf;
	else
	    tstate->context.debugreg[7] = *(uint32_t *)v->buf;
	value_free(v);
	v = NULL;

    }
    else {
	vwarn("could not load debugreg for tid %d; no debuginfo!\n",tid);
    }

    vdebug(4,LA_TARGET,LF_XV,
	   "debug registers (kernel context): 0x%"PRIxADDR",0x%"PRIxADDR
	   ",0x%"PRIxADDR",0x%"PRIxADDR",0,0,0x%"PRIxADDR",0x%"PRIxADDR"\n",
	   tstate->context.debugreg[0],tstate->context.debugreg[1],
	   tstate->context.debugreg[2],tstate->context.debugreg[3],
	   tstate->context.debugreg[6],tstate->context.debugreg[7]);

    if (v) 
	value_free(v);
    if (comm)
	free(comm);

    tthread->valid = 1;

    return tthread;

 errout:
    if (v) 
	value_free(v);
    if (comm)
	free(comm);
    if (threadinfov) 
	value_free(threadinfov);
    if (threadv)
	value_free(threadv);
    if (tstate) {
	tstate->thread_info = NULL;
	tstate->thread_struct = NULL;
	tstate->task_struct = NULL;
    }

    return NULL;
}

static struct target_thread *xen_vm_load_thread(struct target *target,
						tid_t tid,int force) {
    struct target_thread *tthread = NULL;
    struct xen_vm_thread_state *xtstate;
    struct value *taskv = NULL;
    int taskv_loaded;

    /*
     * If we are asking for the global thread (TID_GLOBAL), do that
     * right away.
     */
    if (tid == TID_GLOBAL) {
	/*
	 * We have to *not* call _load_current_thread if the global
	 * thread is valid.  This is part of a hack (chicken and egg)
	 * problem where to "fully" load the global thread, we must have
	 * its registers.  Our register read functions try to load the
	 * current thread if it's not loaded.  So... see
	 * _load_current_thread for more...
	 */
	if (target->global_thread->valid)
	    return target->global_thread;
	else {
	    xen_vm_load_current_thread(target,force);
	    return target->global_thread;
	}
    }

    /*
     * If we haven't loaded current_thread yet, we really should load it
     * because otherwise we don't know if current_thread->tid == @tid.
     * If it does, we don't want to do the below stuff, which only
     * applies to non-running threads.
     */
    if (!xen_vm_load_current_thread(target,force)) {
	vwarn("could not load current thread to compare with"
	      " tid %"PRIiTID"!\n",tid);
    }

    /*
     * If the thread tid we are asking for is the current thread and is
     * valid, or if the thread is in our cache and is valid.
     */
    else if (target->current_thread 
	     && target->current_thread->valid
	     && target->current_thread->tid == tid) {
	return xen_vm_load_current_thread(target,force);
    }
    /*
     * Otherwise, try to lookup thread @tid.
     */
    else if ((tthread = target_lookup_thread(target,tid))) {
	if (tthread->valid && !force) {
	    vdebug(4,LA_TARGET,LF_XV,"did not need to load thread; copy is valid\n");
	    return tthread;
	}
    }

    /*
     * Note:
     *
     * At this point, we can be sure that we are loading a thread that
     * is not running; thus, its CPU state is on the kernel stack.
     */

    /* 
     * We need to find the task on the kernel's task list that matches
     * @tid.  If no match, but we had a thread with a matching @tid in
     * our cache, we need to nuke that thread.  If there is a match, but
     * its core data is different than what's in the cache, we have to
     * nuke the old task from the cache and build a new one.  If the
     * match matches, just reload its volatile data and context.
     */

    if (target_status(target) != TSTATUS_PAUSED) {
	verror("target not paused; cannot load current task!\n");
	errno = EBUSY;
	return NULL;
    }

    /*
     * If we didn't find a cached thread, or we're not live-tracking
     * thread exit, check for stale thread!  If we have a cached thread,
     * and we are tracking EXITs, we don't need to walk the task list.
     */
    if (!tthread 
	|| !(target->active_probe_flags & ACTIVE_PROBE_FLAG_THREAD_EXIT)) {
	taskv = linux_get_task(target,tid);
	taskv_loaded = 1;

	if (!taskv) {
	    vwarn("no task matching %"PRIiTID"\n",tid);

	    if (tthread) {
		vdebug(3,LA_TARGET,LF_XV,
		       "evicting old thread %"PRIiTID"; no longer exists!\n",tid);
		target_add_state_change(target,tthread->tid,
					TARGET_STATE_CHANGE_THREAD_EXITED,
					0,0,0,0,NULL);
		target_delete_thread(target,tthread,0);
	    }

	    return NULL;
	}
    }
    else {
	taskv_loaded = 0;
	xtstate = (struct xen_vm_thread_state *)tthread->state;

	if (!value_refresh(xtstate->task_struct,1)) {
	    verror("could not refresh cached struct; aborting to manual update!\n");

	    taskv = linux_get_task(target,tid);
	    taskv_loaded = 1;

	    if (!taskv) {
		vwarn("no task matching %"PRIiTID"\n",tid);

		if (tthread) {
		    vdebug(3,LA_TARGET,LF_XV,
			   "evicting old thread %"PRIiTID"; no longer exists!\n",
			   tid);
		    target_add_state_change(target,tthread->tid,
					    TARGET_STATE_CHANGE_THREAD_EXITED,
					    0,0,0,0,NULL);
		    target_delete_thread(target,tthread,0);
		}

		return NULL;
	    }
	}
    }

    if (!(tthread = __xen_vm_load_thread_from_value(target,taskv)))
	goto errout;

    return tthread;

 errout:
    if (taskv_loaded && taskv)
	value_free(taskv);

    return NULL;
}

static struct target_thread *
__xen_vm_load_current_thread_from_userspace(struct target *target,int force) {
    GHashTableIter iter;
    struct target_thread *tthread = NULL;
    struct xen_vm_thread_state *xtstate;
    uint64_t cr3;
    REGVAL ipval;

#if __WORDSIZE == 64
    /*
     * libxc claims that for x86_64, pagetable is in CR1.
     */
    cr3 = (uint64_t)xen_vm_read_reg(target,TID_GLOBAL,XV_TSREG_CR1);
#else
    cr3 = (uint64_t)xen_vm_read_reg(target,TID_GLOBAL,XV_TSREG_CR3);
#endif

    ipval = xen_vm_read_reg(target,TID_GLOBAL,target->ipregno);

    vdebug(5,LA_TARGET,LF_XV,
	   "ip 0x%"PRIxADDR"; cr3/pgd = 0x%"PRIx64"\n",ipval,cr3);

    /*
     * First, we scan our current cache; if we find a cr3 hit, we're
     * money.  Otherwise, we have load all tasks (well, at least until
     * we find what we need).
     */
    g_hash_table_iter_init(&iter,target->threads);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer *)&tthread)) {
	xtstate = (struct xen_vm_thread_state *)tthread->state;

	if (xtstate->pgd == cr3) 
	    break;
	else {
	    tthread = NULL;
	    xtstate = NULL;
	}
    }

    if (!tthread) {
	vdebug(5,LA_TARGET,LF_XV,
	       "could not find task match for cr3 0x%"PRIx64";"
	       " loading all tasks!\n",cr3);

	/*
	 * We really should just use a reverse init_task list traversal
	 * here.  The task is most likely to be nearer the end.
	 */
	if (xen_vm_load_available_threads(target,force)) {
	    verror("could not load all threads to match on cr3!\n");
	    return NULL;
	}

	/* Search again. */
	g_hash_table_iter_init(&iter,target->threads);
	while (g_hash_table_iter_next(&iter,NULL,(gpointer *)&tthread)) {
	    xtstate = (struct xen_vm_thread_state *)tthread->state;

	    if (xtstate->pgd == cr3) 
		break;
	    else {
		vdebug(8,LA_TARGET,LF_XV,
		       "thread %"PRIiTID" with pgd 0x%"PRIx64" did not match!\n",
		       tthread->tid,xtstate->pgd);
		tthread = NULL;
		xtstate = NULL;
	    }
	}

	if (!tthread) {
	    verror("could not find task match for cr3 0x%"PRIx64
		   " after loading all tasks!\n",cr3);
	    errno = ESRCH;
	    return NULL;
	}
    }
    else {
	/* Reload its value. */
	if (!tthread->valid 
	    && !(tthread = __xen_vm_load_thread_from_value(target,
							   xtstate->task_struct))) {
	    verror("could not load cached thread %"PRIiTID" from value!",
		   tthread->tid);
	    return NULL;
	}
    }

    vdebug(5,LA_TARGET,LF_XV,
	   "ip 0x%"PRIxADDR"; cr3/pgd = 0x%"PRIx64" --> thread %"PRIiTID"\n",
	   ipval,cr3,tthread->tid);

    return tthread;
}

#ifdef __x86_64__
/*
 * NB: these functions do *NOT* zero out the destination's contents;
 * they just copy what they can into the destination.
 */
static int __xen_vm_hvm_cpu_to_vcpu_context(HVM_SAVE_TYPE(CPU) *hvm,
					    vcpu_guest_context_t *svm) {
    assert(sizeof(svm->fpu_ctxt.x) == sizeof(hvm->fpu_regs));

    memcpy(svm->fpu_ctxt.x,hvm->fpu_regs,sizeof(svm->fpu_ctxt.x));

    svm->user_regs.rax = hvm->rax;
    svm->user_regs.rbx = hvm->rbx;
    svm->user_regs.rcx = hvm->rcx;
    svm->user_regs.rdx = hvm->rdx;
    svm->user_regs.rbp = hvm->rbp;
    svm->user_regs.rsi = hvm->rsi;
    svm->user_regs.rdi = hvm->rdi;
    svm->user_regs.rsp = hvm->rsp;
    svm->user_regs.r8  = hvm->r8;
    svm->user_regs.r9  = hvm->r9;
    svm->user_regs.r10 = hvm->r10;
    svm->user_regs.r11 = hvm->r11;
    svm->user_regs.r12 = hvm->r12;
    svm->user_regs.r13 = hvm->r13;
    svm->user_regs.r14 = hvm->r14;
    svm->user_regs.r15 = hvm->r15;

    svm->user_regs.rip = hvm->rip;
    svm->user_regs.rflags = hvm->rflags;

    svm->user_regs.error_code = hvm->error_code;

    /* XXX: cs, ds, es, fs, gs */

    if (hvm->gs_base)
	svm->gs_base_kernel = hvm->gs_base;
    else
	svm->gs_base_kernel = hvm->shadow_gs;

    /* XXX: ldt/gdt stuff */

    /* XXX: kernel_ss, kernel_sp */

    svm->ctrlreg[0] = hvm->cr0;
    svm->ctrlreg[2] = hvm->cr2;
    svm->ctrlreg[3] = hvm->cr3;
    svm->ctrlreg[4] = hvm->cr4;

    svm->debugreg[0] = hvm->dr0;
    svm->debugreg[1] = hvm->dr1;
    svm->debugreg[2] = hvm->dr2;
    svm->debugreg[3] = hvm->dr3;
    svm->debugreg[6] = hvm->dr6;
    svm->debugreg[7] = hvm->dr7;

    /* XXX: fs_base, gs_base_kernel, gs_base_user */

    return 0;
}

static int __xen_vm_vcpu_to_hvm_cpu_context(vcpu_guest_context_t *svm,
					    HVM_SAVE_TYPE(CPU) *hvm) {
    assert(sizeof(svm->fpu_ctxt.x) == sizeof(hvm->fpu_regs));

    memcpy(hvm->fpu_regs,svm->fpu_ctxt.x,sizeof(hvm->fpu_regs));

    if (hvm->rax != svm->user_regs.rax) {
	vdebug(9,LA_TARGET,LF_XV,"setting rax = 0x%"PRIx64" (old 0x%"PRIx64")\n",
               svm->user_regs.rax,hvm->rax);
	hvm->rax = svm->user_regs.rax;
    }
    if (hvm->rbx != svm->user_regs.rbx) {
        vdebug(9,LA_TARGET,LF_XV,"setting rbx = 0x%"PRIx64" (old 0x%"PRIx64")\n",
               svm->user_regs.rbx,hvm->rbx);
        hvm->rbx = svm->user_regs.rbx;
    }
    if (hvm->rcx != svm->user_regs.rcx) {
        vdebug(9,LA_TARGET,LF_XV,"setting rcx = 0x%"PRIx64" (old 0x%"PRIx64")\n",
               svm->user_regs.rcx,hvm->rcx);
        hvm->rcx = svm->user_regs.rcx;
    }
    if (hvm->rdx != svm->user_regs.rdx) {
        vdebug(9,LA_TARGET,LF_XV,"setting rdx = 0x%"PRIx64" (old 0x%"PRIx64")\n",
               svm->user_regs.rdx,hvm->rdx);
        hvm->rdx = svm->user_regs.rdx;
    }
    if (hvm->rbp != svm->user_regs.rbp) {
        vdebug(9,LA_TARGET,LF_XV,"setting rbp = 0x%"PRIx64" (old 0x%"PRIx64")\n",
               svm->user_regs.rbp,hvm->rbp);
        hvm->rbp = svm->user_regs.rbp;
    }
    if (hvm->rsi != svm->user_regs.rsi) {
        vdebug(9,LA_TARGET,LF_XV,"setting rsi = 0x%"PRIx64" (old 0x%"PRIx64")\n",
               svm->user_regs.rsi,hvm->rsi);
        hvm->rsi = svm->user_regs.rsi;
    }
    if (hvm->rdi != svm->user_regs.rdi) {
        vdebug(9,LA_TARGET,LF_XV,"setting rdi = 0x%"PRIx64" (old 0x%"PRIx64")\n",
               svm->user_regs.rdi,hvm->rdi);
        hvm->rdi = svm->user_regs.rdi;
    }
    if (hvm->rsp != svm->user_regs.rsp) {
        vdebug(9,LA_TARGET,LF_XV,"setting rsp = 0x%"PRIx64" (old 0x%"PRIx64")\n",
               svm->user_regs.rsp,hvm->rsp);
        hvm->rsp = svm->user_regs.rsp;
    }
    if (hvm->r8 != svm->user_regs.r8) {
        vdebug(9,LA_TARGET,LF_XV,"setting r8 = 0x%"PRIx64" (old 0x%"PRIx64")\n",
               svm->user_regs.r8,hvm->r8);
        hvm->r8 = svm->user_regs.r8;
    }
    if (hvm->r9 != svm->user_regs.r9) {
        vdebug(9,LA_TARGET,LF_XV,"setting r9 = 0x%"PRIx64" (old 0x%"PRIx64")\n",
               svm->user_regs.r9,hvm->r9);
        hvm->r9 = svm->user_regs.r9;
    }
    if (hvm->r10 != svm->user_regs.r10) {
        vdebug(9,LA_TARGET,LF_XV,"setting r10 = 0x%"PRIx64" (old 0x%"PRIx64")\n",
               svm->user_regs.r10,hvm->r10);
        hvm->r10 = svm->user_regs.r10;
    }
    if (hvm->r11 != svm->user_regs.r11) {
        vdebug(9,LA_TARGET,LF_XV,"setting r11 = 0x%"PRIx64" (old 0x%"PRIx64")\n",
               svm->user_regs.r11,hvm->r11);
        hvm->r11 = svm->user_regs.r11;
    }
    if (hvm->r12 != svm->user_regs.r12) {
        vdebug(9,LA_TARGET,LF_XV,"setting r12 = 0x%"PRIx64" (old 0x%"PRIx64")\n",
               svm->user_regs.r12,hvm->r12);
        hvm->r12 = svm->user_regs.r12;
    }
    if (hvm->r13 != svm->user_regs.r13) {
        vdebug(9,LA_TARGET,LF_XV,"setting r13 = 0x%"PRIx64" (old 0x%"PRIx64")\n",
               svm->user_regs.r13,hvm->r13);
        hvm->r13 = svm->user_regs.r13;
    }
    if (hvm->r14 != svm->user_regs.r14) {
        vdebug(9,LA_TARGET,LF_XV,"setting r14 = 0x%"PRIx64" (old 0x%"PRIx64")\n",
               svm->user_regs.r14,hvm->r14);
        hvm->r14 = svm->user_regs.r14;
    }
    if (hvm->r15 != svm->user_regs.r15) {
        vdebug(9,LA_TARGET,LF_XV,"setting r15 = 0x%"PRIx64" (old 0x%"PRIx64")\n",
               svm->user_regs.r15,hvm->r15);
        hvm->r15 = svm->user_regs.r15;
    }

    if (hvm->rip != svm->user_regs.rip) {
        vdebug(9,LA_TARGET,LF_XV,"setting rip = 0x%"PRIx64" (old 0x%"PRIx64")\n",
               svm->user_regs.rip,hvm->rip);
        hvm->rip = svm->user_regs.rip;
    }
    if (hvm->rflags != svm->user_regs.rflags) {
        vdebug(9,LA_TARGET,LF_XV,"setting rflags = 0x%"PRIx64" (old 0x%"PRIx64")\n",
               svm->user_regs.rflags,hvm->rflags);
        hvm->rflags = svm->user_regs.rflags;
    }

    if (hvm->error_code != svm->user_regs.error_code) {
        vdebug(9,LA_TARGET,LF_XV,"setting cr0 = 0x%"PRIx64" (old 0x%"PRIx64")\n",
               svm->user_regs.error_code,hvm->error_code);
	hvm->error_code = svm->user_regs.error_code;
    }

    /* XXX: cs, ds, es, fs, gs */

    /* XXX: ldt/gdt stuff */

    /* XXX: kernel_ss, kernel_sp */

    if (hvm->cr0 != svm->ctrlreg[0]) {
        vdebug(9,LA_TARGET,LF_XV,"setting cr0 = 0x%"PRIx64" (old 0x%"PRIx64")\n",
               svm->ctrlreg[0],hvm->cr0);
        hvm->cr0 = svm->ctrlreg[0];
    }
    if (hvm->cr2 != svm->ctrlreg[2]) {
        vdebug(9,LA_TARGET,LF_XV,"setting cr2 = 0x%"PRIx64" (old 0x%"PRIx64")\n",
               svm->ctrlreg[2],hvm->cr2);
        hvm->cr2 = svm->ctrlreg[2];
    }
    if (hvm->cr3 != svm->ctrlreg[3]) {
        vdebug(9,LA_TARGET,LF_XV,"setting cr3 = 0x%"PRIx64" (old 0x%"PRIx64")\n",
               svm->ctrlreg[3],hvm->cr3);
        hvm->cr3 = svm->ctrlreg[3];
    }
    if (hvm->cr4 != svm->ctrlreg[4]) {
        vdebug(9,LA_TARGET,LF_XV,"setting cr4 = 0x%"PRIx64" (old 0x%"PRIx64")\n",
               svm->ctrlreg[4],hvm->cr4);
        hvm->cr4 = svm->ctrlreg[4];
    }

    if (hvm->dr0 != svm->debugreg[0]) {
        vdebug(9,LA_TARGET,LF_XV,"setting dr0 = 0x%"PRIx64" (old 0x%"PRIx64")\n",
               svm->debugreg[0],hvm->dr0);
        hvm->dr0 = svm->debugreg[0];
    }
    if (hvm->dr1 != svm->debugreg[1]) {
        vdebug(9,LA_TARGET,LF_XV,"setting dr1 = 0x%"PRIx64" (old 0x%"PRIx64")\n",
               svm->debugreg[1],hvm->dr1);
        hvm->dr1 = svm->debugreg[1];
    }
    if (hvm->dr2 != svm->debugreg[2]) {
        vdebug(9,LA_TARGET,LF_XV,"setting dr2 = 0x%"PRIx64" (old 0x%"PRIx64")\n",
               svm->debugreg[2],hvm->dr2);
        hvm->dr2 = svm->debugreg[2];
    }
    if (hvm->dr3 != svm->debugreg[3]) {
        vdebug(9,LA_TARGET,LF_XV,"setting dr3 = 0x%"PRIx64" (old 0x%"PRIx64")\n",
               svm->debugreg[3],hvm->dr3);
        hvm->dr3 = svm->debugreg[3];
    }
    if (hvm->dr6 != svm->debugreg[6]) {
        vdebug(9,LA_TARGET,LF_XV,"setting dr6 = 0x%"PRIx64" (old 0x%"PRIx64")\n",
               svm->debugreg[6],hvm->dr6);
        hvm->dr6 = svm->debugreg[6];
    }
    if (hvm->dr7 != svm->debugreg[7]) {
        vdebug(9,LA_TARGET,LF_XV,"setting dr7 = 0x%"PRIx64" (old 0x%"PRIx64")\n",
               svm->debugreg[7],hvm->dr7);
        hvm->dr7 = svm->debugreg[7];
    }

    /* XXX: fs_base, gs_base_kernel, gs_base_user */

    return 0;
}					    
#endif

/*
 * Simple wrapper around xc_vcpu_getcontext and the HVM stuff.
 *
 * NB: it appears that the only reason to use the HVM-specific stuff
 * (for CPU info) is to get correct segment register info, the VMCS/VMCB
 * stuff, LDT stuff; pretty much everything else is already in
 * vcpu_guest_context for the VCPU in question (see
 * xen/xen/arch/x86/hvm/hvm.c:hvm_save_cpu_ctxt()).
 *
 * If the domain is HVM, it populates a vcpu_guest_context as best as
 * possible from HVM info.  It keeps the HVM data around for a later
 * setcontext operation.
 *
 * XXX: notice that we only load the highest-number VCPU.  Initially we
 * focused on single-core VMs; that assumption is built into the code.
 * We can relax it sometime; but that's the reason for the code being
 * like it is.
 */
static int __xen_vm_cpu_getcontext(struct target *target,
				   vcpu_guest_context_t *context) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;
#ifdef __x86_64__
    uint32_t size = 0;
    uint32_t offset = 0;
    HVM_SAVE_TYPE(CPU) *cpu = NULL;
    struct hvm_save_descriptor *sdesc = NULL;

#endif

    if (!xstate->hvm) {
	if (xc_vcpu_getcontext(xc_handle,xstate->id,
			       xstate->dominfo.max_vcpu_id,context) < 0) {
	    verror("could not get vcpu context for %d\n",xstate->id);
	    return -1;
	}
    }
    else {
#ifdef __x86_64__
	if ((size = xc_domain_hvm_getcontext(xc_handle,xstate->id,0,0)) <= 0) {
	    verror("Could not get HVM context buf size!\n");
	    return -1;
	}

	/* Handle increasing size; this should not happen. */
	if (unlikely(!xstate->hvm_context_buf)) {
	    xstate->hvm_context_bufsiz = size;
	    xstate->hvm_context_buf = malloc(size);
	}
	else if (size >= xstate->hvm_context_bufsiz) {
	    free(xstate->hvm_context_buf);
	    xstate->hvm_context_bufsiz = size;
	    xstate->hvm_context_buf = malloc(size);
	}

	xstate->hvm_cpu = NULL;

	if (xc_domain_hvm_getcontext(xc_handle,xstate->id,xstate->hvm_context_buf,
				     xstate->hvm_context_bufsiz) < 0) {
	    verror("Could not load HVM context buf!\n");
	    return -1;
	}

	offset = 0;
	while (offset < size) {
	    sdesc = (struct hvm_save_descriptor *) \
		(xstate->hvm_context_buf + offset);

	    offset += sizeof(*sdesc);

	    if (sdesc->typecode == HVM_SAVE_CODE(CPU) 
		&& sdesc->instance == xstate->dominfo.max_vcpu_id) {
		xstate->hvm_cpu = (HVM_SAVE_TYPE(CPU) *) \
		    (xstate->hvm_context_buf + offset);
		break;
	    }

	    offset += sdesc->length;
	}

	if (!xstate->hvm_cpu) {
	    verror("Could not find HVM context for VCPU %d!\n",
		   xstate->dominfo.max_vcpu_id);
	    return -1;
	}

	if (__xen_vm_hvm_cpu_to_vcpu_context(xstate->hvm_cpu,context)) {
	    verror("Could not translate HVM vcpu info to software vcpu info!\n");
	    return -1;
	}
#else
	/* Impossible. */
	verror("HVM unsupported on 32-bit platform!\n");
	errno = EINVAL;
	return -1;
#endif
    }

    return 0;
}

static int __xen_vm_cpu_setcontext(struct target *target,
				   vcpu_guest_context_t *context) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;

    if (!xstate->hvm) {
	if (xc_vcpu_setcontext(xc_handle,xstate->id,
			       xstate->dominfo.max_vcpu_id,context) < 0) {
	    verror("could not set vcpu context for dom %d\n",xstate->id);
	    errno = EINVAL;
	    return -1;
	}
    }
    else {
#ifdef __x86_64__
	if (__xen_vm_vcpu_to_hvm_cpu_context(context,xstate->hvm_cpu)) {
	    verror("Could not translate software vcpu info to HVM vcpu info!\n");
	    return -1;
	}

	if (xc_domain_hvm_setcontext(xc_handle,xstate->id,
				     xstate->hvm_context_buf,
				     xstate->hvm_context_bufsiz)) {
	    verror("Could not store HVM context buf!\n");
	    return -1;
	}
#else
	/* Impossible. */
	verror("HVM unsupported on 32-bit platform!\n");
	errno = EINVAL;
	return -1;
#endif
    }

    return 0;
}

static struct target_thread *__xen_vm_load_current_thread(struct target *target,
							  int force,
							  int globalonly) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;
    tid_t tid = 0;
    struct value *threadinfov = NULL;
    int preempt_count;
    unum_t tiflags;
    struct value *taskv = NULL;
    num_t tgid;
    num_t task_flags = 0;
    struct target_thread *tthread = NULL;
    struct xen_vm_thread_state *tstate = NULL;;
    struct xen_vm_thread_state *gtstate;
    struct value *v = NULL;
    REGVAL ipval;
    ADDR mm_addr = 0;
    uint64_t pgd = 0;
    REGVAL kernel_esp = 0;
    char *comm = NULL;

    /*
     * If the global thread has been loaded, and that's all the caller
     * wants, and they don't want to force a reload, give them that.
     */
    if (globalonly && !force
	&& target->global_thread && target->global_thread->valid)
	return target->global_thread;
    /*
     * Otherwise, if the current thread is valid, and we're not forcing
     * a reload, give them the current thread.
     */
    else if (!globalonly && !force
	     && target->current_thread && target->current_thread->valid)
	return target->current_thread;

    /* Use the default thread, always, if we're single threaded. */
    /*
    if (target_is_singlethread(target)) {
	tthread = target->global_thread;
	tstate = (struct xen_vm_thread_state *)tthread->state;
    }
    */

    if (target_status(target) != TSTATUS_PAUSED) {
	verror("target not paused; cannot load current task!\n");
	errno = EBUSY;
	return 0;
    }

    /*
     * The first thing to do is load the machine state into the global
     * thread, and set it as valid -- EVEN THOUGH we have not loaded
     * thread_info for it!  We must do this so that a whole bunch of
     * register reads can work via the API.
     */
    if (xen_vm_load_dominfo(target))
	goto errout;

    gtstate = (struct xen_vm_thread_state *)target->global_thread->state;

    /*
     * Only need to call xc if we haven't loaded this thread.
     */
    if (!target->global_thread->valid) {
	if (__xen_vm_cpu_getcontext(target,&gtstate->context) < 0) {
	    verror("could not get vcpu context for %d\n",xstate->id);
	    goto errout;
	}
	target->global_thread->valid = 1;
	target_thread_set_status(target->global_thread,THREAD_STATUS_RUNNING);
    }

    /*
     * Load EIP for later user-mode check.
     */
    errno = 0;
    ipval = xen_vm_read_reg(target,TID_GLOBAL,target->ipregno);
    if (errno) {
	vwarn("could not read EIP for user-mode check; continuing anyway.\n");
	errno = 0;
    }

    /*
     * If only loading the global thread, stop here.
     */
    if (globalonly) 
	return target->global_thread;

    /*
     * We used to not load the current thread in this case, but now we
     * do.  This is sort of misleading, because the thread is not
     * exactly in kernel context.  BUT, the important thing to realize
     * is that this target does not only provide service for in-kernel
     * operations.  The difference between this target and the
     * xen-process target is that the xen-process target has *extra*
     * functionality for inspecting the guts of a process, using its
     * symbols; this target can manipulate a process's CPU state, and it
     * can write virtual memory that is paged in; but that's it.
     *
     * So -- this target has to realize that its CPU state currently
     * corresponds to user state.  That means tricks like using the
     * current esp to find the current thread, and the task, do not
     * work.
     *
     * I'm not 100% happy about this; you have to check which context a
     * thread is in before you access its stack, etc.  But it's good
     * enough for now.
     *
     * Once we have loaded the global thread above, in this case, we
     * call a different function.  We actually try to infer which task
     * is running by checking cr3; we compare it to our existing, cached
     * tasks, and try to load the cached thread that matches.  If there
     * is no match, we have no choice but to load all the threads again
     * so we find the match.
     *
     * Anyway, we do that in another function.
     */
    if (ipval < xstate->kernel_start_addr) {
	/*
	vdebug(9,LA_TARGET,LF_XV,
	       "at user-mode EIP 0x%"PRIxADDR"; not loading current thread;"
	       " returning global thread.\n",
	       ipval);
	return __xen_vm_load_current_thread_from_userspace(target,force);
	*/

	kernel_esp = gtstate->context.kernel_sp;
	vdebug(9,LA_TARGET,LF_XV,
	       "at user-mode EIP 0x%"PRIxADDR"; trying to load current kernel"
	       " thread with kernel_sp 0x%"PRIxADDR"\n",
	       ipval,kernel_esp);
    }

    /* We need to load in the current task_struct, AND if it's already
     * in target->threads, CHECK if it really matches one of our cached
     * threads.  If not, and there is an old thread in the cache, nuke
     * that one and build a new one -- TIDs can of course be reused in
     * Linux.
     */

    /*
     * But first, we need to see if we're handling a hard or soft IRQ
     * (and are ksoftirqd (?) -- but how do we check *which* kind of
     * soft IRQ we are??).
     *
     * If we are, we just set out TID to TID_GLOBAL, and load state
     * from Xen.
     *
     * If we are not, then, we can be safe to check the kernel's
     * task_struct to see which thread we are.  But wait, since the
     * kernel runs all softirqs in interrupt context, the current task
     * is really pretty irrelevant (unless it's ksoftirqd; we could
     * check and make a note of that...).
     *
     * So, we always set TID to TID_GLOBAL, and load state from Xen.
     */

    threadinfov = linux_load_current_thread_as_type(target,
						    xstate->thread_info_type,
						    kernel_esp);
    if (!threadinfov) {
	verror("could not load current thread info!  cannot get current TID!\n");
	/* errno should be set for us. */
	goto errout;
    }

    v = target_load_value_member(target,threadinfov,"preempt_count",NULL,
				 LOAD_FLAG_NONE);
    if (!v) {
	verror("could not load thread_info->preempt_count (to check IRQ status)!");
	/* errno should be set for us. */
	goto errout;
    }
    preempt_count = v_num(v);
    value_free(v);
    v = NULL;

    if (SOFTIRQ_COUNT(preempt_count) || HARDIRQ_COUNT(preempt_count)) {
	vdebug(3,LA_TARGET,LF_XV,"in interrupt context (hardirq=%d,softirq=%d)\n",
	       HARDIRQ_COUNT(preempt_count),SOFTIRQ_COUNT(preempt_count));
	tid = TID_GLOBAL;
	tgid = TID_GLOBAL;
	taskv = NULL;

	vdebug(5,LA_TARGET,LF_XV,
	       "loading global thread cause in hard/soft irq (0x%"PRIx64")\n",
	       preempt_count);
    }
    else {
	/* Now, load the current task_struct. */
	taskv = target_load_value_member(target,threadinfov,"task",NULL,
					 LOAD_FLAG_AUTO_DEREF);

	if (!taskv) {
	    verror("could not load current task!  cannot get current TID!\n");
	    /* errno should be set for us. */
	    goto errout;
	}

	v = target_load_value_member(target,taskv,"pid",NULL,LOAD_FLAG_NONE);
	if (!v) {
	    verror("could not load pid in current task; BUG?\n");
	    /* errno should be set for us. */
	    goto errout;
	}
	tid = v_i32(v);
	value_free(v);
	v = NULL;

	v = target_load_value_member(target,taskv,"comm",NULL,LOAD_FLAG_NONE);
	if (!v) {
	    verror("could not load comm in current task; BUG?\n");
	    /* errno should be set for us. */
	    goto errout;
	}
	comm = strndup(v->buf,v->bufsiz);
	value_free(v);
	v = NULL;

	vdebug(5,LA_TARGET,LF_XV,"loading thread %"PRIiTID"\n",tid);

	v = target_load_value_member(target,taskv,"tgid",NULL,LOAD_FLAG_NONE);
	if (!v) {
	    verror("could not load tgid in current task; BUG?\n");
	    /* errno should be set for us. */
	    goto errout;
	}
	tgid = v_num(v);
	value_free(v);
	v = NULL;

	v = target_load_value_member(target,taskv,"flags",NULL,LOAD_FLAG_NONE);
	if (!v) {
	    verror("could not load flags in task %"PRIiTID" current task; BUG?\n",
		   tid);
	    /* errno should be set for us. */
	    goto errout;
	}
	task_flags = v_num(v);
	value_free(v);
	v = NULL;

	v = target_load_value_member(target,taskv,"mm",NULL,LOAD_FLAG_NONE);
	if (!v) {
	    verror("could not see if thread %"PRIiTID" was kernel or user\n",tid);
	    goto errout;
	}
	mm_addr = v_addr(v);
	value_free(v);
	v = NULL;

	if (mm_addr) {
	    v = target_load_value_member(target,taskv,"mm.pgd",NULL,
					 LOAD_FLAG_AUTO_DEREF);
	    if (!v) {
		verror("could not load thread %"PRIiTID" pgd (for cr3 tracking)\n",
		       tid);
		goto errout;
	    }
	    pgd = v_u64(v);
	    value_free(v);
	    v = NULL;
	}
    }

    v = target_load_value_member(target,threadinfov,"flags",NULL,
				 LOAD_FLAG_NONE);
    if (!v) {
	verror("could not load thread_info->flags in current thread; BUG?\n");
	/* errno should be set for us. */
	goto errout;
    }
    tiflags = v_unum(v);
    value_free(v);
    v = NULL;

    /*
     * Now, update the current thread with the value info we just
     * loaded.  If it's not the global thread (irq context), we check
     * our cache, and create/delete as needed.
     */

    /* Check the cache: */
    if ((tthread = (struct target_thread *) \
	     g_hash_table_lookup(target->threads,(gpointer)tid))) {
	tstate = (struct xen_vm_thread_state *)tthread->state;
	/*
	 * Check if this is a cached entry for an old task.  Except
	 * don't check if the thread is TID_GLOBAL, since we must
	 * always leave that meta-thread in the cache; it doesn't
	 * represent a real system thread.
	 */
	if (tid != TID_GLOBAL 
	    && (tstate->tgid != tgid 
		|| (taskv && tstate->task_struct_addr != value_addr(taskv)))) {
	    vdebug(5,LA_TARGET,LF_XV,
		   "deleting non-matching cached old thread %"PRIiTID
		   " (thread %p, tpc %p)\n",
		   tid,tthread,tthread->tpc);
	    target_add_state_change(target,tthread->tid,
				    TARGET_STATE_CHANGE_THREAD_EXITED,
				    0,0,0,0,NULL);
	    target_delete_thread(target,tthread,0);
	    tstate = NULL;
	    tthread = NULL;
	}
	else {
	    vdebug(5,LA_TARGET,LF_XV,
		   "found matching cached thread %"PRIiTID" (thread %p, tpc %p)\n",
		   tid,tthread,tthread->tpc);
	}
    }

    if (!tthread) {
	/* Build a new one. */
	tstate = (struct xen_vm_thread_state *)calloc(1,sizeof(*tstate));
	tthread = target_create_thread(target,tid,tstate);

	target_add_state_change(target,tid,TARGET_STATE_CHANGE_THREAD_CREATED,
				0,0,0,0,NULL);

	vdebug(5,LA_TARGET,LF_XV,
	       "built new thread %"PRIiTID" (thread %p, tpc %p)\n",
		   tid,tthread,tthread->tpc);
    }

    /*
     * Set the current thread (might be a real thread, or the global thread).
     */
    target->current_thread = tthread;
    target_thread_set_status(target->current_thread,THREAD_STATUS_RUNNING);

    if (taskv) { //!(SOFTIRQ_COUNT(preempt_count) || HARDIRQ_COUNT(preempt_count))) {
	if (tstate->task_struct) {
	    vwarn("stale task_struct for thread %"PRIiTID"!\n",tid);
	    value_free(tstate->task_struct);
	    tstate->task_struct = NULL;
	}
	tstate->task_struct_addr = value_addr(taskv);
	tstate->task_struct = taskv;
	tstate->tgid = tgid;
	tstate->task_flags = task_flags;
    }

    /*
     * Check for stale cached values.  These should not be here, but... !
     */
    if (tstate->thread_struct) {
	vwarn("stale thread_struct for thread %"PRIiTID"!\n",tid);
	value_free(tstate->thread_struct);
	tstate->thread_struct = NULL;
    }
    if (tstate->thread_info) {
	vwarn("stale thread_info for thread %"PRIiTID"!\n",tid);
	value_free(tstate->thread_info);
	tstate->thread_info = NULL;
    }

    tstate->thread_info = threadinfov;
    tstate->thread_info_flags = tiflags;
    tstate->thread_info_preempt_count = preempt_count;

    /*
     * We don't bother loading this, because it's our "current" thread
     * -- all the state in the thread_struct is directly accessible from
     * hardware.
     */
    tstate->thread_struct = NULL;
    tstate->ptregs_stack_addr = 0;
    tstate->mm_addr = mm_addr;
    tstate->pgd = pgd;

    /*
     * If the current thread is not the global thread, fill in a little
     * bit more info for the global thread.
     */
    if (tthread != target->global_thread) {
	/*
	 * Copy context from global thread to current thread -- from Xen info.
	 */
	memcpy(&tstate->context,&gtstate->context,sizeof(vcpu_guest_context_t));

	/*
	 * Don't copy in any of the other per-xen thread state; we want
	 * to force users to load and operate on real threads for any
	 * other information.  The global thread only has thread_info in
	 * interrupt context.
	 */
	gtstate->task_struct_addr = 0;
	gtstate->task_struct = NULL;
	gtstate->task_flags = 0;
	gtstate->thread_struct = NULL;
	gtstate->ptregs_stack_addr = 0;
	gtstate->mm_addr = 0;
	gtstate->pgd = 0;

	/* BUT, do copy in thread_info. */
	if (gtstate->thread_info) {
	    vwarn("stale thread_info for global thread %"PRIiTID"!\n",TID_GLOBAL);
	    value_free(gtstate->thread_info);
	    gtstate->thread_info = NULL;
	}
	gtstate->thread_info = value_clone(threadinfov);
	gtstate->thread_info_flags = tiflags;
	gtstate->thread_info_preempt_count = preempt_count;

	if (mm_addr) 
	    tthread->supported_overlay_types = TARGET_TYPE_XEN_PROCESS;
	else
	    tthread->supported_overlay_types = TARGET_TYPE_NONE;

	if (tthread->name)
	    free(tthread->name);
	tthread->name = comm;
	comm = NULL;
    }

    vdebug(4,LA_TARGET,LF_XV,
	   "debug registers (vcpu context): 0x%"PRIxADDR",0x%"PRIxADDR
	   ",0x%"PRIxADDR",0x%"PRIxADDR",0,0,0x%"PRIxADDR",0x%"PRIxADDR"\n",
	   tstate->context.debugreg[0],tstate->context.debugreg[1],
	   tstate->context.debugreg[2],tstate->context.debugreg[3],
	   tstate->context.debugreg[6],tstate->context.debugreg[7]);

    /* Mark its state as valid in our cache. */
    tthread->valid = 1;

    if (v)
	value_free(v);
    if (comm)
	free(comm);

    return tthread;

 errout:
    if (v)
	value_free(v);
    if (comm)
	free(comm);
    if (threadinfov)
	value_free(threadinfov);
    if (taskv)
	value_free(taskv);
    if (tstate) {
	tstate->thread_info = NULL;
	tstate->thread_struct = NULL;
	tstate->task_struct = NULL;
    }

    /* XXX: should we really set this here? */
    target->current_thread = target->global_thread;

    vwarn("error loading current thread; trying to use default thread\n");

    return target->global_thread;
}

static struct target_thread *xen_vm_load_current_thread(struct target *target,
							int force) {
    return __xen_vm_load_current_thread(target,force,0);
}

/**
 ** Target API implementation.
 **/

/*
 * If the target is not paused, the result of this function is
 * undefined.
 * 
 * Otherwise, first we get the CPL out of the lower two bits of the CS
 * register.  Then we grab the current task and its pid.
 */
tid_t xen_vm_gettid(struct target *target) {
    struct target_thread *tthread;

    if (target->current_thread && target->current_thread->valid)
	return target->current_thread->tid;

    tthread = xen_vm_load_current_thread(target,0);
    if (!tthread) {
	verror("could not load current thread to get TID!\n");
	return 0;
    }

    return tthread->tid;
}

void xen_vm_free_thread_state(struct target *target,void *state) {
    struct xen_vm_thread_state *xtstate = (struct xen_vm_thread_state *)state;

    if (xtstate->thread_struct) {
	value_free(xtstate->thread_struct);
	xtstate->thread_struct = NULL;
    }
    if (xtstate->thread_info) {
	value_free(xtstate->thread_info);
	xtstate->thread_info = NULL;
    }
    if (xtstate->task_struct) {
	value_free(xtstate->task_struct);
	xtstate->task_struct = NULL;
    }

    free(state);
}

static char *xen_vm_tostring(struct target *target,char *buf,int bufsiz) {
    struct xen_vm_spec *xspec = \
	(struct xen_vm_spec *)target->spec->backend_spec;

    if (!buf) {
	bufsiz = strlen("domain()") + strlen(xspec->domain) + 1;
	buf = malloc(bufsiz*sizeof(char));
    }
    snprintf(buf,bufsiz,"domain(%s)",xspec->domain);

    return buf;
}

static int xen_vm_init(struct target *target) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;
    struct xen_vm_thread_state *tstate;

    vdebug(5,LA_TARGET,LF_XV,"dom %d\n",xstate->id);

    /*
     * We really should read all the kernel CONFIG_* stuff, but for now,
     * this is a hack for handling kernel module loading!  It affects
     * module program layout and ELF relocation.  If your kernel doesn't
     * support it, this will screw up all that stuff.
     */
    g_hash_table_insert(target->config,strdup("CONFIG_KALLSYMS"),strdup("y"));

    if (target->spec->bpmode == THREAD_BPMODE_STRICT) {
	vwarn("auto-enabling SEMI_STRICT bpmode on Xen target.\n");
	target->spec->bpmode = THREAD_BPMODE_SEMI_STRICT;
    }

    /*
     * We can use the RF flag to temporarily disable the hw breakpoint
     * if we don't need to single step the breaked instruction (i.e.,
     * beacuse there are no post handlers nor actions).  This saves us
     * from disable the hw breakpoint in this situation.
     */
    target->nodisablehwbponss = 1;
    target->threadctl = 0;

    xstate->dominfo_valid = 0;

    /* Create the default thread. */
    tstate = (struct xen_vm_thread_state *)calloc(1,sizeof(*tstate));

    tstate->task_struct_addr = 0;

    tstate->task_struct = NULL;
    tstate->tgid = 0;
    tstate->task_flags = 0;
    /* Populate tstate->task_struct_addr later in postloadinit once we 
     * have debuginfo (and thus hopefully the address of the `init_task'
     * symbol.
     */
    tstate->thread_info = NULL;
    tstate->thread_info_flags = 0;
    tstate->thread_info_preempt_count = 0;
    tstate->thread_struct = NULL;
    tstate->ptregs_stack_addr = 0;

    target->global_thread = target_create_thread(target,TID_GLOBAL,tstate);
    /* Default thread is always running. */
    target_thread_set_status(target->global_thread,THREAD_STATUS_RUNNING);

    return 0;
}

static int xen_vm_attach_internal(struct target *target) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;
    struct xen_domctl domctl;
    struct addrspace *space;
    struct addrspace *tspace;
    struct target_thread *tthread;
    struct xen_vm_thread_state *xtstate;
    struct bsymbol *tbs;
    OFFSET tasks_offset,pid_offset,mm_offset,pgd_offset;
    int size;
    char *tmp;

    domctl.cmd = XEN_DOMCTL_setdebugging;
    domctl.domain = xstate->id;
    domctl.u.setdebugging.enable = true;

    vdebug(5,LA_TARGET,LF_XV,"dom %d\n",xstate->id);

    if (xc_handle == XC_IF_INVALID) {
#ifdef XENCTRL_HAS_XC_INTERFACE
	xc_handle = xc_interface_open(NULL, NULL, 0);
#else
	xc_handle = xc_interface_open();
#endif
	if (xc_handle == XC_IF_INVALID) {
	    verror("failed to open xc interface: %s\n",strerror(errno));
	    return -1;
	}

#ifdef XENCTRL_HAS_XC_INTERFACE
	xce_handle = xc_evtchn_open(NULL, 0);
#else
	xce_handle = xc_evtchn_open();
#endif
	if (xce_handle == XC_IF_INVALID) {
	    xc_interface_close(xc_handle);
	    verror("failed to open event channel: %s\n",strerror(errno));
	    return -1;
	}

	dbg_port = xc_evtchn_bind_virq(xce_handle,VIRQ_DEBUGGER);
	/* Try to cast dbg_port to something signed.  Old xc versions
	 * have a bug in that evtchn_port_t is declared as uint32_t, but
	 * the function prototypes that return them can theoretically
	 * return -1.  So, try to test for that...
	 */
	if ((int32_t)dbg_port < 0) {
	    verror("failed to bind debug virq port: %s",strerror(errno));
	    xc_evtchn_close(xce_handle);
	    xc_interface_close(xc_handle);
	}
    }

    if (xc_domctl(xc_handle,&domctl)) {
	verror("could not enable debugging of dom %d!\n",xstate->id);
        return -1;
    }

    /* NOT thread-safe! */
    ++xc_refcnt;

    /* Null out current state so we reload and see that it's paused! */
    xstate->dominfo_valid = 0;
    if (xen_vm_load_dominfo(target)) {
	verror("could not load dominfo for dom %d\n",xstate->id);
	return -1;
    }

    if (xen_vm_pause(target,0)) {
	verror("could not pause target before attaching; letting user handle!\n");
    }
    target_set_status(target,TSTATUS_PAUSED);

    /*
     * Make sure xenaccess/libvmi is setup to read from userspace memory.
     */
    errno = 0;
    tasks_offset = symbol_offsetof(xstate->task_struct_type,"tasks",NULL);
    if (errno) 
	vwarn("could not resolve offset of task_struct.tasks!\n");
    errno = 0;
    pid_offset = symbol_offsetof(xstate->task_struct_type,"pid",NULL);
    if (errno) 
	vwarn("could not resolve offset of task_struct.pid!\n");
    errno = 0;
    mm_offset = symbol_offsetof(xstate->task_struct_type,"mm",NULL);
    if (errno) 
	vwarn("could not resolve offset of task_struct.mm!\n");
    errno = 0;
    pgd_offset = symbol_offsetof(xstate->mm_struct_type,"pgd",NULL);
    if (errno) 
	vwarn("could not resolve offset of mm_struct.pgd!\n");

#ifdef ENABLE_XENACCESS
    xstate->xa_instance.init_task = xstate->init_task_addr;
    xstate->xa_instance.page_offset = 0;
    xstate->xa_instance.os.linux_instance.tasks_offset = tasks_offset;
    xstate->xa_instance.os.linux_instance.pid_offset = pid_offset;
    xstate->xa_instance.os.linux_instance.mm_offset = mm_offset;
    xstate->xa_instance.os.linux_instance.pgd_offset = pgd_offset;

    tbs = target_lookup_sym(target,"swapper_pg_dir",NULL,NULL,
			    SYMBOL_TYPE_FLAG_NONE);
    if (!tbs) 
	vwarn("could not find 'swapper_pg_dir'; userspace vm access will fail!\n");
    else {
	xstate->xa_instance.kpgd = 
	    target_addressof_symbol(target,TID_GLOBAL,tbs,LOAD_FLAG_NONE,NULL);
	bsymbol_release(tbs);
    }
#endif
#ifdef ENABLE_LIBVMI
    /*
     * Offsets are:
     *   linux_tasks: offset of "tasks" in task_struct
     *   linux_mm:    offset of "mm" in task_struct
     *   linux_pid:   offset of "pid" in task_struct
     *   linux_pgd:   offset of "pgd" in mm_struct
     */
#define LIBVMI_CONFIG_TEMPLATE "{ostype=\"Linux\";" \
	" sysmap=\"%s\"; linux_tasks=0x%"PRIxOFFSET"; linux_mm=0x%"PRIxOFFSET";" \
	" linux_pid=0x%"PRIxOFFSET"; linux_pgd=0x%"PRIxOFFSET";" \
	" }"
#define LIBVMI_CONFIG_TEMPLATE_HVM "{ ostype=\"Linux\"; sysmap=\"%s\"; }"

    if (0 && xstate->hvm) {
	size = sizeof(LIBVMI_CONFIG_TEMPLATE_HVM) 
	    + strlen(xstate->kernel_sysmap_filename) + 1;
	tmp = malloc(size);
	snprintf(tmp,size,LIBVMI_CONFIG_TEMPLATE_HVM,
		 xstate->kernel_sysmap_filename);
    }
    else {
	size = sizeof(LIBVMI_CONFIG_TEMPLATE) 
	    + strlen(xstate->kernel_sysmap_filename) + 4 * 16 + 1;
	tmp = malloc(size);
	snprintf(tmp,size,LIBVMI_CONFIG_TEMPLATE,
		 xstate->kernel_sysmap_filename,
		 tasks_offset,mm_offset,pid_offset,pgd_offset);
    }

    if (vmi_init_complete(&xstate->vmi_instance, tmp) == VMI_FAILURE) {
	verror("failed to complete init of vmi instance for dom %d (config was '%s')\n",
	       xstate->id,tmp);
	vmi_destroy(xstate->vmi_instance);
	free(tmp);
	tmp = NULL;
	return -1;
    }

    /* XXX this is in the vmi_instance, but they don't expose it! */
    xstate->vmi_page_size = XC_PAGE_SIZE;
#endif

    /*
     * Make sure to pull in our modules!
     */
    list_for_each_entry_safe(space,tspace,&target->spaces,space) {
	xen_vm_updateregions(target,space);
    }

    if (target->evloop && xstate->evloop_fd < 0) {
	xen_vm_attach_evloop(target,target->evloop);
    }

    /*
     * Null out hardware breakpoints, so that we don't try to infer that
     * one was set, only to error because it's a software BP, not a
     * hardware BP (even if the ip matches).  This can happen if you do
     * one run with hw bps, then breakpoint the same ip with a sw bp.
     * Good practice anyway!
     */

    if (!(tthread = xen_vm_load_cached_thread(target,TID_GLOBAL))) {
	if (!errno) 
	    errno = EINVAL;
	verror("could not load cached thread %"PRIiTID"\n",TID_GLOBAL);
	return -1;
    }
    xtstate = (struct xen_vm_thread_state *)tthread->state;

    xtstate->dr[0] = 0;
    xtstate->dr[1] = 0;
    xtstate->dr[2] = 0;
    xtstate->dr[3] = 0;
    /* Clear the status bits */
    xtstate->dr[6] = 0;
    /* Clear the control bit. */
    xtstate->dr[7] = 0;

    /* Now save these values for later write in flush_context! */
    xtstate->context.debugreg[0] = 0;
    xtstate->context.debugreg[1] = 0;
    xtstate->context.debugreg[2] = 0;
    xtstate->context.debugreg[3] = 0;
    xtstate->context.debugreg[6] = 0;
    xtstate->context.debugreg[7] = 0;

    tthread->dirty = 1;

    if (target->current_thread) {
	tthread = target->current_thread;
	xtstate = (struct xen_vm_thread_state *)tthread->state;

	xtstate->dr[0] = 0;
	xtstate->dr[1] = 0;
	xtstate->dr[2] = 0;
	xtstate->dr[3] = 0;
	/* Clear the status bits */
	xtstate->dr[6] = 0;
	/* Clear the control bit. */
	xtstate->dr[7] = 0;

	/* Now save these values for later write in flush_context! */
	xtstate->context.debugreg[0] = 0;
	xtstate->context.debugreg[1] = 0;
	xtstate->context.debugreg[2] = 0;
	xtstate->context.debugreg[3] = 0;
	xtstate->context.debugreg[6] = 0;
	xtstate->context.debugreg[7] = 0;

	target->current_thread->dirty = 1;
    }

    return 0;
}

static int xen_vm_detach(struct target *target) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)(target->state);
    struct xen_domctl domctl;

    domctl.cmd = XEN_DOMCTL_setdebugging;
    domctl.domain = xstate->id;
    domctl.u.setdebugging.enable = false;

    vdebug(5,LA_TARGET,LF_XV,"dom %d\n",xstate->id);

    if (!target->opened)
	return 0;

    if (xen_vm_status(target) == TSTATUS_PAUSED
	&& (g_hash_table_size(target->threads) || target->global_thread)) {
	/* Flush back registers if they're dirty, but if we don't have
	 * any threads (i.e. because we're closing/detaching), don't
	 * flush all, which would load the global thread!
	 */
	xen_vm_flush_all_threads(target);
    }

    if (target->evloop && xstate->evloop_fd > -1)
	xen_vm_detach_evloop(target);

    if (xstate->live_shinfo)
	munmap(xstate->live_shinfo,PAGE_SIZE);

    if (xc_domctl(xc_handle,&domctl)) {
	verror("could not disable debugging of dom %d!\n",xstate->id);
        return -1;
    }

    if (xen_vm_status(target) == TSTATUS_PAUSED) {
	__xen_vm_resume(target,1);
    }

    --xc_refcnt;

    if (!xc_refcnt) {
	/* Close all the xc stuff; we're the last one. */
	if (xc_evtchn_unbind(xce_handle,(evtchn_port_t)dbg_port)) {
	    verror("failed to unbind debug virq port\n");
	}
	dbg_port = -1;

	if (xc_evtchn_close(xce_handle)) {
	    verror("failed to close event channel\n");
	}
	xce_handle = XC_IF_INVALID;
    
	if (xc_interface_close(xc_handle)) {
	    verror("failed to close xc interface\n");
	}
	xc_handle = XC_IF_INVALID;

	vdebug(4,LA_TARGET,LF_XV,"xc detach dom %d succeeded.\n",xstate->id);
    }

    vdebug(3,LA_TARGET,LF_XV,"detach dom %d succeeded.\n",xstate->id);

    return 0;
}

static int xen_vm_fini(struct target *target) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)(target->state);
    REFCNT trefcnt;

    vdebug(5,LA_TARGET,LF_XV,"dom %d\n",xstate->id);

    if (target->opened) 
	xen_vm_detach(target);

    if (xstate->init_task)
	bsymbol_release(xstate->init_task);
    if (xstate->task_struct_type)
	symbol_release(xstate->task_struct_type);
    if (xstate->thread_struct_type)
	symbol_release(xstate->thread_struct_type);
    if (xstate->task_struct_type_ptr)
	symbol_release(xstate->task_struct_type_ptr);
    if (xstate->mm_struct_type)
	symbol_release(xstate->mm_struct_type);
    if (xstate->pt_regs_type)
	symbol_release(xstate->pt_regs_type);
    if (xstate->thread_info_type)
	RPUT(xstate->thread_info_type,symbol,target,trefcnt);
    if (xstate->modules)
	bsymbol_release(xstate->modules);
    if (xstate->module_type)
	bsymbol_release(xstate->module_type);

    if (xstate->vmpath)
	free(xstate->vmpath);
    if (xstate->kernel_filename)
	free(xstate->kernel_filename);
    if (xstate->kernel_elf_filename)
	free(xstate->kernel_elf_filename);
    if (xstate->kernel_sysmap_filename)
	free(xstate->kernel_sysmap_filename);
    if (xstate->kernel_module_dir)
	free(xstate->kernel_module_dir);
    if (xstate->name)
	free(xstate->name);
    if (xstate)
	free(xstate);

    return 0;
}

static int xen_vm_kill(struct target *target,int sig) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)(target->state);

    vdebug(5,LA_TARGET,LF_XV,"dom %d\n",xstate->id);

    /* XXX: fill in! */
    return 0;
}

/*
 * For now, just one big address space.
 */
static int xen_vm_loadspaces(struct target *target) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)(target->state);
    struct addrspace *space = addrspace_create(target,"kernel",xstate->id);

    space->target = target;
    RHOLD(space,target);

    list_add_tail(&space->space,&target->spaces);

    return 0;
}

/*
 * For now, just find our kernel binary path from xen store, as well as
 * the max amount of mem, and create a single region (with a single
 * range that is R/W/X) covering either all 32 or 64 bits.
 *
 * The immediate reason to do this is that figuring out which memory is
 * currently mapped to kernel or user address space is going to be slow
 * because it involves lots of list traverses.  Plus, even if we had an
 * efficient data structure for searching address ranges, we would have
 * to reload the ranges/regions *every* time the domain runs.  We do not
 * want to do this!
 *
 * So, XXX: come back to it later.
 */
static int xen_vm_loadregions(struct target *target,struct addrspace *space) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)(target->state);
    struct memregion *region;
    struct memrange *range;

    region = memregion_create(space,REGION_TYPE_MAIN,
			      xstate->kernel_elf_filename);
    range = memrange_create(region,0,ADDRMAX,0,
			    PROT_READ | PROT_WRITE | PROT_EXEC);

    return 0;
}

/*
 * For now, just try to find the debuginfo for our kernel, unless the
 * user told us about it in xstate.
 *
 * We need to look for gnu_debuglink first, and then look in
 * /usr*lib/debug for a match.  Actually, we prefer the buildid because
 * for fedora kernel modules, we don't necessarily know the path to the
 * module in /lib/modules/VERSION/.../module.ko in the fs, so we can't
 * duplicate ... in the /usr/lib/debug search... so build id is the way
 * to go.
 *
 * But for just the kernel itself, this is easier.  If we have buildid
 * or debuglink, we use /usr*lib/debug.  Else, we look in /boot for a
 * file that replaces the vmlinuz part with vmlinux.
 */
static int xen_vm_loaddebugfiles(struct target *target,
				 struct addrspace *space,
				 struct memregion *region) {
    int retval = -1;
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;
    struct debugfile *debugfile;

    vdebug(5,LA_TARGET,LF_XV,"dom %d\n",xstate->id);

    /*
     * Open up the actual ELF binary and look for three sections to inform
     * our search.  First, if there is a nonzero .debug_info section,
     * load that.  Second, if there is a .note.gnu.build-id section,
     * read the build id and decompose it into a two-byte dir/file.debug
     * string that we look for in our search path (i.e., we look for
     * $PATH/.build-id/b1/b2..bX.debug).  Otherwise, if there is a
     * .gnu_debuglink section, we read that section and try to find a
     * matching debug file. 
     */
    if (!region->name || strlen(region->name) == 0)
	return -1;

    debugfile = debugfile_from_file(region->name,
				    target->spec->debugfile_root_prefix,
				    target->spec->debugfile_load_opts_list);
    if (!debugfile)
	goto out;

    if (target_associate_debugfile(target,region,debugfile)) {
	debugfile_release(debugfile);
	goto out;
    }
    else {
	debugfile_release(debugfile);
    }

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
     * Propagate some binfile info...
     */
    region->base_phys_addr = region->binfile->base_phys_addr;
    region->base_virt_addr = region->binfile->base_virt_addr;

    retval = 0;

 out:
    return retval;
}

static int xen_vm_postloadinit(struct target *target) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;
    struct bsymbol *thread_info_type;
    struct bsymbol *mm_struct_type;
    struct lsymbol *tmpls;
    struct bsymbol *tmpbs;

    /*
     * Assume if we did this, we've done it all.
     */
    if (xstate->init_task) 
	return 0;

    /*
     * Try to load some debuginfo stuff so we can provide better
     * functionality!  We have to do this in target_attach because only
     * at that point can we know that the debuginfo sources have been
     * loaded.
     *
     */

    /*
     * Find the kernel start address.
     */
    
    /* Try .text first (and fake the delimiter!!!) */
    if (xstate->kernel_start_addr == 0) {
	tmpbs = target_lookup_sym(target,".text","|",NULL,
				  SYMBOL_TYPE_FLAG_FUNCTION);
	if (tmpbs) {
	    if (symbol_get_location_addr(tmpbs->lsymbol->symbol,
					 &xstate->kernel_start_addr)) {
		vwarnopt(1,LA_TARGET,LF_XV,
			 "could not resolve addr of .text;"
			 " trying startup_(32|64)!\n");
	    }
	    bsymbol_release(tmpbs);
	    tmpbs = NULL;
	}
	else {
	    vwarnopt(1,LA_TARGET,LF_XV,
		     "could not find symbol .text; trying startup_(32|64)!\n");
	}
    }

    /* If we didn't find .text, try startup_(32|64). */
    if (xstate->kernel_start_addr == 0) {
	if (target->wordsize == 4) {
	    tmpbs = target_lookup_sym(target,"startup_32",NULL,NULL,
				      SYMBOL_TYPE_FLAG_FUNCTION);
	    if (tmpbs) {
		if (symbol_get_location_addr(tmpbs->lsymbol->symbol,
					     &xstate->kernel_start_addr)) {
		    vwarnopt(1,LA_TARGET,LF_XV,
			     "could not resolve addr of startup_32!\n");
		}
		bsymbol_release(tmpbs);
		tmpbs = NULL;
	    }
	    else {
		vwarnopt(1,LA_TARGET,LF_XV,
			 "could not find symbol startup_32!\n");
	    }
	}
	else {
	    tmpbs = target_lookup_sym(target,"startup_64",NULL,NULL,
				      SYMBOL_TYPE_FLAG_FUNCTION);
	    if (tmpbs) {
		if (symbol_get_location_addr(tmpbs->lsymbol->symbol,
					     &xstate->kernel_start_addr)) {
		    vwarnopt(1,LA_TARGET,LF_XV,
			     "could not resolve addr of startup_64!\n");
		}
		bsymbol_release(tmpbs);
		tmpbs = NULL;
	    }
	    else {
		vwarnopt(1,LA_TARGET,LF_XV,
			 "could not find symbol startup_64!\n");
	    }
	}
    }

    /* If we still didn't find it... */
    if (xstate->kernel_start_addr == 0) {
	vwarn("could not find addr of .text nor startup_(32|64);"
	      " using defaults!\n");

	if (target->wordsize == 4) 
	    xstate->kernel_start_addr = 0xC0000000;
#if __WORDSIZE == 64
	else if (target->wordsize == 8)
	    xstate->kernel_start_addr = 0xFFFFFFFF81000000ULL;
#endif
    }

    vdebug(3,LA_TARGET,LF_XV,"kernel start addr is 0x%"PRIxREGVAL"\n",
	   xstate->kernel_start_addr);

    xstate->init_task = target_lookup_sym(target,"init_task",NULL,NULL,
					  SYMBOL_TYPE_FLAG_VAR);
    if (!xstate->init_task) {
	vwarn("could not lookup init_task in debuginfo; no multithread support!\n");
	/* This is not an error, so we don't return error -- it
	 * would upset target_open.
	 */
	return 0;
    }

    if (symbol_get_location_addr(xstate->init_task->lsymbol->symbol,
				 &xstate->init_task_addr)) {
	vwarn("could not resolve addr of init_task!\n");
    }

    /*
     * For x86_64, current_thread_ptr depends on this value -- so just
     * load it once and keep it around forever.
     * target_xen_vm_util::current_thread_ptr refreshes it as needed.
     */
    if (target->wordsize == 8) {
	vdebug(3,LA_TARGET,LF_XV,
	       "attempting to find per-cpu kernel stack offset\n");

	if ((tmpbs = target_lookup_sym(target,"kernel_stack",NULL,NULL,
				       SYMBOL_TYPE_FLAG_VAR))) {
	    errno = 0;
	    xstate->kernel_stack_percpu_offset = 
		target_addressof_symbol(target,TID_GLOBAL,tmpbs,
					LOAD_FLAG_NONE,NULL);
	    bsymbol_release(tmpbs);
	    if (errno) {
		verror("could not load kernel_stack percpu offset;"
		       " cannot continue!\n");
		return -1;
	    }
	}
	else if ((tmpbs = target_lookup_sym(target,"struct x8664_pda",NULL,NULL,
					    SYMBOL_TYPE_FLAG_TYPE))) {
	    errno = 0;
	    xstate->kernel_stack_percpu_offset = 
		symbol_offsetof(bsymbol_get_symbol(tmpbs),"kernelstack",NULL);
	    if (errno) {
		verror("could not get offsetof struct x8664_pda.kernelstack;"
		       " cannot continue!\n");
		return -1;
	    }
	}
	else {
	    verror("could not find x86_64 kernel stack percpu var in debuginfo;"
		   " cannot continue!\n");
	    return -1;
	}
    }

    /* Fill in the init_task addr in the default thread. */
    ((struct xen_vm_thread_state *)(target->global_thread->state))->task_struct_addr = \
	xstate->init_task_addr;

    /*
     * Save the 'struct task_struct' type.  Hold a ref to it since it
     * might be an autofollowed abstract origin type!
     */
    xstate->task_struct_type =						\
	symbol_get_datatype(xstate->init_task->lsymbol->symbol);

    mm_struct_type = target_lookup_sym(target,"struct mm_struct",
				       NULL,NULL,SYMBOL_TYPE_FLAG_TYPE);
    if (!mm_struct_type) {
	vwarn("could not lookup 'struct mm_struct' in debuginfo;"
	      " userspace vm access might fail!\n");
	/* This is not an error, so we don't return error -- it
	 * would upset target_open.
	 */
	return 0;
    }
    xstate->mm_struct_type = bsymbol_get_symbol(mm_struct_type);
    RHOLD(xstate->mm_struct_type,target);
    bsymbol_release(mm_struct_type);

    /* We might also want to load tasks from pointers (i.e., the
     * current task.
     */
    xstate->task_struct_type_ptr =				\
	target_create_synthetic_type_pointer(target,xstate->task_struct_type);

    /*
     * Save the 'struct pt_regs' type.
     */
    tmpbs = target_lookup_sym(target,"struct pt_regs",NULL,NULL,
			      SYMBOL_TYPE_FLAG_TYPE);
    if (!tmpbs) {
	vwarn("could not lookup 'struct pt_regs' in debuginfo;"
	      " no multithread support!\n");
	/* This is not an error, so we don't return error -- it
	 * would upset target_open.
	 */
	return 0;
    }
    xstate->pt_regs_type = bsymbol_get_symbol(tmpbs);
    RHOLD(xstate->pt_regs_type,target);
    bsymbol_release(tmpbs);

    /*
     * Find out if pt_regs has ds/es (only i386 should have it; old i386
     * has xds/xes; new i386 has ds/es).
     */
    if ((tmpls = symbol_lookup_sym(xstate->pt_regs_type,"ds",NULL))
	|| (tmpls = symbol_lookup_sym(xstate->pt_regs_type,"xds",NULL))) {
	lsymbol_release(tmpls);
	xstate->pt_regs_has_ds_es = 1;
    }
    else
	xstate->pt_regs_has_ds_es = 0;

    /*
     * Find out if pt_regs has fs/gs (only i386 should have it).
     */
    if ((tmpls = symbol_lookup_sym(xstate->pt_regs_type,"fs",NULL))) {
	lsymbol_release(tmpls);
	xstate->pt_regs_has_fs_gs = 1;
    }
    else
	xstate->pt_regs_has_fs_gs = 0;

    /*
     * Find the offset of the (r|e)ip member in pt_regs (we use this for
     * faster loading/saving).
     */
    errno = 0;
    xstate->pt_regs_ip_offset = 
	(int)symbol_offsetof(xstate->pt_regs_type,"ip",NULL);
    if (errno) {
	errno = 0;
	xstate->pt_regs_ip_offset = 
	    (int)symbol_offsetof(xstate->pt_regs_type,"eip",NULL);
	if (errno) {
	    errno = 0;
	    xstate->pt_regs_ip_offset = 
		(int)symbol_offsetof(xstate->pt_regs_type,"rip",NULL);
	    if (errno) {
		vwarn("could not find (r|e)ip in pt_regs; things will break!\n");
	    }
	}
    }

    /*
     * Find out if task_struct has a thread_info member (older), or if
     * it just has a void * stack (newer).  As always, either way, the
     * thread_info struct is at the "bottom" of the stack; the stack top
     * is either a page or two up.
     */
    if ((tmpls = symbol_lookup_sym(xstate->task_struct_type,"thread_info",NULL))) {
	xstate->task_struct_has_thread_info = 1;
	lsymbol_release(tmpls);
    }
    else if ((tmpls = symbol_lookup_sym(xstate->task_struct_type,"stack",NULL))) {
	xstate->task_struct_has_stack = 1;
	lsymbol_release(tmpls);
    }
    else {
	vwarn("could not find thread_info nor stack member in struct task_struct;"
	      " no multithread support!\n");
	return 0;
    }

    /*
     * Save the 'struct thread_struct' type.
     */
    tmpbs = target_lookup_sym(target,"struct thread_struct",NULL,NULL,
			      SYMBOL_TYPE_FLAG_TYPE);
    if (!tmpbs) {
	vwarn("could not lookup 'struct thread_struct' in debuginfo;"
	      " no multithread support!\n");
	/* This is not an error, so we don't return error -- it
	 * would upset target_open.
	 */
	return 0;
    }
    xstate->thread_struct_type = bsymbol_get_symbol(tmpbs);
    RHOLD(xstate->thread_struct_type,target);
    bsymbol_release(tmpbs);
    /* Now figure out if the member is esp/sp. */
    if ((tmpls = symbol_lookup_sym(xstate->thread_struct_type,"esp0",NULL))) {
	xstate->thread_sp_member_name = "esp";
	xstate->thread_sp0_member_name = "esp0";
	lsymbol_release(tmpls);
    }
    else if ((tmpls = symbol_lookup_sym(xstate->thread_struct_type,"sp",NULL))) {
	xstate->thread_sp_member_name = "sp";
	xstate->thread_sp0_member_name = "sp0";
	lsymbol_release(tmpls);
    }
    else if ((tmpls = symbol_lookup_sym(xstate->thread_struct_type,"rsp0",NULL))) {
	xstate->thread_sp_member_name = "rsp";
	xstate->thread_sp0_member_name = "rsp0";
	lsymbol_release(tmpls);
    }
    else {
	vwarn("could not find 'struct thread_struct.(esp0|sp|rsp0)';"
	      " will cause problems!\n");
	xstate->thread_sp_member_name = NULL;
	xstate->thread_sp0_member_name = NULL;
    }

    /* Now figure out if thread_struct has an eip/ip member. */
    if ((tmpls = symbol_lookup_sym(xstate->thread_struct_type,"eip",NULL))) {
	xstate->thread_ip_member_name = "eip";
	lsymbol_release(tmpls);
    }
    else if ((tmpls = symbol_lookup_sym(xstate->thread_struct_type,"ip",NULL))) {
	xstate->thread_ip_member_name = "ip";
	lsymbol_release(tmpls);
    }
    else if ((tmpls = symbol_lookup_sym(xstate->thread_struct_type,"rip",NULL))) {
	xstate->thread_ip_member_name = "rip";
	lsymbol_release(tmpls);
    }
    else {
	xstate->thread_ip_member_name = NULL;
    }

    /*
     * Find out if thread_struct has ds/es (x86_64).
     */
    if ((tmpls = symbol_lookup_sym(xstate->thread_struct_type,"es",NULL))) {
	lsymbol_release(tmpls);
	xstate->thread_struct_has_ds_es = 1;
    }
    else
	xstate->thread_struct_has_ds_es = 0;

    /*
     * Find out if thread_struct has fs (x86_64 only -- it's on the
     * pt_regs stack for i386).
     *
     * Also, gs is always in the thread_struct, as far as I can tell.
     */
    if ((tmpls = symbol_lookup_sym(xstate->thread_struct_type,"fs",NULL))) {
	lsymbol_release(tmpls);
	xstate->thread_struct_has_fs = 1;
    }
    else
	xstate->thread_struct_has_fs = 0;

    /*
     * Find out if thread_struct has debugreg, debugreg0, or perf_event.
     */
    if ((tmpls = symbol_lookup_sym(xstate->thread_struct_type,"debugreg",
				   NULL))) {
	lsymbol_release(tmpls);
	xstate->thread_struct_has_debugreg = 1;
    }
    else
	xstate->thread_struct_has_debugreg = 0;
    if ((tmpls = symbol_lookup_sym(xstate->thread_struct_type,"debugreg0",
				   NULL))) {
	lsymbol_release(tmpls);
	xstate->thread_struct_has_debugreg0 = 1;
    }
    else
	xstate->thread_struct_has_debugreg0 = 0;
    if ((tmpls = symbol_lookup_sym(xstate->thread_struct_type,"ptrace_bps",
				   NULL))) {
	lsymbol_release(tmpls);
	xstate->thread_struct_has_perf_debugreg = 1;
    }
    else
	xstate->thread_struct_has_perf_debugreg = 0;

    /*
     * Load in thread_info struct type.
     */
    thread_info_type = target_lookup_sym(target,"struct thread_info",
					 NULL,NULL,SYMBOL_TYPE_FLAG_TYPE);
    if (!thread_info_type) {
	vwarn("could not lookup 'struct thread_info' in debuginfo;"
	      " no multithread support!\n");
	/* This is not an error, so we don't return error -- it
	 * would upset target_open.
	 */
	return 0;
    }
    xstate->thread_info_type = bsymbol_get_symbol(thread_info_type);
    RHOLD(xstate->thread_info_type,target);
    bsymbol_release(thread_info_type);

    if (!(xstate->module_type = target_lookup_sym(target,"struct module",
						  NULL,NULL,
						  SYMBOL_TYPE_FLAG_TYPE))) {
	vwarn("could not lookup 'struct module'; no module debuginfo support!\n");
    }
    else if (!(xstate->modules = target_lookup_sym(target,"modules",NULL,NULL,
						   SYMBOL_TYPE_FLAG_VAR))) {
	vwarn("could not lookup modules; not updating modules list!\n");
	return 0;
    }

    /*
     * Lookup symbols for active probing, here, regardless of
     * target->spec->active_probe_flags ; user may change active probing
     * settings later!
     */
    if (!(xstate->module_free_symbol = 
	  target_lookup_sym(target,"module_free",NULL,NULL,
			    SYMBOL_TYPE_NONE))) {
	vwarn("could not lookup module_free; active memory updates"
	      " cannot function!\n");
    }
    else if (!(xstate->module_free_mod_symbol = 
	           target_lookup_sym(target,"module_free.mod",NULL,NULL,
				     SYMBOL_TYPE_NONE))) {
	bsymbol_release(xstate->module_free_symbol);
	xstate->module_free_symbol = NULL;

	vwarn("could not lookup module_free.mod; active memory updates"
	      " cannot function!\n");
    }
    else {
	VLS(target,"MODULE_STATE_LIVE",LOAD_FLAG_NONE,
	    &xstate->MODULE_STATE_LIVE,NULL,err_vmiload_meminfo);
	vdebug(8,LA_TARGET,LF_XV,
	       "MODULE_STATE_LIVE = %d\n",xstate->MODULE_STATE_LIVE);
	VLS(target,"MODULE_STATE_COMING",LOAD_FLAG_NONE,
	    &xstate->MODULE_STATE_COMING,NULL,err_vmiload_meminfo);
	vdebug(8,LA_TARGET,LF_XV,
	       "MODULE_STATE_COMING = %d\n",xstate->MODULE_STATE_COMING);
	VLS(target,"MODULE_STATE_GOING",LOAD_FLAG_NONE,
	    &xstate->MODULE_STATE_GOING,NULL,err_vmiload_meminfo);
	vdebug(8,LA_TARGET,LF_XV,
	       "MODULE_STATE_GOING = %d\n",xstate->MODULE_STATE_GOING);

	if (0) {
	err_vmiload_meminfo:
	    bsymbol_release(xstate->module_free_symbol);
	    xstate->module_free_symbol = NULL;
	    bsymbol_release(xstate->module_free_mod_symbol);
	    xstate->module_free_mod_symbol = NULL;

	    vwarn("could not lookup MODULE_STATE_* var; active memory updates"
		  " cannot function!\n");
	}
    }

#ifdef ENABLE_DISTORM
    if (!(xstate->thread_entry_f_symbol = 
	      target_lookup_sym(target,"copy_process",NULL,NULL,
				SYMBOL_TYPE_NONE))) {
	vwarn("could not lookup copy_process;"
	      " active thread entry updates cannot function!\n");
    }
    else if (!(xstate->thread_entry_v_symbol = 
	           target_lookup_sym(target,"copy_process.p",NULL,NULL,
				     SYMBOL_TYPE_NONE))) {
	bsymbol_release(xstate->thread_entry_f_symbol);
	xstate->thread_entry_f_symbol = NULL;

	vwarn("could not lookup copy_process.p;"
	      " active thread entry updates cannot function!\n");
    }
#endif

    if (!(xstate->thread_exit_f_symbol = 
	      target_lookup_sym(target,"sched_exit",NULL,NULL,
				SYMBOL_TYPE_NONE))) {
	vwarn("could not lookup sched_exit; trying __unhash_process!\n");

	if (!(xstate->thread_exit_f_symbol = 
	      target_lookup_sym(target,"__unhash_process",NULL,NULL,
				SYMBOL_TYPE_NONE))) {
	    vwarn("could not lookup __unhash_process;"
		  " active thread exit updates cannot function!\n");
	}
	else if (!(xstate->thread_exit_v_symbol = 
		   target_lookup_sym(target,"__unhash_process.p",NULL,NULL,
				     SYMBOL_TYPE_NONE))) {
	    bsymbol_release(xstate->thread_exit_f_symbol);
	    xstate->thread_exit_f_symbol = NULL;
	    vwarn("could not lookup __unhash_process.p;"
		  " active thread exit updates cannot function!\n");
	}
    }
    else if (!(xstate->thread_exit_v_symbol = 
	      target_lookup_sym(target,"sched_exit.p",NULL,NULL,
				SYMBOL_TYPE_NONE))) {
	bsymbol_release(xstate->thread_exit_f_symbol);
	xstate->thread_exit_f_symbol = NULL;
	vwarn("could not lookup sched_exit.p;"
	      " active thread exit updates cannot function!\n");
    }

    return 0;
}

static int xen_vm_postopened(struct target *target) {
    return 0;
}

static int xen_vm_set_active_probing(struct target *target,
				     active_probe_flags_t flags) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;
    struct probe *probe;
    char *name;

    if ((flags & ACTIVE_PROBE_FLAG_MEMORY) 
	!= (target->active_probe_flags & ACTIVE_PROBE_FLAG_MEMORY)) {
	if (flags & ACTIVE_PROBE_FLAG_MEMORY) {
	    probe = probe_create(target,TID_GLOBAL,NULL,
				 bsymbol_get_name(xstate->module_free_symbol),
				 xen_vm_active_memory_handler,NULL,NULL,0,1);
	    /* NB: always use this; it should be the default! */
	    if (!probe_register_inlined_symbol(probe,xstate->module_free_symbol,
					       1,PROBEPOINT_SW,0,0)) {
		probe_free(probe,1);
		probe = NULL;

		vwarn("could not probe module_free; not enabling"
		      " active memory updates!\n");

		xstate->active_memory_probe = NULL;
		target->active_probe_flags &= ~ACTIVE_PROBE_FLAG_MEMORY;
	    }
	    else {
		xstate->active_memory_probe = probe;
		target->active_probe_flags |= ACTIVE_PROBE_FLAG_MEMORY;
	    }
	}
	else {
	    if (xstate->active_memory_probe) {
		probe_free(xstate->active_memory_probe,0);
		xstate->active_memory_probe = NULL;
	    }
	    target->active_probe_flags &= ~ACTIVE_PROBE_FLAG_MEMORY;
	}
    }

    if ((flags & ACTIVE_PROBE_FLAG_THREAD_ENTRY) 
	!= (target->active_probe_flags & ACTIVE_PROBE_FLAG_THREAD_ENTRY)) {
	if (flags & ACTIVE_PROBE_FLAG_THREAD_ENTRY) {
#ifdef ENABLE_DISTORM
	    name = bsymbol_get_name(xstate->thread_entry_f_symbol);
	    /*
	     * Create it with only a post handler so that we only probe
	     * on the RETs from copy_process().
	     */
	    probe = probe_create(target,TID_GLOBAL,NULL,name,
				 NULL,xen_vm_active_thread_entry_handler,
				 NULL,0,1);
	    if (!probe_register_function_ee(probe,PROBEPOINT_SW,
					    xstate->thread_entry_f_symbol,0,0)) {
		probe_free(probe,1);
		probe = NULL;

		vwarn("could not probe %s entry/exits; not enabling"
		      " active thread entry updates!\n",name);

		xstate->active_thread_entry_probe = NULL;
		target->active_probe_flags &= ~ACTIVE_PROBE_FLAG_THREAD_ENTRY;
	    }
	    else {
		xstate->active_thread_entry_probe = probe;
		target->active_probe_flags |= ACTIVE_PROBE_FLAG_THREAD_ENTRY;
	    }
#else
	    verror("cannot enable active thread_entry probes; distorm (disasm)"
		   " support not built in!");
#endif
	}
	else {
	    if (xstate->active_thread_entry_probe) {
		probe_free(xstate->active_thread_entry_probe,0);
		xstate->active_thread_entry_probe = NULL;
	    }
	    target->active_probe_flags &= ~ACTIVE_PROBE_FLAG_THREAD_ENTRY;
	}
    }

    if ((flags & ACTIVE_PROBE_FLAG_THREAD_EXIT) 
	!= (target->active_probe_flags & ACTIVE_PROBE_FLAG_THREAD_EXIT)) {
	if (flags & ACTIVE_PROBE_FLAG_THREAD_EXIT) {
	    name = bsymbol_get_name(xstate->thread_exit_f_symbol);
	    probe = probe_create(target,TID_GLOBAL,NULL,name,
				 xen_vm_active_thread_exit_handler,
				 NULL,NULL,0,1);
	    /* NB: always use this; it should be the default! */
	    if (!probe_register_inlined_symbol(probe,
					       xstate->thread_exit_f_symbol,
					       1,PROBEPOINT_SW,0,0)) {
		probe_free(probe,1);
		probe = NULL;

		vwarn("could not probe %s; not enabling"
		      " active thread exit updates!\n",name);

		xstate->active_thread_exit_probe = NULL;
		target->active_probe_flags &= ~ACTIVE_PROBE_FLAG_THREAD_EXIT;
	    }
	    else {
		xstate->active_thread_exit_probe = probe;
		target->active_probe_flags |= ACTIVE_PROBE_FLAG_THREAD_EXIT;
	    }
	}
	else {
	    if (xstate->active_thread_exit_probe) {
		probe_free(xstate->active_thread_exit_probe,0);
		xstate->active_thread_exit_probe = NULL;
	    }
	    target->active_probe_flags &= ~ACTIVE_PROBE_FLAG_THREAD_EXIT;
	}
    }

    return 0;
}

static struct target *
xen_vm_instantiate_overlay(struct target *target,
			   struct target_thread *tthread,
			   struct target_spec *spec) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;
    struct target *overlay;
    REGVAL thip;

    if (spec->target_type != TARGET_TYPE_XEN_PROCESS) {
	errno = EINVAL;
	return NULL;
    }

    errno = 0;
    thip = xen_vm_read_reg(target,tthread->tid,target->ipregno);
    if (errno) {
	verror("could not read IP for tid %"PRIiTID"!!\n",tthread->tid);
	return NULL;
    }
    if (thip >= xstate->kernel_start_addr) {
	errno = EINVAL;
	verror("tid %"PRIiTID" IP 0x%"PRIxADDR" is a kernel thread!\n",
	       tthread->tid,thip);
	return NULL;
    }

    /*
     * All we want to do here is create the overlay target.
     */
    overlay = target_create("xen_vm_process",spec);

    return overlay;
}

static struct target_thread *
xen_vm_lookup_overlay_thread_by_id(struct target *target,int id) {
    struct target_thread *retval;
    struct xen_vm_thread_state *xtstate;

    retval = xen_vm_load_thread(target,id,0);
    if (!retval) {
	if (!errno)
	    errno = ESRCH;
	return NULL;
    }

    xtstate = (struct xen_vm_thread_state *)retval->state;
    if (xtstate->mm_addr) {
	vdebug(5,LA_TARGET,LF_XV,
	       "found overlay thread %d\n",id);
	return retval;
    }
    else {
	verror("tid %d matched %d, but is a kernel thread!\n",retval->tid,id);
	errno = EINVAL;
	return NULL;
    }
}

static struct target_thread *
xen_vm_lookup_overlay_thread_by_name(struct target *target,char *name) {
    struct target_thread *retval = NULL;
    struct target_thread *tthread;
    struct xen_vm_thread_state *xtstate;
    int slen;
    int rc;
    GHashTableIter iter;
    struct value *value;

    if ((rc = xen_vm_load_available_threads(target,0)))
	vwarn("could not load %d threads; continuing anyway!\n",-rc);

    g_hash_table_iter_init(&iter,target->threads);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer)&tthread)) {
	if (tthread == target->global_thread)
	    continue;
	else {
	    xtstate = (struct xen_vm_thread_state *)tthread->state;
	    value = target_load_value_member(target,xtstate->task_struct,"comm",
					     NULL,LOAD_FLAG_NONE);
	    if (!value) {
		vwarn("could not load .comm in task_struct for tid %d; continuing!\n",
		      tthread->tid);
		continue;
	    }
	    slen = strnlen(value->buf,value->bufsiz);
	    vdebug(8,LA_TARGET,LF_XV,
		   "checking task with name '%*s' against '%s'\n",
		   slen,value->buf,name);
	    if (strncmp(name,value->buf,slen) == 0) {
		retval = tthread;
		break;
	    }
	}
    }

    if (retval) {
	if (xtstate->mm_addr == 0) {
	    verror("tid %d matched '%s', but is a kernel thread!\n",
		   retval->tid,name);
	    errno = EINVAL;
	    return NULL;
	}
	else {
	    vdebug(5,LA_TARGET,LF_XV,
		   "found overlay thread %"PRIiTID"\n",retval->tid);
	    return tthread;
	}
    }
    else {
	errno = ESRCH;
	return NULL;
    }
}

static target_status_t xen_vm_status(struct target *target) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;
    target_status_t retval = TSTATUS_UNKNOWN;

    if (xen_vm_load_dominfo(target)) {
	verror("could not load dominfo for dom %d\n",xstate->id);
	return retval;
    }

    if (xstate->dominfo.paused)
	retval = TSTATUS_PAUSED;
    else if (xstate->dominfo.running || xstate->dominfo.blocked) 
	/* XXX: is this right?  i.e., is "blocked" from the hypervisor
	   perspective? */
	retval = TSTATUS_RUNNING;
    else if (xstate->dominfo.dying || xstate->dominfo.crashed)
	retval = TSTATUS_DEAD;
    else if (xstate->dominfo.shutdown)
	retval = TSTATUS_STOPPED;
    else
	retval = TSTATUS_ERROR;

    vdebug(9,LA_TARGET,LF_XV,"dom %d status %d\n",xstate->id,retval);

    return retval;
}

static int xen_vm_pause(struct target *target,int nowait) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;

    vdebug(5,LA_TARGET,LF_XV,"dom %d\n",xstate->id);

    if (xen_vm_load_dominfo(target)) 
	vwarn("could not load dominfo for dom %d, trying to pause anyway!\n",xstate->id);

    if (xstate->dominfo.paused)
	return 0;

    if (xc_domain_pause(xc_handle,xstate->id)) {
	verror("could not pause dom %d!\n",xstate->id);
	return -1;
    }

    target_set_status(target,TSTATUS_PAUSED);

    xstate->dominfo_valid = 0;
    if (xen_vm_load_dominfo(target)) 
	vwarn("could not reload dominfo for dom %d after pause!\n",xstate->id);

    return 0;
}

static int xen_vm_flush_current_thread(struct target *target) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)(target->state);
    struct target_thread *tthread;
    struct xen_vm_thread_state *tstate;
    struct value *v;
    tid_t tid;

    if (!target->current_thread) {
	verror("current thread not loaded!\n");
	errno = EINVAL;
	return -1;
    }

    tthread = target->current_thread;
    tid = tthread->tid;
    tstate = (struct xen_vm_thread_state *)tthread->state;

    vdebug(5,LA_TARGET,LF_XV,"dom %d tid %"PRIiTID"\n",xstate->id,tid);

    if (!tthread->valid || !tthread->dirty) {
	vdebug(8,LA_TARGET,LF_XV,
	       "dom %d tid %"PRIiTID" not valid (%d) or not dirty (%d)\n",
	       xstate->id,tid,tthread->valid,tthread->dirty);
	return 0;
    }

    vdebug(3,LA_TARGET,LF_XV,
	   "EIP is 0x%"PRIxREGVAL" before flush (dom %d tid %"PRIiTID")\n",
	   xen_vm_read_reg(target,TID_GLOBAL,target->ipregno),
	   xstate->id,tid);

    /*
     * Flush Xen machine context.
     */
    if (__xen_vm_cpu_setcontext(target,&tstate->context) < 0) {
	verror("could not set vcpu context (dom %d tid %"PRIiTID")\n",
	       xstate->id,tid);
	errno = EINVAL;
	return -1;
    }

    /*
     * Flush PCB state -- task_flags, thread_info_flags.
     *
     * NOTE: might not be able to flush this if the current thread is
     * the global thread...
     */
    if (tstate->thread_info) {
	v = target_load_value_member(target,tstate->thread_info,"flags",NULL,
				     LOAD_FLAG_NONE);
	value_update_unum(v,tstate->thread_info_flags);
	target_store_value(target,v);
	value_free(v);
    }

    /* Can only flush this if we weren't in interrupt context. */
    if (tstate->task_struct) {
	v = target_load_value_member(target,tstate->task_struct,"flags",NULL,
				     LOAD_FLAG_NONE);
	value_update_num(v,tstate->task_flags);
	target_store_value(target,v);
	value_free(v);
    }

    /* Mark cached copy as clean. */
    tthread->dirty = 0;

#if __WORDSIZE == 32
    vdebug(4,LA_TARGET,LF_XV,
	   "eflags (vcpu context): 0x%"PRIxADDR"\n",
	   tstate->context.user_regs.eflags);
#else
    vdebug(4,LA_TARGET,LF_XV,
	   "rflags (vcpu context): 0x%"PRIxADDR"\n",
	   tstate->context.user_regs.rflags);
#endif
    vdebug(4,LA_TARGET,LF_XV,
	   "debug registers (vcpu context): 0x%"PRIxADDR",0x%"PRIxADDR
	   ",0x%"PRIxADDR",0x%"PRIxADDR",0,0,0x%"PRIxADDR",0x%"PRIxADDR"\n",
	   tstate->context.debugreg[0],tstate->context.debugreg[1],
	   tstate->context.debugreg[2],tstate->context.debugreg[3],
	   tstate->context.debugreg[6],tstate->context.debugreg[7]);

    vdebug(4,LA_TARGET,LF_XV,
	   "debug registers (our copy): 0x%"PRIxADDR",0x%"PRIxADDR
	   ",0x%"PRIxADDR",0x%"PRIxADDR",0,0,0x%"PRIxADDR",0x%"PRIxADDR"\n",
	   tstate->dr[0],tstate->dr[1],tstate->dr[2],tstate->dr[3],
	   tstate->dr[6],tstate->dr[7]);

    return 0;
}

/*
 * Very similar to flush_current_thread -- BUT it doesn't flush anything
 * but CPU context.
 *
 * Also, if @current_thread is not NULL, we do a funny thing -- we use
 * the cpu context from @current_thread as our base, and overlay ONLY the
 * debug registers from the global thread -- and set the context to
 * that.  If @current_thread is NULL, we upload the full CPU context we
 * have.  @current_thread must not be the global thread itself.
 *
 * We do things this way because the only time we use the global thread
 * to pass to bp/ss handlers in the probe library is when Xen is in
 * interrupt context.  In that case, there is no current_thread -- the
 * current_thread is the global thread.  So in reality, the only thing
 * that gets stored in the global thread is hardware probepoints that
 * were set for TID_GLOBAL.  However, when the bp/ss handlers handle
 * those probepoints, they do so in the context of the thread -- which
 * is either current_thread (if in task context) or global_thread (if in
 * interrupt context, because there is no task thread, just an interrupt
 * stack).  So, even when a TID_GLOBAL hardware probepoint is being
 * handled, all the non-debug-register modifications to it happen in the
 * current_thread CPU state.
 */
static int xen_vm_flush_global_thread(struct target *target,
				      struct target_thread *current_thread) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)(target->state);
    struct target_thread *gthread;
    struct xen_vm_thread_state *tstate;
    struct xen_vm_thread_state *gtstate;
    vcpu_guest_context_t *ctxp;
    vcpu_guest_context_t context;
    int i;

    if (!target->global_thread) {
	verror("BUG: no global thread loaded!!!\n");
	errno = EINVAL;
	return -1;
    }
    if (current_thread == target->global_thread)
	current_thread = NULL;

    gthread = target->global_thread;
    gtstate = (struct xen_vm_thread_state *)gthread->state;
    if (current_thread)
	tstate = (struct xen_vm_thread_state *)current_thread->state;
    else
	tstate = NULL;

    if (!gthread->valid || !gthread->dirty) {
	vdebug(8,LA_TARGET,LF_XV,
	       "dom %d tid %"PRIiTID" not valid (%d) or not dirty (%d)\n",
	       xstate->id,gthread->tid,gthread->valid,gthread->dirty);
	return 0;
    }

    if (!current_thread) {
	/* Flush the global thread's CPU context directly. */

	vdebug(5,LA_TARGET,LF_XV,"dom %d tid %"PRIiTID" (full global vCPU flush)\n",
	       xstate->id,gthread->tid);

	ctxp = &gtstate->context;
    }
    else {
	/* We have to merge the hardware debug register state from the
	 * current thread with the state for the global thread.
	 */
	ctxp = &context;

	/* Copy the current_thread's whole context in; then overlay teh
	 * global thread's debugreg values *that are in use*.
	 */
	memcpy(ctxp,&tstate->context,sizeof(tstate->context));

	/* Unilaterally NULL status register out; we're about to flush. */
	ctxp->debugreg[6] = 0;

	/* For any TID_GLOBAL debugreg that is in use, copy the register
	 * and its control bits into the merged ctxp.
	 */
	for (i = 0; i < 4; ++i) {
	    if (gtstate->context.debugreg[i] == 0)
		continue;

	    vdebug(5,LA_TARGET,LF_XV,"merging global debug reg %d in!\n",i);
	    /* Copy in the break address */
	    ctxp->debugreg[i] = gtstate->context.debugreg[i];
	    /* Overwrite the control bits; unset them first, then set. */
	    ctxp->debugreg[7] &= ~(0x3 << (i * 2));
	    ctxp->debugreg[7] |= ((0x3 << (i * 2)) & gtstate->context.debugreg[7]);
	    /* Overwrite the break-on bits; unset them first, then set. */
	    ctxp->debugreg[7] &= ~(0x3 << (16 + (i * 4)));
	    ctxp->debugreg[7] |= ((0x3 << (16 + (i * 4))) & gtstate->context.debugreg[7]);
	    /* Overwrite the break-on size bits (watchpoint size) */
	    ctxp->debugreg[7] &= ~(0x3 << (18 + (i * 4)));
	    ctxp->debugreg[7] |= ((0x3 << (18 + (i * 4))) & gtstate->context.debugreg[7]);
	}

	/* Unilaterally set the break-exact bits. */
	//ctxp->debugreg[7] |= 0x3 << 8;
	
    }

    if (!current_thread) {
	vdebug(3,LA_TARGET,LF_XV,
	       "EIP is 0x%"PRIxREGVAL" before flush (dom %d tid %"PRIiTID")\n",
	       xen_vm_read_reg(target,TID_GLOBAL,target->ipregno),
	       xstate->id,gthread->tid);
    }
    else {
	vdebug(3,LA_TARGET,LF_XV,
	       "EIP is 0x%"PRIxREGVAL" (in thread %"PRIiTID") before flush (dom %d tid %"PRIiTID")\n",
	       xen_vm_read_reg(target,current_thread->tid,target->ipregno),
	       current_thread->tid,
	       xstate->id,gthread->tid);
    }

    /*
     * Flush Xen machine context.
     */
    if (__xen_vm_cpu_setcontext(target,ctxp) < 0) {
	verror("could not set vcpu context (dom %d tid %"PRIiTID")\n",
	       xstate->id,gthread->tid);
	errno = EINVAL;
	return -1;
    }

    /* Mark cached copy as clean. */
    gthread->dirty = 0;

    if (!current_thread)
	vdebug(4,LA_TARGET,LF_XV,
	       "debug registers (setting full vcpu context): 0x%"PRIxADDR",0x%"PRIxADDR
	       ",0x%"PRIxADDR",0x%"PRIxADDR",0,0,0x%"PRIxADDR",0x%"PRIxADDR"\n",
	       gtstate->context.debugreg[0],gtstate->context.debugreg[1],
	       gtstate->context.debugreg[2],gtstate->context.debugreg[3],
	       gtstate->context.debugreg[6],gtstate->context.debugreg[7]);
    else
	vdebug(4,LA_TARGET,LF_XV,
	       "debug registers (setting MERGED!!! vcpu context): 0x%"PRIxADDR",0x%"PRIxADDR
	       ",0x%"PRIxADDR",0x%"PRIxADDR",0,0,0x%"PRIxADDR",0x%"PRIxADDR"\n",
	       ctxp->debugreg[0],ctxp->debugreg[1],
	       ctxp->debugreg[2],ctxp->debugreg[3],
	       ctxp->debugreg[6],ctxp->debugreg[7]);

    if (!current_thread) 
	vdebug(4,LA_TARGET,LF_XV,
	       "debug registers (our copy): 0x%"PRIxADDR",0x%"PRIxADDR
	       ",0x%"PRIxADDR",0x%"PRIxADDR",0,0,0x%"PRIxADDR",0x%"PRIxADDR"\n",
	       gtstate->dr[0],gtstate->dr[1],gtstate->dr[2],gtstate->dr[3],
	       gtstate->dr[6],gtstate->dr[7]);

    return 0;
}

static int xen_vm_pause_thread(struct target *target,tid_t tid,int nowait) {
    verror("cannot pause individual threads in guests!\n");
    errno = EINVAL;
    return -1;
}

static int xen_vm_flush_thread(struct target *target,tid_t tid) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;
    struct target_thread *tthread;
    struct xen_vm_thread_state *tstate = NULL;
    struct value *v;
    int iskernel = 0;
    int ip_offset;
    int i;

    vdebug(16,LA_TARGET,LF_XV,"dom %d tid %"PRIiTID"\n",xstate->id,tid);

    /*
     * If we are flushing the global thread (TID_GLOBAL), do it right
     * away.
     */
    if (tid == TID_GLOBAL)
	return xen_vm_flush_current_thread(target);

    /*
     * If we haven't loaded current_thread yet, we really should load it
     * because otherwise we don't know if current_thread->tid == @tid.
     * If it does, we don't want to do the below stuff, which only
     * applies to non-running threads -- in this case, we want to flush
     * to the hardware directly.
     *
     * BUT -- we can't load a thread in the flush code; we might be
     * iterating over the threads hashtable, so a load might result in
     * a thread create which would result in the hashtable being
     * modified.
     */
    if (!target->current_thread) {
	vdebug(9,LA_TARGET,LF_XV,
	       "current thread not loaded to compare with"
	       " tid %"PRIiTID"; exiting, user-mode EIP, or BUG?\n",
	       tid);
    }
    else if (!target->current_thread->valid) {
	vdebug(9,LA_TARGET,LF_XV,
	       "current thread not valid to compare with"
	       " tid %"PRIiTID"; exiting, user-mode EIP, or BUG?\n",
	       tid);
    }

    /*
     * If the thread tid we are asking for is the current thread and is
     * valid, or if the thread is in our cache and is valid.
     */
    if (target->current_thread && target->current_thread->tid == tid) {
	return xen_vm_flush_current_thread(target);
    }
    /*
     * Otherwise, try to lookup thread @tid.
     */
    else if ((tthread = target_lookup_thread(target,tid))) {
	tstate = (struct xen_vm_thread_state *)tthread->state;
    }

    if (tthread == target->current_thread)
	return xen_vm_flush_current_thread(target);

    if (!tthread) {
	verror("cannot flush unknown thread %"PRIiTID"; you forgot to load?\n",
	       tid);
	errno = EINVAL;
	return -1;
    }

    if (!tthread->valid || !tthread->dirty) {
	vdebug(8,LA_TARGET,LF_XV,
	       "dom %d tid %"PRIiTID" not valid (%d) or not dirty (%d)\n",
	       xstate->id,tthread->tid,tthread->valid,tthread->dirty);
	return 0;
    }

    if (tstate->mm_addr == 0)
	iskernel = 1;

    /*
     * Ok, we can finally flush this thread's state to memory.
     */

    /*
     * Flush (fake) Xen machine context loaded from stack, back to
     * stack.
     *
     * NB: this is a duplicate of the loading procedure!  See all the
     * comments there.
     */

    if (xstate->thread_ip_member_name) {
	v = target_load_value_member(target,tstate->thread_struct,
				     xstate->thread_ip_member_name,
				     NULL,LOAD_FLAG_NONE);
	if (!v) 
	    vwarn("could not store thread.%s for task %"PRIiTID"!\n",
		  xstate->thread_ip_member_name,tid);
	else {
	    value_update(v,(const char *)&tstate->eip,v->bufsiz);
	    target_store_value(target,v);
	    value_free(v);
	    v = NULL;
	}
    }
    else {
	v = target_load_addr_real(target,tstate->esp + 3 * target->wordsize,
				  LOAD_FLAG_NONE,target->wordsize);
	if (!v) 
	    vwarn("could not store 64-bit IP (thread.ip) for task %"PRIiTID"!\n",
		  tid);
	else {
	    value_update(v,(const char *)&tstate->eip,v->bufsiz);
	    target_store_value(target,v);
	    value_free(v);
	    v = NULL;
	}
    }

    /*
     * GS is always in the thread data structure:
     */
    v = target_load_value_member(target,tstate->thread_struct,"gs",NULL,
				 LOAD_FLAG_NONE);
    value_update_u16(v,tstate->context.user_regs.gs);
    target_store_value(target,v);
    value_free(v);
    v = NULL;

    if (xstate->thread_struct_has_fs) {
	v = target_load_value_member(target,tstate->thread_struct,"fs",NULL,
				     LOAD_FLAG_NONE);
	if (!v) {
	    vwarn("could not store thread.fs for task %"PRIiTID"!\n",tid);
	    goto errout;
	}
	else {
	    value_update(v,(const char *)&tstate->context.user_regs.fs,
			 v->bufsiz);
	    target_store_value(target,v);
	    value_free(v);
	    v = NULL;
	}
    }
    else {
	/* Load this to pt_regs below if we can. */
    }

    if (xstate->thread_struct_has_ds_es) {
	v = target_load_value_member(target,tstate->thread_struct,"ds",NULL,
				     LOAD_FLAG_NONE);
	if (!v) {
	    vwarn("could not store thread.ds for task %"PRIiTID"!\n",tid);
	    goto errout;
	}
	else {
	    value_update(v,(const char *)&tstate->context.user_regs.ds,
			 v->bufsiz);
	    target_store_value(target,v);
	    value_free(v);
	    v = NULL;
	}

	v = target_load_value_member(target,tstate->thread_struct,"es",NULL,
				     LOAD_FLAG_NONE);
	if (!v) {
	    vwarn("could not store thread.es for task %"PRIiTID"!\n",tid);
	    goto errout;
	}
	else {
	    value_update(v,(const char *)&tstate->context.user_regs.es,
			 v->bufsiz);
	    target_store_value(target,v);
	    value_free(v);
	    v = NULL;
	}
    }
    else {
	/* Load this to pt_regs below if we can. */
    }

    if (tstate->ptregs_stack_addr) {
	v = target_load_addr_real(target,tstate->ptregs_stack_addr,
				  LOAD_FLAG_NONE,
				  symbol_bytesize(xstate->pt_regs_type));
	if (!v) {
	    verror("could not store stack register save frame task %"PRIiTID"!\n",
		   tid);
	    goto errout;
	}

	/* Copy the first range. */
	if (target->wordsize == 8)
	    memcpy(v->buf,&tstate->context.user_regs,8 * 15);
	else
	    memcpy(v->buf,&tstate->context.user_regs,4 * 7);

	/* Copy the second range. */
	/**
	 ** WARNING: esp and ss may not be valid if the sleeping thread was
	 ** interrupted while it was in the kernel, because the interrupt
	 ** gate does not push ss and esp; see include/asm-i386/processor.h .
	 **/
#if __WORDSIZE == 64
	ip_offset = offsetof(struct vcpu_guest_context,user_regs.rip);
#else
	ip_offset = offsetof(struct vcpu_guest_context,user_regs.eip);
#endif
	if (target->wordsize == 8)
	    memcpy(v->buf + xstate->pt_regs_ip_offset,
		   ((char *)&tstate->context) + ip_offset,8 * 5);
	else
	    memcpy(v->buf + xstate->pt_regs_ip_offset,
		   ((char *)&tstate->context) + ip_offset,4 * 5);

	/*
	 * ds, es, fs, gs are all special; see other comments.
	 */
	if (!xstate->thread_struct_has_ds_es && xstate->pt_regs_has_ds_es) {
	    memcpy((char *)v->buf + 7 * target->wordsize,
		   &tstate->context.user_regs.ds,v->bufsiz);
	    memcpy((char *)v->buf + 8 * target->wordsize,
		   &tstate->context.user_regs.es,v->bufsiz);
	}
	if (!xstate->thread_struct_has_fs && xstate->pt_regs_has_fs_gs) {
	    /* XXX: this is only true on newer x86 stuff; x86_64 and old
	     * i386 stuff did not save it on the stack.
	     */
	    memcpy((char *)v->buf + 9 * target->wordsize,
		   &tstate->context.user_regs.fs,v->bufsiz);
	}

	target_store_value(target,v);

	value_free(v);
	v = NULL;
    }
    else {
	/*
	 * Either we could not load pt_regs due to lack of type info; or
	 * this thread was just context-switched out, not interrupted
	 * nor preempted, so we can't get its GP registers.  Get what we
	 * can...
	 */
	memset(&tstate->context,0,sizeof(vcpu_guest_context_t));
	tstate->context.user_regs.eip = tstate->eip;
	tstate->context.user_regs.esp = tstate->esp;
	tstate->context.user_regs.fs = tstate->fs;
	tstate->context.user_regs.gs = tstate->gs;

	/* eflags and ebp are on the stack. */
	v = target_load_addr_real(target,tstate->esp,LOAD_FLAG_NONE,
				  2 * target->wordsize);
	if (target->wordsize == 8) {
	    ((uint64_t *)v->buf)[1] = tstate->eflags;
	    ((uint64_t *)v->buf)[0] = tstate->ebp;
	}
	else {
	    ((uint32_t *)v->buf)[1] = tstate->eflags;
	    ((uint32_t *)v->buf)[0] = tstate->ebp;
	}

	target_store_value(target,v);

	value_free(v);
	v = NULL;
    }


    
    if (xstate->thread_struct_has_debugreg) {
	v = target_load_value_member(target,tstate->thread_struct,"debugreg",
				     NULL,LOAD_FLAG_AUTO_DEREF);
	if (!v) {
	    verror("could not store thread->debugreg for task %"PRIiTID"\n",tid);
	    goto errout;
	}
	if (target->wordsize == 8) {
	    ((uint64_t *)v->buf)[0] = tstate->context.debugreg[0];
	    ((uint64_t *)v->buf)[1] = tstate->context.debugreg[1];
	    ((uint64_t *)v->buf)[2] = tstate->context.debugreg[2];
	    ((uint64_t *)v->buf)[3] = tstate->context.debugreg[3];
	    ((uint64_t *)v->buf)[6] = tstate->context.debugreg[6];
	    ((uint64_t *)v->buf)[7] = tstate->context.debugreg[7];
	}
	else {
	    ((uint32_t *)v->buf)[0] = tstate->context.debugreg[0];
	    ((uint32_t *)v->buf)[1] = tstate->context.debugreg[1];
	    ((uint32_t *)v->buf)[2] = tstate->context.debugreg[2];
	    ((uint32_t *)v->buf)[3] = tstate->context.debugreg[3];
	    ((uint32_t *)v->buf)[6] = tstate->context.debugreg[6];
	    ((uint32_t *)v->buf)[7] = tstate->context.debugreg[7];
	}

	target_store_value(target,v);

	value_free(v);
	v = NULL;
    }
    else if (xstate->thread_struct_has_debugreg0) {
	/*
	 * This is old x86_64 style.
	 */
	static const char *dregmembers[8] = {
	    "debugreg0","debugreg1","debugreg2","debugreg3",
	    NULL,NULL,
	    "debugreg6","debugreg7"
	};

	for (i = 0; i < 8; ++i) {
	    if (!dregmembers[i])
		continue;

	    v = target_load_value_member(target,tstate->thread_struct,
					 dregmembers[i],NULL,
					 LOAD_FLAG_AUTO_DEREF);
	    if (!v) {
		verror("could not store thread->%s for task %"PRIiTID"\n",
		       dregmembers[i],tid);
		goto errout;
	    }
	    if (target->wordsize == 8) 
		*(uint64_t *)v->buf = tstate->context.debugreg[i];
	    else
		*(uint32_t *)v->buf = tstate->context.debugreg[i];

	    target_store_value(target,v);

	    value_free(v);
	    v = NULL;
	}
    }
    else if (xstate->thread_struct_has_perf_debugreg) {
	/*
	 * XXX: still need to store perf_events 0-3.
	 */

	v = target_load_value_member(target,tstate->thread_struct,"debugreg6",
				     NULL,LOAD_FLAG_AUTO_DEREF);
	if (!v) {
	    verror("could not store thread->debugreg6 for task %"PRIiTID"\n",tid);
	    goto errout;
	}
	if (target->wordsize == 8) 
	    *(uint64_t *)v->buf = tstate->context.debugreg[6];
	else
	    *(uint32_t *)v->buf = tstate->context.debugreg[6];

	target_store_value(target,v);

	value_free(v);
	v = NULL;

	v = target_load_value_member(target,tstate->thread_struct,"ptrace_dr7",
				     NULL,LOAD_FLAG_AUTO_DEREF);
	if (!v) {
	    verror("could not store thread->ptrace_dr7 for task %"PRIiTID"\n",tid);
	    goto errout;
	}
	if (target->wordsize == 8) 
	    *(uint64_t *)v->buf = tstate->context.debugreg[7];
	else
	    *(uint32_t *)v->buf = tstate->context.debugreg[7];

	target_store_value(target,v);

	value_free(v);
	v = NULL;

    }
    else {
	vwarn("could not store debugreg for tid %d; no debuginfo!\n",tid);
    }

    /*
     * Flush PCB state -- task_flags, thread_info_flags.
     */
    v = target_load_value_member(target,tstate->thread_info,"flags",NULL,
				 LOAD_FLAG_NONE);
    value_update_unum(v,tstate->thread_info_flags);
    target_store_value(target,v);
    value_free(v);

    /* Can only flush this if we weren't in interrupt context. */
    if (tstate->task_struct) {
	v = target_load_value_member(target,tstate->task_struct,"flags",NULL,
				     LOAD_FLAG_NONE);
	value_update_num(v,tstate->task_flags);
	target_store_value(target,v);
	value_free(v);
    }

    tthread->dirty = 0;

    return 0;

 errout:
    return -1;
}

static int xen_vm_flush_all_threads(struct target *target) {
    int rc, retval = 0;
    GHashTableIter iter;
    struct target_thread *tthread;
    struct target_thread *current_thread = NULL;

    g_hash_table_iter_init(&iter,target->threads);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer)&tthread)) {
	if (tthread == target->current_thread 
	    || tthread == target->global_thread)
	    continue;
	else
	    rc = xen_vm_flush_thread(target,tthread->tid);
	if (rc) {
	    verror("could not flush thread %"PRIiTID"\n",tthread->tid);
	    ++retval;
	}
    }

    /*
     * If the current thread is not the global thread, we have to try to
     * flush it.
     */
    if (target->current_thread
	&& target->current_thread != target->global_thread) {
	/* Save this off to tell flush_global_thread below that
	 * it must merge its state with this thread's state.
	 *
	 * So if the current thread is not the global thread itself, and
	 * its state is valid (whether it is dirty or not!!), we must
	 * merge.
	 */
	if (target->current_thread->valid)
	    current_thread = target->current_thread;

	rc = xen_vm_flush_current_thread(target);
	if (rc) {
	    verror("could not flush current thread %"PRIiTID"\n",
		   target->current_thread->tid);
	    ++retval;
	}
    }

    /*
     * Also, we always have to try to flush the "global" thread.
     * Remember, the global thread is a fake thread; it never maps to
     * anything real; it is just the current CPU registers.  If the user
     * sets any probes or modifies registers with TID_GLOBAL, they only
     * get flushed if we flush the global thread.
     *
     * OF COURSE, this means that if you mix per-thread probing/register
     * modification and global thread modification, your changes to the
     * current hardware state will almost certainly stomp on each
     * other.  OK, this is no longer permitted; get_unused_debug_reg now
     * makes sure this cannot happen.
     *
     * If we were handling a software breakpoint, we would have modified
     * cpu context in the current thread; if we were hanlding a hardware
     * probe or modifying a hardware probe, we would have written the
     * the global thread's cpu state (AND the current thread's CPU state
     * too, like EIP, etc).  So what we need to is arbitrate between the
     * two contexts depending on what we're doing.  For instance, if we
     * handled a hardware probepoint, we'll always need to flush the
     * global thread -- see monitor() and flush_global_thread().
    */
    rc = xen_vm_flush_global_thread(target,current_thread);
    if (rc) {
	verror("could not flush global thread %"PRIiTID"\n",TID_GLOBAL);
	++retval;
    }

    return retval;
}

static int __value_get_append_tid(struct target *target,struct value *value,
				  void *data) {
    struct array_list *list = (struct array_list *)data;
    struct value *v;

    v = target_load_value_member(target,value,"pid",NULL,LOAD_FLAG_NONE);
    if (!v) {
	verror("could not load pid in task; BUG?\n");
	/* errno should be set for us. */
	return -1;
    }
    array_list_append(list,(void *)(uintptr_t)v_i32(v));
    value_free(v);

    return 0;
}

static struct array_list *xen_vm_list_available_tids(struct target *target) {
    struct array_list *retval;
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;

    /*
     * If we are tracking threads, we don't have scan the list!
     */
    if ((target->active_probe_flags & ACTIVE_PROBE_FLAG_THREAD_ENTRY)
	&& (target->active_probe_flags & ACTIVE_PROBE_FLAG_THREAD_EXIT)) {
	vdebug(8,LA_TARGET,LF_XV,
	       "active probing thread entry/exit, so just reloading cache!\n");
	return target_list_tids(target);
    }

    /* Try to be smart about the size of the list we create. */
    if (xstate->last_thread_count)
	retval = array_list_create((xstate->last_thread_count + 16) & ~15);
    else
	retval = array_list_create(64);

    if (linux_list_for_each_struct(target,xstate->init_task,"tasks",0,
				   __value_get_append_tid,retval)) {
	verror("could not load all tids in task list (did %d tasks)\n",
	       array_list_len(retval));
	array_list_free(retval);
	return NULL;
    }

    xstate->last_thread_count = array_list_len(retval);

    vdebug(5,LA_TARGET,LF_XV | LF_THREAD,"%d current threads\n",
	   xstate->last_thread_count);

    return retval;
}

static int xen_vm_load_all_threads(struct target *target,int force) {
    struct array_list *cthreads;
    int rc = 0;
    int i;
    struct target_thread *tthread;

    cthreads = target_list_threads(target);

    for (i = 0; i < array_list_len(cthreads); ++i) {
	tthread = (struct target_thread *)array_list_item(cthreads,i);

	vdebug(8,LA_TARGET,LF_XV,
	       "tid %"PRIiTID" (%p)\n",tthread->tid,tthread);

	if (!xen_vm_load_thread(target,tthread->tid,force)) {
	    if (target_lookup_thread(target,tthread->tid)) {
		verror("could not load thread %"PRIiTID"\n",tthread->tid);
		--rc;
		continue;
	    }
	    /*
	     * If it's no longer in the cache, we evicted it because it
	     * no longer exists... so this is not an error.
	     */
	}
    }

    return rc;
}

static int __value_load_thread(struct target *target,struct value *value,
			       void *data) {
    struct target_thread *tthread;
    int *load_counter = (int *)data;

    if (!(tthread = __xen_vm_load_thread_from_value(target,value))) {
	verror("could not load thread from task value; BUG?\n");
	value_free(value);
	return -1;
    }

    if (vdebug_is_on(8,LA_TARGET,LF_XV)) {
	char buf[512];
	target_thread_tostring(target,tthread->tid,1,buf,sizeof(buf));
	vdebug(8,LA_TARGET,LF_XV,
	       "loaded tid %d:%s (%s)\n",tthread->tid,tthread->name,buf);
    }

    if (load_counter)
	++*load_counter;

    return 0;
}

static int xen_vm_load_available_threads(struct target *target,int force) {
    int rc = 0;
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;
    int i = 0;
    struct array_list *cthreads;
    struct target_thread *tthread;

    /*
     * Load the current thread first to load the global thread.  The
     * current thread will get loaded again in the loop below if @force
     * is set...
     */
    if (!__xen_vm_load_current_thread(target,force,1)) {
	verror("could not load current thread!\n");
	rc = -1;
    }

    /*
     * If we are tracking threads, we don't have scan the list!
     */
    if ((target->active_probe_flags & ACTIVE_PROBE_FLAG_THREAD_ENTRY)
	&& (target->active_probe_flags & ACTIVE_PROBE_FLAG_THREAD_EXIT)) {
	vdebug(8,LA_TARGET,LF_XV,
	       "active probing thread entry/exit, so just reloading cache!\n");
	return xen_vm_load_all_threads(target,force);
    }

    if (linux_list_for_each_struct(target,xstate->init_task,"tasks",1,
				   __value_load_thread,&i)) {
	verror("could not load all threads in task list (did %d tasks)\n",i);
	rc = -1;
    }
    /*
     * If there are still any invalid threads, they are no longer live
     * -- so delete them!
     */
    else {
	cthreads = target_list_threads(target);
	for (i = 0; i < array_list_len(cthreads); ++i) {
	    tthread = (struct target_thread *)array_list_item(cthreads,i);
	    if (!tthread->valid) {
		vdebug(5,LA_TARGET,LF_XV | LF_THREAD,
		       "evicting invalid thread %"PRIiTID"; no longer exists\n",
		       tthread->tid);
		target_add_state_change(target,tthread->tid,
					TARGET_STATE_CHANGE_THREAD_EXITED,
					0,0,0,0,NULL);
		target_delete_thread(target,tthread,0);
	    }
	}
	array_list_free(cthreads);
    }

    return rc;
}

static char *xen_vm_thread_tostring(struct target *target,tid_t tid,int detail,
				    char *buf,int bufsiz) {
    struct target_thread *tthread;
    struct xen_vm_thread_state *tstate;
    struct cpu_user_regs *r;

    if (!(tthread = target_lookup_thread(target,tid))) {
	verror("thread %"PRIiTID" does not exist?\n",tid);
	return NULL;
    }
    tstate = (struct xen_vm_thread_state *)tthread->state;
    r = &tstate->context.user_regs;

    if (!buf) {
	if (target->wordsize == 8)
	    bufsiz = 1024;
	else
	    bufsiz = 512;
	buf = malloc(sizeof(char)*bufsiz);
    }

    if (detail < 1)
	snprintf(buf,bufsiz,
		 "ip=%"RF" bp=%"RF" sp=%"RF" flags=%"RF
		 " ax=%"RF" bx=%"RF" cx=%"RF" dx=%"RF" di=%"RF" si=%"RF
		 " cs=%d ss=%d ds=%d es=%d fs=%d gs=%d"
		 " dr0=%"DRF" dr1=%"DRF" dr2=%"DRF" dr3=%"DRF" dr6=%"DRF" dr7=%"DRF
		 "\n\t(tgid=%"PRIiNUM",task_flags=0x%"PRIxNUM","
		 "thread_info_flags=0x%"PRIxNUM",stack_base=0x%"PRIxADDR","
		 "pgd=0x%"PRIx64")",
#if __WORDSIZE == 64
		 r->rip,r->rbp,r->rsp,r->eflags,
		 r->rax,r->rbx,r->rcx,r->rdx,r->rdi,r->rsi,
		 r->cs,r->ss,r->ds,r->es,r->fs,r->gs,
#else
		 r->eip,r->ebp,r->esp,r->eflags,
		 r->eax,r->ebx,r->ecx,r->edx,r->edi,r->esi,
		 r->cs,r->ss,r->ds,r->es,r->fs,r->gs,
#endif
		 tstate->dr[0],tstate->dr[1],tstate->dr[2],tstate->dr[3],
		 tstate->dr[6],tstate->dr[7],
		 tstate->tgid,tstate->task_flags,tstate->thread_info_flags,
		 tstate->stack_base,tstate->pgd);
    else 
	snprintf(buf,bufsiz,
		 "ip=%"RF" bp=%"RF" sp=%"RF" flags=%"RF
		 " ax=%"RF" bx=%"RF" cx=%"RF" dx=%"RF" di=%"RF" si=%"RF"\n"
		 " cs=%d ss=%d ds=%d es=%d fs=%d gs=%d\n"
		 " dr0=%"DRF" dr1=%"DRF" dr2=%"DRF" dr3=%"DRF" dr6=%"DRF" dr7=%"DRF
		 "\n\t(tgid=%"PRIiNUM",task_flags=0x%"PRIxNUM","
		 "thread_info_flags=0x%"PRIxNUM",stack_base=0x%"PRIxADDR","
		 "pgd=0x%"PRIx64")",
#if __WORDSIZE == 64
		 r->rip,r->rbp,r->rsp,r->eflags,
		 r->rax,r->rbx,r->rcx,r->rdx,r->rdi,r->rsi,
		 r->cs,r->ss,r->ds,r->es,r->fs,r->gs,
#else
		 r->eip,r->ebp,r->esp,r->eflags,
		 r->eax,r->ebx,r->ecx,r->edx,r->edi,r->esi,
		 r->cs,r->ss,r->ds,r->es,r->fs,r->gs,
#endif
		 tstate->dr[0],tstate->dr[1],tstate->dr[2],tstate->dr[3],
		 tstate->dr[6],tstate->dr[7],
		 tstate->tgid,tstate->task_flags,tstate->thread_info_flags,
		 tstate->stack_base,tstate->pgd);

    return buf;
}

static int xen_vm_invalidate_all_threads(struct target *target) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;
    GHashTableIter iter;
    struct target_thread *tthread;
    struct xen_vm_thread_state *tstate;

    vdebug(5,LA_TARGET,LF_XV,"dom %d\n",xstate->id);

    g_hash_table_iter_init(&iter,target->threads);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer)&tthread)) {
	tstate = (struct xen_vm_thread_state *)tthread->state;

	//if (!tthread->valid) 
	//    continue;

	if (tstate->thread_struct) {
	    value_free(tstate->thread_struct);
	    tstate->thread_struct = NULL;
	}
	if (tstate->thread_info) {
	    value_free(tstate->thread_info);
	    tstate->thread_info = NULL;
	}
	if (tstate->task_struct) {
	    value_free(tstate->task_struct);
	    tstate->task_struct = NULL;
	}

	tthread->valid = 0;
    }

    return 0;
}

static int __xen_vm_resume(struct target *target,int detaching) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;
    int rc;

    vdebug(5,LA_TARGET,LF_XV,"dom %d\n",xstate->id);

    if (xen_vm_load_dominfo(target)) 
	vwarn("could not load dominfo for dom %d, trying to pause anyway!\n",xstate->id);

    if (!xstate->dominfo.paused) {
	vwarn("dom %d not paused; not invalidating and resuming; bug?\n",
	      xstate->id);
	return -1;
    }

    /*
     * Only call this if we have threads still, or we are not detaching;
     * if we're detaching and the target_api has already deleted our
     * threads, flush_all_threads will end up loading at least the
     * global thread... which is counterproductive.
     */
    if (!detaching 
	|| g_hash_table_size(target->threads) || target->global_thread) {
	/* Flush back registers if they're dirty! */
	xen_vm_flush_all_threads(target);

	/* Invalidate our cached copies of threads. */
	xen_vm_invalidate_all_threads(target);
    }

    /* flush_context will not have done this necessarily! */
    xstate->dominfo_valid = 0;

    rc = xc_domain_unpause(xc_handle,xstate->id);

    target_set_status(target,TSTATUS_RUNNING);

    return rc;
}

static int xen_vm_resume(struct target *target) {
    return __xen_vm_resume(target,0);
}

struct __update_module_data {
    struct addrspace *space;
    struct memregion *region;
    GHashTable *moddep;
    GHashTable *config;
};

static int __update_module(struct target *target,struct value *value,void *data) {
    struct value *mod_name = NULL;
    struct value *vt = NULL;
    ADDR mod_core_addr;
    ADDR mod_init_addr;
    unum_t mod_core_size;
    unum_t mod_init_size;
    struct __update_module_data *ud = (struct __update_module_data *)data;
    struct list_head *pos;
    struct memregion *tregion = NULL;
    struct memrange *range;
    char *modfilename;
    int retval;
    struct binfile_instance *bfi = NULL;
    struct debugfile *debugfile = NULL;
    struct addrspace *space = ud->space;

    if (!ud) {
	errno = EINVAL;
	return -1;
    }

    mod_name = target_load_value_member(target,value,"name",NULL,
					LOAD_FLAG_NONE);
    if (!mod_name) {
	verror("could not load name for module!\n");
	goto errout;
    }

    vt = target_load_value_member(target,value,"module_core",NULL,
				     LOAD_FLAG_NONE);
    if (!vt) {
	verror("could not load module_core addr!\n");
	goto errout;
    }
    mod_core_addr = v_addr(vt);
    value_free(vt);

    vt = target_load_value_member(target,value,"module_init",NULL,
				     LOAD_FLAG_NONE);
    if (!vt) {
	verror("could not load module_init addr!\n");
	goto errout;
    }
    mod_init_addr = v_addr(vt);
    value_free(vt);

    vt = target_load_value_member(target,value,"core_size",NULL,
				     LOAD_FLAG_NONE);
    if (!vt) {
	verror("could not load module core_size!\n");
	goto errout;
    }
    mod_core_size = v_unum(vt);
    value_free(vt);

    vt = target_load_value_member(target,value,"init_size",NULL,
				     LOAD_FLAG_NONE);
    if (!vt) {
	verror("could not load module init_size!\n");
	goto errout;
    }
    mod_init_size = v_unum(vt);
    value_free(vt);

    vdebug(2,LA_TARGET,LF_XV,
	   "module %s (core=0x%"PRIxADDR"(%u),init=0x%"PRIxADDR"(%u))\n",
	   v_string(mod_name),mod_core_addr,(unsigned)mod_core_size,
	   mod_init_addr,(unsigned)mod_init_size);

    modfilename = g_hash_table_lookup(ud->moddep,v_string(mod_name));
    if (!modfilename) {
	retval = -1;
	goto errout;
    }

    list_for_each(pos,&space->regions) {
	tregion = list_entry(pos,typeof(*tregion),region);
	if (strcmp(tregion->name,modfilename) == 0) {
	    if (tregion->base_load_addr == mod_core_addr)
		break;
	}
	tregion = NULL;
    }

    if (tregion) {
	tregion->exists = 1;
    }
    else {
	/*
	 * Create a new one!  Anything could have happened.
	 */
	tregion = memregion_create(ud->space,REGION_TYPE_LIB,
				   strdup(modfilename));
	tregion->new = 1;

	/*
	 * Create a new range for the region.
	 */
	range = memrange_create(tregion,mod_core_addr,
				mod_core_addr + mod_core_size,0,0);

	/*
	 * Load its debuginfo.
	 */
	bfi = binfile_infer_instance(tregion->name,
				     target->spec->debugfile_root_prefix,
				     mod_core_addr,target->config);
	if (!bfi) {
	    verror("could not infer instance for module %s!\n",tregion->name);
	    retval = -1;
	    goto errout;
	}

	debugfile = 
	    debugfile_from_instance(bfi,target->spec->debugfile_load_opts_list);
	if (!debugfile) {
	    retval = -1;
	    goto errout;
	}

	if (target_associate_debugfile(target,tregion,debugfile)) {
	    retval = -1;
	    goto errout;
	}
    }

    ud->region = tregion;
    retval = 0;

    if (mod_name)
	value_free(mod_name);

    return retval;

 errout:
    if (mod_name)
	value_free(mod_name);
    if (debugfile)
	debugfile_release(debugfile);
    if (bfi)
	binfile_instance_free(bfi);
    if (tregion)
	memregion_free(tregion);

    return retval;
}

static int xen_vm_reload_modules_dep(struct target *target) {
    struct xen_vm_state *xstate = \
	(struct xen_vm_state *)target->state;
    GHashTable *moddep = NULL;
    FILE *moddep_file;
    char moddep_path[PATH_MAX];
    char buf[PATH_MAX * 2];
    char *colon;
    char *slash;
    char *newline;
    char *extension;
    char *modname;
    char *modfilename;
    struct stat statbuf;
    time_t moddep_mtime;

    snprintf(moddep_path,PATH_MAX,"%s/modules.dep",xstate->kernel_module_dir);

    /*
     * Stat it and see if our cached copy (if there is one) is still
     * valid.
     */
    if (stat(moddep_path,&statbuf)) {
	verror("stat(%s): %s; aborting!\n",moddep_path,strerror(errno));
	return -1;
    }
    moddep_mtime = statbuf.st_mtime;

    if (xstate->moddep && xstate->last_moddep_mtime == moddep_mtime) {
	vdebug(16,LA_TARGET,LF_XV,
	       "cached moddep is valid\n");
	return 0;
    }

    /*
     * Read the current modules.dep file and build up the name->file map.
     */
    if (!(moddep_file = fopen(moddep_path,"r"))) {
	verror("fopen(%s): %s\n",moddep_path,strerror(errno));
	return -1;
    }

    moddep = g_hash_table_new_full(g_str_hash,g_str_equal,free,free);

    while (fgets(buf,sizeof(buf),moddep_file)) {
	newline = index(buf,'\n');

	/*
	 * Find lines starting with "<module_filename>:", and split them
	 * into a map of <module_name> -> <module_filename>
	 */
	if (!(colon = index(buf,':'))) 
	    goto drain;

	*colon = '\0';
	if (!(slash = rindex(buf,'/'))) 
	    goto drain;

	/* Check relative and abs paths. */
	modfilename = strdup(buf);
	if (stat(modfilename,&statbuf)) {
	    vwarnopt(8,LA_TARGET,LF_XV,
		     "could not find modules.dep file %s; trying abs path\n",
		     modfilename);
	    free(modfilename);

	    modfilename = calloc(1,sizeof(char)*(strlen(xstate->kernel_module_dir)
						 +1+strlen(buf)+1));
	    sprintf(modfilename,"%s/%s",xstate->kernel_module_dir,buf);
	    if (stat(modfilename,&statbuf)) {
		vwarnopt(7,LA_TARGET,LF_XV,
			 "could not find modules.dep file %s at all!\n",
			 modfilename);
		free(modfilename);
		modfilename = NULL;
		goto drain;
	    }
	}
	/* If we have one, insert it. */
	if (modfilename) {
	    modname = strdup(slash+1);
	    if ((extension = rindex(modname,'.')))
		*extension = '\0';

	    g_hash_table_insert(moddep,modname,modfilename);

	    vdebug(8,LA_TARGET,LF_XV,
		   "modules.dep: %s -> %s\n",modname,modfilename);
	}

	/*
	 * Drain until we get a newline.
	 */
    drain:
	if (!newline) {
	    while (fgets(buf,sizeof(buf),moddep_file)) {
		if (index(buf,'\n'))
		    break;
	    }
	}
    }
    fclose(moddep_file);

    /*
     * Update our cache.
     */
    if (xstate->moddep)
	g_hash_table_destroy(xstate->moddep);
    xstate->moddep = moddep;
    xstate->last_moddep_mtime = moddep_mtime;

    vdebug(5,LA_TARGET,LF_XV,
	   "updated modules.dep cache (%d entries from %s)\n",
	   g_hash_table_size(xstate->moddep),moddep_path);

    return 0;
}

/*
 * Only called if active memory probing is disabled, or if it fails.
 */
static int xen_vm_updateregions(struct target *target,
				struct addrspace *space) {
    struct xen_vm_state *xstate = \
	(struct xen_vm_state *)target->state;
    struct __update_module_data ud;
    struct memregion *region,*tregion;
    struct memrange *range,*trange;

    vdebug(5,LA_TARGET,LF_XV,"dom %d\n",xstate->id);

    /*
     * We never update the main kernel region.  Instead, we update the
     * module subregions as needed.
     *
     * XXX: in this first version, we don't worry about module init
     * sections that can be removed after the kernel initializes the
     * module.
     */

    if (!xstate->module_type || !xstate->modules || !xstate->kernel_module_dir) {
	/*	
	 * Don't return an error; would upset target_open.
	 */
	return 0;
    }

    if (xen_vm_reload_modules_dep(target)) 
	verror("failed to reload modules.dep; trying to continue!\n");

    ud.space = space;
    ud.moddep = xstate->moddep;

    /*
     * Clear out the current modules region bits.
     *
     * We don't bother checking ranges.  No need.
     */
    list_for_each_entry(region,&space->regions,region) {
	if (region->type == REGION_TYPE_LIB) {
	    region->exists = 0;
	    region->new = 0;
	}
    }

    /*
     * Handle the modules via callback via iterator.
     */
    linux_list_for_each_entry(target,xstate->module_type,xstate->modules,"list",0,
			      __update_module,&ud);

    /*
     * Now, for all the regions, check if they were newly added
     * or still exist; if none of those, then they vanished
     * and we have to purge them.
     */

    list_for_each_entry_safe(region,tregion,&space->regions,region) {
	/* Skip anything not a kernel module. */
	if (region->type != REGION_TYPE_LIB)
	    continue;

	if (!region->exists && !region->new) {
	    list_for_each_entry_safe(range,trange,&region->ranges,range) {
		vdebug(3,LA_TARGET,LF_XV,
		       "removing stale range 0x%"PRIxADDR"-0x%"PRIxADDR":%"PRIiOFFSET"\n",
		       range->start,range->end,range->offset);

		target_add_state_change(target,TID_GLOBAL,
					TARGET_STATE_CHANGE_RANGE_DEL,
					0,range->prot_flags,
					range->start,range->end,region->name);
		memrange_free(range);
	    }

	    vdebug(3,LA_TARGET,LF_XV,"removing stale region (%s:%s:%s)\n",
		   region->space->idstr,region->name,REGION_TYPE(region->type));

	    target_add_state_change(target,TID_GLOBAL,
				    TARGET_STATE_CHANGE_REGION_DEL,
				    0,0,region->base_load_addr,0,region->name);
	    memregion_free(region);
	}
	else if (region->new) {
	    list_for_each_entry_safe(range,trange,&region->ranges,range) {
		vdebug(3,LA_TARGET,LF_LUP,
		       "new range 0x%"PRIxADDR"-0x%"PRIxADDR":%"PRIiOFFSET"\n",
		       range->start,range->end,range->offset);

		target_add_state_change(target,TID_GLOBAL,
					TARGET_STATE_CHANGE_RANGE_NEW,
					0,range->prot_flags,
					range->start,range->end,region->name);
	    }

	    target_add_state_change(target,TID_GLOBAL,
				    TARGET_STATE_CHANGE_REGION_NEW,
				    0,0,region->base_load_addr,0,region->name);
	}

	region->new = region->exists = 0;
    }

    return 0;
}

static result_t xen_vm_active_memory_handler(struct probe *probe,
					     void *handler_data,
					     struct probe *trigger) {
    struct target *target;
    struct xen_vm_state *xstate;
    struct value *mod = NULL;
    struct addrspace *space;
    int state = -1;
    struct __update_module_data ud;
    char *modfilename;
    struct list_head *pos;
    struct memregion *region;
    struct memrange *range,*trange;
    char *name;
    struct value *name_value = NULL;

    target = probe->target;
    xstate = (struct xen_vm_state *)target->state;
    space = list_entry(target->spaces.next,typeof(*space),space);

    /*
     * For kernels that have do_init_module(), we can simply place a
     * probe on the entry of that function.  If we cannot read the first
     * arg, the module is already on the list, so just scan the list
     * manually.
     *
     * For older kernels, it is not as good.  We cannot catch the
     * incoming module once it is guaranteed to be on the list UNLESS we
     * use return probes on one of a few functions (__link_module would
     * work), but that requires disasm, which we want to avoid.
     *
     * So -- the only strategy that works for all kernels is to place a
     * probe on module_free(), and look at both the addr being freed,
     * and the module->state field.  If ->state is MODULE_STATE_LIVE,
     * we know the module is new.  If mod->state is MODULE_STATE_GOING,
     * we know the module is being removed (or failed to initialize).
     * If mod->state is MODULE_STATE_COMING, we know the module failed
     * to initialize.
     *
     * This way, if we fail to load module_free's mod arg -- we can just
     * rescan the list.  By the time this function is called, whether
     * the module is coming or going, the module is either on the list
     * or off it.
     *
     * NB: module_free is called multiple times per module (for the
     * init_text section, and the core_text section).  So, we just
     * handle those cases and ignore them.
     *
     *   NB: we *could* utilize this to track the presence/absence of
     *   the init_text section too; but we don't for now.
     */

    /*
     * Load mod.
     */
    mod = target_load_symbol(target,TID_GLOBAL,
			     xstate->module_free_mod_symbol,
			     LOAD_FLAG_AUTO_DEREF);
    if (!mod) {
	/*
	 * Again, the module is either on the list if it's coming; or
	 * off the list if it's going.  By the time module_free is
	 * called, its state is known based on whether it is on the list
	 * or off the list.
	 *
	 * So, it is safe to manually update regions.
	 */
	vwarn("could not load mod in module_free; manually updating"
	      " modules!\n");
	goto manual_update;
    }

    /*
     * Load mod->state, so we know what is happening.
     */
    VLV(target,mod,"state",LOAD_FLAG_NONE,&state,NULL,err_vmiload_state);

    /*
     * Update modules.dep, just in case; don't worry if it fails, just
     * do our best.
     */
    xen_vm_reload_modules_dep(target);

    if (state == xstate->MODULE_STATE_LIVE) {
	ud.space = space;
	ud.moddep = xstate->moddep;

	__update_module(target,mod,&ud);
	region = ud.region;

	list_for_each_entry_safe(range,trange,&region->ranges,range) {
	    vdebug(3,LA_TARGET,LF_LUP,
		   "new range 0x%"PRIxADDR"-0x%"PRIxADDR":%"PRIiOFFSET"\n",
		   range->start,range->end,range->offset);

	    target_add_state_change(target,TID_GLOBAL,
				    TARGET_STATE_CHANGE_RANGE_NEW,
				    0,range->prot_flags,
				    range->start,range->end,region->name);
	}

	target_add_state_change(target,TID_GLOBAL,
				TARGET_STATE_CHANGE_REGION_NEW,
				0,0,region->base_load_addr,0,region->name);
    }
    else if (state == xstate->MODULE_STATE_COMING
	     || state == xstate->MODULE_STATE_GOING) {
	/*
	 * Look up and destroy it if it's one of our regions.
	 */
	VLV(target,mod,"name",LOAD_FLAG_AUTO_STRING,NULL,&name_value,
	    err_vmiload_name);
	name = v_string(name_value);

	modfilename = g_hash_table_lookup(xstate->moddep,name);
	if (!modfilename) {
	    verror("could not find modfilename for module '%s'; aborting to"
		   " manual update!\n",
		   name);
	    goto manual_update;
	}

	list_for_each(pos,&space->regions) {
	    region = list_entry(pos,typeof(*region),region);
	    if (strcmp(region->name,modfilename) == 0) 
		break;
	    region = NULL;
	}

	if (region) {
	    list_for_each_entry_safe(range,trange,&region->ranges,range) {
		vdebug(3,LA_TARGET,LF_XV,
		       "removing stale range 0x%"PRIxADDR"-0x%"PRIxADDR":%"PRIiOFFSET"\n",
		       range->start,range->end,range->offset);

		target_add_state_change(target,TID_GLOBAL,
					TARGET_STATE_CHANGE_RANGE_DEL,
					0,range->prot_flags,
					range->start,range->end,region->name);
		memrange_free(range);
	    }

	    vdebug(3,LA_TARGET,LF_XV,"removing stale region (%s:%s:%s)\n",
		   region->space->idstr,region->name,REGION_TYPE(region->type));

	    target_add_state_change(target,TID_GLOBAL,
				    TARGET_STATE_CHANGE_REGION_DEL,
				    0,0,region->base_load_addr,0,region->name);
	    memregion_free(region);
	}
	else {
	    vdebug(5,LA_TARGET,LF_XV,
		   "ignoring untracked departing module '%s'\n",name);
	}
    }
    else {
	verror("unexpected module state %d; reverting to manual update!\n",state);
	goto manual_update;
    }

    if (name_value)
	value_free(name_value);
    if (mod)
	value_free(mod);

    return RESULT_SUCCESS;

 err_vmiload_state:
    verror("could not load mod->state; aborting to manual update!\n");
    goto manual_update;

 err_vmiload_name:
    verror("could not load mod->name for departing module; aborting to manual"
	   " update!\n");
    goto manual_update;

 manual_update:
    if (name_value)
	value_free(name_value);
    if (mod)
	value_free(mod);

    if (xen_vm_updateregions(target,space)) {
	verror("manual module update failed; regions may be wrong!\n");
	return RESULT_ERROR;
    }

    return RESULT_SUCCESS;
}

/*
 * NB: this was hard!
 *
 * It is very, very hard to find an available function to place a probe
 * on, that is not either optimized out of existence (well, it may
 * exist, but either the instances are not available or the parameters
 * have no locations at the inlined site).
 *
 * And we really want to try hard to only probe *after* (but very near
 * to) the place where the task is placed on the tasks list; this way,
 * if we fail to read the new task out of target memory, we can abort to
 * scanning the task list.  I guess that doesn't matter so much though.
 * Anyway, the list add happens in copy_process, so that is our target.
 *
 * I worked very hard to avoid requiring disasm support (so that I could
 * register probes on the RETs from copy_process); but ultimately I
 * could not manage it.  proc_fork_connector() is the only
 * copy_process()-specific hook just before the success RET in
 * copy_process.  We could also have caught the increment of total_forks
 * via watchpoint, but I want to avoid wasting a watchpoint if I can!
 *
 * I tried to catch proc_fork_connector() inside copy_process() (but of
 * course, silly me, that is only really defined if CONFIG_CONNECTOR;
 * otherwise it's just declared) because it is the last "hook" in
 * copy_process; by that time, we know that the new task is on the tasks
 * list.
 *
 * Another option might have been to catch the new task just after the
 * invocations of copy_process() in fork_idle() or do_fork(); but this
 * would basically require us to use debuginfo variable availability
 * (when does the `task' local var in those functions become
 * available!), and then place a probe on that exact location.  But, of
 * course that doesn't work; you have no idea what code is where, or the
 * debuginfo might be wrong/incomplete.
 *
 * So -- the best options all involve requiring disasm support.  Once we
 * have this, the easiest thing to do is catch the RETs in copy_process;
 * if the local var 'p' is !IS_ERR(), we know we have a new task.  If we
 * fail to load memory, or something goes wrong, we can fall back to
 * manually walking the task list.
 */
static result_t xen_vm_active_thread_entry_handler(struct probe *probe,
						   void *handler_data,
						   struct probe *trigger) {
    struct target *target = probe->target;
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;
    struct target_thread *tthread;
    struct value *value;

    /*
     * Load task.
     */
    value = target_load_symbol(target,TID_GLOBAL,
			       xstate->thread_entry_v_symbol,
			       LOAD_FLAG_AUTO_DEREF);
    if (!value) {
	/*
	 * This target does not require thread entry tracking; so ignore
	 * it.  We just load threads as they appear; it's stale threads
	 * we really prefer to avoid -- or for overlay targets, we need
	 * to know when a overlay thread disappears.
	 */
	vwarn("could not load %s in %s; ignoring new thread!\n",
	      bsymbol_get_name(xstate->thread_entry_v_symbol),
	      bsymbol_get_name(xstate->thread_entry_f_symbol));
	return RESULT_ERROR;
    }

    if (!(tthread = __xen_vm_load_thread_from_value(target,value))) {
	verror("could not load thread from task value; BUG?\n");
	value_free(value);
	return RESULT_ERROR;
    }

    vdebug(5,LA_TARGET,LF_XV,
	   "new task %"PRIiTID" (%s)\n",tthread->tid,tthread->name);

    return RESULT_SUCCESS;
}

/*
 * NB: this was hard!
 *
 * It is very, very hard to find an available function to place a probe
 * on, that is not either optimized out of existence (well, it may
 * exist, but either the instances are not available or the parameters
 * have no locations at the inlined site).  __unhash_process, the
 * function that takes the pid off the list, is the ideal place, but
 * that doesn't work.  release_task also does not work, but that is
 * because it contains a loop that reaps zombie group leaders (if they
 * exist) -- so we would miss some zombies.  Thus we are left with
 * sched_exit, which is (unfortunately) well after the process is off
 * the task list.  BUT -- every exiting task hits it.  Another
 * alternative (of course) is to probe inside of schedule(), but that is
 * tricky because it adds tons of unnecessary overhead,
 *
 * Of course, then the problem becomes that in release_task, the task IS
 * exiting, but it is still running on its kernel stack (at least when
 * called from the normal do_exit() exit path; this means that although
 * we want to delete our thread, we cannot delete it because it may
 * "reappear".
 *
 * One strategy, for kernels that do NOT support CONFIG_PREEMPT, is to
 * mark the thread "exiting", and when the next debug exception hits,
 * clear out any such threads if the exception is not for one of them!
 * Why does this work?  An exiting task will simply not be preempted
 * until it calls schedule().
 *
 * For kernels that do support CONFIG_PREEMPT, the only "safe" places to
 * *know* that a task is exiting, but preemption has been disabled, is
 * the call to preempt_disable() inside do_exit().  And we can't catch
 * that -- it is really just a write to a field in the task struct,
 * followed by an MFENCE instruction (on x86).  So, we really have to
 * catch the call to schedule() inside do_exit() -- or the call to
 * release_task() inside wait_task_zombie().  This makes sure we catch
 * all the paths leading to release_task().
 *
 * NB: therefore, this version does not support CONFIG_PREEMPT very well
 * -- it could be racy.  We need support for placing probes on function
 * invocations; this requires disasm support.
 */
static result_t xen_vm_active_thread_exit_handler(struct probe *probe,
						  void *handler_data,
						  struct probe *trigger) {
    struct target *target = probe->target;
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;
    struct target_thread *tthread;
    struct xen_vm_thread_state *xtstate;
    struct value *value;

    /*
     * Load task.
     */
    value = target_load_symbol(target,TID_GLOBAL,xstate->thread_exit_v_symbol,
			       LOAD_FLAG_AUTO_DEREF);
    if (!value) {
	/*
	 * We need avoid stale threads for overlay targets; we need to
	 * know when a overlay thread disappears.
	 */
	vwarn("could not load %s in %s; ignoring new thread!\n",
	      bsymbol_get_name(xstate->thread_exit_v_symbol),
	      bsymbol_get_name(xstate->thread_exit_f_symbol));
	return RESULT_ERROR;
    }

    if (!(tthread = __xen_vm_load_thread_from_value(target,value))) {
	verror("could not load thread from task value; BUG?\n");
	value_free(value);
	return RESULT_ERROR;
    }

    xtstate = (struct xen_vm_thread_state *)tthread->state;

    xtstate->exiting = 1;

    vdebug(5,LA_TARGET,LF_XV,
	   "exiting task %"PRIiTID" (%s)\n",tthread->tid,tthread->name);

    return RESULT_SUCCESS;
}

/*
 * If again is not NULL, we set again
 *   to -1 if there was an error, but we should try again;
 *   to 0 if not again;
 *   to 1 if just handled a bp and should try again;
 *   to 2 if just handled an ss and should try again.
 */
static target_status_t xen_vm_handle_internal(struct target *target,
					      int *again) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;
    REGVAL ipval;
    int dreg = -1;
    struct probepoint *dpp;
    struct target_thread *tthread;
    struct xen_vm_thread_state *gtstate;
    struct xen_vm_thread_state *xtstate;
    tid_t tid;
    struct probepoint *spp;
    struct target_thread *sstep_thread;
    struct addrspace *space;
    struct target_thread *bogus_sstep_thread;
    ADDR bogus_sstep_probepoint_addr;
    struct target *overlay;
    GHashTableIter iter;

#ifdef ENABLE_XENACCESS
    /* From previous */
    xa_destroy_cache(&xstate->xa_instance);
    xa_destroy_pid_cache(&xstate->xa_instance);
#endif
#ifdef ENABLE_LIBVMI
    /* XXX is this right? */
    vmi_v2pcache_flush(xstate->vmi_instance);
    vmi_symcache_flush(xstate->vmi_instance);
    vmi_pidcache_flush(xstate->vmi_instance);
#endif

    /* Reload our dominfo */
    xstate->dominfo_valid = 0;
    if (xen_vm_load_dominfo(target)) {
	verror("could not load dominfo; returning to user!\n");
	goto out_err;
    }

    target_clear_state_changes(target);

    vdebug(3,LA_TARGET,LF_XV,
	   "new debug event (brctr = %"PRIu64", tsc = %"PRIx64")\n",
	   xen_vm_get_counter(target),xen_vm_get_tsc(target));

    target_set_status(target,TSTATUS_PAUSED);

    if (target_status(target) == TSTATUS_PAUSED) {
	/* Force the current thread to be reloaded. */
	target->current_thread = NULL;

	/*
	 * Grab EIP first so we can see if we're in user or kernel
	 * space.
	 */
	errno = 0;
	ipval = xen_vm_read_reg(target,TID_GLOBAL,target->ipregno);
	if (errno) {
	    verror("could not read EIP while checking debug event: %s\n",
		   strerror(errno));
	    goto out_err;
	}

	/*
	 * If not active probing memory, we kind of want to update our
	 * addrspaces aggressively (by checking the module list) so that
	 * if a user lookups a module symbol, we already have it.
	 *
	 * Active probing memory for the Xen target is a big win.
	 */
	if (!(target->active_probe_flags & ACTIVE_PROBE_FLAG_MEMORY)) {
	    list_for_each_entry(space,&target->spaces,space) {
		xen_vm_updateregions(target,space);
	    }
	}

	if (ipval < xstate->kernel_start_addr) {
	    if (!__xen_vm_load_current_thread(target,0,1)) {
		vdebug(3,LA_TARGET,LF_XV | LF_THREAD,
		       "user-mode debug event at EIP 0x%"PRIxADDR" in unknown tid;"
		       " will try to handle it if it is single step!\n",
		       ipval);
		verror("could not read current thread in user mode context!\n");
		goto out_err_again;
	    }
	    tthread = target->current_thread;
	    gtstate = (struct xen_vm_thread_state *) \
		target->global_thread->state;
	    xtstate = (struct xen_vm_thread_state *) \
		target->current_thread->state;
	    tid = target->current_thread->tid;
	    vdebug(3,LA_TARGET,LF_XV | LF_THREAD,
		   "user-mode debug event at EIP 0x%"PRIxADDR" in tid %"PRIiTID";"
		   " will try to handle it if it is single step!\n",
		   ipval,tid);
	}
	else {
	    /* 
	     * Reload the current thread.  We don't force it because we
	     * flush all threads before continuing the loop via again:,
	     * or in target_resume/target_singlestep.
	     */
	    xen_vm_load_current_thread(target,0);

	    /*
	     * If we are tracking thread exits, we have to nuke
	     * "exiting" threads.  See comments near
	     * xen_vm_active_thread_exit_handler .
	     */
	    if (target->active_probe_flags & ACTIVE_PROBE_FLAG_THREAD_EXIT) {
		g_hash_table_iter_init(&iter,target->threads);
		while (g_hash_table_iter_next(&iter,NULL,(gpointer *)&tthread)) {
		    xtstate = (struct xen_vm_thread_state *)tthread->state;

		    if (!xtstate->exiting) 
			continue;

		    if (tthread == target->current_thread) {
			vdebug(5,LA_TARGET,LF_XV,
			       "active-probed exiting thread %"PRIiTID" (%s)"
			       " is still running; not deleting yet!\n",
			       tthread->tid,tthread->name);
		    }
		    else {
			vdebug(5,LA_TARGET,LF_XV,
			       "active-probed exiting thread %"PRIiTID" (%s)"
			       " can be deleted; doing it\n",
			       tthread->tid,tthread->name);
			target_add_state_change(target,tthread->tid,
						TARGET_STATE_CHANGE_THREAD_EXITED,
						0,0,0,0,NULL);
			target_delete_thread(target,tthread,1);
			g_hash_table_iter_remove(&iter);
		    }
		}
	    }

	    /*
	     * First, we check the current thread's state/registers to
	     * try to handle the exception in the current thread.  If
	     * there is no information (and the current thread was not
	     * the global thread), we try the global thread.
	     */
	    if (!(tthread = target->current_thread)) {
		verror("could not read current thread!\n");
		goto out_err_again;
	    }

	    /*
	     * Next, if auto garbage collection is enabled, do it.
	     *
	     * We need to only do this every N interrupts, or something,
	     * but what we really want is something that is related to
	     * how many cycles have eclipsed in the target -- i.e., if
	     * more than one second's worth of wallclock time has
	     * elapsed in the target, we should garbage collect.
	     *
	     * But I don't know how to grab the current cycle counter
	     * off the top of my head, so just do it when we accumulate
	     * at least 32 threads.
	     */
	    if (g_hash_table_size(target->threads) > 32) {
		target_gc_threads(target);
	    }

	    gtstate = (struct xen_vm_thread_state *)target->global_thread->state;
	    xtstate = (struct xen_vm_thread_state *)tthread->state;
	    tid = tthread->tid;
	}

	vdebug(6,LA_TARGET,LF_XV,
	       "thread %d at EIP 0x%"PRIxADDR": "
	       "dbgreg[6]=0x%"DRF", eflags=0x%"RF"\n",
	       tid, ipval, xtstate->context.debugreg[6],
	       xtstate->context.user_regs.eflags);

	/* handle the triggered probe based on its event type */
	if (xtstate->context.debugreg[6] & 0x4000
	    || (xstate->hvm && xstate->hvm_monitor_trap_flag_set)) {
	    vdebug(3,LA_TARGET,LF_XV,"new single step debug event (MTF %d)\n",
		   xstate->hvm_monitor_trap_flag_set);

	    /*
	     * Two cases: either we single-stepped an instruction that
	     * could have taken us to a userspace EIP, or somehow the
	     * kernel jumped to one!  Either way, if we had been
	     * expecting this, try to handle it.
	     */
	    if (target->sstep_thread 
		&& ((target->sstep_thread->tpc
		     && target->sstep_thread->tpc->probepoint->can_switch_context)
		    || (ipval < xstate->kernel_start_addr
			&& !target->sstep_thread_overlay))) {
		sstep_thread = target->sstep_thread;
	    }
	    else if (target->sstep_thread
		     && ipval < xstate->kernel_start_addr
		     && target->sstep_thread_overlay) {
		vdebug(8,LA_TARGET,LF_XV,
		       "single step event in overlay tid %"PRIiTID
		       " (tgid %"PRIiTID"); notifying overlay\n",
		       tid,target->sstep_thread_overlay->base_tid);
		return target_notify_overlay(target->sstep_thread_overlay,
					     tid,ipval,again);
	    }
	    else
		sstep_thread = NULL;

	    target->sstep_thread = NULL;

	    if (xtstate->context.user_regs.eflags & EF_TF
		|| (xstate->hvm && xstate->hvm_monitor_trap_flag_set)) {
	    handle_inferred_sstep:
		if (!tthread->tpc) {
		    if (sstep_thread && ipval < xstate->kernel_start_addr) {
			vwarn("single step event (status reg and eflags) into"
			      " userspace; trying to handle in sstep thread"
			      " %"PRIiTID"!\n",sstep_thread->tid);
			goto handle_sstep_thread;
		    }
		    else {
			target->ss_handler(target,tthread,NULL);

			/* Clear the status bits right now. */
			xtstate->context.debugreg[6] = 0;
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
			gtstate->context.debugreg[6] = 0;
			target->global_thread->dirty = 1;
			vdebug(5,LA_TARGET,LF_XV,"cleared status debug reg 6\n");

			goto out_ss_again;
			/*
			verror("single step event (status reg and eflags), but"
			       " no handling context in thread %"PRIiTID"!"
			       "  letting user handle.\n",tthread->tid);
			goto out_paused;
			*/
		    }
		}
		    
		/* Save the currently hanlding probepoint;
		 * ss_handler may clear tpc.
		 */
		spp = tthread->tpc->probepoint;

		target->ss_handler(target,tthread,tthread->tpc->probepoint);

		/* Clear the status bits right now. */
		xtstate->context.debugreg[6] = 0;
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
		if (spp->style == PROBEPOINT_HW) {
		    gtstate->context.debugreg[6] = 0;
		    target->global_thread->dirty = 1;
		}
		vdebug(5,LA_TARGET,LF_XV,"cleared status debug reg 6\n");

		goto out_ss_again;
	    }
	    else if (sstep_thread) {
		vdebug(3,LA_TARGET,LF_XV | LF_THREAD,
		       "thread %"PRIiTID" single stepped can_context_switch"
		       " instr; trying to handle exception in old thread!\n",
		       sstep_thread->tid);

	    handle_sstep_thread:
		target->ss_handler(target,sstep_thread,
				   sstep_thread->tpc->probepoint);

		/* Clear the status bits right now. */
		xtstate->context.debugreg[6] = 0;
		tthread->dirty = 1;
		vdebug(5,LA_TARGET,LF_XV,"cleared status debug reg 6\n");

		goto out_ss_again;
	    }
	    else if (ipval < xstate->kernel_start_addr) {
		verror("user-mode debug event (single step) at 0x%"PRIxADDR
		       "; debug status reg 0x%"DRF"; eflags 0x%"RF
		       "; skipping handling!\n",
		       ipval,xtstate->context.debugreg[6],
		       xtstate->context.user_regs.eflags);
		goto out_err_again;
	    }
	    else {
		target->ss_handler(target,tthread,NULL);

		/* Clear the status bits right now. */
		xtstate->context.debugreg[6] = 0;
		tthread->dirty = 1;
		vdebug(5,LA_TARGET,LF_XV,"cleared status debug reg 6\n");

		goto out_ss_again;
	    }
	}
	else {
	    vdebug(3,LA_TARGET,LF_XV,"new (breakpoint?) debug event\n");
	    /*
	     * Some Xen kernels send us a debug event after a successful
	     * singlestep, but they do not set the right flag to notify
	     * us.  So, if the TF flag is set, and we were expecting a
	     * singlestep to happen, and there is not a breakpoint
	     * exception instead -- assume that it is a singlestep
	     * event.
	     *
	     * So, save it off in a special variable and handle below.
	     */
	    bogus_sstep_thread = target->sstep_thread;
	    target->sstep_thread = NULL;

	    dreg = -1;

	    /* Check the hw debug status reg first */

	    /* Only check the 4 low-order bits */
	    if (xtstate->context.debugreg[6] & 15) {
		if (xtstate->context.debugreg[6] & 0x1)
		    dreg = 0;
		else if (xtstate->context.debugreg[6] & 0x2)
		    dreg = 1;
		else if (xtstate->context.debugreg[6] & 0x4)
		    dreg = 2;
		else if (xtstate->context.debugreg[6] & 0x8)
		    dreg = 3;
	    }

	    /*
	     * More hypervisor bugs: some Xens don't appropriately
	     * signal us for hw debug exceptions, and leave a stale
	     * value in DR6.  So, even if the debugreg[6] status
	     * indicated that an HW debug reg was hit, check (if the HW
	     * debug reg is for a breakpoint) that EIP is the same as
	     * that debug reg!  If it is not, don't believe DR6, and
	     * look for soft breakpoints.
	     */
	    if (dreg > -1) {
		dpp = (struct probepoint *) \
		    g_hash_table_lookup(tthread->hard_probepoints,
					(gpointer)ipval);
		if (!dpp) {
		    dpp = (struct probepoint *) \
			g_hash_table_lookup(target->global_thread->hard_probepoints,
					    (gpointer)ipval);
		    if (!dpp) {
			verror("DR6 said hw dbg reg %d at 0x%"PRIxADDR" was hit;"
			       " but EIP 0x%"PRIxADDR" in tid %"PRIiTID" does not"
			       " match! ignoring hw dbg status; continuing"
			       " other checks!\n",
			       dreg,xtstate->context.debugreg[dreg],ipval,
			       tthread->tid);
			dreg = -1;

			/*
			 * Clear DR6 in global thread; it is clearly wrong!
			 *
			 * MUST DO THIS.  If we are going to modify both the
			 * current thread's CPU state possibly, and possibly
			 * operate on the global thread's CPU state, we need to
			 * clear the global thread's debug reg status here; this
			 * also has the important side effect of forcing a merge
			 * of the global thread's debug reg state; see
			 * flush_global_thread !
			 */
			gtstate->context.debugreg[6] = 0;
			target->global_thread->dirty = 1;
		    }
		}
	    }			    

	    if (dreg > -1) {
		if (ipval < xstate->kernel_start_addr) {
		    vwarn("user-mode debug event (hw dbg reg)"
			  " at 0x%"PRIxADDR"; debug status reg 0x%"DRF"; eflags"
			  " 0x%"RF"; trying to handle in global thread!\n",
			  ipval,xtstate->context.debugreg[6],
			  xtstate->context.user_regs.eflags);
		}

		/* If we are relying on the status reg to tell us,
		 * then also read the actual hw debug reg to get the
		 * address we broke on.
		 */
		errno = 0;
		ipval = xtstate->context.debugreg[dreg];

		vdebug(4,LA_TARGET,LF_XV,
		       "found hw break (status) in dreg %d on 0x%"PRIxADDR"\n",
		       dreg,ipval);
	    }
	    else if (ipval < xstate->kernel_start_addr) {
		overlay = target_lookup_overlay(target,tid);
		if (overlay) {
		    /*
		     * Try to notify the overlay!
		     */
		    vdebug(9,LA_TARGET,LF_XV,
			   "user-mode debug event in overlay tid %"PRIiTID
			   " (tgid %"PRIiTID") (not single step, not hw dbg reg)"
			   " at 0x%"PRIxADDR"; debug status reg 0x%"DRF"; eflags"
			   " 0x%"RF"; passing to overlay!\n",
			   tid,overlay->base_tid,ipval,
			   xtstate->context.debugreg[6],
			   xtstate->context.user_regs.eflags);
		    return target_notify_overlay(overlay,tid,ipval,again);
		}
		else {
		    verror("user-mode debug event (not single step, not hw dbg reg)"
			   " at 0x%"PRIxADDR"; debug status reg 0x%"DRF"; eflags"
			   " 0x%"RF"; skipping handling!\n",
			   ipval,xtstate->context.debugreg[6],
			   xtstate->context.user_regs.eflags);
		    goto out_err_again;
		}
	    }
	    else {
		vdebug(4,LA_TARGET,LF_XV,
		       "dreg status was 0x%"PRIxREGVAL"; trying eip method\n",
		       (ADDR)xtstate->context.debugreg[6]);

		if (xtstate->dr[0] == ipval)
		    dreg = 0;
		else if (xtstate->dr[1] == ipval)
		    dreg = 1;
		else if (xtstate->dr[2] == ipval)
		    dreg = 2;
		else if (xtstate->dr[3] == ipval)
		    dreg = 3;

		if (dreg > -1) 
		    vdebug(4,LA_TARGET,LF_XV,
			   "found hw break (eip) in dreg %d on 0x%"PRIxADDR"\n",
			   dreg,ipval);
		else {
		    if (xtstate != gtstate) {
			/*
			 * Check the global thread too; might be a
			 * global breakpoint/watchpoint.
			 */
			if (gtstate->dr[0] == ipval)
			    dreg = 0;
			else if (gtstate->dr[1] == ipval)
			    dreg = 1;
			else if (gtstate->dr[2] == ipval)
			    dreg = 2;
			else if (gtstate->dr[3] == ipval)
			    dreg = 3;

			if (dreg > -1) 
			    vdebug(4,LA_TARGET,LF_XV,
				   "found hw break (eip) in GLOBAL dreg %d on 0x%"PRIxADDR"\n",
				   dreg,ipval);
			else
			    vdebug(6,LA_TARGET,LF_XV,
				   "did NOT find hw break (eip) on 0x%"PRIxADDR
				   " (neither global nor per-thread!)\n",
				   ipval);
		    }
		    else {
			vdebug(6,LA_TARGET,LF_XV,
			       "did NOT find hw break (eip) on 0x%"PRIxADDR"\n",
			       ipval);
		    }
		}
	    }

	    if (dreg > -1) {
		/* Found HW breakpoint! */
		dpp = (struct probepoint *) \
		    g_hash_table_lookup(tthread->hard_probepoints,
					(gpointer)ipval);

		if (dpp) {
		    vdebug(4,LA_TARGET,LF_XV,
			   "found hw break in thread %"PRIiTID"\n",
			   tthread->tid);
		}
		else {
		    /* Check the global thread if not already checking it! */
		    dpp = (struct probepoint *) \
			g_hash_table_lookup(target->global_thread->hard_probepoints,
					    (gpointer)ipval);
		    if (!dpp) {
			verror("could not find probepoint for hw dbg reg %d"
			       " in current or global threads!\n",dreg);
			goto out_err;
		    }
		    else {
			vdebug(4,LA_TARGET,LF_XV,
			       "found hw break in global thread!\n");

			/*
			 * MUST DO THIS.  If we are going to modify both
			 * the current thread's CPU state possibly, and
			 * possibly operate on the global thread's CPU
			 * state, we need to clear the global thread's
			 * debug reg status here; this also has the
			 * important side effect of forcing a merge of
			 * the global thread's debug reg state; see
			 * flush_global_thread !
			 */
			gtstate->context.debugreg[6] = 0;
			target->global_thread->dirty = 1;
		    }			    
		}

		/* BEFORE we run the bp handler: 
		 *
		 * If the domain happens to be in singlestep mode, and
		 * we are hitting a breakpoint anyway... we have to
		 * handle the breakpoint, singlestep ourselves, AND
		 * THEN leave the processor in single step mode.
		 */
		if (0 && xtstate->context.user_regs.eflags & EF_TF) {
		    //target->sstep_leave_enabled = 1;
		}

		/* Run the breakpoint handler. */
		target->bp_handler(target,tthread,dpp,
				   xtstate->context.debugreg[6] & 0x4000);

		/* Clear the status bits right now. */
		xtstate->context.debugreg[6] = 0;
		tthread->dirty = 1;
		vdebug(5,LA_TARGET,LF_XV,"cleared status debug reg 6\n");

		goto out_bp_again;
	    }
	    else if ((dpp = (struct probepoint *) \
		      g_hash_table_lookup(target->soft_probepoints,
					  (gpointer)(ipval - target->breakpoint_instrs_len)))) {
		/* Run the breakpoint handler. */
		target->bp_handler(target,tthread,dpp,
				   xtstate->context.debugreg[6] & 0x4000);

		/* Clear the status bits right now. */
		xtstate->context.debugreg[6] = 0;
		tthread->dirty = 1;
		vdebug(5,LA_TARGET,LF_XV,"cleared status debug reg 6\n");

		goto out_bp_again;
	    }
	    else if (xtstate->context.user_regs.eflags & EF_TF
		     && bogus_sstep_thread
		     && bogus_sstep_thread->tpc
		     && bogus_sstep_thread->tpc->probepoint) {
		bogus_sstep_probepoint_addr = 
		    bogus_sstep_thread->tpc->probepoint->addr;

		/*
		 * If the single step took us <= 15 bytes (max x86 instr
		 * len), assume this is a single step on a bad Xen.
		 */
		if ((ipval - bogus_sstep_probepoint_addr) <= 15) {
		    vdebug(2,LA_TARGET,LF_XV,
			   "inferred single step for dom %d (TF set, but not"
			   " dreg status!) at 0x%"PRIxADDR" (stepped %d bytes"
			   " from probepoint)!\n",
			   xstate->id,ipval,ipval - bogus_sstep_probepoint_addr);
		    sstep_thread = bogus_sstep_thread;
		    goto handle_inferred_sstep;
		}
		else {
		    vdebug(2,LA_TARGET,LF_XV,
			   "tried to infer single step for dom %d (TF set, but not"
			   " dreg status!) at 0x%"PRIxADDR" -- BUT stepped %d bytes"
			   " from probepoint -- TOO FAR!\n",
			   xstate->id,ipval,ipval - bogus_sstep_probepoint_addr);
		    goto phantom;
		}
	    }
	    else if (xtstate->context.user_regs.eflags & EF_TF) {
	    phantom:
		vwarn("phantom single step for dom %d (no breakpoint"
		      " set either!); letting user handle fault at"
		      " 0x%"PRIxADDR"!\n",xstate->id,ipval);
		goto out_paused;
	    }
	    else {
		vwarn("could not find hardware bp and not sstep'ing;"
		      " letting user handle fault at 0x%"PRIxADDR"!\n",
		      ipval);
		goto out_paused;
	    }
	}
    }

 out_err:
    if (again)
	*again = 0;
    return TSTATUS_ERROR;

 out_err_again:
    if (again)
	*again = -1;
    return TSTATUS_ERROR;

 out_paused:
    if (again)
	*again = 0;
    return TSTATUS_PAUSED;

 out_bp_again:
    if (again)
	*again = 1;
    return TSTATUS_PAUSED;

 out_ss_again:
    if (again)
	*again = 2;
    return TSTATUS_PAUSED;
}

int xen_vm_evloop_handler(int readfd,int fdtype,void *state) {
    struct target *target = (struct target *)state;
    int again;
    int retval;
    XC_EVTCHN_PORT_T port = -1;

    /* we've got something from eventchn. let's see what it is! */
    port = xc_evtchn_pending(xce_handle);

    /* unmask the event channel BEFORE doing anything else,
     * like unpausing the target!
     */
    retval = xc_evtchn_unmask(xce_handle, port);
    if (retval == -1) {
	verror("failed to unmask event channel\n");
	return EVLOOP_HRET_BADERROR;
    }

    if (port != dbg_port)
	return EVLOOP_HRET_SUCCESS;

    again = 0;
    retval = xen_vm_handle_internal(target,&again);
    if (retval == TSTATUS_ERROR && again == 0)
	return EVLOOP_HRET_ERROR;
    /*
     * XXX: this is the "abort to user handler" case -- but in this
     * case, we have no user, basically.  Fix this.
     */
    //else if (retval == TSTATUS_PAUSED && again == 0)
    //    return EVLOOP_HRET_SUCCESS;

    __xen_vm_resume(target,0);

    return EVLOOP_HRET_SUCCESS;
}

int xen_vm_attach_evloop(struct target *target,struct evloop *evloop) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;

    if (!target->evloop) {
	verror("no evloop attached!\n");
	return -1;
    }

    /* get a select()able file descriptor of the event channel */
    xstate->evloop_fd = xc_evtchn_fd(xce_handle);
    if (xstate->evloop_fd == -1) {
        verror("event channel not initialized\n");
        return -1;
    }

    evloop_set_fd(target->evloop,xstate->evloop_fd,EVLOOP_FDTYPE_R,
		  xen_vm_evloop_handler,target);

    vdebug(5,LA_TARGET,LF_XV,
	   "added evloop readfd %d event channel\n",xstate->evloop_fd);

    return 0;
}

int xen_vm_detach_evloop(struct target *target) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;

    if (xstate->evloop_fd < 0)
	return 0;

    evloop_unset_fd(target->evloop,xstate->evloop_fd,EVLOOP_FDTYPE_A);

    xstate->evloop_fd = -1;

    return 0;
}

static target_status_t xen_vm_monitor(struct target *target) {
    int ret, fd;
    XC_EVTCHN_PORT_T port = -1;
    struct timeval tv;
    fd_set inset;
    int again;
    target_status_t retval;

    /* get a select()able file descriptor of the event channel */
    fd = xc_evtchn_fd(xce_handle);
    if (fd == -1) {
        verror("event channel not initialized\n");
        return TSTATUS_ERROR;
    }

    while (1) {
        tv.tv_sec = 0;
        tv.tv_usec = 50;
        FD_ZERO(&inset);
        FD_SET(fd,&inset);

        /* wait for a domain to trigger the VIRQ */
        ret = select(fd+1,&inset,NULL,NULL,&tv);
        if (ret == -1) // timeout
            continue;

        if (!FD_ISSET(fd, &inset)) 
            continue; // nothing in eventchn

        /* we've got something from eventchn. let's see what it is! */
        port = xc_evtchn_pending(xce_handle);

	/* unmask the event channel BEFORE doing anything else,
	 * like unpausing the target!
	 */
	ret = xc_evtchn_unmask(xce_handle, port);
	if (ret == -1) {
	    verror("failed to unmask event channel\n");
	    break;
	}

        if (port != dbg_port)
            continue; // not the event that we are looking for

	again = 0;
	retval = xen_vm_handle_internal(target,&again);
	if (retval == TSTATUS_ERROR && again == 0)
	    return retval;
	//else if (retval == TSTATUS_PAUSED && again == 0)
	//    return retval;

	__xen_vm_resume(target,0);
	continue;
    }

    return TSTATUS_ERROR; /* Never hit, just compiler foo */
}

static target_status_t xen_vm_poll(struct target *target,struct timeval *tv,
				   target_poll_outcome_t *outcome,int *pstatus) {
    int ret, fd;
    XC_EVTCHN_PORT_T port = -1;
    struct timeval itv;
    fd_set inset;
    int again;
    target_status_t retval;

    /* get a select()able file descriptor of the event channel */
    fd = xc_evtchn_fd(xce_handle);
    if (fd == -1) {
        verror("event channel not initialized\n");
        return TSTATUS_ERROR;
    }

    if (!tv) {
	itv.tv_sec = 0;
	itv.tv_usec = 0;
	tv = &itv;
    }
    FD_ZERO(&inset);
    FD_SET(fd,&inset);

    /* see if the VIRQ is lit for this domain */
    ret = select(fd+1,&inset,NULL,NULL,tv);
    if (ret == 0) {
	if (outcome)
	    *outcome = POLL_NOTHING;
	return TSTATUS_RUNNING;
    }

    if (!FD_ISSET(fd, &inset)) {
	if (outcome)
	    *outcome = POLL_NOTHING;
	return TSTATUS_RUNNING;
    }

    /* we've got something from eventchn. let's see what it is! */
    port = xc_evtchn_pending(xce_handle);

    /* unmask the event channel BEFORE doing anything else,
     * like unpausing the target!
     */
    ret = xc_evtchn_unmask(xce_handle, port);
    if (ret == -1) {
	verror("failed to unmask event channel\n");
	if (outcome)
	    *outcome = POLL_ERROR;
	return TSTATUS_ERROR;
    }

    if (port != dbg_port) {
	if (outcome)
	    *outcome = POLL_NOTHING;
	return TSTATUS_RUNNING;
    }

    again = 0;
    retval = xen_vm_handle_internal(target,&again);
    if (pstatus)
	*pstatus = again;

    return retval;
}

static unsigned char *xen_vm_read(struct target *target,ADDR addr,
				  unsigned long target_length,
				  unsigned char *buf) {
    return xen_vm_read_pid(target,0,addr,target_length,buf);
}

static unsigned long xen_vm_write(struct target *target,ADDR addr,
				  unsigned long length,unsigned char *buf) {
    return xen_vm_write_pid(target,0,addr,length,buf);
}

#ifdef ENABLE_XENACCESS
static unsigned char *mmap_pages(xa_instance_t *xa_instance,ADDR addr, 
				 unsigned long size,uint32_t *offset,
				 int *npages,int prot,int pid) {
    unsigned char *pages;
    unsigned long page_size, page_offset;
    char *dstr = "small";

    page_size = xa_instance->page_size;
    page_offset = addr & (page_size - 1);

    if (size > 0 && size <= (page_size - page_offset)) {
        /* let xenaccess use its memory cache for small size */
        pages = xa_access_user_va(xa_instance,addr,offset,pid,prot);
	if (!pages) {
	    if (!pid)
		return NULL;

	    pages = xa_access_user_va(xa_instance,addr,offset,0,prot);
	    if (!pages)
		return NULL;
	}
	*npages = 1;
    }
    else {
	dstr = "large";
        /* xenaccess can't map multiple pages properly, use our own function */
        pages = xa_access_user_va_range(xa_instance,addr,size,offset,pid,prot);

	if (!pages) { // && pid) {
	    //return NULL;
	    if (!pid)
		return NULL;

	    /* try kernel */
	    pages = xa_access_user_va_range(xa_instance,addr,size,offset,0,prot);
	    if (!pages) 
		return NULL;
	}

	/*
	 * Compute how many pages were mapped.
	 * *offset is the offset within the initial page mapped.
	 * Number of pages is thus:
	 *   round((*offset+size), page_size)
	 */
	*npages = (*offset + size) / page_size;
	if ((*offset + size) % page_size)
	    (*npages)++;
    }

    vdebug(9,LA_TARGET,LF_XV,"%ld bytes at %lx mapped (%s)\n",size,addr,dstr);

    return pages; /* munmap it later */
}

/*
 * Our xen read and write functions are a little special.  First,
 * xenaccess has the ability to read/write using the current cr3
 * contents as the pgdir location, or it can use a different pgdir
 * (i.e., for a thread that is not running).  

 */

unsigned char *xen_vm_read_pid(struct target *target,int pid,ADDR addr,
			       unsigned long target_length,unsigned char *buf) {
    unsigned char *pages;
    unsigned int offset = 0;
    unsigned long length = target_length, size = 0;
    unsigned long page_size;
    unsigned char *retval = NULL;
    unsigned int page_offset;
    int no_pages;
    struct xen_vm_state *xstate;

    xstate = (struct xen_vm_state *)(target->state);

    // XXX: need to check, if pid > 0, if we can actually read it --
    // i.e., do we have the necessary task_struct offsets for xenaccess,
    // and is it in mem...

    page_size = xstate->xa_instance.page_size;
    page_offset = addr & (page_size - 1);

    vdebug(16,LA_TARGET,LF_XV,
	   "read dom %d: addr=0x%"PRIxADDR" offset=%d len=%d pid=%d\n",
	   xstate->id,addr,page_offset,target_length,pid);

    /* if we know what length we need, just grab it */
    if (length > 0) {
	pages = (unsigned char *)mmap_pages(&xstate->xa_instance,addr,
					    length,&offset,&no_pages,
					    PROT_READ,pid);
	if (!pages)
	    return NULL;

	assert(offset == page_offset);
	vdebug(9,LA_TARGET,LF_XV,
	       "read dom %d: addr=0x%"PRIxADDR" offset=%d pid=%d len=%d mapped pages=%d\n",
	       xstate->id,addr,page_offset,pid,length,no_pages);
    }
    else {
	/* increase the mapping size by this much if the string is longer 
	   than we expect at first attempt. */
	size = (page_size - page_offset);

	while (1) {
	    if (1 || size > page_size) 
		vdebug(16,LA_TARGET,LF_XV,
		       "increasing size to %d (dom=%d,addr=%"PRIxADDR",pid=%d)\n",
		       size,xstate->id,addr,pid);
	    pages = (unsigned char *)mmap_pages(&xstate->xa_instance,addr,size,
						&offset,&no_pages,
						PROT_READ,pid);
	    if (!pages)
		return NULL;

	    length = strnlen((const char *)(pages + offset), size);
	    if (length < size) {
		vdebug(9,LA_TARGET,LF_XV,"got string of length %d, mapped %d pages\n",
		       length,no_pages);
		break;
	    }
	    if (munmap(pages,no_pages * page_size))
		vwarn("munmap of %p failed\n",pages);
	    size += page_size;
	}
    }

    if (!buf)
	retval = (unsigned char *)malloc(length+1);
    else 
	retval = buf;
    if (retval) {
	memcpy(retval,pages + offset,length);
	if (target_length == 0) {
	    retval[length] = '\0';
	}
    }

    if (munmap(pages,no_pages * page_size))
	vwarn("munmap of %p failed\n",pages);
    
    return retval;
}

unsigned long xen_vm_write_pid(struct target *target,int pid,ADDR addr,
			       unsigned long length,unsigned char *buf) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)(target->state);
    struct memrange *range = NULL;
    unsigned char *pages;
    unsigned int offset = 0;
    unsigned long page_size;
    unsigned int page_offset;
    int no_pages;

    xstate = (struct xen_vm_state *)(target->state);

    page_size = xstate->xa_instance.page_size;
    page_offset = addr & (page_size - 1);

    vdebug(16,LA_TARGET,LF_XV,
	   "write dom %d: addr=0x%"PRIxADDR" offset=%d len=%d pid=%d\n",
	   xstate->id,addr,page_offset,length,pid);

    target_find_memory_real(target,addr,NULL,NULL,&range);

    /*
     * This is mostly a stub for later, when we might actually check
     * bounds of writes.
     */
    if (!range || !(range->prot_flags & PROT_WRITE)) {
	errno = EFAULT;
	return 0;
    }

    /* Map the pages we have to write to. */
    pages = (unsigned char *)mmap_pages(&xstate->xa_instance,addr,
					length,&offset,&no_pages,
					PROT_WRITE,pid);
    if (!pages) {
	errno = EFAULT;
	return 0;
    }

    assert(offset == page_offset);
    vdebug(9,LA_TARGET,LF_XV,
	   "write dom %d: addr=0x%"PRIxADDR" offset=%d pid=%d len=%d mapped pages=%d\n",
	   xstate->id,addr,page_offset,pid,length,no_pages);

    memcpy(pages + offset,buf,length);

    if (munmap(pages,no_pages * page_size))
	vwarn("munmap of %p failed\n",pages);

    return length;
}
#endif

#ifdef ENABLE_LIBVMI
/*
 * Reads a block of memory from the target.  If @buf is non-NULL, we
 * assume it is at least @length bytes long; the result is placed into
 * @buf and @buf is returned.  If @buf is NULL, we allocate a buffer
 * large enough to hold the result (@length if @length >0; if @length is
 * 0 we attempt to read a string at that address; we stop when we hit a
 * NULL byte).
 *
 * On error, returns NULL, and sets errno.
 */
unsigned char *xen_vm_read_pid(struct target *target, int pid, ADDR addr,
				  unsigned long target_length,
				  unsigned char *buf)
{
    struct xen_vm_state *xstate = (struct xen_vm_state *)(target->state);
    vmi_instance_t vmi = xstate->vmi_instance;
    int alloced = 0;
    size_t cc;

    vdebug(16,LA_TARGET,LF_XV,
	   "read dom %d: addr=0x%"PRIxADDR" len=%d pid=%d\n",
	   xstate->id,addr,target_length,pid);

    /* if length == 0, we are copying in a string. */
    if (target_length == 0)
	return (unsigned char *)vmi_read_str_va(vmi, (addr_t)addr, pid);

    /* allocate buffer if necessary */
    if (!buf) {
	buf = malloc(target_length + 1);
	alloced = 1;
    }

    /* read the data */
    if (buf) {
	cc = vmi_read_va(vmi, (addr_t)addr, pid, buf, target_length);

	/* there is no provision for a partial read, assume an error */
	if ((unsigned long)cc != target_length) {
	    vwarn("vmi_read_va returns partial data (%lu of %lu)\n",
		  (unsigned long)cc, target_length);
	    if (alloced)
		free(buf);
	    return NULL;
	}
    }

    return buf;
}

/*
 * Writes @length bytes from @buf to @addr.  Returns the number of bytes
 * written (and sets errno nonzero if there is an error).  Successful if
 * @return == @length.
 */
unsigned long xen_vm_write_pid(struct target *target, int pid, ADDR addr,
			   unsigned long length, unsigned char *buf)
{
    struct xen_vm_state *xstate = (struct xen_vm_state *)(target->state);

    vdebug(16,LA_TARGET,LF_XV,
	   "write dom %d: addr=0x%"PRIxADDR" len=%d pid=%d\n",
	   xstate->id,addr,length,pid);

    return (unsigned long)vmi_write_va(xstate->vmi_instance, (addr_t)addr,
				       pid, buf, (size_t)length);
}
#endif

/*
 * The register mapping between x86_64 registers is defined by AMD in
 * http://www.x86-64.org/documentation/abi-0.99.pdf :
 */

/* Register mapping.
 *
 * First, be aware that our host bit size (64/32) *does* influence which
 * registers we can access -- i.e., 64-bit host tracing a
 * 32-bit process still gets the 64-bit registers -- but even then, we
 * want the 32-bit mapping for DWARF reg num to i386 reg.
 *
 * XXX XXX XXX
 * If structs in xen/xen.h (and arch-specific includes containing
 * cpu_user_regs) change, ever, these mappings will be wrong.
 */
#if __WORDSIZE == 64
#define X86_64_DWREG_COUNT 67
static int dreg_to_offset64[X86_64_DWREG_COUNT] = { 
    offsetof(struct vcpu_guest_context,user_regs.rax),
    offsetof(struct vcpu_guest_context,user_regs.rdx),
    offsetof(struct vcpu_guest_context,user_regs.rcx),
    offsetof(struct vcpu_guest_context,user_regs.rbx),
    offsetof(struct vcpu_guest_context,user_regs.rsi),
    offsetof(struct vcpu_guest_context,user_regs.rdi),
    offsetof(struct vcpu_guest_context,user_regs.rbp),
    offsetof(struct vcpu_guest_context,user_regs.rsp),
    offsetof(struct vcpu_guest_context,user_regs.r8),
    offsetof(struct vcpu_guest_context,user_regs.r9),
    offsetof(struct vcpu_guest_context,user_regs.r10),
    offsetof(struct vcpu_guest_context,user_regs.r11),
    offsetof(struct vcpu_guest_context,user_regs.r12),
    offsetof(struct vcpu_guest_context,user_regs.r13),
    offsetof(struct vcpu_guest_context,user_regs.r14),
    offsetof(struct vcpu_guest_context,user_regs.r15),
    offsetof(struct vcpu_guest_context,user_regs.rip),
    -1, -1, -1, -1, -1, -1, -1, -1, 
    -1, -1, -1, -1, -1, -1, -1, -1, 
    -1, -1, -1, -1, -1, -1, -1, -1, 
    -1, -1, -1, -1, -1, -1, -1, -1, 
    offsetof(struct vcpu_guest_context,user_regs.rflags),
    offsetof(struct vcpu_guest_context,user_regs.es),
    offsetof(struct vcpu_guest_context,user_regs.cs),
    offsetof(struct vcpu_guest_context,user_regs.ss),
    offsetof(struct vcpu_guest_context,user_regs.ds),
    offsetof(struct vcpu_guest_context,user_regs.fs),
    offsetof(struct vcpu_guest_context,user_regs.gs),
    -1, -1, 
    -1, -1, /* XXX: what about fs_base, gs_base; that's what these are. */
    -1, -1, 
    -1, -1, -1, -1, -1,
};
static char *dreg_to_name64[X86_64_DWREG_COUNT] = { 
    "rax", "rdx", "rcx", "rbx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "rip",
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
    "rflags", "es", "cs", "ss", "ds", "fs", "gs",
    NULL, NULL,
    NULL, NULL, /* "fs_base", "gs_base", */
    NULL, NULL,
    NULL, NULL, NULL, NULL, NULL,
};
static int creg_to_dreg64[COMMON_REG_COUNT] = { 
    [CREG_AX] = 0,
    [CREG_BX] = 3,
    [CREG_CX] = 2,
    [CREG_DX] = 1,
    [CREG_DI] = 5,
    [CREG_SI] = 4,
    [CREG_BP] = 6,
    [CREG_SP] = 7,
    [CREG_IP] = 16,
    [CREG_FLAGS] = 49,
    [CREG_CS] = 51,
    [CREG_SS] = 52,
    [CREG_DS] = 53,
    [CREG_ES] = 50,
    [CREG_FS] = 54,
    [CREG_GS] = 55,
};
#endif

#define X86_32_DWREG_COUNT 59
static int dreg_to_offset32[X86_32_DWREG_COUNT] = { 
    offsetof(struct vcpu_guest_context,user_regs.eax),
    offsetof(struct vcpu_guest_context,user_regs.ecx),
    offsetof(struct vcpu_guest_context,user_regs.edx),
    offsetof(struct vcpu_guest_context,user_regs.ebx),
    offsetof(struct vcpu_guest_context,user_regs.esp),
    offsetof(struct vcpu_guest_context,user_regs.ebp),
    offsetof(struct vcpu_guest_context,user_regs.esi),
    offsetof(struct vcpu_guest_context,user_regs.edi),
    offsetof(struct vcpu_guest_context,user_regs.eip),
    offsetof(struct vcpu_guest_context,user_regs.eflags),
    -1, -1, -1, -1, -1, -1, 
    -1, -1, -1, -1, -1, -1, -1, -1, 
    -1, -1, -1, -1, -1, -1, -1, -1, 
    -1, -1, -1, -1, -1, -1, -1, -1, 
    -1, -1, -1, -1, -1, -1, -1, -1, 
    -1, -1, -1, -1, -1,
    /* These are "fake" DWARF regs. */
    offsetof(struct vcpu_guest_context,user_regs.cs),
    offsetof(struct vcpu_guest_context,user_regs.ss),
    offsetof(struct vcpu_guest_context,user_regs.ds),
    offsetof(struct vcpu_guest_context,user_regs.es),
    offsetof(struct vcpu_guest_context,user_regs.fs),
    offsetof(struct vcpu_guest_context,user_regs.gs),
};
static char *dreg_to_name32[X86_32_DWREG_COUNT] = { 
    "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
    "eip", "eflags",
    NULL, NULL, NULL, NULL, NULL, NULL, 
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
    NULL, NULL, NULL, NULL, NULL,
    "cs", "ss", "ds", "es", "fs", "gs",
};
static int creg_to_dreg32[COMMON_REG_COUNT] = { 
    [CREG_AX] = 0,
    [CREG_BX] = 3,
    [CREG_CX] = 1,
    [CREG_DX] = 2,
    [CREG_DI] = 7,
    [CREG_SI] = 6,
    [CREG_BP] = 5,
    [CREG_SP] = 4,
    [CREG_IP] = 8,
    [CREG_FLAGS] = 9,
    [CREG_CS] = 53,
    [CREG_SS] = 54,
    [CREG_DS] = 55,
    [CREG_ES] = 56,
    [CREG_FS] = 57,
    [CREG_GS] = 58,
};

static int tsreg_to_offset[XV_TSREG_COUNT] = { 
    offsetof(struct vcpu_guest_context,debugreg[0]),
    offsetof(struct vcpu_guest_context,debugreg[1]),
    offsetof(struct vcpu_guest_context,debugreg[2]),
    offsetof(struct vcpu_guest_context,debugreg[3]),
    offsetof(struct vcpu_guest_context,debugreg[6]),
    offsetof(struct vcpu_guest_context,debugreg[7]),
    offsetof(struct vcpu_guest_context,ctrlreg[0]),
    offsetof(struct vcpu_guest_context,ctrlreg[1]),
    offsetof(struct vcpu_guest_context,ctrlreg[2]),
    offsetof(struct vcpu_guest_context,ctrlreg[3]),
    offsetof(struct vcpu_guest_context,ctrlreg[4]),
    offsetof(struct vcpu_guest_context,ctrlreg[5]),
    offsetof(struct vcpu_guest_context,ctrlreg[6]),
    offsetof(struct vcpu_guest_context,ctrlreg[7]),
};

/*
 * Register functions.
 */
char *xen_vm_reg_name(struct target *target,REG reg) {
#if __WORDSIZE == 64
    if (reg >= X86_64_DWREG_COUNT) {
	verror("DWARF regnum %d does not have a 64-bit target mapping!\n",reg);
	return NULL;
    }
    return dreg_to_name64[reg];
#else
    if (reg >= X86_32_DWREG_COUNT) {
	verror("DWARF regnum %d does not have a 32-bit target mapping!\n",reg);
	return NULL;
    }
    return dreg_to_name32[reg];
#endif
}

REG xen_vm_dwregno_targetname(struct target *target,char *name) {
    /* This sucks. */
    REG retval = 0;
    int i;
    int count;
    char **dregname;

#if __WORDSIZE == 64
    count = X86_64_DWREG_COUNT;
    dregname = dreg_to_name64;
#else
    count = X86_32_DWREG_COUNT;
    dregname = dreg_to_name32;
#endif

    for (i = 0; i < count; ++i) {
	if (dregname[i] == NULL)
	    continue;
	else if (strcmp(name,dregname[i]) == 0) {
	    retval = i;
	    break;
	}
    }

    if (i == count) {
	verror("could not find register number for name %s!\n",name);
	errno = EINVAL;
	return 0;
    }

    return retval;
}

REG xen_vm_dw_reg_no(struct target *target,common_reg_t reg) {
    if (reg >= COMMON_REG_COUNT) {
	verror("common regnum %d does not have an x86 mapping!\n",reg);
	errno = EINVAL;
	return 0;
    }
#if __WORDSIZE == 64
    return creg_to_dreg64[reg];
#else
    return creg_to_dreg32[reg];
#endif
}

REGVAL xen_vm_read_reg(struct target *target,tid_t tid,REG reg) {
    int offset;
    struct xen_vm_state *xstate;
    REGVAL retval;
    struct target_thread *tthread;
    struct xen_vm_thread_state *xtstate;

    vdebug(16,LA_TARGET,LF_XV,"reading reg %s\n",xen_vm_reg_name(target,reg));

    if (reg >= XV_TSREG_END_INDEX && reg <= XV_TSREG_START_INDEX) 
	offset = tsreg_to_offset[XV_TSREG_START_INDEX - reg];
#if __WORDSIZE == 64
    else if (reg >= X86_64_DWREG_COUNT) {
	verror("DWARF regnum %d does not have a 64-bit target mapping!\n",reg);
	errno = EINVAL;
	return 0;
    }
    else
	offset = dreg_to_offset64[reg];
#else
    else if (reg >= X86_32_DWREG_COUNT) {
	verror("DWARF regnum %d does not have a 32-bit target mapping!\n",reg);
	errno = EINVAL;
	return 0;
    }
    else 
	offset = dreg_to_offset32[reg];
#endif

    xstate = (struct xen_vm_state *)(target->state);
    if (!(tthread = xen_vm_load_cached_thread(target,tid))) {
	if (!errno) 
	    errno = EINVAL;
	verror("could not load cached thread %"PRIiTID"\n",tid);
	return 0;
    }
    xtstate = (struct xen_vm_thread_state *)tthread->state;

#if __WORDSIZE == 64
    if (likely(reg < 50) || unlikely(reg >= XV_TSREG_END_INDEX))
	retval = (REGVAL)*(uint64_t *)(((char *)&(xtstate->context)) + offset);
    else
	retval = (REGVAL)*(uint16_t *)(((char *)&(xtstate->context)) + offset);
#else 
    retval = (REGVAL)*(uint32_t *)(((char *)&(xtstate->context)) + offset);
#endif
    vdebug(9,LA_TARGET,LF_XV,"read reg %s 0x%"PRIxREGVAL"\n",
	   xen_vm_reg_name(target,reg),retval);

    return retval;
}

int xen_vm_write_reg(struct target *target,tid_t tid,REG reg,REGVAL value) {
    int offset;
    struct xen_vm_state *xstate;
    struct target_thread *tthread;
    struct xen_vm_thread_state *xtstate;

    vdebug(16,LA_TARGET,LF_XV,"writing reg %s 0x%"PRIxREGVAL"\n",
	   xen_vm_reg_name(target,reg),value);

    if (reg >= XV_TSREG_DR0 && reg <= XV_TSREG_DR7) {
	errno = EACCES;
	verror("cannot write debug registers directly!");
	return -1;
    }
    else if (reg >= XV_TSREG_CR0 && reg <= XV_TSREG_CR7) 
	offset = tsreg_to_offset[XV_TSREG_START_INDEX - reg];
#if __WORDSIZE == 64
    else if (reg >= X86_64_DWREG_COUNT) {
	verror("DWARF regnum %d does not have a 64-bit target mapping!\n",reg);
	errno = EINVAL;
	return -1;
    }
    else 
	offset = dreg_to_offset64[reg];
#else
    else if (reg >= X86_32_DWREG_COUNT) {
	verror("DWARF regnum %d does not have a 32-bit target mapping!\n",reg);
	errno = EINVAL;
	return -1;
    }
    else 
	offset = dreg_to_offset32[reg];
#endif

    xstate = (struct xen_vm_state *)(target->state);
    if (!(tthread = xen_vm_load_cached_thread(target,tid))) {
	if (!errno) 
	    errno = EINVAL;
	verror("could not load cached thread %"PRIiTID"\n",tid);
	return -1;
    }
    xtstate = (struct xen_vm_thread_state *)tthread->state;

#if __WORDSIZE == 64
    if (likely(reg < 50) || unlikely(reg >= XV_TSREG_END_INDEX))
	*(uint64_t *)(((char *)&(xtstate->context)) + offset) = (uint64_t)value;
    else
	*(uint16_t *)(((char *)&(xtstate->context)) + offset) = (uint16_t)value;
#else 
    *(uint32_t *)(((char *)&(xtstate->context)) + offset) = (uint32_t)value;
#endif

    /* Flush the context in target_resume! */
    tthread->dirty = 1;

    return 0;
}

GHashTable *xen_vm_copy_registers(struct target *target,tid_t tid) {
    GHashTable *retval;
    int i;
    int count;
    REGVAL *rvp;
    int *dregs;
    char **dregnames;
    struct target_thread *tthread;
    struct xen_vm_thread_state *xtstate;

    if (!(tthread = xen_vm_load_cached_thread(target,tid))) {
	if (!errno) 
	    errno = EINVAL;
	verror("could not load cached thread %"PRIiTID"\n",tid);
	return 0;
    }
    xtstate = (struct xen_vm_thread_state *)tthread->state;

#if __WORDSIZE == 64
    count = X86_64_DWREG_COUNT;
    dregs = dreg_to_offset64;
    dregnames = dreg_to_name64;
#else 
    count = X86_32_DWREG_COUNT;
    dregs = dreg_to_offset32;
    dregnames = dreg_to_name32;
#endif

    retval = g_hash_table_new_full(g_str_hash,g_str_equal,NULL,free);

    for (i = 0; i < count; ++i) {
	if (dregs[i] == -1) 
	    continue;

	rvp = malloc(sizeof(*rvp));
	
#if __WORDSIZE == 64
    if (likely(i < 50) || unlikely(i >= XV_TSREG_END_INDEX))
	*rvp = (REGVAL)*(uint64_t *)(((char *)&xtstate->context) + dregs[i]);
    else
	*rvp = (REGVAL)*(uint16_t *)(((char *)&(xtstate->context)) + dregs[i]);
#else 
    *rvp = (REGVAL)*(uint32_t *)(((char *)&(xtstate->context)) + dregs[i]);
#endif

	g_hash_table_insert(retval,dregnames[i],rvp);
    }

    return retval;
}

/*
 * Hardware breakpoint support.
 */
static REG xen_vm_get_unused_debug_reg(struct target *target,tid_t tid) {
    struct xen_vm_state *xstate;
    REG retval = -1;
    struct target_thread *tthread;
    struct xen_vm_thread_state *xtstate;

    if (tid != TID_GLOBAL) {
	verror("currently must use TID_GLOBAL for hardware probepoints!\n");
	return -1;
    }

    xstate = (struct xen_vm_state *)(target->state);
    if (!(tthread = xen_vm_load_cached_thread(target,tid))) {
	if (!errno) 
	    errno = EINVAL;
	verror("could not load cached thread %"PRIiTID"\n",tid);
	return 0;
    }
    xtstate = (struct xen_vm_thread_state *)tthread->state;

    if (!xtstate->dr[0]) { retval = 0; }
    else if (!xtstate->dr[1]) { retval = 1; }
    else if (!xtstate->dr[2]) { retval = 2; }
    else if (!xtstate->dr[3]) { retval = 3; }

    vdebug(5,LA_TARGET,LF_XV,"returning unused debug reg %d\n",retval);

    return retval;
}

/*
 * struct x86_dr_format {
 *     int dr0_l:1;
 *     int dr0_g:1;
 *     int dr1_l:1;
 *     int dr1_g:1;
 *     int dr2_l:1;
 *     int dr2_g:1;
 *     int dr3_l:1;
 *     int dr3_g:1;
 *     int exact_l:1;
 *     int exact_g:1;
 *     int reserved:6;
 *     probepoint_whence_t dr0_break:2;
 *     probepoint_watchsize_t dr0_len:2;
 *     probepoint_whence_t dr1_break:2;
 *     probepoint_watchsize_t dr1_len:2;
 *     probepoint_whence_t dr2_break:2;
 *     probepoint_watchsize_t dr2_len:2;
 *     probepoint_whence_t dr3_break:2;
 *     probepoint_watchsize_t dr3_len:2;
 * };
*/

static int xen_vm_set_hw_breakpoint(struct target *target,tid_t tid,
					    REG reg,ADDR addr) {
    struct xen_vm_state *xstate;
    struct target_thread *tthread;
    struct xen_vm_thread_state *xtstate;

    if (reg < 0 || reg > 3) {
	errno = EINVAL;
	return -1;
    }

    xstate = (struct xen_vm_state *)(target->state);
    if (!(tthread = xen_vm_load_cached_thread(target,tid))) {
	if (!errno) 
	    errno = EINVAL;
	verror("could not load cached thread %"PRIiTID"\n",tid);
	return -1;
    }
    xtstate = (struct xen_vm_thread_state *)tthread->state;

    if (xtstate->context.debugreg[reg] != 0) {
	vwarn("debug reg %"PRIiREG" already has an address, overwriting (0x%lx)!\n",
	      reg,xtstate->context.debugreg[reg]);
	//errno = EBUSY;
	//return -1;
    }

    /* Set the address, then the control bits. */
    xtstate->dr[reg] = (unsigned long)addr;

    /* Clear the status bits */
    xtstate->dr[6] = 0; //&= ~(1 << reg);

    /* Set the local control bit, and unset the global bit. */
    xtstate->dr[7] |= (1 << (reg * 2));
    xtstate->dr[7] &= ~(1 << (reg * 2 + 1));
    /* Set the break to be on execution (00b). */
    xtstate->dr[7] &= ~(3 << (16 + (reg * 4)));

    /* Now save these values for later write in flush_context! */
    xtstate->context.debugreg[reg] = xtstate->dr[reg];
    xtstate->context.debugreg[6] = xtstate->dr[6];
    xtstate->context.debugreg[7] = xtstate->dr[7];

    tthread->dirty = 1;

#ifdef CONFIG_DETERMINISTIC_TIMETRAVEL
    assert(xstate->dominfo_valid);
    if (xstate->dominfo.ttd_replay_flag) {
	int ret = xc_ttd_vmi_add_probe(xc_handle,xstate->id,addr);

	if (ret) {
	    verror("failed to register probe [dom%d:%"PRIxADDR" (%d)\n",
		   xstate->id,addr,ret);
	    return ret;
	}
	vdebug(4,LA_TARGET,LF_XV,
	       "registered probe in replay domain [dom%d:%"PRIxADDR"]\n",
	       xstate->id,addr);
    }
#endif

    return 0;
}

static int xen_vm_set_hw_watchpoint(struct target *target,tid_t tid,
					    REG reg,ADDR addr,
					    probepoint_whence_t whence,
					    probepoint_watchsize_t watchsize) {
    struct xen_vm_state *xstate;
    struct target_thread *tthread;
    struct xen_vm_thread_state *xtstate;

    if (reg < 0 || reg > 3) {
	errno = EINVAL;
	return -1;
    }

    xstate = (struct xen_vm_state *)(target->state);
    if (!(tthread = xen_vm_load_cached_thread(target,tid))) {
	if (!errno) 
	    errno = EINVAL;
	verror("could not load cached thread %"PRIiTID"\n",tid);
	return -1;
    }
    xtstate = (struct xen_vm_thread_state *)tthread->state;

    if (xtstate->context.debugreg[reg] != 0) {
	vwarn("debug reg %"PRIiREG" already has an address, overwriting (0x%lx)!\n",
	      reg,xtstate->context.debugreg[reg]);
	//errno = EBUSY;
	//return -1;
    }

    /* Set the address, then the control bits. */
    xtstate->dr[reg] = addr;

    /* Clear the status bits */
    xtstate->dr[6] = 0; //&= ~(1 << reg);

    /* Set the local control bit, and unset the global bit. */
    xtstate->dr[7] |= (1 << (reg * 2));
    xtstate->dr[7] &= ~(1 << (reg * 2 + 1));
    /* Set the break to be on whatever whence was) (clear the bits first!). */
    xtstate->dr[7] &= ~(3 << (16 + (reg * 4)));
    xtstate->dr[7] |= (whence << (16 + (reg * 4)));
    /* Set the watchsize to be whatever watchsize was). */
    xtstate->dr[7] &= ~(3 << (18 + (reg * 4)));
    xtstate->dr[7] |= (watchsize << (18 + (reg * 4)));

    vdebug(4,LA_TARGET,LF_XV,
	   "dreg6 = 0x%"PRIxADDR"; dreg7 = 0x%"PRIxADDR", w = %d, ws = 0x%x\n",
	   xtstate->dr[6],xtstate->dr[7],whence,watchsize);

    /* Now save these values for later write in flush_context! */
    xtstate->context.debugreg[reg] = xtstate->dr[reg];
    xtstate->context.debugreg[6] = xtstate->dr[6];
    xtstate->context.debugreg[7] = xtstate->dr[7];

    tthread->dirty = 1;

#ifdef CONFIG_DETERMINISTIC_TIMETRAVEL
    assert(xstate->dominfo_valid);
    if (xstate->dominfo.ttd_replay_flag) {
	int ret = xc_ttd_vmi_add_probe(xc_handle,xstate->id,addr);

	if (ret) {
	    verror("failed to register probe [dom%d:%"PRIxADDR" (%d)\n",
		   xstate->id,addr,ret);
	    return ret;
	}
	vdebug(4,LA_TARGET,LF_XV,
	       "registered probe in replay domain [dom%d:%"PRIxADDR"]\n",
	       xstate->id,addr);
    }
#endif

    return 0;
}

static int xen_vm_unset_hw_breakpoint(struct target *target,tid_t tid,REG reg) {
    struct xen_vm_state *xstate;
#ifdef CONFIG_DETERMINISTIC_TIMETRAVEL
    ADDR addr;
#endif
    struct target_thread *tthread;
    struct xen_vm_thread_state *xtstate;

    if (reg < 0 || reg > 3) {
	errno = EINVAL;
	return -1;
    }

    xstate = (struct xen_vm_state *)(target->state);
    if (!(tthread = xen_vm_load_cached_thread(target,tid))) {
	if (!errno) 
	    errno = EINVAL;
	verror("could not load cached thread %"PRIiTID"\n",tid);
	return -1;
    }
    xtstate = (struct xen_vm_thread_state *)tthread->state;

#ifdef CONFIG_DETERMINISTIC_TIMETRAVEL
    addr = xtstate->dr[reg];
#endif

    /* Set the address, then the control bits. */
    xtstate->dr[reg] = 0;

    /* Clear the status bits */
    xtstate->dr[6] = 0; //&= ~(1 << reg);

    /* Unset the local control bit, and unset the global bit. */
    xtstate->dr[7] &= ~(3 << (reg * 2));

    /* Now save these values for later write in flush_context! */
    xtstate->context.debugreg[reg] = xtstate->dr[reg];
    xtstate->context.debugreg[6] = xtstate->dr[6];
    xtstate->context.debugreg[7] = xtstate->dr[7];

    tthread->dirty = 1;

#ifdef CONFIG_DETERMINISTIC_TIMETRAVEL
    assert(xstate->dominfo_valid);
    if (xstate->dominfo.ttd_replay_flag) {
	int ret = xc_ttd_vmi_remove_probe(xc_handle,xstate->id,addr);

	if (ret) {
	    verror("failed to unregister probe [dom%d:%"PRIxADDR" (%d)\n",
		   xstate->id,addr,ret);
	    return ret;
	}
	vdebug(4,LA_TARGET,LF_XV,
	       "unregistered probe in replay domain [dom%d:%"PRIxADDR"]\n",
	       xstate->id,addr);
    }
#endif

    return 0;
}

static int xen_vm_unset_hw_watchpoint(struct target *target,tid_t tid,REG reg) {
    /* It's the exact same thing, yay! */
    return xen_vm_unset_hw_breakpoint(target,tid,reg);
}

int xen_vm_disable_hw_breakpoints(struct target *target,tid_t tid) {
    struct target_thread *tthread;
    struct xen_vm_thread_state *xtstate;

    if (!(tthread = xen_vm_load_cached_thread(target,tid))) {
	if (!errno) 
	    errno = EINVAL;
	verror("could not load cached thread %"PRIiTID"\n",tid);
	return -1;
    }
    xtstate = (struct xen_vm_thread_state *)tthread->state;

    xtstate->context.debugreg[7] = 0;

    tthread->dirty = 1;

    return 0;
}

int xen_vm_enable_hw_breakpoints(struct target *target,tid_t tid) {
    struct target_thread *tthread;
    struct xen_vm_thread_state *xtstate;

    if (!(tthread = xen_vm_load_cached_thread(target,tid))) {
	if (!errno) 
	    errno = EINVAL;
	verror("could not load cached thread %"PRIiTID"\n",tid);
	return -1;
    }
    xtstate = (struct xen_vm_thread_state *)tthread->state;

    xtstate->context.debugreg[7] = xtstate->dr[7];

    tthread->dirty = 1;

    return 0;
}

int xen_vm_disable_hw_breakpoint(struct target *target,tid_t tid,REG dreg) {
    struct xen_vm_state *xstate;
    struct target_thread *tthread;
    struct xen_vm_thread_state *xtstate;

    if (dreg < 0 || dreg > 3) {
	errno = EINVAL;
	return -1;
    }

    xstate = (struct xen_vm_state *)(target->state);
    if (!(tthread = xen_vm_load_cached_thread(target,tid))) {
	if (!errno) 
	    errno = EINVAL;
	verror("could not load cached thread %"PRIiTID"\n",tid);
	return -1;
    }
    xtstate = (struct xen_vm_thread_state *)tthread->state;

    /* Clear the status bits */
    xtstate->dr[6] = 0; //&= ~(1 << reg);

    /* Unset the local control bit, and unset the global bit. */
    xtstate->dr[7] &= ~(3 << (dreg * 2));

    /* Now save these values for later write in flush_context! */
    xtstate->context.debugreg[6] = xtstate->dr[6];
    xtstate->context.debugreg[7] = xtstate->dr[7];

    tthread->dirty = 1;

#ifdef CONFIG_DETERMINISTIC_TIMETRAVEL
    assert(xstate->dominfo_valid);
    if (xstate->dominfo.ttd_replay_flag) {
	int ret = xc_ttd_vmi_remove_probe(xc_handle,xstate->id,xtstate->dr[dreg]);

	if (ret) {
	    verror("failed to unregister probe [dom%d:%lx (%d)\n",
		   xstate->id,xtstate->dr[dreg],ret);
	    return ret;
	}
	vdebug(4,LA_TARGET,LF_XV,
	       "unregistered probe in replay domain [dom%d:%lx]\n",
	       xstate->id,xtstate->dr[dreg]);
    }
#endif

    return 0;
}

int xen_vm_enable_hw_breakpoint(struct target *target,tid_t tid,REG dreg) {
    struct xen_vm_state *xstate;
    struct target_thread *tthread;
    struct xen_vm_thread_state *xtstate;

    if (dreg < 0 || dreg > 3) {
	errno = EINVAL;
	return -1;
    }

    xstate = (struct xen_vm_state *)(target->state);
    if (!(tthread = xen_vm_load_cached_thread(target,tid))) {
	if (!errno) 
	    errno = EINVAL;
	verror("could not load cached thread %"PRIiTID"\n",tid);
	return -1;
    }
    xtstate = (struct xen_vm_thread_state *)tthread->state;

    /* Clear the status bits */
    xtstate->dr[6] = 0; //&= ~(1 << reg);

    /* Set the local control bit, and unset the global bit. */
    xtstate->dr[7] |= (1 << (dreg * 2));
    xtstate->dr[7] &= ~(1 << (dreg * 2 + 1));

    /* Now save these values for later write in flush_context! */
    xtstate->context.debugreg[6] = xtstate->dr[6];
    xtstate->context.debugreg[7] = xtstate->dr[7];

    tthread->dirty = 1;

#ifdef CONFIG_DETERMINISTIC_TIMETRAVEL
    assert(xstate->dominfo_valid);
    if (xstate->dominfo.ttd_replay_flag) {
	int ret = xc_ttd_vmi_add_probe(xc_handle,xstate->id,xtstate->dr[dreg]);

	if (ret) {
	    verror("failed to register probe [dom%d:%lx (%d)\n",
		   xstate->id,xtstate->dr[dreg],ret);
	    return ret;
	}
	vdebug(4,LA_TARGET,LF_XV,
	       "registered probe in replay domain [dom%d:%lx]\n",
	       xstate->id,xtstate->dr[dreg]);
    }
#endif

    return 0;
}

int xen_vm_notify_sw_breakpoint(struct target *target,ADDR addr,
				int notification) {
#ifdef CONFIG_DETERMINISTIC_TIMETRAVEL
    struct xen_vm_state *xstate;
    int ret = -1;
    char *msg = "unregister";

    xstate = (struct xen_vm_state *)(target->state);

    /* SW breakpoints are only implemented for replay domains right now */
    assert(xstate->dominfo_valid);
    if (!xstate->dominfo.ttd_replay_flag)
	return 0;

    if (notification) {
	msg = "register";
	ret = xc_ttd_vmi_add_probe(xc_handle,xstate->id,addr);
    }
    else {
	ret = xc_ttd_vmi_remove_probe(xc_handle,xstate->id,addr);
    }

    if (ret) {
        verror("failed to %s probe [dom%d:%"PRIxADDR" (%d)\n",
	       msg,xstate->id,addr,ret);
        return ret;
    }
    vdebug(4,LA_TARGET,LF_XV,
	   "%sed probe in replay domain [dom%d:%"PRIxADDR"]\n",
	   msg,xstate->id,addr);
#endif
    return 0;
}

int xen_vm_singlestep(struct target *target,tid_t tid,int isbp,
		      struct target *overlay) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;
    struct target_thread *tthread;
    struct xen_vm_thread_state *xtstate;

    if (!(tthread = xen_vm_load_cached_thread(target,tid))) {
	if (!errno) 
	    errno = EINVAL;
	verror("could not load cached thread %"PRIiTID"\n",tid);
	return -1;
    }
    xtstate = (struct xen_vm_thread_state *)tthread->state;

    /*
     * Try to use xc_domain_debug_control for HVM domains; but if it
     * fails, abort to the old way.
     *
     * NB: it had better not fail.  HVM Xen looks to see if EFLAGS_TF is
     * set, and if it is, it will reinject the debug trap into the guest
     * after we see it... which we don't want!  Maybe I can find a way
     * around that too.
     *
     * NB: this uses the CPU's monitor trap flag.  Xen's VMX HVM support
     * doesn't give us a way to figure out that the monitor trap flag is
     * what was triggered... so for the hvm case, we keep a special bit
     * (only need one cause we only support one VCPU).
     *
     * XXX: in the future, only use HVM trap monitor flag if the thread
     * is the current or global thread.  Otherwise obviously we won't
     * get what we want.  Ugh, this is all crazy.
     */
    if (xstate->hvm) {
#ifdef XC_HAVE_DOMAIN_DEBUG_CONTROL
	if (xc_domain_debug_control(xc_handle,xstate->id,
				    XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_ON,
				    xstate->dominfo.max_vcpu_id)) {
	    vwarn("xc_domain_debug_control failed!  falling back to eflags!\n");
	    goto nohvm;
	}
	else 
	    xstate->hvm_monitor_trap_flag_set = 1;
#else
	vwarn("xc_domain_debug_control does not exist; falling back to eflags!\n");
	goto nohvm;
#endif
    }
    else {
    nohvm:
#if __WORDSIZE == 32
	xtstate->context.user_regs.eflags |= EF_TF;
	/*
	 * If this is a single step of an instruction for which a breakpoint
	 * is set, set the RF flag.  Why?  Because then we don't have to
	 * disable the hw breakpoint at this instruction if there is one.
	 * The x86 clears it after one instruction anyway, so it's safe.
	 */
	if (isbp)
	    xtstate->context.user_regs.eflags |= EF_RF;
	xtstate->context.user_regs.eflags &= ~EF_IF;
#else
	xtstate->context.user_regs.rflags |= EF_TF;
	if (isbp)
	    xtstate->context.user_regs.rflags |= EF_RF;
	xtstate->context.user_regs.rflags &= ~EF_IF;
#endif
	tthread->dirty = 1;
    }

    target->sstep_thread = tthread;
    if (overlay)
	target->sstep_thread_overlay = overlay;
    else 
	target->sstep_thread_overlay = NULL;

    return 0;
}

int xen_vm_singlestep_end(struct target *target,tid_t tid,
			  struct target *overlay) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;
    struct target_thread *tthread;
    struct xen_vm_thread_state *xtstate;

    if (!(tthread = xen_vm_load_cached_thread(target,tid))) {
	if (!errno) 
	    errno = EINVAL;
	verror("could not load cached thread %"PRIiTID"\n",tid);
	return -1;
    }
    xtstate = (struct xen_vm_thread_state *)tthread->state;

    /*
     * Try to use xc_domain_debug_control for HVM domains; but if it
     * fails, abort to the old way.
     */
    if (xstate->hvm) {
#ifdef XC_HAVE_DOMAIN_DEBUG_CONTROL
	if (xc_domain_debug_control(xc_handle,xstate->id,
				    XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_OFF,
				    xstate->dominfo.max_vcpu_id)) {
	    vwarn("xc_domain_debug_control failed!  falling back to eflags!\n");
	    goto nohvm;
	}
	else 
	    xstate->hvm_monitor_trap_flag_set = 0;
#else
	vwarn("xc_domain_debug_control does not exist; falling back to eflags!\n");
	goto nohvm;
#endif
    }
    else {
    nohvm:
#if __WORDSIZE ==32
	xtstate->context.user_regs.eflags &= ~EF_TF;
#else
	xtstate->context.user_regs.rflags &= ~EF_TF;
#endif
	tthread->dirty = 1;
    }

    target->sstep_thread = NULL;
    target->sstep_thread_overlay = NULL;

    return 0;
}

int xen_vm_instr_can_switch_context(struct target *target,ADDR addr) {
    unsigned char buf[2];

    if (!target_read_addr(target,addr,2,buf)) {
	verror("could not read 2 bytes at 0x%"PRIxADDR"!\n",addr);
	return -1;
    }

    /* For now, if it's an IRET, or INT, return 1; otherwise, don't. */
    if (buf[0] == 0xcf) 
	return (int)buf[0];
    else if (buf[0] == 0xcc || buf[0] == 0xcd || buf[1] == 0xce)
	return (int)buf[0];

    return 0;
}

uint64_t xen_vm_get_tsc(struct target *target) {
    struct target_thread *gthread;
    struct xen_vm_thread_state *gtstate;
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;

    assert(xstate->dominfo_valid);

#ifdef CONFIG_DETERMINISTIC_TIMETRAVEL
    if (xstate->dominfo.ttd_guest) {
	if (target->global_thread && target->global_thread->valid)
	    gthread = target->global_thread;
	else if (!(gthread = __xen_vm_load_current_thread(target,0,1))) {
	    verror("could not load global thread!\n");
	    return UINT64_MAX;
	}

	gtstate = (struct xen_vm_thread_state *)gthread->state;

	return gtstate->context.ttd_perf.tsc;
    }
    else {
#endif
	if (xstate->vcpuinfo.time.version & 0x1) 
	    vwarn("tsc update in progress; tsc may be wrong?!\n");

	return xstate->vcpuinfo.time.tsc_timestamp;
#ifdef CONFIG_DETERMINISTIC_TIMETRAVEL
    }
#endif
}

uint64_t xen_vm_get_time(struct target *target) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;

    assert(xstate->dominfo_valid);

    if (xstate->vcpuinfo.time.version & 0x1) 
	vwarn("tsc update in progress; time may be wrong?!\n");

    return xstate->vcpuinfo.time.system_time;
}

uint64_t xen_vm_get_counter(struct target *target) {
    struct target_thread *gthread;
    struct xen_vm_thread_state *gtstate;
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;

    assert(xstate->dominfo_valid);

#ifdef CONFIG_DETERMINISTIC_TIMETRAVEL
    if (xstate->dominfo.ttd_guest) {
	if (target->global_thread && target->global_thread->valid)
	    gthread = target->global_thread;
	else if (!(gthread = __xen_vm_load_current_thread(target,0,1))) {
	    verror("could not load global thread!\n");
	    return UINT64_MAX;
	}

	gtstate = (struct xen_vm_thread_state *)gthread->state;

	return gtstate->context.ttd_perf.brctr;
    }
    else {
#endif
	if (xstate->vcpuinfo.time.version & 0x1) 
	    vwarn("time (subbing for counter) update in progress; time/counter"
		  " may be wrong?!\n");

	return xstate->vcpuinfo.time.system_time;
#ifdef CONFIG_DETERMINISTIC_TIMETRAVEL
    }
#endif
}

int xen_vm_enable_feature(struct target *target,int feature,void *arg) {
    struct xen_vm_state *xstate;

    if (feature != XV_FEATURE_BTS)
	return -1;

#ifdef CONFIG_DETERMINISTIC_TIMETRAVEL
    xstate = (struct xen_vm_state *)(target->state);

    assert(xstate->dominfo_valid);
    if (!xstate->dominfo.ttd_replay_flag)
	return 0;

    return xc_ttd_set_bts_on(xc_handle,xstate->id);
#else
    return -1;
#endif
}

int xen_vm_disable_feature(struct target *target,int feature) {
    struct xen_vm_state *xstate;

    if (feature != XV_FEATURE_BTS)
	return -1;

#ifdef CONFIG_DETERMINISTIC_TIMETRAVEL
    xstate = (struct xen_vm_state *)(target->state);

    assert(xstate->dominfo_valid);
    if (!xstate->dominfo.ttd_replay_flag)
	return 0;

    return xc_ttd_set_bts_off(xc_handle,xstate->id);
#else
    return -1;
#endif
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * End:
 */
