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

#include <xenctrl.h>
#include <xen/xen.h>
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
	free(target);
	return NULL;
    }

    if (!(xsh = xs_domain_open())) {
	verror("could not open xenstore!\n");
	free(target);
	return NULL;
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
	snprintf(buf,PATH_MAX,"%s/image/kernel",xstate->vmpath);
	xstate->kernel_filename = xs_read(xsh,xth,buf,NULL);
	if (!xstate->kernel_filename) 
	    vwarn("could not read kernel for dom %d; may cause problems!\n",
		  xstate->id);
    }

    if (xsh)
	xs_daemon_close(xsh);

    free(buf);
    buf = NULL;

#ifdef ENABLE_XENACCESS
    /* Now load up our xa_instance as much as we can now; we'll try to
       do more when we load the debuginfo file for the kernel. */
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
    /*
     * XXX total hack. The offsets are really a function of both word size
     * and OS version. But right now 32-bit implies Linux 2.6 and 64-bit
     * implies 3.2. We should just get these values from the debuginfo.
     * Offsets are:
     *   linux_tasks: offset of "tasks" in task_struct
     *   linux_mm:    offset of "mm" in task_struct
     *   linux_pid:   offset of "pid" in task_struct
     *   linux_pgd:   offset of "pgd" in mm_struct
     * Values below came from running gdb on the appropriate kernel; e.g.
     *   p &((struct task_struct *)0)->tasks
     */
    if (vmi_get_page_mode(xstate->vmi_instance) == VMI_PM_IA32E) {
	/*
	 * XXX another awesome hack. See if we have 3.8.4,
	 * if not assume 3.2.16.
	 */
	if (access("/boot/System.map-3.8.4", F_OK) == 0) {
	    tmp = "{"
		"ostype=\"Linux\"; "
		"sysmap=\"/boot/System.map-3.8.4\"; "
		"linux_tasks=0x260; "
		"linux_mm=0x298; "
		"linux_pid=0x2d4; "
		"linux_pgd=0x50;"
		"}";
	} else {
	    tmp = "{"
		"ostype=\"Linux\"; "
		"sysmap=\"/boot/System.map-3.2.16emulab1\"; "
		"linux_tasks=0x238; "
		"linux_mm=0x270; "
		"linux_pid=0x2ac; "
		"linux_pgd=0x50;"
		"}";
	}
    } else {
	tmp = "{"
	    "ostype=\"Linux\"; "
	    "sysmap=\"/boot/System.map-2.6.18.8-xenU\"; "
	    "linux_tasks=0x6c; "
	    "linux_mm=0x84; "
	    "linux_pid=0xa8; "
	    "linux_pgd=0x24;"
	    "}";
    }
    if (vmi_init_complete(&xstate->vmi_instance, tmp) == VMI_FAILURE) {
	verror("failed to complete init of vmi instance for dom %d\n",
	       xstate->id);
	vmi_destroy(xstate->vmi_instance);
	goto errout;
    }

    /* XXX this is in the vmi_instance, but they don't expose it! */
    xstate->vmi_page_size = XC_PAGE_SIZE;
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

	/* Figure out where the real ELF file is. */
	if ((tmp = strstr(xstate->kernel_filename,"vmlinuz"))) {
	    xstate->kernel_elf_filename = malloc(PATH_MAX);
	    snprintf(xstate->kernel_elf_filename,PATH_MAX,
		     "/boot/%s%s","vmlinux-syms",
		     xstate->kernel_filename + (tmp - xstate->kernel_filename) + 7);
	}

	/* Figure out where the modules are. */
	if ((tmp = strstr(xstate->kernel_filename,"vmlinuz-"))) {
	    xstate->kernel_module_dir = malloc(PATH_MAX);
	    snprintf(xstate->kernel_module_dir,PATH_MAX,
		     "/lib/modules/%s",tmp+strlen("vmlinuz-"));
	}
    }

    if (!xstate->kernel_elf_filename) {
	verror("could not discover kernel ELF filename from %s; aborting!\n",
	       xstate->kernel_filename);
	goto errout;
    }

    if (xstate->kernel_elf_filename) {
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
    }
    else {
	vwarn("could not find kernel ELF (vmlinux) file for %s; assuming"
	       " host/target same binary info!\n",xstate->kernel_filename);
#if __WORDSIZE == 64
	target->wordsize = 8;
	target->ptrsize = 8;
#else
	target->wordsize = 4;
	target->ptrsize = 4;
#endif
#if __BYTE_ORDER == __LITTLE_ENDIAN
	target->endian = DATA_LITTLE_ENDIAN;
#else
	target->endian = DATA_BIG_ENDIAN;
#endif
    }

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
    if (xstate->kernel_filename)
	free(xstate->kernel_filename);
    if (xstate->kernel_elf_filename)
	free(xstate->kernel_elf_filename);
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
    shared_info_t *live_shinfo = NULL;

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
	 * Have to grab vcpuinfo out of shared frame, argh!  This can't
	 * be the only way to access the tsc, but I can't find a better
	 * libxc way to do it!
	 *
	 * XXX: Do we really have to do this every time the domain is
	 * interrupted?
	 */
#ifdef ENABLE_XENACCESS
	live_shinfo = xa_mmap_mfn(&xstate->xa_instance,PROT_READ,
				  xstate->dominfo.shared_info_frame);
	if (!live_shinfo) {
	    verror("failed to mmap shared_info_frame!\n");
	    errno = EINVAL;
	    return -1;
	}
	/*
	 * Copy the vcpu_info_t out, then munmap.
	 */
	memcpy(&xstate->vcpuinfo,&live_shinfo->vcpu_info[0],
	       sizeof(xstate->vcpuinfo));
	munmap(live_shinfo,PAGE_SIZE);
#endif
#ifdef ENABLE_LIBVMI
	live_shinfo = malloc(xstate->vmi_page_size);
	if (!live_shinfo ||
	    vmi_read_pa(xstate->vmi_instance,
			(xstate->dominfo.shared_info_frame*(addr_t)xstate->vmi_page_size),
			live_shinfo, xstate->vmi_page_size) != xstate->vmi_page_size) {
            verror("failed to read shared_info!\n");
	    if (live_shinfo)
		free(live_shinfo);
            errno = EINVAL;
	    return -1;
	}
	memcpy(&xstate->vcpuinfo,&live_shinfo->vcpu_info[0],
	       sizeof(xstate->vcpuinfo));
	free(live_shinfo);
#endif

	xstate->dominfo_valid = 1;
    } else {
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
	    target_delete_thread(target,tthread,0);
	    tstate = NULL;
	    tthread = NULL;
	}
    }

    if (!tthread) {
	/* Build a new one. */
	tstate = (struct xen_vm_thread_state *)calloc(1,sizeof(*tstate));

	tthread = target_create_thread(target,tid,tstate);
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

    threadinfov = target_load_value_member(target,taskv,"thread_info",NULL,
					   LOAD_FLAG_AUTO_DEREF);
    if (!threadinfov) {
	verror("could not load thread_info in task %"PRIiTID"; BUG?\n",tid);
	/* errno should be set for us. */
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

    v = target_load_value_member(target,threadv,"esp",NULL,LOAD_FLAG_NONE);
    if (!v) {
	verror("could not load thread.esp for task %"PRIiTID"!\n",tid);
	goto errout;
    }
    tstate->esp = v_addr(v);
    //stack_base = -THREAD_SIZE & tstate->esp;
    /* The stack base is also the value of the task_struct->thread_info ptr. */
    tstate->stack_base = value_addr(threadinfov);
    stack_top = tstate->stack_base + THREAD_SIZE;
    /* See include/asm-i386/processor.h .  And since it doesn't explain
     * why it is subtracting 8, it's because fs/gs are not pushed on the
     * stack, so the ptrace regs struct doesn't really match with what's
     * on the stack ;).
     */
    if (iskernel && preempt_count) {
	tstate->ptregs_stack_addr = tstate->esp - 8 - 15 * 4;
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
    else {
	tstate->ptregs_stack_addr = stack_top - 8 - 15 * 4;
    }
    value_free(v);
    v = NULL;

    vdebug(5,LA_TARGET,LF_XV,
	   "esp=%"PRIxADDR",stack_base=%"PRIxADDR",stack_top=%"PRIxADDR
	   ",ptregs_stack_addr=%"PRIxADDR"\n",
	   tstate->esp,stack_top,tstate->stack_base,tstate->ptregs_stack_addr);

    v = target_load_value_member(target,threadv,"esp0",NULL,LOAD_FLAG_NONE);
    if (!v) 
	vwarn("could not load thread.esp0 for task %"PRIiTID"!\n",tid);
    tstate->esp0 = v_addr(v);
    value_free(v);
    v = NULL;

    v = target_load_value_member(target,threadv,"eip",NULL,LOAD_FLAG_NONE);
    if (!v) 
	vwarn("could not load thread.eip for task %"PRIiTID"!\n",tid);
    tstate->eip = v_addr(v);
    value_free(v);
    v = NULL;

    /*
     * FS/GS are in the thread data structure:
     */
    v = target_load_value_member(target,threadv,"fs",NULL,LOAD_FLAG_NONE);
    if (!v) {
	verror("could not load thread.fs for task %"PRIiTID"!\n",tid);
	goto errout;
    }
    else
	tstate->fs = tstate->context.user_regs.fs = v_u16(v);
    value_free(v);
    v = NULL;

    v = target_load_value_member(target,threadv,"gs",NULL,LOAD_FLAG_NONE);
    if (!v) {
	verror("could not load thread.gs for task %"PRIiTID"!\n",tid);
	goto errout;
    }
    else
	tstate->gs = tstate->context.user_regs.gs = v_u16(v);
    value_free(v);
    v = NULL;

    if (tstate->ptregs_stack_addr) {
	/*
	 * The save order on the linux stack is:
	 *
	 * ebx,ecx,edx,esi,edi,ebp,eax,xds,xes,orig_eax,eip,xcs,eflags,esp,xss
	 *
	 * The first 7 are in the same order as the Xen vcpu user regs for
	 * 32-bit guest.  The others, we have to copy in piecemeal.
	 */
	v = target_load_addr_real(target,tstate->ptregs_stack_addr,
				  LOAD_FLAG_NONE,15 * 4);
	if (!v) {
	    verror("could not load stack register save frame task %"PRIiTID"!\n",
		   tid);
	    goto errout;
	}

	/* Copy ebx,ecx,edx,esi,edi,ebp,eax; all 4 bytes on both stack and vcpu. */
	memcpy(&tstate->context.user_regs,v->buf,7 * 4);

	/* eip */
	tstate->context.user_regs.eip = *(uint32_t *)(v->buf + 10 * 4);
	/* cs */
	tstate->context.user_regs.cs = (uint16_t)*(uint32_t *)(v->buf + 11 * 4);
	/* eflags */
	tstate->context.user_regs.eflags = *(uint32_t *)(v->buf + 12 * 4);
	/**
	 ** WARNING: esp and ss may not be valid if the sleeping thread was
	 ** interrupted while it was in the kernel, because the interrupt
	 ** gate does not push ss and esp; see include/asm-i386/processor.h .
	 **/
	/* esp */
	tstate->context.user_regs.esp = *(uint32_t *)(v->buf + 13 * 4);
	/* ss */
	tstate->context.user_regs.ss = (uint16_t)*(uint32_t *)(v->buf + 14 * 4);
	/* ds */
	tstate->context.user_regs.ds = (uint16_t)*(uint32_t *)(v->buf + 7 * 4);
	/* es */
	tstate->context.user_regs.es = (uint16_t)*(uint32_t *)(v->buf + 8 * 4);
	
	value_free(v);
	v = NULL;
    }
    else {
	/*
	 * This thread was just context-switched out, not interrupted
	 * nor preempted, so we can't get its GP registers.  Get what we
	 * can...
	 */
	memset(&tstate->context,0,sizeof(vcpu_guest_context_t));
	tstate->context.user_regs.eip = tstate->eip;
	tstate->context.user_regs.esp = tstate->esp;
	tstate->context.user_regs.fs = tstate->fs;
	tstate->context.user_regs.gs = tstate->gs;

	/* eflags and ebp are on the stack. */
	v = target_load_addr_real(target,tstate->esp,LOAD_FLAG_NONE,2*4);
	tstate->eflags = ((uint32_t *)v->buf)[1];
	tstate->ebp = ((uint32_t *)v->buf)[0];
	value_free(v);
	v = NULL;

	tstate->context.user_regs.eflags = tstate->eflags;
	tstate->context.user_regs.ebp = tstate->ebp;
    }

    /*
     * Load the current debug registers from the thread.
     */
    v = target_load_value_member(target,threadv,"debugreg",NULL,
				 LOAD_FLAG_AUTO_DEREF);
    if (!v) {
	verror("could not load thread->debugreg for task %"PRIiTID"\n",tid);
	goto errout;
    }
    tstate->context.debugreg[0] = ((uint32_t *)v->buf)[0];
    tstate->context.debugreg[1] = ((uint32_t *)v->buf)[1];
    tstate->context.debugreg[2] = ((uint32_t *)v->buf)[2];
    tstate->context.debugreg[3] = ((uint32_t *)v->buf)[3];
    tstate->context.debugreg[6] = ((uint32_t *)v->buf)[6];
    tstate->context.debugreg[7] = ((uint32_t *)v->buf)[7];
    value_free(v);
    v = NULL;

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
    struct value *taskv;

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

    taskv = linux_get_task(target,tid);

    if (!taskv) {
	vwarn("no task matching %"PRIiTID"\n",tid);

	if (tthread) {
	    vdebug(3,LA_TARGET,LF_XV,
		   "evicting old thread %"PRIiTID"; no longer exists!\n",tid);
	    target_delete_thread(target,tthread,0);
	}

	return NULL;
    }

    if (!(tthread = __xen_vm_load_thread_from_value(target,taskv)))
	goto errout;

    return tthread;

 errout:
    if (taskv)
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
	if (xc_vcpu_getcontext(xc_handle,xstate->id,
			       xstate->dominfo.max_vcpu_id,
			       &gtstate->context) < 0) {
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
	       kernel_esp);
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
	taskv = linux_load_current_task_as_type(target,
						xstate->task_struct_type_ptr,
						kernel_esp);
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
    tstate->thread_info = NULL;
    if (taskv)
	value_free(taskv);
    tstate->thread_struct = NULL;
    tstate->task_struct = NULL;

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
     * Make sure xenaccess is setup to read from userspace memory.
     */
#ifdef ENABLE_XENACCESS
    xstate->xa_instance.init_task = xstate->init_task_addr;

    xstate->xa_instance.page_offset = 0;

    errno = 0;
    xstate->xa_instance.os.linux_instance.tasks_offset = 
	symbol_offsetof(xstate->task_struct_type,"tasks",NULL);
    if (errno) 
	vwarn("could not resolve offset of task_struct.tasks!\n");
    errno = 0;
    xstate->xa_instance.os.linux_instance.pid_offset = 
	symbol_offsetof(xstate->task_struct_type,"pid",NULL);
    if (errno) 
	vwarn("could not resolve offset of task_struct.pid!\n");
    errno = 0;
    xstate->xa_instance.os.linux_instance.mm_offset = 
	symbol_offsetof(xstate->task_struct_type,"mm",NULL);
    if (errno) 
	vwarn("could not resolve offset of task_struct.mm!\n");
    errno = 0;
    xstate->xa_instance.os.linux_instance.pgd_offset = 
	symbol_offsetof(xstate->mm_struct_type,"pgd",NULL);
    if (errno) 
	vwarn("could not resolve offset of mm_struct.pgd!\n");

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
    if (xstate->task_struct_type_ptr)
	symbol_release(xstate->task_struct_type_ptr);
    if (xstate->mm_struct_type)
	symbol_release(xstate->mm_struct_type);
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

    /* Find the kernel start address */
    xstate->kernel_start_addr = 0xC0000000;
#if __WORDSIZE == 64
    if (target->wordsize == 8)
	xstate->kernel_start_addr = 0xFFFFFFFF81000000ULL;
#endif
#if 0
    {
	struct bsymbol *kernaddr;

	kernaddr = target_lookup_sym(target, "_text", NULL, NULL,
				     SYMBOL_TYPE_VAR);
	if (kernaddr) {
	    if (symbol_get_location_addr(kernaddr->lsymbol->symbol,
					 &xstate->kernel_start_addr)) {
		vwarn("could not resolve addr of _text!\n");
	    }
	    bsymbol_release(kernaddr);
	} else {
	    vwarn("could not find symbol _text!\n");
	}
    }
#endif
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
    if (xc_vcpu_setcontext(xc_handle,xstate->id,xstate->dominfo.max_vcpu_id,
			   &tstate->context) < 0) {
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
    if (xc_vcpu_setcontext(xc_handle,xstate->id,xstate->dominfo.max_vcpu_id,
			   ctxp) < 0) {
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

    /*
     * Ok, we can finally flush this thread's state to memory.
     */

    /*
     * Flush (fake) Xen machine context loaded from stack, back to stack.
     */

    /*
     * FS/GS are in the thread data structure:
     */
    v = target_load_value_member(target,tstate->thread_struct,"fs",NULL,
				 LOAD_FLAG_NONE);
    value_update_u16(v,tstate->context.user_regs.gs);
    target_store_value(target,v);
    value_free(v);
    v = NULL;

    v = target_load_value_member(target,tstate->thread_struct,"gs",NULL,
				 LOAD_FLAG_NONE);
    value_update_u16(v,tstate->context.user_regs.gs);
    target_store_value(target,v);
    value_free(v);
    v = NULL;

    /*
     * The save order on the linux stack is:
     *
     * ebx,ecx,edx,esi,edi,ebp,eax,xds,xes,orig_eax,eip,xcs,eflags,esp,xss
     *
     * The first 7 are in the same order as the Xen vcpu user regs for
     * 32-bit guest.  The others, we have to copy in piecemeal.
     */
    v = target_load_addr_real(target,tstate->ptregs_stack_addr,
			      LOAD_FLAG_NONE,15 * 4);
    if (!v) {
	verror("could not load register save frame task %"PRIiTID"!\n",tid);
	goto errout;
    }

    /* Copy ebx,ecx,edx,esi,edi,ebp,eax; all 4 bytes on both stack and vcpu. */
    memcpy(v->buf,&tstate->context.user_regs,7 * 4);

    /* eip */
    *(uint32_t *)(v->buf + 10 * 4) = tstate->context.user_regs.eip;
    /* cs */
    *(uint32_t *)(v->buf + 11 * 4) = (uint32_t)tstate->context.user_regs.cs;
    /* eflags */
    *(uint32_t *)(v->buf + 12 * 4) = tstate->context.user_regs.eflags;
    /* esp */
    *(uint32_t *)(v->buf + 13 * 4) = tstate->context.user_regs.esp;
    /* ss */
    *(uint32_t *)(v->buf + 14 * 4) = (uint32_t)tstate->context.user_regs.ss;
    /* ds */
    *(uint32_t *)(v->buf + 7 * 4) = (uint32_t)tstate->context.user_regs.ds;
    /* es */
    *(uint32_t *)(v->buf + 8 * 4) = (uint32_t)tstate->context.user_regs.es;

    target_store_value(target,v);
    value_free(v);
    v = NULL;

    /*
     * Load the current debug registers from the thread.
     */
    v = target_load_value_member(target,tstate->thread_struct,"debugreg",NULL,
				 LOAD_FLAG_AUTO_DEREF);
    if (!v) {
	verror("could not load thread->debugreg for task %"PRIiTID"\n",tid);
	goto errout;
    }
    ((uint32_t *)v->buf)[0] = tstate->context.debugreg[0];
    ((uint32_t *)v->buf)[1] = tstate->context.debugreg[1];
    ((uint32_t *)v->buf)[2] = tstate->context.debugreg[2];
    ((uint32_t *)v->buf)[3] = tstate->context.debugreg[3];
    ((uint32_t *)v->buf)[6] = tstate->context.debugreg[6];
    ((uint32_t *)v->buf)[7] = tstate->context.debugreg[7];

    target_store_value(target,v);
    value_free(v);
    v = NULL;

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
    int *load_counter = (int *)data;

    if (!__xen_vm_load_thread_from_value(target,value)) {
	verror("could not load thread from task value; BUG?\n");
	value_free(value);
	return -1;
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
#if __WORDSIZE == 64
	bufsiz = 33*3*16 + 1;
	buf = malloc(sizeof(char)*bufsiz);
#else
	bufsiz = 25*3*8 + 1;
	buf = malloc(sizeof(char)*bufsiz);
#endif
    }

    if (detail < 1)
	snprintf(buf,bufsiz,
		 "ip=%"RF" bp=%"RF" sp=%"RF" flags=%"RF
		 " ax=%"RF" bx=%"RF" cx=%"RF" dx=%"RF" di=%"RF" si=%"RF
		 " cs=%"RF" ss=%"RF" ds=%"RF" es=%"RF" fs=%"RF" gs=%"RF
		 " dr0=%"DRF" dr1=%"DRF" dr2=%"DRF" dr3=%"DRF" dr6=%"DRF" dr7=%"DRF,
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
		 tstate->dr[6],tstate->dr[7]);
    else 
	snprintf(buf,bufsiz,
		 "ip=%"RF" bp=%"RF" sp=%"RF" flags=%"RF
		 " ax=%"RF" bx=%"RF" cx=%"RF" dx=%"RF" di=%"RF" si=%"RF"\n"
		 " cs=%"RF" ss=%"RF" ds=%"RF" es=%"RF" fs=%"RF" gs=%"RF"\n"
		 " dr0=%"DRF" dr1=%"DRF" dr2=%"DRF" dr3=%"DRF" dr6=%"DRF" dr7=%"DRF,
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
		 tstate->dr[6],tstate->dr[7]);

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

static int xen_vm_updateregions(struct target *target,
				struct addrspace *space) {
    struct xen_vm_state *xstate = \
	(struct xen_vm_state *)target->state;
    GHashTable *moddep;
    FILE *moddep_file;
    char moddep_path[PATH_MAX];
    char buf[PATH_MAX * 2];
    char *colon;
    char *slash;
    char *newline;
    char *extension;
    char *modname;
    char *modfilename;
    struct __update_module_data ud;
    struct memregion *region;
    struct memregion *tmp;
    struct stat statbuf;

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

    /*
     * Read the current modules.dep file and build up the name->file map.
     */
    snprintf(moddep_path,PATH_MAX,"%s/modules.dep",xstate->kernel_module_dir);
    if (!(moddep_file = fopen(moddep_path,"r"))) {
	verror("fopen(%s): %s\n",moddep_path,strerror(errno));
	return 0;
    }
    moddep = g_hash_table_new_full(g_str_hash,g_str_equal,free,free);

    while (fgets(buf,sizeof(buf),moddep_file)) {
	newline = index(buf,'\n');

	/*
	 * Find lines starting with "<module_filename>:", and split them
	 * into a map of <module_name> -> <module_filename>
	 */
	if ((colon = index(buf,':'))) {
	    *colon = '\0';
	    if ((slash = rindex(buf,'/'))) {
		modfilename = strdup(buf);
		if (stat(modfilename,&statbuf)) {
		    vdebug(3,LA_TARGET,LF_XV,
			   "could not find modules.dep file %s; trying abs path\n",
			   modfilename);
		    free(modfilename);
		    modfilename = calloc(1,sizeof(char)*(strlen(xstate->kernel_module_dir)+1+strlen(buf)+1));
		    sprintf(modfilename,"%s/%s",xstate->kernel_module_dir,buf);
		    if (stat(modfilename,&statbuf)) {
			vwarnopt(3,LA_TARGET,LF_XV,
				 "could not find modules.dep file %s at all!\n",
				 modfilename);
			free(modfilename);
			goto drain;
		    }
		}
		modname = strdup(slash+1);
		if ((extension = rindex(modname,'.')))
		    *extension = '\0';

		g_hash_table_insert(moddep,modname,modfilename);
		vdebug(8,LA_TARGET,LF_XV,
		       "modules.dep: %s -> %s\n",modname,modfilename);
	    }
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

    ud.space = space;
    ud.moddep = moddep;

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
     * Garbage-collect stale modules.
     *
     * XXX: eventually, we need to check any target stuff in a region we
     * delete -- values, probes, etc.
     */
    list_for_each_entry_safe(region,tmp,&space->regions,region) {
	if (region->type == REGION_TYPE_LIB
	    && !region->exists && !region->new) {
	    vdebug(3,LA_TARGET,LF_XV,"removing stale region (%s:%s:%s)\n",
		   region->space->idstr,region->name,REGION_TYPE(region->type));
	    memregion_free(region);
	}
    }

    g_hash_table_destroy(moddep);

    return 0;
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

	list_for_each_entry(space,&target->spaces,space) {
	    xen_vm_updateregions(target,space);
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
	if (xtstate->context.debugreg[6] & 0x4000) {
	    vdebug(3,LA_TARGET,LF_XV,"new single step debug event\n");

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

	    if (xtstate->context.user_regs.eflags & EF_TF) {
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

    vdebug(4,LA_TARGET,LF_XV,"%ld bytes at %lx mapped (%s)\n",size,addr,dstr);

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
    vdebug(5,LA_TARGET,LF_XV,"read reg %s 0x%"PRIxREGVAL"\n",
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
    struct target_thread *tthread;
    struct xen_vm_thread_state *xtstate;

    if (!(tthread = xen_vm_load_cached_thread(target,tid))) {
	if (!errno) 
	    errno = EINVAL;
	verror("could not load cached thread %"PRIiTID"\n",tid);
	return -1;
    }
    xtstate = (struct xen_vm_thread_state *)tthread->state;

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

    target->sstep_thread = tthread;
    if (overlay)
	target->sstep_thread_overlay = overlay;
    else 
	target->sstep_thread_overlay = NULL;

    return 0;
}

int xen_vm_singlestep_end(struct target *target,tid_t tid,
			  struct target *overlay) {
    struct target_thread *tthread;
    struct xen_vm_thread_state *xtstate;

    if (!(tthread = xen_vm_load_cached_thread(target,tid))) {
	if (!errno) 
	    errno = EINVAL;
	verror("could not load cached thread %"PRIiTID"\n",tid);
	return -1;
    }
    xtstate = (struct xen_vm_thread_state *)tthread->state;

#if __WORDSIZE ==32
    xtstate->context.user_regs.eflags &= ~EF_TF;
#else
    xtstate->context.user_regs.rflags &= ~EF_TF;
#endif

    tthread->dirty = 1;

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
