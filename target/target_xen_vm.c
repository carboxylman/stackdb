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

#include "config.h"

#include <errno.h>
#include <assert.h>
#include <ctype.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#if !defined(UNIX_PATH_MAX)
#define UNIX_PATH_MAX (size_t)sizeof(((struct sockaddr_un *) 0)->sun_path)
#endif
#include <libgen.h>
#include <endian.h>
#include <gelf.h>
#include <elf.h>
#include <libelf.h>
#include <argp.h>

#include "common.h"
#include "arch.h"
#include "arch_x86.h"
#include "arch_x86_64.h"
#include "evloop.h"
#include "binfile.h"
#include "dwdebug.h"
#include "dwdebug_priv.h"
#include "target_api.h"
#include "target.h"
#include "target_arch_x86.h"
#include "target_os.h"
#include "probe_api.h"

#include <xenctrl.h>
#include <xs.h>

#include "target_xen_vm.h"
#include "target_xen_vm_vmp.h"

#ifdef ENABLE_XENACCESS
extern struct xen_vm_mem_ops xen_vm_mem_ops_xenaccess;
#endif
#ifdef ENABLE_LIBVMI
extern struct xen_vm_mem_ops xen_vm_mem_ops_libvmi;
#endif

extern struct xen_vm_mem_ops xen_vm_mem_ops_builtin;

/*
 * Prototypes.
 */
struct target *xen_vm_instantiate(struct target_spec *spec,
				  struct evloop *evloop);

static struct target *xen_vm_attach(struct target_spec *spec,
				    struct evloop *evloop);

static int xen_vm_snprintf(struct target *target,char *buf,int bufsiz);
static int xen_vm_init(struct target *target);
static int xen_vm_attach_internal(struct target *target);
static int xen_vm_detach(struct target *target);
static int xen_vm_fini(struct target *target);
static int xen_vm_kill(struct target *target,int sig);
static int xen_vm_loadspaces(struct target *target);
static int xen_vm_loadregions(struct target *target,struct addrspace *space);
static int xen_vm_loaddebugfiles(struct target *target,struct addrspace *space,
				 struct memregion *region);
static int xen_vm_postloadinit(struct target *target);
static int xen_vm_postopened(struct target *target);
static int xen_vm_set_active_probing(struct target *target,
				     active_probe_flags_t flags);

static target_status_t xen_vm_handle_exception(struct target *target,
					       int *again,void *priv);

static struct target *
xen_vm_instantiate_overlay(struct target *target,
			   struct target_thread *tthread,
			   struct target_spec *spec,
			   struct target_thread **ntthread);
static struct target_thread *
xen_vm_lookup_overlay_thread_by_id(struct target *target,int id);
static struct target_thread *
xen_vm_lookup_overlay_thread_by_name(struct target *target,char *name);
int xen_vm_attach_overlay_thread(struct target *base,struct target *overlay,
				 tid_t newtid);
int xen_vm_detach_overlay_thread(struct target *base,struct target *overlay,
				 tid_t tid);
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
/*
 * NB: initially, we will use VM phys addrs here.  We could have also
 * used Xen machine addrs; but for now, given the current
 * libvmi code, using VM phys addrs is easiest.  Later on,
 * machine addrs will probably be *faster*.  The risk with that approach
 * is if the VM pfn/mfn mapping ever changes out from under us.
 */
static int xen_vm_addr_v2p(struct target *target,tid_t tid,
			   ADDR vaddr,ADDR *paddr);
static unsigned char *xen_vm_read_phys(struct target *target,ADDR paddr,
				       unsigned long length,unsigned char *buf);
static unsigned long xen_vm_write_phys(struct target *target,ADDR paddr,
				       unsigned long length,unsigned char *buf);

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
static int xen_vm_invalidate_thread(struct target *target,
				    struct target_thread *tthread);
static int xen_vm_thread_snprintf(struct target_thread *tthread,
				  char *buf,int bufsiz,
				  int detail,char *sep,char *key_val_sep);
/*
static REGVAL xen_vm_read_reg(struct target *target,tid_t tid,REG reg);
static int xen_vm_write_reg(struct target *target,tid_t tid,REG reg,REGVAL value);
static GHashTable *xen_vm_copy_registers(struct target *target,tid_t tid);
REGVAL xen_vm_read_reg_tidctxt(struct target *target,
			       tid_t tid,thread_ctxt_t tidctxt,REG reg);
int xen_vm_write_reg_tidctxt(struct target *target,
			     tid_t tid,thread_ctxt_t tidctxt,
			     REG reg,REGVAL value);
*/
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
static int __xen_vm_pgd(struct target *target,tid_t tid,uint64_t *pgd);
int __xen_vm_vcpu_to_thread_regcache(struct target *target,
				     struct vcpu_guest_context *context,
				     struct target_thread *tthread,
				     thread_ctxt_t tctxt);
int __xen_vm_thread_regcache_to_vcpu(struct target *target,
				     struct target_thread *tthread,
				     thread_ctxt_t tctxt,
				     struct vcpu_guest_context *context);
static result_t xen_vm_active_memory_handler(struct probe *probe,tid_t tid,
					     void *handler_data,
					     struct probe *trigger,
					     struct probe *base);
static result_t xen_vm_active_thread_entry_handler(struct probe *probe,tid_t tid,
						   void *handler_data,
						   struct probe *trigger,
						   struct probe *base);
static result_t xen_vm_active_thread_exit_handler(struct probe *probe,tid_t tid,
						  void *handler_data,
						  struct probe *trigger,
						  struct probe *base);

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
 *
 * We support a couple different ways of listening for debug exceptions
 * from the hypervisor.  Exceptions come via the VIRQ_DEBUGGER virq; and
 * only one consumer may bind to that irq.  This is a problem if we want
 * to have multiple VMI programs each debugging one or more
 * domains... we have to demultiplex the IRQ signal to the right VMI
 * program.  Unforunately, it's tricky to figure out which domain the
 * IRQ was for, because of Xen bugs in the handling of x86 debug
 * registers.  So, the demultiplexer must pass the notification to *all*
 * clients and let them decide if the signal was for them.
 *
 * So... we support a dedicated mode, where only one VMI program can run
 * at a time; and a "shared" mode, where a demultiplexer process is
 * spawned (if it doesn't already exist), and the VMI program(s) connect
 * to it to receive VIRQ notifications.
 *
 * The xc_handle variable is always valid.  For dedicated mode,
 * xce_handle and dbg_port are valid; for shared mode,
 * xen_vm_vmp_client_fd is valid instead.
 */
static int xc_refcnt = 0;

#ifdef XENCTRL_HAS_XC_INTERFACE
xc_interface *xc_handle = NULL;
static xc_interface *xce_handle = NULL;
#define XC_IF_INVALID (NULL)
#else
int xc_handle = -1;
static int xce_handle = -1;
#define XC_IF_INVALID (-1)
#endif
int xce_handle_fd = -1;

#if !defined(XC_EVTCHN_PORT_T)
#error "XC_EVTCHN_PORT_T undefined!"
#endif
static XC_EVTCHN_PORT_T dbg_port = -1;

static int xen_vm_vmp_client_fd = -1;
static char *xen_vm_vmp_client_path = NULL;

#define EF_TF (0x00000100)
#define EF_IF (0x00000200)
#define EF_RF (0x00010000)

/*
 * Set up the target interface for this library.
 */
struct target_ops xen_vm_ops = {
    .snprintf = xen_vm_snprintf,

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

    .handle_exception = xen_vm_handle_exception,
    .handle_break = probepoint_bp_handler,
    .handle_step = probepoint_ss_handler,
    .handle_interrupted_step = NULL,

    .instantiate_overlay = xen_vm_instantiate_overlay,
    .lookup_overlay_thread_by_id = xen_vm_lookup_overlay_thread_by_id,
    .lookup_overlay_thread_by_name = xen_vm_lookup_overlay_thread_by_name,
    .attach_overlay_thread = xen_vm_attach_overlay_thread,
    .detach_overlay_thread = xen_vm_detach_overlay_thread,

    .status = xen_vm_status,
    .pause = xen_vm_pause,
    .resume = xen_vm_resume,
    .monitor = xen_vm_monitor,
    .poll = xen_vm_poll,
    .read = xen_vm_read,
    .write = xen_vm_write,
    .addr_v2p = xen_vm_addr_v2p,
    .read_phys = xen_vm_read_phys,
    .write_phys = xen_vm_write_phys,

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
    .invalidate_thread = xen_vm_invalidate_thread,
    .thread_snprintf = xen_vm_thread_snprintf,

    .attach_evloop = xen_vm_attach_evloop,
    .detach_evloop = xen_vm_detach_evloop,

    .readreg = target_regcache_readreg,
    .writereg = target_regcache_writereg,
    .copy_registers = target_regcache_copy_registers,
    .readreg_tidctxt = target_regcache_readreg_tidctxt,
    .writereg_tidctxt = target_regcache_writereg_tidctxt,

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

#define XV_ARGP_USE_XENACCESS      0x550001
#define XV_ARGP_USE_LIBVMI         0x550002
#define XV_ARGP_CLEAR_MEM_CACHES   0x550003
#define XV_ARGP_MEMCACHE_MMAP_SIZE 0x550004

struct argp_option xen_vm_argp_opts[] = {
    /* These options set a flag. */
    { "domain",'m',"DOMAIN",0,"The Xen domain ID or name.",-4 },
    { "kernel-filename",'K',"FILE",0,
          "Override xenstore kernel filepath for guest.",-4 },
    { "no-clear-hw-debug-regs",'H',NULL,0,
          "Don't clear hardware debug registers at target attach.",-4 },
    { "clear-mem-caches-each-exception",XV_ARGP_CLEAR_MEM_CACHES,NULL,0,
          "Clear mem caches on each debug exception.",-4 },
#ifdef ENABLE_LIBVMI
    { "use-libvmi",XV_ARGP_USE_LIBVMI,NULL,0,
          "Clear mem caches on each debug exception.",-4 },
#endif
#ifdef ENABLE_XENACCESS
    { "use-xenaccess",XV_ARGP_USE_XENACCESS,NULL,0,
          "Clear mem caches on each debug exception.",-4 },
#endif
    { "memcache-mmap-size",XV_ARGP_MEMCACHE_MMAP_SIZE,"BYTES",0,
          "Max size (bytes) of the mmap cache (default 128MB).",-4 },
    { "no-hvm-setcontext",'V',NULL,0,
          "Don't use HVM-specific libxc get/set context functions to access"
          "virtual CPU info.",-4 },
    { "configfile",'c',"FILE",0,"The Xen config file.",-4 },
    { "replaydir",'r',"DIR",0,"The XenTT replay directory.",-4 },
    { "no-use-multiplexer",'M',NULL,0,"Do not spawn/attach to the Xen multiplexer server",-4 },
    { "dominfo-timeout",'T',"MICROSECONDS",0,"If libxc gets a \"NULL\" dominfo status, the number of microseconds we should keep retrying",-4 },
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
    if (xspec->kernel_filename) 
	ac += 2;
    if (xspec->no_hw_debug_reg_clear)
	ac += 1;
    if (xspec->no_hvm_setcontext)
	ac += 1;
    if (xspec->clear_mem_caches_each_exception)
	ac += 1;
#ifdef ENABLE_LIBVMI
    if (xspec->use_libvmi)
	ac += 1;
#endif
#ifdef ENABLE_XENACCESS
    if (xspec->use_xenaccess)
	ac += 1;
#endif
    if (xspec->memcache_mmap_size)
	ac += 2;
    if (xspec->config_file)
	ac += 2;
    if (xspec->replay_dir)
	ac += 2;
    if (xspec->no_use_multiplexer)
	ac += 1;
    if (xspec->dominfo_timeout > 0)
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
    if (xspec->no_hw_debug_reg_clear) {
	av[j++] = strdup("--no-clear-hw-debug-regs");
    }
    if (xspec->no_hvm_setcontext) {
	av[j++] = strdup("--no-hvm-setcontext");
    }
    if (xspec->clear_mem_caches_each_exception) {
	av[j++] = strdup("--clear-mem-caches-each-exception");
    }
#ifdef ENABLE_LIBVMI
    if (xspec->use_libvmi)
	av[j++] = strdup("--use-libvmi");
#endif
#ifdef ENABLE_XENACCESS
    if (xspec->use_xenaccess)
	av[j++] = strdup("--use-xenaccess");
#endif
    if (xspec->memcache_mmap_size) {
	av[j++] = strdup("--memcache-mmap-size");
	av[j] = malloc(32);
	snprintf(av[j],32,"%lu",xspec->memcache_mmap_size);
	j++;
    }
    if (xspec->config_file) {
	av[j++] = strdup("-c");
	av[j++] = strdup(xspec->config_file);
    }
    if (xspec->replay_dir) {
	av[j++] = strdup("-r");
	av[j++] = strdup(xspec->replay_dir);
    }
    if (xspec->no_use_multiplexer) {
	av[j++] = strdup("--no-use-multiplexer");
    }
    if (xspec->dominfo_timeout > 0) {
	av[j++] = strdup("-T");
	av[j] = malloc(16);
	snprintf(av[j],16,"%d",xspec->dominfo_timeout);
	j++;
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
	    xspec = xen_vm_build_spec();
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
    case 'H':
	xspec->no_hw_debug_reg_clear = 1;
	break;
    case 'V':
	xspec->no_hvm_setcontext = 1;
	break;
    case 'c':
	xspec->config_file = strdup(arg);
	break;
    case XV_ARGP_CLEAR_MEM_CACHES:
	xspec->clear_mem_caches_each_exception = 1;
	break;
#ifdef ENABLE_LIBVMI
    case XV_ARGP_USE_LIBVMI:
	xspec->use_libvmi = 1;
	break;
#endif
#ifdef ENABLE_XENACCESSS
    case XV_ARGP_USE_XENACCESS:
	xspec->use_xenaccess = 1;
	break;
#endif
    case XV_ARGP_MEMCACHE_MMAP_SIZE:
	xspec->memcache_mmap_size = atoi(arg);
	break;
    case 'r':
	xspec->replay_dir = strdup(arg);
	break;
    case 'M':
	xspec->no_use_multiplexer = 1;
	break;
    case 'T':
	xspec->dominfo_timeout = atoi(arg);
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
    /* default to 128MB. */
    xspec->memcache_mmap_size = 128 * 1024 * 1024;

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
			tmp = NULL;
			break;
		    }
		    else {
			verror("matching domain name for %s; but bad"
			       " domain id %s: %s\n",
			       tmp,domains[i],strerror(errno));
			free(tmp);
			tmp = NULL;
			goto errout;
		    }
		}
		else {
		    if (have_id)
			free(xstate->name);
		    xstate->name = strdup(tmp);
		    have_id = 1;
		    vdebug(4,LA_TARGET,LF_XV,"dom %d (from %s) matches id\n",
			   xstate->id,domain);
		}
	    }
	    else if (tmp) {
		free(tmp);
		tmp = NULL;
	    }
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
    else {
	snprintf(buf,PATH_MAX,"%s/image/ostype",xstate->vmpath);
	xstate->ostype = xs_read(xsh,xth,buf,NULL);
	if (!xstate->ostype) {
	    vwarn("could not read ostype for dom %d; may cause problems!\n",
		  xstate->id);
	    g_hash_table_insert(target->config,strdup("VM_TYPE"),
				strdup("paravirt"));
	}
	else if (strcmp(xstate->ostype,"hvm") == 0) {
	    xstate->hvm = 1;
	    g_hash_table_insert(target->config,strdup("VM_TYPE"),
				strdup("hvm"));
	}
	else {
	    g_hash_table_insert(target->config,strdup("OS_TYPE"),
				strdup(xstate->ostype));
	    g_hash_table_insert(target->config,strdup("VM_TYPE"),
				strdup("paravirt"));
	}

	snprintf(buf,PATH_MAX,"%s/image/kernel",xstate->vmpath);
	xstate->kernel_filename = xs_read(xsh,xth,buf,NULL);
	if (!xstate->kernel_filename)
	    vwarn("could not read kernel for dom %d; may cause problems!\n",
		  xstate->id);
	else {
	    g_hash_table_insert(target->config,strdup("OS_KERNEL_FILENAME"),
				strdup(xstate->kernel_filename));
	}
    }

    if (xspec->kernel_filename) {
	vdebug(1,LA_TARGET,LF_XV,
	       "using kernel filename %s (overrides %s from xenstore)\n",
	       xspec->kernel_filename,xstate->kernel_filename ? xstate->kernel_filename : "''");

	if (xstate->kernel_filename)
	    free(xstate->kernel_filename);

	xstate->kernel_filename = strdup(xspec->kernel_filename);

	g_hash_table_remove(target->config,"OS_KERNEL_FILENAME");
	g_hash_table_insert(target->config,strdup("OS_KERNEL_FILENAME"),
			    strdup(xstate->kernel_filename));
    }

    if (xsh) {
	xs_daemon_close(xsh);
	xsh = NULL;
    }

    free(buf);
    buf = NULL;

    /*
     * Try to infer the personality.
     */
    if (!target->personality_ops
	&& xstate->kernel_filename
	&& (strstr(xstate->kernel_filename,"inux")
	    || strstr(xstate->kernel_filename,"inuz"))) {
	if (target_personality_attach(target,"os_linux_generic",NULL) == 0) {
	    vdebug(3,LA_TARGET,LF_XV,
		   "autoinitialized the os_linux_generic personality!\n");
	}
	else {
	    verror("failed to autoinitialize the os_linux_generic personality!\n");
	    goto errout;
	}
    }
    else {
	vwarn("cannot initialize a personality!\n");
    }

    target->live = 1;
    target->writeable = 1;
    target->mmapable = 0; /* XXX: change this once we get mmap API
			     worked out. */

    /*
     * Now load up our {xa|vmi}_instance as much as we can now; we'll
     * try to do more when we load the debuginfo file for the kernel.
     */
    xstate->memops = NULL;
#ifdef ENABLE_LIBVMI
    if (!xstate->memops && xspec->use_libvmi)
	xstate->memops = &xen_vm_mem_ops_libvmi;
#endif
#ifdef ENABLE_XENACCESS
    if (!xstate->memops && xspec->use_xenaccess)
	xstate->memops = &xen_vm_mem_ops_xenaccess;
#endif
    if (!xstate->memops)
	xstate->memops = &xen_vm_mem_ops_builtin;

    if (xstate->memops->init) {
	if (xstate->memops->init(target)) {
	    verror("failed to init memops!\n");
        goto errout;
    }
    }

    /* Our threads can have two contexts -- kernel and user spaces. */
    target->max_thread_ctxt = THREAD_CTXT_USER;

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
    if (xstate->vmpath) {
	free(xstate->vmpath);
	xstate->vmpath = NULL;
    }
    if (xstate->ostype) {
	free(xstate->ostype);
	xstate->ostype = NULL;
    }
    if (xstate->name) {
	free(xstate->name);
	xstate->name = NULL;
    }
    if (xsh)
	xs_daemon_close(xsh);
    if (xstate) {
	free(xstate);
	if (target)
	    target->state = NULL;
    }
    if (target)
	target_free(target);

    return NULL;
}

/**
 ** Utility functions.
 **/

static int xen_vm_load_dominfo(struct target *target) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)(target->state);
    struct xen_vm_spec *xspec = (struct xen_vm_spec *)target->spec->backend_spec;
    long total,waited;
    /*
     * Wait for 10us repeatedly if dominfo doesn't return what we think
     * it should.  10us is arbitrary, but a mid-granularity compromise.
     */
    long interval = 10;
    struct timeval itv = { 0,0 };
    int rc;

    if (!xstate->dominfo_valid) {
        vdebug(4,LA_TARGET,LF_XV,
	       "load dominfo; current dominfo is invalid\n");
	memset(&xstate->dominfo,0,sizeof(xstate->dominfo));
	if (xc_domain_getinfo(xc_handle,xstate->id,1,
			      &xstate->dominfo) <= 0) {
	    verror("could not get dominfo for %d\n",xstate->id);
	    errno = EINVAL;
	    return -1;
	}

	waited = 0;
	total = (xspec->dominfo_timeout > 0) ? xspec->dominfo_timeout : 0;

	while (!xstate->dominfo.dying && !xstate->dominfo.crashed
	       && !xstate->dominfo.shutdown && !xstate->dominfo.paused
	       && !xstate->dominfo.blocked && !xstate->dominfo.running
	       && (total - waited) > 0) {
	    vwarnopt(5,LA_TARGET,LF_XV,"domain %d has no status!\n",xstate->id);

	    itv.tv_sec = 0;
	    itv.tv_usec = (interval > (total - waited)) \
		? (total - waited) : interval;

	    rc = select(0,NULL,NULL,NULL,&itv);
	    if (rc < 0) {
		if (errno != EINTR) {
		    verror("select(dominfo retry): %s\n",strerror(errno));
		    return -1;
		}
		else {
		    /* Assume itv timer has expired -- even though it
		     * may not have, of course, since select() errored
		     * and we can't trust the timer value.
		     */
		    itv.tv_usec = 0;
		}
	    }

	    waited += (interval - itv.tv_usec);

	    vdebug(8,LA_TARGET,LF_XV,
		   "waited %d of %d total microseconds to retry dominfo...\n",
		   waited,total);

	    if (xc_domain_getinfo(xc_handle,xstate->id,1,
				  &xstate->dominfo) <= 0) {
		verror("could not get dominfo for %d\n",xstate->id);
		errno = EINVAL;
		return -1;
	    }
	}

	/*
	 * Only do this once, and use libxc directly.
	 */
	if (unlikely(!xstate->live_shinfo)) {
	    xstate->live_shinfo = 
		xc_map_foreign_range(xc_handle,xstate->id,__PAGE_SIZE,PROT_READ,
				     xstate->dominfo.shared_info_frame);
	    if (!xstate->live_shinfo) {
		verror("could not mmap shared_info frame 0x%lx!\n",
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

static struct target_thread *__xen_vm_load_cached_thread(struct target *target,
							 tid_t tid) {
    struct target_thread *tthread;

    tthread = target_lookup_thread(target,tid);
    if (!tthread)
	return NULL;

    if (!tthread->valid)
	return xen_vm_load_thread(target,tid,0);

    return tthread;
}

static int __xen_vm_in_userspace(struct target *target,int cpl,REGVAL ipval) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;

    /*
     * This is a real pain.  We have to use kernel_start_addr because on
     * at least some Xen hypervisors, %cs is zeroed out, so we cannot
     * extract the CPL.  From my reading of the x86 and amd64 manuals,
     * it should not be zeroed out -- the segment selector registers are
     * only used for privilege levels in long mode.
     */
    if (xstate->kernel_start_addr && xstate->kernel_start_addr < ADDRMAX) {
	if (ipval < xstate->kernel_start_addr)
	    return 1;
	else
	    return 0;
    }
    else {
	if (cpl == 3)
	    return 1;
	else
	    return 0;
    }
}

static int __xen_get_cpl_thread(struct target *target,
				struct target_thread *tthread) {
    REG csr = -1;
    REGVAL cs;

    if (target->arch->type == ARCH_X86)
	csr = REG_X86_CS;
    else if (target->arch->type == ARCH_X86_64)
	csr = REG_X86_64_CS;

    /* Load the CPL. */
    errno = 0;
    cs = 0x3 & target_read_reg(target,tthread->tid,csr);
    if (errno) {
	verror("could not read CS register to find CPL!\n");
	return -1;
    }

    return (int)cs;
}

static int __xen_get_cpl(struct target *target,tid_t tid) {
    struct target_thread *tthread;

    if (!(tthread = __xen_vm_load_cached_thread(target,tid))) {
	if (!errno) 
	    errno = EINVAL;
	verror("could not load cached thread %"PRIiTID"\n",tid);
	return 0;
    }

    return __xen_get_cpl_thread(target,tthread);
}

static struct target_thread *xen_vm_load_thread(struct target *target,
						tid_t tid,int force) {
    struct target_thread *tthread = NULL;

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
     *
     * This means we must ask the personality to do it, because only the
     * personality can interpret the kernel stack.
     */
    return target_personality_load_thread(target,tid,force);
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
    struct xen_vm_spec *xspec = (struct xen_vm_spec *)target->spec->backend_spec;
#ifdef __x86_64__
    uint32_t size = 0;
    uint32_t offset = 0;
    struct hvm_save_descriptor *sdesc = NULL;
#endif
#ifdef XC_HAVE_CONTEXT_ANY
    vcpu_guest_context_any_t context_any;
#endif
    int ret;

    if (!xstate->hvm || xspec->no_hvm_setcontext) {
#ifdef XC_HAVE_CONTEXT_ANY
	ret = xc_vcpu_getcontext(xc_handle,xstate->id,
				 xstate->dominfo.max_vcpu_id,&context_any);
#else
	ret = xc_vcpu_getcontext(xc_handle,xstate->id,
				 xstate->dominfo.max_vcpu_id,context);
#endif
	if (ret < 0) {
	    verror("could not get vcpu context for %d\n",xstate->id);
	    return -1;
	}
#ifdef XC_HAVE_CONTEXT_ANY
	else
	    memcpy(context,&context_any.c,sizeof(*context));
#endif
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
    struct xen_vm_spec *xspec = (struct xen_vm_spec *)target->spec->backend_spec;
#ifdef XC_HAVE_CONTEXT_ANY
    vcpu_guest_context_any_t context_any;
#endif
    int ret;

    if (!xstate->hvm || xspec->no_hvm_setcontext) {
#ifdef XC_HAVE_CONTEXT_ANY
	memcpy(&context_any.c,context,sizeof(*context));
	ret = xc_vcpu_setcontext(xc_handle,xstate->id,
				 xstate->dominfo.max_vcpu_id,&context_any);
#else
	ret = xc_vcpu_setcontext(xc_handle,xstate->id,
				 xstate->dominfo.max_vcpu_id,context);
#endif
	if (ret < 0) {
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
    struct target_thread *tthread = NULL;
    struct xen_vm_thread_state *tstate = NULL;
    struct xen_vm_thread_state *gtstate;
    REGVAL ipval;
    uint64_t pgd = 0;
    int cpl;

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

    if (target_status(target) != TSTATUS_PAUSED) {
	verror("target not paused; cannot load current task!\n");
	errno = EBUSY;
	return NULL;
    }

    /*
     * The first thing to do is load the machine state into the global
     * thread, and set it as valid -- EVEN THOUGH we have not loaded
     * thread_info for it!  We must do this so that a whole bunch of
     * register reads can work via the API.
     */
    if (xen_vm_load_dominfo(target)) {
	verror("could not load dominfo!\n");
	errno = EFAULT;
	return NULL;
    }

    gtstate = (struct xen_vm_thread_state *)target->global_thread->state;

    /*
     * Only need to call xc if we haven't loaded this thread.
     */
    if (!target->global_thread->valid) {
	if (__xen_vm_cpu_getcontext(target,&gtstate->context) < 0) {
	    verror("could not get vcpu context for %d\n",xstate->id);
	    goto errout;
	}
    }

    /*
     * Load EIP for info, and CPL for user-mode check.
     *
     * NB: note that these two calls do *not* go through the target
     * API.  They cannot, because the global thread has not been loaded
     * yet.  And we can't finish loading the global thread yet, even
     * though we have the machine state, because we don't know which
     * thread context's regcache to put the machine state into (kernel
     * or userspace).
     */
    errno = 0;
#ifdef __x86_64__
    ipval = gtstate->context.user_regs.rip;
#else
    ipval = gtstate->context.user_regs.eip;
#endif

    cpl = 0x3 & gtstate->context.user_regs.cs;

    /* Keep loading the global thread... */
    if(!target->global_thread->valid) {
	if (__xen_vm_in_userspace(target,cpl,ipval))
	    target->global_thread->tidctxt = THREAD_CTXT_USER;
	else
	    target->global_thread->tidctxt = THREAD_CTXT_KERNEL;

	/*
	 * Push the registers into the regcache!
	 */
	__xen_vm_vcpu_to_thread_regcache(target,&gtstate->context,
					 target->global_thread,
					 target->global_thread->tidctxt);

	/*
	 * Very important.  If thread is in userspace, we need to get
	 * Xen's special kernel_sp register and set it as SP for the
	 * kernel context so that personalities can load kernel threads
	 * on i386 because they need kernel_sp to find the stack.  On
	 * x86_64 this is not necessary.
	 */
	if (target->global_thread->tidctxt == THREAD_CTXT_USER) {
	    target_regcache_init_reg_tidctxt(target,target->global_thread,
					     THREAD_CTXT_KERNEL,target->spregno,
					     gtstate->context.kernel_sp);
	}

	/*
	 * NB: we must set the thread as valid now, because the next few
	 * function calls are going to try to use the target API to read
	 * registers from the global thread.  So even through we're
	 * technically still loading it, mark it as valid now... it'll
	 * be fully valid shortly!
	 */
	target->global_thread->valid = 1;
	target_thread_set_status(target->global_thread,THREAD_STATUS_RUNNING);
    }

    /*
     * Load CR3 for debug purposes.
     */
    __xen_vm_pgd(target,TID_GLOBAL,&pgd);

    vdebug(9,LA_TARGET,LF_XV,
	   "loading current thread (ip = 0x%"PRIxADDR",pgd = 0x%"PRIxADDR","
	   "cpl = %d,tidctxt = %d)\n",ipval,pgd,cpl,
	   target->global_thread->tidctxt);

    /*
     * If only loading the global thread, stop here.
     */
    if (globalonly) 
	return target->global_thread;

    /*
     * Ask the personality to detect our current thread.
     */
    tthread = target_personality_load_current_thread(target,force);

    /*
     * Set the current thread (might be a real thread, or the global
     * thread).  If the personality detects a current thread, use it;
     * otherwise we have to just use the global thread!
     */
    if (tthread) {
	target->current_thread = tthread;

	/*
	 * We want to set the current thread's context to whatever the
	 * global thread was detected to be in.  Enforce our will, no
	 * matter what the personality does!
	 */
	if (tthread->tidctxt != target->global_thread->tidctxt) {
	    vwarn("personality set current thread context to %d; global thread"
		  " context is %d; forcing current to global!\n",
		  tthread->tidctxt,target->global_thread->tidctxt);
	    tthread->tidctxt = target->global_thread->tidctxt;
	}

	/*
	 * Now, copy in the machine state.  Be careful -- if we have not
	 * allocated tthread->state yet, allocate it now!
	 */
	tstate = (struct xen_vm_thread_state *)tthread->state;
	if (!tstate)
	    tthread->state = tstate = \
		(struct xen_vm_thread_state *)calloc(1,sizeof(*tstate));

	memcpy(&tstate->context,&gtstate->context,sizeof(gtstate->context));

	/* Also update the regcache for the current thread. */
	target_regcache_copy_all(target->global_thread,
				 target->global_thread->tidctxt,
				 tthread,tthread->tidctxt);
    }
    else
	target->current_thread = target->global_thread;

    target_thread_set_status(target->current_thread,THREAD_STATUS_RUNNING);

    vdebug(4,LA_TARGET,LF_XV,
	   "debug registers (vcpu context): 0x%"PRIxADDR",0x%"PRIxADDR
	   ",0x%"PRIxADDR",0x%"PRIxADDR",0,0,0x%"PRIxADDR",0x%"PRIxADDR"\n",
	   gtstate->context.debugreg[0],gtstate->context.debugreg[1],
	   gtstate->context.debugreg[2],gtstate->context.debugreg[3],
	   gtstate->context.debugreg[6],gtstate->context.debugreg[7]);

    /* Mark its state as valid in our cache. */
    tthread->valid = 1;

    return tthread;

 errout:
    /* XXX: should we really set this here? */
    target->current_thread = target->global_thread;

    vwarn("error loading current thread; trying to use default thread\n");
    errno = 0;

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
    free(state);
}

static int xen_vm_snprintf(struct target *target,char *buf,int bufsiz) {
    struct xen_vm_spec *xspec = \
	(struct xen_vm_spec *)target->spec->backend_spec;

    return snprintf(buf,bufsiz,"domain(%s)",xspec->domain);
}

static int xen_vm_init(struct target *target) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;
    struct xen_vm_thread_state *tstate;

    vdebug(5,LA_TARGET,LF_XV,"dom %d\n",xstate->id);

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
    xstate->dominfo.domid = 0;
    xstate->dominfo.dying = 0;
    xstate->dominfo.crashed = 0;
    xstate->dominfo.shutdown = 0;
    xstate->dominfo.paused = 0;
    xstate->dominfo.blocked = 0;
    xstate->dominfo.running = 0;
    xstate->dominfo.hvm = 0;
    xstate->dominfo.debugged = 0;
    xstate->dominfo.shutdown_reason = 0;
    xstate->dominfo.max_vcpu_id = 0;
    xstate->dominfo.shared_info_frame = 0;

    /* Create the default thread. */
    tstate = (struct xen_vm_thread_state *)calloc(1,sizeof(*tstate));

    target->global_thread = target_create_thread(target,TID_GLOBAL,tstate,NULL);
    /* Default thread is always running. */
    target_thread_set_status(target->global_thread,THREAD_STATUS_RUNNING);

    /* Create our default context now; update its region later. */
    target->global_tlctxt =
	target_location_ctxt_create(target,TID_GLOBAL,NULL);

    return 0;
}

#ifdef XENCTRL_HAS_XC_INTERFACE
int xen_vm_xc_attach(xc_interface **xc_handle,xc_interface **xce_handle) {
#else
int xen_vm_xc_attach(int *xc_handle,int *xce_handle) {
#endif

    if (xc_handle && *xc_handle == XC_IF_INVALID) {
#ifdef XENCTRL_HAS_XC_INTERFACE
	*xc_handle = xc_interface_open(NULL,NULL,0);
#else
	*xc_handle = xc_interface_open();
#endif
	if (*xc_handle == XC_IF_INVALID) {
	    verror("failed to open xc interface: %s\n",strerror(errno));
	    return -1;
	}
    }

    if (xce_handle && *xce_handle == XC_IF_INVALID) {
#ifdef XENCTRL_HAS_XC_INTERFACE
	*xce_handle = xc_evtchn_open(NULL,0);
#else
	*xce_handle = xc_evtchn_open();
#endif
	if (*xce_handle == XC_IF_INVALID) {
	    verror("failed to open event channel: %s\n",strerror(errno));
	    return -1;
	}
    }

    return 0;
}

#ifdef XENCTRL_HAS_XC_INTERFACE
int xen_vm_xc_detach(xc_interface **xc_handle,xc_interface **xce_handle)
#else
int xen_vm_xc_detach(int *xc_handle,int *xce_handle)
#endif
{
    if (xc_handle && *xc_handle != XC_IF_INVALID) {
	xc_interface_close(*xc_handle);
	*xc_handle = XC_IF_INVALID;
    }

    if (xce_handle && *xce_handle != XC_IF_INVALID) {
	xc_evtchn_close(*xce_handle);
	*xce_handle = XC_IF_INVALID;
    }

    return 0;
}

#ifdef XENCTRL_HAS_XC_INTERFACE
int xen_vm_virq_attach(xc_interface *xce_handle,XC_EVTCHN_PORT_T *dbg_port)
#else
int xen_vm_virq_attach(int xce_handle,XC_EVTCHN_PORT_T *dbg_port)
#endif
{
    if (dbg_port && *dbg_port == -1) {
	*dbg_port = xc_evtchn_bind_virq(xce_handle,VIRQ_DEBUGGER);
	/* Try to cast dbg_port to something signed.  Old xc versions
	 * have a bug in that evtchn_port_t is declared as uint32_t, but
	 * the function prototypes that return them can theoretically
	 * return -1.  So, try to test for that...
	 */
	if ((int32_t)*dbg_port < 0) {
	    verror("failed to bind debug virq port: %s",strerror(errno));
	    return -1;
	}
    }

    return 0;
}

#ifdef XENCTRL_HAS_XC_INTERFACE
int xen_vm_virq_detach(xc_interface *xce_handle,XC_EVTCHN_PORT_T *dbg_port)
#else
int xen_vm_virq_detach(int xce_handle,XC_EVTCHN_PORT_T *dbg_port)
#endif
{
    if (dbg_port && *dbg_port != -1) {
	if (xc_evtchn_unbind(xce_handle,(evtchn_port_t)*dbg_port)) {
	    verror("failed to unbind debug virq port\n");
	    return -1;
	}

	*dbg_port = -1;
    }

    return 0;
}

int xen_vm_vmp_attach(char *path,int *cfd,char **cpath) {
    struct stat sbuf;
    struct sockaddr_un sun,sun_client;
    char *tmpdir;
    char *spath;
    int spath_len,cpath_len;
    int len;

    assert(cfd);
    assert(cpath);

    if (cfd && *cfd != -1)
	return 0;

    if (!path) {
	/*
	 * Just try /var/run or TMPDIR or /tmp or .
	 */
	if (stat("/var/run",&sbuf) == 0 
	    && S_ISDIR(sbuf.st_mode) && access("/var/run",W_OK) == 0) {
	    spath_len = strlen("/var/run") + 1 + strlen(TARGET_XV_VMP_SOCKET_FILENAME) + 1;
	    spath = malloc(spath_len);
	    snprintf(spath,spath_len,"%s/%s","/var/run",TARGET_XV_VMP_SOCKET_FILENAME);
	}
	else if ((tmpdir = getenv("TMPDIR"))
		 && stat(tmpdir,&sbuf) == 0 && access(tmpdir,W_OK) == 0) {
	    spath_len = strlen(tmpdir) + 1 + strlen(TARGET_XV_VMP_SOCKET_FILENAME) + 1;
	    spath = malloc(spath_len);
	    snprintf(spath,spath_len,"%s/%s",tmpdir,TARGET_XV_VMP_SOCKET_FILENAME);
	}
	else if (stat("/tmp",&sbuf) == 0 
		 && S_ISDIR(sbuf.st_mode) && access("/tmp",W_OK) == 0) {
	    spath_len = strlen("/tmp") + 1 + strlen(TARGET_XV_VMP_SOCKET_FILENAME) + 1;
	    spath = malloc(spath_len);
	    snprintf(spath,spath_len,"%s/%s","/tmp",TARGET_XV_VMP_SOCKET_FILENAME);
	}
	else {
	    spath_len = strlen(".") + 1 + strlen(TARGET_XV_VMP_SOCKET_FILENAME) + 1;
	    spath = malloc(spath_len);
	    snprintf(spath,spath_len,"%s/%s",".",TARGET_XV_VMP_SOCKET_FILENAME);
	}
    }
    else
	spath = strdup(path);

    memset(&sun,0,sizeof(sun));
    sun.sun_family = AF_UNIX;
    snprintf(sun.sun_path,UNIX_PATH_MAX,"%s",spath);

    /*
     * The server only accepts path-bound unix domain socket
     * connections, so bind one and do it.  Try to use the same basedir
     * as in @spath; else use TMPDIR or /tmp or .
     */
    if (1) {
	dirname(spath);

	cpath_len = strlen(spath) + 1
	    + strlen(TARGET_XV_VMP_SOCKET_CLIENT_FILE_FORMAT)
	    + TARGET_XV_VMP_SOCKET_CLIENT_FILE_FORMAT_EXTRA + 1;
	*cpath = malloc(cpath_len);

	snprintf(*cpath,cpath_len,"%s/" TARGET_XV_VMP_SOCKET_CLIENT_FILE_FORMAT,
		 spath,getpid());
	if (open(*cpath,O_CREAT | O_RDWR,S_IRUSR | S_IWUSR) < 0) {
	    vwarnopt(6,LA_TARGET,LF_XV,
		     "could not open client VMP socket file %s: %s\n",
		     *cpath,strerror(errno));
	    free(*cpath);
	    *cpath = NULL;
	}
	unlink(*cpath);
    }

    if (cpath[0] == '\0' && (tmpdir = getenv("TMPDIR"))) {
	cpath_len = strlen(tmpdir) + 1
	    + strlen(TARGET_XV_VMP_SOCKET_CLIENT_FILE_FORMAT)
	    + TARGET_XV_VMP_SOCKET_CLIENT_FILE_FORMAT_EXTRA + 1;
	*cpath = malloc(cpath_len);

	snprintf(*cpath,cpath_len,"%s/" TARGET_XV_VMP_SOCKET_CLIENT_FILE_FORMAT,
		 tmpdir,getpid());
	if (open(*cpath,O_CREAT | O_RDWR,S_IRUSR | S_IWUSR) < 0) {
	    vwarnopt(6,LA_TARGET,LF_XV,
		     "could not open client VMP socket file %s: %s\n",
		     *cpath,strerror(errno));
	    free(*cpath);
	    *cpath = NULL;
	}
	unlink(*cpath);
    }

    if (cpath[0] == '\0') {
	cpath_len = strlen("/tmp") + 1
	    + strlen(TARGET_XV_VMP_SOCKET_CLIENT_FILE_FORMAT)
	    + TARGET_XV_VMP_SOCKET_CLIENT_FILE_FORMAT_EXTRA + 1;
	*cpath = malloc(cpath_len);

	snprintf(*cpath,cpath_len,"%s/" TARGET_XV_VMP_SOCKET_CLIENT_FILE_FORMAT,
		 "/tmp",getpid());
	if (open(*cpath,O_CREAT | O_RDWR,S_IRUSR | S_IWUSR) < 0) {
	    vwarnopt(6,LA_TARGET,LF_XV,
		     "could not open client VMP socket file %s: %s\n",
		     *cpath,strerror(errno));
	    free(*cpath);
	    *cpath = NULL;
	}
	unlink(*cpath);
    }

    if (cpath[0] == '\0') {
	cpath_len = strlen(".") + 1
	    + strlen(TARGET_XV_VMP_SOCKET_CLIENT_FILE_FORMAT)
	    + TARGET_XV_VMP_SOCKET_CLIENT_FILE_FORMAT_EXTRA + 1;
	*cpath = malloc(cpath_len);

	snprintf(*cpath,cpath_len,"%s/" TARGET_XV_VMP_SOCKET_CLIENT_FILE_FORMAT,
		 ".",getpid());
	if (open(*cpath,O_CREAT | O_RDWR,S_IRUSR | S_IWUSR) < 0) {
	    vwarnopt(6,LA_TARGET,LF_XV,
		     "could not open client VMP socket file %s: %s\n",
		     *cpath,strerror(errno));
	    free(*cpath);
	    *cpath = NULL;
	}
	unlink(*cpath);
    }

    if (!*cpath) {
	verror("could not open a client VMP socket file; aborting!\n");
	goto err;
    }

    memset(&sun_client,0,sizeof(sun_client));
    sun_client.sun_family = AF_UNIX;
    snprintf(sun_client.sun_path,UNIX_PATH_MAX,"%s",*cpath);

    *cfd = socket(AF_UNIX,SOCK_STREAM,0);
    if (*cfd < 0) {
	verror("socket(): %s\n",strerror(errno));
	goto err;
    }
    len = offsetof(struct sockaddr_un,sun_path) + strlen(sun_client.sun_path);
    if (bind(*cfd,&sun_client,len) < 0) {
	verror("bind(%s): %s\n",sun_client.sun_path,strerror(errno));
	goto err;
    }
    if (fchmod(*cfd,S_IRUSR | S_IWUSR) < 0) {
	verror("chmod(%s): %s\n",sun_client.sun_path,strerror(errno));
	goto err;
    }

    len = offsetof(struct sockaddr_un,sun_path) + strlen(sun.sun_path);
    if (connect(*cfd,&sun,len) < 0) {
	verror("connect(%s): %s\n",sun.sun_path,strerror(errno));
	goto err;
    }

    free(spath);

    return 0;

 err:
    *cfd = -1;
    if (*cpath)
	free(*cpath);
    *cpath = NULL;
    free(spath);

    return -1;
}

int xen_vm_vmp_detach(int *cfd,char **cpath) {
    if (cfd && *cfd != -1) {
	close(*cfd);
	*cfd = -1;
	if (cpath && *cpath) {
	    unlink(*cpath);
	    free(*cpath);
	    *cpath = NULL;
	}
    }

    return 0;
}

int xen_vm_vmp_launch() {
    int rc;

    rc = system(TARGET_XV_VMP_BIN_PATH);
    if (rc) {
	verror("system(%s): %s\n",TARGET_XV_VMP_BIN_PATH,strerror(errno));
	return -1;
    }

    return 0;
}

int xen_vm_virq_or_vmp_attach_or_launch(struct target *target) {
    struct xen_vm_spec *xspec = (struct xen_vm_spec *)target->spec->backend_spec;
    int i;
    int rc = -1;

    if (xspec->no_use_multiplexer)
	return xen_vm_virq_attach(xce_handle,&dbg_port);

    /* Try to connect.  If we can't, then launch, wait, and try again. */
    if (xen_vm_vmp_attach(NULL,&xen_vm_vmp_client_fd,&xen_vm_vmp_client_path)) {
	if (xen_vm_vmp_launch()) {
	    verror("could not launch Xen VIRQ_DEBUGGER multiplexer!\n");
	    return -1;
	}
	else {
	    vdebug(6,LA_TARGET,LF_XV,"launched Xen VIRQ_DEBUGGER multiplexer!\n");
	}

	for (i = 0; i < 5; ++i) {
	    rc = xen_vm_vmp_attach(NULL,&xen_vm_vmp_client_fd,
				   &xen_vm_vmp_client_path);
	    if (rc == 0)
		break;
	    else
		sleep(1);
	}

	if (rc) {
	    verror("could not connect to launched Xen VIRQ_DEBUGGER multiplexer!\n");
	    return -1;
	}
    }

    vdebug(6,LA_TARGET,LF_XV,"connected to Xen VIRQ_DEBUGGER multiplexer!\n");

    return 0;
}

int xen_vm_virq_or_vmp_detach() {
    if (dbg_port != -1) {
	xce_handle_fd = -1;
	return xen_vm_virq_detach(xce_handle,&dbg_port);
    }
    else
	return xen_vm_vmp_detach(&xen_vm_vmp_client_fd,
				 &xen_vm_vmp_client_path);
}

int xen_vm_virq_or_vmp_get_fd() {
    if (dbg_port != -1) {
	if (xce_handle_fd == -1)
	    xce_handle_fd = xc_evtchn_fd(xce_handle);
	return xce_handle_fd;
    }
    else
	return xen_vm_vmp_client_fd;
}

int xen_vm_virq_or_vmp_read(int *vmid) {
    XC_EVTCHN_PORT_T port = -1;
    struct target_xen_vm_vmp_client_response resp = { 0 };
    int retval;
    int rc;

    if (dbg_port != -1) {
	/* we've got something from eventchn. let's see what it is! */
	port = xc_evtchn_pending(xce_handle);

	/* unmask the event channel BEFORE doing anything else,
	 * like unpausing the target!
	 */
	retval = xc_evtchn_unmask(xce_handle, port);
	if (retval == -1) {
	    verror("failed to unmask event channel\n");
	    return -1;
	}

	if (port != dbg_port) {
	    *vmid = -1;
	    return 0;
	}
	else {
	    /* XXX: don't try to figure out which VM; must check them
	     * all; no infallible way to find out which one(s).
	     */
	    *vmid = 0;
	    return 0;
	}
    }
    else {
	rc = read(xen_vm_vmp_client_fd,&resp,sizeof(resp));
	if (rc < 0) {
	    if (errno == EINTR) {
		*vmid = -1;
		return 0;
	    }
	    return -1;
	}
	else if (rc == 0) {
	    return -1;
	}
	else if (rc != sizeof(resp)) {
	    return -1;
	}
	else {
	    *vmid = resp.vmid;
	    return 0;
	}
    }

    /* Not reached, despite what gcc thinks! */
    return -1;
}

static int xen_vm_attach_internal(struct target *target) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;
    struct xen_domctl domctl;
    struct addrspace *space;
    struct addrspace *tspace;
    struct target_thread *tthread;
    struct xen_vm_thread_state *xtstate;
    struct xen_vm_spec *xspec;

    xspec = (struct xen_vm_spec *)target->spec->backend_spec;

    domctl.cmd = XEN_DOMCTL_setdebugging;
    domctl.domain = xstate->id;
    domctl.u.setdebugging.enable = true;

    vdebug(5,LA_TARGET,LF_XV,"dom %d\n",xstate->id);

    /*
     * Always attach to XC.
     */
    if (xen_vm_xc_attach(&xc_handle,&xce_handle))
	return -1;

    /*
     * Connect to VIRQ_DEBUGGER, either through demultiplexer daemon, or
     * directly.  If daemon, launch or connect...
     */
    if (xen_vm_virq_or_vmp_attach_or_launch(target))
	return -1;

    /* NOT thread-safe! */
    ++xc_refcnt;

    if (xc_domctl(xc_handle,&domctl)) {
	verror("could not enable debugging of dom %d!\n",xstate->id);
        return -1;
    }

    /* Null out current state so we reload and see that it's paused! */
    xstate->dominfo_valid = 0;
    if (xen_vm_load_dominfo(target)) {
	verror("could not load dominfo for dom %d\n",xstate->id);
	return -1;
    }

    if (xen_vm_pause(target,0)) {
	verror("could not pause target before attaching; letting user handle!\n");
    }

    /*
     * Make sure memops is setup to read from memory.
     */
    if (xstate->memops && xstate->memops->attach) {
	if (xstate->memops->attach(target)) {
	    verror("could not attach memops!\n");
	return -1;
    }
    }

    if (target->evloop && xstate->evloop_fd < 0) {
	xen_vm_attach_evloop(target,target->evloop);
    }

    if (!xspec->no_hw_debug_reg_clear) {
	/*
	 * Null out hardware breakpoints, so that we don't try to infer that
	 * one was set, only to error because it's a software BP, not a
	 * hardware BP (even if the ip matches).  This can happen if you do
	 * one run with hw bps, then breakpoint the same ip with a sw bp.
	 * Good practice anyway!
	 */

	if (!(tthread = __xen_vm_load_cached_thread(target,TID_GLOBAL))) {
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
	target_flush_all_threads(target);
    }

    if (target->evloop && xstate->evloop_fd > -1)
	xen_vm_detach_evloop(target);

    if (xstate->memops->fini) {
	if (xstate->memops->fini(target)) {
	    verror("failed to fini memops; continuing anyway!\n");
	    return 0;
	}
    }

    if (xstate->live_shinfo)
	munmap(xstate->live_shinfo,__PAGE_SIZE);

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
	vdebug(4,LA_TARGET,LF_XV,"last domain; closing xc/xce interfaces.\n");

	if (xen_vm_virq_or_vmp_detach(xce_handle,&dbg_port))
	    verror("failed to unbind debug virq port\n");

	if (xen_vm_xc_detach(&xc_handle,&xce_handle))
	    verror("failed to close xc interfaces\n");
    }

    vdebug(3,LA_TARGET,LF_XV,"detach dom %d succeeded.\n",xstate->id);

    return 0;
}

static int xen_vm_fini(struct target *target) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)(target->state);

    vdebug(5,LA_TARGET,LF_XV,"dom %d\n",xstate->id);

    if (target->opened) 
	xen_vm_detach(target);

    if (xstate->vmpath)
	free(xstate->vmpath);
    if (xstate->kernel_filename)
	free(xstate->kernel_filename);
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
    struct memregion *region;
    struct memrange *range;
    char *kernel_filename;

    kernel_filename = 
	(char *)g_hash_table_lookup(target->config,"OS_KERNEL_FILENAME");

    region = memregion_create(space,REGION_TYPE_MAIN,kernel_filename);
    if (!region)
	return -1;
    range = memrange_create(region,0,ADDRMAX,0,
			    PROT_READ | PROT_WRITE | PROT_EXEC);
    if (!range)
	return -1;

    target->global_tlctxt->region = region;

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
    int bfn = 0;
    int bfpn = 0;

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
     * With Xen VMs, we can't always know what the vCPU is running as
     * from the xenstore.  For instance, with an HVM, we can't seem to
     * figure out whether it's running x86_64, x32, or i386 at all; we
     * have to load the kernel debuginfo binary to know.
     */
    if (!target->arch) {
	target->arch = debugfile->binfile->arch;
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
    int rc;
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;

    /*
     * We might not know this until now!  Which register is the fbreg is
     * dependent on host cpu type, not target cpu type.
     */
    if (target->arch->type == ARCH_X86_64) {
	target->fbregno = REG_X86_64_RBP;
	target->spregno = REG_X86_64_RSP;
	target->ipregno = REG_X86_64_RIP;
    }
    else {
	target->fbregno = REG_X86_EBP;
	target->spregno = REG_X86_ESP;
	target->ipregno = REG_X86_EIP;
    }

    rc = target_personality_postloadinit(target);
    if (rc < 0)
	return rc;

    char *start = (char *)g_hash_table_lookup(target->config,
					      "OS_KERNEL_START_ADDR");
    if (start)
	xstate->kernel_start_addr = strtoul(start,NULL,0);

    return 0;
}

static int xen_vm_postopened(struct target *target) {
    return target_personality_postopened(target);
}

static int xen_vm_set_active_probing(struct target *target,
				     active_probe_flags_t flags) {
    return target_personality_set_active_probing(target,flags);
}

static struct target *
xen_vm_instantiate_overlay(struct target *target,
			   struct target_thread *tthread,
			   struct target_spec *spec,
			   struct target_thread **ntthread) {
    struct target *overlay;
    REGVAL thip;
    tid_t ltid;
    struct target_thread *leader;

    if (spec->target_type != TARGET_TYPE_XEN_PROCESS) {
	errno = EINVAL;
	return NULL;
    }

    errno = 0;
    thip = target_read_reg(target,tthread->tid,target->ipregno);
    if (errno) {
	verror("could not read IP for tid %"PRIiTID"!!\n",tthread->tid);
	return NULL;
    }
    if (target_os_thread_is_user(target,tthread->tid) != 1) {
	errno = EINVAL;
	verror("tid %"PRIiTID" IP 0x%"PRIxADDR" is not a user thread!\n",
	       tthread->tid,thip);
	return NULL;
    }

    /*
     * Flip to the group leader if it is not this thread itself.
     */
    ltid = target_os_thread_get_leader(target,tthread->tid);
    leader = target_lookup_thread(target,ltid);
    if (!leader) {
	verror("could not load group_leader for thread %d; BUG?!\n",tthread->tid);
	return NULL;
    }
    else if (leader != tthread) {
	vdebug(5,LA_TARGET,LF_XV,
	       "using group_leader %d instead of user-supplied overlay thread %d\n",
	       leader->tid,tthread->tid);
	*ntthread = leader;
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

    retval = xen_vm_load_thread(target,id,0);
    if (!retval) {
	if (!errno)
	    errno = ESRCH;
	return NULL;
    }

    if (target_os_thread_is_user(target,retval->tid) == 1) {
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
    int slen;
    int rc;
    GHashTableIter iter;

    if ((rc = xen_vm_load_available_threads(target,0)))
	vwarn("could not load %d threads; continuing anyway!\n",-rc);

    g_hash_table_iter_init(&iter,target->threads);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer)&tthread)) {
	if (tthread == target->global_thread)
	    continue;

	if (!tthread->name) {
	    vwarn("tid %d does not have a name; continuing!\n",
		  tthread->tid);
	    continue;
	}

	slen = strlen(tthread->name);
	vdebug(8,LA_TARGET,LF_XV,
	       "checking task with name '%*s' against '%s'\n",
	       slen,tthread->name,name);
	if (strncmp(name,tthread->name,slen) == 0) {
	    retval = tthread;
	    break;
	}
    }

    if (retval) {
	if (target_os_thread_is_user(target,retval->tid) != 1) {
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

int xen_vm_attach_overlay_thread(struct target *base,struct target *overlay,
				 tid_t newtid) {
    tid_t cltid,nltid;

    nltid = target_os_thread_get_leader(base,newtid);
    cltid = target_os_thread_get_leader(base,overlay->base_thread->tid);

    if (nltid == -1 || cltid == -1)
	return -1;

    if (nltid == cltid)
	return 0;

    errno = EINVAL;
    return 1;
}

int xen_vm_detach_overlay_thread(struct target *base,struct target *overlay,
				 tid_t tid) {
    return 0;
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
    struct timeval check_tv = { 0,0};
    target_poll_outcome_t outcome;
    int pstatus;

    vdebug(5,LA_TARGET,LF_XV,"dom %d\n",xstate->id);

    if (xen_vm_load_dominfo(target)) 
	vwarn("could not load dominfo for dom %d, trying to pause anyway!\n",xstate->id);

    if (xstate->dominfo.paused) {
	if (target_get_status(target) != TSTATUS_PAUSED)
	    target_set_status(target,TSTATUS_PAUSED);
	else
	    return 0;
    }
    else if (xc_domain_pause(xc_handle,xstate->id)) {
	verror("could not pause dom %d!\n",xstate->id);
	return -1;
    }

    /*
     * Give the memops a chance to handle pause.
     */
    if (xstate->memops && xstate->memops->handle_pause) {
	xstate->memops->handle_pause(target);
    }

    target_set_status(target,TSTATUS_PAUSED);

    xstate->dominfo_valid = 0;
    if (xen_vm_load_dominfo(target)) 
	vwarn("could not reload dominfo for dom %d after pause!\n",xstate->id);

    /*
     * NB: very important.
     *
     * Since we allow pauses to be commanded asynchronously
     * w.r.t. target vm execution state, we have to check if there is
     * something to handle once we successfully pause it, and handle it
     * if so.  Otherwise if a target_pause() and debug exception happen
     * at the "same" time relative to the user, we might leave a debug
     * event unhandled, and this could whack the target.
     *
     * We pass in a 0,0 timeval so that the select() in xen_vm_poll
     * truly polls.
     *
     * Also note that we don't care what the outcome is.
     */
    xen_vm_poll(target,&check_tv,&outcome,&pstatus);

    return 0;
}

static int xen_vm_flush_current_thread(struct target *target) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)(target->state);
    struct target_thread *tthread;
    struct xen_vm_thread_state *tstate;
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
	   target_read_reg(target,TID_GLOBAL,target->ipregno),
	   xstate->id,tid);

    if (__xen_vm_thread_regcache_to_vcpu(target,tthread,tthread->tidctxt,
					 &tstate->context)) {
	verror("could not convert regcache to vcpu context(dom %d tid %"PRIiTID")\n",
	       xstate->id,tid);
	errno = EINVAL;
	return -1;
    }

    /*
     * Flush Xen machine context.
     */
    if (__xen_vm_cpu_setcontext(target,&tstate->context) < 0) {
	verror("could not set vcpu context (dom %d tid %"PRIiTID")\n",
	       xstate->id,tid);
	errno = EINVAL;
	return -1;
    }

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

    return target_personality_flush_current_thread(target);
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
    else {
	/*
	 * Always have to convert the global thread.
	 */
	if (__xen_vm_thread_regcache_to_vcpu(target,target->global_thread,
					     target->global_thread->tidctxt,
					     &gtstate->context)) {
	    verror("could not convert regcache to vcpu context"
		   " (dom %d tid %"PRIiTID") ctxt %d\n",
		   xstate->id,target->global_thread->tid,
		   target->global_thread->tidctxt);
	    errno = EINVAL;
	    return -1;
	}
    }

    if (!current_thread) {
	/* Flush the global thread's CPU context directly. */

	vdebug(5,LA_TARGET,LF_XV,"dom %d tid %"PRIiTID" (full global vCPU flush)\n",
	       xstate->id,gthread->tid);

	ctxp = &gtstate->context;

    }
    else {
	if (__xen_vm_thread_regcache_to_vcpu(target,target->current_thread,
					     target->current_thread->tidctxt,
					     &tstate->context)) {
	    verror("could not convert regcache to vcpu context"
		   " (dom %d tid %"PRIiTID") ctxt %d\n",
		   xstate->id,target->current_thread->tid,
		   target->current_thread->tidctxt);
	    errno = EINVAL;
	    return -1;
	}

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
	       target_read_reg(target,TID_GLOBAL,target->ipregno),
	       xstate->id,gthread->tid);
    }
    else {
	vdebug(3,LA_TARGET,LF_XV,
	       "EIP is 0x%"PRIxREGVAL" (in thread %"PRIiTID") before flush (dom %d tid %"PRIiTID")\n",
#ifdef __x86_64__
	       gtstate->context.user_regs.rip,
#else
	       gtstate->context.user_regs.eip,
#endif
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
    tthread = target_lookup_thread(target,tid);

    if (!tthread) {
	verror("cannot flush unknown thread %"PRIiTID"; you forgot to load?\n",
	       tid);
	errno = EINVAL;
	return -1;
    }

    if (tthread == target->current_thread)
	return xen_vm_flush_current_thread(target);

    if (!tthread->valid || !tthread->dirty) {
	vdebug(8,LA_TARGET,LF_XV,
	       "dom %d tid %"PRIiTID" not valid (%d) or not dirty (%d)\n",
	       xstate->id,tthread->tid,tthread->valid,tthread->dirty);
	return 0;
    }

    if (target_personality_flush_thread(target,tid))
	goto errout;

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

    v = target_load_value_member(target,target_global_tlctxt(target),
				 value,"pid",NULL,LOAD_FLAG_NONE);
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
    return target_personality_list_available_tids(target);
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

static int xen_vm_load_available_threads(struct target *target,int force) {
    /*
     * Load the current thread first to load the global thread.  The
     * current thread will get loaded again in the loop below if @force
     * is set...
     */
    if (!__xen_vm_load_current_thread(target,force,1)) {
	verror("could not load current thread!\n");
	return -1;
    }

    return target_personality_load_available_threads(target,force);
}

static int xen_vm_thread_snprintf(struct target_thread *tthread,
				  char *buf,int bufsiz,
				  int detail,char *sep,char *kvsep) {
    struct target *target = tthread->target;
    int rc = 0;
    int nrc;

    if (tthread == target->current_thread || tthread == target->global_thread) {
	rc = target_regcache_snprintf(target,tthread,tthread->tidctxt,
				      buf,bufsiz,detail,sep,kvsep,0);
	if (rc < 0)
	    return rc;
    }

    nrc = target_personality_thread_snprintf(tthread,
					     (rc >= bufsiz) ? NULL : buf + rc,
					     (rc >= bufsiz) ? 0 : bufsiz - rc,
					     detail,sep,kvsep);
    if (nrc < 0) {
	verror("could not snprintf personality info for thread %d!\n",
	       tthread->tid);
	return nrc;
    }

    return rc + nrc;
}

/**
 ** The arch-based thread snprintf is slower, so keep this older version
 ** around for now, but don't build it.
 **/
#if 0
static int xen_vm_thread_snprintf(struct target_thread *tthread,
				  char *buf,int bufsiz,
				  int detail,char *sep,char *kvsep) {
    struct xen_vm_thread_state *tstate;
    struct cpu_user_regs *r;
    int rc = 0;
    int nrc;

    if (detail < 0)
	goto personality_out;

    tstate = (struct xen_vm_thread_state *)tthread->state;
    if (!tstate)
	goto personality_out;

    r = &tstate->context.user_regs;

    if (detail >= 0) {
	;
    }

    if (detail >= 1)
	rc += snprintf((rc >= bufsiz) ? NULL : buf + rc,
		       (rc >= bufsiz) ? 0 :bufsiz - rc,
		       "%s" "ip%s%"RF "%s" "bp%s%"RF "%s" "sp%s%"RF "%s" 
		       "flags%s%"RF "%s" "ax%s%"RF "%s" "bx%s%"RF "%s"
		       "cx%s%"RF "%s" "dx%s%"RF "%s" "di%s%"RF "%s" 
		       "si%s%"RF "%s" "cs%s%d" "%s" "ss%s%d" "%s"
		       "ds%s%d" "%s" "es%s%d" "%s"
		       "fs%s%d" "%s" "gs%s%d",
#if __WORDSIZE == 64
		       sep,kvsep,r->rip,sep,kvsep,r->rbp,sep,kvsep,r->rsp,sep,
		       kvsep,r->eflags,sep,kvsep,r->rax,sep,kvsep,r->rbx,sep,
		       kvsep,r->rcx,sep,kvsep,r->rdx,sep,kvsep,r->rdi,sep,
		       kvsep,r->rsi,sep,kvsep,r->cs,sep,kvsep,r->ss,sep,
		       kvsep,r->ds,sep,kvsep,r->es,sep,
		       kvsep,r->fs,sep,kvsep,r->gs
#else
		       sep,kvsep,r->eip,sep,kvsep,r->ebp,sep,kvsep,r->esp,sep,
		       kvsep,r->eflags,sep,kvsep,r->eax,sep,kvsep,r->ebx,sep,
		       kvsep,r->ecx,sep,kvsep,r->edx,sep,kvsep,r->edi,sep,
		       kvsep,r->esi,sep,kvsep,r->cs,sep,kvsep,r->ss,sep,
		       kvsep,r->ds,sep,kvsep,r->es,sep,
		       kvsep,r->fs,sep,kvsep,r->gs
#endif
		       );
    if (detail >= 2)
	rc += snprintf((rc >= bufsiz) ? NULL : buf + rc,
		       (rc >= bufsiz) ? 0 :bufsiz - rc,
		       "%s" "dr0%s%"DRF "%s" "dr1%s%"DRF 
		       "%s" "dr2%s%"DRF "%s" "dr3%s%"DRF 
		       "%s" "dr6%s%"DRF "%s" "dr7%s%"DRF,
		       sep,kvsep,tstate->dr[0],sep,kvsep,tstate->dr[1],
		       sep,kvsep,tstate->dr[1],sep,kvsep,tstate->dr[2],
		       sep,kvsep,tstate->dr[6],sep,kvsep,tstate->dr[7]);

 personality_out:
    nrc = target_personality_thread_snprintf(tthread,
					     (rc >= bufsiz) ? NULL : buf + rc,
					     (rc >= bufsiz) ? 0 : bufsiz - rc,
					     detail,sep,kvsep);
    if (nrc < 0) {
	verror("could not snprintf personality info for thread %d!\n",
	       tthread->tid);
	return rc;
    }

    return rc + nrc;
}
#endif /* 0 */

static int xen_vm_invalidate_thread(struct target *target,
				    struct target_thread *tthread) {
    return target_personality_invalidate_thread(target,tthread);
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
	target_flush_all_threads(target);

	/* Invalidate our cached copies of threads. */
	target_invalidate_all_threads(target);
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

/*
 * If again is not NULL, we set again
 *   to -1 if there was an error, but we should try again;
 *   to 0 if not again;
 *   to 1 if just handled a bp and should try again;
 *   to 2 if just handled an ss and should try again.
 */
static target_status_t xen_vm_handle_exception(struct target *target,
					       int *again,void *priv) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;
    int cpl;
    REGVAL ipval;
    int dreg = -1;
    struct probepoint *dpp;
    struct target_thread *tthread;
    tid_t overlay_leader_tid;
    struct xen_vm_thread_state *gtstate;
    struct xen_vm_thread_state *xtstate;
    tid_t tid;
    struct probepoint *spp;
    struct target_thread *sstep_thread;
    struct target_thread *bogus_sstep_thread;
    ADDR bogus_sstep_probepoint_addr;
    struct target *overlay;
    GHashTableIter iter;
    gpointer vp;
    struct target_memmod *pmmod;
    ADDR paddr;
    REGVAL tmp_ipval;
    int rc;
    target_status_t tstatus;

    /* Reload our dominfo */
    xstate->dominfo_valid = 0;
    if (xen_vm_load_dominfo(target)) {
	verror("could not load dominfo; returning to user!\n");
	goto out_err;
    }

    tstatus = target_status(target);

    if (tstatus == TSTATUS_RUNNING) {
	vdebug(8,LA_TARGET,LF_XV,
	       "ignoring \"exception\" in our running VM %d; not for us\n",
	       xstate->id);
	if (again)
	    *again = 0;
	return tstatus;
    }
    else if (tstatus == TSTATUS_PAUSED) {
	target_clear_state_changes(target);

	vdebug(3,LA_TARGET,LF_XV,
	       "new debug event (brctr = %"PRIu64", tsc = %"PRIx64")\n",
	       xen_vm_get_counter(target),xen_vm_get_tsc(target));

	target->monitorhandling = 1;

	/* Force the current thread to be reloaded. */
	target->current_thread = NULL;

	/*
	 * Load the global thread (machine state) very first... we have
	 * to be able to read some register state!
	 */
	if (!__xen_vm_load_current_thread(target,0,1)) {
	    verror("could not load global thread!\n");
	    goto out_err;
	}

	/*
	 * Grab EIP and CPL first so we can see if we're in user or
	 * kernel space and print better messages.
	 */
	errno = 0;
	cpl = __xen_get_cpl(target,TID_GLOBAL);
	if (errno) {
	    verror("could not read CPL while checking debug event: %s\n",
		   strerror(errno));
	    goto out_err;
	}
	ipval = target_read_reg(target,TID_GLOBAL,target->ipregno);
	if (errno) {
	    verror("could not read EIP while checking debug event: %s\n",
		   strerror(errno));
	    goto out_err;
	}

	/*
	 * Give the personality a chance to update its state.
	 */
	target_personality_handle_exception(target);

	/* 
	 * Give the memops a chance to update.
	 */
	if (xstate->memops && xstate->memops->handle_exception_ours) {
	    xstate->memops->handle_exception_ours(target);
	}

	/* 
	 * Reload the current thread.  We don't force it because we
	 * flush all threads before continuing the loop via again:,
	 * or in target_resume/target_singlestep.
	 */
	xen_vm_load_current_thread(target,0);

	if (__xen_vm_in_userspace(target,cpl,ipval)) {
	    tthread = target->current_thread;

	    if (!tthread) {
		verror("could not load current userspace thread at 0x%"PRIxADDR"!\n",
		       ipval);
		goto out_err;
	    }

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
	     * If we are tracking thread exits, we have to nuke
	     * "exiting" threads.  See comments near
	     * xen_vm_active_thread_exit_handler .
	     */
	    if (target->active_probe_flags & ACTIVE_PROBE_FLAG_THREAD_EXIT) {
		g_hash_table_iter_init(&iter,target->threads);
		while (g_hash_table_iter_next(&iter,NULL,(gpointer *)&vp)) {
		    tthread = (struct target_thread *)vp;

		    if (!tthread->exiting) 
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
	    /*
	    if (g_hash_table_size(target->threads) > 32) {
		target_gc_threads(target);
	    }
	    */

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
	    || (xstate->hvm && xstate->hvm_monitor_trap_flag_set)
	    || (tthread->emulating_debug_mmod)) {
	    vdebug(3,LA_TARGET,LF_XV,"new single step debug event (MTF %d)\n",
		   xstate->hvm_monitor_trap_flag_set);

	    /*
	     * Three cases: 
	     * 1) We had to emulate a breakpoint/singlestep for a shared
	     * page breakpoint; or
	     * 2) we single-stepped an instruction that could have taken
	     * us to a userspace EIP; or  
	     * 3) somehow the kernel jumped to one!
	     */
	    if (tthread->emulating_debug_mmod) {
		//&& __xen_vm_in_userspace(target,cpl,ipval)) {
		/* This is a shared-page singlestep. */
		tmp_ipval = ipval - target->arch->breakpoint_instrs_len;

		vdebug(5,LA_TARGET,LF_XV,
		       "emulating debug memmod at ss for tid %"PRIiTID
		       " at paddr 0x%"PRIxADDR" (vaddr 0x%"PRIxADDR")\n",
		       tid,tthread->emulating_debug_mmod->addr,tmp_ipval);

		target_memmod_emulate_ss_handler(target,tid,
						 tthread->emulating_debug_mmod);

		/* Clear the status bits right now. */
		/*
		xtstate->context.debugreg[6] = 0;
		tthread->dirty = 1;

		gtstate->context.debugreg[6] = 0;
		target->global_thread->dirty = 1;
		vdebug(5,LA_TARGET,LF_XV,"cleared status debug reg 6\n");
		*/

		goto out_ss_again;
	    }
	    else if (target->sstep_thread 
		&& ((target->sstep_thread->tpc
		     && target->sstep_thread->tpc->probepoint->can_switch_context)
		    || (__xen_vm_in_userspace(target,cpl,ipval)
			&& !target->sstep_thread_overlay))) {
		sstep_thread = target->sstep_thread;
	    }
	    else if (target->sstep_thread
		     && target->sstep_thread_overlay) {
		if (__xen_vm_in_userspace(target,cpl,ipval)) {
		    vdebug(8,LA_TARGET,LF_XV,
			   "single step event in overlay tid %"PRIiTID
			   " (tgid %"PRIiTID"); notifying overlay\n",
			   tid,target->sstep_thread_overlay->base_tid);
		    return target_notify_overlay(target->sstep_thread_overlay,
						 tid,ipval,again);
		}
		else {
		    /*
		     * This is a thread that was stepping in userspace,
		     * and found itself in the kernel.  This can happen
		     * if we have to use HVM global monitor trap flag
		     * instead of EFLAGS TF.  Even if we had setup the
		     * MTF to single step the guest in userspace, that
		     * may not be what happens.  For instance, suppose
		     * the instruction causes a page fault, or that a
		     * clock interrupt happened.  We'll find ourselves
		     * stepping in the kernel, in its handlers, I
		     * believe.
		     *
		     * We assume the thread did *not* do its singlestep
		     * of the breakpoint's original instruction.  If it
		     * had, the EIP for the MTF event would still be in
		     * userspace -- because single step debug exceptions
		     * are traps following an instruction's execution.
		     * Thus, we need to put the breakpoint back into
		     * place and remove all state setup to handle it,
		     * EXCEPT to note down that this thread's overlay SS
		     * was interrupted at probepoint X, but that the
		     * prehandler was already run.  This way, we won't
		     * run the prehandler again.
		     *
		     * This of course is somewhat bogus, because it
		     * might affect vCPU state (we hit the BP twice
		     * instead of just once)... but whatever.
		     *
		     * See target_thread::interrupted_ss_probepoint .
		     */
		    vdebug(8,LA_TARGET,LF_XV,
			   "single step event in overlay tid %"PRIiTID
			   " (tgid %"PRIiTID") INTO KERNEL (at 0x%"PRIxADDR")"
			   " notifying overlay\n",
			   tid,target->sstep_thread_overlay->base_tid,ipval);
		    return target_notify_overlay(target->sstep_thread_overlay,
						 tid,ipval,again);
		}
	    }
	    else
		sstep_thread = NULL;

	    target->sstep_thread = NULL;

	    if (xtstate->context.user_regs.eflags & EF_TF
		|| (xstate->hvm && xstate->hvm_monitor_trap_flag_set)) {
	    handle_inferred_sstep:
		if (!tthread->tpc) {
		    if (sstep_thread && __xen_vm_in_userspace(target,cpl,ipval)) {
			vwarn("single step event (status reg and eflags) into"
			      " userspace; trying to handle in sstep thread"
			      " %"PRIiTID"!\n",sstep_thread->tid);
			goto handle_sstep_thread;
		    }
		    else {
			target->ops->handle_step(target,tthread,NULL);

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
		 * handle_step may clear tpc.
		 */
		spp = tthread->tpc->probepoint;

		target->ops->handle_step(target,tthread,tthread->tpc->probepoint);

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
		target->ops->handle_step(target,sstep_thread,
				   sstep_thread->tpc->probepoint);

		/* Clear the status bits right now. */
		xtstate->context.debugreg[6] = 0;
		tthread->dirty = 1;
		vdebug(5,LA_TARGET,LF_XV,"cleared status debug reg 6\n");

		goto out_ss_again;
	    }
	    else if (__xen_vm_in_userspace(target,cpl,ipval)) {
		verror("user-mode debug event (single step) at 0x%"PRIxADDR
		       "; debug status reg 0x%"DRF"; eflags 0x%"RF
		       "; skipping handling!\n",
		       ipval,xtstate->context.debugreg[6],
		       xtstate->context.user_regs.eflags);
		goto out_err_again;
	    }
	    else {
		target->ops->handle_step(target,tthread,NULL);

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
			verror("DR6 said hw dbg reg %d at 0x%"DRF" was hit;"
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
		if (__xen_vm_in_userspace(target,cpl,ipval)) {
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
	    else if (__xen_vm_in_userspace(target,cpl,ipval)) {
		overlay = target_lookup_overlay(target,tid);

		/* If we didn't find one, try to find its leader as an overlay. */
		if (!overlay) {
		    overlay_leader_tid =
			target_os_thread_get_leader(target,tthread->tid);
		    overlay = target_lookup_overlay(target,overlay_leader_tid);
		    if (overlay) {
			vdebug(5,LA_TARGET,LF_XV,
			       "found yet-unknown thread %d with"
			       " overlay leader %d; will notify!\n",
			       tthread->tid,overlay_leader_tid);
		    }
		}

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
		    /*
		     * Try to lookup paddr for ipval; if it matches and
		     * hits as a memmod... then emulate a breakpoint.
		     *
		     * To do this, we must mark this kthread as
		     * emulating a breakpoint at a memmod; flip the
		     * memmod; then catch its  singlestep above; and
		     * flip the memmod back.
		     */

		    /* XXX: this is bad.  We use the base target's
		     * breakpoint_instr_len to try to detect an overlay!
		     * It's ok for Xen and the Xen-process overlay, but
		     * it's a definite abstraction breakdown.
		     */
		    tmp_ipval = ipval - target->arch->breakpoint_instrs_len;
		    rc = xen_vm_addr_v2p(target,TID_GLOBAL,tmp_ipval,&paddr);
		    if (!rc)
			pmmod = target_memmod_lookup(target,TID_GLOBAL,paddr,1);
		    if (!rc && pmmod) {
			/*
			 * Emulate it!
			 */
			vdebug(5,LA_TARGET,LF_XV,
			       "emulating debug memmod at bp for tid %"PRIiTID
			       " at paddr 0x%"PRIxADDR" (vaddr 0x%"PRIxADDR")\n",
			       tid,pmmod->addr,tmp_ipval);
			       
			if (target_memmod_emulate_bp_handler(target,tid,pmmod)) {
			    verror("could not emulate debug memmod for"
				   " tid %"PRIiTID" at paddr 0x%"PRIxADDR"\n",
				   tid,pmmod->addr);
			    goto out_err_again;
			}
			else {
			    /* Clear the status bits right now. */
			    xtstate->context.debugreg[6] = 0;
			    tthread->dirty = 1;

			    gtstate->context.debugreg[6] = 0;
			    target->global_thread->dirty = 1;
			    vdebug(5,LA_TARGET,LF_XV,
				   "cleared status debug reg 6\n");

			    goto out_bp_again;
			}
		    }
		    else {
			verror("user-mode debug event (not single step, not"
			       " hw dbg reg) at 0x%"PRIxADDR"; debug status reg"
			       " 0x%"DRF"; eflags 0x%"RF"; skipping handling!\n",
			       tmp_ipval,xtstate->context.debugreg[6],
			       xtstate->context.user_regs.eflags);
			goto out_err_again;
		    }
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
		target->ops->handle_break(target,tthread,dpp,
					  xtstate->context.debugreg[6] & 0x4000);

		/* Clear the status bits right now. */
		xtstate->context.debugreg[6] = 0;
		tthread->dirty = 1;
		vdebug(5,LA_TARGET,LF_XV,"cleared status debug reg 6\n");

		goto out_bp_again;
	    }
	    else if ((dpp = (struct probepoint *) \
		      g_hash_table_lookup(target->soft_probepoints,
					  (gpointer)(ipval - target->arch->breakpoint_instrs_len)))) {
		/* Run the breakpoint handler. */
		target->ops->handle_break(target,tthread,dpp,
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
		 * We have to assume it's valid.  We can't do expensive
		 * stuff and see if it could have gotten here validly;
		 * we could have stepped a RET, IRET, anything.
		 */
		vdebug(2,LA_TARGET,LF_XV,
		       "inferred single step for dom %d (TF set, but not"
		       " dreg status!) at 0x%"PRIxADDR" (stepped %d bytes"
		       " from probepoint)!\n",
		       xstate->id,ipval,ipval - bogus_sstep_probepoint_addr);
		sstep_thread = bogus_sstep_thread;
		goto handle_inferred_sstep;
	    }
	    else if (xtstate->context.user_regs.eflags & EF_TF) {
	    //phantom:
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
    target->monitorhandling = 0;
    if (again)
	*again = 0;
    return TSTATUS_ERROR;

 out_err_again:
    target->monitorhandling = 0;
    if (again)
	*again = -1;
    return TSTATUS_ERROR;

 out_paused:
    target->monitorhandling = 0;
    if (again)
	*again = 0;
    return TSTATUS_PAUSED;

 out_bp_again:
    target->monitorhandling = 0;
    if (again)
	*again = 1;
    return TSTATUS_PAUSED;

 out_ss_again:
    target->monitorhandling = 0;
    if (again)
	*again = 2;
    return TSTATUS_PAUSED;
}

int xen_vm_evloop_handler(int readfd,int fdtype,void *state) {
    struct target *target = (struct target *)state;
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;
    int again;
    int retval;
    int vmid = -1;

    if (xen_vm_virq_or_vmp_read(&vmid)) {
	return EVLOOP_HRET_BADERROR;
    }

    if (vmid == -1)
	return EVLOOP_HRET_SUCCESS;

    if (vmid != 0 && vmid != xstate->id)
	return EVLOOP_HRET_SUCCESS;

    again = 0;
    retval = xen_vm_handle_exception(target,&again,NULL);
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
    xstate->evloop_fd = xen_vm_virq_or_vmp_get_fd();
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
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;
    int ret, fd;
    struct timeval tv;
    fd_set inset;
    int again;
    target_status_t retval;
    int vmid = -1;

    /* get a select()able file descriptor of the event channel */
    fd = xen_vm_virq_or_vmp_get_fd();
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

	if (xen_vm_virq_or_vmp_read(&vmid)) {
	    verror("failed to unmask event channel\n");
	    break;
	}

        /* we've got something from eventchn. let's see what it is! */
	if (vmid != 0 && vmid != xstate->id)
            continue; // not the event that we are looking for

	again = 0;
	retval = xen_vm_handle_exception(target,&again,NULL);
	if (retval == TSTATUS_ERROR && again == 0) {
	    target->needmonitorinterrupt = 0;
	    return retval;
	}
	else if (target->needmonitorinterrupt) {
	    target->needmonitorinterrupt = 0;
	    return TSTATUS_INTERRUPTED;
	}

	//else if (retval == TSTATUS_PAUSED && again == 0)
	//    return retval;
	
	if (xen_vm_load_dominfo(target)) {
	    vwarn("could not load dominfo for dom %d, trying to unpause anyway!\n",
		  xstate->id);
	    __xen_vm_resume(target,0);
	}
	else if (xstate->dominfo.paused) {
	    __xen_vm_resume(target,0);
	}
    }

    return TSTATUS_ERROR; /* Never hit, just compiler foo */
}

static target_status_t xen_vm_poll(struct target *target,struct timeval *tv,
				   target_poll_outcome_t *outcome,int *pstatus) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;
    int ret, fd;
    struct timeval itv;
    fd_set inset;
    int again;
    target_status_t retval;
    int vmid = -1;

    /* get a select()able file descriptor of the event channel */
    fd = xen_vm_virq_or_vmp_get_fd();
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

    if (xen_vm_virq_or_vmp_read(&vmid)) {
	verror("failed to unmask event channel\n");
	if (outcome)
	    *outcome = POLL_ERROR;
	return TSTATUS_ERROR;
    }

    /* we've got something from eventchn. let's see what it is! */
    if (vmid != 0 && vmid != xstate->id) {
	if (outcome)
	    *outcome = POLL_NOTHING;
	return TSTATUS_RUNNING; // not the event that we are looking for
    }

    again = 0;
    retval = xen_vm_handle_exception(target,&again,NULL);
    if (pstatus)
	*pstatus = again;

    return retval;
}

static unsigned char *xen_vm_read(struct target *target,ADDR addr,
				  unsigned long target_length,
				  unsigned char *buf) {
    return xen_vm_read_pid(target,TID_GLOBAL,addr,target_length,buf);
}

static unsigned long xen_vm_write(struct target *target,ADDR addr,
				  unsigned long length,unsigned char *buf) {
    return xen_vm_write_pid(target,TID_GLOBAL,addr,length,buf);
}

/*
 * We have to either load pgd from vcpu context (for a running task), or
 * from the task struct (for a swapped out task).
 *
 * NB: @cr3 will be a physical address, not a kernel virtual address.
 * The mm_struct contains a virtual address; but the CR3 register of
 * course contains a physical one.  And the CR3 content is not quite a
 * physical address, sometimes, it seems.
 */
static int __xen_vm_pgd(struct target *target,tid_t tid,uint64_t *pgd) {
    struct xen_vm_state *xstate;
    struct target_thread *tthread;
    struct xen_vm_thread_state *xtstate;
    REGVAL cr0 = 0,cr4 = 0,msr_efer = 0,cpuid_edx = 0;
    REG reg;

    xstate = (struct xen_vm_state *)target->state;

    if (tid == TID_GLOBAL) {
	tthread = __xen_vm_load_current_thread(target,0,1);
	if (!tthread) {
	    verror("could not load global thread!\n");
	    return -1;
	}
	xtstate = (struct xen_vm_thread_state *)tthread->state;

	if (xtstate->context.vm_assist & (1 << VMASST_TYPE_pae_extended_cr3)) {
	    *pgd = ((uint64_t)xen_cr3_to_pfn(xtstate->context.ctrlreg[3])) \
		       << XC_PAGE_SHIFT;
	}
	else {
	    *pgd = xtstate->context.ctrlreg[3] & ~(__PAGE_SIZE - 1);
	}

	/*
	 * XXX NB: Also load the current paging flags!  This seems to be
	 * the right place to do it... realistically, the flags are not
	 * going to change much except during boot... or in the future
	 * where there are nested HVMs!  I suppose, in the future, we'll
	 * have to have these set on a per-thread basis...
	 *
	 * (Pass cpuid_edx=REGVALMAX for now to make sure the NOPSE*
	 * bits don't get set -- until we actually bother to find the
	 * cpuid info.)
	 */
	cr0 = xtstate->context.ctrlreg[0];
	cr4 = xtstate->context.ctrlreg[4];
	if (xstate->hvm && xstate->hvm_cpu)
	    msr_efer = xstate->hvm_cpu->msr_efer;
	cpuid_edx = ADDRMAX;

	if (target_arch_x86_v2p_get_flags(target,cr0,cr4,msr_efer,
					  cpuid_edx,&xstate->v2p_flags)) {
	    if (target->arch->type == ARCH_X86_64) {
		verror("could not determine v2p_flags!  pgd walks might fail;"
		       " assuming 64-bit long mode and paging!\n");
		xstate->v2p_flags = ARCH_X86_V2P_LMA;
	    }
	    else {
		verror("could not determine v2p_flags!  pgd walks might fail;"
		       " assuming 32-bit mode and PAE (and auto-PSE)!\n");
		xstate->v2p_flags = ARCH_X86_V2P_PAE;
	    }
	}

	if (vdebug_is_on(8,LA_TARGET,LF_XV)) {
	    char buf[256];
	    buf[0] = '\0';
	    target_arch_x86_v2p_flags_snprintf(target,xstate->v2p_flags,
					       buf,sizeof(buf));
	    vdebug(8,LA_TARGET,LF_TARGET,"v2p_flags = %s\n",buf);
	}

	/* Also quickly set the V2P_PV flag if this domain is paravirt. */
	if (!xstate->hvm)
	    xstate->v2p_flags |= ARCH_X86_V2P_PV;
    }
    else {
	tthread = xen_vm_load_thread(target,tid,0);
	if (!tthread) {
	    verror("could not load tid %"PRIiTID"!\n",tid);
	    return -1;
	}
	xtstate = (struct xen_vm_thread_state *)tthread->state;

	/*
	if (target->wordsize == 8) {
	    if (xtstate->pgd >= xstate->kernel_start_addr)
		*pgd = xtstate->pgd - xstate->kernel_start_addr;
	    else
#if __WORDSIZE == 64
		*pgd = xtstate->pgd - 0xffff810000000000UL;
#else
		*pgd = xtstate->pgd - 0xffff810000000000ULL;
#endif
	}
	else {
	    *pgd = xtstate->pgd - xstate->kernel_start_addr;
	}
	*/
	
	if (target_os_thread_get_pgd_phys(target,tid,pgd)) {
	    verror("could not get phys pgd for tid %"PRIiTID": %s!\n",
		   tid,strerror(errno));
	    return -1;
	}
    }

    vdebug(12,LA_TARGET,LF_XV,
	   "tid %"PRIiTID" pgd (phys) = 0x%"PRIx64"\n",tid,*pgd);

    return 0;
}

static int xen_vm_addr_v2p(struct target *target,tid_t tid,
			   ADDR vaddr,ADDR *paddr) {
    struct xen_vm_state *xstate;
    uint64_t pgd = 0;

    xstate = (struct xen_vm_state *)target->state;

    if (__xen_vm_pgd(target,tid,&pgd)) {
	verror("could not read pgd for tid %"PRIiTID"!\n",tid);
	return -1;
    }

    if (!xstate->memops || !xstate->memops->addr_v2p) {
	errno = EINVAL;
	return -1;
    }

    return xstate->memops->addr_v2p(target,tid,pgd,vaddr,paddr);
}

static unsigned char *xen_vm_read_phys(struct target *target,ADDR paddr,
				       unsigned long length,unsigned char *buf) {
    struct xen_vm_state *xstate;

    xstate = (struct xen_vm_state *)target->state;

    if (!xstate->memops || !xstate->memops->read_phys) {
	errno = EINVAL;
	return NULL;
    }

    return xstate->memops->read_phys(target,paddr,length,buf);
}

static unsigned long xen_vm_write_phys(struct target *target,ADDR paddr,
				       unsigned long length,unsigned char *buf) {
    struct xen_vm_state *xstate;

    xstate = (struct xen_vm_state *)target->state;

    if (!xstate->memops || !xstate->memops->read_phys) {
	errno = EINVAL;
    return 0;
	}

    return xstate->memops->write_phys(target,paddr,length,buf);
}

unsigned char *xen_vm_read_pid(struct target *target,tid_t tid,ADDR vaddr,
			       unsigned long length,unsigned char *buf) {
    struct xen_vm_state *xstate;
    uint64_t pgd = 0;

    xstate = (struct xen_vm_state *)target->state;

    if (!xstate->memops || !xstate->memops->read_tid) {
	errno = EINVAL;
	return 0;
    }

    if (__xen_vm_pgd(target,tid,&pgd)) {
	verror("could not read pgd for tid %"PRIiTID"!\n",tid);
		return NULL;
    }

    return xstate->memops->read_tid(target,tid,pgd,vaddr,length,buf);
}

unsigned long xen_vm_write_pid(struct target *target,tid_t tid,ADDR vaddr,
			       unsigned long length,unsigned char *buf) {
    struct xen_vm_state *xstate;
    uint64_t pgd = 0;

    xstate = (struct xen_vm_state *)target->state;

    if (!xstate->memops || !xstate->memops->write_tid) {
	errno = EINVAL;
	return 0;
    }

    if (__xen_vm_pgd(target,tid,&pgd)) {
	verror("could not read pgd for tid %"PRIiTID"!\n",tid);
	return 0;
    }

    return xstate->memops->write_tid(target,tid,pgd,vaddr,length,buf);
}

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
#ifdef __x86_64__
static int dreg_to_offset64[ARCH_X86_64_REG_COUNT] = { 
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
    /* What about fs_base, gs_base, gs_base_kernel; that's what these are. */
    offsetof(struct vcpu_guest_context,fs_base),
    offsetof(struct vcpu_guest_context,gs_base_kernel), /* XXX: reuse kernel */
    offsetof(struct vcpu_guest_context,gs_base_kernel),
    offsetof(struct vcpu_guest_context,gs_base_user),
    -1, -1, -1, -1, -1, -1,
    -1, -1,
    offsetof(struct vcpu_guest_context,ctrlreg[0]),
    offsetof(struct vcpu_guest_context,ctrlreg[1]),
    offsetof(struct vcpu_guest_context,ctrlreg[2]),
    offsetof(struct vcpu_guest_context,ctrlreg[3]),
    offsetof(struct vcpu_guest_context,ctrlreg[4]),
    -1, -1, -1, -1, -1,
    offsetof(struct vcpu_guest_context,debugreg[0]),
    offsetof(struct vcpu_guest_context,debugreg[1]),
    offsetof(struct vcpu_guest_context,debugreg[2]),
    offsetof(struct vcpu_guest_context,debugreg[3]),
    -1,-1,
    offsetof(struct vcpu_guest_context,debugreg[6]),
    offsetof(struct vcpu_guest_context,debugreg[7]),
};
#endif
static int dreg_to_offset32[ARCH_X86_REG_COUNT] = { 
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
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, 
    -1, -1, -1, -1, -1, -1, -1, -1, 
    -1, -1, -1,
    /* These are "fake" DWARF regs. */
    offsetof(struct vcpu_guest_context,user_regs.es),
    offsetof(struct vcpu_guest_context,user_regs.cs),
    offsetof(struct vcpu_guest_context,user_regs.ss),
    offsetof(struct vcpu_guest_context,user_regs.ds),
    offsetof(struct vcpu_guest_context,user_regs.fs),
    offsetof(struct vcpu_guest_context,user_regs.gs),
    offsetof(struct vcpu_guest_context,ctrlreg[0]),
    offsetof(struct vcpu_guest_context,ctrlreg[1]),
    offsetof(struct vcpu_guest_context,ctrlreg[2]),
    offsetof(struct vcpu_guest_context,ctrlreg[3]),
    offsetof(struct vcpu_guest_context,ctrlreg[4]),
    offsetof(struct vcpu_guest_context,debugreg[0]),
    offsetof(struct vcpu_guest_context,debugreg[1]),
    offsetof(struct vcpu_guest_context,debugreg[2]),
    offsetof(struct vcpu_guest_context,debugreg[3]),
    -1,-1,
    offsetof(struct vcpu_guest_context,debugreg[6]),
    offsetof(struct vcpu_guest_context,debugreg[7]),
};

/*
 * Register functions.
 */
int __xen_vm_vcpu_to_thread_regcache(struct target *target,
				     struct vcpu_guest_context *context,
				     struct target_thread *tthread,
				     thread_ctxt_t tctxt) {
    int offset;
    int i;
    int count = 0;
    REGVAL regval;

    vdebug(9,LA_TARGET,LF_XV,"translating vcpu to thid %d tctxt %d\n",
	   tthread->tid,tctxt);

    /*
     * NB: we need to read 64-bit numbers from the vcpu structs if the
     * host is 64-bit, even if the target is 32-bit, I think...
     */
    if (arch_wordsize(target->arch) == 8 || __WORDSIZE == 64) {
	for (i = 0; i < ARCH_X86_64_REG_COUNT; ++i) {
	    offset = dreg_to_offset64[i];
	    if (offset < 0)
		continue;

	    if (likely(i < REG_X86_64_ES) || likely(i > REG_X86_64_GS))
		regval = (REGVAL)*(uint64_t *)(((char *)context) + offset);
	    else
		regval = (REGVAL)*(uint16_t *)(((char *)context) + offset);

	    if (target_regcache_init_reg_tidctxt(target,tthread,tctxt,
						 i,regval)) {
		vwarn("could not set reg %d thid %d tctxt %d\n",
		      i,tthread->tid,tctxt);
	    }
	    else
		++count;
	}
    }
    else if (arch_wordsize(target->arch) == 4) {
	for (i = 0; i < ARCH_X86_REG_COUNT; ++i) {
	    offset = dreg_to_offset32[i];
	    if (offset < 0)
		continue;

	    regval = (REGVAL)*(uint32_t *)(((char *)context) + offset);

	    if (target_regcache_init_reg_tidctxt(target,tthread,tctxt,
						 i,regval)) {
		vwarn("could not set reg %d thid %d tctxt %d\n",
		      i,tthread->tid,tctxt);
	    }
	    else
		++count;
	}
    }

    vdebug(9,LA_TARGET,LF_XV,
	   "translated %d vcpu regs to thid %d tctxt %d regcache\n",
	   count,tthread->tid,tctxt);

    return 0;
}

int __xen_vm_thread_regcache_to_vcpu_64_reg_h(struct target *target,
					      struct target_thread *tthread,
					      thread_ctxt_t tctxt,
					      REG reg,REGVAL regval,void *priv) {
    struct vcpu_guest_context *context;
    int offset;

    if (reg > ARCH_X86_64_REG_COUNT) {
	vwarn("unsupported reg %d!\n",reg);
	errno = EINVAL;
	return -1;
    }

    context = (struct vcpu_guest_context *)priv;
    offset = dreg_to_offset64[reg];

    if (offset < 0) {
	vwarn("unsupported reg %d!\n",reg);
	errno = EINVAL;
	return -1;
    }

    vdebug(16,LA_TARGET,LF_XV,
	   "tid %d thid %d tctxt %d regcache->vcpu %d 0x%"PRIxREGVAL"\n",
	   target->id,tthread->tid,tctxt,reg,regval);

    if (likely(reg < REG_X86_64_ES) || likely(reg > REG_X86_64_GS))
	*(uint64_t *)(((char *)context) + offset) = 
	    (uint64_t)regval;
    else
	*(uint16_t *)(((char *)context) + offset) =
	    (uint16_t)regval;

    return 0;
}

int __xen_vm_thread_regcache_to_vcpu_64_raw_h(struct target *target,
					      struct target_thread *tthread,
					      thread_ctxt_t tctxt,
					      REG reg,void *rawval,int rawlen,
					      void *priv) {
    //struct vcpu_guest_context *context;
    int offset;

    if (reg > ARCH_X86_64_REG_COUNT) {
	vwarn("unsupported reg %d!\n",reg);
	errno = EINVAL;
	return -1;
    }

    //context = (struct vcpu_guest_context *)priv;
    offset = dreg_to_offset64[reg];

    if (offset < 0) {
	vwarn("unsupported reg %d!\n",reg);
	errno = EINVAL;
	return -1;
    }

    vwarn("tid %d thid %d tctxt %d regcache->vcpu %d"
	  " -- unsupported rawval len %d\n",
	  target->id,tthread->tid,tctxt,reg,rawlen);

    return -1;
}

int __xen_vm_thread_regcache_to_vcpu_32_reg_h(struct target *target,
					      struct target_thread *tthread,
					      thread_ctxt_t tctxt,
					      REG reg,REGVAL regval,void *priv) {
    struct vcpu_guest_context *context;
    int offset;

    if (reg > ARCH_X86_REG_COUNT) {
	vwarn("unsupported reg %d!\n",reg);
	errno = EINVAL;
	return -1;
    }

    context = (struct vcpu_guest_context *)priv;
    offset = dreg_to_offset32[reg];

    if (offset < 0) {
	vwarn("unsupported reg %d!\n",reg);
	errno = EINVAL;
	return -1;
    }

    vdebug(16,LA_TARGET,LF_XV,
	   "tid %d thid %d tctxt %d regcache->vcpu %d 0x%"PRIxREGVAL"\n",
	   target->id,tthread->tid,tctxt,reg,regval);

    *(uint32_t *)(((char *)context) + offset) = (uint32_t)regval;

    return 0;
}

int __xen_vm_thread_regcache_to_vcpu_32_raw_h(struct target *target,
					      struct target_thread *tthread,
					      thread_ctxt_t tctxt,
					      REG reg,void *rawval,int rawlen,
					      void *priv) {
    //struct vcpu_guest_context *context;
    int offset;

    if (reg > ARCH_X86_REG_COUNT) {
	vwarn("unsupported reg %d!\n",reg);
	errno = EINVAL;
	return -1;
    }

    //context = (struct vcpu_guest_context *)priv;
    offset = dreg_to_offset32[reg];

    if (offset < 0) {
	vwarn("unsupported reg %d!\n",reg);
	errno = EINVAL;
	return -1;
    }

    vwarn("tid %d thid %d tctxt %d regcache->vcpu %d"
	  " -- unsupported rawval len %d\n",
	  target->id,tthread->tid,tctxt,reg,rawlen);

    return -1;
}

int __xen_vm_thread_regcache_to_vcpu(struct target *target,
				     struct target_thread *tthread,
				     thread_ctxt_t tctxt,
				     struct vcpu_guest_context *context) {
    vdebug(9,LA_TARGET,LF_XV,"translating thid %d tctxt %d to vcpu\n",
	   tthread->tid,tctxt);

    /*
     * NB: we need to write 64-bit numbers from the vcpu structs if the
     * host is 64-bit, even if the target is 32-bit, I think...
     */
    if (arch_wordsize(target->arch) == 8 || __WORDSIZE == 64) {
	target_regcache_foreach_dirty(target,tthread,tctxt,
				      __xen_vm_thread_regcache_to_vcpu_64_reg_h,
				      __xen_vm_thread_regcache_to_vcpu_64_raw_h,
				      context);
    }
    else if (arch_wordsize(target->arch) == 4) {
	target_regcache_foreach_dirty(target,tthread,tctxt,
				      __xen_vm_thread_regcache_to_vcpu_32_reg_h,
				      __xen_vm_thread_regcache_to_vcpu_32_raw_h,
				      context);
    }

    return 0;
}

/*
 * Hardware breakpoint support.
 */
static REG xen_vm_get_unused_debug_reg(struct target *target,tid_t tid) {
    REG retval = -1;
    struct target_thread *tthread;
    struct xen_vm_thread_state *xtstate;

    if (tid != TID_GLOBAL) {
	verror("currently must use TID_GLOBAL for hardware probepoints!\n");
	return -1;
    }

    if (!(tthread = __xen_vm_load_cached_thread(target,tid))) {
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
    struct target_thread *tthread;
    struct xen_vm_thread_state *xtstate;

    if (reg < 0 || reg > 3) {
	errno = EINVAL;
	return -1;
    }

    if (!(tthread = __xen_vm_load_cached_thread(target,tid))) {
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
    struct xen_vm_state *xstate;
    xstate = (struct xen_vm_state *)(target->state);
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
    struct target_thread *tthread;
    struct xen_vm_thread_state *xtstate;

    if (reg < 0 || reg > 3) {
	errno = EINVAL;
	return -1;
    }

    if (!(tthread = __xen_vm_load_cached_thread(target,tid))) {
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
    struct xen_vm_state *xstate;
    xstate = (struct xen_vm_state *)(target->state);
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
#ifdef CONFIG_DETERMINISTIC_TIMETRAVEL
    ADDR addr;
#endif
    struct target_thread *tthread;
    struct xen_vm_thread_state *xtstate;

    if (reg < 0 || reg > 3) {
	errno = EINVAL;
	return -1;
    }

    if (!(tthread = __xen_vm_load_cached_thread(target,tid))) {
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
    struct xen_vm_state *xstate;
    xstate = (struct xen_vm_state *)(target->state);
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

    if (!(tthread = __xen_vm_load_cached_thread(target,tid))) {
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

    if (!(tthread = __xen_vm_load_cached_thread(target,tid))) {
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
    struct target_thread *tthread;
    struct xen_vm_thread_state *xtstate;

    if (dreg < 0 || dreg > 3) {
	errno = EINVAL;
	return -1;
    }

    if (!(tthread = __xen_vm_load_cached_thread(target,tid))) {
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
    struct xen_vm_state *xstate;
    xstate = (struct xen_vm_state *)(target->state);
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
    struct target_thread *tthread;
    struct xen_vm_thread_state *xtstate;

    if (dreg < 0 || dreg > 3) {
	errno = EINVAL;
	return -1;
    }

    if (!(tthread = __xen_vm_load_cached_thread(target,tid))) {
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
    struct xen_vm_state *xstate;
    xstate = (struct xen_vm_state *)(target->state);
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

    if (!(tthread = __xen_vm_load_cached_thread(target,tid))) {
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

    if (!(tthread = __xen_vm_load_cached_thread(target,tid))) {
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
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;

    assert(xstate->dominfo_valid);

#ifdef CONFIG_DETERMINISTIC_TIMETRAVEL
    struct target_thread *gthread;
    struct xen_vm_thread_state *gtstate;
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
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;

    assert(xstate->dominfo_valid);

#ifdef CONFIG_DETERMINISTIC_TIMETRAVEL
    struct target_thread *gthread;
    struct xen_vm_thread_state *gtstate;
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
    if (feature != XV_FEATURE_BTS)
	return -1;

#ifdef CONFIG_DETERMINISTIC_TIMETRAVEL
    struct xen_vm_state *xstate;

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
    if (feature != XV_FEATURE_BTS)
	return -1;

#ifdef CONFIG_DETERMINISTIC_TIMETRAVEL
    struct xen_vm_state *xstate;

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
