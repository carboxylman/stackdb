/*
 * Copyright (c) 2014 The University of Utah
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
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <fcntl.h>
#include <sys/mman.h>
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

#include "target_gdb.h"
#include "target_gdb_rsp.h"

#include <glib.h>

extern struct gdb_helper_ops gdb_helper_ops_qemu;
extern struct gdb_helper_ops gdb_helper_ops_builtin;

/*
 * Prototypes.
 */
struct target *gdb_instantiate(struct target_spec *spec,struct evloop *evloop);
static struct target *gdb_attach(struct target_spec *spec,
				 struct evloop *evloop);

static int gdb_snprintf(struct target *target,char *buf,int bufsiz);
static int gdb_init(struct target *target);
static int gdb_attach_internal(struct target *target);
static int gdb_detach(struct target *target);
static int gdb_fini(struct target *target);
static int gdb_kill(struct target *target,int sig);
static int gdb_loadspaces(struct target *target);
static int gdb_loadregions(struct target *target,struct addrspace *space);
static int gdb_loaddebugfiles(struct target *target,struct addrspace *space,
			      struct memregion *region);
static int gdb_postloadinit(struct target *target);
static int gdb_postopened(struct target *target);
static int gdb_set_active_probing(struct target *target,
				     active_probe_flags_t flags);

static target_status_t gdb_handle_exception(struct target *target,
					       int *again,void *priv);

static struct target *
gdb_instantiate_overlay(struct target *target,
			struct target_thread *tthread,
			struct target_spec *spec,
			struct target_thread **ntthread);
static struct target_thread *
gdb_lookup_overlay_thread_by_id(struct target *target,int id);
static struct target_thread *
gdb_lookup_overlay_thread_by_name(struct target *target,char *name);
static int gdb_attach_overlay_thread(struct target *base,struct target *overlay,
				     tid_t newtid);
static int gdb_detach_overlay_thread(struct target *base,struct target *overlay,
				     tid_t tid);
static target_status_t gdb_status(struct target *target);
static int gdb_pause(struct target *target,int nowait);
static int __gdb_resume(struct target *target,int detaching);
static int gdb_resume(struct target *target);
static target_status_t gdb_monitor(struct target *target);
static target_status_t gdb_poll(struct target *target,struct timeval *tv,
				target_poll_outcome_t *outcome,int *pstatus);
static int gdb_attach_evloop(struct target *target,struct evloop *evloop);
static int gdb_detach_evloop(struct target *target);
static unsigned char *gdb_read(struct target *target,ADDR addr,
			       unsigned long length,unsigned char *buf);
static unsigned long gdb_write(struct target *target,ADDR addr,
			       unsigned long length,unsigned char *buf);
static int gdb_addr_v2p(struct target *target,tid_t tid,
			ADDR vaddr,ADDR *paddr);
static unsigned char *gdb_read_phys(struct target *target,ADDR paddr,
				       unsigned long length,unsigned char *buf);
static unsigned long gdb_write_phys(struct target *target,ADDR paddr,
				       unsigned long length,unsigned char *buf);

static tid_t gdb_gettid(struct target *target);
static void gdb_free_thread_state(struct target *target,void *state);
static struct array_list *gdb_list_available_tids(struct target *target);
static struct target_thread *gdb_load_thread(struct target *target,tid_t tid,
					     int force);
static struct target_thread *gdb_load_current_thread(struct target *target,
						     int force);
static int gdb_load_all_threads(struct target *target,int force);
static int gdb_load_available_threads(struct target *target,int force);
/*
 * XXX: figure out how to do this later... for some targets, pausing a
 * single thread might be meaningful; others you don't have thread control.
 */
//static int gdb_pause_thread(struct target *target,tid_t tid,int nowait);
static int gdb_flush_thread(struct target *target,tid_t tid);
static int gdb_flush_current_thread(struct target *target);
static int gdb_flush_all_threads(struct target *target);
static int gdb_invalidate_thread(struct target *target,
				    struct target_thread *tthread);
static int gdb_thread_snprintf(struct target_thread *tthread,
				  char *buf,int bufsiz,
				  int detail,char *sep,char *key_val_sep);

static struct target_memmod *gdb_insert_sw_breakpoint(struct target *target,
						      tid_t tid,ADDR addr);
static int gdb_remove_sw_breakpoint(struct target *target,tid_t tid,
				    struct target_memmod *mmod);
static int gdb_remove_sw_breakpoint(struct target *target,tid_t tid,
				    struct target_memmod *mmod);
static int gdb_enable_sw_breakpoint(struct target *target,tid_t tid,
				    struct target_memmod *mmod);
static int gdb_disable_sw_breakpoint(struct target *target,tid_t tid,
				     struct target_memmod *mmod);
static int gdb_set_hw_breakpoint(struct target *target,tid_t tid,
				 REG num,ADDR addr);
static int gdb_set_hw_watchpoint(struct target *target,tid_t tid,
				 REG num,ADDR addr,
				 probepoint_whence_t whence,
				 probepoint_watchsize_t watchsize);
static int gdb_unset_hw_breakpoint(struct target *target,tid_t tid,REG num);
static int gdb_unset_hw_watchpoint(struct target *target,tid_t tid,REG num);
static int gdb_disable_hw_breakpoints(struct target *target,tid_t tid);
static int gdb_enable_hw_breakpoints(struct target *target,tid_t tid);
static int gdb_disable_hw_breakpoint(struct target *target,tid_t tid,REG dreg);
static int gdb_enable_hw_breakpoint(struct target *target,tid_t tid,REG dreg);

static int gdb_singlestep(struct target *target,tid_t tid,int isbp,
			  struct target *overlay);
static int gdb_singlestep_end(struct target *target,tid_t tid,
			      struct target *overlay);

int gdb_instr_can_switch_context(struct target *target,ADDR addr);

/* Internal prototypes. */
static struct target_thread *__gdb_load_cached_thread(struct target *target,
						      tid_t tid);
static struct target_thread *__gdb_load_current_thread(struct target *target,
						       int force,
						       int globalonly);
static int __gdb_pgd(struct target *target,tid_t tid,uint64_t *pgd);

/*
 * Globals.
 */


/*
 * Set up the target interface for this library.
 */
struct target_ops gdb_ops = {
    .snprintf = gdb_snprintf,

    .init = gdb_init,
    .fini = gdb_fini,
    .attach = gdb_attach_internal,
    .detach = gdb_detach,
/*
    .kill = gdb_kill,
*/

    .loadspaces = gdb_loadspaces,
    .loadregions = gdb_loadregions,
    .loaddebugfiles = gdb_loaddebugfiles,
    .postloadinit = gdb_postloadinit,
/*
    .postopened = gdb_postopened,
    .set_active_probing = gdb_set_active_probing,
*/
    .handle_exception = gdb_handle_exception,
    .handle_break = probepoint_bp_handler,
    .handle_step = probepoint_ss_handler,
/*
    .handle_interrupted_step = NULL,
*/
/*
    .instantiate_overlay = gdb_instantiate_overlay,
    .lookup_overlay_thread_by_id = gdb_lookup_overlay_thread_by_id,
    .lookup_overlay_thread_by_name = gdb_lookup_overlay_thread_by_name,
    .attach_overlay_thread = gdb_attach_overlay_thread,
    .detach_overlay_thread = gdb_detach_overlay_thread,
*/
    .status = gdb_status,
    .pause = gdb_pause,
    .resume = gdb_resume,
    .monitor = gdb_monitor,
    .poll = gdb_poll,

    .read = gdb_read,
    .write = gdb_write,
    .addr_v2p = gdb_addr_v2p,
    .read_phys = gdb_read_phys,
    .write_phys = gdb_write_phys,

    .gettid = gdb_gettid,
    .free_thread_state = gdb_free_thread_state,
    .list_available_tids = gdb_list_available_tids,
    .load_available_threads = gdb_load_available_threads,
    .load_thread = gdb_load_thread,
    .load_current_thread = gdb_load_current_thread,
    .load_all_threads = gdb_load_all_threads,
    .pause_thread = NULL,
    .flush_thread = gdb_flush_thread,
    .flush_current_thread = gdb_flush_current_thread,
    .flush_all_threads = gdb_flush_all_threads,
    .invalidate_thread = gdb_invalidate_thread,
    .thread_snprintf = gdb_thread_snprintf,

    .attach_evloop = gdb_attach_evloop,
    .detach_evloop = gdb_detach_evloop,

    .readreg = target_regcache_readreg,
    .writereg = target_regcache_writereg,
    .copy_registers = target_regcache_copy_registers,
    .readreg_tidctxt = target_regcache_readreg_tidctxt,
    .writereg_tidctxt = target_regcache_writereg_tidctxt,

    .insert_sw_breakpoint = gdb_insert_sw_breakpoint,
    .remove_sw_breakpoint = gdb_remove_sw_breakpoint,
    .change_sw_breakpoint = NULL,
    .enable_sw_breakpoint = gdb_enable_sw_breakpoint,
    .disable_sw_breakpoint = gdb_disable_sw_breakpoint,

    .set_hw_breakpoint = gdb_set_hw_breakpoint,
    .set_hw_watchpoint = gdb_set_hw_watchpoint,
    .unset_hw_breakpoint = gdb_unset_hw_breakpoint,
    .unset_hw_watchpoint = gdb_unset_hw_watchpoint,
    .disable_hw_breakpoints = gdb_disable_hw_breakpoints,
    .enable_hw_breakpoints = gdb_enable_hw_breakpoints,
    .disable_hw_breakpoint = gdb_disable_hw_breakpoint,
    .enable_hw_breakpoint = gdb_enable_hw_breakpoint,

    .singlestep = gdb_singlestep,
    .singlestep_end = gdb_singlestep_end,
/*
    .instr_can_switch_context = gdb_instr_can_switch_context,
*/
};

#define GDB_ARGP_HOST               0x650001
#define GDB_ARGP_PORT               0x650002
#define GDB_ARGP_UDP                0x650003
#define GDB_ARGP_SOCKFILE           0x650004
#define GDB_ARGP_IS_KVM             0x650005
#define GDB_ARGP_IS_QEMU            0x650006
#define GDB_ARGP_QEMU_QMP_HOST      0x650007
#define GDB_ARGP_QEMU_MEM_PATH      0x650008
#define GDB_ARGP_QEMU_QMP_PORT      0x650009
#define GDB_ARGP_CLEAR_MEM_CACHES   0x65000a
#define GDB_ARGP_MEMCACHE_MMAP_SIZE 0x65000b

struct argp_option gdb_argp_opts[] = {
    /* These options set a flag. */
    { "gdb-host",GDB_ARGP_HOST,"HOSTNAME",0,
          "The hostname the GDB stub is listening on (default localhost).",-4 },
    { "gdb-port",GDB_ARGP_PORT,"PORT",0,
          "The port the GDB stub is listening on (default 1234).",-4 },
    { "gdb-udp",GDB_ARGP_UDP,NULL,0,
          "Use UDP instead of TCP (default TCP).",-4 },
    { "gdb-sockfile",GDB_ARGP_SOCKFILE,"FILENAME",0,
          "The UNIX domain socket filename the GDB stub is listening on.",-4 },
    { "main-filename",'M',"FILE",0,
          "Set main binary's filepath for target.",-4 },
    { "clear-mem-caches-each-exception",GDB_ARGP_CLEAR_MEM_CACHES,NULL,0,
          "Clear mem caches on each debug exception.",-4 },
    { "qemu",GDB_ARGP_IS_QEMU,NULL,0,
          "Enable QEMU GDB stub support",-4 },
    { "qemu-qmp-host",GDB_ARGP_QEMU_QMP_HOST,"HOSTNAME",0,
          "Attach to QEMU QMP on the given host (default localhost).",-4 },
    { "qemu-qmp-port",GDB_ARGP_QEMU_QMP_PORT,"PORT",0,
          "Attach to QEMU QMP on the given port (default 1235).",-4 },
    { "qemu-mem-path",GDB_ARGP_QEMU_MEM_PATH,"PATHNAME",0,
          "Read/write QEMU's physical memory via this filename (see QEMU's -mem-path option; also preload libnunlink.so and set NUNLINK_PREFIX accordingly).",-4 },
    { "kvm",GDB_ARGP_IS_KVM,NULL,0,
          "Enable QEMU GDB KVM stub support.",-4 },
    { "memcache-mmap-size",GDB_ARGP_MEMCACHE_MMAP_SIZE,"BYTES",0,
          "Max size (bytes) of the mmap cache (default 128MB).",-4 },
    { 0,0,0,0,0,0 }
};

int gdb_spec_to_argv(struct target_spec *spec,int *argc,char ***argv) {
    struct gdb_spec *xspec = 
	(struct gdb_spec *)spec->backend_spec;
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

    if (xspec->hostname)
	ac += 2;
    if (xspec->port)
	ac += 2;
    if (xspec->do_udp)
	ac += 1;
    if (xspec->sockfile)
	ac += 2;

    if (xspec->main_filename) 
	ac += 2;
    if (xspec->clear_mem_caches_each_exception)
	ac += 1;
    if (xspec->is_qemu)
	ac += 1;
    if (xspec->qemu_qmp_hostname)
	ac += 2;
    if (xspec->qemu_qmp_port > 0)
	ac += 2;
    if (xspec->qemu_mem_path)
	ac += 2;
    if (xspec->is_kvm)
	ac += 1;
    if (xspec->memcache_mmap_size)
	ac += 2;

    av = calloc(ac + 1,sizeof(char *));
    j = 0;
    if (xspec->hostname) {
	av[j++] = strdup("--gdb-host");
	av[j++] = strdup(xspec->hostname);
    }
    if (xspec->port > -1) {
	av[j++] = strdup("--gdb-port");
	av[j] = malloc(16);
	snprintf(av[j],16,"%d",xspec->port);
	++j;
    }
    if (xspec->do_udp) {
	av[j++] = strdup("--gdb-udp");
    }
    if (xspec->sockfile) {
	av[j++] = strdup("--gdb-sockfile");
	av[j++] = strdup(xspec->sockfile);
    }
    if (xspec->main_filename) {
	av[j++] = strdup("-M");
	av[j++] = strdup(xspec->main_filename);
    }
    if (xspec->clear_mem_caches_each_exception) {
	av[j++] = strdup("--clear-mem-caches-each-exception");
    }
    if (xspec->is_qemu)
	av[j++] = strdup("--qemu");
    if (xspec->qemu_qmp_hostname) {
	av[j++] = strdup("--qemu-qmp-host");
	av[j++] = strdup(xspec->qemu_qmp_hostname);
    }
    if (xspec->qemu_qmp_port > 0) {
	av[j++] = strdup("--qemu-qmp-port");
	av[j] = malloc(16);
	snprintf(av[j],16,"%d",xspec->qemu_qmp_port);
	j++;
    }
    if (xspec->qemu_mem_path) {
	av[j++] = strdup("--qemu-mem-path");
	av[j++] = strdup(xspec->qemu_mem_path);
    }
    if (xspec->is_kvm)
	av[j++] = strdup("--kvm");
    if (xspec->memcache_mmap_size) {
	av[j++] = strdup("--memcache-mmap-size");
	av[j] = malloc(32);
	snprintf(av[j],32,"%lu",xspec->memcache_mmap_size);
	j++;
    }
    av[j++] = NULL;

    if (argv)
	*argv = av;
    if (argc)
	*argc = ac;

    return 0;
}

error_t gdb_argp_parse_opt(int key,char *arg,struct argp_state *state) {
    struct target_argp_parser_state *tstate = \
	(struct target_argp_parser_state *)state->input;
    struct target_spec *spec;
    struct gdb_spec *xspec;
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
    for (opti = &gdb_argp_opts[0]; opti->key != 0; ++opti) {
	if (key == opti->key) {
	    ourkey = 1;
	    break;
	}
    }

    if (ourkey) {
	if (spec->target_type == TARGET_TYPE_NONE) {
	    spec->target_type = TARGET_TYPE_GDB;
	    xspec = gdb_build_spec();
	    spec->backend_spec = xspec;
	}
	else if (spec->target_type != TARGET_TYPE_GDB) {
	    verror("cannot mix arguments for GDB target (%c) with non-GDB"
		   " target!\n",key);
	    return EINVAL;
	}

	/* Only "claim" these args if this is our key. */
	if (spec->target_type == TARGET_TYPE_NONE) {
	    spec->target_type = TARGET_TYPE_GDB;
	    xspec = calloc(1,sizeof(*xspec));
	    spec->backend_spec = xspec;
	}
	else if (spec->target_type != TARGET_TYPE_GDB) {
	    verror("cannot mix arguments for GDB target with non-GDB target!\n");
	    return EINVAL;
	}
    }

    if (spec->target_type == TARGET_TYPE_GDB)
	xspec = (struct gdb_spec *)spec->backend_spec;
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

    case GDB_ARGP_HOST:
	xspec->hostname = strdup(arg);
	break;
    case GDB_ARGP_PORT:
	xspec->port = atoi(arg);
	break;
    case GDB_ARGP_UDP:
	xspec->do_udp = 1;
	break;
    case GDB_ARGP_SOCKFILE:
	xspec->sockfile = strdup(arg);
	break;
    case 'M':
	xspec->main_filename = strdup(arg);
	break;
    case GDB_ARGP_CLEAR_MEM_CACHES:
	xspec->clear_mem_caches_each_exception = 1;
	break;
    case GDB_ARGP_IS_QEMU:
	xspec->is_qemu = 1;
	break;
    case GDB_ARGP_QEMU_QMP_HOST:
	xspec->qemu_qmp_hostname = strdup(arg);
	break;
    case GDB_ARGP_QEMU_QMP_PORT:
	xspec->qemu_qmp_port = atoi(arg);
	break;
    case GDB_ARGP_QEMU_MEM_PATH:
	xspec->qemu_mem_path = strdup(arg);
	break;
    case GDB_ARGP_IS_KVM:
	xspec->is_kvm = 1;
	break;
    case GDB_ARGP_MEMCACHE_MMAP_SIZE:
	xspec->memcache_mmap_size = atoi(arg);
	break;
    default:
	return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

struct argp gdb_argp = { 
    gdb_argp_opts,gdb_argp_parse_opt,NULL,NULL,NULL,NULL,NULL
};
char *gdb_argp_header = "GDB Backend Options";

/**
 ** These are the only user-visible functions.
 **/

struct gdb_spec *gdb_build_spec(void) {
    struct gdb_spec *xspec;

    xspec = calloc(1,sizeof(*xspec));
    xspec->port = -1;

    return xspec;
}

void gdb_free_spec(struct gdb_spec *xspec) {
    if (xspec->devfile)
	free(xspec->devfile);
    if (xspec->sockfile)
	free(xspec->sockfile);
    if(xspec->hostname)
	free(xspec->hostname);

    free(xspec);
}

struct target *gdb_instantiate(struct target_spec *spec,
				  struct evloop *evloop) {
    return gdb_attach(spec,evloop);
}

/**
 ** Utility functions.
 **/

/*
 * Attaches to the GDB server.
 */
static struct target *gdb_attach(struct target_spec *spec,
				 struct evloop *evloop) {
    struct gdb_spec *xspec = (struct gdb_spec *)spec->backend_spec;
    struct target *target = NULL;
    struct gdb_state *xstate = NULL;

    vdebug(5,LA_TARGET,LF_GDB,"attaching to GDB server\n");

    if (!(target = target_create("gdb",spec)))
	return NULL;

    if (!(xstate = (struct gdb_state *)malloc(sizeof(*xstate)))) {
	free(target);
	return NULL;
    }
    memset(xstate,0,sizeof(*xstate));
    /* Assume RSP needs acks unless we hear otherwise. */
    xstate->need_ack = 1;

    xstate->fd = xstate->wfd = -1;

    target->state = xstate;

    xstate->evloop_fd = -1;

    if (xspec->main_filename) {
	g_hash_table_insert(target->config,strdup("MAIN_FILENAME"),
			    strdup(xspec->main_filename));

	vdebug(1,LA_TARGET,LF_GDB,
	       "using main filename %s\n",xspec->main_filename);
    }

    /*
     * Try to infer the personality.
     */
    if (!target->personality_ops
	&& xspec->main_filename
	&& (strstr(xspec->main_filename,"inux")
	    || strstr(xspec->main_filename,"inuz"))) {
	if (target_personality_attach(target,"os_linux_generic",NULL) == 0) {
	    vdebug(3,LA_TARGET,LF_GDB,
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
    xstate->hops = NULL;
    if (!xstate->hops && xspec->is_qemu)
	xstate->hops = &gdb_helper_ops_qemu;
    else if (!xstate->hops)
	xstate->hops = &gdb_helper_ops_builtin;

    if (xstate->hops->init) {
	if (xstate->hops->init(target)) {
	    verror("failed to init hops!\n");
	    goto errout;
	}
    }

    /* Our threads can have two contexts -- kernel and user spaces. */
    target->max_thread_ctxt = THREAD_CTXT_USER;

    if (evloop && xstate->evloop_fd < 0) {
	/*
	 * Just save it off; we can't use it until in gdb_attach_internal.
	 */
	target->evloop = evloop;
    }

    vdebug(5,LA_TARGET,LF_GDB,"opened GDB server\n");

    return target;

 errout:
    if (xstate->ostype) {
	free(xstate->ostype);
	xstate->ostype = NULL;
    }
    if (xstate) {
	free(xstate);
	if (target)
	    target->state = NULL;
    }
    if (target)
	target_free(target);

    return NULL;
}

static int gdb_snprintf(struct target *target,char *buf,int bufsiz) {
    struct gdb_spec *xspec = \
	(struct gdb_spec *)target->spec->backend_spec;

    if (xspec->do_udp)
	return snprintf(buf,bufsiz,"gdbstub@udp(%s::%d)",
			xspec->hostname,xspec->port);
    else if (xspec->do_unix)
	return snprintf(buf,bufsiz,"gdbstub@unix(%s)",
			xspec->sockfile);
    else if (xspec->hostname || xspec->port > -1)
	return snprintf(buf,bufsiz,"gdbstub@tcp(%s::%d)",
			xspec->hostname,xspec->port);
    else
	return snprintf(buf,bufsiz,"gdbstub@unknown");
}

static int gdb_init(struct target *target) {
    struct gdb_state *xstate = (struct gdb_state *)target->state;
    struct gdb_thread_state *tstate;

    vdebug(5,LA_TARGET,LF_GDB,"target %s\n",target->name);

    if (target->spec->bpmode == THREAD_BPMODE_STRICT) {
	vwarn("auto-enabling SEMI_STRICT bpmode on GDB target %s\n",target->name);
	target->spec->bpmode = THREAD_BPMODE_SEMI_STRICT;
    }

    // XXX
    target->nodisablehwbponss = 1;
    target->threadctl = 0;
    /*
     * GDB manages EIP for us, of course.
     */
    target->no_adjust_bp_ip = 1;

    xstate->stubfeatures =
	g_hash_table_new_full(g_str_hash,g_str_equal,free,free);

    /* Create the default thread. */
    tstate = (struct gdb_thread_state *)calloc(1,sizeof(*tstate));

    target->global_thread = target_create_thread(target,TID_GLOBAL,tstate,NULL);
    /* Default thread is always running. */
    target_thread_set_status(target->global_thread,THREAD_STATUS_RUNNING);

    /* Create our default context now; update its region later. */
    target->global_tlctxt =
	target_location_ctxt_create(target,TID_GLOBAL,NULL);

    return 0;
}

static int gdb_attach_internal(struct target *target) {
    struct gdb_state *xstate = (struct gdb_state *)target->state;

    vdebug(5,LA_TARGET,LF_GDB,"attaching to GDB stub\n");

    /*
     * Attach to the GDB stub!
     */
    if (gdb_rsp_connect(target))
	return -1;

    if (gdb_pause(target,0)) {
	vwarn("could not pause target before attaching; continuing anyway!\n");
    }

    /*
     * Make sure hops is setup to read from memory.
     */
    if (xstate->hops && xstate->hops->attach) {
	if (xstate->hops->attach(target)) {
	    verror("could not attach hops!\n");
	    return -1;
	}
    }

    if (target->evloop && xstate->evloop_fd < 0) {
	gdb_attach_evloop(target,target->evloop);
    }

    return 0;
}

static int gdb_detach(struct target *target) {
    struct gdb_state *xstate = (struct gdb_state *)(target->state);

    vdebug(5,LA_TARGET,LF_GDB,
	   "preparing to detach from GDB stub (target %s)\n",target->name);

    if (!target->opened)
	return 0;

    if (gdb_status(target) == TSTATUS_PAUSED
	&& (g_hash_table_size(target->threads) || target->global_thread)) {
	/* Flush back registers if they're dirty, but if we don't have
	 * any threads (i.e. because we're closing/detaching), don't
	 * flush all, which would load the global thread!
	 */
	target_flush_all_threads(target);
    }

    if (target->evloop && xstate->evloop_fd > -1)
	gdb_detach_evloop(target);

    if (xstate->hops->fini) {
	if (xstate->hops->fini(target)) {
	    verror("failed to fini hops; continuing anyway (target %s)!\n",
		   target->name);
	    return 0;
	}
    }

    /*
     * Hopefully we don't need this...
     */
    /*
    if (gdb_status(target) == TSTATUS_PAUSED) {
	__gdb_resume(target,1);
    }
    */

    vdebug(4,LA_TARGET,LF_GDB,"detaching from stub (target %s)\n",target->name);

    if (gdb_rsp_close(target))
	verror("failed to detach from GDB stub (target %s)!\n",target->name);
    else
	vdebug(3,LA_TARGET,LF_GDB,"detach succeeded (target %s)\n",target->name);

    return 0;
}

static int gdb_fini(struct target *target) {
    struct gdb_state *xstate = (struct gdb_state *)(target->state);

    vdebug(5,LA_TARGET,LF_GDB,"target %s\n",target->name);

    if (target->opened) 
	gdb_detach(target);

    if (xstate) {
	if (xstate->machine) {
	    regcache_destroy(xstate->machine);
	    xstate->machine = NULL;
	}
	if (xstate->sockfile) {
	    unlink(xstate->sockfile);
	    free(xstate->sockfile);
	}
	if (xstate->stubfeatures)
	    g_hash_table_destroy(xstate->stubfeatures);
	if (xstate->ibuf)
	    free(xstate->ibuf);

	free(xstate);
    }

    return 0;
}

/*
 * One is enough for any GDB target, I think.
 */
static int gdb_loadspaces(struct target *target) {
    struct addrspace *space;

    vdebug(5,LA_TARGET,LF_GDB,"%s\n",target->name);

    if (target->personality == TARGET_PERSONALITY_OS)
	space = addrspace_create(target,"kernel",1);
    else
	space = addrspace_create(target,"main",1);

    space->target = target;
    RHOLD(space,target);

    list_add_tail(&space->space,&target->spaces);

    return 0;
}

/*
 * XXX: actually use GDB RSP's region info...
 */
static int gdb_loadregions(struct target *target,struct addrspace *space) {
    struct memregion *region;
    struct memrange *range;
    char *main_filename;

    vdebug(5,LA_TARGET,LF_GDB,"%s\n",target->name);

    main_filename = 
	(char *)g_hash_table_lookup(target->config,"MAIN_FILENAME");
    if (!main_filename)
	return 0;

    region = memregion_create(space,REGION_TYPE_MAIN,main_filename);
    if (!region)
	return -1;
    range = memrange_create(region,0,ADDRMAX,0,
			    PROT_READ | PROT_WRITE | PROT_EXEC);
    if (!range)
	return -1;

    target->global_tlctxt->region = region;

    return 0;
}

static int gdb_loaddebugfiles(struct target *target,struct addrspace *space,
			      struct memregion *region) {
    int retval = -1;
    struct debugfile *debugfile;
    int bfn = 0;
    int bfpn = 0;

    vdebug(5,LA_TARGET,LF_GDB,"%s\n",target->name);

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

static int gdb_postloadinit(struct target *target) {
    struct gdb_state *gstate = (struct gdb_state *)target->state;
    int rc;

    gstate->machine = regcache_create(target->arch);

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
	gstate->kernel_start_addr = strtoul(start,NULL,0);

    return 0;

    return 0;
}

static int __gdb_in_userspace(struct target *target,int cpl,REGVAL ipval) {
    struct gdb_state *xstate = (struct gdb_state *)target->state;

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

static int __gdb_get_cpl_thread(struct target *target,
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

static int __gdb_get_cpl(struct target *target,tid_t tid) {
    struct target_thread *tthread;

    if (!(tthread = __gdb_load_cached_thread(target,tid))) {
	if (!errno) 
	    errno = EINVAL;
	verror("could not load cached thread %"PRIiTID"\n",tid);
	return 0;
    }

    return __gdb_get_cpl_thread(target,tthread);
}

static target_status_t gdb_handle_exception(struct target *target,
					    int *again,void *priv) {
    struct gdb_state *gstate = (struct gdb_state *)target->state;
    struct gdb_rsp_stop_status *ss =
	(struct gdb_rsp_stop_status *)&gstate->last_stop_status;
    target_status_t tstatus;
    REGVAL ipval;
    int cpl;
    tid_t tid;
    struct target_thread *tthread;
    struct probepoint *pp;


    tstatus = gdb_status(target);
    if (tstatus == TSTATUS_ERROR) {
	vwarn("failed to load status for GDB stub (target %s);"
	      " returning to user!\n",target->name);
	goto out_err;
    }
    else if (tstatus == TSTATUS_UNKNOWN) {
	vwarn("unknown status for GDB stub (target %s);"
	      " returning to user!\n",target->name);
	goto out_err;
    }
    else if (tstatus == TSTATUS_RUNNING) {
	vwarn("%s is running; ignoring\n",target->name);
	if (again)
	    *again = 0;
	return tstatus;
    }
    else if (tstatus == TSTATUS_PAUSED) {
	target_clear_state_changes(target);

	vdebug(3,LA_TARGET,LF_GDB,"new debug event\n");

	target->monitorhandling = 1;

	/* Force current thread to be reloaded. */
	target->current_thread = NULL;

	/*
	 * Load the global thread (machine state) very first... we have
	 * to be able to read some register state!
	 */
	if (!__gdb_load_current_thread(target,0,1)) {
	    verror("could not load global thread!\n");
	    goto out_err;
	}

	/*
	 * Grab EIP and CPL first so we can see if we're in user or
	 * kernel space and print better messages.
	 */
	errno = 0;
	cpl = __gdb_get_cpl(target,TID_GLOBAL);
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
	 * Give the hops a chance to update.
	 */
	if (gstate->hops && gstate->hops->handle_exception_ours) {
	    gstate->hops->handle_exception_ours(target);
	}

	/* 
	 * Reload the current thread.  We don't force it because we
	 * flush all threads before continuing the loop via again:,
	 * or in target_resume/target_singlestep.
	 */
	gdb_load_current_thread(target,0);

	tthread = target->current_thread;

	if (!tthread) {
	    verror("could not load current thread!\n");
	    goto out_err_again;
	}

	tid = target->current_thread->tid;

	if (__gdb_in_userspace(target,cpl,ipval)) {
	    vdebug(3,LA_TARGET,LF_GDB,
		   "user-mode debug event at EIP 0x%"PRIxADDR" in tid %"PRIiTID
		   "; will try to handle it!\n",ipval,tid);
	}

	vdebug(5,LA_TARGET,LF_GDB,
	       "thread %d at IP 0x%"PRIxADDR"\n",tid,ipval);
    }
    else {
	verror("bad GDB status %d; aborting!\n",tstatus);
	goto out_err;
    }

    /*
     * Handle the exception!  We loaded everything we needed above...
     */
    switch (ss->reason) {
    case GDB_RSP_STOP_UNKNOWN:
    case GDB_RSP_STOP_NONE:
	return TSTATUS_ERROR;
    case GDB_RSP_STOP_SIGNAL:
	if (ss->signal == SIGTRAP) {
	    /*
	     * Must be a single step -- wait -- how do we know?  I guess
	     * for now, it'll be whether or not the event happened at a
	     * breakpoint, and if the IP is the breakpoint.  Anything
	     * else we'll have to assume is a single step.  Then if we
	     * can't find a thread that is stepping, maybe it's an
	     * exception somewhere else.
	     */
	    vdebug(9,LA_TARGET,LF_GDB,"checking for breakpoint hit\n");

	    pp = (struct probepoint *) \
		g_hash_table_lookup(tthread->hard_probepoints,(gpointer)ipval);
	    if (pp) {
		vdebug(5,LA_TARGET,LF_GDB,
		       "found hw break on 0x%"PRIxADDR"\n",ipval);
	    }
	    else {
		pp = (struct probepoint *) \
		    g_hash_table_lookup(target->soft_probepoints,
					(gpointer)ipval);
		if (pp) {
		    vdebug(5,LA_TARGET,LF_GDB,
			   "found sw break on 0x%"PRIxADDR"\n",ipval);
		}
		else {
		    vdebug(5,LA_TARGET,LF_GDB,
			   "did not find hw/sw break; must be step!\n");
		}
	    }

	    /*
	     * Handle the breakpoint, if there was one:
	     */
	    if (pp) {
		target->ops->handle_break(target,tthread,pp,0);
		goto out_bp_again;
	    }

	    /*
	     * Ok, hunt down the single step -- if we can!
	     */
	    if (target->sstep_thread == tthread) {
		vdebug(5,LA_TARGET,LF_GDB,"assuming single step in tid %d\n",
		       tthread->tid);

		pp = tthread->tpc->probepoint;

		target->ops->handle_step(target,tthread,pp);

		goto out_ss_again;
	    }

	    /*
	     * Finally, if there's not a single step, 
	     */
	    vwarn("could not find hardware bp and not sstep'ing;"
		  " letting user handle fault at 0x%"PRIxADDR"!\n",ipval);
	    goto out_paused;
	}
	else {
	    vwarn("target %s signaled unexpectedly with %lu; ignoring!\n",
		  target->name,ss->signal);
	}
	break;
    case GDB_RSP_STOP_WATCH:
    case GDB_RSP_STOP_RWATCH:
    case GDB_RSP_STOP_AWATCH:
	vdebug(5,LA_TARGET,LF_GDB,"watchpoint 0x%"PRIxADDR"\n",ss->addr);
	break;
    case GDB_RSP_STOP_LIBRARY:
	vdebug(5,LA_TARGET,LF_GDB,"library notification not supported!\n");
	break;
    case GDB_RSP_STOP_REPLAYLOG:
	vdebug(5,LA_TARGET,LF_GDB,"replaylog notification not supported!\n");
	break;
    case GDB_RSP_STOP_EXITED:
	vdebug(5,LA_TARGET,LF_GDB,"exited notification not supported!\n");
	break;
    case GDB_RSP_STOP_TERMINATED:
	vdebug(5,LA_TARGET,LF_GDB,"termination notification not supported!\n");
	break;
    default:
	verror("bad GDB stop status %d; aborting!\n",ss->reason);
	break;
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

static target_status_t gdb_status(struct target *target) {
    struct gdb_state *gstate = (struct gdb_state *)target->state;
    target_status_t retval = TSTATUS_UNKNOWN;

    if (gstate->rsp_status_valid) {
        vdebug(4,LA_TARGET,LF_GDB,
	       "current GDB stub (%s) status is valid\n",target->name);
	return target->status;
    }

    retval = gdb_rsp_load_status(target);
    if (retval == TSTATUS_ERROR) {
	verror("could not load status for target %s\n",target->name);
	return retval;
    }

    gstate->rsp_status_valid = 1;

    vdebug(9,LA_TARGET,LF_GDB,"target %s status %d\n",target->name,retval);

    return retval;
}

static int gdb_pause(struct target *target,int nowait) {
    struct gdb_state *gstate = (struct gdb_state *)target->state;
    struct timeval check_tv = { 0,0};
    target_poll_outcome_t outcome;
    int pstatus;
    target_status_t status;

    vdebug(5,LA_TARGET,LF_GDB,"target %s\n",target->name);

    status = gdb_status(target);
    if (status == TSTATUS_ERROR)
	vwarn("failed to load status for GDB stub (target %s);"
	      " trying to pause anyway!\n",target->name);
    else if (status == TSTATUS_UNKNOWN)
	vwarn("unknown status for GDB stub (target %s);"
	      " trying to pause anyway!\n",target->name);

    if (gdb_rsp_pause(target)) {
	verror("could not pause target %s!\n",target->name);
	return -1;
    }

    /*
     * Give the hops a chance to handle pause.
     */
    if (gstate->hops && gstate->hops->handle_pause) {
	gstate->hops->handle_pause(target);
    }

    target_set_status(target,TSTATUS_PAUSED);

    gstate->rsp_status_valid = 0;
    status = gdb_rsp_load_status(target);
    if (status == TSTATUS_UNKNOWN || status == TSTATUS_ERROR)
	vwarn("could not reload GDB stub status target %s after pause!\n",
	      target->name);
    else 
	gstate->rsp_status_valid = 1;

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
     * We pass in a 0,0 timeval so that the select() in gdb_poll
     * truly polls.
     *
     * Also note that we don't care what the outcome is.
     */
    gdb_poll(target,&check_tv,&outcome,&pstatus);

    return 0;
}

static int __gdb_resume(struct target *target,int detaching) {
    struct gdb_state *gstate = (struct gdb_state *)target->state;
    int rc;
    target_status_t status;

    vdebug(5,LA_TARGET,LF_GDB,"target %s\n",target->name);

    status = gdb_status(target);
    if (status == TSTATUS_ERROR)
	vwarn("failed to load status for GDB stub (target %s);"
	      " trying to resume anyway!\n",target->name);
    else if (status == TSTATUS_UNKNOWN)
	vwarn("unknown status for GDB stub (target %s);"
	      " trying to resume anyway!\n",target->name);

    if (target_status(target) != TSTATUS_PAUSED) {
	vwarn("not paused; not invalidating and resuming; BUG?\n");
	return -1;
    }

    REGVAL ipval = target_read_reg(target,TID_GLOBAL,target->ipregno);
    target_write_reg(target,TID_GLOBAL,target->ipregno,ipval);

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

    /*
     * Flush machine state via gdb_rsp_write_regs .
     */
    if ((rc = regcache_isdirty(gstate->machine))) {
	vdebug(7,LA_TARGET,LF_GDB,
	       "machine dirty; writing %d regs!\n",rc);

	rc = gdb_rsp_write_regs(target,gstate->machine);
	if (rc) {
	    verror("could not write CPU regs!\n");
	    target_set_status(target,TSTATUS_UNKNOWN);
	    return rc;
	}
    }
    else {
	vdebug(7,LA_TARGET,LF_GDB,
	       "machine state not dirty; not writing regs!\n");
    }

    regcache_mark_flushed(gstate->machine);
    regcache_invalidate(gstate->machine);
    gstate->machine_valid = 0;

    if (gstate->stepping)
	rc = gdb_rsp_step(target);
    else
	rc = gdb_rsp_resume(target);
    if (rc) {
	if (gstate->fd < 0) {
	    verror("cannot resume; disconnected!\n");
	    target_set_status(target,TSTATUS_UNKNOWN);
	    return rc;
	}
    }

    target_set_status(target,TSTATUS_RUNNING);

    return rc;
}

static int gdb_resume(struct target *target) {
    return __gdb_resume(target,0);
}

static target_status_t gdb_monitor(struct target *target) {
    struct gdb_state *gstate = (struct gdb_state *)target->state;
    int ret;
    struct timeval tv;
    fd_set inset;
    int again;
    target_status_t retval;

    while (1) {
	if (gstate->fd < 0) {
	    verror("server disconnected!\n");
	    return TSTATUS_UNKNOWN;
	}

        tv.tv_sec = 0;
        tv.tv_usec = 50;
        FD_ZERO(&inset);
        FD_SET(gstate->fd,&inset);

        /* wait for input from the stub */
        ret = select(gstate->fd + 1,&inset,NULL,NULL,&tv);
        if (ret == -1) // timeout
            continue;

        if (!FD_ISSET(gstate->fd,&inset)) 
            continue; // nothing from stub

        /* we've got something from the stub; let's see what it is! */
	ret = gdb_rsp_recv(target,0,0,NULL);

	again = 0;
	retval = gdb_handle_exception(target,&again,NULL);
	if (retval == TSTATUS_ERROR && again == 0) {
	    target->needmonitorinterrupt = 0;
	    return retval;
	}
	else if (target->needmonitorinterrupt) {
	    target->needmonitorinterrupt = 0;
	    return TSTATUS_INTERRUPTED;
	}

	__gdb_resume(target,0);

	/*
	else if (retval == TSTATUS_PAUSED && again == 0)
	    return retval;
	*/
	/*
	if (gdb_load_dominfo(target)) {
	    vwarn("could not load dominfo for dom %d, trying to unpause anyway!\n",
		  xstate->id);
	    __gdb_resume(target,0);
	}
	else if (xstate->dominfo.paused) {
	    __gdb_resume(target,0);
	}
	*/
    }

    return TSTATUS_ERROR; /* Never hit, just compiler foo */
}

static target_status_t gdb_poll(struct target *target,struct timeval *tv,
				target_poll_outcome_t *outcome,int *pstatus) {

}

static int gdb_attach_evloop(struct target *target,struct evloop *evloop) {

}

static int gdb_detach_evloop(struct target *target) {

}

tid_t gdb_gettid(struct target *target) {
    struct target_thread *tthread;

    if (target->current_thread && target->current_thread->valid)
	return target->current_thread->tid;

    tthread = gdb_load_current_thread(target,0);
    if (!tthread) {
	verror("could not load current thread to get TID!\n");
	return 0;
    }

    return tthread->tid;
}

void gdb_free_thread_state(struct target *target,void *state) {
    if (state)
	free(state);
}

static struct target_thread *__gdb_load_cached_thread(struct target *target,
						      tid_t tid) {
    struct target_thread *tthread;

    tthread = target_lookup_thread(target,tid);
    if (!tthread)
	return NULL;

    if (!tthread->valid)
	return gdb_load_thread(target,tid,0);

    return tthread;
}

static struct target_thread *__gdb_load_current_thread(struct target *target,
						       int force,
						       int globalonly) {
    struct gdb_state *gstate = (struct gdb_state *)target->state;
    int rc;
    struct target_thread *tthread = NULL;
    struct gdb_thread_state *tstate = NULL;
    //struct gdb_thread_state *gtstate;
    REG rip,rcs;
    REGVAL ipval,cs;
    //uint64_t pgd = 0;
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
	verror("target not paused; cannot load current thread!\n");
	errno = EBUSY;
	return NULL;
    }

    /*
     * The first thing to do is load the machine state into the global
     * thread, and set it as valid -- EVEN THOUGH we have not loaded
     * thread_info for it!  We must do this so that a whole bunch of
     * register reads can work via the API.
     */
    if (!gstate->machine_valid) {
	rc = gdb_rsp_read_regs(target,gstate->machine);
	if (rc) {
	    verror("could not read CPU regs!\n");
	    return NULL;
	}

	gstate->machine_valid = 1;

	/*
	 * Let the helper ops help!
	 */
	if (gstate->hops && gstate->hops->load_machine) {
	    rc = gstate->hops->load_machine(target,gstate->machine);
	    if (rc) {
		vwarn("helper ops load_machine failed!\n");
	    }
	}
    }

    //gtstate = (struct gdb_thread_state *)target->global_thread->state;

    /*
     * Load EIP for info, and CPL for user-mode check.  This should work
     * out whether we're an OS or a process; in the former case, threads
     * will have a context, either kernel or user; in the latter, if the
     * stub sets %cs appropriately, CPL will be 3 == user; else, if it
     * does not, CPL will be 0 -- but the point is it will be
     * consistent.  I could also always force the CPL to 3 if we're not
     * attached to an OS, but I'd prefer not to do that, so that the
     * right thing still happens whether or not there's a personality
     * attached.
     *
     * NB: note that these two calls do *not* go through the target
     * API.  They cannot, because the global thread has not been loaded
     * yet.  And we can't finish loading the global thread yet, even
     * though we have the machine state, because we don't know which
     * thread context's regcache to put the machine state into (kernel
     * or userspace).
     */
    errno = 0;
    if (target->arch->type == ARCH_X86_64) {
	rip = REG_X86_64_RIP;
	rcs = REG_X86_64_CS;
    }
    else {
	rip = REG_X86_EIP;
	rcs = REG_X86_CS;
    }

    rc = regcache_read_reg(gstate->machine,rip,&ipval);
    if (rc) {
	verror("could not read IP from machine state!\n");
	goto errout;
    }
    rc = regcache_read_reg(gstate->machine,rcs,&cs);
    if (rc) {
	verror("could not read IP from machine state!\n");
	goto errout;
    }

    cpl = 0x3 & cs;

    /* Keep loading the global thread... */
    if (!target->global_thread->valid) {
	if (__gdb_in_userspace(target,cpl,ipval))
	    target->global_thread->tidctxt = THREAD_CTXT_USER;
	else
	    target->global_thread->tidctxt = THREAD_CTXT_KERNEL;

	/*
	 * Push the registers into the regcache!
	 */
	target_regcache_copy_from(target->global_thread,
				  target->global_thread->tidctxt,
				  gstate->machine);

	/*
	 * Very important.  If thread is in userspace, we need to get
	 * Xen's special kernel_sp register and set it as SP for the
	 * kernel context so that personalities can load kernel threads
	 * on i386 because they need kernel_sp to find the stack.  On
	 * x86_64 this is not necessary.
	 */
	if (target->global_thread->tidctxt == THREAD_CTXT_USER
	    && target->personality == TARGET_PERSONALITY_OS) {
	    vwarn("not supported yet!!!\n");
	    /*
	    target_regcache_init_reg_tidctxt(target,target->global_thread,
					     THREAD_CTXT_KERNEL,target->spregno,
					     gtstate->context.kernel_sp);
	    */
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
     *
     * Can't do this from GDB with only gp regs!
     */
    /*
    __gdb_vm_pgd(target,TID_GLOBAL,&pgd);

    vdebug(9,LA_TARGET,LF_GDB,
	   "loading current thread (ip = 0x%"PRIxADDR",pgd = 0x%"PRIxADDR","
	   "cpl = %d,tidctxt = %d)\n",ipval,pgd,cpl,
	   target->global_thread->tidctxt);
    */

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
	tstate = (struct gdb_thread_state *)tthread->state;
	if (!tstate)
	    tthread->state = tstate = \
		(struct gdb_thread_state *)calloc(1,sizeof(*tstate));

	/* Also update the regcache for the current thread. */
	target_regcache_copy_all(target->global_thread,
				 target->global_thread->tidctxt,
				 tthread,tthread->tidctxt);
    }
    else
	target->current_thread = target->global_thread;

    target_thread_set_status(target->current_thread,THREAD_STATUS_RUNNING);

    vdebug(4,LA_TARGET,LF_GDB,
	   "loaded current thread %d\n",target->current_thread->tid);

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

static struct target_thread *gdb_load_current_thread(struct target *target,
						     int force) {
    return __gdb_load_current_thread(target,force,0);
}

static struct target_thread *gdb_load_thread(struct target *target,
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
	    gdb_load_current_thread(target,force);
	    return target->global_thread;
	}
    }

    /*
     * If we haven't loaded current_thread yet, we really should load it
     * because otherwise we don't know if current_thread->tid == @tid.
     * If it does, we don't want to do the below stuff, which only
     * applies to non-running threads.
     */
    if (!gdb_load_current_thread(target,force)) {
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
	return gdb_load_current_thread(target,force);
    }
    /*
     * Otherwise, try to lookup thread @tid.
     */
    else if ((tthread = target_lookup_thread(target,tid))) {
	if (tthread->valid && !force) {
	    vdebug(4,LA_TARGET,LF_GDB,
		   "did not need to load thread; copy is valid\n");
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

static struct array_list *gdb_list_available_tids(struct target *target) {
    return target_personality_list_available_tids(target);
}

static int gdb_load_all_threads(struct target *target,int force) {
    struct array_list *cthreads;
    int rc = 0;
    int i;
    struct target_thread *tthread;

    cthreads = target_list_threads(target);

    for (i = 0; i < array_list_len(cthreads); ++i) {
	tthread = (struct target_thread *)array_list_item(cthreads,i);

	vdebug(8,LA_TARGET,LF_GDB,
	       "tid %"PRIiTID" (%p)\n",tthread->tid,tthread);

	if (!gdb_load_thread(target,tthread->tid,force)) {
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

static int gdb_load_available_threads(struct target *target,int force) {
    /*
     * Load the current thread first to load the global thread.  The
     * current thread will get loaded again in the loop below if @force
     * is set...
     */
    if (!__gdb_load_current_thread(target,force,1)) {
	verror("could not load current thread!\n");
	return -1;
    }

    return target_personality_load_available_threads(target,force);
}

/*
 * This only flushes CPU state, from the global thread, to the machine.
 *
 * NB: we don't write the machine until we unpause the target!
 */
static int gdb_flush_global_thread(struct target *target,
				   struct target_thread *current_thread) {
    struct target_thread *tthread;
    struct gdb_state *xstate = (struct gdb_state *)(target->state);
    tid_t tid;
    REGVAL ipval;

    tthread = target->global_thread;
    tid = tthread->tid;

    if (!tthread) {
	verror("global thread not loaded; BUG!!!\n");
	errno = EINVAL;
	return -1;
    }

    vdebug(5,LA_TARGET,LF_GDB,"%s tid %"PRIiTID"\n",target->name,tid);

    if (!tthread->valid || !tthread->dirty) {
	vdebug(8,LA_TARGET,LF_GDB,
	       "%s tid %"PRIiTID" not valid (%d) or not dirty (%d)\n",
	       target->name,tid,tthread->valid,tthread->dirty);
	return 0;
    }

    ipval = target_read_reg(target,tid,target->ipregno);
    vdebug(3,LA_TARGET,LF_GDB,
	   "EIP is 0x%"PRIxREGVAL" before flush (%s tid %"PRIiTID")\n",
	   ipval,target->name,tid);

    /*
     * Just copy the dirty registers from current to gstate->machine.
     */
    if (target_regcache_copy_dirty_to(tthread,tthread->tidctxt,
				      xstate->machine)) {
	verror("failed to copy dirty regs from %s tid %d tidctxt %d to machine!\n",
	       target->name,tid,target->current_thread->tidctxt);
	errno = EINVAL;
	return -1;
    }

    if (target_regcache_mark_flushed(target,tthread,tthread->tidctxt)) {
	vwarn("failed to mark %s tid %d tidctxt %d flushed!\n",
	      target->name,tid,tthread->tidctxt);
    }

    /* Mark cached copy as clean. */
    tthread->dirty = 0;

    return 0;
}

static int gdb_flush_current_thread(struct target *target) {
    struct gdb_state *xstate = (struct gdb_state *)(target->state);
    struct target_thread *tthread;
    tid_t tid;

    if (!target->current_thread) {
	verror("current thread not loaded!\n");
	errno = EINVAL;
	return -1;
    }

    /* gdb_flush_global_thread must be called to handle this. */
    if (target->current_thread == target->global_thread)
	return 0;

    tthread = target->current_thread;
    tid = tthread->tid;

    vdebug(5,LA_TARGET,LF_GDB,"%s tid %"PRIiTID"\n",target->name,tid);

    if (!tthread->valid || !tthread->dirty) {
	vdebug(8,LA_TARGET,LF_GDB,
	       "%s tid %"PRIiTID" not valid (%d) or not dirty (%d)\n",
	       target->name,tid,tthread->valid,tthread->dirty);
	return 0;
    }

    vdebug(3,LA_TARGET,LF_GDB,
	   "EIP is 0x%"PRIxREGVAL" before flush (%s tid %"PRIiTID")\n",
	   target_read_reg(target,tid,target->ipregno),target->name,tid);

    /*
     * Just copy the dirty registers from current to gstate->machine.
     */
    if (target_regcache_copy_dirty_to(tthread,tthread->tidctxt,
				      xstate->machine)) {
	verror("failed to copy dirty regs from %s tid %d tidctxt %d to machine!\n",
	       target->name,tid,target->current_thread->tidctxt);
	errno = EINVAL;
	return -1;
    }

    if (target_regcache_mark_flushed(target,tthread,tthread->tidctxt)) {
	vwarn("failed to mark %s tid %d tidctxt %d flushed!\n",
	      target->name,tid,tthread->tidctxt);
    }

    return target_personality_flush_current_thread(target);
}

static int gdb_flush_thread(struct target *target,tid_t tid) {
    struct target_thread *tthread;

    vdebug(16,LA_TARGET,LF_GDB,"%s\n",target->name);

    /*
     * If we are flushing the global thread (TID_GLOBAL), do it right
     * away.
     */
    if (tid == TID_GLOBAL)
	return gdb_flush_current_thread(target);

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
	vdebug(9,LA_TARGET,LF_GDB,
	       "current thread not loaded to compare with"
	       " tid %"PRIiTID"; exiting, user-mode EIP, or BUG?\n",
	       tid);
    }
    else if (!target->current_thread->valid) {
	vdebug(9,LA_TARGET,LF_GDB,
	       "current thread not valid to compare with"
	       " tid %"PRIiTID"; exiting, user-mode EIP, or BUG?\n",
	       tid);
    }

    /*
     * If the thread tid we are asking for is the current thread and is
     * valid, or if the thread is in our cache and is valid.
     */
    if (target->current_thread && target->current_thread->tid == tid) {
	return gdb_flush_current_thread(target);
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
	return gdb_flush_current_thread(target);

    if (!tthread->valid || !tthread->dirty) {
	vdebug(8,LA_TARGET,LF_GDB,
	       "%s tid %"PRIiTID" not valid (%d) or not dirty (%d)\n",
	       target->name,tthread->tid,tthread->valid,tthread->dirty);
	return 0;
    }

    if (target_personality_flush_thread(target,tid))
	goto errout;

    tthread->dirty = 0;

    return 0;

 errout:
    return -1;
}

static int gdb_flush_all_threads(struct target *target) {
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
	    rc = gdb_flush_thread(target,tthread->tid);
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

	rc = gdb_flush_current_thread(target);
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
    rc = gdb_flush_global_thread(target,current_thread);
    if (rc) {
	verror("could not flush global thread %"PRIiTID"\n",TID_GLOBAL);
	++retval;
    }

    return retval;
}

static int gdb_invalidate_thread(struct target *target,
				 struct target_thread *tthread) {
    return target_personality_invalidate_thread(target,tthread);
}

static int gdb_thread_snprintf(struct target_thread *tthread,
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

static unsigned char *gdb_read(struct target *target,ADDR addr,
			       unsigned long length,unsigned char *buf) {
    struct gdb_state *xstate;
    uint64_t pgd = 0;

    xstate = (struct gdb_state *)target->state;

    if (!xstate->hops || !xstate->hops->read_tid) {
	errno = EINVAL;
	return 0;
    }

    if (__gdb_pgd(target,TID_GLOBAL,&pgd)) {
	verror("could not read pgd for tid %"PRIiTID"!\n",TID_GLOBAL);
	return NULL;
    }

    return xstate->hops->read_tid(target,TID_GLOBAL,pgd,addr,length,buf);
}

static unsigned long gdb_write(struct target *target,ADDR addr,
			       unsigned long length,unsigned char *buf) {
    struct gdb_state *xstate;
    uint64_t pgd = 0;

    xstate = (struct gdb_state *)target->state;

    if (!xstate->hops || !xstate->hops->write_tid) {
	errno = EINVAL;
	return 0;
    }

    if (__gdb_pgd(target,TID_GLOBAL,&pgd)) {
	verror("could not read pgd for tid %"PRIiTID"!\n",TID_GLOBAL);
	return 0;
    }

    return xstate->hops->write_tid(target,TID_GLOBAL,pgd,addr,length,buf);
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
static int __gdb_pgd(struct target *target,tid_t tid,uint64_t *pgd) {
    struct gdb_spec *gspec;
    struct gdb_state *xstate;
    struct target_thread *tthread;
    //struct gdb_thread_state *xtstate;
    REGVAL cr0 = 0,cr3 = 0,cr4 = 0,msr_efer = 0,cpuid_edx = 0;

    gspec = (struct gdb_spec *)target->spec->backend_spec;
    xstate = (struct gdb_state *)target->state;

    if (tid == TID_GLOBAL) {
	tthread = __gdb_load_current_thread(target,0,1);
	if (!tthread) {
	    verror("could not load global thread!\n");
	    return -1;
	}
	/*
	xtstate = (struct gdb_thread_state *)tthread->state;

	if (xtstate->context.vm_assist & (1 << VMASST_TYPE_pae_extended_cr3)) {
	    *pgd = ((uint64_t)xen_cr3_to_pfn(xtstate->context.ctrlreg[3])) \
		       << XC_PAGE_SHIFT;
	}
	else {
	    *pgd = xtstate->context.ctrlreg[3] & ~(__PAGE_SIZE - 1);
	}
	*/

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
	if (target->arch->type == ARCH_X86_64) {
	    regcache_read_reg(xstate->machine,REG_X86_64_CR0,&cr0);
	    regcache_read_reg(xstate->machine,REG_X86_64_CR3,&cr3);
	    regcache_read_reg(xstate->machine,REG_X86_64_CR4,&cr4);
	    regcache_read_reg(xstate->machine,REG_X86_64_MSR_EFER,&msr_efer);
	}
	else {
	    regcache_read_reg(xstate->machine,REG_X86_CR0,&cr0);
	    regcache_read_reg(xstate->machine,REG_X86_CR3,&cr3);
	    regcache_read_reg(xstate->machine,REG_X86_CR4,&cr4);
	    regcache_read_reg(xstate->machine,REG_X86_MSR_EFER,&msr_efer);
	}
	cpuid_edx = ADDRMAX;

	*pgd = cr3;

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

	if (vdebug_is_on(8,LA_TARGET,LF_GDB)) {
	    char buf[256];
	    buf[0] = '\0';
	    target_arch_x86_v2p_flags_snprintf(target,xstate->v2p_flags,
					       buf,sizeof(buf));
	    vdebug(8,LA_TARGET,LF_TARGET,"v2p_flags = %s\n",buf);
	}

	/* Also quickly set the V2P_PV flag if this domain is paravirt. */
	if (!gspec->is_kvm)
	    xstate->v2p_flags |= ARCH_X86_V2P_PV;
    }
    else {
	tthread = gdb_load_thread(target,tid,0);
	if (!tthread) {
	    verror("could not load tid %"PRIiTID"!\n",tid);
	    return -1;
	}

	if (target_os_thread_get_pgd_phys(target,tid,pgd)) {
	    verror("could not get phys pgd for tid %"PRIiTID": %s!\n",
		   tid,strerror(errno));
	    return -1;
	}
    }

    vdebug(12,LA_TARGET,LF_GDB,
	   "tid %"PRIiTID" pgd (phys) = 0x%"PRIx64"\n",tid,*pgd);

    return 0;
}

static int gdb_addr_v2p(struct target *target,tid_t tid,
			   ADDR vaddr,ADDR *paddr) {
    struct gdb_state *xstate;
    uint64_t pgd = 0;

    xstate = (struct gdb_state *)target->state;

    if (__gdb_pgd(target,tid,&pgd)) {
	verror("could not read pgd for tid %"PRIiTID"!\n",tid);
	return -1;
    }

    if (!xstate->hops || !xstate->hops->addr_v2p) {
	errno = EINVAL;
	return -1;
    }

    return xstate->hops->addr_v2p(target,tid,pgd,vaddr,paddr);
}

static unsigned char *gdb_read_phys(struct target *target,ADDR paddr,
				    unsigned long length,unsigned char *buf) {
    struct gdb_state *xstate;

    xstate = (struct gdb_state *)target->state;

    if (!xstate->hops || !xstate->hops->read_phys) {
	errno = EINVAL;
	return NULL;
    }

    return xstate->hops->read_phys(target,paddr,length,buf);
}

static unsigned long gdb_write_phys(struct target *target,ADDR paddr,
				    unsigned long length,unsigned char *buf) {
    struct gdb_state *xstate;

    xstate = (struct gdb_state *)target->state;

    if (!xstate->hops || !xstate->hops->write_phys) {
	errno = EINVAL;
	return 0;
    }

    return xstate->hops->write_phys(target,paddr,length,buf);
}

static struct target_memmod *gdb_insert_sw_breakpoint(struct target *target,
						      tid_t tid,ADDR addr) {
    if (gdb_rsp_insert_break(target,addr,GDB_RSP_BREAK_SW,1)) {
	verror("could not insert breakpoint!\n");
	return NULL;
    }
    else
	return target_memmod_create(target,tid,addr,0,MMT_BP,NULL,0);
}

static int gdb_remove_sw_breakpoint(struct target *target,tid_t tid,
				    struct target_memmod *mmod) {
    if (gdb_rsp_remove_break(target,mmod->addr,GDB_RSP_BREAK_SW,1)) {
	verror("could not remove breakpoint!\n");
	return -1;
    }
    else
	return 0;
}

static int gdb_enable_sw_breakpoint(struct target *target,tid_t tid,
				    struct target_memmod *mmod) {
    if (gdb_rsp_insert_break(target,mmod->addr,GDB_RSP_BREAK_SW,1)) {
	verror("could not insert breakpoint!\n");
	return -1;
    }
    else
	return 0;
}

static int gdb_disable_sw_breakpoint(struct target *target,tid_t tid,
				     struct target_memmod *mmod) {
    if (gdb_rsp_remove_break(target,mmod->addr,GDB_RSP_BREAK_SW,1)) {
	verror("could not remove breakpoint!\n");
	return -1;
    }
    else
	return 0;
}

#define CHECKTIDGLOBAL(tid)					\
    if ((tid) != TID_GLOBAL) {					\
        verror("only TID_GLOBAL supported, not tid %d!\n",tid);	\
	errno = EINVAL;						\
	return -1;						\
    }

#define CHECKTIDGLOBALORCURRENT(_T)					\
    if ((_T) != TID_GLOBAL						\
	&& (!target->current_thread || target->current_thread->tid != (_T))) { \
	verror("only TID_GLOBAL/current tid supported, not tid %d!\n",(_T)); \
	errno = EINVAL;							\
	return -1;							\
    }

static int gdb_set_hw_breakpoint(struct target *target,tid_t tid,
				 REG num,ADDR addr) {
    CHECKTIDGLOBAL(tid);
    if (gdb_rsp_insert_break(target,addr,GDB_RSP_BREAK_HW,1)) {
	verror("could not insert breakpoint!\n");
	return -1;
    }
    else
	return 0;
}

static int gdb_set_hw_watchpoint(struct target *target,tid_t tid,
				 REG num,ADDR addr,
				 probepoint_whence_t whence,
				 probepoint_watchsize_t watchsize) {
    gdb_rsp_break_t bt = GDB_RSP_BREAK_WATCH;
    int ws = target->arch->wordsize;

    CHECKTIDGLOBAL(tid);

    if (whence == PROBEPOINT_WRITE) bt = GDB_RSP_BREAK_AWATCH;
    else if (whence == PROBEPOINT_READWRITE) bt = GDB_RSP_BREAK_RWATCH;

    if (watchsize == PROBEPOINT_L0) ws = 0;
    else if (watchsize == PROBEPOINT_L2) ws = 2;
    else if (watchsize == PROBEPOINT_L4) ws = 4;
    else if (watchsize == PROBEPOINT_L8) ws = 8;

    if (gdb_rsp_insert_break(target,addr,bt,ws)) {
	verror("could not insert breakpoint!\n");
	return -1;
    }
    else
	return 0;
}

static int gdb_unset_hw_breakpoint(struct target *target,tid_t tid,REG num) {

}

static int gdb_unset_hw_watchpoint(struct target *target,tid_t tid,REG num) {

}

static int gdb_disable_hw_breakpoints(struct target *target,tid_t tid) {

}

static int gdb_enable_hw_breakpoints(struct target *target,tid_t tid) {

}

static int gdb_disable_hw_breakpoint(struct target *target,tid_t tid,REG dreg) {

}

static int gdb_enable_hw_breakpoint(struct target *target,tid_t tid,REG dreg) {

}


static int gdb_singlestep(struct target *target,tid_t tid,int isbp,
			  struct target *overlay) {
    struct gdb_state *gstate = (struct gdb_state *)target->state;
    struct target_thread *tthread;

    CHECKTIDGLOBALORCURRENT(tid);

    tthread = __gdb_load_cached_thread(target,tid);
    gstate->stepping = 1;
    target->sstep_thread = tthread;

    return 0;
}

static int gdb_singlestep_end(struct target *target,tid_t tid,
			      struct target *overlay) {
    struct gdb_state *gstate = (struct gdb_state *)target->state;
    struct target_thread *tthread;

    CHECKTIDGLOBALORCURRENT(tid);

    tthread = __gdb_load_cached_thread(target,tid);
    gstate->stepping = 0;

    if (target->sstep_thread == tthread) {
	vdebug(5,LA_TARGET,LF_GDB,"clearing sstep flag for tid %d\n",tid);
    }
    else if (target->sstep_thread) {
	vwarn("was told to clear sstep flag for tid %d, but tid %d was stepping;"
	      " clearing anyway!\n",tid,target->sstep_thread->tid);
    }
    else {
	vwarn("was told to clear sstep flag for tid %d, but no tid was stepping;"
	      " clearing anyway!\n",tid);
    }

    target->sstep_thread = NULL;

    return 0;
}
