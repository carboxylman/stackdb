/*
 * Copyright (c) 2011, 2012, 2013 The University of Utah
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
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <bits/wordsize.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <dirent.h>
#include <sys/time.h>
#include <argp.h>

#include <gelf.h>
#include <elf.h>
#include <libelf.h>

#include "waitpipe.h"
#include "evloop.h"

#include "dwdebug.h"
#include "dwdebug_priv.h"

#include "target_api.h"
#include "target.h"
#include "target_linux_userproc.h"

#define EF_RF (0x00010000)

/*
 * Prototypes.
 */
struct target *linux_userproc_instantiate(struct target_spec *spec,
					  struct evloop *evloop);

static struct target *linux_userproc_attach(struct target_spec *spec,
					    struct evloop *evloop);
static struct target *linux_userproc_launch(struct target_spec *spec,
					    struct evloop *evloop);

static int linux_userproc_snprintf(struct target *target,
				   char *buf,int bufsiz);
static int linux_userproc_init(struct target *target);
static int linux_userproc_postloadinit(struct target *target);
static int linux_userproc_attach_internal(struct target *target);
static int linux_userproc_detach(struct target *target);
static int linux_userproc_fini(struct target *target);
static int linux_userproc_kill(struct target *target,int sig);
static int linux_userproc_loadspaces(struct target *target);
static int linux_userproc_loadregions(struct target *target,
				      struct addrspace *space);
static int linux_userproc_loaddebugfiles(struct target *target,
					 struct addrspace *space,
					 struct memregion *region);

static struct target *
linux_userproc_instantiate_overlay(struct target *target,
				   struct target_thread *tthread,
				   struct target_spec *spec);

static target_status_t linux_userproc_status(struct target *target);
static int linux_userproc_pause(struct target *target,int nowait);
static int linux_userproc_resume(struct target *target);
static target_status_t linux_userproc_monitor(struct target *target);
static target_status_t linux_userproc_poll(struct target *target,
					   struct timeval *tv,
					   target_poll_outcome_t *outcome,
					   int *pstatus);
int linux_userproc_attach_evloop(struct target *target,struct evloop *evloop);
int linux_userproc_detach_evloop(struct target *target);
static unsigned char *linux_userproc_read(struct target *target,
					  ADDR addr,
					  unsigned long length,
					  unsigned char *buf);
static unsigned long linux_userproc_write(struct target *target,
					  ADDR addr,
					  unsigned long length,
					  unsigned char *buf);
static char *linux_userproc_reg_name(struct target *target,REG reg);
static REG linux_userproc_dwregno_targetname(struct target *target,char *name);
static REG linux_userproc_dw_reg_no(struct target *target,common_reg_t reg);

static tid_t linux_userproc_gettid(struct target *target);
static void linux_userproc_free_thread_state(struct target *target,void *state);
static struct target_thread *linux_userproc_load_thread(struct target *target,
							tid_t tid,int force);
static struct target_thread *linux_userproc_load_current_thread(struct target *target,
								int force);
static int linux_userproc_load_all_threads(struct target *target,int force);
static int linux_userproc_pause_thread(struct target *target,tid_t tid,
				       int nowait);
static int linux_userproc_flush_thread(struct target *target,tid_t tid);
static int linux_userproc_flush_current_thread(struct target *target);
static int linux_userproc_flush_all_threads(struct target *target);
static int linux_userproc_thread_snprintf(struct target_thread *tthread,
					  char *buf,int bufsiz,
					  int detail,char *sep,char *kvsep);

static REGVAL linux_userproc_read_reg(struct target *target,tid_t tid,REG reg);
static int linux_userproc_write_reg(struct target *target,tid_t tid,REG reg,
				    REGVAL value);
static GHashTable *linux_userproc_copy_registers(struct target *target,tid_t tid);
static REG linux_userproc_get_unused_debug_reg(struct target *target,tid_t tid);
static int linux_userproc_set_hw_breakpoint(struct target *target,tid_t tid,
					    REG num,ADDR addr);
static int linux_userproc_set_hw_watchpoint(struct target *target,tid_t tid,
					    REG num,ADDR addr,
					    probepoint_whence_t whence,
					    probepoint_watchsize_t watchsize);
static int linux_userproc_unset_hw_breakpoint(struct target *target,tid_t tid,
					      REG num);
static int linux_userproc_unset_hw_watchpoint(struct target *target,tid_t tid,
					      REG num);
int linux_userproc_disable_hw_breakpoints(struct target *target,tid_t tid);
int linux_userproc_enable_hw_breakpoints(struct target *target,tid_t tid);
int linux_userproc_disable_hw_breakpoint(struct target *target,tid_t tid,
					 REG dreg);
int linux_userproc_enable_hw_breakpoint(struct target *target,tid_t tid,
					REG dreg);
int linux_userproc_notify_sw_breakpoint(struct target *target,ADDR addr,
					int notification);
int linux_userproc_singlestep(struct target *target,tid_t tid,int isbp,
			      struct target *overlay);
int linux_userproc_singlestep_end(struct target *target,tid_t tid,
				  struct target *overlay);


static int linux_userproc_evloop_add_tid(struct target *target,int tid);
static int linux_userproc_evloop_del_tid(struct target *target,int tid);

/*
 * Set up the target interface for this library.
 */
struct target_ops linux_userspace_process_ops = {
    .snprintf = linux_userproc_snprintf,

    .init = linux_userproc_init,
    .fini = linux_userproc_fini,
    .attach = linux_userproc_attach_internal,
    .detach = linux_userproc_detach,
    .kill = linux_userproc_kill,
    .loadspaces = linux_userproc_loadspaces,
    .loadregions = linux_userproc_loadregions,
    .loaddebugfiles = linux_userproc_loaddebugfiles,
    .postloadinit = linux_userproc_postloadinit,

    .instantiate_overlay = linux_userproc_instantiate_overlay,

    .status = linux_userproc_status,
    .pause = linux_userproc_pause,
    .resume = linux_userproc_resume,
    .monitor = linux_userproc_monitor,
    .poll = linux_userproc_poll,
    .read = linux_userproc_read,
    .write = linux_userproc_write,
    .regname = linux_userproc_reg_name,
    .dwregno_targetname = linux_userproc_dwregno_targetname,
    .dwregno = linux_userproc_dw_reg_no,

    .gettid = linux_userproc_gettid,
    .free_thread_state = linux_userproc_free_thread_state,
    /* There are never any untracked threads in this target. */
    .list_available_tids = target_list_tids,
    /* There are never any untracked threads in this target. */
    .load_available_threads = linux_userproc_load_all_threads,
    .load_thread = linux_userproc_load_thread,
    .load_current_thread = linux_userproc_load_current_thread,
    .load_all_threads = linux_userproc_load_all_threads,
    .pause_thread = linux_userproc_pause_thread,
    .flush_thread = linux_userproc_flush_thread,
    .flush_current_thread = linux_userproc_flush_current_thread,
    .flush_all_threads = linux_userproc_flush_all_threads,
    .thread_snprintf = linux_userproc_thread_snprintf,

    .attach_evloop = linux_userproc_attach_evloop,
    .detach_evloop = linux_userproc_detach_evloop,

    .readreg = linux_userproc_read_reg,
    .writereg = linux_userproc_write_reg,
    .copy_registers = linux_userproc_copy_registers,
    .get_unused_debug_reg = linux_userproc_get_unused_debug_reg,
    .set_hw_breakpoint = linux_userproc_set_hw_breakpoint,
    .set_hw_watchpoint = linux_userproc_set_hw_watchpoint,
    .unset_hw_breakpoint = linux_userproc_unset_hw_breakpoint,
    .unset_hw_watchpoint = linux_userproc_unset_hw_watchpoint,
    .disable_hw_breakpoints = linux_userproc_disable_hw_breakpoints,
    .enable_hw_breakpoints = linux_userproc_enable_hw_breakpoints,
    .disable_hw_breakpoint = linux_userproc_disable_hw_breakpoint,
    .enable_hw_breakpoint = linux_userproc_enable_hw_breakpoint,
    .notify_sw_breakpoint = linux_userproc_notify_sw_breakpoint,
    .singlestep = linux_userproc_singlestep,
    .singlestep_end = linux_userproc_singlestep_end,
};

struct argp_option linux_userproc_argp_opts[] = {
    /* These options set a flag. */
    { "pid",'p',"PID",0,"A target process to attach to.",-4 },
    { "program",'b',"FILE",0,"A program to launch as the target.",-4 },
    { "args",'a',"LIST",0,"A comma-separated argument list.",-4 },
    { "envvars",'e',"LIST",0,"A comma-separated envvar list.",-4 },
    { 0,0,0,0,0,0 },
};

int linux_userproc_spec_to_argv(struct target_spec *spec,int *argc,char ***argv) {
    struct linux_userproc_spec *lspec = 
	(struct linux_userproc_spec *)spec->backend_spec;
    char **av = NULL;
    int ac = 0;
    int rc;
    int i;
    int envstrlen;
    int j;
    char *p;

    if (!lspec) {
	if (argv)
	    *argv = NULL;
	if (argc)
	    *argc = 0;
	return 0;
    }
	
    if (lspec->program) {
	/* -- <lspec->program> */
	ac = 2;
	if (lspec->argv) 
	    for (i = 0; lspec->argv[i] != NULL; ++i,++ac) ;
	envstrlen = 0;
	if (lspec->envp) {
	    /* -e */
	    ++ac;
	    for (i = 0; lspec->envp[i] != NULL; ++i,++ac) 
		envstrlen += strlen(lspec->envp[i]) + 1;
	}

	av = calloc(ac + 1,sizeof(char *));

	j = 0;

	if (lspec->envp) {
	    av[j++] = strdup("-e");
	    envstrlen += 1;
	    av[j] = malloc(envstrlen);
	    i = 0;
	    p = av[j];
	    while (p < (av[j] + envstrlen)) {
		rc = snprintf(p,(av[j] + envstrlen) - p,"%s",lspec->envp[i]);
		++i;
		/*
		 * Since snprintf returns the num chars that were or
		 * would have been printed, this will still term the loop
		 * even though the final value of p is invalid for
		 * future use.
		 */
		p += rc;
	    }
	    ++j;
	}

	av[j++] = strdup("--");
	av[j++] = strdup(lspec->program);

	if (lspec->argv) {
	    for (i = 0; lspec->argv[i] != NULL; ++i) {
		av[j++] = strdup(lspec->argv[i]);
	    }
	}
	av[j] = NULL;
	ac = j + 1;
    }
    else if (lspec->pid > -1) {
	av = calloc(3,sizeof(char *));
	av[0] = strdup("-p");
	av[1] = malloc(11);
	snprintf(av[1],11,"%d",lspec->pid);
	ac = 2;
    }

    if (argv)
	*argv = av;
    if (argc)
	*argc = ac;

    return 0;
}

error_t linux_userproc_argp_parse_opt(int key,char *arg,struct argp_state *state) {
    struct target_argp_parser_state *tstate = \
	(struct target_argp_parser_state *)state->input;
    struct target_spec *spec = NULL;
    struct linux_userproc_spec *lspec;
    struct argp_option *opti;
    int ourkey;
    int count;
    int i;
    int previ;
    char *argdup;

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
    if (spec && spec->target_type == TARGET_TYPE_NONE && tstate->quoted_argc)
	ourkey = 1;
    else {
	ourkey = 0;
	for (opti = &linux_userproc_argp_opts[0]; opti->key != 0; ++opti) {
	    if (key == opti->key) {
		ourkey = 1;
		break;
	    }
	}
    }

    if (ourkey) {
	/* Only claim this as ours if it was one of our keys. */
	if (spec->target_type == TARGET_TYPE_NONE) {
	    spec->target_type = TARGET_TYPE_PTRACE;
	    spec->backend_spec = linux_userproc_build_spec();
	}
	else if (spec->target_type != TARGET_TYPE_PTRACE) {
	    verror("cannot mix arguments for ptrace target (%c) with non-ptrace"
		   " target!\n",key);
	    return EINVAL;
	}

    }
    /*
     * Allow ptrace target to swallow quoted args.
     */
    else if (spec->target_type == TARGET_TYPE_NONE && tstate->quoted_argc) {
	ourkey = 1;
    }

    if (spec->target_type == TARGET_TYPE_PTRACE)
	lspec = (struct linux_userproc_spec *)spec->backend_spec;
    else
	lspec = NULL;

    switch (key) {
    case ARGP_KEY_ARG:
    case ARGP_KEY_ARGS:
	return ARGP_ERR_UNKNOWN;
    case ARGP_KEY_INIT:
    case ARGP_KEY_END:
	return 0;
    case ARGP_KEY_NO_ARGS:
    case ARGP_KEY_SUCCESS:
	/*
	 * Steal any quoted args here...
	 */
	if (spec->target_type == TARGET_TYPE_PTRACE && tstate->quoted_argc) {
	    if (lspec->program) {
		verror("cannot specify both binary to launch and an argv!\n");
		return EINVAL;
	    }
	    lspec->program = strdup(tstate->quoted_argv[0]);
	    lspec->argv = calloc(tstate->quoted_argc + 1,sizeof(char *));
	    for (i = 0; i < tstate->quoted_argc; ++i)
		lspec->argv[i] = strdup(tstate->quoted_argv[i]);
	    lspec->argv[tstate->quoted_argc] = NULL;

	    /* Report our theft :). */
	    tstate->quoted_argc = 0;
	}
	return 0;
    case ARGP_KEY_ERROR:
    case ARGP_KEY_FINI:
	if (lspec && lspec->pid > -1 && lspec->program) {
	    verror("cannot specify both pid (to attach) and binary (to launch!)\n");
	    return EINVAL;
	}
	return 0;

    case 'p':
	lspec->pid = atoi(arg);
	break;
    case 'b':
	lspec->program = strdup(arg);
	if (lspec->argv)
	    lspec->argv[0] = strdup(arg);
	break;
    case 'a':
	count = 1;
	for (i = 0; arg[i] != '\0'; ++i) {
	    if (arg[i] == ',')
		++count;
	}
	lspec->argv = calloc(count+2,sizeof(char *));
	if (lspec->program)
	    lspec->argv[0] = strdup(lspec->program);
	count = 1;
	previ = 0;
	argdup = strdup(arg);
	for (i = 0; argdup[i] != '\0'; ++i) {
	    if (argdup[i] == ',') {
		argdup[i] = '\0';
		lspec->argv[count++] = strdup(&argdup[previ]);
		previ = i + 1;
	    }
	}
	free(argdup);
	lspec->argv[count+1] = NULL;
	break;
    case 'e':
	count = 1;
	for (i = 0; arg[i] != '\0'; ++i) {
	    if (arg[i] == ',')
		++count;
	}
	lspec->envp = calloc(count+1,sizeof(char *));
	lspec->envp[0] = arg;
	count = 1;
	previ = 0;
	argdup = strdup(arg);
	for (i = 0; argdup[i] != '\0'; ++i) {
	    if (argdup[i] == ',') {
		argdup[i] = '\0';
		lspec->envp[count] = strdup(&argdup[previ]);
		previ = i + 1;
	    }
	}
	free(argdup);
	lspec->envp[count] = NULL;
	break;

    default:
	return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

struct argp linux_userproc_argp = { 
    linux_userproc_argp_opts,linux_userproc_argp_parse_opt,NULL,NULL,NULL,NULL,NULL
};
char *linux_userproc_argp_header = "Ptrace Backend Options";

/*
 * If we ever want to support multithreaded targets, we'll have to track
 * fork/clone/vfork via ptrace too.  For now, we just want the bare
 * minimum so we can tell the user about it.
 */
#define INITIAL_PTRACE_OPTS \
    PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXIT

/**
 ** These are the only user-visible functions.
 **/

int linux_userproc_last_signo(struct target *target,tid_t tid) {
    struct target_thread *tthread;

    if (!target)
	return -1;

    tthread = target_lookup_thread(target,tid);
    if (!tthread) {
	verror("thread %"PRIiTID" does not exist; forgot to load?\n",tid);
	errno = EINVAL;
	return -1;
    }

    return ((struct linux_userproc_thread_state *)tthread->state)->last_signo;
}

int linux_userproc_last_status(struct target *target,tid_t tid) {
    struct target_thread *tthread;

    if (!target)
	return -1;

    tthread = target_lookup_thread(target,tid);
    if (!tthread) {
	verror("thread %"PRIiTID" does not exist; forgot to load?\n",tid);
	errno = EINVAL;
	return -1;
    }

    return ((struct linux_userproc_thread_state *)tthread->state)->last_status;
}

int linux_userproc_at_syscall(struct target *target,tid_t tid) {
    struct target_thread *tthread;

    if (!target)
	return -1;

    tthread = target_lookup_thread(target,tid);
    if (!tthread) {
	verror("thread %"PRIiTID" does not exist; forgot to load?\n",tid);
	errno = EINVAL;
	return -1;
    }

    return ((struct linux_userproc_thread_state *)tthread->state)->last_status \
	== (SIGTRAP | 0x80);
}

int linux_userproc_at_exec(struct target *target,tid_t tid) {
    struct target_thread *tthread;

    if (!target)
	return -1;

    tthread = target_lookup_thread(target,tid);
    if (!tthread) {
	verror("thread %"PRIiTID" does not exist; forgot to load?\n",tid);
	errno = EINVAL;
	return -1;
    }

    return ((struct linux_userproc_thread_state *)tthread->state)->last_status \
	== (SIGTRAP | (PTRACE_EVENT_EXEC << 8));
}

int linux_userproc_at_exit(struct target *target,tid_t tid) {
    struct target_thread *tthread;

    if (!target)
	return -1;

    tthread = target_lookup_thread(target,tid);
    if (!tthread) {
	verror("thread %"PRIiTID" does not exist; forgot to load?\n",tid);
	errno = EINVAL;
	return -1;
    }

    return ((struct linux_userproc_thread_state *)tthread->state)->last_status \
	== (SIGTRAP | (PTRACE_EVENT_EXIT<<8));
}

int linux_userproc_pid(struct target *target) {
    struct linux_userproc_state *lstate = \
	(struct linux_userproc_state *)target->state;

    if (!lstate)
	return -1;

    return lstate->pid;
}

struct target *linux_userproc_instantiate(struct target_spec *spec,
					  struct evloop *evloop) {
    struct linux_userproc_spec *lspec = \
	(struct linux_userproc_spec *)spec->backend_spec;

    if (lspec->pid > -1) {
	return linux_userproc_attach(spec,evloop);
    }
    else {
	return linux_userproc_launch(spec,evloop);
    }
}

struct linux_userproc_spec *linux_userproc_build_spec(void) {
    struct linux_userproc_spec *lspec;

    lspec = calloc(1,sizeof(*lspec));
    lspec->pid = -1;

    return lspec;
}

void linux_userproc_free_spec(struct linux_userproc_spec *lspec) {
    char **ptr;

    if (lspec->program)
	free(lspec->program);
    if (lspec->argv) {
	ptr = lspec->argv;
	while (*ptr) {
	    free(*ptr);
	    ++ptr;
	}
	free(lspec->argv);
    }
    if (lspec->envp) {
	ptr = lspec->envp;
	while (*ptr) {
	    free(*ptr);
	    ++ptr;
	}
	free(lspec->envp);
    }

    free(lspec);
}

/*
 * Attaches to @pid.  The caller does all of the normal ptrace
 * interaction; we just facilitate debuginfo-assisted data operations.
 */
static struct target *linux_userproc_attach(struct target_spec *spec,
					    struct evloop *evloop) {
    struct linux_userproc_state *lstate;
    struct target *target;
    char buf[256];
    struct stat sbuf;
    FILE *stfile;
    char pbuf[PATH_MAX*2];
    char main_exe[PATH_MAX];
    int rc;
    struct binfile *binfile;
    struct linux_userproc_spec *lspec = \
	(struct linux_userproc_spec *)spec->backend_spec;
    int pid = lspec->pid;

    vdebug(5,LA_TARGET,LF_LUP,"opening pid %d\n",pid);

    /* This is not strictly true; if they have the right capability they
     * can trace... but this is easier to check.
     */
    if (geteuid() != 0) {
	verror("must be root!\n");
	errno = EPERM;
	return NULL;
    }

    snprintf(buf,256,"/proc/%d/stat",pid);
    if (stat(buf,&sbuf)) {
	verror("stat %s: %s\n",buf,strerror(errno));
	errno = ESRCH;
	return NULL;
    }
    else {
	stfile = fopen(buf,"r");
	if (!stfile) {
	    verror("fopen %s: %s\n",buf,strerror(errno));
	    return NULL;
	}
	else if (!fgets(buf,256,stfile)) {
	    verror("fgets %s: %s\n",buf,strerror(errno));
	    fclose(stfile);
	    return NULL;
	}	    
	if (strlen(buf) && buf[strlen(buf)-1] == '\n')
	    buf[strlen(buf)-1] = '\0';
	fclose(stfile);
    }

    /* Discover the wordsize and endianness of the process, based off
     * its main executable.
     */
    /* first, find the pathname of our main exe */
    snprintf(pbuf,PATH_MAX*2,"/proc/%d/exe",pid);
    if ((rc = readlink(pbuf,main_exe,PATH_MAX - 1)) < 1)
	return NULL;
    main_exe[rc] = '\0';

    if (!(binfile = binfile_open__int(pbuf,spec->debugfile_root_prefix,NULL))) {
	verror("binfile_open %s: %s\n",pbuf,strerror(errno));
	return NULL;
    }

    target = target_create("linux_userspace_process",spec);
    if (!target) 
	return NULL;

    target->live = 1;
    target->writeable = 1;

    /*
     * Save off the binfile, and some stuff from it.
     */
    target->binfile = binfile;
    RHOLD(target->binfile,target);

    target->wordsize = binfile->wordsize;
    target->endian = binfile->endian;

    /* Wordsize and ptrsize the same, obviously... */
    target->ptrsize = target->wordsize;

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

    lstate = (struct linux_userproc_state *)malloc(sizeof(*lstate));
    if (!lstate) {
	target_free(target);
	errno = ENOMEM;
	return NULL;
    }
    memset(lstate,0,sizeof(*lstate));

    lstate->pid = pid;
    lstate->current_tid = 0;

    target->state = lstate;

    if (evloop) {
	target->evloop = evloop;
	linux_userproc_attach_evloop(target,evloop);
    }

    vdebug(5,LA_TARGET,LF_LUP,"opened pid %d\n",pid);

    return target;
}

static struct target *linux_userproc_launch(struct target_spec *spec,
					    struct evloop *evloop) {
    struct linux_userproc_state *lstate;
    struct target *target;
    int pid;
    int newfd;
    int pstatus;
    struct linux_userproc_spec *lspec;
    char *filename;
    char **argv;
    char **envp;
    struct binfile *binfile;
    REFCNT trefcnt;
    int inpfd[2] = { -1,-1 };
    int outpfd[2] = { -1,-1 };
    int errpfd[2] = { -1,-1 };
    int infd = -1;
    int outfd = -1;
    int errfd = -1;

#if __WORDSIZE == 64
#define LUP_SC_EXEC             59
#define LUP_SC_MPROTECT         10
#define LUP_SC_MMAP              9
#define LUP_SC_MUNMAP           11
#define LUP_SC_MMAP2             9 /* no mmap2 */
#define LUP_SC_PRCTL           157
#define LUP_SC_ARCH_PRCTL      158
#define LUP_SC_SET_THREAD_AREA 205
#else
#define LUP_SC_EXEC             11
#define LUP_SC_MPROTECT        125
#define LUP_SC_MMAP             90
#define LUP_SC_MUNMAP           91
#define LUP_SC_MMAP2           192
#define LUP_SC_PRCTL           172
#define LUP_SC_ARCH_PRCTL      172 /* no arch_prctl */
#define LUP_SC_SET_THREAD_AREA 243
#endif

    struct user_regs_struct uregs;
#if __WORDSIZE == 64
    unsigned long orig_eax;
#else
    long int orig_eax;
#endif
    REGVAL syscall = 0;
    char *argv_default[2] = { NULL,NULL };

    lspec = (struct linux_userproc_spec *)spec->backend_spec;

    filename = lspec->program;
    argv = lspec->argv;
    envp = lspec->envp;

    if (argv == NULL || *argv == NULL) {
	/*
	 * We cannot have a NULL argv; just handle it here.
	 */
	argv_default[0] = filename;
	argv = argv_default;
    }

    /*
     * Read the binary and see if it is a dynamic or statically-linked
     * executable.  If it's dynamic, we look for one sequence of
     * syscalls to infer when the the fully-linked program is in
     * memory.  If it's static, we look for another (much simpler)
     * sequence.
     */
    binfile = binfile_open__int(filename,spec->debugfile_root_prefix,NULL);
    if (!binfile) {
	verror("binfile_open %s: %s\n",filename,strerror(errno));
	return NULL;
    }

    target = target_create("linux_userspace_process",spec);
    if (!target) 
	goto errout;

    target->live = 1;
    target->writeable = 1;

    /*
     * Save off the binfile, and some stuff from it.
     */
    target->binfile = binfile;
    RHOLD(target->binfile,target);

    target->wordsize = binfile->wordsize;
    target->endian = binfile->endian;
    target->ptrsize = target->wordsize;

    if (binfile->is_dynamic < 0) {
	verror("could not check if %s is static/dynamic exe; aborting!\n",
	       filename);
	goto errout;
    }
    else if (!binfile->is_dynamic)
	vdebug(2,LA_TARGET,LF_LUP,"executable %s is static\n",filename);
    else 
	vdebug(2,LA_TARGET,LF_LUP,"executable %s is dynamic\n",filename);

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

    lstate = (struct linux_userproc_state *)malloc(sizeof(*lstate));
    if (!lstate) {
	errno = ENOMEM;
	goto errout;
    }
    memset(lstate,0,sizeof(*lstate));

    /* We attach and can't detach, and also can't attach again when the
     * target API tells us to.
     */
    lstate->initdidattach = 1;

    target->state = lstate;

    /*
     * Handle some I/O setup; the rest is handled in parent/child after
     * fork().
     */
    if (spec->in_evh) {
	/* build a pipe to the child */
	if (pipe(inpfd)) {
	    verror("pipe(in): %s\n",strerror(errno));
	    goto errout;
	}
    }
    else if (spec->infile && strcmp(spec->infile,"-") != 0) {
	infd = open(spec->infile,O_RDONLY);
	if (infd < 0) {
	    verror("open(%s): %s\n",spec->infile,strerror(errno));
	    goto errout;
	}
    }
    if (spec->out_evh) {
	if (pipe(outpfd)) {
	    verror("pipe(out): %s\n",strerror(errno));
	    goto errout;
	}
    }
    else if (spec->outfile && strcmp(spec->outfile,"-") != 0) {
	outfd = open(spec->outfile,O_WRONLY | O_CREAT | O_APPEND,
		     S_IRUSR | S_IWUSR | S_IRGRP);
	if (outfd < 0) {
	    verror("open(%s): %s\n",spec->outfile,strerror(errno));
	    goto errout;
	}
    }
    if (spec->err_evh) {
	if (pipe(errpfd)) {
	    verror("pipe(err): %s\n",strerror(errno));
	    goto errout;
	};
    }
    else if (spec->errfile && strcmp(spec->errfile,"-") != 0) {
	errfd = open(spec->errfile,O_WRONLY | O_CREAT | O_APPEND,
		     S_IRUSR | S_IWUSR | S_IRGRP);
	if (errfd < 0) {
	    verror("open(%s): %s\n",spec->errfile,strerror(errno));
	    goto errout;
	}
    }

    /*
     * Launch it!
     */

    if ((pid = fork()) > 0) {
	lstate->pid = pid;
	lstate->current_tid = 0;

	/*
	 * Handle i/o stuff: close child-only FDs.
	 */
	if (inpfd[0] > -1) {
	    close(inpfd[0]);
	    inpfd[0] = -1;
	    target->infd = inpfd[1];
	}
	else if (infd > -1) {
	    close(infd);
	    infd = -1;
	}
	if (outpfd[1] > -1) {
	    close(outpfd[1]);
	    outpfd[1] = -1;
	    target->outfd = outpfd[0];
	}
	else if (outfd > -1) {
	    close(outfd);
	    outfd = -1;
	}
	if (errpfd[1] > -1) {
	    close(errpfd[1]);
	    errpfd[1] = -1;
	    target->errfd = errpfd[0];
	}
	else if (errfd > -1) {
	    close(errfd);
	    errfd = -1;
	}
	
	/* Parent; wait for ptrace to signal us. */
	vdebug(3,LA_TARGET,LF_LUP,"waiting for ptrace traceme pid %d to exec\n",pid);
     again:
	vdebug(9,LA_TARGET,LF_LUP,"waitpid target %d\n",pid);
	if (waitpid(pid,&pstatus,0) < 0) {
	    if (errno == ECHILD || errno == EINVAL) {
		verror("waitpid(%d): %s\n",pid,strerror(errno));
		goto errout;
	    }
	    else {
		if (ptrace(PTRACE_SYSCALL,pid,NULL,NULL) < 0) {
		    verror("ptrace syscall pid %d failed: %s\n",pid,strerror(errno));
		    goto errout;
		}
		goto again;
	    }
	}
	if (WIFSTOPPED(pstatus)) {
	    /* Ok, this was a ptrace event; if it was a syscall, figure out
	     * which one.
	     */
	    if (WSTOPSIG(pstatus) == SIGTRAP) {
		vdebug(3,LA_TARGET,LF_LUP,"ptrace traceme: pid %d has exec'd\n",pid);
		if (ptrace(PTRACE_GETREGS,pid,0,&uregs) < 0) {
		    vwarn("could not read EAX to deciper exec syscall!\n");
		}
		else {
#if __WORDSIZE == 64
		    orig_eax = uregs.orig_rax;
#else
		    orig_eax = uregs.orig_eax;
#endif
		    vdebug(5,LA_TARGET,LF_LUP,"exec syscall: %lu\n",orig_eax);
		}
	    }
	    else {
		vdebug(5,LA_TARGET,LF_LUP,"exec hunt sig (no trap)\n");
		if (ptrace(PTRACE_SYSCALL,pid,NULL,NULL) < 0) {
		    verror("ptrace syscall pid %d failed: %s\n",pid,strerror(errno));
		    goto errout;
		}
		goto again;
	    }
	}
	else {
	    if (ptrace(PTRACE_SYSCALL,pid,NULL,NULL) < 0) {
		verror("ptrace syscall pid %d failed: %s\n",pid,strerror(errno));
		goto errout;
	    }
	    goto again;
	}
    }
    else if (!pid) {
	if (inpfd[0] > 0) {
	    /* close the write end of the pipe; dup2() the read end to STDIN */
	    close(inpfd[1]);
	    dup2(inpfd[0],STDIN_FILENO);
	}
	else if (infd > 0) {
	    dup2(infd,STDIN_FILENO);
	}
	else if (!spec->infile || strcmp("-",spec->infile) != 0) {
	    close(STDIN_FILENO);
	}
	else {
	    /* Take stdin from caller! */
	}

	if (outpfd[1] > 0) {
	    /* close the read end of the pipe; dup2() the write end to STDOUT */
	    close(outpfd[0]);
	    dup2(inpfd[1],STDOUT_FILENO);
	}
	else if (outfd > 0) {
	    dup2(outfd,STDOUT_FILENO);
	}
	else if (!spec->outfile || strcmp("-",spec->outfile) != 0) {
	    newfd = open("/dev/null",O_WRONLY);
	    dup2(newfd,STDOUT_FILENO);
	}
	else {
	    /* Take stdout from caller! */
	}

	if (errpfd[1] > 0) {
	    /* close the read end of the pipe; dup2() the write end to STDERR */
	    close(errpfd[0]);
	    dup2(inpfd[1],STDERR_FILENO);
	}
	else if (errfd > 0) {
	    dup2(errfd,STDERR_FILENO);
	}
	else if (!spec->errfile || strcmp("-",spec->errfile) != 0) {
	    newfd = open("/dev/null",O_WRONLY);
	    dup2(newfd,STDERR_FILENO);
	}
	else {
	    /* Take stderr from caller! */
	}

	/* Don't chdir like normal for daemons. */

	ptrace(PTRACE_TRACEME,0,NULL,NULL);
	kill(getpid(),SIGINT);

	execve(filename,argv,envp);
	exit(-1);
    }
    else {
	verror("fork: %s\n",strerror(errno));
	goto errout;
    }

    target_set_status(target,TSTATUS_PAUSED);

    /*
     * Ok, now that we have our child process, more setup!
     * 
     * We let the process spin through its setup; if it's static,
     * simply look for prctl or set_thread_area.  If it's dynamic, look
     * for a sequence like 
     * mmap|mmap2|mprotect* ; arch_prctl|set_thread_area ; mprotect* ; munmap
     */
 again2:
    /* Look for syscalls! */
    if (ptrace(PTRACE_SYSCALL,pid,NULL,NULL) < 0) {
	verror("ptrace syscall pid %d failed: %s\n",pid,strerror(errno));
	goto errout;
    }
    vdebug(9,LA_TARGET,LF_LUP,"waitpid target %d (syscall inference)\n",pid);
    if (waitpid(pid,&pstatus,0) < 0) {
	if (errno == ECHILD || errno == EINVAL) {
	    verror("waitpid(%d): %s\n",pid,strerror(errno));
	    goto errout;
	}
	else {
	    goto again2;
	}
    }
    if (WIFSTOPPED(pstatus)) {
	/* Ok, this was a ptrace event; if it was a syscall, figure out
	 * which one.
	 */
	if (WSTOPSIG(pstatus) == SIGTRAP) {
	    if (ptrace(PTRACE_GETREGS,pid,0,&uregs) < 0) {
		vwarn("could not read EAX to deciper syscall; skipping inference!\n");
		errno = 0;
		goto out;
	    }
#if __WORDSIZE == 64
	    orig_eax = uregs.orig_rax;
#else
	    orig_eax = uregs.orig_eax;
#endif

	    vdebug(5,LA_TARGET,LF_LUP,"syscall: %ld (%ld)\n",orig_eax,syscall);

	    if (binfile->is_dynamic) {
		/* syscall state machine for the dynamic case: */
		if ((syscall == 0 
		     || ((syscall == LUP_SC_MPROTECT
			  || syscall == LUP_SC_MMAP
			  || syscall == LUP_SC_MMAP2)))
		    && (orig_eax == LUP_SC_MPROTECT
			|| orig_eax == LUP_SC_MMAP
			|| orig_eax == LUP_SC_MMAP2)) {
		    syscall = orig_eax;
		}
		else if ((syscall == LUP_SC_MPROTECT
			  || syscall == LUP_SC_MMAP
			  || syscall == LUP_SC_MMAP2)
			 && (orig_eax == LUP_SC_PRCTL
			     || orig_eax == LUP_SC_ARCH_PRCTL
			     || orig_eax == LUP_SC_SET_THREAD_AREA)) {
		    syscall = orig_eax;
		}
		else if ((syscall == LUP_SC_PRCTL
			  || syscall == LUP_SC_ARCH_PRCTL
			  || syscall == LUP_SC_SET_THREAD_AREA)
			 && orig_eax == LUP_SC_MPROTECT) {
		    syscall = orig_eax;
		}
		else if (syscall == LUP_SC_MPROTECT
			 && orig_eax == LUP_SC_MUNMAP) {
		    syscall = orig_eax;
		}
		else if (syscall == LUP_SC_MUNMAP
			 && orig_eax == LUP_SC_MUNMAP) {
		    syscall = orig_eax;
		    vdebug(5,LA_TARGET,LF_LUP,"found end of munmap to end dynamic load sequence!\n");
		    goto out;
		}
	    }
	    else {
		if (orig_eax == LUP_SC_PRCTL) {
		    vdebug(5,LA_TARGET,LF_LUP,"found prctl to end static load sequence!\n");
		    goto out;
		}
		else if (orig_eax == LUP_SC_ARCH_PRCTL) {
		    vdebug(5,LA_TARGET,LF_LUP,"found arch_prctl to end static load sequence!\n");
		    goto out;
		}
		else if (orig_eax == LUP_SC_SET_THREAD_AREA) {
		    vdebug(5,LA_TARGET,LF_LUP,"found set_thread_area to end static load sequence!\n");
		    goto out;
		}
	    }
	}
	goto again2;
    }
    else if (WIFCONTINUED(pstatus)) {
	goto again2;
    }
    else if (WIFSIGNALED(pstatus)) {
	verror("pid %d signaled (%d) in initial tracing!\n",
	       pid,WTERMSIG(pstatus));
	goto errout;
    }
    else if (WIFEXITED(pstatus)) {
	/* yikes, it was sigkill'd out from under us! */
	/* XXX: is error good enough?  The pid is gone; we should
	 * probably dump this target.
	 */
	verror("pid %d bailed in initial tracing!\n",pid);
	goto errout;
    }
    else {
	vwarn("pid %d: unhandled waitpid condition while waiting for load; trying again!\n",pid);
	goto again2;
    }

 out:
    /*
     * We can't detach; that will resume the child.  We have to leave it
     * paused until the user starts interacting with it.  See
     * target->initdidattach .
     */
    /*
    if (ptrace(PTRACE_DETACH,pid,NULL,NULL) < 0) {
	verror("ptrace temporary detach failed (will try to kill child): %s\n",strerror(errno));
	kill(9,pid);
	goto errout;
    }
    */

    /* Set the initial PTRACE opts. */
    lstate->ptrace_opts_new = lstate->ptrace_opts = INITIAL_PTRACE_OPTS;
    errno = 0;
    if (ptrace(PTRACE_SETOPTIONS,pid,NULL,lstate->ptrace_opts) < 0) {
	vwarn("ptrace setoptions failed: %s\n",strerror(errno));
    }

    /* Clear the status bits right now. */
    errno = 0;
    if (ptrace(PTRACE_POKEUSER,pid,offsetof(struct user,u_debugreg[6]),0)) {
	verror("could not clear status debug reg, continuing anyway: %s!\n",
	       strerror(errno));
	errno = 0;
    }
    else {
	vdebug(5,LA_TARGET,LF_LUP,
	       "cleared status debug reg 6 for pid %d\n",pid);
    }

    if (evloop) {
	target->evloop = evloop;
	linux_userproc_attach_evloop(target,evloop);
    }

    return target;

 errout:
    /*
     * Cleanup I/O stuff first!  Do it before target_free!
     */
    if (inpfd[0] > -1) 
	close(inpfd[0]);
    if (inpfd[1] > -1) {
	if (evloop)
	    evloop_unset_fd(evloop,target->infd,EVLOOP_FDTYPE_A);
	close(inpfd[1]);
	target->infd = -1;
    }
    if (infd > -1) 
	close(infd);

    if (outpfd[1] > -1) 
	close(outpfd[1]);
    if (outpfd[0] > -1) {
	if (evloop)
	    evloop_unset_fd(evloop,target->outfd,EVLOOP_FDTYPE_A);
	close(outpfd[0]);
	target->outfd = -1;
    }
    if (outfd > -1) 
	close(outfd);

    if (errpfd[1] > -1) 
	close(errpfd[1]);
    if (errpfd[0] > -1) {
	if (evloop)
	    evloop_unset_fd(evloop,target->errfd,EVLOOP_FDTYPE_A);
	close(errpfd[0]);
	target->errfd = -1;
    }
    if (errfd > -1) 
	close(errfd);

    if (target)
	target_free(target);
    else if (binfile)
	RPUT(binfile,binfile,target,trefcnt);

    return NULL;
}

static int __tid_exists(int pid,tid_t tid) {
    char buf[256];
    struct stat sbuf;

    snprintf(buf,256,"/proc/%d/task/%d",pid,tid);
    if (stat(buf,&sbuf)) {
	errno = EINVAL;
	return 0;
    }

    return 1;
}

int linux_userproc_attach_thread(struct target *target,tid_t parent,tid_t child) {
    struct linux_userproc_state *lstate;
    struct target_thread *tthread;
    int pid;
    struct linux_userproc_thread_state *tstate;
    gpointer value;
    int racy_status;
    int pstatus;
    int rc;

    lstate = (struct linux_userproc_state *)target->state;

    if (!lstate) {
	errno = EFAULT;
	return 1;
    }
    if (!target->opened) {
	verror("cannot attach to thread until process is attached to!\n");
	errno = EINVAL;
	return 1;
    }

    pid = lstate->pid;

    if (!__tid_exists(pid,child)) {
	verror("thread %d in pid %d does not exist!\n",child,pid);
	return 1;
    }

    vdebug(5,LA_TARGET,LF_LUP,
	   "pid %d parent thread %"PRIiTID" child thread %"PRIiTID"\n",
	   pid,parent,child);

    /*
     * Create the thread.
     */
    tstate = (struct linux_userproc_thread_state *)calloc(1,sizeof(*tstate));

    tstate->last_status = 0;
    tstate->last_signo = 0;
    /*
     * Don't wait for the child to get the PTRACE-sent SIGSTOP; just
     * note that a fake control signal is going to hit the thread; then
     * the monitor/poll stuff will wait for it and process it
     * correctly.  We don't want to deliver that signal.
     *
     * But, if the thread signaled its SIGSTOP before we were notified
     * about the clone() via SIGCHLD, that was recorded in
     * lstate->new_racy_threads; in this case, we do not want to wait to
     * recv the SIGSTOP!
     */
    if (g_hash_table_lookup_extended(lstate->new_racy_threads,
				     (gpointer)(uintptr_t)child,NULL,&value)) {
	racy_status = (int)(uintptr_t)value;

	g_hash_table_remove(lstate->new_racy_threads,(gpointer)(uintptr_t)child);

	if (WIFSTOPPED(racy_status) && WSTOPSIG(racy_status) == SIGSTOP) {
	    vdebug(5,LA_TARGET,LF_LUP,"new racy thread %d already hit sigstop\n",
		   child);
	}
	else {
	    vwarn("new racy thread %d had status %d (but not SIGSTOP);"
		  " assuming it is stopped though!\n",child,racy_status);
	}

	tstate->ctl_sig_sent = 0;
	tstate->ctl_sig_recv = 0;

	/*
	 * Don't reinject this signal!
	 */
	tstate->last_signo = -1;

	/* Set the initial PTRACE opts. */
	lstate->ptrace_opts_new = lstate->ptrace_opts = INITIAL_PTRACE_OPTS;
	errno = 0;
	if (ptrace(PTRACE_SETOPTIONS,pid,NULL,INITIAL_PTRACE_OPTS) < 0) {
	    vwarn("ptrace setoptions failed: %s\n",strerror(errno));
	}

	/* Restart just this thread. */
	/*
	if (ptrace(lstate->ptrace_type,child,NULL,NULL) < 0) {
	    verror("ptrace restart of tid %"PRIiTID" failed: %s\n",
		   child,strerror(errno));
	    free(tstate);
	    return 1;
	}
	*/
	//kill(child,SIGCONT);

	vdebug(5,LA_TARGET,LF_LUP,"restarted new racy thread %d\n",child);
    }
    else {
	tstate->ctl_sig_sent = 1;
	tstate->ctl_sig_recv = 0;

	/*
	 * Try to handle it right now, WNOHANG.
	 */
	pstatus = 0;
	rc = waitpid(child,&pstatus,WNOHANG | __WALL);
	if (rc == 0) {
	    vdebug(5,LA_TARGET,LF_LUP,
		   "waitpid returned nothing for new non-racy tid %d!\n",child);
	}
	else if (rc < 0) {
	    verror("waitpid(%d): %s\n",child,strerror(errno));
	}
	else {
	    vdebug(5,LA_TARGET,LF_LUP,
		   "waited for new non-racy tid %d successfully\n",child);

	    /*
	     * Ok, the SIGSTOP is available for us; grab it now and
	     * set the thread up to get restarted.
	     */
	    tstate->ctl_sig_sent = 0;
	    tstate->ctl_sig_recv = 0;
	}
    }
    tstate->ctl_sig_pause_all = 0;

    tthread = target_create_thread(target,child,tstate);

    target_add_state_change(target,child,TARGET_STATE_CHANGE_THREAD_CREATED,0,0,
			    0,0,NULL);

    target_thread_set_status(tthread,THREAD_STATUS_PAUSED);

    if (target->evloop)
	linux_userproc_evloop_add_tid(target,child);

    return 0;
}


static int __handle_internal_detaching(struct target *target,
				       struct target_thread *tthread,
				       int pstatus) {
    REG dreg = -1;
    struct probepoint *dpp;
    REGVAL ipval;
#if __WORDSIZE == 64
    unsigned long cdr;
#else
    int cdr;
#endif
    struct linux_userproc_state *lstate = \
	(struct linux_userproc_state *)target->state;
    int pid = lstate->pid;
    struct linux_userproc_thread_state *tstate = \
	(struct linux_userproc_thread_state *)tthread->state;
    tid_t tid = tthread->tid;
    tid_t newtid;
    long newstatus;

    if (!WIFSTOPPED(pstatus)) {
	vdebug(5,LA_TARGET,LF_LUP,
	       "pid %d thread %"PRIiTID" not stopped; ignoring\n",pid,tid);
	return 0;
    }

    /*
     * Don't handle a just-cloning thread if we are detaching from
     * the parent doing the clone().
     */
    if (pstatus >> 8 == (SIGTRAP | PTRACE_EVENT_CLONE << 8)) {
	ptrace(PTRACE_GETEVENTMSG,tid,NULL,&newstatus);
	newtid = (tid_t)newstatus;
	vdebug(5,LA_TARGET,LF_LUP,
	       "target %d thread %d cloned new thread %d; NOT attaching!\n",
	       pid,tid,newtid);
	return 0;
    }

    if (!linux_userproc_load_thread(target,tid,0)) {
	verror("could not load thread %"PRIiTID"!\n",tid);
	return -1;
    }

    tstate->last_status = tstate->last_signo = WSTOPSIG(pstatus);
    if (tstate->last_status == (SIGTRAP | 0x80)) {
	vdebug(8,LA_TARGET,LF_LUP,
	       "thread %"PRIiTID" stopped with syscall trap signo %d, ignoring\n",
	       tid,tstate->last_status);
	tstate->last_signo = -1;
    }
    else if (pstatus >> 8 == (SIGTRAP | PTRACE_EVENT_EXIT << 8)) {
	vdebug(5,LA_TARGET,LF_LUP,"target %d exiting (%d), ignoring on detach\n",
	       pid,tstate->last_status);
	tstate->last_signo = -1;
    }
    else if (tstate->last_status == SIGTRAP) {
	/* Don't deliver debug traps! */
	vdebug(5,LA_TARGET,LF_LUP,
	       "thread %"PRIiTID" stopped with trap %d, minimal handling\n",
	       tid,tstate->last_status);
	tstate->last_signo = -1;

	/*
	 * This is where we handle breakpoint or single step
	 * events.
	 */

	/* Check the hw debug status reg first */
	errno = 0;
	cdr = ptrace(PTRACE_PEEKUSER,tid,
		     offsetof(struct user,u_debugreg[6]),NULL);
	if (errno) {
	    vwarn("could not read current val of status debug reg;"
		  " don't know which handler to call; fatal!\n");
	    return -1;
	}

	if (cdr & 0x4000) {
	    vdebug(5,LA_TARGET,LF_LUP,
		   "ignoring single step event pid %d thread %"PRIiTID"\n",
		   pid,tid);
	}
	else {
	    /* Only check the 4 low-order bits */
	    if (cdr & 15) {
		if (cdr & 0x1)
		    dreg = 0;
		else if (cdr & 0x2)
		    dreg = 1;
		else if (cdr & 0x4)
		    dreg = 2;
		else if (cdr & 0x8)
		    dreg = 3;

		/* If we are relying on the status reg to tell us,
		 * then also read the actual hw debug reg to get the
		 * address we broke on.
		 */
		errno = 0;
		ipval = ptrace(PTRACE_PEEKUSER,tid,
			       offsetof(struct user,u_debugreg[dreg]),NULL );
		if (errno) {
		    verror("could not read current val of debug reg %d after up status!\n",dreg);
		    return -1;
		}

		vdebug(6,LA_TARGET,LF_LUP,
		       "found hw break (status) in dreg %d on 0x%"PRIxADDR"\n",
		       dreg,ipval);
	    }
	    else {
		ipval = linux_userproc_read_reg(target,tid,target->ipregno);
		if (errno) {
		    verror("could not read EIP while finding probepoint: %s\n",
			   strerror(errno));
		    return -1;
		}

		if (tstate->dr[0] == (ptrace_reg_t)ipval)
		    dreg = 0;
		else if (tstate->dr[1] == (ptrace_reg_t)ipval)
		    dreg = 1;
		else if (tstate->dr[2] == (ptrace_reg_t)ipval)
		    dreg = 2;
		else if (tstate->dr[3] == (ptrace_reg_t)ipval)
		    dreg = 3;

		if (dreg > -1) 
		    vdebug(4,LA_TARGET,LF_LUP,
			   "found hw break (eip) in dreg %d on 0x%"PRIxADDR"\n",
			   dreg,ipval);
	    }

	    if (dreg > -1) {
		/* Found HW breakpoint! */
		dpp = (struct probepoint *) \
		    g_hash_table_lookup(tthread->hard_probepoints,
					(gpointer)ipval);

		if (!dpp) {
		    verror("found hw breakpoint 0x%"PRIxADDR
			   " in debug reg %d, BUT no probepoint!\n",
			   ipval,dreg);
		    return -1;
		}

		vdebug(5,LA_TARGET,LF_LUP,
		       "hw bp %d pid %d thread %"PRIiTID", not resetting EIP\n",
		       dreg,pid,tid);
	    }
	    /* catch glib bug in hash table init; check for empty hashtable */
	    else if ((dpp = (struct probepoint *) \
		      g_hash_table_lookup(target->soft_probepoints,
					  (gpointer)(ipval - target->breakpoint_instrs_len)))) {
		vdebug(5,LA_TARGET,LF_LUP,
		       "sw bp pid %d thread %"PRIiTID", resetting EIP\n",
		       pid,tid);

		ipval -= target->breakpoint_instrs_len;
		errno = 0;
		target_write_reg(target,tid,target->ipregno,ipval);
		if (errno) {
		    verror("could not reset EIP; thread will crash\n");
		    return -1;
		}
		target_flush_thread(target,tid);
	    }
	    else {
		vwarn("could not find bp and not in sstep; letting thread"
		      " pid %d thread %"PRIiTID" detach without handling"
		      " (at 0x%"PRIxADDR"!\n",
		      pid,tid,ipval);
		return 0;
	    }
	}
    }
    else if (WIFCONTINUED(pstatus)) {
	vdebug(5,LA_TARGET,LF_LUP,
	       "waitpid CONT event pid %d thread %"PRIiTID" (status 0x%x); ignoring\n",
	      pid,tid,pstatus);
	tstate->last_signo = -1;
	tstate->last_status = -1;
    }
    else if (WIFEXITED(pstatus)) {
	/* yikes, it was sigkill'd out from under us! */
	/* XXX: is error good enough?  The pid is gone; we should
	 * probably dump this target.
	 */
	vdebug(5,LA_TARGET,LF_LUP,
	       "waitpid EXITED event pid %d thread %"PRIiTID" (status 0x%x); ignoring\n",
	       pid,tid,pstatus);
	tstate->last_signo = -1;
	tstate->last_status = -1;

	return 1;
    }
    else if (WIFSIGNALED(pstatus)) {
	vdebug(5,LA_TARGET,LF_LUP,
	       "waitpid SIGNALED event pid %d thread %"PRIiTID" (status 0x%x); ignoring\n",
	       pid,tid,pstatus);
	tstate->last_signo = -1;
	tstate->last_status = -1;

	return 1;
    }
    else {
	vwarn("unknown waitpid event pid %d thread %"PRIiTID" (status 0x%x)\n",
	      pid,tid,pstatus);
	return -1;
    }

    return 1;
}

int __poll_and_handle_detaching(struct target *target,
				struct target_thread *tthread) {
    int status = 0;
    int retval;
    struct linux_userproc_state *lstate;
    int pid;
    tid_t tid = tthread->tid;

    lstate = (struct linux_userproc_state *)target->state;
    pid = lstate->pid;

    tthread = target_lookup_thread(target,tid);

    retval = waitpid(tid,&status,WNOHANG | __WALL);
    if (retval == 0) {
	vdebug(5,LA_TARGET,LF_LUP,
	       "pid %d thread %"PRIiTID" running; not handling\n",pid,tid);
	return 0;
    }
    else if (retval < 0) {
	verror("waitpid pid %d thread %"PRIiTID": %s\n",pid,tid,strerror(errno));
	return retval;
    }

    /*
     * Handle in a basic way so as to remove our presence from the
     * thread -- which means if the thread just hit a breakpoint, remove
     * the breakpoint and reset EIP, and flush.
     *
     * If we're at a single step, nothing to worry about!
     */

    vdebug(5,LA_TARGET,LF_LUP,"handling pid %d thread %"PRIiTID"\n",pid,tid);
    return __handle_internal_detaching(target,tthread,status);
}

int linux_userproc_detach_thread(struct target *target,tid_t tid,
				 int detaching_all) {
    struct linux_userproc_state *lstate;
    struct target_thread *tthread;
    char buf[256];
    int pid;
    struct stat sbuf;

    lstate = (struct linux_userproc_state *)target->state;
    if (!lstate) {
	errno = EFAULT;
	return 1;
    }
    pid = lstate->pid;

    vdebug(5,LA_TARGET,LF_LUP,"pid %d thread %"PRIiTID"\n",pid,tid);

    if (!target->opened) {
	verror("cannot detach from thread until process is attached to!\n");
	errno = EINVAL;
	return 1;
    }

    if (!(tthread = target_lookup_thread(target,tid))) {
	verror("thread %"PRIiTID" does not exist!\n",tid);
	errno = EINVAL;
	return 1;
    }

    if (target->evloop)
	linux_userproc_evloop_del_tid(target,tid);

    /*
     * If it exists, actually detach.  Else, just clean up our state.
     */
    snprintf(buf,256,"/proc/%d/task/%d",pid,tid);
    if (stat(buf,&sbuf) == 0) {

	target_detach_thread(target,tthread);

	/*
	 * If the thread is stopped with status, check it and handle it
	 * in a basic way -- like if it's stopped at a breakpoint, reset
	 * EIP and replace orig code -- don't handle it more.
	 */
	if (__poll_and_handle_detaching(target,tthread) == 0) {
	    /* 
	     * Sleep the child first if it's still running; otherwise
	     * we'll end up sending it a trace trap, which will kill it.
	     */
	    kill(tid,SIGSTOP);
	}

	ptrace(PTRACE_DETACH,tid,NULL,NULL);

	/*
	 * Don't CONT it if we're detaching; we'll signal the pid
	 * globally if necessary.
	 */
	if (!detaching_all)
	    kill(tid,SIGCONT);

	errno = 0;
    }

    target_delete_thread(target,tthread,0);

    return 0;
}

/**
 ** These are all functions supporting the target API.
 **/
static int linux_userproc_snprintf(struct target *target,
				   char *buf,int bufsiz) {
    struct linux_userproc_spec *lspec = \
	(struct linux_userproc_spec *)target->spec->backend_spec;

    if (lspec->program) 
	return snprintf(buf,bufsiz,"ptrace(%d,%s)",lspec->pid,lspec->program);
    else 
	return snprintf(buf,bufsiz,"ptrace(%d)",lspec->pid);
}

static tid_t linux_userproc_gettid(struct target *target) {
    struct target_thread *tthread;

    /*
     * Note: this is really all the same as target->state->current_tid
     * -- but we also make sure we load the current thread.
     */

    if (target->current_thread && target->current_thread->valid)
	return target->current_thread->tid;

    tthread = linux_userproc_load_current_thread(target,0);
    if (!tthread) {
	verror("could not load current thread to get TID!\n");
	return 0;
    }

    return tthread->tid;
}

static void linux_userproc_free_thread_state(struct target *target,void *state) {
    free(state);
}

static int __linux_userproc_load_thread_status(struct target_thread *tthread,
					       tid_t tid,int force) {
    struct linux_userproc_state *lstate;
    int pid;
    char buf[64];
    FILE *statf;
    char pstate;
    int rc;
    tid_t rtid = 0;

    lstate = (struct linux_userproc_state *)tthread->target->state;
    pid = lstate->pid;

    if (tthread->valid && !force) {
	vdebug(9,LA_TARGET,LF_LUP,
	       "pid %d thread %"PRIiTID" already valid\n",pid,tid);
	return 0;
    }

    vdebug(12,LA_TARGET,LF_LUP,"pid %d thread %"PRIiTID" (%"PRIiTID")\n",
	   pid,tid,tthread->tid);

    /* Load its status from /proc */
    snprintf(buf,64,"/proc/%d/task/%d/stat",pid,tthread->tid);
 again:
    statf = fopen(buf,"r");
    if (!statf) {
	vwarnopt(9,LA_TARGET,LF_LUP,
		 "fopen(%s): %s; UNKNOWN!\n",buf,strerror(errno));
	target_thread_set_status(tthread,THREAD_STATUS_UNKNOWN);
	return -1;
    }

    if ((rc = fscanf(statf,"%d (%s %c",&rtid,buf,&pstate))) {
	if (pstate == 'R' || pstate == 'r')
	    target_thread_set_status(tthread,THREAD_STATUS_RUNNING);
	else if (pstate == 'W' || pstate == 'w')
	    target_thread_set_status(tthread,THREAD_STATUS_PAGING);
	else if (pstate == 'S' || pstate == 's')
	    target_thread_set_status(tthread,THREAD_STATUS_STOPPED);
	else if (pstate == 'D' || pstate == 'd')
	    target_thread_set_status(tthread,THREAD_STATUS_BLOCKEDIO);
	else if (pstate == 'Z' || pstate == 'z')
	    target_thread_set_status(tthread,THREAD_STATUS_ZOMBIE);
	else if (pstate == 'T' || pstate == 't')
	    target_thread_set_status(tthread,THREAD_STATUS_PAUSED);
	else if (pstate == 'X' || pstate == 'x')
	    target_thread_set_status(tthread,THREAD_STATUS_DEAD);
	else {
	    verror("fscanf returned %d; read tid %d (%s) %c; UNKNOWN!\n",
		  rc,rtid,buf,pstate);
	    target_thread_set_status(tthread,THREAD_STATUS_UNKNOWN);
	    goto errout;
	}
    }
    else if (rc < 0 && errno == EINTR) {
	fclose(statf);
	goto again;
    }
    fclose(statf);

    vdebug(3,LA_TARGET,LF_LUP,"pid %d tid %"PRIiTID" status %d\n",
	   pid,tthread->tid,tthread->status);

    return 0;

 errout:
    return -1;
}

static struct target_thread *__linux_userproc_load_thread(struct target *target,
							  tid_t tid,int force,
							  int have_status) {
    struct target_thread *tthread;
    struct linux_userproc_thread_state *tstate;
    struct linux_userproc_state *lstate;
    int pid;

    lstate = (struct linux_userproc_state *)target->state;
    pid = lstate->pid;

    if (!(tthread = target_lookup_thread(target,tid))) {
	verror("thread %"PRIiTID" does not exist; forgot to attach?\n",tid);
	errno = EINVAL;
	return NULL;
    }
    tstate = (struct linux_userproc_thread_state *)tthread->state;

    if (tthread->valid && !force) {
	vdebug(9,LA_TARGET,LF_LUP,"pid %d thread %"PRIiTID" already valid\n",
	       pid,tid);
	return tthread;
    }

    vdebug(12,LA_TARGET,LF_LUP,"pid %d thread %"PRIiTID" (%"PRIiTID")\n",
	   pid,tid,tthread->tid);

    if (!have_status) 
	__linux_userproc_load_thread_status(tthread,tid,force);

    vdebug(3,LA_TARGET,LF_LUP,"pid %d tid %"PRIiTID" status %d\n",
	   pid,tthread->tid,tthread->status);

    if (tthread->status == THREAD_STATUS_PAUSED) {
	errno = 0;
	if (ptrace(PTRACE_GETREGS,tthread->tid,NULL,&(tstate->regs)) == -1) {
	    verror("ptrace(GETREGS): %s\n",strerror(errno));
	    tthread->valid = 0;
	    tthread->dirty = 0;
	    return NULL;
	}
	tthread->valid = 1;
    }
    else {
	memset(&tstate->regs,0,sizeof(tstate->regs));
	tthread->valid = 0;
    }

    tthread->dirty = 0;

    return tthread;
}

static struct target_thread *linux_userproc_load_thread(struct target *target,
							tid_t tid,int force) {
    return __linux_userproc_load_thread(target,tid,force,0);
}

static struct target_thread *linux_userproc_load_current_thread(struct target *target,
								int force) {
    struct linux_userproc_state *lstate = \
	(struct linux_userproc_state *)target->state;

    return linux_userproc_load_thread(target,lstate->current_tid,force);
}

static int linux_userproc_load_all_threads(struct target *target,int force) {
    int retval = 0;
    GHashTableIter iter;
    struct target_thread *tthread;
    gpointer key;

    g_hash_table_iter_init(&iter,target->threads);
    while (g_hash_table_iter_next(&iter,&key,(gpointer)&tthread)) {
	if (key == (gpointer)TID_GLOBAL)
	    continue;

	if (!linux_userproc_load_thread(target,tthread->tid,force)) {
	    verror("could not load thread %"PRIiTID"\n",tthread->tid);
	    ++retval;
	}
    }

    return retval;
}

static int linux_userproc_flush_thread(struct target *target,tid_t tid) {
    struct target_thread *tthread;
    struct linux_userproc_thread_state *tstate;

    vdebug(5,LA_TARGET,LF_LUP | LF_THREAD,"thread %"PRIiTID"\n",tid);

    if ((tthread = target_lookup_thread(target,tid))) {
	tstate = (struct linux_userproc_thread_state *)tthread->state;
    }
    else {
	verror("cannot flush unknown thread %"PRIiTID"; forgot to load?\n",tid);
	errno = EINVAL;
	return -1;
    }

    if (!tthread->valid || !tthread->dirty)
	return 0;

    errno = 0;
    if (ptrace(PTRACE_SETREGS,tthread->tid,NULL,&(tstate->regs)) == -1) {
	verror("ptrace(SETREGS): %s\n",strerror(errno));
	return -1;
    }
    tthread->dirty = 0;

    return 0;
}

static int linux_userproc_flush_current_thread(struct target *target) {
    if (!target->current_thread && linux_userproc_load_current_thread(target,0))
	return -1;
	
    return linux_userproc_flush_thread(target,target->current_thread->tid);
}

static int linux_userproc_flush_all_threads(struct target *target) {
    int rc, retval = 0;
    GHashTableIter iter;
    struct target_thread *tthread;
    gpointer key;

    g_hash_table_iter_init(&iter,target->threads);
    while (g_hash_table_iter_next(&iter,&key,(gpointer)&tthread)) {
	if (key == (gpointer)TID_GLOBAL)
	    continue;

	rc = linux_userproc_flush_thread(target,tthread->tid);
	if (rc) {
	    verror("could not flush thread %"PRIiTID"\n",tthread->tid);
	    ++retval;
	}
    }

    return retval;
}

static int linux_userproc_thread_snprintf(struct target_thread *tthread,
					  char *buf,int bufsiz,
					  int detail,char *sep,char *kvsep) {
    struct linux_userproc_thread_state *tstate;
    struct user_regs_struct *r;
    int rc = 0;

    if (detail < 0)
	return 0;

    tstate = (struct linux_userproc_thread_state *)tthread->state;
    r = &tstate->regs;

#if __WORDSIZE == 64
#define RF "lx"
#define DRF "lx"
#else
#define RF "lx"
#define DRF "x"
#endif

    if (detail >= 1)
	rc += snprintf((rc >= bufsiz) ? NULL : buf + rc,
		       (rc >= bufsiz) ? 0 :bufsiz - rc,
		       "%s" "ip%s%"RF "%s" "bp%s%"RF "%s" "sp%s%"RF "%s" 
		       "flags%s%"RF "%s" "ax%s%"RF "%s" "bx%s%"RF "%s"
		       "cx%s%"RF "%s" "dx%s%"RF "%s" "di%s%"RF "%s" 
		       "si%s%"RF "%s" "cs%s%"RF "%s" "ss%s%"RF "%s"
		       "ds%s%"RF "%s" "es%s%"RF "%s"
		       "fs%s%"RF "%s" "gs%s%"RF,
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

    return rc;
}

static int linux_userproc_init(struct target *target) {
    struct linux_userproc_state *lstate = \
	(struct linux_userproc_state *)target->state;
    struct linux_userproc_thread_state *tstate;
    struct target_thread *tthread;

    /*
     * We must single step hardware breakpoints; we can't set the RF
     * flag and thus disable them if we don't technically need a single
     * step (i.e., no post handlers nor actions).  So we have to disable
     * the hw breakpoint, single step it, then reenable it.  See
     * linux_userproc_singlestep() below.
     */
    target->nodisablehwbponss = 0;
    target->threadctl = 1;

    vdebug(5,LA_TARGET,LF_LUP,"pid %d\n",lstate->pid);

    lstate->memfd = -1;
    lstate->ptrace_opts_new = lstate->ptrace_opts = INITIAL_PTRACE_OPTS;
    lstate->ptrace_type = PTRACE_CONT;

    lstate->new_racy_threads = g_hash_table_new(g_direct_hash,g_direct_equal);

    /* Create the default thread. */
    tstate = (struct linux_userproc_thread_state *)calloc(1,sizeof(*tstate));

    tstate->last_status = -1;
    tstate->last_signo = -1;

    tthread = target_create_thread(target,lstate->pid,tstate);
    /* Default thread is always starts paused. */
    target_thread_set_status(tthread,THREAD_STATUS_PAUSED);

    /* Reuse the pid's primary thread as the global thread. */
    target_reuse_thread_as_global(target,tthread);

    /* Set thread->current_thread to our primary thread! */
    target->current_thread = tthread;
    lstate->current_tid = tthread->tid;

    if (target->evloop)
	linux_userproc_evloop_add_tid(target,tthread->tid);

    return 0;
}

static int linux_userproc_postloadinit(struct target *target) {
    return 0;
}

static int linux_userproc_attach_internal(struct target *target) {
    struct linux_userproc_state *lstate;
    char buf[256];
    int pstatus;
    int pid;
    struct dirent *dirent;
    DIR *dirp;
    char *endp;
    tid_t tid;
    int rc = 0;
    struct target_thread *tthread;
    struct linux_userproc_thread_state *tstate;

    lstate = (struct linux_userproc_state *)target->state;
    pid = lstate->pid;

    vdebug(5,LA_TARGET,LF_LUP,"pid %d\n",pid);

    if (!lstate) {
	errno = EFAULT;
	return 1;
    }
    pid = lstate->pid;
    if (target->opened)
	return 0;

    errno = 0;
    if (!lstate->initdidattach) {
	if (ptrace(PTRACE_ATTACH,pid,NULL,NULL) < 0) {
	    verror("ptrace attach pid %d failed: %s\n",pid,strerror(errno));
	    return 1;
	}
    }

    snprintf(buf,256,"/proc/%d/mem",pid);
    if ((lstate->memfd = open(buf,O_LARGEFILE,O_RDWR)) < 0) {
	verror("open %s failed, detaching: %s!\n",buf,strerror(errno));
	ptrace(PTRACE_DETACH,pid,NULL,NULL);
	return 1;
    }

    if (!lstate->initdidattach) {
	/*
	 * Wait for the child to get the PTRACE-sent SIGSTOP, then make sure
	 * we *don't* deliver that signal to it when the library user calls
	 * target_resume!
	 */

	vdebug(3,LA_TARGET,LF_LUP,"waiting for ptrace attach to hit pid %d\n",pid);
    again:
	vdebug(5,LA_TARGET,LF_LUP,"initial waitpid target %d\n",pid);
	if (waitpid(pid,&pstatus,0) < 0) {
	    if (errno == ECHILD || errno == EINVAL)
		return TSTATUS_ERROR;
	    else
		goto again;
	}
	vdebug(3,LA_TARGET,LF_LUP,"ptrace attach has hit pid %d\n",pid);
	target_set_status(target,TSTATUS_PAUSED);
    }

    /* Set the initial PTRACE opts. */
    errno = 0;
    if (ptrace(PTRACE_SETOPTIONS,pid,NULL,lstate->ptrace_opts) < 0) {
	vwarn("ptrace setoptions failed: %s\n",strerror(errno));
    }

    /*
     * Try to attach to any other threads.  For a process we spawned,
     * there should not be any.  But it's harmless to check.
     */
    snprintf(buf,256,"/proc/%d/task",pid);
    if (!(dirp = opendir(buf))) {
	verror("could not opendir %s to attach to threads: %s!\n",
	       buf,strerror(errno));
	return TSTATUS_ERROR;
    }

    errno = 0;
    while ((dirent = readdir(dirp))) {
	if (dirent->d_name[0] == '.')
	    continue;

	tid = (tid_t)strtol(dirent->d_name,&endp,10);
	if (endp == dirent->d_name || errno == ERANGE || errno == EINVAL) {
	    verror("weird error parsing thread id out of '%s': %s; skipping!\n",
		   dirent->d_name,strerror(errno));
	    errno = 0;
	    continue;
	}

	if (tid == pid)
	    continue;

	if (ptrace(PTRACE_ATTACH,tid,NULL,NULL) < 0) {
	    verror("ptrace attach tid %d failed: %s\n",tid,strerror(errno));
	    ++rc;
	    continue;
	}

	vdebug(3,LA_TARGET,LF_LUP,"waiting for ptrace attach to hit tid %d\n",tid);
    again2:
	vdebug(5,LA_TARGET,LF_LUP,"initial waitpid tid %d\n",tid);
	if (waitpid(tid,&pstatus,__WALL) < 0) {
	    if (errno == ECHILD || errno == EINVAL) {
		verror("waitpid tid %d failed: %s\n",tid,strerror(errno));
		++rc;
		continue;
	    }
	    else
		goto again2;
	}
	vdebug(3,LA_TARGET,LF_LUP,"ptrace attach has hit tid %d\n",tid);

	if (ptrace(PTRACE_SETOPTIONS,tid,NULL,lstate->ptrace_opts) < 0) {
	    vwarn("ptrace setoptions failed, continuing: %s\n",strerror(errno));
	    errno = 0;
	}

	/*
	 * Create the thread.
	 */
	tstate = (struct linux_userproc_thread_state *)calloc(1,sizeof(*tstate));

	tstate->last_status = 0;
	tstate->last_signo = 0;

	tstate->ctl_sig_sent = 0;
	tstate->ctl_sig_recv = 0;
	tstate->ctl_sig_pause_all = 0;

	tthread = target_create_thread(target,tid,tstate);
	target_thread_set_status(tthread,THREAD_STATUS_PAUSED);

	if (target->evloop)
	    linux_userproc_evloop_add_tid(target,tid);
    }

    closedir(dirp);

    return rc;
}

static int linux_userproc_detach(struct target *target) {
    struct linux_userproc_state *lstate;
    int rc, retval = 0;
    GHashTableIter iter;
    struct target_thread *tthread;
    struct array_list *threadlist;
    int i;

    lstate = (struct linux_userproc_state *)(target->state);
    vdebug(5,LA_TARGET,LF_LUP,"pid %d\n",lstate->pid);

    if (!lstate) {
	errno = EFAULT;
	return 1;
    }
    if (!target->opened)
	return 0;

    /*
     * Detach from all the threads first.  We push them onto a list
     * first because we can't trust detach_thread not to delete them
     * from the hashtable, which we can't do while we're iterating
     * through it.
     */
    threadlist = array_list_create(g_hash_table_size(target->threads));
    g_hash_table_iter_init(&iter,target->threads);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer)&tthread)) {
	if (tthread == target->global_thread)
	    continue;

	array_list_append(threadlist,tthread);
    }
    for (i = 0; i < array_list_len(threadlist); ++i) {
	tthread = (struct target_thread *)array_list_item(threadlist,i);

	rc = linux_userproc_detach_thread(target,tthread->tid,1);
	if (rc) {
	    verror("could not detach thread %"PRIiTID"\n",tthread->tid);
	    ++retval;
	}
    }
    array_list_free(threadlist);

    /*
     * Now detach from the primary process thread.
     */
    tthread = target->global_thread;
    if (tthread) {
	rc = linux_userproc_detach_thread(target,tthread->tid,1);
	if (rc) {
	    verror("could not detach global thread %"PRIiTID"\n",tthread->tid);
	    ++retval;
	}
	else
	    target->global_thread = NULL;
    }

    /* Also, remove the global thread from target->threads! */
    g_hash_table_remove(target->threads,(gpointer)(uintptr_t)TID_GLOBAL);

    /*
     *
     */
    /*
    errno = 0;
    if (ptrace(PTRACE_DETACH,lstate->pid,NULL,NULL) < 0) {
	verror("ptrace detach %d failed: %s\n",lstate->pid,strerror(errno));
	kill(lstate->pid,SIGCONT);
	//return 1;
    }
    */

    kill(lstate->pid,SIGCONT);

    if (lstate->memfd > 0)
	close(lstate->memfd);

    vdebug(3,LA_TARGET,LF_LUP,"ptrace detach %d done.\n",lstate->pid);

    return 0;
}

static int linux_userproc_fini(struct target *target) {
    struct linux_userproc_state *lstate;

    lstate = (struct linux_userproc_state *)(target->state);

    vdebug(5,LA_TARGET,LF_LUP,"pid %d\n",lstate->pid);

    if (target->opened) 
	linux_userproc_detach(target);

    if (target->spec->outfile) {
	unlink(target->spec->outfile);
	free(target->spec->outfile);
	target->spec->outfile = NULL;
    }

    if (target->spec->errfile) {
	unlink(target->spec->errfile);
	free(target->spec->errfile);
	target->spec->errfile = NULL;
    }

    free(target->state);

    return 0;
}

static int linux_userproc_kill(struct target *target,int sig) {
    struct linux_userproc_state *lstate;

    lstate = (struct linux_userproc_state *)(target->state);
    vdebug(5,LA_TARGET,LF_LUP,"pid %d\n",lstate->pid);

    if (!lstate) {
	errno = EFAULT;
	return 1;
    }

    if (kill(lstate->pid,sig))
	return 1;

    return 0;
}

static int linux_userproc_loadspaces(struct target *target) {
    struct linux_userproc_state *lstate = \
	(struct linux_userproc_state *)target->state;
    struct addrspace *space = addrspace_create(target,"NULL",lstate->pid);

    space->target = target;
    RHOLD(space,target);

    list_add_tail(&space->space,&target->spaces);

    return 0;
}

static int linux_userproc_loadregions(struct target *target,
				      struct addrspace *space) {
    char buf[PATH_MAX*2];
    char main_exe[PATH_MAX];
    FILE *f;
    char p[4];
    struct memregion *region;
    struct memrange *range;
    unsigned long long start,end,offset;
    region_type_t rtype;
    int rc;
    char *ret;
    struct linux_userproc_state *lstate = \
	(struct linux_userproc_state *)target->state;

    vdebug(5,LA_TARGET,LF_LUP,"pid %d\n",lstate->pid);

    /* first, find the pathname of our main exe */
    snprintf(buf,PATH_MAX*2,"/proc/%d/exe",lstate->pid);
    if ((rc = readlink(buf,main_exe,PATH_MAX - 1)) < 1)
	return -1;
    main_exe[rc] = '\0';

    snprintf(buf,PATH_MAX,"/proc/%d/maps",lstate->pid);
    f = fopen(buf,"r");
    if (!f)
	return 1;

    while (1) {
	errno = 0;
	if (!(ret = fgets(buf,PATH_MAX*2,f)) && !errno)
	    break;
	else if (!ret && errno) {
	    verror("fgets: %s",strerror(errno));
	    break;
	}

	vdebug(8,LA_TARGET,LF_LUP,"scanning mmap line %s",buf);

	rc = sscanf(buf,"%Lx-%Lx %c%c%c%c %Lx %*x:%*x %*d %s",&start,&end,
		    &p[0],&p[1],&p[2],&p[3],&offset,buf);
	if (rc == 8 || rc == 7) {
	    if (rc == 8) {
		/* we got the whole thing, including a path */
		if (strncmp(main_exe,buf,PATH_MAX) == 0) 
		    rtype = REGION_TYPE_MAIN;
		else if (strcmp(buf,"[heap]") == 0) 
		    rtype = REGION_TYPE_HEAP;
		else if (strcmp(buf,"[stack]") == 0) 
		    rtype = REGION_TYPE_STACK;
		else if (strcmp(buf,"[vdso]") == 0) 
		    rtype = REGION_TYPE_VDSO;
		else if (strcmp(buf,"[vsyscall]") == 0) 
		    rtype = REGION_TYPE_VSYSCALL;
		else
		    rtype = REGION_TYPE_LIB;
	    }
	    else {
		rtype = REGION_TYPE_ANON;
		buf[0] = '\0';
	    }

	    /* Create a region for this map entry if it doesn't already
	     * exist.
	     */
	    if (rtype == REGION_TYPE_ANON 
		|| !(region = addrspace_find_region(space,buf))) {
		if (!(region = memregion_create(space,rtype,buf)))
		    goto err;
	    }

	    if (!(range = memrange_create(region,start,end,offset,0))) {
		goto err;
	    }

	    if (p[0] == 'r')
		range->prot_flags |= PROT_READ;
	    if (p[1] == 'w')
		range->prot_flags |= PROT_WRITE;
	    if (p[2] == 'x')
		range->prot_flags |= PROT_EXEC;
	    if (p[3] == 's')
		range->prot_flags |= PROT_SHARED;

	    range = NULL;
	    region = NULL;
	}
	/*
	else if (rc == EOF && !errno) {
	    break;
	else if (rc == EOF && errno) {
	    verror("fscanf error: %s\n",strerror(errno));
	    goto err;
	}
	*/
	else if (rc > 0 && !errno) {
	    vwarn("weird content in /proc/pid/maps (%d)!\n",rc);
	}
	else if (rc > 0 && errno) {
	    vwarn("weird content in /proc/pid/maps (%d): %s!\n",rc,strerror(errno));
	}
    }

    fclose(f);
    return 0;

 err:
    fclose(f);
    // XXX cleanup the regions we added??
    return -1;
}

static int linux_userproc_updateregions(struct target *target,
					struct addrspace *space) {
    char buf[PATH_MAX*2];
    char main_exe[PATH_MAX];
    FILE *f;
    char p[4];
    struct memregion *region,*tregion;
    struct memrange *range,*trange;
    unsigned long long start,end,offset;
    region_type_t rtype;
    int rc;
    char *ret;
    struct linux_userproc_state *lstate = \
	(struct linux_userproc_state *)target->state;
    uint32_t prot_flags;
    int exists;
    int updated;

    vdebug(5,LA_TARGET,LF_LUP,"pid %d\n",lstate->pid);

    /* first, find the pathname of our main exe */
    snprintf(buf,PATH_MAX*2,"/proc/%d/exe",lstate->pid);
    if ((rc = readlink(buf,main_exe,PATH_MAX - 1)) < 1)
	return -1;
    main_exe[rc] = '\0';

    snprintf(buf,PATH_MAX,"/proc/%d/maps",lstate->pid);
    f = fopen(buf,"r");
    if (!f)
	return 1;

    while (1) {
	errno = 0;
	if (!(ret = fgets(buf,PATH_MAX*2,f)) && !errno)
	    break;
	else if (!ret && errno) {
	    verror("fgets: %s",strerror(errno));
	    break;
	}

	vdebug(9,LA_TARGET,LF_LUP,"scanning mmap line %s",buf);

	rc = sscanf(buf,"%Lx-%Lx %c%c%c%c %Lx %*x:%*x %*d %s",&start,&end,
		    &p[0],&p[1],&p[2],&p[3],&offset,buf);
	if (rc == 8 || rc == 7) {
	    if (rc == 8) {
		/* we got the whole thing, including a path */
		if (strncmp(main_exe,buf,PATH_MAX) == 0) 
		    rtype = REGION_TYPE_MAIN;
		else if (strcmp(buf,"[heap]") == 0) 
		    rtype = REGION_TYPE_HEAP;
		else if (strcmp(buf,"[stack]") == 0) 
		    rtype = REGION_TYPE_STACK;
		else if (strcmp(buf,"[vdso]") == 0) 
		    rtype = REGION_TYPE_VDSO;
		else if (strcmp(buf,"[vsyscall]") == 0) 
		    rtype = REGION_TYPE_VSYSCALL;
		else
		    rtype = REGION_TYPE_LIB;
	    }
	    else {
		rtype = REGION_TYPE_ANON;
		buf[0] = '\0';
	    }

	    /* Create a region for this map entry if it doesn't already
	     * exist.
	     */
	    if ((rtype != REGION_TYPE_ANON 
		 && !(region = addrspace_match_region_name(space,rtype,buf)))
		|| (rtype == REGION_TYPE_ANON
		    && !(region = addrspace_match_region_start(space,rtype,start)))) {
		if (!(region = memregion_create(space,rtype,buf)))
		    goto err;
		region->new = 1;
	    }
	    else {
		region->exists = 1;
	    }

	    prot_flags = 0;
	    if (p[0] == 'r')
		prot_flags |= PROT_READ;
	    if (p[1] == 'w')
		prot_flags |= PROT_WRITE;
	    if (p[2] == 'x')
		prot_flags |= PROT_EXEC;
	    if (p[3] == 's')
		prot_flags |= PROT_SHARED;

	    if (!(range = memregion_match_range(region,start))) {
		if (!(range = memrange_create(region,start,end,offset,0))) {
		    goto err;
		}
		range->new = 1;
	    }
	    else {
		if (range->end == end 
		    && range->offset == offset 
		    && range->prot_flags == prot_flags)
		    range->same = 1;
		else {
		    range->end = end;
		    range->offset = offset;
		    range->prot_flags = prot_flags;
		    range->updated = 1;

		    if (start < region->base_load_addr)
			region->base_load_addr = start;
		}
	    }

	    range = NULL;
	    region = NULL;
	}
	else if (rc > 0 && !errno) {
	    vwarn("weird content in /proc/pid/maps (%d)!\n",rc);
	}
	else if (rc > 0 && errno) {
	    vwarn("weird content in /proc/pid/maps (%d): %s!\n",rc,strerror(errno));
	}
    }
    fclose(f);

    /*
     * Now, for all the regions/ranges, check if they were newly added
     * or modified or still exist; if none of those, then they vanished
     * and we have to purge them.
     */

    list_for_each_entry_safe(region,tregion,&space->regions,region) {
	exists = 0;
	updated = 0;
	list_for_each_entry_safe(range,trange,&region->ranges,range) {
	    if (range->new) {
		vdebug(3,LA_TARGET,LF_LUP,
		       "new range 0x%"PRIxADDR"-0x%"PRIxADDR":%"PRIiOFFSET"\n",
		       range->start,range->end,range->offset);
		exists = 1;
		target_add_state_change(target,TID_GLOBAL,
					TARGET_STATE_CHANGE_RANGE_NEW,
					0,range->prot_flags,
					range->start,range->end,region->name);
	    }
	    else if (range->same) {
		vdebug(9,LA_TARGET,LF_LUP,
		       "same range 0x%"PRIxADDR"-0x%"PRIxADDR":%"PRIiOFFSET"\n",
		       range->start,range->end,range->offset);
		exists = 1;
	    }
	    else if (range->updated) {
		vdebug(3,LA_TARGET,LF_LUP,
		       "updated range 0x%"PRIxADDR"-0x%"PRIxADDR":%"PRIiOFFSET"\n",
		       range->start,range->end,range->offset);
		exists = 1;
		updated = 1;

		target_add_state_change(target,TID_GLOBAL,
					TARGET_STATE_CHANGE_RANGE_MOD,
					0,range->prot_flags,
					range->start,range->end,region->name);
	    }
	    else {
		vdebug(3,LA_TARGET,LF_LUP,
		       "removing stale range 0x%"PRIxADDR"-0x%"PRIxADDR":%"PRIiOFFSET"\n",
		       range->start,range->end,range->offset);
		target_add_state_change(target,TID_GLOBAL,
					TARGET_STATE_CHANGE_RANGE_DEL,
					0,range->prot_flags,
					range->start,range->end,region->name);
		memrange_free(range);
	    }
	    range->new = range->same = range->updated = 0;
	}
	if (!exists || list_empty(&region->ranges)) {
	    vdebug(3,LA_TARGET,LF_LUP,"removing stale region (%s:%s:%s)\n",
		   region->space->idstr,region->name,REGION_TYPE(region->type));
	    target_add_state_change(target,TID_GLOBAL,
				    TARGET_STATE_CHANGE_REGION_DEL,
				    0,0,region->base_load_addr,0,region->name);
	    memregion_free(region);
	}
	else if (updated) {
	    target_add_state_change(target,TID_GLOBAL,
				    TARGET_STATE_CHANGE_REGION_MOD,
				    0,0,region->base_load_addr,0,region->name);
	}
	else if (region->new) {
	    region->exists = region->new = 0;
	    target_add_state_change(target,TID_GLOBAL,
				    TARGET_STATE_CHANGE_REGION_NEW,
				    0,0,region->base_load_addr,0,region->name);

	    /*
	     * Add debugfiles for the region!
	     */
	    if (linux_userproc_loaddebugfiles(target,space,region)) {
		vwarn("could not load debugfile for new region (%s:%s:%s)\n",
		      region->space->idstr,region->name,
		      REGION_TYPE(region->type));
	    }
	}
	else {
	    region->exists = region->new = 0;
	}
    }

    return 0;

 err:
    fclose(f);
    // XXX cleanup the regions we added/modified??
    return -1;
}

static int linux_userproc_loaddebugfiles(struct target *target,
					 struct addrspace *space,
					 struct memregion *region) {
    int retval = -1;
    struct debugfile *debugfile = NULL;
    struct linux_userproc_state *lstate = \
	(struct linux_userproc_state *)target->state;

    vdebug(5,LA_TARGET,LF_LUP,"pid %d\n",lstate->pid);

    if (!(region->type == REGION_TYPE_MAIN 
	  || region->type == REGION_TYPE_LIB)) {
	vdebug(4,LA_TARGET,LF_LUP,"region %s is not MAIN nor LIB; skipping!\n",
	       region->name);
	return 0;
    }

    if (!region->name || strlen(region->name) == 0)
	return -1;

    debugfile = debugfile_from_file(region->name,
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
     * Propagate some binfile info...
     */
    region->base_phys_addr = region->binfile->base_phys_addr;
    region->base_virt_addr = region->binfile->base_virt_addr;

    retval = 0;

 out:
    return retval;
}

static struct target *
linux_userproc_instantiate_overlay(struct target *target,
				   struct target_thread *tthread,
				   struct target_spec *spec) {
    errno = ENOTSUP;
    return NULL;
}

static target_status_t linux_userproc_status(struct target *target) {
    char buf[256];
    FILE *statf;
    char pstate;
    target_status_t retval = TSTATUS_ERROR;
    int rc;
    struct linux_userproc_state *lstate = \
	(struct linux_userproc_state *)target->state;
    int pid = lstate->pid;

    vdebug(5,LA_TARGET,LF_LUP,"pid %d\n",pid);

 again:
    snprintf(buf,256,"/proc/%d/stat",pid);
    statf = fopen(buf,"r");
    if (!statf) {
	verror("statf(%s): %s\n",buf,strerror(errno));
	return TSTATUS_ERROR;
    }

    if ((rc = fscanf(statf,"%d (%s %c",&pid,buf,&pstate))) {
	if (pstate == 'R' || pstate == 'r' || pstate == 'W' || pstate == 'w')
	    retval = TSTATUS_RUNNING;
	else if (pstate == 'S' || pstate == 's' || pstate == 'D' || pstate == 'd')
	    retval = TSTATUS_STOPPED;
	else if (pstate == 'Z' || pstate == 'z')
	    retval = TSTATUS_DEAD;
	else if (pstate == 'T' || pstate == 't')
	    retval = TSTATUS_PAUSED;
	else {
	    vwarn("fscanf returned %d; read %d (%s) %c; returning TSTATUS_UNKNOWN!\n",
		  rc,pid,buf,pstate);
	    retval = TSTATUS_UNKNOWN;
	}
    }
    else if (rc < 0 && errno == EINTR) {
	fclose(statf);
	goto again;
    }

    vdebug(3,LA_TARGET,LF_LUP,"pid %d status %d\n",lstate->pid,retval);

    fclose(statf);
    return retval;
}

static int linux_userproc_pause(struct target *target,int nowait) {
    GHashTableIter iter;
    struct target_thread *tthread;
    gpointer key;
    int pstatus;
    struct linux_userproc_state *lstate = \
	(struct linux_userproc_state *)target->state;
    int rc = 0;
    struct linux_userproc_thread_state *tstate;
    siginfo_t sinfo;
    
    vdebug(5,LA_TARGET,LF_LUP,"pid %d\n",lstate->pid);

    /*
     * We send a stop to each traced tid, and wait until it is delivered
     * to us!  We do not save it for redelivery to the child!
     *
     * Only do this if the target is not currently paused, because it
     * might need to be restarted with whatever last_signo state it had
     * previously been paused with.
     */

    g_hash_table_iter_init(&iter,target->threads);
    while (g_hash_table_iter_next(&iter,&key,(gpointer)&tthread)) {
	if (key == (gpointer)TID_GLOBAL)
	    continue;

	if (!linux_userproc_load_thread(target,tthread->tid,0)) {
	    verror("could not load thread %"PRIiTID"; pausing anyway!\n",
		   tthread->tid);
	}
	else if (tthread->status == THREAD_STATUS_PAUSED) {
	    vdebug(3,LA_TARGET,LF_LUP,"tid %d already paused\n",tthread->tid);
	    continue;
	}
	/*
	 * Since thread load is slow (goes through libc and /proc to
	 * check status, we try a last-ditch means to avoid stomping on
	 * pending signal info that we need to handle to detect a ptrace
	 * stop event.
	 */
	else if (waitid(P_PID,tthread->tid,&sinfo,WNOHANG | WNOWAIT) == 0
		 && sinfo.si_pid == tthread->tid) {
	    vdebug(3,LA_TARGET,LF_LUP,
		   "tid %d has pending siginfo to waitpid on; not pausing here\n",
		   tthread->tid);
	    continue;
	}

	tstate = (struct linux_userproc_thread_state *)tthread->state;

	tstate->ctl_sig_sent = 1;
	/* If we have an evloop attached, we might get interrupted
	 * before the synchronous waitpid() below is run.
	 *
	 * Of course, this is only an issue for multithread uses of this
	 * library, and we technically would have a race by setting the
	 * signal state bits like we do here :).
	 */
	if (!nowait) 
	    tstate->ctl_sig_synch = 1;
	if (kill(tthread->tid,SIGSTOP) < 0) {
	    verror("kill(%d,SIGSTOP): %s\n",tthread->tid,strerror(errno));
	    --rc;
	    continue;
	}

	if (nowait) {
	    vdebug(3,LA_TARGET,LF_LUP,"not waiting for pause to hit tid %d\n",
		   tthread->tid);
	    continue;
	}

	vdebug(3,LA_TARGET,LF_LUP,"waiting for pause SIGSTOP to hit tid %d\n",
	       tthread->tid);
    again:
	if (waitpid(tthread->tid,&pstatus,__WALL) < 0) {
	    if (errno == ECHILD || errno == EINVAL) {
		verror("waitpid(%"PRIiTID"): %s\n",tthread->tid,strerror(errno));
		--rc;
		continue;
	    }
	    else
		goto again;
	}
	vdebug(3,LA_TARGET,LF_LUP,"pause SIGSTOP has hit tid %d\n",tthread->tid);
	target_thread_set_status(tthread,THREAD_STATUS_PAUSED);
	tstate->ctl_sig_sent = 0;
	tstate->ctl_sig_synch = 0;
    }

    target_set_status(target,TSTATUS_PAUSED);

    return rc;
}

static int linux_userproc_pause_thread(struct target *target,tid_t tid,
				       int nowait) {
    int pstatus;
    struct linux_userproc_state *lstate;
    struct target_thread *tthread;
    struct linux_userproc_thread_state *tstate;

    /*
     * The global thread doesn't really exist, so we can't pause it.
     */
    if (tid == TID_GLOBAL)
	return 0;

    lstate = (struct linux_userproc_state *)(target->state);
    if (!(tthread = target_lookup_thread(target,tid))) {
	verror("thread %"PRIiTID" does not exist!\n",tid);
	errno = EINVAL;
	return 1;
    }
    tstate = (struct linux_userproc_thread_state *)tthread->state;
    
    vdebug(5,LA_TARGET,LF_LUP,"pid %d thread %"PRIiTID"\n",lstate->pid,tid);

    /*
     * We send a stop to each traced tid, and wait until it is delivered
     * to us!  We do not save it for redelivery to the child!
     *
     * Only do this if the target is not currently paused, because it
     * might need to be restarted with whatever last_signo state it had
     * previously been paused with.
     */

    if (!linux_userproc_load_thread(target,tthread->tid,0)) {
	verror("could not load thread %"PRIiTID"; pausing anyway!\n",
	       tthread->tid);
    }
    else if (tthread->status == THREAD_STATUS_PAUSED) {
	vdebug(3,LA_TARGET,LF_LUP,"tid %d already paused\n",tthread->tid);
	return 0;
    }

    if (kill(tthread->tid,SIGSTOP) < 0) {
	verror("kill(%d,SIGSTOP): %s\n",tthread->tid,strerror(errno));
	return 1;
    }
    tstate->ctl_sig_sent = 1;

    if (nowait) {
	vdebug(3,LA_TARGET,LF_LUP,"not waiting for pause to hit tid %d\n",tthread->tid);
	return 0;
    }

    vdebug(3,LA_TARGET,LF_LUP,"waiting for pause SIGSTOP to hit tid %d\n",tthread->tid);
 again:
    if (waitpid(tthread->tid,&pstatus,__WALL) < 0) {
	if (errno == ECHILD || errno == EINVAL) {
	    verror("waitpid(%"PRIiTID"): %s\n",tthread->tid,strerror(errno));
	    return 1;
	}
	else
	    goto again;
    }
    vdebug(3,LA_TARGET,LF_LUP,"pause SIGSTOP has hit tid %d\n",tthread->tid);
    target_thread_set_status(tthread,THREAD_STATUS_PAUSED);
    tstate->ctl_sig_sent = 0;

    return 0;
}

static int linux_userproc_resume(struct target *target) {
    struct linux_userproc_state *lstate;
    GHashTableIter iter;
    struct target_thread *tthread;
    struct linux_userproc_thread_state *tstate;
    gpointer key;
    int rc = 0;

    lstate = (struct linux_userproc_state *)(target->state);

    vdebug(9,LA_TARGET,LF_LUP,"pid %d\n",lstate->pid);

    /*
     * First, on resume, try to keep handling any threads that were
     * "paused" (by the probe layer not restarting them) at some point
     * in the breakpoint handling process -- but only if the probepoint
     * they needed has freed up.
     */

    /* Flush back registers if they're dirty, for paused threads. */
    linux_userproc_flush_all_threads(target);
    /* Always invalidate all threads so their status (and state) is
     * re-read each time we waitpid.
     */
    target_invalidate_all_threads(target);

    /*
     * Then, go through all the threads and figure out which ones we can
     * restart, and which ones we can't.  Invalidate only the ones we
     * are restarting.
     */
    g_hash_table_iter_init(&iter,target->threads);
    while (g_hash_table_iter_next(&iter,&key,(gpointer)&tthread)) {
	if (key == (gpointer)TID_GLOBAL)
	    continue;

	/*
	 * We have several cases.  First, we might have tried to pause
	 * all threads except target->blocking_thread; blocking_thread
	 * always gets restarted, and all others are ignored.  (Well, if
	 * the blocking thread has a single step scheduled, it may
	 * already be running -- this is target specific).  Second, if a
	 * thread is not paused, don't restart it (doh).  Otherwise, all
	 * other paused threads get restarted.
	 */
	if (target->blocking_thread && tthread != target->blocking_thread) 
	    continue;

	if (tthread->status != THREAD_STATUS_PAUSED
	    && tthread->status != THREAD_STATUS_EXITING)
	    continue;
	else if (tthread->resumeat != THREAD_RESUMEAT_NONE)
	    continue;

	/*
	 * Do the restart.
	 */

	if (lstate->ptrace_opts != lstate->ptrace_opts_new) {
	    errno = 0;
	    if (ptrace(PTRACE_SETOPTIONS,tthread->tid,NULL,
		       lstate->ptrace_opts_new) < 0) {
		vwarn("ptrace setoptions on tid %"PRIiTID" failed: %s\n",
		      tthread->tid,strerror(errno));
	    }
	}
	tstate = (struct linux_userproc_thread_state *)tthread->state;

	if (tstate->last_signo > -1) {
	    if (ptrace(lstate->ptrace_type,tthread->tid,NULL,
		       tstate->last_signo) < 0) {
		verror("ptrace signo %d restart of tid %"PRIiTID" failed: %s\n",
		       tstate->last_signo,tthread->tid,strerror(errno));
		--rc;
		continue;
	    }
	}
	else {
	    if (ptrace(lstate->ptrace_type,tthread->tid,NULL,NULL) < 0) {
		verror("ptrace restart of tid %"PRIiTID" (status %d) failed: %s\n",
		       tthread->tid,tthread->status,strerror(errno));
		--rc;
		continue;
	    }
	}

	vdebug(8,LA_TARGET,LF_LUP,"ptrace restart pid %d tid %"PRIiTID" succeeded\n",
	       lstate->pid,tthread->tid);
	target_thread_set_status(tthread,THREAD_STATUS_RUNNING);

	tstate->last_signo = -1;
	tstate->last_status = -1;
    }

    if (lstate->ptrace_opts != lstate->ptrace_opts_new) 
	lstate->ptrace_opts = lstate->ptrace_opts_new;

    /*
     * If there's a blocking thread, we can't do anything here, yet.
     */
    if (!target->blocking_thread) {
	g_hash_table_iter_init(&iter,target->threads);
	while (g_hash_table_iter_next(&iter,&key,(gpointer)&tthread)) {
	    if (key == (gpointer)TID_GLOBAL)
		continue;

	    /*
	     * If the thread was needing to be resumed because it could not
	     * own the probepoint, and the probepoint it needed is now free,
	     * then let it go!  Also, as soon as one of these happens
	     * successfully and sets target->blocking, break out of the
	     * loop, because once a resumeat thread calls target_pause,
	     * we can't try to do anything else that would call
	     * target_pause and thus set target->blocking_thread.
	     */
	    if (tthread->status == THREAD_STATUS_PAUSED
		&& tthread->resumeat != THREAD_RESUMEAT_NONE) {
		probepoint_resumeat_handler(target,tthread);
	    }

	    if (target->blocking_thread)
		break;
	}
    }

    target_set_status(target,TSTATUS_RUNNING);
    return 0;
}

static thread_status_t linux_userproc_handle_internal(struct target *target,
						      tid_t tid,
						      int pstatus,int *again) {
    struct linux_userproc_state *lstate;
    REG dreg = -1;
    struct probepoint *dpp;
    REGVAL ipval;
#if __WORDSIZE == 64
    unsigned long cdr;
#else
    int cdr;
#endif
    struct target_thread *tthread = NULL;
    struct linux_userproc_thread_state *tstate;
    tid_t newtid;
    int pid;
    long int newstatus;
    struct addrspace *space;

    lstate = (struct linux_userproc_state *)(target->state);
    pid = lstate->pid;
    if (!(tthread = target_lookup_thread(target,tid))) {
	if (__tid_exists(pid,tid)) {
	    vdebug(5,LA_TARGET,LF_LUP,
		   "thread %d does not YET exist; might be new!\n",tid);
	    g_hash_table_insert(lstate->new_racy_threads,
				(gpointer)(uintptr_t)tid,
				(gpointer)(uintptr_t)pstatus);
	    goto out_again;
	}
	verror("thread %"PRIiTID" does not exist!\n",tid);
	errno = EINVAL;
	goto out_err;
    }
    tstate = (struct linux_userproc_thread_state *)tthread->state;

    target_clear_state_changes(target);

    if (WIFSTOPPED(pstatus)) {
	/* Ok, this was a ptrace event; figure out which sig (or if it
	 * was a syscall), and redeliver the sig if it was a sig;
	 * otherwise, don't deliver a sig, and just continue the child,
	 * on resume.
	 */

	/*
	 * We know the thread is at least "paused", so set that; change
	 * it later depending on *which* ptrace event *if necessary*.
	 *
	 * (This avoids expensive polling of /proc/pid/task/tid/stat in
	 * linux_userproc_load_thread, and we can just call
	 * __linux_userproc_load_thread.)
	 */
	target_thread_set_status(tthread,THREAD_STATUS_PAUSED);
	target_set_status(target,TSTATUS_PAUSED);

	/*
	 * Handle clone before loading the current thread; we don't need
	 * the extra overhead of loading the current thread in this
	 * case; we just want to attach to the new thread right away.
	 */
	if (pstatus >> 8 == (SIGTRAP | PTRACE_EVENT_CLONE << 8)) {
	    ptrace(PTRACE_GETEVENTMSG,tid,NULL,&newstatus);
	    newtid = (tid_t)newstatus;
	    vdebug(5,LA_TARGET,LF_LUP,
		   "target %d thread %d cloned new thread %d; attaching now.\n",
		   pid,tid,newtid);

	    linux_userproc_attach_thread(target,tid,newtid);
	    /*
	     * Flush, invalidate, and restart the parent.
	     */
	    /*
	    if (ptrace(lstate->ptrace_type,tid,NULL,NULL) < 0) {
		vwarn("ptrace parent restart failed: %s\n",strerror(errno));
	    }
	    */
	    //target_thread_set_status(tthread,THREAD_STATUS_RUNNING);
	    goto out_again;
	}

	//if (!lstate->live_syscall_maps_tracking) {
	list_for_each_entry(space,&target->spaces,space) {
	    linux_userproc_updateregions(target,space);
	}
	//}

	if (!__linux_userproc_load_thread(target,tid,0,1)) {
	    verror("could not load thread %"PRIiTID"!\n",tid);
	    goto out_err;
	}

	target->current_thread = tthread;
	lstate->current_tid = tthread->tid;

	tstate->last_status = tstate->last_signo = WSTOPSIG(pstatus);
	if (tstate->last_status == (SIGTRAP | 0x80)) {
	    vdebug(5,LA_TARGET,LF_LUP,
		   "thread %"PRIiTID" stopped with syscall trap signo %d\n",
		   tid,tstate->last_status);
	    tstate->last_signo = -1;
	}
	else if (pstatus >> 8 == (SIGTRAP | PTRACE_EVENT_EXIT << 8)) {
	    vdebug(5,LA_TARGET,LF_LUP,
		   "target %d tid %d exiting (%d)! will detach at next resume.\n",
		   pid,tid,tstate->last_status);
	    tstate->last_signo = -1;
	    //linux_userproc_detach(target);
	    //target_set_status(target,TSTATUS_EXITING);
	    target_thread_set_status(tthread,TSTATUS_EXITING);

	    target_add_state_change(target,tid,TARGET_STATE_CHANGE_EXITING,
				    0,0,0,0,NULL);

	    return THREAD_STATUS_EXITING;
	}
	else if (tstate->last_status == SIGTRAP) {
	    /* Don't deliver debug traps! */
	    vdebug(5,LA_TARGET,LF_LUP,"thread %"PRIiTID" stopped with trap signo %d\n",
		   tid,tstate->last_status);
	    tstate->last_signo = -1;

	    /*
	     * This is where we handle breakpoint or single step
	     * events.
	     *
	     * If this was a single step event, notify the ss handler
	     * (we always assume that if target->sstep_probepoint was
	     * set, we are single stepping with hardware breakpoints
	     * disabled, since the target code does this for us!).
	     *
	     * Otherwise, if the address matches one of our hardware
	     * breakpoints, we pass that addr to the handler.
	     *
	     * Otherwise, if it doesn't match, we (locally, not in the
	     * CPU's register state -- the generic bp handler does
	     * this!) decrement EIP by the breakpoint instruction length
	     * and search for that address.  If we find one, we notify
	     * that BP handler.
	     *
	     * Otherwise, if we haven't found a SW probepoint that
	     * matches, return to the user, and let THEM handle it!
	     */

	    /* Check the hw debug status reg first */
	    errno = 0;
	    cdr = ptrace(PTRACE_PEEKUSER,tid,
			 offsetof(struct user,u_debugreg[6]),NULL);
	    if (errno) {
		vwarn("could not read current val of status debug reg;"
		      " don't know which handler to call; fatal!\n");
		return THREAD_STATUS_ERROR;
	    }

	    /*
	     * Check the breakpoints first; starting with the debug
	     * status register.
	     */
	    if (cdr & 15) {
		if (cdr & 0x1)
		    dreg = 0;
		else if (cdr & 0x2)
		    dreg = 1;
		else if (cdr & 0x4)
		    dreg = 2;
		else if (cdr & 0x8)
		    dreg = 3;

		/* If we are relying on the status reg to tell us,
		 * then also read the actual hw debug reg to get the
		 * address we broke on.
		 */
		errno = 0;
		ipval = ptrace(PTRACE_PEEKUSER,tid,
			       offsetof(struct user,u_debugreg[dreg]),NULL );
		if (errno) {
		    verror("could not read current val of debug reg %d after up status!\n",dreg);
		    return THREAD_STATUS_ERROR;
		}

		vdebug(4,LA_TARGET,LF_LUP,
		       "found hw break (status) in dreg %d on 0x%"PRIxADDR"\n",
		       dreg,ipval);
	    }
	    else {
		ipval = linux_userproc_read_reg(target,tid,target->ipregno);
		if (errno) {
		    verror("could not read EIP while finding probepoint: %s\n",
			   strerror(errno));
		    return THREAD_STATUS_ERROR;
		}

		if (tstate->dr[0] == (ptrace_reg_t)ipval)
		    dreg = 0;
		else if (tstate->dr[1] == (ptrace_reg_t)ipval)
		    dreg = 1;
		else if (tstate->dr[2] == (ptrace_reg_t)ipval)
		    dreg = 2;
		else if (tstate->dr[3] == (ptrace_reg_t)ipval)
		    dreg = 3;

		if (dreg > -1)
		    vdebug(4,LA_TARGET,LF_LUP,
			   "found hw break (eip) in dreg %d on 0x%"PRIxADDR"\n",
			   dreg,ipval);
		else
		    vdebug(4,LA_TARGET,LF_LUP,
			   "checking for SS or sw break on 0x%"PRIxADDR"\n",
			   ipval - target->breakpoint_instrs_len);
	    }

	    /*
	     * Handle the hardware breakpoint if we found one.
	     */
	    if (dreg > -1) {
		/* Found HW breakpoint! */
		/* Clear the status bits right now. */
		errno = 0;
		if (ptrace(PTRACE_POKEUSER,tid,
			   offsetof(struct user,u_debugreg[6]),0)) {
		    verror("could not clear status debug reg, continuing"
			   " anyway: %s!\n",strerror(errno));
		    errno = 0;
		}
		else {
		    vdebug(5,LA_TARGET,LF_LUP,"cleared status debug reg 6\n");
		}

		dpp = (struct probepoint *)				\
		    g_hash_table_lookup(tthread->hard_probepoints,
					(gpointer)ipval);

		if (!dpp) {
		    verror("found hw breakpoint 0x%"PRIxADDR
			   " in debug reg %d, BUT no probepoint!\n",
			   ipval,dreg);
		    return THREAD_STATUS_ERROR;
		}

		if (target->bp_handler(target,tthread,dpp,cdr & 0x4000)
		    != RESULT_SUCCESS)
		    return THREAD_STATUS_ERROR;
		goto out_again;
	    }
	    /*
	     * Try to handle a single step.
	     *
	     * NOTE NOTE NOTE: we must do this before checking the
	     * software breakpoint.  Suppose we are single stepping
	     * something at the breakpoint location; if we take the
	     * single step interrupt, but check the software probepoint
	     * below first, we'll think we're at a breakpoint, but we're
	     * at a single step.
	     *
	     * Similarly, but differently, we cannot check single step
	     * before hardware brekapoint, because we don't catch
	     * the case where we single step into a hardware breakpoint
	     * -- we miss the single step because the hw bp seems to
	     * dominate the single step exception.  bp_handler handles
	     * this...
	     */
	    else if (cdr & 0x4000) {
		if (tthread->tpc) {
		    if (target->ss_handler(target,tthread,tthread->tpc->probepoint)
			!= RESULT_SUCCESS)
			return THREAD_STATUS_ERROR;
		    goto out_again;
		}
		else {
		    if (target->ss_handler(target,tthread,NULL)
			!= RESULT_SUCCESS)
			return THREAD_STATUS_ERROR;
		    goto out_again;
		}
	    }
	    /* Try to handle a software breakpoint. */
	    else if ((dpp = (struct probepoint *)			\
		      g_hash_table_lookup(target->soft_probepoints,
					  (gpointer)(ipval - target->breakpoint_instrs_len)))) {
		if (target->bp_handler(target,tthread,dpp,cdr & 0x4000)
		    != RESULT_SUCCESS)
		    return THREAD_STATUS_ERROR;
		goto out_again;
	    }
	    else {
		vwarn("could not find hardware bp and not sstep'ing;"
		      " letting user handle fault at 0x%"PRIxADDR"!\n",
		      ipval);
	    }
	}
	else {
	    if (tstate->ctl_sig_sent) {
		vdebug(5,LA_TARGET,LF_LUP,
		       "thread %"PRIiTID" stopped with (our) signo %d\n",
		       tid,tstate->last_status);
		/*
		 * Don't reinject this signal!
		 */
		tstate->last_signo = -1;
		tstate->ctl_sig_sent = 0;

		/*
		 * If we were trying to sigstop all threads, let all the
		 * stop sigs get recv'd...
		 */
		if (lstate->ctl_sig_pausing_all) {
		    tstate->ctl_sig_recv = 1;
		    goto out_again;
		}
		else {
		    tstate->ctl_sig_recv = 0;
		    /* Restart just this thread. */
		    if (ptrace(lstate->ptrace_type,tid,NULL,NULL) < 0) {
			verror("ptrace restart of tid %"PRIiTID" failed: %s\n",
			       tid,strerror(errno));
		    }
		    target_thread_set_status(tthread,THREAD_STATUS_RUNNING);
		    goto out_again;
		}
	    }
	    else
		vdebug(5,LA_TARGET,LF_LUP,
		       "thread %"PRIiTID" stopped with (ext) signo %d\n",
		       tid,tstate->last_status);
	}

	return THREAD_STATUS_PAUSED;
    }
    else if (WIFCONTINUED(pstatus)) {

	target_set_status(target,TSTATUS_PAUSED);

	tstate->last_signo = -1;
	tstate->last_status = -1;

	goto out_again;
    }
    else if (WIFSIGNALED(pstatus) || WIFEXITED(pstatus)) {

	target_set_status(target,TSTATUS_PAUSED);

	/* yikes, it was sigkill'd out from under us! */
	/* XXX: is error good enough?  The pid is gone; we should
	 * probably dump this target.
	 */
	target_tid_set_status(target,tid,THREAD_STATUS_DONE);

	target_add_state_change(target,tid,TARGET_STATE_CHANGE_THREAD_EXITED,
				pstatus,0,0,0,NULL);

	/*
	 * If we're out of threads (besides the global thread); detach
	 * the target now.  Otherwise, just detach from the thread.
	 */
	if (g_hash_table_size(target->threads) == 2) {
	    target_set_status(target,TSTATUS_DONE);

	    target_add_state_change(target,tid,TARGET_STATE_CHANGE_EXITED,
				    0,0,0,0,NULL);

	    linux_userproc_detach(target);
	}
	else 
	    linux_userproc_detach_thread(target,tid,0);

	return THREAD_STATUS_DONE;
    }
    else {
	target_set_status(target,TSTATUS_PAUSED);

	vwarn("unexpected child process status event: %08x; bailing!\n",
	      pstatus);
	return THREAD_STATUS_ERROR;
    }

 out_err:
    return THREAD_STATUS_ERROR;

 out_again:
    /*
     * If this is not returning to the user (i.e., not going back
     * through target_resume()), we must flush and invalidate our
     * threads ourself!
     */
    //linux_userproc_flush_all_threads(target);
    //target_invalidate_all_threads(target);
    //target_set_status(target,TSTATUS_RUNNING);
    target_resume(target);
    if (again)
	*again = 1;
    return THREAD_STATUS_RUNNING;
}

int linux_userproc_evloop_handler(int readfd,int fdtype,void *state) {
    int tid;
    int retval;
    int status;
    int again = 0;
    struct target *target = (struct target *)state;
    struct target_thread *tthread;
    struct linux_userproc_thread_state *tstate;

    if ((tid = waitpipe_get_pid(readfd)) < 0) {
	verror("could not find thread tid for readfd %d!\n",readfd);
	errno = ESRCH;
	return EVLOOP_HRET_BADERROR;
    }

    if ((waitpipe_drain(tid)) < 0) {
	verror("waitpipe_drain: %s\n",strerror(errno));
	return EVLOOP_HRET_BADERROR;
    }

    if (!(tthread = target_lookup_thread(target,tid))) {
	verror("cound not find thread %d!\n",tid);
	errno = ESRCH;
	return EVLOOP_HRET_BADERROR;
    }

    tstate = (struct linux_userproc_thread_state *)tthread->state;

    if (tstate->ctl_sig_sent && tstate->ctl_sig_synch) {
	vdebug(5,LA_TARGET,LF_LUP,
	       "synchronous ctl sig sent to tid %d; not calling waitpid; ignoring"
	       " (probable multithread bug!)\n",
	       tid);
	return EVLOOP_HRET_SUCCESS;
    }

    /* Need to waitpid(tid) to grab status, then can call handle_internal(). */
 again:
    retval = waitpid(tid,&status,WNOHANG | __WALL);
    if (retval < 0) {
	if (errno == ECHILD || errno == EINVAL) {
	    verror("waitpid(%"PRIiTID"): %s\n",tid,strerror(errno));
	    return EVLOOP_HRET_ERROR;
	}
	else
	    goto again;
    }
    else if (retval == 0) {
	vdebug(5,LA_TARGET,LF_LUP,
	       "tid %"PRIiTID" running; waitpid has nothing to report; ignoring!\n",
	       tid);
	return EVLOOP_HRET_SUCCESS;
    }

    vdebug(5,LA_TARGET,LF_LUP,
	   "tid %"PRIiTID" running; handling evloop sig\n",tid);

    /*
     * Ok, handle whatever happened.  If we can't handle it, pass
     * control to the user, just like monitor() would.
     */
    retval = linux_userproc_handle_internal(target,tid,status,&again);

    if (THREAD_SPECIFIC_STATUS(retval)) {
	verror("thread-specific status %d tid %d; bad!\n",retval,tid);
	return EVLOOP_HRET_BADERROR;
    }
    else if (retval == TSTATUS_ERROR) {
	/* invoke user error handler... ? */
	verror("unexpected error on thread %d; bad!\n",tid);
	return EVLOOP_HRET_ERROR;
    }
    else if (retval == TSTATUS_UNKNOWN) {
	/* invoke user error handler... ? */
	verror("unexpected unknown on thread %d; bad!\n",tid);
	return EVLOOP_HRET_ERROR;
    }
    else if (retval == TSTATUS_RUNNING) {
	/* target_resume() has been called, so return success */
	return EVLOOP_HRET_SUCCESS;
    }
    else if (retval == TSTATUS_EXITING) {
	/*
	 * NB:
	 *
	 * target_resume() has NOT been called; we need to call it since
	 * we don't want to intercept it.
	 */
	target_resume(target);
	return EVLOOP_HRET_SUCCESS;
    }
    else if (retval == TSTATUS_DONE) {
	/* remove FD from set */
	vdebug(5,LA_TARGET,LF_LUP,
	       "tid %"PRIiTID" done; removing its fd (%d) from evloop\n",
	       tid,readfd);
	/*
	 * NB:
	 *
	 * If the whole target is not finished, but only this thread,
	 * then resume!
	 */
	if (target->status != TSTATUS_DONE) 
	    target_resume(target);
	/* now remove FD from set */
	return EVLOOP_HRET_REMOVEALLTYPES;
    }
    else if (retval == TSTATUS_PAUSED
	     && tstate->last_signo > -1) {
	/*
	 * NB:
	 *
	 * target_resume() has NOT been called; we need to call it since
	 * we don't want to intercept it.
	 *
	 * It was signaled; we don't expose this to the user when evloop
	 * is handling!
	 */
	vdebug(5,LA_TARGET,LF_LUP,
	       "tid %"PRIiTID" signaled with %d; resuming; signal will hit tid\n",
	       tid,tstate->last_signo);
	target_resume(target);
	return EVLOOP_HRET_SUCCESS;
    }
    else if (retval == TSTATUS_PAUSED) {
	/* user must handle fault; invoke error handler */
	vwarn("unexpected pause on thread %d; bad!\n",tid);
	return EVLOOP_HRET_ERROR;
    }
    else {
	/* user must handle unexpected fault; invoke error handler */
	verror("unexpected error on thread %d; bad!\n",tid);
	return EVLOOP_HRET_BADERROR;
    }
}

/*
 * We need to add waitpipe FDs for any tids we are monitoring.  Also,
 * once we setup an evloop, we need to keep tracking tid
 * addition/subtraction and add/remove waitpipes as the tids come and
 * go.
 */
static int linux_userproc_evloop_add_tid(struct target *target,int tid) {
    int readfd;

    if (!target->evloop) {
	verror("no evloop attached!\n");
	return -1;
    }

    if ((readfd = waitpipe_get(tid)) > 0) {
	vdebug(9,LA_TARGET,LF_LUP,
	       "not adding waitpipe readfd %d for tid %d\n",readfd,tid);
    }
    else {
	readfd = waitpipe_add(tid);
	if (readfd < 0) {
	    verror("could not add tid %d to waitpipe!\n",tid);
	    return -1;
	}

	evloop_set_fd(target->evloop,readfd,EVLOOP_FDTYPE_R,
		      linux_userproc_evloop_handler,target);

	vdebug(5,LA_TARGET,LF_LUP,
	       "added waitpipe/evloop readfd %d for tid %d\n",readfd,tid);
    }

    return 0;
}

/*
 * We need to remove the waitpipe FDs for each tid we are monitoring!
 */
static int linux_userproc_evloop_del_tid(struct target *target,int tid) {
    int readfd;

    if (!target->evloop) {
	verror("no evloop attached!\n");
	return -1;
    }

    if ((readfd = waitpipe_get(tid)) > 0) {
	evloop_unset_fd(target->evloop,readfd,EVLOOP_FDTYPE_A);
	waitpipe_remove(tid);

	vdebug(9,LA_TARGET,LF_LUP,
	       "removed waitpipe/evloop readfd %d for tid %d\n",
	       readfd,tid);
    }
    else {
	vdebug(9,LA_TARGET,LF_LUP,
	       "did not find valid readfd (%d) to remove tid %d from evloop!\n",
	       readfd,tid);
    }

    if (target->infd > -1) 
	evloop_unset_fd(target->evloop,target->infd,EVLOOP_FDTYPE_A);
    if (target->outfd > -1) 
	evloop_unset_fd(target->evloop,target->outfd,EVLOOP_FDTYPE_A);
    if (target->errfd > -1) 
	evloop_unset_fd(target->evloop,target->errfd,EVLOOP_FDTYPE_A);

    return 0;
}

int linux_userproc_attach_evloop(struct target *target,struct evloop *evloop) {
    struct array_list *tids;
    int tid;
    int i;

    if (!waitpipe_is_initialized())
	waitpipe_init_auto(NULL);

    if (target->infd > -1) 
	evloop_set_fd(target->evloop,target->infd,EVLOOP_FDTYPE_W,
		      target->spec->in_evh,target);
    if (target->outfd > -1) 
	evloop_set_fd(target->evloop,target->outfd,EVLOOP_FDTYPE_R,
		      target->spec->out_evh,target);
    if (target->errfd > -1) 
	evloop_set_fd(target->evloop,target->errfd,EVLOOP_FDTYPE_R,
		      target->spec->err_evh,target);

    tids = target_list_tids(target);
    if (!tids)
	return 0;

    array_list_foreach_fakeptr_t(tids,i,tid,uintptr_t) {
	linux_userproc_evloop_add_tid(target,tid);
    }

    array_list_free(tids);

    return 0;
}

int linux_userproc_detach_evloop(struct target *target) {
    struct array_list *tids;
    int tid;
    int i;

    if (!waitpipe_is_initialized())
	waitpipe_init_auto(NULL);

    tids = target_list_tids(target);
    if (!tids)
	return 0;

    array_list_foreach_fakeptr_t(tids,i,tid,uintptr_t) {
	linux_userproc_evloop_del_tid(target,tid);
    }

    array_list_free(tids);

    return 0;
}

static target_status_t linux_userproc_poll(struct target *target,
					   struct timeval *tv,
					   target_poll_outcome_t *outcome,
					   int *pstatus) {
    int tid;
    int status;
    target_status_t retval;
    struct linux_userproc_state *lstate = \
	(struct linux_userproc_state *)target->state;
    struct timespec req, rem;
    unsigned int usec_thresh = 100; // 100 us is the least we'll sleep
    uint64_t total_us;
    uint64_t total_ns = 0;

    if (tv) {
	total_us = tv->tv_sec * 1000000 + tv->tv_usec;
	total_ns = total_us * 1000;

	if (total_us < usec_thresh) {
	    req.tv_sec = 0;
	    req.tv_nsec = total_ns;
	}
	else {
	    req.tv_sec = 0;
	    req.tv_nsec = usec_thresh * 1000;
	}
    }

    vdebug(9,LA_TARGET,LF_LUP,"waitpid target %d\n",lstate->pid);
 again:
    tid = waitpid(-1,&status,WNOHANG | __WALL);
    if (tid < 0) {
	/* We always do this on error; these two errnos are the only
	 * ones we should see, though.
	 */
	if (1 || errno == ECHILD || errno == EINVAL) {
	    if (outcome)
		*outcome = POLL_ERROR;
	    return TSTATUS_ERROR;
	}
    }
    else if (tid == 0) {
	if (!tv) {
	    if (outcome)
		*outcome = POLL_NOTHING;
	    /* Assume it is running!  Is this right? */
	    return TSTATUS_RUNNING;
	}
	else {
	    /* Try to sleep for a bit. */
	    rem.tv_sec = 0;
	    rem.tv_nsec = 0;
	    nanosleep(&req,&rem);
	    if (rem.tv_nsec)
		total_ns -= req.tv_nsec - rem.tv_nsec;
	    else
		total_ns -= req.tv_nsec;

	    if (total_ns > 0) {
		if (total_ns > usec_thresh * 1000)
		    req.tv_nsec = usec_thresh * 1000;
		else
		    req.tv_nsec = total_ns;

		goto again;
	    }
	    else {
		if (outcome)
		    *outcome = POLL_NOTHING;
		/* Assume it is running!  Is this right? */
		return TSTATUS_RUNNING;
	    }
	}
    }
    else if (target_lookup_thread(target,tid)) {
	if (outcome)
	    *outcome = POLL_SUCCESS;
	if (pstatus)
	    *pstatus = status;

	/*
	 * Ok, handle whatever happened.  If we can't handle it, pass
	 * control to the user, just like monitor() would.
	 */
	retval = linux_userproc_handle_internal(target,tid,status,NULL);

	if (THREAD_SPECIFIC_STATUS(retval)) {
	    vwarn("unhandled thread-specific status %d!\n",retval);
	}

	return retval;
    }
    else {
	if (outcome)
	    *outcome = POLL_UNKNOWN;
	return TSTATUS_ERROR;
    }
}

static target_status_t linux_userproc_monitor(struct target *target) {
    int tid;
    int pstatus;
    int again = 0;
    thread_status_t retval;
    struct linux_userproc_state *lstate = \
	(struct linux_userproc_state *)target->state;

    vdebug(9,LA_TARGET,LF_LUP,"pid %d\n",lstate->pid);

    /* do the whole ptrace waitpid dance */

 again:
    vdebug(9,LA_TARGET,LF_LUP,"monitor pid %d (again %d)\n",lstate->pid,again);
    again = 0;
    tid = waitpid(-1,&pstatus,__WALL);
    if (tid < 0) {
	if (errno == ECHILD || errno == EINVAL)
	    return TSTATUS_ERROR;
	else
	    goto again;
    }

    retval = linux_userproc_handle_internal(target,tid,pstatus,&again);
    if (again)
	goto again;

    // xxx write!  then write generic target functions, clean up the
    // headers and makefile, and get it to compile.  then add debug code
    // and try to actually load regions and monitor a process!

    if (THREAD_SPECIFIC_STATUS(retval)) {
	vwarn("unhandled thread-specific status %d!\n",retval);
    }

    return retval;
}

static unsigned char *linux_userproc_read(struct target *target,
					  ADDR addr,
					  unsigned long length,
					  unsigned char *buf) {
    struct linux_userproc_state *lstate = \
	(struct linux_userproc_state *)target->state;

    vdebug(5,LA_TARGET,LF_LUP,"pid %d\n",lstate->pid);

    /* Don't bother checking if process is stopped!  We can't send it a
     * STOP without interfering with its execution, so we don't!
     */
    return target_generic_fd_read(lstate->memfd,addr,length,buf);
}

unsigned long linux_userproc_write(struct target *target,
				   ADDR addr,
				   unsigned long length,
				   unsigned char *buf) {
    struct linux_userproc_state *lstate;
    lstate = (struct linux_userproc_state *)(target->state);
#if __WORDSIZE == 64
    int64_t word;
#else
    int32_t word;
#endif
    struct memrange *range = NULL;;
    unsigned int i = 0;
    unsigned int j;

    vdebug(5,LA_TARGET,LF_LUP,"pid %d length %lu ",lstate->pid,length);
    for (j = 0; j < length && j < 16; ++j)
	vdebugc(5,LA_TARGET,LF_LUP,"%02hhx ",buf[j]);
    vdebugc(5,LA_TARGET,LF_LUP,"\n");

    target_find_memory_real(target,addr,NULL,NULL,&range);

    /* Don't bother checking if process is stopped!  We can't send it a
     * STOP without interfering with its execution, so we don't!
     */

    /*
     * We cannot just write to text/executable ranges via the memory
     * device.  BUT, if we can't resolve the address to a range, we just
     * try it anyway.
     */
    if (!range || range->prot_flags & PROT_WRITE) {
	return target_generic_fd_write(lstate->memfd,addr,length,buf);
    }

    /*
     * If we're writing to a write-protected range, we have to use
     * ptrace, word by word!  So if our write doesn't end on a word
     * boundary, first read the word containing the last byte we're
     * going to write, and fill it with our last byte.  Then write all
     * the preceding words, and finally the special last word.
     */
    if (length % (__WORDSIZE / 8)) {
	errno = 0;
	word = ptrace(PTRACE_PEEKTEXT,lstate->current_tid,
		      (addr + length) - (length % (__WORDSIZE / 8)),
		      NULL);
	if (errno) {
	    verror("ptrace(PEEKTEXT) last word: %s\n",strerror(errno));
	    return 0;
	}

	vdebug(9,LA_TARGET,LF_LUP,"last word was ");
	for (j = 0; j < __WORDSIZE / 8; ++j)
	    vdebugc(9,LA_TARGET,LF_LUP,"%02hhx ",*(((char *)&word) + j));
	vdebugc(9,LA_TARGET,LF_LUP,"\n");

	memcpy(&word,(buf + length) - (length % (__WORDSIZE / 8)),
	       length % (__WORDSIZE / 8));

	vdebug(9,LA_TARGET,LF_LUP,"new last word is ");
	for (j = 0; j < __WORDSIZE / 8; ++j)
	    vdebugc(9,LA_TARGET,LF_LUP,"%02hhx ",*(((char *)&word) + j));
	vdebugc(9,LA_TARGET,LF_LUP,"\n");
    }

    if (length / (__WORDSIZE / 8)) {
	for (i = 0; i < length; i += (__WORDSIZE / 8)) {
	    errno = 0;
	    if (ptrace(PTRACE_POKETEXT,lstate->current_tid,
#if __WORDSIZE == 64
		       addr + i,*(uint64_t *)(buf + i)) == -1) {
#else
		       addr + i,*(uint32_t *)(buf + i)) == -1) {
#endif
		verror("ptrace(POKETEXT): %s\n",strerror(errno));
		return 0;
	    }
	}
    }

    if (length % (__WORDSIZE / 8)) {
	errno = 0;
	if (ptrace(PTRACE_POKETEXT,lstate->current_tid,
		   (i) ? addr + i - (__WORDSIZE / 8) : addr,
		   word) == -1) {
	    verror("ptrace(POKETEXT) last word: %s\n",strerror(errno));
	    return 0;
	}
    }

    return length;
}

/*
 * The register mapping between x86_64 registers is defined by AMD in
 * http://www.x86-64.org/documentation/abi-0.99.pdf :
 *
 *
 * Figure 3.36: DWARF Register Number Mapping
 * Register Name Number Abbreviation
 * General Purpose Register RAX 0 %rax
 * General Purpose Register RDX 1 %rdx
 * General Purpose Register RCX 2 %rcx
 * General Purpose Register RBX 3 %rbx
 * General Purpose Register RSI 4 %rsi
 * General Purpose Register RDI 5 %rdi
 * Frame Pointer Register RBP 6 %rbp
 * Stack Pointer Register RSP 7 %rsp
 * Extended Integer Registers 8-15 8-15 %r8-%r15
 * Return Address RA 16
 * Vector Registers 0-7 17-24 %xmm0-%xmm7
 * Extended Vector Registers 8-15 25-32 %xmm8-%xmm15
 * Floating Point Registers 0-7 33-40 %st0-%st7
 * MMX Registers 0-7 41-48 %mm0-%mm7
 * Flag Register 49 %rFLAGS
 * Segment Register ES 50 %es
 * Segment Register CS 51 %cs
 * Segment Register SS 52 %ss
 * Segment Register DS 53 %ds
 * Segment Register FS 54 %fs
 * Segment Register GS 55 %gs
 * Reserved 56-57
 * FS Base address 58 %fs.base
 * GS Base address 59 %gs.base
 * Reserved 60-61
 * Task Register 62 %tr
 * LDT Register 63 %ldtr
 * 128-bit Media Control and Status 64 %mxcsr
 * x87 Control Word 65 %fcw
 * x87 Status Word 66 %fsw
 */

/* Register mapping.
 *
 * First, be aware that our host bit size (64/32) *does* influence which
 * registers we can access -- i.e., ptrace on 64-bit host tracing a
 * 32-bit process still gets the 64-bit registers -- but even then, we
 * want the 32-bit mapping for DWARF reg num to i386 reg.
 *
 * Second, the mappings below are defined in sys/reg.h, but since the
 * macros there are defined according to compile-time __WORDSIZE, we
 * don't use them, and just encode the indexes manually.
 * regmapNN[x] = y provides, for DWARF register x, an offset y into the
 * register structs returned by ptrace.
 *
 * XXX XXX XXX
 * If structs in sys/user.h change, ever, these mappings will be wrong.
 * It is unfortunate that sys/user.h conditions the macros on __WORDSIZE.
 */
#if __WORDSIZE == 64
#define X86_64_DWREG_COUNT 67
static int dreg_to_ptrace_idx64[X86_64_DWREG_COUNT] = { 
    10, 12, 11, 5, 13, 14, 4, 19,
    9, 8, 7, 6, 3, 2, 1, 0,
    16, 
    -1, -1, -1, -1, -1, -1, -1, -1, 
    -1, -1, -1, -1, -1, -1, -1, -1, 
    -1, -1, -1, -1, -1, -1, -1, -1, 
    -1, -1, -1, -1, -1, -1, -1, -1, 
    18, 24, 17, 20, 23, 25, 26, 
    -1, -1, 
    21, 22, 
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
    "fs_base", "gs_base", 
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
#else
#define X86_32_DWREG_COUNT 59
static int dreg_to_ptrace_idx32[X86_32_DWREG_COUNT] = { 
    6, 1, 2, 0, 15, 5, 3, 4,
    12, 14,
    -1, -1, -1, -1, -1, -1, 
    -1, -1, -1, -1, -1, -1, -1, -1, 
    -1, -1, -1, -1, -1, -1, -1, -1, 
    -1, -1, -1, -1, -1, -1, -1, -1, 
    -1, -1, -1, -1, -1, -1, -1, -1, 
    -1, -1, -1, -1, -1,
    /* These are "fake" DWARF regs. */
    13, 16, 7, 8, 9, 10,
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
#endif

/*
 * Register functions.
 */
char *linux_userproc_reg_name(struct target *target,REG reg) {
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

REG linux_userproc_dwregno_targetname(struct target *target,char *name) {
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

REG linux_userproc_dw_reg_no(struct target *target,common_reg_t reg) {
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

REGVAL linux_userproc_read_reg(struct target *target,tid_t tid,REG reg) {
    int ptrace_idx;
    struct target_thread *tthread;
    struct linux_userproc_thread_state *tstate;

    tthread = linux_userproc_load_thread(target,tid,0);
    if (!tthread) {
	verror("thread %"PRIiTID" does not exist; forgot to load?\n",tid);
	errno = EINVAL;
	return 0;
    }
    tstate = (struct linux_userproc_thread_state *)tthread->state;

    vdebug(5,LA_TARGET,LF_LUP,"reading reg %s\n",linux_userproc_reg_name(target,reg));

#if __WORDSIZE == 64
    if (reg >= X86_64_DWREG_COUNT) {
	verror("DWARF regnum %d does not have a 64-bit target mapping!\n",reg);
	errno = EINVAL;
	return 0;
    }
    ptrace_idx = dreg_to_ptrace_idx64[reg];
#else
    if (reg >= X86_32_DWREG_COUNT) {
	verror("DWARF regnum %d does not have a 32-bit target mapping!\n",reg);
	errno = EINVAL;
	return 0;
    }
    ptrace_idx = dreg_to_ptrace_idx32[reg];
#endif

#if __WORDSIZE == 64
    return (REGVAL)(((unsigned long *)&(tstate->regs))[ptrace_idx]);
#else 
    return (REGVAL)(((long int *)&(tstate->regs))[ptrace_idx]);
#endif
}

int linux_userproc_write_reg(struct target *target,tid_t tid,REG reg,
			     REGVAL value) {
    int ptrace_idx;
    struct target_thread *tthread;
    struct linux_userproc_thread_state *tstate;

    tthread = linux_userproc_load_thread(target,tid,0);
    if (!tthread) {
	verror("thread %"PRIiTID" does not exist; forgot to load?\n",tid);
	errno = EINVAL;
	return 0;
    }
    tstate = (struct linux_userproc_thread_state *)tthread->state;

    vdebug(5,LA_TARGET,LF_LUP,"writing reg %s 0x%"PRIxREGVAL"\n",
	   linux_userproc_reg_name(target,reg),value);

#if __WORDSIZE == 64
    if (reg >= X86_64_DWREG_COUNT) {
	verror("DWARF regnum %d does not have a 64-bit target mapping!\n",reg);
	errno = EINVAL;
	return -1;
    }
    ptrace_idx = dreg_to_ptrace_idx64[reg];
#else
    if (reg >= X86_32_DWREG_COUNT) {
	verror("DWARF regnum %d does not have a 32-bit target mapping!\n",reg);
	errno = EINVAL;
	return -1;
    }
    ptrace_idx = dreg_to_ptrace_idx32[reg];
#endif

#if __WORDSIZE == 64
    ((unsigned long *)&(tstate->regs))[ptrace_idx] = (unsigned long)value;
#else 
    ((long int*)&(tstate->regs))[ptrace_idx] = (long int)value;
#endif

    /* Flush the registers in target_resume! */
    tthread->dirty = 1;

    return 0;
}

GHashTable *linux_userproc_copy_registers(struct target *target,tid_t tid) {
    GHashTable *retval;
    int i;
    int count;
    REGVAL *rvp;
    int *dregs;
    char **dregnames;
    struct target_thread *tthread;
    struct linux_userproc_thread_state *tstate;

    tthread = linux_userproc_load_thread(target,tid,0);
    if (!tthread) {
	verror("thread %"PRIiTID" does not exist; forgot to load?\n",tid);
	errno = EINVAL;
	return 0;
    }
    tstate = (struct linux_userproc_thread_state *)tthread->state;

#if __WORDSIZE == 64
    count = X86_64_DWREG_COUNT;
    dregs = dreg_to_ptrace_idx64;
    dregnames = dreg_to_name64;
#else 
    count = X86_32_DWREG_COUNT;
    dregs = dreg_to_ptrace_idx32;
    dregnames = dreg_to_name32;
#endif

    retval = g_hash_table_new_full(g_str_hash,g_str_equal,NULL,free);

    for (i = 0; i < count; ++i) {
	if (dregs[i] == -1) 
	    continue;

	rvp = malloc(sizeof(*rvp));
	
#if __WORDSIZE == 64
	memcpy(rvp,&((unsigned long *)&(tstate->regs))[i],sizeof(unsigned long));
#else 
	memcpy(rvp,&((long int *)&(tstate->regs))[i],sizeof(long int));
#endif

	g_hash_table_insert(retval,dregnames[i],rvp);
    }

    return retval;
}

/*
 * Hardware breakpoint support.
 */
static REG linux_userproc_get_unused_debug_reg(struct target *target,tid_t tid) {
    REG retval = -1;
    struct target_thread *tthread;
    struct linux_userproc_thread_state *tstate;

    tthread = linux_userproc_load_thread(target,tid,0);
    if (!tthread) {
	verror("thread %"PRIiTID" does not exist; forgot to load?\n",tid);
	errno = EINVAL;
	return 0;
    }
    tstate = (struct linux_userproc_thread_state *)tthread->state;

    if (!tstate->dr[0]) { retval = 0; }
    else if (!tstate->dr[1]) { retval = 1; }
    else if (!tstate->dr[2]) { retval = 2; }
    else if (!tstate->dr[3]) { retval = 3; }

    vdebug(5,LA_TARGET,LF_LUP,"returning unused debug reg %d\n",retval);

    return retval;
}

#define VWORDBYTESIZE __WORDSIZE / 8

#if __WORDSIZE == 64
static int read_ptrace_debug_reg(int pid,unsigned long *array) {
#else
static int read_ptrace_debug_reg(int pid,int *array) {
#endif
    int i = 0;

    errno = 0;
    for ( ; i < 8; ++i) {
#if __WORDSIZE == 64
	array[i] = \
	    (unsigned long)ptrace(PTRACE_PEEKUSER,pid,
				  offsetof(struct user,u_debugreg[i]),NULL);
#else
	array[i] = \
	    (int)ptrace(PTRACE_PEEKUSER,pid,
			offsetof(struct user,u_debugreg[i]),NULL);
#endif
	if (errno) {
	    verror("ptrace(PEEKUSER): %s\n",strerror(errno));
	    return -1;
	}
    }

    return 0;
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

static int linux_userproc_set_hw_breakpoint(struct target *target,tid_t tid,
					    REG reg,ADDR addr) {
#if __WORDSIZE == 64
    unsigned long cdr;
#else
    int cdr = 0;
#endif
    struct target_thread *tthread;
    struct linux_userproc_thread_state *tstate;

    tthread = linux_userproc_load_thread(target,tid,0);
    if (!tthread) {
	verror("thread %"PRIiTID" does not exist; forgot to load?\n",tid);
	errno = EINVAL;
	return 0;
    }
    tstate = (struct linux_userproc_thread_state *)tthread->state;

    if (reg < 0 || reg > 3) {
	errno = EINVAL;
	return -1;
    }

    errno = 0;
    ptrace(PTRACE_PEEKUSER,tid,
	   offsetof(struct user,u_debugreg[reg]),(void *)&cdr);
    if (errno) {
	vwarn("could not read current val of debug reg %"PRIiREG": %s!\n",
	      reg,strerror(errno));
    }
    else if (cdr != 0) {
	vwarn("debug reg %"PRIiREG" already has an address, overwriting (0x%"PRIxADDR")!\n",
	      reg,cdr);
	//errno = EBUSY;
	//return -1;
    }

    /* Set the address, then the control bits. */
    tstate->dr[reg] = addr;

    /* Clear the status bits */
    tstate->dr[6] = 0; //&= ~(1 << reg);

    /* Set the local control bit, and unset the global bit. */
    tstate->dr[7] |= (1 << (reg * 2));
    tstate->dr[7] &= ~(1 << (reg * 2 + 1));
    /* Set the break to be on execution (00b). */
    tstate->dr[7] &= ~(3 << (16 + (reg * 4)));

    /*
    if (reg == 0) {
	dr7->dr0_l = 1;
	dr7->dr0_g = 0;
	dr7->dr0_break = PROBEPOINT_EXEC;
	dr7->dr0_len = 0;
    }
    */

    /* Now write these values! */
    errno = 0;
    ptrace(PTRACE_POKEUSER,tid,
	   offsetof(struct user,u_debugreg[reg]),(void *)(tstate->dr[reg]));
    if (errno) {
	verror("could not update debug reg %"PRIiREG", aborting: %s!\n",
	       reg,strerror(errno));
	goto errout;
    }

    ptrace(PTRACE_POKEUSER,tid,
	   offsetof(struct user,u_debugreg[6]),(void *)(tstate->dr[6]));
    if (errno) {
	verror("could not update status debug reg, aborting: %s!\n",
	       strerror(errno));
	goto errout;
    }
    ptrace(PTRACE_POKEUSER,tid,
	   offsetof(struct user,u_debugreg[7]),(void *)(tstate->dr[7]));
    if (errno) {
	verror("could not update control debug reg, aborting: %s!\n",
	       strerror(errno));
	goto errout;
    }

    return 0;

 errout:
    tstate->dr[reg] = 0;

    return -1;
}

 static int linux_userproc_set_hw_watchpoint(struct target *target,tid_t tid,
					    REG reg,ADDR addr,
					    probepoint_whence_t whence,
					    probepoint_watchsize_t watchsize) {
#if __WORDSIZE == 64
    unsigned long cdr;
#else
    int cdr;
#endif
    struct target_thread *tthread;
    struct linux_userproc_thread_state *tstate;

    tthread = linux_userproc_load_thread(target,tid,0);
    if (!tthread) {
	verror("thread %"PRIiTID" does not exist; forgot to load?\n",tid);
	errno = EINVAL;
	return 0;
    }
    tstate = (struct linux_userproc_thread_state *)tthread->state;

    if (reg < 0 || reg > 3) {
	errno = EINVAL;
	return -1;
    }

    errno = 0;
    ptrace(PTRACE_PEEKUSER,tid,
	   offsetof(struct user,u_debugreg[reg]),(void *)&cdr);
    if (errno) {
	vwarn("could not read current val of debug reg %"PRIiREG"!\n",reg);
    }
    else if (cdr != 0) {
	vwarn("debug reg %"PRIiREG" already has an address, overwriting (0x%"PRIxADDR")!\n",
	      reg,cdr);
	//errno = EBUSY;
	//return -1;
    }

    /* Set the address, then the control bits. */
    tstate->dr[reg] = addr;

    /* Clear the status bits */
    tstate->dr[6] = 0; //&= ~(1 << reg);

    /* Set the local control bit, and unset the global bit. */
    tstate->dr[7] |= (1 << (reg * 2));
    tstate->dr[7] &= ~(1 << (reg * 2 + 1));
    /* Set the break to be on whatever whence was) (clear the bits first!). */
    tstate->dr[7] &= ~(3 << (16 + (reg * 4)));
    tstate->dr[7] |= (whence << (16 + (reg * 4)));
    /* Set the watchsize to be whatever watchsize was). */
    tstate->dr[7] &= ~(3 << (18 + (reg * 4)));
    tstate->dr[7] |= (watchsize << (18 + (reg * 4)));

    /* Enable the LE bit to slow the processor! */
    tstate->dr[7] |= (1 << 8);
    /* Enable the GE bit to slow the processor! */
    /* tstate->dr[7] |= (1 << 9); */

    vdebug(4,LA_TARGET,LF_LUP,"dreg6 = 0x%"PRIxADDR"; dreg7 = 0x%"PRIxADDR", w = %d, ws = 0x%x\n",
	   tstate->dr[6],tstate->dr[7],whence,watchsize);

    /* Now write these values! */
    errno = 0;
    ptrace(PTRACE_POKEUSER,tid,
	   offsetof(struct user,u_debugreg[reg]),(void *)(tstate->dr[reg]));
    if (errno) {
	verror("could not update debug reg %"PRIiREG" (%p), aborting: %s!\n",reg,
	       (void *)(tstate->dr[reg]),strerror(errno));
	goto errout;
    }

    ptrace(PTRACE_POKEUSER,tid,
	   offsetof(struct user,u_debugreg[6]),(void *)(tstate->dr[6]));
    if (errno) {
	verror("could not update status debug reg (%p), aborting: %s!\n",
	       (void *)(tstate->dr[6]),strerror(errno));
	goto errout;
    }
    ptrace(PTRACE_POKEUSER,tid,
	   offsetof(struct user,u_debugreg[7]),(void *)(tstate->dr[7]));
    if (errno) {
	verror("could not update control debug reg (%p), aborting: %s!\n",
	       (void *)(tstate->dr[7]),strerror(errno));
	goto errout;
    }

    return 0;

 errout:
    tstate->dr[reg] = 0;

    return -1;
}

static int linux_userproc_unset_hw_breakpoint(struct target *target,tid_t tid,
					      REG reg) {
    struct target_thread *tthread;
    struct linux_userproc_thread_state *tstate;

    tthread = linux_userproc_load_thread(target,tid,0);
    if (!tthread) {
	verror("thread %"PRIiTID" does not exist; forgot to load?\n",tid);
	errno = EINVAL;
	return 0;
    }
    tstate = (struct linux_userproc_thread_state *)tthread->state;

    if (reg < 0 || reg > 3) {
	errno = EINVAL;
	return -1;
    }

    /* Set the address, then the control bits. */
    tstate->dr[reg] = 0;

    /* Clear the status bits */
    tstate->dr[6] = 0; //&= ~(1 << reg);

    /* Unset the local control bit, and unset the global bit. */
    tstate->dr[7] &= ~(3 << (reg * 2));

    errno = 0;
    /* Now write these values! */
    ptrace(PTRACE_POKEUSER,tid,
	   offsetof(struct user,u_debugreg[reg]),(void *)(tstate->dr[reg]));
    if (errno) {
	verror("could not update debug reg %"PRIiREG", aborting: %s!\n",
	       reg,strerror(errno));
	goto errout;
    }

    ptrace(PTRACE_POKEUSER,tid,
	   offsetof(struct user,u_debugreg[6]),(void *)(tstate->dr[6]));
    if (errno) {
	verror("could not update status debug reg, aborting: %s!\n",
	       strerror(errno));
	goto errout;
    }
    ptrace(PTRACE_POKEUSER,tid,
	   offsetof(struct user,u_debugreg[7]),(void *)(tstate->dr[7]));
    if (errno) {
	verror("could not update control debug reg,aborting: %s!\n",
	       strerror(errno));
	goto errout;
    }

    return 0;

 errout:
    return -1;
}

static int linux_userproc_unset_hw_watchpoint(struct target *target,tid_t tid,
					      REG reg) {
    /* It's the exact same thing, yay! */
    return linux_userproc_unset_hw_breakpoint(target,tid,reg);
}

int linux_userproc_disable_hw_breakpoints(struct target *target,tid_t tid) {
    ptrace(PTRACE_POKEUSER,tid,
	   offsetof(struct user,u_debugreg[7]),(void *)0);
    if (errno) {
	verror("could not update control debug reg, aborting: %s!\n",
	       strerror(errno));
	return -1;
    }
    return 0;
}

int linux_userproc_enable_hw_breakpoints(struct target *target,tid_t tid) {
    struct target_thread *tthread;
    struct linux_userproc_thread_state *tstate;

    tthread = linux_userproc_load_thread(target,tid,0);
    if (!tthread) {
	verror("thread %"PRIiTID" does not exist; forgot to load?\n",tid);
	errno = EINVAL;
	return 0;
    }
    tstate = (struct linux_userproc_thread_state *)tthread->state;
    
    ptrace(PTRACE_POKEUSER,tid,
	   offsetof(struct user,u_debugreg[7]),(void *)tstate->dr[7]);
    if (errno) {
	verror("could not update control debug reg, aborting: %s!\n",
	       strerror(errno));
	return -1;
    }
    return 0;
}

int linux_userproc_disable_hw_breakpoint(struct target *target,tid_t tid,
					 REG dreg) {
    struct target_thread *tthread;
    struct linux_userproc_thread_state *tstate;

    tthread = linux_userproc_load_thread(target,tid,0);
    if (!tthread) {
	verror("thread %"PRIiTID" does not exist; forgot to load?\n",tid);
	errno = EINVAL;
	return 0;
    }
    tstate = (struct linux_userproc_thread_state *)tthread->state;

    if (dreg < 0 || dreg > 3) {
	errno = EINVAL;
	return -1;
    }

    /* Clear the status bits */
    tstate->dr[6] = 0; //&= ~(1 << reg);

    /* Unset the local control bit, and unset the global bit. */
    tstate->dr[7] &= ~(3 << (dreg * 2));

    errno = 0;
    /* Now write these values! */
    ptrace(PTRACE_POKEUSER,tid,
	   offsetof(struct user,u_debugreg[6]),(void *)(tstate->dr[6]));
    if (errno) {
	verror("could not update status debug reg, aborting: %s!\n",
	       strerror(errno));
	goto errout;
    }
    ptrace(PTRACE_POKEUSER,tid,
	   offsetof(struct user,u_debugreg[7]),(void *)(tstate->dr[7]));
    if (errno) {
	verror("could not update control debug reg,aborting: %s!\n",
	       strerror(errno));
	goto errout;
    }

    return 0;

 errout:
    return -1;
}

int linux_userproc_enable_hw_breakpoint(struct target *target,tid_t tid,
					REG dreg) {
    struct target_thread *tthread;
    struct linux_userproc_thread_state *tstate;

    tthread = linux_userproc_load_thread(target,tid,0);
    if (!tthread) {
	verror("thread %"PRIiTID" does not exist; forgot to load?\n",tid);
	errno = EINVAL;
	return 0;
    }
    tstate = (struct linux_userproc_thread_state *)tthread->state;

    if (dreg < 0 || dreg > 3) {
	errno = EINVAL;
	return -1;
    }

    /* Clear the status bits */
    tstate->dr[6] = 0; //&= ~(1 << reg);

    /* Set the local control bit, and unset the global bit. */
    tstate->dr[7] |= (1 << (dreg * 2));
    tstate->dr[7] &= ~(1 << (dreg * 2 + 1));

    /* Now write these values! */
    errno = 0;
    ptrace(PTRACE_POKEUSER,tid,
	   offsetof(struct user,u_debugreg[6]),(void *)(tstate->dr[6]));
    if (errno) {
	verror("could not update status debug reg, aborting: %s!\n",
	       strerror(errno));
	goto errout;
    }
    ptrace(PTRACE_POKEUSER,tid,
	   offsetof(struct user,u_debugreg[7]),(void *)(tstate->dr[7]));
    if (errno) {
	verror("could not update control debug reg, aborting: %s!\n",
	       strerror(errno));
	goto errout;
    }

    return 0;

 errout:
    return -1;
}

int linux_userproc_notify_sw_breakpoint(struct target *target,ADDR addr,
					int notification) {
    return 0;
}

int linux_userproc_singlestep(struct target *target,tid_t tid,int isbp,
			      struct target *overlay) {
    struct target_thread *tthread;
    struct linux_userproc_thread_state *tstate;

    tthread = linux_userproc_load_thread(target,tid,0);
    if (!tthread) {
	verror("thread %"PRIiTID" does not exist; forgot to load?\n",tid);
	errno = EINVAL;
	return -1;
    }
    tstate = (struct linux_userproc_thread_state *)tthread->state;

    /* Clear the status bits */
    tstate->dr[6] = 0; //&= ~(1 << reg);

    /* Now write these values! */
    errno = 0;
    ptrace(PTRACE_POKEUSER,tid,
	   offsetof(struct user,u_debugreg[6]),(void *)(tstate->dr[6]));
    if (errno) {
	verror("could not update status debug reg, aborting: %s!\n",
	       strerror(errno));
	return -1;
    }

    /*
     * If this is a single step of an instruction for which a breakpoint
     * is set, set the RF flag.  Why?  Because then we don't have to
     * disable the hw breakpoint at this instruction if there is one.
     * The x86 clears it after one instruction anyway, so it's safe.
     *
     * Actually (and leaving this in so nobody else tries it), with
     * ptrace, we can't set the RF flag... it's masked out.
     */
    /*
    if (isbp) {
	flagsregno = linux_userproc_dw_reg_no(target,CREG_FLAGS);
	flags = linux_userproc_read_reg(target,tid,flagsregno);
	flags |= EF_RF;
	if (linux_userproc_write_reg(target,tid,flagsregno,flags)) 
	    verror("could not set RF flag to single step breakpoint'd instr!\n");
    }
    */

    if (linux_userproc_flush_thread(target,tid) < 0) {
	verror("could not flush thread; not single stepping!\n");
	return -1;
    }

    ptrace(PTRACE_SINGLESTEP,tid,NULL,NULL);
    if (errno) {
	verror("could not ptrace single step thread %"PRIiTID": %s\n",
	       tid,strerror(errno));
	return -1;
    }

    /*
     * PTRACE_SINGLESTEP runs the thread right away, so we have make
     * sure to do all the things _resume() would have done to it.
     */
    target_invalidate_thread(target,tthread);
    target_thread_set_status(tthread,THREAD_STATUS_RUNNING);

    return 0;
}

int linux_userproc_singlestep_end(struct target *target,tid_t tid,
				  struct target *overlay) {
    struct target_thread *tthread;
    struct linux_userproc_thread_state *tstate;

    tthread = linux_userproc_load_thread(target,tid,0);
    if (!tthread) {
	verror("thread %"PRIiTID" does not exist; forgot to load?\n",tid);
	errno = EINVAL;
	return 0;
    }
    tstate = (struct linux_userproc_thread_state *)tthread->state;

    /* Clear the status bits */
    tstate->dr[6] = 0; //&= ~(1 << reg);

    /* Now write these values! */
    errno = 0;
    ptrace(PTRACE_POKEUSER,tid,
	   offsetof(struct user,u_debugreg[6]),(void *)(tstate->dr[6]));
    if (errno) {
	verror("could not update status debug reg, aborting: %s!\n",
	       strerror(errno));
	return -1;
    }

    //target_thread_set_status(tthread,THREAD_STATUS_PAUSED);

    return 0;
}
