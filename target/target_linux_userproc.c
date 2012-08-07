/*
 * Copyright (c) 2011, 2012 The University of Utah
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

#include <gelf.h>
#include <elf.h>
#include <libelf.h>

#include "dwdebug.h"

#include "target_api.h"
#include "target.h"
#include "target_linux_userproc.h"

/*
 * Prototypes.
 */
struct target *linux_userproc_attach(int pid,
				     struct debugfile_load_opts **dfoptlist);
struct target *linux_userproc_launch(char *filename,char **argv,char **envp,
				     int keepstdin,char *outfile,char *errfile,
				     struct debugfile_load_opts **dfoptlist);

static int linux_userproc_init(struct target *target);
static int linux_userproc_attach_internal(struct target *target);
static int linux_userproc_detach(struct target *target);
static int linux_userproc_fini(struct target *target);
static int linux_userproc_loadspaces(struct target *target);
static int linux_userproc_loadregions(struct target *target,
				      struct addrspace *space);
static int linux_userproc_loaddebugfiles(struct target *target,
					 struct addrspace *space,
					 struct memregion *region);
static target_status_t linux_userproc_status(struct target *target);
static int linux_userproc_pause(struct target *target);
static int linux_userproc_resume(struct target *target);
static target_status_t linux_userproc_monitor(struct target *target);
static target_status_t linux_userproc_poll(struct target *target,
					   target_poll_outcome_t *outcome,
					   int *pstatus);
static unsigned char *linux_userproc_read(struct target *target,
					  ADDR addr,
					  unsigned long length,
					  unsigned char *buf,
					  void *targetspecdata);
static unsigned long linux_userproc_write(struct target *target,
					  ADDR addr,
					  unsigned long length,
					  unsigned char *buf,
					  void *targetspecdata);
static char *linux_userproc_reg_name(struct target *target,REG reg);
static REGVAL linux_userproc_read_reg(struct target *target,REG reg);
static int linux_userproc_write_reg(struct target *target,REG reg,REGVAL value);
static int linux_userproc_flush_context(struct target *target);
static REG linux_userproc_get_unused_debug_reg(struct target *target);
static int linux_userproc_set_hw_breakpoint(struct target *target,
					    REG num,ADDR addr);
static int linux_userproc_set_hw_watchpoint(struct target *target,
					    REG num,ADDR addr,
					    probepoint_whence_t whence,
					    probepoint_watchsize_t watchsize);
static int linux_userproc_unset_hw_breakpoint(struct target *target,
					      REG num);
static int linux_userproc_unset_hw_watchpoint(struct target *target,
					      REG num);
int linux_userproc_disable_hw_breakpoints(struct target *target);
int linux_userproc_enable_hw_breakpoints(struct target *target);
int linux_userproc_notify_sw_breakpoint(struct target *target,ADDR addr,
					int notification);
int linux_userproc_singlestep(struct target *target);
int linux_userproc_singlestep_end(struct target *target);

/*
 * Set up the target interface for this library.
 */
struct target_ops linux_userspace_process_ops = {
    .init = linux_userproc_init,
    .fini = linux_userproc_fini,
    .attach = linux_userproc_attach_internal,
    .detach = linux_userproc_detach,
    .loadspaces = linux_userproc_loadspaces,
    .loadregions = linux_userproc_loadregions,
    .loaddebugfiles = linux_userproc_loaddebugfiles,
    .status = linux_userproc_status,
    .pause = linux_userproc_pause,
    .resume = linux_userproc_resume,
    .monitor = linux_userproc_monitor,
    .poll = linux_userproc_poll,
    .read = linux_userproc_read,
    .write = linux_userproc_write,
    .regname = linux_userproc_reg_name,
    .readreg = linux_userproc_read_reg,
    .writereg = linux_userproc_write_reg,
    .flush_context = linux_userproc_flush_context,
    .get_unused_debug_reg = linux_userproc_get_unused_debug_reg,
    .set_hw_breakpoint = linux_userproc_set_hw_breakpoint,
    .set_hw_watchpoint = linux_userproc_set_hw_watchpoint,
    .unset_hw_breakpoint = linux_userproc_unset_hw_breakpoint,
    .unset_hw_watchpoint = linux_userproc_unset_hw_watchpoint,
    .disable_hw_breakpoints = linux_userproc_disable_hw_breakpoints,
    .enable_hw_breakpoints = linux_userproc_enable_hw_breakpoints,
    .notify_sw_breakpoint = linux_userproc_notify_sw_breakpoint,
    .singlestep = linux_userproc_singlestep,
    .singlestep_end = linux_userproc_singlestep_end,
};

/*
 * If we ever want to support multithreaded targets, we'll have to track
 * fork/clone/vfork via ptrace too.  For now, we just want the bare
 * minimum so we can tell the user about it.
 */
#define INITIAL_PTRACE_OPTS \
    PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT

/**
 ** These are the only user-visible functions.
 **/

int linux_userproc_last_signo(struct target *target) {
    if (target)
	return ((struct linux_userproc_state *)target->state)->last_signo;
    return -1;
}

int linux_userproc_last_status(struct target *target) {
    if (target)
	return ((struct linux_userproc_state *)target->state)->last_status;
    return -1;
}

/*
 * Attaches to @pid.  The caller does all of the normal ptrace
 * interaction; we just facilitate debuginfo-assisted data operations.
 */
struct target *linux_userproc_attach(int pid,
				     struct debugfile_load_opts **dfoptlist) {
    struct linux_userproc_state *lstate;
    struct target *target;
    char buf[256];
    struct stat sbuf;
    FILE *debugfile;
    char pbuf[PATH_MAX*2];
    char main_exe[PATH_MAX];
    int fd;
    Elf *elf;
    int rc;
    int wordsize;
    int endian;

    vdebug(5,LOG_T_LUP,"opening pid %d\n",pid);

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
	debugfile = fopen(buf,"r");
	if (!debugfile || !fgets(buf,256,debugfile)) {
	    verror("fopen %s: %s\n",buf,strerror(errno));
	    fclose(debugfile);
	    return NULL;
	}
	if (strlen(buf) && buf[strlen(buf)-1] == '\n')
	    buf[strlen(buf)-1] = '\0';
	fclose(debugfile);
    }

    /* Discover the wordsize and endianness of the process, based off
     * its main executable.
     */
    /* first, find the pathname of our main exe */
    snprintf(pbuf,PATH_MAX*2,"/proc/%d/exe",pid);
    if ((rc = readlink(pbuf,main_exe,PATH_MAX - 1)) < 1)
	return NULL;
    main_exe[rc] = '\0';

    if ((fd = open(main_exe,0,O_RDONLY)) < 0) {
	verror("open %s: %s\n",main_exe,strerror(errno));
	return NULL;
    }

    target = target_create("linux_userspace_process",NULL,
			   &linux_userspace_process_ops,dfoptlist);
    if (!target) 
	return NULL;

    target->live = 1;
    target->writeable = 1;

    elf_version(EV_CURRENT);
    if (!(elf = elf_begin(fd,ELF_C_READ,NULL))) {
	verror("elf_begin %s: %s\n",main_exe,elf_errmsg(elf_errno()));
	target_free(target);
	return NULL;
    }

    if (elf_get_arch_info(elf,&wordsize,&endian)) {
	verror("could not get ELF arch info for %s\n",main_exe);
	target_free(target);
	elf_end(elf);
	return NULL;
    }
    target->wordsize = wordsize;
    target->endian = endian;
    vdebug(3,LOG_T_LUP,
	   "loaded ELF arch info for %s (wordsize=%d;endian=%s\n",
	   main_exe,target->wordsize,
	   (target->endian == DATA_LITTLE_ENDIAN ? "LSB" : "MSB"));

    /* Done with the elf stuff. */
    elf_end(elf);

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

    target->state = lstate;

    vdebug(5,LOG_T_LUP,"opened pid %d\n",pid);

    return target;
}

struct target *linux_userproc_launch(char *filename,char **argv,char **envp,
				     int keepstdin,char *outfile,char *errfile,
				     struct debugfile_load_opts **dfoptlist) {
    struct linux_userproc_state *lstate;
    struct target *target;
    int pid;
    int newfd;
    int dynamic = 0;
    Elf *elf = NULL;
    int wordsize;
    int endian;
    int fd = -1;
    int pstatus;

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

    /* Read the binary and see if it is a dynamic or statically-linked
     * executable.  If it's dynamic, we look for one sequence of
     * syscalls to infer when the the fully-linked program is in
     * memory.  If it's static, we look for another (much simpler)
     * sequence.
     */
    if ((fd = open(filename,0,O_RDONLY)) < 0) {
	verror("open %s: %s\n",filename,strerror(errno));
	return NULL;
    }

    target = target_create("linux_userspace_process",NULL,
			   &linux_userspace_process_ops,dfoptlist);
    if (!target) {
	errno = ENOMEM;
	return NULL;
    }

    target->live = 1;
    target->writeable = 1;

    /* We attach and can't detach, and also can't attach again when the
     * target API tells us to.
     */
    target->initdidattach = 1;

    /* Figure out some ELF stuff. */

    elf_version(EV_CURRENT);
    if (!(elf = elf_begin(fd,ELF_C_READ,NULL))) {
	verror("elf_begin %s: %s\n",filename,elf_errmsg(elf_errno()));
	goto errout;
    }

    if (elf_get_arch_info(elf,&wordsize,&endian)) {
	verror("could not get ELF arch info\n");
	goto errout;
    }
    target->wordsize = wordsize;
    target->endian = endian;
    vdebug(3,LOG_T_LUP,
	   "loaded ELF arch info (wordsize=%d;endian=%s)\n",
	   target->wordsize,
	   (target->endian == DATA_LITTLE_ENDIAN ? "LSB" : "MSB"));

    target->ptrsize = target->wordsize;

    dynamic = elf_is_dynamic_exe(elf);
    if (dynamic < 0) {
	verror("could not check if %s is static/dynamic exe; aborting!\n",
	       filename);
	goto errout;
    }
    else if (!dynamic)
	vdebug(2,LOG_T_LUP,"executable %s is static\n",filename);
    else 
	vdebug(2,LOG_T_LUP,"executable %s is dynamic\n",filename);

    /* Done with ELF stuff. */
    elf_end(elf);
    elf = NULL;
    close(fd);
    fd = -1;

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

    target->state = lstate;

    if ((pid = fork()) > 0) {
	lstate->pid = pid;
	
	/* Parent; wait for ptrace to signal us. */
	vdebug(3,LOG_T_LUP,"waiting for ptrace traceme pid %d to exec\n",pid);
     again:
	vdebug(9,LOG_T_LUP,"waitpid target %d\n",pid);
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
		vdebug(3,LOG_T_LUP,"ptrace traceme: pid %d has exec'd\n",pid);
		if (ptrace(PTRACE_GETREGS,pid,0,&uregs) < 0) {
		    vwarn("could not read EAX to deciper exec syscall!\n");
		}
		else {
#if __WORDSIZE == 64
		    orig_eax = uregs.orig_rax;
#else
		    orig_eax = uregs.orig_eax;
#endif
		    vdebug(5,LOG_T_LUP,"exec syscall: %lu\n",orig_eax);
		}
	    }
	    else {
		vdebug(5,LOG_T_LUP,"exec hunt sig (no trap)\n");
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
	if (!keepstdin) 
	    close(STDIN_FILENO);

	if (outfile && strcmp(outfile,"-") != 0) {
	    newfd = open(outfile,O_CREAT | O_APPEND | O_WRONLY,
			 S_IWUSR | S_IRUSR | S_IWGRP | S_IRGRP);
	    if (newfd < 0) {
		verror("open(%s): %s\n",outfile,strerror(errno));
		exit(-1);
	    }
	    dup2(newfd,STDOUT_FILENO);
	}
	else if (!outfile) {
	    newfd = open("/dev/null",O_WRONLY);
	    dup2(newfd,STDOUT_FILENO);
	}

	if (errfile && strcmp(errfile,"-") != 0) {
	    newfd = open(errfile,O_CREAT | O_APPEND | O_WRONLY,
			 S_IWUSR | S_IRUSR | S_IWGRP | S_IRGRP);
	    if (newfd < 0) {
		verror("open(%s): %s\n",errfile,strerror(errno));
		exit(-1);
	    }
	    dup2(newfd,STDERR_FILENO);
	}
	else if (!errfile) {
	    newfd = open("/dev/null",O_WRONLY);
	    dup2(newfd,STDERR_FILENO);
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
    vdebug(9,LOG_T_LUP,"waitpid target %d (syscall inference)\n",pid);
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

	    vdebug(5,LOG_T_LUP,"syscall: %ld (%ld)\n",orig_eax,syscall);

	    if (dynamic) {
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
		    vdebug(5,LOG_T_LUP,"found end of munmap to end dynamic load sequence!\n");
		    goto out;
		}
	    }
	    else {
		if (orig_eax == LUP_SC_PRCTL) {
		    vdebug(5,LOG_T_LUP,"found prctl to end static load sequence!\n");
		    goto out;
		}
		else if (orig_eax == LUP_SC_ARCH_PRCTL) {
		    vdebug(5,LOG_T_LUP,"found arch_prctl to end static load sequence!\n");
		    goto out;
		}
		else if (orig_eax == LUP_SC_SET_THREAD_AREA) {
		    vdebug(5,LOG_T_LUP,"found set_thread_area to end static load sequence!\n");
		    goto out;
		}
	    }
	}
	goto again2;
    }
    else if (WIFCONTINUED(pstatus)) {
	goto again2;
    }
    else if (WIFSIGNALED(pstatus) || WIFEXITED(pstatus)) {
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
    return target;

 errout:
    if (target)
	target_free(target);
    if (elf)
	elf_end(elf);
    if (fd > 1)
	close(fd);
    return NULL;
}

/**
 ** These are all functions supporting the target API.
 **/

int linux_userproc_pid(struct target *target) {
    if (target && target->state)
	return ((struct linux_userproc_state *)target->state)->pid;
    return -1;
}

static int linux_userproc_init(struct target *target) {
    struct linux_userproc_state *lstate = \
	(struct linux_userproc_state *)target->state;

    vdebug(5,LOG_T_LUP,"pid %d\n",linux_userproc_pid(target));

    lstate->memfd = -1;
    lstate->attached = 0;
    lstate->ptrace_opts_new = lstate->ptrace_opts = INITIAL_PTRACE_OPTS;
    lstate->ptrace_type = PTRACE_CONT;
    lstate->last_signo = -1;
    lstate->last_status = -1;

    return 0;
}

static int linux_userproc_attach_internal(struct target *target) {
    struct linux_userproc_state *lstate;
    char buf[256];
    int pstatus;
    int pid = linux_userproc_pid(target);

    vdebug(5,LOG_T_LUP,"pid %d\n",pid);

    lstate = (struct linux_userproc_state *)(target->state);
    if (!lstate) {
	errno = EFAULT;
	return 1;
    }
    if (lstate->attached)
	return 0;

    errno = 0;
    if (!target->initdidattach) {
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

    if (!target->initdidattach) {
	/*
	 * Wait for the child to get the PTRACE-sent SIGSTOP, then make sure
	 * we *don't* deliver that signal to it when the library user calls
	 * target_resume!
	 */

	vdebug(3,LOG_T_LUP,"waiting for ptrace attach to hit pid %d\n",pid);
    again:
	vdebug(5,LOG_T_LUP,"initial waitpid target %d\n",pid);
	if (waitpid(pid,&pstatus,0) < 0) {
	    if (errno == ECHILD || errno == EINVAL)
		return TSTATUS_ERROR;
	    else
		goto again;
	}
	vdebug(3,LOG_T_LUP,"ptrace attach has hit pid %d\n",pid);
    }

    /* Set the initial PTRACE opts. */
    errno = 0;
    if (ptrace(PTRACE_SETOPTIONS,pid,NULL,lstate->ptrace_opts) < 0) {
	vwarn("ptrace setoptions failed: %s\n",strerror(errno));
    }

    lstate->attached = 1;

    return 0;
}

static int linux_userproc_detach(struct target *target) {
    struct linux_userproc_state *lstate;

    vdebug(5,LOG_T_LUP,"pid %d\n",linux_userproc_pid(target));

    lstate = (struct linux_userproc_state *)(target->state);
    if (!lstate) {
	errno = EFAULT;
	return 1;
    }
    if (!lstate->attached)
	return 0;

    if (lstate->memfd > 0)
	close(lstate->memfd);

    /* Sleep the child first; otherwise we'll end up sending it a trace
       trap, which will kill it. */
    kill(linux_userproc_pid(target),SIGSTOP);

    errno = 0;
    if (ptrace(PTRACE_DETACH,linux_userproc_pid(target),NULL,NULL) < 0) {
	verror("ptrace detach %d failed: %s\n",linux_userproc_pid(target),
	       strerror(errno));
	kill(linux_userproc_pid(target),SIGCONT);
	return 1;
    }

    kill(linux_userproc_pid(target),SIGCONT);

    vdebug(3,LOG_T_LUP,"ptrace detach %d succeeded.\n",linux_userproc_pid(target));
    lstate->attached = 0;

    return 0;
}

static int linux_userproc_fini(struct target *target) {
    struct linux_userproc_state *lstate;

    vdebug(5,LOG_T_LUP,"pid %d\n",linux_userproc_pid(target));

    lstate = (struct linux_userproc_state *)(target->state);

    if (lstate->attached) 
	linux_userproc_detach(target);

    free(target->state);

    return 0;
}

static int linux_userproc_loadspaces(struct target *target) {
    struct addrspace *space = addrspace_create(target,"NULL",0,
					       linux_userproc_pid(target));
    RHOLD(space);

    space->target = target;

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

    vdebug(5,LOG_T_LUP,"pid %d\n",linux_userproc_pid(target));

    /* first, find the pathname of our main exe */
    snprintf(buf,PATH_MAX*2,"/proc/%d/exe",linux_userproc_pid(target));
    if ((rc = readlink(buf,main_exe,PATH_MAX - 1)) < 1)
	return -1;
    main_exe[rc] = '\0';

    snprintf(buf,PATH_MAX,"/proc/%d/maps",linux_userproc_pid(target));
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

	vdebug(8,LOG_T_LUP,"scanning mmap line %s",buf);

	rc = sscanf(buf,"%Lx-%Lx %c%c%c%c %Lx %*d:%*d %*d %s",&start,&end,
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
	    if (!(region = addrspace_find_region(space,buf))) {
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

static int DEBUGPATHLEN = 2;
static char *DEBUGPATH[] = { 
    "/usr/lib/debug",
    "/usr/local/lib/debug"
};

static int linux_userproc_loaddebugfiles(struct target *target,
					 struct addrspace *space,
					 struct memregion *region) {
    Elf *elf = NULL;
    int has_debuginfo = 0;
    char *buildid = NULL;
    char *debuglinkfile = NULL;
    uint32_t debuglinkfilecrc = 0;
    int fd = -1;
    int i;
    int len;
    int retval = 0;
    char pbuf[PATH_MAX];
    char *finalfile = NULL;
    char *regionfiledir = NULL;
    char *tmp;
    struct stat stbuf;
    struct debugfile *debugfile = NULL;
    struct debugfile_load_opts *opts = NULL;

    vdebug(5,LOG_T_LUP,"pid %d\n",linux_userproc_pid(target));

    if (!(region->type == REGION_TYPE_MAIN 
	  || region->type == REGION_TYPE_LIB)) {
	vdebug(4,LOG_T_LUP,"region %s is not MAIN nor LIB; skipping!\n",
	       region->name);
	return 0;
    }

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

    if ((fd = open(region->name,0,O_RDONLY)) < 0) {
	verror("open %s: %s\n",region->name,strerror(errno));
	return -1;
    }

    elf_version(EV_CURRENT);
    if (!(elf = elf_begin(fd,ELF_C_READ,NULL))) {
	verror("elf_begin %s: %s\n",region->name,elf_errmsg(elf_errno()));
	goto errout;
    }

    /* This should be in load_regions, but we've already got the ELF
     * binary open here... so just do it.
     */
    if (elf_get_base_addrs(elf,&region->base_virt_addr,&region->base_phys_addr)) {
	verror("elf_get_base_addrs %s failed!\n",region->name);
	goto errout;
    }

    if (elf_get_debuginfo_info(elf,&has_debuginfo,&buildid,&debuglinkfile,
			       &debuglinkfilecrc)) {
	verror("elf_get_debuginfo_info %s failed!\n",region->name);
	goto errout;
    }

    vdebug(5,LOG_T_LUP,"ELF info for region file %s:\n",region->name);
    vdebug(5,LOG_T_LUP,"    has_debuginfo=%d,buildid='",has_debuginfo);
    if (buildid) {
	len = (int)strlen(buildid);
	for (i = 0; i < len; ++i)
	    vdebugc(5,LOG_T_LUP,"%hhx",buildid[i]);
    }
    vdebugc(5,LOG_T_LUP,"'\n");
    vdebug(5,LOG_T_LUP,"    debuglinkfile=%s,debuglinkfilecrc=0x%x\n",
	   debuglinkfile,debuglinkfilecrc);

    if (has_debuginfo) {
	finalfile = region->name;
    }

    if (!finalfile && buildid) {
	for (i = 0; i < DEBUGPATHLEN; ++i) {
	    snprintf(pbuf,PATH_MAX,"%s/.build-id/%02hhx/%s.debug",
		     DEBUGPATH[i],*buildid,(char *)(buildid+1));
	    if (stat(pbuf,&stbuf) == 0) {
		finalfile = pbuf;
		break;
	    }
	}
    }

    if (!finalfile && debuglinkfile) {
	/* Find the containing dir path so we can use it in our search
	 * of the standard debug file dir infrastructure.
	 */
	regionfiledir = strdup(region->name);
	tmp = rindex(regionfiledir,'/');
	if (tmp)
	    *tmp = '\0';
	for (i = 0; i < DEBUGPATHLEN; ++i) {
	    snprintf(pbuf,PATH_MAX,"%s/%s/%s",
		     DEBUGPATH[i],regionfiledir,debuglinkfile);
	    if (stat(pbuf,&stbuf) == 0) {
		finalfile = pbuf;
		break;
	    }
	}
    }

    if (!finalfile) {
	verror("could not find any debuginfo sources from ELF file %s!\n",
	       region->name);
	goto errout;
    }
    else if (!(opts = \
	       target_get_debugfile_load_opts(target,region,finalfile,
					      region->type == REGION_TYPE_MAIN ? \
					      DEBUGFILE_TYPE_MAIN :	\
					      DEBUGFILE_TYPE_SHAREDLIB))
	     && errno) {
	vdebug(2,LOG_D_DFILE | LOG_T_TARGET | LOG_T_LUP,
	       "opts prohibit loading of debugfile for region %s\n",
	       region->name);
	/* "Success", fall out. */
    }
    else if ((debugfile = \
	      target_reuse_debugfile(target,region,finalfile,
				     region->type == REGION_TYPE_MAIN ? \
				     DEBUGFILE_TYPE_MAIN :		\
				     DEBUGFILE_TYPE_SHAREDLIB))) {
	vdebug(2,LOG_D_DFILE | LOG_T_TARGET | LOG_T_LUP,
	       "reusing debugfile %s for region %s\n",
	       debugfile->idstr,region->name);
	/* Success, just fall out. */
    }
    else {
	/*
	 * Need to create a new debugfile.  But first, we try to
	 * populate the "debugfile's" ELF symtab/strtab using the ELF
	 * binary, not debuginfo.  We want the internal ELF symbols, and
	 * some distros put those in the debuginfo file; some put them
	 * in the actual executable/lib.  So we check the actual binary
	 * first.
	 */
	debugfile = target_create_debugfile(target,finalfile,
					    region->type == REGION_TYPE_MAIN ? \
					    DEBUGFILE_TYPE_MAIN :	\
					    DEBUGFILE_TYPE_SHAREDLIB);
	if (!debugfile)
	    goto errout;

	if (elf_load_symtab(elf,region->name,debugfile))
	    vwarn("could not load ELF symtab into debugfile %s\n",
		  debugfile->idstr);

	if (target_load_and_associate_debugfile(target,region,debugfile,opts)) 
	    goto errout;
    }

    /* Success!  Skip past errout. */
    retval = 0;
    goto out;

 errout:
    retval = -1;

 out:
    if (elf)
	elf_end(elf);
    if (fd > -1)
	close(fd);
    if (regionfiledir) 
	free(regionfiledir);
    if (buildid)
	free(buildid);
    if (debuglinkfile)
	free(debuglinkfile);

    return retval;
}

static target_status_t linux_userproc_status(struct target *target) {
    char buf[256];
    FILE *statf;
    int pid = linux_userproc_pid(target);
    char pstate;
    target_status_t retval = TSTATUS_ERROR;
    int rc;

    vdebug(5,LOG_T_LUP,"pid %d\n",pid);

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

    vdebug(3,LOG_T_LUP,"pid %d status %d\n",linux_userproc_pid(target),retval);

    fclose(statf);
    return retval;
}

static int linux_userproc_pause(struct target *target) {
    int pid = linux_userproc_pid(target);
    target_status_t status;
    int pstatus;
    
    vdebug(5,LOG_T_LUP,"pid %d\n",linux_userproc_pid(target));

    /*
     * We send a stop to the traced pid, and wait until it is delivered
     * to us!  We do not save it for redelivery to the child!
     *
     * Only do this if the target is not currently paused, because it
     * might need to be restarted with whatever last_signo state it had
     * previously been paused with.
     */
    status = linux_userproc_status(target);
    if (status == TSTATUS_PAUSED) 
	return 0;

    if (kill(pid,SIGSTOP) < 0) {
	verror("kill(%d,SIGSTOP): %s\n",pid,strerror(errno));
	return -1;
    }

    vdebug(3,LOG_T_LUP,"waiting for pause SIGSTOP to hit pid %d\n",pid);
 again:
    if (waitpid(pid,&pstatus,0) < 0) {
	if (errno == ECHILD || errno == EINVAL)
	    return TSTATUS_ERROR;
	else
	    goto again;
    }
    vdebug(3,LOG_T_LUP,"pause SIGSTOP has hit pid %d\n",pid);

    return 0;
}

static int linux_userproc_resume(struct target *target) {
    struct linux_userproc_state *lstate;

    lstate = (struct linux_userproc_state *)(target->state);

    vdebug(9,LOG_T_LUP,"pid %d\n",linux_userproc_pid(target));

    /* First, flush back registers if they're dirty! */
    linux_userproc_flush_context(target);

    /* ALWAYS invalidate our cached copy of registers; flush_context may
     * not do this!
     */
    lstate->regs_loaded = 0;

    if (lstate->ptrace_opts != lstate->ptrace_opts_new) {
	lstate->ptrace_opts = lstate->ptrace_opts_new;
	errno = 0;
	if (ptrace(PTRACE_SETOPTIONS,linux_userproc_pid(target),NULL,
		   lstate->ptrace_opts) < 0) {
	    vwarn("ptrace setoptions failed: %s\n",strerror(errno));
	}
    }

    if (lstate->last_signo > -1) {
	if (ptrace(lstate->ptrace_type,linux_userproc_pid(target),NULL,
		   lstate->last_signo) < 0) {
	    verror("ptrace signo %d restart failed: %s\n",
		   lstate->last_signo,strerror(errno));
	    return 1;
	}
    }
    else {
	if (ptrace(lstate->ptrace_type,linux_userproc_pid(target),NULL,NULL) < 0) {
	    verror("ptrace restart failed: %s\n",strerror(errno));
	    return 1;
	}
    }

    vdebug(9,LOG_T_LUP,"ptrace restart %d succeeded\n",linux_userproc_pid(target));
    lstate->last_signo = -1;
    lstate->last_status = -1;

    return 0;
}

static target_status_t linux_userproc_handle_internal(struct target *target,
						      int pstatus,int *again) {
    struct linux_userproc_state *lstate;
    pid_t pid = linux_userproc_pid(target);
    REG dreg = -1;
    struct probepoint *dpp;
    REGVAL ipval;
#if __WORDSIZE == 64
    unsigned long cdr;
#else
    int cdr;
#endif

    lstate = (struct linux_userproc_state *)(target->state);

    if (WIFSTOPPED(pstatus)) {
	/* Ok, this was a ptrace event; figure out which sig (or if it
	 * was a syscall), and redeliver the sig if it was a sig;
	 * otherwise, don't deliver a sig, and just continue the child,
	 * on resume.
	 */
	lstate->last_status = lstate->last_signo = WSTOPSIG(pstatus);
	if (lstate->last_status == (SIGTRAP | 0x80)) {
	    vdebug(5,LOG_T_LUP,"target %d stopped with syscall trap signo %d\n",
		   pid,lstate->last_status);
	    lstate->last_signo = -1;
	}
	else if (lstate->last_status == SIGTRAP) {
	    /* Don't deliver debug traps! */
	    vdebug(5,LOG_T_LUP,"target %d stopped with trap signo %d\n",
		   pid,lstate->last_status);
	    lstate->last_signo = -1;

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

	    if (target->sstep_probepoint) {
		target->ss_handler(target,target->sstep_probepoint);
		goto out_again;
	    }
	    else {
		/* Check the hw debug status reg first */
		errno = 0;
		cdr = ptrace(PTRACE_PEEKUSER,pid,
			     offsetof(struct user,u_debugreg[6]),NULL);
		if (errno) {
		    vwarn("could not read current val of status debug reg; skipping to EIP check!\n");
		    errno = 0;
		    cdr = 0;
		}

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
		    ipval = ptrace(PTRACE_PEEKUSER,pid,
				   offsetof(struct user,u_debugreg[dreg]),NULL );
		    if (errno) {
			verror("could not read current val of debug reg %d after up status!\n",dreg);
			return TSTATUS_ERROR;
		    }

		    vdebug(4,LOG_T_LUP,
			   "found hw break (status) in dreg %d on 0x%"PRIxADDR"\n",
			   dreg,ipval);
		}
		else {
		    ipval = linux_userproc_read_reg(target,target->ipregno);
		    if (errno) {
			verror("could not read EIP while finding probepoint: %s\n",
			       strerror(errno));
			return TSTATUS_ERROR;
		    }

		    if (lstate->dr[0] == (ptrace_reg_t)ipval)
			dreg = 0;
		    else if (lstate->dr[1] == (ptrace_reg_t)ipval)
			dreg = 1;
		    else if (lstate->dr[2] == (ptrace_reg_t)ipval)
			dreg = 2;
		    else if (lstate->dr[3] == (ptrace_reg_t)ipval)
			dreg = 3;

		    vdebug(4,LOG_T_LUP,
			   "found hw break (eip) in dreg %d on 0x%"PRIxADDR"\n",
			   dreg,ipval);
		}

		if (dreg > -1) {
		    /* Found HW breakpoint! */
		    /* Clear the status bits right now. */
		    errno = 0;
		    if (ptrace(PTRACE_POKEUSER,linux_userproc_pid(target),
			       offsetof(struct user,u_debugreg[6]),0)) {
			verror("could not clear status debug reg, continuing"
			       " anyway: %s!\n",strerror(errno));
			errno = 0;
		    }
		    else {
			vdebug(5,LOG_T_LUP,"cleared status debug reg 6\n",pid);
		    }

		    dpp = (struct probepoint *)g_hash_table_lookup(target->probepoints,
								   (gpointer)ipval);

		    if (!dpp) {
			verror("found hw breakpoint with no probe!\n");
			return TSTATUS_ERROR;
		    }

		    target->bp_handler(target,dpp);
		    goto out_again;
		}
		else if ((dpp = (struct probepoint *) \
			  g_hash_table_lookup(target->probepoints,
					      (gpointer)(ipval - target->breakpoint_instrs_len)))) {
		    target->bp_handler(target,dpp);
		    goto out_again;
		}
		else {
		    vwarn("could not find hardware bp and not sstep'ing;"
			  " letting user handle fault at 0x%"PRIxADDR"!\n",
			  ipval);
		}
	    }
	}
	else {
	    vdebug(5,LOG_T_LUP,"target %d stopped with signo %d\n",
		   pid,lstate->last_status);
	}

	return TSTATUS_PAUSED;
    }
    else if (WIFCONTINUED(pstatus)) {
	lstate->last_signo = -1;
	lstate->last_status = -1;
	goto out_again;
    }
    else if (WIFSIGNALED(pstatus) || WIFEXITED(pstatus)) {
	/* yikes, it was sigkill'd out from under us! */
	/* XXX: is error good enough?  The pid is gone; we should
	 * probably dump this target.
	 */
	return TSTATUS_DONE;
    }
    else {
	vwarn("unexpected child process status event: %08x; bailing!\n",
	      pstatus);
	return TSTATUS_ERROR;
    }

    return TSTATUS_ERROR;

 out_again:
    if (again)
	*again = 1;
    return TSTATUS_RUNNING;
}

static target_status_t linux_userproc_poll(struct target *target,
					   target_poll_outcome_t *outcome,
					   int *pstatus) {
    pid_t pid = linux_userproc_pid(target);
    int status;
    target_status_t retval;

    vdebug(9,LOG_T_LUP,"waitpid target %d\n",pid);
    pid = waitpid(pid,&status,WNOHANG);
    if (pid < 0) {
	/* We always do this on error; these two errnos are the only
	 * ones we should see, though.
	 */
	if (1 || errno == ECHILD || errno == EINVAL) {
	    if (outcome)
		*outcome = POLL_ERROR;
	    return TSTATUS_ERROR;
	}
    }
    else if (pid == 0) {
	if (outcome)
	    *outcome = POLL_NOTHING;
	/* Assume it is running!  Is this right? */
	return TSTATUS_RUNNING;
    }
    else if (pid == linux_userproc_pid(target)) {
	if (outcome)
	    *outcome = POLL_SUCCESS;
	if (pstatus)
	    *pstatus = status;

	/*
	 * Ok, handle whatever happened.  If we can't handle it, pass
	 * control to the user, just like monitor() would.
	 */
	retval = linux_userproc_handle_internal(target,status,NULL);

	return retval;
    }
    else {
	if (outcome)
	    *outcome = POLL_UNKNOWN;
	return TSTATUS_ERROR;
    }
}

static target_status_t linux_userproc_monitor(struct target *target) {
    pid_t pid = linux_userproc_pid(target);
    int pstatus;
    int again;
    target_status_t retval;

    vdebug(9,LOG_T_LUP,"pid %d\n",linux_userproc_pid(target));

    /* do the whole ptrace waitpid dance */

 again:
    again = 0;
    vdebug(9,LOG_T_LUP,"waitpid target %d\n",pid);
    pid = waitpid(pid,&pstatus,0);
    if (pid < 0) {
	if (errno == ECHILD || errno == EINVAL)
	    return TSTATUS_ERROR;
	else
	    goto again;
    }

    retval = linux_userproc_handle_internal(target,pstatus,&again);
    if (again)
	goto again;

    // xxx write!  then write generic target functions, clean up the
    // headers and makefile, and get it to compile.  then add debug code
    // and try to actually load regions and monitor a process!

    return retval;
}

static unsigned char *linux_userproc_read(struct target *target,
					  ADDR addr,
					  unsigned long length,
					  unsigned char *buf,
					  void *targetspecdata) {
    struct linux_userproc_state *lstate;
    lstate = (struct linux_userproc_state *)(target->state);

    vdebug(5,LOG_T_LUP,"pid %d\n",linux_userproc_pid(target));

    /* Don't bother checking if process is stopped!  We can't send it a
     * STOP without interfering with its execution, so we don't!
     */
    return target_generic_fd_read(lstate->memfd,addr,length,buf);
}

unsigned long linux_userproc_write(struct target *target,
				   ADDR addr,
				   unsigned long length,
				   unsigned char *buf,
				   void *targetspecdata) {
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

    vdebug(5,LOG_T_LUP,"pid %d length %lu ",linux_userproc_pid(target),length);
    for (j = 0; j < length && j < 16; ++j)
	vdebugc(5,LOG_T_LUP,"%02hhx ",buf[j]);
    vdebugc(5,LOG_T_LUP,"\n");

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
	word = ptrace(PTRACE_PEEKTEXT,linux_userproc_pid(target),
		      (addr + length) - (length % (__WORDSIZE / 8)),
		      NULL);
	if (errno) {
	    verror("ptrace(PEEKTEXT) last word: %s\n",strerror(errno));
	    return 0;
	}

	vdebug(9,LOG_T_LUP,"last word was ");
	for (j = 0; j < __WORDSIZE / 8; ++j)
	    vdebugc(9,LOG_T_LUP,"%02hhx ",*(((char *)&word) + j));
	vdebugc(9,LOG_T_LUP,"\n");

	memcpy(&word,(buf + length) - (length % (__WORDSIZE / 8)),
	       length % (__WORDSIZE / 8));

	vdebug(9,LOG_T_LUP,"new last word is ");
	for (j = 0; j < __WORDSIZE / 8; ++j)
	    vdebugc(9,LOG_T_LUP,"%02hhx ",*(((char *)&word) + j));
	vdebugc(9,LOG_T_LUP,"\n");
    }

    if (length / (__WORDSIZE / 8)) {
	for (i = 0; i < length; i += (__WORDSIZE / 8)) {
	    errno = 0;
	    if (ptrace(PTRACE_POKETEXT,linux_userproc_pid(target),
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
	if (ptrace(PTRACE_POKETEXT,linux_userproc_pid(target),
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

#define X86_32_DWREG_COUNT 10
static int dreg_to_ptrace_idx32[X86_32_DWREG_COUNT] = { 
    6, 1, 2, 0, 15, 5, 3, 4,
    12, 14,
};
static char *dreg_to_name32[X86_32_DWREG_COUNT] = { 
    "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
    "eip", "eflags",
};

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

REGVAL linux_userproc_read_reg(struct target *target,REG reg) {
    int ptrace_idx;
    struct linux_userproc_state *lstate;

    lstate = (struct linux_userproc_state *)(target->state);

    vdebug(5,LOG_T_LUP,"reading reg %s\n",linux_userproc_reg_name(target,reg));

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

    /* Don't bother checking if process is stopped! */
    if (!lstate->regs_loaded) {
	errno = 0;
	if (ptrace(PTRACE_GETREGS,linux_userproc_pid(target),
		   NULL,&(lstate->regs)) == -1) {
	    verror("ptrace(GETREGS): %s\n",strerror(errno));
	    return 0;
	}
	lstate->regs_loaded = 1;
	lstate->regs_dirty = 0;
    }

    errno = 0;
#if __WORDSIZE == 64
    return (REGVAL)(((unsigned long *)&(lstate->regs))[ptrace_idx]);
#else 
    return (REGVAL)(((long int *)&(lstate->regs))[ptrace_idx]);
#endif
}

int linux_userproc_write_reg(struct target *target,REG reg,REGVAL value) {
    int ptrace_idx;
    struct linux_userproc_state *lstate;

    lstate = (struct linux_userproc_state *)(target->state);

    vdebug(5,LOG_T_LUP,"writing reg %s 0x%"PRIxREGVAL"\n",
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

    /* Don't bother checking if process is stopped! */
    if (!lstate->regs_loaded) {
	errno = 0;
	if (ptrace(PTRACE_GETREGS,linux_userproc_pid(target),
		   NULL,&(lstate->regs)) == -1) {
	    verror("ptrace(GETREGS): %s\n",strerror(errno));
	    return 0;
	}
	lstate->regs_loaded = 1;
	lstate->regs_dirty = 0;
    }

#if __WORDSIZE == 64
    ((unsigned long *)&(lstate->regs))[ptrace_idx] = (unsigned long)value;
#else 
    ((long int*)&(lstate->regs))[ptrace_idx] = (long int)value;
#endif

    /* Flush the registers in target_resume! */
    lstate->regs_dirty = 1;

    return 0;
}

static int linux_userproc_flush_context(struct target *target) {
    struct linux_userproc_state *lstate;
    lstate = (struct linux_userproc_state *)(target->state);

    vdebug(9,LOG_T_LUP,"pid %d\n",linux_userproc_pid(target));

    /* Flush back registers if they're dirty! */
    if (lstate->regs_dirty) {
	errno = 0;
	if (ptrace(PTRACE_SETREGS,linux_userproc_pid(target),
		   NULL,&(lstate->regs)) == -1) {
	    verror("ptrace(SETREGS): %s\n",strerror(errno));
	    return -1;
	}
	/* Invalidate our cache. */
	lstate->regs_dirty = 0;
	lstate->regs_loaded = 0;
    }

    return 0;
}

/*
 * Hardware breakpoint support.
 */
static REG linux_userproc_get_unused_debug_reg(struct target *target) {
    struct linux_userproc_state *lstate;
    REG retval = -1;

    lstate = (struct linux_userproc_state *)(target->state);

    if (!lstate->dr[0]) { retval = 0; }
    else if (!lstate->dr[1]) { retval = 1; }
    else if (!lstate->dr[2]) { retval = 2; }
    else if (!lstate->dr[3]) { retval = 3; }

    vdebug(5,LOG_T_LUP,"returning unused debug reg %d\n",retval);

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

struct x86_dr_format {
    int dr0_l:1;
    int dr0_g:1;
    int dr1_l:1;
    int dr1_g:1;
    int dr2_l:1;
    int dr2_g:1;
    int dr3_l:1;
    int dr3_g:1;
    int exact_l:1;
    int exact_g:1;
    int reserved:6;
    probepoint_whence_t dr0_break:2;
    probepoint_watchsize_t dr0_len:2;
    probepoint_whence_t dr1_break:2;
    probepoint_watchsize_t dr1_len:2;
    probepoint_whence_t dr2_break:2;
    probepoint_watchsize_t dr2_len:2;
    probepoint_whence_t dr3_break:2;
    probepoint_watchsize_t dr3_len:2;
};

static int linux_userproc_set_hw_breakpoint(struct target *target,
					    REG reg,ADDR addr) {
    struct linux_userproc_state *lstate;
    int pid;
#if __WORDSIZE == 64
    unsigned long cdr;
#else
    int cdr;
#endif

    if (reg < 0 || reg > 3) {
	errno = EINVAL;
	return -1;
    }

    lstate = (struct linux_userproc_state *)(target->state);
    pid = linux_userproc_pid(target);

    errno = 0;
    ptrace(PTRACE_PEEKUSER,pid,
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
    lstate->dr[reg] = addr;

    /* Clear the status bits */
    lstate->dr[6] = 0; //&= ~(1 << reg);

    /* Set the local control bit, and unset the global bit. */
    lstate->dr[7] |= (1 << (reg * 2));
    lstate->dr[7] &= ~(1 << (reg * 2 + 1));
    /* Set the break to be on execution (00b). */
    lstate->dr[7] &= ~(3 << (16 + (reg * 4)));

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
    ptrace(PTRACE_POKEUSER,pid,
	   offsetof(struct user,u_debugreg[reg]),(void *)(lstate->dr[reg]));
    if (errno) {
	verror("could not update debug reg %"PRIiREG", aborting: %s!\n",
	       reg,strerror(errno));
	goto errout;
    }

    ptrace(PTRACE_POKEUSER,linux_userproc_pid(target),
	   offsetof(struct user,u_debugreg[6]),(void *)(lstate->dr[6]));
    if (errno) {
	verror("could not update status debug reg, aborting: %s!\n",
	       strerror(errno));
	goto errout;
    }
    ptrace(PTRACE_POKEUSER,linux_userproc_pid(target),
	   offsetof(struct user,u_debugreg[7]),(void *)(lstate->dr[7]));
    if (errno) {
	verror("could not update control debug reg, aborting: %s!\n",
	       strerror(errno));
	goto errout;
    }

    return 0;

 errout:
    lstate->dr[reg] = 0;

    return -1;
}

static int linux_userproc_set_hw_watchpoint(struct target *target,
					    REG reg,ADDR addr,
					    probepoint_whence_t whence,
					    probepoint_watchsize_t watchsize) {
    struct linux_userproc_state *lstate;
    int pid;
#if __WORDSIZE == 64
    unsigned long cdr;
#else
    int cdr;
#endif

    if (reg < 0 || reg > 3) {
	errno = EINVAL;
	return -1;
    }

    lstate = (struct linux_userproc_state *)(target->state);
    pid = linux_userproc_pid(target);

    errno = 0;
    ptrace(PTRACE_PEEKUSER,pid,
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
    lstate->dr[reg] = addr;

    /* Clear the status bits */
    lstate->dr[6] = 0; //&= ~(1 << reg);

    /* Set the local control bit, and unset the global bit. */
    lstate->dr[7] |= (1 << (reg * 2));
    lstate->dr[7] &= ~(1 << (reg * 2 + 1));
    /* Set the break to be on whatever whence was) (clear the bits first!). */
    lstate->dr[7] &= ~(3 << (16 + (reg * 4)));
    lstate->dr[7] |= (whence << (16 + (reg * 4)));
    /* Set the watchsize to be whatever watchsize was). */
    lstate->dr[7] &= ~(3 << (18 + (reg * 4)));
    lstate->dr[7] |= (watchsize << (18 + (reg * 4)));

    /* Enable the LE bit to slow the processor! */
    lstate->dr[7] |= (1 << 8);
    /* Enable the GE bit to slow the processor! */
    /* lstate->dr[7] |= (1 << 9); */

    vdebug(4,LOG_T_LUP,"dreg6 = 0x%"PRIxADDR"; dreg7 = 0x%"PRIxADDR", w = %d, ws = 0x%x\n",
	   lstate->dr[6],lstate->dr[7],whence,watchsize);

    /* Now write these values! */
    errno = 0;
    ptrace(PTRACE_POKEUSER,pid,
	   offsetof(struct user,u_debugreg[reg]),(void *)(lstate->dr[reg]));
    if (errno) {
	verror("could not update debug reg %"PRIiREG" (%p), aborting: %s!\n",reg,
	       (void *)(lstate->dr[reg]),strerror(errno));
	goto errout;
    }

    ptrace(PTRACE_POKEUSER,linux_userproc_pid(target),
	   offsetof(struct user,u_debugreg[6]),(void *)(lstate->dr[6]));
    if (errno) {
	verror("could not update status debug reg (%p), aborting: %s!\n",
	       (void *)(lstate->dr[6]),strerror(errno));
	goto errout;
    }
    ptrace(PTRACE_POKEUSER,linux_userproc_pid(target),
	   offsetof(struct user,u_debugreg[7]),(void *)(lstate->dr[7]));
    if (errno) {
	verror("could not update control debug reg (%p), aborting: %s!\n",
	       (void *)(lstate->dr[7]),strerror(errno));
	goto errout;
    }

    return 0;

 errout:
    lstate->dr[reg] = 0;

    return -1;
}

static int linux_userproc_unset_hw_breakpoint(struct target *target,REG reg) {
    struct linux_userproc_state *lstate;
    int pid;

    if (reg < 0 || reg > 3) {
	errno = EINVAL;
	return -1;
    }

    lstate = (struct linux_userproc_state *)(target->state);
    pid = linux_userproc_pid(target);

    /* Set the address, then the control bits. */
    lstate->dr[reg] = 0;

    /* Clear the status bits */
    lstate->dr[6] = 0; //&= ~(1 << reg);

    /* Unset the local control bit, and unset the global bit. */
    lstate->dr[7] &= ~(3 << (reg * 2));

    errno = 0;
    /* Now write these values! */
    ptrace(PTRACE_POKEUSER,pid,
	   offsetof(struct user,u_debugreg[reg]),(void *)(lstate->dr[reg]));
    if (errno) {
	verror("could not update debug reg %"PRIiREG", aborting: %s!\n",
	       reg,strerror(errno));
	goto errout;
    }

    ptrace(PTRACE_POKEUSER,linux_userproc_pid(target),
	   offsetof(struct user,u_debugreg[6]),(void *)(lstate->dr[6]));
    if (errno) {
	verror("could not update status debug reg, aborting: %s!\n",
	       strerror(errno));
	goto errout;
    }
    ptrace(PTRACE_POKEUSER,linux_userproc_pid(target),
	   offsetof(struct user,u_debugreg[7]),(void *)(lstate->dr[7]));
    if (errno) {
	verror("could not update control debug reg,aborting: %s!\n",
	       strerror(errno));
	goto errout;
    }

    return 0;

 errout:
    return -1;
}

static int linux_userproc_unset_hw_watchpoint(struct target *target,REG reg) {
    /* It's the exact same thing, yay! */
    return linux_userproc_unset_hw_breakpoint(target,reg);
}

int linux_userproc_disable_hw_breakpoints(struct target *target) {
    ptrace(PTRACE_POKEUSER,linux_userproc_pid(target),
	   offsetof(struct user,u_debugreg[7]),(void *)0);
    if (errno) {
	verror("could not update control debug reg, aborting: %s!\n",
	       strerror(errno));
	return -1;
    }
    return 0;
}

int linux_userproc_enable_hw_breakpoints(struct target *target) {
    struct linux_userproc_state *lstate = \
	(struct linux_userproc_state *)(target->state);
    
    ptrace(PTRACE_POKEUSER,linux_userproc_pid(target),
	   offsetof(struct user,u_debugreg[7]),(void *)lstate->dr[7]);
    if (errno) {
	verror("could not update control debug reg, aborting: %s!\n",
	       strerror(errno));
	return -1;
    }
    return 0;
}

int linux_userproc_notify_sw_breakpoint(struct target *target,ADDR addr,
					int notification) {
    return 0;
}

int linux_userproc_singlestep(struct target *target) {
    if (target_flush_context(target) < 0) {
	verror("could not flush context; not single stepping!\n");
	return -1;
    }

    ptrace(PTRACE_SINGLESTEP,linux_userproc_pid(target),NULL,NULL);
    if (errno) {
	verror("could not ptrace single step: %s\n",strerror(errno));
	return -1;
    }
    return 0;
}

int linux_userproc_singlestep_end(struct target *target) {
    return 0;
}
