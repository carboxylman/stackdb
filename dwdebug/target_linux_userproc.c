#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>

#include "libdwdebug.h"

/*
 * Prototypes.
 */
struct target *linux_userproc_attach(int pid);
struct target *linux_userproc_launch(char *filename,char **argv,char **envp);

static int linux_userproc_init(struct target *target);
static int linux_userproc_attach_internal(struct target *target);
static int linux_userproc_detach(struct target *target);
static int linux_userproc_fini(struct target *target);
static int linux_userproc_loadregions(struct target *target);
static int linux_userproc_loaddebugfiles(struct target *target,
					 struct memregion *region);
static target_status_t linux_userproc_status(struct target *target);
static int linux_userproc_pause(struct target *target);
static int linux_userproc_resume(struct target *target);
static target_status_t linux_userproc_monitor(struct target *target);
static unsigned char *linux_userproc_read(struct target *target,
					  unsigned long long addr,
					  unsigned long length,
					  unsigned char *buf);
unsigned long linux_userproc_write(struct target *target,
				   unsigned long long addr,
				   unsigned long length,
				   unsigned char *buf);

/*
 * Set up the target interface for this library.
 */
struct target_ops linux_userspace_process_ops = {
    .init = linux_userproc_init,
    .fini = linux_userproc_fini,
    .attach = linux_userproc_attach_internal,
    .detach = linux_userproc_detach,
    .loadregions = linux_userproc_loadregions,
    .loaddebugfiles = linux_userproc_loaddebugfiles,
    .status = linux_userproc_status,
    .pause = linux_userproc_pause,
    .resume = linux_userproc_resume,
    .monitor = linux_userproc_monitor,
    .read = linux_userproc_read,
    .write = linux_userproc_write,
};

struct linux_userproc_state {
    int memfd;
    int attached;
    int32_t ptrace_opts;
    enum __ptrace_request ptrace_type;
    int last_signo;
};

/**
 ** These are the only user-visible functions.
 **/

/*
 * Attaches to @pid.  The caller does all of the normal ptrace
 * interaction; we just facilitate debuginfo-assisted data operations.
 */
struct target *linux_userproc_attach(int pid) {
    struct target *target;
    char buf[256];
    struct stat sbuf;
    FILE *debugfile;

    ldebug(5,"opening pid %d\n",pid);

    /* This is not strictly true; if they have the right capability they
     * can trace... but this is easier to check.
     */
    if (geteuid() != 0) {
	lerror("must be root!\n");
	errno = EPERM;
	return NULL;
    }

    snprintf(buf,256,"/proc/%d/stat",pid);
    if (stat(buf,&sbuf)) {
	lerror("stat %s: %s\n",buf,strerror(errno));
	errno = ESRCH;
	return NULL;
    }
    else {
	debugfile = fopen(buf,"r");
	if (!debugfile || !fgets(buf,256,debugfile)) {
	    lerror("fopen %s: %s\n",buf,strerror(errno));
	    fclose(debugfile);
	    return NULL;
	}
	if (strlen(buf) && buf[strlen(buf)-1] == '\n')
	    buf[strlen(buf)-1] = '\0';
	fclose(debugfile);
    }

    target = (struct target *)malloc(sizeof(*target));
    if (!target) {
	errno = ENOMEM;
	return NULL;
    }

    memset(target,0,sizeof(*target));

    target->type = "linux_userspace_process";
    target->live = 1;
    target->writeable = 1;
    target->ops = &linux_userspace_process_ops;

    target->space = addrspace_create("NULL",0,pid);

    ldebug(5,"opened pid %d\n",pid);

    return target;
}

struct target *linux_userproc_launch(char *filename,char **argv,char **envp) {
    return NULL;
}

/**
 ** These are all functions supporting the target API.
 **/

static int linux_userproc_init(struct target *target) {
    struct linux_userproc_state *lstate;

    ldebug(5,"pid %d\n",target->space->pid);

    lstate = (struct linux_userproc_state *)malloc(sizeof(*lstate));
    if (!lstate) {
	errno = ENOMEM;
	return 1;
    }
    memset(lstate,0,sizeof(*lstate));

    lstate->memfd = -1;
    lstate->attached = 0;
    lstate->ptrace_opts = 0;
    lstate->ptrace_type = PTRACE_SYSCALL;
    lstate->last_signo = -1;

    target->state = lstate;

    return 0;
}

static int linux_userproc_attach_internal(struct target *target) {
    struct linux_userproc_state *lstate;
    char buf[256];

    ldebug(5,"pid %d\n",target->space->pid);

    lstate = (struct linux_userproc_state *)(target->state);
    if (!lstate) {
	errno = EFAULT;
	return 1;
    }
    if (lstate->attached)
	return 0;

    if (ptrace(PTRACE_ATTACH,target->space->pid) < 0)
	return 1;

    snprintf(buf,256,"/proc/%d/mem",target->space->pid);
    if ((lstate->memfd = open(buf,O_LARGEFILE,O_RDWR)) < 0)
	return 1;

    return 0;
}

static int linux_userproc_detach(struct target *target) {
    struct linux_userproc_state *lstate;

    ldebug(5,"pid %d\n",target->space->pid);

    lstate = (struct linux_userproc_state *)(target->state);
    if (!lstate) {
	errno = EFAULT;
	return 1;
    }
    if (!lstate->attached)
	return 0;

    if (lstate->memfd > 0)
	close(lstate->memfd);

    if (ptrace(PTRACE_DETACH,target->space->pid) < 0)
	return 1;

    lstate->attached = 0;

    return 0;
}

static int linux_userproc_fini(struct target *target) {
    struct linux_userproc_state *lstate;

    ldebug(5,"pid %d\n",target->space->pid);

    lstate = (struct linux_userproc_state *)(target->state);

    if (lstate->attached) 
	linux_userproc_detach(target);

    free(target->state);

    return 0;
}

static int linux_userproc_loadregions(struct target *target) {
    char buf[PATH_MAX*2];
    char main_exe[PATH_MAX];
    FILE *f;
    char p[4];
    struct memregion *region;
    unsigned long long start,end,offset;
    region_type_t rtype;
    int rc;
    char *ret;

    ldebug(5,"pid %d\n",target->space->pid);

    /* first, find the pathname of our main exe */
    snprintf(buf,PATH_MAX*2,"/proc/%d/exe",target->space->pid);
    if ((rc = readlink(buf,main_exe,PATH_MAX - 1)) < 1)
	return -1;
    main_exe[rc] = '\0';

    snprintf(buf,PATH_MAX,"/proc/%d/maps",target->space->pid);
    f = fopen(buf,"r");
    if (!f)
	return 1;

    while (1) {
	errno = 0;
	if (!(ret = fgets(buf,PATH_MAX*2,f)) && !errno)
	    break;
	else if (!ret && errno) {
	    lerror("fgets: %s",strerror(errno));
	    break;
	}

	ldebug(8,"scanning mmap line %s",buf);

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

	    if (!(region = memregion_create(target->space,rtype,buf))) {
		goto err;
	    }

	    region->start = start;
	    region->end = end;
	    region->offset = offset;

	    if (p[0] == 'r')
		region->prot_flags |= PROT_READ;
	    if (p[1] == 'w')
		region->prot_flags |= PROT_WRITE;
	    if (p[2] == 'x')
		region->prot_flags |= PROT_EXEC;
	    if (p[3] == 's')
		region->prot_flags |= PROT_SHARED;

	    region = NULL;
	}
	/*
	else if (rc == EOF && !errno) {
	    break;
	else if (rc == EOF && errno) {
	    lerror("fscanf error: %s\n",strerror(errno));
	    goto err;
	}
	*/
	else if (rc > 0 && !errno) {
	    lwarn("weird content in /proc/pid/maps (%d)!\n",rc);
	}
	else if (rc > 0 && errno) {
	    lwarn("weird content in /proc/pid/maps (%d): %s!\n",rc,strerror(errno));
	}
    }

    fclose(f);
    return 0;

 err:
    fclose(f);
    // XXX cleanup the regions we added??
    return -1;
}

static int linux_userproc_loaddebugfiles(struct target *target,
					 struct memregion *region) {
    ldebug(5,"pid %d\n",target->space->pid);

    return 0;
}

static target_status_t linux_userproc_status(struct target *target) {
    char buf[256];
    FILE *statf;
    int pid;
    char pstate;
    target_status_t retval = STATUS_ERROR;
    int rc;

    ldebug(5,"pid %d\n",target->space->pid);

 again:
    snprintf(buf,256,"/proc/%d/stat",target->space->pid);
    statf = fopen(buf,"r");
    if (!statf)
	return STATUS_ERROR;

    if ((rc = fscanf(statf,"%d (%s) %c",&pid,buf,&pstate)) == 3) {
	if (pstate == 'R' || pstate == 'W')
	    retval = STATUS_RUNNING;
	else if (pstate == 'S' || pstate == 'D')
	    retval = STATUS_STOPPED;
	else if (pstate == 'Z')
	    retval = STATUS_DEAD;
	else if (pstate == 'T')
	    retval = STATUS_PAUSED;
	else 
	    retval = STATUS_UNKNOWN;
    }
    else if (rc < 0 && errno == EINTR) {
	fclose(statf);
	goto again;
    }

    return retval;
}

static int linux_userproc_pause(struct target *target) {
    /* pause/resume are invalid for ptrace processes; we only do I/O on
     * them when they trap naturally.
     */
    ldebug(5,"pid %d\n",target->space->pid);
    return 0;
}

static int linux_userproc_resume(struct target *target) {
    struct linux_userproc_state *lstate;

    lstate = (struct linux_userproc_state *)(target->state);

    ldebug(5,"pid %d\n",target->space->pid);

    int ptopts = PTRACE_O_TRACESYSGOOD;
    ptopts |= lstate->ptrace_opts;
    if (ptrace(PTRACE_SETOPTIONS,target->space->pid,NULL,ptopts) < 0) {
	lwarn("ptrace setoptions failed: %s\n",strerror(errno));
    }

    if (lstate->last_signo > -1) {
	if (ptrace(lstate->ptrace_type,target->space->pid,NULL,
		   lstate->last_signo) < 0) {
	    lerror("ptrace signo %d restart failed: %s\n",
		   lstate->last_signo,strerror(errno));
	    return 1;
	}
    }
    else {
	if (ptrace(lstate->ptrace_type,target->space->pid,NULL,NULL) < 0) {
	    lerror("ptrace restart failed: %s\n",strerror(errno));
	    return 1;
	}
    }

    return 0;
}

static target_status_t linux_userproc_monitor(struct target *target) {
    struct linux_userproc_state *lstate;
    pid_t pid;
    int pstatus;

    ldebug(5,"pid %d\n",target->space->pid);

    lstate = (struct linux_userproc_state *)(target->state);

    /* do the whole ptrace waitpid dance */

 again:
    pid = waitpid(target->space->pid,&pstatus,0);
    if (pid < 0) {
	if (errno == ECHILD || errno == EINVAL)
	    return STATUS_ERROR;
	else
	    goto again;
    }

    if (WIFSTOPPED(pstatus)) {
	/* Ok, this was a ptrace event; figure out which sig (or if it
	 * was a syscall), and redeliver the sig if it was a sig;
	 * otherwise, don't deliver a sig, and just continue the child,
	 * on resume.
	 */
	lstate->last_signo = WSTOPSIG(pstatus);
	if (lstate->last_signo & 0x80) {
	    ldebug(5,"target %d stopped with trap signo %d\n",
		   pid,lstate->last_signo);
	    lstate->last_signo = -1;
	}
	else {
	    ldebug(5,"target %d stopped with signo %d\n",
		   pid,lstate->last_signo);
	}
    }
    else if (WIFCONTINUED(pstatus)) 
	lstate->last_signo = -1;
    else if (WIFSIGNALED(pstatus) || WIFEXITED(pstatus)) {
	/* yikes, it was sigkill'd out from under us! */
	/* XXX: is error good enough?  The pid is gone; we should
	 * probably dump this target.
	 */
	return STATUS_DONE;
    }
    else {
	lwarn("unexpected child process status event: %08x; bailing!\n",
	      pstatus);
	return STATUS_ERROR;
    }

    // xxx write!  then write generic target functions, clean up the
    // headers and makefile, and get it to compile.  then add debug code
    // and try to actually load regions and monitor a process!

    return STATUS_PAUSED;
}

static unsigned char *linux_userproc_read(struct target *target,
					  unsigned long long addr,
					  unsigned long length,
					  unsigned char *buf) {
    struct linux_userproc_state *lstate;
    lstate = (struct linux_userproc_state *)(target->state);

    ldebug(5,"pid %d\n",target->space->pid);

    /* Don't bother checking if process is stopped!  We can't send it a
     * STOP without interfering with its execution, so we don't!
     */
    return target_generic_fd_read(lstate->memfd,addr,length,buf);
}

unsigned long linux_userproc_write(struct target *target,
				   unsigned long long addr,
				   unsigned long length,
				   unsigned char *buf) {
    struct linux_userproc_state *lstate;
    lstate = (struct linux_userproc_state *)(target->state);

    ldebug(5,"pid %d\n",target->space->pid);

    /* Don't bother checking if process is stopped!  We can't send it a
     * STOP without interfering with its execution, so we don't!
     */
    return target_generic_fd_write(lstate->memfd,addr,length,buf);
}
