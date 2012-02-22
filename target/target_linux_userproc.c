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
 * Foundation, 51 Franklin St, Suite 500, Boston, MA 02110-1335, USA.
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

/*
 * Prototypes.
 */
struct target *linux_userproc_attach(int pid);
struct target *linux_userproc_launch(char *filename,char **argv,char **envp);

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
    .singlestep = linux_userproc_singlestep,
    .singlestep_end = linux_userproc_singlestep_end,
};
#if __WORDSIZE == 64
typedef unsigned long int ptrace_reg_t;
#else
typedef int ptrace_reg_t;
#endif

struct linux_userproc_state {
    int pid;
    int memfd;
    int attached;
    int32_t ptrace_opts;
    enum __ptrace_request ptrace_type;
    int last_signo;
    int syscall;

    /*
     * On the first register read on a paused domain, we read in this,
     * and if it gets dirty, we flush it on resume.  All other reg ops
     * are satisfied by just writing to this struct.
     */
    int regs_dirty:1,
	regs_loaded:1;
    struct user_regs_struct regs;

    /* XXX: can we debug a 32-bit target on a 64-bit host?  If yes, how 
     * we use this might have to change.
     */
    ptrace_reg_t dr[8];
};

/**
 ** These are the only user-visible functions.
 **/

int linux_userproc_last_signo(struct target *target) {
    if (target)
	return ((struct linux_userproc_state *)target->state)->last_signo;
    return -1;
}

int linux_userproc_stopped_by_syscall(struct target *target) {
    if (target)
	return ((struct linux_userproc_state *)target->state)->syscall;
    return 0;
}

/*
 * Attaches to @pid.  The caller does all of the normal ptrace
 * interaction; we just facilitate debuginfo-assisted data operations.
 */
struct target *linux_userproc_attach(int pid) {
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
    char *eident;

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

    elf_version(EV_CURRENT);
    if (!(elf = elf_begin(fd,ELF_C_READ,NULL))) {
	verror("elf_begin %s: %s\n",main_exe,elf_errmsg(elf_errno()));
	return NULL;
    }

    /* read the ident stuff to get wordsize and endianness info */
    if (!(eident = elf_getident(elf,NULL))) {
	verror("elf_getident %s: %s\n",main_exe,elf_errmsg(elf_errno()));
	elf_end(elf);
	return NULL;
    }

    target = target_create("linux_userspace_process",NULL,
			   &linux_userspace_process_ops);
    if (!target) {
	elf_end(elf);
	errno = ENOMEM;
	return NULL;
    }

    target->live = 1;
    target->writeable = 1;

    if ((uint8_t)eident[EI_CLASS] == ELFCLASS32) {
	target->wordsize = 4;
	vdebug(3,LOG_T_LUP,"32-bit %s\n",main_exe);
    }
    else if ((uint8_t)eident[EI_CLASS] == ELFCLASS64) {
	target->wordsize = 8;
	vdebug(3,LOG_T_LUP,"64-bit %s\n",main_exe);
    }
    else {
	verror("unknown elf class %d; not 32/64 bit!\n",
	       (uint8_t)eident[EI_CLASS]);
	free(target);
	elf_end(elf);
	return NULL;
    }
    target->ptrsize = target->wordsize;

    if ((uint8_t)eident[EI_DATA] == ELFDATA2LSB) {
	target->endian = DATA_LITTLE_ENDIAN;
	vdebug(3,LOG_T_LUP,"little endian %s\n",main_exe);
    }
    else if ((uint8_t)eident[EI_DATA] == ELFDATA2MSB) {
	target->endian = DATA_BIG_ENDIAN;
	vdebug(3,LOG_T_LUP,"big endian %s\n",main_exe);
    }
    else {
	verror("unknown elf data %d; not big/little endian!\n",
	       (uint8_t)eident[EI_DATA]);
	free(target);
	elf_end(elf);
	return NULL;
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
    *(char *)(target->ret_instrs) = 0xc3;
    target->ret_instrs_len = 1;
    target->ret_instr_count = 1;

    /* Done with the elf ident data. */
    elf_end(elf);

    lstate = (struct linux_userproc_state *)malloc(sizeof(*lstate));
    if (!lstate) {
	free(target);
	errno = ENOMEM;
	return NULL;
    }
    memset(lstate,0,sizeof(*lstate));

    lstate->pid = pid;

    target->state = lstate;

    vdebug(5,LOG_T_LUP,"opened pid %d\n",pid);

    return target;
}

struct target *linux_userproc_launch(char *filename,char **argv,char **envp) {
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
    lstate->ptrace_opts = 0;
    lstate->ptrace_type = PTRACE_SYSCALL;
    lstate->last_signo = -1;

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
    if (ptrace(PTRACE_ATTACH,pid,NULL,NULL) < 0) {
	verror("ptrace attach pid %d failed: %s\n",pid,strerror(errno));
	return 1;
    }

    snprintf(buf,256,"/proc/%d/mem",pid);
    if ((lstate->memfd = open(buf,O_LARGEFILE,O_RDWR)) < 0) {
	verror("open %s failed, detaching: %s!\n",buf,strerror(errno));
	ptrace(PTRACE_DETACH,pid,NULL,NULL);
	return 1;
    }

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
    Elf_Scn *scn;
    GElf_Shdr shdr_mem;
    GElf_Shdr *shdr;
    char *name;
    size_t shstrndx;
    int has_debuginfo = 0;
    char *buildid = NULL;
    char *debuglinkfile = NULL;
    uint32_t debuglinkfilecrc = 0;
    Elf_Data *edata;
    char *eident = NULL;
    int is64 = 0;
    Elf32_Nhdr *nthdr32;
    Elf64_Nhdr *nthdr64;
    char *ndata,*nend;
    int fd = -1;;
    int i;
    int len;
    int retval = 0;
    char pbuf[PATH_MAX];
    char *finalfile = NULL;
    char *regionfiledir = NULL;
    char *tmp;
    struct stat stbuf;

    vdebug(5,LOG_T_LUP,"pid %d\n",linux_userproc_pid(target));

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

    /* read the ident stuff to get ELF byte size */
    if (!(eident = elf_getident(elf,NULL))) {
	verror("elf_getident %s: %s\n",region->name,elf_errmsg(elf_errno()));
	goto errout;
    }

    if ((uint8_t)eident[EI_CLASS] == ELFCLASS32) {
	is64 = 0;
	vdebug(3,LOG_T_LUP,"32-bit %s\n",region->name);
    }
    else if ((uint8_t)eident[EI_CLASS] == ELFCLASS64) {
	is64 = 1;
    }
    else {
	verror("unknown elf class %d; not 32/64 bit!\n",
	       (uint8_t)eident[EI_CLASS]);
	goto errout;
    }

#if _INT_ELFUTILS_VERSION >= 152
    if (elf_getshdrstrndx(elf,&shstrndx) < 0) {
#else 
    if (elf_getshstrndx(elf,&shstrndx) < 0) {
#endif
	verror("cannot get section header string table index\n");
	goto errout;
    }

    scn = NULL;
    while ((scn = elf_nextscn(elf,scn)) != NULL) {
	shdr = gelf_getshdr(scn,&shdr_mem);

	if (shdr && shdr->sh_size > 0) {
	    name = elf_strptr(elf,shstrndx,shdr->sh_name);

	    if (strcmp(name,".debug_info") == 0) {
		vdebug(2,LOG_T_LUP,
		       "found %s section (%d) in region filename %s\n",
		       name,shdr->sh_size,region->name);
		has_debuginfo = 1;
		continue;
	    }
	    else if (!buildid && shdr->sh_type == SHT_NOTE) {
		vdebug(2,LOG_T_LUP,
		       "found %s note section (%d) in region filename %s\n",
		       name,shdr->sh_size,region->name);
		edata = elf_rawdata(scn,NULL);
		if (!edata) {
		    vwarn("cannot get data for valid section '%s': %s",
			  name,elf_errmsg(-1));
		    continue;
		}

		ndata = edata->d_buf;
		nend = ndata + edata->d_size;
		while (ndata < nend) {
		    if (is64) {
			nthdr64 = (Elf64_Nhdr *)ndata;
			/* skip past the header and the name string and its
			 * padding */
			ndata += sizeof(Elf64_Nhdr);
			vdebug(5,LOG_T_LUP,"found note name '%s'\n",ndata);
			ndata += nthdr64->n_namesz;
			if (nthdr64->n_namesz % 4)
			    ndata += (4 - nthdr64->n_namesz % 4);
			vdebug(5,LOG_T_LUP,"found note desc '%s'\n",ndata);
			/* dig out the build ID */
			if (nthdr64->n_type == NT_GNU_BUILD_ID) {
			    buildid = strdup(ndata);
			    break;
			}
			/* skip past the descriptor and padding */
			ndata += nthdr64->n_descsz;
			if (nthdr64->n_namesz % 4)
			    ndata += (4 - nthdr64->n_namesz % 4);
		    }
		    else {
			nthdr32 = (Elf32_Nhdr *)ndata;
			/* skip past the header and the name string and its
			 * padding */
			ndata += sizeof(Elf32_Nhdr);
			ndata += nthdr32->n_namesz;
			if (nthdr32->n_namesz % 4)
			    ndata += (4 - nthdr32->n_namesz % 4);
			/* dig out the build ID */
			if (nthdr32->n_type == NT_GNU_BUILD_ID) {
			    buildid = strdup(ndata);
			    break;
			}
			/* skip past the descriptor and padding */
			ndata += nthdr32->n_descsz;
			if (nthdr32->n_namesz % 4)
			    ndata += (4 - nthdr32->n_namesz % 4);
		    }
		}
	    }
	    else if (strcmp(name,".gnu_debuglink") == 0) {
		edata = elf_rawdata(scn,NULL);
		if (!edata) {
		    vwarn("cannot get data for valid section '%s': %s",
			  name,elf_errmsg(-1));
		    continue;
		}
		debuglinkfile = strdup(edata->d_buf);
		debuglinkfilecrc = *(uint32_t *)(edata->d_buf + edata->d_size - 4);
	    }
	}
    }

    elf_end(elf);
    elf = NULL;
    close(fd);
    fd = -1;

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
    else if (buildid) {
	for (i = 0; i < DEBUGPATHLEN; ++i) {
	    snprintf(pbuf,PATH_MAX,"%s/.build-id/%02hhx/%s.debug",
		     DEBUGPATH[i],*buildid,(char *)(buildid+1));
	    if (stat(pbuf,&stbuf) == 0) {
		finalfile = pbuf;
		break;
	    }
	}
    }
    else if (debuglinkfile) {
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
    else {
	verror("could not find any debuginfo sources from ELF file %s!\n",
	       region->name);
	goto errout;
    }

    if (finalfile) {
	if (region->type == REGION_TYPE_MAIN 
	    || region->type == REGION_TYPE_LIB) {
	    if (!target_associate_debugfile(target,region,finalfile,
					    region->type == REGION_TYPE_MAIN ? \
					    DEBUGFILE_TYPE_MAIN : \
					    DEBUGFILE_TYPE_SHAREDLIB))
		goto errout;
	}
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

    int ptopts = PTRACE_O_TRACESYSGOOD;
    ptopts |= lstate->ptrace_opts;
    errno = 0;
    if (ptrace(PTRACE_SETOPTIONS,linux_userproc_pid(target),NULL,ptopts) < 0) {
	vwarn("ptrace setoptions failed: %s\n",strerror(errno));
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
    lstate->syscall = 0;

    return 0;
}

static target_status_t linux_userproc_handle_internal(struct target *target,
						      int pstatus,int *again) {
    struct linux_userproc_state *lstate;
    pid_t pid = linux_userproc_pid(target);
    REG dreg = -1;
    struct probepoint *dpp;
    REGVAL ipval;

    lstate = (struct linux_userproc_state *)(target->state);

    if (WIFSTOPPED(pstatus)) {
	/* Ok, this was a ptrace event; figure out which sig (or if it
	 * was a syscall), and redeliver the sig if it was a sig;
	 * otherwise, don't deliver a sig, and just continue the child,
	 * on resume.
	 */
	lstate->last_signo = WSTOPSIG(pstatus);
	if (lstate->last_signo == (SIGTRAP | 0x80)) {
	    vdebug(5,LOG_T_LUP,"target %d stopped with syscall trap signo %d\n",
		   pid,lstate->last_signo);
	    lstate->last_signo = -1;
	    lstate->syscall = 1;
	}
	else if (lstate->last_signo == SIGTRAP) {
	    /* Don't deliver debug traps! */
	    vdebug(5,LOG_T_LUP,"target %d stopped with trap signo %d\n",
		   pid,lstate->last_signo);
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
		ipval = linux_userproc_read_reg(target,target->ipregno);
		if (errno) {
		    verror("could not read EIP while finding probepoint: %s\n",
			   strerror(errno));
		    return TSTATUS_ERROR;
		}

		/* We could check the debug status register bits, but
		 * this is the same, really...
		 */
		if (lstate->dr[0] == (ptrace_reg_t)ipval)
		    dreg = 0;
		else if (lstate->dr[1] == (ptrace_reg_t)ipval)
		    dreg = 1;
		else if (lstate->dr[2] == (ptrace_reg_t)ipval)
		    dreg = 2;
		else if (lstate->dr[3] == (ptrace_reg_t)ipval)
		    dreg = 3;

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
		   pid,lstate->last_signo);
	}

	return TSTATUS_PAUSED;
    }
    else if (WIFCONTINUED(pstatus)) {
	lstate->last_signo = -1;
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

    target_find_range_real(target,addr,NULL,NULL,&range);

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
 * Extended Integer Registers 8-15 8-15 %r8–%r15
 * Return Address RA 16
 * Vector Registers 0–7 17-24 %xmm0–%xmm7
 * Extended Vector Registers 8–15 25-32 %xmm8–%xmm15
 * Floating Point Registers 0–7 33-40 %st0–%st7
 * MMX Registers 0–7 41-48 %mm0–%mm7
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
    /* Set the break to be on whatever whence was). */
    lstate->dr[7] &= ~(whence << (16 + (reg * 4)));
    /* Set the watchsize to be whatever watchsize was). */
    lstate->dr[7] &= ~(watchsize << (18 + (reg * 4)));

    /* Now write these values! */
    errno = 0;
    ptrace(PTRACE_POKEUSER,pid,
	   offsetof(struct user,u_debugreg[reg]),(void *)(lstate->dr[reg]));
    if (errno) {
	verror("could not update debug reg %"PRIiREG", aborting: %s!\n",reg,
	       strerror(errno));
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
