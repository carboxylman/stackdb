/*
 * Copyright (c) 2014, 2015 The University of Utah
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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <signal.h>
#include <dlfcn.h>

static void *(*real_mmap)(void *addr,size_t length,int prot,int flags,
			  int fd,off_t offset) = NULL;
static int (*real_unlink)(const char *name) = NULL;
static int (*real_atexit)(void (*function)(void)) = NULL;
static int (*real_sigaction)(int signum,const struct sigaction *act,
			     struct sigaction *oldact) = NULL;

static char **files = NULL;
static unsigned int files_size = 0;

static void (*qemu_sigint_handler)(int signo,siginfo_t *siginfo,void *c) = NULL;
static void (*qemu_sigterm_handler)(int signo,siginfo_t *siginfo,void *c) = NULL;
static void (*qemu_sighup_handler)(int signo,siginfo_t *siginfo,void *c) = NULL;

static int use_atexit = 0;
static int use_sig_override = 1;
static int no_cleanup = 0;

static void cleanup(void) {
    unsigned int i;

    for (i = 0; i < files_size; ++i) {
	real_unlink(files[i]);
	free(files[i]);
    }

    free(files);
}

/*
 * QEMU on POSIX OSes catches SIGINT, SIGHUP, SIGTERM, and dies.  This
 * is both the internal and external kill mechanism (i.e., if the
 * machine shuts itself down).  We know the machine is going to die at
 * this point, so cleanup, then call its sighandler!
 */
static void sig_override_handler(int signal,siginfo_t *info,void *x) {
    cleanup();
    if (signal == SIGINT && qemu_sigint_handler)
	qemu_sigint_handler(signal,info,x);
    if (signal == SIGTERM && qemu_sigterm_handler)
	qemu_sigterm_handler(signal,info,x);
    if (signal == SIGHUP && qemu_sighup_handler)
	qemu_sighup_handler(signal,info,x);;
}

/*
 * But unfortunately, QEMU unlink()s before it sets sighandlers.  So we
 * have to catch sigaction too.
 */
int sigaction(int signum,const struct sigaction *act,struct sigaction *oldact) {
    char *ev;
    struct sigaction ouract;

    if (!real_sigaction)
	real_sigaction = dlsym(RTLD_NEXT,"sigaction");

    ev = getenv("QEMU_NO_CLEANUP");
    if (ev) {
	no_cleanup = 1;
	use_atexit = 0;
	use_sig_override = 0;
    }
    ev = getenv("QEMU_USE_ATEXIT");
    if (ev) {
	use_atexit = 1;
	use_sig_override = 0;
    }
    ev = getenv("QEMU_USE_SIGOVERRIDE");
    if (ev) {
	use_atexit = 0;
	use_sig_override = 1;
    }

    if (no_cleanup)
	goto real;

    /*
     * Ok, intercept a few signals we know QEMU dies on.
     */
    if (signum == SIGINT || signum == SIGTERM || signum == SIGHUP) {
	memset(&ouract,0,sizeof(ouract));
	ouract.sa_sigaction = sig_override_handler;
	if (act) {
	    ouract.sa_mask = act->sa_mask;
	    ouract.sa_flags = act->sa_flags;

	    if (signum == SIGINT)
		qemu_sigint_handler = act->sa_sigaction;
	    else if (signum == SIGTERM)
		qemu_sigterm_handler = act->sa_sigaction;
	    else if (signum == SIGHUP)
		qemu_sighup_handler = act->sa_sigaction;
	}

	return real_sigaction(signum,&ouract,oldact);
    }
    else
	goto real;

 real:
    return real_sigaction(signum,act,oldact);
}

/*
 * Wrap unlink to not unlink if @pathname starts with $QEMU_MEMPATH_PREFIX !
 */
int unlink(const char *pathname) {
    char *prefix;

    prefix = getenv("QEMU_MEMPATH_PREFIX");
    if (prefix && strncmp(prefix,pathname,strlen(prefix)) == 0) {
	errno = 0;
	files = realloc(files,files_size + 1);
	files[files_size] = strdup(pathname);
	++files_size;
	if (files_size == 1) {
	    char *ev;

	    ev = getenv("QEMU_NO_CLEANUP");
	    if (ev)
		no_cleanup = 1;
	    ev = getenv("QEMU_USE_ATEXIT");
	    if (ev)
		use_atexit = 1;
	    ev = getenv("QEMU_USE_SIGOVERRIDE");
	    if (ev)
		use_sig_override = 1;

	    if (no_cleanup)
		;
/*
 * This way doesn't work; we override sigaction() above.
 */
#if 0
	    else if (use_sig_override) {
		struct sigaction act;
		struct sigaction oldact;

		memset(&act,0,sizeof(act));
		memset(&oldact,0,sizeof(oldact));

		act.sa_sigaction = sig_override_handler;
		act.sa_flags = SA_SIGINFO;

		sigaction(SIGTERM,&act,&oldact);
		if (0 && !oldact.sa_sigaction) {
		    free(files[0]);
		    free(files);
		    files = NULL;
		    files_size = 0;
		    goto real;
		}
		else
		    qemu_sighandler = oldact.sa_sigaction;

		if (oldact.sa_sigaction) {
		    act.sa_flags = oldact.sa_flags;
		    act.sa_mask = oldact.sa_mask;
		}

		sigaction(SIGINT,&act,NULL);
		sigaction(SIGHUP,&act,NULL);
		sigaction(SIGTERM,&act,NULL);
	    }
#endif /* 0 */
	    else {
		real_atexit = dlsym(RTLD_NEXT,"atexit");
		if (real_atexit)
		    real_atexit(cleanup);
	    }
	}
	return 0;
    }

    /* real: */
    if (!real_unlink)
	real_unlink = dlsym(RTLD_NEXT,"unlink");

    return real_unlink(pathname);
}

/*
 * Wrap mmap to share the mapping instead of privatize it if @fd's
 * pathname starts with $QEMU_MEMPATH_PREFIX .
 */
void *mmap(void *addr,size_t length,int prot,int flags,int fd,off_t offset) {
    char *prefix;

    if (fd <= 0)
	goto real;

    prefix = getenv("QEMU_MEMPATH_PREFIX");

    if (prefix) {
	char buf[32];
	char rbuf[256];
	snprintf(buf,sizeof(buf),"/proc/self/fd/%d",fd);
	if (readlink(buf,rbuf,sizeof(rbuf)) > 0
	    && strncmp(prefix,rbuf,strlen(prefix)) == 0) {
	    flags &= ~MAP_PRIVATE;
	    flags |= MAP_SHARED;
	}
    }

 real:
    if (!real_mmap)
	real_mmap = dlsym(RTLD_NEXT,"mmap");
    return real_mmap(addr,length,prot,flags,fd,offset);
}
