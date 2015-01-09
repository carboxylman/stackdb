/*
 * Copyright (c) 2015 The University of Utah
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

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/user.h>

#include "log.h"
#include "dwdebug.h"
#include "dlmalloc.h"

/**
 * debugserver "serves" a single debug file, meaning it fully loads a
 * non-relocatable debugging information file (using dwdebug) into a
 * shared memory segment.  We don't serve relocatable debugfiles because
 * they have to be relocated on a per-instance basis, and there's not
 * much point caching a per-instance relocated version of a debuginfo
 * file.
 *
 * To make this work, we bump the size of /proc/sys/kernel/shmmax to 4GB
 * (/proc/sys/kernel/shmall should already be 8GB).  No single debugfile
 * should require more than 2.5GB anyway (Linux kernel files top out a
 * bit over 2GB when fully loaded and indexed).
 *
 * dwdebug insists on fully loading shared debugfiles.  The whole idea
 * behind this server is that when it is started, no dwdebug user (like
 * the target lib) has started any debugging work --- and thus we have
 * time to build a full index so that runtime use is as fast as
 * possible.  That's the exact use case we're targeting.
 *
 * If we added multi-thread support to dwdebug, we could relax this
 * case, because multiple debugserver clients could expand partial
 * symbols on-demand.  However, then we run the risk of one client
 * blocking another.  Since the goal is to optimize runtime lookups, we
 * aren't going to bother with this at present.  Moreover, all access to
 * the dwdebug debugfile, scope, and symbol structs that we create would
 * have to be mitigated by a per-debugfile write lock that blocks all
 * readers (i.e., symbol lookups) (and a per-debugfile read lock that
 * blocks all writers) --- because otherwise one client's lookup could
 * obviously encounter an incomplete debugfile struct modification
 * during partial symbol expansion triggered by another client (and one
 * client's partial symbol expansion could corrupt the structures during
 * another client's lookup).
 *
 * Obviously, these problems are all fixable, but it's not really
 * necessary right now.  The main reason to fix them would be if memory
 * usage is really a concern.  So for now, if that's really a concern,
 * you're stuck *not* using debugservers.  Right now, the target library
 * (the only real user of the dwdebug library) only checks to see if
 * there's a debugserver running, but it doesn't automatically start a
 * debugserver --- it just opens debugfiles internal to the program
 * using it.
 */

/*
 * Implementation:
 *
 * It was surprisingly hard to figure out how to do this.  Right away,
 * the obviously method is to create a shared memory segment (whichever
 * way), and restrict malloc to the segment.  There doesn't appear to be
 * any software that does this (and believe me, I've looked many times
 * --- Ralf Engelschall's `mm' library is probably closest, but it has
 * an apparently arbitrary 64MB soft limit).
 *
 * Anyway, it turned out to be easiest to grab the latest Doug Lea
 * malloc (2.8.6), because it allows you to define an mspace with a
 * fixed base address, and provide your own morecore function.  So, we
 * use the POSIX shared memory strategy (shm_open, ftruncate, mmap), but
 * I added ftruncate as my morecore strategy, and build dlmalloc
 * accordingly.  Then (once we are initialized!!!) we use mspaces to
 * restrict memory operations to our mspace.  We create a mspace ASAP,
 * but there is still some malloc'ing going on using the heap (sbrk --
 * my malloc wrappers and morecore will just call the regular dlmalloc
 * (non-mspace) functions, and use sbrk (I disable mmap as a strategy),
 * until we've initialized the fixed-base mspace.  We create an mspace
 * at a "safe" offset that provides us enough room to fully load the
 * debugfile (we use the db file to guess at a hole, and estimate based
 * on debuginfo file size how much space we'll need).  Also, if
 * ftruncate fails during alloc/free, that's it --- we abort.
 * Technically, we could switch back to the non-mspace dlmalloc at any
 * time, but there's no need.
 *
 * Because the whole goal of the debugserver is to share full,
 * in-memory, dynamically-allocated data structures with other
 * processes, it must publish metadata telling these client processes
 * where to mmap the shm segment.  For now, debugservers are
 * root-privilege only, and keep metadata in /var/lib/vmi/debugserver.db
 * (which is edited safely by multiple instances of a debugserver via
 * flock).  Eventually, we'll 
 * debugservers edit/create the /var/lib/vmi/debugserver.db file ;
 * however, you can specify a separate db file if desired --- and this
 * may be 1) necessary if you are not root; and/or 2) desirable if you
 * want to control
 */

/*
 * Our malloc wrappers --- just call the dl mspace_* functions with our
 * mspace.  If the mspace hasn't been initialized, the default dl malloc
 * strategy gets used.
 */

#define MADDR 0x100000000

static char shm_mm_name[NAME_MAX];
static int shm_mm_on = 0;
static int shm_mm_fd = -1;
static off_t shm_mm_length = 0;
static void *shm_mm_base = (void *)0;
static mspace global_mspace;

/*
 * Our MoreCore function for shm.
 */
void *shm_morecore(int size) {

    printf("morecore: %d\n",size);

    /* If we're not initialized yet, let sbrk handle it. */
    if (!shm_mm_base || shm_mm_fd < 0)
	return sbrk(size);

    /* Conform. */
    if (!size) {
	printf("morecore: ret 0x%lx\n",(uintptr_t)(shm_mm_base + shm_mm_length + 1));
	return (shm_mm_base + shm_mm_length + 1);
    }

    if (ftruncate(shm_mm_fd,shm_mm_length + size)) {
	verror("ftruncate: %s\n",strerror(errno));
	errno = ENOMEM;
	return (void *)MFAIL;
    }
    else if (mremap(shm_mm_base,shm_mm_length,shm_mm_length + size,0)
	     != shm_mm_base) {
	verror("mremap: %s\n",strerror(errno));
	errno = ENOMEM;
	return (void *)MFAIL;
    }
    else {
	shm_mm_length += size;
	errno = 0;
	printf("morecore: ret 0x%lx (0x%lx,0x%lx)\n",
	       (uintptr_t)(shm_mm_base + shm_mm_length - size + 1),
	       (uintptr_t)shm_mm_base,(uintptr_t)shm_mm_length);
	return (shm_mm_base + shm_mm_length - size + 1);
    }
}

int shm_init(char *name,off_t size) {
    shm_mm_fd = shm_open(name,O_CREAT | O_EXCL | O_RDWR,
			 S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
    if (shm_mm_fd < 0)
	return -1;

    if (ftruncate(shm_mm_fd,size)) {
	shm_unlink(shm_mm_name);
	shm_mm_fd = -1;
	return -1;
    }

    if (mmap((void *)MADDR,size,PROT_READ | PROT_WRITE,MAP_SHARED | MAP_FIXED,
	     shm_mm_fd,0) != (void *)MADDR) {
	shm_unlink(shm_mm_name);
	shm_mm_fd = -1;
	return -1;
    }

    shm_mm_base = (void *)MADDR;
    shm_mm_length = size;
    strncpy(shm_mm_name,name,NAME_MAX);
    shm_mm_name[NAME_MAX - 1] = '\0';
    global_mspace = create_mspace_with_base(shm_mm_base,shm_mm_length,0);
    shm_mm_on = 1;

    return 0;
}

void *calloc(size_t nmemb,size_t size) {
    if (!shm_mm_on)
	return dlcalloc(nmemb,size);
    else
	return mspace_calloc(global_mspace,nmemb,size);
}

void free(void *ptr) {
    if (!shm_mm_on)
	return dlfree(ptr);
    else
	return mspace_free(global_mspace,ptr);
}

void *malloc(size_t size) {
    if (!shm_mm_on)
	return dlmalloc(size);
    else
	return mspace_malloc(global_mspace,size);
}

void *realloc(void *ptr,size_t size) {
    if (!shm_mm_on)
	return dlrealloc(ptr,size);
    else
	return mspace_realloc(global_mspace,ptr,size);
}

void *memalign(size_t alignment,size_t size) {
    if (!shm_mm_on)
	return dlmemalign(alignment,size);
    else
	return mspace_memalign(global_mspace,alignment,size);
}

int posix_memalign(void **memptr,size_t alignment,size_t size) {
    if (!shm_mm_on)
	return dlposix_memalign(memptr,alignment,size);
    else
	return mspace_posix_memalign(global_mspace,memptr,alignment,size);
}

void *valloc(size_t size) {
    if (!shm_mm_on)
	return dlvalloc(size);
    else
	return mspace_memalign(global_mspace,PAGE_SIZE,size);
}

void *pvalloc(size_t size) {
    if (!shm_mm_on)
	return dlpvalloc(size);
    else {
	size_t rsize = (size + PAGE_SIZE - (size_t)1) & ~(PAGE_SIZE - (size_t)1);
	return mspace_memalign(global_mspace,PAGE_SIZE,rsize);
    }
}

struct mallinfo mallinfo(void) {
    if (!shm_mm_on)
	return dlmallinfo();
    else
	return mspace_mallinfo(global_mspace);
}

int mallopt(int param,int value) {
    if (!shm_mm_on)
	return dlmallopt(param,value);
    else
	/* XXX: weird, no mspace first arg? */
	return mspace_mallopt(param,value);
}

int malloc_trim(size_t pad) {
    if (!shm_mm_on)
	return dlmalloc_trim(pad);
    else
	return mspace_trim(global_mspace,pad);
}

void malloc_stats(void) {
    if (!shm_mm_on)
	return dlmalloc_stats();
    else
	return mspace_malloc_stats(global_mspace);
}

size_t malloc_usable_size(void *ptr) {
    if (!shm_mm_on)
	return dlmalloc_usable_size(ptr);
    else
	/* XXX: no mspace-specific version? */
	return mspace_usable_size((const void *)ptr);
}

void cleanup() {
    dwdebug_fini();
    munmap((void *)MADDR,shm_mm_length);
    shm_unlink(shm_mm_name);
    exit(0);
}

void sigh(int signo) {
    cleanup();
}

int main(int argc,char **argv) {
    struct stat sbuf;
    struct debugfile *debugfile;
    char sname[NAME_MAX];
    char *cptr;

    if (argc < 1) {
	verror("Must supply a debugfile pathname!\n");
	exit(-1);
    }

    if (geteuid() != 0) {
	verror("must be root!\n");
	exit(-1);
    }

    if (stat("/var/lib/vmi",&sbuf) && mkdir("/var/lib/vmi",0)) {
	verror("could not create /var/lib/vmi: %s\n",strerror(errno));
	exit(-1);
    }

    signal(SIGINT,sigh);
    signal(SIGHUP,sigh);

    strncpy(sname,argv[1],NAME_MAX);
    sname[NAME_MAX - 1] = '\0';

    /* POSIX shm names can't have '/' */
    for (cptr = sname; *cptr != '\0'; ++cptr)
	if (*cptr == '/')
	    *cptr = '|';

    if (shm_init(sname,4096)) {
	verror("Could not initialize shm-backed heap: %s\n",strerror(errno));
	exit(-1);
    }

    dwdebug_init();
    atexit(dwdebug_fini);

    debugfile = debugfile_from_file(argv[1],NULL,NULL);
    if (!debugfile) {
	cleanup();
	exit(-8);
    }

    printf("shm_base = 0x%lx, shm_length = 0x%lx, debugfile = 0x%lx ...\n",
	   (uintptr_t)shm_mm_base,(uintptr_t)shm_mm_length,(uintptr_t)debugfile);

    while (1)
	sleep(32768);

    return 0;
}
