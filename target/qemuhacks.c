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

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <dlfcn.h>

/*
 * Wrap unlink to not unlink if @pathname starts with $QEMU_MEMPATH_PREFIX !
 */
int unlink(const char *pathname) {
    int (*real_unlink)(const char *name);
    char *prefix;

    prefix = getenv("QEMU_MEMPATH_PREFIX");
    if (prefix && strncmp(prefix,pathname,strlen(prefix)) == 0) {
	errno = 0;
	return 0;
    }

    real_unlink = dlsym(RTLD_NEXT,"unlink");
    return real_unlink(pathname);
}

/*
 * Wrap mmap to share the mapping instead of privatize it if @fd's
 * pathname starts with $QEMU_MEMPATH_PREFIX .
 */
void *mmap(void *addr,size_t length,int prot,int flags,int fd,off_t offset) {
    void *(*real_mmap)(void *addr,size_t length,int prot,int flags,
		       int fd,off_t offset);
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
    real_mmap = dlsym(RTLD_NEXT,"mmap");
    return real_mmap(addr,length,prot,flags,fd,offset);
}
