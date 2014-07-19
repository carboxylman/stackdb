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
#include <fcntl.h>

#include "common.h"
#include "target_api.h"
#include "target.h"

#include "target_gdb.h"
#include "target_gdb_rsp.h"

/*
 * Oh, this is a pain.  A GDB stub by default will probably read virtual
 * memory; but some stubs (like those that sit outside a VM) will read
 * whatever memory the VM is exposing at the CPU level -- so if paging
 * is enabled, then virtual memory; if not, physical memory.
 *
 * But, I guess, whether it's KGDB or qemu's GDB, m/M read/write
 * whatever memory the CPU is addressing.  So... the only way we can
 * translate v2p or r/w physical addrs is by some non-GDB stub route --
 * like through QEMU's QMP's xp command (or a hack to the VM making
 * mmap'able memory available).  Other debugger stubs might have their
 * own workarounds.
 *
 * So, we only build in support for r/w virtual memory.
 */

/*
 * Local prototypes.
 */
unsigned char *gdb_helper_builtin_read_tid(struct target *target,
					   tid_t tid,ADDR pgd,ADDR addr,
					   unsigned long length,
					   unsigned char *buf);

struct gdb_helper_builtin_state {
    /* Nothing yet! */
};

int gdb_helper_builtin_init(struct target *target) {
    return 0;
}

int gdb_helper_builtin_attach(struct target *target) {
    return 0;
}

int gdb_helper_builtin_handle_exception_any(struct target *target) {
    return 0;
}

int gdb_helper_builtin_handle_exception_ours(struct target *target) {
    return 0;
}

int gdb_helper_builtin_handle_pause(struct target *target) {
    return 0;
}

unsigned char *gdb_helper_builtin_read_v_str(struct target *target,
					     tid_t tid,ADDR pgd,ADDR addr) {
    int j;
    unsigned char *lbuf = NULL;
    int lbuf_alen = 0,lbuf_len = 0;

    /*
     * Best strategy is to read page by page (starting with the remnant
     * of the page containing @addr), or byte by byte -- depending on
     * the GDB stub.  A page should always be safe, so do that for now.
     */

    lbuf_alen = __PAGE_SIZE - (addr & (__PAGE_SIZE - 1));
    lbuf = realloc(lbuf,lbuf_alen);
    if (!gdb_helper_builtin_read_tid(target,tid,pgd,addr,lbuf_alen,lbuf)) {
	verror("failed to read string at 0x%"PRIxADDR" (target %s)!\n",
	       addr,target->name);
	free(lbuf);
	return NULL;
    }

    do {
	/*
	 * Scan the mmap as necessary for '\0', malloc as necessary, and
	 * break or keep going.
	 */
	for (j = lbuf_len; j < lbuf_alen; ++j) {
	    if (lbuf[j] == '\0')
		break;
	}

	if (j < lbuf_alen) {
	    /* Found it!  realloc and return. */
	    lbuf = realloc(lbuf,j + 1);
	    return lbuf;
	}
	else {
	    lbuf_len = lbuf_alen;
	    lbuf_alen += __PAGE_SIZE;
	    lbuf = realloc(lbuf,lbuf_alen);
	}
    } while (1);

    return (unsigned char *)lbuf;
}

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
unsigned char *gdb_helper_builtin_read_tid(struct target *target,
					   tid_t tid,ADDR pgd,ADDR addr,
					   unsigned long length,
					   unsigned char *buf) {
    struct target_thread *tthread;
    int rc;

    /*
     * Check @tid is current thread or global thread or that all threads
     * share a single address space!
     *
     * How to check if all threads share a single address space?  Maybe
     * just by checking the target type for now; if OS, assume threads
     * need not share an address space; if process or higher-level,
     * assume they do?
     */
    if (target->personality <= TARGET_PERSONALITY_OS && tid != TID_GLOBAL) {
	tthread = target_load_current_thread(target,0);
	if (!tthread) {
	    vwarn("could not load current thread; assuming tid %d is current!\n",
		  tid);
	}
	else {
	    if (tthread->tid != tid) {
		verror("tid %d is not current nor global; cannot read!\n",tid);
		return NULL;
	    }
	}
    }

    if (length == 0)
	return gdb_helper_builtin_read_v_str(target,tid,pgd,addr);

    rc = gdb_rsp_read_mem(target,addr,length,buf);
    if (rc == 0)
	return buf;
    else {
	verror("v 0x%"PRIxADDR" len %lu: %s (%d); continuing\n",
	       addr,length,strerror(errno),rc);
	return NULL;
    }
}

/*
 * Writes @length bytes from @buf to @addr.  Returns the number of bytes
 * written (and sets errno nonzero if there is an error).  Successful if
 * @return == @length.
 */
unsigned long gdb_helper_builtin_write_tid(struct target *target,
					   tid_t tid,ADDR pgd,ADDR addr,
					   unsigned long length,
					   unsigned char *buf) {
    struct target_thread *tthread;
    int rc;

    /*
     * Check @tid is current thread or global thread or that all threads
     * share a single address space!
     *
     * How to check if all threads share a single address space?  Maybe
     * just by checking the target type for now; if OS, assume threads
     * need not share an address space; if process or higher-level,
     * assume they do?
     */
    if (target->personality <= TARGET_PERSONALITY_OS && tid != TID_GLOBAL) {
	tthread = target_load_current_thread(target,0);
	if (!tthread) {
	    vwarn("could not load current thread; assuming tid %d is current!\n",
		  tid);
	}
	else {
	    if (tthread->tid != tid) {
		verror("tid %d is not current nor global; cannot read!\n",tid);
		errno = EINVAL;
		return 0;
	    }
	}
    }

    rc = gdb_rsp_write_mem(target,addr,length,buf);
    if (rc == 0) {
	return length;
    }
    else {
	verror("v 0x%"PRIxADDR" len %lu: %s (%d)\n",
	       addr,length,strerror(errno),rc);
	return 0;
    }
}

int gdb_helper_builtin_fini(struct target *target) {
    return 0;
}

struct gdb_helper_ops gdb_helper_ops_builtin = {
    .init = gdb_helper_builtin_init,
    .attach = gdb_helper_builtin_attach,

    .handle_exception_any = gdb_helper_builtin_handle_exception_any,
    .handle_exception_ours = gdb_helper_builtin_handle_exception_ours,
    .handle_pause = gdb_helper_builtin_handle_pause,
    /*
     * No physical address space access; see comments at top!
     */
    .addr_v2p = NULL,
    .read_phys = NULL,
    .write_phys = NULL,

    .read_tid = gdb_helper_builtin_read_tid,
    .write_tid = gdb_helper_builtin_write_tid,

    .fini = gdb_helper_builtin_fini,
};
