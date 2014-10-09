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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "common.h"
#include "arch.h"
#include "arch_x86.h"
#include "arch_x86_64.h"
#include "target_api.h"
#include "target.h"
#include "target_arch_x86.h"
#include "target_os.h"

#include <xenctrl.h>
#include <xs.h>
#include <xenaccess/xenaccess.h>
#include <xenaccess/xa_private.h>

#include "target_xen_vm.h"


struct xen_vm_mem_xenaccess_state {
    /* XenAccess instance used to read/write domain's memory */
    xa_instance_t xa_instance;
};

/*
 * Prototypes.
 */

int xen_vm_mem_xenaccess_init(struct target *target) {
    struct xen_vm_state *xstate;
    struct xen_vm_mem_xenaccess_state *mstate;

    xstate = (struct xen_vm_state *)target->state;

    mstate = (struct xen_vm_mem_xenaccess_state *)calloc(1,sizeof(*mstate));

    mstate->xa_instance.os_type = XA_OS_LINUX;
    if (xa_init_vm_id_strict_noos(xstate->id,&mstate->xa_instance) == XA_FAILURE) {
	if (mstate->xa_instance.sysmap)
	    free(mstate->xa_instance.sysmap);
        verror("failed to init xa instance for dom %d\n",xstate->id);
	free(mstate);
	return -1;
    }

    xstate->memops_priv = mstate;

    return 0;
}

int xen_vm_mem_xenaccess_attach(struct target *target) {
    struct xen_vm_state *xstate;
    struct xen_vm_mem_xenaccess_state *mstate;
    ADDR init_task_addr,pgd_addr;
    char *val;
    OFFSET tasks_offset,pid_offset,mm_offset,pgd_offset;

    xstate = (struct xen_vm_state *)target->state;
    mstate = (struct xen_vm_mem_xenaccess_state *)xstate->memops_priv;

    /*
     * Make sure xenaccess is setup to read from userspace memory.
     *
     * This is hacky, but we do it by reading properties that the
     * personality has (hopefully) set.
     */
    val = (char *)g_hash_table_lookup(target->config,"OS_KERNEL_INIT_TASK_ADDR");
    if (val)
	init_task_addr = (ADDR)strtol(val,NULL,0);
    val = (char *)g_hash_table_lookup(target->config,"OS_KERNEL_PGD_ADDR");
    if (val)
	pgd_addr = (ADDR)strtol(val,NULL,0);


    val = (char *)g_hash_table_lookup(target->config,"OS_KERNEL_TASKS_OFFSET");
    if (val)
	tasks_offset = (ADDR)strtol(val,NULL,0);
    val = (char *)g_hash_table_lookup(target->config,"OS_KERNEL_PID_OFFSET");
    if (val)
	pid_offset = (ADDR)strtol(val,NULL,0);
    val = (char *)g_hash_table_lookup(target->config,"OS_KERNEL_MM_OFFSET");
    if (val)
	mm_offset = (ADDR)strtol(val,NULL,0);
    val = (char *)g_hash_table_lookup(target->config,"OS_KERNEL_MM_PGD_OFFSET");
    if (val)
	pgd_offset = (ADDR)strtol(val,NULL,0);

    xstate->xa_instance.init_task = init_task_addr;
    xstate->xa_instance.page_offset = 0;
    xstate->xa_instance.os.linux_instance.tasks_offset = tasks_offset;
    xstate->xa_instance.os.linux_instance.pid_offset = pid_offset;
    xstate->xa_instance.os.linux_instance.mm_offset = mm_offset;
    xstate->xa_instance.os.linux_instance.pgd_offset = pgd_offset;
    xstate->xa_instance.kpgd = pgd_addr;

    return 0;
}

int xen_vm_mem_xenaccess_handle_exception_any(struct target *target) {
    return 0;
}

int xen_vm_mem_xenaccess_handle_exception_ours(struct target *target) {
    struct xen_vm_state *xstate;
    struct xen_vm_mem_xenaccess_state *mstate;

    xstate = (struct xen_vm_state *)target->state;
    mstate = (struct xen_vm_mem_xenaccess_state *)xstate->memops_priv;

    /* From previous */
    xa_destroy_cache(&mstate->xa_instance);
    xa_destroy_pid_cache(&mstate->xa_instance);

    return 0;
}

int xen_vm_mem_xenaccess_addr_v2p(struct target *target,tid_t tid,ADDR pgd,
				  ADDR vaddr,ADDR *paddr) {
    struct xen_vm_state *xstate;
    struct xen_vm_mem_xenaccess_state *mstate;
    uint64_t tvaddr = 0;
    uint64_t tpaddr = 0;

    xstate = (struct xen_vm_state *)target->state;
    mstate = (struct xen_vm_mem_xenaccess_state *)xstate->memops_priv;

    /*
     * Strip the offset bits to improve xenaccess cache perf.
     */
    tvaddr = vaddr & ~(__PAGE_SIZE - 1);

#if __WORDSIZE == 64
    verror("no XenAccess support for 64-bit host!\n");
    errno = ENOTSUP;
    return -1;
#else
    tpaddr = xa_pagetable_lookup(&xstate->xa_instance,pgd,tvaddr,0);
    if (tpaddr == 0) {
	verror("could not lookup vaddr 0x%"PRIxADDR" in tid %"PRIiTID
	       " pgd 0x%"PRIxADDR"!\n",
	       vaddr,tid,pgd);
	return -1;
    }
#endif

    *paddr = tpaddr | (vaddr & (__PAGE_SIZE - 1));

    vdebug(12,LA_TARGET,LF_XV,
	   "tid %"PRIiTID" vaddr 0x%"PRIxADDR" -> paddr 0x%"PRIxADDR"\n",
	   tid,vaddr,*paddr);

    return 0;
}

unsigned char *xen_vm_mem_xenaccess_read_phys(struct target *target,ADDR paddr,
					      unsigned long length,
					      unsigned char *buf) {
    struct xen_vm_state *xstate;
    struct xen_vm_mem_xenaccess_state *mstate;
    unsigned char *retval = NULL;
    unsigned long npages;
    unsigned long page_offset;
    unsigned long i;
    unsigned long cur;
    unsigned char *mmap;
    unsigned long rc;
    uint32_t offset;

    xstate = (struct xen_vm_state *)target->state;

    if (!buf)
	retval = (unsigned char *)malloc(length+1);
    else 
	retval = buf;

    page_offset = paddr & (__PAGE_SIZE - 1);
    npages = (page_offset + length) / __PAGE_SIZE;
    if ((page_offset + length) % __PAGE_SIZE)
	++npages;

    /* Have to mmap them one by one. */
    cur = paddr & ~(__PAGE_SIZE - 1);
    rc = 0;
    for (i = 0; i < npages; ++i) {
	mmap = xa_access_pa(&xstate->xa_instance,cur,&offset,PROT_READ);
	if (!mmap) {
	    verror("failed to mmap paddr 0x%lx (for write to"
		   " 0x%"PRIxADDR"): %s!\n",
		   cur,paddr,strerror(errno));
	    goto errout;
	}
	if (i == 0) {
	    memcpy(retval + rc,mmap + page_offset,__PAGE_SIZE - page_offset);
	    rc = __PAGE_SIZE - page_offset;
	}
	else if (i == (npages - 1)) {
	    memcpy(retval + rc,mmap,(length - rc));
	    rc += length - rc;
	}
	else {
	    memcpy(retval + rc,mmap,__PAGE_SIZE);
	    rc += __PAGE_SIZE;
	}
	munmap(mmap,__PAGE_SIZE);
	cur += __PAGE_SIZE;
    }

    return retval;

 errout:
    if (!buf && retval)
	free(retval);
    if (!errno)
	errno = EFAULT;
    return NULL;
}

unsigned long xen_vm_mem_xenaccess_write_phys(struct target *target,ADDR paddr,
					      unsigned long length,
					      unsigned char *buf) {
    struct xen_vm_state *xstate;
    unsigned long npages;
    unsigned long page_offset;
    unsigned long i;
    unsigned long cur;
    unsigned char *mmap;
    unsigned long rc;
    uint32_t offset;

    xstate = (struct xen_vm_state *)target->state;

    page_offset = paddr & (__PAGE_SIZE - 1);
    npages = (page_offset + length) / __PAGE_SIZE;
    if ((page_offset + length) % __PAGE_SIZE)
	++npages;

    /* Have to mmap them one by one. */
    cur = paddr & ~(__PAGE_SIZE - 1);
    rc = 0;
    for (i = 0; i < npages; ++i) {
	mmap = xa_access_pa(&xstate->xa_instance,cur,&offset,PROT_READ);
	if (!mmap) {
	    verror("failed to mmap paddr 0x%lx (for write to"
		   " 0x%"PRIxADDR"): %s!\n",
		   cur,paddr,strerror(errno));
	    goto errout;
	}
	if (i == 0) {
	    memcpy(mmap + page_offset,buf + rc,__PAGE_SIZE - page_offset);
	    rc = __PAGE_SIZE - page_offset;
	}
	else if (i == (npages - 1)) {
	    memcpy(mmap,buf + rc,(length - rc));
	    rc += length - rc;
	}
	else {
	    memcpy(mmap,buf + rc,__PAGE_SIZE);
	    rc += __PAGE_SIZE;
	}
	munmap(mmap,__PAGE_SIZE);
	cur += __PAGE_SIZE;
    }

    return length;

 errout:
    if (!errno)
	errno = EFAULT;
    return 0;
}

static unsigned char *
__xen_vm_mem_xenaccess_mmap_pages(xa_instance_t *xa_instance,ADDR addr, 
				  unsigned long size,uint32_t *offset,
				  int *npages,int prot,int pid) {
    unsigned char *pages;
    unsigned long page_size, page_offset;
    char *dstr = "small";

    page_size = xa_instance->page_size;
    page_offset = addr & (page_size - 1);

    if (size > 0 && size <= (page_size - page_offset)) {
        /* let xenaccess use its memory cache for small size */
        pages = xa_access_user_va(xa_instance,addr,offset,pid,prot);
	if (!pages) {
	    if (!pid)
		return NULL;

	    pages = xa_access_user_va(xa_instance,addr,offset,0,prot);
	    if (!pages)
		return NULL;
	}
	*npages = 1;
    }
    else {
	dstr = "large";
        /* xenaccess can't map multiple pages properly, use our own function */
        pages = xa_access_user_va_range(xa_instance,addr,size,offset,pid,prot);

	if (!pages) { // && pid) {
	    //return NULL;
	    if (!pid)
		return NULL;

	    /* try kernel */
	    pages = xa_access_user_va_range(xa_instance,addr,size,offset,0,prot);
	    if (!pages) 
		return NULL;
	}

	/*
	 * Compute how many pages were mapped.
	 * *offset is the offset within the initial page mapped.
	 * Number of pages is thus:
	 *   round((*offset+size), page_size)
	 */
	*npages = (*offset + size) / page_size;
	if ((*offset + size) % page_size)
	    (*npages)++;
    }

    vdebug(9,LA_TARGET,LF_XV,"%ld bytes at %lx mapped (%s)\n",size,addr,dstr);

    return pages; /* munmap it later */
}

/*
 * Our xen read and write functions are a little special.  First,
 * xenaccess has the ability to read/write using the current cr3
 * contents as the pgdir location, or it can use a different pgdir
 * (i.e., for a thread that is not running).  
 */
unsigned char *xen_vm_mem_xenaccess_read_tid(struct target *target,tid_t tid,
					     ADDR addr,
					     unsigned long target_length,
					     unsigned char *buf) {
    unsigned char *pages;
    unsigned int offset = 0;
    unsigned long length = target_length, size = 0;
    unsigned long page_size;
    unsigned char *retval = NULL;
    unsigned int page_offset;
    int no_pages;
    struct xen_vm_state *xstate;

    xstate = (struct xen_vm_state *)(target->state);

    /*
     * Change the TID to 0 if TID was global.  The Xen backend always
     * defaults non-tid-specific reads/writes to the kernel, via
     * TID_GLOBAL.
     */
    if (tid == TID_GLOBAL)
	tid = 0;

    // XXX: need to check, if pid > 0, if we can actually read it --
    // i.e., do we have the necessary task_struct offsets for xenaccess,
    // and is it in mem...

    page_size = xstate->xa_instance.page_size;
    page_offset = addr & (page_size - 1);

    vdebug(16,LA_TARGET,LF_XV,
	   "read dom %d: addr=0x%"PRIxADDR" offset=%d len=%d pid=%d\n",
	   xstate->id,addr,page_offset,target_length,pid);

    /* if we know what length we need, just grab it */
    if (length > 0) {
	pages = (unsigned char *) \
	    __xen_vm_mem_xenaccess_mmap_pages(&xstate->xa_instance,addr,
					      length,&offset,&no_pages,
					      PROT_READ,pid);
	if (!pages)
	    return NULL;

	assert(offset == page_offset);
	vdebug(9,LA_TARGET,LF_XV,
	       "read dom %d: addr=0x%"PRIxADDR" offset=%d pid=%d len=%d mapped pages=%d\n",
	       xstate->id,addr,page_offset,pid,length,no_pages);
    }
    else {
	/* increase the mapping size by this much if the string is longer 
	   than we expect at first attempt. */
	size = (page_size - page_offset);

	while (1) {
	    if (1 || size > page_size) 
		vdebug(16,LA_TARGET,LF_XV,
		       "increasing size to %d (dom=%d,addr=%"PRIxADDR",pid=%d)\n",
		       size,xstate->id,addr,pid);
	    pages = (unsigned char *) \
		__xen_vm_mem_xenaccess_mmap_pages(&xstate->xa_instance,addr,size,
						  &offset,&no_pages,
						  PROT_READ,pid);
	    if (!pages)
		return NULL;

	    length = strnlen((const char *)(pages + offset), size);
	    if (length < size) {
		vdebug(9,LA_TARGET,LF_XV,"got string of length %d, mapped %d pages\n",
		       length,no_pages);
		break;
	    }
	    if (munmap(pages,no_pages * page_size))
		vwarn("munmap of %p failed\n",pages);
	    size += page_size;
	}
    }

    if (!buf)
	retval = (unsigned char *)malloc(length+1);
    else 
	retval = buf;
    if (retval) {
	memcpy(retval,pages + offset,length);
	if (target_length == 0) {
	    retval[length] = '\0';
	}
    }

    if (munmap(pages,no_pages * page_size))
	vwarn("munmap of %p failed\n",pages);
    
    return retval;
}

unsigned long xen_vm_mem_xenaccess_write_tid(struct target *target,
					     int pid,ADDR addr,
					     unsigned long length,
					     unsigned char *buf) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)(target->state);
    struct memrange *range = NULL;
    unsigned char *pages;
    unsigned int offset = 0;
    unsigned long page_size;
    unsigned int page_offset;
    int no_pages;

    xstate = (struct xen_vm_state *)(target->state);

    /*
     * Change the TID to 0 if TID was global.  The Xen backend always
     * defaults non-tid-specific reads/writes to the kernel, via
     * TID_GLOBAL.
     */
    if (tid == TID_GLOBAL)
	tid = 0;

    page_size = xstate->xa_instance.page_size;
    page_offset = addr & (page_size - 1);

    vdebug(16,LA_TARGET,LF_XV,
	   "write dom %d: addr=0x%"PRIxADDR" offset=%d len=%d pid=%d\n",
	   xstate->id,addr,page_offset,length,pid);

    target_find_memory_real(target,addr,NULL,NULL,&range);

    /*
     * This is mostly a stub for later, when we might actually check
     * bounds of writes.
     */
    if (!range || !(range->prot_flags & PROT_WRITE)) {
	errno = EFAULT;
	return 0;
    }

    /* Map the pages we have to write to. */
    pages = (unsigned char *) \
	__xen_vm_mem_xenaccess_mmap_pages(&xstate->xa_instance,addr,
					  length,&offset,&no_pages,
					  PROT_WRITE,pid);
    if (!pages) {
	errno = EFAULT;
	return 0;
    }

    assert(offset == page_offset);
    vdebug(9,LA_TARGET,LF_XV,
	   "write dom %d: addr=0x%"PRIxADDR" offset=%d pid=%d len=%d mapped pages=%d\n",
	   xstate->id,addr,page_offset,pid,length,no_pages);

    memcpy(pages + offset,buf,length);

    if (munmap(pages,no_pages * page_size))
	vwarn("munmap of %p failed\n",pages);

    return length;
}
