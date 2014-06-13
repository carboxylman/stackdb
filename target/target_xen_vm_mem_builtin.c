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
#include "target_xen_vm.h"

#ifdef XENCTRL_HAS_XC_INTERFACE
extern xc_interface *xc_handle;
#define XC_IF_INVALID (NULL)
#else
extern int xc_handle;
#define XC_IF_INVALID (-1)
#endif

struct xen_vm_mem_builtin_state {
    /* Nothing yet! */
};

int xen_vm_mem_builtin_init(struct target *target) {
    struct xen_vm_state *xstate;
    struct xen_vm_mem_builtin_state *mstate;

    xstate = (struct xen_vm_state *)target->state;

    mstate = (struct xen_vm_mem_builtin_state *)NULL; //calloc(1,sizeof(*mstate));

    xstate->memops_priv = mstate;

    /* We use memcache -- create one. */
    if (target->memcache) {
	verror("memcache already in use!\n");
	errno = EINVAL;
	return -1;
    }

    target->memcache = memcache_create(0,0,NULL);

    return 0;
}

int xen_vm_mem_builtin_attach(struct target *target) {
    return 0;
}

int xen_vm_mem_builtin_handle_exception_any(struct target *target) {
    return 0;
}

int xen_vm_mem_builtin_handle_exception_ours(struct target *target) {
    struct xen_vm_state *xstate;
    struct xen_vm_mem_builtin_state *mstate;
    struct xen_vm_spec *xspec;

    xstate = (struct xen_vm_state *)target->state;
    xspec = (struct xen_vm_spec *)target->spec->backend_spec;
    mstate = (struct xen_vm_mem_builtin_state *)xstate->memops_priv;

    /* XXX: invalidate caches? */
    if (xspec->clear_mem_caches_each_exception) {
	memcache_invalidate_all(target->memcache);
    }

    return 0;
}

int xen_vm_mem_builtin_handle_pause(struct target *target) {
    struct xen_vm_state *xstate;
    struct xen_vm_mem_builtin_state *mstate;
    struct xen_vm_spec *xspec;

    xstate = (struct xen_vm_state *)target->state;
    xspec = (struct xen_vm_spec *)target->spec->backend_spec;
    mstate = (struct xen_vm_mem_builtin_state *)xstate->memops_priv;

    /* XXX: invalidate caches? */
    if (xspec->clear_mem_caches_each_exception) {
	memcache_invalidate_all(target->memcache);
    }

    return 0;
}

int xen_vm_mem_builtin_addr_v2p(struct target *target,tid_t tid,ADDR pgd,
			       ADDR vaddr,ADDR *paddr) {
    struct xen_vm_state *xstate;
    struct xen_vm_mem_builtin_state *mstate;
    ADDR tvaddr,tpaddr;
    int rc;

    xstate = (struct xen_vm_state *)target->state;
    mstate = (struct xen_vm_mem_builtin_state *)xstate->memops_priv;

    /*
     * Strip the offset bits to improve builtin/xenaccess cache perf.
     */
    tvaddr = vaddr & ~(__PAGE_SIZE - 1);

    rc = memcache_get_v2p(target->memcache,pgd,tvaddr,paddr,NULL);
    if (rc == 0)
	return 0;
    else if (rc < 0) {
	vwarn("error while looking up vaddr 0x%"PRIxADDR" (for vaddr"
	      " 0x%"PRIxADDR") in memcache: %s (%d); trying full lookup!\n",
	      tvaddr,vaddr,strerror(errno),rc);
    }

    rc = target_arch_x86_v2p(target,pgd,vaddr,ARCH_X86_V2P_LMA,&tpaddr);
    if (rc) {
	verror("could not lookup vaddr 0x%"PRIxADDR" in tid %"PRIiTID
	       " pgd 0x%"PRIxADDR"!\n",
	       vaddr,tid,pgd);
	return -1;
    }

    *paddr = tpaddr | (vaddr & (__PAGE_SIZE - 1));

    vdebug(12,LA_TARGET,LF_XV,
	   "tid %"PRIiTID" vaddr 0x%"PRIxADDR" -> paddr 0x%"PRIxADDR"\n",
	   tid,vaddr,*paddr);

    memcache_set_v2p(target->memcache,pgd,vaddr,*paddr);

    return 0;
}

static void *__xen_vm_mem_builtin_mmap_phys(struct target *target,ADDR paddr,
					    unsigned long length,int prot,
					    ADDR *pbase,OFFSET *poffset,
					    unsigned long *plength) {
    struct xen_vm_state *xstate;
    xen_pfn_t *pfn_arr;
    int num,i;
    OFFSET paddr_offset;
    ADDR lpaddr,pfn;
    void *mmap;

    xstate = (struct xen_vm_state *)target->state;

    paddr_offset = paddr & (((ADDR)__PAGE_SIZE) - 1);
    num = (paddr_offset + length) / ((ADDR)__PAGE_SIZE);
    if ((paddr_offset + length) % ((ADDR)__PAGE_SIZE))
	++num;
    //num = (length - paddr_offset) / __PAGE_SIZE;
    //num += ((length - paddr_offset) & (__PAGE_SIZE - 1)) ? 1 : 0;

    pfn_arr = calloc(num,sizeof(*pfn_arr));
    lpaddr = paddr & ~(((ADDR)__PAGE_SIZE) - 1);
    pfn = lpaddr / ((ADDR)__PAGE_SIZE);
    for (i = 0; i < num; ++i) {
	pfn_arr[i] = pfn + i;
    }

    mmap = xc_map_foreign_pages(xc_handle,xstate->id,prot,pfn_arr,num);
    //mmap = xc_map_foreign_range(xc_handle,xstate->id,prot,num * __PAGE_SIZE,
    //				pfn);
    if (!mmap) {
	verror("failed to mmap %d pages at paddr 0x%"PRIxADDR
	       " (page 0x%"PRIxADDR")!\n",
	       num,paddr,lpaddr);
	if (!errno)
	    errno = EFAULT;
	return NULL;
    }
    else {
	if (pbase)
	    *pbase = lpaddr;
	if (poffset)
	    *poffset = paddr_offset;
	if (plength)
	    *plength = num * __PAGE_SIZE;

	vdebug(8,LA_TARGET,LF_XV,
	       "mmap'd %d pages at phys 0x%"PRIxADDR" at 0x%p\n",
	       num,lpaddr,mmap);

	return mmap;
    }
}

unsigned char *xen_vm_mem_builtin_read_phys_str(struct target *target,
						ADDR addr) {
    ADDR lvaddr;
    OFFSET voffset = 0;
    char *mmap = NULL;
    unsigned long mlen;
    int rc,i,j,pad;
    ADDR paddr;
    char *lbuf = NULL;
    int lbuf_alen = 0,lbuf_len = 0;
    OFFSET coffset;
    short didmmap,savedmmap;
    ADDR pbase;
    unsigned long plength = 0;

    /*
     * Read phys pages until we see a '\0'.
     *
     * NB: Cache physical pages as tid 0!
     */

    lvaddr = addr & ~(__PAGE_SIZE - 1);
    voffset = addr & (__PAGE_SIZE - 1);
    for (i = 0; ; ++i) {
	paddr = lvaddr + i * __PAGE_SIZE;

	mlen = __PAGE_SIZE;
	coffset = 0;
	if (i == 0) {
	    mlen -= voffset;
	    coffset = voffset;
	}

	rc = memcache_get_mmap(target->memcache,0,paddr,1,MEMCACHE_PHYS,
			       &pbase,NULL,(void **)&mmap,&plength,NULL);
	if (rc < 0) {
	    vwarn("memcache_get_mmap error: v 0x%"PRIxADDR" len %lu: %s (%d); continuing\n",
		  addr,1ul,strerror(errno),rc);
	}
	if (!mmap) {
	    mmap = __xen_vm_mem_builtin_mmap_phys(target,paddr,mlen,PROT_WRITE,
						  NULL,NULL,NULL);
	    if (!mmap) {
		verror("could not mmap p 0x%"PRIxADDR" (start p 0x%"PRIxADDR")!\n",
		       paddr,addr);
		if (lbuf)
		    free(lbuf);
		return NULL;
	    }
	    didmmap = savedmmap = 0;
	}
	else {
	    /* Cache it. */
	    didmmap = 1;
	    savedmmap = 0;
	    rc = memcache_set_mmap(target->memcache,0,pbase,MEMCACHE_PHYS,
				   mmap,plength);
	    if (rc == 1) {
		vdebug(5,LA_TARGET,LF_XV | LF_MEMCACHE,
		       "something already cached at p 0x%"PRIxADDR" len %lu"
		       " for read p 0x%"PRIxADDR"; skipping!\n",
		       pbase,plength,addr);
	    }
	    else if (rc < 0) {
		vwarn("memcache_set_mmap error: p 0x%"PRIxADDR" len %lu (for read"
		      " p 0x%"PRIxADDR": %s (%d); continuing\n",
		      pbase,plength,addr,strerror(errno),rc);
	    }
	    else {
		savedmmap = 1;
	    }
	}

	/*
	 * Scan the mmap as necessary for '\0', malloc as necessary, and
	 * break or keep going.
	 */
	for (j = coffset; j < __PAGE_SIZE; ++j) {
	    if (mmap[j] == '\0')
		break;
	}

	pad = (j < __PAGE_SIZE) ? 1 : 0;
	if (!lbuf) {
	    lbuf_alen = j - coffset + pad;
	    lbuf = malloc(lbuf_alen);
	}
	else {
	    lbuf_alen += j - coffset + pad;
	    lbuf = realloc(lbuf,lbuf_alen);
	}
	memcpy(lbuf + lbuf_len,mmap + coffset,j - coffset);
	lbuf_len += j - coffset;

	if (didmmap && !savedmmap)
	    munmap(mmap,plength);

	if (pad) {
	    lbuf[lbuf_len] = '\0';
	    break;
	}
    }

    return (unsigned char *)lbuf;
}

unsigned char *xen_vm_mem_builtin_read_phys(struct target *target,ADDR paddr,
					    unsigned long length,
					    unsigned char *buf) {
    unsigned long plength = 0;
    OFFSET poffset = 0;
    ADDR pbase = 0;
    void *mmap = NULL;
    int rc;

    if (length == 0)
	return xen_vm_mem_builtin_read_phys_str(target,paddr);

    rc = memcache_get_mmap(target->memcache,0,paddr,length,0,
			   &pbase,&poffset,&mmap,&plength,NULL);
    if (rc == 0)
	goto out;
    else if (rc < 0) {
	vwarn("memcache_get_mmap error: p 0x%"PRIxADDR" len %lu: %s (%d); continuing\n",
	      paddr,length,strerror(errno),rc);
    }

    mmap = __xen_vm_mem_builtin_mmap_phys(target,paddr,length,PROT_READ,
					  &pbase,&poffset,&plength);
    if (!mmap)
	return NULL;

    rc = memcache_set_mmap(target->memcache,0,pbase,0,mmap,plength);
    if (rc == 1) {
	vdebug(5,LA_TARGET,LF_XV | LF_MEMCACHE,
	       "something already cached at p 0x%"PRIxADDR" len %lu"
	       " (for read p 0x%"PRIxADDR")!\n",
	       pbase,plength,paddr);
    }
    else if (rc < 0) {
	vwarn("memcache_set_mmap error: p 0x%"PRIxADDR" len %lu (for read p"
	      " 0x%"PRIxADDR": %s (%d); continuing\n",
	      pbase,plength,paddr,strerror(errno),rc);
    }

 out:
    memcpy(buf,mmap + poffset,length);
    /*
     * Only unmap if the mmap wasn't cache, or if we couldn't cache the
     * mmap we just made.
     */
    if (rc)
	munmap(mmap,plength);

    return buf;
}

unsigned long xen_vm_mem_builtin_write_phys(struct target *target,ADDR paddr,
					    unsigned long length,
					    unsigned char *buf) {
    unsigned long plength = 0;
    OFFSET poffset = 0;
    ADDR pbase = 0;
    void *mmap = NULL;
    int rc;

    rc = memcache_get_mmap(target->memcache,0,paddr,length,0,
			   &pbase,&poffset,&mmap,&plength,NULL);
    if (rc == 0)
	goto out;
    else if (rc < 0) {
	vwarn("memcache_get_mmap error: p 0x%"PRIxADDR" len %lu: %s (%d); continuing\n",
	      paddr,length,strerror(errno),rc);
    }

    mmap = __xen_vm_mem_builtin_mmap_phys(target,paddr,length,PROT_WRITE,
					  &pbase,&poffset,&plength);
    if (!mmap)
	return 0;

    rc = memcache_set_mmap(target->memcache,0,pbase,0,mmap,plength);
    if (rc == 1) {
	vdebug(5,LA_TARGET,LF_XV | LF_MEMCACHE,
	       "something already cached at p 0x%"PRIxADDR" len %lu"
	       " (for read p 0x%"PRIxADDR")!\n",
	       pbase,plength,paddr);
    }
    else if (rc < 0) {
	vwarn("memcache_set_mmap error: p 0x%"PRIxADDR" len %lu (for read p"
	      " 0x%"PRIxADDR": %s (%d); continuing\n",
	      pbase,plength,paddr,strerror(errno),rc);
    }

 out:
    memcpy(mmap + poffset,buf,length);
    /*
     * Only unmap if the mmap wasn't cache, or if we couldn't cache the
     * mmap we just made.
     */
    if (rc)
	munmap(mmap,plength);

    return length;
}

static void *__xen_vm_mem_builtin_mmap_virt(struct target *target,
					    tid_t tid,ADDR pgd,ADDR vaddr,
					    unsigned long length,int prot,
					    ADDR *vbase,OFFSET *voffset,
					    unsigned long *vlength) {
    struct xen_vm_state *xstate;
    xen_pfn_t *pfn_arr;
    int num,i,rc;
    ADDR paddr;
    OFFSET vaddr_offset;
    ADDR pfn;
    void *mmap;
    ADDR lvaddr;

    xstate = (struct xen_vm_state *)target->state;

    lvaddr = vaddr & ~(__PAGE_SIZE - 1);
    vaddr_offset = vaddr & (__PAGE_SIZE - 1);
    num = (vaddr_offset + length) / __PAGE_SIZE;
    if ((vaddr_offset + length) % __PAGE_SIZE)
	++num;
    //num = (length - vaddr_offset) / __PAGE_SIZE;
    //num += ((length - vaddr_offset) & (__PAGE_SIZE - 1)) ? 1 : 0;

    pfn_arr = calloc(num,sizeof(*pfn_arr));
    for (i = 0; i < num; ++i) {
	rc = xen_vm_mem_builtin_addr_v2p(target,tid,pgd,lvaddr + i * __PAGE_SIZE,
					 &paddr);
	if (rc) {
	    free(pfn_arr);
	    return NULL;
	}
	pfn = paddr / __PAGE_SIZE;
	pfn_arr[i] = pfn;
    }

    mmap = xc_map_foreign_pages(xc_handle,xstate->id,prot,pfn_arr,num);
    if (!mmap) {
	verror("failed to mmap %d pages at vaddr 0x%"PRIxADDR
	       " (for 0x%"PRIxADDR") (first page paddr 0x%"PRIxADDR")!\n",
	       num,lvaddr,vaddr,pfn_arr[0] * __PAGE_SIZE);
	if (!errno)
	    errno = EFAULT;
	return NULL;
    }
    else {
	if (vbase)
	    *vbase = lvaddr;
	if (voffset)
	    *voffset = vaddr_offset;
	if (vlength)
	    *vlength = num * __PAGE_SIZE;

	vdebug(8,LA_TARGET,LF_XV,
	       "mmap'd %d pages at virt 0x%"PRIxADDR" (for 0x%"PRIxADDR" at 0x%p\n",
	       num,vbase,vaddr,mmap);

	return mmap;
    }
}

unsigned char *xen_vm_mem_builtin_read_v_str(struct target *target,
					     tid_t tid,ADDR pgd,ADDR addr) {
    ADDR lvaddr;
    OFFSET voffset = 0;
    char *mmap = NULL;
    unsigned long mlen;
    int rc,i,j,pad;
    ADDR paddr;
    char *lbuf = NULL;
    int lbuf_alen = 0,lbuf_len = 0;
    OFFSET coffset;
    short didmmap,savedmmap;
    ADDR pbase;
    unsigned long plength = 0;

    /*
     * Ok, translate vaddrs to paddrs page by page until we see a '\0'.
     *
     * NB:Cache physical pages as tid 0!
     */

    lvaddr = addr & ~(__PAGE_SIZE - 1);
    voffset = addr & (__PAGE_SIZE - 1);
    for (i = 0; ; ++i) {
	rc = xen_vm_mem_builtin_addr_v2p(target,tid,pgd,lvaddr + i * __PAGE_SIZE,
					 &paddr);
	if (rc) {
	    verror("could not translate v 0x%"PRIxADDR"; start v 0x%"PRIxADDR"!\n",
		   lvaddr,addr);
	    if (lbuf)
		free(lbuf);
	    return NULL;
	}
	mlen = __PAGE_SIZE;
	coffset = 0;
	if (i == 0) {
	    mlen -= voffset;
	    coffset = voffset;
	}

	rc = memcache_get_mmap(target->memcache,0,paddr,1,MEMCACHE_PHYS,
			       &pbase,NULL,(void **)&mmap,&plength,NULL);
	if (rc < 0) {
	    vwarn("memcache_get_mmap error: v 0x%"PRIxADDR" len %lu: %s (%d); continuing\n",
		  addr,1ul,strerror(errno),rc);
	}
	if (!mmap) {
	    mmap = __xen_vm_mem_builtin_mmap_phys(target,paddr,mlen,PROT_WRITE,
						  NULL,NULL,NULL);
	    if (!mmap) {
		verror("could not mmap p 0x%"PRIxADDR" (after translating"
		       " v 0x%"PRIxADDR"; start v 0x%"PRIxADDR")!\n",
		       paddr,lvaddr,addr);
		if (lbuf)
		    free(lbuf);
		return NULL;
	    }
	    didmmap = savedmmap = 0;
	}
	else {
	    /* Cache it. */
	    didmmap = 1;
	    savedmmap = 0;
	    rc = memcache_set_mmap(target->memcache,0,pbase,MEMCACHE_PHYS,
				   mmap,plength);
	    if (rc == 1) {
		vdebug(5,LA_TARGET,LF_XV | LF_MEMCACHE,
		       "something already cached at p 0x%"PRIxADDR" len %lu"
		       " for read v 0x%"PRIxADDR"; skipping!\n",
		       pbase,plength,addr);
	    }
	    else if (rc < 0) {
		vwarn("memcache_set_mmap error: p 0x%"PRIxADDR" len %lu (for read"
		      " v 0x%"PRIxADDR": %s (%d); continuing\n",
		      pbase,plength,addr,strerror(errno),rc);
	    }
	    else {
		savedmmap = 1;
	    }
	}

	/*
	 * Scan the mmap as necessary for '\0', malloc as necessary, and
	 * break or keep going.
	 */
	for (j = coffset; j < __PAGE_SIZE; ++j) {
	    if (mmap[j] == '\0')
		break;
	}

	pad = (j < __PAGE_SIZE) ? 1 : 0;
	if (!lbuf) {
	    lbuf_alen = j - coffset + pad;
	    lbuf = malloc(lbuf_alen);
	}
	else {
	    lbuf_alen += j - coffset + pad;
	    lbuf = realloc(lbuf,lbuf_alen);
	}
	memcpy(lbuf + lbuf_len,mmap + coffset,j - coffset);
	lbuf_len += j - coffset;

	if (didmmap && !savedmmap)
	    munmap(mmap,plength);

	if (pad) {
	    lbuf[lbuf_len] = '\0';
	    break;
	}
    }

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
unsigned char *xen_vm_mem_builtin_read_tid(struct target *target,
					   tid_t tid,ADDR pgd,ADDR addr,
					   unsigned long length,
					   unsigned char *buf) {
    ADDR vbase = 0;
    unsigned long vlength = 0;
    OFFSET voffset = 0;
    void *mmap = NULL;
    int rc;

    if (length == 0)
	return xen_vm_mem_builtin_read_v_str(target,tid,pgd,addr);

    rc = memcache_get_mmap(target->memcache,pgd,addr,length,MEMCACHE_VIRT,
			   &vbase,&voffset,&mmap,&vlength,NULL);
    if (rc == 0)
	goto out;
    else if (rc < 0) {
	vwarn("memcache_get_mmap error: v 0x%"PRIxADDR" len %lu: %s (%d); continuing\n",
	      addr,length,strerror(errno),rc);
    }

    mmap = __xen_vm_mem_builtin_mmap_virt(target,tid,pgd,addr,length,PROT_WRITE,
					  &vbase,&voffset,&vlength);
    if (!mmap)
	return NULL;

    rc = memcache_set_mmap(target->memcache,pgd,vbase,MEMCACHE_VIRT,mmap,vlength);
    if (rc == 1) {
	vdebug(5,LA_TARGET,LF_XV | LF_MEMCACHE,
	       "something already cached at v 0x%"PRIxADDR" len %lu"
	       " (for read v 0x%"PRIxADDR")!\n",
	       vbase,vlength,addr);
    }
    else if (rc < 0) {
	vwarn("memcache_set_mmap error: p 0x%"PRIxADDR" len %lu (for read"
	      " v 0x%"PRIxADDR": %s (%d); continuing\n",
	      vbase,vlength,addr,strerror(errno),rc);
    }

 out:
    memcpy(buf,mmap + voffset,length);
    /*
     * Only unmap if the mmap wasn't cache, or if we couldn't cache the
     * mmap we just made.
     */
    if (rc)
	munmap(mmap,vlength);

    return buf;
}

/*
 * Writes @length bytes from @buf to @addr.  Returns the number of bytes
 * written (and sets errno nonzero if there is an error).  Successful if
 * @return == @length.
 */
unsigned long xen_vm_mem_builtin_write_tid(struct target *target,
					   tid_t tid,ADDR pgd,ADDR addr,
					   unsigned long length,
					   unsigned char *buf) {
    ADDR vbase = 0;
    unsigned long vlength = 0;
    OFFSET voffset = 0;
    void *mmap = NULL;
    int rc;

    rc = memcache_get_mmap(target->memcache,pgd,addr,length,MEMCACHE_VIRT,
			   &vbase,&voffset,&mmap,&vlength,NULL);
    if (rc == 0)
	goto out;
    else if (rc < 0) {
	vwarn("memcache_get_mmap error: v 0x%"PRIxADDR" len %lu: %s (%d); continuing\n",
	      addr,length,strerror(errno),rc);
    }

    mmap = __xen_vm_mem_builtin_mmap_virt(target,tid,pgd,addr,length,PROT_WRITE,
					  &vbase,&voffset,&vlength);
    if (!mmap)
	return 0;

    rc = memcache_set_mmap(target->memcache,pgd,vbase,MEMCACHE_VIRT,mmap,vlength);
    if (rc == 1) {
	vdebug(5,LA_TARGET,LF_XV | LF_MEMCACHE,
	       "something already cached at v 0x%"PRIxADDR" len %lu"
	       " (for read v 0x%"PRIxADDR")!\n",
	       vbase,vlength,addr);
    }
    else if (rc < 0) {
	vwarn("memcache_set_mmap error: p 0x%"PRIxADDR" len %lu (for read"
	      " v 0x%"PRIxADDR": %s (%d); continuing\n",
	      vbase,vlength,addr,strerror(errno),rc);
    }

 out:

    memcpy(mmap + voffset,buf,length);
    /*
     * Only unmap if the mmap wasn't cache, or if we couldn't cache the
     * mmap we just made.
     */
    if (rc)
	munmap(mmap,vlength);

    return length;
}

int xen_vm_mem_builtin_fini(struct target *target) {
    if (target->memcache) {
	memcache_destroy(target->memcache);
	target->memcache = NULL;
    }

    return 0;
}

struct xen_vm_mem_ops xen_vm_mem_ops_builtin = {
    .init = xen_vm_mem_builtin_init,
    .attach = xen_vm_mem_builtin_attach,
    .handle_exception_any = xen_vm_mem_builtin_handle_exception_any,
    .handle_exception_ours = xen_vm_mem_builtin_handle_exception_ours,
    .handle_pause = xen_vm_mem_builtin_handle_pause,
    .addr_v2p = xen_vm_mem_builtin_addr_v2p,
    .read_phys = xen_vm_mem_builtin_read_phys,
    .write_phys = xen_vm_mem_builtin_write_phys,
    .read_tid = xen_vm_mem_builtin_read_tid,
    .write_tid = xen_vm_mem_builtin_write_tid,
    .fini = xen_vm_mem_builtin_fini,
};
