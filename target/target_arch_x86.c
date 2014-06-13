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
#include "common.h"
#include "log.h"
#include "target.h"
#include "target_api.h"
#include "target_arch_x86.h"

#ifndef PAGE_SHIFT
#define PAGE_SHIFT 12
#endif

#define CR0_PG  0x80000000
#define CR4_PAE 0x20
#define EFER_LMA 0x400

#define PTE_PSE          (1 << 7)
#define PTE_DIRTY        (1 << 5)
#define PTE_NOCACHE      (1 << 4)
#define PTE_WRITETHROUGH (1 << 3)
#define PTE_USER         (1 << 2)
#define PTE_WRITE        (1 << 1)
#define PTE_PRESENT      (1 << 0)

int target_arch_x86_v2p_get_flags(struct target *target,REGVAL cr0,REGVAL cr4,
				  REGVAL msr_efer,REGVAL cpuid_edx,
				  arch_x86_v2p_flags_t *flags) {
    arch_x86_v2p_flags_t pflags = 0;

    if (!(cr0 & CR0_PG))
	pflags |= ARCH_X86_V2P_NOTPAGING;
    if (msr_efer & EFER_LMA)
	pflags |= ARCH_X86_V2P_LMA;
    if (cr4 & CR4_PAE)
	pflags |= ARCH_X86_V2P_PAE;
    /*
     * Detecting PSE itself doesn't really matter; we trust the
     * pagetables; but we would like to know if the CPU is in PSE-36 or
     * PSE-40 mode.  I haven't found a bit for PSE-40 support yet!
     *
     * NB: but -- the thing is, for PSE-36 -- the extra bits used for
     * PSE-36 in the PTE are reserved and must be zero anyway for the
     * regular PSE case!  Thus, just always do PSE-36.
     */
    if (!(cpuid_edx & (1 << 3)))
	pflags |= ARCH_X86_V2P_NOPSE;
    if (!(cpuid_edx & (1 << 17))) {
	pflags |= ARCH_X86_V2P_NOPSE36;
	/*
	 * XXX: just lump this in with PSE36 -- really we should check
	 * if this is an AMD64 CPU...
	 */
	pflags |= ARCH_X86_V2P_NOPSE40;
    }

    if (flags)
	*flags = pflags;

    return 0;
}

/*
Architecture	Bits used
		PGD	PUD	PMD	PTE
i386		22-31	  	 	12-21
i386-PAE	30-31	  	21-29	12-20
x86-64		39-47 	30-38 	21-29 	12-20
*/

int target_arch_x86_v2p(struct target *target,ADDR pgd,ADDR virt,
			arch_x86_v2p_flags_t flags,ADDR *phys) {
    int curlevel = 0;
    int ptlevels;
    ADDR pbase,paddr;
    ADDR retval;
    ADDR vmask;
    ADDR entry;
    unsigned int size = 8;
    unsigned int wordsizealignbits;
    int downshift;
    int shiftinc;
    ADDR entryaddrmask;
    ADDR nentry;

    if (target->arch->type != ARCH_X86 && target->arch->type != ARCH_X86_64) {
	errno = EINVAL;
	return -1;
    }

    vdebug(16,LA_TARGET,LF_TARGET,"lookup vaddr = 0x%"PRIxADDR"\n",virt);

    if (flags & ARCH_X86_V2P_NOTPAGING) {
	retval = virt >> PAGE_SHIFT;
	vdebug(16,LA_TARGET,LF_TARGET,"not paging; paddr = 0x%"PRIxADDR"\n",
	       retval);
	goto out;
    }

    if (flags & ARCH_X86_V2P_PV) {
	if (target->arch->type == ARCH_X86_64)
	    ptlevels = 4;
	else
	    /* Assume PAE. */
	    ptlevels = 3;
    }
    else if (flags & ARCH_X86_V2P_LMA)
	ptlevels = 4;
    else if (flags & ARCH_X86_V2P_PAE)
	ptlevels = 3;
    else {
	ptlevels = 2;
	size = 4;
    }

    /* x86-64 long mode. */
    if (ptlevels == 4) {
	downshift = 39;
	vmask = 0x01ffull << downshift;
	downshift -= 3;
	shiftinc = 9;
    }
    else if (ptlevels == 3) {
	/* The top level of PAE is special; these are for levels 2 and down. */
	downshift = 21;
	vmask = 0x01ffll << downshift;
	downshift -= 3;
	shiftinc = 9;
    }
    else if (ptlevels == 2) {
	downshift = 22;
	vmask = 0x03ffll << downshift;
	shiftinc = 10;
    }

    if (size == 8) {
	wordsizealignbits = 3;
	entryaddrmask = 0x00ffffffffff000ull; /* 40 bits, 12 through 51 */
    }
    else {
	wordsizealignbits = 2;
	entryaddrmask = 0xfffff000ull; /* 20 bits, 12 through 31 */
    }

    vdebug(16,LA_TARGET,LF_TARGET,
	   "lookup: pgd=0x%"PRIxADDR",ptlevels=%d,size=%u,"
	   "downshift=%d,shiftinc=%d,vmask=0x%"PRIxADDR","
	   "entryaddrmask=0x%"PRIxADDR"\n",
	   pgd,ptlevels,size,downshift,shiftinc,vmask,entryaddrmask);

    if (ptlevels == 4 || ptlevels == 3) {
	pbase = pgd;
	for (curlevel = ptlevels; curlevel > 0; --curlevel) {
	    if (ptlevels == 3 && ptlevels == curlevel) {
		/* Top level of PAE is special -- and remember to align
		   to wordsize! */
		paddr = pbase + (((0x03ull << 30) & virt) >> (30 - wordsizealignbits));
	    }
	    else {
		paddr = pbase + ((vmask & virt) >> downshift);
		/* adjust for next iteration */
		vmask >>= shiftinc;
		downshift -= shiftinc;
	    }

	    entry = 0;
	    if (!target_read_physaddr(target,paddr,size,(unsigned char *)&entry)) {
		verror("could not read L%d entry (pbase 0x%"PRIxADDR","
		       " paddr 0x%"PRIxADDR")!\n",curlevel,pbase,paddr);
		errno = EINVAL;
		return -1;
	    }

	    if (!(entry & PTE_PRESENT)) {
		vwarnopt(5,LA_TARGET,LF_TARGET,
			 "nonpresent L%d entry 0x%"PRIxADDR" (pbase 0x%"PRIxADDR
			 ", paddr 0x%"PRIxADDR"\n",curlevel,entry,pbase,paddr);
		errno = EADDRNOTAVAIL;
		return -1;
	    }
	    else if (curlevel == 3 && entry & PTE_PSE) {
		if (!(flags & ARCH_X86_V2P_NOPSE40))
		    nentry = 
			((entry & (0x0full << 12)) << 20) /* 16-13 -> 35-32 */
			| ((entry & (0x0full << 16)) << 16) /* 20-17 -> 39-36 */
			| ((entry & (0x03ffull << 21))); /* 31-22 -> 31-22 */
		else if (!(flags & ARCH_X86_V2P_NOPSE36))
		    nentry = 
			((entry & (0x0full << 12)) << 20) /* 16-13 -> 35-32 */
			| (entry & (0x03ffull << 21)); /* 31-22 -> 31-22 */
		else if (!(flags & ARCH_X86_V2P_NOPSE))
		    nentry = 
			(entry & ((0x03ffull << 21))); /* 31-22 -> 31-22 */
		else {
		    verror("PSE set in PTE, but PSE support disabled in CPU!!\n");
		    errno = EINVAL;
		    return -1;
		}

		/* Grab the offset */
		retval = nentry | (virt & 0x3fffffff);

		vdebug(16,LA_TARGET,LF_TARGET,
		       "lookup L%d: entry 0x%"PRIxADDR
		       " -> 1GB phys addr 0x%"PRIxADDR"\n",
		       curlevel,entry,retval);

		goto out;
	    }
	    else if (curlevel == 2 && entry & PTE_PSE) {
		if (!(flags & ARCH_X86_V2P_NOPSE40))
		    nentry = 
			((entry & (0x0full << 12)) << 20) /* 16-13 -> 35-32 */
			| ((entry & (0x0full << 16)) << 16) /* 20-17 -> 39-36 */
			| ((entry & (0x03ffull << 21))); /* 31-22 -> 31-22 */
		else if (!(flags & ARCH_X86_V2P_NOPSE36))
		    nentry = 
			((entry & (0x0full << 12)) << 16) /* 16-13 -> 35-32 */
			| ((entry & (0x03ffull << 21))); /* 31-22 -> 31-22 */
		else if (!(flags & ARCH_X86_V2P_NOPSE))
		    nentry = 
			(entry & ((0x03ffull << 21))); /* 31-22 -> 31-22 */
		else {
		    verror("PSE set in PTE, but PSE support disabled in CPU!!\n");
		    errno = EINVAL;
		    return -1;
		}

		/* Grab the offset */
		retval = nentry | (virt & 0x0001fffff);

		vdebug(16,LA_TARGET,LF_TARGET,
		       "lookup L%d: entry 0x%"PRIxADDR
		       " -> 2MB phys addr 0x%"PRIxADDR"\n",
		       curlevel,nentry,retval);

		goto out;
	    }
	    else {
		pbase = (entryaddrmask & entry);

		vdebug(16,LA_TARGET,LF_TARGET,
		       "lookup L%d: entry 0x%"PRIxADDR" -> table 0x%"PRIxADDR"\n",
		       curlevel,entry,pbase);
	    }
	}

	/*
	 * If we get here, we have walked the tables and just need to
	 * grab the index from the vaddr according to target page size;
	 * XXX assume 4K pages for now.
	 */
	retval = pbase | (virt & 0x0fffull);
    }
    else {
	pbase = pgd;
	for (curlevel = ptlevels; curlevel > 0; --curlevel) {
	    paddr = pbase + ((vmask & virt) >> downshift);
	    vmask >>= shiftinc;
	    downshift -= shiftinc;

	    entry = 0;
	    if (!target_read_physaddr(target,paddr,size,(unsigned char *)&entry)) {
		verror("could not read L%d entry (pbase 0x%"PRIxADDR","
		       " paddr 0x%"PRIxADDR")!\n",curlevel,pbase,paddr);
		errno = EINVAL;
		return 0;
	    }

	    if (!(entry & PTE_PRESENT)) {
		vwarnopt(5,LA_TARGET,LF_TARGET,
			 "nonpresent L%d entry 0x%"PRIxADDR" (pbase 0x%"PRIxADDR
			 ", paddr 0x%"PRIxADDR"\n",curlevel,entry,pbase,paddr);
		errno = EADDRNOTAVAIL;
		return 0;
	    }
	    else if (curlevel == 2 && entry & PTE_PSE) {
		if (!(flags & ARCH_X86_V2P_NOPSE40))
		    retval = 
			(entry & ((0x0full << 13) << 19)) /* 16-13 -> 35-32 */
			| (entry & ((0x0full << 17) << 15)) /* 20-17 -> 39-36 */
			| (entry & ((0x03ffull << 22))); /* 31-22 -> 31-22 */
		else if (!(flags & ARCH_X86_V2P_NOPSE36))
		    retval = 
			(entry & ((0x0full << 13) << 19)) /* 16-13 -> 35-32 */
			| (entry & ((0x03ffull << 22))); /* 31-22 -> 31-22 */
		else if (!(flags & ARCH_X86_V2P_NOPSE))
		    retval = 
			(entry & ((0x03ffull << 22))); /* 31-22 -> 31-22 */
		else {
		    verror("PSE set in PTE, but PSE support disabled in CPU!!\n");
		    errno = EINVAL;
		    return -1;
		}

		/* Grab the offset */
		retval |= (virt & 0x0001fffff);

		vdebug(16,LA_TARGET,LF_TARGET,
		       "lookup L%d: entry 0x%"PRIxADDR
		       " -> 2MB phys addr 0x%"PRIxADDR"\n",
		       curlevel,entry,retval);

		goto out;
	    }
	    else {
		pbase = (entryaddrmask & entry);

		vdebug(16,LA_TARGET,LF_TARGET,
		       "lookup L%d: entry 0x%"PRIxADDR" -> table 0x%"PRIxADDR"\n",
		       curlevel,entry,pbase);
	    }
	}

	/*
	 * If we get here, we have walked the tables and just need to
	 * grab the index from the vaddr according to target page size;
	 * XXX assume 4K pages for now.
	 */
	retval = entry | (virt & 0x0fffull);
    }

 out:
    if (curlevel == 0) {
	vdebug(16,LA_TARGET,LF_TARGET,"paddr = 0x%"PRIxADDR"\n",retval);
    }
    /* Done! */
    if (phys)
	*phys = retval;

    return 0;
}

int target_arch_x86_v2p_flags_snprintf(struct target *target,
				       arch_x86_v2p_flags_t flags,
				       char *buf,unsigned int bufsiz) {
    unsigned int remaining = bufsiz;

    if (flags & ARCH_X86_V2P_NOTPAGING) {
	strncpy(buf + (bufsiz - remaining),"NOTPAGING,",remaining);
	if (strlen("NOTPAGING,") > remaining) {
	    buf[bufsiz-1] = '\0';
	    return bufsiz;
	}
	else
	    remaining -= strlen("NOTPAGING,");
    }
    if (flags & ARCH_X86_V2P_PAE) {
	strncpy(buf + (bufsiz - remaining),"PAE,",remaining);
	if (strlen("PAE,") > remaining) {
	    buf[bufsiz-1] = '\0';
	    return bufsiz;
	}
	else
	    remaining -= strlen("PAE,");
    }
    if (flags & ARCH_X86_V2P_NOPSE) {
	strncpy(buf + (bufsiz - remaining),"NOPSE,",remaining);
	if (strlen("NOPSE,") > remaining) {
	    buf[bufsiz-1] = '\0';
	    return bufsiz;
	}
	else
	    remaining -= strlen("NOPSE,");
    }
    if (flags & ARCH_X86_V2P_NOPSE36) {
	strncpy(buf + (bufsiz - remaining),"NOPSE36,",remaining);
	if (strlen("NOPSE36,") > remaining) {
	    buf[bufsiz-1] = '\0';
	    return bufsiz;
	}
	else
	    remaining -= strlen("NOPSE36,");
    }
    if (flags & ARCH_X86_V2P_NOPSE40) {
	strncpy(buf + (bufsiz - remaining),"NOPSE40,",remaining);
	if (strlen("NOPSE40,") > remaining) {
	    buf[bufsiz-1] = '\0';
	    return bufsiz;
	}
	else
	    remaining -= strlen("NOPSE40,");
    }
    if (flags & ARCH_X86_V2P_LMA) {
	strncpy(buf + (bufsiz - remaining),"LMA,",remaining);
	if (strlen("LMA,") > remaining) {
	    buf[bufsiz-1] = '\0';
	    return bufsiz;
	}
	else
	    remaining -= strlen("LMA,");
    }
    if (flags & ARCH_X86_V2P_PV) {
	strncpy(buf + (bufsiz - remaining),"PV,",remaining);
	if (strlen("PV,") > remaining) {
	    buf[bufsiz-1] = '\0';
	    return bufsiz;
	}
	else
	    remaining -= strlen("PV,");
    }

    if (remaining >= bufsiz)
	buf[bufsiz - 1] = '\0';
    else
	buf[bufsiz - remaining] = '\0';

    return bufsiz - remaining;
}
