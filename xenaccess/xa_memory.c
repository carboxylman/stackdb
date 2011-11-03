/*
 * The libxa library provides access to resources in domU machines.
 * 
 * Copyright (C) 2005 - 2008  Bryan D. Payne (bryan@thepaynes.cc)
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * --------------------
 * This file contains functions for sharing the memory of a domU
 * machine.  The functions basically only differ in how the memory
 * is referenced (pfn, mfn, virtual address, physical address, etc).
 *
 * File: xa_memory.c
 *
 * Author(s): Bryan D. Payne (bryan@thepaynes.cc)
 */

#include <stdlib.h>
#include <sys/mman.h>
#include "xenaccess.h"
#include "xa_private.h"

/* hack to get this to compile on xen 3.0.4 */
#ifndef XENMEM_maximum_gpfn
#define XENMEM_maximum_gpfn 0
#endif

/* convert a pfn to a mfn based on the live mapping tables */
unsigned long helper_pfn_to_mfn (xa_instance_t *instance, unsigned long pfn)
{
#ifdef ENABLE_XEN
    shared_info_t *live_shinfo = NULL;
    unsigned long *live_pfn_to_mfn_frame_list_list = NULL;
    unsigned long *live_pfn_to_mfn_frame_list = NULL;

    /* Live mapping of the table mapping each PFN to its current MFN. */
    unsigned long *live_pfn_to_mfn_table = NULL;
    unsigned long nr_pfns = 0;
    unsigned long ret = -1;
//    unsigned long mfn;
//    int i;

    if (instance->hvm){
        return pfn;
    }

    if (NULL == instance->m.xen.live_pfn_to_mfn_table){
        live_shinfo = xa_mmap_mfn(
            instance, PROT_READ, instance->m.xen.info.shared_info_frame);
        if (live_shinfo == NULL){
            printf("ERROR: failed to init live_shinfo\n");
            goto error_exit;
        }

        if (instance->m.xen.xen_version == XA_XENVER_3_1_0){
            nr_pfns = xc_memory_op(
                        instance->m.xen.xc_handle,
                        XENMEM_maximum_gpfn,
                        &(instance->m.xen.domain_id)) + 1;
        }
        else{
            nr_pfns = live_shinfo->arch.max_pfn;
        }

        live_pfn_to_mfn_frame_list_list = xa_mmap_mfn(
            instance, PROT_READ, live_shinfo->arch.pfn_to_mfn_frame_list_list);
        if (live_pfn_to_mfn_frame_list_list == NULL){
            printf("ERROR: failed to init live_pfn_to_mfn_frame_list_list\n");
            goto error_exit;
        }

        live_pfn_to_mfn_frame_list = xc_map_foreign_batch(
            instance->m.xen.xc_handle,
            instance->m.xen.domain_id,
            PROT_READ,
            live_pfn_to_mfn_frame_list_list,
            (nr_pfns+(fpp*fpp)-1)/(fpp*fpp) );
        if (live_pfn_to_mfn_frame_list == NULL){
            printf("ERROR: failed to init live_pfn_to_mfn_frame_list\n");
            goto error_exit;
        }

        live_pfn_to_mfn_table = xc_map_foreign_batch(
            instance->m.xen.xc_handle,
            instance->m.xen.domain_id,
            PROT_READ,
            live_pfn_to_mfn_frame_list, (nr_pfns+fpp-1)/fpp );
        if (live_pfn_to_mfn_table  == NULL){
            printf("ERROR: failed to init live_pfn_to_mfn_table\n");
            goto error_exit;
        }

        /*TODO validate the mapping */
//        for (i = 0; i < nr_pfns; ++i){
//            mfn = live_pfn_to_mfn_table[i];
//            if( (mfn != INVALID_P2M_ENTRY) && (mfn_to_pfn(mfn) != i) )
//            {
//                DPRINTF("i=0x%x mfn=%lx live_m2p=%lx\n", i,
//                        mfn, mfn_to_pfn(mfn));
//                err++;
//            }
//        }

        /* save mappings for later use */
        instance->m.xen.live_pfn_to_mfn_table = live_pfn_to_mfn_table;
        instance->m.xen.nr_pfns = nr_pfns;
    }

    ret = instance->m.xen.live_pfn_to_mfn_table[pfn];

error_exit:
    if (live_shinfo) munmap(live_shinfo, XC_PAGE_SIZE);
    if (live_pfn_to_mfn_frame_list_list)
        munmap(live_pfn_to_mfn_frame_list_list, XC_PAGE_SIZE);
    if (live_pfn_to_mfn_frame_list)
        munmap(live_pfn_to_mfn_frame_list, XC_PAGE_SIZE);

    return ret;
#else
    return 0;
#endif /* ENABLE_XEN */
}

void *xa_mmap_mfn (xa_instance_t *instance, int prot, unsigned long mfn)
{
//    xa_dbprint(0,"--MapMFN: Mapping mfn = 0x%.8x.\n", (unsigned int)mfn);
    return xa_map_page(instance, prot, mfn);
}

void *xa_mmap_pfn (xa_instance_t *instance, int prot, unsigned long pfn)
{
    unsigned long mfn = -1;

    if (XA_MODE_XEN == instance->mode){
        mfn = helper_pfn_to_mfn(instance, pfn);
    }
    else if (XA_MODE_FILE == instance->mode){
        mfn = pfn;
    }

    if (-1 == mfn){
        printf("ERROR: pfn to mfn mapping failed.\n");
        return NULL;
    }
    else{
//        xa_dbprint(0,"--MapPFN: Mapping mfn = %lu / pfn = %lu.\n", mfn, pfn);
        return xa_map_page(instance, prot, mfn);
    }
}

/* bit flag testing */
int entry_present (unsigned long entry){
    return xa_get_bit(entry, 0);
}

int page_size_flag (unsigned long entry){
    return xa_get_bit(entry, 7);
}

/* page directory pointer table */
uint32_t get_pdptb (uint32_t pdpr){
    return pdpr & 0xFFFFFFE0;
}

uint32_t pdpi_index (uint32_t pdpi){
    return (pdpi >> 30) * sizeof(uint64_t);
}

uint64_t get_pdpi (
        xa_instance_t *instance, uint32_t vaddr, uint32_t cr3, int k)
{
    uint64_t value;
    uint32_t pdpi_entry = get_pdptb(cr3) + pdpi_index(vaddr);
    xa_dbprint(0,"--PTLookup: pdpi_entry = 0x%.8x\n", pdpi_entry);
    if (k){
        xa_read_long_long_mach(instance, pdpi_entry, &value);
    }
    else{
        xa_read_long_long_virt(instance, pdpi_entry, 0, &value);
    }
    return value;
}

/* page directory */
uint32_t pgd_index (xa_instance_t *instance, uint32_t address){
    if (!instance->pae){
        return (((address) >> 22) & 0x3FF) * sizeof(uint32_t);
    }
    else{
        return (((address) >> 21) & 0x1FF) * sizeof(uint64_t);
    }
}

uint32_t pdba_base_nopae (uint32_t pdpe){
    return pdpe & 0xFFFFF000;
}

uint64_t pdba_base_pae (uint64_t pdpe){
    return pdpe & 0xFFFFFF000ULL;
}

uint32_t get_pgd_nopae (
        xa_instance_t *instance, uint32_t vaddr, uint32_t pdpe, int k)
{
    uint32_t value;
    uint32_t pgd_entry = pdba_base_nopae(pdpe) + pgd_index(instance, vaddr);
    xa_dbprint(0,"--PTLookup: pgd_entry = 0x%.8x\n", pgd_entry);
    if (k){
        xa_read_long_mach(instance, pgd_entry, &value);
    }
    else{
        xa_read_long_virt(instance, pgd_entry, 0, &value);
    }
    return value;
}

uint64_t get_pgd_pae (
        xa_instance_t *instance, uint32_t vaddr, uint64_t pdpe, int k)
{
    uint64_t value;
    uint32_t pgd_entry = pdba_base_pae(pdpe) + pgd_index(instance, vaddr);
    xa_dbprint(0,"--PTLookup: pgd_entry = 0x%.8x\n", pgd_entry);
    xa_read_long_long_mach(instance, pgd_entry, &value);
    return value;
}

/* page table */
uint32_t pte_index (xa_instance_t *instance, uint32_t address){
    if (!instance->pae){
        return (((address) >> 12) & 0x3FF) * sizeof(uint32_t);
    }
    else{
        return (((address) >> 12) & 0x1FF) * sizeof(uint64_t); 
    }
}
        
uint32_t ptba_base_nopae (uint32_t pde){
    return pde & 0xFFFFF000;
}

uint64_t ptba_base_pae (uint64_t pde){
    return pde & 0xFFFFFF000ULL;
}

uint32_t get_pte_nopae (xa_instance_t *instance, uint32_t vaddr, uint32_t pgd){
    uint32_t value;
    uint32_t pte_entry = ptba_base_nopae(pgd) + pte_index(instance, vaddr);
    xa_dbprint(0,"--PTLookup: pte_entry = 0x%.8x\n", pte_entry);
    xa_read_long_mach(instance, pte_entry, &value);
    return value;
}

uint64_t get_pte_pae (xa_instance_t *instance, uint32_t vaddr, uint64_t pgd){
    uint64_t value;
    uint32_t pte_entry = ptba_base_pae(pgd) + pte_index(instance, vaddr);
    xa_dbprint(0,"--PTLookup: pte_entry = 0x%.8x\n", pte_entry);
    xa_read_long_long_mach(instance, pte_entry, &value);
    return value;
}

/* page */
#define _PAGE_PRESENT	0x001
#define _PAGE_RW	0x002
#define _PAGE_USER	0x004
#define _PAGE_PWT	0x008
#define _PAGE_PCD	0x010
#define _PAGE_ACCESSED	0x020
#define _PAGE_DIRTY	0x040
#define _PAGE_PSE	0x080	/* 4 MB (or 2MB) page, Pentium+, if present.. */
#define _PAGE_GLOBAL	0x100	/* Global TLB entry PPro+ */
#define _PAGE_UNUSED1	0x200	/* available for programmer */
#define _PAGE_UNUSED2	0x400
#define _PAGE_UNUSED3	0x800

/* If _PAGE_PRESENT is clear, we use these: */
#define _PAGE_FILE	0x040	/* nonlinear file mapping, saved PTE; unset:swap */
#define _PAGE_PROTNONE	0x080	/* if the user mapped it with PROT_NONE;
				   pte_present gives true */
#define _PAGE_NX	(1ULL << 63 )

void pte_dumpflags_nopae(uint32_t pte) {
    if (pte & _PAGE_PRESENT)
	xa_dbprint_plain(0,"PRESENT ");
    if (pte & _PAGE_RW)
	xa_dbprint_plain(0,"RW ");
    if (pte & _PAGE_USER)
	xa_dbprint_plain(0,"USER ");
    if (pte & _PAGE_PWT)
	xa_dbprint_plain(0,"PWT ");
    if (pte & _PAGE_PCD)
	xa_dbprint_plain(0,"PCD ");
    if (pte & _PAGE_ACCESSED)
	xa_dbprint_plain(0,"ACCESSED ");
    if (pte & _PAGE_DIRTY)
	xa_dbprint_plain(0,"DIRTY ");
    if (pte & _PAGE_PSE)
	xa_dbprint_plain(0,"PSE ");
    if (pte & _PAGE_GLOBAL)
	xa_dbprint_plain(0,"GLOBAL ");
    if (!(pte & _PAGE_PRESENT)) {
	if (pte & _PAGE_FILE)
	    xa_dbprint_plain(0,"FILE ");
	if (pte & _PAGE_PROTNONE)
	    xa_dbprint_plain(0,"PROTNONE ");
    }
}

void pte_dumpflags_pae(uint64_t pte) {
    pte_dumpflags_nopae((uint32_t)(0xfff & pte));
    if (pte & _PAGE_NX)
	xa_dbprint_plain(0,"NX ");
}

uint32_t pte_pfn_nopae (uint32_t pte){
    return pte & 0xFFFFF000;
}

uint64_t pte_pfn_pae (uint64_t pte){
    return pte & 0xFFFFFF000ULL;
}

uint32_t get_paddr_nopae (uint32_t vaddr, uint32_t pte){
    return pte_pfn_nopae(pte) | (vaddr & 0xFFF);
}

uint64_t get_paddr_pae (uint32_t vaddr, uint64_t pte){
    return pte_pfn_pae(pte) | (vaddr & 0xFFF);
}

uint32_t get_large_paddr (
        xa_instance_t *instance, uint32_t vaddr, uint32_t pgd_entry)
{
    if (!instance->pae){
        return (pgd_entry & 0xFFC00000) | (vaddr & 0x3FFFFF);
    }
    else{
        return (pgd_entry & 0xFFE00000) | (vaddr & 0x1FFFFF);
    }
}

/* "buffalo" routines
 * see "Using Every Part of the Buffalo in Windows Memory Analysis" by
 * Jesse D. Kornblum for details. 
 * for now, just test the bits and print out details */
int get_transition_bit(uint32_t entry)
{
    return xa_get_bit(entry, 11);
}

int get_prototype_bit(uint32_t entry)
{
    return xa_get_bit(entry, 10);
}

void buffalo_nopae (xa_instance_t *instance, uint32_t entry, int pde)
{
    /* similar techniques are surely doable in linux, but for now
     * this is only testing for windows domains */
    if (!instance->os_type == XA_OS_WINDOWS){
        return;
    }

    if (!get_transition_bit(entry) && !get_prototype_bit(entry)){
        uint32_t pfnum = (entry >> 1) & 0xF;
        uint32_t pfframe = entry & 0xFFFFF000;

        /* pagefile */
        if (pfnum != 0 && pfframe != 0){
            xa_dbprint(0,"--Buffalo: page file = %d, frame = 0x%.8x\n",
                pfnum, pfframe);
        }
        /* demand zero */
        else if (pfnum == 0 && pfframe == 0){
            xa_dbprint(0,"--Buffalo: demand zero page\n");
        }
    }

    else if (get_transition_bit(entry) && !get_prototype_bit(entry)){
        /* transition */
        xa_dbprint(0,"--Buffalo: page in transition\n");
    }

    else if (!pde && get_prototype_bit(entry)){
        /* prototype */
        xa_dbprint(0,"--Buffalo: prototype entry\n");
    }

    else if (entry == 0){
        /* zero */
        xa_dbprint(0,"--Buffalo: entry is zero\n");
    }

    else{
        /* zero */
        xa_dbprint(0,"--Buffalo: unknown\n");
    }
}

/* translation */
uint32_t v2p_nopae(xa_instance_t *instance, uint32_t cr3, uint32_t vaddr, int k)
{
    uint32_t paddr = 0;
    uint32_t pgd, pte;
        
    xa_dbprint(0,"--PTLookup: lookup vaddr = 0x%.8x\n", vaddr);
    xa_dbprint(0,"--PTLookup: cr3 = 0x%.8x\n", cr3);
    pgd = get_pgd_nopae(instance, vaddr, cr3, k);
    xa_dbprint(0,"--PTLookup: pgd = 0x%.8x\n", pgd);
        
    if (entry_present(pgd)){
        if (page_size_flag(pgd)){
            paddr = get_large_paddr(instance, vaddr, pgd);
            xa_dbprint(0,"--PTLookup: 4MB page\n", pgd);
        }
        else{
            pte = get_pte_nopae(instance, vaddr, pgd);
            xa_dbprint(0,"--PTLookup: pte = 0x%.8x (", pte);
	    pte_dumpflags_nopae(pte);
	    xa_dbprint_plain(0,")\n");
            if (entry_present(pte)){
                paddr = get_paddr_nopae(vaddr, pte);
            }
            else{
                buffalo_nopae(instance, pte, 1);
            }
        }
    }
    else{
        buffalo_nopae(instance, pgd, 0);
    }
    xa_dbprint(0,"--PTLookup: paddr = 0x%.8x\n", paddr);
    return paddr;
}

uint32_t v2p_pae (xa_instance_t *instance, uint32_t cr3, uint32_t vaddr, int k)
{
    uint32_t paddr = 0;
    uint64_t pdpe, pgd, pte;
        
    xa_dbprint(0,"--PTLookup: lookup vaddr = 0x%.8x\n", vaddr);
    xa_dbprint(0,"--PTLookup: cr3 = 0x%.8x\n", cr3);
    pdpe = get_pdpi(instance, vaddr, cr3, k);
    xa_dbprint(0,"--PTLookup: pdpe = 0x%.16x\n", pdpe);
    if (!entry_present(pdpe)){
        return paddr;
    }
    pgd = get_pgd_pae(instance, vaddr, pdpe, k);
    xa_dbprint(0,"--PTLookup: pgd = 0x%.16x\n", pgd);

    if (entry_present(pgd)){
        if (page_size_flag(pgd)){
            paddr = get_large_paddr(instance, vaddr, pgd);
            xa_dbprint(0,"--PTLookup: 2MB page\n");
        }
        else{
            pte = get_pte_pae(instance, vaddr, pgd);
            xa_dbprint(0,"--PTLookup: pte = 0x%.16x (", pte);
	    pte_dumpflags_pae(pte);
	    xa_dbprint_plain(0,")\n");
            if (entry_present(pte)){
                paddr = get_paddr_pae(vaddr, pte);
            }
        }
    }
    xa_dbprint(0,"--PTLookup: paddr = 0x%.8x\n", paddr);
    return paddr;
}

/* convert address to machine address via page tables */
uint32_t xa_pagetable_lookup (
            xa_instance_t *instance,
            uint32_t cr3,
            uint32_t vaddr,
            int kernel)
{
    if (instance->pae){
        return v2p_pae(instance, cr3, vaddr, kernel);
    }
    else{
        return v2p_nopae(instance, cr3, vaddr, kernel);
    }
}

uint32_t xa_current_cr3 (xa_instance_t *instance, uint32_t *cr3)
{
    int ret = XA_SUCCESS;
#ifdef ENABLE_XEN
#ifdef HAVE_CONTEXT_ANY
    vcpu_guest_context_any_t ctxt_any;
#endif /* HAVE_CONTEXT_ANY */
    vcpu_guest_context_t ctxt;
#endif /* ENABLE_XEN */

    if (XA_MODE_XEN == instance->mode){
#ifdef ENABLE_XEN
#ifdef HAVE_CONTEXT_ANY
        if ((ret = xc_vcpu_getcontext(
                instance->m.xen.xc_handle,
                instance->m.xen.domain_id,
                0, /*TODO vcpu, assuming only 1 for now */
                &ctxt_any)) != 0){
#else
        if ((ret = xc_vcpu_getcontext(
                instance->m.xen.xc_handle,
                instance->m.xen.domain_id,
                0, /*TODO vcpu, assuming only 1 for now */
                &ctxt)) != 0){
#endif /* HAVE_CONTEXT_ANY */
	    const xc_error *e = xc_get_last_error();
            printf("ERROR: failed to get context information: %d, %s.\n",e->code,e->message);
            ret = XA_FAILURE;
            goto error_exit;
        }
#ifdef HAVE_CONTEXT_ANY
        *cr3 = ctxt_any.c.ctrlreg[3] & 0xFFFFF000;
#else
        *cr3 = ctxt.ctrlreg[3] & 0xFFFFF000;
#endif /* HAVE_CONTEXT_ANY */
#endif /* ENABLE_XEN */
    }
    else if (XA_MODE_FILE == instance->mode){
        *cr3 = instance->kpgd - instance->page_offset;
    }

error_exit:
    return ret;
}

/* expose virtual to physical mapping via api call */
uint32_t xa_translate_kv2p(xa_instance_t *instance, uint32_t virt_address)
{
    uint32_t cr3 = 0;
    xa_current_cr3(instance, &cr3);
    return xa_pagetable_lookup(instance, cr3, virt_address, 1);
}

/* map memory given a kernel symbol */
void *xa_access_kernel_sym (
        xa_instance_t *instance, char *symbol, uint32_t *offset, int prot)
{
    if (XA_OS_LINUX == instance->os_type){
        return linux_access_kernel_symbol(instance, symbol, offset, prot);
    }
    else if (XA_OS_WINDOWS == instance->os_type){
        return windows_access_kernel_symbol(instance, symbol, offset, prot);
    }
    else{
        return NULL;
    }
}

/*TODO fix these functions to return machine address just like real CR3 */
/* finds the address of the page global directory for a given pid */
uint32_t xa_pid_to_pgd (xa_instance_t *instance, int pid)
{
    xa_dbprint(1,"pid=%d\n", pid);
    /* first check the cache */
    uint32_t pgd = 0;
    if (xa_check_pid_cache(instance, pid, &pgd)){
	xa_dbprint(1,"pgd=%08x\n", pgd);
        return pgd;
    }

    /* otherwise do the lookup */
    if (XA_OS_LINUX == instance->os_type){
        pgd = linux_pid_to_pgd(instance, pid);
    }
    else if (XA_OS_WINDOWS == instance->os_type){
        pgd = windows_pid_to_pgd(instance, pid);
    }

    xa_dbprint(1,"pgd=%08x\n", pgd);
    return pgd;
}

void *xa_access_user_va (
        xa_instance_t *instance,
        uint32_t virt_address,
        uint32_t *offset,
        int pid,
        int prot)
{
    uint32_t address = 0;

    xa_dbprint(0,"va = %08x, pid = %d\n", virt_address, pid);

    /* check the LRU cache */
    if (xa_check_cache_virt(instance, virt_address, pid, &address)){
        return xa_access_ma(instance, address, offset, PROT_READ);
    }

    /* use kernel page tables */
    /*TODO HYPERVISOR_VIRT_START = 0xFC000000 so we can't go over that.
      Figure out what this should be b/c there still may be a fixed
      mapping range between the page'd addresses and VIRT_START */
    if (!pid){
        uint32_t cr3 = 0;
        xa_current_cr3(instance, &cr3);
        address = xa_pagetable_lookup(instance, cr3, virt_address, 1);
        if (!address){
            xa_dbprint(0,"ERROR: address (k) not in page table (0x%x)\n",virt_address);
            return NULL;
        }
    }

    /* use user page tables */
    else{
        uint32_t pgd = xa_pid_to_pgd(instance, pid);
	int kernel = 0;
	if (pgd) {
	    xa_dbprint(0,"--UserVirt: pgd for pid=%d is 0x%.8x.\n", pid, pgd);
	}
	else {
	    kernel = 1;
	    xa_current_cr3(instance, &pgd);
	    xa_dbprint(0,"--UserVirt: pgd for pid=%d is 0; using kernel pgd 0x%.8x instead!\n", pid, pgd);
	}

        if (pgd){
            address = xa_pagetable_lookup(instance, pgd, virt_address, kernel);
        }

        if (!address){
            xa_dbprint(0,"ERROR: address (u) not in page table (0x%x)\n",virt_address);
            return NULL;
        }
    }

    /* update cache and map the memory */
    xa_update_cache(instance, NULL, virt_address, pid, address);
    return xa_access_ma(instance, address, offset, prot);
}

/*TODO find a way to support this in file mode */
void *xa_access_user_va_range (
        xa_instance_t *instance,
        uint32_t virt_address,
        uint32_t size,
        uint32_t *offset,
        int pid,
        int prot)
{
    xa_dbprint(0,"va = %08x, pid = %d, size = %d\n", virt_address, pid, size);
#ifdef ENABLE_XEN
    void *retval = NULL;
    int i;
    unsigned long maddr;
    int kernel = !pid;
    int tmp_offset;

    uint32_t num_pages = size / instance->page_size;
    uint32_t start = virt_address & ~(instance->page_size-1);
    tmp_offset = virt_address - start;

    // add a page if we weren't an exact multiple of the page size
    if (size == 0 || size % instance->page_size)
	++num_pages;
    // if we still need more bytes because we started too far into the 
    // first page, add another!
    if (size > (num_pages * instance->page_size - tmp_offset))
	++num_pages;

    uint32_t pgd = pid ? xa_pid_to_pgd(instance, pid) : instance->kpgd;
    if (pid && !pgd) {
	kernel = 1;
	xa_current_cr3(instance, &pgd);
	xa_dbprint(0,"--UserVirt: pgd for pid=%d is 0; using kernel pgd 0x%.8x instead!\n", pid, pgd);
    }
    else if (!pid && !instance->kpgd) {
	xa_current_cr3(instance, &pgd);
    }
    xen_pfn_t* pfns = (xen_pfn_t*)malloc(sizeof(xen_pfn_t)*num_pages);

    xa_dbprint(0,"va = %08x, pid = %d, size = %d, num_pages = %d, offset = %d\n",
	       virt_address, pid, size, num_pages, tmp_offset);
    
    for (i = 0; i < num_pages; i++){
        /* Virtual address for each page we will map */
        uint32_t addr = start + i*instance->page_size;
    
        if(!addr) {
            xa_dbprint(0,"ERROR: address (%d)v not in page table (%p)\n",pid,(void *)addr);
	    free(pfns);
            return NULL;
        }

        /* Physical page frame number of each page */
        maddr = xa_pagetable_lookup(instance, pgd, addr, kernel);
	if (!maddr) {
	    xa_dbprint(0,"ERROR: address (%d)m not in page table (%p)!\n",pid,(void *)addr);
	    free(pfns);
	    return NULL;
	}
	pfns[i] = maddr >> instance->page_shift;
    }

    *offset = tmp_offset;

    retval = xc_map_foreign_pages(
        instance->m.xen.xc_handle,
        instance->m.xen.domain_id, prot, pfns, num_pages
    );
    free(pfns);
    return retval;
#else
    return NULL;
#endif /* ENABLE_XEN */
}

void *xa_access_kernel_va (
        xa_instance_t *instance,
        uint32_t virt_address,
        uint32_t *offset,
        int prot)
{
    return xa_access_user_va(instance, virt_address, offset, 0, prot);
}

void *xa_access_kernel_va_range (
    xa_instance_t *instance,
    uint32_t virt_address,
    uint32_t size,
    uint32_t* offset,
    int prot)
{
    return xa_access_user_va_range(
        instance, virt_address, size, offset, 0, prot);
}

void *xa_access_pa (
        xa_instance_t *instance,
        uint32_t phys_address,
        uint32_t *offset,
        int prot)
{
    unsigned long pfn;
    
    /* page frame number = physical address >> PAGE_SHIFT */
    pfn = phys_address >> instance->page_shift;
    
    /* get the offset */
    *offset = (instance->page_size-1) & phys_address;
    
    /* access the memory */
    return xa_mmap_pfn(instance, prot, pfn);
}

void *xa_access_ma (
        xa_instance_t *instance,
        uint32_t mach_address,
        uint32_t *offset,
        int prot)
{
    unsigned long mfn;

    /* machine frame number = machine address >> PAGE_SHIFT */
    mfn = mach_address >> instance->page_shift;

    /* get the offset */
    *offset = (instance->page_size-1) & mach_address;

    /* access the memory */
    return xa_mmap_mfn(instance, prot, mfn);
}

/* ------------------------------------------------------------------------ */
/* The code below is experimental and needs some cleanup and optimization
 * before being ready for prime time.  This code is designed to search the
 * entire memory space to find page directories, with the ultimate goal of
 * finding the kernel page directory that can be used for kpgd.  The
 * techinque, as implemented right now, has been tested on a Windows XP SP2
 * HVM VM and a Fedora Linux HVM VM and works well in those settings.
 *
 * The algorthims used are a combination of previously used algorithms from
 * Andreas Schuster (see blog posts titled 'Searching for Page Directories'),
 * Joe Stewart (see pmodump.pl), and Jacky We (see blog post titled 'Search
 * PDEs in Memory Dump of Windows XP SP2 with PAE'); combined with some new
 * ideas that extend these to work more robustly.  The benefit is that this
 * works for both Linux and Windows VMs.
 *
 * Current limitations include:
 *  - the inline code for list management is ugly, need macros or functions
 *    setup to handle this in a more clean fashion
 *  - performance is decent, but would be nice to remove the n^2 loop so that
 *    all scanning is linear as this will improve startup speed
 *  - only works for non-PAE
 *  - functions could use general cleanup (single exit point, error checking,
 *    and other generally useful coding practices).
 */

/* MIT Hackmem Count algorithm */
int xa_kernel_pd_bitcount (uint32_t n)
{
    uint32_t count = 0;
    count = n - ((n >> 1) & 033333333333) - ((n >> 2) & 011111111111);
    return ((count + (count >> 3)) & 030707070707) % 63;
}

int xa_kernel_pd_valid_entry (uint32_t value, uint32_t msize)
{
    /* basic sanity checks */
    if (0xffffffff == value){
        return 0;
    }

    /* 4 MB page entry */
    if (xa_get_bit(value, 7)){
        /* check that page falls within memory bounds */
        if ((value & 0xFFE00000) > msize){
            return 0;
        }
    }

    /* 4 KB page entry */
    else{
        /* check that page falls within memory bounds */
        if ((value & 0xFFFFF000) > msize){
            return 0;
        }
    }

    return 1;
}

/* scores the page by determining how many bits are set the same (zero or one)
   for all non-zero entries in the page.  this works under the idea that page
   directory entires have some similarity between then (same bits flipped on,
   pointing to similar areas in the kernel, etc).  we also penalize any pages
   that contain entries that are trivially not valid PDEs */
int xa_kernel_pd_score (unsigned char *memory, uint32_t length, uint32_t msize)
{
    uint32_t offset = 0;
    uint32_t matches0 = 0;
    uint32_t matches1 = 0;
    int started = 0;
    int correction = 0;

    if (NULL == memory){
        return 0;
    }

    while (offset < length){
        uint32_t value = *((uint32_t*)(memory + offset));
        
        /* check for valid PD entries */
        if (!xa_kernel_pd_valid_entry(value, msize)){
            correction--;
        }

        if (0 != value){
            /* start by comparing first two non-zero entries */
            if (!started){
                offset += 4;
                while (offset < length){
                    uint32_t value2 = *((uint32_t*)(memory + offset));
                    if (0 != value2){
                        matches0 = (~value) & (~value2);
                        matches1 = value & value2;
                        started = 1;
                        break;
                    }
                    offset += 4;
                }
            }

            /* then add each remaining non-zero entry to the comparison */
            else if (0 != value){
                matches0 = matches0 & (~value);
                matches1 = matches1 & value;
            }
        }
        offset += 4;
    }
    /* score by adding the number of matching 0 or 1 bits */
    return xa_kernel_pd_bitcount(matches0) +
           xa_kernel_pd_bitcount(matches1) +
           correction;
}

/* create a simple checksum of the first few entries in the kernel region 
   of the PD.  the checksum is simply the addition of the entries, with
   no regard to overflow.  this seems sufficient for our purposes of just
   knowing which pages have identical entries */
uint32_t xa_kernel_pd_checksum (xa_instance_t *instance, unsigned char *memory)
{
    uint32_t start = 0;
    uint32_t end = 0;
    uint32_t checksum = 0;

    if (NULL == memory){
        return 0;
    }

    if (0x80000000 == instance->page_offset){
        start = instance->page_size / 2;
    }
    else if (0xc0000000 == instance->page_offset){
        start = 3 * instance->page_size / 4;
    }
    end = start + 8 * 4;

    while (start < end){
        uint32_t value = *((uint32_t*)(memory + start));
        checksum += value;
        start += 4;
    }

    return checksum;
}

/* returns the number of entries in this page that, if parsed as a PDE, point
   to the same pfn as the current page */
int xa_kernel_pd_selfref(
        xa_instance_t *instance, unsigned char *memory, uint32_t address)
{
    uint32_t offset = 0;
    int selfref = 0;

    if (NULL == memory){
        return 0;
    }

    while (offset < instance->page_size){
        uint32_t value = *((uint32_t*)(memory + offset));
        if (0 != value){
            value &= 0xFFFFF000;
            if (value == address){
                selfref++;
            }
        }
        offset += 4;
    }

    return selfref;
}

/* entry point into the search algorithm, this is the function to call */
uint32_t xa_find_kernel_pd (xa_instance_t *instance)
{
    uint32_t end = 0;
    uint32_t address = 0;
    uint32_t offset = 0;
    int score = 0;
    unsigned char *memory = NULL;

    /* this is used to hold a list of the candidate pages */
    struct candidates{
        uint32_t address;
        uint32_t checksum;
        int score;
        int matches;
        int selfref;
        struct candidates *next;
    };
    typedef struct candidates* candidates_t;
    candidates_t list = (candidates_t) malloc(sizeof(struct candidates));
    candidates_t cur = list;
    candidates_t prev = NULL;

    /* get the size of the physical memory */
    if (XA_MODE_XEN == instance->mode){
#ifdef ENABLE_XEN
        end = instance->m.xen.size;
#endif /* ENABLE_XEN */
    }
    else if (XA_MODE_FILE == instance->mode){
        end = instance->m.file.size;
    }

    /* look for pages with similarity between entries */
    while (address < end){
        memory = xa_access_pa(instance, address, &offset, PROT_READ);
        score = xa_kernel_pd_score(memory, instance->page_size, end);
        if (0 < score){
            /* list add */
            cur->address = address;
            cur->score = score;
            cur->next = (candidates_t) malloc(sizeof(struct candidates));
            cur = cur->next;
            cur->address = 0;
        }
        if (NULL != memory){
            munmap(memory, instance->page_size);
        }
        address += instance->page_size;
    }
//    printf("---------------------------------------\n");
//    printf("score\n");
//    for (cur = list; cur->address != 0; cur = cur->next){
//        printf("Candidate at 0x%.8x (%d)\n", cur->address, cur->score);
//    }

    /* check for matching entries in the kernel region */
    for (cur = list; cur->address != 0; cur = cur->next){
        /* create a simple checksum for each page */
        memory = xa_access_pa(instance, cur->address, &offset, PROT_READ);
        cur->checksum = xa_kernel_pd_checksum(instance, memory);
        if (NULL != memory){
            munmap(memory, instance->page_size);
        }
    }
    for (cur = list; cur->address != 0; cur = cur->next){
        /* compare the checksums to see who's entries match */
        candidates_t cur2 = list;
        cur->matches = -1;
        for (cur2 = list; cur2->address != 0; cur2 = cur2->next){
            if (cur->checksum == cur2->checksum && cur->checksum != 0){
                cur->matches++;
            }
        }
    }
    /* remove the ones that didn't have matches */
    prev = NULL;
    for (cur = list; cur->address != 0; ){
        if (cur->matches <= 0){
            /* list remove */
            if (cur == list){
                candidates_t tmp = cur;
                cur = cur->next;
                list = cur;
                free(tmp);
            }
            else{
                candidates_t tmp = cur;
                cur = cur->next;
                prev->next = cur;
                free(tmp);
            }
        }
        else{
            prev = cur;
            cur = cur->next;
        }
    }

//    printf("---------------------------------------\n");
//    printf("matches\n");
//    for (cur = list; cur->address != 0; cur = cur->next){
//        printf("Candidate at 0x%.8x (%d)\n", cur->address, cur->matches);
//    }

    /* check for self referencing entries */
    /* from some basic testing it appears that only windows does this */
    if (XA_OS_WINDOWS == instance->os_type){
        for (cur = list; cur->address != 0; cur = cur->next){
            memory = xa_access_pa(instance, cur->address, &offset, PROT_READ);
            cur->selfref = xa_kernel_pd_selfref(instance, memory, cur->address);
            if (NULL != memory){
                munmap(memory, instance->page_size);
            }
        }
        /* remove the ones that didn't have selfrefs */
        prev = NULL;
        for (cur = list; cur->address != 0; ){
            if (cur->selfref <= 0){
                /* list remove */
                if (cur == list){
                    candidates_t tmp = cur;
                    cur = cur->next;
                    list = cur;
                    free(tmp);
                }
                else{
                    candidates_t tmp = cur;
                    cur = cur->next;
                    prev->next = cur;
                    free(tmp);
                }
            }
            else{
                prev = cur;
                cur = cur->next;
            }
        }

//        printf("---------------------------------------\n");
//        printf("selfref\n");
//        for (cur = list; cur->address != 0; cur = cur->next){
//            printf("Candidate at 0x%.8x (%d)\n", cur->address, cur->selfref);
//        }
//        printf("---------------------------------------\n");
    }

    // for each candidate
        // the kernel PD should have no lower entries
        // find this one and return it's virtual address

    /* return the lowest physical address that is still in the list */
    /*TODO need some better method to check that this is the correct value */
    return list->address + instance->page_offset;
}
