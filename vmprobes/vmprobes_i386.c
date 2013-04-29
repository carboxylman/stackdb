/*
 * Copyright (c) 2011-2013 The University of Utah
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

#include <assert.h>
#include "vmprobes.h"
#include "vmprobes_i386.h"

#ifdef ENABLE_XENACCESS
static int __arch_replace_instr(struct vmprobe_probepoint *probepoint,
				struct vmprobe_opcode **opcode_list,
				int opcode_list_len,
				uint8_t **dst,unsigned int *dst_len,
				int extraoffset,uint8_t nosave)
{
    struct vmprobe_domain *domain;
    xa_instance_t *xa_instance;
    uint32_t offset = 0;
    unsigned char *page;
    int i;
    int total = 0;
    
    domain = probepoint->domain;
    xa_instance = &domain->xa_instance;

    for (i = 0; i < opcode_list_len; ++i) {
	total += opcode_list[i]->len;
    }
    
    debug(2,"dom%d: replacing at 0x%lx\n",
	  domain->id,probepoint->vaddr);
    
    page = xa_access_kernel_va_range(xa_instance, 
                                     probepoint->vaddr, 
                                     total, 
                                     &offset, 
                                     PROT_WRITE);
    if (!page)
        return -1;

    assert(offset + total < xa_instance->page_size);
    offset += extraoffset;

    if (!nosave) {
	/* if they pass us raw memory, don't malloc */
	if (*dst == NULL) {
	    *dst = (uint8_t *)malloc(total);
	    debug(2,"dom%d: malloc(%d) bytes to dst %p, *dst %p\n",
		  domain->id,total,dst,*dst);
	    if (!*dst) {
		if (munmap(page, xa_instance->page_size))
		    warning("munmap of %p failed\n", page);
		return -1;
	    }
	}

	debug(2,"dom%d: %u opcodes to %lx with offset %u; total %d\n",
	      domain->id,opcode_list_len,probepoint->vaddr,offset,total);

	debug(2,"dom%d: saving %d bytes to dst %p from src page %lx, offset %x\n",
	      domain->id,total,*dst,(unsigned long)page,offset);

	/* save */
	memcpy(*dst, page + offset, total);
	if (dst_len)
	    *dst_len = total;
    }

    /* replace */
    for (i = 0; i < opcode_list_len; ++i) {
	memcpy(page + offset, opcode_list[i]->bytes, opcode_list[i]->len);
	offset += opcode_list[i]->len;
    }

    if (munmap(page, xa_instance->page_size))
	warning("munmap of %p failed\n", page);
    return 0;
}

static int __arch_restore_instr(struct vmprobe_probepoint *probepoint,
				uint8_t **src,unsigned int *src_len,
				int extraoffset,uint8_t dofree)
{
    struct vmprobe_domain *domain;
    xa_instance_t *xa_instance;
    uint32_t offset;
    unsigned char *page;
    
    domain = probepoint->domain;
    xa_instance = &domain->xa_instance;
    
    page = xa_access_kernel_va_range(xa_instance, 
                                     probepoint->vaddr, 
                                     *src_len,
                                     &offset, 
                                     PROT_WRITE);
    if (!page)
        return -1;

    assert(offset + *src_len < xa_instance->page_size);
    offset += extraoffset;

    debug(2,"dom%u: restoring %d bytes to %lx with offset %u\n",
	  domain->id,*src_len,probepoint->vaddr,offset);
    
    memcpy(page + offset, *src, *src_len);

    if (dofree) {
	free(*src);
	*src = NULL;
	if (src_len) {
	    *src_len = 0;
	}
    }

    if (munmap(page, xa_instance->page_size))
	warning("munmap of %p failed\n", page);
    return 0;
}
#endif

#ifdef ENABLE_LIBVMI
static int __arch_replace_instr(struct vmprobe_probepoint *probepoint,
				struct vmprobe_opcode **opcode_list,
				int opcode_list_len,
				uint8_t **dst,unsigned int *dst_len,
				int extraoffset,uint8_t nosave)
{
    struct vmprobe_domain *domain;
    vmi_instance_t vmi_instance;
    unsigned long offset;
    char *buffer;
    uint8_t *bp;
    int i;
    int total = 0;
    size_t cc;
    
    domain = probepoint->domain;
    vmi_instance = domain->vmi_instance;
    offset = probepoint->vaddr + extraoffset;

    for (i = 0; i < opcode_list_len; ++i) {
	total += opcode_list[i]->len;
    }
    buffer = malloc(total);
    if (buffer == NULL)
	return -1;

    debug(2,"dom%d: replacing at 0x%lx+0x%x (%ssave)\n",
	  domain->id,probepoint->vaddr,extraoffset,nosave?"no":"");
    
    if (!nosave) {
	/* if they pass us raw memory, don't malloc */
	if (*dst == NULL) {
	    *dst = (uint8_t *)malloc(total);
	    debug(2,"dom%d: malloc(%d) bytes to dst %p, *dst %p\n",
		  domain->id,total,dst,*dst);
	    if (!*dst) {
		free(buffer);
		return -1;
	    }
	}

	debug(2,"dom%d: %u opcodes to %lx; total %d\n",
	      domain->id,opcode_list_len,offset,total);

	debug(2,"dom%d: saving %d bytes to dst %p\n",
	      domain->id,total,*dst);

	cc = vmi_read_va(vmi_instance, offset, 0, *dst, total);
	if (cc != total) {
	    error("incomplete read (%d of %d) at 0x%x\n", cc, total, offset);
	    free(buffer);
	    return -1;
	}
    }

    /* replace */
    bp = (uint8_t *)buffer;
    for (i = 0; i < opcode_list_len; ++i) {
	memcpy(bp, opcode_list[i]->bytes, opcode_list[i]->len);
	bp += opcode_list[i]->len;
    }

    cc = vmi_write_va(vmi_instance, offset, 0, buffer, total);
    free(buffer);

    if (cc != total) {
	error("incomplete write (%d of %d) at 0x%x\n", cc, total, offset);
	return -1;
    }
    return 0;
}

static int __arch_restore_instr(struct vmprobe_probepoint *probepoint,
				uint8_t **src,unsigned int *src_len,
				int extraoffset,uint8_t dofree)
{
    struct vmprobe_domain *domain;
    vmi_instance_t vmi_instance;
    unsigned long offset;
    size_t cc;
    
    domain = probepoint->domain;
    vmi_instance = domain->vmi_instance;
    offset = probepoint->vaddr + extraoffset;
    
    debug(2,"dom%u: restoring %d bytes to %lx with offset %u\n",
	  domain->id,*src_len,probepoint->vaddr,extraoffset);

    cc = vmi_write_va(vmi_instance, offset, 0, *src, *src_len);
    if (cc != *src_len) {
	error("incomplete write (%d of %d) at 0x%lx\n", cc, *src_len, offset);
	return -1;
    }
    
    if (dofree) {
	free(*src);
	*src = NULL;
	if (src_len) {
	    *src_len = 0;
	}
    }

    return 0;
}
#endif

static int
arch_insert_code(struct vmprobe_probepoint *probepoint,
		 struct vmprobe_opcode **opcode_list,
		 unsigned int opcode_list_len,
		 uint8_t offset,
		 uint8_t nosave)
{
    return __arch_replace_instr(probepoint,
				opcode_list,
				opcode_list_len,
				&probepoint->saved_instr,
				&probepoint->saved_instr_len,
				offset,
				nosave);
}

static int
arch_remove_code(struct vmprobe_probepoint *probepoint)
{
    return __arch_restore_instr(probepoint,
				&probepoint->saved_instr,
				&probepoint->saved_instr_len,
				0,
				1);
}

static int
arch_insert_breakpoint(struct vmprobe_probepoint *probepoint)
{
    struct vmprobe_opcode *tmp[1] = { &BREAKPOINT };

    return __arch_replace_instr(probepoint,
				tmp,
				1,
				&probepoint->breakpoint_saved_instr,
				&probepoint->breakpoint_saved_instr_len,
				0,
				0);
}

static int
arch_remove_breakpoint(struct vmprobe_probepoint *probepoint)
{
    unsigned int tmp = (unsigned int)BREAKPOINT.len;

    return __arch_restore_instr(probepoint,
				&probepoint->breakpoint_saved_instr,
				&tmp,
				0,
				1);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * End:
 */
