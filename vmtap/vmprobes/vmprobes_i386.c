#include "vmprobes_i386.h"

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
    
    page = xa_access_kernel_va_range(xa_instance, 
                                     probepoint->vaddr, 
                                     total, 
                                     &offset, 
                                     PROT_WRITE);
    offset += extraoffset;

    if (!page)
        return -1;

    if (!nosave) {
	/* if they pass us raw memory, don't malloc */
	if (*dst == NULL) {
	    *dst = (uint8_t *)malloc(total);
	    debug(0,"dom%d: malloc(%d) bytes to dst %x, *dst %x\n",
		  domain->id,total,(unsigned int)dst,(unsigned int)*dst);
	    if (!*dst) {
		munmap(page, xa_instance->page_size);
		return -1;
	    }
	}

	debug(0,"dom%d: %u opcodes to %lx with offset %u; total %d\n",
	      domain->id,opcode_list_len,probepoint->vaddr,offset,total);

	debug(0,"dom%d: saving %d bytes to dst %x from src page %x, offset %x\n",
	      domain->id,total,(unsigned int)*dst,(unsigned int)page,offset);

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

    munmap(page, xa_instance->page_size);
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
    offset += extraoffset;

    if (!page)
        return -1;

	debug(0,"dom%u: restoring %d bytes to %lx with offset %u\n",
		 domain->id,*src_len,probepoint->vaddr,offset);
    
    memcpy(page + offset, *src, *src_len);

    if (dofree) {
	free(*src);
	*src = NULL;
	if (src_len) {
	    *src_len = 0;
	}
    }

    munmap(page, xa_instance->page_size);
    return 0;
}

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
