const vmprobe_opcode_t breakpoint = BREAKPOINT_INSTRUCTION;

static int
arch_save_org_insn(struct vmprobe_probepoint *probepoint)
{
    struct vmprobe_domain *domain;
    xa_instance_t *xa_instance;
    unsigned long vaddr;
    uint32_t offset;
    vmprobe_opcode_t *opcode;
    unsigned char *page;
    
    domain = probepoint->domain;
    xa_instance = &domain->xa_instance;
    vaddr = probepoint->vaddr;
    
    page = xa_access_kernel_va_range(xa_instance, 
                                     vaddr, 
                                     BP_INSN_SIZE, 
                                     &offset, 
                                     PROT_READ);
    if (!page)
        return -1;
    
    opcode = &probepoint->opcode;
    memcpy(opcode, page + offset, BP_INSN_SIZE);
    
    munmap(page, xa_instance->page_size);
    //printf("opcode saved: %x\n", probepoint->opcode);
    return 0;
}

static int
arch_insert_breakpoint(struct vmprobe_probepoint *probepoint)
{
    struct vmprobe_domain *domain;
    xa_instance_t *xa_instance;
    unsigned long vaddr;
    uint32_t offset;
    unsigned char *page;
    
    domain = probepoint->domain;
    xa_instance = &domain->xa_instance;
    vaddr = probepoint->vaddr;
    
    page = xa_access_kernel_va_range(xa_instance, 
                                     vaddr, 
                                     BP_INSN_SIZE,
                                     &offset, 
                                     PROT_WRITE);
    if (!page)
        return -1;
    
    memcpy(page + offset, &breakpoint, BP_INSN_SIZE);
    
    munmap(page, xa_instance->page_size);
    //printf("breakpoint inserted: %x\n", BREAKPOINT_INSTRUCTION);
    return 0;
}

static int
arch_remove_breakpoint(struct vmprobe_probepoint *probepoint)
{
    struct vmprobe_domain *domain;
    xa_instance_t *xa_instance;
    unsigned long vaddr;
    uint32_t offset;
    vmprobe_opcode_t *opcode;
    unsigned char *page;
    
    domain = probepoint->domain;
    xa_instance = &domain->xa_instance;
    vaddr = probepoint->vaddr;
    
    page = xa_access_kernel_va_range(xa_instance, 
                                     vaddr, 
                                     BP_INSN_SIZE,
                                     &offset, 
                                     PROT_WRITE);
    if (!page)
        return -1;
    
    opcode = &probepoint->opcode;
    memcpy(page + offset, opcode, BP_INSN_SIZE);
    
    munmap(page, xa_instance->page_size);
    //printf("opcode restored: %x\n", probepoint->opcode);
    return 0;
}
