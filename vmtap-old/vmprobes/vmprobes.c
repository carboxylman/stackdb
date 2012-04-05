/*
 * Copyright (c) 2011, 2012 The University of Utah
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

/* 
 * File:   vmprobes.c
 * Author: Chung Hwan Kim
 * E-mail: chunghwn@cs.utah.edu
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <vmprobes.h>

#define __arm_vmprobe(p)          (arch_arm_vmprobe(p))
#define __disarm_vmprobe(p)       (arch_disarm_vmprobe(p))
#define __restore_regs(regs)      (arch_restore_regs(regs))
#define __inst_singlestep(regs)   (arch_inst_singlestep(regs))
#define __uninst_singlestep(regs) (arch_uninst_singlestep(regs))
#define __dump_regs(regs)         (arch_dump_regs(regs))

/* Saved pointer to the vmprobe instance. (Assume there is only one probe.) */
static struct vmprobe * __p;

/*
 * a signal handler that is invoked when the user unexpectedly terminates the
 * process and unregister all registered vmprobes.
 */
void vmprobe_sighandler(int sig)
{
    unregister_vmprobe(__p);
    fprintf(stderr, "Warning: probe forcefully unregistered.\n");
    signal(sig, SIG_DFL);
    raise(sig);
}

/*
 * register a signal handler to catch process-terminating signals.
 */
void vmprobe_signals()
{
    if (signal(SIGINT, vmprobe_sighandler) == SIG_IGN)
        signal(SIGINT, SIG_IGN);
    if (signal(SIGABRT, vmprobe_sighandler) == SIG_IGN)
        signal(SIGABRT, SIG_IGN);
    if (signal(SIGHUP, vmprobe_sighandler) == SIG_IGN)
        signal(SIGHUP, SIG_IGN);
    if (signal(SIGILL, vmprobe_sighandler) == SIG_IGN)
        signal(SIGILL, SIG_IGN);
    if (signal(SIGFPE, vmprobe_sighandler) == SIG_IGN)
        signal(SIGFPE, SIG_IGN);
    if (signal(SIGSEGV, vmprobe_sighandler) == SIG_IGN)
        signal(SIGSEGV, SIG_IGN);
    if (signal(SIGTERM, vmprobe_sighandler) == SIG_IGN)
        signal(SIGTERM, SIG_IGN);
}

/* 
 * initialize the specified xenaccess instance given a domain id or a domain 
 * name. domain_id is ignored when domain_name is specified. return non-zero
 * value if an error occurs. 
 */
static int __vmprobes vmprobe_init_xa(domid_t domain_id, 
                                      const char *domain_name, 
                                      xa_instance_t *xa_instance)
{
    xa_instance->pae = 1; // set pae mode always on due to a xenaccess bug
    
    if (domain_name)
    {
        if (domain_id)
            return -EINVAL;
        
        if (xa_init_vm_name_strict((char *)domain_name, xa_instance) == 
            XA_FAILURE)
        {
            fprintf(stderr, "Error: Domain '%s' does not exist.\n", 
                domain_name);
            return -EINVAL;
        }
    }
    else if (domain_id > 0)
    {
        if (xa_init_vm_id_strict(domain_id, xa_instance) == XA_FAILURE)
        {
            fprintf(stderr, "Error: Domain '%d' does not exist.\n", domain_id);
            return -EINVAL;
        }
    }
    else
        return -EINVAL;
    
    return 0;
}

/* 
 * clean up the specified xenaccess instance. 
 */
static void __vmprobes vmprobe_cleanup_xa(xa_instance_t *xa_instance)
{
    if (xa_instance)
        xa_destroy(xa_instance);
}

/* 
 * return the domain id specified in the xenaccess instance. This function must
 * be called after register_vmprobe(). If the user only specified a domain name 
 * when registring vmprobe, XenAccess must have found the domain ID 
 * corresponding to the domain name while being initialized. returns a value 
 * equal to or less than zero if an error occurs.
 */
static domid_t __vmprobes vmprobe_domain_id(xa_instance_t *xa_instance)
{
    domid_t domain_id = xa_instance->m.xen.domain_id;
    return domain_id;
}

/* 
 * if we have a symbol_name argument, look it up and add the offset field to it.
 * this way, we can specify a relative address to a symbol. 
 */
static vmprobe_opcode_t *__vmprobes vmprobe_addr(vmprobe_opcode_t *addr, 
                                                 const char *symbol_name, 
                                                 uint32_t offset, 
                                                 xa_instance_t *xa_instance)
{
    if (symbol_name)
    {
        if (addr)
            return NULL;
        
        // vmprobes currently supports linux symbols only
        if (linux_system_map_symbol_to_address(xa_instance, symbol_name, 
           (uint32_t *)&addr) == XA_FAILURE)
        {
            return NULL;
        }
    }
    
    if (!addr)
        return NULL;
        
    addr = (vmprobe_opcode_t *)(((char *)addr) + offset);

    return addr;
}

/*
 * return the xenctrl handle stored in the xenaccess instance.
 */
static int __vmprobes vmprobe_xc_handle(xa_instance_t *xa_instance)
{
    return (xa_instance->m.xen.xc_handle);
}

/*
 * return the domain information stored in the xenaccess instance.
 */
static xc_dominfo_t *__vmprobes vmprobe_domain_info(xa_instance_t *xa_instance)
{
    return (&xa_instance->m.xen.info);
}

/*
 * map multiple pages from the target domain to a local address range. the
 * memory of the returned address must be unmapped manually with munmap().
 * return NULL if an error occurs.
 */
static int __vmprobes vmprobe_mmap(uint32_t address, void **memory, 
                                   uint32_t size, uint32_t *offset, 
                                   int prot, xa_instance_t *xa_instance)
{
    void *pages;
    uint32_t cr3 = 0;
    uint32_t vaddr;
    uint32_t maddr;
    int kernel = 1; // currently supports kernel memory access only
    int xc_handle;
    domid_t domain_id;
    uint32_t i;

    uint32_t page_size = xa_instance->page_size;
    uint32_t start = address & ~(page_size - 1);
    uint32_t offset_tmp = address - start;
    uint32_t num_pages = (size + offset_tmp) / page_size + 1;
    uint32_t mapped = 0;

    xen_pfn_t *mfns = (xen_pfn_t *)malloc(sizeof(xen_pfn_t) * num_pages);
    if (!mfns)
        return ENOMEM;
    
    vmprobe_verbose("Mapping v-address: %08x (%d bytes)\n", address, size);
    vmprobe_verbose("- Offset: %x\n", offset_tmp);
    vmprobe_verbose("- No of Pages: %d\n", num_pages);

    // cr3 register holds the page directory
    xa_current_cr3(xa_instance, &cr3);
    vmprobe_verbose("- CR3: %08x\n", cr3);

    for (i = 0; i < num_pages; i++)
    {
        // virtual address for each page we will map
        vaddr = start + i * page_size;
        if (!vaddr)
        {
            free(mfns);
            return -EINVAL;
        }
        vmprobe_verbose("- Page%d V-address: %08x\n", i, vaddr);

        // machine address for each page
        maddr = xa_pagetable_lookup(xa_instance, cr3, vaddr, kernel);
        vmprobe_verbose("- Page%d M-address: %08x\n", i, maddr);

        if (maddr)
            mapped++;
        else
            break; // map pages that are found only

        // machine page frame number of each page
        mfns[i] = maddr >> xa_instance->page_shift;
        vmprobe_verbose("- Page%d Frame No: %x\n", i, mfns[i]);
    }

    xc_handle = vmprobe_xc_handle(xa_instance);
    domain_id = vmprobe_domain_id(xa_instance);

    pages = xc_map_foreign_pages(xc_handle, domain_id, prot, mfns, mapped);
    if (!pages)
    {
        free(mfns);
        return -errno;
    }
    vmprobe_verbose("Mapped to: %08x (%d pages)\n", pages, mapped);

    *offset = offset_tmp;
    *memory = pages;

    return (mapped * page_size);
}

/*
 * read the specified bytes at the address of the target domain, and save the 
 * data in text. return a non-zero value if an error occurs.
 */
static int __vmprobes vmprobe_peek(uint32_t address, void *text, 
                                   uint32_t bytes, xa_instance_t *xa_instance)
{
    unsigned char *memory = NULL;
    uint32_t offset = 0;
    int mapped;
    int size;

    mapped = vmprobe_mmap(address, (void **)&memory, bytes, &offset, 
        PROT_READ, xa_instance);
    if (!mapped)
        return -1;
    else if (mapped < 0)
        return mapped;

    size = mapped - offset;
    if (bytes < size) size = bytes;

    memcpy(text, memory + offset, size);

    munmap(memory, mapped);
    return 0;
}

/*
 * write the specified bytes of text to the address of the target domain. 
 * return a non-zero value if an error occurs.
 */
static int __vmprobes vmprobe_poke(uint32_t address, const void *text, 
                                   uint32_t bytes, xa_instance_t *xa_instance)
{
    unsigned char *memory = NULL;
    uint32_t offset = 0;
    int mapped;
    int size;

    mapped = vmprobe_mmap(address, (void **)&memory, bytes, &offset, 
        PROT_WRITE, xa_instance);
    if (!mapped)
        return -1;
    else if (mapped < 0)
        return mapped;

    size = mapped - offset;
    if (bytes < size) size = bytes;

    memcpy(memory + offset, text, size);
    
    munmap(memory, mapped); 
    return 0;
}

/*
 * read the opcode at the specified address of the domain. return a non-zero 
 * value if an error occurs.
 */
static int __vmprobes vmprobe_opcode(vmprobe_opcode_t *opcode, 
                                     vmprobe_opcode_t *addr, 
                                     xa_instance_t *xa_instance)
{
    return (vmprobe_peek((uint32_t)addr, opcode, sizeof(vmprobe_opcode_t),
        xa_instance));
}

/*
 * get current registers of the domain.
 */
static int __vmprobes vmprobe_get_regs(struct pt_regs *regs, domid_t domain_id, 
    int xc_handle)
{
    int ret = 0;
    int vcpu = 0; // assume there is only one cpu
    vcpu_guest_context_t ctxt = {0,};
    
    ret = xc_vcpu_getcontext(xc_handle, domain_id, vcpu, &ctxt);
    if (ret)
        return ret;
        
    SET_PT_REGS((*regs), ctxt.user_regs);

    return ret;
}

/*
 * set new registers to the domain.
 */
static int __vmprobes vmprobe_set_regs(const struct pt_regs *regs, 
    domid_t domain_id, int xc_handle)
{
    int ret = 0;
    int vcpu = 0; // assume there is only one cpu
    vcpu_guest_context_t ctxt = {0,};
    
    ret = xc_vcpu_getcontext(xc_handle, domain_id, vcpu, &ctxt);
    if (ret)
        return ret;

    SET_XC_REGS(regs, ctxt.user_regs);

    ret = xc_vcpu_setcontext(xc_handle, domain_id, vcpu, &ctxt);
    return ret;
}

/*
 * restore the registers of the domain to the original values.
 */
static int __vmprobes vmprobe_restore_regs(domid_t domain_id, int xc_handle)
{
    int ret = 0;
    struct pt_regs regs;

    ret = vmprobe_get_regs(&regs, domain_id, xc_handle);
    if (ret)
        return ret;
    
    __restore_regs(&regs);
    
    ret = vmprobe_set_regs(&regs, domain_id, xc_handle);
    return ret;
}

/*
 * turn the domain into singlestep mode if the specfied singlestep is non-zero,
 * or turn the domain back to debug-mode if it is zero.
 */
static int __vmprobes vmprobe_singlestep(domid_t domain_id, int xc_handle,
    int singlestep)
{
    int ret = 0;
    struct pt_regs regs;
    int status;
    
    ret = vmprobe_get_regs(&regs, domain_id, xc_handle);
    if (ret)
        return ret;

    if (singlestep)
        __inst_singlestep(&regs);
    else
        __uninst_singlestep(&regs);
    
    ret = vmprobe_set_regs(&regs, domain_id, xc_handle);
    if (ret)
        return ret;
    vmprobe_verbose("- Singlestep-mode %s\n", (singlestep) ? "On" : "Off");

    if (singlestep)
    {
        ret = xc_domain_unpause(xc_handle, domain_id);
        if (ret)
            return ret;
        vmprobe_verbose("- Domain Resumed.\n");

        vmprobe_verbose("- Waiting for domain to singlestep...\n"); 
        xc_waitdomain(xc_handle, domain_id, &status, 0);
        vmprobe_verbose("- Singlestep Hit! (Domain Paused)\n");
    }
    
    return ret;
}

/*
 * resume the domain to continue execution. call this function after 
 * arm_vmprobe() that injects a breakpoint into the domain. this function 
 * returns right after the injected breakpoint is hit by the guest execution.
 */
static int __vmprobes vmprobe_resume(domid_t domain_id, int xc_handle)
{
    int ret = 0;
    int status;
    
    ret - xc_ptrace(xc_handle, PTRACE_CONT, domain_id, 0, 0);
    if (ret)
        return ret; 
    vmprobe_verbose("- Domain Resumed.\n");

    vmprobe_verbose("- Waiting for domain to hit breakpoint...\n");
    xc_waitdomain(xc_handle, domain_id, &status, 0);
    vmprobe_verbose("- Breakpoint Hit! (Domain Paused)\n");

    return ret;
}

/*
 * turn the domain into debug-mode, and save the original opcode at the 
 * address to instrument.
 */
static int __vmprobes prepare_vmprobe(struct vmprobe *p)
{
    int ret = 0;
    domid_t domain_id = p->domain_id;
    vmprobe_opcode_t *addr = p->addr;
    int xc_handle = vmprobe_xc_handle(&p->xa_instance);
    vmprobe_opcode_t opcode;
    int status;
    
    ret = xc_ptrace(xc_handle, PTRACE_ATTACH, domain_id, 0, 0);
    if (ret)
    {
        fprintf(stderr, "Error: Cannot turn the domain into debug-mode.\n");
        return ret;
    }
    xc_waitdomain(xc_handle, domain_id, &status, 0);
    vmprobe_verbose("- Debug-mode On (Domain Paused)\n");

    ret = vmprobe_opcode(&opcode, addr, &p->xa_instance);
    if (ret)
    {
        xc_ptrace(xc_handle, PTRACE_DETACH, domain_id, 0, 0);
        fprintf(stderr, "Error: Cannot obtain opcode.\n");      
        return ret;
    }
    p->opcode = opcode;
    vmprobe_verbose("- Opcode (%p) Saved\n", p->opcode);
    
    p->flags |= VMPROBE_FLAG_PREPARED;
    return ret;
}

/*
 * arm the domain for instrumentation. (see arch_arm_vmprobe() for more details 
 * varying on hardware archtectures)
 */
static int __vmprobes arm_vmprobe(struct vmprobe *p)
{
    int ret = 0;
    
    ret = __arm_vmprobe(p);
    if (ret)
        return ret;
        
    p->flags |= VMPROBE_FLAG_ARMED;
    return ret;
}

/*
 * disarm the domain to finish instrumentation. (see arch_disarm_vmprobe() for 
 * more details varying on hardware archtectures)
 */
static int __vmprobes disarm_vmprobe(struct vmprobe *p)
{
    int ret = 0;
    
    if (!vmprobe_armed(p))
        return EPERM;
        
    ret = __disarm_vmprobe(p);
    if (ret)
        return ret;
        
    p->flags &= ~VMPROBE_FLAG_ARMED;
    return ret;
}

/*
 * restore the domain state to its original state.
 */
static int __vmprobes restore_vmprobe(struct vmprobe *p)
{
    int ret = 0;
    domid_t domain_id = p->domain_id;
    int xc_handle = vmprobe_xc_handle(&p->xa_instance);
    
    if (vmprobe_restored(p))
        return EPERM;
    
    /* restore registers */
    ret = vmprobe_restore_regs(domain_id, xc_handle);
    if (ret)
    {
        fprintf(stderr, "Error: Cannot restore registers.\n");
        return ret;
    }
    
    /* TODO: restore other domain states if necessary (might needed for 
       architectures other than i386) */
    
    p->flags |= VMPROBE_FLAG_RESTORED;
    vmprobe_verbose("- Domain state restored.\n");

    return ret;
}

/*
 * notify user-specified pre-handler or post-handler depending on the specified 
 * 'notify' value. invoke pre-handler if notify is VMPROBE_NOTIFY_INT3, or
 * post-handler if notify is VMPROBE_NOTIFY_DEBUG. this function returns 
 * VMPROBE_NOTIFY_DONE if user handler indicated a normal execution, i.e. 
 * continue instrumentation, or VMPROBE_NOTIFY_STOP if user handler wants to
 * stop instrumentation. loop_vmprobe then finally returns after finishing
 * its job.
 */
static int __vmprobes notify_vmprobe(struct vmprobe *p, int notify, 
    struct pt_regs* regs)
{
    int ret_notify = VMPROBE_NOTIFY_DONE;
    int ret_handler;
    uint32_t flags;
    
    if (vmprobe_disabled(p))
        return ret_notify;
    
    switch (notify)
    {
    case VMPROBE_NOTIFY_INT3:
        if (p->pre_handler)
        {
            vmprobe_verbose("- Invoking pre-handler...\n");
            if (ret_handler = p->pre_handler(p, regs))
                ret_notify = VMPROBE_NOTIFY_STOP;
            vmprobe_verbose("- Pre-handler returned %d.\n", ret_handler);
        }
        break;
    case VMPROBE_NOTIFY_DEBUG:
        if (p->post_handler)
        {
            flags = p->flags;
            vmprobe_verbose("- Invoking post-handler...\n");
            if (ret_handler = p->post_handler(p, regs, flags))
                ret_notify = VMPROBE_NOTIFY_STOP;
            vmprobe_verbose("- Post-handler returned %d.\n", ret_handler);
        }
        break;
    default:
        break;
    }
    
    return ret_notify;
}

/* 
 * given a user-specified vmprobe instance, initialize and prepare for 
 * instrumentation. return non-zero value when error occurs. 
 */
int __vmprobes register_vmprobe(struct vmprobe *p)
{
    int ret = 0;
    domid_t domain_id;
    xc_dominfo_t *domain_info;
    vmprobe_opcode_t *addr;
    
    if (getuid())
    {
        fprintf(stderr, "Error: Need root access. Please try again as root.\n");
        return -EACCES;
    }

    if (!p)
        return -EINVAL;

    disable_vmprobe(p);
    p->flags |= VMPROBE_FLAG_RESTORED; // domain starts with 'restored' state.
    
    /* TODO: extend codes to support multiple probes */
    __p = p; // save the user-specified vmprobe in a global variable

    vmprobe_signals();
    
    ret = vmprobe_init_xa(p->domain_id, p->domain_name, &p->xa_instance);
    if (ret)
        return ret;

    domain_id = vmprobe_domain_id(&p->xa_instance);
    if (domain_id <= 0)
    {
        ret = -1;
        fprintf(stderr, "Error: Cannot obtain domain ID. (unexpected)\n");
        goto error_out;
    }
    p->domain_id = domain_id;
    vmprobe_verbose("- Domain Name: %s\n", p->domain_name);
    vmprobe_verbose("- Domain ID: %d\n", p->domain_id);

    domain_info = vmprobe_domain_info(&p->xa_instance);
    if (!domain_info)
    {
        ret = -1;
        fprintf(stderr, "Error: Cannot obtain domain info. (unexpected)\n");
        goto error_out;
    }
    if (domain_info->paused)
    {
        ret = -EPERM;
        fprintf(stderr, "Error: Domain is currently paused. "
            "Please unpause the domain.\n");
        goto error_out;
    }
    
    addr = vmprobe_addr(p->addr, p->symbol_name, p->offset, &p->xa_instance);
    if (!addr)
    {
        ret = -1;
        fprintf(stderr, "Error: Cannot obtain symbol address. "
            "Please check your XenAccess configuration.\n");
        goto error_out;
    }
    p->addr = addr;
    vmprobe_verbose("- Symbol Name: %s\n", p->symbol_name);
    vmprobe_verbose("- Address: %p (= %x + 0x%x)\n", p->addr, 
        (p->addr - p->offset), p->offset);

    ret = prepare_vmprobe(p);
    if (ret)
        goto error_out;
    
    ret = arm_vmprobe(p);
    if (ret)
        goto error_out;
    
    enable_vmprobe(p);
    return ret;

error_out:
    unregister_vmprobe(p);
    return ret;
}

/* 
 * finish up instrumentation and restore the status of the target vm. return 
 * non-zero value when error occurs. 
 */
void __vmprobes unregister_vmprobe(struct vmprobe *p)
{
    domid_t domain_id;
    int xc_handle;

    if (!p)
        return;

    disable_vmprobe(p);

    domain_id = p->domain_id;
    xc_handle = vmprobe_xc_handle(&p->xa_instance);
    
    restore_vmprobe(p);
        
    disarm_vmprobe(p);
    
    if (vmprobe_prepared(p))
    {
        xc_ptrace(xc_handle, PTRACE_DETACH, domain_id, 0, 0);
        vmprobe_verbose("- Debug-mode Off (Domain Resumed)\n");
        p->flags &= ~VMPROBE_FLAG_PREPARED;
    }
    
    vmprobe_cleanup_xa(&p->xa_instance);
}

/* 
 * start instrumentation and continue until a user handler returns non-zero. 
 * return non-zero value when error occurs. 
 */
int __vmprobes loop_vmprobe(struct vmprobe *p)
{
    int ret = 0;
    domid_t domain_id;
    int xc_handle;
    struct pt_regs regs;
    int notify;
    
    if (!p)
        return -EINVAL;

    if (vmprobe_disabled(p) || !vmprobe_prepared(p) || !vmprobe_armed(p))
        return -EPERM;
    
    domain_id = p->domain_id;
    xc_handle = vmprobe_xc_handle(&p->xa_instance);

    while (1)
    {
        /* resume domain execution so that domain can hit the breakpoint */
        ret = vmprobe_resume(domain_id, xc_handle);
        if (ret)
        {
            fprintf(stderr, "Cannot resume domain execution.\n");
            break;
        }
        p->flags &= ~VMPROBE_FLAG_RESTORED; // assure restoring registers later

        /* get current registers for pre-handlers */
        ret = vmprobe_get_regs(&regs, domain_id, xc_handle);
        if (ret)
        {
            fprintf(stderr, "Cannot obtain registers for pre-handler.\n");
            break;
        }
        vmprobe_verbose("- Registers obtained for pre-handler.\n");

        /* notify user-specified pre-handler */
        __restore_regs(&regs); // original registers before breakpoint hit.  
        notify = notify_vmprobe(p, VMPROBE_NOTIFY_INT3, &regs);
        
        /* restore the domain state (registers and etc.) back to original */
        ret = restore_vmprobe(p);
        if (ret)
            break;

        /* disarm the probe */
        ret = disarm_vmprobe(p);
        if (ret)
            break;
        
        /* end the loop if pre-handler notified stop */
        if (notify == VMPROBE_NOTIFY_STOP)
            break;
        
        /* turn the domain into singlestep mode (function returns when the 
           restored original instruction is executed.) */
        ret = vmprobe_singlestep(domain_id, xc_handle, 1);
        if (ret)
        {
            fprintf(stderr, "Cannot turn single-step mode on.\n");
            break;
        }
        
        /* get current registers for post-handlers */
        ret = vmprobe_get_regs(&regs, domain_id, xc_handle);
        if (ret)
        {
            fprintf(stderr, "Cannot obtain registers for post-handler.\n");
            break;
        }
        vmprobe_verbose("- Registers obtained for post-handler.\n");
        
        /* notify user-specified post-handler */
        notify = notify_vmprobe(p, VMPROBE_NOTIFY_DEBUG, &regs);
        
        /* turn the domain back to debug mode */
        ret = vmprobe_singlestep(domain_id, xc_handle, 0);
        if (ret)
        {
            fprintf(stderr, "Cannot turn single-step mode off.\n");
            break;
        }
        
        /* end the loop if post-handler notified stop */
        if (notify == VMPROBE_NOTIFY_STOP)
            break;
        
        /* re-arm the probe */
        ret = arm_vmprobe(p);
        if (ret)
            break;
    }

    return ret;
}

/* 
 * disable the specified vmprobe. 
 */
void __vmprobes disable_vmprobe(struct vmprobe *p)
{
    p->flags |= VMPROBE_FLAG_DISABLED;
}

/* 
 * enable the specified vmprobe. 
 */
void __vmprobes enable_vmprobe(struct vmprobe *p)
{
    p->flags &= ~VMPROBE_FLAG_DISABLED;
}

/* 
 * read the specified size at the address of the instrumented vm, and save the
 * data in the buffer. return non-zero if an error occurs. 
 */
int __vmprobes read_vmprobe(struct vmprobe *p, uint32_t addr, void *buf, 
    uint32_t size)
{
    if (!p || !addr || !buf || !size)
        return -EINVAL;
    
    return (vmprobe_peek(addr, buf, size, &p->xa_instance));
}

/* 
 * write the specified size of the data in the buffer to the address of the 
 * instrumented vm. return non-zero if an error occurs. 
 */
int __vmprobes write_vmprobe(struct vmprobe *p, uint32_t addr, const void *buf, 
                             uint32_t size)
{
    if (!p || !addr || !buf || !size)
        return -EINVAL;

    return (vmprobe_poke(addr, buf, size, &p->xa_instance));
}

/* 
 * print out the fields of the specified vmprobe instance. 
 */
void __vmprobes dump_vmprobe(struct vmprobe *p)
{
    if (!p)
    {
        printf("Dumping vmprobe: NULL\n");
        return;
    }
    printf("Dumping vmprobe:\n");
    printf("- Domain Name: %s\n"
           "- Domain ID: %d\n"
           "- Symbol Name: %s\n"
           "- Address: %p\n"
           "- Offset: 0x%x\n",
           p->domain_name, 
           p->domain_id, 
           p->symbol_name, 
           p->addr, 
           p->offset);
}

/*
 * print out the specified register values.
 */
void __vmprobes dump_regs(struct pt_regs *regs)
{
    if (!regs)
    {
        printf("Dumping registers: NULL\n");
        return;
    }
    printf("Dumping registers:\n");
    __dump_regs(regs);
}
