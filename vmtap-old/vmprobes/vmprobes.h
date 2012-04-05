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
 * File:   vmprobes.h
 * Author: Chung Hwan Kim
 * E-mail: chunghwn@cs.utah.edu
 */

#ifndef _XEN_VMPROBES_H
#define _XEN_VMPROBES_H

#include <stdarg.h>
#include <xenctrl.h>
#define ENABLE_XEN
#include <xenaccess/xenaccess.h>

#ifdef __i386__
#include <vmprobes/arch/i386/vmprobes.h> // currently supports i386 only
#else // __i386__
#error hardware architecture not supported.
#endif // __i386__

/* vmprobes function signiture */
#define __vmprobes

#ifdef _VERBOSE
static void __vmprobes vmprobe_verbose(char *format, ...)
{
    va_list args;
    va_start(args, format);
    vfprintf(stdout, format, args);
    va_end(args);
}
#else // _VERBOSE
#define vmprobe_verbose(format, args...) ((void)0)
#endif // _VERBOSE

struct vmprobe;

/* user-defined handler types */
typedef int (*vmprobe_pre_handler_t) (struct vmprobe *, struct pt_regs *);
typedef int (*vmprobe_post_handler_t) (struct vmprobe *, struct pt_regs *, 
                                       unsigned long flags);

/* represents a probe */
struct vmprobe {
    /* id of the guest domain to instrument */
    domid_t domain_id;
    
    /* allow user to indicate domain name instead of domain id */
    const char *domain_name;
    
    /* virtual address to instrument */
    vmprobe_opcode_t *addr;
    
    /* allow user to indicate symbol name instead of address */
    const char *symbol_name;
    
    /* offset into the symbol */
    uint32_t offset;
    
    /* called before addr is executed */
    vmprobe_pre_handler_t pre_handler;
    
    /* called after addr is executed, unless... */
    vmprobe_post_handler_t post_handler;
    
    /* saved opcode (which has been replaced with breakpoint) */
    vmprobe_opcode_t opcode;
    
    /* indicates various status flags */
    uint32_t flags;
    
    /* handle to xenaccess library */
    xa_instance_t xa_instance;
};

/* status flags */
#define VMPROBE_FLAG_DISABLED (0x00000001) /* probe is temporarily disabled */
#define VMPROBE_FLAG_PREPARED (0x00000002) /* domain is prepared to instrument */
#define VMPROBE_FLAG_ARMED    (0x00000004) /* domain is armed with breakpoint */
#define VMPROBE_FLAG_RESTORED (0x00000008) /* domain registers are restored */

/* Is this vmprobe disabled? */
static inline int vmprobe_disabled(struct vmprobe *p)
{
    return (p->flags & VMPROBE_FLAG_DISABLED);
}

/* Is this vmprobe prepared? */
static inline int vmprobe_prepared(struct vmprobe *p)
{
    return (p->flags & VMPROBE_FLAG_PREPARED);
}

/* Is this vmprobe armed? */
static inline int vmprobe_armed(struct vmprobe *p)
{
    return (p->flags & VMPROBE_FLAG_ARMED);
}

/* Is this vmprobe restored? */
static inline int vmprobe_restored(struct vmprobe *p)
{
    return (p->flags & VMPROBE_FLAG_RESTORED);
}

/* vmprobe notify values */
#define VMPROBE_NOTIFY_DONE  (0)
#define VMPROBE_NOTIFY_STOP  (1)
#define VMPROBE_NOTIFY_INT3  (2)
#define VMPROBE_NOTIFY_DEBUG (3)

/* hardware architecture-dependent functions */
extern int arch_arm_vmprobe(struct vmprobe *p);
extern int arch_disarm_vmprobe(struct vmprobe *p);
extern void arch_restore_regs(struct pt_regs *regs);
extern void arch_inst_singlestep(struct pt_regs *regs);
extern void arch_uninst_singlestep(struct pt_regs *regs);
extern void arch_dump_regs(struct pt_regs *regs);

/* given a user-specified vmprobe instance, initialize and prepare for 
   instrumentation. return non-zero value when an error occurs. */
int register_vmprobe(struct vmprobe *p);

/* finish up instrumentation and restore the status of the target vm. return 
   non-zero value when an error occurs. */
void unregister_vmprobe(struct vmprobe *p);

/* start instrumentation and continue until a user handler returns non-zero. 
   return non-zero value when error occurs. */
int loop_vmprobe(struct vmprobe *p);

/* disable the specified vmprobe.  */
void disable_vmprobe(struct vmprobe *p);

/* enable the specified vmprobe. */
void enable_vmprobe(struct vmprobe *p);

/* read the specified size at the address of the instrumented vm, and save the
   data in the buffer. return non-zero if an error occurs. */
int read_vmprobe(struct vmprobe *p, uint32_t addr, void *buf, uint32_t size);

/* write the specified size of the data in the buffer to the address of the 
   instrumented vm. return non-zero if an error occurs. */
int write_vmprobe(struct vmprobe *p, uint32_t addr, const void *buf, 
                  uint32_t size);

/* print out the fields of the specified vmprobe instance. */
void dump_vmprobe(struct vmprobe *p);

/* print out the specified register values. */
void dump_regs(struct pt_regs *regs);

#endif // _XEN_VMPROBES_H
