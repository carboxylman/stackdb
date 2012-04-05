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
 * File:   arch/i386/vmprobes.c
 * Author: Chung Hwan Kim
 * E-mail: chunghwn@cs.utah.edu
 */

#include <stdio.h>
#include <vmprobes/vmprobes.h>

/* 
 * inject a breakpoint instruction at the address to instrument. 
 */
int __vmprobes arch_arm_vmprobe(struct vmprobe *p)
{
    int ret = 0;
    vmprobe_opcode_t *addr = p->addr;
    vmprobe_opcode_t bp = BREAKPOINT_INSTRUCTION;
    
    ret = write_vmprobe(p, (uint32_t)addr, &bp, sizeof(bp));
    if (ret)
    {
        fprintf(stderr, "Error: Failed to inject breakpoint.\n");
        return ret;
    }
    
    vmprobe_verbose("- Breakpoint (%p) Injected.\n", bp);
    return ret;
}

/* 
 * remove a breakpoint instruction at the address to instrument. 
 */
int __vmprobes arch_disarm_vmprobe(struct vmprobe *p)
{
    int ret = 0;
    vmprobe_opcode_t *addr = p->addr;
    vmprobe_opcode_t opcode = p->opcode;
    
    ret = write_vmprobe(p, (uint32_t)addr, &opcode, sizeof(opcode));
    if (ret)
    {
        fprintf(stderr, "Error: Failed to restore opcode.\n");
        return ret;
    }
    
    vmprobe_verbose("- Opcode (%p) Restored.\n", opcode);
    return ret;
}

/*
 * modify the specified registers back to their original values as before
 * a breakpoint hit.
 */
void __vmprobes arch_restore_regs(struct pt_regs *regs)
{
    vmprobe_opcode_t *addr;
    /* subtract breakpoint size from eip */
    addr = (vmprobe_opcode_t *)(regs->eip - sizeof(vmprobe_opcode_t));
    regs->eip = (uint32_t)addr;
}

/*
 * modify the specified registers to turn singlestep mode on.
 */
void __vmprobes arch_inst_singlestep(struct pt_regs *regs)
{
    regs->eflags |= PSL_T;
}

/*
 * modify the specified registers to turn singlestep mode off.
 */
void __vmprobes arch_uninst_singlestep(struct pt_regs *regs)
{
    regs->eflags &= ~PSL_T;
}

/*
 * print out the specified register values.
 */
void __vmprobes arch_dump_regs(struct pt_regs *regs)
{
    printf("-- ebx: %08x\n"
           "-- ecx: %08x\n"
           "-- edx: %08x\n"
           "-- esi: %08x\n"
           "-- edi: %08x\n"
           "-- ebp: %08x\n"
           "-- eax: %08x\n"
           "-- eip: %08x\n"
           "-- xcs: %08x\n"
           "-- eflags: %08x\n"
           "-- esp: %08x\n"
           "-- xss: %08x\n"
           "-- xes: %08x\n"
           "-- xds: %08x\n"
           "-- xfs: %08x\n"
           "-- xgs: %08x\n",           
           regs->ebx, 
           regs->ecx,
           regs->edx,
           regs->esi,
           regs->edi,
           regs->ebp,
           regs->eax,
           regs->eip,
           regs->xcs,
           regs->eflags,
           regs->esp,
           regs->xss,
           regs->xes,
           regs->xds,
           regs->xfs,
           regs->xgs);
}
