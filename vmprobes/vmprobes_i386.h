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

#ifndef _ASM_VMPROBES_H
#define _ASM_VMPROBES_H

#include <stdint.h>

#define MAX_I386_INSTR_LEN 17

struct vmprobe_opcode {
    uint8_t bytes[MAX_I386_INSTR_LEN];
    uint8_t len;
};

#define INSTR_BREAKPOINT     (0xcc)
#define INSTR_BREAKPOINT_LEN 1
#define INSTR_LEAVE      (0xc9)
#define INSTR_RET        (0xc3)

vmprobe_opcode_t BREAKPOINT = {
    .bytes = { INSTR_BREAKPOINT },
    .len = 1,
};

vmprobe_opcode_t RETURN = {
    .bytes = { INSTR_RET },
    .len = 1,
};

#define EF_TF (0x00000100)
#define EF_IF (0x00000200)

#define BITS_PER_LONG (8 * sizeof(long))
#define GOLDEN_RATIO_PRIME (0x9e370001UL)

struct vmprobe_probepoint;

static int
arch_insert_breakpoint(struct vmprobe_probepoint *probepoint);

static int
arch_remove_breakpoint(struct vmprobe_probepoint *probepoint);

static int
arch_insert_code(struct vmprobe_probepoint *probepoint,
		 struct vmprobe_opcode **opcode_list,
		 unsigned int opcode_list_len,
		 uint8_t offset,
		 uint8_t nosave);

static int
arch_remove_code(struct vmprobe_probepoint *probepoint);

static inline int
arch_in_singlestep(struct cpu_user_regs *regs)
{
    return (regs->eflags & EF_TF) ? 1 : 0;
}

static inline void
arch_enter_singlestep(struct cpu_user_regs *regs)
{
    regs->eflags |= EF_TF;
}

static inline void
arch_leave_singlestep(struct cpu_user_regs *regs)
{
    regs->eflags &= ~EF_TF;
}

/* On i386, the int3 traps leaves eip pointing past the int3 instruction. */
static inline unsigned long 
arch_get_org_ip(struct cpu_user_regs *regs)
{
    return (unsigned long)(regs->eip - BREAKPOINT.len);
}

static inline void 
arch_reset_ip(struct cpu_user_regs *regs)
{
    regs->eip -= BREAKPOINT.len;
}

static inline unsigned long
arch_hash_long(unsigned long val, unsigned int bits)
{
    unsigned long hash = val * GOLDEN_RATIO_PRIME;
    return (hash >> (BITS_PER_LONG - bits));
}

#endif /* _ASM_VMPROBES_H */

