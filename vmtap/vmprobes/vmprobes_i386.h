#ifndef _ASM_VMPROBES_H
#define _ASM_VMPROBES_H

#include <stdint.h>

typedef uint8_t vmprobe_opcode_t;

#define BREAKPOINT_INSTRUCTION (0xcc)
#define BP_INSN_SIZE (1)

#define EF_TF (0x00000100)
#define EF_IF (0x00000200)

#define BITS_PER_LONG (32)
#define GOLDEN_RATIO_PRIME (0x9e370001UL)

struct vmprobe_probepoint;

static int
arch_save_org_insn(struct vmprobe_probepoint *probepoint);

static int
arch_insert_breakpoint(struct vmprobe_probepoint *probepoint);

static int
arch_remove_breakpoint(struct vmprobe_probepoint *probepoint);

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
    return (unsigned long)(regs->eip - BP_INSN_SIZE);
}

static inline void 
arch_reset_ip(struct cpu_user_regs *regs)
{
    regs->eip -= BP_INSN_SIZE;
}

static inline unsigned long
arch_hash_long(unsigned long val, unsigned int bits)
{
    unsigned long hash = val * GOLDEN_RATIO_PRIME;
    return (hash >> (BITS_PER_LONG - bits));
}

#endif /* _ASM_VMPROBES_H */

