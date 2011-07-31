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

struct pt_regs {
    long ebx;       /* 0 */
    long ecx;       /* 4 */
    long edx;       /* 8 */
    long esi;       /* 12 */
    long edi;       /* 16 */
    long ebp;       /* 20 */
    long eax;       /* 24 */
    int  xds;       /* 28 */
    int  xes;       /* 32 */
    int  xfs;       /* 36 */
    int  xgs;       /* 40 */
    long orig_eax;  /* 44 */
    long eip;       /* 48 */
    int  xcs;       /* 52 */
    long eflags;    /* 56 */
    long esp;       /* 60 */
    int  xss;       /* 64 */
};

#define SET_PT_REGS(pt, xc)     \
{                               \
    pt.ebx = xc.ebx;            \
    pt.ecx = xc.ecx;            \
    pt.edx = xc.edx;            \
    pt.esi = xc.esi;            \
    pt.edi = xc.edi;            \
    pt.ebp = xc.ebp;            \
    pt.eax = xc.eax;            \
    pt.eip = xc.eip;            \
    pt.xcs = xc.cs;             \
    pt.eflags = xc.eflags;      \
    pt.esp = xc.esp;            \
    pt.xss = xc.ss;             \
    pt.xes = xc.es;             \
    pt.xds = xc.ds;             \
    pt.xfs = xc.fs;             \
    pt.xgs = xc.gs;             \
}

#define SET_XC_REGS(pt, xc)     \
{                               \
    xc.ebx = pt->ebx;           \
    xc.ecx = pt->ecx;           \
    xc.edx = pt->edx;           \
    xc.esi = pt->esi;           \
    xc.edi = pt->edi;           \
    xc.ebp = pt->ebp;           \
    xc.eax = pt->eax;           \
    xc.eip = pt->eip;           \
    xc.cs = pt->xcs;            \
    xc.eflags = pt->eflags;     \
    xc.esp = pt->esp;           \
    xc.ss = pt->xss;            \
    xc.es = pt->xes;            \
    xc.ds = pt->xds;            \
    xc.fs = pt->xfs;            \
    xc.gs = pt->xgs;            \
}

struct vmprobe_probepoint;

static int
arch_save_org_insn(struct vmprobe_probepoint *probepoint);

static int
arch_insert_breakpoint(struct vmprobe_probepoint *probepoint);

static int
arch_remove_breakpoint(struct vmprobe_probepoint *probepoint);

static inline void
arch_enter_singlestep(struct pt_regs *regs)
{
    regs->eflags |= EF_TF;
}

static inline void
arch_leave_singlestep(struct pt_regs *regs)
{
    regs->eflags &= ~EF_TF;
}

/* On i386, the int3 traps leaves eip pointing past the int3 instruction. */
static inline unsigned long 
arch_get_org_ip(struct pt_regs *regs)
{
    return (unsigned long)(regs->eip - BP_INSN_SIZE);
}

static inline void 
arch_reset_ip(struct pt_regs *regs)
{
    regs->eip -= BP_INSN_SIZE;
}

static inline unsigned long 
arch_get_cur_sp(struct pt_regs *regs)
{
    return (unsigned long)regs->esp;
}

static inline unsigned long
arch_hash_long(unsigned long val, unsigned int bits)
{
    unsigned long hash = val * GOLDEN_RATIO_PRIME;
    return (hash >> (BITS_PER_LONG - bits));
}

#endif /* _ASM_VMPROBES_H */

