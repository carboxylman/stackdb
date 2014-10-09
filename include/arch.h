/*
 * Copyright (c) 2014 The University of Utah
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

#ifndef __ARCH_H__
#define __ARCH_H__

#include "config.h"
#include "common.h"

#include <glib.h>

/*
 * Ok.  Architecture support should have any instruction-level or
 * register-level definitions, functions, that we need.  For instance,
 * it should have things like X86_IP, X86_CR1, X86_64_IP, etc.
 *
 * Each arch should have a register file that allows
 * reading/writing/flushing/setting, and doing so for the REGVAL size by
 * default, but also supporting arbitrary-sized regvals (like 512-bit
 * avx2 registers, or whatever).
 *
 * There should be mappings for debuginfo register numbers.  These ABI
 * register numbers should be the primary register numbers for each
 * arch.
 *
 * But then how does the user access the regs?  Ideally, through a CREG
 * abstraction.  Any arch should have an IP/PC; SP; BP; RA; RV; but then
 * the GP ones always have different names.
 *
 * I'm fine to have files like arch_x86.h that have X86_IP 55 macros in
 * them.  We could even allow RAX to mean EAX on x86_64, transparently?
 * And each arch_ops struct would have translation tables that trnaslate
 * names to numbers.  We can evn support pseudo-registers or MTRRs this
 * way... the backend just writes numeric registers based on what the
 * arch_ops type of the target is.  So, readreg/writereg might become
 * arch-specific instead of target-specific???
 *
 * Also push breakpoint instruction stuff in.
 * Also disassembly (?)
 * Also 
 *
 * Anyway, backends can cache the current thread's registers when they
 * load them; then the target API will tell teh backend to write
 * registers, and it will update its cache; then it will flush later.
 * The target API/arch ops should keep track of which regs were
 * modified, and only write those.
 *
 * Hm, maybe our register file can actually be generic?  Just give it a
 * max number, and degree of sparseness, and let it do its thing?  Then
 * hint which regs are super-sized... ?  Yes!
 */

typedef enum {
    ENDIAN_BIG = 0,
    ENDIAN_LITTLE = 1,
} endian_t;

typedef enum {
    CREG_IP = 0,
    CREG_BP,
    CREG_SP,
    CREG_FLAGS,
    CREG_RET,
} common_reg_t;
#define COMMON_REG_COUNT CREG_RET + 1

/*
 * A simple abstraction for machine architectures.  Haven't even made
 * any endian swapping arrangements yet.  Right now, this is all about
 * registers.  This structure, coupled to an arch_config, helps the
 * target lib get the most out of a regcache.
 *
 * For now, we just assume that sizeof(REG) is 1 byte; this means that
 * our data structures stay small enough with flat arrays.  Later, we
 * might need to go to hashtables or sparse arrays for many-register
 * architectures.  When pigs fly... even ia64 was only 128.  We could
 * fix that by changing REG to uint8_t instead of int8_t and doing
 * better error handling.
 *
 * Assume a byte is 8 bits, and that every significant machine
 * abstraction is at least byte-aligned.  We'll never support anything
 * else!
 */

typedef enum {
    ARCH_NONE = 0,
    ARCH_X86 = 1,
    ARCH_X86_64 = 2,
} arch_type_t;

/*
 * This is a two-dimensional array.  It specifies an ordered list of
 * registers to print at each level of detail.  For instance,
 *
 * { { 1,3,5,7,-1 },
 *   { 2,4,6,8,-1 },
 *   NULL, }
 */
#define ARCH_SNPRINTF_DETAIL_LEVELS 3 /* 0,1,2 */

struct arch {
    arch_type_t type;
    const char *name;

    endian_t endian;
    unsigned int wordsize;
    unsigned int ptrsize;

    /*
     * Max register number + 1.  Not all registers from (0,max) need be
     * supported; set reg_sizes[i] and reg_names[i] appropriately.
     */
    int regcount;
    /*
     * This array must be @regcount long.  Register numbers that this
     * architecture does not provide should be set to 0.
     */
    uint8_t *reg_sizes;
    /*
     * This array must be COMMON_REG_COUNT long.  Unbound regs should be
     * set to -1.
     */
    REG *common_to_arch; //[COMMON_REG_COUNT];
    /*
     * This array must be @regcount long.  Unbound regs should have NULL
     * names.
     */
    char **reg_names;

    int *snprintf_ordering[ARCH_SNPRINTF_DETAIL_LEVELS];
    int max_snprintf_ordering;

    /* One or more opcodes that create a software breakpoint */
    uint8_t *breakpoint_instrs;
    unsigned int breakpoint_instrs_len;
    /* How many opcodes are in the above sequence, so we can single-step
     * past them all.
     */
    unsigned int breakpoint_instr_count;

    uint8_t *ret_instrs;
    unsigned int ret_instrs_len;
    unsigned int ret_instr_count;

    uint8_t *full_ret_instrs;
    unsigned int full_ret_instrs_len;
    unsigned int full_ret_instr_count;
};

/* Get the arch struct corresponding to the given arch type. */
struct arch *arch_get(arch_type_t at);

/* Some simple accessors. */
static inline const char *arch_name(struct arch *arch) { return arch->name; }
static inline arch_type_t arch_type(struct arch *arch) { return arch->type; }
static inline endian_t arch_endian(struct arch *arch) { return arch->endian; }
static inline unsigned int arch_wordsize(struct arch *arch) { return arch->wordsize; }
static inline unsigned int arch_ptrsize(struct arch *arch) { return arch->ptrsize; }
static inline int arch_regcount(struct arch *arch) { return arch->regcount; }

int arch_has_reg(struct arch *arch,REG reg);
/* Get the size of an arch-specific register number. */
unsigned int arch_regsize(struct arch *arch,REG reg);
/* Get arch-specific register name. */
const char *arch_regname(struct arch *arch,REG reg);
/* Get arch-specific reg number for the "common" register. */
int arch_regno(struct arch *arch,char *name,REG *reg);
/* Get arch-specific reg number for the "common" register. */
int arch_cregno(struct arch *arch,common_reg_t creg,REG *reg);

#endif /* __ARCH_H__ */
