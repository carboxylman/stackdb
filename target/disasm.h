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

#ifndef __DISASM_H__
#define __DISASM_H__

#include <mnemonics.h>
#include <distorm.h>
#include "common.h"

typedef _InstructionType dis_inst_t;
typedef _RegisterType dis_reg_t;

typedef enum {
    DECODE_TYPE_NONE = 0,
    DECODE_TYPE_CONTROL = 1,
} decode_t;

struct inst_data {
    SMOFFSET offset;
    dis_inst_t type;
    decode_t dtype;
    uint8_t size;
};

#define INST_NAME(inst_type) GET_MNEMONIC_NAME((inst_type))
#define REG_NAME(reg_type) GET_REGISTER_NAME((reg_type))

extern char *const inst_type_names[];

typedef enum {
    INST_NONE    = 0,
    INST_RET,
    INST_IRET,
    INST_CALL,
    INST_SYSCALL,
    INST_SYSRET,
    INST_SYSENTER,
    INST_SYSEXIT,
    INST_INT,
    INST_INT3,
    INST_INTO,
    INST_JMP,
    INST_JCC,
    INST_CMOV,
} inst_type_t;

#define INST_TYPE_NAME(inst_type) (((inst_type) < (sizeof(inst_type_names) \
						   / sizeof(inst_type_names[0]))) \
				   ? inst_type_names[(inst_type)] : "UNKNOWN")

typedef enum {
    INST_CF_ANY     = 0,
    INST_CF_RET     = 1 << INST_RET,
    INST_CF_IRET    = 1 << INST_IRET,
    INST_CF_CALL    = 1 << INST_CALL,
    INST_CF_SYSCALL = 1 << INST_SYSCALL,
    INST_CF_SYSRET  = 1 << INST_SYSRET,
    INST_CF_SYSENTER= 1 << INST_SYSENTER,
    INST_CF_SYSEXIT = 1 << INST_SYSEXIT,
    INST_CF_INT     = 1 << INST_INT,
    INST_CF_INT3    = 1 << INST_INT3,
    INST_CF_INTO    = 1 << INST_INTO,
    INST_CF_JMP     = 1 << INST_JMP,
    INST_CF_JCC     = 1 << INST_JCC,
    INST_CF_CMOV    = 1 << INST_CMOV,
} inst_cf_flags_t;

#define INST_TO_CF_FLAG(inst) (1 << (inst))

#define LOGDUMPDISASMCFIDATA(dl,lt,idata)		\
    vdebugc((dl),(lt),					\
	    "cf_inst_data(%s:+%"PRIdOFFSET":%s%s%s%s:disp=%"PRIu64","	\
	    "target=0x%"PRIxADDR")\n",					\
	    INST_TYPE_NAME((idata)->type),(idata)->offset,		\
	    ((idata)->cf.is_relative) ? "relative," : "",		\
	    ((idata)->cf.is_mem) ? "mem," : "",				\
	    ((idata)->cf.is_reg) ? "reg," : "",				\
	    ((idata)->cf.target_in_segment) ? "target_in_segment," : "", \
	    (idata)->cf.disp,(idata)->target);

struct cf_inst_data {
    inst_type_t type;
    OFFSET offset;
    uint8_t size;

    struct {
	int is_relative:1,
	    is_mem:1,
	    is_reg:1,
	    target_in_segment:1;

	uint64_t disp;
	union {
	    /* If it's an interrupt, which number. */
	    uint8_t intnum;
	    /* If it's an indirect jump/call, which register or mem
	     * contains the target address.
	     */
	    struct {
		dis_reg_t base_reg;
		dis_reg_t index_reg;
		uint8_t scale;
	    };
	    ADDR mem;
	    /* If it's a relative branch, the offset. */
	    OFFSET reloffset;
	    /* If it's an absolute branch, the dest addr. */
	    ADDR addr;
	};
	/* If the base address of the bytes to disasm is available, and the
	 * branch is an absolute branch, we can compute the actual
	 * destination.
	 */
	ADDR target;
    } cf;
};

struct disasm_data {
    struct bsymbol *bsymbol;
    ADDR start;
    unsigned int len;
    unsigned char *code;
};

#endif /* __DISASM_H__ */
