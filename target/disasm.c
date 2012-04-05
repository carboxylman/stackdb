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

#include "disasm.h"
#include "target_api.h"
#include "alist.h"

#include <distorm.h>
#include <mnemonics.h>

static char *inst_names[] = {
    "NONE",
    "RET",
    "CALL",
    "SYSCALL",
    "SYSRET",
    "INT",
    "JMP",
    "JCC",
    "CMOV",
};

const char *disasm_get_inst_name(inst_type_t type) {
    return inst_names[type];
}

/*
 * Returns offsets for a specific instruction.
 */
int disasm_get_control_flow_offsets(struct target *target,inst_cf_flags_t flags,
				    unsigned char *inst_buf,unsigned int buf_len,
				    struct array_list **offset_list,ADDR base,
				    int noabort) {
    _CodeInfo ci;
    _DInst di;
    _DecodedInst inst;
    unsigned int di_count = 0;
    struct array_list *tmplist;
    struct inst_cf_data *idata;

    if (!offset_list || flags == 0) {
	errno = EINVAL;
	return -1;
    }

    tmplist = array_list_create(0);

    ci.code = (unsigned char *)inst_buf;
    ci.codeLen = buf_len;
    ci.codeOffset = 0;
    ci.features = DF_NONE;
    if (target->wordsize == 4)
	ci.dt = Decode32Bits;
    else
	ci.dt = Decode64Bits;

    while (ci.codeOffset < buf_len) {
	memset(&di,0,sizeof(di));
	if (distorm_decompose64(&ci,&di,1,&di_count) == DECRES_INPUTERR) {
	    vwarn("decoding error at offset %"PRIu64"\n",ci.codeOffset);
	    goto inst_err_out;
	}
	if (di_count == 0) 
	    break;

	if (di.flags == FLAG_NOT_DECODABLE) {
	    vwarn("bad instruction at offset %"PRIu64"\n",ci.codeOffset);
	    if (!noabort)
		goto inst_err_out;
	    else {
		ci.codeOffset += 1;
		ci.code += 1;
		continue;
	    }
	}

	/*
	 * Only decode RETs; add their offsets to the list when we find them! 
	 */
	memset(&inst,0,sizeof(inst));
	if (flags & INST_CF_RET 
	    && (di.opcode == I_RET || di.opcode == I_RETF)) {
	    idata = calloc(1,sizeof(*idata));
	    memset(idata,0,sizeof(*idata));

	    idata->type = INST_RET;
	    idata->offset = ci.codeOffset;
	    array_list_add(tmplist,idata);

	    goto valid_inst;
	}
	else if (flags & INST_CF_CALL 
	    && (di.opcode == I_CALL || di.opcode == I_CALL_FAR)) {
	    idata = calloc(1,sizeof(*idata));
	    memset(idata,0,sizeof(*idata));

	    idata->type = INST_CALL;
	    idata->offset = ci.codeOffset;

	    if (di.ops[0].type == O_PC) {
		idata->target_addr = base + INSTRUCTION_GET_TARGET(&di);
	    }
	    else if (di.ops[0].type == O_IMM && di.opcode == I_CALL) {
		idata->target_is_offset = 1;
		idata->target_offset = di.imm.sqword;
	    }
	    else if (di.ops[0].type == O_IMM && di.opcode == I_CALL_FAR) {
		idata->target_addr = di.imm.qword;
	    }
	    else if (di.ops[0].type == O_PTR && di.opcode == I_CALL_FAR) {
		idata->target_addr = di.imm.ptr.off;
	    }
	    else if (di.ops[0].type == O_REG && di.opcode == I_CALL) {
		idata->target_is_reg = 1;
		idata->target_reg = di.ops[0].index;
	    }
	    else {
		distorm_format(&ci,&di,&inst);
		vwarn("decoded unknown call inst %s %s at %"PRIu64"\n",
		       inst.mnemonic.p,inst.operands.p,ci.codeOffset);
		goto invalid_inst;
	    }

	    array_list_add(tmplist,idata);

	    goto valid_inst;
	}
	else {
	    distorm_format(&ci,&di,&inst);
	    vdebug(6,LOG_T_DISASM,"decoded ignored inst %s %s at %"PRIu64"\n",
		   inst.mnemonic.p,inst.operands.p,ci.codeOffset);
	    goto invalid_inst;
	}

    valid_inst:
	distorm_format(&ci,&di,&inst);
	vdebug(3,LOG_T_DISASM,"decoded %s %s at %"PRIu64"\n",
	       inst.mnemonic.p,inst.operands.p,ci.codeOffset);

    invalid_inst:
	/* Setup next iteration. */
	ci.codeOffset += di.size;
	ci.code += di.size;
    }

    if (ci.codeOffset != buf_len) {
	vwarn("decoding stopped %"PRIi64" bytes short\n",
	      (uint64_t)buf_len - ci.codeOffset);
	if (!noabort)
	    goto inst_err_out;
    }

    if (offset_list)
	*offset_list = tmplist;
    return 0;

 inst_err_out:
    array_list_deep_free(tmplist);
    return -1;
}


/*
 * Returns an integer corresponding to modifications to the stack
 * pointer.  For instance, if you pass it a prologue, we'll likely
 * return a negative integer as the stack grows downwards -- i.e.,
 * during pushes, subs, enters.
 *
 * On error, we return -1; on success, 0.
 */
int disasm_get_prologue_stack_size(struct target *target,
				   unsigned char *inst_buf,unsigned int buf_len,
				   int *sp) {
    _CodeInfo ci;
    _DInst di;
    _DecodedInst inst;
    unsigned int di_count = 0;
    int retval = 0;
    int i;

    if (!sp) {
	errno = EINVAL;
	return -1;
    }

    ci.code = (unsigned char *)inst_buf;
    ci.codeLen = buf_len;
    ci.codeOffset = 0;
    /* Make it stop decoding if it encounters
     * CALL/FAR, RET/IRET/RETF, SYSENTER/SYSEXIT/SYSCALL/SYSRET,
     * conditional/unconditional branches, INT, CMOV.
     */
    ci.features = DF_STOP_ON_FLOW_CONTROL;
    if (target->wordsize == 4)
	ci.dt = Decode32Bits;
    else
	ci.dt = Decode64Bits;

    while (ci.codeOffset < buf_len) {
	memset(&di,0,sizeof(di));
	if (distorm_decompose64(&ci,&di,1,&di_count) == DECRES_INPUTERR) {
	    vwarn("decoding error at offset %"PRIu64"\n",ci.codeOffset);
	    return -1;
	}
	if (di_count == 0) 
	    break;

	if (di.flags == FLAG_NOT_DECODABLE) {
	    vwarn("bad instruction at offset %"PRIu64"\n",ci.codeOffset);
	    return -1;
	}

	distorm_format(&ci,&di,&inst);
	vdebug(3,LOG_T_DISASM,"decoded %s %s\n",inst.mnemonic.p,inst.operands.p);

	/*
	 * XXX: all the inc/decrements for ENTER, POP/PUSH are affected
	 * by the operand-size attribute of the current code segment
	 * and/or stack segment descriptor.  We'd have to read the
	 * current CS/SS registers, or if the target is not executing,
	 * we'd have to get their state from elsewhere.
	 *
	 * So just ignore this for now and assume 8-byte stack size
	 * increments for 64-bit, and 4-byte increments for 32-bit
	 * binaries.
	 */
	switch (di.opcode) {
	case I_NOP:
	    break;
	case I_ENTER:
	    /* We only support 32- or 64-bit ENTER. */
	    if (di.ops[0].type != O_IMM1 || di.ops[1].type != O_IMM2) {
		vwarn("ENTER did not have two imm operands; error!\n");
		goto inst_err_out;
	    }

	    int size = di.imm.ex.i1;
	    int nestinglevel = di.imm.ex.i2 % 32;

	    /* Handle BP push. */
	    retval -= target->wordsize;

	    /* Push nesting area. */
	    for (i = 1; i < nestinglevel; ++i) {
		retval -= target->wordsize;
	    }

	    /* Push frame temp. */
	    retval -= target->wordsize;

	    /* Push the size. */
	    retval -= size;

	    break;
	case I_PUSH:
	case I_PUSHF:
	    retval -= target->wordsize;
	    break;
	case I_PUSHA:
	    /* Push all general-purpose regs. */
	    retval -= target->wordsize * 8;
	    break;
	case I_POP:
	case I_POPF:
	    retval += target->wordsize;
	    break;
	case I_POPA:
	    /* Pop all general-purpose regs (except ESP, which is skipped). */
	    retval += target->wordsize * 8;
	    break;
	case I_ADD:
	    if (di.ops[0].type == O_REG && di.ops[0].index & RM_SP) {
		if (di.ops[1].type == O_IMM)
		    retval += di.imm.sword;
		else {
		    vwarn("unsupported SP offset op: ADD!\n");
		    goto inst_err_out;
		}
	    }
	    break;
	case I_SUB:
	    if (di.ops[0].type == O_REG && di.ops[0].index & RM_SP) {
		if (di.ops[1].type == O_IMM)
		    retval -= di.imm.sword;
		else {
		    vwarn("unsupported SP offset op: SUB!\n");
		    goto inst_err_out;
		}
	    }
	    break;
	/* We assume shifts never operate on a 0-valued ESP!!  That
	 * would be silly, but I suppose it could happen.
	 */
	case I_SAL:
	case I_SAR:
	case I_SHL:
	    if (di.ops[0].type == O_REG && di.ops[0].index & RM_SP) {
		if (di.ops[1].type != O_IMM) {
		    vwarn("unsupported SP offset op: SAL/SAR/SHL!\n");
		    goto inst_err_out;
		}
		else {
		    if (di.imm.byte == 0)
			break;
		    if (di.opcode == I_SAR)
			retval -= 1 << di.imm.byte;
		    else 
			retval += 1 << di.imm.byte;
		}
	    }
	    break;
	case I_SHR:
	    if (di.ops[0].type == O_REG && di.ops[0].index & RM_SP) {
		vwarn("unsupported SP offset op: SHR!\n");
		goto inst_err_out;
	    }
	    break;
	case I_MOV:
	    if (di.ops[0].type == O_REG && di.ops[0].index & RM_SP) {
		vwarn("unsupported SP offset op: MOV!\n");
		goto inst_err_out;
	    }
	    break;
        /* These can never have any effect on ESP since they only
	 * inc/dec by 1 -- and we always inc/dec the SP by at least 2.
	 */
	case I_DEC:
	case I_INC:
	    break;
	/* These have implied destination of EAX, so we can ignore
	 * them.
	 */
	case I_DIV:
	case I_MUL:
	case I_IDIV:
	    break;
	/* If the first operand (destination) is ESP, we have to give
	 * up, since our offset would be dependent on the current value
	 * of ESP -- which we don't know without actually arriving at
	 * this code point.
	 */
	case I_IMUL:
	    /* This can take either the MUL one-operand form, or more. */
	    if (di.ops[1].type != O_NONE 
		&& di.ops[0].type == O_REG && di.ops[0].index & RM_SP) {
		vwarn("unsupported SP offset op: IMUL!\n");
		goto inst_err_out;
	    }
	    break;
	case I_XOR:
	    if (di.ops[0].type == O_REG && di.ops[0].index & RM_SP) {
		vwarn("unsupported SP offset op: XOR!\n");
		goto inst_err_out;
	    }
	    break;
	case I_AND:
	    if (di.ops[0].type == O_REG && di.ops[0].index & RM_SP) {
		vwarn("unsupported SP offset op: AND!\n");
		goto inst_err_out;
	    }
	    break;
	case I_OR:
	    if (di.ops[0].type == O_REG && di.ops[0].index & RM_SP) {
		vwarn("unsupported SP offset op: OR!\n");
		goto inst_err_out;
	    }
	    break;
        /* One-operand instructions: */
	case I_NOT:
	    if (di.ops[0].type == O_REG && di.ops[0].index & RM_SP) {
		vwarn("unsupported SP offset op: NOT!\n");
		goto inst_err_out;
	    }
	    break;
	case I_NEG:
	    if (di.ops[0].type == O_REG && di.ops[0].index & RM_SP) {
		vwarn("unsupported SP offset op: NEG!\n");
		goto inst_err_out;
	    }
	    break;
	default:
	    break;
	}

	/* Setup next iteration. */
	ci.codeOffset += di.size;
    }

    if (ci.codeOffset != buf_len) {
	vwarn("decoding stopped %"PRIu64" bytes short; bad prologue?\n",
	      buf_len - ci.codeOffset - 1);
	return -1;
    }

    *sp = retval;
    return 0;

 inst_err_out:
    return -1;
}
