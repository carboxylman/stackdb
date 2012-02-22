#include "target_api.h"

#include <distorm.h>
#include <mnemonics.h>

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
	vdebug(3,LOG_P_ACTION,"decoded %s %s\n",inst.mnemonic.p,inst.operands.p);

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
