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

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>

#include "common.h"
#include "dwdebug.h"
#include "dwdebug_priv.h"

#include "memory-access.h"

#include <dwarf.h>
#include <gelf.h>
#include <elfutils/libebl.h>
#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>

/*
 * DWARF operations, nicely indexed.
 */
static const char *const known_ops[] = {
    [DW_OP_addr] = "addr",
    [DW_OP_deref] = "deref",
    [DW_OP_const1u] = "const1u",
    [DW_OP_const1s] = "const1s",
    [DW_OP_const2u] = "const2u",
    [DW_OP_const2s] = "const2s",
    [DW_OP_const4u] = "const4u",
    [DW_OP_const4s] = "const4s",
    [DW_OP_const8u] = "const8u",
    [DW_OP_const8s] = "const8s",
    [DW_OP_constu] = "constu",
    [DW_OP_consts] = "consts",
    [DW_OP_dup] = "dup",
    [DW_OP_drop] = "drop",
    [DW_OP_over] = "over",
    [DW_OP_pick] = "pick",
    [DW_OP_swap] = "swap",
    [DW_OP_rot] = "rot",
    [DW_OP_xderef] = "xderef",
    [DW_OP_abs] = "abs",
    [DW_OP_and] = "and",
    [DW_OP_div] = "div",
    [DW_OP_minus] = "minus",
    [DW_OP_mod] = "mod",
    [DW_OP_mul] = "mul",
    [DW_OP_neg] = "neg",
    [DW_OP_not] = "not",
    [DW_OP_or] = "or",
    [DW_OP_plus] = "plus",
    [DW_OP_plus_uconst] = "plus_uconst",
    [DW_OP_shl] = "shl",
    [DW_OP_shr] = "shr",
    [DW_OP_shra] = "shra",
    [DW_OP_xor] = "xor",
    [DW_OP_bra] = "bra",
    [DW_OP_eq] = "eq",
    [DW_OP_ge] = "ge",
    [DW_OP_gt] = "gt",
    [DW_OP_le] = "le",
    [DW_OP_lt] = "lt",
    [DW_OP_ne] = "ne",
    [DW_OP_skip] = "skip",
    [DW_OP_lit0] = "lit0",
    [DW_OP_lit1] = "lit1",
    [DW_OP_lit2] = "lit2",
    [DW_OP_lit3] = "lit3",
    [DW_OP_lit4] = "lit4",
    [DW_OP_lit5] = "lit5",
    [DW_OP_lit6] = "lit6",
    [DW_OP_lit7] = "lit7",
    [DW_OP_lit8] = "lit8",
    [DW_OP_lit9] = "lit9",
    [DW_OP_lit10] = "lit10",
    [DW_OP_lit11] = "lit11",
    [DW_OP_lit12] = "lit12",
    [DW_OP_lit13] = "lit13",
    [DW_OP_lit14] = "lit14",
    [DW_OP_lit15] = "lit15",
    [DW_OP_lit16] = "lit16",
    [DW_OP_lit17] = "lit17",
    [DW_OP_lit18] = "lit18",
    [DW_OP_lit19] = "lit19",
    [DW_OP_lit20] = "lit20",
    [DW_OP_lit21] = "lit21",
    [DW_OP_lit22] = "lit22",
    [DW_OP_lit23] = "lit23",
    [DW_OP_lit24] = "lit24",
    [DW_OP_lit25] = "lit25",
    [DW_OP_lit26] = "lit26",
    [DW_OP_lit27] = "lit27",
    [DW_OP_lit28] = "lit28",
    [DW_OP_lit29] = "lit29",
    [DW_OP_lit30] = "lit30",
    [DW_OP_lit31] = "lit31",
    [DW_OP_reg0] = "reg0",
    [DW_OP_reg1] = "reg1",
    [DW_OP_reg2] = "reg2",
    [DW_OP_reg3] = "reg3",
    [DW_OP_reg4] = "reg4",
    [DW_OP_reg5] = "reg5",
    [DW_OP_reg6] = "reg6",
    [DW_OP_reg7] = "reg7",
    [DW_OP_reg8] = "reg8",
    [DW_OP_reg9] = "reg9",
    [DW_OP_reg10] = "reg10",
    [DW_OP_reg11] = "reg11",
    [DW_OP_reg12] = "reg12",
    [DW_OP_reg13] = "reg13",
    [DW_OP_reg14] = "reg14",
    [DW_OP_reg15] = "reg15",
    [DW_OP_reg16] = "reg16",
    [DW_OP_reg17] = "reg17",
    [DW_OP_reg18] = "reg18",
    [DW_OP_reg19] = "reg19",
    [DW_OP_reg20] = "reg20",
    [DW_OP_reg21] = "reg21",
    [DW_OP_reg22] = "reg22",
    [DW_OP_reg23] = "reg23",
    [DW_OP_reg24] = "reg24",
    [DW_OP_reg25] = "reg25",
    [DW_OP_reg26] = "reg26",
    [DW_OP_reg27] = "reg27",
    [DW_OP_reg28] = "reg28",
    [DW_OP_reg29] = "reg29",
    [DW_OP_reg30] = "reg30",
    [DW_OP_reg31] = "reg31",
    [DW_OP_breg0] = "breg0",
    [DW_OP_breg1] = "breg1",
    [DW_OP_breg2] = "breg2",
    [DW_OP_breg3] = "breg3",
    [DW_OP_breg4] = "breg4",
    [DW_OP_breg5] = "breg5",
    [DW_OP_breg6] = "breg6",
    [DW_OP_breg7] = "breg7",
    [DW_OP_breg8] = "breg8",
    [DW_OP_breg9] = "breg9",
    [DW_OP_breg10] = "breg10",
    [DW_OP_breg11] = "breg11",
    [DW_OP_breg12] = "breg12",
    [DW_OP_breg13] = "breg13",
    [DW_OP_breg14] = "breg14",
    [DW_OP_breg15] = "breg15",
    [DW_OP_breg16] = "breg16",
    [DW_OP_breg17] = "breg17",
    [DW_OP_breg18] = "breg18",
    [DW_OP_breg19] = "breg19",
    [DW_OP_breg20] = "breg20",
    [DW_OP_breg21] = "breg21",
    [DW_OP_breg22] = "breg22",
    [DW_OP_breg23] = "breg23",
    [DW_OP_breg24] = "breg24",
    [DW_OP_breg25] = "breg25",
    [DW_OP_breg26] = "breg26",
    [DW_OP_breg27] = "breg27",
    [DW_OP_breg28] = "breg28",
    [DW_OP_breg29] = "breg29",
    [DW_OP_breg30] = "breg30",
    [DW_OP_breg31] = "breg31",
    [DW_OP_regx] = "regx",
    [DW_OP_fbreg] = "fbreg",
    [DW_OP_bregx] = "bregx",
    [DW_OP_piece] = "piece",
    [DW_OP_deref_size] = "deref_size",
    [DW_OP_xderef_size] = "xderef_size",
    [DW_OP_nop] = "nop",
    [DW_OP_push_object_address] = "push_object_address",
    [DW_OP_call2] = "call2",
    [DW_OP_call4] = "call4",
    [DW_OP_call_ref] = "call_ref",
    [DW_OP_form_tls_address] = "form_tls_address",
    [DW_OP_call_frame_cfa] = "call_frame_cfa",
    [DW_OP_bit_piece] = "bit_piece",
#if _INT_ELFUTILS_VERSION > 138
    [DW_OP_GNU_push_tls_address] = "GNU_push_tls_address",
    [DW_OP_GNU_uninit] = "GNU_uninit",
    [DW_OP_GNU_encoded_addr] = "GNU_encoded_addr",
#endif
#if _INT_ELFUTILS_VERSION > 141
    [DW_OP_implicit_value] = "implicit_value",
    [DW_OP_stack_value] = "stack_value",
#endif
#if _INT_ELFUTILS_VERSION > 148
    [DW_OP_GNU_implicit_pointer] = "GNU_implicit_pointer",
#endif
};

const char *dwarf_op_string(unsigned int op) {
    if (op < (sizeof(known_ops) / sizeof(known_ops[0])))
	return known_ops[op];
    return NULL;
}

loctype_t dwarf_location_resolve(const unsigned char *data,unsigned int len,
				 struct location_ctxt *lctxt,
				 struct symbol *symbol,struct location *o_loc) {
    unsigned int addrsize = 0;

    /* const unsigned int ref_size = vers < 3 ? addrsize : offset_size; */

    /* XXX: we can't get other_byte_order from dbg since we don't have
     * the struct def for it... so we assume it's not a diff byte order
     * than the phys host for now.
     */
    int obo = 0;

    /* save the originals for later for runtime computation if we need */
    const unsigned char *origdata = data;
    int origlen = len;

    /*
     * We try to use a static stack; if we run out, we malloc one.
     */
    int stackdepth = 0;
    Dwarf_Word stack[16];
    Dwarf_Word *overflowstack = NULL;
    int overflowstacklen = 0;

    struct location_ops *lops = NULL;

    if (!lctxt || !lctxt->ops) {
	verror("no location ops for current frame %d!\n",lctxt->current_frame);
	errno = EINVAL;
	return -1;
    }
    lops = lctxt->ops;

    if (len == 0) {
	vwarn("empty dwarf block num!\n");
	goto errout;
    }

    /*
     * We don't want to have to trace from @symbol all the way back to
     * the root and grab the DWARF addrsize out of root->extra.root each
     * time we call this function.  So try to rely on the target's info,
     * if it exists; else, just assume host word size == target word
     * size.
     */
    if (lops && lops->getaddrsize)
	addrsize = lops->getaddrsize(lctxt);
    /* Else just make a best-effort guess. */
    if (addrsize <= 0)
	addrsize = sizeof(Dwarf_Word);

#define NEED(n)								\
    if (len < (n)) goto errout
#define CONSUME(n)							\
    NEED (n); else len -= (n)
#define NEEDSTACK(n)							\
    do {								\
	if (n > stackdepth) {						\
	    verror("op %s needed %d stack values, but only %d available!\n", \
		   known_ops[op],(n),stackdepth);			\
	    goto errout;						\
	}								\
    } while (0)
#define PUSH(value)							\
    do {								\
	if (overflowstack) {						\
	    if (stackdepth == overflowstacklen) {			\
		overflowstack =						\
		    realloc(overflowstack,				\
			    (overflowstacklen + 4) * sizeof(Dwarf_Word)); \
		overflowstacklen += 4;					\
	    }								\
	    overflowstack[stackdepth] = value;				\
	}								\
	else if (stackdepth == (sizeof(stack) / sizeof(Dwarf_Word))) {	\
	    overflowstacklen = stackdepth + 4;				\
	    overflowstack = calloc(overflowstacklen,sizeof(Dwarf_Word)); \
	    memcpy(overflowstack,&stack,sizeof(stack));			\
	    overflowstack[stackdepth] = value;				\
	}								\
	else {								\
	    stack[stackdepth] = value;					\
	}								\
	++stackdepth;							\
    } while (0)
#define PEEK() ((overflowstack) ? overflowstack[stackdepth - 1]  \
		                : stack[stackdepth - 1])
#define POP() ((overflowstack) ? overflowstack[--stackdepth]	\
	                       : stack[--stackdepth])
#define PICK(i)	((overflowstack) ? overflowstack[stackdepth - 1 - i]  \
		                 : stack[stackdepth - 1 - i])
#define INPLACE1(OP,value)					\
    do {							\
	NEEDSTACK(1);						\
	if (overflowstack)					\
	    overflowstack[stackdepth - 1] =			\
		overflowstack[stackdepth - 1] OP (value);	\
	else							\
	    stack[stackdepth - 1] =				\
		stack[stackdepth - 1] OP (value);		\
    } while (0)
#define INPLACE1SIGNED(OP,value)				\
    do {							\
	NEEDSTACK(1);						\
	if (overflowstack)					\
	    overflowstack[stackdepth - 1] = (Dwarf_Word)	\
		((int64_t)overflowstack[stackdepth - 1] OP (int64_t)(value)); \
	else							\
	    stack[stackdepth - 1] = (Dwarf_Word)		\
		((int64_t)stack[stackdepth - 1] OP (int64_t)(value));	\
    } while (0)
#define INPLACE1UNARY(OP)					\
    do {							\
	NEEDSTACK(1);						\
	if (overflowstack)					\
	    overflowstack[stackdepth - 1] =			\
		OP overflowstack[stackdepth - 1];		\
	else							\
	    stack[stackdepth - 1] =				\
		OP stack[stackdepth - 1];			\
    } while (0)
#define INPLACE2(OP)						\
    do {							\
	NEEDSTACK(2);						\
	if (overflowstack)					\
	    overflowstack[stackdepth - 2] =			\
		overflowstack[stackdepth - 2] OP overflowstack[stackdepth - 1];	\
	else							\
	    stack[stackdepth - 2] =				\
		stack[stackdepth - 1] OP stack[stackdepth - 2];	\
	--stackdepth;						\
    } while (0)
#define OPCONSTU(size,tt)					\
    NEED(size);							\
    u64 = (uint64_t)*((tt *)data);				\
    data += size;						\
    CONSUME(size);						\
    vdebug(6,LA_DEBUG,LF_DWARFOPS,"%s -> 0x%"PRIu64"\n",	\
	   known_ops[op],u64);					\
    PUSH((Dwarf_Word)u64)
#define OPCONSTS(size,tt)					\
    NEED(size);							\
    s64 = (int64_t)*((tt *)data);				\
    data += size;						\
    CONSUME(size);						\
    vdebug(6,LA_DEBUG,LF_DWARFOPS,"%s -> 0x%"PRIx64"\n",	\
	   known_ops[op],s64);					\
    PUSH((Dwarf_Word)s64)

    /*
     * Process the operation list.
     */
    REG lreg = -1;
    unsigned char *ldata = NULL;
    int llen = 0;
    uint_fast8_t op;

    while (len-- > 0) {
	op = *data++;
	const unsigned char *start = data;

	if (op < (sizeof(known_ops) / sizeof(known_ops[0])) 
	    && known_ops[op] != NULL) 
	    vdebug(9,LA_DEBUG,LF_DWARFOPS,
		   "%s with len = %d\n",known_ops[op],len);
	else
	    vwarnopt(2,LA_DEBUG,LF_DWARF | LF_DWARFOPS,
		     "unknown op 0x%hhx with len = %d\n",op,len);

	Dwarf_Word addr;
	uint64_t u64;
	int64_t s64;
	Dwarf_Word tvalue;
	ADDR taddr;
	REG treg;
	loctype_t rc;
	uint8_t index;
	uint8_t number;
	struct symbol *parent;
	uint16_t skipval;
	struct location tloc;
	int nrc;

#if __WORDSIZE == 64
#define PRIxDwarfWord PRIx64
#else
#define PRIxDwarfWord PRIx32
#endif

	switch (op) {
	/*
	 * Literal encodings.
	 */
	case DW_OP_lit0 ... DW_OP_lit31:
	    PUSH(op - (uint8_t)DW_OP_lit0);
	    break;
	case DW_OP_addr:
	    NEED(addrsize);
	    if (addrsize == 4) 
		addr = read_4ubyte_unaligned(obo,data);
	    else {
		assert(addrsize == 8);
		addr = read_8ubyte_unaligned(obo,data);
	    }
	    vdebug(6,LA_DEBUG,LF_DWARFOPS,
		   "%s -> 0x%"PRIxDwarfWord"\n",known_ops[op],addr);
	    data += addrsize;
	    CONSUME(addrsize);
	    /*
	     * NB: if we have a location_ops struct, we need to try to
	     * relocate this address, because location_resolution
	     * functions must produce real, relocated addresses (if
	     * location_ops and location_ops->relocate was specified).
	     */
	    if (lops && lops->relocate) {
		taddr = addr;
		if (!lops->relocate(lctxt,taddr,&taddr))
		    addr = (Dwarf_Word)taddr;
	    }
	    PUSH(addr);
	    break;
	case DW_OP_const1u:
	    OPCONSTU(1,uint8_t);
	    break;
	case DW_OP_const2u:
	    OPCONSTU(2,uint16_t);
	    break;
	case DW_OP_const4u:
	    OPCONSTU(4,uint32_t);
	    break;
	case DW_OP_const8u:
	    OPCONSTU(8,uint64_t);
	    break;
	case DW_OP_const1s:
	    OPCONSTS(1,int8_t);
	    break;
	case DW_OP_const2s:
	    OPCONSTS(2,int16_t);
	    break;
	case DW_OP_const4s:
	    OPCONSTS(4,int32_t);
	    break;
	case DW_OP_const8s:
	    OPCONSTS(8,int64_t);
	    break;
	case DW_OP_constu:
	    NEED(1);
	    get_uleb128(u64,data); /* XXX check overrun */
	    CONSUME(data - start);
	    vdebug(6,LA_DEBUG,LF_DWARFOPS,
		   "%s -> 0x%"PRIu64"\n",known_ops[op],u64);
	    PUSH((Dwarf_Word)u64);
	    break;
	case DW_OP_consts:
	    NEED(1);
	    get_sleb128(s64,data); /* XXX check overrun */
	    CONSUME(data - start);
	    vdebug(6,LA_DEBUG,LF_DWARFOPS,"%s -> 0x%"PRIx64"\n",
		   known_ops[op],s64);
	    PUSH((Dwarf_Word)s64);
	    break;
	/*
	 * Register-based addressing.
	 */
	case DW_OP_fbreg:
	    NEED(1);
	    get_sleb128(s64,data); /* XXX check overrun */
	    CONSUME(data - start);
	    vdebug(6,LA_DEBUG,LF_DWARFOPS,
		   "%s -> fbreg offset %"PRIi64"\n",known_ops[op],s64);

	    if (!symbol) {
		verror("cannot find frame_base; no symbol supplied!\n");
		errno = EINVAL;
		goto errout;
	    }
	    /*
	     * To determine the value of the frame base pseudo register, we
	     * must find @symbol's containing function.
	     */
	    parent = symbol;
	    while ((parent = symbol_find_parent(parent))) {
		if (SYMBOL_IS_FUNC(parent))
		    break;
	    }
	    if (!parent || !SYMBOL_IS_FUNC(parent)) {
		verror("cannot find frame_base; no parent function contains ");
		ERRORDUMPSYMBOL_NL(symbol);
		errno = EINVAL;
		goto errout;
	    }

	    SYMBOL_RX_FUNC(parent,pf);
	    if (!pf || !pf->fbloc) {
		verror("cannot find frame_base; no frame base in parent"
		       " function of ");
		ERRORDUMPSYMBOL_NL(symbol);
		errno = EINVAL;
		goto errout;
	    }

	    /* Resolve the parent's fbloc; load it; and apply the offset! */
	    memset(&tloc,0,sizeof(tloc));
	    rc = location_resolve(pf->fbloc,lctxt,parent,&tloc);
	    if (rc == LOCTYPE_REG) {
		treg = LOCATION_REG(&tloc);
		nrc = location_ctxt_read_reg(lctxt,treg,&taddr);
		if (nrc) {
		    verror("cannot read reg %"PRIiREG" to get frame_base value\n",
			   treg);
		    goto errout;
		}
	    }
	    else if (rc == LOCTYPE_IMPLICIT_WORD) {
		taddr = LOCATION_WORD(&tloc);
	    }
	    else if (rc == LOCTYPE_ADDR) {
		taddr = LOCATION_ADDR(&tloc);
	    }
	    else {
		verror("cannot get frame base value: %s (%s)\n",
		       strerror(errno),LOCTYPE(rc));
		goto errout;
	    }

	    vdebug(6,LA_DEBUG,LF_DWARFOPS,
		   "frame_base 0x%"PRIxADDR",fboffset %"PRIi64"\n",
		   taddr,s64);

	    PUSH((Dwarf_Word)(taddr + s64));
	    break;
	case DW_OP_breg0 ... DW_OP_breg31:
	    NEED(1);
	    get_sleb128(s64,data); /* XXX check overrun */
	    CONSUME(data - start);
	    vdebug(6,LA_DEBUG,LF_DWARFOPS,
		   "%s -> reg (%hhd) offset %"PRIi64"\n",
		   known_ops[op],(uint8_t)(op - DW_OP_breg0),s64);

	    taddr = 0;
	    treg = (op - DW_OP_breg0);
	    nrc = location_ctxt_read_reg(lctxt,treg,&taddr);
	    if (nrc) {
		verror("error reading reg %"PRIiREG" to compute %s!\n",
		       treg,known_ops[op]);
		goto errout;
	    }

	    vdebug(6,LA_DEBUG,LF_DWARFOPS,
		   "%s -> reg (%hhd) offset %"PRIi64" = 0x%"PRIxDwarfWord"\n",
		   known_ops[op],treg,s64,(Dwarf_Word)(taddr + s64));

	    PUSH((Dwarf_Word)(taddr + s64));
	    break;
	case DW_OP_bregx:
	    NEED(2);
	    get_uleb128(u64,data); /* XXX check overrun */
	    get_sleb128(s64,data); /* XXX check overrun */
	    CONSUME(data - start);
	    vdebug(6,LA_DEBUG,LF_DWARFOPS,
		   "%s -> reg%" PRId8 ", offset %"PRIi64"\n",
		   known_ops[op],(uint8_t)u64,s64);

	    taddr = 0;
	    treg = (REG)u64;
	    nrc = location_ctxt_read_reg(lctxt,treg,&taddr);
	    if (nrc) {
		verror("error reading reg %"PRIiREG" to compute %s!\n",
		       treg,known_ops[op]);
		goto errout;
	    }

	    vdebug(6,LA_DEBUG,LF_DWARFOPS,
		   "%s -> reg (%hhd) offset %"PRIi64" = 0x%"PRIxDwarfWord"\n",
		   known_ops[op],treg,s64,(Dwarf_Word)(taddr + s64));

	    PUSH((Dwarf_Word)(taddr + s64));
	    break;
	/*
	 * Stack operations.
	 */
	case DW_OP_dup:
	    NEEDSTACK(1);
	    tvalue = PEEK();
	    PUSH(tvalue);
	    break;
	case DW_OP_drop:
	    NEEDSTACK(1);
	    POP();
	    break;
	case DW_OP_pick:
	    NEED(1);
	    index = *((uint8_t *)data);
	    CONSUME(1);
	    NEEDSTACK(index + 1);
	    tvalue = PICK(index);
	    PUSH(tvalue);
	    break;
	case DW_OP_over:
	    NEEDSTACK(2);
	    tvalue = PICK(1);
	    PUSH(tvalue);
	    break;
	case DW_OP_swap:
	    NEEDSTACK(2);
	    if (overflowstack) {
		tvalue = overflowstack[stackdepth - 1];
		overflowstack[stackdepth - 1] = overflowstack[stackdepth - 2];
		overflowstack[stackdepth - 2] = tvalue;
	    }
	    else {
		tvalue = stack[stackdepth - 1];
		stack[stackdepth - 1] = stack[stackdepth - 2];
		stack[stackdepth - 2] = tvalue;
	    }
	    break;
	case DW_OP_rot:
	    NEEDSTACK(3);
	    if (overflowstack) {
		tvalue = overflowstack[stackdepth - 1];
		overflowstack[stackdepth - 1] = overflowstack[stackdepth - 2];
		overflowstack[stackdepth - 2] = overflowstack[stackdepth - 3];
		overflowstack[stackdepth - 3] = tvalue;
	    }
	    else {
		tvalue = stack[stackdepth - 1];
		stack[stackdepth - 1] = stack[stackdepth - 2];
		stack[stackdepth - 2] = stack[stackdepth - 3];
		stack[stackdepth - 3] = tvalue;
	    }
	    break;
	case DW_OP_deref:
	    NEEDSTACK(1);
	    taddr = POP();
	    if (!lops || !lops->readword) {
		verror("cannot read ptr to compute %s op; no location op!\n",
		       known_ops[op]);
		errno = EINVAL;
		goto errout;
	    }
	    else if (lops->readword(lctxt,taddr,&taddr)) {
		verror("error reading addr %"PRIxADDR" to compute %s!\n",
		       taddr,known_ops[op]);
		goto errout;
	    }
	    PUSH((Dwarf_Word)taddr);
	    break;
	case DW_OP_deref_size:
	    NEED(1);
	    number = *(uint8_t *)data;
	    CONSUME(1);
	    NEEDSTACK(1);
	    taddr = POP();
	    if (!lops || !lops->readword) {
		verror("cannot read ptr to compute %s op; no location op!\n",
		       known_ops[op]);
		errno = EINVAL;
		goto errout;
	    }
	    else if (lops->readword(lctxt,taddr,&taddr)) {
		verror("error reading addr %"PRIxADDR" to compute %s!\n",
		       taddr,known_ops[op]);
		goto errout;
	    }
	    addr = 0;
	    /* XXX: this is little-endian only, obviously. */
	    memcpy(&addr,&taddr,number);
	    PUSH(addr);
	    break;
	case DW_OP_xderef:
	case DW_OP_xderef_size:
	    verror("%s op unsupported (we don't know multiple addrspaces)!\n",
		   known_ops[op]);
	    errno = ENOTSUP;
	    goto errout;
	case DW_OP_push_object_address:
	case DW_OP_form_tls_address:
	    verror("%s op unsupported!\n",known_ops[op]);
	    errno = ENOTSUP;
	    goto errout;
	case DW_OP_call_frame_cfa:
	    verror("%s op unsupported (no CFA support yet)!\n",known_ops[op]);
	    errno = ENOTSUP;
	    goto errout;
	/*
	 * Arithmetic and logical operations.
	 */
	case DW_OP_abs:
	    NEEDSTACK(1);
	    tvalue = POP();
	    s64 = (int64_t)tvalue;
	    if (s64 < 0)
		tvalue = (uint64_t)-s64;
	    PUSH((Dwarf_Word)tvalue);
	    break;
	case DW_OP_and:
	    INPLACE2(&);
	    break;
	case DW_OP_div:
	    INPLACE2(/);
	    break;
	case DW_OP_minus:
	    INPLACE2(-);
	    break;
	case DW_OP_mod:
	    INPLACE2(%);
	    break;
	case DW_OP_mul:
	    INPLACE2(*);
	    break;
	case DW_OP_neg:
	    NEEDSTACK(1);
	    s64 = (int64_t)POP();
	    u64 = (uint64_t)-s64;
	    PUSH((Dwarf_Word)u64);
	    break;
	case DW_OP_or:
	    INPLACE2(|);
	    break;
	case DW_OP_plus:
	    INPLACE2(+);
	    break;
	case DW_OP_plus_uconst:
	    NEED(1);
	    get_uleb128(u64,data); /* XXX check overrun */
	    CONSUME(data - start);
	    vdebug(6,LA_DEBUG,LF_DWARFOPS,
		   "%s -> 0x%"PRIu64"\n",known_ops[op],u64);
	    INPLACE1(+,(Dwarf_Word)u64);
	    break;
	case DW_OP_shl:
	    NEEDSTACK(2);
	    tvalue = POP();
	    INPLACE1(<<,tvalue);
	    break;
	case DW_OP_shr:
	    NEEDSTACK(2);
	    tvalue = POP();
	    INPLACE1(>>,tvalue);
	    break;
	case DW_OP_shra:
	    NEEDSTACK(2);
	    tvalue = POP();
	    s64 = (int64_t)POP();
	    /* XXX: is this right? */
	    s64 = s64 >> tvalue;
	    PUSH((Dwarf_Word)s64);
	    break;
	case DW_OP_xor:
	    INPLACE2(^);
	    break;
	/*
	 * Control flow operations.
	 */
	case DW_OP_le:
	    NEEDSTACK(2);
	    tvalue = POP();
	    INPLACE1SIGNED(<=,tvalue);
	    break;
	case DW_OP_ge:
	    NEEDSTACK(2);
	    tvalue = POP();
	    INPLACE1SIGNED(>=,tvalue);
	    break;
	case DW_OP_eq:
	    NEEDSTACK(2);
	    tvalue = POP();
	    INPLACE1SIGNED(==,tvalue);
	    break;
	case DW_OP_lt:
	    NEEDSTACK(2);
	    tvalue = POP();
	    INPLACE1SIGNED(<,tvalue);
	    break;
	case DW_OP_gt:
	    NEEDSTACK(2);
	    tvalue = POP();
	    INPLACE1SIGNED(>,tvalue);
	    break;
	case DW_OP_ne:
	    NEEDSTACK(2);
	    tvalue = POP();
	    INPLACE1SIGNED(!=,tvalue);
	    break;
	case DW_OP_skip:
	    NEED(2);
	    skipval = *(int16_t *)data;
	    /*
	     * NB: don't CONSUME(); we go back/forward from the op byte.
	     */
	    len += 1 - skipval;
	    data = (data - 1) + skipval;
	    if (data < origdata || data >= (origdata + origlen)) {
		verror("bad %s skip distance %hd!\n",known_ops[op],skipval);
		errno = ERANGE;
		goto errout;
	    }
	    break;
	case DW_OP_bra:
	    NEED(2);
	    skipval = *(int16_t *)data;
	    NEEDSTACK(1);
	    tvalue = POP();
	    if (tvalue != 0) {
		/* Do the branch. */
		len += 1 - skipval;
		data = (data - 1) + skipval;
		if (data < origdata || data >= (origdata + origlen)) {
		    verror("bad %s skip distance %hd!\n",known_ops[op],skipval);
		    errno = ERANGE;
		    goto errout;
		}
	    }
	    else {
		/* Don't branch; just CONSUME() and continue. */
		CONSUME(2);
	    }
	    break;
	case DW_OP_call2:
	case DW_OP_call4:
	case DW_OP_call_ref:
	    verror("known op %s not supported (calls not supported yet)!\n",
		   known_ops[op]);
	    errno = ENOTSUP;
	    goto errout;
	/*
	 * Special operations.
	 */
	case DW_OP_nop:
	    break;
	/*
	 * Location operations that can be used to name a register as
	 * being the location of the location expression.
	 */
	case DW_OP_reg0 ... DW_OP_reg31:
	    lreg = op - (uint8_t)DW_OP_reg0;
	    vdebug(6,LA_DEBUG,LF_DWARFOPS,
		   "%s -> 0x%"PRIu8"\n",known_ops[op],lreg);
	    break;
	case DW_OP_regx:
	    NEED(1);
	    get_uleb128(u64,data); /* XXX check overrun */
	    CONSUME(data - start);
	    lreg = (REG)u64;
	    vdebug(6,LA_DEBUG,LF_DWARFOPS,
		   "%s -> 0x%"PRIu8"\n",known_ops[op],lreg);
	    break;
	/*
	 * Implicit location descriptions.
	 */
#if _INT_ELFUTILS_VERSION > 141
	case DW_OP_implicit_value:
	    NEED(1);
	    get_uleb128(u64,data); /* XXX check overrun */
	    CONSUME(data - start);
	    ldata = (unsigned char *)data;
	    llen = (int)u64;
	    CONSUME(u64);
	    break;
	case DW_OP_stack_value:
	    NEEDSTACK(1);
	    break;
#endif
	case DW_OP_piece:
	case DW_OP_bit_piece:
	    verror("known op %s not supported (composite location descriptions"
		   " not supported in location expressions yet)!\n",
		   known_ops[op]);
	    errno = ENOTSUP;
	    goto errout;
	/*
	 * GNU operations.
	 */
#if _INT_ELFUTILS_VERSION > 138
	case DW_OP_GNU_push_tls_address:
	case DW_OP_GNU_uninit:
	case DW_OP_GNU_encoded_addr:
#if _INT_ELFUTILS_VERSION > 148
	case DW_OP_GNU_implicit_pointer:
	    verror("known GNU op %s not supported!\n",known_ops[op]);
	    errno = ENOTSUP;
	    goto errout;
#endif
#endif
	/* No Operand.  */
	default:
	    break;
	}

	continue;
    }

    /*
     * Return.
     */
 out:
    /*
     * Check our last op to see how we should return!
     */
    switch (op) {
    /*
     * If we had named a register, return a register location.
     */
    case DW_OP_reg0 ... DW_OP_reg31:
    case DW_OP_regx:
	if (o_loc)
	    location_set_reg(o_loc,lreg);
	if (overflowstack)
	    free(overflowstack);
	return LOCTYPE_REG;
    /*
     * If we had found an implicit value, handle that.
     */
#if _INT_ELFUTILS_VERSION > 141
    case DW_OP_implicit_value:
	if (o_loc)
	    location_set_implicit_data(o_loc,(char *)ldata,llen,0);
	return LOCTYPE_IMPLICIT_DATA;
    case DW_OP_stack_value:
	if (stackdepth < 1) {
	    verror("stackdepth at return was %d; no implicit value available!\n",
		   stackdepth);
	    errno = EADDRNOTAVAIL;
	    if (overflowstack)
		free(overflowstack);
	    return -LOCTYPE_IMPLICIT_WORD;
	}
	if (o_loc)
	    location_set_implicit_word(o_loc,PEEK());
	return LOCTYPE_IMPLICIT_WORD;
#endif
    default:
	break;
    }

    /*
     * If we reach here, we must be returning the top stack value as an
     * address.
     */
    if (stackdepth < 1) {
	verror("stackdepth at return was %d; no value available!\n",
	       stackdepth);
	errno = EADDRNOTAVAIL;
	if (overflowstack)
	    free(overflowstack);
	return -LOCTYPE_ADDR;
    }
    if (o_loc)
	location_set_addr(o_loc,(ADDR)PEEK());
    if (overflowstack)
	free(overflowstack);
    return LOCTYPE_ADDR;

    /*
     * The default error returned is -LOCTYPE_ADDR; unless we *know*
     * that the resulting value of our expression will be LOCTYPE_REG or
     * LOCTYPE_IMPLICIT_*, we can only assume the output *will* have
     * been a LOCTYPE_ADDR.
     */
 errout:
    if (overflowstack)
	free(overflowstack);
    return -LOCTYPE_ADDR;
}

/*
 * This originally came from readelf.c, but I rewrote much of it.  Some
 * operations can be evaluated statically to produce a fixed location
 * that never changes, except for a simple offset.  Others actually need
 * runtime information.  So, we evaluate everything that is simple to
 * do, and punt the rest for runtime evaluation against actual machine
 * data.
 */
struct location *dwarf_get_static_ops(struct symbol_root_dwarf *srd,
				      const unsigned char *data,Dwarf_Word len,
				      unsigned int attr) {
    struct location *retval = NULL;
    unsigned int addrsize = srd->addrsize;

    /* const unsigned int ref_size = vers < 3 ? addrsize : offset_size; */

    /* XXX: we can't get other_byte_order from dbg since we don't have
     * the struct def for it... so we assume it's not a diff byte order
     * than the phys host for now.
     */
    int obo = 0;

    /* save the originals for later for runtime computation if we need */
    const unsigned char *origdata = data;
    Dwarf_Word origlen = len;

    if (len == 0) {
	vwarn("empty dwarf block num!\n");
	goto errout;
    }

    retval = location_create();

#define SNEED(n)	if (len < (Dwarf_Word) (n)) goto errout
#define SCONSUME(n)	SNEED(n); else len -= (n)

/* If this is the only thing in this op list, be done now. */
#define ONLYOP(location,setter,...)					\
    if (start == (origdata + 1) && len == 0) {				\
	location_set_ ## setter((location), ## __VA_ARGS__);		\
	goto out;							\
    }									\
    else {								\
	vdebug(6,LA_DEBUG,LF_DWARFSOPS,					\
	       "unsupported %s op with other ops!\n",known_ops[op]);	\
    }
#define SOPCONSTU(size,tt)						\
    SNEED(size);								\
    u64 = (uint64_t)*((tt *)data);					\
    data += size;							\
    SCONSUME(size);							\
    vdebug(6,LA_DEBUG,LF_DWARFSOPS,"%s -> 0x%" PRIuMAX "\n",known_ops[op],u64);	\
    if (attr == DW_AT_data_member_location) {				\
	ONLYOP(retval,member_offset,(int32_t)u64);			\
    }									\
    else {								\
	vdebug(6,LA_DEBUG,LF_DWARFSOPS,					\
	       "assuming constXu is for loctype_addr!\n");		\
	ONLYOP(retval,addr,u64);					\
    }
#define SOPCONSTS(size,tt)						\
    SNEED(size);								\
    s64 = (int64_t)*((tt *)data);					\
    data += size;							\
    SCONSUME(size);							\
    vdebug(6,LA_DEBUG,LF_DWARFSOPS,"%s -> 0x%" PRIxMAX "\n",known_ops[op],s64); \
    if (attr == DW_AT_data_member_location) {				\
	ONLYOP(retval,member_offset,(int32_t)s64);			\
    }									\
    else {								\
	vdebug(6,LA_DEBUG,LF_DWARFSOPS,					\
	       "assuming constXs is for loctype_addr!\n");		\
	ONLYOP(retval,addr,(uint64_t)s64);				\
    }

    /*
     * Process the ops a little bit.
     */
    while (len-- > 0) {
	uint_fast8_t op = *data++;
	const unsigned char *start = data;

	if (op < (sizeof(known_ops) / sizeof(known_ops[0])) 
	    && known_ops[op] != NULL) 
	    vdebug(6,LA_DEBUG,LF_DWARFSOPS,
		   "%s with len = %d\n",known_ops[op],len);
	else
	    vwarnopt(6,LA_DEBUG,LF_DWARF | LF_DWARFSOPS,
		     "unknown op 0x%hhx with len = %d\n",op,len);

	Dwarf_Word addr;
	uint8_t reg;
	uint64_t u64;
	int64_t s64;

	switch (op) {
	case DW_OP_addr:
	    SNEED(addrsize);
	    if (addrsize == 4)
		addr = read_4ubyte_unaligned(obo,data);
	    else {
		assert(addrsize == 8);
		addr = read_8ubyte_unaligned(obo,data);
	    }
	    data += addrsize;
	    SCONSUME(addrsize);
	    vdebug(6,LA_DEBUG,LF_DWARFSOPS,
		   "%s -> 0x%"PRIxDwarfWord"\n",known_ops[op],addr);
	    if (start == (origdata + 1) && len == 0) {
		retval->loctype = LOCTYPE_ADDR;
		retval->l.addr = addr;
		goto out;
	    }
	    else {
		vdebug(6,LA_DEBUG,LF_DWARFSOPS,
		       "unsupported %s op with other ops!\n",known_ops[op]);
	    }
	    //ONLYOP(retval,addr,((uint64_t)addr));
	    break;
	case DW_OP_reg0...DW_OP_reg31:
	    reg = op - (uint8_t)DW_OP_reg0;
	    vdebug(6,LA_DEBUG,LF_DWARFSOPS,
		   "%s -> 0x%"PRIu8"\n",known_ops[op],reg);
	    ONLYOP(retval,reg,reg);
	    break;
	//case DW_OP_piece:
	case DW_OP_regx:
	    SNEED(1);
	    get_uleb128(u64,data); /* XXX check overrun */
	    SCONSUME(data - start);
	    vdebug(6,LA_DEBUG,LF_DWARFSOPS,
		   "%s -> 0x%"PRIu64"\n",known_ops[op],u64);
	    ONLYOP(retval,reg,(uint8_t)u64);
	    break;
	case DW_OP_plus_uconst:
	case DW_OP_constu:
	    SNEED(1);
	    get_uleb128(u64,data); /* XXX check overrun */
	    SCONSUME(data - start);
	    vdebug(6,LA_DEBUG,LF_DWARFSOPS,
		   "%s -> 0x%"PRIu64"\n",known_ops[op],u64);
	    if (attr == DW_AT_data_member_location) {
		ONLYOP(retval,member_offset,(int32_t)u64);
	    }
	    else {
		ONLYOP(retval,addr,(uint64_t)u64);
		vdebug(6,LA_DEBUG,LF_DWARFSOPS,
		       "assuming known op %s is for loctype_addr!\n",
		       known_ops[op]);
	    }
	    break;
	case DW_OP_consts:
	    SNEED(1);
	    get_sleb128(s64,data); /* XXX check overrun */
	    SCONSUME(data - start);
	    vdebug(6,LA_DEBUG,LF_DWARFSOPS,
		   "%s -> %"PRIi64"\n",known_ops[op],s64);
	    if (attr == DW_AT_data_member_location) {
		ONLYOP(retval,member_offset,(int32_t)s64);
	    }
	    else {
		ONLYOP(retval,addr,(uint64_t)s64);
		vdebug(6,LA_DEBUG,LF_DWARFSOPS,
		       "assuming known op %s is for loctype_addr!\n",
		       known_ops[op]);
	    }
	    break;
	case DW_OP_const1u:
	    SOPCONSTU(1,uint8_t);
	    break;
	case DW_OP_const2u:
	    SOPCONSTU(2,uint16_t);
	    break;
	case DW_OP_const4u:
	    SOPCONSTU(4,uint32_t);
	    break;
	case DW_OP_const8u:
	    SOPCONSTU(8,uint64_t);
	    break;
	case DW_OP_const1s:
	    SOPCONSTS(1,int8_t);
	    break;
	case DW_OP_const2s:
	    SOPCONSTS(2,int16_t);
	    break;
	case DW_OP_const4s:
	    SOPCONSTS(4,int32_t);
	    break;
	case DW_OP_const8s:
	    SOPCONSTS(8,int64_t);
	    break;
	case DW_OP_fbreg:
	  SNEED(1);
	  get_sleb128(s64,data); /* XXX check overrun */
	  SCONSUME(data - start);
	  vdebug(6,LA_DEBUG,LF_DWARFSOPS,
		 "%s -> fbreg offset %"PRIi64"\n",known_ops[op],s64);
	  ONLYOP(retval,fbreg_offset,s64);
	  break;
	case DW_OP_breg0 ... DW_OP_breg31:
	    SNEED(1);
	    get_sleb128(s64,data); /* XXX check overrun */
	    SCONSUME(data - start);
	    vdebug(6,LA_DEBUG,LF_DWARFSOPS,
		   "%s -> reg (%"PRIu8") offset %"PRIi64"\n",known_ops[op],
		   (uint8_t)(op - DW_OP_breg0),s64);
	    ONLYOP(retval,reg_offset,(uint8_t)(op - DW_OP_breg0),s64);
	    break;
	case DW_OP_bregx:
	    SNEED(2);
	    get_uleb128(u64,data); /* XXX check overrun */
	    get_sleb128(s64,data); /* XXX check overrun */
	    SCONSUME(data - start);
	    vdebug(6,LA_DEBUG,LF_DWARFSOPS,
		   "%s -> reg%"PRIu8", offset %"PRIi64"\n",known_ops[op],
		   (uint8_t)u64,s64);
	    ONLYOP(retval,reg_offset,(uint8_t)u64,s64);
	    break;
	default:
	    /* No operand. */
	    break;
	}

	continue;
    }

    vdebug(6,LA_DEBUG,LF_DWARFSOPS,"had to save dwarf ops for runtime!\n");
    location_set_runtime(retval,(char *)origdata,origlen,0);

 out:
    return retval;

 errout:
    if (retval)
	location_free(retval);
    return NULL;
}
