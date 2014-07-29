/*
 * Copyright (c) 2011-2014 The University of Utah
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

#include <dwarf.h>
#include <gelf.h>
#include <elfutils/libebl.h>
#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>

#include "common.h"
#include "clfit.h"
#include "alist.h"
#include "binfile.h"
#include "dwdebug.h"
#include "dwdebug_priv.h"

#include "memory-access.h"

static const unsigned char *__read_encoded(unsigned int encoding,
					   unsigned int wordsize,
					   const unsigned char *readp,
					   const unsigned char *const endp,
					   uint64_t *res,Dwarf *dbg);
int dwarf_cfa_read_saved_reg(struct debugfile *debugfile,
			     struct location_ctxt *lctxt,
			     REG reg,REGVAL *o_regval);
/*
 * DWARF register rules.
 */
typedef enum {
    RRT_UNDEF = 0,
    RRT_SAME  = 1,
    RRT_OFFSET = 2,
    RRT_VAL_OFFSET = 3,
    RRT_REG = 5,
    RRT_EXPR = 6,
    RRT_VAL_EXPR = 7,
    RRT_ARCH = 8,
} dwarf_cfa_regrule_t;

struct dwarf_cfa_regrule {
    dwarf_cfa_regrule_t rrt;
    union {
	uint64_t reg;
	struct {
	    const unsigned char *block;
	    unsigned int len;
	} block;
	struct {
	    uint64_t reg;
	    int64_t offset;
	} offset;
    };
};

/*
 * When we parse the CFA program, we might not have any location_ops to
 * tell us which platform register is the stack pointer register -- so
 * we need a special macro to represent the CFA pseudo-register (which
 * is the stack pointer register value in the previous frame).  So,
 * whenever we load this register in a frame, we must also cache it in
 * the register table as the stack pointer's value in the previous
 * frame.
 */
#define DWARF_CFA_REG INT8_MAX

/*
 * Our cached CIE data is small.  We don't need length, CIE_id,
 * address_size (assumed to be the debugfile's wordsize); we do need
 * segment size; augmentation (split into decoded fields);
 * code_alignment_factor; data_alignment_factor; return_address_register.
 */
struct dwarf_cfa_cie {
    ptrdiff_t offset;
    uint8_t version;
    uint8_t segment_size;
    unsigned int code_alignment_factor;
    int data_alignment_factor;
    unsigned int return_address_register;
    unsigned int fde_encoding;
    unsigned int lsda_encoding;
    uint64_t personality;
    char *aug;
    unsigned int auglen;
    /* A table of int to struct dwarf_cfa_regrule *. */
    GHashTable *default_regrules;
};

struct dwarf_cfa_fde {
    ptrdiff_t offset;
    struct dwarf_cfa_cie *cie;
    ADDR initial_location;
    ADDR address_range;
    /* ADDR vma_base; */
    unsigned char *instructions;
    unsigned int len;

    /* A table of int to clmatchone_t. */
    GHashTable *regrules;
};

static void dwarf_cfa_fde_free(struct dwarf_cfa_fde *fde) {
    GHashTableIter iter;
    gpointer vp,kp;
    clmatchone_t *cl;
    struct dwarf_cfa_regrule *rr;
    Word_t o_index = ADDRMAX;

    if (fde->regrules) {
	g_hash_table_iter_init(&iter,fde->regrules);
	while (g_hash_table_iter_next(&iter,&kp,&vp)) {
	    cl = (clmatchone_t *)vp;
	    while ((rr = (struct dwarf_cfa_regrule *) \
		    clmatchone_find(cl,o_index,&o_index))) {
		/* Look for a previous index so not to double free. */
		o_index -= 1;
		free(rr);
	    }
	    clmatchone_free(*cl);
	    g_hash_table_iter_replace(&iter,NULL);
	}
	g_hash_table_destroy(fde->regrules);
    }

    free(fde);
}

static void dwarf_cfa_cie_free(struct dwarf_cfa_cie *cie) {
    GHashTableIter iter;
    gpointer vp,kp;
    struct dwarf_cfa_regrule *rr;

    if (cie->default_regrules) {
	g_hash_table_iter_init(&iter,cie->default_regrules);
	while (g_hash_table_iter_next(&iter,&kp,&vp)) {
	    rr = (struct dwarf_cfa_regrule *)vp;
	    free(rr);
	    g_hash_table_iter_replace(&iter,NULL);
	}
	g_hash_table_destroy(cie->default_regrules);
    }

    free(cie);
}

int dwarf_cfa_program_interpret(struct debugfile *debugfile,
				struct dwarf_cfa_cie *cie,
				struct dwarf_cfa_fde *fde,
				const unsigned char *buf,unsigned int len,
				GHashTable *regrules) {
    /* XXX: we can't get other_byte_order from dbg since we don't have
     * the struct def for it... so we assume it's not a diff byte order
     * than the phys host for now.
     */
    int obo = 0;
    const unsigned char *readp = buf;
    const unsigned char *const endp = readp + len;
    ADDR pc;
    /* Dwarf_Word vma_base; */
    uint64_t op1;
    int64_t sop1;
    uint64_t op2;
    int64_t sop2;
    uint_fast8_t opcode;
    struct dwarf_cfa_regrule *rr;
    struct dwarf_cfa_regrule *last_cfa_rr = NULL;
    struct dwarf_cfa_regrule *def_rr;
    int wordsize;
    struct dwarf_debugfile_info *ddi;
    GSList *stack = NULL;
    GHashTable *stackhash;
    GHashTableIter iter;
    gpointer kp,vp;
    struct dwarf_cfa_regrule *tmp_rr;
    clmatchone_t *cl;

    ddi = (struct dwarf_debugfile_info *)debugfile->priv;

    pc = 0;
    /*
    if (fde && fde->vma_base)
	pc = fde->vma_base;
    */
    if (fde)
	pc = fde->initial_location;

    last_cfa_rr = (struct dwarf_cfa_regrule *) \
	g_hash_table_lookup(cie->default_regrules,
			    (gpointer)(uintptr_t)DWARF_CFA_REG);

    inline void __insert_regrule(ADDR pc,uint64_t reg,
				 struct dwarf_cfa_regrule *rr) {
	clmatchone_t *_cl;
	struct dwarf_cfa_regrule *_tmp_rr;

	if (!regrules)
	    return;

	/*
	 * NB: if we are doing an FDE, we need to create a clmatchone
	 * structure to index based on pc.  But, if we're doing CIE,
	 * then each reg has only a single default regrule, so we don't
	 * create clmatchones for those!
	 */
	if (fde) {
	    _cl = (clmatchone_t *)					\
		g_hash_table_lookup(regrules,(gpointer)(uintptr_t)reg);
	    if (!_cl) {
		_cl = calloc(1,sizeof(*_cl));
		*_cl = clmatchone_create();
	    }
	    clmatchone_add(_cl,pc,rr);
	    g_hash_table_insert(regrules,(gpointer)(uintptr_t)reg,_cl);
	}
	else {
	    _tmp_rr = (struct dwarf_cfa_regrule *)			\
		g_hash_table_lookup(regrules,(gpointer)(uintptr_t)reg);
	    if (_tmp_rr) {
		vwarn("r%"PRIu64" already has a default value in CIE 0x%lx;"
		      " will overwrite!\n",reg,(unsigned long)cie->offset);
		free(_tmp_rr);
	    }
	    g_hash_table_insert(regrules,(gpointer)(uintptr_t)reg,rr);
	}
    }

    while (readp < endp) {
	opcode = *readp++;

	switch (opcode) {
	/*
	 * Padding Instruction.
	 */
	case DW_CFA_nop:
	    break;

	/*
	 * Row Creation Instructions.
	 */
	case DW_CFA_set_loc:
	    switch (cie->fde_encoding & 7) {
	    case 2:  wordsize = 2; break;
	    case 3:  wordsize = 4; break;
	    case 4:  wordsize = 8; break;
	    default: wordsize = debugfile->binfile->wordsize;
	    }

	    const unsigned char *base = readp;
	    if (cie->fde_encoding & DW_EH_PE_signed)
		op1 = read_sbyte_unaligned_inc(wordsize,obo,readp);
	    else
		op1 = read_ubyte_unaligned_inc(wordsize,obo,readp);

	    if ((cie->fde_encoding & 0x70) == DW_EH_PE_pcrel)
		op1 += ddi->frame_sec_addr 
		    + (base - (unsigned char *)debugfile->frametab);
	    pc = op1;
	    // XXX overflow check
	    //get_leb128(op1,readp);
	    /*
	    if (fde)
		vma_base = fde->vma_base;
	    else
		vma_base = 0;
	    pc = (op1 + vma_base) * cie->code_alignment_factor;

	    if ((cie->fde_encoding & 0x70) == DW_EH_PE_pcrel)
		fde->initial_location += ddi->frame_sec_addr 
		    + (base - (unsigned char *)debugfile->frametab);
	    */
	    vdebug(8,LA_DEBUG,LF_DCFA,"DW_CFA_set_loc 0x%"PRIxADDR"\n",pc);
	    break;

	case DW_CFA_advance_loc ... (DW_CFA_advance_loc + 0x3f):
	    op1 = opcode & 0x3f;
	    pc += op1 * cie->code_alignment_factor;
	    vdebug(8,LA_DEBUG,LF_DCFA,
		   "DW_CFA_advance_loc %u to 0x%"PRIxADDR"\n",op1,pc);
	    break;
	case DW_CFA_advance_loc1:
	    pc += *readp * cie->code_alignment_factor;
	    vdebug(8,LA_DEBUG,LF_DCFA,
		   "DW_CFA_advance_loc1 %u to 0x%"PRIxADDR"\n",*readp,pc);
	    ++readp;
	    break;
	case DW_CFA_advance_loc2:
	    op1 = read_2ubyte_unaligned_inc(obo,readp);
	    pc += op1 * cie->code_alignment_factor;
	    vdebug(8,LA_DEBUG,LF_DCFA,
		   "DW_CFA_advance_loc2 %"PRIu64" to 0x%"PRIxADDR"\n",op1,pc);
	    break;
	case DW_CFA_advance_loc4:
	    op1 = read_4ubyte_unaligned_inc(obo,readp);
	    pc += op1 * cie->code_alignment_factor;
	    vdebug(8,LA_DEBUG,LF_DCFA,
		   "DW_CFA_advance_loc4 %"PRIu64" to 0x%"PRIxADDR"\n",op1,pc);
	    break;
	case DW_CFA_MIPS_advance_loc8:
	    op1 = read_8ubyte_unaligned_inc(obo,readp);
	    pc += op1 * cie->code_alignment_factor;
	    vdebug(8,LA_DEBUG,LF_DCFA,
		   "DW_CFA_MIPS_advance_loc8 %"PRIu64" to 0x%"PRIxADDR"\n",
		   op1,pc);
	    break;

	/*
	 * CFA Definition Instructions.
	 */
	case DW_CFA_def_cfa:
	    // XXX overflow check
	    get_uleb128(op1,readp);
	    get_uleb128(op2,readp);
	    vdebug(8,LA_DEBUG,LF_DCFA,
		   "DW_CFA_def_cfa r%"PRIu64" at offset %"PRIu64"\n",op1,op2);

	    rr = calloc(1,sizeof(*rr));
	    rr->rrt = RRT_VAL_OFFSET;
	    rr->offset.reg = op1;
	    rr->offset.offset = (int64_t)op2;

	    __insert_regrule(pc,DWARF_CFA_REG,rr);
	    last_cfa_rr = rr;

	    break;
	case DW_CFA_def_cfa_sf:
	    // XXX overflow check
	    get_uleb128(op1,readp);
	    get_sleb128(sop2,readp);
	    vdebug(8,LA_DEBUG,LF_DCFA,
		   "DW_CFA_def_cfa_sf r%"PRIu64" at offset %"PRId64"\n",
		    op1,sop2 * cie->data_alignment_factor);

	    rr = calloc(1,sizeof(*rr));
	    rr->rrt = RRT_VAL_OFFSET;
	    rr->offset.reg = op1;
	    rr->offset.offset = sop2;

	    __insert_regrule(pc,DWARF_CFA_REG,rr);
	    last_cfa_rr = rr;

	    break;
	case DW_CFA_def_cfa_register:
	    // XXX overflow check
	    get_uleb128(op1,readp);

	    rr = calloc(1,sizeof(*rr));
	    if (last_cfa_rr && last_cfa_rr->rrt == RRT_VAL_OFFSET) {
		rr->rrt = RRT_VAL_OFFSET;
		rr->offset.reg = op1;
		rr->offset.offset = last_cfa_rr->offset.offset;

		vdebug(8,LA_DEBUG,LF_DCFA,
		       "DW_CFA_def_cfa_register r%"PRIu64
		       " (current offset %"PRId64")\n",
		       op1,rr->offset.offset);
	    }
	    else {
		rr->rrt = RRT_VAL_OFFSET;
		rr->offset.reg = op1;
		rr->offset.offset = 0;

		vwarn("DW_CFA_def_cfa_register r%"PRIu64" but no current CFA"
		      " regrule to get last CFA offset; assuming offset 0!\n",
		      op1);
	    }

	    __insert_regrule(pc,DWARF_CFA_REG,rr);
	    last_cfa_rr = rr;

	    break;
	case DW_CFA_def_cfa_offset:
	    // XXX overflow check
	    get_uleb128(op1,readp);

	    rr = calloc(1,sizeof(*rr));
	    if (last_cfa_rr && last_cfa_rr->rrt == RRT_VAL_OFFSET) {
		rr->rrt = RRT_VAL_OFFSET;
		rr->offset.reg = last_cfa_rr->offset.reg;
		rr->offset.offset = (int64_t)op1;

		vdebug(8,LA_DEBUG,LF_DCFA,
		       "DW_CFA_def_cfa_offset offset %"PRId64
		       " (current r%"PRIu64")\n",
		       (int64_t)op1,rr->offset.reg);
	    }
	    else {
		rr->rrt = RRT_VAL_OFFSET;
		rr->offset.reg = 0;
		rr->offset.offset = (int64_t)op1;

		vwarn("DW_CFA_def_cfa_offset offset %"PRIu64" but no current CFA"
		      " regrule to get last CFA offset; assuming reg 0!\n",
		      op1);
	    }

	    __insert_regrule(pc,DWARF_CFA_REG,rr);
	    last_cfa_rr = rr;

	    break;
	case DW_CFA_def_cfa_offset_sf:
	    // XXX overflow check
	    get_sleb128(sop1,readp);
	    sop1 *= cie->data_alignment_factor;

	    if (last_cfa_rr && last_cfa_rr->rrt == RRT_VAL_OFFSET) {
		rr = calloc(1,sizeof(*rr));
		rr->rrt = RRT_VAL_OFFSET;
		rr->offset.reg = last_cfa_rr->offset.reg;
		rr->offset.offset = sop1;

		vdebug(8,LA_DEBUG,LF_DCFA,
		       "DW_CFA_def_cfa_offset_sf offset %"PRId64
		       " (current r%"PRIu64")\n",
		       sop1,rr->offset.reg);
	    }
	    else {
		vwarn("DW_CFA_def_cfa_offset_sf offset %"PRId64" but no current CFA"
		      " regrule to get last CFA offset; skipping!!\n",
		      sop1);
		break;
	    }

	    __insert_regrule(pc,DWARF_CFA_REG,rr);
	    last_cfa_rr = rr;

	    break;
	case DW_CFA_def_cfa_expression:
	    // XXX overflow check
	    get_uleb128(op1,readp); /* Length of DW_FORM_block.  */
	    vdebug(8,LA_DEBUG,LF_DCFA,
		   "DW_CFA_def_cfa_expression len %"PRIu64"\n",op1);

	    rr = calloc(1,sizeof(*rr));
	    rr->rrt = RRT_VAL_EXPR;
	    rr->block.block = readp;
	    rr->block.len = op1;

	    __insert_regrule(pc,DWARF_CFA_REG,rr);
	    last_cfa_rr = rr;

	    readp += op1;
	    break;

	/*
	 * Register Rule Instructions.
	 */
	case DW_CFA_undefined:
	    // XXX overflow check
	    get_uleb128(op1,readp);
	    vdebug(8,LA_DEBUG,LF_DCFA,"DW_CFA_undefined r%"PRIu64"\n",op1);

	    rr = calloc(1,sizeof(*rr));
	    rr->rrt = RRT_UNDEF;

	    __insert_regrule(pc,op1,rr);

	    break;
	case DW_CFA_same_value:
	    // XXX overflow check
	    get_uleb128(op1,readp);
	    vdebug(8,LA_DEBUG,LF_DCFA,"DW_CFA_same_value r%"PRIu64"\n",op1);

	    rr = calloc(1,sizeof(*rr));
	    rr->rrt = RRT_SAME;

	    __insert_regrule(pc,op1,rr);

	    break;
	/*
	 * NB: some DWARF emitters (gcc) do this; I have no idea why.
	 * But they mean DW_CFA_offset.  Well, actually, I'm not sure if
	 * they do.  There seems to be an 0x90 opcode that is used, and
	 * instead of it meaning an unsigned offset, it seems to be a
	 * signed offset.  So -- we try to handle DW_CFA_offset the
	 * unsigned way; and DW_CFA_offset + 1 ... the signed way.  Who
	 * knows...
	 */
	case DW_CFA_offset:
	    // XXX overflow check
	    op1 = opcode & 0x3f;
	    get_uleb128(op2,readp);
	    sop2 = op2 * cie->data_alignment_factor;
	    vdebug(8,LA_DEBUG,LF_DCFA,"DW_CFA_offset r%u at cfa%+"PRId64"\n",
		   op1,sop2);

	    rr = calloc(1,sizeof(*rr));
	    rr->rrt = RRT_OFFSET;
	    rr->offset.reg = DWARF_CFA_REG;
	    rr->offset.offset = sop2;

	    __insert_regrule(pc,op1,rr);

	    break;
	case (DW_CFA_offset + 1) ... (DW_CFA_offset + 0x3f):
	    // XXX overflow check
	    op1 = opcode & 0x3f;
	    get_uleb128(op2,readp);
	    sop2 = op2 * cie->data_alignment_factor;
	    vdebug(8,LA_DEBUG,LF_DCFA,"DW_CFA_offset r%u at cfa%+"PRId64"\n",
		   op1,(int64_t)sop2);

	    rr = calloc(1,sizeof(*rr));
	    rr->rrt = RRT_OFFSET;
	    rr->offset.reg = DWARF_CFA_REG;
	    rr->offset.offset = sop2;

	    __insert_regrule(pc,op1,rr);

	    break;
	case DW_CFA_offset_extended:
	    // XXX overflow check
	    get_uleb128(op1,readp);
	    get_uleb128(op2,readp);
	    sop2 = op2 * cie->data_alignment_factor;
	    vdebug(8,LA_DEBUG,LF_DCFA,
		   "DW_CFA_offset_extended r%"PRIu64" at cfa%+"PRId64"\n",
		   op1,sop2);

	    rr = calloc(1,sizeof(*rr));
	    rr->rrt = RRT_OFFSET;
	    rr->offset.reg = DWARF_CFA_REG;
	    rr->offset.offset = sop2;

	    __insert_regrule(pc,op1,rr);

	    break;
	case DW_CFA_offset_extended_sf:
	    // XXX overflow check
	    get_uleb128(op1,readp);
	    get_sleb128(sop2,readp);
	    sop2 *= cie->data_alignment_factor;
	    vdebug(8,LA_DEBUG,LF_DCFA,
		   "DW_CFA_offset_extended_sf r%"PRIu64" at cfa%+"PRId64"\n",
		    op1,sop2);

	    rr = calloc(1,sizeof(*rr));
	    rr->rrt = RRT_OFFSET;
	    rr->offset.reg = DWARF_CFA_REG;
	    rr->offset.offset = sop2;

	    __insert_regrule(pc,op1,rr);

	    break;
	/* Obsoleted by DW_CFA_offset_extended_sf. */
	case DW_CFA_GNU_negative_offset_extended:
	    // XXX overflow check
	    get_uleb128(op1,readp);
	    get_uleb128(op2,readp);
	    vdebug(8,LA_DEBUG,LF_DCFA,
		   "DW_CFA_negative_offset_extended r%"PRIu64" at cfa-%"PRIu64"\n",
		    op1,op2);

	    rr = calloc(1,sizeof(*rr));
	    rr->rrt = RRT_OFFSET;
	    rr->offset.reg = DWARF_CFA_REG;
	    rr->offset.offset = -(int64_t)op2;

	    __insert_regrule(pc,op1,rr);

	    break;
	case DW_CFA_val_offset:
	    // XXX overflow check
	    get_uleb128(op1,readp);
	    get_uleb128(op2,readp);
	    sop2 = op2 * cie->data_alignment_factor;
	    vdebug(8,LA_DEBUG,LF_DCFA,
		   "DW_CFA_val_offset r%"PRIu64" at offset %"PRId64"\n",
		    op1,sop2);

	    rr = calloc(1,sizeof(*rr));
	    rr->rrt = RRT_VAL_OFFSET;
	    rr->offset.reg = DWARF_CFA_REG;
	    rr->offset.offset = sop2;

	    __insert_regrule(pc,op1,rr);

	    break;
	case DW_CFA_val_offset_sf:
	    // XXX overflow check
	    get_uleb128(op1,readp);
	    get_sleb128(sop2,readp);
	    sop2 *= cie->data_alignment_factor;
	    vdebug(8,LA_DEBUG,LF_DCFA,
		   "DW_CFA_val_offset_sf r%"PRIu64" at offset %"PRId64"\n",
		   op1,sop2);

	    rr = calloc(1,sizeof(*rr));
	    rr->rrt = RRT_VAL_OFFSET;
	    rr->offset.reg = DWARF_CFA_REG;
	    rr->offset.offset = sop2;

	    __insert_regrule(pc,op1,rr);

	    break;
	case DW_CFA_register:
	    // XXX overflow check
	    get_uleb128(op1,readp);
	    get_uleb128(op2,readp);
	    vdebug(8,LA_DEBUG,LF_DCFA,
		   "DW_CFA_register r%"PRIu64" in r%"PRIu64"\n",op1,op2);

	    rr = calloc(1,sizeof(*rr));
	    rr->rrt = RRT_REG;
	    rr->reg = op2;

	    __insert_regrule(pc,op1,rr);

	    break;
	case DW_CFA_expression:
	    // XXX overflow check
	    get_uleb128(op1,readp);
	    get_uleb128(op2,readp); /* Length of DW_FORM_block.  */
	    vdebug(8,LA_DEBUG,LF_DCFA,
		   "DW_CFA_expression r%"PRIu64" len %"PRIu64"\n",op1,op2);

	    rr = calloc(1,sizeof(*rr));
	    rr->rrt = RRT_EXPR;
	    rr->block.block = readp;
	    rr->block.len = op2;

	    __insert_regrule(pc,op1,rr);

	    readp += op2;
	    break;
	case DW_CFA_val_expression:
	    // XXX overflow check
	    get_uleb128(op1,readp);
	    get_uleb128(op2,readp); /* Length of DW_FORM_block.  */
	    vdebug(8,LA_DEBUG,LF_DCFA,
		   "DW_CFA_val_expression r%"PRIu64" len %"PRIu64"\n",op1,op2);

	    rr = calloc(1,sizeof(*rr));
	    rr->rrt = RRT_VAL_EXPR;
	    rr->block.block = readp;
	    rr->block.len = op2;

	    __insert_regrule(pc,op1,rr);

	    readp += op2;
	    break;
	case DW_CFA_restore ... (DW_CFA_restore + 0x3f):
	    op1 = opcode & 0x3f;
	    vdebug(8,LA_DEBUG,LF_DCFA,"DW_CFA_restore r%"PRIu64"\n",op1);

	    rr = calloc(1,sizeof(*rr));
	    def_rr = (struct dwarf_cfa_regrule *) \
		g_hash_table_lookup(cie->default_regrules,
				    (gpointer)(uintptr_t)op1);
	    if (!def_rr) {
		vwarn("no default regrule for r%"PRIu64"; undefining!\n",op1);
		rr->rrt = RRT_UNDEF;
	    }
	    else {
		memcpy(rr,def_rr,sizeof(*rr));
	    }

	    __insert_regrule(pc,op1,rr);

	    break;
	  case DW_CFA_restore_extended:
	    // XXX overflow check
	    get_uleb128(op1,readp);
	    vdebug(8,LA_DEBUG,LF_DCFA,"DW_CFA_restore_extended r%"PRIu64"\n",op1);

	    rr = calloc(1,sizeof(*rr));
	    def_rr = (struct dwarf_cfa_regrule *) \
		g_hash_table_lookup(cie->default_regrules,
				    (gpointer)(uintptr_t)op1);
	    if (!def_rr) {
		vwarn("no default regrule for r%"PRIu64"; undefining!\n",op1);
		rr->rrt = RRT_UNDEF;
	    }
	    else {
		memcpy(rr,def_rr,sizeof(*rr));
	    }

	    __insert_regrule(pc,op1,rr);

	    break;

	/*
	 * Row State Instructions.
	 */
	case DW_CFA_remember_state:
	    /*
	     * Create a tmp hashtable; grab the last regrule for each
	     * reg in the current hashtable; and put them into the tmp
	     * hashtable and push that onto an array_list stack.  Don't
	     * clone them on push; just clone on pop (restore).
	     */
	    stackhash = g_hash_table_new(g_direct_hash,g_direct_equal);
	    g_hash_table_iter_init(&iter,regrules);
	    while (g_hash_table_iter_next(&iter,&kp,&vp)) {
		cl = (clmatchone_t *)vp;
		tmp_rr = (struct dwarf_cfa_regrule *) \
		    clmatchone_find(cl,ADDRMAX,NULL);
		g_hash_table_insert(stackhash,kp,tmp_rr);
	    }
	    /*
	     * XXX: should we bother with default rules?  Probably not,
	     * because they'll still be the default rules; why
	     * duplicate them?
	     */

	    stack = g_slist_prepend(stack,stackhash);

	    vdebug(8,LA_DEBUG,LF_DCFA,"DW_CFA_remember_state (%d registers)\n",
		   g_hash_table_size(stackhash));

	    break;
	case DW_CFA_restore_state:
	    /*
	     * Ok, pop the latest tmp hashtable off the stack, clone the
	     * regrules, and insert them at the current pc.
	     */
	    if (!stack) {
		verror("no stack for DW_CFA_restore_state; underflow; ignoring!\n");
		break;
	    }

	    stackhash = (GHashTable *)g_slist_nth_data(stack,0);
	    stack = g_slist_remove(stack,stackhash);

	    g_hash_table_iter_init(&iter,stackhash);
	    while (g_hash_table_iter_next(&iter,&kp,&vp)) {
		tmp_rr = (struct dwarf_cfa_regrule *)vp;
		rr = calloc(1,sizeof(*rr));
		memcpy(rr,tmp_rr,sizeof(*rr));
		__insert_regrule(pc,(uint64_t)(uintptr_t)kp,rr);
	    }

	    vdebug(8,LA_DEBUG,LF_DCFA,"DW_CFA_restore_state (%d registers)\n",
		   g_hash_table_size(stackhash));

	    g_hash_table_destroy(stackhash);

	    break;

	/*
	 * Extra stuff.
	 */
	case DW_CFA_GNU_args_size:
	    // XXX overflow check
	    get_uleb128(op1,readp);
	    vdebug(8,LA_DEBUG,LF_DCFA,
		   "DW_CFA_args_size %"PRIu64"; ignoring\n",op1);
	    break;

	/*
	 * And we're done.
	 */
	default:
	    verror("unrecognized DW_CFA_??? opcode (%u); skipping!!\n",opcode);
	    break;
	}
    }

    return 0;
}

int dwarf_load_cfa(struct debugfile *debugfile,
		   unsigned char *buf,unsigned int len,Dwarf *dbg) {
    struct dwarf_debugfile_info *ddi;
    struct dwarf_cfa_cie *cie = NULL;
    struct dwarf_cfa_fde *fde;
    /* XXX: we can't get other_byte_order from dbg since we don't have
     * the struct def for it... so we assume it's not a diff byte order
     * than the phys host for now.
     */
    int obo = 0;

    ptrdiff_t offset,cie_offset;
    Dwarf_Word unit_len;
    unsigned int hlen;
    int wordsize;
    ptrdiff_t start;
    unsigned char *unit_end;
    Dwarf_Off cie_id;
    uint_fast8_t version;
    unsigned int code_alignment_factor;
    int data_alignment_factor;
    unsigned int fde_encoding;
    unsigned int lsda_encoding;
    uint_fast8_t segment_size;
    unsigned int return_address_register;
    char *aug;
    unsigned int auglen;
    uint64_t personality;

    ddi = (struct dwarf_debugfile_info *)debugfile->priv;

    if (!debugfile->frametab) {
	vwarnopt(8,LA_DEBUG,LF_DCFA,"no cfa info");
	return 0;
    }

    ddi->cfa_fde = g_hash_table_new(g_direct_hash,g_direct_equal);
    ddi->cfa_cie = g_hash_table_new(g_direct_hash,g_direct_equal);

    /*
     * Read CIEs/FDEs.  Don't run CFA programs for FDEs; do that on demand.
     */
    const unsigned char *readp = (unsigned char *)buf;
    const unsigned char *const end = readp + len;

    while (readp < end) {
	if (unlikely(readp + 4 > end)) {
	invalid_data:
	    verror("invalid CIE/FDE data at offset 0x%lx!\n",
		   (unsigned long)(readp - buf));
	    errno = EINVAL;
	    return -1;
	}

	/* Read a CIE/FDE length/id. */
	offset = readp - (unsigned char *)buf;
	unit_len = read_4ubyte_unaligned_inc(obo,readp);
	hlen = 4;
	if (unlikely(unit_len == 0xffffffff)) {
	    if (unlikely (readp + 8 > end)) {
		verror("CIE/FDE is too short for length field!\n");
		goto invalid_data;
	    }

	    unit_len = read_8ubyte_unaligned_inc(obo,readp);
	    hlen = 8;
	}

	if (unlikely(unit_len == 0)) {
	    vdebug(8,LA_DEBUG,LF_DCFA,"zero-len CIE at %p\n",offset);
	    continue;
	}

	start = readp - (unsigned char *)buf;
	unit_end = (unsigned char *)readp + unit_len;
	if (unlikely(unit_end > end || (readp + hlen) > end)) {
	    verror("CIE/FDE len exceeds data!\n");
	    goto invalid_data;
	}

	if (hlen == 4) {
	    cie_id = read_4ubyte_unaligned_inc(obo,readp);
	    if (!ddi->is_eh_frame && cie_id == DW_CIE_ID_32)
		cie_id = DW_CIE_ID_64;
	}
	else
	    cie_id = read_8ubyte_unaligned_inc(obo,readp);

	wordsize = debugfile->binfile->wordsize;

	/* Read a CIE. */
	if (cie_id == (ddi->is_eh_frame ? 0 : DW_CIE_ID_64)) {
	    cie = NULL;
	    fde = NULL;

	    version = *readp++;
	    aug = (char *)readp;
	    readp = memchr(readp,'\0',(char *)unit_end - aug);
	    if (unlikely(readp == NULL)) {
		verror("unterminated augmentation string!\n");
		goto invalid_cie_data;
	    }
	    ++readp;

	    if (aug[0] != '\0'
		&& aug[0] != 'z'
		&& !(aug[0] == 'e' && aug[1] == 'h')
		&& aug[0] != 'S') {
		verror("unrecognized augmentation string '%s'; skipping!\n",
		       aug);
		goto invalid_cie_data;
	    }

	    segment_size = 0;
	    if (version >= 4) {
		if (unit_end - readp < 5) {
		    verror("invalid version 4 CIE (not long enough for"
			   " wordsize, segment_size, code/data alignment"
			   " factors, return address register)!\n");
		    goto invalid_cie_data;
		}
		wordsize = *readp++;
		segment_size = *readp++;

		if (!(likely(wordsize == 4 || wordsize == 8))) {
		    verror("bad wordsize %d in CIE 0x%"PRIxPTR"!\n",
			   wordsize,offset);
		    goto invalid_cie_data;
		}
	    }

	    // XXX Check overflow
	    get_uleb128(code_alignment_factor,readp);
	    // XXX Check overflow
	    get_sleb128(data_alignment_factor,readp);

	    /* In some variant for unwind data there is another field.  */
	    if (aug[0] == 'e' && aug[1] == 'h')
		readp += wordsize;

	    if (unlikely (version == 1))
		return_address_register = *readp++;
	    else
		// XXX Check overflow
		get_uleb128(return_address_register,readp);

	    vdebug(8,LA_DEBUG,LF_DCFA,
		   "CIE 0x%lx length=%"PRIu64" id=%"PRIu64" version=%u"
		   " augmentation='%s' address_size=%u segment_size=%u"
		    " code_factor=%u data_factor=%d return_address_register=%u\n",
		   (unsigned long)offset,(uint64_t)unit_len,(uint64_t)cie_id,
		   version,aug,wordsize,segment_size,code_alignment_factor,
		   data_alignment_factor,return_address_register);

	    fde_encoding = 0;
	    lsda_encoding = 0;
	    personality = 0;

	    if (aug[0] == 'z') {
		get_uleb128(auglen,readp);

		if (auglen > (size_t)(end - readp)) {
		    verror("invalid augmentation length %d\n",
			   (int)(end - readp));
		    goto invalid_cie_data;
		}

		const char *cp = aug + 1;
		while (*cp != '\0') {
		    if (*cp == 'R') {
			fde_encoding = *readp++;
		    }
		    else if (*cp == 'L') {
			lsda_encoding = *readp++;
		    }
		    else if (*cp == 'P') {
		      /* Personality.  This field usually has a relocation
			 attached pointing to __gcc_personality_v0.  */
		      unsigned int encoding = *readp++;
		      personality = 0;
		      readp = __read_encoded(encoding,
					     debugfile->binfile->wordsize,
					     readp,readp - 1 + auglen,
					     &personality,dbg);
		    }
		    else {
			vwarn("unrecognized augmentation substring (%s);"
			      " trying to skip substring (CIE 0x%lx)!\n",
			      (char *)readp,(unsigned long)offset);
			++readp;
		    }

		    ++cp;
		}
	    }

	    /* Cache the CIE. */
	    cie = calloc(1,sizeof(*cie));
	    cie->offset = offset;
	    cie->version = version;
	    cie->segment_size = segment_size;
	    cie->code_alignment_factor = code_alignment_factor;
	    cie->data_alignment_factor = data_alignment_factor;
	    cie->fde_encoding = fde_encoding;
	    cie->lsda_encoding = lsda_encoding;
	    cie->personality = personality;
	    cie->return_address_register = return_address_register;
	    cie->default_regrules = 
		g_hash_table_new(g_direct_hash,g_direct_equal);
	    cie->aug = aug;
	    cie->auglen = 
		memchr(aug,'\0',(size_t)(unit_end - (unsigned char *)aug)) 
		    - (void *)aug;

	    g_hash_table_insert(ddi->cfa_cie,(gpointer)offset,cie);

	    /* Parse the CIE instructions to get default regrules. */
	    dwarf_cfa_program_interpret(debugfile,cie,NULL,readp,
					unit_end - readp,cie->default_regrules);

	    readp = unit_end;
	    continue;

	invalid_cie_data:
	    verror("invalid CIE (0x%lx) data at offset 0x%lx!\n",
		   (unsigned long)offset,(unsigned long)(readp - buf));
	    cie = NULL;
	    readp = unit_end;
	    continue;
	}
	/*
	 * Parse an FDE once we are in a CIE!
	 */
	else {
	    cie_offset = (ddi->is_eh_frame) \
		? start - (ptrdiff_t)cie_id : (ptrdiff_t)cie_id;

	    cie = (struct dwarf_cfa_cie *)				\
		g_hash_table_lookup(ddi->cfa_cie,(gpointer)cie_offset);
	    if (!cie) {
		verror("invalid CIE reference 0x%lx in FDE 0x%lx; skipping FDE!\n",
		       (unsigned long)cie_offset,(unsigned long)offset);
		return -1;
	    }

	    fde = calloc(1,sizeof(*fde));
	    fde->cie = cie;
	    fde->offset = offset;

	    /* Initialize from CIE data.  */
	    lsda_encoding = cie->lsda_encoding;
	    switch (cie->fde_encoding & 7) {
	    case 2:  wordsize = 2; break;
	    case 3:  wordsize = 4; break;
	    case 4:  wordsize = 8; break;
	    default: wordsize = debugfile->binfile->wordsize;
	    }

	    const unsigned char *base = readp;
	    // XXX There are sometimes relocations for this value
	    if (cie->fde_encoding & DW_EH_PE_signed)
		fde->initial_location = (ADDR)
		    read_sbyte_unaligned_inc(wordsize,obo,readp);
	    else
		fde->initial_location = (ADDR)
		    read_ubyte_unaligned_inc(wordsize,obo,readp);

	    if ((cie->fde_encoding & 0x70) == DW_EH_PE_pcrel)
		fde->initial_location += ddi->frame_sec_addr 
		    + (base - (unsigned char *)debugfile->frametab);

	    fde->address_range = (ADDR) 
		read_ubyte_unaligned_inc(wordsize,obo,readp);

	    /*
	    if ((cie->fde_encoding & 0x70) == DW_EH_PE_pcrel) {
		fde->vma_base = ((ddi->frame_sec_offset
				  + (base - (const unsigned char *)debugfile->frametab)
				  + (uint64_t)fde->initial_location)
				 & (wordsize == 4
				    ? UINT64_C(0xffffffff)
				    : UINT64_C(0xffffffffffffffff)));
	    }
	    */

	    vdebug(8,LA_DEBUG,LF_DCFA,
		   "FDE 0x%lx length=%"PRIu64" cie=0x%lx id=%"PRIx64
		   " initial_location=0x%"PRIxADDR" address_range=0x%"PRIxADDR,
		   (unsigned long)offset,(uint64_t)unit_len,
		   (unsigned long)cie->offset,(uint64_t)cie_id,
		   fde->initial_location,fde->address_range);
	    /*
	    if (fde->vma_base) {
		vdebugc(8,LA_DEBUG,LF_DCFA,
			" (vma_base=0x%"PRIx64" vma_range=0x%"PRIx64"\n",
			(uint64_t)fde->vma_base,
			(uint64_t)(fde->vma_base + fde->address_range));
	    }
	    else {
	    */
		vdebugc(8,LA_DEBUG,LF_DCFA,"\n");
	    /*
	    }
	    */

	    if (cie->aug[0] == 'z') {
		get_uleb128(auglen,readp);

		if (auglen > 0) {
		    //const char *hdr = "Augmentation data:";
		    const char *cp = cie->aug + 1;
		    unsigned int u = 0;
		    while (*cp != '\0') {
			if (*cp == 'L') {
			    uint64_t lsda_pointer;
			    const unsigned char *p =
				__read_encoded(cie->lsda_encoding,wordsize,
					       &readp[u],&readp[auglen],
					       &lsda_pointer,dbg);
			    u = p - readp;
			    //printf (gettext ("%-26sLSDA pointer: %#" PRIx64 "\n"),
			    //hdr, lsda_pointer);
			    //hdr = "";
			}
			++cp;
		    }

		    while (u < auglen) {
			//printf ("   %-26s%#x\n", hdr, readp[u]);
			//hdr = "";
			u++;
		    }
		}

		readp += auglen;
	    }

	    fde->instructions = (unsigned char *)readp;
	    fde->len = unit_end - readp;

	    /*
	     * NB: don't run the FDE programs until we need them.
	     */
	    /*/
	    fde->regrules = g_hash_table_new(g_direct_hash,g_direct_equal);

	    dwarf_cfa_program_interpret(debugfile,cie,fde,fde->instructions,
	                                fde->len,fde->regrules);
	    */

	    g_hash_table_insert(ddi->cfa_fde,
				(gpointer)(uintptr_t)fde->initial_location,fde);
	}

	readp = unit_end;
    }

    return 0;
}

int dwarf_cfa_fde_decode(struct debugfile *debugfile,
			 struct dwarf_cfa_fde *fde) {
    if (fde->regrules)
	return 0;

    fde->regrules = g_hash_table_new(g_direct_hash,g_direct_equal);

    if (dwarf_cfa_program_interpret(debugfile,fde->cie,fde,fde->instructions,
				    fde->len,fde->regrules)) {
	verror("error while decoding FDE 0x%lx (CIE 0x%lx)!\n",
	       (unsigned long)fde->offset,(unsigned long)fde->cie->offset);
	return -1;
    }

    return 0;
}

struct dwarf_cfa_regrule *
dwarf_cfa_fde_lookup_regrule(struct dwarf_cfa_fde *fde,REG reg,ADDR obj_addr) {
    struct dwarf_cfa_regrule *rr;
    clmatchone_t *cl;

    cl = g_hash_table_lookup(fde->regrules,(gpointer)(uintptr_t)reg);
    if (cl) {
	if ((rr = clmatchone_find(cl,obj_addr,NULL)))
	    return rr;
    }

    rr = (struct dwarf_cfa_regrule *) \
	g_hash_table_lookup(fde->cie->default_regrules,(gpointer)(uintptr_t)reg);
    return rr;
}

static int dwarf_cfa_fde_run_regrule(struct debugfile *debugfile,
				     struct dwarf_cfa_fde *fde,
				     struct dwarf_cfa_regrule *rr,
				     struct location_ctxt *lctxt,
				     REG reg,REGVAL *o_regval) {
    REGVAL rv;
    ADDR addr;
    ADDR word;
    loctype_t ltrc;
    struct location loc;
    int rc;
    struct symbol *symbol;
    struct location_ops *lops;

    if (!lctxt || !lctxt->ops) {
	verror("could not get location ops for current frame %d!\n",
	       lctxt->current_frame);
	errno = EINVAL;
	return -1;
    }
    lops = lctxt->ops;

    if (!lops->getsymbol) {
	verror("no location_ops->getsymbol for current frame %d!\n",
	       lctxt->current_frame);
	errno = EINVAL;
	return -1;
    }
    symbol = lops->getsymbol(lctxt);

    switch (rr->rrt) {
    case RRT_UNDEF:
	return 1;
    case RRT_SAME:
	/*
	 * Temporarily adjust lctxt->current_frame.  This sucks a bit
	 * cause we're not tail-recursive, but it's not a big deal.
	 */
	if (!lops->setcurrentframe) {
	    verror("no location_ops->setcurrentframe for current frame %d!\n",
		   lctxt->current_frame);
	    errno = EINVAL;
	    return -1;
	}
	if (lops->setcurrentframe(lctxt,lctxt->current_frame - 1)) {
	    verror("failed to setcurrentframe from %d to %d!\n",
		   lctxt->current_frame,lctxt->current_frame - 1);
	    errno = EINVAL;
	    return -1;
	}
	rc = location_ctxt_read_reg(lctxt,reg,o_regval);
	if (lops->setcurrentframe(lctxt,lctxt->current_frame + 1)) {
	    verror("failed to setcurrentframe from %d to %d!\n",
		   lctxt->current_frame,lctxt->current_frame + 1);
	    errno = EINVAL;
	    return -1;
	}
	return rc;
    case RRT_OFFSET:
	/*
	 * We actually enhance the DWARF offset(N) register rule to not
	 * only load the CFA register -- but potentially any register.
	 * This makes things easier.  But we do then have to
	 * special-case the CFA register, because it's a pseudo-reg we
	 * have to compute.
	 *
	 * Get the current frame's offset.reg value, add the offset, and
	 * load that address.
	 */
	if (rr->offset.reg == DWARF_CFA_REG) {
	    rc = dwarf_cfa_read_saved_reg(debugfile,lctxt,(REG)rr->offset.reg,&rv);
	    if (rc) {
		verror("could not read CFA pseudo-reg %"PRIu64" value"
		       " to read reg %"PRIiREG"!\n",rr->offset.reg,reg);
		return -1;
	    }
	}
	else {
	    rc = location_ctxt_read_reg(lctxt,rr->offset.reg,&rv);
	    if (rc) {
		verror("could not read reg %"PRIu64" value"
		       " to read reg %"PRIiREG"!\n",rr->offset.reg,reg);
		return -1;
	    }
	}
	addr = rv + rr->offset.offset;
	if (lops->readword(lctxt,addr,&word)) {
	    verror("could not read addr 0x%"PRIxADDR" to read reg %d"
		   " in frame %d!\n",
		   addr,reg,lctxt->current_frame);
	    return -1;
	}
	if (o_regval)
	    *o_regval = (REGVAL)word;
	return 0;
    case RRT_VAL_OFFSET:
	/*
	 * Get the current frame's offset.reg value, add the offset, and
	 * return it as the value.  Same comment as for the RRT_OFFSET
	 * case as far as enlarging the val_offset(N) operation to
	 * handle any register, not just the CFA pseudo register.
	 */
	rc = location_ctxt_read_reg(lctxt,rr->offset.reg,&rv);
	if (rc) {
	    if (rr->offset.reg == DWARF_CFA_REG)
		verror("could not read CFA pseudo-reg %"PRIu64" value"
		       " to read reg %"PRIiREG"!\n",rr->offset.reg,reg);
	    else
		verror("could not read reg %"PRIu64" value"
		       " to read reg %"PRIiREG"!\n",rr->offset.reg,reg);
	    return -1;
	}
	rv += rr->offset.offset;
	if (o_regval)
	    *o_regval = (REGVAL)rv;
	return 0;
    case RRT_REG:
	/*
	 * Get rr->reg's value to return as the value of @reg.
	 */
	rc = location_ctxt_read_reg(lctxt,rr->reg,&rv);
	if (rc) {
	    verror("could not read reg %"PRIu64" value"
		   " as the value for reg %"PRIiREG"!\n",rr->reg,reg);
	    return -1;
	}
	if (o_regval)
	    *o_regval = (REGVAL)rv;
	return 0;
    case RRT_EXPR:
	/*
	 * Run the DWARF expr block; load the regval from the resulting
	 * address.
	 */
	memset(&loc,0,sizeof(loc));
	ltrc = dwarf_location_resolve(rr->block.block,rr->block.len,
				      lctxt,symbol,&loc);
	if (ltrc != LOCTYPE_ADDR) {
	    if ((int)ltrc < 0) 
		verror("error evaluating DWARF expr for frame %d (symbol %s):"
		       " %d!\n",
		       lctxt->current_frame,symbol_get_name(symbol),ltrc);
	    else 
		verror("error evaluating DWARF expr for frame %d (symbol %s):"
		       " unexpected expr result %d!\n",
		       lctxt->current_frame,symbol_get_name(symbol),ltrc);
	    return -1;
	}
	addr = LOCATION_ADDR(&loc);
	if (lops->readword(lctxt,addr,&word)) {
	    verror("could not read addr 0x%"PRIxADDR" to read reg %d"
		   " in frame %d!\n",
		   addr,reg,lctxt->current_frame);
	    return -1;
	}
	if (o_regval)
	    *o_regval = (REGVAL)word;
	return 0;
    case RRT_VAL_EXPR:
	/*
	 * Run the DWARF expr block; the result is the register's value.
	 */
	memset(&loc,0,sizeof(loc));
	ltrc = dwarf_location_resolve(rr->block.block,rr->block.len,
				      lctxt,symbol,&loc);
	if (ltrc != LOCTYPE_ADDR && ltrc != LOCTYPE_IMPLICIT_WORD) {
	    if ((int)ltrc < 0) 
		verror("error evaluating DWARF expr for frame %d (symbol %s):"
		       " %d!\n",
		       lctxt->current_frame,symbol_get_name(symbol),ltrc);
	    else 
		verror("error evaluating DWARF expr for frame %d (symbol %s):"
		       " unexpected expr result %d!\n",
		       lctxt->current_frame,symbol_get_name(symbol),ltrc);
	    return -1;
	}
	else if (ltrc == LOCTYPE_ADDR) 
	    rv = LOCATION_ADDR(&loc);
	else if (ltrc == LOCTYPE_IMPLICIT_WORD)
	    rv = LOCATION_WORD(&loc);

	if (o_regval)
	    *o_regval = rv;
	return 0;
    default:
	verror("unknown DWARF CFA register rule %d; BUG!\n",rr->rrt);
	errno = EINVAL;
	return -1;
    }
}

/*
 * If the caller asks for this platform's stack pointer register value,
 * we instead compute CFA!
 */
int dwarf_cfa_read_saved_reg(struct debugfile *debugfile,
			     struct location_ctxt *lctxt,
			     REG reg,REGVAL *o_regval) {
    struct dwarf_debugfile_info *ddi;
    struct dwarf_cfa_fde *fde;
    struct dwarf_cfa_cie *cie;
    struct symbol *symbol;
    REG ipreg;
    ADDR ip;
    struct dwarf_cfa_regrule *rr;
    ADDR retval;
    int rc;
    struct location_ops *lops;
    REG spreg = -1;
    int was_sp = 0;
    struct scope *scope;

    if (!lctxt || !lctxt->ops) {
	verror("no location ops for current frame %d!\n",lctxt->current_frame);
	errno = EINVAL;
	return -1;
    }
    lops = lctxt->ops;

    if (!debugfile->priv) {
	errno = EINVAL;
	return -1;
    }

    ddi = (struct dwarf_debugfile_info *)debugfile->priv;
    if (!ddi || !ddi->cfa_fde || !ddi->cfa_cie) {
	errno = EINVAL;
	return -1;
    }

    symbol = lops->getsymbol(lctxt);
    if (!symbol) {
	verror("failed to getsymbol for current frame %d!\n",
	       lctxt->current_frame);
	errno = EINVAL;
	return -1;
    }

    if (symbol->isinlineinstance 
	&& symbol->scope->symbol && SYMBOL_IS_FUNC(symbol->scope->symbol)) {
	vdebug(5,LA_DEBUG,LF_DCFA,
	       "using symbol %s instead of inline instance of %s for CFA\n",
	       symbol_get_name(symbol->scope->symbol),symbol_get_name(symbol));
	symbol = symbol->scope->symbol;
    }
    else if (symbol->isinlineinstance) {
	vwarn("inlined %s not in parent func; BUG?!\n",symbol_get_name(symbol));
    }

    if (!lops || !lops->getregno || lops->getregno(lctxt,CREG_SP,&spreg)) {
	vwarn("could not check CREG_SP for equivalence with DWARF CFA reg;"
	      " things might break!\n");
    }
    else if (reg == spreg) {
	vdebug(8,LA_DEBUG,LF_DCFA,
	       "reading CFA pseudo-reg to get SP value in current frame %d\n",
	       lctxt->current_frame);
	reg = DWARF_CFA_REG;
	was_sp = 1;
    }

    /*
     * Figure out what IP is in the current frame, and unrelocate it so
     * we can use it.
     */
    if (!lops || !lops->getregno) {
	verror("could not get debuginfo IP reg number!\n");
	errno = EINVAL;
	return -1;
    }
    lops->getregno(lctxt,CREG_IP,&ipreg);
    if (lops->readreg(lctxt,ipreg,&ip)) {
	verror("could not read IP reg in frame %d!\n",lctxt->current_frame);
	return -1;
    }
    if (lops && lops->unrelocate && lops->unrelocate(lctxt,ip,&ip)) {
	verror("could not unrelocate real IP 0x%"PRIxADDR"!\n",ip);
	return -1;
    }

    /*
     * Assume symbol->addr has the address that we recorded for this
     * FDE.  It must.
     */
    fde = (struct dwarf_cfa_fde *) \
	g_hash_table_lookup(ddi->cfa_fde,(gpointer)(uintptr_t)symbol->addr);
    if (!fde) {
	/*
	 * Try to handle the case where the symbol is an inlined
	 * instance.  In this case, the FDE info might be at the address
	 * of the inlined decl source.  So keep looking up the scope
	 * chain, trying to find an FDE that matches us.
	 */
	scope = symbol->scope;
	while (scope) {
	    if (!scope->range) 
		continue;

	    fde = (struct dwarf_cfa_fde *)		\
		g_hash_table_lookup(ddi->cfa_fde,
				    (gpointer)(uintptr_t)scope->range->start);
	    if (fde) {
		if (scope->symbol) {
		    vdebug(5,LA_DEBUG,LF_DCFA,
			   "found DWARF CFA FDE at addr 0x%"PRIxADDR" symbol '%s'"
			   " containing symbol '%s' addr 0x%"PRIxADDR";"
			   " probably inlined\n",
			   scope->range->start,symbol_get_name(scope->symbol),
			   symbol_get_name(symbol),symbol->addr);
		}
		else {
		    vdebug(5,LA_DEBUG,LF_DCFA,
			   "found DWARF CFA FDE at scope addr 0x%"PRIxADDR
			   " containing symbol '%s' addr 0x%"PRIxADDR";"
			   " probably inlined\n",
			   scope->range->start,symbol_get_name(symbol),
			   symbol->addr);
		}
		break;
	    }

	    scope = scope->parent;
	}
    }

    if (!fde) {
	verror("no DWARF CFA FDE for symbol '%s' at addr 0x%"PRIxADDR"!\n",
	       symbol_get_name(symbol),symbol->addr);
	errno = ESRCH;
	return -1;
    }
    else if (!(fde->initial_location <= symbol->addr 
	       && symbol->addr < (fde->initial_location + fde->address_range))) {
	verror("no DWARF CFA FDE for symbol '%s' containing addr 0x%"PRIxADDR"!\n",
	       symbol_get_name(symbol),symbol->addr);
	errno = ESRCH;
	return -1;
    }
    cie = fde->cie;

    /*
     * If the FDE hasn't been decoded, decode it now.
     */
    if (dwarf_cfa_fde_decode(debugfile,fde)) {
	verror("error while decoding DWARF CFA FDE for symbol '%s'"
	       " at addr 0x%"PRIxADDR"!\n",
	       symbol_get_name(symbol),symbol->addr);
	return -1;
    }

    /*
     * If it doesn't have a regrule for the retaddr register number,
     * bail successfully.
     */
    rr = dwarf_cfa_fde_lookup_regrule(fde,reg,ip);
    if (!rr) {
	verror("could not find DWARF CFA regrule for reg %d at"
	       " obj addr 0x%"PRIxADDR"\n",
	       reg,ip);
	return -1;
    }

    /*
     * Otherwise, execute the regrule!
     */
    rc = dwarf_cfa_fde_run_regrule(debugfile,fde,rr,lctxt,reg,&retval);
    if (rc) {
	verror("could not load register %d in FDE 0x%lx CIE 0x%lx\n!",
	       reg,(unsigned long)fde->offset,(unsigned long)cie->offset);
	return -1;
    }

    if (reg == DWARF_CFA_REG) {
	vdebug(8,LA_DEBUG,LF_DCFA,
	       "read CFA pseudo-reg value 0x%"PRIxADDR" in current frame %d\n",
	       retval,lctxt->current_frame);
    }

    if (was_sp) {
	vdebug(8,LA_DEBUG,LF_DCFA,
	       "read CFA pseudo-reg to get SP value in current frame %d;"
	       " SP is 0x%"PRIxADDR"\n",
	       lctxt->current_frame,retval);
    }

    if (o_regval)
	*o_regval = retval;
    return 0;
}

/*
 * Read the return address value from the current frame.
 *
 * We have to find the CFA decoding for the current frame's symbol; find
 * its return address register number; if it doesn't have one, return 0
 * AND set o_retaddr to NULL; if it has one, then read the current
 * frame's IP and find the rule for the return address number for that
 * IP.  Then execute the rule and save the value in o_retaddr.
 */
int dwarf_cfa_read_retaddr(struct debugfile *debugfile,
			   struct location_ctxt *lctxt,ADDR *o_retaddr) {
    struct dwarf_debugfile_info *ddi;
    struct dwarf_cfa_fde *fde;
    struct dwarf_cfa_cie *cie;
    struct symbol *symbol;
    REG ipreg;
    ADDR ip;
    struct dwarf_cfa_regrule *rr;
    ADDR retval;
    int rc;
    struct location_ops *lops;
    struct scope *scope;

    if (!lctxt || !lctxt->ops) {
	verror("no location_ops for current frame %d!\n",lctxt->current_frame);
	errno = EINVAL;
	return -1;
    }
    lops = lctxt->ops;

    if (!debugfile->priv) {
	errno = EINVAL;
	return -1;
    }
    ddi = (struct dwarf_debugfile_info *)debugfile->priv;
    if (!ddi->cfa_fde || !ddi->cfa_cie) {
	errno = EINVAL;
	return -1;
    }

    if (!lops->getsymbol) {
	verror("no location_ops->getsymbol for current frame %d\n",
	       lctxt->current_frame);
	errno = EINVAL;
	return -1;
    }
    symbol = lops->getsymbol(lctxt);
    if (!symbol) {
	verror("failed to getsymbol for current frame %d!\n",
	       lctxt->current_frame);
	errno = EINVAL;
	return -1;
    }

    /*
     * This strategy does not work for handling inlines; see below for
     * the one that does.
     */
    /*
    if (symbol->isinlineinstance 
	&& symbol->scope->symbol && SYMBOL_IS_FUNC(symbol->scope->symbol)) {
	vdebug(5,LA_DEBUG,LF_DCFA,
	       "using symbol %s instead of inline instance of %s for CFA\n",
	       symbol_get_name(symbol->scope->symbol),symbol_get_name(symbol));
	symbol = symbol->scope->symbol;
    }
    else if (symbol->isinlineinstance) {
	vwarn("inlined %s not in parent func; BUG?!\n",symbol_get_name(symbol));
    }
    */

    /*
     * Figure out what IP is in the current frame, and unrelocate it so
     * we can use it.
     */
    if (!lops->getregno) {
	verror("could not get debuginfo IP reg number!\n");
	errno = EINVAL;
	return -1;
    }
    lops->getregno(lctxt,CREG_IP,&ipreg);
    if (location_ctxt_read_reg(lctxt,ipreg,&ip)) {
        verror("IP register value not in current frame %d; BUG!\n",
	       lctxt->current_frame);
	errno = EINVAL;
	return -1;
    }
    if (lops->unrelocate && lops->unrelocate(lctxt,ip,&ip)) {
	verror("could not unrelocate real IP 0x%"PRIxADDR"!\n",ip);
	return -1;
    }

    /*
     * Assume symbol->addr has the address that we recorded for this
     * FDE.  It must.
     */
    fde = (struct dwarf_cfa_fde *) \
	g_hash_table_lookup(ddi->cfa_fde,(gpointer)(uintptr_t)symbol->addr);
    if (!fde) {
	/*
	 * Try to handle the case where the symbol is an inlined
	 * instance.  In this case, the FDE info might be at the address
	 * of the inlined decl source.  So keep looking up the scope
	 * chain, trying to find an FDE that matches us.
	 */
	scope = symbol->scope;
	while (scope) {
	    if (!scope->range) 
		continue;

	    fde = (struct dwarf_cfa_fde *)		\
		g_hash_table_lookup(ddi->cfa_fde,
				    (gpointer)(uintptr_t)scope->range->start);
	    if (fde) {
		if (scope->symbol) {
		    vdebug(5,LA_DEBUG,LF_DCFA,
			   "found DWARF CFA FDE at addr 0x%"PRIxADDR" symbol '%s'"
			   " containing symbol '%s' addr 0x%"PRIxADDR";"
			   " probably inlined\n",
			   scope->range->start,symbol_get_name(scope->symbol),
			   symbol_get_name(symbol),symbol->addr);
		}
		else {
		    vdebug(5,LA_DEBUG,LF_DCFA,
			   "found DWARF CFA FDE at scope addr 0x%"PRIxADDR
			   " containing symbol '%s' addr 0x%"PRIxADDR";"
			   " probably inlined\n",
			   scope->range->start,symbol_get_name(symbol),
			   symbol->addr);
		}
		break;
	    }

	    scope = scope->parent;
	}
    }

    if (!fde) {
	verror("no DWARF CFA FDE for symbol '%s' at addr 0x%"PRIxADDR"!\n",
	       symbol_get_name(symbol),symbol->addr);
	errno = ESRCH;
	return -1;
    }
    else if (!(fde->initial_location <= symbol->addr 
	       && symbol->addr < (fde->initial_location + fde->address_range))) {
	verror("no DWARF CFA FDE for symbol '%s' containing addr 0x%"PRIxADDR"!\n",
	       symbol_get_name(symbol),symbol->addr);
	errno = ESRCH;
	return -1;
    }

    cie = fde->cie;

    /*
     * If the FDE hasn't been decoded, decode it now.
     */
    if (dwarf_cfa_fde_decode(debugfile,fde)) {
	verror("error while decoding DWARF CFA FDE for symbol '%s'"
	       " at addr 0x%"PRIxADDR"!\n",
	       symbol_get_name(symbol),symbol->addr);
	return -1;
    }

    /*
     * If it doesn't have a regrule for the retaddr register number,
     * bail successfully.
     */
    rr = dwarf_cfa_fde_lookup_regrule(fde,cie->return_address_register,ip);
    if (!rr) {
	verror("could not find DWARF CFA regrule for retaddr reg %d at"
	       " obj addr 0x%"PRIxADDR"\n",
	       cie->return_address_register,ip);
	return -1;
    }

    /*
     * Otherwise, execute the regrule!
     */
    rc = dwarf_cfa_fde_run_regrule(debugfile,fde,rr,lctxt,
				   cie->return_address_register,&retval);
    if (rc) {
	verror("could not load return address register %d"
	       " in FDE 0x%lx CIE 0x%lx\n!",
	       cie->return_address_register,(unsigned long)fde->offset,
	       (unsigned long)cie->offset);
	return -1;
    }

    if (o_retaddr)
	*o_retaddr = retval;
    return 0;
}

int dwarf_unload_cfa(struct debugfile *debugfile) {
    struct dwarf_debugfile_info *ddi;
    GHashTableIter iter;
    gpointer kp, vp;
    struct dwarf_cfa_fde *fde;
    struct dwarf_cfa_cie *cie;

    if (!debugfile->priv)
	return 0;

    ddi = (struct dwarf_debugfile_info *)debugfile->priv;
    
    if (ddi->cfa_fde) {
	g_hash_table_iter_init(&iter,ddi->cfa_fde);
	while (g_hash_table_iter_next(&iter,&kp,&vp)) {
	    fde = (struct dwarf_cfa_fde *)vp;
	    dwarf_cfa_fde_free(fde);
	    g_hash_table_iter_replace(&iter,NULL);
	}
        g_hash_table_destroy(ddi->cfa_fde);
	ddi->cfa_fde = NULL;
    }

    if (ddi->cfa_cie) {
	g_hash_table_iter_init(&iter,ddi->cfa_cie);
	while (g_hash_table_iter_next(&iter,&kp,&vp)) {
	    cie = (struct dwarf_cfa_cie *)vp;
	    dwarf_cfa_cie_free(cie);
	    g_hash_table_iter_replace(&iter,NULL);
	}
	g_hash_table_destroy(ddi->cfa_cie);
	ddi->cfa_cie = NULL;
    }

    return 0;
}

/*
 * Taken from elfutils/src/readelf.c and slightly modified.
 */
static const unsigned char *__read_encoded(unsigned int encoding,
					   unsigned int wordsize,
					   const unsigned char *readp,
					   const unsigned char *const endp,
					   uint64_t *res,Dwarf *dbg) {
    /* XXX: we can't get other_byte_order from dbg since we don't have
     * the struct def for it... so we assume it's not a diff byte order
     * than the phys host for now.
     */
    int obo = 0;

    if ((encoding & 0xf) == DW_EH_PE_absptr)
	encoding = (wordsize == 4) ? DW_EH_PE_udata4 : DW_EH_PE_udata8;

    switch (encoding & 0xf) {
    case DW_EH_PE_uleb128:
	// XXX buffer overrun check
	get_uleb128(*res,readp);
      break;
    case DW_EH_PE_sleb128:
	// XXX buffer overrun check
	get_sleb128(*res,readp);
	break;
    case DW_EH_PE_udata2:
	if (readp + 2 > endp)
	    goto invalid;
	*res = read_2ubyte_unaligned_inc(obo,readp);
	break;
    case DW_EH_PE_udata4:
	if (readp + 4 > endp)
	    goto invalid;
	*res = read_4ubyte_unaligned_inc(obo,readp);
	break;
    case DW_EH_PE_udata8:
	if (readp + 8 > endp)
	    goto invalid;
	*res = read_8ubyte_unaligned_inc(obo,readp);
	break;
    case DW_EH_PE_sdata2:
	if (readp + 2 > endp)
	    goto invalid;
	*res = read_2sbyte_unaligned_inc(obo,readp);
      break;
    case DW_EH_PE_sdata4:
	if (readp + 4 > endp)
	    goto invalid;
	*res = read_4sbyte_unaligned_inc(obo,readp);
	break;
    case DW_EH_PE_sdata8:
	if (readp + 8 > endp)
	    goto invalid;
	*res = read_8sbyte_unaligned_inc(obo,readp);
	break;
    default:
    invalid:
	verror("invalid encoding '%*s' at %p!\n",
	       (int)(uintptr_t)(endp - readp),readp,readp);
    }

    return readp;
}
