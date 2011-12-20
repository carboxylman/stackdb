#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>

#include "libdwdebug.h"

#include <dwarf.h>
#include <gelf.h>
#include <elfutils/libebl.h>
#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>

#include "memory-access.h"

/*
 * Prototypes.
 */

/*
 * Return a list of files to load debuginfo from!
 */
int find_debug_files(struct target *target,
		     struct memregion *region,
		     char **filelist) {
    int alloclen = 4;
    int listlen = 0;

    filelist = malloc(sizeof(char *)*alloclen);
    if (!filelist)
	return -1;

    memset(filelist,0,sizeof(char *)*alloclen);

    return 0;
}

struct attrcb_args {
    Dwfl_Module *dwflmod;
    Dwarf *dbg;
    int level;
    unsigned int addrsize;
    unsigned int offset_size;
    Dwarf_Off cu_offset;
    Dwarf_Half version;

    struct debugfile *debugfile;
    struct symtab *cu_symtab;
    struct symtab *symtab;
    struct symbol *symbol;
    struct symbol *parentsymbol;
    struct symbol *voidsymbol;
    GHashTable *typeoffsettab;
};

/* Declare this now; it's used in attr_callback. */
static int get_static_ops(Dwfl_Module *dwflmod,Dwarf *dbg,unsigned int vers,
			  unsigned int addrsize,unsigned int offset_size,
			  Dwarf_Word len,const unsigned char *data,
			  unsigned int attr,struct location *retval);

static int attr_callback(Dwarf_Attribute *attrp,void *arg) {
    struct attrcb_args *cbargs = (struct attrcb_args *)arg;
    const int level = cbargs->level;
    struct debugfile *debugfile = cbargs->debugfile;

    if (unlikely(attrp == NULL)) {
	lerror("cannot get attribute: %s",dwarf_errmsg (-1));
	return DWARF_CB_ABORT;
    }

    unsigned int attr = attrp->code;
    unsigned int form = attrp->form;

    if (unlikely(attr == 0)) {
	lerror("attr code was 0, aborting!\n");
	goto errout;
    }
    if (unlikely(form == 0)) {
	lerror("form code was 0, aborting!\n");
	goto errout;
    }

    ldebug(4,"\t\t%d %s (%s) (as=%d,os=%d)\n",(int)level,
	   dwarf_attr_string(attr),dwarf_form_string(form),cbargs->addrsize,
	   cbargs->offset_size);

    /* if form is a string */
    char *str = NULL;

    Dwarf_Word num;
    Dwarf_Addr addr;
    Dwarf_Block block;
    bool flag;
    uint64_t ref;
    Dwarf_Die rref;

    uint8_t str_set = 0;
    uint8_t num_set = 0;
    uint8_t addr_set = 0;
    uint8_t flag_set = 0;
    uint8_t ref_set = 0;
    uint8_t block_set = 0;

    switch(form) {
    case DW_FORM_string:
	str = (char *)attrp->valp;
	str_set = 1;
	break;
    case DW_FORM_strp:
    case DW_FORM_indirect:
	//str = dwarf_formstring(attrp);
	//str_set = 1;
	//break;
	if (*(attrp->valp) > (debugfile->strtablen - 1)) {
	    lerror("dwarf str at 0x%lx not in strtab for attr %s!\n",
		   (unsigned long int)*(attrp->valp),
		   dwarf_attr_string(attr));
	    goto errout;
	}
	// XXX relocation...
	if (cbargs->offset_size == 4)
	    str = &debugfile->strtab[*((uint32_t *)attrp->valp)];
	else 
	    str = &debugfile->strtab[*((uint64_t *)attrp->valp)];
	str_set = 1;
	break;
    case DW_FORM_addr:
	if (unlikely(dwarf_formaddr(attrp,&addr) != 0)) {
	    lerror("could not get dwarf addr for attr %s\n",
		   dwarf_attr_string(attr));
	    goto errout;
	}
	addr_set = 1;
	break;
    case DW_FORM_ref_addr:
    case DW_FORM_ref_udata:
    case DW_FORM_ref8:
    case DW_FORM_ref4:
    case DW_FORM_ref2:
    case DW_FORM_ref1:
	if (unlikely(dwarf_formref_die(attrp,&rref) == NULL)) {
	    lerror("could not get dwarf die ref for attr %s\n",
		   dwarf_attr_string(attr));
	    goto errout;
	}
	ref = dwarf_dieoffset(&rref);
	ref_set = 1;
	break;
    case DW_FORM_udata:
    case DW_FORM_sdata:
    case DW_FORM_data8:
    case DW_FORM_data4:
    case DW_FORM_data2:
    case DW_FORM_data1:
	if (unlikely(dwarf_formudata(attrp,&num) != 0)) {
	    lerror("could not load dwarf num for attr %s",
		   dwarf_attr_string(attr));
	    goto errout;
	}
	num_set = 1;
	break;
    case DW_FORM_exprloc:
    case DW_FORM_block4:
    case DW_FORM_block2:
    case DW_FORM_block1:
    case DW_FORM_block:
	if (unlikely(dwarf_formblock(attrp,&block) != 0)) {
	    lerror("could not load dwarf block for attr %s",
		   dwarf_attr_string(attr));
	    goto errout;
	}
	block_set = 1;
	break;
    case DW_FORM_flag:
	if (unlikely(dwarf_formflag(attrp,&flag) != 0)) {
	    lerror("could not load dwarf flag for attr %s",
		   dwarf_attr_string(attr));
	    goto errout;
	}
	flag_set = 1;
	break;
    default:
	lwarn("unrecognized form %s for attr %s\n",
	      dwarf_form_string(form),dwarf_attr_string(attr));
	goto errout;
    }

    switch (attr) {
    case DW_AT_name:
	ldebug(4,"\t\t\tvalue = %s\n",str);
	if (level == 0) {
	    symtab_set_srcfilename(cbargs->cu_symtab,str);
	}
	else if (cbargs->symbol) {
	    symbol_set_name(cbargs->symbol,str);
	}
	else {
	    lwarn("attrval %s for attr %s in bad context\n",
		  str,dwarf_attr_string(attr));
	}
	break;
    case DW_AT_producer:
	ldebug(4,"\t\t\tvalue = %s\n",str);
	if (level == 0) 
	    symtab_set_producer(cbargs->cu_symtab,str);
	else 
	    lwarn("attrval %s for attr %s in bad context\n",
		  str,dwarf_attr_string(attr));
	break;
    case DW_AT_comp_dir:
	ldebug(4,"\t\t\tvalue = %s\n",str);
	if (level == 0) 
	    symtab_set_compdirname(cbargs->cu_symtab,str);
	else 
	    lwarn("attrval %s for attr %s in bad context\n",
		  str,dwarf_attr_string(attr));
	break;
    case DW_AT_language:
	ldebug(4,"\t\t\tvalue = %d\n",num);
	if (level == 0) 
	    cbargs->cu_symtab->language = num;
	else 
	    lwarn("attrval %d for attr %s in bad context\n",
		  (int)num,dwarf_attr_string(attr));
	break;
    case DW_AT_low_pc:
	ldebug(4,"\t\t\tvalue = 0x%p\n",addr);
	if (level == 0) 
	    cbargs->cu_symtab->lowpc = addr;
	else if (cbargs->symbol 
		 && cbargs->symbol->type == SYMBOL_TYPE_FUNCTION) {
	    cbargs->symbol->s.ii.d.f.lowpc = addr;
	}
	else 
	    lwarn("attrval %Lx for attr %s in bad context\n",
		  (int)addr,dwarf_attr_string(attr));
	break;
    case DW_AT_high_pc:
	ldebug(4,"\t\t\tvalue = 0x%p\n",addr);
	if (level == 0) 
	    cbargs->cu_symtab->highpc = addr;
	else if (cbargs->symbol 
		 && cbargs->symbol->type == SYMBOL_TYPE_FUNCTION) {
	    cbargs->symbol->s.ii.d.f.highpc = addr;
	}
	else 
	    lwarn("attrval %Lx for attr %s in bad context\n",
		  (int)addr,dwarf_attr_string(attr));
	break;
    case DW_AT_decl_file:
	if (cbargs->symbol) {
	    ; // XXX
	}
	else 
	    lwarn("attrval %d for attr %s in bad context\n",
		  (int)num,dwarf_attr_string(attr));
	break;
    case DW_AT_decl_line:
	if (cbargs->symbol) {
	    cbargs->symbol->srcline = (int)num;
	}
	else 
	    lwarn("attrval %d for attr %s in bad context\n",
		  (int)num,dwarf_attr_string(attr));
	break;
    case DW_AT_encoding:
	if (cbargs->symbol && cbargs->symbol->type == SYMBOL_TYPE_TYPE) {
	    cbargs->symbol->s.ti.d.v.encoding = num;
	}
	else 
	    lwarn("attrval %d for attr %s in bad context\n",
		  (int)num,dwarf_attr_string(attr));
	break;
    case DW_AT_external:
	if (cbargs->symbol && cbargs->symbol->type == SYMBOL_TYPE_FUNCTION) {
	    cbargs->symbol->s.ii.d.f.external = flag;
	}
	else 
	    lwarn("attrval %d for attr %s in bad context\n",
		  flag,dwarf_attr_string(attr));
	break;
    case DW_AT_prototyped:
	if (cbargs->symbol && cbargs->symbol->type == SYMBOL_TYPE_FUNCTION) {
	    cbargs->symbol->s.ii.d.f.prototyped = flag;
	}
	else 
	    lwarn("attrval %d for attr %s in bad context\n",
		  flag,dwarf_attr_string(attr));
	break;
    case DW_AT_type:
	if (ref_set && cbargs->symbol) {
	    struct symbol *datatype = (struct symbol *) \
		g_hash_table_lookup(cbargs->typeoffsettab,(gpointer)ref);
	    if (cbargs->symbol->type == SYMBOL_TYPE_TYPE) {
		if (cbargs->symbol->s.ti.datatype_code == DATATYPE_PTR) {
		    if (datatype)
			cbargs->symbol->s.ti.d.p.ptr_datatype = datatype;
		    else 
			cbargs->symbol->s.ti.d.p.ptr_datatype_addr_ref = \
			    (uint64_t)ref;
		}
		else if (cbargs->symbol->s.ti.datatype_code == DATATYPE_TYPEDEF) {
		    if (datatype)
			cbargs->symbol->s.ti.d.td.td_datatype = datatype;
		    else 
			cbargs->symbol->s.ti.d.td.td_datatype_addr_ref = \
			    (uint64_t)ref;
		}
		else if (cbargs->symbol->s.ti.datatype_code == DATATYPE_ARRAY) {
		    /* This is the data type for the array. */
		    if (datatype)
			cbargs->symbol->s.ti.d.a.array_datatype = datatype;
		    else
			cbargs->symbol->s.ti.d.a.array_datatype_addr_ref = \
			    (uint64_t)ref;
		}
		else if (cbargs->symbol->s.ti.datatype_code == DATATYPE_CONST) {
		    /* This is the data type for the const qualifier. */
		    if (datatype)
			cbargs->symbol->s.ti.d.cq.const_datatype = datatype;
		    else
			cbargs->symbol->s.ti.d.cq.const_datatype_addr_ref = \
			    (uint64_t)ref;
		}
		else if (cbargs->symbol->s.ti.datatype_code == DATATYPE_VOL) {
		    /* This is the data type for the volatile qualifier. */
		    if (datatype)
			cbargs->symbol->s.ti.d.vq.vol_datatype = datatype;
		    else
			cbargs->symbol->s.ti.d.vq.vol_datatype_addr_ref = \
			    (uint64_t)ref;
		}
		else 
		    lwarn("bogus: type ref for unknown type symbol\n");
	    }
	    else {
		if (datatype)
		    cbargs->symbol->datatype = datatype;
		else 
		    cbargs->symbol->datatype_addr_ref = (uint64_t)ref;
	    }
	}
	else if (ref_set && !cbargs->symbol && cbargs->parentsymbol 
		 && cbargs->parentsymbol->type == SYMBOL_TYPE_TYPE 
		 && cbargs->parentsymbol->s.ti.datatype_code == DATATYPE_ARRAY) {
	    /* If the parent was an array_type, don't worry about typing its
	     * array subranges.
	     */
	    ;
	}
	else 
	    lwarn("attrval %Lx for attr %s in bad context\n",
		  (uint64_t)ref,dwarf_attr_string(attr));
	break;
    case DW_AT_const_value:
	if (num_set
	    && cbargs->symbol 
	    && cbargs->symbol->type == SYMBOL_TYPE_VAR
	    && cbargs->parentsymbol
	    && cbargs->parentsymbol->type == SYMBOL_TYPE_TYPE
	    && cbargs->parentsymbol->s.ti.datatype_code == DATATYPE_ENUM
	    && cbargs->parentsymbol->s.ti.byte_size > 0) {
	    // XXX we just use a 64-bit int and hope it doesn't
	    // overflow; the alternative is to malloc a chunk of mem
	    // once we know how many enumerators there are!
	    cbargs->symbol->s.ii.d.constval = \
		malloc(cbargs->parentsymbol->s.ti.byte_size);
	    memcpy(cbargs->symbol->s.ii.d.constval,&num,
		   cbargs->parentsymbol->s.ti.byte_size);
	    cbargs->symbol->s.ii.isenumval = 1;
	}
	else 
	    lwarn("attrval %Lx for attr %s in bad context\n",
		  (uint64_t)num,dwarf_attr_string(attr));
	break;
    case DW_AT_byte_size:
	if (num_set 
	    && cbargs->symbol && cbargs->symbol->type == SYMBOL_TYPE_TYPE) {
	    cbargs->symbol->s.ti.byte_size = num;
	}
	else if (num_set 
		 && cbargs->symbol && cbargs->symbol->type == SYMBOL_TYPE_VAR) {
	    cbargs->symbol->s.ii.d.v.byte_size = num;
	}
	else 
	    lwarn("attrval %d for attr %s in bad context\n",
		  (int)num,dwarf_attr_string(attr));
	break;
    case DW_AT_bit_size:
	if (num_set 
	    && cbargs->symbol && cbargs->symbol->type == SYMBOL_TYPE_VAR) {
	    cbargs->symbol->s.ii.d.v.bit_size = num;
	}
	else 
	    lwarn("attrval %d for attr %s in bad context\n",
		  (int)num,dwarf_attr_string(attr));
	break;
    case DW_AT_bit_offset:
	if (num_set 
	    && cbargs->symbol && cbargs->symbol->type == SYMBOL_TYPE_VAR) {
	    cbargs->symbol->s.ii.d.v.bit_offset = num;
	}
	else 
	    lwarn("attrval %d for attr %s in bad context\n",
		  (int)num,dwarf_attr_string(attr));
	break;
    case DW_AT_sibling:
	/* we process all DIEs, so no need to skip any child content. */
	break;
    case DW_AT_data_member_location:
	/* can be either a constant or a loclist */
	if (num_set && form != DW_FORM_sec_offset
	    && (cbargs->version >= 4
		|| (form != DW_FORM_data4 
		    && form != DW_FORM_data8))) {
	    /* it's a constant */
	    if (cbargs->symbol) {
		cbargs->symbol->s.ii.l.loctype = LOCTYPE_MEMBER_OFFSET;
		cbargs->symbol->s.ii.l.l.member_offset = (int32_t)num;
	    }
	    else {
		lwarn("attrval %Lx for attr %s in bad context\n",
		      (uint64_t)num,dwarf_attr_string(attr));
	    }
	    break;
	}
	/* else fall through to loclist, then block if necessary */
    case DW_AT_location:
    //case DW_AT_data_member_location:
    case DW_AT_frame_base:
	/* if it's a loclist */
	if (num_set) {
	    lwarn("unrecognized loclist for attr %s // form %s mix!\n",
		  dwarf_attr_string(attr),dwarf_form_string(form));
	    break;
	}
    /* else fall through to a block op */
    /* well, not so fast -- let's flip through subrange stuff too! */
    //case DW_AT_count:
    case DW_AT_lower_bound:
	if (num_set && num) {
	    lwarn("we only support lower_bound attrs of 0 (%d)!\n",num);
	    break;
	}
    case DW_AT_upper_bound:
	/* it's a constant, not a block op */
	if (num_set) {
	    if (!cbargs->symbol && cbargs->parentsymbol
		&& cbargs->parentsymbol->type == SYMBOL_TYPE_TYPE
		&& cbargs->parentsymbol->s.ti.datatype_code == DATATYPE_ARRAY) {
		if (cbargs->parentsymbol->s.ti.d.a.count == \
		    cbargs->parentsymbol->s.ti.d.a.alloc) {
		    if (!realloc(cbargs->parentsymbol->s.ti.d.a.subranges,
				 sizeof(int)*(cbargs->parentsymbol->s.ti.d.a.alloc + 4))) {
			lerror("realloc: %s",strerror(errno));
			return DWARF_CB_ABORT;
		    }
		    cbargs->parentsymbol->s.ti.d.a.alloc += 4;
		}

		cbargs->parentsymbol->s.ti.d.a.subranges[cbargs->parentsymbol->s.ti.d.a.count] = (int)num;
		++cbargs->parentsymbol->s.ti.d.a.count;
	    }
	    else {
		lwarn("attrval %Lx for attr %s in bad context\n",
		      (uint64_t)num,dwarf_attr_string(attr));
	    }
	    break;
	}
    /* now fall through to the block op */
    /* bit_size and bit_offset should probably always be consts! */
    //case DW_AT_bit_size:
    //case DW_AT_bit_offset:
	/* these all need ops evaluated! */
	if (block_set) {
	    get_static_ops(cbargs->dwflmod,cbargs->dbg,
			   cbargs->version,cbargs->addrsize,cbargs->offset_size,
			   block.length,block.data,attr,
			   &cbargs->symbol->s.ii.l);
	    break;
	}
	else {
	    lwarn("unrecognized location attr %s // form %s mix!\n",
		  dwarf_attr_string(attr),dwarf_form_string(form));
	    //goto errout;
	    break;
	}
    default:
	lwarn("unrecognized attr %s\n",dwarf_attr_string(attr));
	//goto errout;
	break;
    }

    goto out;

 errout:
    return DWARF_CB_ABORT;
 out:
    return 0;
}


/*
 * This originally came from readelf.c, but I rewrote much of it.  Some
 * operations can be evaluated statically to produce a fixed location
 * that never changes, except for a simple offset.  Others actually need
 * runtime information.  So, we evaluate everything that is simple to
 * do, and punt the rest for runtime evaluation against actual machine
 * data.
 */
int get_static_ops(Dwfl_Module *dwflmod,Dwarf *dbg,unsigned int vers,
		   unsigned int addrsize,unsigned int offset_size,
		   Dwarf_Word len,const unsigned char *data,
		   unsigned int attr,struct location *retval) {

    const unsigned int ref_size = vers < 3 ? addrsize : offset_size;

    /* XXX: we can't get other_byte_order from dbg since we don't have
     * the struct def for it... so we assume it's not a diff byte order
     * than the phys host for now.
     */
    int obo = 0;

    /* save the originals for later for runtime computation if we need */
    const unsigned char *origdata = data;
    Dwarf_Word origlen = len;

    static const char *const known[] = {
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
	[DW_OP_implicit_value] = "implicit_value",
	[DW_OP_stack_value] = "stack_value",
	[DW_OP_GNU_implicit_pointer] = "GNU_implicit_pointer",
    };

    if (len == 0) {
	lwarn("empty dwarf block num!\n");
	goto errout;
    }

#define NEED(n)		if (len < (Dwarf_Word) (n)) goto errout
#define CONSUME(n)	NEED (n); else len -= (n)

/* If this is the only thing in this op list, be done now. */
#define ONLYOP(location,type,field,value) \
    if (start == (origdata + 1) && len == 0) {	\
	location->loctype = (type);	  \
	location->l.field = (value);	  \
	goto out;			  \
    }					  \
    else {				  \
	lwarn("unsupported %s op with other ops!\n",known[op]); \
    }

#define OPCONSTU(size,tt)			\
    NEED(size);						\
    u64 = (uint64_t)*((tt *)data);			\
    data += size;					\
    CONSUME(size);					\
    ldebug(9,"%s -> 0x%" PRIuMAX "\n",known[op],u64);	\
    if (attr == DW_AT_data_member_location) {		\
	ONLYOP(retval,LOCTYPE_MEMBER_OFFSET,		\
	       member_offset,(int32_t)u64);		\
    }							\
    else {					       	\
	lwarn("assuming constXu is for loctype_addr!\n");	\
	ONLYOP(retval,LOCTYPE_ADDR,addr,u64);		\
    }

#define OPCONSTS(size,tt)			\
    NEED(size);						\
    s64 = (int64_t)*((tt *)data);			\
    data += size;					\
    CONSUME(size);					\
    ldebug(9,"%s -> 0x%" PRIxMAX "\n",known[op],s64);	\
    if (attr == DW_AT_data_member_location) {		\
	ONLYOP(retval,LOCTYPE_MEMBER_OFFSET,		\
	       member_offset,(int32_t)s64);		\
    }							\
    else {					       	\
	lwarn("assuming constXs is for loctype_addr!\n");	\
	ONLYOP(retval,LOCTYPE_ADDR,addr,(uint64_t)s64);		\
    }

    while (len-- > 0) {
	uint_fast8_t op = *data++;
	const unsigned char *start = data;

	ldebug(9,"%s with len = %d\n",known[op],len);

	Dwarf_Word addr;
	uint8_t reg;
	uint64_t u64;
	int64_t s64;

	switch (op) {
	case DW_OP_addr:
	    NEED(addrsize);
	    if (addrsize == 4)
		addr = read_4ubyte_unaligned(obo,data);
	    else {
		assert(addrsize == 8);
		addr = read_8ubyte_unaligned(obo,data);
	    }
	    data += addrsize;
	    CONSUME(addrsize);
	    ldebug(9,"%s -> 0x%" PRIx64 "\n",known[op],addr);
	    ONLYOP(retval,LOCTYPE_ADDR,addr,addr);
	    break;

	case DW_OP_reg0...DW_OP_reg31:
	    NEED(1);
	    reg = *((uint8_t *)data) - (uint8_t)DW_OP_reg0;
	    data += 1;
	    CONSUME(1);

	    ldebug(9,"%s -> 0x%" PRIu8 "\n",known[op],reg);
	    ONLYOP(retval,LOCTYPE_REG,reg,reg);
	    break;
	//case DW_OP_piece:
	case DW_OP_regx:
	    NEED(1);
	    get_uleb128(u64,data); /* XXX check overrun */
	    CONSUME(data - start);
	    ldebug(9,"%s -> 0x%" PRIuMAX "\n",known[op],u64);
	    ONLYOP(retval,LOCTYPE_REG,reg,(uint8_t)u64);
	    break;

	case DW_OP_plus_uconst:
	case DW_OP_constu:
	    NEED(1);
	    get_uleb128(u64,data); /* XXX check overrun */
	    CONSUME(data - start);
	    ldebug(9,"%s -> 0x%" PRIuMAX "\n",known[op],u64);
	    if (attr == DW_AT_data_member_location) {
		ONLYOP(retval,LOCTYPE_MEMBER_OFFSET,
		       member_offset,(int32_t)u64);
	    }
	    else {
		lwarn("assuming uconst/constu is for loctype_addr!\n");
		ONLYOP(retval,LOCTYPE_ADDR,
		       addr,(uint64_t)u64);
	    }
	    break;
	case DW_OP_consts:
	    NEED(1);
	    get_sleb128(s64,data); /* XXX check overrun */
	    CONSUME(data - start);
	    ldebug(9,"%s -> 0x%" PRIxMAX "\n",known[op],s64);
	    if (attr == DW_AT_data_member_location) {
		ONLYOP(retval,LOCTYPE_MEMBER_OFFSET,
		       member_offset,(int32_t)s64);
	    }
	    else {
		lwarn("assuming consts is for loctype_addr!\n");
		ONLYOP(retval,LOCTYPE_ADDR,
		       addr,(uint64_t)s64);
	    }
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
	/*
	case DW_OP_bit_piece:
	  start = data;
	  uint64_t uleb2;
	  NEED (2);
	  get_uleb128 (uleb, data); // XXX check overrun
	  get_uleb128 (uleb2, data); // XXX check overrun 
	  //printf ("%*s[%4" PRIuMAX "] %s %" PRIu64 ", %" PRIu64 "\n",
	  //indent, "", (uintmax_t) offset, known[op], uleb, uleb2);
	  CONSUME (data - start);
	  break;
	*/
	case DW_OP_fbreg:
	  NEED(1);
	  get_sleb128(s64,data); /* XXX check overrun */
	  CONSUME(data - start);
	  ldebug(9,"%s -> fbreg offset %ld\n",known[op],s64);
	  ONLYOP(retval,LOCTYPE_FBREG_OFFSET,fboffset,s64);
	  break;
	case DW_OP_breg0 ... DW_OP_breg31:
	    NEED(1);
	    get_sleb128(s64,data); /* XXX check overrun */
	    CONSUME(data - start);
	    ldebug(9,"%s -> reg (%d) offset %ld\n",known[op],
		   (uint8_t)(op - DW_OP_breg0),s64);
	    ONLYOP(retval,LOCTYPE_REG_OFFSET,regoffset.reg,
		   (uint8_t)(op - DW_OP_breg0));
	    retval->l.regoffset.offset = s64;
	  break;
	case DW_OP_bregx:
	    NEED(2);
	    get_uleb128(u64,data); /* XXX check overrun */
	    get_sleb128(s64,data); /* XXX check overrun */
	    CONSUME(data - start);
	    ldebug(9,"%s -> reg%" PRId8 ", offset %ld\n",known[op],
		   (uint8_t)reg,s64);
	    ONLYOP(retval,LOCTYPE_REG_OFFSET,regoffset.reg,(uint8_t)u64);
	    retval->l.regoffset.offset = s64;
	    break;
	default:
	  /* No Operand.  */
	  if (op < sizeof known / sizeof known[0] && known[op] != NULL)
	      ; /*printf ("%*s[%4" PRIuMAX "] %s\n",
		indent, "", (uintmax_t) offset, known[op]);*/
	  else
	      ; /*printf ("%*s[%4" PRIuMAX "] %#x\n",
		indent, "", (uintmax_t) offset, op);*/
	  break;
	}

	continue;

    invalid:
	;
	/*printf (gettext ("%*s[%4" PRIuMAX "] %s  <TRUNCATED>\n"),
	  indent, "", (uintmax_t) offset, known[op]);*/
	break;
    }

 runtimeout:
    lwarn("had to save dwarf ops for runtime!\n");
    retval->loctype = LOCTYPE_RUNTIME;
    retval->l.runtime.data = malloc(origlen);
    memcpy(retval->l.runtime.data,origdata,origlen);

 out:
    return 0;

 errout:
    return -1;
}

/* Used in fill_debuginfo; defined right afer it for ease of
 * understanding the code.
 */
int finalize_die_symbol(struct debugfile *debugfile,int level,
			struct symbol *symbol,
			struct symbol *parentsymbol,
			struct symbol *voidsymbol);
void resolve_type_refs(gpointer key,gpointer value,gpointer data);

struct symbol *add_void_symbol(struct debugfile *debugfile,
			       struct symtab *symtab) {
    /* must malloc it so it can be freed safely */
    char *vstr = malloc(5);
    memcpy(vstr,"void",5);
    struct symbol *symbol = symbol_create(symtab,vstr,SYMBOL_TYPE_TYPE);
    symbol->s.ti.datatype_code = DATATYPE_VOID;

    /* Always put it in its primary symtab, of course -- probably the CU's. */
    symbol_insert(symbol);

    /* And also always put it in the debugfile's global types table. */
    debugfile_add_type(debugfile,symbol);

    return symbol;
}

static int fill_debuginfo(struct debugfile *debugfile,
			  Dwfl_Module *dwflmod,Ebl *ebl,GElf_Ehdr *ehdr,
			  Elf_Scn *scn,GElf_Shdr *shdr,Dwarf *dbg) {
    int rc;
    int retval = 0;

    if (shdr->sh_size == 0) {
	ldebug(2,"section empty, which is fine!\n");
	return 0;
    }

    ldebug(1,"starting on %s \n",debugfile->filename);

    int maxdies = 8;
    int level;
    Dwarf_Die *dies = (Dwarf_Die *)malloc(maxdies*sizeof(Dwarf_Die));
    Dwarf_Off offset = 0;

    /* New compilation unit.  */
    size_t cuhl;
    Dwarf_Off abbroffset;
    uint8_t addrsize;
    uint8_t offsize;
    Dwarf_Off nextcu;
    Dwarf_Half version;

    struct symtab *cu_symtab;
    struct symtab *symtab;
    struct symbol *symbol;
    struct symbol **symbols = (struct symbol **)malloc(maxdies*sizeof(struct symbol *));

    GHashTable *typeoffsettab = g_hash_table_new(g_direct_hash,g_direct_equal);
    struct symbol *voidsymbol;

 next_cu:
    if ((rc = dwarf_next_unit(dbg,offset,&nextcu,&cuhl,&version,
			      &abbroffset,&addrsize,&offsize,NULL,NULL)) < 0) {
	lerror("dwarf_next_unit: %s (%d)\n",dwarf_errmsg(dwarf_errno()),rc);
	goto errout;
    }
    else if (rc > 0) {
	ldebug(2,"dwarf_next_unit returned (%d), aborting successfully.\n",rc);
	goto out;
    }

    /*
     * Clean up our temp types offset table; it contains per-CU offsets
     * that map to types we've built.  We need this in case one type
     * symbol references a type that has not yet appeared in the debug info.
     */
    g_hash_table_remove_all(typeoffsettab);

    /* attr_callback has to fill this, and *MUST* fill at least
     * srcfilename; otherwise we can't add the symtab to our hash table.
     */
    cu_symtab = symtab_create(debugfile,NULL,NULL,0,NULL,0,0);
    int cu_symtab_added = 0;

    /* Add the void symbol, always. */
    voidsymbol = add_void_symbol(debugfile,cu_symtab);

    struct attrcb_args args = {
	.dwflmod = dwflmod,
	.dbg = dbg,
	.addrsize = addrsize,
	.offset_size = offsize,
	.cu_offset = offset,
	.version = version,

	.debugfile = debugfile,
	.cu_symtab = cu_symtab,
	.symtab = NULL,
	.symbol = NULL,
	.parentsymbol = NULL,
	.voidsymbol = voidsymbol,
	.typeoffsettab = typeoffsettab,
    };

    offset += cuhl;
    level = 0;

    if (dwarf_offdie(dbg,offset,&dies[level]) == NULL) {
	lerror("cannot get DIE at offset %Lx: %s\n",
	       (uint64_t)offset,dwarf_errmsg(-1));
	goto errout;
    }

    do {
	/* The first time we are not level 0 (i.e., at the CU's DIE),
	 * check that we found a src filename attr; we must have it to
	 * hash the symtab.
	 */
	if (level > 0 && !cu_symtab_added) {
	    if (!cu_symtab->srcfilename) {
		lerror("CU did not have a src filename; aborting processing!\n");
		symtab_free(cu_symtab);
		goto next_cu;
	    }
	    else {
		debugfile_add_symtab(debugfile,cu_symtab);
		cu_symtab_added = 1;
	    }
	}

	offset = dwarf_dieoffset(&dies[level]);
	if (offset == ~0ul) {
	    lerror("cannot get DIE offset: %s",dwarf_errmsg(-1));
	    goto errout;
	}

	int tag = dwarf_tag(&dies[level]);
	if (tag == DW_TAG_invalid) {
	    lerror("cannot get tag of DIE at offset %Lx: %s\n",
		   (uint64_t)offset,dwarf_errmsg(-1));
	    goto errout;
	}

	ldebug(4," [%6Lx] %d %s\n",(uint64_t)offset,(int)level,
	       dwarf_tag_string(tag));

	/* XXX if we ever support per-function symtabs, we have
	 * to fix this!
	 */
	symtab = cu_symtab;

	/* Figure out what type of symbol (or symtab?) to create! */
	if (tag == DW_TAG_variable
	    || tag == DW_TAG_formal_parameter
	    || tag == DW_TAG_member
	    || tag == DW_TAG_enumerator) {
	    symbols[level] = symbol_create(symtab,NULL,SYMBOL_TYPE_VAR);
	    if (tag == DW_TAG_formal_parameter) {
		symbols[level]->s.ii.isparam = 1;
	    }
	}
	else if (tag == DW_TAG_base_type
		 || tag == DW_TAG_typedef
		 || tag == DW_TAG_pointer_type
		 || tag == DW_TAG_array_type
		 || tag == DW_TAG_structure_type
		 || tag == DW_TAG_enumeration_type
		 || tag == DW_TAG_union_type
		 || tag == DW_TAG_const_type
		 || tag == DW_TAG_volatile_type) {
	    symbols[level] = symbol_create(symtab,NULL,SYMBOL_TYPE_TYPE);
	    switch (tag) {
	    case DW_TAG_base_type:
		symbols[level]->s.ti.datatype_code = DATATYPE_BASE; break;
	    case DW_TAG_typedef:
		symbols[level]->s.ti.datatype_code = DATATYPE_TYPEDEF; break;
	    case DW_TAG_pointer_type:
		symbols[level]->s.ti.datatype_code = DATATYPE_PTR; break;
	    case DW_TAG_array_type:
		symbols[level]->s.ti.datatype_code = DATATYPE_ARRAY;
		symbols[level]->s.ti.d.a.subranges = malloc(sizeof(int)*4);
		symbols[level]->s.ti.d.a.count = 0;
		symbols[level]->s.ti.d.a.alloc = 4;
		break;
	    case DW_TAG_structure_type:
		symbols[level]->s.ti.datatype_code = DATATYPE_STRUCT;
		INIT_LIST_HEAD(&(symbols[level]->s.ti.d.su.members));
		break;
	    case DW_TAG_enumeration_type:
		symbols[level]->s.ti.datatype_code = DATATYPE_ENUM; 
		INIT_LIST_HEAD(&(symbols[level]->s.ti.d.e.members));
		break;
	    case DW_TAG_union_type:
		symbols[level]->s.ti.datatype_code = DATATYPE_UNION;
		INIT_LIST_HEAD(&(symbols[level]->s.ti.d.su.members));
		break;
	    case DW_TAG_const_type:
		symbols[level]->s.ti.datatype_code = DATATYPE_CONST; break;
	    case DW_TAG_volatile_type:
		symbols[level]->s.ti.datatype_code = DATATYPE_VOL; break;
	    //case DW_TAG_:
		//symbols[level]->s.ti.t.datatype_code = DATATYPE_; break;
	    default:
		break;
	    }
	}
	else if (tag == DW_TAG_subrange_type) {
	    /* We cheat and don't actually type subranges... we're C
	     * hackers, after all :).
	    */
	    
	}
	else if (tag == DW_TAG_subprogram) {
	    symbols[level] = symbol_create(symtab,NULL,SYMBOL_TYPE_FUNCTION);
	    INIT_LIST_HEAD(&(symbols[level]->s.ii.d.f.args));
	}
	else {
	    if (tag != DW_TAG_compile_unit)
		lwarn("unknown dwarf tag %s!\n",dwarf_tag_string(tag));
	    symbols[level] = NULL;
	}

	/* Get the attribute values.  */
	args.level = level;
	if (level > 1)
	    args.parentsymbol = symbols[level-1];
	else
	    args.parentsymbol = NULL;
	args.symbol = symbols[level];
	(void)dwarf_getattrs(&dies[level],attr_callback,&args,0);

	/* Make room for the next level's DIE.  */
	if (level + 1 == maxdies) {
	    dies = (Dwarf_Die *)realloc(dies,(maxdies += 8)*sizeof(Dwarf_Die));
	    symbols = (struct symbol **)realloc(symbols,maxdies*sizeof(struct symbol *));
	}

	if (symbols[level] && symbols[level]->type == SYMBOL_TYPE_TYPE) {
	    if (!symbols[level]->name) {
		/*
		 * Fixup for GCC bugs, and for handling cases where a
		 * type actually is an anonymous type.
		 */
		char *newname = malloc(17+5);
		snprintf(newname,17,"anon:%Lx",(uint64_t)offset);
		    //symbols[level]->s.ti.byte_size,
		    //symbols[level]->s.ti.d.v.encoding);
		ldebug(5,"unnamed/anonymous type! renamed to %s.\n",newname);
		symbol_set_name(symbols[level],newname);
		/* We don't want anonymous type symbols in the real
		 * symbol tables!
		*/
		symbols[level]->s.ti.isanon = 1;
	    }
	    /*
	     * Add to this CU's temp type offset table.
	     */
	    g_hash_table_insert(typeoffsettab,(gpointer)offset,symbols[level]);
	}

	/* Handle adding child symbols to parents!
	 */
	if (level > 1 && symbols[level-1]) {
	    if (tag == DW_TAG_member) {
		list_add_tail(&(symbols[level]->member),
			      &(symbols[level-1]->s.ti.d.su.members));
		++(symbols[level-1]->s.ti.d.su.count);
	    }
	    else if (tag == DW_TAG_formal_parameter) {
		list_add_tail(&(symbols[level]->member),
			      &(symbols[level-1]->s.ii.d.f.args));
		++(symbols[level-1]->s.ii.d.f.count);
	    }
	    else if (tag == DW_TAG_enumerator) {
		if (symbols[level-1]->type == SYMBOL_TYPE_TYPE 
		    && symbols[level-1]->s.ti.datatype_code == DATATYPE_ENUM) {
		    symbols[level]->datatype = symbols[level-1];
		    list_add_tail(&(symbols[level]->member),
				  &(symbols[level-1]->s.ti.d.e.members));
		    ++(symbols[level-1]->s.ti.d.e.count);
		}
		else
		    lerror("invalid parent for enumerator %s!\n",
			   symbols[level]->name);
	    }
	    else {
		// XXX maybe array types too?  what else can have
		// children?
	    }
	}

	int res = dwarf_child(&dies[level],&dies[level + 1]);
	if (res > 0) {
	    /* No new child, but possibly a new sibling, so finalize the
	     * current sibling if it exists!
	     */
	    if (symbols[level]) {
		finalize_die_symbol(debugfile,level,symbols[level],
				    symbols[level-1],voidsymbol);
		symbols[level] = NULL;
	    }

	    while ((res = dwarf_siblingof(&dies[level],&dies[level])) == 1) {

		if (level-- == 0)
		    break;

		/* Now that a DIE's children have all been parsed, and
		 * we're leveling up, finalize the "parent" DIE's symbol.
		 */
		if (symbols[level]) {
		    finalize_die_symbol(debugfile,level,symbols[level],
					symbols[level-1],voidsymbol);
		    symbols[level] = NULL;
		}
	    }

	    if (res == -1) {
		lerror("cannot get next DIE: %s\n",dwarf_errmsg(-1));
		goto errout;
	    }
	}
	else if (res < 0) {
	    lerror("cannot get next DIE: %s",dwarf_errmsg(-1));
	    goto errout;
	}
	else {
	    /* New child */
	    ++level;
	    symbols[level] = NULL;
	}
    }
    while (level >= 0);

    /*
     * Since we may not have been able to resolve all the dwarf type refs for
     * our symbols during our single pass (since a type can follow its
     * use in dwarf debug info), we have to postpass all the symbols :(.
     *
     * The only other alternative is to use libelf/libdw to resolve them
     * during the single pass, which seems less good...
     */
    g_hash_table_foreach(cu_symtab->tab,resolve_type_refs,typeoffsettab);

    offset = nextcu;
    if (offset != 0) {
	goto next_cu;
    }

    goto out;

 errout:
    if (dies)
	free(dies);
    return -1;
 out:
    if (dies)
	free(dies);
    return retval;
}

/*
 * Returns 0 if the symbol was successfully inserted into symbol tables, 
 * and 1 if not (which may not be an error).
 */
int finalize_die_symbol(struct debugfile *debugfile,int level,
			struct symbol *symbol,
			struct symbol *parentsymbol,
			struct symbol *voidsymbol) {
    int retval = 0;

    if (!symbol) {
	lwarn("null symbol!\n");
	return -1;
    }

    if (symbol->type == SYMBOL_TYPE_TYPE
	&& symbol->s.ti.isanon) {
	/* Don't free it, but also don't insert it into symbol
	 * tables.
	 */
	if (symbol->s.ti.datatype_code == DATATYPE_PTR
	    && symbol->s.ti.d.p.ptr_datatype == NULL
	    && symbol->s.ti.d.p.ptr_datatype_addr_ref == 0) {
	    ldebug(3,"assuming anon ptr type %s without type is void\n",
		   symbol->name);
	    symbol->s.ti.d.p.ptr_datatype = voidsymbol;
	}

	retval = 1;
    }
    else if (symbol->name) {
	symbol_insert(symbol);

	if (symbol->type == SYMBOL_TYPE_TYPE) {
	    /* If it's a valid symbol, but doesn't have a type, make it
	     * void!
	     */
	    if (symbol->s.ti.datatype_code == DATATYPE_PTR
		&& symbol->s.ti.d.p.ptr_datatype == NULL
		&& symbol->s.ti.d.p.ptr_datatype_addr_ref == 0) {
		ldebug(3,"assuming ptr type %s without type is void\n",
		       symbol->name);
		symbol->s.ti.d.p.ptr_datatype = voidsymbol;
	    }
	    else if (symbol->s.ti.datatype_code == DATATYPE_TYPEDEF
		     && symbol->s.ti.d.td.td_datatype == NULL
		     && symbol->s.ti.d.td.td_datatype_addr_ref == 0) {
		ldebug(3,"assuming typedef type %s without type is void\n",
		       symbol->name);
		symbol->s.ti.d.td.td_datatype = voidsymbol;
	    }
	    else if (symbol->s.ti.datatype_code == DATATYPE_ARRAY) {
		/* Reduce the allocation to exactly the length we used! */
		if (symbol->s.ti.d.a.alloc > symbol->s.ti.d.a.count)
		    realloc(symbol->s.ti.d.a.subranges,
			    sizeof(int)*symbol->s.ti.d.a.count);
	    }
	    /* Not sure if C lets these two cases through, but whatever */
	    else if (symbol->s.ti.datatype_code == DATATYPE_CONST
		     && symbol->s.ti.d.cq.const_datatype == NULL
		     && symbol->s.ti.d.cq.const_datatype_addr_ref == 0) {
		ldebug(3,"assuming const type %s without type is void\n",
		       symbol->name);
		symbol->s.ti.d.cq.const_datatype = voidsymbol;
	    }
	    else if (symbol->s.ti.datatype_code == DATATYPE_VOL
		     && symbol->s.ti.d.vq.vol_datatype == NULL
		     && symbol->s.ti.d.vq.vol_datatype_addr_ref == 0) {
		ldebug(3,"assuming volatile type %s without type is void\n",
		       symbol->name);
		symbol->s.ti.d.vq.vol_datatype = voidsymbol;
	    }

	    if (!debugfile_find_type(debugfile,symbol->name))
		debugfile_add_type(debugfile,symbol);
	}
	else if (symbol->type == SYMBOL_TYPE_FUNCTION) {
	    if (symbol->datatype == NULL
		&& symbol->datatype_addr_ref == 0) {
		ldebug(3,"assuming function %s without type is void\n",
		       symbol->name);
		symbol->datatype = voidsymbol;
	    }

	    if (symbol->s.ii.d.f.external) 
		debugfile_add_global(debugfile,symbol);
	}
	else if (symbol->type == SYMBOL_TYPE_VAR) {
	    if (symbol->datatype == NULL
		&& symbol->datatype_addr_ref == 0) {
		ldebug(3,"assuming var %s without type is void\n",
		       symbol->name);
		symbol->datatype = voidsymbol;
	    }

	    if (level == 1)
		debugfile_add_global(debugfile,symbol);
	}
    }
    else if (symbol) {
	lerror("non-anonymous symbol of type %s without a name!\n",
	       SYMBOL_TYPE(symbol->type));
	symbol_free(symbol);
	retval = 1;
    }
    else {
	lwarn("null symbol!\n");
    }

    return retval;
}

void resolve_type_refs(gpointer key,gpointer value,gpointer data) {
    struct symbol *symbol = (struct symbol *)value;
    GHashTable *typeoffsettab = (GHashTable *)data;
    struct symbol *member;

    if (symbol->type == SYMBOL_TYPE_TYPE) {
	if (symbol->s.ti.datatype_code == DATATYPE_PTR) {
	    if (!symbol->s.ti.d.p.ptr_datatype) {
		symbol->s.ti.d.p.ptr_datatype =		\
		    g_hash_table_lookup(typeoffsettab,
					(gpointer)symbol->s.ti.d.p.ptr_datatype_addr_ref);
		if (!symbol->s.ti.d.p.ptr_datatype) 
		    lerror("could not resolve ref %Lx for ptr type symbol %s\n",
			   symbol->s.ti.d.p.ptr_datatype_addr_ref,symbol->name);
		else {
		    ldebug(3,"resolved ptr type symbol %s ptref 0x%x\n",
			   symbol->name,symbol->s.ti.d.p.ptr_datatype_addr_ref);

		    /* If it's a pointer, always recurse */
		    if (SYMBOL_IST_PTR(symbol->datatype))
			resolve_type_refs(NULL,symbol->datatype,typeoffsettab);
		}
	    }
	    else if (SYMBOL_IST_PTR(symbol->s.ti.d.p.ptr_datatype)) {
		/* Even if we resolved *this* pointer, anon pointers
		 * further down the pointer chain may not have been
		 * resolved!
		 */
		ldebug(3,"rresolving known ptr type symbol %s ptref 0x%x\n",
		       symbol->s.ti.d.p.ptr_datatype->name,
		       symbol->s.ti.d.p.ptr_datatype->s.ti.d.p.ptr_datatype_addr_ref);

		resolve_type_refs(NULL,symbol->s.ti.d.p.ptr_datatype,data);
	    }
	}
	else if (symbol->s.ti.datatype_code == DATATYPE_TYPEDEF 
		 && !symbol->s.ti.d.td.td_datatype) {
	    symbol->s.ti.d.td.td_datatype = \
		g_hash_table_lookup(typeoffsettab,
				    (gpointer)symbol->s.ti.d.td.td_datatype_addr_ref);
	    if (!symbol->s.ti.d.td.td_datatype) 
		lerror("could not resolve ref %Lx for typedef type symbol %s\n",
		       symbol->s.ti.d.td.td_datatype_addr_ref,symbol->name);
	    else {
		ldebug(3,"resolved typedef type symbol %s tdtref 0x%x\n",
		       symbol->name,symbol->s.ti.d.p.ptr_datatype_addr_ref);

		/* If it's a pointer, always recurse */
		if (SYMBOL_IST_PTR(symbol->datatype))
		    resolve_type_refs(NULL,symbol->datatype,typeoffsettab);
	    }
	}
	else if (symbol->s.ti.datatype_code == DATATYPE_ARRAY 
		 && !symbol->s.ti.d.a.array_datatype) {
	    symbol->s.ti.d.a.array_datatype = \
		g_hash_table_lookup(typeoffsettab,
				    (gpointer)symbol->s.ti.d.a.array_datatype_addr_ref);
	    if (!symbol->s.ti.d.a.array_datatype) 
		lerror("could not resolve ref %Lx for array type symbol %s\n",
		       symbol->s.ti.d.a.array_datatype_addr_ref,symbol->name);
	    else {
		ldebug(3,"resolved array type symbol %s atref 0x%x\n",
		       symbol->name,symbol->s.ti.d.p.ptr_datatype_addr_ref);

		/* If it's a pointer, always recurse */
		if (SYMBOL_IST_PTR(symbol->datatype))
		    resolve_type_refs(NULL,symbol->datatype,typeoffsettab);
	    }
	}
	else if (symbol->s.ti.datatype_code == DATATYPE_CONST 
		 && !symbol->s.ti.d.cq.const_datatype) {
	    symbol->s.ti.d.cq.const_datatype = \
		g_hash_table_lookup(typeoffsettab,
				    (gpointer)symbol->s.ti.d.cq.const_datatype_addr_ref);
	    if (!symbol->s.ti.d.cq.const_datatype) 
		lerror("could not resolve ref %Lx for const type symbol %s\n",
		       symbol->s.ti.d.cq.const_datatype_addr_ref,symbol->name);
	    else {
		ldebug(3,"resolved const type symbol %s ctref 0x%x\n",
		       symbol->name,symbol->s.ti.d.p.ptr_datatype_addr_ref);

		/* If it's a pointer, always recurse */
		if (SYMBOL_IST_PTR(symbol->datatype))
		    resolve_type_refs(NULL,symbol->datatype,typeoffsettab);
	    }
	}
	else if (symbol->s.ti.datatype_code == DATATYPE_VOL 
		 && !symbol->s.ti.d.vq.vol_datatype) {
	    symbol->s.ti.d.vq.vol_datatype = \
		g_hash_table_lookup(typeoffsettab,
				    (gpointer)symbol->s.ti.d.vq.vol_datatype_addr_ref);
	    if (!symbol->s.ti.d.vq.vol_datatype) 
		lerror("could not resolve ref %Lx for volatile type symbol %s\n",
		       symbol->s.ti.d.vq.vol_datatype_addr_ref,symbol->name);
	    else {
		ldebug(3,"resolved volatile type symbol %s ctref 0x%x\n",
		       symbol->name,symbol->s.ti.d.p.ptr_datatype_addr_ref);

		/* If it's a pointer, always recurse */
		if (SYMBOL_IST_PTR(symbol->datatype))
		    resolve_type_refs(NULL,symbol->datatype,typeoffsettab);
	    }
	}
	else if (symbol->s.ti.datatype_code == DATATYPE_STRUCT
		 || symbol->s.ti.datatype_code == DATATYPE_UNION) 
	    /* do it for the struct members! */
	    list_for_each_entry(member,&(symbol->s.ti.d.su.members),member) {
		if (!member->datatype) {
		    ldebug(3,"resolving s/u %s arg %s tref 0x%x\n",
			   symbol->name,member->name,member->datatype_addr_ref);
		    resolve_type_refs(NULL,member,typeoffsettab);
		}
	    }
    }
    else {
	/* do it for the variable or function's main type */
	if (!symbol->datatype) {
	    if (!(symbol->datatype = \
		  g_hash_table_lookup(typeoffsettab,
				      (gpointer)symbol->datatype_addr_ref)))
		lerror("could not resolve ref %Lx for var/func symbol %s\n",
		       symbol->datatype_addr_ref,symbol->name);
	    else {
		ldebug(3,"resolved non-type symbol %s tref 0x%x\n",
		       symbol->name,symbol->datatype_addr_ref);

		/* If it's a pointer, always recurse */
		if (SYMBOL_IST_PTR(symbol->datatype))
		    resolve_type_refs(NULL,symbol->datatype,typeoffsettab);
	    }
	}

	/* then, if this is a function, do the args */
	if (symbol->type == SYMBOL_TYPE_FUNCTION) 
	    list_for_each_entry(member,&(symbol->s.ii.d.f.args),member) {
		if (!member->datatype) {
		    ldebug(3,"resolving function %s arg %s tref 0x%x\n",
			   symbol->name,member->name,member->datatype_addr_ref);
		    resolve_type_refs(NULL,member,typeoffsettab);
		}
	    }
    }
}

struct process_dwflmod_argdata {
    struct debugfile *debugfile;
    int fd;
};

/*
 * Stub callback telling 
 */
static int find_no_debuginfo(Dwfl_Module *mod __attribute__ ((unused)),
			     void **userdata __attribute__ ((unused)),
			     const char *modname __attribute__ ((unused)),
			     Dwarf_Addr base __attribute__ ((unused)),
			     const char *file_name __attribute__ ((unused)),
			     const char *debuglink_file __attribute__ ((unused)),
			     GElf_Word debuglink_crc __attribute__ ((unused)),
			     char **debuginfo_file_name __attribute__ ((unused))) {
    return -1;
}

static int process_dwflmod (Dwfl_Module *dwflmod,
			    void **userdata __attribute__ ((unused)),
			    const char *name __attribute__ ((unused)),
			    Dwarf_Addr base __attribute__ ((unused)),
			    void *arg) {
    struct process_dwflmod_argdata *data = \
	(struct process_dwflmod_argdata *)arg;

    GElf_Addr dwflbias;
    Elf *elf = dwfl_module_getelf(dwflmod,&dwflbias);

    GElf_Ehdr ehdr_mem;
    GElf_Ehdr *ehdr = gelf_getehdr(elf,&ehdr_mem);

    if (ehdr == NULL) {
	lerror("cannot read ELF header: %s",elf_errmsg(-1));
	return DWARF_CB_ABORT;
    }

    Ebl *ebl = ebl_openbackend(elf);
    if (ebl == NULL) {
	lerror("cannot create EBL handle: %s",strerror(errno));
	return DWARF_CB_ABORT;
    }

    /*
     * Last setup before parsing DWARF stuff!
     */
    Dwarf_Addr dwbias;
    Dwarf *dbg = dwfl_module_getdwarf(dwflmod,&dwbias);
    if (!dbg) {
	lerror("could not get dwarf module!\n");
	return DWARF_CB_ABORT;
    }

    size_t shstrndx;
#if HAVE_ELFUTILS_VERSION >= 152
    if (elf_getshdrstrndx(elf,&shstrndx) < 0) {
#else 
    if (elf_getshstrndx(elf,&shstrndx) < 0) {
#endif
	lerror("cannot get section header string table index\n");
	return DWARF_CB_ABORT;
    }

    /* read the string section contents into a big buf for use in dwarf
     * attr interpretation.
     */
    char *string_section_data;
    int string_section_data_len = 0;

    Elf_Scn *scn = NULL;
    while ((scn = elf_nextscn(elf,scn)) != NULL) {
	GElf_Shdr shdr_mem;
	GElf_Shdr *shdr = gelf_getshdr(scn,&shdr_mem);

	if (shdr) { // && shdr->sh_size > 0 &&shdr->sh_type != SHT_PROGBITS) {
	    //shdr_mem.sh_flags & SHF_STRINGS) {
	    const char *name = elf_strptr(elf,shstrndx,shdr->sh_name);

	    if (strcmp(name,".debug_str") == 0) {
		ldebug(2,"found %s section (%d) in debugfile %s\n",name,
		       shdr->sh_size,data->debugfile->idstr);

		Elf_Data *edata = elf_rawdata(scn,NULL);
		if (!edata) {
		    lerror("cannot get data for valid string section '%s': %s",
			   name,elf_errmsg(-1));
		    return DWARF_CB_ABORT;
		}

		/*
		 * We just malloc a big buf now, and then we don't free
		 * anything in symtabs or syms that is present in here!
		 */
		data->debugfile->strtablen = edata->d_size;
		data->debugfile->strtab = malloc(edata->d_size);
		memcpy(data->debugfile->strtab,edata->d_buf,edata->d_size);

		break;
	    }
	}
    }
    if (!data->debugfile->strtab) {
	lwarn("no string table found for debugfile %s; things may break!\n",
	      data->debugfile->filename);
    }

    /* now rescan for debug_info sections */
    scn = NULL;
    while ((scn = elf_nextscn(elf,scn)) != NULL) {
	GElf_Shdr shdr_mem;
	GElf_Shdr *shdr = gelf_getshdr(scn,&shdr_mem);

	if (shdr && shdr->sh_size > 0 && shdr->sh_type == SHT_PROGBITS) {
	    const char *name = elf_strptr(elf,shstrndx,shdr->sh_name);

	    if (strcmp(name,".debug_info") == 0) {
		ldebug(2,"found .debug_info section in debugfile %s\n",
		       data->debugfile->idstr);
		fill_debuginfo(data->debugfile,dwflmod,ebl,ehdr,scn,shdr,dbg);
		//break;
	    }
	}
    }

    return DWARF_CB_OK;
}

/*
 * Primary debuginfo interface.  Given an ELF filename, load all its
 * debuginfo into the supplied debugfile using elfutils libs.
 */
int load_debug_info(struct debugfile *debugfile) {
    int fd;
    Dwfl *dwfl;
    Dwfl_Module *mod;
    char *filename = debugfile->filename;

    if ((fd = open(filename,0,O_RDONLY)) < 0) {
	lerror("open %s: %s\n",filename,strerror(errno));
	return -1;
    }

    /* 
     * Don't try to find any extra debuginfo; we'll handle that elsewhere.
     *
     * XXX This takes care of applying relocations to DWARF data in
     * ET_REL files.  Do we want this???
     *
     * I think not -- what I'd rather have is a post-pass to apply
     * section relocation information when we decode, so that we can
     * share debuginfo-loaded data structs.
     */
    static const Dwfl_Callbacks callbacks = {
	.section_address = dwfl_offline_section_address,
	.find_debuginfo  = find_no_debuginfo,
    };

    dwfl = dwfl_begin(&callbacks);
    if (dwfl == NULL) {
	lerror("could not init libdwfl: %s\n",dwfl_errmsg(dwfl_errno()));
	close(fd);
	return -1;
    }

    // XXX do we really need this?  Can't have it without libdwflP.h
    //dwfl->offline_next_address = 0;

    if (!(mod = dwfl_report_offline(dwfl,filename,filename,fd))) {
	lerror("dwfl_report_offline: %s\n",dwfl_errmsg(dwfl_errno()));
	dwfl_end(dwfl);
	close(fd);
	return -1;
    }

    dwfl_report_end(dwfl,NULL,NULL);

    /*
     * This is where the guts of the work happen -- and that stuff all
     * happens in the callback.
     */
    struct process_dwflmod_argdata data = { 
	.debugfile = debugfile,
	.fd = fd,
    };
    if (dwfl_getmodules(dwfl,&process_dwflmod,&data,0) < 0) {
	lerror("getting dwarf modules: %s\n",dwfl_errmsg(dwfl_errno()));
	return -1;
    }

    dwfl_end(dwfl);
    close(fd);

    return 0;
}


