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

#include "target.h"

struct symbol *target_create_synthetic_type_pointer(struct target *target,
						  struct symbol *type) {
    struct symbol *retval = symbol_create(type->symtab,0,NULL,SYMBOL_TYPE_TYPE,
					  SYMBOL_SOURCE_DWARF,1);

    retval->datatype_code = DATATYPE_PTR;
    retval->issynthetic = 1;

    retval->datatype = type;
    retval->datatype_ref = type->ref;

    retval->size = target->ptrsize;

    symbol_hold(type);
    symbol_hold(retval);

    return retval;
}


struct bsymbol *bsymbol_create(struct lsymbol *lsymbol,
			       struct memregion *region,
			       struct memrange *range) {
    struct bsymbol *bsymbol = (struct bsymbol *)malloc(sizeof(struct bsymbol));
    memset(bsymbol,0,sizeof(struct bsymbol *));

    bsymbol->lsymbol = lsymbol;
    bsymbol->region = region;
    bsymbol->range = range;
    bsymbol->refcnt = 0;

    lsymbol_hold(lsymbol);

    return bsymbol;
}

char *bsymbol_get_name(struct bsymbol *bsymbol) {
    return lsymbol_get_name(bsymbol->lsymbol);
}

struct symbol *bsymbol_get_symbol(struct bsymbol *bsymbol) {
    return lsymbol_get_symbol(bsymbol->lsymbol);
}

struct lsymbol *bsymbol_get_lsymbol(struct bsymbol *bsymbol) {
    return bsymbol->lsymbol;
}

void bsymbol_hold(struct bsymbol *bsymbol) {
    RHOLD(bsymbol);
}

REFCNT bsymbol_release(struct bsymbol *bsymbol) {
    return RPUT(bsymbol,bsymbol);
}

REFCNT bsymbol_free(struct bsymbol *bsymbol,int force) {
    int retval = bsymbol->refcnt;

    if (retval) {
	if (!force) {
	    vwarn("cannot free (%d refs) ",retval);
	    ERRORDUMPBSYMBOL_NL(bsymbol);
	    return retval;
	}
	else {
	    verror("forced free (%d refs) ",retval);
	    ERRORDUMPBSYMBOL(bsymbol);
	}
    }

    if (bsymbol->lsymbol) 
	lsymbol_release(bsymbol->lsymbol);

    free(bsymbol);

    return retval;
}

void bsymbol_dump(struct bsymbol *bsymbol,struct dump_info *ud) {
    struct dump_info udn = {
	.stream = ud->stream,
	.detail = ud->detail,
	.meta = ud->meta,
    };
    udn.prefix = malloc(strlen(ud->prefix) + 2 + 1);
    sprintf(udn.prefix,"%s  ",ud->prefix);

    fprintf(ud->stream,"bsymbol (");
    if (bsymbol->region) {
	memregion_dump(bsymbol->region,ud);
    }
    fprintf(ud->stream,")\n");

    lsymbol_dump(bsymbol->lsymbol,&udn);

    free(udn.prefix);
}

void symbol_type_rvalue_print(FILE *stream,struct symbol *type,
			      void *buf,int bufsiz,
			      load_flags_t flags,
			      struct target *target) {
    struct symbol_instance *member_instance;
    struct symbol *member;
    int i;

 again:
    switch (type->datatype_code) {
    case DATATYPE_VOID:
	fprintf(stream,"<VOID>");
	return;
    case DATATYPE_BASE:
	if (type->size == 1) {
	    if (type->s.ti->d.t.encoding == ENCODING_SIGNED_CHAR)
		fprintf(stream,"%c",rv_c(buf));
	    else if (type->s.ti->d.t.encoding == ENCODING_UNSIGNED_CHAR)
		fprintf(stream,"%uc",rv_uc(buf));
	    else if (type->s.ti->d.t.encoding == ENCODING_SIGNED)
		fprintf(stream,"%" PRIi8,rv_i8(buf));
	    else if (type->s.ti->d.t.encoding == ENCODING_SIGNED)
		fprintf(stream,"%" PRIu8,rv_u8(buf));
	    else 
		fprintf(stream,"<BASE_%d>",type->size);
	}
	else if (type->size == 2) {
	    if (strstr(type->name,"char"))
		fprintf(stream,"%lc",rv_wc(buf));
	    else if (type->s.ti->d.t.encoding == ENCODING_SIGNED)
		fprintf(stream,"%" PRIi16,rv_i16(buf));
	    else if (type->s.ti->d.t.encoding == ENCODING_UNSIGNED)
		fprintf(stream,"%" PRIu16,rv_u16(buf));
	    else 
		fprintf(stream,"<BASE_%d>",type->size);
	}
	else if (type->size == 4) {
	    if (type->s.ti->d.t.encoding == ENCODING_SIGNED)
		fprintf(stream,"%" PRIi32,rv_i32(buf));
	    else if (type->s.ti->d.t.encoding == ENCODING_UNSIGNED)
		fprintf(stream,"%" PRIu32,rv_u32(buf));
	    else 
		fprintf(stream,"<BASE_%d>",type->size);
	}
	else if (type->size == 8) {
	    if (type->s.ti->d.t.encoding == ENCODING_SIGNED)
		fprintf(stream,"%" PRIi64,rv_i64(buf));
	    else if (type->s.ti->d.t.encoding == ENCODING_UNSIGNED)
		fprintf(stream,"%" PRIu64,rv_u64(buf));
	    else 
		fprintf(stream,"<BASE_%d>",type->size);
	}
	else {
	    fprintf(stream,"<BASE_%d>",type->size);
	}
	return;
    case DATATYPE_ARRAY:;
	/* catch 0-byte arrays */
	if (type->s.ti->d.a.count == 0
	    || type->s.ti->d.a.subranges[type->s.ti->d.a.count - 1] == 0) {
	    fprintf(stream,"[  ]");
	    return;
	}

	int typebytesize = type->datatype->size;
	int total = 1;
	int *arcounts = (int *)malloc(sizeof(int)*(type->s.ti->d.a.count));
	uint64_t offset = 0;
	int rowlength = type->s.ti->d.a.subranges[type->s.ti->d.a.count - 1] + 1;
	struct symbol *datatype = type->datatype;

	for (i = 0; i < type->s.ti->d.a.count; ++i) {
	    if (likely(i < (type->s.ti->d.a.count - 1))) {
		arcounts[i] = 0;
		fprintf(stream,"[ ");
	    }
	    total = total * (type->s.ti->d.a.subranges[i] + 1);
	}
	while (total) {
	    /* do one row according to the current baseoffset */
	    fprintf(stream,"[ ");
	    for (i = 0; i < rowlength; ++i, offset += typebytesize) {
		if (likely(i > 0))
		    fprintf(stream,", ");
		symbol_type_rvalue_print(stream,datatype,
					 (void *)(buf+offset),typebytesize,
					 flags,target);
	    }
	    total -= rowlength;
	    fprintf(stream," ] ");

	    /* Flow the index counters back and up as we do rows.  We
	     * increment the next highest one each time we reach the
	     * max length for one of the indices.
	     */
	    for (i = type->s.ti->d.a.count - 1; i > -1; --i) {
		if (arcounts[i]++ < (type->s.ti->d.a.subranges[i] + 1)) 
		    break;
		else {
		    fprintf(stream,"] ");
		    /* reset this index counter */
		    arcounts[i] = 0;
		}
	    }
	}
	free(arcounts);
	return;
    case DATATYPE_UNION:
	if (flags & LOAD_FLAG_AUTO_DEREF) {
	    vwarn("do not enable auto_deref for unions; clearing!\n");
	    flags &= ~LOAD_FLAG_AUTO_DEREF;
	    flags &= ~LOAD_FLAG_AUTO_DEREF_RECURSE;
	}
	if (flags & LOAD_FLAG_AUTO_STRING) {
	    vwarn("do not enable auto_string for unions; clearing!\n");
	    flags &= ~LOAD_FLAG_AUTO_STRING;
	}
    case DATATYPE_STRUCT:
	fprintf(stream,"{ ");
	/* Only recursively follow pointers if the flags say so. */
	if (!(flags & LOAD_FLAG_AUTO_DEREF_RECURSE)) 
	    flags &= ~LOAD_FLAG_AUTO_DEREF;
	i = 0;
	list_for_each_entry(member_instance,&type->s.ti->d.su.members,
			    d.v.member) {
	    member = member_instance->d.v.member_symbol;
	    if (likely(i))
		fprintf(stream,", ");
	    if (type->datatype_code == DATATYPE_STRUCT 
		&& member->s.ii->l.loctype != LOCTYPE_MEMBER_OFFSET) {
		vwarn("type %s member %s did not have a MEMBER_OFFSET location, skipping!\n",type->name,member->name);
		if (member->name)
		    fprintf(stream,".%s = ???",member->name);
		continue;
	    }

	    if (member->name) 
		fprintf(stream,".%s = ",member->name);
	    if (type->datatype_code == DATATYPE_UNION)
		symbol_rvalue_print(stream,member,buf,bufsiz,flags,target);
	    else
		symbol_rvalue_print(stream,member,
				    buf + member->s.ii->l.l.member_offset,
				    bufsiz - member->s.ii->l.l.member_offset,
				    flags,target);
	    ++i;
	}
	fprintf(stream," }");
	return;
    case DATATYPE_BITFIELD:
	fprintf(stream,"<BITFIELD>");
	return;
    case DATATYPE_PTR:
	if ((flags & LOAD_FLAG_AUTO_DEREF) ||
	    ((flags & LOAD_FLAG_AUTO_STRING) 
	     && symbol_type_is_char(type->datatype))) {
	    type = symbol_type_skip_ptrs(type);

	    if (symbol_type_is_char(type)) {
		fprintf(stream,"%s",(char *)buf);
	    }
	    else
		goto again;
	}
	else {
	    fprintf(stream,"0x");
	    if (target->endian == DATA_LITTLE_ENDIAN) {
		for (i = target->ptrsize - 1; i > -1; --i) {
		    fprintf(stream,"%02hhx",*(((uint8_t *)buf)+i));
		}
	    }
	    else {
		for (i = 0; i < target->ptrsize; ++i) {
		    fprintf(stream,"%02hhx",*(((uint8_t *)buf)+i));
		}
	    }
	}
	return;
    case DATATYPE_FUNCTION:
	fprintf(stream,"<FUNCTION>");
	return;
    case DATATYPE_TYPEDEF:
	fprintf(stream,"<TYPEDEF>");
	return;
    case DATATYPE_CONST:
	fprintf(stream,"<CONST>");
	return;
    case DATATYPE_VOL:
	fprintf(stream,"<VOL>");
	return;
    default:
	return;
    }
}

void symbol_rvalue_print(FILE *stream,struct symbol *symbol,
			 void *buf,int bufsiz,
			 load_flags_t flags,struct target *target) {
    struct symbol *type; 
    uint64_t bitmask;
    uint16_t lboffset;
    int i;

    if (!SYMBOL_IS_VAR(symbol))
	return;

    type = symbol_type_skip_qualifiers(symbol_get_datatype(symbol));

    if (symbol->s.ii->d.v.bit_size
	&& type->datatype_code != DATATYPE_BASE) {
	vwarn("apparent bitfield %s is not backed by a base type!",symbol->name);
	fprintf(stream,"<BADBITFIELDTYPE>");
	return;
    }
    /* If it's a bitfield, select those bits and print them. */
    else if (symbol->s.ii->d.v.bit_size) {
	vdebug(5,LOG_T_SYMBOL,
	       "doing bitfield for symbol %s: size=%d,offset=%d\n",
	       symbol->name,symbol->s.ii->d.v.bit_size,
	       symbol->s.ii->d.v.bit_offset);
	/* Create a bitmask */
	bitmask = 1;
	for (i = 1; i < symbol->s.ii->d.v.bit_size; ++i) {
	    bitmask <<= 1;
	    bitmask |= 1;
	}
	if (target->endian == DATA_LITTLE_ENDIAN)
	    lboffset = (symbol->size * 8) - (symbol->s.ii->d.v.bit_offset + symbol->s.ii->d.v.bit_size);
	else 
	    lboffset = symbol->s.ii->d.v.bit_offset;
	bitmask <<= lboffset;
	
	if (symbol->size == 1) 
	    fprintf(stream,"%hhu",(uint8_t)(((*(uint8_t *)buf) & bitmask) \
					    >> lboffset));
	else if (symbol->size == 2) 
	    fprintf(stream,"%hu",(uint16_t)(((*(uint16_t *)buf) & bitmask) \
					    >> lboffset));
	else if (symbol->size == 4) 
	    fprintf(stream,"%u",(uint32_t)(((*(uint32_t *)buf) & bitmask) \
					    >> lboffset));
	else if (symbol->size == 8) 
	    fprintf(stream,"%"PRIu64,(uint64_t)(((*(uint64_t *)buf) & bitmask) \
					    >> lboffset));
	else {
	    vwarn("unsupported bitfield byte size %d for symbol %s\n",
		  symbol->size,symbol->name);
	    fprintf(stream,"<BADBITFIELDBYTESIZE>");
	}
	
	return;
    }

    return symbol_type_rvalue_print(stream,type,buf,bufsiz,flags,target);
}
