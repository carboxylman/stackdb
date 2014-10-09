/*
 * Copyright (c) 2011, 2012, 2013, 2014 The University of Utah
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

#include <glib.h>
#include "glib_wrapper.h"

#include "arch.h"
#include "target.h"
#include "dwdebug.h"
#include "dwdebug_priv.h"

struct symbol *target_create_synthetic_type_pointer(struct target *target,
						    struct symbol *type) {
    struct symbol *retval = 
	symbol_create(SYMBOL_TYPE_TYPE,SYMBOL_SOURCE_DWARF,NULL,0,
		      0,LOADTYPE_FULL,symbol_containing_scope(type));

    retval->datatype_code = DATATYPE_PTR;
    retval->issynthetic = 1;

    retval->datatype = type;
    retval->datatype_ref = type->ref;

    retval->size.bytes = target->arch->ptrsize;
    retval->size_is_bytes = 1;

    RHOLD(type,retval);
    RHOLD(retval,retval);

    return retval;
}

struct bsymbol *bsymbol_create(struct lsymbol *lsymbol,
			       struct memregion *region) {
    struct bsymbol *bsymbol = (struct bsymbol *)malloc(sizeof(struct bsymbol));
    memset(bsymbol,0,sizeof(struct bsymbol *));

    bsymbol->lsymbol = lsymbol;
    bsymbol->region = region;
    bsymbol->refcnt = 0;

    RHOLD(lsymbol,bsymbol);

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

int bsymbol_is_inline(struct bsymbol *bsymbol) {
    if (bsymbol->lsymbol->symbol->isinlineinstance)
	return 1;
    return 0;
}

struct bsymbol *bsymbol_create_noninline(struct bsymbol *bsymbol) {
    struct lsymbol *lsymbol;

    lsymbol = lsymbol_create_noninline(bsymbol->lsymbol);
    if (!lsymbol) 
	return NULL;

    return bsymbol_create(lsymbol,bsymbol->region);
}

REFCNT bsymbol_release(struct bsymbol *bsymbol) {
    REFCNT retval;
    RPUT(bsymbol,bsymbol,bsymbol,retval);
    return retval;
}

REFCNT bsymbol_free(struct bsymbol *bsymbol,int force) {
    int retval = bsymbol->refcnt;
    REFCNT trefcnt;

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
	RPUT(bsymbol->lsymbol,lsymbol,bsymbol,trefcnt);

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
    struct symbol *member;
    int i;
    uint32_t bytesize;
    GSList *gsltmp;
    loctype_t ltrc;
    OFFSET offset;
    struct location tloc;

 again:
    bytesize = symbol_get_bytesize(type);
    switch (type->datatype_code) {
    case DATATYPE_VOID:
	fprintf(stream,"<VOID>");
	return;
    case DATATYPE_BASE:;
	encoding_t enc = SYMBOLX_ENCODING_V(type);
	if (bytesize == 1) {
	    if (enc == ENCODING_SIGNED_CHAR)
		fprintf(stream,"%c",rv_c(buf));
	    else if (enc == ENCODING_UNSIGNED_CHAR)
		fprintf(stream,"%uc",rv_uc(buf));
	    else if (enc == ENCODING_SIGNED)
		fprintf(stream,"%" PRIi8,rv_i8(buf));
	    else if (enc == ENCODING_SIGNED)
		fprintf(stream,"%" PRIu8,rv_u8(buf));
	    else 
		fprintf(stream,"<BASE_%d>",bytesize);
	}
	else if (bytesize == 2) {
	    if (strstr(type->name,"char"))
		fprintf(stream,"%lc",rv_wc(buf));
	    else if (enc == ENCODING_SIGNED)
		fprintf(stream,"%" PRIi16,rv_i16(buf));
	    else if (enc == ENCODING_UNSIGNED)
		fprintf(stream,"%" PRIu16,rv_u16(buf));
	    else 
		fprintf(stream,"<BASE_%d>",bytesize);
	}
	else if (bytesize == 4) {
	    if (enc == ENCODING_SIGNED)
		fprintf(stream,"%" PRIi32,rv_i32(buf));
	    else if (enc == ENCODING_UNSIGNED)
		fprintf(stream,"%" PRIu32,rv_u32(buf));
	    else 
		fprintf(stream,"<BASE_%d>",bytesize);
	}
	else if (bytesize == 8) {
	    if (enc == ENCODING_SIGNED)
		fprintf(stream,"%" PRIi64,rv_i64(buf));
	    else if (enc == ENCODING_UNSIGNED)
		fprintf(stream,"%" PRIu64,rv_u64(buf));
	    else 
		fprintf(stream,"<BASE_%d>",bytesize);
	}
	else {
	    fprintf(stream,"<BASE_%d>",bytesize);
	}
	return;
    case DATATYPE_ARRAY:;
	GSList *subranges = SYMBOLX_SUBRANGES(type);
	int subrange;

	if (!subranges) {
	    fprintf(stream,"[  ]");
	    return;
	}

	/* catch 0-byte arrays */
	subrange = (int)(uintptr_t)subranges->data;
	if (subrange == 0) {
	    fprintf(stream,"[  ]");
	    return;
	}

	int llen = g_slist_length(subranges);
	int typebytesize = symbol_get_bytesize(symbol_get_datatype(type));
	int total = 1;
	int *arcounts = (int *)malloc(sizeof(int) * llen);
	uint64_t aoffset = 0;
	int rowlength = 
	    ((int)(uintptr_t)g_slist_nth_data(subranges,llen - 1)) + 1;
	struct symbol *datatype = symbol_get_datatype(type);

	for (i = 0; i < llen; ++i) {
	    if (likely(i < (llen - 1))) {
		arcounts[i] = 0;
		fprintf(stream,"[ ");
	    }
	    int sri = (int)(uintptr_t)g_slist_nth_data(subranges,i);
	    total = total * (sri + 1);
	}
	while (total) {
	    /* do one row according to the current baseoffset */
	    fprintf(stream,"[ ");
	    for (i = 0; i < rowlength; ++i, aoffset += typebytesize) {
		if (likely(i > 0))
		    fprintf(stream,", ");
		symbol_type_rvalue_print(stream,datatype,
					 (void *)(buf+aoffset),typebytesize,
					 flags,target);
	    }
	    total -= rowlength;
	    fprintf(stream," ] ");

	    /* Flow the index counters back and up as we do rows.  We
	     * increment the next highest one each time we reach the
	     * max length for one of the indices.
	     */
	    int sri = (int)(uintptr_t)g_slist_nth_data(subranges,i);
	    for (i = llen - 1; i > -1; --i) {
		if (arcounts[i]++ < (sri + 1)) 
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
	gsltmp = NULL;
	v_g_slist_foreach(SYMBOLX_MEMBERS(type),gsltmp,member) {
	    if (likely(i))
		fprintf(stream,", ");

	    if (member->name) 
		fprintf(stream,".%s = ",member->name);
	    if (type->datatype_code == DATATYPE_UNION)
		symbol_rvalue_print(stream,member,buf,bufsiz,flags,target);
	    else {
		memset(&tloc,0,sizeof(tloc));
		ltrc = symbol_resolve_location(member,NULL,&tloc);
		if (ltrc != LOCTYPE_MEMBER_OFFSET) 
		    fputs("?",stream);
		else {
		    offset = LOCATION_OFFSET(&tloc);
		    symbol_rvalue_print(stream,member,
					buf + offset,bufsiz - offset,
					flags,target);
		}
		location_internal_free(&tloc);
	    }
	    ++i;
	}
	fprintf(stream," }");
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
	    int ptrsize = (int)target->arch->ptrsize;

	    fprintf(stream,"0x");
	    if (target->arch->endian == ENDIAN_LITTLE) {
		for (i = ptrsize - 1; i > -1; --i) {
		    fprintf(stream,"%02hhx",*(((uint8_t *)buf)+i));
		}
	    }
	    else {
		for (i = 0; i < ptrsize; ++i) {
		    fprintf(stream,"%02hhx",*(((uint8_t *)buf)+i));
		}
	    }
	}
	return;
    case DATATYPE_FUNC:
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

    type = symbol_get_datatype(symbol);

    if (symbol->size_is_bits
	&& type->datatype_code != DATATYPE_BASE) {
	vwarn("apparent bitfield %s is not backed by a base type!",symbol->name);
	fprintf(stream,"<BADBITFIELDTYPE>");
	return;
    }
    /* If it's a bitfield, select those bits and print them. */
    else if (symbol->size_is_bits ) {
	vdebug(5,LA_TARGET,LF_SYMBOL,
	       "doing bitfield for symbol %s: size=%d,offset=%d\n",
	       symbol->name,symbol->size.bits,
	       symbol->size.offset);
	/* Create a bitmask */
	bitmask = 1;
	for (i = 1; i < symbol->size.bits; ++i) {
	    bitmask <<= 1;
	    bitmask |= 1;
	}
	if (target->arch->endian == ENDIAN_LITTLE)
	    lboffset = (symbol->size.ctbytes * 8) - (symbol->size.offset + symbol->size.bits);
	else 
	    lboffset = symbol->size.offset;
	bitmask <<= lboffset;
	
	if (symbol->size.ctbytes == 1) 
	    fprintf(stream,"%hhu",(uint8_t)(((*(uint8_t *)buf) & bitmask) \
					    >> lboffset));
	else if (symbol->size.ctbytes == 2) 
	    fprintf(stream,"%hu",(uint16_t)(((*(uint16_t *)buf) & bitmask) \
					    >> lboffset));
	else if (symbol->size.ctbytes == 4) 
	    fprintf(stream,"%u",(uint32_t)(((*(uint32_t *)buf) & bitmask) \
					    >> lboffset));
	else if (symbol->size.ctbytes == 8) 
	    fprintf(stream,"%"PRIu64,(uint64_t)(((*(uint64_t *)buf) & bitmask) \
					    >> lboffset));
	else {
	    vwarn("unsupported bitfield byte size %d for symbol %s\n",
		  symbol->size.ctbytes,symbol->name);
	    fprintf(stream,"<BADBITFIELDBYTESIZE>");
	}
	
	return;
    }

    return symbol_type_rvalue_print(stream,type,buf,bufsiz,flags,target);
}
