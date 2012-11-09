/*
 * Copyright (c) 2012 The University of Utah
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

#include "debuginfo_xml.h"
#include <string.h>

#if V_GSOAP_VERSION_MAJOR >= 2 && V_GSOAP_VERSION_MINOR >= 8
#define __UUSCORE 1
#endif

struct vmi1__DebugFileOptsT defDebugFileOpts = {
    .symbolRefDepth = 1,
    .symtabRefDepth = 1,
};

void *_soap_calloc(struct soap *soap,size_t size) {
    void *r;

    r = soap_malloc(soap,size);
    memset(r,0,size);

    return r;
}

struct vmi1__LocationT *
d_location_to_x_LocationT(struct soap *soap,struct location *l,
			  struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			  int depth) {
    struct vmi1__LocationT *vl;
    int i;

    if (reftab && (vl = (struct vmi1__LocationT *) \
		   g_hash_table_lookup(reftab,(gpointer)l))) 
	return vl;

    vl = _soap_calloc(soap,1*sizeof(*vl));

    /*
     * If there is an error, we must remove this.  This does not happen
     * for locationT's, but just in case, if there was a circular dep,
     * we have to put it in the reftab before calling
     * d_location_to_x_LocationT() in the loclist case below.  Also,
     * errors do not happen for LocationT encoding, so this comment just
     * serves as a model reminder :).
     *
     * (This model is necessary to use for the symbols/symtabs/type
     * cases where there *is* circularity of reference.)
     */
    if (reftab)
	g_hash_table_insert(reftab,(gpointer)l,(gpointer)vl);

    if (!opts)
	opts = &defDebugFileOpts;

    switch(l->loctype) {
    case LOCTYPE_ADDR:
    case LOCTYPE_REALADDR:
	vl->type = _vmi1__LocationT_type__addr;
	vl->__union_LocationT = SOAP_UNION__vmi1__union_LocationT_addr;
	vl->union_LocationT.addr = l->l.addr;
	break;
    case LOCTYPE_REG:
	vl->type = _vmi1__LocationT_type__reg;
	vl->__union_LocationT = SOAP_UNION__vmi1__union_LocationT_reg;
	vl->union_LocationT.reg = l->l.reg;
	break;
    case LOCTYPE_REG_ADDR:
	vl->type = _vmi1__LocationT_type__regAddr;
	vl->__union_LocationT = SOAP_UNION__vmi1__union_LocationT_regAddr;
	vl->union_LocationT.regAddr = l->l.reg;
	break;
    case LOCTYPE_REG_OFFSET:
	vl->type = _vmi1__LocationT_type__regOffset;
	vl->__union_LocationT = SOAP_UNION__vmi1__union_LocationT_regOffset;
	vl->union_LocationT.regOffset = \
	    _soap_calloc(soap,1*sizeof(*vl->union_LocationT.regOffset));
	vl->union_LocationT.regOffset->reg = l->l.regoffset.reg;
	vl->union_LocationT.regOffset->offset = l->l.regoffset.offset;
	break;
    case LOCTYPE_FBREG_OFFSET:
	vl->type = _vmi1__LocationT_type__fbRegOffset;
	vl->__union_LocationT = SOAP_UNION__vmi1__union_LocationT_fbRegOffset;
	vl->union_LocationT.fbRegOffset = l->l.fboffset;
	break;
    case LOCTYPE_MEMBER_OFFSET:
	vl->type = _vmi1__LocationT_type__memberOffset;
	vl->__union_LocationT = SOAP_UNION__vmi1__union_LocationT_memberOffset;
	vl->union_LocationT.memberOffset = l->l.member_offset;
	break;
    case LOCTYPE_RUNTIME:
	vl->type = _vmi1__LocationT_type__runtime;
	vl->__union_LocationT = SOAP_UNION__vmi1__union_LocationT_runtimeLoc;
	vl->union_LocationT.runtimeLoc = "";
	break;
    case LOCTYPE_LOCLIST:
	vl->type = _vmi1__LocationT_type__list;
	vl->__union_LocationT = SOAP_UNION__vmi1__union_LocationT_rangeLocList;
	vl->union_LocationT.rangeLocList = \
	    _soap_calloc(soap,1*sizeof(*vl->union_LocationT.rangeLocList));
	
	vl->union_LocationT.rangeLocList->__sizerangeLoc = l->l.loclist->len;
	vl->union_LocationT.rangeLocList->rangeLoc =	\
	    _soap_calloc(soap,
			l->l.loclist->len *				\
			sizeof(*vl->union_LocationT.rangeLocList->rangeLoc));

	for (i = 0; i < l->l.loclist->len; ++i) {
	    struct _vmi1__rangeLoc *rl = \
		&vl->union_LocationT.rangeLocList->rangeLoc[i];

	    rl->start = l->l.loclist->list[i]->start;
	    rl->end = l->l.loclist->list[i]->end;

	    rl->location = \
		d_location_to_x_LocationT(soap,l->l.loclist->list[i]->loc,
					  opts,reftab,depth);
	}
	break;
    case LOCTYPE_UNKNOWN:
    case __LOCTYPE_MAX:
	vl->type = _vmi1__LocationT_type__none;
	vl->__union_LocationT = 0;
	break;
    }

    return vl;
}

struct vmi1__RangesT *
d_range_to_x_RangesT(struct soap *soap,struct range *r,
		     struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
		     int depth) {
    struct vmi1__RangesT *vr;
    int i;

    if (reftab && (vr = (struct vmi1__RangesT *) \
		   g_hash_table_lookup(reftab,(gpointer)r))) 
	return vr;

    if (!opts)
	opts = &defDebugFileOpts;

    if (r->rtype == RANGE_TYPE_NONE)
	return NULL;

    vr = _soap_calloc(soap,1*sizeof(*vr));

    if (reftab)
	g_hash_table_insert(reftab,(gpointer)r,(gpointer)vr);

    if (r->rtype == RANGE_TYPE_PC) {
	vr->__sizerange = 1;
	vr->range = _soap_calloc(soap,1*sizeof(*vr->range));
	vr->range->start = r->r.a.lowpc;
	vr->range->end = r->r.a.highpc;
    }
    else if (r->rtype == RANGE_TYPE_LIST) {
	vr->__sizerange = r->r.rlist.len;
	vr->range = _soap_calloc(soap,r->r.rlist.len * sizeof(*vr->range));
	for (i = 0; i < r->r.rlist.len; ++i) {
	    vr->range[i].start = r->r.rlist.list[i]->start;
	    vr->range[i].end = r->r.rlist.list[i]->end;
	}
    }
    else {
	verror("bad range type %d!\n",r->rtype);
	free(vr);
	return NULL;
    }

    return vr;
}

#define FILL_SYMBOLHEADERCONTENTS(s,r)					\
    do {								\
	int _rc;							\
	char *_name;							\
	char _idbuf[16];						\
	int _idblen = 16;						\
									\
	_rc = snprintf(_idbuf,_idblen,"%d",(s)->ref);			\
	_rc = (_rc > _idblen) ? _idblen : (_rc + 1);			\
	(r)->id = _soap_calloc(soap,_rc);				\
	strncpy((r)->id,_idbuf,_rc);					\
	if (symbol_get_name(s)) {					\
	    _name = symbol_get_name((s));				\
	    _rc = strlen(_name) + 1;					\
	    (r)->name = _soap_calloc(soap,_rc);				\
	    strncpy((r)->name,_name,_rc);				\
	}								\
	(r)->symbolMeta = _soap_calloc(soap,1*sizeof(*(r)->symbolMeta));	\
	if (SYMBOL_IS_DWARF((s)))					\
	    (r)->symbolMeta->source = _vmi1__symbolMeta_source__dwarf;	\
	else if (SYMBOL_IS_ELF((s)))					\
	    (r)->symbolMeta->source = _vmi1__symbolMeta_source__elf;	\
	(r)->symbolMeta->external = (enum xsd__boolean)((s)->isexternal & 1); \
	(r)->symbolMeta->declaration = (enum xsd__boolean)((s)->isdeclaration & 1); \
	(r)->symbolMeta->prototyped = (enum xsd__boolean)((s)->isprototyped & 1); \
	if ((s)->size_is_bytes) {					\
	    (r)->size = _soap_calloc(soap,sizeof(*(r)->size));		\
	    *(r)->size = symbol_bytesize((s));				\
	}								\
	if ((s)->size_is_bits) {					\
	    (r)->bitSize = _soap_calloc(soap,sizeof(*(r)->bitSize));	\
	    *(r)->bitSize = symbol_bitsize(s);				\
	    (r)->bitOffset = _soap_calloc(soap,sizeof(*(r)->bitOffset)); \
	    *(r)->bitOffset = s->size.offset;				\
	    (r)->containingTypeByteSize =				\
		_soap_calloc(soap,sizeof(*(r)->containingTypeByteSize)); \
	    *(r)->containingTypeByteSize = s->size.ctbytes;		\
	}								\
    } while (0);

#define FILL_INSTANCESYMBOLCONTENTS(s,opts,reftab,depth,r)		\
    if ((s)->has_base_addr) {						\
       (r)->addr = _soap_calloc(soap,sizeof(*(r)->addr));		\
       *(r)->addr = s->base_addr;					\
    }			 	      					\
    r->inlineInstance = (enum xsd__boolean)(s->isinlineinstance & 1);   \
    if (SYMBOL_IS_FULL((s))) {						\
	r->declaredInline = (enum xsd__boolean)((s)->s.ii->isdeclinline & 1); \
	r->inlined = (enum xsd__boolean)((s)->s.ii->isinlined & 1); 	\
    }									\
    if ((s)->datatype)							\
	(r)->type = d_symbol_to_x_SymbolOrSymbolRef(soap,(s)->datatype,(opts), \
						    (reftab),(depth)+1); \
    /* XXX: do constValue!!! */						\
    if (SYMBOL_IS_FULL((s)) && (s)->s.ii->origin) {			\
	r->abstractOrigin =						\
	    d_symbol_to_x_SymbolOrSymbolRef(soap,(s)->s.ii->origin,(opts), \
					    (reftab),(depth)+1);	\
    }									\
    if (SYMBOL_IS_FULL((s)) && (s)->s.ii->inline_instances		\
	&& array_list_len((s)->s.ii->inline_instances)) {		\
	r->inlineInstances =						\
	    d_symbol_array_list_to_x_SymbolsOrSymbolRefs(soap,(s)->s.ii->inline_instances, \
							 (opts),(reftab), \
							 (depth)+1);	\
    }

struct vmi1__VariableT *
d_symbol_to_x_VariableT(struct soap *soap,struct symbol *s,
			struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			int depth) {
    struct vmi1__VariableT *r;

    if (reftab && (r = (struct vmi1__VariableT *) \
		   g_hash_table_lookup(reftab,(gpointer)s))) 
	return r;

    if (!opts)
	opts = &defDebugFileOpts;

    r = _soap_calloc(soap,sizeof(*r));

    if (reftab)
	g_hash_table_insert(reftab,(gpointer)s,(gpointer)r);

    FILL_SYMBOLHEADERCONTENTS(s,r)

    r->param = (enum xsd__boolean)(s->isparam & 1);
    r->member = (enum xsd__boolean)(s->ismember & 1);
    r->enumval = (enum xsd__boolean)(s->isenumval & 1);

    FILL_INSTANCESYMBOLCONTENTS(s,opts,reftab,depth,r);

    if (SYMBOL_IS_FULL_VAR(s)) {
	r->location = d_location_to_x_LocationT(soap,&s->s.ii->d.v.l,
						opts,reftab,depth);
    }
    else {
	/* Schema requires us to have one, so we'd better */
	r->location = _soap_calloc(soap,sizeof(*r->location));
	r->location->__union_LocationT = 0;
	r->location->type = _vmi1__LocationT_type__none;
    }

    return r;
}

struct vmi1__FunctionT *
d_symbol_to_x_FunctionT(struct soap *soap,struct symbol *s,
			struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			int depth) {
    struct vmi1__FunctionT *r;
    struct symbol *arg;
    struct symbol_instance *argi;
    struct array_list *gslist;

    if (reftab && (r = (struct vmi1__FunctionT *) \
		   g_hash_table_lookup(reftab,(gpointer)s)))
	return r;

    if (!opts)
	opts = &defDebugFileOpts;

    r = _soap_calloc(soap,sizeof(*r));

    if (reftab)
	g_hash_table_insert(reftab,(gpointer)s,(gpointer)r);

    FILL_SYMBOLHEADERCONTENTS(s,r);

    if (SYMBOL_IS_FULL(s)) {
	r->argCount = s->s.ii->d.f.count;
	r->hasUnspecifiedParams = \
	    (s->s.ii->d.f.hasunspec) ? xsd__boolean__true_ : xsd__boolean__false_;
	if (s->s.ii->d.f.hasentrypc) {
	    r->entryPC = _soap_calloc(soap,sizeof(*r->entryPC));
	    *r->entryPC = s->s.ii->d.f.entry_pc;
	}
	if (s->s.ii->d.f.prologue_known) {
	    r->prologueEnd = _soap_calloc(soap,sizeof(*r->prologueEnd));
	    *r->prologueEnd = s->s.ii->d.f.prologue_end;
	}
	else if (s->s.ii->d.f.prologue_guessed) {
	    r->prologueEnd = _soap_calloc(soap,sizeof(*r->prologueEnd));
	    *r->prologueEnd = s->s.ii->d.f.prologue_end;
	}
	if (s->s.ii->d.f.epilogue_known) {
	    r->epilogueBegin = _soap_calloc(soap,sizeof(*r->epilogueBegin));
	    *r->epilogueBegin = s->s.ii->d.f.epilogue_begin;
	}
    }

    FILL_INSTANCESYMBOLCONTENTS(s,opts,reftab,depth,r);

    // XXX: do constval!!!

    if (SYMBOL_IS_FULL(s)) {
	if (s->s.ii->d.f.count) {
	    /* Make a tmp array list of the symbols */
	    gslist = array_list_create(s->s.ii->d.f.count);
	    /*
	     * This is a nasty hack, but if you look at the stub,
	     * vmi1__SymbolsOrSymbolRefs and vmi1__SymbolsOrSymbolRefsOpt are
	     * identical except in name.
	     *
	     * I expect SymbolRefs to go away soon anyway, so cheat for now.
	     */
	    list_for_each_entry(argi,&s->s.ii->d.f.args,d.v.member) {
		arg = argi->d.v.member_symbol;
		array_list_append(gslist,arg);
	    }
	    r->arguments = (struct vmi1__SymbolsOrSymbolRefsOpt *) \
		d_symbol_array_list_to_x_SymbolsOrSymbolRefs(soap,gslist,
							     opts,reftab,depth);
	    array_list_free(gslist);
	}
	else {
	    r->arguments = _soap_calloc(soap,sizeof(*r->arguments));
	}

	if (s->s.ii->d.f.symtab) {
	    r->ranges = d_range_to_x_RangesT(soap,&s->s.ii->d.f.symtab->range,
					     opts,reftab,depth);
	    r->symtab = d_symtab_to_x_SymtabT(soap,s->s.ii->d.f.symtab,
					      opts,reftab,depth+1,NULL);
	}
    }

    return r;
}

struct vmi1__LabelT *
d_symbol_to_x_LabelT(struct soap *soap,struct symbol *s,
		     struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
		     int depth) {
    struct vmi1__LabelT *r;

    if (reftab && (r = (struct vmi1__LabelT *) \
		   g_hash_table_lookup(reftab,(gpointer)s)))
	return r;
    else {
	r = _soap_calloc(soap,sizeof(*r));
	if (reftab)
	    g_hash_table_insert(reftab,(gpointer)s,(gpointer)r);
    }

    if (!opts)
	opts = &defDebugFileOpts;

    FILL_SYMBOLHEADERCONTENTS(s,r);
    FILL_INSTANCESYMBOLCONTENTS(s,opts,reftab,depth,r);

    return r;
}

struct vmi1__VoidTypeT *
d_symbol_to_x_VoidTypeT(struct soap *soap,struct symbol *s,
			struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			int depth) {
    struct vmi1__VoidTypeT *r;

    if (reftab && (r = (struct vmi1__VoidTypeT *) \
		   g_hash_table_lookup(reftab,(gpointer)s)))
	return r;
    else {
	r = _soap_calloc(soap,sizeof(*r));
	if (reftab)
	    g_hash_table_insert(reftab,(gpointer)s,(gpointer)r);
    }

    if (!opts)
	opts = &defDebugFileOpts;

    FILL_SYMBOLHEADERCONTENTS(s,r);

    return r;
}

struct vmi1__BaseTypeT *
d_symbol_to_x_BaseTypeT(struct soap *soap,struct symbol *s,
			struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			int depth) {
    struct vmi1__BaseTypeT *r;

    if (reftab && (r = (struct vmi1__BaseTypeT *) \
		   g_hash_table_lookup(reftab,(gpointer)s)))
	return r;
    else {
	r = _soap_calloc(soap,sizeof(*r));
	if (reftab)
	    g_hash_table_insert(reftab,(gpointer)s,(gpointer)r);
    }

    if (!opts)
	opts = &defDebugFileOpts;

    FILL_SYMBOLHEADERCONTENTS(s,r);

    if (SYMBOL_IS_FULL(s)) {
	switch (s->s.ti->d.t.encoding) {
	case ENCODING_ADDRESS:
	    r->encoding = _vmi1__encoding__address;
	    break;
	case ENCODING_BOOLEAN:
	    r->encoding = _vmi1__encoding__boolean;
	    break;
	case ENCODING_COMPLEX_FLOAT:
	    r->encoding = _vmi1__encoding__complexFloat;
	    break;
	case ENCODING_FLOAT:
	    r->encoding = _vmi1__encoding__float_;
	    break;
	case ENCODING_SIGNED:
	    r->encoding = _vmi1__encoding__signed_;
	    break;
	case ENCODING_SIGNED_CHAR:
	    r->encoding = _vmi1__encoding__signedChar;
	    break;
	case ENCODING_UNSIGNED:
	    r->encoding = _vmi1__encoding__unsigned_;
	    break;
	case ENCODING_UNSIGNED_CHAR:
	    r->encoding = _vmi1__encoding__unsignedChar;
	    break;
	case ENCODING_IMAGINARY_FLOAT:
	    r->encoding = _vmi1__encoding__imaginaryFloat;
	    break;
	case ENCODING_PACKED_DECIMAL:
	    r->encoding = _vmi1__encoding__packedDecimal;
	    break;
	case ENCODING_NUMERIC_STRING:
	    r->encoding = _vmi1__encoding__numericString;
	    break;
	case ENCODING_EDITED:
	    r->encoding = _vmi1__encoding__edited;
	    break;
	case ENCODING_SIGNED_FIXED:
	    r->encoding = _vmi1__encoding__signedFixed;
	    break;
	case ENCODING_UNSIGNED_FIXED:
	    r->encoding = _vmi1__encoding__unsignedFixed;
	    break;
	default:
	    r->encoding = _vmi1__encoding__unknown;
	    break;
	}
    }

    return r;
}

struct vmi1__PointerTypeT *
d_symbol_to_x_PointerTypeT(struct soap *soap,struct symbol *s,
			   struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			   int depth) {
    struct vmi1__PointerTypeT *r;

    if (reftab && (r = (struct vmi1__PointerTypeT *) \
		   g_hash_table_lookup(reftab,(gpointer)s)))
	return r;
    else {
	r = _soap_calloc(soap,sizeof(*r));
	if (reftab)
	    g_hash_table_insert(reftab,(gpointer)s,(gpointer)r);
    }

    if (!opts)
	opts = &defDebugFileOpts;

    FILL_SYMBOLHEADERCONTENTS(s,r);

    r->type = d_symbol_to_x_SymbolOrSymbolRef(soap,s->datatype,
					      opts,reftab,depth+1);

    return r;
}

struct vmi1__TypedefTypeT *
d_symbol_to_x_TypedefTypeT(struct soap *soap,struct symbol *s,
			  struct vmi1__DebugFileOptsT *opts,
			  GHashTable *reftab,int depth) {
    struct vmi1__TypedefTypeT *r;

    if (reftab && (r = (struct vmi1__TypedefTypeT *) \
		   g_hash_table_lookup(reftab,(gpointer)s)))
	return r;
    else {
	r = _soap_calloc(soap,sizeof(*r));
	if (reftab)
	    g_hash_table_insert(reftab,(gpointer)s,(gpointer)r);
    }

    if (!opts)
	opts = &defDebugFileOpts;

    FILL_SYMBOLHEADERCONTENTS(s,r);

    r->type = d_symbol_to_x_SymbolOrSymbolRef(soap,s->datatype,
					      opts,reftab,depth+1);

    return r;
}

struct vmi1__ConstTypeT *
d_symbol_to_x_ConstTypeT(struct soap *soap,struct symbol *s,
			struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			int depth) {
    struct vmi1__ConstTypeT *r;

    if (reftab && (r = (struct vmi1__ConstTypeT *) \
		   g_hash_table_lookup(reftab,(gpointer)s)))
	return r;
    else {
	r = _soap_calloc(soap,sizeof(*r));
	if (reftab)
	    g_hash_table_insert(reftab,(gpointer)s,(gpointer)r);
    }

    if (!opts)
	opts = &defDebugFileOpts;

    FILL_SYMBOLHEADERCONTENTS(s,r);

    r->type = d_symbol_to_x_SymbolOrSymbolRef(soap,s->datatype,
					      opts,reftab,depth+1);

    return r;
}

struct vmi1__VolatileTypeT *
d_symbol_to_x_VolatileTypeT(struct soap *soap,struct symbol *s,
			   struct vmi1__DebugFileOptsT *opts,
			   GHashTable *reftab,int depth) {
    struct vmi1__VolatileTypeT *r;

    if (reftab && (r = (struct vmi1__VolatileTypeT *) \
		   g_hash_table_lookup(reftab,(gpointer)s)))
	return r;
    else {
	r = _soap_calloc(soap,sizeof(*r));
	if (reftab)
	    g_hash_table_insert(reftab,(gpointer)s,(gpointer)r);
    }

    if (!opts)
	opts = &defDebugFileOpts;

    FILL_SYMBOLHEADERCONTENTS(s,r);

    r->type = d_symbol_to_x_SymbolOrSymbolRef(soap,s->datatype,
					      opts,reftab,depth+1);

    return r;
}

struct vmi1__ArrayTypeT *
d_symbol_to_x_ArrayTypeT(struct soap *soap,struct symbol *s,
			struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			int depth) {
    struct vmi1__ArrayTypeT *r;
    int i;

    if (reftab && (r = (struct vmi1__ArrayTypeT *) \
		   g_hash_table_lookup(reftab,(gpointer)s)))
	return r;
    else {
	r = _soap_calloc(soap,sizeof(*r));
	if (reftab)
	    g_hash_table_insert(reftab,(gpointer)s,(gpointer)r);
    }

    if (!opts)
	opts = &defDebugFileOpts;

    FILL_SYMBOLHEADERCONTENTS(s,r);

    r->subrangeCount = s->s.ti->d.a.count;
    if (s->s.ti->d.a.count) {
	r->subranges = _soap_calloc(soap,sizeof(*r->subranges));
	r->subranges->__sizesubrange = s->s.ti->d.a.count;
	r->subranges->subrange = \
	    _soap_calloc(soap,
			 s->s.ti->d.a.count * sizeof(*r->subranges->subrange));
	for (i = 0; i < s->s.ti->d.a.count; ++i) {
	    r->subranges->subrange[i] = s->s.ti->d.a.subranges[i];
	}
    }

    return r;
}

struct vmi1__EnumTypeT *
d_symbol_to_x_EnumTypeT(struct soap *soap,struct symbol *s,
		       struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
		       int depth) {
    struct vmi1__EnumTypeT *r;
    struct symbol_instance *tmpi;
    struct symbol *tmps;
    struct array_list *gslist;

    if (reftab && (r = (struct vmi1__EnumTypeT *) \
		   g_hash_table_lookup(reftab,(gpointer)s)))
	return r;
    else {
	r = _soap_calloc(soap,sizeof(*r));
	if (reftab)
	    g_hash_table_insert(reftab,(gpointer)s,(gpointer)r);
    }

    if (!opts)
	opts = &defDebugFileOpts;

    FILL_SYMBOLHEADERCONTENTS(s,r);

    r->memberCount = s->s.ti->d.e.count;
    if (s->s.ti->d.e.count) {
	gslist = array_list_create(s->s.ti->d.e.count);
	list_for_each_entry(tmpi,&s->s.ti->d.e.members,d.v.member) {
	    tmps = tmpi->d.v.member_symbol;
	    array_list_append(gslist,tmps);
	}
	r->members = (struct vmi1__SymbolsOrSymbolRefsOpt *) \
	    d_symbol_array_list_to_x_SymbolsOrSymbolRefs(soap,gslist,
							 opts,reftab,depth+1);
	array_list_free(gslist);
    }

    return r;
}

struct vmi1__StructTypeT *
d_symbol_to_x_StructTypeT(struct soap *soap,struct symbol *s,
			 struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			 int depth) {
    struct vmi1__StructTypeT *r;
    struct symbol_instance *tmpi;
    struct symbol *tmps;
    struct array_list *gslist;

    if (reftab && (r = (struct vmi1__StructTypeT *) \
		   g_hash_table_lookup(reftab,(gpointer)s)))
	return r;
    else {
	r = _soap_calloc(soap,sizeof(*r));
	if (reftab)
	    g_hash_table_insert(reftab,(gpointer)s,(gpointer)r);
    }

    if (!opts)
	opts = &defDebugFileOpts;

    FILL_SYMBOLHEADERCONTENTS(s,r);

    r->memberCount = s->s.ti->d.su.count;
    if (s->s.ti->d.su.count) {
	gslist = array_list_create(s->s.ti->d.su.count);
	list_for_each_entry(tmpi,&s->s.ti->d.su.members,d.v.member) {
	    tmps = tmpi->d.v.member_symbol;
	    array_list_append(gslist,tmps);
	}
	r->members = (struct vmi1__SymbolsOrSymbolRefsOpt *)		\
	    d_symbol_array_list_to_x_SymbolsOrSymbolRefs(soap,gslist,
							 opts,reftab,depth+1);
	array_list_free(gslist);
    }

    return r;
}

struct vmi1__UnionTypeT *
d_symbol_to_x_UnionTypeT(struct soap *soap,struct symbol *s,
			struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			int depth) {
    struct vmi1__UnionTypeT *r;
    struct symbol_instance *tmpi;
    struct symbol *tmps;
    struct array_list *gslist;

    if (reftab && (r = (struct vmi1__UnionTypeT *) \
		   g_hash_table_lookup(reftab,(gpointer)s)))
	return r;
    else {
	r = _soap_calloc(soap,sizeof(*r));
	if (reftab)
	    g_hash_table_insert(reftab,(gpointer)s,(gpointer)r);
    }

    if (!opts)
	opts = &defDebugFileOpts;

    FILL_SYMBOLHEADERCONTENTS(s,r);

    r->memberCount = s->s.ti->d.su.count;
    if (s->s.ti->d.su.count) {
	gslist = array_list_create(s->s.ti->d.su.count);
	list_for_each_entry(tmpi,&s->s.ti->d.su.members,d.v.member) {
	    tmps = tmpi->d.v.member_symbol;
	    array_list_append(gslist,tmps);
	}
	r->members = (struct vmi1__SymbolsOrSymbolRefsOpt *)		\
	    d_symbol_array_list_to_x_SymbolsOrSymbolRefs(soap,gslist,
							 opts,reftab,depth+1);
	array_list_free(gslist);
    }

    return r;
}

struct vmi1__FunctionTypeT *
d_symbol_to_x_FunctionTypeT(struct soap *soap,struct symbol *s,
			   struct vmi1__DebugFileOptsT *opts,
			   GHashTable *reftab,int depth) {
    struct vmi1__FunctionTypeT *r;
    struct symbol_instance *tmpi;
    struct symbol *tmps;
    struct array_list *gslist;

    if (reftab && (r = (struct vmi1__FunctionTypeT *) \
		   g_hash_table_lookup(reftab,(gpointer)s)))
	return r;
    else {
	r = _soap_calloc(soap,sizeof(*r));
	if (reftab)
	    g_hash_table_insert(reftab,(gpointer)s,(gpointer)r);
    }

    if (!opts)
	opts = &defDebugFileOpts;

    FILL_SYMBOLHEADERCONTENTS(s,r);

    r->argCount = s->s.ti->d.f.count;
    if (s->s.ti->d.f.count) {
	gslist = array_list_create(s->s.ti->d.f.count);
	list_for_each_entry(tmpi,&s->s.ti->d.f.args,d.v.member) {
	    tmps = tmpi->d.v.member_symbol;
	    array_list_append(gslist,tmps);
	}
	r->arguments = (struct vmi1__SymbolsOrSymbolRefsOpt *)		\
	    d_symbol_array_list_to_x_SymbolsOrSymbolRefs(soap,gslist,
							 opts,reftab,depth+1);
	array_list_free(gslist);
    }
    if (s->s.ti->d.f.hasunspec) 
	r->hasUnspecifiedParams = xsd__boolean__true_;
    else
	r->hasUnspecifiedParams = xsd__boolean__false_;

    return r;
}

struct vmi1__SymbolOrSymbolRef *
d_symbol_to_x_SymbolOrSymbolRef(struct soap *soap,struct symbol *s,
				struct vmi1__DebugFileOptsT *opts,
				GHashTable *reftab,int depth) {
    struct vmi1__SymbolOrSymbolRef *r;
    gpointer cached = NULL;
    char idbuf[16];
    int rc;

    if (!opts)
	opts = &defDebugFileOpts;

    r = (struct vmi1__SymbolOrSymbolRef *)_soap_calloc(soap,sizeof(*r));

    /*
     * If we've hit the max depth, encode Refs, not Symbols/Symtabs.
     *
     * NOTE: we do *not* cache SymbolOrSymbolRef choices, nor do we
     * cache symbolRef/symtabRef elements.  Why?  Because the choice of
     * whether to encode a symbol or not is depth-dependent, so at some
     * depths we might encode a ref, not a symbol/symtab.
     *
     * BUT, perhaps, we should always return the full symbol if it has
     * already been encoded, instead of a ref to it, even if we've
     * reached the max depth?  For now, we don't for consistency.
     */
    if (depth >= opts->symbolRefDepth) {
	rc = snprintf(idbuf,16,"%d",(s)->ref);
	rc = (rc > 16) ? 16 : (rc + 1);
	r->__union_SymbolOrSymbolRef = \
	    SOAP_UNION__vmi1__union_SymbolOrSymbolRef_symbolRef;
	r->union_SymbolOrSymbolRef.symbolRef = _soap_calloc(soap,rc);
	strncpy(r->union_SymbolOrSymbolRef.symbolRef,idbuf,rc);

	return r;
    }

    if (reftab)
	cached = g_hash_table_lookup(reftab,(gpointer)s);

    if (SYMBOL_IS_VAR(s)) {
	if (cached)
	    r->union_SymbolOrSymbolRef.variable = \
		(struct vmi1__VariableT *)cached;
	else
	    r->union_SymbolOrSymbolRef.variable = \
		d_symbol_to_x_VariableT(soap,s,opts,reftab,depth);
	r->__union_SymbolOrSymbolRef = \
	    SOAP_UNION__vmi1__union_SymbolOrSymbolRef_variable;
    }
    else if (SYMBOL_IS_FUNCTION(s)) {
	if (cached)
	    r->union_SymbolOrSymbolRef.function = \
		(struct vmi1__FunctionT *)cached;
	else
	    r->union_SymbolOrSymbolRef.function = \
		d_symbol_to_x_FunctionT(soap,s,opts,reftab,depth);
	r->__union_SymbolOrSymbolRef = \
	    SOAP_UNION__vmi1__union_SymbolOrSymbolRef_function;
    }
    else if (SYMBOL_IS_LABEL(s)) {
	if (cached)
	    r->union_SymbolOrSymbolRef.label = (struct vmi1__LabelT *)cached;
	else
	    r->union_SymbolOrSymbolRef.label = \
		d_symbol_to_x_LabelT(soap,s,opts,reftab,depth);
	r->__union_SymbolOrSymbolRef = \
	    SOAP_UNION__vmi1__union_SymbolOrSymbolRef_label;
    }
    else if (SYMBOL_IS_TYPE(s)) {
	switch (s->datatype_code) {
	case DATATYPE_VOID:
	    if (cached)
		r->union_SymbolOrSymbolRef.voidType = \
		    (struct vmi1__VoidTypeT *)cached;
	    else
		r->union_SymbolOrSymbolRef.voidType = \
		    d_symbol_to_x_VoidTypeT(soap,s,opts,reftab,depth);
	    r->__union_SymbolOrSymbolRef = \
		SOAP_UNION__vmi1__union_SymbolOrSymbolRef_voidType;
	    break;
	case DATATYPE_ARRAY:
	    if (cached)
		r->union_SymbolOrSymbolRef.arrayType = \
		    (struct vmi1__ArrayTypeT *)cached;
	    else
		r->union_SymbolOrSymbolRef.arrayType = \
		    d_symbol_to_x_ArrayTypeT(soap,s,opts,reftab,depth);
	    r->__union_SymbolOrSymbolRef = \
		SOAP_UNION__vmi1__union_SymbolOrSymbolRef_arrayType;
	    break;
	case DATATYPE_STRUCT:
	    if (cached)
		r->union_SymbolOrSymbolRef.structType = \
		    (struct vmi1__StructTypeT *)cached;
	    else
		r->union_SymbolOrSymbolRef.structType = \
		    d_symbol_to_x_StructTypeT(soap,s,opts,reftab,depth);
	    r->__union_SymbolOrSymbolRef = \
		SOAP_UNION__vmi1__union_SymbolOrSymbolRef_structType;
	    break;
	case DATATYPE_ENUM:
	    if (cached)
		r->union_SymbolOrSymbolRef.enumType = \
		    (struct vmi1__EnumTypeT *)cached;
	    else
		r->union_SymbolOrSymbolRef.enumType = \
		    d_symbol_to_x_EnumTypeT(soap,s,opts,reftab,depth);
	    r->__union_SymbolOrSymbolRef = \
		SOAP_UNION__vmi1__union_SymbolOrSymbolRef_enumType;
	    break;
	case DATATYPE_PTR:
	    if (cached)
		r->union_SymbolOrSymbolRef.pointerType = \
		    (struct vmi1__PointerTypeT *)cached;
	    else
		r->union_SymbolOrSymbolRef.pointerType = \
		    d_symbol_to_x_PointerTypeT(soap,s,opts,reftab,depth);
	    r->__union_SymbolOrSymbolRef = \
		SOAP_UNION__vmi1__union_SymbolOrSymbolRef_pointerType;
	    break;
	case DATATYPE_FUNCTION:
	    if (cached)
		r->union_SymbolOrSymbolRef.functionType = \
		    (struct vmi1__FunctionTypeT *)cached;
	    else 
		r->union_SymbolOrSymbolRef.functionType = \
		    d_symbol_to_x_FunctionTypeT(soap,s,opts,reftab,depth);
	    r->__union_SymbolOrSymbolRef = \
		SOAP_UNION__vmi1__union_SymbolOrSymbolRef_functionType;
	    break;
	case DATATYPE_TYPEDEF:
	    if (cached)
		r->union_SymbolOrSymbolRef.typedefType = \
		    (struct vmi1__TypedefTypeT *)cached;
	    else
		r->union_SymbolOrSymbolRef.typedefType = \
		    d_symbol_to_x_TypedefTypeT(soap,s,opts,reftab,depth);
	    r->__union_SymbolOrSymbolRef = \
		SOAP_UNION__vmi1__union_SymbolOrSymbolRef_typedefType;
	    break;
	case DATATYPE_UNION:
	    if (cached)
		r->union_SymbolOrSymbolRef.unionType = \
		    (struct vmi1__UnionTypeT *)cached;
	    else
		r->union_SymbolOrSymbolRef.unionType = \
		    d_symbol_to_x_UnionTypeT(soap,s,opts,reftab,depth);
	    r->__union_SymbolOrSymbolRef = \
		SOAP_UNION__vmi1__union_SymbolOrSymbolRef_unionType;
	    break;
	case DATATYPE_BASE:
	    if (cached)
		r->union_SymbolOrSymbolRef.baseType = \
		    (struct vmi1__BaseTypeT *)cached;
	    else
		r->union_SymbolOrSymbolRef.baseType = \
		    d_symbol_to_x_BaseTypeT(soap,s,opts,reftab,depth);
	    r->__union_SymbolOrSymbolRef = \
		SOAP_UNION__vmi1__union_SymbolOrSymbolRef_baseType;
	    break;
	case DATATYPE_CONST:
	    if (cached)
		r->union_SymbolOrSymbolRef.constType = \
		    (struct vmi1__ConstTypeT *)cached;
	    else 
		r->union_SymbolOrSymbolRef.constType = \
		    d_symbol_to_x_ConstTypeT(soap,s,opts,reftab,depth);
	    r->__union_SymbolOrSymbolRef = \
		SOAP_UNION__vmi1__union_SymbolOrSymbolRef_constType;
	    break;
	case DATATYPE_VOL:
	    if (cached)
		r->union_SymbolOrSymbolRef.volatileType = \
		    (struct vmi1__VolatileTypeT *)cached;
	    else
		r->union_SymbolOrSymbolRef.volatileType = \
		    d_symbol_to_x_VolatileTypeT(soap,s,opts,reftab,depth);
	    r->__union_SymbolOrSymbolRef = \
		SOAP_UNION__vmi1__union_SymbolOrSymbolRef_volatileType;
	    break;
	default:
	    verror("bad datatype code %d!\n",s->datatype_code);
	    free(r);
	    return NULL;
	}
    }
    else {
	verror("bad symbol type %d!\n",s->type);
	free(r);
	return NULL;
    }

    return r;
}

_vmi1__nestedSymbol *
d_lsymbol_to_x_nestedSymbol(struct soap *soap,struct lsymbol *ls,
			    struct vmi1__DebugFileOptsT *opts,
			    GHashTable *reftab,int depth) {
    /* Weird that we have to cast here... */
    return (_vmi1__nestedSymbol *) \
	d_symbol_array_list_to_x_SymbolsOrSymbolRefs(soap,ls->chain,
						     opts,reftab,depth);
}

struct vmi1__SymbolsOrSymbolRefs *
d_symbol_array_list_to_x_SymbolsOrSymbolRefs(struct soap *soap,
					     struct array_list *list,
					     struct vmi1__DebugFileOptsT *opts,
					     GHashTable *reftab,int depth) {
    int i;
    int len = array_list_len(list);
    struct symbol *s;
    gpointer cached = NULL;
    struct vmi1__SymbolsOrSymbolRefs *r;
    char idbuf[16];
#if V_GSOAP_VERSION_MAJOR >= 2 && V_GSOAP_VERSION_MINOR >= 8
    union _vmi1__union_SymbolsOrSymbolRefs_ *ui;
#else
    union _vmi1__union_SymbolsOrSymbolRefs *ui;
#endif
    int *uw;
    int rc;

    if (!opts)
	opts = &defDebugFileOpts;

    r = calloc(1,sizeof(*r));

    if (depth >= opts->symbolRefDepth) {
	r->__sizesymbolRef = len;
	r->symbolRef = calloc(len,sizeof(*r->symbolRef));
    }
    else {
#if V_GSOAP_VERSION_MAJOR >= 2 && V_GSOAP_VERSION_MINOR >= 8
	r->__size_SymbolsOrSymbolRefs_ = len;
	r->__union_SymbolsOrSymbolRefs_ = \
	    calloc(len,sizeof(*r->__union_SymbolsOrSymbolRefs_));
#else
	r->__size_SymbolsOrSymbolRefs = len;
	r->__union_SymbolsOrSymbolRefs = \
	    calloc(len,sizeof(*r->__union_SymbolsOrSymbolRefs));
#endif
    }

    for (i = 0; i < len; ++i) {
	s = (struct symbol *)array_list_item(list,i);

	/* If we are too deep, do ref first and continue... */
	if (depth >= opts->symbolRefDepth) {
	    rc = snprintf(idbuf,16,"%d",(s)->ref);
	    rc = (rc > 16) ? 16 : (rc + 1);
	    r->symbolRef[i] = _soap_calloc(soap,rc);
	    strncpy(r->symbolRef[i],idbuf,rc);
	    continue;
	}
	/* Else, keep going and do a full symbol */

#if V_GSOAP_VERSION_MAJOR >= 2 && V_GSOAP_VERSION_MINOR >= 8
	uw = &r->__union_SymbolsOrSymbolRefs_[i].__union_SymbolsOrSymbolRefs_;
	ui = &r->__union_SymbolsOrSymbolRefs_[i].union_SymbolsOrSymbolRefs_;
#else
	uw = &r->__union_SymbolsOrSymbolRefs[i].__union_SymbolsOrSymbolRefs;
	ui = &r->__union_SymbolsOrSymbolRefs[i].union_SymbolsOrSymbolRefs;
#endif

	cached = NULL;
	if (reftab)
	    cached = g_hash_table_lookup(reftab,(gpointer)s);

	if (SYMBOL_IS_VAR(s)) {
	    if (cached) 
		ui->variable = (struct vmi1__VariableT *)cached;
	    else
		ui->variable = \
		    d_symbol_to_x_VariableT(soap,s,opts,reftab,depth);
#if V_GSOAP_VERSION_MAJOR >= 2 && V_GSOAP_VERSION_MINOR >= 8
	    *uw = SOAP_UNION__vmi1__union_SymbolsOrSymbolRefs__variable;
#else
	    *uw = SOAP_UNION__vmi1__union_SymbolsOrSymbolRefs_variable;
#endif
	}
	else if (SYMBOL_IS_FUNCTION(s)) {
	    if (cached)
		ui->function = \
		    (struct vmi1__FunctionT *)cached;
	    else
		ui->function = \
		    d_symbol_to_x_FunctionT(soap,s,opts,reftab,depth);
#if V_GSOAP_VERSION_MAJOR >= 2 && V_GSOAP_VERSION_MINOR >= 8
	    *uw = SOAP_UNION__vmi1__union_SymbolsOrSymbolRefs__function;
#else
	    *uw = SOAP_UNION__vmi1__union_SymbolsOrSymbolRefs_function;
#endif
	}
	else if (SYMBOL_IS_LABEL(s)) {
	    if (cached) 
		ui->label = \
		    (struct vmi1__LabelT *)cached;
	    else 
		ui->label =	\
		    d_symbol_to_x_LabelT(soap,s,opts,reftab,depth);
#if V_GSOAP_VERSION_MAJOR >= 2 && V_GSOAP_VERSION_MINOR >= 8
	    *uw = SOAP_UNION__vmi1__union_SymbolsOrSymbolRefs__label;
#else
	    *uw = SOAP_UNION__vmi1__union_SymbolsOrSymbolRefs_label;
#endif
	}
	else if (SYMBOL_IS_TYPE(s)) {
	    switch (s->datatype_code) {
	    case DATATYPE_VOID:
		if (cached)
		    ui->voidType = \
			(struct vmi1__VoidTypeT *)cached;
		else
		    ui->voidType =	\
			d_symbol_to_x_VoidTypeT(soap,s,opts,reftab,depth);
#if V_GSOAP_VERSION_MAJOR >= 2 && V_GSOAP_VERSION_MINOR >= 8
		*uw = SOAP_UNION__vmi1__union_SymbolsOrSymbolRefs__voidType;
#else
		*uw = SOAP_UNION__vmi1__union_SymbolsOrSymbolRefs_voidType;
#endif
		break;
	    case DATATYPE_ARRAY:
		if (cached)
		    ui->arrayType = \
			(struct vmi1__ArrayTypeT *)cached;
		else
		    ui->arrayType =	\
			d_symbol_to_x_ArrayTypeT(soap,s,opts,reftab,depth);
#if V_GSOAP_VERSION_MAJOR >= 2 && V_GSOAP_VERSION_MINOR >= 8
		*uw = SOAP_UNION__vmi1__union_SymbolsOrSymbolRefs__arrayType;
#else
		*uw = SOAP_UNION__vmi1__union_SymbolsOrSymbolRefs_arrayType;
#endif
		break;
	    case DATATYPE_STRUCT:
		if (cached)
		    ui->structType = \
			(struct vmi1__StructTypeT *)cached;
		else
		    ui->structType =	\
			d_symbol_to_x_StructTypeT(soap,s,opts,reftab,depth);
#if V_GSOAP_VERSION_MAJOR >= 2 && V_GSOAP_VERSION_MINOR >= 8
		*uw = SOAP_UNION__vmi1__union_SymbolsOrSymbolRefs__structType;
#else
		*uw = SOAP_UNION__vmi1__union_SymbolsOrSymbolRefs_structType;
#endif
		break;
	    case DATATYPE_ENUM:
		if (cached)
		    ui->enumType = \
			(struct vmi1__EnumTypeT *)cached;
		else
		    ui->enumType =	\
			d_symbol_to_x_EnumTypeT(soap,s,opts,reftab,depth);
#if V_GSOAP_VERSION_MAJOR >= 2 && V_GSOAP_VERSION_MINOR >= 8
		*uw = SOAP_UNION__vmi1__union_SymbolsOrSymbolRefs__enumType;
#else
		*uw = SOAP_UNION__vmi1__union_SymbolsOrSymbolRefs_enumType;
#endif
		break;
	    case DATATYPE_PTR:
		if (cached)
		    ui->pointerType = \
			(struct vmi1__PointerTypeT *)cached;
		else
		    ui->pointerType =	\
			d_symbol_to_x_PointerTypeT(soap,s,opts,reftab,depth);
#if V_GSOAP_VERSION_MAJOR >= 2 && V_GSOAP_VERSION_MINOR >= 8
		*uw = SOAP_UNION__vmi1__union_SymbolsOrSymbolRefs__pointerType;
#else
		*uw = SOAP_UNION__vmi1__union_SymbolsOrSymbolRefs_pointerType;
#endif
		break;
	    case DATATYPE_FUNCTION:
		if (cached)
		    ui->functionType = \
			(struct vmi1__FunctionTypeT *)cached;
		else
		    ui->functionType = \
			d_symbol_to_x_FunctionTypeT(soap,s,opts,reftab,depth);
#if V_GSOAP_VERSION_MAJOR >= 2 && V_GSOAP_VERSION_MINOR >= 8
		*uw = SOAP_UNION__vmi1__union_SymbolsOrSymbolRefs__functionType;
#else
		*uw = SOAP_UNION__vmi1__union_SymbolsOrSymbolRefs_functionType;
#endif
		break;
	    case DATATYPE_TYPEDEF:
		if (cached)
		    ui->typedefType = \
			(struct vmi1__TypedefTypeT *)cached;
		else
		    ui->typedefType =	\
			d_symbol_to_x_TypedefTypeT(soap,s,opts,reftab,depth);
#if V_GSOAP_VERSION_MAJOR >= 2 && V_GSOAP_VERSION_MINOR >= 8
		*uw = SOAP_UNION__vmi1__union_SymbolsOrSymbolRefs__typedefType;
#else
		*uw = SOAP_UNION__vmi1__union_SymbolsOrSymbolRefs_typedefType;
#endif
		break;
	    case DATATYPE_UNION:
		if (cached)
		    ui->unionType = \
			(struct vmi1__UnionTypeT *)cached;
		else
		    ui->unionType =	\
			d_symbol_to_x_UnionTypeT(soap,s,opts,reftab,depth);
#if V_GSOAP_VERSION_MAJOR >= 2 && V_GSOAP_VERSION_MINOR >= 8
		*uw = SOAP_UNION__vmi1__union_SymbolsOrSymbolRefs__unionType;
#else
		*uw = SOAP_UNION__vmi1__union_SymbolsOrSymbolRefs_unionType;
#endif
		break;
	    case DATATYPE_BASE:
		if (cached)
		    ui->baseType = \
			(struct vmi1__BaseTypeT *)cached;
		else
		    ui->baseType =	\
			d_symbol_to_x_BaseTypeT(soap,s,opts,reftab,depth);
#if V_GSOAP_VERSION_MAJOR >= 2 && V_GSOAP_VERSION_MINOR >= 8
		*uw = SOAP_UNION__vmi1__union_SymbolsOrSymbolRefs__baseType;
#else
		*uw = SOAP_UNION__vmi1__union_SymbolsOrSymbolRefs_baseType;
#endif
		break;
	    case DATATYPE_CONST:
		if (cached)
		    ui->constType = \
			(struct vmi1__ConstTypeT *)cached;
		else
		    ui->constType =	\
			d_symbol_to_x_ConstTypeT(soap,s,opts,reftab,depth);
#if V_GSOAP_VERSION_MAJOR >= 2 && V_GSOAP_VERSION_MINOR >= 8
		*uw = SOAP_UNION__vmi1__union_SymbolsOrSymbolRefs__constType;
#else
		*uw = SOAP_UNION__vmi1__union_SymbolsOrSymbolRefs_constType;
#endif
		break;
	    case DATATYPE_VOL:
		if (cached)
		    ui->volatileType = \
			(struct vmi1__VolatileTypeT *)cached;
		else
		    ui->volatileType = \
			d_symbol_to_x_VolatileTypeT(soap,s,opts,reftab,depth);
#if V_GSOAP_VERSION_MAJOR >= 2 && V_GSOAP_VERSION_MINOR >= 8
		*uw = SOAP_UNION__vmi1__union_SymbolsOrSymbolRefs__volatileType;
#else
		*uw = SOAP_UNION__vmi1__union_SymbolsOrSymbolRefs_volatileType;
#endif
		break;
	    default:
		verror("BUG: bad datatype code %d; skipping!\n",
		       s->datatype_code);
		ui->variable = NULL;
		continue;
	    }
	}
	else {
	    verror("BUG: bad symbol type %d; skipping!\n",s->type);
	    ui->variable = NULL;
	    continue;
	}
    }

    return r;
}

#define SOAP_STRCPY(soap,d,s)			\
    do {					\
	char *_ss = (s);			\
	int _rc;				\
						\
	if (!_ss)				\
	    (d) = NULL;				\
	else {					\
	    _rc = strlen(_ss) + 1;		\
	    (d) = _soap_calloc((soap),_rc);	\
	    strncpy((d),_ss,_rc);		\
	}					\
    } while (0);

struct vmi1__DebugFileT *
d_debugfile_to_x_DebugFileT(struct soap *soap,struct debugfile *df,
			    struct vmi1__DebugFileOptsT *opts,
			    GHashTable *reftab,int depth) {
    struct vmi1__DebugFileT *r;
    gpointer cached = NULL;
    GHashTableIter iter;
    struct symtab *symtab;
    char *sfn;
    int i;
    struct array_list *gslist;
    struct symbol *symbol;

    if (!opts)
	opts = &defDebugFileOpts;

    if (reftab &&
	(cached = g_hash_table_lookup(reftab,(gpointer)df))) 
	return (struct vmi1__DebugFileT *)cached;

    r = (struct vmi1__DebugFileT *)_soap_calloc(soap,sizeof(*r));

    if (reftab)
	g_hash_table_insert(reftab,(gpointer)df,(gpointer)r);

    if (df->type == DEBUGFILE_TYPE_KERNEL)
	r->type = _vmi1__DebugFileT_type__kernel;
    else if (df->type == DEBUGFILE_TYPE_KMOD)
	r->type = _vmi1__DebugFileT_type__kmod;
    else if (df->type == DEBUGFILE_TYPE_MAIN)
	r->type = _vmi1__DebugFileT_type__static_;
    else if (df->type == DEBUGFILE_TYPE_SHAREDLIB)
	r->type = _vmi1__DebugFileT_type__sharedlib;

    SOAP_STRCPY(soap,r->filename,df->filename);
    SOAP_STRCPY(soap,r->name,df->name);
    SOAP_STRCPY(soap,r->version,df->version);

    r->sourceFiles = _soap_calloc(soap,sizeof(*r->sourceFiles));
    r->sourceFiles->__sizesourceFile = g_hash_table_size(df->srcfiles);
    r->sourceFiles->sourceFile = \
	_soap_calloc(soap,r->sourceFiles->__sizesourceFile * \
		    sizeof(*r->sourceFiles->sourceFile));

    g_hash_table_iter_init(&iter,df->srcfiles);
    i = 0;
    while (g_hash_table_iter_next(&iter,(gpointer)&sfn,(gpointer)&symtab)) {
	SOAP_STRCPY(soap,r->sourceFiles->sourceFile[i].filename,sfn);
	r->sourceFiles->sourceFile[i].symtab = \
	    d_symtab_to_x_SymtabT(soap,symtab,opts,reftab,depth,NULL);

	++i;
    }

    /* Make a tmp array list of the symbols */
    gslist = array_list_create(g_hash_table_size(df->globals));
    g_hash_table_iter_init(&iter,df->globals);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer)&symbol))
	array_list_append(gslist,symbol);

    d_symbol_array_list_to_x_SymbolsOrSymbolRefs(soap,gslist,
						 opts,reftab,depth);

    array_list_free(gslist);

    return r;
}

struct vmi1__SymtabT *
d_symtab_to_x_SymtabT(struct soap *soap,struct symtab *st,
		      struct vmi1__DebugFileOptsT *opts,
		      GHashTable *reftab,int depth,
		      struct vmi1__SymtabT *ir) {
    struct vmi1__SymtabT *r;
    gpointer cached = NULL;
    GHashTableIter iter;
    struct symtab *symtab;
    char idbuf[16];
    int idblen = 16;
    int rc;
    int len;
    int i;
    struct list_head *pos;
    struct array_list *gslist;
    struct symbol *symbol;

    if (!opts)
	opts = &defDebugFileOpts;

    if (reftab &&
	(cached = g_hash_table_lookup(reftab,(gpointer)st))) 
	return (struct vmi1__SymtabT *)cached;

    if (!ir)
	r = (struct vmi1__SymtabT *)_soap_calloc(soap,sizeof(*r));
    else
	r = ir;

    rc = snprintf(idbuf,idblen,"%d",st->ref);
    rc = (rc > idblen) ? idblen : (rc + 1);
    r->id = _soap_calloc(soap,rc);
    strncpy(r->id,idbuf,rc);
    SOAP_STRCPY(soap,r->name,st->name);

    /*
     * If we've hit the max depth, stop here without dumping it into the
     * reftab; we only want full symtabs in there.
     */
    if (depth >= opts->symtabRefDepth)
	return r;
    /*
     * Else dump this into our reftab, since we're encoding the full
     * thing.
     *
     * XXX: not sure how gSOAP handles the multi-ref stuff when we pass
     * it a ref into an array of values.  Hopefully this won't result in
     * too much duplication...
     */
    else if (reftab)
	g_hash_table_insert(reftab,(gpointer)st,(gpointer)r);

    r->__SymtabT_sequence = _soap_calloc(soap,sizeof(*r->__SymtabT_sequence));

    r->__SymtabT_sequence->ranges = \
	d_range_to_x_RangesT(soap,&st->range,opts,reftab,depth);

    if (st->meta) {
	r->__SymtabT_sequence->rootMeta = \
	    _soap_calloc(soap,sizeof(*r->__SymtabT_sequence->rootMeta));
	SOAP_STRCPY(soap,r->__SymtabT_sequence->rootMeta->compilationDir,
		    st->meta->compdirname);
	SOAP_STRCPY(soap,r->__SymtabT_sequence->rootMeta->producer,
		    st->meta->producer);
	SOAP_STRCPY(soap,r->__SymtabT_sequence->rootMeta->language,
		    st->meta->language);
    }

    if (st->parent) 
	r->__SymtabT_sequence->parent = \
	    d_symtab_to_x_SymtabT(soap,st->parent,opts,reftab,depth+1,NULL);

    len = 0;
    list_for_each(pos,&st->subtabs) 
	++len;

    r->__SymtabT_sequence->symtabs = \
	_soap_calloc(soap,sizeof(r->__SymtabT_sequence->symtabs));
    r->__SymtabT_sequence->symtabs->__sizesymtab = len;
    r->__SymtabT_sequence->symtabs->symtab = \
	_soap_calloc(soap,len*sizeof(*r->__SymtabT_sequence->symtabs->symtab));

    i = 0;
    list_for_each_entry(symtab,&st->subtabs,member) {
	d_symtab_to_x_SymtabT(soap,symtab,opts,reftab,depth+1,
			      &r->__SymtabT_sequence->symtabs->symtab[i]);
	++i;
    }

    /* Make a tmp array list of the symbols */
    gslist = array_list_create(g_hash_table_size(st->tab));
    g_hash_table_iter_init(&iter,st->tab);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer)&symbol))
	array_list_append(gslist,symbol);
    /*
     * This is a nasty hack, but if you look at the stub,
     * vmi1__SymbolsOrSymbolRefs and vmi1__SymbolsOrSymbolRefsOpt are
     * identical except in name.
     *
     * I expect SymbolRefs to go away soon anyway, so cheat for now.
     */
    r->__SymtabT_sequence->symbols = (struct vmi1__SymbolsOrSymbolRefsOpt *) \
	d_symbol_array_list_to_x_SymbolsOrSymbolRefs(soap,gslist,
						     opts,reftab,depth);
    array_list_free(gslist);

    /* Make a tmp array list of the anon symbols */
    gslist = array_list_create(g_hash_table_size(st->anontab));
    g_hash_table_iter_init(&iter,st->anontab);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer)&symbol))
	array_list_append(gslist,symbol);
    /*
     * This is a nasty hack, but if you look at the stub,
     * vmi1__SymbolsOrSymbolRefs and vmi1__SymbolsOrSymbolRefsOpt are
     * identical except in name.
     *
     * I expect SymbolRefs to go away soon anyway, so cheat for now.
     */
    r->__SymtabT_sequence->anonSymbols = (struct vmi1__SymbolsOrSymbolRefsOpt *) \
	d_symbol_array_list_to_x_SymbolsOrSymbolRefs(soap,gslist,
						     opts,reftab,depth);
    array_list_free(gslist);

    return r;
}
