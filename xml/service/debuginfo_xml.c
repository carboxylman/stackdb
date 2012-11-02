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

#if V_GSOAP_VERSION_MAJOR >= 2 && V_GSOAP_VERSION_MINOR >= 8
#define __UUSCORE 1
#endif

struct vmi1__DebugFileOptsT defDebugFileOpts = {
    .symbolRefDepth = 1,
    .symtabRefDepth = 1,
};

struct vmi1__LocationT *
d_location_to_x_LocationT(struct location *l,
			  struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			  int depth) {
    struct vmi1__LocationT *vl = calloc(1,sizeof(*vl));
    int i;

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
	    calloc(1,sizeof(*vl->union_LocationT.regOffset));
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
	    calloc(1,sizeof(*vl->union_LocationT.rangeLocList));
	
	vl->union_LocationT.rangeLocList->__sizerangeLoc = l->l.loclist->len;
	vl->union_LocationT.rangeLocList->rangeLoc =	\
	    calloc(l->l.loclist->len,
		   sizeof(*vl->union_LocationT.rangeLocList->rangeLoc));

	for (i = 0; i < l->l.loclist->len; ++i) {
	    struct _vmi1__rangeLoc *rl = \
		&vl->union_LocationT.rangeLocList->rangeLoc[i];

	    rl->start = l->l.loclist->list[i]->start;
	    rl->end = l->l.loclist->list[i]->end;

	    if (!reftab 
		|| !(rl->location = (struct vmi1__LocationT *)	\
		     g_hash_table_lookup(reftab,
					 (gpointer)l->l.loclist->list[i]->loc))) {
		rl->location = \
		    d_location_to_x_LocationT(l->l.loclist->list[i]->loc,
					      opts,reftab,depth);
		if (reftab)
		    g_hash_table_insert(reftab,
					(gpointer)l->l.loclist->list[i]->loc,
					(gpointer)rl->location);
	    }
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
d_range_to_x_RangesT(struct range *r,
		     struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
		     int depth) {
    struct vmi1__RangesT *vr;
    int i;

    if (!opts)
	opts = &defDebugFileOpts;

    if (r->rtype == RANGE_TYPE_NONE)
	return NULL;

    vr = calloc(1,sizeof(*vr));

    if (r->rtype == RANGE_TYPE_PC) {
	vr->__sizerange = 1;
	vr->range = calloc(1,sizeof(*vr->range));
	vr->range->start = r->r.a.lowpc;
	vr->range->end = r->r.a.highpc;
    }
    else if (r->rtype == RANGE_TYPE_LIST) {
	vr->__sizerange = r->r.rlist.len;
	vr->range = calloc(r->r.rlist.len,sizeof(*vr->range));
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

#define FILL_SYMBOLHEADERCONTENTS(s,idb,idblen,r)			\
    snprintf((idb),(idblen),"%d",(s)->ref);				\
    (r)->id = strdup((idb));						\
    if (symbol_get_name(s))						\
	(r)->name = strdup(symbol_get_name((s)));			\
    (r)->meta = calloc(1,sizeof(*(r)->meta));				\
    if (SYMBOL_IS_DWARF((s)))						\
	(r)->meta->source = _vmi1__meta_source__dwarf;			\
    else if (SYMBOL_IS_ELF((s)))					\
	(r)->meta->source = _vmi1__meta_source__elf;			\
    (r)->meta->external = (enum xsd__boolean)((s)->isexternal & 1);	\
    (r)->meta->declaration = (enum xsd__boolean)((s)->isdeclaration & 1); \
    (r)->meta->prototyped = (enum xsd__boolean)((s)->isprototyped & 1);

#define FILL_INSTANCESYMBOLCONTENTS(s,opts,reftab,depth,idb,idblen,r)	\
    if ((s)->size != 0) {						\
       (r)->size = calloc(1,sizeof(*(r)->size));			\
       *(r)->size = s->size;						\
    }			 	      					\
    if ((s)->has_base_addr) {						\
       (r)->addr = calloc(1,sizeof(*(r)->addr));			\
       *(r)->addr = s->base_addr;					\
    }			 	      					\
    r->inlineInstance = (enum xsd__boolean)(s->isinlineinstance & 1);   \
    if (SYMBOL_IS_FULL((s))) {						\
	r->declaredInline = (enum xsd__boolean)((s)->s.ii->isdeclinline & 1); \
	r->inlined = (enum xsd__boolean)((s)->s.ii->isinlined & 1); 	\
    }									\
    if ((s)->datatype)							\
	(r)->type = d_symbol_to_x_SymbolOrSymbolRef((s)->datatype,(opts), \
						    (reftab),(depth)+1); \
    /* XXX: do constValue!!! */						\
    if (SYMBOL_IS_FULL((s)) && (s)->s.ii->origin) {			\
	r->abstractOrigin =						\
	    d_symbol_to_x_SymbolOrSymbolRef((s)->s.ii->origin,(opts),	\
					    (reftab),(depth)+1);	\
    }									\
    if (SYMBOL_IS_FULL((s)) && (s)->s.ii->inline_instances		\
	&& array_list_len((s)->s.ii->inline_instances)) {		\
	r->inlineInstances =						\
	    d_symbol_array_list_to_x_SymbolsOrSymbolRefs((s)->s.ii->inline_instances, \
							 (opts),(reftab), \
							 (depth)+1);	\
    }

struct vmi1__VariableT *
d_symbol_to_x_VariableT(struct symbol *s,
			struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			int depth) {
    struct vmi1__VariableT *r = calloc(1,sizeof(*r));
    char idbuf[16];

    if (!opts)
	opts = &defDebugFileOpts;

    FILL_SYMBOLHEADERCONTENTS(s,idbuf,16,r)

    r->param = (enum xsd__boolean)(s->isparam & 1);
    r->member = (enum xsd__boolean)(s->ismember & 1);
    r->enumval = (enum xsd__boolean)(s->isenumval & 1);

    if (SYMBOL_IS_FULL_VAR(s)) {
	r->bitOffset = s->s.ii->d.v.bit_offset;
	r->bitSize = s->s.ii->d.v.bit_size;
    }

    FILL_INSTANCESYMBOLCONTENTS(s,opts,reftab,depth,idbuf,16,r);

    if (SYMBOL_IS_FULL(s)) {
	if (!reftab || !(r->location = (struct vmi1__LocationT *) \
			 g_hash_table_lookup(reftab,(gpointer)&s->s.ii->l))) {
	    r->location = d_location_to_x_LocationT(&s->s.ii->l,
						    opts,reftab,depth);
	    if (reftab)
		g_hash_table_insert(reftab,(gpointer)&s->s.ii->l,
				    (gpointer)r->location);
	}
    }
    else {
	/* Schema requires us to have one, so we'd better */
	r->location = calloc(1,sizeof(*r->location));
	r->location->__union_LocationT = 0;
	r->location->type = _vmi1__LocationT_type__none;
    }

    return r;
}

struct vmi1__FunctionT *
d_symbol_to_x_FunctionT(struct symbol *s,
			struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			int depth) {
    struct vmi1__FunctionT *r = calloc(1,sizeof(*r));
    char idbuf[16];

    if (!opts)
	opts = &defDebugFileOpts;

    FILL_SYMBOLHEADERCONTENTS(s,idbuf,16,r);

    FILL_INSTANCESYMBOLCONTENTS(s,opts,reftab,depth,idb,idblen,r);

    // XXX: do constval!!!

    if (SYMBOL_IS_FULL(s) && s->s.ii->d.f.symtab) {
	if (!reftab 
	    || !(r->ranges = (struct vmi1__RangesT *)			\
		 g_hash_table_lookup(reftab,
				     (gpointer)&s->s.ii->d.f.symtab->range))) {
	    r->ranges = d_range_to_x_RangesT(&s->s.ii->d.f.symtab->range,
					    opts,reftab,depth);
	    if (reftab)
		g_hash_table_insert(reftab,
				    (gpointer)&s->s.ii->d.f.symtab->range,
				    (gpointer)r->ranges);
	}
    }

    return r;
}

struct vmi1__LabelT *
d_symbol_to_x_LabelT(struct symbol *symbol,
		     struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
		     int depth) {

    if (!opts)
	opts = &defDebugFileOpts;

}

struct vmi1__VoidTypeT *
d_symbol_to_x_VoidTypeT(struct symbol *symbol,
			struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			int depth) {

    if (!opts)
	opts = &defDebugFileOpts;

}

struct vmi1__BaseTypeT *
d_symbol_to_x_BaseTypeT(struct symbol *symbol,
			struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			int depth) {

    if (!opts)
	opts = &defDebugFileOpts;

}

struct vmi1__PointerTypeT *
d_symbol_to_x_PointerTypeT(struct symbol *symbol,
			   struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			   int depth) {

    if (!opts)
	opts = &defDebugFileOpts;

}

struct vmi1__TypedefTypeT *
d_symbol_to_x_TypedefTypeT(struct symbol *symbol,
			  struct vmi1__DebugFileOptsT *opts,
			  GHashTable *reftab,int depth) {

    if (!opts)
	opts = &defDebugFileOpts;

}

struct vmi1__ConstTypeT *
d_symbol_to_x_ConstTypeT(struct symbol *symbol,
			struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			int depth) {

    if (!opts)
	opts = &defDebugFileOpts;

}

struct vmi1__VolatileTypeT *
d_symbol_to_x_VolatileTypeT(struct symbol *symbol,
			   struct vmi1__DebugFileOptsT *opts,
			   GHashTable *reftab,int depth) {

    if (!opts)
	opts = &defDebugFileOpts;

}

struct vmi1__ArrayTypeT *
d_symbol_to_x_ArrayTypeT(struct symbol *symbol,
			struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			int depth) {

    if (!opts)
	opts = &defDebugFileOpts;

}

struct vmi1__EnumTypeT *
d_symbol_to_x_EnumTypeT(struct symbol *symbol,
		       struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
		       int depth) {

    if (!opts)
	opts = &defDebugFileOpts;

}

struct vmi1__StructTypeT *
d_symbol_to_x_StructTypeT(struct symbol *symbol,
			 struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			 int depth) {

    if (!opts)
	opts = &defDebugFileOpts;

}

struct vmi1__UnionTypeT *
d_symbol_to_x_UnionTypeT(struct symbol *symbol,
			struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			int depth) {

    if (!opts)
	opts = &defDebugFileOpts;

}

struct vmi1__FunctionTypeT *
d_symbol_to_x_FunctionTypeT(struct symbol *symbol,
			   struct vmi1__DebugFileOptsT *opts,
			   GHashTable *reftab,int depth) {

    if (!opts)
	opts = &defDebugFileOpts;

}

struct vmi1__SymbolOrSymbolRef *
d_symbol_to_x_SymbolOrSymbolRef(struct symbol *s,
				struct vmi1__DebugFileOptsT *opts,
				GHashTable *reftab,int depth) {
    struct vmi1__SymbolOrSymbolRef *r;
    gpointer cached = NULL;
    gpointer uncached = NULL;
    char idbuf[16];

    if (!opts)
	opts = &defDebugFileOpts;

    r = (struct vmi1__SymbolOrSymbolRef *)calloc(1,sizeof(*r));

    /*
     * If we've hit the max depth, encode Refs, not Symbols/Symtabs.
     */
    if (depth >= opts->symbolRefDepth) {
	snprintf(idbuf,16,"%d",(s)->ref);
	r->__union_SymbolOrSymbolRef = \
	    SOAP_UNION__vmi1__union_SymbolOrSymbolRef_symbolRef;
	r->union_SymbolOrSymbolRef.symbolRef = strdup(idbuf);

	return r;
    }

    if (reftab)
	cached = g_hash_table_lookup(reftab,(gpointer)s);

    if (SYMBOL_IS_VAR(s)) {
	if (cached)
	    r->union_SymbolOrSymbolRef.variable = \
		(struct vmi1__VariableT *)cached;
	else
	    r->union_SymbolOrSymbolRef.variable = uncached = \
		d_symbol_to_x_VariableT(s,opts,reftab,depth);
	r->__union_SymbolOrSymbolRef = \
	    SOAP_UNION__vmi1__union_SymbolOrSymbolRef_variable;
    }
    else if (SYMBOL_IS_FUNCTION(s)) {
	if (cached)
	    r->union_SymbolOrSymbolRef.function = \
		(struct vmi1__FunctionT *)cached;
	else
	    r->union_SymbolOrSymbolRef.function = uncached = \
		d_symbol_to_x_FunctionT(s,opts,reftab,depth);
	r->__union_SymbolOrSymbolRef = \
	    SOAP_UNION__vmi1__union_SymbolOrSymbolRef_function;
    }
    else if (SYMBOL_IS_LABEL(s)) {
	if (cached)
	    r->union_SymbolOrSymbolRef.label = (struct vmi1__LabelT *)cached;
	else
	    r->union_SymbolOrSymbolRef.label = uncached = \
		d_symbol_to_x_LabelT(s,opts,reftab,depth);
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
		r->union_SymbolOrSymbolRef.voidType = uncached = \
		    d_symbol_to_x_VoidTypeT(s,opts,reftab,depth);
	    r->__union_SymbolOrSymbolRef = \
		SOAP_UNION__vmi1__union_SymbolOrSymbolRef_voidType;
	    break;
	case DATATYPE_ARRAY:
	    if (cached)
		r->union_SymbolOrSymbolRef.arrayType = \
		    (struct vmi1__ArrayTypeT *)cached;
	    else
		r->union_SymbolOrSymbolRef.arrayType = uncached = \
		    d_symbol_to_x_ArrayTypeT(s,opts,reftab,depth);
	    r->__union_SymbolOrSymbolRef = \
		SOAP_UNION__vmi1__union_SymbolOrSymbolRef_arrayType;
	    break;
	case DATATYPE_STRUCT:
	    if (cached)
		r->union_SymbolOrSymbolRef.structType = \
		    (struct vmi1__StructTypeT *)cached;
	    else
		r->union_SymbolOrSymbolRef.structType = uncached = \
		    d_symbol_to_x_StructTypeT(s,opts,reftab,depth);
	    r->__union_SymbolOrSymbolRef = \
		SOAP_UNION__vmi1__union_SymbolOrSymbolRef_structType;
	    break;
	case DATATYPE_ENUM:
	    if (cached)
		r->union_SymbolOrSymbolRef.enumType = \
		    (struct vmi1__EnumTypeT *)cached;
	    else
		r->union_SymbolOrSymbolRef.enumType = uncached = \
		    d_symbol_to_x_EnumTypeT(s,opts,reftab,depth);
	    r->__union_SymbolOrSymbolRef = \
		SOAP_UNION__vmi1__union_SymbolOrSymbolRef_enumType;
	    break;
	case DATATYPE_PTR:
	    if (cached)
		r->union_SymbolOrSymbolRef.pointerType = \
		    (struct vmi1__PointerTypeT *)cached;
	    else
		r->union_SymbolOrSymbolRef.pointerType = uncached = \
		    d_symbol_to_x_PointerTypeT(s,opts,reftab,depth);
	    r->__union_SymbolOrSymbolRef = \
		SOAP_UNION__vmi1__union_SymbolOrSymbolRef_pointerType;
	    break;
	case DATATYPE_FUNCTION:
	    if (cached)
		r->union_SymbolOrSymbolRef.functionType = \
		    (struct vmi1__FunctionTypeT *)cached;
	    else 
		r->union_SymbolOrSymbolRef.functionType = uncached = \
		    d_symbol_to_x_FunctionTypeT(s,opts,reftab,depth);
	    r->__union_SymbolOrSymbolRef = \
		SOAP_UNION__vmi1__union_SymbolOrSymbolRef_functionType;
	    break;
	case DATATYPE_TYPEDEF:
	    if (cached)
		r->union_SymbolOrSymbolRef.typedefType = \
		    (struct vmi1__TypedefTypeT *)cached;
	    else
		r->union_SymbolOrSymbolRef.typedefType = uncached = \
		    d_symbol_to_x_TypedefTypeT(s,opts,reftab,depth);
	    r->__union_SymbolOrSymbolRef = \
		SOAP_UNION__vmi1__union_SymbolOrSymbolRef_typedefType;
	    break;
	case DATATYPE_UNION:
	    if (cached)
		r->union_SymbolOrSymbolRef.unionType = \
		    (struct vmi1__UnionTypeT *)cached;
	    else
		r->union_SymbolOrSymbolRef.unionType = uncached = \
		    d_symbol_to_x_UnionTypeT(s,opts,reftab,depth);
	    r->__union_SymbolOrSymbolRef = \
		SOAP_UNION__vmi1__union_SymbolOrSymbolRef_unionType;
	    break;
	case DATATYPE_BASE:
	    if (cached)
		r->union_SymbolOrSymbolRef.baseType = \
		    (struct vmi1__BaseTypeT *)cached;
	    else
		r->union_SymbolOrSymbolRef.baseType = uncached = \
		    d_symbol_to_x_BaseTypeT(s,opts,reftab,depth);
	    r->__union_SymbolOrSymbolRef = \
		SOAP_UNION__vmi1__union_SymbolOrSymbolRef_baseType;
	    break;
	case DATATYPE_CONST:
	    if (cached)
		r->union_SymbolOrSymbolRef.constType = \
		    (struct vmi1__ConstTypeT *)cached;
	    else 
		r->union_SymbolOrSymbolRef.constType = uncached = \
		    d_symbol_to_x_ConstTypeT(s,opts,reftab,depth);
	    r->__union_SymbolOrSymbolRef = \
		SOAP_UNION__vmi1__union_SymbolOrSymbolRef_constType;
	    break;
	case DATATYPE_VOL:
	    if (cached)
		r->union_SymbolOrSymbolRef.volatileType = \
		    (struct vmi1__VolatileTypeT *)cached;
	    else
		r->union_SymbolOrSymbolRef.volatileType = uncached = \
		    d_symbol_to_x_VolatileTypeT(s,opts,reftab,depth);
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

    if (reftab && uncached)
	g_hash_table_insert(reftab,(gpointer)s,uncached);

    return r;
}

_vmi1__nestedSymbol *
d_lsymbol_to_x_nestedSymbol(struct lsymbol *ls,
			    struct vmi1__DebugFileOptsT *opts,
			    GHashTable *reftab,int depth) {
    /* Weird that we have to cast here... */
    return (_vmi1__nestedSymbol *) \
	d_symbol_array_list_to_x_SymbolsOrSymbolRefs(ls->chain,
						     opts,reftab,depth);
}

struct vmi1__SymbolsOrSymbolRefs *
d_symbol_array_list_to_x_SymbolsOrSymbolRefs(struct array_list *list,
					     struct vmi1__DebugFileOptsT *opts,
					     GHashTable *reftab,int depth) {
    int i;
    int len = array_list_len(list);
    struct symbol *s;
    gpointer cached = NULL;
    gpointer uncached = NULL;
    struct vmi1__SymbolsOrSymbolRefs *r;
    char idbuf[16];
#if V_GSOAP_VERSION_MAJOR >= 2 && V_GSOAP_VERSION_MINOR >= 8
    union _vmi1__union_SymbolsOrSymbolRefs_ *ui;
#else
    union _vmi1__union_SymbolsOrSymbolRefs *ui;
#endif
    int *uw;

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
	    snprintf(idbuf,16,"%d",(s)->ref);
	    r->symbolRef[i] = strdup(idbuf);
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
	uncached = NULL;
	if (reftab)
	    cached = g_hash_table_lookup(reftab,(gpointer)s);

	if (SYMBOL_IS_VAR(s)) {
	    if (cached) 
		ui->variable = (struct vmi1__VariableT *)cached;
	    else
		ui->variable = uncached = \
		    d_symbol_to_x_VariableT(s,opts,reftab,depth);
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
		ui->function = uncached = \
		    d_symbol_to_x_FunctionT(s,opts,reftab,depth);
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
		ui->label = uncached =	\
		    d_symbol_to_x_LabelT(s,opts,reftab,depth);
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
		    ui->voidType = uncached =	\
			d_symbol_to_x_VoidTypeT(s,opts,reftab,depth);
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
		    ui->arrayType = uncached =	\
			d_symbol_to_x_ArrayTypeT(s,opts,reftab,depth);
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
		    ui->structType = uncached =	\
			d_symbol_to_x_StructTypeT(s,opts,reftab,depth);
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
		    ui->enumType = uncached =	\
			d_symbol_to_x_EnumTypeT(s,opts,reftab,depth);
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
		    ui->pointerType = uncached =	\
			d_symbol_to_x_PointerTypeT(s,opts,reftab,depth);
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
		    ui->functionType = uncached = \
			d_symbol_to_x_FunctionTypeT(s,opts,reftab,depth);
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
		    ui->typedefType = uncached =	\
			d_symbol_to_x_TypedefTypeT(s,opts,reftab,depth);
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
		    ui->unionType = uncached =	\
			d_symbol_to_x_UnionTypeT(s,opts,reftab,depth);
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
		    ui->baseType = uncached =	\
			d_symbol_to_x_BaseTypeT(s,opts,reftab,depth);
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
		    ui->constType = uncached =	\
			d_symbol_to_x_ConstTypeT(s,opts,reftab,depth);
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
		    ui->volatileType = uncached = \
			d_symbol_to_x_VolatileTypeT(s,opts,reftab,depth);
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

	if (uncached && reftab)
	    g_hash_table_insert(reftab,(gpointer)s,uncached);
    }

    return r;
}

