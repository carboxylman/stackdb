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

static struct vmi1__DebugFileOptsT defDebugFileOpts = {
    .symbolRefDepth = 1,
    .symtabRefDepth = 1,
    .doMultiRef = 0,
    .doManualRef = 0,
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

#define FILL_SYMBOLHEADER(s,r)						\
    do {								\
	int _rc;							\
	char *_name;							\
	char _idbuf[16];						\
	int _idblen = 16;						\
									\
	_rc = snprintf(_idbuf,_idblen,"%d",(s)->ref);			\
	_rc = (_rc > _idblen) ? _idblen : (_rc + 1);			\
	(r)->sid = _soap_calloc(soap,_rc);				\
	strncpy((r)->sid,_idbuf,_rc);					\
	if (symbol_get_name(s)) {					\
	    _name = symbol_get_name((s));				\
	    _rc = strlen(_name) + 1;					\
	    (r)->name = _soap_calloc(soap,_rc);				\
	    strncpy((r)->name,_name,_rc);				\
	}								\
    } while (0);

#define FILL_SYMBOLCOMMON(typename,s,r)					\
    (r)->source = _soap_calloc(soap,1*sizeof(*(r)->source));		\
    if (SYMBOL_IS_DWARF((s)))						\
	*(r)->source = _vmi1__source__dwarf;				\
    else if (SYMBOL_IS_ELF((s)))					\
	*(r)->source = _vmi1__source__elf;				\
    (r)->declaration = _soap_calloc(soap,1*sizeof(*(r)->declaration));  \
    (r)->declaration->isExternal = (enum xsd__boolean)((s)->isexternal & 1); \
    (r)->declaration->isDeclaration = (enum xsd__boolean)((s)->isdeclaration & 1); \
    (r)->declaration->isPrototyped = (enum xsd__boolean)((s)->isprototyped & 1); \
    if ((s)->size_is_bytes || (s)->size_is_bits) {			\
	(r)->byteSize = _soap_calloc(soap,sizeof(*(r)->byteSize));	\
	*(r)->byteSize = symbol_bytesize((s));				\
    }									\
    if ((s)->size_is_bits) {						\
	(r)->__size_ ## typename ## _sequence = 1;			\
	(r)->__ ## typename ## _sequence =				\
	    _soap_calloc(soap,sizeof(*(r)->__ ## typename ## _sequence)); \
	(r)->__ ## typename ## _sequence->bitSize =			\
	    _soap_calloc(soap,sizeof(*(r)->__ ## typename ## _sequence->bitSize)); \
	*(r)->__ ## typename ## _sequence->bitSize = symbol_bitsize(s);	\
	(r)->__ ## typename ## _sequence->bitOffset =			\
	    _soap_calloc(soap,sizeof(*(r)->__ ## typename ## _sequence->bitOffset)); \
	*(r)->__ ## typename ## _sequence->bitOffset = s->size.offset;	\
	(r)->__ ## typename ## _sequence->containingTypeByteSize =	\
	    _soap_calloc(soap,sizeof(*(r)->__ ## typename ## _sequence->containingTypeByteSize)); \
	*(r)->__ ## typename ## _sequence->containingTypeByteSize =	\
	    s->size.ctbytes;						\
    }

#define FILL_SYMBOLTYPE(s,r)						\
    if ((s)->datatype)							\
	(r)->type = d_symbol_to_x_SymbolT(soap,(s)->datatype,(opts),	\
					  (reftab),(depth)+1);
    
#define FILL_INSTANCESYMBOLCONTENTS(s,opts,reftab,depth,r)		\
    if ((s)->has_base_addr) {						\
       (r)->addr = _soap_calloc(soap,sizeof(*(r)->addr));		\
       *(r)->addr = s->base_addr;					\
    }			 	      					\
    /* XXX: do constValue!!! */						\
    (r)->inline_ = _soap_calloc(soap,sizeof(*(r)->inline_));		\
    if (SYMBOL_IS_FULL((s)) && (s)->s.ii->origin) {			\
	r->inline_->origin =						\
	    d_symbol_to_x_SymbolT(soap,(s)->s.ii->origin,(opts),	\
				  (reftab),(depth)+1);			\
    }									\
    (r)->inline_->isInlineInstance = (enum xsd__boolean)		\
	(s->isinlineinstance & 1);					\
    if (SYMBOL_IS_FULL((s))) {						\
	(r)->inline_->isDeclaredInline = (enum xsd__boolean)		\
	    ((s)->s.ii->isdeclinline & 1);				\
	(r)->inline_->isInlined = (enum xsd__boolean)			\
	    ((s)->s.ii->isinlined & 1);					\
    }									\
    if (SYMBOL_IS_FULL((s)) && (s)->s.ii->inline_instances		\
	&& array_list_len((s)->s.ii->inline_instances)) {		\
	(r)->inline_->instances =					\
	    d_symbol_array_list_to_x_SymbolsT(soap,			\
					      (s)->s.ii->inline_instances, \
					      (opts),(reftab),(depth)+1); \
    }

#define RETURN_REF_OR_ALLOC(objtype,s,opts,reftab,depth,r)		\
    do {								\
        typeof(r) _r = NULL;						\
	int _rc;							\
	char *_name;							\
	char _idbuf[16];						\
	int _idblen = 16;						\
									\
	/*								\
	 * If it is in the reftab, and if multi-ref encoding is enabled,\
	 * or we have reached the max depth but manual multi-ref is	\
	 * disabled (or we haven't reached the max depth), just return  \
	 * the gsoap serialization struct we already encoded for this	\
	 * symbol so gsoap can fully render it again.			\
	 */								\
        if (reftab							\
	    && (_r = (typeof(r))g_hash_table_lookup(reftab,(gpointer)s)) \
	    && ((opts)->doMultiRef					\
		|| (depth < (opts)-> objtype ## RefDepth		\
		    && !(opts)->doManualRef))) {			\
									\
	    if (!(r)) {							\
		vdebug(5,LOG_X_XML,					\
		       "reusing encoded %s(%"PRIiSMOFFSET") at (d=%d,%d/%d)" \
		       " (multiref=%d)\n",				\
		       objtype ## _get_name(s),(s)->ref,depth,		\
		       (opts)->symbolRefDepth,(opts)->symtabRefDepth,	\
		       (opts)->doMultiRef);				\
		  							\
		return (typeof(r))_r;					\
	    }								\
	    else {							\
		/* Must memcpy contents into existing buffer. */	\
		vdebug(5,LOG_X_XML,					\
		       "copying encoded %s(%"PRIiSMOFFSET") at (d=%d,%d/%d)" \
		       " (multiref=%d)\n",				\
		       objtype ## _get_name(s),(s)->ref,depth,		\
		       (opts)->symbolRefDepth,(opts)->symtabRefDepth,	\
		       (opts)->doMultiRef);				\
									\
		memcpy(r,_r,sizeof(r));					\
									\
		return (typeof(r))_r;					\
	    }								\
	}								\
	else {								\
	    /*								\
	     * Need to encode it as a ref and return immediately.	\
	     */								\
	    if (_r && ((opts)->doManualRef)) {				\
		if (!(r))						\
		    (r) = _soap_calloc(soap,sizeof(*(r)));		\
									\
		_rc = snprintf(_idbuf,_idblen,"%d",(s)->ref);		\
		_rc = (_rc > _idblen) ? _idblen : (_rc + 1);		\
		(r)->sref = _soap_calloc(soap,_rc);			\
		strncpy((r)->sref,_idbuf,_rc);				\
									\
		vdebug(5,LOG_X_XML,					\
		       "encoding manual ref for %s(%"PRIiSMOFFSET")"    \
		       " at (d=%d,%d/%d)\n",				\
		       objtype ## _get_name(s),s->ref,depth,		\
		       opts->symbolRefDepth,opts->symtabRefDepth);	\
									\
		return (typeof(r))r;					\
	    }								\
	    else if (depth >= (opts)-> objtype ## RefDepth) {		\
		if (!(r))						\
		    (r) = _soap_calloc(soap,sizeof(*(r)));		\
									\
		_rc = snprintf(_idbuf,_idblen,"%d",(s)->ref);		\
		_rc = (_rc > _idblen) ? _idblen : (_rc + 1);		\
		(r)->sref = _soap_calloc(soap,_rc);			\
		strncpy((r)->sref,_idbuf,_rc);				\
									\
		if (objtype ## _get_name(s)) {				\
		    _name = objtype ## _get_name((s));			\
		    _rc = strlen(_name) + 1;				\
		    (r)->name = _soap_calloc(soap,_rc);			\
		    strncpy((r)->name,_name,_rc);			\
		}							\
									\
		vdebug(5,LOG_X_XML,					\
		       "encoding fetchable ref for %s(%"PRIiSMOFFSET")" \
		       " at (d=%d,%d/%d)\n",				\
		       objtype ## _get_name(s),s->ref,depth,		\
		       opts->symbolRefDepth,opts->symtabRefDepth);	\
									\
		return (typeof(r))r;					\
	    }								\
	    /*								\
	     * Need to fully encode it, so just malloc it, place it in  \ 
	     * the reftab, and let caller take over.			\
	     */								\
	    else {							\
		if (!(r))						\
		    (r) = _soap_calloc(soap,sizeof(*(r)));		\
									\
		vdebug(5,LOG_X_XML,					\
		       "encoding full %s(%"PRIiSMOFFSET")"		\
		       " at (d=%d,%d/%d)\n",				\
		       objtype ## _get_name(s),s->ref,depth,		\
		       opts->symbolRefDepth,opts->symtabRefDepth);	\
									\
		if (reftab)						\
		    g_hash_table_insert(reftab,(gpointer)s,(gpointer)r);\
	    }								\
	}								\
    } while (0);

struct vmi1__VariableT *
d_symbol_to_x_VariableT(struct soap *soap,struct symbol *s,
			struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			int depth) {
    struct vmi1__VariableT *r = NULL;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,s,opts,reftab,depth,r);

    FILL_SYMBOLHEADER(s,r);
    FILL_SYMBOLCOMMON(VariableT,s,r);
    FILL_SYMBOLTYPE(s,r);

    r->kind = _soap_calloc(soap,sizeof(*r->kind));
    if (s->isparam)
	*r->kind = _vmi1__kind__parameter;
    else if (s->ismember)
	*r->kind = _vmi1__kind__member;
    else if (s->isenumval)
	*r->kind = _vmi1__kind__enumerator;
    else
	*r->kind = _vmi1__kind__variable;

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
    struct vmi1__FunctionT *r = NULL;
    struct symbol *arg;
    struct symbol_instance *argi;
    struct array_list *gslist;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,s,opts,reftab,depth,r);

    FILL_SYMBOLHEADER(s,r);
    FILL_SYMBOLCOMMON(FunctionT,s,r);
    FILL_SYMBOLTYPE(s,r);

    if (SYMBOL_IS_FULL(s)) {
	r->argCount = _soap_calloc(soap,sizeof(*r->argCount));
	*r->argCount = s->s.ii->d.f.count;
	r->hasUnspecifiedParams = \
	    _soap_calloc(soap,sizeof(*r->hasUnspecifiedParams));
	*r->hasUnspecifiedParams = \
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
	    list_for_each_entry(argi,&s->s.ii->d.f.args,d.v.member) {
		arg = argi->d.v.member_symbol;
		array_list_append(gslist,arg);
	    }
	    r->arguments = \
		d_symbol_array_list_to_x_SymbolsOptT(soap,gslist,
						     opts,reftab,depth+1);
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
    struct vmi1__LabelT *r = NULL;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,s,opts,reftab,depth,r);

    FILL_SYMBOLHEADER(s,r);
    FILL_SYMBOLCOMMON(LabelT,s,r);
    FILL_INSTANCESYMBOLCONTENTS(s,opts,reftab,depth,r);

    return r;
}

struct vmi1__VoidTypeT *
d_symbol_to_x_VoidTypeT(struct soap *soap,struct symbol *s,
			struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			int depth) {
    struct vmi1__VoidTypeT *r = NULL;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,s,opts,reftab,depth,r);

    FILL_SYMBOLHEADER(s,r);
    FILL_SYMBOLCOMMON(VoidTypeT,s,r);

    return r;
}

struct vmi1__BaseTypeT *
d_symbol_to_x_BaseTypeT(struct soap *soap,struct symbol *s,
			struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			int depth) {
    struct vmi1__BaseTypeT *r = NULL;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,s,opts,reftab,depth,r);

    FILL_SYMBOLHEADER(s,r);
    FILL_SYMBOLCOMMON(BaseTypeT,s,r);

    if (SYMBOL_IS_FULL(s)) {
	r->encoding = _soap_calloc(soap,sizeof(*r->encoding));
	switch (s->s.ti->d.t.encoding) {
	case ENCODING_ADDRESS:
	    *r->encoding = _vmi1__encoding__address;
	    break;
	case ENCODING_BOOLEAN:
	    *r->encoding = _vmi1__encoding__boolean;
	    break;
	case ENCODING_COMPLEX_FLOAT:
	    *r->encoding = _vmi1__encoding__complexFloat;
	    break;
	case ENCODING_FLOAT:
	    *r->encoding = _vmi1__encoding__float_;
	    break;
	case ENCODING_SIGNED:
	    *r->encoding = _vmi1__encoding__signed_;
	    break;
	case ENCODING_SIGNED_CHAR:
	    *r->encoding = _vmi1__encoding__signedChar;
	    break;
	case ENCODING_UNSIGNED:
	    *r->encoding = _vmi1__encoding__unsigned_;
	    break;
	case ENCODING_UNSIGNED_CHAR:
	    *r->encoding = _vmi1__encoding__unsignedChar;
	    break;
	case ENCODING_IMAGINARY_FLOAT:
	    *r->encoding = _vmi1__encoding__imaginaryFloat;
	    break;
	case ENCODING_PACKED_DECIMAL:
	    *r->encoding = _vmi1__encoding__packedDecimal;
	    break;
	case ENCODING_NUMERIC_STRING:
	    *r->encoding = _vmi1__encoding__numericString;
	    break;
	case ENCODING_EDITED:
	    *r->encoding = _vmi1__encoding__edited;
	    break;
	case ENCODING_SIGNED_FIXED:
	    *r->encoding = _vmi1__encoding__signedFixed;
	    break;
	case ENCODING_UNSIGNED_FIXED:
	    *r->encoding = _vmi1__encoding__unsignedFixed;
	    break;
	default:
	    *r->encoding = _vmi1__encoding__unknown;
	    break;
	}
    }

    return r;
}

struct vmi1__PointerTypeT *
d_symbol_to_x_PointerTypeT(struct soap *soap,struct symbol *s,
			   struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			   int depth) {
    struct vmi1__PointerTypeT *r = NULL;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,s,opts,reftab,depth,r);

    FILL_SYMBOLHEADER(s,r);
    FILL_SYMBOLCOMMON(PointerTypeT,s,r);
    FILL_SYMBOLTYPE(s,r);

    return r;
}

struct vmi1__TypedefTypeT *
d_symbol_to_x_TypedefTypeT(struct soap *soap,struct symbol *s,
			  struct vmi1__DebugFileOptsT *opts,
			  GHashTable *reftab,int depth) {
    struct vmi1__TypedefTypeT *r = NULL;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,s,opts,reftab,depth,r);

    FILL_SYMBOLHEADER(s,r);
    FILL_SYMBOLCOMMON(TypedefTypeT,s,r);
    FILL_SYMBOLTYPE(s,r);

    return r;
}

struct vmi1__ConstTypeT *
d_symbol_to_x_ConstTypeT(struct soap *soap,struct symbol *s,
			struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			int depth) {
    struct vmi1__ConstTypeT *r = NULL;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,s,opts,reftab,depth,r);

    FILL_SYMBOLHEADER(s,r);
    FILL_SYMBOLCOMMON(ConstTypeT,s,r);
    FILL_SYMBOLTYPE(s,r);

    return r;
}

struct vmi1__VolatileTypeT *
d_symbol_to_x_VolatileTypeT(struct soap *soap,struct symbol *s,
			   struct vmi1__DebugFileOptsT *opts,
			   GHashTable *reftab,int depth) {
    struct vmi1__VolatileTypeT *r = NULL;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,s,opts,reftab,depth,r);

    FILL_SYMBOLHEADER(s,r);
    FILL_SYMBOLCOMMON(VolatileTypeT,s,r);
    FILL_SYMBOLTYPE(s,r);

    return r;
}

struct vmi1__ArrayTypeT *
d_symbol_to_x_ArrayTypeT(struct soap *soap,struct symbol *s,
			struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			int depth) {
    struct vmi1__ArrayTypeT *r = NULL;
    int i;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,s,opts,reftab,depth,r);

    FILL_SYMBOLHEADER(s,r);
    FILL_SYMBOLCOMMON(ArrayTypeT,s,r);
    FILL_SYMBOLTYPE(s,r);

    r->subrangeCount = _soap_calloc(soap,sizeof(*r->subrangeCount));
    *r->subrangeCount = s->s.ti->d.a.count;
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
    struct vmi1__EnumTypeT *r = NULL;
    struct symbol_instance *tmpi;
    struct symbol *tmps;
    struct array_list *gslist;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,s,opts,reftab,depth,r);

    FILL_SYMBOLHEADER(s,r);
    FILL_SYMBOLCOMMON(EnumTypeT,s,r);
    FILL_SYMBOLTYPE(s,r);

    r->memberCount = _soap_calloc(soap,sizeof(*r->memberCount));
    *r->memberCount = s->s.ti->d.e.count;
    if (s->s.ti->d.e.count) {
	gslist = array_list_create(s->s.ti->d.e.count);
	list_for_each_entry(tmpi,&s->s.ti->d.e.members,d.v.member) {
	    tmps = tmpi->d.v.member_symbol;
	    array_list_append(gslist,tmps);
	}
	r->members = d_symbol_array_list_to_x_SymbolsT(soap,gslist,
						       opts,reftab,depth+1);
	array_list_free(gslist);
    }

    return r;
}

struct vmi1__StructTypeT *
d_symbol_to_x_StructTypeT(struct soap *soap,struct symbol *s,
			 struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			 int depth) {
    struct vmi1__StructTypeT *r = NULL;
    struct symbol_instance *tmpi;
    struct symbol *tmps;
    struct array_list *gslist;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,s,opts,reftab,depth,r);

    FILL_SYMBOLHEADER(s,r);
    FILL_SYMBOLCOMMON(StructTypeT,s,r);
    FILL_SYMBOLTYPE(s,r);

    r->memberCount = _soap_calloc(soap,sizeof(*r->memberCount));
    *r->memberCount = s->s.ti->d.su.count;
    if (s->s.ti->d.su.count) {
	gslist = array_list_create(s->s.ti->d.su.count);
	list_for_each_entry(tmpi,&s->s.ti->d.su.members,d.v.member) {
	    tmps = tmpi->d.v.member_symbol;
	    array_list_append(gslist,tmps);
	}
	r->members = (struct vmi1__SymbolsOptT *)			\
	    d_symbol_array_list_to_x_SymbolsT(soap,gslist,opts,reftab,depth+1);
	array_list_free(gslist);
    }

    return r;
}

struct vmi1__UnionTypeT *
d_symbol_to_x_UnionTypeT(struct soap *soap,struct symbol *s,
			struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			int depth) {
    struct vmi1__UnionTypeT *r = NULL;
    struct symbol_instance *tmpi;
    struct symbol *tmps;
    struct array_list *gslist;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,s,opts,reftab,depth,r);

    FILL_SYMBOLHEADER(s,r);
    FILL_SYMBOLCOMMON(UnionTypeT,s,r);
    FILL_SYMBOLTYPE(s,r);

    r->memberCount = _soap_calloc(soap,sizeof(*r->memberCount));
    *r->memberCount = s->s.ti->d.su.count;
    if (s->s.ti->d.su.count) {
	gslist = array_list_create(s->s.ti->d.su.count);
	list_for_each_entry(tmpi,&s->s.ti->d.su.members,d.v.member) {
	    tmps = tmpi->d.v.member_symbol;
	    array_list_append(gslist,tmps);
	}
	r->members = (struct vmi1__SymbolsOptT *)			\
	    d_symbol_array_list_to_x_SymbolsT(soap,gslist,opts,reftab,depth+1);
	array_list_free(gslist);
    }

    return r;
}

struct vmi1__FunctionTypeT *
d_symbol_to_x_FunctionTypeT(struct soap *soap,struct symbol *s,
			   struct vmi1__DebugFileOptsT *opts,
			   GHashTable *reftab,int depth) {
    struct vmi1__FunctionTypeT *r = NULL;
    struct symbol_instance *tmpi;
    struct symbol *tmps;
    struct array_list *gslist;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,s,opts,reftab,depth,r);

    FILL_SYMBOLHEADER(s,r);
    FILL_SYMBOLCOMMON(FunctionTypeT,s,r);
    FILL_SYMBOLTYPE(s,r);

    r->argCount = _soap_calloc(soap,sizeof(*r->argCount));
    *r->argCount = s->s.ti->d.f.count;
    if (s->s.ti->d.f.count) {
	gslist = array_list_create(s->s.ti->d.f.count);
	list_for_each_entry(tmpi,&s->s.ti->d.f.args,d.v.member) {
	    tmps = tmpi->d.v.member_symbol;
	    array_list_append(gslist,tmps);
	}
	r->arguments = (struct vmi1__SymbolsOptT *)			\
	    d_symbol_array_list_to_x_SymbolsT(soap,gslist,opts,reftab,depth+1);
	array_list_free(gslist);
    }
    r->hasUnspecifiedParams = \
	_soap_calloc(soap,sizeof(*r->hasUnspecifiedParams));
    if (s->s.ti->d.f.hasunspec) 
	*r->hasUnspecifiedParams = xsd__boolean__true_;
    else
	*r->hasUnspecifiedParams = xsd__boolean__false_;

    return r;
}

struct vmi1__SymbolT *
d_symbol_to_x_SymbolT(struct soap *soap,struct symbol *s,
		      struct vmi1__DebugFileOptsT *opts,
		      GHashTable *reftab,int depth) {
    struct vmi1__SymbolT *r;

    if (!opts)
	opts = &defDebugFileOpts;

    r = (struct vmi1__SymbolT *)_soap_calloc(soap,sizeof(*r));

    if (SYMBOL_IS_VAR(s)) {
	r->union_SymbolT.variable =					\
	    d_symbol_to_x_VariableT(soap,s,opts,reftab,depth);
	r->__union_SymbolT =				\
	    SOAP_UNION__vmi1__union_SymbolT_variable;
    }
    else if (SYMBOL_IS_FUNCTION(s)) {
	r->union_SymbolT.function =					\
	    d_symbol_to_x_FunctionT(soap,s,opts,reftab,depth);
	r->__union_SymbolT =				\
	    SOAP_UNION__vmi1__union_SymbolT_function;
    }
    else if (SYMBOL_IS_LABEL(s)) {
	r->union_SymbolT.label =				\
	    d_symbol_to_x_LabelT(soap,s,opts,reftab,depth);
	r->__union_SymbolT =				\
	    SOAP_UNION__vmi1__union_SymbolT_label;
    }
    else if (SYMBOL_IS_TYPE(s)) {
	switch (s->datatype_code) {
	case DATATYPE_VOID:
	    r->union_SymbolT.voidType =					\
		d_symbol_to_x_VoidTypeT(soap,s,opts,reftab,depth);
	    r->__union_SymbolT =				\
		SOAP_UNION__vmi1__union_SymbolT_voidType;
	    break;
	case DATATYPE_ARRAY:
	    r->union_SymbolT.arrayType =				\
		d_symbol_to_x_ArrayTypeT(soap,s,opts,reftab,depth);
	    r->__union_SymbolT =				\
		SOAP_UNION__vmi1__union_SymbolT_arrayType;
	    break;
	case DATATYPE_STRUCT:
	    r->union_SymbolT.structType =				\
		d_symbol_to_x_StructTypeT(soap,s,opts,reftab,depth);
	    r->__union_SymbolT = \
		SOAP_UNION__vmi1__union_SymbolT_structType;
	    break;
	case DATATYPE_ENUM:
	    r->union_SymbolT.enumType =					\
		d_symbol_to_x_EnumTypeT(soap,s,opts,reftab,depth);
	    r->__union_SymbolT =				\
		SOAP_UNION__vmi1__union_SymbolT_enumType;
	    break;
	case DATATYPE_PTR:
	    r->union_SymbolT.pointerType =				\
		d_symbol_to_x_PointerTypeT(soap,s,opts,reftab,depth);
	    r->__union_SymbolT =				\
		SOAP_UNION__vmi1__union_SymbolT_pointerType;
	    break;
	case DATATYPE_FUNCTION:
	    r->union_SymbolT.functionType =				\
		d_symbol_to_x_FunctionTypeT(soap,s,opts,reftab,depth);
	    r->__union_SymbolT =				\
		SOAP_UNION__vmi1__union_SymbolT_functionType;
	    break;
	case DATATYPE_TYPEDEF:
	    r->union_SymbolT.typedefType =				\
		d_symbol_to_x_TypedefTypeT(soap,s,opts,reftab,depth);
	    r->__union_SymbolT =				\
		SOAP_UNION__vmi1__union_SymbolT_typedefType;
	    break;
	case DATATYPE_UNION:
	    r->union_SymbolT.unionType =				\
		d_symbol_to_x_UnionTypeT(soap,s,opts,reftab,depth);
	    r->__union_SymbolT =				\
		SOAP_UNION__vmi1__union_SymbolT_unionType;
	    break;
	case DATATYPE_BASE:
	    r->union_SymbolT.baseType =					\
		d_symbol_to_x_BaseTypeT(soap,s,opts,reftab,depth);
	    r->__union_SymbolT =				\
		SOAP_UNION__vmi1__union_SymbolT_baseType;
	    break;
	case DATATYPE_CONST:
	    r->union_SymbolT.constType =				\
		d_symbol_to_x_ConstTypeT(soap,s,opts,reftab,depth);
	    r->__union_SymbolT =				\
		SOAP_UNION__vmi1__union_SymbolT_constType;
	    break;
	case DATATYPE_VOL:
	    r->union_SymbolT.volatileType =				\
		d_symbol_to_x_VolatileTypeT(soap,s,opts,reftab,depth);
	    r->__union_SymbolT =				\
		SOAP_UNION__vmi1__union_SymbolT_volatileType;
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
    return (_vmi1__nestedSymbol *) \
	d_symbol_array_list_to_x_SymbolsT(soap,ls->chain,
					  opts,reftab,depth);
}

struct vmi1__SymbolsT *
d_symbol_array_list_to_x_SymbolsT(struct soap *soap,
				  struct array_list *list,
				  struct vmi1__DebugFileOptsT *opts,
				  GHashTable *reftab,int depth) {
    int i;
    int len = array_list_len(list);
    struct symbol *s;
    struct vmi1__SymbolsT *r;
    union _vmi1__union_SymbolsT *ui;
    int *uw;

    if (!opts)
	opts = &defDebugFileOpts;

    r = _soap_calloc(soap,sizeof(*r));

    r->__size_SymbolsT = len;
    r->__union_SymbolsT = _soap_calloc(soap,len*sizeof(*r->__union_SymbolsT));

    for (i = 0; i < len; ++i) {
	s = (struct symbol *)array_list_item(list,i);

	uw = &r->__union_SymbolsT[i].__union_SymbolsT;
	ui = &r->__union_SymbolsT[i].union_SymbolsT;

	if (SYMBOL_IS_VAR(s)) {
	    ui->variable =						\
		d_symbol_to_x_VariableT(soap,s,opts,reftab,depth);
	    *uw = SOAP_UNION__vmi1__union_SymbolsT_variable;
	}
	else if (SYMBOL_IS_FUNCTION(s)) {
	    ui->function =						\
		d_symbol_to_x_FunctionT(soap,s,opts,reftab,depth);
	    *uw = SOAP_UNION__vmi1__union_SymbolsT_function;
	}
	else if (SYMBOL_IS_LABEL(s)) {
	    ui->label =							\
		d_symbol_to_x_LabelT(soap,s,opts,reftab,depth);
	    *uw = SOAP_UNION__vmi1__union_SymbolsT_label;
	}
	else if (SYMBOL_IS_TYPE(s)) {
	    switch (s->datatype_code) {
	    case DATATYPE_VOID:
		ui->voidType =						\
		    d_symbol_to_x_VoidTypeT(soap,s,opts,reftab,depth);
		*uw = SOAP_UNION__vmi1__union_SymbolsT_voidType;
		break;
	    case DATATYPE_ARRAY:
		ui->arrayType =						\
		    d_symbol_to_x_ArrayTypeT(soap,s,opts,reftab,depth);
		*uw = SOAP_UNION__vmi1__union_SymbolsT_arrayType;
		break;
	    case DATATYPE_STRUCT:
		ui->structType =					\
		    d_symbol_to_x_StructTypeT(soap,s,opts,reftab,depth);
		*uw = SOAP_UNION__vmi1__union_SymbolsT_structType;
		break;
	    case DATATYPE_ENUM:
		ui->enumType =						\
		    d_symbol_to_x_EnumTypeT(soap,s,opts,reftab,depth);
		*uw = SOAP_UNION__vmi1__union_SymbolsT_enumType;
		break;
	    case DATATYPE_PTR:
		ui->pointerType =					\
		    d_symbol_to_x_PointerTypeT(soap,s,opts,reftab,depth);
		*uw = SOAP_UNION__vmi1__union_SymbolsT_pointerType;
		break;
	    case DATATYPE_FUNCTION:
		ui->functionType =					\
		    d_symbol_to_x_FunctionTypeT(soap,s,opts,reftab,depth);
		*uw = SOAP_UNION__vmi1__union_SymbolsT_functionType;
		break;
	    case DATATYPE_TYPEDEF:
		ui->typedefType =					\
		    d_symbol_to_x_TypedefTypeT(soap,s,opts,reftab,depth);
		*uw = SOAP_UNION__vmi1__union_SymbolsT_typedefType;
		break;
	    case DATATYPE_UNION:
		ui->unionType =						\
		    d_symbol_to_x_UnionTypeT(soap,s,opts,reftab,depth);
		*uw = SOAP_UNION__vmi1__union_SymbolsT_unionType;
		break;
	    case DATATYPE_BASE:
		ui->baseType =						\
		    d_symbol_to_x_BaseTypeT(soap,s,opts,reftab,depth);
		*uw = SOAP_UNION__vmi1__union_SymbolsT_baseType;
		break;
	    case DATATYPE_CONST:
		ui->constType =						\
		    d_symbol_to_x_ConstTypeT(soap,s,opts,reftab,depth);
		*uw = SOAP_UNION__vmi1__union_SymbolsT_constType;
		break;
	    case DATATYPE_VOL:
		ui->volatileType =					\
		    d_symbol_to_x_VolatileTypeT(soap,s,opts,reftab,depth);
		*uw = SOAP_UNION__vmi1__union_SymbolsT_volatileType;
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

struct vmi1__SymbolsOptT *
d_symbol_array_list_to_x_SymbolsOptT(struct soap *soap,
				     struct array_list *list,
				     struct vmi1__DebugFileOptsT *opts,
				     GHashTable *reftab,int depth) {
    /*
     * This is nasty.  We just return a vmi1__SymbolsT because gSOAP
     * gives us the same C structs/unions/enums types for
     * vmi1__SymbolsOptT as vmi1__SymbolsT.
     *
     * It just saves some code.
     */
    return (struct vmi1__SymbolsOptT *) \
        d_symbol_array_list_to_x_SymbolsT(soap,list,opts,reftab,depth);
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

    d_symbol_array_list_to_x_SymbolsT(soap,gslist,
						 opts,reftab,depth);

    array_list_free(gslist);

    return r;
}

struct vmi1__SymtabT *
d_symtab_to_x_SymtabT(struct soap *soap,struct symtab *st,
		      struct vmi1__DebugFileOptsT *opts,
		      GHashTable *reftab,int depth,
		      struct vmi1__SymtabT *ir) {
    struct vmi1__SymtabT *r = NULL;
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

    RETURN_REF_OR_ALLOC(symtab,st,opts,reftab,depth,r);

    rc = snprintf(idbuf,idblen,"%d",st->ref);
    rc = (rc > idblen) ? idblen : (rc + 1);
    r->sid = _soap_calloc(soap,rc);
    strncpy(r->sid,idbuf,rc);
    SOAP_STRCPY(soap,r->name,st->name);

    r->ranges = d_range_to_x_RangesT(soap,&st->range,opts,reftab,depth);

    if (st->meta) {
	r->rootMeta = _soap_calloc(soap,sizeof(*r->rootMeta));
	SOAP_STRCPY(soap,r->rootMeta->compilationDir,st->meta->compdirname);
	SOAP_STRCPY(soap,r->rootMeta->producer,st->meta->producer);
	SOAP_STRCPY(soap,r->rootMeta->language,st->meta->language);
    }

    if (st->parent) 
	r->parent = \
	    d_symtab_to_x_SymtabT(soap,st->parent,opts,reftab,depth+1,NULL);

    len = 0;
    list_for_each(pos,&st->subtabs) 
	++len;

    r->symtabs = _soap_calloc(soap,sizeof(r->symtabs));
    r->symtabs->__sizesymtab = len;
    r->symtabs->symtab = _soap_calloc(soap,len*sizeof(*r->symtabs->symtab));

    i = 0;
    list_for_each_entry(symtab,&st->subtabs,member) {
	d_symtab_to_x_SymtabT(soap,symtab,opts,reftab,depth+1,
			      &r->symtabs->symtab[i]);
	++i;
    }

    /* Make a tmp array list of the symbols */
    gslist = array_list_create(g_hash_table_size(st->tab));
    g_hash_table_iter_init(&iter,st->tab);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer)&symbol))
	array_list_append(gslist,symbol);
    r->symbols = \
	d_symbol_array_list_to_x_SymbolsOptT(soap,gslist,opts,reftab,depth);
    array_list_free(gslist);

    /* Make a tmp array list of the anon symbols */
    gslist = array_list_create(g_hash_table_size(st->anontab));
    g_hash_table_iter_init(&iter,st->anontab);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer)&symbol))
	array_list_append(gslist,symbol);
    r->anonSymbols = \
	d_symbol_array_list_to_x_SymbolsOptT(soap,gslist,opts,reftab,depth);
    array_list_free(gslist);

    return r;
}
