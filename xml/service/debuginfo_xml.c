/*
 * Copyright (c) 2012, 2013 The University of Utah
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
#include "util.h"

static struct vmi1__DebugFileOptsT defDebugFileOpts = {
    .debugfileRefDepth = 1,
    .symbolRefDepth = 1,
    .symtabRefDepth = 1,
    .doMultiRef = 0,
    .doManualRef = 0,
};

static void *_soap_calloc(struct soap *soap,size_t size) {
    void *r;

    r = soap_malloc(soap,size);
    memset(r,0,size);

    return r;
}

struct vmi1__LocationT *
d_location_to_x_LocationT(struct soap *soap,struct location *l,
			  struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			  struct array_list *refstack,int depth) {
    struct vmi1__LocationT *vl;
    int i;

    vl = _soap_calloc(soap,1*sizeof(*vl));

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
					  opts,reftab,refstack,depth);
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
		     struct array_list *refstack,int depth) {
    struct vmi1__RangesT *vr;
    int i;

    if (!opts)
	opts = &defDebugFileOpts;

    if (r->rtype == RANGE_TYPE_NONE)
	return NULL;

    vr = _soap_calloc(soap,1*sizeof(*vr));

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
    do {								\
        struct __vmi1__ ## typename ## _sequence *guts;			\
	struct _vmi1__declaration *_decl;				\
	struct vmi1__SizeT *_size;					\
									\
	guts = (r)->__ ## typename ## _sequence;			\
									\
	if (SYMBOL_IS_DWARF((s)))					\
	    guts->source = _vmi1__source__dwarf;			\
	else if (SYMBOL_IS_ELF((s)))					\
	    guts->source = _vmi1__source__elf;				\
									\
	_decl = _soap_calloc(soap,sizeof(*_decl));			\
	_decl->isExternal = (enum xsd__boolean)((s)->isexternal & 1);	\
	_decl->isDeclaration = (enum xsd__boolean)((s)->isdeclaration & 1); \
	_decl->isPrototyped = (enum xsd__boolean)((s)->isprototyped & 1); \
	guts->declaration = _decl;					\
									\
	if ((s)->size_is_bytes || (s)->size_is_bits) {			\
	    _size = _soap_calloc(soap,sizeof(*_size));			\
	    _size->byteSize = symbol_bytesize((s));			\
									\
	    if ((s)->size_is_bytes) {					\
		_size->sizeType = _vmi1__SizeT_sizeType__byte;		\
	    }								\
	    else if ((s)->size_is_bits) {				\
		_size->sizeType = _vmi1__SizeT_sizeType__bit;		\
		_size->__size_SizeT_sequence = 1;			\
		_size->__SizeT_sequence =				\
		    _soap_calloc(soap,sizeof(*_size->__SizeT_sequence)); \
		_size->__SizeT_sequence->bitSize = symbol_bitsize(s);	\
		_size->__SizeT_sequence->bitOffset = s->size.offset;	\
		_size->__SizeT_sequence->containingTypeByteSize =	\
		    s->size.ctbytes;					\
	    }								\
									\
	    guts->size = _size;						\
	}								\
    } while (0);

#define FILL_SYMBOLTYPE(typename,s,r)					\
    if ((s)->datatype)							\
	(r)->__ ## typename ## _sequence->type =			\
	    d_symbol_to_x_SymbolT(soap,(s)->datatype,(opts),		\
				  (reftab),(refstack),(depth)+1);
    
#define FILL_INSTANCESYMBOLCONTENTS(typename,s,opts,reftab,refstack,depth,r) \
    do {								\
        struct __vmi1__ ## typename ## _sequence *guts;			\
	struct _vmi1__inline *_inline;					\
									\
	guts = (r)->__ ## typename ## _sequence;			\
									\
	if ((s)->has_base_addr) {					\
	    guts->addr = _soap_calloc(soap,sizeof(*guts->addr));	\
	    *guts->addr = s->base_addr;					\
	}								\
	/* XXX: do constValue!!! */					\
	_inline = _soap_calloc(soap,sizeof(*guts->inline_));		\
	if (SYMBOL_IS_FULL((s)) && (s)->s.ii->origin) {			\
	    _inline->origin =						\
		d_symbol_to_x_SymbolT(soap,(s)->s.ii->origin,(opts),	\
				      (reftab),(refstack),(depth)+1);	\
	}								\
	_inline->isInlineInstance = (enum xsd__boolean)			\
	    (s->isinlineinstance & 1);					\
	if (SYMBOL_IS_FULL((s))) {					\
	    _inline->isDeclaredInline = (enum xsd__boolean)		\
		((s)->s.ii->isdeclinline & 1);				\
	    _inline->isInlined = (enum xsd__boolean)			\
		((s)->s.ii->isinlined & 1);				\
	}								\
	if (SYMBOL_IS_FULL((s)) && (s)->s.ii->inline_instances		\
	    && array_list_len((s)->s.ii->inline_instances)) {		\
	    _inline->instances =					\
		d_symbol_array_list_to_x_SymbolsT(soap,			\
						  (s)->s.ii->inline_instances, \
						  (opts),(reftab),(refstack),(depth)+1); \
	}								\
	guts->inline_ = _inline;					\
    } while (0);

#define REF_ALLOC_SEQ(typename,r,rs)					\
    if (!(r)->__ ## typename ## _sequence) {				\
	(r)->__size_ ## typename ## _sequence = 1;			\
	(r)->__ ## typename ## _sequence =				\
	    _soap_calloc(soap,sizeof(*(r)->__ ## typename ## _sequence)); \
    }									\
    rs = (r)->__ ## typename ## _sequence;

#define REF_ALLOC_SEQ_NOSET(typename,r)					\
    if (!(r)->__ ## typename ## _sequence) {				\
	(r)->__size_ ## typename ## _sequence = 1;			\
	(r)->__ ## typename ## _sequence =				\
	    _soap_calloc(soap,sizeof(*(r)->__ ## typename ## _sequence)); \
    }

#define CLEANUP_REF(objtype,typename,s,opts,reftab,refstack,depth,r)	\
    if (reftab)								\
	array_list_remove(refstack);

/*
 * We expect that idstr is either a character string, or a function that
 * produces one.  Thus, it is only referenced once (only evaluated once)
 * in the macro body.  But still, the caller doesn't need to free it as
 * long as it was allocated via gSOAP; we only use it if it's going to
 * be encoded, so that is safe.
 */
#define RETURN_REF_OR_ALLOC(objtype,typename,s,idstr,opts,reftab,refstack,depth,r) \
    do {								\
        typeof(r) _r = NULL;						\
	int _rc;							\
	char *_name = objtype ## _get_name(s);				\
	int _rfound = -1;						\
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
		    && !(opts)->doManualRef				\
		    && (_rfound = array_list_find(refstack,_r)) < 0))) { \
									\
	    if (!(r)) {							\
		vdebug(5,LA_XML,LF_XML,					\
		       "reusing encoded %s(%s) at (d=%d,%d/%d)" \
		       " (multiref=%d)\n",				\
		       _name,_r->sid,depth,				\
		       (opts)->symbolRefDepth,(opts)->symtabRefDepth,	\
		       (opts)->doMultiRef);				\
		  							\
		return (typeof(r))_r;					\
	    }								\
	    else {							\
		/* Must memcpy contents into existing buffer. */	\
		vdebug(5,LA_XML,LF_XML,					\
		       "copying encoded %s(%s) at (d=%d,%d/%d)" \
		       " (multiref=%d)\n",				\
		       _name,_r->sid,depth,				\
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
	    if (_r && (opts)->doManualRef) {				\
		if (!(r))						\
		    (r) = _soap_calloc(soap,sizeof(*(r)));		\
									\
		(r)->sref = idstr;					\
									\
		vdebug(5,LA_XML,LF_XML,					\
		       "encoding manual ref for %s(%s)"    \
		       " at (d=%d,%d/%d)\n",				\
		       _name,(r)->sref,depth,				\
		       opts->symbolRefDepth,opts->symtabRefDepth);	\
									\
		return (typeof(r))r;					\
	    }								\
	    else if (_r && _rfound > -1) {				\
		if (!(r))						\
		    (r) = _soap_calloc(soap,sizeof(*(r)));		\
									\
		(r)->sref = idstr;					\
									\
		vdebug(5,LA_XML,LF_XML,					\
		       "forcing (cyclic) manual ref for %s(%s)" \
		       " at (d=%d,%d/%d)\n",				\
		       _name,(r)->sref,depth,				\
		       opts->symbolRefDepth,opts->symtabRefDepth);	\
									\
		return (typeof(r))r;					\
	    }								\
	    else if (depth >= (opts)-> objtype ## RefDepth) {		\
		if (!(r))						\
		    (r) = _soap_calloc(soap,sizeof(*(r)));		\
									\
		(r)->sref = idstr;					\
									\
		if (objtype ## _get_name(s)) {				\
		    _rc = strlen(_name) + 1;				\
		    (r)->name = _soap_calloc(soap,_rc);			\
		    strncpy((r)->name,_name,_rc);			\
		}							\
									\
		vdebug(5,LA_XML,LF_XML,					\
		       "encoding fetchable ref for %s(%s)" \
		       " at (d=%d,%d/%d)\n",				\
		       _name,(r)->sref,depth,				\
		       opts->symbolRefDepth,opts->symtabRefDepth);	\
									\
		return (typeof(r))r;					\
	    }								\
	    /*								\
	     * Need to fully encode it, so just malloc it, place it in  \ 
	     * the reftab, and let caller take over.			\
	     */								\
	    else {							\
		if (!(r)) {						\
		    (r) = _soap_calloc(soap,sizeof(*(r)));		\
		}							\
									\
		(r)->sref = idstr;					\
									\
		vdebug(5,LA_XML,LF_XML,					\
		       "encoding full %s(%"PRIiSMOFFSET")"		\
		       " at (d=%d,%d/%d)\n",				\
		       _name,(r)->sref,depth,				\
		       opts->symbolRefDepth,opts->symtabRefDepth);	\
									\
		if (reftab) {						\
		    g_hash_table_insert(reftab,(gpointer)s,(gpointer)r);\
		    array_list_append(refstack,r);			\
		}							\
	    }								\
	}								\
    } while (0);

static inline char *_ref_build_int(struct soap *soap,int ref) {
    char idbuf[16];
    int rc;
    char *retval;

    rc = snprintf(idbuf,16,"%d",ref);
    rc = (rc > 16) ? 16 : (rc + 1);
    retval = _soap_calloc(soap,rc);
    strncpy(retval,idbuf,rc);

    return retval;
}

struct vmi1__VariableT *
d_symbol_to_x_VariableT(struct soap *soap,struct symbol *s,
			struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			struct array_list *refstack,int depth) {
    struct vmi1__VariableT *r = NULL;
    struct __vmi1__VariableT_sequence *rs;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,VariableT,s,_ref_build_int(soap,s->ref),opts,reftab,refstack,depth,r);
    REF_ALLOC_SEQ(VariableT,r,rs);

    FILL_SYMBOLHEADER(s,r);
    FILL_SYMBOLCOMMON(VariableT,s,r);
    FILL_SYMBOLTYPE(VariableT,s,r);

    if (s->isparam)
	rs->kind = _vmi1__kind__parameter;
    else if (s->ismember)
	rs->kind = _vmi1__kind__member;
    else if (s->isenumval)
	rs->kind = _vmi1__kind__enumerator;
    else
	rs->kind = _vmi1__kind__variable;

    FILL_INSTANCESYMBOLCONTENTS(VariableT,s,opts,reftab,refstack,depth,r);

    if (SYMBOL_IS_FULL_VAR(s)) {
	rs->location = d_location_to_x_LocationT(soap,&s->s.ii->d.v.l,
						opts,reftab,refstack,depth);
    }
    else {
	/* Schema requires us to have one, so we'd better */
	rs->location = _soap_calloc(soap,sizeof(*rs->location));
	rs->location->__union_LocationT = 0;
	rs->location->type = _vmi1__LocationT_type__none;
    }

    CLEANUP_REF(symbol,VariableT,s,opts,reftab,refstack,depth,r);

    return r;
}

struct vmi1__FunctionT *
d_symbol_to_x_FunctionT(struct soap *soap,struct symbol *s,
			struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			struct array_list *refstack,int depth) {
    struct vmi1__FunctionT *r = NULL;
    struct __vmi1__FunctionT_sequence *rs;
    struct symbol *arg;
    struct symbol_instance *argi;
    struct array_list *gslist;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,FunctionT,s,_ref_build_int(soap,s->ref),opts,reftab,refstack,depth,r);
    REF_ALLOC_SEQ(FunctionT,r,rs);

    FILL_SYMBOLHEADER(s,r);
    FILL_SYMBOLCOMMON(FunctionT,s,r);
    FILL_SYMBOLTYPE(FunctionT,s,r);

    if (SYMBOL_IS_FULL(s)) {
	rs->argCount = s->s.ii->d.f.count;
	rs->hasUnspecifiedParams =					\
	    (s->s.ii->d.f.hasunspec) ? xsd__boolean__true_ : xsd__boolean__false_;
	if (s->s.ii->d.f.hasentrypc) {
	    rs->entryPC = _soap_calloc(soap,sizeof(*rs->entryPC));
	    *rs->entryPC = s->s.ii->d.f.entry_pc;
	}
	if (s->s.ii->d.f.prologue_known) {
	    rs->prologueEnd = _soap_calloc(soap,sizeof(*rs->prologueEnd));
	    *rs->prologueEnd = s->s.ii->d.f.prologue_end;
	}
	else if (s->s.ii->d.f.prologue_guessed) {
	    rs->prologueEnd = _soap_calloc(soap,sizeof(*rs->prologueEnd));
	    *rs->prologueEnd = s->s.ii->d.f.prologue_end;
	}
	if (s->s.ii->d.f.epilogue_known) {
	    rs->epilogueBegin = _soap_calloc(soap,sizeof(*rs->epilogueBegin));
	    *rs->epilogueBegin = s->s.ii->d.f.epilogue_begin;
	}
    }

    FILL_INSTANCESYMBOLCONTENTS(FunctionT,s,opts,reftab,refstack,depth,r);

    // XXX: do constval!!!

    if (SYMBOL_IS_FULL(s)) {
	if (s->s.ii->d.f.count) {
	    /* Make a tmp array list of the symbols */
	    gslist = array_list_create(s->s.ii->d.f.count);
	    list_for_each_entry(argi,&s->s.ii->d.f.args,d.v.member) {
		arg = argi->d.v.member_symbol;
		array_list_append(gslist,arg);
	    }
	    rs->arguments = \
		d_symbol_array_list_to_x_SymbolsOptT(soap,gslist,
						     opts,reftab,refstack,depth+1);
	    array_list_free(gslist);
	}
	else {
	    rs->arguments = _soap_calloc(soap,sizeof(*rs->arguments));
	}

	if (s->s.ii->d.f.symtab) {
	    rs->ranges = d_range_to_x_RangesT(soap,&s->s.ii->d.f.symtab->range,
					      opts,reftab,refstack,depth);
	    rs->symtab = d_symtab_to_x_SymtabT(soap,s->s.ii->d.f.symtab,
					       opts,reftab,refstack,depth+1,NULL);
	}
    }

    CLEANUP_REF(symbol,FunctionT,s,opts,reftab,refstack,depth,r);

    return r;
}

struct vmi1__LabelT *
d_symbol_to_x_LabelT(struct soap *soap,struct symbol *s,
		     struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
		     struct array_list *refstack,int depth) {
    struct vmi1__LabelT *r = NULL;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,LabelT,s,_ref_build_int(soap,s->ref),opts,reftab,refstack,depth,r);
    REF_ALLOC_SEQ_NOSET(LabelT,r);

    FILL_SYMBOLHEADER(s,r);
    FILL_SYMBOLCOMMON(LabelT,s,r);
    FILL_INSTANCESYMBOLCONTENTS(LabelT,s,opts,reftab,refstack,depth,r);

    CLEANUP_REF(symbol,LabelT,s,opts,reftab,refstack,depth,r);

    return r;
}

struct vmi1__VoidTypeT *
d_symbol_to_x_VoidTypeT(struct soap *soap,struct symbol *s,
			struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			struct array_list *refstack,int depth) {
    struct vmi1__VoidTypeT *r = NULL;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,VoidTypeT,s,_ref_build_int(soap,s->ref),opts,reftab,refstack,depth,r);

    FILL_SYMBOLHEADER(s,r);

    if (SYMBOL_IS_DWARF(s)) 
	r->source = _vmi1__source__dwarf;
    else if (SYMBOL_IS_ELF(s)) 
	r->source = _vmi1__source__elf;

    CLEANUP_REF(symbol,VoidTypeT,s,opts,reftab,refstack,depth,r);

    return r;
}

struct vmi1__BaseTypeT *
d_symbol_to_x_BaseTypeT(struct soap *soap,struct symbol *s,
			struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			struct array_list *refstack,int depth) {
    struct vmi1__BaseTypeT *r = NULL;
    struct __vmi1__BaseTypeT_sequence *rs;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,BaseTypeT,s,_ref_build_int(soap,s->ref),opts,reftab,refstack,depth,r);
    REF_ALLOC_SEQ(BaseTypeT,r,rs);

    FILL_SYMBOLHEADER(s,r);
    FILL_SYMBOLCOMMON(BaseTypeT,s,r);

    if (SYMBOL_IS_FULL(s)) {
	switch (s->s.ti->d.t.encoding) {
	case ENCODING_ADDRESS:
	    rs->encoding = _vmi1__encoding__address;
	    break;
	case ENCODING_BOOLEAN:
	    rs->encoding = _vmi1__encoding__boolean;
	    break;
	case ENCODING_COMPLEX_FLOAT:
	    rs->encoding = _vmi1__encoding__complexFloat;
	    break;
	case ENCODING_FLOAT:
	    rs->encoding = _vmi1__encoding__float_;
	    break;
	case ENCODING_SIGNED:
	    rs->encoding = _vmi1__encoding__signed_;
	    break;
	case ENCODING_SIGNED_CHAR:
	    rs->encoding = _vmi1__encoding__signedChar;
	    break;
	case ENCODING_UNSIGNED:
	    rs->encoding = _vmi1__encoding__unsigned_;
	    break;
	case ENCODING_UNSIGNED_CHAR:
	    rs->encoding = _vmi1__encoding__unsignedChar;
	    break;
	case ENCODING_IMAGINARY_FLOAT:
	    rs->encoding = _vmi1__encoding__imaginaryFloat;
	    break;
	case ENCODING_PACKED_DECIMAL:
	    rs->encoding = _vmi1__encoding__packedDecimal;
	    break;
	case ENCODING_NUMERIC_STRING:
	    rs->encoding = _vmi1__encoding__numericString;
	    break;
	case ENCODING_EDITED:
	    rs->encoding = _vmi1__encoding__edited;
	    break;
	case ENCODING_SIGNED_FIXED:
	    rs->encoding = _vmi1__encoding__signedFixed;
	    break;
	case ENCODING_UNSIGNED_FIXED:
	    rs->encoding = _vmi1__encoding__unsignedFixed;
	    break;
	default:
	    rs->encoding = _vmi1__encoding__unknown;
	    break;
	}
    }

    CLEANUP_REF(symbol,BaseTypeT,s,opts,reftab,refstack,depth,r);

    return r;
}

struct vmi1__PointerTypeT *
d_symbol_to_x_PointerTypeT(struct soap *soap,struct symbol *s,
			   struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			   struct array_list *refstack,int depth) {
    struct vmi1__PointerTypeT *r = NULL;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,PointerTypeT,s,_ref_build_int(soap,s->ref),opts,reftab,refstack,depth,r);
    REF_ALLOC_SEQ_NOSET(PointerTypeT,r);

    FILL_SYMBOLHEADER(s,r);
    FILL_SYMBOLCOMMON(PointerTypeT,s,r);
    FILL_SYMBOLTYPE(PointerTypeT,s,r);

    CLEANUP_REF(symbol,PointerTypeT,s,opts,reftab,refstack,depth,r);

    return r;
}

struct vmi1__TypedefTypeT *
d_symbol_to_x_TypedefTypeT(struct soap *soap,struct symbol *s,
			  struct vmi1__DebugFileOptsT *opts,
			   GHashTable *reftab,struct array_list *refstack,
			   int depth) {
    struct vmi1__TypedefTypeT *r = NULL;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,TypedefTypeT,s,_ref_build_int(soap,s->ref),opts,reftab,refstack,depth,r);
    REF_ALLOC_SEQ_NOSET(TypedefTypeT,r);

    FILL_SYMBOLHEADER(s,r);
    FILL_SYMBOLCOMMON(TypedefTypeT,s,r);
    FILL_SYMBOLTYPE(TypedefTypeT,s,r);

    CLEANUP_REF(symbol,TypedefTypeT,s,opts,reftab,refstack,depth,r);

    return r;
}

struct vmi1__ConstTypeT *
d_symbol_to_x_ConstTypeT(struct soap *soap,struct symbol *s,
			struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			struct array_list *refstack,int depth) {
    struct vmi1__ConstTypeT *r = NULL;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,ConstTypeT,s,_ref_build_int(soap,s->ref),opts,reftab,refstack,depth,r);
    REF_ALLOC_SEQ_NOSET(ConstTypeT,r);

    FILL_SYMBOLHEADER(s,r);
    FILL_SYMBOLCOMMON(ConstTypeT,s,r);
    FILL_SYMBOLTYPE(ConstTypeT,s,r);

    CLEANUP_REF(symbol,ConstTypeT,s,opts,reftab,refstack,depth,r);

    return r;
}

struct vmi1__VolatileTypeT *
d_symbol_to_x_VolatileTypeT(struct soap *soap,struct symbol *s,
			   struct vmi1__DebugFileOptsT *opts,
			    GHashTable *reftab,struct array_list *refstack,
			    int depth) {
    struct vmi1__VolatileTypeT *r = NULL;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,VolatileTypeT,s,_ref_build_int(soap,s->ref),opts,reftab,refstack,depth,r);
    REF_ALLOC_SEQ_NOSET(VolatileTypeT,r);

    FILL_SYMBOLHEADER(s,r);
    FILL_SYMBOLCOMMON(VolatileTypeT,s,r);
    FILL_SYMBOLTYPE(VolatileTypeT,s,r);

    CLEANUP_REF(symbol,VolatileTypeT,s,opts,reftab,refstack,depth,r);

    return r;
}

struct vmi1__ArrayTypeT *
d_symbol_to_x_ArrayTypeT(struct soap *soap,struct symbol *s,
			struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			 struct array_list *refstack,int depth) {
    struct vmi1__ArrayTypeT *r = NULL;
    struct __vmi1__ArrayTypeT_sequence *rs;
    int i;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,ArrayTypeT,s,_ref_build_int(soap,s->ref),opts,reftab,refstack,depth,r);
    REF_ALLOC_SEQ(ArrayTypeT,r,rs);

    FILL_SYMBOLHEADER(s,r);
    FILL_SYMBOLCOMMON(ArrayTypeT,s,r);
    FILL_SYMBOLTYPE(ArrayTypeT,s,r);

    rs->subrangeCount = s->s.ti->d.a.count;
    if (s->s.ti->d.a.count) {
	rs->subranges = _soap_calloc(soap,sizeof(*rs->subranges));
	rs->subranges->__sizesubrange = s->s.ti->d.a.count;
	rs->subranges->subrange = \
	    _soap_calloc(soap,
			 s->s.ti->d.a.count * sizeof(*rs->subranges->subrange));
	for (i = 0; i < s->s.ti->d.a.count; ++i) {
	    rs->subranges->subrange[i] = s->s.ti->d.a.subranges[i];
	}
    }

    CLEANUP_REF(symbol,ArrayTypeT,s,opts,reftab,refstack,depth,r);

    return r;
}

struct vmi1__EnumTypeT *
d_symbol_to_x_EnumTypeT(struct soap *soap,struct symbol *s,
		       struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			struct array_list *refstack,int depth) {
    struct vmi1__EnumTypeT *r = NULL;
    struct __vmi1__EnumTypeT_sequence *rs;
    struct symbol_instance *tmpi;
    struct symbol *tmps;
    struct array_list *gslist;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,EnumTypeT,s,_ref_build_int(soap,s->ref),opts,reftab,refstack,depth,r);
    REF_ALLOC_SEQ(EnumTypeT,r,rs);

    FILL_SYMBOLHEADER(s,r);
    FILL_SYMBOLCOMMON(EnumTypeT,s,r);
    FILL_SYMBOLTYPE(EnumTypeT,s,r);

    rs->memberCount = s->s.ti->d.e.count;
    if (s->s.ti->d.e.count) {
	gslist = array_list_create(s->s.ti->d.e.count);
	list_for_each_entry(tmpi,&s->s.ti->d.e.members,d.v.member) {
	    tmps = tmpi->d.v.member_symbol;
	    array_list_append(gslist,tmps);
	}
	rs->members = d_symbol_array_list_to_x_SymbolsT(soap,gslist,
							opts,reftab,refstack,depth+1);
	array_list_free(gslist);
    }

    CLEANUP_REF(symbol,EnumTypeT,s,opts,reftab,refstack,depth,r);

    return r;
}

struct vmi1__StructTypeT *
d_symbol_to_x_StructTypeT(struct soap *soap,struct symbol *s,
			 struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			  struct array_list *refstack,int depth) {
    struct vmi1__StructTypeT *r = NULL;
    struct __vmi1__StructTypeT_sequence *rs;
    struct symbol_instance *tmpi;
    struct symbol *tmps;
    struct array_list *gslist;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,StructTypeT,s,_ref_build_int(soap,s->ref),opts,reftab,refstack,depth,r);
    REF_ALLOC_SEQ(StructTypeT,r,rs);

    FILL_SYMBOLHEADER(s,r);
    FILL_SYMBOLCOMMON(StructTypeT,s,r);
    FILL_SYMBOLTYPE(StructTypeT,s,r);

    rs->memberCount = s->s.ti->d.su.count;
    if (s->s.ti->d.su.count) {
	gslist = array_list_create(s->s.ti->d.su.count);
	list_for_each_entry(tmpi,&s->s.ti->d.su.members,d.v.member) {
	    tmps = tmpi->d.v.member_symbol;
	    array_list_append(gslist,tmps);
	}
	rs->members = \
	    d_symbol_array_list_to_x_SymbolsOptT(soap,gslist,opts,reftab,refstack,depth+1);
	array_list_free(gslist);
    }

    CLEANUP_REF(symbol,StructTypeT,s,opts,reftab,refstack,depth,r);

    return r;
}

struct vmi1__UnionTypeT *
d_symbol_to_x_UnionTypeT(struct soap *soap,struct symbol *s,
			struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			 struct array_list *refstack,int depth) {
    struct vmi1__UnionTypeT *r = NULL;
    struct __vmi1__UnionTypeT_sequence *rs;
    struct symbol_instance *tmpi;
    struct symbol *tmps;
    struct array_list *gslist;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,UnionTypeT,s,_ref_build_int(soap,s->ref),opts,reftab,refstack,depth,r);
    REF_ALLOC_SEQ(UnionTypeT,r,rs);

    FILL_SYMBOLHEADER(s,r);
    FILL_SYMBOLCOMMON(UnionTypeT,s,r);
    FILL_SYMBOLTYPE(UnionTypeT,s,r);

    rs->memberCount = s->s.ti->d.su.count;
    if (s->s.ti->d.su.count) {
	gslist = array_list_create(s->s.ti->d.su.count);
	list_for_each_entry(tmpi,&s->s.ti->d.su.members,d.v.member) {
	    tmps = tmpi->d.v.member_symbol;
	    array_list_append(gslist,tmps);
	}
	rs->members = \
	    d_symbol_array_list_to_x_SymbolsOptT(soap,gslist,opts,reftab,refstack,depth+1);
	array_list_free(gslist);
    }

    CLEANUP_REF(symbol,UnionTypeT,s,opts,reftab,refstack,depth,r);

    return r;
}

struct vmi1__FunctionTypeT *
d_symbol_to_x_FunctionTypeT(struct soap *soap,struct symbol *s,
			   struct vmi1__DebugFileOptsT *opts,
			    GHashTable *reftab,struct array_list *refstack,
			    int depth) {
    struct vmi1__FunctionTypeT *r = NULL;
    struct __vmi1__FunctionTypeT_sequence *rs;
    struct symbol_instance *tmpi;
    struct symbol *tmps;
    struct array_list *gslist;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,FunctionTypeT,s,_ref_build_int(soap,s->ref),opts,reftab,refstack,depth,r);
    REF_ALLOC_SEQ(FunctionTypeT,r,rs);

    FILL_SYMBOLHEADER(s,r);
    FILL_SYMBOLCOMMON(FunctionTypeT,s,r);
    FILL_SYMBOLTYPE(FunctionTypeT,s,r);

    rs->argCount = s->s.ti->d.f.count;
    if (s->s.ti->d.f.count) {
	gslist = array_list_create(s->s.ti->d.f.count);
	list_for_each_entry(tmpi,&s->s.ti->d.f.args,d.v.member) {
	    tmps = tmpi->d.v.member_symbol;
	    array_list_append(gslist,tmps);
	}
	rs->arguments = \
	    d_symbol_array_list_to_x_SymbolsOptT(soap,gslist,opts,reftab,refstack,depth+1);
	array_list_free(gslist);
    }
    if (s->s.ti->d.f.hasunspec) 
	rs->hasUnspecifiedParams = xsd__boolean__true_;
    else
	rs->hasUnspecifiedParams = xsd__boolean__false_;

    CLEANUP_REF(symbol,FunctionTypeT,s,opts,reftab,refstack,depth,r);

    return r;
}

struct vmi1__SymbolT *
d_symbol_to_x_SymbolT(struct soap *soap,struct symbol *s,
		      struct vmi1__DebugFileOptsT *opts,
		      GHashTable *reftab,struct array_list *refstack,int depth) {
    struct vmi1__SymbolT *r;

    if (!opts)
	opts = &defDebugFileOpts;

    r = (struct vmi1__SymbolT *)_soap_calloc(soap,sizeof(*r));

    if (SYMBOL_IS_VAR(s)) {
	r->union_SymbolT.variable =					\
	    d_symbol_to_x_VariableT(soap,s,opts,reftab,refstack,depth);
	r->__union_SymbolT =				\
	    SOAP_UNION__vmi1__union_SymbolT_variable;
    }
    else if (SYMBOL_IS_FUNCTION(s)) {
	r->union_SymbolT.function =					\
	    d_symbol_to_x_FunctionT(soap,s,opts,reftab,refstack,depth);
	r->__union_SymbolT =				\
	    SOAP_UNION__vmi1__union_SymbolT_function;
    }
    else if (SYMBOL_IS_LABEL(s)) {
	r->union_SymbolT.label =				\
	    d_symbol_to_x_LabelT(soap,s,opts,reftab,refstack,depth);
	r->__union_SymbolT =				\
	    SOAP_UNION__vmi1__union_SymbolT_label;
    }
    else if (SYMBOL_IS_TYPE(s)) {
	switch (s->datatype_code) {
	case DATATYPE_VOID:
	    r->union_SymbolT.voidType =					\
		d_symbol_to_x_VoidTypeT(soap,s,opts,reftab,refstack,depth);
	    r->__union_SymbolT =				\
		SOAP_UNION__vmi1__union_SymbolT_voidType;
	    break;
	case DATATYPE_ARRAY:
	    r->union_SymbolT.arrayType =				\
		d_symbol_to_x_ArrayTypeT(soap,s,opts,reftab,refstack,depth);
	    r->__union_SymbolT =				\
		SOAP_UNION__vmi1__union_SymbolT_arrayType;
	    break;
	case DATATYPE_STRUCT:
	    r->union_SymbolT.structType =				\
		d_symbol_to_x_StructTypeT(soap,s,opts,reftab,refstack,depth);
	    r->__union_SymbolT = \
		SOAP_UNION__vmi1__union_SymbolT_structType;
	    break;
	case DATATYPE_ENUM:
	    r->union_SymbolT.enumType =					\
		d_symbol_to_x_EnumTypeT(soap,s,opts,reftab,refstack,depth);
	    r->__union_SymbolT =				\
		SOAP_UNION__vmi1__union_SymbolT_enumType;
	    break;
	case DATATYPE_PTR:
	    r->union_SymbolT.pointerType =				\
		d_symbol_to_x_PointerTypeT(soap,s,opts,reftab,refstack,depth);
	    r->__union_SymbolT =				\
		SOAP_UNION__vmi1__union_SymbolT_pointerType;
	    break;
	case DATATYPE_FUNCTION:
	    r->union_SymbolT.functionType =				\
		d_symbol_to_x_FunctionTypeT(soap,s,opts,reftab,refstack,depth);
	    r->__union_SymbolT =				\
		SOAP_UNION__vmi1__union_SymbolT_functionType;
	    break;
	case DATATYPE_TYPEDEF:
	    r->union_SymbolT.typedefType =				\
		d_symbol_to_x_TypedefTypeT(soap,s,opts,reftab,refstack,depth);
	    r->__union_SymbolT =				\
		SOAP_UNION__vmi1__union_SymbolT_typedefType;
	    break;
	case DATATYPE_UNION:
	    r->union_SymbolT.unionType =				\
		d_symbol_to_x_UnionTypeT(soap,s,opts,reftab,refstack,depth);
	    r->__union_SymbolT =				\
		SOAP_UNION__vmi1__union_SymbolT_unionType;
	    break;
	case DATATYPE_BASE:
	    r->union_SymbolT.baseType =					\
		d_symbol_to_x_BaseTypeT(soap,s,opts,reftab,refstack,depth);
	    r->__union_SymbolT =				\
		SOAP_UNION__vmi1__union_SymbolT_baseType;
	    break;
	case DATATYPE_CONST:
	    r->union_SymbolT.constType =				\
		d_symbol_to_x_ConstTypeT(soap,s,opts,reftab,refstack,depth);
	    r->__union_SymbolT =				\
		SOAP_UNION__vmi1__union_SymbolT_constType;
	    break;
	case DATATYPE_VOL:
	    r->union_SymbolT.volatileType =				\
		d_symbol_to_x_VolatileTypeT(soap,s,opts,reftab,refstack,depth);
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

struct vmi1__SymbolsT *
d_symbol_array_list_to_x_SymbolsT(struct soap *soap,
				  struct array_list *list,
				  struct vmi1__DebugFileOptsT *opts,
				  GHashTable *reftab,
				  struct array_list *refstack,int depth) {
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
		d_symbol_to_x_VariableT(soap,s,opts,reftab,refstack,depth);
	    *uw = SOAP_UNION__vmi1__union_SymbolsT_variable;
	}
	else if (SYMBOL_IS_FUNCTION(s)) {
	    ui->function =						\
		d_symbol_to_x_FunctionT(soap,s,opts,reftab,refstack,depth);
	    *uw = SOAP_UNION__vmi1__union_SymbolsT_function;
	}
	else if (SYMBOL_IS_LABEL(s)) {
	    ui->label =							\
		d_symbol_to_x_LabelT(soap,s,opts,reftab,refstack,depth);
	    *uw = SOAP_UNION__vmi1__union_SymbolsT_label;
	}
	else if (SYMBOL_IS_TYPE(s)) {
	    switch (s->datatype_code) {
	    case DATATYPE_VOID:
		ui->voidType =						\
		    d_symbol_to_x_VoidTypeT(soap,s,opts,reftab,refstack,depth);
		*uw = SOAP_UNION__vmi1__union_SymbolsT_voidType;
		break;
	    case DATATYPE_ARRAY:
		ui->arrayType =						\
		    d_symbol_to_x_ArrayTypeT(soap,s,opts,reftab,refstack,depth);
		*uw = SOAP_UNION__vmi1__union_SymbolsT_arrayType;
		break;
	    case DATATYPE_STRUCT:
		ui->structType =					\
		    d_symbol_to_x_StructTypeT(soap,s,opts,reftab,refstack,depth);
		*uw = SOAP_UNION__vmi1__union_SymbolsT_structType;
		break;
	    case DATATYPE_ENUM:
		ui->enumType =						\
		    d_symbol_to_x_EnumTypeT(soap,s,opts,reftab,refstack,depth);
		*uw = SOAP_UNION__vmi1__union_SymbolsT_enumType;
		break;
	    case DATATYPE_PTR:
		ui->pointerType =					\
		    d_symbol_to_x_PointerTypeT(soap,s,opts,reftab,refstack,depth);
		*uw = SOAP_UNION__vmi1__union_SymbolsT_pointerType;
		break;
	    case DATATYPE_FUNCTION:
		ui->functionType =					\
		    d_symbol_to_x_FunctionTypeT(soap,s,opts,reftab,refstack,depth);
		*uw = SOAP_UNION__vmi1__union_SymbolsT_functionType;
		break;
	    case DATATYPE_TYPEDEF:
		ui->typedefType =					\
		    d_symbol_to_x_TypedefTypeT(soap,s,opts,reftab,refstack,depth);
		*uw = SOAP_UNION__vmi1__union_SymbolsT_typedefType;
		break;
	    case DATATYPE_UNION:
		ui->unionType =						\
		    d_symbol_to_x_UnionTypeT(soap,s,opts,reftab,refstack,depth);
		*uw = SOAP_UNION__vmi1__union_SymbolsT_unionType;
		break;
	    case DATATYPE_BASE:
		ui->baseType =						\
		    d_symbol_to_x_BaseTypeT(soap,s,opts,reftab,refstack,depth);
		*uw = SOAP_UNION__vmi1__union_SymbolsT_baseType;
		break;
	    case DATATYPE_CONST:
		ui->constType =						\
		    d_symbol_to_x_ConstTypeT(soap,s,opts,reftab,refstack,depth);
		*uw = SOAP_UNION__vmi1__union_SymbolsT_constType;
		break;
	    case DATATYPE_VOL:
		ui->volatileType =					\
		    d_symbol_to_x_VolatileTypeT(soap,s,opts,reftab,refstack,depth);
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
				     GHashTable *reftab,
				     struct array_list *refstack,int depth) {
    /*
     * This is nasty.  We just return a vmi1__SymbolsT because gSOAP
     * gives us the same C structs/unions/enums types for
     * vmi1__SymbolsOptT as vmi1__SymbolsT.
     *
     * It just saves some code.
     */
    return (struct vmi1__SymbolsOptT *) \
        d_symbol_array_list_to_x_SymbolsT(soap,list,opts,reftab,refstack,depth);
}

struct vmi1__DebugFileT *
d_debugfile_to_x_DebugFileT(struct soap *soap,struct debugfile *df,
			    struct vmi1__DebugFileOptsT *opts,
			    GHashTable *reftab,struct array_list *refstack,
			    int depth) {
    struct vmi1__DebugFileT *r = NULL;
    struct __vmi1__DebugFileT_sequence *rs;
    GHashTableIter iter;
    struct symtab *symtab;
    char *sfn;
    int i;
    struct array_list *gslist;
    struct symbol *symbol;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(debugfile,DebugFileT,df,df->filename,opts,reftab,refstack,depth,r);
    REF_ALLOC_SEQ(DebugFileT,r,rs);

    if (df->type == DEBUGFILE_TYPE_KERNEL)
	rs->type = _vmi1__DebugFileT_type__kernel;
    else if (df->type == DEBUGFILE_TYPE_KMOD)
	rs->type = _vmi1__DebugFileT_type__kmod;
    else if (df->type == DEBUGFILE_TYPE_MAIN)
	rs->type = _vmi1__DebugFileT_type__static_;
    else if (df->type == DEBUGFILE_TYPE_SHAREDLIB)
	rs->type = _vmi1__DebugFileT_type__sharedlib;

    SOAP_STRCPY(soap,rs->filename,df->filename);
    /* Done in RETURN_REF_OR_ALLOC above. */
    /*SOAP_STRCPY(soap,rs->name,df->name);*/
    SOAP_STRCPY(soap,rs->version,df->version);

    rs->sourceFiles = _soap_calloc(soap,sizeof(*rs->sourceFiles));
    rs->sourceFiles->__sizesourceFile = g_hash_table_size(df->srcfiles);
    rs->sourceFiles->sourceFile = \
	_soap_calloc(soap,rs->sourceFiles->__sizesourceFile * \
		    sizeof(*rs->sourceFiles->sourceFile));

    g_hash_table_iter_init(&iter,df->srcfiles);
    i = 0;
    while (g_hash_table_iter_next(&iter,(gpointer)&sfn,(gpointer)&symtab)) {
	SOAP_STRCPY(soap,rs->sourceFiles->sourceFile[i].filename,sfn);
	rs->sourceFiles->sourceFile[i].symtab =				\
	    d_symtab_to_x_SymtabT(soap,symtab,opts,reftab,refstack,depth,NULL);

	++i;
    }

    /* Make a tmp array list of the symbols */
    gslist = array_list_create(g_hash_table_size(df->globals));
    g_hash_table_iter_init(&iter,df->globals);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer)&symbol))
	array_list_append(gslist,symbol);

    d_symbol_array_list_to_x_SymbolsT(soap,gslist,
						 opts,reftab,refstack,depth);

    array_list_free(gslist);

    CLEANUP_REF(debugfile,DebugFileT,df,opts,reftab,refstack,depth,r);

    return r;
}

struct vmi1__SymtabT *
d_symtab_to_x_SymtabT(struct soap *soap,struct symtab *st,
		      struct vmi1__DebugFileOptsT *opts,
		      GHashTable *reftab,struct array_list *refstack,int depth,
		      struct vmi1__SymtabT *ir) {
    struct vmi1__SymtabT *r = NULL;
    struct __vmi1__SymtabT_sequence *rs;
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

    RETURN_REF_OR_ALLOC(symtab,SymtabT,st,_ref_build_int(soap,st->ref),opts,reftab,refstack,depth,r);
    REF_ALLOC_SEQ(SymtabT,r,rs);

    rc = snprintf(idbuf,idblen,"%d",st->ref);
    rc = (rc > idblen) ? idblen : (rc + 1);
    r->sid = _soap_calloc(soap,rc);
    strncpy(r->sid,idbuf,rc);
    SOAP_STRCPY(soap,r->name,st->name);

    rs->ranges = d_range_to_x_RangesT(soap,&st->range,opts,reftab,refstack,depth);

    if (st->meta) {
	rs->rootMeta = _soap_calloc(soap,sizeof(*rs->rootMeta));
	SOAP_STRCPY(soap,rs->rootMeta->compilationDir,st->meta->compdirname);
	SOAP_STRCPY(soap,rs->rootMeta->producer,st->meta->producer);
	SOAP_STRCPY(soap,rs->rootMeta->language,st->meta->language);
    }

    if (st->parent) 
	rs->parent = \
	    d_symtab_to_x_SymtabT(soap,st->parent,opts,reftab,refstack,depth+1,NULL);

    len = 0;
    list_for_each(pos,&st->subtabs) 
	++len;

    rs->symtabs = _soap_calloc(soap,sizeof(rs->symtabs));
    rs->symtabs->__sizesymtab = len;
    rs->symtabs->symtab = _soap_calloc(soap,len*sizeof(*rs->symtabs->symtab));

    i = 0;
    list_for_each_entry(symtab,&st->subtabs,member) {
	d_symtab_to_x_SymtabT(soap,symtab,opts,reftab,refstack,depth+1,
			      &rs->symtabs->symtab[i]);
	++i;
    }

    /* Make a tmp array list of the symbols */
    gslist = array_list_create(g_hash_table_size(st->tab));
    g_hash_table_iter_init(&iter,st->tab);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer)&symbol))
	array_list_append(gslist,symbol);
    rs->symbols = \
	d_symbol_array_list_to_x_SymbolsOptT(soap,gslist,opts,reftab,refstack,depth);
    array_list_free(gslist);

    /* Make a tmp array list of the anon symbols */
    gslist = array_list_create(g_hash_table_size(st->anontab));
    g_hash_table_iter_init(&iter,st->anontab);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer)&symbol))
	array_list_append(gslist,symbol);
    rs->anonSymbols = \
	d_symbol_array_list_to_x_SymbolsOptT(soap,gslist,opts,reftab,refstack,depth);
    array_list_free(gslist);

    CLEANUP_REF(symtab,SymtabT,st,opts,reftab,refstack,depth,r);

    return r;
}
