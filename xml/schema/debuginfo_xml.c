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
#include "glib_wrapper.h"

static struct vmi1__DebugFileOptsT defDebugFileOpts = {
    .debugfileRefDepth = 1,
    .symbolRefDepth = 1,
    .scopeRefDepth = 1,
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
    int i,count;
    struct loclistloc *loclistloc;

    vl = _soap_calloc(soap,1*sizeof(*vl));

    if (!opts)
	opts = &defDebugFileOpts;

    switch(l->loctype) {
    case LOCTYPE_ADDR:
    case LOCTYPE_REALADDR:
	vl->locationType = _vmi1__LocationT_locationType__addr;
	vl->__union_LocationT = SOAP_UNION__vmi1__union_LocationT_addr;
	vl->union_LocationT.addr = LOCATION_ADDR(l);
	break;
    case LOCTYPE_REG:
	vl->locationType = _vmi1__LocationT_locationType__reg;
	vl->__union_LocationT = SOAP_UNION__vmi1__union_LocationT_reg;
	vl->union_LocationT.reg = LOCATION_REG(l);
	break;
    case LOCTYPE_REG_ADDR:
	vl->locationType = _vmi1__LocationT_locationType__regAddr;
	vl->__union_LocationT = SOAP_UNION__vmi1__union_LocationT_regAddr;
	vl->union_LocationT.regAddr = LOCATION_REG(l);
	break;
    case LOCTYPE_REG_OFFSET:
	vl->locationType = _vmi1__LocationT_locationType__regOffset;
	vl->__union_LocationT = SOAP_UNION__vmi1__union_LocationT_regOffset;
	vl->union_LocationT.regOffset = \
	    _soap_calloc(soap,1*sizeof(*vl->union_LocationT.regOffset));
	vl->union_LocationT.regOffset->reg = (REG)(l)->extra;
	vl->union_LocationT.regOffset->offset = (l)->l.offset;
	break;
    case LOCTYPE_FBREG_OFFSET:
	vl->locationType = _vmi1__LocationT_locationType__fbRegOffset;
	vl->__union_LocationT = SOAP_UNION__vmi1__union_LocationT_fbRegOffset;
	vl->union_LocationT.fbRegOffset = LOCATION_OFFSET(l);
	break;
    case LOCTYPE_MEMBER_OFFSET:
	vl->locationType = _vmi1__LocationT_locationType__memberOffset;
	vl->__union_LocationT = SOAP_UNION__vmi1__union_LocationT_memberOffset;
	vl->union_LocationT.memberOffset = LOCATION_OFFSET(l);
	break;
    case LOCTYPE_RUNTIME:
	vl->locationType = _vmi1__LocationT_locationType__runtime;
	vl->__union_LocationT = SOAP_UNION__vmi1__union_LocationT_runtimeLoc;
	LOCATION_GET_DATA(l,vl->union_LocationT.runtimeLoc.__ptr,
			  vl->union_LocationT.runtimeLoc.__size);
	break;
    case LOCTYPE_LOCLIST:
	vl->locationType = _vmi1__LocationT_locationType__list;
	vl->__union_LocationT = SOAP_UNION__vmi1__union_LocationT_locList;
	vl->union_LocationT.locList = \
	    _soap_calloc(soap,1*sizeof(*vl->union_LocationT.locList));

	loclistloc = LOCATION_LOCLIST(l);
	count = 0;
	while (loclistloc) {
	    ++count;
	    loclistloc = loclistloc->next;
	}

	loclistloc = LOCATION_LOCLIST(l);
	vl->union_LocationT.locList->__sizelocListLoc = count;
	if (count) {
	    vl->union_LocationT.locList->locListLoc =	\
		_soap_calloc(soap,
			     count *					\
			     sizeof(*vl->union_LocationT.locList->locListLoc));
	    i = 0;
	    while (loclistloc) {
		struct _vmi1__locListLoc *lll =			\
		    &vl->union_LocationT.locList->locListLoc[i];

		lll->start = loclistloc->start;
		lll->end = loclistloc->end;

		lll->location =					\
		    d_location_to_x_LocationT(soap,loclistloc->loc,
					      opts,reftab,refstack,depth);

		++i;
		loclistloc = loclistloc->next;
	    }
	}
	break;
    case LOCTYPE_UNKNOWN:
    default:
	vl->locationType = _vmi1__LocationT_locationType__none;
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
    int i,count;
    struct range *tr;

    if (!r)
	return NULL;

    if (!opts)
	opts = &defDebugFileOpts;

    vr = _soap_calloc(soap,1*sizeof(*vr));

    i = 0;
    count = 0;
    tr = r;
    while (tr) {
	++count;
	tr = tr->next;
    }

    i = 0;
    vr->__sizerange = count;
    if (count) {
	vr->range = _soap_calloc(soap,count*sizeof(*vr->range));
	tr = r;
	while (tr) {
	    vr->range[i].start = tr->start;
	    vr->range[i].end = tr->end;
	    ++i;
	    tr = tr->next;
	}
    }

    return vr;
}

#define FILL_SYMBOLHEADER(s,r,reft,refv)				\
    do {								\
	int _rc;							\
	char *_name;							\
	char _idbuf[20];						\
	int _idblen = 20;						\
									\
	_rc = snprintf(_idbuf,_idblen,"%s%d",reft,refv);		\
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
	    _size->byteSize = symbol_get_bytesize((s));			\
									\
	    if ((s)->size_is_bytes) {					\
		_size->sizeType = _vmi1__SizeT_sizeType__byte;		\
	    }								\
	    else if ((s)->size_is_bits) {				\
		_size->sizeType = _vmi1__SizeT_sizeType__bit;		\
		_size->__size_SizeT_sequence = 1;			\
		_size->__SizeT_sequence =				\
		    _soap_calloc(soap,sizeof(*_size->__SizeT_sequence)); \
		_size->__SizeT_sequence->bitSize = symbol_get_bitsize(s); \
		_size->__SizeT_sequence->bitOffset = symbol_get_bitoffset(s); \
		_size->__SizeT_sequence->containingTypeByteSize =	\
		    symbol_get_bitctbytes(s);				\
	    }								\
									\
	    guts->size = _size;						\
	}								\
    } while (0);

#define FILL_SYMBOLCOMMON_NOSEQ(typename,s,r)				\
    do {								\
	struct _vmi1__declaration *_decl;				\
	struct vmi1__SizeT *_size;					\
									\
	if (SYMBOL_IS_DWARF((s)))					\
	    (r)->source = _vmi1__source__dwarf;			\
	else if (SYMBOL_IS_ELF((s)))					\
	    (r)->source = _vmi1__source__elf;				\
									\
	_decl = _soap_calloc(soap,sizeof(*_decl));			\
	_decl->isExternal = (enum xsd__boolean)((s)->isexternal & 1);	\
	_decl->isDeclaration = (enum xsd__boolean)((s)->isdeclaration & 1); \
	_decl->isPrototyped = (enum xsd__boolean)((s)->isprototyped & 1); \
	(r)->declaration = _decl;					\
									\
	if ((s)->size_is_bytes || (s)->size_is_bits) {			\
	    _size = _soap_calloc(soap,sizeof(*_size));			\
	    _size->byteSize = symbol_get_bytesize((s));			\
									\
	    if ((s)->size_is_bytes) {					\
		_size->sizeType = _vmi1__SizeT_sizeType__byte;		\
	    }								\
	    else if ((s)->size_is_bits) {				\
		_size->sizeType = _vmi1__SizeT_sizeType__bit;		\
		_size->__size_SizeT_sequence = 1;			\
		_size->__SizeT_sequence =				\
		    _soap_calloc(soap,sizeof(*_size->__SizeT_sequence)); \
		_size->__SizeT_sequence->bitSize = symbol_get_bitsize(s); \
		_size->__SizeT_sequence->bitOffset = symbol_get_bitoffset(s); \
		_size->__SizeT_sequence->containingTypeByteSize =	\
		    symbol_get_bitctbytes(s);				\
	    }								\
									\
	    (r)->size = _size;						\
	}								\
    } while (0);

#define FILL_SYMBOLTYPE(typename,s,r)					\
    if ((s)->datatype)							\
	(r)->__ ## typename ## _sequence->symtype =			\
	    d_symbol_to_x_SymbolT(soap,(s)->datatype,(opts),		\
				  (reftab),(refstack),(depth)+1);
    
#define FILL_INSTANCESYMBOLCONTENTS(typename,s,opts,reftab,refstack,depth,r) \
    do {								\
        struct __vmi1__ ## typename ## _sequence *guts;			\
	struct _vmi1__inlineInfo *_inline = NULL;			\
	struct symbol_inline *_ii;					\
									\
	guts = (r)->__ ## typename ## _sequence;			\
									\
	if ((s)->has_addr) {						\
	    guts->addr = _soap_calloc(soap,sizeof(*guts->addr));	\
	    *guts->addr = s->addr;					\
	}								\
	/* XXX: do constValue!!! */					\
	_ii = SYMBOLX_INLINE((s));					\
	if ((s)->isinlineinstance || (s)->isdeclinline || (s)->isinlined) { \
	    _inline = _soap_calloc(soap,sizeof(*guts->inlineInfo));	\
	    if (_ii && _ii->origin) {					\
		_inline->origin =					\
		    d_symbol_to_x_SymbolT(soap,_ii->origin,(opts),	\
					  (reftab),(refstack),(depth)+1); \
	    }								\
	    _inline->isInlineInstance = (enum xsd__boolean)		\
		(s->isinlineinstance & 1);				\
	    _inline->isDeclaredInline = (enum xsd__boolean)		\
		((s)->isdeclinline & 1);				\
	    _inline->isInlined = (enum xsd__boolean)			\
		((s)->isinlined & 1);					\
	    if (_ii && _ii->inline_instances) {				\
		_inline->instances =					\
		    d_symbol_gslist_to_x_SymbolsT(soap,			\
						  _ii->inline_instances, \
						  (opts),(reftab),(refstack),(depth)+1); \
	    }								\
	}								\
	guts->inlineInfo = _inline;					\
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
 * refv must be a 32-bit int.  reft can be up to a 2-char string.
 */
#define RETURN_REF_OR_ALLOC(objtype,typename,s,reft,refv,opts,reftab,refstack,depth,r) \
    do {								\
        typeof(r) _r = NULL;						\
	int _rc;							\
	char *_name = objtype ## _get_name(s);				\
	int _rfound = -1;						\
	char _idbuf[19];						\
	int _idblen = 19;						\
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
		       (opts)->symbolRefDepth,(opts)->scopeRefDepth,	\
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
		       (opts)->symbolRefDepth,(opts)->scopeRefDepth,	\
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
		_rc = snprintf(_idbuf,_idblen,"%s%d",reft,refv);	\
		_rc = (_rc > _idblen) ? _idblen : (_rc + 1); \
		(r)->sref = _soap_calloc(soap,_rc);			\
		strncpy((r)->sref,_idbuf,_rc);				\
									\
		/* (r)->sref = idstr; */				\
									\
		vdebug(5,LA_XML,LF_XML,					\
		       "encoding manual ref for %s(%s)"    \
		       " at (d=%d,%d/%d)\n",				\
		       _name,(r)->sref,depth,				\
		       opts->symbolRefDepth,opts->scopeRefDepth);	\
									\
		return (typeof(r))r;					\
	    }								\
	    else if (_r && _rfound > -1) {				\
		if (!(r))						\
		    (r) = _soap_calloc(soap,sizeof(*(r)));		\
									\
		_rc = snprintf(_idbuf,_idblen,"%s%d",reft,refv);	\
		_rc = (_rc > _idblen) ? _idblen : (_rc + 1); \
		(r)->sref = _soap_calloc(soap,_rc);			\
		strncpy((r)->sref,_idbuf,_rc);				\
									\
		/* (r)->sref = idstr; */				\
									\
		vdebug(5,LA_XML,LF_XML,					\
		       "forcing (cyclic) manual ref for %s(%s)" \
		       " at (d=%d,%d/%d)\n",				\
		       _name,(r)->sref,depth,				\
		       opts->symbolRefDepth,opts->scopeRefDepth);	\
									\
		return (typeof(r))r;					\
	    }								\
	    else if (depth >= (opts)-> objtype ## RefDepth) {		\
		if (!(r))						\
		    (r) = _soap_calloc(soap,sizeof(*(r)));		\
									\
		_rc = snprintf(_idbuf,_idblen,"%s%d",reft,refv);	\
		_rc = (_rc > _idblen) ? _idblen : (_rc + 1); \
		(r)->sref = _soap_calloc(soap,_rc);			\
		strncpy((r)->sref,_idbuf,_rc);				\
									\
		/* (r)->sref = idstr; */				\
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
		       opts->symbolRefDepth,opts->scopeRefDepth);	\
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
		_rc = snprintf(_idbuf,_idblen,"%s%d",reft,refv);	\
		_rc = (_rc > _idblen) ? _idblen : (_rc + 1); \
		(r)->sref = _soap_calloc(soap,_rc);			\
		strncpy((r)->sref,_idbuf,_rc);				\
									\
		/* (r)->sref = idstr; */				\
									\
		vdebug(5,LA_XML,LF_XML,					\
		       "encoding full %s(%"PRIiSMOFFSET")"		\
		       " at (d=%d,%d/%d)\n",				\
		       _name,(r)->sref,depth,				\
		       opts->symbolRefDepth,opts->scopeRefDepth);	\
									\
		if (reftab) {						\
		    g_hash_table_insert(reftab,(gpointer)s,(gpointer)r);\
		    array_list_append(refstack,r);			\
		}							\
	    }								\
	}								\
    } while (0);

static inline char *_ref_build_int(struct soap *soap,char *reft,int refv) {
    char idbuf[20];
    int rc;
    char *retval;

    rc = snprintf(idbuf,sizeof(idbuf),"%s%d",reft,refv);
    rc = (rc > (int)sizeof(idbuf)) ? (int)sizeof(idbuf) : (rc + 1);
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

    RETURN_REF_OR_ALLOC(symbol,VariableT,s,"sym",s->ref,opts,reftab,refstack,depth,r);
    REF_ALLOC_SEQ(VariableT,r,rs);

    FILL_SYMBOLHEADER(s,r,"sym",s->ref);
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

    if (SYMBOLX_VAR_LOC(s)) {
	rs->location = d_location_to_x_LocationT(soap,SYMBOLX_VAR_LOC(s),
						opts,reftab,refstack,depth);
    }
    else {
	/* Schema requires us to have one, so we'd better */
	rs->location = _soap_calloc(soap,sizeof(*rs->location));
	rs->location->__union_LocationT = 0;
	rs->location->locationType = _vmi1__LocationT_locationType__none;
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
    struct symbol_function *sf;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,FunctionT,s,"sym",s->ref,opts,reftab,refstack,depth,r);
    REF_ALLOC_SEQ(FunctionT,r,rs);

    FILL_SYMBOLHEADER(s,r,"sym",s->ref);
    FILL_SYMBOLCOMMON(FunctionT,s,r);
    FILL_SYMBOLTYPE(FunctionT,s,r);

    rs->hasUnspecifiedParams =						\
	(s->has_unspec_params) ? xsd__boolean__true_ : xsd__boolean__false_;
    rs->parameterCount = g_slist_length(SYMBOLX_MEMBERS(s));

    sf = SYMBOLX_FUNC(s);
    if (sf) {
	if (sf->has_entry_pc) {
	    rs->entryPC = _soap_calloc(soap,sizeof(*rs->entryPC));
	    *rs->entryPC = sf->entry_pc;
	}
	if (sf->prologue_known) {
	    rs->prologueEnd = _soap_calloc(soap,sizeof(*rs->prologueEnd));
	    *rs->prologueEnd = sf->prologue_end;
	}
	else if (sf->prologue_guessed) {
	    rs->prologueEnd = _soap_calloc(soap,sizeof(*rs->prologueEnd));
	    *rs->prologueEnd = sf->prologue_end;
	}
	if (sf->epilogue_known) {
	    rs->epilogueBegin = _soap_calloc(soap,sizeof(*rs->epilogueBegin));
	    *rs->epilogueBegin = sf->epilogue_begin;
	}
    }

    FILL_INSTANCESYMBOLCONTENTS(FunctionT,s,opts,reftab,refstack,depth,r);

    // XXX: do constval!!!

    if (SYMBOLX_MEMBERS(s)) {
	rs->parameters =						\
	    d_symbol_gslist_to_x_SymbolsOptT(soap,SYMBOLX_MEMBERS(s),
					     opts,reftab,refstack,depth+1);
    }
    else {
	rs->parameters = _soap_calloc(soap,sizeof(*rs->parameters));
    }

    if (sf->scope) {
	rs->scope = d_scope_to_x_ScopeT(soap,sf->scope,
					opts,reftab,refstack,depth+1,NULL);
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

    RETURN_REF_OR_ALLOC(symbol,LabelT,s,"sym",s->ref,opts,reftab,refstack,depth,r);
    REF_ALLOC_SEQ_NOSET(LabelT,r);

    FILL_SYMBOLHEADER(s,r,"sym",s->ref);
    FILL_SYMBOLCOMMON(LabelT,s,r);
    FILL_INSTANCESYMBOLCONTENTS(LabelT,s,opts,reftab,refstack,depth,r);

    CLEANUP_REF(symbol,LabelT,s,opts,reftab,refstack,depth,r);

    return r;
}

struct vmi1__BlockT *
d_symbol_to_x_BlockT(struct soap *soap,struct symbol *s,
		     struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
		     struct array_list *refstack,int depth) {
    struct vmi1__BlockT *r = NULL;
    struct __vmi1__BlockT_sequence *rs;
    struct symbol_block *sb;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,BlockT,s,"sym",s->ref,opts,reftab,refstack,depth,r);
    REF_ALLOC_SEQ(BlockT,r,rs);

    FILL_SYMBOLHEADER(s,r,"sym",s->ref);
    FILL_SYMBOLCOMMON(BlockT,s,r);
    FILL_INSTANCESYMBOLCONTENTS(BlockT,s,opts,reftab,refstack,depth,r);

    sb = SYMBOLX_BLOCK(s);
    if (sb->scope) {
	rs->scope = d_scope_to_x_ScopeT(soap,sb->scope,
					opts,reftab,refstack,depth+1,NULL);
    }

    CLEANUP_REF(symbol,BlockT,s,opts,reftab,refstack,depth,r);

    return r;
}

struct vmi1__RootT *
d_symbol_to_x_RootT(struct soap *soap,struct symbol *s,
		     struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
		     struct array_list *refstack,int depth) {
    struct vmi1__RootT *r = NULL;
    struct symbol_root *sr;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,RootT,s,"sym",s->ref,opts,reftab,refstack,depth,r);

    FILL_SYMBOLHEADER(s,r,"sym",s->ref);
    FILL_SYMBOLCOMMON_NOSEQ(RootT,s,r);

    sr = SYMBOLX_ROOT(s);
    if (sr && sr->compdirname) {
	SOAP_STRCPY(soap,r->compilationDir,sr->compdirname);
    }
    if (sr && sr->producer) {
	SOAP_STRCPY(soap,r->producer,sr->producer);
    }
    if (sr && sr->language) {
	SOAP_STRCPY(soap,r->language,sr->language);
    }
    if (sr->scope) {
	r->scope = d_scope_to_x_ScopeT(soap,sr->scope,
					opts,reftab,refstack,depth+1,NULL);
    }

    CLEANUP_REF(symbol,RootT,s,opts,reftab,refstack,depth,r);

    return r;
}

struct vmi1__VoidTypeT *
d_symbol_to_x_VoidTypeT(struct soap *soap,struct symbol *s,
			struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			struct array_list *refstack,int depth) {
    struct vmi1__VoidTypeT *r = NULL;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,VoidTypeT,s,"sym",s->ref,opts,reftab,refstack,depth,r);

    FILL_SYMBOLHEADER(s,r,"sym",s->ref);

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

    RETURN_REF_OR_ALLOC(symbol,BaseTypeT,s,"sym",s->ref,opts,reftab,refstack,depth,r);
    REF_ALLOC_SEQ(BaseTypeT,r,rs);

    FILL_SYMBOLHEADER(s,r,"sym",s->ref);
    FILL_SYMBOLCOMMON(BaseTypeT,s,r);

    if (SYMBOL_IS_FULL(s)) {
	switch (SYMBOLX_ENCODING_V(s)) {
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

    RETURN_REF_OR_ALLOC(symbol,PointerTypeT,s,"sym",s->ref,opts,reftab,refstack,depth,r);
    REF_ALLOC_SEQ_NOSET(PointerTypeT,r);

    FILL_SYMBOLHEADER(s,r,"sym",s->ref);
    FILL_SYMBOLCOMMON(PointerTypeT,s,r);
    FILL_SYMBOLTYPE(PointerTypeT,s,r);

    CLEANUP_REF(symbol,PointerTypeT,s,opts,reftab,refstack,depth,r);

    return r;
}

struct vmi1__RefTypeT *
d_symbol_to_x_RefTypeT(struct soap *soap,struct symbol *s,
		       struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
		       struct array_list *refstack,int depth) {
    struct vmi1__RefTypeT *r = NULL;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,RefTypeT,s,"sym",s->ref,opts,reftab,refstack,depth,r);
    REF_ALLOC_SEQ_NOSET(RefTypeT,r);

    FILL_SYMBOLHEADER(s,r,"sym",s->ref);
    FILL_SYMBOLCOMMON(RefTypeT,s,r);
    FILL_SYMBOLTYPE(RefTypeT,s,r);

    CLEANUP_REF(symbol,RefTypeT,s,opts,reftab,refstack,depth,r);

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

    RETURN_REF_OR_ALLOC(symbol,TypedefTypeT,s,"sym",s->ref,opts,reftab,refstack,depth,r);
    REF_ALLOC_SEQ_NOSET(TypedefTypeT,r);

    FILL_SYMBOLHEADER(s,r,"sym",s->ref);
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

    RETURN_REF_OR_ALLOC(symbol,ConstTypeT,s,"sym",s->ref,opts,reftab,refstack,depth,r);
    REF_ALLOC_SEQ_NOSET(ConstTypeT,r);

    FILL_SYMBOLHEADER(s,r,"sym",s->ref);
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

    RETURN_REF_OR_ALLOC(symbol,VolatileTypeT,s,"sym",s->ref,opts,reftab,refstack,depth,r);
    REF_ALLOC_SEQ_NOSET(VolatileTypeT,r);

    FILL_SYMBOLHEADER(s,r,"sym",s->ref);
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
    GSList *l;
    int i;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,ArrayTypeT,s,"sym",s->ref,opts,reftab,refstack,depth,r);
    REF_ALLOC_SEQ(ArrayTypeT,r,rs);

    FILL_SYMBOLHEADER(s,r,"sym",s->ref);
    FILL_SYMBOLCOMMON(ArrayTypeT,s,r);
    FILL_SYMBOLTYPE(ArrayTypeT,s,r);

    l = SYMBOLX_SUBRANGES(s);
    if (l) {
	rs->subrangeCount = g_slist_length(l);
	rs->subranges = _soap_calloc(soap,sizeof(*rs->subranges));
	rs->subranges->__sizesubrange = rs->subrangeCount;
	if (rs->subrangeCount) {
	    rs->subranges->subrange =		\
		_soap_calloc(soap,
			     rs->subrangeCount * sizeof(*rs->subranges->subrange));
	    i = 0;
	    while (l) {
		rs->subranges->subrange[i] = (int)(uintptr_t)g_slist_nth_data(l,0);
		l = g_slist_next(l);
		++i;
	    }
	}
    }

    CLEANUP_REF(symbol,ArrayTypeT,s,opts,reftab,refstack,depth,r);

    return r;
}

#define FILL_MEMBERS(s,rs,soap,opts,reftab,refstack,depth)		\
    do {								\
        GSList *_members = SYMBOLX_MEMBERS(s);				\
									\
	if (_members) {							\
	    rs->memberCount = (int)(uintptr_t)g_slist_length(_members); \
	    rs->members =						\
		d_symbol_gslist_to_x_SymbolsOptT(soap,_members,opts,reftab, \
						 refstack,(depth)+1);	\
	}								\
	else {								\
	    rs->memberCount = 0;					\
	    rs->members = NULL;						\
	}								\
    } while (0);

struct vmi1__EnumTypeT *
d_symbol_to_x_EnumTypeT(struct soap *soap,struct symbol *s,
		       struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			struct array_list *refstack,int depth) {
    struct vmi1__EnumTypeT *r = NULL;
    struct __vmi1__EnumTypeT_sequence *rs;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,EnumTypeT,s,"sym",s->ref,opts,reftab,refstack,depth,r);
    REF_ALLOC_SEQ(EnumTypeT,r,rs);

    FILL_SYMBOLHEADER(s,r,"sym",s->ref);
    FILL_SYMBOLCOMMON(EnumTypeT,s,r);
    FILL_SYMBOLTYPE(EnumTypeT,s,r);

    FILL_MEMBERS(s,rs,soap,opts,reftab,refstack,depth);

    CLEANUP_REF(symbol,EnumTypeT,s,opts,reftab,refstack,depth,r);

    return r;
}

struct vmi1__StructTypeT *
d_symbol_to_x_StructTypeT(struct soap *soap,struct symbol *s,
			 struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			  struct array_list *refstack,int depth) {
    struct vmi1__StructTypeT *r = NULL;
    struct __vmi1__StructTypeT_sequence *rs;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,StructTypeT,s,"sym",s->ref,opts,reftab,refstack,depth,r);
    REF_ALLOC_SEQ(StructTypeT,r,rs);

    FILL_SYMBOLHEADER(s,r,"sym",s->ref);
    FILL_SYMBOLCOMMON(StructTypeT,s,r);
    FILL_SYMBOLTYPE(StructTypeT,s,r);

    FILL_MEMBERS(s,rs,soap,opts,reftab,refstack,depth);

    CLEANUP_REF(symbol,StructTypeT,s,opts,reftab,refstack,depth,r);

    return r;
}

struct vmi1__ClassTypeT *
d_symbol_to_x_ClassTypeT(struct soap *soap,struct symbol *s,
			 struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			  struct array_list *refstack,int depth) {
    struct vmi1__ClassTypeT *r = NULL;
    struct __vmi1__ClassTypeT_sequence *rs;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,ClassTypeT,s,"sym",s->ref,opts,reftab,refstack,depth,r);
    REF_ALLOC_SEQ(ClassTypeT,r,rs);

    FILL_SYMBOLHEADER(s,r,"sym",s->ref);
    FILL_SYMBOLCOMMON(ClassTypeT,s,r);
    FILL_SYMBOLTYPE(ClassTypeT,s,r);

    FILL_MEMBERS(s,rs,soap,opts,reftab,refstack,depth);

    CLEANUP_REF(symbol,ClassTypeT,s,opts,reftab,refstack,depth,r);

    return r;
}

struct vmi1__NamespaceTypeT *
d_symbol_to_x_NamespaceTypeT(struct soap *soap,struct symbol *s,
			 struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			  struct array_list *refstack,int depth) {
    struct vmi1__NamespaceTypeT *r = NULL;
    struct __vmi1__NamespaceTypeT_sequence *rs;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,NamespaceTypeT,s,"sym",s->ref,opts,reftab,refstack,depth,r);
    REF_ALLOC_SEQ(NamespaceTypeT,r,rs);

    FILL_SYMBOLHEADER(s,r,"sym",s->ref);
    FILL_SYMBOLCOMMON(NamespaceTypeT,s,r);
    FILL_SYMBOLTYPE(NamespaceTypeT,s,r);

    FILL_MEMBERS(s,rs,soap,opts,reftab,refstack,depth);

    CLEANUP_REF(symbol,NamespaceTypeT,s,opts,reftab,refstack,depth,r);

    return r;
}

struct vmi1__TemplateTypeT *
d_symbol_to_x_TemplateTypeT(struct soap *soap,struct symbol *s,
			 struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			  struct array_list *refstack,int depth) {
    struct vmi1__TemplateTypeT *r = NULL;
    struct __vmi1__TemplateTypeT_sequence *rs;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,TemplateTypeT,s,"sym",s->ref,opts,reftab,refstack,depth,r);
    REF_ALLOC_SEQ(TemplateTypeT,r,rs);

    FILL_SYMBOLHEADER(s,r,"sym",s->ref);
    FILL_SYMBOLCOMMON(TemplateTypeT,s,r);
    FILL_SYMBOLTYPE(TemplateTypeT,s,r);

    FILL_MEMBERS(s,rs,soap,opts,reftab,refstack,depth);

    CLEANUP_REF(symbol,TemplateTypeT,s,opts,reftab,refstack,depth,r);

    return r;
}

struct vmi1__UnionTypeT *
d_symbol_to_x_UnionTypeT(struct soap *soap,struct symbol *s,
			struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			 struct array_list *refstack,int depth) {
    struct vmi1__UnionTypeT *r = NULL;
    struct __vmi1__UnionTypeT_sequence *rs;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,UnionTypeT,s,"sym",s->ref,opts,reftab,refstack,depth,r);
    REF_ALLOC_SEQ(UnionTypeT,r,rs);

    FILL_SYMBOLHEADER(s,r,"sym",s->ref);
    FILL_SYMBOLCOMMON(UnionTypeT,s,r);
    FILL_SYMBOLTYPE(UnionTypeT,s,r);

    FILL_MEMBERS(s,rs,soap,opts,reftab,refstack,depth);

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
    GSList *members;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(symbol,FunctionTypeT,s,"sym",s->ref,opts,reftab,refstack,depth,r);
    REF_ALLOC_SEQ(FunctionTypeT,r,rs);

    FILL_SYMBOLHEADER(s,r,"sym",s->ref);
    FILL_SYMBOLCOMMON(FunctionTypeT,s,r);
    FILL_SYMBOLTYPE(FunctionTypeT,s,r);

    members = SYMBOLX_MEMBERS(s);
    if (members) {
	rs->parameterCount = (int)(uintptr_t)g_slist_length(members); 
	rs->parameters = 
	    d_symbol_gslist_to_x_SymbolsOptT(soap,members,opts,reftab,
					     refstack,(depth)+1);
    }
    else {
	rs->parameterCount = 0;
	rs->parameters = NULL;
    }

    if (s->has_unspec_params) 
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
    else if (SYMBOL_IS_FUNC(s)) {
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
	case DATATYPE_FUNC:
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
	else if (SYMBOL_IS_FUNC(s)) {
	    ui->function =						\
		d_symbol_to_x_FunctionT(soap,s,opts,reftab,refstack,depth);
	    *uw = SOAP_UNION__vmi1__union_SymbolsT_function;
	}
	else if (SYMBOL_IS_LABEL(s)) {
	    ui->label =							\
		d_symbol_to_x_LabelT(soap,s,opts,reftab,refstack,depth);
	    *uw = SOAP_UNION__vmi1__union_SymbolsT_label;
	}
	else if (SYMBOL_IS_BLOCK(s)) {
	    ui->block =							\
		d_symbol_to_x_BlockT(soap,s,opts,reftab,refstack,depth);
	    *uw = SOAP_UNION__vmi1__union_SymbolsT_block;
	}
	else if (SYMBOL_IS_ROOT(s)) {
	    ui->root =							\
		d_symbol_to_x_RootT(soap,s,opts,reftab,refstack,depth);
	    *uw = SOAP_UNION__vmi1__union_SymbolsT_root;
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
	    case DATATYPE_CLASS:
		ui->classType =						\
		    d_symbol_to_x_ClassTypeT(soap,s,opts,reftab,refstack,depth);
		*uw = SOAP_UNION__vmi1__union_SymbolsT_classType;
		break;
	    case DATATYPE_NAMESPACE:
		ui->namespaceType =					\
		    d_symbol_to_x_NamespaceTypeT(soap,s,opts,reftab,refstack,depth);
		*uw = SOAP_UNION__vmi1__union_SymbolsT_namespaceType;
		break;
	    case DATATYPE_TEMPLATE:
		ui->templateType =					\
		    d_symbol_to_x_TemplateTypeT(soap,s,opts,reftab,refstack,depth);
		*uw = SOAP_UNION__vmi1__union_SymbolsT_templateType;
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
	    case DATATYPE_REF:
		ui->refType =						\
		    d_symbol_to_x_RefTypeT(soap,s,opts,reftab,refstack,depth);
		*uw = SOAP_UNION__vmi1__union_SymbolsT_pointerType;
		break;
	    case DATATYPE_FUNC:
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

struct vmi1__SymbolsT *
d_symbol_gslist_to_x_SymbolsT(struct soap *soap,
			      GSList *list,
			      struct vmi1__DebugFileOptsT *opts,
			      GHashTable *reftab,
			      struct array_list *refstack,int depth) {
    int i;
    int len = g_slist_length(list);
    struct symbol *s;
    struct vmi1__SymbolsT *r;
    union _vmi1__union_SymbolsT *ui;
    int *uw;
    GSList *gsltmp;

    if (!opts)
	opts = &defDebugFileOpts;

    r = _soap_calloc(soap,sizeof(*r));

    r->__size_SymbolsT = len;
    r->__union_SymbolsT = _soap_calloc(soap,len*sizeof(*r->__union_SymbolsT));

    i = -1;
    v_g_slist_foreach(list,gsltmp,s) {
	++i;

	uw = &r->__union_SymbolsT[i].__union_SymbolsT;
	ui = &r->__union_SymbolsT[i].union_SymbolsT;

	if (SYMBOL_IS_VAR(s)) {
	    ui->variable =						\
		d_symbol_to_x_VariableT(soap,s,opts,reftab,refstack,depth);
	    *uw = SOAP_UNION__vmi1__union_SymbolsT_variable;
	}
	else if (SYMBOL_IS_FUNC(s)) {
	    ui->function =						\
		d_symbol_to_x_FunctionT(soap,s,opts,reftab,refstack,depth);
	    *uw = SOAP_UNION__vmi1__union_SymbolsT_function;
	}
	else if (SYMBOL_IS_LABEL(s)) {
	    ui->label =							\
		d_symbol_to_x_LabelT(soap,s,opts,reftab,refstack,depth);
	    *uw = SOAP_UNION__vmi1__union_SymbolsT_label;
	}
	else if (SYMBOL_IS_BLOCK(s)) {
	    ui->block =							\
		d_symbol_to_x_BlockT(soap,s,opts,reftab,refstack,depth);
	    *uw = SOAP_UNION__vmi1__union_SymbolsT_block;
	}
	else if (SYMBOL_IS_ROOT(s)) {
	    ui->root =							\
		d_symbol_to_x_RootT(soap,s,opts,reftab,refstack,depth);
	    *uw = SOAP_UNION__vmi1__union_SymbolsT_root;
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
	    case DATATYPE_CLASS:
		ui->classType =						\
		    d_symbol_to_x_ClassTypeT(soap,s,opts,reftab,refstack,depth);
		*uw = SOAP_UNION__vmi1__union_SymbolsT_classType;
		break;
	    case DATATYPE_NAMESPACE:
		ui->namespaceType =					\
		    d_symbol_to_x_NamespaceTypeT(soap,s,opts,reftab,refstack,depth);
		*uw = SOAP_UNION__vmi1__union_SymbolsT_namespaceType;
		break;
	    case DATATYPE_TEMPLATE:
		ui->templateType =					\
		    d_symbol_to_x_TemplateTypeT(soap,s,opts,reftab,refstack,depth);
		*uw = SOAP_UNION__vmi1__union_SymbolsT_templateType;
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
	    case DATATYPE_REF:
		ui->refType =						\
		    d_symbol_to_x_RefTypeT(soap,s,opts,reftab,refstack,depth);
		*uw = SOAP_UNION__vmi1__union_SymbolsT_pointerType;
		break;
	    case DATATYPE_FUNC:
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

struct vmi1__SymbolsOptT *
d_symbol_gslist_to_x_SymbolsOptT(struct soap *soap,
				 GSList *list,
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
        d_symbol_gslist_to_x_SymbolsT(soap,list,opts,reftab,refstack,depth);
}

struct vmi1__DebugFileT *
d_debugfile_to_x_DebugFileT(struct soap *soap,struct debugfile *df,
			    struct vmi1__DebugFileOptsT *opts,
			    GHashTable *reftab,struct array_list *refstack,
			    int depth) {
    struct vmi1__DebugFileT *r = NULL;
    struct __vmi1__DebugFileT_sequence *rs;
    int i,flen;
    GSList *gslist;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(debugfile,DebugFileT,df,"dbg",df->id,opts,reftab,refstack,depth,r);
    REF_ALLOC_SEQ(DebugFileT,r,rs);

    *r->sid = _ref_build_int(soap,"dbg",df->id);

    switch (df->type) {
    case DEBUGFILE_TYPE_ELF:
	rs->debugfileType = _vmi1__debugfileType__elf;
	break;
    case DEBUGFILE_TYPE_DWARF:
	rs->debugfileType = _vmi1__debugfileType__dwarf;
	break;
    default:
	rs->debugfileType = _vmi1__debugfileType__none;
	break;
    }

    flen = 0;
    if (df->flags & DEBUGFILE_TYPE_FLAG_KERNEL)
	++flen;
    if (df->flags & DEBUGFILE_TYPE_FLAG_KMOD)
	++flen;

    rs->debugfileTypeFlags = 
	_soap_calloc(soap,1 * sizeof(*rs->debugfileTypeFlags));
    rs->debugfileTypeFlags->__sizedebugfileTypeFlag = flen;
    rs->debugfileTypeFlags->debugfileTypeFlag = 
	_soap_calloc(soap,rs->debugfileTypeFlags->__sizedebugfileTypeFlag * \
		     sizeof(*rs->debugfileTypeFlags->debugfileTypeFlag));

    i = 0;
    if (df->flags & DEBUGFILE_TYPE_FLAG_KERNEL) {
	rs->debugfileTypeFlags->debugfileTypeFlag[i] = 
	    _vmi1__debugfileTypeFlag__kernel;
	++i;
    }
    if (df->flags & DEBUGFILE_TYPE_FLAG_KMOD) {
	rs->debugfileTypeFlags->debugfileTypeFlag[i] = 
	    _vmi1__debugfileTypeFlag__kmod;
	++i;
    }

    /* Done in RETURN_REF_OR_ALLOC above. */
    /*SOAP_STRCPY(soap,rs->name,df->name);*/
    if (df->binfile)
	SOAP_STRCPY(soap,rs->version,df->binfile->version);

    gslist = g_hash_table_get_values_slist(df->srcfiles);
    rs->rootSymbols = d_symbol_gslist_to_x_SymbolsT(soap,gslist,
						    opts,reftab,refstack,depth);
    if (gslist)
	g_slist_free(gslist);

    gslist = g_hash_table_get_values_slist(df->globals);
    rs->globalSymbols = d_symbol_gslist_to_x_SymbolsT(soap,gslist,
						      opts,reftab,refstack,depth);
    if (gslist)
	g_slist_free(gslist);

    CLEANUP_REF(debugfile,DebugFileT,df,opts,reftab,refstack,depth,r);

    return r;
}

struct vmi1__ScopeT *
d_scope_to_x_ScopeT(struct soap *soap,struct scope *st,
		      struct vmi1__DebugFileOptsT *opts,
		      GHashTable *reftab,struct array_list *refstack,int depth,
		      struct vmi1__ScopeT *ir) {
    struct vmi1__ScopeT *r = ir;
    struct __vmi1__ScopeT_sequence *rs;
    struct scope *scope;
    int len;
    int i;
    GSList *gslist;
    GSList *gsltmp;

    if (!opts)
	opts = &defDebugFileOpts;

    RETURN_REF_OR_ALLOC(scope,ScopeT,st,"sc",st->ref,opts,reftab,refstack,depth,r);
    REF_ALLOC_SEQ(ScopeT,r,rs);

    r->sid = _ref_build_int(soap,"sc",st->ref);

    if (st->symbol && symbol_get_name(st->symbol)) {
	SOAP_STRCPY(soap,r->name,symbol_get_name(st->symbol));
    }

    rs->ranges = d_range_to_x_RangesT(soap,st->range,opts,reftab,refstack,depth);

#if 0
    if (st->parent) 
	rs->parent = \
	    d_scope_to_x_ScopeT(soap,st->parent,opts,reftab,refstack,depth+1,NULL);
#endif

    if (st->subscopes)
	len = g_slist_length(st->subscopes);
    else
	len = 0;

    rs->scopes = _soap_calloc(soap,1 * sizeof(*rs->scopes));
    rs->scopes->__sizescope = len;
    if (len)
	rs->scopes->scope = _soap_calloc(soap,len*sizeof(*rs->scopes->scope));
    else
	rs->scopes->scope = NULL;

    if (len) {
	i = 0;
	v_g_slist_foreach(st->subscopes,gsltmp,scope) {
	    d_scope_to_x_ScopeT(soap,scope,opts,reftab,refstack,depth+1,
				&rs->scopes->scope[i]);
	    ++i;
	}
    }

    /* Make a tmp array list of the symbols */
    gslist = NULL;
    if (st->symdict) 
	gslist = symdict_match_syms_by_tab(st->symdict,NULL,SYMBOL_TYPE_FLAG_NONE,
					   0,0,1);
    rs->symbols = d_symbol_gslist_to_x_SymbolsOptT(soap,gslist,opts,
						   reftab,refstack,depth);
    if (gslist)
	g_slist_free(gslist);

    /* Make a tmp array list of the anon symbols */
    gslist = NULL;
    if (st->symdict)
	gslist = symdict_match_syms_by_tab(st->symdict,NULL,SYMBOL_TYPE_FLAG_NONE,
					   1,1,0);
    rs->anonSymbols = d_symbol_gslist_to_x_SymbolsOptT(soap,gslist,opts,
						       reftab,refstack,depth);
    if (gslist)
	g_slist_free(gslist);

    CLEANUP_REF(scope,ScopeT,st,opts,reftab,refstack,depth,r);

    return r;
}
