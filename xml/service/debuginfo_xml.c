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

struct _vmi1__location *d_location_to_x_location(struct location *l) {
    struct _vmi1__location *vl = calloc(1,sizeof(*vl));
    int i;

    switch(l->loctype) {
    case LOCTYPE_ADDR:
    case LOCTYPE_REALADDR:
	vl->type = _vmi1__location_type__addr;
	vl->__union_location = SOAP_UNION__vmi1__union_location_addr;
	vl->union_location.addr = calloc(1,sizeof(*vl->union_location.addr));
	vl->union_location.addr->addr = l->l.addr;
	break;
    case LOCTYPE_REG:
	vl->type = _vmi1__location_type__reg;
	vl->__union_location = SOAP_UNION__vmi1__union_location_reg;
	vl->union_location.reg = calloc(1,sizeof(*vl->union_location.reg));
	vl->union_location.reg->reg = l->l.reg;
	break;
    case LOCTYPE_REG_ADDR:
	vl->type = _vmi1__location_type__regAddr;
	vl->__union_location = SOAP_UNION__vmi1__union_location_regAddr;
	vl->union_location.regAddr = \
	    calloc(1,sizeof(*vl->union_location.regAddr));
	vl->union_location.regAddr->reg = l->l.reg;
	break;
    case LOCTYPE_REG_OFFSET:
	vl->type = _vmi1__location_type__regOffset;
	vl->__union_location = SOAP_UNION__vmi1__union_location_regOffset;
	vl->union_location.regOffset = \
	    calloc(1,sizeof(*vl->union_location.regOffset));
	vl->union_location.regOffset->reg = l->l.regoffset.reg;
	vl->union_location.regOffset->offset = l->l.regoffset.offset;
	break;
    case LOCTYPE_FBREG_OFFSET:
	vl->type = _vmi1__location_type__fbRegOffset;
	vl->__union_location = SOAP_UNION__vmi1__union_location_fbRegOffset;
	vl->union_location.fbRegOffset = \
	    calloc(1,sizeof(*vl->union_location.fbRegOffset));
	vl->union_location.fbRegOffset->offset = l->l.fboffset;
	break;
    case LOCTYPE_MEMBER_OFFSET:
	vl->type = _vmi1__location_type__memberOffset;
	vl->__union_location = SOAP_UNION__vmi1__union_location_memberOffset;
	vl->union_location.memberOffset = \
	    calloc(1,sizeof(*vl->union_location.memberOffset));
	vl->union_location.memberOffset->offset = l->l.member_offset;
	break;
    case LOCTYPE_RUNTIME:
	vl->type = _vmi1__location_type__runtime;
	vl->__union_location = SOAP_UNION__vmi1__union_location_runtimeLoc;
	vl->union_location.runtimeLoc = "";
	break;
    case LOCTYPE_LOCLIST:
	vl->type = _vmi1__location_type__list;
	vl->__union_location = SOAP_UNION__vmi1__union_location_listLoc;
	vl->union_location.listLoc = \
	    calloc(1,sizeof(*vl->union_location.listLoc));
	
	vl->union_location.listLoc->__sizerangeLoc = l->l.loclist->len;
	vl->union_location.listLoc->rangeLoc =	\
	    calloc(l->l.loclist->len,
		   sizeof(*vl->union_location.listLoc->rangeLoc));

	for (i = 0; i < l->l.loclist->len; ++i) {
	    vl->union_location.listLoc->rangeLoc[i].range = \
		calloc(1,sizeof(*vl->union_location.listLoc->rangeLoc[i].range));
	    vl->union_location.listLoc->rangeLoc[i].range->start = \
		l->l.loclist->list[i]->start;
	    vl->union_location.listLoc->rangeLoc[i].range->end = \
		l->l.loclist->list[i]->end;

	    vl->union_location.listLoc->rangeLoc[i].location = \
		d_location_to_x_location(l->l.loclist->list[i]->loc);
	}
	break;
    case LOCTYPE_UNKNOWN:
    case __LOCTYPE_MAX:
	vl->type = _vmi1__location_type__none;
	vl->__union_location = 0;
	break;
    }

    return vl;
}

struct _vmi1__variable *d_symbol_to_x_variable(struct symbol *s) {
    struct _vmi1__variable *r = calloc(1,sizeof(*r));
    char idbuf[16];
    int len;
    int i;
    struct symbol *ts;

    snprintf(idbuf,16,"%d",s->ref);
    r->id = strdup(idbuf);
    if (symbol_get_name(s))
	r->name = strdup(symbol_get_name(s));
    if (SYMBOL_IS_DWARF(s))
	r->source = _vmi1__variable_source__dwarf;
    else if (SYMBOL_IS_ELF(s))
	r->source = _vmi1__variable_source__elf;
    r->external = (enum xsd__boolean)(s->isexternal & 1);
    r->declaration = (enum xsd__boolean)(s->isdeclaration & 1);
    r->prototyped = (enum xsd__boolean)(s->isprototyped & 1);
    r->param = (enum xsd__boolean)(s->isparam & 1);
    r->member = (enum xsd__boolean)(s->ismember & 1);
    r->enumval = (enum xsd__boolean)(s->isenumval & 1);

    r->size = s->size;
    if (s->has_base_addr)
	r->addr = s->base_addr;
    
    snprintf(idbuf,16,"%d",s->datatype_ref);
    r->id = strdup(idbuf);

    r->inlineInstance = (enum xsd__boolean)(s->isinlineinstance & 1);
    if (SYMBOL_IS_FULL(s)) {
	r->declaredInline = (enum xsd__boolean)(s->s.ii->isdeclinline & 1);
	r->inlined = (enum xsd__boolean)(s->s.ii->isinlined & 1);
    }
    if (SYMBOL_IS_FULL_VAR(s)) {
	r->bitOffset = s->s.ii->d.v.bit_offset;
	r->bitSize = s->s.ii->d.v.bit_size;
    }

    // XXX: do constval!!!

    if (SYMBOL_IS_FULL(s)) {
	if (s->s.ii->origin_ref) {
	    snprintf(idbuf,16,"%d",s->s.ii->origin_ref);
	    r->abstractOriginRef = strdup(idbuf);
	}
	if (s->s.ii->inline_instances
	    && (len = array_list_len(s->s.ii->inline_instances))) {
	    r->inlineInstances = calloc(1,sizeof(*r->inlineInstances));
	    r->inlineInstances->__sizesymbolRef = len;
	    r->inlineInstances->symbolRef = calloc(len,sizeof(xsd__IDREF));
	    for (i = 0; i < len; ++i) {
		ts = (struct symbol *) \
		    array_list_item(s->s.ii->inline_instances,i);
		snprintf(idbuf,16,"%d",ts->ref);
		r->inlineInstances->symbolRef[i] = strdup(idbuf);
	    }
	}
	r->location = d_location_to_x_location(&s->s.ii->l);
    }
    else {
	/* Schema requires us to have one, so we'd better */
	r->location = calloc(1,sizeof(*r->location));
	r->location->__union_location = 0;
	r->location->type = _vmi1__location_type__none;
    }

    return r;
}

struct _vmi1__function *d_symbol_to_x_function(struct symbol *symbol) {
    return NULL;
}

struct _vmi1__label *d_symbol_to_x_label(struct symbol *symbol) {
    return NULL;
}

struct _vmi1__voidType *d_symbol_to_x_voidType(struct symbol *symbol) {
    return NULL;
}

struct _vmi1__baseType *d_symbol_to_x_baseType(struct symbol *symbol) {
    return NULL;
}

struct _vmi1__pointerType *d_symbol_to_x_pointerType(struct symbol *symbol) {
    return NULL;
}

struct _vmi1__typedefType *d_symbol_to_x_typedefType(struct symbol *symbol) {
    return NULL;
}

struct _vmi1__constType *d_symbol_to_x_constType(struct symbol *symbol) {
    return NULL;
}

struct _vmi1__volatileType *d_symbol_to_x_volatileType(struct symbol *symbol) {
    return NULL;
}

struct _vmi1__arrayType *d_symbol_to_x_arrayType(struct symbol *symbol) {
    return NULL;
}

struct _vmi1__enumType *d_symbol_to_x_enumType(struct symbol *symbol) {
    return NULL;
}

struct _vmi1__structType *d_symbol_to_x_structType(struct symbol *symbol) {
    return NULL;
}

struct _vmi1__unionType *d_symbol_to_x_unionType(struct symbol *symbol) {
    return NULL;
}

struct _vmi1__functionType *d_symbol_to_x_functionType(struct symbol *symbol) {
    return NULL;
}

int d_symbol_to_x_symbolchoice(struct symbol *s,
			       union vmi1__symbolChoice *sc,int *sc_which) {
    if (SYMBOL_IS_VAR(s)) {
	sc->variable = d_symbol_to_x_variable(s);
	*sc_which = SOAP_UNION_vmi1__symbolChoice_variable;
    }
    else if (SYMBOL_IS_FUNCTION(s)) {
	sc->function = d_symbol_to_x_function(s);
	*sc_which = SOAP_UNION_vmi1__symbolChoice_function;
    }
    else if (SYMBOL_IS_LABEL(s)) {
	sc->label = d_symbol_to_x_label(s);
	*sc_which = SOAP_UNION_vmi1__symbolChoice_label;
    }
    else if (SYMBOL_IS_TYPE(s)) {
	switch (s->datatype_code) {
	case DATATYPE_VOID:
	    sc->voidType = d_symbol_to_x_voidType(s);
	    *sc_which = SOAP_UNION_vmi1__symbolChoice_voidType;
	    break;
	case DATATYPE_ARRAY:
	    sc->arrayType = d_symbol_to_x_arrayType(s);
	    *sc_which = SOAP_UNION_vmi1__symbolChoice_arrayType;
	    break;
	case DATATYPE_STRUCT:
	    sc->structType = d_symbol_to_x_structType(s);
	    *sc_which = SOAP_UNION_vmi1__symbolChoice_structType;
	    break;
	case DATATYPE_ENUM:
	    sc->enumType = d_symbol_to_x_enumType(s);
	    *sc_which = SOAP_UNION_vmi1__symbolChoice_enumType;
	    break;
	case DATATYPE_PTR:
	    sc->pointerType = d_symbol_to_x_pointerType(s);
	    *sc_which = SOAP_UNION_vmi1__symbolChoice_pointerType;
	    break;
	case DATATYPE_FUNCTION:
	    sc->functionType = d_symbol_to_x_functionType(s);
	    *sc_which = SOAP_UNION_vmi1__symbolChoice_functionType;
	    break;
	case DATATYPE_TYPEDEF:
	    sc->typedefType = d_symbol_to_x_typedefType(s);
	    *sc_which = SOAP_UNION_vmi1__symbolChoice_typedefType;
	    break;
	case DATATYPE_UNION:
	    sc->unionType = d_symbol_to_x_unionType(s);
	    *sc_which = SOAP_UNION_vmi1__symbolChoice_unionType;
	    break;
	case DATATYPE_BASE:
	    sc->baseType = d_symbol_to_x_baseType(s);
	    *sc_which = SOAP_UNION_vmi1__symbolChoice_baseType;
	    break;
	case DATATYPE_CONST:
	    sc->constType = d_symbol_to_x_constType(s);
	    *sc_which = SOAP_UNION_vmi1__symbolChoice_constType;
	    break;
	case DATATYPE_VOL:
	    sc->volatileType = d_symbol_to_x_volatileType(s);
	    *sc_which = SOAP_UNION_vmi1__symbolChoice_volatileType;
	    break;
	default:
	    verror("bad datatype code %d!\n",s->datatype_code);
	    return -1;
	}
    }
    else {
	verror("bad symbol type %d!\n",s->type);
	return -1;
    }

    return 0;
}
