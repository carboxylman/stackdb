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

#ifndef __DEBUGINFO_XML_H__
#define __DEBUGINFO_XML_H__

#include "debuginfo_soapH.h" 
#include "dwdebug.h"

struct _vmi1__location *d_location_to_x_location(struct location *l);
struct _vmi1__variable *d_symbol_to_x_variable(struct symbol *s);
struct _vmi1__function *d_symbol_to_x_function(struct symbol *symbol);
struct _vmi1__label *d_symbol_to_x_label(struct symbol *symbol);
struct _vmi1__voidType *d_symbol_to_x_voidType(struct symbol *symbol);
struct _vmi1__baseType *d_symbol_to_x_baseType(struct symbol *symbol);
struct _vmi1__pointerType *d_symbol_to_x_pointerType(struct symbol *symbol);
struct _vmi1__typedefType *d_symbol_to_x_typedefType(struct symbol *symbol);
struct _vmi1__constType *d_symbol_to_x_constType(struct symbol *symbol);
struct _vmi1__volatileType *d_symbol_to_x_volatileType(struct symbol *symbol);
struct _vmi1__arrayType *d_symbol_to_x_arrayType(struct symbol *symbol);
struct _vmi1__enumType *d_symbol_to_x_enumType(struct symbol *symbol);
struct _vmi1__structType *d_symbol_to_x_structType(struct symbol *symbol);
struct _vmi1__unionType *d_symbol_to_x_unionType(struct symbol *symbol);
struct _vmi1__functionType *d_symbol_to_x_functionType(struct symbol *symbol);
int d_symbol_to_x_symbolchoice(struct symbol *s,
			       union vmi1__symbolChoice *sc,int *sc_which);

#endif /* __DEBUGINFO_XML_H__ */
