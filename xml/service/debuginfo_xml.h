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

#include "debuginfo_soapStub.h"
#include "dwdebug.h"
#include <glib.h>

extern struct vmi1__DebugFileOptsT defDebugFileOpts;

struct vmi1__LocationT *
d_location_to_x_LocationT(struct location *l,
			  struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			  int depth);
struct vmi1__RangesT *
d_range_to_x_RangesT(struct range *r,
		     struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
		     int depth);
struct vmi1__VariableT *
d_symbol_to_x_VariableT(struct symbol *s,
			struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			int depth);
struct vmi1__FunctionT *
d_symbol_to_x_FunctionT(struct symbol *symbol,
			struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			int depth);
struct vmi1__LabelT *
d_symbol_to_x_LabelT(struct symbol *symbol,
		     struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
		     int depth);
struct vmi1__VoidTypeT *
d_symbol_to_x_VoidTypeT(struct symbol *symbol,
			struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			int depth);
struct vmi1__BaseTypeT *
d_symbol_to_x_BaseTypeT(struct symbol *symbol,
			struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			int depth);
struct vmi1__PointerTypeT *
d_symbol_to_x_PointerTypeT(struct symbol *symbol,
			   struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			   int depth);
struct vmi1__TypedefTypeT *
d_symbol_to_x_TypedefTypeT(struct symbol *symbol,
			   struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			   int depth);
struct vmi1__ConstTypeT *
d_symbol_to_x_ConstTypeT(struct symbol *symbol,
			 struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			 int depth);
struct vmi1__VolatileTypeT *
d_symbol_to_x_VolatileTypeT(struct symbol *symbol,
			    struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			   int depth);
struct vmi1__ArrayTypeT *
d_symbol_to_x_ArrayTypeT(struct symbol *symbol,
			 struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			 int depth);
struct vmi1__EnumTypeT *
d_symbol_to_x_EnumTypeT(struct symbol *symbol,
			struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			int depth);
struct vmi1__StructTypeT *
d_symbol_to_x_StructTypeT(struct symbol *symbol,
			  struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			  int depth);
struct vmi1__UnionTypeT *
d_symbol_to_x_UnionTypeT(struct symbol *symbol,
			 struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			 int depth);
struct vmi1__FunctionTypeT *
d_symbol_to_x_FunctionTypeT(struct symbol *symbol,
			    struct vmi1__DebugFileOptsT *opts,GHashTable *reftab,
			    int depth);

struct vmi1__SymbolsOrSymbolRefs *
d_symbol_array_list_to_x_SymbolsOrSymbolRefs(struct array_list *list,
					     struct vmi1__DebugFileOptsT *opts,
					     GHashTable *reftab,int depth);

struct vmi1__SymbolOrSymbolRef *
d_symbol_to_x_SymbolOrSymbolRef(struct symbol *s,
				struct vmi1__DebugFileOptsT *opts,
				GHashTable *reftab,int depth);

#endif /* __DEBUGINFO_XML_H__ */
