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

#ifndef __DEBUGINFO_RPC_H__
#define __DEBUGINFO_RPC_H__

#include "debuginfo_rpc_moduleStub.h"
#include "debuginfo_xml.h"

void debuginfo_rpc_init(void);
void debuginfo_rpc_fini(void);

int vmi1__ListDebugFiles(struct soap *soap,
			 struct vmi1__DebugFileOptsT *opts,
			 struct vmi1__DebugFiles *debugFile);
int vmi1__LoadDebugFile(struct soap *soap,
			char *filename,struct vmi1__DebugFileOptsT *opts,
			struct vmi1__DebugFile *debugFile);
int vmi1__LoadDebugFileForBinary(struct soap*,
				 char *filename,
				 struct vmi1__DebugFileOptsT *opts,
				 struct vmi1__DebugFile *r);

int vmi1__LookupSymbolSimple(struct soap *soap,
			     char *filename,char *name,
			     struct vmi1__DebugFileOptsT *opts,
			     struct vmi1__SymbolResponse *r);

int vmi1__LookupSymbol(struct soap *soap,
		       char *filename,char *name,
		       struct vmi1__DebugFileOptsT *opts,
		       struct vmi1__NestedSymbolResponse *r);
int vmi1__LookupAddrSimple(struct soap *soap,
			   char *filename,vmi1__ADDR addr,
			   struct vmi1__DebugFileOptsT *opts,
			   struct vmi1__SymbolResponse *r);
int vmi1__LookupAddr(struct soap *soap,
		     char *filename,vmi1__ADDR addr,
		     struct vmi1__DebugFileOptsT *opts,
		     struct vmi1__NestedSymbolResponse *r);
int vmi1__LookupAllSymbols(struct soap *soap,
			   char *filename,char *name,
			   struct vmi1__DebugFileOptsT *opts,
			   struct vmi1__NestedSymbolResponse *r);

#endif /* __DEBUGINFO_RPC_H__ */
