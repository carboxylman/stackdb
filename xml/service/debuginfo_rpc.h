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

#include "debuginfo_soapH.h"

int vmi1__ListDebugFiles(struct soap *soap,
			 void *_,
			 struct vmi1__DebugFileList *r);
int vmi1__LoadDebugFile(struct soap *soap,
			char *filename,
			struct vmi1__DebugFile *r);
int vmi1__LoadDebugFileForBinary(struct soap*,
				 char *filename,
				 struct vmi1__DebugFile *r);

int vmi1__LookupSymbolSimple(struct soap *soap,
			     char *filename,char *name,
			     struct vmi1__DebugFileOptsT *opts,
			     struct vmi1__Symbol *r);

int vmi1__LookupSymbol(struct soap *soap,
		       char *filename,char *name,
		       struct vmi1__DebugFileOptsT *opts,
		       struct vmi1__NestedSymbol *r);
int vmi1__LookupAddrSimple(struct soap *soap,
			   char *filename,vmi1__ADDR addr,
			   struct vmi1__DebugFileOptsT *opts,
			   struct vmi1__Symbol *r);
int vmi1__LookupAddr(struct soap *soap,
		     char *filename,vmi1__ADDR addr,
		     struct vmi1__DebugFileOptsT *opts,
		     struct vmi1__NestedSymbol *r);
int vmi1__LookupAllSymbols(struct soap *soap,
			   char *filename,
			   struct vmi1__DebugFileOptsT *opts,
			   struct vmi1__NestedSymbol *r);

#endif /* __DEBUGINFO_RPC_H__ */