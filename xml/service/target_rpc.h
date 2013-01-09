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

#ifndef __TARGET_RPC_H__
#define __TARGET_RPC_H__

#include "target_rpc_moduleStub.h"
#include "debuginfo_rpc_moduleStub.h"
#include "debuginfo_xml.h"

#include "dwdebug.h"
#include "target_api.h"
#include <glib.h>
#include <pthread.h>

void target_rpc_init(void);
void target_rpc_fini(void);

/*
 * Handle a new request.  Frees/queues the soap struct as necessary; the
 * caller must not free it!
 */
int target_rpc_handle_request(struct soap *soap);

/*
 * Get a target by ID.  Locks/unlocks the target_rpc master mutex.
 */
struct target *target_lookup(int id);

int vmi1__ListTargetTypes(struct soap *soap,
			  void *_,
			  struct vmi1__TargetTypesResponse *r);

//gsoap vmi1 service method-documentation: 
int vmi1__ListTargets(struct soap *soap,
		      void *_,
		      struct vmi1__TargetsResponse *r);

int vmi1__GetTarget(struct soap *soap,
		    vmi1__TargetIdT tid,
		    struct vmi1__TargetResponse *r);

int vmi1__InstantiateTarget(struct soap *soap,
			    struct vmi1__TargetSpecT *spec,
			    struct vmi1__TargetResponse *r);

int vmi1__PauseTarget(struct soap *soap,
		      vmi1__TargetIdT tid,
		      struct vmi1__NoneResponse *r);
int vmi1__ResumeTarget(struct soap *soap,
		       vmi1__TargetIdT tid,
		      struct vmi1__NoneResponse *r);
int vmi1__CloseTarget(struct soap *soap,
		      vmi1__TargetIdT tid,enum xsd__boolean kill,
		      struct vmi1__NoneResponse *r);

int vmi1__PauseThread(struct soap *soap,
		      vmi1__TargetIdT tid,vmi1__ThreadIdT thid,
		      struct vmi1__NoneResponse *r);
int vmi1__ResumeThread(struct soap *soap,
		       vmi1__TargetIdT tid,vmi1__ThreadIdT thid,
		       struct vmi1__NoneResponse *r);

int vmi1__SinglestepThread(struct soap *soap,
			   vmi1__TargetIdT tid,vmi1__ThreadIdT thid,
			   struct vmi1__NoneResponse *r);

int vmi1__LookupTargetSymbol(struct soap *soap,
			     vmi1__TargetIdT tid,char *name,
			     struct vmi1__DebugFileOptsT *opts,
			     struct vmi1__NestedSymbolResponse *r);
int vmi1__LookupTargetAddrSimple(struct soap *soap,
				 vmi1__TargetIdT tid,vmi1__ADDR addr,
				 struct vmi1__DebugFileOptsT *opts,
				 struct vmi1__SymbolResponse *r);
int vmi1__LookupTargetAddr(struct soap *soap,
			   vmi1__TargetIdT tid,vmi1__ADDR addr,
			   struct vmi1__DebugFileOptsT *opts,
			   struct vmi1__NestedSymbolResponse *r);
int vmi1__LookupTargetAllSymbols(struct soap *soap,
				 vmi1__TargetIdT tid,char *name,
				 struct vmi1__DebugFileOptsT *opts,
				 struct vmi1__NestedSymbolResponse *r);

int vmi1__OpenSession(struct soap *soap,
		      vmi1__TargetIdT tid,
		      vmi1__SessionIdT *sid);

int vmi1__CloseSession(struct soap *soap,
		       vmi1__TargetIdT tid,
		       vmi1__SessionIdT *sid);

#endif /* __TARGET_RPC_H__ */
