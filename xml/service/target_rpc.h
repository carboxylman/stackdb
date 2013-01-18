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

#ifndef __TARGET_RPC_H__
#define __TARGET_RPC_H__

#include "target_rpc_moduleStub.h"
#include "debuginfo_rpc_moduleStub.h"
#include "debuginfo_xml.h"

#include "dwdebug.h"
#include "target_api.h"
#include <glib.h>
#include <pthread.h>

struct target_rpc_listener {
    int target_id;
    char *hostname;
    int port;
};

/*
 * Module init stuff.
 */
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
/*
 * Resuming a single thread is not yet supported.
 */
/*
int vmi1__ResumeThread(struct soap *soap,
		       vmi1__TargetIdT tid,vmi1__ThreadIdT thid,
		       struct vmi1__NoneResponse *r);
*/

/*
 * Single stepping a single thread (without having hit a probepoint) is
 * not supported by the target library.  Not sure if it ever will be.
 */
/*
int vmi1__SinglestepThread(struct soap *soap,
			   vmi1__TargetIdT tid,vmi1__ThreadIdT thid,int steps,
			   struct vmi1__NoneResponse *r);
*/

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

int vmi1__ProbeSymbolSimple(struct soap *soap,
			    vmi1__TargetIdT tid,vmi1__ThreadIdT thid,
			    char *probeName,char *symbol,
			    struct vmi1__ProbeResponse *r);
int vmi1__ProbeSymbol(struct soap *soap,
		      vmi1__TargetIdT tid,vmi1__ThreadIdT thid,
		      char *probeName,char *symbol,
		      vmi1__ProbepointStyleT *probepointStyle,
		      vmi1__ProbepointWhenceT *probepointWhence,
		      vmi1__ProbepointSizeT *probepointSize,
		      struct vmi1__ProbeResponse *r);
int vmi1__ProbeAddr(struct soap *soap,
		    vmi1__TargetIdT tid,vmi1__ThreadIdT thid,
		    char *probeName,vmi1__ADDR addr,
		    vmi1__ProbepointTypeT *probepointType,
		    vmi1__ProbepointStyleT *probepointStyle,
		    vmi1__ProbepointWhenceT *probepointWhence,
		    vmi1__ProbepointSizeT *probepointSize,
		    struct vmi1__ProbeResponse *r);
int vmi1__ProbeLine(struct soap *soap,
		    vmi1__TargetIdT tid,vmi1__ThreadIdT thid,
		    char *probeName,char *filename,int line,
		    vmi1__ProbepointStyleT *probepointStyle,
		    vmi1__ProbepointWhenceT *probepointWhence,
		    vmi1__ProbepointSizeT *probepointSize,
		    struct vmi1__ProbeResponse *r);
int vmi1__EnableProbe(struct soap *soap,
		      vmi1__TargetIdT tid,vmi1__ProbeIdT pid,
		      struct vmi1__NoneResponse *r);
int vmi1__DisableProbe(struct soap *soap,
		       vmi1__TargetIdT tid,vmi1__ProbeIdT pid,
		       struct vmi1__NoneResponse *r);
int vmi1__RemoveProbe(struct soap *soap,
		      vmi1__TargetIdT tid,vmi1__ProbeIdT pid,
		      struct vmi1__NoneResponse *r);

int vmi1__RegisterTargetListener(struct soap *soap,
				 vmi1__TargetIdT tid,
				 char *host,int port,enum xsd__boolean ssl,
				 struct vmi1__NoneResponse *r);
int vmi1__UnregisterTargetListener(struct soap *soap,
				   vmi1__TargetIdT tid,
				   char *host,int port,
				   struct vmi1__NoneResponse *r);

#endif /* __TARGET_RPC_H__ */
