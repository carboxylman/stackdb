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

/*
 * Targets as XML SOAP server-monitored objects.
 */
#define MONITOR_OBJTYPE_TARGET 0x08
extern struct monitor_objtype_ops target_rpc_monitor_objtype_ops;

#define MONITORED_TARGET_LAUNCHER "/home/johnsond/git/a3/vmi.obj/xml/service/monitored_target"

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

void target_rpc_insert(int target_id,struct target *target);

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

int vmi1__GetTargetLogs(struct soap *soap,
			vmi1__TargetIdT tid,int maxSize,
			struct vmi1__TargetLogsResponse *r);

int vmi1__InstantiateTarget(struct soap *soap,
			    struct vmi1__TargetSpecT *spec,
			    vmi1__ListenerT *ownerListener,
			    struct vmi1__TargetResponse *r);

int vmi1__PauseTarget(struct soap *soap,
		      vmi1__TargetIdT tid,
		      struct vmi1__NoneResponse *r);
int vmi1__ResumeTarget(struct soap *soap,
		       vmi1__TargetIdT tid,
		      struct vmi1__NoneResponse *r);
int vmi1__CloseTarget(struct soap *soap,
		      vmi1__TargetIdT tid,
		      struct vmi1__NoneResponse *r);
int vmi1__KillTarget(struct soap *soap,
		     vmi1__TargetIdT tid,int kill_sig,
		     struct vmi1__NoneResponse *r);
int vmi1__FinalizeTarget(struct soap *soap,
			 vmi1__TargetIdT tid,
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
/*
// gsoap vmi1 service method-documentation: Add a "client" service
//   endpoint <hostname,port> tuple for the target server to call back
//   to; this gets transformed into a default service URL.  Returns a
//   listenerId that can be passed to the server when instantiating
//   targets, creating probes, and returning actions from probe
//   notification responses.
int vmi1__RegisterTargetListener(struct soap *soap,
				 char *host,int port,enum xsd__boolean ssl,
				 struct vmi1__ListenerIdResponse *r);
// gsoap vmi1 service method-documentation: Add a "client" service
//   endpoint URL for the target server to call back to.  Returns a
//   listenerId that can be passed to the server when instantiating
//   targets, creating probes, and returning actions from probe
//   notification responses.
int vmi1__RegisterTargetListenerURL(struct soap *soap,
				    char *url,enum xsd__boolean ssl,
				    struct vmi1__ListenerIdResponse *r);
// gsoap vmi1 service method-documentation: Remove a listener, and any
//   associations it has with Target/Probe/Action objects.
int vmi1__UnregisterTargetListener(struct soap *soap,
				   vmi1__ListenerIdT listenerId,
				   struct vmi1__NoneResponse *r);
*/
// gsoap vmi1 service method-documentation: Add a non-authoritative
//   listener to @tid. 
int vmi1__TargetBindListener(struct soap *soap,
			     vmi1__TargetIdT tid,vmi1__ListenerT *listener,
			     struct vmi1__NoneResponse *r);
// gsoap vmi1 service method-documentation: Remove a non-authoritative
//   listener from @tid. 
int vmi1__TargetUnbindListener(struct soap *soap,
			       vmi1__TargetIdT tid,vmi1__ListenerT *listener,
			       struct vmi1__NoneResponse *r);

#endif /* __TARGET_RPC_H__ */
