
#module "tgtr" "target_rpc_module"

#import "xsdc.gsm.h"
#import "debuginfo_rpc.gsm.h"
#import "target_xml.gsm.h"

//gsoap vmi1 service name: target
//gsoap vmi1 service namespace: http://anathema.flux.utah.edu/schema/vmi/1

//gsoap vmi1 service method-style: document
//gsoap vmi1 service method-encoding: literal


struct vmi1__TargetTypesResponse {
    $int __size_targetType;
    enum vmi1__TargetTypeT *targetType;
};
struct vmi1__TargetResponse {
    struct vmi1__TargetT *target;
};
struct vmi1__TargetsResponse {
    $int __size_target;
    struct vmi1__TargetT **target;
};
struct vmi1__ProbeResponse {
    struct vmi1__ProbeT *probe;
};
struct vmi1__ListenerIdResponse {
    vmi1__ListenerIdT listenerId;
};
struct vmi1__NoneResponse { };

//gsoap vmi1 service method-documentation: 
int vmi1__ListTargetTypes(void *_,
			  struct vmi1__TargetTypesResponse *r);

//gsoap vmi1 service method-documentation: 
int vmi1__ListTargets(void *_,
		      struct vmi1__TargetsResponse *r);

int vmi1__GetTarget(vmi1__TargetIdT tid,
		    struct vmi1__TargetResponse *r);

int vmi1__InstantiateTarget(struct vmi1__TargetSpecT *spec,
			    vmi1__ListenerIdT ownerListener,
			    struct vmi1__TargetResponse *r);

int vmi1__PauseTarget(vmi1__TargetIdT tid,
		      struct vmi1__NoneResponse *r);
int vmi1__ResumeTarget(vmi1__TargetIdT tid,
		      struct vmi1__NoneResponse *r);
int vmi1__CloseTarget(vmi1__TargetIdT tid,enum xsd__boolean kill,int kill_sig,
		      struct vmi1__NoneResponse *r);

int vmi1__PauseThread(vmi1__TargetIdT tid,vmi1__ThreadIdT thid,
		      struct vmi1__NoneResponse *r);
//int vmi1__ResumeThread(vmi1__TargetIdT tid,vmi1__ThreadIdT thid,
//		       struct vmi1__NoneResponse *r);

//int vmi1__SinglestepThread(vmi1__TargetIdT tid,vmi1__ThreadIdT thid,int steps,
//			   struct vmi1__NoneResponse *r);

int vmi1__LookupTargetSymbolSimple(vmi1__TargetIdT tid,char *name,
				   struct vmi1__DebugFileOptsT *opts,
				   struct vmi1__SymbolResponse *r);
int vmi1__LookupTargetSymbol(vmi1__TargetIdT tid,char *name,
			     struct vmi1__DebugFileOptsT *opts,
			     struct vmi1__NestedSymbolResponse *r);
int vmi1__LookupTargetAddrSimple(vmi1__TargetIdT tid,vmi1__ADDR addr,
				 struct vmi1__DebugFileOptsT *opts,
				 struct vmi1__SymbolResponse *r);
int vmi1__LookupTargetAddr(vmi1__TargetIdT tid,vmi1__ADDR addr,
			   struct vmi1__DebugFileOptsT *opts,
			   struct vmi1__NestedSymbolResponse *r);
int vmi1__LookupTargetLineSimple(vmi1__TargetIdT tid,char *filename,int line,
				 struct vmi1__DebugFileOptsT *opts,
				 struct vmi1__SymbolResponse *r);
int vmi1__LookupTargetLine(vmi1__TargetIdT tid,char *filename,int line,
			   struct vmi1__DebugFileOptsT *opts,
			   struct vmi1__NestedSymbolResponse *r);
/*
int vmi1__LookupTargetLineRegex(vmi1__TargetIdT tid,
				char *filenameRegex,int line,
				struct vmi1__DebugFileOptsT *opts,
				struct vmi1__NestedSymbolResponse *r);
int vmi1__LookupTargetAllSymbols(vmi1__TargetIdT tid,char *name,
				 struct vmi1__DebugFileOptsT *opts,
				 struct vmi1__NestedSymbolResponse *r);
*/

int vmi1__ProbeSymbolSimple(vmi1__TargetIdT tid,vmi1__ThreadIdT thid,
			    char *probeName,char *symbol,
			    struct vmi1__ProbeResponse *r);
int vmi1__ProbeSymbol(vmi1__TargetIdT tid,vmi1__ThreadIdT thid,
		      char *probeName,char *symbol,
		      vmi1__ProbepointStyleT *probepointStyle,
		      vmi1__ProbepointWhenceT *probepointWhence,
		      vmi1__ProbepointSizeT *probepointSize,
		      struct vmi1__ProbeResponse *r);
int vmi1__ProbeAddr(vmi1__TargetIdT tid,vmi1__ThreadIdT thid,
		    char *probeName,vmi1__ADDR addr,
		    vmi1__ProbepointTypeT *probepointType,
		    vmi1__ProbepointStyleT *probepointStyle,
		    vmi1__ProbepointWhenceT *probepointWhence,
		    vmi1__ProbepointSizeT *probepointSize,
		    struct vmi1__ProbeResponse *r);
int vmi1__ProbeLine(vmi1__TargetIdT tid,vmi1__ThreadIdT thid,
		    char *probeName,char *filename,int line,
		    vmi1__ProbepointStyleT *probepointStyle,
		    vmi1__ProbepointWhenceT *probepointWhence,
		    vmi1__ProbepointSizeT *probepointSize,
		    struct vmi1__ProbeResponse *r);
int vmi1__EnableProbe(vmi1__TargetIdT tid,vmi1__ProbeIdT pid,
		      struct vmi1__NoneResponse *r);
int vmi1__DisableProbe(vmi1__TargetIdT tid,vmi1__ProbeIdT pid,
		       struct vmi1__NoneResponse *r);
int vmi1__RemoveProbe(vmi1__TargetIdT tid,vmi1__ProbeIdT pid,
		      struct vmi1__NoneResponse *r);

int vmi1__RegisterTargetListener(char *host,int port,enum xsd__boolean ssl,
				 struct vmi1__ListenerIdResponse *r);
int vmi1__RegisterTargetListenerURL(char *url,enum xsd__boolean ssl,
				    struct vmi1__ListenerIdResponse *r);
int vmi1__UnregisterTargetListener(vmi1__ListenerIdT listenerId,
				   struct vmi1__NoneResponse *r);

int vmi1__TargetBindListener(vmi1__TargetIdT tid,vmi1__ListenerIdT listenerId,
			     struct vmi1__NoneResponse *r);
int vmi1__TargetUnbindListener(vmi1__TargetIdT tid,vmi1__ListenerIdT listenerId,
			       struct vmi1__NoneResponse *r);
