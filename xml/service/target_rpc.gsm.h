
#module "tgtr" "target_rpc_module"

#import "xsdc.gsm.h"
#import "debuginfo_rpc.gsm.h"
#import "target_xml.gsm.h"

//gsoap vmi1 service name: target
//gsoap vmi1 service port: http://anathema.flux.utah.edu/cgi-bin/target.cgi
//gsoap vmi1 service portName: http
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
struct vmi1__NoneResponse { };

//gsoap vmi1 service method-documentation: 
int vmi1__ListTargetTypes(void *_,
			  struct vmi1__TargetTypesResponse *r);

//gsoap vmi1 service method-documentation: 
int vmi1__ListTargets(void *_,
		      struct vmi1__TargetResponse *r);

int vmi1__GetTarget(vmi1__TargetIdT tid,
		    struct vmi1__TargetResponse *r);

int vmi1__InstantiateTarget(struct vmi1__TargetSpecT *spec,
			    struct vmi1__TargetResponse *r);

int vmi1__PauseTarget(vmi1__TargetIdT tid,
		      struct vmi1__NoneResponse *r);
int vmi1__ResumeTarget(vmi1__TargetIdT tid,
		      struct vmi1__NoneResponse *r);
int vmi1__CloseTarget(vmi1__TargetIdT tid,
		      struct vmi1__NoneResponse *r);
int vmi1__KillTarget(vmi1__TargetIdT tid,
		     struct vmi1__NoneResponse *r);

int vmi1__PauseThread(vmi1__TargetIdT tid,vmi1__ThreadIdT thid,
		      struct vmi1__NoneResponse *r);
int vmi1__ResumeThread(vmi1__TargetIdT tid,vmi1__ThreadIdT thid,
		       struct vmi1__NoneResponse *r);

int vmi1__SinglestepThread(vmi1__TargetIdT tid,vmi1__ThreadIdT thid,
			   struct vmi1__NoneResponse *r);

int vmi1__LookupTargetSymbol(vmi1__TargetIdT tid,char *name,
			     struct vmi1__DebugFileOptsT *opts,
			     struct vmi1__NestedSymbolResponse *r);
int vmi1__LookupTargetAddrSimple(vmi1__TargetIdT tid,vmi1__ADDR addr,
				 struct vmi1__DebugFileOptsT *opts,
				 struct vmi1__SymbolResponse *r);
int vmi1__LookupTargetAddr(vmi1__TargetIdT tid,vmi1__ADDR addr,
			   struct vmi1__DebugFileOptsT *opts,
			   struct vmi1__NestedSymbolResponse *r);
int vmi1__LookupTargetAllSymbols(vmi1__TargetIdT tid,char *name,
				 struct vmi1__DebugFileOptsT *opts,
				 struct vmi1__NestedSymbolResponse *r);


int vmi1__OpenSession(vmi1__TargetIdT tid,
		      vmi1__SessionIdT *sid);

int vmi1__CloseSession(vmi1__TargetIdT tid,
		       vmi1__SessionIdT *sid);

