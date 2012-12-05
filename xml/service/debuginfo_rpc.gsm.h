
#module "dbgr" "debuginfo_rpc_module"

#import "xsdc.gsm.h"
#import "debuginfo_xml.gsm.h"

//gsoap vmi1 service name: debuginfo
//gsoap vmi1 service port: http://anathema.flux.utah.edu/cgi-bin/debuginfo.cgi
//gsoap vmi1 service portName: http
//gsoap vmi1 service namespace: http://anathema.flux.utah.edu/schema/vmi/1

//gsoap vmi1 service method-style: document
//gsoap vmi1 service method-encoding: literal


struct vmi1__DebugFile {
    struct vmi1__DebugFileT *vmi1__debugFile;
};
struct vmi1__DebugFiles {
    $int __size_debugFile;
    struct vmi1__DebugFileT **debugFile;
};

struct vmi1__SymbolResponse {
    struct vmi1__SymbolT *symbol;
};
struct vmi1__NestedSymbolResponse {
    struct vmi1__SymbolsT *nestedSymbol;
};

//gsoap vmi1 service method-documentation: returns an array of loaded DebugFiles
int vmi1__ListDebugFiles(struct vmi1__DebugFileOptsT *opts,
			 struct vmi1__DebugFiles *r);
int vmi1__LoadDebugFile(char *filename,struct vmi1__DebugFileOptsT *opts,
			struct vmi1__DebugFile *r);
int vmi1__LoadDebugFileForBinary(char *filename,
				 struct vmi1__DebugFileOptsT *opts,
				 struct vmi1__DebugFile *r);

int vmi1__LookupSymbolSimple(char *filename,char *name,
			     struct vmi1__DebugFileOptsT *opts,
			     struct vmi1__SymbolResponse *r);
int vmi1__LookupSymbol(char *filename,char *name,
		       struct vmi1__DebugFileOptsT *opts,
		       struct vmi1__NestedSymbolResponse *r);
int vmi1__LookupAddrSimple(char *filename,vmi1__ADDR addr,
			   struct vmi1__DebugFileOptsT *opts,
			   struct vmi1__SymbolResponse *r);
int vmi1__LookupAddr(char *filename,vmi1__ADDR addr,
		     struct vmi1__DebugFileOptsT *opts,
		     struct vmi1__NestedSymbolResponse *r);
int vmi1__LookupAllSymbols(char *filename,char *name,
			   struct vmi1__DebugFileOptsT *opts,
			   struct vmi1__NestedSymbolResponse *r);

/*
int vmi1__LookupAddrsByLine(debugfile,line_no)
int vmi1__LookupSymbolByLine(debugfile,line_no) -> Symbol and Addr

int vmi1__ListSourceCodeFiles(debugfile)
int vmi1__ListPublicSymbols(debugfile)
int vmi1__ListGlobalSymbols(debugfile)
int vmi1__ListGlobalTypes(debugfile)
int vmi1__ListSharedTypes(debugfile)
int vmi1__ListElfSymbols(debugfile)
*/
