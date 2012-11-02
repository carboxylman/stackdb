
//gsoapopt c

//gsoap vmi1 service name: debuginfo
//gsoap vmi1 service port: http://anathema.flux.utah.edu/cgi-bin/debuginfo.cgi
//gsoap vmi1 service namespace: http://anathema.flux.utah.edu/schema/vmi/1

//gsoap vmi1 service method-style: document
//gsoap vmi1 service method-encoding: literal

struct vmi1__DebugFile {
    struct vmi1__DebugFileT *vmi1__debugFile;
};
struct vmi1__DebugFileList {
    $int __size_debugFileList;
    struct vmi1__DebugFile **debugFileList;
};
struct vmi1__Symbol {
    struct vmi1__SymbolOrSymbolRef *symbol;
};
struct vmi1__NestedSymbol {
    struct vmi1__SymbolsOrSymbolRefs *vmi1__nestedSymbol;
};

//gsoap vmi1 service method-documentation: returns an array of loaded DebugFiles
int vmi1__ListDebugFiles(void *_,
			 struct vmi1__DebugFileList *r);
int vmi1__LoadDebugFile(char *filename,
			struct vmi1__DebugFile *r);
int vmi1__LoadDebugFileForBinary(char *filename,
				 struct vmi1__DebugFile *r);

int vmi1__LookupSymbolSimple(char *filename,char *name,
			     struct vmi1__DebugFileOptsT *opts,
			     struct vmi1__Symbol *r);
int vmi1__LookupSymbol(char *filename,char *name,
		       struct vmi1__DebugFileOptsT *opts,
		       struct vmi1__NestedSymbol *r);
int vmi1__LookupAddrSimple(char *filename,vmi1__ADDR addr,
			   struct vmi1__DebugFileOptsT *opts,
			   struct vmi1__Symbol *r);
int vmi1__LookupAddr(char *filename,vmi1__ADDR addr,
		     struct vmi1__DebugFileOptsT *opts,
		     struct vmi1__NestedSymbol *r);
int vmi1__LookupAllSymbols(char *filename,
			   struct vmi1__DebugFileOptsT *opts,
			   struct vmi1__NestedSymbol *r);

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
