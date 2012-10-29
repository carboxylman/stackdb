
//gsoapopt c

//gsoap vmi1 service name: debuginfo
//gsoap vmi1 service port: http://anathema.flux.utah.edu/cgi-bin/debuginfo.cgi
//gsoap vmi1 service namespace: http://anathema.flux.utah.edu/schema/vmi/1

//gsoap vmi1 service method-style: document
//gsoap vmi1 service method-encoding: literal

union vmi1__symbolChoice {
    struct _vmi1__variable*              variable                       1;	///< Required element.
    struct _vmi1__function*              function                       1;	///< Required element.
    struct _vmi1__label*                 label                          1;	///< Required element.
    struct _vmi1__voidType*              voidType                       1;	///< Required element.
    struct _vmi1__baseType*              baseType                       1;	///< Required element.
    struct _vmi1__pointerType*           pointerType                    1;	///< Required element.
    struct _vmi1__typedefType*           typedefType                    1;	///< Required element.
    struct _vmi1__constType*             constType                      1;	///< Required element.
    struct _vmi1__volatileType*          volatileType                   1;	///< Required element.
    struct _vmi1__arrayType*             arrayType                      1;	///< Required element.
    struct _vmi1__enumType*              enumType                       1;	///< Required element.
    struct _vmi1__structType*            structType                     1;	///< Required element.
    struct _vmi1__unionType*             unionType                      1;	///< Required element.
    struct _vmi1__functionType*          functionType                   1;	///< Required element.
};

struct vmi1__lookupSymbolResponse {
    $int __sc;
    union vmi1__symbolChoice sc;
};

/*
struct vmi1__lookupSymbolResponse {
    struct _vmi1__symbol *result;
};
*/

int vmi1__lookupSymbol(char *debugfile,char *name,char *filter,char *flags,
		       struct vmi1__lookupSymbolResponse *r);
