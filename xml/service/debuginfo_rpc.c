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

#include "debuginfo_xml.h"
#include <pthread.h>
#include <glib.h>
#include <errno.h>

/*
 * Overall note about how we handle multi-ref data: gsoap would handle
 * this if it we didn't have this middle layer of translation between
 * our native data structs/unions and the "nice" ones for the XML
 * server; so we have to do an additional layer to help gsoap handle
 * multi-ref data.  Each time we encode one of our data structs that has
 * a unique memory location, we store it in a per-invocation hashtable
 * mapping it to its gsoap C data struct.  Then each time we encode one
 * of our data structs, we check the hashtable quick and simply return
 * the already-encoded version.
 */

extern GHashTable *debugfiles;
extern GHashTable *binaries;
/*
 * We don't check error codes for locking this mutex; don't need to
 * since the only way it could fail (unless the mutex structure gets
 * corrupted) is if the calling thread already owns it.
 */
extern pthread_mutex_t debugfile_mutex;

int vmi1__ListDebugFiles(struct soap *soap,
			 struct vmi1__DebugFileOptsT *opts,
			 struct vmi1__DebugFiles *r) {
    GHashTableIter iter;
    gpointer key, value;
    struct debugfile *df;
    int i;
    GHashTable *reftab;
    
    pthread_mutex_lock(&debugfile_mutex);

    r->__size_debugFile = g_hash_table_size(debugfiles);
    if (r->__size_debugFile == 0) {
	r->debugFile = NULL;
	pthread_mutex_unlock(&debugfile_mutex);
	return SOAP_OK;
    }

    reftab = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);
    r->debugFile = soap_malloc(soap,r->__size_debugFile * sizeof(*r->debugFile));

    g_hash_table_iter_init(&iter,debugfiles);
    i = 0;
    while (g_hash_table_iter_next(&iter,NULL,(gpointer)&df)) {
	r->debugFile[i] = d_debugfile_to_x_DebugFileT(soap,df,opts,reftab,0);
	++i;
    }

    g_hash_table_destroy(reftab);

    pthread_mutex_unlock(&debugfile_mutex);
    return SOAP_OK;
}

int vmi1__LoadDebugFile(struct soap *soap,
			char *filename,struct vmi1__DebugFileOptsT *opts,
			struct vmi1__DebugFile *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__LoadDebugFileForBinary(struct soap *soap,
				 char *filename,
				 struct vmi1__DebugFileOptsT *opts,
				 struct vmi1__DebugFile *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__LookupSymbolSimple(struct soap *soap,
			     char *filename,char *name,
			     struct vmi1__DebugFileOptsT *opts,
			     struct vmi1__Symbol *r) {
    struct debugfile *debugfile;
    struct lsymbol *lsymbol;
    GHashTable *reftab;

    if (!opts)
	opts = &defDebugFileOpts;

    if (filename == NULL || name == NULL
	|| strcmp(filename,"") == 0 || strcmp(name,"") == 0) {
	return soap_receiver_fault(soap,"Bad debugfile or name!",
				   "Bad debugfile or name!");
    }

    debugfile = debugfile_filename_create(filename,DEBUGFILE_TYPE_MAIN);
    if (!debugfile) 
	return soap_receiver_fault(soap,"Could not create debugfile!",
				   "Could not create debugfile!");

    /* Load the DWARF symbols. */
    if (debugfile_load(debugfile,NULL)) {
	return soap_receiver_fault(soap,"Could not load debugfile!",
				   "Could not load debugfile!");
    }

    lsymbol = debugfile_lookup_sym(debugfile,name,NULL,NULL,SYMBOL_TYPE_NONE);

    if (!lsymbol)
	return soap_receiver_fault(soap,"Could not find symbol!",
				   "Could not find symbol!");

    reftab = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);
    r->symbol = d_symbol_to_x_SymbolOrSymbolRef(soap,lsymbol->symbol,
						opts,reftab,0);
    g_hash_table_destroy(reftab);

    lsymbol_release(lsymbol);

    return SOAP_OK;
}


int vmi1__LookupSymbol(struct soap *soap,
		       char *filename,char *name,
		       struct vmi1__DebugFileOptsT *opts,
		       struct vmi1__NestedSymbol *r) {
    struct debugfile *debugfile;
    struct lsymbol *lsymbol;
    GHashTable *reftab;
    char errbuf[64];

    if (!opts)
	opts = &defDebugFileOpts;

    if (filename == NULL || name == NULL
	|| strcmp(filename,"") == 0 || strcmp(name,"") == 0) {
	return soap_receiver_fault(soap,"Bad debugfile or name!",
				   "Bad debugfile or name!");
    }

    debugfile = debugfile_filename_create(filename,DEBUGFILE_TYPE_MAIN);
    if (!debugfile) 
	return soap_receiver_fault(soap,"Could not create debugfile!",
				   "Could not create debugfile!");

    /* Load the DWARF symbols. */
    if (debugfile_load(debugfile,NULL)) {
	return soap_receiver_fault(soap,"Could not load debugfile!",
				   "Could not load debugfile!");
    }

    lsymbol = debugfile_lookup_sym(debugfile,name,NULL,NULL,SYMBOL_TYPE_NONE);

    if (!lsymbol)
	return soap_receiver_fault(soap,"Could not find symbol!",
				   "Could not find symbol!");

    reftab = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);
    r->vmi1__nestedSymbol = \
	d_symbol_array_list_to_x_SymbolsOrSymbolRefs(soap,lsymbol->chain,
						     opts,reftab,0);
    if (r->vmi1__nestedSymbol) 
	vwarn("%d %d %d %p %p\n",g_hash_table_size(reftab),
	      r->vmi1__nestedSymbol->__size_SymbolsOrSymbolRefs_,
	      r->vmi1__nestedSymbol->__sizesymbolRef,
	      r->vmi1__nestedSymbol->__union_SymbolsOrSymbolRefs_,
	      r->vmi1__nestedSymbol->symbolRef);
    else
	vwarn("%d\n",g_hash_table_size(reftab));

    g_hash_table_destroy(reftab);

    lsymbol_release(lsymbol);

    return SOAP_OK;
}

int vmi1__LookupAddrSimple(struct soap *soap,
			   char *filename,vmi1__ADDR addr,
			   struct vmi1__DebugFileOptsT *opts,
			   struct vmi1__Symbol *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__LookupAddr(struct soap *soap,
		     char *filename,vmi1__ADDR addr,
		     struct vmi1__DebugFileOptsT *opts,
		     struct vmi1__NestedSymbol *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__LookupAllSymbols(struct soap *soap,
			   char *filename,
			   struct vmi1__DebugFileOptsT *opts,
			   struct vmi1__NestedSymbol *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}
