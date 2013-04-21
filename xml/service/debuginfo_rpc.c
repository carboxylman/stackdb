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

#include "generic_rpc.h"
#include "debuginfo_rpc.h"
#include "alist.h"
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

/*
 * We don't check error codes for locking this mutex; don't need to
 * since the only way it could fail (unless the mutex structure gets
 * corrupted) is if the calling thread already owns it.
 */
pthread_mutex_t debuginfo_rpc_mutex = PTHREAD_MUTEX_INITIALIZER;

struct vmi1__DebugFileOptsT defDebugFileOpts = {
    .symbolRefDepth = 1,
    .symtabRefDepth = 1,
    .doMultiRef = 0,
};

static int init_done = 0;

void debuginfo_rpc_init(void) {
    pthread_mutex_lock(&debuginfo_rpc_mutex);

    if (init_done) {
	pthread_mutex_unlock(&debuginfo_rpc_mutex);
	return;
    }

    dwdebug_init();
    generic_rpc_init();

    init_done = 1;

    pthread_mutex_unlock(&debuginfo_rpc_mutex);
}

void debuginfo_rpc_fini(void) {
    if (!init_done)
	return;

    pthread_mutex_lock(&debuginfo_rpc_mutex);

    if (!init_done)
	return;

    generic_rpc_fini();
    dwdebug_fini();

    init_done = 0;

    pthread_mutex_unlock(&debuginfo_rpc_mutex);
}

int vmi1__ListDebugFiles(struct soap *soap,
			 struct vmi1__DebugFileOptsT *opts,
			 struct vmi1__DebugFiles *r) {
    struct debugfile *df;
    int i;
    GHashTable *reftab;
    struct array_list *refstack;
    struct array_list *loaded_list;

    debuginfo_rpc_init();

    if (!opts)
	opts = &defDebugFileOpts;

    if (opts->doMultiRef)
	soap_set_omode(soap,SOAP_XML_GRAPH);

    pthread_mutex_lock(&debuginfo_rpc_mutex);

    loaded_list = debugfile_get_loaded_debugfiles();
    r->__size_debugFile = loaded_list ? array_list_len(loaded_list) : 0;
    if (r->__size_debugFile == 0) {
	r->debugFile = NULL;
	pthread_mutex_unlock(&debuginfo_rpc_mutex);
	return SOAP_OK;
    }

    reftab = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);
    refstack = array_list_create(DEF_REFSTACK_SIZE);
    r->debugFile = soap_malloc(soap,r->__size_debugFile * sizeof(*r->debugFile));

    array_list_foreach(loaded_list,i,df) 
	r->debugFile[i] = d_debugfile_to_x_DebugFileT(soap,df,opts,reftab,refstack,0);

    array_list_free(refstack);
    g_hash_table_destroy(reftab);

    array_list_free(loaded_list);

    pthread_mutex_unlock(&debuginfo_rpc_mutex);
    return SOAP_OK;
}

int vmi1__LoadDebugFile(struct soap *soap,
			char *filename,struct vmi1__DebugFileOptsT *opts,
			struct vmi1__DebugFile *r) {
    debuginfo_rpc_init();

    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__LoadDebugFileForBinary(struct soap *soap,
				 char *filename,
				 struct vmi1__DebugFileOptsT *opts,
				 struct vmi1__DebugFile *r) {
    debuginfo_rpc_init();

    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__LookupSymbolSimple(struct soap *soap,
			     char *filename,char *name,
			     struct vmi1__DebugFileOptsT *opts,
			     struct vmi1__SymbolResponse *r) {
    struct debugfile *debugfile;
    struct lsymbol *lsymbol;
    GHashTable *reftab;
    struct array_list *refstack;

    if (!opts)
	opts = &defDebugFileOpts;

    if (opts->doMultiRef)
	soap_set_omode(soap,SOAP_XML_GRAPH);

    if (filename == NULL || name == NULL
	|| strcmp(filename,"") == 0 || strcmp(name,"") == 0) {
	return soap_receiver_fault(soap,"Bad debugfile or name!",
				   "Bad debugfile or name!");
    }

    if (!(debugfile = debugfile_from_file(filename,NULL))) 
	return soap_receiver_fault(soap,"Could not load debugfile!",
				   "Could not load debugfile!");

    lsymbol = debugfile_lookup_sym(debugfile,name,NULL,NULL,SYMBOL_TYPE_NONE);

    if (!lsymbol)
	return soap_receiver_fault(soap,"Could not find symbol!",
				   "Could not find symbol!");

    reftab = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);
    refstack = array_list_create(DEF_REFSTACK_SIZE);
    r->symbol = d_symbol_to_x_SymbolT(soap,lsymbol->symbol,
				      opts,reftab,refstack,0);
    array_list_free(refstack);
    g_hash_table_destroy(reftab);

    lsymbol_release(lsymbol);

    return SOAP_OK;
}


int vmi1__LookupSymbol(struct soap *soap,
		       char *filename,char *name,
		       struct vmi1__DebugFileOptsT *opts,
		       struct vmi1__NestedSymbolResponse *r) {
    struct debugfile *debugfile;
    struct lsymbol *lsymbol;
    GHashTable *reftab;
    struct array_list *refstack;
    char errbuf[64];

    if (!opts)
	opts = &defDebugFileOpts;

    if (opts->doMultiRef)
	soap_set_omode(soap,SOAP_XML_GRAPH);

    if (filename == NULL || name == NULL
	|| strcmp(filename,"") == 0 || strcmp(name,"") == 0) {
	return soap_receiver_fault(soap,"Bad debugfile or name!",
				   "Bad debugfile or name!");
    }
    if (!(debugfile = debugfile_from_file(filename,NULL))) 
	return soap_receiver_fault(soap,"Could not load debugfile!",
				   "Could not load debugfile!");

    lsymbol = debugfile_lookup_sym(debugfile,name,NULL,NULL,SYMBOL_TYPE_NONE);

    if (!lsymbol)
	return soap_receiver_fault(soap,"Could not find symbol!",
				   "Could not find symbol!");

    reftab = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);
    refstack = array_list_create(DEF_REFSTACK_SIZE);
    r->nestedSymbol = \
	d_symbol_array_list_to_x_SymbolsT(soap,lsymbol->chain,
					  opts,reftab,refstack,0);
    if (r->nestedSymbol) 
	vwarn("%d %d %p\n",g_hash_table_size(reftab),
	      r->nestedSymbol->__size_SymbolsT,
	      r->nestedSymbol->__union_SymbolsT);
    else
	vwarn("%d\n",g_hash_table_size(reftab));

    array_list_free(refstack);
    g_hash_table_destroy(reftab);

    lsymbol_release(lsymbol);

    return SOAP_OK;
}

int vmi1__LookupAddrSimple(struct soap *soap,
			   char *filename,vmi1__ADDR addr,
			   struct vmi1__DebugFileOptsT *opts,
			   struct vmi1__SymbolResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__LookupAddr(struct soap *soap,
		     char *filename,vmi1__ADDR addr,
		     struct vmi1__DebugFileOptsT *opts,
		     struct vmi1__NestedSymbolResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__LookupAllSymbols(struct soap *soap,
			   char *filename,char *name,
			   struct vmi1__DebugFileOptsT *opts,
			   struct vmi1__NestedSymbolResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}
