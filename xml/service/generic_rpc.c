/*
 * Copyright (c) 2013 The University of Utah
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

#include <stdsoap2.h>
#include <pthread.h>
#include <sys/prctl.h>

#include "log.h"
#include "alist.h"
#include "generic_rpc.h"

static pthread_mutex_t generic_rpc_mutex = PTHREAD_MUTEX_INITIALIZER;
static int init_done = 0;

static GHashTable *rpc_listener_tab = NULL;

/**
 ** Module init/fini stuff.
 **/
void generic_rpc_init(void) {
    pthread_mutex_lock(&generic_rpc_mutex);

    if (init_done) {
	pthread_mutex_unlock(&generic_rpc_mutex);
	return;
    }

    rpc_listener_tab = 
	g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);

    init_done = 1;

    pthread_mutex_unlock(&generic_rpc_mutex);
}

void generic_rpc_fini(void) {
    GHashTableIter iter;
    struct generic_rpc_listener *tl;

    pthread_mutex_lock(&generic_rpc_mutex);

    if (!init_done) {
	pthread_mutex_unlock(&generic_rpc_mutex);
	return;
    }

    /* Nuke any existing target listeners. */
    g_hash_table_iter_init(&iter,rpc_listener_tab);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer *)&tl)) {
	free(tl);
    }
    g_hash_table_destroy(rpc_listener_tab);
    rpc_listener_tab = NULL;

    init_done = 0;

    pthread_mutex_unlock(&generic_rpc_mutex);
}

struct generic_rpc_listener *
_generic_rpc_lookup_listener(int objid,char *hostname,int port) {
    struct array_list *tll;
    int i;
    struct generic_rpc_listener *tl = NULL;

    tll = (struct array_list *)						\
	g_hash_table_lookup(rpc_listener_tab,(gpointer)(uintptr_t)objid);

    if (tll) {
	array_list_foreach(tll,i,tl) {
	    if (strcmp(hostname,tl->hostname) == 0 && tl->port == port)
		break;
	    else
		tl = NULL;
	}
    }

    return tl;
}
struct generic_rpc_listener *
generic_rpc_lookup_listener(int objid,char *hostname,int port) {
    struct generic_rpc_listener *tl;

    pthread_mutex_lock(&generic_rpc_mutex);
    tl = _generic_rpc_lookup_listener(objid,hostname,port);
    pthread_mutex_unlock(&generic_rpc_mutex);

    return tl;
}

int _generic_rpc_insert_listener(int objid,char *hostname,int port) {
    struct array_list *tll;
    struct generic_rpc_listener *tl = calloc(1,sizeof(*tl));

    tl->objid = objid;
    tl->hostname = strdup(hostname);
    tl->port = port;

    tll = (struct array_list *)						\
	g_hash_table_lookup(rpc_listener_tab,(gpointer)(uintptr_t)objid);

    if (!tll) {
	tll = array_list_create(1);
	g_hash_table_insert(rpc_listener_tab,
			    (gpointer)(uintptr_t)objid,tll);
    }

    array_list_append(tll,tl);

    return 0;
}
int generic_rpc_insert_listener(int objid,char *hostname,int port) {
    int rc;

    pthread_mutex_lock(&generic_rpc_mutex);
    rc = _generic_rpc_insert_listener(objid,hostname,port);
    pthread_mutex_unlock(&generic_rpc_mutex);

    return rc;
}

int _generic_rpc_remove_listener(int objid,char *hostname,int port) {
    struct array_list *tll;
    int i;
    struct generic_rpc_listener *tl;

    tll = (struct array_list *)						\
	g_hash_table_lookup(rpc_listener_tab,(gpointer)(uintptr_t)objid);

    if (!tll) 
	return -1;

    array_list_foreach(tll,i,tl) {
	if (strcmp(hostname,tl->hostname) == 0 && tl->port == port)
	    break;
	else
	    tl = NULL;
    }

    if (tl) {
	array_list_remove_item_at(tll,i);
	free(tl->hostname);
	free(tl);
	return 0;
    }

    return -1;
}

int generic_rpc_remove_listener(int objid,char *hostname,int port) {
    int rc;

    pthread_mutex_lock(&generic_rpc_mutex);
    rc = _generic_rpc_remove_listener(objid,hostname,port);
    pthread_mutex_unlock(&generic_rpc_mutex);

    return rc;
}

int _generic_rpc_remove_all_listeners(int objid) {
    struct array_list *tll;
    int i;
    struct generic_rpc_listener *tl;

    tll = (struct array_list *)						\
	g_hash_table_lookup(rpc_listener_tab,(gpointer)(uintptr_t)objid);

    if (!tll) 
	return 0;

    array_list_foreach(tll,i,tl) {
	free(tl->hostname);
	free(tl);
    }

    array_list_free(tll);
    g_hash_table_remove(rpc_listener_tab,(gpointer)(uintptr_t)objid);

    return 0;
}

int generic_rpc_remove_all_listeners(int objid) {
    int rc;

    pthread_mutex_lock(&generic_rpc_mutex);
    rc = _generic_rpc_remove_all_listeners(objid);
    pthread_mutex_unlock(&generic_rpc_mutex);

    return rc;
}

int generic_rpc_count_listeners(int objid) {
    struct array_list *tll;
    int rc = 0;

    pthread_mutex_lock(&generic_rpc_mutex);
    tll = (struct array_list *) \
	g_hash_table_lookup(rpc_listener_tab,(gpointer)(uintptr_t)objid);
    if (tll)
	rc = array_list_len(tll);
    pthread_mutex_unlock(&generic_rpc_mutex);

    return rc;
}

int generic_rpc_listener_notify_all(int objid,
				    generic_rpc_listener_notifier_t *notifier,
				    void *data) {
    struct array_list *tll;
    int i;
    int rc;
    struct generic_rpc_listener *tl;

    pthread_mutex_lock(&generic_rpc_mutex);

    tll = (struct array_list *) \
	g_hash_table_lookup(rpc_listener_tab,(gpointer)(uintptr_t)objid);

    if (!tll || array_list_len(tll) < 1) 
	return 0;

    array_list_foreach(tll,i,tl) {
	rc = notifier(tl,data);
	if (rc < 0) {
	    vwarnopt(6,LA_XML,LF_RPC,
		     "notifier returned %d on %s:%d; removing!\n",
		     rc,tl->hostname,tl->port);
	    array_list_foreach_delete(tll,i);
	    free(tl->hostname);
	    free(tl);
	}
	else 
	    vdebug(9,LA_XML,LF_RPC,"notified %s:%d\n",tl->hostname,tl->port);
    }

    pthread_mutex_unlock(&generic_rpc_mutex);

    return 0;
}
