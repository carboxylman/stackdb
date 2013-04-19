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
#include <glib.h>

#include "log.h"
#include "alist.h"
#include "generic_rpc.h"

struct svctype_info {
    /* url -> listener */
    GHashTable *url_listener_tab;
    /* listener_id -> listener */
    GHashTable *id_listener_tab;

    /* objid -> listener (authoritative) */
    GHashTable *objid_listener_tab;
    /* objid -> array_list(listener) */
    GHashTable *objid_listenerlist_tab;
};

static pthread_mutex_t generic_rpc_mutex = PTHREAD_MUTEX_INITIALIZER;
static int init_done = 0;

static int generic_rpc_listener_count = 1;

/* rpc_svctype_t -> struct svctype_info */
static GHashTable *svctype_info_tab;

/* Prototypes. */
void _generic_rpc_unregister_svctype(rpc_svctype_t svctype,int no_hash_delete);

/**
 ** Module init/fini stuff.
 **/
void generic_rpc_init(void) {
    pthread_mutex_lock(&generic_rpc_mutex);

    if (init_done) {
	pthread_mutex_unlock(&generic_rpc_mutex);
	return;
    }

    svctype_info_tab = 
	g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);

    init_done = 1;

    pthread_mutex_unlock(&generic_rpc_mutex);
}

void generic_rpc_fini(void) {
    GHashTableIter iter;
    gpointer key;

    pthread_mutex_lock(&generic_rpc_mutex);

    if (!init_done) {
	pthread_mutex_unlock(&generic_rpc_mutex);
	return;
    }

    g_hash_table_iter_init(&iter,svctype_info_tab);
    while (g_hash_table_iter_next(&iter,&key,NULL)) {
	/* XXX: this function looks up in the tab; does lookup work in iter? */
	_generic_rpc_unregister_svctype((int)(uintptr_t)key,1);
    }
    g_hash_table_destroy(svctype_info_tab);
    svctype_info_tab = NULL;

    init_done = 0;

    pthread_mutex_unlock(&generic_rpc_mutex);
}

struct svctype_info *__get_si(rpc_svctype_t svctype) {
    return (struct svctype_info *) \
	g_hash_table_lookup(svctype_info_tab,(gpointer)(uintptr_t)svctype);
}

void generic_rpc_register_svctype(rpc_svctype_t svctype) {
    struct svctype_info *si;

    pthread_mutex_lock(&generic_rpc_mutex);

    if (__get_si(svctype)) {
	pthread_mutex_unlock(&generic_rpc_mutex);
	return;
    }

    si = calloc(1,sizeof(*si));
    si->url_listener_tab = g_hash_table_new(g_str_hash,g_str_equal);
    si->id_listener_tab = g_hash_table_new(g_direct_hash,g_direct_equal);
    /* We delete the listeners manually in a loop. */
    si->objid_listener_tab = 
	g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);
    si->objid_listenerlist_tab = 
	g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);

    g_hash_table_insert(svctype_info_tab,(gpointer)(uintptr_t)svctype,si);

    pthread_mutex_unlock(&generic_rpc_mutex);
}

static void _generic_rpc_listener_free(struct generic_rpc_listener *l) {
    /* Cleanup any soap state */
    if (soap_valid_socket(l->soap.socket))
	soap_closesock(&(l->soap));
    /* Make sure these has happened... */
    soap_destroy(&l->soap);
    soap_end(&l->soap);
    /* This must be done here, I think. */
    soap_done(&l->soap);
    g_hash_table_destroy(l->objid_tab);
    free(l->url);
    free(l);
}

void _generic_rpc_unregister_svctype(rpc_svctype_t svctype,int no_hash_delete) {
    struct array_list *ll;
    struct generic_rpc_listener *l;
    GHashTableIter iter;
    struct svctype_info *si;

    if (!(si = __get_si(svctype))) 
	return;

    /*
     * We need to remove the listeners
     */
    ll = array_list_create_from_g_hash_table(si->id_listener_tab);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer *)&l)) {
	_generic_rpc_listener_free(l);
    }

    g_hash_table_destroy(si->url_listener_tab);
    g_hash_table_destroy(si->id_listener_tab);
    g_hash_table_destroy(si->objid_listener_tab);

    g_hash_table_iter_init(&iter,si->objid_listenerlist_tab);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer *)&ll)) {
	array_list_free(ll);
    }
    g_hash_table_destroy(si->objid_listenerlist_tab);

    free(si);

    if (!no_hash_delete)
	g_hash_table_remove(svctype_info_tab,(gpointer)(uintptr_t)svctype);
}
void generic_rpc_unregister_svctype(rpc_svctype_t svctype) {
    pthread_mutex_lock(&generic_rpc_mutex);
    _generic_rpc_unregister_svctype(svctype,0);
    pthread_mutex_unlock(&generic_rpc_mutex);
}

struct generic_rpc_listener *
_generic_rpc_lookup_listener_url(rpc_svctype_t svctype,char *url) {
    struct svctype_info *si;

    if (!(si = __get_si(svctype))) 
	return NULL;

    return (struct generic_rpc_listener *) \
	g_hash_table_lookup(si->url_listener_tab,url);
}
struct generic_rpc_listener *
generic_rpc_lookup_listener_url(rpc_svctype_t svctype,char *url) {
    struct generic_rpc_listener *l;

    pthread_mutex_lock(&generic_rpc_mutex);
    l = _generic_rpc_lookup_listener_url(svctype,url);
    pthread_mutex_unlock(&generic_rpc_mutex);

    return l;
}

struct generic_rpc_listener *
_generic_rpc_lookup_listener_id(rpc_svctype_t svctype,int listener_id) {
    struct svctype_info *si;

    if (!(si = __get_si(svctype))) 
	return NULL;

    return (struct generic_rpc_listener *) \
	g_hash_table_lookup(si->id_listener_tab,(gpointer)(uintptr_t)listener_id);
}
struct generic_rpc_listener *
generic_rpc_lookup_listener_id(rpc_svctype_t svctype,int listener_id) {
    struct generic_rpc_listener *l;

    pthread_mutex_lock(&generic_rpc_mutex);
    l = _generic_rpc_lookup_listener_id(svctype,listener_id);
    pthread_mutex_unlock(&generic_rpc_mutex);

    return l;
}

int _generic_rpc_insert_listener(rpc_svctype_t svctype,char *url) {
    struct generic_rpc_listener *l = NULL;
    struct svctype_info *si;

    if (!(si = __get_si(svctype))) 
	return -1;

    if (_generic_rpc_lookup_listener_url(svctype,url)) 
	return -1;

    l = calloc(1,sizeof(*l));

    l->id = generic_rpc_listener_count++;
    l->svctype = svctype;
    l->url = strdup(url);
    l->svctype = svctype;
    l->objid_tab = g_hash_table_new(g_direct_hash,g_direct_equal);

    soap_init2(&l->soap,SOAP_IO_KEEPALIVE,SOAP_IO_KEEPALIVE);
    l->soap.socket_flags = MSG_NOSIGNAL;
    l->soap.tcp_keep_alive = 1;
    /*
     * These are default timeouts for non-owner listener notifications.
     *
     * If the listener is being notified about an object it owns, we
     * increase the timeouts a lot (but not the connect_timeout -- it
     * should be able to *connect* quickly).
     */
    l->soap.connect_timeout = 4;
    l->soap.send_timeout = 4;
    l->soap.recv_timeout = 4;

    g_hash_table_insert(si->url_listener_tab,url,l);
    g_hash_table_insert(si->id_listener_tab,(gpointer)(uintptr_t)l->id,l);

    return l->id;
}
int generic_rpc_insert_listener(rpc_svctype_t svctype,char *url) {
    int rc;

    pthread_mutex_lock(&generic_rpc_mutex);
    rc = _generic_rpc_insert_listener(svctype,url);
    pthread_mutex_unlock(&generic_rpc_mutex);

    return rc;
}

int _generic_rpc_remove_listener(rpc_svctype_t svctype,int listener_id,
				 int no_objid_deletes) {
    struct generic_rpc_listener *l;
    struct generic_rpc_listener *tmpl;
    struct svctype_info *si;
    struct array_list *ll;
    GHashTableIter iter;
    int i;

    if (!(si = __get_si(svctype))) 
	return -1;

    l = (struct generic_rpc_listener *) \
	g_hash_table_lookup(si->id_listener_tab,(gpointer)(uintptr_t)listener_id);
    if (!l)
	return -1;

    g_hash_table_remove(si->id_listener_tab,(gpointer)(uintptr_t)listener_id);
    g_hash_table_remove(si->url_listener_tab,l->url);

    /*
     * We have to go through the objid_listenerlist_table, and remove
     * this listener from any objid/list.
     */
    if (!no_objid_deletes) {
	/* Do the authoritative listener tab */
	g_hash_table_iter_init(&iter,si->objid_listener_tab);
	while (g_hash_table_iter_next(&iter,NULL,(gpointer *)&tmpl)) {
	    if (l == tmpl)
		g_hash_table_iter_remove(&iter);
	}

	/* Do the non-auth listener tab */
	g_hash_table_iter_init(&iter,si->objid_listenerlist_tab);
	while (g_hash_table_iter_next(&iter,NULL,(gpointer *)&ll)) {
	    array_list_foreach(ll,i,tmpl) {
		if (l == tmpl) {
		    array_list_foreach_delete(ll,i);
		    break;
		}
	    }
	}
    }

    _generic_rpc_listener_free(l);

    return 0;
}

int generic_rpc_remove_listener(rpc_svctype_t svctype,int listener_id) {
    int rc;

    pthread_mutex_lock(&generic_rpc_mutex);
    rc = _generic_rpc_remove_listener(svctype,listener_id,0);
    pthread_mutex_unlock(&generic_rpc_mutex);

    return rc;
}

struct generic_rpc_listener *
_generic_rpc_listener_lookup_owner(rpc_svctype_t svctype,int objid) {
    struct svctype_info *si;

    if (!(si = __get_si(svctype))) {
	return NULL;
    }

    return (struct generic_rpc_listener *) \
	g_hash_table_lookup(si->objid_listener_tab,(gpointer)(uintptr_t)objid);
}

int _generic_rpc_unbind_all_listeners_objid(rpc_svctype_t svctype,int objid) {
    struct array_list *ll;
    struct svctype_info *si;

    if (!(si = __get_si(svctype))) 
	return -1;

    ll = (struct array_list *)g_hash_table_lookup(si->objid_listenerlist_tab,
						  (gpointer)(uintptr_t)objid);
    array_list_free(ll);
    g_hash_table_remove(si->objid_listenerlist_tab,(gpointer)(uintptr_t)objid);
    g_hash_table_remove(si->objid_listener_tab,(gpointer)(uintptr_t)objid);

    return 0;
}

int generic_rpc_unbind_all_listeners_objid(rpc_svctype_t svctype,int objid) {
    int rc;

    pthread_mutex_lock(&generic_rpc_mutex);
    rc = _generic_rpc_unbind_all_listeners_objid(svctype,objid);
    pthread_mutex_unlock(&generic_rpc_mutex);

    return rc;
}

int _generic_rpc_unbind_listener_objid(rpc_svctype_t svctype,int listener_id,
				       int objid) {
    struct svctype_info *si;
    struct array_list *ll;
    struct generic_rpc_listener *l;
    struct generic_rpc_listener *tmpl;
    int i;

    if (!(si = __get_si(svctype))) {
	return -1;
    }

    if (!(l = _generic_rpc_lookup_listener_id(svctype,listener_id))) {
	return -1;
    }

    /*
     * Remove the owner, if this binding is the owner.
     */
    if ((l == _generic_rpc_listener_lookup_owner(svctype,objid))) 
	g_hash_table_remove(si->objid_listener_tab,(gpointer)(uintptr_t)objid);

    ll = (struct array_list *) \
	g_hash_table_lookup(si->objid_listenerlist_tab,(gpointer)(uintptr_t)objid);
    if (!ll || array_list_len(ll) < 1)
	return 0;

    /*
     * Remove the listener from the object's list of bound listeners
     */
    array_list_foreach(ll,i,tmpl) {
	if (tmpl == l) {
	    array_list_foreach_delete(ll,i);
	    break;
	}
    }

    return 0;
}

int generic_rpc_unbind_listener_objid(rpc_svctype_t svctype,int listener_id,
				      int objid) {
    int rc;

    pthread_mutex_lock(&generic_rpc_mutex);
    rc = _generic_rpc_unbind_listener_objid(svctype,listener_id,objid);
    pthread_mutex_unlock(&generic_rpc_mutex);

    return rc;
}

int generic_rpc_bind_listener_objid(rpc_svctype_t svctype,int listener_id,
				    int objid,int owns) {
    struct svctype_info *si;
    struct array_list *ll;
    struct generic_rpc_listener *l;

    pthread_mutex_lock(&generic_rpc_mutex);

    if (!(si = __get_si(svctype))) {
	pthread_mutex_unlock(&generic_rpc_mutex);
	return -1;
    }

    if (!(l = _generic_rpc_lookup_listener_id(svctype,listener_id))) {
	pthread_mutex_unlock(&generic_rpc_mutex);
	verror("listener %d does not exist!\n",listener_id);
	return -1;
    }

    if (owns) {
	if (g_hash_table_lookup(si->objid_listener_tab,
				(gpointer)(uintptr_t)objid)) {
	    pthread_mutex_unlock(&generic_rpc_mutex);
	    return -1;
	}

	g_hash_table_insert(si->objid_listener_tab,(gpointer)(uintptr_t)objid,l);
    }

    if (!(ll = (struct array_list *) \
	           g_hash_table_lookup(si->objid_listenerlist_tab,
				       (gpointer)(uintptr_t)objid))) {
	ll = array_list_create(1);
	g_hash_table_insert(si->objid_listenerlist_tab,
			    (gpointer)(uintptr_t)objid,ll);
    }
    else if (array_list_find(ll,l) != -1) {
	pthread_mutex_unlock(&generic_rpc_mutex);
	if (owns)
	    /* This should be impossible, see above if (owns) check. */
	    return 0;
	else {
	    verror("listener %d already on objid %d's list!\n",
		   listener_id,objid);
	    return -1;
	}
    }

    array_list_append(ll,l);

    pthread_mutex_unlock(&generic_rpc_mutex);

    return 0;
}

int generic_rpc_count_listeners(rpc_svctype_t svctype,int objid) {
    struct svctype_info *si;
    struct array_list *ll;
    int rc = 0;

    pthread_mutex_lock(&generic_rpc_mutex);

    if (!(si = __get_si(svctype))) {
	pthread_mutex_unlock(&generic_rpc_mutex);
	return 0;
    }

    ll = (struct array_list *) \
	g_hash_table_lookup(si->objid_listenerlist_tab,(gpointer)(uintptr_t)objid);
    if (ll)
	rc = array_list_len(ll);

    pthread_mutex_unlock(&generic_rpc_mutex);

    return rc;
}

int generic_rpc_listener_notify_all(rpc_svctype_t svctype,int objid,
				    generic_rpc_listener_notifier_t *notifier,
				    void *data) {
    struct array_list *ll;
    int i;
    int rc;
    struct generic_rpc_listener *l;
    struct generic_rpc_listener *owner = NULL;
    struct svctype_info *si;

    pthread_mutex_lock(&generic_rpc_mutex);

    if (!(si = __get_si(svctype))) {
	pthread_mutex_unlock(&generic_rpc_mutex);
	return -1;
    }

    owner = _generic_rpc_listener_lookup_owner(objid,svctype);

    ll = (struct array_list *) \
	g_hash_table_lookup(si->objid_listenerlist_tab,
			    (gpointer)(uintptr_t)objid);

    if (!ll || array_list_len(ll) < 1) {
	pthread_mutex_unlock(&generic_rpc_mutex);
	return 0;
    }

    /*
     * First, contact the authoritative listener.  Change the soap
     * timeouts temporarily; we need to wait for the owner.
     */
    if (owner) {
	owner->soap.connect_timeout = 24 * 60 * 60;
	owner->soap.send_timeout = 24 * 60 * 60;
	owner->soap.recv_timeout = 24 * 60 * 60;

	rc = notifier(owner,1,data);

	owner->soap.connect_timeout = 4;
	owner->soap.send_timeout = 4;
	owner->soap.recv_timeout = 4;
    }

    /*
     * Then do the others.
     */
    array_list_foreach(ll,i,l) {
	if (l == owner)
	    continue;

	rc = notifier(l,0,data);
	if (rc < 0) {
	    vwarnopt(6,LA_XML,LF_RPC,
		     "notifier returned %d on %s for (%d,%d); removing!\n",
		     rc,l->url,svctype,objid);
	    /*
	     * We *must* delete this listener from the list we are
	     * iterating through, because the remove_listener function
	     * will try to remove it and mess up our loop!
	     */
	    array_list_foreach_delete(ll,i);
	    /* Now the list we're currently on will not be touched
	     * (unless there are duplicates, which cannot happen).
	     */
	    _generic_rpc_remove_listener(svctype,l->id,0);
	}
	else { 
	    vdebug(9,LA_XML,LF_RPC,"notified %s for (%d,%d)\n",
		   l->url,svctype,objid);
	}
    }

    pthread_mutex_unlock(&generic_rpc_mutex);

    return 0;
}
