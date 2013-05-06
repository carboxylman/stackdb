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

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <glib.h>
#include <pthread.h>
#include <inttypes.h>
#include <glib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>

#include "log.h"
#include "alist.h"
#include "waitpipe.h"
#include "evloop.h"

#include "monitor.h"

static int init_done = 0;

/*
 * Our primary mutex: used for library initialization, serialized access
 * to per-monitor locks;
 */
static pthread_mutex_t monitor_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * Objtypes have a per-type operations struct.
 */
static GHashTable *objtype_ops_tab = NULL;
/*
 * Sometimes objtypes have a global per-type mutex they want locked when
 * they lookup an object; this table stores that.  It is populated at
 * objtype registration.
 */
static GHashTable *objtype_mutex_tab = NULL;
/*
 * Sometimes we quickly want to list all objects of a type, or do 
 * something with them.
 */
static GHashTable *objtype_objid_obj_tab;
/*
 * Each object might have some state associated with it; store it.
 */
static GHashTable *objtype_objid_objstate_tab;

/*
 * This is a global counter for generating unique objids.  Object ids
 * must be globally unique so that objtypes can exist within the same
 * "namespace".
 */
static int monitor_objid_idx = 0;

/*
 * Map of thread IDs to monitors.
 */
static GHashTable *tid_monitor_tab = NULL;
/*
 * Maps of objs/objids to monitors, objtypes, and objid/obj.
 *
 * Each monitor has one primary object associated with it that it
 * monitors, but it may have secondary objects as well.  This table
 * holds them (as well as the primary obj info).
 *
 * Sometimes we want to lookup by obj, sometimes by objid.  So the
 * multiplicity of hashtables is just for convenience.
 */
static GHashTable *obj_monitor_tab = NULL;
static GHashTable *objid_monitor_tab = NULL;
static GHashTable *obj_objtype_tab;
static GHashTable *objid_objtype_tab;
static GHashTable *obj_objid_tab;
static GHashTable *objid_obj_tab;

void monitor_init(void) {
    if (init_done)
	return;

    pthread_mutex_lock(&monitor_mutex);

    if (init_done) {
	pthread_mutex_unlock(&monitor_mutex);
	return;
    }

    objtype_ops_tab = g_hash_table_new(g_direct_hash,g_direct_equal);
    objtype_mutex_tab = g_hash_table_new(g_direct_hash,g_direct_equal);
    objtype_objid_obj_tab = g_hash_table_new(g_direct_hash,g_direct_equal);
    objtype_objid_objstate_tab = g_hash_table_new(g_direct_hash,g_direct_equal);

    tid_monitor_tab = g_hash_table_new(g_direct_hash,g_direct_equal);

    obj_monitor_tab = g_hash_table_new(g_direct_hash,g_direct_equal);
    objid_monitor_tab = g_hash_table_new(g_direct_hash,g_direct_equal);

    obj_objtype_tab = g_hash_table_new(g_direct_hash,g_direct_equal);
    objid_objtype_tab = g_hash_table_new(g_direct_hash,g_direct_equal);

    obj_objid_tab = g_hash_table_new(g_direct_hash,g_direct_equal);
    objid_obj_tab = g_hash_table_new(g_direct_hash,g_direct_equal);

    init_done = 1;

    pthread_mutex_unlock(&monitor_mutex);

    return;
}

void monitor_fini(void) {
    if (!init_done)
	return;

    pthread_mutex_lock(&monitor_mutex);

    if (!init_done) {
	pthread_mutex_unlock(&monitor_mutex);
	return;
    }

    g_hash_table_destroy(tid_monitor_tab);

    g_hash_table_destroy(obj_monitor_tab);
    g_hash_table_destroy(objid_monitor_tab);

    g_hash_table_destroy(obj_objtype_tab);
    g_hash_table_destroy(objid_objtype_tab);

    g_hash_table_destroy(obj_objid_tab);
    g_hash_table_destroy(objid_obj_tab);

    g_hash_table_destroy(objtype_objid_objstate_tab);
    g_hash_table_destroy(objtype_objid_obj_tab);
    g_hash_table_destroy(objtype_ops_tab);
    g_hash_table_destroy(objtype_mutex_tab);

    init_done = 0;

    pthread_mutex_unlock(&monitor_mutex);

    return;
}

int monitor_get_unique_objid(void) {
    int retval;

    pthread_mutex_lock(&monitor_mutex);
    retval = ++monitor_objid_idx;
    while (g_hash_table_lookup(objid_monitor_tab,(gpointer)(uintptr_t)retval))
	++monitor_objid_idx;
    pthread_mutex_unlock(&monitor_mutex);

    return retval;
}

static struct monitor_objtype_ops *__monitor_lookup_objtype_ops(int objtype) {
    struct monitor_objtype_ops *retval;

    retval = g_hash_table_lookup(objtype_ops_tab,(gpointer)(uintptr_t)objtype);

    return retval;
}

static struct monitor_objtype_ops *monitor_lookup_objtype_ops(int objtype) {
    struct monitor_objtype_ops *retval;

    pthread_mutex_lock(&monitor_mutex);
    retval = __monitor_lookup_objtype_ops(objtype);
    pthread_mutex_unlock(&monitor_mutex);

    return retval;
}

static int __monitor_lookup_objid(int objid,
				  int *objtype,void **obj,
				  struct monitor **monitor) {
    struct monitor *_monitor;
    int _objtype;
    void *_obj;

    _monitor = g_hash_table_lookup(objid_monitor_tab,
				   (gpointer)(uintptr_t)objid);
    if (!_monitor) 
	return 0;
    _objtype = (int)(uintptr_t)g_hash_table_lookup(objid_objtype_tab,
						   (gpointer)(uintptr_t)objid);
    if (!_objtype) 
	vwarn("bad objtype %d for obj %p monitor %p!\n",_objtype,obj,_monitor);
    _obj = g_hash_table_lookup(objid_obj_tab,
			       (gpointer)(uintptr_t)objid);

    if (monitor)
	*monitor = _monitor;
    if (objtype)
	*objtype = _objtype;
    if (obj)
	*obj = _obj;

    return 1;
}

int monitor_lookup_objid(int objid,
			 int *objtype,void **obj,
			 struct monitor **monitor) {
    int retval;

    pthread_mutex_lock(&monitor_mutex);
    retval = __monitor_lookup_objid(objid,objtype,obj,monitor);
    pthread_mutex_unlock(&monitor_mutex);

    return retval;
}

int __monitor_lock_objtype(int objtype) {
    pthread_mutex_t *mutex;

    mutex = (pthread_mutex_t *)g_hash_table_lookup(objtype_mutex_tab,
						   (gpointer)(uintptr_t)objtype);
    if (!mutex) 
	return -1;

    pthread_mutex_lock(mutex);
    return 0;
}

int monitor_lock_objtype(int objtype) {
    int rc;

    pthread_mutex_lock(&monitor_mutex);
    rc = __monitor_lock_objtype(objtype);
    pthread_mutex_unlock(&monitor_mutex);

    return rc;
}

int __monitor_unlock_objtype(int objtype) {
    pthread_mutex_t *mutex;

    mutex = (pthread_mutex_t *)g_hash_table_lookup(objtype_mutex_tab,
						   (gpointer)(uintptr_t)objtype);
    if (!mutex) 
	return -1;

    pthread_mutex_unlock(mutex);
    return 0;
}

int monitor_unlock_objtype(int objtype) {
    int rc;

    pthread_mutex_lock(&monitor_mutex);
    rc = __monitor_unlock_objtype(objtype);
    pthread_mutex_unlock(&monitor_mutex);

    return rc;
}

int monitor_unlock_objtype_unsafe(int objtype) {
    return __monitor_unlock_objtype(objtype);
}

struct array_list *monitor_list_objids_by_objtype_lock_objtype(int objtype,
							       int include_null) {
    struct array_list *retval;
    GHashTable *tmp_objid_obj_tab;
    GHashTableIter iter;
    void *obj;
    int rc;
    gpointer objid;

    pthread_mutex_lock(&monitor_mutex);

    rc = __monitor_lock_objtype(objtype);
    if (rc) {
	pthread_mutex_unlock(&monitor_mutex);
	return NULL;
    }
    tmp_objid_obj_tab = (GHashTable *) \
	g_hash_table_lookup(objtype_objid_obj_tab,(gpointer)(uintptr_t)objtype);
    if (!tmp_objid_obj_tab) {
	pthread_mutex_unlock(&monitor_mutex);
	return NULL;
    }

    retval = array_list_create(g_hash_table_size(tmp_objid_obj_tab));
    g_hash_table_iter_init(&iter,tmp_objid_obj_tab);
    while (g_hash_table_iter_next(&iter,&objid,&obj)) {
	if (!include_null && !obj)
	    continue;
	array_list_append(retval,objid);
    }

    pthread_mutex_unlock(&monitor_mutex);

    return retval;
}

struct array_list *monitor_list_objs_by_objtype_lock_objtype(int objtype,
							     int include_null) {
    struct array_list *retval;
    GHashTable *tmp_objid_obj_tab;
    GHashTableIter iter;
    void *obj;
    int rc;

    pthread_mutex_lock(&monitor_mutex);

    rc = __monitor_lock_objtype(objtype);
    if (rc) {
	pthread_mutex_unlock(&monitor_mutex);
	return NULL;
    }
    tmp_objid_obj_tab = (GHashTable *) \
	g_hash_table_lookup(objtype_objid_obj_tab,(gpointer)(uintptr_t)objtype);
    if (!tmp_objid_obj_tab) {
	pthread_mutex_unlock(&monitor_mutex);
	return NULL;
    }

    retval = array_list_create(g_hash_table_size(tmp_objid_obj_tab));
    g_hash_table_iter_init(&iter,tmp_objid_obj_tab);
    while (g_hash_table_iter_next(&iter,NULL,&obj)) {
	if (!include_null && !obj)
	    continue;
	array_list_append(retval,obj);
    }

    pthread_mutex_unlock(&monitor_mutex);

    return retval;
}

int monitor_lookup_objid_lock_objtype(int objid,int objtype,
				      void **obj,struct monitor **monitor) {
    int retval;

    pthread_mutex_lock(&monitor_mutex);
    retval = __monitor_lock_objtype(objtype);
    if (retval) {
	verror("could not find objtype %d -- BUG!\n",objtype);
	pthread_mutex_unlock(&monitor_mutex);
	return 0;
    }
    retval = __monitor_lookup_objid(objid,NULL,obj,monitor);
    if (!retval) {
	vwarnopt(9,LA_LIB,LF_MONITOR,"could not find objid %d\n",objid);
	__monitor_unlock_objtype(objtype);
    }

    pthread_mutex_unlock(&monitor_mutex);

    return retval;
}

int monitor_lookup_objid_lock_objtype_and_monitor(int objid,int objtype,
						  void **obj,
						  struct monitor **monitor) {
    int retval;
    struct monitor *_monitor;

    pthread_mutex_lock(&monitor_mutex);
    retval = __monitor_lock_objtype(objtype);
    if (retval) {
	verror("could not find objtype %d -- BUG!\n",objtype);
	pthread_mutex_unlock(&monitor_mutex);
	return 0;
    }
    retval = __monitor_lookup_objid(objid,NULL,obj,&_monitor);
    if (retval && monitor)
	*monitor = _monitor;
    if (retval && _monitor)
	pthread_mutex_lock(&_monitor->mutex);
    if (!retval) {
	vwarnopt(9,LA_LIB,LF_MONITOR,"could not find objid %d\n",objid);
	__monitor_unlock_objtype(objtype);
    }

    pthread_mutex_unlock(&monitor_mutex);

    return retval;
}

int monitor_lookup_objid_lock_monitor(int objid,
				      int *objtype,void **obj,
				      struct monitor **monitor) {
    int retval;
    struct monitor *_monitor;

    pthread_mutex_lock(&monitor_mutex);
    retval = __monitor_lookup_objid(objid,objtype,obj,&_monitor);
    if (retval && monitor)
	*monitor = _monitor;
    if (retval && _monitor)
	pthread_mutex_lock(&_monitor->mutex);
    pthread_mutex_unlock(&monitor_mutex);

    return retval;
}

static int __monitor_lookup_obj(void *obj,
				int *objtype,int *objid,
				struct monitor **monitor) {
    struct monitor *_monitor;
    int _objtype;
    int _objid;
    
    _monitor = g_hash_table_lookup(obj_monitor_tab,obj);
    if (!_monitor) 
	return 0;
    _objtype = (int)(uintptr_t)g_hash_table_lookup(obj_objtype_tab,obj);
    if (!_objtype) 
	vwarn("bad objtype %d for obj %p monitor %p!\n",_objtype,obj,_monitor);
    _objid = (int)(uintptr_t)g_hash_table_lookup(obj_objid_tab,obj);
    if (!_objid)
	vwarn("bad objid %d for obj %p monitor %p!\n",_objid,obj,_monitor);

    if (monitor)
	*monitor = _monitor;
    if (objtype)
	*objtype = _objtype;
    if (objid)
	*objid = _objid;

    return 1;
}

int monitor_lookup_obj(void *obj,
		       int *objtype,int *objid,
		       struct monitor **monitor) {
    int retval;

    pthread_mutex_lock(&monitor_mutex);
    retval = __monitor_lookup_obj(obj,objtype,objid,monitor);
    pthread_mutex_unlock(&monitor_mutex);

    return retval;
}

int monitor_lookup_obj_lock_monitor(void *obj,
				    int *objtype,int *objid,
				    struct monitor **monitor) {
    int retval;
    struct monitor *_monitor;

    pthread_mutex_lock(&monitor_mutex);
    retval = __monitor_lookup_obj(obj,objtype,objid,&_monitor);
    if (retval && monitor)
	*monitor = _monitor;
    if (retval && _monitor)
	pthread_mutex_lock(&_monitor->mutex);
    pthread_mutex_unlock(&monitor_mutex);

    return retval;
}


static int __monitor_add_obj(struct monitor *monitor,
			     int objid,int objtype,void *obj,void *objstate) {
    int retval = -1;
    struct monitor_objtype_ops *ops;
    int _objtype = 0;
    int _objid = 0;
    void *_obj = NULL;
    struct monitor *_monitor = NULL;
    GHashTable *tmp_tab;

    if (!(ops = __monitor_lookup_objtype_ops(objtype))) {
	verror("unknown objtype %d!\n",objtype);
	errno = EINVAL;
	goto out;
    }

    if (__monitor_lookup_objid(objid,&_objtype,&_obj,&_monitor)) {
	verror("obj %d (%p) already being monitored!\n",objid,_obj);
	errno = EBUSY;
	goto out;
    }

    if (obj && __monitor_lookup_obj(obj,&_objtype,&_objid,&_monitor)) {
	verror("obj %d (%p) already being monitored!\n",_objid,obj);
	errno = EBUSY;
	goto out;
    }

    /*
     * Insert it into all the hashtables.
     */
    g_hash_table_insert(obj_monitor_tab,obj,monitor);
    g_hash_table_insert(objid_monitor_tab,(gpointer)(uintptr_t)objid,monitor);

    g_hash_table_insert(obj_objtype_tab,obj,(gpointer)(uintptr_t)objtype);
    g_hash_table_insert(objid_objtype_tab,(gpointer)(uintptr_t)objid,
			(gpointer)(uintptr_t)objtype);

    g_hash_table_insert(objid_obj_tab,(gpointer)(uintptr_t)objid,obj);
    g_hash_table_insert(obj_objid_tab,obj,(gpointer)(uintptr_t)objid);

    if (ops->evloop_is_attached 
	&& ops->evloop_is_attached(monitor->evloop,obj) > 0) 
	/* Skip attach; already attached. */
	;
    else if (ops->evloop_attach) {
	if (ops->evloop_attach(monitor->evloop,obj) < 0) {
	    verror("could not attach evloop to objid %d (%p)!\n",objid,obj);

	    g_hash_table_remove(obj_monitor_tab,obj);
	    g_hash_table_remove(objid_monitor_tab,(gpointer)(uintptr_t)objid);

	    g_hash_table_remove(obj_objtype_tab,obj);
	    g_hash_table_remove(objid_objtype_tab,(gpointer)(uintptr_t)objid);

	    g_hash_table_remove(objid_obj_tab,(gpointer)(uintptr_t)objid);
	    g_hash_table_remove(obj_objid_tab,obj);

	    goto out;
	}
    }

    tmp_tab = (GHashTable *) \
	g_hash_table_lookup(objtype_objid_obj_tab,(gpointer)(uintptr_t)objtype);
    g_hash_table_insert(tmp_tab,(gpointer)(uintptr_t)objid,obj);
    if (objstate) {
	tmp_tab = (GHashTable *)g_hash_table_lookup(objtype_objid_objstate_tab,
						    (gpointer)(uintptr_t)objtype);
	g_hash_table_insert(tmp_tab,(gpointer)(uintptr_t)objid,objstate);
    }

    retval = 0;

 out:
    return retval;
}

int monitor_add_obj(struct monitor *monitor,int objid,int objtype,void *obj,
		    void *objstate) {
    int retval;

    pthread_mutex_lock(&monitor_mutex);
    pthread_mutex_lock(&monitor->mutex);

    retval = __monitor_add_obj(monitor,objid,objtype,obj,objstate);

    pthread_mutex_unlock(&monitor->mutex);
    pthread_mutex_unlock(&monitor_mutex);

    return retval;
}

static int __monitor_close_obj(struct monitor *monitor,
			       int objid,int objtype,void *obj,
			       int kill,int kill_sig,
			       GHashTable *iter_hashtable) {
    int retval = 0;
    struct monitor_objtype_ops *ops;
    int _objtype = 0;
    int _objid = 0;
    void *_obj = NULL;
    struct monitor *_monitor = NULL;
    void *objstate;

    if (!(ops = __monitor_lookup_objtype_ops(objtype))) {
	verror("unknown objtype %d!\n",objtype);
	errno = EINVAL;
	return -1;
    }

    if (!__monitor_lookup_objid(objid,&_objtype,&_obj,&_monitor)) {
	vwarn("objid %d (%p) not being monitored!\n",objid,obj);
	errno = EINVAL;
	return -1;
    }

    if (!__monitor_lookup_obj(obj,&_objtype,&_objid,&_monitor)) {
	vwarn("objid %d (%p) not being monitored!\n",objid,obj);
	errno = EBUSY;
	return -1;
    }

    retval = 0;

    /* Detach the object. */
    if (ops->evloop_is_attached && !ops->evloop_is_attached(monitor->evloop,obj)) {
	;
    }
    else if (ops->evloop_detach) {
	if (ops->evloop_detach(monitor->evloop,obj) < 0) {
	    verror("error detaching evloop from objid %d (%p)!\n",objid,obj);
	    return -1;
	}
    }

    /* Close the object, with @sig. */
    if (ops->close && ops->close(obj,objstate,kill,kill_sig)) {
	verror("error closing objid %d (kill = %d, kill_sig %d)!\n",
	       objid,kill,kill_sig);
	return -1;
    }

    return retval;
}

int monitor_close_obj(struct monitor *monitor,void *obj,
		      int kill,int kill_sig) {
    int retval;
    int objid = 0;
    int objtype = 0;
    struct monitor *_monitor = NULL;

    pthread_mutex_lock(&monitor_mutex);
    pthread_mutex_lock(&monitor->mutex);

    if (!__monitor_lookup_obj(obj,&objtype,&objid,&_monitor) || !_monitor) {
	verror("could not lookup obj %p!\n",obj);
	errno = EINVAL;
	pthread_mutex_unlock(&monitor->mutex);
	pthread_mutex_unlock(&monitor_mutex);
	return -1;
    }

    retval = __monitor_close_obj(monitor,objid,objtype,obj,kill,kill_sig,NULL);

    pthread_mutex_unlock(&monitor->mutex);
    pthread_mutex_unlock(&monitor_mutex);

    return retval;
}

int monitor_close_objid(struct monitor *monitor,int objid,
		      int kill,int kill_sig) {
    int retval;
    void *obj = NULL;
    int objtype = 0;
    struct monitor *_monitor = NULL;

    pthread_mutex_lock(&monitor_mutex);
    pthread_mutex_lock(&monitor->mutex);

    if (!__monitor_lookup_objid(objid,&objtype,&obj,&_monitor) || !_monitor) {
	verror("could not lookup objid %d!\n",objid);
	errno = EINVAL;
	pthread_mutex_unlock(&monitor->mutex);
	pthread_mutex_unlock(&monitor_mutex);
	return -1;
    }

    retval = __monitor_close_obj(monitor,objid,objtype,obj,kill,kill_sig,NULL);

    pthread_mutex_unlock(&monitor->mutex);
    pthread_mutex_unlock(&monitor_mutex);

    return retval;
}

static int __monitor_del_obj(struct monitor *monitor,
			     int objid,int objtype,void *obj,
			     GHashTable *iter_hashtable) {
    int retval = -1;
    struct monitor_objtype_ops *ops;
    int _objtype = 0;
    int _objid = 0;
    void *_obj = NULL;
    struct monitor *_monitor = NULL;
    GHashTable *tmp_tab;
    void *objstate;

    if (!(ops = __monitor_lookup_objtype_ops(objtype))) {
	verror("unknown objtype %d!\n",objtype);
	errno = EINVAL;
	goto out;
    }

    if (!__monitor_lookup_objid(objid,&_objtype,&_obj,&_monitor)) {
	vwarn("objid %d (%p) not being monitored!\n",objid,obj);
	errno = EINVAL;
	goto out;
    }

    if (!__monitor_lookup_obj(obj,&_objtype,&_objid,&_monitor)) {
	vwarn("objid %d (%p) not being monitored!\n",objid,obj);
	errno = EBUSY;
	goto out;
    }

    retval = 0;

    tmp_tab = (GHashTable *) \
	g_hash_table_lookup(objtype_objid_obj_tab,(gpointer)(uintptr_t)objtype);
    g_hash_table_remove(tmp_tab,(gpointer)(uintptr_t)objid);
    tmp_tab = (GHashTable *)g_hash_table_lookup(objtype_objid_objstate_tab,
						(gpointer)(uintptr_t)objtype);
    objstate = g_hash_table_lookup(tmp_tab,(gpointer)(uintptr_t)objid);
    g_hash_table_remove(tmp_tab,(gpointer)(uintptr_t)objid);


    /* Detach the object. */
    if (ops->evloop_is_attached && !ops->evloop_is_attached(monitor->evloop,obj)) {
	;
    }
    else if (ops->evloop_detach) {
	if (ops->evloop_detach(monitor->evloop,obj) < 0) {
	    verror("could not detach evloop from objid %d (%p);"
		   " removing anyway!\n",objid,obj);
	    retval = -1;
	}
    }

    /* Close the object. */
    if (ops->close && ops->close(obj,objstate,0,0)) {
	verror("could not close objid %d; removing anyway!\n",objid);
	retval = -1;
    }

    /* Fini the object. */
    if (ops->fini && ops->fini(obj,objstate)) {
	verror("could not fini objid %d; removing anyway!\n",objid);
	retval = -1;
    }

    /*
     * Remove it from all the hashtables.
     */
    if (iter_hashtable != obj_monitor_tab)
	g_hash_table_remove(obj_monitor_tab,obj);
    if (iter_hashtable != objid_monitor_tab)
	g_hash_table_remove(objid_monitor_tab,(gpointer)(uintptr_t)objid);

    if (iter_hashtable != obj_objtype_tab)
	g_hash_table_remove(obj_objtype_tab,obj);
    if (iter_hashtable != objid_objtype_tab)
	g_hash_table_remove(objid_objtype_tab,(gpointer)(uintptr_t)objid);

    if (iter_hashtable != objid_obj_tab)
	g_hash_table_remove(objid_obj_tab,(gpointer)(uintptr_t)objid);
    if (iter_hashtable != objid_obj_tab)
	g_hash_table_remove(objid_obj_tab,obj);

 out:
    return retval;
}

int monitor_del_obj(struct monitor *monitor,void *obj) {
    int retval;
    int objid = 0;
    int objtype = 0;
    struct monitor *_monitor = NULL;

    pthread_mutex_lock(&monitor_mutex);
    pthread_mutex_lock(&monitor->mutex);

    if (!__monitor_lookup_obj(obj,&objtype,&objid,&_monitor) || !_monitor) {
	verror("could not lookup obj %p!\n",obj);
	errno = EINVAL;
	pthread_mutex_unlock(&monitor->mutex);
	pthread_mutex_unlock(&monitor_mutex);
	return -1;
    }

    retval = __monitor_del_obj(monitor,objid,objtype,obj,NULL);

    pthread_mutex_unlock(&monitor->mutex);
    pthread_mutex_unlock(&monitor_mutex);

    return retval;
}

int monitor_del_objid(struct monitor *monitor,int objid) {
    int retval;
    void *obj = NULL;
    int objtype = 0;
    struct monitor *_monitor = NULL;

    pthread_mutex_lock(&monitor_mutex);
    pthread_mutex_lock(&monitor->mutex);

    if (!__monitor_lookup_objid(objid,&objtype,&obj,&_monitor) || !_monitor) {
	verror("could not lookup objid %d!\n",objid);
	errno = EINVAL;
	pthread_mutex_unlock(&monitor->mutex);
	pthread_mutex_unlock(&monitor_mutex);
	return -1;
    }

    retval = __monitor_del_obj(monitor,objid,objtype,obj,NULL);

    pthread_mutex_unlock(&monitor->mutex);
    pthread_mutex_unlock(&monitor_mutex);

    return retval;
}

/*
 * Keep this reentrant so it can be called many times without tracking
 * the state of the monitor -- so NULL/-1/0 anything destroyed.
 */
static int __monitor_shutdown(struct monitor *monitor) {
    GHashTableIter iter;
    gpointer obj;
    int objid;
    int objtype;
    struct monitor *_monitor;

    /*
     * Need to close all objs; gracefully shutdown evloop.
     */

    if (!pthread_equal(pthread_self(),monitor->mtid)) {
	verror("only monitor thread can shutdown itself!\n");
	errno = EPERM;
	return -1;
    }

    vdebug(5,LA_LIB,LF_MONITOR,"shutting down monitor 0x%lx\n",monitor->mtid);

    /*
     * Close all the objects.
     */
    g_hash_table_iter_init(&iter,obj_monitor_tab);
    while (g_hash_table_iter_next(&iter,&obj,(gpointer *)&_monitor)) {
	if (monitor == _monitor) {
	    if (!__monitor_lookup_obj(obj,&objtype,&objid,NULL))
		verror("could not lookup obj %p to close it!\n",obj);
	    else {
		vdebug(5,LA_LIB,LF_MONITOR,"closing objid %d\n",objid);
		__monitor_close_obj(monitor,objid,objtype,obj,0,0,obj_monitor_tab);
	    }
	}
    }

    if (monitor->monitor_send_fd > -1) {
	close(monitor->monitor_send_fd);
	monitor->monitor_send_fd = -1;
    }
    if (monitor->child_recv_fd > -1) {
	if (monitor->flags & MONITOR_FLAG_BIDI) {
	    /* This should have been closed when we forked the child... */
	    vwarn("BUG: child_recv_fd still live!\n");
	}
	close(monitor->child_recv_fd);
	monitor->child_recv_fd = -1;
    }

    if (monitor->flags & MONITOR_FLAG_BIDI) {
	if (monitor->child_send_fd > -1) {
	    /* This should have been closed when we forked the child... */
	    vwarn("BUG: child_send_fd still live %d!\n",getpid());
	    close(monitor->child_send_fd);
	    monitor->child_send_fd = -1;
	}
	if (monitor->monitor_recv_fd > -1)  {
	    close(monitor->monitor_recv_fd);
	    monitor->monitor_recv_fd = -1;
	}
    }

    if (monitor->type == MONITOR_TYPE_PROCESS) {
	if (monitor->p.stdin_buf) {
	    free(monitor->p.stdin_buf);
	    monitor->p.stdin_buf = NULL;
	}

	if (monitor->p.stdin_m_fd > -1) {
	    close(monitor->p.stdin_m_fd);
	    monitor->p.stdin_m_fd = -1;
	}
	if (monitor->p.stdin_c_fd > -1) {
	    /* This should have been closed when we forked the child... */
	    vwarn("BUG: p.stdin_c_fd still live!\n");
	    close(monitor->p.stdin_c_fd);
	    monitor->p.stdin_c_fd = -1;
	}

	if (monitor->p.stdout_m_fd > -1) {
	    close(monitor->p.stdout_m_fd);
	    monitor->p.stdout_m_fd = -1;
	}
	if (monitor->p.stdout_c_fd > -1) {
	    /* This should have been closed when we forked the child... */
	    vwarn("BUG: p.stdout_c_fd still live!\n");
	    close(monitor->p.stdout_c_fd);
	    monitor->p.stdout_c_fd = -1;
	}
	if (monitor->p.stdout_log_fd > -1) {
	    close(monitor->p.stdout_log_fd);
	    monitor->p.stdout_log_fd = -1;
	}

	if (monitor->p.stderr_m_fd > -1) {
	    close(monitor->p.stderr_m_fd);
	    monitor->p.stderr_m_fd = -1;
	}
	if (monitor->p.stderr_c_fd > -1) {
	    /* This should have been closed when we forked the child... */
	    vwarn("BUG: p.stderr_c_fd still live!\n");
	    close(monitor->p.stderr_c_fd);
	    monitor->p.stderr_c_fd = -1;
	}
	if (monitor->p.stderr_log_fd > -1) {
	    close(monitor->p.stderr_log_fd);
	    monitor->p.stderr_log_fd = -1;
	}
    }

    if (monitor->evloop) {
	evloop_free(monitor->evloop);
	monitor->evloop = NULL;
    }

    /*
     * Since this is the last function we can guarantee that the monitor
     * thread will call (i.e., another thread could call
     * monitor_destroy() if the monitor thread exits without calling
     * it), we have to remove it from our thread -> monitor table here.
     */
    g_hash_table_remove(tid_monitor_tab,(gpointer)(uintptr_t)monitor->mtid);

    return 0;
}

int monitor_shutdown(struct monitor *monitor) {
    int rc;

    pthread_mutex_lock(&monitor_mutex);
    pthread_mutex_lock(&monitor->mutex);

    rc = __monitor_shutdown(monitor);

    pthread_mutex_unlock(&monitor->mutex);
    pthread_mutex_unlock(&monitor_mutex);

    return rc;
}

static int __monitor_destroy(struct monitor *monitor) {
    GHashTableIter iter;
    gpointer obj;
    int objid;
    int objtype;
    struct monitor *_monitor;
    int found = 1;

    /*
     * If the monitor thread is still running, only that thread can
     * destroy the monitor.  Otherwise, another thread can.
     */
    if (pthread_kill(monitor->mtid,0) == 0
	&& !pthread_equal(pthread_self(),monitor->mtid)) {
	verror("only monitor thread can destroy itself!\n");
	errno = EPERM;
	return -1;
    }

    vdebug(5,LA_LIB,LF_MONITOR,"destroying monitor 0x%lx\n",monitor->mtid);

    /* Make sure. */
    __monitor_shutdown(monitor);

    /*
     * Free all the objects.
     */
    while (found) {
	found = 0;
	g_hash_table_iter_init(&iter,obj_monitor_tab);
	while (g_hash_table_iter_next(&iter,&obj,(gpointer *)&_monitor)) {
	    if (monitor == _monitor) {
		found = 1;

		if (!__monitor_lookup_obj(obj,&objtype,&objid,NULL)) 
		    verror("could not lookup obj %p to free it!\n",obj);
		else {
		    vdebug(5,LA_LIB,LF_MONITOR,"freeing objid %d\n",objid);
		    __monitor_del_obj(monitor,objid,objtype,obj,obj_monitor_tab);
		}

		g_hash_table_iter_remove(&iter);

		break;
	    }
	}
    }

    if (monitor->msg_obj_tab) {
	g_hash_table_destroy(monitor->msg_obj_tab);
	monitor->msg_obj_tab = NULL;
    }

    /*
     * XXX: don't free the callback states; trust that they are
     * associated with a monitored object and will be freed that way.
     */

    free(monitor);

    return 0;
}

int monitor_destroy(struct monitor *monitor) {
    int rc;

    pthread_mutex_lock(&monitor_mutex);
    pthread_mutex_lock(&monitor->mutex);

    rc = __monitor_destroy(monitor);

    pthread_mutex_unlock(&monitor_mutex);

    return rc;
}

int monitor_register_objtype(int objtype,struct monitor_objtype_ops *ops,
			     pthread_mutex_t *mutex) {
    pthread_mutex_lock(&monitor_mutex);

    if (g_hash_table_lookup(objtype_ops_tab,(gpointer)(uintptr_t)objtype)) {
	verror("monitor objtype %d already exists!\n",objtype);
	errno = EBUSY;
	pthread_mutex_unlock(&monitor_mutex);
	return -1;
    }

    g_hash_table_insert(objtype_ops_tab,(gpointer)(uintptr_t)objtype,ops);
    if (mutex)
	g_hash_table_insert(objtype_mutex_tab,(gpointer)(uintptr_t)objtype,
			    mutex);
    g_hash_table_insert(objtype_objid_obj_tab,(gpointer)(uintptr_t)objtype,
			g_hash_table_new(g_direct_hash,g_direct_equal));
    g_hash_table_insert(objtype_objid_objstate_tab,(gpointer)(uintptr_t)objtype,
			g_hash_table_new(g_direct_hash,g_direct_equal));

    pthread_mutex_unlock(&monitor_mutex);

    return objtype;
}

int __monitor_recv_evh(int fd,int fdtype,void *state) {
    struct monitor *monitor = (struct monitor *)state;
    struct monitor_msg *msg;
    struct monitor_objtype_ops *ops;
    int retval = EVLOOP_HRET_SUCCESS;
    int objtype = -1;
    void *obj = NULL;

    /* XXX: need to hold monitor lock?!  But cannot; we need to be done
       with global lock by the time we hold the monitor's lock. */

    /* XXX: don't bother checking if @fd == @monitor->monitor_reply_fd */
    msg = monitor_recv(monitor);

    if (!msg) {
	verror("could not recv msg on fd %d; closing!\n",fd);
	close(fd);
	monitor->monitor_recv_fd = -1;
	retval = EVLOOP_HRET_REMOVETYPE;
	goto out;
    }

    if (!monitor_lookup_objid(msg->objid,&objtype,&obj,NULL)) {
	verror("could not lookup objid %d; ignoring msg!\n",msg->objid);
	retval = EVLOOP_HRET_SUCCESS;
	goto out;
    }

    ops = monitor_lookup_objtype_ops(objtype);
    if (!ops) {
	verror("unknown objtype %d; ignoring msg!\n",objtype);
	retval = EVLOOP_HRET_SUCCESS;
	goto out;
    }

    vdebug(9,LA_LIB,LF_MONITOR,
	   "defhandler: recv type(%d) objid(%d) %d:%d '%s' (%d)\n",
	   objtype,msg->objid,msg->id,msg->seqno,msg->msg,msg->len);

    if (ops->recv_msg) {
	ops->recv_msg(monitor,msg);
	return retval;
    }

 out:
    if (msg)
	monitor_msg_free(msg);

    return retval;
}

int __monitor_child_recv_evh(int fd,int fdtype,void *state) {
    struct monitor *monitor = (struct monitor *)state;
    struct monitor_msg *msg;
    struct monitor_objtype_ops *ops;
    int retval = EVLOOP_HRET_SUCCESS;
    int objtype = -1;
    void *obj = NULL;

    /* XXX: locking; see above function. */

    /* XXX: don't bother checking if @fd == @monitor->monitor_reply_fd */
    msg = monitor_child_recv(monitor);

    if (!msg) {
	verror("could not recv msg on fd %d; closing!\n",fd);
	close(fd);
	monitor->child_recv_fd = -1;
	retval = EVLOOP_HRET_REMOVETYPE;
	goto out;
    }

    if (!monitor_lookup_objid(msg->objid,&objtype,&obj,NULL)) {
	vwarn("could not lookup objid %d; ignoring msg!\n",msg->objid);
	retval = EVLOOP_HRET_SUCCESS;
	goto out;
    }

    ops = monitor_lookup_objtype_ops(objtype);
    if (!ops) {
	vwarn("unknown objtype %d; ignoring msg\n",objtype);
	retval = EVLOOP_HRET_SUCCESS;
	goto out;
    }

    vdebug(9,LA_LIB,LF_MONITOR,
	   "defhandler: recv type(%d) objid(%d) %hd:%hd '%s' (%d)\n",
	   objtype,msg->objid,msg->id,msg->seqno,msg->msg,msg->len);

    if (ops && ops->child_recv_msg) {
	ops->child_recv_msg(monitor,msg);
	return retval;
    }

 out:
    if (msg)
	monitor_msg_free(msg);

    return retval;
}

int __safe_write(int fd,char *buf,int count) {
    int rc = 0;
    int retval;

    while (rc < count) {
        retval = write(fd,buf + rc,count - rc);
	if (retval < 0) {
	    if (errno == EINTR)
		continue;
	    else if (errno == EAGAIN || errno == EWOULDBLOCK) {
		return rc;
	    }
	    else {
	        verror("write(%d): %s\n",fd,strerror(errno));
		return retval;
	    }
	}
	else 
	    rc += retval;
    }

    return rc;
}

static int __monitor_stdout_evh(int fd,int fdtype,void *state) {
    struct monitor *monitor = (struct monitor *)state;
    int logfd = -1;
    monitor_stdio_callback_t callback;
    void *callback_state;
    char buf[256];
    int rc = 0;
    int retval;
    char *str = "out";

    if (fd == monitor->p.stdout_m_fd) {
	logfd = monitor->p.stdout_log_fd;
	callback = monitor->p.stdout_callback;
	callback_state = monitor->p.stdout_callback_state;
    }
    else if (fd == monitor->p.stderr_m_fd) {
	str = "err";
	logfd = monitor->p.stderr_log_fd;
	callback = monitor->p.stderr_callback;
	callback_state = monitor->p.stderr_callback_state;
    }
    else {
	verror("unknown stdout/err fd %d -- BUG!\n",fd);
	return EVLOOP_HRET_BADERROR;
    }

    while (rc < (int)sizeof(buf)) {
        retval = read(fd,buf + rc,sizeof(buf) - 1 - rc);
	if (retval < 0) {
	    if (errno == EINTR)
		continue;
	    else if (errno == EAGAIN || errno == EWOULDBLOCK) {
		/* Stop here; fire callback if we need */
		if (callback && rc) {
		    buf[rc] = '\0';
		    callback(fd,buf,rc,callback_state);
		}
		if (logfd > -1) 
		    __safe_write(logfd,buf,rc);
		return EVLOOP_HRET_SUCCESS;
	    }
	    else {
	        verror("read(%d): %s (closing)\n",fd,strerror(errno));
		close(fd);
		return EVLOOP_HRET_REMOVETYPE;
	    }
	}
	else if (retval == 0) {
	    if (rc && callback) {
		buf[rc] = '\0';
		callback(fd,buf,rc,callback_state);
	    }
	    if (logfd > -1) 
		__safe_write(logfd,buf,rc);
	    vdebug(8,LA_LIB,LF_MONITOR,"closing std%s (%d) after EOF\n",str,fd);
	    return EVLOOP_HRET_REMOVETYPE;
	}
	else {
	    rc += retval;
	    if (retval == sizeof(buf)) {
		if (callback) {
		    buf[rc] = '\0';
		    callback(fd,buf,rc,callback_state);
		}
		if (logfd > -1) 
		    __safe_write(logfd,buf,rc);
		rc = 0;
	    }
	}
    }

    return EVLOOP_HRET_SUCCESS;
}

static int __monitor_stdin_evh(int fd,int fdtype,void *state) {
    struct monitor *monitor = (struct monitor *)state;
    monitor_stdio_callback_t callback;
    void *callback_state;
    char buf[256];
    int rc = 0;
    int retval;

    if (fd == STDIN_FILENO) {
	callback = monitor->stdin_callback;
	callback_state = monitor->stdin_callback_state;
    }
    else {
	verror("unknown stdin fd %d -- BUG!\n",fd);
	return EVLOOP_HRET_BADERROR;
    }

    while (1) {
        retval = read(fd,buf + rc,sizeof(buf) - rc);
	if (retval < 0) {
	    if (errno == EINTR)
		continue;
	    else if (errno == EAGAIN || errno == EWOULDBLOCK) {
		/* Stop here; fire callback if we need */
		if (callback && rc) {
		    buf[rc] = '\0';
		    callback(fd,buf,rc,callback_state);
		}
		return EVLOOP_HRET_SUCCESS;
	    }
	    else {
	        verror("read(%d): %s (closing)\n",fd,strerror(errno));
		close(fd);
		return EVLOOP_HRET_REMOVETYPE;
	    }
	}
	else if (retval == 0) {
	    if (rc && callback) {
		buf[rc] = '\0';
		callback(fd,buf,rc,callback_state);
	    }
	    vdebug(8,LA_LIB,LF_MONITOR,"closing stdin after EOF\n",fd);
	    close(fd);
	    return EVLOOP_HRET_REMOVEALLTYPES;
	}
	else {
	    rc += retval;
	    if (retval == sizeof(buf)) {
		if (callback) {
		    buf[rc] = '\0';
		    callback(fd,buf,rc,callback_state);
		}
		rc = 0;
	    }
	}
    }

    return EVLOOP_HRET_SUCCESS;
}

static int __monitor_eh(int errortype,int fd,int fdtype,
			struct evloop_fdinfo *fdinfo) {
    struct monitor *monitor = NULL;

    if (fdtype == EVLOOP_FDTYPE_R)
	monitor = (struct monitor *)fdinfo->rhstate;
    else if (fdtype == EVLOOP_FDTYPE_W)
	monitor = (struct monitor *)fdinfo->whstate;
    if (fdtype == EVLOOP_FDTYPE_X)
	monitor = (struct monitor *)fdinfo->xhstate;

    if (!monitor) {
	verror("no monitor state to handle evloop error -- double fault!\n");
	return EVLOOP_HRET_BADERROR;
    }

    /*
     * If it happened on one of our descriptors, warn that way -- that
     * would be our BUG!
     *
     * If it happened on an "unknown" one, it happened on one of our
     * objects; so the objtype handler needs to be fixed!
     */
    if (fd == monitor->monitor_send_fd
	|| fd == monitor->monitor_recv_fd
	|| fd == monitor->child_recv_fd
	|| fd == monitor->child_send_fd) {
	verror("BUG: error on monitor pipe fd %d: %d\n",fd,errortype);
    }
    else if (fd == monitor->p.pid_waitpipe_fd) {
	verror("BUG: error on monitor child pid waitpipe fd %d: %d\n",
	       fd,errortype);
    }
    else if (fd == monitor->p.stdin_m_fd || fd == monitor->p.stdin_c_fd
	     || fd == monitor->p.stdout_m_fd || fd == monitor->p.stdout_c_fd
	     || fd == monitor->p.stderr_m_fd || fd == monitor->p.stderr_c_fd) {
	verror("BUG: error on monitor stdio fd %d: %d\n",fd,errortype);
    }
    else {
	verror("BUG: evloop error on a non-monitor descriptor %d: %d\n",
	       fd,errortype);
    }

    return EVLOOP_HRET_BADERROR;
}

int __monitor_add_primary_obj(struct monitor *monitor,
			      int objid,int objtype,void *obj,void *objstate);

struct monitor *monitor_create_custom(monitor_type_t type,monitor_flags_t flags,
				      int objid,int objtype,void *obj,void *objstate,
				      evloop_handler_t custom_recv_evh,
				      evloop_handler_t custom_child_recv_evh) {
    struct monitor *monitor;
    struct monitor_objtype_ops *ops;
    int req_pipe[2] = { -1,-1 };
    int rep_pipe[2] = { -1,-1 };

    if (type != MONITOR_TYPE_THREAD && type != MONITOR_TYPE_PROCESS) {
	verror("unknown monitor type %d\n",type);
	errno = EINVAL;
	return NULL;
    }
    else if (type == MONITOR_TYPE_PROCESS) {
	/*
	 * Need to ensure init waitpipe().  We don't need an extra sighandler.
	 */
	if (!waitpipe_is_initialized()) 
	    waitpipe_init_auto(NULL);
    }

    if (!(ops = monitor_lookup_objtype_ops(objtype))) {
	verror("unknown objtype %d!\n",objtype);
	errno = EINVAL;
	return NULL;
    }

    monitor = calloc(1,sizeof(*monitor));

    monitor->type = type;
    monitor->flags = flags;
    monitor->mtid = pthread_self();

    pthread_mutex_init(&monitor->mutex,NULL);

    monitor->msg_obj_tab = g_hash_table_new(g_direct_hash,g_direct_equal);
    pthread_mutex_init(&monitor->msg_obj_tab_mutex,NULL);

    monitor->evloop = evloop_create(__monitor_eh);

    if (pipe(req_pipe)) {
	verror("pipe: %s\n",strerror(errno));
	goto errout;
    }
    monitor->monitor_send_fd = req_pipe[1];
    fcntl(monitor->monitor_send_fd,F_SETFD,FD_CLOEXEC);
    monitor->child_recv_fd = req_pipe[0];

    monitor->p.pid = -1;

    if (flags & MONITOR_FLAG_BIDI) {
	if (pipe(rep_pipe)) {
	    verror("pipe: %s\n",strerror(errno));
	    goto errout;
	}
	monitor->child_send_fd = rep_pipe[1];
	monitor->monitor_recv_fd = rep_pipe[0];
	fcntl(monitor->monitor_recv_fd,F_SETFD,FD_CLOEXEC);
    }
    else {
	monitor->child_send_fd = -1;
	monitor->monitor_recv_fd = -1;
    }
	
    /*
     * Set up @monitor->evloop with our default handler if this is a
     * thread-based monitor, because the client and monitor are in the
     * same thread :).  For processes, we do nothing, because the
     * process does not have the child end of the pipes; the child
     * process has those.
     */
    if (type == MONITOR_TYPE_THREAD && monitor->child_recv_fd > -1) {
	if (custom_child_recv_evh)
	    evloop_set_fd(monitor->evloop,
			  monitor->child_recv_fd,EVLOOP_FDTYPE_R,
			  custom_child_recv_evh,monitor);
	else
	    evloop_set_fd(monitor->evloop,
			  monitor->child_recv_fd,EVLOOP_FDTYPE_R,
			  __monitor_child_recv_evh,monitor);

    }
	
    /*
     * Set up @monitor->evloop with our default handler if this is a
     * bidirectional monitor.
     */
    if (monitor->monitor_recv_fd > -1) {
	if (custom_recv_evh)
	    evloop_set_fd(monitor->evloop,
			  monitor->monitor_recv_fd,EVLOOP_FDTYPE_R,
			  custom_recv_evh,monitor);
	else 
	    evloop_set_fd(monitor->evloop,
			  monitor->monitor_recv_fd,EVLOOP_FDTYPE_R,
			  __monitor_recv_evh,monitor);
    }

    vdebug(4,LA_LIB,LF_MONITOR,"msfd=%d,crfd=%d,csfd=%d,mrfd=%d\n",
	   monitor->monitor_send_fd,monitor->child_recv_fd,
	   monitor->child_send_fd,monitor->monitor_recv_fd);

    /* These are initialized by calling monitor_setup_io if necessary. */
    monitor->p.stdin_m_fd = -1;
    monitor->p.stdin_c_fd = -1;
    monitor->p.stdout_m_fd = -1;
    monitor->p.stdout_c_fd = -1;
    monitor->p.stdout_log_fd = -1;
    monitor->p.stderr_m_fd = -1;
    monitor->p.stderr_c_fd = -1;
    monitor->p.stderr_log_fd = -1;

    pthread_mutex_lock(&monitor_mutex);
    pthread_mutex_lock(&monitor->mutex);

    g_hash_table_insert(tid_monitor_tab,
			(gpointer)(uintptr_t)monitor->mtid,monitor);

    if (obj && __monitor_add_primary_obj(monitor,objid,objtype,obj,objstate)) {
	pthread_mutex_unlock(&monitor->mutex);
	pthread_mutex_unlock(&monitor_mutex);
	goto errout;
    }

    pthread_mutex_unlock(&monitor->mutex);
    pthread_mutex_unlock(&monitor_mutex);

    return monitor;

 errout:
    if (monitor->msg_obj_tab)
	g_hash_table_destroy(monitor->msg_obj_tab);
    if (monitor->evloop)
	evloop_free(monitor->evloop);
    if (req_pipe[0] > -1)
	close(req_pipe[0]);
    if (req_pipe[1] > -1)
	close(req_pipe[1]);
    if (rep_pipe[0] > -1)
	close(rep_pipe[0]);
    if (rep_pipe[1] > -1)
	close(rep_pipe[1]);
    free(monitor);

    return NULL;
}

int __monitor_add_primary_obj(struct monitor *monitor,
			    int objid,int objtype,void *obj,void *objstate) {
    /*
     * Save the primary object directly in the monitor.
     */
    monitor->objid = objid;
    monitor->obj = obj;

    if (__monitor_add_obj(monitor,monitor->objid,objtype,obj,objstate)) {
	monitor->objid = -1;
	monitor->obj = NULL;
	return -1;
    }

    return 0;
}

int monitor_add_primary_obj(struct monitor *monitor,
			    int objid,int objtype,void *obj,void *objstate) {
    int retval;

    /*
     * Grab our locks.
     */
    pthread_mutex_lock(&monitor_mutex);
    pthread_mutex_lock(&monitor->mutex);

    retval = __monitor_add_primary_obj(monitor,objid,objtype,obj,objstate);

    pthread_mutex_unlock(&monitor->mutex);
    pthread_mutex_unlock(&monitor_mutex);

    return retval;
}

struct monitor *monitor_create(monitor_type_t type,monitor_flags_t flags,
			       int objid,int objtype,void *obj,void *objstate) {
    struct monitor *monitor;

    monitor = monitor_create_custom(type,flags,objid,objtype,obj,objstate,NULL,NULL);

    return monitor;
}

int monitor_can_attach(void) {
    if (getenv(MONITOR_CHILD_RECV_FD_ENVVAR))
	return 1;
    return 0;
}

int monitor_can_attach_bidi(void) {
    if (getenv(MONITOR_CHILD_RECV_FD_ENVVAR)
	&& getenv(MONITOR_CHILD_SEND_FD_ENVVAR))
	return 1;
    return 0;
}

struct monitor *monitor_attach(monitor_type_t type,monitor_flags_t flags,
			       int objtype,void *obj,void *objstate,
			       evloop_handler_t custom_child_recv_evh,
			       monitor_stdio_callback_t stdin_callback,
			       void *callback_state) {
    struct monitor *monitor;

    if (type != MONITOR_TYPE_PROCESS) {
	verror("can only attach to process-based monitors! (%d)\n",type);
	errno = EINVAL;
	return NULL;
    }

    /*
     * We could check the env vars, and fail if we can't get them, but
     * we don't in this case.  We want to allow "headless" monitor
     * childs through.
     */

    monitor = calloc(1,sizeof(*monitor));

    monitor->type = type;
    monitor->flags = flags;
    monitor->mtid = pthread_self();

    monitor->obj = obj;

    pthread_mutex_init(&monitor->mutex,NULL);

    monitor->msg_obj_tab = g_hash_table_new(g_direct_hash,g_direct_equal);
    pthread_mutex_init(&monitor->msg_obj_tab_mutex,NULL);

    if (getenv(MONITOR_OBJID_ENVVAR)) {
	vdebug(5,LA_LIB,LF_MONITOR,"child objid is %s\n",
	       getenv(MONITOR_OBJID_ENVVAR));
	monitor->objid = atoi(getenv(MONITOR_OBJID_ENVVAR));
	/* Don't want any children to inherit this... */
	fcntl(monitor->child_recv_fd,F_SETFD,FD_CLOEXEC);
    }
    else {
	verror("no objid set by parent!\n");
	free(monitor);
	errno = EINVAL;
	return NULL;
    }

    if (getenv(MONITOR_CHILD_RECV_FD_ENVVAR)) {
	vdebug(5,LA_LIB,LF_MONITOR,"child recv fd is %s\n",
	       getenv(MONITOR_CHILD_RECV_FD_ENVVAR));
	monitor->child_recv_fd = atoi(getenv(MONITOR_CHILD_RECV_FD_ENVVAR));
	/* Don't want any children to inherit this... */
	fcntl(monitor->child_recv_fd,F_SETFD,FD_CLOEXEC);
    }
    else
	monitor->child_recv_fd = -1;

    if (getenv(MONITOR_CHILD_SEND_FD_ENVVAR)) {
	vdebug(5,LA_LIB,LF_MONITOR,"child send fd is %s\n",
	       getenv(MONITOR_CHILD_SEND_FD_ENVVAR));
	monitor->child_send_fd = atoi(getenv(MONITOR_CHILD_SEND_FD_ENVVAR));
	/* Don't want any children to inherit this... */
	if (monitor->child_send_fd > -1) {
	    fcntl(monitor->child_send_fd,F_SETFD,FD_CLOEXEC);

	    if (!(flags & MONITOR_FLAG_BIDI)) {
		close(monitor->child_send_fd);
		monitor->child_send_fd = -1;
	    }
	}
	else if (flags & MONITOR_FLAG_BIDI) {
	    vwarn("could not enable bidirectional communication; bad envvar fd!\n");
	    monitor->flags &= ~MONITOR_FLAG_BIDI;
	}
    }
    else {
	if (flags & MONITOR_FLAG_BIDI) {
	    vwarn("could not enable bidirectional communication; no envvar fd!\n");
	    monitor->flags &= ~MONITOR_FLAG_BIDI;
	}
	monitor->child_send_fd = -1;
    }

    monitor->evloop = evloop_create(__monitor_eh);

    /* Only process-based monitor children can call this, so we do not
     * listen on anything else.
     */
    if (monitor->child_recv_fd > -1) {
	if (custom_child_recv_evh)
	    evloop_set_fd(monitor->evloop,
			  monitor->child_recv_fd,EVLOOP_FDTYPE_R,
			  custom_child_recv_evh,monitor);
	else
	    evloop_set_fd(monitor->evloop,
			  monitor->child_recv_fd,EVLOOP_FDTYPE_R,
			  __monitor_child_recv_evh,monitor);
    }

    monitor->p.stdin_m_fd = -1;
    monitor->p.stdin_c_fd = -1;
    monitor->p.stdout_m_fd = -1;
    monitor->p.stdout_c_fd = -1;
    monitor->p.stdout_log_fd = -1;
    monitor->p.stderr_m_fd = -1;
    monitor->p.stderr_c_fd = -1;
    monitor->p.stderr_log_fd = -1;

    /* XXX: really should try to check if stdin will have input */
    evloop_set_fd(monitor->evloop,STDIN_FILENO,EVLOOP_FDTYPE_R,
		  __monitor_stdin_evh,monitor);
    monitor->stdin_callback = stdin_callback;

    /*
     * Now grab our locks.
     */
    pthread_mutex_lock(&monitor_mutex);
    pthread_mutex_lock(&monitor->mutex);

    /*
     * Add the primary object.
     */
    if (obj && __monitor_add_obj(monitor,monitor->objid,objtype,obj,objstate)) {
	pthread_mutex_unlock(&monitor->mutex);
	pthread_mutex_unlock(&monitor_mutex);
	goto errout;
    }

    pthread_mutex_unlock(&monitor->mutex);
    pthread_mutex_unlock(&monitor_mutex);

    return monitor;

 errout:
    if (monitor->msg_obj_tab)
	g_hash_table_destroy(monitor->msg_obj_tab);
    if (monitor->evloop)
	evloop_free(monitor->evloop);
    /*
     * Don't close the pipes; there cannot have been an error involving
     * them.  Let the user retry if they want.
     */
    free(monitor);

    return monitor;
}

int __monitor_send_stdin_evh(int fd,int fdtype,void *state) {
    struct monitor *monitor = (struct monitor *)state;
    int retval;

    if (monitor->p.stdin_left <= 0) {
	vwarn("called again even with no input remaining!\n");
	return EVLOOP_HRET_REMOVEALLTYPES;
    }

 again:
    retval = write(monitor->p.stdin_m_fd,
		   monitor->p.stdin_buf + \
		       (monitor->p.stdin_bufsiz - monitor->p.stdin_left),
		   monitor->p.stdin_left);
    if (retval < 0) {
	if (errno == EAGAIN || errno == EWOULDBLOCK) 
	    return EVLOOP_HRET_SUCCESS;
	else if (errno == EINTR) 
	    goto again;
	else if (errno == EPIPE) {
	    vwarn("child closed read stdin unexpectedly?\n");
	    /* XXX: do something more informative? */
	    return EVLOOP_HRET_BADERROR;
	}
	else {
	    verror("error(wrote %d of %d bytes stdin): write: %s\n",
		   monitor->p.stdin_bufsiz - monitor->p.stdin_left,
		   monitor->p.stdin_bufsiz,strerror(errno));
	    return EVLOOP_HRET_REMOVEALLTYPES;
	}
    }
    else {
	monitor->p.stdin_left -= retval;
	vdebug(8,LA_LIB,LF_MONITOR,"wrote %d of %d bytes stdin\n",
	       monitor->p.stdin_bufsiz - monitor->p.stdin_left,
	       monitor->p.stdin_bufsiz);

	if (monitor->p.stdin_left <= 0) {
	    vdebug(8,LA_LIB,LF_MONITOR,"finished writing %d bytes stdin\n",
		   monitor->p.stdin_bufsiz);

	    monitor->p.stdin_left = monitor->p.stdin_bufsiz = -1;

	    free(monitor->p.stdin_buf);
	    monitor->p.stdin_buf = NULL;
	    close(monitor->p.stdin_m_fd);
	    monitor->p.stdin_m_fd = -1;

	    return EVLOOP_HRET_REMOVEALLTYPES;
	}
    }

    return EVLOOP_HRET_SUCCESS;
}

int monitor_setup_stdin(struct monitor *monitor,
			char *stdin_buf,int stdin_buflen) {
    int pipefds[2] = { -1,-1 };

    if (monitor->type != MONITOR_TYPE_PROCESS) {
	errno = EINVAL;
	verror("invalid monitor type %d\n",monitor->type);
	return -1;
    }

    if (pipe(pipefds)) {
	verror("pipe: %s\n",strerror(errno));
	return -1;
    }
    monitor->p.stdin_m_fd = pipefds[1];
    fcntl(monitor->p.stdin_m_fd,F_SETFD,FD_CLOEXEC);
    /*
     * Also open this one nonblocking because we don't want the monitor
     * thread to block while sending input to the child.
     */
    fcntl(pipefds[1],F_SETFL,fcntl(pipefds[1],F_GETFL) | O_NONBLOCK);
    monitor->p.stdin_c_fd = pipefds[0];

    monitor->p.stdin_buf = stdin_buf;
    monitor->p.stdin_left = stdin_buflen;
    monitor->p.stdin_bufsiz = stdin_buflen;

    return 0;
}

int monitor_setup_stdout(struct monitor *monitor,
			 int maxbufsiz,char *stdout_logfile,
			 monitor_stdio_callback_t stdout_callback,
			 void *callback_state) {
    int pipefds[2] = { -1,-1 };

    if (monitor->type != MONITOR_TYPE_PROCESS) {
	errno = EINVAL;
	verror("invalid monitor type %d\n",monitor->type);
	return -1;
    }

    if (stdout_logfile) {
	monitor->p.stdout_log_fd = \
	    open(stdout_logfile,O_RDWR | O_CREAT | O_APPEND | O_TRUNC,
		 S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	if (monitor->p.stdout_log_fd < 0) {
	    verror("could not open stdout logfile %s!\n",stdout_logfile);
	    return -1;
	}
    }

    if (pipe(pipefds)) {
	verror("pipe: %s\n",strerror(errno));
	if (monitor->p.stdout_log_fd != -1)
	    close(monitor->p.stdout_log_fd);
	return -1;
    }
    monitor->p.stdout_c_fd = pipefds[1];
    monitor->p.stdout_m_fd = pipefds[0];
    fcntl(monitor->p.stdout_m_fd,F_SETFD,FD_CLOEXEC);
    /*
     * Also open this one nonblocking because we don't want the monitor
     * thread to block while reading output from the child.
     */
    fcntl(monitor->p.stdout_m_fd,F_SETFL,
	  fcntl(monitor->p.stdout_m_fd,F_GETFL) | O_NONBLOCK);

    /*
    if (maxbufsiz > 0) 
	monitor->p.stdout_buf = cbuf_alloc(maxbufsiz,-1);
    */

    monitor->p.stdout_callback = stdout_callback;
    monitor->p.stdout_callback_state = callback_state;

    return 0;
}

int monitor_setup_stderr(struct monitor *monitor,
			 int maxbufsiz,char *stderr_logfile,
			 monitor_stdio_callback_t stderr_callback,
			 void *callback_state) {
    int pipefds[2] = { -1,-1 };

    if (monitor->type != MONITOR_TYPE_PROCESS) {
	errno = EINVAL;
	verror("invalid monitor type %d\n",monitor->type);
	return -1;
    }

    if (stderr_logfile) {
	monitor->p.stderr_log_fd = \
	    open(stderr_logfile,O_RDWR | O_CREAT | O_APPEND | O_TRUNC,
		 S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	if (monitor->p.stderr_log_fd < 0) {
	    verror("could not open stderr logfile %s!\n",stderr_logfile);
	    return -1;
	}
    }

    if (pipe(pipefds)) {
	verror("pipe: %s\n",strerror(errno));
	if (monitor->p.stderr_log_fd != -1)
	    close(monitor->p.stderr_log_fd);
	return -1;
    }
    monitor->p.stderr_c_fd = pipefds[1];
    monitor->p.stderr_m_fd = pipefds[0];
    fcntl(monitor->p.stderr_m_fd,F_SETFD,FD_CLOEXEC);
    /*
     * Also open this one nonblocking because we don't want the monitor
     * thread to block while reading output from the child.
     */
    fcntl(monitor->p.stderr_m_fd,F_SETFL,
	  fcntl(monitor->p.stderr_m_fd,F_GETFL) | O_NONBLOCK);

    /*
    if (maxbufsiz > 0) 
	monitor->p.stderr_buf = cbuf_alloc(maxbufsiz,-1);
    */

    monitor->p.stderr_callback = stderr_callback;
    monitor->p.stderr_callback_state = callback_state;

    return 0;
}

static int __monitor_pid_evh(int fd,int fdtype,void *state) {
    struct monitor *monitor = (struct monitor *)state;
    int pid = monitor->p.pid;
    int status;

    /* The waitpipe tells us that the pid died; wait for it and save its
     * status.
     */

    vdebug(9,LA_LIB,LF_MONITOR,"pid %d finished\n",pid);
    waitpid(pid,&status,0);
    vdebug(9,LA_LIB,LF_MONITOR,"pid %d finished status %d\n",pid,WEXITSTATUS(status));

    /* nuke the pipe */
    waitpipe_remove(pid);

    /* save status */
    monitor->p.status = status;

    /* declare that the half is dead */
    monitor->halfdead = 1;

    monitor->p.pid_waitpipe_fd = -1;

    /* remove ALL the fds from the event loop */
    return EVLOOP_HRET_DONE_SUCCESS;
}

extern char **environ;

int monitor_spawn(struct monitor *monitor,char *filename,
		  char *const argv[],char *const envp[],char *dir) {
    int pid;
    char envvarbuf[64];
    int envlen;
    char **envp_actual;
    char cwd[PATH_MAX];
    int i;

    if (monitor->type != MONITOR_TYPE_PROCESS) {
	verror("cannot handle a non-MONITOR_TYPE_PROCESS!\n");
	errno = EINVAL;
	return -1;
    }

    if (dir) {
	if (!getcwd(cwd,PATH_MAX)) {
	    verror("getcwd: %s\n",strerror(errno));
	    return -1;
	}
	if (chdir(dir)) {
	    verror("chdir(%s): %s!\n",dir,strerror(errno));
	    return -1;
	}
    }

    pid = fork();

    if (pid < 0) {
	verror("fork: %s\n",strerror(errno));
	return pid;
    }
    else if (!pid) {
	/* Setup env vars.  Extend our current env if they don't pass one. */
	envlen = 0;
	i = 0;
	if (!envp)
	    envp = environ;
	if (envp) {
	    while (envp[i++]) 
		++envlen;
	}

	envp_actual = calloc(envlen + 4,sizeof(char *));

	i = 0;
	if (envp) {
	    while (i < envlen) {
		envp_actual[i] = envp[i];
		++i;
	    }
	}

	/* Tell the child it is monitored, and tell it its FDs. */
	if (monitor->child_recv_fd > -1) {
	    snprintf(envvarbuf,sizeof(envvarbuf),"%s=%d",
		     MONITOR_CHILD_RECV_FD_ENVVAR,monitor->child_recv_fd);
	    envp_actual[i] = strdup(envvarbuf);
	    ++i;
	    envp_actual[i] = NULL;
	}
	if (monitor->child_send_fd > -1) {
	    snprintf(envvarbuf,sizeof(envvarbuf),"%s=%d",
		     MONITOR_CHILD_SEND_FD_ENVVAR,monitor->child_send_fd);
	    envp_actual[i] = strdup(envvarbuf);
	    ++i;
	    envp_actual[i] = NULL;
	}
	/* Also tell it its primary monitored object id */
	snprintf(envvarbuf,sizeof(envvarbuf),"%s=%d",
		 MONITOR_OBJID_ENVVAR,monitor->objid);
	envp_actual[i] = strdup(envvarbuf);
	++i;
	envp_actual[i] = NULL;

	/*
	 * Setup stdio streams.
	 */
	if (monitor->p.stdin_c_fd > -1) {
	    if (dup2(monitor->p.stdin_c_fd,STDIN_FILENO)) {
		verror("dup2(%d,stdin): %s; closing stdin!\n",
		       monitor->p.stdin_c_fd,strerror(errno));
		close(STDIN_FILENO);
	    }
	}
	else {
	    close(STDIN_FILENO);
	}

	if (monitor->p.stdout_c_fd > -1) {
	    if (dup2(monitor->p.stdout_c_fd,STDOUT_FILENO) < 0) {
		verror("dup2(%d,stdout): %s; ignoring!\n",
		       monitor->p.stdout_c_fd,strerror(errno));
	    }
	}

	if (monitor->p.stderr_c_fd > -1) {
	    if (dup2(monitor->p.stderr_c_fd,STDERR_FILENO) < 0) {
		verror("dup2(%d,stderr): %s; ignoring!\n",
		       monitor->p.stderr_c_fd,strerror(errno));
	    }
	}

	/*
	 * XXX: cleanup any monitor-only state!
	 */

	vdebug(3,LA_LIB,LF_MONITOR,"execve(%s) in %s\n",filename,dir);

	if (execve(filename,argv,envp_actual)) {
	    verror("execve(%s): %s!\n",filename,strerror(errno));
	    return -1;
	}
    }
    else {
	monitor->p.pid = pid;

	/* Change dir back if we need. */
	if (dir && chdir(cwd)) {
	    verror("chdir(%s): %s!\n",cwd,strerror(errno));
	    // XXX: do not exit; this should not happen; trust it won't.
	}

	/*
	 * Add our default handlers for stderr/stdout if necessary.
	 */
	if (monitor->p.stdout_m_fd > -1) 
	    evloop_set_fd(monitor->evloop,monitor->p.stdout_m_fd,
			  EVLOOP_FDTYPE_R,__monitor_stdout_evh,monitor);
	if (monitor->p.stderr_m_fd > -1) 
	    evloop_set_fd(monitor->evloop,monitor->p.stderr_m_fd,
			  EVLOOP_FDTYPE_R,__monitor_stdout_evh,monitor);
	/* Make sure to send our stdin to the child. */
	if (monitor->p.stdin_m_fd > -1) 
	    evloop_set_fd(monitor->evloop,monitor->p.stdin_m_fd,EVLOOP_FDTYPE_W,
			  __monitor_send_stdin_evh,monitor);

	/*
	 * Add a waitpipe handler for the child.
	 */
	monitor->p.pid_waitpipe_fd = waitpipe_add(pid);
	if (monitor->p.pid_waitpipe_fd < 0) {
	    if (errno == EINVAL) {
		verror("could not wait on pid %d: %s; continuing anyway!\n",
		       pid,strerror(errno));
	    }
	}
	else {
	    evloop_set_fd(monitor->evloop,monitor->p.pid_waitpipe_fd,
			  EVLOOP_FDTYPE_R,__monitor_pid_evh,monitor);
	}

	/*
	 * Close child ends of pipes.
	 */
	if (monitor->child_recv_fd > -1) {
	    close(monitor->child_recv_fd);
	    monitor->child_recv_fd = -1;
	}
	if (monitor->child_send_fd > -1) {
	    close(monitor->child_send_fd);
	    monitor->child_send_fd = -1;
	}
	if (monitor->p.stdin_c_fd > -1) {
	    close(monitor->p.stdin_c_fd);
	    monitor->p.stdin_c_fd = -1;
	}
	if (monitor->p.stdout_c_fd > -1) {
	    close(monitor->p.stdout_c_fd);
	    monitor->p.stdout_c_fd = -1;
	}
	if (monitor->p.stderr_c_fd > -1) {
	    close(monitor->p.stderr_c_fd);
	    monitor->p.stderr_c_fd = -1;
	}
    }

    return pid;
}

static int __monitor_error_evh(int errortype,int fd,int fdtype,
			       struct evloop_fdinfo *error_fdinfo) {
    /*
     * Basically, we have to check all our FDs, see which one the error
     * happened for, then decide what to do!
     */
    vdebug(5,LA_LIB,LF_MONITOR,"errortype %d fd %d fdtype %d\n",
	   errortype,fd,fdtype);

    return EVLOOP_HRET_SUCCESS;
}

void monitor_interrupt(struct monitor *monitor) {
    pthread_mutex_lock(&monitor->mutex);
    if (monitor->running && !monitor->interrupt) 
	monitor->interrupt = 1;
    pthread_mutex_unlock(&monitor->mutex);
}

void monitor_interrupt_done(struct monitor *monitor,result_t status,int finalize) {
    pthread_mutex_lock(&monitor->mutex);
    if (monitor->running && !monitor->interrupt) 
	monitor->interrupt = 1;
    monitor->done = 1;
    monitor->done_status = status;
    monitor->finalize = finalize;
    pthread_mutex_unlock(&monitor->mutex);
}

int monitor_is_done(struct monitor *monitor) {
    int retval;

    pthread_mutex_lock(&monitor->mutex);
    retval = monitor->done;
    pthread_mutex_unlock(&monitor->mutex);

    return retval;
}

int monitor_should_self_finalize(struct monitor *monitor) {
    int retval;

    pthread_mutex_lock(&monitor->mutex);
    retval = monitor->finalize;
    pthread_mutex_unlock(&monitor->mutex);

    return retval;
}

void monitor_halfdead(struct monitor *monitor) {
    pthread_mutex_lock(&monitor->mutex);
    monitor->halfdead = 1;
    pthread_mutex_unlock(&monitor->mutex);
}

int monitor_is_halfdead(struct monitor *monitor) {
    int retval;

    pthread_mutex_lock(&monitor->mutex);
    retval = monitor->halfdead;
    pthread_mutex_unlock(&monitor->mutex);

    return retval;
}

/*
 * Runs the monitor (basically just runs its internal evloop).
 */
int monitor_run(struct monitor *monitor) {
    int rc;
    struct monitor_objtype_ops *ops;
    GHashTableIter iter;
    gpointer tobj;
    int objid;
    int objtype;
    struct monitor *_monitor;
    int found = 1;
    struct evloop_fdinfo *fdinfo = NULL;
    int hrc;
    int islive;

    /*
     * If the monitor thread is still running, only that thread can
     * run the monitor.  Otherwise, another thread can.
     */
    if (pthread_kill(monitor->mtid,0) == 0
	&& !pthread_equal(pthread_self(),monitor->mtid)) {
	verror("only monitor thread can run!\n");
	errno = EPERM;
	return -1;
    }

    pthread_mutex_lock(&monitor->mutex);
    if (monitor->done) {
	pthread_mutex_unlock(&monitor->mutex);
	return 0;
    }
    pthread_mutex_unlock(&monitor->mutex);

    while (1) {
	/*
	 * Check interrupt line.
	 */
	pthread_mutex_lock(&monitor->mutex);
	if (monitor->done) {
	    pthread_mutex_unlock(&monitor->mutex);
	    return 0;
	}
	/*
	else if (monitor->halfdead) {
	    pthread_mutex_unlock(&monitor->mutex);
	    return 0;
	}
	*/
	else if (monitor->interrupt) {
	    monitor->interrupt = 0;
	    pthread_mutex_unlock(&monitor->mutex);
	    return 0;
	}
	else {
	    monitor->running = 1;
	    pthread_mutex_unlock(&monitor->mutex);
	}

	hrc = -1;
	fdinfo = NULL;

	/*
	 * XXX: fix this!  Race condition, because we cannot call this
	 * with the main monitor mutex held.  This is going to be tricky
	 * to fix...
	 */
	rc = evloop_handleone(monitor->evloop,NULL,&fdinfo,&hrc);

	pthread_mutex_lock(&monitor_mutex);
	pthread_mutex_lock(&monitor->mutex);

	if (rc == 0) {
	    /*
	     * Each time we handle an event, we need to check the status
	     * of the monitored child, and/or the monitored objects.
	     * Only check the objects if there is no child, or its is
	     * dead.
	     */

	    islive = 0;
	    if (monitor->type == MONITOR_TYPE_PROCESS 
		&& monitor->p.pid > -1 && monitor->p.pid_waitpipe_fd > -1) {
		vdebug(12,LA_LIB,LF_MONITOR,
		       "monitor (0x%lx) child still live\n",monitor->mtid);
		islive = 1;
	    }

	    vdebug(12,LA_LIB,LF_MONITOR,
		   "checking status of monitor (0x%lx) objs\n",monitor->mtid);

	    g_hash_table_iter_init(&iter,obj_monitor_tab);
	    while (g_hash_table_iter_next(&iter,&tobj,(gpointer *)&_monitor)) {
		if (monitor != _monitor) 
		    continue;

		if (!__monitor_lookup_obj(tobj,&objtype,&objid,NULL))
		    verror("could not lookup obj %p to check its status!\n",
			   tobj);
		else {
		    ops = __monitor_lookup_objtype_ops(objtype);
		    if (ops->evloop_is_attached)
			rc = ops->evloop_is_attached(monitor->evloop,tobj);
		    vdebug(12,LA_LIB,LF_MONITOR,
			   "objid %d attached = %d\n",objid,rc);
		    islive |= rc;
		}
	    }

	    if (!islive) {
		monitor->halfdead = 1;
	    }

	    if (evloop_maxsize(monitor->evloop) < 0) {
		pthread_mutex_unlock(&monitor_mutex);
		pthread_mutex_unlock(&monitor->mutex);
		return 0;
	    }
	    else { //if (!fdinfo)
		pthread_mutex_unlock(&monitor_mutex);
		pthread_mutex_unlock(&monitor->mutex);
		continue;
	    }
	}

	/*
	 * XXX: Fatal error -- handle I/O errors of our own, and
	 * call the fatal handler for the objtype; then free
	 * ourself.
	 */
	verror("fatal uncaught error from evloop_handleone, cleaning up!\n");

	while (found) {
	    found = 0;
	    g_hash_table_iter_init(&iter,obj_monitor_tab);
	    while (g_hash_table_iter_next(&iter,&tobj,(gpointer *)&_monitor)) {
		if (monitor == _monitor) {
		    found = 1;

		    if (!__monitor_lookup_obj(tobj,&objtype,&objid,NULL)) {
			verror("could not lookup obj %p to deliver fatal error!\n",
			       tobj);
		    }
		    else {
			ops = __monitor_lookup_objtype_ops(objtype);
			if (ops->fatal_error)
			    ops->fatal_error(MONITOR_ERROR_UNKNOWN,tobj);
		    }

		    /* Let the target decide if it should self-terminate! */
		    __monitor_del_obj(monitor,objid,objtype,tobj,obj_monitor_tab);

		    g_hash_table_iter_remove(&iter);

		    break;
		}
	    }
	}

	pthread_mutex_unlock(&monitor_mutex);
	pthread_mutex_unlock(&monitor->mutex);

	return -1;
    }

    /* Never reached. */
    return -1;
}

static void __monitor_store_msg_obj(struct monitor *monitor,
				    struct monitor_msg *msg) {
    if (!msg->msg_obj)
	return;

    g_hash_table_insert(monitor->msg_obj_tab,
			(gpointer)(uintptr_t)msg->id,msg->msg_obj);
}

void monitor_store_msg_obj(struct monitor *monitor,
			   struct monitor_msg *msg) {
    if (!msg->msg_obj)
	return;

    pthread_mutex_lock(&monitor->msg_obj_tab_mutex);
    monitor_store_msg_obj(monitor,msg);
    pthread_mutex_unlock(&monitor->msg_obj_tab_mutex);
}

static void *monitor_peek_msg_obj(struct monitor *monitor,
				  struct monitor_msg *msg) {
    void *retval;

    pthread_mutex_lock(&monitor->msg_obj_tab_mutex);
    retval = (void *)g_hash_table_lookup(monitor->msg_obj_tab,
					 (gpointer)(uintptr_t)msg->id);
    pthread_mutex_unlock(&monitor->msg_obj_tab_mutex);

    return retval;
}

static void monitor_retrieve_msg_obj(struct monitor *monitor,
				     struct monitor_msg *msg) {
    pthread_mutex_lock(&monitor->msg_obj_tab_mutex);
    msg->msg_obj = g_hash_table_lookup(monitor->msg_obj_tab,
				       (gpointer)(uintptr_t)msg->id);
    g_hash_table_remove(monitor->msg_obj_tab,(gpointer)(uintptr_t)msg->id);
    pthread_mutex_unlock(&monitor->msg_obj_tab_mutex);
}

void monitor_msg_free(struct monitor_msg *msg) {
    if (msg->msg)
	free(msg->msg);
    free(msg);
}

void monitor_msg_free_save_buffer(struct monitor_msg *msg) {
    free(msg);
}

struct monitor_msg *monitor_msg_create(int objid,
				       int id,short cmd,short seqno,
				       int buflen,char *buf,
				       void *msg_obj) {
    struct monitor *monitor = NULL;
    struct monitor_msg *msg;
    void *obj = NULL;

    if (id == -1) {	
	if (objid > 0 
	    && !monitor_lookup_objid_lock_monitor(objid,NULL,&obj,&monitor)) {
	    verror("could not find monitor for objid %d to get msg_obj_id!\n",
		   objid);
	    return NULL;
	}
	else {
	    id = ++monitor->msg_obj_id_counter;
	    pthread_mutex_unlock(&monitor->mutex);
	}
    }

    msg = calloc(1,sizeof(*msg));

    msg->objid = objid;

    msg->cmd = cmd;
    msg->seqno = seqno;
    msg->len = buflen;
    msg->msg = buf; //malloc(buflen);
    //memcpy(msg->msg,buf,buflen);

    /*
     * These do not get emplaced into the state table until send.
     */
    msg->id = id;
    msg->msg_obj = msg_obj;

    if (!obj && objid > 0) {
	if (!monitor_lookup_objid(objid,NULL,&obj,&monitor)) {
	    vwarn("could not find obj for objid %d!\n",objid);
	}
	else
	    msg->obj = obj;
    }

    return msg;
}

#define __M_SAFE_IO(fn,fns,fd,buf,buflen) {				\
    char *_p;								\
    int _rc = 0;							\
    int _left;								\
									\
    _p = (char *)(buf);							\
    _left = (buflen);							\
									\
    while (_left) {							\
        _rc = fn((fd),_p,_left);					\
	if (_rc < 0) {							\
	    if (errno == EAGAIN || errno == EWOULDBLOCK) {		\
		goto errout_wouldblock;					\
	    }								\
	    else if (errno != EINTR) {					\
	        vwarn(fns "(%d,%d): %s\n",				\
		       fd,buflen,strerror(errno));			\
		goto errout_fatal;					\
	    }								\
	    else {							\
	        verror(fns "(%d,%d): %s\n",				\
		       fd,buflen,strerror(errno));			\
	    }								\
	}								\
	else if (_rc == 0) {						\
	    goto errout_wouldblock;					\
	}								\
	else {								\
	    _left -= _rc;						\
	    _p += _rc;							\
	}								\
    }									\
    /*vwarn("%d bytes of %d iopd\n",(buflen)-_left,(buflen));*/		\
}

int monitor_send(struct monitor_msg *msg) {
    struct monitor *monitor;
    unsigned int rc = 0;
    unsigned int len;

    /*
     * We have to lookup the monitor and hold its lock to make sure
     * the monitor thread does not monitor_free() it out from under us!
     */
    if (!monitor_lookup_objid_lock_monitor(msg->objid,NULL,NULL,&monitor)) {
	errno = ESRCH;
	return -1;
    }

    /*
     * Insert the object and release the lock first so receiver does not
     * block on it if it reads the msg before the sender releases the
     * lock.
     */
    if (msg->msg_obj) 
	__monitor_store_msg_obj(monitor,msg);

    len = sizeof(msg->objid) + sizeof(msg->id) \
	+ sizeof(msg->cmd) + sizeof(msg->seqno) + sizeof(msg->len);
    if (msg->len > 0)
	len += msg->len;

    /*
     * Now send the message.
     */
    if (monitor->monitor_send_fd < 1) {
	if (monitor->type == MONITOR_TYPE_THREAD) {
	    verror("no way to send to thread %lu!\n",monitor->mtid);
	}
	else if (monitor->type == MONITOR_TYPE_PROCESS) {
	    verror("no way to send to process %d!\n",monitor->p.pid);
	}
	errno = EINVAL;
	goto errout;
    }

    /* Write the msg objid */
    __M_SAFE_IO(write,"write",monitor->monitor_send_fd,
		&msg->objid,(int)sizeof(msg->objid));
    rc += (int)sizeof(msg->objid);

    /* Write the msg id */
    __M_SAFE_IO(write,"write",monitor->monitor_send_fd,
		&msg->id,(int)sizeof(msg->id));
    rc += (int)sizeof(msg->id);

    /* Write the msg cmd */
    __M_SAFE_IO(write,"write",monitor->monitor_send_fd,
		&msg->cmd,(int)sizeof(msg->cmd));
    rc += (int)sizeof(msg->cmd);

    /* Write the msg seqno */
    __M_SAFE_IO(write,"write",monitor->monitor_send_fd,
		&msg->seqno,(int)sizeof(msg->seqno));
    rc += (int)sizeof(msg->seqno);

    /* Write the msg payload len */
    __M_SAFE_IO(write,"write",monitor->monitor_send_fd,
		&msg->len,(int)sizeof(msg->len));
    rc += (int)sizeof(msg->len);

    if (msg->len > 0) {
	/* Write the msg payload, if any */
	__M_SAFE_IO(write,"write",monitor->monitor_send_fd,msg->msg,msg->len);
	rc += msg->len;
    }

    vdebug(9,LA_LIB,LF_MONITOR,
	   "sent objid(%d) %d %hd:%hd '%s' (%d)\n",
	   msg->objid,msg->id,msg->cmd,msg->seqno,msg->msg,msg->len);

    pthread_mutex_unlock(&monitor->mutex);
    return 0;

 errout_wouldblock:
    if (rc < len && (errno == EAGAIN || errno == EWOULDBLOCK)) {
	verror("would have blocked after %d of %d bytes!\n",rc,len);
	goto errout;
    }

 errout_fatal:
    /*
     * Error while writing to pipe; may be in bad state; must nuke the
     * pipe.  We can leave the monitor open, but all communication ends
     * here.
     *
     * Actually, we can't nuke the pipe, because the caller may not be
     * the thread monitoring the monitor's evloop -- so we cannot alter
     * the evloop.
     *
     * The only thing we *can* do is close() the pipe FD; do that for
     * now and let the evloop handle that normally (it should see an
     * error condition too, if it's a real problem?).
     */
    if (errno == EPIPE) {
	close(monitor->monitor_send_fd);
	monitor->monitor_send_fd = -1;
    }

 errout:
    pthread_mutex_unlock(&monitor->mutex);
    if (msg->msg_obj) 
	monitor_retrieve_msg_obj(monitor,msg);
    return -1;
}

struct monitor_msg *monitor_recv(struct monitor *monitor) {
    struct monitor_msg *msg = monitor_msg_create(-1,0,0,0,0,NULL,NULL);
    int rc = 0;
    int len;
    void *obj;
    struct monitor *_monitor = NULL;

    len = sizeof(msg->objid) + sizeof(msg->id) \
	+ sizeof(msg->cmd) + sizeof(msg->seqno) + sizeof(msg->len);

    /* Read the msg objid */
    __M_SAFE_IO(read,"read",monitor->monitor_recv_fd,
		&msg->objid,(int)sizeof(msg->objid));
    rc += (int)sizeof(msg->objid);

    /* Read the msg id */
    __M_SAFE_IO(read,"read",monitor->monitor_recv_fd,
		&msg->id,(int)sizeof(msg->id));
    rc += (int)sizeof(msg->id);

    /* Read the msg cmd */
    __M_SAFE_IO(read,"read",monitor->monitor_recv_fd,&msg->cmd,
		(int)sizeof(msg->cmd));
    rc += (int)sizeof(msg->cmd);

    /* Read the msg seqno */
    __M_SAFE_IO(read,"read",monitor->monitor_recv_fd,&msg->seqno,
		(int)sizeof(msg->seqno));
    rc += (int)sizeof(msg->seqno);

    /* Read the msg payload len */
    __M_SAFE_IO(read,"read",monitor->monitor_recv_fd,
		&msg->len,(int)sizeof(msg->len));
    rc += (int)sizeof(msg->len);

    if (msg->len > 0)
	len += msg->len;

    /* Read the msg payload */
    if (msg->len > 0) {
	msg->msg = malloc(msg->len);
	__M_SAFE_IO(read,"read",monitor->monitor_recv_fd,
		    msg->msg,msg->len);
	rc += msg->len;
    }

    vdebug(9,LA_LIB,LF_MONITOR,
	   " objid(%d) %d %hd:%hd '%s' (%d)\n",
	   msg->objid,msg->id,msg->cmd,msg->seqno,msg->msg,msg->len);

    /* Don't lock here; the sender holds the lock! */
    if (!__monitor_lookup_objid(msg->objid,NULL,&obj,&_monitor)) {
	vwarn("could not find obj for objid %d!\n",msg->objid);
	msg->obj = NULL;
    }
    else
	msg->obj = obj;

    monitor_retrieve_msg_obj(monitor,msg);

    return msg;

 errout_wouldblock:
    if (rc < len && (errno == EAGAIN || errno == EWOULDBLOCK)) {
	verror("would have blocked after %d of (at least) %d bytes !\n",rc,len);
	goto errout_fatal;
    }

 errout_fatal:
    monitor_msg_free(msg);

    return NULL;
}

int monitor_child_send(struct monitor_msg *msg) {
    struct monitor *monitor;
    int rc = 0;
    int len;

    /*
     * We have to lookup the monitor and hold its lock to make sure
     * the monitor thread does not monitor_free() it out from under us!
     */
    
    if (!monitor_lookup_objid_lock_monitor(msg->objid,NULL,NULL,&monitor)) {
	errno = ESRCH;
	return -1;
    }

    len = sizeof(msg->objid) + sizeof(msg->id) \
	+ sizeof(msg->cmd) + sizeof(msg->seqno) + sizeof(msg->len);
    if (msg->len > 0)
	len += msg->len;

    /*
     * If this is a process-based monitor, we allow multiple threads in
     * the child!  So we have to lock to ensure our sends are
     * synchronous.
     *
     * Insert the object and release the lock first so receiver does not
     * block on it if it reads the msg before the sender releases the
     * lock.
     */
    if (msg->msg_obj && monitor->type == MONITOR_TYPE_PROCESS) 
	__monitor_store_msg_obj(monitor,msg);

    /*
     * Now send the message.  No locking FOR THREADS because only one caller.
     */
    if (monitor->child_send_fd < 1) {
	if (monitor->type == MONITOR_TYPE_THREAD) {
	    verror("no way to send from monitor thread!\n");
	}
	else if (monitor->type == MONITOR_TYPE_PROCESS) {
	    verror("no way to send from monitored process!\n");
	}
	errno = EINVAL;
	goto errout_fatal;
    }

    /* Write the msg objid */
    __M_SAFE_IO(write,"write",monitor->child_send_fd,
		&msg->objid,(int)sizeof(msg->objid));
    rc += (int)sizeof(msg->objid);

    /* Write the msg id */
    __M_SAFE_IO(write,"write",monitor->child_send_fd,
		&msg->id,(int)sizeof(msg->id));
    rc += (int)sizeof(msg->id);

    /* Write the msg cmd */
    __M_SAFE_IO(write,"write",monitor->child_send_fd,
		&msg->cmd,(int)sizeof(msg->cmd));
    rc += (int)sizeof(msg->cmd);

    /* Write the msg seqno */
    __M_SAFE_IO(write,"write",monitor->child_send_fd,
		&msg->seqno,(int)sizeof(msg->seqno));
    rc += (int)sizeof(msg->seqno);

    /* Write the msg payload len */
    __M_SAFE_IO(write,"write",monitor->child_send_fd,
		&msg->len,(int)sizeof(msg->len));
    rc += (int)sizeof(msg->len);

    if (msg->len > 0) {
	/* Write the msg payload, if any */
	__M_SAFE_IO(write,"write",monitor->child_send_fd,msg->msg,msg->len);
	rc += msg->len;
    }

    vdebug(9,LA_LIB,LF_MONITOR,
	   " objid(%d) %d %hd:%hd '%s' (%d)\n",
	   msg->objid,msg->id,msg->cmd,msg->seqno,msg->msg,msg->len);

    pthread_mutex_unlock(&monitor->mutex);
    return 0;

 errout_wouldblock:
    if (rc < len && (errno == EAGAIN || errno == EWOULDBLOCK)) {
	verror("would have blocked after %d of %d bytes (BUG)!\n",rc,len);
	goto errout_fatal;
    }

 errout_fatal:
    /*
     * Error while writing to pipe; may be in bad state; must nuke the
     * pipe.  We can leave the monitor open, but all communication ends
     * here.
     *
     * Actually, we can't nuke the pipe, because the caller may not be
     * the thread monitoring the monitor's evloop -- so we cannot alter
     * the evloop.  The only thing we *could* do is close() the pipe
     * FDs, but for now let's not, and let's let the evloop handle that
     * normally (it should see an error condition too, if it's a real
     * problem?).
     */
    verror("error after %d of %d bytes: %s!\n",rc,len,strerror(errno));
    pthread_mutex_unlock(&monitor->mutex);
    if (msg->msg_obj) 
	monitor_retrieve_msg_obj(monitor,msg);
    return -1;
}

struct monitor_msg *monitor_child_recv(struct monitor *monitor) {
    struct monitor_msg *msg = monitor_msg_create(-1,0,0,0,0,NULL,NULL);
    int rc = 0;
    int len;
    void *obj;
    struct monitor *_monitor = NULL;

    len = sizeof(msg->objid) + sizeof(msg->id) \
	+ sizeof(msg->cmd) + sizeof(msg->seqno) + sizeof(msg->len);

    /* Read the msg objid */
    __M_SAFE_IO(read,"read",monitor->child_recv_fd,
		&msg->objid,(int)sizeof(msg->objid));
    rc += (int)sizeof(msg->objid);

    /* Read the msg id */
    __M_SAFE_IO(read,"read",monitor->child_recv_fd,
		&msg->id,(int)sizeof(msg->id));
    rc += (int)sizeof(msg->id);

    /* Read the msg cmd */
    __M_SAFE_IO(read,"read",monitor->child_recv_fd,&msg->cmd,
		(int)sizeof(msg->cmd));
    rc += (int)sizeof(msg->cmd);

    /* Read the msg seqno */
    __M_SAFE_IO(read,"read",monitor->child_recv_fd,&msg->seqno,
		(int)sizeof(msg->seqno));
    rc += (int)sizeof(msg->seqno);

    /* Read the msg payload len */
    __M_SAFE_IO(read,"read",monitor->child_recv_fd,
		&msg->len,(int)sizeof(msg->len));
    rc += (int)sizeof(msg->len);

    if (msg->len > 0)
	len += msg->len;

    vdebug(9,LA_LIB,LF_MONITOR,
	   " objid(%d) %d %hd:%hd '%s' (%d)\n",
	   msg->objid,msg->id,msg->cmd,msg->seqno,msg->msg,msg->len);

    /* Read the msg payload */
    if (msg->len > 0) {
	msg->msg = malloc(msg->len);
	__M_SAFE_IO(read,"read",monitor->child_recv_fd,
		    msg->msg,(int)msg->len);
	rc += msg->len;
    }

    vdebug(9,LA_LIB,LF_MONITOR,
	   " objid(%d) %d %hd:%hd '%s' (%d)\n",
	   msg->objid,msg->id,msg->cmd,msg->seqno,msg->msg,msg->len);

    /*
     * Don't lock here; the sender holds the lock if this is a threaded
     * monitor!
     */
    if (!__monitor_lookup_objid(msg->objid,NULL,&obj,&_monitor)) {
	vwarn("could not find obj for objid %d!\n",msg->objid);
	msg->obj = NULL;
    }
    else
	msg->obj = obj;

    if (rc != len)
	vwarn("received msg len only %d (should be %d)\n",rc,len);

    monitor_retrieve_msg_obj(monitor,msg);

    return msg;

 errout_wouldblock:
    if (rc < len && (errno == EAGAIN || errno == EWOULDBLOCK)) {
	verror("would have blocked after %d of %d bytes (BUG)!\n",rc,len);
	goto errout_fatal;
    }

 errout_fatal:
    verror("error after %d of %d bytes: %s!\n",rc,len,strerror(errno));
    monitor_msg_free(msg);

    return NULL;
}
