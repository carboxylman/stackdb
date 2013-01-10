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

#include "target_rpc.h"
#include "debuginfo_rpc.h"
#include "target_xml.h"
#include "util.h"
#include "alist.h"
#include "target.h"
#include "target_api.h"

#include "evloop.h"
#include "monitor.h"
#include "proxyreq.h"

#include <pthread.h>
#include <glib.h>
#include <errno.h>

static pthread_mutex_t target_rpc_mutex = PTHREAD_MUTEX_INITIALIZER;
static int init_done = 0;
/* These are the targets we know about. */
static GHashTable *target_tab = NULL;
static GHashTable *session_tab = NULL;

/**
 ** A bunch of stuff for per-target monitor interactions.
 **/
int monitor_objtype_target = -1;

static int target_rpc_monitor_evloop_attach(struct evloop *evloop,void *obj) {
    struct target *target = (struct target *)obj;
    return target_attach_evloop(target,evloop);
}

static int target_rpc_monitor_evloop_detach(struct evloop *evloop,void *obj) {
    struct target *target = (struct target *)obj;
    return target_detach_evloop(target);
}

static int target_rpc_monitor_error(monitor_error_t error,void *obj) {
    vdebug(5,LA_XML,LF_RPC,"target id %d (error %d)\n",((struct target *)obj)->id,
	   error);
    return 0;
}

static int target_rpc_monitor_fatal_error(monitor_error_t error,void *obj) {
    vdebug(5,LA_XML,LF_RPC,"target id %d (error %d)\n",((struct target *)obj)->id,
	   error);
    //free(dummy);
    return 0;
}

static int target_rpc_monitor_child_recv_msg(struct monitor *monitor,
					     struct monitor_msg *msg) {
    struct target *target = (struct target *)monitor->obj;

    vdebug(9,LA_XML,LF_RPC,"msg(%d:%d,%d) = '%s' (target %id)\n",
	   msg->id,msg->seqno,msg->len,msg->msg,target->id);

    return proxyreq_recv_request(monitor,msg);
}

static int target_rpc_monitor_recv_msg(struct monitor *monitor,
				       struct monitor_msg *msg) {
    struct target *target = (struct target *)monitor->obj;

    vdebug(9,LA_XML,LF_RPC,"msg(%d:%d,%d) = '%s' (target->id)\n",
	   msg->id,msg->seqno,msg->len,msg->msg,target->id);

    return proxyreq_recv_response(monitor,msg);
}

static struct monitor_objtype_ops target_rpc_monitor_objtype_ops = {
    .evloop_attach = target_rpc_monitor_evloop_attach,
    .evloop_detach = target_rpc_monitor_evloop_detach,
    .error = target_rpc_monitor_error,
    .fatal_error = target_rpc_monitor_fatal_error,
    .child_recv_evh = NULL,
    .recv_evh = NULL,
    .child_recv_msg = target_rpc_monitor_child_recv_msg,
    .recv_msg = target_rpc_monitor_recv_msg,
};

/**
 ** Module init/fini stuff.
 **/
void target_rpc_init(void) {
    pthread_mutex_lock(&target_rpc_mutex);

    if (init_done) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return;
    }

    debuginfo_rpc_init();

    monitor_objtype_target = 
	monitor_register_objtype(monitor_objtype_target,
				 &target_rpc_monitor_objtype_ops);

    target_init();

    target_tab = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);
    session_tab = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);

    init_done = 1;

    pthread_mutex_unlock(&target_rpc_mutex);
}

void target_rpc_fini(void) {
    GHashTableIter iter;
    struct target *target;

    pthread_mutex_lock(&target_rpc_mutex);

    if (!init_done) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return;
    }

    /* Nuke any existing targets. */
    g_hash_table_iter_init(&iter,target_tab);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer *)&target)) {
	target_close(target);
	target_free(target);
    }
    g_hash_table_destroy(target_tab);
    target_tab = NULL;

    /* Remove any lingering sessions. */

    target_fini();
    debuginfo_rpc_fini();

    init_done = 0;

    pthread_mutex_unlock(&target_rpc_mutex);
}

/**
 ** The main handling function.  Will use proxyreqs for now; perhaps
 ** later we'll optionally add a different model involving a SOAP server
 ** for each target/analysis, where the master server is a
 ** launchpad/registry.
 **/

int target_rpc_handle_request(struct soap *soap) {
    struct proxyreq *pr;
    struct monitor *monitor;
    int retval;

    /*
     * If there is even a possibility that we might proxy the request to
     * a different thread or process for handling, we have to save off
     * the request before even beginning to handle it.  If the request
     * is handled in the RPC method, we can just free the proxy request
     * buf.  If, on the other hand, the RPC method signals us that we
     * have to signal another thread/process to handle the request, we
     * have to do that.
     */
    pr = proxyreq_create(soap);

    soap_serve(soap);

    if (soap->error == SOAP_STOP) {
	vdebug(8,LA_XML,LF_RPC,"proxying request from %d.%d.%d.%d\n",
	       (soap->ip >> 24) & 0xff,(soap->ip >> 16) & 0xff,
	       (soap->ip >> 8) & 0xff,soap->ip & 0xff);

	/*
	 * Don't destroy the soap context; the monitor thread will
	 * destroy it once it answers the request.
	 */
	retval = 0;
    }
    else if (soap->error == SOAP_OK) {
	if (pr->monitor && pr->monitor_is_new) {
	    vdebug(5,LA_XML,LF_RPC,
		   "finished request from %d.%d.%d.%d; new monitor thread %lu\n",
		   (soap->ip >> 24) & 0xff,(soap->ip >> 16) & 0xff,
		   (soap->ip >> 8) & 0xff,soap->ip & 0xff,
		   pr->monitor->mtid);

	    monitor = pr->monitor;

	    proxyreq_free(pr);
	    soap_destroy(soap);
	    soap_end(soap);
	    soap_done(soap);
	    free(soap);

	    return monitor_run(monitor);
	}
	else {
	    vdebug(5,LA_XML,LF_RPC,
		   "finished request from %d.%d.%d.%d\n",
		   (soap->ip >> 24) & 0xff,(soap->ip >> 16) & 0xff,
		   (soap->ip >> 8) & 0xff,soap->ip & 0xff);
	}

	retval = soap->error;

	proxyreq_free(pr);
	soap_destroy(soap);
	soap_end(soap);
	soap_done(soap);
	free(soap);
    }
    else {
	vdebug(8,LA_XML,LF_RPC,"finished request from %d.%d.%d.%d with status %d\n",
	       (soap->ip >> 24) & 0xff,(soap->ip >> 16) & 0xff,
	       (soap->ip >> 8) & 0xff,soap->ip & 0xff,soap->error);

	retval = soap->error;

	proxyreq_free(pr);
	soap_destroy(soap);
	soap_end(soap);
	soap_done(soap);

	free(soap);
    }

    return retval;
}

/**
 ** These are locking/nonlocking accessors to the global target hashtable.
 **
 ** Call the _ variants if you already hold the target_rpc_mutex; else,
 ** call the normal functions!
 **/
void _target_rpc_insert(struct target *target) {
    if (init_done)
	g_hash_table_insert(target_tab,(gpointer)(uintptr_t)target->id,target);
}
void target_rpc_insert(struct target *target) {
    pthread_mutex_lock(&target_rpc_mutex);
    _target_rpc_insert(target);
    pthread_mutex_unlock(&target_rpc_mutex);
}
struct target *_target_rpc_lookup(int id) {
    if (!init_done) 
	return NULL;

    return (struct target *)g_hash_table_lookup(target_tab,(gpointer)(ptr_t)id);
}
struct target *target_rpc_lookup(int id) {
    struct target *t;

    pthread_mutex_lock(&target_rpc_mutex);
    t = _target_rpc_lookup(id);
    pthread_mutex_unlock(&target_rpc_mutex);

    return t;
}
void _target_rpc_remove(struct target *target) {
    if (target_tab)
	g_hash_table_remove(target_tab,(gpointer)(uintptr_t)target->id);
}
void target_rpc_remove(struct target *target) {
    pthread_mutex_lock(&target_rpc_mutex);
    _target_rpc_remove(target);
    pthread_mutex_unlock(&target_rpc_mutex);
}

/*
 * Call with lock held!
 */
struct array_list *_target_rpc_get_existing_targets(void) {
    struct array_list *retval;
    GHashTableIter iter;
    struct target *t;

    if (!init_done || g_hash_table_size(target_tab) == 0)
	return NULL;

    retval = array_list_create(g_hash_table_size(target_tab));
    g_hash_table_iter_init(&iter,target_tab);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer *)&t)) 
	array_list_append(retval,t);

    return retval;
}

void *do_thread_split_request(void *arg) {
    struct soap *soap = (struct soap *)arg;

    pthread_detach(pthread_self());

    soap_serve(soap);

    if (soap->error != SOAP_STOP) {
	vdebug(8,LA_XML,LF_RPC,"finished request from %d.%d.%d.%d\n",
	       (soap->ip >> 24) & 0xff,(soap->ip >> 16) & 0xff,
	       (soap->ip >> 8) & 0xff,soap->ip & 0xff);

	soap_destroy(soap);
	soap_end(soap);
	soap_done(soap);

	free(soap);
    }

    return NULL;
}

int vmi1__ListTargetTypes(struct soap *soap,
			  void *_,
			  struct vmi1__TargetTypesResponse *r) {
#ifdef ENABLE_XENACCESS
    r->__size_targetType = 2;
#else
    r->__size_targetType = 1;
#endif

    r->targetType = \
	SOAP_CALLOC(soap,r->__size_targetType,sizeof(*(r->targetType)));

    r->targetType[0] = vmi1__TargetTypeT__ptrace;
#ifdef ENABLE_XENACCESS
    r->targetType[1] = vmi1__TargetTypeT__xen;
#endif

    return SOAP_OK;
}

//gsoap vmi1 service method-documentation: 
int vmi1__ListTargets(struct soap *soap,
		      void *_,
		      struct vmi1__TargetsResponse *r) {
    struct target *target;
    int i;
    GHashTable *reftab;
    struct array_list *tlist;

    target_rpc_init();

    pthread_mutex_lock(&target_rpc_mutex);

    tlist = _target_rpc_get_existing_targets();
    r->__size_target = tlist ? array_list_len(tlist) : 0;
    if (r->__size_target == 0) {
	r->target = NULL;
	pthread_mutex_unlock(&target_rpc_mutex);
	return SOAP_OK;
    }

    reftab = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);
    r->target = SOAP_CALLOC(soap,r->__size_target,sizeof(*r->target));
    array_list_foreach(tlist,i,target) 
	r->target[i] = t_target_to_x_TargetT(soap,target,reftab,NULL);

    g_hash_table_destroy(reftab);
    array_list_free(tlist);

    pthread_mutex_unlock(&target_rpc_mutex);

    return SOAP_OK;
}

int vmi1__GetTarget(struct soap *soap,
		    vmi1__TargetIdT tid,
		    struct vmi1__TargetResponse *r) {
    struct target *t;
    GHashTable *reftab;

    target_rpc_init();
    pthread_mutex_lock(&target_rpc_mutex);

    t = _target_rpc_lookup(tid);
    if (!t) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Nonexistent target!",
				   "Specified target does not exist!");
    }

    reftab = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);
    r->target = t_target_to_x_TargetT(soap,t,reftab,NULL);

    g_hash_table_destroy(reftab);
    pthread_mutex_unlock(&target_rpc_mutex);

    return SOAP_OK;
}

int vmi1__InstantiateTarget(struct soap *soap,
			    struct vmi1__TargetSpecT *spec,
			    struct vmi1__TargetResponse *r) {
    struct target *t;
    struct target_spec *s;
    GHashTable *reftab;
    struct monitor *monitor;
    struct proxyreq *pr;

    target_rpc_init();

    pr = soap->user;
    if (!pr) {
	return soap_receiver_fault(soap,
				   "Request needed splitting but not split!",
				   "Request needed splitting but not split!");
    }

    reftab = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);

    s = x_TargetSpecT_to_t_target_spec(soap,spec,reftab,NULL);
    if (!s) {
	g_hash_table_destroy(reftab);
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Bad target spec!",
				   "Bad target spec!");
    }

    pthread_mutex_lock(&target_rpc_mutex);

    /*
     * Have to see if we need to fork this target, or spawn it in a
     * thread.  For now, just always spawn in a thread.
     */
    if (1) {
	t = target_instantiate(s);
	if (!t) {
	    target_free_spec(s);
	    g_hash_table_destroy(reftab);
	    pthread_mutex_unlock(&target_rpc_mutex);
	    return soap_receiver_fault(soap,"Could not instantiate target!",
				       "Could not instantiate target!");
	}

	if (target_open(t)) {
	    verror("could not open target!\n");
	    target_free(t);
	    target_free_spec(s);
	    g_hash_table_destroy(reftab);
	    pthread_mutex_unlock(&target_rpc_mutex);
	    return soap_receiver_fault(soap,"Could not open target!",
				       "Could not open target after"
				       " instantiating it successfully!");
	}

	/*
	 * At this point, we need to create a monitor object associated with
	 * this thread's new target; then create an evloop, attach it to our
	 * new target and to the monitor; and call evloop_run infinitely --
	 * only destroying the target and the monitor if a fatal error
	 * occurs.
	 *
	 * Instead of even bothering to "share" soap struct state between
	 * incoming requests and request monitor threads that are directly
	 * attached to a target, we should always follow the model that we
	 * would use for forking: record the request, signal the monitor
	 * thread by copying the request over the pipe to the monitor
	 * thread; and block the client handling thread on the monitor
	 * thread serving the request.  Monitors have to handle requests
	 * serially anyway (well, at least operations on a target; debuginfo
	 * operations might be another story and could be parallelized).
	 *
	 * So this means no more queues; no more shared soap structs; all
	 * soap structs are faked if the request is split;
	 * requests/responses are fully buffered over pipes (sigh) (well,
	 * can we chain the read/write functions direct so they don't have
	 * to?  but does soap really buffer the whole response before
	 * writing it?  it would have to in order to write the
	 * content-header line...) (so, let's start out with full buffering,
	 * then later we could break pipe comms into well-known packet lengths
	 * with a length header field, then data).
	 *
	 * Debuginfo responses are big and huge and we have to do something
	 * better than querying the debuginfo per-target... unless gsoap
	 * really buffers the entire result before writing anything.  If it
	 * does, we may as well double-buffer :).  It would just be best to
	 * figure a way to share the buffer to avoid all the mallocs in the
	 * second buffering when passing a result back.
	 */
	monitor = monitor_create(MONITOR_TYPE_THREAD,MONITOR_FLAG_NONE,
				 monitor_objtype_target,t);
	if (!monitor) {
	    target_free_spec(s);
	    g_hash_table_destroy(reftab);
	    pthread_mutex_unlock(&target_rpc_mutex);
	    return soap_receiver_fault(soap,"Could not create monitor!",
				       "Could not create monitor!");
	}

	proxyreq_attach_new(pr,monitor);

	_target_rpc_insert(t);

	r->target = t_target_to_x_TargetT(soap,t,reftab,NULL);
	pthread_mutex_unlock(&target_rpc_mutex);

	return SOAP_OK;
    }
    else {
	/* XXX: Use our special servetarget program to fork the target. */

    }
}
int vmi1__PauseTarget(struct soap *soap,
		      vmi1__TargetIdT tid,
		      struct vmi1__NoneResponse *r) {
    struct target *t;

    target_rpc_init();
    pthread_mutex_lock(&target_rpc_mutex);

    t = _target_rpc_lookup(tid);
    if (!t) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Nonexistent target!",
				   "Specified target does not exist!");
    }

    PROXY_REQUEST_LOCKED(soap,t,t->id,&target_rpc_mutex);

    if (target_pause(t)) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Could not pause target!",
				   "Could not pause target!");
    }

    pthread_mutex_unlock(&target_rpc_mutex);

    return SOAP_OK;
}
int vmi1__ResumeTarget(struct soap *soap,
		       vmi1__TargetIdT tid,
		      struct vmi1__NoneResponse *r) {
    struct target *t;

    target_rpc_init();
    pthread_mutex_lock(&target_rpc_mutex);

    t = _target_rpc_lookup(tid);
    if (!t) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Nonexistent target!",
				   "Specified target does not exist!");
    }

    PROXY_REQUEST_LOCKED(soap,t,t->id,&target_rpc_mutex);

    if (target_resume(t)) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Could not resume target!",
				   "Could not resume target!");
    }

    pthread_mutex_unlock(&target_rpc_mutex);

    return SOAP_OK;
}

int vmi1__CloseTarget(struct soap *soap,
		      vmi1__TargetIdT tid,enum xsd__boolean kill,
		      struct vmi1__NoneResponse *r) {
    struct target *t;

    target_rpc_init();
    pthread_mutex_lock(&target_rpc_mutex);

    t = _target_rpc_lookup(tid);
    if (!t) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Nonexistent target!",
				   "Specified target does not exist!");
    }

    PROXY_REQUEST_LOCKED(soap,t,t->id,&target_rpc_mutex);

    if (target_close(t)) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Could not close target!",
				   "Could not close target!");
    }

    if (kill == xsd__boolean__true_) {
	if (target_kill(t)) {
	    pthread_mutex_unlock(&target_rpc_mutex);
	    return soap_receiver_fault(soap,"Could not kill target!",
				       "Could not kill target!");
	}
    }

    _target_rpc_remove(t);

    target_free(t);

    pthread_mutex_unlock(&target_rpc_mutex);

    return SOAP_OK;
}

int vmi1__PauseThread(struct soap *soap,
		      vmi1__TargetIdT tid,vmi1__ThreadIdT thid,
		      struct vmi1__NoneResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}
int vmi1__ResumeThread(struct soap *soap,
		       vmi1__TargetIdT tid,vmi1__ThreadIdT thid,
		       struct vmi1__NoneResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__SinglestepThread(struct soap *soap,
			   vmi1__TargetIdT tid,vmi1__ThreadIdT thid,
			   struct vmi1__NoneResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__LookupTargetSymbol(struct soap *soap,
			     vmi1__TargetIdT tid,char *name,
			     struct vmi1__DebugFileOptsT *opts,
			     struct vmi1__NestedSymbolResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}
int vmi1__LookupTargetAddrSimple(struct soap *soap,
				 vmi1__TargetIdT tid,vmi1__ADDR addr,
				 struct vmi1__DebugFileOptsT *opts,
				 struct vmi1__SymbolResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}
int vmi1__LookupTargetAddr(struct soap *soap,
			   vmi1__TargetIdT tid,vmi1__ADDR addr,
			   struct vmi1__DebugFileOptsT *opts,
			   struct vmi1__NestedSymbolResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}
int vmi1__LookupTargetAllSymbols(struct soap *soap,
				 vmi1__TargetIdT tid,char *name,
				 struct vmi1__DebugFileOptsT *opts,
				 struct vmi1__NestedSymbolResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__OpenSession(struct soap *soap,
		      vmi1__TargetIdT tid,
		      vmi1__SessionIdT *sid) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__CloseSession(struct soap *soap,
		       vmi1__TargetIdT tid,
		       vmi1__SessionIdT *sid) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}
