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

#include <pthread.h>
#include <glib.h>
#include <errno.h>
#include <sys/prctl.h>

#include "common_xml.h"
#include "target_rpc.h"
#include "debuginfo_rpc.h"
#include "target_xml.h"
#include "util.h"
#include "alist.h"
#include "target.h"
#include "target_api.h"
#include "probe_api.h"

#include "evloop.h"
#include "monitor.h"
#include "proxyreq.h"

#include "target_listener_moduleStub.h"

static pthread_mutex_t target_rpc_mutex = PTHREAD_MUTEX_INITIALIZER;
static int init_done = 0;
/* These are the targets we know about. */
static GHashTable *target_tab = NULL;

/* Map target id to an array_list of target listeners. */
static GHashTable *target_listener_tab = NULL;

extern struct vmi1__DebugFileOptsT defDebugFileOpts;

/**
 ** A bunch of stuff for per-target monitor interactions.
 **/
static int target_rpc_monitor_evloop_attach(struct evloop *evloop,void *obj) {
    struct target *target = (struct target *)obj;

    if (!obj) 
	return 0;

    return target_attach_evloop(target,evloop);
}

static int target_rpc_monitor_evloop_detach(struct evloop *evloop,void *obj) {
    struct target *target = (struct target *)obj;

    if (!obj) 
	return 0;

    return target_detach_evloop(target);
}

static int target_rpc_monitor_close(int sig,void *obj) {
    struct target *target = (struct target *)obj;
    int retval;

    if (!obj)
	return 0;

    if ((retval = target_close(target)) != TSTATUS_DONE) {
	verror("could not close target (error %d); freeing anyway!\n",retval);
    }
    target_free(target);

    return 0;
}

static int target_rpc_monitor_evloop_is_attached(struct evloop *evloop,void *obj) {
    struct target *target = (struct target *)obj;

    if (!obj)
	return 0;

    return target_is_evloop_attached(target,evloop);
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

    vdebug(9,LA_XML,LF_RPC,"msg(%d:%hd,%hd,%d) = '%s' (target %d (%p))\n",
	   msg->id,msg->cmd,msg->seqno,msg->len,msg->msg,msg->objid,target);

    return proxyreq_recv_request(monitor,msg);
}

static int target_rpc_monitor_recv_msg(struct monitor *monitor,
				       struct monitor_msg *msg) {
    struct target *target = (struct target *)monitor->obj;

    vdebug(9,LA_XML,LF_RPC,"msg(%d:%hd,%hd,%d) = '%s' (target %d (%p))\n",
	   msg->id,msg->cmd,msg->seqno,msg->len,msg->msg,msg->objid,target);

    return proxyreq_recv_response(monitor,msg);
}

struct monitor_objtype_ops target_rpc_monitor_objtype_ops = {
    .evloop_attach = target_rpc_monitor_evloop_attach,
    .evloop_detach = target_rpc_monitor_evloop_detach,
    .close = target_rpc_monitor_close,
    .evloop_is_attached = target_rpc_monitor_evloop_is_attached,
    .error = target_rpc_monitor_error,
    .fatal_error = target_rpc_monitor_fatal_error,
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
    monitor_init();
    target_init();

    monitor_register_objtype(MONITOR_OBJTYPE_TARGET,
			     &target_rpc_monitor_objtype_ops);

    target_tab = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);
    target_listener_tab = 
	g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);

    init_done = 1;

    pthread_mutex_unlock(&target_rpc_mutex);
}

void target_rpc_fini(void) {
    GHashTableIter iter;
    struct target *target;
    struct target_rpc_listener *tl;

    pthread_mutex_lock(&target_rpc_mutex);

    if (!init_done) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return;
    }

    /* Nuke any existing target listeners. */
    g_hash_table_iter_init(&iter,target_listener_tab);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer *)&tl)) {
	free(tl);
    }
    g_hash_table_destroy(target_listener_tab);
    target_listener_tab = NULL;

    /* Nuke any existing targets. */
    g_hash_table_iter_init(&iter,target_tab);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer *)&target)) {
	if (!target)
	    continue;

	target_close(target);
	target_free(target);
    }
    g_hash_table_destroy(target_tab);
    target_tab = NULL;

    monitor_fini();
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
    char name[16];
    int rc;

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

    retval = soap_serve(soap);

    if (retval == SOAP_STOP) {
	vdebug(8,LA_XML,LF_RPC,"proxying request from %d.%d.%d.%d\n",
	       (soap->ip >> 24) & 0xff,(soap->ip >> 16) & 0xff,
	       (soap->ip >> 8) & 0xff,soap->ip & 0xff);

	PROXY_REQUEST_LOCKED_HANDLE_STOP(soap,&target_rpc_mutex);

	if (soap->error != SOAP_OK) {
	    verror("could not handle SOAP_STOP by proxing request!\n");
	    // XXX: need to send SOAP error!;
	    proxyreq_free(pr);
	    soap_destroy(soap);
	    soap_end(soap);
	    soap_done(soap);
	    free(soap);
	}

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

	    snprintf(name,16,"target_m_%d",monitor->objid);
	    prctl(PR_SET_NAME,name,NULL,NULL,NULL);

	    proxyreq_free(pr);
	    soap_destroy(soap);
	    soap_end(soap);
	    soap_done(soap);
	    free(soap);

	    while (1) {
		rc = monitor_run(monitor);
		if (rc < 0) {
		    verror("bad internal error in monitor for target %d; destroying!\n",
			   monitor->objid);
		    monitor_destroy(monitor);
		    return -1;
		}
		else {
		    if (monitor_is_done(monitor)) {
			vdebug(2,LA_XML,LF_RPC,
			       "monitoring on target %d is done;"
			      " closing (not finalizing)!\n",
			      monitor->objid);
			monitor_shutdown(monitor);
			return 0;
		    }
		    else if (monitor_is_halfdead(monitor)) {
			vwarn("target %d monitor child died unexpectedly;"
			      " closing (not finalizing)!\n",
			      monitor->objid);
			monitor_shutdown(monitor);
			return -1;
		    }
		    else if (monitor_should_self_finalize(monitor)) {
			vwarn("forked target %d finalizing!\n",
			      monitor->objid);
			monitor_destroy(monitor);
			return 0;
		    }
		    else {
			vwarn("target %d monitor_run finished unexpectedly;"
			      " closing (not finalizing)!\n",
			      monitor->objid);
			monitor_shutdown(monitor);
			return 0;
		    }
		}
	    }

	    return 0;
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
 ** These are locking/nonlocking accessors to the global target hashtables.
 **
 ** Call the _ variants if you already hold the target_rpc_mutex; else,
 ** call the normal functions!
 **/
static void _target_rpc_insert(int target_id,struct target *target) {
    if (init_done)
	g_hash_table_insert(target_tab,(gpointer)(uintptr_t)target_id,target);
}
void target_rpc_insert(int target_id,struct target *target) {
    pthread_mutex_lock(&target_rpc_mutex);
    _target_rpc_insert(target_id,target);
    pthread_mutex_unlock(&target_rpc_mutex);
}
static int _target_rpc_lookup(int id,struct target **target) {
    if (!init_done) 
	return 0;

    return g_hash_table_lookup_extended(target_tab,(gconstpointer)(ptr_t)id,
					NULL,(gpointer *)target);
}
int target_rpc_lookup(int id,struct target **target) {
    int retval;

    pthread_mutex_lock(&target_rpc_mutex);
    retval = _target_rpc_lookup(id,target);
    pthread_mutex_unlock(&target_rpc_mutex);

    return retval;
}
static void _target_rpc_remove(int target_id) {
    if (target_tab)
	g_hash_table_remove(target_tab,(gpointer)(uintptr_t)target_id);
}
static void target_rpc_remove(int target_id) {
    pthread_mutex_lock(&target_rpc_mutex);
    _target_rpc_remove(target_id);
    pthread_mutex_unlock(&target_rpc_mutex);
}

struct target_rpc_listener *_target_rpc_lookup_listener(int target_id,
							char *hostname,int port) {
    struct array_list *tll;
    int i;
    struct target_rpc_listener *tl = NULL;

    tll = (struct array_list *)						\
	g_hash_table_lookup(target_listener_tab,(gpointer)(uintptr_t)target_id);

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
struct target_rpc_listener *target_rpc_lookup_listener(int target_id,
						       char *hostname,int port) {
    struct target_rpc_listener *tl;

    pthread_mutex_lock(&target_rpc_mutex);
    tl = _target_rpc_lookup_listener(target_id,hostname,port);
    pthread_mutex_unlock(&target_rpc_mutex);

    return tl;
}

int _target_rpc_insert_listener(int target_id,char *hostname,int port) {
    struct array_list *tll;
    struct target_rpc_listener *tl = calloc(1,sizeof(*tl));

    tl->target_id = target_id;
    tl->hostname = strdup(hostname);
    tl->port = port;

    tll = (struct array_list *)						\
	g_hash_table_lookup(target_listener_tab,(gpointer)(uintptr_t)target_id);

    if (!tll) {
	tll = array_list_create(1);
	g_hash_table_insert(target_listener_tab,
			    (gpointer)(uintptr_t)target_id,tll);
    }

    array_list_append(tll,tl);

    return 0;
}
int target_rpc_insert_listener(int target_id,char *hostname,int port) {
    int rc;

    pthread_mutex_lock(&target_rpc_mutex);
    rc = _target_rpc_insert_listener(target_id,hostname,port);
    pthread_mutex_unlock(&target_rpc_mutex);

    return rc;
}

int _target_rpc_remove_listener(int target_id,char *hostname,int port) {
    struct array_list *tll;
    int i;
    struct target_rpc_listener *tl;

    tll = (struct array_list *)						\
	g_hash_table_lookup(target_listener_tab,(gpointer)(uintptr_t)target_id);

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
int target_rpc_remove_listener(int target_id,char *hostname,int port) {
    int rc;

    pthread_mutex_lock(&target_rpc_mutex);
    rc = _target_rpc_remove_listener(target_id,hostname,port);
    pthread_mutex_unlock(&target_rpc_mutex);

    return rc;
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

int vmi1__ListTargetTypes(struct soap *soap,
			  void *_,
			  struct vmi1__TargetTypesResponse *r) {
#ifdef ENABLE_XENSUPPORT
    r->__size_targetType = 2;
#else
    r->__size_targetType = 1;
#endif

    r->targetType = \
	SOAP_CALLOC(soap,r->__size_targetType,sizeof(*(r->targetType)));

    r->targetType[0] = vmi1__TargetTypeT__ptrace;
#ifdef ENABLE_XENSUPPORT
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
    struct target *t = NULL;
    GHashTable *reftab;

    target_rpc_init();
    pthread_mutex_lock(&target_rpc_mutex);

    if (!_target_rpc_lookup(tid,&t)) {
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
    int tid;
    int largc = 0;
    char **largv = NULL;
    int i;
    char *tmpbuf;
    int tmpbuflen;
    int pid;

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

    tid = monitor_get_unique_objid();
    /* Force it to use our new monitored object id. */
    s->target_id = tid;

    /*
     * Have to see if we need to fork this target, or spawn it in a
     * thread.  For now, just always spawn in a thread.
     */
    if (!spec->dedicatedMonitor 
	|| (spec->dedicatedMonitor 
	    && *spec->dedicatedMonitor == xsd__boolean__false_)) {
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
				 tid,MONITOR_OBJTYPE_TARGET,NULL);
	if (!monitor) {
	    target_free_spec(s);
	    g_hash_table_destroy(reftab);
	    pthread_mutex_unlock(&target_rpc_mutex);
	    return soap_receiver_fault(soap,"Could not create monitor!",
				       "Could not create monitor!");
	}

	/* Make sure to use our new evloop right away. */
	t = target_instantiate(s,monitor->evloop);
	if (!t) {
	    target_free_spec(s);
	    g_hash_table_destroy(reftab);
	    pthread_mutex_unlock(&target_rpc_mutex);
	    return soap_receiver_fault(soap,"Could not instantiate target!",
				       "Could not instantiate target!");
	}

	monitor_add_primary_obj(monitor,t->id,MONITOR_OBJTYPE_TARGET,t);

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

	proxyreq_attach_new_objid(pr,t->id,monitor);

	_target_rpc_insert(t->id,t);

	r->target = t_target_to_x_TargetT(soap,t,reftab,NULL);
	pthread_mutex_unlock(&target_rpc_mutex);

	return SOAP_OK;
    }
    else {
	/* Use our special servetarget program to fork the target. */
	if (target_spec_to_argv(s,MONITORED_TARGET_LAUNCHER,&largc,&largv)) {
	    target_free_spec(s);
	    g_hash_table_destroy(reftab);
	    pthread_mutex_unlock(&target_rpc_mutex);
	    return soap_receiver_fault(soap,"Could not create argv from spec!",
				       "Could not create argv from spec!");
	}

	monitor = monitor_create(MONITOR_TYPE_PROCESS,MONITOR_FLAG_BIDI,
				 s->target_id,MONITOR_OBJTYPE_TARGET,NULL);
	if (!monitor) {
	    if (largc > 0) {
		for (i = 0; i < largc; ++i)
		    if (largv[i])
			free(largv[i]);
		free(largv);
	    }
	    monitor_destroy(monitor);
	    target_free_spec(s);
	    g_hash_table_destroy(reftab);
	    pthread_mutex_unlock(&target_rpc_mutex);
	    return soap_receiver_fault(soap,"Could not create monitor!",
				       "Could not create monitor!");
	}

	/*
	 * Setup I/O to child!  We always have to use our callbacks and
	 * do our own logging.  BUT, we want to log/interact with the
	 * spawned target's I/O, not to the child process that is
	 * launching the child.  Unfortunately, this is more
	 * time-consuming to implement, so, for now, just ensure that
	 * the target gets launched using the child's I/O streams --
	 * which our callbacks here will listen to.  It's either do that
	 * or open additional streams that we tell the child about.
	 *
	 * So, for now, we just use the monitor's I/O abstractions, just
	 * like if we were spawning an analysis.
	 */
	/* Hack the spec to get the target to use the child's FDs.*/

	if (spec->stdinBytes && spec->stdinBytes->__size > 0) {
	    s->infile = strdup("-");

	    tmpbuf = malloc(spec->stdinBytes->__size);
	    memcpy(tmpbuf,spec->stdinBytes->__ptr,spec->stdinBytes->__size);

	    monitor_setup_stdin(monitor,tmpbuf,spec->stdinBytes->__size);
	}

	if (spec->logStdout && *spec->logStdout == xsd__boolean__true_) {
	    s->outfile = strdup("-");

	    tmpbuflen = 5 + 11 + 1 + 6 + 1 + 3 + 1;
	    tmpbuf = malloc(tmpbuflen);
	    snprintf(tmpbuf,tmpbuflen,"/tmp/%d.stdout.log",s->target_id);

	    monitor_setup_stdout(monitor,-1,tmpbuf,NULL);
	}

	if (spec->logStderr && *spec->logStderr == xsd__boolean__true_) {
	    s->errfile = strdup("-");

	    tmpbuflen = 5 + 11 + 1 + 6 + 1 + 3 + 1;
	    tmpbuf = malloc(tmpbuflen);
	    snprintf(tmpbuf,tmpbuflen,"/tmp/%d.stderr.log",s->target_id);

	    monitor_setup_stderr(monitor,-1,tmpbuf,NULL);
	}

	monitor_add_primary_obj(monitor,s->target_id,MONITOR_OBJTYPE_TARGET,NULL);

	pid = monitor_spawn(monitor,MONITORED_TARGET_LAUNCHER,largv,NULL,"/tmp");
	if (pid < 0) {
	    verror("error spawning: %d (%s)\n",pid,strerror(errno));
	    if (largc > 0) {
		for (i = 0; i < largc; ++i)
		    if (largv[i])
			free(largv[i]);
		free(largv);
	    }
	    monitor_destroy(monitor);
	    target_free_spec(s);
	    g_hash_table_destroy(reftab);
	    pthread_mutex_unlock(&target_rpc_mutex);
	    return soap_receiver_fault(soap,"Could not spawn forked target!",
				       "Could not spawn forked target!");
	}

	proxyreq_attach_new_objid(pr,s->target_id,monitor);

	_target_rpc_insert(s->target_id,NULL);

	r->target = t_target_id_to_x_TargetT(soap,s->target_id,s,reftab,NULL);
	pthread_mutex_unlock(&target_rpc_mutex);

	return SOAP_OK;
    }
}
int vmi1__PauseTarget(struct soap *soap,
		      vmi1__TargetIdT tid,
		      struct vmi1__NoneResponse *r) {
    struct target *t = NULL;

    target_rpc_init();
    pthread_mutex_lock(&target_rpc_mutex);

    if (!_target_rpc_lookup(tid,&t)) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Nonexistent target!",
				   "Specified target does not exist!");
    }

    PROXY_REQUEST_LOCKED(soap,tid,&target_rpc_mutex);

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
    struct target *t = NULL;

    target_rpc_init();
    pthread_mutex_lock(&target_rpc_mutex);

    if (!_target_rpc_lookup(tid,&t)) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Nonexistent target!",
				   "Specified target does not exist!");
    }

    PROXY_REQUEST_LOCKED(soap,tid,&target_rpc_mutex);

    if (target_resume(t)) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Could not resume target!",
				   "Could not resume target!");
    }

    pthread_mutex_unlock(&target_rpc_mutex);

    return SOAP_OK;
}

int vmi1__CloseTarget(struct soap *soap,
		      vmi1__TargetIdT tid,enum xsd__boolean kill,int kill_sig,
		      struct vmi1__NoneResponse *r) {
    struct target *t = NULL;
    struct monitor *monitor;

    target_rpc_init();
    pthread_mutex_lock(&target_rpc_mutex);

    if (!monitor_lookup_objid(tid,NULL,NULL,&monitor)) {
	verror("no monitor for objid %d!\n",tid);
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Nonexistent target monitor!",
				   "Specified target monitor does not exist!");
    }

    if (!_target_rpc_lookup(tid,&t)) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Nonexistent target!",
				   "Specified target does not exist!");
    }

    PROXY_REQUEST_LOCKED(soap,tid,&target_rpc_mutex);

    if (kill == xsd__boolean__true_) {
	t->kill_on_close = 1;
	if (kill_sig > 0)
	    t->kill_sig = kill_sig;
	else 
	    t->kill_sig = -1;
    }

    /*
     * Let the monitor close/kill the target.
     */

    monitor_interrupt_done(monitor,RESULT_SUCCESS,0);

    pthread_mutex_unlock(&target_rpc_mutex);

    return SOAP_OK;
}

int vmi1__FinalizeTarget(struct soap *soap,
			 vmi1__TargetIdT tid,
			 struct vmi1__NoneResponse *r) {
    struct target *t = NULL;

    target_rpc_init();
    pthread_mutex_lock(&target_rpc_mutex);

    if (!_target_rpc_lookup(tid,&t)) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Nonexistent target!",
				   "Specified target does not exist!");
    }

    PROXY_REQUEST_LOCKED(soap,tid,&target_rpc_mutex);

    _target_rpc_remove(t->id);

    pthread_mutex_unlock(&target_rpc_mutex);

    return SOAP_OK;
}

int vmi1__PauseThread(struct soap *soap,
		      vmi1__TargetIdT tid,vmi1__ThreadIdT thid,
		      struct vmi1__NoneResponse *r) {
    struct target *t = NULL;

    target_rpc_init();
    pthread_mutex_lock(&target_rpc_mutex);

    if (!_target_rpc_lookup(tid,&t)) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Nonexistent target!",
				   "Specified target does not exist!");
    }

    PROXY_REQUEST_LOCKED(soap,tid,&target_rpc_mutex);

    if (target_pause_thread(t,thid,0)) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Could not pause target thread!",
				   "Could not pause target thread!");
    }

    pthread_mutex_unlock(&target_rpc_mutex);

    return SOAP_OK;
}

int vmi1__LookupTargetSymbolSimple(struct soap *soap,
				   vmi1__TargetIdT tid,char *name,
				   struct vmi1__DebugFileOptsT *opts,
				   struct vmi1__SymbolResponse *r) {
    struct bsymbol *bsymbol;
    GHashTable *reftab;
    struct array_list *refstack;
    struct target *t = NULL;

    target_rpc_init();
    pthread_mutex_lock(&target_rpc_mutex);

    if (!_target_rpc_lookup(tid,&t)) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Nonexistent target!",
				   "Specified target does not exist!");
    }

    PROXY_REQUEST_LOCKED(soap,tid,&target_rpc_mutex);

    if (!opts)
	opts = &defDebugFileOpts;

    if (opts->doMultiRef)
	soap_set_omode(soap,SOAP_XML_GRAPH);

    bsymbol = target_lookup_sym(t,name,NULL,NULL,SYMBOL_TYPE_NONE);

    if (!bsymbol) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Could not find symbol!",
				   "Could not find symbol!");
    }

    reftab = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);
    refstack = array_list_create(DEF_REFSTACK_SIZE);

    r->symbol = d_symbol_to_x_SymbolT(soap,bsymbol->lsymbol->symbol,
				      opts,reftab,refstack,0);

    array_list_free(refstack);
    g_hash_table_destroy(reftab);

    bsymbol_release(bsymbol);

    pthread_mutex_unlock(&target_rpc_mutex);

    return SOAP_OK;
}

int vmi1__LookupTargetSymbol(struct soap *soap,
			     vmi1__TargetIdT tid,char *name,
			     struct vmi1__DebugFileOptsT *opts,
			     struct vmi1__NestedSymbolResponse *r) {
    struct bsymbol *bsymbol;
    GHashTable *reftab;
    struct array_list *refstack;
    struct target *t = NULL;

    target_rpc_init();
    pthread_mutex_lock(&target_rpc_mutex);

    if (!_target_rpc_lookup(tid,&t)) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Nonexistent target!",
				   "Specified target does not exist!");
    }

    PROXY_REQUEST_LOCKED(soap,tid,&target_rpc_mutex);

    if (!opts)
	opts = &defDebugFileOpts;

    if (opts->doMultiRef)
	soap_set_omode(soap,SOAP_XML_GRAPH);

    bsymbol = target_lookup_sym(t,name,NULL,NULL,SYMBOL_TYPE_NONE);

    if (!bsymbol) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Could not find symbol!",
				   "Could not find symbol!");
    }

    reftab = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);
    refstack = array_list_create(DEF_REFSTACK_SIZE);
    r->nestedSymbol = \
	d_symbol_array_list_to_x_SymbolsT(soap,bsymbol->lsymbol->chain,
					  opts,reftab,refstack,0);
    if (r->nestedSymbol) 
	vwarn("%d %d %p\n",g_hash_table_size(reftab),
	      r->nestedSymbol->__size_SymbolsT,
	      r->nestedSymbol->__union_SymbolsT);
    else
	vwarn("%d\n",g_hash_table_size(reftab));

    array_list_free(refstack);
    g_hash_table_destroy(reftab);

    bsymbol_release(bsymbol);

    pthread_mutex_unlock(&target_rpc_mutex);

    return SOAP_OK;
}

int vmi1__LookupTargetAddrSimple(struct soap *soap,
				 vmi1__TargetIdT tid,vmi1__ADDR addr,
				 struct vmi1__DebugFileOptsT *opts,
				 struct vmi1__SymbolResponse *r) {
    struct bsymbol *bsymbol;
    GHashTable *reftab;
    struct array_list *refstack;
    struct target *t = NULL;

    target_rpc_init();
    pthread_mutex_lock(&target_rpc_mutex);

    if (!_target_rpc_lookup(tid,&t)) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Nonexistent target!",
				   "Specified target does not exist!");
    }

    PROXY_REQUEST_LOCKED(soap,tid,&target_rpc_mutex);

    if (!opts)
	opts = &defDebugFileOpts;

    if (opts->doMultiRef)
	soap_set_omode(soap,SOAP_XML_GRAPH);

    bsymbol = target_lookup_sym_addr(t,addr);

    if (!bsymbol) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Could not find address!",
				   "Could not find address!");
    }

    reftab = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);
    refstack = array_list_create(DEF_REFSTACK_SIZE);

    r->symbol = d_symbol_to_x_SymbolT(soap,bsymbol->lsymbol->symbol,
				      opts,reftab,refstack,0);

    array_list_free(refstack);
    g_hash_table_destroy(reftab);

    bsymbol_release(bsymbol);

    pthread_mutex_unlock(&target_rpc_mutex);

    return SOAP_OK;
}

int vmi1__LookupTargetAddr(struct soap *soap,
			   vmi1__TargetIdT tid,vmi1__ADDR addr,
			   struct vmi1__DebugFileOptsT *opts,
			   struct vmi1__NestedSymbolResponse *r) {
    struct bsymbol *bsymbol;
    GHashTable *reftab;
    struct array_list *refstack;
    struct target *t = NULL;

    target_rpc_init();
    pthread_mutex_lock(&target_rpc_mutex);

    if (!_target_rpc_lookup(tid,&t)) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Nonexistent target!",
				   "Specified target does not exist!");
    }

    PROXY_REQUEST_LOCKED(soap,tid,&target_rpc_mutex);

    if (!opts)
	opts = &defDebugFileOpts;

    if (opts->doMultiRef)
	soap_set_omode(soap,SOAP_XML_GRAPH);

    bsymbol = target_lookup_sym_addr(t,addr);

    if (!bsymbol) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Could not find address!",
				   "Could not find address!");
    }

    reftab = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);
    refstack = array_list_create(DEF_REFSTACK_SIZE);
    r->nestedSymbol = \
	d_symbol_array_list_to_x_SymbolsT(soap,bsymbol->lsymbol->chain,
					  opts,reftab,refstack,0);
    if (r->nestedSymbol) 
	vwarn("%d %d %p\n",g_hash_table_size(reftab),
	      r->nestedSymbol->__size_SymbolsT,
	      r->nestedSymbol->__union_SymbolsT);
    else
	vwarn("%d\n",g_hash_table_size(reftab));

    array_list_free(refstack);
    g_hash_table_destroy(reftab);

    bsymbol_release(bsymbol);

    pthread_mutex_unlock(&target_rpc_mutex);

    return SOAP_OK;
}

int vmi1__LookupTargetLineSimple(struct soap *soap,
				 vmi1__TargetIdT tid,char *filename,int line,
				 struct vmi1__DebugFileOptsT *opts,
				 struct vmi1__SymbolResponse *r) {
    struct bsymbol *bsymbol;
    GHashTable *reftab;
    struct array_list *refstack;
    struct target *t = NULL;

    target_rpc_init();
    pthread_mutex_lock(&target_rpc_mutex);

    if (!_target_rpc_lookup(tid,&t)) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Nonexistent target!",
				   "Specified target does not exist!");
    }

    PROXY_REQUEST_LOCKED(soap,tid,&target_rpc_mutex);

    if (!opts)
	opts = &defDebugFileOpts;

    if (opts->doMultiRef)
	soap_set_omode(soap,SOAP_XML_GRAPH);

    bsymbol = target_lookup_sym_line(t,filename,line,NULL,NULL);

    if (!bsymbol) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Could not find line!",
				   "Could not find line!");
    }

    reftab = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);
    refstack = array_list_create(DEF_REFSTACK_SIZE);

    r->symbol = d_symbol_to_x_SymbolT(soap,bsymbol->lsymbol->symbol,
				      opts,reftab,refstack,0);

    array_list_free(refstack);
    g_hash_table_destroy(reftab);

    bsymbol_release(bsymbol);

    pthread_mutex_unlock(&target_rpc_mutex);

    return SOAP_OK;

}

int vmi1__LookupTargetLine(struct soap *soap,
			   vmi1__TargetIdT tid,char *filename,int line,
			   struct vmi1__DebugFileOptsT *opts,
			   struct vmi1__NestedSymbolResponse *r) {
    struct bsymbol *bsymbol;
    GHashTable *reftab;
    struct array_list *refstack;
    struct target *t = NULL;

    target_rpc_init();
    pthread_mutex_lock(&target_rpc_mutex);

    if (!_target_rpc_lookup(tid,&t)) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Nonexistent target!",
				   "Specified target does not exist!");
    }

    PROXY_REQUEST_LOCKED(soap,tid,&target_rpc_mutex);

    if (!opts)
	opts = &defDebugFileOpts;

    if (opts->doMultiRef)
	soap_set_omode(soap,SOAP_XML_GRAPH);

    bsymbol = target_lookup_sym_line(t,filename,line,NULL,NULL);

    if (!bsymbol) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Could not find line!",
				   "Could not find line!");
    }

    reftab = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);
    refstack = array_list_create(DEF_REFSTACK_SIZE);
    r->nestedSymbol = \
	d_symbol_array_list_to_x_SymbolsT(soap,bsymbol->lsymbol->chain,
					  opts,reftab,refstack,0);
    if (r->nestedSymbol) 
	vwarn("%d %d %p\n",g_hash_table_size(reftab),
	      r->nestedSymbol->__size_SymbolsT,
	      r->nestedSymbol->__union_SymbolsT);
    else
	vwarn("%d\n",g_hash_table_size(reftab));

    array_list_free(refstack);
    g_hash_table_destroy(reftab);

    bsymbol_release(bsymbol);

    pthread_mutex_unlock(&target_rpc_mutex);

    return SOAP_OK;
}

struct action *x_ActionSpecT_to_t_action(struct soap *soap,
					 struct vmi1__ActionSpecT *spec,
					 struct target *target) {
    struct action *action = NULL;
    action_type_t atype;
    REG reg;
    char *ddata;

    atype = x_ActionTypeT_to_t_action_type_t(soap,spec->type);
    if (atype == ACTION_RETURN && spec->union_ActionSpecT.return_) 
	action = action_return(spec->union_ActionSpecT.return_->code);
    else if (atype == ACTION_REGMOD && spec->union_ActionSpecT.regmod
	&& spec->union_ActionSpecT.regmod->registerValue
	&& spec->union_ActionSpecT.regmod->registerValue->name) {
	reg = target_dw_reg_no_targetname(target,spec->union_ActionSpecT.regmod->registerValue->name);
	if (reg == 0 && errno == EINVAL) {
	    verror("bad register number in regmod action!\n");
	    return NULL;
	}
	action = \
	    action_regmod(reg,
			  spec->union_ActionSpecT.regmod->registerValue->value);
    }
    else if (atype == ACTION_MEMMOD && spec->union_ActionSpecT.memmod
	     && spec->union_ActionSpecT.memmod->data.__ptr) {
	ddata = calloc(1,spec->union_ActionSpecT.memmod->data.__size);
	memcpy(ddata,spec->union_ActionSpecT.memmod->data.__ptr,
	       spec->union_ActionSpecT.memmod->data.__size);
	action = \
	    action_memmod(spec->union_ActionSpecT.memmod->addr,ddata,
			  spec->union_ActionSpecT.memmod->data.__size);
    }
    else if (atype == ACTION_SINGLESTEP && spec->union_ActionSpecT.singlestep) {
	action = action_singlestep(spec->union_ActionSpecT.singlestep->stepCount);
    }
    else {
	verror("bad action spec -- could not attempt action creation!!\n");
	return NULL;
    }

    if (!action) 
	verror("bad action spec -- failure in action creation!\n");

    return action;
}

result_t _target_rpc_action_handler(struct action *action,
				    struct target_thread *thread,
				    struct probe *probe,
				    struct probepoint *probepoint,
				    handler_msg_t msg,int msg_detail,
				    void *handler_data) {
    struct soap soap;
    GHashTable *reftab;
    struct array_list *tll;
    int i;
    struct target_rpc_listener *tl = NULL;
    struct target *target = thread->target;
    int target_id;
    char urlbuf[SOAP_TAGLEN];
    struct vmi1__ActionEventT event;
    struct vmi1__ActionEventResponse aer;
    int rc;
    result_t retval = RESULT_SUCCESS;
    result_t retval2;

    if (target)
	target_id = target->id;
    else {
	verror("probe not associated with target!\n");
	return RESULT_ERROR;
    }

    pthread_mutex_lock(&target_rpc_mutex);

    tll = (struct array_list *)	\
	g_hash_table_lookup(target_listener_tab,(gpointer)(uintptr_t)target_id);

    if (tll) {
	soap_init(&soap);

	reftab = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);
	t_action_to_x_ActionEventT(&soap,action,thread,msg,msg_detail,reftab,
				   &event);
	g_hash_table_destroy(reftab);

	array_list_foreach(tll,i,tl) {
	    snprintf(urlbuf,sizeof(urlbuf),"http://%s:%d",tl->hostname,tl->port);

	    soap.connect_timeout = 4;
	    soap.send_timeout = 4;
	    soap.recv_timeout = 4;

	    rc = soap_call_vmi1__ActionEvent(&soap,urlbuf,NULL,&event,&aer);
	    if (rc != SOAP_OK) {
		if (soap.error == SOAP_EOF && soap.errnum == 0) {
		    vwarn("timeout notifying %s:%d; removing!",
			  tl->hostname,tl->port);
		}
		else {
		    verrorc("ActionEvent client call failure (%s:%d): ",
			    tl->hostname,tl->port);
		    soap_print_fault(&soap,stderr);
		}
		/* Remove the listener. */
		array_list_foreach_delete(tll,i);
		free(tl->hostname);
		free(tl);

		continue;
	    }

	    /*
	     * This is a bit crazy at the moment: if we have more than
	     * one listener, let them all fight for the handler outcome.
	     * Eventually, we have to restrict the outcome to only the
	     * RPC client that created the probe, or something.
	     */
	    retval2 = x_ResultT_to_t_result_t(&soap,aer.result);
	    if (retval2 > retval)
		retval = retval2;

	    soap_closesock(&soap);

	    vdebug(5,LA_XML,LF_RPC,
		   "notified listener %s (which returned %d)\n",urlbuf,retval2);
	}
	soap_destroy(&soap);
	soap_end(&soap);
	soap_done(&soap);
    }

    pthread_mutex_unlock(&target_rpc_mutex);

    return retval;
}

result_t _target_rpc_probe_handler(int type,struct probe *probe,
				   void *handler_data,struct probe *trigger) {
    struct soap soap;
    GHashTable *reftab;
    struct array_list *tll;
    int i;
    struct target_rpc_listener *tl = NULL;
    struct target *target = probe->target;
    int target_id;
    char urlbuf[SOAP_TAGLEN];
    struct vmi1__ProbeEventT event;
    struct vmi1__ProbeEventResponse per;
    int rc;
    result_t retval = RESULT_SUCCESS;
    result_t retval2;
    struct action *action;
    action_whence_t aw;

    if (target)
	target_id = target->id;
    else {
	verror("probe not associated with target!\n");
	return RESULT_ERROR;
    }

    pthread_mutex_lock(&target_rpc_mutex);

    tll = (struct array_list *)	\
	g_hash_table_lookup(target_listener_tab,(gpointer)(uintptr_t)target_id);

    if (tll) {
	soap_init(&soap);


	reftab = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);
	t_probe_to_x_ProbeEventT(&soap,probe,type,trigger,reftab,&event);
	g_hash_table_destroy(reftab);

	array_list_foreach(tll,i,tl) {
	    snprintf(urlbuf,sizeof(urlbuf),"http://%s:%d",tl->hostname,tl->port);

	    soap.connect_timeout = 4;
	    soap.send_timeout = 4;
	    soap.recv_timeout = 4;

	    rc = soap_call_vmi1__ProbeEvent(&soap,urlbuf,NULL,&event,&per);
	    if (rc != SOAP_OK) {
		if (soap.error == SOAP_EOF && soap.errnum == 0) {
		    vwarn("timeout notifying %s:%d; removing!",
			  tl->hostname,tl->port);
		}
		else {
		    verrorc("ProbeEvent client call failure (%s:%d): ",
			    tl->hostname,tl->port);
		    soap_print_fault(&soap,stderr);
		}
		/* Remove the listener. */
		array_list_foreach_delete(tll,i);
		free(tl->hostname);
		free(tl);

		continue;
	    }
	    /*
	     * This is a bit crazy at the moment: if we have more than
	     * one listener, let them all fight for the handler outcome.
	     * Eventually, we have to restrict the outcome to only the
	     * RPC client that created the probe, or something.
	     */
	    retval2 = x_ResultT_to_t_result_t(&soap,per.result);
	    if (retval2 > retval)
		retval = retval2;

	    soap_closesock(&soap);

	    vdebug(5,LA_XML,LF_RPC,
		   "notified listener %s (which returned %d -- %d actions)\n",
		   urlbuf,retval2,per.actionSpecs.__sizeactionSpec);

	    if (retval == RESULT_SUCCESS) {
		for (i = 0; i < per.actionSpecs.__sizeactionSpec; ++i) {
		    /*
		     * Create the new action.
		     */
		    action = \
			x_ActionSpecT_to_t_action(&soap,
						  &per.actionSpecs.actionSpec[i],
						  target);
		    if (!action) {
			verror("bad ActionSpec in probe response!\n");
			continue;
		    }

		    aw = x_ActionWhenceT_to_t_action_whence_t(&soap,per.actionSpecs.actionSpec[i].whence);
		    if (action_sched(probe,action,aw,1,
				     _target_rpc_action_handler,NULL)) {
			verror("could not schedule action!\n");
			action_free(action,1);
		    }
		}
	    }
	}
	soap_destroy(&soap);
	soap_end(&soap);
	soap_done(&soap);
    }

    pthread_mutex_unlock(&target_rpc_mutex);

    return retval;
};

result_t _target_rpc_probe_prehandler(struct probe *probe,void *handler_data,
				      struct probe *trigger) {
    return _target_rpc_probe_handler(0,probe,handler_data,trigger);
};


result_t _target_rpc_probe_posthandler(struct probe *probe,void *handler_data,
				       struct probe *trigger) {
    return _target_rpc_probe_handler(1,probe,handler_data,trigger);
};

int vmi1__ProbeSymbolSimple(struct soap *soap,
			    vmi1__TargetIdT tid,vmi1__ThreadIdT thid,
			    char *probeName,char *symbol,
			    struct vmi1__ProbeResponse *r) {
    struct target *t = NULL;
    struct probe *p;
    target_status_t status;
    GHashTable *reftab;

    target_rpc_init();
    pthread_mutex_lock(&target_rpc_mutex);

    if (!_target_rpc_lookup(tid,&t)) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Nonexistent target!",
				   "Specified target does not exist!");
    }

    PROXY_REQUEST_LOCKED(soap,tid,&target_rpc_mutex);

    if (thid == -1)
	thid = TID_GLOBAL;

    if ((status = target_status(t)) != TSTATUS_PAUSED) {
	if (target_pause(t)) {
	    pthread_mutex_unlock(&target_rpc_mutex);
	    return soap_receiver_fault(soap,"Could not pause target!",
				       "Could not pause target before adding probe!");
	}
    }
    vdebug(9,LA_XML,LF_RPC,"target status %d\n",status);

    p = probe_simple(t,thid,symbol,_target_rpc_probe_prehandler,
		     _target_rpc_probe_posthandler,NULL);

    probe_rename(p,probeName);

    if (status != TSTATUS_PAUSED) {
	if (target_resume(t)) {
	    pthread_mutex_unlock(&target_rpc_mutex);
	    return soap_receiver_fault(soap,"Could not resume target!",
				       "Could not resume target after adding probe!");
	}
    }

    reftab = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);
    r->probe = t_probe_to_x_ProbeT(soap,p,reftab,NULL);
    g_hash_table_destroy(reftab);

    pthread_mutex_unlock(&target_rpc_mutex);

    return SOAP_OK;
}

int vmi1__ProbeSymbol(struct soap *soap,
		      vmi1__TargetIdT tid,vmi1__ThreadIdT thid,
		      char *probeName,char *symbol,
		      vmi1__ProbepointStyleT *probepointStyle,
		      vmi1__ProbepointWhenceT *probepointWhence,
		      vmi1__ProbepointSizeT *probepointSize,
		      struct vmi1__ProbeResponse *r) {
    struct target *t = NULL;
    target_status_t status;
    struct bsymbol *bsymbol;
    GHashTable *reftab;
    struct probe *probe;
    probepoint_style_t ppstyle = PROBEPOINT_FASTEST;
    probepoint_whence_t ppwhence = PROBEPOINT_EXEC;
    probepoint_watchsize_t ppsize = PROBEPOINT_WAUTO;

    target_rpc_init();
    pthread_mutex_lock(&target_rpc_mutex);

    if (!_target_rpc_lookup(tid,&t)) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Nonexistent target!",
				   "Specified target does not exist!");
    }

    PROXY_REQUEST_LOCKED(soap,tid,&target_rpc_mutex);

    if (thid == -1)
	thid = TID_GLOBAL;

    if ((status = target_status(t)) != TSTATUS_PAUSED) {
	if (target_pause(t)) {
	    pthread_mutex_unlock(&target_rpc_mutex);
	    return soap_receiver_fault(soap,"Could not pause target!",
				       "Could not pause target before adding probe!");
	}
    }
    vdebug(9,LA_XML,LF_RPC,"target status %d\n",status);

    bsymbol = target_lookup_sym(t,symbol,NULL,NULL,SYMBOL_TYPE_NONE);

    if (!bsymbol) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Could not find symbol!",
				   "Could not find symbol!");
    }

    probe = probe_create(t,tid,NULL,probeName,_target_rpc_probe_prehandler,
			 _target_rpc_probe_posthandler,NULL,0,1);
    if (!probe) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Could not create probe!",
				   "Could not create probe!");
    }

    if (probepointStyle) 
	ppstyle = x_ProbepointStyleT_to_t_probepoint_style_t(soap,*probepointStyle);
    if (probepointWhence) 
	ppwhence = x_ProbepointWhenceT_to_t_probepoint_whence_t(soap,*probepointWhence);
    if (probepointSize) 
	ppsize = x_ProbepointSizeT_to_t_probepoint_watchsize_t(soap,*probepointSize);

    if (probe_register_symbol(probe,bsymbol,ppstyle,ppwhence,ppsize)) {
	probe_free(probe,1);
	bsymbol_release(bsymbol);
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Could not register probe!",
				   "Could not register probe!");
    }

    bsymbol_release(bsymbol);

    if (status != TSTATUS_PAUSED) {
	if (target_resume(t)) {
	    pthread_mutex_unlock(&target_rpc_mutex);
	    return soap_receiver_fault(soap,"Could not resume target!",
				       "Could not resume target after adding probe!");
	}
    }

    reftab = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);
    r->probe = t_probe_to_x_ProbeT(soap,probe,reftab,NULL);
    g_hash_table_destroy(reftab);

    pthread_mutex_unlock(&target_rpc_mutex);

    return SOAP_OK;
}

int vmi1__ProbeAddr(struct soap *soap,
		    vmi1__TargetIdT tid,vmi1__ThreadIdT thid,
		    char *probeName,vmi1__ADDR addr,
		    vmi1__ProbepointTypeT *probepointType,
		    vmi1__ProbepointStyleT *probepointStyle,
		    vmi1__ProbepointWhenceT *probepointWhence,
		    vmi1__ProbepointSizeT *probepointSize,
		    struct vmi1__ProbeResponse *r) {
    struct target *t = NULL;
    target_status_t status;
    GHashTable *reftab;
    struct probe *probe;
    probepoint_type_t pptype = PROBEPOINT_BREAK;
    probepoint_style_t ppstyle = PROBEPOINT_FASTEST;
    probepoint_whence_t ppwhence = PROBEPOINT_EXEC;
    probepoint_watchsize_t ppsize = PROBEPOINT_WAUTO;

    target_rpc_init();
    pthread_mutex_lock(&target_rpc_mutex);

    if (!_target_rpc_lookup(tid,&t)) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Nonexistent target!",
				   "Specified target does not exist!");
    }

    PROXY_REQUEST_LOCKED(soap,tid,&target_rpc_mutex);

    if (thid == -1)
	thid = TID_GLOBAL;

    if ((status = target_status(t)) != TSTATUS_PAUSED) {
	if (target_pause(t)) {
	    pthread_mutex_unlock(&target_rpc_mutex);
	    return soap_receiver_fault(soap,"Could not pause target!",
				       "Could not pause target before adding probe!");
	}
    }
    vdebug(9,LA_XML,LF_RPC,"target status %d\n",status);

    probe = probe_create(t,thid,NULL,probeName,_target_rpc_probe_prehandler,
			 _target_rpc_probe_posthandler,NULL,0,1);
    if (!probe) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Could not create probe!",
				   "Could not create probe!");
    }

    if (probepointType)
	pptype = x_ProbepointTypeT_to_t_probepoint_type_t(soap,*probepointType);
    if (probepointStyle) 
	ppstyle = x_ProbepointStyleT_to_t_probepoint_style_t(soap,*probepointStyle);
    if (probepointWhence) 
	ppwhence = x_ProbepointWhenceT_to_t_probepoint_whence_t(soap,*probepointWhence);
    if (probepointSize) 
	ppsize = x_ProbepointSizeT_to_t_probepoint_watchsize_t(soap,*probepointSize);

    if (!probe_register_addr(probe,addr,pptype,ppstyle,ppwhence,ppsize,NULL)) {
	probe_free(probe,1);
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Could not register probe!",
				   "Could not register probe!");
    }

    if (status != TSTATUS_PAUSED) {
	if (target_resume(t)) {
	    pthread_mutex_unlock(&target_rpc_mutex);
	    return soap_receiver_fault(soap,"Could not resume target!",
				       "Could not resume target after adding probe!");
	}
    }

    reftab = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);
    r->probe = t_probe_to_x_ProbeT(soap,probe,reftab,NULL);
    g_hash_table_destroy(reftab);

    pthread_mutex_unlock(&target_rpc_mutex);

    return SOAP_OK;
}

int vmi1__ProbeLine(struct soap *soap,
		    vmi1__TargetIdT tid,vmi1__ThreadIdT thid,
		    char *probeName,char *filename,int line,
		    vmi1__ProbepointStyleT *probepointStyle,
		    vmi1__ProbepointWhenceT *probepointWhence,
		    vmi1__ProbepointSizeT *probepointSize,
		    struct vmi1__ProbeResponse *r) {
    struct target *t = NULL;
    target_status_t status;
    GHashTable *reftab;
    struct probe *probe;
    probepoint_style_t ppstyle = PROBEPOINT_FASTEST;
    probepoint_whence_t ppwhence = PROBEPOINT_EXEC;
    probepoint_watchsize_t ppsize = PROBEPOINT_WAUTO;

    target_rpc_init();
    pthread_mutex_lock(&target_rpc_mutex);

    if (!_target_rpc_lookup(tid,&t)) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Nonexistent target!",
				   "Specified target does not exist!");
    }

    PROXY_REQUEST_LOCKED(soap,tid,&target_rpc_mutex);

    if (thid == -1)
	thid = TID_GLOBAL;

    if ((status = target_status(t)) != TSTATUS_PAUSED) {
	if (target_pause(t)) {
	    pthread_mutex_unlock(&target_rpc_mutex);
	    return soap_receiver_fault(soap,"Could not pause target!",
				       "Could not pause target before adding probe!");
	}
    }
    vdebug(9,LA_XML,LF_RPC,"target status %d\n",status);

    probe = probe_create(t,thid,NULL,probeName,_target_rpc_probe_prehandler,
			 _target_rpc_probe_posthandler,NULL,0,1);
    if (!probe) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Could not create probe!",
				   "Could not create probe!");
    }

    if (probepointStyle) 
	ppstyle = x_ProbepointStyleT_to_t_probepoint_style_t(soap,*probepointStyle);
    if (probepointWhence) 
	ppwhence = x_ProbepointWhenceT_to_t_probepoint_whence_t(soap,*probepointWhence);
    if (probepointSize) 
	ppsize = x_ProbepointSizeT_to_t_probepoint_watchsize_t(soap,*probepointSize);

    if (!probe_register_line(probe,filename,line,ppstyle,ppwhence,ppsize)) {
	probe_free(probe,1);
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Could not register probe!",
				   "Could not register probe!");
    }

    if (status != TSTATUS_PAUSED) {
	if (target_resume(t)) {
	    pthread_mutex_unlock(&target_rpc_mutex);
	    return soap_receiver_fault(soap,"Could not resume target!",
				       "Could not resume target after adding probe!");
	}
    }

    reftab = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);
    r->probe = t_probe_to_x_ProbeT(soap,probe,reftab,NULL);
    g_hash_table_destroy(reftab);

    pthread_mutex_unlock(&target_rpc_mutex);

    return SOAP_OK;
}

int vmi1__EnableProbe(struct soap *soap,
		      vmi1__TargetIdT tid,vmi1__ProbeIdT pid,
		      struct vmi1__NoneResponse *r) {
    struct target *t = NULL;
    target_status_t status;
    struct probe *probe;

    target_rpc_init();
    pthread_mutex_lock(&target_rpc_mutex);

    if (!_target_rpc_lookup(tid,&t)) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Nonexistent target!",
				   "Specified target does not exist!");
    }

    PROXY_REQUEST_LOCKED(soap,tid,&target_rpc_mutex);

    probe = target_lookup_probe(t,pid);
    if (!probe) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Could not find probe!",
				   "Could not find probe!");
    }

    if ((status = target_status(t)) != TSTATUS_PAUSED) {
	if (target_pause(t)) {
	    pthread_mutex_unlock(&target_rpc_mutex);
	    return soap_receiver_fault(soap,"Could not pause target!",
				       "Could not pause target before adding probe!");
	}
    }
    vdebug(9,LA_XML,LF_RPC,"target status %d\n",status);

    probe = target_lookup_probe(t,pid);
    if (!probe) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Could not find probe!",
				   "Could not find probe!");
    }

    if (probe_enable(probe)) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Could not enable probe!",
				   "Could not enable probe!");
    }

    if (status != TSTATUS_PAUSED) {
	if (target_resume(t)) {
	    pthread_mutex_unlock(&target_rpc_mutex);
	    return soap_receiver_fault(soap,"Could not resume target!",
				       "Could not resume target after adding probe!");
	}
    }

    pthread_mutex_unlock(&target_rpc_mutex);

    return SOAP_OK;
}

int vmi1__DisableProbe(struct soap *soap,
		       vmi1__TargetIdT tid,vmi1__ProbeIdT pid,
		       struct vmi1__NoneResponse *r) {
    struct target *t = NULL;
    target_status_t status;
    struct probe *probe;

    target_rpc_init();
    pthread_mutex_lock(&target_rpc_mutex);

    if (!_target_rpc_lookup(tid,&t)) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Nonexistent target!",
				   "Specified target does not exist!");
    }

    PROXY_REQUEST_LOCKED(soap,tid,&target_rpc_mutex);

    probe = target_lookup_probe(t,pid);
    if (!probe) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Could not find probe!",
				   "Could not find probe!");
    }

    if ((status = target_status(t)) != TSTATUS_PAUSED) {
	if (target_pause(t)) {
	    pthread_mutex_unlock(&target_rpc_mutex);
	    return soap_receiver_fault(soap,"Could not pause target!",
				       "Could not pause target before adding probe!");
	}
    }
    vdebug(9,LA_XML,LF_RPC,"target status %d\n",status);

    probe = target_lookup_probe(t,pid);
    if (!probe) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Could not find probe!",
				   "Could not find probe!");
    }

    if (probe_disable(probe)) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Could not disable probe!",
				   "Could not disable probe!");
    }

    if (status != TSTATUS_PAUSED) {
	if (target_resume(t)) {
	    pthread_mutex_unlock(&target_rpc_mutex);
	    return soap_receiver_fault(soap,"Could not resume target!",
				       "Could not resume target after adding probe!");
	}
    }

    pthread_mutex_unlock(&target_rpc_mutex);

    return SOAP_OK;
}

int vmi1__RemoveProbe(struct soap *soap,
		      vmi1__TargetIdT tid,vmi1__ProbeIdT pid,
		      struct vmi1__NoneResponse *r) {
    struct target *t = NULL;
    target_status_t status;
    struct probe *probe;

    target_rpc_init();
    pthread_mutex_lock(&target_rpc_mutex);

    if (!_target_rpc_lookup(tid,&t)) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Nonexistent target!",
				   "Specified target does not exist!");
    }

    PROXY_REQUEST_LOCKED(soap,tid,&target_rpc_mutex);

    probe = target_lookup_probe(t,pid);
    if (!probe) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Could not find probe!",
				   "Could not find probe!");
    }

    if ((status = target_status(t)) != TSTATUS_PAUSED) {
	if (target_pause(t)) {
	    pthread_mutex_unlock(&target_rpc_mutex);
	    return soap_receiver_fault(soap,"Could not pause target!",
				       "Could not pause target before adding probe!");
	}
    }
    vdebug(9,LA_XML,LF_RPC,"target status %d\n",status);

    probe = target_lookup_probe(t,pid);
    if (!probe) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Could not find probe!",
				   "Could not find probe!");
    }

    if (probe_free(probe,1)) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return soap_receiver_fault(soap,"Could not remove probe!",
				   "Could not remove probe!");
    }

    if (status != TSTATUS_PAUSED) {
	if (target_resume(t)) {
	    pthread_mutex_unlock(&target_rpc_mutex);
	    return soap_receiver_fault(soap,"Could not resume target!",
				       "Could not resume target after adding probe!");
	}
    }

    pthread_mutex_unlock(&target_rpc_mutex);

    return SOAP_OK;
}

int vmi1__RegisterTargetListener(struct soap *soap,
				 vmi1__TargetIdT tid,
				 char *host,int port,enum xsd__boolean ssl,
				 struct vmi1__NoneResponse *r) {
    struct target_rpc_listener *tl = calloc(1,sizeof(*tl));

    target_rpc_init();

    if (target_rpc_lookup_listener(tid,host,port)) 
	return soap_receiver_fault(soap,"Could not register listener!",
				   "Could not register listener: duplicate!");

    if (target_rpc_insert_listener(tid,host,port)) 
	return soap_receiver_fault(soap,"Could not register listener!",
				   "Could not register listener: insert()!");

    return SOAP_OK;
}

int vmi1__UnregisterTargetListener(struct soap *soap,
				   vmi1__TargetIdT tid,
				   char *host,int port,
				   struct vmi1__NoneResponse *r) {
    struct target_rpc_listener *tl = calloc(1,sizeof(*tl));

    target_rpc_init();

    if (!target_rpc_lookup_listener(tid,host,port)) 
	return soap_receiver_fault(soap,"Could not find listener!",
				   "Could not find listener!");

    if (!target_rpc_remove_listener(tid,host,port)) 
	return soap_receiver_fault(soap,"Could not remove listener!",
				   "Could not remove listener!");

    return SOAP_OK;
}
