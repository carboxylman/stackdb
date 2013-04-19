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

#include "generic_rpc.h"
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

    generic_rpc_init();
    debuginfo_rpc_init();
    monitor_init();
    target_init();

    generic_rpc_register_svctype(RPC_SVCTYPE_TARGET);

    monitor_register_objtype(MONITOR_OBJTYPE_TARGET,
			     &target_rpc_monitor_objtype_ops,&target_rpc_mutex);

    init_done = 1;

    pthread_mutex_unlock(&target_rpc_mutex);
}

int _target_rpc_remove_objid(int objid) {
    void *obj = NULL;
    struct monitor *monitor = NULL;
    int objtype;

    /*
     * Shutdown the monitor for each target, if the monitor owns
     * this target!  If it doesn't, the target is probably owned by
     * some other monitor!
     */
    if (!monitor_lookup_objid(objid,&objtype,&obj,&monitor)
	|| objtype != MONITOR_OBJTYPE_TARGET
	|| monitor->objid != objid) 
	return -1;

    monitor_shutdown(monitor);

    //target_close(target);
    //target_free(target);

    /* Unbind any existing target listeners. */
    generic_rpc_unbind_all_listeners_objid(RPC_SVCTYPE_TARGET,objid);

    return 0;
}

void target_rpc_fini(void) {
    void *objid;
    struct array_list *tlist;
    int i;

    pthread_mutex_lock(&target_rpc_mutex);

    if (!init_done) {
	pthread_mutex_unlock(&target_rpc_mutex);
	return;
    }

    pthread_mutex_unlock(&target_rpc_mutex);

    /* Nuke any existing targets. */
    tlist = 
	monitor_list_objids_by_objtype_lock_objtype(MONITOR_OBJTYPE_TARGET,1);

    array_list_foreach(tlist,i,objid) {
	_target_rpc_remove_objid((int)(uintptr_t)objid);
    }

    generic_rpc_unregister_svctype(RPC_SVCTYPE_TARGET);

    monitor_fini();
    target_fini();
    debuginfo_rpc_fini();
    generic_rpc_fini();

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
    return proxyreq_handle_request(soap,"target");
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

int vmi1__ListTargets(struct soap *soap,
		      void *_,
		      struct vmi1__TargetsResponse *r) {
    struct target *target;
    int i;
    GHashTable *reftab;
    struct array_list *tlist;

    tlist = monitor_list_objs_by_objtype_lock_objtype(MONITOR_OBJTYPE_TARGET,1);
    r->__size_target = tlist ? array_list_len(tlist) : 0;
    if (r->__size_target == 0) {
	r->target = NULL;
	if (tlist)
	    array_list_free(tlist);
	monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
	return SOAP_OK;
    }

    reftab = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);
    r->target = SOAP_CALLOC(soap,r->__size_target,sizeof(*r->target));
    array_list_foreach(tlist,i,target) 
	r->target[i] = t_target_to_x_TargetT(soap,target,reftab,NULL);

    g_hash_table_destroy(reftab);
    array_list_free(tlist);

    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);

    return SOAP_OK;
}

int vmi1__GetTarget(struct soap *soap,
		    vmi1__TargetIdT tid,
		    struct vmi1__TargetResponse *r) {
    struct target *t = NULL;
    GHashTable *reftab;

    if (!monitor_lookup_objid_lock_objtype(tid,MONITOR_OBJTYPE_TARGET,
					   (void **)&t,NULL)) 
	return soap_receiver_fault(soap,"Nonexistent target!",
				   "Specified target does not exist!");

    reftab = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);
    r->target = t_target_to_x_TargetT(soap,t,reftab,NULL);
    g_hash_table_destroy(reftab);

    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);

    return SOAP_OK;
}

int vmi1__InstantiateTarget(struct soap *soap,
			    struct vmi1__TargetSpecT *spec,
			    vmi1__ListenerIdT ownerListener,
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

    pr = soap->user;
    if (!pr) {
	return soap_receiver_fault(soap,
				   "Request needed splitting but not split!",
				   "Request needed splitting but not split!");
    }

    if (ownerListener > 0 
	&& !generic_rpc_lookup_listener_id(RPC_SVCTYPE_TARGET,ownerListener)) 
	return soap_receiver_fault(soap,"No such ownerListener!",
				   "No such ownerListener!");

    reftab = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);

    s = x_TargetSpecT_to_t_target_spec(soap,spec,reftab,NULL);
    if (!s) {
	g_hash_table_destroy(reftab);
	return soap_receiver_fault(soap,"Bad target spec!",
				   "Bad target spec!");
    }

    monitor_lock_objtype(MONITOR_OBJTYPE_TARGET);

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
	    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
	    return soap_receiver_fault(soap,"Could not create monitor!",
				       "Could not create monitor!");
	}

	/* Make sure to use our new evloop right away. */
	t = target_instantiate(s,monitor->evloop);
	if (!t) {
	    target_free_spec(s);
	    g_hash_table_destroy(reftab);
	    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
	    return soap_receiver_fault(soap,"Could not instantiate target!",
				       "Could not instantiate target!");
	}

	monitor_add_primary_obj(monitor,t->id,MONITOR_OBJTYPE_TARGET,t);

	if (target_open(t)) {
	    verror("could not open target!\n");
	    target_free(t);
	    target_free_spec(s);
	    g_hash_table_destroy(reftab);
	    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
	    return soap_receiver_fault(soap,"Could not open target!",
				       "Could not open target after"
				       " instantiating it successfully!");
	}

	proxyreq_attach_new_objid(pr,t->id,monitor);

	if (ownerListener > 0) {
	    if (generic_rpc_bind_listener_objid(RPC_SVCTYPE_TARGET,
						ownerListener,t->id,1))
		vwarn("could not bind target %d to listener %d!?\n",
		      t->id,ownerListener);
	}

	r->target = t_target_to_x_TargetT(soap,t,reftab,NULL);
	monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);

	return SOAP_OK;
    }
    else {
	/* Use our special servetarget program to fork the target. */
	if (target_spec_to_argv(s,MONITORED_TARGET_LAUNCHER,&largc,&largv)) {
	    target_free_spec(s);
	    g_hash_table_destroy(reftab);
	    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
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
	    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
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
	    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
	    return soap_receiver_fault(soap,"Could not spawn forked target!",
				       "Could not spawn forked target!");
	}

	proxyreq_attach_new_objid(pr,s->target_id,monitor);

	r->target = t_target_id_to_x_TargetT(soap,s->target_id,s,reftab,NULL);
	monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);

	return SOAP_OK;
    }
}

int vmi1__PauseTarget(struct soap *soap,
		      vmi1__TargetIdT tid,
		      struct vmi1__NoneResponse *r) {
    struct target *t = NULL;

    if (!monitor_lookup_objid_lock_objtype(tid,MONITOR_OBJTYPE_TARGET,
					   (void **)&t,NULL)) {
	return soap_receiver_fault(soap,"Nonexistent target!",
				   "Specified target does not exist!");
    }

    PROXY_REQUEST_LOCKED(soap,tid,&target_rpc_mutex);

    if (target_pause(t)) {
	monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
	return soap_receiver_fault(soap,"Could not pause target!",
				   "Could not pause target!");
    }

    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);

    return SOAP_OK;
}

int vmi1__ResumeTarget(struct soap *soap,
		       vmi1__TargetIdT tid,
		      struct vmi1__NoneResponse *r) {
    struct target *t = NULL;

    if (!monitor_lookup_objid_lock_objtype(tid,MONITOR_OBJTYPE_TARGET,
					   (void **)&t,NULL)) {
	return soap_receiver_fault(soap,"Nonexistent target!",
				   "Specified target does not exist!");
    }

    PROXY_REQUEST_LOCKED(soap,tid,&target_rpc_mutex);

    if (target_resume(t)) {
	monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
	return soap_receiver_fault(soap,"Could not resume target!",
				   "Could not resume target!");
    }

    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);

    return SOAP_OK;
}

int vmi1__CloseTarget(struct soap *soap,
		      vmi1__TargetIdT tid,enum xsd__boolean kill,int kill_sig,
		      struct vmi1__NoneResponse *r) {
    struct target *t = NULL;
    struct monitor *monitor;

    if (!monitor_lookup_objid_lock_objtype(tid,MONITOR_OBJTYPE_TARGET,
					   (void **)&t,&monitor)) {
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

    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);

    return SOAP_OK;
}

int vmi1__FinalizeTarget(struct soap *soap,
			 vmi1__TargetIdT tid,
			 struct vmi1__NoneResponse *r) {
    struct target *t = NULL;

    if (!monitor_lookup_objid_lock_objtype(tid,MONITOR_OBJTYPE_TARGET,
					   (void **)&t,NULL)) {
	return soap_receiver_fault(soap,"Nonexistent target!",
				   "Specified target does not exist!");
    }

    PROXY_REQUEST_LOCKED(soap,tid,&target_rpc_mutex);

    _target_rpc_remove_objid(t->id);

    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);

    return SOAP_OK;
}

int vmi1__PauseThread(struct soap *soap,
		      vmi1__TargetIdT tid,vmi1__ThreadIdT thid,
		      struct vmi1__NoneResponse *r) {
    struct target *t = NULL;

    if (!monitor_lookup_objid_lock_objtype(tid,MONITOR_OBJTYPE_TARGET,
					   (void **)&t,NULL)) {
	return soap_receiver_fault(soap,"Nonexistent target!",
				   "Specified target does not exist!");
    }

    PROXY_REQUEST_LOCKED(soap,tid,&target_rpc_mutex);

    if (target_pause_thread(t,thid,0)) {
	monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
	return soap_receiver_fault(soap,"Could not pause target thread!",
				   "Could not pause target thread!");
    }

    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);

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

    if (!monitor_lookup_objid_lock_objtype(tid,MONITOR_OBJTYPE_TARGET,
					   (void **)&t,NULL)) {
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
	monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
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

    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);

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

    if (!monitor_lookup_objid_lock_objtype(tid,MONITOR_OBJTYPE_TARGET,
					   (void **)&t,NULL)) {
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
	monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
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

    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);

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

    if (!monitor_lookup_objid_lock_objtype(tid,MONITOR_OBJTYPE_TARGET,
					   (void **)&t,NULL)) {
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
	monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
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

    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);

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

    if (!monitor_lookup_objid_lock_objtype(tid,MONITOR_OBJTYPE_TARGET,
					   (void **)&t,NULL)) {
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
	monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
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

    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);

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

    if (!monitor_lookup_objid_lock_objtype(tid,MONITOR_OBJTYPE_TARGET,
					   (void **)&t,NULL)) {
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
	monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
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

    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);

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

    if (!monitor_lookup_objid_lock_objtype(tid,MONITOR_OBJTYPE_TARGET,
					   (void **)&t,NULL)) {
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
	monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
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

    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);

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

struct target_rpc_listener_action_data {
    GHashTable *reftab;
    struct vmi1__ActionEventT event;
    struct vmi1__ActionEventNotificationResponse aer;
    result_t retval;
};

static int _action_generic_rpc_listener_notifier(struct generic_rpc_listener *l,
						 int is_owner,void *data) {
    result_t retval;
    struct target_rpc_listener_action_data *lad = \
	(struct target_rpc_listener_action_data *)data;
    int rc;

    /*
     * This stinks... but if we were the first 
     */

    rc = soap_call_vmi1__ActionEventNotification(&l->soap,l->url,NULL,
						 &lad->event,&lad->aer);
    if (rc != SOAP_OK) {
	if (l->soap.error == SOAP_EOF && l->soap.errnum == 0) {
	    vwarn("timeout notifying %s; removing!",l->url);
	}
	else {
	    verrorc("ActionEvent client call failure %s : ",
		    l->url);
	    soap_print_fault(&l->soap,stderr);
	}
	/* Let generic_rpc do this... */
	//soap_closesock(&lad->soap);
	return -1;
    }

    /*
     * (old) This is a bit crazy at the moment: if we have more than
     * one listener, let them all fight for the handler outcome.
     * Eventually, we have to restrict the outcome to only the
     * RPC client that created the probe, or something.
     *
     * Ok, now we know the owner; only take their response as
     * authoritative.
     */
    retval = x_ResultT_to_t_result_t(&l->soap,lad->aer.result);
    if (is_owner) {
	//if (retval > lad->retval)
	lad->retval = retval;

	vdebug(5,LA_XML,LF_RPC,
	       "notified authoritative listener %s (which returned %d)\n",
	       l->url,retval);
    }
    else {
	vdebug(5,LA_XML,LF_RPC,
	       "notified authoritative listener %s (which returned %d)\n",
	       l->url,retval);
    }

    if (!l->soap.keep_alive)
	soap_closesock(&l->soap);
    /*
     * Clean up temp/serialization data, but don't kill the sock if we
     * can avoid it.
     */
    soap_destroy(&l->soap);
    soap_end(&l->soap);
    //soap_done(&l->soap);

    return 0;
}

result_t _target_rpc_action_handler(struct action *action,
				    struct target_thread *thread,
				    struct probe *probe,
				    struct probepoint *probepoint,
				    handler_msg_t msg,int msg_detail,
				    void *handler_data) {
    struct target *target = thread->target;
    struct target_rpc_listener_action_data lad;
    struct soap encoder;

    if (!target) {
	verror("probe not associated with target!\n");
	return RESULT_ERROR;
    }

    /*
     * Don't go to any effort if we don't need to...
     */
    if (generic_rpc_count_listeners(RPC_SVCTYPE_TARGET,target->id) < 1)
	return RESULT_SUCCESS;

    memset(&lad,0,sizeof(lad));
    lad.retval = RESULT_SUCCESS;

    monitor_lock_objtype(MONITOR_OBJTYPE_TARGET);

    /*
     * We only want to build the gsoap data struct once -- so we have to
     * set up a temp soap struct to do that on.  We can't use the
     * per-listener soap struct yet cause we don't have it until we're
     * in the iterator above.
     */
    soap_init(&encoder);
    lad.reftab = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);

    t_action_to_x_ActionEventT(&encoder,action,thread,msg,msg_detail,
			       lad.reftab,&lad.event);

    generic_rpc_listener_notify_all(RPC_SVCTYPE_TARGET,target->id,
				    _action_generic_rpc_listener_notifier,
				    &lad);
    /*
     * Clean up temp/serialization data, but don't kill the sock if we
     * can avoid it.
     */
    g_hash_table_destroy(lad.reftab);
    soap_destroy(&encoder);
    soap_end(&encoder);
    soap_done(&encoder);

    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);

    return lad.retval;
}

struct target_rpc_listener_probe_data {
    GHashTable *reftab;
    struct target *target;
    struct probe *probe;
    struct vmi1__ProbeEventT event;
    struct vmi1__ProbeEventNotificationResponse per;
    result_t retval;
};

static int _probe_generic_rpc_listener_notifier(struct generic_rpc_listener *l,
						int is_owner,void *data) {
    result_t retval;
    struct target_rpc_listener_probe_data *lpd = \
	(struct target_rpc_listener_probe_data *)data;
    int rc;
    int i;
    struct action *action;
    action_whence_t aw;

    rc = soap_call_vmi1__ProbeEventNotification(&l->soap,l->url,NULL,
						&lpd->event,&lpd->per);
    if (rc != SOAP_OK) {
	if (l->soap.error == SOAP_EOF && l->soap.errnum == 0) {
	    vwarn("timeout notifying %s; removing!",l->url);
	}
	else {
	    verrorc("ProbeEvent client call failure %s : ",l->url);
	    soap_print_fault(&l->soap,stderr);
	}
	return -1;
    }

    retval = x_ResultT_to_t_result_t(&l->soap,lpd->per.result);
    if (is_owner) {
	//if (retval > lpd->retval)
	lpd->retval = retval;

	vdebug(5,LA_XML,LF_RPC,
	       "notified authoritative listener %s (which returned %d)\n",
	       l->url,retval);
    }
    else {
	vdebug(5,LA_XML,LF_RPC,
	       "notified nonauthoritative listener %s (which returned %d)\n",
	       l->url,retval);
    }

    if (!l->soap.keep_alive)
	soap_closesock(&l->soap);

    if (is_owner && retval == RESULT_SUCCESS) {
	for (i = 0; i < lpd->per.actionSpecs.__sizeactionSpec; ++i) {
	    /*
	     * Create the new action.
	     */
	    action =						\
		x_ActionSpecT_to_t_action(&l->soap,
					  &lpd->per.actionSpecs.actionSpec[i],
					  lpd->target);
	    if (!action) {
		verror("bad ActionSpec in probe response!\n");
		continue;
	    }
	    
	    aw = x_ActionWhenceT_to_t_action_whence_t(&l->soap,lpd->per.actionSpecs.actionSpec[i].whence);
	    if (action_sched(lpd->probe,action,aw,1,
			     _target_rpc_action_handler,NULL)) {
		verror("could not schedule action!\n");
		action_free(action,1);
	    }
	}
    }
    else if (lpd->per.actionSpecs.__sizeactionSpec > 0) {
	vwarn("nonauthoritative listener %s tried to send %d actions!\n",
	      l->url,lpd->per.actionSpecs.__sizeactionSpec);
    }

    soap_destroy(&l->soap);
    soap_end(&l->soap);
    //soap_done(&l->soap);

    return 0;
}

result_t _target_rpc_probe_handler(int type,struct probe *probe,
				   void *handler_data,struct probe *trigger) {
    struct target *target = probe->target;
    struct target_rpc_listener_probe_data lpd;
    struct soap encoder;

    if (!target) {
	verror("probe not associated with target!\n");
	return RESULT_ERROR;
    }

    /*
     * Don't go to any effort if we don't need to...
     */
    if (generic_rpc_count_listeners(RPC_SVCTYPE_TARGET,target->id) < 1)
	return RESULT_SUCCESS;

    memset(&lpd,0,sizeof(lpd));
    lpd.retval = RESULT_SUCCESS;

    monitor_lock_objtype(MONITOR_OBJTYPE_TARGET);

    /*
     * We only want to build the gsoap data struct once -- so we have to
     * set up a temp soap struct to do that on.  We can't use the
     * per-listener soap struct yet cause we don't have it until we're
     * in the iterator above.
     */
    soap_init(&encoder);

    lpd.reftab = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);
    lpd.target = target;
    lpd.probe = probe;
    t_probe_to_x_ProbeEventT(&encoder,probe,type,trigger,lpd.reftab,&lpd.event);

    generic_rpc_listener_notify_all(RPC_SVCTYPE_TARGET,target->id,
				    _probe_generic_rpc_listener_notifier,
				    &lpd);

    g_hash_table_destroy(lpd.reftab);
    soap_destroy(&encoder);
    soap_end(&encoder);
    soap_done(&encoder);

    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);

    return lpd.retval;
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
    int did_pause = 0;

    if (!monitor_lookup_objid_lock_objtype(tid,MONITOR_OBJTYPE_TARGET,
					   (void **)&t,NULL)) {
	return soap_receiver_fault(soap,"Nonexistent target!",
				   "Specified target does not exist!");
    }

    PROXY_REQUEST_LOCKED(soap,tid,&target_rpc_mutex);

    if (thid == -1)
	thid = TID_GLOBAL;

    if ((status = target_status(t)) != TSTATUS_PAUSED) {
	if (target_pause(t)) {
	    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
	    return soap_receiver_fault(soap,"Could not pause target!",
				       "Could not pause target before adding probe!");
	}
	did_pause = 1;
    }

    vdebug(9,LA_XML,LF_RPC,"target status %d\n",status);

    p = probe_simple(t,thid,symbol,_target_rpc_probe_prehandler,
		     _target_rpc_probe_posthandler,NULL);
    if (!p) {
	verror("could not add a probe on symbol '%s' in target %d thread %d\n",
	       symbol,tid,thid);
	if (did_pause)
	    target_resume(t);
	monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
	return soap_receiver_fault(soap,"Could not add probe!",
				   "Could not add probe!");
    }

    probe_rename(p,probeName);

    if (did_pause) {
	if (target_resume(t)) {
	    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
	    return soap_receiver_fault(soap,"Could not resume target, but probe added successfully!",
				       "Could not resume target after adding probe!");
	}
    }

    reftab = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);
    r->probe = t_probe_to_x_ProbeT(soap,p,reftab,NULL);
    g_hash_table_destroy(reftab);

    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);

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

    if (!monitor_lookup_objid_lock_objtype(tid,MONITOR_OBJTYPE_TARGET,
					   (void **)&t,NULL)) {
	return soap_receiver_fault(soap,"Nonexistent target!",
				   "Specified target does not exist!");
    }

    PROXY_REQUEST_LOCKED(soap,tid,&target_rpc_mutex);

    if (thid == -1)
	thid = TID_GLOBAL;

    if ((status = target_status(t)) != TSTATUS_PAUSED) {
	if (target_pause(t)) {
	    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
	    return soap_receiver_fault(soap,"Could not pause target!",
				       "Could not pause target before adding probe!");
	}
    }
    vdebug(9,LA_XML,LF_RPC,"target status %d\n",status);

    bsymbol = target_lookup_sym(t,symbol,NULL,NULL,SYMBOL_TYPE_NONE);

    if (!bsymbol) {
	monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
	return soap_receiver_fault(soap,"Could not find symbol!",
				   "Could not find symbol!");
    }

    probe = probe_create(t,tid,NULL,probeName,_target_rpc_probe_prehandler,
			 _target_rpc_probe_posthandler,NULL,0,1);
    if (!probe) {
	monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
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
	monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
	return soap_receiver_fault(soap,"Could not register probe!",
				   "Could not register probe!");
    }

    bsymbol_release(bsymbol);

    if (status != TSTATUS_PAUSED) {
	if (target_resume(t)) {
	    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
	    return soap_receiver_fault(soap,"Could not resume target!",
				       "Could not resume target after adding probe!");
	}
    }

    reftab = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);
    r->probe = t_probe_to_x_ProbeT(soap,probe,reftab,NULL);
    g_hash_table_destroy(reftab);

    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);

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

    if (!monitor_lookup_objid_lock_objtype(tid,MONITOR_OBJTYPE_TARGET,
					   (void **)&t,NULL)) {
	return soap_receiver_fault(soap,"Nonexistent target!",
				   "Specified target does not exist!");
    }

    PROXY_REQUEST_LOCKED(soap,tid,&target_rpc_mutex);

    if (thid == -1)
	thid = TID_GLOBAL;

    if ((status = target_status(t)) != TSTATUS_PAUSED) {
	if (target_pause(t)) {
	    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
	    return soap_receiver_fault(soap,"Could not pause target!",
				       "Could not pause target before adding probe!");
	}
    }
    vdebug(9,LA_XML,LF_RPC,"target status %d\n",status);

    probe = probe_create(t,thid,NULL,probeName,_target_rpc_probe_prehandler,
			 _target_rpc_probe_posthandler,NULL,0,1);
    if (!probe) {
	monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
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
	monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
	return soap_receiver_fault(soap,"Could not register probe!",
				   "Could not register probe!");
    }

    if (status != TSTATUS_PAUSED) {
	if (target_resume(t)) {
	    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
	    return soap_receiver_fault(soap,"Could not resume target!",
				       "Could not resume target after adding probe!");
	}
    }

    reftab = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);
    r->probe = t_probe_to_x_ProbeT(soap,probe,reftab,NULL);
    g_hash_table_destroy(reftab);

    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);

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

    if (!monitor_lookup_objid_lock_objtype(tid,MONITOR_OBJTYPE_TARGET,
					   (void **)&t,NULL)) {
	return soap_receiver_fault(soap,"Nonexistent target!",
				   "Specified target does not exist!");
    }

    PROXY_REQUEST_LOCKED(soap,tid,&target_rpc_mutex);

    if (thid == -1)
	thid = TID_GLOBAL;

    if ((status = target_status(t)) != TSTATUS_PAUSED) {
	if (target_pause(t)) {
	    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
	    return soap_receiver_fault(soap,"Could not pause target!",
				       "Could not pause target before adding probe!");
	}
    }
    vdebug(9,LA_XML,LF_RPC,"target status %d\n",status);

    probe = probe_create(t,thid,NULL,probeName,_target_rpc_probe_prehandler,
			 _target_rpc_probe_posthandler,NULL,0,1);
    if (!probe) {
	monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
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
	monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
	return soap_receiver_fault(soap,"Could not register probe!",
				   "Could not register probe!");
    }

    if (status != TSTATUS_PAUSED) {
	if (target_resume(t)) {
	    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
	    return soap_receiver_fault(soap,"Could not resume target!",
				       "Could not resume target after adding probe!");
	}
    }

    reftab = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);
    r->probe = t_probe_to_x_ProbeT(soap,probe,reftab,NULL);
    g_hash_table_destroy(reftab);

    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);

    return SOAP_OK;
}

int vmi1__EnableProbe(struct soap *soap,
		      vmi1__TargetIdT tid,vmi1__ProbeIdT pid,
		      struct vmi1__NoneResponse *r) {
    struct target *t = NULL;
    target_status_t status;
    struct probe *probe;

    if (!monitor_lookup_objid_lock_objtype(tid,MONITOR_OBJTYPE_TARGET,
					   (void **)&t,NULL)) {
	return soap_receiver_fault(soap,"Nonexistent target!",
				   "Specified target does not exist!");
    }

    PROXY_REQUEST_LOCKED(soap,tid,&target_rpc_mutex);

    probe = target_lookup_probe(t,pid);
    if (!probe) {
	monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
	return soap_receiver_fault(soap,"Could not find probe!",
				   "Could not find probe!");
    }

    if ((status = target_status(t)) != TSTATUS_PAUSED) {
	if (target_pause(t)) {
	    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
	    return soap_receiver_fault(soap,"Could not pause target!",
				       "Could not pause target before adding probe!");
	}
    }
    vdebug(9,LA_XML,LF_RPC,"target status %d\n",status);

    probe = target_lookup_probe(t,pid);
    if (!probe) {
	monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
	return soap_receiver_fault(soap,"Could not find probe!",
				   "Could not find probe!");
    }

    if (probe_enable(probe)) {
	monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
	return soap_receiver_fault(soap,"Could not enable probe!",
				   "Could not enable probe!");
    }

    if (status != TSTATUS_PAUSED) {
	if (target_resume(t)) {
	    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
	    return soap_receiver_fault(soap,"Could not resume target!",
				       "Could not resume target after adding probe!");
	}
    }

    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);

    return SOAP_OK;
}

int vmi1__DisableProbe(struct soap *soap,
		       vmi1__TargetIdT tid,vmi1__ProbeIdT pid,
		       struct vmi1__NoneResponse *r) {
    struct target *t = NULL;
    target_status_t status;
    struct probe *probe;

    if (!monitor_lookup_objid_lock_objtype(tid,MONITOR_OBJTYPE_TARGET,
					   (void **)&t,NULL)) {
	return soap_receiver_fault(soap,"Nonexistent target!",
				   "Specified target does not exist!");
    }

    PROXY_REQUEST_LOCKED(soap,tid,&target_rpc_mutex);

    probe = target_lookup_probe(t,pid);
    if (!probe) {
	monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
	return soap_receiver_fault(soap,"Could not find probe!",
				   "Could not find probe!");
    }

    if ((status = target_status(t)) != TSTATUS_PAUSED) {
	if (target_pause(t)) {
	    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
	    return soap_receiver_fault(soap,"Could not pause target!",
				       "Could not pause target before adding probe!");
	}
    }
    vdebug(9,LA_XML,LF_RPC,"target status %d\n",status);

    probe = target_lookup_probe(t,pid);
    if (!probe) {
	monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
	return soap_receiver_fault(soap,"Could not find probe!",
				   "Could not find probe!");
    }

    if (probe_disable(probe)) {
	monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
	return soap_receiver_fault(soap,"Could not disable probe!",
				   "Could not disable probe!");
    }

    if (status != TSTATUS_PAUSED) {
	if (target_resume(t)) {
	    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
	    return soap_receiver_fault(soap,"Could not resume target!",
				       "Could not resume target after adding probe!");
	}
    }

    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);

    return SOAP_OK;
}

int vmi1__RemoveProbe(struct soap *soap,
		      vmi1__TargetIdT tid,vmi1__ProbeIdT pid,
		      struct vmi1__NoneResponse *r) {
    struct target *t = NULL;
    target_status_t status;
    struct probe *probe;

    if (!monitor_lookup_objid_lock_objtype(tid,MONITOR_OBJTYPE_TARGET,
					   (void **)&t,NULL)) {
	return soap_receiver_fault(soap,"Nonexistent target!",
				   "Specified target does not exist!");
    }

    PROXY_REQUEST_LOCKED(soap,tid,&target_rpc_mutex);

    probe = target_lookup_probe(t,pid);
    if (!probe) {
	monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
	return soap_receiver_fault(soap,"Could not find probe!",
				   "Could not find probe!");
    }

    if ((status = target_status(t)) != TSTATUS_PAUSED) {
	if (target_pause(t)) {
	    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
	    return soap_receiver_fault(soap,"Could not pause target!",
				       "Could not pause target before adding probe!");
	}
    }
    vdebug(9,LA_XML,LF_RPC,"target status %d\n",status);

    probe = target_lookup_probe(t,pid);
    if (!probe) {
	monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
	return soap_receiver_fault(soap,"Could not find probe!",
				   "Could not find probe!");
    }

    if (probe_free(probe,1)) {
	monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
	return soap_receiver_fault(soap,"Could not remove probe!",
				   "Could not remove probe!");
    }

    if (status != TSTATUS_PAUSED) {
	if (target_resume(t)) {
	    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
	    return soap_receiver_fault(soap,"Could not resume target!",
				       "Could not resume target after adding probe!");
	}
    }

    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);

    return SOAP_OK;
}

int vmi1__RegisterTargetListener(struct soap *soap,
				 char *host,int port,enum xsd__boolean ssl,
				 struct vmi1__ListenerIdResponse *r) {
    int listener_id;
    char urlbuf[SOAP_TAGLEN];

    snprintf(urlbuf,sizeof(urlbuf),
	     "http://%s:%d/vmi/1/targetListener",host,port);

    listener_id = generic_rpc_insert_listener(RPC_SVCTYPE_TARGET,urlbuf);
    if (listener_id < 0)
	return soap_receiver_fault(soap,"Could not register listener!",
				   "Could not register listener!");

    r->listenerId = listener_id;

    return SOAP_OK;
}

int vmi1__RegisterTargetListenerURL(struct soap *soap,
				    char *url,enum xsd__boolean ssl,
				    struct vmi1__ListenerIdResponse *r) {
    int listener_id;

    if ((listener_id = generic_rpc_insert_listener(RPC_SVCTYPE_TARGET,url)) < 0)
	return soap_receiver_fault(soap,"Could not register listener!",
				   "Could not register listener!");

    r->listenerId = listener_id;

    return SOAP_OK;
}

int vmi1__UnregisterTargetListener(struct soap *soap,
				   vmi1__ListenerIdT listenerId,
				   struct vmi1__NoneResponse *r) {
    if (generic_rpc_remove_listener(RPC_SVCTYPE_TARGET,listenerId))
	return soap_receiver_fault(soap,"Could not remove listener!",
				   "Could not remove listener!");

    return SOAP_OK;
}

int vmi1__TargetBindListener(struct soap *soap,
			     vmi1__TargetIdT tid,vmi1__ListenerIdT listenerId,
			     struct vmi1__NoneResponse *r) {
    if (generic_rpc_bind_listener_objid(RPC_SVCTYPE_TARGET,listenerId,tid,0)) 
	return soap_receiver_fault(soap,"Could not bind to target!",
				   "Could not bind to target!");

    return SOAP_OK;
}

int vmi1__TargetUnbindListener(struct soap *soap,
			       vmi1__TargetIdT tid,vmi1__ListenerIdT listenerId,
			       struct vmi1__NoneResponse *r) {
    if (generic_rpc_unbind_listener_objid(RPC_SVCTYPE_TARGET,listenerId,tid)) 
	return soap_receiver_fault(soap,"Could not unbind from target!",
				   "Could not unbind from target!");

    return SOAP_OK;
}
