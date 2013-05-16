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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

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

static int target_rpc_monitor_close(struct monitor *monitor,
				    void *obj,void *objstate,
				    int kill,int kill_sig) {
    struct target *target = (struct target *)obj;
    int retval;

    if (!obj)
	return 0;

    if ((retval = target_close(target)) != TSTATUS_DONE) {
	verror("could not close target (error %d)!\n",retval);
    }

    return 0;
}

static int target_rpc_monitor_fini(struct monitor *monitor,
				   void *obj,void *objstate) {
    struct target *target = (struct target *)obj;

    if (!obj)
	return 0;

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

static int target_rpc_monitor_event(monitor_event_t event,int data,void *obj) {
    /* XXX: fill in! */
    return 0;
}

struct target_rpc_listener_target_data {
    GHashTable *reftab;
    struct vmi1__TargetEventT event;
    struct vmi1__TargetEventNotificationResponse ter;
    result_t retval;
};

static int _target_generic_rpc_listener_notifier(struct generic_rpc_listener *l,
						 int is_owner,void *data) {
    result_t retval;
    struct target_rpc_listener_target_data *ltd = \
	(struct target_rpc_listener_target_data *)data;
    int rc;

    /*
     * This stinks... but if we were the first 
     */

    rc = soap_call_vmi1__TargetEventNotification(&l->soap,l->url,NULL,
						 &ltd->event,&ltd->ter);
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
	//soap_closesock(&ltd->soap);
	return -1;
    }

    /*
     * Take only the owner's response as authoritative.
     */
    retval = x_ResultT_to_t_result_t(&l->soap,ltd->ter.result);
    if (is_owner) {
	//if (retval > ltd->retval)
	ltd->retval = retval;

	vdebug(5,LA_XML,LF_RPC,
	       "notified authoritative listener %s (which returned %d)\n",
	       l->url,retval);
    }
    else {
	vdebug(5,LA_XML,LF_RPC,
	       "notified non-authoritative listener %s (which returned %d)\n",
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

enum _vmi1__targetEventType 
t_target_state_change_type_t_to_x_targetEventType(target_state_change_type_t chtype) {
    switch (chtype) {
    case TARGET_STATE_CHANGE_EXITED:
	return _vmi1__targetEventType__exited;
    case TARGET_STATE_CHANGE_EXITING:
	return _vmi1__targetEventType__exiting;
    case TARGET_STATE_CHANGE_ERROR:
	return _vmi1__targetEventType__error;
    case TARGET_STATE_CHANGE_THREAD_CREATED:
	return _vmi1__targetEventType__threadCreated;
    case TARGET_STATE_CHANGE_THREAD_EXITED:
	return _vmi1__targetEventType__threadExited;
    case TARGET_STATE_CHANGE_THREAD_EXITING:
	return _vmi1__targetEventType__threadExiting;
    case TARGET_STATE_CHANGE_REGION_NEW:
	return _vmi1__targetEventType__regionNew;
    case TARGET_STATE_CHANGE_REGION_MOD:
	return _vmi1__targetEventType__regionMod;
    case TARGET_STATE_CHANGE_REGION_DEL:
	return _vmi1__targetEventType__regionDel;
    case TARGET_STATE_CHANGE_RANGE_NEW:
	return _vmi1__targetEventType__rangeNew;
    case TARGET_STATE_CHANGE_RANGE_MOD:
	return _vmi1__targetEventType__rangeMod;
    case TARGET_STATE_CHANGE_RANGE_DEL:
	return _vmi1__targetEventType__rangeDel;

    default:
	verror("BUG: bad target_state_change_type_t %d; returning UINT_MAX\n",
	       chtype);
	return UINT_MAX;
    }
}

static int target_rpc_monitor_notify(void *obj) {
    struct target *target = (struct target *)obj;
    struct target_rpc_listener_target_data ltd;
    struct soap encoder;
    struct target_state_change *change;
    int i;

    if (!obj)
	return 0;

    if (array_list_len(target->state_changes) < 1) 
	return 0;

    /*
     * Don't go to any effort if we don't need to...
     */
    if (generic_rpc_count_listeners(RPC_SVCTYPE_TARGET,target->id) < 1)
	return RESULT_SUCCESS;

    memset(&ltd,0,sizeof(ltd));
    ltd.retval = RESULT_SUCCESS;

    /*
     * NB: cannot call monitor_lock_objtype(MONITOR_OBJTYPE_TARGET)
     * since our caller might hold &monitor_mutex already!
     */
    pthread_mutex_lock(&target_rpc_mutex);

    /*
     * We only want to build the gsoap data struct once -- so we have to
     * set up a temp soap struct to do that on.  We can't use the
     * per-listener soap struct yet cause we don't have it until we're
     * in the iterator above.
     */
    soap_init(&encoder);
    ltd.reftab = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);

    array_list_foreach(target->state_changes,i,change) {
	ltd.event.targetEventType = 
	    t_target_state_change_type_t_to_x_targetEventType(change->chtype);
	if (ltd.event.targetEventType == UINT_MAX)
	    continue;

	ltd.event.tid = target->id;
	ltd.event.thid = change->tid;
	ltd.event.targetStatus = 
	    t_target_status_t_to_x_TargetStatusT(&encoder,target->status,
						 ltd.reftab,NULL);
	ltd.event.eventCode = &change->code;
	ltd.event.eventData = &change->data;
	ltd.event.eventStartAddr = &change->start;
	ltd.event.eventEndAddr = &change->end;
	ltd.event.eventMsg = change->msg;

	generic_rpc_listener_notify_all(RPC_SVCTYPE_TARGET,target->id,
					_target_generic_rpc_listener_notifier,
					&ltd);
    }

    /*
     * Clean up temp/serialization data, but don't kill the sock if we
     * can avoid it.
     */
    g_hash_table_destroy(ltd.reftab);
    soap_destroy(&encoder);
    soap_end(&encoder);
    soap_done(&encoder);

    pthread_mutex_unlock(&target_rpc_mutex);

    /*
     * XXX: maybe shouldn't do this here...
     */
    target_clear_state_changes(target);

    return 0;
}

struct monitor_objtype_ops target_rpc_monitor_objtype_ops = {
    .evloop_attach = target_rpc_monitor_evloop_attach,
    .evloop_detach = target_rpc_monitor_evloop_detach,
    .close = target_rpc_monitor_close,
    .fini = target_rpc_monitor_fini,
    .evloop_is_attached = target_rpc_monitor_evloop_is_attached,
    .child_recv_msg = target_rpc_monitor_child_recv_msg,
    .recv_msg = target_rpc_monitor_recv_msg,
    .error = target_rpc_monitor_error,
    .fatal_error = target_rpc_monitor_fatal_error,
    .notify = target_rpc_monitor_notify,
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

    monitor_init();
    target_init();
    generic_rpc_init();
    debuginfo_rpc_init();

    generic_rpc_register_svctype(RPC_SVCTYPE_TARGET);

    monitor_register_objtype(MONITOR_OBJTYPE_TARGET,
			     &target_rpc_monitor_objtype_ops,&target_rpc_mutex);

    init_done = 1;

    pthread_mutex_unlock(&target_rpc_mutex);
}

void target_rpc_fini(void) {
    void *objid;
    struct array_list *tlist;
    int i;
    struct target *t = NULL;
    struct monitor *m = NULL;

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
	t = NULL;
	m = NULL;
	if (!monitor_lookup_objid((int)(uintptr_t)objid,NULL,(void **)&t,&m)
	    || !t) 
	    continue;
	monitor_del_objid(m,(int)(uintptr_t)objid);
	generic_rpc_unbind_all_listeners_objid(RPC_SVCTYPE_TARGET,
					       (int)(uintptr_t)objid);
    }

    generic_rpc_unregister_svctype(RPC_SVCTYPE_TARGET);

    debuginfo_rpc_fini();
    generic_rpc_fini();
    target_fini();
    monitor_fini();

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

int vmi1__GetTargetLogs(struct soap *soap,
			vmi1__TargetIdT tid,int maxSize,
			struct vmi1__TargetLogsResponse *r) {
    struct target *t = NULL;
    struct monitor *m = NULL;
    int rc;
    struct stat statbuf;
    int fd;
    int sz;

    if (!monitor_lookup_objid_lock_objtype(tid,MONITOR_OBJTYPE_TARGET,
					   (void **)&t,&m)) {
	return soap_receiver_fault(soap,"Nonexistent target!",
				   "Specified target does not exist!");
    }

    /* NB: don't lock monitor just to read its filenames.  Those aren't
     * deallocated until monitor_destroy() anyway.
     *
     * Also, we *do* record the i/o of monitored_target if we forked a
     * process-monitored target, but right now, we don't try to capture
     * its logfiles, because we proxy the RPC to the child.
     */

    PROXY_REQUEST_LOCKED(soap,tid,&target_rpc_mutex);

    if (t->spec->outfile) {
	memset(&statbuf,0,sizeof(statbuf));
	if (stat(t->spec->outfile,&statbuf)) 
	    verror("could not stat target stdout logfile %s: %s\n",
		   t->spec->outfile,strerror(errno));
	else if ((fd = open(t->spec->outfile,O_RDONLY)) < 0) {
	    verror("could not open target stdout logfile %s: %s\n",
		   t->spec->outfile,strerror(errno));
	}
	else {
	    r->stdoutLog = SOAP_CALLOC(soap,1,sizeof(*r->stdoutLog));
	    if (statbuf.st_size > 0) {
		sz = statbuf.st_size;
		if (maxSize > 0 && maxSize < statbuf.st_size)
		    sz = maxSize;
		r->stdoutLog->__ptr = SOAP_CALLOC(soap,1,sz);
		r->stdoutLog->__size = sz;

		/* Read it all */
		lseek(fd,statbuf.st_size - sz,SEEK_SET);
		rc = 0;
		__SAFE_IO(read,"read",fd,r->stdoutLog->__ptr,sz,rc);
		if (errno) {
		    vwarn("only read %d of %d bytes for stdoutLog: %s\n",
			  rc,sz,strerror(errno));
		}
		if (rc != sz) {
		    vwarn("only read %d of %d bytes for stdoutLog (no error)\n",
			  rc,sz);
		    r->stdoutLog->__size = rc;
		}
	    }
	    close(fd);
	}
    }

    if (t->spec->errfile) {
	memset(&statbuf,0,sizeof(statbuf));
	if (stat(t->spec->errfile,&statbuf)) 
	    verror("could not stat target stderr logfile %s: %s\n",
		   t->spec->errfile,strerror(errno));
	else if ((fd = open(t->spec->errfile,O_RDONLY)) < 0) {
	    verror("could not open target stderr logfile %s: %s\n",
		   t->spec->errfile,strerror(errno));
	}
	else {
	    r->stderrLog = SOAP_CALLOC(soap,1,sizeof(*r->stderrLog));
	    if (statbuf.st_size > 0) {
		sz = statbuf.st_size;
		if (maxSize > 0 && maxSize < statbuf.st_size)
		    sz = maxSize;
		r->stderrLog->__ptr = SOAP_CALLOC(soap,1,sz);
		r->stderrLog->__size = sz;

		/* Read it all */
		lseek(fd,statbuf.st_size - sz,SEEK_SET);
		rc = 0;
		__SAFE_IO(read,"read",fd,r->stderrLog->__ptr,sz,rc);
		if (rc != sz && errno) {
		    vwarn("only read %d of %d bytes for stderrLog: %s\n",
			  rc,sz,strerror(errno));
		}
		else if (rc != sz) {
		    vwarn("only read %d of %d bytes for stderrLog (no error)\n",
			  rc,sz);
		    r->stderrLog->__size = rc;
		}
	    }
	    close(fd);
	}
    }

    /* XXX: don't do this for now; later, fix GetTargetLogs to not be
     * proxied and just do it all from the server.  BUT, right now, the
     * server doesn't have access to the target->spec->logfile names, so
     * it can't try to read them.  If we were saving monitored object
     * metadata better, this would be easier...
     */

    /*
    if (m->type == MONITOR_TYPE_PROCESS
	&& m->p.stdout_logfile) {
	memset(&statbuf,0,sizeof(statbuf));
	if (stat(m->p.stdout_logfile,&statbuf)) 
	    verror("could not stat dedicated monitor stdout logfile %s: %s\n",
		   m->p.stdout_logfile,strerror(errno));
	else if ((fd = open(m->p.stdout_logfile,O_RDONLY)) < 0) {
	    verror("could not open dedicated monitor stdout logfile %s: %s\n",
		   m->p.stdout_logfile,strerror(errno));
	}
	else {
	    r->dedicatedMonitorStdoutLog = 
		SOAP_CALLOC(soap,1,sizeof(*r->dedicatedMonitorStdoutLog));
	    if (statbuf.st_size > 0) {
		sz = statbuf.st_size;
		if (maxSize > 0 && maxSize < statbuf.st_size)
		    sz = maxSize;
		r->dedicatedMonitorStdoutLog->__ptr = SOAP_CALLOC(soap,1,sz);
		r->dedicatedMonitorStdoutLog->__size = sz;

		lseek(fd,statbuf.st_size - sz,SEEK_SET);
		rc = 0;
		__SAFE_IO(read,"read",fd,r->dedicatedMonitorStdoutLog->__ptr,sz,rc);
		if (errno) {
		    vwarn("only read %d of %d bytes for"
			  " dedicatedMonitorStdoutLog: %s\n",
			  rc,sz,strerror(errno));
		}
		if (rc != sz) {
		    vwarn("only read %d of %d bytes for"
			  " dedicatedMonitorStdoutLog (no error)\n",
			  rc,sz);
		    r->dedicatedMonitorStdoutLog->__size = rc;
		}
	    }
	    close(fd);
	}
    }

    if (m->type == MONITOR_TYPE_PROCESS
	&& m->p.stderr_logfile) {
	memset(&statbuf,0,sizeof(statbuf));
	if (stat(m->p.stderr_logfile,&statbuf)) 
	    verror("could not stat dedicated monitor stderr logfile %s: %s\n",
		   m->p.stderr_logfile,strerror(errno));
	else if ((fd = open(m->p.stderr_logfile,O_RDONLY)) < 0) {
	    verror("could not open dedicated monitor stderr logfile %s: %s\n",
		   m->p.stderr_logfile,strerror(errno));
	}
	else {
	    r->dedicatedMonitorStderrLog = 
		SOAP_CALLOC(soap,1,sizeof(*r->dedicatedMonitorStderrLog));
	    if (statbuf.st_size > 0) {
		sz = statbuf.st_size;
		if (maxSize > 0 && maxSize < statbuf.st_size)
		    sz = maxSize;
		r->dedicatedMonitorStderrLog->__ptr = SOAP_CALLOC(soap,1,sz);
		r->dedicatedMonitorStderrLog->__size = sz;

		lseek(fd,statbuf.st_size - sz,SEEK_SET);
		rc = 0;
		__SAFE_IO(read,"read",fd,r->dedicatedMonitorStderrLog->__ptr,sz,rc);
		if (errno) {
		    vwarn("only read %d of %d bytes for"
			  " dedicatedMonitorStderrLog: %s\n",
			  rc,sz,strerror(errno));
		}
		if (rc != sz) {
		    vwarn("only read %d of %d bytes for"
			  " dedicatedMonitorStderrLog (no error)\n",
			  rc,sz);
		    r->dedicatedMonitorStderrLog->__size = rc;
		}
	    }
	    close(fd);
	}
    }
    */

    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);

    return SOAP_OK;
}

int vmi1__InstantiateTarget(struct soap *soap,
			    struct vmi1__TargetSpecT *spec,
			    vmi1__ListenerT *ownerListener,
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
    char *url = NULL;
    int len = 0;
    int rn;

    pr = soap->user;
    if (!pr) {
	return soap_receiver_fault(soap,
				   "Request needed splitting but not split!",
				   "Request needed splitting but not split!");
    }

    if (ownerListener) {
	if (ownerListener->url != NULL) 
	    url = ownerListener->url;
	else if (ownerListener->hostname != NULL 
		 && ownerListener->port != NULL) {
	    len = sizeof("http://") + strlen(ownerListener->hostname) \
		+ sizeof(":") + 11 + sizeof(":/vmi/1/targetListener") + 1;
	    url = malloc(len * sizeof(char));
	    sprintf(url,"http://%s:%d/vmi/1/targetListener",
		    ownerListener->hostname,*ownerListener->port);
	}
	else {
	    return soap_receiver_fault(soap,"Bad listener!","Bad listener!");
	}
    }

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

    rn = rand();

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
				 tid,MONITOR_OBJTYPE_TARGET,NULL,NULL);
	if (!monitor) {
	    target_free_spec(s);
	    g_hash_table_destroy(reftab);
	    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);
	    return soap_receiver_fault(soap,"Could not create monitor!",
				       "Could not create monitor!");
	}

	/*
	 * NB: let target API handle stdout/err if the client wants it
	 * logged; just provide it valid tmpfile names.
	 */
	if (spec->logStdout && *spec->logStdout == xsd__boolean__true_) {
	    tmpbuflen = strlen(GENERIC_RPC_TMPDIR) + 1 + 11 + 1 + 11 
		+ sizeof(".stdout.log") + 1;
	    tmpbuf = malloc(tmpbuflen);
	    snprintf(tmpbuf,tmpbuflen,"%s/%d.%d.stdout.log",
		     GENERIC_RPC_TMPDIR,s->target_id,rn);

	    s->outfile = tmpbuf;
	}

	if (spec->logStderr && *spec->logStderr == xsd__boolean__true_) {
	    tmpbuflen = strlen(GENERIC_RPC_TMPDIR) + 1 + 11 + 1 + 11 
		+ sizeof(".stderr.log") + 1;
	    tmpbuf = malloc(tmpbuflen);
	    snprintf(tmpbuf,tmpbuflen,"%s/%d.%d.stderr.log",
		     GENERIC_RPC_TMPDIR,s->target_id,rn);

	    s->errfile = tmpbuf;
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

	monitor_add_primary_obj(monitor,t->id,MONITOR_OBJTYPE_TARGET,t,NULL);

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

	if (url) {
	    if (generic_rpc_bind_dynlistener_objid(RPC_SVCTYPE_TARGET,
						   url,t->id,1))
		vwarn("could not bind target %d to listener %s!?\n",
		      t->id,url);
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
				 s->target_id,MONITOR_OBJTYPE_TARGET,NULL,NULL);
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
	    //s->outfile = strdup("-");

	    tmpbuflen = strlen(GENERIC_RPC_TMPDIR) + 1 + 11 + 1 + 11 
		+ sizeof(".stdout.log") + 1;
	    tmpbuf = malloc(tmpbuflen);
	    snprintf(tmpbuf,tmpbuflen,"%s/%d.%d.stdout.log",
		     GENERIC_RPC_TMPDIR,s->target_id,rn);
	    s->outfile = tmpbuf;

	    tmpbuflen = strlen(GENERIC_RPC_TMPDIR) + 1 + 11 + 1 + 11 
		+ sizeof(".dedicatedMonitor.stdout.log") + 1;
	    tmpbuf = malloc(tmpbuflen);
	    snprintf(tmpbuf,tmpbuflen,"%s/%d.%d.dedicatedMonitor.stdout.log",
		     GENERIC_RPC_TMPDIR,s->target_id,rn);

	    monitor_setup_stdout(monitor,-1,tmpbuf,NULL,NULL);
	    free(tmpbuf);
	}

	if (spec->logStderr && *spec->logStderr == xsd__boolean__true_) {
	    //s->errfile = strdup("-");

	    tmpbuflen = strlen(GENERIC_RPC_TMPDIR) + 1 + 11 + 1 + 11 
		+ sizeof(".stderr.log") + 1;
	    tmpbuf = malloc(tmpbuflen);
	    snprintf(tmpbuf,tmpbuflen,"%s/%d.%d.stderr.log",
		     GENERIC_RPC_TMPDIR,s->target_id,rn);
	    s->errfile = tmpbuf;

	    tmpbuflen = strlen(GENERIC_RPC_TMPDIR) + 1 + 11 + 1 + 11 
		+ sizeof(".dedicatedMonitor.stderr.log") + 1;
	    tmpbuf = malloc(tmpbuflen);
	    snprintf(tmpbuf,tmpbuflen,"%s/%d.%d.dedicatedMonitor.stderr.log",
		     GENERIC_RPC_TMPDIR,s->target_id,rn);

	    monitor_setup_stderr(monitor,-1,tmpbuf,NULL,NULL);
	    free(tmpbuf);
	}

	monitor_add_primary_obj(monitor,s->target_id,MONITOR_OBJTYPE_TARGET,NULL,NULL);

	pid = monitor_spawn(monitor,MONITORED_TARGET_LAUNCHER,largv,NULL,
			    GENERIC_RPC_TMPDIR);
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
		      vmi1__TargetIdT tid,
		      struct vmi1__NoneResponse *r) {
    struct target *t = NULL;
    struct monitor *monitor;

    if (!monitor_lookup_objid_lock_objtype(tid,MONITOR_OBJTYPE_TARGET,
					   (void **)&t,&monitor)) {
	return soap_receiver_fault(soap,"Nonexistent target!",
				   "Specified target does not exist!");
    }

    PROXY_REQUEST_LOCKED(soap,tid,&target_rpc_mutex);

    /*
     * Let the monitor close/kill the target.
     */
    monitor_close_obj(monitor,t,0,0);

    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);

    return SOAP_OK;
}

int vmi1__KillTarget(struct soap *soap,
		     vmi1__TargetIdT tid,int kill_sig,
		      struct vmi1__NoneResponse *r) {
    struct target *t = NULL;
    struct monitor *monitor;

    if (!monitor_lookup_objid_lock_objtype(tid,MONITOR_OBJTYPE_TARGET,
					   (void **)&t,&monitor)) {
	return soap_receiver_fault(soap,"Nonexistent target!",
				   "Specified target does not exist!");
    }

    PROXY_REQUEST_LOCKED(soap,tid,&target_rpc_mutex);

    /*
     * Override whatever the default was!
     */
    t->spec->kill_on_close = 1;
    t->spec->kill_on_close_sig = kill_sig;

    /*
     * Let the monitor close/kill the target.
     */
    monitor_close_obj(monitor,t,0,0);

    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);

    return SOAP_OK;
}

int vmi1__FinalizeTarget(struct soap *soap,
			 vmi1__TargetIdT tid,
			 struct vmi1__NoneResponse *r) {
    struct target *t = NULL;
    struct monitor *monitor = NULL;

    if (!monitor_lookup_objid_lock_objtype(tid,MONITOR_OBJTYPE_TARGET,
					   (void **)&t,&monitor)) {
	return soap_receiver_fault(soap,"Nonexistent target!",
				   "Specified target does not exist!");
    }

    PROXY_REQUEST_LOCKED(soap,tid,&target_rpc_mutex);

    monitor_del_obj(monitor,t);

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
	       "notified non-authoritative listener %s (which returned %d)\n",
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
	       "notified non-authoritative listener %s (which returned %d)\n",
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
	vwarn("non-authoritative listener %s tried to send %d actions!\n",
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

int vmi1__TargetBindListener(struct soap *soap,
			     vmi1__TargetIdT tid,vmi1__ListenerT *listener,
			     struct vmi1__NoneResponse *r) {
    char *url;
    int len = 0;
    struct target *t = NULL;

    if (!listener) 
	return soap_receiver_fault(soap,"Bad listener!","Bad listener!");
    else if (listener->url != NULL) 
	url = listener->url;
    else if (listener->hostname != NULL && listener->port != NULL) {
	len = sizeof("http://") + strlen(listener->hostname) \
	    + sizeof(":") + 11 + sizeof(":/vmi/1/targetListener") + 1;
	url = malloc(len * sizeof(char));
	sprintf(url,"http://%s:%d/vmi/1/targetListener",
		listener->hostname,*listener->port);
    }
    else {
	return soap_receiver_fault(soap,"Bad listener!","Bad listener!");
    }

    if (!monitor_lookup_objid_lock_objtype(tid,MONITOR_OBJTYPE_TARGET,
					   (void **)&t,NULL)) {
	if (len)
	    free(url);
	return soap_receiver_fault(soap,"Nonexistent target!",
				   "Specified target does not exist!");
    }

    PROXY_REQUEST_LOCKED(soap,tid,&target_rpc_mutex);

    if (generic_rpc_bind_dynlistener_objid(RPC_SVCTYPE_TARGET,url,tid,0)) {
	if (len)
	    free(url);
	return soap_receiver_fault(soap,"Could not bind to target!",
				   "Could not bind to target!");
    }

    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);

    return SOAP_OK;
}

int vmi1__TargetUnbindListener(struct soap *soap,
			       vmi1__TargetIdT tid,vmi1__ListenerT *listener,
			       struct vmi1__NoneResponse *r) {
    char *url;
    int len = 0;
    struct target *t = NULL;

    if (!listener) 
	return soap_receiver_fault(soap,"Bad listener!","Bad listener!");
    else if (listener->url != NULL) 
	url = listener->url;
    else if (listener->hostname != NULL && listener->port != NULL) {
	len = sizeof("http://") + strlen(listener->hostname) \
	    + sizeof(":") + 11 + sizeof(":/vmi/1/targetListener") + 1;
	url = malloc(len * sizeof(char));
	sprintf(url,"http://%s:%d/vmi/1/targetListener",
		listener->hostname,*listener->port);
    }
    else {
	return soap_receiver_fault(soap,"Bad listener!","Bad listener!");
    }

    if (!monitor_lookup_objid_lock_objtype(tid,MONITOR_OBJTYPE_TARGET,
					   (void **)&t,NULL)) {
	if (len)
	    free(url);
	return soap_receiver_fault(soap,"Nonexistent target!",
				   "Specified target does not exist!");
    }

    PROXY_REQUEST_LOCKED(soap,tid,&target_rpc_mutex);

    if (generic_rpc_unbind_dynlistener_objid(RPC_SVCTYPE_TARGET,url,tid)) {
	if (len)
	    free(url);
	return soap_receiver_fault(soap,"Could not unbind from target!",
				   "Could not unbind from target!");
    }

    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_TARGET);

    return SOAP_OK;
}

/**
 ** All this code is still here.  But, I had to abandon this approach to
 ** listeners.  Why?  Because when target/analyses are managed by proxy
 ** and we have to forward requests to them, the listener IDs won't be
 ** registered in them.  So -- listeners have to be identified by URL,
 ** and dynamically bound.  Because of this problem, we now have
 ** identifiable listeners, AND dynamically-bound listeners that are
 ** distinguished by URL!  Argh!!!
 **/

/*
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
*/
