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

#include "analysis_rpc.h"

#include "log.h"
#include "monitor.h"

#include "analysis.h"
#include "target_api.h"
#include "target.h"

#include "generic_rpc.h"
#include "target_rpc.h"
#include "proxyreq.h"
#include "util.h"
#include "analysis_xml.h"
#include "target_xml.h"

static pthread_mutex_t analysis_rpc_mutex = PTHREAD_MUTEX_INITIALIZER;
static int init_done = 0;

extern struct vmi1__DebugFileOptsT defDebugFileOpts;

/**
 ** A bunch of prototypes per-analysis monitor interactions.
 **/
static int analysis_rpc_monitor_evloop_attach(struct evloop *evloop,void *obj);
static int analysis_rpc_monitor_evloop_detach(struct evloop *evloop,void *obj);
static int analysis_rpc_monitor_close(int sig,void *obj,void *objstate);
static int analysis_rpc_monitor_fini(void *obj,void *objstate);
static int analysis_rpc_monitor_evloop_is_attached(struct evloop *evloop,
						   void *obj);
static int analysis_rpc_monitor_error(monitor_error_t error,void *obj);
static int analysis_rpc_monitor_fatal_error(monitor_error_t error,void *obj);
static int analysis_rpc_monitor_child_recv_msg(struct monitor *monitor,
					       struct monitor_msg *msg);
static int analysis_rpc_monitor_recv_msg(struct monitor *monitor,
					 struct monitor_msg *msg);

struct monitor_objtype_ops analysis_rpc_monitor_objtype_ops = {
    .evloop_attach = NULL,
    .evloop_detach = NULL,
    .close = analysis_rpc_monitor_close,
    .fini = analysis_rpc_monitor_fini,
    .evloop_is_attached = NULL,
    .error = analysis_rpc_monitor_error,
    .fatal_error = analysis_rpc_monitor_fatal_error,
    .child_recv_msg = analysis_rpc_monitor_child_recv_msg,
    .recv_msg = analysis_rpc_monitor_recv_msg,
};

/**
 ** Module init/fini stuff.
 **/
void analysis_rpc_init(void) {
    pthread_mutex_lock(&analysis_rpc_mutex);

    if (init_done) {
	pthread_mutex_unlock(&analysis_rpc_mutex);
	return;
    }

    target_rpc_init();
    analysis_init();

    generic_rpc_register_svctype(RPC_SVCTYPE_ANALYSIS);

    monitor_register_objtype(MONITOR_OBJTYPE_ANALYSIS,
			     &analysis_rpc_monitor_objtype_ops,
			     &analysis_rpc_mutex);

    init_done = 1;

    pthread_mutex_unlock(&analysis_rpc_mutex);
}

void analysis_rpc_fini(void) {
    pthread_mutex_lock(&analysis_rpc_mutex);

    if (!init_done) {
	pthread_mutex_unlock(&analysis_rpc_mutex);
	return;
    }

    pthread_mutex_unlock(&analysis_rpc_mutex);

    /* XXX: nuke any existing analyses. */

    generic_rpc_unregister_svctype(RPC_SVCTYPE_ANALYSIS);

    analysis_fini();
    target_rpc_fini();

    init_done = 0;

    pthread_mutex_unlock(&analysis_rpc_mutex);
}

/**
 ** The main handling function.  Will use proxyreqs for now; perhaps
 ** later we'll optionally add a different model involving a SOAP server
 ** for each target/analysis, where the master server is a
 ** launchpad/registry.
 **/
int analysis_rpc_handle_request(struct soap *soap) {
    return proxyreq_handle_request(soap,"analysis");
}

int vmi1__ListAnalysisDescNames(struct soap *soap,
				void *_,
				struct vmi1__AnalysisDescNamesResponse *r) {
    struct array_list *names;
    char *name;
    int i;

    names = analysis_list_names();
    if (names && array_list_len(names) > 0) {
	r->__size_analysisDescName = array_list_len(names);
	r->analysisDescName = 
	    SOAP_CALLOC(soap,r->__size_analysisDescName,sizeof(char *));

	array_list_foreach(names,i,name) {
	    SOAP_STRCPY(soap,r->analysisDescName[i],name);
	}
    }
    else {
	r->__size_analysisDescName = 0;
	r->analysisDescName = NULL;
    }

    return SOAP_OK;
}

int vmi1__ListAnalysisDescs(struct soap *soap,
			    void *_,
			    struct vmi1__AnalysisDescsResponse *r) {
    struct array_list *descs;
    struct analysis_desc *desc;
    int i;
    GHashTable *reftab;

    descs = analysis_load_all();
    if (descs && array_list_len(descs) > 0) {
	r->__size_analysisDesc = array_list_len(descs);
	r->analysisDesc = 
	    SOAP_CALLOC(soap,r->__size_analysisDesc,sizeof(*r->analysisDesc));

	reftab = g_hash_table_new(g_direct_hash,g_direct_equal);
	array_list_foreach(descs,i,desc) {
	    a_analysis_desc_to_x_AnalysisDescT(soap,desc,reftab,
					       &r->analysisDesc[i]);
	}
	g_hash_table_destroy(reftab);
		
    }
    else {
	r->__size_analysisDesc = 0;
	r->analysisDesc = NULL;
    }

    return SOAP_OK;
}

int vmi1__ListAnalyses(struct soap *soap,
		       void *_,
		       struct vmi1__AnalysesResponse *r) {
    struct analysis *analysis;
    int i;
    GHashTable *reftab;
    struct array_list *list;

    list = monitor_list_objs_by_objtype_lock_objtype(MONITOR_OBJTYPE_ANALYSIS,1);
    r->__size_analysis = list ? array_list_len(list) : 0;
    if (r->__size_analysis == 0) {
	r->analysis = NULL;
	if (list)
	    array_list_free(list);
	monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_ANALYSIS);
	return SOAP_OK;
    }

    reftab = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);
    r->analysis = SOAP_CALLOC(soap,r->__size_analysis,sizeof(*r->analysis));
    array_list_foreach(list,i,analysis) 
	a_analysis_to_x_AnalysisT(soap,analysis,reftab,&r->analysis[i]);

    g_hash_table_destroy(reftab);
    array_list_free(list);

    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_ANALYSIS);

    return SOAP_OK;
}

int vmi1__UploadAnalysis(struct soap *soap,
			 struct vmi1__AnalysisDescT *analysisDesc,
			 struct xsd__hexBinary *inputFileContents,
			 struct vmi1__NoneResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__InstantiateAnalysis(struct soap *soap,
			      struct vmi1__AnalysisSpecT *analysisSpec,
			      struct vmi1__TargetSpecT *targetSpec,
			      struct vmi1__ListenerT *ownerListener,
			      struct vmi1__AnalysisResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__PauseAnalysis(struct soap *soap,
			vmi1__AnalysisIdT aid,
			struct vmi1__NoneResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__ResumeAnalysis(struct soap *soap,
			 vmi1__AnalysisIdT aid,
			 struct vmi1__NoneResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__EndAnalysis(struct soap *soap,
		      vmi1__AnalysisIdT aid,
		      struct vmi1__NoneResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__GetAnalysis(struct soap *soap,
		      vmi1__AnalysisIdT aid,
		      struct vmi1__AnalysisResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__GetAnalysisStatus(struct soap *soap,
			    vmi1__AnalysisIdT aid,
			    struct vmi1__AnalysisStatusResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__GetAnalysisResults(struct soap *soap,
			     vmi1__AnalysisIdT aid,
			     struct vmi1__AnalysisResultsResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__AnalysisBindListener(struct soap *soap,
			       vmi1__AnalysisIdT aid,vmi1__ListenerT *listener,
			       struct vmi1__NoneResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__AnalysisUnbindListener(struct soap *soap,
				 vmi1__AnalysisIdT tid,vmi1__ListenerT *listener,
				 struct vmi1__NoneResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

/**
 ** A bunch of stuff for per-analysis monitor interactions.
 **/
static int analysis_rpc_monitor_evloop_attach(struct evloop *evloop,void *obj) {
    if (!obj) 
	return 0;
    return analysis_attach_evloop((struct analysis *)obj,evloop);
}

static int analysis_rpc_monitor_evloop_detach(struct evloop *evloop,void *obj) {
    if (!obj) 
	return 0;
    return analysis_detach_evloop((struct analysis *)obj);
}

static int analysis_rpc_monitor_close(int sig,void *obj,void *objstate) {
    struct analysis *analysis = (struct analysis *)obj;
    int retval;

    if (!obj)
	return 0;

    if ((retval = analysis_close(analysis)) != TSTATUS_DONE) {
	verror("could not close analysis %d (error %d)!\n",analysis->id,retval);
    }

    return 0;
}

static int analysis_rpc_monitor_fini(void *obj,void *objstate) {
    if (!obj)
	return 0;
    analysis_free((struct analysis *)obj);
    return 0;
}

static int analysis_rpc_monitor_evloop_is_attached(struct evloop *evloop,
						   void *obj) {
    if (!obj)
	return 0;
    return analysis_is_evloop_attached((struct analysis *)obj,evloop);
}

static int analysis_rpc_monitor_error(monitor_error_t error,void *obj) {
    vdebug(5,LA_XML,LF_RPC,"analysis id %d (error %d)\n",
	   ((struct analysis *)obj)->id,error);
    return 0;
}

static int analysis_rpc_monitor_fatal_error(monitor_error_t error,void *obj) {
    vdebug(5,LA_XML,LF_RPC,"analysis id %d (error %d)\n",
	   ((struct analysis *)obj)->id,error);
    return 0;
}

static int analysis_rpc_monitor_child_recv_msg(struct monitor *monitor,
					       struct monitor_msg *msg) {
    struct analysis *analysis = (struct analysis *)monitor->obj;

    vdebug(9,LA_XML,LF_RPC,"msg(%d:%hd,%hd,%d) = '%s' (analysis %d (%p))\n",
	   msg->id,msg->cmd,msg->seqno,msg->len,msg->msg,msg->objid,analysis);

    return proxyreq_recv_request(monitor,msg);
}

static int analysis_rpc_monitor_recv_msg(struct monitor *monitor,
				       struct monitor_msg *msg) {
    struct analysis *analysis = (struct analysis *)monitor->obj;

    vdebug(9,LA_XML,LF_RPC,"msg(%d:%hd,%hd,%d) = '%s' (analysis %d (%p))\n",
	   msg->id,msg->cmd,msg->seqno,msg->len,msg->msg,msg->objid,analysis);

    return proxyreq_recv_response(monitor,msg);
}
