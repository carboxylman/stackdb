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
#include "common_xml.h"
#include "analysis_xml.h"
#include "target_xml.h"

#include "analysis_listener_moduleStub.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>

static pthread_mutex_t analysis_rpc_mutex = PTHREAD_MUTEX_INITIALIZER;
static int init_done = 0;

extern struct vmi1__DebugFileOptsT defDebugFileOpts;

/**
 ** A bunch of prototypes per-analysis monitor interactions.
 **/
static int analysis_rpc_monitor_evloop_attach(struct evloop *evloop,void *obj);
static int analysis_rpc_monitor_evloop_detach(struct evloop *evloop,void *obj);
static int analysis_rpc_monitor_close(struct monitor *monitor,
				      void *obj,void *objstate,
				      int kill,int kill_sig);
static int analysis_rpc_monitor_fini(struct monitor *monitor,
				     void *obj,void *objstate);
static int analysis_rpc_monitor_evloop_is_attached(struct evloop *evloop,
						   void *obj);
static int analysis_rpc_monitor_error(monitor_error_t error,void *obj);
static int analysis_rpc_monitor_fatal_error(monitor_error_t error,void *obj);
static int analysis_rpc_monitor_event(struct monitor *monitor,
				      monitor_event_t event,
				      int objid,void *obj);
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
    .event = analysis_rpc_monitor_event,
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

    monitor_init();
    analysis_init();
    generic_rpc_init();
    target_rpc_init();

    generic_rpc_register_svctype(RPC_SVCTYPE_ANALYSIS);

    monitor_register_objtype(MONITOR_OBJTYPE_ANALYSIS,
			     &analysis_rpc_monitor_objtype_ops,
			     &analysis_rpc_mutex);

    init_done = 1;

    pthread_mutex_unlock(&analysis_rpc_mutex);
}

void analysis_rpc_fini(void) {
    void *objid;
    struct array_list *alist;
    int i;
    struct analysis *a = NULL;
    struct monitor *m = NULL;

    pthread_mutex_lock(&analysis_rpc_mutex);

    if (!init_done) {
	pthread_mutex_unlock(&analysis_rpc_mutex);
	return;
    }

    pthread_mutex_unlock(&analysis_rpc_mutex);

    /* Nuke any existing analyses. */
    alist = 
	monitor_list_objids_by_objtype_lock_objtype(MONITOR_OBJTYPE_ANALYSIS,1);

    array_list_foreach(alist,i,objid) {
	a = NULL;
	m = NULL;
	if (!monitor_lookup_objid((int)(uintptr_t)objid,NULL,(void **)&a,&m)
	    || !a) 
	    continue;
	monitor_del_objid(m,(int)(uintptr_t)objid);
	generic_rpc_unbind_all_listeners_objid(RPC_SVCTYPE_ANALYSIS,
					       (int)(uintptr_t)objid);
    }

    generic_rpc_unregister_svctype(RPC_SVCTYPE_ANALYSIS);

    target_rpc_fini();
    generic_rpc_fini();
    analysis_fini();
    monitor_fini();

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

struct analysis_rpc_listener_result_data {
    GHashTable *reftab;
    struct vmi1__AnalysisResultT result;
    struct vmi1__AnalysisResultNotificationResponse r;
    result_t retval;
};

static int _analysis_rpc_notify_listener_result(struct generic_rpc_listener *l,
						int is_owner,void *data) {
    result_t retval;
    struct analysis_rpc_listener_result_data *d = \
	(struct analysis_rpc_listener_result_data *)data;
    int rc;

    /*
     * This stinks... but if we were the first 
     */

    rc = soap_call_vmi1__AnalysisResultNotification(&l->soap,l->url,NULL,
						    &d->result,&d->r);
    if (rc != SOAP_OK) {
	if (l->soap.error == SOAP_EOF && l->soap.errnum == 0) {
	    vwarn("timeout notifying %s; removing!",l->url);
	}
	else {
	    verrorc("AnalysisResult client call failure %s : ",
		    l->url);
	    soap_print_fault(&l->soap,stderr);
	}
	/* Let generic_rpc do this... */
	//soap_closesock(&lad->soap);
	return -1;
    }

    retval = x_ResultT_to_t_result_t(&l->soap,d->r.result);
    if (is_owner) {
	//if (retval > lad->retval)
	d->retval = retval;

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

int analysis_rpc_notify_listeners_result(struct analysis *analysis,
					 struct analysis_datum *datum) {
    struct soap encoder;
    struct analysis_rpc_listener_result_data d;

    memset(&d,0,sizeof(d));
    d.retval = RESULT_SUCCESS;

    /*
     * We only want to build the gsoap data struct once -- so we have to
     * set up a temp soap struct to do that on.  We can't use the
     * per-listener soap struct yet cause we don't have it until we're
     * in the iterator above.
     */
    soap_init(&encoder);
    d.reftab = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);

    a_analysis_datum_to_x_AnalysisResultT(&encoder,datum,analysis,d.reftab,&d.result);

    generic_rpc_listener_notify_all(RPC_SVCTYPE_ANALYSIS,analysis->id,
				    _analysis_rpc_notify_listener_result,&d);
    /*
     * Clean up temp/serialization data, but don't kill the sock if we
     * can avoid it.
     */
    g_hash_table_destroy(d.reftab);
    soap_destroy(&encoder);
    soap_end(&encoder);
    soap_done(&encoder);

    return 0;
}

#define _CB_SAVEBUF_INC 1024

int analysis_rpc_stdout_callback(int fd,char *buf,int len,void *state) {
    struct analysis *a = (struct analysis *)state;
    char *name = NULL;
    int id = -1;
    int type = -1;
    char *result_value = NULL;
    char *value_str = NULL;
    char *msg = NULL;
    struct analysis_datum *datum;
    char *saveptr = NULL;
    char *token;
    char *ptr;
    int rc;
    char rt = 0;
    int remaining;
    char *sbuf;
    char *ebuf;
    char *pbuf;
    char *pbuf_next;
    int saved = 0;
    int new_alen = 0;

    vdebug(5,LA_XML,LF_RPC,"fd %d recv '%s' (%d)\n",fd,buf,len);

    /*
     * Don't go to any effort if we don't need to...
     */
    if (!a->desc->supports_autoparse_simple_results)
	return 0;

    /*
     * If we're going to try to parse it, make sure we have at least one
     * newline in our buffer.  Once we do, process as many lines as are
     * in the buffer.  If there is any stuff left, place it at the head
     * of the buffer for next time.
     *
     * NB: the buf we get is NULL-terminated, but len does not include
     * the NULL.  Convenience.  SO -- if we copy the buf, make sure to
     * always keep the destination NULL-terminated too so we can always
     * use sscanf safely.
     */
    if (a->stdout_buf) {
	if ((len + 1) <= (a->stdout_buf_alen - a->stdout_buf_len)) {
	    memcpy(a->stdout_buf + a->stdout_buf_len,buf,len);
	    a->stdout_buf_len += len;
	    a->stdout_buf[a->stdout_buf_len] = '\0';

	    vdebug(8,LA_XML,LF_RPC,
		   "appending new input to existing buf; will process '''%s'''\n",
		   a->stdout_buf);
	}
	else {
	    new_alen = a->stdout_buf_len + len + 1;
	    if (new_alen % _CB_SAVEBUF_INC > 0) 
		new_alen += new_alen % _CB_SAVEBUF_INC;
	    a->stdout_buf = realloc(a->stdout_buf,new_alen);
	    a->stdout_buf_alen = new_alen;
	    memcpy(a->stdout_buf + a->stdout_buf_len,buf,len);
	    a->stdout_buf_len += len;
	    a->stdout_buf[a->stdout_buf_len] = '\0';

	    vdebug(8,LA_XML,LF_RPC,
		   "enlarged existing buf with new input; will process '''%s'''\n",
		   a->stdout_buf);
	}
	sbuf = pbuf = a->stdout_buf;
	saved = 1;
	remaining = a->stdout_buf_len;
    }
    else {
	sbuf = pbuf = buf;
	saved = 0;
	remaining = len;

	vdebug(8,LA_XML,LF_RPC,
	       "will process callback buf direct; input is '''%s'''\n",
	       pbuf);
    }
    /* One byte past the last char in buf. */
    ebuf = sbuf + remaining;

    if ((pbuf_next = strchr(pbuf,'\n')) == NULL) {
	/*
	 * No newline yet, save it off it we didn't do it already, and
	 * return.
	 */
	if (!saved) {
	    new_alen = a->stdout_buf_len + len + 1;
	    if (new_alen % _CB_SAVEBUF_INC > 0) 
		new_alen += new_alen % _CB_SAVEBUF_INC;
	    a->stdout_buf = malloc(new_alen);
	    a->stdout_buf_alen = new_alen;
	    memcpy(a->stdout_buf,buf,len);
	    a->stdout_buf_len = len;
	    a->stdout_buf[a->stdout_buf_len] = '\0';

	    vdebug(8,LA_XML,LF_RPC,
		   "no initial newline in direct buf; saved;"
		   " next callback will start with '''%s'''\n",
		   a->stdout_buf);
	}
	else {
	    vdebug(8,LA_XML,LF_RPC,
		   "no initial newline in direct buf; already saved;"
		   " next callback will start with '''%s'''\n",
		   a->stdout_buf);
	}
	return RESULT_SUCCESS;
    }

    /*
     * Ok, we have at least one line; process until we're done.
     */
    *pbuf_next = '\0';
    while (pbuf_next) {
	rt = 0;
	msg = value_str = name = result_value = NULL;
	rc = sscanf(pbuf,"RESULT(%c:%d): %ms (%d) %ms \"%m[^\"]\" (%m[^)])",
		    &rt,&id,&name,&type,&result_value,&msg,&value_str);
	if (rc >= 5) {
	    /*
	     * Don't bother to create an intermediate result if there are no
	     * listeners.
	     */
	    if (rt != 'f' 
		&& generic_rpc_count_listeners(RPC_SVCTYPE_ANALYSIS,a->id) < 1) {
		if (msg)
		    free(msg);
		if (value_str)
		    free(value_str);
		if (name)
		    free(name);
		if (result_value)
		    free(result_value);
		goto do_continue;
	    }

	    datum = analysis_create_simple_datum(a,id,name,type,result_value,
						 msg,1);
	    if (value_str) {
		saveptr = NULL;
		while ((token = strtok_r(saveptr ? NULL : value_str,",",
					 &saveptr))) {
		    ptr = index(token,'=');
		    if (!ptr) {
			vwarn("bad autoparse value token '%s'; skipping!\n",
			      token);
			continue;
		    }
		    *ptr = '\0';
		    ++ptr;
		    analysis_datum_add_simple_value(datum,token,ptr,0);
		}
		free(value_str);
	    }

	    monitor_lock_objtype(MONITOR_OBJTYPE_ANALYSIS);
	    analysis_rpc_notify_listeners_result(a,datum);
	    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_ANALYSIS);

	    if (rt == 'f') 
		array_list_append(a->results,datum);
	    else
		analysis_datum_free(datum);
	}

    do_continue:
	++pbuf_next;
	remaining -= (pbuf_next - pbuf);
	/* Skip to next newline-terminated segment, or break out. */
	pbuf = pbuf_next;
	if (pbuf >= ebuf) {
	    pbuf = pbuf_next = NULL;
	    break;
	}
	else {
	    pbuf_next = strchr(pbuf,'\n');
	    continue;
	}
    }

    /*
     * Ok, we are done processing; if we have any more input left to
     * scan, either in a->stdout_buf, or in buf (i.e., !saved), adjust
     * a->stdout_buf and make sure it has the remnant.
     */
    if (remaining > 0) {
	if (!saved) {
	    new_alen = remaining + 1;
	    if (new_alen % _CB_SAVEBUF_INC > 0) 
		new_alen += new_alen % _CB_SAVEBUF_INC;
	    a->stdout_buf = malloc(new_alen);
	    a->stdout_buf_alen = new_alen;
	    memcpy(a->stdout_buf,pbuf,remaining);
	    a->stdout_buf_len = remaining;
	    a->stdout_buf[a->stdout_buf_len] = '\0';

	    vdebug(8,LA_XML,LF_RPC,
		   "%d bytes remaining; saved; next callback will start with '''%s'''\n",
		   remaining,a->stdout_buf);
	}
	else {
	    vdebug(8,LA_XML,LF_RPC,
		   "%d bytes remaining; already saved; next callback will start with '''%s'''\n",
		   remaining,a->stdout_buf);
	}
	    
    }
    else {
	if (a->stdout_buf) {
	    free(a->stdout_buf);
	    a->stdout_buf = NULL;
	    a->stdout_buf_len = 0;
	    a->stdout_buf_alen = 0;

	    vdebug(8,LA_XML,LF_RPC,
		   "0 bytes remaining; freeing buf!\n");
	}
	else {
	    vdebug(8,LA_XML,LF_RPC,
		   "0 bytes remaining; no preexisting buf to free!\n");
	}
    }

    return 0;
}

int analysis_rpc_stderr_callback(int fd,char *buf,int len,void *state) {
    struct analysis *a = (struct analysis *)state;

    // XXX: fill

    //vdebug(5,LA_XML,LF_RPC,"fd %d recv '%s' (%d)\n",fd,buf,len);

    return 0;
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
    struct target_spec *ts = NULL;
    struct analysis_desc *d = NULL;
    struct analysis_spec *as = NULL;
    struct analysis *a = NULL;
    char *path = NULL;
    int targc = 0;
    char **targv = NULL;
    char *binarypath = NULL;
    int len;
    int tid;
    int aid = -1;
    GHashTable *reftab = NULL;
    struct monitor *monitor = NULL;
    struct proxyreq *pr;
    int fargc = 0;
    char **fargv = NULL;
    int i;
    struct stat statbuf;
    char *err = NULL, *err_detail = NULL;
    int locked = 0;
    char *pbuf = NULL;
    int fd = -1;
    int rc = 0;
    int retval;
    char *tmpbuf;
    int pid;
    int urllen = 0;
    char *url = NULL;
    char *atmpdir = NULL;
    char *wbuf;

    pr = soap->user;
    if (!pr) {
	err = err_detail = "Request needed splitting but not split!";
	goto errout;
    }

    /*
     * First, make sure we can find and load the analysis, and that the
     * target spec is valid enough to get going.
     */

    if (!analysisSpec || !analysisSpec->name) {
	err = err_detail = "Must set an analysis spec name!";
	goto errout;
    }

    if (ownerListener) {
	if (ownerListener->url != NULL) 
	    url = ownerListener->url;
	else if (ownerListener->hostname != NULL 
		 && ownerListener->port != NULL) {
	    urllen = sizeof("http://") + strlen(ownerListener->hostname) \
		+ sizeof(":") + 11 + sizeof(":/vmi/1/analysisListener") + 1;
	    url = malloc(urllen * sizeof(char));
	    snprintf(url,urllen,"http://%s:%d/vmi/1/analysisListener",
		    ownerListener->hostname,*ownerListener->port);
	}
	else {
	    return soap_receiver_fault(soap,"Bad listener!","Bad listener!");
	}
    }

    as = x_AnalysisSpecT_to_a_analysis_spec(soap,analysisSpec,reftab,NULL);
    if (!as) {
	err = err_detail = "Bad analysis spec!";
	goto errout;
    }

    path = analysis_find(as->name);
    if (!path) {
	err = err_detail = "Could not find analysis!";
	goto errout;
    }

    d = analysis_load_pathname(path);
    if (!d) {
	err = err_detail = "Could not load analysis description!";
	goto errout;
    }

    /*
     * If the analysis supports external control, give it a specific
     * analysis id too!  Well, we just grab one no matter what; it's
     * just we don't care if the monitored child uses it or not if we
     * know it doesn't support external control -- so we don't pass it
     * in that case.
     */
    aid = monitor_get_unique_objid();
    as->analysis_id = aid;

    /* Setup the analysis binary full path to launch. */
    len = strlen(path) + 1 + strlen(d->binary) + 1;
    binarypath = calloc(len,sizeof(char));
    snprintf(binarypath,len,"%s/%s",path,d->binary);

    /*
     * Setup its tmp dir name, but don't create it yet;
     * <ANALYSIS_TMPDIR>/<name>.<id>
     */
    len = strlen(ANALYSIS_TMPDIR) + sizeof("/vmi.analysis.") \
	+ strlen(as->name) + sizeof(".") + 11 + 1 + 11 + 1;
    atmpdir = malloc(len * sizeof(char));
    snprintf(atmpdir,len,"%s/vmi.analysis.%s.%d.%u",
	     ANALYSIS_TMPDIR,as->name,aid,rand());
    if (stat(atmpdir,&statbuf) == 0) 
	vwarn("analysis tmpdir %s already exists!\n",atmpdir);

    reftab = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);

    ts = x_TargetSpecT_to_t_target_spec(soap,targetSpec,reftab,NULL);
    if (!ts) {
	err = err_detail = "Bad target spec!";
	goto errout;
    }

    /*
     * Choose a specific target id!
     */
    tid = monitor_get_unique_objid();
    /* Force it to use our new monitored object id. */
    ts->target_id = tid;

    /*
     * Also need to setup the various stdio file args, if necessary.
     */
    if (targetSpec->stdinBytes && targetSpec->stdinBytes->__size > 0) {
	len = strlen(atmpdir) + 1 + sizeof("target.stdin.") + 11 + 1;
	ts->infile = malloc(len * sizeof(char));
	snprintf(ts->infile,len,"%s/target.stdin.%u",atmpdir,ts->target_id);

	/* NB: write the stdin file below, once we have a tmpdir! */
    }
    if (targetSpec->logStdout && *targetSpec->logStdout == xsd__boolean__true_) {
	len = strlen(atmpdir) + 1 + sizeof("target.stdout.") + 11 + 1;
	ts->outfile = malloc(len * sizeof(char));
	snprintf(ts->outfile,len,"%s/target.stdout.%u",atmpdir,ts->target_id);
    }
    if (targetSpec->logStderr && *targetSpec->logStderr == xsd__boolean__true_) {
	len = strlen(atmpdir) + 1 + sizeof("target.stderr.") + 11 + 1;
	ts->errfile = malloc(len * sizeof(char));
	snprintf(ts->errfile,len,"%s/target.stderr.%u",atmpdir,ts->target_id);
    }

    if (target_spec_to_argv(ts,binarypath,&targc,&targv)) {
	err = err_detail = "Could not create argv from target spec!";
	goto errout;
    }

    if (d->supports_external_control) {
	fargc = targc + 3;
	fargv = calloc(fargc,sizeof(char *));
	fargv[0] = targv[0];
	fargv[1] = strdup("-a");
	fargv[2] = malloc(11);
	snprintf(fargv[2],11,"%d",aid);
	memcpy(&fargv[3],&targv[1],fargc - 1);
	free(targv);
	targv = NULL;
	targc = 0;
    }
    else {
	fargc = targc;
	fargv = targv;
	targv = NULL;
	targc = 0;
    }

    /*
     * Create an analysis instance.  Both the monitor and monitored
     * child will have one; but analysis->target will only be live in
     * the child.  That is because the monitor has to monitor the
     * analysis binary for results, and maybe report to listeners; its
     * RPC functionality is not contained to the child.
     *
     * So unlike forked targets in the target RPC server, we cannot just
     * have a NULL obj.
     */
    a = analysis_create(as->analysis_id,as,d,tid,NULL);

    /* Save this off so we can grab the logfile names later if needed. */
    a->target_spec = ts;

    /*
     * Create the analysis tmpdir.  This means writing out any support files it
     * needs (right now just the target's stdin, if any).
     * <ANALYSIS_TMPDIR>/<name>.<id>
     */
    a->tmpdir = atmpdir;
    mkdir(ANALYSIS_TMPDIR,S_IRWXU | S_IRGRP | S_IXGRP);
    if (mkdir(a->tmpdir,S_IRWXU | S_IRGRP | S_IXGRP)) {
	verror("could not create analysis tmpdir %s: %s!\n",
	       a->tmpdir,strerror(errno));
	err = err_detail = "Could not create analysis tmpdir!";
	goto errout;
    }

    /*
     * Write any support files.
     */
    if (analysisSpec->supportFiles) {
	for (i = 0; i < analysisSpec->supportFiles->__sizesupportFile; ++i) {
	    len = strlen(a->tmpdir) + sizeof("/") 
		+ strlen(analysisSpec->supportFiles->supportFile[i].name) + 1;
	    pbuf = malloc(len);
	    snprintf(pbuf,len,"%s/%s",a->tmpdir,
		     analysisSpec->supportFiles->supportFile[i].name);
	    fd = open(pbuf,O_CREAT | O_TRUNC | O_WRONLY,S_IRUSR | S_IWUSR);
	    if (fd < 0) {
		verror("could not open(%s) for write: %s!\n",
		       pbuf,strerror(errno));
		err = err_detail = "Could not write file!";
		goto errout;
	    }

	    rc = 0;
	    len = analysisSpec->supportFiles->supportFile[i].content.__size;
	    wbuf = (char *)analysisSpec->supportFiles->supportFile[i].content.__ptr;
	    while (rc < len) {
		retval = write(fd,wbuf + rc,len - rc);
		if (retval < 0) {
		    if (errno == EINTR)
			continue;
		    else {
			verror("write(%s): %s\n",pbuf,strerror(errno));
			err = err_detail =				\
			    "Could not finish writing source file in tmpdir!";
			close(fd);
			goto errout;
		    }
		}
		else 
		    rc += retval;
	    }
	    close(fd);
	    free(pbuf);
	}
    }

    if (targetSpec->stdinBytes && targetSpec->stdinBytes->__size > 0) {
	len = strlen(a->tmpdir) + sizeof("/") + strlen(ts->infile) + 1;
	pbuf = malloc(len);
	snprintf(pbuf,len,"%s/%s",a->tmpdir,ts->infile);

	/* Write the stdin file now that we have a tmpdir */
	fd = open(pbuf,O_CREAT | O_TRUNC | O_WRONLY,S_IRUSR | S_IWUSR | S_IRGRP);
	if (fd < 0) {
	    verror("open(%s): %s\n",pbuf,strerror(errno));
	    err = err_detail = "Could not save target stdin in tmpdir!";
	    goto errout;
	}

	while (rc < targetSpec->stdinBytes->__size) {
	    retval = write(fd,targetSpec->stdinBytes->__ptr + rc,
			   targetSpec->stdinBytes->__size - rc);
	    if (retval < 0) {
		if (errno == EINTR)
		    continue;
		else {
		    verror("write(%s): %s\n",pbuf,strerror(errno));
		    err = err_detail = \
			"Could not finish writing target stdin in tmpdir!";
		    close(fd);
		    goto errout;
		}
	    }
	    else 
		rc += retval;
	}
	close(fd);
    }

    monitor_lock_objtype(MONITOR_OBJTYPE_ANALYSIS);
    locked = 1;

    /*
     * We have to setup a monitor that will exec the analysis binary.
     *
     * If the analysis supports external control, we need to choose a
     *
     * Also, we need to register/bind the ownerListener (and any
     * subsequent listeners) in this server, and in the forked program.
     * Why?  So that the monitor thread can autoparse results from the
     * analysis's stdout/err, AND so that the analysis itself can
     * generate results.  This does suck, but we don't want to be in the
     * business of forwarding results from the monitored analysis to the
     * monitor thread.  No reason to, especially since we've set it up
     * so that the monitored analysis can itself receive RPCs!
     */

    monitor = monitor_create(MONITOR_TYPE_PROCESS,MONITOR_FLAG_BIDI,
			     aid,MONITOR_OBJTYPE_ANALYSIS,a,NULL);
    if (!monitor) {
	err = err_detail = "Could not create analysis monitor!";
	goto errout;
    }

    /*
     * XXX: eventually, for analyses that support external control,
     * we'll have to forward the ownerListener URL to them!
     */
    if (generic_rpc_bind_dynlistener_objid(RPC_SVCTYPE_ANALYSIS,url,aid,1)) {
	err = err_detail = "Could not bind to analysis (monitor)!";
	goto errout;
    }

    /*
     * Setup I/O to child!  We always have to use our callbacks and
     * do our own logging.  BUT, we want to log/interact with the
     * spawned analysis's I/O, AND those of any analysis-spawned
     * targets.  Sigh... for now we get lucky by 1) setting up analysis
     * stdin if desired, and 2) assuming a single target per analysis,
     * and using the target command-line API to specify a stdin file,
     * and by writing that tmp file into our analysis tmpdir.
     *
     * Eventually, we will either need to extend the command line to be
     * able specify multiple targets, or to write targetSpec files into
     * the analysis tmpdir, or something else -- setup stdin pipes?  :)
     */

    if (analysisSpec->stdinBytes && analysisSpec->stdinBytes->__size > 0) {
	tmpbuf = malloc(analysisSpec->stdinBytes->__size);
	memcpy(tmpbuf,analysisSpec->stdinBytes->__ptr,
	       analysisSpec->stdinBytes->__size);

	monitor_setup_stdin(monitor,tmpbuf,analysisSpec->stdinBytes->__size);
	tmpbuf = NULL;
    }
    if (analysisSpec->logStdout 
	&& analysisSpec->logStdout == xsd__boolean__true_) {
	len = strlen(a->tmpdir) + sizeof("/analysis.stdout.") + 11 + 1;
	as->outfile = malloc(len);
	snprintf(as->outfile,len,"%s/analysis.stdout.%d",a->tmpdir,aid);

	monitor_setup_stdout(monitor,-1,as->outfile,
			     analysis_rpc_stdout_callback,a);
    }
    if (analysisSpec->logStderr 
	&& analysisSpec->logStderr == xsd__boolean__true_) {
	len = strlen(a->tmpdir) + sizeof("/analysis.stderr.") + 11 + 1;
	as->errfile = malloc(len);
	snprintf(as->errfile,len,"%s/analysis.stderr.%d",a->tmpdir,aid);

	monitor_setup_stderr(monitor,-1,as->errfile,
			     analysis_rpc_stderr_callback,a);
    }

    analysis_set_status(a,ASTATUS_RUNNING);

    pid = monitor_spawn(monitor,binarypath,fargv,NULL,a->tmpdir);
    if (pid < 0) {
	verror("error spawning: %d (%s)\n",pid,strerror(errno));
	err = err_detail = "Could not spawn analysis!";
	goto errout;
    }

    proxyreq_attach_new_objid(pr,aid,monitor);

    r->analysis = a_analysis_to_x_AnalysisT(soap,a,reftab,NULL);
    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_ANALYSIS);

    return SOAP_OK;

 errout:
    /* Cleanup! */

    if (fargc > 0) {
	for (i = 0; i < fargc; ++i)
	    if (fargv[i])
		free(fargv[i]);
	free(fargv);
    }
    if (a) {
	analysis_free(a);
    }
    else {
	if (atmpdir)
	    free(atmpdir);
	if (as) 
	    analysis_spec_free(as);
	if (d)
	    analysis_desc_free(d);
	if (ts)	   
	    target_free_spec(ts);
    }
    if (reftab)
	g_hash_table_destroy(reftab);
    if (binarypath)
	free(binarypath);
    if (path)
	free(path);
    if (pbuf)
	free(pbuf);
    if (url) 
	generic_rpc_unbind_dynlistener_objid(RPC_SVCTYPE_ANALYSIS,url,aid);
    if (urllen) 
	free(url);

    if (locked)
	monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_ANALYSIS);

    return soap_receiver_fault(soap,err,err_detail);
}

int __vmi1__InstantiateOverlayAnalysis(struct soap *soap,
				       struct vmi1__AnalysisSpecT *analysisSpec,
				       struct vmi1__TargetSpecT *targetSpec,
				       struct vmi1__TargetSpecT *overlayTargetSpec,
				       vmi1__ThreadIdT baseThid,
				       char *baseThreadName,
				       vmi1__ListenerT *ownerListener,
				       struct vmi1__AnalysisResponse *r) {
    struct target_spec *ts = NULL;
    struct target_spec *ots = NULL;
    struct analysis_desc *d = NULL;
    struct analysis_spec *as = NULL;
    struct analysis *a = NULL;
    char *path = NULL;
    int targc = 0;
    char **targv = NULL;
    int otargc = 0;
    char **otargv = NULL;
    int otrc;
    char otbuf[256];
    char *binarypath = NULL;
    int len;
    int tid;
    int aid = -1;
    GHashTable *reftab = NULL;
    struct monitor *monitor = NULL;
    struct proxyreq *pr;
    int fargc = 0;
    char **fargv = NULL;
    int i;
    struct stat statbuf;
    char *err = NULL, *err_detail = NULL;
    int locked = 0;
    char *pbuf = NULL;
    int fd = -1;
    int rc = 0;
    int retval;
    char *tmpbuf;
    int pid;
    int urllen = 0;
    char *url = NULL;
    char *atmpdir = NULL;
    char *wbuf;

    pr = soap->user;
    if (!pr) {
	err = err_detail = "Request needed splitting but not split!";
	goto errout;
    }

    /*
     * First, make sure we can find and load the analysis, and that the
     * target spec is valid enough to get going.
     */

    if (!analysisSpec || !analysisSpec->name) {
	err = err_detail = "Must set an analysis spec name!";
	goto errout;
    }

    if (ownerListener) {
	if (ownerListener->url != NULL) 
	    url = ownerListener->url;
	else if (ownerListener->hostname != NULL 
		 && ownerListener->port != NULL) {
	    urllen = sizeof("http://") + strlen(ownerListener->hostname) \
		+ sizeof(":") + 11 + sizeof(":/vmi/1/analysisListener") + 1;
	    url = malloc(urllen * sizeof(char));
	    snprintf(url,urllen,"http://%s:%d/vmi/1/analysisListener",
		    ownerListener->hostname,*ownerListener->port);
	}
	else {
	    return soap_receiver_fault(soap,"Bad listener!","Bad listener!");
	}
    }

    as = x_AnalysisSpecT_to_a_analysis_spec(soap,analysisSpec,reftab,NULL);
    if (!as) {
	err = err_detail = "Bad analysis spec!";
	goto errout;
    }

    path = analysis_find(as->name);
    if (!path) {
	err = err_detail = "Could not find analysis!";
	goto errout;
    }

    d = analysis_load_pathname(path);
    if (!d) {
	err = err_detail = "Could not load analysis description!";
	goto errout;
    }

    /*
     * If the analysis supports external control, give it a specific
     * analysis id too!  Well, we just grab one no matter what; it's
     * just we don't care if the monitored child uses it or not if we
     * know it doesn't support external control -- so we don't pass it
     * in that case.
     */
    aid = monitor_get_unique_objid();
    as->analysis_id = aid;

    /* Setup the analysis binary full path to launch. */
    len = strlen(path) + 1 + strlen(d->binary) + 1;
    binarypath = calloc(len,sizeof(char));
    snprintf(binarypath,len,"%s/%s",path,d->binary);

    /*
     * Setup its tmp dir name, but don't create it yet;
     * <ANALYSIS_TMPDIR>/<name>.<id>
     */
    len = strlen(ANALYSIS_TMPDIR) + sizeof("/vmi.analysis.") \
	+ strlen(as->name) + sizeof(".") + 11 + 1 + 11 + 1;
    atmpdir = malloc(len * sizeof(char));
    snprintf(atmpdir,len,"%s/vmi.analysis.%s.%d.%u",
	     ANALYSIS_TMPDIR,as->name,aid,rand());
    if (stat(atmpdir,&statbuf) == 0) 
	vwarn("analysis tmpdir %s already exists!\n",atmpdir);

    reftab = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);

    ts = x_TargetSpecT_to_t_target_spec(soap,targetSpec,reftab,NULL);
    if (!ts) {
	err = err_detail = "Bad target spec!";
	goto errout;
    }

    ots = x_TargetSpecT_to_t_target_spec(soap,overlayTargetSpec,reftab,NULL);
    if (!ots) {
	err = err_detail = "Bad overlay target spec!";
	goto errout;
    }

    /*
     * Choose a specific target id!
     */
    tid = monitor_get_unique_objid();
    /* Force it to use our new monitored object id. */
    ts->target_id = tid;

    /*
     * Also need to setup the various stdio file args, if necessary.
     */
    if (targetSpec->stdinBytes && targetSpec->stdinBytes->__size > 0) {
	len = strlen(atmpdir) + 1 + sizeof("target.stdin.") + 11 + 1;
	ts->infile = malloc(len * sizeof(char));
	snprintf(ts->infile,len,"%s/target.stdin.%u",atmpdir,ts->target_id);

	/* NB: write the stdin file below, once we have a tmpdir! */
    }
    else if (overlayTargetSpec->stdinBytes 
	     && overlayTargetSpec->stdinBytes->__size > 0) {
	len = strlen(atmpdir) + 1 + sizeof("target.stdin.") + 11 + 1;
	ts->infile = malloc(len * sizeof(char));
	snprintf(ts->infile,len,"%s/target.stdin.%u",atmpdir,ts->target_id);

	/* NB: write the stdin file below, once we have a tmpdir! */
    }
    if (targetSpec->logStdout && *targetSpec->logStdout == xsd__boolean__true_) {
	len = strlen(atmpdir) + 1 + sizeof("target.stdout.") + 11 + 1;
	ts->outfile = malloc(len * sizeof(char));
	snprintf(ts->outfile,len,"%s/target.stdout.%u",atmpdir,ts->target_id);
    }
    else if (overlayTargetSpec->logStdout 
	     && *overlayTargetSpec->logStdout == xsd__boolean__true_) {
	len = strlen(atmpdir) + 1 + sizeof("target.stdout.") + 11 + 1;
	ts->outfile = malloc(len * sizeof(char));
	snprintf(ts->outfile,len,"%s/target.stdout.%u",atmpdir,ts->target_id);
    }
    if (targetSpec->logStderr && *targetSpec->logStderr == xsd__boolean__true_) {
	len = strlen(atmpdir) + 1 + sizeof("target.stderr.") + 11 + 1;
	ts->errfile = malloc(len * sizeof(char));
	snprintf(ts->errfile,len,"%s/target.stderr.%u",atmpdir,ts->target_id);
    }
    else if (overlayTargetSpec->logStderr 
	     && *overlayTargetSpec->logStderr == xsd__boolean__true_) {
	len = strlen(atmpdir) + 1 + sizeof("target.stderr.") + 11 + 1;
	ts->errfile = malloc(len * sizeof(char));
	snprintf(ts->errfile,len,"%s/target.stderr.%u",atmpdir,ts->target_id);
    }

    if (target_spec_to_argv(ts,binarypath,&targc,&targv)) {
	err = err_detail = "Could not create argv from target spec!";
	goto errout;
    }
    if (target_spec_to_argv(ots,binarypath,&otargc,&otargv)) {
	err = err_detail = "Could not create argv from overlay target spec!";
	goto errout;
    }

    if (d->supports_external_control) {
	fargc = targc + 2 + 3;
	fargv = calloc(fargc,sizeof(char *));
	fargv[0] = targv[0];
	fargv[1] = strdup("-a");
	fargv[2] = malloc(11);
	snprintf(fargv[2],11,"%d",aid);
	memcpy(&fargv[3],&targv[1],fargc - 1);
	free(targv);
	targv = NULL;
	targc = 0;
    }
    else {
	fargc = targc + 2;
	fargv = calloc(fargc,sizeof(char *));
	memcpy(&fargv[0],&targv[0],targc);
	fargv[targc++] = strdup("-O");

	otrc = 0;
	otrc += snprintf(otbuf + otrc,sizeof(otbuf) - otrc,"'");
	if (baseThreadName) 
	    otrc += snprintf(otbuf + otrc,sizeof(otbuf) - otrc,
			     "%s:",baseThreadName);
	else
	    otrc += snprintf(otbuf + otrc,sizeof(otbuf) - otrc,
			     "%d:",baseThid);
	for (i = 0; i < otargc; ++i) {
	    otrc += snprintf(otbuf + otrc,sizeof(otbuf) - otrc," %s",otargv[i]);
	}
	otrc += snprintf(otbuf + otrc,sizeof(otbuf) - otrc,"'");

	fargv[targc++] = strdup(otbuf);

	free(targv);
	targv = NULL;
	targc = 0;
    }

    /*
     * Create an analysis instance.  Both the monitor and monitored
     * child will have one; but analysis->target will only be live in
     * the child.  That is because the monitor has to monitor the
     * analysis binary for results, and maybe report to listeners; its
     * RPC functionality is not contained to the child.
     *
     * So unlike forked targets in the target RPC server, we cannot just
     * have a NULL obj.
     */
    a = analysis_create(as->analysis_id,as,d,tid,NULL);

    /* Save this off so we can grab the logfile names later if needed. */
    a->target_spec = ts;
    a->overlay_target_spec = ts;

    /*
     * Create the analysis tmpdir.  This means writing out any support files it
     * needs (right now just the target's stdin, if any).
     * <ANALYSIS_TMPDIR>/<name>.<id>
     */
    a->tmpdir = atmpdir;
    mkdir(ANALYSIS_TMPDIR,S_IRWXU | S_IRGRP | S_IXGRP);
    if (mkdir(a->tmpdir,S_IRWXU | S_IRGRP | S_IXGRP)) {
	verror("could not create analysis tmpdir %s: %s!\n",
	       a->tmpdir,strerror(errno));
	err = err_detail = "Could not create analysis tmpdir!";
	goto errout;
    }

    /*
     * Write any support files.
     */
    if (analysisSpec->supportFiles) {
	for (i = 0; i < analysisSpec->supportFiles->__sizesupportFile; ++i) {
	    len = strlen(a->tmpdir) + sizeof("/") 
		+ strlen(analysisSpec->supportFiles->supportFile[i].name) + 1;
	    pbuf = malloc(len);
	    snprintf(pbuf,len,"%s/%s",a->tmpdir,
		     analysisSpec->supportFiles->supportFile[i].name);
	    fd = open(pbuf,O_CREAT | O_TRUNC | O_WRONLY,S_IRUSR | S_IWUSR);
	    if (fd < 0) {
		verror("could not open(%s) for write: %s!\n",
		       pbuf,strerror(errno));
		err = err_detail = "Could not write file!";
		goto errout;
	    }

	    rc = 0;
	    len = analysisSpec->supportFiles->supportFile[i].content.__size;
	    wbuf = (char *)analysisSpec->supportFiles->supportFile[i].content.__ptr;
	    while (rc < len) {
		retval = write(fd,wbuf + rc,len - rc);
		if (retval < 0) {
		    if (errno == EINTR)
			continue;
		    else {
			verror("write(%s): %s\n",pbuf,strerror(errno));
			err = err_detail =				\
			    "Could not finish writing source file in tmpdir!";
			close(fd);
			goto errout;
		    }
		}
		else 
		    rc += retval;
	    }
	    close(fd);
	    free(pbuf);
	}
    }

    if (targetSpec->stdinBytes && targetSpec->stdinBytes->__size > 0) {
	len = strlen(a->tmpdir) + sizeof("/") + strlen(ts->infile) + 1;
	pbuf = malloc(len);
	snprintf(pbuf,len,"%s/%s",a->tmpdir,ts->infile);

	/* Write the stdin file now that we have a tmpdir */
	fd = open(pbuf,O_CREAT | O_TRUNC | O_WRONLY,S_IRUSR | S_IWUSR | S_IRGRP);
	if (fd < 0) {
	    verror("open(%s): %s\n",pbuf,strerror(errno));
	    err = err_detail = "Could not save target stdin in tmpdir!";
	    goto errout;
	}

	while (rc < targetSpec->stdinBytes->__size) {
	    retval = write(fd,targetSpec->stdinBytes->__ptr + rc,
			   targetSpec->stdinBytes->__size - rc);
	    if (retval < 0) {
		if (errno == EINTR)
		    continue;
		else {
		    verror("write(%s): %s\n",pbuf,strerror(errno));
		    err = err_detail = \
			"Could not finish writing target stdin in tmpdir!";
		    close(fd);
		    goto errout;
		}
	    }
	    else 
		rc += retval;
	}
	close(fd);
    }
    else if (overlayTargetSpec->stdinBytes 
	     && overlayTargetSpec->stdinBytes->__size > 0) {
	len = strlen(a->tmpdir) + sizeof("/") + strlen(ts->infile) + 1;
	pbuf = malloc(len);
	snprintf(pbuf,len,"%s/%s",a->tmpdir,ts->infile);

	/* Write the stdin file now that we have a tmpdir */
	fd = open(pbuf,O_CREAT | O_TRUNC | O_WRONLY,S_IRUSR | S_IWUSR | S_IRGRP);
	if (fd < 0) {
	    verror("open(%s): %s\n",pbuf,strerror(errno));
	    err = err_detail = "Could not save target stdin in tmpdir!";
	    goto errout;
	}

	while (rc < overlayTargetSpec->stdinBytes->__size) {
	    retval = write(fd,overlayTargetSpec->stdinBytes->__ptr + rc,
			   overlayTargetSpec->stdinBytes->__size - rc);
	    if (retval < 0) {
		if (errno == EINTR)
		    continue;
		else {
		    verror("write(%s): %s\n",pbuf,strerror(errno));
		    err = err_detail = \
			"Could not finish writing target stdin in tmpdir!";
		    close(fd);
		    goto errout;
		}
	    }
	    else 
		rc += retval;
	}
	close(fd);
    }

    monitor_lock_objtype(MONITOR_OBJTYPE_ANALYSIS);
    locked = 1;

    /*
     * We have to setup a monitor that will exec the analysis binary.
     *
     * If the analysis supports external control, we need to choose a
     *
     * Also, we need to register/bind the ownerListener (and any
     * subsequent listeners) in this server, and in the forked program.
     * Why?  So that the monitor thread can autoparse results from the
     * analysis's stdout/err, AND so that the analysis itself can
     * generate results.  This does suck, but we don't want to be in the
     * business of forwarding results from the monitored analysis to the
     * monitor thread.  No reason to, especially since we've set it up
     * so that the monitored analysis can itself receive RPCs!
     */

    monitor = monitor_create(MONITOR_TYPE_PROCESS,MONITOR_FLAG_BIDI,
			     aid,MONITOR_OBJTYPE_ANALYSIS,a,NULL);
    if (!monitor) {
	err = err_detail = "Could not create analysis monitor!";
	goto errout;
    }

    /*
     * XXX: eventually, for analyses that support external control,
     * we'll have to forward the ownerListener URL to them!
     */
    if (generic_rpc_bind_dynlistener_objid(RPC_SVCTYPE_ANALYSIS,url,aid,1)) {
	err = err_detail = "Could not bind to analysis (monitor)!";
	goto errout;
    }

    /*
     * Setup I/O to child!  We always have to use our callbacks and
     * do our own logging.  BUT, we want to log/interact with the
     * spawned analysis's I/O, AND those of any analysis-spawned
     * targets.  Sigh... for now we get lucky by 1) setting up analysis
     * stdin if desired, and 2) assuming a single target per analysis,
     * and using the target command-line API to specify a stdin file,
     * and by writing that tmp file into our analysis tmpdir.
     *
     * Eventually, we will either need to extend the command line to be
     * able specify multiple targets, or to write targetSpec files into
     * the analysis tmpdir, or something else -- setup stdin pipes?  :)
     */

    if (analysisSpec->stdinBytes && analysisSpec->stdinBytes->__size > 0) {
	tmpbuf = malloc(analysisSpec->stdinBytes->__size);
	memcpy(tmpbuf,analysisSpec->stdinBytes->__ptr,
	       analysisSpec->stdinBytes->__size);

	monitor_setup_stdin(monitor,tmpbuf,analysisSpec->stdinBytes->__size);
	tmpbuf = NULL;
    }
    if (analysisSpec->logStdout 
	&& analysisSpec->logStdout == xsd__boolean__true_) {
	len = strlen(a->tmpdir) + sizeof("/analysis.stdout.") + 11 + 1;
	as->outfile = malloc(len);
	snprintf(as->outfile,len,"%s/analysis.stdout.%d",a->tmpdir,aid);

	monitor_setup_stdout(monitor,-1,as->outfile,
			     analysis_rpc_stdout_callback,a);
    }
    if (analysisSpec->logStderr 
	&& analysisSpec->logStderr == xsd__boolean__true_) {
	len = strlen(a->tmpdir) + sizeof("/analysis.stderr.") + 11 + 1;
	as->errfile = malloc(len);
	snprintf(as->errfile,len,"%s/analysis.stderr.%d",a->tmpdir,aid);

	monitor_setup_stderr(monitor,-1,as->errfile,
			     analysis_rpc_stderr_callback,a);
    }

    analysis_set_status(a,ASTATUS_RUNNING);

    pid = monitor_spawn(monitor,binarypath,fargv,NULL,a->tmpdir);
    if (pid < 0) {
	verror("error spawning: %d (%s)\n",pid,strerror(errno));
	err = err_detail = "Could not spawn analysis!";
	goto errout;
    }

    proxyreq_attach_new_objid(pr,aid,monitor);

    r->analysis = a_analysis_to_x_AnalysisT(soap,a,reftab,NULL);
    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_ANALYSIS);

    return SOAP_OK;

 errout:
    /* Cleanup! */

    if (fargc > 0) {
	for (i = 0; i < fargc; ++i)
	    if (fargv[i])
		free(fargv[i]);
	free(fargv);
    }
    if (a) {
	analysis_free(a);
    }
    else {
	if (atmpdir)
	    free(atmpdir);
	if (as) 
	    analysis_spec_free(as);
	if (d)
	    analysis_desc_free(d);
	if (ts)	   
	    target_free_spec(ts);
    }
    if (reftab)
	g_hash_table_destroy(reftab);
    if (binarypath)
	free(binarypath);
    if (path)
	free(path);
    if (pbuf)
	free(pbuf);
    if (url) 
	generic_rpc_unbind_dynlistener_objid(RPC_SVCTYPE_ANALYSIS,url,aid);
    if (urllen) 
	free(url);

    if (locked)
	monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_ANALYSIS);

    return soap_receiver_fault(soap,err,err_detail);
}

int vmi1__InstantiateOverlayAnalysis(struct soap *soap,
				     struct vmi1__AnalysisSpecT *analysisSpec,
				     struct vmi1__TargetSpecT *targetSpec,
				     struct vmi1__TargetSpecT *overlayTargetSpec,
				     vmi1__ThreadIdT baseThid,
				     vmi1__ListenerT *ownerListener,
				     struct vmi1__AnalysisResponse *r) {
    return __vmi1__InstantiateOverlayAnalysis(soap,analysisSpec,targetSpec,
					      overlayTargetSpec,
					      baseThid,NULL,
					      ownerListener,r);
}

int vmi1__InstantiateOverlayAnalysisByThreadName(struct soap *soap,
						 struct vmi1__AnalysisSpecT *analysisSpec,
						 struct vmi1__TargetSpecT *targetSpec,
						 struct vmi1__TargetSpecT *overlayTargetSpec,
						 char *baseThreadName,
						 vmi1__ListenerT *ownerListener,
						 struct vmi1__AnalysisResponse *r) {
    return __vmi1__InstantiateOverlayAnalysis(soap,analysisSpec,targetSpec,
					      overlayTargetSpec,
					      -1,baseThreadName,
					      ownerListener,r);
}

int vmi1__PauseAnalysis(struct soap *soap,
			vmi1__AnalysisIdT aid,
			struct vmi1__NoneResponse *r) {
    struct analysis *a = NULL;
    struct monitor *monitor;
    char *errmsg;

    if (!monitor_lookup_objid_lock_objtype(aid,MONITOR_OBJTYPE_ANALYSIS,
					   (void **)&a,&monitor)) {
	return soap_receiver_fault(soap,"Nonexistent analysis!",
				   "Specified analysis does not exist!");
    }

    if (a->desc->supports_external_control) {
	PROXY_REQUEST_LOCKED(soap,aid,&analysis_rpc_mutex);

	monitor_close_obj(monitor,a,0,0);
    }
    else {
	/*
	 * Try our best to pause it via SIGSTOP.
	 */
	if (a->status == ASTATUS_PAUSED) {
	    errmsg = "Analysis already paused!";
	    goto errout;
	}
	else if (a->status == ASTATUS_DONE) {
	    errmsg = "Analysis already done; cannot pause!";
	    goto errout;
	}

	if (kill(monitor->p.pid,SIGSTOP) < 0) {
	    if (errno == ESRCH) {
		errmsg = "Analysis seems dead; cannot pause!";
		goto errout;
	    }
	    else {
		errmsg = "Error pausing analysis!";
		goto errout;
	    }
	}
	analysis_set_status(a,ASTATUS_PAUSED);
    }

    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_ANALYSIS);

    return SOAP_OK;

 errout:
    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_ANALYSIS);

    return soap_receiver_fault(soap,errmsg,errmsg);
}

int vmi1__ResumeAnalysis(struct soap *soap,
			 vmi1__AnalysisIdT aid,
			 struct vmi1__NoneResponse *r) {
    struct analysis *a = NULL;
    struct monitor *monitor;
    char *errmsg;

    if (!monitor_lookup_objid_lock_objtype(aid,MONITOR_OBJTYPE_ANALYSIS,
					   (void **)&a,&monitor)) {
	return soap_receiver_fault(soap,"Nonexistent analysis!",
				   "Specified analysis does not exist!");
    }

    if (a->desc->supports_external_control) {
	PROXY_REQUEST_LOCKED(soap,aid,&analysis_rpc_mutex);

	monitor_close_obj(monitor,a,0,0);
    }
    else {
	/*
	 * Try our best to pause it via SIGCONT.
	 */
	if (a->status == ASTATUS_RUNNING) {
	    errmsg = "Analysis already running!";
	    goto errout;
	}
	else if (a->status == ASTATUS_DONE) {
	    errmsg = "Analysis already done; cannot resume!";
	    goto errout;
	}

	if (kill(monitor->p.pid,SIGCONT) < 0) {
	    if (errno == ESRCH) {
		errmsg = "Analysis seems dead; cannot resume!";
		goto errout;
	    }
	    else {
		errmsg = "Error resuming analysis!";
		goto errout;
	    }
	}
	analysis_set_status(a,ASTATUS_RUNNING);
    }

    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_ANALYSIS);

    return SOAP_OK;

 errout:
    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_ANALYSIS);

    return soap_receiver_fault(soap,errmsg,errmsg);
}

int vmi1__CloseAnalysis(struct soap *soap,
			vmi1__AnalysisIdT aid,
			struct vmi1__NoneResponse *r) {
    struct analysis *a = NULL;
    struct monitor *monitor;

    if (!monitor_lookup_objid_lock_objtype(aid,MONITOR_OBJTYPE_ANALYSIS,
					   (void **)&a,&monitor)) {
	return soap_receiver_fault(soap,"Nonexistent analysis!",
				   "Specified analysis does not exist!");
    }

    /*
     * Let the monitor close/kill the analysis; if it supports external
     * control, pass the RPC to it and let it close itself in the child;
     * otherwise, close it from the outside.
     */
    if (a->desc->supports_external_control) {
	PROXY_REQUEST_LOCKED(soap,aid,&analysis_rpc_mutex);

	monitor_close_obj(monitor,a,0,0);
    }
    else
	monitor_close_obj(monitor,a,0,0);

    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_ANALYSIS);

    return SOAP_OK;
}


int vmi1__KillAnalysis(struct soap *soap,
		       vmi1__AnalysisIdT aid,int kill_sig,
		       struct vmi1__NoneResponse *r) {
    struct analysis *a = NULL;
    struct monitor *monitor;

    if (!monitor_lookup_objid_lock_objtype(aid,MONITOR_OBJTYPE_ANALYSIS,
					   (void **)&a,&monitor)) {
	return soap_receiver_fault(soap,"Nonexistent analysis!",
				   "Specified analysis does not exist!");
    }

    /*
     * Let the monitor close/kill the analysis; if it supports external
     * control, pass the RPC to it and let it close itself in the child;
     * otherwise, close it from the outside.
     */

    /*
     * Override whatever the default was!
     */
    if (kill_sig) {
	a->spec->kill_on_close = 1;
	a->spec->kill_on_close_sig = kill_sig;
    }

    if (a->desc->supports_external_control) {
	PROXY_REQUEST_LOCKED(soap,aid,&analysis_rpc_mutex);

	monitor_close_obj(monitor,a,0,0);
    }
    else
	monitor_close_obj(monitor,a,0,0);

    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_ANALYSIS);

    return SOAP_OK;
}

int vmi1__FinalizeAnalysis(struct soap *soap,
			   vmi1__AnalysisIdT aid,
			   struct vmi1__NoneResponse *r) {
    struct analysis *a = NULL;
    struct monitor *monitor;

    if (!monitor_lookup_objid_lock_objtype(aid,MONITOR_OBJTYPE_ANALYSIS,
					   (void **)&a,&monitor)) {
	return soap_receiver_fault(soap,"Nonexistent analysis!",
				   "Specified analysis does not exist!");
    }

    /*
     * Let the monitor close/kill the analysis; if it supports external
     * control, pass the RPC to it and let it close itself in the child;
     * otherwise, close it from the outside.
     */

    if (a->desc->supports_external_control) {
	PROXY_REQUEST_LOCKED(soap,aid,&analysis_rpc_mutex);

	monitor_del_obj(monitor,a);
    }
    else
	monitor_del_obj(monitor,a);

    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_ANALYSIS);

    return SOAP_OK;
}

int vmi1__GetAnalysis(struct soap *soap,
		      vmi1__AnalysisIdT aid,
		      struct vmi1__AnalysisResponse *r) {
    struct analysis *a = NULL;
    struct monitor *monitor;
    GHashTable *reftab;

    if (!monitor_lookup_objid_lock_objtype(aid,MONITOR_OBJTYPE_ANALYSIS,
					   (void **)&a,&monitor)) {
	return soap_receiver_fault(soap,"Nonexistent analysis!",
				   "Specified analysis does not exist!");
    }

    if (a->desc->supports_external_control) {
	PROXY_REQUEST_LOCKED(soap,aid,&analysis_rpc_mutex);
    }
    else {
	reftab = g_hash_table_new(g_direct_hash,g_direct_equal);
	r->analysis = a_analysis_to_x_AnalysisT(soap,a,reftab,NULL);
	g_hash_table_destroy(reftab);
    }

    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_ANALYSIS);

    return SOAP_OK;
}

int vmi1__GetAnalysisStatus(struct soap *soap,
			    vmi1__AnalysisIdT aid,
			    struct vmi1__AnalysisStatusResponse *r) {
    struct analysis *a = NULL;
    struct monitor *monitor;
    GHashTable *reftab;

    if (!monitor_lookup_objid_lock_objtype(aid,MONITOR_OBJTYPE_ANALYSIS,
					   (void **)&a,&monitor)) {
	return soap_receiver_fault(soap,"Nonexistent analysis!",
				   "Specified analysis does not exist!");
    }

    reftab = g_hash_table_new(g_direct_hash,g_direct_equal);
    r->analysisStatus = 
	a_analysis_status_t_to_x_AnalysisStatusT(soap,a->status,reftab,NULL);
    g_hash_table_destroy(reftab);

    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_ANALYSIS);

    return SOAP_OK;
}

int vmi1__GetAnalysisResults(struct soap *soap,
			     vmi1__AnalysisIdT aid,
			     struct vmi1__AnalysisResultsResponse *r) {
    struct analysis *a = NULL;
    struct monitor *monitor;
    GHashTable *reftab;

    if (!monitor_lookup_objid_lock_objtype(aid,MONITOR_OBJTYPE_ANALYSIS,
					   (void **)&a,&monitor)) {
	return soap_receiver_fault(soap,"Nonexistent analysis!",
				   "Specified analysis does not exist!");
    }

    reftab = g_hash_table_new(g_direct_hash,g_direct_equal);
    a_analysis_datum_list_to_x_AnalysisResultsT(soap,a->results,a,reftab,
						&r->analysisResults);
    g_hash_table_destroy(reftab);

    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_ANALYSIS);

    return SOAP_OK;
}

int vmi1__GetAnalysisLogs(struct soap *soap,
			  vmi1__AnalysisIdT aid,int maxSize,
			  struct vmi1__AnalysisLogsResponse *r) {
    struct analysis *a = NULL;
    struct monitor *m = NULL;

    if (!monitor_lookup_objid_lock_objtype(aid,MONITOR_OBJTYPE_ANALYSIS,
					   (void **)&a,&m)) {
	return soap_receiver_fault(soap,"Nonexistent analysis!",
				   "Specified analysis does not exist!");
    }

    if (a->desc->supports_external_control) 
	PROXY_REQUEST_LOCKED(soap,aid,&analysis_rpc_mutex);

    if (a->spec->outfile) 
	r->stdoutLog = 
	    generic_rpc_read_file_into_hexBinary(soap,a->spec->outfile,maxSize);
    if (a->spec->errfile) 
	r->stderrLog = 
	    generic_rpc_read_file_into_hexBinary(soap,a->spec->errfile,maxSize);
    if (a->target_spec) {
	if (a->target_spec->outfile) 
	    r->targetStdoutLog = 
		generic_rpc_read_file_into_hexBinary(soap,
						     a->target_spec->outfile,
						     maxSize);
	if (a->target_spec->errfile) 
	    r->targetStderrLog = 
		generic_rpc_read_file_into_hexBinary(soap,
						     a->target_spec->errfile,
						     maxSize);
    }

    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_ANALYSIS);

    return SOAP_OK;
}

int vmi1__AnalysisBindListener(struct soap *soap,
			       vmi1__AnalysisIdT aid,vmi1__ListenerT *listener,
			       struct vmi1__NoneResponse *r) {
    char *url;
    int len = 0;
    struct analysis *a = NULL;

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

    /*
     * We want to "snoop" on this listener call -- saving the listener
     * in the server so that the thread monitoring stdout/err has it if
     * it needs to autoparse results.  Plus, if the analysis doesn't
     * support external control, this is the only place to stand.
     */

    if (!monitor_lookup_objid_lock_objtype(aid,MONITOR_OBJTYPE_ANALYSIS,
					   (void **)&a,NULL)) {
	if (len)
	    free(url);
	return soap_receiver_fault(soap,"Nonexistent analysis!",
				   "Specified analysis does not exist!");
    }

    /* XXX: this check is pretty bad; it should be monitor_is_parent() */
    if (!a->target) {
	if (generic_rpc_bind_dynlistener_objid(RPC_SVCTYPE_ANALYSIS,url,aid,0)) {
	    if (len)
		free(url);
	    return soap_receiver_fault(soap,
				       "Could not bind to analysis (monitor)!",
				       "Could not bind to analysis (monitor)!");
	}
    }

    if (a->desc->supports_external_control) {
	PROXY_REQUEST_LOCKED(soap,aid,&analysis_rpc_mutex);

	if (generic_rpc_bind_dynlistener_objid(RPC_SVCTYPE_ANALYSIS,url,aid,0)) {
	    if (len)
		free(url);
	    return soap_receiver_fault(soap,"Could not bind to analysis!",
				       "Could not bind to analysis!");
	}
    }

    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_ANALYSIS);

    return SOAP_OK;
}

int vmi1__AnalysisUnbindListener(struct soap *soap,
				 vmi1__AnalysisIdT aid,vmi1__ListenerT *listener,
				 struct vmi1__NoneResponse *r) {
    char *url;
    int len = 0;
    struct analysis *a = NULL;

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

    /*
     * We want to "snoop" on this listener call -- saving the listener
     * in the server so that the thread monitoring stdout/err has it if
     * it needs to autoparse results.  Plus, if the analysis doesn't
     * support external control, this is the only place to stand.
     */

    if (!monitor_lookup_objid_lock_objtype(aid,MONITOR_OBJTYPE_ANALYSIS,
					   (void **)&a,NULL)) {
	if (len)
	    free(url);
	return soap_receiver_fault(soap,"Nonexistent analysis!",
				   "Specified analysis does not exist!");
    }

    /* XXX: this check is pretty bad; it should be monitor_is_parent() */
    if (!a->target) {
	if (generic_rpc_unbind_dynlistener_objid(RPC_SVCTYPE_ANALYSIS,url,aid)) {
	    if (len)
		free(url);
	    return soap_receiver_fault(soap,
				       "Could not bind to analysis (monitor)!",
				       "Could not bind to analysis (monitor)!");
	}
    }

    if (a->desc->supports_external_control) {
	PROXY_REQUEST_LOCKED(soap,aid,&analysis_rpc_mutex);

	if (generic_rpc_unbind_dynlistener_objid(RPC_SVCTYPE_ANALYSIS,url,aid)) {
	    if (len)
		free(url);
	    return soap_receiver_fault(soap,"Could not bind to analysis!",
				       "Could not bind to analysis!");
	}
    }

    monitor_unlock_objtype_unsafe(MONITOR_OBJTYPE_ANALYSIS);

    return SOAP_OK;
}

/**
 ** A bunch of stuff for per-analysis monitor interactions.
 **/
static int analysis_rpc_monitor_evloop_attach(struct evloop *evloop,void *obj) {
    if (!obj) 
	return 0;

    if (((struct analysis *)obj)->target)
	return analysis_attach_evloop((struct analysis *)obj,evloop);
    else 
	return 0;
}

static int analysis_rpc_monitor_evloop_detach(struct evloop *evloop,void *obj) {
    if (!obj) 
	return 0;

    if (((struct analysis *)obj)->target)
	return analysis_detach_evloop((struct analysis *)obj);
    else 
	return 0;
}

static int analysis_rpc_monitor_close(struct monitor *monitor,
				      void *obj,void *objstate,
				      int dokill,int kill_sig) {
    struct analysis *analysis = (struct analysis *)obj;
    int retval;
    int rsig = kill_sig;
    int apid = monitor->p.pid;

    if (!obj)
	return 0;

    if (analysis->target)
	target_close(analysis->target);
    else if (dokill || analysis->spec->kill_on_close) {
	if (!dokill)
	    rsig = analysis->spec->kill_on_close_sig;
	vdebug(5,LA_XML,LF_XML,
	       "killing analysis pgid %d with signal %d\n",apid,rsig);
	if (kill(-apid,rsig) < 0) {
	    vwarn("kill(%d,%d): %s\n",apid,rsig,strerror(errno));
	}
    }

    if ((retval = analysis_close(analysis)) != ASTATUS_DONE) {
	verror("could not close analysis %d (error %d)!\n",analysis->id,retval);
    }

    return 0;
}

static int analysis_rpc_monitor_fini(struct monitor *monitor,
				     void *obj,void *objstate) {
    struct analysis *analysis = (struct analysis *)obj;
    if (!obj)
	return 0;
    if (analysis->target_spec) {
	target_free_spec(analysis->target_spec);
	analysis->target_spec = NULL;
    }
    else if (analysis->target && analysis->target->spec) {
	target_free_spec(analysis->target->spec);
	analysis->target->spec = NULL;
    }
    analysis_free(analysis);
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

struct analysis_rpc_listener_event_data {
    GHashTable *reftab;
    struct vmi1__AnalysisEventT event;
    struct vmi1__AnalysisEventNotificationResponse r;
    result_t retval;
};

static int _analysis_rpc_notify_listener_event(struct generic_rpc_listener *l,
					       int is_owner,void *data) {
    result_t retval;
    struct analysis_rpc_listener_event_data *d = \
	(struct analysis_rpc_listener_event_data *)data;
    int rc;

    rc = soap_call_vmi1__AnalysisEventNotification(&l->soap,l->url,NULL,
						   &d->event,&d->r);
    if (rc != SOAP_OK) {
	if (l->soap.error == SOAP_EOF && l->soap.errnum == 0) {
	    vwarn("timeout notifying %s; removing!",l->url);
	}
	else {
	    verrorc("AnalysisEvent client call failure %s : ",
		    l->url);
	    soap_print_fault(&l->soap,stderr);
	}
	/* Let generic_rpc do this... */
	//soap_closesock(&lad->soap);
	return -1;
    }

    retval = x_ResultT_to_t_result_t(&l->soap,d->r.result);
    if (is_owner) {
	//if (retval > lad->retval)
	d->retval = retval;

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

int analysis_rpc_notify_listeners_event(struct analysis *analysis,
					enum _vmi1__analysisEventType type) {
    struct soap encoder;
    struct analysis_rpc_listener_event_data d;

    memset(&d,0,sizeof(d));

    /*
     * We only want to build the gsoap data struct once -- so we have to
     * set up a temp soap struct to do that on.  We can't use the
     * per-listener soap struct yet cause we don't have it until we're
     * in the iterator above.
     */
    soap_init(&encoder);
    d.reftab = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);
    d.retval = RESULT_SUCCESS;
    d.event.analysisEventType = type;
    d.event.analysisId = analysis->id;
    a_analysis_status_t_to_x_AnalysisStatusT(&encoder,analysis->status,
					     d.reftab,&d.event.analysisStatus);

    generic_rpc_listener_notify_all(RPC_SVCTYPE_ANALYSIS,analysis->id,
				    _analysis_rpc_notify_listener_event,&d);
    /*
     * Clean up temp/serialization data, but don't kill the sock if we
     * can avoid it.
     */
    g_hash_table_destroy(d.reftab);
    soap_destroy(&encoder);
    soap_end(&encoder);
    soap_done(&encoder);

    return 0;
}

static int analysis_rpc_monitor_event(struct monitor *monitor,
				      monitor_event_t event,
				      int objid,void *obj) {
    struct analysis *a = (struct analysis *)obj;

    vdebug(5,LA_XML,LF_RPC,"analysis id %d (event %d)\n",
	   a->id,event);

    if (event != MONITOR_EVENT_CHILD_DIED)
	return 0;

    /*
     * Send notification.
     */
    analysis_rpc_notify_listeners_event(a,_vmi1__analysisEventType__exited);

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
