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

    vdebug(5,LA_XML,LF_RPC,"fd %d recv '%s' (%d)\n",fd,buf,len);

    /*
     * Don't go to any effort if we don't need to...
     */
    if (!a->desc->supports_autoparse_simple_results)
	return 0;
    else if (generic_rpc_count_listeners(RPC_SVCTYPE_ANALYSIS,a->id) < 1)
	return RESULT_SUCCESS;

    rc = sscanf(buf,"RESULT(i:%d): %ms (%d) %ms \"%m[^\"]\" (%m[^)])",
		&id,&name,&type,&result_value,&msg,&value_str);
    if (rc >= 4) {
	datum = analysis_create_simple_datum(a,id,name,type,result_value,msg,1);
	if (value_str) {
	    while ((token = strtok_r(saveptr ? NULL : value_str,",",&saveptr))) {
		ptr = index(token,'=');
		if (!ptr) {
		    vwarn("bad autoparse value token '%s'; skipping!\n",token);
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

    /* Setup the analysis binary full path to launch. */
    len = strlen(path) + 1 + strlen(d->binary) + 1;
    binarypath = calloc(len,sizeof(char));
    snprintf(binarypath,len,"%s/%s",path,d->binary);

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
	len = sizeof("target.stdin.") + 11 + 1;
	ts->infile = malloc(len * sizeof(char));
	snprintf(ts->infile,len,"target.stdin.%u",ts->target_id);

	/* NB: write the stdin file below, once we have a tmpdir! */
    }
    if (targetSpec->logStdout && *targetSpec->logStdout == xsd__boolean__true_) {
	len = sizeof("target.stdout.") + 11 + 1;
	ts->outfile = malloc(len * sizeof(char));
	snprintf(ts->outfile,len,"target.stdout.%u",ts->target_id);
    }
    if (targetSpec->logStderr && *targetSpec->logStderr == xsd__boolean__true_) {
	len = sizeof("target.stderr.") + 11 + 1;
	ts->errfile = malloc(len * sizeof(char));
	snprintf(ts->errfile,len,"target.stderr.%u",ts->target_id);
    }

    if (target_spec_to_argv(ts,binarypath,&targc,&targv)) {
	err = err_detail = "Could not create argv from target spec!";
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

    /*
     * Setup its tmp dir.  This means writing out any support files it
     * needs (right now just the target's stdin, if any).
     * <ANALYSIS_TMPDIR>/<name>.<id>
     */
    len = strlen(ANALYSIS_TMPDIR) + sizeof("/vmi.analysis.") \
	+ strlen(as->name) + sizeof(".") + 11 + 1 + 11 + 1;
    a->tmpdir = malloc(len * sizeof(char));
    snprintf(a->tmpdir,len,"%s/vmi.analysis.%s.%d.%u",
	     ANALYSIS_TMPDIR,as->name,aid,rand());
    if (stat(a->tmpdir,&statbuf) == 0) 
	vwarn("analysis tmpdir %s already exists!\n",a->tmpdir);

    mkdir(ANALYSIS_TMPDIR,S_IRWXU | S_IRGRP | S_IXGRP);
    if (mkdir(a->tmpdir,S_IRWXU | S_IRGRP | S_IXGRP)) {
	verror("could not create analysis tmpdir %s: %s!\n",
	       a->tmpdir,strerror(errno));
	err = err_detail = "Could not create analysis tmpdir!";
	goto errout;
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

	monitor_setup_stdout(monitor,-1,tmpbuf,analysis_rpc_stdout_callback,a);
    }
    if (analysisSpec->logStderr 
	&& analysisSpec->logStderr == xsd__boolean__true_) {
	len = strlen(a->tmpdir) + sizeof("/analysis.stderr.") + 11 + 1;
	as->errfile = malloc(len);
	snprintf(as->errfile,len,"%s/analysis.stderr.%d",a->tmpdir,aid);

	monitor_setup_stderr(monitor,-1,tmpbuf,analysis_rpc_stderr_callback,a);
    }

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
	if (as) 
	    analysis_spec_free(as);
	if (d)
	    analysis_desc_free(d);
    }
    if (ts)	   
	target_free_spec(ts);
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

    if ((retval = analysis_close(analysis)) != ASTATUS_DONE) {
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
