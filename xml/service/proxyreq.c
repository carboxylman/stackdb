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
#include "monitor.h"
#include "proxyreq.h"

/**
 ** The main function this library exposes to servers.
 **/
int proxyreq_handle_request(struct soap *soap,char *svc_name) {
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

	PROXY_REQUEST_HANDLE_STOP(soap);

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

	    snprintf(name,16,"%s_m_%d",svc_name,monitor->objid);
	    prctl(PR_SET_NAME,name,NULL,NULL,NULL);

	    proxyreq_free(pr);
	    soap_destroy(soap);
	    soap_end(soap);
	    soap_done(soap);
	    free(soap);

	    while (1) {
		rc = monitor_run(monitor);
		if (rc < 0) {
		    verror("bad internal error in monitor for %s %d; destroying!\n",
			   svc_name,monitor->objid);
		    monitor_destroy(monitor);
		    return -1;
		}
		else {
		    if (monitor_is_done(monitor)) {
			vdebug(2,LA_XML,LF_RPC,
			       "monitoring on %s %d is done;"
			       " closing (not finalizing)!\n",
			       svc_name,monitor->objid);
			monitor_shutdown(monitor);
			return 0;
		    }
		    else if (monitor_is_halfdead(monitor)) {
			vwarn("%s %d monitor child died unexpectedly;"
			      " closing (not finalizing)!\n",
			      svc_name,monitor->objid);
			monitor_shutdown(monitor);
			return -1;
		    }
		    else if (monitor_should_self_finalize(monitor)) {
			vwarn("forked %s %d finalizing!\n",
			      svc_name,monitor->objid);
			monitor_destroy(monitor);
			return 0;
		    }
		    else {
			vwarn("%s %d monitor_run finished unexpectedly;"
			      " closing (not finalizing)!\n",
			      svc_name,monitor->objid);
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
 ** These functions override the gsoap handlers when we are using proxy
 ** requests.
 **/
/*
 * Saves a request into a buffer for later use.  Uses the default gsoap
 * receiver function to read from the real source during save.
 *
 * (gsoap documentation:
 *    Called for all receive operations to fill buffer s of maximum length
 *    n. Should return the number of bytes read or 0 in case of an error,
 *    e.g. EOF. Built-in gSOAP function: frecv)
 */
static size_t _soap_proxyreq_frecv_save(struct soap *soap,char *s,size_t n) {
    struct proxyreq *pr;
    size_t retval = 0;
    char *tmp;

    pr = (struct proxyreq *)soap->user;

    if (!pr) {
	verror("no proxyreq state!\n");
	return soap_receiver_fault(soap,"Internal error!",
				   "Internal error: no proxyreq state!");
    }

    if (!pr->buf) {
	pr->bufsiz = 4096;
	pr->buf = malloc(pr->bufsiz);
	pr->len = 0;
	pr->bufidx = 0;
    }

    retval = pr->orig_frecv(soap,s,n);

    if (retval > 0) {
	if (retval > (size_t)(pr->bufsiz - pr->len)) {
	    tmp = malloc(pr->bufsiz + 4096);
	    memcpy(tmp,pr->buf,pr->bufsiz);
	    free(pr->buf);
	    pr->buf = tmp;
	    pr->bufsiz += 4096;
	}
	memcpy(&pr->buf[pr->len],s,retval);
	pr->len += retval;
    }

    return retval;
}

/*
 * Reads a request from a saved proxy request.
 */
static size_t _soap_proxyreq_frecv_read(struct soap *soap,char *s,size_t n) {
    struct proxyreq *pr;
    size_t retval = 0;

    pr = (struct proxyreq *)soap->user;
    if (!pr) {
	verror("no proxyreq!\n");
	return soap_receiver_fault(soap,"Internal error!",
				   "Internal error: no proxyreq!");
    }

    retval = pr->len - pr->bufidx;
    retval = (n > retval) ? retval : n;

    if (retval > 0) {
	memcpy(s,&pr->buf[pr->bufidx],retval);

	pr->bufidx += retval;

	soap->error = SOAP_OK;
    }
    else {
	soap->error = SOAP_OK;

	pr->state = PROXYREQ_STATE_PROCESSING;

	vdebug(5,LA_XML,LF_RPC,"finished injecting %d bytes!\n",pr->len);

	/*
	 * Set up for _soap_proxyreq_fsend!
	 *
	 * XXX: free the buf???
	 */
	pr->buf = NULL;
	pr->len = pr->bufidx = pr->bufsiz = 0;
    }

    return retval;
}

/*
 * Sends a whole buffered gsoap response as a proxyreq response.
 */
static int _soap_proxyreq_fsend(struct soap *soap,const char *s,size_t n) {
    struct proxyreq *pr;

    pr = (struct proxyreq *)soap->user;
    if (!pr) {
	verror("no proxyreq!\n");
	return soap_receiver_fault(soap,"Internal error!",
				   "Internal error: no proxyreq!");
    }

    if (!pr->buf) {
	pr->bufsiz = (n > 1024) ? n : 1024;
	pr->buf = malloc(pr->bufsiz);
    }
    else if ((unsigned)(pr->bufsiz - pr->len) < n) {
	pr->bufsiz += ((n - (pr->bufsiz - pr->len)) > 1024) \
	    ? n - (pr->bufsiz - pr->len) : 1024;
	if (!realloc(pr->buf,pr->bufsiz)) {
	    verror("could not increase buf from %d to %d!\n",pr->len,pr->bufsiz);
	    free(pr->buf);
	    pr->bufidx = pr->bufsiz = pr->len = 0;
	    return SOAP_EOF;
	}
    }

    memcpy(pr->buf + pr->len,s,n);
    pr->len += n;

    return 0;
}

static int _soap_proxyreq_noclose(struct soap *soap) {
    return SOAP_OK;
}

/**
 ** proxyreq API implementation.
 **/
struct proxyreq *proxyreq_create(struct soap *soap) {
    struct proxyreq *pr;

    if (soap->user) {
	verror("soap->user already set; already proxied this request?!\n");
	return NULL;
    }

    pr = calloc(1,sizeof(*pr));

    pr->tid = pthread_self();
    pr->state = PROXYREQ_STATE_NEW;
    pr->soap = soap;

    soap->user = pr;

    /*
     * Adjust soap struct to save off the request as it processes it the
     * first time.
     */
    pr->orig_frecv = soap->frecv;
    soap->frecv = _soap_proxyreq_frecv_save;

    pr->orig_fclose = soap->fclose;
    soap->fclose = _soap_proxyreq_noclose;

    /*
     * Note: we do not have to worry about the gsoap sock; it is already
     * set CLOEXEC, so we can fork safely if we need to.
     */

    return pr;
}

struct proxyreq *proxyreq_create_proxied(int objid,char *buf,int buflen) {
    struct proxyreq *pr;
    struct soap *soap;
    struct monitor *monitor = NULL;

    if (!monitor_lookup_objid(objid,NULL,NULL,&monitor)) {
	verror("no monitor for object %d!\n",objid);
	return NULL;
    }

    soap = calloc(1,sizeof(*soap));
    soap_init(soap);
    //soap->error = SOAP_OK;

    pr = calloc(1,sizeof(*pr));

    pr->monitor = monitor;
    pr->tid = pthread_self();
    pr->state = PROXYREQ_STATE_BUFFERED;
    pr->soap = soap;

    pr->objid = objid;

    pr->buf = buf;
    pr->len = buflen;
    pr->bufsiz = buflen;
    pr->bufidx = 0;

    soap->user = pr;

    /*
     * Adjust soap struct to replay the request as it processes it the
     * "second" time.
     */
    pr->orig_frecv = soap->frecv;
    soap->frecv = _soap_proxyreq_frecv_read;

    /*
     * Adjust soap struct to send a proxyreq response when it finishes.
     * Also, force it to buffer the response internally before sending
     * anything.  This ensures we send a complete response, which is
     * what we want to do.  Wait, this doesn't work; even SOAP_IO_STORE
     * buffering results in two part msgs: the HTTP header, and the
     * content :(.  Still buffer internally to avoid lots of
     * mallocs/memcpys hopefully, but this stinks a bit.
     */
    pr->orig_fsend = pr->soap->fsend;
    pr->soap->fsend = _soap_proxyreq_fsend;

    /* Force it to buffer internally. */
    soap_set_omode(pr->soap,SOAP_IO_STORE);

    return pr;
}

int proxyreq_switchto_proxied(struct proxyreq *pr) {
    pr->state = PROXYREQ_STATE_BUFFERED;

    /*
     * Adjust soap struct to replay the request as it processes it the
     * "second" time.
     */
    pr->orig_frecv = pr->soap->frecv;
    pr->soap->frecv = _soap_proxyreq_frecv_read;

    return 0;
}

int proxyreq_attach_objid(struct proxyreq *pr,int objid) {
    if (pr->monitor) {
	verror("proxyreq already attached to a monitor!\n");
	return SOAP_ERR;
    }

    if (!monitor_lookup_objid(objid,NULL,NULL,&pr->monitor)) {
	verror("no monitor for object %d!\n",objid);
	return SOAP_ERR;
    }

    /*
     * We save off the object separately in case the monitor disappears
     * asynchronous w.r.t. our functions; this helps us avoid locking
     * the monitor's (and the global monitor lock).
     */
    pr->objid = objid;

    return SOAP_OK;
}

int proxyreq_attach_new_objid(struct proxyreq *pr,int objid,
			      struct monitor *monitor) {
    if (pr->monitor) {
	verror("proxyreq already attached to a monitor!\n");
	return SOAP_ERR;
    }

    pr->monitor = monitor;
    /*
     * We save off the object separately in case the monitor disappears
     * asynchronous w.r.t. our functions; this helps us avoid locking
     * the monitor's (and the global monitor lock).
     */
    pr->objid = objid;

    pr->monitor_is_new = 1;

    return SOAP_OK;
}

/*
 * Msg commands.
 */
#define PROXYREQ_REQUEST  1
#define PROXYREQ_RESPONSE 2

int proxyreq_send_request(struct proxyreq *pr) {
    struct monitor *monitor;
    int rc;
    struct monitor_msg *msg;

    if (pr->state != PROXYREQ_STATE_BUFFERED) {
	verror("request in bad state %d!\n",pr->state);
	errno = EINVAL;
	return SOAP_ERR;
    }

    monitor = pr->monitor;

    /*
     * This is tricky.  We NULL out the buffer in pr once the message
     * has been created.  Then once the message is sent, we fully free
     * the msg, which frees the original request buffer.  We have to do
     * it in this sequence because if we tried to alter the proxyreq
     * *after* sending, and the child happens to respond to it first, it
     * could get overwritten before we can free it.  Of course, that is
     * all but impossible, but we're careful.
     */
    /*
     * Also, if it is unidirectional, assume that the child can access
     * @pr in its address space, so don't send the request over the
     * pipe; trust that it can retrieve pr as a msg_obj later.
     */
    if (monitor->type == MONITOR_TYPE_THREAD) {
	msg = monitor_msg_create(pr->objid,-1,PROXYREQ_REQUEST,1,
				 0,NULL,pr);
    }
    else {
	/*
	 * Associate pr as the "msg_obj" in the monitor's hashtable, for
	 * later use.
	 */
	msg = monitor_msg_create(pr->objid,-1,PROXYREQ_REQUEST,1,
				 pr->len,pr->buf,pr);

	pr->buf = NULL;
	pr->len = pr->bufsiz = pr->bufidx = 0;
    }

    rc = monitor_send(msg);

    /* This results in the buffer being freed for msgs to
     * MONITOR_TYPE_PROCESS monitored children;
     * in the other case, we assume that whoever uses @pr (the receiver
     * of our 0-len notification msg will free it).
     */
    monitor_msg_free(msg);

    if (rc) {
	verror("could not send msg to monitored child!\n");
	return SOAP_ERR;
    }

    return SOAP_OK;
}

int proxyreq_send_response(struct proxyreq *pr) {
    struct monitor *monitor;
    int rc;
    struct monitor_msg *msg;

    if (pr->state != PROXYREQ_STATE_SERVING) {
	verror("request in bad state %d!\n",pr->state);
	errno = EINVAL;
	return SOAP_ERR;
    }

    monitor = pr->monitor;

    if (!(monitor->flags & MONITOR_FLAG_BIDI)) {
	verror("monitor is not bidirectional!\n");
	errno = EINVAL;
	return SOAP_ERR;
    }

    /*
     * We just send the contents of pr->buf using pr->len as the
     * length.  WE DO NOT FREE THE BUFFER -- we just null them out.
     * It's the caller's job to handle that.
     *
     * DO NOT associate pr as the "msg_obj" in the monitor's hashtable;
     * there is no later use.  If we ever did need to send chunked
     * messages, this would be how we would do it.
     */
    msg = monitor_msg_create(pr->objid,-1,PROXYREQ_RESPONSE,1,
			     pr->len,pr->buf,NULL);

    rc = monitor_child_send(msg);
    monitor_msg_free_save_buffer(msg);

    if (rc) {
	verror("could not send msg to monitor!\n");
	return SOAP_ERR;
    }

    pr->buf = NULL;
    pr->len = pr->bufsiz = pr->bufidx = 0;

    return SOAP_OK;
}

int proxyreq_recv_request(struct monitor *monitor,struct monitor_msg *msg) {
    struct proxyreq *pr;
    struct soap *soap;

    if (!(pr = (struct proxyreq *)msg->msg_obj)) {
	pr = proxyreq_create_proxied(msg->objid,msg->msg,msg->len);
	/* Steal the message's buf in proxyreq_create_proxied. */
	msg->len = 0;
	msg->msg = NULL;

	soap = pr->soap;

	pr->state = PROXYREQ_STATE_PROCESSING;

	soap_serve(soap);

	/* XXX: get rid of these!  They pollute child STDERR! */
	if (soap->error == SOAP_OK) {
	    vdebug(5,LA_XML,LF_RPC,
		   "finished forked proxied request from %d.%d.%d.%d\n",
		   (soap->ip >> 24) & 0xff,(soap->ip >> 16) & 0xff,
		   (soap->ip >> 8) & 0xff,soap->ip & 0xff);
	}
	else {
	    vdebug(5,LA_XML,LF_RPC,
		   "failingly finished forked proxied request from %d.%d.%d.%d\n",
		   (soap->ip >> 24) & 0xff,(soap->ip >> 16) & 0xff,
		   (soap->ip >> 8) & 0xff,soap->ip & 0xff);
	}

	proxyreq_send_response(pr);
    }
    else {
	/* Use the soap struct in the existing proxyreq. */
	soap = pr->soap;

	proxyreq_switchto_proxied(pr);

	pr->state = PROXYREQ_STATE_PROCESSING;

	soap_serve(soap);

	if (soap->error == SOAP_OK) {
	    vdebug(5,LA_XML,LF_RPC,
		   "finished threaded proxied request from %d.%d.%d.%d\n",
		   (soap->ip >> 24) & 0xff,(soap->ip >> 16) & 0xff,
		   (soap->ip >> 8) & 0xff,soap->ip & 0xff);
	}
	else {
	    vdebug(5,LA_XML,LF_RPC,
		   "failingly finished threaded proxied request from %d.%d.%d.%d\n",
		   (soap->ip >> 24) & 0xff,(soap->ip >> 16) & 0xff,
		   (soap->ip >> 8) & 0xff,soap->ip & 0xff);
	}
    }

    //monitor_msg_free(msg);

    proxyreq_free(pr);

    soap_destroy(soap);
    soap_end(soap);
    soap_done(soap);
    free(soap);

    return 0;
}

int proxyreq_recv_response(struct monitor *monitor,struct monitor_msg *msg) {
    struct proxyreq *pr;
    struct soap *soap;

    if (!(pr = (struct proxyreq *)msg->msg_obj)) {
	verror("cannot associated a proxyreq request handler thread with monitor child msg!\n");
	return SOAP_ERR;
    }

    /*
     * We're in the monitor thread now; our original request thread
     * returned after it proxied the request.
     *
     * XXX: should have a thread pool for responses so we don't
     * block the main monitor thread on a response...
     */

    soap = pr->soap;

    /* Dump out the soap response. */
    soap_begin_send(soap);
    soap_send_raw(soap,msg->msg,msg->len);
    soap_end_send(soap);
    soap_closesock(soap);

    if (soap->error == SOAP_OK) {
	vdebug(5,LA_XML,LF_RPC,
	       "finished proxied request from %d.%d.%d.%d\n",
	       (soap->ip >> 24) & 0xff,(soap->ip >> 16) & 0xff,
	       (soap->ip >> 8) & 0xff,soap->ip & 0xff);
    }
    else {
	vdebug(5,LA_XML,LF_RPC,
	       "failingly finished proxy request from %d.%d.%d.%d\n",
	       (soap->ip >> 24) & 0xff,(soap->ip >> 16) & 0xff,
	       (soap->ip >> 8) & 0xff,soap->ip & 0xff);
    }

    monitor_msg_free(msg);

    proxyreq_free(pr);

    soap_destroy(soap);
    soap_end(soap);
    soap_done(soap);
    free(soap);

    return 0;
}

void proxyreq_detach_soap(struct proxyreq *pr) {
    if (!pr->soap)
	return;

    if (pr->orig_frecv) {
	pr->soap->frecv = pr->orig_frecv;
	pr->orig_frecv = NULL;
    }

    if (pr->orig_fclose) {
	pr->soap->fclose = pr->orig_fclose;
	pr->orig_fclose = NULL;
    }
}

void proxyreq_free_buffer(struct proxyreq *pr) {
    if (pr->buf) {
	free(pr->buf);
	pr->buf = NULL;
	pr->len = 0;
	pr->bufsiz = 0;
	pr->bufidx = 0;
    }
}

void proxyreq_free(struct proxyreq *pr) {
    
    if (pr->soap)
	proxyreq_detach_soap(pr);

    proxyreq_free_buffer(pr);

    pr->tid = -1;
    pr->monitor = NULL;
    pr->objid = -1;

    free(pr);
}


/*
 * "Call" in the RPC once you know if you would proxy or not.  Calls
 * either splitreq_split or splitreq_fini().
 */
#define THREAD_SPLITREQ(soap,tm) {					\
    struct splitreq *_sr;						\
    _sr = (struct splitreq *)(soap)->user;				\
    if (!_sr) {								\
        verror("no splitreq state!\n");					\
	return SOAP_ERR;						\
    }									\
    if ((soap)->frecv == splitreq_frecv_save) {				\
	splitreq_split((soap),0);					\
	/* XXX: normally have to queue for thread or send to pid */	\
	return SOAP_STOP;						\
    }									\
    else if ((soap)->frecv == splitreq_frecv_read)	{		\
	splitreq_fini(soap);						\
        /* Caller normally executes RPC here... */			\
    }									\
    else {								\
	verror("unexpected soap->frecv value; user error?!\n");		\
	return SOAP_ERR;						\
    }									\
}
#define FORK_SPLITREQ(soap,tm) {					\
    struct splitreq *_sr;						\
    struct splitreq_data srd;						\
									\
    _sr = (struct splitreq *)(soap)->user;				\
    if (!_sr) {								\
        verror("no splitreq state!\n");					\
	return SOAP_ERR;						\
    }									\
    if ((soap)->frecv == splitreq_frecv_save) {				\
        splitreq_split((soap),1);					\
	_srd.buf = _sr->buf;						\
	_srd.buflen = _sr->buflen;					\
	if (process_monitor_send_request(tm,&srd)) {			\
	    verror("could not send request to pid %d",tm->p.pid);	\
	    return SOAP_ERR;						\
	}								\
	else								\
	    return SOAP_STOP;						\
    }									\
    else if ((soap)->frecv == splitreq_frecv_read)	{		\
	splitreq_fini(soap);						\
        /* Caller normally executes RPC here... */			\
    }									\
    else {								\
	verror("unexpected soap->frecv value; user error?!\n");		\
	return SOAP_ERR;						\
    }									\
}
