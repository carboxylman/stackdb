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

#include "log.h"
#include "monitor.h"
#include "proxyreq.h"

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

    memcpy(s,&pr->buf[pr->bufidx],retval);

    return retval;
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

struct proxyreq *proxyreq_create_proxied(char *buf,int buflen) {
    struct proxyreq *pr;
    struct soap *soap;

    soap = calloc(1,sizeof(*soap));
    soap->error = SOAP_OK;

    pr = calloc(1,sizeof(*pr));

    pr->tid = pthread_self();
    pr->state = PROXYREQ_STATE_BUFFERED;
    pr->soap = soap;

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

int proxyreq_attach_monitor(struct proxyreq *pr,struct monitor *monitor) {
    if (pr->monitor) {
	verror("proxyreq already attached to a monitor!\n");
	return SOAP_ERR;
    }

    pr->monitor = monitor;
    /*
     * We save off the object separately in case the monitor disappears
     * asynchronous w.r.t. our functions; this helps us avoid locking
     * the monitor's (and the global monitor lock) lock prior to send.
     * This way, if the monitored object has vanished during the call
     * chain that got us here, we still safely error.
     *
     * See monitor_sendfor
     */
    pr->obj = monitor->obj;

    return SOAP_OK;
}

int proxyreq_attach_new(struct proxyreq *pr,struct monitor *monitor) {
    int rc;

    rc = proxyreq_attach_monitor(pr,monitor);
    if (rc != SOAP_OK)
	return rc;

    pr->monitor_is_new = 1;

    return SOAP_OK;
}

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
    if (!(monitor->flags & MONITOR_FLAG_BIDI)) {
	msg = monitor_msg_create(pr->tid,1,0,NULL);
    }
    else {
	msg = monitor_msg_create(pr->tid,1,pr->len,pr->buf);

	pr->buf = NULL;
	pr->len = pr->bufsiz = pr->bufidx = 0;
    }

    /*
     * Associate pr as the "msg_obj" in the monitor's hashtable, for
     * later use.
     */
    rc = monitor_sendfor(pr->obj,msg,pr);

    /* This results in the buffer being freed for msgs over BIDI pipes;
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

    if (pr->state != PROXYREQ_STATE_PROCESSING) {
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
     * This is tricky.  We NULL out the buffer in pr once the message
     * has been created.  Then once the message is sent, we fully free
     * the msg, which frees the original request buffer.  We have to do
     * it in this sequence because if we tried to alter the proxyreq
     * *after* sending, and the child happens to respond to it first, it
     * could get overwritten before we can free it.  Of course, that is
     * all but impossible, but we're careful.
     */
    msg = monitor_msg_create(pr->tid,2,pr->len,pr->buf);

    pr->buf = NULL;
    pr->len = pr->bufsiz = pr->bufidx = 0;

    /* DO NOT associate pr as the "msg_obj" in the monitor's hashtable;
     * there is no later use.
     */
    rc = monitor_child_sendfor(pr->obj,NULL,msg);
    monitor_msg_free(msg);
    if (rc) {
	verror("could not send msg to monitor!\n");
	return SOAP_ERR;
    }

    return SOAP_OK;
}

int proxyreq_recv_request(struct monitor *monitor,struct monitor_msg *msg) {
    struct proxyreq *pr;
    struct soap *soap;

    if (!(pr = (struct proxyreq *)monitor_get_msg_obj(monitor,msg->id))) {
	pr = proxyreq_create_proxied(msg->msg,msg->len);

	soap = pr->soap;

	pr->state = PROXYREQ_STATE_PROCESSING;

	soap_serve(soap);

	/* XXX: get rid of these!  They pollute child STDERR! */
	if (soap->error == SOAP_OK) {
	    vdebug(5,LOG_X_RPC,
		   "finished proxied request from %d.%d.%d.%d\n",
		   (soap->ip >> 24) & 0xff,(soap->ip >> 16) & 0xff,
		   (soap->ip >> 8) & 0xff,soap->ip & 0xff);
	}
	else {
	    vdebug(5,LOG_X_RPC,
		   "failingly finished proxy request from %d.%d.%d.%d\n",
		   (soap->ip >> 24) & 0xff,(soap->ip >> 16) & 0xff,
		   (soap->ip >> 8) & 0xff,soap->ip & 0xff);
	}

	proxyreq_send_response(pr);

	proxyreq_free(pr);

	soap_destroy(soap);
	soap_end(soap);
	soap_done(soap);
	free(soap);
    }
    else {
	/* Use the soap struct in the existing proxyreq. */
	soap = pr->soap;

	proxyreq_switchto_proxied(pr);

	pr->state = PROXYREQ_STATE_PROCESSING;

	soap_serve(soap);

	if (soap->error == SOAP_OK) {
	    vdebug(5,LOG_X_RPC,
		   "finished proxy request from %d.%d.%d.%d\n",
		   (soap->ip >> 24) & 0xff,(soap->ip >> 16) & 0xff,
		   (soap->ip >> 8) & 0xff,soap->ip & 0xff);
	}
	else {
	    vdebug(5,LOG_X_RPC,
		   "failingly finished proxy request from %d.%d.%d.%d\n",
		   (soap->ip >> 24) & 0xff,(soap->ip >> 16) & 0xff,
		   (soap->ip >> 8) & 0xff,soap->ip & 0xff);
	}

	proxyreq_free(pr);

	soap_destroy(soap);
	soap_end(soap);
	soap_done(soap);
	free(soap);
    }

    return 0;
}

int proxyreq_recv_response(struct monitor *monitor,struct monitor_msg *msg) {
    // XXX: write
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

    pr->monitor = NULL;
    pr->obj = NULL;

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
