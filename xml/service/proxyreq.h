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

#ifndef __PROXYREQ_H__
#define __PROXYREQ_H__

#include <stdsoap2.h>
#include <stdlib.h>

#include "evloop.h"
#include "monitor.h"

/*
 * Our multithreaded, gSOAP-based servers sometimes need to "proxy"
 * request handling.  Why?  If the RPC request is to pause a target
 * (monitored by the server via a server thread attached to the target
 * via ptrace), or to pause an analysis (monitored by the server thread
 * that created the analysis, and interacted with by incoming
 * request-handler threads), we need to make sure the request is handled
 * in the thread that is attached to the target/analysis.  This is
 * necessary for targets that are built on the ptrace API, and also
 * allows us to enforce serialization of request handling... but it is
 * primarily driven by the ptrace API.  With ptrace, only one thread can
 * attach to another thread, and only that thread can interact with the
 * monitored thread's CPU/memory state or control it via ptrace.  Not
 * all debugged entities may have a similar requirement, but
 * fundamentally, only a single control thread should access a debugged
 * entity at a single time -- all debugging actions must be coordinated
 * through a common controller -- so overall, this model is reasonable.
 *
 * (The other way to have constructed our server would have been to have
 * created a new server, on a different port, for each target and
 * analysis we launch.  This model seemed unattractive earlier on
 * because it requires basically a launchpad/registry server that
 * redirects new target/analysis requests to another server that does
 * the work on a different port, and because it completely prohibits
 * debuginfo sharing (until we solve that problem elsewhere).  However,
 * this need to proxy RPCs to specific handler threads turned out to be
 * a real pain, and I wish I had done the new-server-per-target/analysis
 * thing even though it's less elegant.)
 *
 * Anyway, this means that some RPCs must be "redirected" to the
 * target/analysis control thread that is attached to the
 * target/analysis.  We have to have gsoap process the incoming request
 * enough to obtain the target/analysis id, and because of the way gsoap
 * is built, the best we can do is buffer the whole incoming request,
 * see what object (target/analysis) it is destined for, stop serving
 * the request in the request handling thread, and pass the original
 * request bytes to that entity and *reprocess* the request.  Yes, this
 * sucks; more details later.
 * 
 * A request-handler thread in a server handles incoming SOAP requests,
 * "proxies" them (i.e., the gSOAP code parses the request and invokes
 * the RPC function), and either passes them to another thread/process
 * for handling, OR responds directly.
 *
 * Some requests don't end up getting proxied; they are handled simply in
 * the request handling thread.  If soap->error is set to SOAP_STOP,
 * that means that the RPC function proxied the request, and the request
 * needs to be passed to the thread/process (i.e., target or analysis)
 * that it is destined for.  All proxied requests are synchronous (from
 * the perspective of the client, at least), and are handled serially in
 * order of arrival.
 *
 *   In the case where the destination is a thread, the request and soap
 *   object is queued for the handling thread, and the request thread
 *   returns, leaving its gsoap state intact.  The monitor thread
 *   receives notification of the monitor msg over a monitor pipe, and
 *   handles the request, responds directly to the client, and
 *   terminates the gsoap state and client connection.
 *
 *   In the case where the destination is a process, the request is
 *   marshalled into a monitor msg, and the request thread forwards that
 *   to the monitor and returns, leaving its gsoap state intact.  The
 *   monitor services it using a dummy gsoap object, and responds with
 *   the XML response as a monitor msg.  Then, the monitor thread
 *   "coerces" the gsoap object into just sending a response directly.
 *
 * This does mean that any requests that *might* need to be proxied must
 * be buffered and processed twice by gsoap, because gsoap does not
 * expose its internal demux-to-RPC function mechanism (and we can't
 * just hack up a call to the RPC function dynamically, with
 * already-processed arguments, without some function interface -- well,
 * we *could*, maybe, but it's not worth it).
 *
 * But worse, for processes, we must buffer the response XML *fully*,
 * then let the request thread send the response.  In the future, we
 * might be able to make it zero-copy via mmap, but not yet.
 */

#define PROXYREQ_MAXSIZE 1024 * 1024 * 4096 // 4MB

typedef enum {
    PROXYREQ_STATE_NEW = 0,
    PROXYREQ_STATE_BUFFERED = 1,
    PROXYREQ_STATE_PROCESSING = 2,
    PROXYREQ_STATE_SERVING = 3,
    PROXYREQ_STATE_DONE = 4,
} proxyreq_state_t;

struct proxyreq {
    /*
     * The request-handling thread that initiated the request.  We use
     * this as a unique ID for the request, even though the monitor
     * thread will handle the response.
     *
     * (We should also point out that we don't need a unique ID for
     * threads at the moment, since proxied request RPCs are handled
     * serially.  But monitor messages have IDs, so we make requests
     * have them too, since requests are sent as monitor messages.)
     */
    unsigned long tid;

    proxyreq_state_t state;

    /*
     * Each proxied request is associated with a monitor.  RPCs that
     * instantiate a new monitored object (target or analysis), or are
     * destined to an existing object, must set the @monitor field.
     */
    struct monitor *monitor;
    void *obj;

    /*
     * If this request instantiated the monitor, @monitor_is_new is
     * set.
     */
    uint8_t monitor_is_new;

    /* The soap struct associated with this request. */
    struct soap *soap;

    /*
     * Various processing state as we proxy the request.
     */

    /* Set to the gsoap frecv to get the real data. */
    size_t (*orig_frecv)(struct soap *soap,char *s,size_t n);
    /* Set to the gsoap fclose to temporarily prevent sock close. */
    int (*orig_fclose)(struct soap *soap);

    /*
     * Request/response buffer info.
     */
    char *buf;
    int len;
    int bufsiz;
    int bufidx;
};

/*
 * Creates a proxy request associated with @monitor, and prepares @soap
 * to capture the request.
 *
 * (Must be called before a soap_serve() call so it can capture the whole
 * incoming request.)
 */
struct proxyreq *proxyreq_create(struct soap *soap);

/*
 * Creates a proxy request associated with @buf that was passed to a
 * monitored child from a monitor, and creates a soap struct set up to
 * replay the forwarded request.
 *
 * (Must be called before a soap_serve() call so it can replay the whole
 * incoming request.)
 */
struct proxyreq *proxyreq_create_proxied(char *buf,int buflen);

/*
 * Attaches @monitor to @pr.  Must be called before actually proxying a
 * request!
 */
int proxyreq_attach(struct proxyreq *pr,struct monitor *monitor);

/*
 * Attaches a new @monitor to @pr.  Must be called before actually proxying a
 * request!
 */
int proxyreq_attach_new(struct proxyreq *pr,struct monitor *monitor);

/*
 * Frees a proxy request.
 */
void proxyreq_free(struct proxyreq *pr);

/*
 * Detaches (and cleans up!) a soap struct from a proxyreq.
 *
 * (User should not have to call this; proxyreq_free calls it.)
 */
void proxyreq_detach_soap(struct proxyreq *pr);

/*
 * Frees a proxy request *buffer*.  Only call when you want the buffer
 * freed (i.e., so it doesn't hang around during request processing)
 * without freeing the proxy request itself (because it still needs to
 * be processed and completed).
 */
void proxyreq_free_buffer(struct proxyreq *pr);

/**
 ** The following basically interact with monitors via messages or the
 ** msg_obj hashtable.  They also interact with gsoap to effect the
 ** proxying.
 **/

/*
 * Receives and handles the request from @pr->monitor.  For threads, can
 * just pull the msg out of the monitor's hashtable; for processes, has
 * to read it from the monitor msg.
 *
 * Receiving/handling/response is synchronous w.r.t. requests, so it all
 * happens here.
 *
 * For threads, we have to adjust the soap struct's receive functions to
 * use some of ours, to replay back the request during soap_serve().
 *
 * For processes, we have to create a fake proxyreq and soap struct,
 * setup the state to replay the request AND setup the output functions
 * to write only to our buffer, then call soap_serve, then send the
 * resulting buffer as a response msg to the monitor.
 */
int proxyreq_recv_request(struct monitor *monitor,struct monitor_msg *msg);

/*
 * Receives and handles an incoming response from @pr->monitor.
 *
 * For threads, this function is not currently used (because the thread
 * monitor can respond directly via soap_serve()).
 *
 * For processes, 
 */
int proxyreq_recv_response(struct monitor *monitor,struct monitor_msg *msg);

/*
 * Sends the request to @pr->monitor via monitor_sendfor().
 */
int proxyreq_send_request(struct proxyreq *pr);

/*
 * Sends a response to @pr->monitor as a monitor_msg from a process via
 * monitor_child_sendfor().
 */
int proxyreq_send_response(struct proxyreq *pr);

/*
 * "Call" in the RPC once you know if you would proxy or not.  Calls
 * either proxyreq_send_request to forward the request to a proxy or
 * allows the RPC to execute normally.
 *
 * Also unlocks @mutex if non-NULL if it returns an error.
 */
#define PROXY_REQUEST_LOCKED(soap,mobj,mobjid,mutex) {			\
    struct proxyreq *_pr;						\
    int _rc;								\
    _pr = (struct proxyreq *)(soap)->user;				\
    if (!_pr) {								\
        verror("no proxyreq state!\n");					\
	pthread_mutex_unlock(mutex);					\
	return SOAP_ERR;						\
    }									\
    if (_pr->state == PROXYREQ_STATE_NEW) {				\
	_pr->state = PROXYREQ_STATE_BUFFERED;				\
	_pr->obj = mobj;						\
	_pr->monitor = monitor_lookup(mobj);				\
	if (!_pr->monitor) {						\
	    verror("no monitor for object %d!\n",(mobjid));		\
	    pthread_mutex_unlock(mutex);				\
	    return SOAP_ERR;						\
	}								\
	if ((_rc = proxyreq_send_request(_pr))) {			\
	    verror("proxyreq_send_request error %d\n",_rc);		\
	    pthread_mutex_unlock(mutex);				\
	    return SOAP_ERR;						\
	}								\
	pthread_mutex_unlock(mutex);					\
	return SOAP_STOP;						\
    }									\
    else if (_pr->state == PROXYREQ_STATE_PROCESSING) {			\
	_pr->state = PROXYREQ_STATE_SERVING;				\
	/* Free the request buffer, allowing us to create a response 	\
	 * buf in its place if necessary.				\
	 */								\
	if (_pr->buf) {							\
	    free(_pr->buf);						\
	    _pr->buf = NULL;						\
	    _pr->len = _pr->bufsiz = _pr->bufidx = 0;			\
	}								\
	if (_pr->orig_fclose) {						\
	    _pr->soap->fclose = _pr->orig_fclose;			\
	    _pr->orig_fclose = NULL;					\
	}								\
        /* Caller continues to normally execute RPC here... */		\
    }									\
    else {								\
	verror("unexpected proxyreq state %d; bug?!\n",_pr->state);	\
	pthread_mutex_unlock(mutex);					\
	return SOAP_ERR;						\
    }									\
}

#endif /* __PROXY_H__ */
