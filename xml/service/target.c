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

#include <string.h>
#include <pthread.h>
#include <getopt.h>
#include <signal.h>

#include "log.h"

#include "target_rpc.h"
#include "debuginfo_rpc.h"
#include "util.h"
#include "waitpipe.h"
#include "monitor.h"
#include "proxyreq.h"

/* Pull in gsoap-generated namespace array. */
#include "target.nsmap"

/*
 * How we use proxy requests:
 *
 *   - do_request creates a proxyreq to record the request
 *   - soap_serve demuxes to the RPC, which associates an existing
 *     monitor or creates a new one
 *     - if existing, call proxyreq_send_req
 *       - if process, wait for a response
 *       - if thread, don't wait, but don't GC the soap struct
 *     - if new
 *       - if thread, call proxyreq_monitor() (which must use evloop and
 *         target_monitor stuff to loop in the control thread, handling
 *         both the target(s?) and new requests), and return success.
 *       - if process, return success after inserting monitor object.
 *         no control thread for this case.
 */

void *handle_request(void *arg) {
    struct soap *soap = (struct soap *)arg; //trs->soap;

    /* Server never waits for us. */
    pthread_detach(pthread_self());

    /* This does all the work. */
    target_rpc_handle_request(soap);

    return NULL;
}

void *sight(void *arg) {
    sigset_t *sigset = (sigset_t *)arg;
    int rc;
    siginfo_t siginfo;

    while (1) {
	memset(&siginfo,0,sizeof(siginfo));
	rc = sigwaitinfo(sigset,&siginfo);
	if (rc < 0) {
	    if (errno == EINTR || errno == EAGAIN)
		continue;
	    else {
		vwarn("sigwait: %s!\n",strerror(errno));
		exit(4);
	    }
	}
	else if (rc == SIGINT) {
	    vwarn("interrupted, exiting!\n");
	    exit(0);
	}
	else if (rc == SIGCHLD) {
	    waitpipe_notify(rc,&siginfo);
	    sigaddset(sigset,SIGCHLD);
	}
	else if (rc == SIGPIPE) {
	    vdebug(15,LA_XML,LF_SVC,"sigpipe!\n");
	    sigaddset(sigset,SIGPIPE);
	}
	else {
	    vwarn("unexpected signal %d; ignoring!\n",rc);
	}
    }

    return NULL;
}

extern char *optarg;
extern int optind, opterr, optopt;

int main(int argc, char **argv) {
    struct soap soap;
    struct soap *tsoap;
    pthread_t tid;
    pthread_t sigtid;
    int port = 0;
    SOAP_SOCKET m, s;
    char ch;
    int doelfsymtab = 1;
    sigset_t sigset;
    int rc;

    while ((ch = getopt(argc, argv, "dwl:Ep:")) != -1) {
	switch(ch) {
	case 'd':
	    vmi_inc_log_level();
	    break;
	case 'w':
	    vmi_inc_warn_level();
	    break;
	case 'l':
	    if (vmi_set_log_area_flaglist(optarg,NULL)) {
		fprintf(stderr,"ERROR: bad debug flag in '%s'!\n",optarg);
		exit(-1);
	    }
	    break;
	case 'E':
	    doelfsymtab = 0;
	    break;
	case 'p':
	    port = atoi(optarg);
	    break;
	default:
	    fprintf(stderr,"ERROR: unknown option %c!\n",ch);
	    exit(-1);
	}
    }

    argc -= optind;
    argv += optind;

    waitpipe_init_ext(NULL);
    dwdebug_init();
    debuginfo_rpc_init();
    target_rpc_init();

    atexit(target_rpc_fini);
    atexit(debuginfo_rpc_fini);
    atexit(dwdebug_fini);

    soap_init(&soap);
    //soap_set_omode(&soap,SOAP_XML_GRAPH);

    /*
     * If no args, assume this is CGI coming in on stdin.
     */
    if (!port) {
	soap_serve(&soap);
	soap_destroy(&soap);
	soap_end(&soap);
	return 0;
    }

    /*
     * Otherwise, let's serve forever!
     */
    soap.send_timeout = 60;
    soap.recv_timeout = 60;
    soap.accept_timeout = 0;
    soap.max_keep_alive = 100;

    /*
     * Create a thread for handling SIGINT, SIGCHLD, and SIGPIPE; the
     * other threads block all sigs.
     */
    sigemptyset(&sigset);
    //sigaddset(&sigset,SIGINT);
    sigaddset(&sigset,SIGCHLD);
    sigaddset(&sigset,SIGPIPE);
    if ((rc = pthread_sigmask(SIG_BLOCK,&sigset,NULL))) {
	verror("pthread_sigmask: %s\n",strerror(rc));
	exit(2);
    }

    if ((rc = pthread_create(&sigtid,NULL,&sight,(void *)&sigset))) {
	verror("pthread: %s\n",strerror(rc));
	exit(3);
    }

    m = soap_bind(&soap,NULL,port,64);
    if (!soap_valid_socket(m)) {
	verror("Could not bind to port %d: ",port);
	soap_print_fault(&soap,stderr);
	verrorc("\n");
	exit(1);
    }

    vdebug(5,LA_XML,LF_RPC,"bound to port %d\n",port);

    while (1) {
	s = soap_accept(&soap);
	if (!soap_valid_socket(s)) {
            if (soap.errnum) {
		verror("SOAP: ");
		soap_print_fault(&soap,stderr);
		exit(1);
            }
            verror("SOAP: server timed out\n");
            break;
	}
	vdebug(8,LA_XML,LF_RPC,"connection from %d.%d.%d.%d\n",
	       (soap.ip >> 24) & 0xff,(soap.ip >> 16) & 0xff,
	       (soap.ip >> 8) & 0xff,soap.ip & 0xff);

	tsoap = soap_copy(&soap);
	if (!tsoap) {
	    verror("could not copy SOAP data to handle connection; exiting!\n");
	    break;
	}

	pthread_create(&tid,NULL,handle_request,(void *)tsoap);
    }

    soap_done(&soap);
    return 0;
}
