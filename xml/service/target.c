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
#include <getopt.h>

#include "log.h"

#include "target_rpc.h"
#include "debuginfo_rpc.h"
#include "util.h"
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

extern char *optarg;
extern int optind, opterr, optopt;

int main(int argc, char **argv) {
    struct soap soap;
    struct soap *tsoap;
    pthread_t tid;
    int port = 0;
    SOAP_SOCKET m, s;
    char ch;
    int debug = 0;
    int warn = 0;
    log_flags_t flags;
    int doelfsymtab = 1;

    while ((ch = getopt(argc, argv, "dwl:Ep:")) != -1) {
	switch(ch) {
	case 'd':
	    ++debug;
	    vmi_set_log_level(debug);
	    break;
	case 'w':
	    ++warn;
	    vmi_set_warn_level(warn);
	    break;
	case 'l':
	    if (vmi_log_get_flag_mask(optarg,&flags)) {
		fprintf(stderr,"ERROR: bad debug flag in '%s'!\n",optarg);
		exit(-1);
	    }
	    vmi_set_log_flags(flags);
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

    m = soap_bind(&soap,NULL,port,64);
    if (!soap_valid_socket(m)) {
	verror("Could not bind to port %d: ",port);
	soap_print_fault(&soap,stderr);
	verrorc("\n");
	exit(1);
    }

    vdebug(5,LOG_X_RPC,"bound to port %d\n",port);

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
	vdebug(8,LOG_X_RPC,"connection from %d.%d.%d.%d\n",
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
