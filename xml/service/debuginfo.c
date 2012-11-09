/*
 * Copyright (c) 2012 The University of Utah
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

#include "log.h"

#include "debuginfo_xml.h"
#include "debuginfo_rpc.h"

/* Pull in gsoap-generated namespace array. */
#include "debuginfo.nsmap"

GHashTable *debugfiles;
GHashTable *binaries;
pthread_mutex_t debugfile_mutex;

void *do_request(void *arg) {
    struct soap *soap = (struct soap *)arg;

    pthread_detach(pthread_self());

    soap_serve(soap);
    soap_destroy(soap);
    soap_end(soap);
    soap_done(soap);

    free(soap);

    return NULL;
}

int main(int argc, char **argv) {
    struct soap soap;
    struct soap *tsoap;
    pthread_t tid;
    int port;
    SOAP_SOCKET m, s;

    soap_init(&soap);

    pthread_mutex_init(&debugfile_mutex,NULL);

    debugfiles = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);
    binaries = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);

    /*
     * If no args, assume this is CGI coming in on stdin.
     */
    if (argc < 2) {
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

    port = atoi(argv[1]);
    m = soap_bind(&soap,NULL,port,64);

    if (!soap_valid_socket(m)) {
	verror("Could not bind to port %d: ",port);
	soap_print_fault(&soap,stderr);
	verrorc("\n");
	exit(1);
    }

    vdebug(9,LOG_OTHER,"bound to port %d\n",port);

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
	vdebug(8,LOG_OTHER,"connection from %d.%d.%d.%d\n",
	       (soap.ip >> 24) & 0xff,(soap.ip >> 16) & 0xff,
	       (soap.ip >> 8) & 0xff,soap.ip & 0xff);

	tsoap = soap_copy(&soap);
	if (!tsoap) {
	    verror("could not copy SOAP data to handle connection; exiting!\n");
	    break;
	}

	pthread_create(&tid,NULL,do_request,(void *)tsoap);
    }

    soap_done(&soap);
    return 0;
}
