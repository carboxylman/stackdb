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

#include <argp.h>

#include "log.h"
#include "generic_rpc.h"
#include "target_rpc.h"

/* Pull in gsoap-generated namespace array. */
#include "target.nsmap"

int main(int argc, char **argv) {
    struct generic_rpc_config cfg;

    if (argp_parse(&generic_rpc_argp,argc,argv,0,NULL,&cfg))
	exit(errno);

    target_rpc_init();

    atexit(target_rpc_fini);

    /*
     * Setup some config options.
     *
     * First, do the signals we want our dedicated sighandling thread to catch.
     * Then set the name and our primary handler.  That's it!
     */
    sigemptyset(&cfg.sigset);
    //sigaddset(&cfg.sigset,SIGINT);
    sigaddset(&cfg.sigset,SIGCHLD);
    sigaddset(&cfg.sigset,SIGPIPE);

    cfg.name = "target";

    cfg.handle_request = target_rpc_handle_request;

    return generic_rpc_serve(&cfg);
}
