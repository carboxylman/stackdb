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
#include "analysis.h"
#include "generic_rpc.h"
#include "analysis_rpc.h"

/* Pull in gsoap-generated namespace array. */
#include "analysis.nsmap"

struct analysis_rpc_handler_state {
    struct analysis_rpc_config *cfg;
    struct soap *soap;
};

#define ARGP_KEY_ANALYSIS_PATH   4096
#define ARGP_KEY_SCHEMA_PATH     4097
#define ARGP_KEY_ANNOTATION_PATH 4098

struct argp_option analysis_rpc_argp_opts[] = {
    { "analysis-path",ARGP_KEY_ANALYSIS_PATH,"PATH",0,
        "Set the analysis description PATH.",0 },
    { "schema-path",ARGP_KEY_SCHEMA_PATH,"PATH",0,
        "Set the schema PATH.",0 },
    { "annotation-path",ARGP_KEY_ANNOTATION_PATH,"PATH",0,
        "Set the annotation PATH.",0 },
    { 0,0,0,0,0,0 }
};

error_t analysis_rpc_argp_parse_opt(int key,char *arg,struct argp_state *state) {
    struct analysis_rpc_config *cfg = (struct analysis_rpc_config *)state->input;

    switch (key) {
    case ARGP_KEY_ARG:
    case ARGP_KEY_ARGS:
	return ARGP_ERR_UNKNOWN;
    case ARGP_KEY_END:
    case ARGP_KEY_NO_ARGS:
    case ARGP_KEY_SUCCESS:
    case ARGP_KEY_ERROR:
    case ARGP_KEY_FINI:
	return 0;
    case ARGP_KEY_INIT:
	/* Pass the config obj directly to our first child. */
	state->child_inputs[0] = cfg;
	return 0;

    case ARGP_KEY_ANALYSIS_PATH:
	analysis_set_path_string(arg);
	break;
    case ARGP_KEY_SCHEMA_PATH:
	analysis_set_schema_path_string(arg);
	break;
    case ARGP_KEY_ANNOTATION_PATH:
	analysis_set_annotation_path_string(arg);
	break;

    default:
	return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

const struct argp_child analysis_rpc_argp_children[2] = {
    { &generic_rpc_argp,0,generic_rpc_argp_header,0 },
    { NULL,0,NULL,0 },
};

struct argp analysis_rpc_argp = { 
    analysis_rpc_argp_opts,analysis_rpc_argp_parse_opt,
    NULL,"Analysis RPC Server Options",analysis_rpc_argp_children,NULL,NULL
};

int main(int argc, char **argv) {
    struct generic_rpc_config cfg;

    if (argp_parse(&analysis_rpc_argp,argc,argv,0,NULL,&cfg))
	exit(errno);

    analysis_rpc_init();

    atexit(analysis_rpc_fini);

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

    cfg.handle_request = analysis_rpc_handle_request;

    return generic_rpc_serve(&cfg);
}
