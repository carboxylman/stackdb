/*
 * Copyright (c) 2011, 2012 The University of Utah
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
 * Foundation, 51 Franklin St, Suite 500, Boston, MA 02110-1335, USA.
 * 
 *  examples/nfs-perf-analysis/nfs-perf.c
 *
 *  Performance analysis of the request processing path in the
 *  Linux network file system stack. 
 *
 *  Authors: Anton Burtsev, aburtsev@flux.utah.edu
 * 
 */

#include <argp.h>

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>

#include <signal.h>

#include <log.h>
#include <dwdebug.h>
#include <target_api.h>
#include <target.h>
#include <target_xen_vm.h>

#include <probe_api.h>
#include <probe.h>
#include <alist.h>

#include "probes.h"
#include "debug.h"

char *dom_name = NULL; 
int verbose = 0; 

struct target *t;
GHashTable *probes;



void sigh(int signo)
{
    if (t)
    {
        target_pause(t);
        DBG("Ending trace.\n");
        unregister_probes(probes);
        target_close(t);
        DBG("Ended trace.\n");
    }

    exit(0);
}

/* command parser for GNU argp - see  GNU docs for more info */
error_t cmd_parser(int key, char *arg, struct argp_state *state)
{
    /*settings_t *setup = (settings_t *)state->input;*/

    switch ( key )
    {
        case 'm': 
		{
			dom_name = arg;
			break;
		}

	    case 'v': 
		{
			verbose = 1; 
			break;
		}

        default:
            return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

const struct argp_option cmd_opts[] =
{
    { .name = "domain-name",  .key = 'm', .arg = "FILE",  .flags = 0,
		.doc = "Domain name" },

    { .name = "verbose",  .key = 'v', .arg = 0, .flags = 0, 
		.doc = "Verbose" },

    {0}
};

const struct argp parser_def =
{
    .options = cmd_opts,
    .parser = cmd_parser,
    .doc =
        "Performance analysis of the Linux Network File System stack"
};


const char *argp_program_version     = "nfs-perf v0.1";
const char *argp_program_bug_address = "<aburtsev@flux.utah.edu>";

int main(int argc, char *argv[])
{
    int debug_level = -1;
    target_status_t tstat;
    int ret;


    argp_parse(&parser_def, argc, argv, 0, 0, NULL);

    dwdebug_init();
    vmi_set_log_level(debug_level);
    xa_set_debug_level(debug_level);

    t = xen_vm_attach(dom_name);
    if (!t)
    {
        ERR("Can't attach to dom %s!\n", dom_name);
        exit(-3);
    }

    if (target_open(t))
    {
        ERR("Can't open target %s!\n", dom_name);
        exit(-4);
    }

    ret = register_probes(t, probes);
    if (ret)
    {
        ERR("Failed to register probes, ret:%d", ret);
        exit(ret);
    }

    signal(SIGHUP, sigh);
    signal(SIGINT, sigh);
    signal(SIGQUIT, sigh);
    signal(SIGABRT, sigh);
    signal(SIGKILL, sigh);
    signal(SIGSEGV, sigh);
    signal(SIGPIPE, sigh);
    signal(SIGALRM, sigh);
    signal(SIGTERM, sigh);
    signal(SIGUSR1, sigh);
    signal(SIGUSR2, sigh); 

    /* 
     * The target is paused after the attach; we have to resume it now
     * that we've registered probes.
     */
    target_resume(t);

    DBG("Starting main debugging loop!\n");
    
    while (1)
    {
        tstat = target_monitor(t);
        if (tstat == TSTATUS_PAUSED)
        {
            printf("domain %s interrupted at 0x%" PRIxREGVAL "\n", dom_name, 
                    target_read_reg(t,t->ipregno));
            if (target_resume(t))
            {
                ERR("Can't resume target dom %s\n", dom_name);
                target_close(t);
                exit(-16);
            }
        }
        else
        {
            unregister_probes(probes);
            target_close(t);
            if (tstat == TSTATUS_DONE)
                break;
            else if (tstat == TSTATUS_ERROR)
                return -9;
            else
                return -10;
        }
    }

    return 0;
}
