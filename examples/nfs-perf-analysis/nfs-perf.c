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

/*
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
int debug_level = -1;

struct target *t;
GHashTable *probes;

extern unsigned long long request_count;

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
           case ARGP_KEY_INIT:
	       target_driver_argp_init_children(state);
	       break;
           case 'c': 
                {
                        int res;

                         res = sscanf(arg, "%llu", &request_count);

                         DBG("Process up to %llu requests\n", request_count);

                         if(res != 1){
                             ERR("Something is wrong with the command line, "
                                 "can't read request counter (-c param)\n");
                             break;
                         }

                        break;
                }


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

            case 'd': 
                {
                        ++debug_level; 
                        break;
                }

            case 'l': 
                {
                        log_flags_t flags;
                        if (vmi_log_get_flag_mask(arg,&flags)) {
                                fprintf(stderr,"ERROR: bad debug flag in '%s'!\n",arg);
                                exit(-1);
                        }
                        vmi_set_log_flags(flags);
                        break;
                }

        default:
            return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

const struct argp_option cmd_opts[] =
{
    { .name = "request-count",  .key = 'c', .arg = "FILE",  .flags = 0,
                .doc = "Process up to <request count> requests and exit" },

    { .name = "domain-name",  .key = 'm', .arg = "FILE",  .flags = 0,
                .doc = "Domain name" },

    { .name = "verbose",  .key = 'v', .arg = 0, .flags = 0, 
                .doc = "Verbose" },

    { .name = "logtypes",  .key = 'l', .arg = "FILE", .flags = 0, 
                .doc = "Log types" },

    { .name = "debug",  .key = 'd', .arg = 0, .flags = 0, 
                .doc = "Debug level" },

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
    target_status_t tstat;
    int ret;
    struct target_spec *tspec;
    char targetstr[128];

    dwdebug_init();
    atexit(dwdebug_fini);

    memset(&opts,0,sizeof(opts));

    target_argp_driver_parse(&parser_def,NULL,argc,argv,TARGET_TYPE_XEN,1);

    if (!opts.tspec) {
	verror("could not parse target arguments!\n");
	exit(-1);
    }

    if (!opts.argc) {
	fprintf(stderr,"ERROR: must supply a gadget file!\n");
	exit(-5);
    }

    filename = opts.argv[0];

    t = target_instantiate(opts.tspec);
    if (!t) {
	verror("could not instantiate target!\n");
	exit(-1);
    }
    target_tostring(t,targetstr,sizeof(targetstr));

    argp_parse(&parser_def, argc, argv, 0, 0, NULL);

    dwdebug_init();
    vmi_set_log_level(debug_level);
    xa_set_debug_level(debug_level);

    tspec = target_build_spec(TARGET_TYPE_XEN,TARGET_MODE_LIVE);
    ((struct xen_vm_spec *)tspec->backend_spec)->domain = domain_name;
    /* Just set this for completeness for the future. */
    ((struct xen_vm_spec *)tspec->backend_spec)->xenaccess_debug_level = debug_level;

    t = xen_vm_attach(dom_name,NULL);
    if (!t)
    {
        ERR("Can't attach to dom %s!\n", dom_name);
        exit(-3);
    }

    if (target_open(t,NULL))
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
                   target_read_reg(t,TID_GLOBAL,t->ipregno));
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
