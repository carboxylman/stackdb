/*
 * Copyright (c) 2011, 2012, 2013 The University of Utah
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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/ptrace.h>
#include <argp.h>

#include "log.h"
#include "dwdebug.h"
#include "target_api.h"
#include "target.h"
#include "target_xen_vm.h"
#include "probe_api.h"
#include "probe.h"
#include "alist.h"
#include "list.h"

struct target *t = NULL;
struct bsymbol *bs;
struct value *v;

struct psa_argp_state {
    int argc;
    char ** argv;
    struct target_spec *tspec;
};
struct psa_argp_state opts;
struct argp_option psa_argp_opts[] = { { 0, 0, 0, 0, 0, 0 }, };

error_t psa_argp_parse_opt(int key, char *arg, struct argp_state *state) {
    struct psa_argp_state *opts =
            (struct psa_argp_state *) target_argp_driver_state(state);

    switch (key) {
    case ARGP_KEY_ARG:
        return ARGP_ERR_UNKNOWN;
    case ARGP_KEY_ARGS:
        if (state->quoted > 0)
            opts->argc = state->quoted - state->next;
        else
            opts->argc = state->argc - state->next;
        if (opts->argc > 0) {
            opts->argv = calloc(opts->argc, sizeof(char *));
            memcpy(opts->argv, &state->argv[state->next],
                    opts->argc * sizeof(char *));
            state->next += opts->argc;
        }
        return 0;
    case ARGP_KEY_INIT:
        target_driver_argp_init_children(state);
        return 0;
    case ARGP_KEY_END:
    case ARGP_KEY_NO_ARGS:
    case ARGP_KEY_SUCCESS:
        opts->tspec = target_argp_target_spec(state);
        return 0;
    case ARGP_KEY_ERROR:
    case ARGP_KEY_FINI:
        return 0;

    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

struct argp psa_argp = { psa_argp_opts, psa_argp_parse_opt, NULL, NULL, NULL,
        NULL, NULL, };

int main(int argc, char **argv) {

    int new_val;
    int result;
    /* define a target spec structure, guess this
     * specifies all the attributes to setup connection with the
     * target
     */
    struct target_spec *tspec;
    target_status_t tstat;

    memset(&opts, 0, sizeof(opts));

    /* parse the command line arguments and get the
     * tspec struct variable.
     */
    tspec = target_argp_driver_parse(&psa_argp, &opts, argc, argv,
            TARGET_TYPE_XEN, 1);

    if (!tspec) {
        verror("Could not parse target arguments!\n");
        exit(-1);
    }

    /* Make sure that the process ID is passed.*/
    if (opts.argc < 1) {
        fprintf(stderr, "ERROR: PID  not passed.\n");
        exit(-1);
    }

    dwdebug_init();
    atexit(dwdebug_fini);

    /* now initialize the target */
    t = target_instantiate(tspec);
    if (!t) {
        verror("Count not instantiate target\n");
        exit(-1);
    }

    /* Open connection to the target.*/
    if (target_open(t)) {
        fprintf(stderr, "Could not open the target\n");
        exit(-1);
    }

    sscanf(opts.argv[0], "%d", &new_val);
    fprintf(stderr, "Pid value passed %d\n", new_val);

    bs = target_lookup_sym(t, "pid", NULL, "psaction_module",
            SYMBOL_TYPE_FLAG_VAR);
    if (!bs) {
        fprintf(stderr, "Error: could not lookup symbol pid\n");
        goto exit;
    }

    /* load the current value of the variable
     * in the value structure. Second argument is the thread id.
     * Which thread id needs to be passed here ?
     */
    v = target_load_symbol(t, TID_GLOBAL, bs,
            LOAD_FLAG_AUTO_STRING | LOAD_FLAG_AUTO_DEREF);
    if (!v) {
        goto exit;
    }

    //memcpy(v->buf, &new_val, sizeof(new_val));
    result = value_update_i32(v, new_val);
    if (result == -1) {
        fprintf(stderr, "Error: failed to update value\n");
        goto exit;
    }

    /*finally write the new value back */
    result = target_store_value(t, v);
    if (result == -1) {
        fprintf(stderr, "Error: failed to write the new value\n");
        goto exit;
    }

    value_free(v);
    bsymbol_release(bs);

    /* Now we need to set the input flag, indicating
     * that the pid value is set.
     */

    bs = target_lookup_sym(t, "iflag", NULL, "psaction_module",
            SYMBOL_TYPE_FLAG_VAR);
    if (!bs) {
        fprintf(stderr, "Error: could not lookup symbol iflag\n");
        goto exit;
    }

    v = target_load_symbol(t, TID_GLOBAL, bs,
            LOAD_FLAG_AUTO_STRING | LOAD_FLAG_AUTO_DEREF);
    if (!v) {
        fprintf(stderr, "ERROR: could not load value of symbol iflag\n");
        goto exit;
    }

    /* set the iflag */
    result = value_update_i32(v, 1);
    if (result == -1) {
        fprintf(stderr, "Error: failed to update value\n");
        goto exit;
    }
    result = target_store_value(t, v);
    if (result == -1) {
        fprintf(stderr, "Error: failed to set the iflag\n");
        goto exit;
    }

    value_free(v);
    bsymbol_release(bs);

    /* If we need an ack form the module that the process has been killed
     * the we need to add code here that waits on some flag set by the kernel module.
     * Once flag is set it displays appropriate message and does a clean exit.
     */

    /* Clean exit code */
    exit: fflush(stderr);
    fflush(stdout);
    tstat = target_close(t);
    if (tstat == TSTATUS_DONE) {
        printf("Finished.\n");
        exit(0);
    }
    else if (tstat == TSTATUS_ERROR) {
        printf("Monitoring failed!\n");
        exit(-1);
    }
    else {
        printf("Monitoring failed with %d!\n", tstat);
        exit(-1);
    }
}
