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
struct psa_argp_state opts;

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
     * tspec struct variable. not sure if this function can be used as
     * a general function
     */
    tspec = target_argp_driver_parse(&psa_argp, &opts, argc, argv,
            TARGET_TYPE_XEN, 1);

    if (!tspec) {
        verror("could not parse target arguments!\n");
        exit(-1);
    }

    /* Pass process id of the process that needs to be killed*/
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

    /* Open connection to the target. Is the target VM paused ? */
    if (target_open(t)) {
        fprintf(stderr, "Could not open the target\n");
        exit(-1);
    }

    /* not sure if i have to use a bsymbol or lsymbol here*/
    bs = target_lookup_sym(t, "psaction_module.pid", ".", NULL,
            SYMBOL_TYPE_FLAG_VAR);
    if (!bs) {
        fprintf(stderr, "Error: could not lookup symbol pid",);
        goto exit;
    }

    /* load the current value of the variable
     * in the value structure. Second argument is the thread id.
     * Which thread id needs to be passed here ?
     */
    v = target_load_symbol(t, TID_GLOBAL, bs,
            LOAD_FLAG_AUTO_STRING | LOAD_FLAG_AUTO_DEREF);
    if (!v) {
        fprintf(stderr, "ERROR: could not load value of symbol pid\n");
        goto exit;
    }

    new_val = opts.argv[1];
    memcpy(v->buf, &new_val, sizeof(new_val));

    /*finally write the new value back */
    resut = target_store_value(t, v);
    if (!result) {
        fprintf(stderr, "Error: failed to write the new value\n");
        goto exit;
    }

    value_free(v);
    bsymbol_free(bs, 0);

    /* Now we need to set the input flag, indicating
     * that the pid value is set.
     */

    bs = target_lookup_sym(t, "psaction_module.iflag", ".", NULL,
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

    new_val = 1;
    memcpy(v->buf, &new_val, sizeof(new_val));

    result = target_store_value(t, v);
    if (!result) {
        fprintf(stderr, "Error: failed to set the iflag\n");
        goto exit;
    }

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
