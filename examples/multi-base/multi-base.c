/*
 * Copyright (c) 2011, 2012, 2013, 2014 The University of Utah
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
#include <sys/user.h>
#include <sys/ptrace.h>
#include <inttypes.h>
#include <signal.h>
#include <argp.h>
#include <glib.h>
#include "glib_wrapper.h"

#include "common.h"
#include "log.h"
#include "dwdebug.h"
#include "target_api.h"
#include "target.h"
#include "probe_api.h"
#include "target_os_process.h"

/**
 ** This program dirived from the ./tools/probetargets.c.
 ** And it also reuses the handler function from the ./example/multi-overlay.c.
 ** 
 ** It monitors multiple processes running on different VMs.
 ** It places break points on lines of processes and print out specific symbol
 ** values.
 **
 ** The argument parsing of this program consist of two parts: the stackdb argp
 ** wrapper (target_argp_driver_parse) and an stackdb unrelated argument 
 ** extracter (extract_args).
 ** For the stackdb argp wrapper, you just need to follow the way GNU argp to 
 ** define necessary data structures and functions.
 ** And the stackdb unrelated argument extracter is used in this format:
 **     <target id>:<source file name>:<line No.>:<valuable name>
 **
 ** Usage: 
 ** sudo ./multi-base \
 ** --base '-t <TYPENAME> -m <vmID1> -i <target id1> -K <path to kernel file>' \
 ** --overlay '<targetid1>:<task name>:-t <TYPENAME> -i <target id2> \
 **   -R <path to debuginfo-filesystem-mirror>' \
 ** --base '-t <TYPENAME> -m <vmID2> -i <target id3> -K <path to kernel file>' \
 ** --overlay '<targetid3>:<task name>:-t <TYPENAME> -i <target id4> \
 **   -R <path to debuginfo-filesystem-mirror>' \
 ** <target id2>:<source file 1>:<line No.>:<valuable name> \
 ** <target id4>:<source file 2>:<line No.>:<valuable name>
 **
 ** An example: 
 ** sudo ./multi-base \
 ** --base '-t xen -m vm3 -i 10 \
 **   -K /opt/debuginfo/vm3/usr/lib/debug/boot/vmlinux-2.6.32-67-server' \
 ** --overlay '10:rserver:-t os-process -i 100 -R /opt/debuginfo/vm3' \
 ** --base '-t xen -m vm9 -i 20 \
 **   -K /opt/debuginfo/vm9/usr/lib/debug/boot/vmlinux-2.6.32-70-server' \
 ** --overlay '20:lclient:-t os-process -i 201 -R /opt/debuginfo/vm9' \
 ** 100:rserver.c:84:vm3_s_pingpong \
 ** 201:lclient.c:53:vm9_c_pingpong 
 **/

struct tgt_sym {
    int tgtid;
    char *file_name;
    char *sym_name;
    int line;
};
struct handler_data {
    struct tgt_sym task2sym_entry;
};
struct dt_argp_state {
    int do_post;
    int quiet;
    int argc;
    char **argv;
    int line_num;
    char *val;
    unsigned int ospecs_len;
};

result_t handler_line(struct probe *probe, tid_t tid, void *data,
                      struct probe *trigger, struct probe *base);

/* Extract arguments into an table. */
void extract_args(int argc, char **argv, struct tgt_sym *task2sym);

/* This is the argp parsing function */
error_t dt_argp_parse_opt(int key, char *arg, struct argp_state *state);

struct argp_option dt_argp_opts[] = {
    {"post", 'P', 0, 0, "Enable post handlers.", 0},
    {"quiet", 'q', 0, 0, "Silent but deadly.", 0},
    {0, 0, 0, 0, 0, 0},
};

struct argp dt_argp = {
    dt_argp_opts, dt_argp_parse_opt, NULL, NULL, NULL, NULL, NULL,
};

struct dt_argp_state opts;

int main(int argc, char **argv) {
    int i;
    struct probe *probe;
    struct target_spec *primary_target_spec = NULL;
    GList *base_target_specs = NULL;
    GList *overlay_target_specs = NULL;
    GList *targets;
    int rc;
    struct evloop *evloop;
    GList *t1;
    struct target *target;
    struct bsymbol *bsymbol;
    struct tgt_sym *task2sym;
    char filename[1024];
    struct handler_data *fdata;

    target_init();
    atexit(target_fini);
    memset(&opts, 0, sizeof(opts));

    /* 
     * After we prepare the necessary data structure and parsing function,
     * we call this function to put the arguments into opts.
     */
    rc = target_argp_driver_parse(&dt_argp, &opts, argc, argv,
                                  TARGET_TYPE_PTRACE | TARGET_TYPE_XEN
                                  | TARGET_TYPE_GDB, 1,
                                  &primary_target_spec, &base_target_specs,
                                  &overlay_target_specs);
    if (rc) {
        verror("could not parse target arguments!\n");
        exit(-1);
    }

    target_install_default_sighandlers(NULL);

    /* Create the evloop structure */
    evloop = evloop_create(NULL);

    /* instantiate and open the targets */
    targets = target_instantiate_and_open(primary_target_spec,
                                          base_target_specs,
                                          overlay_target_specs, evloop, NULL);
    if (!targets) {
        verror("could not instantiate and open targets!\n");
        exit(-1);
    }
    task2sym = (struct tgt_sym *) calloc(argc, sizeof(struct tgt_sym));

    /* extract the arguments into the task2sym table */
    extract_args(opts.argc, opts.argv, task2sym);

    for (i = 0; i < opts.argc; ++i) {
        target = target_lookup_target_id(task2sym[i].tgtid);
        if (!target) {
            fprintf(stderr,
                    "Could not lookup target %d for symbol %s; aborting!\n",
                    task2sym[i].tgtid, task2sym[i].sym_name);
            target_default_cleanup();
            exit(-3);
        }
        bsymbol = target_lookup_sym(target, task2sym[i].sym_name, NULL, NULL,
                                    SYMBOL_TYPE_FLAG_NONE);
        if (!bsymbol) {
            fprintf(stderr, "could not lookup symbol %s; aborting!\n",
                    task2sym[i].sym_name);
            target_default_cleanup();
            exit(-3);
        }

        /* We use fdata to transfer the task2sym table to the probe handler */
        fdata = (struct handler_data *) calloc(1, sizeof(*fdata));
        fdata->task2sym_entry = task2sym[i];

        /* Create a probe for a target with a name and a handler */
        probe =
            probe_create(target, TID_GLOBAL, NULL,
                         task2sym[i].file_name, handler_line, handler_line,
                         fdata, 0, 0);
        if (!probe) {
            fprintf(stderr, "creating probe failed; aborting!\n");
            target_default_cleanup();
            exit(-3);
        }

        /* Insert a probe point (break point here) in action */
        memset(filename, 0, 1024);
        strcat(filename, task2sym[i].file_name);
        printf("filename == %s\n", filename);
        probe =
            probe_register_line(probe, filename, task2sym[i].line,
                                PROBEPOINT_SW, 0, 0);
        if (!probe) {
            fprintf(stderr, "probe register failed; aborting!\n");
            target_default_cleanup();
            exit(-3);
        }
        bsymbol_release(bsymbol);
    }

    /* 
     * The target is paused after the attach; we have to resume it now
     * that we've registered probes (or hit the at_symbol).
     */
    v_g_list_foreach(targets, t1, target) {
        target_resume(target);
    }

    fprintf(stdout, "Starting main debugging loop!\n");
    fflush(stdout);

    while (1) {
        tid_t tid = 0;
        struct target *t;
        target_status_t tstat;
        char *tname;

        rc = target_monitor_evloop(evloop, NULL, &t, &tstat);

        /* Did we get interrupted safely? */
        if (target_monitor_was_interrupted(NULL));
        /* Did we experience an error in select() or in evloop? */
        else if (rc < 0) {
            fprintf(stderr, "error in target_monitor_evloop (%d): %s;"
                    " attempting to continue!\n", rc, strerror(errno));
            continue;
        }
        /* Did we experience a significant event on a target? */
        else if (rc == 0 && evloop_maxsize(evloop) < 0) {
            break;
        }
        else if (rc == 0) {
            tid = target_gettid(t);
            tname = target_name(t);
            if (tstat == TSTATUS_ERROR) {
                fprintf(stderr,
                        "Error handling target '%s'; closing and finalizing!\n",
                        tname);

                target_close(t);
                target_finalize(t);
                targets = g_list_remove(targets, t);
            }
            else if (tstat == TSTATUS_DONE) {
                fprintf(stderr, "Target '%s' finished; finalizing!\n", tname);

                target_close(t);
                target_finalize(t);
                targets = g_list_remove(targets, t);
            }
            else if (tstat == TSTATUS_EXITING) {
                fprintf(stderr, "Target '%s' exiting...\n", tname);
            }
            else if (tstat == TSTATUS_INTERRUPTED) {
                fprintf(stderr, "Target '%s' interrupted, resuming...\n",
                        tname);
                if (target_resume(t)) {
                    fprintf(stderr,
                            "Could not resume target %s tid %" PRIiTID "\n",
                            tname, tid);

                    target_close(t);
                    target_finalize(t);
                    targets = g_list_remove(targets, t);
                }
            }
            else {
                fprintf(stderr,
                        "Target '%s' tid %d received unexpected status '%s'"
                        " at 0x%" PRIxADDR "; attempting to continue!\n",
                        tname, tid, TSTATUS(tstat), target_read_reg(t, tid,
                                                                    CREG_IP));
                if (target_resume(t)) {
                    fprintf(stderr,
                            "Could not resume target %s tid %" PRIiTID "\n",
                            tname, tid);

                    target_close(t);
                    target_finalize(t);
                    targets = g_list_remove(targets, t);
                }
            }
        }
    }
    printf("Monitoring completed; exiting!\n");

    exit(0);
}

error_t dt_argp_parse_opt(int key, char *arg, struct argp_state *state) {
    struct dt_argp_state *opts =
        (struct dt_argp_state *) target_argp_driver_state(state);

    switch (key) {
    case ARGP_KEY_ARG:
        /* 
         * We want to process all the remaining args, so bounce to the
         * next case by returning this value.
         */
        return ARGP_ERR_UNKNOWN;
    case ARGP_KEY_ARGS:
        /* Eat all the remaining args. */
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
        return 0;
    case ARGP_KEY_ERROR:
    case ARGP_KEY_FINI:
        return 0;
    case 'P':
        opts->do_post = 1;
        break;
    case 'q':
        opts->quiet = 1;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

result_t handler_line(struct probe * probe, tid_t tid, void *data,
                      struct probe * trigger, struct probe * base) {
    struct value *value;
    char buf[1024];
    struct bsymbol *psym;
    struct target *target;
    struct target_location_ctxt *tlctxt;
    REGVAL ipval;
    struct bsymbol *function;

    printf("********** handler begins **********\n");

    target = probe_target(probe);
    psym = target_lookup_sym(target,
                             ((struct handler_data *) data)->task2sym_entry.
                             sym_name, NULL, NULL, SYMBOL_TYPE_FLAG_NONE);
    if (!psym) {
        printf("Could not get any symbol!\n");
        exit(-1);
    }
    tlctxt = target_location_ctxt_create_from_bsymbol(target, tid, psym);
    value = target_load_symbol(target, tlctxt, psym, LOAD_FLAG_NONE);
    if (value) {
        value_snprintf(value, buf, sizeof(buf));
        printf("Value of %s is now '%s'\n", bsymbol_get_name(psym), buf);
    }
    ipval = target_read_creg(target, tid, CREG_IP);
    if (ipval && errno) {
        fprintf(stderr, "ERROR: could not read IP register!\n");
    }
    else {
        function = target_lookup_sym_addr(target, ipval);
        if (function) {
            printf("Hit in function '%s' at IP 0x%" PRIxREGVAL
                   "\n", bsymbol_get_name(function) ? : "", ipval);
            bsymbol_release(function);
        }
        else {
            printf("In unknown function at IP 0x%" PRIxREGVAL "\n", ipval);
        }
    }
    printf("********** handler ends **********\n\n\n");

    target_location_ctxt_free(tlctxt);

    return RESULT_SUCCESS;
}

void extract_args(int argc, char **argv, struct tgt_sym *task2sym) {
    char *tmpfile, *tmpline, *tmpval;
    int i;
    char **argv_tmp;

    argv_tmp = (char **) malloc(sizeof(char *) * argc);
    for (i = 0; i < argc; i++) {
        argv_tmp[i] = (char *) malloc(128);
        memset(argv_tmp[i], 0, 128);
        printf("argc %d,argv[%d]==%s\n", argc, i, argv[i]);
        strcpy(argv_tmp[i], argv[i]);
    }
    for (i = 0; i < argc; i++) {
        /* Get the target id */
        tmpfile = index(argv_tmp[i], ':');
        *tmpfile = '\0';
        task2sym[i].tgtid = atoi(argv_tmp[i]);
        printf("tgtid = %d\n", task2sym[i].tgtid);

        /* Get the file name */
        tmpline = index(tmpfile + 1, ':');
        *tmpline = '\0';
        task2sym[i].file_name = tmpfile + 1;
        printf("task name = %s\n", task2sym[i].file_name);

        /* Get the line number */
        tmpval = index(tmpline + 1, ':');
        *tmpval = '\0';
        task2sym[i].line = atoi(tmpline + 1);
        printf("line = %d\n", task2sym[i].line);

        /* Get the valuable name */
        task2sym[i].sym_name = tmpval + 1;
        printf("sym_name = %s\n", task2sym[i].sym_name);
    }
    for (i = 0; i < argc; i++) {
        printf("the tgtid == %d file_name == %s, line == %d, sym_name == %s \n",
               task2sym[i].tgtid, task2sym[i].file_name, task2sym[i].line,
               task2sym[i].sym_name);
    }

    return;
}
