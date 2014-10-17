#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <glib.h>
#include "glib_wrapper.h"
#include "common.h"
#include "target_api.h"
#include "probe_api.h"
#include "target_linux_userproc.h"

/**
 ** This program places a watch point on each of the processes we want to
 ** monitor, and print out the value once the watch point is hit.
 **
 ** The main elements are: target, symbol, probe.
 ** Attach to a target -> find the symbol -> place the probe -> polling
 **
 ** These are the main steps:
 ** 1. Create target objects for monitoring. (target_instantiate)
 ** 2. Attach each target object to its process. (target_open)
 ** 3. Look up symbol in the targets. (target_lookup_sym)
 ** 4. Create probe for each target and symbol pair. (probe_create)
 ** 5. Insert probe point for each target. (probe_register_symbol)
 ** 6. Resume the targets. (target_resume)
 ** 7. Monitor the target status. (target_poll & on_poll_return)
 **
 ** Usage: sudo ./multi_watch <pid1>:<valuable1> <pid2>:<valuable2>
 **/

GHashTable *prb_hash = NULL;
GList *tgt_list = NULL;
int needtodie = 0;
int needtodie_exitcode = 0;
struct tgt_sym {
    int tgtid;
    int pid;
    char *sym_name;
};
struct handler_data {
    unum_t old_value;
};

/* Extract arguments into a pid to symbol name table.  */
void extract_args(int argc, char **argv, struct tgt_sym *pid2sym);

/*
 * Make the target_spec struct for initializing a target.
 * It mainly sets the target id, pid, and specifies the target type.
 * After initializaing the target, the target is appended into a target list.
 */
void init_specs(struct tgt_sym *pid2sym, int argc);

/* Install signal handlers. */
int signal_init();

/*
 * This is the handler when the watch point is hit.
 * It simple print out the value of the watch point.
 */
result_t handler_var(struct probe *probe, tid_t tid, void *data,
                     struct probe *trigger, struct probe *base);

void buffer_flush();
void cleanup_probes();
void cleanup();
void sigh(int signo);

int main(int argc, char **argv) {
    struct target *tgt = NULL;
    struct tgt_sym *pid2sym;
    struct handler_data *fdata;
    char targetstr[128];
    int retint;
    struct bsymbol *found_sym;
    struct probe *probe;
    char *sym_name;
    void *ret;
    GList *tmplist;
    int i;

    prb_hash = g_hash_table_new(g_direct_hash, g_direct_equal);

    /* Initialize the target library */
    target_init();
    atexit(target_fini);
    if (argc < 3) {
        printf("Usage: sudo ./multi_watch" 
               " <pid1>:<val1> <pid2>:<val2> \n");
        exit(0);
    }
    else {
        /* extracting the arguments */
        pid2sym = (struct tgt_sym *) calloc(argc, sizeof(struct tgt_sym));
        extract_args(argc, argv, pid2sym);

        /* initialize the target with target_spec */
        init_specs(pid2sym, argc);
    }

    /* Install signal handlers */
    signal_init();
    v_g_list_foreach(tgt_list, tmplist, tgt) {
        target_snprintf(tgt, targetstr, sizeof(targetstr));

        /* We take the targets from the list and open it one by one */
        retint = target_open(tgt);
        if (retint) {
            fprintf(stderr, "could not open %s!\n", targetstr);
            exit(-4);
        }

        fprintf(stdout, "Opened target '%s'.\n", targetstr);
    }

    for (i = 0; i < argc - 1; i++) {
        /* Look up the target by target id */
        tgt = target_lookup_target_id(pid2sym[i].tgtid);
        char tmpstr[64];

        sprintf(tmpstr, "%d", pid2sym[i].tgtid);
        if (!tgt) {
            fprintf(stderr,
                    "could not find target with id '%s'; aborting!\n", tmpstr);
            exit(-5);
        }

        target_snprintf(tgt, targetstr, sizeof(targetstr));

        /* Look up a symbol in a target, making sure we can find that symebol */
        found_sym =
            target_lookup_sym(tgt, pid2sym[i].sym_name, NULL, NULL,
                              SYMBOL_TYPE_FLAG_NONE);
        if (!found_sym) {
            fprintf(stderr, "could not lookup symbol %s; aborting!\n",
                    pid2sym[i].sym_name);
            cleanup();
            exit(-3);
        }

        /* Create a probe for a target with a symbol name and a handler */
        fdata = (struct handler_data *) calloc(1, sizeof(*fdata));
        probe =
            probe_create(tgt, TID_GLOBAL, NULL,
                         bsymbol_get_name(found_sym), handler_var, NULL,
                         fdata, 0, 0);
        if (!probe) {
            fprintf(stderr,
                    "could not create probe on symbol:%s; aborting!\n",
                    bsymbol_get_name(found_sym));
            cleanup();
            exit(-3);
        }

        /* Insert a probe point (watch point here) in action */
        probe =
            probe_register_symbol(probe, found_sym, PROBEPOINT_FASTEST,
                                  PROBEPOINT_WAUTO, PROBEPOINT_LAUTO);
        if (!probe) {
            fprintf(stderr,
                    "could not register probe on symbol:%s; aborting!\n",
                    bsymbol_get_name(found_sym));
            cleanup();
            exit(-3);
        }
        g_hash_table_insert(prb_hash, sym_name, probe);
        bsymbol_release(found_sym);
    }

    retint = g_hash_table_size(prb_hash);
    if (retint == 0) {
        fprintf(stderr, "No symbols to probe; exiting!\n");
        cleanup();
        exit(-1);
    }

    v_g_list_foreach(tgt_list, tmplist, tgt) {
        /* 
         * Target is paused before as it is opened or a probe point is inserted.
         * So we need to resume each target before we start to monitor them.
         */
        target_resume(tgt);
    }

    fprintf(stdout, "Starting Probing!\n");
    fflush(stdout);

    while (1) {
        v_g_list_foreach(tgt_list, tmplist, tgt) {
            target_snprintf(tgt, targetstr, sizeof(targetstr));
            struct timeval tv = { 0, 50 };
            target_status_t tstat;

            /* We use target_poll to monitor multiple targets */
            tstat = target_poll(tgt, &tv, NULL, NULL);

            /*
             * Polling return can either be a good state like TSTATUS_RUNNING
             * or bad states. Everytime it returns, we need to check whether it
             * is going right.
             */
            switch (tstat) {
            case TSTATUS_INTERRUPTED:
                if (needtodie) {
                    target_pause(tgt);
                    cleanup_probes();
                    cleanup();
                    exit(needtodie_exitcode);
                }
                target_resume(tgt);
                break;

            case TSTATUS_PAUSED:
                buffer_flush();
                vwarn("target %s interrupted at 0x%" PRIxREGVAL
                      "; trying resume!\n",
                      targetstr, target_read_creg(tgt, TID_GLOBAL, CREG_IP));

                if (target_resume(tgt)) {
                    fprintf(stderr, "could not resume target\n");
                    cleanup();
                    exit(-16);
                }
                break;

            case TSTATUS_EXITING:
                buffer_flush();
                fprintf(stdout,
                        "target %s exiting, removing probes safely...\n",
                        targetstr);
                cleanup_probes();
                if (target_resume(tgt)) {
                    fprintf(stderr, "could not resume target!\n");
                    cleanup();
                    exit(-16);
                    break;
                }

            case TSTATUS_DONE:
                buffer_flush();
                fprintf(stdout, "target %s exited, cleaning up.\n", targetstr);
                cleanup();
                buffer_flush();
                exit(0);
                break;

            case TSTATUS_RUNNING:
                break;
            }
        }
    }

    return 0;
}

void init_specs(struct tgt_sym *pid2sym, int argc) {
    struct target *tgt = NULL;
    struct target_spec *tspec;
    struct linux_userproc_spec *luspec;
    int i;

    for (i = 0; i < argc - 1; i++) {
        printf("argc = %d, i = %d\n", argc, i);
        tspec = (struct target_spec *) calloc(1, sizeof(*tspec));
        luspec = (struct linux_userproc_spec *) calloc(1, sizeof(*luspec));
        luspec->pid = pid2sym[i].pid;
        printf("pid = %d\n", luspec->pid);
        tspec->target_id = pid2sym[i].tgtid;
        printf("tgtid = %d\n", tspec->target_id);
        tspec->target_type = TARGET_TYPE_PTRACE;
        tspec->backend_spec = luspec;

        /* Create a target base on the target_spec we made  */
        tgt = target_instantiate(tspec, NULL);

        /* If error checking is hit, then it will exit, so no need if-else.  */
        if (!tgt) {
            fprintf(stderr, "could not instantiate target!\n");
            exit(-1);
        }
        /* append the created target to a target list */
        tgt_list = g_list_append(tgt_list, tgt);
    }
}

void cleanup_probes() {
    GList *tmp;
    GHashTableIter iter;
    gpointer key;
    struct probe *probe;
    struct target *tgt;

    if (tgt_list) {
        v_g_list_foreach(tgt_list, tmp, tgt) {
            target_pause(tgt);
        }
    }
    if (prb_hash) {
        g_hash_table_iter_init(&iter, prb_hash);
        while (g_hash_table_iter_next(&iter,
                                      (gpointer) & key, (gpointer) & probe)) {
            probe_unregister(probe, 1);
            probe_free(probe, 1);
        }
        g_hash_table_destroy(prb_hash);
        prb_hash = NULL;
    }
}

void cleanup() {
    static int cleaning = 0;
    GList *tmp;
    struct target *tgt;

    if (cleaning)
        return;
    cleaning = 1;

    cleanup_probes();

    if (tgt_list) {
        v_g_list_foreach(tgt_list, tmp, tgt) {
            target_close(tgt);
            target_finalize(tgt);
            tgt = NULL;
        }
    }
    g_list_free(tgt_list);
    tgt_list = NULL;
}

void sigh(int signo) {
    GList *tmp;
    struct target *tgt;
    int was_handling = 0;

    needtodie = 1;
    needtodie_exitcode = 0;

    if (tgt_list) {
        v_g_list_foreach(tgt_list, tmp, tgt) {
            if (target_is_monitor_handling(tgt)) {
                target_monitor_schedule_interrupt(tgt);
                was_handling = 1;
            }
        }
    }
    if (!was_handling) {
        cleanup();
        exit(needtodie_exitcode);
    }
    signal(signo, sigh);
}

int signal_init() {
    signal(SIGINT, sigh);
    signal(SIGQUIT, sigh);
    signal(SIGABRT, sigh);
    signal(SIGSEGV, sigh);
    signal(SIGPIPE, sigh);
    signal(SIGALRM, sigh);
    signal(SIGTERM, sigh);

    return 0;
}

void buffer_flush() {
    fflush(stderr);
    fflush(stdout);
}

void extract_args(int argc, char **argv, struct tgt_sym *pid2sym) {
    char *tmp;
    int i;
    char **argv_tmp;

    argv_tmp = (char**) malloc(1024);
    for (i = 0; i < argc; i++){
        argv_tmp[i] = (char*) malloc(32);
        strcpy(argv_tmp[i],argv[i]);
    }
    
    for (i = 0; i < argc - 1; i++) {
        pid2sym[i].tgtid = i + 1;
        printf("tgtid = %d\n", pid2sym[i].tgtid);
        tmp = index(argv_tmp[i + 1], ':');
        if (tmp) {
            *tmp = '\0';
            pid2sym[i].pid = atoi(argv_tmp[i + 1]);
            printf("pid = %d\n", pid2sym[i].pid);
            pid2sym[i].sym_name = tmp + 1;
        }
        else {
            printf("input Error, check ':'\n");
        }
    }

    for (i = 0; i < argc - 1; i++) {
        printf("the %d pid == %d, symbol == %s \n", pid2sym[i].tgtid,
               pid2sym[i].pid, pid2sym[i].sym_name);
    }

    return;
}

result_t handler_var(struct probe * probe, tid_t tid, void *data,
                     struct probe * trigger, struct probe * base) {
    struct value *value;
    char buf[64];
    struct bsymbol *psym;
    struct target *target;
    unum_t pnum;
    struct target_location_ctxt *tlctxt;
    REGVAL ipval;
    struct bsymbol *function;

    printf("********** handler begins **********\n");

    target = probe_target(probe);
    psym = probe_symbol(probe);
    tlctxt = target_location_ctxt_create_from_bsymbol(target, tid, psym);

    value = target_load_symbol(target, tlctxt, psym, LOAD_FLAG_NONE);
    if (value) {
        pnum = v_unum(value);
        value_snprintf(value, buf, sizeof(buf));

        printf("Value of %s is now %lu '%s'\n", bsymbol_get_name(psym),
               pnum, buf);
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
