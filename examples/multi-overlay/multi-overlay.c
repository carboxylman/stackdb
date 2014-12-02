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
#include "target_xen_vm.h"
#include "target_os_process.h"

/**
 ** This program monitors multiple processes running on another VM.
 ** It place break point on a line of the process and print out symbol values.
 **
 ** Please refer to the multi-watch example about the target initialization.
 **
 ** The main differences are:
 ** 1. There are overlay targets atop the base target.
 ** 2. This program use break point instead of watch point.
 **
 ** Usage: sudo ./multi_overlay <vmID> \
 **        <file1>:<line1>:<valuable1>  <file2>:<line2>:<valuable2>
 **/

GHashTable *prb_hash = NULL;
GList *overlay_list = NULL;
struct target *underlay = NULL;
int needtodie = 0;
int needtodie_exitcode = 0;
struct tgt_sym {
    int tgtid;
    char *task_name;
    char *sym_name;
    int line;
};
struct handler_data {
    struct tgt_sym task2sym_entry;
};

/* Extract arguments into an table. */
void extract_args(int argc, char **argv, struct tgt_sym *task2sym);

/* Instantiate the overlay targets and append them into a list. */
void init_overlay_specs(struct tgt_sym *task2sym, int argc,
                        struct target_spec **over_specs);
void init_underlay_spec(char *underlay_name, struct xen_vm_spec *bspec,
                        struct target_spec *tspec);

/* Install signal handlers. */
int signal_init();

/*
 * This is the handler when the watch point is hit.
 * It simple print out the value of the watch point.
 */
result_t handler_line(struct probe *probe, tid_t tid, void *data,
                     struct probe *trigger, struct probe *base);
void buffer_flush();
void cleanup_probes();
void cleanup();
void sigh(int signo);

int main(int argc, char **argv) {
    struct xen_vm_spec under_spec;
    struct target_spec under_tspec;
    struct target_spec **over_specs;
    char filename[1024];
    struct target *overlay = NULL;
    struct target *tgt = NULL;
    struct tgt_sym *task2sym;
    struct handler_data *fdata;
    char targetstr[128];
    char otargetstr[128];
    int retint;
    struct bsymbol *found_sym;
    struct probe *probe;
    char *sym_name;
    void *ret;
    GList *tmplist;
    int i;

    memset(&under_spec, 0, sizeof(under_spec));
    memset(&under_tspec, 0, sizeof(under_tspec));
    prb_hash = g_hash_table_new(g_direct_hash, g_direct_equal);

    /* Initialize the target library */
    target_init();
    atexit(target_fini);

    vmi_set_log_level(20);
    vmi_set_warn_level(20);
    vmi_set_log_area_flags(LA_TARGET, LF_T_ALL | LF_XV | LF_OSP);
    vmi_set_log_area_flags(LA_PROBE, LF_P_ALL);

    if (argc < 3) {
        printf("Usage: sudo ./multi_overlay <vmID>"
               "<file1>:<line1>:<valuable1>  <file2>:<line2>:<valuable2> \n");
        exit(0);
    }
    else {
        /* extracting the arguments */
        task2sym = (struct tgt_sym *) calloc(argc, sizeof(struct tgt_sym));
        extract_args(argc, argv, task2sym);

        /* initialize the underlay target */
        init_underlay_spec(argv[1], &under_spec, &under_tspec);

        /* initialize the overlay target */
        init_overlay_specs(task2sym, argc, over_specs);
    }

    /* Install signal handlers */
    signal_init();
    v_g_list_foreach(overlay_list, tmplist, overlay) {
        target_snprintf(overlay, otargetstr, sizeof(otargetstr));

        /* We take the targets from the list and open it one by one */
        retint = target_open(overlay);
        if (retint) {
            fprintf(stderr, "could not open %s!\n", otargetstr);
            cleanup();
            exit(-4);
        }

        fprintf(stdout, "Opened overlay '%s'.\n", otargetstr);
    }

    for (i = 0; i < argc - 2; i++) {
        /* Look up the target by target id */
        overlay = target_lookup_target_id(task2sym[i].tgtid);

        if (!overlay) {
            fprintf(stderr,
                    "could not find target with id '%d'; aborting!\n",
                    task2sym[i].tgtid);
            exit(-5);
        }

        target_snprintf(overlay, targetstr, sizeof(targetstr));

        /* Look up a symbol in a target, making sure we can find that symbol */
        found_sym =
            target_lookup_sym(overlay, task2sym[i].sym_name, NULL, NULL,
                              SYMBOL_TYPE_FLAG_NONE);
        if (!found_sym) {
            fprintf(stderr, "could not lookup symbol %s; aborting!\n",
                    task2sym[i].sym_name);
            cleanup();
            exit(-3);
        }
        bsymbol_release(found_sym);

        /* We use fdata to transfer the task2sym table to the probe handler */
        fdata = (struct handler_data *) calloc(1, sizeof(*fdata));
        fdata->task2sym_entry = task2sym[i];

        /* Create a probe for a target with a symbol name and a handler */
        probe =
            probe_create(overlay, TID_GLOBAL, NULL,
                         task2sym[i].task_name, handler_line, handler_line,
                         fdata, 0, 0);
        if (!probe) {
            fprintf(stderr, "creating probe failed; aborting!\n");
            cleanup();
            exit(-3);
        }

        /* Insert a probe point (break point here) in action */
        memset(filename, 0, 1024);
        strcat(filename, task2sym[i].task_name);
        strcat(filename, ".c");
        probe =
            probe_register_line(probe, filename, task2sym[i].line,
                                PROBEPOINT_SW, 0, 0);
        if (!probe) {
            fprintf(stderr, "probe register failed; aborting!\n");
            cleanup();
            exit(-3);
        }
        g_hash_table_insert(prb_hash, task2sym[i].task_name, probe);
    }

    retint = g_hash_table_size(prb_hash);
    if (retint == 0) {
        fprintf(stderr, "No symbols to probe; exiting!\n");
        cleanup();
        exit(-1);
    }

    /* Resume the base target so that the overlay targets also gets resumed */
    target_resume(underlay);

    fprintf(stdout, "Starting Probing!\n");
    fflush(stdout);
    target_status_t tstat;

    while (1) {
        tstat = target_monitor(underlay);

        switch (tstat) {
        case TSTATUS_INTERRUPTED:
            if (needtodie) {
                target_pause(underlay);
                cleanup_probes();
                cleanup();
                exit(needtodie_exitcode);
            }
            target_resume(underlay);
            break;

        case TSTATUS_PAUSED:
            buffer_flush();
            vwarn("target %s interrupted at 0x%" PRIxREGVAL
                  "; trying resume!\n",
                  targetstr, target_read_creg(underlay, TID_GLOBAL, CREG_IP));

            if (target_resume(underlay)) {
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
            if (target_resume(underlay)) {
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

    return 0;
}

void init_underlay_spec(char *underlay_name, struct xen_vm_spec *bspec,
                        struct target_spec *tspec) {
    char targetstr[128];

    bspec->domain = underlay_name;
    bspec->memcache_mmap_size = 512 * 4096;
    bspec->kernel_filename =
        strdup("/opt/debuginfo/vm3/boot/vmlinux-2.6.32-67-server");

    tspec->target_id = 101;
    tspec->target_type = TARGET_TYPE_XEN;
    tspec->style = PROBEPOINT_SW;
    tspec->backend_spec = bspec;

    underlay = target_instantiate(tspec, NULL);

    if (!underlay) {
        fprintf(stderr, "could not instantiate target!\n");
        exit(-1);
    }

    target_snprintf(underlay, targetstr, sizeof(targetstr));

    if (target_open(underlay)) {
        fprintf(stderr, "could not open %s!\n", targetstr);
        cleanup();
        exit(-4);
    }
}

void init_overlay_specs(struct tgt_sym *task2sym, int argc,
                        struct target_spec **over_specs) {
    struct target *overlay;
    tid_t otid;
    int i;

    over_specs = (struct target_spec **) malloc(sizeof(struct target_spec *) *
                                       (argc - 2));
    for (i = 0; i < argc - 2; i++) {
        overlay = NULL;
        printf("Initializing the %d th overlay\n", i);
        over_specs[i] =
            (struct target_spec *) calloc(1, sizeof(struct target_spec));
        memset(over_specs[i], 0, sizeof(struct target_spec));
        over_specs[i]->target_id = task2sym[i].tgtid;
        over_specs[i]->target_type = TARGET_TYPE_OS_PROCESS;
        over_specs[i]->style = PROBEPOINT_SW;
        over_specs[i]->backend_spec = NULL;
        over_specs[i]->debugfile_root_prefix = strdup("/opt/debuginfo/vm3");
        otid = target_lookup_overlay_thread_by_name(underlay,
                                                 task2sym[i].task_name);
        /* Instantiate the overlay target object! */
        overlay = target_instantiate_overlay(underlay, otid, over_specs[i]);

        if (!overlay) {
            fprintf(stderr, "could not instantiate overlay target!\n");
            cleanup();
            exit(-1);
        }
        overlay_list = g_list_append(overlay_list, overlay);
    }
}

void cleanup_probes() {
    GList *tmp;
    GHashTableIter iter;
    gpointer key;
    struct probe *probe;
    struct target *tgt;

    if (overlay_list) {
        v_g_list_foreach(overlay_list, tmp, tgt) {
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

    if (overlay_list) {
        v_g_list_foreach(overlay_list, tmp, tgt) {
            target_close(tgt);
            target_finalize(tgt);
            tgt = NULL;
        }
    }
    g_list_free(overlay_list);
    overlay_list = NULL;
}

void sigh(int signo) {
    GList *tmp;
    struct target *tgt;
    int was_handling = 0;

    needtodie = 1;
    needtodie_exitcode = 0;

    if (target_monitor_handling_exception(underlay))
        target_monitor_schedule_interrupt(underlay);
    else if (overlay_list) {
        v_g_list_foreach(overlay_list, tmp, tgt) {
            if (target_monitor_handling_exception(tgt)) {
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

void extract_args(int argc, char **argv, struct tgt_sym *task2sym) {
    char *tmp, *tmp1;
    int i;
    char **argv_tmp;

    argv_tmp = (char **) malloc(sizeof(char *) * argc);
    for (i = 0; i < argc; i++) {
        argv_tmp[i] = (char *) malloc(128);
        printf("argc %d,argv[%d]==%s\n", argc, i, argv[i]);
        strcpy(argv_tmp[i], argv[i]);
    }

    for (i = 0; i < argc - 2; i++) {
        task2sym[i].tgtid = i + 1;
        printf("tgtid = %d\n", task2sym[i].tgtid);
        tmp = index(argv_tmp[i + 2], ':');
        if (tmp) {
            *tmp = '\0';
            task2sym[i].task_name = argv_tmp[i + 2];
            printf("task name = %s\n", task2sym[i].task_name);
            tmp1 = index(tmp + 1, ':');
            if (tmp1) {
                *tmp1 = '\0';
                task2sym[i].line = atoi(tmp + 1);
                printf("line = %d\n", task2sym[i].line);
            }
            task2sym[i].sym_name = tmp1 + 1;
            printf("sym_name = %s\n", task2sym[i].sym_name);
        }
        else {
            printf("input Error, check ':'\n");
        }
    }

    for (i = 0; i < argc - 2; i++) {
        printf("the %d task_name == %s, line == %d, sym_name == %s \n",
               task2sym[i].tgtid, task2sym[i].task_name, task2sym[i].line,
               task2sym[i].sym_name);
    }

    return;
}

result_t handler_line(struct probe * probe, tid_t tid, void *data,
                     struct probe * trigger, struct probe * base) {
    struct value *value;
    char buf[1024];
    struct bsymbol *psym;
    struct target *target;
    unum_t pnum;
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
