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
 *  examples/perf-model-test/probes.c
 *
 *  Probe handlers for the network file system performance analsis
 *
 *  Authors: Anton Burtsev, aburtsev@flux.utah.edu
 * 
 */

#include <log.h>
#include <dwdebug.h>
#include <target_api.h>
#include <target.h>
#include <target_xen_vm.h>

#include <probe_api.h>
#include <probe.h>

#include <perf.h>

#include "probes.h"
#include "debug.h"

/*
unsigned long long null_start, null_end;
unsigned long long nop10_start, nop10_end;
unsigned long long nop100_start, nop100_end;
unsigned long long nop1000_start, nop1000_end;
unsigned long long nop10000_start, nop10000_end;
unsigned long long nop100000_start, nop100000_end;
unsigned long long nop1000000_start, nop1000000_end;
*/

#define PROBE_FUNC_START(name)  probe_ttd_test_perf_model_ ## name ## _start
#define PROBE_FUNC_END(name)  probe_ttd_test_perf_model_ ## name ## _end
#define PROBE_FUNC_INIT(name)  probe_ttd_test_perf_model_ ## name ## _init

#define DECLARE_PROBE_FUNCS(name) unsigned long long name ## _start; \
unsigned long long name ## _end; \
int probe_ttd_test_perf_model_ ## name ## _init \
(struct probe *probe)\
{ \
    DBG("called\n"); \
    return 0; \
} \
  \
int probe_ttd_test_perf_model_ ## name ## _start \
(struct probe *probe, void *handler_data, struct probe *trigger)\
{ \
    DBG("called\n"); \
    name ## _start = perf_get_rdtsc(probe->target); \
    return 0; \
} \
  \
int probe_ttd_test_perf_model_ ## name ## _end \
(struct probe *probe, void *handler_data, struct probe *trigger) \
{ \
    name ## _end = perf_get_rdtsc(probe->target); \
    DBG("Time to do a  ## name ##  measurement:%llu (%llu:%llu)\n", \
        name ## _end - name ## _start, name ## _start, name ## _end); \
    return 0; \
}

DECLARE_PROBE_FUNCS(nop1);
DECLARE_PROBE_FUNCS(nop10);
DECLARE_PROBE_FUNCS(nop100);
DECLARE_PROBE_FUNCS(nop1000);
DECLARE_PROBE_FUNCS(nop10000);
DECLARE_PROBE_FUNCS(nop100000);
DECLARE_PROBE_FUNCS(nop1000000);

typedef struct probe_registration {
    char                *symbol;
    probe_handler_t     handler; 
    struct probe_ops    ops;
} probe_registration_t;

const probe_registration_t probe_list[] = {
    {"ttd_test_perf_model_perf_null_start", PROBE_FUNC_START(nop1), {.init = PROBE_FUNC_INIT(nop1)}},
    {"ttd_test_perf_model_perf_null_end", PROBE_FUNC_END(nop1), {.init = PROBE_FUNC_INIT(nop1)}},
    {"ttd_test_perf_model_perf_nop10_start", PROBE_FUNC_START(nop10), {.init = PROBE_FUNC_INIT(nop10)}},
    {"ttd_test_perf_model_perf_nop10_end", PROBE_FUNC_END(nop10), {.init = PROBE_FUNC_INIT(nop10)}},
    {"ttd_test_perf_model_perf_nop100_start", PROBE_FUNC_START(nop100), {.init = PROBE_FUNC_INIT(nop100)}},
    {"ttd_test_perf_model_perf_nop100_end", PROBE_FUNC_END(nop100), {.init = PROBE_FUNC_INIT(nop100)}},
    {"ttd_test_perf_model_perf_nop1000_start",PROBE_FUNC_START(nop1000), {.init = PROBE_FUNC_INIT(nop1000)}},
    {"ttd_test_perf_model_perf_nop1000_end", PROBE_FUNC_END(nop1000), {.init = PROBE_FUNC_INIT(nop1000)}},
    {"ttd_test_perf_model_perf_nop10000_start",PROBE_FUNC_START(nop10000), {.init = PROBE_FUNC_INIT(nop10000)}},
    {"ttd_test_perf_model_perf_nop10000_end", PROBE_FUNC_END(nop10000), {.init = PROBE_FUNC_INIT(nop10000)}},
    {"ttd_test_perf_model_perf_nop100000_start", PROBE_FUNC_START(nop100000), {.init = PROBE_FUNC_INIT(nop100000)}},
    {"ttd_test_perf_model_perf_nop100000_end", PROBE_FUNC_END(nop100000), {.init = PROBE_FUNC_INIT(nop100000)}},
    {"ttd_test_perf_model_perf_nop1000000_start", PROBE_FUNC_START(nop1000000), {.init = PROBE_FUNC_INIT(nop1000000)}},
    {"ttd_test_perf_model_perf_nop1000000_end", PROBE_FUNC_END(nop1000000), {.init = PROBE_FUNC_INIT(nop1000000)}},

};


int register_probes(struct target *t, GHashTable *probes) {

    int i, probe_count;
    struct bsymbol *bsymbol;
    struct probe *probe;

    probes = g_hash_table_new(g_direct_hash, g_direct_equal);

    perf_init();
    
    /*
     * Inject probes at locations specified in probe_list.
     */
    probe_count = sizeof(probe_list) / sizeof(probe_list[0]);
    for (i = 0; i < probe_count; i++)
    {
        bsymbol = target_lookup_sym(t, probe_list[i].symbol, ".", NULL, SYMBOL_TYPE_FLAG_NONE);
        if (!bsymbol)
        {
            ERR("Could not find symbol %s!\n", probe_list[i].symbol);
            unregister_probes(probes);
            target_close(t);
            return -1;
        }

        //bsymbol_dump(bsymbol, &udn);

        probe = probe_create(t, TID_GLOBAL, &probe_list[i].ops, 
                             bsymbol->lsymbol->symbol->name,
                             probe_list[i].handler, NULL, NULL, 0);
        if (!probe)
        {
            ERR("could not create probe on '%s'\n", 
                bsymbol->lsymbol->symbol->name);
            unregister_probes(probes);
            return -1;
        }

        if (!probe_register_symbol(probe, 
                                   bsymbol, PROBEPOINT_SW /*PROBEPOINT_FASTEST*/,
                                   PROBEPOINT_EXEC, PROBEPOINT_LAUTO))
        {
            ERR("could not register probe on '%s'\n",
                bsymbol->lsymbol->symbol->name);
            probe_free(probe, 1);
            unregister_probes(probes);
            return -1;
        }
        g_hash_table_insert(probes, 
                            (gpointer)probe->probepoint->addr, 
                            (gpointer)probe);
    }

    return 0;
};

void unregister_probes(GHashTable *probes)
{
    GHashTableIter iter;
    gpointer key;
    struct probe *probe;

    g_hash_table_iter_init(&iter, probes);
    while (g_hash_table_iter_next(&iter,
                (gpointer)&key,
                (gpointer)&probe))
    {
        probe_unregister(probe,1);
    }

    return;
}



