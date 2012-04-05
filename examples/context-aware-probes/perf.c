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
 *  examples/context-aware-probes/perf.c
 *
 *  Functions to access performance model during replay
 *
 *  Authors: Anton Burtsev, aburtsev@flux.utah.edu
 *  Date: April, 2012
 */

#ifdef CONFIG_DETERMINISTIC_TIMETRAVEL

#include "perf.h"
#include "debug.h"

#include <target.h>
#include <target_xen_vm.h>

int xc_handle_perf = -1;

int perf_init(void) {

    xc_handle_perf= xc_interface_open();

    if (xc_handle_perf < 0) {
        ERR("failed to open xc interface: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

unsigned long long perf_get_rdtsc(struct target *t) 
{
    vcpu_guest_context_t ctx;
    struct xen_vm_state *xstate = (struct xen_vm_state *)(t->state); 

    if (xc_vcpu_getcontext(xc_handle_perf, xstate->id, 
                           xstate->dominfo.max_vcpu_id, &ctx)) {
        ERR("Failed to get vcpu context for dom:%d, vcpu:%d\n",
            xstate->id, xstate->dominfo.max_vcpu_id);
        return 0;
    }

    return ctx.ttd_perf.tsc;
};


unsigned long long perf_get_brctr(struct target *t) 
{
    vcpu_guest_context_t ctx;
    struct xen_vm_state *xstate = (struct xen_vm_state *)(t->state); 

    if (xc_vcpu_getcontext(xc_handle_perf, xstate->id, 
                           xstate->dominfo.max_vcpu_id, &ctx)) {
        ERR("Failed to get vcpu context for dom:%d, vcpu:%d\n",
            xstate->id, xstate->dominfo.max_vcpu_id);
        return 0;
    }

    return ctx.ttd_perf.brctr;
};

#endif /* CONFIG_DETERMINISTIC_TIMETRAVEL */

