/*
 * Copyright (c) 2014 The University of Utah
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

#ifndef __NULLPAGE_H__
#define __NULLPAGE_H__

#include <glib.h>
#include "common.h"
#include "target_api.h"
#include "probe_api.h"

struct np_config {
    unsigned int do_mmap:1,
	do_mprotect:1,
	do_pgfault:1;
    int ttctx;
    int ttdetail;
};

struct np_status {
    struct np_config *config;

    struct target *target;

    /* Metaprobe. */
    struct probe *np_probe;

    /* Subordinate probes. */
    struct probe *pgfault_probe;
    struct probe *mmap_probe;
    struct probe *mprotect_probe;

    unsigned int mmap_violations;
    unsigned int mprotect_violations;
    unsigned int pgfault_violations;
    unsigned int total_violations;
};

#define NP_IS_MMAP(trigger,nps) ((trigger) == (nps)->mmap_probe)
#define NP_IS_MPROTECT(trigger,nps) ((trigger) == (nps)->mprotect_probe)
#define NP_IS_PGFAULT(trigger,nps) ((trigger) == (nps)->pgfault_probe)

/*
 * Create a null-page r/w/x "probe".
 */
struct probe *probe_np(struct target *target,struct np_config *npc,
		       probe_handler_t pre_handler,probe_handler_t post_handler,
		       void *handler_data);

extern struct argp np_argp;

#endif /* __NULLPAGE_H__ */
