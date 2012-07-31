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
 *  examples/context-tracker/examples/perf.h
 *
 *  Functions to access performance model during replay.
 *
 *  Authors: Anton Burtsev, aburtsev@flux.utah.edu
 *  Date: April, 2012
 * 
 */

#ifndef __CTXTRACKER_EXAMPLES_PERF_H__
#define __CTXTRACKER_EXAMPLES_PERF_H__

#ifdef CONFIG_DETERMINISTIC_TIMETRAVEL

#include <target.h>

int perf_init(void);
unsigned long long perf_get_rdtsc(struct target *t);
unsigned long long perf_get_brctr(struct target *t);

#endif /* CONFIG_DETERMINISTIC_TIMETRAVEL */

#endif /* __CTXTRACKER_EXAMPLES_PERF_H__ */
