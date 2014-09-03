/*
 * Copyright (c) 2013, 2014 The University of Utah
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

#ifndef __TARGET_OS_PROCESS_H__
#define __TARGET_OS_PROCESS_H__

#include <glib.h>

#include "evloop.h"
#include "target_api.h"

/*
 * Notes:
 *
 * First, we always add all threads in the thread group associated with
 * the thread the user instantiates the overlay for.  If they don't
 * provide the main thread, we "pivot" it into place in our init() ops.
 */

extern struct target_ops os_process_ops;

struct os_process_spec *os_process_build_spec(void);
void os_process_free_spec(struct os_process_spec *spec);

/*
 * Nothing at the moment.
 */
struct os_process_spec { };
struct os_process_thread_state { };


struct os_process_state {
    uint8_t loading_memory:1;
};

#endif /* __TARGET_OS_PROCESS_H__ */
