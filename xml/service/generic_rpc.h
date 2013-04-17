/*
 * Copyright (c) 2012, 2013 The University of Utah
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

#ifndef __GENERIC_RPC_H__
#define __GENERIC_RPC_H__

#include <glib.h>
#include <pthread.h>

struct generic_rpc_listener {
    int objid;
    char *hostname;
    int port;
};

typedef int (generic_rpc_listener_notifier_t)(struct generic_rpc_listener *l,
					       void *data);

void generic_rpc_init(void);
void generic_rpc_fini(void);

int generic_rpc_count_listeners(int objid);
int generic_rpc_listener_notify_all(int objid,
				    generic_rpc_listener_notifier_t *notifier,
				    void *data);


struct generic_rpc_listener *
generic_rpc_lookup_listener(int objid,char *hostname,int port);
int generic_rpc_insert_listener(int objid,char *hostname,int port);
int generic_rpc_remove_listener(int objid,char *hostname,int port);
int generic_rpc_remove_all_listeners(int objid);

#endif /* __GENERIC_RPC_H__ */
