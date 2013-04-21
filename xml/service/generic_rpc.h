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

#include "alist.h"

#include <glib.h>
#include <pthread.h>
#include <stdsoap2.h>

typedef enum {
    RPC_SVCTYPE_TARGET   = 1,
    RPC_SVCTYPE_ANALYSIS = 2,
} rpc_svctype_t;

#define generic_rpc_argp_header "Generic RPC Server Options"
extern struct argp generic_rpc_argp;

struct generic_rpc_config {
    char *name;

    /*
     * State for the siginfowait thread.
     */
    sigset_t sigset;

    int port;

    /*
     * Functions.
     */
    int (*handle_request)(struct soap *soap);
};

/*
 * We support a sort of strange listener API.  Basically, we want to
 * expose not a multiplicity of listener interfaces, but rather a
 * per-service interface.  However, each service might offer multiple
 * object types and event types on those objects.
 *
 * Eventually, we will allow per-listener filtering, but for now, all we
 * care about is ownership.  Listener RPCs usually return something that
 * affects the service object being listened to; so there can only be
 * one authoritative listener that has control.  The server *must* wait
 * for a response (for a very long timeout) from the authoritative
 * listener; but it must not block on any other listeners unduly.
 *
 * For many reasons, it is complicated to have one listener own a probe,
 * but have another listener own that probe's target.  The primary
 * reason is that probe IDs are only unique to the target; they are not
 * unique per VMI process.  That would require us to coordinate probe Id
 * assignment between any target served by the server.  This is fine if
 * all targets are thread-backed, because we share the VMI process's
 * address space; but since some targets can be forked, we can't do it.
 *
 * So, for now, a target's owning listener also owns its probes and
 * actions.  This probably will never matter, so leave it this way in
 * this "generic" listener model.
 */

struct generic_rpc_listener {
    /* The listener ID. */
    int id;

    /* The RPC type the listener supports. */
    rpc_svctype_t svctype;

    /* A table of objids it is listening to; values are always NULL. */
    GHashTable *objid_tab;

    /*
     * An already-connected soap struct.  We try to use this if non-NULL
     * -- but only if it is still live.  We also only stash it if it
     * supports HTTP keep-alives.
     */
    struct soap soap;

    int errors;

    /*
     * The listener endpoint.
     */
    char *url;
};

typedef int (generic_rpc_listener_notifier_t)(struct generic_rpc_listener *l,
					      int is_owner,void *data);

void generic_rpc_init(void);
void generic_rpc_fini(void);

void generic_rpc_register_svctype(rpc_svctype_t svctype);
void generic_rpc_unregister_svctype(rpc_svctype_t svctype);

int generic_rpc_serve(struct generic_rpc_config *cfg);
/*
 * A generic handler that detaches the pthread, calls soap_serve, and
 * destroys the soap context when finished.
 */
int generic_rpc_handle_request(struct soap *soap);

struct generic_rpc_listener *
generic_rpc_lookup_listener_url(rpc_svctype_t svctype,char *url);
struct generic_rpc_listener *
generic_rpc_lookup_listener_id(rpc_svctype_t svctype,int listener_id);

int generic_rpc_insert_listener(rpc_svctype_t svctype,char *url);
int generic_rpc_remove_listener(rpc_svctype_t svctype,int listener_id);

int generic_rpc_count_listeners(rpc_svctype_t svctype,int objid);

int generic_rpc_listener_notify_all(rpc_svctype_t svctype,int objid,
				    generic_rpc_listener_notifier_t *notifier,
				    void *data);


int generic_rpc_insert_listener(rpc_svctype_t svctype,char *url);
int generic_rpc_remove_listener(rpc_svctype_t svctype,int listener_id);

int generic_rpc_bind_listener_objid(rpc_svctype_t svctype,int listener_id,
				    int objid,int owns);
int generic_rpc_unbind_listener_objid(rpc_svctype_t svctype,int listener_id,
				      int objid);

int generic_rpc_unbind_all_listeners_objid(rpc_svctype_t svctype,int objid);

#endif /* __GENERIC_RPC_H__ */
