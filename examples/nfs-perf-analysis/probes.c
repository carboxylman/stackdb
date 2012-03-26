/*
 * Copyright (c) 2011, 2012 The University of Utah
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
 * Foundation, 51 Franklin St, Suite 500, Boston, MA 02110-1335, USA.
 * 
 *  examples/nfs-perf-analysis/probes.c
 *
 *  Probe handlers for the network file system performance analsis
 *
 *  Authors: Anton Burtsev, aburtsev@flux.utah.edu
 * 
 */

#include <probe.h>

#include "probes.h"
#include "debug.h"


typedef struct reg_var {
    char           *name;
    struct bsymbol *bsymbol;
} reg_var_t;

struct bsymbol bsymbol_netif_poll_local_skb;

const reg_var_t var_list[] = {
        {"skb",                  &bsymbol_netif_poll_local_skb},
};

int register_vars(){
    int i, var_count;

    varcount = sizeof(var_list) / sizeof(var_list[0]);
    for (i = 0; i < var_count; i++)
    {
        cmdlist[i].bsymbol = target_lookup_sym(target, cmdlist[i].name, ".", 
                                                NULL, SYMBOL_TYPE_FLAG_NONE);
        if (!cmdlist[i].bsymbol)
        {
            ERR("Could not find symbol %s!\n", cmdlist[i].symbol);
            return -1;
        }

    }
}


typedef enum nfs_perf_stage_id {
        STAGE_ID_NETIF_POLL             1, 
        STAGE_ID_NETIF_POLL_SKB_DEQUEUE 2,
} nfs_perf_stage_id_t;

/* XXX: This funciton pollutes the kernel binary since it's included in many places */
static inline char *stage_id_to_name(nfs_perf_stage_id_t id) {
    switch ( id ) {
    case STAGE_ID_NETIF_POLL: return "netif_poll";
    case STAGE_ID_NETIF_POLL_SKB_DEQUEUE: return "netif_poll_skb_dequeue";
    default: return "undefined";
    };
};

int probe_netif_poll(struct probe *probe, void *handler_data, struct probe *trigger)
{
    DBG("netif_poll called\n");
    return 0;
}

int probe_netif_poll_lb_skb_dequeue(struct probe *probe, void *handler_data, struct probe *trigger)
{
    struct request *req;
    struct stage   *req_stage;

    DBG("netif_poll at label skb_dequeue called\n");

#if 0

    /* we add a new request to the analysis */
    req = request_alloc();
    if (!req) {
        ERR("Failed to allocate request\n");
        return 0;
    }

    req_stage = request_stage_alloc(stage_id_to_name(STAGE_ID_NETIF_POLL));
    if (!req_stage) {
        ERR("Failed to allocate request stage\n");
        request_free(req);
        return 0;
    }

    /* XXX: read the timestampt here */
    req_stage->timestamp = 0;

    /* XXX: read stage id (address of the skb) */
    req_stage->id = 0;

    request_add_stage(req, req_stage);
#endif

    return 0;
}

int probe_netif_receive_skb(struct probe *probe, void *handler_data, struct probe *trigger)
{
    struct request *req;
    struct stage   *req_stage;
    u32 req_id;

    DBG("netif_receive_skb called\n");

    /* XXX: read request id -- address of the skb passed to the netif_skb_function */
    req_id = 0;
    return 0;
}

int probe_ip_rcv(struct probe *probe, void *handler_data, struct probe *trigger)
{
    DBG("ip_rcv called\n");
    return 0;
}

int probe_tcp_v4_rcv(struct probe *probe, void *handler_data, struct probe *trigger)
{
    DBG("tcp_v4_rcv called\n");
    return 0;
}

int probe_tcp_data_queue(struct probe *probe, void *handler_data, struct probe *trigger)
{
    DBG("tcp_data_queue called\n");
    return 0;
}

int probe_skb_copy_datagram_iovec(struct probe *probe, void *handler_data, struct probe *trigger)
{
    DBG("skb_copy_datagram_iovec called\n");
    return 0;
}

int probe_svc_process(struct probe *probe, void *handler_data, struct probe *trigger)
{
    DBG("svc_process called\n");
    return 0;
}

int probe_nfsd3_proc_write(struct probe *probe, void *handler_data, struct probe *trigger)
{
    DBG("nfsd3_proc_write called\n");
    return 0;
}

int probe_do_readv_writev_ttd_copy_from_user(struct probe *probe, void *handler_data, struct probe *trigger)
{
    DBG("do_readv_writev_ttd_copy_from_user called\n");
    return 0;
}

int probe_generic_file_writev(struct probe *probe, void *handler_data, struct probe *trigger)
{
    DBG("generic_file_writev called\n");
    return 0;
}

int probe_generic_file_buffered_write(struct probe *probe, void *handler_data, struct probe *trigger)
{
    DBG("generic_file_buffered_write called\n");
    return 0;
}

int probe_ext3_journalled_writepage(struct probe *probe, void *handler_data, struct probe *trigger)
{
    DBG("ext3_journalled_writepage called\n");
    return 0;
}

int probe___block_write_full_page(struct probe *probe, void *handler_data, struct probe *trigger)
{
    DBG("__block_write_full_page called\n");
    return 0;
}

int probe_submit_bh(struct probe *probe, void *handler_data, struct probe *trigger)
{
    DBG("submit_bh called\n");
    return 0;
}

int probe_blkif_queue_request(struct probe *probe, void *handler_data, struct probe *trigger)
{
    DBG("blkif_queue_request called\n");
    return 0;
}

int probe_blkif_int(struct probe *probe, void *handler_data, struct probe *trigger)
{
    DBG("blkif_int called\n");
    return 0;
}





