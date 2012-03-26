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

struct bsymbol bsymbol_netif_poll_local_skb;

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

int probe_netif_poll_init(struct probe *probe) {
    return 0;
};

int probe_netif_poll(struct probe *probe, void *handler_data, struct probe *trigger)
{
    DBG("netif_poll called\n");
    return 0;
}

int probe_netif_poll_lb_skb_dequeue_init(struct probe *probe) {
    return 0;
};

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

int probe_netif_receive_skb_init(struct probe *probe) {
    return 0;
};

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

int probe_ip_rcv_init(struct probe *probe) {
    return 0;
};

int probe_ip_rcv(struct probe *probe, void *handler_data, struct probe *trigger)
{
    DBG("ip_rcv called\n");
    return 0;
}

int probe_tcp_v4_rcv_init(struct probe *probe) {
    return 0;
};

int probe_tcp_v4_rcv(struct probe *probe, void *handler_data, struct probe *trigger)
{
    DBG("tcp_v4_rcv called\n");
    return 0;
}

int probe_tcp_data_queue_init(struct probe *probe) {
    return 0;
};

int probe_tcp_data_queue(struct probe *probe, void *handler_data, struct probe *trigger)
{
    DBG("tcp_data_queue called\n");
    return 0;
}

int probe_skb_copy_datagram_iovec_init(struct probe *probe) {
    return 0;
};

int probe_skb_copy_datagram_iovec(struct probe *probe, void *handler_data, struct probe *trigger)
{
    DBG("skb_copy_datagram_iovec called\n");
    return 0;
}

int probe_svc_process_init(struct probe *probe) {
    return 0;
};

int probe_svc_process(struct probe *probe, void *handler_data, struct probe *trigger)
{
    DBG("svc_process called\n");
    return 0;
}

int probe_nfsd3_proc_write_init(struct probe *probe) {
    return 0;
};

int probe_nfsd3_proc_write(struct probe *probe, void *handler_data, struct probe *trigger)
{
    DBG("nfsd3_proc_write called\n");
    return 0;
}

int probe_do_readv_writev_ttd_copy_from_user_init(struct probe *probe) {
    return 0;
};

int probe_do_readv_writev_ttd_copy_from_user(struct probe *probe, void *handler_data, struct probe *trigger)
{
    DBG("do_readv_writev_ttd_copy_from_user called\n");
    return 0;
}

int probe_generic_file_writev_init(struct probe *probe) {
    return 0;
};

int probe_generic_file_writev(struct probe *probe, void *handler_data, struct probe *trigger)
{
    DBG("generic_file_writev called\n");
    return 0;
}

int probe_generic_file_buffered_write_init(struct probe *probe) {
    return 0;
};

int probe_generic_file_buffered_write(struct probe *probe, void *handler_data, struct probe *trigger)
{
    DBG("generic_file_buffered_write called\n");
    return 0;
}

int probe_ext3_journalled_writepage_init(struct probe *probe) {
    return 0;
};

int probe_ext3_journalled_writepage(struct probe *probe, void *handler_data, struct probe *trigger)
{
    DBG("ext3_journalled_writepage called\n");
    return 0;
}

int probe___block_write_full_page_init(struct probe *probe) {
    return 0;
};

int probe___block_write_full_page(struct probe *probe, void *handler_data, struct probe *trigger)
{
    DBG("__block_write_full_page called\n");
    return 0;
}

int probe_submit_bh_init(struct probe *probe) {
    return 0;
};

int probe_submit_bh(struct probe *probe, void *handler_data, struct probe *trigger)
{
    DBG("submit_bh called\n");
    return 0;
}

int probe_blkif_queue_request_init(struct probe *probe) {
    return 0;
};

int probe_blkif_queue_request(struct probe *probe, void *handler_data, struct probe *trigger)
{
    DBG("blkif_queue_request called\n");
    return 0;
}

int probe_blkif_int_init(struct probe *probe) {
    return 0;
};

int probe_blkif_int(struct probe *probe, void *handler_data, struct probe *trigger)
{
    DBG("blkif_int called\n");
    return 0;
}

typedef struct probe_registration {
    char                *symbol;
    probe_handler_t     handler; 
    struct probe_ops    ops;
} probe_registration_t;

const probe_registration_t probe_list[] = {
    {"netif_poll",                  probe_netif_poll, {.init = probe_netif_poll_init}},
    {"netif_poll.ttd_skb_dequeue",  probe_netif_poll_lb_skb_dequeue, {.init = probe_netif_poll_lb_skb_dequeue_init}},
    {"netif_receive_skb",           probe_netif_receive_skb, {.init = probe_netif_receive_skb_init}},
    {"ip_rcv",                      probe_ip_rcv, {.init = probe_ip_rcv_init}},
    {"tcp_v4_rcv",                  probe_tcp_v4_rcv, {.init = probe_tcp_v4_rcv_init}},
    {"tcp_data_queue",              probe_tcp_data_queue, {.init = probe_tcp_data_queue_init}},
    {"skb_copy_datagram_iovec",     probe_skb_copy_datagram_iovec, {.init = probe_skb_copy_datagram_iovec_init}},
    {"svc_process",                 probe_svc_process, {.init = probe_svc_process_init}},
    {"nfsd3_proc_write",            probe_nfsd3_proc_write, {.init = probe_nfsd3_proc_write_init}},
    {"do_readv_writev",             probe_do_readv_writev_ttd_copy_from_user, {.init = probe_do_readv_writev_ttd_copy_from_user_init}},
    {"generic_file_writev",         probe_generic_file_writev, {.init = probe_generic_file_writev_init}},
    {"generic_file_buffered_write", probe_generic_file_buffered_write, {.init = probe_generic_file_buffered_write_init}},
    {"ext3_journalled_writepage",   probe_ext3_journalled_writepage, {.init = probe_ext3_journalled_writepage_init}},
    {"__block_write_full_page",     probe___block_write_full_page, {.init = probe___block_write_full_page_init}},
    {"submit_bh",                   probe_submit_bh, {.init = probe_submit_bh_init}},
//    {"blkif_queue_request",         probe_blkif_queue_request, {.init = blkif_queue_request_init}},
    {"blkif_int",                   probe_blkif_int, {.init = probe_blkif_int_init}},
};

int register_probes(struct target *t, GHashTable *probes) {

    int i, probe_count;

    probes = g_hash_table_new(g_direct_hash, g_direct_equal);

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

        probe = probe_create(t, &probe_list[i].ops, 
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
                                   bsymbol, PROBEPOINT_FASTEST,
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



