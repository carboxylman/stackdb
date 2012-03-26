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

#include <log.h>
#include <dwdebug.h>
#include <target_api.h>
#include <target.h>
#include <target_xen_vm.h>

#include <probe_api.h>
#include <probe.h>

#include "probes.h"
#include "debug.h"
//#include "request.h"

struct bsymbol *bsymbol_netif_poll_lvar_skb = NULL;
struct bsymbol *bsymbol_netif_receive_skb_lvar_skb = NULL;
struct bsymbol *bsymbol_skb_copy_datagram_iovec_lvar_skb = NULL;
struct bsymbol *bsymbol_skb_copy_datagram_iovec_lvar_to = NULL;
struct bsymbol *bsymbol_ip_rcv_lvar_skb = NULL;
struct bsymbol *bsymbol_tcp_v4_rcv_lvar_skb = NULL;
struct bsymbol *bsymbol_tcp_data_queue_lvar_skb = NULL;
struct bsymbol *bsymbol_do_readv_writev_lvar_iov = NULL;
struct bsymbol *bsymbol_do_readv_writev_lvar_uvector = NULL;
struct bsymbol *bsymbol_generic_file_writev_lvar_iov = NULL;
struct bsymbol *bsymbol_generic_file_buffered_write_lvar_iov = NULL;
struct bsymbol *bsymbol_generic_file_buffered_write_lvar_page = NULL;
struct bsymbol *bsymbol_ext3_journalled_writepage_lvar_page = NULL;
struct bsymbol *bsymbol___block_write_full_page_lvar_page = NULL;
struct bsymbol *bsymbol___block_write_full_page_lvar_bh = NULL;
struct bsymbol *bsymbol_submit_bh_lvar_bh = NULL;
struct bsymbol *bsymbol_submit_bh_lvar_bio = NULL;
struct bsymbol *bsymbol_blkif_queue_request_lvar_bio = NULL;
struct bsymbol *bsymbol_blkif_queue_request_lvar_id = NULL;
struct bsymbol *bsymbol_blkif_int_lvar_id = NULL;

typedef enum nfs_perf_stage_id {
        STAGE_ID_NETIF_POLL              = 1, 
        STAGE_ID_NETIF_POLL_SKB_DEQUEUE  = 2,
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
    DBG("netif_poll_init called\n");
    return 0;
};

int probe_netif_poll(struct probe *probe, void *handler_data, struct probe *trigger)
{
    DBG("netif_poll called\n");
    return 0;
}

int probe_netif_poll_lb_skb_dequeue_init(struct probe *probe) {
    DBG("netif_poll_lb_skb_dequeue_init at label skb_dequeue called\n");

    bsymbol_netif_poll_lvar_skb = target_lookup_sym(probe->target, "netif_poll.skb", ".", NULL, SYMBOL_TYPE_NONE); 
    if (!bsymbol_netif_poll_lvar_skb) {
        ERR("Failed to create a bsymbol for netif_poll.skb\n");
        return -1;
    }

    return 0;
};

int probe_netif_poll_lb_skb_dequeue(struct probe *probe, void *handler_data, struct probe *trigger)
{
    struct request *req;
    struct stage   *req_stage;
    struct value   *lval_skb;

    DBG("netif_poll at label skb_dequeue called\n");

    lval_skb = bsymbol_load(bsymbol_netif_poll_lvar_skb, LOAD_FLAG_NONE);
    if (!lval_skb) {
        ERR("Cannot access value of skb\n");
        return -1;
    }
    DBG("skb = 0x%lx\n", *(unsigned long*)lval_skb->buf);

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
    req_id = *(unsigned long*)lval_skb->buf;

    request_add_stage(req, req_stage);
#endif

    return 0;
}

int probe_netif_receive_skb_init(struct probe *probe) {
    DBG("netif_receive_skb_init called\n");

    bsymbol_netif_receive_skb_lvar_skb = target_lookup_sym(probe->target, "netif_receive_skb.skb", ".", NULL, SYMBOL_TYPE_NONE); 
    if (!bsymbol_netif_receive_skb_lvar_skb) {
        ERR("Failed to create a bsymbol for netif_receive_skb.skb\n");
        return -1;
    }

    return 0;
};

int probe_netif_receive_skb(struct probe *probe, void *handler_data, struct probe *trigger)
{
    struct request *req;
    struct stage   *req_stage;
    unsigned long   req_id;
    struct value   *lval_skb;

    DBG("netif_receive_skb called\n");

    lval_skb = bsymbol_load(bsymbol_netif_receive_skb_lvar_skb, LOAD_FLAG_NONE);
    if (!lval_skb) {
        ERR("Cannot access value of skb\n");
        return -1;
    }
    DBG("skb = 0x%lx\n", *(unsigned long*)lval_skb->buf);

    /* Rrequest id is address of the skb passed to the netif_skb_function */
    req_id = *(unsigned long*)lval_skb->buf;
    return 0;
}

int probe_ip_rcv_init(struct probe *probe) {

    DBG("ip_rcv called\n");

    bsymbol_ip_rcv_lvar_skb = target_lookup_sym(probe->target, "ip_rcv.skb", ".", NULL, SYMBOL_TYPE_NONE); 
    if (!bsymbol_ip_rcv_lvar_skb) {
        ERR("Failed to create a bsymbol for ip_rcv.skb\n");
        return -1;
    }

    return 0;
};

int probe_ip_rcv(struct probe *probe, void *handler_data, struct probe *trigger)
{
    struct value   *lval_skb;

    DBG("ip_rcv called\n");

    lval_skb = bsymbol_load(bsymbol_ip_rcv_lvar_skb, LOAD_FLAG_NONE);
    if (!lval_skb) {
        ERR("Cannot access value of skb\n");
        return -1;
    }
    DBG("skb = 0x%lx\n", *(unsigned long*)lval_skb->buf);
    return 0;
}

int probe_tcp_v4_rcv_init(struct probe *probe) {
    DBG("tcp_v4_rcv_init called\n");

    bsymbol_tcp_v4_rcv_lvar_skb = target_lookup_sym(probe->target, "tcp_v4_rcv.skb", ".", NULL, SYMBOL_TYPE_NONE); 
    if (!bsymbol_tcp_v4_rcv_lvar_skb) {
        ERR("Failed to create a bsymbol for tcp_v4_rcv.skb\n");
        return -1;
    }

    return 0;
};

int probe_tcp_v4_rcv(struct probe *probe, void *handler_data, struct probe *trigger)
{
    struct value   *lval_skb;

    DBG("tcp_v4_rcv called\n");

    lval_skb = bsymbol_load(bsymbol_tcp_v4_rcv_lvar_skb, LOAD_FLAG_NONE);
    if (!lval_skb) {
        ERR("Cannot access value of skb\n");
        return -1;
    }
    DBG("skb = 0x%lx\n", *(unsigned long*)lval_skb->buf);
    return 0;
}

int probe_tcp_data_queue_init(struct probe *probe) {
    DBG("tcp_data_queue_init called\n");

    bsymbol_tcp_data_queue_lvar_skb = target_lookup_sym(probe->target, "tcp_data_queue.skb", ".", NULL, SYMBOL_TYPE_NONE); 
    if (!bsymbol_tcp_data_queue_lvar_skb) {
        ERR("Failed to create a bsymbol for tcp_data_queue.skb\n");
        return -1;
    }

    return 0;
};

int probe_tcp_data_queue(struct probe *probe, void *handler_data, struct probe *trigger)
{
    struct value   *lval_skb;

    DBG("tcp_data_queue called\n");

    lval_skb = bsymbol_load(bsymbol_tcp_data_queue_lvar_skb, LOAD_FLAG_NONE);
    if (!lval_skb) {
        ERR("Cannot access value of skb\n");
        return -1;
    }
    DBG("skb = 0x%lx\n", *(unsigned long*)lval_skb->buf);

    return 0;
}

int probe_skb_copy_datagram_iovec_init(struct probe *probe) {
    DBG("skb_copy_datagram_iovec_init called\n");

    bsymbol_skb_copy_datagram_iovec_lvar_skb = target_lookup_sym(probe->target, "skb_copy_datagram_iovec.skb", ".", NULL, SYMBOL_TYPE_NONE); 
    if (!bsymbol_skb_copy_datagram_iovec_lvar_skb) {
        ERR("Failed to create a bsymbol for skb_copy_datagram_iovec.skb\n");
        return -1;
    }

    bsymbol_skb_copy_datagram_iovec_lvar_to = target_lookup_sym(probe->target, "skb_copy_datagram_iovec.to", ".", NULL, SYMBOL_TYPE_NONE); 
    if (!bsymbol_skb_copy_datagram_iovec_lvar_to) {
        ERR("Failed to create a bsymbol for skb_copy_datagram_iovec.to\n");
        return -1;
    }

    return 0;
};

int probe_skb_copy_datagram_iovec(struct probe *probe, void *handler_data, struct probe *trigger)
{
    struct value   *lval_skb;
    struct value   *lval_to;

    DBG("skb_copy_datagram_iovec called\n");

    lval_skb = bsymbol_load(bsymbol_skb_copy_datagram_iovec_lvar_skb, LOAD_FLAG_NONE);
    if (!lval_skb) {
        ERR("Cannot access value of skb\n");
        return -1;
    }
    DBG("skb = 0x%lx\n", *(unsigned long*)lval_skb->buf);

    lval_to = bsymbol_load(bsymbol_skb_copy_datagram_iovec_lvar_to, LOAD_FLAG_NONE);
    if (!lval_to) {
        ERR("Cannot access value of to\n");
        return -1;
    }
    DBG("iovec to = 0x%lx\n", *(unsigned long*)lval_to->buf);

    return 0;
}

int probe_svc_process_init(struct probe *probe) {
    DBG("svc_process_init called\n");
    return 0;
};

int probe_svc_process(struct probe *probe, void *handler_data, struct probe *trigger)
{
    DBG("svc_process called\n");
    return 0;
}

int probe_nfsd3_proc_write_init(struct probe *probe) {
    DBG("nfsd3_proc_write_init called\n");
    return 0;
};

int probe_nfsd3_proc_write(struct probe *probe, void *handler_data, struct probe *trigger)
{
    DBG("nfsd3_proc_write called\n");
    return 0;
}

int probe_do_readv_writev_ttd_copy_from_user_init(struct probe *probe) {
    DBG("do_readv_writev_ttd_copy_from_user_init called\n");

    bsymbol_do_readv_writev_lvar_uvector = target_lookup_sym(probe->target, "do_readv_writev.uvector", ".", NULL, SYMBOL_TYPE_NONE); 
    if (!bsymbol_do_readv_writev_lvar_uvector) {
        ERR("Failed to create a bsymbol for do_readv_writev.uvector\n");
        return -1;
    }

    bsymbol_do_readv_writev_lvar_iov = target_lookup_sym(probe->target, "do_readv_writev.iov", ".", NULL, SYMBOL_TYPE_NONE); 
    if (!bsymbol_do_readv_writev_lvar_iov) {
        ERR("Failed to create a bsymbol for do_readv_writev.iov\n");
        return -1;
    }

    return 0;
};

int probe_do_readv_writev_ttd_copy_from_user(struct probe *probe, void *handler_data, struct probe *trigger)
{
    struct value   *lval_uvector;
    struct value   *lval_iov;

    DBG("do_readv_writev.ttd_copy_from_user called\n");

    lval_uvector = bsymbol_load(bsymbol_do_readv_writev_lvar_uvector, LOAD_FLAG_NONE);
    if (!lval_uvector) {
        ERR("Cannot access value of uvector\n");
        return -1;
    }
    DBG("uvector = 0x%lx\n", *(unsigned long*)lval_uvector->buf);

    lval_iov = bsymbol_load(bsymbol_do_readv_writev_lvar_iov, LOAD_FLAG_NONE);
    if (!lval_iov) {
        ERR("Cannot access value of iov\n");
        return -1;
    }
    DBG("iov = 0x%lx\n", *(unsigned long*)lval_iov->buf);

    return 0;
}

int probe_generic_file_writev_init(struct probe *probe) {
    DBG("generic_file_writev_init called\n");

    bsymbol_generic_file_writev_lvar_iov = target_lookup_sym(probe->target, "generic_file_writev.iov", ".", NULL, SYMBOL_TYPE_NONE); 
    if (!bsymbol_generic_file_writev_lvar_iov) {
        ERR("Failed to create a bsymbol for generic_file_writev.iov\n");
        return -1;
    }

    return 0;
};

int probe_generic_file_writev(struct probe *probe, void *handler_data, struct probe *trigger)
{
    struct value   *lval_iov;

    DBG("generic_file_writev called\n");

    lval_iov = bsymbol_load(bsymbol_generic_file_writev_lvar_iov, LOAD_FLAG_NONE);
    if (!lval_iov) {
        ERR("Cannot access value of iov\n");
        return -1;
    }
    DBG("iov = 0x%lx\n", *(unsigned long*)lval_iov->buf);

    return 0;
}

int probe_generic_file_buffered_write_init(struct probe *probe) {
    DBG("generic_file_buffered_write_init called\n");

    bsymbol_generic_file_buffered_write_lvar_iov 
        = target_lookup_sym(probe->target, "generic_file_buffered_write.iov", ".", NULL, SYMBOL_TYPE_NONE); 
    if (!bsymbol_generic_file_buffered_write_lvar_iov) {
        ERR("Failed to create a bsymbol for generic_file_buffered_write.iov\n");
        return -1;
    }

    bsymbol_generic_file_buffered_write_lvar_page 
        = target_lookup_sym(probe->target, "generic_file_buffered_write.page", ".", NULL, SYMBOL_TYPE_NONE); 
    if (!bsymbol_generic_file_buffered_write_lvar_page) {
        ERR("Failed to create a bsymbol for generic_file_buffered_write.page\n");
        return -1;
    }
    return 0;
};

int probe_generic_file_buffered_write(struct probe *probe, void *handler_data, struct probe *trigger)
{
    struct value   *lval_iov;
    struct value   *lval_page;

    DBG("generic_file_buffered_write called\n");
    lval_iov = bsymbol_load(bsymbol_generic_file_buffered_write_lvar_iov, LOAD_FLAG_NONE);
    if (!lval_iov) {
        ERR("Cannot access value of iov\n");
        return -1;
    }
    DBG("iov = 0x%lx\n", *(unsigned long*)lval_iov->buf);

    lval_page = bsymbol_load(bsymbol_generic_file_buffered_write_lvar_page, LOAD_FLAG_NONE);
    if (!lval_page) {
        ERR("Cannot access value of page\n");
        return -1;
    }
    DBG("page = 0x%lx\n", *(unsigned long*)lval_page->buf);

    return 0;
}

int probe_ext3_journalled_writepage_init(struct probe *probe) {
    DBG("ext3_journalled_writepage_init called\n");

    bsymbol_ext3_journalled_writepage_lvar_page 
        = target_lookup_sym(probe->target, "ext3_journalled_writepage.page", ".", NULL, SYMBOL_TYPE_NONE); 
    if (!bsymbol_ext3_journalled_writepage_lvar_page) {
        ERR("Failed to create a bsymbol for ext3_journalled_writepage.page\n");
        return -1;
    }

    return 0;
};

int probe_ext3_journalled_writepage(struct probe *probe, void *handler_data, struct probe *trigger)
{
    struct value   *lval_page;

    DBG("ext3_journalled_writepage called\n");
    lval_page = bsymbol_load(bsymbol_ext3_journalled_writepage_lvar_page, LOAD_FLAG_NONE);
    if (!lval_page) {
        ERR("Cannot access value of page\n");
        return -1;
    }
    DBG("page = 0x%lx\n", *(unsigned long*)lval_page->buf);
    return 0;
}

int probe___block_write_full_page_init(struct probe *probe) {
    DBG("__block_write_full_page_init called\n");

    bsymbol___block_write_full_page_lvar_page
        = target_lookup_sym(probe->target, "__block_write_full_page.page", ".", NULL, SYMBOL_TYPE_NONE); 
    if (!bsymbol___block_write_full_page_lvar_page) {
        ERR("Failed to create a bsymbol for __block_write_full_page.page\n");
        return -1;
    }

    bsymbol___block_write_full_page_lvar_bh
        = target_lookup_sym(probe->target, "__block_write_full_page.bh", ".", NULL, SYMBOL_TYPE_NONE); 
    if (!bsymbol___block_write_full_page_lvar_bh) {
        ERR("Failed to create a bsymbol for __block_write_full_page.bh\n");
        return -1;
    }

    return 0;
};

int probe___block_write_full_page(struct probe *probe, void *handler_data, struct probe *trigger)
{
    struct value   *lval_page;
    struct value   *lval_bh;

    DBG("__block_write_full_page called\n");

    lval_page = bsymbol_load(bsymbol___block_write_full_page_lvar_page, LOAD_FLAG_NONE);
    if (!lval_page) {
        ERR("Cannot access value of page\n");
        return -1;
    }
    DBG("page = 0x%lx\n", *(unsigned long*)lval_page->buf);

    lval_bh = bsymbol_load(bsymbol___block_write_full_page_lvar_bh, LOAD_FLAG_NONE);
    if (!lval_bh) {
        ERR("Cannot access value of page\n");
        return -1;
    }
    DBG("page = 0x%lx\n", *(unsigned long*)lval_bh->buf);

    return 0;
}

int probe_submit_bh_init(struct probe *probe) {
    DBG("submit_bh_init called\n");

    bsymbol_submit_bh_lvar_bh
        = target_lookup_sym(probe->target, "submit_bh.bh", ".", NULL, SYMBOL_TYPE_NONE); 
    if (!bsymbol_submit_bh_lvar_bh) {
        ERR("Failed to create a bsymbol for submit_bh.bh\n");
        return -1;
    }

    bsymbol_submit_bh_lvar_bio
        = target_lookup_sym(probe->target, "submit_bh.bio", ".", NULL, SYMBOL_TYPE_NONE);
    if (!bsymbol_submit_bh_lvar_bio) {
        ERR("Failed to create a bsymbol for submit_bh.bio\n");
        return -1;
    }

    return 0;
};

int probe_submit_bh(struct probe *probe, void *handler_data, struct probe *trigger)
{
    struct value   *lval_bh;
    struct value   *lval_bio;

    DBG("submit_bh called\n");
    
    lval_bh  = bsymbol_load(bsymbol_submit_bh_lvar_bh, LOAD_FLAG_NONE);
    if (!lval_bh) {
        ERR("Cannot access value of bh\n");
        return -1;
    }
    DBG("bh = 0x%lx\n", *(unsigned long*)lval_bh->buf);

    lval_bio  = bsymbol_load(bsymbol_submit_bh_lvar_bio, LOAD_FLAG_NONE);
    if (!lval_bio) {
        ERR("Cannot access value of bio\n");
        return -1;
    }
    DBG("bio = 0x%lx\n", *(unsigned long*)lval_bio->buf);
    return 0;
}

int probe_blkif_queue_request_init(struct probe *probe) {
    DBG("blkif_queue_request_init called\n");

    bsymbol_blkif_queue_request_lvar_bio
        = target_lookup_sym(probe->target, "blkif_queue_request.bio", ".", NULL, SYMBOL_TYPE_NONE); 
    if (!bsymbol_blkif_queue_request_lvar_bio) {
        ERR("Failed to create a bsymbol for blkif_queue_request.bio\n");
        return -1;
    }

    bsymbol_blkif_queue_request_lvar_id
        = target_lookup_sym(probe->target, "blkif_queue_request.id", ".", NULL, SYMBOL_TYPE_NONE); 
    if (!bsymbol_blkif_queue_request_lvar_id) {
        ERR("Failed to create a bsymbol for blkif_queue_request.id\n");
        return -1;
    }

    return 0;
};

int probe_blkif_queue_request(struct probe *probe, void *handler_data, struct probe *trigger)
{
    struct value   *lval_bio;
    struct value   *lval_id;

    DBG("blkif_queue_request called\n");

    lval_bio  = bsymbol_load(bsymbol_blkif_queue_request_lvar_bio, LOAD_FLAG_NONE);
    if (!lval_bio) {
        ERR("Cannot access value of bh\n");
        return -1;
    }
    DBG("bio = 0x%lx\n", *(unsigned long*)lval_bio->buf);

    lval_id  = bsymbol_load(bsymbol_blkif_queue_request_lvar_id, LOAD_FLAG_NONE);
    if (!lval_id) {
        ERR("Cannot access value of id\n");
        return -1;
    }
    DBG("id = 0x%lx\n", *(unsigned long*)lval_id->buf);
    return 0;
}

int probe_blkif_int_init(struct probe *probe) {
    DBG("blkif_int_init called\n");

    bsymbol_blkif_int_lvar_id
        = target_lookup_sym(probe->target, "blkif_int.id", ".", NULL, SYMBOL_TYPE_NONE); 
    if (!bsymbol_blkif_int_lvar_id) {
        ERR("Failed to create a bsymbol for blkif_int.id\n");
        return -1;
    }
    return 0;
};

int probe_blkif_int(struct probe *probe, void *handler_data, struct probe *trigger)
{
    struct value   *lval_id;

    DBG("blkif_int called\n");

    lval_id  = bsymbol_load(bsymbol_blkif_int_lvar_id, LOAD_FLAG_NONE);
    if (!lval_id) {
        ERR("Cannot access value of id\n");
        return -1;
    }
    DBG("id = 0x%lx\n", *(unsigned long*)lval_id->buf);
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
    struct bsymbol *bsymbol;
    struct probe *probe;

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



