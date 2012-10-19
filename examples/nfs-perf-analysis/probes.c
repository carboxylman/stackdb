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

#include <perf.h>

#include "probes.h"
#include "debug.h"
#include "request.h"

unsigned long long request_count = 0;
unsigned long long requests_seen = 0;

unsigned long last_seen_req_id;

struct bsymbol *bsymbol_netif_poll_lvar_skb = NULL;
struct bsymbol *bsymbol_netif_receive_skb_lvar_skb = NULL;
struct bsymbol *bsymbol_ip_rcv_lvar_skb = NULL;
struct bsymbol *bsymbol_tcp_v4_rcv_lvar_skb = NULL;
struct bsymbol *bsymbol_tcp_data_queue_lvar_skb = NULL;
struct bsymbol *bsymbol_skb_copy_datagram_iovec_lvar_skb = NULL;
struct bsymbol *bsymbol_skb_copy_datagram_iovec_lvar_to = NULL;

struct bsymbol *bsymbol_svc_tcp_recvfrom_lvar_vec = NULL;
struct bsymbol *bsymbol_svc_tcp_recvfrom_lvar_rqstp = NULL;


struct bsymbol *bsymbol_nfsd3_proc_write_lvar_rqstp = NULL;
struct bsymbol *bsymbol_nfsd3_proc_write_lvar_argp_vec = NULL;

struct bsymbol *bsymbol_do_readv_writev_lvar_iov = NULL;
struct bsymbol *bsymbol_do_readv_writev_lvar_uvector = NULL;
struct bsymbol *bsymbol_generic_file_writev_lvar_iov = NULL;
struct bsymbol *bsymbol_generic_file_buffered_write_lvar_iov = NULL;
struct bsymbol *bsymbol_generic_file_buffered_write_lvar_page = NULL;
struct bsymbol *bsymbol_ext3_journalled_writepage_lvar_page = NULL;
struct bsymbol *bsymbol___block_write_full_page_lvar_page = NULL;
struct bsymbol *bsymbol___block_write_full_page_lvar_bh = NULL;

struct bsymbol *bsymbol___block_commit_write_lvar_page = NULL;
struct bsymbol *bsymbol___block_commit_write_lvar_bh = NULL;

struct bsymbol *bsymbol_submit_bh_lvar_bh = NULL;
struct bsymbol *bsymbol_submit_bh_lvar_bio = NULL;
struct bsymbol *bsymbol_blkif_queue_request_lvar_bio = NULL;
struct bsymbol *bsymbol_blkif_queue_request_lvar_id = NULL;
struct bsymbol *bsymbol_blkif_int_lvar_id = NULL;


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
    struct value   *lval_skb;
    unsigned long  req_id;
    struct target *target = probe->target;
    tid_t tid = probe->thread->tid;

    DBG("netif_poll at label skb_dequeue called\n");

    if (request_count && (request_count < requests_seen)) {
        DBG("We've processed %llu requests, exit\n", requests_seen);
        request_analysis_done(probe);
        return 0;
    };

    lval_skb = target_load_symbol(target,tid,bsymbol_netif_poll_lvar_skb,
				  LOAD_FLAG_NO_CHECK_VISIBILITY);
    if (!lval_skb) {
        ERR("Cannot access value of skb\n");
        return -1;
    }

    req_id = *(unsigned long*)lval_skb->buf;

    DBG("skb = 0x%lx\n", req_id);
    
    /* we add a new request to the analysis */
    req = request_alloc();
    if (!req) {
        ERR("Failed to allocate request\n");
        return 0;
    }

    requests_seen ++;

    request_hash_add(req, req_id);

    req = request_move_on_path(probe, req_id, STAGE_ID_NETIF_POLL_SKB_DEQUEUE);
    if(!req) {
        ERR("Failed to move request on its processing path to stage:%s\n", 
            stage_id_to_name(STAGE_ID_NETIF_POLL_SKB_DEQUEUE));
        return -1;
    }
    
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
    unsigned long   req_id;
    struct value   *lval_skb;
    struct target *target = probe->target;
    tid_t tid = probe->thread->tid;

    DBG("netif_receive_skb called\n");

    lval_skb = target_load_symbol(target,tid,bsymbol_netif_receive_skb_lvar_skb,
				  LOAD_FLAG_NO_CHECK_VISIBILITY);
    if (!lval_skb) {
        ERR("Cannot access value of skb\n");
        return -1;
    }
    req_id = *(unsigned long*)lval_skb->buf;

    DBG("skb = 0x%lx\n", req_id);

    req = request_move_on_path(probe, req_id, STAGE_ID_NETIF_RECEIVE_SKB);
    if(!req) {
        ERR("Failed to move request (id:0x%lx) on its processing path to stage:%s\n", 
            req_id, stage_id_to_name(STAGE_ID_NETIF_RECEIVE_SKB));
        return -1;
    }
    
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
    struct request *req;
    unsigned long   req_id;
    struct target *target = probe->target;
    tid_t tid = probe->thread->tid;

    DBG("ip_rcv called\n");

    lval_skb = target_load_symbol(target,tid,bsymbol_ip_rcv_lvar_skb,
				  LOAD_FLAG_NO_CHECK_VISIBILITY);
    if (!lval_skb) {
        ERR("Cannot access value of skb\n");
        return -1;
    }
    
    req_id = *(unsigned long*)lval_skb->buf;

    DBG("skb = 0x%lx\n", req_id);

    req = request_move_on_path(probe, req_id, STAGE_ID_IP_RCV);
    if(!req) {
        ERR("Failed to move request (id:0x%lx) on its processing path to stage:%s\n", 
            req_id, stage_id_to_name(STAGE_ID_IP_RCV));
        return -1;
    }

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
    struct request *req;
    unsigned long   req_id;
    struct target *target = probe->target;
    tid_t tid = probe->thread->tid;

    DBG("tcp_v4_rcv called\n");

    lval_skb = target_load_symbol(target,tid,bsymbol_tcp_v4_rcv_lvar_skb,
				  LOAD_FLAG_NO_CHECK_VISIBILITY);
    if (!lval_skb) {
        ERR("Cannot access value of skb\n");
        return -1;
    }
    
    req_id = *(unsigned long*)lval_skb->buf;

    DBG("skb = 0x%lx\n", req_id);

    req = request_move_on_path(probe, req_id, STAGE_ID_TCP_V4_RCV);
    if(!req) {
        ERR("Failed to move request (id:0x%lx) on its processing path to stage:%s\n", 
            req_id, stage_id_to_name(STAGE_ID_TCP_V4_RCV));
        return -1;
    }

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
    struct request *req;
    unsigned long   req_id;
    struct target *target = probe->target;
    tid_t tid = probe->thread->tid;

    DBG("tcp_data_queue called\n");

    lval_skb = target_load_symbol(target,tid,bsymbol_tcp_data_queue_lvar_skb,
				  LOAD_FLAG_NO_CHECK_VISIBILITY);
    if (!lval_skb) {
        ERR("Cannot access value of skb\n");
        return -1;
    }

    req_id = *(unsigned long*)lval_skb->buf;

    DBG("skb = 0x%lx\n", req_id);

    req = request_move_on_path(probe, req_id, STAGE_ID_TCP_DATA_QUEUE);
    if(!req) {
        ERR("Failed to move request (id:0x%lx) on its processing path to stage:%s\n", 
            req_id, stage_id_to_name(STAGE_ID_TCP_DATA_QUEUE));
        return -1;
    }
    return 0;
}

int probe_skb_copy_datagram_iovec_init(struct probe *probe) {
    DBG("skb_copy_datagram_iovec_init called\n");

    bsymbol_skb_copy_datagram_iovec_lvar_skb = target_lookup_sym(probe->target, "skb_copy_datagram_iovec.skb", ".", NULL, SYMBOL_TYPE_NONE); 
    if (!bsymbol_skb_copy_datagram_iovec_lvar_skb) {
        ERR("Failed to create a bsymbol for skb_copy_datagram_iovec.skb\n");
        return -1;
    }

    bsymbol_skb_copy_datagram_iovec_lvar_to = target_lookup_sym(probe->target, "skb_copy_datagram_iovec.to.iov_base", ".", NULL, SYMBOL_TYPE_NONE); 
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
    struct request *req;
    unsigned long   req_id, new_req_id;
    int             ret;
    struct target *target = probe->target;
    tid_t tid = probe->thread->tid;

    DBG("skb_copy_datagram_iovec called\n");

    lval_skb = target_load_symbol(target,tid,bsymbol_skb_copy_datagram_iovec_lvar_skb,
				  LOAD_FLAG_NO_CHECK_VISIBILITY);
    if (!lval_skb) {
        ERR("Cannot access value of skb\n");
        return -1;
    }

    req_id = *(unsigned long*)lval_skb->buf;
    DBG("skb = 0x%lx\n", req_id);

    lval_to = target_load_symbol(target,tid,bsymbol_skb_copy_datagram_iovec_lvar_to,
				 LOAD_FLAG_NO_CHECK_VISIBILITY);
    if (!lval_to) {
        ERR("Cannot access value of to\n");
        return -1;
    }
    
    new_req_id = *(unsigned long*)lval_to->buf;
    DBG("iovec to = 0x%lx\n", new_req_id);

    req = request_move_on_path(probe, req_id, STAGE_ID_SKB_COPY_DATAGRAM_IOVEC);
    if(!req) {
        ERR("Failed to move request (id:0x%lx) on its processing path to stage:%s\n", 
            req_id, stage_id_to_name(STAGE_ID_SKB_COPY_DATAGRAM_IOVEC));
        return -1;
    }

    ret = request_hash_change_id(req, new_req_id);
    if(ret) {
        ERR("Failed to change request id in the hash, id:0x%lx -> 0x%lx, stage:%s\n",
             req_id, new_req_id, stage_id_to_name(STAGE_ID_SKB_COPY_DATAGRAM_IOVEC));
        request_done(req);
        return -1;
    }

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

int probe_svc_tcp_recvfrom_init(struct probe *probe) {
    DBG("called\n");

    bsymbol_svc_tcp_recvfrom_lvar_vec = target_lookup_sym(probe->target, 
            "svc_tcp_recvfrom.vec", ".", NULL, SYMBOL_TYPE_NONE); 
    if (!bsymbol_svc_tcp_recvfrom_lvar_vec) {
        ERR("Failed to create a bsymbol for svc_tcp_recvfrom.vec\n");
        return -1;
    }

    bsymbol_svc_tcp_recvfrom_lvar_rqstp = target_lookup_sym(probe->target, 
            "svc_tcp_recvfrom.rqstp", ".", NULL, SYMBOL_TYPE_NONE); 
    if (!bsymbol_svc_tcp_recvfrom_lvar_rqstp) {
        ERR("Failed to create a bsymbol for svc_tcp_recvfrom.rqstp\n");
        return -1;
    }

    return 0;
};

int probe_svc_tcp_recvfrom(struct probe *probe, void *handler_data, struct probe *trigger)
{
    struct value   *lval_vec;
    struct value   *lval_rqstp;
    struct request *req;
    unsigned long   req_id, new_req_id;
    int             ret;
    struct target *target = probe->target;
    tid_t tid = probe->thread->tid;
 
    DBG("called\n");

    lval_vec = target_load_symbol(target, tid, bsymbol_svc_tcp_recvfrom_lvar_vec,
				      LOAD_FLAG_NO_CHECK_VISIBILITY);
    if (!lval_vec) {
        ERR("Cannot access value of vec\n");
        return -1;
    }

    req_id = *(unsigned long*)lval_vec->buf;
    DBG("vec = 0x%lx\n", req_id);

    lval_rqstp = target_load_symbol(target, tid, bsymbol_svc_tcp_recvfrom_lvar_rqstp,
				      LOAD_FLAG_NO_CHECK_VISIBILITY);
    if (!lval_rqstp) {
        ERR("Cannot access value of argp->vec\n");
        return -1;
    }
    new_req_id = *(unsigned long*)lval_rqstp->buf;
    DBG("rqstp = 0x%lx\n", new_req_id);

    req = request_move_on_path(probe, req_id, STAGE_ID_SVC_RECVFROM);
    if(!req) {
        ERR("Failed to move request (id:0x%lx) on its processing path to stage:%s\n", 
            req_id, stage_id_to_name(STAGE_ID_SVC_RECVFROM));
        return -1;
    }

    ret = request_hash_change_id(req, new_req_id);
    if(ret) {
        ERR("Failed to change request id in the hash, id:0x%lx -> 0x%lx, stage:%s\n",
             req_id, new_req_id, stage_id_to_name(STAGE_ID_SVC_RECVFROM));
        request_done(req);
        return -1;
    }


    return 0;
}

int probe_nfsd3_proc_write_init(struct probe *probe) {
    DBG("nfsd3_proc_write_init called\n");

    bsymbol_nfsd3_proc_write_lvar_rqstp = target_lookup_sym(probe->target, "nfsd3_proc_write.rqstp", ".", NULL, SYMBOL_TYPE_NONE); 
    if (!bsymbol_nfsd3_proc_write_lvar_rqstp) {
        ERR("Failed to create a bsymbol for nfsd3_proc_write.rqstp\n");
        return -1;
    }

    bsymbol_nfsd3_proc_write_lvar_argp_vec = target_lookup_sym(probe->target, "nfsd3_proc_write.argp.vec", ".", NULL, SYMBOL_TYPE_NONE); 
    if (!bsymbol_nfsd3_proc_write_lvar_argp_vec) {
        ERR("Failed to create a bsymbol for nfsd3_proc_write.argp.vec\n");
        return -1;
    }

    return 0;
};

int probe_nfsd3_proc_write(struct probe *probe, void *handler_data, struct probe *trigger)
{
    struct value   *lval_rqstp;
    struct value   *lval_argp_vec;
    struct request *req;
    unsigned long   req_id, new_req_id;
    int             ret;
    struct target *target = probe->target;
    tid_t tid = probe->thread->tid;
 
    DBG("nfsd3_proc_write called\n");

    lval_rqstp = target_load_symbol(target, tid, bsymbol_nfsd3_proc_write_lvar_rqstp,
				      LOAD_FLAG_NO_CHECK_VISIBILITY);
    if (!lval_rqstp) {
        ERR("Cannot access value of argp->vec\n");
        return -1;
    }

    req_id = *(unsigned long*)lval_rqstp->buf;
    DBG("argp = 0x%lx\n", req_id);

    lval_argp_vec = target_load_symbol(target, tid, bsymbol_nfsd3_proc_write_lvar_argp_vec,
				      LOAD_FLAG_NO_CHECK_VISIBILITY);
    if (!lval_argp_vec) {
        ERR("Cannot access value of argp->vec\n");
        return -1;
    }
    new_req_id = *(unsigned long*)lval_argp_vec->buf;
    DBG("argp.vec = 0x%lx\n", new_req_id);

    req = request_move_on_path(probe, req_id, STAGE_ID_NFSD3_PROC_WRITE);
    if(!req) {
        ERR("Failed to move request (id:0x%lx) on its processing path to stage:%s\n", 
            req_id, stage_id_to_name(STAGE_ID_NFSD3_PROC_WRITE));
        return -1;
    }

    last_seen_req_id = new_req_id;

    ret = request_hash_change_id(req, new_req_id);
    if(ret) {
        ERR("Failed to change request id in the hash, id:0x%lx -> 0x%lx, stage:%s\n",
             req_id, new_req_id, stage_id_to_name(STAGE_ID_NFSD3_PROC_WRITE));
        request_done(req);
        return -1;
    }

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
    struct request *req;
    unsigned long   req_id, new_req_id;
    int             ret;
    struct target *target = probe->target;
    tid_t tid = probe->thread->tid;

    DBG("do_readv_writev.ttd_copy_from_user called\n");

    lval_uvector = target_load_symbol(target,tid,bsymbol_do_readv_writev_lvar_uvector,
				      LOAD_FLAG_NO_CHECK_VISIBILITY);
    if (!lval_uvector) {
        ERR("Cannot access value of uvector\n");
        return -1;
    }
    req_id = *(unsigned long*)lval_uvector->buf;
    //DBG("uvector = 0x%lx\n", req_id);
    DBG("uvector = 0x%lx, last_seen = 0x%lx\n", req_id, last_seen_req_id);
    req_id = last_seen_req_id;

    lval_iov = target_load_symbol(target,tid,bsymbol_do_readv_writev_lvar_iov,
				  LOAD_FLAG_NO_CHECK_VISIBILITY);
    if (!lval_iov) {
        ERR("Cannot access value of iov\n");
        return -1;
    }
    new_req_id = *(unsigned long*)lval_iov->buf;
    DBG("iov = 0x%lx\n", new_req_id);

    req = request_move_on_path(probe, req_id, STAGE_ID_DO_READV_WRITEV);
    if(!req) {
        ERR("Failed to move request (id:0x%lx) on its processing path to stage:%s\n", 
            req_id, stage_id_to_name(STAGE_ID_DO_READV_WRITEV));
        return -1;
    }

    ret = request_hash_change_id(req, new_req_id);
    if(ret) {
        ERR("Failed to change request id in the hash, id:0x%lx -> 0x%lx, stage:%s\n",
             req_id, new_req_id, stage_id_to_name(STAGE_ID_DO_READV_WRITEV));
        request_done(req);
        return -1;
    }

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
    unsigned long   req_id;
    struct request *req;
    struct target *target = probe->target;
    tid_t tid = probe->thread->tid;

    DBG("generic_file_writev called\n");

    lval_iov = target_load_symbol(target,tid,bsymbol_generic_file_writev_lvar_iov,
				  LOAD_FLAG_NO_CHECK_VISIBILITY);
    if (!lval_iov) {
        ERR("Cannot access value of iov\n");
        return -1;
    }
    req_id = *(unsigned long*)lval_iov->buf;
    DBG("iov = 0x%lx, last_seen = 0x%lx\n", req_id, last_seen_req_id);
   // req_id = last_seen_req_id;

    req = request_move_on_path(probe, req_id, STAGE_ID_GENERIC_FILE_WRITEV);
    if(!req) {
        ERR("Failed to move request (id:0x%lx) on its processing path to stage:%s\n", 
            req_id, stage_id_to_name(STAGE_ID_GENERIC_FILE_WRITEV));
        return -1;
    }

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
    unsigned long   req_id, new_req_id;
    int             ret;
    struct request *req;
    struct target *target = probe->target;
    tid_t tid = probe->thread->tid;

    DBG("generic_file_buffered_write called\n");
    lval_iov = target_load_symbol(target,tid,bsymbol_generic_file_buffered_write_lvar_iov,
				  LOAD_FLAG_NO_CHECK_VISIBILITY);
    if (!lval_iov) {
        ERR("Cannot access value of iov\n");
        return -1;
    }
    req_id = *(unsigned long*)lval_iov->buf;
    DBG("iov = 0x%lx\n", req_id);

    lval_page = target_load_symbol(target,tid,bsymbol_generic_file_buffered_write_lvar_page,
				   LOAD_FLAG_NO_CHECK_VISIBILITY);
    if (!lval_page) {
        ERR("Cannot access value of page\n");
        return -1;
    }
    new_req_id = *(unsigned long*)lval_page->buf;
    DBG("page = 0x%lx\n", new_req_id);

    req = request_move_on_path(probe, req_id, STAGE_ID_GENERIC_FILE_BUFFERED_WRITE);
    if(!req) {
        ERR("Failed to move request (id:0x%lx) on its processing path to stage:%s\n", 
            req_id, stage_id_to_name(STAGE_ID_GENERIC_FILE_BUFFERED_WRITE));
        return -1;
    }

    ret = request_hash_change_id(req, new_req_id);
    if(ret) {
        ERR("Failed to change request id in the hash, id:0x%lx -> 0x%lx, stage:%s\n",
             req_id, new_req_id, stage_id_to_name(STAGE_ID_GENERIC_FILE_BUFFERED_WRITE));
        request_done(req);
        return -1;
    }
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
    unsigned long   req_id;
    struct request *req;
    struct target *target = probe->target;
    tid_t tid = probe->thread->tid;

    DBG("ext3_journalled_writepage called\n");
    lval_page = target_load_symbol(target,tid,bsymbol_ext3_journalled_writepage_lvar_page,
				   LOAD_FLAG_NO_CHECK_VISIBILITY);
    if (!lval_page) {
        ERR("Cannot access value of page\n");
        return -1;
    }
    req_id = *(unsigned long*)lval_page->buf;
    DBG("page = 0x%lx\n", req_id);

    req = request_move_on_path(probe, req_id, STAGE_ID_EXT3_JOURNALLED_WRITEPAGE);
    if(!req) {
        ERR("Failed to move request (id:0x%lx) on its processing path to stage:%s\n", 
            req_id, stage_id_to_name(STAGE_ID_EXT3_JOURNALLED_WRITEPAGE));
        return -1;
    }

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
    unsigned long   req_id, new_req_id;
    int             ret;
    struct request *req;
    struct target *target = probe->target;
    tid_t tid = probe->thread->tid;

    DBG("__block_write_full_page called\n");

    lval_page = target_load_symbol(target,tid,bsymbol___block_write_full_page_lvar_page,
				   LOAD_FLAG_NO_CHECK_VISIBILITY);
    if (!lval_page) {
        ERR("Cannot access value of page\n");
        return -1;
    }
    req_id = *(unsigned long*)lval_page->buf;
    DBG("page = 0x%lx\n", req_id);

    lval_bh = target_load_symbol(target,tid,bsymbol___block_write_full_page_lvar_bh,
				 LOAD_FLAG_NO_CHECK_VISIBILITY);
    if (!lval_bh) {
        ERR("Cannot access value of page\n");
        return -1;
    }
    new_req_id = *(unsigned long*)lval_bh->buf;
    DBG("bh = 0x%lx\n", new_req_id);

    req = request_move_on_path(probe, req_id, STAGE_ID___BLOCK_WRITE_FULL_PAGE);
    if(!req) {
        ERR("Failed to move request (id:0x%lx) on its processing path to stage:%s\n", 
            req_id, stage_id_to_name(STAGE_ID___BLOCK_WRITE_FULL_PAGE));
        return -1;
    }
#if 0
    ret = request_hash_change_id(req, new_req_id);
    if(ret) {
        ERR("Failed to change request id in the hash, id:0x%lx -> 0x%lx, stage:%s\n",
             req_id, new_req_id, stage_id_to_name(STAGE_ID___BLOCK_WRITE_FULL_PAGE));
        request_done(req);
        return -1;
    }
#endif
    return 0;
}

int probe___block_commit_write_init(struct probe *probe) {
    DBG("called\n");

    bsymbol___block_commit_write_lvar_page
        = target_lookup_sym(probe->target, "__block_commit_write.page", ".", NULL, SYMBOL_TYPE_NONE); 
    if (!bsymbol___block_commit_write_lvar_page) {
        ERR("Failed to create a bsymbol for __block_commit_write.page\n");
        return -1;
    }

    bsymbol___block_commit_write_lvar_bh
        = target_lookup_sym(probe->target, "__block_commit_write.bh", ".", NULL, SYMBOL_TYPE_NONE); 
    if (!bsymbol___block_commit_write_lvar_bh) {
        ERR("Failed to create a bsymbol for __block_commit_write.bh\n");
        return -1;
    }

    return 0;
};

int probe___block_commit_write(struct probe *probe, void *handler_data, struct probe *trigger)
{
    struct value   *lval_page;
    struct value   *lval_bh;
    unsigned long   req_id, new_req_id;
    int             ret;
    struct request *req;
    struct target *target = probe->target;
    tid_t tid = probe->thread->tid;

    DBG("__block_commit_write called\n");

    lval_page = target_load_symbol(target,tid,bsymbol___block_commit_write_lvar_page,
				   LOAD_FLAG_NO_CHECK_VISIBILITY);
    if (!lval_page) {
        ERR("Cannot access value of page\n");
        return -1;
    }
    req_id = *(unsigned long*)lval_page->buf;
    DBG("page = 0x%lx\n", req_id);

    lval_bh = target_load_symbol(target,tid,bsymbol___block_commit_write_lvar_bh,
				 LOAD_FLAG_NO_CHECK_VISIBILITY);
    if (!lval_bh) {
        ERR("Cannot access value of page\n");
        return -1;
    }
    new_req_id = *(unsigned long*)lval_bh->buf;
    DBG("bh = 0x%lx\n", new_req_id);

    req = request_move_on_path(probe, req_id, STAGE_ID___BLOCK_WRITE_FULL_PAGE);
    if(!req) {
        ERR("Failed to move request (id:0x%lx) on its processing path to stage:%s\n", 
            req_id, stage_id_to_name(STAGE_ID___BLOCK_WRITE_FULL_PAGE));
        return -1;
    }

/*    ret = request_hash_change_id(req, new_req_id);
    if(ret) {
        ERR("Failed to change request id in the hash, id:0x%lx -> 0x%lx, stage:%s\n",
             req_id, new_req_id, stage_id_to_name(STAGE_ID___BLOCK_WRITE_FULL_PAGE));
        request_done(req);
        return -1;
    }
*/
    return 0;
}

int probe_submit_bh_init(struct probe *probe) {
    DBG("submit_bh_init called\n");

    bsymbol_submit_bh_lvar_bh
        = target_lookup_sym(probe->target, "submit_bh.bh.b_page", ".", NULL, SYMBOL_TYPE_NONE); 
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
    unsigned long   req_id, new_req_id;
    int             ret;
    struct request *req;
    struct target *target = probe->target;
    tid_t tid = probe->thread->tid;

    DBG("submit_bh called\n");
    
    lval_bh  = target_load_symbol(target,tid,bsymbol_submit_bh_lvar_bh,
				  LOAD_FLAG_NO_CHECK_VISIBILITY);
    if (!lval_bh) {
        ERR("Cannot access value of bh\n");
        return -1;
    }
    req_id = *(unsigned long*)lval_bh->buf;
    DBG("bh.page = 0x%lx\n", req_id);

    lval_bio  = target_load_symbol(target,tid,bsymbol_submit_bh_lvar_bio,
				   LOAD_FLAG_NO_CHECK_VISIBILITY);
    if (!lval_bio) {
        ERR("Cannot access value of bio\n");
        return -1;
    }
    new_req_id = *(unsigned long*)lval_bio->buf;
    DBG("bio = 0x%lx\n", new_req_id);

    req = request_move_on_path(probe, req_id, STAGE_ID_SUBMIT_BH);
    if(!req) {
        ERR("Failed to move request (id:0x%lx) on its processing path to stage:%s\n", 
            req_id, stage_id_to_name(STAGE_ID_SUBMIT_BH));
        return -1;
    }

    ret = request_hash_change_id(req, new_req_id);
    if(ret) {
        ERR("Failed to change request id in the hash, id:0x%lx -> 0x%lx, stage:%s\n",
             req_id, new_req_id, stage_id_to_name(STAGE_ID_SUBMIT_BH));
        request_done(req);
        return -1;
    }

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
    unsigned long   req_id, new_req_id;
    int             ret;
    struct request *req;
    struct target *target = probe->target;
    tid_t tid = probe->thread->tid;

    DBG("blkif_queue_request called\n");

    lval_bio  = target_load_symbol(target,tid,bsymbol_blkif_queue_request_lvar_bio,
				   LOAD_FLAG_NO_CHECK_VISIBILITY);
    if (!lval_bio) {
        ERR("Cannot access value of bh\n");
        return -1;
    }
    req_id = *(unsigned long*)lval_bio->buf;
    DBG("bio = 0x%lx\n", req_id);

    lval_id  = target_load_symbol(target,tid,bsymbol_blkif_queue_request_lvar_id,
				  LOAD_FLAG_NO_CHECK_VISIBILITY);
    if (!lval_id) {
        ERR("Cannot access value of id\n");
        return -1;
    }
    new_req_id = *(unsigned long*)lval_id->buf;
    DBG("id = 0x%lx\n", new_req_id);

    req = request_move_on_path(probe, req_id, STAGE_ID_BLKIF_QUEUE_REQUEST);
    if(!req) {
        ERR("Failed to move request (id:0x%lx) on its processing path to stage:%s\n", 
            req_id, stage_id_to_name(STAGE_ID_BLKIF_QUEUE_REQUEST));
        return -1;
    }

    ret = request_hash_change_id(req, new_req_id);
    if(ret) {
        ERR("Failed to change request id in the hash, id:0x%lx -> 0x%lx, stage:%s\n",
             req_id, new_req_id, stage_id_to_name(STAGE_ID_BLKIF_QUEUE_REQUEST));
        request_done(req);
        return -1;
    }

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
    unsigned long   req_id;
    struct request *req;
    struct target *target = probe->target;
    tid_t tid = probe->thread->tid;

    DBG("blkif_int called\n");

    lval_id  = target_load_symbol(target,tid,bsymbol_blkif_int_lvar_id,
				  LOAD_FLAG_NO_CHECK_VISIBILITY);
    if (!lval_id) {
        ERR("Cannot access value of id\n");
        return -1;
    }
    
    req_id = *(unsigned long*)lval_id->buf;
    DBG("id = 0x%lx\n", req_id);

    req = request_move_on_path(probe, req_id, STAGE_ID_BLKIF_INT);
    if(!req) {
        ERR("Failed to move request (id:0x%lx) on its processing path to stage:%s\n", 
            req_id, stage_id_to_name(STAGE_ID_BLKIF_INT));
        return -1;
    }

    WARN("FULL PATH");
    request_done(req);
    return 0;
}

int probe_kernel_halt_fini(struct probe *probe) {
    DBG("kernel_halt_fini called\n");
    request_analysis_done(probe);
    return 0;
};

int probe_kernel_halt(struct probe *probe, void *handler_data, struct probe *trigger)
{
    DBG("kernel_halt called\n");
    request_analysis_done(probe);
    return 0;
}

#define PROBE_ON_LINE (1<<1)

typedef struct probe_registration {
    char                *symbol;
    probe_handler_t     handler; 
    struct probe_ops    ops;
    unsigned long       line_number;
    unsigned long       addr;
} probe_registration_t;

const probe_registration_t probe_list[] = {
    {"netif_poll",                                  probe_netif_poll, {.init = probe_netif_poll_init}, 0, 0},
    {"netif_poll.ttd_skb_dequeue",                  probe_netif_poll_lb_skb_dequeue, {.init = probe_netif_poll_lb_skb_dequeue_init}, 0, 0},
    {"netif_receive_skb",                           probe_netif_receive_skb, {.init = probe_netif_receive_skb_init}, 0, 0},
    {"ip_rcv",                                      probe_ip_rcv, {.init = probe_ip_rcv_init}, 0, 0},
    {"tcp_v4_rcv",                                  probe_tcp_v4_rcv, {.init = probe_tcp_v4_rcv_init}, 0, 0},
    {"tcp_data_queue",                              probe_tcp_data_queue, {.init = probe_tcp_data_queue_init}, 0, 0},
    {"skb_copy_datagram_iovec",                     probe_skb_copy_datagram_iovec, {.init = probe_skb_copy_datagram_iovec_init}, 0, 0},
    {"svcsock.c",                                   probe_svc_tcp_recvfrom, {.init = probe_svc_tcp_recvfrom_init}, 0 /* 995 */, 0xc04e8aff},
    {"svc_process",                                 probe_svc_process, {.init = probe_svc_process_init}, 0, 0},
    {"nfsd3_proc_write",                            probe_nfsd3_proc_write, {.init = probe_nfsd3_proc_write_init}, 0, 0},
    {"do_readv_writev.ttd_iov_label",               probe_do_readv_writev_ttd_copy_from_user, {.init = probe_do_readv_writev_ttd_copy_from_user_init}, 0, 0},
    {"generic_file_writev",                         probe_generic_file_writev, {.init = probe_generic_file_writev_init}, 0, 0},
    {"generic_file_buffered_write.ttd_page_label",  probe_generic_file_buffered_write, {.init = probe_generic_file_buffered_write_init}, 0, 0},
    {"ext3_journalled_writepage",                   probe_ext3_journalled_writepage, {.init = probe_ext3_journalled_writepage_init}, 0, 0},
    {"__block_write_full_page.ttd_bh_label",        probe___block_write_full_page, {.init = probe___block_write_full_page_init}, 0, 0},
    {"__block_commit_write",                        probe___block_commit_write, {.init = probe___block_commit_write_init}, 0, /*2038 */0xc0362216},

    {/*"submit_bh"*/ "buffer.c",                    probe_submit_bh, {.init = probe_submit_bh_init}, 0, 0xc0361716},
    {"blkif_queue_request",                         probe_blkif_queue_request, {.init = probe_blkif_queue_request_init}, 0, /* 678 */ 0xc0465424},
    {"blkif_int.ttd_id_label",                      probe_blkif_int, {.init = probe_blkif_int_init}, 0, 0},
    {"kernel_halt",                                 probe_kernel_halt, {.fini = probe_kernel_halt_fini}, 0, 0},

};

int register_probes(struct target *t, GHashTable *probes) {

    int i, probe_count;
    struct bsymbol *bsymbol;
    struct probe *probe;

    probes = g_hash_table_new(g_direct_hash, g_direct_equal);

    request_hash_init();

    perf_init();
    
    /*
     * Inject probes at locations specified in probe_list.
     */
    probe_count = sizeof(probe_list) / sizeof(probe_list[0]);
    for (i = 0; i < probe_count; i++)
    {

        if (probe_list[i].addr) {
            
                probe = probe_create(t, TID_GLOBAL, &probe_list[i].ops, 
                                     NULL,
                                     probe_list[i].handler, NULL, NULL, 0);
                if (!probe)
                {
                        ERR("could not create probe on raw addr:%lx\n",
                            probe_list[i].addr);

                        unregister_probes(probes);
                        return -1;
                }


                if (!probe_register_addr(probe, 
                                   probe_list[i].addr, 
                                   PROBEPOINT_BREAK, PROBEPOINT_SW /*PROBEPOINT_FASTEST*/,
                                   PROBEPOINT_EXEC, PROBEPOINT_LAUTO, NULL))
                {
                        ERR("could not register probe on raw addr: %lx\n",
                            probe_list[i].addr);
                        probe_free(probe, 1);
                        unregister_probes(probes);
                        return -1;
               }
        } else 
        if (probe_list[i].line_number) {
            
                probe = probe_create(t, TID_GLOBAL, &probe_list[i].ops, 
                                     NULL,
                                     probe_list[i].handler, NULL, NULL, 0);
                if (!probe)
                {
                        ERR("could not create probe on line number: %s:%lu\n",
                            probe_list[i].symbol, probe_list[i].line_number);

                        unregister_probes(probes);
                        return -1;
                }


                if (!probe_register_line(probe, 
                                   probe_list[i].symbol, 
                                   probe_list[i].line_number, 
                                   PROBEPOINT_SW /*PROBEPOINT_FASTEST*/,
                                   PROBEPOINT_EXEC, PROBEPOINT_LAUTO))
                {
                        ERR("could not register probe on line number: %s:%lu\n",
                            probe_list[i].symbol, probe_list[i].line_number);
                        probe_free(probe, 1);
                        unregister_probes(probes);
                        return -1;
               }
        } else {

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



