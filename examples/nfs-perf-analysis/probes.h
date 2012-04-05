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
 *  examples/nfs-perf-analysis/probes.h
 *
 *  Probe handlers for the network file system performance analsis
 *
 *  Authors: Anton Burtsev, aburtsev@flux.utah.edu
 * 
 */

#ifndef __NFS_PERF_PROBES_H__
#define __NFS_PERF_PROBES_H__

#include <target.h>

typedef enum nfs_perf_stage_id {
        STAGE_ID_NETIF_POLL              = 1, 
        STAGE_ID_NETIF_POLL_SKB_DEQUEUE  = 2,
        STAGE_ID_NETIF_RECEIVE_SKB       = 3,
        STAGE_ID_IP_RCV                  = 4,
        STAGE_ID_TCP_V4_RCV              = 5, 
	STAGE_ID_TCP_DATA_QUEUE          = 6,
        STAGE_ID_SKB_COPY_DATAGRAM_IOVEC = 7,
        STAGE_ID_DO_READV_WRITEV         = 8, 
        STAGE_ID_GENERIC_FILE_WRITEV     = 9, 
        STAGE_ID_GENERIC_FILE_BUFFERED_WRITE = 10, 
        STAGE_ID_EXT3_JOURNALLED_WRITEPAGE = 11, 
        STAGE_ID___BLOCK_WRITE_FULL_PAGE = 12, 
        STAGE_ID_SUBMIT_BH               = 13, 
        STAGE_ID_BLKIF_QUEUE_REQUEST     = 14,
        STAGE_ID_BLKIF_INT               = 15,	

} nfs_perf_stage_id_t;

/* XXX: This funciton pollutes the kernel binary since it's included in many places */
static inline char *stage_id_to_name(nfs_perf_stage_id_t id) {
    switch ( id ) {
    case STAGE_ID_NETIF_POLL: return "netif_poll";
    case STAGE_ID_NETIF_POLL_SKB_DEQUEUE: return "netif_poll_skb_dequeue";
    case STAGE_ID_NETIF_RECEIVE_SKB: return "netif_receive_skb";
    case STAGE_ID_IP_RCV: return "ip_rcv";
    case STAGE_ID_TCP_V4_RCV: return "tcp_v4_rcv";
    case STAGE_ID_TCP_DATA_QUEUE: return "tcp_data_queue";
    case STAGE_ID_SKB_COPY_DATAGRAM_IOVEC: return "skb_copy_datagram_iovec";
    case STAGE_ID_DO_READV_WRITEV: return "do_readv_writev";
    case STAGE_ID_GENERIC_FILE_WRITEV: return "generic_file_writev";
    case STAGE_ID_GENERIC_FILE_BUFFERED_WRITE: return "generic_file_buffered_write";
    case STAGE_ID_EXT3_JOURNALLED_WRITEPAGE: return "ext3_journalled_writepage";
    case STAGE_ID___BLOCK_WRITE_FULL_PAGE: return "__block_write_full_page";
    case STAGE_ID_SUBMIT_BH: return "submit_bh";
    case STAGE_ID_BLKIF_QUEUE_REQUEST: return "blkif_queue_request";
    case STAGE_ID_BLKIF_INT: return "blkif_int";		       
    default: return "undefined";
    };
};

int register_probes(struct target *t, GHashTable *probes);
void unregister_probes(GHashTable *probes);

#endif /* __NFS_PERF_PROBES_H__ */
