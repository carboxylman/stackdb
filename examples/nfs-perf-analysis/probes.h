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
 *  examples/nfs-perf-analysis/probes.h
 *
 *  Probe handlers for the network file system performance analsis
 *
 *  Authors: Anton Burtsev, aburtsev@flux.utah.edu
 * 
 */

#ifndef __NFS_PERF_PROBES_H__
#define __NFS_PERF_PROBES_H__

typedef enum nfs_perf_stage_id {
        STAGE_ID_NETIF_POLL              = 1, 
        STAGE_ID_NETIF_POLL_SKB_DEQUEUE  = 2,
        STAGE_ID_NETIF_RECEIVE_SKB       = 3,
        STAGE_ID_IP_RCV                  = 4,
        STAGE_ID_TCP_V4_RCV              = 5, 
        STAGE_ID_SKB_COPY_DATAGRAM_IOVEC = 6,
} nfs_perf_stage_id_t;

/* XXX: This funciton pollutes the kernel binary since it's included in many places */
static inline char *stage_id_to_name(nfs_perf_stage_id_t id) {
    switch ( id ) {
    case STAGE_ID_NETIF_POLL: return "netif_poll";
    case STAGE_ID_NETIF_POLL_SKB_DEQUEUE: return "netif_poll_skb_dequeue";
    case STAGE_ID_NETIF_RECEIVE_SKB: return "netif_receive_skb";
    case STAGE_ID_IP_RCV: return "ip_rcv";
    case STAGE_ID_TCP_V4_RCV: return "tcp_v4_rcv";
    case STAGE_ID_SKB_COPY_DATAGRAM_IOVEC: return "skb_copy_datagram_iovec";
    default: return "undefined";
    };
};

int register_probes(struct target *t, GHashTable *probes);
void unregister_probes(GHashTable *probes);

#endif /* __NFS_PERF_PROBES_H__ */
