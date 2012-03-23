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

int probe_netif_poll(struct probe *probe, void *handler_data, struct probe *trigger)
{
    DBG("netif_poll called\n");
    return 0;
}

int probe_netif_poll_lb_skb_dequeue(struct probe *probe, void *handler_data, struct probe *trigger)
{
    DBG("netif_poll at label skb_dequeue called\n");
    return 0;
}

int probe_netif_receive_skb(struct probe *probe, void *handler_data, struct probe *trigger)
{
    DBG("netif_receive_skb called\n");
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





