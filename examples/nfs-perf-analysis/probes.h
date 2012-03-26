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

#if 0

int probe_netif_poll(struct probe *probe, void *handler_data, struct probe *trigger);
int probe_netif_poll_lb_skb_dequeue(struct probe *probe, void *handler_data, struct probe *trigger);
int probe_netif_receive_skb(struct probe *probe, void *handler_data, struct probe *trigger);
int probe_ip_rcv(struct probe *probe, void *handler_data, struct probe *trigger);
int probe_tcp_v4_rcv(struct probe *probe, void *handler_data, struct probe *trigger);
int probe_tcp_data_queue(struct probe *probe, void *handler_data, struct probe *trigger);
int probe_skb_copy_datagram_iovec(struct probe *probe, void *handler_data, struct probe *trigger);
int probe_svc_process(struct probe *probe, void *handler_data, struct probe *trigger);
int probe_nfsd3_proc_write(struct probe *probe, void *handler_data, struct probe *trigger);
int probe_do_readv_writev_ttd_copy_from_user(struct probe *probe, void *handler_data, struct probe *trigger);
int probe_generic_file_writev(struct probe *probe, void *handler_data, struct probe *trigger);
int probe_generic_file_buffered_write(struct probe *probe, void *handler_data, struct probe *trigger);
int probe_ext3_journalled_writepage(struct probe *probe, void *handler_data, struct probe *trigger);
int probe___block_write_full_page(struct probe *probe, void *handler_data, struct probe *trigger);
int probe_submit_bh(struct probe *probe, void *handler_data, struct probe *trigger);
int probe_blkif_queue_request(struct probe *probe, void *handler_data, struct probe *trigger);
int probe_blkif_int(struct probe *probe, void *handler_data, struct probe *trigger);

#endif

int register_probes(struct target *t, GHashTable *probes);
void unregister_probes(GHashTable *probes);

#endif /* __NFS_PERF_PROBES_H__ */
