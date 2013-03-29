/*
 * Copyright (c) 2011, 2012, 2013 The University of Utah
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

#define LINUX
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/sched.h> 
#include <asm/thread_info.h>
#include <asm/signal.h>
#include <asm/siginfo.h>
/* need to decide where we want to keep this header file */
#include<linux/repair_driver.h>

struct cmd_ring_channel tx_ring_channel, rx_ring_channel;
static unsigned int cmd_buf_size = 4; /* buffer size (in pages) */

int cmd_ring_channel_alloc_with_metadata(struct cmd_ring_channel *ring_channel,
        unsigned long size_in_pages, unsigned long size_of_a_rec,
        unsigned long priv_metadata_size) {

    int ret;
    unsigned long order, header_order, i;
    unsigned long size_of_header_in_pages;

    printk(KERN_INFO "Allocating ring channel\n");
    cmd_ring_channel_init(ring_channel);

    header_order = get_order(priv_metadata_size + sizeof(struct cmd_buf));
    if ((ring_channel->buf = __get_free_pages(GFP_KERNEL, header_order))
            == NULL) {
        printk(KERN_INFO "Memory allocation failed\n");
        return -EINVAL;
    }

    size_of_header_in_pages = 1 << header_order;
    printk(KERN_INFO "Allocating ring channel: header area size:%lu, in pages:%lu\n",
            priv_metadata_size + sizeof(struct ttd_buf),
            size_of_header_in_pages);
    /* Figure out the right way of doing this */
    order = get_order(size_in_pages * PAGE_SIZE);
    if ((ring_channel->recs = __get_free_pages(GFP_KERNEL, order)) == NULL) {

        printk(KERN_INFO "Buffer page allocation failed, "
                "size in pages:%lu, order:%lu\n", size_in_pages, order);
        ret = -EINVAL;
        goto cleanup;
    }

    ring_channel->priv_metadata = (char *) (ring_channel->buf + 1);
    ring_channel->buf->cons = ring_channel->buf->prod = 0;

    ring_channel->size_of_a_rec = size_of_a_rec;
    ring_channel->size_in_recs = (size_in_pages * PAGE_SIZE)
            / ring_channel->size_of_a_rec;

    /* Init shared buffer structures */
    ring_channel->buf->payload_buffer_mfn = virt_to_mfn(ring_channel->recs);
    ring_channel->buf->payload_buffer_size = size_in_pages * PAGE_SIZE;
    ring_channel->buf->size_of_a_rec = ring_channel->size_of_a_rec;
    ring_channel->buf->size_in_recs = ring_channel->size_in_recs;

    ring_channel->highwater = ring_channel->size_in_recs >> 1; /* 50% high water */
    ring_channel->emergency_margin = ring_channel->size_in_recs >> 4; /* 5% we are very close */

    /*    printk(KERN_INFO "New ring channel: payload area {requested:%lu, allocated:%lu, wasted on allocation:%lu (order:%lu), \n"
     "metadata area {size:%lu, buffer size: %lu, full header: %lu, "
     "allocated:%lu, wasted on allocation:%lu (order:%lu)} \n"
     "rec: {requested size:%lu, size ^2:%lu, rownded down size in recs:%lu, "
     "possible size in recs:%lu, wasted:%lu} "
     "highwater: %lu, emergency margin: %lu\n",
     size_in_pages * PAGE_SIZE,
     ((unsigned long)1 << order) * PAGE_SIZE,
     ((1 << order) * PAGE_SIZE) - size_in_pages * PAGE_SIZE, order,
     priv_metadata_size, (unsigned long) sizeof(struct ttd_buf),
     priv_metadata_size + sizeof(struct ttd_buf),
     ((unsigned long)1 << header_order) * PAGE_SIZE,
     ((1 << header_order)* PAGE_SIZE) - priv_metadata_size - sizeof(struct ttd_buf),
     header_order, size_of_a_rec,
     ttd_ring_channel_size_of_a_rec(ring_channel),
     ttd_ring_channel_size_in_recs(ring_channel),
     (size_in_pages * PAGE_SIZE)/ring_channel->size_of_a_rec,
     (size_in_pages * PAGE_SIZE)/ring_channel->size_of_a_rec - ttd_ring_channel_size_in_recs(ring_channel),
     ttd_ring_channel_highwater(ring_channel),
     ttd_ring_channel_emergency_margin(ring_channel));
     */
    ring_channel->header_order = header_order;
    ring_channel->buf_order = order;

    return 0;

    cleanup: if (ring_channel->recs) {
        free_pages(ring_channel->recs, order);
        ring_channel->recs = NULL;
    }

    if (ring_channel->buf) {
        free_pages(ring_channel->buf, header_order);
        ring_channel->buf = NULL;
    }

    return ret;

}

static int initialize_buffer(void *__unused) {

    int ret = 0;
    if (cmd_ring_channel_alloc_with_metadata(&tx_ring_channel, cmd_buf_size, sizeof(struct cmd_rec), 0) == 0) {
        printk(KERN_INFO "Transmitter ring buffer initialized.\n");
    }
    else {
        printk(KERN_INFO "Transmitter ring buffer initialization failed\n");
        return -ENOMEM;
    }

    if (cmd_ring_channel_alloc_with_metadata(&rx_ring_channel, cmd_buf_size, sizeof(struct cmd_rec), 0) == 0) {
        printk(KERN_INFO "Receiver ring buffer initialized.\n");
    }
    else {
        printk(KERN_INFO "Receiver ring buffer initialization failed\n");
        ret = -ENOMEM;
        goto exit;
    }

    exit:
    if (ring_channel->recs) {
        free_pages(ring_channel->recs, order);
        ring_channel->recs = NULL;
    }
    return ret;
}

int cmd_ring_channel_free(struct cmd_ring_channel *ring_channel) {

    if (ring_channel->recs) {
            free_pages((void*) ring_channel->recs, ring_channel->buf_order);
            ring_channel->recs = NULL;
    }

    if (ring_channel->buf) {
        free_pages((void*) ring_channel->buf, ring_channel->header_order);
        ring_channel->buf = NULL;
    }

    return 0;
}

static int __init initialize_driver(void) {
    int result;

    printk(KERN_INFO "Creating a kthread to initialize the ring buffer. \n");
    result = initialize_buffer(NULL);
    if (!result) {
        printk(KERN_INFO "Ring-Buffer initialization failed\n");
        return -ENOMEM;
    }
    return 0;
}

static void __exit cleanup_driver(void) {
    int result;

    result = cmd_ring_channel_free(&tx_ring_channel);
    if (!result) {
        printk(KERN_INFO "Transmitter ring buffer cleanup failed\n");
    }
    result = cmd_ring_channel_free(&rx_ring_channel);
    if (!result) {
        printk(KERN_INFO "Receiver ring buffer cleanup failed\n");
    }
}

module_init( initialize_driver);
module_exit( cleanup_driver);