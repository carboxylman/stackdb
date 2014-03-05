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
#include <linux/slab.h>
/* need to decide where we want to keep this header file */
#include "repair_driver.h"

#define SUB_MODULE_COUNT 10

static struct task_struct *driver_thread;
struct submod_table submodule;
struct cmd_ring_channel req_ring_channel, res_ring_channel;
static unsigned int cmd_buf_size = 4; /* buffer size (in pages) */
static int ack_ready = 0;


static int load_submodules(void *__unused) {

    struct cmd_rec *cmd;  /* structure representing the command */
    struct ack_rec *ack;  /* structure representing the acknowledgment */
    int result;
    unsigned long req_cons;
    unsigned long res_prod;

    /* Wait till the buffer is populate with some command*/
    while (!kthread_should_stop()) {

	if (cmd_ring_channel_get_cons(&req_ring_channel) >=
		cmd_ring_channel_get_prod(&req_ring_channel)) {
	    yield();
	    continue;
	}

	printk(KERN_INFO "Read a command from the request ring buffer\n");
	/* Read the command */
	cmd = (struct cmd_rec*) cmd_ring_channel_get_rec(&req_ring_channel,
		cmd_ring_channel_get_cons(&req_ring_channel));

	/* Increment the consumer index in the request ring channel */
	req_cons = cmd_ring_channel_get_cons(&req_ring_channel);
	req_cons += 1;
	cmd_ring_channel_set_cons(&req_ring_channel, req_cons);

	/* Based on the submodule id switch to appropriate block */
	switch(cmd->submodule_id) {
	    /* Case 0 refers to the psaction submodule */
	    case 0 :
		printk(KERN_INFO " Number of arguments passed = %d\n",cmd->argc);
		if(submodule.mod_table[cmd->submodule_id] == NULL)
		    printk(KERN_INFO "Loading the the psaction sub module\n");
		if((result = request_module("psaction_module")) < 0) {
		    printk(KERN_INFO "psaction_module not available\n");
		    return -ENODEV;
		}

		/* 
		 * get the address in the res_ring_channel where the 
		 * acknowledgment should be inserted 
		 */
		ack = (struct ack_rec*) cmd_ring_channel_put_rec_addr(
			&res_ring_channel,
			cmd_ring_channel_get_prod(&res_ring_channel));
		printk( KERN_INFO " ack rec addr %p\n",ack);

		/*TODO: Zero out the record on the ring channel before use */
		/* Increment the prod index for the res_ring_channel */
		res_prod = cmd_ring_channel_get_prod(&res_ring_channel);
		printk(KERN_INFO " producer index = %d\n",res_prod);
		res_prod += 1;
		cmd_ring_channel_set_prod(&res_ring_channel, res_prod);
		/* 
		 * Call the appropriate handler in the submodule based on command id
		 * After the handler executes it set ack_ready flag, VMI 
		 * tool probes this flag periodically to retrive the result
		 */
		if(submodule.mod_table[cmd->submodule_id] != NULL && 
			submodule.mod_table[cmd->submodule_id]->func_table[cmd->cmd_id] != NULL) {


		    result = submodule.mod_table[cmd->submodule_id]->func_table[cmd->cmd_id](cmd,ack);
		    if(result) {
			printk(KERN_INFO "Function call failed.\n");
			ack->exec_status = 0;
			ack_ready++;
		    }
		    printk(KERN_INFO " ack exec status = %d\n",ack->exec_status);

		} else {
		    printk(KERN_INFO "ERROR: Sub Module not loaded.\n");
		}

		printk(KERN_INFO "Waiting for the next command.\n");

		break;
		/* Case 1 refers to the ps_deescalate submodule */
	    
	    case 1:
		if(submodule.mod_table[cmd->submodule_id] == NULL) {
		    printk(KERN_INFO "Loading the the ps_deescalate sub module\n");
		}
		if((result = request_module("ps_deescalate_module")) < 0) {
		    printk(KERN_INFO "ps_deescalate_module not available\n");
		    return -ENODEV;
		}

		/* 
		 * get the address in the res_ring_channel where the 
		 * acknowledgment should be inserted
		 */
		ack = (struct ack_rec*) cmd_ring_channel_put_rec_addr(
			&res_ring_channel,
			cmd_ring_channel_get_prod(&res_ring_channel));
		/*Increment the prod index for the result ring channel*/
		res_prod = cmd_ring_channel_get_prod(&res_ring_channel);
		res_prod += 1; 
		cmd_ring_channel_set_prod(&res_ring_channel, res_prod);
		/* call the appropriate function in the submodule based on command id*/
		if(submodule.mod_table[cmd->submodule_id] != NULL && 
			submodule.mod_table[cmd->submodule_id]->func_table[cmd->cmd_id] != NULL) {


		    result = submodule.mod_table[cmd->submodule_id]->func_table[cmd->cmd_id](cmd,ack);
		    if(result) {
			printk(KERN_INFO "Function call failed.\n");
			ack->exec_status = 0;
			ack_ready++;
		    }
		} else {
		    printk(KERN_INFO "ERROR: Sub Module not loaded.\n");
		}


		printk(KERN_INFO "Waiting for the next command.\n");
		break;
		/* Case 2 refers to the system_map_reset submodule */
	    
	    case 2:
		if(submodule.mod_table[cmd->submodule_id] == NULL) {
		    printk(KERN_INFO "Loading the the system_map_reset sub module\n");
		}
		if((result = request_module("system_map_reset")) < 0) {
		    printk(KERN_INFO "system_map_reset module not available\n");
		    return -ENODEV;
		}

		/* 
		 * get the address in the res_ring_channel where the 
		 * acknowledgment should be inserted
		 */
		ack = (struct ack_rec*) cmd_ring_channel_put_rec_addr(
			&res_ring_channel,
			cmd_ring_channel_get_prod(&res_ring_channel));
		/*Increment the prod index for the result ring channel*/
		res_prod = cmd_ring_channel_get_prod(&res_ring_channel);
		res_prod += 1; 
		cmd_ring_channel_set_prod(&res_ring_channel, res_prod);
		/* call the appropriate function in the submodule based on command id*/
		if(submodule.mod_table[cmd->submodule_id] != NULL && 
			submodule.mod_table[cmd->submodule_id]->func_table[cmd->cmd_id] != NULL) {
		    result = submodule.mod_table[cmd->submodule_id]->func_table[cmd->cmd_id](cmd,ack);
		    if(result) {
			printk(KERN_INFO "Function call failed.\n");
			ack->exec_status = 0;
			ack_ready++;
		    }
		} else {
		    printk(KERN_INFO "ERROR: Sub Module not loaded.\n");
		}

		printk(KERN_INFO "Waiting for the next command.\n");
		break;
	    case 3:
		if(submodule.mod_table[cmd->submodule_id] == NULL) {
		    printk(KERN_INFO "Loading the the killsocket submodule\n");
		}
		if((result = request_module("killsocket_module")) < 0) {
		    printk(KERN_INFO "system_map_reset module not available\n");
		    return -ENODEV;
		}

		/* 
		 * get the address in the res_ring_channel where the 
		 * acknowledgment should be inserted
		 */
		ack = (struct ack_rec*) cmd_ring_channel_put_rec_addr(
			&res_ring_channel,
			cmd_ring_channel_get_prod(&res_ring_channel));
		/*Increment the prod index for the result ring channel*/
		res_prod = cmd_ring_channel_get_prod(&res_ring_channel);
		res_prod += 1; 
		cmd_ring_channel_set_prod(&res_ring_channel, res_prod);
		/* call the appropriate function in the submodule based on command id*/
		if(submodule.mod_table[cmd->submodule_id] != NULL && 
			submodule.mod_table[cmd->submodule_id]->func_table[cmd->cmd_id] != NULL) {
		    result = submodule.mod_table[cmd->submodule_id]->func_table[cmd->cmd_id](cmd,ack);
		    if(result) {
			printk(KERN_INFO "Function call failed.\n");
			ack->exec_status = 0;
			ack_ready++;
		    }
		} else {
		    printk(KERN_INFO "ERROR: Sub Module not loaded.\n");
		}


		printk(KERN_INFO "Waiting for the next command.\n");
		break;	    default :
		printk(KERN_INFO 
			"Invalid submodule Id specified, hence no module loaded\n");
		return -1;

	}
    }

    return 1;
}



int cmd_ring_channel_alloc_with_metadata(struct cmd_ring_channel *ring_channel,
	unsigned long size_in_pages, unsigned long size_of_a_rec) {

    int ret = 0;
    unsigned long order;

    printk(KERN_INFO "Allocating ring channel\n");
    cmd_ring_channel_init(ring_channel);


    /* Figure out the right way of doing this */
    order = get_order(size_in_pages * PAGE_SIZE);
    if ((ring_channel->recs = (char*) __get_free_pages(GFP_KERNEL, order)) == NULL) {

	printk(KERN_INFO "Buffer page allocation failed, "
		"size in pages:%lu, order:%lu\n", size_in_pages, order);
	ret = -ENOMEM;
	goto cleanup;
    }
    printk(KERN_INFO "Allocated pages for the buffer in the ring channel\n");


    /* init structure members */
    ring_channel->cons = ring_channel->prod = 0;
    ring_channel->size_of_a_rec = size_of_a_rec;
    ring_channel->size_in_recs = (size_in_pages * PAGE_SIZE) / ring_channel->size_of_a_rec;
    ring_channel->payload_buffer_size = size_in_pages * PAGE_SIZE;
    ring_channel->buf_order = order;

    return ret;

cleanup: if (ring_channel->recs) {
	     free_pages((unsigned long) ring_channel->recs, order);
	     ring_channel->recs = NULL;
	 }

	 return ret;

}

static int initialize_submodule_table(void* __unused ) {

    int i;
    submodule.submodule_count = SUB_MODULE_COUNT;

    /* Allocate memory for submodule table */
    submodule.mod_table = (struct submodule **) kmalloc(SUB_MODULE_COUNT  * sizeof(struct submodule *), GFP_KERNEL);
    if(!submodule.mod_table) {
	printk(KERN_INFO "Fialed to allocate memory for submodule table\n");
	return -ENOMEM;
    }
    printk(KERN_INFO "Initialized submodule table.\n");

    /* initialize the array of pointers to submodule struct */
    for(i = 0; i<SUB_MODULE_COUNT; i++) {
	submodule.mod_table[i] = NULL;
    }

    return 0;
}



static int initialize_buffer(void *__unused) {

    int ret = 0;
    if (cmd_ring_channel_alloc_with_metadata(&req_ring_channel, 
		cmd_buf_size, 
		sizeof(struct cmd_rec)) == 0) {
	printk(KERN_INFO "Request ring buffer initialized.\n");
    }
    else {
	printk(KERN_INFO "Request ring buffer initialization failed\n");
	return -ENOMEM;
    }

    if (cmd_ring_channel_alloc_with_metadata(&res_ring_channel,
		cmd_buf_size,
		sizeof(struct ack_rec)) == 0) {
	printk(KERN_INFO "Result ring buffer initialized.\n");
    }
    else {
	printk(KERN_INFO "Result ring buffer initialization failed\n");
	ret = -ENOMEM;
	goto exit;
    }
    return ret;

exit:
    if (req_ring_channel.recs) {
	free_pages((unsigned long)req_ring_channel.recs, req_ring_channel.buf_order);
	req_ring_channel.recs = NULL;
    }
    return ret;
}

int cmd_ring_channel_free(struct cmd_ring_channel *ring_channel) {

    if (ring_channel->recs) {
	free_pages((unsigned long) ring_channel->recs, ring_channel->buf_order);
	ring_channel->recs = NULL;
    }

    return 0;
}

static int __init initialize_driver(void) {
    int result;

    /* initialize the submodule table */
    result = initialize_submodule_table(NULL);
    if (result) {
	printk(KERN_INFO "Sub module table initialization failed\n");
	return -ENOMEM;
    }
    /* create the ring buffers */
    result = initialize_buffer(NULL);
    if (result) {
	printk(KERN_INFO "Ring-Buffer initialization failed\n");
	return -ENOMEM;
    }

    /* Now that the ring buffers are created we fork a kthread to
     * continiously monitor the producer and consumer indices. If there
     * a command in the buffer then load the appropriate sub module.
     */
    printk(KERN_INFO "Creating a  driver kthread in the init function\n");
    driver_thread = kthread_run(load_submodules, NULL, "repair_submodule_loader");
    if (IS_ERR(driver_thread)) {
	printk(KERN_INFO "Kthread creation failed\n");
	return -ENOMEM;
    }

    return 0;
}

static void __exit cleanup_driver(void) {
    int result;

    result = cmd_ring_channel_free(&req_ring_channel);
    if (result) {
	printk(KERN_INFO "Transmitter ring buffer cleanup failed\n");
    }
    result = cmd_ring_channel_free(&res_ring_channel);
    if (result) {
	printk(KERN_INFO "Receiver ring buffer cleanup failed\n");
    }
    /* free the memory allocated for the submodule table */
    if(submodule.mod_table) {
	kfree(submodule.mod_table);
	submodule.mod_table = NULL;
    }
    /* Stop the kthread */
    result = kthread_stop(driver_thread);
    if (result == -EINTR)
	printk(KERN_INFO "Kthread_stop failed\n");
    else
	printk(KERN_INFO " load_submodules returned %d\n",result);
}


EXPORT_SYMBOL(req_ring_channel);
EXPORT_SYMBOL(res_ring_channel);
EXPORT_SYMBOL(submodule);
EXPORT_SYMBOL(ack_ready);

module_init( initialize_driver);
module_exit( cleanup_driver);
MODULE_LICENSE("GPL");
