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
 *  examples/nfs-perf-analysis/request.c
 *
 *  Request manipulation functions: hashing, move between stages,
 *  pretty printing, alloc, free.
 *
 *  Authors: Anton Burtsev, aburtsev@flux.utah.edu
 * 
 */

#include "debug.h"
#include "request.h"
#include "probes.h"

#include <target.h>
#include <target_xen_vm.h>

#include <probe_api.h>
#include <probe.h>



GHashTable *request_hash; 
unsigned long global_unique_request_number = 0;

void request_hash_init(void) {
    request_hash = g_hash_table_new(g_direct_hash, g_direct_equal);
    return;
};

void request_hash_add(struct request *req, unsigned long req_id) {
    struct request *lost_req;

    /* Check if guest re-uses this address and we somehow
       lost track of this request and forgot to remove it
       from our hashes */
    lost_req = request_hash_lookup(req_id);
    if (lost_req) {
        ERR_ON(lost_req->req_id != req_id,
               "lost_req->req_id != req_id: 0x%lx != 0x%lx\n", 
               lost_req->req_id, req_id);

        lost_req->req_id = req_id;
        request_done(lost_req);
    }

    req->req_id = req_id;
    g_hash_table_insert(request_hash, (gpointer)req_id, (gpointer)req);
    return;
}

struct request *request_hash_lookup(unsigned long req_id) {
    return (struct request *) g_hash_table_lookup (request_hash, (gpointer) req_id);
}

int request_hash_change_id(struct request *req, unsigned long new_req_id) {

    req = request_hash_lookup(req->req_id);
    if (!req) {
        WARN("Hash has no request with id:0x%lx\n", req->req_id);
        return -1;
    }

    WARN_ON(req->req_id == new_req_id, "old and new ids are the same, you have an error in your code\n");

    if(!g_hash_table_remove(request_hash, (gpointer)req->req_id)) {
        ERR("Failed to remove request from the hash, req_id:0x%lx\n", req->req_id);
    }

    request_hash_add(req, new_req_id);
    return 0;
}

int request_hash_remove(struct request *req) {
    int ret; 
    if(!req) {
        ERR("request is NULL, that's bad\n");
	return -1;
    }

    ret = (int)g_hash_table_remove(request_hash, (gpointer)req->req_id);
    if (!ret) {
        ERR("Failed to remove request from the hash, req_id:0x%lx\n", req->req_id);
        return ret;
    }

    return ret;
};

struct request *request_alloc(void) {
    struct request *req; 

    req = (struct request *)malloc(sizeof(struct request));
    if (!req)
        return req;

    req->req_id = 0;
    INIT_LIST_HEAD(&req->stages);
    req->req_number = global_unique_request_number;
    global_unique_request_number++;

    return req;
}

struct stage *request_stage_alloc(nfs_perf_stage_id_t stage_id) {
    struct stage *stage; 

    stage= (struct stage *)malloc(sizeof(struct stage));
    if (!stage)
        return stage;

    memset(stage, 0, sizeof(struct stage));
    INIT_LIST_HEAD(&stage->next_stage);
    stage->id = stage_id;
    
    return stage;
}

void request_free(struct request *req) {
    struct stage *stage, *next;

    /* deallocate stages first */
    list_for_each_entry_safe(stage, next, &req->stages, next_stage) 
    {
        list_del(&stage->next_stage);
        free(stage);
    }

    free(req);
    return;
};

void request_print(struct request *req) {
    struct stage *stage, *next;
    unsigned long long prev_timestamp = 0;
    int first_stage = 1;

    printf("req #%lu", req->req_number);
    list_for_each_entry_safe(stage, next, &req->stages, next_stage) 
    {
        if(first_stage) {
            first_stage = 0;
            printf(" %s:%d", stage_id_to_name(stage->id), 0);
	} else {
            printf(" %s:%lld", stage_id_to_name(stage->id), stage->timestamp - prev_timestamp);
        }
        
	prev_timestamp = stage->timestamp;
	 
    }
    printf("\n");
    
    return; 
};

void request_add_stage(struct request *req, struct stage *req_stage)
{
    list_add_tail(&req_stage->next_stage, &req->stages);
    return;
}

void request_done(struct request *req) {
    request_hash_remove(req);
    request_print(req);
    request_free(req);
    return;
}

struct request *request_move_on_path(struct probe *probe, unsigned long req_id, nfs_perf_stage_id_t stage_id)
{
    struct request *req; 
    struct stage *req_stage;

    req = request_hash_lookup(req_id);
    if (!req) {
        ERR("Fail to lookup request with id:0x%lx\n", req_id);
        return NULL;
    }

    req_stage = request_stage_alloc(stage_id);
    if (!req_stage) {
        ERR("Failed to allocate request stage:%s\n", 
            stage_id_to_name(stage_id));
        return NULL;
    }

    /* XXX: read the time stamp here */
    req_stage->timestamp = perf_get_rdtsc(probe->target);
    request_add_stage(req, req_stage);
    return req;
}

gboolean request_hash_print_and_free(gpointer key, gpointer value, gpointer user_data) {
    struct request *req = (struct request*)value;
    request_print(req);
    request_free(req);
    return 1;
};

void request_analysis_done(struct probe *probe) {
    DBG("Print out all requests\n");
    g_hash_table_foreach_remove(request_hash, request_hash_print_and_free, NULL);
    DBG("Done...unregistering\n");

    target_close(probe->target);
    return;
};


