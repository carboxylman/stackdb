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
 *  examples/nfs-perf-analysis/request.h
 *
 *  Datastructures, which describe NFS requests for the
 *  analysis algorithm. Each request is a list of stages. 
 *
 *  Authors: Anton Burtsev, aburtsev@flux.utah.edu
 * 
 */

#ifndef __NFS_PERF_REQUEST_H__
#define __NFS_PERF_REQUEST_H__

#include "list.h"
#include "probes.h"

/* request is a linked list of stages */
typedef struct request {
    unsigned long req_id;
    unsigned long req_number;
    struct list_head  stages;        
} request_t;

/* a stage has a name, timestamp, and 4 words of stage-specific data just in
   case we want to record something special about this stage */
typedef struct stage {
    struct request      *req;
    unsigned long       id;
    unsigned long long  timestamp;
    unsigned long       data[4];
    struct list_head    next_stage;        
} stage_t;

void request_hash_init(void);
void request_hash_add(struct request *req, unsigned long req_id);
struct request * request_hash_lookup(unsigned long req_id);
int request_hash_change_id(struct request *req, unsigned long new_req_id);
int request_hash_remove(struct request *req);
struct request *request_alloc(void);
struct stage *request_stage_alloc(nfs_perf_stage_id_t stage_id);
void request_free(struct request *req);
void request_print(struct request *req);
void request_add_stage(struct request *req, struct stage *req_stage);
void request_done(struct request *req);
struct request *request_move_on_path(unsigned long req_id, nfs_perf_stage_id_t stage_id);

#endif

