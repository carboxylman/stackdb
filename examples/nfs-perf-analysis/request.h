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
 *  Datastructures, which describe NFS requests for the analysis algorithm
 *
 *  Authors: Anton Burtsev, aburtsev@flux.utah.edu
 * 
 */

#ifndef __NFS_PERF_REQUEST_H__
#define __NFS_PERF_REQUEST_H__

/* request is a linked list of stages */
struct request {
        struct list_head  stages;        
}

/* a stage has a name, timestamp, and 4 words of stage-specific data just in
   case we want to record something special about this stage */
struct stage {
        struct request *req;
        char  name[32];
        u64   timestamp;
        u32   id;
        u32   data[4];
        struct list_head  next_stage;        
}

struct request *request_alloc();
void request_free(struct request *req);

struct stage * request_stage_alloc(char *name);
int request_add_stage(struct request *req, struct stage *req_stage);

/* We have an individual hash for every stage, this function lookups a hash
   by name (typically a name of a stage) */
struct hash * global_hash_by_name(char *name);

/* hash is used to resolve unique IDs into requests */
struct request *hash_request_by_id(struct hash *h, u32 id)

#endif

