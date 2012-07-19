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

#ifndef __CLFIT_H__
#define __CLFIT_H__

#include <Judy.h>
#include "alist.h"

typedef Pvoid_t clrange_t;

struct clf_range_data { 
    Word_t start;
    Word_t end;
    void *data;
};

#define CLRANGE_START(crd) ((crd)->start)
#define CLRANGE_END(crd)   ((crd)->end)
#define CLRANGE_DATA(crd)  ((crd)->data)

clrange_t clrange_create();
int clrange_add(clrange_t *clf,Word_t start,Word_t end,void *data);
int clrange_update_end(clrange_t *clf,Word_t start,Word_t end,void *data);
void *clrange_find(clrange_t *clf,Word_t index);

struct array_list *clrange_find_prev_inc(clrange_t *clf,Word_t index);
struct array_list *clrange_find_prev_exc(clrange_t *clf,Word_t index);
struct array_list *clrange_find_next_inc(clrange_t *clf,Word_t index);
struct array_list *clrange_find_next_exc(clrange_t *clf,Word_t index);
struct array_list *clrange_find_subranges_inside(clrange_t *clf,
						 Word_t index,
						 unsigned int len);

void clrange_free(clrange_t clf);

typedef Pvoid_t clmatch_t;

clmatch_t clmatch_create();
int clmatch_add(clmatch_t *clf,Word_t index,void *data);
struct array_list *clmatch_find(clmatch_t *clf,Word_t index);
void clmatch_free(clmatch_t clf);

#endif

