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

/*
 * We assume that clrange_t ranges DO NOT overlap -- i.e., where the
 * start of range B is contained within range A, but the end of B is not
 * within A.  This is a safe assumption when dealing with code segments
 * that are associated with symbols; however, it may not be appropriate
 * for other kinds of things.
 */

typedef Pvoid_t clrange_t;

struct clf_range_data { 
    Word_t start;
    Word_t end;
    void *data;
    struct clf_range_data *containing_range;
};

#define CLRANGE_START(crd) ((crd)->start)
#define CLRANGE_END(crd)   ((crd)->end)
#define CLRANGE_DATA(crd)  ((crd)->data)

struct clf_range_data *crd_get_loosest(struct array_list *crdlist,
				       Word_t start,Word_t end,
				       int *contains_saveptr);
struct clf_range_data *crd_get_tightest(struct array_list *crdlist,
					Word_t start,Word_t end,
					int *contains_saveptr);
struct clf_range_data *crd_top_containing_range(struct clf_range_data *crd);

clrange_t clrange_create(void);
int clrange_add(clrange_t *clf,Word_t start,Word_t end,void *data);
int clrange_update_end(clrange_t *clf,Word_t start,Word_t end,void *data);
void *clrange_find(clrange_t *clf,Word_t index);
/*
 * Find the range that is the widest range containing index.
 */
struct clf_range_data *clrange_find_loosest(clrange_t *clf,Word_t index,
					    struct array_list **al_saveptr);
/*
 * Try to find the next index, given @index is (or might be) an existing
 * valid index in our range array -- BUT the index we find must *not* be
 * inside of the range(s) specified by @index; it must be completely
 * outside them.  Also, the bound we return will be the lengthiest
 * (loosest) bound; i.e., if there are multiple things at the next
 * index, we take the one with the widest range.
 */
struct clf_range_data *clrange_find_next_loosest(clrange_t *clf,Word_t index,
						 struct array_list **al_saveptr);

struct array_list *clrange_find_prev_inc(clrange_t *clf,Word_t index);
struct array_list *clrange_find_prev_exc(clrange_t *clf,Word_t index);
struct array_list *clrange_find_next_inc(clrange_t *clf,Word_t index);
struct array_list *clrange_find_next_exc(clrange_t *clf,Word_t index);
struct array_list *clrange_find_subranges_inside(clrange_t *clf,
						 Word_t index,
						 unsigned int len);

void clrange_free(clrange_t clf);

typedef Pvoid_t clmatch_t;

clmatch_t clmatch_create(void);
int clmatch_add(clmatch_t *clf,Word_t index,void *data);
struct array_list *clmatch_find(clmatch_t *clf,Word_t index);
void clmatch_free(clmatch_t clf);

typedef Pvoid_t clmatchone_t;

clmatchone_t clmatchone_create(void);
int clmatchone_add(clmatchone_t *clf,Word_t index,void *data);
int clmatchone_update(clmatchone_t *clf,Word_t index,void *data);
void *clmatchone_find(clmatchone_t *clf,Word_t index);
void clmatchone_free(clmatchone_t clf);

#endif

