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

#include <stdio.h>
#include <stdlib.h>
#include "clfit.h"
#include "alist.h"

struct clf_range_data {
    Word_t end;
    void *data;
};

clrange_t clrange_create() {
    return (Pvoid_t) NULL;
}

int clrange_add(clrange_t *clf,Word_t start,Word_t end,void *data) {
    struct clf_range_data *crd = (struct clf_range_data *)malloc(sizeof(*crd));
    PWord_t pv = NULL;
    struct array_list *alist;
    int created = 0;

    crd->end = end;
    crd->data = data;

    if (*clf) 
	JLG(pv,*clf,start);
    if (!pv) {
	//fprintf(stderr,"inserting new alist for 0x%lx,0x%lx\n",start,end);
	//fflush(stderr);
	alist = array_list_create(1);
	created = 1;
	JLI(pv,*clf,start);
	if (pv == PJERR) {
	    goto errout;
	}
	*pv = (Word_t)alist;
    }
    else if (pv == PJERR) 
	goto errout;
    else 
	alist = (struct array_list *)*pv;

    array_list_append(alist,crd);

    return 0;

 errout:
    if (created) 
	array_list_free(alist);
    free(crd);
    return -1;
}

int clrange_update_end(clrange_t *clf,Word_t start,Word_t end,void *data) {
    struct clf_range_data *crd;
    PWord_t pv;
    struct array_list *alist;
    int i;

    /* We look for an exact match, and update the end value if there is
     * an exact match for this start addr and data.
     */
    JLG(pv,*clf,start);
    if (!pv) 
	return -1;

    alist = (struct array_list *)*pv;
    for (i = 0; i < array_list_len(alist); ++i) {
	crd = (struct clf_range_data *)array_list_item(alist,i);
	if (crd->end != end && crd->data == data) {
	    crd->end = end;
	    break;
	}
    }

    return 0;
}

void *clrange_find(clrange_t *clf,Word_t index) {
    PWord_t pv;
    struct array_list *alist;
    Word_t idx = index;
    int i,j;
    Word_t lrlen = ~(Word_t)0;
    struct clf_range_data *retval = NULL;

    if (!clf || !*clf)
	return NULL;

    //fprintf(stderr,"starting looking for %lu\n",idx);
    //fflush(stderr);

    /*
     * We look for the previous index (including @index itself).  Each
     * index will have an array_list associated with it; we scan through
     * the whole array list looking for the tightest range containing
     * @index.  If we find such a range, return the *data associated
     * with it.  If we don't find a range in the array list, find the
     * previous index of the previous index we found first, and repeat
     * the range search for that array list.  Keep going until we find a
     * match...
     */
    while (1) {
	//fprintf(stderr,"looking for %lu\n",idx);
	//fflush(stderr);
	JLL(pv,*clf,idx);
	//fprintf(stderr,"found %lu\n",idx);
	if (pv == NULL)
	    return NULL;
	alist = (struct array_list *)*pv;

	j = -1;
	for (i = 0; i < array_list_len(alist); ++i) {
	    struct clf_range_data *crd = (struct clf_range_data *) \
		array_list_item(alist,i);
	    if (index < crd->end && (crd->end - idx) < lrlen) {
		retval = crd;
		lrlen = crd->end - idx;
	    }
	}

	if (retval) 
	    /* We found a tightest bound containing @index; return! */
	    return retval->data;
	else {
	    /* If the index was zero, we can't find any previous
	     * matches, so we're done!
	     */
	    if (idx == 0)
		return NULL;
	}

	/* If we did not find a tightest bound containing @index, try
	 * the previous index to the current previous index.
	 */
	idx -= 1;
    }
}

void clrange_free(clmatch_t clf) {
    PWord_t pv;
    int rci;
    Word_t index;
    Word_t bytes_freed;

    if (!clf)
	return;

    /* This stinks -- we have to free each element one by one. */
    while (1) {
	index = 0;
	JLF(pv,clf,index);
	if (pv == NULL)
	    break;
	array_list_deep_free((struct array_list *)*pv);
	*pv = NULL;
	JLD(rci,clf,index);
    }

    JLFA(bytes_freed,clf);
}

clmatch_t clmatch_create() {
    return (Pvoid_t) NULL;
}

/*
 * This function associates @data with some integer @index.  Later, when
 * you call clfit_find_closest(), you can find the closest index match
 * to these values.  You can associate multiple pieces of data with each
 * index.  If you 
 */
int clmatch_add(clmatch_t *clf,Word_t index,void *data) {
    PWord_t pv = NULL;
    struct array_list *alist;
    int created = 0;

    if (*clf) 
	JLG(pv,*clf,index);
    if (!pv) {
	alist = array_list_create(1);
	created = 1;
	JLI(pv,*clf,index);
	if (pv == PJERR) {
	    goto errout;
	}
	*pv = (Word_t)alist;
    }
    else if (pv == PJERR) 
	goto errout;
    else 
	alist = (struct array_list *)*pv;

    array_list_append(alist,data);

    return 0;

 errout:
    if (created) 
	array_list_free(alist);
    return -1;
}

/*
 * This function finds an array_list at the closest previous match.  We
 * return an array_list because there might be multiple things at that
 * index.
 */
struct array_list *clmatch_find(clmatch_t *clf,Word_t index) {
    PWord_t pv;

    if (!clf || !*clf)
	return NULL;

    /*
     * We look for the previous index (including @index itself).
     */
    JLL(pv,*clf,index);
    if (pv == NULL)
	return NULL;
    return (struct array_list *)*pv;
}

void clmatch_free(clmatch_t clf) {
    PWord_t pv;
    int rci;
    Word_t index;
    Word_t bytes_freed;

    if (!clf)
	return;

    /* This stinks -- we have to free each element one by one. */
    while (1) {
	index = 0;
	JLF(pv,clf,index);
	if (pv == NULL)
	    break;
	array_list_free((struct array_list *)*pv);
	*pv = NULL;
	JLD(rci,clf,index);
    }

    JLFA(bytes_freed,clf);
}
