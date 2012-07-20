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
#include "log.h"
#include "clfit.h"
#include "alist.h"

clrange_t clrange_create() {
    return (Pvoid_t) NULL;
}

int clrange_add(clrange_t *clf,Word_t start,Word_t end,void *data) {
    struct clf_range_data *crd = (struct clf_range_data *)malloc(sizeof(*crd));
    PWord_t pv = NULL;
    struct array_list *alist;
    int created = 0;

    crd->start = start;
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
	if (CLRANGE_END(crd) != end && CLRANGE_DATA(crd) == data) {
	    CLRANGE_END(crd) = end;
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
	if (pv == NULL)
	    return NULL;
	//fprintf(stderr,"found %lu\n",idx);
	//fflush(stderr);
	alist = (struct array_list *)*pv;

	j = -1;
	for (i = array_list_len(alist) - 1; i > -1; --i) {
	    struct clf_range_data *crd = (struct clf_range_data *) \
		array_list_item(alist,i);
	    if (idx < CLRANGE_END(crd) && (CLRANGE_END(crd) - idx) < lrlen) {
		retval = crd;
		lrlen = CLRANGE_END(crd) - idx;
	    }
	}

	if (retval) {
	    /* We found a tightest bound containing @index; return! */
	    //fprintf(stderr,"found %lu at %d\n",idx,i);
	    return CLRANGE_DATA(retval);
	}
	else {
	    /* If the index was zero, we can't find any previous
	     * matches, so we're done!
	     */
	    if (idx == 0) {
		//fprintf(stderr,"did not find %lu range fit!\n",idx,i);
		return NULL;
	    }
	}

	/* If we did not find a tightest bound containing @index, try
	 * the previous index to the current previous index.
	 */
	idx -= 1;
    }
}

void *clrange_find_next_loosest(clrange_t *clf,Word_t index,
				struct array_list **al_saveptr) {
    PWord_t pv;
    struct array_list *alist;
    Word_t idx;
    struct clf_range_data *prev_crd = NULL;
    Word_t widest_len = (Word_t)0;
    struct clf_range_data *crd;
    int i;

    if (!clf || !*clf)
	return NULL;

    /* Find the index that matches @index; if there isn't one, don't
     * worry about it.
     */
    JLL(pv,*clf,index);
    if (pv != NULL) {
	alist = (struct array_list *)*pv;

	for (i = 0; i < array_list_len(alist); ++i) {
	    crd = (struct clf_range_data *)array_list_item(alist,i);
	    if (CLRANGE_START(crd) <= index && CLRANGE_END(crd) >= index
		&& (CLRANGE_END(crd) - CLRANGE_START(crd)) > widest_len) {
		widest_len = CLRANGE_END(crd) - CLRANGE_START(crd);
		prev_crd = crd;
	    }
	}
    }

    /* If we did find the widest previous range containing @index, then
     * we want to try to find the next widest range that does *not*
     * contain it (which is an inclusive search on the end of the widest
     * range, since the range does not contain its end).  Otherwise, we
     * just try to find the next range, exclusive, from @index.
     */
    if (prev_crd) {
	idx = CLRANGE_END(prev_crd);
    }
    else {
	idx = index + 1; /* + 1 to make "inclusive" search be right. */
    }

    JLF(pv,*clf,idx);
    if (pv == NULL)
	return NULL;
    alist = (struct array_list *)*pv;

    /* Again, hunt for the widest bound from this start symbol. */
    widest_len = 0;
    prev_crd = NULL;
    for (i = 0; i < array_list_len(alist); ++i) {
	crd = (struct clf_range_data *)array_list_item(alist,i);
	if (CLRANGE_START(crd) <= idx && CLRANGE_END(crd) >= idx
	    && (CLRANGE_END(crd) - CLRANGE_START(crd)) > widest_len) {
	    widest_len = CLRANGE_END(crd) - CLRANGE_START(crd);
	    prev_crd = crd;
	}
    }

    if (al_saveptr && prev_crd)
	*al_saveptr = alist;

    return prev_crd;
}

struct array_list *clrange_find_prev_inc(clrange_t *clf,Word_t index) {
    PWord_t pv;

    if (!clf || !*clf)
	return NULL;

    JLL(pv,*clf,index);
    if (pv == NULL)
	return NULL;

    return (struct array_list *)*pv;
}

struct array_list *clrange_find_prev_exc(clrange_t *clf,Word_t index) {
    PWord_t pv;

    if (!clf || !*clf)
	return NULL;

    JLP(pv,*clf,index);
    if (pv == NULL)
	return NULL;

    return (struct array_list *)*pv;
}

struct array_list *clrange_find_next_inc(clrange_t *clf,Word_t index) {
    PWord_t pv;

    if (!clf || !*clf)
	return NULL;

    JLF(pv,*clf,index);
    if (pv == NULL)
	return NULL;

    return (struct array_list *)*pv;
}

struct array_list *clrange_find_next_exc(clrange_t *clf,Word_t index) {
    PWord_t pv;

    if (!clf || !*clf)
	return NULL;

    JLN(pv,*clf,index);
    if (pv == NULL)
	return NULL;

    return (struct array_list *)*pv;
}

struct array_list *clrange_find_subranges_inside(clrange_t *clf,
						 Word_t index,
						 unsigned int len) {
    PWord_t pv;
    struct array_list *retval = NULL;
    struct array_list *alist;
    Word_t idx_end = index + len;
    /* Start our search here, exclusive. */
    Word_t idx = idx_end;
    int i;
    struct clf_range_data *crd;

    if (!clf || !*clf)
	return NULL;

    retval = array_list_create(1);

    /*
     * We look for the previous index prior to (@index + @len),
     * exclusive; and keep repeating this until we find an index less
     * than @index.  For each range we find, if it is entirely inside
     * the given range, we include it in our results.
     */
    while ((alist = (struct array_list *)clrange_find_prev_exc(clf,idx))) {
	/* We do this loop backward so that we theoretically produce an
	 * exactly reverse-sorted list of struct clrnage_data * items --
	 * reverse of the way they are in the judy array.
	 */
	crd = NULL;
	for (i = array_list_len(alist) - 1; i >= 0; --i) {
	    crd = (struct clf_range_data *)array_list_item(alist,i);
	    if (CLRANGE_START(crd) <= index && CLRANGE_END(crd) <= idx_end) 
		array_list_append(retval,crd);
	}
	if (!crd) {
	    /* Bad!  List was not-NULL but empty?  Corruption somewhere
	     * is likely!
	     */
	    verror("CRD array list empty, but not NULL!\n");
	    goto errout;
	}
	/* Update the search idx. */
	idx = CLRANGE_START(crd);
	/* If the new idx is the start of the target range, or is prior
	 * to it, we're done.
	 *
	 * XXX: and yes, this means that the loop above is wasted for
	 * this list of CRDs.
	 */
	if (idx <= index)
	    goto out;
    }

 out:
    /* If we didn't find anything, dealloc and leave. */
    if (array_list_len(retval) == 0) {
	array_list_free(retval);
	retval = NULL;
    }
    return retval;

 errout:
    array_list_free(retval);
    return NULL;
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
