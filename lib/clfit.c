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
#include <limits.h>
#include "log.h"
#include "clfit.h"
#include "alist.h"

clrange_t clrange_create() {
    return (Pvoid_t) NULL;
}

struct clf_range_data *crd_top_containing_range(struct clf_range_data *crd) {
    while (crd->containing_range)
	crd = crd->containing_range;

    return crd;
}

struct clf_range_data *crd_get_loosest(struct array_list *crdlist,
				       Word_t start,Word_t end,
				       int *contains_saveptr) {
    int i;
    Word_t loosest_len = 0;
    struct clf_range_data *crd;
    struct clf_range_data *best_crd = NULL;

    if (end < start)
	return NULL;

    if (contains_saveptr)
	*contains_saveptr = 0;

    for (i = 0; i < array_list_len(crdlist); ++i) {
	crd = (struct clf_range_data *)array_list_item(crdlist,i);
	if ((CLRANGE_END(crd) - CLRANGE_START(crd)) > loosest_len) {
	    loosest_len = CLRANGE_END(crd) - CLRANGE_START(crd);
	    best_crd = crd;
	    if (contains_saveptr 
		&& CLRANGE_START(crd) <= start && CLRANGE_END(crd) >= end) 
		*contains_saveptr = 1;
	}
    }

    return best_crd;
}

struct clf_range_data *crd_get_tightest(struct array_list *crdlist,
					Word_t start,Word_t end,
					int *contains_saveptr) {
    int i;
    Word_t tightest_len = ULONG_MAX;
    Word_t tightest_containing_len = ULONG_MAX;
    struct clf_range_data *crd;
    struct clf_range_data *best_crd = NULL;
    struct clf_range_data *best_containing_crd = NULL;

    if (end < start)
	return NULL;

    if (contains_saveptr)
	*contains_saveptr = 0;

    for (i = 0; i < array_list_len(crdlist); ++i) {
	crd = (struct clf_range_data *)array_list_item(crdlist,i);
	if ((CLRANGE_END(crd) - CLRANGE_START(crd)) < tightest_len) {
	    tightest_len = CLRANGE_END(crd) - CLRANGE_START(crd);
	    best_crd = crd;
	    if (CLRANGE_START(crd) <= start && CLRANGE_END(crd) > end
		&& (CLRANGE_END(crd) - CLRANGE_START(crd)) 
		   < tightest_containing_len) {
		if (contains_saveptr) 
		    *contains_saveptr = 1;
		best_containing_crd = crd;
		tightest_containing_len = CLRANGE_END(crd) - CLRANGE_START(crd);
	    }
	}
    }

    if (best_containing_crd)
	return best_containing_crd;
    else
	return best_crd;
}

int clrange_add(clrange_t *clf,Word_t start,Word_t end,void *data) {
    struct clf_range_data *crd = (struct clf_range_data *)malloc(sizeof(*crd));
    PWord_t pv = NULL;
    struct array_list *alist;
    struct array_list *tmpalist;
    int created = 0;
    struct clf_range_data *ccrd;
    int contains = 0;
    Word_t idx;

    crd->start = start;
    crd->end = end;
    crd->data = data;
    crd->containing_range = NULL;

    idx = start;
    if (*clf) 
	JLG(pv,*clf,idx);
    if (!pv) {
	vdebug(10,LOG_OTHER,"inserting new alist for 0x%lx,0x%lx\n",start,end);
	alist = array_list_create(1);
	created = 1;
	JLI(pv,*clf,start);
	if (pv == PJERR) {
	    goto errout;
	}
	*pv = (Word_t)alist;

	/* Now we need to find the containing parent.  Basically...
	 *
	 * 1) If the previous range (previous, inclusive, of index - 1)
	 * does not contain our range, we have two cases: 
	 *   a) if that previous range is contained, we keep searching up that
	 *      hierarchy until there is no more containing ranges to
	 *      find one that contains our range; OR 
	 *   b) if that previous range is not contained, our range also
	 *      has no container.
	 * OR
	 * 2) If the previous range (previous, inclusive, of index - 1)
	 * DOES contain our range, our range's container is that
	 * previous range.
	 *
	 * AND, for these, we want the *tightest* containing parent.
	 */
	pv = NULL;
	idx = start;
	JLP(pv,*clf,idx);
	if (pv && pv != PJERR) {
	    /* Find the widest containing range in this list. */
	    tmpalist = (struct array_list *)*pv;
	    ccrd = crd_get_tightest(tmpalist,start,end,&contains);
	    /* Case 1a) above: */
	    if (!contains && ccrd->containing_range) {
		while (ccrd->containing_range) {
		    if (start >= CLRANGE_START(ccrd->containing_range)
			&& end <= CLRANGE_END(ccrd->containing_range)) {
			crd->containing_range = ccrd->containing_range;
			break;
		    }
		    ccrd = ccrd->containing_range;
		}
	    }
	    /* Case 1b) above: */
	    else if (!contains && !ccrd->containing_range)
		crd->containing_range = NULL;
	    /* Case 2) above: */
	    else if (contains)
		crd->containing_range = ccrd;

	    if (crd->containing_range)
		vdebug(10,LOG_OTHER,
		       "containing range for (0x%lx,0x%lx) is (0x%lx,0x%lx)\n",
		       start,end,crd->containing_range->start,
		       crd->containing_range->end);
	    else 
		vdebug(10,LOG_OTHER,
		       "no containing range for (0x%lx,0x%lx) (%d)!\n",
		       start,end,contains);
	}
    }
    else if (pv == PJERR) 
	goto errout;
    else {
	/* Since we make the non-overlapping assumption, the container
	 * of this new range is the same as the container of the "peer"
	 * ranges on the alist.
	 */
	alist = (struct array_list *)*pv;
	crd->containing_range = ((struct clf_range_data *) \
				 array_list_item(alist,0))->containing_range;
    }

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
    struct clf_range_data *ccrd;
    struct clf_range_data *tmpcrd;
    PWord_t pv;
    struct array_list *alist;
    int i;
    Word_t idx;
    int found;

    /* We look for an exact match, and update the end value if there is
     * an exact match for this start addr and data.
     */
    JLG(pv,*clf,start);
    if (!pv) 
	return -1;

    alist = (struct array_list *)*pv;
    crd = NULL;
    for (i = 0; i < array_list_len(alist); ++i) {
	crd = (struct clf_range_data *)array_list_item(alist,i);
	if (CLRANGE_END(crd) != end && CLRANGE_DATA(crd) == data) {
	    vdebug(10,LOG_OTHER,
		   "updated alist %p crd %p start %lx end %lx (old end %lx)"
		   " i %d data %p\n",alist,crd,start,end,CLRANGE_END(crd),i,data);
	    CLRANGE_END(crd) = end;
	    break;
	}
    }

    /* Now, technically, we have to update the containing_range
     * hierarchy as well, since we might have swallowed more ranges
     * downstream from us.
     *
     * What we do is keep finding next indexes from our old end
     * (inclusive) to our new end (exclusive); if they are contained in
     * us: 1) if they have a container, and we are not already in that
     * hierarchy, we become their new container; 2) if the don't have a
     * container, we become their new container.
     *
     * XXX: case 1 relies on the assumption that the widest ranges at
     * any start index come first in the array_list at that index!  Fix
     * this here and elsewhere.
     */
    /* Also, since ranges can't overlap, we can't "outgrow" our
     * container.
     */

    idx = end;
    while (1) {
	pv = NULL;
	JLN(pv,*clf,idx);
	if (!pv || pv == PJERR)
	    break;
	alist = (struct array_list *)*pv;
	tmpcrd = NULL;
	for (i = 0; i < array_list_len(alist); ++i) {
	    tmpcrd = (struct clf_range_data *)array_list_item(alist,i);
	    /* This will break us out for good; see bottom of while loop. */
	    if (CLRANGE_START(tmpcrd) >= end)
		goto while_done;

	    /* If they are contained in us... */
	    if (start <= CLRANGE_START(tmpcrd) && CLRANGE_END(tmpcrd) <= end) {
		/* Case 1) above: */
		if (tmpcrd->containing_range) {
		    found = 0;
		    ccrd = tmpcrd;
		    while (ccrd->containing_range) {
			if (ccrd->containing_range == crd) {
			    found = 1;
			    break;
			}
			ccrd = ccrd->containing_range;
		    }
		    if (!found)
			tmpcrd = crd;
		}
		/* Case 2) above: */
		else 
		    tmpcrd->containing_range = crd;
	    }
	}

    while_done:
	;
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

    vdebug(10,LOG_OTHER,"starting looking for 0x%lx\n",idx);

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
	vdebug(10,LOG_OTHER,"looking for 0x%lx\n",idx);
	JLL(pv,*clf,idx);
	if (pv == NULL)
	    return NULL;
	vdebug(10,LOG_OTHER,"found 0x%lx\n",idx);
	alist = (struct array_list *)*pv;

	j = -1;
	for (i = array_list_len(alist) - 1; i > -1; --i) {
	    struct clf_range_data *crd = (struct clf_range_data *) \
		array_list_item(alist,i);
	    if (index < CLRANGE_END(crd) && (CLRANGE_END(crd) - CLRANGE_START(crd)) < lrlen) {
		retval = crd;
		lrlen = CLRANGE_END(crd) - CLRANGE_START(crd);
	    }
	}

	if (retval) {
	    /* We found a tightest bound containing @index; return! */
	    vdebug(10,LOG_OTHER,"found 0x%lx at %d\n",idx,i);
	    return CLRANGE_DATA(retval);
	}
	else {
	    /* If the index was zero, we can't find any previous
	     * matches, so we're done!
	     */
	    if (idx == 0) {
		vdebug(10,LOG_OTHER,"did not find 0x%lx range fit!\n",idx,i);
		return NULL;
	    }
	}

	/* If we did not find a tightest bound containing @index, try
	 * the previous index to the current previous index.
	 */
	idx -= 1;
    }
}

/*
 * Find the range that is the widest range containing index.
 */
struct clf_range_data *clrange_find_loosest(clrange_t *clf,Word_t index,
					    struct array_list **al_saveptr) {
    PWord_t pv;
    struct array_list *alist;
    struct clf_range_data *crd;
    int contains = 0;
    Word_t idx;

    if (!clf || !*clf)
	return NULL;

    /* Find the index that is previous to index; if that range contains
     * us and has a containing range, follow its containing_range chain
     * on up; otherwise return that range.
     */
    idx = index;
    JLL(pv,*clf,idx);
    if (pv == NULL || pv == PJERR) 
	return NULL;

    vdebug(10,LOG_OTHER,"found 0x%lx previous to 0x%lx\n",idx,index);
    alist = (struct array_list *)*pv;
    crd = crd_get_tightest(alist,index,index,&contains);
    if (crd) {
	vdebug(10,LOG_OTHER,"found crd (0x%lx,0x%lx) (contains is %d)\n",
	       CLRANGE_START(crd),CLRANGE_END(crd),contains);
    }
    else {
	verror("did not find a tightest range for 0x%lx even though we should have!\n",index);
	return NULL;
    }
    if (contains && crd->containing_range) {
	crd = crd_top_containing_range(crd);
	vdebug(10,LOG_OTHER,"found top containing crd (0x%lx,0x%lx)\n",
	       CLRANGE_START(crd),CLRANGE_END(crd));
    }

    if (al_saveptr)
	*al_saveptr = alist;

    return crd;
}

struct clf_range_data *clrange_find_next_loosest(clrange_t *clf,Word_t index,
						 struct array_list **al_saveptr) {
    struct array_list *alist;
    Word_t idx;
    struct array_list *prev_alist = NULL;
    struct clf_range_data *prev_crd = NULL;
    struct clf_range_data *crd;
    int contains;

    if (!clf || !*clf)
	return NULL;

    /* 
     * Find the loosest range that contains index.  If there isn't one,
     * just try to find the next range beyond index.
     */
    prev_crd = clrange_find_loosest(clf,index,&prev_alist);
    if (!prev_crd) 
	idx = index + 1;
    else 
	idx = CLRANGE_END(prev_crd);

    /*
     * Find the next index, find the loosest range at that index, and
     * return.
     */
    alist = clrange_find_next_inc(clf,idx);
    if (!alist)
	return NULL;

    crd = crd_get_loosest(alist,index,index,&contains);

    return crd;
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
    int bytes_freed;

    if (!clf)
	return;

    /* This stinks -- we have to free each element one by one. */
    while (1) {
	index = 0;
	JLF(pv,clf,index);
	if (pv == NULL)
	    break;
	array_list_deep_free((struct array_list *)*pv);
	*pv = (Word_t)NULL;
	JLD(rci,clf,index);
    }

    /*
     * Man page says bytes_freed should be Word_t (unsigned), but
     * compiler disagrees!
     */
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
    int bytes_freed;

    if (!clf)
	return;

    /* This stinks -- we have to free each element one by one. */
    while (1) {
	index = 0;
	JLF(pv,clf,index);
	if (pv == NULL)
	    break;
	array_list_free((struct array_list *)*pv);
	*pv = (Word_t)NULL;
	JLD(rci,clf,index);
    }

    /*
     * Man page says bytes_freed should be Word_t (unsigned), but
     * compiler disagrees!
     */
    JLFA(bytes_freed,clf);
}
