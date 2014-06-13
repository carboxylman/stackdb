/*
 * Copyright (c) 2014 The University of Utah
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

#include "config.h"
#include <sys/mman.h>
#include "common.h"
#include "log.h"
#include "clfit.h"
#include "memcache.h"
#include "glib.h"

/*
 * Local prototypes.
 */
static void __memcache_clrangesimple_dtor(ADDR start,ADDR end,void *data);

struct memcache *memcache_create(unsigned long int max_v2p,
				 unsigned long int max_mmap_size,
				 memcache_tag_priv_dtor pdtor) {
    struct memcache *retval;

    retval = (struct memcache *)calloc(1,sizeof(*retval));
    retval->max_v2p = max_v2p;
    retval->max_mmap_size = max_mmap_size;
    retval->current_mmap_size = 0;
    retval->cache = g_hash_table_new_full(g_direct_hash,g_direct_equal,
					  NULL,NULL);
    retval->tag_priv_dtor = pdtor;

    return retval;
}

void memcache_destroy(struct memcache *memcache) {
    GHashTableIter iter;
    gpointer kp,vp;
    struct memcache_tag_entry *mte;

    g_hash_table_iter_init(&iter,memcache->cache);
    while (g_hash_table_iter_next(&iter,&kp,&vp)) {
	mte = (struct memcache_tag_entry *)vp;
	memcache_invalidate_all_v2p(memcache,(ADDR)kp);
	memcache_invalidate_all_mmap(memcache,(ADDR)kp);
	g_hash_table_destroy(mte->v2p_cache);

	clrangesimple_free(mte->mmap_cache_p,__memcache_clrangesimple_dtor);
	mte->mmap_cache_p = clrangesimple_create();
	clrangesimple_free(mte->mmap_cache_v,__memcache_clrangesimple_dtor);
	mte->mmap_cache_v = clrangesimple_create();

	if (memcache->tag_priv_dtor)
	    memcache->tag_priv_dtor((ADDR)kp,mte->priv);
	free(mte);
	g_hash_table_iter_remove(&iter);
    }

    g_hash_table_destroy(memcache->cache);
    free(memcache);
}

int memcache_invalidate_all_v2p(struct memcache *memcache,ADDR tag) {
    GHashTableIter iter;
    gpointer kp,vp;
    struct memcache_tag_entry *mte;

    mte = (struct memcache_tag_entry *) \
	g_hash_table_lookup(memcache->cache,(gpointer)tag);
    if (!mte)
	return 0;

    g_hash_table_iter_init(&iter,mte->v2p_cache);
    while (g_hash_table_iter_next(&iter,&kp,&vp)) {
	free(vp);
	g_hash_table_iter_remove(&iter);
    }

    return 0;
}

static void __memcache_clrangesimple_dtor(ADDR start,ADDR end,void *data) {
    struct memcache_mmap_entry *mme;

    mme = (struct memcache_mmap_entry *)data;

    munmap(mme->mem,mme->mem_len);

    vdebug(8,LA_TARGET,LF_MEMCACHE,
	   "munmap(0x%p,%lu) (0x%"PRIxADDR",0x%"PRIxADDR")\n",
	   mme->mem,mme->mem_len,start,end);

    free(mme);
}

int memcache_invalidate_all_mmap(struct memcache *memcache,ADDR tag) {
    struct memcache_tag_entry *mte;

    mte = (struct memcache_tag_entry *) \
	g_hash_table_lookup(memcache->cache,(gpointer)tag);
    if (!mte)
	return 0;

    clrangesimple_free(mte->mmap_cache_p,__memcache_clrangesimple_dtor);
    mte->mmap_cache_p = clrangesimple_create();
    clrangesimple_free(mte->mmap_cache_v,__memcache_clrangesimple_dtor);
    mte->mmap_cache_v = clrangesimple_create();

    return 0;
}

int memcache_invalidate_all(struct memcache *memcache) {
    GHashTableIter iter;
    gpointer kp;

    g_hash_table_iter_init(&iter,memcache->cache);
    while (g_hash_table_iter_next(&iter,&kp,NULL)) {
	memcache_invalidate_all_v2p(memcache,(ADDR)kp);
	memcache_invalidate_all_mmap(memcache,(ADDR)kp);
    }

    return 0;
}

struct __clrs_foreach_inc_ticks_data {
    unsigned int new_ticks;
    unsigned int max_unused_ticks;
    ADDR max_unused_ticks_addr;
};

int __memcache_clrangesimple_foreach_inc_ticks(Word_t start,Word_t end,void *data,
					       void *hpriv) {
    struct __clrs_foreach_inc_ticks_data *d =
	(struct __clrs_foreach_inc_ticks_data *)hpriv;
    struct memcache_mmap_entry *mme = (struct memcache_mmap_entry *)data;

    mme->unused_ticks += d->new_ticks;
    if (mme->unused_ticks > d->max_unused_ticks) {
	d->max_unused_ticks = mme->unused_ticks;
	d->max_unused_ticks_addr = start;
    }

    return 0;
}

void memcache_inc_ticks(struct memcache *memcache,unsigned int new_ticks) {
    GHashTableIter iter,iter2;
    gpointer vp,kp2,vp2;
    ADDR vaddr;
    struct memcache_tag_entry *mte;
    struct memcache_v2p_entry *mve;
    ADDR oldest;
    unsigned int ticks;
    struct __clrs_foreach_inc_ticks_data d;

    g_hash_table_iter_init(&iter,memcache->cache);
    while (g_hash_table_iter_next(&iter,NULL,&vp)) {
	mte = (struct memcache_tag_entry *)vp;

	/*
	 * Use ADDRMAX as our magic value because mmaps only happen at
	 * page boundaries, and anything ending in 0xfff is not a page
	 * boundary, basically.  And nobody has < 4096B pages.
	 */
	oldest = ADDRMAX;
	ticks = 0;
	g_hash_table_iter_init(&iter2,mte->v2p_cache);
	while (g_hash_table_iter_next(&iter2,&kp2,&vp2)) {
	    vaddr = (ADDR)kp2;
	    mve = (struct memcache_v2p_entry *)vp2;

	    mve->unused_ticks += new_ticks;
	    if (mve->unused_ticks > ticks) {
		ticks = mve->unused_ticks;
		oldest = vaddr;
	    }
	}
	mte->oldest_v2p = oldest;

	d.new_ticks = new_ticks;
	d.max_unused_ticks = 0;
	d.max_unused_ticks_addr = ADDRMAX;
	clrangesimple_foreach(mte->mmap_cache_p,
			      __memcache_clrangesimple_foreach_inc_ticks,
			      &d);
	mte->oldest_mmap_p = d.max_unused_ticks_addr;

	d.new_ticks = new_ticks;
	d.max_unused_ticks = 0;
	d.max_unused_ticks_addr = ADDRMAX;
	clrangesimple_foreach(mte->mmap_cache_v,
			      __memcache_clrangesimple_foreach_inc_ticks,
			      &d);
	mte->oldest_mmap_v = d.max_unused_ticks_addr;
    }
}

int memcache_get_v2p(struct memcache *memcache,ADDR tag,ADDR va,
		     ADDR *pa,void **tag_priv) {
    struct memcache_tag_entry *mte;
    struct memcache_v2p_entry *mve;

    mte = (struct memcache_tag_entry *) \
	g_hash_table_lookup(memcache->cache,(gpointer)tag);
    if (!mte)
	return 1;

    mve = (struct memcache_v2p_entry *) \
	g_hash_table_lookup(mte->v2p_cache,(gpointer)va);
    if (!mve)
	return 1;

    /* Found it! */
    vdebug(8,LA_TARGET,LF_MEMCACHE,
	   "CACHE HIT: v 0x%"PRIxADDR" -> p 0x%"PRIxADDR" (tag 0x%"PRIxADDR")\n",
	   va,mve->pa,tag);

    mve->unused_ticks = 0;
    if (pa)
	*pa = mve->pa;
    if (tag_priv)
	*tag_priv = mte->priv;
    return 0;
}

int memcache_get_mmap(struct memcache *memcache,ADDR tag,ADDR pa,
		      unsigned long int pa_len,memcache_flags_t flags,
		      ADDR *pa_start,OFFSET *pa_offset,
		      void **mem,unsigned long int *mem_len,void **tag_priv) {
    struct memcache_tag_entry *mte;
    ADDR __pa_start;
    void *data;
    struct memcache_mmap_entry *mme;
    int rc;
    clrangesimple_t *clr;

    mte = (struct memcache_tag_entry *) \
	g_hash_table_lookup(memcache->cache,(gpointer)tag);
    if (!mte)
	return 1;

    clr = &mte->mmap_cache_p;
    if (flags & MEMCACHE_VIRT)
	clr = &mte->mmap_cache_v;

    rc = clrangesimple_find(clr,pa,&__pa_start,NULL,&data);
    if (rc == -1 || rc == 1)
	return 1;

    /* Found it! */
    mme = (struct memcache_mmap_entry *)data;

    if ((mme->mem_len - (pa - __pa_start)) < pa_len) {
	vwarnopt(8,LA_TARGET,LF_MEMCACHE,
		 "CACHE MISS LEN %s 0x%"PRIxADDR" len %lu (for p 0x%"PRIxADDR"),"
		 " but not long enough (needed %lu; %lu short)!\n",
		 (flags & MEMCACHE_VIRT) ? "v" : "p",
		 __pa_start,mme->mem_len,pa,pa_len,
		 pa_len - (mme->mem_len - (pa - __pa_start)));
	return 1;
    }

    vdebug(8,LA_TARGET,LF_MEMCACHE,
	   "CACHE HIT %s 0x%"PRIxADDR" len %lu (at 0x%p) (for p 0x%"PRIxADDR" %lu)\n",
	   (flags & MEMCACHE_VIRT) ? "v" : "p",
	   __pa_start,mme->mem_len,mme->mem,pa,pa_len);

    mme->unused_ticks = 0;
    if (pa_start)
	*pa_start = __pa_start;
    if (pa_offset)
	*pa_offset = pa - __pa_start;
    if (mem)
	*mem = mme->mem;
    if (mem_len)
	*mem_len = mme->mem_len;
    if (tag_priv)
	*tag_priv = mte->priv;
    return 0;
}

static struct memcache_tag_entry *__memcache_mte_create(void *tag_priv) {
    struct memcache_tag_entry *mte;

    mte = (struct memcache_tag_entry *)calloc(1,sizeof(*mte));
    mte->priv = tag_priv;
    mte->oldest_v2p = ADDRMAX;
    mte->oldest_mmap_p = ADDRMAX;
    mte->oldest_mmap_v = ADDRMAX;
    mte->v2p_cache = g_hash_table_new_full(g_direct_hash,g_direct_equal,
					   NULL,NULL);
    mte->mmap_cache_p = clrangesimple_create();
    mte->mmap_cache_v = clrangesimple_create();

    return mte;
}

int memcache_set_tag_priv(struct memcache *memcache,ADDR tag,void *tag_priv) {
    struct memcache_tag_entry *mte;

    mte = (struct memcache_tag_entry *) \
	g_hash_table_lookup(memcache->cache,(gpointer)tag);
    if (!mte) {
	mte = __memcache_mte_create(tag_priv);
	g_hash_table_insert(memcache->cache,(gpointer)tag,mte);
    }

    mte->priv = tag_priv;

    return 0;
}

int memcache_set_v2p(struct memcache *memcache,ADDR tag,ADDR va,ADDR pa) {
    struct memcache_tag_entry *mte;
    struct memcache_v2p_entry *mve;

    mte = (struct memcache_tag_entry *) \
	g_hash_table_lookup(memcache->cache,(gpointer)tag);
    if (!mte) {
	mte = __memcache_mte_create(NULL);
	g_hash_table_insert(memcache->cache,(gpointer)tag,mte);
    }

    mve = (struct memcache_v2p_entry *) \
	g_hash_table_lookup(mte->v2p_cache,(gpointer)va);
    if (!mve) {
	mve = (struct memcache_v2p_entry *)calloc(1,sizeof(*mve));
	g_hash_table_insert(mte->v2p_cache,(gpointer)va,mve);
	vdebug(8,LA_TARGET,LF_MEMCACHE,
	       "CACHE ENTRY: v 0x%"PRIxADDR" -> p 0x%"PRIxADDR" (tag 0x%"PRIxADDR")\n",
	       va,pa,tag);
    }
    else {
	vdebug(8,LA_TARGET,LF_MEMCACHE,
	       "CACHE REPLACE: v 0x%"PRIxADDR", old p 0x%"PRIxADDR
	       " new p 0x%"PRIxADDR" (tag 0x%"PRIxADDR")\n",
	       va,mve->pa,pa,tag);
    }

    mve->unused_ticks = 0;
    mve->pa = pa;

    /*
     * XXX: deal with oldest_v2p and LRU...
     */

    return 0;
}

int memcache_set_mmap(struct memcache *memcache,ADDR tag,ADDR pa,
		      memcache_flags_t flags,
		      void *mem,unsigned long int mem_len) {
    struct memcache_tag_entry *mte;
    struct memcache_mmap_entry *mme;
    int rc;
    clrangesimple_t *clr;

    mte = (struct memcache_tag_entry *) \
	g_hash_table_lookup(memcache->cache,(gpointer)tag);
    if (!mte) {
	mte = __memcache_mte_create(NULL);
	g_hash_table_insert(memcache->cache,(gpointer)tag,mte);
    }

    mme = (struct memcache_mmap_entry *)calloc(1,sizeof(*mme));
    mme->mem = mem;
    mme->mem_len = mem_len;
    mme->unused_ticks = 0;

    clr = &mte->mmap_cache_p;
    if (flags & MEMCACHE_VIRT)
	clr = &mte->mmap_cache_v;

    rc = clrangesimple_add(clr,pa,pa + mem_len,mme);
    if (rc == -1) {
	vwarn("internal error; cannot cache mmap of %s 0x%"PRIxADDR" at 0x%p!\n",
	      (flags & MEMCACHE_VIRT) ? "v" : "p",pa,mem);
	free(mme);
	return -1;
    }
    else if (rc == 1) {
	vwarnopt(8,LA_TARGET,LF_MEMCACHE,
		 "cannot cache mmap of %s 0x%"PRIxADDR" at 0x%p; already used!\n",
		 (flags & MEMCACHE_VIRT) ? "v" : "p",pa,mem);
	free(mme);
	return 1;
    }

    vdebug(8,LA_TARGET,LF_MEMCACHE,
	   "CACHE ENTRY %s 0x%"PRIxADDR" len %lu tag 0x%"PRIxADDR" (at 0x%p)\n",
	   (flags & MEMCACHE_VIRT) ? "v" : "p",pa,mem_len,tag,mem);

    /*
     * XXX: deal with oldest_mmap and LRU...
     */

    return 0;
}
