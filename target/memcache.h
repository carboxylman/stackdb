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

#ifndef __MEMCACHE_H__
#define __MEMCACHE_H__

#include "config.h"
#include "glib.h"
#include "common.h"
#include "clfit.h"

/*
 * Conceptually, we might need/want to cache any of physical or virtual
 * memory page, or page ranges, depending on what kind of memory the
 * target supports.  We might want to tag it based on some kind of
 * thread/addrspace/region identifier, so we can quickly blow away parts
 * of the cache if a thread/addrspace/region goes away.
 *
 * Then, we also want to cache address translations; for now, start with
 * v2p.  Tag these with the same identifier as the mmap cache for now.
 *
 * I think we should do this via whatever ADDR-sized identifier the
 * target wants to use.  For an OS target, it would probably be the pgd.
 */

/*
 * NB: TAG_ANY is a wildcard tag for some functions; therefore, never
 * use it as a legitimate tag!
 */
#define MEMCACHE_TAG_ANY ADDRMAX

typedef void (*memcache_tag_priv_dtor)(ADDR tag,void *tag_priv);

typedef enum {
    MEMCACHE_PHYS = 1 << 0,
    MEMCACHE_VIRT = 1 << 1,
} memcache_flags_t;

struct memcache {
    unsigned long int max_v2p;
    unsigned long int max_mmap_size;
    unsigned long int current_mmap_size;
    GHashTable *cache;
    memcache_tag_priv_dtor tag_priv_dtor;
};

struct memcache_tag_entry {
    void *priv;
    GHashTable *v2p_cache;
    /*
     * For now, offer the option to cache either phys or virt mmaps.
     * The reason to do this is that sometimes a bulk mmap might be made
     * for a virt address, but of course, the mapped phys pages
     * underneath are 1) only good in that mapping, for that v2p
     * translation for that pgd; and 2)
     * because it's a single mmap, we can't benefit from selectively
     * uncaching only the virtual parts we're done with, and saving the
     * phys pages that are still valid.  So there seems to be little
     * point to only caching phys pages -- *IF YOU WANT* the benefits of
     * contiguously-mapped virtual address space!
     *
     * If you do not want contiguously-mapped vaddr space, then,
     * clearly, caching individual physical pages is *always* the way to
     * go... it offers the least need to remap.
     *
     * So let's at least offer users the option!  Which mmap cache they
     * get is controlled by the flags argument to the get|set_mmap
     * functions.
     */
    clrangesimple_t mmap_cache_p;
    clrangesimple_t mmap_cache_v;
    /*
     * Every time we increment ticks, we calculate the oldest entry.
     * Then it's ready for our LRU eviction.  We use ADDRMAX as the
     * magic value saying there is no "max" entry (i.e., there *is* no
     * entry :)).  This can happen if memcache_lru_evict_mmap has to
     * evict more than one (oldest) mapping, for instance.  It's a win
     * to keep these calculated only when we inc_ticks, though.  If we
     * need them and they're not available, we can calculate them
     * quickly.
     */
    ADDR oldest_v2p;
    ADDR oldest_mmap_p;
    ADDR oldest_mmap_v;
    unsigned int oldest_mmap_p_ticks;
    unsigned int oldest_mmap_v_ticks;
};

struct memcache_v2p_entry {
    //int used;
    unsigned int unused_ticks;
    ADDR pa;
};

struct memcache_mmap_entry {
    //int used;
    unsigned int unused_ticks;
    unsigned long int mem_len;
    void *mem;
    /*
     * For now, don't track dependent values -- because we can always
     * just use memcache_get to check and see if the tagged v2p exists,
     * and if pa is mmap'd or not.
     */
};

struct memcache *memcache_create(unsigned long int max_v2p,
				 unsigned long int max_mmap_size,
				 memcache_tag_priv_dtor pdtor);
void memcache_destroy(struct memcache *memcache);

int memcache_invalidate_all_v2p(struct memcache *memcache,ADDR tag);
int memcache_invalidate_all_mmap(struct memcache *memcache,ADDR tag);
int memcache_invalidate_all(struct memcache *memcache);

void memcache_inc_ticks(struct memcache *memcache,unsigned int new_ticks);

int memcache_get_v2p(struct memcache *memcache,ADDR tag,ADDR va,
		     ADDR *pa,void **tag_priv);
int memcache_get_mmap(struct memcache *memcache,ADDR tag,ADDR pa,
		      unsigned long int pa_len,memcache_flags_t flags,
		      ADDR *pa_start,OFFSET *pa_offset,
		      void **mem,unsigned long int *mem_len,void **tag_priv);

int memcache_set_tag_priv(struct memcache *memcache,ADDR tag,void *tag_priv);
int memcache_set_v2p(struct memcache *memcache,ADDR tag,ADDR va,ADDR pa);
int memcache_set_mmap(struct memcache *memcache,ADDR tag,ADDR pa,
		      memcache_flags_t flags,
		      void *mem,unsigned long int mem_len);

/*
 * A dumb little LRU evictor.  Just makes sure to evict (at least)
 * mem_len.  It doesn't try to evict smartly -- i.e., even if the oldest
 * is a big huge mmap and there's a slightly less-used smaller map right
 * there, we'll evict that anyway.  Also, for us, it might make more
 * sense to evict virt ranges rather than physical pages... but no :).
 * Return number of bytes evicted; might be less than requested if          
 * we couldn't find enough!
 */
unsigned long int memcache_lru_evict_mmap(struct memcache *memcache,ADDR tag,
					  memcache_flags_t flags,
					  unsigned long int mem_len);

#endif /* __MEMCACHE_H__ */
