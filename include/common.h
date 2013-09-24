/*
 * Copyright (c) 2011, 2012, 2013 The University of Utah
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

#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdint.h>
#include <inttypes.h>

typedef enum {
    RESULT_SUCCESS = 0,
    RESULT_ERROR = 1,
    RESULT_ABORT = 2,
} result_t;

/*
 * For now, thread ids are a 32-bit int.  This is enough, for instance,
 * to do TIDs on Linux (because pids on 64-bit are still int32_ts. Note
 * that we have reserved INT32_MAX as our "global" identifier.
 */
typedef int32_t tid_t;
#define PRIiTID PRIi32

/* Might have to split these out into platform-specific stuff later; for
 * now, just make them big enough for anything.
 *
 * Also, we only support debugging 32-bit targets on a 32-bit host.  We
 * support 32-bit targets on a 64-bit host, but not the reverse for
 * now.  That case would only have meaning if we wanted to investigate a
 * non-live target (i.e., a 64-bit memory dump) on a 32-bit host.  Even
 * then, we would still need all the 64-bit debuginfo files... and they
 * wouldn't be likely to be on a 32-bit host.  SO, for now, we don't
 * support this case.
 */
#if __WORDSIZE == 64
typedef uint64_t ADDR;
typedef int64_t OFFSET;
typedef uint64_t REGVAL;
#define PRIxADDR PRIx64
#define PRIuADDR PRIu64
#define PRIiOFFSET PRIi64
#define PRIxOFFSET PRIx64
#define PRIxREGVAL PRIx64
#define PRIuREGVAL PRIu64
#define ADDRMAX UINT64_MAX
#define OFFSETMAX UINT64_MAX
#else
typedef uint32_t ADDR;
typedef int32_t OFFSET;
typedef uint32_t REGVAL;
#define PRIxADDR PRIx32
#define PRIuADDR PRIu32
#define PRIiOFFSET PRIi32
#define PRIxOFFSET PRIx32
#define PRIxREGVAL PRIx32
#define PRIuREGVAL PRIu32
#define ADDRMAX UINT32_MAX
#define OFFSETMAX UINT32_MAX
#endif

#ifndef ptr_t
#define ptr_t unsigned long int
#endif

/*
 * Define a "numeric" type; size should be the largest int for any
 * target, for now.  Later we might need something more
 * flexible... sigh.
 */
typedef int64_t num_t;
typedef uint64_t unum_t;
#define PRIuNUM PRIu64
#define PRIiNUM PRIi64
#define PRIxNUM PRIx64

typedef int8_t REG;
#define PRIiREG PRIi8

typedef enum {
    CREG_AX = 0,
    CREG_BX,
    CREG_CX,
    CREG_DX,
    CREG_DI,
    CREG_SI,
    CREG_BP,
    CREG_SP,
    CREG_IP,
    CREG_FLAGS,
    CREG_CS,
    CREG_SS,
    CREG_DS,
    CREG_ES,
    CREG_FS,
    CREG_GS,
} common_reg_t;
#define COMMON_REG_COUNT 16

/*
 * We use small offsets for DWARF offset addrs.  Saves mem in symbol
 * structures, which is very important.
 */
typedef int32_t SMOFFSET;
#define PRIiSMOFFSET PRIi32
#define PRIxSMOFFSET PRIx32

#define DATA_BIG_ENDIAN 0
#define DATA_LITTLE_ENDIAN 1

#define PROT_READ         0x1
#define PROT_WRITE        0x2
#define PROT_EXEC         0x4
#define PROT_SHARED       0x8

/*
 * Reference count stuff.
 *
 * The way this stuff works is a bit unfortunate.  I tried to hide it
 * from the users, so that what they think they get is a simple
 * lookup/release interface.  They *can* call RHOLD themselves, but they
 * should not need to if they go through the public functions in each
 * sub-library that state that they claim locks for the object they are
 * returning (i.e., some symbol lookup functions).
 *
 * So, it's good for users.  It's not so good for debugging refcnt
 * leaks; see below!
 */
typedef uint32_t REFCNT;

/*
 * Reference count debugging is hard because of the ways we use it.  We
 * try to keep the use entirely internal, and hidden from user, but what
 * this means is that we inevitably take locks on behalf of the user.
 * This means we don't have good tracking for lock owners (we don't know
 * the address of the "owning" object).  So, when the user releases a
 * lock on an object, we do not know who the "owning" object was.  For
 * these cases, we just keep a separate count, so we can determine in a
 * rough sense whether the leak was internal or external.
 *
 * HOWEVER, this means that *inside* our libraries, we must not call the
 * functions that RHOLD on the user's behalf.  We must act more
 * manually.  In this way, we can know that our internal refcnting is
 * sound, which is what we're really after -- because then both owners
 * and their referents can be tracked.  We can fix the user-side refcnt
 * debugging more later if we ever care.  But that is small potatoes.
 *
 * Also, inside our libraries, we must never call (objtype)_release
 * functions!  Those are intended for external use only.  We must always
 * call RPUT* directly.
 *
 * XXX: need to change user-API calls to a _lookup()/_release()
 * paradigm.  This will make the REFCNT stuff more obvious to them.
 * Basically, any call that ends in _lookup() needs to have a )release()
 * done on _lookup()'s return value.
 *
 *
 * NB: this is important!  Objects cannot reference each other; such
 * objects may not get deleted since we do maintain data structures that
 * contain any such object (i.e., a referenced object may not be on some
 * global hashtable, but one it references may not be -- it may be
 * buried in some symtab tree -- and if we deleted the top of that tree,
 * we'll be left with a dangling ref).  To solve this, we would need
 * some library-wide, global, type-aware reftab -- more memory usage.
 *
 * So, avoid it for now by only allowing top-down refs.  This means that
 * objects that hold refs to lower ones must clear the lower objects'
 * backrefs to them.  This may or not break the object model, of course.
 * For now, it's ok for the way this library uses objects.  The real
 * problem is symbol tables -- it is very possible that the symtab an
 * object is on will go away during debugfile free operations.  But, if
 * we always only partially free debugfiles by freeing root symtabs,
 * this problem won't matter.  As a matter of fact, we already don't do
 * partial free (only incremental load), so this doesn't matter.  Just
 * notes for the future...
 *
 * Ok, unfortunately, the future is now.
 *
 * In early versions of this library, we tried to get away with keeping
 * non-cyclic, hierarchical parent->child refs only.  But unfortunately,
 * some of our objects keep refs to the parent and operations on them
 * end up requiring a parent deref.  So we have to make sure that the
 * parent does not get dealloc'd until its children are gone.  But, this
 * brings up the cyclic ref problem.  If an object gets unlinked from
 * our global data structures, and it is no longer reachable but still
 * need to be freed, we still have to know it needs to be freed -- but
 * even this situation will never be arrived at for two objects that
 * hold each other.  One must hold weakly to the other, so we know when
 * it is safe to deallocate the first.
 *
 * Imagine the scenario where symbols hold symbols/symtabs, are on
 * symtabs, which are on either debugfiles or binfiles.  Symbols hold
 * symtabs/symbols; symtabs hold debugfiles/binfiles/symbols; debugfiles
 * hold symtabs.
 *
 * Here's what we do.  We keep two counts for each object.  Strong refs
 * are the parent->child refs; weak refs are the child->parent refs.
 * Basically, the idea is that when any object's strong ref counter
 * becomes 0, we can start deallocating the object.  Deallocation must
 * first 1) remove itself from all global data structures, such as
 * caches, and 2) release refs to any of its children (any objects it
 * has strong refs to), and remove them from its structures IFF they are
 * freed themselves.  If all children are freed, and there are no more
 * weak refs to the object, we can finish freeing it (we need both
 * constraints to know which children we must save and not remove from
 * our object's data structures); else we must place the object on a
 * global "to-free" hashtable.  Then, when weak refs are released, the
 * object that was weakly held must be checked to see if it can be
 * released.  That's how we will do this.  This frees us from having to
 * track ref holders.
 */

#ifdef REF_DEBUG

#include <glib.h>
/*
 * NB: this table never gets freed unless you call REF_DEBUG_REPORT_FINISH().
 *
 * Oh, and this is NOT thread-safe, obviously.  Make it so if you need it...
 */

/* This one holds data for distinct obj/owner pairs. */
extern GHashTable *greftab;
/* This one holds data for self-owning objects (i.e., user-inspired refs). */
extern GHashTable *grefstab;

/* This one holds data for distinct obj/owner pairs. */
extern GHashTable *grefwtab;
/* This one holds data for self-owning objects (i.e., user-inspired refs). */
extern GHashTable *grefwstab;

#define RHOLD(x,hx)							\
    do {								\
        GHashTable *htab;						\
	char *buf;							\
	unsigned int count;						\
	void *_hx = (hx);						\
									\
        ++((x)->refcnt);						\
									\
	/* If self-ref, just save by caller function address. */	\
	if ((x) == _hx) {						\
	    _hx = (void *)__builtin_return_address(1);			\
	    fprintf(stderr,"REFDEBUG: hold %p,%p (%d) (self)\n",	\
		    (x),_hx,(x)->refcnt);				\
									\
	    if (unlikely(!grefstab)) {					\
		grefstab = g_hash_table_new(g_direct_hash,g_direct_equal); \
		htab = g_hash_table_new_full(g_direct_hash,g_direct_equal, \
					     NULL,NULL);		\
		g_hash_table_insert(grefstab,(gpointer)(x),htab);	\
	    }								\
	    else if (!(htab = (GHashTable *)g_hash_table_lookup(grefstab,(x)))) { \
		htab = g_hash_table_new_full(g_direct_hash,g_direct_equal, \
					     NULL,NULL);		\
		g_hash_table_insert(grefstab,(gpointer)(x),htab);	\
	    }								\
	    count = (unsigned int)(ptr_t)g_hash_table_lookup(htab,(gpointer)_hx); \
	    ++count;							\
	    g_hash_table_insert(htab,(gpointer)_hx,(void *)(ptr_t)count); \
	    /* XXX: we should track more than caller addr? */		\
	}								\
	else {								\
	    fprintf(stderr,"REFDEBUG: hold %p,%p (%d)\n",		\
		    (x),_hx,(x)->refcnt);				\
									\
	    if (unlikely(!greftab)) {					\
		greftab = g_hash_table_new(g_direct_hash,g_direct_equal); \
		htab = g_hash_table_new_full(g_direct_hash,g_direct_equal, \
					     NULL,NULL);		\
		g_hash_table_insert(greftab,(gpointer)(x),htab);	\
	    }								\
	    else if (!(htab = (GHashTable *)g_hash_table_lookup(greftab,(x)))) { \
		htab = g_hash_table_new_full(g_direct_hash,g_direct_equal, \
					     NULL,free);		\
		g_hash_table_insert(greftab,(gpointer)(x),htab);	\
	    }								\
									\
	    buf = malloc(sizeof(__FUNCTION__)+sizeof(__LINE__)+1+1);	\
	    snprintf(buf,sizeof(__FUNCTION__)+sizeof(__LINE__)+1+1,	\
		     "%s:%d",__FUNCTION__,__LINE__);			\
	    g_hash_table_insert(htab,(gpointer)_hx,buf);		\
	}								\
    } while (0);
#define RHOLDW(x,hx)							\
    do {								\
        GHashTable *htab;						\
	char *buf;							\
	unsigned int count;						\
	void *_hx = (hx);						\
									\
        ++((x)->refcntw);						\
									\
	/* If self-ref, just save by caller function address. */	\
	if ((x) == _hx) {						\
	    _hx = (void *)__builtin_return_address(1);			\
	    fprintf(stderr,"REFDEBUG: holdw %p,%p (%d) (self)\n",	\
		    (x),_hx,(x)->refcnt);				\
									\
	    if (unlikely(!grefwstab)) {					\
		grefwstab = g_hash_table_new(g_direct_hash,g_direct_equal); \
		htab = g_hash_table_new_full(g_direct_hash,g_direct_equal, \
					     NULL,NULL);		\
		g_hash_table_insert(grefwstab,(gpointer)(x),htab);	\
	    }								\
	    else if (!(htab = (GHashTable *)g_hash_table_lookup(grefwstab,(x)))) { \
		htab = g_hash_table_new_full(g_direct_hash,g_direct_equal, \
					     NULL,NULL);		\
		g_hash_table_insert(grefwstab,(gpointer)(x),htab);	\
	    }								\
	    count = (unsigned int)g_hash_table_lookup(htab,(gpointer)_hx); \
	    ++count;							\
	    g_hash_table_insert(htab,(gpointer)_hx,(void *)(ptr_t)count); \
	    /* XXX: we should track more than caller addr? */		\
	}								\
	else {								\
	    fprintf(stderr,"REFDEBUG: holdw %p,%p (%d)\n",		\
		    (x),_hx,(x)->refcnt);				\
									\
	    if (unlikely(!grefwtab)) {					\
		grefwtab = g_hash_table_new(g_direct_hash,g_direct_equal); \
		htab = g_hash_table_new_full(g_direct_hash,g_direct_equal, \
					     NULL,NULL);		\
		g_hash_table_insert(grefwtab,(gpointer)(x),htab);	\
	    }								\
	    else if (!(htab = (GHashTable *)g_hash_table_lookup(grefwtab,(x)))) { \
		htab = g_hash_table_new_full(g_direct_hash,g_direct_equal, \
					     NULL,free);		\
		g_hash_table_insert(grefwtab,(gpointer)(x),htab);	\
	    }								\
									\
	    buf = malloc(sizeof(__FUNCTION__)+sizeof(__LINE__)+1+1);	\
	    snprintf(buf,sizeof(__FUNCTION__)+sizeof(__LINE__)+1+1,	\
		     "%s:%d",__FUNCTION__,__LINE__);			\
	    g_hash_table_insert(htab,(gpointer)_hx,buf);		\
	}								\
    } while (0);
#define RPUT(x,objtype,hx,rc)						\
    do {								\
        typeof(x) _x = (x);						\
        void *_hx = (hx);						\
        GHashTable *htab;						\
	/*unsigned int count;					*/	\
									\
	/* if ((x)->refcnt == 0) */					\
	    /* asm("int $3"); */					\
									\
	(rc) = (--((x)->refcnt) == 0)					\
	            ? objtype ## _free(x,0) : ((x)->refcnt);		\
									\
	if (_x == _hx) {						\
	    if (!grefstab)						\
		break;							\
									\
	    fprintf(stderr,"REFDEBUG: put %p,%p (%d) (self)\n",(x),_hx,(rc)); \
									\
	    htab = (GHashTable *)g_hash_table_lookup(grefstab,_x);	\
	    if (!htab)							\
		break;							\
	    /* Can't track holder; just nuke hashtable. */		\
	    if ((rc) == 0) {						\
		g_hash_table_destroy(htab);				\
		g_hash_table_remove(grefstab,_x);			\
	    }								\
	    /*count = (unsigned int)g_hash_table_remove(htab,_hx); */	\
	    /*if (--count == 0) {				*/	\
	    /*    if (g_hash_table_size(htab) == 0)		*/	\
	    /*	    g_hash_table_destroy(htab);			*/	\
	    /*}							*/	\
	    /*else						*/	\
	    /*	  g_hash_table_insert(htab,_hx,(gpointer)(ptr_t)count); */ \
	}								\
	else {								\
	    if (!greftab)						\
		break;							\
									\
	    fprintf(stderr,"REFDEBUG: put %p,%p (%d)\n",(x),_hx,(rc));	\
									\
	    htab = (GHashTable *)g_hash_table_lookup(greftab,_x);	\
	    if (!htab)							\
		break;							\
	    g_hash_table_remove(htab,_hx);				\
	    if (g_hash_table_size(htab) == 0) {				\
		g_hash_table_destroy(htab);				\
		g_hash_table_remove(greftab,_x);			\
	    }								\
	}								\
    } while (0);
#define RPUTW(x,objtype,hx,rc)						\
    do {								\
        typeof(x) _x = (x);						\
        void *_hx = (hx);						\
        GHashTable *htab;						\
									\
	/* if ((x)->refcntw == 0) */					\
	    /* asm("int $3");  */					\
									\
	(rc) = (--((x)->refcntw) == 0)					\
	            ? objtype ## _free(x,0) : ((x)->refcntw);		\
									\
	if (_x == _hx) {						\
	    if (!grefwstab)						\
		break;							\
									\
	    fprintf(stderr,"REFDEBUG: putw %p,%p (%d) (self)\n",(x),_hx,(rc)); \
									\
	    htab = (GHashTable *)g_hash_table_lookup(grefwstab,_x);	\
	    if (!htab)							\
		break;							\
	    /* Can't track holder; just nuke hashtable. */		\
	    if ((rc) == 0) {						\
		g_hash_table_destroy(htab);				\
		g_hash_table_remove(grefwstab,_x);			\
	    }								\
	}								\
	else {								\
	    if (!grefwtab)						\
		break;							\
									\
	    fprintf(stderr,"REFDEBUG: putw %p,%p (%d)\n",(x),_hx,(rc));	\
									\
	    htab = (GHashTable *)g_hash_table_lookup(grefwtab,_x);	\
	    if (!htab)							\
		break;							\
	    g_hash_table_remove(htab,_hx);				\
	    if (g_hash_table_size(htab) == 0) {				\
		g_hash_table_destroy(htab);				\
		g_hash_table_remove(grefwtab,_x);			\
	    }								\
	}								\
    } while (0);
/*
 * Nobody should use RPUTNF/RPUTFF at all, ever -- it means you are not
 * using refcnts appropriately.  Do not enable them without talking to
 * David, and you better have a darn good reason.
 */
//#if 0
#define RPUTFF(x,objtype,hx,rc)						\
    do {								\
        typeof(x) _x = (x);						\
        void *_hx = (hx);						\
        GHashTable *htab;						\
	unsigned int count;						\
									\
	(rc) = (--((x)->refcnt) == 0)					\
	            ? objtype ## _free(x,1) : objtype ## _free(x,1);	\
									\
	if (_x == _hx) {						\
	    if (!grefstab)						\
		break;							\
									\
	    fprintf(stderr,"REFDEBUG: putf %p,%p (%d) (self)\n",(x),_hx,(rc)); \
									\
	    htab = (GHashTable *)g_hash_table_lookup(grefstab,_x);	\
	    if (!htab)							\
		break;							\
	    count = (unsigned int)g_hash_table_remove(htab,_hx);	\
	    if (--count == 0) {						\
	        if (g_hash_table_size(htab) == 0)			\
		    g_hash_table_destroy(htab);				\
	    }								\
	    else							\
		g_hash_table_insert(htab,_hx,(gpointer)(ptr_t)count);	\
	}								\
	else {								\
	    if (!greftab)						\
		break;							\
									\
	    fprintf(stderr,"REFDEBUG: putf %p,%p (%d)\n",(x),_hx,(rc)); \
									\
	    htab = (GHashTable *)g_hash_table_lookup(greftab,_x);	\
	    if (!htab)							\
		break;							\
	    g_hash_table_remove(htab,_hx);				\
	    if (g_hash_table_size(htab) == 0) {				\
		g_hash_table_destroy(htab);				\
		g_hash_table_remove(greftab,_x);			\
	    }								\
	}								\
    } while (0);
#define RPUTNF(x,hx,rc)							\
    do {								\
        typeof(x) _x = (x);						\
        void *_hx = (hx);						\
        GHashTable *htab;						\
	unsigned int count;						\
									\
	(rc) = (--((x)->refcnt));					\
									\
	if (_x == _hx) {						\
	    if (!grefstab)						\
		break;							\
									\
	    fprintf(stderr,"REFDEBUG: putn %p,%p (%d) (self)\n",(x),_hx,(rc)); \
									\
	    htab = (GHashTable *)g_hash_table_lookup(grefstab,_x);	\
	    if (!htab)							\
		break;							\
	    count = (unsigned int)g_hash_table_remove(htab,_hx);	\
	    if (--count == 0) {						\
	        if (g_hash_table_size(htab) == 0)			\
		    g_hash_table_destroy(htab);				\
	    }								\
	    else							\
		g_hash_table_insert(htab,_hx,(gpointer)(ptr_t)count);	\
	}								\
	else {								\
	    if (!greftab)						\
		break;							\
									\
	    fprintf(stderr,"REFDEBUG: putn %p,%p (%d)\n",(x),_hx,(rc));	\
									\
	    htab = (GHashTable *)g_hash_table_lookup(greftab,_x);	\
	    if (!htab)							\
		break;							\
	    g_hash_table_remove(htab,_hx);				\
	    if (g_hash_table_size(htab) == 0) {				\
		g_hash_table_destroy(htab);				\
		g_hash_table_remove(greftab,_x);			\
	    }								\
	}								\
    } while (0);
//#endif /* 0 */
/*
 * You should call this when your main program terminates.
 */
#define REF_DEBUG_REPORT_FINISH()					\
    do {								\
        GHashTableIter iter,iter2;					\
	GHashTable *htab;						\
	void *_x,*_hx;							\
	char *info;							\
	unsigned int count;						\
	if (greftab) {							\
	    g_hash_table_iter_init(&iter,greftab);			\
	    while (g_hash_table_iter_next(&iter,&_x,(gpointer)&htab)) {	\
		fprintf(stderr,"REFDEBUG: %d refs held for %p :\n",	\
			g_hash_table_size(htab),_x);			\
		g_hash_table_iter_init(&iter2,htab);			\
		while (g_hash_table_iter_next(&iter2,&_hx,(gpointer)&info)) { \
		    fprintf(stderr,"    %p held %p : %s\n",		\
			    _hx,_x,info);				\
		    g_hash_table_iter_remove(&iter2);			\
		}							\
		g_hash_table_destroy(htab);				\
									\
		/* asm("int $3"); */					\
	    }								\
	    g_hash_table_destroy(greftab);				\
	    greftab = NULL;						\
	}								\
	if (grefstab) {							\
	    g_hash_table_iter_init(&iter,grefstab);			\
	    while (g_hash_table_iter_next(&iter,&_x,(gpointer)&htab)) {	\
		fprintf(stderr,"REFDEBUG: %d refs self-held for %p :\n", \
			g_hash_table_size(htab),_x);			\
		g_hash_table_iter_init(&iter2,htab);			\
		while (g_hash_table_iter_next(&iter2,&_hx,(gpointer)&info)) { \
		    count = (unsigned int)(ptr_t)info;			\
		    fprintf(stderr,"    %p self-held %p : %d\n",	\
			    _hx,_x,count);				\
		    g_hash_table_iter_remove(&iter2);			\
		}							\
		g_hash_table_destroy(htab);				\
									\
		/* asm("int $3"); */					\
	    }								\
	    g_hash_table_destroy(grefstab);				\
	    grefstab = NULL;						\
	}								\
	if (grefwtab) {							\
	    g_hash_table_iter_init(&iter,grefwtab);			\
	    while (g_hash_table_iter_next(&iter,&_x,(gpointer)&htab)) {	\
		fprintf(stderr,"REFDEBUG: %d weak refs held for %p :\n", \
			g_hash_table_size(htab),_x);			\
		g_hash_table_iter_init(&iter2,htab);			\
		while (g_hash_table_iter_next(&iter2,&_hx,(gpointer)&info)) { \
		    fprintf(stderr,"    %p weakly held %p : %s\n",	\
			    _hx,_x,info);				\
		    g_hash_table_iter_remove(&iter2);			\
		}							\
		g_hash_table_destroy(htab);				\
									\
		/* asm("int $3"); */					\
	    }								\
	    g_hash_table_destroy(grefwtab);				\
	    grefwtab = NULL;						\
	}								\
	if (grefwstab) {						\
	    g_hash_table_iter_init(&iter,grefwstab);			\
	    while (g_hash_table_iter_next(&iter,&_x,(gpointer)&htab)) {	\
		fprintf(stderr,"REFDEBUG: %d weak refs self-held for %p :\n", \
			g_hash_table_size(htab),_x);			\
		g_hash_table_iter_init(&iter2,htab);			\
		while (g_hash_table_iter_next(&iter2,&_hx,(gpointer)&info)) { \
		    fprintf(stderr,"    %p weakly self-held %p : %s\n",	\
			    _hx,_x,info);				\
		    g_hash_table_iter_remove(&iter2);			\
		}							\
		g_hash_table_destroy(htab);				\
									\
		/* asm("int $3"); */					\
	    }								\
	    g_hash_table_destroy(grefwstab);				\
	    grefwstab = NULL;						\
	}								\
    } while (0);
#else
#define RHOLD(x,hx)          ++((x)->refcnt)
#define RHOLDW(x,hx)         ++((x)->refcntw)
#define RPUT(x,objtype,hx,rc)  ((rc) = (--((x)->refcnt) == 0)	\
				           ? objtype ## _free(x,0) \
				           : (x)->refcnt); \
                               (rc) += 0
#define RPUTFF(x,objtype,hx,rc) ((rc) = (--((x)->refcnt) == 0)	\
	                                     ? objtype ## _free(x,1) \
	                                     : objtype ## _free(x,1)
#define RPUTNF(x,hx,rc)         ((rc) = (--((x)->refcnt)))

#define REF_DEBUG_REPORT_FINISH() (void)
#endif

#endif /* __COMMON_H__ */
