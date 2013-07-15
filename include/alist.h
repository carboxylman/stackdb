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

#ifndef _ARRAY_LIST_H
#define _ARRAY_LIST_H

/**
 ** A very, very simple array list.  But, useful!
 **/

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <glib.h> 

struct array_list {
    int32_t len;
    int32_t alloc_len;
    void **list;
};

static inline struct array_list *array_list_create(int initsize) {
    struct array_list *list = \
	(struct array_list *)malloc(sizeof(struct array_list));
    memset(list,0,sizeof(struct array_list));
    if (initsize) {
	list->alloc_len = initsize;
	list->list = (void **)malloc(sizeof(void *)*initsize);
    }
    return list;
}

static inline struct array_list *array_list_init(struct array_list *list,
						 int initsize) {
    if (initsize) {
	list->alloc_len = initsize;
	list->list = (void **)malloc(sizeof(void *)*initsize);
    }
    return list;
}

static inline struct array_list *array_list_clone(struct array_list *oldlist,
						  int more) {
    struct array_list *newlist = \
	(struct array_list *)malloc(sizeof(struct array_list));
    memset(newlist,0,sizeof(struct array_list));
    if (oldlist)
	newlist->alloc_len = oldlist->len + more;
    else 
	newlist->alloc_len = more;
    newlist->list = (void **)malloc(sizeof(void *)*(newlist->alloc_len));
    if (oldlist && oldlist->len) {
	memcpy(newlist->list,oldlist->list,sizeof(void *)*(oldlist->len));
	newlist->len = oldlist->len;
    }
    return newlist;
}

static inline int32_t array_list_len(struct array_list *list) {
    if (!list)
	return 0;

    return list->len;
}

static inline int32_t array_list_alloc_len(struct array_list *list) {
    if (!list)
	return 0;

    return list->alloc_len;
}

static inline int32_t array_list_space(struct array_list *list) {
    return list->alloc_len - list->len;
}

static inline int array_list_resize(struct array_list *list,int newsize) {
    void **lltmp;

    if (newsize == list->alloc_len)
	return 0;

    if (!(lltmp = (void **)realloc(list->list,newsize*sizeof(void *)))) {
	return -1;
    }
 
    list->list = lltmp;
    list->alloc_len = newsize;
    if (newsize < list->len)
	list->len = newsize;

    return 0;
}

static inline int array_list_compact(struct array_list *list) {
    return array_list_resize(list,list->len);
}

static inline int array_list_expand(struct array_list *list,int plussize) {
    void **lltmp;

    if (!(lltmp = (void **)realloc(list->list,
				   (list->alloc_len+plussize)*sizeof(void *)))) {
	return -1;
    }
 
    list->list = lltmp;
    list->alloc_len = (list->alloc_len+plussize);
    if (list->alloc_len < list->len)
	list->len = list->alloc_len;

    return 0;
}

static inline int array_list_expand_to(struct array_list *list,int plussize) {
    int newsize = plussize - (list->alloc_len - list->len);

    if (newsize <= 0)
	return 0;

    return array_list_expand(list,newsize);
}

static inline struct array_list *array_list_concat(struct array_list *list,
						   struct array_list *newtail) {
    array_list_expand_to(list,list->len + newtail->len);
    memcpy(list->list + list->len * sizeof(void *),newtail->list,newtail->len);
    list->len += newtail->len;

    return list;
}

static inline int array_list_add(struct array_list *list,void *element) {
    void **lltmp;

    /* allocate space for another entry if necessary */
    if (list->len == list->alloc_len) {
	if (!(lltmp = (void **)realloc(list->list,
				       (list->len+1)*sizeof(void *)))) {
	    return -1;
	}
	list->list = lltmp;
	list->alloc_len += 1;
    }

    list->list[list->len] = element;

    list->len += 1;

    return 0;
}

static inline int array_list_append(struct array_list *list,void *element) {
    return array_list_add(list,element);
}

static inline int array_list_prepend(struct array_list *list,void *element) {
    void **lltmp;
    int i;

    /* allocate space for another entry if necessary */
    if (list->len == list->alloc_len) {
	if (!(lltmp = (void **)realloc(list->list,
				       (list->len+1)*sizeof(void *)))) {
	    return -1;
	}
	list->list = lltmp;
	list->alloc_len += 1;
    }

    /* shift the whole list over one, ugh */
    for (i = list->len - 1; i > -1; --i) {
	list->list[i + 1] = list->list[i];
    }

    list->list[0] = element;

    list->len += 1;

    return 0;
}

static inline int array_list_prepend_sublist(struct array_list *list,
					  struct array_list *prelist,
					  int howmany) {
    void **lltmp;
    int i;

    if (howmany < 0)
	howmany = prelist->len + howmany;
    else if (howmany == 0)
	return 0;
    else if (howmany > prelist->len)
	return -1;

    /* allocate space for another entry if necessary */
    if (list->len == list->alloc_len) {
	if (!(lltmp = (void **)realloc(list->list,
				       (list->alloc_len + howmany)*sizeof(void *)))) {
	    return -1;
	}
	list->list = lltmp;
	list->alloc_len += howmany;
    }

    /* shift the whole list over by howmany, ugh */
    for (i = list->len - 1; i > -1; --i) {
	list->list[i + howmany] = list->list[i];
    }

    memcpy(list->list,prelist->list,howmany * (sizeof(void *)));

    list->len += howmany;

    return 0;
}

static inline void *array_list_remove(struct array_list *list) {
    if (list->len) 
	return list->list[--list->len];

    return NULL;
}

static inline void array_list_remove_all(struct array_list *list,int maxsize) {
    if (list->len) 
	list->len = 0;
    if (list->alloc_len > maxsize) 
	array_list_resize(list,maxsize);
}

static inline void *array_list_remove_item_at(struct array_list *list,int i) {
    void *item;

    if (!list->list || list->len < 1)
	return NULL;

    if (i == (list->len - 1)) {
	item = list->list[i];
	--list->len;
	return item;
    }
    else if (i < list->len) {
	item = list->list[i];
	/* shift the list over one after i, ugh */
	for ( ; i < list->len - 1; ++i) {
	    list->list[i] = list->list[i + 1];
	}
	--list->len;
	return item;
    }

    return NULL;
}

static inline void *array_list_remove_item(struct array_list *list,void *item) {
    int i;

    if (!list->list || list->len < 1)
	return NULL;

    for (i = 0; i < list->len; ++i) {
	if (list->list[i] == item) 
	    break;
    }

    if (i < list->len) 
	return array_list_remove_item_at(list,i);
    else
	return NULL;
}

static inline int array_list_find(struct array_list *list,void *item) {
    int i;

    if (!list->list || list->len < 1)
	return -1;

    for (i = 0; i < list->len; ++i) {
	if (list->list[i] == item) 
	    return i;
    }

    return -1;
}

static inline void *array_list_item(struct array_list *list,int i) {
    if (!list->list || i < 0 || i >= list->alloc_len) {
	errno = EINVAL;
	return NULL;
    }
    return list->list[i];
}

static inline int array_list_item_set(struct array_list *list,int i,void *item) {
    if (!list->list || i < 0 || i >= list->alloc_len) {
	errno = EINVAL;
	return -1;
    }
    list->list[i] = item;
    return 0;
}

static inline void array_list_free(struct array_list *list) {
    if (list->list)
	free(list->list);
    free(list);
}

static inline void array_list_internal_free(struct array_list *list) {
    int i;

    for (i = 0; i < list->len; ++i)
	free(list->list[i]);
}

static inline void array_list_deep_free(struct array_list *list) {
    array_list_internal_free(list);
    array_list_free(list);
}

#define array_list_foreach(alist,lpc,placeholder)			\
    for (lpc = 0, (placeholder) = alist->len ? (typeof(placeholder))alist->list[lpc] : (typeof(placeholder))NULL; \
	 alist->len - lpc > 0;						\
	 ++lpc, (placeholder) = lpc < alist->len ? (typeof(placeholder))alist->list[lpc] : (typeof(placeholder))NULL) 

#define array_list_foreach_continue(alist,lpc,placeholder)		\
    for ((placeholder) = (alist->len - lpc > 0) ? (typeof(placeholder))alist->list[lpc] : (typeof(placeholder))NULL; \
	 alist->len - lpc > 0;						\
	 ++lpc, (placeholder) = lpc < alist->len ? (typeof(placeholder))alist->list[lpc] : (typeof(placeholder))NULL) 

#define array_list_foreach_fakeptr_t(alist,lpc,placeholder,intertype)	\
    for (lpc = 0, (placeholder) = alist->len ? (typeof(placeholder))(intertype)alist->list[lpc] : (typeof(placeholder))(intertype)NULL; \
	 alist->len - lpc > 0;						\
	 ++lpc, (placeholder) = lpc < alist->len ? (typeof(placeholder))(intertype)alist->list[lpc] : (typeof(placeholder))(intertype)NULL) 

#define array_list_foreach_delete(alist,lpc)	\
    array_list_remove_item_at(alist,lpc); lpc = lpc - 1;

static inline struct array_list *array_list_create_from_g_hash_table(GHashTable *ht) {
    GHashTableIter iter;
    gpointer value;
    int len;
    struct array_list *list;

    len = g_hash_table_size(ht);
    list = (struct array_list *)malloc(sizeof(struct array_list));
    memset(list,0,sizeof(struct array_list));
    if (len) {
	list->alloc_len = len;
	list->list = (void **)malloc(sizeof(void *)*len);
    }
    g_hash_table_iter_init(&iter,ht);
    while (g_hash_table_iter_next(&iter,NULL,&value)) 
	array_list_append(list,value);

    return list;
}

static inline struct array_list *array_list_create_from_g_hash_table_keys(GHashTable *ht) {
    GHashTableIter iter;
    gpointer key;
    int len;
    struct array_list *list;

    len = g_hash_table_size(ht);
    list = (struct array_list *)malloc(sizeof(struct array_list));
    memset(list,0,sizeof(struct array_list));
    if (len) {
	list->alloc_len = len;
	list->list = (void **)malloc(sizeof(void *)*len);
    }
    g_hash_table_iter_init(&iter,ht);
    while (g_hash_table_iter_next(&iter,&key,NULL)) 
	array_list_append(list,key);

    return list;
}

#endif
