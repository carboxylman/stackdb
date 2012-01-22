#ifndef _ARRAY_LIST_H
#define _ARRAY_LIST_H

/**
 ** A very, very simple array list.  But, useful!
 **/

#include <stdlib.h>
#include <errno.h>
#include <string.h>

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

static inline int32_t array_list_len(struct array_list *list) {
    return list->len;
}

static inline int32_t array_list_alloc_len(struct array_list *list) {
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
    free(list->list);
    free(list);
}

static inline void array_list_deep_free(struct array_list *list) {
    int i;

    for (i = 0; i < list->len; ++i)
	free(list->list[i]);
}



#endif
