#ifndef __CLFIT_H__
#define __CLFIT_H__

#include <Judy.h>
#include "alist.h"

typedef Pvoid_t clrange_t;

clrange_t clrange_create();
int clrange_add(clrange_t *clf,Word_t start,Word_t end,void *data);
int clrange_update_end(clrange_t *clf,Word_t start,Word_t end,void *data);
void *clrange_find(clrange_t *clf,Word_t index);
void clrange_free(clrange_t clf);

typedef Pvoid_t clmatch_t;

clmatch_t clmatch_create();
int clmatch_add(clmatch_t *clf,Word_t index,void *data);
struct array_list *clmatch_find(clmatch_t *clf,Word_t index);
void clmatch_free(clmatch_t clf);

#endif

