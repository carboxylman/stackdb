#ifndef __RFILTER_H__
#define __RFILTER_H__

#include <stdarg.h>
#include <sys/types.h>
#include <regex.h>

#include "log.h"
#include "alist.h"

#define RF_ACCEPT 1
#define RF_REJECT 0

/*
 * Each rfilter has a default state where nothing matches; if the
 * default state is 0 and no filter entries match, we accept.  If the
 * default state is 1 and no filter entries match, we reject.  If a
 * filter matches, we do whatever the individual filter says.
 */
struct rfilter_list {
    int defaccept;
    struct array_list list;
};

struct rfilter {
    regex_t *regex;
    int accept;
    void *data;
};

static inline int rfilter_check(struct rfilter_list *list,const char *str,
				int *accept,struct rfilter **rfmatch) {
    int i;
    struct rfilter *rf;

    for (i = 0; i < array_list_len(&list->list); ++i) {
	rf = (struct rfilter *)array_list_item(&list->list,i);
	if (regexec(rf->regex,str,0,NULL,0) == 0) {
	    if (accept) 
		*accept = rf->accept;
	    if (rfmatch) 
		*rfmatch = rf;
	    return 1;
	}
    }

    if (accept)
	*accept = list->defaccept;
    return 0;
}

static inline int rfilter_add(struct rfilter_list *list,
			      char *rstr,int accept,void *data) {
    struct rfilter *rf;
    regex_t *regex;
    int rc;
    char errbuf[64];

    regex = (regex_t *)malloc(sizeof(*regex));
    memset(regex,0,sizeof(*regex));
    if ((rc = regcomp(regex,rstr,REG_EXTENDED | REG_NOSUB))) {
	regerror(rc,regex,errbuf,64);
	verror("bad regex '%s': %s\n",rstr,errbuf);
	regfree(regex);
	free(regex);
	return -1;
    }

    rf = (struct rfilter *)malloc(sizeof(*rf));
    memset(rf,0,sizeof(*rf));
    rf->regex = regex;
    rf->accept = accept;
    rf->data = data;

    array_list_add(&list->list,rf);

    return 0;
}

static inline struct rfilter_list *rfilter_create(int defaccept) {
    struct rfilter_list *rfl = (struct rfilter_list *)malloc(sizeof(*rfl));
    memset(rfl,0,sizeof(*rfl));
    rfl->defaccept = defaccept;
    array_list_init(&rfl->list,0);

    return rfl;
}

static inline void rfilter_free(struct rfilter_list *list) {
    int i;
    struct rfilter *rf;

    for (i = 0; i < array_list_len(&list->list); ++i) {
	rf = (struct rfilter *)array_list_item(&list->list,i);
	regfree(rf->regex);
	if (rf->data)
	    free(rf->data);
	free(rf);
    }
    free(list->list.list);
    free(list);

    return;
}

static inline struct rfilter_list *rfilter_create_simple(int defaccept,
							 char *rstr,...) {
    va_list ap;
    struct rfilter_list *rfl;

    rfl = rfilter_create(defaccept);

    if (rfilter_add(rfl,rstr,0,NULL)) {
	free(rfl->list.list);
	return NULL;
    }

    va_start(ap,rstr);
    while ((rstr = va_arg(ap,char *))) {
	if (rfilter_add(rfl,va_arg(ap,char *),0,NULL))
	    goto errout;
    }
    va_end(ap);

    return rfl;

 errout:
    rfilter_free(rfl);
    return NULL;
}

#endif
