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
 * default state is 1 and no filter entries match, we accept.  If the
 * default state is 0 and no filter entries match, we reject.  If a
 * filter matches, we do whatever the individual filter says.  A NULL
 * rfilter always rejects.
 */
struct rfilter {
    int defaccept;
    struct array_list list;
};

struct rfilter_entry {
    regex_t *regex;
    int accept;
    void *data;
};

/*
 * Returns 1 if there was a match; 0 if not; sets *@accept to whatever
 * the match (or default filter policy) told us to do.
 */
static inline int rfilter_check(struct rfilter *rf,const char *str,
				int *accept,struct rfilter_entry **rfmatch) {
    int i;
    struct rfilter_entry *rfe;

    if (!rf) {
	if (accept)
	    *accept = RF_ACCEPT;
	return 0;
    }

    for (i = 0; i < array_list_len(&rf->list); ++i) {
	rfe = (struct rfilter_entry *)array_list_item(&rf->list,i);
	if (regexec(rfe->regex,str,0,NULL,0) == 0) {
	    if (accept) 
		*accept = rfe->accept;
	    if (rfmatch) 
		*rfmatch = rfe;
	    return 1;
	}
    }

    if (accept)
	*accept = rf->defaccept;
    return 0;
}

static inline int rfilter_add(struct rfilter *rf,
			      char *rstr,int accept,void *data) {
    struct rfilter_entry *rfe;
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

    rfe = (struct rfilter_entry *)malloc(sizeof(*rfe));
    memset(rfe,0,sizeof(*rfe));
    rfe->regex = regex;
    rfe->accept = accept;
    rfe->data = data;

    array_list_add(&rf->list,rfe);

    return 0;
}

static inline struct rfilter *rfilter_create(int defaccept) {
    struct rfilter *rf = (struct rfilter *)malloc(sizeof(*rf));
    memset(rf,0,sizeof(*rf));
    rf->defaccept = defaccept;
    array_list_init(&rf->list,0);

    return rf;
}

static inline void rfilter_free(struct rfilter *rf) {
    int i;
    struct rfilter_entry *rfe;

    for (i = 0; i < array_list_len(&rf->list); ++i) {
	rfe = (struct rfilter_entry *)array_list_item(&rf->list,i);
	regfree(rfe->regex);
	if (rfe->data)
	    free(rfe->data);
	free(rfe);
    }
    free(rf->list.list);
    free(rf);

    return;
}

static inline struct rfilter *rfilter_create_parse(char *fstr) {
    struct rfilter *rf;
    int pol;
    char *token = NULL;
    char *saveptr;

    while (*fstr == ' ' || *fstr == '\t') 
	++fstr;

    if (*fstr == '.' || *fstr == '*' || *fstr == '\0')
	return NULL;

    /* Check for default policy. */
    if ((*fstr == '1' || *fstr == 'A' || *fstr == 'a') 
	&& *(fstr+1) == ':' && *(fstr+2) == ':') {
	pol = 1;
	fstr += 3;
    }
    else if ((*fstr == '0' || *fstr == 'R' || *fstr == 'r')
	     && *(fstr+1) == ':' && *(fstr+2) == ':') {
	pol = 0;
	fstr += 3;
    }
    else {
	pol = 0;
    }

    rf = rfilter_create(pol);

    while ((token = strtok_r((!token)?fstr:NULL,";",&saveptr))) {
	vdebug(7,LOG_D_DFILE,"token = '%s'\n",token);

	if ((*token == '1' || *token == 'A' || *token == 'a') 
	    && *(token+1) == ':') {
	    pol = 1;
	    token += 2;
	}
	else if ((*token == '0' || *token == 'R' || *token == 'r') 
		 && *(token+1) == ':') {
	    pol = 0;
	    token += 2;
	}
	else 
	    pol = 0;

	if (rfilter_add(rf,token,pol,NULL))
	    goto errout;
    }

    return rf;

 errout:
    rfilter_free(rf);
    return NULL;
}

static inline struct rfilter *rfilter_create_simple(int defaccept,
						    char *rstr,...) {
    va_list ap;
    struct rfilter *rf;

    rf = rfilter_create(defaccept);

    if (rfilter_add(rf,rstr,0,NULL)) {
	free(rf->list.list);
	return NULL;
    }

    va_start(ap,rstr);
    while ((rstr = va_arg(ap,char *))) {
	if (rfilter_add(rf,va_arg(ap,char *),0,NULL))
	    goto errout;
    }
    va_end(ap);

    return rf;

 errout:
    rfilter_free(rf);
    return NULL;
}

#endif
