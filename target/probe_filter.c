/*
 * Copyright (c) 2013 The University of Utah
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

#include <ctype.h>
#include <regex.h>

#include "log.h"
#include "target_api.h"
#include "target.h"
#include "target_os.h"
#include "probe.h"
#include "probe_api.h"
#include "glib_wrapper.h"

/*
struct GHashTable *target_thread_get_context(struct target *target,tid_t tid);
int target_thread_match_context(struct target *target,tid_t tid,struct
GHashTable *context_values);
*/

void probe_filter_regex_free(struct probe_filter_regex *pfr) {
    if (pfr->value_name)
	free(pfr->value_name);
    regfree(&pfr->regex);
    free(pfr);
}

void probe_filter_free(struct probe_filter *pf) {
    GSList *gsltmp;
    struct probe_filter_regex *pfr;

    v_g_slist_foreach(pf->value_regex_list,gsltmp,pfr) {
	probe_filter_regex_free(pfr);
    }
    g_slist_free(pf->value_regex_list);
    free(pf);
}

/*
 * Just parse name/value pairs.
 */
struct probe_filter *probe_filter_parse(char *expr) {
    struct probe_filter *pf;
    struct probe_filter_regex *pfr;
    GSList *gsltmp;
    int isescaped;
    char *cur;
    char *str;
    char *orig = expr;

    expr = strdup(expr);

    pf = calloc(1,sizeof(*pf));

    cur = expr;
    while (*cur != '\0') {
	pfr = calloc(1,sizeof(*pfr));
	/*
	 * Read: <identifier>, \s+, '=', \s+, '/', <regex>, '/'
	 */
	while (*cur != '\0' && isspace(*cur))
	    ++cur;
	str = cur;
	while (*cur != '\0' && (isalnum(*cur) || *cur == '_'))
	    ++cur;
	while (*cur != '\0' && isspace(*cur)) {
	    *cur = '\0';
	    ++cur;
	}
	if (*cur == '=') {
	    *cur = '\0';
	    ++cur;
	}
	else 
	    goto errout;
	pfr->value_name = strdup(str);
	while (*cur != '\0' && isspace(*cur))
	    ++cur;
	if (*cur == '/') {
	    ++cur;
	    str = cur;
	}
	else
	    goto errout;
	isescaped = 0;
	while (*cur != '\0') {
	    if (*cur == '\\' && !isescaped)
		isescaped = 1;
	    else 
		isescaped = 0;
	    if (!isescaped && *cur == '/') {
		break;
	    }
	    ++cur;
	}
	if (*cur == '/') {
	    *cur = '\0';
	    if (regcomp(&pfr->regex,str,REG_EXTENDED | REG_NOSUB))
		goto errout;
	    ++cur;
	}

	pf->value_regex_list = g_slist_append(pf->value_regex_list,pfr);

	while (*cur != '\0' && isspace(*cur))
	    ++cur;

	if (*cur == ',')
	    ++cur;
    }

    free(expr);

    return pf;

 errout:
    if (pfr)
	probe_filter_regex_free(pfr);
    v_g_slist_foreach(pf->value_regex_list,gsltmp,pfr) {
	probe_filter_regex_free(pfr);
    }
    g_slist_free(pf->value_regex_list);
    free(pf);
    free(expr);
    return NULL;
}

/*
 * Can only check pre/post_filters if @trigger provides probe_values.
 *
 * XXX: add support for checking context.
 */
int probe_filter_check(struct probe *probe,tid_t tid,struct probe *trigger,
		       int whence) {
    struct probe_filter *pf;
    char vstrbuf[1024];
    int rc;
    struct value *v;
    GSList *gsltmp;
    struct probe_filter_regex *pfr;

    if (whence == 0)
	pf = probe->pre_filter;
    else if (whence == 1) 
	pf = probe->post_filter;
    else
	return -1;

    if (!pf)
	return 0;

    /*
     * Check each filter by loading the value from @trigger.
     */
    v_g_slist_foreach(pf->value_regex_list,gsltmp,pfr) {
	v = probe_value_get(trigger,tid,pfr->value_name);
	if (!v) {
	    vwarn(//8,LA_PROBE,LF_PROBE,
		     "could not load value name %s",pfr->value_name);
	    return -1;
	}
	rc = value_snprintf(v,vstrbuf,sizeof(vstrbuf));
	if (regexec(&pfr->regex,(const char *)vstrbuf,0,NULL,0) == REG_NOMATCH) {
	    vdebug(9,LA_PROBE,LF_PROBE,
		   "failed to match name %s value '%s' with regex!\n",
		   pfr->value_name,vstrbuf);
	    return 1;
	}
	else {
	    vdebug(9,LA_PROBE,LF_PROBE,
		   "matched name %s value '%s' with regex\n",
		   pfr->value_name,vstrbuf);
	}
    }

    return 0;
}

struct probe *probe_create_filtered(struct target *target,tid_t tid,
				    struct probe_ops *pops,
				    const char *name,
				    probe_handler_t pre_handler,
				    struct probe_filter *pre_filter,
				    probe_handler_t post_handler,
				    struct probe_filter *post_filter,
				    void *handler_data,
				    int autofree,int tracked) {
    struct probe *fprobe;

    fprobe = probe_create(target,tid,pops,name,pre_handler,post_handler,
			  handler_data,autofree,tracked);
    fprobe->pre_filter = pre_filter;
    fprobe->post_filter = post_filter;

    return fprobe;
}
