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
#include "glib_wrapper.h"

void target_nv_filter_regex_free(struct target_nv_filter_regex *tfr) {
    if (tfr->value_name)
	free(tfr->value_name);
    regfree(&tfr->regex);
    free(tfr);
}

void target_nv_filter_free(struct target_nv_filter *tf) {
    GSList *gsltmp;
    struct target_nv_filter_regex *tfr;

    v_g_slist_foreach(tf->value_regex_list,gsltmp,tfr) {
	target_nv_filter_regex_free(tfr);
    }
    g_slist_free(tf->value_regex_list);
    free(tf);
}

/*
 * Just parse name/value pairs.
 */
struct target_nv_filter *target_nv_filter_parse(char *expr) {
    struct target_nv_filter *tf;
    struct target_nv_filter_regex *tfr;
    GSList *gsltmp;
    int isescaped;
    char *cur;
    char *str;
    char *orig = expr;

    expr = strdup(expr);

    tf = calloc(1,sizeof(*tf));

    cur = expr;
    while (*cur != '\0') {
	tfr = calloc(1,sizeof(*tfr));
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
	tfr->value_name = strdup(str);
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
	    if (regcomp(&tfr->regex,str,REG_EXTENDED | REG_NOSUB))
		goto errout;
	    ++cur;
	}

	tf->value_regex_list = g_slist_append(tf->value_regex_list,tfr);

	while (*cur != '\0' && isspace(*cur))
	    ++cur;

	if (*cur == ',')
	    ++cur;
    }

    free(expr);

    return tf;

 errout:
    if (tfr)
	target_nv_filter_regex_free(tfr);
    v_g_slist_foreach(tf->value_regex_list,gsltmp,tfr) {
	target_nv_filter_regex_free(tfr);
    }
    g_slist_free(tf->value_regex_list);
    free(tf);
    free(expr);
    return NULL;
}
