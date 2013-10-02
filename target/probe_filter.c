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
 * Can only check pre/post_filters if @trigger provides probe_values.
 */
int probe_filter_check(struct probe *probe,tid_t tid,struct probe *trigger,
		       int whence) {
    struct target_nv_filter *tf;
    char vstrbuf[1024];
    int rc;
    struct value *v;
    GSList *gsltmp;
    struct target_nv_filter_regex *tfr;

    if (whence == 0)
	tf = probe->pre_filter;
    else if (whence == 1) 
	tf = probe->post_filter;
    else
	return -1;

    /*
     * Check the thread filter first.
     */
    if (probe->thread_filter) {
	rc = target_thread_filter_check(probe->target,tid,probe->thread_filter);
	if (rc)
	    return rc;
    }

    if (!tf)
	return 0;

    /*
     * Check each filter by loading the value from @trigger.
     */
    v_g_slist_foreach(tf->value_regex_list,gsltmp,tfr) {
	v = probe_value_get(trigger,tid,tfr->value_name);
	if (!v) {
	    vwarn(//8,LA_PROBE,LF_PROBE,
		     "could not load value name %s",tfr->value_name);
	    return -1;
	}
	rc = value_snprintf(v,vstrbuf,sizeof(vstrbuf));
	if (regexec(&tfr->regex,(const char *)vstrbuf,0,NULL,0) == REG_NOMATCH) {
	    vdebug(9,LA_PROBE,LF_PROBE,
		   "failed to match name %s value '%s' with regex!\n",
		   tfr->value_name,vstrbuf);
	    return 1;
	}
	else {
	    vdebug(9,LA_PROBE,LF_PROBE,
		   "matched name %s value '%s' with regex\n",
		   tfr->value_name,vstrbuf);
	}
    }

    return 0;
}

struct probe *probe_create_filtered(struct target *target,tid_t tid,
				    struct probe_ops *pops,
				    const char *name,
				    probe_handler_t pre_handler,
				    struct target_nv_filter *pre_filter,
				    probe_handler_t post_handler,
				    struct target_nv_filter *post_filter,
				    struct target_nv_filter *thread_filter,
				    void *handler_data,
				    int autofree,int tracked) {
    struct probe *fprobe;

    fprobe = probe_create(target,tid,pops,name,pre_handler,post_handler,
			  handler_data,autofree,tracked);
    fprobe->pre_filter = pre_filter;
    fprobe->post_filter = post_filter;
    fprobe->thread_filter = thread_filter;

    return fprobe;
}
