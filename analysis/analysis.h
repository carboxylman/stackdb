/*
 * Copyright (c) 2012, 2013 The University of Utah
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

#ifndef __ANALYSIS_H__
#define __ANALYSIS_H__

#include "alist.h"
#include "target_api.h"

struct analysis;
struct analysis_desc;
struct analysis_spec;
struct analysis_datum;
struct analysis_datum_simple_value;
struct analysis_datum_typed_value;
struct param;
struct name_value;

typedef enum {
    ASTATUS_UNKNOWN        = 0,
    ASTATUS_RUNNING        = 1,
    ASTATUS_PAUSED         = 2,
    ASTATUS_ERROR          = 3,
    ASTATUS_DONE           = 4,
} analysis_status_t;

void analysis_init(void);
void analysis_fini(void);

struct analysis_datum *analysis_create_simple_datum(struct analysis *analysis,
						    char *name,
						    int type,int subtype,
						    char *value,char *msg);

int analysis_datum_add_simple_value(struct analysis_datum *datum,
				    char *name,char *value);

int analysis_datum_add_typed_value(struct analysis_datum *datum,
				   char *name,void *value,int datatype_id);

/*
 * Reports to stdout as text; the analysis controller as XML; or both.
 */
int analysis_datum_report(struct analysis *analysis,struct analysis_datum *datum);

struct analysis *analysis_create_from_memory(char *name,char *driver_bytes,
					     char *input_bytes,
					     struct array_list *file_names,
					     struct array_list *file_bytes);

/*
 * Set the search path.
 */
void analysis_set_path(const char **path);
void analysis_set_path_string(const char *path);
void analysis_set_annotation_path(const char **path);
void analysis_set_annotation_path_string(const char *path);
void analysis_set_schema_path(const char **path);
void analysis_set_schema_path_string(const char *path);

/*
 * Get the search path.
 */
char **analysis_get_path(void);

/*
 * Returns a full path to an analysis named @name.
 */
char *analysis_find(const char *name);

/*
 * List analysis names as a struct array_list.
 */
struct array_list *analysis_list_names(void);

/*
 * List analysis pathnames as a struct array_list.
 */
struct array_list *analysis_list_pathnames(void);

/*
 * Load analysis metadata for a specific analysis (by dirname -- must
 * be a dir on ANALYSIS_PATH -- set that via analysis_set_path).
 */
struct analysis_desc *analysis_load(const char *name);

/*
 * Load analysis metadata for a specific analysis by full dirpath --
 * must have either description.{xml,txt} in it.
 */
struct analysis_desc *analysis_load_pathname(const char *path);

/*
 * Frees a struct analysis_desc.
 */
void analysis_desc_free(struct analysis_desc *desc);

/*
 * Load analysis metadata from all analyses; returns an array_list of
 * struct analysis_desc values.
 */
struct array_list *analysis_load_all(void);

/*
 * Populates an evloop with any select()able file descriptors that this
 * analysis (and any of its targets) needs monitored, and with their
 * evloop callback functions.  Since analyses might have multiple
 * targets, etc, this is necessary.
 *
 * If a file descriptor closes or exhibits error conditions, the
 * analysis's evloop callback function *must* remove the descriptor from
 * the @evloop -- there is no mechanism for the evloop to clean up
 * garbage.
 */
int analysis_attach_evloop(struct analysis *analysis,struct evloop *evloop);

/*
 * Removes the selectable file descriptors for @analysis from @analysis->evloop.
 */
int analysis_detach_evloop(struct analysis *analysis);

/*
 * Returns 1 if @evloop is already attached to @analysis; 0 if not.
 */
int analysis_is_evloop_attached(struct analysis *analysis,
				struct evloop *evloop);

struct analysis_result *analysis_run(struct analysis_spec *analysis_spec,
				     struct target_spec *target_spec);

analysis_status_t analysis_close(struct analysis *analysis);

void analysis_free(struct analysis *analysis);

/*
 * Analysis instances serve multiple purposes.  First, they are used
 * internally by analysis programs/libraries so that the analysis API
 * can be used by them to report analysis data, annotate traces,
 * coordinate/control, etc.
 *
 * Second, they are used by whatever is launching the analysis for
 * bookkeeping/monitoring.
 */
struct analysis {
    int id;

    analysis_status_t status;

    /*
     * The target ID that this analysis is analyzing.
     *
     * XXX: in future, support multiple targets if desireable.
     */
    int target_id;

    /*
     * This is only valid in the process that instantiated the target,
     * obviously.
     */
    struct target *target;

    struct array_list *results;
    int result_idx;
};

/*
 * A description of an analysis.
 */
struct analysis_desc {
    char *name;
    char *description;
    char *author;
    char *author_contact;

    uint32_t requires_write:1,
	requires_control:1,
	generates_annotations:1,
	reports_intermediate_results:1,
	reports_final_results:1,
	supports_external_control:1,
	supports_autoparse_simple_results:1;

    /*
     * Hash of name/long_name to struct analysis_param.  Params always
     * have short names, so the struct param *s in the _long hashtables
     * are just dups of the ones in the non-long hashtables.  Just that
     * way for easier lookup.
     */
    GHashTable *in_params;
    GHashTable *in_params_long;
    GHashTable *out_params;
    GHashTable *out_params_long;

    time_t mtime;
};

/*
 * A configuration of an analysis_desc; will result in an analysis.
 */
struct analysis_spec {
    char *name;

    char *stdin_bytes;
    int stdin_bytes_len;

    uint32_t log_stdout:1,
	log_stderr:1,
	report_stdout_intermediate:1,
	report_stderr_intermediate:1,
	autoparse_simple_data:1;

    /* array_list of struct name_value */
    struct array_list *in_params;
};

struct param {
    char *name;
    char *long_name;
    char *description;
    char *default_value;
};

struct name_value {
    char *name;
    char *value;
};

struct analysis_datum {
    uint32_t is_simple:1,
	     is_typed:1,
	     is_custom:1,

	     is_event:1,
	     is_marker:1,
	     is_discovery:1,
	     is_result:1;

    int id;
    char *name;
    int type;

    unsigned long tsc;
    unsigned long time;
    unsigned long counter;

    char *value;
    char *msg;

    union {
	/* Valid for is_simple/is_typed */
	struct array_list *values;
	/* Valid for is_custom */
	char *custom;
    };
};

struct analysis_datum_simple_value {
    char *name;
    void *value;
};

struct analysis_datum_typed_value {
    int datatype_id;
    char *name;
    void *value;
};

#endif /* __ANALYSIS_H__ */
