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

#include "config.h"

#include "common.h"
#include "log.h"
#include "alist.h"
#include "analysis.h"

#include <errno.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/time.h>

#include <glib.h>

#ifdef ENABLE_SOAP
#include "analysis_xml_moduleH.h"
#include "analysis_xml.h"
#endif

static char *DEFAULT_ANALYSIS_PATH[] = {
    INSTALL_LIBEXECDIR "/analysis",
    NULL,
};
static char *DEFAULT_ANNOTATION_PATH[] = {
    INSTALL_SHAREDIR "/annotation",
    NULL,
};
static char *DEFAULT_SCHEMA_PATH[] = {
    INSTALL_SHAREDIR "/schema",
    NULL,
};

char *ANALYSIS_TMPDIR = "/var/tmp/";

static char **ANALYSIS_PATH = (char **)DEFAULT_ANALYSIS_PATH;
static char **ANNOTATION_PATH = (char **)DEFAULT_ANNOTATION_PATH;
static char **SCHEMA_PATH = (char **)DEFAULT_SCHEMA_PATH;

static GHashTable *cache = NULL;

static int next_analysis_id = 1;

static int init_done = 0;

void analysis_init(void) {
    struct timeval tv;

    if (init_done)
	return;

    target_init();

    gettimeofday(&tv,NULL);
    srand(tv.tv_usec);

    init_done = 1;
}

void analysis_fini(void) {
    if (!init_done)
	return;

    target_fini();

    init_done = 0;
}

struct array_list *analysis_list_names(void) {
    struct array_list *retval = array_list_create(8);
    DIR *dir;
    struct dirent *dirp;
    char *dirname;
    int i;

    for (i = 0; (dirname = ANALYSIS_PATH[i]) != NULL; ++i) {
	dir = opendir(dirname);
	if (!dir) {
	    vwarnopt(5,LA_ANL,LF_ANL,"could not open ANALYSIS_PATH dir '%s'\n",
		     dirname);
	    continue;
	}
	while ((dirp = readdir(dir))) 
	    array_list_append(retval,strdup(dirp->d_name));
	closedir(dir);
    }

    return retval;
}

struct array_list *analysis_list_pathnames(void) {
    struct array_list *retval = array_list_create(8);
    DIR *dir;
    struct dirent *dirp;
    char *dirname;
    int i;
    char pbuf[PATH_MAX];
    int path_base_len;
    char *pbuf_base_ptr;
    char *newpath;

    for (i = 0; (dirname = ANALYSIS_PATH[i]) != NULL; ++i) {
	dir = opendir(dirname);
	if (!dir) {
	    vwarnopt(5,LA_ANL,LF_ANL,"could not open ANALYSIS_PATH dir '%s'\n",
		     dirname);
	    continue;
	}

	/* Get our base path ready to go; we'll just append to it. */
	path_base_len = snprintf(pbuf,PATH_MAX,"%s/",dirname);
	pbuf_base_ptr = pbuf + path_base_len;

	while ((dirp = readdir(dir))) {
	    if (dirp->d_name[0] == '.')
		continue;

	    strncpy(pbuf_base_ptr,dirp->d_name,PATH_MAX - path_base_len);
	    newpath = strdup(pbuf);
	    vdebug(5,LA_ANL,LF_ANL,"adding path %s (%p)\n",newpath,newpath);
	    array_list_append(retval,newpath);
	}
	closedir(dir);
    }

    return retval;
}

char *analysis_find(const char *name) {
    char *retval = NULL;
    DIR *dir;
    struct dirent *dirp;
    char *dirname;
    int i;
    int len;

    for (i = 0; (dirname = ANALYSIS_PATH[i]) != NULL; ++i) {
	dir = opendir(dirname);
	if (!dir) {
	    vwarnopt(5,LA_ANL,LF_ANL,"could not open ANALYSIS_PATH dir '%s'\n",
		     dirname);
	    continue;
	}
	while ((dirp = readdir(dir))) {
	    if (strcmp(dirp->d_name,name) == 0) {
		len = strlen(dirp->d_name) + strlen(dirname) + 2;
		retval = malloc(sizeof(char) * len);
		snprintf(retval,len,"%s/%s",dirname,dirp->d_name);
		break;
	    }
	}
	closedir(dir);
	if (retval)
	    break;
    }

    return retval;
}

struct analysis_desc *analysis_load_txt(const char *path,
					const char *desc_file_path) {

}

#ifdef ENABLE_SOAP
struct analysis_desc *analysis_load_xml(const char *path,
					const char *desc_file_path) {
    struct vmi1__AnalysisDescT *analysisDesc;
    struct analysis_desc *retval;
    GHashTable *reftab;
    struct soap soap;
    int fd;

    if ((fd = open(desc_file_path,O_RDONLY)) < 0) {
	verror("open(%s): %s\n",desc_file_path,strerror(errno));
	return NULL;
    }

    soap_init(&soap);
    //soap_imode(&soap, flags);
    soap_begin(&soap);
    soap.recvfd = fd;
    soap_begin_recv(&soap);
    reftab = g_hash_table_new(g_direct_hash,g_direct_equal);

    analysisDesc = soap_get_vmi1__AnalysisDescT(&soap,NULL,"analysisDesc",NULL);
    if (!analysisDesc) {
	verror("could not read AnalysisDesc element from %s!\n",
	       desc_file_path);
	g_hash_table_destroy(reftab);
	soap_end_recv(&soap);
	soap_destroy(&soap);
	soap_end(&soap);
	soap_done(&soap);
	close(fd);
	return NULL;
    }
    soap_end_recv(&soap);

    /*
     * Safe to use object now... (soap_end_recv checks id/href consistency).
     */
    retval = x_AnalysisDescT_to_a_analysis_desc(&soap,analysisDesc,reftab,NULL);

    /*
     * Cannot use deserialized data after this...
     */
    g_hash_table_destroy(reftab);
    soap_destroy(&soap);
    soap_end(&soap);
    soap_done(&soap);
    close(fd);

    return retval;
}
#endif

struct analysis_desc *analysis_load(const char *name) {
    struct analysis_desc *retval;
    char *path;
    struct stat statbuf;
    time_t mtime = 0;

    /* Find it first by scanning the path. */
    path = analysis_find(name);
    if (!path) {
	vwarnopt(4,LA_ANL,LA_ANL,"could not find analysis '%s'\n",name);
	errno = ENOENT;
	return NULL;
    }

    /* Stat its dir to get the mtime. */
    if (stat(path,&statbuf)) 
	vwarn("stat(%s): %s (not using cache)\n",path,strerror(errno));
    else 
	mtime = statbuf.st_mtime;

    /*
     * XXX: cache!
     */

    retval = analysis_load_pathname(path);
    free(path);

    return retval;
}

struct analysis_desc *analysis_load_pathname(const char *path) {
    struct analysis_desc *retval;
    char *name;
    char pbuf[PATH_MAX];
    struct stat statbuf;
    time_t mtime = 0;
    int path_base_len = 0;
    char *pbuf_base_ptr;
    int isxml = 0;

    name = rindex(path,'/');
    if (!name) {
	errno = EINVAL;
	return NULL;
    }
    ++name;

    /* Stat its dir to get the mtime. */
    if (stat(path,&statbuf)) 
	vwarn("stat(%s): %s (not using cache)\n",path,strerror(errno));
    else 
	mtime = statbuf.st_mtime;

    /* Get our base path ready to go; we'll just append to it. */
    path_base_len = snprintf(pbuf,PATH_MAX,"%s/",path);
    pbuf_base_ptr = pbuf + path_base_len;

    vdebug(5,LA_ANL,LF_ANL,"trying to load description.* in %s (%s/%p)\n",
	   pbuf,path,path);

    /*
     * Figure out if it is an XML analysis; if we have XML support, load
     * it, if not skip it; if not an XML analysis, load by text.
     */
#ifdef ENABLE_SOAP
    strncpy(pbuf_base_ptr,"description.xml",PATH_MAX - path_base_len);
    if (stat(pbuf,&statbuf) == 0) 
	isxml = 1;
#endif

    if (!isxml) {
	strncpy(pbuf_base_ptr,"description.txt",PATH_MAX - path_base_len);
	if (stat(pbuf,&statbuf)) {
	    vwarnopt(5,LA_ANL,LA_ANL,"could not stat %s\n",pbuf);
	    verror("could not read description.{xml,txt} in %s!\n",path);
	    return NULL;
	}
    }

#ifdef ENABLE_SOAP
    if (isxml) {
	retval = analysis_load_xml(path,pbuf);
    }
    else 
#endif
    {
	retval = analysis_load_txt(path,pbuf);
    }

    return retval;
}

struct array_list *analysis_load_all(void) {
    struct array_list *retval;
    struct array_list *pnlist;
    char *pathname;
    struct analysis_desc *desc;
    int i;

    pnlist = analysis_list_pathnames();
    if (!pnlist || array_list_len(pnlist) <= 0)
	return NULL;

    i = array_list_len(pnlist);
    retval = array_list_create(i);
    i = 0;
    array_list_foreach(pnlist,i,pathname) {
	vdebug(5,LA_ANL,LF_ANL,"trying to load pathname %s (%p)\n",
	       pathname,pathname);

	desc = analysis_load_pathname(pathname);
	if (!desc) {
	    verror("could not load analysis in %s %p %i; skipping!\n",pathname,pathname,i);
	    free(pathname);
	    continue;
	}
	else {
	    free(pathname);
	    array_list_append(retval,desc);
	}
    }
    array_list_free(pnlist);

    return retval;
}


analysis_status_t analysis_status_from_target_status(target_status_t status) {
    if (status <= 0xf)
	return status;
    else if (status == TSTATUS_DEAD)
	return ASTATUS_ERROR;
    else if (status == TSTATUS_STOPPED)
	return ASTATUS_PAUSED;
    else 
	return ASTATUS_UNKNOWN;
}

int analysis_attach_evloop(struct analysis *analysis,struct evloop *evloop) {
    return target_attach_evloop(analysis->target,evloop);
}

int analysis_detach_evloop(struct analysis *analysis) {
    return target_detach_evloop(analysis->target);
}

int analysis_is_evloop_attached(struct analysis *analysis,
				struct evloop *evloop) {
    return target_is_evloop_attached(analysis->target,evloop);
}

struct analysis *analysis_create(int id,struct analysis_spec *spec,
				 struct analysis_desc *desc,
				 int target_id,struct target *target) {
    struct analysis *retval = calloc(1,sizeof(*retval));

    retval->id = id;
    retval->spec = spec;
    retval->desc = desc;
    retval->target_id = target_id;
    retval->target = target;

    return retval;
}

struct analysis_datum *analysis_create_simple_datum(struct analysis *analysis,
						    int id,char *name,int type,
						    char *value,char *msg,
						    int no_copy) {
    struct analysis_datum *datum;

    datum = calloc(1,sizeof(*datum));

    datum->is_simple = 1;
    datum->values = array_list_create(1);

    datum->id = id;
    if (no_copy)
	datum->name = name;
    else if (name)
	datum->name = strdup(name);
    datum->type = type;
    if (no_copy)
	datum->value = value;
    else if (value)
	datum->value = strdup(value);
    if (no_copy)
	datum->msg = msg;
    else if (msg)
	datum->msg = strdup(msg);

    return datum;
}

int analysis_datum_add_simple_value(struct analysis_datum *datum,
				    char *name,char *value,
				    int no_copy) {
    struct analysis_datum_simple_value *v = 
	calloc(1,sizeof(*v));

    if (name && !no_copy)
	v->name = strdup(name);
    else
	v->name = name;
    if (value && !no_copy)
	v->value = strdup(value);
    else
	v->value = value;

    array_list_append(datum->values,v);

    return 0;
}

int analysis_datum_add_typed_value(struct analysis_datum *datum,
				   char *name,void *value,int len,int datatype_id,
				   int no_copy) {
    struct analysis_datum_typed_value *v = 
	calloc(1,sizeof(*v));

    v->datatype_id = datatype_id;
    if (name && !no_copy)
	v->name = strdup(name);
    else
	v->name = name;
    if (value && !no_copy) {
	v->value = malloc(len);
	memcpy(v->value,value,len);
    }
    else
	v->value = value;

    array_list_append(datum->values,v);

    return 0;
}

void analysis_datum_free(struct analysis_datum *datum) {
    int i;
    struct analysis_datum_simple_value *sv;
    struct analysis_datum_typed_value *tv;

    if (datum->name)
	free(datum->name);
    if (datum->value)
	free(datum->value);
    if (datum->msg)
	free(datum->msg);

    if (datum->is_simple && datum->values)  {
	array_list_foreach(datum->values,i,sv) 
	    analysis_datum_simple_value_free(sv);
	array_list_free(datum->values);
    }
    else if (datum->is_typed && datum->values)  {
	array_list_foreach(datum->values,i,tv) 
	    analysis_datum_typed_value_free(tv);
	array_list_free(datum->values);
    }

    free(datum);
}

void analysis_datum_simple_value_free(struct analysis_datum_simple_value *v) {
    if (v->name)
	free(v->name);
    if (v->value)
	free(v->value);
    free(v);
}

void analysis_datum_typed_value_free(struct analysis_datum_typed_value *v) {
    if (v->name)
	free(v->name);
    if (v->value)
	free(v->value);
    free(v);
}

analysis_status_t analysis_close(struct analysis *analysis) {
    if ((analysis->status == ASTATUS_RUNNING 
	 || analysis->status == ASTATUS_PAUSED)
	&& analysis->target)
	analysis->status = target_close(analysis->target);

    return analysis->status;
}

void analysis_cleanup(struct analysis *analysis) {
    DIR *dir;
    int dfd;
    struct dirent *dirp;

    if (!analysis->tmpdir)
	return;

    dir = opendir(analysis->tmpdir);
    if (dir) {
	dfd = dirfd(dir);
	while ((dirp = readdir(dir))) {
	    if (!strcmp(dirp->d_name,".") || !strcmp(dirp->d_name,"..")) 
		continue;

	    if (unlinkat(dfd,dirp->d_name,0)) 
		vwarn("could not remove %s in dir %s: %s\n",
		      dirp->d_name,analysis->tmpdir,strerror(errno));
	}
    }
    closedir(dir);
    if (rmdir(analysis->tmpdir))
	vwarn("could not remove dir %s: %s\n",
	      analysis->tmpdir,strerror(errno));
}

void analysis_free(struct analysis *analysis) {
    analysis_close(analysis);

    if (analysis->target) {
	target_free(analysis->target);
	analysis->target = NULL;
    }

    /* XXX: deep free! */
    if (analysis->results)
	array_list_free(analysis->results);

    /*
     * Cleanup @analysis->tmpdir if it exists; just remove everything.
     */
    if (analysis->tmpdir) {
	analysis_cleanup(analysis);
	free(analysis->tmpdir);
    }

    analysis_spec_free(analysis->spec);
    analysis_desc_free(analysis->desc);
}

void analysis_desc_free(struct analysis_desc *desc) {
    GHashTableIter iter;
    gpointer value;

    if (desc->name)
	free(desc->name);
    if (desc->description)
	free(desc->description);
    if (desc->author)
	free(desc->author);
    if (desc->author_contact)
	free(desc->author_contact);
    if (desc->binary)
	free(desc->binary);

    if (desc->in_params) {
	g_hash_table_iter_init(&iter,desc->in_params);
	while (g_hash_table_iter_next(&iter,NULL,&value)) 
	    analysis_param_free((struct analysis_param *)value);
	g_hash_table_destroy(desc->in_params);
    }
    if (desc->in_params_long)
	g_hash_table_destroy(desc->in_params_long);
    if (desc->out_params) {
	g_hash_table_iter_init(&iter,desc->out_params);
	while (g_hash_table_iter_next(&iter,NULL,&value)) 
	    analysis_param_free((struct analysis_param *)value);
	g_hash_table_destroy(desc->out_params);
    }
    if (desc->out_params_long)
	g_hash_table_destroy(desc->out_params_long);


    free(desc);
}

void analysis_spec_free(struct analysis_spec *spec) {
    if (spec->stdin_bytes)
	free(spec->stdin_bytes);

    if (spec->infile) {
	free(spec->infile);
	spec->infile = NULL;
    }
    if (spec->outfile) {
	free(spec->outfile);
	spec->outfile = NULL;
    }
    if (spec->errfile) {
	free(spec->errfile);
	spec->errfile = NULL;
    }

    free(spec);
}

void analysis_param_free(struct analysis_param *param) {
    if (param->name)
	free(param->name);
    if (param->long_name)
	free(param->long_name);
    if (param->description) 
	free(param->description);
    if (param->default_value)
	free(param->default_value);

    free(param);
}

char **analysis_get_path(void) {
    return ANALYSIS_PATH;
}

char **__path_string_to_vec(const char *path) {
    int i;
    int pathlen = 0;
    char *ptr;
    char *nptr;
    char **bpath;

    if (!path)
	return NULL;

    ptr = (char *)path;
    pathlen = 1;
    while (*ptr != '\0') {
	if (*ptr == ':')
	    ++pathlen;
	++ptr;
    }

    bpath = calloc(pathlen + 1,sizeof(*bpath));

    i = 0;
    ptr = (char *)path;
    nptr = (char *)path;

    for (i = 0; nptr && *nptr != '\0'; ++i) {
	nptr = index(nptr,':');
	if (nptr == NULL) {
	    if (*ptr != '\0') {
		bpath[i] = strdup(ptr);
	    }
	    else 
		continue; /* terminate on next pass too */
	}
	else {
	    bpath[i] = malloc(sizeof(char)*(nptr - ptr + 1));
	    strncpy(bpath[i],ptr,nptr - ptr);
	    bpath[i][nptr - ptr] = '\0';

	    ++nptr;
	    ptr = nptr;
	}
    }
    bpath[i] = NULL;

    return bpath;
}

void analysis_set_path(const char **path) {
    int i;
    int pathlen = 0;
    char **ptr = (char **)path;

    if (!path)
	return;

    while (*ptr) {
	++pathlen;
	++ptr;
    }

    ANALYSIS_PATH = calloc(pathlen + 1,sizeof(char *));
    for (i = 0; i < pathlen; ++i) 
	ANALYSIS_PATH[i] = strdup(path[i]);
}

void analysis_set_path_string(const char *path) {
    char **bpath;

    if (!path)
	return;

    if ((bpath = __path_string_to_vec(path)))
	ANALYSIS_PATH = bpath;
}

void analysis_set_annotation_path(const char **path) {
    int i;
    int pathlen = 0;
    char **ptr = (char **)path;

    if (!path)
	return;

    while (*ptr) {
	++pathlen;
	++ptr;
    }

    ANNOTATION_PATH = calloc(pathlen + 1,sizeof(char *));
    for (i = 0; i < pathlen; ++i) 
	ANNOTATION_PATH[i] = strdup(path[i]);
}

void analysis_set_annotation_path_string(const char *path) {
    char **bpath;

    if (!path)
	return;

    if ((bpath = __path_string_to_vec(path)))
	ANNOTATION_PATH = bpath;
}

void analysis_set_schema_path(const char **path) {
    int i;
    int pathlen = 0;
    char **ptr = (char **)path;

    if (!path)
	return;

    while (*ptr) {
	++pathlen;
	++ptr;
    }

    SCHEMA_PATH = calloc(pathlen + 1,sizeof(char *));
    for (i = 0; i < pathlen; ++i) 
	SCHEMA_PATH[i] = strdup(path[i]);
}

void analysis_set_schema_path_string(const char *path) {
    char **bpath;

    if (!path)
	return;

    if ((bpath = __path_string_to_vec(path)))
	SCHEMA_PATH = bpath;
}
