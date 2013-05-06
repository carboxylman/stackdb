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

#include "analysis_xml.h"
#include "util.h"

#include <glib.h>

struct vmi1__AnalysisT *a_analysis_to_x_AnalysisT(struct soap *soap,	
						  struct analysis *in,
						  GHashTable *reftab,
						  struct vmi1__AnalysisT *out) {
    struct vmi1__AnalysisT *rout;

    if (out)
	rout = out;
    else
	rout = calloc(1,sizeof(*rout));

    rout->aid = in->id;
    rout->tid = in->target_id;
    rout->analysisStatus = 
	a_analysis_status_t_to_x_AnalysisStatusT(soap,in->status,reftab,NULL);
    rout->analysisResults = 
	a_analysis_datum_list_to_x_AnalysisResultsT(soap,in->results,in,reftab,NULL);

    return rout;
}

struct analysis_desc *
x_AnalysisDescT_to_a_analysis_desc(struct soap *soap,
				   struct vmi1__AnalysisDescT *in,
				   GHashTable *reftab,
				   struct analysis_desc *out) {
    struct analysis_desc *rout;
    struct analysis_param *param;
    int i;

    if (out)
	rout = out;
    else
	rout = calloc(1,sizeof(*rout));

    rout->name = strdup(in->name);
    if (in->description)
	rout->description = strdup(in->description);
    if (in->author)
	rout->author = strdup(in->author);
    if (in->authorContact)
	rout->author_contact = strdup(in->authorContact);

    rout->binary = strdup(in->binary);

    if (in->requiresWrite == xsd__boolean__true_)
	rout->requires_write = 1;
    if (in->requiresControl == xsd__boolean__true_)
	rout->requires_control = 1;
    if (in->generatesAnnotations == xsd__boolean__true_)
	rout->generates_annotations = 1;
    if (in->reportsIntermediateResults == xsd__boolean__true_)
	rout->reports_intermediate_results = 1;
    if (in->reportsFinalResults == xsd__boolean__true_)
	rout->reports_final_results = 1;
    if (in->supportsExternalControl == xsd__boolean__true_)
	rout->supports_external_control = 1;
    if (in->supportsAutoparseSimpleResults == xsd__boolean__true_)
	rout->supports_autoparse_simple_results = 1;

    rout->in_params = g_hash_table_new(g_str_hash,g_str_equal);
    rout->in_params_long = g_hash_table_new(g_str_hash,g_str_equal);
    if (in->inParams) {
	for (i = 0; i < in->inParams->__sizeparam; ++i) {
	    param = x_ParamT_to_a_param(soap,&(in->inParams->param[i]),NULL);
	    g_hash_table_insert(rout->in_params,param->name,param);
	    if (param->long_name)
		g_hash_table_insert(rout->in_params_long,param->long_name,param);
	}
    }

    rout->out_params = g_hash_table_new(g_str_hash,g_str_equal);
    rout->out_params_long = g_hash_table_new(g_str_hash,g_str_equal);
    if (in->outParams) {
	for (i = 0; i < in->outParams->__sizeparam; ++i) {
	    param = x_ParamT_to_a_param(soap,&(in->outParams->param[i]),NULL);
	    g_hash_table_insert(rout->out_params,param->name,param);
	    if (param->long_name)
		g_hash_table_insert(rout->out_params_long,param->long_name,param);
	}
    }

    return rout;
}

struct vmi1__AnalysisDescT *
a_analysis_desc_to_x_AnalysisDescT(struct soap *soap,
				   struct analysis_desc *in,
				   GHashTable *reftab,
				   struct vmi1__AnalysisDescT *out) {
    struct vmi1__AnalysisDescT *rout;
    GHashTableIter iter;
    struct analysis_param *param;
    int i;

    if (out)
	rout = out;
    else
	rout = calloc(1,sizeof(*rout));

    SOAP_STRCPY(soap,rout->name,in->name);
    if (in->description)
	SOAP_STRCPY(soap,rout->description,in->description);
    if (in->author)
	SOAP_STRCPY(soap,rout->author,in->author);
    if (in->author_contact)
	SOAP_STRCPY(soap,rout->authorContact,in->author_contact);

    SOAP_STRCPY(soap,rout->binary,in->binary);

    if (in->requires_write)
	rout->requiresWrite = xsd__boolean__true_;
    else
	rout->requiresWrite = xsd__boolean__false_;
    if (in->requires_control)
	rout->requiresControl = xsd__boolean__true_;
    else
	rout->requiresControl = xsd__boolean__false_;
    if (in->generates_annotations)
	rout->generatesAnnotations = xsd__boolean__true_;
    else
	rout->generatesAnnotations = xsd__boolean__false_;
    if (in->reports_intermediate_results == xsd__boolean__true_)
	rout->reportsIntermediateResults = xsd__boolean__true_;
    else
	rout->reportsIntermediateResults = xsd__boolean__false_;
    if (in->reports_final_results)
	rout->reportsFinalResults = xsd__boolean__true_;
    else
	rout->reportsFinalResults = xsd__boolean__false_;
    if (in->supports_external_control)
	rout->supportsExternalControl = xsd__boolean__true_;
    else
	rout->supportsExternalControl = xsd__boolean__false_;
    if (in->supports_autoparse_simple_results)
	rout->supportsAutoparseSimpleResults = xsd__boolean__true_;
    else
	rout->supportsAutoparseSimpleResults = xsd__boolean__false_;

    rout->inParams = SOAP_CALLOC(soap,1,sizeof(*rout->inParams));
    rout->inParams->__sizeparam = g_hash_table_size(in->in_params);
    rout->inParams->param = SOAP_CALLOC(soap,rout->inParams->__sizeparam,
					sizeof(*rout->inParams->param));
    i = 0;
    g_hash_table_iter_init(&iter,in->in_params);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer *)&param)) {
	a_param_to_x_ParamT(soap,param,&(rout->inParams->param[i]));
	++i;
    }

    rout->outParams = SOAP_CALLOC(soap,1,sizeof(*rout->outParams));
    rout->outParams->__sizeparam = g_hash_table_size(in->out_params);
    rout->outParams->param = SOAP_CALLOC(soap,rout->outParams->__sizeparam,
					sizeof(*rout->outParams->param));
    i = 0;
    g_hash_table_iter_init(&iter,in->out_params);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer *)&param)) {
	a_param_to_x_ParamT(soap,param,&(rout->outParams->param[i]));
	++i;
    }

    return rout;
}

struct analysis_spec *
x_AnalysisSpecT_to_a_analysis_spec(struct soap *soap,
				   struct vmi1__AnalysisSpecT *in,
				   GHashTable *reftab,
				   struct analysis_spec *out) {
    struct analysis_spec *rout;
    struct analysis_name_value *nv;
    int i;
    
    if (out)
	rout = out;
    else
	rout = calloc(1,sizeof(*rout));

    if (in->name)
	rout->name = strdup(in->name);
    if (in->stdinBytes) {
	rout->stdin_bytes_len = in->stdinBytes->__size;
	if (in->stdinBytes->__size) {
	    rout->stdin_bytes = calloc(in->stdinBytes->__size,sizeof(char));
	    memcpy(rout->stdin_bytes,in->stdinBytes->__ptr,in->stdinBytes->__size);
	}
	else
	    rout->stdin_bytes = NULL;
    }

    if (in->logStdout == xsd__boolean__true_)
	rout->log_stdout = 1;
    else
	rout->log_stdout = 0;
    if (in->logStderr == xsd__boolean__true_)
	rout->log_stderr = 1;
    else
	rout->log_stderr = 0;
    if (in->reportStdoutIntermediateResults == xsd__boolean__true_)
	rout->report_stdout_intermediate = 1;
    else
	rout->report_stdout_intermediate = 0;
    if (in->reportStderrIntermediateResults == xsd__boolean__true_)
	rout->report_stderr_intermediate = 1;
    else
	rout->report_stderr_intermediate = 0;
    if (in->autoparseSimpleResults == xsd__boolean__true_)
	rout->autoparse_simple_data = 1;
    else
	rout->autoparse_simple_data = 0;
    if ((in->killOnClose && *in->killOnClose == xsd__boolean__true_)
	|| in->killOnCloseSignal) {
	rout->kill_on_close = 1;
	rout->kill_on_close_sig = 
	    (in->killOnCloseSignal) ? *in->killOnCloseSignal : SIGKILL;
    }

    if (in->inputParams && in->inputParams->__sizenameValue) {
	rout->in_params = array_list_create(in->inputParams->__sizenameValue);
	for (i = 0; i < in->inputParams->__sizenameValue; ++i) {
	    nv = calloc(1,sizeof(*nv));
	    nv->name = strdup(in->inputParams->nameValue[i].nvName);
	    if (in->inputParams->nameValue[i].nvValue)
		nv->value = strdup(in->inputParams->nameValue[i].nvValue);
	}
    }

    return rout;
}
struct vmi1__AnalysisSpecT *
a_analysis_spec_to_x_AnalysisSpecT(struct soap *soap,
				   struct analysis_spec *in,
				   GHashTable *reftab,
				   struct vmi1__AnalysisSpecT *out) {
    struct vmi1__AnalysisSpecT *rout;
    struct analysis_name_value *nv;
    int i;
    
    if (out)
	rout = out;
    else
	rout = calloc(1,sizeof(*rout));

    SOAP_STRCPY(soap,rout->name,in->name);
    if (in->stdin_bytes && in->stdin_bytes_len > 0) {
	rout->stdinBytes = SOAP_CALLOC(soap,in->stdin_bytes_len,sizeof(char));
	memcpy(rout->stdinBytes,in->stdin_bytes,in->stdin_bytes_len);
    }
    if (in->log_stdout)
	rout->logStdout = xsd__boolean__true_;
    else
	rout->logStdout = xsd__boolean__false_;
    if (in->log_stderr)
	rout->logStderr = xsd__boolean__true_;
    else
	rout->logStderr = xsd__boolean__false_;
    if (in->report_stdout_intermediate)
	rout->reportStdoutIntermediateResults = xsd__boolean__true_;
    else
	rout->reportStdoutIntermediateResults = xsd__boolean__false_;
    if (in->report_stderr_intermediate)
	rout->reportStderrIntermediateResults = xsd__boolean__true_;
    else
	rout->reportStderrIntermediateResults = xsd__boolean__false_;
    if (in->autoparse_simple_data)
	rout->autoparseSimpleResults = xsd__boolean__true_;
    else
	rout->autoparseSimpleResults = xsd__boolean__false_;
    rout->killOnClose = SOAP_CALLOC(soap,1,sizeof(*rout->killOnClose));
    if (in->kill_on_close) 
	*rout->killOnClose = xsd__boolean__true_;
    else
	*rout->killOnClose = xsd__boolean__false_;
    if (in->kill_on_close) {
	rout->killOnCloseSignal = 
	    SOAP_CALLOC(soap,1,sizeof(*rout->killOnCloseSignal));
	*rout->killOnCloseSignal = in->kill_on_close_sig;
    }

    rout->inputParams = SOAP_CALLOC(soap,1,sizeof(*rout->inputParams));
    if (in->in_params) {
	rout->inputParams->__sizenameValue = array_list_len(in->in_params);
	if (rout->inputParams->__sizenameValue > 0) {
	    rout->inputParams->nameValue = 
		SOAP_CALLOC(soap,rout->inputParams->__sizenameValue,
			    sizeof(*rout->inputParams->nameValue));
	    array_list_foreach(in->in_params,i,nv) {
		SOAP_STRCPY(soap,rout->inputParams->nameValue[i].nvName,nv->name);
		if (nv->value)
		    SOAP_STRCPY(soap,rout->inputParams->nameValue[i].nvValue,
				nv->value);
	    }
	}
	else 
	    rout->inputParams->nameValue = NULL;
    }
    else {
	rout->inputParams->__sizenameValue = 0;
	rout->inputParams->nameValue = NULL;
    }

    return rout;
}

struct vmi1__AnalysisResultT *
a_analysis_datum_to_x_AnalysisResultT(struct soap *soap,
				      struct analysis_datum *in,
				      struct analysis *analysis,
				      GHashTable *reftab,
				      struct vmi1__AnalysisResultT *out) {
    struct vmi1__AnalysisResultT *rout;
    struct vmi1__SimpleResultT *rs;
    struct vmi1__CustomResultT *rc;
    struct analysis_datum_simple_value *dsv;
    /* struct analysis_datum_typed_value *dtv; */
    int i;

    if (out)
	rout = out;
    else
	rout = calloc(1,sizeof(*rout));

    if (in->is_simple) {
	rout->__union_AnalysisResultT = 
	    SOAP_UNION__vmi1__union_AnalysisResultT_simpleResult;
	rs = rout->union_AnalysisResultT.simpleResult = 
	    SOAP_CALLOC(soap,1,sizeof(*rout->union_AnalysisResultT.simpleResult));

	rout->analysisId = analysis->id;
	rs->id = in->id;
	if (in->name) {
	    SOAP_STRCPY(soap,rs->name,in->name);
	}
	else
	    rs->name = "";
	rs->type = in->type;
	rs->time = in->time;
	rs->tsc = in->tsc;
	rs->counter = in->counter;

	if (in->value) {
	    SOAP_STRCPY(soap,rs->resultValue,in->value);
	}
	else
	    rs->resultValue = "";
	if (in->msg)
	    SOAP_STRCPY(soap,rs->msg,in->msg);

	rs->outputValues = SOAP_CALLOC(soap,1,sizeof(*rs->outputValues));
	rs->outputValues->__sizenameValue = array_list_len(in->values);
	if (rs->outputValues->__sizenameValue > 0) {
	    rs->outputValues->nameValue = 
		SOAP_CALLOC(soap,rs->outputValues->__sizenameValue,
			    sizeof(*rs->outputValues->nameValue));
	    array_list_foreach(in->values,i,dsv) {
		SOAP_STRCPY(soap,rs->outputValues->nameValue[i].nvName,dsv->name);
		if (dsv->value) {
		    SOAP_STRCPY(soap,rs->outputValues->nameValue[i].nvValue,
				dsv->value);
		}
		else
		    rs->outputValues->nameValue[i].nvValue = "";
	    }
	}
    }
    else if (in->is_typed) {
	verror("no typed datum support yet!\n");
	return NULL;
    }
    else {
	rout->__union_AnalysisResultT = 
	    SOAP_UNION__vmi1__union_AnalysisResultT_customResult;
	rc = rout->union_AnalysisResultT.customResult = 
	    SOAP_CALLOC(soap,1,sizeof(*rout->union_AnalysisResultT.customResult));

	rc->id = in->id;
	if (in->name) {
	    SOAP_STRCPY(soap,rc->name,in->name);
	}
	else
	    rc->name = "";
	rc->time = in->time;
	rc->tsc = in->tsc;
	rc->counter = in->counter;

	if (in->value) {
	    SOAP_STRCPY(soap,rc->resultValue,in->value);
	}
	else
	    rc->resultValue = "";
	if (in->msg)
	    SOAP_STRCPY(soap,rc->msg,in->msg);

	/*
	 * XXX: this is broken!  Figure out how to get gsoap to handle
	 * AnyExtension better.
	 */
	if (in->custom) {
	    rc->__size_CustomResultT = 1;
	    rc->__union_CustomResultT = 
		SOAP_CALLOC(soap,1,sizeof(*rc->__union_CustomResultT));
	    rc->__union_CustomResultT[0].__union_CustomResultT = 
		SOAP_UNION__vmi1__union_CustomResultT___any;
	    SOAP_STRCPY(soap,rc->__union_CustomResultT[0].union_CustomResultT.__any,
			in->custom);
	}
    }

    return NULL;
}

struct vmi1__AnalysisResultsT *
a_analysis_datum_list_to_x_AnalysisResultsT(struct soap *soap,
					    struct array_list *in,
					    struct analysis *analysis,
					    GHashTable *reftab,
					    struct vmi1__AnalysisResultsT *out) {
    struct vmi1__AnalysisResultsT *rout;
    struct analysis_datum *d;
    int i;

    if (out)
	rout = out;
    else
	rout = calloc(1,sizeof(*rout));

    rout->__sizeanalysisResult = array_list_len(in);
    if (rout->__sizeanalysisResult > 0) {
	rout->analysisResult = SOAP_CALLOC(soap,rout->__sizeanalysisResult,
					   sizeof(*rout->analysisResult));
	array_list_foreach(in,i,d) {
	    a_analysis_datum_to_x_AnalysisResultT(soap,d,analysis,reftab,
						  &rout->analysisResult[i]);
	}
    }

    return rout;
}

struct analysis_param *x_ParamT_to_a_param(struct soap *soap,
					   struct vmi1__ParamT *in,
					   struct analysis_param *out) {
    struct analysis_param *rout;

    if (out)
	rout = out;
    else
	rout = calloc(1,sizeof(*rout));

    if (in->name)
	rout->name = strdup(in->name);
    if (in->longName)
	rout->long_name = strdup(in->longName);
    if (in->description)
	rout->description = strdup(in->description);
    if (in->defaultValue)
	rout->default_value = strdup(in->defaultValue);

    return rout;
}

struct vmi1__ParamT *a_param_to_x_ParamT(struct soap *soap,	
					 struct analysis_param *in,
					 struct vmi1__ParamT *out) {
    struct vmi1__ParamT *rout;

    if (out)
	rout = out;
    else
	rout = SOAP_CALLOC(soap,1,sizeof(*rout));

    if (in->name)
	SOAP_STRCPY(soap,rout->name,in->name);
    if (in->long_name)
	SOAP_STRCPY(soap,rout->longName,in->long_name);
    if (in->description)
	SOAP_STRCPY(soap,rout->description,in->description);
    if (in->default_value)
	SOAP_STRCPY(soap,rout->defaultValue,in->default_value);

    return rout;
}


struct analysis_name_value *
x_NameValueT_to_a_analysis_name_value(struct soap *soap,
				      struct vmi1__NameValueT *in,
				      struct analysis_name_value *out) {
    struct analysis_name_value *rout;

    if (out)
	rout = out;
    else
	rout = calloc(1,sizeof(*rout));

    if (in->nvName)
	rout->name = strdup(in->nvName);
    if (in->nvValue)
	rout->value = strdup(in->nvValue);

    return rout;
}

struct vmi1__NameValueT *
a_analysis_name_value_to_x_NameValueT(struct soap *soap,	
				      struct analysis_name_value *in,
				      struct vmi1__NameValueT *out) {
    struct vmi1__NameValueT *rout;

    if (out)
	rout = out;
    else
	rout = SOAP_CALLOC(soap,1,sizeof(*rout));

    if (in->name)
	SOAP_STRCPY(soap,rout->nvName,in->name);
    if (in->value)
	SOAP_STRCPY(soap,rout->nvValue,in->value);

    return rout;
}

analysis_status_t 
x_AnalysisStatusT_to_a_analysis_status_t(struct soap *soap,
					 enum vmi1__AnalysisStatusT status,
					 GHashTable *reftab,
					 analysis_status_t *out) {
    analysis_status_t retval;

    switch (status) {
    case vmi1__AnalysisStatusT__unknown:
	retval = ASTATUS_UNKNOWN;
	break;
    case vmi1__AnalysisStatusT__running:
	retval = ASTATUS_RUNNING;
	break;
    case vmi1__AnalysisStatusT__paused:
	retval = ASTATUS_PAUSED;
	break;
    case vmi1__AnalysisStatusT__error:
	retval = ASTATUS_ERROR;
	break;
    case vmi1__AnalysisStatusT__done:
	retval = ASTATUS_DONE;
	break;
    default:
	verror("unknown AnalysisStatusT %d\n",status);
	retval = ASTATUS_UNKNOWN;
	break;
    }

    if (out)
	*out = retval;

    return retval;
}

enum vmi1__AnalysisStatusT 
a_analysis_status_t_to_x_AnalysisStatusT(struct soap *soap,
					 analysis_status_t status,
					 GHashTable *reftab,
					 enum vmi1__AnalysisStatusT *out) {

    enum vmi1__AnalysisStatusT retval;

    switch (status) {
    case ASTATUS_UNKNOWN:
	retval = vmi1__AnalysisStatusT__unknown;
	break;
    case ASTATUS_RUNNING:
	retval = vmi1__AnalysisStatusT__running;
	break;
    case ASTATUS_PAUSED:
	retval = vmi1__AnalysisStatusT__paused;
	break;
    case ASTATUS_ERROR:
	retval = vmi1__AnalysisStatusT__error;
	break;
    case ASTATUS_DONE:
	retval = vmi1__AnalysisStatusT__done;
	break;
    default:
	verror("unknown analysis_status_t %d\n",status);
	retval = vmi1__AnalysisStatusT__unknown;
	break;
    }

    if (out)
	*out = retval;

    return retval;
}
