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

#include "analysis_rpc.h"

#include "util.h"
#include "analysis_xml.h"
#include "target_xml.h"

#include "analysis.h"

void analysis_rpc_init(void) {
    return;
}

void analysis_rpc_fini(void) {
    return;
}

int vmi1__ListAnalysisDescNames(struct soap *soap,
				void *_,
				struct vmi1__AnalysisDescNamesResponse *r) {
    struct array_list *names;
    char *name;
    int i;

    names = analysis_list_names();
    if (names && array_list_len(names) > 0) {
	r->__size_analysisDescName = array_list_len(names);
	r->analysisDescName = 
	    SOAP_CALLOC(soap,r->__size_analysisDescName,sizeof(char *));

	array_list_foreach(names,i,name) {
	    SOAP_STRCPY(soap,r->analysisDescName[i],name);
	}
    }
    else {
	r->__size_analysisDescName = 0;
	r->analysisDescName = NULL;
    }

    return SOAP_OK;
}

int vmi1__ListAnalysisDescs(struct soap *soap,
			    void *_,
			    struct vmi1__AnalysisDescsResponse *r) {
    struct array_list *descs;
    struct analysis_desc *desc;
    int i;
    GHashTable *reftab;

    descs = analysis_load_all();
    if (descs && array_list_len(descs) > 0) {
	r->__size_analysisDesc = array_list_len(descs);
	r->analysisDesc = 
	    SOAP_CALLOC(soap,r->__size_analysisDesc,sizeof(*r->analysisDesc));

	reftab = g_hash_table_new(g_direct_hash,g_direct_equal);
	array_list_foreach(descs,i,desc) {
	    a_analysis_desc_to_x_AnalysisDescT(soap,desc,reftab,
					       &r->analysisDesc[i]);
	}
	g_hash_table_destroy(reftab);
		
    }
    else {
	r->__size_analysisDesc = 0;
	r->analysisDesc = NULL;
    }

    return SOAP_OK;
}

int vmi1__ListAnalyses(struct soap *soap,
		       void *_,
		       struct vmi1__AnalysesResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__UploadAnalysis(struct soap *soap,
			 struct vmi1__AnalysisDescT *analysisDesc,
			 struct xsd__hexBinary *inputFileContents,
			 struct vmi1__NoneResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__RunAnalysis(struct soap *soap,
		      struct vmi1__AnalysisSpecT analysisSpec,
		      struct vmi1__TargetSpecT *targetSpec,
		      enum xsd__boolean autorun,
		      struct vmi1__AnalysisResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__PauseAnalysis(struct soap *soap,
			vmi1__AnalysisIdT aid,
			struct vmi1__NoneResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__ResumeAnalysis(struct soap *soap,
			 vmi1__AnalysisIdT aid,
			 struct vmi1__NoneResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__EndAnalysis(struct soap *soap,
		      vmi1__AnalysisIdT aid,
		      struct vmi1__NoneResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__GetAnalysis(struct soap *soap,
		      vmi1__AnalysisIdT aid,
		      struct vmi1__AnalysisResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__GetAnalysisStatus(struct soap *soap,
			    vmi1__AnalysisIdT aid,
			    struct vmi1__AnalysisStatusResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__GetAnalysisResults(struct soap *soap,
			     vmi1__AnalysisIdT aid,
			     struct vmi1__AnalysisResultsResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__RegisterAnalysisListener(struct soap *soap,
				   vmi1__AnalysisIdT aid,
				   char *host,int port,enum xsd__boolean ssl,
				   struct vmi1__NoneResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}
int vmi1__UnregisterAnalysisListener(struct soap *soap,
				     vmi1__AnalysisIdT tid,
				     char *host,int port,
				     struct vmi1__NoneResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}
