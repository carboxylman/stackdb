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

void analysis_rpc_init(void) {
    return;
}

void analysis_rpc_fini(void) {
    return;
}

int vmi1__ListAvailableAnalyses(struct soap *soap,void *_,
				struct vmi1__AnalysesResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__ListAnalysisInstances(struct soap *soap,void *_,
				struct vmi1__AnalysisInstancesResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__CreateAnalysis(struct soap *soap,struct vmi1__TargetSpecT *targetSpec,
			 xsd__ID analysisId,enum xsd__boolean autorun,
			 vmi1__SessionIdT *sessionId) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__RunAnalysis(struct soap *soap,vmi1__SessionIdT sessionId,
		      struct vmi1__NoneResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__PauseAnalysis(struct soap *soap,vmi1__SessionIdT sessionId,
			struct vmi1__NoneResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__EndAnalysis(struct soap *soap,vmi1__SessionIdT sessionId,
		      struct vmi1__NoneResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__GetAnalysis(struct soap *soap,vmi1__SessionIdT sessionId,
		      struct vmi1__AnalysisInstanceResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__GetAnalysisStatus(struct soap *soap,vmi1__SessionIdT sessionId,
			    struct vmi1__AnalysisStatusResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__GetAnalysisResults(struct soap *soap,vmi1__SessionIdT sessionId,
			     struct vmi1__AnalysisResultsResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__PollAnalysisResults(struct soap *soap,vmi1__SessionIdT sessionId,
			      struct vmi1__AnalysisResultsResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__PollAnalysisAnnotations(struct soap *soap,vmi1__SessionIdT sessionId,
				  struct vmi1__AnalysisAnnotationsResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}
