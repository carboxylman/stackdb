/*
 * Copyright (c) 2012 The University of Utah
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

int vmi1__listAvailableAnalyses(struct soap *soap,void *_,
				struct vmi1__availableAnalysesResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__listAnalysisInstances(struct soap *soap,void *_,
				struct vmi1__analysisInstancesResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__createAnalysis(struct soap *soap,struct _vmi1__targetSpec *targetSpec,
			 vmi1__sessionId *sessionId) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__runAnalysis(struct soap *soap,vmi1__sessionId sessionId,
		      struct vmi1__runAnalysisNoneResponse  *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__pauseAnalysis(struct soap *soap,vmi1__sessionId sessionId,
			struct vmi1__pauseAnalysisNoneResponse  *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__endAnalysis(struct soap *soap,vmi1__sessionId sessionId,
		      struct vmi1__endAnalysisNoneResponse  *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__getAnalysis(struct soap *soap,vmi1__sessionId sessionId,
		      struct vmi1__analysisResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__getAnalysisStatus(struct soap *soap,vmi1__sessionId sessionId,
			    struct vmi1__analysisStatusResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__getAnalysisResults(struct soap *soap,vmi1__sessionId sessionId,
			     struct vmi1__analysisResultsResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__pollAnalysisResults(struct soap *soap,vmi1__sessionId sessionId,
			      struct vmi1__analysisResultsResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}

int vmi1__pollAnalysisAnnotations(struct soap *soap,vmi1__sessionId sessionId,
				  struct vmi1__analysisAnnotationsResponse *r) {
    return soap_receiver_fault(soap,"Not implemented!","Not implemented!");
}
