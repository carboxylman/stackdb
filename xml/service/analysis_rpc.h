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

#ifndef __ANALYSIS_RPC_H__
#define __ANALYSIS_RPC_H__

#include "analysis_rpc_moduleStub.h"

/*
 * Targets as XML SOAP server-monitored objects.
 */
#define MONITOR_OBJTYPE_ANALYSIS 0x09
extern struct monitor_objtype_ops analysis_rpc_monitor_objtype_ops;

void analysis_rpc_init(void);
void analysis_rpc_fini(void);

int analysis_rpc_handle_request(struct soap *soap);


int vmi1__ListAnalysisDescNames(struct soap *soap,
				void *_,
				struct vmi1__AnalysisDescNamesResponse *r);

int vmi1__ListAnalysisDescs(struct soap *soap,
			    void *_,
			    struct vmi1__AnalysisDescsResponse *r);

int vmi1__ListAnalyses(struct soap *soap,
		       void *_,
		       struct vmi1__AnalysesResponse *r);

int vmi1__UploadAnalysis(struct soap *soap,
			 struct vmi1__AnalysisDescT *analysisDesc,
			 struct xsd__hexBinary *inputFileContents,
			 struct vmi1__NoneResponse *r);

int vmi1__InstantiateAnalysis(struct soap *soap,
			      struct vmi1__AnalysisSpecT *analysisSpec,
			      struct vmi1__TargetSpecT *targetSpec,
			      struct vmi1__ListenerT *ownerListener,
			      struct vmi1__AnalysisResponse *r);

int vmi1__PauseAnalysis(struct soap *soap,
			vmi1__AnalysisIdT aid,
			struct vmi1__NoneResponse *r);

int vmi1__ResumeAnalysis(struct soap *soap,
			 vmi1__AnalysisIdT aid,
			 struct vmi1__NoneResponse *r);

int vmi1__CloseAnalysis(struct soap *soap,
			vmi1__AnalysisIdT aid,
			struct vmi1__NoneResponse *r);
int vmi1__KillAnalysis(struct soap *soap,
		       vmi1__AnalysisIdT aid,int kill_sig,
		       struct vmi1__NoneResponse *r);
int vmi1__FinalizeAnalysis(struct soap *soap,
			   vmi1__AnalysisIdT aid,
			   struct vmi1__NoneResponse *r);

int vmi1__GetAnalysis(struct soap *soap,
		      vmi1__AnalysisIdT aid,
		      struct vmi1__AnalysisResponse *r);

int vmi1__GetAnalysisStatus(struct soap *soap,
			    vmi1__AnalysisIdT aid,
			    struct vmi1__AnalysisStatusResponse *r);

int vmi1__GetAnalysisResults(struct soap *soap,
			     vmi1__AnalysisIdT aid,
			     struct vmi1__AnalysisResultsResponse *r);

int vmi1__AnalysisBindListener(struct soap *soap,
			       vmi1__AnalysisIdT aid,vmi1__ListenerT *listener,
			       struct vmi1__NoneResponse *r);
int vmi1__AnalysisUnbindListener(struct soap *soap,
				 vmi1__AnalysisIdT tid,vmi1__ListenerT *listener,
				 struct vmi1__NoneResponse *r);
#endif /* __ANALYSIS_RPC_H__ */
