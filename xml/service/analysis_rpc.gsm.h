
#module "anlr" "analysis_rpc_module"

#import "xsdc.gsm.h"
#import "debuginfo_xml.gsm.h"
#import "debuginfo_rpc.gsm.h"
#import "target_xml.gsm.h"
#import "target_rpc.gsm.h"
#import "analysis_xml.gsm.h"

//gsoap vmi1 service name: analysis
//gsoap vmi1 service namespace: http://anathema.flux.utah.edu/schema/vmi/1

//gsoap vmi1 service method-style: document
//gsoap vmi1 service method-encoding: literal

struct vmi1__AnalysisDescNamesResponse {
    $int __size_analysisDescName;
    char **analysisDescName;
};

struct vmi1__AnalysisDescsResponse {
    $int __size_analysisDesc;
    struct vmi1__AnalysisDescT *analysisDesc;
};

struct vmi1__AnalysesResponse {
    $int __size_analysis;
    struct vmi1__AnalysisT *analysis;
};

struct vmi1__AnalysisResponse {
    struct vmi1__AnalysisT *analysis;
};

struct vmi1__AnalysisStatusResponse {
    enum vmi1__AnalysisStatusT analysisStatus;
};

struct vmi1__AnalysisResultsResponse {
    struct vmi1__AnalysisResultsT analysisResults;
};

// gsoap vmi1 service method-documentation: ListAnalysisDescNames
//   returns a list of available Analysis object names.
int vmi1__ListAnalysisDescNames(void *_,
				struct vmi1__AnalysisDescNamesResponse *r);

// gsoap vmi1 service method-documentation: ListAnalysisDescs
//   returns a list of available AnalysisDesc objects this
//   service can run against targets.
int vmi1__ListAnalysisDescs(void *_,
			    struct vmi1__AnalysisDescsResponse *r);

// gsoap vmi1 service method-documentation: ListAnalyses
//   returns a list of Analysis objects this service is running. 
int vmi1__ListAnalyses(void *_,
		       struct vmi1__AnalysesResponse *r);

// gsoap vmi1 service method-documentation: UploadAnalysis uploads a
//   new analysis.
int vmi1__UploadAnalysis(struct vmi1__AnalysisDescT *analysisDesc,
			 struct xsd__hexBinary *inputFileContents,
			 struct vmi1__NoneResponse *r);

// gsoap vmi1 service method-documentation: InstantiateAnalysis runs an analysis
//   against the given target specification and analysis specification,
//   optionally autorunning the target if autorun is true. 
int vmi1__InstantiateAnalysis(struct vmi1__AnalysisSpecT *analysisSpec,
			      struct vmi1__TargetSpecT *targetSpec,
			      struct vmi1__ListenerT *ownerListener,
			      struct vmi1__AnalysisResponse *r);

// gsoap vmi1 service method-documentation: PauseAnalysis pauses an
//   analysis if the analysis supports external control.
int vmi1__PauseAnalysis(vmi1__AnalysisIdT aid,
			struct vmi1__NoneResponse *r);

// gsoap vmi1 service method-documentation: ResumeAnalysis pauses an
//   analysis if the analysis supports external control.
int vmi1__ResumeAnalysis(vmi1__AnalysisIdT aid,
			 struct vmi1__NoneResponse *r);

// gsoap vmi1 service method-documentation: EndAnalysis ends an analysis.
int vmi1__CloseAnalysis(vmi1__AnalysisIdT aid,
			struct vmi1__NoneResponse *r);
int vmi1__KillAnalysis(vmi1__AnalysisIdT aid,int kill_sig,
		       struct vmi1__NoneResponse *r);
int vmi1__FinalizeAnalysis(vmi1__AnalysisIdT aid,
			   struct vmi1__NoneResponse *r);

// gsoap vmi1 service method-documentation: GetAnalysis returns an Analysis.
int vmi1__GetAnalysis(vmi1__AnalysisIdT aid,
		      struct vmi1__AnalysisResponse *r);

// gsoap vmi1 service method-documentation: GetAnalysisStatus returns
//   the AnalysisStatus associated with aid 
int vmi1__GetAnalysisStatus(vmi1__AnalysisIdT aid,
			    struct vmi1__AnalysisStatusResponse *r);

// gsoap vmi1 service method-documentation: GetAnalysisResults returns
//   results for an analysis.
int vmi1__GetAnalysisResults(vmi1__AnalysisIdT aid,
			     struct vmi1__AnalysisResultsResponse *r);

int vmi1__AnalysisBindListener(vmi1__AnalysisIdT aid,vmi1__ListenerT *listener,
			     struct vmi1__NoneResponse *r);
int vmi1__AnalysisUnbindListener(vmi1__AnalysisIdT tid,vmi1__ListenerT *listener,
			       struct vmi1__NoneResponse *r);
