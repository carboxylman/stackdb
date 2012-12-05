
#module "anlr" "analysis_rpc_module"

#import "xsdc.gsm.h"
#import "debuginfo_xml.gsm.h"
#import "debuginfo_rpc.gsm.h"
#import "target_xml.gsm.h"
#import "target_rpc.gsm.h"
#import "analysis_xml.gsm.h"

//gsoap vmi1 service name: analysis
//gsoap vmi1 service port: http://anathema.flux.utah.edu/cgi-bin/analysis.cgi
//gsoap vmi1 service namespace: http://anathema.flux.utah.edu/schema/vmi/1

//gsoap vmi1 service method-style: document
//gsoap vmi1 service method-encoding: literal

struct vmi1__AnalysesResponse {
    $int __size_analysis;
    struct vmi1__AnalysisT *analysis;
};

struct vmi1__AnalysisInstancesResponse {
    $int __size_analysisInstance;
    struct vmi1__AnalysisInstanceT *analysisInstance;
};

struct vmi1__AnalysisInstanceResponse {
    struct vmi1__AnalysisInstanceT *analysisInstance;
};

struct vmi1__AnalysisStatusResponse {
    enum vmi1__AnalysisStatusT *analysisStatus;
};

struct vmi1__AnalysisResultsResponse {
    $int __size_analysisResult;
    struct vmi1__AnalysisResultT *analysisResult;
};

struct vmi1__AnalysisAnnotationsResponse {
    $int __size_annotation;
    struct vmi1__AnnotationT *annotation;
};

//gsoap vmi1 service method-documentation: listAvailableAnalyses returns a list of available Analysis objects this service can run against targets. 
int vmi1__listAvailableAnalyses(void *_,
				struct vmi1__AnalysesResponse *r);
//gsoap vmi1 service method-documentation: listAnalysisInstances returns a list of AnalysisInstance objects this service is running.
int vmi1__listAnalysisInstances(void *_,
				struct vmi1__AnalysisInstancesResponse *r);

//gsoap vmi1 service method-documentation: createAnalysis creates an analysis against the given target specification and analysisId, optionally autorunning the target if autorun is true.
int vmi1__createAnalysis(struct vmi1__TargetSpecT *targetSpec,
			 xsd__ID analysisId,enum xsd__boolean autorun,
			 vmi1__SessionIdT *sessionId);
//gsoap vmi1 service method-documentation: runAnalysis runs an analysis that is new or paused.
int vmi1__runAnalysis(vmi1__SessionIdT sessionId,
		      struct vmi1__NoneResponse *r);
//gsoap vmi1 service method-documentation: pauseAnalysis pauses an analysis.
int vmi1__pauseAnalysis(vmi1__SessionIdT sessionId,
			struct vmi1__NoneResponse *r);
//gsoap vmi1 service method-documentation: endAnalysis ends an analysis.
int vmi1__endAnalysis(vmi1__SessionIdT sessionId,
		      struct vmi1__NoneResponse *r);

//gsoap vmi1 service method-documentation: getAnalysis returns an AnalysisInstance that describes the analysis associated with sessionId.
int vmi1__getAnalysis(vmi1__SessionIdT sessionId,
		      struct vmi1__AnalysisInstanceResponse *r);
//gsoap vmi1 service method-documentation: getAnalysisStatus returns the AnalysisStatus associated with sessionId.
int vmi1__getAnalysisStatus(vmi1__SessionIdT sessionId,
			    struct vmi1__AnalysisStatusResponse *r);

//gsoap vmi1 service method-documentation: getAnalysisResults returns results for a finished analysis, or else returns nothing if the analysis is not finished.
int vmi1__getAnalysisResults(vmi1__SessionIdT sessionId,
			     struct vmi1__AnalysisResultsResponse *r);
//gsoap vmi1 service method-documentation: pollAnalysisResults returns any results that the analysis may have reported during its runtime.
int vmi1__pollAnalysisResults(vmi1__SessionIdT sessionId,
			      struct vmi1__AnalysisResultsResponse *r);
//gsoap vmi1 service method-documentation: pollAnalysisAnnotations returns any annotations that the analysis may have reported during its runtime.
int vmi1__pollAnalysisAnnotations(vmi1__SessionIdT sessionId,
				  struct vmi1__AnalysisAnnotationsResponse *r);
