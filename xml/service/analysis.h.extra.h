
//gsoapopt c

//gsoap vmi1 service name: analysis
//gsoap vmi1 service port: http://anathema.flux.utah.edu/cgi-bin/analysis.cgi
//gsoap vmi1 service namespace: http://anathema.flux.utah.edu/schema/vmi/1

//gsoap vmi1 service method-style: document
//gsoap vmi1 service method-encoding: literal

struct vmi1__availableAnalysesResponse {
    $int __size_analyses;
    struct _vmi1__analysis *analyses;
};

struct vmi1__analysisInstancesResponse {
    $int __size_analysisInstances;
    struct _vmi1__target *analysisInstances;
};

struct vmi1__analysisResponse {
    struct _vmi1__analysisInstance analysisInstance;
};

struct vmi1__analysisStatusResponse {
    enum _vmi1__analysisStatus analysisStatus;
};

struct vmi1__analysisResultsResponse {
    $int __size_analysisResults;
    struct _vmi1__analysis *analysisResults;
};

struct vmi1__analysisAnnotationsResponse {
    $int __size_annotations;
    struct _vmi1__annotation *annotations;
};

int vmi1__listAvailableAnalyses(void *_,
				struct vmi1__availableAnalysesResponse *r);
int vmi1__listAnalysisInstances(void *_,
				struct vmi1__analysisInstancesResponse *r);

int vmi1__createAnalysis(struct _vmi1__targetSpec *targetSpec,
			 vmi1__sessionId *sessionId);
int vmi1__runAnalysis(vmi1__sessionId sessionId,
		      struct vmi1__runAnalysisNoneResponse { } *r);
int vmi1__pauseAnalysis(vmi1__sessionId sessionId,
			struct vmi1__pauseAnalysisNoneResponse { } *r);
int vmi1__endAnalysis(vmi1__sessionId sessionId,
		      struct vmi1__endAnalysisNoneResponse { } *r);

int vmi1__getAnalysis(vmi1__sessionId sessionId,
		      struct vmi1__analysisResponse *r);
int vmi1__getAnalysisStatus(vmi1__sessionId sessionId,
			    struct vmi1__analysisStatusResponse *r);

int vmi1__getAnalysisResults(vmi1__sessionId sessionId,
			     struct vmi1__analysisResultsResponse *r);
int vmi1__pollAnalysisResults(vmi1__sessionId sessionId,
			      struct vmi1__analysisResultsResponse *r);
int vmi1__pollAnalysisAnnotations(vmi1__sessionId sessionId,
				  struct vmi1__analysisAnnotationsResponse *r);
