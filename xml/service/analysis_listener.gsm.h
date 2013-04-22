
#module "anll" "analysis_listener_module"

#import "xsdc.gsm.h"
#import "analysis_xml.gsm.h"

//gsoap vmi1 service name: analysisListener
//gsoap vmi1 service namespace: http://anathema.flux.utah.edu/schema/vmi/1
//gsoap vmi1 service portName: http
//gsoap vmi1 service port: http://localhost:3953/vmi/1/analysisListener

//gsoap vmi1 service method-style: document
//gsoap vmi1 service method-encoding: literal

struct vmi1__AnalysisEventNotificationResponse {
    enum vmi1__ResultT result;
};

struct vmi1__AnalysisResultNotificationResponse {
    enum vmi1__ResultT result;
};

// gsoap vmi1 service method-documentation: 
int vmi1__AnalysisEventNotification(struct vmi1__AnalysisEventT *analysisEvent,
				    struct vmi1__AnalysisEventNotificationResponse *r);

// gsoap vmi1 service method-documentation: 
int vmi1__AnalysisResultNotification(struct vmi1__AnalysisResultT *result,
				     struct vmi1__AnalysisResultNotificationResponse *r);
