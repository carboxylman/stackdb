
#module "tgtl" "target_listener_module"

#import "xsdc.gsm.h"
#import "target_xml.gsm.h"

//gsoap vmi1 service name: targetListener
//gsoap vmi1 service namespace: http://anathema.flux.utah.edu/schema/vmi/1
//gsoap vmi1 service portName: http
//gsoap vmi1 service port: http://localhost:3952/vmi/1/targetListener

//gsoap vmi1 service method-style: document
//gsoap vmi1 service method-encoding: literal

struct vmi1__ProbeEventNotificationResponse {
    enum vmi1__ResultT result;
    struct vmi1__ActionSpecsT actionSpecs;
};

struct vmi1__ActionEventNotificationResponse {
    enum vmi1__ResultT result;
};

//gsoap vmi1 service method-documentation: 

int vmi1__ProbeEventNotification(struct vmi1__ProbeEventT *probeEvent,
				 struct vmi1__ProbeEventNotificationResponse *r);

int vmi1__ActionEventNotification(struct vmi1__ActionEventT *actionEvent,
				  struct vmi1__ActionEventNotificationResponse *r);
