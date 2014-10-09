
package vmi1;

import vmi1.*;

import java.util.Map;
import java.util.HashMap;
import org.apache.axis2.engine.MessageReceiver;
import javax.jws.WebService;
import javax.jws.WebMethod;
import javax.jws.soap.SOAPBinding;
import javax.xml.namespace.QName;

import org.apache.axis2.description.WSDL2Constants;

/*
 * NB: make sure getTargetNamespace and getServiceName return the same
 * values as the annotation!!!
 */
@WebService(name = "targetListener",
	    serviceName="targetListener",
            targetNamespace = "http://anathema.flux.utah.edu/schema/vmi/1")

@SOAPBinding(style = SOAPBinding.Style.DOCUMENT,
	     use = SOAPBinding.Use.LITERAL,
	     parameterStyle = SOAPBinding.ParameterStyle.WRAPPED)

public class SimpleTargetListener extends TargetListenerSkeleton
    implements SimpleService {

    protected static final String tns = 
	"http://anathema.flux.utah.edu/schema/vmi/1";
    protected static final String sns = 
	"http://anathema.flux.utah.edu/schema/vmi/1";
    protected static final String snsPrefix = "vmi1";
    protected static Map<String,MessageReceiver> messageReceiverClassMap = null;
    protected static final String schemaResourcePath = 
	"targetListener.wsdl";
    protected static Map<String,QName> typeMapping = null;
    protected static Map<String,String> methodClassNameMapping = null;
    protected static Map<String,QName> dynamicTypeMapping = null;

    @WebMethod(exclude = true)
    public Map<String,MessageReceiver> getMessageReceiverClassMap() {
	if (SimpleTargetListener.messageReceiverClassMap == null) {
	    SimpleTargetListener.messageReceiverClassMap = 
		new HashMap<String,MessageReceiver>();

	    SimpleTargetListener.messageReceiverClassMap.
		put(WSDL2Constants.MEP_URI_IN_OUT, //"vmi1.SimpleTargetListener",
		    new vmi1.TargetListenerMessageReceiverInOut());
	}
	return SimpleTargetListener.messageReceiverClassMap;
    }

    @WebMethod(exclude = true)
    public String getTargetNamespace() {
	return SimpleTargetListener.tns;
    }

    @WebMethod(exclude = true)
    public String getSchemaNamespace() {
	return SimpleTargetListener.sns;
    }

    @WebMethod(exclude = true)
    public String getSchemaNamespacePrefix() {
	return SimpleTargetListener.snsPrefix;
    }

    @WebMethod(exclude = true)
    public String getSchemaResourcePath() {
	return SimpleTargetListener.schemaResourcePath;
    }

    @WebMethod(exclude = true)
    public Map<String,QName> getStaticTypeMapping() {
	if (SimpleTargetListener.typeMapping == null) {
	    SimpleTargetListener.typeMapping = new HashMap<String,QName>();

	    //String jType = snsPrefix + "." + "probeEvent";
	    /*
	    String jType = "targetEventNotification";
	    QName qn = new QName(sns,"TargetEventNotification");
	    SimpleTargetListener.typeMapping.put(jType,qn);

	    String jType = "probeEventNotification";
	    QName qn = new QName(sns,"ProbeEventNotification");
	    SimpleTargetListener.typeMapping.put(jType,qn);

	    jType = snsPrefix + "." + "actionEventNotification";
	    qn = new QName(sns,"ActionEventNotification");
	    SimpleTargetListener.typeMapping.put(jType,qn);
	    */
	}
	return typeMapping;
    }

    @WebMethod(exclude = true)
    public Map<String,String> getMethodClassNameMapping() {
	if (SimpleTargetListener.methodClassNameMapping == null) {
	    SimpleTargetListener.methodClassNameMapping = 
		new HashMap<String,String>();

	    SimpleTargetListener.methodClassNameMapping
		.put("targetEventNotification","vmi.TargetEventNotification");
	    SimpleTargetListener.methodClassNameMapping
		.put("probeEventNotification","vmi.ProbeEventNotification");
	    SimpleTargetListener.methodClassNameMapping
		.put("actionEventNotification","vmi.ActionEventNotification");
	}
	return methodClassNameMapping;
    }

    @WebMethod(exclude = true)
    public Map<String,QName> getDynamicTypeMapping() {
	if (SimpleTargetListener.dynamicTypeMapping == null) {
	    SimpleTargetListener.dynamicTypeMapping = 
		new HashMap<String,QName>();

	    SimpleTargetListener.dynamicTypeMapping
		.put("targetEventNotification",
		     new QName(SimpleTargetListener.sns,"TargetEventNotification"));
	    SimpleTargetListener.dynamicTypeMapping
		.put("probeEventNotification",
		     new QName(SimpleTargetListener.sns,"ProbeEventNotification"));
	    SimpleTargetListener.dynamicTypeMapping
		.put("actionEventNotification",
		     new QName(SimpleTargetListener.sns,"ActionEventNotification"));
	}
	return dynamicTypeMapping;
    }

    @WebMethod(exclude = true)
    public boolean isRootService() {
	return true;
    }

    @WebMethod(exclude = true)
    public String getServiceName() {
	return "targetListener";
    }

    @WebMethod(exclude = true)
    public String getServicePath() {
	return "/vmi1/targetListener";
    }

    /**
     * Service definition of function vmi1__TargetEventNotification
     * @param targetEventNotification 
     * @return targetEventNotificationResponse 
     */
    public vmi1.TargetEventNotificationResponse targetEventNotification
	(vmi1.TargetEventNotification targetEventNotification) {
	TargetEventT te = targetEventNotification.getTargetEvent();

	System.out.printf("TargetEvent(%s tid=%d thid=%d status=%s)\n"
			  + "    msg: \"%s\"\n\n",
			  te.getTargetEventType(),te.getTid().getTargetIdT(),
			  te.getThid().getThreadIdT(),te.getTargetStatus(),
			  te.getEventMsg());

	vmi1.TargetEventNotificationResponse retval = 
	    new vmi1.TargetEventNotificationResponse();
	retval.setResult(vmi1.ResultT.success);
	return retval;
    }

    /**
     * Service definition of function vmi1__ProbeEvent
     * @param probeEvent 
     * @return probeEventResponse 
     */
    public vmi1.ProbeEventNotificationResponse probeEventNotification
	(vmi1.ProbeEventNotification probeEventNotification) {
	ProbeEventT pe = probeEventNotification.getProbeEvent();
	ProbeT probe = pe.getProbe();
	ThreadT thread = pe.getThread();
	RegisterValueT[] rva = pe.getRegisterValues().getRegisterValue();
	
	System.out.printf("ProbeEvent(%s name=%s id=%d addr=0x%x,type=%s,"
			  + "style=%s,whence=%s,size=%s)\n",
			  pe.getProbeEventType(),probe.getName(),
			  probe.getPid().getProbeIdT(),
			  probe.getAddr().getADDR().longValue(),
			  probe.getType(),probe.getStyle(),probe.getWhence(),
			  probe.getPsize());

	System.out.printf("  thread: %d %s\n",
			  thread.getThid().getThreadIdT(),
			  thread.getThreadStatus());

	System.out.printf("  registers:\n");
	for (int i = 0; i < rva.length; ++i) {
	    System.out.printf("    %7.7s 0x%x\n",
			      rva[i].getName(),rva[i].getValue().longValue());
	}
	System.out.println("");

	vmi1.ProbeEventNotificationResponse retval = 
	    new vmi1.ProbeEventNotificationResponse();
	retval.setResult(vmi1.ResultT.success);
	return retval;
    }

    /**
     * Service definition of function vmi1__ActionEvent
     * @param actionEvent 
     * @return actionEventResponse 
     */
    public vmi1.ActionEventNotificationResponse actionEventNotification
	(vmi1.ActionEventNotification actionEventNotification) {
	System.out.println("ActionEventNotification " + actionEventNotification);
	vmi1.ActionEventNotificationResponse retval = 
	    new vmi1.ActionEventNotificationResponse();
	retval.setResult(vmi1.ResultT.success);
	return retval;
    }

}
