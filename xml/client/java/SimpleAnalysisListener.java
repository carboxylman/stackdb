
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
 * NB: make sure getAnalysisNamespace and getServiceName return the same
 * values as the annotation!!!
 */
@WebService(name = "analysisListener",
	    serviceName="analysisListener",
            targetNamespace = "http://anathema.flux.utah.edu/schema/vmi/1")

@SOAPBinding(style = SOAPBinding.Style.DOCUMENT,
	     use = SOAPBinding.Use.LITERAL,
	     parameterStyle = SOAPBinding.ParameterStyle.WRAPPED)

public class SimpleAnalysisListener extends AnalysisListenerSkeleton
    implements SimpleService {

    protected static final String tns = 
	"http://anathema.flux.utah.edu/schema/vmi/1";
    protected static final String sns = 
	"http://anathema.flux.utah.edu/schema/vmi/1";
    protected static final String snsPrefix = "vmi1";
    protected static Map<String,MessageReceiver> messageReceiverClassMap = null;
    protected static final String schemaResourcePath = 
	"analysisListener.wsdl";
    protected static Map<String,QName> typeMapping = null;
    protected static Map<String,String> methodClassNameMapping = null;
    protected static Map<String,QName> dynamicTypeMapping = null;

    @WebMethod(exclude = true)
    public Map<String,MessageReceiver> getMessageReceiverClassMap() {
	if (SimpleAnalysisListener.messageReceiverClassMap == null) {
	    SimpleAnalysisListener.messageReceiverClassMap = 
		new HashMap<String,MessageReceiver>();

	    SimpleAnalysisListener.messageReceiverClassMap.
		put(WSDL2Constants.MEP_URI_IN_OUT, //"vmi1.SimpleAnalysisListener",
		    new vmi1.AnalysisListenerMessageReceiverInOut());
	}
	return SimpleAnalysisListener.messageReceiverClassMap;
    }

    @WebMethod(exclude = true)
    public String getTargetNamespace() {
	return SimpleAnalysisListener.tns;
    }

    @WebMethod(exclude = true)
    public String getSchemaNamespace() {
	return SimpleAnalysisListener.sns;
    }

    @WebMethod(exclude = true)
    public String getSchemaNamespacePrefix() {
	return SimpleAnalysisListener.snsPrefix;
    }

    @WebMethod(exclude = true)
    public String getSchemaResourcePath() {
	return SimpleAnalysisListener.schemaResourcePath;
    }

    @WebMethod(exclude = true)
    public Map<String,QName> getStaticTypeMapping() {
	if (SimpleAnalysisListener.typeMapping == null) {
	    SimpleAnalysisListener.typeMapping = new HashMap<String,QName>();

	    //String jType = snsPrefix + "." + "probeEvent";
	    /*
	    String jType = "probeEventNotification";
	    QName qn = new QName(sns,"ProbeEventNotification");
	    SimpleAnalysisListener.typeMapping.put(jType,qn);

	    jType = snsPrefix + "." + "actionEventNotification";
	    qn = new QName(sns,"ActionEventNotification");
	    SimpleAnalysisListener.typeMapping.put(jType,qn);
	    */
	}
	return typeMapping;
    }

    @WebMethod(exclude = true)
    public Map<String,String> getMethodClassNameMapping() {
	if (SimpleAnalysisListener.methodClassNameMapping == null) {
	    SimpleAnalysisListener.methodClassNameMapping = 
		new HashMap<String,String>();

	    SimpleAnalysisListener.methodClassNameMapping
		.put("analysisEventNotification","vmi.AnalysisEventNotification");
	    SimpleAnalysisListener.methodClassNameMapping
		.put("analysisResultNotification","vmi.AnalysisResultNotification");
	}
	return methodClassNameMapping;
    }

    @WebMethod(exclude = true)
    public Map<String,QName> getDynamicTypeMapping() {
	if (SimpleAnalysisListener.dynamicTypeMapping == null) {
	    SimpleAnalysisListener.dynamicTypeMapping = 
		new HashMap<String,QName>();

	    SimpleAnalysisListener.dynamicTypeMapping
		.put("analysisEventNotification",
		     new QName(SimpleAnalysisListener.sns,"AnalysisEventNotification"));
	    SimpleAnalysisListener.dynamicTypeMapping
		.put("analysisResultNotification",
		     new QName(SimpleAnalysisListener.sns,"AnalysisResultNotification"));
	}
	return dynamicTypeMapping;
    }

    @WebMethod(exclude = true)
    public boolean isRootService() {
	return true;
    }

    @WebMethod(exclude = true)
    public String getServiceName() {
	return "analysisListener";
    }

    @WebMethod(exclude = true)
    public String getServicePath() {
	return "/vmi1/analysisListener";
    }

    public vmi1.AnalysisResultNotificationResponse analysisResultNotification
	(vmi1.AnalysisResultNotification analysisResultNotification) {

	AnalysisResultT e = analysisResultNotification.getResult();

	if (e.isSimpleResultSpecified()) {
	    vmi1.SimpleResultT r = e.getSimpleResult();

	    System.out.printf("SimpleResult(id=%d,name=%s,type=%d,time=%d,tsc=%d,counter=%d)\n",
			      r.getId(),r.getName(),r.getType(),
			      r.getTime().longValue(),r.getTsc().longValue(),
			      r.getCounter().longValue());
	    System.out.printf("    value=%s msg=%s\n",r.getResultValue(),
			      r.getMsg());
	    if (r.getOutputValues() != null) {
		vmi1.OutputValues_type0 ov = r.getOutputValues();
		if (ov != null) {
		    vmi1.NameValueT[] ova = ov.getNameValue();
		    if (ova != null) {
			if (ova.length > 0)
			    System.out.printf("    ");
			for (int i = 0; i < ova.length; ++i) {
			    System.out.printf("%s=%s ",ova[i].getNvName(),
					      ova[i].getNvValue());
			}
			if (ova.length > 0)
			    System.out.println();
		    }
		}
	    }
	}
	else if (e.isCustomResultSpecified()) {
	    vmi1.CustomResultT r = e.getCustomResult();


	}
	else {
	    System.out.printf("Unknown AnalysisResultT!\n");
	}

	vmi1.AnalysisResultNotificationResponse retval = 
	    new vmi1.AnalysisResultNotificationResponse();
	retval.setResult(vmi1.ResultT.success);
	return retval;
    }

    public vmi1.AnalysisEventNotificationResponse analysisEventNotification
	(vmi1.AnalysisEventNotification analysisEventNotification) {

	AnalysisEventT e = analysisEventNotification.getAnalysisEvent();

	System.out.printf("AnalysisEvent(id=%d,type=%s)\n",
			  e.getAnalysisId(),e.getAnalysisEventType().toString());

	vmi1.AnalysisEventNotificationResponse retval = 
	    new vmi1.AnalysisEventNotificationResponse();
	retval.setResult(vmi1.ResultT.success);
	return retval;
    }
}
