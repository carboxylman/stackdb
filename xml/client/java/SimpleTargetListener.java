
package vmi1;

import vmi1.*;

import java.util.Map;
import java.util.HashMap;
import org.apache.axis2.engine.MessageReceiver;
import javax.jws.WebService;
import javax.jws.WebMethod;
import javax.jws.soap.SOAPBinding;
import javax.xml.namespace.QName;

@WebService(name = "SimpleTargetListener",
	    serviceName="SimpleTargetListener",
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

    @WebMethod(exclude = true)
    public Map<String,MessageReceiver> getMessageReceiverClassMap() {
	if (SimpleTargetListener.messageReceiverClassMap == null) {
	    SimpleTargetListener.messageReceiverClassMap = 
		new HashMap<String,MessageReceiver>();

	    SimpleTargetListener.messageReceiverClassMap. 
		put("vmi1.SimpleTargetListener",
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
	    String jType = "probeEvent";
	    QName qn = new QName(sns,snsPrefix + "." + "ProbeEvent");
	    SimpleTargetListener.typeMapping.put(jType,qn);

	    jType = snsPrefix + "." + "actionEvent";
	    qn = new QName(sns,snsPrefix + "." + "ActionEvent");
	    SimpleTargetListener.typeMapping.put(jType,qn);
	    
	}
	return typeMapping;
    }

    /**
     * Service definition of function vmi1__ProbeEvent
     * @param probeEvent 
     * @return probeEventResponse 
     */
    public vmi1.ProbeEventResponse probeEvent(vmi1.ProbeEventE probeEvent) {
	System.out.println("ProbeEvent");
	return null;
    }

    /**
     * Service definition of function vmi1__ActionEvent
     * @param actionEvent 
     * @return actionEventResponse 
     */
    public vmi1.ActionEventResponse actionEvent(vmi1.ActionEventE actionEvent) {
	System.out.println("ActionEvent");
	return null;
    }

}
