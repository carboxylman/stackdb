
package vmi1;

import vmi1.*;

import java.util.Map;
import java.util.HashMap;
import org.apache.axis2.engine.MessageReceiver;

public class SimpleTargetListener extends TargetListenerSkeleton 
    implements SimpleService {

    protected static final String tns = 
	"http://anathema.flux.utah.edu/schema/vmi/1";
    protected static final String sns = 
	"http://anathema.flux.utah.edu/schema/vmi/1";
    protected static Map<String,MessageReceiver> messageReceiverClassMap = null;

    public Map<String,MessageReceiver> getMessageReceiverClassMap() {
	if (SimpleTargetListener.messageReceiverClassMap == null) {
	    SimpleTargetListener.messageReceiverClassMap = new HashMap<String,MessageReceiver>();
	    SimpleTargetListener.messageReceiverClassMap. 
		put("vmi1.SimpleTargetListener",
		    new vmi1.TargetListenerMessageReceiverInOut());
	}
	return SimpleTargetListener.messageReceiverClassMap;
    }

    public String getTargetNamespace() {
	return SimpleTargetListener.tns;
    }

    public String getSchemaNamespace() {
	return SimpleTargetListener.sns;
    }

    /**
     * Service definition of function vmi1__ProbeEvent
     * @param probeEvent 
     * @return probeEventResponse 
     */
    public vmi1.ProbeEventResponse probeEvent(vmi1.ProbeEventE probeEvent) {
	System.out.println("probeEvent");
	return null;
    }

    /**
     * Service definition of function vmi1__ActionEvent
     * @param actionEvent 
     * @return actionEventResponse 
     */
    public vmi1.ActionEventResponse actionEvent(vmi1.ActionEventE actionEvent) {
	System.out.println("actionEvent");
	return null;
    }

}
