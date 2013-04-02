
package vmi1;

import java.util.Map;
import org.apache.axis2.engine.MessageReceiver;

public interface SimpleService {
    public Map<String,MessageReceiver> getMessageReceiverClassMap();
    public String getTargetNamespace();
    public String getSchemaNamespace();
}
