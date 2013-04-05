
package vmi1;

import java.util.Map;
import org.apache.axis2.engine.MessageReceiver;
import javax.xml.namespace.QName;

public interface SimpleService {
    public Map<String,MessageReceiver> getMessageReceiverClassMap();
    public String getTargetNamespace();
    public String getSchemaNamespace();
    public String getSchemaNamespacePrefix();
    public String getSchemaResourcePath();
    public Map<String,QName> getStaticTypeMapping();
}
