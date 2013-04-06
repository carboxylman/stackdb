
package vmi1;

import java.util.Map;
import org.apache.axis2.engine.MessageReceiver;
import javax.xml.namespace.QName;

public interface SimpleService {
    /**
     * This tells the SimpleServiceServer which MessageReceiver this
     * service requires.  Then it can tell Axis.
     *
     * Note, you must use special strings as the keys in the map.  They
     * come from org.apache.axis2.description.WSDL2Constants, and which
     * one you use depends on whether your service operations do in/out
     * messages, in-only, out-only, etc.
     *
     * Probably just use WSDL2Constants.MEP_URI_IN_OUT because you'll
     * probably have service operations that do both input/output.
     *
     * Unfortunately, there doesn't seem to be any of this information
     * inside the MessageReceiver object itself, or I would have just
     * used that!
     */
    public Map<String,MessageReceiver> getMessageReceiverClassMap();

    /**
     * Return the target namespace.  If you use JSR-181 web service
     * annotations, **make sure** this is the same thing as in your
     * annotation!
     */
    public String getTargetNamespace();

    /**
     * Return the schema namespace in your WSDL file.  If you use
     * JSR-181 web service annotations, **make sure** this is the same
     * thing as in your annotation!
     *
     * If this is not the same as getTargetNamespace(), everything will
     * probably break.  So don't do it!
     */
    public String getSchemaNamespace();

    /**
     * Return the schema namespace prefix.
     */
    public String getSchemaNamespacePrefix();

    /**
     * Right now, this must be a relative JAR path to a WSDL file.
     */
    public String getSchemaResourcePath();

    /**
     * Return the service name.  If you return null, we will just use
     * the name of the class that implements this interface; this will
     * probably fail.  You must use a real service name that corresponds
     * to a WSDL service location.  This should be the last thing in the
     * WSDL location path, too; i.e., the part after the final '/'.
     * 
     * Also, if you use JSR-181 web service annotations, **make sure**
     * this is the same thing as in your annotation!
     */
    public String getServiceName();

    /**
     * Don't use this right now; just provide an empty HashMap.
     */
    public Map<String,QName> getStaticTypeMapping();

    /**
     * Basically, if your web service RPCs start with an uppercase
     * letter, and you use Axis to generate your service skeleton, it
     * will lowercase the letter -- BUT it will generate a class
     * representing that RPC SOAP message with the letter still
     * uppercased!  So, we have to map between these things.
     *
     * So, return a HashMap of lowercase service method name to
     * fully-qualified class name for the message that calls it.  i.e.,
     *
     *   probeEventNotification -> vmi1.ProbeEventNotification
     *
     * etc.
     */
    public Map<String,String> getMethodClassNameMapping();

    /**
     * Basically, if your web service RPCs start with an uppercase
     * letter, and you use Axis to generate your service skeleton, it
     * will lowercase the letter -- BUT it will generate a class
     * representing that RPC SOAP message with the letter still
     * uppercased!  So, we have to map between these things.
     *
     * We *also* have to map them to XML schema elements.  This function
     * does this!
     *
     * So, return a HashMap of lowercase service method name to
     * fully-qualified class name for the message that calls it.  i.e.,
     *
     *   probeEventNotification -> new QName(getTargetNamespace(),
     *                                       "ProbeEventNotification")
     *
     * etc.
     *
     * (The dynamic type map is only consulted for methods right now;
     * but we could extend it!)
     */
    public Map<String,QName> getDynamicTypeMapping();
}
