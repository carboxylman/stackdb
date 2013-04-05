
package vmi1;

import java.io.InputStream;
import java.util.Collection;
import java.util.Set;
import java.util.Map;
import java.util.Iterator;

import java.net.URL;

/* Failed wsdl4j attempt; cannot access the DOM to read XmlSchemas from WSDL */
/*
import javax.wsdl.factory.WSDLFactory;
import javax.wsdl.xml.WSDLReader;
import javax.wsdl.Definition;
import javax.wsdl.extensions.ExtensibilityElement;
*/

/* Failed woden attempt; woden does not support wsdl 1.x */
/*
import org.apache.woden.*;
import org.apache.woden.schema.*;
*/

/* Success: read from the document directly; WSDLs are simple! */
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Element;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.namespace.QName;

import org.apache.axis2.jaxrs.JAXRSUtils;
import org.apache.axis2.jaxrs.JAXRSModel;

import org.apache.axis2.description.java2wsdl.SchemaGenerator;
import org.apache.axis2.description.java2wsdl.DefaultSchemaGenerator;

import org.apache.ws.commons.schema.resolver.DefaultURIResolver;

import org.apache.ws.commons.schema.*;
import org.apache.axis2.deployment.util.Utils;

import org.apache.axis2.description.AxisService;

import org.apache.axis2.jsr181.JSR181Helper;
import org.apache.axis2.jsr181.WebMethodAnnotation;
import org.apache.axis2.jsr181.WebParamAnnotation;
import org.apache.axis2.jsr181.WebResultAnnotation;
import org.apache.axis2.jsr181.WebServiceAnnotation;

public class ResourceSchemaGenerator extends DefaultSchemaGenerator {
    protected Class resourceClass;
    protected String resourceSchemaLocation = null;
    protected Map<String,QName> typeMapping = null;

    public ResourceSchemaGenerator(ClassLoader loader,String className,
				   String resourceSchemaLocation,
				   Class resourceClass,
				   String schemaTargetNamespace,
				   String schemaTargetNamespacePrefix,
				   Map<String,QName> typeMapping,
				   AxisService service)
	throws Exception {

	super(loader,className,schemaTargetNamespace,schemaTargetNamespacePrefix,
	      service);

	this.resourceSchemaLocation = resourceSchemaLocation;
	this.resourceClass = resourceClass;
	this.typeMapping = typeMapping;
    }

    public Collection<XmlSchema> generateSchema() throws Exception {
	/*
        WebServiceAnnotation wsa =
	    JSR181Helper.INSTANCE.getWebServiceAnnotation(serviceClass);
        if (wsa != null) {
            String tns = wsa.getTargetNamespace();
            if (tns != null && !"".equals(tns)) {
                targetNamespace = tns;
		if (this.schemaTargetNameSpace == null)
		    this.schemaTargetNameSpace = tns;
            }
	    if (service != null 
		&& (service.getName() == null || service.getName().equals("")))
		service.setName(Utils.getAnnotatedServiceName(serviceClass,wsa));
        }
*/

	if (resourceSchemaLocation == null)
	    return super.generateSchema();

	try {
	    InputStream ris = null;
	    URL rurl = null;

	    if (java.lang.Thread.currentThread().getContextClassLoader() != null) {
		ClassLoader cl = java.lang.Thread.currentThread().getContextClassLoader();
		rurl = cl.getResource(resourceSchemaLocation);
		System.err.println("DEBUG: " + rurl);
		ris = cl.getResourceAsStream(resourceSchemaLocation);
	    }
	    else if (resourceClass != null) {
		rurl = resourceClass.getResource(resourceSchemaLocation);
		System.err.println("DEBUG: " + rurl);
		ris = resourceClass.getResourceAsStream(resourceSchemaLocation);
	    }
	    else if (classLoader != null) {
		rurl = classLoader.getResource(resourceSchemaLocation);
		System.err.println("DEBUG: " + rurl);
		ris = classLoader.getResourceAsStream(resourceSchemaLocation);
	    }
	    else {
		rurl = ClassLoader.getSystemResource(resourceSchemaLocation);
		System.err.println("DEBUG: " + rurl);
		ris = ClassLoader.getSystemResourceAsStream(resourceSchemaLocation);
	    }

	    /*
	     * Linkage with wsdl4j that amounts to nothing because
	     * wsdl4j gives no access to the DOM underneath.
	     */
	    /*
	    URLWSDLLocator wl = new URLWSDLLocator(rurl);
	    WSDLFactory wf = WSDLFactory.newInstance();
	    WSDLReader wr = wf.newWSDLReader();
	    Definition wd = wr.readWSDL(wl);
	    //Document doc = wd.getTypes().
	    Iterator<ExtensibilityElement> eei = (Iterator<ExtensibilityElement>)wd.getTypes().getExtensibilityElements().iterator();
	    while (eei.hasNext()) {
		ExtensibilityElement ee = eei.next();
		System.err.println("DEBUG: wsdl type qname = " + ee);
		if (eei instanceof javax.wsdl.extensions.schema.Schema)
		    System.err.println("DEBUG: wsdl ee document = " + ((javax.wsdl.extensions.schema.Schema)ee).getElement());
	    }
	    */

	    /* So instead, to get to the schema types stuff we need, we
	     * manually read WSDLs and look for element trees like
	     *   <definitions><types><schema>
	     * or
	     *   <description><types><schema>
	     *
	     * Once we have the Element for <schema>, we use axis's
	     * tools to grab the XmlSchema from it -- then we're money.
	     *
	     * Right now, we don't support multiple <types> or <schema>
	     * elements.
	     */

	    CustomURIResolver dr = new CustomURIResolver(rurl);
	    xmlSchemaCollection.setSchemaResolver(dr);

	    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
	    dbf.setNamespaceAware(true);
	    DocumentBuilder db = dbf.newDocumentBuilder();
	    Document doc = db.parse(ris);

	    String toplevel[] = new String[] { "definitions","description" };
	    for (int i = 0; i < toplevel.length; ++i) {
		NodeList nl = doc.getElementsByTagName(toplevel[i]);
		for (int j = 0; j < nl.getLength(); ++j) {
		    Element defE = (Element)nl.item(j);

		    NodeList defL = doc.getElementsByTagName("types");
		    for (int k = 0; k < defL.getLength(); ++k) {
			Element typesE = (Element)defL.item(k);

			NodeList schemaL = doc.getElementsByTagName("schema");
			for (int l = 0; l < schemaL.getLength(); ++l) {
			    Element schemaE = (Element)schemaL.item(k);

			    /*
			     * Finally, read a schema!
			     */
			    XmlSchema schema = xmlSchemaCollection.read(schemaE);
			    schemaMap.put(schema.getTargetNamespace(),schema);

			    Iterator<?> iterator = schema.getItems().getIterator();
			    while (iterator.hasNext()) {
				XmlSchemaObject obj = (XmlSchemaObject) iterator.next();
				if (obj instanceof XmlSchemaElement) {
				    System.err.println("Element " + ((XmlSchemaElement)obj).getQName());
				}
				else
				    System.err.println("Object " + obj);
			    }
			}
		    }
		}
	    }

	    if (typeMapping != null) {
		Set<Map.Entry<String,QName>> tms = typeMapping.entrySet();
		Iterator<Map.Entry<String,QName>> tmi = tms.iterator();
		while (tmi.hasNext()) {
		    Map.Entry<String,QName> me = tmi.next();
		    typeTable.addComplexSchema(me.getKey(),me.getValue());
		}
	    }
	} catch (Exception e) {
	    e.printStackTrace();
	}

	System.err.println("sC = " + serviceClass + "; s = " + service);

        //classModel = JAXRSUtils.getClassModel(serviceClass);
        //methods = processMethods(serviceClass.getDeclaredMethods());

	Collection<XmlSchema> retval = null;

	try {
	    retval = super.generateSchema();
	}
	catch (Exception ex) {
	    ex.printStackTrace();
	    throw ex;
	}

	return retval; //super.generateSchema(); //schemaMap.values();
    }

    private Node getNode(String tagName,NodeList nodes) {
    for ( int x = 0; x < nodes.getLength(); x++ ) {
        Node node = nodes.item(x);
        if (node.getNodeName().equalsIgnoreCase(tagName)) {
            return node;
        }
    }
 
    return null;
}

    protected XmlSchemaComplexType getComplexTypeForElement(XmlSchema xmlSchema,
							    QName name) {
	System.err.println("DEBUG: getComplexTypeForElement(" + name + ")");
	XmlSchemaComplexType retval = 
	    super.getComplexTypeForElement(xmlSchema,name);
	System.err.println("DEBUG: getComplexTypeForElement(" + name + ") = " + retval);
	return retval;
    }

    protected XmlSchema getXmlSchema(String targetNamespace) {
	System.err.println("DEBUG: getXmlSchema(" + targetNamespace + ")");
        XmlSchema xmlSchema = super.getXmlSchema(targetNamespace);
	System.err.println("DEBUG: getXmlSchema(" + targetNamespace + ") = " + xmlSchema);
        return xmlSchema;
    }
}
