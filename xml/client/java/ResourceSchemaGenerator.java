
package vmi1;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Set;
import java.util.Map;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Iterator;

import java.lang.reflect.*;
import java.lang.annotation.Annotation;

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

import org.apache.axis2.wsdl.WSDLConstants;

import org.apache.axis2.description.java2wsdl.SchemaGenerator;
import org.apache.axis2.description.java2wsdl.DefaultSchemaGenerator;
import org.apache.axis2.description.java2wsdl.DocLitBareSchemaGenerator;
import org.apache.axis2.description.AxisOperation;
import org.apache.axis2.description.AxisService;
import org.apache.axis2.description.AxisMessage;

import org.apache.axis2.deployment.util.Utils;

import org.apache.ws.commons.schema.*;

import org.apache.axis2.jsr181.JSR181Helper;
import org.apache.axis2.jsr181.WebMethodAnnotation;
import org.apache.axis2.jsr181.WebParamAnnotation;
import org.apache.axis2.jsr181.WebResultAnnotation;
import org.apache.axis2.jsr181.WebServiceAnnotation;

public class ResourceSchemaGenerator extends DefaultSchemaGenerator {
    protected URL schemaURL = null;
    protected Map<String,QName> typeMapping = 
	new HashMap<String,QName>();
    protected Map<String,String> methodClassNameMapping = 
	new HashMap<String,String>();
    protected Map<String,QName> dynamicTypeMapping = 
	new HashMap<String,QName>();

    protected JAXRSModel myClassModel;

    public ResourceSchemaGenerator(ClassLoader loader,String className,
				   URL schemaURL,
				   String schemaTargetNamespace,
				   String schemaTargetNamespacePrefix,
				   Map<String,String> methodClassNameMapping,
				   Map<String,QName> dynamicTypeMapping,
				   Map<String,QName> typeMapping,
				   AxisService service)
	throws Exception {

	super(loader,className,schemaTargetNamespace,schemaTargetNamespacePrefix,
	      service);

	this.schemaURL = schemaURL;
	this.typeMapping = typeMapping;
	this.methodClassNameMapping = methodClassNameMapping;
	this.dynamicTypeMapping = dynamicTypeMapping;
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

	if (schemaURL == null)
	    return super.generateSchema();

	try {
	    InputStream ris = schemaURL.openStream();

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

	    /*
	     * Right now, we have to use a custom resolver because a
	     * null baseUri is passed to it for some reason -- perhaps
	     * because of the soap schema being imported rather than
	     * included -- and there is no schemaLocation in our schema
	     * for the import.  Anyway, this causes an NPE, so do this
	     * for now.
	     */
	    CustomURIResolver dr = new CustomURIResolver(schemaURL);
	    xmlSchemaCollection.setSchemaResolver(dr);

	    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
	    dbf.setNamespaceAware(true);
	    DocumentBuilder db = dbf.newDocumentBuilder();
	    Document doc = db.parse(ris);

	    /*
	     * This will hopefully find all <schema> elements inlined in
	     * any WSDL document, 1.x or 2.0.
	     */
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

			    /*
			    XmlSchemaType tt = schema.getTypeByName(new QName(schema.getTargetNamespace(),"TargetSpecT"));
			    System.err.println("TargetSpecT = " + tt);

			    Iterator<?> iterator = schema.getItems().getIterator();
			    while (iterator.hasNext()) {
				XmlSchemaObject obj = (XmlSchemaObject) iterator.next();
				if (obj instanceof XmlSchemaElement) {
				    System.err.println("Element " + ((XmlSchemaElement)obj).getQName());
				}
				//else if (
				else
				    System.err.println("Object " + obj);
			    }
			    */
			}
		    }
		}
	    }

	    if (typeMapping != null) {
		Set<Map.Entry<String,QName>> tms = typeMapping.entrySet();
		Iterator<Map.Entry<String,QName>> tmi = tms.iterator();
		while (tmi.hasNext()) {
		    Map.Entry<String,QName> me = tmi.next();
		    System.err.println("DEBUG: adding static mapping to"
				       + " typeTable: "
				       + me.getKey() + " -> " + me.getValue());
		    typeTable.addComplexSchema(me.getKey(),me.getValue());
		}
	    }
	} catch (Exception e) {
	    e.printStackTrace();
	}

	//System.err.println("sC = " + serviceClass + "; s = " + service);

        myClassModel = JAXRSUtils.getClassModel(serviceClass);
        //methods = processMethods(serviceClass.getDeclaredMethods());

	Collection<XmlSchema> retval = super.generateSchema();

	return retval; //super.generateSchema(); //schemaMap.values();
    }

    /*
     * We try to use pre-existing axis-generated classes based off the
     * schema we've imported.  If nothing exists, fallback to the
     * DefaultSchemaGenerator way by calling super.processMethods()
     * method by method.
     */
    protected Method[] processMethods(Method[] declaredMethods) throws Exception {
        XmlSchema xmlSchema = getXmlSchema(schemaTargetNameSpace);

        ArrayList<Method> list = new ArrayList<Method>();

        Arrays.sort(declaredMethods,new MathodComparator());

        // since we do not support overload
        HashMap<String,Method> uniqueMethods = new LinkedHashMap<String,Method>();

        for (Method jMethod : declaredMethods) {
            if (jMethod.isBridge()) 
                continue;

            WebMethodAnnotation methodAnnon = 
		JSR181Helper.INSTANCE.getWebMethodAnnotation(jMethod);
            if (methodAnnon != null && methodAnnon.isExclude()) 
		continue;

            String methodName = jMethod.getName();

            if (excludeMethods.contains(methodName)) 
                continue;
            if (uniqueMethods.get(methodName) != null) 
                continue;
            if (!Modifier.isPublic(jMethod.getModifiers())) 
                continue;
	    if (nonRpcMethods.contains(methodName)) {
		System.err.println("DEBUG: " + methodName + " is a nonRpcMethod;"
				   + " letting DefaultSchemaGenerator handle!");
		Method tmplist[] = new Method[] { jMethod };
		Method retval[] = super.processMethods(tmplist);
		if (retval != null && retval.length == 1) {
		    list.add(jMethod);
		    uniqueMethods.put(methodName,jMethod);
		}
		continue;
	    }

	    /*
	     * Need to get a classname for the method (i.e., its wsdl
	     * message), and get a qname for that class!
	     */
	    String methodClassName = methodName;
	    if (methodClassNameMapping.get(methodName) != null)
		System.err.println("DEBUG: mapping method " + methodName
				   + " to class " + methodClassName);
	    QName methodQName = 
		new QName(xmlSchema.getTargetNamespace(),methodName);
	    if (dynamicTypeMapping.get(methodName) != null) {
		methodQName = dynamicTypeMapping.get(methodName);
		System.err.println("DEBUG: mapping method " + methodName
				   + " type to " + methodQName);
	    }
	    XmlSchemaComplexType methodSchemaType = 
		getComplexTypeForElement(xmlSchema,methodQName);
	    if (methodSchemaType == null) {
		System.err.println("DEBUG: could not find schema type for" 
				   + " method " + methodName + "; letting"
				   + "DefaultSchemaGenerator handle!");
		Method tmplist[] = new Method[] { jMethod };
		Method retval[] = super.processMethods(tmplist);
		if (retval != null && retval.length == 1) {
		    list.add(jMethod);
		    uniqueMethods.put(methodName,jMethod);
		}
		continue;
	    }
            boolean addToService = false;
            AxisOperation axisOperation = service.getOperation(methodQName);
            if (axisOperation == null) {
                axisOperation = Utils.getAxisOperationForJmethod(jMethod);
                addToService = true;
            }
            if (axisOperation != null) {
	    	Object model = 
		    JAXRSUtils.getMethodModel(this.myClassModel,jMethod);
	    	axisOperation.addParameter("JAXRSAnnotaion",model);
	    }

            Class<?>[] parameters = jMethod.getParameterTypes();
            String parameterNames[] = null;
            if (parameters.length > 0) 
                parameterNames = methodTable.getParameterNames(methodName);
            Annotation[][] parameterAnnotation = jMethod.getParameterAnnotations();
            Type[] genericParameterTypes = jMethod.getGenericParameterTypes();
            for (int j = 0; j < parameters.length; j++) {
                Class<?> methodParameter = parameters[j];
                String parameterName = 
		    getParameterName(parameterAnnotation,j,parameterNames);
		Type genericParameterType = genericParameterTypes[j];

		/* XXX: does the element for the param, and its type, exist? */
            }

            Class<?> returnType = jMethod.getReturnType();
	    String returnClassName = returnType.getName();
	    QName returnQName = null;
	    if ((returnQName = dynamicTypeMapping.get(returnClassName)) != null) {
		System.err.println("DEBUG: mapping return type " + returnClassName
				   + " to " + returnQName);
	    }
	    else {
		int idx = returnClassName.lastIndexOf('.');
		if (idx > -1) 
		    returnQName = new QName(xmlSchema.getTargetNamespace(),
					    returnClassName.substring(idx + 1));
		else
		    returnQName = new QName(xmlSchema.getTargetNamespace(),
					    returnClassName);
	    }
	    XmlSchemaType returnSchemaType = null;
            if (!"void".equals(jMethod.getReturnType().getName())) {
                returnSchemaType = 
		    getComplexTypeForElement(xmlSchema,returnQName);

		if (returnSchemaType == null) {
		    System.err.println("DEBUG: could not find schema type for" 
				       + "return type " + returnType
				       + " of method " + methodName + ";"
				       + " letting DefaultSchemaGenerator handle!");
		    Method tmplist[] = new Method[] { jMethod };
		    Method retval[] = super.processMethods(tmplist);
		    if (retval != null && retval.length == 1) {
			list.add(jMethod);
			uniqueMethods.put(methodName,jMethod);
		    }
		    continue;
		}
	    }

	    /*
	     * We're committed to handling this one now, rather than
	     * punting it to axis!
	     */
            list.add(jMethod);
            uniqueMethods.put(methodName, jMethod);

	    /* TypeTable inserts for method (i.e., in message). */
	    typeTable.addComplexSchema(methodClassName,methodQName);
	    typeTable.addClassNameForQName(methodQName,methodClassName);
	    // hedge our bets with the "original" unqualified method name.
	    typeTable.addComplexSchema(methodName,methodQName);
	    typeTable.addClassNameForQName(methodQName,methodName);

            if (parameters.length > 0) {
                parameterNames = methodTable.getParameterNames(methodName);
                // put the parameter names to use it for parsing
                service.addParameter(methodName,parameterNames);
            }

            AxisMessage inMessage = 
		axisOperation.getMessage(WSDLConstants.MESSAGE_LABEL_IN_VALUE);
            inMessage.setElementQName(methodQName);
	    inMessage.setName(methodQName.getLocalPart());
            service.addMessageElementQNameToOperationMapping(methodSchemaType.getQName(),
							     axisOperation);

	    typeTable.addComplexSchema(returnClassName,returnQName);
	    typeTable.addClassNameForQName(returnQName,returnClassName);

	    if (returnSchemaType != null) {
                AxisMessage outMessage = 
		    axisOperation.getMessage(WSDLConstants.MESSAGE_LABEL_OUT_VALUE);
                outMessage.setElementQName(returnQName);
                outMessage.setName(returnQName.getLocalPart());
                service.addMessageElementQNameToOperationMapping(returnSchemaType.getQName(),
								 axisOperation);
	    }

            processException(jMethod,axisOperation);

            if (addToService) 
                service.addOperation(axisOperation);
        }

        return list.toArray(new Method[list.size()]);
    }

    protected XmlSchemaComplexType getComplexTypeForElement(XmlSchema xmlSchema,
							    QName name) {
	System.err.println("DEBUG: getComplexTypeForElement(" + name + ")");
	XmlSchemaComplexType retval = 
	    super.getComplexTypeForElement(xmlSchema,name);
	System.err.println("DEBUG: getComplexTypeForElement(" + name + ") = " + retval);
	if (retval == null) {
	    String newLocalPart = name.getLocalPart();
	    char localPartChars[] = newLocalPart.toCharArray();
	    if (localPartChars != null && localPartChars.length > 0
		&& Character.isLowerCase(localPartChars[0])) {
		localPartChars[0] = Character.toUpperCase(localPartChars[0]);
		newLocalPart = new String(localPartChars);
		name = new QName(name.getNamespaceURI(),newLocalPart,name.getPrefix());
		System.err.println("DEBUG: (uppercase) getComplexTypeForElement(" + name + ")");
		retval = 
		    super.getComplexTypeForElement(xmlSchema,name);
		System.err.println("DEBUG: (uppercase) getComplexTypeForElement(" + name + ") = " + retval);
	    }
	}
	return retval;
    }

    protected XmlSchema getXmlSchema(String targetNamespace) {
	System.err.println("DEBUG: getXmlSchema(" + targetNamespace + ")");
        XmlSchema xmlSchema = super.getXmlSchema(targetNamespace);
	System.err.println("DEBUG: getXmlSchema(" + targetNamespace + ") = " + xmlSchema);
        return xmlSchema;
    }
}
