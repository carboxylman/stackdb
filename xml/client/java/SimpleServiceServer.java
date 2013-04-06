
package vmi1;

import vmi1.*;

import java.io.File;
import java.util.List;
import java.util.Map;
import java.util.Iterator;

import java.net.URL;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.apache.axis2.AxisFault;
import org.apache.axis2.Constants;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.axis2.engine.ListenerManager;
import org.apache.axis2.transport.TransportListener;
import org.apache.axis2.description.TransportInDescription;

import org.apache.axis2.engine.AxisConfiguration;
import org.apache.axis2.engine.AxisServer;
import org.apache.axis2.description.AxisService;
import org.apache.axis2.engine.MessageReceiver;
import org.apache.axis2.AxisFault;
import org.apache.axis2.transport.http.SimpleHTTPServer;
import org.apache.axis2.description.java2wsdl.SchemaGenerator;
import org.apache.axis2.description.java2wsdl.Java2WSDLConstants;

public class SimpleServiceServer extends SimpleHTTPServer {
    private static final Log log = LogFactory.getLog(SimpleServiceServer.class);

    public SimpleServiceServer(int port) throws AxisFault {
	super(ConfigurationContextFactory
	      .createConfigurationContextFromFileSystem(null,null),
	      port);
    }

    public SimpleServiceServer(ConfigurationContext cctx,int port) 
	throws AxisFault {
	super(cctx,port);
    }

    public void start() throws AxisFault {
	try {
	    ConfigurationContext cctx = getConfigurationContext();
	    super.start();
	    ListenerManager listenerManager = cctx.getListenerManager();
	    TransportInDescription trsIn = 
	    new TransportInDescription(Constants.TRANSPORT_HTTP);
	    trsIn.setReceiver(this);
	    if (listenerManager == null) {
		listenerManager = new ListenerManager();
		listenerManager.init(cctx);
	    }
	    listenerManager.addListener(trsIn, true);

	    Iterator<String> iter = cctx.getAxisConfiguration().
		getTransportsIn().keySet().iterator();
	    while (iter.hasNext()) {
		String trp = iter.next();
		if (!Constants.TRANSPORT_HTTP.equals(trp)) {
		    trsIn = (TransportInDescription)
			cctx.getAxisConfiguration().getTransportsIn().get(trp);
		    listenerManager.addListener(trsIn, false);
		}
	    }
        }
	catch (Exception ex) {
            log.error(ex.getMessage(),ex);
            throw AxisFault.makeFault(ex);
        }
    }

    public AxisService buildService(String className) 
	throws Exception,ClassNotFoundException,InstantiationException,
	       IllegalAccessException,AxisFault {
	return buildService((SimpleService)Class.forName(className,true,this.getClass().getClassLoader()).newInstance());
    }

    public AxisService buildService(SimpleService ss) 
	throws Exception,ClassNotFoundException,AxisFault {
	String resourcePath = ss.getSchemaResourcePath();
	Class implClass = ss.getClass();
	String implClassName = implClass.getCanonicalName();
	int index = implClassName.lastIndexOf(".");
	String serviceName;
	if (index > 0) {
	    serviceName = implClassName.substring(index + 1,implClassName.length());
	} else {
	    serviceName = implClassName;
	}

	SchemaGenerator sg = null;
	AxisService as = null;
	if (resourcePath != null) {
	    AxisConfiguration ac = 
		getConfigurationContext().getAxisConfiguration();
	    as = new AxisService();
	    as.setParent(ac);
	    as.setName(serviceName);

	    URL rurl = null;

	    if (java.lang.Thread.currentThread().getContextClassLoader() != null) {
		ClassLoader cl = 
		    java.lang.Thread.currentThread().getContextClassLoader();
		rurl = cl.getResource(resourcePath);
	    }
	    else if (implClass != null) {
		rurl = implClass.getResource(resourcePath);
	    }
	    else {
		rurl = implClass.getClassLoader().getResource(resourcePath);
	    }

	    sg = new ResourceSchemaGenerator(implClass.getClassLoader(),
					     implClassName,
					     rurl,
					     ss.getSchemaNamespace(),
					     ss.getSchemaNamespacePrefix(),
					     ss.getMethodClassNameMapping(),
					     ss.getDynamicTypeMapping(),
					     ss.getStaticTypeMapping(),
					     as);
	    sg.setElementFormDefault(Java2WSDLConstants.FORM_DEFAULT_UNQUALIFIED);
	}

	return buildService(ss.getClass().getCanonicalName(),serviceName,
			    ss.getMessageReceiverClassMap(),
			    ss.getTargetNamespace(),ss.getSchemaNamespace(),sg,as);
    }

    public AxisService buildService(String implClass,String serviceName,
				    Map<String,MessageReceiver> msgReceiverClassMap,
				    String targetNamespace,String schemaNamespace,
				    SchemaGenerator sg,AxisService as) 
	throws ClassNotFoundException,AxisFault {
	AxisConfiguration ac = getConfigurationContext().getAxisConfiguration();

	if (sg != null) {
	    as = AxisService.createService(implClass,serviceName,
					   ac,msgReceiverClassMap,targetNamespace,
					   this.getClass().getClassLoader(),
					   sg,as);
	}
	else
	    as = AxisService.createService(implClass,ac,msgReceiverClassMap,
					   targetNamespace,schemaNamespace,
					   this.getClass().getClassLoader());
	ac.addService(as);

	return as;
    }

    /**
     * Simple main class that accepts a list of service object
     * classnames, loads them, and adds them to our server before
     * starting it.
     */
    public static void main(String[] args) {
	SimpleServiceServer ss;

	try {
	    ss = new SimpleServiceServer(3952);

	    for (int i = 0; i < args.length; ++i) {
		ss.buildService(args[i]);
	    }

	    ss.start();
	    System.out.println("Started HTTP server on port " 
			       + ss.getHttpFactory().getPort());
	}
	catch (Throwable t) {
	    System.err.println("Could not start server:");
	    t.printStackTrace();
	    System.exit(6);
	}
    }

}

