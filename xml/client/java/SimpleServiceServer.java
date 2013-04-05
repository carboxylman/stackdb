
package vmi1;

import vmi1.*;

import java.io.File;
import java.util.List;
import java.util.Map;

import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.axis2.engine.ListenerManager;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.apache.axis2.engine.AxisConfiguration;
import org.apache.axis2.engine.AxisServer;
import org.apache.axis2.description.AxisService;
import org.apache.axis2.engine.MessageReceiver;
import org.apache.axis2.AxisFault;
import org.apache.axis2.transport.http.SimpleHTTPServer;
import org.apache.axis2.description.java2wsdl.SchemaGenerator;
import org.apache.axis2.description.java2wsdl.Java2WSDLConstants;

public class SimpleServiceServer extends AxisServer {
    private static final Log log = LogFactory.getLog(SimpleServiceServer.class);

    public SimpleServiceServer() {
	super();
    }

    public SimpleServiceServer(boolean startOnDeploy,ConfigurationContext cctx) {
	super(startOnDeploy);
	setConfigurationContext(cctx);
    }

    public AxisService buildService(String className) 
	throws Exception,ClassNotFoundException,InstantiationException,
	       IllegalAccessException,AxisFault {
	return buildService((SimpleService)Class.forName(className,true,this.getClass().getClassLoader()).newInstance());
    }

    public AxisService buildService(SimpleService ss) 
	throws Exception,ClassNotFoundException,AxisFault {
	String resourcePath = ss.getSchemaResourcePath();

	String implClass = ss.getClass().getCanonicalName();
	int index = implClass.lastIndexOf(".");
	String serviceName;
	if (index > 0) {
	    serviceName = implClass.substring(index + 1, implClass.length());
	} else {
	    serviceName = implClass;
	}

	SchemaGenerator sg = null;
	AxisService as = null;
	if (resourcePath != null) {
	    AxisConfiguration ac = 
		getConfigurationContext().getAxisConfiguration();
	    as = new AxisService();
	    as.setParent(ac);
	    as.setName(serviceName);

	    sg = new ResourceSchemaGenerator(ss.getClass().getClassLoader(),
					     ss.getClass().getCanonicalName(),
					     resourcePath,ss.getClass(),
					     ss.getSchemaNamespace(),
					     ss.getSchemaNamespacePrefix(),
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
	SimpleServiceServer ss = new SimpleServiceServer();
        SimpleHTTPServer server;
	int added = 0;
	int notadded = 0;

	for (int i = 0; i < args.length; ++i) {
	    try {
		ss.buildService(args[i]);
		++added;
	    }
	    catch (Throwable t) {
		++notadded;
		System.err.println("could not add service " + args[i]);
		t.printStackTrace();
	    }
	}

	if (added > 0) {
	    try {
		server = new SimpleHTTPServer(ss.getConfigurationContext(),-1);
		System.out.println("Starting HTTP server on port " 
				   + server.getHttpFactory().getPort());
		ss.start();
	    }
	    catch (Throwable t) {
		System.err.println("Could not start server:");
		t.printStackTrace();
		System.exit(6);
	    }
	    System.out.println("Server exiting.");
	}
	else {
	    System.out.println("Server exiting; no services added!");
	}

	System.exit(0);
    }

}

