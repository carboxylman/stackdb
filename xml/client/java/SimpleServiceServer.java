
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
import java.net.URL;
import java.net.URLClassLoader;
import java.net.MalformedURLException;

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
	throws ClassNotFoundException,InstantiationException,
	       IllegalAccessException,AxisFault {
	return buildService((SimpleService)SimpleServiceServer.class.getClassLoader().loadClass(className).newInstance()); //Class.forName(className).newInstance());
    }

    public AxisService buildService(SimpleService ss) 
	throws ClassNotFoundException,AxisFault {
	return buildService(ss.getClass().toString(),
			    ss.getMessageReceiverClassMap(),
			    ss.getTargetNamespace(),
			    ss.getSchemaNamespace());
    }

    public AxisService buildService(String implClass,
				    Map<String,MessageReceiver> msgReceiverClassMap,
				    String targetNamespace,String schemaNamespace) 
	throws ClassNotFoundException,AxisFault {
	AxisConfiguration ac = getConfigurationContext().getAxisConfiguration();
	URL[] urls = new URL[1];
	try {
	    urls[0] = new URL("file:///home/johnsond/git/a3/vmi.obj/xml/client/java/target-all.jar");
	}
	catch (MalformedURLException e) {
	    e.printStackTrace();
	    return null;
	}
	AxisService as = 
	    AxisService.createService(implClass,ac,msgReceiverClassMap,
				      targetNamespace,schemaNamespace,
				      new URLClassLoader(urls,SimpleServiceServer.class.getClassLoader()));
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
