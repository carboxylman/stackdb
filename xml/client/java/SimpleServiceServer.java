
package vmi1;

import vmi1.*;

import java.io.File;
import java.util.List;
import java.util.Map;
import java.util.Iterator;

import java.net.URL;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.axis2.util.LoggingControl;

import org.apache.axis2.AxisFault;
import org.apache.axis2.Constants;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.axis2.engine.ListenerManager;
import org.apache.axis2.transport.TransportListener;
import org.apache.axis2.description.TransportInDescription;

import org.apache.axis2.engine.AxisConfigurator;
import org.apache.axis2.deployment.FileSystemConfigurator;
import org.apache.axis2.engine.AxisConfiguration;
import org.apache.axis2.engine.AxisServer;
import org.apache.axis2.description.AxisService;
import org.apache.axis2.description.Parameter;
import org.apache.axis2.engine.MessageReceiver;
import org.apache.axis2.AxisFault;
import org.apache.axis2.transport.http.SimpleHTTPServer;
import org.apache.axis2.description.java2wsdl.SchemaGenerator;
import org.apache.axis2.description.java2wsdl.Java2WSDLConstants;

import org.apache.axis2.deployment.util.Utils;

public class SimpleServiceServer extends SimpleHTTPServer {
    private static final Log log = LogFactory.getLog(SimpleServiceServer.class);

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
	String serviceName = ss.getServiceName();
	if (serviceName == null) {
	    if (index > 0) {
		serviceName = 
		    implClassName.substring(index + 1,implClassName.length());
	    } else {
		serviceName = implClassName;
	    }
	}
	String serviceURL = ss.getServicePath();
	if (serviceURL == null) 
	    serviceURL = "http:///" + serviceName;
	else
	    serviceURL = "http://" + serviceURL;
	boolean isRootService = ss.isRootService();

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
			    serviceURL,isRootService,
			    ss.getMessageReceiverClassMap(),
			    ss.getTargetNamespace(),ss.getSchemaNamespace(),sg,as);
    }

    public AxisService buildService(String implClass,String serviceName,
				    String serviceURL,boolean isRootService,
				    Map<String,MessageReceiver> msgReceiverClassMap,
				    String targetNamespace,String schemaNamespace,
				    SchemaGenerator sg,AxisService as) 
	throws Exception,ClassNotFoundException,AxisFault {
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

	if (serviceURL == null)
	    serviceURL = "http:///" + serviceName;
	Utils.addSoap12Endpoint(as,serviceURL);
	if (isRootService)
	    Utils.addSoap12Endpoint(as,"http:///");

	ac.addService(as);

	return as;
    }

    /**
     * Simple main class that accepts a list of service object
     * classnames, loads them, and adds them to our server before
     * starting it.
     */
    public static void main(String[] args) {
	AxisConfigurator ac;
	ConfigurationContext cctx;
	SimpleServiceServer ss;

	try {
	    ac = new FileSystemConfigurator(null,null);
	    //ac.getAxisConfiguration().addParameter(Constants.PARAM_SERVICE_PATH,
	    //					   "/");
	    //ac.getAxisConfiguration().addParameter(Constants.PARAM_CONTEXT_ROOT,
	    //					   "/");
	    cctx = ConfigurationContextFactory.createConfigurationContext(ac);

	    ss = new SimpleServiceServer(cctx,3952);

	    //Parameter servicePath = ac.getAxisConfiguration().getParameter(Constants.PARAM_SERVICE_PATH);
	    //Parameter contextPath = ac.getAxisConfiguration().getParameter(Constants.PARAM_CONTEXT_ROOT);

	    /*
	     * NB: must set contextRoot after servicePath to ensure an
	     * internal cache is updated.
	     *
	     * More importantly, you must set root to /, and servicePath
	     * to some relative path ***that is part of your namespace
	     * string!***
	     *
	     * Well, at least one path through axis's dispatchers
	     * considers this valid; there may be other ways!
	     */
	    ss.getConfigurationContext().setServicePath("vmi/1");
	    ss.getConfigurationContext().setContextRoot("/");

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

