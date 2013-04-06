
package vmi1;

import org.apache.ws.commons.schema.resolver.URIResolver;
import org.apache.ws.commons.schema.resolver.CollectionURIResolver;

import org.xml.sax.InputSource;

import java.io.InputStream;
import java.net.URL;

public class CustomURIResolver implements CollectionURIResolver {
    protected String baseURI;
    protected URL baseURL;

    public CustomURIResolver(URL baseURL) {
	this.baseURL = baseURL;
    }

    public CustomURIResolver() {
	super();
    }

    public String getCollectionBaseURI() {
	if (this.baseURL != null)
	    return this.baseURL.toString();
	return this.baseURI;
    }

    public void setCollectionBaseURI(String uri) {
	this.baseURI = uri;
    }

    public InputSource resolveEntity(String targetNamespace,String schemaLocation,
				     String baseUri) {
	URL newImportedURL = null;
	try {
	    //System.err.println("baseUri = " + baseUri);
	    URL parentLocationURL;
	    if (this.baseURL != null)
		parentLocationURL = this.baseURL;
	    else
		parentLocationURL = new URL(baseUri);
	    newImportedURL = new URL(parentLocationURL,schemaLocation);
	    InputStream newInputStream = newImportedURL.openStream();
	    return new InputSource(newInputStream);
	}
	catch (Exception ex) {
	    ex.printStackTrace();
	    return null;
	}
    }
}
