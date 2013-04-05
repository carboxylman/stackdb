
package vmi1;

import javax.wsdl.xml.WSDLLocator;
import org.xml.sax.InputSource;

import java.util.Map;
import java.util.HashMap;
import java.util.Set;
import java.util.Iterator;

import java.net.URL;
import java.net.MalformedURLException;
import java.net.URISyntaxException;

import java.io.InputStream;
import java.io.IOException;

public class URLWSDLLocator implements WSDLLocator {
    protected URL url;
    protected Map<String,URL> urlMap;
    protected Map<String,InputStream> inputStreamMap;
    protected URL lastImportedURL = null;

    public URLWSDLLocator(URL url) {
	this.url = url;
	this.urlMap = new HashMap<String,URL>();
	this.inputStreamMap = new HashMap<String,InputStream>();
    }

    public void close() {
	Set<Map.Entry<String,InputStream>> isms = inputStreamMap.entrySet();
	Iterator<Map.Entry<String,InputStream>> isi = isms.iterator();
	while (isi.hasNext()) {
	    Map.Entry<String,InputStream> me = isi.next();
	    try {
		me.getValue().close();
	    }
	    catch (Exception ex) { }
	}

	inputStreamMap.clear();
	urlMap.clear();
	lastImportedURL = null;
    }

    public InputSource getBaseInputSource() {
	InputSource newInputSource = null;
	InputStream is = inputStreamMap.get(url.toString());
	if (is != null)
	    return new InputSource(is);
	else {
	    try {
		is = url.openStream();
	    }
	    catch (IOException ex) {
		ex.printStackTrace();
		return null;
	    }
	    newInputSource = new InputSource(is);
	    urlMap.put(url.toString(),url);
	    inputStreamMap.put(url.toString(),is);
	    return newInputSource;
	}

    }

    public String getBaseURI() {
	String uri = null;
	try {
	    uri = url.toURI().toString();
	}
	catch (URISyntaxException ex) {
	    ex.printStackTrace();
	}
	return uri;
    }

    public InputSource getImportInputSource(String parentLocation,
					    String importLocation) {
	URL newImportedURL = null;
	try {
	    URL parentLocationURL = new URL(parentLocation);

	    newImportedURL = new URL(parentLocationURL,importLocation);
	}
	catch (MalformedURLException ex) {
	    ex.printStackTrace();
	    return null;
	}

	InputStream newInputStream = inputStreamMap.get(newImportedURL.toString());
	if (newInputStream != null) {
	    lastImportedURL = newImportedURL;
	    return new InputSource(newInputStream);
	}
	else {
	    try {
		newInputStream = newImportedURL.openStream();
	    }
	    catch (IOException ex) {
		ex.printStackTrace();
		return null;
	    }
	    InputSource newInputSource = new InputSource(newInputStream);

	    urlMap.put(newImportedURL.toString(),newImportedURL);
	    inputStreamMap.put(newImportedURL.toString(),newInputStream);

	    lastImportedURL = newImportedURL;

	    return newInputSource;
	}
    }

    public String getLatestImportURI() {
	if (lastImportedURL != null) 
	    return lastImportedURL.toString();
	return null;
    }
}
