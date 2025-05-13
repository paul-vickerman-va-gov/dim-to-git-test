package gov.va.vba.css.security.service;

import gov.va.vba.css.security.model.IAMUser;

import org.w3c.dom.Element;

public interface CssSecurityContextService {
	
	boolean isAuthenticated();
	
	IAMUser getUserDetails();

	String getUserName();

	String getRemoteAddress();
	
	Element getUserSAMLCredentialsAsXML();
	
}
