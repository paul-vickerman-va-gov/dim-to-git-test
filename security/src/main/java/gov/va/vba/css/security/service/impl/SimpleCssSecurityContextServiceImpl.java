package gov.va.vba.css.security.service.impl;

import org.w3c.dom.Element;

import gov.va.vba.css.security.model.IAMUser;
import gov.va.vba.css.security.service.CssSecurityContextService;

public class SimpleCssSecurityContextServiceImpl implements CssSecurityContextService {

	@Override
	public boolean isAuthenticated() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public IAMUser getUserDetails() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getUserName() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getRemoteAddress() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Element getUserSAMLCredentialsAsXML() {
		// TODO Auto-generated method stub
		return null;
	}

}
