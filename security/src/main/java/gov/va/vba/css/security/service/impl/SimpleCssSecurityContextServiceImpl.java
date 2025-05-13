package gov.va.vba.css.security.service.impl;

import org.springframework.security.core.context.SecurityContextHolder;
import org.w3c.dom.Element;

import gov.va.vba.css.security.exceptions.CssWsException;
import gov.va.vba.css.security.model.IAMUser;
import gov.va.vba.css.security.service.CssSecurityContextService;

public class SimpleCssSecurityContextServiceImpl implements CssSecurityContextService {

	@Override
	public boolean isAuthenticated() {
		return (null != SecurityContextHolder.getContext().getAuthentication());
	}

	@Override
	public IAMUser getUserDetails() {
		Object obj = SecurityContextHolder.getContext().getAuthentication()
				.getPrincipal();
		if(obj == null){
			throw new CssWsException("IAMUser Object is not set ");
		}
		if (obj instanceof IAMUser) {
			return (IAMUser) obj;
		}
		throw new CssWsException("IAMUser Object is not set ");
	}

	@Override
	public String getUserName() {
		String username = getUserDetails().getSamaccountname();
		
		/**
		 * username is mandatory and must not be null or empty
		 */
		if (username == null || username.isEmpty()) {
			throw new CssWsException("The required username is either null or empty");
		}
		
		return username;
	}

	@Override
	public Element getUserSAMLCredentialsAsXML() {
		return getUserDetails().getSamlTokenXML();
	}

	@Override
	public String getClientIPAddress() {
		String clientIPAddress = getUserDetails().getClientIPAddress();
		/**
		 * clientIPAddress is mandatory and must not be null or empty
		 */
		if (clientIPAddress == null || clientIPAddress.isEmpty()) {
			throw new CssWsException("The required Client IP Address is either null or empty");
		}
		
		return clientIPAddress;
	}
}
