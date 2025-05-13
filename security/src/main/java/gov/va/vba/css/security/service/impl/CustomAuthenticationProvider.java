package gov.va.vba.css.security.service.impl;

import gov.va.vba.css.security.model.IAMUser;

import java.util.Collection;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.w3c.dom.Element;

public class CustomAuthenticationProvider implements Authentication {

    /**
     *
     */
    private static final long serialVersionUID = -451181883385729861L;
    private IAMUser iamUser;
	private boolean isAuthenticated = false;
	private Element samlElement;

	public CustomAuthenticationProvider(IAMUser iamUser){
		this.iamUser = iamUser;
	}

	@Override
	public String getName() {
		return iamUser.getUsername();
	}

	@Override
	public Collection<GrantedAuthority> getAuthorities() {
		return iamUser.getAuthorities();
	}

	@Override
	public Object getCredentials() {
		return null;
	}

	@Override
	public Object getDetails() {
		return null;
	}

	@Override
	public Object getPrincipal() {
		return iamUser;
	}

	@Override
	public boolean isAuthenticated() {
		return isAuthenticated;
	}

	@Override
	public void setAuthenticated(boolean isAuthenticated) {
	    this.isAuthenticated = isAuthenticated;
	}

	public Element getSamlElement() {
		return samlElement;
	}

	public void setSamlElement(Element samlElement) {
		this.samlElement = samlElement;
	}

}
