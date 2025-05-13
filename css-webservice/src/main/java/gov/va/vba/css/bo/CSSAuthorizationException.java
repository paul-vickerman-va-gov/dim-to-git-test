package gov.va.vba.css.bo;

import gov.va.vba.framework.services.CssUserRepositoryException;

public class CSSAuthorizationException extends Exception {

	private static final long serialVersionUID = 1L;
	
	public CSSAuthorizationException(String message) {
		super(message);
	}

	public CSSAuthorizationException(String message, CssUserRepositoryException e) {
		super(message, e);
	}

}
