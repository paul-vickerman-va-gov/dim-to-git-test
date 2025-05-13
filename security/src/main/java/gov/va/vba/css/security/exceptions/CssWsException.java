package gov.va.vba.css.security.exceptions;

import javax.xml.ws.ProtocolException;

public class CssWsException extends ProtocolException {

	private static final long serialVersionUID = 1L;
	
	public CssWsException(String message) {
		super(message);
	}

	public CssWsException(String message, Throwable e) {
		super(message, e);
	}

}