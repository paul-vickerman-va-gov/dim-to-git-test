package gov.va.vba.css.bo;

public class CSSFrameworkLayerException extends Exception {

	private static final long serialVersionUID = 1L;
	
	public CSSFrameworkLayerException(String message, Exception cause) {
		super(message, cause);
	}

	public CSSFrameworkLayerException(String message) {
		super(message);
	}

}
