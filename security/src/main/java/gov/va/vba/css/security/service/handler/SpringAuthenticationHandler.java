package gov.va.vba.css.security.service.handler;

import gov.va.vba.css.security.service.handler.WssSecurityBean;
import gov.va.vba.css.security.exceptions.CssWsException;
import gov.va.vba.css.security.model.IAMUser;
import gov.va.vba.css.security.util.SecurityProperties;
import gov.va.vba.css.security.service.impl.SamlAuthenticationUserDetailsService;
import gov.va.vba.css.security.service.impl.CustomAuthenticationProvider;
import gov.va.vba.framework.logging.Logger;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.ws.security.util.WSSecurityUtil;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.util.Assert;
import org.w3c.dom.Element;

import javax.servlet.http.HttpServletRequest;
import javax.xml.namespace.QName;
import javax.xml.soap.SOAPHeader;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPMessageContext;
import javax.xml.ws.spi.http.HttpExchange;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * This web service handler is intended to ...
 */
public class SpringAuthenticationHandler extends CSSWSHandler {
    private static Logger logger = Logger.getLogger(SpringAuthenticationHandler.class);
	
    @Autowired
	private SecurityProperties props;
    
    /**
     * handleMessage expects the user id to be included in the SOAP message
     * context.  it grabs the user id from the SOAP message context and
     * authenticates the user to the local Spring Security context using a
     * custom Spring AuthenticationProvider.
     */


    @Autowired(required = true)
    private WssSecurityBean springAuthenticationHandlerBean;

    @Override
    public boolean handleMessage(SOAPMessageContext context) {
        
    	if(!props.isSecurityTurnedOn()){
        	logger.debug(this.getClass() + " Security property turned off, ignoring message...");
        }else if (isOutbound(context)) {
        	logger.info("Outbound message: Logging out user");
        	Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        	if (auth != null) {
        		auth.setAuthenticated(false);
        	} else {
        		logger.warn("Unable to set authentication to false in the context due to Authentication element being null");
        	}
            SecurityContextHolder.getContext().setAuthentication(null);
        }
        else {
            try {
            	logger.info("Inbound message: Authenticate user and create security context");

            	SOAPHeader header = context.getMessage().getSOAPHeader();
            	IAMUser iamUser = null;
            	iamUser = this.getIAMUser(header);
            	
                if(iamUser != null){
                	String clientIPAddress = getClientIPFromContext(context);
                	logger.info("Client IP Address obtained from the SOAP Context: "+clientIPAddress);
                	iamUser.setClientIPAddress(clientIPAddress);
                	final Authentication auth = new CustomAuthenticationProvider(iamUser);
                    auth.setAuthenticated(true);
                    logger.warn("Logging in with [{"+auth.getPrincipal()+"}]");
                    SecurityContextHolder.getContext().setAuthentication(auth);
                    boolean isAuthenticated = SecurityContextHolder.getContext().getAuthentication().isAuthenticated();
                    logger.warn("Is User Authenticated: [{"+isAuthenticated+"}]" );
                }
                else
                {
                	logger.error("User is not authenticated to make the call");
                	throw new CssWsException("Unable to load the user from the security headers in the incoming request");                	
                }
            } catch (Exception e) {
                SecurityContextHolder.getContext().setAuthentication(null);
                logger.error("Failure in autoLogin", e);
                throw new CssWsException("Unable to load the user from the security headers in the incoming request",e);
            }
        }
        return true;
    }

    private String getClientIPFromContext(SOAPMessageContext context) {
    	HttpServletRequest request = (HttpServletRequest)context.get(MessageContext.SERVLET_REQUEST);
    	return request.getRemoteAddr();
	}

	@Override
    public boolean handleFault(SOAPMessageContext context) {
        return true;
    }

    @Override
    public void close(MessageContext context) {
    }

    @Override
    public Set<QName> getHeaders() {
        return null;
    }

    public WssSecurityBean getSpringAuthenticationHandlerBean() {
        return springAuthenticationHandlerBean;
    }

    public void setSpringAuthenticationHandlerBean(WssSecurityBean springAuthenticationHandlerBean) {
        this.springAuthenticationHandlerBean = springAuthenticationHandlerBean;
    }

    protected IAMUser getIAMUser(SOAPHeader soapHeader) throws CssWsException {

        Element samlElement = WSSecurityUtil.findElement(soapHeader, WSConstants.ASSERTION_LN, WSConstants.SAML2_NS);
        
        Assert.notNull(samlElement,"Unable to find mandatory authnetication headers in the incomming request ");
        
        samlElement.getElementsByTagName("*");
        AssertionWrapper assWrapper =  null;
        
        try {
        	assWrapper = new AssertionWrapper(samlElement);
        } catch (Exception e) {
            logger.error("Error creating AssertionWrapper " + e.getMessage());
            e.printStackTrace(System.out);
            throw new CssWsException("Unable to handle SOAP Request Security Headers",e);
        }

        Assertion samlAssertion = assWrapper.getSaml2();

        List<AttributeStatement> attStatements = samlAssertion.getAttributeStatements();
        List<Attribute> attributeList = new ArrayList<Attribute>();

        for(AttributeStatement at: attStatements){
            List<Attribute> aList = at.getAttributes();
            attributeList.addAll(aList);
        }

        SAMLCredential samlCred = new SAMLCredential(samlAssertion.getSubject().getNameID(), samlAssertion, samlAssertion.getIssuer().getValue(), attributeList, "IAM");

        SamlAuthenticationUserDetailsService vsud = new SamlAuthenticationUserDetailsService();
        
        IAMUser iamUser = (IAMUser) vsud.loadUserBySAML(samlCred);

        return iamUser;
    }

}