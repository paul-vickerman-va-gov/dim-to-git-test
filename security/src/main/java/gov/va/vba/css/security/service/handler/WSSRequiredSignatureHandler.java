package gov.va.vba.css.security.service.handler;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.List;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPPart;
import javax.xml.ws.handler.soap.SOAPMessageContext;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.util.WSSecurityUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.util.Assert;
import org.w3c.dom.Element;
import gov.va.vba.css.security.exceptions.CssWsException;
import gov.va.vba.framework.logging.Logger;

public class WSSRequiredSignatureHandler extends CSSWSHandler {

	private static Logger logger = Logger.getLogger(WSSRequiredSignatureHandler.class);
	
	@Autowired
	private JKSKeyManager keyManager;
    
    @Override
    public boolean handleFault(SOAPMessageContext context) {
        return true;
    }
    
    private KeyStore getKeystore() throws CssWsException{
		KeyStore ks = null;
		
    	try {
    		if (keyManager == null) {
    			logger.error("Error getting keystore, key manager null ");
    			throw new CssWsException("Unable to get key manager ");
    		} else {
    			logger.debug("Key manager available credentials: " + keyManager.getAvailableCredentials().toString());
    			ks = keyManager.getKeyStore();
    		}
		} catch (Exception e) {
			logger.error("Error getting keystore " + e.getMessage());
            e.printStackTrace(System.out);
            throw new CssWsException("Unable to get keystore ", e);
		} 
    	
    	return ks;
    }
    
    private Enumeration<String> getAliases(KeyStore ks) throws CssWsException{
    	Enumeration<String> aliases = null;
		try {
			aliases = ks.aliases();
		} catch (KeyStoreException e) {
			logger.error("Error getting aliases " + e.getMessage());
            e.printStackTrace(System.out);
            throw new CssWsException("Unable to get aliases ", e);
		}
		
		if (aliases == null || !(aliases.hasMoreElements())) {
        	throw new CssWsException("Unable to find any aliases in the provided keystore ");
        }
		
		return aliases;
    }
	
	@Override
	public boolean handleMessage(SOAPMessageContext context) {
		if (isOutbound(context)) {
			return true;
		}
		
		boolean validSignature = false;
		
		SOAPPart header = null;
		Element soapBody = null;
        try {
        	header = context.getMessage().getSOAPPart();
			soapBody = (Element) context.getMessage().getSOAPBody();
		} catch (SOAPException e) {
			logger.error("Error getting soap header and body " + e.getMessage());
            e.printStackTrace(System.out);
            throw new CssWsException("Unable to handle SOAP Request header and body ",e);
		}
        
        if (header == null || soapBody == null) {
        	logger.error("Unable to handle SOAP Request header or body, null not allowed ");
        	throw new CssWsException("Unable to handle SOAP Request header or body, null not allowed ");
        }
        
        List<Element> sigElements = WSSecurityUtil.findElements(header, WSConstants.SIG_LN, WSConstants.SIG_NS);
		Assert.notNull(sigElements,"Unable to find mandatory signature headers in the incoming request (null) ");
		Assert.notEmpty(sigElements, "Unable to find mandatory signature headers in the incoming request (empty) ");

		validSignature = validateSignatures(soapBody, sigElements);
		logger.debug("Found valid signatures: " + validSignature);
		return validSignature;
	}
	
	private boolean validateSignatures(Element soapBody, List<Element> sigElements ) throws CssWsException {
		boolean validSignature = false;
		boolean assertSigValid = false;
		boolean wsSigValid = false;

		KeyStore ks = this.getKeystore();
		Enumeration<String> aliases = this.getAliases(ks);
		
		while(aliases.hasMoreElements() && !wsSigValid) {
			String alias = aliases.nextElement();
			
			Certificate cert = null;
			try {
				cert = (X509Certificate) ks.getCertificate(alias);
			} catch (KeyStoreException e) {
				logger.debug("Certificate error for alias " + alias + ", exception " + e.getMessage());
			}
			
			for (Element sig : sigElements) {
				if (wsSigValid && assertSigValid) {
					break;
				}
				
				if ("Assertion".equalsIgnoreCase(sig.getParentNode().getLocalName()) && !assertSigValid) {
					logger.debug("Assertion signature found, trying validation against " + alias);
					try {
						assertSigValid = validateSignature(cert, sig, true, (Element) sig.getParentNode());
						logger.debug("ASignature valid for alias " + alias + ": " + assertSigValid);
						if (assertSigValid) {
							continue;
						}
					} catch (Exception e) {
						logger.debug("ASignature not valid for alias " + alias + ", exception " + e.getMessage());
					}
				} else if ("Security".equalsIgnoreCase(sig.getParentNode().getLocalName()) && !wsSigValid) {
					logger.debug("WS Security Signature found, trying validation against " + alias);
					try {
						wsSigValid = validateSignature(cert, sig, false, soapBody);
						logger.debug("WSignature valid for alias " + alias + ": " + wsSigValid);
						if (wsSigValid) {
							continue;
						}
					} catch (Exception e) {
						logger.debug("WSignature not valid for alias " + alias + ", exception " + e.getMessage());
					}
				}
			}
		}
			
		validSignature = wsSigValid && assertSigValid;
		if (!validSignature) {
			logger.error("Invalid signature found, WS Sig: " + wsSigValid + ", Assert Sig: " + assertSigValid);
			throw new CssWsException("Invalid signature found, WS Sig: " + wsSigValid + ", Assert Sig: " + assertSigValid);
		}
		
		return validSignature;
	}
	
	private boolean validateSignature(Certificate certificate, Element signature, boolean isAssertion, Element signedNode) throws Exception {
		PublicKey publicKey = certificate.getPublicKey();
        DOMValidateContext ctx = new DOMValidateContext(publicKey, signature);
       
        if (signedNode != null) {
        	if (isAssertion) {
            	try {
            		ctx.setIdAttributeNS(signedNode, null, "ID");
            	} catch (Exception e) {
            		logger.error("Unable to set IdAttributeNS ID: " + e.getMessage());
            	}
            } else {
            	try {
            		ctx.setIdAttributeNS(signedNode, "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "Id");
            	} catch (Exception e) {
            		logger.error("Unable to set IdAttributeNS ID: " + e.getMessage());
            	}
            }
        }
        
        XMLSignatureFactory sigF = XMLSignatureFactory.getInstance("DOM");
        XMLSignature sig = sigF.unmarshalXMLSignature(ctx);
        return sig.validate(ctx);
	}
	
}
