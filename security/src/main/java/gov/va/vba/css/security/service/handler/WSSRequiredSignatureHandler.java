package gov.va.vba.css.security.service.handler;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
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
import org.springframework.util.Assert;
import org.w3c.dom.Element;
import gov.va.vba.css.security.exceptions.CssWsException;
import gov.va.vba.css.security.formatters.BasicXmlFormatter;
import gov.va.vba.css.security.formatters.XmlFormatter;
import gov.va.vba.framework.logging.Logger;

public class WSSRequiredSignatureHandler extends CSSWSHandler {

	private static Logger logger = Logger.getLogger(WSSRequiredSignatureHandler.class);
    
    private XmlFormatter formatter = new BasicXmlFormatter();

    public XmlFormatter getFormatter() {
        return formatter;
    }

    public void setFormatter(XmlFormatter formatter) {
        this.formatter = formatter;
    }
    
    @Override
    public boolean handleFault(SOAPMessageContext context) {
        return true;
    }
    
    private KeyStore getKeystore() throws CssWsException{
    	InputStream inStream = null;
		KeyStore ks = null;
		
    	try {
    		//TODO bring these in from properties file
			inStream = new FileInputStream("css_props/cssKeystore.jks");//keystore
			ks = KeyStore.getInstance("JKS");
			ks.load(inStream, "csskey".toCharArray());//keystore password
			
		} catch (Exception e) {
			logger.error("Error getting keystore " + e.getMessage());
            e.printStackTrace(System.out);
            throw new CssWsException("Unable to get keystore ", e);
		} finally {
			if (inStream != null) {
				try {
					inStream.close();
				} catch (IOException e) {
					logger.error("Error closing keystore inStream " + e.getMessage());
				}
			}
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
		logger.debug("Found valid signature: " + validSignature);
		return validSignature;
	}
	
	private boolean validateSignatures(Element soapBody, List<Element> sigElements ) throws CssWsException {
		boolean validSignature = false;
//		boolean assertSigValid = false;
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
				
				if ("Assertion".equalsIgnoreCase(sig.getParentNode().getLocalName())) {
					logger.debug("Assertion signature found, skipping ");
				} else {
					logger.debug("Signature found, trying validation against " + alias);
					try {
						wsSigValid = validateSignature(cert, sig, soapBody);
						if (wsSigValid) {
							logger.debug("Signature valid for alias " + alias);
							break;
						}
						logger.debug("Signature not valid for alias " + alias);
					} catch (Exception e) {
						logger.debug("Signature not valid for alias " + alias + ", exception " + e.getMessage());
					}
				}
			}
		}
			
		validSignature = wsSigValid;
		if (!validSignature) {
			logger.error("Invalid WS Security signature found ");
			throw new CssWsException("Invalid WS Security signature found ");
		}
		
		return validSignature;
	}

	private boolean validateSignature(Certificate certificate, Element signature, Element soapBody) throws Exception {
		PublicKey publicKey = certificate.getPublicKey();
        DOMValidateContext ctx = new DOMValidateContext(publicKey, signature);
        ctx.setIdAttributeNS(soapBody, "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "Id");
        XMLSignatureFactory sigF = XMLSignatureFactory.getInstance("DOM");
        XMLSignature sig = sigF.unmarshalXMLSignature(ctx);
        return sig.validate(ctx);
	}
	
}
