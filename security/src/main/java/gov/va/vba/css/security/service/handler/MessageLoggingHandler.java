package gov.va.vba.css.security.service.handler;

import gov.va.vba.css.security.formatters.BasicXmlFormatter;
import gov.va.vba.css.security.formatters.XmlFormatter;
import gov.va.vba.css.security.util.SecurityProperties;
import gov.va.vba.framework.logging.Logger;

import org.springframework.beans.factory.annotation.Autowired;
import org.w3c.dom.Node;

import javax.xml.namespace.QName;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPFault;
import javax.xml.transform.TransformerException;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import java.util.Set;

/**
 * This web service handler is intended to be added into any handler chain 
 * where the web service requests and responses are to be logged.  SOAP faults 
 * returned to the client are also logged.
 * 
 * Currently, the logging is output at the DEBUG level and logging is only 
 * attempted when WARN is enabled.
 */
public class MessageLoggingHandler extends CSSWSHandler {
    private static Logger logger = Logger.getLogger(MessageLoggingHandler.class);
    
    @Autowired
   	private SecurityProperties props;
    
    private XmlFormatter formatter = new BasicXmlFormatter();

    public XmlFormatter getFormatter() {
        return formatter;
    }

    public void setFormatter(XmlFormatter formatter) {
        this.formatter = formatter;
    }

    /**
     * handleMessage simply identifies whether a message is an outgoing request 
     * or an incoming response and then logs the message.
     */
    @Override
    public boolean handleMessage(SOAPMessageContext context) {
        try {
        	if (!props.isSecurityTurnedOn()){
            	logger.debug(this.getClass()+ " Security property turned off, ignoring message...");
            } 
        	else if (isOutbound(context)) {
                logger.warn("Outgoing SOAP message: ");
                logMessage(context);
            }
            else {
                logger.warn("Incoming SOAP message: ");
                logMessage(context);
            }
        }
        catch (RuntimeException e) {
            logger.error("Error while attempting to log SOAP message.", e);
        }
        
        // Always return true.  This handler should not prevent the web service 
        // chain from continuing.
        return true;
    }

    @Override
    public boolean handleFault(SOAPMessageContext context) {
		
        try {
            logFault(context);

			if (isOutbound(context)) {
                logger.error("Outgoing SOAP fault message: ");
                logMessage(context);
            }
            else {
                logger.error("Incoming SOAP fault message: ");
                logMessage(context);
            }
			
        }
        catch (RuntimeException e) {
            logger.error("Error while attempting to log SOAP fault.", e);}

        // Always return true.  This handler should not prevent the web service 
        // chain from continuing.
        return true;
    }

    @Override
    public void close(MessageContext context) {
    }

    @Override
    public Set<QName> getHeaders() {
        return null;
    }

    /**
     * Logs the SOAP message.
     * 
     * @param context The current SOAPMessageContext
     * 
     * @return
     * @throws TransformerException 
     */
    void logMessage(SOAPMessageContext context) {
        Node message = context.getMessage().getSOAPPart();
		try {
			String output = formatter.formatNode(message);
			logger.warn(output);
		} catch (TransformerException e) {
			logger.error("Unable to log SOAP message",e);
		}
    }

    /**
     * Logs the SOAP message.
     * 
     * @param context The current SOAPMessageContext
     * 
     * @return
     * @throws TransformerException 
     * @throws SOAPException 
     */
    void logFault(SOAPMessageContext context) {
		try {
	        SOAPFault fault = context.getMessage().getSOAPBody().getFault();
	        logger.error("SOAP Fault: " + fault.getFaultString());
		} catch (SOAPException e) {
			logger.error("Unable to log SOAP fault",e);
		}
    }

	public void setProps(SecurityProperties props) {
		this.props = props;
	}
}
