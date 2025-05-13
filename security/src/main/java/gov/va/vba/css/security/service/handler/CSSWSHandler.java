package gov.va.vba.css.security.service.handler;

import org.springframework.web.context.support.SpringBeanAutowiringSupport;

import javax.xml.namespace.QName;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;
import java.util.Set;

public abstract class CSSWSHandler extends SpringBeanAutowiringSupport implements SOAPHandler<SOAPMessageContext> {
    public static final String WS_SECURITY_ENGINE_RESULTS = "WSSE_RESULTS";
    public static final String ENCRYPTION_ALIAS = "ENCRYPTION_ALIAS";

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

    /**
     * Checks to see if the message passing through a service object is an
     * outgoing message.
     * 
     * @param context
     *            The current SOAPMessageContext
     * 
     * @return True if the SOAP message is outbound. Otherwise, false.
     */
    protected boolean isOutbound(SOAPMessageContext context) {
        boolean retVal = false;
        Boolean outbound = (Boolean)context
            .get(SOAPMessageContext.MESSAGE_OUTBOUND_PROPERTY);
        retVal = outbound.booleanValue();
        return retVal;
    }

    /**
     * Checks to see if the message passing through a service object is an
     * incoming message.
     * 
     * @param context
     *            The current SOAPMessageContext
     * 
     * @return True if the SOAP message is inbound. Otherwise, false.
     */
    protected boolean isInbound(SOAPMessageContext context) {
        return !isOutbound(context);
    }
}
