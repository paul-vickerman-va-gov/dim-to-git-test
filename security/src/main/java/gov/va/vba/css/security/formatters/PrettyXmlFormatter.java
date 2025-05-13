package gov.va.vba.css.security.formatters;

import org.w3c.dom.Node;

import java.io.StringWriter;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

public class PrettyXmlFormatter implements XmlFormatter {
    @Override
    public String formatNode(Node input) throws TransformerException {
        String retVal = null;
        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        StreamResult result = new StreamResult(new StringWriter());
        DOMSource source = new DOMSource(input);
        transformer.transform(source, result);
        retVal = result.getWriter().toString();
        return retVal;
    }
}
