package gov.va.vba.css.security.formatters;

import org.w3c.dom.Node;

import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;

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
        TransformerFactory factory = TransformerFactory.newInstance();
        factory.setAttribute(ACCESS_EXTERNAL_DTD, "");
        Transformer transformer = factory.newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        StreamResult result = new StreamResult(new StringWriter());
        DOMSource source = new DOMSource(input);
        transformer.transform(source, result);
        Writer writer = null;
        try {
        	writer = result.getWriter();
        	retVal = writer.toString();
        } finally {
        	if (writer != null) {
        		try {
					writer.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
        	}
		}
        return retVal;
    }
}
