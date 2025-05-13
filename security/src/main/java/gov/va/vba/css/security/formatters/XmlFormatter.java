package gov.va.vba.css.security.formatters;

import org.w3c.dom.Node;

import javax.xml.transform.TransformerException;

public interface XmlFormatter {
    String formatNode(Node input) throws TransformerException;
}
