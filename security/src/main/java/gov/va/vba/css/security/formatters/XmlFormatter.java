package gov.va.vba.css.security.formatters;

import org.w3c.dom.Node;

import javax.xml.transform.TransformerException;

public interface XmlFormatter {
	String ACCESS_EXTERNAL_DTD = "http://javax.xml.XMLConstants/property/accessExternalDTD";
    String formatNode(Node input) throws TransformerException;
}
