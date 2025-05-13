package gov.va.vba.css.security.service.impl;


import gov.va.vba.framework.logging.Logger;

import java.util.ArrayList;
import java.util.List;

import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.NameID;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSString;
//import org.opensaml.saml2.core.NameID;
//import org.opensaml.xml.XMLObject;
//import org.opensaml.xml.schema.XSString;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.util.Assert;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

import gov.va.vba.css.security.model.IAMUser;

public class SamlAuthenticationUserDetailsService implements SAMLUserDetailsService {

	public static final String IAM_ROLE_SAML_ATTR_NAME = "role";
	public static final String IAM_LNAME_SAML_ATTR_NAME = "lastname";
	public static final String IAM_FNAME_SAML_ATTR_NAME = "firstname";
	public static final String IAM_SAMACCOUNTNAME_SAML_ATTR_NAME = "adSamAccountName"; 
	public static final String IAM_EMAIL_SAML_ATTR_NAME = "adEmail";
	public static final String IAM_ORG_SAML_ATTR_NAME = "organization";

	private static final Logger LOG = Logger.getLogger(SamlAuthenticationUserDetailsService.class);

	/**
	 * Take the SAML credential and turn it into a IAMUser ( for Spring
	 * Security )
	 * 
	 * @see org.springframework.security.saml.userdetails.SAMLUserDetailsService#loadUserBySAML(org.springframework.security.saml.SAMLCredential)
	 */
	public Object loadUserBySAML(SAMLCredential credential) {
		// verify credential is not null
		Assert.notNull(credential, "The SAML Credential must be not null");
		NameID nameID = credential.getNameID();

		//verify that NameId is not null
		Assert.notNull(nameID, "The NameId element in the SAML Credential must be not null");
		
		LOG.info("User Authentication Completed for" + credential.getNameID().getValue());
		List<Attribute> attributes = credential.getAttributes();
		
		// verify attributes are not null
		Assert.notNull(attributes, "SAML Credential Attrubutes mus be not null");

		IAMUser iamUser = createUser(credential, attributes);
		
		
		String firstName = null;
		String lastName = null;
		String samaccountname = null;
		String email = null;
		String organization = null;

		// loop through attributes to find the ones that have values that are
		// needed
		for (Attribute attribute : attributes) {
			String attributeName = attribute.getName();
			
			if (IAM_LNAME_SAML_ATTR_NAME.equalsIgnoreCase(attributeName)) {
				lastName = getSingleAttributeValue(attribute);
			} else if (IAM_FNAME_SAML_ATTR_NAME.equalsIgnoreCase(attributeName)) {
				firstName = getSingleAttributeValue(attribute);
			} else if (IAM_EMAIL_SAML_ATTR_NAME.equalsIgnoreCase(attributeName)) {
				email = getSingleAttributeValue(attribute);
			} else if (IAM_SAMACCOUNTNAME_SAML_ATTR_NAME.equalsIgnoreCase(attributeName)) {
				samaccountname = getSingleAttributeValue(attribute);
			} else if (IAM_ORG_SAML_ATTR_NAME.equalsIgnoreCase(attributeName)) {
				organization = getSingleAttributeValue(attribute);
			}
		}
		
		if(credential.getAuthenticationAssertion() != null && credential.getAuthenticationAssertion().getDOM() != null){
			Element samlXML = credential.getAuthenticationAssertion().getDOM();
			Element cloned = (Element)samlXML.cloneNode(true);
			iamUser.setSamlTokenXML(cloned);
		}
		else{
			LOG.error("Could not get SAML Credentials XML for vbmsUser, efolder will not be available");
		}		
		
		iamUser.setEmail(email);
		iamUser.setFirstName(firstName);
		iamUser.setLastName(lastName);
		iamUser.setOrganization(organization);
		iamUser.setSamaccountname(samaccountname);
		
		logIAMUser(iamUser);
		return iamUser;
	}

	private void logIAMUser(IAMUser user) {
		LOG.info("User Details: " + "NameId: " + user.getUsername()
				+ ", First Name: " + user.getFirstName() + ", Last Name:"
				+ user.getLastName() + ", email:" + user.getEmail()
				+ ", Organization:" +user.getOrganization() 
				+ ", SAMACCOUNTNAME:" +user.getSamaccountname());
	}

	/**
	 * @param credential
	 * @param attributes
	 * @return
	 */
	IAMUser createUser(SAMLCredential credential, List<Attribute> attributes) {

		// verify attributes are not null
		Assert.notNull(attributes, "The list of attributes for a user should not be null");

		List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();

		// loop through attributes to find the authorities
		for (Attribute attribute : attributes) {
			String attributeName = attribute.getName();
			if (IAM_ROLE_SAML_ATTR_NAME.equalsIgnoreCase(attributeName)) {
				authorities.addAll(this.getAuthoritiesFromAttribute(attribute));
			}
		}

		// get the user name
		String userName = credential.getNameID().getValue();
		
		// create the user
		return new IAMUser(userName, authorities);
	}

	/**
	 * @param attribute
	 * @return the authorities to be
	 */
	List<GrantedAuthority> getAuthoritiesFromAttribute(Attribute attribute) {
		List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
		String[] values = getSimpleAttributeValues(attribute);
		for (String roleName : values) {
			// Had to parse the returned role from local IDP because of
			// restrictions on role naming conventions
			String[] splitRoleName = roleName.split("=");
			String role = null;
			if (splitRoleName.length > 1) {
				role = splitRoleName[1];
			} else {
				role = roleName;
			}
			addGrantedAuthorities(role, authorities);
		}
		return authorities;
	}

	private void addGrantedAuthorities(String role,
			List<GrantedAuthority> grantedAuthorityList) {
		LOG.info("Role Name" + role);
		grantedAuthorityList.add(new SimpleGrantedAuthority(role));
	}

	/**
	 * @param attribute
	 * @return
	 */
	String getSingleAttributeValue(Attribute attribute) {
		String[] values = getSimpleAttributeValues(attribute);
		if (values.length > 0) {
			return values[0];
		}
		return null;
	}

	/**
	 * @param attribute
	 * @return
	 */
	String[] getSimpleAttributeValues(Attribute attribute) {
		List<XMLObject> attributeValues = attribute.getAttributeValues();
		String[] values = new String[attributeValues.size()];
		for (int i = 0; i < attributeValues.size(); i++) {
			XMLObject value = attributeValues.get(i);
			if (value instanceof XSString) {
				values[i] = ((XSString) value).getValue();
			} else {
				values[i] = DomUtils.getTextValue(attributeValues.get(i)
						.getDOM());
			}
		}
		return values;
	}
}
