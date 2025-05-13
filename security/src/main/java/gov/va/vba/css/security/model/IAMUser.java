package gov.va.vba.css.security.model;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.w3c.dom.Element;

public class IAMUser extends User {

	private static final long serialVersionUID = 1L;
	
	private String firstName = null;
	private String lastName = null;
	private String email = null;
	private Element samlTokenXML;
	private String organization = null;
	private String samaccountname = null;

	public IAMUser(String username, String password, boolean enabled,
			boolean accountNonExpired, boolean credentialsNonExpired,
			boolean accountNonLocked,
			Collection<GrantedAuthority> authorities) {
		super(username, password, enabled, accountNonExpired,
				credentialsNonExpired, accountNonLocked, authorities);
	}

	public IAMUser(String userName, Collection<GrantedAuthority> authorities) {
		super(userName, "", true, true, true, true, authorities);
	}

	public String getFirstName() {
		return firstName;
	}

	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}

	public String getLastName() {
		return lastName;
	}

	public void setLastName(String lastName) {
		this.lastName = lastName;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public Element getSamlTokenXML() {
		return samlTokenXML;
	}

	public void setSamlTokenXML(Element samlTokenXML) {
		this.samlTokenXML = samlTokenXML;
	}

	public String getOrganization() {
		return organization;
	}

	public void setOrganization(String organization) {
		this.organization = organization;
	}

	public String getSamaccountname() {
		return samaccountname;
	}

	public void setSamaccountname(String samaccountname) {
		this.samaccountname = samaccountname;
	}

	

}
