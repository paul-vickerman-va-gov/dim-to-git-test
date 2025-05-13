package gov.va.vba.css.bo;

import gov.va.vba.framework.css.cssiam.domain.entities.CssUser;
import gov.va.vba.framework.services.CommonSecurityServiceV2;

public interface CommonSecuritySystemBean {

	public CommonSecurityServiceV2 getCommonSecurityServiceEJB();

	public void setCommonSecurityServiceEJB(CommonSecurityServiceV2 commonSecurityServiceEJB);
	
	public CssUser getCSSStationsByApplication(String username, String applicationName, String clientIpAddress);
	
}
